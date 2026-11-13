package credentials

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SOCKS credentials of external SOCKS exits (model.ExternalExit): the
// username and password of an existing SOCKS5 proxy the panel does not
// manage. Both halves are secret: written once, never returned by the API,
// never in compile output, previews, logs, snapshots or exports. They are
// read back only at the install boundary, for the carrier's redirector
// configuration (compile.SOCKSUserSecret / SOCKSPassSecret placeholders).

// SOCKSIDPrefix starts every SOCKS credential id.
const SOCKSIDPrefix = "socks"

// SOCKSCredential is the metadata of one SOCKS credential (no material).
type SOCKSCredential struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Notes     string `json:"notes,omitempty"`
	SecretSet bool   `json:"secret_set"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	RotatedAt string `json:"rotated_at,omitempty"`
}

type socksRecord struct {
	SOCKSCredential
	Gen int `json:"gen"`
}

// socksValueRe is what a SOCKS username or password may contain: printable
// ASCII without whitespace, quotes, backslash and the characters that would
// need escaping in the redirector's YAML or a proxy URL ("@ : / # ? % &").
// RFC 1929 bounds both at 255 bytes.
var socksValueRe = regexp.MustCompile(`^[A-Za-z0-9._~!$*+,;=^\-\[\]{}()|<>]{1,255}$`)

// ValidSOCKSValue reports whether v can be a SOCKS username or password.
func ValidSOCKSValue(v string) bool { return socksValueRe.MatchString(v) }

// SOCKSSecretInput is the material of a SOCKS credential (write-only).
type SOCKSSecretInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Secrets lists the values to scrub from error text.
func (in SOCKSSecretInput) Secrets() []string { return []string{in.Username, in.Password} }

func checkSOCKS(in SOCKSSecretInput) error {
	if !ValidSOCKSValue(in.Username) {
		return errf(CodeInvalid, "username", "SOCKS 用户名必须是 1–255 个可打印 ASCII 字符，不能有空白、引号、反斜杠和 @ : / # ? %% &")
	}
	if !ValidSOCKSValue(in.Password) {
		return errf(CodeInvalid, "password", "SOCKS 密码必须是 1–255 个可打印 ASCII 字符，不能有空白、引号、反斜杠和 @ : / # ? %% &")
	}
	return nil
}

func (i *index) socks(id string) int {
	for n, c := range i.SOCKSCredentials {
		if c.ID == id {
			return n
		}
	}
	return -1
}

// SOCKSCredentials lists the SOCKS credentials (metadata only), by name.
func (s *Store) SOCKSCredentials() []SOCKSCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SOCKSCredential, 0, len(s.idx.SOCKSCredentials))
	for _, c := range s.idx.SOCKSCredentials {
		out = append(out, c.SOCKSCredential)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || out[i].Name == out[j].Name && out[i].ID < out[j].ID
	})
	return out
}

// SOCKSCredential returns one credential's metadata.
func (s *Store) SOCKSCredential(id string) (SOCKSCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.socks(id)
	if n < 0 {
		return SOCKSCredential{}, errf(CodeNotFound, "", "SOCKS 凭据 %s 不存在", id)
	}
	return s.idx.SOCKSCredentials[n].SOCKSCredential, nil
}

// CreateSOCKSCredential stores a new credential.
func (s *Store) CreateSOCKSCredential(name, notes string, in SOCKSSecretInput) (SOCKSCredential, error) {
	name, err := checkText("name", name, 64, true)
	if err != nil {
		return SOCKSCredential{}, err
	}
	if notes, err = checkText("notes", notes, 2000, false); err != nil {
		return SOCKSCredential{}, err
	}
	if err := checkSOCKS(in); err != nil {
		return SOCKSCredential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	id := newID(SOCKSIDPrefix)
	for next.idTaken(id) {
		id = newID(SOCKSIDPrefix)
	}
	now := s.now()
	rec := socksRecord{SOCKSCredential: SOCKSCredential{ID: id, Name: name, Notes: notes, SecretSet: true, CreatedAt: now, UpdatedAt: now}, Gen: 1}
	next.SOCKSCredentials = append(next.SOCKSCredentials, rec)
	if err := s.commit(next, map[string]secret{s.secretPath(id, 1): {Kind: "socks", SOCKSUser: in.Username, SOCKSPass: in.Password}}); err != nil {
		return SOCKSCredential{}, err
	}
	return rec.SOCKSCredential, nil
}

// UpdateSOCKSCredential changes name and notes; the secret is unchanged.
func (s *Store) UpdateSOCKSCredential(id string, p CredentialPatch) (SOCKSCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.socks(id)
	if n < 0 {
		return SOCKSCredential{}, errf(CodeNotFound, "", "SOCKS 凭据 %s 不存在", id)
	}
	c := next.SOCKSCredentials[n]
	var err error
	if p.Name != nil {
		if c.Name, err = checkText("name", *p.Name, 64, true); err != nil {
			return SOCKSCredential{}, err
		}
	}
	if p.Notes != nil {
		if c.Notes, err = checkText("notes", *p.Notes, 2000, false); err != nil {
			return SOCKSCredential{}, err
		}
	}
	if p.Comment != nil {
		return SOCKSCredential{}, errf(CodeKindMismatch, "comment", "SOCKS 凭据没有注释")
	}
	c.UpdatedAt = s.now()
	next.SOCKSCredentials[n] = c
	if err := s.commit(next, nil); err != nil {
		return SOCKSCredential{}, err
	}
	return c.SOCKSCredential, nil
}

// RotateSOCKSCredential replaces username and password under the same id
// (the carrier needs a re-install to use them).
func (s *Store) RotateSOCKSCredential(id string, in SOCKSSecretInput) (SOCKSCredential, error) {
	if err := checkSOCKS(in); err != nil {
		return SOCKSCredential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.socks(id)
	if n < 0 {
		return SOCKSCredential{}, errf(CodeNotFound, "", "SOCKS 凭据 %s 不存在", id)
	}
	c := next.SOCKSCredentials[n]
	now := s.now()
	c.Gen++
	c.UpdatedAt, c.RotatedAt, c.SecretSet = now, now, true
	next.SOCKSCredentials[n] = c
	if err := s.commit(next, map[string]secret{s.secretPath(id, c.Gen): {Kind: "socks", SOCKSUser: in.Username, SOCKSPass: in.Password}}); err != nil {
		return SOCKSCredential{}, err
	}
	return c.SOCKSCredential, nil
}

// DeleteSOCKSCredential removes a credential. inUse lists what still
// refers to it (external exits of the stored topology); a non-empty list
// refuses the delete.
func (s *Store) DeleteSOCKSCredential(id string, inUse []Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.socks(id)
	if n < 0 {
		return errf(CodeNotFound, "", "SOCKS 凭据 %s 不存在", id)
	}
	if len(inUse) > 0 {
		names := make([]string, 0, len(inUse))
		for _, r := range inUse {
			names = append(names, r.Name)
		}
		return &Error{Code: CodeInUse, Msg: fmt.Sprintf("SOCKS 凭据 %s 仍被外部出口 %s 使用：先让它们改用别的凭据或删除它们（可以原地轮换）", next.SOCKSCredentials[n].Name, strings.Join(names, "、")), InUse: inUse}
	}
	next.SOCKSCredentials = append(next.SOCKSCredentials[:n], next.SOCKSCredentials[n+1:]...)
	return s.commit(next, nil)
}

// SOCKSSecrets reads the credentials ids names, for the install boundary:
// the map holds "<id>-user" and "<id>-pass" (the placeholders the
// carrier's files carry). Any missing or unreadable one is an error.
func (s *Store) SOCKSSecrets(ids []string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, id := range ids {
		n := s.idx.socks(id)
		if n < 0 {
			return nil, errf(CodeNotFound, "", "SOCKS 凭据 %s 不存在", id)
		}
		sec, err := s.readSecret(id, s.idx.SOCKSCredentials[n].Gen)
		if err != nil {
			return nil, err
		}
		if !ValidSOCKSValue(sec.SOCKSUser) || !ValidSOCKSValue(sec.SOCKSPass) {
			return nil, errf(CodeStorage, "", "SOCKS 凭据 %s 的文件损坏", id)
		}
		out[id+"-user"] = sec.SOCKSUser
		out[id+"-pass"] = sec.SOCKSPass
	}
	return out, nil
}

// IsSOCKSSecretID reports whether a placeholder id names a SOCKS
// credential half ("<credential id>-user" / "-pass").
func IsSOCKSSecretID(id string) bool {
	if !strings.HasPrefix(id, SOCKSIDPrefix+"-") {
		return false
	}
	return strings.HasSuffix(id, "-user") || strings.HasSuffix(id, "-pass")
}
