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

// Versions of SOCKS credentials (docs/architecture.md「轮换外部 SOCKS 凭据」).
//
// A credential's version is its generation: 1 when created, +1 per
// rotation — a counter in the index, nothing derived from the username or
// password. The panel compiles it into the configuration of the carrier
// that names the credential, so a rotation changes the carrier's files and
// the carrier shows as pending (internal/api/socks_version.go).
//
// Carriers installed before versions were tracked have no such line, and
// adding one to all of them would turn every carrier into "pending" on
// upgrade. So the store keeps a baseline: the ids and generations of the
// SOCKS credentials that existed when tracking started. It is written
// once — by MigrateSOCKSVersions, or together with the first creation or
// rotation when that comes first, in the same index write and under the
// same lock — and never changed afterwards. A credential of the baseline
// is "tracked" (its version is compiled in) only once its generation
// exceeds the baseline's, that is after its first rotation since; a
// credential created later is tracked from the start. Without a baseline
// nothing is tracked and carriers compile exactly as before.

// socksBaseline is that record.
type socksBaseline struct {
	// At is when it was taken.
	At string `json:"at"`
	// Gens: credential id → generation at that moment, for every SOCKS
	// credential that existed (possibly none).
	Gens map[string]int `json:"gens"`
}

// SOCKSVersion is the version state of one SOCKS credential. No secret.
type SOCKSVersion struct {
	// Version: 1 when created, +1 per rotation.
	Version int `json:"version"`
	// Baseline is the version the baseline recorded for it; 0 when it was
	// created after the baseline (or there is none yet).
	Baseline int `json:"baseline,omitempty"`
	// Tracked: the version is compiled into the carriers' configuration
	// (created after the baseline, or rotated since). False: the credential
	// is as the baseline found it, and which of its values a carrier
	// installed before was given is not recorded anywhere.
	Tracked bool `json:"tracked"`
}

// SOCKSTracking is the state of the baseline.
type SOCKSTracking struct {
	// Ready: the baseline is written; rotations are tracked.
	Ready bool `json:"ready"`
	// Since is when it was taken.
	Since string `json:"since,omitempty"`
	// Error is why the last attempt to write it failed (only while not
	// Ready). Never contains secret material.
	Error string `json:"error,omitempty"`
}

// withSOCKSBaseline gives next the baseline when the store has none yet:
// the SOCKS credentials of the committed index (s.idx, before the change
// next carries) with their generations. The caller holds s.mu and commits
// next, so the baseline and the change land in one index write, or neither.
func (s *Store) withSOCKSBaseline(next *index) {
	if next.SOCKSBaseline != nil {
		return
	}
	b := &socksBaseline{At: s.now(), Gens: map[string]int{}}
	for _, c := range s.idx.SOCKSCredentials {
		b.Gens[c.ID] = c.Gen
	}
	next.SOCKSBaseline = b
}

// MigrateSOCKSVersions writes the baseline when the store has none: once,
// atomically with the index, under the lock rotations take. With a
// baseline already there it does nothing (a restart never takes it again).
// A failure is returned and remembered (SOCKSTracking); the store is left
// as it was, without a baseline, and carriers keep compiling as before
// until a later call, or the next creation or rotation, writes it.
func (s *Store) MigrateSOCKSVersions() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx.SOCKSBaseline != nil {
		return nil
	}
	next := cloneIndex(s.idx)
	s.withSOCKSBaseline(&next)
	if err := s.commit(next, nil); err != nil {
		s.socksMigErr = err.Error()
		return errf(CodeStorage, "", "没能写入 SOCKS 凭据的版本基线（%s）：写入之前承载节点的配置按原样编译，下次启动、新建或轮换 SOCKS 凭据时会再试", err.Error())
	}
	s.socksMigErr = ""
	return nil
}

// SOCKSTracking reports whether the baseline is written.
func (s *Store) SOCKSTracking() SOCKSTracking {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.idx.SOCKSBaseline; b != nil {
		return SOCKSTracking{Ready: true, Since: b.At}
	}
	return SOCKSTracking{Error: s.socksMigErr}
}

func (i *index) socksVersion(n int) SOCKSVersion {
	c := i.SOCKSCredentials[n]
	v := SOCKSVersion{Version: c.Gen}
	if b := i.SOCKSBaseline; b != nil {
		v.Baseline = b.Gens[c.ID]
		v.Tracked = v.Baseline == 0 || c.Gen > v.Baseline
	}
	return v
}

// SOCKSVersions returns the version state of each named credential that
// exists.
func (s *Store) SOCKSVersions(ids []string) map[string]SOCKSVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]SOCKSVersion{}
	for _, id := range ids {
		if n := s.idx.socks(id); n >= 0 {
			out[id] = s.idx.socksVersion(n)
		}
	}
	return out
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
	// A credential created now is not part of the baseline: its version
	// is tracked from the start.
	s.withSOCKSBaseline(&next)
	id := newID(SOCKSIDPrefix)
	for next.idTaken(id) || next.SOCKSBaseline.Gens[id] != 0 {
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
// and raises its version: every carrier that names it is then "changed"
// until it is preflighted and installed again. Without a baseline yet, the
// same index write records one first (the generations before this
// rotation), so no rotation goes untracked.
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
	s.withSOCKSBaseline(&next)
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
	out, _, err := s.SOCKSSecretsVersioned(ids)
	return out, err
}

// SOCKSSecretsVersioned is SOCKSSecrets with the version state of each
// credential read (SOCKSVersions), under the same lock: one snapshot. The
// install compares it with the versions its files were compiled with and
// records the versions it applied.
func (s *Store) SOCKSSecretsVersioned(ids []string) (map[string]string, map[string]SOCKSVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	vers := map[string]SOCKSVersion{}
	for _, id := range ids {
		n := s.idx.socks(id)
		if n < 0 {
			return nil, nil, errf(CodeNotFound, "", "SOCKS 凭据 %s 不存在", id)
		}
		sec, err := s.readSecret(id, s.idx.SOCKSCredentials[n].Gen)
		if err != nil {
			return nil, nil, err
		}
		if !ValidSOCKSValue(sec.SOCKSUser) || !ValidSOCKSValue(sec.SOCKSPass) {
			return nil, nil, errf(CodeStorage, "", "SOCKS 凭据 %s 的文件损坏", id)
		}
		out[id+"-user"] = sec.SOCKSUser
		out[id+"-pass"] = sec.SOCKSPass
		vers[id] = s.idx.socksVersion(n)
	}
	return out, vers, nil
}

// IsSOCKSSecretID reports whether a placeholder id names a SOCKS
// credential half ("<credential id>-user" / "-pass").
func IsSOCKSSecretID(id string) bool {
	if !strings.HasPrefix(id, SOCKSIDPrefix+"-") {
		return false
	}
	return strings.HasSuffix(id, "-user") || strings.HasSuffix(id, "-pass")
}
