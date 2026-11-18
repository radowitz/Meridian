package credentials

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DNS account identifiers of an exit's encrypted upstream resolver
// (model.ExitDNSUpstream, docs/architecture.md「出口解析上游」): the
// account-identifying part of a provider's DoT host name (its first label)
// or DoH path. The value is restricted like the other secrets here:
// written once, never returned by the API, never in the topology, compile
// output, previews, diffs, logs, snapshots, exports or demo data. It is
// read back only at the install boundary, for the exit's SmartDNS config
// (placeholder __MERIDIAN_SECRET_<id>__, apply.InjectSecrets).

// DNSAccountIDPrefix starts every DNS account credential id.
const DNSAccountIDPrefix = "dnsacct"

// DNSAccountCredential is the metadata of one DNS account identifier.
type DNSAccountCredential struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Notes     string `json:"notes,omitempty"`
	SecretSet bool   `json:"secret_set"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	RotatedAt string `json:"rotated_at,omitempty"`
}

type dnsAccountRecord struct {
	DNSAccountCredential
	Gen int `json:"gen"`
}

// dnsAccountRe: one DNS label that is also a plain URL path segment
// (validate.ExitDNSAccountValid; a test keeps the two equal).
var dnsAccountRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{1,61}[A-Za-z0-9])$`)

// ValidDNSAccount reports whether v can be a DNS account identifier.
func ValidDNSAccount(v string) bool { return dnsAccountRe.MatchString(v) }

// DNSAccountInput is the material of a DNS account credential (write-only).
type DNSAccountInput struct {
	Account string `json:"account"`
}

// Secrets lists the values to scrub from error text.
func (in DNSAccountInput) Secrets() []string { return []string{in.Account} }

func checkDNSAccount(in DNSAccountInput) error {
	if !ValidDNSAccount(in.Account) {
		return errf(CodeInvalid, "account", "账户标识必须是 3–63 个字母、数字或中间的连字符（一个域名标签，也能直接放进 URL 路径）")
	}
	return nil
}

func (i *index) dnsAccount(id string) int {
	for n, c := range i.DNSAccounts {
		if c.ID == id {
			return n
		}
	}
	return -1
}

// DNSAccountCredentials lists the credentials (metadata only), by name.
func (s *Store) DNSAccountCredentials() []DNSAccountCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DNSAccountCredential, 0, len(s.idx.DNSAccounts))
	for _, c := range s.idx.DNSAccounts {
		out = append(out, c.DNSAccountCredential)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || out[i].Name == out[j].Name && out[i].ID < out[j].ID
	})
	return out
}

// DNSAccountCredential returns one credential's metadata.
func (s *Store) DNSAccountCredential(id string) (DNSAccountCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.dnsAccount(id)
	if n < 0 {
		return DNSAccountCredential{}, errf(CodeNotFound, "", "DNS 账户标识 %s 不存在", id)
	}
	return s.idx.DNSAccounts[n].DNSAccountCredential, nil
}

// CreateDNSAccountCredential stores a new credential.
func (s *Store) CreateDNSAccountCredential(name, notes string, in DNSAccountInput) (DNSAccountCredential, error) {
	name, err := checkText("name", name, 64, true)
	if err != nil {
		return DNSAccountCredential{}, err
	}
	if notes, err = checkText("notes", notes, 2000, false); err != nil {
		return DNSAccountCredential{}, err
	}
	if err := checkDNSAccount(in); err != nil {
		return DNSAccountCredential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	id := newID(DNSAccountIDPrefix)
	for next.idTaken(id) {
		id = newID(DNSAccountIDPrefix)
	}
	now := s.now()
	rec := dnsAccountRecord{DNSAccountCredential: DNSAccountCredential{ID: id, Name: name, Notes: notes, SecretSet: true, CreatedAt: now, UpdatedAt: now}, Gen: 1}
	next.DNSAccounts = append(next.DNSAccounts, rec)
	if err := s.commit(next, map[string]secret{s.secretPath(id, 1): {Kind: "dns_account", DNSAccount: in.Account}}); err != nil {
		return DNSAccountCredential{}, err
	}
	return rec.DNSAccountCredential, nil
}

// UpdateDNSAccountCredential changes name and notes; the value is unchanged.
func (s *Store) UpdateDNSAccountCredential(id string, p CredentialPatch) (DNSAccountCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.dnsAccount(id)
	if n < 0 {
		return DNSAccountCredential{}, errf(CodeNotFound, "", "DNS 账户标识 %s 不存在", id)
	}
	c := next.DNSAccounts[n]
	var err error
	if p.Name != nil {
		if c.Name, err = checkText("name", *p.Name, 64, true); err != nil {
			return DNSAccountCredential{}, err
		}
	}
	if p.Notes != nil {
		if c.Notes, err = checkText("notes", *p.Notes, 2000, false); err != nil {
			return DNSAccountCredential{}, err
		}
	}
	if p.Comment != nil {
		return DNSAccountCredential{}, errf(CodeKindMismatch, "comment", "DNS 账户标识没有注释")
	}
	c.UpdatedAt = s.now()
	next.DNSAccounts[n] = c
	if err := s.commit(next, nil); err != nil {
		return DNSAccountCredential{}, err
	}
	return c.DNSAccountCredential, nil
}

// RotateDNSAccountCredential replaces the value under the same id and
// raises its version (DNSAccountVersions): every exit that names it is then
// "changed" until it is preflighted and installed again.
func (s *Store) RotateDNSAccountCredential(id string, in DNSAccountInput) (DNSAccountCredential, error) {
	if err := checkDNSAccount(in); err != nil {
		return DNSAccountCredential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.dnsAccount(id)
	if n < 0 {
		return DNSAccountCredential{}, errf(CodeNotFound, "", "DNS 账户标识 %s 不存在", id)
	}
	c := next.DNSAccounts[n]
	now := s.now()
	c.Gen++
	c.UpdatedAt, c.RotatedAt, c.SecretSet = now, now, true
	next.DNSAccounts[n] = c
	if err := s.commit(next, map[string]secret{s.secretPath(id, c.Gen): {Kind: "dns_account", DNSAccount: in.Account}}); err != nil {
		return DNSAccountCredential{}, err
	}
	return c.DNSAccountCredential, nil
}

// DeleteDNSAccountCredential removes a credential; a non-empty inUse (the
// global setting or exits of the stored topology that name it) refuses.
func (s *Store) DeleteDNSAccountCredential(id string, inUse []Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.dnsAccount(id)
	if n < 0 {
		return errf(CodeNotFound, "", "DNS 账户标识 %s 不存在", id)
	}
	if len(inUse) > 0 {
		names := make([]string, 0, len(inUse))
		for _, r := range inUse {
			names = append(names, r.Name)
		}
		return &Error{Code: CodeInUse, Msg: fmt.Sprintf("DNS 账户标识 %s 仍被 %s 使用：先改掉出口解析上游的设置（可以原地轮换）", next.DNSAccounts[n].Name, strings.Join(names, "、")), InUse: inUse}
	}
	next.DNSAccounts = append(next.DNSAccounts[:n], next.DNSAccounts[n+1:]...)
	return s.commit(next, nil)
}

// DNSAccountVersions returns the version of each named credential that
// exists: its generation, 1 when created and +1 per rotation. It is a
// counter kept in the index, nothing derived from the value, so it may be
// shown, compiled into an exit's SmartDNS config and recorded with an
// install (internal/api/dns_version.go).
func (s *Store) DNSAccountVersions(ids []string) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, id := range ids {
		if n := s.idx.dnsAccount(id); n >= 0 {
			out[id] = s.idx.DNSAccounts[n].Gen
		}
	}
	return out
}

// DNSAccountSecrets reads the credentials ids names, for the install
// boundary: id → value (the placeholder an exit's SmartDNS config carries
// is the credential id itself). Any missing or unreadable one is an error.
func (s *Store) DNSAccountSecrets(ids []string) (map[string]string, error) {
	out, _, err := s.DNSAccountSecretsVersioned(ids)
	return out, err
}

// DNSAccountSecretsVersioned is DNSAccountSecrets with the version of each
// value read (DNSAccountVersions), read under the same lock: the install
// compares it with the version its files were compiled with.
func (s *Store) DNSAccountSecretsVersioned(ids []string) (map[string]string, map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	vers := map[string]int{}
	for _, id := range ids {
		n := s.idx.dnsAccount(id)
		if n < 0 {
			return nil, nil, errf(CodeNotFound, "", "DNS 账户标识 %s 不存在", id)
		}
		gen := s.idx.DNSAccounts[n].Gen
		sec, err := s.readSecret(id, gen)
		if err != nil {
			return nil, nil, err
		}
		if !ValidDNSAccount(sec.DNSAccount) {
			return nil, nil, errf(CodeStorage, "", "DNS 账户标识 %s 的文件损坏", id)
		}
		out[id], vers[id] = sec.DNSAccount, gen
	}
	return out, vers, nil
}

// IsDNSAccountSecretID reports whether a placeholder id names a DNS
// account credential.
func IsDNSAccountSecretID(id string) bool {
	return strings.HasPrefix(id, DNSAccountIDPrefix+"-") && ValidID(id)
}
