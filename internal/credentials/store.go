// Package credentials keeps the managed servers, the reusable SSH
// credentials and the Cloudflare accounts, with their secret material in a
// restricted store of its own: a 0700 directory outside the data
// directory's snapshots, 0600 files written atomically, and a too-open file
// refused on read. The API only ever sees metadata (see the View types).
//
// Layout of <dir>:
//
//	index.json                 metadata of every object (no secret)
//	secrets/<id>-<gen>.json    one generation of one object's secret
//
// A rotation writes a new generation, then atomically replaces the index,
// then removes the old file: an interruption leaves the index pointing at a
// complete generation, and Open removes files the index does not name.
// There is no encryption at rest: the panel must use these secrets
// unattended, so any key would have to sit next to them (see
// docs/architecture.md).
package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/radowitz/meridian/internal/model"
	"golang.org/x/crypto/ssh"
)

// Credential kinds.
const (
	KindPassword   = "password"
	KindPrivateKey = "private_key"
)

const indexSchema = 1

// Error codes (machine-readable, stable for the panel).
const (
	CodeInvalid            = "invalid_field"
	CodeNotFound           = "not_found"
	CodeInUse              = "in_use"
	CodeKindMismatch       = "kind_mismatch"
	CodeInvalidKey         = "invalid_key"
	CodePassphraseRequired = "passphrase_required"
	CodePassphraseInvalid  = "passphrase_invalid"
	CodeHostKeyNotSeen     = "host_key_not_discovered"
	CodeHostKeyChanged     = "host_key_changed"
	CodeHostKeyMismatch    = "host_key_mismatch"
	CodeInsecureStorage    = "insecure_storage"
	CodeStorage            = "storage_error"
	CodeConflict           = "conflict"
)

// Ref names an object that refers to another one.
type Ref struct {
	Kind string `json:"kind"` // server | node | mesh_deployment
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Error is every error this package returns for a request. Msg never
// contains secret input.
type Error struct {
	Code  string
	Field string
	Msg   string
	InUse []Ref
}

func (e *Error) Error() string { return e.Msg }

func errf(code, field, format string, a ...any) *Error {
	return &Error{Code: code, Field: field, Msg: fmt.Sprintf(format, a...)}
}

// ErrNotFound is matched with errors.Is on any not-found *Error.
var ErrNotFound = errors.New("not found")

func (e *Error) Is(target error) bool { return target == ErrNotFound && e.Code == CodeNotFound }

// SSHCredential is the metadata of a reusable SSH credential. For a private
// key only derived, public information is kept here.
type SSHCredential struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Notes         string `json:"notes,omitempty"`
	KeyType       string `json:"key_type,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	Comment       string `json:"comment,omitempty"`
	HasPassphrase bool   `json:"has_passphrase,omitempty"`
	Generated     bool   `json:"generated,omitempty"`
	SecretSet     bool   `json:"secret_set"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	RotatedAt     string `json:"rotated_at,omitempty"`
}

// PermissionCheck is the result of checking an account's token against
// what Mesh needs (filled in by the Cloudflare check, not by this package).
// OK means every probe that was run passed; it does not mean write access
// was proven: Unconfirmed lists what read-only probes cannot establish.
type PermissionCheck struct {
	CheckedAt string   `json:"checked_at"`
	OK        bool     `json:"ok"`
	Missing   []string `json:"missing,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	// TokenStatus is Cloudflare's verify result: active, disabled,
	// expired, or "" when it could not be read.
	TokenStatus string `json:"token_status,omitempty"`
	// TokenKind is "account" (account-owned token) or "user".
	TokenKind   string            `json:"token_kind,omitempty"`
	Confirmed   []string          `json:"confirmed,omitempty"`
	Unconfirmed []string          `json:"unconfirmed,omitempty"`
	Checks      []PermissionProbe `json:"checks,omitempty"`
}

// PermissionProbe is one read-only call of a permission check.
type PermissionProbe struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	// Status: pass, denied (Cloudflare refused: missing permission or
	// wrong account), error (network or unexpected answer), skipped.
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CloudflareAccount is the metadata of one Cloudflare account. The API
// token is write-only.
type CloudflareAccount struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	AccountID       string           `json:"account_id"`
	Notes           string           `json:"notes,omitempty"`
	TokenSet        bool             `json:"token_set"`
	PermissionCheck *PermissionCheck `json:"permission_check,omitempty"`
	CreatedAt       string           `json:"created_at"`
	UpdatedAt       string           `json:"updated_at"`
	RotatedAt       string           `json:"rotated_at,omitempty"`
	MigratedFrom    string           `json:"migrated_from,omitempty"`
}

type credRecord struct {
	SSHCredential
	Gen int `json:"gen"`
}

type accountRecord struct {
	CloudflareAccount
	Gen int `json:"gen"`
}

type index struct {
	Schema      int             `json:"schema"`
	Servers     []model.Server  `json:"servers"`
	Credentials []credRecord    `json:"ssh_credentials"`
	Accounts    []accountRecord `json:"cloudflare_accounts"`
	MeshAccount string          `json:"mesh_account,omitempty"`
	// WGSecrets are WireGuard keys for the gateway's remote access (its
	// private key and the devices' pre-shared keys). Metadata only here.
	WGSecrets []WGSecretMeta `json:"wireguard_secrets,omitempty"`
	// WSSSecrets are the WSS carriers' upgrade path prefixes and
	// certificate private keys (metadata only here); WSS is the public
	// per-listener state (certificates, fingerprints, rotation stages).
	WSSSecrets []WSSSecretMeta `json:"wss_secrets,omitempty"`
	WSS        model.WSSState  `json:"wss,omitempty"`
	// SOCKSCredentials are the usernames and passwords of external SOCKS
	// exits' proxies (socks.go). Metadata only here.
	SOCKSCredentials []socksRecord `json:"socks_credentials,omitempty"`
	// RuleSetAuth are the subscription credentials of rule-sets
	// (ruleset_auth.go). Metadata only here.
	RuleSetAuth []ruleSetAuthRecord `json:"ruleset_auth,omitempty"`
}

// secret is the content of one secret file.
type secret struct {
	Kind       string `json:"kind"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	APIToken   string `json:"api_token,omitempty"`
	WGKey      string `json:"wg_key,omitempty"`
	WSSValue   string `json:"wss_value,omitempty"`
	SOCKSUser  string `json:"socks_user,omitempty"`
	SOCKSPass  string `json:"socks_pass,omitempty"`
	// Rule-set subscription credential (ruleset_auth.go).
	RSToken string `json:"rs_token,omitempty"`
	RSUser  string `json:"rs_user,omitempty"`
	RSPass  string `json:"rs_pass,omitempty"`
	RSQuery string `json:"rs_query,omitempty"`
}

// Store is the credential store. Methods are safe for concurrent use.
type Store struct {
	dir string
	mu  sync.Mutex
	idx index
	// Now is the clock (tests).
	Now func() time.Time
	// pins returns the hosts that deployments which are not fully
	// withdrawn still need (see SetDeploymentPins).
	pins func() ([]PinnedHost, error)
}

// PinnedHost is one host a deployment that is not fully withdrawn pinned:
// the server and SSH credential it will use to undo its changes, and the
// endpoint it connected to. ServerID or CredentialID may be empty for a
// journal written before they were recorded; the endpoint then identifies
// the server, and the server's current credential is the one needed.
type PinnedHost struct {
	Deployment   Ref
	ServerID     string
	CredentialID string
	Address      string
	Port         int
	User         string
}

// SetDeploymentPins installs the source of pinned hosts. It is called with
// the store lock held, so it must not call back into the store. An error
// makes every server and credential count as referenced (nothing a
// deployment might need is removed while its record cannot be read).
func (s *Store) SetDeploymentPins(f func() ([]PinnedHost, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins = f
}

func (s *Store) pinned() ([]PinnedHost, error) {
	if s.pins == nil {
		return nil, nil
	}
	return s.pins()
}

func addRef(refs []Ref, r Ref) []Ref {
	for _, x := range refs {
		if x.Kind == r.Kind && x.ID == r.ID {
			return refs
		}
	}
	return append(refs, r)
}

var unreadableDeployment = Ref{Kind: "mesh_deployment", ID: "unknown", Name: "Mesh 部署记录无法读取"}

func (i *index) pinMatchesServer(p PinnedHost, sv model.Server) bool {
	if p.ServerID != "" {
		return p.ServerID == sv.ID
	}
	return p.Address != "" && p.Address == sv.Address && (p.Port == sv.Port || (p.Port == 0 && sv.Port == 22))
}

// deploymentRefsServer lists the deployments that still need server id.
func (s *Store) deploymentRefsServer(i *index, id string) []Ref {
	refs := []Ref{}
	n := i.server(id)
	if n < 0 {
		return refs
	}
	pins, err := s.pinned()
	if err != nil {
		return []Ref{unreadableDeployment}
	}
	for _, p := range pins {
		if i.pinMatchesServer(p, i.Servers[n]) {
			refs = addRef(refs, p.Deployment)
		}
	}
	return refs
}

// deploymentRefsCred lists the deployments that still need credential id.
func (s *Store) deploymentRefsCred(i *index, id string) []Ref {
	refs := []Ref{}
	pins, err := s.pinned()
	if err != nil {
		return []Ref{unreadableDeployment}
	}
	for _, p := range pins {
		if p.CredentialID != "" {
			if p.CredentialID == id {
				refs = addRef(refs, p.Deployment)
			}
			continue
		}
		for _, sv := range i.Servers {
			if sv.CredentialID == id && i.pinMatchesServer(p, sv) {
				refs = addRef(refs, p.Deployment)
			}
		}
	}
	return refs
}

// DeploymentRefsForServer lists the deployments that still need a server.
func (s *Store) DeploymentRefsForServer(id string) []Ref {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deploymentRefsServer(&s.idx, id)
}

// DeploymentRefsForCredential lists the deployments that still need a
// credential.
func (s *Store) DeploymentRefsForCredential(id string) []Ref {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deploymentRefsCred(&s.idx, id)
}

// Open opens (creating if needed) the store at dir. The directory is made
// 0700; an index or secret file readable by group or others is refused.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errf(CodeStorage, "", "没有配置凭据存储目录")
	}
	for _, d := range []string{dir, filepath.Join(dir, "secrets")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, errf(CodeStorage, "", "无法创建凭据存储目录：%v", err)
		}
		fi, err := os.Stat(d)
		if err != nil {
			return nil, errf(CodeStorage, "", "凭据存储目录不可用：%v", err)
		}
		if !fi.IsDir() {
			return nil, errf(CodeStorage, "", "%s 不是目录", d)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			// A fresh Docker volume root is 0755; tighten it rather than
			// keep secrets in a listable directory.
			if err := os.Chmod(d, 0o700); err != nil {
				return nil, errf(CodeInsecureStorage, "", "凭据存储目录 %s 权限是 %o，无法收紧到 700：%v", d, fi.Mode().Perm(), err)
			}
		}
	}
	s := &Store{dir: dir}
	idx, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	s.idx = idx
	s.cleanOrphans()
	return s, nil
}

// Dir is the store directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) now() string {
	if s.Now != nil {
		return s.Now().UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func (s *Store) indexPath() string { return filepath.Join(s.dir, "index.json") }

func (s *Store) secretPath(id string, gen int) string {
	return filepath.Join(s.dir, "secrets", fmt.Sprintf("%s-%d.json", id, gen))
}

// readPrivate reads a 0600 (or stricter) file; a too-open one is refused.
func readPrivate(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errf(CodeInsecureStorage, "", "%s 不是普通文件，拒绝使用", filepath.Base(path))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, errf(CodeInsecureStorage, "", "%s 权限是 %o，必须是 600；拒绝使用", filepath.Base(path), fi.Mode().Perm())
	}
	return os.ReadFile(path)
}

func (s *Store) readIndex() (index, error) {
	b, err := readPrivate(s.indexPath())
	if os.IsNotExist(err) {
		return index{Schema: indexSchema}, nil
	}
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			return index{}, ce
		}
		return index{}, errf(CodeStorage, "", "读取凭据索引失败：%v", err)
	}
	var idx index
	if err := json.Unmarshal(b, &idx); err != nil {
		return index{}, errf(CodeStorage, "", "凭据索引损坏")
	}
	if idx.Schema > indexSchema {
		return index{}, errf(CodeStorage, "", "凭据索引版本 %d 比本程序新", idx.Schema)
	}
	idx.Schema = indexSchema
	return idx, nil
}

// cleanOrphans removes temp files and secret generations the index does
// not name (left by an interrupted write).
func (s *Store) cleanOrphans() {
	want := map[string]bool{}
	for _, c := range s.idx.Credentials {
		want[filepath.Base(s.secretPath(c.ID, c.Gen))] = true
	}
	for _, a := range s.idx.Accounts {
		want[filepath.Base(s.secretPath(a.ID, a.Gen))] = true
	}
	for _, w := range s.idx.WGSecrets {
		want[filepath.Base(s.secretPath(w.ID, 1))] = true
	}
	for _, w := range s.idx.WSSSecrets {
		want[filepath.Base(s.secretPath(w.ID, 1))] = true
	}
	for _, c := range s.idx.SOCKSCredentials {
		want[filepath.Base(s.secretPath(c.ID, c.Gen))] = true
	}
	for _, c := range s.idx.RuleSetAuth {
		want[filepath.Base(s.secretPath(c.ID, c.Gen))] = true
	}
	for _, d := range []string{s.dir, filepath.Join(s.dir, "secrets")} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			switch {
			case strings.HasPrefix(name, ".tmp-"):
				_ = os.Remove(filepath.Join(d, name))
			case d != s.dir && strings.HasSuffix(name, ".json") && !want[name]:
				_ = os.Remove(filepath.Join(d, name))
			}
		}
	}
}

func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func cloneIndex(i index) index {
	b, _ := json.Marshal(i)
	var out index
	_ = json.Unmarshal(b, &out)
	return out
}

// commit writes new secrets first, then the index, then drops the files
// the old index named and the new one does not.
func (s *Store) commit(next index, secrets map[string]secret) error {
	for path, sec := range secrets {
		b, _ := json.Marshal(sec)
		if err := writeAtomic(path, b); err != nil {
			return errf(CodeStorage, "", "写入凭据失败：%v", err)
		}
	}
	b, _ := json.MarshalIndent(next, "", "  ")
	if err := writeAtomic(s.indexPath(), b); err != nil {
		for path := range secrets {
			_ = os.Remove(path)
		}
		return errf(CodeStorage, "", "写入凭据索引失败：%v", err)
	}
	old := s.idx
	s.idx = next
	keep := map[string]bool{}
	for _, c := range next.Credentials {
		keep[s.secretPath(c.ID, c.Gen)] = true
	}
	for _, a := range next.Accounts {
		keep[s.secretPath(a.ID, a.Gen)] = true
	}
	for _, w := range next.WGSecrets {
		keep[s.secretPath(w.ID, 1)] = true
	}
	for _, w := range next.WSSSecrets {
		keep[s.secretPath(w.ID, 1)] = true
	}
	for _, c := range next.SOCKSCredentials {
		keep[s.secretPath(c.ID, c.Gen)] = true
	}
	for _, c := range next.RuleSetAuth {
		keep[s.secretPath(c.ID, c.Gen)] = true
	}
	for _, c := range old.Credentials {
		if p := s.secretPath(c.ID, c.Gen); !keep[p] {
			_ = os.Remove(p)
		}
	}
	for _, a := range old.Accounts {
		if p := s.secretPath(a.ID, a.Gen); !keep[p] {
			_ = os.Remove(p)
		}
	}
	for _, w := range old.WGSecrets {
		if p := s.secretPath(w.ID, 1); !keep[p] {
			_ = os.Remove(p)
		}
	}
	for _, w := range old.WSSSecrets {
		if p := s.secretPath(w.ID, 1); !keep[p] {
			_ = os.Remove(p)
		}
	}
	for _, c := range old.SOCKSCredentials {
		if p := s.secretPath(c.ID, c.Gen); !keep[p] {
			_ = os.Remove(p)
		}
	}
	for _, c := range old.RuleSetAuth {
		if p := s.secretPath(c.ID, c.Gen); !keep[p] {
			_ = os.Remove(p)
		}
	}
	return nil
}

func (s *Store) readSecret(id string, gen int) (secret, error) {
	b, err := readPrivate(s.secretPath(id, gen))
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			return secret{}, ce
		}
		return secret{}, errf(CodeStorage, "", "读取 %s 的密文失败", id)
	}
	var sec secret
	if err := json.Unmarshal(b, &sec); err != nil {
		return secret{}, errf(CodeStorage, "", "%s 的密文文件损坏", id)
	}
	return sec, nil
}

// ---------------------------------------------------------------- IDs ---

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

// ValidID reports whether s can be an object ID (also a safe file name).
func ValidID(s string) bool { return idRe.MatchString(s) }

func newID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}

func (i *index) idTaken(id string) bool {
	for _, x := range i.Servers {
		if x.ID == id {
			return true
		}
	}
	for _, x := range i.Credentials {
		if x.ID == id {
			return true
		}
	}
	for _, x := range i.Accounts {
		if x.ID == id {
			return true
		}
	}
	for _, x := range i.WGSecrets {
		if x.ID == id {
			return true
		}
	}
	for _, x := range i.WSSSecrets {
		if x.ID == id {
			return true
		}
	}
	for _, x := range i.SOCKSCredentials {
		if x.ID == id {
			return true
		}
	}
	for _, x := range i.RuleSetAuth {
		if x.ID == id {
			return true
		}
	}
	return false
}

func (i *index) server(id string) int {
	for n, x := range i.Servers {
		if x.ID == id {
			return n
		}
	}
	return -1
}

func (i *index) cred(id string) int {
	for n, x := range i.Credentials {
		if x.ID == id {
			return n
		}
	}
	return -1
}

func (i *index) account(id string) int {
	for n, x := range i.Accounts {
		if x.ID == id {
			return n
		}
	}
	return -1
}

// --------------------------------------------------------- validation ---

func checkText(field, v string, max int, required bool) (string, error) {
	v = strings.TrimSpace(v)
	if required && v == "" {
		return "", errf(CodeInvalid, field, "%s 不能为空", field)
	}
	if utf8.RuneCountInString(v) > max {
		return "", errf(CodeInvalid, field, "%s 最长 %d 个字符", field, max)
	}
	if !utf8.ValidString(v) {
		return "", errf(CodeInvalid, field, "%s 不是有效的 UTF-8", field)
	}
	for _, r := range v {
		if unicode.IsControl(r) && !(field == "notes" && (r == '\n' || r == '\t')) {
			return "", errf(CodeInvalid, field, "%s 含控制字符", field)
		}
	}
	return v, nil
}

var (
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)
	userRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	tagRe      = regexp.MustCompile(`^[\p{L}\p{N}_.:-]{1,32}$`)
)

// ValidAddress accepts an IP literal or a DNS host name (never anything
// starting with "-", so it cannot become an ssh option).
func ValidAddress(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, "-") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return hostnameRe.MatchString(s)
}

var (
	cfAccountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	cfTokenRe   = regexp.MustCompile(`^[A-Za-z0-9_\-]{20,200}$`)
)

// ValidCloudflareAccountID matches mesh.ValidAccountID.
func ValidCloudflareAccountID(s string) bool { return cfAccountRe.MatchString(s) }

// ValidCloudflareToken matches mesh.ValidAPIToken.
func ValidCloudflareToken(s string) bool { return cfTokenRe.MatchString(s) }

// ------------------------------------------------------------ servers ---

// ServerInput creates a server; ServerPatch changes the non-nil fields.
type ServerInput struct {
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	Port         int      `json:"port"`
	User         string   `json:"user"`
	Auth         string   `json:"auth"`
	CredentialID string   `json:"credential_id"`
	Tags         []string `json:"tags"`
	Notes        string   `json:"notes"`
	// Channel is the management channel (nil or mode direct: direct).
	Channel *model.ManagementChannel `json:"channel"`
}

type ServerPatch struct {
	Name         *string   `json:"name"`
	Address      *string   `json:"address"`
	Port         *int      `json:"port"`
	User         *string   `json:"user"`
	Auth         *string   `json:"auth"`
	CredentialID *string   `json:"credential_id"`
	Tags         *[]string `json:"tags"`
	Notes        *string   `json:"notes"`
	// Channel replaces the management channel ({"mode":"direct"} goes back
	// to the direct connection).
	Channel *model.ManagementChannel `json:"channel"`
}

func (i *index) checkServer(sv *model.Server) error {
	var err error
	if sv.Name, err = checkText("name", sv.Name, 64, true); err != nil {
		return err
	}
	sv.Address = strings.TrimSpace(sv.Address)
	if !ValidAddress(sv.Address) {
		return errf(CodeInvalid, "address", "地址应为 IP 或主机名")
	}
	if sv.Port == 0 {
		sv.Port = 22
	}
	if sv.Port < 1 || sv.Port > 65535 {
		return errf(CodeInvalid, "port", "端口应在 1–65535")
	}
	sv.User = strings.TrimSpace(sv.User)
	if sv.User == "" {
		sv.User = "root"
	}
	if !userRe.MatchString(sv.User) {
		return errf(CodeInvalid, "user", "用户名只允许字母、数字、_ . -，且不能以数字或 - 开头")
	}
	if sv.Auth == "" {
		sv.Auth = model.AuthKey
	}
	if sv.Auth != model.AuthPassword && sv.Auth != model.AuthKey {
		return errf(CodeInvalid, "auth", "认证方式只能是 password 或 key")
	}
	sv.CredentialID = strings.TrimSpace(sv.CredentialID)
	if sv.CredentialID != "" {
		n := i.cred(sv.CredentialID)
		if n < 0 {
			return errf(CodeNotFound, "credential_id", "SSH 凭据 %s 不存在", sv.CredentialID)
		}
		want := KindPrivateKey
		if sv.Auth == model.AuthPassword {
			want = KindPassword
		}
		if i.Credentials[n].Kind != want {
			return errf(CodeKindMismatch, "credential_id", "认证方式 %s 需要 %s 类型的凭据", sv.Auth, want)
		}
	}
	if len(sv.Tags) > 16 {
		return errf(CodeInvalid, "tags", "最多 16 个标签")
	}
	seen := map[string]bool{}
	var tags []string
	for _, t := range sv.Tags {
		t = strings.TrimSpace(t)
		if !tagRe.MatchString(t) {
			return errf(CodeInvalid, "tags", "标签只允许文字、数字和 _ . : -，最长 32 个字符")
		}
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	sv.Tags = tags
	if sv.Notes, err = checkText("notes", sv.Notes, 2000, false); err != nil {
		return err
	}
	if sv.HostKey.State == "" {
		sv.HostKey.State = model.HostKeyUnknown
	}
	return i.checkChannel(sv)
}

// checkChannel normalises and validates a server's management channel. A
// direct channel is stored as nil (so a server without a channel looks
// exactly as before). A tunnel channel needs an IP address; a jump channel
// needs another existing server that is itself reached directly (one hop,
// no chains, no cycles).
func (i *index) checkChannel(sv *model.Server) error {
	ch := sv.Channel
	if ch == nil {
		return nil
	}
	c := *ch
	c.Mode = strings.TrimSpace(c.Mode)
	c.Address = strings.TrimSpace(c.Address)
	c.ViaServerID = strings.TrimSpace(c.ViaServerID)
	if c.Port != 0 && (c.Port < 1 || c.Port > 65535) {
		return errf(CodeInvalid, "channel.port", "管理通道的端口应在 1–65535")
	}
	switch c.Mode {
	case "", model.ChannelDirect:
		if c.Address != "" || c.Port != 0 || c.ViaServerID != "" {
			return errf(CodeInvalid, "channel", "直连不需要通道地址、端口或中继")
		}
		sv.Channel = nil
		return nil
	case model.ChannelTunnel:
		if c.ViaServerID != "" {
			return errf(CodeInvalid, "channel.via_server_id", "经隧道地址管理不经过中继；要经中继跳转请选「跳转」")
		}
		if err := checkChannelAddr(c.Address, true); err != nil {
			return err
		}
	case model.ChannelJump:
		if c.Address != "" {
			if err := checkChannelAddr(c.Address, false); err != nil {
				return err
			}
		}
		if c.ViaServerID == "" {
			return errf(CodeInvalid, "channel.via_server_id", "跳转需要选择一台受管中继服务器")
		}
		if c.ViaServerID == sv.ID {
			return errf(CodeInvalid, "channel.via_server_id", "服务器不能经自己跳转")
		}
		n := i.server(c.ViaServerID)
		if n < 0 {
			return errf(CodeNotFound, "channel.via_server_id", "跳转用的服务器 %s 不存在", c.ViaServerID)
		}
		if i.Servers[n].Channel.ChannelMode() != model.ChannelDirect {
			return errf(CodeInvalid, "channel.via_server_id", "跳转用的服务器 %s 自己也经通道管理；只支持一跳（中继必须是直连的）", i.Servers[n].Name)
		}
	default:
		return errf(CodeInvalid, "channel.mode", "管理通道只能是 direct、tunnel 或 jump")
	}
	sv.Channel = &c
	return nil
}

// checkChannelAddr: an IP literal (no name: nothing is resolved on the
// way), not unspecified, multicast or broadcast.
func checkChannelAddr(s string, required bool) error {
	if s == "" {
		if required {
			return errf(CodeInvalid, "channel.address", "经隧道地址管理需要填写这台服务器的隧道地址（IP）")
		}
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return errf(CodeInvalid, "channel.address", "通道地址应为 IP 地址（不接受主机名）")
	}
	if a.IsUnspecified() || a.IsMulticast() || (a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		return errf(CodeInvalid, "channel.address", "通道地址不能是未指定、组播或广播地址")
	}
	return nil
}

// ChannelUsers lists the servers whose jump channel goes through id.
func (i *index) channelUsers(id string) []model.Server {
	var out []model.Server
	for _, sv := range i.Servers {
		if sv.Channel != nil && sv.Channel.Mode == model.ChannelJump && sv.Channel.ViaServerID == id {
			out = append(out, sv)
		}
	}
	return out
}

// Servers lists the servers, sorted by name.
func (s *Store) Servers() []model.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := cloneIndex(s.idx).Servers
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// Server returns one server.
func (s *Store) Server(id string) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.server(id)
	if n < 0 {
		return model.Server{}, errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	return cloneIndex(s.idx).Servers[n], nil
}

// CreateServer adds a server with a new ID and an unknown host key.
func (s *Store) CreateServer(in ServerInput) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	now := s.now()
	sv := model.Server{ID: newID("srv"), Name: in.Name, Address: in.Address, Port: in.Port, User: in.User, Auth: in.Auth,
		CredentialID: in.CredentialID, Tags: in.Tags, Notes: in.Notes, HostKey: model.HostKey{State: model.HostKeyUnknown},
		CreatedAt: now, UpdatedAt: now, Channel: in.Channel}
	if err := next.checkServer(&sv); err != nil {
		return model.Server{}, err
	}
	next.Servers = append(next.Servers, sv)
	if err := s.commit(next, nil); err != nil {
		return model.Server{}, err
	}
	return sv, nil
}

// UpdateServer changes the given fields. A new address or port clears the
// host key record (another endpoint is another identity).
func (s *Store) UpdateServer(id string, p ServerPatch) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.server(id)
	if n < 0 {
		return model.Server{}, errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	sv := next.Servers[n]
	old := sv
	oldAddr, oldPort := sv.Address, sv.Port
	if p.Name != nil {
		sv.Name = *p.Name
	}
	if p.Address != nil {
		sv.Address = *p.Address
	}
	if p.Port != nil {
		sv.Port = *p.Port
	}
	if p.User != nil {
		sv.User = *p.User
	}
	if p.Auth != nil {
		sv.Auth = *p.Auth
		if p.CredentialID == nil && sv.CredentialID != "" {
			// Switching the method drops a credential of the other kind.
			if c := next.cred(sv.CredentialID); c >= 0 && (next.Credentials[c].Kind == KindPassword) != (sv.Auth == model.AuthPassword) {
				sv.CredentialID = ""
			}
		}
	}
	if p.CredentialID != nil {
		sv.CredentialID = *p.CredentialID
	}
	if p.Tags != nil {
		sv.Tags = *p.Tags
	}
	if p.Notes != nil {
		sv.Notes = *p.Notes
	}
	if p.Channel != nil {
		ch := *p.Channel
		sv.Channel = &ch
	}
	if err := next.checkServer(&sv); err != nil {
		return model.Server{}, err
	}
	if sv.Channel.ChannelMode() != model.ChannelDirect {
		if users := next.channelUsers(id); len(users) > 0 {
			return model.Server{}, errf(CodeInvalid, "channel", "服务器 %s 是 %s 的跳转中继，中继本身必须直连；先改掉那些服务器的通道", old.Name, users[0].Name)
		}
	}
	if !sameChannel(sv.Channel, old.Channel) {
		// The channel is transport, not identity: a deployment pin and the
		// host key stay; the last connection test was over the old path.
		sv.LastTest = nil
	}
	repointed := sv.Address != old.Address || sv.Port != old.Port || sv.User != old.User || sv.Auth != old.Auth || sv.CredentialID != old.CredentialID
	if repointed {
		// A deployment that is not fully withdrawn will reconnect to
		// exactly this endpoint with exactly this credential.
		if refs := s.deploymentRefsServer(&s.idx, id); len(refs) > 0 {
			return model.Server{}, &Error{Code: CodeInUse, Field: "address", InUse: refs,
				Msg: fmt.Sprintf("服务器 %s 被未撤回完的部署固定；撤回前不能修改地址、端口、用户、认证方式或凭据（名称、标签、备注可以改；凭据可以原地轮换）", old.Name)}
		}
		sv.LastTest = nil
	}
	if sv.Address != oldAddr || sv.Port != oldPort {
		sv.HostKey = model.HostKey{State: model.HostKeyUnknown}
	}
	sv.UpdatedAt = s.now()
	next.Servers[n] = sv
	if err := s.commit(next, nil); err != nil {
		return model.Server{}, err
	}
	return sv, nil
}

// DeleteServer removes a server. References from the topology and Mesh
// deployments are checked by the caller (internal/api) before.
func (s *Store) DeleteServer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.server(id)
	if n < 0 {
		return errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	if refs := s.deploymentRefsServer(&s.idx, id); len(refs) > 0 {
		return &Error{Code: CodeInUse, InUse: refs, Msg: fmt.Sprintf("服务器 %s 被未撤回完的部署固定，撤回需要它；先撤回再删除", next.Servers[n].Name)}
	}
	if users := next.channelUsers(id); len(users) > 0 {
		var refs []Ref
		for _, u := range users {
			refs = append(refs, Ref{Kind: "server", ID: u.ID, Name: u.Name})
		}
		return &Error{Code: CodeInUse, InUse: refs, Msg: fmt.Sprintf("服务器 %s 是其它服务器的跳转中继；先改掉它们的管理通道再删除", next.Servers[n].Name)}
	}
	next.Servers = append(next.Servers[:n], next.Servers[n+1:]...)
	return s.commit(next, nil)
}

func sameChannel(a, b *model.ManagementChannel) bool {
	if a.ChannelMode() == model.ChannelDirect || b.ChannelMode() == model.ChannelDirect {
		return a.ChannelMode() == b.ChannelMode()
	}
	return *a == *b
}

var fpRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// ValidFingerprint reports whether s is an ssh.FingerprintSHA256 value.
func ValidFingerprint(s string) bool { return fpRe.MatchString(s) }

// ObserveHostKey records the host key a server presented on connection.
// It returns a *Error with CodeHostKeyMismatch when the server is pinned to
// another key (the connection must then be refused), and nil otherwise; a
// nil error does not mean the key is trusted: check the returned state.
func (s *Store) ObserveHostKey(id, keyType, fingerprint string) (model.Server, error) {
	if !ValidFingerprint(fingerprint) {
		return model.Server{}, errf(CodeInvalid, "fingerprint", "指纹格式应为 SHA256:…")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.server(id)
	if n < 0 {
		return model.Server{}, errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	sv := next.Servers[n]
	hk := sv.HostKey
	now := s.now()
	var mismatch error
	switch {
	case (hk.State == model.HostKeyTrusted || hk.State == model.HostKeyMismatch) && hk.Fingerprint == fingerprint:
		hk.State, hk.Seen, hk.SeenKeyType, hk.SeenAt = model.HostKeyTrusted, "", "", ""
	case hk.State == model.HostKeyTrusted || hk.State == model.HostKeyMismatch:
		hk.State, hk.Seen, hk.SeenKeyType, hk.SeenAt = model.HostKeyMismatch, fingerprint, keyType, now
		mismatch = &Error{Code: CodeHostKeyMismatch, Field: "fingerprint",
			Msg: fmt.Sprintf("%s 出示的主机指纹是 %s，不是已固定的 %s；拒绝连接", sv.Name, fingerprint, hk.Fingerprint)}
	default:
		hk.State, hk.Seen, hk.SeenKeyType, hk.SeenAt = model.HostKeyDiscovered, fingerprint, keyType, now
	}
	if hk == sv.HostKey {
		return sv, mismatch
	}
	sv.HostKey = hk
	next.Servers[n] = sv
	if err := s.commit(next, nil); err != nil {
		return model.Server{}, err
	}
	return sv, mismatch
}

// TrustHostKey pins the fingerprint the operator confirmed. It must equal
// the one awaiting confirmation (discovered, or the new key of a mismatch).
func (s *Store) TrustHostKey(id, fingerprint string) (model.Server, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if !ValidFingerprint(fingerprint) {
		return model.Server{}, errf(CodeInvalid, "fingerprint", "指纹格式应为 SHA256:…")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.server(id)
	if n < 0 {
		return model.Server{}, errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	sv := next.Servers[n]
	hk := sv.HostKey
	switch {
	case hk.State == model.HostKeyTrusted && hk.Fingerprint == fingerprint:
		return sv, nil
	case hk.Seen == "" || (hk.State != model.HostKeyDiscovered && hk.State != model.HostKeyMismatch):
		return model.Server{}, errf(CodeHostKeyNotSeen, "fingerprint", "还没有发现 %s 的主机指纹，先连接一次再确认", sv.Name)
	case hk.Seen != fingerprint:
		return model.Server{}, errf(CodeHostKeyChanged, "fingerprint", "确认的指纹与发现的 %s 不一致，未固定", hk.Seen)
	}
	sv.HostKey = model.HostKey{State: model.HostKeyTrusted, Fingerprint: fingerprint, KeyType: hk.SeenKeyType, PinnedAt: s.now(), Source: "operator"}
	sv.UpdatedAt = s.now()
	next.Servers[n] = sv
	if err := s.commit(next, nil); err != nil {
		return model.Server{}, err
	}
	return sv, nil
}

// ForgetHostKey clears the host key record (back to unknown).
func (s *Store) ForgetHostKey(id string) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.server(id)
	if n < 0 {
		return model.Server{}, errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	next.Servers[n].HostKey = model.HostKey{State: model.HostKeyUnknown}
	next.Servers[n].UpdatedAt = s.now()
	if err := s.commit(next, nil); err != nil {
		return model.Server{}, err
	}
	return next.Servers[n], nil
}

// ---------------------------------------------------- SSH credentials ---

// SSHSecretInput is the secret part of creating or rotating a credential.
type SSHSecretInput struct {
	Kind       string `json:"kind"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase"`
	// Generate asks for a new ed25519 key pair (kind private_key).
	Generate bool   `json:"generate"`
	Comment  string `json:"comment"`
}

// Secrets returns the secret strings of in (for scrubbing error text).
func (in SSHSecretInput) Secrets() []string {
	return []string{in.Password, in.PrivateKey, in.Passphrase}
}

const (
	maxPassword   = 1024
	maxPrivateKey = 16 << 10
)

// buildSSHSecret validates in and derives the public metadata. Messages
// never contain the input.
func buildSSHSecret(in SSHSecretInput) (secret, SSHCredential, error) {
	var meta SSHCredential
	comment, err := checkText("comment", in.Comment, 128, false)
	if err != nil {
		return secret{}, meta, err
	}
	switch in.Kind {
	case KindPassword:
		if in.Generate || in.PrivateKey != "" {
			return secret{}, meta, errf(CodeInvalid, "kind", "密码凭据不接受私钥或 generate")
		}
		if in.Password == "" {
			return secret{}, meta, errf(CodeInvalid, "password", "密码不能为空")
		}
		if len(in.Password) > maxPassword || strings.ContainsRune(in.Password, 0) || !utf8.ValidString(in.Password) {
			return secret{}, meta, errf(CodeInvalid, "password", "密码过长或含不允许的字符")
		}
		meta.Kind = KindPassword
		return secret{Kind: KindPassword, Password: in.Password}, meta, nil
	case KindPrivateKey:
	default:
		return secret{}, meta, errf(CodeInvalid, "kind", "种类只能是 password 或 private_key")
	}
	if in.Password != "" {
		return secret{}, meta, errf(CodeInvalid, "password", "私钥凭据不接受 password 字段")
	}
	meta.Kind = KindPrivateKey
	meta.Comment = comment
	var pemText string
	var signer ssh.Signer
	if in.Generate {
		if in.PrivateKey != "" || in.Passphrase != "" {
			return secret{}, meta, errf(CodeInvalid, "generate", "generate 时不能同时提供私钥或口令")
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return secret{}, meta, errf(CodeStorage, "", "生成密钥失败")
		}
		blk, err := ssh.MarshalPrivateKey(priv, comment)
		if err != nil {
			return secret{}, meta, errf(CodeStorage, "", "生成密钥失败")
		}
		pemText = string(pem.EncodeToMemory(blk))
		if signer, err = ssh.NewSignerFromKey(priv); err != nil {
			return secret{}, meta, errf(CodeStorage, "", "生成密钥失败")
		}
		meta.Generated = true
	} else {
		pemText = strings.TrimSpace(in.PrivateKey) + "\n"
		if strings.TrimSpace(in.PrivateKey) == "" {
			return secret{}, meta, errf(CodeInvalid, "private_key", "私钥不能为空")
		}
		if len(pemText) > maxPrivateKey {
			return secret{}, meta, errf(CodeInvalid, "private_key", "私钥过长")
		}
		raw, err := ssh.ParseRawPrivateKey([]byte(pemText))
		var missing *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &missing):
			if in.Passphrase == "" {
				return secret{}, meta, errf(CodePassphraseRequired, "passphrase", "这把私钥有口令保护，请同时填写口令")
			}
			raw, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(pemText), []byte(in.Passphrase))
			if err != nil {
				return secret{}, meta, errf(CodePassphraseInvalid, "passphrase", "口令不正确或私钥无法解密")
			}
			meta.HasPassphrase = true
		case err != nil:
			return secret{}, meta, errf(CodeInvalidKey, "private_key", "无法识别的私钥（支持 OpenSSH / PEM 格式的 ed25519、ECDSA、RSA）")
		}
		if signer, err = ssh.NewSignerFromKey(raw); err != nil {
			return secret{}, meta, errf(CodeInvalidKey, "private_key", "无法识别的私钥")
		}
	}
	pub := signer.PublicKey()
	meta.KeyType = pub.Type()
	meta.Fingerprint = ssh.FingerprintSHA256(pub)
	meta.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		meta.PublicKey += " " + comment
	}
	sec := secret{Kind: KindPrivateKey, PrivateKey: pemText}
	if meta.HasPassphrase {
		sec.Passphrase = in.Passphrase
	}
	return sec, meta, nil
}

// SSHCredentials lists the credentials (metadata only), sorted by name.
func (s *Store) SSHCredentials() []SSHCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SSHCredential, 0, len(s.idx.Credentials))
	for _, c := range s.idx.Credentials {
		out = append(out, c.SSHCredential)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// SSHCredential returns one credential's metadata.
func (s *Store) SSHCredential(id string) (SSHCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.cred(id)
	if n < 0 {
		return SSHCredential{}, errf(CodeNotFound, "", "SSH 凭据 %s 不存在", id)
	}
	return s.idx.Credentials[n].SSHCredential, nil
}

// SSHCredentialGen returns the generation of a credential's secret: it
// changes whenever the secret is replaced (RotateSSHCredential), so a
// connection authenticated under an older generation can be recognised
// (sshexec.Pool never reuses one).
func (s *Store) SSHCredentialGen(id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.cred(id)
	if n < 0 {
		return 0, errf(CodeNotFound, "", "SSH 凭据 %s 不存在", id)
	}
	return s.idx.Credentials[n].Gen, nil
}

// CreateSSHCredential stores a new credential.
func (s *Store) CreateSSHCredential(name, notes string, in SSHSecretInput) (SSHCredential, error) {
	name, err := checkText("name", name, 64, true)
	if err != nil {
		return SSHCredential{}, err
	}
	if notes, err = checkText("notes", notes, 2000, false); err != nil {
		return SSHCredential{}, err
	}
	sec, meta, err := buildSSHSecret(in)
	if err != nil {
		return SSHCredential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	now := s.now()
	meta.ID, meta.Name, meta.Notes, meta.SecretSet, meta.CreatedAt, meta.UpdatedAt = newID("key"), name, notes, true, now, now
	rec := credRecord{SSHCredential: meta, Gen: 1}
	next.Credentials = append(next.Credentials, rec)
	if err := s.commit(next, map[string]secret{s.secretPath(meta.ID, 1): sec}); err != nil {
		return SSHCredential{}, err
	}
	return meta, nil
}

// CredentialPatch changes a credential's descriptive fields.
type CredentialPatch struct {
	Name    *string `json:"name"`
	Notes   *string `json:"notes"`
	Comment *string `json:"comment"`
}

// UpdateSSHCredential changes name, notes or (for keys) the comment shown
// after the public key. The secret is unchanged.
func (s *Store) UpdateSSHCredential(id string, p CredentialPatch) (SSHCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.cred(id)
	if n < 0 {
		return SSHCredential{}, errf(CodeNotFound, "", "SSH 凭据 %s 不存在", id)
	}
	c := next.Credentials[n]
	var err error
	if p.Name != nil {
		if c.Name, err = checkText("name", *p.Name, 64, true); err != nil {
			return SSHCredential{}, err
		}
	}
	if p.Notes != nil {
		if c.Notes, err = checkText("notes", *p.Notes, 2000, false); err != nil {
			return SSHCredential{}, err
		}
	}
	if p.Comment != nil {
		if c.Kind != KindPrivateKey {
			return SSHCredential{}, errf(CodeKindMismatch, "comment", "只有私钥有注释")
		}
		cm, err := checkText("comment", *p.Comment, 128, false)
		if err != nil {
			return SSHCredential{}, err
		}
		fields := strings.Fields(c.PublicKey)
		if len(fields) >= 2 {
			c.PublicKey = fields[0] + " " + fields[1]
			if cm != "" {
				c.PublicKey += " " + cm
			}
		}
		c.Comment = cm
	}
	c.UpdatedAt = s.now()
	next.Credentials[n] = c
	if err := s.commit(next, nil); err != nil {
		return SSHCredential{}, err
	}
	return c.SSHCredential, nil
}

// RotateSSHCredential replaces the secret under the same ID. The kind
// cannot change (servers chose their auth method by it).
func (s *Store) RotateSSHCredential(id string, in SSHSecretInput) (SSHCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.cred(id)
	if n < 0 {
		return SSHCredential{}, errf(CodeNotFound, "", "SSH 凭据 %s 不存在", id)
	}
	c := next.Credentials[n]
	if in.Kind == "" {
		in.Kind = c.Kind
	}
	if in.Kind != c.Kind {
		return SSHCredential{}, errf(CodeKindMismatch, "kind", "轮换不能改变种类（当前是 %s）；需要另一种请新建凭据", c.Kind)
	}
	if in.Comment == "" && c.Kind == KindPrivateKey {
		in.Comment = c.Comment
	}
	sec, meta, err := buildSSHSecret(in)
	if err != nil {
		return SSHCredential{}, err
	}
	now := s.now()
	meta.ID, meta.Name, meta.Notes, meta.SecretSet, meta.CreatedAt, meta.UpdatedAt, meta.RotatedAt = c.ID, c.Name, c.Notes, true, c.CreatedAt, now, now
	rec := credRecord{SSHCredential: meta, Gen: c.Gen + 1}
	next.Credentials[n] = rec
	for k := range next.Servers {
		if next.Servers[k].CredentialID == id {
			next.Servers[k].LastTest = nil
		}
	}
	if err := s.commit(next, map[string]secret{s.secretPath(id, rec.Gen): sec}); err != nil {
		return SSHCredential{}, err
	}
	return meta, nil
}

// DeleteSSHCredential removes a credential no server refers to. Other
// referrers (deployments) are checked by the caller before.
func (s *Store) DeleteSSHCredential(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.cred(id)
	if n < 0 {
		return errf(CodeNotFound, "", "SSH 凭据 %s 不存在", id)
	}
	if refs := next.serversUsing(id); len(refs) > 0 {
		return &Error{Code: CodeInUse, Msg: fmt.Sprintf("SSH 凭据 %s 仍被 %d 台服务器使用，先改用别的凭据", next.Credentials[n].Name, len(refs)), InUse: refs}
	}
	if refs := s.deploymentRefsCred(&s.idx, id); len(refs) > 0 {
		return &Error{Code: CodeInUse, Msg: fmt.Sprintf("SSH 凭据 %s 被未撤回完的部署固定，撤回需要它；先撤回再删除（可以原地轮换）", next.Credentials[n].Name), InUse: refs}
	}
	next.Credentials = append(next.Credentials[:n], next.Credentials[n+1:]...)
	return s.commit(next, nil)
}

func (i *index) serversUsing(credID string) []Ref {
	var refs []Ref
	for _, sv := range i.Servers {
		if sv.CredentialID == credID {
			refs = append(refs, Ref{Kind: "server", ID: sv.ID, Name: sv.Name})
		}
	}
	return refs
}

// ServersUsing lists the servers that refer to a credential.
func (s *Store) ServersUsing(credID string) []Ref {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idx.serversUsing(credID)
}

// SSHAuth is everything needed to log in to a server. It holds secrets:
// use it at the execution boundary only and never log or return it.
type SSHAuth struct {
	Server       model.Server
	CredentialID string
	Kind         string // KindPassword | KindPrivateKey
	Password     string
	PrivateKey   string
	Passphrase   string
}

// Secrets returns the secret strings (for scrubbing output).
func (a SSHAuth) Secrets() []string { return []string{a.Password, a.PrivateKey, a.Passphrase} }

// ResolveSSH returns a server with its credential's secret.
func (s *Store) ResolveSSH(serverID string) (SSHAuth, error) {
	return s.ResolveSSHWith(serverID, "")
}

// CodeNoCredential: the server has no SSH credential selected.
const CodeNoCredential = "no_credential"

// ResolveSSHWith returns a server with the secret of credentialID, or of
// the server's own credential when credentialID is "" (a deployment
// withdrawal passes the credential it pinned, whatever the server's
// current selection). The current generation is read, so a credential
// rotated in place is used with its new secret.
func (s *Store) ResolveSSHWith(serverID, credentialID string) (SSHAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.server(serverID)
	if n < 0 {
		return SSHAuth{}, errf(CodeNotFound, "server_id", "服务器 %s 不存在", serverID)
	}
	sv := s.idx.Servers[n]
	if credentialID == "" {
		credentialID = sv.CredentialID
	}
	if credentialID == "" {
		return SSHAuth{}, errf(CodeNoCredential, "credential_id", "服务器 %s 还没有选择 SSH 凭据", sv.Name)
	}
	c := s.idx.cred(credentialID)
	if c < 0 {
		return SSHAuth{}, errf(CodeNotFound, "credential_id", "服务器 %s 使用的 SSH 凭据 %s 不存在", sv.Name, credentialID)
	}
	sec, err := s.readSecret(credentialID, s.idx.Credentials[c].Gen)
	if err != nil {
		return SSHAuth{}, err
	}
	return SSHAuth{Server: sv, CredentialID: credentialID, Kind: s.idx.Credentials[c].Kind,
		Password: sec.Password, PrivateKey: sec.PrivateKey, Passphrase: sec.Passphrase}, nil
}

// RecordConnectionTest stores the last "test connection" result.
func (s *Store) RecordConnectionTest(id string, ct model.ConnectionTest) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.server(id)
	if n < 0 {
		return model.Server{}, errf(CodeNotFound, "", "服务器 %s 不存在", id)
	}
	if ct.At == "" {
		ct.At = s.now()
	}
	next.Servers[n].LastTest = &ct
	if err := s.commit(next, nil); err != nil {
		return model.Server{}, err
	}
	return next.Servers[n], nil
}

// ------------------------------------------------ Cloudflare accounts ---

// AccountInput creates an account.
type AccountInput struct {
	Name      string `json:"name"`
	AccountID string `json:"account_id"`
	APIToken  string `json:"api_token"`
	Notes     string `json:"notes"`
}

// AccountPatch changes the non-nil descriptive fields.
type AccountPatch struct {
	Name      *string `json:"name"`
	Notes     *string `json:"notes"`
	AccountID *string `json:"account_id"`
}

func checkToken(tok string) (string, error) {
	tok = strings.TrimSpace(tok)
	if !ValidCloudflareToken(tok) {
		return "", errf(CodeInvalid, "api_token", "Cloudflare API token 格式无效（只允许字母、数字、- 和 _，20–200 个字符）")
	}
	return tok, nil
}

func checkAccountID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !ValidCloudflareAccountID(id) {
		return "", errf(CodeInvalid, "account_id", "Cloudflare account id 应为 32 位小写十六进制")
	}
	return id, nil
}

// Accounts lists the Cloudflare accounts, sorted by name.
func (s *Store) Accounts() []CloudflareAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CloudflareAccount, 0, len(s.idx.Accounts))
	for _, a := range cloneIndex(s.idx).Accounts {
		out = append(out, a.CloudflareAccount)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// Account returns one account.
func (s *Store) Account(id string) (CloudflareAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.account(id)
	if n < 0 {
		return CloudflareAccount{}, errf(CodeNotFound, "", "Cloudflare 账户 %s 不存在", id)
	}
	return cloneIndex(s.idx).Accounts[n].CloudflareAccount, nil
}

// CreateAccount stores a new account and its token.
func (s *Store) CreateAccount(in AccountInput) (CloudflareAccount, error) {
	return s.createAccount("", in, "")
}

func (s *Store) createAccount(id string, in AccountInput, migratedFrom string) (CloudflareAccount, error) {
	name, err := checkText("name", in.Name, 64, true)
	if err != nil {
		return CloudflareAccount{}, err
	}
	notes, err := checkText("notes", in.Notes, 2000, false)
	if err != nil {
		return CloudflareAccount{}, err
	}
	acct, err := checkAccountID(in.AccountID)
	if err != nil {
		return CloudflareAccount{}, err
	}
	tok, err := checkToken(in.APIToken)
	if err != nil {
		return CloudflareAccount{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	if id == "" {
		id = newID("cf")
	} else if next.idTaken(id) {
		return CloudflareAccount{}, errf(CodeConflict, "id", "ID %s 已被占用", id)
	}
	now := s.now()
	a := CloudflareAccount{ID: id, Name: name, AccountID: acct, Notes: notes, TokenSet: true, CreatedAt: now, UpdatedAt: now, MigratedFrom: migratedFrom}
	next.Accounts = append(next.Accounts, accountRecord{CloudflareAccount: a, Gen: 1})
	if migratedFrom != "" && next.MeshAccount == "" {
		next.MeshAccount = id
	}
	if err := s.commit(next, map[string]secret{s.secretPath(id, 1): {Kind: "cloudflare_token", APIToken: tok}}); err != nil {
		return CloudflareAccount{}, err
	}
	return a, nil
}

// UpdateAccount changes descriptive fields or the account id. The caller
// enforces the Mesh binding before changing the account id.
func (s *Store) UpdateAccount(id string, p AccountPatch) (CloudflareAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.account(id)
	if n < 0 {
		return CloudflareAccount{}, errf(CodeNotFound, "", "Cloudflare 账户 %s 不存在", id)
	}
	a := next.Accounts[n]
	var err error
	if p.Name != nil {
		if a.Name, err = checkText("name", *p.Name, 64, true); err != nil {
			return CloudflareAccount{}, err
		}
	}
	if p.Notes != nil {
		if a.Notes, err = checkText("notes", *p.Notes, 2000, false); err != nil {
			return CloudflareAccount{}, err
		}
	}
	if p.AccountID != nil {
		acct, err := checkAccountID(*p.AccountID)
		if err != nil {
			return CloudflareAccount{}, err
		}
		if acct != a.AccountID {
			// The token belongs to the old account; its check is stale.
			a.AccountID, a.PermissionCheck = acct, nil
		}
	}
	a.UpdatedAt = s.now()
	next.Accounts[n] = a
	if err := s.commit(next, nil); err != nil {
		return CloudflareAccount{}, err
	}
	return a.CloudflareAccount, nil
}

// RotateAccountToken replaces the API token under the same ID and account.
func (s *Store) RotateAccountToken(id, token string) (CloudflareAccount, error) {
	tok, err := checkToken(token)
	if err != nil {
		return CloudflareAccount{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.account(id)
	if n < 0 {
		return CloudflareAccount{}, errf(CodeNotFound, "", "Cloudflare 账户 %s 不存在", id)
	}
	a := next.Accounts[n]
	a.Gen++
	now := s.now()
	a.TokenSet, a.UpdatedAt, a.RotatedAt, a.PermissionCheck = true, now, now, nil
	next.Accounts[n] = a
	if err := s.commit(next, map[string]secret{s.secretPath(id, a.Gen): {Kind: "cloudflare_token", APIToken: tok}}); err != nil {
		return CloudflareAccount{}, err
	}
	return a.CloudflareAccount, nil
}

// DeleteAccount removes an account (clearing the Mesh selection if it was
// selected). The caller enforces the Mesh binding before.
func (s *Store) DeleteAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.account(id)
	if n < 0 {
		return errf(CodeNotFound, "", "Cloudflare 账户 %s 不存在", id)
	}
	next.Accounts = append(next.Accounts[:n], next.Accounts[n+1:]...)
	if next.MeshAccount == id {
		next.MeshAccount = ""
	}
	return s.commit(next, nil)
}

// AccountToken returns an account's API token (execution boundary only).
func (s *Store) AccountToken(id string) (CloudflareAccount, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.account(id)
	if n < 0 {
		return CloudflareAccount{}, "", errf(CodeNotFound, "", "Cloudflare 账户 %s 不存在", id)
	}
	a := s.idx.Accounts[n]
	sec, err := s.readSecret(id, a.Gen)
	if err != nil {
		return CloudflareAccount{}, "", err
	}
	return a.CloudflareAccount, sec.APIToken, nil
}

// MeshAccount is the ID of the account Mesh uses ("" when none).
func (s *Store) MeshAccount() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idx.MeshAccount
}

// SetMeshAccount selects the account Mesh uses ("" clears). The caller
// enforces the Mesh binding before.
func (s *Store) SetMeshAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	if id != "" && next.account(id) < 0 {
		return errf(CodeNotFound, "account", "Cloudflare 账户 %s 不存在", id)
	}
	if next.MeshAccount == id {
		return nil
	}
	next.MeshAccount = id
	return s.commit(next, nil)
}

// RecordPermissionCheck stores the result of a token permission check.
func (s *Store) RecordPermissionCheck(id string, pc PermissionCheck) (CloudflareAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	n := next.account(id)
	if n < 0 {
		return CloudflareAccount{}, errf(CodeNotFound, "", "Cloudflare 账户 %s 不存在", id)
	}
	if pc.CheckedAt == "" {
		pc.CheckedAt = s.now()
	}
	next.Accounts[n].PermissionCheck = &pc
	if err := s.commit(next, nil); err != nil {
		return CloudflareAccount{}, err
	}
	return next.Accounts[n].CloudflareAccount, nil
}

// AccountByCloudflareID finds the stored account with a Cloudflare id.
func (s *Store) AccountByCloudflareID(acct string) (CloudflareAccount, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.idx.Accounts {
		if a.AccountID == acct {
			return a.CloudflareAccount, true
		}
	}
	return CloudflareAccount{}, false
}

// ----------------------------------------------------------- scrubbing ---

// Scrub replaces every non-empty secret in text, whatever its length, and
// every longer line of a multi-line secret (a PEM body echoed in pieces).
func Scrub(text string, secrets ...string) string {
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		text = strings.ReplaceAll(text, sec, "***")
		if t := strings.TrimSpace(sec); t != "" && t != sec {
			text = strings.ReplaceAll(text, t, "***")
		}
		if strings.Contains(sec, "\n") {
			for _, line := range strings.Split(sec, "\n") {
				if line = strings.TrimSpace(line); len(line) >= 16 {
					text = strings.ReplaceAll(text, line, "***")
				}
			}
		}
	}
	return text
}

// ----------------------------------------------------------- migration ---

// LegacyCloudflareID is the fixed ID of the account imported from
// <DataDir>/mesh/cloudflare.json, so an interrupted import is recognised.
const LegacyCloudflareID = "cf-mesh"

// LegacyCloudflareSource is the migrated_from value of that account.
const LegacyCloudflareSource = "mesh/cloudflare.json"

// MigrateLegacyCloudflare imports the Mesh card's credential file (written
// by internal/mesh.CredStore) as account cf-mesh, selects it for Mesh when
// nothing is selected, and only then removes the file. It is idempotent: an
// account already imported from the file only causes the file's removal.
// A file that is too open or unreadable is left alone and reported.
func (s *Store) MigrateLegacyCloudflare(path string) (bool, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	}
	b, err := readPrivate(path)
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			return false, ce
		}
		return false, errf(CodeStorage, "", "读取旧 Cloudflare 凭据失败：%v", err)
	}
	var legacy struct {
		AccountID string `json:"account_id"`
		APIToken  string `json:"api_token"`
	}
	if err := json.Unmarshal(b, &legacy); err != nil {
		return false, errf(CodeStorage, "", "旧 Cloudflare 凭据文件损坏，未迁移")
	}
	if existing, err := s.Account(LegacyCloudflareID); err == nil {
		if existing.MigratedFrom != LegacyCloudflareSource || existing.AccountID != strings.TrimSpace(legacy.AccountID) {
			return false, errf(CodeConflict, "", "旧 Cloudflare 凭据文件与已迁移的账户 %s 不一致，保留文件未处理", LegacyCloudflareID)
		}
	} else {
		if _, err := s.createAccount(LegacyCloudflareID, AccountInput{Name: "Mesh 账户（迁移）", AccountID: legacy.AccountID, APIToken: legacy.APIToken}, LegacyCloudflareSource); err != nil {
			return false, err
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return true, errf(CodeStorage, "", "已迁移，但删除旧文件失败：%v", err)
	}
	return true, nil
}

// HostPin is a host identity a Mesh deployment pinned for a node.
type HostPin struct {
	NodeID      string
	Address     string
	Port        int
	Fingerprint string
}

var nodeIDSafe = regexp.MustCompile(`[^a-z0-9-]+`)

// MigrateNodes turns the ssh_* fields of topology nodes into servers. It
// writes the servers first and then sets node.ServerID and clears the
// fields in t; the caller saves t. A server already created from a node by
// an interrupted run (same migrated_from) is linked, not duplicated. The
// gateway (local host), nodes without an SSH host and RFC 2606 ".invalid"
// example hosts are skipped. Returns whether t changed.
func (s *Store) MigrateNodes(t *model.Topology, pins []HostPin) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	now := s.now()
	type link struct {
		node int
		id   string
	}
	var links []link
	added := false
	for i, n := range t.Nodes {
		if n.Role == model.RoleGateway || n.ServerID != "" {
			continue
		}
		host := strings.TrimSpace(n.SSHHost)
		if host == "" || strings.HasSuffix(strings.TrimSuffix(strings.ToLower(host), "."), ".invalid") {
			continue
		}
		from := "node:" + n.ID
		id := ""
		for _, sv := range next.Servers {
			if sv.MigratedFrom == from {
				id = sv.ID
				break
			}
		}
		if id == "" {
			cand := "srv-" + strings.Trim(nodeIDSafe.ReplaceAllString(strings.ToLower(n.ID), "-"), "-")
			if !ValidID(cand) || next.idTaken(cand) {
				cand = newID("srv")
			}
			name := n.Name
			if strings.TrimSpace(name) == "" {
				name = n.ID
			}
			sv := model.Server{ID: cand, Name: name, Address: host, Port: n.SSHPort, User: n.SSHUser, Auth: model.AuthKey,
				CreatedAt: now, UpdatedAt: now, MigratedFrom: from, HostKey: model.HostKey{State: model.HostKeyUnknown}}
			if r := []rune(sv.Name); len(r) > 64 {
				sv.Name = string(r[:64])
			}
			if err := next.checkServer(&sv); err != nil {
				// Not representable (bad address or user): leave the node
				// as it is and report.
				return false, &Error{Code: CodeInvalid, Field: "node:" + n.ID, Msg: fmt.Sprintf("节点 %s 的 SSH 目标无法迁移为服务器：%s", n.ID, err.Error())}
			}
			for _, p := range pins {
				if p.NodeID == n.ID && p.Address == sv.Address && p.Port == sv.Port && ValidFingerprint(p.Fingerprint) {
					sv.HostKey = model.HostKey{State: model.HostKeyTrusted, Fingerprint: p.Fingerprint, PinnedAt: now, Source: "mesh_journal"}
				}
			}
			next.Servers = append(next.Servers, sv)
			id = cand
			added = true
		}
		links = append(links, link{i, id})
	}
	if added {
		if err := s.commit(next, nil); err != nil {
			return false, err
		}
	}
	changed := false
	for _, l := range links {
		n := &t.Nodes[l.node]
		n.ServerID, n.SSHHost, n.SSHPort, n.SSHUser = l.id, "", 0, ""
		changed = true
	}
	return changed, nil
}
