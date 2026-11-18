package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Credentials is the Cloudflare account and API token the panel uses for
// Mesh. It is stored at <DataDir>/mesh/cloudflare.json, mode 0600 in a 0700
// directory, and is never returned by the API (CredentialView is).
type Credentials struct {
	AccountID string `json:"account_id"`
	APIToken  string `json:"api_token"`
	// Ref is the credential-store account object the credentials came
	// from ("" for the old file). Never serialised.
	Ref string `json:"-"`
}

// CredentialView is what the panel may show.
type CredentialView struct {
	AccountID string `json:"account_id,omitempty"`
	TokenSet  bool   `json:"token_set"`
}

// View hides the token.
func (c Credentials) View() CredentialView {
	return CredentialView{AccountID: c.AccountID, TokenSet: c.APIToken != ""}
}

// CredentialSource is where a Deployer reads (and the old Mesh card
// writes) the Cloudflare credentials it binds to. CredStore is the original
// file; the panel passes an adapter over internal/credentials, where the
// file is migrated to (the account selected for Mesh).
type CredentialSource interface {
	Load() (Credentials, error)
	Save(Credentials) error
	Delete() error
}

// WithDeploymentLock runs fn while no deployment, withdrawal or credential
// change of a Deployer can run, so a caller can check the journal's account
// binding and change stored accounts atomically with respect to them.
func WithDeploymentLock(fn func() error) error {
	deployMu.Lock()
	defer deployMu.Unlock()
	return fn()
}

// CredStore persists Credentials in <Dir>/cloudflare.json. Since the
// credential store exists it is only read to migrate the file (and by
// tests).
type CredStore struct{ Dir string }

func (s CredStore) path() string { return filepath.Join(s.Dir, "cloudflare.json") }

// ErrNoCredentials means nothing is stored.
var ErrNoCredentials = errors.New("还没有保存 Cloudflare 凭据（部署 → Mesh → 凭据）")

// Load reads the credentials. A file readable by group or others is refused
// rather than used.
func (s CredStore) Load() (Credentials, error) {
	fi, err := os.Stat(s.path())
	if os.IsNotExist(err) {
		return Credentials{}, ErrNoCredentials
	}
	if err != nil {
		return Credentials{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return Credentials{}, fmt.Errorf("%s 权限是 %o，必须是 600；拒绝使用", s.path(), fi.Mode().Perm())
	}
	b, err := os.ReadFile(s.path())
	if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, errors.New("Cloudflare 凭据文件损坏")
	}
	return c, nil
}

// Save validates and writes the credentials (0600, atomic).
func (s CredStore) Save(c Credentials) error {
	c.AccountID = strings.TrimSpace(c.AccountID)
	c.APIToken = strings.TrimSpace(c.APIToken)
	if !ValidAccountID(c.AccountID) {
		return errors.New("Cloudflare account id 应为 32 位十六进制")
	}
	if !ValidAPIToken(c.APIToken) {
		return errors.New("Cloudflare API token 格式无效（只允许字母、数字、- 和 _，不含空白）")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	return writeAtomic(s.path(), b, 0o600)
}

// Delete removes the stored credentials.
func (s CredStore) Delete() error {
	err := os.Remove(s.path())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
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

// Redactor replaces known secrets in any text that leaves the deployer.
type Redactor struct{ secrets []string }

// Add registers a secret (ignored when short enough to collide with text).
func (r *Redactor) Add(s string) {
	if len(s) >= 8 {
		r.secrets = append(r.secrets, s)
	}
}

// Redact hides every registered secret.
func (r *Redactor) Redact(s string) string {
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}
