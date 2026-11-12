package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/model"
	"golang.org/x/crypto/ssh"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	const hexdig = "0123456789abcdef"
	out := make([]byte, 2*n)
	for i, c := range b {
		out[2*i], out[2*i+1] = hexdig[c>>4], hexdig[c&15]
	}
	return string(out)
}

// testKey makes a throwaway OpenSSH private key, optionally encrypted.
func testKey(t *testing.T, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blk *pem.Block
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return string(pem.EncodeToMemory(blk)), sp
}

func codeOf(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// grepDir fails when any file under dir contains needle.
func grepDir(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), needle) {
			hits = append(hits, p)
		}
		return nil
	})
	return hits
}

func TestStoragePermissionsAndAtomicFiles(t *testing.T) {
	s, dir := open(t)
	pw := randHex(t, 2) // a 4-character password
	c, err := s.CreateSSHCredential("ops", "", SSHSecretInput{Kind: KindPassword, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, filepath.Join(dir, "secrets")} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, err, fi.Mode())
		}
	}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %o", p, fi.Mode().Perm())
		}
		if err == nil && !fi.IsDir() && strings.HasPrefix(fi.Name(), ".tmp-") {
			t.Errorf("temp file left: %s", p)
		}
		return nil
	})
	idx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if strings.Contains(string(idx), `"`+pw+`"`) {
		t.Fatal("password in the index")
	}
	if hits := grepDir(t, dir, `"password":"`+pw+`"`); len(hits) != 1 || !strings.Contains(hits[0], filepath.Join("secrets", c.ID+"-1.json")) {
		t.Fatalf("secret file: %v", hits)
	}

	// A too-open secret file is refused on read, not used.
	sp := filepath.Join(dir, "secrets", c.ID+"-1.json")
	if err := os.Chmod(sp, 0o644); err != nil {
		t.Fatal(err)
	}
	sv, err := s.CreateServer(ServerInput{Name: "hub", Address: "203.0.113.5", Auth: model.AuthPassword, CredentialID: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSSH(sv.ID); codeOf(err) != CodeInsecureStorage || strings.Contains(err.Error(), pw) {
		t.Fatalf("too-open secret: %v", err)
	}
	_ = os.Chmod(sp, 0o600)
	auth, err := s.ResolveSSH(sv.ID)
	if err != nil || auth.Password != pw {
		t.Fatalf("resolve: %v", err)
	}

	// A too-open index is refused when the store is opened.
	if err := os.Chmod(filepath.Join(dir, "index.json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); codeOf(err) != CodeInsecureStorage {
		t.Fatalf("too-open index: %v", err)
	}
	_ = os.Chmod(filepath.Join(dir, "index.json"), 0o600)

	// A directory created too open (fresh Docker volume) is tightened.
	loose := filepath.Join(t.TempDir(), "vol")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(loose); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o700 {
		t.Fatalf("volume root left at %o", fi.Mode().Perm())
	}
}

// Rotation keeps the ID; an interrupted write leaves the index on a
// complete generation and the orphan is removed on the next open.
func TestRotationAndOrphans(t *testing.T) {
	s, dir := open(t)
	k1, pub1 := testKey(t, "")
	c, err := s.CreateSSHCredential("deploy", "", SSHSecretInput{Kind: KindPrivateKey, PrivateKey: k1, Comment: "ops@meridian"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint != ssh.FingerprintSHA256(pub1) || c.KeyType != "ssh-ed25519" || !strings.HasSuffix(c.PublicKey, " ops@meridian") || c.Generated {
		t.Fatalf("%+v", c)
	}
	r, err := s.RotateSSHCredential(c.ID, SSHSecretInput{Generate: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != c.ID || r.Fingerprint == c.Fingerprint || r.RotatedAt == "" || !r.Generated || r.Comment != "ops@meridian" {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", c.ID+"-1.json")); !os.IsNotExist(err) {
		t.Fatal("old generation kept")
	}
	auth, err := func() (SSHAuth, error) {
		sv, err := s.CreateServer(ServerInput{Name: "x", Address: "x.example.net", CredentialID: c.ID})
		if err != nil {
			return SSHAuth{}, err
		}
		return s.ResolveSSH(sv.ID)
	}()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(auth.PrivateKey))
	if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != r.Fingerprint {
		t.Fatal("rotated secret does not match its metadata")
	}
	if _, err := s.RotateSSHCredential(c.ID, SSHSecretInput{Kind: KindPassword, Password: "abcd"}); codeOf(err) != CodeKindMismatch {
		t.Fatalf("kind change: %v", err)
	}
	// Leftovers of an interrupted write.
	_ = os.WriteFile(filepath.Join(dir, "secrets", c.ID+"-9.json"), []byte(`{}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte(`x`), 0o600)
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", c.ID+"-9.json")); !os.IsNotExist(err) {
		t.Fatal("orphan generation kept")
	}
	if got, _ := s2.SSHCredential(c.ID); got.Fingerprint != r.Fingerprint {
		t.Fatal("reopened store lost the rotation")
	}
}

func TestKeyImportValidation(t *testing.T) {
	s, _ := open(t)
	pass := randHex(t, 6)
	enc, pub := testKey(t, pass)
	if _, err := s.CreateSSHCredential("k", "", SSHSecretInput{Kind: KindPrivateKey, PrivateKey: enc}); codeOf(err) != CodePassphraseRequired {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := s.CreateSSHCredential("k", "", SSHSecretInput{Kind: KindPrivateKey, PrivateKey: enc, Passphrase: "wrong-" + pass}); codeOf(err) != CodePassphraseInvalid || strings.Contains(err.Error(), pass) {
		t.Fatalf("bad passphrase: %v", err)
	}
	c, err := s.CreateSSHCredential("k", "", SSHSecretInput{Kind: KindPrivateKey, PrivateKey: enc, Passphrase: pass})
	if err != nil || !c.HasPassphrase || c.Fingerprint != ssh.FingerprintSHA256(pub) {
		t.Fatalf("%+v %v", c, err)
	}
	junk := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + randHex(t, 40) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	if _, err := s.CreateSSHCredential("k", "", SSHSecretInput{Kind: KindPrivateKey, PrivateKey: junk}); codeOf(err) != CodeInvalidKey || strings.Contains(err.Error(), junk[40:60]) {
		t.Fatalf("junk key: %v", err)
	}
	if _, err := s.CreateSSHCredential("k", "", SSHSecretInput{Kind: KindPassword}); codeOf(err) != CodeInvalid {
		t.Fatalf("empty password: %v", err)
	}
	g, err := s.CreateSSHCredential("gen", "", SSHSecretInput{Kind: KindPrivateKey, Generate: true, Comment: "meridian"})
	if err != nil || !g.Generated || !strings.HasPrefix(g.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("%+v %v", g, err)
	}
	b, _ := json.Marshal(g)
	if strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatal("metadata carries the private key")
	}
}

func TestScrubShortSecrets(t *testing.T) {
	pw := "Qx7!"
	msg := Scrub("ssh: unable to authenticate with password Qx7! for root", pw, "")
	if strings.Contains(msg, pw) {
		t.Fatal(msg)
	}
	k, _ := testKey(t, "")
	lines := strings.Split(strings.TrimSpace(k), "\n")
	msg = Scrub("parse error near "+lines[2], k)
	if strings.Contains(msg, lines[2]) {
		t.Fatal("PEM line not scrubbed")
	}
}

func TestHostKeyStates(t *testing.T) {
	s, _ := open(t)
	sv, err := s.CreateServer(ServerInput{Name: "exit", Address: "exit.example.net", Port: 2222, User: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if sv.HostKey.State != model.HostKeyUnknown || sv.Auth != model.AuthKey {
		t.Fatalf("%+v", sv)
	}
	_, p1 := testKey(t, "")
	_, p2 := testKey(t, "")
	fp1, fp2 := ssh.FingerprintSHA256(p1), ssh.FingerprintSHA256(p2)
	if _, err := s.TrustHostKey(sv.ID, fp1); codeOf(err) != CodeHostKeyNotSeen {
		t.Fatalf("trust before discovery: %v", err)
	}
	if got, err := s.ObserveHostKey(sv.ID, "ssh-ed25519", fp1); err != nil || got.HostKey.State != model.HostKeyDiscovered || got.HostKey.Seen != fp1 {
		t.Fatalf("%+v %v", got.HostKey, err)
	}
	if _, err := s.TrustHostKey(sv.ID, fp2); codeOf(err) != CodeHostKeyChanged {
		t.Fatalf("trust of another key: %v", err)
	}
	got, err := s.TrustHostKey(sv.ID, fp1)
	if err != nil || got.HostKey.State != model.HostKeyTrusted || got.HostKey.Fingerprint != fp1 || got.HostKey.PinnedAt == "" || got.HostKey.Source != "operator" {
		t.Fatalf("%+v %v", got.HostKey, err)
	}
	if got, err := s.ObserveHostKey(sv.ID, "ssh-ed25519", fp2); codeOf(err) != CodeHostKeyMismatch || got.HostKey.State != model.HostKeyMismatch || got.HostKey.Fingerprint != fp1 {
		t.Fatalf("mismatch: %+v %v", got.HostKey, err)
	}
	// The original key coming back restores trust; a new address resets.
	if got, err := s.ObserveHostKey(sv.ID, "ssh-ed25519", fp1); err != nil || got.HostKey.State != model.HostKeyTrusted {
		t.Fatalf("%+v %v", got.HostKey, err)
	}
	addr := "exit2.example.net"
	if got, err := s.UpdateServer(sv.ID, ServerPatch{Address: &addr}); err != nil || got.HostKey.State != model.HostKeyUnknown {
		t.Fatalf("%+v %v", got.HostKey, err)
	}
	bad := "-oProxyCommand=x"
	if _, err := s.UpdateServer(sv.ID, ServerPatch{Address: &bad}); codeOf(err) != CodeInvalid {
		t.Fatalf("option-like address: %v", err)
	}
}

func TestCredentialReferences(t *testing.T) {
	s, _ := open(t)
	pw, err := s.CreateSSHCredential("pw", "", SSHSecretInput{Kind: KindPassword, Password: "abcd"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateServer(ServerInput{Name: "a", Address: "a.example.net", Auth: model.AuthKey, CredentialID: pw.ID}); codeOf(err) != CodeKindMismatch {
		t.Fatalf("key auth with a password: %v", err)
	}
	sv, err := s.CreateServer(ServerInput{Name: "a", Address: "a.example.net", Auth: model.AuthPassword, CredentialID: pw.ID})
	if err != nil {
		t.Fatal(err)
	}
	err = s.DeleteSSHCredential(pw.ID)
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != CodeInUse || len(ce.InUse) != 1 || ce.InUse[0].ID != sv.ID {
		t.Fatalf("delete in use: %v", err)
	}
	key := model.AuthKey
	if got, err := s.UpdateServer(sv.ID, ServerPatch{Auth: &key}); err != nil || got.CredentialID != "" {
		t.Fatalf("switching auth must drop a password credential: %+v %v", got, err)
	}
	if err := s.DeleteSSHCredential(pw.ID); err != nil {
		t.Fatal(err)
	}
}

func legacyCF(t *testing.T, dir, acct, tok string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "cloudflare.json")
	b, _ := json.Marshal(map[string]string{"account_id": acct, "api_token": tok})
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, mode)
	return p
}

func TestMigrateLegacyCloudflareIdempotent(t *testing.T) {
	s, dir := open(t)
	acct, tok := randHex(t, 16), "tok_"+randHex(t, 16)
	p := legacyCF(t, filepath.Join(t.TempDir(), "mesh"), acct, tok, 0o600)
	if ok, err := s.MigrateLegacyCloudflare(p); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("old file kept after import")
	}
	a, got, err := s.AccountToken(LegacyCloudflareID)
	if err != nil || got != tok || a.AccountID != acct || s.MeshAccount() != LegacyCloudflareID {
		t.Fatalf("%+v %v", a, err)
	}
	// Interrupted after the index was written: the file reappears.
	p = legacyCF(t, filepath.Dir(p), acct, tok, 0o600)
	if _, err := s.MigrateLegacyCloudflare(p); err != nil {
		t.Fatal(err)
	}
	if len(s.Accounts()) != 1 {
		t.Fatalf("duplicated: %d accounts", len(s.Accounts()))
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file kept")
	}
	// Nothing to do the second time.
	if ok, err := s.MigrateLegacyCloudflare(p); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	// A too-open legacy file is not imported and kept for the operator.
	s2, _ := open(t)
	p2 := legacyCF(t, filepath.Join(t.TempDir(), "mesh"), acct, tok, 0o644)
	if _, err := s2.MigrateLegacyCloudflare(p2); codeOf(err) != CodeInsecureStorage || strings.Contains(err.Error(), tok) {
		t.Fatalf("too-open legacy file: %v", err)
	}
	if _, err := os.Stat(p2); err != nil {
		t.Fatal("refused legacy file removed")
	}
	if hits := grepDir(t, dir, tok); len(hits) != 1 {
		t.Fatalf("token copies: %v", hits)
	}
}

func TestMigrateNodesIdempotentAndInterrupted(t *testing.T) {
	s, _ := open(t)
	_, hk := testKey(t, "")
	fp := ssh.FingerprintSHA256(hk)
	topo := model.Topology{Nodes: []model.Node{
		{ID: "gw", Role: model.RoleGateway, SSHHost: "192.168.100.88"},
		{ID: "hk-hub", Name: "香港枢纽", Role: model.RoleHub, SSHHost: "198.51.100.7", SSHPort: 2200, SSHUser: "ops"},
		{ID: "jp", Role: model.RoleExit, SSHHost: "jp.example.net"},
		{ID: "sg", Role: model.RoleExit, SSHHost: "sg.example.invalid"},
		{ID: "ix", Role: model.RoleIX},
	}}
	pins := []HostPin{{NodeID: "hk-hub", Address: "198.51.100.7", Port: 2200, Fingerprint: fp}}

	// Interrupted: servers written, topology never saved.
	lost := topo
	lost.Nodes = append([]model.Node(nil), topo.Nodes...)
	if _, err := s.MigrateNodes(&lost, pins); err != nil {
		t.Fatal(err)
	}
	changed, err := s.MigrateNodes(&topo, pins)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if len(s.Servers()) != 2 {
		t.Fatalf("servers: %+v", s.Servers())
	}
	hub, _ := topo.NodeByID("hk-hub")
	if hub.ServerID != "srv-hk-hub" || hub.SSHHost != "" || hub.SSHPort != 0 || hub.SSHUser != "" {
		t.Fatalf("%+v", hub)
	}
	sv, _ := s.Server("srv-hk-hub")
	if sv.Address != "198.51.100.7" || sv.Port != 2200 || sv.User != "ops" || sv.Name != "香港枢纽" || sv.MigratedFrom != "node:hk-hub" ||
		sv.HostKey.State != model.HostKeyTrusted || sv.HostKey.Fingerprint != fp || sv.HostKey.Source != "mesh_journal" {
		t.Fatalf("%+v", sv)
	}
	jp, _ := s.Server("srv-jp")
	if jp.Port != 22 || jp.User != "root" || jp.HostKey.State != model.HostKeyUnknown {
		t.Fatalf("%+v", jp)
	}
	if gw, _ := topo.NodeByID("gw"); gw.ServerID != "" || gw.SSHHost == "" {
		t.Fatal("the gateway is not a remote server")
	}
	if sg, _ := topo.NodeByID("sg"); sg.ServerID != "" {
		t.Fatal(".invalid example host migrated")
	}
	// Second run: nothing changes.
	if changed, err := s.MigrateNodes(&topo, pins); err != nil || changed || len(s.Servers()) != 2 {
		t.Fatalf("second run: %v %v %d", changed, err, len(s.Servers()))
	}
}

func wgTestKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestWGSecretsRestricted(t *testing.T) {
	s, dir := open(t)
	key, psk := wgTestKey(t), wgTestKey(t)
	kid := s.NewWGSecretID("ra-key")
	if err := s.PutWGSecret(kid, WGPurposeRemoteKey, key); err != nil {
		t.Fatal(err)
	}
	if err := s.PutWGSecret("ra-psk-one", WGPurposeRemotePSK, psk); err != nil {
		t.Fatal(err)
	}
	if err := s.PutWGSecret("ra-psk-one", WGPurposeRemotePSK, wgTestKey(t)); err == nil {
		t.Fatal("an existing id must not be overwritten")
	}
	if err := s.PutWGSecret("ra-psk-two", WGPurposeRemotePSK, "not-a-key"); err == nil || strings.Contains(err.Error(), "not-a-key") {
		t.Fatalf("bad key must be refused without echo: %v", err)
	}
	idx, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(idx), key) || strings.Contains(string(idx), psk) {
		t.Fatal("secret material in the index")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "secrets", "*.json"))
	if len(files) != 2 {
		t.Fatalf("secret files %v", files)
	}
	for _, f := range files {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", f, fi.Mode().Perm())
		}
	}
	// Reopen: still readable; a too-open file is refused.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	all, err := s2.WGSecrets()
	if err != nil || all[kid] != key || all["ra-psk-one"] != psk {
		t.Fatalf("read back: %v", err)
	}
	if err := os.Chmod(s2.secretPath("ra-psk-one", 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.WGSecret("ra-psk-one"); err == nil {
		t.Fatal("a 0644 secret file must be refused")
	}
	_ = os.Chmod(s2.secretPath("ra-psk-one", 1), 0o600)
	if err := s2.DeleteWGSecret("ra-psk-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s2.secretPath("ra-psk-one", 1)); !os.IsNotExist(err) {
		t.Fatal("deleted secret file still on disk")
	}
	if _, err := s2.WGSecret("ra-psk-one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
