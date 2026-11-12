package sshexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type fixture struct {
	srv  *sshtest.Server
	cs   *credentials.Store
	conn *Connector
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	srv, err := sshtest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	cs, err := credentials.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd == TestCommand {
			return "MERIDIAN_ARCH=x86_64\nMERIDIAN_KERNEL=6.12.0-test\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n", 0
		}
		return "ran " + cmd + " with " + stdin, 0
	})
	return &fixture{srv: srv, cs: cs, conn: &Connector{Store: cs, HandshakeTimeout: 5 * time.Second}}
}

func (f *fixture) server(t *testing.T, auth, cred string) model.Server {
	t.Helper()
	sv, err := f.cs.CreateServer(credentials.ServerInput{Name: "s-" + randHex(3), Address: f.srv.Host, Port: f.srv.Port, User: "ops", Auth: auth, CredentialID: cred})
	if err != nil {
		t.Fatal(err)
	}
	return sv
}

func (f *fixture) trust(t *testing.T, id string) {
	t.Helper()
	d, err := f.conn.Discover(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cs.TrustHostKey(id, d.Fingerprint); err != nil {
		t.Fatal(err)
	}
}

func encryptedKey(t *testing.T, pass string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var blk *pem.Block
	var err error
	if pass == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(pass))
	}
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ssh.NewPublicKey(pub)
	return string(pem.EncodeToMemory(blk)), k
}

func TestDiscoverDoesNotAuthenticate(t *testing.T) {
	f := newFixture(t)
	pw := "pw-" + randHex(8)
	f.srv.SetPassword(pw)
	c, _ := f.cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	sv := f.server(t, model.AuthPassword, c.ID)
	d, err := f.conn.Discover(context.Background(), sv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Fingerprint != f.srv.Fingerprint() || d.KeyType != ssh.KeyAlgoED25519 || d.MatchesPinned {
		t.Fatalf("discovery %+v", d)
	}
	if f.srv.AuthAttempts() != 0 || len(f.srv.Commands()) != 0 {
		t.Fatalf("discovery authenticated or ran something: %d %v", f.srv.AuthAttempts(), f.srv.Commands())
	}
	got, _ := f.cs.Server(sv.ID)
	if got.HostKey.State != model.HostKeyDiscovered || got.HostKey.Seen != d.Fingerprint {
		t.Fatalf("not recorded: %+v", got.HostKey)
	}
	// Discovered is not trusted: nothing runs, nothing authenticates.
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "echo hi"); CodeOf(err) != CodeUntrusted {
		t.Fatalf("untrusted server ran: %v", err)
	}
	if _, err := f.conn.Test(context.Background(), sv.ID); CodeOf(err) != CodeUntrusted {
		t.Fatalf("untrusted server tested: %v", err)
	}
	if f.srv.AuthAttempts() != 0 {
		t.Fatal("authenticated against an untrusted server")
	}
}

func TestPasswordAuthEndToEnd(t *testing.T) {
	f := newFixture(t)
	pw := "pw-" + randHex(8)
	f.srv.SetPassword(pw)
	c, err := f.cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	sv := f.server(t, model.AuthPassword, c.ID)
	f.trust(t, sv.ID)
	// The host echoes the password back: it must be scrubbed.
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) { return "out " + pw + " " + stdin, 0 })
	res, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "echo MERIDIAN_OK")
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthMethod != AuthPassword || res.Fingerprint != f.srv.Fingerprint() || res.CredentialID != c.ID {
		t.Fatalf("result %+v", res)
	}
	if strings.Contains(res.Output, pw) || !strings.Contains(res.Output, "echo MERIDIAN_OK") {
		t.Fatalf("output %q", res.Output)
	}
	if cmds := f.srv.Commands(); len(cmds) != 1 || cmds[0] != "bash -s" {
		t.Fatalf("script not sent on stdin: %v", cmds)
	}
	// Wrong password after the host changed it: auth_failed, no secret.
	f.srv.SetPassword("other-" + randHex(4))
	_, err = f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeAuthFailed || strings.Contains(err.Error(), pw) {
		t.Fatalf("auth failure: %v", err)
	}
	// Rotation in place: the new secret is used under the same ID.
	pw2 := "pw2-" + randHex(8)
	f.srv.SetPassword(pw2)
	if _, err := f.cs.RotateSSHCredential(c.ID, credentials.SSHSecretInput{Password: pw2}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x"); err != nil {
		t.Fatalf("rotated credential: %v", err)
	}
}

func TestShortPasswordScrubbed(t *testing.T) {
	f := newFixture(t)
	pw := "Zq7"
	f.srv.SetPassword(pw)
	c, _ := f.cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	sv := f.server(t, model.AuthPassword, c.ID)
	f.trust(t, sv.ID)
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) { return "leak Zq7 leak", 1 })
	res, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeCommandFailed || strings.Contains(res.Output, pw) || strings.Contains(err.Error(), pw) {
		t.Fatalf("%v %q", err, res.Output)
	}
}

func TestKeyAuthWithAndWithoutPassphrase(t *testing.T) {
	for _, pass := range []string{"", "pp-" + randHex(6)} {
		f := newFixture(t)
		pemText, pub := encryptedKey(t, pass)
		f.srv.SetAuthorizedKey(pub)
		c, err := f.cs.CreateSSHCredential("k", "", credentials.SSHSecretInput{Kind: credentials.KindPrivateKey, PrivateKey: pemText, Passphrase: pass})
		if err != nil {
			t.Fatal(err)
		}
		sv := f.server(t, model.AuthKey, c.ID)
		f.trust(t, sv.ID)
		ct, err := f.conn.Test(context.Background(), sv.ID)
		if err != nil || !ct.OK || ct.AuthMethod != AuthKey || ct.Arch != "x86_64" || ct.OS != "Debian GNU/Linux 13 (trixie)" || ct.Kernel != "6.12.0-test" {
			t.Fatalf("passphrase %v: %+v %v", pass != "", ct, err)
		}
		if cmds := f.srv.Commands(); cmds[len(cmds)-1] != TestCommand {
			t.Fatalf("test ran %q", cmds)
		}
		// Another key on the host side: auth_failed.
		_, other := encryptedKey(t, "")
		f.srv.SetAuthorizedKey(other)
		ct, err = f.conn.Test(context.Background(), sv.ID)
		if err != nil || ct.OK || ct.Code != CodeAuthFailed {
			t.Fatalf("wrong key: %+v %v", ct, err)
		}
		if pass != "" && strings.Contains(ct.Error, pass) {
			t.Fatal("passphrase in error")
		}
	}
}

func TestMismatchRefusedBeforeAuthentication(t *testing.T) {
	f := newFixture(t)
	pw := "pw-" + randHex(8)
	f.srv.SetPassword(pw)
	c, _ := f.cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	sv := f.server(t, model.AuthPassword, c.ID)
	f.trust(t, sv.ID)
	pinned := f.srv.Fingerprint()
	f.srv.SetHostKey(sshtest.NewHostKey())
	before := f.srv.AuthAttempts()
	_, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeMismatch {
		t.Fatalf("mismatch: %v", err)
	}
	if f.srv.AuthAttempts() != before {
		t.Fatal("authenticated against a host presenting another key")
	}
	got, _ := f.cs.Server(sv.ID)
	if got.HostKey.State != model.HostKeyMismatch || got.HostKey.Fingerprint != pinned || got.HostKey.Seen != f.srv.Fingerprint() {
		t.Fatalf("pin not kept: %+v", got.HostKey)
	}
	// Refused up front from now on, still without authenticating.
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x"); CodeOf(err) != CodeMismatch {
		t.Fatalf("second attempt: %v", err)
	}
	if f.srv.AuthAttempts() != before || len(f.srv.Commands()) != 0 {
		t.Fatal("ran on mismatched host")
	}
	// Explicit re-trust of the new key.
	if _, err := f.cs.TrustHostKey(sv.ID, f.srv.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x"); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentPinEnforced(t *testing.T) {
	f := newFixture(t)
	pw := "pw-" + randHex(8)
	f.srv.SetPassword(pw)
	c, _ := f.cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	sv := f.server(t, model.AuthPassword, c.ID)
	f.trust(t, sv.ID)
	tg := Target{ServerID: sv.ID, CredentialID: c.ID, Address: sv.Address, Port: sv.Port, User: sv.User, Fingerprint: f.srv.Fingerprint()}
	if _, err := f.conn.RunScript(context.Background(), tg, "x"); err != nil {
		t.Fatal(err)
	}
	bad := tg
	bad.Fingerprint = "SHA256:" + strings.Repeat("A", 43)
	if _, err := f.conn.RunScript(context.Background(), bad, "x"); CodeOf(err) != CodePinMismatch {
		t.Fatalf("pin: %v", err)
	}
	bad = tg
	bad.User = "root"
	if _, err := f.conn.RunScript(context.Background(), bad, "x"); CodeOf(err) != CodeTargetChanged {
		t.Fatalf("target: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	f := newFixture(t)
	sv := f.server(t, model.AuthKey, "")
	f.srv.Close()
	_, err := f.conn.Discover(context.Background(), sv.ID)
	if c := CodeOf(err); c != CodeUnreachable && c != CodeTimeout {
		t.Fatalf("%v", err)
	}
}
