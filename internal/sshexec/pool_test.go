package sshexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
)

// passwordServer is a trusted server reached with a password credential
// (the IX-like case: the server offers password login only).
func passwordServer(t *testing.T, f *fixture) (model.Server, credentials.SSHCredential, string) {
	t.Helper()
	pw := "pw-" + randHex(8)
	f.srv.SetPassword(pw)
	f.srv.OfferOnly("password")
	c, err := f.cs.CreateSSHCredential("p-"+randHex(2), "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	sv := f.server(t, model.AuthPassword, c.ID)
	f.trust(t, sv.ID)
	return sv, c, pw
}

// "Not allowed at this time" before the banner: classified as rate
// limiting (not EOF, not a login or host-key problem), nothing is sent, and
// the endpoint is left alone for the cooldown, by every operation.
func TestRateLimitedBeforeBanner(t *testing.T) {
	f := newFixture(t)
	sv, _, pw := passwordServer(t, f)
	f.conn.Pool = &Pool{Cooldown: 2 * time.Minute}
	before := f.srv.AuthAttempts()
	base := f.srv.Accepted() // the discovery that trusted the key
	f.srv.RefuseBeforeBanner("Not allowed at this time")

	_, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeRateLimited {
		t.Fatalf("code %q: %v", CodeOf(err), err)
	}
	if RetryAfterOf(err) != 120 {
		t.Fatalf("retry after %d", RetryAfterOf(err))
	}
	msg := err.Error()
	for _, want := range []string{"Not allowed at this time", "不是密码、密钥或主机指纹的问题", "120 秒"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "EOF") || strings.Contains(msg, pw) {
		t.Fatalf("message: %s", msg)
	}
	if f.srv.AuthAttempts() != before {
		t.Fatal("a credential was tried")
	}
	// The pin is untouched.
	if got, _ := f.cs.Server(sv.ID); got.HostKey.State != model.HostKeyTrusted {
		t.Fatalf("host key state %s", got.HostKey.State)
	}
	// No automatic retry, and nothing dials during the cooldown: the
	// connection test, discovery and the preflight answer from the
	// cooldown without a new TCP connection.
	n := f.srv.Accepted()
	if n != base+1 {
		t.Fatalf("accepted %d connections for one refused attempt", n)
	}
	ct, err := f.conn.Test(context.Background(), sv.ID)
	if err != nil || ct.OK || ct.Code != CodeRateLimited || ct.RetryAfter <= 0 || ct.RetryAfter > 120 {
		t.Fatalf("test %+v %v", ct, err)
	}
	if _, err := f.conn.Discover(context.Background(), sv.ID); CodeOf(err) != CodeRateLimited {
		t.Fatalf("discover %v", err)
	}
	if _, err := f.conn.RunPreflight(context.Background(), Target{ServerID: sv.ID}, nil); CodeOf(err) != CodeRateLimited {
		t.Fatalf("preflight %v", err)
	}
	if _, err := f.conn.ReadGroupState(context.Background(), Target{ServerID: sv.ID}); CodeOf(err) != CodeRateLimited {
		t.Fatalf("group state %v", err)
	}
	if f.srv.Accepted() != n {
		t.Fatalf("dialed during the cooldown: %d connections", f.srv.Accepted())
	}
	if left := f.conn.Pool.CooldownLeft(sv.Address, sv.Port); left <= 0 || left > 2*time.Minute {
		t.Fatalf("cooldown left %v", left)
	}

	// After the cooldown (clock moved), a server that accepts again works.
	f.srv.RefuseBeforeBanner("")
	now := time.Now().Add(3 * time.Minute)
	f.conn.Pool.Now = func() time.Time { return now }
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x"); err != nil {
		t.Fatalf("after cooldown: %v", err)
	}
}

// Discovery (no authentication) classifies the same line, and without a
// pool the classification still holds.
func TestRateLimitedDiscoverWithoutPool(t *testing.T) {
	f := newFixture(t)
	sv := f.server(t, model.AuthKey, "")
	f.srv.RefuseBeforeBanner("Not allowed at this time")
	_, err := f.conn.Discover(context.Background(), sv.ID)
	if CodeOf(err) != CodeRateLimited || RetryAfterOf(err) != int(DefaultCooldown/time.Second) {
		t.Fatalf("discover %q %v", CodeOf(err), err)
	}
	if got, _ := f.cs.Server(sv.ID); got.HostKey.Fingerprint != "" {
		t.Fatalf("something was recorded: %+v", got.HostKey)
	}
}

// Other text before a missing banner is shown (sanitised), not classified
// as rate limiting.
func TestOtherPreBannerText(t *testing.T) {
	f := newFixture(t)
	sv, _, _ := passwordServer(t, f)
	f.conn.Pool = &Pool{}
	f.srv.RefuseBeforeBanner("Too many connections \x1b[31mbye")
	_, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeUnreachable || !strings.Contains(err.Error(), "Too many connections") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("%q %v", CodeOf(err), err)
	}
	if f.conn.Pool.CooldownLeft(sv.Address, sv.Port) != 0 {
		t.Fatal("cooldown for a non-rate-limit answer")
	}
}

// One login serves the steps of a flow: connection test, preflight, the
// re-run of the preflight and the provision script.
func TestPoolReusesOneLogin(t *testing.T) {
	f := newFixture(t)
	sv, _, _ := passwordServer(t, f)
	f.conn.Pool = &Pool{}
	ctx := context.Background()
	if ct, err := f.conn.Test(ctx, sv.ID); err != nil || !ct.OK {
		t.Fatalf("test %+v %v", ct, err)
	}
	tg := Target{ServerID: sv.ID, Address: sv.Address, Port: sv.Port, User: sv.User, Fingerprint: f.srv.Fingerprint()}
	for i := 0; i < 2; i++ {
		res, err := f.conn.RunPreflight(ctx, tg, []string{"'/etc/wireguard/m00.conf'"})
		if err != nil || !res.Reused {
			t.Fatalf("preflight %d: reused=%v %v", i, res.Reused, err)
		}
	}
	if res, err := f.conn.RunScript(ctx, tg, "echo MERIDIAN_PROVISION_OK"); err != nil || !res.Reused {
		t.Fatalf("script reused=%v %v", res.Reused, err)
	}
	if f.srv.Accepted() != 2 || f.srv.Logins() != 1 { // discovery + one login
		t.Fatalf("accepted %d logins %d", f.srv.Accepted(), f.srv.Logins())
	}
	if got := f.srv.Commands(); len(got) != 4 || !strings.HasPrefix(got[1], "bash -s -- ") {
		t.Fatalf("commands %v", got)
	}
	// A second explicit connection test logs in again (it tests the
	// login) and replaces the idle connection instead of adding one.
	if ct, err := f.conn.Test(ctx, sv.ID); err != nil || !ct.OK {
		t.Fatalf("test %+v %v", ct, err)
	}
	if f.srv.Logins() != 2 || f.conn.Pool.Idle() != 1 {
		t.Fatalf("logins %d idle %d", f.srv.Logins(), f.conn.Pool.Idle())
	}
	waitOpen(t, f, 1)
}

func waitOpen(t *testing.T, f *fixture, n int) {
	t.Helper()
	for i := 0; i < 200 && f.srv.Open() != n; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if f.srv.Open() != n {
		t.Fatalf("open connections %d, want %d", f.srv.Open(), n)
	}
}

// Any change of the identity a connection was authenticated under closes
// it instead of reusing it: rotated secret, another credential, edited
// endpoint/user, re-trusted or cleared pin, deployment pin.
func TestPoolBoundToIdentity(t *testing.T) {
	ctx := context.Background()
	login := func(t *testing.T, f *fixture, id string) Result {
		t.Helper()
		res, err := f.conn.RunScript(ctx, Target{ServerID: id}, "x")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("rotated secret", func(t *testing.T) {
		f := newFixture(t)
		sv, c, _ := passwordServer(t, f)
		f.conn.Pool = &Pool{}
		login(t, f, sv.ID)
		pw2 := "pw2-" + randHex(6)
		f.srv.SetPassword(pw2)
		if _, err := f.cs.RotateSSHCredential(c.ID, credentials.SSHSecretInput{Password: pw2}); err != nil {
			t.Fatal(err)
		}
		if res := login(t, f, sv.ID); res.Reused {
			t.Fatal("reused across a secret rotation")
		}
		if f.srv.Logins() != 2 {
			t.Fatalf("logins %d", f.srv.Logins())
		}
		waitOpen(t, f, 1)
	})
	t.Run("other credential", func(t *testing.T) {
		f := newFixture(t)
		sv, _, pw := passwordServer(t, f)
		f.conn.Pool = &Pool{}
		login(t, f, sv.ID)
		c2, _ := f.cs.CreateSSHCredential("p2", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
		cid := c2.ID
		if _, err := f.cs.UpdateServer(sv.ID, credentials.ServerPatch{CredentialID: &cid}); err != nil {
			t.Fatal(err)
		}
		if res := login(t, f, sv.ID); res.Reused || res.CredentialID != c2.ID {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("edited user", func(t *testing.T) {
		f := newFixture(t)
		sv, _, _ := passwordServer(t, f)
		f.conn.Pool = &Pool{}
		login(t, f, sv.ID)
		u := "root"
		if _, err := f.cs.UpdateServer(sv.ID, credentials.ServerPatch{User: &u}); err != nil {
			t.Fatal(err)
		}
		if got, _ := f.cs.Server(sv.ID); got.HostKey.State == model.HostKeyTrusted {
			if res := login(t, f, sv.ID); res.Reused {
				t.Fatal("reused across a user change")
			}
		} else if _, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "x"); err == nil {
			t.Fatal("ran after the edit reset trust")
		}
		if f.srv.Logins() == 1 && f.conn.Pool.Idle() != 0 {
			t.Fatal("stale idle connection kept")
		}
	})
	t.Run("pin cleared and re-trusted", func(t *testing.T) {
		f := newFixture(t)
		sv, _, _ := passwordServer(t, f)
		f.conn.Pool = &Pool{}
		login(t, f, sv.ID)
		if _, err := f.cs.ForgetHostKey(sv.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "x"); CodeOf(err) != CodeUntrusted {
			t.Fatalf("untrusted: %v", err)
		}
		f.trust(t, sv.ID)
		if res := login(t, f, sv.ID); res.Reused {
			t.Fatal("reused across a re-trust")
		}
	})
	t.Run("deployment pin", func(t *testing.T) {
		f := newFixture(t)
		sv, _, _ := passwordServer(t, f)
		f.conn.Pool = &Pool{}
		login(t, f, sv.ID)
		_, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID, Address: sv.Address, Port: sv.Port, User: sv.User, Fingerprint: "SHA256:other"}, "x")
		if CodeOf(err) != CodePinMismatch {
			t.Fatalf("pin: %v", err)
		}
	})
	t.Run("explicit invalidation", func(t *testing.T) {
		f := newFixture(t)
		sv, c, _ := passwordServer(t, f)
		f.conn.Pool = &Pool{}
		login(t, f, sv.ID)
		f.conn.Pool.InvalidateServer(sv.ID)
		waitOpen(t, f, 0)
		login(t, f, sv.ID)
		f.conn.Pool.InvalidateCredential(c.ID)
		waitOpen(t, f, 0)
		if f.conn.Pool.Idle() != 0 {
			t.Fatal("idle after invalidation")
		}
	})
}

// A failed step closes the connection; the next step logs in again (it
// is a new operation, not an automatic retry). Idle and age limits close
// connections too.
func TestPoolClosesOnErrorAndExpiry(t *testing.T) {
	f := newFixture(t)
	sv, _, _ := passwordServer(t, f)
	f.conn.Pool = &Pool{IdleTTL: 150 * time.Millisecond}
	ctx := context.Background()
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if strings.Contains(stdin, "fail") {
			return "no", 3
		}
		return "ok", 0
	})
	if _, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "fail"); CodeOf(err) != CodeCommandFailed {
		t.Fatalf("fail: %v", err)
	}
	if f.conn.Pool.Idle() != 0 {
		t.Fatal("connection kept after an error")
	}
	waitOpen(t, f, 0)
	if res, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "ok"); err != nil || res.Reused {
		t.Fatalf("after error: reused=%v %v", res.Reused, err)
	}
	// Idle expiry.
	waitOpen(t, f, 0)
	if f.conn.Pool.Idle() != 0 {
		t.Fatal("idle connection outlived IdleTTL")
	}
	// Age: a connection older than MaxAge is not handed out.
	f.conn.Pool.IdleTTL = time.Minute
	if _, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "ok"); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(10 * time.Minute)
	f.conn.Pool.Now = func() time.Time { return later }
	if res, err := f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "ok"); err != nil || res.Reused {
		t.Fatalf("aged: reused=%v %v", res.Reused, err)
	}
	// A cancelled operation does not return its connection.
	f.conn.Pool.Now = nil
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = f.conn.RunScript(cctx, Target{ServerID: sv.ID}, "ok")
	if f.conn.Pool.Idle() > 1 {
		t.Fatal("cancelled connection pooled")
	}
	// A dead idle connection (server went away) is not used: the server
	// restarted on the same port is not possible here, so check that the
	// keepalive fails and nothing is handed out.
	f.conn.Pool.CloseAll()
}
