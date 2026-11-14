package sshexec

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// dialLog records every TCP connection the panel opens and refuses any
// that is not on loopback (nothing in these tests may leave the machine).
type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialLog) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	host, _, _ := net.SplitHostPort(addr)
	if host != "127.0.0.1" {
		return nil, errors.New("test: refusing to dial " + addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

func (d *dialLog) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// jumpFix is a relay and a target, both local SSH stand-ins with their own
// password credentials, the target reached through the relay.
type jumpFix struct {
	relay, target     *sshtest.Server
	cs                *credentials.Store
	conn              *Connector
	dials             *dialLog
	relaySv, targetSv model.Server
	relayPw, targetPw string
}

func newJumpFix(t *testing.T) *jumpFix {
	t.Helper()
	f := &jumpFix{dials: &dialLog{}}
	var err error
	if f.relay, err = sshtest.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.relay.Close)
	if f.target, err = sshtest.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.target.Close)
	if f.cs, err = credentials.Open(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	f.relayPw, f.targetPw = "relay-"+randHex(6), "target-"+randHex(6)
	f.relay.SetPassword(f.relayPw)
	f.target.SetPassword(f.targetPw)
	f.relay.AllowForwarding(true)
	f.target.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd == TestCommand {
			return "MERIDIAN_ARCH=x86_64\n", 0
		}
		return "target ran " + cmd, 0
	})
	f.relay.SetHandler(func(cmd, stdin string) (string, uint32) { return "relay ran " + cmd, 0 })
	rc, _ := f.cs.CreateSSHCredential("relay", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: f.relayPw})
	tc, _ := f.cs.CreateSSHCredential("target", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: f.targetPw})
	if f.relaySv, err = f.cs.CreateServer(credentials.ServerInput{Name: "relay", Address: f.relay.Host, Port: f.relay.Port, User: "root", Auth: model.AuthPassword, CredentialID: rc.ID}); err != nil {
		t.Fatal(err)
	}
	// The target's own address is a documentation address that is never
	// dialed: the jump forwards to the channel address (the relay's view).
	if f.targetSv, err = f.cs.CreateServer(credentials.ServerInput{Name: "hub", Address: "198.51.100.20", Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: tc.ID,
		Channel: &model.ManagementChannel{Mode: model.ChannelJump, ViaServerID: f.relaySv.ID, Address: f.target.Host, Port: f.target.Port}}); err != nil {
		t.Fatal(err)
	}
	f.conn = &Connector{Store: f.cs, HandshakeTimeout: 5 * time.Second, Dial: f.dials.dial, Pool: &Pool{}}
	for _, id := range []string{f.relaySv.ID, f.targetSv.ID} {
		d, err := f.conn.Discover(context.Background(), id)
		if err != nil {
			t.Fatalf("discover %s: %v", id, err)
		}
		if _, err := f.cs.TrustHostKey(id, d.Fingerprint); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func noAgent(t *testing.T, srvs ...*sshtest.Server) {
	t.Helper()
	for _, s := range srvs {
		for _, r := range s.Requests() {
			if strings.Contains(r, "agent") {
				t.Fatalf("agent forwarding requested: %v", s.Requests())
			}
		}
	}
}

// A jump: the panel dials only the relay; the relay forwards, runs
// nothing; the target is authenticated with its own credential against its
// own pinned key; the connection is pooled across steps.
func TestJumpChannel(t *testing.T) {
	f := newJumpFix(t)
	ctx := context.Background()
	if got, _ := f.cs.Server(f.targetSv.ID); got.HostKey.Fingerprint != f.target.Fingerprint() {
		t.Fatalf("discovery through the relay pinned %q, the target presents %q", got.HostKey.Fingerprint, f.target.Fingerprint())
	}
	ct, err := f.conn.Test(ctx, f.targetSv.ID)
	if err != nil || !ct.OK || ct.Channel != model.ChannelJump {
		t.Fatalf("test %+v %v", ct, err)
	}
	res, err := f.conn.RunScript(ctx, Target{ServerID: f.targetSv.ID}, "echo hi")
	if err != nil || !res.Reused || res.Channel != model.ChannelJump || !strings.Contains(res.Output, "target ran bash -s") {
		t.Fatalf("script %+v %v", res, err)
	}
	for _, a := range f.dials.list() {
		if a != endpoint(f.relay.Host, f.relay.Port) {
			t.Fatalf("the panel dialed %s directly", a)
		}
	}
	if len(f.relay.Commands()) != 0 {
		t.Fatalf("the relay executed %v", f.relay.Commands())
	}
	if fw := f.relay.Forwards(); len(fw) == 0 || fw[0] != endpoint(f.target.Host, f.target.Port) {
		t.Fatalf("forwards %v", fw)
	}
	noAgent(t, f.relay, f.target)
	// The relay's password never reaches the target and vice versa.
	if f.target.AuthAttempts() == 0 || f.relay.AuthAttempts() == 0 {
		t.Fatal("a hop was not authenticated")
	}
	// Invalidating the relay drops the pooled jump connection.
	f.conn.Pool.InvalidateServer(f.relaySv.ID)
	if f.conn.Pool.Idle() != 0 {
		t.Fatal("jump connection survived the relay's invalidation")
	}
}

// A changed host key on either hop is refused before anything is sent to
// the target; the pin of that hop's server goes to mismatch.
func TestJumpHostKeyChange(t *testing.T) {
	ctx := context.Background()
	t.Run("relay", func(t *testing.T) {
		f := newJumpFix(t)
		attempts, accepted := f.target.AuthAttempts(), f.target.Accepted()
		f.relay.SetHostKey(sshtest.NewHostKey())
		_, err := f.conn.RunScript(ctx, Target{ServerID: f.targetSv.ID}, "x")
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeMismatch || e.Hop != "relay" || !e.NotExecuted || e.SafeToRetry {
			t.Fatalf("%+v", err)
		}
		if f.target.Accepted() != accepted || f.target.AuthAttempts() != attempts || len(f.target.Commands()) != 0 {
			t.Fatal("the target was reached through a relay presenting another key")
		}
		if got, _ := f.cs.Server(f.relaySv.ID); got.HostKey.State != model.HostKeyMismatch {
			t.Fatalf("relay pin %+v", got.HostKey)
		}
	})
	t.Run("target", func(t *testing.T) {
		f := newJumpFix(t)
		attempts := f.target.AuthAttempts()
		f.target.SetHostKey(sshtest.NewHostKey())
		_, err := f.conn.RunScript(ctx, Target{ServerID: f.targetSv.ID}, "x")
		if CodeOf(err) != CodeMismatch || !NotExecutedOf(err) {
			t.Fatalf("%v", err)
		}
		if f.target.AuthAttempts() != attempts || len(f.target.Commands()) != 0 {
			t.Fatal("authenticated against a target presenting another key")
		}
		if got, _ := f.cs.Server(f.targetSv.ID); got.HostKey.State != model.HostKeyMismatch {
			t.Fatalf("target pin %+v", got.HostKey)
		}
	})
}

// The target behind the relay rate-limits (the relay is its one source):
// recognised, nothing executed, and no new connection during the cooldown.
func TestJumpRateLimited(t *testing.T) {
	f := newJumpFix(t)
	f.conn.Pool.CloseAll()
	f.target.RefuseBeforeBanner("Not allowed at this time")
	before := f.relay.Accepted()
	_, err := f.conn.RunScript(context.Background(), Target{ServerID: f.targetSv.ID}, "x")
	if CodeOf(err) != CodeRateLimited || !NotExecutedOf(err) || !SafeToRetryOf(err) || RetryAfterOf(err) <= 0 {
		t.Fatalf("%+v", err)
	}
	if f.relay.Accepted() != before+1 {
		t.Fatalf("relay connections %d", f.relay.Accepted()-before)
	}
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: f.targetSv.ID}, "x"); CodeOf(err) != CodeRateLimited {
		t.Fatalf("during cooldown: %v", err)
	}
	if f.relay.Accepted() != before+1 {
		t.Fatal("connected again during the cooldown")
	}
}

// A relay that does not forward, and a jump the policy refuses.
func TestJumpRefusals(t *testing.T) {
	f := newJumpFix(t)
	f.conn.Pool.CloseAll()
	f.relay.AllowForwarding(false)
	_, err := f.conn.RunScript(context.Background(), Target{ServerID: f.targetSv.ID}, "x")
	if CodeOf(err) != CodeJumpRefused || !NotExecutedOf(err) {
		t.Fatalf("%v", err)
	}
	f.relay.AllowForwarding(true)
	f.conn.JumpPolicy = func(via, target model.Server) error { return errors.New("not a managed relay") }
	n := len(f.dials.list())
	if _, err := f.conn.RunScript(context.Background(), Target{ServerID: f.targetSv.ID}, "x"); CodeOf(err) != CodeChannelNotAllowed {
		t.Fatalf("policy: %v", err)
	}
	if len(f.dials.list()) != n {
		t.Fatal("dialed although the channel is not allowed")
	}
}

// The store keeps channels explicit: one hop only, an IP address for a
// tunnel, no deleting a relay in use.
func TestChannelValidation(t *testing.T) {
	f := newJumpFix(t)
	bad := []model.ManagementChannel{
		{Mode: model.ChannelTunnel},
		{Mode: model.ChannelTunnel, Address: "hub.example"},
		{Mode: model.ChannelTunnel, Address: "0.0.0.0"},
		{Mode: model.ChannelJump},
		{Mode: model.ChannelJump, ViaServerID: f.targetSv.ID}, // itself
		{Mode: "proxycommand"},
	}
	for _, ch := range bad {
		ch := ch
		if _, err := f.cs.UpdateServer(f.targetSv.ID, credentials.ServerPatch{Channel: &ch}); err == nil {
			t.Fatalf("accepted %+v", ch)
		}
	}
	// The relay may not itself be reached through a channel.
	tun := model.ManagementChannel{Mode: model.ChannelTunnel, Address: "10.66.0.1"}
	if _, err := f.cs.UpdateServer(f.relaySv.ID, credentials.ServerPatch{Channel: &tun}); err == nil {
		t.Fatal("a relay in use was moved behind a channel")
	}
	if err := f.cs.DeleteServer(f.relaySv.ID); err == nil {
		t.Fatal("deleted a relay in use")
	}
	// Back to direct: stored as no channel at all.
	direct := model.ManagementChannel{Mode: model.ChannelDirect}
	sv, err := f.cs.UpdateServer(f.targetSv.ID, credentials.ServerPatch{Channel: &direct})
	if err != nil || sv.Channel != nil {
		t.Fatalf("%+v %v", sv.Channel, err)
	}
	// The pin stays (the channel is transport, not identity).
	if sv.HostKey.State != model.HostKeyTrusted {
		t.Fatalf("pin lost: %+v", sv.HostKey)
	}
}

// A tunnel channel dials the tunnel address only, never the public one,
// and the pinned key is still required there.
func TestTunnelChannel(t *testing.T) {
	f := newFixture(t)
	pw := "pw-" + randHex(6)
	f.srv.SetPassword(pw)
	c, _ := f.cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	sv, err := f.cs.CreateServer(credentials.ServerInput{Name: "exit", Address: "203.0.113.30", Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: c.ID,
		Channel: &model.ManagementChannel{Mode: model.ChannelTunnel, Address: f.srv.Host, Port: f.srv.Port}})
	if err != nil {
		t.Fatal(err)
	}
	dl := &dialLog{}
	f.conn.Dial = dl.dial
	f.trust(t, sv.ID)
	res, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID, Address: "203.0.113.30", Port: 22, User: "root", Fingerprint: f.srv.Fingerprint()}, "x")
	if err != nil || res.Channel != model.ChannelTunnel {
		t.Fatalf("%+v %v", res, err)
	}
	for _, a := range dl.list() {
		if a != endpoint(f.srv.Host, f.srv.Port) {
			t.Fatalf("dialed %s", a)
		}
	}
	// The tunnel is down: reported with the channel, no fallback.
	f.srv.Close()
	_, err = f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if err == nil || !strings.Contains(err.Error(), "经隧道地址") || !strings.Contains(err.Error(), "不会自动改走直连") || !NotExecutedOf(err) {
		t.Fatalf("%v", err)
	}
	for _, a := range dl.list() {
		if a != endpoint(f.srv.Host, f.srv.Port) {
			t.Fatalf("fell back to %s", a)
		}
	}
}

// Failures before anything runs are classified and, when transient, said
// to be safe to retry; nothing is retried automatically.
func TestPreExecutionFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(s *sshtest.Server)
		code  string
	}{
		{"banner timeout", func(s *sshtest.Server) { s.Silent(true) }, CodeBannerTimeout},
		{"handshake timeout", func(s *sshtest.Server) { s.Stall(true) }, CodeHandshakeTimeout},
		{"closed before banner", func(s *sshtest.Server) { s.HangUp(true) }, CodeClosedBeforeBanner},
		{"rate limited", func(s *sshtest.Server) { s.RefuseBeforeBanner("Not allowed at this time") }, CodeRateLimited},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			sv, _, _ := passwordServer(t, f)
			f.conn.HandshakeTimeout = 300 * time.Millisecond
			f.conn.Pool = &Pool{}
			base := f.srv.Accepted()
			tc.setup(f.srv)
			_, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
			if CodeOf(err) != tc.code || !NotExecutedOf(err) || !SafeToRetryOf(err) {
				t.Fatalf("%q %v", CodeOf(err), err)
			}
			if tc.code != CodeRateLimited && !strings.Contains(err.Error(), "可以安全重试") {
				t.Fatalf("message %q", err.Error())
			}
			if f.srv.Accepted() != base+1 || len(f.srv.Commands()) != 0 {
				t.Fatalf("connections %d commands %v", f.srv.Accepted()-base, f.srv.Commands())
			}
		})
	}
	// After the command started, a failure is never "not executed".
	f := newFixture(t)
	sv, _, _ := passwordServer(t, f)
	f.srv.SetHandler(func(string, string) (string, uint32) { return "", 1 })
	_, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeCommandFailed || NotExecutedOf(err) || SafeToRetryOf(err) {
		t.Fatalf("%v", err)
	}
	// A timeout during the run: outcome unknown, not safe to retry.
	f.srv.SetStreamHandler(func(_, _ string, _, _ io.Writer) uint32 { time.Sleep(2 * time.Second); return 0 })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = f.conn.RunScript(ctx, Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeRunTimeout || NotExecutedOf(err) || SafeToRetryOf(err) {
		t.Fatalf("%v", err)
	}
}

// Markers come from standard output line by line, so standard error
// arriving in the middle of a marker line cannot break it, and a long
// output does not cut them off.
func TestMarkersSurviveInterleavingAndCap(t *testing.T) {
	f := newFixture(t)
	sv, _, _ := passwordServer(t, f)
	f.conn.MaxOutput = 64
	f.srv.SetStreamHandler(func(_, _ string, stdout, stderr io.Writer) uint32 {
		io.WriteString(stdout, strings.Repeat("apt noise\n", 50))
		io.WriteString(stdout, "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_COMPEN")
		io.WriteString(stderr, "meridian: something failed\n")
		io.WriteString(stdout, "SATED\n")
		io.WriteString(stderr, "MERIDIAN_PROVISION_OK\n") // stderr never counts
		return 1
	})
	res, err := f.conn.RunScript(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeCommandFailed {
		t.Fatalf("%v", err)
	}
	if len(res.Output) > 64 {
		t.Fatalf("output not capped: %d", len(res.Output))
	}
	want := []string{"MERIDIAN_COMPENSATING exit=1", "MERIDIAN_COMPENSATED"}
	if strings.Join(res.Markers, "|") != strings.Join(want, "|") {
		t.Fatalf("markers %q", res.Markers)
	}
}

// The host's own record is read on the same login after the script ended,
// whatever its exit status; not after an unknown outcome.
func TestRunScriptAndRead(t *testing.T) {
	f := newFixture(t)
	sv, _, _ := passwordServer(t, f)
	f.conn.Pool = &Pool{}
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd == NodeStateCommand {
			return "meridian-node-state 1\njournal state compensated\njournal run run-1\nmeridian-node-state-end\n", 0
		}
		return "no markers here\n", 1
	})
	res, state, ok, err := f.conn.RunScriptAndRead(context.Background(), Target{ServerID: sv.ID}, "x")
	if CodeOf(err) != CodeCommandFailed || !ok || !strings.Contains(state, "journal state compensated") || res.Output != "no markers here\n" {
		t.Fatalf("%v ok=%v %q", err, ok, state)
	}
	if f.srv.Logins() != 1 {
		t.Fatalf("logins %d", f.srv.Logins())
	}
	if cmds := f.srv.Commands(); cmds[len(cmds)-1] != NodeStateCommand {
		t.Fatalf("commands %v", cmds)
	}
}
