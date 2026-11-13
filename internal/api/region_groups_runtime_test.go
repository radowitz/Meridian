package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

type hubStateBody struct {
	Groups   []gView `json:"groups"`
	HubState struct {
		HubNode     string `json:"hub_node"`
		ServerID    string `json:"server_id"`
		Readable    bool   `json:"readable"`
		NotReadable string `json:"not_readable_code"`
		Refreshing  bool   `json:"refreshing"`
		StaleAfter  int    `json:"stale_after_sec"`
		Loop        int    `json:"loop_interval_sec"`
		LastRead    *struct {
			ReadAt    string   `json:"read_at"`
			OK        bool     `json:"ok"`
			ErrorCode string   `json:"error_code"`
			SSHCode   string   `json:"ssh_code"`
			Error     string   `json:"error"`
			Ignored   []string `json:"ignored"`
			Current   bool     `json:"current_hub"`
			IDCode    string   `json:"identity_code"`
			IDMessage string   `json:"identity_message"`
		} `json:"last_read"`
		Counts map[string]int `json:"counts"`
	} `json:"hub_state"`
}

func (b hubStateBody) group(t *testing.T, id string) gView {
	t.Helper()
	for _, g := range b.Groups {
		if g.ID == id {
			return g
		}
	}
	t.Fatalf("no group %s", id)
	return gView{}
}

// hubFixture: the example topology with its hub node on an in-process SSH
// server whose answer to the fixed read is canned.
type hubFixture struct {
	t      *testing.T
	s      *Server
	srv    *sshtest.Server
	pw     string
	server string
	plan   string
	mu     sync.Mutex
	answer func() (string, uint32)
	logs   *bytes.Buffer
}

func newHubFixture(t *testing.T, trust bool) *hubFixture {
	t.Helper()
	f := &hubFixture{t: t, s: newTest(t), logs: &bytes.Buffer{}}
	log.SetOutput(f.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	srv, err := sshtest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	f.srv = srv
	f.pw = "pw-" + rnd(t, 8)
	srv.SetPassword(f.pw)
	srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if cmd != sshexec.GroupStateCommand {
			return "unexpected", 1
		}
		f.mu.Lock()
		a := f.answer
		f.mu.Unlock()
		if a == nil {
			return "", 1
		}
		return a()
	})
	s := f.s
	do(s, http.MethodGet, "/api/topology", nil)
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "hub", "kind": "password", "password": f.pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	rr = do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "枢纽", "address": srv.Host, "port": srv.Port, "user": "ops", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(t, rr, &sv)
	f.server = sv.Server.ID
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk-hub" {
			topo.Nodes[i].ServerID, topo.Nodes[i].SSHHost, topo.Nodes[i].SSHPort, topo.Nodes[i].SSHUser = f.server, "", 0, ""
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	plans, err := compile.PlanGroups(topo)
	if err != nil {
		t.Fatal(err)
	}
	f.plan = compile.GroupPlanID(plans)
	if trust {
		f.trust()
	}
	return f
}

func (f *hubFixture) trust() {
	f.t.Helper()
	rr := do(f.s, http.MethodPost, "/api/servers/"+f.server+"/host-key/discover", nil)
	var disc struct{ Discovery sshexec.Discovery }
	decode(f.t, rr, &disc)
	if rr = do(f.s, http.MethodPost, "/api/servers/"+f.server+"/host-key/trust", mustJSON(map[string]string{"fingerprint": disc.Discovery.Fingerprint})); rr.Code != 200 {
		f.t.Fatal(rr.Body.String())
	}
}

func (f *hubFixture) serve(out string, status uint32) {
	f.mu.Lock()
	f.answer = func() (string, uint32) { return out, status }
	f.mu.Unlock()
}

// hubOutput is what the fixed command prints on a hub whose clock reads
// now: the plan record and the given report blocks.
func hubOutput(plan string, now int64, blocks ...string) string {
	return fmt.Sprintf("%s\nnow %d\nplan %s %d\n%s%s\n", hubstate.Header, now, plan, now-3600, strings.Join(blocks, ""), hubstate.Footer)
}

func hubReport(gid, plan string, beat int64, kv ...string) string {
	m := map[string]string{"hop": "hk-2", "active": "hk-2", "reason": "failover", "alert": "0", "switched": fmt.Sprint(beat - 30), "result": "ok"}
	var extra []string
	for _, x := range kv {
		k, v, _ := strings.Cut(x, " ")
		if _, ok := m[k]; ok {
			m[k] = v
		} else {
			extra = append(extra, x)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\ngroup %s\nplan %s\nbeat %d\n", hubstate.ReportHeader, gid, plan, beat)
	for _, k := range []string{"hop", "active", "reason", "alert", "switched", "result"} {
		fmt.Fprintf(&b, "%s %s\n", k, m[k])
	}
	for _, x := range extra {
		b.WriteString(x + "\n")
	}
	b.WriteString("end\n")
	return b.String()
}

func (f *hubFixture) refresh(body []byte) hubStateBody {
	f.t.Helper()
	rr := do(f.s, http.MethodPost, "/api/region-groups/runtime/refresh", body)
	if rr.Code != 200 {
		f.t.Fatalf("refresh: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), f.pw) {
		f.t.Fatal("password in the refresh response")
	}
	var out hubStateBody
	decode(f.t, rr, &out)
	return out
}

func (f *hubFixture) list() hubStateBody {
	f.t.Helper()
	rr := do(f.s, http.MethodGet, "/api/region-groups", nil)
	var out hubStateBody
	decode(f.t, rr, &out)
	return out
}

// noActual: a non-ok state never carries a member in use, on the group or
// on any member row.
func noActual(t *testing.T, g gView, state, code string) {
	t.Helper()
	if g.Actual.State != state || (code != "" && g.Actual.Code != code) || g.Actual.Active != "" || g.Actual.Hop != "" || g.Actual.LastSwitch != nil {
		t.Fatalf("group %s: actual %+v, want %s/%s with no member", g.ID, g.Actual, state, code)
	}
	for _, m := range g.MemberStatus {
		if m.ActualActive {
			t.Fatalf("group %s: member %s marked actually active in state %s", g.ID, m.ID, state)
		}
	}
}

func TestHubStateUnreachable(t *testing.T) {
	f := newHubFixture(t, false)
	// Untrusted host key: refused before any login.
	b := f.refresh(nil)
	noActual(t, b.group(t, "hk"), hubstate.StateUnavailable, hubstate.CodeServerNotReady)
	if b.HubState.Readable || b.HubState.NotReadable != hubstate.CodeServerNotReady || b.HubState.LastRead == nil || b.HubState.LastRead.OK ||
		f.srv.AuthAttempts() != 0 || len(f.srv.Commands()) != 0 {
		t.Fatalf("untrusted: %+v attempts %d", b.HubState, f.srv.AuthAttempts())
	}
	// Hub without a server.
	topo, _, _ := f.s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk-hub" {
			topo.Nodes[i].ServerID = ""
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	b = f.refresh(nil)
	noActual(t, b.group(t, "hk"), hubstate.StateUnavailable, hubstate.CodeHubNoServer)
	if b.HubState.LastRead.ErrorCode != hubstate.CodeHubNoServer || b.HubState.Readable {
		t.Fatalf("no server: %+v", b.HubState)
	}
	// Static-only groups say so whatever the read.
	noActual(t, b.group(t, "v6"), hubstate.StateNotSwitchable, "")
}

func TestHubStateReadStates(t *testing.T) {
	f := newHubFixture(t, true)
	// Never read.
	b := f.list()
	noActual(t, b.group(t, "hk"), hubstate.StateNeverRead, "")
	if !b.HubState.Readable || b.HubState.LastRead != nil || b.HubState.Loop != 5 || b.HubState.StaleAfter < 60 {
		t.Fatalf("before read: %+v", b.HubState)
	}

	now := time.Now().Unix()
	// ok, plus a report of a group the topology no longer has.
	f.serve(hubOutput(f.plan, now, hubReport("hk", f.plan, now-2), hubReport("gone", f.plan, now-2)), 0)
	// Whatever the body says, nothing of it reaches the command.
	b = f.refresh([]byte(`{"command":"rm -rf /","server_id":"x","node_id":"gw"}`))
	hk := b.group(t, "hk")
	if hk.Actual.State != hubstate.StateOK || hk.Actual.Active != "hk-2" || hk.Actual.Reason != "failover" || hk.Actual.LastSwitch == nil ||
		hk.Actual.ReadAt == nil || hk.Actual.HubReportedAt == nil || hk.Actual.DeployedMatches == nil || !*hk.Actual.DeployedMatches {
		t.Fatalf("ok: %+v", hk.Actual)
	}
	// The model is separate and still says what it computed.
	if hk.Model.Source != "panel_model" || hk.Model.Active != "hk-ix" || hk.Model.Observed {
		t.Fatalf("model changed by the hub read: %+v", hk.Model)
	}
	for _, m := range hk.MemberStatus {
		if m.ActualActive != (m.ID == "hk-2") || m.ModelActive != (m.ID == "hk-ix") {
			t.Fatalf("member %s actual %v model %v", m.ID, m.ActualActive, m.ModelActive)
		}
	}
	if b.HubState.LastRead == nil || !b.HubState.LastRead.OK || strings.Join(b.HubState.LastRead.Ignored, ",") != "gone" || b.HubState.Counts["ok"] != 1 {
		t.Fatalf("hub state %+v", b.HubState)
	}
	for _, c := range f.srv.Commands() {
		if c != sshexec.GroupStateCommand {
			t.Fatalf("command sent: %q", c)
		}
	}
	if len(f.srv.Stdins()) != 0 && strings.Join(f.srv.Stdins(), "") != "" {
		t.Fatal("something was sent on stdin")
	}
	// Stored: a later GET shows the same read.
	if again := f.list().group(t, "hk"); again.Actual.State != hubstate.StateOK || *again.Actual.ReadAt != *hk.Actual.ReadAt {
		t.Fatalf("not stored: %+v", again.Actual)
	}
	rr := do(f.s, http.MethodGet, "/api/region-groups/hk", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"state":"ok"`) || !strings.Contains(rr.Body.String(), `"hub_state"`) {
		t.Fatal(rr.Body.String())
	}

	cases := []struct {
		name, out    string
		status       uint32
		state, code  string
		reportedHop  string
		lastReadCode string
	}{
		{"stale", hubOutput(f.plan, now, hubReport("hk", f.plan, now-int64(b.HubState.StaleAfter)-1, fmt.Sprintf("switched %d", now-1000))), 0,
			hubstate.StateStale, hubstate.CodeHeartbeatOld, "", ""},
		{"version", hubOutput("aaaaaaaaaaaaaaaaaaaaaaaa", now, hubReport("hk", "aaaaaaaaaaaaaaaaaaaaaaaa", now-2)), 0,
			hubstate.StateVersionMismatch, hubstate.CodePlanDiffers, "", ""},
		{"switch failed", hubOutput(f.plan, now, hubReport("hk", f.plan, now-2, "hop hk-ix", "active hk-ix", "reason preferred", "alert 1", "switched 0", "result failed", "want hk-2", fmt.Sprintf("lastfail hk-2 %d", now-2))), 0,
			hubstate.StateSwitchFailed, hubstate.CodeHopFailed, "hk-ix", ""},
		{"unknown member", hubOutput(f.plan, now, hubReport("hk", f.plan, now-2, "hop us-2", "active us-2")), 0,
			hubstate.StateUnavailable, hubstate.CodeInvalidReport, "", ""},
		{"missing", hubOutput(f.plan, now), 0, hubstate.StateUnavailable, hubstate.CodeStateMissing, "", ""},
		{"malformed", hubOutput(f.plan, now, hubReport("hk", f.plan, now-2, "hop $(id)")), 0,
			hubstate.StateUnavailable, hubstate.CodeParseError, "", hubstate.CodeParseError},
		{"oversized", hubOutput(f.plan, now, hubReport("hk", f.plan, now-2)) + strings.Repeat("A", sshexec.GroupStateMax+100), 0,
			hubstate.StateUnavailable, hubstate.CodeParseError, "", hubstate.CodeParseError},
		{"command fails", "", 1, hubstate.StateUnavailable, hubstate.CodeSSHFailed, "", hubstate.CodeSSHFailed},
	}
	for _, c := range cases {
		f.serve(c.out, c.status)
		b = f.refresh(nil)
		g := b.group(t, "hk")
		noActual(t, g, c.state, c.code)
		if c.reportedHop != "" && (g.Actual.Reported == nil || g.Actual.Reported.Hop != c.reportedHop || g.Actual.Reported.Want != "hk-2") {
			t.Fatalf("%s: reported %+v", c.name, g.Actual.Reported)
		}
		if c.lastReadCode != "" && (b.HubState.LastRead.ErrorCode != c.lastReadCode || b.HubState.LastRead.OK) {
			t.Fatalf("%s: last read %+v", c.name, b.HubState.LastRead)
		}
		if g.Model.Source != "panel_model" {
			t.Fatalf("%s: model %+v", c.name, g.Model)
		}
	}

	// Wrong password: SSH failure, no member, no secret anywhere.
	f.srv.SetPassword(f.pw + "-rotated")
	f.serve(hubOutput(f.plan, now, hubReport("hk", f.plan, now-2)), 0)
	b = f.refresh(nil)
	noActual(t, b.group(t, "hk"), hubstate.StateUnavailable, hubstate.CodeSSHFailed)
	if b.HubState.LastRead.SSHCode != sshexec.CodeAuthFailed {
		t.Fatalf("auth failure: %+v", b.HubState.LastRead)
	}
	f.srv.SetPassword(f.pw)

	// The host is reinstalled: the pinned key no longer matches.
	f.srv.SetHostKey(sshtest.NewHostKey())
	attempts := f.srv.AuthAttempts()
	b = f.refresh(nil)
	noActual(t, b.group(t, "hk"), hubstate.StateUnavailable, hubstate.CodeServerNotReady)
	if f.srv.AuthAttempts() != attempts {
		t.Fatal("logged in to a host with a changed key")
	}
	if strings.Contains(f.logs.String(), f.pw) {
		t.Fatal("password in the logs")
	}
	raw, _, _ := f.s.Store.Get(groupHubKey)
	if strings.Contains(raw, f.pw) {
		t.Fatal("password in the stored read")
	}
}

// One read at a time: a second refresh while one runs is refused.
func TestHubStateRefreshSerialised(t *testing.T) {
	f := newHubFixture(t, true)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	now := time.Now().Unix()
	f.mu.Lock()
	f.answer = func() (string, uint32) {
		started <- struct{}{}
		<-release
		return hubOutput(f.plan, now, hubReport("hk", f.plan, now-2)), 0
	}
	f.mu.Unlock()
	done := make(chan int, 1)
	go func() { done <- do(f.s, http.MethodPost, "/api/region-groups/runtime/refresh", nil).Code }()
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("first read never reached the hub")
	}
	if b := f.list(); !b.HubState.Refreshing {
		t.Fatal("list does not show the running read")
	}
	rr := do(f.s, http.MethodPost, "/api/region-groups/runtime/refresh", nil)
	var e apiErr
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if rr.Code != http.StatusConflict || e.Code != hubstate.CodeRefreshInProgress {
		t.Fatalf("concurrent refresh: %d %s", rr.Code, rr.Body.String())
	}
	close(release)
	if code := <-done; code != 200 {
		t.Fatalf("first refresh %d", code)
	}
	if g := f.list().group(t, "hk"); g.Actual.State != hubstate.StateOK {
		t.Fatalf("after serialised read %+v", g.Actual)
	}
}

func TestHubStateLimitsAgree(t *testing.T) {
	if sshexec.GroupStateMax != hubstate.MaxOutput || !strings.HasSuffix(sshexec.GroupStateCommand, fmt.Sprintf("head -c %d", hubstate.MaxOutput+1)) {
		t.Fatal("the command's output cap and the parser's limit differ")
	}
	for _, bad := range []string{"$1", "${", "`", "%v", "{{"} {
		if strings.Contains(strings.ReplaceAll(sshexec.GroupStateCommand, `"$(date +%s)"`, ""), bad) {
			t.Fatalf("the fixed command contains %q", bad)
		}
	}
}

// ------------------------------------------------- hub identity binding ---

// okOutput: the hub reports group hk on member hop (fresh, current plan).
func (f *hubFixture) okOutput(hop, reason string) string {
	now := time.Now().Unix()
	return hubOutput(f.plan, now, hubReport("hk", f.plan, now-2, "hop "+hop, "active "+hop, "reason "+reason))
}

// readOK stores a successful read from the current hub and returns its time.
func (f *hubFixture) readOK() string {
	f.t.Helper()
	f.serve(f.okOutput("hk-2", "failover"), 0)
	b := f.refresh(nil)
	hk := b.group(f.t, "hk")
	if hk.Actual.State != hubstate.StateOK || hk.Actual.Active != "hk-2" || b.HubState.LastRead == nil || !b.HubState.LastRead.Current {
		f.t.Fatalf("first read: %+v %+v", hk.Actual, b.HubState.LastRead)
	}
	return b.HubState.LastRead.ReadAt
}

// identityChanged: the stored read is shown as unknown because it was
// taken from another hub identity, on the group and on the hub bar, on
// both GET endpoints.
func (f *hubFixture) identityChanged(why string) {
	f.t.Helper()
	b := f.list()
	noActual(f.t, b.group(f.t, "hk"), hubstate.StateUnavailable, hubstate.CodeIdentityChanged)
	if g := b.group(f.t, "hk"); g.Actual.ReadAt == nil || g.Model.Source != "panel_model" {
		f.t.Fatalf("%s: %+v", why, g)
	}
	lr := b.HubState.LastRead
	if lr == nil || lr.Current || lr.IDCode != hubstate.CodeIdentityChanged || lr.IDMessage == "" || len(lr.Ignored) != 0 || b.HubState.Counts["ok"] != 0 {
		f.t.Fatalf("%s: hub state %+v", why, b.HubState)
	}
	rr := do(f.s, http.MethodGet, "/api/region-groups/hk", nil)
	if !strings.Contains(rr.Body.String(), `"code":"`+hubstate.CodeIdentityChanged+`"`) || strings.Contains(rr.Body.String(), `"state":"ok"`) {
		f.t.Fatalf("%s: GET group %s", why, rr.Body.String())
	}
}

// addServer registers another in-process SSH server as a managed server
// (password credential) and trusts its key.
func (f *hubFixture) addServer(name string) (*sshtest.Server, string) {
	f.t.Helper()
	srv, err := sshtest.Start()
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(srv.Close)
	srv.SetPassword(f.pw)
	rr := do(f.s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": name, "kind": "password", "password": f.pw}))
	var c struct{ Credential credView }
	decode(f.t, rr, &c)
	rr = do(f.s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": name, "address": srv.Host, "port": srv.Port, "user": "ops", "auth": "password", "credential_id": c.Credential.ID}))
	var sv struct{ Server serverView }
	decode(f.t, rr, &sv)
	f.trustServer(sv.Server.ID)
	return srv, sv.Server.ID
}

func (f *hubFixture) trustServer(id string) {
	f.t.Helper()
	rr := do(f.s, http.MethodPost, "/api/servers/"+id+"/host-key/discover", nil)
	var disc struct{ Discovery sshexec.Discovery }
	decode(f.t, rr, &disc)
	if rr = do(f.s, http.MethodPost, "/api/servers/"+id+"/host-key/trust", mustJSON(map[string]string{"fingerprint": disc.Discovery.Fingerprint})); rr.Code != 200 {
		f.t.Fatal(rr.Body.String())
	}
}

// relink points the hub node at another server.
func (f *hubFixture) relink(serverID string) {
	f.t.Helper()
	topo, _, _ := f.s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "hk-hub" {
			topo.Nodes[i].ServerID = serverID
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		f.t.Fatal(err)
	}
}

func (f *hubFixture) patchServer(body map[string]any) {
	f.t.Helper()
	if rr := do(f.s, http.MethodPatch, "/api/servers/"+f.server, mustJSON(body)); rr.Code != 200 {
		f.t.Fatalf("patch server: %d %s", rr.Code, rr.Body.String())
	}
}

// Re-linking the hub node to another server: the old host's report is
// unknown at once, and a new read reports the new host.
func TestHubStateIdentityRelink(t *testing.T) {
	f := newHubFixture(t, true)
	f.readOK()
	srv2, id2 := f.addServer("另一台枢纽")
	srv2.SetHandler(func(cmd, _ string) (string, uint32) {
		if cmd != sshexec.GroupStateCommand {
			return "unexpected", 1
		}
		return f.okOutput("hk-ix", "preferred"), 0
	})
	f.relink(id2)
	f.identityChanged("relinked")
	if b := f.list(); !b.HubState.Readable || b.HubState.ServerID != id2 {
		t.Fatalf("hub bar after relink %+v", b.HubState)
	}
	b := f.refresh(nil)
	if hk := b.group(t, "hk"); hk.Actual.State != hubstate.StateOK || hk.Actual.Active != "hk-ix" || !b.HubState.LastRead.Current {
		t.Fatalf("read of the new hub: %+v", hk.Actual)
	}
	if cmds := srv2.Commands(); len(cmds) != 1 || cmds[0] != sshexec.GroupStateCommand {
		t.Fatalf("new hub commands %q", cmds)
	}
	// And back: the stored read is now the second server's.
	f.relink(f.server)
	f.identityChanged("relinked back")
}

// Editing the same server's address in place, even when the very same key
// is pinned again afterwards: the read from the old address is unknown
// until the new address is read. A rename changes nothing.
func TestHubStateIdentityAddressEdit(t *testing.T) {
	f := newHubFixture(t, true)
	f.readOK()
	f.patchServer(map[string]any{"name": "改名后的枢纽", "notes": "x"})
	if hk := f.list().group(t, "hk"); hk.Actual.State != hubstate.StateOK {
		t.Fatalf("rename invalidated the read: %+v", hk.Actual)
	}
	f.patchServer(map[string]any{"address": "localhost"})
	f.identityChanged("address edited")
	if b := f.list(); b.HubState.Readable || b.HubState.NotReadable != hubstate.CodeServerNotReady {
		t.Fatalf("an edited address needs its key confirmed again: %+v", b.HubState)
	}
	// Same host, same key pinned again: the address still differs from
	// the read's.
	f.trust()
	f.identityChanged("address edited, key re-pinned")
	b := f.refresh(nil)
	if hk := b.group(t, "hk"); hk.Actual.State != hubstate.StateOK || !b.HubState.LastRead.Current {
		t.Fatalf("read at the new address: %+v %+v", hk.Actual, b.HubState.LastRead)
	}
}

// Changing the SSH port: unknown at once.
func TestHubStateIdentityPortEdit(t *testing.T) {
	f := newHubFixture(t, true)
	f.readOK()
	f.patchServer(map[string]any{"port": 2222})
	f.identityChanged("port edited")
	// Back to the old port: the key must be confirmed again, and until
	// then nothing is pinned, so the old read still does not count.
	f.patchServer(map[string]any{"port": f.srv.Port})
	f.identityChanged("port restored, key not pinned")
}

// A re-pinned (different) host key: unknown at once. A key contradicting
// the pin (mismatch) also stops the old report from counting.
func TestHubStateIdentityFingerprint(t *testing.T) {
	f := newHubFixture(t, true)
	f.readOK()
	f.srv.SetHostKey(sshtest.NewHostKey())
	// Discovery sees the other key: the pin is now contradicted.
	do(f.s, http.MethodPost, "/api/servers/"+f.server+"/host-key/discover", nil)
	b := f.list()
	noActual(t, b.group(t, "hk"), hubstate.StateUnavailable, hubstate.CodeIdentityChanged)
	if b.HubState.Readable || b.HubState.LastRead.Current {
		t.Fatalf("mismatch: %+v", b.HubState)
	}
	// Confirming the new key: a new pin, a new identity.
	f.trust()
	f.identityChanged("re-pinned")
	if b = f.refresh(nil); b.group(t, "hk").Actual.State != hubstate.StateOK {
		t.Fatalf("read with the new pin: %+v", b.group(t, "hk").Actual)
	}
	// Forgetting the key: nothing pinned, unknown.
	if rr := do(f.s, http.MethodDelete, "/api/servers/"+f.server+"/host-key", nil); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	f.identityChanged("pin forgotten")
}

// A read that was started against the old identity and ends after the
// identity changed is discarded: the stored read stays what it was and is
// shown as unknown for the new identity.
func TestHubStateIdentityLateResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *hubFixture)
	}{
		{"relink", func(f *hubFixture) { _, id2 := f.addServer("另一台"); f.relink(id2) }},
		{"repin", func(f *hubFixture) { f.srv.SetHostKey(sshtest.NewHostKey()); f.trust() }},
		{"address", func(f *hubFixture) { f.patchServer(map[string]any{"address": "localhost"}) }},
		{"port", func(f *hubFixture) { f.patchServer(map[string]any{"port": 2222}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHubFixture(t, true)
			first := f.readOK()
			release := make(chan struct{})
			started := make(chan struct{}, 1)
			f.mu.Lock()
			f.answer = func() (string, uint32) {
				started <- struct{}{}
				<-release
				return f.okOutput("hk-ix", "preferred"), 0
			}
			f.mu.Unlock()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- do(f.s, http.MethodPost, "/api/region-groups/runtime/refresh", nil) }()
			select {
			case <-started:
			case <-time.After(20 * time.Second):
				t.Fatal("read never reached the hub")
			}
			tc.change(f)
			// GETs while the read runs already show the change.
			f.identityChanged("during the read")
			close(release)
			rr := <-done
			var e apiErr
			_ = json.Unmarshal(rr.Body.Bytes(), &e)
			if rr.Code != http.StatusConflict || e.Code != hubstate.CodeIdentityChanged {
				t.Fatalf("late result: %d %s", rr.Code, rr.Body.String())
			}
			b := f.list()
			if b.HubState.LastRead == nil || b.HubState.LastRead.ReadAt != first || b.HubState.Refreshing {
				t.Fatalf("late result was stored: %+v", b.HubState)
			}
			f.identityChanged("after the late result")
			if strings.Contains(rr.Body.String(), f.pw) {
				t.Fatal("password in the response")
			}
		})
	}
}
