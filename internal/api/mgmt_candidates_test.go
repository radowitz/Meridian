package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// Tunnel management address candidates over the API (mgmt_candidates.go)
// and the connection test of a candidate before it is saved (ssh_ops.go).
// The SSH stand-in is reached only through SSHDial; nothing leaves the
// machine.

type mgmtFix struct {
	s    *Server
	srv  *sshtest.Server
	cs   *credentials.Store
	sid  string
	up   *fakeUpstream
	dial []string
}

// newMgmtFix: the nested example (main path and backup hub), the server of
// exit dc1 on a documentation address (never dialed), its candidate
// addresses dialed to the stand-in.
func newMgmtFix(t *testing.T) *mgmtFix {
	t.Helper()
	f := &mgmtFix{s: newTest(t), srv: startSSH(t), up: &fakeUpstream{}}
	f.s.Upstream = f.up
	topo := defaults.NestedExample()
	pw := "pw-" + rnd(t, 8)
	f.srv.SetPassword(pw)
	cs, err := f.s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	f.cs = cs
	c, err := cs.CreateSSHCredential("p", "", credentials.SSHSecretInput{Kind: credentials.KindPassword, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	sv, err := cs.CreateServer(credentials.ServerInput{Name: "机器 dc1", Address: "192.0.2.61", Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	f.sid = sv.ID
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "dc1" {
			topo.Nodes[i].ServerID = sv.ID
		}
	}
	if err := f.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	f.s.SSHDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		f.dial = append(f.dial, addr)
		host, _, _ := net.SplitHostPort(addr)
		if !strings.HasPrefix(host, "fd66:") && !strings.HasPrefix(host, "10.66.") {
			return nil, fmt.Errorf("test: refusing to dial %s", addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(f.srv.Host, fmt.Sprint(f.srv.Port)))
	}
	return f
}

type candView struct {
	ServerID string `json:"server_id"`
	Nodes    []struct {
		NodeID     string                  `json:"node_id"`
		States     []compile.MgmtState     `json:"states"`
		Candidates []compile.MgmtCandidate `json:"candidates"`
		Notes      []string                `json:"notes"`
	} `json:"nodes"`
	Carrying mgmtCarry    `json:"carrying"`
	Current  *mgmtCurrent `json:"current"`
	Message  string       `json:"message"`
}

func (f *mgmtFix) candidates(t *testing.T) candView {
	t.Helper()
	rr := do(f.s, http.MethodGet, "/api/servers/"+f.sid+"/tunnel-candidates", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var v candView
	decode(t, rr, &v)
	return v
}

// candOf finds the candidate on link of family (the panel allocates the
// link addresses itself, so tests do not hard-code them).
func candOf(v candView, link, family string) compile.MgmtCandidate {
	for _, n := range v.Nodes {
		for _, c := range n.Candidates {
			if c.LinkID == link && c.Family == family {
				return c
			}
		}
	}
	return compile.MgmtCandidate{}
}

// carry makes the gateway's upstream record name the state's interface.
func (f *mgmtFix) carry(t *testing.T, v candView, state string) {
	t.Helper()
	for _, st := range v.Nodes[0].States {
		if st.ID == state {
			tier := "primary"
			if st.Tier == "backup" {
				tier = "backup"
			}
			f.up.set(st.Hub, tier, time.Now().Unix())
			f.up.mu.Lock()
			f.up.st.Record.Iface, f.up.st.Record.Path = st.Iface, st.ID
			f.up.mu.Unlock()
			return
		}
	}
	t.Fatalf("no state %s", state)
}

func TestTunnelCandidatesAPI(t *testing.T) {
	f := newMgmtFix(t)
	v := f.candidates(t)
	if len(v.Nodes) != 1 || v.Nodes[0].NodeID != "dc1" || len(v.Nodes[0].States) != 3 || len(v.Nodes[0].Notes) == 0 {
		t.Fatalf("%+v", v)
	}
	if c := candOf(v, "ix-dc1", "ipv6"); c.Status != compile.MgmtUsable || c.Depends != compile.MgmtDependsMain || c.PeerID != "ix" {
		t.Fatalf("main candidate %+v", c)
	}
	if c := candOf(v, "hkb-dc1", "ipv6"); c.Status != compile.MgmtUsable || c.Depends != compile.MgmtDependsBackup {
		t.Fatalf("backup candidate %+v", c)
	}
	if c := candOf(v, "ix-dc1", "ipv4"); c.Status != compile.MgmtUnreachable || !strings.Contains(c.Reason, "AllowedIPs") {
		t.Fatalf("v4 candidate %+v", c)
	}
	// No upstream record: the carrying state is not known, and says why.
	if v.Carrying.Known || v.Carrying.Message == "" {
		t.Fatalf("carrying %+v", v.Carrying)
	}
	// The gateway records the backup hub: known.
	f.carry(t, v, "backup")
	if v := f.candidates(t); !v.Carrying.Known || v.Carrying.State != "backup" || v.Carrying.Tier != "backup" {
		t.Fatalf("carrying %+v", v.Carrying)
	}
	// Nothing was dialed to derive the candidates.
	if len(f.dial) != 0 {
		t.Fatalf("dialed %v", f.dial)
	}
	// A server without a node: no candidates, a message.
	sv, err := f.cs.CreateServer(credentials.ServerInput{Name: "闲置", Address: "192.0.2.62", Port: 22, User: "root", Auth: model.AuthPassword})
	if err != nil {
		t.Fatal(err)
	}
	f.sid = sv.ID
	if v := f.candidates(t); len(v.Nodes) != 0 || v.Message == "" {
		t.Fatalf("%+v", v)
	}
}

// The failure message per carrying state.
func TestTunnelPathNotePerCarryingState(t *testing.T) {
	topo := defaults.NestedExample()
	r, err := compile.ManagementCandidates(topo, "dc1")
	if err != nil {
		t.Fatal(err)
	}
	view := func(c mgmtCarry) *mgmtView {
		return &mgmtView{Nodes: []mgmtNode{{NodeID: "dc1", MgmtReach: r}}, Carrying: c}
	}
	main := mgmtCarry{Known: true, State: "udp", Label: "主链路，网关到中继走 UDP 腿", Tier: "main"}
	backup := mgmtCarry{Known: true, State: "backup", Label: "备用枢纽承载（网关直连备用枢纽的 WSS）", Tier: "backup"}
	unknown := mgmtCarry{Message: "读不到网关当前的承载路径：没有配置 host agent"}
	cases := []struct {
		addr  string
		carry mgmtCarry
		want  []string
	}{
		{"fd66:0:0:6::2", main, []string{"不是因为承载路径切换"}},
		{"fd66:0:0:6::2", backup, []string{"依赖主链路", "网关现在经备用枢纽承载", "主链路可能不通"}},
		{"fd66:0:0:4::2", main, []string{"依赖备用枢纽", "不经备用枢纽"}},
		{"fd66:0:0:4::2", backup, []string{"不是因为承载路径切换"}},
		{"fd66:0:0:6::2", unknown, []string{"依赖主链路", "读不到网关当前的承载路径", "无法判断"}},
		{"10.66.6.2", main, []string{"到不了", "AllowedIPs"}},
		{"10.66.99.9", main, []string{"手工填写", "未经推导"}},
	}
	for _, tc := range cases {
		note := tunnelNote(view(tc.carry), tc.addr)
		text, _ := note["text"].(string)
		for _, w := range tc.want {
			if !strings.Contains(text, w) {
				t.Fatalf("%s / %+v: %q lacks %q", tc.addr, tc.carry, text, w)
			}
		}
		if !strings.Contains(text, "不会自动改走其它管理通道") {
			t.Fatalf("%q", text)
		}
	}
}

// The connection test of a candidate before saving: pinned key required
// (first contact through the existing discovery and confirmation), the
// result is not recorded on the server, the stored channel is not
// touched, the rate-limit wait is honoured, and a failure carries the
// carrying-state note.
func TestTunnelCandidateConnectionTest(t *testing.T) {
	f := newMgmtFix(t)
	v := f.candidates(t)
	main := candOf(v, "ix-dc1", "ipv6").Address
	cand := map[string]any{"channel": map[string]any{"mode": "tunnel", "address": main, "port": 22}}
	path := "/api/servers/" + f.sid
	// Not pinned: refused before anything is dialed.
	if rr := do(f.s, http.MethodPost, path+"/test", mustJSON(cand)); rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), sshexec.CodeUntrusted) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if len(f.dial) != 0 {
		t.Fatalf("dialed %v", f.dial)
	}
	// Other modes are not tried before saving.
	if rr := do(f.s, http.MethodPost, path+"/test", mustJSON(map[string]any{"channel": map[string]any{"mode": "direct"}})); rr.Code != http.StatusBadRequest && rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("direct: %d %s", rr.Code, rr.Body.String())
	}
	// First contact through the candidate: discovered, then confirmed.
	var disc struct {
		Discovery struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"discovery"`
	}
	rr := do(f.s, http.MethodPost, path+"/host-key/discover", mustJSON(cand))
	decode(t, rr, &disc)
	if rr.Code != http.StatusOK || disc.Discovery.Fingerprint != f.srv.Fingerprint() {
		t.Fatalf("discover %d %s", rr.Code, rr.Body.String())
	}
	if sv, _ := f.cs.Server(f.sid); sv.HostKey.State != model.HostKeyDiscovered {
		t.Fatalf("discovery trusted the key by itself: %+v", sv.HostKey)
	}
	if rr := do(f.s, http.MethodPost, path+"/host-key/trust", mustJSON(map[string]any{"fingerprint": disc.Discovery.Fingerprint})); rr.Code != http.StatusOK {
		t.Fatalf("trust %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Test      model.ConnectionTest `json:"test"`
		Candidate bool                 `json:"candidate"`
		PathNote  map[string]any       `json:"path_note"`
	}
	rr = do(f.s, http.MethodPost, path+"/test", mustJSON(cand))
	decode(t, rr, &out)
	if rr.Code != http.StatusOK || !out.Test.OK || !out.Candidate || out.Test.Channel != model.ChannelTunnel || out.PathNote != nil {
		t.Fatalf("test %d %s", rr.Code, rr.Body.String())
	}
	if sv, _ := f.cs.Server(f.sid); sv.LastTest != nil || sv.Channel != nil {
		t.Fatalf("recorded on the server: %+v %+v", sv.LastTest, sv.Channel)
	}
	for _, a := range f.dial {
		if a != net.JoinHostPort(main, "22") {
			t.Fatalf("dialed %s", a)
		}
	}
	// The backup hub carries now and the main path is down: the failure
	// says that this address depends on the main path.
	f.carry(t, v, "backup")
	f.srv.Close()
	out.PathNote = nil
	rr = do(f.s, http.MethodPost, path+"/test", mustJSON(cand))
	decode(t, rr, &out)
	text, _ := out.PathNote["text"].(string)
	if rr.Code != http.StatusOK || out.Test.OK || !out.Test.NotExecuted || !strings.Contains(text, "依赖主链路") || !strings.Contains(text, "备用枢纽承载") {
		t.Fatalf("failure %d %s", rr.Code, rr.Body.String())
	}
	// Rate limited at the candidate: the next test inside the wait does
	// not connect.
	f2 := newMgmtFix(t)
	f2.srv.RefuseBeforeBanner("Not allowed at this time")
	if _, err := f2.cs.ObserveHostKey(f2.sid, "ssh-ed25519", f2.srv.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := f2.cs.TrustHostKey(f2.sid, f2.srv.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	rr = do(f2.s, http.MethodPost, "/api/servers/"+f2.sid+"/test", mustJSON(cand))
	decode(t, rr, &out)
	if out.Test.Code != sshexec.CodeRateLimited || out.Test.RetryAfter <= 0 {
		t.Fatalf("rate limited %s", rr.Body.String())
	}
	accepted := f2.srv.Accepted()
	rr = do(f2.s, http.MethodPost, "/api/servers/"+f2.sid+"/test", mustJSON(cand))
	decode(t, rr, &out)
	if out.Test.Code != sshexec.CodeRateLimited || f2.srv.Accepted() != accepted {
		t.Fatalf("connected during the wait: %s", rr.Body.String())
	}
}
