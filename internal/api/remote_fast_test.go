package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
)

// peerHost is a synthetic host agent: actions succeed (activate counted),
// the peer sync checks the written mra.conf (0600, digest) and can fail.
type peerHost struct {
	mu        sync.Mutex
	root      string
	activates int
	syncs     []hostexec.PeerSyncRequest
	failSync  bool
}

func (h *peerHost) Do(_ context.Context, req hostexec.Request) (hostexec.Result, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.Action == hostexec.ActionActivate {
		h.activates++
	}
	return hostexec.Result{RequestID: req.RequestID, Action: req.Action, OK: true}, nil
}

func (h *peerHost) PeerSync(_ context.Context, req hostexec.PeerSyncRequest) (hostexec.Result, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := hostexec.ValidatePeerSync(req); err != nil {
		return hostexec.Result{}, err
	}
	h.syncs = append(h.syncs, req)
	p := filepath.Join(h.root, "etc", "wireguard", "mra.conf")
	fi, err := os.Stat(p)
	b, _ := os.ReadFile(p)
	res := hostexec.Result{RequestID: req.Transaction, Action: hostexec.ActionPeerSync, OK: true,
		Steps: []hostexec.Step{{Name: "wg syncconf mra", OK: true}}}
	switch {
	case err != nil || fi.Mode().Perm() != 0o600:
		res.OK, res.Error = false, "mode"
	case hostexec.FileDigest(b) != req.Digest:
		res.OK, res.Error = false, "digest"
	case h.failSync && strings.HasSuffix(req.Transaction, "/fwd"):
		res.OK, res.Error = false, "wg syncconf mra 失败：synthetic"
	}
	if !res.OK {
		return res, &syncErr{res.Error}
	}
	return res, nil
}

type syncErr struct{ s string }

func (e *syncErr) Error() string { return "远程接入快速生效失败：" + e.s }

type fastResp struct {
	ApplyRequired bool      `json:"apply_required"`
	FastApply     fastApply `json:"fast_apply"`
	Config        *struct {
		Text string `json:"text"`
	} `json:"config"`
	Device struct {
		ID        string `json:"id"`
		PublicKey string `json:"public_key"`
	} `json:"device"`
}

func fastCall(t *testing.T, s *Server, method, path, body string, want int) (fastResp, string) {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	rr := do(s, method, path, b)
	if rr.Code != want {
		t.Fatalf("%s %s: %d %s", method, path, rr.Code, rr.Body.String())
	}
	var out fastResp
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out, rr.Body.String()
}

// fastRig: remote access configured, one device, gateway installed.
func fastRig(t *testing.T) (*Server, *peerHost) {
	t.Helper()
	s, host, _ := installTest(t)
	s.Activate = nil
	h := &peerHost{root: host}
	s.Host = h
	s.HostPreflight = &fakeHostPreflight{}
	fastCall(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true,"endpoint":"home.example.net","listen_port":51999}`, 200)
	r, _ := fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"phone"}`, 201)
	if !r.ApplyRequired || r.FastApply.Status != FastSkipped || r.FastApply.Reason != "网关尚未安装" {
		t.Fatalf("before the first install: %+v", r)
	}
	opInstall(t, s)
	return s, h
}

// opInstall is the operator's install with a reviewed preflight.
func opInstall(t *testing.T, s *Server) {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != 200 {
		t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID})); rr.Code != 200 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
}

func installedVersion(t *testing.T, s *Server) int64 {
	t.Helper()
	m, err := s.applier(true).Installed()
	if err != nil {
		t.Fatal(err)
	}
	return m.Version
}

func hostMRA(t *testing.T, s *Server) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.HostRoot, "etc", "wireguard", "mra.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func inSync(t *testing.T, s *Server) {
	t.Helper()
	topo, _ := s.topology()
	b, err := s.compileTopo(topo)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.applier(true).InstalledDiff(b)
	if err != nil || d == nil || !d.Empty() {
		t.Fatalf("panel not in sync with the gateway: %+v %v", d, err)
	}
}

// Add and delete are installed at once: a normal transaction (version +1,
// rollback-able, in sync) activated by the peer sync, no restart, and no
// secret in any response, record or log.
func TestRemoteFastApplyAddDelete(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s, h := fastRig(t)
	v0 := installedVersion(t, s)
	act := h.activates

	r, body := fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"laptop"}`, 201)
	if r.ApplyRequired || r.FastApply.Status != FastApplied || r.FastApply.Version != v0+1 {
		t.Fatalf("add: %s", body)
	}
	if installedVersion(t, s) != v0+1 || h.activates != act || len(h.syncs) != 1 {
		t.Fatalf("version %d activates %d syncs %d", installedVersion(t, s), h.activates-act, len(h.syncs))
	}
	mra := hostMRA(t, s)
	if !strings.Contains(mra, r.Device.PublicKey) {
		t.Fatal("new peer not on the host")
	}
	fi, _ := os.Stat(filepath.Join(s.HostRoot, "etc", "wireguard", "mra.conf"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	inSync(t, s)
	if !s.applier(true).PreviousAvailable() {
		t.Fatal("fast install is not rollback-able")
	}
	cs, _ := s.credStore()
	topo, _ := s.topology()
	gwKey, _ := cs.WGSecret(topo.RemoteAccess.KeyID)
	psk, _ := cs.WGSecret(topo.RemoteAccess.Devices[0].PSKID)
	priv := cfgPrivate.FindStringSubmatch(r.Config.Text)[1]
	if !strings.Contains(mra, gwKey) || !strings.Contains(mra, psk) {
		t.Fatal("secrets not injected at the install boundary")
	}
	secrets := []string{gwKey, psk, priv}

	// Rename: nothing changes on the host.
	r2, _ := fastCall(t, s, http.MethodPatch, "/api/remote-access/devices/"+r.Device.ID, `{"name":"laptop2"}`, 200)
	if r2.ApplyRequired || r2.FastApply.Status != FastNone {
		t.Fatalf("rename: %+v", r2)
	}

	d, body := fastCall(t, s, http.MethodDelete, "/api/remote-access/devices/"+r.Device.ID, "", 200)
	if d.ApplyRequired || d.FastApply.Status != FastApplied || installedVersion(t, s) != v0+2 || h.activates != act {
		t.Fatalf("delete: %s", body)
	}
	if strings.Contains(hostMRA(t, s), r.Device.PublicKey) {
		t.Fatal("deleted peer still on the host")
	}
	inSync(t, s)
	for _, v := range secrets {
		if strings.Contains(body, v) || strings.Contains(logs.String(), v) {
			t.Fatal("secret in a response or the log")
		}
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
	// Rollback goes back through the normal runtime rollback.
	if rr := do(s, http.MethodPost, "/api/rollback", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if !strings.Contains(hostMRA(t, s), r.Device.PublicKey) {
		t.Fatal("rollback did not restore the previous peers")
	}
}

// A failing syncconf is compensated: the previous mra.conf is written back
// and synced, the version stays, and the reason comes back in one line.
func TestRemoteFastApplyFailureRestores(t *testing.T) {
	s, h := fastRig(t)
	v0 := installedVersion(t, s)
	before := hostMRA(t, s)
	h.failSync = true
	r, body := fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"tablet"}`, 201)
	if !r.ApplyRequired || r.FastApply.Status != FastFailed || !strings.Contains(r.FastApply.Reason, "已恢复原配置") || strings.Contains(r.FastApply.Reason, "\n") {
		t.Fatalf("%s", body)
	}
	if hostMRA(t, s) != before || installedVersion(t, s) != v0 {
		t.Fatal("previous mra.conf not restored")
	}
	if len(h.syncs) != 2 || !strings.HasSuffix(h.syncs[1].Transaction, "/comp") {
		t.Fatalf("compensation did not sync the previous peers: %+v", h.syncs)
	}
	if p, _ := s.applier(true).Pending(); p != nil {
		t.Fatalf("transaction left pending: %+v", p)
	}
	// The response carries the new device's one-time config, nothing else
	// secret: not the gateway key, not another device's PSK, and the
	// reason none at all.
	cs, _ := s.credStore()
	topo, _ := s.topology()
	for _, id := range []string{topo.RemoteAccess.KeyID, topo.RemoteAccess.Devices[0].PSKID} {
		v, _ := cs.WGSecret(id)
		if v == "" || strings.Contains(body, v) {
			t.Fatal("secret in the failure response")
		}
	}
	for _, m := range cs.WGSecretIDs() {
		v, _ := cs.WGSecret(m.ID)
		if strings.Contains(r.FastApply.Reason, v) {
			t.Fatal("secret in the failure reason")
		}
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
	// The earlier device stays pending: the next change is not installed
	// along with it (see TestRemoteFastApplyPendingBefore).
	h.failSync = false
	n := len(h.syncs)
	r, _ = fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"watch"}`, 201)
	if !r.ApplyRequired || r.FastApply.Status != FastSkipped || r.FastApply.Reason != remoteFastPending || len(h.syncs) != n || installedVersion(t, s) != v0 {
		t.Fatalf("%+v", r)
	}
	// After the operator's install the fast path is back.
	opInstall(t, s)
	r, _ = fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"ring"}`, 201)
	if r.FastApply.Status != FastApplied || strings.Count(hostMRA(t, s), "[Peer]") != 4 {
		t.Fatalf("%+v", r)
	}
}

// Device A's sync fails and A stays pending; adding device B afterwards
// does not fast-apply A and B together.
func TestRemoteFastApplyPendingBefore(t *testing.T) {
	s, h := fastRig(t)
	v0 := installedVersion(t, s)
	h.failSync = true
	a, body := fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"A"}`, 201)
	if a.FastApply.Status != FastFailed || installedVersion(t, s) != v0 {
		t.Fatalf("A: %s", body)
	}
	h.failSync = false
	n := len(h.syncs)
	before := hostMRA(t, s)
	b, body := fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"B"}`, 201)
	if !b.ApplyRequired || b.FastApply.Status != FastSkipped || b.FastApply.Reason != remoteFastPending {
		t.Fatalf("B: %s", body)
	}
	if len(h.syncs) != n || installedVersion(t, s) != v0 || hostMRA(t, s) != before {
		t.Fatalf("B installed: syncs %d->%d version %d", n, len(h.syncs), installedVersion(t, s))
	}
	// The same holds for a patch and a delete while A is pending.
	if r, _ := fastCall(t, s, http.MethodDelete, "/api/remote-access/devices/"+b.Device.ID, "", 200); r.FastApply.Status != FastSkipped || len(h.syncs) != n {
		t.Fatalf("delete B: %+v", r)
	}
}

// Pool/port changes, other pending changes, a busy gateway and the rate
// limit are not the fast path.
func TestRemoteFastApplyNotEligible(t *testing.T) {
	s, h := fastRig(t)
	v0 := installedVersion(t, s)
	add := func(name string) fastResp {
		r, _ := fastCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"`+name+`"}`, 201)
		return r
	}
	// Another gateway file pending: a peer node's key changes its tunnel.
	topo, _, _ := s.Store.Load()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID != localNodeID {
			topo.Nodes[i].PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, 32))
			break
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	if r := add("a"); !r.ApplyRequired || r.FastApply.Status != FastSkipped || r.FastApply.Reason != remoteFastPending {
		t.Fatalf("other pending: %+v", r)
	}
	opInstall(t, s)
	// Port change: the [Interface] section changes.
	fastCall(t, s, http.MethodPut, "/api/remote-access", `{"listen_port":51998}`, 200)
	if r := add("b"); !r.ApplyRequired || r.FastApply.Status != FastSkipped {
		t.Fatalf("port: %+v", r)
	}
	opInstall(t, s)
	// Busy gateway.
	if !s.lockNode(localNodeID) {
		t.Fatal("lock")
	}
	if r := add("c"); r.FastApply.Status != FastSkipped || r.FastApply.Reason != "网关正忙" {
		t.Fatalf("busy: %+v", r)
	}
	s.unlockNode(localNodeID)
	opInstall(t, s)
	// Rate limit.
	var doc remoteFastDoc
	for i := 0; i < remoteFastHourMax; i++ {
		doc.Attempts = append(doc.Attempts, time.Now().UTC())
	}
	buf, _ := json.Marshal(doc)
	_ = s.Store.Put(remoteFastKey, string(buf))
	if r := add("d"); r.FastApply.Status != FastSkipped || !strings.Contains(r.FastApply.Reason, "频繁") {
		t.Fatalf("rate: %+v", r)
	}
	_ = s.Store.Put(remoteFastKey, "{}")
	opInstall(t, s)
	if r := add("e"); r.FastApply.Status != FastApplied {
		t.Fatalf("after: %+v", r)
	}
	if h.activates == 0 || installedVersion(t, s) <= v0 {
		t.Fatal("full installs did not run")
	}
	// An agent without the peer sync: not the fast path.
	s.Host = nil
	s.Activate = func() error { return nil }
	if r := add("f"); r.FastApply.Status != FastSkipped {
		t.Fatalf("no peer sync: %+v", r)
	}
}

// The [Interface] section compares equal with and without peers, so going
// from zero devices to one (or deleting the last one) stays a peer-only
// change and takes the fast path.
func TestRemoteIfaceSectionZeroPeers(t *testing.T) {
	iface := "[Interface]\nAddress = 10.67.0.1/24\nListenPort = 51999\nPrivateKey = __X__\n"
	withPeer := iface + "\n[Peer]\nPublicKey = AAAA\nAllowedIPs = 10.67.0.2/32\n"
	for _, c := range []struct{ a, b string }{
		{iface, withPeer},
		{iface + "\n", withPeer},
		{strings.TrimRight(iface, "\n"), withPeer},
	} {
		if remoteIfaceSection(c.a) != remoteIfaceSection(c.b) {
			t.Fatalf("interface sections differ:\n%q\n%q", remoteIfaceSection(c.a), remoteIfaceSection(c.b))
		}
	}
	if remoteIfaceSection(iface) == remoteIfaceSection(strings.Replace(iface, "51999", "51998", 1)) {
		t.Fatal("a port change must still differ")
	}
}
