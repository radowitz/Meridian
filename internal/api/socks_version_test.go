package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sshexec"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// SOCKS credential versions (socks_version.go). The hosts are the local SSH
// stand-ins (sshtest): no remote host is contacted.

// The version line: written only into a config that names a tracked SOCKS
// credential, read back the same, never a value; a config whose
// credentials are all untracked is returned byte for byte.
func TestSOCKSVersionStamp(t *testing.T) {
	a, b := "socks-0123456789ab", "socks-ba9876543210"
	body := "# Meridian external SOCKS exits: transparent TCP redirector (gost test).\n# Secret-bearing (0600): the proxy credentials are injected at install.\nservices:\n" +
		"          username: \"__MERIDIAN_SECRET_" + a + "-user__\"\n          password: \"__MERIDIAN_SECRET_" + a + "-pass__\"\n" +
		"          username: \"__MERIDIAN_SECRET_" + b + "-user__\"\n          password: \"__MERIDIAN_SECRET_" + b + "-pass__\"\n"
	if ids := socksCredIDsIn(body); len(ids) != 2 || ids[0] != a || ids[1] != b {
		t.Fatalf("ids %v", ids)
	}
	// Nothing tracked, or only credentials the file does not name: unchanged.
	for _, vers := range []map[string]int{nil, {}, {"socks-ffffffffffff": 4}, {a: 0}} {
		if got := stampSOCKSVersions(body, vers); got != body {
			t.Fatalf("changed with %v:\n%s", vers, got)
		}
	}
	// One of two tracked: only that one is named, after the header.
	got := stampSOCKSVersions(body, map[string]int{b: 3})
	want := strings.Replace(body, "services:\n", socksVersionMarker+b+"=3"+socksVersionNote+"\nservices:\n", 1)
	if got != want {
		t.Fatalf("stamped:\n%s", got)
	}
	if v := socksVersionsIn(got); len(v) != 1 || v[b] != 3 {
		t.Fatalf("read back %v", v)
	}
	got = stampSOCKSVersions(body, map[string]int{a: 2, b: 11})
	if v := socksVersionsIn(got); len(v) != 2 || v[a] != 2 || v[b] != 11 || !strings.Contains(got, socksVersionMarker+a+"=2,"+b+"=11 ") {
		t.Fatalf("read back %v from\n%s", v, got)
	}
	// Stamping twice changes nothing; the placeholders are all still there.
	if again := stampSOCKSVersions(got, map[string]int{a: 9}); again != got || strings.Count(got, "__MERIDIAN_SECRET_") != 4 {
		t.Fatalf("stamped twice:\n%s", again)
	}
	if v := socksVersionsIn(body); v != nil {
		t.Fatalf("unstamped read back %v", v)
	}
	// A line this file does not write is not read as versions.
	for _, bad := range []string{"x=1", a + "=0", a + "=x", a, "dnsacct-0123456789ab=1"} {
		if v := socksVersionsIn("# h\n" + socksVersionMarker + bad + " (x)\nservices:\n"); v != nil {
			t.Fatalf("%q read as %v", bad, v)
		}
	}
	// Only the redirector config counts, wherever the node is.
	files := map[string]string{"nodes/dc2" + compile.ExtProxyConfig: got, "nodes/dc2/etc/other.yaml": got}
	if v := socksVersionsOf(files); len(v) != 2 {
		t.Fatalf("%v", v)
	}
	if v := socksVersionsOf(map[string]string{"/etc/other.yaml": got}); v != nil {
		t.Fatalf("%v", v)
	}
	if ids := socksCredsOf(map[string]string{compile.ExtProxyConfig: body}); len(ids) != 2 {
		t.Fatalf("%v", ids)
	}
	// Other kinds of placeholders are not SOCKS credentials.
	if ids := socksCredIDsIn("x __MERIDIAN_SECRET_dnsacct-0123456789ab__ y"); len(ids) != 0 {
		t.Fatalf("%v", ids)
	}
}

// carrierHost is one synthetic carrier host: it answers the preflight
// with the clean report (its external proxies reachable), the provision
// script with success, and keeps the journal and manifest a real host
// would.
type carrierHost struct {
	srv  *sshtest.Server
	mu   sync.Mutex
	host string
	// during runs once, while the next provision script "runs";
	// onPreflight once, while the preflight command after skip more of
	// them "runs".
	during      func()
	onPreflight func()
	skip        int
}

func (h *carrierHost) scripts() []string {
	var out []string
	for _, in := range h.srv.Stdins() {
		if strings.Contains(in, "echo MERIDIAN_PROVISION_OK") {
			out = append(out, in)
		}
	}
	return out
}

// carrierFix is a panel with the external example topology (myext behind
// carrier dc2, my2 behind carrier dc1) and a synthetic host per carrier.
type carrierFix struct {
	s     *Server
	hosts map[string]*carrierHost
}

const carrierProbes = "link wg9\nroute4 198.51.100.64/29 dev wg9 proto kernel scope link src 198.51.100.65\ntcpconnect 198.51.100.66 1080 ok\ntcpconnect 198.51.100.67 1080 ok\n"

func socksCreate(t *testing.T, s *Server, name, user, pass string) string {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/socks-credentials", mustJSON(map[string]any{"name": name, "username": user, "password": pass}))
	var c struct{ Credential socksCredView }
	if rr.Code != http.StatusCreated || json.Unmarshal(rr.Body.Bytes(), &c) != nil || c.Credential.ID == "" {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	return c.Credential.ID
}

type socksRotateAnswer struct {
	Credential socksCredView `json:"credential"`
	Pending    []string      `json:"pending"`
	Note       string        `json:"note"`
}

func socksRotate(t *testing.T, s *Server, id, user, pass string) socksRotateAnswer {
	t.Helper()
	rr := do(s, http.MethodPut, "/api/socks-credentials/"+id+"/secret", mustJSON(map[string]any{"username": user, "password": pass}))
	var out socksRotateAnswer
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	noSecretIn(t, "rotate answer", rr.Body.String(), user, pass)
	return out
}

// newCarrierFix saves the topology (myext uses credential cred1 behind dc2,
// my2 uses cred2 behind dc1) and gives both carriers a trusted server.
func newCarrierFix(t *testing.T, s *Server, cred1, cred2 string) *carrierFix {
	t.Helper()
	f := &carrierFix{s: s, hosts: map[string]*carrierHost{}}
	topo := defaults.ExternalExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "myext" {
			topo.Nodes[i].External.CredentialID = cred1
		}
	}
	topo.Nodes = append(topo.Nodes, model.Node{
		ID: "my2", Name: "第二台外部出口", Role: model.RoleExit, Region: "my", Managed: false, X: 880, Y: 340,
		PathV4: true, EgressV4: true,
		External: &model.ExternalExit{Carrier: "dc1", SOCKSAddress: "198.51.100.67", SOCKSPort: 1080, Interface: "wg9", CredentialID: cred2},
	})
	for i := range topo.Groups {
		if topo.Groups[i].ID == "my" {
			topo.Groups[i].Members = append(topo.Groups[i].Members, "my2")
		}
	}
	if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	pw := "pw-" + rnd(t, 8)
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw", "kind": "password", "password": pw}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	for _, node := range []string{"dc1", "dc2"} {
		h := &carrierHost{srv: startSSH(t)}
		h.srv.SetPassword(pw)
		h.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
			h.mu.Lock()
			extra := carrierProbes + hostLinkMTU(h.host)
			h.mu.Unlock()
			if out, ok := cleanPreflight(cmd, stdin, extra); ok {
				h.mu.Lock()
				var hook func()
				if h.onPreflight != nil {
					if h.skip > 0 {
						h.skip--
					} else {
						hook, h.onPreflight = h.onPreflight, nil
					}
				}
				h.mu.Unlock()
				if hook != nil {
					hook()
				}
				return out, 0
			}
			if cmd == "bash -s" && strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") {
				h.mu.Lock()
				during := h.during
				h.during = nil
				h.mu.Unlock()
				if during != nil {
					during()
				}
				out := "MERIDIAN_PROVISION_OK\n"
				h.mu.Lock()
				h.host = defaultHostRecord(stdin, out, h.host)
				h.mu.Unlock()
				return out, 0
			}
			if cmd == sshexec.NodeStateCommand {
				h.mu.Lock()
				rec := h.host
				h.mu.Unlock()
				return "meridian-node-state 1\n" + rec + "meridian-node-state-end\n", 0
			}
			if cmd == sshexec.TestCommand {
				return "MERIDIAN_ARCH=x86_64\n", 0
			}
			return "unexpected", 1
		})
		rr := do(s, http.MethodPost, "/api/servers", mustJSON(map[string]any{"name": "承载 " + node, "address": h.srv.Host, "port": h.srv.Port, "user": "root", "auth": "password", "credential_id": c.Credential.ID}))
		var sv struct{ Server serverView }
		decode(t, rr, &sv)
		do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/discover", nil)
		if rr := do(s, http.MethodPost, "/api/servers/"+sv.Server.ID+"/host-key/trust", mustJSON(map[string]string{"fingerprint": h.srv.Fingerprint()})); rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
		stored, _, _ := s.Store.Load()
		for i := range stored.Nodes {
			if stored.Nodes[i].ID == node {
				stored.Nodes[i].ServerID, stored.Nodes[i].SSHHost, stored.Nodes[i].SSHPort, stored.Nodes[i].SSHUser = sv.Server.ID, "", 0, ""
			}
		}
		if err := s.Store.Save(stored); err != nil {
			t.Fatal(err)
		}
		f.hosts[node] = h
	}
	return f
}

func (f *carrierFix) preflight(t *testing.T, node string) preflightRecord {
	t.Helper()
	rr := do(f.s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": node}))
	var out struct{ Preflight preflightRecord }
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatalf("preflight %s: %d %s", node, rr.Code, rr.Body.String())
	}
	if out.Preflight.Blocking {
		t.Fatalf("preflight %s blocks: %+v", node, out.Preflight.Findings)
	}
	return out.Preflight
}

func (f *carrierFix) provision(node, pf string) *httptest.ResponseRecorder {
	return do(f.s, http.MethodPost, "/api/provision", mustJSON(map[string]any{"node_id": node, "preflight_id": pf}))
}

// install preflights and installs node and returns the script that ran.
func (f *carrierFix) install(t *testing.T, node string) string {
	t.Helper()
	n := len(f.hosts[node].scripts())
	if rr := f.provision(node, f.preflight(t, node).ID); rr.Code != 200 {
		t.Fatalf("install %s: %d %s", node, rr.Code, rr.Body.String())
	}
	sc := f.hosts[node].scripts()
	if len(sc) != n+1 {
		t.Fatalf("install %s ran %d scripts", node, len(sc)-n)
	}
	return sc[len(sc)-1]
}

func (f *carrierFix) scriptCount() int {
	n := 0
	for _, h := range f.hosts {
		n += len(h.scripts())
	}
	return n
}

// socksViews are the read-only views checked for SOCKS material.
func socksViews() []string {
	return append([]string{"/api/socks-credentials", "/api/provision/state", "/api/provision/preflight/dc1", "/api/provision/preflight/dc2", "/api/deploy", "/api/deployments", "/api/dns", "/api/region-groups", "/api/upstream"}, readOnlyViews...)
}

func assertNoSOCKSMaterial(t *testing.T, s *Server, logs *bytes.Buffer, secrets ...string) {
	t.Helper()
	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		noSecretIn(t, "POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String(), secrets...)
	}
	for _, p := range socksViews() {
		noSecretIn(t, "GET "+p, do(s, http.MethodGet, p, nil).Body.String(), secrets...)
	}
	if logs != nil {
		noSecretIn(t, "logs", logs.String(), secrets...)
	}
	for _, v := range secrets {
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
}

func planStepOf(t *testing.T, s *Server, node string) (planStep, bool) {
	t.Helper()
	var dv struct {
		Plan *deployPlan `json:"plan"`
	}
	decode(t, do(s, http.MethodGet, "/api/deploy", nil), &dv)
	if dv.Plan == nil {
		t.Fatal("no deployment plan")
	}
	for _, st := range dv.Plan.Steps {
		if st.NodeID == node {
			return st, true
		}
	}
	return planStep{}, false
}

// Rotating a SOCKS credential on a panel that tracks versions from the
// start: every carrier of an exit that uses it is "changed" with the
// rotation as reason and an install step of the plan; nodes that do not
// carry it keep their bundle; a preflight reviewed before the rotation is
// refused; installing one carrier brings that carrier back in sync and
// leaves the other pending; neither the old nor the new username and
// password is anywhere but the install scripts.
func TestSOCKSRotationMarksCarriersPending(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	oldU, oldP, newU, newP := "su-"+rnd(t, 6), "sp-"+rnd(t, 8), "nu-"+rnd(t, 6), "np-"+rnd(t, 8)
	secrets := []string{oldU, oldP, newU, newP}
	id := socksCreate(t, s, "路由器", oldU, oldP)
	f := newCarrierFix(t, s, id, id)

	for _, node := range []string{"dc1", "dc2"} {
		sc := f.install(t, node)
		if !strings.Contains(sc, `username: "`+oldU+`"`) || !strings.Contains(sc, `password: "`+oldP+`"`) || !strings.Contains(sc, socksVersionMarker+id+"=1 ") {
			t.Fatalf("the first install of %s did not carry the credential and its version", node)
		}
		st := nodeState(t, s, node)
		if st.State != nodeInSync || st.Pending || st.SOCKSVersions[id] != 1 || st.InstalledSOCKSVersions[id] != 1 || len(st.SOCKSUnrecorded) != 0 || st.Note != "" {
			t.Fatalf("%s after install: %+v", node, st)
		}
	}
	before := bundlesOf(t, s)
	reviewed := f.preflight(t, "dc2") // reviewed before the rotation
	if reviewed.SOCKSVersions[id] != 1 {
		t.Fatalf("preflight versions %v", reviewed.SOCKSVersions)
	}

	rot := socksRotate(t, s, id, newU, newP)
	if rot.Credential.Version != 2 || !rot.Credential.Tracked || strings.Join(rot.Pending, ",") != "dc1,dc2" || !strings.Contains(rot.Note, "dc1") || !strings.Contains(rot.Note, "dc2") {
		t.Fatalf("rotate answer %+v", rot)
	}

	// State: both carriers changed, everything else as before.
	after := bundlesOf(t, s)
	topo := mustTopo(t, s)
	for _, n := range topo.Nodes {
		if !n.Managed || n.Role == model.RoleGateway {
			continue
		}
		carries := len(carrierSOCKSCredentials(topo, n.ID)) > 0
		if changed := before[n.ID] != after[n.ID]; changed != carries {
			t.Fatalf("node %s carries the credential: %v, bundle changed: %v", n.ID, carries, changed)
		}
	}
	for _, node := range []string{"dc1", "dc2"} {
		st := nodeState(t, s, node)
		if st.State != nodeChanged || !st.Pending || !strings.Contains(st.Reason, "外部 SOCKS 凭据已轮换") || !strings.Contains(st.Reason, "已安装版本 1，现在是版本 2") ||
			st.SOCKSVersions[id] != 2 || st.InstalledSOCKSVersions[id] != 1 {
			t.Fatalf("%s after rotation: %+v", node, st)
		}
		step, ok := planStepOf(t, s, node)
		if !ok || step.VerifyOnly || step.PlanState != nodeChanged || step.PlanBundle != after[node] {
			t.Fatalf("plan step of %s: %v %+v", node, ok, step)
		}
	}
	for _, node := range []string{"access", "ix", "hkb"} {
		if st := nodeState(t, s, node); st.SOCKSVersions != nil || st.InstalledSOCKSVersions != nil || st.SOCKSUnrecorded != nil || st.Note != "" || strings.Contains(st.Reason, "SOCKS") {
			t.Fatalf("%s does not carry an external exit: %+v", node, st)
		}
	}

	// The preflight reviewed before the rotation no longer counts.
	n := f.scriptCount()
	rr := f.provision("dc2", reviewed.ID)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), codeBundleChanged) || f.scriptCount() != n {
		t.Fatalf("stale preflight: %d %s", rr.Code, rr.Body.String())
	}

	// A new preflight shows the version; the install injects the new pair.
	pf := f.preflight(t, "dc2")
	if pf.SOCKSVersions[id] != 2 {
		t.Fatalf("preflight versions %v", pf.SOCKSVersions)
	}
	shown := false
	for _, ch := range pf.Evaluation.Changes {
		shown = shown || ch.Resource == compile.ExtProxyConfig && strings.Contains(ch.Detail, id+" 版本 2")
	}
	if !shown {
		t.Fatalf("preflight changes %+v", pf.Evaluation.Changes)
	}
	noSecretIn(t, "preflight", string(mustJSON(pf)), secrets...)
	if rr := f.provision("dc2", pf.ID); rr.Code != 200 {
		t.Fatalf("reinstall: %d %s", rr.Code, rr.Body.String())
	} else {
		noSecretIn(t, "install answer", rr.Body.String(), secrets...)
	}
	sc := f.hosts["dc2"].scripts()
	last := sc[len(sc)-1]
	if !strings.Contains(last, `username: "`+newU+`"`) || !strings.Contains(last, `password: "`+newP+`"`) || strings.Contains(last, oldU) || strings.Contains(last, oldP) || !strings.Contains(last, socksVersionMarker+id+"=2 ") {
		t.Fatal("the reinstall did not carry the new credential and version only")
	}
	if st := nodeState(t, s, "dc2"); st.State != nodeInSync || st.Pending || st.InstalledSOCKSVersions[id] != 2 || st.Reason != "" {
		t.Fatalf("dc2 after reinstall: %+v", st)
	}
	// Installing dc2 did not bring dc1 in sync: it still runs version 1.
	if st := nodeState(t, s, "dc1"); st.State != nodeChanged || !st.Pending || st.InstalledSOCKSVersions[id] != 1 || !strings.Contains(st.Reason, "已轮换") {
		t.Fatalf("dc1 after dc2's reinstall: %+v", st)
	}
	if _, ok := planStepOf(t, s, "dc1"); !ok {
		t.Fatal("dc1 left the plan when dc2 was installed")
	}
	if sc := f.install(t, "dc1"); !strings.Contains(sc, `password: "`+newP+`"`) {
		t.Fatal("dc1's reinstall did not carry the new password")
	}
	if st := nodeState(t, s, "dc1"); st.State != nodeInSync || st.InstalledSOCKSVersions[id] != 2 {
		t.Fatalf("dc1 after reinstall: %+v", st)
	}

	// Secret hygiene, old and new pair: responses, compile output, diff,
	// plan, export, logs and every file outside secrets/.
	assertNoSOCKSMaterial(t, s, &logs, secrets...)
	rr = do(s, http.MethodPost, "/api/compile", []byte(`{}`))
	if !strings.Contains(rr.Body.String(), socksVersionMarker+id+"=2 ") || !strings.Contains(rr.Body.String(), "__MERIDIAN_SECRET_"+id+"-pass__") {
		t.Fatalf("compile output lacks the version or the placeholder: %.300s", rr.Body.String())
	}
	// The digests are of the placeholder form: the same before and after a
	// rotation to the very same pair would differ only by the counter.
	var list struct {
		Credentials []socksCredView           `json:"credentials"`
		Tracking    credentials.SOCKSTracking `json:"version_tracking"`
	}
	decode(t, do(s, http.MethodGet, "/api/socks-credentials", nil), &list)
	if !list.Tracking.Ready || len(list.Credentials) != 1 || list.Credentials[0].Version != 2 || !list.Credentials[0].Tracked || strings.Join(list.Credentials[0].Carriers, ",") != "dc1,dc2" {
		t.Fatalf("list %+v", list)
	}
}

// The bundle digest depends on the version counter and never on the
// material: rotating to other values and rotating to the same values move
// it the same way, and two stores with different material but the same
// counters compile the same carrier files.
func TestSOCKSDigestIsOfVersionNotMaterial(t *testing.T) {
	digests := func(user, pass string, rotate ...[2]string) (string, string) {
		s := newTest(t)
		do(s, http.MethodGet, "/api/topology", nil)
		id := socksCreate(t, s, "路由器", user, pass)
		topo := defaults.ExternalExample()
		for i := range topo.Nodes {
			if topo.Nodes[i].External != nil {
				topo.Nodes[i].External.CredentialID = id
			}
		}
		if rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo)); rr.Code != 200 {
			t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
		}
		for _, r := range rotate {
			socksRotate(t, s, id, r[0], r[1])
		}
		b, err := s.compileTopo(mustTopo(t, s))
		if err != nil {
			t.Fatal(err)
		}
		body := provision.FilesFor(b.Files, "dc2")[compile.ExtProxyConfig]
		for _, v := range append([]string{user, pass}, func() []string {
			var out []string
			for _, r := range rotate {
				out = append(out, r[0], r[1])
			}
			return out
		}()...) {
			if strings.Contains(body, v) {
				t.Fatal("material in the compiled carrier config")
			}
		}
		// Normalise the store's random credential id.
		return strings.ReplaceAll(body, id, "socks-ID"), body
	}
	a1, _ := digests("user-a", "pass-a")
	b1, _ := digests("user-b", "pass-b")
	if a1 != b1 {
		t.Fatal("the compiled carrier config depends on the material")
	}
	a2, _ := digests("user-a", "pass-a", [2]string{"user-c", "pass-c"})
	same2, _ := digests("user-a", "pass-a", [2]string{"user-a", "pass-a"})
	if a2 != same2 || a2 == a1 || !strings.Contains(a2, socksVersionMarker+"socks-ID=2 ") {
		t.Fatal("a rotation must change the config by the counter alone")
	}
}

// An open deployment run goes stale when a tracked SOCKS credential its
// carriers name is rotated; a topology without an external exit, and one
// whose credentials are all as the baseline found them, keep the plan
// version they had before versions existed.
func TestSOCKSRotationStalesDeployVersion(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	l, err := s.liveDeploy()
	if err != nil {
		t.Fatal(err)
	}
	if l.version != topologyVersion(l.t) {
		t.Fatal("a topology without an external exit changed its plan version")
	}
	id := socksCreate(t, s, "路由器", "u-"+rnd(t, 4), "p-"+rnd(t, 8))
	newCarrierFix(t, s, id, id)
	upgradeSOCKSStore(t, s)
	l0, err := s.liveDeploy()
	if err != nil {
		t.Fatal(err)
	}
	if l0.version != topologyVersion(l0.t) {
		t.Fatal("un-rotated credentials of the baseline changed the plan version")
	}
	socksRotate(t, s, id, "u-"+rnd(t, 4), "p-"+rnd(t, 8))
	l1, _ := s.liveDeploy()
	socksRotate(t, s, id, "u-"+rnd(t, 4), "p-"+rnd(t, 8))
	l2, _ := s.liveDeploy()
	if l1.version == l0.version || l1.version == l2.version || topologyVersion(l0.t) != topologyVersion(l2.t) {
		t.Fatalf("plan version %s → %s → %s", l0.version, l1.version, l2.version)
	}
}

// upgradeSOCKSStore turns the panel's credential store into one written
// by a version that did not track SOCKS versions (no baseline in the
// index) and restarts the store: the reopening takes the baseline, as an
// upgrade does.
func upgradeSOCKSStore(t *testing.T, s *Server) {
	t.Helper()
	stripSOCKSBaseline(t, s)
	reopenCreds(t, s)
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	if tr := cs.SOCKSTracking(); !tr.Ready {
		t.Fatalf("the reopened store took no baseline: %+v", tr)
	}
}

// stripSOCKSBaseline removes the baseline from the index file.
func stripSOCKSBaseline(t *testing.T, s *Server) {
	t.Helper()
	p := filepath.Join(s.secretsDir(), "index.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var idx map[string]json.RawMessage
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	if _, ok := idx["socks_version_baseline"]; !ok {
		t.Fatal("the index has no baseline to strip")
	}
	delete(idx, "socks_version_baseline")
	out, _ := json.MarshalIndent(idx, "", "  ")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// reopenCreds forgets the open credential store: the next use opens it
// from disk and runs the migrations, like a restart of the panel.
func reopenCreds(t *testing.T, s *Server) {
	t.Helper()
	s.credMu.Lock()
	s.creds = nil
	s.credMu.Unlock()
}

// previousCompile is what the version before SOCKS versions compiled:
// everything compileWith does except the SOCKS step.
func previousCompile(t *testing.T, s *Server) *compile.Bundle {
	t.Helper()
	topo := mustTopo(t, s)
	b, err := compile.CompileWithDecisions(topo, s.unlockDecisions(topo))
	if err != nil {
		t.Fatal(err)
	}
	return s.stampDNSAccounts(s.resolveWSS(topo, b))
}

// firstDiff is a path whose content differs between a and b ("" when the
// two are identical).
func firstDiff(a, b map[string]string) string {
	for p, body := range a {
		if other, ok := b[p]; !ok || other != body {
			return p
		}
	}
	for p := range b {
		if _, ok := a[p]; !ok {
			return p
		}
	}
	return ""
}

// Upgrade: carriers deployed before versions were tracked. The upgrade by
// itself changes no compiled byte and makes no carrier pending; such a
// carrier says that its installed version was never recorded. Only the
// carriers of a credential rotated after the upgrade become pending, with
// the reason; a reinstall records the version and clears the note; later
// rotations show the installed and the current version; a restart keeps
// all of it (the baseline is not taken again).
func TestSOCKSVersionUpgrade(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	u1, p1, u2, p2 := "au-"+rnd(t, 6), "ap-"+rnd(t, 8), "bu-"+rnd(t, 6), "bp-"+rnd(t, 8)
	credA := socksCreate(t, s, "路由器 A", u1, p1) // myext behind dc2
	credB := socksCreate(t, s, "路由器 B", u2, p2) // my2 behind dc1
	f := newCarrierFix(t, s, credA, credB)

	// The credentials exist, the store has no baseline: the old version.
	// Restarting on this version takes the baseline with both in it.
	upgradeSOCKSStore(t, s)
	cs, _ := s.credStore()
	for id, v := range cs.SOCKSVersions([]string{credA, credB}) {
		if v.Tracked || v.Baseline != 1 || v.Version != 1 {
			t.Fatalf("%s after the upgrade: %+v", id, v)
		}
	}
	// Byte-identical to what the previous version compiled, every file.
	b, err := s.compileTopo(mustTopo(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if p := firstDiff(previousCompile(t, s).Files, b.Files); p != "" {
		t.Fatalf("the upgrade changed %s", p)
	}
	for p, body := range b.Files {
		if strings.Contains(body, socksVersionMarker) {
			t.Fatalf("%s carries a version line for an un-rotated credential of the baseline", p)
		}
	}

	// The carriers as the previous version left them: installed with these
	// very files, no version in the record.
	for _, node := range []string{"dc1", "dc2"} {
		if sc := f.install(t, node); strings.Contains(sc, socksVersionMarker) {
			t.Fatalf("%s: version line in an install of un-rotated baseline credentials", node)
		}
		s.updateOutcome(node, func(o *provisionOutcome) { o.SOCKSVersions, o.InstalledSOCKSVersions = nil, nil })
	}
	for node, cred := range map[string]string{"dc1": credB, "dc2": credA} {
		st := nodeState(t, s, node)
		if st.State != nodeInSync || st.Pending || st.Reason != "" {
			t.Fatalf("%s became pending by the upgrade alone: %+v", node, st)
		}
		if len(st.SOCKSUnrecorded) != 1 || st.SOCKSUnrecorded[0] != cred || st.SOCKSVersions != nil || st.InstalledSOCKSVersions != nil ||
			!strings.Contains(st.Note, "没有记录") || !strings.Contains(st.Note, "不能证明") || !strings.Contains(st.Note, cred) {
			t.Fatalf("%s does not say its version is unrecorded: %+v", node, st)
		}
		if _, ok := planStepOf(t, s, node); ok {
			t.Fatalf("%s is in the plan after the upgrade alone", node)
		}
	}
	before := bundlesOf(t, s)
	var list struct {
		Credentials []socksCredView `json:"credentials"`
	}
	decode(t, do(s, http.MethodGet, "/api/socks-credentials", nil), &list)
	for _, c := range list.Credentials {
		if c.Tracked || c.Version != 1 || len(c.Carriers) != 1 {
			t.Fatalf("credential view after the upgrade: %+v", c)
		}
	}

	// First rotation after the upgrade, credential A only.
	n1, np1 := "cu-"+rnd(t, 6), "cp-"+rnd(t, 8)
	rot := socksRotate(t, s, credA, n1, np1)
	if rot.Credential.Version != 2 || !rot.Credential.Tracked || strings.Join(rot.Pending, ",") != "dc2" {
		t.Fatalf("rotate answer %+v", rot)
	}
	after := bundlesOf(t, s)
	st := nodeState(t, s, "dc2")
	if st.State != nodeChanged || !st.Pending || !strings.Contains(st.Reason, "开始记录版本之后轮换过") || !strings.Contains(st.Reason, credA+" 现在是版本 2") ||
		st.SOCKSVersions[credA] != 2 || st.InstalledSOCKSVersions != nil {
		t.Fatalf("dc2 after the first rotation: %+v", st)
	}
	if step, ok := planStepOf(t, s, "dc2"); !ok || step.VerifyOnly {
		t.Fatalf("dc2 is not an install step: %v %+v", ok, step)
	}
	// dc1 names credential B only: nothing about it changed.
	for node := range before {
		if node != "dc2" && before[node] != after[node] {
			t.Fatalf("%s does not name the rotated credential but its bundle changed", node)
		}
	}
	if st := nodeState(t, s, "dc1"); st.State != nodeInSync || st.Pending || len(st.SOCKSUnrecorded) != 1 || st.Note == "" {
		t.Fatalf("dc1 after rotating the other credential: %+v", st)
	}

	// Reinstall dc2: the new pair, version 2 recorded, no note.
	sc := f.install(t, "dc2")
	if !strings.Contains(sc, `password: "`+np1+`"`) || strings.Contains(sc, p1) || !strings.Contains(sc, socksVersionMarker+credA+"=2 ") {
		t.Fatal("dc2's reinstall did not carry the rotated credential")
	}
	if st := nodeState(t, s, "dc2"); st.State != nodeInSync || st.Pending || st.InstalledSOCKSVersions[credA] != 2 || len(st.SOCKSUnrecorded) != 0 || st.Note != "" {
		t.Fatalf("dc2 after reinstall: %+v", st)
	}

	// Reinstalling dc1 without any rotation rewrites the same files and
	// records the version: the note goes, the bundle stays.
	pf := f.preflight(t, "dc1")
	told := false
	for _, ch := range pf.Evaluation.Changes {
		told = told || ch.Resource == compile.ExtProxyConfig && strings.Contains(ch.Detail, credB+" 版本 1") && strings.Contains(ch.Detail, "这次安装会记下")
	}
	if !told || pf.SOCKSVersions != nil || pf.Bundle != before["dc1"] {
		t.Fatalf("dc1's preflight: versions %v changes %+v", pf.SOCKSVersions, pf.Evaluation.Changes)
	}
	if rr := f.provision("dc1", pf.ID); rr.Code != 200 {
		t.Fatalf("dc1 reinstall: %d %s", rr.Code, rr.Body.String())
	}
	if st := nodeState(t, s, "dc1"); st.State != nodeInSync || st.CurrentBundle != before["dc1"] || st.InstalledSOCKSVersions[credB] != 1 || len(st.SOCKSUnrecorded) != 0 || st.Note != "" {
		t.Fatalf("dc1 after a reinstall without rotation: %+v", st)
	}

	// A later rotation: installed 2, now 3.
	socksRotate(t, s, credA, "du-"+rnd(t, 6), "dp-"+rnd(t, 8))
	if st := nodeState(t, s, "dc2"); st.State != nodeChanged || !strings.Contains(st.Reason, "已安装版本 2，现在是版本 3") {
		t.Fatalf("dc2 after the second rotation: %+v", st)
	}
	// First rotation of B, now that dc1 has a record: installed 1, now 2.
	socksRotate(t, s, credB, "eu-"+rnd(t, 6), "ep-"+rnd(t, 8))
	if st := nodeState(t, s, "dc1"); st.State != nodeChanged || !strings.Contains(st.Reason, "已安装版本 1，现在是版本 2") {
		t.Fatalf("dc1 after its first rotation: %+v", st)
	}

	// Restart: the baseline is not taken again, nothing flips back.
	states := map[string]nodeInstallState{"dc1": nodeState(t, s, "dc1"), "dc2": nodeState(t, s, "dc2")}
	reopenCreds(t, s)
	if errs := s.MigrateCredentials(); len(errs) != 0 {
		t.Fatalf("migration after restart: %v", errs)
	}
	cs, _ = s.credStore()
	vs := cs.SOCKSVersions([]string{credA, credB})
	if vs[credA] != (credentials.SOCKSVersion{Version: 3, Baseline: 1, Tracked: true}) || vs[credB] != (credentials.SOCKSVersion{Version: 2, Baseline: 1, Tracked: true}) {
		t.Fatalf("after restart: %+v", vs)
	}
	for node, was := range states {
		if st := nodeState(t, s, node); st.State != was.State || st.CurrentBundle != was.CurrentBundle || st.Reason != was.Reason {
			t.Fatalf("%s changed by a restart: %+v", node, st)
		}
	}
	assertNoSOCKSMaterial(t, s, &logs, u1, p1, u2, p2, n1, np1)
}

// A record from before versions existed still decodes, and a topology
// without an external exit compiles exactly as without the SOCKS step.
func TestSOCKSVersionNoExternalExit(t *testing.T) {
	var o provisionOutcome
	if err := json.Unmarshal([]byte(`{"node_id":"dc2","installed":true,"installed_bundle":"x"}`), &o); err != nil || o.InstalledSOCKSVersions != nil || o.SOCKSVersions != nil {
		t.Fatalf("%v %+v", err, o)
	}
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	// An unused credential, rotated: no file names it.
	id := socksCreate(t, s, "没人用", "u-"+rnd(t, 4), "p-"+rnd(t, 8))
	if rot := socksRotate(t, s, id, "u-"+rnd(t, 4), "p-"+rnd(t, 8)); len(rot.Pending) != 0 || !strings.Contains(rot.Note, "不需要重新安装") {
		t.Fatalf("rotating an unused credential: %+v", rot)
	}
	prev := previousCompile(t, s)
	if got := s.stampSOCKS(prev); got != prev {
		t.Fatal("a bundle without a redirector config was copied or changed")
	}
	b, err := s.compileTopo(mustTopo(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if p := firstDiff(prev.Files, b.Files); p != "" {
		t.Fatalf("%s differs without any external exit", p)
	}
	for _, st := range getStatusFull(t, s).Nodes {
		if st.SOCKSVersions != nil || st.InstalledSOCKSVersions != nil || st.SOCKSUnrecorded != nil || st.Note != "" {
			t.Fatalf("%+v", st)
		}
	}
}

// breakCredIndex makes every write of the credential index fail (the
// index path becomes a non-empty directory); the returned function puts
// the file back.
func breakCredIndex(t *testing.T, s *Server) func() {
	t.Helper()
	idx := filepath.Join(s.secretsDir(), "index.json")
	if err := os.Rename(idx, idx+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(idx, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.RemoveAll(idx); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(idx+".bak", idx); err != nil {
			t.Fatal(err)
		}
	}
}

// The baseline cannot be written at the upgrade: the failure is reported
// (migration errors, the credentials view), nothing is tracked and the
// carriers compile the old bytes and stay in sync. A restart with a
// working store takes the baseline (still nothing changes); the first
// rotation after it makes the carrier pending. Without a restart, the
// first rotation writes the baseline itself, in the same index write.
func TestSOCKSMigrationFailureAndRestart(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	tracking := func(s *Server) credentials.SOCKSTracking {
		t.Helper()
		var list struct {
			Tracking credentials.SOCKSTracking `json:"version_tracking"`
		}
		decode(t, do(s, http.MethodGet, "/api/socks-credentials", nil), &list)
		return list.Tracking
	}
	for _, restart := range []bool{true, false} {
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			s := newTest(t)
			do(s, http.MethodGet, "/api/topology", nil)
			u, p := "fu-"+rnd(t, 6), "fp-"+rnd(t, 8)
			id := socksCreate(t, s, "路由器", u, p)
			f := newCarrierFix(t, s, id, id)
			old := previousCompile(t, s).Files

			// The old version's store, opened by this version while the
			// index cannot be written.
			stripSOCKSBaseline(t, s)
			cs, err := credentials.Open(s.secretsDir())
			if err != nil {
				t.Fatal(err)
			}
			s.credMu.Lock()
			s.creds = cs
			s.credMu.Unlock()
			restore := breakCredIndex(t, s)
			errs := s.MigrateCredentials()
			found := false
			for _, e := range errs {
				found = found || strings.Contains(e.Error(), "SOCKS 凭据版本") && strings.Contains(e.Error(), "版本基线")
				noSecretIn(t, "migration error", e.Error(), u, p)
			}
			if !found {
				t.Fatalf("the failed migration was not reported: %v", errs)
			}
			if tr := tracking(s); tr.Ready || tr.Error == "" {
				t.Fatalf("tracking after a failed migration: %+v", tr)
			}
			b, err := s.compileTopo(mustTopo(t, s))
			if err != nil {
				t.Fatal(err)
			}
			if p := firstDiff(old, b.Files); p != "" {
				t.Fatalf("%s is not the old bytes while the migration is incomplete", p)
			}
			// A rotation cannot be stored either: refused, nothing tracked.
			rr := do(s, http.MethodPut, "/api/socks-credentials/"+id+"/secret", mustJSON(map[string]any{"username": "gu-" + rnd(t, 4), "password": "gp-" + rnd(t, 8)}))
			if rr.Code < 400 || !strings.Contains(rr.Body.String(), credentials.CodeStorage) {
				t.Fatalf("rotation on a broken store: %d %s", rr.Code, rr.Body.String())
			}
			if v := cs.SOCKSVersions([]string{id})[id]; v.Version != 1 || v.Tracked {
				t.Fatalf("after the refused rotation: %+v", v)
			}
			restore()

			// The carriers, installed with the old bytes.
			for _, node := range []string{"dc1", "dc2"} {
				if sc := f.install(t, node); strings.Contains(sc, socksVersionMarker) {
					t.Fatal("version line while the migration is incomplete")
				}
				s.updateOutcome(node, func(o *provisionOutcome) { o.SOCKSVersions, o.InstalledSOCKSVersions = nil, nil })
			}
			before := bundlesOf(t, s)

			if restart {
				reopenCreds(t, s)
				if errs := s.MigrateCredentials(); len(errs) != 0 {
					t.Fatalf("migration after the restart: %v", errs)
				}
				tr := tracking(s)
				if !tr.Ready || tr.Since == "" || tr.Error != "" {
					t.Fatalf("tracking after the restart: %+v", tr)
				}
				// Again: the record is kept, not taken anew.
				reopenCreds(t, s)
				if errs := s.MigrateCredentials(); len(errs) != 0 || tracking(s).Since != tr.Since {
					t.Fatalf("the baseline was taken again: %v %+v", errs, tracking(s))
				}
				for node, d := range bundlesOf(t, s) {
					if d != before[node] {
						t.Fatalf("%s changed when the baseline was written", node)
					}
				}
				for _, node := range []string{"dc1", "dc2"} {
					if st := nodeState(t, s, node); st.State != nodeInSync || st.Pending || len(st.SOCKSUnrecorded) != 1 {
						t.Fatalf("%s after the migration: %+v", node, st)
					}
				}
			} else if tr := tracking(s); tr.Ready {
				t.Fatalf("a baseline appeared without a migration: %+v", tr)
			}

			// The first rotation: tracked either way.
			nu, np := "hu-"+rnd(t, 6), "hp-"+rnd(t, 8)
			rot := socksRotate(t, s, id, nu, np)
			if rot.Credential.Version != 2 || !rot.Credential.Tracked || strings.Join(rot.Pending, ",") != "dc1,dc2" {
				t.Fatalf("rotate answer %+v", rot)
			}
			if tr := tracking(s); !tr.Ready || tr.Error != "" {
				t.Fatalf("tracking after the rotation: %+v", tr)
			}
			for _, node := range []string{"dc1", "dc2"} {
				if st := nodeState(t, s, node); st.State != nodeChanged || !st.Pending || !strings.Contains(st.Reason, "开始记录版本之后轮换过") {
					t.Fatalf("%s after the rotation: %+v", node, st)
				}
			}
			if sc := f.install(t, "dc2"); !strings.Contains(sc, `password: "`+np+`"`) || !strings.Contains(sc, socksVersionMarker+id+"=2 ") {
				t.Fatal("the reinstall did not carry the rotated credential")
			}
			if st := nodeState(t, s, "dc2"); st.State != nodeInSync || st.InstalledSOCKSVersions[id] != 2 {
				t.Fatalf("dc2 after reinstall: %+v", st)
			}
			if st := nodeState(t, s, "dc1"); st.State != nodeChanged {
				t.Fatalf("dc1 after dc2's reinstall: %+v", st)
			}
			assertNoSOCKSMaterial(t, s, &logs, u, p, nu, np)
		})
	}
}

// The install's snapshot: material and versions are read together and
// must be the versions the files were compiled with.
func TestSOCKSInstallSnapshot(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	legacy := socksCreate(t, s, "升级前就有", "lu-"+rnd(t, 4), "lp-"+rnd(t, 8)) // myext behind dc2
	newCarrierFix(t, s, legacy, legacy)
	upgradeSOCKSStore(t, s)
	fresh := socksCreate(t, s, "升级后新建", "nu-"+rnd(t, 4), "np-"+rnd(t, 8)) // my2 behind dc1
	topo := mustTopo(t, s)
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "my2" {
			topo.Nodes[i].External.CredentialID = fresh
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	cs, _ := s.credStore()
	filesOf := func(node string) map[string]string {
		t.Helper()
		b, err := s.compileTopo(mustTopo(t, s))
		if err != nil {
			t.Fatal(err)
		}
		return provision.FilesFor(b.Files, node)
	}
	for _, c := range []struct {
		node, cred string
		stamped    bool
	}{{"dc2", legacy, false}, {"dc1", fresh, true}} {
		ids := carrierSOCKSCredentials(mustTopo(t, s), c.node)
		if len(ids) != 1 || ids[0] != c.cred {
			t.Fatalf("%s names %v", c.node, ids)
		}
		files := filesOf(c.node)
		if got := socksVersionsOf(files)[c.cred] == 1; got != c.stamped {
			t.Fatalf("%s stamped: %v", c.node, got)
		}
		sec, applied, err := socksInstallSnapshot(cs, ids, files)
		if err != nil || len(sec) != 2 || applied[c.cred] != 1 {
			t.Fatalf("%s snapshot: %v %v", c.node, err, applied)
		}
		// Rotated after the files were compiled: refused, whether the
		// credential was tracked before or becomes so by this rotation.
		nu, np := "ru-"+rnd(t, 4), "rp-"+rnd(t, 8)
		socksRotate(t, s, c.cred, nu, np)
		if _, _, err := socksInstallSnapshot(cs, ids, files); !errors.Is(err, errSOCKSRotated) {
			t.Fatalf("%s: files from before a rotation accepted: %v", c.node, err)
		}
		// Files of the current version: the new pair and version 2.
		sec, applied, err = socksInstallSnapshot(cs, ids, filesOf(c.node))
		if err != nil || sec[c.cred+"-user"] != nu || sec[c.cred+"-pass"] != np || applied[c.cred] != 2 {
			t.Fatalf("%s snapshot after rotation: %v %v", c.node, err, applied)
		}
	}
	// A missing credential is not a rotation.
	if _, _, err := socksInstallSnapshot(cs, []string{"socks-000000000000"}, filesOf("dc2")); err == nil || errors.Is(err, errSOCKSRotated) {
		t.Fatalf("missing credential: %v", err)
	}
}

var scriptPassRe = regexp.MustCompile(`password: "([^"]+)"`)

// Rotations during installs. One that arrives while the script runs does
// not reach that install: it applies and records the pair it read, and the
// carrier is pending again right after. With rotations racing a series of
// installs, every install that succeeds recorded exactly the version of
// the pair its script carried, and one that lost the race was refused
// before any script ran.
func TestSOCKSInstallRacesRotation(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	pass := map[string]int{} // password → version
	var passMu sync.Mutex
	mk := func(v int) (string, string) {
		u, p := fmt.Sprintf("u%d-%s", v, rnd(t, 4)), fmt.Sprintf("p%d-%s", v, rnd(t, 8))
		passMu.Lock()
		pass[p] = v
		passMu.Unlock()
		return u, p
	}
	u, p := mk(1)
	id := socksCreate(t, s, "路由器", u, p)
	f := newCarrierFix(t, s, id, id)
	versionOf := func(script string) int {
		t.Helper()
		m := scriptPassRe.FindStringSubmatch(script)
		if m == nil {
			t.Fatal("no password in the script")
		}
		passMu.Lock()
		defer passMu.Unlock()
		return pass[m[1]]
	}
	f.install(t, "dc2")

	// Rotation while the script runs.
	pf := f.preflight(t, "dc2")
	u, p = mk(2)
	f.hosts["dc2"].mu.Lock()
	f.hosts["dc2"].during = func() {
		rr := do(s, http.MethodPut, "/api/socks-credentials/"+id+"/secret", mustJSON(map[string]any{"username": u, "password": p}))
		if rr.Code != 200 {
			t.Errorf("rotate during install: %d %s", rr.Code, rr.Body.String())
		}
	}
	f.hosts["dc2"].mu.Unlock()
	if rr := f.provision("dc2", pf.ID); rr.Code != 200 {
		t.Fatalf("install with a rotation during it: %d %s", rr.Code, rr.Body.String())
	}
	sc := f.hosts["dc2"].scripts()
	if v := versionOf(sc[len(sc)-1]); v != 1 || !strings.Contains(sc[len(sc)-1], socksVersionMarker+id+"=1 ") {
		t.Fatalf("the install used version %d of the pair", v)
	}
	st := nodeState(t, s, "dc2")
	if st.State != nodeChanged || !st.Pending || st.InstalledSOCKSVersions[id] != 1 || st.SOCKSVersions[id] != 2 || !strings.Contains(st.Reason, "已安装版本 1，现在是版本 2") {
		t.Fatalf("after an install overtaken by a rotation: %+v", st)
	}
	if v := versionOf(f.install(t, "dc2")); v != 2 {
		t.Fatalf("the next install used version %d", v)
	}
	if st := nodeState(t, s, "dc2"); st.State != nodeInSync || st.InstalledSOCKSVersions[id] != 2 {
		t.Fatalf("after the next install: %+v", st)
	}

	// Rotation while the install re-runs the preflight, after the reviewed
	// one was accepted: the files compiled for the install are no longer
	// the reviewed ones. Refused, no script.
	rotate := func(v int) {
		u, p := mk(v)
		rr := do(s, http.MethodPut, "/api/socks-credentials/"+id+"/secret", mustJSON(map[string]any{"username": u, "password": p}))
		if rr.Code != 200 {
			t.Errorf("rotate to version %d: %d %s", v, rr.Code, rr.Body.String())
		}
	}
	pf = f.preflight(t, "dc2")
	f.hosts["dc2"].mu.Lock()
	f.hosts["dc2"].onPreflight = func() { rotate(3) }
	f.hosts["dc2"].mu.Unlock()
	n := len(f.hosts["dc2"].scripts())
	if rr := f.provision("dc2", pf.ID); rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), codeBundleChanged) || len(f.hosts["dc2"].scripts()) != n {
		t.Fatalf("rotation during the install's own preflight: %d %s", rr.Code, rr.Body.String())
	}
	if st := nodeState(t, s, "dc2"); st.State != nodeChanged || st.InstalledSOCKSVersions[id] != 2 || st.SOCKSVersions[id] != 3 {
		t.Fatalf("after the refused install: %+v", st)
	}

	// Rotations racing installs, unsynchronised.
	const last = 24
	done := make(chan struct{})
	go func() {
		defer close(done)
		for v := 4; v <= last; v++ {
			rotate(v)
			// Irregular gaps, around the length of an install's steps.
			time.Sleep(time.Duration(5+(v%5)*40) * time.Millisecond)
		}
	}()
	installs, refused := 0, 0
	for i := 0; ; i++ {
		finished := false
		select {
		case <-done:
			finished = true
		default:
		}
		n := len(f.hosts["dc2"].scripts())
		rr := do(s, http.MethodPost, "/api/provision/preflight", mustJSON(map[string]any{"node_id": "dc2"}))
		var out struct{ Preflight preflightRecord }
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("preflight: %d %s", rr.Code, rr.Body.String())
		}
		rr = f.provision("dc2", out.Preflight.ID)
		sc := f.hosts["dc2"].scripts()
		switch rr.Code {
		case 200:
			installs++
			if len(sc) != n+1 {
				t.Fatalf("an install ran %d scripts", len(sc)-n)
			}
			script := sc[len(sc)-1]
			v := versionOf(script)
			if v == 0 || !strings.Contains(script, fmt.Sprintf("%s%s=%d ", socksVersionMarker, id, v)) {
				t.Fatalf("the script carries the pair of version %d under another version line", v)
			}
			if out.Preflight.SOCKSVersions[id] != v {
				t.Fatalf("installed version %d with a preflight reviewed for %d", v, out.Preflight.SOCKSVersions[id])
			}
			var rec provisionOutcome
			s.updateOutcome("dc2", func(o *provisionOutcome) { rec = *o })
			if rec.InstalledSOCKSVersions[id] != v || rec.InstalledBundle != out.Preflight.Bundle {
				t.Fatalf("recorded %v for an install of version %d", rec.InstalledSOCKSVersions, v)
			}
		case http.StatusConflict:
			refused++
			if !strings.Contains(rr.Body.String(), codeBundleChanged) || len(sc) != n {
				t.Fatalf("refused install: %s (scripts %d → %d)", rr.Body.String(), n, len(sc))
			}
		default:
			t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
		}
		if finished && rr.Code == 200 {
			break
		}
		if i > 500 {
			t.Fatal("the installs never caught up with the rotations")
		}
	}
	<-done
	t.Logf("%d installs, %d refused before any script ran", installs, refused)
	if st := nodeState(t, s, "dc2"); st.State != nodeInSync || st.InstalledSOCKSVersions[id] != last || st.SOCKSVersions[id] != last {
		t.Fatalf("after the race (%d installs): %+v", installs, st)
	}
	// The other carrier was never installed with any of it.
	if st := nodeState(t, s, "dc1"); st.State != nodeNotInstalled || st.InstalledSOCKSVersions != nil {
		t.Fatalf("dc1: %+v", st)
	}
}

// The rotate endpoint: panel token required, a malformed value refused
// without being echoed, an unknown credential 404; none changes a version.
func TestSOCKSRotateValidation(t *testing.T) {
	s := newTest(t)
	do(s, http.MethodGet, "/api/topology", nil)
	id := socksCreate(t, s, "路由器", "u-"+rnd(t, 4), "p-"+rnd(t, 8))
	body := func() []byte {
		return mustJSON(map[string]any{"username": "u-" + rnd(t, 4), "password": "p-" + rnd(t, 8)})
	}
	s.Token = "tok-" + rnd(t, 4)
	if rr := do(s, http.MethodPut, "/api/socks-credentials/"+id+"/secret", body()); rr.Code != http.StatusUnauthorized {
		t.Fatalf("without token: %d", rr.Code)
	}
	s.Token = ""
	bad := "bad pass@" + rnd(t, 3)
	if rr := do(s, http.MethodPut, "/api/socks-credentials/"+id+"/secret", mustJSON(map[string]any{"username": "u", "password": bad})); rr.Code < 400 || rr.Code >= 500 || strings.Contains(rr.Body.String(), bad) {
		t.Fatalf("bad value: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/socks-credentials/socks-000000000000/secret", body()); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d %s", rr.Code, rr.Body.String())
	}
	cs, _ := s.credStore()
	if v := cs.SOCKSVersions([]string{id})[id]; v.Version != 1 {
		t.Fatalf("refused rotations changed the version: %+v", v)
	}
	// Renaming is not a rotation.
	if rr := do(s, http.MethodPatch, "/api/socks-credentials/"+id, mustJSON(map[string]any{"name": "改名"})); rr.Code != 200 {
		t.Fatalf("rename: %d %s", rr.Code, rr.Body.String())
	}
	if v := cs.SOCKSVersions([]string{id})[id]; v.Version != 1 {
		t.Fatalf("a rename changed the version: %+v", v)
	}
}

// The reasons, as pure functions.
func TestSOCKSChangeReason(t *testing.T) {
	a, b := "socks-0123456789ab", "socks-ba9876543210"
	base := map[string]credentials.SOCKSVersion{a: {Version: 4, Baseline: 3, Tracked: true}, b: {Version: 1, Tracked: true}}
	if r := socksChangeReason(nil, nil, base); r != "" {
		t.Fatalf("no versions: %q", r)
	}
	if r := socksChangeReason(map[string]int{a: 4}, map[string]int{a: 4}, base); r != "" {
		t.Fatalf("same versions: %q", r)
	}
	if r := socksChangeReason(map[string]int{a: 4}, map[string]int{a: 3}, base); !strings.Contains(r, "已轮换") || !strings.Contains(r, a+" 已安装版本 3，现在是版本 4") {
		t.Fatalf("rotated: %q", r)
	}
	if r := socksChangeReason(map[string]int{a: 4}, nil, base); !strings.Contains(r, "开始记录版本之后轮换过") || !strings.Contains(r, "还没有记录凭据版本") {
		t.Fatalf("legacy: %q", r)
	}
	// A credential created after the baseline that this carrier was never
	// installed with: the files differ for another reason.
	if r := socksChangeReason(map[string]int{b: 1}, nil, base); r != "" {
		t.Fatalf("new credential: %q", r)
	}
	if n := socksUnrecordedNote(nil); n != "" {
		t.Fatalf("%q", n)
	}
	st := socksStateOf(map[string]string{compile.ExtProxyConfig: "# h\nservices:\n  u: \"__MERIDIAN_SECRET_" + a + "-user__\"\n  p: \"__MERIDIAN_SECRET_" + b + "-pass__\"\n"}, map[string]int{a: 3}, true)
	if st.Planned != nil || st.Installed[a] != 3 || len(st.Unrecorded) != 1 || st.Unrecorded[0] != b {
		t.Fatalf("%+v", st)
	}
	if preflight.BundleDigest(map[string]string{"/x": "1"}) == "" {
		t.Fatal("digest")
	}
}

// The demo fixtures carry the SOCKS credential's id, placeholders and
// version, never the demo's synthetic username or password.
func TestDemoFixturesNoSOCKSMaterial(t *testing.T) {
	entries, err := os.ReadDir(demoFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	versions := false
	for _, e := range entries {
		b, err := os.ReadFile(demoFixtureDir + "/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), demoSOCKSUser) || strings.Contains(string(b), demoSOCKSPass) {
			t.Fatalf("the demo SOCKS material is in %s", e.Name())
		}
		versions = versions || strings.Contains(string(b), `"socks_versions"`)
	}
	if !versions {
		t.Fatal("no fixture shows a carrier's SOCKS credential version")
	}
}
