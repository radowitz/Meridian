package mesh_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// ---------------------------------------------------------------- fixtures

func dummy(prefix string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// meshTopo is the example topology with one route per Mesh link.
func meshTopo(t *testing.T) model.Topology {
	t.Helper()
	topo := defaults.Example()
	n := 0
	for i := range topo.Links {
		if topo.Links[i].Transport == model.TransportCFMesh {
			topo.Links[i].MeshRoutes = []string{fmt.Sprintf("198.51.%d.0/24", 100+n), fmt.Sprintf("2001:db8:%x::/48", 0x6600+n)}
			n++
		}
	}
	if n == 0 {
		t.Fatal("example has no mesh link")
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].SSHHost == "" {
			topo.Nodes[i].SSHHost = topo.Nodes[i].ID + ".example.invalid"
		}
	}
	return topo
}

func meshPlan(t *testing.T) mesh.Plan {
	t.Helper()
	topo := meshTopo(t)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	p := mesh.BuildPlan(topo, b.Files)
	if !p.OK() {
		t.Fatalf("plan issues: %+v", p.Issues)
	}
	return p
}

// fakeCF is an httptest Cloudflare built from the documented shapes.
type fakeCF struct {
	mu      sync.Mutex
	account string
	token   string
	nodes   map[string]mesh.CFNode
	routes  map[string]mesh.CFRoute
	tokens  map[string]string
	log     []string
	// fault switches
	failCreateNode  int // fail the nth create (1-based), 0 = never
	createdNodes    int
	failCreateRoute int
	createdRoutes   int
	routeCreateLost bool // create succeeds but the response is an error
	failDeleteRoute int  // fail this many deletes
	failToken       int  // fail this many token reads
	status          string
	// blockDelete, when set, holds the next route DELETE (with the fake
	// unlocked) until it is closed; enteredDelete is closed when it starts.
	blockDelete   chan struct{}
	enteredDelete chan struct{}
}

func newFakeCF(t *testing.T) (*fakeCF, *httptest.Server) {
	f := &fakeCF{account: dummy("", 16), token: dummy("tok", 16), nodes: map[string]mesh.CFNode{}, routes: map[string]mesh.CFRoute{}, tokens: map[string]string{}, status: "healthy"}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCF) client(srv *httptest.Server) *mesh.CFClient {
	return &mesh.CFClient{Base: srv.URL, AccountID: f.account, Token: f.token, HTTP: srv.Client()}
}

func writeEnv(w http.ResponseWriter, code int, result any, errs ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	var e []map[string]any
	for _, m := range errs {
		e = append(e, map[string]any{"code": 1000, "message": m})
	}
	if e == nil {
		e = []map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": code/100 == 2, "errors": e, "messages": []any{}, "result": result})
}

func (f *fakeCF) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		writeEnv(w, 403, nil, "Authentication error")
		return
	}
	prefix := "/accounts/" + f.account
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeEnv(w, 404, nil, "no account")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, prefix)
	f.log = append(f.log, r.Method+" "+p)
	var body map[string]any
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/warp_connector" && r.Method == http.MethodPost:
		f.createdNodes++
		if f.failCreateNode == f.createdNodes {
			writeEnv(w, 500, nil, "internal error")
			return
		}
		name, _ := body["name"].(string)
		n := mesh.CFNode{ID: uuid(), Name: name, Status: "inactive"}
		f.nodes[n.ID] = n
		f.tokens[n.ID] = dummy("eyJ", 24)
		writeEnv(w, 200, n)
	case p == "/warp_connector" && r.Method == http.MethodGet:
		var out []mesh.CFNode
		for _, n := range f.nodes {
			out = append(out, n)
		}
		writeEnv(w, 200, out)
	case len(parts) == 3 && parts[0] == "warp_connector" && parts[2] == "token" && r.Method == http.MethodGet:
		if f.failToken > 0 {
			f.failToken--
			writeEnv(w, 500, nil, "token unavailable")
			return
		}
		tok, ok := f.tokens[parts[1]]
		if !ok {
			writeEnv(w, 404, nil, "not found")
			return
		}
		writeEnv(w, 200, tok)
	case len(parts) == 2 && parts[0] == "warp_connector":
		n, ok := f.nodes[parts[1]]
		if !ok {
			writeEnv(w, 404, nil, "Tunnel not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			if n.Status == "inactive" {
				n.Status = f.status
			}
			writeEnv(w, 200, n)
		case http.MethodDelete:
			for _, rt := range f.routes {
				if rt.TunnelID == n.ID {
					writeEnv(w, 400, nil, "tunnel has routes")
					return
				}
			}
			delete(f.nodes, n.ID)
			writeEnv(w, 200, n)
		default:
			writeEnv(w, 405, nil, "method")
		}
	case p == "/teamnet/routes" && r.Method == http.MethodPost:
		f.createdRoutes++
		if f.failCreateRoute == f.createdRoutes {
			writeEnv(w, 500, nil, "route create failed")
			return
		}
		network, _ := body["network"].(string)
		tunnel, _ := body["tunnel_id"].(string)
		comment, _ := body["comment"].(string)
		for _, rt := range f.routes {
			if rt.Network == network {
				writeEnv(w, 409, nil, "route already exists")
				return
			}
		}
		rt := mesh.CFRoute{ID: uuid(), Network: network, TunnelID: tunnel, Comment: comment}
		f.routes[rt.ID] = rt
		if f.routeCreateLost {
			f.routeCreateLost = false
			writeEnv(w, 502, nil, "gateway timeout")
			return
		}
		writeEnv(w, 200, rt)
	case p == "/teamnet/routes" && r.Method == http.MethodGet:
		tid := r.URL.Query().Get("tunnel_id")
		var out []mesh.CFRoute
		for _, rt := range f.routes {
			if tid == "" || rt.TunnelID == tid {
				out = append(out, rt)
			}
		}
		writeEnv(w, 200, out)
	case len(parts) == 3 && parts[0] == "teamnet" && parts[1] == "routes" && r.Method == http.MethodDelete:
		if f.failDeleteRoute > 0 {
			f.failDeleteRoute--
			writeEnv(w, 500, nil, "try again")
			return
		}
		if ch := f.blockDelete; ch != nil {
			f.blockDelete = nil
			close(f.enteredDelete)
			f.mu.Unlock()
			<-ch
			f.mu.Lock()
		}
		rt, ok := f.routes[parts[2]]
		if !ok {
			writeEnv(w, 404, nil, "route not found")
			return
		}
		delete(f.routes, rt.ID)
		writeEnv(w, 200, rt)
	default:
		writeEnv(w, 404, nil, "unknown endpoint "+p)
	}
}

func (f *fakeCF) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range f.log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// fakeRemote records every fixed action and answers like the real scripts.
// Each node presents host key "SHA256:fake-<id>" unless hostKeys says
// otherwise; like the SSH remote, it refuses (runs nothing) when the
// target pins a different key.
type fakeRemote struct {
	mu       sync.Mutex
	calls    []string
	scripts  []string
	targets  []mesh.NodeTarget // target of each executed call
	refused  []string          // "action/node" refused for a host key mismatch
	fail     map[string]bool   // "action/node"
	failOnce map[string]bool
	hostKeys map[string]string // node id -> presented fingerprint
	absent   map[string]bool   // node id -> restore finds no backup dir
	// after, when set, runs (locked) after each executed call.
	after func(r *fakeRemote, key string)
}

func (r *fakeRemote) key(id string) string {
	if k, ok := r.hostKeys[id]; ok {
		return k
	}
	return "SHA256:fake-" + id
}

func (r *fakeRemote) Exec(_ context.Context, n mesh.NodeTarget, act mesh.Action, script string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(act) + "/" + n.ID
	seen := r.key(n.ID)
	if n.HostKey != "" && n.HostKey != seen {
		r.refused = append(r.refused, key)
		return "", "", fmt.Errorf("host key %s is not the pinned %s", seen, n.HostKey)
	}
	out, err := r.answer(key, n, act, script)
	if r.after != nil {
		r.after(r, key)
	}
	return out, seen, err
}

func (r *fakeRemote) answer(key string, n mesh.NodeTarget, act mesh.Action, script string) (string, error) {
	r.calls = append(r.calls, key)
	r.scripts = append(r.scripts, script)
	r.targets = append(r.targets, n)
	if r.failOnce[key] {
		delete(r.failOnce, key)
		return "boom", errors.New("remote failed")
	}
	if r.fail[key] {
		if act == mesh.ActPreflight {
			return "MESH_CONFLICT addr_v4 an address in 169.254.66.0/30 is already configured\nMESH_PREFLIGHT_DONE conflicts=1\n", errors.New("exit 1")
		}
		if act == mesh.ActHealth {
			return "MESH_CHECK nexthop_v6 FAIL fe80::66:2%mmesh does not answer\nMESH_HEALTH_FAIL 1\n", errors.New("exit 1")
		}
		return "failed", errors.New("exit 1")
	}
	switch act {
	case mesh.ActPreflight:
		return "MESH_PREFLIGHT_DONE conflicts=0\nMESH_PREFLIGHT_OK\n", nil
	case mesh.ActInstall:
		return "MESH_INSTALL_OK\n", nil
	case mesh.ActHealth:
		return "MESH_CHECK nexthop_v4 PASS ok\nMESH_CHECK nexthop_v6 PASS ok\nMESH_HEALTH_OK\n", nil
	case mesh.ActRefresh:
		return "MESH_TABLE 198.51.100.0/24 dev CloudflareWARP\nMESH_REFRESH_OK\n", nil
	case mesh.ActRestore:
		if r.absent[n.ID] {
			return "MESH_RESTORE_ABSENT nothing from this run is on the host\n", nil
		}
		return "MESH_RESTORE_OK\n", nil
	}
	return "", fmt.Errorf("unknown action %s", act)
}

func (r *fakeRemote) has(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == key {
			return true
		}
	}
	return false
}

func (r *fakeRemote) count(act mesh.Action) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, string(act)+"/") {
			n++
		}
	}
	return n
}

// newDeployer stores the fake's credentials and lets the deployer load them
// (under its lock) like the panel does; Connect points the client at the
// fake with whatever account and token are stored.
func newDeployer(t *testing.T, f *fakeCF, srv *httptest.Server, rem *fakeRemote) *mesh.Deployer {
	dir := filepath.Join(t.TempDir(), "mesh")
	store := &mesh.CredStore{Dir: dir}
	if err := store.Save(mesh.Credentials{AccountID: f.account, APIToken: f.token}); err != nil {
		t.Fatal(err)
	}
	connect := func(c mesh.Credentials) (mesh.Cloudflare, error) {
		return &mesh.CFClient{Base: srv.URL, AccountID: c.AccountID, Token: c.APIToken, HTTP: srv.Client()}, nil
	}
	return &mesh.Deployer{Dir: dir, Creds: store, Connect: connect, Remote: rem, Redact: &mesh.Redactor{}, HealthWait: 50 * time.Millisecond, HealthPoll: 5 * time.Millisecond}
}

// ---------------------------------------------------------------- addressing

func TestDefaultAddressingIsAValidDualStackNextHop(t *testing.T) {
	a := mesh.DefaultAddressing()
	if iss := a.Validate(); len(iss) != 0 {
		t.Fatalf("default addressing invalid: %+v", iss)
	}
	if a.NextHopV4() != "169.254.66.2" || a.NextHopV6() != "fe80::66:2" {
		t.Fatalf("next-hops %s %s", a.NextHopV4(), a.NextHopV6())
	}
	if a.HostV4CIDR() != "169.254.66.1/30" || a.SidecarV6CIDR() != "fe80::66:2/64" {
		t.Fatal("cidrs")
	}
	bad := a
	bad.SidecarV4 = bad.HostV4
	if len(bad.Validate()) == 0 {
		t.Error("same v4 on both ends accepted")
	}
	bad = a
	bad.SidecarV4 = a.LinkV4.Addr() // network address
	if len(bad.Validate()) == 0 {
		t.Error("network address accepted as next-hop")
	}
	bad = a
	bad.SidecarV6 = mustAddr("2001:db8::2")
	if len(bad.Validate()) == 0 {
		t.Error("global v6 accepted as link-local next-hop")
	}
	bad = a
	bad.HostMAC = "01:00:5e:00:00:01"
	if len(bad.Validate()) == 0 {
		t.Error("multicast MAC accepted")
	}
}

func TestPlanDetectsConflicts(t *testing.T) {
	topo := meshTopo(t)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*model.Topology){
		"mesh_route_conflict": func(t *model.Topology) { setRoutes(t, 0, "10.66.5.0/24") },
		"mesh_route_default":  func(t *model.Topology) { setRoutes(t, 0, "0.0.0.0/0") },
		"mesh_route_invalid":  func(t *model.Topology) { setRoutes(t, 0, "198.51.100.1/24") },
		"mesh_route_overlap":  func(t *model.Topology) { setRoutes(t, 0, "198.51.200.0/24"); setRoutes(t, 1, "198.51.200.128/25") },
		"mesh_routes_empty":   func(t *model.Topology) { setRoutes(t, 0) },
		"mesh_link_conflict": func(t *model.Topology) {
			for i := range t.Links {
				if t.Links[i].Transport == model.TransportDirectWG {
					t.Links[i].FromV4 = "169.254.66.1"
					return
				}
			}
		},
	}
	for code, mut := range cases {
		tp := meshTopo(t)
		mut(&tp)
		p := mesh.BuildPlan(tp, b.Files)
		found := false
		for _, is := range p.Issues {
			if is.Code == code {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: not detected, issues %+v", code, p.Issues)
		}
	}
	// Mesh IP range is reserved.
	tp := meshTopo(t)
	setRoutes(&tp, 0, "100.100.0.0/16")
	if mesh.BuildPlan(tp, b.Files).OK() {
		t.Error("route inside 100.96.0.0/12 accepted")
	}
}

func setRoutes(t *model.Topology, idx int, routes ...string) {
	n := 0
	for i := range t.Links {
		if t.Links[i].Transport != model.TransportCFMesh {
			continue
		}
		if n == idx {
			t.Links[i].MeshRoutes = routes
			return
		}
		n++
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
