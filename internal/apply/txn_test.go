package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

// simHost is a hostexec.Runner standing in for a Debian host. "systemctl
// restart meridian.service" behaves like running the installed
// meridian-up.sh: it brings up exactly the interfaces the script lists and
// loads the tables of the installed meridian.nft. Nothing is executed.
type simHost struct {
	mu      sync.Mutex
	root    string
	links   map[string]bool
	nft     map[string]bool
	units   map[string]bool // active
	enabled map[string]bool
	cmds    []string
	fail    map[string]bool
}

var upIfaces = regexp.MustCompile(`(?m)^for iface in ([^;]*); do$`)

func newSimHost(root string) *simHost {
	return &simHost{root: root, links: map[string]bool{}, nft: map[string]bool{}, units: map[string]bool{}, enabled: map[string]bool{}, fail: map[string]bool{}}
}

func (h *simHost) Run(ctx context.Context, prog string, args ...string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	line := prog + " " + strings.Join(args, " ")
	h.cmds = append(h.cmds, line)
	for p := range h.fail {
		if strings.HasPrefix(line, p) {
			return "sim failure", errors.New("exit status 1")
		}
	}
	unitFile := func(u string) bool {
		if u == "meridian.service" {
			return true
		}
		_, err := os.Stat(filepath.Join(h.root, "etc", "systemd", "system", u))
		return err == nil
	}
	switch {
	case prog == "systemctl" && args[0] == "cat":
		if unitFile(args[1]) {
			return "[Unit]", nil
		}
		return "", errors.New("not found")
	case prog == "systemctl" && args[0] == "restart" && args[1] == "meridian.service":
		up, err := os.ReadFile(filepath.Join(h.root, "usr", "local", "sbin", "meridian-up.sh"))
		if err != nil {
			return "", errors.New("ConditionFileIsExecutable failed")
		}
		if m := upIfaces.FindStringSubmatch(string(up)); m != nil {
			for _, i := range strings.Fields(m[1]) {
				if _, err := os.Stat(filepath.Join(h.root, "etc", "wireguard", i+".conf")); err != nil {
					return "meridian-wg-missing", errors.New("exit status 1")
				}
				h.links[i] = true
			}
		}
		nft, _ := os.ReadFile(filepath.Join(h.root, "etc", "nftables.d", "meridian.nft"))
		for _, m := range nftTableLine.FindAllStringSubmatch(string(nft), -1) {
			h.nft[m[1]+" "+m[2]] = true
		}
		h.units["meridian.service"] = true
	case prog == "systemctl" && args[0] == "restart":
		if !unitFile(args[1]) {
			return "", errors.New("unit not found")
		}
		h.units[args[1]] = true
	case prog == "systemctl" && args[0] == "enable":
		h.enabled[args[1]] = true
	case prog == "systemctl" && args[0] == "is-enabled":
		if !h.enabled[args[len(args)-1]] {
			return "disabled", errors.New("exit status 1")
		}
	case prog == "systemctl" && args[0] == "is-active" && args[1] == "--quiet":
		if !h.units[args[2]] {
			return "", errors.New("exit status 3")
		}
	case prog == "systemctl" && args[0] == "is-active":
		if h.units[args[1]] {
			return "active", nil
		}
		return "inactive", errors.New("exit status 3")
	case prog == "systemctl" && args[0] == "disable":
		delete(h.units, args[len(args)-1])
		delete(h.enabled, args[len(args)-1])
	case prog == "ip" && len(args) > 2 && args[0] == "link" && args[1] == "show":
		if !h.links[args[3]] {
			return "", errors.New("does not exist")
		}
	case prog == "ip" && len(args) > 2 && args[0] == "link" && args[1] == "del":
		delete(h.links, args[3])
	case prog == "ip" && len(args) > 1 && args[1] == "rule":
		return "", errors.New("no such rule")
	case prog == "nft" && args[0] == "list":
		if !h.nft[args[2]+" "+args[3]] {
			return "", errors.New("no such table")
		}
	case prog == "nft" && args[0] == "delete":
		delete(h.nft, args[2]+" "+args[3])
	case prog == "docker":
		return "", errors.New("no such container")
	}
	return "", nil
}

func (h *simHost) liveLinks() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for l := range h.links {
		out = append(out, l)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// agentRT drives a real hostexec.Agent in-process, the way hostexec.Client
// does over the socket, with failure injection by request tag.
type agentRT struct {
	agent *hostexec.Agent
	mu    sync.Mutex
	reqs  []hostexec.Request
	fail  map[string]error // tag suffix -> error returned instead of executing
	crash string           // tag suffix at which the calling goroutine dies
}

func newAgentRT(h *simHost, ledger string) *agentRT {
	return &agentRT{agent: &hostexec.Agent{Token: func() (string, error) { return "x", nil }, Runner: h, LedgerPath: ledger}, fail: map[string]error{}}
}

func tagOf(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

func (r *agentRT) Do(ctx context.Context, req hostexec.Request) (hostexec.Result, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	err := r.fail[tagOf(req.RequestID)]
	crash := r.crash != "" && tagOf(req.RequestID) == r.crash
	r.mu.Unlock()
	if crash {
		runtime.Goexit() // the panel process "dies" mid-transaction
	}
	if err != nil {
		return hostexec.Result{RequestID: req.RequestID, Action: req.Action}, err
	}
	res, code := r.agent.Execute(ctx, req)
	if code != 200 {
		return res, errors.New("agent refused: " + res.Error)
	}
	if !res.OK {
		return res, errors.New(res.Error)
	}
	return res, nil
}

func (r *agentRT) requests(tag string) []hostexec.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []hostexec.Request
	for _, q := range r.reqs {
		if tagOf(q.RequestID) == tag {
			out = append(out, q)
		}
	}
	return out
}

type rig struct {
	data, host string
	sim        *simHost
	rt         *agentRT
	key        string
	ledger     string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{data: t.TempDir(), host: t.TempDir(), key: testKey(t)}
	r.ledger = filepath.Join(t.TempDir(), "ledger.json")
	r.sim = newSimHost(r.host)
	r.rt = newAgentRT(r.sim, r.ledger)
	return r
}

func (r *rig) applier() Applier {
	return Applier{DataDir: r.data, Install: true, LocalID: "gw", PrivateKey: r.key, HostRoot: r.host, Host: r.rt}
}

// restart models a new panel process: same disks, same host, new agent
// connection (the agent keeps its persisted ledger).
func (r *rig) restart() {
	r.rt = newAgentRT(r.sim, r.ledger)
}

func compileTopo(t *testing.T, topo model.Topology) *compile.Bundle {
	t.Helper()
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withoutHubWSS drops the gateway's IX-replacement WSS link: one fewer
// WireGuard interface (m03) and one fewer unit on the gateway.
func withoutHubWSS() model.Topology {
	topo := defaults.Example()
	for i, l := range topo.Links {
		if l.ID == "gw-hub-wss" {
			topo.Links = append(topo.Links[:i:i], topo.Links[i+1:]...)
			break
		}
	}
	return topo
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readHost(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestManifestOwnsGatewayResources(t *testing.T) {
	b := compileTopo(t, defaults.Example())
	m, err := DeriveManifest("gw", nodeFiles(b.Files, "gw"), 3, b.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Interfaces, ",") != "m02,m02w,m03" ||
		strings.Join(m.NFTTables, ",") != "inet meridian,inet meridian_guard" ||
		len(m.RouteTables) != 3 || !m.DNS || len(m.Sidecars) != 0 ||
		!contains(m.Units, "meridian-failover.service") || !contains(m.Units, "wstunnel-client-gw-hub-wss.service") {
		t.Fatalf("%+v", m)
	}
	if m.Version != 3 || m.Owner != "meridian" || m.Canonical == "" {
		t.Fatalf("%+v", m)
	}
	for _, f := range m.Files {
		if strings.Contains(f.Path, "..") || !allowed(f.Path) {
			t.Fatalf("bad managed path %s", f.Path)
		}
	}
	// Hub: Mesh sidecar is recorded; timer-driven services are not started directly.
	hub, err := DeriveManifest("hk-hub", nodeFiles(b.Files, "hk-hub"), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(hub.Sidecars) != 1 {
		t.Fatalf("hub sidecar not owned: %+v", hub.Sidecars)
	}
	if _, err := DeriveManifest("gw", map[string]string{"etc/wireguard/eth0.conf": "x"}, 1, ""); err == nil {
		t.Fatal("a non-Meridian interface name must be refused")
	}
	if _, err := DeriveManifest("gw", map[string]string{"etc/systemd/system/ssh.service": "x"}, 1, ""); err == nil {
		t.Fatal("a non-Meridian unit must be refused")
	}
}

func TestNoHostExecFailsBeforeAnything(t *testing.T) {
	b := compileTopo(t, defaults.Example())
	data := t.TempDir()
	// Real root, no host boundary: refused up front (nothing can be written
	// to / by this test because the check runs first).
	ap := Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: testKey(t)}
	if _, err := ap.Apply(b, false); !errors.Is(err, ErrNoHostExec) {
		t.Fatalf("got %v", err)
	}
	// A boundary that is configured but unreachable: same, before any write.
	host := t.TempDir()
	unreachable := &hostexec.Client{Socket: filepath.Join(t.TempDir(), "none.sock"), TokenFile: filepath.Join(t.TempDir(), "t")}
	ap = Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: testKey(t), HostRoot: host, Host: unreachable}
	if _, err := ap.Apply(b, false); !errors.Is(err, ErrNoHostExec) {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Fatal("host written without host exec")
	}
	if exists(filepath.Join(data, "applied")) {
		t.Fatal("snapshot rotated without host exec")
	}
}

func TestInstallActivatesManifestAndCommits(t *testing.T) {
	r := newRig(t)
	b := compileTopo(t, defaults.Example())
	res, err := r.applier().Apply(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Host == nil || !res.Host.Committed || res.Host.FromVersion != 0 || res.Host.ToVersion != 1 {
		t.Fatalf("%+v", res.Host)
	}
	if strings.Join(res.Host.Diff.InterfacesAdded, ",") != "m02,m02w,m03" {
		t.Fatalf("diff %+v", res.Host.Diff)
	}
	act := r.rt.requests("fwd-activate")
	if len(act) != 1 || strings.Join(act[0].Resources.Interfaces, ",") != "m02,m02w,m03" || !act[0].Resources.DNS {
		t.Fatalf("activate %+v", act)
	}
	if strings.Join(r.sim.liveLinks(), ",") != "m02,m02w,m03" {
		t.Fatalf("live %v", r.sim.liveLinks())
	}
	inst, _ := r.applier().Installed()
	if inst.Version != 1 || len(inst.Files) == 0 {
		t.Fatalf("installed %+v", inst)
	}
	if p, _ := r.applier().Pending(); p != nil {
		t.Fatalf("journal left behind: %+v", p)
	}
	assertNoSecret(t, r.data, r.key)
}

// First activation fails health: the host goes back to "nothing installed"
// (files deleted, created links removed, guard removal turns forwarding off
// first), the data dir has no snapshot, and the error says so.
func TestFirstActivationHealthFailureCompensates(t *testing.T) {
	r := newRig(t)
	r.sim.fail["systemctl restart meridian-failover.service"] = true
	b := compileTopo(t, defaults.Example())
	_, err := r.applier().Apply(b, false)
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(r.host, "etc", "wireguard")); len(entries) != 0 {
		t.Fatal("WireGuard configs left on the host")
	}
	if exists(filepath.Join(r.host, "usr", "local", "sbin", "meridian-up.sh")) {
		t.Fatal("up script left on the host")
	}
	if len(r.sim.liveLinks()) != 0 || len(r.sim.nft) != 0 {
		t.Fatalf("runtime left: links %v nft %v", r.sim.liveLinks(), r.sim.nft)
	}
	cmds := strings.Join(r.sim.cmds, "\n")
	if i, j := strings.Index(cmds, "sysctl -w net.ipv4.ip_forward=0"), strings.Index(cmds, "nft delete table inet meridian_guard"); i < 0 || j < i {
		t.Fatal("forwarding must be turned off before the guard goes")
	}
	if exists(filepath.Join(r.data, "applied")) {
		t.Fatal("failed first install left a snapshot")
	}
	if p, _ := r.applier().Pending(); p != nil {
		t.Fatal("journal left after successful compensation")
	}
	// The next attempt starts clean.
	delete(r.sim.fail, "systemctl restart meridian-failover.service")
	if _, err := r.applier().Apply(b, false); err != nil {
		t.Fatal(err)
	}
}

// An activation timeout on the second install compensates back to the first:
// host files, live links, installed manifest and snapshots.
func TestActivationTimeoutCompensatesToPrevious(t *testing.T) {
	r := newRig(t)
	v1 := compileTopo(t, withoutHubWSS())
	if _, err := r.applier().Apply(v1, false); err != nil {
		t.Fatal(err)
	}
	routesV1 := readHost(t, r.host, "usr/local/sbin/meridian-routes.sh")
	canonV1, _ := os.ReadFile(filepath.Join(r.data, "applied", "canonical.txt"))
	r.rt.fail["fwd-activate"] = errors.New("宿主动作 activate 未完成：超时")
	_, err := r.applier().Apply(compileTopo(t, defaults.Example()), false)
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("got %v", err)
	}
	if readHost(t, r.host, "usr/local/sbin/meridian-routes.sh") != routesV1 {
		t.Fatal("host files not restored")
	}
	if exists(filepath.Join(r.host, "etc", "wireguard", "m03.conf")) {
		t.Fatal("the new tunnel config survived compensation")
	}
	if strings.Join(r.sim.liveLinks(), ",") != "m02,m02w" {
		t.Fatalf("live links %v", r.sim.liveLinks())
	}
	if canon, _ := os.ReadFile(filepath.Join(r.data, "applied", "canonical.txt")); string(canon) != string(canonV1) {
		t.Fatal("snapshot not restored")
	}
	if inst, _ := r.applier().Installed(); inst.Version != 1 {
		t.Fatalf("installed version %d", inst.Version)
	}
}

// Topology deletion: a link removed from the topology loses its config file,
// its interface and its unit on the host. Only what the old manifest owned
// is removed; an unrelated file next to it stays.
func TestTopologyDeletionRemovesOwnedResources(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(r.host, "etc", "wireguard", "m99.conf")
	if err := os.WriteFile(foreign, []byte("not ours\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.sim.links["m99"] = true
	res, err := r.applier().Apply(compileTopo(t, withoutHubWSS()), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Host.Diff.InterfacesRemoved, ",") != "m03" || strings.Join(res.Host.Diff.UnitsRemoved, ",") != "wstunnel-client-gw-hub-wss.service" {
		t.Fatalf("diff %+v", res.Host.Diff)
	}
	rm := r.rt.requests("fwd-remove")
	if len(rm) != 1 || strings.Join(rm[0].Resources.Interfaces, ",") != "m03" {
		t.Fatalf("remove %+v", rm)
	}
	if exists(filepath.Join(r.host, "etc", "wireguard", "m03.conf")) || exists(filepath.Join(r.host, "etc", "systemd", "system", "wstunnel-client-gw-hub-wss.service")) {
		t.Fatal("removed link's files remain")
	}
	if !exists(foreign) || !r.sim.links["m99"] {
		t.Fatal("touched a resource Meridian does not own")
	}
	if strings.Join(r.sim.liveLinks(), ",") != "m02,m02w,m99" {
		t.Fatalf("live %v", r.sim.liveLinks())
	}
}

// Rollback after a new resource was added: the newer config file, interface
// and unit are removed, the up script activates only the old list, and the
// snapshot swap is part of the same transaction.
func TestRuntimeRollbackRemovesNewResources(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, withoutHubWSS()), false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	if !r.sim.links["m03"] {
		t.Fatal("setup: m03 not up")
	}
	// The data-only rollback that the old panel sent is now refused.
	snap := r.applier()
	snap.Install = false
	if err := snap.Rollback(); !errors.Is(err, ErrRuntimeRollbackRequired) {
		t.Fatalf("snapshot-only rollback on an installed host: %v", err)
	}
	rep, err := r.applier().RollbackReport()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Committed || rep.FromVersion != 2 || rep.ToVersion != 1 {
		t.Fatalf("%+v", rep)
	}
	if exists(filepath.Join(r.host, "etc", "wireguard", "m03.conf")) {
		t.Fatal("rollback left the new tunnel config")
	}
	if r.sim.links["m03"] || r.sim.units["wstunnel-client-gw-hub-wss.service"] {
		t.Fatal("rollback left the new interface or unit running")
	}
	act := r.rt.requests("fwd-activate")
	last := act[len(act)-1]
	if strings.Join(last.Resources.Interfaces, ",") != "m02,m02w" {
		t.Fatalf("rollback activated %v", last.Resources.Interfaces)
	}
	if strings.Contains(readHost(t, r.host, "usr/local/sbin/meridian-up.sh"), "m03") {
		t.Fatal("restored up script still lists m03")
	}
	if inst, _ := r.applier().Installed(); inst.Version != 1 {
		t.Fatalf("installed %d", inst.Version)
	}
	// Repeated call: a second rollback swaps forward again, idempotently.
	if _, err := r.applier().RollbackReport(); err != nil {
		t.Fatal(err)
	}
	if !r.sim.links["m03"] || !exists(filepath.Join(r.host, "etc", "wireguard", "m03.conf")) {
		t.Fatal("second rollback did not bring v2 back")
	}
	for _, conf := range gwConfs(t, r.host) {
		if !strings.Contains(conf, "PrivateKey = "+r.key+"\n") {
			t.Fatal("rollback lost the key")
		}
	}
	assertNoSecret(t, r.data, r.key)
}

// Repeated identical installs converge to the same state without removals;
// concurrent calls are serialised.
func TestRepeatedAndConcurrentCalls(t *testing.T) {
	r := newRig(t)
	b := compileTopo(t, defaults.Example())
	for i := 0; i < 2; i++ {
		if _, err := r.applier().Apply(b, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.rt.requests("fwd-remove")) != 0 {
		t.Fatal("identical re-install removed something")
	}
	ids := map[string]bool{}
	for _, q := range r.rt.reqs {
		if ids[q.RequestID] {
			t.Fatalf("request id reused across transactions: %s", q.RequestID)
		}
		ids[q.RequestID] = true
	}
	ser := &serialRT{inner: r.rt}
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ap := r.applier()
			ap.Host = ser
			_, err := ap.Apply(b, false)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ser.max != 1 {
		t.Fatalf("%d host calls overlapped", ser.max)
	}
	if inst, _ := r.applier().Installed(); inst.Version != 5 {
		t.Fatalf("installed version %d after 5 installs", inst.Version)
	}
}

type serialRT struct {
	inner    Runtime
	mu       sync.Mutex
	cur, max int
}

func (s *serialRT) Do(ctx context.Context, req hostexec.Request) (hostexec.Result, error) {
	s.mu.Lock()
	s.cur++
	if s.cur > s.max {
		s.max = s.cur
	}
	s.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	defer func() { s.mu.Lock(); s.cur--; s.mu.Unlock() }()
	return s.inner.Do(ctx, req)
}

// A failed cleanup during compensation must not be reported as success:
// the journal is kept, new work is refused, and Recover (after the fault is
// fixed) restores the pre-transaction state.
func TestCompensationFailureIsNotSuccess(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, withoutHubWSS()), false); err != nil {
		t.Fatal(err)
	}
	r.rt.fail["fwd-activate"] = errors.New("health failed")
	r.rt.fail["comp-remove"] = errors.New("ip link del m03: device busy")
	_, err := r.applier().Apply(compileTopo(t, defaults.Example()), false)
	var te *TxnError
	if !errors.As(err, &te) || te.Compensated || te.CompErr == nil || !strings.Contains(err.Error(), "补偿也失败") {
		t.Fatalf("got %v", err)
	}
	p, _ := r.applier().Pending()
	if p == nil || p.Phase != phaseCompensate {
		t.Fatalf("pending %+v", p)
	}
	if _, err := r.applier().Apply(compileTopo(t, withoutHubWSS()), false); !errors.Is(err, ErrPending) {
		t.Fatalf("new apply with a pending transaction: %v", err)
	}
	if err := r.applier().Rollback(); !errors.Is(err, ErrPending) {
		t.Fatalf("rollback with a pending transaction: %v", err)
	}
	r.restart()
	if _, err := r.applier().Recover(); err != nil {
		t.Fatal(err)
	}
	if p, _ := r.applier().Pending(); p != nil {
		t.Fatal("journal kept after recovery")
	}
	if r.sim.links["m03"] || exists(filepath.Join(r.host, "etc", "wireguard", "m03.conf")) {
		t.Fatal("recovery left the failed transaction's tunnel")
	}
	if inst, _ := r.applier().Installed(); inst.Version != 1 {
		t.Fatalf("installed %d", inst.Version)
	}
}

// The panel dies in the middle of a runtime rollback (after the snapshots
// swapped and old resources were removed, before activation). On restart,
// Recover compensates back to the state before the rollback.
func TestRestartMidRollbackRecovers(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, withoutHubWSS()), false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	canonV2, _ := os.ReadFile(filepath.Join(r.data, "applied", "canonical.txt"))
	r.rt.crash = "fwd-activate"
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.applier().Rollback()
	}()
	<-done
	p, _ := r.applier().Pending()
	if p == nil || p.Phase != phaseHost || p.Kind != "rollback" {
		t.Fatalf("pending %+v", p)
	}
	if r.sim.links["m03"] {
		t.Fatal("setup: the crash should be after m03 was removed")
	}
	r.restart()
	rep, err := r.applier().Recover()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Compensated {
		t.Fatalf("%+v", rep)
	}
	if canon, _ := os.ReadFile(filepath.Join(r.data, "applied", "canonical.txt")); string(canon) != string(canonV2) {
		t.Fatal("snapshots not swapped back")
	}
	if !r.sim.links["m03"] || !exists(filepath.Join(r.host, "etc", "wireguard", "m03.conf")) {
		t.Fatal("pre-rollback state (v2) not restored")
	}
	if inst, _ := r.applier().Installed(); inst.Version != 2 {
		t.Fatalf("installed %d", inst.Version)
	}
	// Recover is idempotent.
	if rep, err := r.applier().Recover(); err != nil || rep != nil {
		t.Fatalf("second recover: %+v %v", rep, err)
	}
	// And the rollback can now be retried to completion.
	if err := r.applier().Rollback(); err != nil {
		t.Fatal(err)
	}
	if r.sim.links["m03"] {
		t.Fatal("retried rollback did not remove m03")
	}
}

// A crash after the host converged (phase commit) is finished, not undone.
func TestRestartAfterHostConvergedFinishesCommit(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	// Simulate: next transaction reached "commit" and the process died.
	ap := r.applier()
	unlock, err := ap.begin()
	if err != nil {
		t.Fatal(err)
	}
	from, _ := ap.Installed()
	b := compileTopo(t, withoutHubWSS())
	to, _ := DeriveManifest("gw", nodeFiles(b.Files, "gw"), 2, b.Canonical())
	j := &journal{ID: newTxnID(), Kind: "apply", Install: true, Phase: phaseCommit, From: from, To: to,
		Before: ap.snapshots(), After: ap.snapshots()}
	if err := writeInstalledCopy(ap.nextDir(), "gw", nodeFiles(b.Files, "gw"), to); err != nil {
		t.Fatal(err)
	}
	if err := ap.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	unlock()
	if _, err := r.applier().Recover(); err != nil {
		t.Fatal(err)
	}
	if inst, _ := r.applier().Installed(); inst.Version != 2 {
		t.Fatalf("commit not finished: installed %d", inst.Version)
	}
	if len(r.rt.requests("comp-remove")) != 0 {
		t.Fatal("a committed transaction must not be compensated")
	}
}

// Snapshots written before manifests existed are upgraded in place and a
// data-only rollback on a host with nothing installed still works.
func TestLegacySnapshotsUpgrade(t *testing.T) {
	data := t.TempDir()
	ap := Applier{DataDir: data, LocalID: "gw"}
	b := compileTopo(t, defaults.Example())
	for i := 0; i < 2; i++ {
		if _, err := ap.Apply(b, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"applied", "previous"} {
		if err := os.Remove(filepath.Join(data, d, "manifest.json")); err != nil {
			t.Fatal(err)
		}
	}
	if err := ap.Rollback(); err != nil {
		t.Fatal(err)
	}
	s := ap.snapshots()
	if s.Applied != 1 || s.Previous != 2 {
		t.Fatalf("%+v", s)
	}
}
