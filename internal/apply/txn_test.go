package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	"github.com/radowitz/meridian/internal/remoteaccess"
	"github.com/radowitz/meridian/internal/wsstest"
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
	// peers is the running WireGuard peer set per interface (public keys),
	// as "wg syncconf" / "wg-quick up" leave it: exactly the file's.
	peers map[string][]string
	// psks are the pre-shared keys the running interfaces were given.
	psks map[string][]string
	// failOnce fails the first matching command only.
	failOnce map[string]bool
}

var upIfaces = regexp.MustCompile(`(?m)^for iface in ([^;]*); do$`)

func newSimHost(root string) *simHost {
	return &simHost{root: root, links: map[string]bool{}, nft: map[string]bool{}, units: map[string]bool{}, enabled: map[string]bool{}, fail: map[string]bool{},
		peers: map[string][]string{}, psks: map[string][]string{}, failOnce: map[string]bool{}}
}

func (h *simHost) Run(ctx context.Context, prog string, args ...string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	line := prog + " " + strings.Join(args, " ")
	h.cmds = append(h.cmds, line)
	for p := range h.failOnce {
		if strings.HasPrefix(line, p) {
			delete(h.failOnce, p)
			return "sim failure", errors.New("exit status 1")
		}
	}
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
				conf, err := os.ReadFile(filepath.Join(h.root, "etc", "wireguard", i+".conf"))
				if err != nil {
					return "meridian-wg-missing", errors.New("exit status 1")
				}
				// wg syncconf (or wg-quick up): the running peer set becomes
				// the file's; a placeholder key is rejected by wg.
				peers, psks := []string{}, []string{}
				for _, line := range strings.Split(string(conf), "\n") {
					k, v, _ := strings.Cut(line, "=")
					k, v = strings.TrimSpace(k), strings.TrimSpace(v)
					if strings.Contains(v, "__MERIDIAN_") {
						return "Key is not the correct length or format", errors.New("exit status 1")
					}
					switch k {
					case "PublicKey":
						peers = append(peers, v)
					case "PresharedKey":
						psks = append(psks, v)
					}
				}
				h.links[i] = true
				h.peers[i], h.psks[i] = peers, psks
			}
		}
		nft, _ := os.ReadFile(filepath.Join(h.root, "etc", "nftables.d", "meridian.nft"))
		for _, m := range nftTableLine.FindAllStringSubmatch(string(nft), -1) {
			h.nft[m[1]+" "+m[2]] = true
		}
		h.units["meridian.service"] = true
	case prog == "systemctl" && args[0] == "restart" && args[1] == "meridian-guard.service":
		// Loads only the guard table from its boot file.
		if _, err := os.Stat(filepath.Join(h.root, "etc", "nftables.d", "meridian-guard.nft")); err != nil {
			return "", errors.New("ConditionPathExists failed")
		}
		h.nft["inet meridian_guard"] = true
		h.units["meridian-guard.service"] = true
	case prog == "systemctl" && args[0] == "stop":
		delete(h.units, args[1])
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
		delete(h.peers, args[3])
		delete(h.psks, args[3])
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
	return Applier{DataDir: r.data, Install: true, LocalID: "gw", PrivateKey: r.key, HostRoot: r.host, Host: r.rt, Secrets: wsstest.StableSecrets()}
}

// restart models a new panel process: same disks, same host, new agent
// connection (the agent keeps its persisted ledger).
func (r *rig) restart() {
	r.rt = newAgentRT(r.sim, r.ledger)
}

func compileTopo(t *testing.T, topo model.Topology) *compile.Bundle {
	t.Helper()
	b, err := wsstest.StableCompileErr(topo)
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
	ap := Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: testKey(t), Secrets: wsstest.StableSecrets()}
	if _, err := ap.Apply(b, false); !errors.Is(err, ErrNoHostExec) {
		t.Fatalf("got %v", err)
	}
	// A boundary that is configured but unreachable: same, before any write.
	host := t.TempDir()
	unreachable := &hostexec.Client{Socket: filepath.Join(t.TempDir(), "none.sock"), TokenFile: filepath.Join(t.TempDir(), "t")}
	ap = Applier{DataDir: data, Install: true, LocalID: "gw", PrivateKey: testKey(t), HostRoot: host, Host: unreachable, Secrets: wsstest.StableSecrets()}
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

// legacyHost puts on the rig's host what a version without manifests left
// behind for topo: the gateway files written straight into the host (the
// WireGuard private key filled in by hand, no forwarding.conf, boot-time
// forwarding lines at 0 as install.sh's upgrade leaves them), the old
// snapshot without a manifest, and the data plane running. It returns the
// host files as written.
func legacyHost(t *testing.T, r *rig, topo model.Topology, key string) map[string]string {
	t.Helper()
	b := compileTopo(t, topo)
	files := nodeFiles(b.Files, "gw")
	delete(files, "etc/meridian/forwarding.conf")
	out := map[string]string{}
	for rel, body := range files {
		body, err := InjectPrivateKey(rel, body, key)
		if err != nil {
			t.Fatal(err)
		}
		// A running data plane has its WSS secrets in place as well.
		if body, err = InjectSecrets(rel, body, wsstest.StableSecrets()); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(r.host, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(rel, "usr/local/sbin/") {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		out[rel] = body
	}
	if !strings.Contains(out["etc/sysctl.d/99-meridian.conf"], "net.ipv4.ip_forward=0\n") {
		t.Fatal("setup: expected boot-time forwarding lines")
	}
	old := Applier{DataDir: r.data, LocalID: "gw"}
	if _, err := old.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(r.data, "applied", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	// The old data plane is running (started by its meridian.service).
	ctx := context.Background()
	if _, err := r.sim.Run(ctx, "systemctl", "restart", "meridian.service"); err != nil {
		t.Fatal(err)
	}
	m, err := DeriveManifest("gw", files, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range m.Units {
		_, _ = r.sim.Run(ctx, "systemctl", "enable", u)
		if _, err := r.sim.Run(ctx, "systemctl", "restart", u); err != nil {
			t.Fatal(err)
		}
	}
	r.sim.cmds = nil
	return out
}

func hostTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(root, p)
			out[rel] = fmt.Sprintf("%o:%s", fi.Mode().Perm(), b)
		}
		return nil
	})
	return out
}

// QA qa-3: a host running a version without manifests. The first install
// of this version fails during activation (after the new up script already
// ran); compensation puts the old files back byte for byte (key injected
// at the boundary, never stored), removes what only the new version
// brought, and re-activates the old data plane, which is healthy again.
// The next install then succeeds from the adopted manifest.
func TestLegacyInstallFailedFirstActivationRestoresOldVersion(t *testing.T) {
	r := newRig(t)
	legacy := legacyHost(t, r, withoutHubWSS(), r.key)
	canonOld, _ := os.ReadFile(filepath.Join(r.data, "applied", "canonical.txt"))
	if strings.Join(r.sim.liveLinks(), ",") != "m02,m02w" {
		t.Fatalf("setup: %v", r.sim.liveLinks())
	}
	ap := r.applier()
	ap.Forwarding = func() (bool, error) { return true, nil }
	// The new-only tunnel's unit fails to start: meridian.service has
	// already been restarted with the new up script (m03 is up by then).
	r.sim.fail["systemctl restart wstunnel-client-gw-hub-wss.service"] = true
	_, err := ap.Apply(compileTopo(t, defaults.Example()), false)
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(strings.Join(te.Report.Warnings, "\n"), "已接管旧版安装") {
		t.Fatalf("report does not say the legacy install was adopted: %v", te.Report.Warnings)
	}
	if len(r.rt.requests("fwd-activate")) != 1 {
		t.Fatal("setup: the new version was not activated")
	}
	// Files: exactly the old ones, the new-only ones gone.
	for rel, body := range legacy {
		want := body
		if rel == "etc/sysctl.d/99-meridian.conf" {
			want = strings.ReplaceAll(strings.ReplaceAll(body, "net.ipv4.ip_forward=0\n", "net.ipv4.ip_forward=1\n"),
				"net.ipv6.conf.all.forwarding=0\n", "net.ipv6.conf.all.forwarding=1\n")
		}
		if got := readHost(t, r.host, rel); got != want {
			t.Fatalf("%s not restored", rel)
		}
	}
	for _, rel := range []string{"etc/wireguard/m03.conf", "etc/meridian/forwarding.conf", "etc/systemd/system/wstunnel-client-gw-hub-wss.service"} {
		if exists(filepath.Join(r.host, filepath.FromSlash(rel))) {
			t.Fatalf("new-only %s left on the host", rel)
		}
	}
	// Runtime: the old data plane is up again, the new tunnel is gone.
	if strings.Join(r.sim.liveLinks(), ",") != "m02,m02w" || !r.sim.units["meridian.service"] || !r.sim.units["meridian-failover.service"] {
		t.Fatalf("old data plane not running: links %v units %v", r.sim.liveLinks(), r.sim.units)
	}
	comp := r.rt.requests("comp-activate")
	if len(comp) != 1 || strings.Join(comp[0].Resources.Interfaces, ",") != "m02,m02w" {
		t.Fatalf("compensation activated %+v", comp)
	}
	inst, _ := r.applier().Installed()
	if inst.Origin != "legacy" || inst.Empty() {
		t.Fatalf("installed %+v", inst)
	}
	if p, _ := r.applier().Pending(); p != nil {
		t.Fatalf("journal left: %+v", p)
	}
	if canon, _ := os.ReadFile(filepath.Join(r.data, "applied", "canonical.txt")); string(canon) != string(canonOld) {
		t.Fatal("snapshot not restored")
	}
	assertNoSecret(t, r.data, r.key)

	// After the fault is fixed the upgrade goes through.
	delete(r.sim.fail, "systemctl restart wstunnel-client-gw-hub-wss.service")
	res, err := ap.Apply(compileTopo(t, defaults.Example()), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Host.FromVersion != inst.Version || !r.sim.links["m03"] {
		t.Fatalf("%+v", res.Host)
	}
	if inst, _ := r.applier().Installed(); inst.Origin != "" || inst.Version != res.Host.ToVersion {
		t.Fatalf("installed %+v", inst)
	}
	assertNoSecret(t, r.data, r.key)
}

// When a legacy install cannot be adopted reliably the install is refused
// before anything changes: host files, runtime, snapshots, data directory.
func TestLegacyInstallRefusedTouchesNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, r *rig)
		next  model.Topology
		want  string
	}{
		{"foreign private key", func(t *testing.T, r *rig) { legacyHost(t, r, withoutHubWSS(), testKey(t)) }, defaults.Example(), "私钥"},
		{"placeholder key", func(t *testing.T, r *rig) {
			legacyHost(t, r, withoutHubWSS(), r.key)
			p := filepath.Join(r.host, "etc", "wireguard", "m02.conf")
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, []byte(strings.ReplaceAll(string(b), r.key, compile.PrivateKeyPlaceholder)), 0o644)
		}, defaults.Example(), "私钥"},
		{"not running", func(t *testing.T, r *rig) {
			legacyHost(t, r, withoutHubWSS(), r.key)
			delete(r.sim.units, "meridian.service")
		}, defaults.Example(), "不健康"},
		{"old-only resources", func(t *testing.T, r *rig) { legacyHost(t, r, defaults.Example(), r.key) }, withoutHubWSS(), "m03"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.setup(t, r)
			hostBefore := hostTree(t, r.host)
			dataBefore := hostTree(t, r.data)
			links := strings.Join(r.sim.liveLinks(), ",")
			_, err := r.applier().Apply(compileTopo(t, c.next), false)
			if !errors.Is(err, ErrLegacyInstall) || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), r.key) {
				t.Fatalf("got %v", err)
			}
			if !reflect.DeepEqual(hostTree(t, r.host), hostBefore) {
				t.Fatal("host files changed")
			}
			// Only bookkeeping may appear: the transaction lock and the
			// version that begin() gives a pre-manifest snapshot.
			dataAfter := hostTree(t, r.data)
			for _, tree := range []map[string]string{dataBefore, dataAfter} {
				delete(tree, filepath.Join("host", "txn.lock"))
				delete(tree, filepath.Join("applied", "manifest.json"))
			}
			if !reflect.DeepEqual(dataAfter, dataBefore) {
				t.Fatalf("data directory changed: %d -> %d files", len(dataBefore), len(dataAfter))
			}
			if strings.Join(r.sim.liveLinks(), ",") != links {
				t.Fatal("runtime changed")
			}
			for _, q := range r.rt.reqs {
				if q.Action != hostexec.ActionHealth {
					t.Fatalf("host action %s sent", q.Action)
				}
			}
		})
	}
}

// ---------------------------------------------------------------- remote access

type raFixture struct {
	topo    model.Topology
	secrets map[string]string
	privs   []string // device private keys (never handed to the applier)
}

func raKeys(t *testing.T) remoteaccess.Keypair {
	t.Helper()
	kp, err := remoteaccess.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// raTopology is the example topology with remote access on and devices
// "dev-aaaa" (with a PSK) and "dev-bbbb". Every key is generated here.
func raTopology(t *testing.T) raFixture {
	t.Helper()
	f := raFixture{topo: defaults.Example(), secrets: map[string]string{}}
	gw := raKeys(t)
	f.secrets["ra-key-test"] = gw.Private
	psk, err := remoteaccess.GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	f.secrets["ra-psk-aaaa"] = psk
	ra := &model.RemoteAccess{Enabled: true, Endpoint: "home.example.net", ListenPort: 51900, PublicKey: gw.Public, KeyID: "ra-key-test"}
	for i, id := range []string{"dev-aaaa", "dev-bbbb"} {
		kp := raKeys(t)
		f.privs = append(f.privs, kp.Private)
		d := model.RemoteDevice{ID: id, Name: id, Mode: model.RemoteModeFull, Enabled: true, PublicKey: kp.Public,
			IPv4: fmt.Sprintf("10.67.0.%d", i+2), IPv6: fmt.Sprintf("fd67::%d", i+2)}
		if i == 0 {
			d.PSKID = "ra-psk-aaaa"
		}
		ra.Devices = append(ra.Devices, d)
	}
	f.topo.RemoteAccess = ra
	return f
}

func (r *rig) raApplier(secrets map[string]string) Applier {
	a := r.applier()
	for k, v := range secrets {
		a.Secrets[k] = v
	}
	return a
}

func (r *rig) peers(iface string) string {
	r.sim.mu.Lock()
	defer r.sim.mu.Unlock()
	return strings.Join(r.sim.peers[iface], ",")
}

// noSecretsUnder fails if any file below dir contains one of the values.
func noSecretsUnder(t *testing.T, dir string, values ...string) {
	t.Helper()
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, v := range values {
			if v != "" && strings.Contains(string(b), v) {
				t.Errorf("secret found in %s", p)
			}
		}
		return nil
	})
}

// Adding, disabling and deleting devices change the running peers through
// the transaction; a failed apply compensates back to the previous peer
// set; disabling the feature removes the interface.
func TestRemotePeersFollowTransaction(t *testing.T) {
	r := newRig(t)
	f := raTopology(t)
	ra := f.topo.RemoteAccess
	a, b := ra.Devices[0].PublicKey, ra.Devices[1].PublicKey
	if _, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false); err != nil {
		t.Fatal(err)
	}
	if got := r.peers("mra"); got != a+","+b {
		t.Fatalf("peers after add: %q", got)
	}
	if got := strings.Join(r.sim.psks["mra"], ","); got != f.secrets["ra-psk-aaaa"] {
		t.Fatal("the PSK was not injected at the install boundary")
	}
	conf := filepath.Join(r.host, "etc", "wireguard", "mra.conf")
	if fi, err := os.Stat(conf); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mra.conf mode: %v %v", fi, err)
	}
	if body := readHost(t, r.host, "etc/wireguard/mra.conf"); !strings.Contains(body, f.secrets["ra-key-test"]) || strings.Contains(body, "__MERIDIAN_") {
		t.Fatal("host config must carry the injected key and no placeholder")
	}
	// Snapshots, the installed copy and the journal keep placeholders only.
	noSecretsUnder(t, r.data, append([]string{f.secrets["ra-key-test"], f.secrets["ra-psk-aaaa"], r.key}, f.privs...)...)
	noSecretsUnder(t, r.host, f.privs...)

	// Disable B: its peer is gone from the running interface.
	f.topo.RemoteAccess.Devices[1].Enabled = false
	if _, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false); err != nil {
		t.Fatal(err)
	}
	if got := r.peers("mra"); got != a {
		t.Fatalf("disabled device still a peer: %q", got)
	}

	// Delete A, but the activation fails after meridian-up.sh ran: the
	// compensation restores the previous peer set (A, with its PSK).
	f.topo.RemoteAccess.Devices = f.topo.RemoteAccess.Devices[1:]
	r.sim.failOnce["systemctl restart meridian-failover.service"] = true
	_, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false)
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("got %v", err)
	}
	for _, v := range f.secrets {
		if strings.Contains(err.Error(), v) {
			t.Fatal("secret in the error")
		}
	}
	if got := r.peers("mra"); got != a {
		t.Fatalf("compensation did not restore the previous peers: %q", got)
	}
	if got := strings.Join(r.sim.psks["mra"], ","); got != f.secrets["ra-psk-aaaa"] {
		t.Fatal("compensation did not restore the PSK")
	}
	if _, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false); err != nil {
		t.Fatal(err)
	}
	if got := r.peers("mra"); got != "" {
		t.Fatalf("deleted device still a peer: %q", got)
	}

	// Feature off: mra is removed through the manifest.
	f.topo.RemoteAccess.Enabled = false
	if _, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false); err != nil {
		t.Fatal(err)
	}
	if exists(conf) {
		t.Fatal("mra.conf survived disabling remote access")
	}
	for _, l := range r.sim.liveLinks() {
		if l == "mra" {
			t.Fatal("mra still exists after disabling remote access")
		}
	}
}

// A config naming a secret that is not supplied fails before any host file
// is written, without echoing any value.
func TestRemoteMissingSecretFailsBeforeWriting(t *testing.T) {
	r := newRig(t)
	f := raTopology(t)
	delete(f.secrets, "ra-psk-aaaa")
	_, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false)
	if !errors.Is(err, ErrMissingSecret) || !strings.Contains(err.Error(), "ra-psk-aaaa") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), f.secrets["ra-key-test"]) {
		t.Fatal("secret in the error")
	}
	if entries, _ := os.ReadDir(filepath.Join(r.host, "etc")); len(entries) != 0 {
		t.Fatal("host files written before the secret check")
	}
	if _, err := InjectSecrets("etc/meridian/x.conf", "a "+model.SecretPlaceholder("ra-key-test"), f.secrets); err == nil {
		t.Fatal("a placeholder outside etc/wireguard must be refused")
	}
}

// ReferencedSecrets keeps the ids a stored configuration still names.
func TestRemoteReferencedSecrets(t *testing.T) {
	r := newRig(t)
	f := raTopology(t)
	if _, err := r.raApplier(f.secrets).Apply(compileTopo(t, f.topo), false); err != nil {
		t.Fatal(err)
	}
	refs, err := r.applier().ReferencedSecrets()
	if err != nil {
		t.Fatal(err)
	}
	// Exactly the two remote-access ids plus the WSS secrets the bundle
	// names (path prefixes and listener keys are referenced the same way).
	nonWSS := 0
	for id := range refs {
		if !IsWSSSecretID(id) {
			nonWSS++
		}
	}
	if !refs["ra-key-test"] || !refs["ra-psk-aaaa"] || nonWSS != 2 {
		t.Fatalf("refs %v", refs)
	}
	for _, id := range SecretRefs(compileTopo(t, f.topo).Canonical()) {
		if !refs[id] {
			t.Fatalf("referenced secret %s missing from %v", id, refs)
		}
	}
}
