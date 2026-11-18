package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// drillHost is a Runner that models what the drills read and change: the
// nft tables (with the block table), policy rules, route tables, links,
// WireGuard endpoints and meridian.service. Hooks stand in for the
// gateway's failover loop, which rewrites the upstream record when a relay
// stops answering. Nothing is executed; every address is a documentation
// address.
type drillHost struct {
	mu        sync.Mutex
	cmds      []string
	tables    map[string]bool
	rules     map[string]string
	ipRules   map[string]string
	routes    map[string]string
	links     map[string]string
	endpoints map[string]string
	shakes    map[string]string
	fail      map[string]bool
	hold      map[string]chan struct{} // command prefix waits for the channel
	core      string
	loaded    string // content of the last block rules file loaded
	onBlock   func()
	onUnblock func()
	onRestart func(h *drillHost)
	// restartBreaks: the restart fails and takes the main table with it.
	restartBreaks bool
}

const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	keyB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
)

func newDrillHost() *drillHost {
	now := time.Now().Unix()
	return &drillHost{
		tables:  map[string]bool{"inet meridian": true, "inet meridian_guard": true},
		rules:   map[string]string{"inet meridian": "table inet meridian {\n\tchain fwd { }\n}\n", "inet meridian_guard": "table inet meridian_guard {\n}\n"},
		ipRules: map[string]string{"-4": "0:\tfrom all lookup local\n17800:\tfrom all fwmark 0x66 lookup 102\n", "-6": "0:\tfrom all lookup local\n"},
		routes:  map[string]string{"102/-4": "default dev m02\n", "102/-6": "default dev m02\n"},
		links:   map[string]string{"m02": "UP,LOWER_UP", "m03": "UP,LOWER_UP", "m04w": "UP,LOWER_UP"},
		endpoints: map[string]string{
			"m02":  keyA + "\t198.51.100.7:51820\n",
			"m03":  keyB + "\t[2001:db8::7]:51820\n",
			"m04w": keyA + "\t127.0.0.1:4001\n",
		},
		shakes: map[string]string{
			"m02":  fmt.Sprintf("%s\t%d\n", keyA, now-20),
			"m03":  fmt.Sprintf("%s\t%d\n", keyB, now-30),
			"m04w": fmt.Sprintf("%s\t%d\n", keyA, now-40),
		},
		fail: map[string]bool{}, hold: map[string]chan struct{}{}, core: "active",
	}
}

func (h *drillHost) Run(ctx context.Context, prog string, args ...string) (string, error) {
	line := prog + " " + strings.Join(args, " ")
	h.mu.Lock()
	h.cmds = append(h.cmds, line)
	var wait chan struct{}
	for p, c := range h.hold {
		if strings.HasPrefix(line, p) {
			wait = c
		}
	}
	h.mu.Unlock()
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	h.mu.Lock()
	for p := range h.fail {
		if strings.HasPrefix(line, p) {
			h.mu.Unlock()
			return "boom", errors.New("exit status 1")
		}
	}
	var after func()
	out, err := h.answer(prog, args, &after)
	h.mu.Unlock()
	if after != nil {
		after()
	}
	return out, err
}

func (h *drillHost) answer(prog string, args []string, after *func()) (string, error) {
	no := errors.New("exit status 1")
	switch {
	case prog == "nft" && len(args) == 2 && args[0] == "list" && args[1] == "tables":
		var b strings.Builder
		for t := range h.tables {
			b.WriteString("table " + t + "\n")
		}
		return b.String(), nil
	case prog == "nft" && len(args) == 6 && args[0] == "-s" && args[1] == "-t":
		t := args[4] + " " + args[5]
		if !h.tables[t] {
			return "No such file or directory", no
		}
		return h.rules[t], nil
	case prog == "nft" && args[0] == "list" && args[1] == "table":
		if !h.tables[args[2]+" "+args[3]] {
			return "No such file or directory", no
		}
	case prog == "nft" && args[0] == "-c":
		if _, err := os.ReadFile(args[2]); err != nil {
			return err.Error(), no
		}
	case prog == "nft" && args[0] == "-f":
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err.Error(), no
		}
		h.loaded = string(b)
		h.tables[DrillTable] = true
		*after = h.onBlock
	case prog == "nft" && args[0] == "delete":
		delete(h.tables, args[2]+" "+args[3])
		*after = h.onUnblock
	case prog == "ip" && len(args) == 3 && args[1] == "rule":
		return h.ipRules[args[0]], nil
	case prog == "ip" && len(args) == 5 && args[1] == "route":
		r, ok := h.routes[args[4]+"/"+args[0]]
		if !ok {
			return "Error: ipv4: FIB table does not exist.", no
		}
		return r, nil
	case prog == "ip" && args[len(args)-2] == "dev":
		fl, ok := h.links[args[len(args)-1]]
		if !ok {
			return "Device does not exist.", no
		}
		return "7: " + args[len(args)-1] + ": <POINTOPOINT,NOARP," + fl + "> mtu 1420 qdisc noqueue state UNKNOWN", nil
	case prog == "wg" && args[2] == "endpoints":
		return h.endpoints[args[1]], nil
	case prog == "wg" && args[2] == "latest-handshakes":
		return h.shakes[args[1]], nil
	case prog == "wg" && args[2] == "transfer":
		out := ""
		for _, l := range strings.Split(strings.TrimSpace(h.shakes[args[1]]), "\n") {
			if f := strings.Fields(l); len(f) == 2 {
				out += f[0] + "\t1000\t2000\n"
			}
		}
		return out, nil
	case prog == "systemctl" && args[0] == "is-active":
		if h.core != "active" {
			return h.core, errors.New("exit status 3")
		}
		return "active", nil
	case prog == "systemctl" && args[0] == "restart" && h.restartBreaks:
		delete(h.tables, "inet meridian")
		return "meridian-up.sh failed", no
	case prog == "systemctl" && args[0] == "restart":
		h.core = "active"
		if h.onRestart != nil {
			f := h.onRestart
			*after = func() { f(h) }
		}
	}
	return "", nil
}

func (h *drillHost) ran(prefix string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// awaitSamples waits (bounded) until the drill has read the nft tables n
// more times: a reload's window is then seen by the sampler on any machine
// instead of lasting a fixed time a loaded scheduler may skip over.
func (h *drillHost) awaitSamples(n int) {
	want := h.ran("nft list tables") + n
	for deadline := time.Now().Add(10 * time.Second); h.ran("nft list tables") < want && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
}

func (h *drillHost) set(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f()
}

func (h *drillHost) has(table string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tables[table]
}

// relayLine is one relay of a version 2 upstream record.
func relayLine(id, iface, status string, weight int) string {
	return fmt.Sprintf("relay %s %s %s %d 0 - 1700000000 good 31000 4 30500 0 1700000100 1048576 2048 20480 100 12 - 0 - - - 0", id, iface, status, weight)
}

type upstreamFile struct {
	root string
	// beatAgo moves the record's heartbeat into the past (seconds).
	beatAgo int64
}

func (u upstreamFile) path() string { return filepath.Join(u.root, UpstreamStateFile) }

func (u upstreamFile) write(t testing.TB, path, iface, hub, tier, state string, relays ...string) {
	now := time.Now().Unix() - u.beatAgo
	s := fmt.Sprintf("meridian-upstream 2\nbeat %d\npath %s\niface %s\nhub %s\ntier %s\nsince %d\nstate %s\ncontroller go\nalert -\nswitched 0\ndesignated relay-a\n",
		now, path, iface, hub, tier, now-100, state)
	s += strings.Join(relays, "\n") + "\nbackup hub-b m04w good 60000 0 60000 0 1700000100 0 0 0\nend\n"
	if err := os.MkdirAll(filepath.Dir(u.path()), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := u.path() + ".tmp"
	if err := os.WriteFile(tmp, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, u.path()); err != nil {
		t.Fatal(err)
	}
}

func (u upstreamFile) normal(t testing.TB) {
	u.write(t, "main", "m02", "hub-a", "primary", "ok", relayLine("relay-a", "m02", "active", 500), relayLine("relay-b", "m03", "active", 500))
}

func (u upstreamFile) evictedA(t testing.TB) {
	u.write(t, "main", "m03", "hub-a", "primary", "ok", relayLine("relay-a", "m02", "evicted", 0), relayLine("relay-b", "m03", "active", 1000))
}

func (u upstreamFile) onBackup(t testing.TB) {
	u.write(t, "backup", "m04w", "hub-b", "backup", "ok", relayLine("relay-a", "m02", "evicted", 0), relayLine("relay-b", "m03", "evicted", 0))
}

const testFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// drillRig is an agent on a drillHost with a synthetic gateway: two relays
// sharing the main path, a backup hub, forwarding on.
type drillRig struct {
	t      testing.TB
	h      *drillHost
	a      *Agent
	up     upstreamFile
	dir    string
	root   string
	seeded bool
}

func newDrillRig(t testing.TB) *drillRig {
	t.Helper()
	root, dir := t.TempDir(), t.TempDir()
	for rel, v := range map[string]string{"proc/sys/net/ipv4/ip_forward": "1\n", "proc/sys/net/ipv6/conf/all/forwarding": "1\n"} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := &drillRig{t: t, h: newDrillHost(), up: upstreamFile{root: root}, dir: dir, root: root}
	r.up.normal(t)
	r.a = r.agent()
	return r
}

// agent builds an agent on the rig's host and state directory (a second
// call is a restarted agent process).
func (r *drillRig) agent() *Agent {
	a := &Agent{
		Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: r.h,
		PreflightRoot: r.root, SniffSocketPath: "/nonexistent-meridian-test/status.sock", SniffSelfCheckWait: 50 * time.Millisecond,
		LedgerPath: filepath.Join(r.dir, "ledger.json"), DrillStatePath: filepath.Join(r.dir, "drill.json"),
		DrillSecond: 2 * time.Millisecond, DrillPoll: 2 * time.Millisecond, DrillSample: time.Millisecond,
		StepTimeout: 5 * time.Second, ListsDir: filepath.Join(r.dir, "lists-dir"),
		DNSCheckExchange: answeringResolver, DNSLivenessWait: 500 * time.Millisecond,
	}
	if !r.seeded {
		// The first process activated the gateway once: the ledger is on
		// disk for every later one.
		r.seeded = true
		a.init()
		if err := a.ledger.add(Resources{Interfaces: []string{"m02", "m03", "m04w"}, NFTTables: []string{"inet meridian", "inet meridian_guard"}, RouteTables: []int{102}}); err != nil {
			r.t.Fatal(err)
		}
	}
	return a
}

func (r *drillRig) relayReq(id string) DrillRequest {
	return DrillRequest{RequestID: id, Kind: DrillRelayIsolation, Interfaces: []string{"m02"}, BlockSeconds: DrillMinBlock, Fingerprint: testFP}
}

func (r *drillRig) hubReq(id string) DrillRequest {
	return DrillRequest{RequestID: id, Kind: DrillHubIsolation, Interfaces: []string{"m02", "m03"}, BackupInterface: "m04w", BlockSeconds: DrillMinBlock, Fingerprint: testFP}
}

// loop makes the host behave like the gateway's failover loop for a relay
// isolation: the blocked relay is evicted, and comes back when unblocked.
func (r *drillRig) loop(blocked, unblocked func(testing.TB)) {
	r.h.set(func() {
		r.h.onBlock = func() { blocked(r.t) }
		r.h.onUnblock = func() { unblocked(r.t) }
	})
}

func waitDrill(t testing.TB, a *Agent, done func(DrillStatus) bool) DrillStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		st := a.DrillStatus()
		if done(st) {
			return st
		}
		if time.Now().After(deadline) {
			b, _ := json.MarshalIndent(st, "", " ")
			t.Fatalf("drill did not reach the expected state:\n%s", b)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func finished(st DrillStatus) bool { return st.Record != nil && !st.Running }

func activateReq(id string) Request {
	return Request{Action: ActionActivate, RequestID: id, Resources: GatewayDataPlane}
}

// Only the three drills, only tunnel interface names, bounded durations.
func TestValidateDrillRejectsFreeForm(t *testing.T) {
	ok := []DrillRequest{
		{RequestID: "d1", Kind: DrillFirewallReload, Fingerprint: testFP},
		{RequestID: "d2", Kind: DrillRelayIsolation, Interfaces: []string{"m02"}, BlockSeconds: 20, Fingerprint: testFP},
		{RequestID: "d3", Kind: DrillHubIsolation, Interfaces: []string{"m02", "m03"}, BackupInterface: "m04w", BlockSeconds: 90, Fingerprint: testFP},
	}
	for _, r := range ok {
		if err := ValidateDrill(r); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
	}
	bad := []DrillRequest{
		{RequestID: "x", Kind: "run", Fingerprint: testFP},
		{RequestID: "x", Kind: "drill_exec", Fingerprint: testFP},
		{RequestID: "has space", Kind: DrillFirewallReload, Fingerprint: testFP},
		{RequestID: "x", Kind: DrillFirewallReload},                                                   // no fingerprint
		{RequestID: "x", Kind: DrillFirewallReload, Fingerprint: "ABC"},                               // malformed
		{RequestID: "x", Kind: DrillFirewallReload, Fingerprint: testFP, Interfaces: []string{"m02"}}, // a target
		{RequestID: "x", Kind: DrillFirewallReload, Fingerprint: testFP, BlockSeconds: 30},            // a duration
		{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 30},            // no target
		{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{"m02", "m03"}},
		{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 19, Interfaces: []string{"m02"}},
		{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 91, Interfaces: []string{"m02"}},
		{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 3600, Interfaces: []string{"m02"}},
		{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{"m02"}, BackupInterface: "m04w"},
		{RequestID: "x", Kind: DrillHubIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{"m02"}},                                 // no backup
		{RequestID: "x", Kind: DrillHubIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{"m02"}, BackupInterface: "m02"},         // backup is a target
		{RequestID: "x", Kind: DrillHubIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{"m02", "m02"}, BackupInterface: "m04w"}, // duplicate
	}
	for _, name := range []string{"eth0", "lo", "mra", "mmesh", "wg0", "m2", "m02; reboot", "198.51.100.7", "../m02", "example.com", "http://example.com/"} {
		bad = append(bad,
			DrillRequest{RequestID: "x", Kind: DrillRelayIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{name}},
			DrillRequest{RequestID: "x", Kind: DrillHubIsolation, Fingerprint: testFP, BlockSeconds: 30, Interfaces: []string{"m02"}, BackupInterface: name})
	}
	for _, r := range bad {
		if err := ValidateDrill(r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}

// The HTTP surface takes no command, path, host or URL: an unknown field
// refuses the request before anything is read on the host.
func TestDrillEndpointsRefuseUnknownFields(t *testing.T) {
	r := newDrillRig(t)
	srv := httptest.NewServer(r.a.Handler())
	defer srv.Close()
	before := r.h.ran("")
	for path, bodies := range map[string][]string{
		"/v1/drill/start": {
			`{"request_id":"d","kind":"drill_relay_isolation","interfaces":["m02"],"block_seconds":30,"fingerprint":"` + testFP + `","command":"id"}`,
			`{"request_id":"d","kind":"drill_relay_isolation","interfaces":["m02"],"block_seconds":30,"fingerprint":"` + testFP + `","address":"198.51.100.9"}`,
			`{"request_id":"d","kind":"drill_firewall_reload","fingerprint":"` + testFP + `","path":"/etc/passwd"}`,
			`{"request_id":"d","kind":"drill_firewall_reload","fingerprint":"` + testFP + `","url":"http://example.com/"}`,
			`{"request_id":"d","kind":"drill_firewall_reload","fingerprint":"` + testFP + `","host":"example.com"}`,
		},
		"/v1/drill/status":     {`{"id":"x"}`},
		"/v1/drill/cancel":     {`{"id":"x","force":true}`, `{"id":"../x y"}`},
		"/v1/acceptance/paths": {`{"request_id":"p","interfaces":["m02"],"ping":"198.51.100.9"}`, `{"request_id":"p","interfaces":["eth0"]}`, `{"request_id":"p","interfaces":[]}`},
	} {
		for _, body := range bodies {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader([]byte(body)))
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s %s: status %d", path, body, resp.StatusCode)
			}
		}
	}
	if r.h.ran("") != before {
		t.Fatalf("a refused request ran something: %v", r.h.cmds)
	}
	// Without the token nothing answers.
	resp, err := http.Post(srv.URL+"/v1/drill/status", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without token: %d", resp.StatusCode)
	}
}

// A relay isolation: the address comes from the host (never the request),
// carries a kernel timeout, the reaction is observed, and when the block
// ends the table is removed and the host verified against the snapshot.
// The caller going away changes nothing: the agent keeps its own clock.
func TestRelayIsolationBlocksObservesAndRestores(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.evictedA, r.up.normal)
	ctx, cancel := context.WithCancel(context.Background())
	st, code := r.a.DrillStart(ctx, r.relayReq("drill-1"))
	cancel() // the browser left
	if code != http.StatusOK || st.Record == nil || st.Record.Phase != DrillActive || !st.Blocked || !st.Running {
		t.Fatalf("start: %d %+v", code, st)
	}
	if st.Record.ChangedAt == nil || len(st.Record.Plan) < 3 || st.Record.Snapshot.Upstream == nil || len(st.Record.Snapshot.Upstream.Relays) != 2 {
		t.Fatalf("record lacks the state before or the plan: %+v", st.Record)
	}
	loaded := ""
	r.h.set(func() { loaded = r.h.loaded })
	if !strings.Contains(loaded, "198.51.100.7 timeout 35s") || strings.Contains(loaded, "2001:db8::7") || !strings.Contains(loaded, "hook output") {
		t.Fatalf("block rules: %s", loaded)
	}
	// On disk while active, with no address in it.
	disk, err := os.ReadFile(r.a.DrillStatePath)
	if err != nil || !strings.Contains(string(disk), `"phase": "active"`) || strings.Contains(string(disk), "198.51.100") {
		t.Fatalf("record on disk: %v %s", err, disk)
	}
	st = waitDrill(t, r.a, finished)
	rec := st.Record
	if rec.Phase != DrillRestored || rec.Outcome != DrillMet || st.Blocked || len(rec.Residual) != 0 || !rec.OwnChangeCleared || rec.Trigger != "deadline" || rec.Reactivated {
		b, _ := json.MarshalIndent(rec, "", " ")
		t.Fatalf("not restored cleanly:\n%s", b)
	}
	if r.h.has(DrillTable) {
		t.Fatal("block table still loaded")
	}
	if _, err := os.Stat(r.a.drillRulesPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("block rules file left behind: %v", err)
	}
	if r.h.ran("systemctl restart") != 0 {
		t.Fatal("a clean restore restarted the data plane")
	}
	if len(rec.Observed) == 0 || !strings.Contains(rec.Observed[len(rec.Observed)-1].Summary, "evicted") {
		t.Fatalf("observations: %+v", rec.Observed)
	}
	// Changes are allowed again.
	if res, code := r.a.Execute(context.Background(), activateReq("after-1")); code != http.StatusOK || !res.OK {
		t.Fatalf("activate after a restored drill: %d %+v", code, res)
	}
}

// A hub isolation moves the gateway to the backup hub and back.
func TestHubIsolationSwitchesToBackupAndBack(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.onBackup, r.up.normal)
	st, code := r.a.DrillStart(context.Background(), r.hubReq("drill-hub"))
	if code != http.StatusOK || st.Record.Blocked != 2 {
		t.Fatalf("start: %d %+v", code, st)
	}
	loaded := ""
	r.h.set(func() { loaded = r.h.loaded })
	if !strings.Contains(loaded, "198.51.100.7 timeout") || !strings.Contains(loaded, "2001:db8::7 timeout") || strings.Contains(loaded, "127.0.0.1") {
		t.Fatalf("block rules: %s", loaded)
	}
	st = waitDrill(t, r.a, finished)
	if st.Record.Phase != DrillRestored || st.Record.Outcome != DrillMet {
		t.Fatalf("%+v", st.Record)
	}
}

// Nothing overlaps a drill: no second drill, no install, rollback or
// withdraw; and a drill does not start while an action runs.
func TestDrillRefusesOverlap(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.evictedA, r.up.normal)
	req := r.relayReq("drill-ov")
	req.BlockSeconds = DrillMaxBlock
	if _, code := r.a.DrillStart(context.Background(), req); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	for _, action := range []string{ActionActivate, ActionRollback, ActionWithdraw} {
		res, code := r.a.Execute(context.Background(), Request{Action: action, RequestID: "ov-" + action, Resources: Resources{NFTTables: []string{"inet meridian"}}})
		if code != http.StatusConflict || !strings.Contains(res.Error, "drill-ov") {
			t.Fatalf("%s during a drill: %d %+v", action, code, res)
		}
	}
	if st, code := r.a.DrillStart(context.Background(), r.hubReq("drill-2")); code != http.StatusConflict || st.Record == nil || st.Record.ID != "drill-ov" {
		t.Fatalf("second drill: %d %+v", code, st)
	}
	// health only reads and still answers.
	if res, code := r.a.Execute(context.Background(), Request{Action: ActionHealth, RequestID: "h1"}); code != http.StatusOK || !res.OK {
		t.Fatalf("health during a drill: %d %+v", code, res)
	}
	if _, code := r.a.DrillCancel("drill-ov"); code != http.StatusOK {
		t.Fatalf("cancel: %d", code)
	}
	waitDrill(t, r.a, finished)

	// An install in flight: the drill is refused, the host untouched.
	gate := make(chan struct{})
	r.h.set(func() { r.h.hold["systemctl daemon-reload"] = gate })
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.a.Execute(context.Background(), activateReq("slow-install"))
	}()
	for r.h.ran("systemctl daemon-reload") == 0 {
		time.Sleep(time.Millisecond)
	}
	loads := r.h.ran("nft -f")
	if st, code := r.a.DrillStart(context.Background(), r.relayReq("drill-3")); code != http.StatusServiceUnavailable || st.Record != nil && st.Record.ID == "drill-3" {
		t.Fatalf("drill during an install: %d %+v", code, st)
	}
	if r.h.ran("nft -f") != loads {
		t.Fatal("a refused drill loaded rules")
	}
	close(gate)
	<-done
}

// A cancel restores at once.
func TestDrillCancelRestores(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.evictedA, r.up.normal)
	req := r.relayReq("drill-c")
	req.BlockSeconds = DrillMaxBlock
	r.a.DrillSecond = 200 * time.Millisecond // the deadline is 18 s away
	if _, code := r.a.DrillStart(context.Background(), req); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	if _, code := r.a.DrillCancel("other"); code != http.StatusNotFound {
		t.Fatalf("cancel of another id: %d", code)
	}
	started := time.Now()
	if _, code := r.a.DrillCancel("drill-c"); code != http.StatusOK {
		t.Fatalf("cancel: %d", code)
	}
	st := waitDrill(t, r.a, finished)
	if st.Record.Phase != DrillRestored || st.Record.Trigger != "cancel" || r.h.has(DrillTable) {
		t.Fatalf("%+v", st.Record)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("the cancel waited for the deadline")
	}
}

// A step of the drill itself fails: the host is restored, nothing is left.
func TestDrillActionFailureRestores(t *testing.T) {
	r := newDrillRig(t)
	r.h.set(func() { r.h.fail["nft -f"] = true })
	st, code := r.a.DrillStart(context.Background(), r.relayReq("drill-f"))
	if code != http.StatusOK || st.Running || st.Record == nil {
		t.Fatalf("start: %d %+v", code, st)
	}
	rec := st.Record
	if rec.Phase != DrillRestored || rec.Outcome != DrillFailedOp || rec.Trigger != "failure" || rec.Error == "" || st.Blocked {
		t.Fatalf("%+v", rec)
	}
	if r.h.has(DrillTable) {
		t.Fatal("table loaded")
	}
	if _, err := os.Stat(r.a.drillRulesPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rules file left: %v", err)
	}
	// The record cannot be written before the change: nothing changes.
	r2 := newDrillRig(t)
	r2.a.DrillSaveFault = func(phase string) error {
		if phase == DrillPrepared {
			return errors.New("disk full")
		}
		return nil
	}
	if st, code := r2.a.DrillStart(context.Background(), r2.relayReq("drill-g")); code != http.StatusConflict || !strings.Contains(st.Error, "宿主没有改动") || r2.h.ran("nft -f") != 0 || r2.h.ran("nft -c") != 0 {
		t.Fatalf("start without a writable record: %d %+v", code, st)
	}
}

// The agent dies mid-drill. The next process finds the record, removes the
// block and verifies the snapshot before it allows any other change.
func TestDrillCrashRestartRestoresBeforeNewChanges(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.evictedA, r.up.normal)
	req := r.relayReq("drill-k")
	req.BlockSeconds = DrillMaxBlock
	r.a.DrillSecond = time.Hour // this process never reaches its deadline: it "dies"
	if _, code := r.a.DrillStart(context.Background(), req); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	if !r.h.has(DrillTable) {
		t.Fatal("block not loaded")
	}
	t.Cleanup(func() { // end the "dead" process's goroutine
		r.a.DrillCancel("drill-k")
		waitDrill(t, r.a, finished)
	})
	// The restarted process: the removal of the table is held so the test
	// can look at the gate while the recovery runs.
	gate := make(chan struct{})
	r.h.set(func() { r.h.hold["nft delete table inet meridian_drill"] = gate })
	b := r.agent()
	b.RecoverDrills()
	st := b.DrillStatus()
	if st.Record == nil || st.Record.ID != "drill-k" || !st.Blocked || !st.Running {
		t.Fatalf("restarted agent does not know the drill: %+v", st)
	}
	if res, code := b.Execute(context.Background(), activateReq("too-early")); code != http.StatusConflict {
		t.Fatalf("activate before the recovery ended: %d %+v", code, res)
	}
	if _, code := b.DrillStart(context.Background(), r.relayReq("drill-new")); code != http.StatusConflict {
		t.Fatalf("new drill before the recovery ended: %d", code)
	}
	close(gate)
	st = waitDrill(t, b, finished)
	if st.Record.Phase != DrillRestored || st.Record.Trigger != "startup" || st.Record.Outcome != DrillAborted || r.h.has(DrillTable) {
		t.Fatalf("%+v", st.Record)
	}
	if res, code := b.Execute(context.Background(), activateReq("now")); code != http.StatusOK || !res.OK {
		t.Fatalf("activate after the recovery: %d %+v", code, res)
	}
	// A record that only says "prepared" (the process died between writing
	// it and loading the block, or right after loading) is restored too.
	r2 := newDrillRig(t)
	rec := DrillRecord{ID: "drill-p", Kind: DrillRelayIsolation, Interfaces: []string{"m02"}, Fingerprint: testFP, Phase: DrillPrepared, StartedAt: time.Now().UTC()}
	snap, err := r2.a.drillSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rec.Snapshot = snap
	raw, _ := json.Marshal(rec)
	if err := os.WriteFile(r2.a.DrillStatePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r2.h.set(func() { r2.h.tables[DrillTable] = true })
	c := r2.agent()
	c.RecoverDrills()
	if st := waitDrill(t, c, finished); st.Record.Phase != DrillRestored || r2.h.has(DrillTable) {
		t.Fatalf("%+v", st.Record)
	}
	// An unreadable record blocks: the agent cannot know what is loaded.
	r3 := newDrillRig(t)
	if err := os.WriteFile(r3.a.DrillStatePath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := r3.agent()
	if res, code := d.Execute(context.Background(), activateReq("x")); code != http.StatusConflict || !strings.Contains(res.Error, "演练记录损坏") {
		t.Fatalf("damaged record: %d %+v", code, res)
	}
	if st := d.DrillStatus(); !st.Blocked || st.Error == "" {
		t.Fatalf("%+v", st)
	}
}

// The block cannot be removed: never "restored". The failure is on disk,
// lists what is left, blocks every change across restarts, cannot be
// released while the block is there, and a retry that works ends it.
func TestDrillRestoreFailurePersistsBlocksAndRetries(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.evictedA, r.up.normal)
	r.h.set(func() { r.h.fail["nft delete table inet meridian_drill"] = true })
	if _, code := r.a.DrillStart(context.Background(), r.relayReq("drill-r")); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	st := waitDrill(t, r.a, finished)
	rec := st.Record
	if rec.Phase != DrillRestoreFailed || !st.Blocked || rec.OwnChangeCleared || len(rec.Residual) == 0 || !strings.Contains(rec.Residual[0], DrillTable) {
		t.Fatalf("%+v", rec)
	}
	if r.h.ran("systemctl restart") != 0 {
		t.Fatal("re-activated the data plane under a block that may still be loaded")
	}
	disk, _ := os.ReadFile(r.a.DrillStatePath)
	if !strings.Contains(string(disk), `"phase": "restore_failed"`) {
		t.Fatalf("failure not on disk: %s", disk)
	}
	for _, a := range []*Agent{r.a, r.agent()} { // this process and a restarted one
		if res, code := a.Execute(context.Background(), activateReq("blocked")); code != http.StatusConflict || !strings.Contains(res.Error, "重试恢复") {
			t.Fatalf("activate with an unverified restore: %d %+v", code, res)
		}
		if _, code := a.DrillStart(context.Background(), r.hubReq("drill-next")); code != http.StatusConflict {
			t.Fatalf("new drill with an unverified restore: %d", code)
		}
		if st, code := a.DrillRelease(context.Background(), "drill-r"); code != http.StatusConflict || st.Record.Phase != DrillRestoreFailed {
			t.Fatalf("released with the block loaded: %d %+v", code, st.Record)
		}
		if st := a.DrillStatus(); st.Running || st.Record.Phase != DrillRestoreFailed {
			t.Fatalf("a restart must not restore a failed one by itself, nor forget it: %+v", st)
		}
	}
	// Retry while it still fails: still failed.
	if st, code := r.a.DrillRetry("drill-r"); code != http.StatusOK || st.Record.Phase != DrillRestoreFailed || st.Record.Attempts != 2 {
		t.Fatalf("retry: %d %+v", code, st.Record)
	}
	r.h.set(func() { delete(r.h.fail, "nft delete table inet meridian_drill") })
	st, code := r.a.DrillRetry("drill-r")
	if code != http.StatusOK || st.Record.Phase != DrillRestored || st.Blocked || len(st.Record.Residual) != 0 || st.Record.Trigger != "retry" {
		t.Fatalf("retry after the fault cleared: %d %+v", code, st.Record)
	}
	if r.h.has(DrillTable) {
		t.Fatal("table still loaded")
	}
	if _, code := r.a.DrillRetry("drill-r"); code != http.StatusConflict {
		t.Fatalf("retry of a restored drill: %d", code)
	}
}

// The block is gone and the data plane is healthy, but the gateway stays
// on the backup hub. Health is not the criterion: the data plane is
// re-activated, compared again, and when it still differs the record says
// so and blocks. Releasing it is possible (the block is verified gone) and
// is recorded as released, not restored.
func TestDrillHealthyButNotSnapshotIsNotRestored(t *testing.T) {
	r := newDrillRig(t)
	r.loop(r.up.onBackup, func(testing.TB) {}) // the loop never returns
	if _, code := r.a.DrillStart(context.Background(), r.hubReq("drill-h")); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	st := waitDrill(t, r.a, finished)
	rec := st.Record
	if rec.Phase != DrillRestoreFailed || !rec.OwnChangeCleared || !rec.Reactivated || rec.Outcome != DrillMet {
		t.Fatalf("%+v", rec)
	}
	if r.h.ran("systemctl restart meridian.service") != 1 {
		t.Fatalf("the fallback did not re-activate exactly once: %d", r.h.ran("systemctl restart meridian.service"))
	}
	joined := strings.Join(rec.Residual, "\n")
	if !strings.Contains(joined, "承载路径") || !strings.Contains(joined, "中继 relay-a") {
		t.Fatalf("residual does not name what differs: %q", joined)
	}
	if res, code := r.a.Execute(context.Background(), activateReq("blocked")); code != http.StatusConflict {
		t.Fatalf("%d %+v", code, res)
	}
	st, code := r.a.DrillRelease(context.Background(), "drill-h")
	if code != http.StatusOK || st.Record.Phase != DrillReleased || st.Blocked || len(st.Record.Residual) == 0 {
		t.Fatalf("release: %d %+v", code, st.Record)
	}
	if res, code := r.a.Execute(context.Background(), activateReq("after-release")); code != http.StatusOK || !res.OK {
		t.Fatalf("%d %+v", code, res)
	}
	// The same, but the re-activation brings the paths back: restored,
	// and the record says the data plane was re-activated.
	r2 := newDrillRig(t)
	r2.loop(r2.up.onBackup, func(testing.TB) {})
	r2.h.set(func() { r2.h.onRestart = func(*drillHost) { r2.up.normal(t) } })
	if _, code := r2.a.DrillStart(context.Background(), r2.hubReq("drill-i")); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	st = waitDrill(t, r2.a, finished)
	if st.Record.Phase != DrillRestored || !st.Record.Reactivated || len(st.Record.Residual) != 0 {
		t.Fatalf("%+v", st.Record)
	}
}

// Every other difference from the snapshot is found: a link that went
// away, changed rules, a changed route table.
func TestDrillDiffNamesWhatDiffers(t *testing.T) {
	r := newDrillRig(t)
	before, err := r.a.drillSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := drillDiff(before, before); len(d) != 0 {
		t.Fatalf("equal snapshots differ: %v", d)
	}
	r.h.set(func() {
		delete(r.h.links, "m03")
		r.h.rules["inet meridian"] += "# changed\n"
		r.h.ipRules["-6"] = ""
		r.h.routes["102/-4"] = "default dev m04w\n"
		r.h.tables[DrillTable] = true
	})
	now, err := r.a.drillSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(drillDiff(before, now), "\n")
	for _, want := range []string{"nft 表不同", "inet meridian 的规则", "IPv6 策略规则", "路由表 102（IPv4）", "接口 m03：演练前 up，现在 absent"} {
		if !strings.Contains(got, want) {
			t.Fatalf("diff lacks %q:\n%s", want, got)
		}
	}
	// A measured "ok" restores an install's "static"; nothing else does.
	if !stateEquals(UpstreamStatic, UpstreamOK) || stateEquals(UpstreamOK, UpstreamStatic) || stateEquals(UpstreamOK, UpstreamDown) {
		t.Fatal("state comparison")
	}
}

// Preconditions are checked on the host's own state, and a refusal leaves
// the host untouched and no record behind.
func TestDrillPreconditions(t *testing.T) {
	cases := []struct {
		name string
		prep func(r *drillRig)
		req  func(r *drillRig) DrillRequest
		want string
	}{
		{"no upstream record", func(r *drillRig) { os.Remove(r.up.path()) }, (*drillRig).relayReqD, "没有可读的上游记录"},
		{"stale heartbeat", func(r *drillRig) {
			r.up.beatAgo = 600
			r.up.normal(r.t)
		}, (*drillRig).relayReqD, "心跳"},
		{"already on backup", func(r *drillRig) { r.up.onBackup(r.t) }, (*drillRig).hubReqD, "不在主链路上"},
		{"state not ok", func(r *drillRig) {
			r.up.write(r.t, "main", "m02", "hub-a", "primary", "degraded", relayLine("relay-a", "m02", "active", 500), relayLine("relay-b", "m03", "active", 500))
		}, (*drillRig).relayReqD, "不是 ok"},
		{"no other relay carrying", func(r *drillRig) {
			r.up.write(r.t, "main", "m02", "hub-a", "primary", "ok", relayLine("relay-a", "m02", "active", 1000), relayLine("relay-b", "m03", "evicted", 0))
		}, (*drillRig).relayReqD, "没有另一个在分担的中继"},
		{"target not a relay of the record", nil, func(r *drillRig) DrillRequest {
			q := r.relayReq("d")
			q.Interfaces = []string{"m04w"}
			return q
		}, "不是上游记录里任何中继的隧道"},
		{"interface not in the ledger", nil, func(r *drillRig) DrillRequest {
			q := r.relayReq("d")
			q.Interfaces = []string{"m09"}
			return q
		}, "不在宿主的受管清单里"},
		{"hub targets are not all relays", nil, func(r *drillRig) DrillRequest {
			q := r.hubReq("d")
			q.Interfaces = []string{"m02"}
			return q
		}, "全部中继隧道"},
		{"backup hub down", func(r *drillRig) {
			b, _ := os.ReadFile(r.up.path())
			os.WriteFile(r.up.path(), []byte(strings.Replace(string(b), "backup hub-b m04w good", "backup hub-b m04w down", 1)), 0o644)
		}, (*drillRig).hubReqD, "备用枢纽现在的质量是 down"},
		{"endpoint on loopback (WSS)", func(r *drillRig) {
			r.h.set(func() { r.h.endpoints["m02"] = keyA + "\t127.0.0.1:4000\n" })
		}, (*drillRig).relayReqD, "没有可隔离的公网端点"},
		{"data plane not running", func(r *drillRig) { r.h.set(func() { r.h.core = "inactive" }) }, (*drillRig).relayReqD, "没有在运行"},
		{"guard table missing", func(r *drillRig) { r.h.set(func() { delete(r.h.tables, GuardTable) }) }, (*drillRig).reloadReqD, "没有加载"},
		{"leftover block table", func(r *drillRig) { r.h.set(func() { r.h.tables[DrillTable] = true }) }, (*drillRig).reloadReqD, "残留"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newDrillRig(t)
			if c.prep != nil {
				c.prep(r)
			}
			st, code := r.a.DrillStart(context.Background(), c.req(r))
			if code != http.StatusConflict || !strings.Contains(st.Error, c.want) || st.Record != nil || st.Blocked {
				t.Fatalf("%d %+v", code, st)
			}
			if r.h.ran("nft -f") != 0 || r.h.ran("nft -c") != 0 || r.h.ran("systemctl restart") != 0 || r.h.ran("nft delete") != 0 {
				t.Fatalf("a refused drill changed the host: %v", r.h.cmds)
			}
			if _, err := os.Stat(r.a.DrillStatePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused drill left a record: %v", err)
			}
			if res, code := r.a.Execute(context.Background(), Request{Action: ActionHealth, RequestID: "h"}); code != http.StatusOK || !res.OK {
				t.Fatalf("agent not free after a refusal: %d", code)
			}
		})
	}
}

func (r *drillRig) relayReqD() DrillRequest { return r.relayReq("d") }
func (r *drillRig) hubReqD() DrillRequest   { return r.hubReq("d") }
func (r *drillRig) reloadReqD() DrillRequest {
	return DrillRequest{RequestID: "d", Kind: DrillFirewallReload, Fingerprint: testFP}
}

// A single-relay record (version 1): a relay isolation is refused, a hub
// isolation needs a fresh handshake on the backup tunnel.
func TestDrillSingleRelayRecord(t *testing.T) {
	r := newDrillRig(t)
	v1 := func() {
		now := time.Now().Unix()
		s := fmt.Sprintf("meridian-upstream 1\nbeat %d\npath udp\niface m02\nhub hub-a\ntier primary\nsince %d\nstate ok\nend\n", now, now-50)
		if err := os.WriteFile(r.up.path(), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	v1()
	if st, code := r.a.DrillStart(context.Background(), r.relayReq("d")); code != http.StatusConflict || !strings.Contains(st.Error, "只有一个中继") {
		t.Fatalf("%d %+v", code, st)
	}
	hub := r.hubReq("d")
	hub.Interfaces = []string{"m02"}
	r.h.set(func() { r.h.shakes["m04w"] = fmt.Sprintf("%s\t%d\n", keyA, time.Now().Unix()-3600) })
	if st, code := r.a.DrillStart(context.Background(), hub); code != http.StatusConflict || !strings.Contains(st.Error, "没有握手") {
		t.Fatalf("stale backup: %d %+v", code, st)
	}
	r.h.set(func() {
		r.h.shakes["m04w"] = fmt.Sprintf("%s\t%d\n", keyA, time.Now().Unix()-10)
		r.h.onBlock = func() {
			now := time.Now().Unix()
			os.WriteFile(r.up.path(), []byte(fmt.Sprintf("meridian-upstream 1\nbeat %d\npath backup\niface m04w\nhub hub-b\ntier backup\nsince %d\nstate ok\nend\n", now, now)), 0o644)
		}
		r.h.onUnblock = v1
	})
	if _, code := r.a.DrillStart(context.Background(), hub); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	if st := waitDrill(t, r.a, finished); st.Record.Phase != DrillRestored || st.Record.Outcome != DrillMet {
		t.Fatalf("%+v", st.Record)
	}
}

// The reload drill restarts meridian.service, samples the tables while it
// runs, and says what such a sample cannot see.
func TestFirewallReloadDrill(t *testing.T) {
	r := newDrillRig(t)
	r.h.set(func() {
		r.h.onRestart = func(h *drillHost) {
			// meridian-up.sh replaces the main table; the guard stays.
			h.set(func() { delete(h.tables, "inet meridian") })
			h.awaitSamples(2)
			h.set(func() { h.tables["inet meridian"] = true })
		}
	})
	st, code := r.a.DrillStart(context.Background(), r.reloadReqD())
	if code != http.StatusOK {
		t.Fatalf("start: %d %+v", code, st)
	}
	st = waitDrill(t, r.a, finished)
	rec := st.Record
	if rec.Phase != DrillRestored || rec.Outcome != DrillMet || r.h.ran("systemctl restart meridian.service") != 1 || r.h.ran("nft -f") != 0 {
		b, _ := json.MarshalIndent(rec, "", " ")
		t.Fatalf("%s", b)
	}
	if got := strings.Join(rec.Findings, "\n"); !strings.Contains(got, "看不到客户端的包") || !strings.Contains(got, "兜底表不在 0 次") {
		t.Fatalf("findings: %s", got)
	}

	// The guard disappears during the reload: the drill says so.
	r2 := newDrillRig(t)
	r2.h.set(func() {
		r2.h.onRestart = func(h *drillHost) {
			h.set(func() { delete(h.tables, "inet meridian"); delete(h.tables, GuardTable) })
			h.awaitSamples(2) // the drill must see the gap, however starved its sampler is
			h.set(func() { h.tables["inet meridian"] = true; h.tables[GuardTable] = true })
		}
	})
	if _, code := r2.a.DrillStart(context.Background(), r2.reloadReqD()); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	if st := waitDrill(t, r2.a, finished); st.Record.Outcome != DrillNotMet || st.Record.Phase != DrillRestored {
		t.Fatalf("%+v", st.Record)
	}

	// The restart fails but nothing differs from the snapshot afterwards:
	// the drill failed, the host is verified as before.
	r3 := newDrillRig(t)
	r3.h.set(func() { r3.h.fail["systemctl restart meridian.service"] = true })
	if _, code := r3.a.DrillStart(context.Background(), r3.reloadReqD()); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	st = waitDrill(t, r3.a, finished)
	if st.Record.Outcome != DrillFailedOp || st.Record.Trigger != "failure" || st.Record.Phase != DrillRestored {
		t.Fatalf("%+v", st.Record)
	}
	// The restart fails and takes the main table down; the re-activation
	// of the restore fails the same way: not restored, blocked, and the
	// record says which table is missing.
	r4 := newDrillRig(t)
	r4.h.set(func() { r4.h.restartBreaks = true })
	if _, code := r4.a.DrillStart(context.Background(), r4.reloadReqD()); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	st = waitDrill(t, r4.a, finished)
	if st.Record.Phase != DrillRestoreFailed || !st.Blocked || !strings.Contains(strings.Join(st.Record.Residual, "\n"), "nft 表不同") || !st.Record.Reactivated {
		t.Fatalf("%+v", st.Record)
	}
	// Once the table is back (an operator fixed the cause), a retry verifies.
	r4.h.set(func() { r4.h.restartBreaks = false; r4.h.tables["inet meridian"] = true })
	if st, code := r4.a.DrillRetry("d"); code != http.StatusOK || st.Record.Phase != DrillRestored {
		t.Fatalf("retry: %d %+v", code, st.Record)
	}
}

// The path check reads managed interfaces only and returns no key.
func TestPathCheck(t *testing.T) {
	r := newDrillRig(t)
	res, code := r.a.PathCheck(context.Background(), PathCheckRequest{RequestID: "p1", Interfaces: []string{"m02", "m04w"}})
	if code != http.StatusOK || len(res.Links) != 2 {
		t.Fatalf("%d %+v", code, res)
	}
	l := res.Links[0]
	if l.State != "up" || !l.WireGuard || l.Peers != 1 || l.HandshakeAgeS == nil || *l.HandshakeAgeS < 19 || *l.HandshakeAgeS > 25 || l.RxBytes != 1000 || l.TxBytes != 2000 {
		t.Fatalf("%+v", l)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), keyA) || strings.Contains(string(raw), "198.51.100") {
		t.Fatalf("the answer carries a key or an address: %s", raw)
	}
	before := r.h.ran("")
	if res, code := r.a.PathCheck(context.Background(), PathCheckRequest{RequestID: "p2", Interfaces: []string{"m02", "m77"}}); code != http.StatusForbidden || len(res.Links) != 0 {
		t.Fatalf("unmanaged interface: %d %+v", code, res)
	}
	if r.h.ran("") != before {
		t.Fatal("a refused path check read something")
	}
	if r.h.ran("wg show m02 dump") != 0 || r.h.ran("wg showconf") != 0 {
		t.Fatal("a command that prints keys was run")
	}
	// A link that is gone, and one that never shook hands.
	r.h.set(func() { delete(r.h.links, "m03"); r.h.shakes["m02"] = keyA + "\t0\n" })
	res, _ = r.a.PathCheck(context.Background(), PathCheckRequest{RequestID: "p3", Interfaces: []string{"m02", "m03"}})
	if res.Links[0].HandshakeAgeS != nil || res.Links[1].State != "absent" {
		t.Fatalf("%+v", res.Links)
	}
}

func TestParseEndpointsAndBlockable(t *testing.T) {
	eps, err := parseEndpoints(keyA + "\t198.51.100.7:51820\n" + keyB + "\t(none)\n")
	if err != nil || len(eps) != 1 || eps[0].String() != "198.51.100.7" {
		t.Fatalf("%v %v", eps, err)
	}
	for _, bad := range []string{"not-a-key\t198.51.100.7:1\n", keyA + "\texample.com:51820\n", keyA + "\t198.51.100.7\n", keyA + " 198.51.100.7:1 extra\n"} {
		if _, err := parseEndpoints(bad); err == nil {
			t.Fatalf("parsed %q", bad)
		}
	}
	for ad, want := range map[string]bool{
		"198.51.100.7": true, "2001:db8::7": true, "192.0.2.9": true,
		"127.0.0.1": false, "::1": false, "0.0.0.0": false, "169.254.1.1": false, "fe80::1": false, "224.0.0.1": false,
		"10.66.0.1": false, "fd66::1": false,
	} {
		eps, err := parseEndpoints(keyA + "\t" + hostPort(ad) + "\n")
		if err != nil {
			t.Fatal(err)
		}
		if blockable(eps[0]) != want {
			t.Fatalf("blockable(%s) != %v", ad, want)
		}
	}
	rules := drillRules(eps, 35)
	if !strings.HasPrefix(strings.SplitN(rules, "\n", 2)[1], "table inet meridian_drill {") || !strings.Contains(rules, "flags timeout") || !strings.Contains(rules, "policy accept") {
		t.Fatalf("%s", rules)
	}
}

func hostPort(ad string) string {
	if strings.Contains(ad, ":") {
		return "[" + ad + "]:51820"
	}
	return ad + ":51820"
}

// Relay weights move with the quality controller: a restore compares the
// path, hub and each relay's status, never the weights (they are only
// noted). An isolated relay that is still evicted is not restored.
func TestDrillDiffIgnoresWeightsButNotRelayStatus(t *testing.T) {
	snap := func(st1 string, w1, w2 int) DrillSnapshot {
		return DrillSnapshot{Upstream: &DrillUpstream{Path: "main", Iface: "m01", Hub: "ix", State: UpstreamOK, Relays: []DrillRelayState{
			{ID: "r1", Iface: "m01", Status: st1, Weight: w1}, {ID: "r2", Iface: "m02", Status: "active", Weight: w2},
		}}}
	}
	before := snap("active", 474, 526)
	after := snap("active", 487, 513)
	if d := drillDiff(before, after); len(d) != 0 {
		t.Fatalf("weights alone made a difference: %v", d)
	}
	notes := strings.Join(drillWeightNotes(before, after), "\n")
	if !strings.Contains(notes, "474") || !strings.Contains(notes, "487") {
		t.Fatalf("weights not noted: %q", notes)
	}
	if d := strings.Join(drillDiff(before, snap("evicted", 0, 1000)), "\n"); !strings.Contains(d, "中继 r1：演练前 active，现在 evicted") {
		t.Fatalf("evicted relay not a difference: %q", d)
	}
	// Still ramping (recovering) or capped (reduced) is not back to the
	// pre-drill active: a difference, and noted while waiting.
	for _, st := range []string{"recovering", "reduced"} {
		if d := strings.Join(drillDiff(before, snap(st, 120, 880)), "\n"); !strings.Contains(d, "中继 r1：演练前 active，现在 "+st) {
			t.Fatalf("%s relay counted as restored: %q", st, d)
		}
		if n := strings.Join(drillWeightNotes(before, snap(st, 120, 880)), "\n"); !strings.Contains(n, "现在 "+st) {
			t.Fatalf("%s not noted: %q", st, n)
		}
	}
	// Back to active (at other weights) passes.
	if d := drillDiff(before, snap("active", 120, 880)); len(d) != 0 {
		t.Fatalf("relay back to active not restored: %v", d)
	}
	for _, st := range []string{"standby", "disabled"} {
		if d := drillDiff(before, snap(st, 0, 1000)); len(d) == 0 {
			t.Fatalf("%s relay is not a difference", st)
		}
	}
	// The verify wait covers the loop's own recovery with margin.
	if DrillVerifyWait < DrillRecoverPasses*DrillLoopInterval+DrillCooldown+60 || DrillVerifyWait < 300 {
		t.Fatalf("DrillVerifyWait %d too short for the loop's recovery", DrillVerifyWait)
	}
}

// shareRules is table inet meridian with the relay-sharing map at weights
// (compile/share.go prints it like this); 0 drops a relay from the map.
func shareRules(wa, wb int) string {
	var parts []string
	lo := 0
	for i, w := range []int{wa, wb} {
		if w > 0 {
			parts = append(parts, fmt.Sprintf("%d-%d : 0x%08x", lo, lo+w-1, 0x101+i))
			lo += w
		}
	}
	m := "map { " + strings.Join(parts, ", ") + " }"
	return "table inet meridian {\n\tchain relay_assign {\n\t\tmeta nfproto ipv4 ct mark set jhash ip saddr . ip daddr . th sport . th dport mod 1000 seed 0x4d52 " + m +
		"\n\t\tmeta nfproto ipv6 ct mark set jhash ip6 saddr . ip6 daddr . th sport . th dport mod 1000 seed 0x4d52 " + m + "\n\t}\n}\n"
}

// The weights also live in the nft rules (the relay-sharing map): a rules
// digest must not change with them, but must with which relays carry.
func TestNormShareMapsIgnoresWeightsOnly(t *testing.T) {
	d := func(s string) string { return digest(normShareMaps(normText(s))) }
	if d(shareRules(474, 526)) != d(shareRules(487, 513)) {
		t.Fatal("weights changed the rules digest")
	}
	if d(shareRules(474, 526)) == d(shareRules(0, 1000)) {
		t.Fatal("a relay dropped from the map is not a difference")
	}
	if d(shareRules(500, 500)) == d(strings.Replace(shareRules(500, 500), "0x00000102", "0x00000103", 2)) {
		t.Fatal("a different mark is not a difference")
	}
	other := "table inet meridian {\n\tchain c {\n\t\tmeta l4proto vmap { tcp : jump a, udp : jump b }\n\t}\n}"
	if normShareMaps(other) != other {
		t.Fatalf("a map that is not a weight map was changed: %s", normShareMaps(other))
	}
}

// Real gateway: the isolated relay comes back, but with other weights
// (474/526 before, 487/513 after) — in the record and in the nft map. That
// is restored, with no re-activation; the weights are only noted.
func TestRelayIsolationRestoredWithOtherWeights(t *testing.T) {
	r := newDrillRig(t)
	r.h.set(func() { r.h.rules["inet meridian"] = shareRules(474, 526) })
	r.up.write(t, "main", "m02", "hub-a", "primary", "ok", relayLine("relay-a", "m02", "active", 474), relayLine("relay-b", "m03", "active", 526))
	r.loop(func(tb testing.TB) {
		r.h.set(func() { r.h.rules["inet meridian"] = shareRules(0, 1000) })
		r.up.evictedA(tb)
	}, func(tb testing.TB) {
		r.h.set(func() { r.h.rules["inet meridian"] = shareRules(487, 513) })
		r.up.write(tb, "main", "m02", "hub-a", "primary", "ok", relayLine("relay-a", "m02", "active", 487), relayLine("relay-b", "m03", "active", 513))
	})
	if _, code := r.a.DrillStart(context.Background(), r.relayReq("drill-w")); code != http.StatusOK {
		t.Fatalf("start: %d", code)
	}
	rec := waitDrill(t, r.a, finished).Record
	if rec.Phase != DrillRestored || rec.Reactivated || len(rec.Residual) != 0 || r.h.ran("systemctl restart") != 0 {
		b, _ := json.MarshalIndent(rec, "", " ")
		t.Fatalf("weights made the restore fail or re-activate:\n%s", b)
	}
	if f := strings.Join(rec.Findings, "\n"); !strings.Contains(f, "474") || !strings.Contains(f, "487") {
		t.Fatalf("weights not noted: %q", f)
	}
}

// A retry or a restore after a failed change waits out the loop's own
// recovery window before it may re-activate; outside it, DrillRetryWait.
func TestDrillRecoveryWait(t *testing.T) {
	a := &Agent{DrillSecond: time.Millisecond}
	sec := time.Millisecond
	full, short := time.Duration(DrillVerifyWait)*sec, time.Duration(DrillRetryWait)*sec
	now := time.Now()
	changed := now.Add(-time.Second)
	cases := []struct {
		name   string
		rec    DrillRecord
		lo, hi time.Duration
	}{
		{"never active", DrillRecord{StartedAt: now, Deadline: now.Add(time.Hour)}, full - 50*sec, full},
		{"block cut short", DrillRecord{StartedAt: now, ChangedAt: &changed, Deadline: now.Add(time.Hour)}, full - 50*sec, full},
		{"inside the window", DrillRecord{StartedAt: now.Add(-time.Hour), ChangedAt: &changed, Deadline: now.Add(-100 * sec)}, full - 150*sec, full - 50*sec},
		{"window over", DrillRecord{StartedAt: now.Add(-time.Hour), ChangedAt: &changed, Deadline: now.Add(-time.Hour)}, short, short},
	}
	for _, c := range cases {
		if w := a.drillRecoveryWait(&c.rec); w < c.lo || w > c.hi {
			t.Errorf("%s: wait %v, want %v..%v", c.name, w, c.lo, c.hi)
		}
	}
}

func TestDrillDiffRetainedReasonIsAState(t *testing.T) {
	snap := func(reason string) DrillSnapshot {
		return DrillSnapshot{Upstream: &DrillUpstream{Path: "main", Iface: "m01", Hub: "ix", State: UpstreamOK, Relays: []DrillRelayState{
			{ID: "r1", Iface: "m01", Status: "reduced", Reason: reason, Weight: 1000}, {ID: "r2", Iface: "m02", Status: "evicted", Reason: "poor_loss"},
		}}}
	}
	if d := drillDiff(snap("mild_rtt"), snap("mild_loss")); len(d) != 0 {
		t.Fatalf("ordinary reduced reasons should compare by status only: %v", d)
	}
	if d := strings.Join(drillDiff(snap("mild_rtt"), snap("retained_best")), "\n"); !strings.Contains(d, "现在 reduced/retained_best") {
		t.Fatalf("retained relay counted as restored: %q", d)
	}
}
