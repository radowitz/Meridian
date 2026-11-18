package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sniff"
)

// serveSniff answers the forwarder's status socket for the sim host while
// its forwarder runs: /v1/health reports the target file on the host,
// POST /v1/selfcheck a result for it as sn.check says. Without a running
// forwarder the socket is gone, like the real one.
func (h *simHost) serveSniff(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "msnr")
	if err != nil {
		t.Fatal(err)
	}
	h.sniffSock = filepath.Join(dir, "status.sock")
	l, err := net.Listen("unix", h.sniffSock)
	if err != nil {
		t.Fatal(err)
	}
	targetsSHA := func() string {
		b, err := os.ReadFile(filepath.Join(h.root, compile.SniffTargetsPath))
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	running := func(w http.ResponseWriter) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.sn.unit != "active" {
			// The real socket does not exist then; a connection refused.
			hj, ok := w.(http.Hijacker)
			if ok {
				if c, _, err := hj.Hijack(); err == nil {
					c.Close()
				}
			}
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if running(w) {
			_ = json.NewEncoder(w).Encode(sniff.Health{Ready: true, Generation: 1, TargetsSHA256: targetsSHA()})
		}
	})
	mux.HandleFunc("/v1/selfcheck", func(w http.ResponseWriter, r *http.Request) {
		if !running(w) {
			return
		}
		h.mu.Lock()
		mode := h.sn.check
		h.sn.checks++
		h.mu.Unlock()
		if mode == "refuse" {
			http.Error(w, "self-check not run", http.StatusServiceUnavailable)
			return
		}
		sha := targetsSHA()
		if mode == "stale" {
			sha = strings.Repeat("0", 64)
		}
		now := time.Now()
		res := sniff.SelfCheck{Version: sniff.SelfCheckVersion, Trigger: sniff.TriggerRequest, StartedAt: now, FinishedAt: now.Add(30 * time.Millisecond),
			DurationMS: 30, Generation: 1, TargetsSHA256: sha, QName: ".", QType: "NS", Default: "group:hk", OK: mode != "default",
			Targets: []sniff.SelfCheckTarget{
				{Target: "group:hk", Default: true, Status: sniff.TargetOK, Resolvers: []sniff.SelfCheckProbe{{Server: "[fd66::53:1]:53", Outcome: sniff.OutcomeAnswer, Reached: true}},
					Connect: &sniff.SelfCheckProbe{Server: "[fd66::53:1]:53", Outcome: sniff.OutcomeConnected, Reached: true}},
				{Target: "group:jp", Status: sniff.TargetOK, Resolvers: []sniff.SelfCheckProbe{{Server: "[fd66::53:2]:53", Outcome: sniff.OutcomeNXDomain, Reached: true}}},
				{Target: "direct", Status: sniff.TargetOK, Resolvers: []sniff.SelfCheckProbe{{Server: "192.0.2.53:53", Outcome: sniff.OutcomeAnswer, Reached: true}}},
			}}
		switch mode {
		case "default":
			res.Targets[0].Status, res.Targets[0].Reason = sniff.TargetFailed, "解析器 [fd66::53:1]:53 超时，没有任何回应"
			res.Targets[0].Resolvers[0] = sniff.SelfCheckProbe{Server: "[fd66::53:1]:53", Outcome: sniff.OutcomeTimeout}
		case "slow": // the default's resolver answered too late, its TCP port opened
			w := "解析器 [fd66::53:1]:53 没有按时回答，但 TCP 53 可以连通（路径可用，解析器慢）"
			res.Targets[0].Warning = w
			res.Targets[0].Resolvers[0] = sniff.SelfCheckProbe{Server: "[fd66::53:1]:53", Outcome: sniff.OutcomeSlow}
			res.Targets[1].Warning = w
			res.Targets[1].Resolvers[0] = sniff.SelfCheckProbe{Server: "[fd66::53:2]:53", Outcome: sniff.OutcomeSlow}
		case "other":
			res.Targets[1].Status, res.Targets[1].Reason = sniff.TargetFailed, "解析器 [fd66::53:2]:53 超时，没有任何回应"
			res.Targets[1].Resolvers[0] = sniff.SelfCheckProbe{Server: "[fd66::53:2]:53", Outcome: sniff.OutcomeTimeout}
		}
		_ = json.NewEncoder(w).Encode(res)
	})
	srv := &http.Server{Handler: mux}
	done := make(chan struct{})
	go func() { _ = srv.Serve(l); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done; os.RemoveAll(dir) })
}

func TestSniffNamesMatchCompile(t *testing.T) {
	if hostexec.SniffUnit != compile.SniffUnit || hostexec.SniffSocket != compile.SniffStatusSocket || hostexec.SniffAccountUnit != compile.SniffAccountUnit {
		t.Fatal("hostexec and compile disagree on the forwarder's units or socket")
	}
}

// sniffSim models what systemd does with the forwarder's two units
// (compile.RenderSniffUnit / RenderSniffAccountUnit), as verified on a real
// host: starting the forwarder first starts its account unit (Requires=,
// After=), whose ExecStart adds the account; a refused add fails the
// account unit and the forwarder's start ("dependency failed"); the
// forwarder's ExecStartPre turns tcp_fwmark_accept on, its ExecStopPost
// off (also after a failed start); stopping the account unit stops the
// forwarder first (Requires= propagates) and its ExecStop removes the
// account. StopWhenUnneeded is asynchronous in systemd: the model never
// stops the account unit by itself, so only the agent's explicit stop
// removes the account here.
type sniffSim struct {
	account     bool   // the account exists in the user database
	accountUnit string // "active", "failed" or "" (inactive)
	unit        string // the forwarder: "active", "failed" or ""
	fwmark      string // net.ipv4.tcp_fwmark_accept
	conflict    bool   // the account script refuses (name or id taken)
	startFails  bool   // the forwarder's start fails (unit present but failing)
	adds, dels  int
	reloads     int
	starts      int
	// check is how the running forwarder's self-check turns out (serveSniff):
	// "" every target ok, "default" the default target fails, "other" another
	// target fails, "refuse" the request is refused, "stale" a result for
	// another rule pair; checks counts the requests.
	check  string
	checks int
}

func (h *simHost) sniffCmd(prog string, args []string, unitFile func(string) bool) (string, bool, error) {
	if prog != "systemctl" || len(args) < 2 {
		return "", false, nil
	}
	target := args[len(args)-1]
	isSniff := func(u string) bool { return u == compile.SniffUnit || u == compile.SniffAccountUnit }
	if !isSniff(target) && !(args[0] == "reset-failed" && isSniff(args[1])) {
		return "", false, nil
	}
	sn := &h.sn
	state := func(u string) *string {
		if u == compile.SniffUnit {
			return &sn.unit
		}
		return &sn.accountUnit
	}
	sync := func() {
		h.units[compile.SniffUnit] = sn.unit == "active"
		if sn.unit != "active" {
			delete(h.units, compile.SniffUnit)
		}
	}
	defer sync()
	startAccount := func() error {
		if sn.accountUnit == "active" {
			return nil
		}
		if !unitFile(compile.SniffAccountUnit) {
			return errors.New("Unit " + compile.SniffAccountUnit + " not found.")
		}
		if sn.conflict {
			sn.accountUnit = "failed"
			return errors.New("meridian-sniff-user-conflict")
		}
		sn.account, sn.accountUnit = true, "active"
		sn.adds++
		return nil
	}
	stopUnit := func() {
		if sn.unit == "active" {
			sn.unit, sn.fwmark = "", "0"
		}
	}
	start := func() error {
		if !unitFile(compile.SniffUnit) {
			return errors.New("Unit " + compile.SniffUnit + " not found.")
		}
		if err := startAccount(); err != nil {
			return errors.New("A dependency job for " + compile.SniffUnit + " failed")
		}
		sn.starts++
		if sn.startFails {
			sn.unit, sn.fwmark = "failed", "0"
			return errors.New("Job for " + compile.SniffUnit + " failed because the control process exited with error code")
		}
		sn.unit, sn.fwmark = "active", "1"
		return nil
	}
	switch args[0] {
	case "cat":
		if unitFile(target) {
			return "[Unit]", true, nil
		}
		return "", true, errors.New("No files found")
	case "enable":
		if target == compile.SniffAccountUnit {
			return "", true, errors.New("the account unit is never enabled")
		}
		h.enabled[target] = true
		return "", true, nil
	case "is-enabled":
		if !h.enabled[target] {
			return "disabled", true, errors.New("exit status 1")
		}
		return "enabled", true, nil
	case "is-active":
		if *state(target) == "active" {
			return "active", true, nil
		}
		st := *state(target)
		if st == "" {
			st = "inactive"
		}
		return st, true, errors.New("exit status 3")
	case "is-failed":
		if *state(target) == "failed" {
			return "failed", true, nil
		}
		return "", true, errors.New("exit status 1")
	case "reset-failed":
		for _, u := range args[1:] {
			if *state(u) == "failed" {
				*state(u) = ""
			}
		}
		return "", true, nil
	case "start":
		if target == compile.SniffAccountUnit {
			return "", true, startAccount()
		}
		return "", true, start()
	case "reload-or-restart":
		if sn.unit == "active" {
			sn.reloads++
			return "", true, nil
		}
		return "", true, start()
	case "stop":
		if target == compile.SniffUnit {
			stopUnit()
			return "", true, nil
		}
		stopUnit() // Requires= propagates the stop
		if sn.accountUnit == "active" {
			sn.account, sn.accountUnit = false, ""
			sn.dels++
		}
		return "", true, nil
	case "disable":
		if target == compile.SniffAccountUnit {
			return "", true, errors.New("the account unit is never disabled")
		}
		delete(h.enabled, target)
		if len(args) > 2 && args[1] == "--now" {
			stopUnit()
		}
		return "", true, nil
	}
	// restart, try-reload-or-restart, ... are not part of the fixed order.
	return "", true, errors.New("unexpected: systemctl " + strings.Join(args, " "))
}

func sniffTopo(on bool, rule string) model.Topology {
	topo := defaults.Example()
	if on {
		topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
	}
	if rule != "" {
		topo.Rules = append(topo.Rules, model.Rule{ID: "sn-x", Name: "x", Enabled: true, MatchType: model.MatchSuffix, MatchValue: rule, TargetGroup: "jp", Priority: 1})
	}
	return topo
}

// The account unit is a managed file, never a manifest unit (the agent
// starts and stops it only with the forwarder); the forwarder's unit is.
func TestSniffManifest(t *testing.T) {
	b := compileTopo(t, sniffTopo(true, ""))
	files := nodeFiles(b.Files, "gw")
	m, err := DeriveManifest("gw", files, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(m.Units, compile.SniffUnit) || contains(m.Units, compile.SniffAccountUnit) {
		t.Fatalf("units %v", m.Units)
	}
	for _, p := range sniffFiles {
		if _, ok := m.fileHash(p); !ok {
			t.Fatalf("%s is not a managed file", p)
		}
	}
	if _, ok := m.fileHash(strings.TrimPrefix(compile.SniffTargetsPath, "/")); !ok {
		t.Fatal("target file not managed")
	}
	off, err := DeriveManifest("gw", nodeFiles(compileTopo(t, sniffTopo(false, "")).Files, "gw"), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range off.Files {
		if strings.Contains(f.Path, "sniff") {
			t.Fatalf("sniff off still installs %s", f.Path)
		}
	}
}

// Reload only when the forwarder ran before and none of its unit files or
// its account script changed.
func TestSniffReloadRule(t *testing.T) {
	mk := func(units bool, hashes map[string]string) Manifest {
		m := FilesOnly(hashes)
		if units {
			m.Units = []string{compile.SniffUnit}
		}
		return m
	}
	same := map[string]string{}
	for _, p := range sniffFiles {
		same[p] = "h-" + p
	}
	if !sniffReload(mk(true, same), mk(true, same)) {
		t.Fatal("unchanged files did not reload")
	}
	if sniffReload(mk(false, same), mk(true, same)) {
		t.Fatal("a forwarder that did not run was reloaded")
	}
	for _, p := range sniffFiles {
		changed := map[string]string{}
		for k, v := range same {
			changed[k] = v
		}
		changed[p] = "other"
		if sniffReload(mk(true, same), mk(true, changed)) {
			t.Fatalf("a change of %s reloaded instead of restarting", p)
		}
		missing := map[string]string{}
		for k, v := range same {
			if k != p {
				missing[k] = v
			}
		}
		if sniffReload(mk(true, missing), mk(true, same)) {
			t.Fatalf("%s new: reloaded", p)
		}
	}
}

// sniffGone checks that nothing of the forwarder is left on the host.
func sniffGone(t *testing.T, r *rig, when string) {
	t.Helper()
	sn := r.sim.sn
	if sn.unit != "" || sn.accountUnit != "" || sn.account || sn.fwmark == "1" {
		t.Fatalf("%s: forwarder state left: %+v", when, sn)
	}
	if r.sim.enabled[compile.SniffUnit] {
		t.Fatalf("%s: forwarder still enabled", when)
	}
	for _, p := range []string{
		filepath.Join(r.host, "etc/systemd/system", compile.SniffUnit),
		filepath.Join(r.host, "etc/systemd/system", compile.SniffAccountUnit),
		filepath.Join(r.host, compile.SniffUserScript),
		filepath.Join(r.host, compile.SniffTargetsPath),
		filepath.Dir(filepath.Join(r.host, compile.SniffTargetsPath)),
	} {
		if exists(p) {
			t.Fatalf("%s: %s left", when, p)
		}
	}
}

// order checks that the commands appear in this order in the log.
func order(t *testing.T, cmds []string, want ...string) {
	t.Helper()
	i := 0
	for _, c := range cmds {
		if i < len(want) && c == want[i] {
			i++
		}
	}
	if i != len(want) {
		t.Fatalf("missing or out of order from %q on:\n%s", want[i], strings.Join(cmds, "\n"))
	}
}

func (h *simHost) since(n int) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.cmds[n:]...)
}

func (h *simHost) mark() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.cmds)
}

// Every transition of the forwarder through the install transaction, with
// the order of the agent's fixed steps:
//
//   - first enable: files written, daemon-reload, the ruleset
//     (meridian.service), then enable, stop, stop account unit, start (the
//     account unit is started by systemd first and adds the account);
//   - a rule change while running: reload (SIGHUP), the account is not
//     touched; a unit change: stop, account removed, start, account added;
//   - disable: disable --now, account unit stopped (account removed),
//     failed states cleared, then the files and the empty directory removed,
//     then daemon-reload;
//   - runtime rollback and withdraw like disable.
func TestSniffLifecycle(t *testing.T) {
	r := newRig(t)
	apply := func(b *compile.Bundle) (Result, error) { return r.applier().Apply(b, false) }
	unitPath := filepath.Join(r.host, "etc/systemd/system", compile.SniffUnit)
	if _, err := apply(compileTopo(t, sniffTopo(false, ""))); err != nil {
		t.Fatal(err)
	}
	r.sim.sn.fwmark = "0"
	sniffGone(t, r, "before")

	// First enable.
	n := r.sim.mark()
	if _, err := apply(compileTopo(t, sniffTopo(true, ""))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{unitPath, filepath.Join(r.host, "etc/systemd/system", compile.SniffAccountUnit), filepath.Join(r.host, compile.SniffTargetsPath), filepath.Join(r.host, compile.SniffUserScript)} {
		if !exists(p) {
			t.Fatalf("%s not installed", p)
		}
	}
	if fi, err := os.Stat(filepath.Join(r.host, compile.SniffUserScript)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("account script mode: %v %v", fi.Mode(), err)
	}
	sn := r.sim.sn
	if sn.unit != "active" || sn.accountUnit != "active" || !sn.account || sn.fwmark != "1" || sn.adds != 1 {
		t.Fatalf("not running after enable: %+v", sn)
	}
	order(t, r.sim.since(n),
		"systemctl daemon-reload",
		"systemctl restart meridian.service",
		"systemctl enable "+compile.SniffUnit,
		"systemctl stop "+compile.SniffUnit,
		"systemctl stop "+compile.SniffAccountUnit,
		"systemctl reset-failed "+compile.SniffUnit+" "+compile.SniffAccountUnit,
		"systemctl start "+compile.SniffUnit,
		"systemctl is-active "+compile.SniffUnit,
		"systemctl is-active "+compile.SniffAccountUnit,
	)
	last := func() hostexec.Request {
		act := r.rt.requests("fwd-activate")
		return act[len(act)-1]
	}
	if q := last(); len(q.Resources.Reload) != 0 || contains(q.Resources.Units, compile.SniffAccountUnit) {
		t.Fatalf("a new unit must be started, not reloaded; the account unit is never named: %+v", q.Resources)
	}

	// A rule change: same unit files, reload; the account stays.
	n = r.sim.mark()
	if _, err := apply(compileTopo(t, sniffTopo(true, "x.example.net"))); err != nil {
		t.Fatal(err)
	}
	if q := last(); strings.Join(q.Resources.Reload, ",") != compile.SniffUnit {
		t.Fatalf("rule change did not reload: %+v", q.Resources)
	}
	if r.sim.sn.reloads != 1 || r.sim.sn.adds != 1 || r.sim.sn.dels != 0 {
		t.Fatalf("reload touched the account: %+v", r.sim.sn)
	}
	for _, c := range r.sim.since(n) {
		if strings.HasPrefix(c, "systemctl stop meridian-sniff") || strings.HasPrefix(c, "systemctl start meridian-sniff") {
			t.Fatalf("reload path ran %q", c)
		}
	}
	order(t, r.sim.since(n), "systemctl restart meridian.service", "systemctl reload-or-restart "+compile.SniffUnit)

	// A setting change (ports): new unit file, restart with a fresh account.
	on := sniffTopo(true, "x.example.net")
	on.Settings.Sniff.Ports = []int{443}
	n = r.sim.mark()
	if _, err := apply(compileTopo(t, on)); err != nil {
		t.Fatal(err)
	}
	if q := last(); len(q.Resources.Reload) != 0 {
		t.Fatalf("unit change reloaded instead of restarting: %+v", q.Resources)
	}
	if r.sim.sn.adds != 2 || r.sim.sn.dels != 1 || r.sim.sn.unit != "active" {
		t.Fatalf("restart did not renew the account: %+v", r.sim.sn)
	}
	order(t, r.sim.since(n), "systemctl stop "+compile.SniffUnit, "systemctl stop "+compile.SniffAccountUnit, "systemctl start "+compile.SniffUnit)

	// Runtime rollback to the previous version: the unit stays (it was in
	// the previous version), restarted for the changed unit file.
	if _, err := r.applier().RollbackReport(); err != nil {
		t.Fatal(err)
	}
	if !exists(unitPath) || r.sim.sn.unit != "active" || !r.sim.sn.account {
		t.Fatalf("rollback lost the forwarder: %+v", r.sim.sn)
	}

	// Disable.
	n = r.sim.mark()
	if _, err := apply(compileTopo(t, sniffTopo(false, "x.example.net"))); err != nil {
		t.Fatal(err)
	}
	sniffGone(t, r, "disable")
	order(t, r.sim.since(n),
		"systemctl disable --now "+compile.SniffUnit,
		"systemctl stop "+compile.SniffAccountUnit,
		"systemctl reset-failed "+compile.SniffUnit+" "+compile.SniffAccountUnit,
		"systemctl daemon-reload",
		"systemctl restart meridian.service",
	)

	// Rollback brings it back (the previous version had it), withdraw
	// removes it.
	if _, err := r.applier().RollbackReport(); err != nil {
		t.Fatal(err)
	}
	if r.sim.sn.unit != "active" || !r.sim.sn.account {
		t.Fatalf("rollback did not restart the forwarder: %+v", r.sim.sn)
	}
	if _, err := r.applier().Withdraw(); err != nil {
		t.Fatal(err)
	}
	sniffGone(t, r, "withdraw")
}

// The failure the real host showed: the forwarder's unit is present but
// does not start. The transaction compensates: afterwards neither unit
// runs or stays failed, the files, the account, the sysctl and the empty
// /etc/meridian/sniff are gone, and the previous version runs.
func TestSniffFailedStartCompensates(t *testing.T) {
	for name, set := range map[string]func(*sniffSim){
		"start fails":      func(s *sniffSim) { s.startFails = true },
		"account conflict": func(s *sniffSim) { s.conflict = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if _, err := r.applier().Apply(compileTopo(t, sniffTopo(false, "")), false); err != nil {
				t.Fatal(err)
			}
			r.sim.sn.fwmark = "0"
			before, err := r.applier().Installed()
			if err != nil {
				t.Fatal(err)
			}
			set(&r.sim.sn)
			_, err = r.applier().Apply(compileTopo(t, sniffTopo(true, "")), false)
			var te *TxnError
			if !errors.As(err, &te) || !te.Compensated {
				t.Fatalf("not compensated: %v", err)
			}
			sniffGone(t, r, "compensated")
			after, err := r.applier().Installed()
			if err != nil || after.Version != before.Version {
				t.Fatalf("installed version %d, want %d (%v)", after.Version, before.Version, err)
			}
			if !r.sim.units["meridian.service"] {
				t.Fatal("previous data plane not running")
			}
			// The fix: the next attempt starts.
			r.sim.sn.startFails, r.sim.sn.conflict = false, false
			if _, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "")), false); err != nil {
				t.Fatal(err)
			}
			if r.sim.sn.unit != "active" || !r.sim.sn.account {
				t.Fatalf("%+v", r.sim.sn)
			}
		})
	}
}

// An empty /etc/meridian/sniff left by an earlier version's compensation is
// removed by the next converge that has no file in it; one with someone
// else's file stays.
func TestOwnedDirRemoval(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/meridian/sniff")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyOwnedDirs(root, FilesOnly(map[string]string{"etc/meridian/rules/decide.json": "x"})); err != nil || exists(dir) {
		t.Fatalf("empty dir kept: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyOwnedDirs(root, FilesOnly(map[string]string{"etc/meridian/sniff/targets.json": "x"})); err != nil || !exists(dir) {
		t.Fatalf("dir of a target file removed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "operator-note"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyOwnedDirs(root, FilesOnly(nil)); err != nil || !exists(dir) {
		t.Fatalf("non-empty dir removed: %v", err)
	}
}
