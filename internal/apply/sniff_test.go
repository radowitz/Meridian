package apply

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

func TestSniffNamesMatchCompile(t *testing.T) {
	if hostexec.SniffUnit != compile.SniffUnit || hostexec.SniffSocket != compile.SniffStatusSocket {
		t.Fatal("hostexec and compile disagree on the forwarder's unit or socket")
	}
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

// The forwarder's resources go through the install transaction: enabling
// installs and starts the unit, its user script and the rule pair; a rule
// change reloads it (same unit file), a setting change restarts it;
// disabling, a runtime rollback and a withdraw remove the unit and its
// files (the unit's ExecStopPost removes its account and the sysctl).
func TestSniffLifecycle(t *testing.T) {
	r := newRig(t)
	// Compile first: the stable WSS secrets must exist when the applier
	// copies them.
	apply := func(b *compile.Bundle) (Result, error) { return r.applier().Apply(b, false) }
	unitPath := filepath.Join(r.host, "etc/systemd/system", compile.SniffUnit)
	if _, err := apply(compileTopo(t, sniffTopo(false, ""))); err != nil {
		t.Fatal(err)
	}
	// Enable.
	if _, err := apply(compileTopo(t, sniffTopo(true, ""))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{unitPath, filepath.Join(r.host, compile.SniffTargetsPath), filepath.Join(r.host, compile.SniffUserScript)} {
		if !exists(p) {
			t.Fatalf("%s not installed", p)
		}
	}
	if !r.sim.units[compile.SniffUnit] {
		t.Fatal("forwarder not started")
	}
	last := func() hostexec.Request {
		act := r.rt.requests("fwd-activate")
		return act[len(act)-1]
	}
	if q := last(); len(q.Resources.Reload) != 0 {
		t.Fatalf("a new unit must be started, not reloaded: %+v", q.Resources)
	}
	// A rule change: same unit file, reload.
	if _, err := apply(compileTopo(t, sniffTopo(true, "x.example.net"))); err != nil {
		t.Fatal(err)
	}
	if q := last(); strings.Join(q.Resources.Reload, ",") != compile.SniffUnit {
		t.Fatalf("rule change did not reload: %+v", q.Resources)
	}
	// A setting change (ports): new unit file, restart.
	on := sniffTopo(true, "x.example.net")
	on.Settings.Sniff.Ports = []int{443}
	if _, err := apply(compileTopo(t, on)); err != nil {
		t.Fatal(err)
	}
	if q := last(); len(q.Resources.Reload) != 0 {
		t.Fatalf("unit change reloaded instead of restarting: %+v", q.Resources)
	}
	// Runtime rollback to the previous version: reload is not used for a
	// changed unit; the unit stays (it was in the previous version).
	if _, err := r.applier().RollbackReport(); err != nil {
		t.Fatal(err)
	}
	if !exists(unitPath) || !r.sim.units[compile.SniffUnit] {
		t.Fatal("rollback lost the forwarder")
	}
	// Disable: unit removed (disable --now), files gone.
	if _, err := apply(compileTopo(t, sniffTopo(false, "x.example.net"))); err != nil {
		t.Fatal(err)
	}
	if exists(unitPath) || exists(filepath.Join(r.host, compile.SniffTargetsPath)) || exists(filepath.Join(r.host, compile.SniffUserScript)) {
		t.Fatal("disabling left the forwarder's files")
	}
	if _, ok := r.sim.units[compile.SniffUnit]; ok {
		t.Fatal("disabling left the unit")
	}
	// Rollback brings it back (the previous version had it), withdraw removes it.
	if _, err := r.applier().RollbackReport(); err != nil {
		t.Fatal(err)
	}
	if !r.sim.units[compile.SniffUnit] {
		t.Fatal("rollback did not restart the forwarder")
	}
	if _, err := r.applier().Withdraw(); err != nil {
		t.Fatal(err)
	}
	if exists(unitPath) || r.sim.units[compile.SniffUnit] {
		t.Fatal("withdraw left the forwarder")
	}
}
