package apply

import (
	"errors"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
)

func stepNamed(steps []hostexec.Step, name string) *hostexec.Step {
	for i := range steps {
		if steps[i].Name == name {
			return &steps[i]
		}
	}
	return nil
}

// The install transaction requires the forwarder's self-check of the rule
// pair it just installed (the incident: a forwarder that ran but could not
// reach any tunnel target):
//
//   - all targets ok: installed, a passing "sniff self-check" step;
//   - another target fails: installed, a warning naming it;
//   - the default target fails, the self-check is refused (not answered),
//     or the result is for another rule pair: the install fails, the
//     transaction compensates (the previous version runs again, the
//     forwarder of the failed version is gone) and the error says why.
func TestSniffSelfCheckInstall(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r := newRig(t)
		b := compileTopo(t, sniffTopo(true, "")) // before applier(): it copies the secrets compiling creates
		res, err := r.applier().Apply(b, false)
		if err != nil {
			t.Fatal(err)
		}
		st := stepNamed(res.Host.Steps, "sniff self-check")
		if st == nil || !st.OK || !strings.Contains(st.Detail, "group:hk") || r.sim.sn.checks != 1 {
			t.Fatalf("%+v checks=%d", res.Host.Steps, r.sim.sn.checks)
		}
		// A rule change reloads the forwarder and checks again.
		if _, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "x.example.net")), false); err != nil || r.sim.sn.reloads != 1 || r.sim.sn.checks != 2 {
			t.Fatalf("%v %+v", err, r.sim.sn)
		}
	})
	t.Run("other target fails", func(t *testing.T) {
		r := newRig(t)
		r.sim.sn.check = "other"
		res, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "")), false)
		if err != nil {
			t.Fatal(err)
		}
		w := strings.Join(res.Host.Warnings, "\n")
		if !strings.Contains(w, "group:jp") || !strings.Contains(w, "超时") || r.sim.sn.unit != "active" {
			t.Fatalf("%s", w)
		}
		if st := stepNamed(res.Host.Steps, "sniff self-check"); st == nil || !st.OK {
			t.Fatalf("%+v", res.Host.Steps)
		}
	})
	// The production false positive: exit resolvers answer the root
	// question only after seconds, but their TCP port opens. Installed,
	// with a warning, not compensated.
	t.Run("slow resolvers", func(t *testing.T) {
		r := newRig(t)
		r.sim.sn.check = "slow"
		res, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "")), false)
		if err != nil {
			t.Fatal(err)
		}
		if st := stepNamed(res.Host.Steps, "sniff self-check"); st == nil || !st.OK {
			t.Fatalf("%+v", res.Host.Steps)
		}
		w := strings.Join(res.Host.Warnings, "\n")
		if !strings.Contains(w, "group:hk") || !strings.Contains(w, "解析器慢") || r.sim.sn.unit != "active" {
			t.Fatalf("%s", w)
		}
	})
	for name, c := range map[string]struct {
		mode, code, text string
	}{
		"default target fails": {"default", "default_failed", "默认目标 group:hk 的路径不通"},
		"not answered":         {"refuse", "timeout", "没有按时完成"},
		"stale result":         {"stale", "stale_generation", "另一版规则"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if _, err := r.applier().Apply(compileTopo(t, sniffTopo(false, "")), false); err != nil {
				t.Fatal(err)
			}
			r.sim.sn.fwmark = "0"
			before, _ := r.applier().Installed()
			r.sim.sn.check = c.mode
			_, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "")), false)
			var te *TxnError
			if !errors.As(err, &te) || !te.Compensated {
				t.Fatalf("not compensated: %v", err)
			}
			var sc *SniffCheckError
			if !errors.As(err, &sc) || sc.Code != c.code || !strings.Contains(err.Error(), c.text) {
				t.Fatalf("reason: %v", err)
			}
			if st := stepNamed(te.Report.Steps, "sniff self-check"); st == nil || st.OK {
				t.Fatalf("%+v", te.Report.Steps)
			}
			sniffGone(t, r, "compensated")
			after, _ := r.applier().Installed()
			if after.Version != before.Version || !r.sim.units["meridian.service"] {
				t.Fatalf("installed %d, want %d", after.Version, before.Version)
			}
		})
	}
}

// A failed install of a new rule pair compensates back to the previous
// version, which also runs the forwarder: its self-check is reported, but
// does not block the restore (an exit or hub that is really down must not
// keep the host in the version that just failed).
func TestSniffSelfCheckCompensationNotBlocked(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "")), false); err != nil {
		t.Fatal(err)
	}
	before, _ := r.applier().Installed()
	r.sim.sn.check = "default"
	_, err := r.applier().Apply(compileTopo(t, sniffTopo(true, "x.example.net")), false)
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("not compensated: %v", err)
	}
	after, _ := r.applier().Installed()
	if after.Version != before.Version || r.sim.sn.unit != "active" {
		t.Fatalf("installed %d, want %d; %+v", after.Version, before.Version, r.sim.sn)
	}
	if st := stepNamed(te.Report.Steps, "sniff self-check (comp)"); st == nil || !st.Skipped {
		t.Fatalf("%+v", te.Report.Steps)
	}
	if !strings.Contains(strings.Join(te.Report.Warnings, "\n"), "恢复的版本") {
		t.Fatalf("%q", te.Report.Warnings)
	}
	if h, _ := after.fileHash(sniffTargetsRel); h == "" || readHost(t, r.host, sniffTargetsRel) == "" {
		t.Fatal("previous target file not restored")
	}
}

// An activation result without a self-check (an agent that does not run
// one) is refused for a forwarder install: fail closed.
func TestSniffSelfCheckMissingFailsClosed(t *testing.T) {
	tx := &txn{rep: &HostReport{}}
	to := FilesOnly(map[string]string{sniffTargetsRel: "h"})
	err := tx.checkSniff(&hostexec.Result{OK: true}, to, "fwd")
	var sc *SniffCheckError
	if !errors.As(err, &sc) || sc.Code != "unavailable" {
		t.Fatalf("%v", err)
	}
	if compile.SniffTargetsPath != "/"+sniffTargetsRel || hostexec.SniffTargets != compile.SniffTargetsPath {
		t.Fatal("target file paths disagree")
	}
}
