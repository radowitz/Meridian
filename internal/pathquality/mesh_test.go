package pathquality

import (
	"github.com/radowitz/meridian/internal/model"
	"testing"
)

func TestSameExitMeshHysteresisAndBlackhole(t *testing.T) {
	p := model.PathQuality{MeshWindowSamples: 2, MinDwellSec: 20, ReturnAfterSec: 10}
	sample := func(recv int, rtt int64) LegSample { return LegSample{Sent: 5, Recv: recv, RTTus: rtt * 1000} }
	var st MeshLegState
	step := func(now int64, d, m LegSample, want string) {
		t.Helper()
		var reason string
		st, reason, _, _ = StepMesh(p, st, d, m, now)
		if st.Active != want {
			t.Fatalf("at %d: got %s (%s), want %s", now, st.Active, reason, want)
		}
	}
	good, slow, down := sample(5, 20), sample(5, 300), sample(0, 0)
	step(100, slow, good, "direct") // not a full sampling window
	step(105, slow, good, "mesh")
	step(110, good, good, "mesh") // still in window and cooldown
	step(115, good, good, "mesh")
	step(120, down, good, "mesh") // resets continuous recovery
	step(125, good, good, "mesh")
	step(130, good, good, "mesh")
	step(135, good, good, "mesh")
	step(140, good, good, "direct")
	step(141, down, good, "mesh") // complete loss bypasses dwell immediately
	step(142, down, down, "blackhole")
	step(143, good, down, "direct")
	step(144, good, good, "direct") // tiny RTT noise does not switch
}

func TestMeshFailureDoesNotMutatePreviousSamples(t *testing.T) {
	p := model.PathQuality{MeshWindowSamples: 2}
	old := MeshLegState{Direct: make([]LegSample, 1, 8), Active: "direct"}
	old.Direct[0] = LegSample{Sent: 5, Recv: 5, RTTus: 10000}
	st, why, d, m := StepMesh(p, old, LegSample{Sent: 5}, LegSample{Sent: 5}, 100)
	if st.Active != "blackhole" || why != "both_down" || d.Up || m.Up || len(old.Direct) != 1 {
		t.Fatalf("%+v %s %+v %+v", st, why, d, m)
	}
	for _, n := range []int{-1, 0, 61} {
		if MeshWindow(model.PathQuality{MeshWindowSamples: n}) != 6 {
			t.Fatal(n)
		}
	}
}
