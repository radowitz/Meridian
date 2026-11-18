package pathquality

import "github.com/radowitz/meridian/internal/model"

// MeshLegState is a same-exit leg selector. Its samples are measured on the
// two tunnel interfaces, never through the currently selected routing table.
// The hub's generated shell implements the same integer decision rules.
type MeshLegState struct {
	Active                    string
	Switched, DirectGoodSince int64
	Direct, Mesh              []LegSample
}

type MeshQuality struct {
	Loss, RTT int
	Up        bool
}

// MeshWindow returns the bounded sampling window (five echoes per batch).
func MeshWindow(p model.PathQuality) int {
	if p.MeshWindowSamples > 0 && p.MeshWindowSamples <= 60 {
		return p.MeshWindowSamples
	}
	return 6
}

func meshQuality(samples []LegSample) MeshQuality {
	var sent, recv int
	var rtt int64
	for _, v := range samples {
		sent += v.Sent
		recv += v.Recv
		rtt += (v.RTTus / 1000) * int64(v.Recv)
	}
	q := MeshQuality{Loss: 1000}
	if sent > 0 {
		q.Loss = (sent - recv) * 1000 / sent
	}
	if recv > 0 {
		q.Up = true
		q.RTT = int(rtt / int64(recv))
	}
	return q
}

// StepMesh selects only direct, mesh, or blackhole. Total loss on the most
// recent batch bypasses smoothing and cooldown; returning to direct requires
// uninterrupted good batches, a full window, and the configured dwell time.
func StepMesh(p model.PathQuality, old MeshLegState, direct, mesh LegSample, now int64) (MeshLegState, string, MeshQuality, MeshQuality) {
	p = (&p).Effective()
	st := old
	appendSample := func(prev []LegSample, v LegSample) []LegSample {
		a := append(append([]LegSample(nil), prev...), v)
		if len(a) > MeshWindow(p) {
			a = a[len(a)-MeshWindow(p):]
		}
		return a
	}
	st.Direct = appendSample(st.Direct, direct)
	st.Mesh = appendSample(st.Mesh, mesh)
	d, m := meshQuality(st.Direct), meshQuality(st.Mesh)
	d.Up = direct.Recv > 0
	m.Up = mesh.Recv > 0
	good := d.Up && d.Loss < p.PoorLossPermille && d.RTT < p.PoorRTTMS && direct.Sent > 0 && (direct.Sent-direct.Recv)*1000/direct.Sent < p.PoorLossPermille && direct.RTTus/1000 < int64(p.PoorRTTMS)
	if good {
		if st.DirectGoodSince == 0 {
			st.DirectGoodSince = now
		}
	} else {
		st.DirectGoodSince = 0
	}
	if st.Active == "" {
		st.Active = "direct"
	}
	want, reason := st.Active, "stable"
	dwell := st.Switched == 0 || now-st.Switched >= int64(p.MinDwellSec)
	switch {
	case !d.Up && !m.Up:
		want, reason = "blackhole", "both_down"
	case st.Active == "direct" && !d.Up:
		want, reason = "mesh", "direct_down"
	case st.Active == "mesh" && !m.Up && d.Up:
		want, reason = "direct", "mesh_down"
	case st.Active == "blackhole" && d.Up:
		want, reason = "direct", "reachable"
	case st.Active == "blackhole" && m.Up:
		want, reason = "mesh", "reachable"
	case st.Active == "direct" && m.Up && len(st.Direct) >= MeshWindow(p) && dwell && (m.RTT+m.Loss)*(100+p.SwitchAdvantagePct) < (d.RTT+d.Loss)*100:
		want, reason = "mesh", "quality"
	case st.Active == "mesh" && good && len(st.Direct) >= MeshWindow(p) && st.DirectGoodSince > 0 && now-st.DirectGoodSince >= int64(p.ReturnAfterSec) && dwell && (d.RTT+d.Loss)*100 <= (m.RTT+m.Loss)*(100+p.SwitchAdvantagePct):
		want, reason = "direct", "direct_recovered"
	}
	if want != st.Active {
		st.Active = want
		st.Switched = now
	}
	return st, reason, d, m
}
