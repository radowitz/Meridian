package hostexec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// agentDoer drives a real Agent (with the fake host) in-process.
type agentDoer struct {
	a    *Agent
	reqs []Request
}

func (d *agentDoer) Do(ctx context.Context, req Request) (Result, error) {
	d.reqs = append(d.reqs, req)
	res, code := d.a.Execute(ctx, req)
	if code != 200 {
		return res, errors.New(res.Error)
	}
	if !res.OK {
		return res, errors.New(res.Error)
	}
	return res, nil
}

func healthyGateway() *fakeHost {
	f := newFakeHost()
	f.units["meridian.service"] = "active"
	f.nft["inet meridian"], f.nft["inet meridian_guard"] = true, true
	return f
}

// Upgrade of a running gateway: healthy data plane, forwarding on, nothing
// is restarted.
func TestRestoreHealthyDoesNotRestart(t *testing.T) {
	f := healthyGateway()
	d := &agentDoer{a: newAgent(f)}
	on := func() (bool, error) { return true, nil }
	rep, err := RestoreDataPlane(context.Background(), d, on, true, "upgrade-1")
	if err != nil || !rep.Healthy || rep.Activated {
		t.Fatalf("%+v %v", rep, err)
	}
	if f.ran("systemctl restart") != 0 || len(d.reqs) != 1 || d.reqs[0].Action != ActionHealth {
		t.Fatalf("healthy data plane was touched: %v", f.commands())
	}
}

// Forwarding found off after the upgrade (it was on before): the data plane
// is re-activated through the agent (meridian.service, i.e. meridian-up.sh),
// never by writing forwarding directly.
func TestRestoreReactivatesWhenForwardingOff(t *testing.T) {
	f := healthyGateway()
	d := &agentDoer{a: newAgent(f)}
	calls := 0
	fwd := func() (bool, error) { calls++; return calls > 1, nil }
	rep, err := RestoreDataPlane(context.Background(), d, fwd, true, "upgrade-2")
	if err != nil || !rep.Healthy || !rep.Activated {
		t.Fatalf("%+v %v", rep, err)
	}
	if f.ran("systemctl restart meridian.service") != 1 {
		t.Fatalf("not re-activated through meridian.service: %v", f.commands())
	}
	for _, c := range f.commands() {
		if strings.HasPrefix(c, "sysctl") {
			t.Fatalf("restore wrote a sysctl itself: %s", c)
		}
	}
}

func TestRestoreFailsWhenActivationFails(t *testing.T) {
	f := newFakeHost() // meridian.service inactive, tables missing
	f.fail["systemctl restart meridian.service"] = true
	d := &agentDoer{a: newAgent(f)}
	rep, err := RestoreDataPlane(context.Background(), d, func() (bool, error) { return false, nil }, true, "upgrade-3")
	if err == nil || rep.Healthy || !rep.Activated || !strings.Contains(rep.Error, "重新激活") {
		t.Fatalf("%+v %v", rep, err)
	}
}

// --health-only never restarts anything, even when unhealthy.
func TestRestoreHealthOnlyNeverActivates(t *testing.T) {
	f := newFakeHost()
	d := &agentDoer{a: newAgent(f)}
	rep, err := RestoreDataPlane(context.Background(), d, nil, false, "upgrade-4")
	if err == nil || rep.Activated {
		t.Fatalf("%+v %v", rep, err)
	}
	if f.ran("systemctl restart") != 0 || f.ran("systemctl daemon-reload") != 0 {
		t.Fatalf("health-only touched the host: %v", f.commands())
	}
}
