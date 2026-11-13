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

// The withdraw action never names the guard and never manages the resolver.
func TestWithdrawValidation(t *testing.T) {
	for _, r := range []Resources{
		{NFTTables: []string{GuardTable}},
		{NFTTables: []string{"inet meridian", GuardTable}},
		{DNS: true},
		{Interfaces: []string{"eth0"}},
		{Units: []string{"meridian-guard.service"}},
	} {
		if err := Validate(Request{Action: ActionWithdraw, RequestID: "w-1", Resources: r}); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if err := Validate(Request{Action: ActionWithdraw, RequestID: "w-1", Resources: Resources{Interfaces: []string{"m02"}, NFTTables: []string{"inet meridian"}, RouteTables: []int{100}}}); err != nil {
		t.Fatal(err)
	}
}

// Withdraw: forwarding off, meridian.service stopped, then the ledger-owned
// resources removed; the guard is checked last and stays.
func TestWithdrawKeepsGuardForwardingOffFirst(t *testing.T) {
	f := healthyGateway()
	f.links["m02"], f.links["wg0"] = true, true
	a := newAgent(f)
	if res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "a1", Resources: Resources{Interfaces: []string{"m02"}, NFTTables: []string{"inet meridian", GuardTable}}}); !res.OK {
		t.Fatalf("activate: %+v", res)
	}
	res, code := a.Execute(context.Background(), Request{Action: ActionWithdraw, RequestID: "w1", Resources: Resources{Interfaces: []string{"m02"}, NFTTables: []string{"inet meridian"}}})
	if code != 200 || !res.OK {
		t.Fatalf("%d %+v", code, res)
	}
	cmds := strings.Join(f.commands(), "\n")
	fwd4, fwd6 := strings.Index(cmds, "sysctl -w net.ipv4.ip_forward=0"), strings.Index(cmds, "sysctl -w net.ipv6.conf.all.forwarding=0")
	stop, del := strings.Index(cmds, "systemctl stop meridian.service"), strings.Index(cmds, "ip link del dev m02")
	if fwd4 < 0 || fwd6 < 0 || stop < fwd6 || del < stop {
		t.Fatalf("order:\n%s", cmds)
	}
	if f.links["m02"] || !f.links["wg0"] || f.nft["inet meridian"] || !f.nft[GuardTable] {
		t.Fatalf("links %v nft %v", f.links, f.nft)
	}
	if strings.Contains(cmds, "nft delete table inet meridian_guard") || strings.Contains(cmds, "ip_forward=1") {
		t.Fatal("withdraw touched the guard or turned forwarding on")
	}
	// A resource Meridian never activated that exists is refused, as for rollback.
	if _, code := a.Execute(context.Background(), Request{Action: ActionWithdraw, RequestID: "w2", Resources: Resources{Interfaces: []string{"m09"}}}); code != 200 {
		t.Fatalf("absent unknown interface must be skipped: %d", code)
	}
	f.links["m10"] = true
	if res, code := a.Execute(context.Background(), Request{Action: ActionWithdraw, RequestID: "w3", Resources: Resources{Interfaces: []string{"m10"}}}); code != 403 || res.OK {
		t.Fatalf("foreign m10: %d %+v", code, res)
	}
	if !f.links["m10"] {
		t.Fatal("foreign interface removed")
	}
}

// A guard that is not loaded is reloaded through meridian-guard.service; if
// it still is not there, the withdraw fails (never "done" without a guard).
func TestWithdrawGuardMissingFails(t *testing.T) {
	f := healthyGateway()
	delete(f.nft, GuardTable)
	f.units["meridian-guard.service"] = "inactive"
	a := newAgent(f)
	res, code := a.Execute(context.Background(), Request{Action: ActionWithdraw, RequestID: "w1"})
	if code != 200 || res.OK || !strings.Contains(res.Error, "guard") {
		t.Fatalf("%d %+v", code, res)
	}
	if f.ran("systemctl restart meridian-guard.service") != 1 {
		t.Fatalf("guard unit not restarted: %v", f.commands())
	}
}
