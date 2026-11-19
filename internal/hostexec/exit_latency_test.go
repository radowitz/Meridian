package hostexec

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/radowitz/meridian/internal/probe"
)

type latencyNet struct {
	dialed int
	iface  string
}

func (n *latencyNet) Resolve(context.Context, string) ([]netip.Addr, error) {
	panic("latency must not query public DNS")
}
func (n *latencyNet) Route(context.Context, netip.Addr) (string, error) { return n.iface, nil }
func (n *latencyNet) Dial(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	if dst.Port() != 53 || !tunnelULA.Contains(dst.Addr()) {
		panic("unexpected latency destination")
	}
	n.dialed++
	a, b := net.Pipe()
	b.Close()
	return a, nil
}
func TestExitLatencyPinnedAndFailClosed(t *testing.T) {
	p := goodProbe()
	req := ExitLatencyRequest{RequestID: p.RequestID, ExitID: p.ExitID, Mark: p.Mark, TransitV4: p.TransitV4, TransitV6: p.TransitV6, Resolver: p.Resolver}
	for _, iface := range []string{"m00", "eth0"} {
		n := &latencyNet{iface: iface}
		a := &Agent{Runner: installedLo(), ProbeNetwork: func(_ ProbeRequest, _ probe.Network) probe.Network { return n }}
		r, code := a.ExitLatency(context.Background(), req)
		if code != 200 {
			t.Fatal(code, r)
		}
		if iface == "eth0" {
			if n.dialed != 0 || r.RTTMS != nil || r.State != "unreachable" {
				t.Fatalf("WAN used: %+v", r)
			}
		} else if n.dialed != 3 || r.RTTMS == nil || r.Received != 3 || r.State != "ok" || r.MeasuredAt.IsZero() {
			t.Fatalf("missing actual samples: %+v", r)
		}
	}
	req.Resolver = "2001:4860:4860::8888"
	if _, code := (&Agent{}).ExitLatency(context.Background(), req); code != 400 {
		t.Fatal("public resolver accepted")
	}
}

type changingLatencyNet struct {
	latencyNet
	reads int
}

func (n *changingLatencyNet) Route(context.Context, netip.Addr) (string, error) {
	n.reads++
	if n.reads > 1 {
		return "eth0", nil
	}
	return "m00", nil
}
func TestExitLatencyDiscardsChangingPath(t *testing.T) {
	p := goodProbe()
	req := ExitLatencyRequest{RequestID: p.RequestID, ExitID: p.ExitID, Mark: p.Mark, TransitV4: p.TransitV4, TransitV6: p.TransitV6, Resolver: p.Resolver}
	n := &changingLatencyNet{}
	a := &Agent{Runner: installedLo(), ProbeNetwork: func(ProbeRequest, probe.Network) probe.Network { return n }}
	r, _ := a.ExitLatency(context.Background(), req)
	if r.State != "path_changed" || r.RTTMS != nil || n.dialed != 1 {
		t.Fatalf("changing path accepted: %+v", r)
	}
}
