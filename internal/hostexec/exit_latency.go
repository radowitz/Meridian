package hostexec

// A bounded TCP handshake to the exit's installed tunnel DNS listener. This
// measures the gateway-to-resolver path, not DNS recursion or public WAN RTT.
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

type ExitLatencyRequest struct {
	RequestID string `json:"request_id"`
	ExitID    string `json:"exit_id"`
	Mark      uint32 `json:"mark"`
	TransitV4 string `json:"transit_v4"`
	TransitV6 string `json:"transit_v6"`
	Resolver  string `json:"resolver"`
}
type ExitLatencyResult struct {
	ExitID     string    `json:"exit_id"`
	State      string    `json:"state"`
	RTTMS      *float64  `json:"rtt_ms,omitempty"`
	Sent       int       `json:"sent"`
	Received   int       `json:"received"`
	Interface  string    `json:"interface,omitempty"`
	MeasuredAt time.Time `json:"measured_at"`
	Error      string    `json:"error,omitempty"`
}

func (a *Agent) ExitLatency(ctx context.Context, req ExitLatencyRequest) (ExitLatencyResult, int) {
	a.init()
	out := ExitLatencyResult{ExitID: req.ExitID, State: "unreachable", MeasuredAt: time.Now().UTC()}
	p := ProbeRequest{RequestID: req.RequestID, ExitID: req.ExitID, Mark: req.Mark, TransitV4: req.TransitV4, TransitV6: req.TransitV6, Resolver: req.Resolver, Family: "ipv6"}
	fail := func(code int, err error) (ExitLatencyResult, int) { out.Error = err.Error(); return out, code }
	if err := validateProbePath(p); err != nil {
		return fail(400, err)
	}
	ctx, done, err := a.beginProbe(ctx)
	if err != nil {
		out.State = "busy"
		return fail(503, err)
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	t4, _ := netip.ParseAddr(req.TransitV4)
	t6, _ := netip.ParseAddr(req.TransitV6)
	res, _ := netip.ParseAddr(req.Resolver)
	pin := probe.Pinned{Mark: req.Mark, Family: unlock.FamilyIPv6, Src4: t4, Src6: t6, Resolver: res, Timeout: 2 * time.Second}
	base := &hostNet{a: a, pin: pin, src: t6, fam: unlock.FamilyIPv6}
	if err := base.checkSource(ctx, t4, t6); err != nil {
		out.State = "not_installed"
		return fail(200, err)
	}
	var n probe.Network = base
	if a.ProbeNetwork != nil {
		n = a.ProbeNetwork(p, base)
	}
	var total float64
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			break
		}
		iface, err := n.Route(ctx, res)
		if err != nil {
			return fail(200, err)
		}
		if !ProbeEgressInterface(iface) {
			return fail(200, fmt.Errorf("路由不经过受管隧道，未发出探测"))
		}
		out.Interface = iface
		sampleCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		start := time.Now()
		out.Sent++
		conn, e := n.Dial(sampleCtx, netip.AddrPortFrom(res, 53))
		elapsed := float64(time.Since(start)) / float64(time.Millisecond)
		if conn != nil {
			conn.Close()
		}
		stop()
		// Do not retain success from a path that changed during the handshake.
		after, re := n.Route(ctx, res)
		if re != nil || after != iface {
			out.State = "path_changed"
			return fail(200, fmt.Errorf("测量期间路由改变，请重测"))
		}
		if e != nil {
			out.Error = "隧道解析器 TCP 握手未完成"
			continue
		}
		out.Received++
		total += elapsed
	}
	out.MeasuredAt = time.Now().UTC()
	if out.Received > 0 {
		v := total / float64(out.Received)
		out.RTTMS = &v
		out.State = "ok"
		if out.Received == 3 {
			out.Error = ""
		} else {
			out.State = "partial"
		}
	}
	if out.Sent == 0 {
		out.State = "cancelled"
	}
	return out, 200
}
func (a *Agent) serveExitLatency(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req ExitLatencyRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, 400, ExitLatencyResult{State: "invalid", Error: "请求格式不正确"})
		return
	}
	out, code := a.ExitLatency(r.Context(), req)
	writeJSON(w, code, out)
}
func (c *Client) ExitLatency(ctx context.Context, req ExitLatencyRequest) (ExitLatencyResult, error) {
	var out ExitLatencyResult
	code, err := c.post(ctx, "/v1/exits/latency", req, 10*time.Second, &out)
	if err != nil {
		return out, err
	}
	if code != 200 {
		return out, fmt.Errorf("host agent 拒绝延迟测量（%d）：%s", code, out.Error)
	}
	return out, nil
}
