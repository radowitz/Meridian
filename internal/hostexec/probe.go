package hostexec

// The read-only unlock probe (POST /v1/probe).
//
// The caller picks one exit (its id, fwmark, transit addresses and tunnel
// resolver, all checked against the ranges compile produces and against the
// host's own state), one address family and services from probe.Catalog. It
// never supplies a URL, host, port, header, command or path.
//
// Locking. A probe does not take the action lock: an activate or rollback
// must not wait minutes behind a probe. Instead those actions preempt
// probes: while one runs no probe starts (503), and when one starts it
// cancels every running probe and waits (at most 15s) for them to stop, so
// no probe traffic is in flight while meridian-up.sh reloads rules, routes
// or the firewall. A preempted probe reports CatFailed ("已取消"), never a
// verdict. health only reads and neither refuses nor cancels probes. At most
// MaxProbes probes run at once (each one exit + family). Even if a reload
// slipped in between, the per-connection route check and the egress
// re-check would turn it into CatFailed rather than a wrong verdict.
//
// Cancellation. Unlike actions, a probe is cancelled when the caller goes
// away: it changes nothing on the host, so there is nothing to finish.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// ProbeRequest is the whole parameter set of the probe action.
type ProbeRequest struct {
	RequestID string `json:"request_id"`
	ExitID    string `json:"exit_id"`
	// Family is ipv4 or ipv6. There is no "any": the family is forced.
	Family    string `json:"family"`
	Mark      uint32 `json:"mark"`
	TransitV4 string `json:"transit_v4"`
	TransitV6 string `json:"transit_v6"`
	// Resolver is the exit's tunnel resolver ULA.
	Resolver string `json:"resolver"`
	// Region and ExpectAddr are what the egress must match.
	Region     string   `json:"region,omitempty"`
	ExpectAddr string   `json:"expect_addr,omitempty"`
	Services   []string `json:"services"`
}

const (
	minExitMark = 0x101
	maxExitMark = 0x101 + 63 // the selector loop in render_routes.go
	maxServices = 16
)

var (
	exitIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`) // validate.idRe
	regionRe  = regexp.MustCompile(`^[a-z]{2,12}$`)
	transit4  = netip.MustParsePrefix("10.66.200.0/24")
	transit6  = netip.MustParsePrefix("fd66:0:0:ff::/64")
	tunnelULA = netip.MustParsePrefix("fd66::/48")
)

// ErrProbeBusy means the agent refused to start a probe now (an action is
// running, or MaxProbes probes already are).
var ErrProbeBusy = errors.New("宿主正忙（安装/回滚进行中或探测已达上限），本次探测没有执行")

// ValidateProbe checks a probe request completely before anything runs.
func ValidateProbe(req ProbeRequest) error {
	if !requestIDRe.MatchString(req.RequestID) {
		return errors.New("request_id 不合法")
	}
	if !exitIDRe.MatchString(req.ExitID) {
		return errors.New("exit_id 不合法")
	}
	fam, ok := unlock.ParseFamily(req.Family)
	if !ok || fam == unlock.FamilyAny {
		return errors.New("family 只能是 ipv4 或 ipv6")
	}
	if req.Mark < minExitMark || req.Mark > maxExitMark {
		return fmt.Errorf("mark %#x 不是 Meridian 出口 mark", req.Mark)
	}
	t4, err := netip.ParseAddr(req.TransitV4)
	if err != nil || !t4.Is4() || !transit4.Contains(t4) {
		return errors.New("transit_v4 必须在 10.66.200.0/24 里")
	}
	t6, err := netip.ParseAddr(req.TransitV6)
	if err != nil || !t6.Is6() || t6.Is4In6() || !transit6.Contains(t6) {
		return errors.New("transit_v6 必须在 fd66:0:0:ff::/64 里")
	}
	res, err := netip.ParseAddr(req.Resolver)
	if err != nil || !res.Is6() || !tunnelULA.Contains(res) || transit6.Contains(res) {
		return errors.New("resolver 必须是 fd66::/48 里的出口隧道地址")
	}
	if req.Region != "" && !regionRe.MatchString(req.Region) {
		return errors.New("region 不合法")
	}
	if req.ExpectAddr != "" {
		a, err := netip.ParseAddr(req.ExpectAddr)
		if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() {
			return errors.New("expect_addr 必须是公网地址")
		}
		if (fam == unlock.FamilyIPv4) != a.Unmap().Is4() {
			return errors.New("expect_addr 的地址族与 family 不一致")
		}
	}
	if req.Region == "" && req.ExpectAddr == "" {
		return errors.New("出口既没有地区也没有公网端点，无法确认实际出口")
	}
	if len(req.Services) == 0 || len(req.Services) > maxServices {
		return fmt.Errorf("services 需要 1 到 %d 个", maxServices)
	}
	seen := map[string]bool{}
	for _, s := range req.Services {
		if _, ok := probe.Lookup(s); !ok {
			return fmt.Errorf("服务 %q 没有探测适配器", s)
		}
		if seen[s] {
			return fmt.Errorf("服务 %q 重复", s)
		}
		seen[s] = true
	}
	return nil
}

// beginAction / endAction / beginProbe are the action/probe interlock
// described at the top of the file.
func (a *Agent) beginAction() {
	a.pmu.Lock()
	a.actionActive = true
	cancels := make([]context.CancelFunc, 0, len(a.probes))
	for _, c := range a.probes {
		cancels = append(cancels, c)
	}
	a.pmu.Unlock()
	for _, c := range cancels {
		c()
	}
	done := make(chan struct{})
	go func() { a.probeWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		// Sockets close on cancellation; a probe that has not returned by
		// now has no request in flight that the action could disturb more.
	}
}

func (a *Agent) endAction() {
	a.pmu.Lock()
	a.actionActive = false
	a.pmu.Unlock()
}

func (a *Agent) beginProbe(ctx context.Context) (context.Context, func(), error) {
	a.pmu.Lock()
	defer a.pmu.Unlock()
	if a.actionActive {
		return nil, nil, fmt.Errorf("%w：宿主动作进行中", ErrProbeBusy)
	}
	if len(a.probes) >= a.MaxProbes {
		return nil, nil, fmt.Errorf("%w：已有 %d 个探测在运行", ErrProbeBusy, len(a.probes))
	}
	pctx, cancel := context.WithTimeout(ctx, a.ProbeTimeout)
	a.probeSeq++
	id := a.probeSeq
	a.probes[id] = cancel
	a.probeWG.Add(1)
	return pctx, func() {
		cancel()
		a.pmu.Lock()
		delete(a.probes, id)
		a.pmu.Unlock()
		a.probeWG.Done()
	}, nil
}

// Probe validates and runs one probe. The HTTP status is 200 for a probe
// that ran (its results may all be failures), 4xx for a refused request and
// 503 when busy.
func (a *Agent) Probe(ctx context.Context, req ProbeRequest) (probe.Report, int) {
	a.init()
	if err := ValidateProbe(req); err != nil {
		return probe.Report{ExitID: req.ExitID, Error: err.Error()}, http.StatusBadRequest
	}
	pctx, done, err := a.beginProbe(ctx)
	if err != nil {
		return probe.Report{ExitID: req.ExitID, Error: err.Error()}, http.StatusServiceUnavailable
	}
	defer done()
	fam, _ := unlock.ParseFamily(req.Family)
	t4, _ := netip.ParseAddr(req.TransitV4)
	t6, _ := netip.ParseAddr(req.TransitV6)
	resolver, _ := netip.ParseAddr(req.Resolver)
	var expect netip.Addr
	if req.ExpectAddr != "" {
		expect, _ = netip.ParseAddr(req.ExpectAddr)
	}
	spec := probe.Spec{ExitID: req.ExitID, Family: fam, Region: req.Region, ExpectAddr: expect, Services: req.Services}
	src := t4
	if fam == unlock.FamilyIPv6 {
		src = t6
	}
	pin := probe.Pinned{Mark: req.Mark, Family: fam, Src4: t4, Src6: t6, Resolver: resolver}
	hn := &hostNet{a: a, pin: pin, src: src, fam: fam}
	// The transit addresses exist only where meridian-routes.sh installed
	// this exit. Refuse to send anything for an exit the host does not have.
	if err := hn.checkSource(pctx, t4, t6); err != nil {
		return probe.FailedReport(spec, err.Error(), time.Now()), http.StatusOK
	}
	var pn probe.Network = hn
	if a.ProbeNetwork != nil {
		pn = a.ProbeNetwork(req, hn)
	}
	p := &probe.Prober{
		Net: pn, AllowIface: ValidInterface, RootCAs: a.ProbeRootCAs,
		TargetTimeout: a.ProbeTargetTimeout, Concurrency: 3,
	}
	return p.Run(pctx, spec), http.StatusOK
}

// hostNet is the agent's probe.Network: Resolve and Dial through Pinned,
// Route through `ip route get` with the same mark and source.
type hostNet struct {
	a   *Agent
	pin probe.Pinned
	src netip.Addr
	fam unlock.Family
}

var devRe = regexp.MustCompile(`\bdev (\S+)`)

func (h *hostNet) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return h.pin.Resolve(ctx, host)
}

func (h *hostNet) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return h.pin.Dial(ctx, dst)
}

func (h *hostNet) Route(ctx context.Context, dst netip.Addr) (string, error) {
	fam := "-4"
	if h.fam == unlock.FamilyIPv6 {
		fam = "-6"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := h.a.Runner.Run(ctx, "ip", fam, "route", "get", dst.String(), "from", h.src.String(), "mark", fmt.Sprintf("%#x", h.pin.Mark))
	if err != nil {
		return "", fmt.Errorf("%v %s", err, firstLine(out))
	}
	m := devRe.FindStringSubmatch(out)
	if m == nil {
		// unreachable / blackhole: no device. That is the fail-closed case.
		return "", fmt.Errorf("没有出口设备：%s", firstLine(out))
	}
	return m[1], nil
}

func (h *hostNet) checkSource(ctx context.Context, t4, t6 netip.Addr) error {
	for _, c := range []struct {
		fam, want string
	}{{"-4", "inet " + t4.String() + "/32"}, {"-6", "inet6 " + t6.String() + "/128"}} {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := h.a.Runner.Run(cctx, "ip", c.fam, "-o", "addr", "show", "dev", "lo")
		cancel()
		if err != nil {
			return fmt.Errorf("读不到 lo 上的地址：%v", err)
		}
		if !strings.Contains(out+" ", c.want+" ") {
			return fmt.Errorf("本机 lo 上没有该出口的中转地址 %s：网关还没有安装这个出口，探测没有发出", strings.Fields(c.want)[1])
		}
	}
	return nil
}

func (a *Agent) serveProbe(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req ProbeRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, probe.Report{Error: "请求格式不正确"})
		return
	}
	rep, code := a.Probe(r.Context(), req)
	writeJSON(w, code, rep)
}

// Probe sends one probe request. It is not retried: a busy agent or a lost
// response is reported, and the job records the exit/family as failed.
func (c *Client) Probe(ctx context.Context, req ProbeRequest) (probe.Report, error) {
	if err := ValidateProbe(req); err != nil {
		return probe.Report{}, err
	}
	sock := c.Socket
	if sock == "" {
		sock = DefaultSocket
	}
	tokPath := c.TokenFile
	if tokPath == "" {
		tokPath = DefaultTokenFile
	}
	if st, err := os.Stat(sock); err != nil || st.Mode()&os.ModeSocket == 0 {
		return probe.Report{}, fmt.Errorf("%w：没有 %s", ErrUnavailable, sock)
	}
	raw, err := os.ReadFile(tokPath)
	if err != nil {
		return probe.Report{}, fmt.Errorf("%w：读不到口令文件 %s", ErrUnavailable, tokPath)
	}
	body, _ := json.Marshal(req)
	hc := &http.Client{
		Timeout: 4 * time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://meridian-host/v1/probe", strings.NewReader(string(body)))
	if err != nil {
		return probe.Report{}, err
	}
	hreq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hreq)
	if err != nil {
		if isDialErr(err) {
			return probe.Report{}, fmt.Errorf("%w：%v", ErrUnavailable, err)
		}
		return probe.Report{}, err
	}
	defer resp.Body.Close()
	var rep probe.Report
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rep); err != nil {
		return probe.Report{}, fmt.Errorf("host agent 应答格式不正确（%s）", resp.Status)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return rep, nil
	case http.StatusServiceUnavailable:
		return rep, fmt.Errorf("%w（%s）", ErrProbeBusy, rep.Error)
	default:
		return rep, fmt.Errorf("host agent 拒绝探测（%d）：%s", resp.StatusCode, rep.Error)
	}
}

// ProbeNetworkFunc lets tests replace the pinned network (which needs Linux,
// root and the gateway's routes). base is the real host network.
type ProbeNetworkFunc func(req ProbeRequest, base probe.Network) probe.Network
