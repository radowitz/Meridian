// Package probe runs the panel's streaming/AI unlock probe for one exit and
// one address family, and classifies what each platform answered.
//
// It is the only place that sends probe traffic, and it runs inside the host
// agent (meridian-host), never in the panel process: leaving through a chosen
// exit needs the exit's fwmark and transit source address, which need
// CAP_NET_ADMIN on the gateway.
//
// Boundaries:
//
//   - Targets are a fixed table (Catalog). A caller names a service from the
//     table; it never supplies a URL, host, port, header or command. Redirects
//     are followed only to hosts listed for that service, over https (at
//     most 4; NoRedirect steps classify the redirect itself). The only value
//     carried between steps of one check comes from the platform's own
//     previous answer and must match extractRe before it is query-escaped
//     into a fixed URL. Bodies are read up to MaxBody.
//   - Every connection is pinned: names are resolved through the exit's own
//     tunnel resolver for the requested family only, the kernel route for the
//     resolved address (under the exit's mark and source) must leave through a
//     Meridian tunnel interface, and the socket is dialled with the family's
//     network ("tcp4"/"tcp6") from the family's transit address. There is no
//     fallback to the default route or to the other address family: anything
//     else is an error and the result is CatFailed.
//   - Egress is verified before any platform is contacted and again after the
//     last one: the public address and location the trace endpoint reports
//     must be of the requested family and match the exit (its region, and its
//     public endpoint address when the topology knows one). An unconfirmed
//     egress never yields a platform verdict.
//   - No cookies, accounts or tokens: requests carry a fixed browser-like
//     header set, no cookie jar, and evidence keeps only status, host, path
//     and the marker a verdict is based on (no query strings, no bodies, no
//     Set-Cookie).
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/unlock"
)

// The catalog, the result model and the classifiers live in adapters.go.

// MaxBody bounds how much of a response is read for classification.
const MaxBody = 256 << 10

// TraceURL is the fixed egress check. It answers with "ip=" and "loc=" lines
// for the connection's public address.
const TraceURL = "https://www.cloudflare.com/cdn-cgi/trace"

var traceHosts = []string{"www.cloudflare.com"}

// userAgent is a fixed, generic desktop browser string. Several platforms
// answer non-browser clients with a different page.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

// ---- egress ---------------------------------------------------------------

// Egress is what the trace endpoint said about the pinned connection.
type Egress struct {
	Confirmed bool   `json:"confirmed"`
	IP        string `json:"ip,omitempty"`
	Region    string `json:"region,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Basis: "address" (public address equals the exit's endpoint and region
	// matches) or "region" (region matches; the topology has no endpoint of
	// this family to compare).
	Basis    string `json:"basis,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ParseTrace reads the "key=value" lines of the trace endpoint.
func ParseTrace(body []byte) (ip netip.Addr, loc string, ok bool) {
	var haveIP bool
	for _, line := range strings.Split(string(body), "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch k {
		case "ip":
			a, err := netip.ParseAddr(v)
			if err == nil {
				ip, haveIP = a.Unmap(), true
			}
		case "loc":
			loc = strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ip, loc, haveIP && loc != ""
}

// VerifyEgress decides whether a trace proves the connection left through
// the exit on family fam. Both the public address family and the location
// must match; when expect (the exit's public endpoint of this family) is
// known, the address must equal it too, so a hub pool failover to another
// member of the same region is not credited to this exit.
func VerifyEgress(fam unlock.Family, body []byte, region string, expect netip.Addr) Egress {
	ip, loc, ok := ParseTrace(body)
	if !ok {
		return Egress{Error: "出口检查的应答里没有 ip / loc"}
	}
	e := Egress{IP: ip.String(), Region: loc}
	switch {
	case fam == unlock.FamilyIPv4 && !ip.Is4():
		e.Error = "要求 IPv4，实际公网地址是 " + ip.String()
		return e
	case fam == unlock.FamilyIPv6 && !ip.Is6():
		e.Error = "要求 IPv6，实际公网地址是 " + ip.String()
		return e
	}
	if region == "" && !expect.IsValid() {
		e.Error = "出口没有地区也没有公网端点，无法确认实际出口"
		return e
	}
	if region != "" && unlock.NormRegion(loc) != unlock.NormRegion(region) {
		e.Error = fmt.Sprintf("实际出口地区 %s 与出口 %s 不一致（可能落到默认出口或别的出口）", strings.ToUpper(loc), strings.ToUpper(region))
		return e
	}
	if expect.IsValid() {
		if ip != expect.Unmap() {
			e.Error = fmt.Sprintf("实际公网地址 %s 不是该出口的端点 %s（可能被池故障切换到别的成员）", ip, expect)
			return e
		}
		e.Basis = "address"
		e.Evidence = fmt.Sprintf("公网地址 %s = 出口端点，地区 %s", ip, strings.ToUpper(loc))
	} else {
		e.Basis = "region"
		e.Evidence = fmt.Sprintf("公网地址 %s，地区 %s 与出口一致（拓扑里没有该地址族的端点可比对）", ip, strings.ToUpper(loc))
	}
	e.Confirmed = true
	return e
}

// ---- running a probe -------------------------------------------------------

// Network is the pinned path to one exit for one family. Resolve answers
// through the exit's resolver and returns only addresses of that family;
// Route reports which interface the kernel would use for dst under the
// exit's mark and transit source; Dial opens a TCP connection pinned the
// same way.
type Network interface {
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
	Route(ctx context.Context, dst netip.Addr) (string, error)
	Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// Spec is one probe run: one exit, one family, a list of catalog services.
type Spec struct {
	ExitID string
	Family unlock.Family
	// Region is the exit's region from the topology; ExpectAddr its public
	// endpoint of this family when known.
	Region     string
	ExpectAddr netip.Addr
	Services   []string
}

// Result is one service's outcome.
type Result struct {
	Service    string        `json:"service"`
	Family     unlock.Family `json:"family"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Category   Category      `json:"category"`
	// Grade is GradeOf(Category); Signal the marker code; Capability the
	// adapter's declaration. Parts are the per-platform checks when an
	// adapter has more than one (only the primary one is ingested).
	Grade      Grade      `json:"grade,omitempty"`
	Signal     string     `json:"signal,omitempty"`
	Capability Capability `json:"capability,omitempty"`
	Region     string     `json:"region,omitempty"`
	Status     int        `json:"status,omitempty"`
	Evidence   string     `json:"evidence,omitempty"`
	Error      string     `json:"error,omitempty"`
	Parts      []Part     `json:"parts,omitempty"`
}

// Part is one platform check of a service.
type Part struct {
	Platform string   `json:"platform"`
	Primary  bool     `json:"primary,omitempty"`
	Category Category `json:"category"`
	Grade    Grade    `json:"grade"`
	Signal   string   `json:"signal,omitempty"`
	Region   string   `json:"region,omitempty"`
	Status   int      `json:"status,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Report is one Spec's outcome.
type Report struct {
	ExitID     string        `json:"exit_id"`
	Family     unlock.Family `json:"family"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Egress     Egress        `json:"egress"`
	Results    []Result      `json:"results"`
	Error      string        `json:"error,omitempty"`
}

// Prober runs Specs over a Network.
type Prober struct {
	Net Network
	// AllowIface reports whether an interface is a Meridian tunnel. Required.
	AllowIface func(string) bool
	// RootCAs nil means the system roots.
	RootCAs *x509.CertPool
	// TargetTimeout bounds one service (or one trace); default 20s.
	TargetTimeout time.Duration
	// Concurrency caps simultaneous services in one Spec; default 3.
	Concurrency int
	Now         func() time.Time
}

// ErrEgress marks a connection that would not have left through a Meridian
// tunnel; it is never retried another way.
var ErrEgress = errors.New("出口不对")

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

// Run probes every service of spec. It never returns a platform verdict
// unless the egress was confirmed before and after the services.
func (p *Prober) Run(ctx context.Context, spec Spec) Report {
	timeout := p.TargetTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	conc := p.Concurrency
	if conc <= 0 {
		conc = 3
	}
	rep := Report{ExitID: spec.ExitID, Family: spec.Family, StartedAt: p.now()}
	fail := func(msg string) Report {
		out := FailedReport(spec, msg, p.now())
		out.StartedAt, out.Egress = rep.StartedAt, rep.Egress
		return out
	}
	if spec.Family != unlock.FamilyIPv4 && spec.Family != unlock.FamilyIPv6 {
		return fail("地址族必须是 ipv4 或 ipv6")
	}
	for _, s := range spec.Services {
		if !Probeable(s) {
			return fail("服务 " + s + " 没有可执行的探测适配器")
		}
	}
	rep.Egress = p.egress(ctx, spec, timeout)
	if !rep.Egress.Confirmed {
		return fail("出口未确认：" + rep.Egress.Error)
	}

	results := make([]Result, len(spec.Services))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, s := range spec.Services {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				t := p.now()
				results[i] = Result{Service: s, Family: spec.Family, StartedAt: t, FinishedAt: t, Category: CatFailed, Grade: GradeError, Error: cancelText(ctx)}
				return
			}
			defer func() { <-sem }()
			if !SupportsFamily(s, spec.Family) {
				t := p.now()
				a, _ := Lookup(s)
				results[i] = Result{Service: s, Family: spec.Family, StartedAt: t, FinishedAt: t, Category: CatUnknown,
					Grade: GradeUnknown, Signal: SigFamily, Capability: a.Capability,
					Evidence: "该服务的公开检测方法只支持 IPv4，没有发出 IPv6 请求"}
				return
			}
			results[i] = p.one(ctx, spec, s, timeout)
		}(i, s)
	}
	wg.Wait()
	rep.Results = results

	// The pool on the hub may have failed over, or the gateway's tunnel
	// may have changed, while the services ran. Check again; if the egress
	// is no longer the same, no verdict from this run is kept.
	after := p.egress(ctx, spec, timeout)
	if !after.Confirmed || after.IP != rep.Egress.IP {
		msg := "探测结束时出口无法再次确认"
		if after.Confirmed {
			msg = fmt.Sprintf("探测期间出口地址从 %s 变成 %s", rep.Egress.IP, after.IP)
		} else if after.Error != "" {
			msg += "：" + after.Error
		}
		rep.Error = msg
		for i := range rep.Results {
			if rep.Results[i].Category != CatFailed {
				rep.Results[i].Error = msg
				rep.Results[i].Evidence = "（作废）" + rep.Results[i].Evidence
				rep.Results[i].Category = CatFailed
				rep.Results[i].Region = ""
			}
			rep.Results[i].Grade, rep.Results[i].Signal = GradeError, SigEgressChanged
			for k := range rep.Results[i].Parts {
				pt := &rep.Results[i].Parts[k]
				pt.Category, pt.Grade, pt.Region, pt.Signal, pt.Error = CatFailed, GradeError, "", SigEgressChanged, msg
			}
		}
	}
	rep.FinishedAt = p.now()
	return rep
}

// FailedReport is a report in which nothing was sent (or nothing counts):
// every service is CatFailed with msg.
func FailedReport(spec Spec, msg string, now time.Time) Report {
	now = now.UTC()
	rep := Report{ExitID: spec.ExitID, Family: spec.Family, StartedAt: now, FinishedAt: now, Error: msg}
	for _, s := range spec.Services {
		rep.Results = append(rep.Results, Result{Service: s, Family: spec.Family, StartedAt: now, FinishedAt: now, Category: CatFailed, Grade: GradeError, Error: msg})
	}
	return rep
}

func cancelText(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "整体超时"
	}
	return "已取消"
}

func (p *Prober) egress(ctx context.Context, spec Spec, timeout time.Duration) Egress {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var iface string
	resp, err := p.fetch(ctx, spec.Family, Step{URL: TraceURL}, TraceURL, traceHosts, &iface)
	if err != nil {
		return Egress{Interface: iface, Error: errText(ctx, err)}
	}
	if resp.Status != http.StatusOK {
		return Egress{Interface: iface, Error: fmt.Sprintf("出口检查 HTTP %d", resp.Status)}
	}
	e := VerifyEgress(spec.Family, resp.Body, spec.Region, spec.ExpectAddr)
	e.Interface = iface
	if e.Confirmed {
		e.Evidence += "，经 " + iface
	}
	return e
}

func (p *Prober) one(ctx context.Context, spec Spec, service string, timeout time.Duration) Result {
	a, _ := Lookup(service)
	res := Result{Service: service, Family: spec.Family, StartedAt: p.now(), Capability: a.Capability}
	// One budget for the whole service: every check and step of it.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	parts := make([]Part, 0, len(a.Checks))
	for _, c := range a.Checks {
		parts = append(parts, p.check(ctx, spec, a, c))
	}
	res.FinishedAt = p.now()
	prim := parts[a.primary()]
	res.Category, res.Region, res.Status = prim.Category, prim.Region, prim.Status
	res.Evidence, res.Error, res.Signal = prim.Evidence, prim.Error, prim.Signal
	res.Grade = GradeOf(res.Category)
	if len(parts) > 1 {
		res.Parts = parts
	}
	return res
}

// check runs one platform check: its fixed steps in order, then the
// classifier on the last response.
func (p *Prober) check(ctx context.Context, spec Spec, a Adapter, c Check) Part {
	part := Part{Platform: c.Platform, Primary: c.Primary}
	finish := func(v Verdict, r Response) Part {
		v = a.enforce(v)
		part.Category, part.Region, part.Signal, part.Status = v.Category, v.Region, v.Signal, r.Status
		part.Evidence = v.Evidence
		if r.URL != nil {
			part.Evidence += "（" + r.URL.Host + r.URL.Path + "）"
		}
		part.Grade = GradeOf(part.Category)
		return part
	}
	value := ""
	var prev []Response
	for i, st := range c.Steps {
		target := st.URL
		if strings.Contains(target, ValuePlaceholder) {
			target = strings.Replace(target, ValuePlaceholder, url.QueryEscape(value), 1)
		}
		r, err := p.fetch(ctx, spec.Family, st, target, c.Hosts, nil)
		if err != nil {
			part.Category, part.Grade, part.Error = CatFailed, GradeError, errText(ctx, err)
			return part
		}
		if i == len(c.Steps)-1 {
			r.Prev = prev
			return finish(c.Classify(r, spec.Region), r)
		}
		prev = append(prev, r)
		if st.Extract == nil {
			continue
		}
		v, stop := st.Extract(r)
		if stop != nil {
			return finish(*stop, r)
		}
		if !extractRe.MatchString(v) {
			return finish(Verdict{Category: CatUnknown, Signal: SigUnexpected,
				Evidence: fmt.Sprintf("前置请求 HTTP %d 返回的值格式不符合预期，未继续", r.Status)}, r)
		}
		value = v
	}
	return finish(Verdict{Category: CatUnknown, Signal: SigUnexpected, Evidence: "适配器没有请求步骤"}, Response{})
}

func errText(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, ErrEgress):
		return err.Error()
	case ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "超时"
	case ctx.Err() != nil:
		return "已取消"
	}
	msg := err.Error()
	if ue := (*url.Error)(nil); errors.As(err, &ue) {
		msg = ue.Err.Error()
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

// fetch GETs rawURL through the pinned network. Redirects are followed only
// to https hosts in hosts (at most 4); a redirect elsewhere stops and the
// redirect response itself is classified.
func (p *Prober) fetch(ctx context.Context, fam unlock.Family, st Step, rawURL string, hosts []string, iface *string) (Response, error) {
	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h] = true
	}
	var ifMu sync.Mutex
	dial := func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if !allowed[host] || port != "443" {
			return nil, fmt.Errorf("%w：%s 不在该服务的固定目标里", ErrEgress, addr)
		}
		addrs, err := p.Net.Resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("经出口解析 %s 失败：%v", host, err)
		}
		var dst netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if (fam == unlock.FamilyIPv4 && a.Is4()) || (fam == unlock.FamilyIPv6 && a.Is6()) {
				dst = a
				break
			}
		}
		if !dst.IsValid() {
			return nil, fmt.Errorf("%s 没有 %s 地址（不改用另一地址族）", host, fam)
		}
		if !dst.IsGlobalUnicast() || dst.IsPrivate() {
			return nil, fmt.Errorf("%w：%s 解析到非公网地址 %s", ErrEgress, host, dst)
		}
		dev, err := p.Net.Route(ctx, dst)
		if err != nil {
			return nil, fmt.Errorf("%w：查不到 %s 的出口路由：%v", ErrEgress, dst, err)
		}
		if p.AllowIface == nil || !p.AllowIface(dev) {
			return nil, fmt.Errorf("%w：%s 会从 %q 出去，不是 Meridian 隧道（不回落到默认出口）", ErrEgress, dst, dev)
		}
		if iface != nil {
			ifMu.Lock()
			*iface = dev
			ifMu.Unlock()
		}
		// Network.Dial uses tcp4 / tcp6 from the family's transit address.
		return p.Net.Dial(ctx, netip.AddrPortFrom(dst, 443))
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		TLSClientConfig:        &tls.Config{RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if st.NoRedirect || len(via) >= 4 || req.URL.Scheme != "https" || !allowed[req.URL.Hostname()] {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	method := http.MethodGet
	var reqBody io.Reader
	if st.Body != "" {
		method, reqBody = http.MethodPost, strings.NewReader(st.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8")
	// Fixed catalog headers only (names checked by catalogHeaderOK).
	for _, h := range st.Headers {
		req.Header.Set(h[0], h[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil && len(body) == 0 {
		return Response{}, err
	}
	final := *resp.Request.URL
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// A redirect we did not follow: classify on where it pointed.
		if u, err := resp.Request.URL.Parse(loc); err == nil {
			final = *u
		}
	}
	final.RawQuery, final.Fragment, final.User = "", "", nil
	return Response{Status: resp.StatusCode, URL: &final, Body: body}, nil
}
