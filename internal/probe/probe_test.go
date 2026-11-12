package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/unlock"
)

// ---- adapters: recorded/synthetic fixtures ---------------------------------

func u(s string) *url.URL {
	x, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return x
}

func TestAdapterClassification(t *testing.T) {
	cases := []struct {
		name, service, region string
		resp                  Response
		want                  Category
		wantRegion            string
	}{
		{"netflix 403", "auto-netflix", "hk", Response{Status: 403, URL: u("https://www.netflix.com/title/81280792")}, CatNotUnlocked, ""},
		{"netflix 404 originals only", "auto-netflix", "hk", Response{Status: 404, URL: u("https://www.netflix.com/title/81280792")}, CatNotUnlocked, ""},
		{"netflix 200 body HK on HK exit", "auto-netflix", "hk", Response{Status: 200, URL: u("https://www.netflix.com/hk-en/title/81280792"),
			Body: []byte(`<script>netflix.reactContext = {"models":{"geo":{"data":{"requestCountry":{"id":"HK","supported":true}}}}}</script>`)}, CatUnlocked, "hk"},
		{"netflix 200 US catalog on HK exit", "auto-netflix", "hongkong", Response{Status: 200, URL: u("https://www.netflix.com/title/81280792"),
			Body: []byte(`{"requestCountry":{"id":"US"}}`)}, CatNotUnlocked, "us"},
		{"netflix 200 path region only", "auto-netflix", "jp", Response{Status: 200, URL: u("https://www.netflix.com/jp/title/81280792")}, CatUnlocked, "jp"},
		{"netflix 200 no marker", "auto-netflix", "us", Response{Status: 200, URL: u("https://www.netflix.com/title/81280792"), Body: []byte("<html>")}, CatUnknown, ""},
		{"netflix 500", "auto-netflix", "us", Response{Status: 500, URL: u("https://www.netflix.com/title/81280792")}, CatUnknown, ""},
		{"disney unavailable redirect", "auto-disney", "hk", Response{Status: 302, URL: u("https://www.disneyplus.com/unavailable")}, CatNotUnlocked, ""},
		{"disney 403", "auto-disney", "hk", Response{Status: 403, URL: u("https://www.disneyplus.com/")}, CatNotUnlocked, ""},
		{"disney body region", "auto-disney", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/"), Body: []byte(`{"countryCode":"HK"}`)}, CatUnlocked, "hk"},
		{"disney lang-region path, wrong region", "auto-disney", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/en-sg")}, CatNotUnlocked, "sg"},
		{"disney 200 nothing", "auto-disney", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/")}, CatUnknown, ""},
		{"openai unsupported", "auto-openai", "us", Response{Status: 403, URL: u("https://api.openai.com/compliance/cookie_requirements"),
			Body: []byte(`{"error":{"code":"unsupported_country","message":"Country, region, or territory not supported"}}`)}, CatNotUnlocked, ""},
		{"openai reachable", "auto-openai", "us", Response{Status: 401, URL: u("https://api.openai.com/compliance/cookie_requirements"), Body: []byte(`{"error":{"code":"invalid_api_key"}}`)}, CatNetworkOK, ""},
		{"openai 502", "auto-openai", "us", Response{Status: 502}, CatUnknown, ""},
		{"claude unavailable", "auto-anthropic", "us", Response{Status: 307, URL: u("https://claude.ai/app-unavailable-in-region")}, CatNotUnlocked, ""},
		{"claude challenge", "auto-anthropic", "us", Response{Status: 403, URL: u("https://claude.ai/"), Body: []byte("<title>Just a moment...</title>")}, CatUnknown, ""},
		{"claude ok", "auto-anthropic", "us", Response{Status: 200, URL: u("https://claude.ai/login")}, CatNetworkOK, ""},
		{"gemini any status is reachability", "auto-gemini", "us", Response{Status: 403, URL: u("https://gemini.google.com/")}, CatNetworkOK, ""},
	}
	for _, c := range cases {
		a, ok := Lookup(c.service)
		if !ok {
			t.Fatalf("%s: no adapter", c.name)
		}
		v := a.Classify(c.resp, c.region)
		if v.Category != c.want || v.Region != c.wantRegion {
			t.Errorf("%s: got %s/%q (%s), want %s/%q", c.name, v.Category, v.Region, v.Evidence, c.want, c.wantRegion)
		}
		if v.Evidence == "" {
			t.Errorf("%s: verdict without evidence", c.name)
		}
		if a.Reachability && (v.Category == CatUnlocked || v.Category == CatNotUnlocked) {
			t.Errorf("%s: reachability adapter claimed a platform verdict", c.name)
		}
	}
}

func TestCatalogIsFixedHTTPS(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Catalog {
		if seen[a.Service] {
			t.Fatalf("duplicate %s", a.Service)
		}
		seen[a.Service] = true
		x := u(a.URL)
		if x.Scheme != "https" || x.Port() != "" || x.RawQuery != "" {
			t.Errorf("%s: target must be plain https on 443 without query: %s", a.Service, a.URL)
		}
		found := false
		for _, h := range a.Hosts {
			found = found || h == x.Hostname()
		}
		if !found || a.Basis == "" || a.Classify == nil {
			t.Errorf("%s: incomplete adapter", a.Service)
		}
	}
	if _, ok := Lookup("https://evil.example/"); ok {
		t.Fatal("lookup must be by catalog id only")
	}
}

// ---- egress verification -----------------------------------------------------

func TestVerifyEgress(t *testing.T) {
	ep := netip.MustParseAddr("203.0.113.5")
	cases := []struct {
		name   string
		fam    unlock.Family
		body   string
		region string
		expect netip.Addr
		ok     bool
		basis  string
		errHas string
	}{
		{"address and region match", unlock.FamilyIPv4, "fl=1\nip=203.0.113.5\nloc=HK\n", "hk", ep, true, "address", ""},
		{"region only", unlock.FamilyIPv4, "ip=198.51.100.9\nloc=HK\n", "hongkong", netip.Addr{}, true, "region", ""},
		{"fell back to the home line (CN)", unlock.FamilyIPv4, "ip=198.51.100.77\nloc=CN\n", "hk", netip.Addr{}, false, "", "CN"},
		{"pool failover to another member", unlock.FamilyIPv4, "ip=203.0.113.6\nloc=HK\n", "hk", ep, false, "", "203.0.113.6"},
		{"asked v4, got v6", unlock.FamilyIPv4, "ip=2001:db8::5\nloc=HK\n", "hk", netip.Addr{}, false, "", "IPv4"},
		{"asked v6, got v4", unlock.FamilyIPv6, "ip=203.0.113.5\nloc=HK\n", "hk", netip.Addr{}, false, "", "IPv6"},
		{"nothing to compare", unlock.FamilyIPv4, "ip=203.0.113.5\nloc=HK\n", "", netip.Addr{}, false, "", "无法确认"},
		{"garbage", unlock.FamilyIPv4, "<html>", "hk", netip.Addr{}, false, "", "ip / loc"},
	}
	for _, c := range cases {
		e := VerifyEgress(c.fam, []byte(c.body), c.region, c.expect)
		if e.Confirmed != c.ok || e.Basis != c.basis || (c.errHas != "" && !strings.Contains(e.Error, c.errHas)) {
			t.Errorf("%s: %+v", c.name, e)
		}
	}
}

// ---- running against fakes ---------------------------------------------------

// platform is an httptest TLS server standing in for every catalog host and
// the trace endpoint, with a certificate for all of them.
type platform struct {
	srv      *httptest.Server
	pool     *x509.CertPool
	mu       sync.Mutex
	hits     map[string]int
	cookies  []string
	traceIPs []string // successive trace answers (last one repeats)
	traceLoc string
	handlers map[string]http.HandlerFunc
	inflight int32
	maxIn    int32
}

func newPlatform(t *testing.T) *platform {
	t.Helper()
	p := &platform{hits: map[string]int{}, traceIPs: []string{"203.0.113.5"}, traceLoc: "HK", handlers: map[string]http.HandlerFunc{}}
	hosts := append([]string(nil), traceHosts...)
	for _, a := range Catalog {
		hosts = append(hosts, a.Hosts...)
	}
	hosts = append(hosts, "evil.example")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: hosts, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(cert)
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	p.srv.StartTLS()
	t.Cleanup(p.srv.Close)
	return p
}

func (p *platform) serve(w http.ResponseWriter, r *http.Request) {
	n := atomic.AddInt32(&p.inflight, 1)
	defer atomic.AddInt32(&p.inflight, -1)
	for {
		m := atomic.LoadInt32(&p.maxIn)
		if n <= m || atomic.CompareAndSwapInt32(&p.maxIn, m, n) {
			break
		}
	}
	host := r.Host
	p.mu.Lock()
	p.hits[host]++
	if c := r.Header.Get("Cookie"); c != "" {
		p.cookies = append(p.cookies, c)
	}
	h := p.handlers[host]
	var ip string
	if host == "www.cloudflare.com" {
		i := p.hits[host] - 1
		if i >= len(p.traceIPs) {
			i = len(p.traceIPs) - 1
		}
		ip = p.traceIPs[i]
	}
	loc := p.traceLoc
	p.mu.Unlock()
	if host == "www.cloudflare.com" {
		_, _ = w.Write([]byte("fl=1\nh=www.cloudflare.com\nip=" + ip + "\nloc=" + loc + "\n"))
		return
	}
	if h != nil {
		h(w, r)
		return
	}
	w.WriteHeader(200)
}

func (p *platform) count(host string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hits[host]
}

// fakeNet resolves every name to a documentation address of the asked
// family, reports a configurable egress device, and dials the test server.
type fakeNet struct {
	p     *platform
	fam   unlock.Family
	dev   string
	only  unlock.Family // if set, Resolve returns only this family
	mu    sync.Mutex
	dials []netip.AddrPort
}

func (f *fakeNet) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	fam := f.fam
	if f.only != "" {
		fam = f.only
	}
	if fam == unlock.FamilyIPv6 {
		return []netip.Addr{netip.MustParseAddr("2001:db8::80")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("203.0.113.80")}, nil
}

func (f *fakeNet) Route(_ context.Context, dst netip.Addr) (string, error) {
	if f.dev == "" {
		return "", errors.New("unreachable")
	}
	return f.dev, nil
}

func (f *fakeNet) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, dst)
	f.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.p.srv.Listener.Addr().String())
}

func managed(dev string) bool { return dev == "m00" || dev == "m00w" }

func newProber(p *platform, n Network) *Prober {
	return &Prober{Net: n, AllowIface: managed, RootCAs: p.pool, TargetTimeout: 2 * time.Second, Concurrency: 2}
}

func resultOf(rep Report, svc string) Result {
	for _, r := range rep.Results {
		if r.Service == svc {
			return r
		}
	}
	return Result{}
}

func TestRunPinnedHappyPath(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.netflix.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/title/81280792" {
			http.SetCookie(w, &http.Cookie{Name: "nfvdid", Value: "x"})
			http.Redirect(w, r, "https://www.netflix.com/hk-en/title/81280792?trkid=1", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"requestCountry":{"id":"HK"}}`))
	}
	p.handlers["www.disneyplus.com"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	}
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}
	rep := newProber(p, n).Run(context.Background(), Spec{
		ExitID: "hk-resi", Family: unlock.FamilyIPv4, Region: "hk", ExpectAddr: netip.MustParseAddr("203.0.113.5"),
		Services: []string{"auto-netflix", "auto-disney", "auto-gemini"},
	})
	if !rep.Egress.Confirmed || rep.Egress.Basis != "address" || rep.Egress.Interface != "m00" {
		t.Fatalf("egress: %+v", rep.Egress)
	}
	nf := resultOf(rep, "auto-netflix")
	if nf.Category != CatUnlocked || nf.Region != "hk" || strings.Contains(nf.Evidence, "trkid") {
		t.Fatalf("netflix: %+v", nf)
	}
	if len(p.cookies) != 0 {
		t.Fatalf("cookies must never be sent back: %v", p.cookies)
	}
	if p.count("evil.example") != 0 {
		t.Fatal("redirect to a host outside the adapter's list was followed")
	}
	if d := resultOf(rep, "auto-disney"); d.Category != CatUnknown {
		t.Fatalf("disney redirect off-list should be classified, not followed: %+v", d)
	}
	if g := resultOf(rep, "auto-gemini"); g.Category != CatNetworkOK {
		t.Fatalf("gemini: %+v", g)
	}
	for _, d := range n.dials {
		if !d.Addr().Is4() || d.Port() != 443 {
			t.Fatalf("v4 probe dialled %s", d)
		}
	}
	if p.count("www.cloudflare.com") != 2 {
		t.Fatalf("egress must be checked before and after: %d", p.count("www.cloudflare.com"))
	}
	for _, r := range rep.Results {
		if r.StartedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) || r.Family != unlock.FamilyIPv4 {
			t.Fatalf("times/family: %+v", r)
		}
	}
}

func TestRunRefusesNonTunnelRoute(t *testing.T) {
	for _, dev := range []string{"eth0", ""} {
		p := newPlatform(t)
		n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: dev}
		rep := newProber(p, n).Run(context.Background(), Spec{ExitID: "hk-ix", Family: unlock.FamilyIPv4, Region: "hk", Services: []string{"auto-netflix"}})
		if rep.Egress.Confirmed || len(n.dials) != 0 {
			t.Fatalf("dev %q: route outside the tunnel must not be dialled: %+v dials=%v", dev, rep.Egress, n.dials)
		}
		if r := resultOf(rep, "auto-netflix"); r.Category != CatFailed || !strings.Contains(r.Error, "出口未确认") {
			t.Fatalf("dev %q: %+v", dev, r)
		}
		if p.count("www.netflix.com") != 0 {
			t.Fatal("platform contacted without a confirmed egress")
		}
	}
}

func TestRunEgressMismatchNeverYieldsVerdict(t *testing.T) {
	p := newPlatform(t)
	p.traceLoc = "CN"
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}
	rep := newProber(p, n).Run(context.Background(), Spec{ExitID: "hk-ix", Family: unlock.FamilyIPv4, Region: "hk", Services: []string{"auto-netflix", "auto-openai"}})
	if rep.Egress.Confirmed || p.count("www.netflix.com") != 0 || p.count("api.openai.com") != 0 {
		t.Fatalf("egress CN on a HK exit: %+v", rep.Egress)
	}
	for _, r := range rep.Results {
		if r.Category != CatFailed {
			t.Fatalf("%+v", r)
		}
	}
}

func TestRunForcedFamilyNoFallback(t *testing.T) {
	p := newPlatform(t)
	// The exit resolver has only AAAA for everything; a v4 probe must fail,
	// not quietly use v6.
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00", only: unlock.FamilyIPv6}
	rep := newProber(p, n).Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyIPv4, Region: "hk", Services: []string{"auto-gemini"}})
	if rep.Egress.Confirmed || len(n.dials) != 0 || !strings.Contains(rep.Egress.Error, "ipv4") {
		t.Fatalf("%+v %v", rep.Egress, n.dials)
	}
	// And a v6 probe dials only v6 addresses.
	p6 := newPlatform(t)
	p6.traceIPs = []string{"2001:db8::5"}
	n6 := &fakeNet{p: p6, fam: unlock.FamilyIPv6, dev: "m00"}
	rep = newProber(p6, n6).Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyIPv6, Region: "hk", Services: []string{"auto-gemini"}})
	if !rep.Egress.Confirmed || resultOf(rep, "auto-gemini").Category != CatNetworkOK {
		t.Fatalf("v6: %+v %+v", rep.Egress, rep.Results)
	}
	for _, d := range n6.dials {
		if !d.Addr().Is6() {
			t.Fatalf("v6 probe dialled %s", d)
		}
	}
	// A v6 run whose trace says v4 (NAT64 or a v4 fallback somewhere) is refused.
	p64 := newPlatform(t)
	rep = newProber(p64, &fakeNet{p: p64, fam: unlock.FamilyIPv6, dev: "m00"}).Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyIPv6, Region: "hk", Services: []string{"auto-gemini"}})
	if rep.Egress.Confirmed || resultOf(rep, "auto-gemini").Category != CatFailed {
		t.Fatalf("v6 with v4 egress: %+v", rep.Egress)
	}
}

func TestRunEgressChangeVoidsResults(t *testing.T) {
	p := newPlatform(t)
	p.traceIPs = []string{"203.0.113.5", "203.0.113.6"}
	p.handlers["www.netflix.com"] = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"requestCountry":{"id":"HK"}}`))
	}
	rep := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}).Run(context.Background(), Spec{ExitID: "hk-resi", Family: unlock.FamilyIPv4, Region: "hk", Services: []string{"auto-netflix"}})
	r := resultOf(rep, "auto-netflix")
	if r.Category != CatFailed || !strings.Contains(r.Error, "203.0.113.6") || r.Region != "" {
		t.Fatalf("result after an egress change must be void: %+v", r)
	}
}

func TestRunTimeoutCancelAndConcurrency(t *testing.T) {
	p := newPlatform(t)
	release := make(chan struct{})
	slow := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}
	p.handlers["gemini.google.com"] = slow
	p.handlers["copilot.microsoft.com"] = func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
	}
	p.handlers["www.perplexity.ai"] = p.handlers["copilot.microsoft.com"]
	p.handlers["grok.x.ai"] = p.handlers["copilot.microsoft.com"]
	pr := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"})
	pr.TargetTimeout = 600 * time.Millisecond
	start := time.Now()
	rep := pr.Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyIPv4, Region: "hk",
		Services: []string{"auto-gemini", "auto-copilot", "auto-perplexity", "auto-grok"}})
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("per-service timeout not enforced: %s", el)
	}
	if g := resultOf(rep, "auto-gemini"); g.Category != CatFailed || g.Error != "超时" {
		t.Fatalf("timeout: %+v", g)
	}
	if c := resultOf(rep, "auto-copilot"); c.Category != CatNetworkOK {
		t.Fatalf("a slow neighbour must not fail others: %+v", c)
	}
	// Two services at most at once, plus nothing else in flight.
	if m := atomic.LoadInt32(&p.maxIn); m > 2 {
		t.Fatalf("concurrency cap exceeded: %d", m)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	pr.TargetTimeout = 5 * time.Second
	rep = pr.Run(ctx, Spec{ExitID: "us", Family: unlock.FamilyIPv4, Region: "hk", Services: []string{"auto-gemini"}})
	close(release)
	if g := resultOf(rep, "auto-gemini"); g.Category != CatFailed || g.Error != "已取消" {
		t.Fatalf("cancel: %+v", g)
	}
}

func TestRunRejectsUnknownServiceAndFamily(t *testing.T) {
	p := newPlatform(t)
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}
	rep := newProber(p, n).Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyAny, Region: "us", Services: []string{"auto-gemini"}})
	if rep.Results[0].Category != CatFailed || len(n.dials) != 0 {
		t.Fatalf("%+v", rep)
	}
	rep = newProber(p, n).Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyIPv4, Region: "us", Services: []string{"auto-bahamut"}})
	if rep.Results[0].Category != CatFailed || len(n.dials) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestPinnedRefusesWithoutMarkOffLinux(t *testing.T) {
	// On the dev machine (not Linux) a pinned dial must fail, never fall
	// back to an unmarked socket. On Linux without CAP_NET_ADMIN it fails too.
	pin := Pinned{Mark: 0x101, Family: unlock.FamilyIPv4, Src4: netip.MustParseAddr("127.0.0.1"), Src6: netip.MustParseAddr("::1"), Resolver: netip.MustParseAddr("::1"), Timeout: time.Second}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	c, err := pin.Dial(context.Background(), netip.MustParseAddrPort(l.Addr().String()))
	if err == nil {
		c.Close()
		t.Skip("SO_MARK allowed here (Linux as root); nothing to assert")
	}
	if !errors.Is(err, ErrEgress) && !strings.Contains(err.Error(), "SO_MARK") && !strings.Contains(err.Error(), "fwmark") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := pin.Dial(context.Background(), netip.MustParseAddrPort("[::1]:443")); !errors.Is(err, ErrEgress) {
		t.Fatalf("a v6 destination on a v4 pin must be refused: %v", err)
	}
}
