package probe

// Body limits and truncation. Every body here is SYNTHETIC: generated in
// the test from neutral filler plus the documented markers at chosen
// offsets. Nothing was captured from a platform; no large file is committed.

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/unlock"
)

// syntheticBody returns a body of exactly size bytes of neutral filler with
// each marker written at its offset (markers must not overlap).
func syntheticBody(size int, at map[int]string) []byte {
	const filler = "<div class=\"synthetic\">lorem ipsum filler</div>\n"
	b := []byte(strings.Repeat(filler, size/len(filler)+1)[:size])
	for off, m := range at {
		copy(b[off:], m)
	}
	return b
}

func serveBody(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}
}

func runService(t *testing.T, p *platform, service, region string) Result {
	t.Helper()
	p.traceLoc = strings.ToUpper(region)
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}
	rep := newProber(p, n).Run(context.Background(), Spec{
		ExitID: "exit-1", Family: unlock.FamilyIPv4, Region: region, ExpectAddr: netip.MustParseAddr("203.0.113.5"),
		Services: []string{service},
	})
	if !rep.Egress.Confirmed {
		t.Fatalf("egress not confirmed: %+v", rep.Egress)
	}
	return resultOf(rep, service)
}

const ytGL = `"INNERTUBE_CONTEXT_GL":"US"`

func TestStepBodyLimitValidation(t *testing.T) {
	for _, n := range []int{-1, MaxBodyCeiling + 1, 1 << 30} {
		if checkBodyLimit(n) == nil {
			t.Errorf("limit %d must be rejected", n)
		}
	}
	for _, n := range []int{0, 1, MaxBody, youtubePremiumMaxBody, MaxBodyCeiling} {
		if checkBodyLimit(n) != nil {
			t.Errorf("limit %d must be accepted", n)
		}
	}
	if (Step{}).bodyLimit() != MaxBody || (Step{MaxBody: -5}).bodyLimit() != MaxBody || (Step{MaxBody: MaxBodyCeiling * 2}).bodyLimit() != MaxBody {
		t.Fatal("default / invalid limit must be MaxBody")
	}
	if MaxBody != 256<<10 || youtubePremiumMaxBody != 2<<20 || disneyMaxBody != 2<<20 || netflixMaxBody != 2<<20 || MaxBodyCeiling != 4<<20 {
		t.Fatal("limits changed")
	}
	// Only the youtube-premium, auto-disney, auto-netflix, auto-gemini and metaai steps declare a larger limit.
	for _, a := range Catalog {
		for _, c := range a.Checks {
			for _, st := range c.Steps {
				if err := checkBodyLimit(st.MaxBody); err != nil {
					t.Errorf("%s: %v", a.Service, err)
				}
				want := 0
				switch a.Service {
				case "youtube-premium":
					want = youtubePremiumMaxBody
				case "auto-disney":
					want = disneyMaxBody
				case "auto-netflix":
					want = netflixMaxBody
				case "auto-gemini":
					want = geminiMaxBody
				case "metaai":
					want = metaAIMaxBody
				}
				if st.MaxBody != want {
					t.Errorf("%s: step body limit %d, want %d", a.Service, st.MaxBody, want)
				}
			}
		}
	}
}

// The YouTube Premium section of docs/unlock-methods.md mirrors the
// catalog's Basis and Limits exactly.
func TestYouTubePremiumDocMatchesCatalog(t *testing.T) {
	doc, err := os.ReadFile("../../docs/unlock-methods.md")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Lookup("youtube-premium")
	if !strings.Contains(string(doc), "- 判断："+a.Basis+"\n") || !strings.Contains(string(doc), "- 限制："+a.Limits+"\n") {
		t.Fatal("youtube-premium 判断/限制 in docs/unlock-methods.md differ from the catalog")
	}
	if !strings.Contains(a.Basis, "2 MiB") || !strings.Contains(a.Limits, "2026-11-15") {
		t.Fatal("catalog text must state the larger limit and the observation")
	}
}

// Through the real fetch path against the local TLS fake: markers past the
// default 256 KiB but inside the step's 2 MiB are read.
func TestYouTubePremiumLateMarkers(t *testing.T) {
	const size = 975_000
	cases := []struct {
		name       string
		body       []byte
		want       Category
		wantRegion string
		wantSignal string
	}{
		{"ad-free late", syntheticBody(size, map[int]string{60_000: ytGL, 850_000: "Enjoy ad-free videos", 900_000: "ad-free"}), CatUnlocked, "us", SigAvailable},
		{"not available late", syntheticBody(size, map[int]string{60_000: ytGL, 900_000: "Premium is not available in your country"}), CatNotUnlocked, "", SigBlocked},
		{"google.cn late", syntheticBody(size, map[int]string{60_000: ytGL, 900_000: `<a href="https://www.google.cn/">`}), CatNotUnlocked, "cn", SigBlocked},
		{"consent first even with late ad-free", syntheticBody(size, map[int]string{100: `<form action="https://consent.youtube.com/save" method="POST">`, 850_000: "ad-free"}), CatUnknown, "", SigConsent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPlatform(t)
			p.handlers["www.youtube.com"] = serveBody(c.body)
			res := runService(t, p, "youtube-premium", "us")
			if res.Category != c.want || res.Region != c.wantRegion || res.Signal != c.wantSignal {
				t.Fatalf("got %s/%q/%s (%s)", res.Category, res.Region, res.Signal, res.Evidence)
			}
			if strings.Contains(res.Evidence, "截断") {
				t.Fatalf("a body inside the limit is not truncated: %s", res.Evidence)
			}
		})
	}
}

// A marker beyond the step's 2 MiB limit is not read: unknown, with
// truncation evidence instead of "page may have changed".
func TestYouTubePremiumMarkerBeyondLimit(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.youtube.com"] = serveBody(syntheticBody(youtubePremiumMaxBody+4096, map[int]string{60_000: ytGL, youtubePremiumMaxBody + 100: "ad-free"}))
	res := runService(t, p, "youtube-premium", "us")
	if res.Category != CatUnknown || res.Signal != SigUnexpected {
		t.Fatalf("got %+v", res)
	}
	if !strings.Contains(res.Evidence, "正文被截断：只读了前 2048 KiB（上限 2048 KiB）") || strings.Contains(res.Evidence, "页面可能改版") {
		t.Fatalf("evidence: %s", res.Evidence)
	}

	// A consent page keeps its own result, truncated or not.
	p = newPlatform(t)
	p.handlers["www.youtube.com"] = serveBody(syntheticBody(youtubePremiumMaxBody+4096, map[int]string{100: "<h1>Before you continue to YouTube</h1>"}))
	res = runService(t, p, "youtube-premium", "us")
	if res.Category != CatUnknown || res.Signal != SigConsent || strings.Contains(res.Evidence, "截断") {
		t.Fatalf("consent on a truncated body: %+v", res)
	}
}

// An adapter with the default limit: a body over 256 KiB with no marker is
// unknown with truncation evidence; a body of exactly 256 KiB is not.
func TestDefaultLimitTruncation(t *testing.T) {
	p := newPlatform(t)
	p.handlers["tubitv.com"] = serveBody(syntheticBody(300<<10, nil))
	res := runService(t, p, "tubi", "us")
	if res.Category != CatUnknown || res.Signal != SigUnexpected || !strings.Contains(res.Evidence, "正文被截断：只读了前 256 KiB（上限 256 KiB），没有读到判定标记") {
		t.Fatalf("truncated default: %+v", res)
	}

	p = newPlatform(t)
	p.handlers["tubitv.com"] = serveBody(syntheticBody(MaxBody, nil))
	res = runService(t, p, "tubi", "us")
	if res.Category != CatUnknown || res.Signal != SigUnexpected || strings.Contains(res.Evidence, "截断") {
		t.Fatalf("exactly the limit is complete: %+v", res)
	}

	// A marker inside the default limit still decides on a truncated body.
	p = newPlatform(t)
	p.handlers["tubitv.com"] = serveBody(syntheticBody(300<<10, map[int]string{1000: "manifest"}))
	res = runService(t, p, "tubi", "us")
	if res.Category != CatNetworkOK || strings.Contains(res.Evidence, "截断") {
		t.Fatalf("marker found: %+v", res)
	}
}

// fetch reads one byte past the limit to tell a complete body of exactly
// the limit from a longer one.
func TestFetchTruncationFlag(t *testing.T) {
	hosts := []string{"tubitv.com"}
	for _, c := range []struct {
		size      int
		step      Step
		wantLen   int
		wantLimit int
		truncated bool
	}{
		{MaxBody - 1, Step{}, MaxBody - 1, MaxBody, false},
		{MaxBody, Step{}, MaxBody, MaxBody, false},
		{MaxBody + 1, Step{}, MaxBody, MaxBody, true},
		{youtubePremiumMaxBody, Step{MaxBody: youtubePremiumMaxBody}, youtubePremiumMaxBody, youtubePremiumMaxBody, false},
		{youtubePremiumMaxBody + 1, Step{MaxBody: youtubePremiumMaxBody}, youtubePremiumMaxBody, youtubePremiumMaxBody, true},
	} {
		p := newPlatform(t)
		p.handlers["tubitv.com"] = serveBody(syntheticBody(c.size, nil))
		pr := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"})
		c.step.URL = "https://tubitv.com/home"
		r, err := pr.fetch(context.Background(), unlock.FamilyIPv4, c.step, c.step.URL, hosts, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Body) != c.wantLen || r.Limit != c.wantLimit || r.Truncated != c.truncated {
			t.Errorf("size %d: len=%d limit=%d truncated=%v", c.size, len(r.Body), r.Limit, r.Truncated)
		}
	}
}

// Truncation only annotates an unexpected unknown; it never changes a
// category or another signal.
func TestNoteTruncatedScope(t *testing.T) {
	r := Response{Status: 200, Body: make([]byte, 1024), Limit: 1024, Truncated: true}
	for _, v := range []Verdict{
		{Category: CatUnlocked, Signal: SigAvailable, Evidence: "x"},
		{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "x"},
		{Category: CatUnknown, Signal: SigChallenge, Evidence: "x"},
		{Category: CatUnknown, Signal: SigRateLimited, Evidence: "x"},
		{Category: CatUnknown, Signal: SigConsent, Evidence: "x"},
		{Category: CatUnknown, Signal: SigLoginRequired, Evidence: "x"},
		{Category: CatUnknown, Signal: SigRedirect, Evidence: "x"},
	} {
		if got := noteTruncated(v, r); got != v {
			t.Errorf("%+v changed to %+v", v, got)
		}
	}
	v := noteTruncated(Verdict{Category: CatUnknown, Signal: SigUnexpected, Evidence: "HTTP 200，但没有标记（页面可能改版或要求登录）"}, r)
	if v.Category != CatUnknown || v.Signal != SigUnexpected || v.Evidence != "HTTP 200，但没有标记；正文被截断：只读了前 1 KiB（上限 1 KiB），没有读到判定标记（不能据此认为页面改版）" {
		t.Fatalf("got %+v", v)
	}
	// Not truncated: untouched.
	plain := Verdict{Category: CatUnknown, Signal: SigUnexpected, Evidence: "HTTP 200（页面可能改版）"}
	if noteTruncated(plain, Response{Status: 200, Body: make([]byte, 1024), Limit: 1024}) != plain {
		t.Fatal("complete body annotated")
	}
	// Through a catalog classifier (guarded): the YouTube "no marker"
	// evidence becomes the truncation evidence.
	_, c := checkOf(t, "youtube-premium", "")
	got := c.Classify(Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte("<html>"), Limit: 2 << 20, Truncated: true}, "us")
	if got.Category != CatUnknown || got.Signal != SigUnexpected || strings.Contains(got.Evidence, "页面可能改版") || !strings.Contains(got.Evidence, "正文被截断") {
		t.Fatalf("classifier: %+v", got)
	}
}

// The Disney+ section of docs/unlock-methods.md mirrors the catalog's Basis
// and Limits exactly.
func TestDisneyDocMatchesCatalog(t *testing.T) {
	doc, err := os.ReadFile("../../docs/unlock-methods.md")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Lookup("auto-disney")
	if !strings.Contains(string(doc), "- 判断："+a.Basis+"\n") || !strings.Contains(string(doc), "- 限制："+a.Limits+"\n") {
		t.Fatal("auto-disney 判断/限制 in docs/unlock-methods.md differ from the catalog")
	}
	if !strings.Contains(a.Basis, "2 MiB") || !strings.Contains(a.Limits, "2026-11-15") || !strings.Contains(a.Limits, "未对真实平台验证") {
		t.Fatal("catalog text must state the larger limit, the observation and the unverified status")
	}
}

const (
	disneyLoc = `"hasContent":true,"language":"en","location":"HK","pageId":"welcome","region":"us","remoteConfig":{}`
	// The fixed region alone, as seen on every exit.
	disneyRegionOnly = `"hasContent":true,"language":"en","pageId":"welcome","region":"us","remoteConfig":{}`
)

// Through the real fetch path: the location marker after the default
// 256 KiB and inside the step's 2 MiB decides; at a realistic ~1.95 MB page
// and ~860 KB offset it also matches/mismatches the exit.
func TestDisneyLateLocation(t *testing.T) {
	const size = 1_950_000
	cases := []struct {
		name       string
		exit       string
		body       []byte
		want       Category
		wantRegion string
		wantSignal string
	}{
		{"location matches exit", "hk", syntheticBody(size, map[int]string{860_000: disneyLoc}), CatUnlocked, "hk", SigRegionMatch},
		{"location is not the fixed region", "us", syntheticBody(size, map[int]string{860_000: disneyLoc}), CatNotUnlocked, "hk", SigRegionMismatch},
		{"only fixed region, no location", "hk", syntheticBody(size, map[int]string{860_000: disneyRegionOnly}), CatUnknown, "", SigUnexpected},
		{"conflicting locations", "hk", syntheticBody(size, map[int]string{860_000: disneyLoc, 1_200_000: `"location":"US","pageId":"x"`}), CatUnknown, "", SigUnexpected},
		{"no markers", "hk", syntheticBody(size, nil), CatUnknown, "", SigUnexpected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPlatform(t)
			p.handlers["www.disneyplus.com"] = serveBody(c.body)
			res := runService(t, p, "auto-disney", c.exit)
			if res.Category != c.want || res.Region != c.wantRegion || res.Signal != c.wantSignal {
				t.Fatalf("got %s/%q/%s (%s)", res.Category, res.Region, res.Signal, res.Evidence)
			}
			if strings.Contains(res.Evidence, "截断") {
				t.Fatalf("a page inside the limit is not truncated: %s", res.Evidence)
			}
		})
	}
}

// A marker beyond the step's 2 MiB limit is unknown with truncation
// evidence; with the default 256 KiB it would not have been reached.
func TestDisneyLocationBeyondLimit(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.disneyplus.com"] = serveBody(syntheticBody(disneyMaxBody+4096, map[int]string{disneyMaxBody + 100: disneyLoc}))
	res := runService(t, p, "auto-disney", "hk")
	if res.Category != CatUnknown || res.Signal != SigUnexpected {
		t.Fatalf("got %+v", res)
	}
	if !strings.Contains(res.Evidence, "正文被截断：只读了前 2048 KiB（上限 2048 KiB）") || strings.Contains(res.Evidence, "页面可能改版") {
		t.Fatalf("evidence: %s", res.Evidence)
	}
}

// The existing redirect and 403 verdicts are unchanged through the fetch path.
func TestDisneyUnavailableRedirectAndForbidden(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.disneyplus.com"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.disneyplus.com/unavailable", http.StatusFound)
	}
	p.handlers["disneyplus.com"] = p.handlers["www.disneyplus.com"]
	res := runService(t, p, "auto-disney", "hk")
	if res.Category != CatNotUnlocked || res.Signal != SigBlocked {
		t.Fatalf("unavailable redirect: %+v", res)
	}
	p = newPlatform(t)
	p.handlers["www.disneyplus.com"] = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }
	res = runService(t, p, "auto-disney", "hk")
	if res.Category != CatNotUnlocked || res.Signal != SigBlocked403 {
		t.Fatalf("403: %+v", res)
	}
}

// The Netflix section of docs/unlock-methods.md mirrors the catalog's Basis
// and Limits exactly.
func TestNetflixDocMatchesCatalog(t *testing.T) {
	doc, err := os.ReadFile("../../docs/unlock-methods.md")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Lookup("auto-netflix")
	if !strings.Contains(string(doc), "- 判断："+a.Basis+"\n") || !strings.Contains(string(doc), "- 限制："+a.Limits+"\n") {
		t.Fatal("auto-netflix 判断/限制 in docs/unlock-methods.md differ from the catalog")
	}
	if !strings.Contains(a.Basis, "2 MiB") || !strings.Contains(a.Limits, "2026-11-15") || !strings.Contains(a.Limits, "未对真实平台验证") {
		t.Fatal("catalog text must state the larger limit, the observation and the unverified status")
	}
	for _, text := range []string{a.Basis, a.Limits} {
		if strings.Contains(text, "其他检测项都是 256 KiB") {
			t.Fatal("outdated 256 KiB wording")
		}
	}
	for _, name := range []string{"youtube-premium", "auto-disney"} {
		b, _ := Lookup(name)
		if strings.Contains(b.Basis, "其他检测项都是") {
			t.Fatalf("%s: outdated 'all other items are 256 KiB' wording", name)
		}
	}
}

// Observed shape (2026-11-15, Hong Kong exit): the visitor country next to
// look-alike preference fields and no countryCode.
const (
	nfReqHK = `"requestCountry":{"supportedLocales":["zh","en"],"id":"HK","countryName":"Hong Kong"},` +
		`"geo":{"supportedLocales":[{"id":"zh","locale":"zh-HK","country":"HK"}]},` +
		`"preferredLocale":{"id":"en-HK","country":"HK","language":"en"},"currentCountry":null`
	nfReqUS = `"requestCountry":{"supportedLocales":["en"],"id":"US","countryName":"United States"}`
)

func nfServe(body []byte, redirectTo string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if redirectTo != "" && r.URL.Path != redirectTo {
			http.Redirect(w, r, "https://www.netflix.com"+redirectTo, http.StatusFound)
			return
		}
		serveBody(body)(w, r)
	}
}

// Through the real fetch path: no URL prefix, the requestCountry marker
// after the default 256 KiB and inside the step's 2 MiB.
func TestNetflixRequestCountryBeyondDefault(t *testing.T) {
	const size = 700_000
	const at = 454_000
	us := syntheticBody(size, map[int]string{at: nfReqUS})
	cases := []struct {
		name, exit, redirect string
		body                 []byte
		want                 Category
		wantRegion, signal   string
	}{
		{"US no prefix on US exit", "us", "", us, CatUnlocked, "us", SigRegionMatch},
		{"US no prefix on non-US exit", "hk", "", us, CatNotUnlocked, "us", SigRegionMismatch},
		{"misleading countryCode ignored", "us", "", syntheticBody(size, map[int]string{1000: `"countryCode":"HK"`, at: nfReqUS}), CatUnlocked, "us", SigRegionMatch},
		{"countryCode alone is no basis", "hk", "", syntheticBody(size, map[int]string{1000: `"countryCode":"HK"`}), CatUnknown, "", SigUnexpected},
		{"conflicting requestCountry", "us", "", syntheticBody(size, map[int]string{at: nfReqUS, at + 5000: `"requestCountry":{"id":"HK"}`}), CatUnknown, "", SigUnexpected},
		{"same requestCountry repeated", "hk", "", syntheticBody(size, map[int]string{at: nfReqHK, at + 700: nfReqHK, at + 1400: nfReqHK}), CatUnlocked, "hk", SigRegionMatch},
		{"observed HK shape, preference fields not used", "us", "", syntheticBody(size, map[int]string{at: nfReqHK}), CatNotUnlocked, "hk", SigRegionMismatch},
		{"preferredLocale and geo only", "hk", "", syntheticBody(size, map[int]string{at: `"geo":{"supportedLocales":[{"id":"zh","locale":"zh-HK","country":"HK"}]},"preferredLocale":{"id":"en-HK","country":"HK"}`}), CatUnknown, "", SigUnexpected},
		{"prefix and matching requestCountry", "hk", "/hk-en/title/81280792", syntheticBody(size, map[int]string{at: nfReqHK}), CatUnlocked, "hk", SigRegionMatch},
		{"prefix and different requestCountry", "hk", "/hk-en/title/81280792", syntheticBody(size, map[int]string{at: nfReqUS}), CatUnknown, "", SigUnexpected},
		{"prefix only", "hk", "/hk-en/title/81280792", syntheticBody(size, nil), CatUnlocked, "hk", SigRegionMatch},
		{"language-only prefix, no requestCountry", "jp", "/ja/title/81280792", syntheticBody(size, nil), CatUnknown, "", SigUnexpected},
		{"language-only prefix with requestCountry", "jp", "/ja/title/81280792", syntheticBody(size, map[int]string{at: `"requestCountry":{"id":"JP"}`}), CatUnlocked, "jp", SigRegionMatch},
		{"no marker at all", "us", "", syntheticBody(size, nil), CatUnknown, "", SigUnexpected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPlatform(t)
			p.handlers["www.netflix.com"] = nfServe(c.body, c.redirect)
			res := runService(t, p, "auto-netflix", c.exit)
			if res.Category != c.want || res.Region != c.wantRegion || res.Signal != c.signal {
				t.Fatalf("got %s/%q/%s (%s)", res.Category, res.Region, res.Signal, res.Evidence)
			}
			if strings.Contains(res.Evidence, "截断") {
				t.Fatalf("a page inside the limit is not truncated: %s", res.Evidence)
			}
		})
	}
}

// A marker beyond the step's 2 MiB limit is unknown with truncation evidence.
func TestNetflixRequestCountryBeyondLimit(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.netflix.com"] = serveBody(syntheticBody(netflixMaxBody+4096, map[int]string{netflixMaxBody + 100: nfReqUS}))
	res := runService(t, p, "auto-netflix", "us")
	if res.Category != CatUnknown || res.Signal != SigUnexpected {
		t.Fatalf("got %+v", res)
	}
	if !strings.Contains(res.Evidence, "正文被截断：只读了前 2048 KiB（上限 2048 KiB）") || strings.Contains(res.Evidence, "页面可能改版") {
		t.Fatalf("evidence: %s", res.Evidence)
	}
}

// The existing 403 and 404 verdicts are unchanged through the fetch path.
func TestNetflixForbiddenAndNotFound(t *testing.T) {
	for _, c := range []struct {
		status int
		signal string
	}{{http.StatusForbidden, SigBlocked403}, {http.StatusNotFound, SigBlocked}} {
		p := newPlatform(t)
		st := c.status
		p.handlers["www.netflix.com"] = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(st) }
		res := runService(t, p, "auto-netflix", "hk")
		if res.Category != CatNotUnlocked || res.Signal != c.signal {
			t.Fatalf("%d: %+v", c.status, res)
		}
	}
}
