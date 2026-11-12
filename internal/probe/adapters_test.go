package probe

// Adapter fixtures.
//
// SYNTHETIC FIXTURES: every response body below was written by hand for
// this test to match the markers documented in docs/unlock-methods.md (and
// the public scripts cited there). None of them was captured from a real
// platform, and none contains cookies, tokens, account data or personal
// data. Passing these tests says the classifiers implement the documented
// rules; it says nothing about how the real platforms answer today.

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/unlock"
)

type fixture struct {
	name       string
	service    string
	platform   string // empty: the primary check
	region     string // the exit's region
	resp       Response
	want       Category
	wantRegion string
	wantSignal string
}

func checkOf(t *testing.T, service, platform string) (Adapter, Check) {
	t.Helper()
	a, ok := Lookup(service)
	if !ok {
		t.Fatalf("no adapter %s", service)
	}
	for _, c := range a.Checks {
		if (platform == "" && c.Primary) || c.Platform == platform {
			return a, c
		}
	}
	t.Fatalf("%s: no check %q", service, platform)
	return a, Check{}
}

const (
	challengeBody = `<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id="cf-chl-widget">synthetic</div></body></html>`
	loginBody     = `<html><body>synthetic login page</body></html>`
)

var fixtures = []fixture{
	// Netflix (region verdict)
	{"netflix 403", "auto-netflix", "", "hk", Response{Status: 403, URL: u("https://www.netflix.com/title/81280792")}, CatNotUnlocked, "", SigBlocked403},
	{"netflix 404 originals only", "auto-netflix", "", "hk", Response{Status: 404, URL: u("https://www.netflix.com/title/81280792")}, CatNotUnlocked, "", SigBlocked},
	{"netflix HK on HK exit", "auto-netflix", "", "hk", Response{Status: 200, URL: u("https://www.netflix.com/hk-en/title/81280792"),
		Body: []byte(`<script>netflix.reactContext = {"models":{"geo":{"data":{"requestCountry":{"id":"HK","supported":true}}}}}</script>`)}, CatUnlocked, "hk", SigRegionMatch},
	{"netflix US catalog on HK exit", "auto-netflix", "", "hongkong", Response{Status: 200, URL: u("https://www.netflix.com/title/81280792"), Body: []byte(`{"requestCountry":{"id":"US"}}`)}, CatNotUnlocked, "us", SigRegionMismatch},
	{"netflix path region only", "auto-netflix", "", "jp", Response{Status: 200, URL: u("https://www.netflix.com/jp/title/81280792")}, CatUnlocked, "jp", SigRegionMatch},
	{"netflix login wall", "auto-netflix", "", "us", Response{Status: 200, URL: u("https://www.netflix.com/login"), Body: []byte(loginBody)}, CatUnknown, "", SigLoginRequired},
	{"netflix no marker", "auto-netflix", "", "us", Response{Status: 200, URL: u("https://www.netflix.com/title/81280792"), Body: []byte("<html>")}, CatUnknown, "", SigUnexpected},
	{"netflix 500", "auto-netflix", "", "us", Response{Status: 500, URL: u("https://www.netflix.com/title/81280792")}, CatUnknown, "", SigServerError},
	{"netflix challenge 403", "auto-netflix", "", "us", Response{Status: 403, URL: u("https://www.netflix.com/title/81280792"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},

	// Disney+ (region verdict)
	{"disney unavailable redirect", "auto-disney", "", "hk", Response{Status: 302, URL: u("https://www.disneyplus.com/unavailable")}, CatNotUnlocked, "", SigBlocked},
	{"disney preview page", "auto-disney", "", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/en-hk/preview")}, CatNotUnlocked, "", SigBlocked},
	{"disney 403", "auto-disney", "", "hk", Response{Status: 403, URL: u("https://www.disneyplus.com/")}, CatNotUnlocked, "", SigBlocked403},
	{"disney body region", "auto-disney", "", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/"), Body: []byte(`{"countryCode":"HK"}`)}, CatUnlocked, "hk", SigRegionMatch},
	{"disney lang-region path, wrong region", "auto-disney", "", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/en-sg")}, CatNotUnlocked, "sg", SigRegionMismatch},
	{"disney 200 nothing", "auto-disney", "", "hk", Response{Status: 200, URL: u("https://www.disneyplus.com/")}, CatUnknown, "", SigUnexpected},
	{"disney off-list redirect", "auto-disney", "", "hk", Response{Status: 302, URL: u("https://evil.example/steal")}, CatUnknown, "", SigRedirect},

	// OpenAI (verdict, no region)
	{"openai unsupported", "auto-openai", "", "us", Response{Status: 403, URL: u("https://api.openai.com/compliance/cookie_requirements"),
		Body: []byte(`{"error":{"code":"unsupported_country","message":"synthetic"}}`)}, CatNotUnlocked, "", SigBlocked},
	{"openai json without marker", "auto-openai", "", "us", Response{Status: 401, URL: u("https://api.openai.com/compliance/cookie_requirements"), Body: []byte(`{"error":{"code":"invalid_api_key"}}`)}, CatUnlocked, "", SigNoNegative},
	{"openai html instead of json", "auto-openai", "", "us", Response{Status: 200, URL: u("https://api.openai.com/compliance/cookie_requirements"), Body: []byte(`<html>changed</html>`)}, CatUnknown, "", SigUnexpected},
	{"openai challenge", "auto-openai", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
	{"openai 502", "auto-openai", "", "us", Response{Status: 502}, CatUnknown, "", SigServerError},
	{"chatgpt ios vpn", "auto-openai", "ChatGPT iOS", "us", Response{Status: 403, URL: u("https://ios.chat.openai.com/"), Body: []byte(`synthetic: VPN detected`)}, CatNotUnlocked, "", SigBlocked},
	{"chatgpt ios ok", "auto-openai", "ChatGPT iOS", "us", Response{Status: 200, URL: u("https://ios.chat.openai.com/"), Body: []byte(`ok`)}, CatUnlocked, "", SigNoNegative},
	{"chatgpt ios challenge", "auto-openai", "ChatGPT iOS", "us", Response{Status: 403, URL: u("https://ios.chat.openai.com/"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},

	// Claude (verdict)
	{"claude unavailable", "auto-anthropic", "", "us", Response{Status: 307, URL: u("https://www.anthropic.com/app-unavailable-in-region")}, CatNotUnlocked, "", SigBlocked},
	{"claude challenge", "auto-anthropic", "", "us", Response{Status: 403, URL: u("https://claude.ai/"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
	{"claude ok (login page on claude.ai)", "auto-anthropic", "", "us", Response{Status: 200, URL: u("https://claude.ai/login")}, CatUnlocked, "", SigNoNegative},
	{"claude 403 plain", "auto-anthropic", "", "us", Response{Status: 403, URL: u("https://claude.ai/")}, CatUnknown, "", SigUnexpected},

	// Gemini (verdict, region informational)
	{"gemini available with country", "auto-gemini", "", "us", Response{Status: 200, URL: u("https://gemini.google.com/app"),
		Body: []byte(`synthetic [[...,45631641,null,true,...],[...,2,1,200,"USA"]]`)}, CatUnlocked, "us", SigAvailable},
	{"gemini available, no country", "auto-gemini", "", "us", Response{Status: 200, URL: u("https://gemini.google.com/"), Body: []byte(`x,45631641,null,true,y`)}, CatUnlocked, "", SigAvailable},
	{"gemini available, other country is informational", "auto-gemini", "", "us", Response{Status: 200, URL: u("https://gemini.google.com/"), Body: []byte(`45631641,null,true ,2,1,200,"JPN"`)}, CatUnlocked, "jp", SigAvailable},
	{"gemini 403", "auto-gemini", "", "us", Response{Status: 403, URL: u("https://gemini.google.com/")}, CatNotUnlocked, "", SigBlocked403},
	{"gemini consent", "auto-gemini", "", "us", Response{Status: 302, URL: u("https://consent.google.com/ml")}, CatUnknown, "", SigConsent},
	{"gemini changed page", "auto-gemini", "", "us", Response{Status: 200, URL: u("https://gemini.google.com/"), Body: []byte(`<html>new layout</html>`)}, CatUnknown, "", SigUnexpected},

	// Copilot (verdict, region informational)
	{"copilot blocked redirect to /", "auto-copilot", "", "us", Response{Status: 302, URL: u("https://copilot.microsoft.com/")}, CatNotUnlocked, "", SigBlocked},
	{"copilot 403", "auto-copilot", "", "us", Response{Status: 403, URL: u("https://copilot.microsoft.com/c/api/user")}, CatNotUnlocked, "", SigBlocked403},
	{"copilot ok", "auto-copilot", "", "us", Response{Status: 200, URL: u("https://copilot.microsoft.com/c/api/user"), Body: []byte(`{"regionCode":"US","synthetic":true}`)}, CatUnlocked, "us", SigAvailable},
	{"copilot login redirect elsewhere", "auto-copilot", "", "us", Response{Status: 302, URL: u("https://login.microsoftonline.com/x")}, CatUnknown, "", SigRedirect},
	{"copilot 200 without region", "auto-copilot", "", "us", Response{Status: 200, URL: u("https://copilot.microsoft.com/c/api/user"), Body: []byte(`{}`)}, CatUnknown, "", SigUnexpected},

	// Perplexity / Grok (reachability only)
	{"perplexity any answer", "auto-perplexity", "", "us", Response{Status: 403, URL: u("https://www.perplexity.ai/")}, CatNetworkOK, "", SigReachable},
	{"perplexity challenge", "auto-perplexity", "", "us", Response{Status: 403, URL: u("https://www.perplexity.ai/"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
	{"grok answer", "auto-grok", "", "us", Response{Status: 200, URL: u("https://grok.com/")}, CatNetworkOK, "", SigReachable},
	{"grok 503", "auto-grok", "", "us", Response{Status: 503, URL: u("https://grok.com/")}, CatUnknown, "", SigServerError},

	// Bahamut (region verdict; Prev[1] is the sn=38832 token)
	{"bahamut TW", "auto-bahamut", "", "tw", bahamut(`{"animeSn":38832}`, `{"animeSn":37783}`), CatUnlocked, "tw", SigRegionMatch},
	{"bahamut HK/MO on TW exit", "auto-bahamut", "", "tw", bahamut(`{"error":{"code":1011}}`, `{"animeSn":37783}`), CatNotUnlocked, "hk", SigRegionMismatch},
	{"bahamut neither is unknown", "auto-bahamut", "", "tw", bahamut(`{"error":{"code":1011}}`, `{"error":{"code":1011}}`), CatUnknown, "", SigUnexpected},
	{"bahamut challenge on token", "auto-bahamut", "", "tw", bahamut(challengeBody, challengeBody), CatUnknown, "", SigChallenge},

	// KKTV (region verdict)
	{"kktv TW allowed", "auto-kktv", "", "tw", Response{Status: 200, URL: u("https://api.kktv.me/v3/ipcheck"), Body: []byte(`{"data":{"country":"TW","is_allowed":true}}`)}, CatUnlocked, "tw", SigRegionMatch},
	{"kktv JP", "auto-kktv", "", "tw", Response{Status: 200, URL: u("https://api.kktv.me/v3/ipcheck"), Body: []byte(`{"data":{"country":"JP","is_allowed":false}}`)}, CatNotUnlocked, "jp", SigBlocked},
	{"kktv TW not allowed", "auto-kktv", "", "tw", Response{Status: 200, URL: u("https://api.kktv.me/v3/ipcheck"), Body: []byte(`{"data":{"country":"TW","is_allowed":false}}`)}, CatNotUnlocked, "tw", SigBlocked},
	{"kktv changed json", "auto-kktv", "", "tw", Response{Status: 200, URL: u("https://api.kktv.me/v3/ipcheck"), Body: []byte(`{"result":"ok"}`)}, CatUnknown, "", SigUnexpected},
	{"kktv challenge", "auto-kktv", "", "tw", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},

	// LINE TV (verdict)
	{"linetv episodes", "auto-linetv", "", "tw", Response{Status: 200, URL: u("https://www.linetv.tw/drama/11829/eps/1"),
		Body: []byte(`<script>window.__INITIAL_STATE__ = {"eps_info": [{"durationInMs": 1440000}]}</script>`)}, CatUnlocked, "", SigAvailable},
	{"linetv empty episodes", "auto-linetv", "", "tw", Response{Status: 200, URL: u("https://www.linetv.tw/drama/11829/eps/1"),
		Body: []byte(`<script>window.__INITIAL_STATE__ = {"eps_info": []}</script>`)}, CatNotUnlocked, "", SigBlocked},
	{"linetv login", "auto-linetv", "", "tw", Response{Status: 200, URL: u("https://www.linetv.tw/login"), Body: []byte(loginBody)}, CatUnknown, "", SigLoginRequired},
	{"linetv changed page", "auto-linetv", "", "tw", Response{Status: 200, URL: u("https://www.linetv.tw/drama/11829/eps/1"), Body: []byte(`<html>app shell</html>`)}, CatUnknown, "", SigUnexpected},

	// Hami Video (verdict)
	{"hami geo ok", "auto-hami", "", "tw", Response{Status: 200, URL: u("https://hamivideo.hinet.net/api/play.do"), Body: []byte(`{"code":"06001-107","message":"synthetic"}`)}, CatUnlocked, "", SigAvailable},
	{"hami geo blocked", "auto-hami", "", "tw", Response{Status: 200, URL: u("https://hamivideo.hinet.net/api/play.do"), Body: []byte(`{"code":"06001-106"}`)}, CatNotUnlocked, "", SigBlocked},
	{"hami other code", "auto-hami", "", "tw", Response{Status: 200, URL: u("https://hamivideo.hinet.net/api/play.do"), Body: []byte(`{"code":"99999-001"}`)}, CatUnknown, "", SigUnexpected},
	{"hami html", "auto-hami", "", "tw", Response{Status: 200, URL: u("https://hamivideo.hinet.net/api/play.do"), Body: []byte(`<html>`)}, CatUnknown, "", SigUnexpected},

	// ABEMA / Niconico
	{"abema JP", "auto-abema", "", "jp", Response{Status: 200, URL: u("https://api.abema.io/v1/ip/check"), Body: []byte(`{"isoCountryCode":"JP"}`)}, CatUnlocked, "jp", SigRegionMatch},
	{"abema oversea", "auto-abema", "", "jp", Response{Status: 200, URL: u("https://api.abema.io/v1/ip/check"), Body: []byte(`{"isoCountryCode":"US"}`)}, CatNotUnlocked, "us", SigRegionMismatch},
	{"abema 403", "auto-abema", "", "jp", Response{Status: 403, URL: u("https://api.abema.io/v1/ip/check")}, CatNotUnlocked, "", SigBlocked403},
	{"abema empty", "auto-abema", "", "jp", Response{Status: 200, URL: u("https://api.abema.io/v1/ip/check"), Body: []byte(`{}`)}, CatUnknown, "", SigUnexpected},
	{"niconico blocked", "auto-abema", "Niconico", "jp", Response{Status: 200, URL: u("https://www.nicovideo.jp/watch/so40278367"), Body: []byte(`<p>同じ地域からのみ視聴できます（synthetic）</p>`)}, CatNotUnlocked, "", SigBlocked},
	{"niconico ok", "auto-abema", "Niconico", "jp", Response{Status: 200, URL: u("https://www.nicovideo.jp/watch/so40278367"), Body: []byte(`<html>video</html>`)}, CatUnlocked, "", SigNoNegative},

	// MyTV SUPER / Viu.com
	{"mytvsuper HK by country_code", "auto-mytvsuper", "", "hk", Response{Status: 200, URL: u("https://www.mytvsuper.com/api/auth/getSession/self/"), Body: []byte(`{"country_code":"HK"}`)}, CatUnlocked, "hk", SigRegionMatch},
	{"mytvsuper HK by region=1", "auto-mytvsuper", "", "hk", Response{Status: 200, URL: u("https://www.mytvsuper.com/api/auth/getSession/self/"), Body: []byte(`{"region":1}`)}, CatUnlocked, "hk", SigRegionMatch},
	{"mytvsuper other country", "auto-mytvsuper", "", "hk", Response{Status: 200, URL: u("https://www.mytvsuper.com/api/auth/getSession/self/"), Body: []byte(`{"country_code":"SG"}`)}, CatNotUnlocked, "sg", SigRegionMismatch},
	{"mytvsuper region 0", "auto-mytvsuper", "", "hk", Response{Status: 200, URL: u("https://www.mytvsuper.com/api/auth/getSession/self/"), Body: []byte(`{"region":0}`)}, CatNotUnlocked, "", SigBlocked},
	{"mytvsuper 403", "auto-mytvsuper", "", "hk", Response{Status: 403}, CatNotUnlocked, "", SigBlocked403},
	{"mytvsuper changed", "auto-mytvsuper", "", "hk", Response{Status: 200, Body: []byte(`{"session":null}`)}, CatUnknown, "", SigUnexpected},
	{"viu hk", "auto-mytvsuper", "Viu.com", "hk", Response{Status: 302, URL: u("https://www.viu.com/ott/hk/zh-hk/")}, CatUnlocked, "hk", SigRegionMatch},
	{"viu no-service", "auto-mytvsuper", "Viu.com", "hk", Response{Status: 302, URL: u("https://www.viu.com/ott/no-service/")}, CatNotUnlocked, "", SigBlocked},
	{"viu 200 no redirect", "auto-mytvsuper", "Viu.com", "hk", Response{Status: 200, URL: u("https://www.viu.com/")}, CatUnknown, "", SigUnexpected},
}

func bahamut(tokenTW, tokenHK string) Response {
	dev := Response{Status: 200, URL: u("https://ani.gamer.com.tw/ajax/getdeviceid.php"), Body: []byte(`{"deviceid":"0123abcd"}`)}
	tw := Response{Status: 200, URL: u("https://ani.gamer.com.tw/ajax/token.php"), Body: []byte(tokenTW)}
	return Response{Status: 200, URL: u("https://ani.gamer.com.tw/ajax/token.php"), Body: []byte(tokenHK), Prev: []Response{dev, tw}}
}

func TestAdapterFixtures(t *testing.T) {
	for _, f := range fixtures {
		a, c := checkOf(t, f.service, f.platform)
		v := a.enforce(c.Classify(f.resp, f.region))
		if v.Category != f.want || v.Region != f.wantRegion || v.Signal != f.wantSignal {
			t.Errorf("%s: got %s/%q/%s (%s), want %s/%q/%s", f.name, v.Category, v.Region, v.Signal, v.Evidence, f.want, f.wantRegion, f.wantSignal)
		}
		if v.Evidence == "" {
			t.Errorf("%s: verdict without evidence", f.name)
		}
	}
}

// The declarations must match what the classifiers can actually return:
// every category a fixture produces is declared, and every declared
// category is produced by at least one fixture of the primary check.
func TestCapabilityMatchesClassifiers(t *testing.T) {
	produced := map[string]map[Category]bool{}
	for _, f := range fixtures {
		a, c := checkOf(t, f.service, f.platform)
		v := c.Classify(f.resp, f.region) // before enforce
		if !a.Allows(v.Category) {
			t.Errorf("%s: classifier returned undeclared %s", f.name, v.Category)
		}
		if c.Primary {
			if produced[f.service] == nil {
				produced[f.service] = map[Category]bool{}
			}
			produced[f.service][v.Category] = true
		}
	}
	for _, a := range Catalog {
		if a.Capability == CapUnsupported {
			continue
		}
		for _, r := range a.Returns {
			if !produced[a.Service][r] {
				t.Errorf("%s: declares %s but no fixture produces it", a.Service, r)
			}
		}
		if a.Capability == CapReachability {
			for c := range produced[a.Service] {
				if ok, has := IngestVerdict(c); has {
					t.Errorf("%s: reachability adapter produced an ingestible verdict (%s → %v)", a.Service, c, ok)
				}
			}
		}
	}
	// Every catalog service has fixtures.
	for _, a := range Catalog {
		if a.Capability != CapUnsupported && produced[a.Service] == nil {
			t.Errorf("%s: no fixtures", a.Service)
		}
	}
}

func TestEnforceDowngradesUndeclared(t *testing.T) {
	a, _ := Lookup("auto-perplexity")
	if v := a.enforce(Verdict{Category: CatUnlocked, Evidence: "x"}); v.Category != CatUnknown {
		t.Fatalf("reachability adapter kept an unlock: %+v", v)
	}
	b, _ := Lookup("auto-netflix")
	if v := b.enforce(Verdict{Category: CatNetworkOK, Evidence: "x"}); v.Category != CatUnknown {
		t.Fatalf("verdict adapter kept reachability: %+v", v)
	}
}

func TestGradeAndIngestMapping(t *testing.T) {
	cases := []struct {
		c       Category
		g       Grade
		ok, has bool
	}{
		{CatUnlocked, GradePlatform, true, true},
		{CatNotUnlocked, GradePlatform, false, true},
		{CatNetworkOK, GradeReachability, false, false},
		{CatUnknown, GradeUnknown, false, false},
		{CatFailed, GradeError, false, false},
		{"weird", GradeError, false, false},
	}
	for _, c := range cases {
		ok, has := IngestVerdict(c.c)
		if GradeOf(c.c) != c.g || ok != c.ok || has != c.has {
			t.Errorf("%s: grade %s ingest %v/%v", c.c, GradeOf(c.c), ok, has)
		}
	}
}

// ---- multi-step and multi-check adapters through the pinned runner ----------

func TestRunBahamutChainCarriesOnlyValidatedValue(t *testing.T) {
	p := newPlatform(t)
	var tokenQueries []string
	p.handlers["ani.gamer.com.tw"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Errorf("cookie sent: %q", r.Header.Get("Cookie"))
		}
		switch r.URL.Path {
		case "/ajax/getdeviceid.php":
			http.SetCookie(w, &http.Cookie{Name: "synthetic", Value: "x"})
			_, _ = w.Write([]byte(`{"deviceid":"abc123"}`))
		case "/ajax/token.php":
			p.mu.Lock()
			tokenQueries = append(tokenQueries, r.URL.RawQuery)
			p.mu.Unlock()
			_, _ = w.Write([]byte(`{"animeSn":` + r.URL.Query().Get("sn") + `}`))
		}
	}
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}
	p.traceLoc = "TW"
	rep := newProber(p, n).Run(context.Background(), Spec{ExitID: "tw", Family: unlock.FamilyIPv4, Region: "tw", Services: []string{"auto-bahamut"}})
	r := resultOf(rep, "auto-bahamut")
	if r.Category != CatUnlocked || r.Region != "tw" || r.Grade != GradePlatform || r.Capability != CapRegionVerdict {
		t.Fatalf("%+v", r)
	}
	if len(tokenQueries) != 2 || !strings.Contains(tokenQueries[0], "device=abc123") || !strings.Contains(tokenQueries[0], "sn=38832") {
		t.Fatalf("token requests: %v", tokenQueries)
	}

	// A device id that is not a plain token stops the chain.
	p2 := newPlatform(t)
	p2.traceLoc = "TW"
	p2.handlers["ani.gamer.com.tw"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ajax/token.php" {
			t.Error("token requested with an unvalidated value")
		}
		_, _ = w.Write([]byte(`{"deviceid":"x&sn=1#evil"}`))
	}
	rep = newProber(p2, &fakeNet{p: p2, fam: unlock.FamilyIPv4, dev: "m00"}).Run(context.Background(), Spec{ExitID: "tw", Family: unlock.FamilyIPv4, Region: "tw", Services: []string{"auto-bahamut"}})
	if r := resultOf(rep, "auto-bahamut"); r.Category != CatUnknown {
		t.Fatalf("%+v", r)
	}
}

func TestRunMultiCheckPrimaryDecidesAndNoRedirect(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.mytvsuper.com"] = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"country_code":"HK"}`))
	}
	p.handlers["www.viu.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("Viu redirect was followed to %s", r.URL.Path)
		}
		http.Redirect(w, r, "https://www.viu.com/ott/no-service/", http.StatusFound)
	}
	p.handlers["copilot.microsoft.com"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/c/api/user" {
			t.Errorf("Copilot redirect was followed to %s", r.URL.Path)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
	rep := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}).Run(context.Background(), Spec{ExitID: "hk", Family: unlock.FamilyIPv4, Region: "hk",
		Services: []string{"auto-mytvsuper", "auto-copilot"}})
	r := resultOf(rep, "auto-mytvsuper")
	if r.Category != CatUnlocked || r.Region != "hk" || len(r.Parts) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.Parts[1].Platform != "Viu.com" || r.Parts[1].Category != CatNotUnlocked || r.Parts[1].Primary {
		t.Fatalf("informational part: %+v", r.Parts[1])
	}
	if c := resultOf(rep, "auto-copilot"); c.Category != CatNotUnlocked || c.Signal != SigBlocked {
		t.Fatalf("copilot: %+v", c)
	}
}

func TestRunEgressChangeVoidsParts(t *testing.T) {
	p := newPlatform(t)
	p.traceIPs = []string{"203.0.113.5", "203.0.113.6"}
	p.handlers["www.mytvsuper.com"] = func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"country_code":"HK"}`)) }
	p.handlers["www.viu.com"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.viu.com/ott/hk/", http.StatusFound)
	}
	rep := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}).Run(context.Background(), Spec{ExitID: "hk", Family: unlock.FamilyIPv4, Region: "hk",
		ExpectAddr: netip.MustParseAddr("203.0.113.5"), Services: []string{"auto-mytvsuper"}})
	r := resultOf(rep, "auto-mytvsuper")
	if r.Category != CatFailed || r.Grade != GradeError {
		t.Fatalf("%+v", r)
	}
	for _, pt := range r.Parts {
		if pt.Category != CatFailed || pt.Region != "" {
			t.Fatalf("part survived an egress change: %+v", pt)
		}
	}
}

func TestRunServiceTimeoutCoversAllSteps(t *testing.T) {
	p := newPlatform(t)
	p.traceLoc = "TW"
	p.handlers["ani.gamer.com.tw"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ajax/getdeviceid.php" {
			_, _ = w.Write([]byte(`{"deviceid":"abc"}`))
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}
	pr := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"})
	pr.TargetTimeout = 400 * time.Millisecond
	start := time.Now()
	rep := pr.Run(context.Background(), Spec{ExitID: "tw", Family: unlock.FamilyIPv4, Region: "tw", Services: []string{"auto-bahamut"}})
	if r := resultOf(rep, "auto-bahamut"); r.Category != CatFailed || r.Error != "超时" {
		t.Fatalf("%+v", r)
	}
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatal("service timeout not shared across steps")
	}
}
