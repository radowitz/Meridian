package probe

// SYNTHETIC FIXTURES for the adapters added with the coverage table. Every
// body was written by hand to match the markers documented for the
// adapter (docs/unlock-methods.md); none was captured from a platform and
// none holds cookies, tokens, account or personal data. Each adapter is
// covered for: unlocked, not unlocked, wrong region (region adapters),
// anti-bot challenge, rate limit and a changed format (unknown).

import (
	"os"
	"strings"
	"testing"
)

const rateLimited = `{"error":"synthetic rate limit"}`

func init() {
	fixtures = append(fixtures, []fixture{
		// YouTube Premium (verdict, region informational)
		{"yt available", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`synthetic "INNERTUBE_CONTEXT_GL":"US" ... Enjoy ad-free videos`)}, CatUnlocked, "us", SigAvailable},
		{"yt other region is informational", "youtube-premium", "", "hk", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`"countryCode":"JP" ad-free`)}, CatUnlocked, "jp", SigAvailable},
		{"yt not available", "youtube-premium", "", "hk", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<p>Premium is not available in your country</p>`)}, CatNotUnlocked, "", SigBlocked},
		{"yt cn", "youtube-premium", "", "hk", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<a href="https://www.google.cn/">synthetic</a>`)}, CatNotUnlocked, "cn", SigBlocked},
		{"yt challenge", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"yt rate limit", "youtube-premium", "", "us", Response{Status: 429, URL: u("https://www.youtube.com/premium"), Body: []byte(rateLimited)}, CatUnknown, "", SigRateLimited},
		{"yt changed page", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<html>new layout</html>`)}, CatUnknown, "", SigUnexpected},

		// Prime Video (region verdict)
		{"prime HK on HK", "primevideo", "", "hk", Response{Status: 200, URL: u("https://www.primevideo.com/"), Body: []byte(`{"currentTerritory":"HK"}`)}, CatUnlocked, "hk", SigRegionMatch},
		{"prime US on HK", "primevideo", "", "hk", Response{Status: 200, URL: u("https://www.primevideo.com/"), Body: []byte(`{"currentTerritory":"US"}`)}, CatNotUnlocked, "us", SigRegionMismatch},
		{"prime restricted", "primevideo", "", "hk", Response{Status: 200, URL: u("https://www.primevideo.com/"), Body: []byte(`{"isServiceRestricted":true}`)}, CatNotUnlocked, "", SigBlocked},
		{"prime challenge", "primevideo", "", "hk", Response{Status: 503, URL: u("https://www.primevideo.com/"), Body: []byte(`<form action="/errors/validateCaptcha">captcha-delivery</form>`)}, CatUnknown, "", SigChallenge},
		{"prime rate limit", "primevideo", "", "hk", Response{Status: 429, URL: u("https://www.primevideo.com/")}, CatUnknown, "", SigRateLimited},
		{"prime changed", "primevideo", "", "hk", Response{Status: 200, URL: u("https://www.primevideo.com/"), Body: []byte(`<html>shell</html>`)}, CatUnknown, "", SigUnexpected},

		// DAZN (region verdict)
		{"dazn allowed jp", "dazn", "", "jp", Response{Status: 200, URL: u("https://startup.core.indazn.com/misl/v5/Startup"), Body: []byte(`{"Region":{"isAllowed":true,"GeolocatedCountry":"jp"}}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"dazn allowed other region", "dazn", "", "jp", Response{Status: 200, Body: []byte(`{"Region":{"isAllowed":true,"GeolocatedCountry":"de"}}`)}, CatNotUnlocked, "de", SigRegionMismatch},
		{"dazn not allowed", "dazn", "", "hk", Response{Status: 200, Body: []byte(`{"Region":{"isAllowed":false,"GeolocatedCountry":"hk"}}`)}, CatNotUnlocked, "hk", SigBlocked},
		{"dazn challenge", "dazn", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"dazn rate limit", "dazn", "", "jp", Response{Status: 429, Body: []byte(rateLimited)}, CatUnknown, "", SigRateLimited},
		{"dazn changed json", "dazn", "", "jp", Response{Status: 200, Body: []byte(`{"region":{"allowed":"yes"}}`)}, CatUnknown, "", SigUnexpected},

		// TVBAnywhere+ (verdict)
		{"tvb allowed", "tvbanywhere", "", "sg", Response{Status: 200, Body: []byte(`{"allow_in_this_country":true,"country":"SG"}`)}, CatUnlocked, "sg", SigAvailable},
		{"tvb not allowed", "tvbanywhere", "", "hk", Response{Status: 200, Body: []byte(`{"allow_in_this_country":false,"country":"HK"}`)}, CatNotUnlocked, "hk", SigBlocked},
		{"tvb challenge", "tvbanywhere", "", "sg", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"tvb rate limit", "tvbanywhere", "", "sg", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"tvb changed", "tvbanywhere", "", "sg", Response{Status: 200, Body: []byte(`{"status":"ok"}`)}, CatUnknown, "", SigUnexpected},

		// DMM TV (region verdict, jp)
		{"dmm unauthorized = jp ok", "dmm-tv", "", "jp", Response{Status: 401, Body: []byte(`{"error":"UNAUTHORIZED"}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"dmm ok but exit not jp", "dmm-tv", "", "hk", Response{Status: 401, Body: []byte(`{"error":"UNAUTHORIZED"}`)}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"dmm foreign", "dmm-tv", "", "jp", Response{Status: 403, Body: []byte(`{"error":"FOREIGN"}`)}, CatNotUnlocked, "", SigRegionMismatch},
		{"dmm challenge", "dmm-tv", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"dmm rate limit", "dmm-tv", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"dmm changed", "dmm-tv", "", "jp", Response{Status: 400, Body: []byte(`{"error":"BAD_REQUEST"}`)}, CatUnknown, "", SigUnexpected},

		// Hulu Japan (region verdict, jp)
		{"hulu jp login", "hulu-jp", "", "jp", Response{Status: 200, URL: u("https://id.hulu.jp/login")}, CatUnlocked, "jp", SigRegionMatch},
		{"hulu jp login, exit not jp", "hulu-jp", "", "tw", Response{Status: 200, URL: u("https://id.hulu.jp/login")}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"hulu jp restrict", "hulu-jp", "", "hk", Response{Status: 302, URL: u("https://www.hulu.jp/restrict")}, CatNotUnlocked, "", SigBlocked},
		{"hulu jp challenge", "hulu-jp", "", "jp", Response{Status: 403, URL: u("https://id.hulu.jp/"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"hulu jp rate limit", "hulu-jp", "", "jp", Response{Status: 429, URL: u("https://id.hulu.jp/")}, CatUnknown, "", SigRateLimited},
		{"hulu jp changed", "hulu-jp", "", "jp", Response{Status: 200, URL: u("https://id.hulu.jp/welcome")}, CatUnknown, "", SigUnexpected},

		// radiko (region verdict, jp)
		{"radiko jp13", "radiko", "", "jp", Response{Status: 200, Body: []byte(`document.write('<span class="JP13">TOKYO JAPAN</span>');`)}, CatUnlocked, "jp", SigRegionMatch},
		{"radiko jp on sg exit", "radiko", "", "sg", Response{Status: 200, Body: []byte(`<span class="JP27">OSAKA</span>`)}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"radiko out", "radiko", "", "jp", Response{Status: 200, Body: []byte(`<span class="OUT">OUT</span>`)}, CatNotUnlocked, "", SigBlocked},
		{"radiko challenge", "radiko", "", "jp", Response{Status: 200, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"radiko rate limit", "radiko", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"radiko changed", "radiko", "", "jp", Response{Status: 200, Body: []byte(`{"area":"JP13"}`)}, CatUnknown, "", SigUnexpected},

		// MyVideo (verdict, tw)
		{"myvideo ok", "myvideo", "", "tw", Response{Status: 200, URL: u("https://www.myvideo.net.tw/login.do")}, CatUnlocked, "", SigNoNegative},
		{"myvideo blocked", "myvideo", "", "hk", Response{Status: 302, URL: u("https://www.myvideo.net.tw/serviceAreaBlock/")}, CatNotUnlocked, "", SigBlocked},
		{"myvideo challenge", "myvideo", "", "tw", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"myvideo rate limit", "myvideo", "", "tw", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"myvideo changed", "myvideo", "", "tw", Response{Status: 302, URL: u("https://www.myvideo.net.tw/newhome/")}, CatUnknown, "", SigRedirect},

		// Peacock (verdict, us)
		{"peacock ok", "peacock", "", "us", Response{Status: 200, URL: u("https://www.peacocktv.com/")}, CatUnlocked, "", SigNoNegative},
		{"peacock unavailable", "peacock", "", "hk", Response{Status: 302, URL: u("https://www.peacocktv.com/unavailable")}, CatNotUnlocked, "", SigBlocked},
		{"peacock challenge", "peacock", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"peacock rate limit", "peacock", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"peacock changed", "peacock", "", "us", Response{Status: 302, URL: u("https://www.peacocktv.com/start")}, CatUnknown, "", SigRedirect},

		// Pluto TV (verdict)
		{"pluto ok", "plutotv", "", "us", Response{Status: 302, URL: u("https://pluto.tv/us/live-tv")}, CatUnlocked, "", SigNoNegative},
		{"pluto blocked", "plutotv", "", "hk", Response{Status: 302, URL: u("https://pluto.tv/thanks-for-watching")}, CatNotUnlocked, "", SigBlocked},
		{"pluto challenge", "plutotv", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"pluto rate limit", "plutotv", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"pluto changed", "plutotv", "", "us", Response{Status: 404, URL: u("https://pluto.tv/")}, CatUnknown, "", SigUnexpected},
	}...)
}

// Every coverage item either names an adapter of the catalog (and, for a
// reference check, one of its checks) or gives a reason with an
// explanation; every adapter appears in the table; every item is in
// docs/unlock-methods.md.
func TestCoverageTable(t *testing.T) {
	inTable := map[string]bool{}
	sections := map[string]bool{}
	for _, s := range Sections {
		sections[s] = true
	}
	doc, err := os.ReadFile("../../docs/unlock-methods.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range Coverage {
		if !sections[it.Section] || it.Name == "" || len(it.Scripts) == 0 {
			t.Errorf("bad item %+v", it)
		}
		switch {
		case it.Adapter != "":
			a, ok := Lookup(it.Adapter)
			if !ok || it.Reason != "" {
				t.Errorf("%s: adapter %q missing or reason given too", it.Name, it.Adapter)
			}
			if it.Part != "" {
				found := false
				for _, c := range a.Checks {
					found = found || c.Platform == it.Part
				}
				if !found {
					t.Errorf("%s: no check %q in %s", it.Name, it.Part, it.Adapter)
				}
			}
			inTable[it.Adapter] = true
		case ReasonText[it.Reason] == "":
			t.Errorf("%s: neither an adapter nor a known reason", it.Name)
		}
		if !strings.Contains(string(doc), it.Name) {
			t.Errorf("%s: missing from docs/unlock-methods.md", it.Name)
		}
	}
	for _, a := range Catalog {
		if !inTable[a.Service] {
			t.Errorf("%s: not in the coverage table", a.Service)
		}
		if !sections[a.Section] {
			t.Errorf("%s: section %q", a.Service, a.Section)
		}
		if !strings.Contains(string(doc), "| "+a.Service+" |") {
			t.Errorf("%s: missing from the capability table of docs/unlock-methods.md", a.Service)
		}
		for _, s := range a.Sources {
			if s.Checked == "" {
				t.Errorf("%s: source without a checked note", a.Service)
			}
		}
		for _, c := range a.Checks {
			for _, st := range c.Steps {
				for _, h := range st.Headers {
					if !allowedHeaders[h[0]] {
						t.Errorf("%s: header %s not allowed", a.Service, h[0])
					}
				}
				host := strings.SplitN(strings.TrimPrefix(st.URL, "https://"), "/", 2)[0]
				listed := false
				for _, h := range c.Hosts {
					listed = listed || h == host
				}
				if !strings.HasPrefix(st.URL, "https://") || !listed {
					t.Errorf("%s: step %s is not https on a listed host", a.Service, st.URL)
				}
			}
		}
	}
}

func TestRegionsAndCost(t *testing.T) {
	a, _ := Lookup("auto-abema")
	if !a.CoversRegion("Japan") || a.CoversRegion("hk") || a.RequestCost() != 2 {
		t.Fatalf("abema: %v %v %d", a.CoversRegion("Japan"), a.CoversRegion("hk"), a.RequestCost())
	}
	n, _ := Lookup("auto-netflix")
	if !n.CoversRegion("sg") || n.RequestCost() != 1 {
		t.Fatal("netflix")
	}
	b, _ := Lookup("auto-bahamut")
	if b.RequestCost() != 3 {
		t.Fatal("bahamut cost")
	}
}
