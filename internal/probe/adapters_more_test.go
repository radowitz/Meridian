package probe

// SYNTHETIC FIXTURES for the adapters added with the coverage table. Every
// body was written by hand to match the markers documented for the
// adapter (docs/unlock-methods.md); none was captured from a platform and
// none holds cookies, tokens, account or personal data. Each adapter is
// covered for: unlocked, not unlocked, wrong region (region adapters),
// anti-bot challenge, rate limit and a changed format (unknown).

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/radowitz/meridian/internal/unlock"
)

const rateLimited = `{"error":"synthetic rate limit"}`

func init() {
	fixtures = append(fixtures, []fixture{
		// YouTube Premium (verdict, region informational)
		{"yt available", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`synthetic "INNERTUBE_CONTEXT_GL":"US" ... Enjoy ad-free videos`)}, CatUnlocked, "us", SigAvailable},
		{"yt other region is informational", "youtube-premium", "", "hk", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`"INNERTUBE_CONTEXT_GL":"JP" Ad-Free`)}, CatUnlocked, "jp", SigAvailable},
		{"yt not available", "youtube-premium", "", "hk", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<p>Premium is NOT available in your country</p>`)}, CatNotUnlocked, "", SigBlocked},
		{"yt cn", "youtube-premium", "", "hk", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<a href="https://www.google.cn/">synthetic</a>`)}, CatNotUnlocked, "cn", SigBlocked},
		{"yt challenge", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"yt rate limit", "youtube-premium", "", "us", Response{Status: 429, URL: u("https://www.youtube.com/premium"), Body: []byte(rateLimited)}, CatUnknown, "", SigRateLimited},
		{"yt changed page", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<html>new layout</html>`)}, CatUnknown, "", SigUnexpected},

		// consent page: via a body form, via a redirect that stopped on a
		// consent host, and one that also contains the success marker (the
		// consent markers are checked before ad-free).
		{"yt consent body form", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<form action="https://consent.youtube.com/save" method="POST"><input type="hidden" name="x" value="synthetic"></form>`)}, CatUnknown, "", SigConsent},
		{"yt consent body text", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<h1>Before you continue to YouTube</h1>`)}, CatUnknown, "", SigConsent},
		{"yt consent redirect youtube", "youtube-premium", "", "us", Response{Status: 302, URL: u("https://consent.youtube.com/m")}, CatUnknown, "", SigConsent},
		{"yt consent redirect google", "youtube-premium", "", "us", Response{Status: 303, URL: u("https://consent.google.com/ml")}, CatUnknown, "", SigConsent},
		{"yt consent page with ad-free is not unlocked", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<h1>Before you continue to YouTube</h1><p>ad-free</p><form action="https://consent.youtube.com/save"></form>`)}, CatUnknown, "", SigConsent},
		{"yt consent page with google.cn is not a cn verdict", "youtube-premium", "", "us", Response{Status: 200, URL: u("https://www.youtube.com/premium"), Body: []byte(`<form action="//consent.google.com/s"></form> www.google.cn`)}, CatUnknown, "", SigConsent},
		{"yt other redirect is not consent", "youtube-premium", "", "us", Response{Status: 302, URL: u("https://evil.example/x")}, CatUnknown, "", SigRedirect},

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
		{"dazn banned", "dazn", "", "hk", Response{Status: 200, Body: []byte(`Security policy has been breached (synthetic)`)}, CatNotUnlocked, "", SigBlocked},
		{"dazn 403", "dazn", "", "hk", Response{Status: 403, Body: []byte(`{}`)}, CatNotUnlocked, "", SigBlocked403},
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
		{"dmm foreign on jp exit = address blocked", "dmm-tv", "", "jp", Response{Status: 403, Body: []byte(`{"error":"FOREIGN"}`)}, CatNotUnlocked, "", SigBlocked},
		{"dmm foreign on hk exit", "dmm-tv", "", "hk", Response{Status: 403, Body: []byte(`{"error":"FOREIGN"}`)}, CatNotUnlocked, "", SigRegionMismatch},
		{"dmm challenge", "dmm-tv", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"dmm rate limit", "dmm-tv", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"dmm changed", "dmm-tv", "", "jp", Response{Status: 400, Body: []byte(`{"error":"BAD_REQUEST"}`)}, CatUnknown, "", SigUnexpected},

		// Hulu Japan (region verdict, jp)
		{"hulu jp final 200", "hulu-jp", "", "jp", Response{Status: 200, URL: u("https://id.hulu.jp/login")}, CatUnlocked, "jp", SigRegionMatch},
		{"hulu jp 403", "hulu-jp", "", "jp", Response{Status: 403, URL: u("https://id.hulu.jp/")}, CatNotUnlocked, "", SigBlocked403},
		{"hulu jp login, exit not jp", "hulu-jp", "", "tw", Response{Status: 200, URL: u("https://id.hulu.jp/login")}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"hulu jp restrict", "hulu-jp", "", "hk", Response{Status: 302, URL: u("https://www.hulu.jp/restrict")}, CatNotUnlocked, "", SigBlocked},
		{"hulu jp challenge", "hulu-jp", "", "jp", Response{Status: 403, URL: u("https://id.hulu.jp/"), Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"hulu jp rate limit", "hulu-jp", "", "jp", Response{Status: 429, URL: u("https://id.hulu.jp/")}, CatUnknown, "", SigRateLimited},
		{"hulu jp changed", "hulu-jp", "", "jp", Response{Status: 404, URL: u("https://id.hulu.jp/welcome")}, CatUnknown, "", SigUnexpected},

		// radiko (region verdict, jp)
		{"radiko jp13", "radiko", "", "jp", Response{Status: 200, Body: []byte(`document.write('<span class="JP13">TOKYO JAPAN</span>');`)}, CatUnlocked, "jp", SigRegionMatch},
		{"radiko jp on sg exit", "radiko", "", "sg", Response{Status: 200, Body: []byte(`<span class="JP27">OSAKA JAPAN</span>`)}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"radiko out", "radiko", "", "jp", Response{Status: 200, Body: []byte(`<span class="OUT">OUT</span>`)}, CatNotUnlocked, "", SigBlocked},
		{"radiko challenge", "radiko", "", "jp", Response{Status: 200, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"radiko rate limit", "radiko", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"radiko changed", "radiko", "", "jp", Response{Status: 200, Body: []byte(`{"area":"JP13"}`)}, CatUnknown, "", SigUnexpected},

		// MyVideo (verdict, tw)
		{"myvideo ok", "myvideo", "", "tw", Response{Status: 200, URL: u("https://www.myvideo.net.tw/login.do")}, CatUnlocked, "", SigNoNegative},
		{"myvideo blocked", "myvideo", "", "hk", Response{Status: 200, URL: u("https://www.myvideo.net.tw/serviceareablock/")}, CatNotUnlocked, "", SigBlocked},
		{"myvideo 403", "myvideo", "", "hk", Response{Status: 403, URL: u("https://www.myvideo.net.tw/login.do")}, CatNotUnlocked, "", SigBlocked403},
		{"myvideo challenge", "myvideo", "", "tw", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"myvideo rate limit", "myvideo", "", "tw", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"myvideo changed", "myvideo", "", "tw", Response{Status: 302, URL: u("https://www.myvideo.net.tw/newhome/")}, CatUnknown, "", SigRedirect},

		// Peacock (verdict, us)
		{"peacock ok", "peacock", "", "us", Response{Status: 200, URL: u("https://www.peacocktv.com/")}, CatUnlocked, "", SigNoNegative},
		{"peacock unavailable", "peacock", "", "hk", Response{Status: 200, URL: u("https://www.peacocktv.com/unavailable")}, CatNotUnlocked, "", SigBlocked},
		{"peacock challenge", "peacock", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"peacock rate limit", "peacock", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"peacock changed", "peacock", "", "us", Response{Status: 302, URL: u("https://www.peacocktv.com/start")}, CatUnknown, "", SigRedirect},

		// Pluto TV (verdict)
		{"pluto ok", "plutotv", "", "us", Response{Status: 200, URL: u("https://pluto.tv/us/live-tv")}, CatUnlocked, "", SigNoNegative},
		{"pluto blocked (url)", "plutotv", "", "hk", Response{Status: 200, URL: u("https://pluto.tv/en/plutotv-is-not-available")}, CatNotUnlocked, "", SigBlocked},
		{"pluto blocked (page)", "plutotv", "", "hk", Response{Status: 200, URL: u("https://pluto.tv/"), Body: []byte(`<a href="/thanks-for-watching">synthetic</a>`)}, CatNotUnlocked, "", SigBlocked},
		{"pluto challenge", "plutotv", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"pluto rate limit", "plutotv", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"pluto changed", "plutotv", "", "us", Response{Status: 404, URL: u("https://pluto.tv/")}, CatUnknown, "", SigUnexpected},
		// FOD
		{"fod true", "fod", "", "jp", Response{Status: 200, Body: []byte(`<?xml version="1.0"?><FLAGS><FLAG TYPE="true">synthetic</FLAG></FLAGS>`)}, CatUnlocked, "jp", SigRegionMatch},
		{"fod true on hk exit", "fod", "", "hk", Response{Status: 200, Body: []byte(`<FLAG TYPE="true"/>`)}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"fod false", "fod", "", "jp", Response{Status: 200, Body: []byte(`<FLAG TYPE="false"/>`)}, CatNotUnlocked, "", SigBlocked},
		{"fod challenge", "fod", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"fod rate limit", "fod", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"fod changed", "fod", "", "jp", Response{Status: 200, Body: []byte(`<FLAG STATE="ok"/>`)}, CatUnknown, "", SigUnexpected},

		// U-NEXT
		{"unext 475", "unext", "", "jp", Response{Status: 200, Body: []byte(`{"data":{"webfront_playlistUrl":{"resultStatus":475}}}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"unext 200 on us exit", "unext", "", "us", Response{Status: 200, Body: []byte(`{"data":{"webfront_playlistUrl":{"resultStatus":200}}}`)}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"unext 475 full reply", "unext", "", "jp", Response{Status: 200, Body: []byte(`{"data":{"webfront_playlistUrl":{"subTitle":"synthetic","playToken":null,"result":{"errorCode":"GAW0500003","errorMessage":"synthetic","__typename":"PlaylistResult"},"resultStatus":475,"__typename":"PlaylistUrl"}}}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"unext graphql errors only", "unext", "", "jp", Response{Status: 200, Body: []byte(`{"errors":[{"message":"synthetic validation error"}],"data":null}`)}, CatUnknown, "", SigUnexpected},
		{"unext 467", "unext", "", "jp", Response{Status: 200, Body: []byte(`{"data":{"webfront_playlistUrl":{"resultStatus":467}}}`)}, CatNotUnlocked, "", SigBlocked},
		{"unext challenge", "unext", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"unext rate limit", "unext", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"unext changed", "unext", "", "jp", Response{Status: 200, Body: []byte(`{"data":{"webfront_playlistUrl":{"resultStatus":499}}}`)}, CatUnknown, "", SigUnexpected},

		// DMM
		{"dmm domestic", "dmm", "", "jp", Response{Status: 200, Body: []byte(`{"data":{"client":{"isForeignAccess":false}}}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"dmm domestic on tw exit", "dmm", "", "tw", Response{Status: 200, Body: []byte(`{"data":{"client":{"isForeignAccess":false}}}`)}, CatNotUnlocked, "jp", SigRegionMismatch},
		{"dmm foreign on jp exit = address blocked", "dmm", "", "jp", Response{Status: 200, Body: []byte(`{"data":{"client":{"isForeignAccess":true}}}`)}, CatNotUnlocked, "", SigBlocked},
		{"dmm foreign on us exit", "dmm", "", "us", Response{Status: 200, Body: []byte(`{"data":{"client":{"isForeignAccess":true}}}`)}, CatNotUnlocked, "", SigRegionMismatch},
		{"dmm domestic with spaces", "dmm", "", "jp", Response{Status: 200, Body: []byte(`{"data": {"client": {"isForeignAccess": false, "__typename": "Client"}}}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"dmm challenge", "dmm", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"dmm rate limit", "dmm", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"dmm changed", "dmm", "", "jp", Response{Status: 200, Body: []byte(`{"errors":[{"message":"synthetic"}]}`)}, CatUnknown, "", SigUnexpected},

		// NHK+
		{"nhk jp", "nhk-plus", "", "jp", Response{Status: 200, Body: []byte(`{"country_code":"JP","area":"synthetic"}`)}, CatUnlocked, "jp", SigRegionMatch},
		{"nhk other country", "nhk-plus", "", "jp", Response{Status: 200, Body: []byte(`{"country_code":"US"}`)}, CatNotUnlocked, "us", SigRegionMismatch},
		{"nhk 403", "nhk-plus", "", "jp", Response{Status: 403}, CatNotUnlocked, "", SigBlocked403},
		{"nhk challenge", "nhk-plus", "", "jp", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"nhk rate limit", "nhk-plus", "", "jp", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"nhk changed", "nhk-plus", "", "jp", Response{Status: 200, Body: []byte(`{"country":"JP"}`)}, CatUnknown, "", SigUnexpected},

		// 4GTV
		{"4gtv Y", "4gtv", "", "tw", Response{Status: 200, Body: []byte(`{"Success":true,"Data":"Y"}`)}, CatUnlocked, "tw", SigRegionMatch},
		{"4gtv Y on hk exit", "4gtv", "", "hk", Response{Status: 200, Body: []byte(`{"Data":"Y"}`)}, CatNotUnlocked, "tw", SigRegionMismatch},
		{"4gtv N", "4gtv", "", "tw", Response{Status: 200, Body: []byte(`{"Data":"N"}`)}, CatNotUnlocked, "", SigRegionMismatch},
		{"4gtv challenge", "4gtv", "", "tw", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"4gtv rate limit", "4gtv", "", "tw", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"4gtv changed", "4gtv", "", "tw", Response{Status: 200, Body: []byte(`{"Data":"maybe"}`)}, CatUnknown, "", SigUnexpected},

		// friDay
		{"friday ok", "friday-video", "", "tw", Response{Status: 200, Body: []byte(`{"code":"0000"}`)}, CatUnlocked, "", SigAvailable},
		{"friday blocked", "friday-video", "", "hk", Response{Status: 200, Body: []byte(`{"code":"1006"}`)}, CatNotUnlocked, "", SigBlocked},
		{"friday challenge", "friday-video", "", "tw", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"friday rate limit", "friday-video", "", "tw", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"friday changed", "friday-video", "", "tw", Response{Status: 200, Body: []byte(`{"code":"9999"}`)}, CatUnknown, "", SigUnexpected},

		// NBA TV
		{"nba ok", "nbatv", "", "us", Response{Status: 200, Body: []byte(`<html>watch</html>`)}, CatUnlocked, "", SigNoNegative},
		{"nba blocked", "nbatv", "", "hk", Response{Status: 200, Body: []byte(`Service is not available in your region`)}, CatNotUnlocked, "", SigBlocked},
		{"nba challenge", "nbatv", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"nba rate limit", "nbatv", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"nba changed", "nbatv", "", "us", Response{Status: 404}, CatUnknown, "", SigUnexpected},

		// B-Global SEA
		{"bglobal ok", "bglobal-sea", "", "sg", Response{Status: 200, Body: []byte(`{"code":0,"message":"0"}`)}, CatUnlocked, "", SigAvailable},
		{"bglobal blocked", "bglobal-sea", "", "hk", Response{Status: 200, Body: []byte(`{"code":10004001}`)}, CatNotUnlocked, "", SigBlocked},
		{"bglobal challenge", "bglobal-sea", "", "sg", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"bglobal rate limit", "bglobal-sea", "", "sg", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"bglobal changed", "bglobal-sea", "", "sg", Response{Status: 200, Body: []byte(`{"code":-404}`)}, CatUnknown, "", SigUnexpected},

		// fuboTV
		{"fubo ok", "fubotv", "", "us", Response{Status: 200, Body: []byte(`{"network_allowed":true,"country_code2":"US"}`)}, CatUnlocked, "us", SigAvailable},
		{"fubo no service", "fubotv", "", "hk", Response{Status: 200, Body: []byte(`{"error":"NO_SERVICE_IN_COUNTRY"}`)}, CatNotUnlocked, "", SigBlocked},
		{"fubo not allowed", "fubotv", "", "hk", Response{Status: 200, Body: []byte(`{"network_allowed":false}`)}, CatNotUnlocked, "", SigBlocked},
		{"fubo challenge", "fubotv", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"fubo rate limit", "fubotv", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"fubo changed", "fubotv", "", "us", Response{Status: 200, Body: []byte(`{"location":{}}`)}, CatUnknown, "", SigUnexpected},

		// Philo
		{"philo ok", "philo", "", "us", Response{Status: 200, Body: []byte(`{"status":"SUCCESS"}`)}, CatUnlocked, "", SigAvailable},
		{"philo fail", "philo", "", "hk", Response{Status: 200, Body: []byte(`{"status":"FAIL"}`)}, CatNotUnlocked, "", SigBlocked},
		{"philo challenge", "philo", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"philo rate limit", "philo", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"philo changed", "philo", "", "us", Response{Status: 200, Body: []byte(`{"status":"PENDING"}`)}, CatUnknown, "", SigUnexpected},

		// Sling TV
		{"sling ok", "sling", "", "us", Response{Status: 200, URL: u("https://www.sling.com/")}, CatUnlocked, "", SigNoNegative},
		{"sling geo-block", "sling", "", "hk", Response{Status: 200, URL: u("https://www.sling.com/geo-block")}, CatNotUnlocked, "", SigBlocked},
		{"sling challenge", "sling", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"sling rate limit", "sling", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"sling changed", "sling", "", "us", Response{Status: 404, URL: u("https://www.sling.com/x")}, CatUnknown, "", SigUnexpected},

		// Tubi
		{"tubi ok", "tubi", "", "us", Response{Status: 200, Body: []byte(`<link rel="manifest" href="/synthetic.json">`)}, CatUnlocked, "", SigAvailable},
		{"tubi blocked", "tubi", "", "hk", Response{Status: 200, Body: []byte(`Tubi is not currently available in your area`)}, CatNotUnlocked, "", SigBlocked},
		{"tubi challenge", "tubi", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"tubi rate limit", "tubi", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"tubi changed", "tubi", "", "us", Response{Status: 200, Body: []byte(`<html>new</html>`)}, CatUnknown, "", SigUnexpected},

		// Acorn TV / BritBox / AMC+
		{"acorn ok", "acorntv", "", "us", Response{Status: 200, Body: []byte(`<a href="https://signup.acorn.tv/">synthetic</a>`)}, CatUnlocked, "", SigAvailable},
		{"acorn blocked", "acorntv", "", "hk", Response{Status: 200, Body: []byte(`Acorn TV is not yet available in your country`)}, CatNotUnlocked, "", SigBlocked},
		{"acorn challenge", "acorntv", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"acorn rate limit", "acorntv", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"acorn changed", "acorntv", "", "us", Response{Status: 200, Body: []byte(`<html>new</html>`)}, CatUnknown, "", SigUnexpected},
		{"britbox ok", "britbox", "", "us", Response{Status: 200, URL: u("https://www.britbox.com/us/")}, CatUnlocked, "", SigNoNegative},
		{"britbox not supported", "britbox", "", "hk", Response{Status: 200, URL: u("https://www.britbox.com/locationnotsupported")}, CatNotUnlocked, "", SigBlocked},
		{"britbox uk site", "britbox", "", "hk", Response{Status: 302, URL: u("https://www.britbox.co.uk/")}, CatNotUnlocked, "", SigBlocked},
		{"britbox challenge", "britbox", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"britbox rate limit", "britbox", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"britbox changed", "britbox", "", "us", Response{Status: 404, URL: u("https://www.britbox.com/x")}, CatUnknown, "", SigUnexpected},
		{"amc ok", "amcplus", "", "us", Response{Status: 200, URL: u("https://www.amcplus.com/")}, CatUnlocked, "", SigNoNegative},
		{"amc restricted", "amcplus", "", "hk", Response{Status: 200, URL: u("https://www.amcplus.com/pages/geographic-restriction")}, CatNotUnlocked, "", SigBlocked},
		{"amc 403", "amcplus", "", "hk", Response{Status: 403, URL: u("https://www.amcplus.com/")}, CatNotUnlocked, "", SigBlocked403},
		{"amc challenge", "amcplus", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"amc rate limit", "amcplus", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"amc changed", "amcplus", "", "us", Response{Status: 404, URL: u("https://www.amcplus.com/x")}, CatUnknown, "", SigUnexpected},

		// Meta AI
		{"metaai ok", "metaai", "", "us", Response{Status: 200, Body: []byte(`<div id="KadabraRootContainer"></div>{"code":"en_US"}`)}, CatUnlocked, "us", SigAvailable},
		{"metaai blocked", "metaai", "", "hk", Response{Status: 200, Body: []byte(`<div id="AbraGeoBlockedErrorRoot"></div>`)}, CatNotUnlocked, "", SigBlocked},
		{"metaai ok via AbraHomeRoot", "metaai", "", "sg", Response{Status: 200, Body: []byte(`{"name":"AbraHomeRootConversationQuery"}`)}, CatUnlocked, "", SigAvailable},
		{"metaai login redirect", "metaai", "", "hk", Response{Status: 200, URL: u("https://www.meta.ai/login/")}, CatUnknown, "", SigLoginRequired},
		{"metaai no marker", "metaai", "", "us", Response{Status: 200, URL: u("https://www.meta.ai/"), Body: []byte(`<html>synthetic</html>`)}, CatUnknown, "", SigUnexpected},
		{"metaai challenge", "metaai", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"metaai rate limit", "metaai", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"metaai changed", "metaai", "", "us", Response{Status: 200, Body: []byte(`<html>new app</html>`)}, CatUnknown, "", SigUnexpected},

		// Coze
		{"coze ok", "coze", "", "us", Response{Status: 200, Body: []byte(`{"code":0,"data":{"IsForbiddenRegion":false,"CountryCode":"US"}}`)}, CatUnlocked, "us", SigAvailable},
		{"coze forbidden", "coze", "", "hk", Response{Status: 200, Body: []byte(`{"code":0,"data":{"IsForbiddenRegion":true,"CountryCode":"HK"}}`)}, CatNotUnlocked, "", SigBlocked},
		{"coze old block", "coze", "", "hk", Response{Status: 200, Body: []byte(`Your region is not supported`)}, CatNotUnlocked, "", SigBlocked},
		{"coze 403", "coze", "", "us", Response{Status: 403}, CatNotUnlocked, "", SigBlocked403},
		{"coze challenge", "coze", "", "us", Response{Status: 403, Body: []byte(challengeBody)}, CatUnknown, "", SigChallenge},
		{"coze country alone is not permission", "coze", "", "us", Response{Status: 200, Body: []byte(`{"code":0,"data":{"CountryCode":"US"}}`)}, CatUnknown, "", SigUnexpected},
		{"coze rate limit", "coze", "", "us", Response{Status: 429}, CatUnknown, "", SigRateLimited},
		{"coze changed", "coze", "", "us", Response{Status: 200, Body: []byte(`{"code":0,"data":{}}`)}, CatUnknown, "", SigUnexpected},
	}...)
}

// Every coverage item either names an adapter of the catalog (and, for a
// reference check, one of its checks) or gives a reason with an
// explanation; every adapter appears in the table; every item is in
// docs/unlock-methods.md.
func TestCoverageTable(t *testing.T) {
	withProdCatalog(t)
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

// The catalog may carry exactly one cookie: the fixed consent value of the
// YouTube Premium adapter, without any identifier cookie.
func TestStepCookieIsOnlyTheFixedConsentValue(t *testing.T) {
	if youtubeConsentCookie != "SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY" {
		t.Fatal("consent cookie changed")
	}
	for _, name := range []string{"YSC", "VISITOR_INFO1_LIVE", "VISITOR_PRIVACY_METADATA", "__Secure-YEC", "__Secure-BUCKET", "PREF"} {
		if strings.Contains(youtubeConsentCookie, name) {
			t.Errorf("identifier cookie %s in the consent cookie", name)
		}
	}
	if strings.Count(youtubeConsentCookie, "=") != 1 || strings.Contains(youtubeConsentCookie, ";") {
		t.Fatal("consent cookie must be a single name=value pair")
	}
	for _, a := range Catalog {
		for _, c := range a.Checks {
			for _, st := range c.Steps {
				if st.Cookie != "" && (a.Service != "youtube-premium" || st.Cookie != youtubeConsentCookie) {
					t.Errorf("%s: unexpected step cookie", a.Service)
				}
			}
		}
	}
}

func runYouTube(t *testing.T, p *platform) Result {
	t.Helper()
	n := &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}
	rep := newProber(p, n).Run(context.Background(), Spec{
		ExitID: "hk-1", Family: unlock.FamilyIPv4, Region: "hk", ExpectAddr: netip.MustParseAddr("203.0.113.5"),
		Services: []string{"youtube-premium"},
	})
	return resultOf(rep, "youtube-premium")
}

// The outgoing request carries exactly the fixed consent cookie and the
// English language header, and a consent redirect to a host outside the
// adapter's list is neither followed nor sent the cookie.
func TestYouTubePremiumRequestAndConsentRedirect(t *testing.T) {
	p := newPlatform(t)
	var mu sync.Mutex
	var cookies, langs []string
	p.handlers["www.youtube.com"] = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Values("Cookie")...)
		langs = append(langs, r.Header.Get("Accept-Language"))
		mu.Unlock()
		http.Redirect(w, r, "https://consent.youtube.com/m?continue=x", http.StatusFound)
	}
	res := runYouTube(t, p)
	if res.Category != CatUnknown || res.Signal != SigConsent {
		t.Fatalf("consent redirect: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cookies) != 1 || cookies[0] != youtubeConsentCookie {
		t.Fatalf("cookie header: %q", cookies)
	}
	if len(p.cookies) != 1 || p.cookies[0] != youtubeConsentCookie {
		t.Fatalf("every cookie the platform saw must be the consent cookie: %q", p.cookies)
	}
	if len(langs) != 1 || !strings.HasPrefix(langs[0], "en-US,en") {
		t.Fatalf("accept-language: %q", langs)
	}
	if p.count("consent.youtube.com") != 0 {
		t.Fatal("consent host was contacted")
	}
}

// A redirect to another host (not listed) is not followed, so the cookie
// never reaches it; a redirect to the adapter's other listed host is followed
// and still carries only the fixed cookie.
func TestYouTubePremiumCookieStaysOnFixedHosts(t *testing.T) {
	p := newPlatform(t)
	p.handlers["www.youtube.com"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	}
	res := runYouTube(t, p)
	if res.Category != CatUnknown || p.count("evil.example") != 0 {
		t.Fatalf("off-list redirect: %+v hits=%d", res, p.count("evil.example"))
	}

	p = newPlatform(t)
	var mu sync.Mutex
	var got []string
	p.handlers["www.youtube.com"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://youtube.com/premium", http.StatusMovedPermanently)
	}
	p.handlers["youtube.com"] = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Values("Cookie")...)
		mu.Unlock()
		_, _ = w.Write([]byte(`"INNERTUBE_CONTEXT_GL":"US" ad-free`))
	}
	res = runYouTube(t, p)
	mu.Lock()
	defer mu.Unlock()
	if res.Category != CatUnlocked || len(got) != 1 || got[0] != youtubeConsentCookie {
		t.Fatalf("listed-host redirect: %+v cookies=%q", res, got)
	}
}

func TestAutomaticRoutingEvidenceBoundary(t *testing.T) {
	for _, id := range []string{"auto-perplexity", "auto-grok", "auto-openai", "auto-anthropic", "peacock", "tubi", "not-a-platform"} {
		if AutoRouteEligible(id) {
			t.Errorf("weak method admitted: %s", id)
		}
	}
	for _, id := range []string{"auto-netflix", "youtube-premium", "auto-disney", "auto-kktv", "auto-abema", "bglobal-sea", "fubotv", "auto-gemini"} {
		if !AutoRouteEligible(id) {
			t.Errorf("documented marker excluded: %s", id)
		}
	}
}
