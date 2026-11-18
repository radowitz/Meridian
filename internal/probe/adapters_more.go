package probe

// Classifiers of the adapters added with the coverage table (coverage.go),
// written in this project's own code from the request facts and response
// markers of the cited sources at SourceCommits (no code was copied). Same
// rules as adapters.go: guard (challenge, 429, 5xx) runs first, a
// documented negative marker is not_unlocked, a documented positive marker
// is unlocked (region adapters also need the region to match the exit),
// anything else is unknown. None of them reads cookies or sends any.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/radowitz/meridian/internal/unlock"
)

var (
	reYTRegion      = regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Za-z]{2})"`)
	rePrimeTerr     = regexp.MustCompile(`"currentTerritory"\s*:\s*"([A-Za-z]{2})"`)
	rePrimeRestrict = regexp.MustCompile(`"isServiceRestricted"\s*:\s*true`)
	reRadikoArea    = regexp.MustCompile(`class="JP\d{1,2}">([^<]{1,40})<`)
	reFODFlag       = regexp.MustCompile(`<FLAG\s+TYPE="([^"]+)"`)
	reUNextStatus   = regexp.MustCompile(`"resultStatus"\s*:\s*(\d+)`)
	re4GTVData      = regexp.MustCompile(`"Data"\s*:\s*"([^"]*)"`)
	reMetaRegion    = regexp.MustCompile(`"code"\s*:\s*"[a-z]{2}_([A-Z]{2})"`)
)

func containsFold(b []byte, s string) bool {
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(s))
}

func urlHas(r Response, s string) bool {
	return r.URL != nil && strings.Contains(strings.ToLower(r.URL.Host+r.URL.Path), strings.ToLower(s))
}

func blocked403(platform string) Verdict {
	return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403（非质询页）：" + platform + " 拒绝该地址"}
}

// youtubeConsentCookie is the fixed, public consent cookie value that the
// cited public method (lmc999/RegionRestrictionCheck,
// MediaUnlockTest_YouTube_Premium) sends so the page is not replaced by the
// consent interstitial. It encodes only "consent given"; it carries no
// identity. The visitor / session identifier cookies sent next to it by that
// method are deliberately NOT sent.
const youtubeConsentCookie = "SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY"

// reYTConsentForm matches a consent interstitial: a form posting to a Google
// consent host.
var reYTConsentForm = regexp.MustCompile(`(?is)<form[^>]+action\s*=\s*["']?(?:https?:)?//consent\.(?:youtube|google)\.com`)

// isYouTubeConsent reports a consent page in either form: a redirect that
// stopped on a consent host (the host is not in the adapter's fixed list, so
// it is not followed), or a body that is the consent interstitial.
func isYouTubeConsent(r Response) bool {
	if r.URL != nil && (r.URL.Hostname() == "consent.youtube.com" || r.URL.Hostname() == "consent.google.com") {
		return true
	}
	return reYTConsentForm.Match(r.Body) || containsFold(r.Body, "Before you continue to YouTube")
}

// youtubePremiumMaxBody is the youtube-premium step's fixed body limit. On
// 2026-11-15 the Premium page was about 975 KB with the first ad-free
// marker near byte 850,000, past the default MaxBody. 2 MiB leaves room for
// growth while staying bounded: one request per exit per address family,
// at most 2 MiB held per request, transport timeouts unchanged.
const youtubePremiumMaxBody = 2 << 20

// disneyMaxBody is the auto-disney step's fixed body limit. On 2026-11-15
// the home page was about 1.95 MB with the visitor-location marker near
// byte 860,000, past the default MaxBody. 2 MiB reaches it with margin and
// stays inside MaxBodyCeiling: one request per exit per address family, at
// most 2 MiB held per request, timeouts unchanged. A bigger page whose
// marker falls beyond the limit is unknown with truncation evidence.
const disneyMaxBody = 2 << 20

// netflixMaxBody is the auto-netflix step's fixed body limit. On 2026-11-15
// a Hong Kong exit's title page was about 690 KB with the requestCountry
// marker near byte 454,000; a US exit (no redirect, no URL prefix) was cut at
// the default 256 KiB. 2 MiB reaches such a marker with margin and stays
// inside MaxBodyCeiling: one request per exit per address family, at most
// 2 MiB held per request, timeouts unchanged.
const netflixMaxBody = 2 << 20

// geminiMaxBody / metaAIMaxBody: both front pages are well over the
// default 256 KiB and the public markers are not guaranteed to sit early.
const (
	geminiMaxBody = 2 << 20
	metaAIMaxBody = 2 << 20
)

func classifyYouTubePremium(r Response, _ string) Verdict {
	// Consent first: an interstitial can mention ad-free or www.google.cn in
	// its text, and must never be read as a verdict.
	if isYouTubeConsent(r) {
		return unknown(SigConsent, "HTTP %d，同意页（Cookie 同意值没有生效或被平台换成同意页）：无法判断", r.Status)
	}
	if containsFold(r.Body, "www.google.cn") || (r.URL != nil && r.URL.Host == "www.google.cn") {
		return Verdict{Category: CatNotUnlocked, Region: "cn", Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面引用 www.google.cn（中国大陆地址）", r.Status)}
	}
	if containsFold(r.Body, "Premium is not available in your country") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面提示 Premium 在该国家不可用", r.Status)}
	}
	if r.Status == http.StatusOK && containsFold(r.Body, "ad-free") {
		v := Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "HTTP 200，介绍页含 ad-free（无负面标记；不是账号判断）"}
		if m := reYTRegion.FindSubmatch(r.Body); m != nil {
			v.Region = strings.ToLower(string(m[1]))
			v.Evidence += "，INNERTUBE_CONTEXT_GL=" + strings.ToUpper(v.Region) + "（仅展示）"
		}
		return v
	}
	if r.Status == http.StatusOK {
		return unknown(SigUnexpected, "HTTP 200，但既没有不可用提示也没有 ad-free 字样（页面可能改版）")
	}
	return unexpected(r, "YouTube Premium")
}

func classifyPrimeVideo(r Response, exitRegion string) Verdict {
	if r.Status != http.StatusOK {
		return unexpected(r, "Prime Video")
	}
	if rePrimeRestrict.Match(r.Body) {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "HTTP 200，页面数据 isServiceRestricted=true"}
	}
	if m := rePrimeTerr.FindSubmatch(r.Body); m != nil {
		return regionVerdict(string(m[1]), exitRegion, "HTTP 200，页面 currentTerritory="+strings.ToUpper(string(m[1])))
	}
	return unknown(SigUnexpected, "HTTP 200，但没有 currentTerritory / isServiceRestricted=true")
}

func classifyDAZN(r Response, exitRegion string) Verdict {
	if containsFold(r.Body, "Security policy has been breached") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，应答含 Security policy has been breached（拒绝该地址）", r.Status)}
	}
	if r.Status == http.StatusForbidden {
		return blocked403("DAZN")
	}
	var v struct {
		Region *struct {
			IsAllowed         *bool  `json:"isAllowed"`
			GeolocatedCountry string `json:"GeolocatedCountry"`
		} `json:"Region"`
	}
	if r.Status != http.StatusOK || json.Unmarshal(r.Body, &v) != nil || v.Region == nil || v.Region.IsAllowed == nil {
		return unexpected(r, "DAZN")
	}
	c := strings.ToLower(v.Region.GeolocatedCountry)
	if !reCC2.MatchString(c) {
		c = ""
	}
	if !*v.Region.IsAllowed {
		return Verdict{Category: CatNotUnlocked, Region: c, Signal: SigBlocked, Evidence: "Startup：Region.isAllowed=false（" + strings.ToUpper(c) + "）"}
	}
	if c == "" {
		return unknown(SigUnexpected, "Startup：isAllowed=true，但没有可读的 GeolocatedCountry")
	}
	return regionVerdict(c, exitRegion, "Startup：Region.isAllowed=true，GeolocatedCountry="+strings.ToUpper(c))
}

func classifyTVBAnywhere(r Response, _ string) Verdict {
	var v struct {
		Allow   *bool  `json:"allow_in_this_country"`
		Country string `json:"country"`
	}
	if r.Status != http.StatusOK || json.Unmarshal(r.Body, &v) != nil || v.Allow == nil {
		return unexpected(r, "TVBAnywhere+")
	}
	c := strings.ToLower(v.Country)
	if !reCC2.MatchString(c) {
		c = ""
	}
	if *v.Allow {
		return Verdict{Category: CatUnlocked, Region: c, Signal: SigAvailable, Evidence: "geoip：allow_in_this_country=true（地区仅展示）"}
	}
	return Verdict{Category: CatNotUnlocked, Region: c, Signal: SigBlocked, Evidence: "geoip：allow_in_this_country=false"}
}

func classifyDMMTV(r Response, exitRegion string) Verdict {
	b := string(r.Body)
	switch {
	case strings.Contains(b, "FOREIGN"):
		return dmmForeign(fmt.Sprintf("HTTP %d，应答含 FOREIGN", r.Status), exitRegion)
	case strings.Contains(b, "UNAUTHORIZED"):
		return regionVerdict("jp", exitRegion, fmt.Sprintf("HTTP %d，应答含 UNAUTHORIZED（通过地区检查，只差登录）", r.Status))
	}
	return unexpected(r, "DMM TV")
}

// dmmForeign is the verdict for DMM's "foreign access" flag. The flag names
// no country, so it is never a region mismatch: on a Japanese exit it means
// DMM treats the address itself as foreign (typically a datacenter / VPN
// range), elsewhere it is the expected overseas block.
func dmmForeign(evidence, exitRegion string) Verdict {
	if unlock.NormRegion(exitRegion) == "jp" {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked,
			Evidence: evidence + "：出口在日本但平台判为海外访问，多半是机房/VPN 地址被当成海外（平台不报国家，不是地区不一致）"}
	}
	return Verdict{Category: CatNotUnlocked, Signal: SigRegionMismatch, Evidence: evidence + "（海外访问）"}
}

func classifyHuluJP(r Response, exitRegion string) Verdict {
	if urlHas(r, "restrict") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "最终地址是地区限制页 " + r.URL.Path}
	}
	if r.Status == http.StatusForbidden {
		return blocked403("Hulu Japan")
	}
	if r.Status == http.StatusOK && r.URL != nil && strings.HasSuffix(r.URL.Host, "hulu.jp") {
		return regionVerdict("jp", exitRegion, "HTTP 200，停在 "+r.URL.Host+r.URL.Path+"（没有地区限制跳转）")
	}
	return unexpected(r, "Hulu Japan")
}

func classifyRadiko(r Response, exitRegion string) Verdict {
	if r.Status != http.StatusOK {
		return unexpected(r, "radiko")
	}
	if strings.Contains(string(r.Body), `class="OUT"`) {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: `HTTP 200，地区 class="OUT"（日本以外）`}
	}
	if containsFold(r.Body, "JAPAN") {
		ev := "HTTP 200，地区应答含 JAPAN"
		if m := reRadikoArea.FindSubmatch(r.Body); m != nil {
			ev += "（" + clip(string(m[1]), 30) + "，仅展示）"
		}
		return regionVerdict("jp", exitRegion, ev)
	}
	return unknown(SigUnexpected, "HTTP 200，既没有 OUT 也没有 JAPAN")
}

func classifyMyVideo(r Response, _ string) Verdict {
	if urlHas(r, "serviceAreaBlock") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "最终地址含 serviceAreaBlock：地区限制"}
	}
	if r.Status == http.StatusForbidden {
		return blocked403("MyVideo")
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有地区限制跳转"}
	}
	return unexpected(r, "MyVideo")
}

func classifyPeacock(r Response, _ string) Verdict {
	if urlHas(r, "unavailable") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "最终地址含 unavailable：Peacock 在该地区不可用"}
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有被引到不可用页"}
	}
	return unexpected(r, "Peacock")
}

func classifyPlutoTV(r Response, _ string) Verdict {
	if urlHas(r, "plutotv-is-not-available") || containsFold(r.Body, "thanks-for-watching") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，被引到不可用页（plutotv-is-not-available / thanks-for-watching）", r.Status)}
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有不可用标记"}
	}
	return unexpected(r, "Pluto TV")
}
