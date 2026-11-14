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

func classifyYouTubePremium(r Response, _ string) Verdict {
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
		return unknown(SigUnexpected, "HTTP 200，但既没有不可用提示也没有 ad-free 字样（页面可能改版或要求先同意 Cookie）")
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
		return Verdict{Category: CatNotUnlocked, Signal: SigRegionMismatch, Evidence: fmt.Sprintf("HTTP %d，应答含 FOREIGN（海外地址）", r.Status)}
	case strings.Contains(b, "UNAUTHORIZED"):
		return regionVerdict("jp", exitRegion, fmt.Sprintf("HTTP %d，应答含 UNAUTHORIZED（通过地区检查，只差登录）", r.Status))
	}
	return unexpected(r, "DMM TV")
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
