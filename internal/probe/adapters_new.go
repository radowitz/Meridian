package probe

// Adapters implemented after reading the cited sources at SourceCommits
// (2026-11-14): items of the region lists that were "not reviewed" before
// and turned out to have a sound unauthenticated signal on a fixed host.
// The method of each is described in its Basis in this project's own
// words; request URLs, fixed bodies and response markers are facts of the
// public method, the code is this project's. Validation status as every
// adapter: synthetic fixtures only, real platforms unverified.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	// unextBody asks the playlist resolver of a fixed title for the one
	// field the method reads (resultStatus). The public method sends the
	// web player's full query; this shorter query is this project's own and
	// is the one difference of the request (real-platform acceptance
	// unverified).
	unextBody = `{"operationName":"cosmo_getPlaylistUrl","variables":{"code":"ED00479780","playMode":"caption","bitrateLow":192,"bitrateHigh":null,"validationOnly":false},"query":"query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) { webfront_playlistUrl(code: $code, playMode: $playMode, bitrateLow: $bitrateLow, bitrateHigh: $bitrateHigh, validationOnly: $validationOnly) { resultStatus } }"}`
	dmmBody   = `{"query":"query FetchClient { client { isForeignAccess } }"}`
)

var jsonCT = [][2]string{{"Content-Type", "application/json"}}

var moreCatalog = []Adapter{
	{
		Service: "fod", Name: "FOD（富士电视台）", Capability: CapRegionVerdict, Returns: verdictReturns, IPv4Only: true, Section: SectionJP, Regions: []string{"jp"},
		Platforms: []Platform{{Name: "FOD", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "FOD", Primary: true, Hosts: []string{"geocontrol1.stream.ne.jp"},
			Steps: []Step{{URL: "https://geocontrol1.stream.ne.jp/fod-geo/check.xml?time=1624504256"}}, Classify: classifyFOD}},
		Basis:   "地区检查 XML 的 <FLAG TYPE=\"…\">：true = 可用（日本），false = 不可用；其他 = 未知",
		Limits:  "只说明地区检查通过；固定的 time 参数与公开方法相同；只发 IPv4",
		Sources: []Source{srcLMC2("MediaUnlockTest_FOD"), srcGO2("FOD.go")},
	},
	{
		Service: "unext", Name: "U-NEXT", Capability: CapRegionVerdict, Returns: verdictReturns, Section: SectionJP, Regions: []string{"jp"},
		Platforms: []Platform{{Name: "U-NEXT", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "U-NEXT", Primary: true, Hosts: []string{"cc.unext.jp"},
			Steps: []Step{{URL: "https://cc.unext.jp", Body: unextBody, Headers: jsonCT}}, Classify: classifyUNext}},
		Basis:   "播放列表接口（固定作品、匿名 GraphQL 请求）的 resultStatus：475 或 200 = 可用（日本），467 = 不可用；其他 = 未知",
		Limits:  "公开方法发送网页播放器的完整查询，本项目只请求 resultStatus 一个字段（自己写的较短查询），平台是否接受未验证；作品下架后会变成未知",
		Sources: []Source{srcLMC2("MediaUnlockTest_unext"), srcGO2("UNext.go")},
	},
	{
		Service: "dmm", Name: "DMM（地区判定接口）", Capability: CapRegionVerdict, Returns: verdictReturns, Section: SectionJP, Regions: []string{"jp"},
		Platforms: []Platform{{Name: "DMM", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "DMM", Primary: true, Hosts: []string{"api.tv.dmm.com"},
			Steps: []Step{{URL: "https://api.tv.dmm.com/graphql", Body: dmmBody, Headers: jsonCT}}, Classify: classifyDMM}},
		Basis:   "匿名 GraphQL 查询 client.isForeignAccess：false = 可用（日本），true = 海外访问，不可用；其他 = 未知",
		Limits:  "按 GO 的方法；LMC 的方法只看一个页面里的提示文字（判断依据弱），未采用",
		Sources: []Source{srcGO2("DMM.go"), srcLMC2("MediaUnlockTest_DMM（未采用）")},
	},
	{
		Service: "nhk-plus", Name: "NHK+", Capability: CapRegionVerdict, Returns: verdictReturns, Section: SectionJP, Regions: []string{"jp"},
		Platforms: []Platform{{Name: "NHK+", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "NHK+", Primary: true, Hosts: []string{"location-plus.nhk.jp"},
			Steps: []Step{{URL: "https://location-plus.nhk.jp/geoip/area.json"}}, Classify: classifyNHKPlus}},
		Basis:   "平台自己的地理接口 JSON country_code：JP = 可用（日本），其他国家码 = 不可用（地区不符）；非质询的 403 = 拒绝；其他 = 未知",
		Limits:  "只说明平台把地址认作日本，不代表账号能看",
		Sources: []Source{srcGO2("NHKPlus.go")},
	},
	{
		Service: "4gtv", Name: "4GTV", Capability: CapRegionVerdict, Returns: verdictReturns, IPv4Only: true, Section: SectionTW, Regions: []string{"tw"},
		Platforms: []Platform{{Name: "4GTV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "4GTV", Primary: true, Hosts: []string{"api2.4gtv.tv"},
			Steps: []Step{{URL: "https://api2.4gtv.tv/Web/IsTaiwanArea", Headers: [][2]string{{"Origin", "https://www.4gtv.tv"}, {"Referer", "https://www.4gtv.tv/"}}}}, Classify: classify4GTV}},
		Basis:   "IsTaiwanArea 接口 JSON 的 Data：Y = 可用（台湾），N = 不可用；其他 = 未知",
		Limits:  "按 LMC 的方法；GO 的方法要 POST 一段编码过的请求体，未采用；只发 IPv4",
		Sources: []Source{srcLMC2("MediaUnlockTest_4GTV"), srcGO2("4GTV.go（未采用）")},
	},
	{
		Service: "friday-video", Name: "friDay 影音", Capability: CapVerdict, Returns: verdictReturns, Section: SectionTW, Regions: []string{"tw"},
		Platforms: []Platform{{Name: "friDay 影音", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "friDay 影音", Primary: true, Hosts: []string{"video.friday.tw"},
			Steps: []Step{{URL: "https://video.friday.tw/api2/streaming/get?streamingId=122581&streamingType=2&contentType=4&contentId=1&clientId="}}, Classify: classifyFriday}},
		Basis:   "播放接口（固定作品、空 clientId）JSON 的 code：0000 = 可用，1006 = 不可用；其他 = 未知",
		Limits:  "只说明地区检查通过；作品下架后会变成未知",
		Sources: []Source{srcGO2("FridayVideo.go")},
	},
	{
		Service: "nbatv", Name: "NBA TV", Capability: CapVerdict, Returns: verdictReturns, Section: SectionInternational,
		Platforms: []Platform{{Name: "NBA TV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "NBA TV", Primary: true, Hosts: []string{"www.nba.com"},
			Steps: []Step{{URL: "https://www.nba.com/watch/"}}, Classify: classifyNBATV}},
		Basis:   "观看页：含 Service is not available in your region = 不可用；200 且没有这句 = 可用（无负面标记）；其他 = 未知",
		Limits:  "多国服务，不判断目录地区；“可用”只是没有负面标记",
		Sources: []Source{srcLMC2("MediaUnlockTest_NBATV"), srcGO2("NBATV.go")},
	},
	{
		Service: "bglobal-sea", Name: "B-Global（东南亚）", Capability: CapVerdict, Returns: verdictReturns, IPv4Only: true, Section: SectionSG,
		Regions:   []string{"sg", "my", "th", "id", "vn", "ph"},
		Platforms: []Platform{{Name: "B-Global", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "B-Global", Primary: true, Hosts: []string{"api.bilibili.tv"},
			Steps: []Step{{URL: "https://api.bilibili.tv/intl/gateway/web/playurl?s_locale=en_US&platform=web&ep_id=347666"}}, Classify: classifyBGlobal}},
		Basis:   "国际版播放地址接口（固定剧集）JSON 的 code：0 = 可用（东南亚版权区），10003003 或 10004001 = 不可用；其他 = 未知",
		Limits:  "只判断这部东南亚版权作品；只发 IPv4",
		Sources: []Source{srcLMC2("MediaUnlockTest_BGlobalSEA")},
	},
	{
		Service: "fubotv", Name: "fuboTV", Capability: CapVerdict, Returns: verdictReturns, IPv4Only: true, Section: SectionUS,
		Platforms: []Platform{{Name: "fuboTV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "fuboTV", Primary: true, Hosts: []string{"api.fubo.tv"},
			Steps: []Step{{URL: "https://api.fubo.tv/v3/location", Headers: [][2]string{{"Origin", "https://www.fubo.tv"}, {"Referer", "https://www.fubo.tv/"}}}}, Classify: classifyFubo}},
		Basis:   "位置接口：含 NO_SERVICE_IN_COUNTRY 或 \"network_allowed\":false = 不可用；\"network_allowed\":true = 可用（country_code2 只作展示）；其他 = 未知",
		Limits:  "fuboTV 在几个国家开放，地区只作展示；只发 IPv4",
		Sources: []Source{srcLMC2("MediaUnlockTest_FuboTV"), srcGO2("FuboTV.go")},
	},
	{
		Service: "philo", Name: "Philo", Capability: CapVerdict, Returns: verdictReturns, IPv4Only: true, Section: SectionUS, Regions: []string{"us"},
		Platforms: []Platform{{Name: "Philo", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Philo", Primary: true, Hosts: []string{"content-us-east-2-fastly-b.www.philo.com"},
			Steps: []Step{{URL: "https://content-us-east-2-fastly-b.www.philo.com/geo"}}, Classify: classifyPhilo}},
		Basis:   "地理接口 JSON 的 status：SUCCESS = 可用，FAIL = 不可用；其他 = 未知",
		Limits:  "主机名是公开方法写死的 CDN 名字，改名后会失败；只发 IPv4",
		Sources: []Source{srcLMC2("MediaUnlockTest_Philo"), srcGO2("Philo.go")},
	},
	{
		Service: "sling", Name: "Sling TV", Capability: CapVerdict, Returns: verdictReturns, Section: SectionUS, Regions: []string{"us"},
		Platforms: []Platform{{Name: "Sling TV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Sling TV", Primary: true, Hosts: []string{"www.sling.com"},
			Steps: []Step{{URL: "https://www.sling.com/"}}, Classify: classifySling}},
		Basis:   "首页跟随跳转后的最终地址：含 geo-block = 不可用；200 = 可用（无负面标记）；其他 = 未知",
		Limits:  "只看是否被引到地区封锁页",
		Sources: []Source{srcLMC2("MediaUnlockTest_SlingTV"), srcGO2("SlingTV.go")},
	},
	{
		Service: "tubi", Name: "Tubi", Capability: CapVerdict, Returns: verdictReturns, Section: SectionUS,
		Platforms: []Platform{{Name: "Tubi", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Tubi", Primary: true, Hosts: []string{"tubitv.com", "www.tubitv.com"},
			Steps: []Step{{URL: "https://tubitv.com/home"}}, Classify: classifyTubi}},
		Basis:   "首页：含 not currently available in your area = 不可用；含 manifest = 可用；都没有 = 未知",
		Limits:  "“可用”的依据是页面里的 manifest 字样（公开方法如此），较弱；多国开放，不判断目录地区",
		Sources: []Source{srcLMC2("MediaUnlockTest_TubiTV"), srcGO2("TubiTV.go")},
	},
	{
		Service: "acorntv", Name: "Acorn TV", Capability: CapVerdict, Returns: verdictReturns, IPv4Only: true, Section: SectionUS,
		Platforms: []Platform{{Name: "Acorn TV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Acorn TV", Primary: true, Hosts: []string{"acorn.tv", "www.acorn.tv"},
			Steps: []Step{{URL: "https://acorn.tv/"}}, Classify: classifyAcorn}},
		Basis:   "首页：含 not yet available in your 或 unavailable in your = 不可用；含 signup.acorn.tv（注册入口）= 可用；都没有 = 未知",
		Limits:  "多国开放，不判断目录地区；只发 IPv4",
		Sources: []Source{srcLMC2("MediaUnlockTest_AcornTV"), srcGO2("AcornTV.go")},
	},
	{
		Service: "britbox", Name: "BritBox", Capability: CapVerdict, Returns: verdictReturns, Section: SectionUS,
		Platforms: []Platform{{Name: "BritBox", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "BritBox", Primary: true, Hosts: []string{"www.britbox.com", "britbox.com"},
			Steps: []Step{{URL: "https://www.britbox.com/"}}, Classify: classifyBritBox}},
		Basis:   "首页跟随跳转后的最终地址：含 locationnotsupported、locationnotvalidated 或被引到 britbox.co.uk = 不可用；200 = 可用（无负面标记）；其他 = 未知",
		Limits:  "只看跳转去向；多国开放，不判断目录地区",
		Sources: []Source{srcLMC2("MediaUnlockTest_BritBox"), srcGO2("BritBox.go")},
	},
	{
		Service: "amcplus", Name: "AMC+", Capability: CapVerdict, Returns: verdictReturns, Section: SectionUS,
		Platforms: []Platform{{Name: "AMC+", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "AMC+", Primary: true, Hosts: []string{"www.amcplus.com", "amcplus.com"},
			Steps: []Step{{URL: "https://www.amcplus.com/"}}, Classify: classifyAMCPlus}},
		Basis:   "首页跟随跳转后的最终地址：含 geographic-restriction 或非质询的 403 = 不可用；200 = 可用（无负面标记）；其他 = 未知",
		Limits:  "公开方法从最终地址的末段读一个地区名，本项目不采用（只作展示意义也不大）；多国开放，不判断目录地区",
		Sources: []Source{srcLMC2("MediaUnlockTest_AMCPlus"), srcGO2("AMCPlus.go")},
	},
	{
		Service: "metaai", Name: "Meta AI", Capability: CapVerdict, Returns: verdictReturns, Section: SectionAI,
		Platforms: []Platform{{Name: "Meta AI", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Meta AI", Primary: true, Hosts: []string{"www.meta.ai"},
			Steps: []Step{{URL: "https://www.meta.ai/"}}, Classify: classifyMetaAI}},
		Basis:   "首页：含 AbraGeoBlockedErrorRoot = 地区封锁，不可用；含 KadabraRootContainer = 可用（\"code\":\"xx_YY\" 的 YY 只作展示）；都没有 = 未知",
		Limits:  "标记是页面组件名，改版会变成未知；不是账号判断",
		Sources: []Source{srcLMC2("WebTest_MetaAI")},
	},
	{
		Service: "coze", Name: "Coze", Capability: CapVerdict, Returns: verdictReturns, Section: SectionAI,
		Platforms: []Platform{{Name: "Coze", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Coze", Primary: true, Hosts: []string{"www.coze.com"},
			Steps: []Step{{URL: "https://www.coze.com/api/developer/get_login_info"}}, Classify: classifyCoze}},
		Basis:   "未登录信息接口 JSON：data.IsForbiddenRegion = true 或应答含 Your region is not supported = 不可用；data.CountryCode 非空 = 可用（地区只作展示）；非质询的 403 = 拒绝；其他 = 未知",
		Limits:  "接口没有公开文档；不是账号判断",
		Sources: []Source{srcGO2("Coze.go")},
	},
}

func classifyFOD(r Response, exitRegion string) Verdict {
	m := reFODFlag.FindSubmatch(r.Body)
	if r.Status != http.StatusOK || m == nil {
		return unexpected(r, "FOD")
	}
	switch strings.ToLower(string(m[1])) {
	case "true":
		return regionVerdict("jp", exitRegion, `HTTP 200，<FLAG TYPE="true">`)
	case "false":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: `HTTP 200，<FLAG TYPE="false">`}
	}
	return unknown(SigUnexpected, "FLAG TYPE=%s：不是已知结果", clip(string(m[1]), 16))
}

func classifyUNext(r Response, exitRegion string) Verdict {
	m := reUNextStatus.FindSubmatch(r.Body)
	if m == nil {
		return unexpected(r, "U-NEXT")
	}
	switch string(m[1]) {
	case "475", "200":
		return regionVerdict("jp", exitRegion, "resultStatus="+string(m[1]))
	case "467":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "resultStatus=467（地区不允许）"}
	}
	return unknown(SigUnexpected, "resultStatus=%s：不是已知结果", clip(string(m[1]), 8))
}

func classifyDMM(r Response, exitRegion string) Verdict {
	b := string(r.Body)
	switch {
	case strings.Contains(b, `"isForeignAccess":true`):
		return Verdict{Category: CatNotUnlocked, Signal: SigRegionMismatch, Evidence: "isForeignAccess=true（海外访问）"}
	case strings.Contains(b, `"isForeignAccess":false`):
		return regionVerdict("jp", exitRegion, "isForeignAccess=false")
	}
	return unexpected(r, "DMM")
}

func classifyNHKPlus(r Response, exitRegion string) Verdict {
	if r.Status == http.StatusForbidden {
		return blocked403("NHK+")
	}
	c, ok := jsonString(r.Body, "country_code")
	if r.Status != http.StatusOK || !ok || !reCC2.MatchString(c) {
		return unexpected(r, "NHK+")
	}
	if strings.EqualFold(c, "JP") {
		return regionVerdict("jp", exitRegion, "area.json：country_code=JP")
	}
	return Verdict{Category: CatNotUnlocked, Region: strings.ToLower(c), Signal: SigRegionMismatch, Evidence: "area.json：country_code=" + strings.ToUpper(c) + "（不是日本）"}
}

func classify4GTV(r Response, exitRegion string) Verdict {
	m := re4GTVData.FindSubmatch(r.Body)
	if r.Status != http.StatusOK || m == nil {
		return unexpected(r, "4GTV")
	}
	switch string(m[1]) {
	case "Y":
		return regionVerdict("tw", exitRegion, "IsTaiwanArea：Data=Y")
	case "N":
		return Verdict{Category: CatNotUnlocked, Signal: SigRegionMismatch, Evidence: "IsTaiwanArea：Data=N"}
	}
	return unknown(SigUnexpected, "IsTaiwanArea：Data=%s 不是已知结果", clip(string(m[1]), 8))
}

func classifyFriday(r Response, _ string) Verdict {
	code, ok := jsonString(r.Body, "code")
	switch {
	case ok && code == "0000":
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "streaming/get code=0000"}
	case ok && code == "1006":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "streaming/get code=1006（地区不允许）"}
	case ok:
		return unknown(SigUnexpected, "streaming/get code=%s：不是已知结果", clip(code, 16))
	}
	return unexpected(r, "friDay 影音")
}

func classifyNBATV(r Response, _ string) Verdict {
	if containsFold(r.Body, "Service is not available in your region") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面提示服务在该地区不可用", r.Status)}
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有地区不可用提示"}
	}
	return unexpected(r, "NBA TV")
}

func classifyBGlobal(r Response, _ string) Verdict {
	var v struct {
		Code *json.Number `json:"code"`
	}
	if json.Unmarshal(r.Body, &v) != nil || v.Code == nil {
		return unexpected(r, "B-Global")
	}
	switch v.Code.String() {
	case "0":
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "playurl code=0"}
	case "10003003", "10004001":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "playurl code=" + v.Code.String() + "（不在版权区）"}
	}
	return unknown(SigUnexpected, "playurl code=%s：不是已知结果", clip(v.Code.String(), 12))
}

func classifyFubo(r Response, _ string) Verdict {
	b := string(r.Body)
	if containsFold(r.Body, "NO_SERVICE_IN_COUNTRY") || strings.Contains(b, `"network_allowed":false`) {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，NO_SERVICE_IN_COUNTRY / network_allowed=false", r.Status)}
	}
	if strings.Contains(b, `"network_allowed":true`) {
		c, _ := jsonString(r.Body, "country_code2")
		v := Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "network_allowed=true（地区仅展示）"}
		if reCC2.MatchString(c) {
			v.Region = strings.ToLower(c)
		}
		return v
	}
	return unexpected(r, "fuboTV")
}

func classifyPhilo(r Response, _ string) Verdict {
	st, ok := jsonString(r.Body, "status")
	switch {
	case ok && st == "SUCCESS":
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "geo：status=SUCCESS"}
	case ok && st == "FAIL":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "geo：status=FAIL"}
	case ok:
		return unknown(SigUnexpected, "geo：status=%s 不是已知结果", clip(st, 16))
	}
	return unexpected(r, "Philo")
}

func classifySling(r Response, _ string) Verdict {
	if urlHas(r, "geo-block") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "最终地址含 geo-block"}
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有被引到地区封锁页"}
	}
	return unexpected(r, "Sling TV")
}

func classifyTubi(r Response, _ string) Verdict {
	switch {
	case containsFold(r.Body, "not currently available in your area"):
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面提示该地区不可用", r.Status)}
	case r.Status == http.StatusOK && containsFold(r.Body, "manifest"):
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "HTTP 200，页面含 manifest（公开方法的可用标记，较弱）"}
	}
	return unexpected(r, "Tubi")
}

func classifyMetaAI(r Response, _ string) Verdict {
	switch {
	case containsFold(r.Body, "AbraGeoBlockedErrorRoot"):
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面是地区封锁组件", r.Status)}
	case containsFold(r.Body, "KadabraRootContainer"):
		v := Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: fmt.Sprintf("HTTP %d，页面是正常应用组件（不是账号判断）", r.Status)}
		if m := reMetaRegion.FindSubmatch(r.Body); m != nil {
			v.Region = strings.ToLower(string(m[1]))
			v.Evidence += "，地区 " + string(m[1]) + "（仅展示）"
		}
		return v
	}
	return unexpected(r, "Meta AI")
}

func classifyCoze(r Response, _ string) Verdict {
	if containsFold(r.Body, "Your region is not supported") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，应答提示地区不支持", r.Status)}
	}
	if r.Status == http.StatusForbidden {
		return blocked403("Coze")
	}
	var v struct {
		Data *struct {
			IsForbiddenRegion bool   `json:"IsForbiddenRegion"`
			CountryCode       string `json:"CountryCode"`
		} `json:"data"`
	}
	if json.Unmarshal(r.Body, &v) != nil || v.Data == nil {
		return unexpected(r, "Coze")
	}
	if v.Data.IsForbiddenRegion {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "get_login_info：IsForbiddenRegion=true"}
	}
	if reCC2.MatchString(v.Data.CountryCode) {
		return Verdict{Category: CatUnlocked, Region: strings.ToLower(v.Data.CountryCode), Signal: SigAvailable, Evidence: "get_login_info：CountryCode=" + strings.ToUpper(v.Data.CountryCode) + "（地区仅展示）"}
	}
	return unknown(SigUnexpected, "get_login_info：没有 CountryCode")
}

func classifyAcorn(r Response, _ string) Verdict {
	switch {
	case containsFold(r.Body, "not yet available in your") || containsFold(r.Body, "unavailable in your"):
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面提示该地区不可用", r.Status)}
	case containsFold(r.Body, "signup.acorn.tv"):
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: fmt.Sprintf("HTTP %d，页面有注册入口 signup.acorn.tv", r.Status)}
	}
	return unexpected(r, "Acorn TV")
}

func classifyBritBox(r Response, _ string) Verdict {
	if urlHas(r, "locationnotsupported") || urlHas(r, "locationnotvalidated") || (r.URL != nil && strings.HasSuffix(r.URL.Host, "britbox.co.uk")) {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "被引到地区不支持页或英国站"}
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有地区限制跳转"}
	}
	return unexpected(r, "BritBox")
}

func classifyAMCPlus(r Response, _ string) Verdict {
	if urlHas(r, "geographic-restriction") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "最终地址含 geographic-restriction"}
	}
	if r.Status == http.StatusForbidden {
		return blocked403("AMC+")
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有地区限制跳转"}
	}
	return unexpected(r, "AMC+")
}
