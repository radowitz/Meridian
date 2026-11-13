package probe

// The service catalog: one adapter per automatic rule, each with an explicit
// capability declaration, the fixed requests it makes, the hosts it may
// reach, the classifier that reads the answers and the public method it was
// derived from. docs/unlock-methods.md is the human-readable version of this
// table; keep them in step.
//
// Status of every adapter in this build: implemented from public detection
// methods, tested on synthetic fixtures only, real-platform behaviour
// pending human verification (Validation / ValidationText). Nothing here has
// been run against the real platforms by this project.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/radowitz/meridian/internal/unlock"
)

// Category is what one probe established. Only CatUnlocked and
// CatNotUnlocked are platform verdicts; CatNetworkOK is reachability only;
// CatFailed and CatUnknown are not statements about the platform.
type Category string

const (
	// CatNetworkOK: egress confirmed and the platform answered over the
	// requested family through the intended exit. Never an unlock verdict.
	CatNetworkOK Category = "network_ok"
	// CatUnlocked: a documented positive marker was found (and, for region
	// adapters, its region matches the exit).
	CatUnlocked Category = "unlocked"
	// CatNotUnlocked: a documented negative marker was found (block page,
	// unavailable-in-region, other catalog region).
	CatNotUnlocked Category = "not_unlocked"
	// CatFailed: no answer to classify. Timeout, DNS or transport error,
	// wrong egress, wrong family, cancellation.
	CatFailed Category = "failed"
	// CatUnknown: the platform answered but not with a documented marker
	// (anti-bot challenge, login wall, changed page, server error).
	CatUnknown Category = "unknown"
	// CatNotApplicable: nothing was sent because the check does not apply
	// (an IPv4-only public method asked for IPv6). Not a response at all,
	// so neither unknown nor failed; never ingested.
	CatNotApplicable Category = "not_applicable"
)

// Grade is the evidence grade of a result, for the panel and for anyone
// reading a stored result: what kind of evidence the category rests on.
type Grade string

const (
	// GradePlatform: a platform verdict from a documented response signal.
	GradePlatform Grade = "platform_signal"
	// GradeReachability: the platform answered; nothing about unlocking.
	GradeReachability Grade = "reachability_only"
	// GradeUnknown: an answer without a documented marker.
	GradeUnknown Grade = "unknown_response"
	// GradeError: no usable answer, or the egress was not confirmed.
	GradeError Grade = "error"
	// GradeNotApplicable: no check ran because it does not apply.
	GradeNotApplicable Grade = "not_applicable"
)

// GradeOf derives the grade from the category. It is the only mapping;
// stored and agent-supplied grades are recomputed with it.
func GradeOf(c Category) Grade {
	switch c {
	case CatUnlocked, CatNotUnlocked:
		return GradePlatform
	case CatNetworkOK:
		return GradeReachability
	case CatUnknown:
		return GradeUnknown
	case CatNotApplicable:
		return GradeNotApplicable
	default:
		return GradeError
	}
}

// IngestVerdict is the single mapping from a category to the unlock state
// machine: unlocked → success, not_unlocked → failure, everything else (in
// particular reachability, unknown and not_applicable) → no verdict. A service whose
// families all have no verdict is ingested as unlock.KindInconclusive,
// which can neither demote nor restore an exit.
func IngestVerdict(c Category) (ok, has bool) {
	switch c {
	case CatUnlocked:
		return true, true
	case CatNotUnlocked:
		return false, true
	default:
		return false, false
	}
}

// Capability declares what an adapter can conclude.
type Capability string

const (
	// CapRegionVerdict: platform verdict including the platform's region.
	CapRegionVerdict Capability = "region_verdict"
	// CapVerdict: platform verdict without a region (or a region that is
	// informational only).
	CapVerdict Capability = "verdict"
	// CapReachability: reachability only; no public signal for a verdict.
	CapReachability Capability = "reachability"
	// CapUnsupported: no check runs (needs credentials, app tokens or JS).
	CapUnsupported Capability = "unsupported"
)

// Validation is the same for every adapter of this build.
const (
	Validation     = "synthetic_only"
	ValidationText = "检测规则依据公开检测方法与合成样本编写，本项目尚未在真实平台上验证；真实平台行为待人工核对。"
)

// Signals: short machine codes for the marker a verdict rests on.
const (
	SigRegionMatch    = "region_match"
	SigRegionMismatch = "region_mismatch"
	SigAvailable      = "available_marker"
	SigNoNegative     = "no_negative_marker"
	SigBlocked        = "blocked_marker"
	SigBlocked403     = "blocked_403"
	SigReachable      = "reachable"
	SigChallenge      = "anti_bot_challenge"
	SigLoginRequired  = "login_required"
	SigConsent        = "consent_page"
	SigRateLimited    = "rate_limited"
	SigServerError    = "server_error"
	SigRedirect       = "redirect_unlisted"
	SigUnexpected     = "unexpected_response"
	SigEgressChanged  = "egress_changed"
	SigFamily         = "family_not_supported"
)

// Verdict is a classifier's reading of one response.
type Verdict struct {
	Category Category
	Region   string
	Signal   string
	Evidence string
}

// Response is what a classifier sees: status, final URL (after the allowed
// redirects; for a redirect that was not followed, its target) and at most
// MaxBody bytes of the body. Prev holds the earlier steps of the same check.
type Response struct {
	Status int
	URL    *url.URL
	Body   []byte
	Prev   []Response
}

// ValuePlaceholder in a step URL is replaced by the value the previous
// step's Extract returned (query-escaped, and only if it matches extractRe).
const ValuePlaceholder = "{value}"

var extractRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Step is one fixed request.
type Step struct {
	URL string
	// Headers are fixed catalog constants (names limited by allowedHeaders).
	Headers [][2]string
	// Body, when set, makes the step a POST with this fixed body.
	Body string
	// NoRedirect classifies a redirect instead of following it.
	NoRedirect bool
	// Extract (non-final steps only) returns a value for the next steps'
	// ValuePlaceholder, or a verdict that ends the check here.
	Extract func(Response) (string, *Verdict)
}

// Check is one platform's check inside an adapter.
type Check struct {
	Platform string
	// Primary decides the service's category. Exactly one per adapter.
	// The others are informational: shown, never ingested.
	Primary  bool
	Hosts    []string
	Steps    []Step
	Classify func(r Response, exitRegion string) Verdict
}

// Platform lists a platform an adapter's service name mentions, whether it
// is checked, and why not when it is not.
type Platform struct {
	Name    string `json:"name"`
	Checked bool   `json:"checked"`
	Primary bool   `json:"primary"`
	Note    string `json:"note,omitempty"`
}

// Source is a public method an adapter's rules came from.
type Source struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Checked string `json:"checked"`
}

// Adapter is one catalog entry.
type Adapter struct {
	Service    string
	Name       string
	Capability Capability
	// Returns is every category Classify may return (CatFailed is added by
	// the transport). Enforced at run time and in the API.
	Returns []Category
	// IPv4Only: the public method is IPv4-only or the platform has no IPv6
	// service; IPv6 runs are not sent.
	IPv4Only  bool
	Platforms []Platform
	Checks    []Check
	// Combine explains how checks become the service result.
	Combine string
	Basis   string
	Limits  string
	Sources []Source
}

// Reachability is kept for older API readers.
func (a Adapter) Reachability() bool { return a.Capability == CapReachability }

func (a Adapter) primary() int {
	for i, c := range a.Checks {
		if c.Primary {
			return i
		}
	}
	return 0
}

// Allows reports whether c is one of the declared categories (or failed).
func (a Adapter) Allows(c Category) bool {
	if c == CatFailed {
		return true
	}
	for _, r := range a.Returns {
		if r == c {
			return true
		}
	}
	return false
}

// enforce downgrades a verdict the adapter did not declare.
func (a Adapter) enforce(v Verdict) Verdict {
	if a.Allows(v.Category) {
		return v
	}
	return Verdict{Category: CatUnknown, Signal: SigUnexpected,
		Evidence: fmt.Sprintf("（超出声明能力 %s，按未知处理）%s", a.Capability, v.Evidence)}
}

// Hosts is every host any step of the adapter may reach.
func (a Adapter) Hosts() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range a.Checks {
		for _, h := range c.Hosts {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// Requests lists the fixed requests, for the panel and docs.
func (a Adapter) Requests() []string {
	var out []string
	for _, c := range a.Checks {
		for _, s := range c.Steps {
			m := "GET"
			if s.Body != "" {
				m = "POST"
			}
			out = append(out, c.Platform+": "+m+" "+s.URL)
		}
	}
	return out
}

// Lookup returns the catalog entry for a rule id.
func Lookup(service string) (Adapter, bool) {
	for _, a := range Catalog {
		if a.Service == service {
			return a, true
		}
	}
	return Adapter{}, false
}

// Probeable: the service has an adapter with at least one check.
func Probeable(service string) bool {
	a, ok := Lookup(service)
	return ok && a.Capability != CapUnsupported && len(a.Checks) > 0
}

// SupportsFamily: whether a run on fam is sent at all.
func SupportsFamily(service string, fam unlock.Family) bool {
	a, ok := Lookup(service)
	return ok && !(a.IPv4Only && fam == unlock.FamilyIPv6)
}

// allowedHeaders are the only extra header names the catalog may set.
var allowedHeaders = map[string]bool{"User-Agent": true, "Referer": true, "Origin": true, "Accept": true, "Content-Type": true}

const checked = "2026-11-13"

var (
	srcLMC = func(fn string) Source {
		return Source{Name: "lmc999/RegionRestrictionCheck check.sh " + fn + "（main @ b6d4a6f）", URL: "https://github.com/lmc999/RegionRestrictionCheck/blob/main/check.sh", Checked: checked}
	}
	src1S = func(fn string) Source {
		return Source{Name: "1-stream/RegionRestrictionCheck check.sh " + fn + "（main @ ef841d0）", URL: "https://github.com/1-stream/RegionRestrictionCheck/blob/main/check.sh", Checked: checked}
	}
	srcGO = func(file string) Source {
		return Source{Name: "HsukqiLee/MediaUnlockTest pkg/providers/" + file + "（main @ dc6c6e6）", URL: "https://github.com/HsukqiLee/MediaUnlockTest/blob/main/pkg/providers/" + file, Checked: checked}
	}
)

const uaAndroid = "Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"

var (
	verdictReturns = []Category{CatUnlocked, CatNotUnlocked, CatUnknown}
	reachReturns   = []Category{CatNetworkOK, CatUnknown}
)

// Catalog is the fixed set of services, keyed by the project's rule ids.
var Catalog = []Adapter{
	{
		Service: "auto-netflix", Name: "Netflix", Capability: CapRegionVerdict, Returns: verdictReturns,
		Platforms: []Platform{{Name: "Netflix", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Netflix", Primary: true, Hosts: []string{"www.netflix.com", "netflix.com"},
			Steps: []Step{{URL: "https://www.netflix.com/title/81280792"}}, Classify: classifyNetflix}},
		Basis:  "自制剧标题页 81280792：403 = 拒绝该 IP；404 = 标题不可用（仅自制剧或未开通）；200 时从页面 requestCountry/countryCode 或 URL 的 /xx(-yy)/ 前缀取目录地区，必须与出口地区一致；其他 = 未知",
		Limits: "公开脚本带浏览器 Cookie 并比较自制剧与非自制剧两个标题，本适配器不带 Cookie、只看一个自制剧标题，所以“仅自制剧”与“完全解锁”不区分；页面结构变化会落到未知",
		Sources: []Source{srcLMC("MediaUnlockTest_Netflix"),
			{Name: "Meridian 既有适配器（本项目 5b01903 起）", URL: "internal/probe/adapters.go", Checked: checked}},
	},
	{
		Service: "auto-disney", Name: "Disney+", Capability: CapRegionVerdict, Returns: verdictReturns,
		Platforms: []Platform{{Name: "Disney+", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Disney+", Primary: true, Hosts: []string{"www.disneyplus.com", "disneyplus.com"},
			Steps: []Step{{URL: "https://www.disneyplus.com/"}}, Classify: classifyDisney}},
		Basis:   "首页：跳到含 unavailable/preview 的路径或 403 = 不可用；200 时从页面 countryCode/region 或 URL 的 /语言-地区 前缀取地区，必须与出口地区一致",
		Limits:  "公开脚本的完整方法要用 bamgrid 设备令牌（应用令牌）调 GraphQL，本项目不使用任何令牌，只用首页跳转与页面地区标记；首页常常不带地区标记，此时为未知",
		Sources: []Source{srcLMC("MediaUnlockTest_DisneyPlus（只取其首页跳转 preview|unavailable 判断）")},
	},
	{
		Service: "auto-openai", Name: "OpenAI / ChatGPT", Capability: CapVerdict, Returns: verdictReturns,
		Platforms: []Platform{{Name: "OpenAI API / Web", Checked: true, Primary: true}, {Name: "ChatGPT iOS", Checked: true, Note: "仅参考，不入库"}},
		Checks: []Check{
			{Platform: "OpenAI API / Web", Primary: true, Hosts: []string{"api.openai.com"},
				Steps: []Step{{URL: "https://api.openai.com/compliance/cookie_requirements",
					Headers: [][2]string{{"Origin", "https://platform.openai.com"}, {"Referer", "https://platform.openai.com/"}}}},
				Classify: classifyOpenAI},
			{Platform: "ChatGPT iOS", Hosts: []string{"ios.chat.openai.com"},
				Steps: []Step{{URL: "https://ios.chat.openai.com/"}}, Classify: classifyOpenAIiOS},
		},
		Combine: "主检查（cookie_requirements）决定服务结论；iOS 检查只作参考展示，不入库",
		Basis:   "cookie_requirements 的 JSON 应答含 unsupported_country = 不支持该地区；是 JSON 且没有这个标记 = 可用（公开脚本的“无负面标记即可用”）；非 JSON / 质询 = 未知。iOS 入口页含 VPN = 该入口拒绝",
		Limits:  "“可用”只是没有公开的负面标记，不是账号或付费能力判断；不带公开脚本里的 authorization: Bearer null 头；地区不判断（AI 服务不分目录地区）",
		Sources: []Source{srcLMC("WebTest_OpenAI")},
	},
	{
		Service: "auto-anthropic", Name: "Claude / Anthropic", Capability: CapVerdict, Returns: verdictReturns,
		Platforms: []Platform{{Name: "Claude", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Claude", Primary: true, Hosts: []string{"claude.ai", "www.claude.ai"},
			Steps: []Step{{URL: "https://claude.ai/"}}, Classify: classifyAnthropic}},
		Basis:   "跳到 app-unavailable-in-region = 不支持该地区；在 claude.ai 上以 2xx 结束 = 可用（公开脚本：最终 URL 停在 claude.ai）；质询页 / 其他 = 未知",
		Limits:  "Cloudflare 质询常见，质询一律为未知；“可用”不是账号判断",
		Sources: []Source{srcLMC("WebTest_Claude")},
	},
	{
		Service: "auto-gemini", Name: "Gemini", Capability: CapVerdict, Returns: verdictReturns,
		Platforms: []Platform{{Name: "Gemini", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Gemini", Primary: true, Hosts: []string{"gemini.google.com"},
			Steps: []Step{{URL: "https://gemini.google.com/"}}, Classify: classifyGemini}},
		Basis:   "页面数据含 45631641,null,true = 可用（地区取 ,2,1,200,\"XXX\" 三字母码，只作展示）；非质询的 403 = 拒绝；跳到 consent.google.com 或没有标记 = 未知",
		Limits:  "标记是页面里的不透明数据，随时可能改变；公开脚本把“没有标记”算作不可用，本项目算未知；欧盟等地区会先出同意页（公开 Go 实现用写死的 Cookie 绕过，本项目不带 Cookie）",
		Sources: []Source{srcLMC("WebTest_Gemini"), srcGO("Gemini.go（403 = Banned）")},
	},
	{
		Service: "auto-copilot", Name: "Microsoft Copilot", Capability: CapVerdict, Returns: verdictReturns,
		Platforms: []Platform{{Name: "Copilot", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Copilot", Primary: true, Hosts: []string{"copilot.microsoft.com"},
			Steps: []Step{{URL: "https://copilot.microsoft.com/c/api/user?api-version=2", NoRedirect: true}}, Classify: classifyCopilot}},
		Basis:   "c/api/user（不跟随跳转）：302 到 / 或非质询 403 = 拒绝；200 且 JSON 有 regionCode = 可用（地区只作展示）；其他 = 未知",
		Limits:  "只有一个公开实现（Go），接口未公开文档化；未登录时的应答形状可能变化",
		Sources: []Source{srcGO("Copilot.go")},
	},
	{
		Service: "auto-perplexity", Name: "Perplexity", Capability: CapReachability, Returns: reachReturns,
		Platforms: []Platform{{Name: "Perplexity", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Perplexity", Primary: true, Hosts: []string{"www.perplexity.ai", "perplexity.ai"},
			Steps: []Step{{URL: "https://www.perplexity.ai/"}}, Classify: classifyReach}},
		Basis:   "只做到达性：非质询、非 5xx 的任何应答 = 可达；不是解锁判断",
		Limits:  "公开方法（Go 实现）只是 cdn-cgi/trace 的 loc 对照写死的受限国家表，没有平台本身的信号，所以不给平台结论；质询页为未知",
		Sources: []Source{srcGO("Perplexity.go（仅作为“没有平台信号”的依据）")},
	},
	{
		Service: "auto-grok", Name: "Grok", Capability: CapReachability, Returns: reachReturns,
		Platforms: []Platform{{Name: "Grok", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Grok", Primary: true, Hosts: []string{"grok.x.ai", "grok.com"},
			Steps: []Step{{URL: "https://grok.x.ai/"}}, Classify: classifyReach}},
		Basis:   "只做到达性：非质询、非 5xx 的任何应答 = 可达；不是解锁判断",
		Limits:  "公开方法（Go 实现）只是 cdn-cgi/trace 的 loc 对照写死的受限国家表加 403，没有平台本身的信号；允许从 grok.x.ai 跳到 grok.com",
		Sources: []Source{srcGO("Grok.go（仅作为“没有平台信号”的依据）")},
	},
	{
		Service: "auto-bahamut", Name: "巴哈姆特動畫瘋", Capability: CapRegionVerdict, Returns: verdictReturns, IPv4Only: true,
		Platforms: []Platform{{Name: "動畫瘋", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "動畫瘋", Primary: true, Hosts: []string{"ani.gamer.com.tw"},
			Steps: []Step{
				{URL: "https://ani.gamer.com.tw/ajax/getdeviceid.php", Extract: extractBahamutDevice},
				{URL: "https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=38832&device=" + ValuePlaceholder},
				{URL: "https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783&device=" + ValuePlaceholder},
			}, Classify: classifyBahamut}},
		Basis:   "先取 deviceid，再取两部作品的 token：两个应答都含 animeSn = 台湾区（TW）；只有 sn=37783 含 animeSn = 港澳区（HK/MO）；都没有 = 未知",
		Limits:  "公开脚本用 Cookie 罐保存 getdeviceid 的会话 Cookie，本项目不收发任何 Cookie，所以“两个都没有”可能只是缺会话，不判为不可用；Cloudflare 质询为未知；公开脚本不支持 IPv6，本项目只发 IPv4",
		Sources: []Source{src1S("MediaUnlockTest_BahamutAnime"), srcLMC("MediaUnlockTest_BahamutAnime"), srcGO("BahamutAnime.go")},
	},
	{
		Service: "auto-kktv", Name: "KKTV", Capability: CapRegionVerdict, Returns: verdictReturns, IPv4Only: true,
		Platforms: []Platform{{Name: "KKTV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "KKTV", Primary: true, Hosts: []string{"api.kktv.me"},
			Steps: []Step{{URL: "https://api.kktv.me/v3/ipcheck"}}, Classify: classifyKKTV}},
		Basis:   "ipcheck JSON：data.country = TW 且 data.is_allowed = true → 可用（TW）；有 country 但不是 TW 或 is_allowed = false → 不可用；没有这两个字段 = 未知",
		Limits:  "API 主机与站点主机不同（api.kktv.me 是公开脚本使用的检测接口）；公开脚本不支持 IPv6",
		Sources: []Source{srcGO("KKTV.go"), srcLMC("MediaUnlockTest_KKTV")},
	},
	{
		Service: "auto-linetv", Name: "LINE TV", Capability: CapVerdict, Returns: verdictReturns, IPv4Only: true,
		Platforms: []Platform{{Name: "LINE TV", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "LINE TV", Primary: true, Hosts: []string{"www.linetv.tw"},
			Steps: []Step{{URL: "https://www.linetv.tw/drama/11829/eps/1"}}, Classify: classifyLineTV}},
		Basis:   "剧集页的服务端数据：有 window.__INITIAL_STATE__ 且同时有 \"eps_info\": [ 与 \"durationInMs\": 数字 → 可用；有 __INITIAL_STATE__ 但没有剧集数据 → 不可用；没有 __INITIAL_STATE__ = 未知",
		Limits:  "依赖页面内嵌数据结构，改版会变成未知或误判为不可用；不采用另一公开脚本“从 main JS 抓 appId 再调 API”的方法，因为 JS 所在主机不是固定的；只发 IPv4",
		Sources: []Source{srcGO("LineTV.go"), srcLMC("MediaUnlockTest_LineTVTW（未采用，见限制）")},
	},
	{
		Service: "auto-hami", Name: "Hami Video", Capability: CapVerdict, Returns: verdictReturns, IPv4Only: true,
		Platforms: []Platform{{Name: "Hami Video", Checked: true, Primary: true}},
		Checks: []Check{{Platform: "Hami Video", Primary: true, Hosts: []string{"hamivideo.hinet.net"},
			Steps: []Step{{URL: "https://hamivideo.hinet.net/api/play.do?id=OTT_VOD_0000249064&freeProduct=1"}}, Classify: classifyHami}},
		Basis:   "play.do JSON 的 code：06001-107 = 地区允许（需要购买，未登录）→ 可用；06001-106 = 地区不允许 → 不可用；其他 = 未知",
		Limits:  "“可用”只表示地区检查通过，不代表能播放（需要账号与权益）；只发 IPv4",
		Sources: []Source{srcLMC("MediaUnlockTest_HamiVideo"), srcGO("HamiVideo.go")},
	},
	{
		Service: "auto-abema", Name: "Abema / Niconico / TVer", Capability: CapRegionVerdict, Returns: verdictReturns, IPv4Only: true,
		Platforms: []Platform{
			{Name: "ABEMA", Checked: true, Primary: true},
			{Name: "Niconico", Checked: true, Note: "仅参考，不入库：规则的域名只有 abema"},
			{Name: "TVer", Checked: false, Note: "不支持：公开方法要先注册平台用户令牌或使用播放器 API key，再走多跳令牌链"},
		},
		Checks: []Check{
			{Platform: "ABEMA", Primary: true, Hosts: []string{"api.abema.io"},
				Steps:    []Step{{URL: "https://api.abema.io/v1/ip/check?device=android", Headers: [][2]string{{"User-Agent", uaAndroid}}}},
				Classify: classifyAbema},
			{Platform: "Niconico", Hosts: []string{"www.nicovideo.jp"},
				Steps: []Step{{URL: "https://www.nicovideo.jp/watch/so40278367"}}, Classify: classifyNiconico},
		},
		Combine: "ABEMA 检查决定服务结论；Niconico 只作参考展示，不入库；TVer 不检查",
		Basis:   "ABEMA ip/check JSON 的 isoCountryCode：JP → 可用（JP）；其他国家码 → 不可用（Oversea Only，该地区码）；非质询 403 → 不可用；没有字段 = 未知。Niconico 视频页含「同じ地域」= 不可用，200 且没有 = 可用",
		Limits:  "公开脚本用 Android UA 调 ABEMA 的检测接口（api.abema.io 与站点 abema.tv 不同，故单列）；只发 IPv4；Niconico 只看一个视频页",
		Sources: []Source{srcLMC("MediaUnlockTest_AbemaTV"), srcGO("Abema.go"), srcGO("NicoNico.go"), srcGO("TVer.go（不采用：需要 API key / 令牌链）")},
	},
	{
		Service: "auto-mytvsuper", Name: "MyTV SUPER / Viu", Capability: CapRegionVerdict, Returns: verdictReturns, IPv4Only: true,
		Platforms: []Platform{
			{Name: "MyTV SUPER", Checked: true, Primary: true},
			{Name: "Viu.com", Checked: true, Note: "仅参考，不入库：规则的域名只有 mytvsuper.com"},
			{Name: "ViuTV", Checked: false, Note: "不支持：公开方法要 POST 一个设备标识与调用参考号"},
		},
		Checks: []Check{
			{Platform: "MyTV SUPER", Primary: true, Hosts: []string{"www.mytvsuper.com"},
				Steps: []Step{{URL: "https://www.mytvsuper.com/api/auth/getSession/self/"}}, Classify: classifyMyTVSuper},
			{Platform: "Viu.com", Hosts: []string{"www.viu.com"},
				Steps: []Step{{URL: "https://www.viu.com/", NoRedirect: true}}, Classify: classifyViu},
		},
		Combine: "MyTV SUPER 检查决定服务结论；Viu.com 只作参考展示，不入库；ViuTV 不检查",
		Basis:   "getSession/self JSON：country_code = HK 或 region = 1 → 可用（HK）；country_code 为其他值或 region 为其他数字 → 不可用；非质询 403 → 不可用；都没有 = 未知。Viu.com 首页跳转（不跟随）路径第二段是地区，no-service = 不可用",
		Limits:  "两个公开实现分别看 country_code 与 region 字段，本项目两者都认；只发 IPv4",
		Sources: []Source{srcLMC("MediaUnlockTest_MyTVSuper"), srcGO("MyTVSuper.go"), srcGO("Viu.go"), srcLMC("MediaUnlockTest_ViuCom")},
	},
}

// ---- classifiers ------------------------------------------------------------
//
// guard runs before every classifier: an anti-bot challenge, a rate limit or
// a server error is never a platform verdict.

func guard(r Response) *Verdict {
	switch {
	case looksLikeChallenge(r.Body):
		return &Verdict{Category: CatUnknown, Signal: SigChallenge, Evidence: fmt.Sprintf("HTTP %d，反爬/质询页：无法判断", r.Status)}
	case r.Status == http.StatusTooManyRequests:
		return &Verdict{Category: CatUnknown, Signal: SigRateLimited, Evidence: "HTTP 429：被限流，无法判断"}
	case r.Status >= 500:
		return &Verdict{Category: CatUnknown, Signal: SigServerError, Evidence: fmt.Sprintf("HTTP %d：服务端错误", r.Status)}
	}
	return nil
}

func guarded(f func(Response, string) Verdict) func(Response, string) Verdict {
	return func(r Response, region string) Verdict {
		if v := guard(r); v != nil {
			return *v
		}
		return f(r, region)
	}
}

func init() {
	for i := range Catalog {
		for k := range Catalog[i].Checks {
			Catalog[i].Checks[k].Classify = guarded(Catalog[i].Checks[k].Classify)
		}
	}
}

func looksLikeChallenge(body []byte) bool {
	l := strings.ToLower(string(body))
	return strings.Contains(l, "just a moment") || strings.Contains(l, "cf-chl") || strings.Contains(l, "challenge-platform") ||
		strings.Contains(l, "captcha-delivery") || strings.Contains(l, "g-recaptcha")
}

func unknown(sig, format string, a ...any) Verdict {
	return Verdict{Category: CatUnknown, Signal: sig, Evidence: fmt.Sprintf(format, a...)}
}

func unexpected(r Response, platform string) Verdict {
	if r.Status >= 300 && r.Status < 400 {
		where := ""
		if r.URL != nil {
			where = r.URL.Host + r.URL.Path
		}
		return unknown(SigRedirect, "HTTP %d 跳到 %s（不在检测方法的已知结果里）", r.Status, where)
	}
	return unknown(SigUnexpected, "HTTP %d：不是可识别的 %s 应答", r.Status, platform)
}

func pathHas(r Response, s string) bool {
	return r.URL != nil && strings.Contains(strings.ToLower(r.URL.Path), s)
}

// regionVerdict turns an explicit platform region into a verdict for an exit
// in exitRegion: a different catalog is not an unlock for this exit (same
// rule as unlock.ParseRegionCheckFor).
func regionVerdict(reported, exitRegion, evidence string) Verdict {
	reported = strings.ToLower(reported)
	if exitRegion == "" || unlock.NormRegion(reported) == unlock.NormRegion(exitRegion) {
		return Verdict{Category: CatUnlocked, Region: reported, Signal: SigRegionMatch, Evidence: evidence}
	}
	return Verdict{Category: CatNotUnlocked, Region: reported, Signal: SigRegionMismatch,
		Evidence: evidence + fmt.Sprintf("；与出口地区 %s 不一致", strings.ToUpper(exitRegion))}
}

var (
	reNetflixCountry = regexp.MustCompile(`"(?:requestCountry"\s*:\s*\{\s*"id|countryCode)"\s*:\s*"([A-Za-z]{2})"`)
	reDisneyCountry  = regexp.MustCompile(`"(?:countryCode|region)"\s*:\s*"([A-Za-z]{2})"`)
	rePathRegion     = regexp.MustCompile(`^/([a-z]{2})(?:-([a-z]{2}))?(?:/|$)`)
	reLangRegion     = regexp.MustCompile(`^/([a-z]{2})-([a-z]{2})(?:/|$)`)
	reGeminiRegion   = regexp.MustCompile(`,2,1,200,"([A-Z]{3})"`)
	reBahamutDevice  = regexp.MustCompile(`"deviceid"\s*:\s*"([^"]+)"`)
	reLineEps        = regexp.MustCompile(`"eps_info"\s*:\s*\[`)
	reLineMs         = regexp.MustCompile(`"durationInMs"\s*:\s*\d+`)
	reCC2            = regexp.MustCompile(`^[A-Za-z]{2}$`)
)

func classifyNetflix(r Response, exitRegion string) Verdict {
	switch r.Status {
	case http.StatusForbidden:
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403：Netflix 拒绝该出口地址"}
	case http.StatusNotFound:
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "HTTP 404：自制剧标题不可用（仅自制剧或未开通）"}
	case http.StatusOK:
		if m := reNetflixCountry.FindSubmatch(r.Body); m != nil {
			return regionVerdict(string(m[1]), exitRegion, "HTTP 200，页面地区标记 "+strings.ToUpper(string(m[1])))
		}
		if r.URL != nil {
			if m := rePathRegion.FindStringSubmatch(r.URL.Path); m != nil {
				return regionVerdict(m[1], exitRegion, "HTTP 200，URL 地区前缀 /"+m[1])
			}
		}
		if pathHas(r, "login") {
			return unknown(SigLoginRequired, "HTTP 200，跳到登录页")
		}
		return unknown(SigUnexpected, "HTTP 200，但页面和 URL 里都没有地区标记")
	default:
		return unexpected(r, "Netflix")
	}
}

func classifyDisney(r Response, exitRegion string) Verdict {
	if pathHas(r, "unavailable") || pathHas(r, "preview") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "跳到 " + r.URL.Path + "：Disney+ 在该地区不可用"}
	}
	switch r.Status {
	case http.StatusForbidden:
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403：Disney+ 拒绝该出口地址"}
	case http.StatusOK:
		if m := reDisneyCountry.FindSubmatch(r.Body); m != nil {
			return regionVerdict(string(m[1]), exitRegion, "HTTP 200，页面地区标记 "+strings.ToUpper(string(m[1])))
		}
		if r.URL != nil {
			if m := reLangRegion.FindStringSubmatch(r.URL.Path); m != nil {
				return regionVerdict(m[2], exitRegion, "HTTP 200，URL 语言-地区前缀 /"+m[1]+"-"+m[2])
			}
		}
		return unknown(SigUnexpected, "HTTP 200，但页面和 URL 里都没有地区标记")
	default:
		return unexpected(r, "Disney+")
	}
}

func looksJSON(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return strings.HasPrefix(t, "{") && json.Valid([]byte(t))
}

func classifyOpenAI(r Response, _ string) Verdict {
	if strings.Contains(strings.ToLower(string(r.Body)), "unsupported_country") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，应答含 unsupported_country", r.Status)}
	}
	if looksJSON(r.Body) && r.Status < 500 && (r.Status < 300 || r.Status >= 400) {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: fmt.Sprintf("HTTP %d，JSON 应答没有 unsupported_country（无负面标记即可用；不是账号判断）", r.Status)}
	}
	return unexpected(r, "OpenAI")
}

func classifyOpenAIiOS(r Response, _ string) Verdict {
	if strings.Contains(string(r.Body), "VPN") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，iOS 入口页含 VPN 拒绝提示", r.Status)}
	}
	if r.Status >= 200 && r.Status < 500 && !(r.Status >= 300 && r.Status < 400) {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: fmt.Sprintf("HTTP %d，没有 VPN 拒绝提示", r.Status)}
	}
	return unexpected(r, "ChatGPT iOS")
}

func classifyAnthropic(r Response, _ string) Verdict {
	if pathHas(r, "unavailable-in-region") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "跳到 " + r.URL.Host + r.URL.Path}
	}
	if r.URL != nil && (r.URL.Host == "claude.ai" || r.URL.Host == "www.claude.ai") && r.Status >= 200 && r.Status < 300 {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: fmt.Sprintf("HTTP %d，停在 claude.ai，没有跳到 unavailable-in-region（不是账号判断）", r.Status)}
	}
	return unexpected(r, "Claude")
}

var alpha3 = map[string]string{"USA": "us", "HKG": "hk", "TWN": "tw", "JPN": "jp", "SGP": "sg", "GBR": "gb", "DEU": "de", "FRA": "fr", "KOR": "kr", "CAN": "ca", "AUS": "au", "CHN": "cn"}

func classifyGemini(r Response, _ string) Verdict {
	if r.URL != nil && strings.HasPrefix(r.URL.Host, "consent.") {
		return unknown(SigConsent, "HTTP %d，跳到 Google 同意页（不带 Cookie 时常见）：无法判断", r.Status)
	}
	if r.Status == http.StatusOK && strings.Contains(string(r.Body), "45631641,null,true") {
		region := ""
		ev := "HTTP 200，页面含可用标记 45631641,null,true"
		if m := reGeminiRegion.FindSubmatch(r.Body); m != nil {
			region = alpha3[string(m[1])]
			if region == "" {
				region = strings.ToLower(string(m[1]))
			}
			ev += "，平台看到的国家 " + string(m[1]) + "（仅展示）"
		}
		return Verdict{Category: CatUnlocked, Region: region, Signal: SigAvailable, Evidence: ev}
	}
	if r.Status == http.StatusForbidden {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403（非质询页）：Gemini 拒绝该地区/地址"}
	}
	if r.Status == http.StatusOK {
		return unknown(SigUnexpected, "HTTP 200，但没有可用标记（页面可能改版或要求登录）")
	}
	return unexpected(r, "Gemini")
}

func classifyCopilot(r Response, _ string) Verdict {
	switch {
	case r.Status >= 300 && r.Status < 400 && r.URL != nil && r.URL.Host == "copilot.microsoft.com" && r.URL.Path == "/":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d 跳回首页 /：Copilot 拒绝该地区", r.Status)}
	case r.Status == http.StatusForbidden:
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403（非质询页）：Copilot 拒绝"}
	case r.Status == http.StatusOK:
		var v struct {
			RegionCode string `json:"regionCode"`
		}
		if json.Unmarshal(r.Body, &v) == nil && reCC2.MatchString(v.RegionCode) {
			return Verdict{Category: CatUnlocked, Region: strings.ToLower(v.RegionCode), Signal: SigAvailable,
				Evidence: "HTTP 200，JSON regionCode=" + strings.ToUpper(v.RegionCode) + "（地区仅展示）"}
		}
		return unknown(SigUnexpected, "HTTP 200，但没有 regionCode")
	}
	return unexpected(r, "Copilot")
}

func classifyReach(r Response, _ string) Verdict {
	return Verdict{Category: CatNetworkOK, Signal: SigReachable, Evidence: fmt.Sprintf("HTTP %d（只说明可达，不是解锁判断）", r.Status)}
}

func extractBahamutDevice(r Response) (string, *Verdict) {
	if v := guard(r); v != nil {
		return "", v
	}
	if m := reBahamutDevice.FindSubmatch(r.Body); m != nil {
		return string(m[1]), nil
	}
	v := unknown(SigUnexpected, "getdeviceid HTTP %d 没有 deviceid", r.Status)
	return "", &v
}

func classifyBahamut(r Response, exitRegion string) Verdict {
	if len(r.Prev) < 2 {
		return unknown(SigUnexpected, "缺少前置应答")
	}
	tw := r.Prev[1]
	if v := guard(tw); v != nil {
		return *v
	}
	hasTW := strings.Contains(string(tw.Body), "animeSn")
	hasHK := strings.Contains(string(r.Body), "animeSn")
	switch {
	case hasTW && hasHK:
		return regionVerdict("tw", exitRegion, "两部作品的 token 都含 animeSn：台湾区")
	case hasHK:
		return regionVerdict("hk", exitRegion, "只有 sn=37783 的 token 含 animeSn：港澳区")
	case hasTW:
		return unknown(SigUnexpected, "只有 sn=38832 含 animeSn，不是公开方法里的已知组合")
	}
	return unknown(SigUnexpected, "token 都没有 animeSn（不带会话 Cookie 时也可能如此，不判为不可用）")
}

func classifyKKTV(r Response, exitRegion string) Verdict {
	var v struct {
		Data struct {
			Country   *string `json:"country"`
			IsAllowed *bool   `json:"is_allowed"`
		} `json:"data"`
	}
	if r.Status != http.StatusOK || json.Unmarshal(r.Body, &v) != nil || v.Data.Country == nil || v.Data.IsAllowed == nil {
		return unexpected(r, "KKTV")
	}
	c := strings.ToLower(*v.Data.Country)
	if c == "tw" && *v.Data.IsAllowed {
		return regionVerdict("tw", exitRegion, "ipcheck：country=TW，is_allowed=true")
	}
	return Verdict{Category: CatNotUnlocked, Region: c, Signal: SigBlocked,
		Evidence: fmt.Sprintf("ipcheck：country=%s，is_allowed=%v", strings.ToUpper(c), *v.Data.IsAllowed)}
}

func classifyLineTV(r Response, _ string) Verdict {
	b := string(r.Body)
	if r.Status != http.StatusOK || !strings.Contains(b, "window.__INITIAL_STATE__") {
		if pathHas(r, "login") {
			return unknown(SigLoginRequired, "HTTP %d，跳到登录页", r.Status)
		}
		return unexpected(r, "LINE TV")
	}
	if reLineEps.MatchString(b) && reLineMs.MatchString(b) {
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "HTTP 200，页面数据含 eps_info 与 durationInMs"}
	}
	return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "HTTP 200，页面数据存在但没有剧集信息（地区不可用）"}
}

func jsonString(body []byte, field string) (string, bool) {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return "", false
	}
	s, ok := m[field].(string)
	return s, ok
}

func classifyHami(r Response, _ string) Verdict {
	code, ok := jsonString(r.Body, "code")
	switch {
	case ok && code == "06001-107":
		return Verdict{Category: CatUnlocked, Signal: SigAvailable, Evidence: "play.do code=06001-107：地区允许（播放需权益）"}
	case ok && code == "06001-106":
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "play.do code=06001-106：地区不允许"}
	case ok:
		return unknown(SigUnexpected, "play.do code=%s：不是已知结果", clip(code, 24))
	}
	return unexpected(r, "Hami Video")
}

func classifyAbema(r Response, exitRegion string) Verdict {
	if r.Status == http.StatusForbidden {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403（非质询页）：ABEMA 拒绝该地址"}
	}
	c, ok := jsonString(r.Body, "isoCountryCode")
	if r.Status != http.StatusOK || !ok || !reCC2.MatchString(c) {
		return unexpected(r, "ABEMA")
	}
	if strings.EqualFold(c, "JP") {
		return regionVerdict("jp", exitRegion, "ip/check：isoCountryCode=JP")
	}
	return Verdict{Category: CatNotUnlocked, Region: strings.ToLower(c), Signal: SigRegionMismatch,
		Evidence: "ip/check：isoCountryCode=" + strings.ToUpper(c) + "（Oversea Only，不是日本区）"}
}

func classifyNiconico(r Response, _ string) Verdict {
	if strings.Contains(string(r.Body), "同じ地域") {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("HTTP %d，页面含「同じ地域」地区限制提示", r.Status)}
	}
	if r.Status == http.StatusOK {
		return Verdict{Category: CatUnlocked, Signal: SigNoNegative, Evidence: "HTTP 200，没有地区限制提示"}
	}
	return unexpected(r, "Niconico")
}

func classifyMyTVSuper(r Response, exitRegion string) Verdict {
	if r.Status == http.StatusForbidden {
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked403, Evidence: "HTTP 403（非质询页）：MyTV SUPER 拒绝该地址"}
	}
	var m map[string]any
	if r.Status != http.StatusOK || json.Unmarshal(r.Body, &m) != nil {
		return unexpected(r, "MyTV SUPER")
	}
	if c, ok := m["country_code"].(string); ok && reCC2.MatchString(c) {
		return regionVerdict(c, exitRegion, "getSession：country_code="+strings.ToUpper(c))
	}
	if n, ok := m["region"].(float64); ok {
		if n == 1 {
			return regionVerdict("hk", exitRegion, "getSession：region=1（香港）")
		}
		return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: fmt.Sprintf("getSession：region=%v（不是 1）", n)}
	}
	return unknown(SigUnexpected, "HTTP 200，JSON 里没有 country_code / region")
}

func classifyViu(r Response, exitRegion string) Verdict {
	if r.Status >= 300 && r.Status < 400 && r.URL != nil && r.URL.Host == "www.viu.com" {
		seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(seg) >= 2 && seg[0] == "ott" {
			if strings.EqualFold(seg[1], "no-service") {
				return Verdict{Category: CatNotUnlocked, Signal: SigBlocked, Evidence: "跳到 /ott/no-service"}
			}
			if reCC2.MatchString(seg[1]) {
				return regionVerdict(seg[1], exitRegion, "跳到 /ott/"+seg[1]+"/")
			}
		}
	}
	return unexpected(r, "Viu.com")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Services returns the catalog's rule ids in catalog order.
func Services() []string {
	out := make([]string, 0, len(Catalog))
	for _, a := range Catalog {
		out = append(out, a.Service)
	}
	return out
}
