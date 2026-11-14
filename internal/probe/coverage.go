package probe

// The coverage table: the region lists of the public scripts cited in
// docs/unlock-methods.md (LMC, 1S, GO), item by item, for Hong Kong, Japan,
// Taiwan, Singapore and the United States, plus the international and AI
// items. Every item either names the catalog adapter that implements it or
// states why there is none. docs/unlock-methods.md「覆盖表」is the same table
// (a test keeps every item name in it).
//
// The item list was compiled from the scripts' region sections as known to
// this project; this pass could not re-read the cited commits (no network
// access), so the list itself is marked for re-checking against them, like
// the request details of the adapters added with it (RecheckPending).

import "github.com/radowitz/meridian/internal/unlock"

// Coverage sections.
const (
	SectionInternational = "international"
	SectionAI            = "ai"
	SectionHK            = "hk"
	SectionTW            = "tw"
	SectionJP            = "jp"
	SectionSG            = "sg"
	SectionUS            = "us"
)

// Sections in display order.
var Sections = []string{SectionInternational, SectionAI, SectionHK, SectionTW, SectionJP, SectionSG, SectionUS}

// Reasons an item has no adapter.
const (
	// NoTokens: the public method sends an account, app token, API key,
	// device identifier or session value as a request parameter.
	ReasonNeedsToken = "needs_token"
	// The public method needs page scripts run, or parameters scraped from
	// scripts on hosts that are not fixed.
	ReasonNeedsJS = "needs_js"
	// Only an unreliable basis: a location table, a bare word in the page,
	// or a region read-out without any negative marker.
	ReasonWeakSignal = "weak_signal"
	// Not a streaming or AI service (region identification, IP reputation,
	// CDN location, games): the egress check already gives the location.
	ReasonNotService = "not_service"
	// The public method uses plain HTTP or a port other than 443.
	ReasonNotHTTPS = "not_https"
	// The platform closed or merged; the method is stale.
	ReasonDiscontinued = "discontinued"
	// The public method submits a (fake) login form.
	ReasonFakeLogin = "fake_login"
	// Request details could not be re-read in this pass; not written from
	// memory alone.
	ReasonNotReviewed = "not_reviewed"
)

// ReasonText explains each reason code.
var ReasonText = map[string]string{
	ReasonNeedsToken:   "公开方法要把账号、应用令牌、API key、设备标识或会话值当作请求参数，本项目不发送任何这类数据",
	ReasonNeedsJS:      "公开方法要执行页面脚本，或从主机不固定的脚本里抓参数，放不进固定主机名单",
	ReasonWeakSignal:   "只有不可靠的判断依据（写死的地区表、页面里的单个字样、只能读出地区而没有任何不可用标记）",
	ReasonNotService:   "不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区",
	ReasonNotHTTPS:     "公开方法用明文 HTTP 或非 443 端口，探测只走 https/443",
	ReasonDiscontinued: "平台已停止或并入别的服务，公开方法已过时",
	ReasonFakeLogin:    "公开方法提交伪造的登录表单来看错误码，本项目不提交任何登录请求",
	ReasonNotReviewed:  "本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补",
}

// CoverageItem is one item of a script's region list.
type CoverageItem struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	// Scripts lists which cited scripts carry the item (LMC, 1S, GO).
	Scripts []string `json:"scripts"`
	// Adapter is the catalog adapter implementing it; Part names the
	// non-primary check inside it when the item is only a reference check.
	Adapter string `json:"adapter,omitempty"`
	Part    string `json:"part,omitempty"`
	// Reason (a Reason* code) and Note say why there is no adapter.
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note,omitempty"`
}

var (
	sLMC  = []string{"LMC"}
	sAll  = []string{"LMC", "1S", "GO"}
	sLG   = []string{"LMC", "GO"}
	sL1   = []string{"LMC", "1S"}
	sGO   = []string{"GO"}
	sLMC1 = sL1
)

// Coverage is the table.
var Coverage = []CoverageItem{
	// International (multination sections).
	{Section: SectionInternational, Name: "Netflix", Scripts: sAll, Adapter: "auto-netflix"},
	{Section: SectionInternational, Name: "Disney+", Scripts: sAll, Adapter: "auto-disney"},
	{Section: SectionInternational, Name: "YouTube Premium", Scripts: sAll, Adapter: "youtube-premium"},
	{Section: SectionInternational, Name: "Amazon Prime Video", Scripts: sAll, Adapter: "primevideo"},
	{Section: SectionInternational, Name: "DAZN", Scripts: sAll, Adapter: "dazn"},
	{Section: SectionInternational, Name: "TVBAnywhere+", Scripts: sLG, Adapter: "tvbanywhere"},
	{Section: SectionInternational, Name: "Viu.com", Scripts: sLG, Adapter: "auto-mytvsuper", Part: "Viu.com"},
	{Section: SectionInternational, Name: "iQIYI 国际版", Scripts: sLG, Reason: ReasonNeedsToken, Note: "地区只出现在 Set-Cookie 里，读它就要收 Cookie"},
	{Section: SectionInternational, Name: "Spotify 注册", Scripts: sLG, Reason: ReasonNeedsToken, Note: "注册接口的表单里带写死的应用 key"},
	{Section: SectionInternational, Name: "TikTok", Scripts: sLG, Reason: ReasonWeakSignal, Note: "只能读出页面里的 region，没有不可用标记"},
	{Section: SectionInternational, Name: "HBO Max", Scripts: sAll, Reason: ReasonNotReviewed},
	{Section: SectionInternational, Name: "Disney+ Hotstar", Scripts: sLMC1, Reason: ReasonNotReviewed},
	{Section: SectionInternational, Name: "YouTube CDN", Scripts: sLMC1, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Netflix 首选 CDN", Scripts: sLMC1, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Steam 货币区", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Bing 地区", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Wikipedia 编辑权限", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Google Play 地区", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Google 搜索免验证码", Scripts: sLMC1, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Instagram 授权音乐", Scripts: sLMC1, Reason: ReasonNeedsToken, Note: "请求带应用 ID 请求头与写死的查询文档 ID"},
	{Section: SectionInternational, Name: "Apple 地区", Scripts: sLG, Reason: ReasonNotService},

	// AI.
	{Section: SectionAI, Name: "ChatGPT / OpenAI", Scripts: sAll, Adapter: "auto-openai"},
	{Section: SectionAI, Name: "Claude", Scripts: sAll, Adapter: "auto-anthropic"},
	{Section: SectionAI, Name: "Gemini", Scripts: sAll, Adapter: "auto-gemini"},
	{Section: SectionAI, Name: "Microsoft Copilot", Scripts: sGO, Adapter: "auto-copilot"},
	{Section: SectionAI, Name: "Perplexity", Scripts: sGO, Adapter: "auto-perplexity", Note: "只做到达性：公开方法只是地区表"},
	{Section: SectionAI, Name: "Grok", Scripts: sGO, Adapter: "auto-grok", Note: "只做到达性：公开方法只是地区表加 403"},

	// Hong Kong.
	{Section: SectionHK, Name: "MyTV SUPER", Scripts: sAll, Adapter: "auto-mytvsuper"},
	{Section: SectionHK, Name: "巴哈姆特動畫瘋（港澳区）", Scripts: sAll, Adapter: "auto-bahamut"},
	{Section: SectionHK, Name: "Now E", Scripts: sLG, Reason: ReasonNeedsToken, Note: "请求体带设备标识与调用参考号"},
	{Section: SectionHK, Name: "ViuTV", Scripts: sLG, Reason: ReasonNeedsToken, Note: "请求体带设备标识与调用参考号"},
	{Section: SectionHK, Name: "HBO GO Asia（香港）", Scripts: sLG, Reason: ReasonDiscontinued},
	{Section: SectionHK, Name: "Bilibili 港澳台限定", Scripts: sAll, Reason: ReasonNotReviewed, Note: "要写死的剧集 ID 与随机会话参数"},

	// Taiwan.
	{Section: SectionTW, Name: "KKTV", Scripts: sLG, Adapter: "auto-kktv"},
	{Section: SectionTW, Name: "LINE TV", Scripts: sLG, Adapter: "auto-linetv"},
	{Section: SectionTW, Name: "Hami Video", Scripts: sLG, Adapter: "auto-hami"},
	{Section: SectionTW, Name: "巴哈姆特動畫瘋", Scripts: sAll, Adapter: "auto-bahamut"},
	{Section: SectionTW, Name: "MyVideo", Scripts: sLG, Adapter: "myvideo"},
	{Section: SectionTW, Name: "LiTV", Scripts: sLG, Reason: ReasonNeedsToken, Note: "请求体带设备标识（puid）"},
	{Section: SectionTW, Name: "4GTV", Scripts: sLG, Reason: ReasonNeedsToken, Note: "请求体是写死的编码串，内容不透明"},
	{Section: SectionTW, Name: "CatchPlay+", Scripts: sLG, Reason: ReasonNeedsToken, Note: "要 Bearer 令牌"},
	{Section: SectionTW, Name: "HBO GO Asia（台湾）", Scripts: sLG, Reason: ReasonDiscontinued},
	{Section: SectionTW, Name: "Bilibili 台湾限定", Scripts: sAll, Reason: ReasonNotReviewed, Note: "要写死的剧集 ID 与随机会话参数"},

	// Japan.
	{Section: SectionJP, Name: "ABEMA", Scripts: sAll, Adapter: "auto-abema"},
	{Section: SectionJP, Name: "Niconico", Scripts: sLG, Adapter: "auto-abema", Part: "Niconico"},
	{Section: SectionJP, Name: "TVer", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要平台用户令牌链或播放器 API key"},
	{Section: SectionJP, Name: "DMM TV", Scripts: sLG, Adapter: "dmm-tv"},
	{Section: SectionJP, Name: "Hulu Japan", Scripts: sLG, Adapter: "hulu-jp"},
	{Section: SectionJP, Name: "radiko", Scripts: sLG, Adapter: "radiko"},
	{Section: SectionJP, Name: "DMM", Scripts: sLG, Reason: ReasonWeakSignal, Note: "只看页面里的一句提示文字"},
	{Section: SectionJP, Name: "FOD（富士电视台）", Scripts: sLG, Reason: ReasonWeakSignal, Note: "只在应答里找 true / false 字样"},
	{Section: SectionJP, Name: "U-NEXT", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionJP, Name: "WOWOW", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionJP, Name: "TELASA", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionJP, Name: "music.jp", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionJP, Name: "mora", Scripts: sLMC, Reason: ReasonNotReviewed},
	{Section: SectionJP, Name: "J:COM On Demand", Scripts: sLMC, Reason: ReasonNotReviewed},
	{Section: SectionJP, Name: "VideoMarket", Scripts: sLG, Reason: ReasonNeedsToken, Note: "要先换取访问令牌"},
	{Section: SectionJP, Name: "Paravi", Scripts: sLMC, Reason: ReasonDiscontinued, Note: "已并入 U-NEXT"},
	{Section: SectionJP, Name: "GYAO!", Scripts: sLMC, Reason: ReasonDiscontinued},
	{Section: SectionJP, Name: "Karaoke@DAM", Scripts: sLG, Reason: ReasonNotHTTPS},
	{Section: SectionJP, Name: "日本区游戏（舰队 Collection、赛马娘、公主连结、世界弹射物语、Project Sekai 等）", Scripts: sLG, Reason: ReasonNotService},

	// Singapore. The international items above (Netflix, Disney+, Prime
	// Video, YouTube Premium, DAZN, TVBAnywhere+, Viu.com) are what the
	// scripts check on a Singapore exit; the regional list adds:
	{Section: SectionSG, Name: "meWATCH", Scripts: sLMC, Reason: ReasonNotReviewed},
	{Section: SectionSG, Name: "HBO GO Asia（新加坡）", Scripts: sLG, Reason: ReasonDiscontinued},

	// United States.
	{Section: SectionUS, Name: "Peacock", Scripts: sLG, Adapter: "peacock"},
	{Section: SectionUS, Name: "Pluto TV", Scripts: sLG, Adapter: "plutotv"},
	{Section: SectionUS, Name: "Hulu", Scripts: sAll, Reason: ReasonFakeLogin},
	{Section: SectionUS, Name: "Paramount+", Scripts: sLG, Reason: ReasonWeakSignal, Note: "跳到 /intl/ 只说明不是美国站，多国都有本地站"},
	{Section: SectionUS, Name: "ESPN+", Scripts: sLG, Reason: ReasonNeedsToken},
	{Section: SectionUS, Name: "Discovery+", Scripts: sLG, Reason: ReasonNeedsToken},
	{Section: SectionUS, Name: "Starz", Scripts: sLG, Reason: ReasonNeedsToken},
	{Section: SectionUS, Name: "Crunchyroll", Scripts: sLG, Reason: ReasonNeedsToken},
	{Section: SectionUS, Name: "Fox", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionUS, Name: "Philo", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionUS, Name: "fuboTV", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionUS, Name: "Sling TV", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionUS, Name: "Tubi", Scripts: sLG, Reason: ReasonNotReviewed},
	{Section: SectionUS, Name: "其他北美频道站（Shudder、BritBox、Crackle、The CW、A&E、NBA TV、NBC、FXNOW、TLC GO、Acorn TV、MGM+、encoreTVB、KOCOWA、KBS America、DirecTV Stream）", Scripts: sLMC, Reason: ReasonNotReviewed},
	{Section: SectionUS, Name: "已停止的北美服务（Funimation、Popcornflix、SHOWTIME 独立应用）", Scripts: sLMC, Reason: ReasonDiscontinued},
}

// RequestCost is how many platform requests one run of the adapter on one
// exit and family sends (every step of every check).
func (a Adapter) RequestCost() int {
	n := 0
	for _, c := range a.Checks {
		n += len(c.Steps)
	}
	return n
}

// TraceCost is the egress check requests around every exit-family run
// (one before the services, one after).
const TraceCost = 2

// CoversRegion reports whether a conclusion of the adapter can speak for
// an exit in region (any region when the adapter declares none).
func (a Adapter) CoversRegion(region string) bool {
	if len(a.Regions) == 0 {
		return true
	}
	for _, r := range a.Regions {
		if unlock.NormRegion(r) == unlock.NormRegion(region) {
			return true
		}
	}
	return false
}
