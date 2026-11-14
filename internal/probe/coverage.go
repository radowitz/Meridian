package probe

import "github.com/radowitz/meridian/internal/unlock"

// The coverage table: the region lists of the public scripts cited in
// docs/unlock-methods.md (LMC, 1S, GO), item by item, for Hong Kong, Japan,
// Taiwan, Singapore (the Singapore part of the South-East Asia lists) and
// the United States (the US part of the North America lists), plus the
// multinational and AI items. Every item either names the catalog adapter
// that implements it or states why there is none. docs/unlock-methods.md
// 「覆盖表」is the same table (a test keeps every item name in it).
//
// The lists were read on 2026-11-14 from the region functions of the two
// check.sh scripts (Global/HK/TW/JP/NA/SEA/AI_UnlockTest) and the test
// lists of pkg/providers/lists.go, at SourceCommits. Items of other
// regions (Europe, Korea, India, Oceania, Canada, South America, Africa)
// are outside this table.

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
	// The public method sends an account, app token, API key, policy key,
	// device identifier or session value as a request parameter.
	ReasonNeedsToken = "needs_token"
	// The public method needs page scripts run, or parameters scraped from
	// scripts on hosts that are not fixed.
	ReasonNeedsJS = "needs_js"
	// Only an unreliable basis: a location table, a bare HTTP status (a 403
	// is also what a WAF answers), a word in a page, a third-party geo
	// service, or a region read-out without any negative marker.
	ReasonWeakSignal = "weak_signal"
	// Not a streaming or AI service (region identification, IP reputation,
	// CDN location, games, forums): the egress check already gives the
	// location.
	ReasonNotService = "not_service"
	// The public method uses plain HTTP or a port other than 443.
	ReasonNotHTTPS = "not_https"
	// The platform closed or merged; the method is stale.
	ReasonDiscontinued = "discontinued"
	// The public method submits a (fake) login form.
	ReasonFakeLogin = "fake_login"
	// The verdict is read from response headers or Set-Cookie, which the
	// probe does not hand to classifiers (no cookies, by design).
	ReasonHeaderOnly = "header_only"
	// The public method lowers TLS requirements (legacy renegotiation) or
	// dials a hard-coded IP address with a rewritten Host header.
	ReasonTransport = "transport"
)

// ReasonText explains each reason code.
var ReasonText = map[string]string{
	ReasonNeedsToken:   "公开方法要把账号、应用令牌、API key、播放器 policy key、设备标识或会话值当作请求参数，本项目不发送任何这类数据",
	ReasonNeedsJS:      "公开方法要执行页面脚本，或从主机不固定的脚本里抓参数，放不进固定主机名单",
	ReasonWeakSignal:   "只有不可靠的判断依据（写死的地区表、只看 HTTP 状态码（403 也可能是风控）、页面里的单个字样、第三方地理服务、只能读出地区而没有任何不可用标记）",
	ReasonNotService:   "不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区",
	ReasonNotHTTPS:     "公开方法用明文 HTTP 或非 443 端口，探测只走 https/443",
	ReasonDiscontinued: "平台已停止或并入别的服务，公开方法已过时",
	ReasonFakeLogin:    "公开方法提交伪造的登录表单看错误码，本项目不提交任何登录请求",
	ReasonHeaderOnly:   "判断依据在应答头或 Set-Cookie 里，探测不把应答头和 Cookie 交给分类器",
	ReasonTransport:    "公开方法降低 TLS 要求（允许旧式重协商）或直连写死的 IP 并改写 Host 头，探测不这样做",
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
	sL   = []string{"LMC"}
	s1   = []string{"1S"}
	sG   = []string{"GO"}
	sL1  = []string{"LMC", "1S"}
	sLG  = []string{"LMC", "GO"}
	s1G  = []string{"1S", "GO"}
	sAll = []string{"LMC", "1S", "GO"}
)

// Coverage is the table.
var Coverage = []CoverageItem{
	// Multinational (LMC Global, 1S Multination, GO GlobeTests).
	{Section: SectionInternational, Name: "Netflix", Scripts: sAll, Adapter: "auto-netflix"},
	{Section: SectionInternational, Name: "Disney+", Scripts: sAll, Adapter: "auto-disney"},
	{Section: SectionInternational, Name: "YouTube Premium", Scripts: sAll, Adapter: "youtube-premium"},
	{Section: SectionInternational, Name: "Amazon Prime Video", Scripts: sAll, Adapter: "primevideo"},
	{Section: SectionInternational, Name: "DAZN", Scripts: sAll, Adapter: "dazn"},
	{Section: SectionInternational, Name: "TVBAnywhere+", Scripts: sAll, Adapter: "tvbanywhere"},
	{Section: SectionInternational, Name: "Viu.com", Scripts: sAll, Adapter: "auto-mytvsuper", Part: "Viu.com"},
	{Section: SectionInternational, Name: "NBA TV", Scripts: sAll, Adapter: "nbatv"},
	{Section: SectionInternational, Name: "iQIYI 国际版", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区来自应答 Set-Cookie 里的 mod= 值"},
	{Section: SectionInternational, Name: "Spotify 注册", Scripts: sAll, Reason: ReasonNeedsToken, Note: "注册接口的表单里带写死的应用 key"},
	{Section: SectionInternational, Name: "HotStar", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区来自跳转与 Cookie 里的 geo= 值"},
	{Section: SectionInternational, Name: "Bilibili Anime（港澳台）", Scripts: s1G, Reason: ReasonNeedsToken, Note: "请求带每次随机生成的 session 参数"},
	{Section: SectionInternational, Name: "TikTok", Scripts: s1G, Reason: ReasonWeakSignal, Note: "只能读出平台认定的地区，没有不可用标记"},
	{Section: SectionInternational, Name: "Instagram 授权音乐", Scripts: s1, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "WeTV", Scripts: sG, Reason: ReasonWeakSignal, Note: "公开方法只读地区"},
	{Section: SectionInternational, Name: "YouTube CDN", Scripts: sAll, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "YouTube 地区", Scripts: s1, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Netflix 首选 CDN", Scripts: sAll, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Steam 货币区", Scripts: sAll, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Bing 地区", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Apple 地区", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "OneTrust 地区", Scripts: sL, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Wikipedia 编辑权限", Scripts: sAll, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Google Play 地区", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Google 搜索免验证码", Scripts: sL1, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "Reddit", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "X（Twitter）", Scripts: sG, Reason: ReasonNotService},
	{Section: SectionInternational, Name: "SD 高达 G 世纪（游戏）", Scripts: sL, Reason: ReasonNotService},

	// AI (1S AI Platform, GO AITests, LMC Global and North America).
	{Section: SectionAI, Name: "ChatGPT / OpenAI", Scripts: sAll, Adapter: "auto-openai"},
	{Section: SectionAI, Name: "Claude", Scripts: sAll, Adapter: "auto-anthropic"},
	{Section: SectionAI, Name: "Gemini", Scripts: sAll, Adapter: "auto-gemini"},
	{Section: SectionAI, Name: "Microsoft Copilot", Scripts: s1G, Adapter: "auto-copilot"},
	{Section: SectionAI, Name: "Perplexity", Scripts: sG, Adapter: "auto-perplexity", Note: "只做到达性：公开方法是地区表"},
	{Section: SectionAI, Name: "Grok", Scripts: sG, Adapter: "auto-grok", Note: "只做到达性：公开方法是地区表加 403"},
	{Section: SectionAI, Name: "Meta AI", Scripts: sL, Adapter: "metaai"},
	{Section: SectionAI, Name: "Coze", Scripts: sG, Adapter: "coze"},
	{Section: SectionAI, Name: "Sora", Scripts: s1, Reason: ReasonWeakSignal, Note: "cdn-cgi/trace 的 loc 对照写死的地区表"},
	{Section: SectionAI, Name: "Poe", Scripts: sG, Reason: ReasonWeakSignal, Note: "loc 对照写死的地区表"},
	{Section: SectionAI, Name: "Mistral", Scripts: sG, Reason: ReasonWeakSignal, Note: "loc 对照写死的地区表"},
	{Section: SectionAI, Name: "DeepSeek", Scripts: sG, Reason: ReasonTransport, Note: "直连写死的 IP 并改写 Host 头"},
	{Section: SectionAI, Name: "Kimi", Scripts: sG, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionAI, Name: "Dola", Scripts: sG, Reason: ReasonWeakSignal, Note: "只能读出地区，没有不可用标记"},

	// Hong Kong.
	{Section: SectionHK, Name: "MyTV SUPER", Scripts: sAll, Adapter: "auto-mytvsuper"},
	{Section: SectionHK, Name: "巴哈姆特動畫瘋（港澳区）", Scripts: sAll, Adapter: "auto-bahamut"},
	{Section: SectionHK, Name: "NBA TV（香港）", Scripts: s1G, Adapter: "nbatv"},
	{Section: SectionHK, Name: "Now E", Scripts: sL, Reason: ReasonNeedsToken, Note: "请求体带设备标识与调用参考号"},
	{Section: SectionHK, Name: "ViuTV", Scripts: sAll, Reason: ReasonNeedsToken, Note: "请求体带设备标识与调用参考号"},
	{Section: SectionHK, Name: "HBO Max（香港）", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区码 countryCode= 在应答头里"},
	{Section: SectionHK, Name: "SonyLiv（香港）", Scripts: sLG, Reason: ReasonNeedsToken, Note: "先从页面取 securityToken 再调接口"},
	{Section: SectionHK, Name: "Bilibili 港澳台限定", Scripts: sL1, Reason: ReasonNeedsToken, Note: "请求带每次随机生成的 session 参数"},
	{Section: SectionHK, Name: "HOY TV", Scripts: s1G, Reason: ReasonWeakSignal, Note: "只看直播流地址的 HTTP 状态码"},

	// Taiwan.
	{Section: SectionTW, Name: "KKTV", Scripts: sAll, Adapter: "auto-kktv"},
	{Section: SectionTW, Name: "LINE TV", Scripts: sAll, Adapter: "auto-linetv"},
	{Section: SectionTW, Name: "Hami Video", Scripts: sAll, Adapter: "auto-hami"},
	{Section: SectionTW, Name: "巴哈姆特動畫瘋", Scripts: sAll, Adapter: "auto-bahamut"},
	{Section: SectionTW, Name: "MyVideo", Scripts: sAll, Adapter: "myvideo"},
	{Section: SectionTW, Name: "4GTV", Scripts: sAll, Adapter: "4gtv"},
	{Section: SectionTW, Name: "friDay 影音", Scripts: s1G, Adapter: "friday-video"},
	{Section: SectionTW, Name: "LiTV", Scripts: sAll, Reason: ReasonNeedsToken, Note: "请求带设备标识（puid）"},
	{Section: SectionTW, Name: "Ofiii", Scripts: s1G, Reason: ReasonNeedsToken, Note: "查询串带写死的设备 ID"},
	{Section: SectionTW, Name: "CatchPlay+", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要 Bearer 令牌"},
	{Section: SectionTW, Name: "HBO Max（台湾）", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区码 countryCode= 在应答头里"},
	{Section: SectionTW, Name: "SonyLiv（台湾）", Scripts: sL, Reason: ReasonNeedsToken, Note: "先从页面取 securityToken 再调接口"},
	{Section: SectionTW, Name: "Bilibili 台湾限定", Scripts: sL1, Reason: ReasonNeedsToken, Note: "请求带每次随机生成的 session 参数"},

	// Japan.
	{Section: SectionJP, Name: "ABEMA", Scripts: sAll, Adapter: "auto-abema"},
	{Section: SectionJP, Name: "Niconico", Scripts: sAll, Adapter: "auto-abema", Part: "Niconico"},
	{Section: SectionJP, Name: "DMM TV", Scripts: sL1, Adapter: "dmm-tv"},
	{Section: SectionJP, Name: "DMM", Scripts: sLG, Adapter: "dmm"},
	{Section: SectionJP, Name: "Hulu Japan", Scripts: sAll, Adapter: "hulu-jp"},
	{Section: SectionJP, Name: "radiko", Scripts: sAll, Adapter: "radiko"},
	{Section: SectionJP, Name: "FOD（富士电视台）", Scripts: sAll, Adapter: "fod"},
	{Section: SectionJP, Name: "U-NEXT", Scripts: sAll, Adapter: "unext"},
	{Section: SectionJP, Name: "NHK+", Scripts: s1G, Adapter: "nhk-plus"},
	{Section: SectionJP, Name: "TVer", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要平台用户令牌链或播放器 API key"},
	{Section: SectionJP, Name: "TELASA", Scripts: sAll, Reason: ReasonNeedsToken, Note: "请求头带写死的设备 ID（X-Device-ID）"},
	{Section: SectionJP, Name: "WOWOW", Scripts: sAll, Reason: ReasonNeedsJS, Note: "四步链，从前一步的页面里取多个地址与作品号"},
	{Section: SectionJP, Name: "VideoMarket", Scripts: sAll, Reason: ReasonNeedsToken, Note: "请求带写死的 Bearer 令牌"},
	{Section: SectionJP, Name: "AnimeFesta", Scripts: sAll, Reason: ReasonNeedsToken, Note: "请求头带用户追踪 ID"},
	{Section: SectionJP, Name: "Lemino", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionJP, Name: "d アニメストア", Scripts: sAll, Reason: ReasonTransport, Note: "要允许旧式 TLS 重协商；判断依据也只是页面里的「海外」字样"},
	{Section: SectionJP, Name: "J:COM On Demand", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionJP, Name: "WATCHA", Scripts: sLG, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionJP, Name: "Rakuten TV JP", Scripts: sAll, Reason: ReasonWeakSignal, Note: "公开方法把 Rakuten TV 的播放信息和另一个服务（Rakuten NBA）的地理过滤拼成一个结论"},
	{Section: SectionJP, Name: "Rakuten Magazine", Scripts: s1G, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionJP, Name: "MGStage", Scripts: s1G, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionJP, Name: "Karaoke@DAM", Scripts: sAll, Reason: ReasonNotHTTPS},
	{Section: SectionJP, Name: "mora", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionJP, Name: "music.jp", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看脚本文件里有没有 checkIp 字样"},
	{Section: SectionJP, Name: "Paravi", Scripts: s1, Reason: ReasonDiscontinued, Note: "已并入 U-NEXT"},
	{Section: SectionJP, Name: "ErogameScape（论坛）", Scripts: sLG, Reason: ReasonNotService},
	{Section: SectionJP, Name: "日本区游戏（舰队 Collection、赛马娘、为美好的世界献上祝福 Fantastic Days、公主连结、Project Sekai、World Flipper）", Scripts: sAll, Reason: ReasonNotService},

	// Singapore (the SG part of the South-East Asia lists, plus the
	// South-East-Asia-wide items).
	{Section: SectionSG, Name: "B-Global 东南亚", Scripts: sL1, Adapter: "bglobal-sea"},
	{Section: SectionSG, Name: "meWATCH", Scripts: sAll, Reason: ReasonWeakSignal, Note: "应答里出现任何数字 code 都算不可用（错误和限流也会这样）"},
	{Section: SectionSG, Name: "StarHub TV+", Scripts: s1, Reason: ReasonWeakSignal, Note: "只看直播清单地址的 HTTP 状态码"},
	{Section: SectionSG, Name: "CatchPlay+（新加坡）", Scripts: s1G, Reason: ReasonNeedsToken, Note: "要 Bearer 令牌"},
	{Section: SectionSG, Name: "HBO Max（东南亚）", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区码 countryCode= 在应答头里"},
	{Section: SectionSG, Name: "SonyLiv（东南亚）", Scripts: sL, Reason: ReasonNeedsToken, Note: "先从页面取 securityToken 再调接口"},

	// United States (the US part of the North America lists).
	{Section: SectionUS, Name: "Peacock", Scripts: sAll, Adapter: "peacock"},
	{Section: SectionUS, Name: "Pluto TV", Scripts: sAll, Adapter: "plutotv"},
	{Section: SectionUS, Name: "fuboTV", Scripts: sLG, Adapter: "fubotv"},
	{Section: SectionUS, Name: "Philo", Scripts: sAll, Adapter: "philo"},
	{Section: SectionUS, Name: "Sling TV", Scripts: sAll, Adapter: "sling"},
	{Section: SectionUS, Name: "Tubi", Scripts: sLG, Adapter: "tubi"},
	{Section: SectionUS, Name: "Acorn TV", Scripts: sAll, Adapter: "acorntv"},
	{Section: SectionUS, Name: "BritBox", Scripts: sAll, Adapter: "britbox"},
	{Section: SectionUS, Name: "AMC+", Scripts: sLG, Adapter: "amcplus"},
	{Section: SectionUS, Name: "Hulu", Scripts: sAll, Reason: ReasonFakeLogin},
	{Section: SectionUS, Name: "HBO Max（美国）", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区码 countryCode= 在应答头里"},
	{Section: SectionUS, Name: "Paramount+", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看是否跳到 /intl/（只说明不是美国站）与状态码"},
	{Section: SectionUS, Name: "ESPN+", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要先换取设备令牌"},
	{Section: SectionUS, Name: "Discovery+", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要设备 ID 与令牌"},
	{Section: SectionUS, Name: "Starz", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要授权头"},
	{Section: SectionUS, Name: "MGM+", Scripts: sAll, Reason: ReasonNeedsToken, Note: "先建会话再带会话令牌"},
	{Section: SectionUS, Name: "NBC TV", Scripts: sAll, Reason: ReasonNeedsToken, Note: "要授权头"},
	{Section: SectionUS, Name: "TLC GO", Scripts: sLG, Reason: ReasonNeedsToken, Note: "要设备 ID 换取令牌"},
	{Section: SectionUS, Name: "encoreTVB", Scripts: sAll, Reason: ReasonNeedsToken, Note: "请求头带播放器 policy key"},
	{Section: SectionUS, Name: "A&E TV", Scripts: sAll, Reason: ReasonHeaderOnly, Note: "地区来自应答 Cookie AETN-Country-Code"},
	{Section: SectionUS, Name: "Crackle", Scripts: sL1, Reason: ReasonHeaderOnly, Note: "地区来自应答头 x-crackle-region"},
	{Section: SectionUS, Name: "FOX", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看一个视频分片地址的 HTTP 状态码"},
	{Section: SectionUS, Name: "NFL+", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看是否跳到另一个产品站点"},
	{Section: SectionUS, Name: "FXNOW", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只有不可用字样，没有可用标记"},
	{Section: SectionUS, Name: "Shudder", Scripts: sAll, Reason: ReasonWeakSignal, Note: "可用标记是页面里的 movies 字样，不可用标记包含泛泛的 not available"},
	{Section: SectionUS, Name: "The CW", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionUS, Name: "KOCOWA", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionUS, Name: "DirecTV Stream", Scripts: sAll, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionUS, Name: "Crunchyroll", Scripts: sAll, Reason: ReasonWeakSignal, Note: "用第三方地理服务判断，不是平台信号"},
	{Section: SectionUS, Name: "SonyLiv（美国）", Scripts: sLG, Reason: ReasonNeedsToken, Note: "先从页面取 securityToken 再调接口"},
	{Section: SectionUS, Name: "Popcornflix", Scripts: sL1, Reason: ReasonWeakSignal, Note: "只看 HTTP 状态码"},
	{Section: SectionUS, Name: "SHOWTIME", Scripts: s1, Reason: ReasonDiscontinued, Note: "已并入 Paramount+"},
	{Section: SectionUS, Name: "KBS America", Scripts: s1, Reason: ReasonWeakSignal, Note: "LMC 里已注释停用；1S 的方法只看状态"},
	{Section: SectionUS, Name: "MathsSpot（Roblox）", Scripts: sL1, Reason: ReasonNotService},
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
