# 解锁探测方法与证据分级

本文是 `internal/probe/adapters.go`、`adapters_more.go` 里检测目录和 `coverage.go` 覆盖表的说明。两边必须一致：改适配器就要改这里（`TestCoverageTable` 检查覆盖表的每一项和每个适配器都出现在本文）。

## 验证状态（所有适配器都一样）

**每个适配器都是依据公开检测方法写成的，只用合成样本测试过。本项目没有拿任何一个去请求真实平台，真实平台上的表现要等人工核对。**

API 里对应 `validation: "synthetic_only"` 和 `validation_text`，出现在目录的每一项、每个探测项和结果矩阵的每一行。下文各节的“查阅日期”是读公开源码的日期，不代表那天验证过平台。

## 探测路径（没有变化）

- 探测在网关的 `meridian-host` 里执行。发出的每个连接都带所选出口的 fwmark，绑定该出口的中转地址，只用 `tcp4`/`tcp6` 中的一种，域名只经该出口的隧道解析器解析。每次连接前都检查内核路由，必须从 Meridian 隧道出去。
- 碰平台之前、跑完全部服务之后，都会用固定的 `https://www.cloudflare.com/cdn-cgi/trace` 确认出口：地址族、`loc=` 与出口地区、已知端点地址。出口没确认，就不给任何平台结论。
- 调用方只能从目录里选服务 id、选受管出口、选地址族，不能给 URL、主机、请求头、命令或路径。
- 每个检查都有固定的主机名单，只走 https/443。跳转只跟到名单内的主机，最多 4 跳；带 `NoRedirect` 的步骤直接拿跳转本身来判断。正文最多读 256 KiB。不用 Cookie 罐，也不带任何账号、令牌或 Cookie。额外请求头只能是 `User-Agent`、`Referer`、`Origin`、`Accept`、`Content-Type`，而且都是目录里写死的常量。
- 多步检查（目前只有巴哈姆特）只把前一步应答里的一个值带进下一步 URL 的查询串，这个值必须匹配 `^[A-Za-z0-9_-]{1,128}$`，不合格就停下，判为未知。
- 每个服务的所有步骤共用 20 秒预算。每个出口加地址族的探测里，同时最多跑 4 个服务。host agent 单次探测上限 3 分钟，面板单次调用上限 200 秒。

## 结果模型与证据分级

| category | grade | 含义 | 入库 |
|---|---|---|---|
| `unlocked` | `platform_signal` | 找到有文档依据的正面标记；带地区的适配器还要求地区与出口一致 | 成功 |
| `not_unlocked` | `platform_signal` | 找到有文档依据的负面标记，或平台报的目录地区与出口不一致 | 失败 |
| `network_ok` | `reachability_only` | 平台有应答，但这不是解锁判断 | 不是结论 → inconclusive |
| `unknown` | `unknown_response` | 有应答但不是已知标记：质询页、登录墙、同意页、限流、5xx、改版、未跟随的站外跳转 | 不是结论 → inconclusive |
| `failed` | `error` | 没有可判断的应答：超时、DNS 或传输错误、出口未确认或变化、agent 报告的出口不对 | 不是结论 → inconclusive |
| `not_applicable` | `not_applicable` | 没有探测：这个服务的公开检测方法只支持 IPv4，没有发出 IPv6 请求（`signal: family_not_supported`）。不是应答，面板显示「不适用 · 仅 IPv4」，不计入「未知」 | 不入库（`ingest: not_ingested:family_not_supported`） |

- `signal` 是判断所依据的标记代码，例如 `region_match`、`region_mismatch`、`available_marker`、`no_negative_marker`、`blocked_marker`、`blocked_403`、`anti_bot_challenge`、`login_required`、`consent_page`、`rate_limited`、`server_error`、`redirect_unlisted`、`unexpected_response`、`egress_changed`、`family_not_supported`。
- `grade` 由面板按 `probe.GradeOf(category)` 重新计算，不采信 agent 自己报的值。
- 适配器里声明了 `returns`，即它允许给出的结论。超出声明的结论都会降为 `unknown`，在 agent 内部降一次，面板 `sanitizeReport` 里再降一次。所以只做到达性的适配器永远给不出 `unlocked` 或 `not_unlocked`。`not_applicable` 只在服务确实不支持该地址族时保留，否则同样降为 `unknown`。
- 有多个平台检查的服务，只由 `primary` 那一项决定服务结论；其余检查放在 `parts` 里展示，不入库。
- 入库规则（`probe.IngestVerdict`，全项目只有这一处）：`unlocked` 算成功，`not_unlocked` 算失败，其他都不算结论。一个服务在一次探测里所有地址族都没有结论时，按 `unlock.KindInconclusive` 交给 `unlock.Ingest`。这种结果不计入两次失败降级，不会开始恢复计时，也不会让出口变成已知可用的备选；它只会终止首选成员正在进行的恢复计时。这一点有回归测试覆盖。
- 出口上报的 `ai` 字段（curl 的 HTTP 状态码）同样只算到达性：照常记入历史并带说明，但不推动状态机。

## 能力声明一览

| 服务 id | 名称 | 能力 | 只发 IPv4 | 检查的平台（主 / 参考） |
|---|---|---|---|---|
| auto-netflix | Netflix | region_verdict | 否 | Netflix |
| auto-disney | Disney+ | region_verdict | 否 | Disney+ |
| auto-openai | OpenAI / ChatGPT | verdict | 否 | OpenAI API/Web；参考：ChatGPT iOS |
| auto-anthropic | Claude | verdict | 否 | Claude |
| auto-gemini | Gemini | verdict（地区仅展示） | 否 | Gemini |
| auto-copilot | Microsoft Copilot | verdict（地区仅展示） | 否 | Copilot |
| auto-perplexity | Perplexity | reachability | 否 | Perplexity |
| auto-grok | Grok | reachability | 否 | Grok |
| auto-bahamut | 巴哈姆特動畫瘋 | region_verdict | 是 | 動畫瘋 |
| auto-kktv | KKTV | region_verdict | 是 | KKTV |
| auto-linetv | LINE TV | verdict | 是 | LINE TV |
| auto-hami | Hami Video | verdict | 是 | Hami Video |
| auto-abema | Abema / Niconico / TVer | region_verdict | 是 | ABEMA；参考：Niconico；不支持：TVer |
| auto-mytvsuper | MyTV SUPER / Viu | region_verdict | 是 | MyTV SUPER；参考：Viu.com；不支持：ViuTV |
| youtube-premium | YouTube Premium | verdict（地区仅展示） | 否 | YouTube Premium |
| primevideo | Amazon Prime Video | region_verdict | 否 | Prime Video |
| dazn | DAZN | region_verdict | 否 | DAZN |
| tvbanywhere | TVBAnywhere+ | verdict（地区仅展示） | 否 | TVBAnywhere+ |
| dmm-tv | DMM TV | region_verdict（仅 jp） | 是 | DMM TV |
| hulu-jp | Hulu Japan | region_verdict（仅 jp） | 是 | Hulu Japan |
| radiko | radiko | region_verdict（仅 jp） | 是 | radiko |
| myvideo | MyVideo | verdict（仅 tw） | 是 | MyVideo |
| peacock | Peacock | verdict（仅 us） | 否 | Peacock |
| plutotv | Pluto TV | verdict | 否 | Pluto TV |

「仅 jp」等是适配器声明的 `regions`：它的结论只能说明出口在不在这个地区可用；放到别的地区的出口上只会得到「地区不符 / 不可用」。没有声明的适配器对任何地区都给出结论（带地区的适配器仍要求平台报的地区与出口一致）。

**下面 10 个适配器（覆盖表新增）比上面 14 个多一层未验证**：它们的请求地址、请求体和标记是按引用脚本的已知行为写的，这一轮没有网络、没能对照引用的提交重读源码，来源一栏标「待对照源码复核」（API 的 `sources[].checked`）。它们和其余适配器一样只在合成样本上测过。另外它们不绑定任何内置规则：只有运营者把它们挂到某个服务组上，结果才会参与选择。

AI 类服务没有“目录地区”的概念，所以 Gemini、Copilot 报的地区只作展示，不拿来和出口地区比较。流媒体的地区不一致按 `not_unlocked` 处理（`region_mismatch`）。

## 各服务

各节引用的公开来源（查阅日期 2026-11-13，只读源码）：

- **LMC**：lmc999/RegionRestrictionCheck `check.sh`，main @ b6d4a6f（2025-12-08）。<https://github.com/lmc999/RegionRestrictionCheck>
- **1S**：1-stream/RegionRestrictionCheck `check.sh`，main @ ef841d0（2026-10-06）。<https://github.com/1-stream/RegionRestrictionCheck>
- **GO**：HsukqiLee/MediaUnlockTest `pkg/providers/*.go`，main @ dc6c6e6（2026-10-14），是 nkeonkeo/MediaUnlockTest 仍在维护的分支。<https://github.com/HsukqiLee/MediaUnlockTest>

### Netflix（auto-netflix）

- 请求：`GET https://www.netflix.com/title/81280792`。主机：`www.netflix.com`、`netflix.com`。
- 不可用：403（拒绝该 IP）；404（只开放自制剧，或该地区没上线）。
- 可用：200，并且页面里 `requestCountry.id`/`countryCode`，或 URL 的 `/xx(-yy)/` 前缀给出的地区与出口一致。地区不一致算不可用。
- 未知：200 但没有地区标记、登录墙、质询页、5xx。
- 来源：LMC `MediaUnlockTest_Netflix`（同一个自制剧标题），加上本项目原有的规则。
- 限制：LMC 会带浏览器 Cookie，并对比自制剧和非自制剧两个标题；本适配器两样都不做，所以分不出“仅自制剧”和“完全解锁”。页面改版会落到未知。

### Disney+（auto-disney）

- 请求：`GET https://www.disneyplus.com/`。主机：`www.disneyplus.com`、`disneyplus.com`。
- 不可用：跳到含 `unavailable` 或 `preview` 的路径；403。
- 可用：200，并且页面 `countryCode`/`region` 或 URL `/语言-地区` 给出的地区与出口一致。
- 未知：没有地区标记；跳到名单外的主机。
- 来源：LMC `MediaUnlockTest_DisneyPlus`，只用了它“最终 URL 含 preview 或 unavailable 就是 No”这一部分。
- 限制：LMC 的完整方法要拿 bamgrid 设备令牌（应用令牌）去调 GraphQL，读 `inSupportedLocation`/`countryCode`。本项目不用任何令牌，所以首页没带地区标记时只能报未知。

### OpenAI / ChatGPT（auto-openai）

- 主检查：`GET https://api.openai.com/compliance/cookie_requirements`，带固定的 `Origin`/`Referer: https://platform.openai.com`。主机：`api.openai.com`（检测接口，和网页站点 chatgpt.com 是不同的主机）。
  - 不可用：应答含 `unsupported_country`。
  - 可用：应答是 JSON（非 3xx、非 5xx），并且没有这个标记。这就是公开脚本的“没有负面标记即可用”，不代表账号能用。
  - 未知：非 JSON、质询页、5xx。
- 参考检查（不入库）：`GET https://ios.chat.openai.com/`。含 `VPN` 算 iOS 入口拒绝；否则算没有负面标记。
- 来源：LMC `WebTest_OpenAI`。
- 限制：不带 LMC 的 `authorization: Bearer null` 头；不判断地区。

### Claude（auto-anthropic）

- 请求：`GET https://claude.ai/`。主机：`claude.ai`、`www.claude.ai`。去 `www.anthropic.com` 的跳转不跟，直接拿跳转地址来判断。
- 不可用：跳到 `app-unavailable-in-region`。
- 可用：最终停在 claude.ai，状态码 2xx。
- 未知：质询页、非质询的 403、其他跳转。
- 来源：LMC `WebTest_Claude`（看最终 URL）。
- 限制：Cloudflare 质询很常见，一律算未知；不是账号判断。

### Gemini（auto-gemini）

- 请求：`GET https://gemini.google.com/`。主机：`gemini.google.com`。
- 可用：200 且页面数据含 `45631641,null,true`。如果有 `,2,1,200,"XXX"`，取三字母国家码，只作展示。
- 不可用：非质询的 403（来自 GO `Gemini.go`）。
- 未知：跳到 `consent.google.com` 同意页；200 但没有标记；其他。
- 来源：LMC `WebTest_Gemini`；GO `Gemini.go`。
- 限制：这个标记是不透明的页面数据，随时可能改。LMC 把“没有标记”算作 No，本项目算未知，避免改版造成误降级。GO 用写死的 Cookie 绕过同意页，本项目不带 Cookie，所以欧盟等地区多半是未知。

### Microsoft Copilot（auto-copilot）

- 请求：`GET https://copilot.microsoft.com/c/api/user?api-version=2`，不跟随跳转。主机：`copilot.microsoft.com`。
- 不可用：302 跳回 `/`；非质询的 403。
- 可用：200 且 JSON 有两位的 `regionCode`（地区只作展示）。
- 未知：跳到其他地方（如登录）、200 但没有 `regionCode`。
- 来源：GO `Copilot.go`（LMC 没有 Copilot；1S 用的 `turing/conversation` 接口看起来已过时，没有采用）。
- 限制：只有一个公开实现可参照，接口没有公开文档。

### Perplexity（auto-perplexity）— 只做到达性

- 请求：`GET https://www.perplexity.ai/`。主机：`www.perplexity.ai`、`perplexity.ai`。
- 结果：非质询、非 5xx 的应答都算 `network_ok`；质询、限流、5xx 算未知。
- 为什么不给平台结论：唯一的公开方法（GO `Perplexity.go`）只是拿 cdn-cgi/trace 的 `loc` 去对照一张写死的受限国家表（CN、RU、IR、KP、CU、SY）。这张表是假设，不是平台信号，本项目出口检查已经有 `loc`。

### Grok（auto-grok）— 只做到达性

- 请求：`GET https://grok.x.ai/`（允许跳到 `grok.com`）。主机：`grok.x.ai`、`grok.com`。
- 结果与理由同 Perplexity。来源：GO `Grok.go`（loc 对照受限表，加 403）。

### 巴哈姆特動畫瘋（auto-bahamut）— 只发 IPv4

- 请求（同一个检查里三步）：
  1. `GET https://ani.gamer.com.tw/ajax/getdeviceid.php`，取 `"deviceid":"…"`。值必须匹配 `^[A-Za-z0-9_-]{1,128}$`。
  2. `GET https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=38832&device=<deviceid>`
  3. `GET https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783&device=<deviceid>`
- 主机：`ani.gamer.com.tw`。
- 判断：两个 token 应答都含 `animeSn` 算台湾区（tw）；只有 sn=37783 含 `animeSn` 算港澳区（hk）。地区与出口不一致算不可用。两个都没有、或只有 sn=38832 有，算未知。
- 来源：1S `MediaUnlockTest_BahamutAnime`（两个 sn 区分 TW 和 HK/MO）；LMC 同名函数；GO `BahamutAnime.go`。
- 限制：三个公开实现都用 Cookie 罐保存 getdeviceid 设下的会话 Cookie，本项目不收发 Cookie。所以“都没有 animeSn”可能只是因为缺会话，不判为不可用。这个服务因此可能常报未知，需要人工核对。Cloudflare 质询算未知。LMC 和 GO 都不支持 IPv6。

### KKTV（auto-kktv）— 只发 IPv4

- 请求：`GET https://api.kktv.me/v3/ipcheck`。主机：`api.kktv.me`（公开脚本用的检测接口，和站点 kktv.me 是不同主机）。
- 可用：`data.country = "TW"` 且 `data.is_allowed = true`，地区记为 tw。
- 不可用：有 `country`，但不是 TW，或 `is_allowed = false`。
- 未知：没有这两个字段、非 200。
- 来源：GO `KKTV.go`；LMC `MediaUnlockTest_KKTV`（只看 country）。

### LINE TV（auto-linetv）— 只发 IPv4

- 请求：`GET https://www.linetv.tw/drama/11829/eps/1`。主机：`www.linetv.tw`。
- 可用：页面有 `window.__INITIAL_STATE__`，并且同时匹配 `"eps_info"\s*:\s*\[` 和 `"durationInMs"\s*:\s*\d+`。
- 不可用：有 `__INITIAL_STATE__` 但没有剧集数据。
- 未知：没有 `__INITIAL_STATE__`、登录页、非 200。
- 来源：GO `LineTV.go`。没有采用 LMC `MediaUnlockTest_LineTVTW` 的方法：它要先从页面里找 main JS、再从 JS 里抓 appId，而 JS 所在的主机不固定，没法放进固定主机名单。
- 限制：依赖页面内嵌的数据结构，改版后可能变成未知，或被误判为不可用。

### Hami Video（auto-hami）— 只发 IPv4

- 请求：`GET https://hamivideo.hinet.net/api/play.do?id=OTT_VOD_0000249064&freeProduct=1`。主机：`hamivideo.hinet.net`。
- 判断：`code = "06001-107"` 算可用（地区允许，播放需要权益）；`"06001-106"` 算不可用；其他 code 或非 JSON 算未知。
- 来源：LMC `MediaUnlockTest_HamiVideo`；GO `HamiVideo.go`。
- 限制：“可用”只说明地区检查通过，不说明能播放。

### Abema / Niconico / TVer（auto-abema）— 只发 IPv4

- 组合规则：ABEMA 检查决定服务结论。Niconico 只作参考，不入库，因为这条规则的域名只有 abema。TVer 不检查。
- ABEMA：`GET https://api.abema.io/v1/ip/check?device=android`，带固定的 Android `User-Agent`。主机：`api.abema.io`（检测接口，和站点 abema.tv 是不同主机）。
  - `isoCountryCode = "JP"` 算可用（jp）。
  - 其他国家码算不可用（“Oversea Only”，地区记为该国家码）。
  - 非质询的 403 算不可用。
  - 没有这个字段算未知。
  - 来源：LMC `MediaUnlockTest_AbemaTV`；GO `Abema.go`。
- Niconico（参考）：`GET https://www.nicovideo.jp/watch/so40278367`。主机：`www.nicovideo.jp`。页面含「同じ地域」算不可用；200 且没有这句算可用。来源：GO `NicoNico.go`。
- TVer：不支持。公开方法要么注册平台用户再走五跳令牌链（LMC 的 Brightcove 方法），要么带播放器的 API key 请求头（1S 和 GO 的 streaks 方法）。这两种都要把令牌或 key 当作请求参数，本项目不这样做。

### MyTV SUPER / Viu（auto-mytvsuper）— 只发 IPv4

- 组合规则：MyTV SUPER 检查决定服务结论。Viu.com 只作参考，不入库，因为这条规则的域名只有 mytvsuper.com。ViuTV 不检查。
- MyTV SUPER：`GET https://www.mytvsuper.com/api/auth/getSession/self/`。主机：`www.mytvsuper.com`。
  - `country_code = "HK"` 算可用（hk）；其他 `country_code` 算不可用（地区不一致）。
  - 没有 `country_code` 时看 `region`：等于 1 算可用（hk），其他数字算不可用。
  - 非质询的 403 算不可用。
  - 两个字段都没有算未知。
  - 来源：LMC `MediaUnlockTest_MyTVSuper`（看 country_code）；GO `MyTVSuper.go` 和 1S（看 region == 1）。
- Viu.com（参考）：`GET https://www.viu.com/`，不跟随跳转。主机：`www.viu.com`。跳转路径 `/ott/<地区>/…` 的地区与出口比较；`/ott/no-service` 算不可用；不跳转算未知。来源：GO `Viu.go`；LMC `MediaUnlockTest_ViuCom`。
- ViuTV：不支持。公开方法要 POST 一段写死的设备标识（`deviceId`）和调用参考号，本项目不发送任何设备标识。

## 覆盖表新增的适配器

以下各节的来源一律是「LMC / GO 同名函数，待对照源码复核」（见上文说明），只在合成样本上测过。

### YouTube Premium（youtube-premium）

- 请求：`GET https://www.youtube.com/premium`。主机：`www.youtube.com`、`youtube.com`。
- 不可用：页面含 `Premium is not available in your country`，或引到 `www.google.cn`（地区记为 cn）。
- 可用：200 且页面含 `ad-free`；`INNERTUBE_CONTEXT_GL` / `countryCode` 给出的地区只作展示。
- 未知：200 但两种标记都没有（改版）、质询、限流、5xx。
- 限制：未登录的介绍页，不是账号判断。

### Amazon Prime Video（primevideo）

- 请求：`GET https://www.primevideo.com/`。主机：`www.primevideo.com`、`primevideo.com`。
- 不可用：页面数据 `"isServiceRestricted":true`；`currentTerritory` 与出口地区不一致（`region_mismatch`）。
- 可用：`currentTerritory` 与出口地区一致。
- 未知：两个标记都没有、非 200。

### DAZN（dazn）

- 请求：`POST https://startup.core.indazn.com/misl/v5/Startup`，固定的匿名 JSON 请求体（`LandingPageKey`、`languages`、`Platform`、`Version` 等常量，不含账号、设备或会话标识），`Content-Type: application/json`。主机：`startup.core.indazn.com`。
- 不可用：`Region.isAllowed = false`；`isAllowed = true` 但 `GeolocatedCountry` 与出口地区不一致。
- 可用：`isAllowed = true` 且地区一致。
- 未知：没有 `Region.isAllowed`。

### TVBAnywhere+（tvbanywhere）

- 请求：`GET https://uapisfm.tvbanywhere.com.sg/geoip/check/platform/android`。主机：`uapisfm.tvbanywhere.com.sg`。
- `allow_in_this_country = true` 可用（`country` 只作展示），`false` 不可用，没有字段为未知。
- 限制：这是 TVB 面向香港以外的服务，香港出口上「不可用」是正常结果。

### DMM TV（dmm-tv）— 只发 IPv4，只判断 jp

- 请求：`POST https://api.beacon.dmm.com/v1/streaming/start`，固定的匿名 JSON 请求体（播放器名、固定作品 ID）。主机：`api.beacon.dmm.com`。
- 应答含 `FOREIGN` 不可用；含 `UNAUTHORIZED`（通过地区检查、只差登录）可用（jp）。其他为未知。
- 限制：作品下架后会变成未知。

### Hulu Japan（hulu-jp）— 只发 IPv4，只判断 jp

- 请求：`GET https://id.hulu.jp/`（允许跳到 `www.hulu.jp`）。主机：`id.hulu.jp`、`www.hulu.jp`。
- 最终路径含 `restrict` 不可用；停在 `login` 路径可用（jp）；其他为未知。

### radiko（radiko）— 只发 IPv4，只判断 jp

- 请求：`GET https://radiko.jp/area`。主机：`radiko.jp`。
- `class="OUT"` 不可用；`class="JP<编号>"` 可用（jp，编号只作展示）；其他为未知。

### MyVideo（myvideo）— 只发 IPv4，只判断 tw

- 请求：`GET https://www.myvideo.net.tw/login.do`，不跟随跳转。主机：`www.myvideo.net.tw`。
- 跳到含 `serviceAreaBlock` 的路径不可用；200 可用（无负面标记）；其他跳转为未知。

### Peacock（peacock）— 只判断 us

- 请求：`GET https://www.peacocktv.com/`，不跟随跳转。主机：`www.peacocktv.com`。
- 跳到含 `unavailable` 的路径不可用；200 可用（无负面标记）；其他为未知。

### Pluto TV（plutotv）

- 请求：`GET https://pluto.tv/`，不跟随跳转。主机：`pluto.tv`。
- 跳到含 `thanks-for-watching` 的路径不可用；200 或站内其他跳转可用（无负面标记）；其他为未知。
- 限制：多国开放、各国频道不同，不判断目录地区。

## 覆盖表

以引用脚本（LMC、1S、GO）各地区清单为基准逐项对照。每一项要么由一个适配器实现，要么写明不实现的原因；不为凑数降低判断标准，证据等级和 `unlock.Ingest` 的准入规则没有因为新增适配器而改变。机器可读的同一张表是 `internal/probe/coverage.go`（`GET /api/unlock/catalog` 的 `coverage`）。

**清单本身也待复核**：这张表按项目已知的各脚本地区分节整理，这一轮没有网络，没能对照引用的提交逐行重读；脚本后来增删的项目可能没有反映在这里。

原因代码：

| 代码 | 含义 |
|---|---|
| `needs_token` | 公开方法要把账号、应用令牌、API key、设备标识或会话值当作请求参数，本项目不发送任何这类数据 |
| `needs_js` | 要执行页面脚本，或从主机不固定的脚本里抓参数，放不进固定主机名单 |
| `weak_signal` | 只有不可靠的判断依据（写死的地区表、页面里的单个字样、只能读出地区而没有任何不可用标记） |
| `not_service` | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），出口确认已经给出实际地区 |
| `not_https` | 公开方法用明文 HTTP 或非 443 端口，探测只走 https/443 |
| `discontinued` | 平台已停止或并入别的服务 |
| `fake_login` | 公开方法提交伪造的登录表单看错误码，本项目不提交任何登录请求 |
| `not_reviewed` | 这一轮无法重读引用的源码，请求细节没有把握，不凭记忆实现；留待对照源码后补 |

各地区实现数：国际流媒体 15 项中 7 项（其中 Viu.com 是参考检查）；AI 6 项全部有适配器（其中 Perplexity、Grok 只做到达性，不能驱动自动选择）；香港 6 项中 2 项；台湾 10 项中 5 项；日本 19 项中 6 项（其中 Niconico 是参考检查）；新加坡地区清单 2 项中 0 项（新加坡出口上能用的是国际一节的 Netflix、Disney+、Prime Video、YouTube Premium、DAZN、TVBAnywhere+）；美国 17 项中 2 项。

### 国际流媒体

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| Netflix | LMC、1S、GO | 已实现：`auto-netflix` |  |
| Disney+ | LMC、1S、GO | 已实现：`auto-disney` |  |
| YouTube Premium | LMC、1S、GO | 已实现：`youtube-premium` |  |
| Amazon Prime Video | LMC、1S、GO | 已实现：`primevideo` |  |
| DAZN | LMC、1S、GO | 已实现：`dazn` |  |
| TVBAnywhere+ | LMC、GO | 已实现：`tvbanywhere` |  |
| Viu.com | LMC、GO | 已实现：`auto-mytvsuper`（参考检查 Viu.com，不入库） |  |
| iQIYI 国际版 | LMC、GO | 未实现（`needs_token`） | 地区只出现在 Set-Cookie 里，读它就要收 Cookie |
| Spotify 注册 | LMC、GO | 未实现（`needs_token`） | 注册接口的表单里带写死的应用 key |
| TikTok | LMC、GO | 未实现（`weak_signal`） | 只能读出页面里的 region，没有不可用标记 |
| HBO Max | LMC、1S、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| Disney+ Hotstar | LMC、1S | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| YouTube CDN | LMC、1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Netflix 首选 CDN | LMC、1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Steam 货币区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Bing 地区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Wikipedia 编辑权限 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Google Play 地区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Google 搜索免验证码 | LMC、1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |
| Instagram 授权音乐 | LMC、1S | 未实现（`needs_token`） | 请求带应用 ID 请求头与写死的查询文档 ID |
| Apple 地区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |

### AI

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| ChatGPT / OpenAI | LMC、1S、GO | 已实现：`auto-openai` |  |
| Claude | LMC、1S、GO | 已实现：`auto-anthropic` |  |
| Gemini | LMC、1S、GO | 已实现：`auto-gemini` |  |
| Microsoft Copilot | GO | 已实现：`auto-copilot` |  |
| Perplexity | GO | 已实现：`auto-perplexity` | 只做到达性：公开方法只是地区表 |
| Grok | GO | 已实现：`auto-grok` | 只做到达性：公开方法只是地区表加 403 |

### 香港

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| MyTV SUPER | LMC、1S、GO | 已实现：`auto-mytvsuper` |  |
| 巴哈姆特動畫瘋（港澳区） | LMC、1S、GO | 已实现：`auto-bahamut` |  |
| Now E | LMC、GO | 未实现（`needs_token`） | 请求体带设备标识与调用参考号 |
| ViuTV | LMC、GO | 未实现（`needs_token`） | 请求体带设备标识与调用参考号 |
| HBO GO Asia（香港） | LMC、GO | 未实现（`discontinued`） | 平台已停止或并入别的服务，公开方法已过时 |
| Bilibili 港澳台限定 | LMC、1S、GO | 未实现（`not_reviewed`） | 要写死的剧集 ID 与随机会话参数 |

### 台湾

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| KKTV | LMC、GO | 已实现：`auto-kktv` |  |
| LINE TV | LMC、GO | 已实现：`auto-linetv` |  |
| Hami Video | LMC、GO | 已实现：`auto-hami` |  |
| 巴哈姆特動畫瘋 | LMC、1S、GO | 已实现：`auto-bahamut` |  |
| MyVideo | LMC、GO | 已实现：`myvideo` |  |
| LiTV | LMC、GO | 未实现（`needs_token`） | 请求体带设备标识（puid） |
| 4GTV | LMC、GO | 未实现（`needs_token`） | 请求体是写死的编码串，内容不透明 |
| CatchPlay+ | LMC、GO | 未实现（`needs_token`） | 要 Bearer 令牌 |
| HBO GO Asia（台湾） | LMC、GO | 未实现（`discontinued`） | 平台已停止或并入别的服务，公开方法已过时 |
| Bilibili 台湾限定 | LMC、1S、GO | 未实现（`not_reviewed`） | 要写死的剧集 ID 与随机会话参数 |

### 日本

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| ABEMA | LMC、1S、GO | 已实现：`auto-abema` |  |
| Niconico | LMC、GO | 已实现：`auto-abema`（参考检查 Niconico，不入库） |  |
| TVer | LMC、1S、GO | 未实现（`needs_token`） | 要平台用户令牌链或播放器 API key |
| DMM TV | LMC、GO | 已实现：`dmm-tv` |  |
| Hulu Japan | LMC、GO | 已实现：`hulu-jp` |  |
| radiko | LMC、GO | 已实现：`radiko` |  |
| DMM | LMC、GO | 未实现（`weak_signal`） | 只看页面里的一句提示文字 |
| FOD（富士电视台） | LMC、GO | 未实现（`weak_signal`） | 只在应答里找 true / false 字样 |
| U-NEXT | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| WOWOW | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| TELASA | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| music.jp | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| mora | LMC | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| J:COM On Demand | LMC | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| VideoMarket | LMC、GO | 未实现（`needs_token`） | 要先换取访问令牌 |
| Paravi | LMC | 未实现（`discontinued`） | 已并入 U-NEXT |
| GYAO! | LMC | 未实现（`discontinued`） | 平台已停止或并入别的服务，公开方法已过时 |
| Karaoke@DAM | LMC、GO | 未实现（`not_https`） | 公开方法用明文 HTTP 或非 443 端口，探测只走 https/443 |
| 日本区游戏（舰队 Collection、赛马娘、公主连结、世界弹射物语、Project Sekai 等） | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏），不是解锁判断；出口确认已经给出实际地区 |

### 新加坡

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| meWATCH | LMC | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| HBO GO Asia（新加坡） | LMC、GO | 未实现（`discontinued`） | 平台已停止或并入别的服务，公开方法已过时 |

### 美国

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| Peacock | LMC、GO | 已实现：`peacock` |  |
| Pluto TV | LMC、GO | 已实现：`plutotv` |  |
| Hulu | LMC、1S、GO | 未实现（`fake_login`） | 公开方法提交伪造的登录表单来看错误码，本项目不提交任何登录请求 |
| Paramount+ | LMC、GO | 未实现（`weak_signal`） | 跳到 /intl/ 只说明不是美国站，多国都有本地站 |
| ESPN+ | LMC、GO | 未实现（`needs_token`） | 公开方法要把账号、应用令牌、API key、设备标识或会话值当作请求参数，本项目不发送任何这类数据 |
| Discovery+ | LMC、GO | 未实现（`needs_token`） | 公开方法要把账号、应用令牌、API key、设备标识或会话值当作请求参数，本项目不发送任何这类数据 |
| Starz | LMC、GO | 未实现（`needs_token`） | 公开方法要把账号、应用令牌、API key、设备标识或会话值当作请求参数，本项目不发送任何这类数据 |
| Crunchyroll | LMC、GO | 未实现（`needs_token`） | 公开方法要把账号、应用令牌、API key、设备标识或会话值当作请求参数，本项目不发送任何这类数据 |
| Fox | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| Philo | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| fuboTV | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| Sling TV | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| Tubi | LMC、GO | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| 其他北美频道站（Shudder、BritBox、Crackle、The CW、A&E、NBA TV、NBC、FXNOW、TLC GO、Acorn TV、MGM+、encoreTVB、KOCOWA、KBS America、DirecTV Stream） | LMC | 未实现（`not_reviewed`） | 本轮无法重读引用的源码（无网络），请求细节没有把握，不凭记忆实现；留待对照源码后补 |
| 已停止的北美服务（Funimation、Popcornflix、SHOWTIME 独立应用） | LMC | 未实现（`discontinued`） | 平台已停止或并入别的服务，公开方法已过时 |

## 服务组自动选择

检测结果改变路由的地方只有两类，都用同一个状态机（`internal/unlock`）和同一个准入（`unlock.Ingest`）：

1. **指向地区组的规则**（内置的 14 条 `auto-*` 规则就是这种）：状态以规则 ID 为键，探测项是同名适配器。
2. **服务组**（`model.ServiceGroup`，mihomo 的「可选择策略组」）：`select: "auto"` 且 `probes` 非空时，状态以 `service-group:<id>` 为键，结论影响所有指向这个服务组的规则。

同一个适配器只能在一处决定出口：服务组开了自动选择、它的某个检测项又是一条**已启用**、指向地区组的内置规则的适配器时，校验报错 `unlock_owner_conflict`。导入 mihomo 规则之后内置规则一般已停用，这时把相应适配器挂到导入的服务组上即可；如果重新启用内置规则，必须先把那个适配器从服务组的自动选择里去掉。

- **候选**：服务组指向的地区组的成员，按地区组的有效顺序（硬约束过滤、IX 优先）。候选范围由运营者决定：选哪个地区组、组里有哪些出口。**默认出口**是地区组自己选中的成员（自动组的首位，手动组的指定成员）。
- **钉死优先**：服务组是固定（`select` 为空）、指向单个出口、指向直连 / 拒绝、目标地区组是手动模式、或者它是兜底（MATCH）服务组时，结果只记录和展示，不移动出口。
- **多个检测项**：一轮里，对同一出口、同一地址族，服务组的任一个「判定」类检测项（`verdict` / `region_verdict`）明确未解锁就是失败；所有适用于该地址族的判定类检测项都发出并且都解锁才是成功；其余（有项没发出、超出预算、未知、只做到达性）都没有结论，按 `inconclusive` 入库。只做到达性的检测项永远不投票。
- **阈值和滞回不变**：连续两次定时失败才换成员（手动和健康补测不计）；切回首选要首选最新结果是 30 分钟内收到的成功，并且从最后一次失败之后连续成功满 30 分钟，期间任何一次失败都重新计时。
- **结果有效期**（`settings.unlock_probe.result_ttl_sec`，默认探测间隔的两倍，即 12 小时）：超过有效期的结果不是证据，既不能让一个成员成为可用备选，也不再把它排除在外。升级前保存、没有收到时间的旧结果保持原有含义，直到该成员的下一次结果把它替换。
- **只用有证据的备选**（服务组）：首选连续两次定时失败时，只换到有**有效期内成功结果**的候选；没有这样的候选就留在默认出口，标「组内都不可用」并在面板告警，不会换到没测过的成员，也不会换地区。指向地区组的规则（内置规则）保留原来的行为：没有已知可用成员时会先试一个还没测过的成员。
- **切换的生效路径**：决定存在面板的解锁状态里（`unlock.Decisions`，键是规则 ID 或 `service-group:<id>`），只经现有的安装事务进入网关（面板显示「待安装」，与内置规则相同；不会无人值守地自动安装）。编译时 `planRules` 是规则目标、mark、地址集合名字的唯一来源：服务组的决定把它的每条规则改到被选成员**自己的** mark，地址集合、SmartDNS 的解析器组（被选成员的隧道解析器，不是国内解析器；该成员没有 IPv6 时照常不返回 AAAA、不声明 IPv6 集合）、嗅探服务的规则快照和目标文件都从这同一份计划生成。按规则 ID 写的决定对经过服务组的规则无效。`internal/compile/service_select_test.go` 编译切换前后的结果，检查每个被引用的集合都已声明、没有重复声明、清单里的地址集合都已声明，嗅探服务接受编译出的快照和目标文件，覆盖 IPv4-only 与双栈目标、嵌套出口、仅 TCP 的外部出口、地区组和单出口目标。
- **没有规则的服务只展示**：一个适配器既不是启用规则的探测项、也没有挂在服务组上时，只能在面板里对指定的出口或地区组手动探测，结果标「未入库：没有关联」，不会因此新增或修改任何规则或服务组。

### 分流域名与探测主机不是一回事

- **一个服务的流量走哪个出口**，只由有序规则列表决定：规则自己的域名 / 后缀 / 关键字、它引用的规则集合（订阅的 Clash / Surge 规则集）或 geosite 名单。服务组只决定这些规则的目标。
- **探测访问哪些主机**，由适配器写死的 `hosts` 决定（例如 Netflix 只访问 `www.netflix.com`，ABEMA 访问检测接口 `api.abema.io`）。这些主机不会被加进任何分流规则，也不保证在服务组的规则覆盖之内；探测本身固定从所选出口出去，不经过分流规则。
- 所以「检测说可用」只说明从那个出口访问那几个固定主机得到的结论；服务的其余域名是否真的走了这个出口，要看规则是否覆盖它们（规则页的「这个域名命中哪条规则」）。

## 调度与克制

`settings.unlock_probe`（都可以不填，填了要通过校验）：

| 设置 | 默认 | 范围 | 作用 |
|---|---|---|---|
| `unlock_interval_sec`（原有） | 6 小时 | 建议 ≥ 1 小时 | 定时探测周期 |
| `exit_concurrency` | 2（与以前相同） | 1–2 | 同时探测的出口数（agent 最多同时 2 个） |
| `exit_request_budget` | 40 | 6–200 | 一次**定时**探测里每个出口最多发多少个平台请求（两个地址族合计，含前后各一次出口确认）。超出的服务这一轮不探测，记「未入库：超出预算」；按候选优先级取舍：服务当前所在的出口和默认出口先测 |
| `result_ttl_sec` | 探测间隔 × 2 | 1 小时–7 天，且不短于探测间隔 | 结果有效期（见上） |

- 定时探测只跑至少有一个**能移动出口**的拥有者（未钉死的规则或自动服务组）的适配器，而且只在它们的候选出口上跑；手动探测可以选任何适配器，但没有关联规则或服务组的适配器必须指定出口。
- 外部 SOCKS 出口只承载 IPv4 的 TCP：只发 IPv4，IPv6 记「未发出」；所有适配器都只用 HTTPS（TCP），所以它的结论只覆盖 TCP，不说明 UDP / QUIC。

## 合成样本

`internal/probe/adapters_test.go` 和 `adapters_more_test.go` 里，每个服务都有手写的应答样本（新增的 10 个各覆盖：可用、不可用、地区不符（带地区的）、质询页、限流、改版），覆盖：地区受限、可用（有地区和无地区）、登录墙、反爬质询、跳到不可用页面、超时（在运行器层面测）、意外或改版的应答。另有测试检查每个适配器声明的 `returns` 与分类器实际能给出的结论完全一致。样本都标明是合成的，不含 Cookie、令牌或个人数据。它们只能证明分类器实现了本文写的规则，证明不了真实平台现在怎么应答。

## 需要人工在真实平台上核对的事项

在受控的出口上，由人执行（本项目的自动化不会去请求平台）：

1. 每个适配器在已知可用和已知受限的出口上各跑一次，确认给出的结论和 `signal` 符合预期。
2. 巴哈姆特：不带 Cookie 时，token.php 是否仍然返回 `animeSn`。如果不返回，这个服务会一直是未知，需要另行决定怎么处理。
3. Gemini：`45631641,null,true` 标记是否还在；未登录时是否先出同意页。
4. Copilot：`c/api/user` 未登录时的应答形状。
5. OpenAI：`cookie_requirements` 在可用地区是否返回 JSON。
6. Claude：可用地区最终停在哪个路径，质询出现的频率。
7. LINE TV：页面里 `__INITIAL_STATE__` 和 `eps_info` 的结构。
8. MyTV SUPER：应答里实际用的是 `country_code` 还是 `region`。
9. 各平台在 IPv6 出口上的表现，以及“只发 IPv4”的服务是否本来就没有 AAAA 记录。
10. 每个检查的跳转链是否都停在固定主机名单内，有没有因此被归为 `redirect_unlisted` 的情况。
11. 覆盖表新增的 10 个适配器：先对照引用脚本的当前源码核对请求地址、请求体和标记（来源标「待对照源码复核」），再在真实平台上各跑一次可用和受限出口。
12. 覆盖表本身：对照引用脚本当前的地区分节，补上漏掉的项目或标出已删除的项目。
13. 服务组自动选择：在真实网关上把一个服务组设为自动，制造首选连续两次定时失败，确认面板给出待安装、安装后该服务组规则的流量和 DNS 都从被选出口出去（抓包，不经国内解析器），首选恢复 30 分钟后切回；所有候选失败时留在默认出口并告警。
