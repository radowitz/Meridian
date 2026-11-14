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
| youtube-premium | YouTube Premium | verdict | 否 | YouTube Premium |
| primevideo | Amazon Prime Video | region_verdict | 是 | Prime Video |
| dazn | DAZN | region_verdict | 是 | DAZN |
| tvbanywhere | TVBAnywhere+ | verdict | 是 | TVBAnywhere+ |
| dmm-tv | DMM TV | region_verdict（仅 jp） | 是 | DMM TV |
| hulu-jp | Hulu Japan | region_verdict（仅 jp） | 是 | Hulu Japan |
| radiko | radiko | region_verdict（仅 jp） | 是 | radiko |
| myvideo | MyVideo | verdict（仅 tw） | 是 | MyVideo |
| peacock | Peacock | verdict（仅 us） | 否 | Peacock |
| plutotv | Pluto TV | verdict | 是 | Pluto TV |
| fod | FOD（富士电视台） | region_verdict（仅 jp） | 是 | FOD |
| unext | U-NEXT | region_verdict（仅 jp） | 否 | U-NEXT |
| dmm | DMM（地区判定接口） | region_verdict（仅 jp） | 否 | DMM |
| nhk-plus | NHK+ | region_verdict（仅 jp） | 否 | NHK+ |
| 4gtv | 4GTV | region_verdict（仅 tw） | 是 | 4GTV |
| friday-video | friDay 影音 | verdict（仅 tw） | 否 | friDay 影音 |
| nbatv | NBA TV | verdict | 否 | NBA TV |
| bglobal-sea | B-Global（东南亚） | verdict（仅 sg/my/th/id/vn/ph） | 是 | B-Global |
| fubotv | fuboTV | verdict | 是 | fuboTV |
| philo | Philo | verdict（仅 us） | 是 | Philo |
| sling | Sling TV | verdict（仅 us） | 否 | Sling TV |
| tubi | Tubi | verdict | 否 | Tubi |
| acorntv | Acorn TV | verdict | 是 | Acorn TV |
| britbox | BritBox | verdict | 否 | BritBox |
| amcplus | AMC+ | verdict | 否 | AMC+ |
| metaai | Meta AI | verdict | 否 | Meta AI |
| coze | Coze | verdict | 否 | Coze |

「仅 jp」等是适配器声明的 `regions`：它的结论只能说明出口在不在这个地区可用；放到别的地区的出口上只会得到「地区不符 / 不可用」。没有声明的适配器对任何地区都给出结论（带地区的适配器仍要求平台报的地区与出口一致）。

**上面 14 个之后的 27 个适配器是覆盖表新增的**：2026-11-14 对照下文「各服务」列出的三个来源（固定到完整提交号）逐项核对了请求地址、方法、关键请求头和请求体、成功 / 失败 / 地区标记，来源一栏的 `checked` 是对照日期。它们和其余适配器一样只在合成样本上测过，没有请求过真实平台。它们不绑定任何内置规则：只有运营者把它们挂到某个服务组上，结果才会参与选择。

AI 类服务没有“目录地区”的概念，所以 Gemini、Copilot 报的地区只作展示，不拿来和出口地区比较。流媒体的地区不一致按 `not_unlocked` 处理（`region_mismatch`）。

## 各服务

各节引用的公开来源（最初的 14 个查阅日期 2026-11-13；覆盖表与新增适配器 2026-11-14 再次只读拉取，同一提交）：

- **LMC**：lmc999/RegionRestrictionCheck `check.sh`，提交 `b6d4a6f9a87fc6eae6d3e62d0092ececcec8e844`（2025-12-08），AGPL-3.0。<https://github.com/lmc999/RegionRestrictionCheck>
- **1S**：1-stream/RegionRestrictionCheck `check.sh`，提交 `ef841d0a2910a44a6ca565e3a03de0f2282d83b3`（2026-10-06），AGPL-3.0。<https://github.com/1-stream/RegionRestrictionCheck>
- **GO**：HsukqiLee/MediaUnlockTest `pkg/providers/*.go`（清单在 `lists.go`），提交 `dc6c6e6cc490315824d485c668f059535e97ea94`（2026-10-14），是 nkeonkeo/MediaUnlockTest 仍在维护的分支；仓库里没有许可证文件。<https://github.com/HsukqiLee/MediaUnlockTest>

只读取了源码，没有复制代码：本项目的请求地址、固定请求体和应答标记是公开方法的事实，判断逻辑和代码是本项目自己写的（`internal/probe/adapters_more.go`、`adapters_new.go`）。机器可读的提交号在 `probe.SourceCommits`。

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

以下各节由 `internal/probe` 的目录生成，与代码一致。和公开方法有意不同的地方写在「限制」里（例如不带 Cookie、对某个标记读得更严）。

### YouTube Premium（youtube-premium）

- 请求：GET `https://www.youtube.com/premium`。主机：`www.youtube.com`、`youtube.com`。
- 判断：Premium 介绍页：引用 www.google.cn = 不可用（cn）；含 Premium is not available in your country（不分大小写）= 不可用；含 ad-free（不分大小写）= 可用，INNERTUBE_CONTEXT_GL 给出的地区只作展示；其他 = 未知
- 限制：两个公开实现都带一组同意页 Cookie 请求，本项目不带 Cookie，所以要求先同意 Cookie 的地区多半是未知；只读未登录的介绍页，不是账号判断
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_YouTube_Premium（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/YouTube.go YoutubeRegion（成功标记不同：看购买按钮或价格字样，未采用）（dc6c6e6）（对照日期 2026-11-14）

### Amazon Prime Video（primevideo）— 只发 IPv4

- 请求：GET `https://www.primevideo.com`。主机：`www.primevideo.com`、`primevideo.com`。
- 判断：首页数据：isServiceRestricted 为 true = 不可用；"currentTerritory":"XX" 给出的地区必须与出口一致，不一致按地区不符为不可用；都没有 = 未知
- 限制：LMC 只要页面出现 isServiceRestricted 这个键就算不可用，本项目要求它的值是 true，避免把 false 读成封锁；GO 在没有地区时会跟随亚马逊各国站点的链接，主机不固定，未采用；公开实现不支持 IPv6，只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_PrimeVideo（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/PrimeVideo.go（dc6c6e6）（对照日期 2026-11-14）

### DAZN（dazn）— 只发 IPv4

- 请求：POST（固定请求体） `https://startup.core.indazn.com/misl/v5/Startup`。主机：`startup.core.indazn.com`。
- 判断：启动接口（固定的匿名 JSON 请求体）：Region.isAllowed = false 不可用；true 且 GeolocatedCountry 与出口一致可用，不一致不可用；非质询的 403 或应答含 Security policy has been breached = 拒绝该地址；字段缺失 = 未知
- 限制：“可用”只是地区允许，不代表有可看的赛事；公开实现不支持 IPv6，只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_Dazn（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/Dazn.go（dc6c6e6）（对照日期 2026-11-14）

### TVBAnywhere+（tvbanywhere）— 只发 IPv4

- 请求：GET `https://uapisfm.tvbanywhere.com.sg/geoip/check/platform/android`。主机：`uapisfm.tvbanywhere.com.sg`。
- 判断：geoip 接口 JSON 的 allow_in_this_country：true = 可用（country 只作展示），false = 不可用；没有这个字段 = 未知
- 限制：GO 把 country = HK 也当作可用，LMC 只看 allow_in_this_country，本项目按 LMC（平台自己的标志）；这是 TVB 面向香港以外的服务，香港出口上「不可用」可能是正常的；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_TVBAnywhere（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/TVBAnywhere.go（dc6c6e6）（对照日期 2026-11-14）

### DMM TV（dmm-tv）— 只发 IPv4

- 请求：POST（固定请求体） `https://api.beacon.dmm.com/v1/streaming/start`。主机：`api.beacon.dmm.com`。
- 判断：播放开始接口（固定的匿名请求体，与 LMC 相同）：应答含 FOREIGN = 海外地址，不可用；含 UNAUTHORIZED = 通过地区检查、只差登录 → 可用（日本）；其他 = 未知
- 限制：“可用”只说明地区检查通过；作品 ID 写死，下架后会变成未知；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_DMMTV（b6d4a6f）；1-stream/RegionRestrictionCheck check.sh MediaUnlockTest_DMMTV（ef841d0）（对照日期 2026-11-14）

### Hulu Japan（hulu-jp）— 只发 IPv4

- 请求：GET `https://id.hulu.jp/`。主机：`id.hulu.jp`、`www.hulu.jp`、`hulu.jp`。
- 判断：账号入口跟随跳转后的最终地址：含 restrict = 地区限制页，不可用；非质询的 403 = 不可用；停在 hulu.jp 上且 200 = 可用（日本）；其他 = 未知
- 限制：只看跳转去向和状态码；GO 不跟随跳转、把 302 当作可用，本项目按 LMC 跟随（只在固定主机内）；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_HuluJP（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/Hulu.go HuluJP（dc6c6e6）（对照日期 2026-11-14）

### radiko（radiko）— 只发 IPv4

- 请求：GET `https://radiko.jp/area?_=1625406539531`。主机：`radiko.jp`。
- 判断：地区接口（与两个公开实现相同的固定查询参数）：class="OUT" = 日本以外，不可用；含 JAPAN = 日本某地区 → 可用（日本，地区名只作展示）；其他 = 未知
- 限制：只说明 IP 被认作日本某一区，不代表能收听全部电台；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_Radiko（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/Radiko.go（dc6c6e6）（对照日期 2026-11-14）

### MyVideo（myvideo）— 只发 IPv4

- 请求：GET `https://www.myvideo.net.tw/login.do`。主机：`www.myvideo.net.tw`。
- 判断：登录页跟随跳转后的最终地址：含 serviceAreaBlock（不分大小写）= 地区限制，不可用；非质询的 403 = 不可用；200 = 可用（无负面标记）；其他 = 未知
- 限制：“可用”只是没有地区限制跳转；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_MyVideo（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/MyVideo.go（dc6c6e6）（对照日期 2026-11-14）

### Peacock（peacock）

- 请求：GET `https://www.peacocktv.com/`。主机：`www.peacocktv.com`。
- 判断：首页跟随跳转后的最终地址：含 unavailable（不分大小写）= 不可用；200 = 可用（无负面标记）；其他 = 未知
- 限制：只看首页是否被引到不可用页；GO 只看第一次跳转的 Location，结论相同
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_PeacockTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/PeacockTV.go（dc6c6e6）（对照日期 2026-11-14）

### Pluto TV（plutotv）— 只发 IPv4

- 请求：GET `https://pluto.tv/`。主机：`pluto.tv`。
- 判断：首页跟随跳转：最终地址含 plutotv-is-not-available（LMC）或页面含 thanks-for-watching（GO）= 不可用；200 = 可用（无负面标记）；其他 = 未知
- 限制：多国开放、各国频道不同，不判断目录地区；只发 IPv4（LMC 不支持 IPv6）
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_PlutoTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/PlutoTV.go（dc6c6e6）（对照日期 2026-11-14）

### FOD（富士电视台）（fod）— 只发 IPv4

- 请求：GET `https://geocontrol1.stream.ne.jp/fod-geo/check.xml?time=1624504256`。主机：`geocontrol1.stream.ne.jp`。
- 判断：地区检查 XML 的 <FLAG TYPE="…">：true = 可用（日本），false = 不可用；其他 = 未知
- 限制：只说明地区检查通过；固定的 time 参数与公开方法相同；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_FOD（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/FOD.go（dc6c6e6）（对照日期 2026-11-14）

### U-NEXT（unext）

- 请求：POST（固定请求体） `https://cc.unext.jp`。主机：`cc.unext.jp`。
- 判断：播放列表接口（固定作品、匿名 GraphQL 请求）的 resultStatus：475 或 200 = 可用（日本），467 = 不可用；其他 = 未知
- 限制：公开方法发送网页播放器的完整查询，本项目只请求 resultStatus 一个字段（自己写的较短查询），平台是否接受未验证；作品下架后会变成未知
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_unext（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/UNext.go（dc6c6e6）（对照日期 2026-11-14）

### DMM（地区判定接口）（dmm）

- 请求：POST（固定请求体） `https://api.tv.dmm.com/graphql`。主机：`api.tv.dmm.com`。
- 判断：匿名 GraphQL 查询 client.isForeignAccess：false = 可用（日本），true = 海外访问，不可用；其他 = 未知
- 限制：按 GO 的方法；LMC 的方法只看一个页面里的提示文字（判断依据弱），未采用
- 来源：HsukqiLee/MediaUnlockTest pkg/providers/DMM.go（dc6c6e6）；lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_DMM（未采用）（b6d4a6f）（对照日期 2026-11-14）

### NHK+（nhk-plus）

- 请求：GET `https://location-plus.nhk.jp/geoip/area.json`。主机：`location-plus.nhk.jp`。
- 判断：平台自己的地理接口 JSON country_code：JP = 可用（日本），其他国家码 = 不可用（地区不符）；非质询的 403 = 拒绝；其他 = 未知
- 限制：只说明平台把地址认作日本，不代表账号能看
- 来源：HsukqiLee/MediaUnlockTest pkg/providers/NHKPlus.go（dc6c6e6）（对照日期 2026-11-14）

### 4GTV（4gtv）— 只发 IPv4

- 请求：GET `https://api2.4gtv.tv/Web/IsTaiwanArea`。主机：`api2.4gtv.tv`。
- 判断：IsTaiwanArea 接口 JSON 的 Data：Y = 可用（台湾），N = 不可用；其他 = 未知
- 限制：按 LMC 的方法；GO 的方法要 POST 一段编码过的请求体，未采用；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_4GTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/4GTV.go（未采用）（dc6c6e6）（对照日期 2026-11-14）

### friDay 影音（friday-video）

- 请求：GET `https://video.friday.tw/api2/streaming/get?streamingId=122581&streamingType=2&contentType=4&contentId=1&clientId=`。主机：`video.friday.tw`。
- 判断：播放接口（固定作品、空 clientId）JSON 的 code：0000 = 可用，1006 = 不可用；其他 = 未知
- 限制：只说明地区检查通过；作品下架后会变成未知
- 来源：HsukqiLee/MediaUnlockTest pkg/providers/FridayVideo.go（dc6c6e6）（对照日期 2026-11-14）

### NBA TV（nbatv）

- 请求：GET `https://www.nba.com/watch/`。主机：`www.nba.com`。
- 判断：观看页：含 Service is not available in your region = 不可用；200 且没有这句 = 可用（无负面标记）；其他 = 未知
- 限制：多国服务，不判断目录地区；“可用”只是没有负面标记
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_NBATV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/NBATV.go（dc6c6e6）（对照日期 2026-11-14）

### B-Global（东南亚）（bglobal-sea）— 只发 IPv4

- 请求：GET `https://api.bilibili.tv/intl/gateway/web/playurl?s_locale=en_US&platform=web&ep_id=347666`。主机：`api.bilibili.tv`。
- 判断：国际版播放地址接口（固定剧集）JSON 的 code：0 = 可用（东南亚版权区），10003003 或 10004001 = 不可用；其他 = 未知
- 限制：只判断这部东南亚版权作品；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_BGlobalSEA（b6d4a6f）（对照日期 2026-11-14）

### fuboTV（fubotv）— 只发 IPv4

- 请求：GET `https://api.fubo.tv/v3/location`。主机：`api.fubo.tv`。
- 判断：位置接口：含 NO_SERVICE_IN_COUNTRY 或 "network_allowed":false = 不可用；"network_allowed":true = 可用（country_code2 只作展示）；其他 = 未知
- 限制：fuboTV 在几个国家开放，地区只作展示；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_FuboTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/FuboTV.go（dc6c6e6）（对照日期 2026-11-14）

### Philo（philo）— 只发 IPv4

- 请求：GET `https://content-us-east-2-fastly-b.www.philo.com/geo`。主机：`content-us-east-2-fastly-b.www.philo.com`。
- 判断：地理接口 JSON 的 status：SUCCESS = 可用，FAIL = 不可用；其他 = 未知
- 限制：主机名是公开方法写死的 CDN 名字，改名后会失败；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_Philo（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/Philo.go（dc6c6e6）（对照日期 2026-11-14）

### Sling TV（sling）

- 请求：GET `https://www.sling.com/`。主机：`www.sling.com`。
- 判断：首页跟随跳转后的最终地址：含 geo-block = 不可用；200 = 可用（无负面标记）；其他 = 未知
- 限制：只看是否被引到地区封锁页
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_SlingTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/SlingTV.go（dc6c6e6）（对照日期 2026-11-14）

### Tubi（tubi）

- 请求：GET `https://tubitv.com/home`。主机：`tubitv.com`、`www.tubitv.com`。
- 判断：首页：含 not currently available in your area = 不可用；含 manifest = 可用；都没有 = 未知
- 限制：“可用”的依据是页面里的 manifest 字样（公开方法如此），较弱；多国开放，不判断目录地区
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_TubiTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/TubiTV.go（dc6c6e6）（对照日期 2026-11-14）

### Acorn TV（acorntv）— 只发 IPv4

- 请求：GET `https://acorn.tv/`。主机：`acorn.tv`、`www.acorn.tv`。
- 判断：首页：含 not yet available in your 或 unavailable in your = 不可用；含 signup.acorn.tv（注册入口）= 可用；都没有 = 未知
- 限制：多国开放，不判断目录地区；只发 IPv4
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_AcornTV（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/AcornTV.go（dc6c6e6）（对照日期 2026-11-14）

### BritBox（britbox）

- 请求：GET `https://www.britbox.com/`。主机：`www.britbox.com`、`britbox.com`。
- 判断：首页跟随跳转后的最终地址：含 locationnotsupported、locationnotvalidated 或被引到 britbox.co.uk = 不可用；200 = 可用（无负面标记）；其他 = 未知
- 限制：只看跳转去向；多国开放，不判断目录地区
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_BritBox（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/BritBox.go（dc6c6e6）（对照日期 2026-11-14）

### AMC+（amcplus）

- 请求：GET `https://www.amcplus.com/`。主机：`www.amcplus.com`、`amcplus.com`。
- 判断：首页跟随跳转后的最终地址：含 geographic-restriction 或非质询的 403 = 不可用；200 = 可用（无负面标记）；其他 = 未知
- 限制：公开方法从最终地址的末段读一个地区名，本项目不采用（只作展示意义也不大）；多国开放，不判断目录地区
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_AMCPlus（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/AMCPlus.go（dc6c6e6）（对照日期 2026-11-14）

### Meta AI（metaai）

- 请求：GET `https://www.meta.ai/`。主机：`www.meta.ai`。
- 判断：首页：含 AbraGeoBlockedErrorRoot = 地区封锁，不可用；含 KadabraRootContainer = 可用（"code":"xx_YY" 的 YY 只作展示）；都没有 = 未知
- 限制：标记是页面组件名，改版会变成未知；不是账号判断
- 来源：lmc999/RegionRestrictionCheck check.sh WebTest_MetaAI（b6d4a6f）（对照日期 2026-11-14）

### Coze（coze）

- 请求：GET `https://www.coze.com/api/developer/get_login_info`。主机：`www.coze.com`。
- 判断：未登录信息接口 JSON：data.IsForbiddenRegion = true 或应答含 Your region is not supported = 不可用；data.CountryCode 非空 = 可用（地区只作展示）；非质询的 403 = 拒绝；其他 = 未知
- 限制：接口没有公开文档；不是账号判断
- 来源：HsukqiLee/MediaUnlockTest pkg/providers/Coze.go（dc6c6e6）（对照日期 2026-11-14）

## 覆盖表

以引用脚本（LMC、1S、GO）各地区清单为基准逐项对照。每一项要么由一个适配器实现，要么写明不实现的原因；不为凑数降低判断标准，证据等级和 `unlock.Ingest` 的准入规则没有因为新增适配器而改变。机器可读的同一张表是 `internal/probe/coverage.go`（`GET /api/unlock/catalog` 的 `coverage`）。

清单来自两个 check.sh 的地区函数（Global / HK / TW / JP / NA / SEA / AI）和 GO 的 `lists.go`，在上面固定的提交上逐项读出；新加坡取东南亚清单里的新加坡部分和东南亚通用项，美国取北美清单里的美国部分和通用项。其他地区（欧洲、韩国、印度、大洋洲、加拿大、南美、非洲）不在这张表里。

原因代码：

| 代码 | 含义 |
|---|---|
| `needs_token` | 公开方法要把账号、应用令牌、API key、播放器 policy key、设备标识或会话值当作请求参数，本项目不发送任何这类数据 |
| `needs_js` | 要执行页面脚本，或从前一步页面里取多个地址和参数，放不进固定的单值链 |
| `weak_signal` | 只有不可靠的判断依据（写死的地区表、只看 HTTP 状态码（403 也可能是风控）、页面里的单个字样、第三方地理服务、只能读出地区而没有不可用标记） |
| `not_service` | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），出口确认已经给出实际地区 |
| `not_https` | 公开方法用明文 HTTP 或非 443 端口，探测只走 https/443 |
| `discontinued` | 平台已停止或并入别的服务 |
| `fake_login` | 公开方法提交伪造的登录表单看错误码，本项目不提交任何登录请求 |
| `header_only` | 判断依据在应答头或 Set-Cookie 里，探测不把应答头和 Cookie 交给分类器 |
| `transport` | 公开方法降低 TLS 要求或直连写死的 IP 并改写 Host 头 |

各地区实现数（含参考检查）：国际（多地区） 28 项中 8 项；AI 14 项中 8 项；香港 9 项中 3 项；台湾 13 项中 7 项；日本 27 项中 9 项；新加坡（含东南亚通用项） 6 项中 1 项；美国 34 项中 9 项。Perplexity、Grok 只做到达性，不能驱动自动选择；Viu.com、Niconico 是参考检查，不入库。新加坡出口上能用的还有国际一节的 Netflix、Disney+、Prime Video、YouTube Premium、DAZN、TVBAnywhere+、NBA TV。

### 国际（多地区）

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| Netflix | LMC、1S、GO | 已实现：`auto-netflix` |  |
| Disney+ | LMC、1S、GO | 已实现：`auto-disney` |  |
| YouTube Premium | LMC、1S、GO | 已实现：`youtube-premium` |  |
| Amazon Prime Video | LMC、1S、GO | 已实现：`primevideo` |  |
| DAZN | LMC、1S、GO | 已实现：`dazn` |  |
| TVBAnywhere+ | LMC、1S、GO | 已实现：`tvbanywhere` |  |
| Viu.com | LMC、1S、GO | 已实现：`auto-mytvsuper`（参考检查 Viu.com，不入库） |  |
| NBA TV | LMC、1S、GO | 已实现：`nbatv` |  |
| iQIYI 国际版 | LMC、1S、GO | 未实现（`header_only`） | 地区来自应答 Set-Cookie 里的 mod= 值 |
| Spotify 注册 | LMC、1S、GO | 未实现（`needs_token`） | 注册接口的表单里带写死的应用 key |
| HotStar | LMC、1S、GO | 未实现（`header_only`） | 地区来自跳转与 Cookie 里的 geo= 值 |
| Bilibili Anime（港澳台） | 1S、GO | 未实现（`needs_token`） | 请求带每次随机生成的 session 参数 |
| TikTok | 1S、GO | 未实现（`weak_signal`） | 只能读出平台认定的地区，没有不可用标记 |
| Instagram 授权音乐 | 1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| WeTV | GO | 未实现（`weak_signal`） | 公开方法只读地区 |
| YouTube CDN | LMC、1S、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| YouTube 地区 | 1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Netflix 首选 CDN | LMC、1S、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Steam 货币区 | LMC、1S、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Bing 地区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Apple 地区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| OneTrust 地区 | LMC | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Wikipedia 编辑权限 | LMC、1S、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Google Play 地区 | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Google 搜索免验证码 | LMC、1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| Reddit | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| X（Twitter） | GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| SD 高达 G 世纪（游戏） | LMC | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |

### AI

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| ChatGPT / OpenAI | LMC、1S、GO | 已实现：`auto-openai` |  |
| Claude | LMC、1S、GO | 已实现：`auto-anthropic` |  |
| Gemini | LMC、1S、GO | 已实现：`auto-gemini` |  |
| Microsoft Copilot | 1S、GO | 已实现：`auto-copilot` |  |
| Perplexity | GO | 已实现：`auto-perplexity` | 只做到达性：公开方法是地区表 |
| Grok | GO | 已实现：`auto-grok` | 只做到达性：公开方法是地区表加 403 |
| Meta AI | LMC | 已实现：`metaai` |  |
| Coze | GO | 已实现：`coze` |  |
| Sora | 1S | 未实现（`weak_signal`） | cdn-cgi/trace 的 loc 对照写死的地区表 |
| Poe | GO | 未实现（`weak_signal`） | loc 对照写死的地区表 |
| Mistral | GO | 未实现（`weak_signal`） | loc 对照写死的地区表 |
| DeepSeek | GO | 未实现（`transport`） | 直连写死的 IP 并改写 Host 头 |
| Kimi | GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| Dola | GO | 未实现（`weak_signal`） | 只能读出地区，没有不可用标记 |

### 香港

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| MyTV SUPER | LMC、1S、GO | 已实现：`auto-mytvsuper` |  |
| 巴哈姆特動畫瘋（港澳区） | LMC、1S、GO | 已实现：`auto-bahamut` |  |
| NBA TV（香港） | 1S、GO | 已实现：`nbatv` |  |
| Now E | LMC | 未实现（`needs_token`） | 请求体带设备标识与调用参考号 |
| ViuTV | LMC、1S、GO | 未实现（`needs_token`） | 请求体带设备标识与调用参考号 |
| HBO Max（香港） | LMC、1S、GO | 未实现（`header_only`） | 地区码 countryCode= 在应答头里 |
| SonyLiv（香港） | LMC、GO | 未实现（`needs_token`） | 先从页面取 securityToken 再调接口 |
| Bilibili 港澳台限定 | LMC、1S | 未实现（`needs_token`） | 请求带每次随机生成的 session 参数 |
| HOY TV | 1S、GO | 未实现（`weak_signal`） | 只看直播流地址的 HTTP 状态码 |

### 台湾

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| KKTV | LMC、1S、GO | 已实现：`auto-kktv` |  |
| LINE TV | LMC、1S、GO | 已实现：`auto-linetv` |  |
| Hami Video | LMC、1S、GO | 已实现：`auto-hami` |  |
| 巴哈姆特動畫瘋 | LMC、1S、GO | 已实现：`auto-bahamut` |  |
| MyVideo | LMC、1S、GO | 已实现：`myvideo` |  |
| 4GTV | LMC、1S、GO | 已实现：`4gtv` |  |
| friDay 影音 | 1S、GO | 已实现：`friday-video` |  |
| LiTV | LMC、1S、GO | 未实现（`needs_token`） | 请求带设备标识（puid） |
| Ofiii | 1S、GO | 未实现（`needs_token`） | 查询串带写死的设备 ID |
| CatchPlay+ | LMC、1S、GO | 未实现（`needs_token`） | 要 Bearer 令牌 |
| HBO Max（台湾） | LMC、1S、GO | 未实现（`header_only`） | 地区码 countryCode= 在应答头里 |
| SonyLiv（台湾） | LMC | 未实现（`needs_token`） | 先从页面取 securityToken 再调接口 |
| Bilibili 台湾限定 | LMC、1S | 未实现（`needs_token`） | 请求带每次随机生成的 session 参数 |

### 日本

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| ABEMA | LMC、1S、GO | 已实现：`auto-abema` |  |
| Niconico | LMC、1S、GO | 已实现：`auto-abema`（参考检查 Niconico，不入库） |  |
| DMM TV | LMC、1S | 已实现：`dmm-tv` |  |
| DMM | LMC、GO | 已实现：`dmm` |  |
| Hulu Japan | LMC、1S、GO | 已实现：`hulu-jp` |  |
| radiko | LMC、1S、GO | 已实现：`radiko` |  |
| FOD（富士电视台） | LMC、1S、GO | 已实现：`fod` |  |
| U-NEXT | LMC、1S、GO | 已实现：`unext` |  |
| NHK+ | 1S、GO | 已实现：`nhk-plus` |  |
| TVer | LMC、1S、GO | 未实现（`needs_token`） | 要平台用户令牌链或播放器 API key |
| TELASA | LMC、1S、GO | 未实现（`needs_token`） | 请求头带写死的设备 ID（X-Device-ID） |
| WOWOW | LMC、1S、GO | 未实现（`needs_js`） | 四步链，从前一步的页面里取多个地址与作品号 |
| VideoMarket | LMC、1S、GO | 未实现（`needs_token`） | 请求带写死的 Bearer 令牌 |
| AnimeFesta | LMC、1S、GO | 未实现（`needs_token`） | 请求头带用户追踪 ID |
| Lemino | LMC、1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| d アニメストア | LMC、1S、GO | 未实现（`transport`） | 要允许旧式 TLS 重协商；判断依据也只是页面里的「海外」字样 |
| J:COM On Demand | LMC、1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| WATCHA | LMC、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| Rakuten TV JP | LMC、1S、GO | 未实现（`weak_signal`） | 公开方法把 Rakuten TV 的播放信息和另一个服务（Rakuten NBA）的地理过滤拼成一个结论 |
| Rakuten Magazine | 1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| MGStage | 1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| Karaoke@DAM | LMC、1S、GO | 未实现（`not_https`） | 公开方法用明文 HTTP 或非 443 端口，探测只走 https/443 |
| mora | LMC、1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| music.jp | LMC、1S、GO | 未实现（`weak_signal`） | 只看脚本文件里有没有 checkIp 字样 |
| Paravi | 1S | 未实现（`discontinued`） | 已并入 U-NEXT |
| ErogameScape（论坛） | LMC、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |
| 日本区游戏（舰队 Collection、赛马娘、为美好的世界献上祝福 Fantastic Days、公主连结、Project Sekai、World Flipper） | LMC、1S、GO | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |

### 新加坡（含东南亚通用项）

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| B-Global 东南亚 | LMC、1S | 已实现：`bglobal-sea` |  |
| meWATCH | LMC、1S、GO | 未实现（`weak_signal`） | 应答里出现任何数字 code 都算不可用（错误和限流也会这样） |
| StarHub TV+ | 1S | 未实现（`weak_signal`） | 只看直播清单地址的 HTTP 状态码 |
| CatchPlay+（新加坡） | 1S、GO | 未实现（`needs_token`） | 要 Bearer 令牌 |
| HBO Max（东南亚） | LMC、1S、GO | 未实现（`header_only`） | 地区码 countryCode= 在应答头里 |
| SonyLiv（东南亚） | LMC | 未实现（`needs_token`） | 先从页面取 securityToken 再调接口 |

### 美国

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| Peacock | LMC、1S、GO | 已实现：`peacock` |  |
| Pluto TV | LMC、1S、GO | 已实现：`plutotv` |  |
| fuboTV | LMC、GO | 已实现：`fubotv` |  |
| Philo | LMC、1S、GO | 已实现：`philo` |  |
| Sling TV | LMC、1S、GO | 已实现：`sling` |  |
| Tubi | LMC、GO | 已实现：`tubi` |  |
| Acorn TV | LMC、1S、GO | 已实现：`acorntv` |  |
| BritBox | LMC、1S、GO | 已实现：`britbox` |  |
| AMC+ | LMC、GO | 已实现：`amcplus` |  |
| Hulu | LMC、1S、GO | 未实现（`fake_login`） | 公开方法提交伪造的登录表单看错误码，本项目不提交任何登录请求 |
| HBO Max（美国） | LMC、1S、GO | 未实现（`header_only`） | 地区码 countryCode= 在应答头里 |
| Paramount+ | LMC、1S、GO | 未实现（`weak_signal`） | 只看是否跳到 /intl/（只说明不是美国站）与状态码 |
| ESPN+ | LMC、1S、GO | 未实现（`needs_token`） | 要先换取设备令牌 |
| Discovery+ | LMC、1S、GO | 未实现（`needs_token`） | 要设备 ID 与令牌 |
| Starz | LMC、1S、GO | 未实现（`needs_token`） | 要授权头 |
| MGM+ | LMC、1S、GO | 未实现（`needs_token`） | 先建会话再带会话令牌 |
| NBC TV | LMC、1S、GO | 未实现（`needs_token`） | 要授权头 |
| TLC GO | LMC、GO | 未实现（`needs_token`） | 要设备 ID 换取令牌 |
| encoreTVB | LMC、1S、GO | 未实现（`needs_token`） | 请求头带播放器 policy key |
| A&E TV | LMC、1S、GO | 未实现（`header_only`） | 地区来自应答 Cookie AETN-Country-Code |
| Crackle | LMC、1S | 未实现（`header_only`） | 地区来自应答头 x-crackle-region |
| FOX | LMC、1S、GO | 未实现（`weak_signal`） | 只看一个视频分片地址的 HTTP 状态码 |
| NFL+ | LMC、1S、GO | 未实现（`weak_signal`） | 只看是否跳到另一个产品站点 |
| FXNOW | LMC、1S、GO | 未实现（`weak_signal`） | 只有不可用字样，没有可用标记 |
| Shudder | LMC、1S、GO | 未实现（`weak_signal`） | 可用标记是页面里的 movies 字样，不可用标记包含泛泛的 not available |
| The CW | LMC、1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| KOCOWA | LMC、1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| DirecTV Stream | LMC、1S、GO | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| Crunchyroll | LMC、1S、GO | 未实现（`weak_signal`） | 用第三方地理服务判断，不是平台信号 |
| SonyLiv（美国） | LMC、GO | 未实现（`needs_token`） | 先从页面取 securityToken 再调接口 |
| Popcornflix | LMC、1S | 未实现（`weak_signal`） | 只看 HTTP 状态码 |
| SHOWTIME | 1S | 未实现（`discontinued`） | 已并入 Paramount+ |
| KBS America | 1S | 未实现（`weak_signal`） | LMC 里已注释停用；1S 的方法只看状态 |
| MathsSpot（Roblox） | LMC、1S | 未实现（`not_service`） | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），不是解锁判断；出口确认已经给出实际地区 |

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
- **切换的生效路径**：决定存在面板的解锁状态里（`unlock.Decisions`，键是规则 ID 或 `service-group:<id>`），只经现有的网关安装事务进入网关：默认由运营者安装（面板显示「待安装」，与内置规则相同）；打开 `auto_apply` 后，满足下节全部条件时由面板自己走同一个安装事务（见「自动安装决定」）。编译时 `planRules` 是规则目标、mark、地址集合名字的唯一来源：服务组的决定把它的每条规则改到被选成员**自己的** mark，地址集合、SmartDNS 的解析器组（被选成员的隧道解析器，不是国内解析器；该成员没有 IPv6 时照常不返回 AAAA、不声明 IPv6 集合）、嗅探服务的规则快照和目标文件都从这同一份计划生成。按规则 ID 写的决定对经过服务组的规则无效。`internal/compile/service_select_test.go` 编译切换前后的结果，检查每个被引用的集合都已声明、没有重复声明、清单里的地址集合都已声明，嗅探服务接受编译出的快照和目标文件，覆盖 IPv4-only 与双栈目标、嵌套出口、仅 TCP 的外部出口、地区组和单出口目标。
- **没有规则的服务只展示**：一个适配器既不是启用规则的探测项、也没有挂在服务组上时，只能在面板里对指定的出口或地区组手动探测，结果标「未入库：没有关联」，不会因此新增或修改任何规则或服务组。

### 自动安装决定（`settings.unlock_probe.auto_apply`，默认关闭）

关闭时（默认）一切与以前相同：决定改变后标「待安装」，等运营者安装。打开后，每当决定改变（服务组或内置规则换成员，或恢复后切回），面板在探测一轮结束、出口报告之后、以及每分钟的定时检查里评估一次；**下面全部满足**才安装，否则决定保持待安装，面板显示是哪一条没满足（`GET /api/unlock` 的 `auto_apply.last_check`）：

1. **安装前已同步**：记录了上一次网关安装用的决定；没有未完成的宿主事务；用这些决定重新编译当前拓扑，得到的网关文件与已安装的逐个哈希相同，并且与上一次应用的快照（全部节点的规范文本）完全相同。所以自动安装除了这个决定不会带上任何别的未审阅改动。升级后还没有经面板安装过一次的网关没有这条记录，要先人工安装一次。
2. **只改规则文件**：用新决定编译，与 (1) 相比只有网关节点的这些文件不同（`compile.DecisionFiles`，由 `TestDecisionChangeTouchesOnlyRuleFiles` 在各种示例拓扑上验证决定改变只碰它们）：`etc/nftables.d/meridian.nft`、`etc/smartdns/smartdns.conf`、`etc/meridian/rules/order.conf`、`etc/meridian/rules/decide.json`、`etc/meridian/sniff/targets.json`。任何别的文件、别的节点、文件增删（密钥、WireGuard 接口文件、单元文件都不在其中）都拒绝。
3. **频率**：距上一次自动安装至少 `auto_apply_min_gap_sec`（默认 600 秒，300–86400），最近 24 小时少于 `auto_apply_daily_max` 次（默认 6，1–48）；同样的决定自动安装失败后 1 小时内不再试（换了别的决定仍受最小间隔约束）。
4. **没有别的动作**：网关节点锁（预检、装机、撤回用的那把）空闲，宿主事务锁没被占用也没有未完成的事务；否则推迟到下一次评估，不排队。
5. **预检**：在节点锁内为这次的文件运行一次宿主预检，没有阻断项。

满足后调用与 `POST /api/apply`（`install: true`）同一个函数 `applyGateway`：同样的密钥处理（只复用已有密钥，不生成）、同样的事务（失败时补偿、补偿失败则保留事务日志等待恢复）、同样的 WSS 与秘密记录；编译结果必须与检查时的完全相同，否则不执行。每次自动安装记入 `unlock_auto_apply`（时间、触发、决定、结果、改动文件）和解锁历史（标「自动安装解锁决定」）。失败后决定保持待安装、不循环重试（见第 3 条的退避）。状态机的阈值和滞回不因此改变；恢复后切回走同一条路。

对流量的影响（按代码，**未在真实网关上验证**）：安装由 `meridian-up.sh` 用一个 nft 批次整体替换 `inet meridian` 表（先 `nft -c` 检查，失败则旧表不动），替换是原子的，但表里按域名学到的地址集合随之清空，客户端重新解析后才重新填上；分类是逐包按目的地址做的，但出口由中转源地址决定：网关上所有出口 mark 都查同一张表 102，枢纽按中转源地址选出口，而中转源地址转换（`transit_snat`，nat 钩子）只在连接的第一个包上决定并记在 conntrack 里，替换规则表不改已有的转换，所以按代码已建立的连接继续从原出口出去直到结束，切换只影响新连接；解析器配置变了时网关的 SmartDNS 会重启（缓存清空）；嗅探转发服务的单元文件不变时只重载，已转发的连接保持原路。

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

`internal/probe/adapters_test.go` 和 `adapters_more_test.go` 里，每个服务都有手写的应答样本（覆盖表新增的 27 个各覆盖：可用、不可用、地区不符（带地区的）、质询页、限流、改版），覆盖：地区受限、可用（有地区和无地区）、登录墙、反爬质询、跳到不可用页面、超时（在运行器层面测）、意外或改版的应答。另有测试检查每个适配器声明的 `returns` 与分类器实际能给出的结论完全一致。样本都标明是合成的，不含 Cookie、令牌或个人数据。它们只能证明分类器实现了本文写的规则，证明不了真实平台现在怎么应答。

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
11. 覆盖表新增的 27 个适配器：已对照固定提交的源码，但没有在真实平台上跑过；在可用和受限出口上各跑一次。U-NEXT 的请求是本项目自己缩短的 GraphQL 查询，平台是否接受要先核对。
12. 覆盖表本身：已按固定提交逐项读出；引用脚本之后增删的项目要在更新提交号时重读。
13. 服务组自动选择：在真实网关上把一个服务组设为自动，制造首选连续两次定时失败，确认面板给出待安装、安装后该服务组规则的流量和 DNS 都从被选出口出去（抓包，不经国内解析器），首选恢复 30 分钟后切回；所有候选失败时留在默认出口并告警。
