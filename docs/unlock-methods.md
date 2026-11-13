# 解锁探测方法与证据分级

本文是 `internal/probe/adapters.go` 里检测目录的说明。两边必须一致：改适配器就要改这里。

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

## 合成样本

`internal/probe/adapters_test.go` 里，每个服务都有手写的应答样本，覆盖：地区受限、可用（有地区和无地区）、登录墙、反爬质询、跳到不可用页面、超时（在运行器层面测）、意外或改版的应答。另有测试检查每个适配器声明的 `returns` 与分类器实际能给出的结论完全一致。样本都标明是合成的，不含 Cookie、令牌或个人数据。它们只能证明分类器实现了本文写的规则，证明不了真实平台现在怎么应答。

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
