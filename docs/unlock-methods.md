# 解锁探测方法与证据分级

本文是 `internal/probe/adapters.go`、`adapters_more.go` 里检测目录和 `coverage.go` 覆盖表的说明。两边必须一致：改适配器就要改这里（`TestCoverageTable` 检查覆盖表的每一项和每个适配器都出现在本文）。

## 验证状态（所有适配器都一样）

**每个适配器都是依据公开检测方法写成的，只用合成样本测试过。本项目没有拿任何一个去请求真实平台，真实平台上的表现要等人工核对。**

API 里对应 `validation: "synthetic_only"` 和 `validation_text`，出现在目录的每一项、每个探测项和结果矩阵的每一行。下文各节的“查阅日期”是读公开源码的日期，不代表那天验证过平台。

## 探测路径（没有变化）

- 探测在网关的 `meridian-host` 里执行。发出的每个连接都带所选出口的 fwmark，绑定该出口的中转地址，只用 `tcp4`/`tcp6` 中的一种，域名只经该出口的隧道解析器解析。每次连接前都检查内核路由，必须从 Meridian 隧道出去。
- 碰平台之前、跑完全部服务之后，都会用固定的 `https://www.cloudflare.com/cdn-cgi/trace` 确认出口：地址族、`loc=` 与出口地区、已知端点地址。出口没确认，就不给任何平台结论。
- 调用方只能从目录里选服务 id、选受管出口、选地址族，不能给 URL、主机、请求头、命令或路径。
- 每个检查都有固定的主机名单，只走 https/443。跳转只跟到名单内的主机，最多 4 跳；带 `NoRedirect` 的步骤直接拿跳转本身来判断。正文默认最多读 256 KiB（个别步骤见下面「正文读取有上限」的固定上限）。不用 Cookie 罐，也不带任何账号、令牌或 Cookie。额外请求头只能是 `User-Agent`、`Referer`、`Origin`、`Accept`、`Content-Type`，而且都是目录里写死的常量。
- 多步检查（目前只有巴哈姆特）只把前一步应答里的一个值带进下一步 URL 的查询串，这个值必须匹配 `^[A-Za-z0-9_-]{1,128}$`，不合格就停下，判为未知。
- 每个服务的所有步骤共用 20 秒预算。每个出口加地址族的探测里，同时最多跑 4 个服务。host agent 单次探测上限 3 分钟，面板单次调用上限 200 秒。

## 结果模型与证据分级

| category | grade | 含义 | 入库 |
|---|---|---|---|
| `unlocked` | `platform_signal` | 找到有文档依据的正面标记；带地区的适配器还要求地区与出口一致 | 成功 |
| `not_unlocked` | `platform_signal` | 找到有文档依据的负面标记，或平台报的目录地区与出口不一致 | 失败 |
| `network_ok` | `reachability_only` | 平台有应答，但这不是解锁判断 | 不是结论 → inconclusive |
| `unknown` | `unknown_response` | 有应答但不是已知标记：质询页、登录墙、同意页、限流、5xx、改版、未跟随的站外跳转、正文被截断（读到上限还有正文，已读部分没有判定标记） | 不是结论 → inconclusive |
| `failed` | `error` | 没有可判断的应答：超时、DNS 或传输错误、出口未确认或变化、agent 报告的出口不对 | 不是结论 → inconclusive |
| `not_applicable` | `not_applicable` | 没有探测：这个服务的公开检测方法只支持 IPv4，没有发出 IPv6 请求（`signal: family_not_supported`）。不是应答，面板显示「不适用 · 仅 IPv4」，不计入「未知」 | 不入库（`ingest: not_ingested:family_not_supported`） |

- `signal` 是判断所依据的标记代码，例如 `region_match`、`region_mismatch`、`available_marker`、`no_negative_marker`、`blocked_marker`、`blocked_403`、`anti_bot_challenge`、`login_required`、`consent_page`、`rate_limited`、`server_error`、`redirect_unlisted`、`unexpected_response`、`egress_changed`、`family_not_supported`。
- `grade` 由面板按 `probe.GradeOf(category)` 重新计算，不采信 agent 自己报的值。
- 正文读取有上限：默认每个应答只读前 256 KiB，个别检测步骤在固定目录里声明更大的上限（`Step.MaxBody`，硬上限 4 MiB；目前只有 YouTube Premium、Disney+ 和 Netflix 是 2 MiB）。读到上限还有正文时应答标为被截断；分类器因为没找到标记而给出的未知（`unexpected_response`）会在证据里写明「正文被截断：只读了前 N KiB（上限 M KiB），没有读到判定标记」，不再说页面可能改版。截断不会变成可用或不可用，也不改变质询、限流、同意页等结论；`signal` 仍是 `unexpected_response`，入库规则不变。
- 适配器里声明了 `returns`，即它允许给出的结论。超出声明的结论都会降为 `unknown`，在 agent 内部降一次，面板 `sanitizeReport` 里再降一次。所以只做到达性的适配器永远给不出 `unlocked` 或 `not_unlocked`。`not_applicable` 只在服务确实不支持该地址族时保留，否则同样降为 `unknown`。
- 有多个平台检查的服务，只由 `primary` 那一项决定服务结论；其余检查放在 `parts` 里展示，不入库。
- 入库规则（`probe.IngestVerdict`，全项目只有这一处）：`unlocked` 算成功，`not_unlocked` 算失败，其他都不算结论。一个服务在一次探测里所有地址族都没有结论时，按 `unlock.KindInconclusive` 交给 `unlock.Ingest`。这种结果不计入两次失败降级，不会开始恢复计时，也不会让出口变成已知可用的备选；它只会终止首选成员正在进行的恢复计时。这一点有回归测试覆盖。
- 出口上报的 `ai` 字段（curl 的 HTTP 状态码）同样只算到达性：照常记入历史并带说明，但不推动状态机。

## 能力声明一览

| 服务 id | 名称 | 能力 | 只发 IPv4 | 检查的平台（主 / 参考） |
|---|---|---|---|---|
| auto-netflix | Netflix | region_verdict | 否 | Netflix |
| auto-disney | Disney+ | region_verdict | 否 | Disney+ |
| auto-bahamut | 巴哈姆特動畫瘋 | region_verdict | 是 | 動畫瘋 |
| auto-kktv | KKTV | region_verdict | 是 | KKTV |
| auto-linetv | LINE TV | verdict | 是 | LINE TV |
| auto-hami | Hami Video | verdict | 是 | Hami Video |
| auto-abema | Abema | region_verdict | 是 | ABEMA；参考：Niconico；不支持：TVer |
| auto-mytvsuper | MyTV SUPER | region_verdict | 是 | MyTV SUPER；不支持：ViuTV |
| auto-viu | Viu | region_verdict | 是 | Viu |
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

「仅 jp」等是适配器声明的 `regions`：它的结论只能说明出口在不在这个地区可用；放到别的地区的出口上只会得到「地区不符 / 不可用」。没有声明的适配器对任何地区都给出结论（带地区的适配器仍要求平台报的地区与出口一致）。

**AI 服务不探测**（2026-11-17 起）：OpenAI / ChatGPT、Claude、Gemini、Copilot、Perplexity、Grok、Meta AI、Coze 这 8 个适配器的代码保留在 `allAdapters` 里，但不注册到目录（`probe.Catalog` 只含流媒体，停用的在 `probe.Disabled`）：「全部探测」和各段探测都不会向任何出口发 AI 请求，矩阵、推荐、确认和手动都没有 AI 行；升级前保存的 AI 结果读入时忽略（`probe.IsAI`），不报错也不显示。AI 规则保持原目标，内置的 `auto-openai`、`auto-anthropic`、`auto-gemini`、`auto-copilot`、`auto-perplexity`、`auto-grok` 默认指向美国地区组（`us`）；解锁页从不改动 AI 规则（属于停用 AI 适配器的规则不算任何流媒体服务的规则）。下文 AI 各节只是保留的方法记录。表中现有 34 个适配器。

**最初 14 个（其中 6 个 AI 已停用；不含 2026-11-17 从 MyTV SUPER 拆出的 auto-viu）之后的 27 个适配器是覆盖表新增的（其中 Meta AI、Coze 已停用）**：2026-11-14 对照下文「各服务」列出的三个来源（固定到完整提交号）逐项核对了请求地址、方法、关键请求头和请求体、成功 / 失败 / 地区标记，来源一栏的 `checked` 是对照日期。它们和其余适配器一样只在合成样本上测过，没有请求过真实平台。它们不绑定任何内置规则：只有指向地区组的规则用到它们时（规则 ID 与适配器同名），结果才参与自动选择；解锁页的推荐与采用对所有可探测的服务都可用。

流媒体的地区不一致按 `not_unlocked` 处理（`region_mismatch`）。

## 各服务

各节引用的公开来源（最初的 14 个查阅日期 2026-11-13；覆盖表与新增适配器 2026-11-14 再次只读拉取，同一提交）：

- **LMC**：lmc999/RegionRestrictionCheck `check.sh`，提交 `b6d4a6f9a87fc6eae6d3e62d0092ececcec8e844`（2025-12-08），AGPL-3.0。<https://github.com/lmc999/RegionRestrictionCheck>
- **1S**：1-stream/RegionRestrictionCheck `check.sh`，提交 `ef841d0a2910a44a6ca565e3a03de0f2282d83b3`（2026-10-06），AGPL-3.0。<https://github.com/1-stream/RegionRestrictionCheck>
- **GO**：HsukqiLee/MediaUnlockTest `pkg/providers/*.go`（清单在 `lists.go`），提交 `dc6c6e6cc490315824d485c668f059535e97ea94`（2026-10-14），是 nkeonkeo/MediaUnlockTest 仍在维护的分支；仓库里没有许可证文件。<https://github.com/HsukqiLee/MediaUnlockTest>

只读取了源码，没有复制代码：本项目的请求地址、固定请求体和应答标记是公开方法的事实，判断逻辑和代码是本项目自己写的（`internal/probe/adapters_more.go`、`adapters_new.go`）。机器可读的提交号在 `probe.SourceCommits`。

### Netflix（auto-netflix）

- 请求：`GET https://www.netflix.com/title/81280792`。主机：`www.netflix.com`、`netflix.com`。
- 不可用：403（拒绝该 IP）；404（只开放自制剧，或该地区没上线）。
- 可用：200，并且地区与出口一致。地区取自 URL 的 `/xx-yy/` 国家前缀（非美国出口上重定向到 `/hk-en/` 这类路径）；没有国家前缀（美国站点是默认站点，没有前缀）时取页面内嵌数据里 `"requestCountry":{…"id":"XX"…}` 的 `id`。不一致按地区不符为不可用。
- 前缀与 `requestCountry` 的关系：只有语言的前缀（`/ja`、`/en`、`/en-gb`）不是地区；两者同时存在必须一致，不一致 = 冲突 = 未知；页面里有取值不同的多处 `requestCountry` = 冲突 = 未知；只有前缀或只有 `requestCountry` 时各自决定。403/404 的处理不变。
- 未知：200 但没有可靠地区标记、冲突、登录墙、质询页、5xx、正文超过读取上限且没有标记（证据写明被截断）。
- 来源：LMC `MediaUnlockTest_Netflix`（同一个自制剧标题），加上本项目原有的规则。
- 判断：自制剧标题页 81280792：403 = 拒绝该 IP；404 = 标题不可用（仅自制剧或未开通）；200 时取目录地区：URL 的 /xx-yy/ 国家前缀（非美国出口上重定向到 /hk-en/ 这类路径；只有语言的 /ja、/en 不算地区），没有国家前缀时读页面内嵌数据里访问者所在国家的 "requestCountry":{…"id":"XX"…}（只认 requestCountry 对象自己的 id，相距有界）；地区必须与出口地区一致；前缀和 requestCountry 同时存在但不一致、或页面里有多处取值不同的 requestCountry = 冲突 = 未知；两者都没有 = 未知；不读 countryCode，也不读 preferredLocale / locale / geo 的 supportedLocales 里的国家（那是偏好或列表，不是访问者所在地）。这一步的正文读取上限是 2 MiB（默认是 256 KiB）；读到上限还有正文且没有标记时仍是未知，证据写明正文被截断和读了多少
- 限制：公开脚本带浏览器 Cookie 并比较自制剧与非自制剧两个标题，本适配器不带 Cookie、只看一个自制剧标题，所以“仅自制剧”与“完全解锁”不区分；页面结构变化会落到未知；2026-11-15 在真实平台上的观察（只是观察）：香港出口上整页约 690 KB，页面内嵌数据里 "requestCountry":{"supportedLocales":["zh","en"],"id":"HK",…} 在约 454,000 字节处（三处相邻），旁边还有 geo.supportedLocales、preferredLocale（id 为 en-HK）和 "currentCountry":null，页面里没有 countryCode；香港、台湾出口靠 URL 前缀（/hk-en/、/tw-en/、/jp-en/ 这类重定向）判定，已在真实出口上用过；美国出口没有重定向也没有前缀，此前报未知（只读了前 256 KiB，正文被截断），所以这一步单独放宽到 2 MiB（硬上限 4 MiB 以内，其他检测项不变），代价有界：每个出口每个地址族一次请求，最多读 2 MiB，超时不变，页面再变大、标记落到上限之外时报未知（正文被截断）；已移除通用 countryCode 作为地区依据（它在页面里可能有别的含义）；没有直接观察过美国出口上 requestCountry 的结构，美国这一情形的修改后尚未在真实平台上复测，仍标为未对真实平台验证
- 保留与移除：保留 403 / 404 和 URL 国家前缀（真实出口上已用过）。移除通用 `countryCode` 作为地区或可用性依据：它在页面里可能有别的含义（例如电话区号表、内容的出品国），而 2026-11-15 的观察是页面里没有这个键；`preferredLocale`、`locale`、`geo.supportedLocales` 里的国家字段是偏好或列表，不是访问者所在地，也不使用；只有语言的前缀（`/ja`）不再当地区。
- 观察（2026-11-15，真实平台，只是观察，本项目的测试没有请求平台）：香港出口整页约 690 KB，`requestCountry` 在约 454,000 字节处（三处相邻），取值与出口一致；香港、台湾出口靠 URL 前缀判定（`/hk-en/`、`/tw-en/`），已在真实出口上用过；美国出口没有重定向也没有前缀，此前返回未知（正文被截断，只读了前 256 KiB）。美国出口上 `requestCountry` 的结构没有直接观察过。
- 资源成本（有界）：这一步的读取上限固定为 2 MiB（硬上限 4 MiB 以内，其他检测项不变）；每个出口每个地址族一次请求，最多读 2 MiB，超时不变。标记落到上限之外时，结果是未知并写明被截断。
- 状态：这次修改**尚未在真实平台上复测，美国出口的情形未验证**；合成应答测试（含经本地 TLS 假平台的完整读取路径）通过，不代替真实平台。

### Disney+（auto-disney）

- 请求：`GET https://www.disneyplus.com/`。主机：`www.disneyplus.com`、`disneyplus.com`。
- 不可用：跳到含 `unavailable` 或 `preview` 的路径；403。这两条沿用公开脚本里的跳转判断。
- 可用：200，并且页面内嵌数据里的 `"location":"XX"`（访问者所在地，两个字母，紧跟 `"pageId"` 键）与出口地区一致。不一致按地区不符为不可用。
- 未知：没有 `location`（只有固定的 `region`，或什么都没有）；页面里有取值不同的多处 `location`（冲突）；跳到名单外的主机；正文超过读取上限且没有标记（证据写明被截断）。
- 判断：首页：跳到含 unavailable/preview 的路径或 403 = 不可用（公开脚本里的跳转判断）；200 时只读页面内嵌数据里表示访问者所在地的 "location":"XX"（XX 是两个字母，且紧跟 "pageId" 键），必须与出口地区一致；页面里有多处且取值不同 = 冲突 = 未知；没有 location（只有固定的 region，或什么都没有）= 未知；不读 countryCode / region，也不用 URL 的语言-地区前缀。这一步的正文读取上限是 2 MiB（默认是 256 KiB）；读到上限还有正文且没有标记时仍是未知，证据写明正文被截断和读了多少
- 限制：公开脚本的完整方法要用 bamgrid 设备令牌（应用令牌）调 GraphQL，本项目不使用任何令牌，只用首页跳转与页面内嵌的 location；location 这一键不在公开脚本里，是 2026-11-15 在真实平台上的观察（首页约 1.95 MB，"location":"XX" 在约 860 KB 处，与实际出口地区一致，后面紧跟 "pageId":"welcome","region":"us"；这个 region 是固定值，从香港访问时也是 us，页面里没有 countryCode），所以只认 "location" 紧跟 "pageId" 的写法，键的顺序或名字一变就是未知，不会误判；URL 语言-地区前缀不在公开脚本的方法里，不可靠，已不再使用；上限 2 MiB 够到约 860 KB 处的标记，代价有界：每个出口每个地址族一次请求，最多读 2 MiB，超时不变；页面再变大、标记落到上限之外时报未知（正文被截断）；修改后尚未在真实平台上复测，仍标为未对真实平台验证
- 保留与移除：保留“跳到 unavailable/preview”和 403，因为它们就是引用的公开脚本（LMC `MediaUnlockTest_DisneyPlus`）里的判断。移除 `countryCode` / `region` 作为可用性或地区依据：2026-11-15 的观察是页面里没有 `countryCode`，`region` 是固定值（从香港访问时也是 `us`），只调大读取上限而沿用旧规则会把所有非美国出口误判为地区不符。同时移除 URL `/语言-地区` 前缀：公开脚本没有用它，它也可能只是语言偏好，没有访问者所在地的含义。
- 防误读：`location` 键在 2 MB 的页面里可能出现在别的含义上，所以要求值是两个字母、且紧跟 `"pageId"` 键（观察到的形状是 `…"language":"en","location":"HK","pageId":"welcome","region":"us","remoteConfig":…`）；两处以上取值不同算冲突，报未知。局限：键的顺序或名字一变就退到未知（不会误判），要人工重新核对；两个字母的取值不校验是否真实国家码。
- 观察（2026-11-15，真实平台，只是观察，本项目的测试没有请求平台）：首页约 1.95 MB，`location` 在约 860 KB 处，与实际出口地区一致；默认的 256 KiB 读不到它（此前的未知是正文被截断，证据写“正文被截断：只读了前 256 KiB”）。
- 资源成本（有界）：这一步的读取上限固定为 2 MiB（硬上限 4 MiB 以内，其他检测项仍是 256 KiB）；每个出口每个地址族一次请求，最多读 2 MiB，超时不变。页面再变大、标记落到上限之外时，结果是未知并写明被截断。
- 来源：LMC `MediaUnlockTest_DisneyPlus`，只用了它“最终 URL 含 preview 或 unavailable 就是 No”这一部分；`location` 键是上面的观察，不来自该脚本。
- 状态：这次修改后**尚未在真实平台上复测**，仍标为未对真实平台验证。

### OpenAI / ChatGPT（auto-openai）

- 已停用：不注册到目录，不探测（方法记录保留）。

- 主检查：`GET https://api.openai.com/compliance/cookie_requirements`，带固定的 `Origin`/`Referer: https://platform.openai.com`。主机：`api.openai.com`（检测接口，和网页站点 chatgpt.com 是不同的主机）。
  - 不可用：应答含 `unsupported_country`。
  - 可用：应答是 JSON（非 3xx、非 5xx），并且没有这个标记。这就是公开脚本的“没有负面标记即可用”，不代表账号能用。
  - 未知：非 JSON、质询页、5xx。
- 参考检查（不入库）：`GET https://ios.chat.openai.com/`。含 `VPN` 算 iOS 入口拒绝；否则算没有负面标记。
- 来源：LMC `WebTest_OpenAI`。
- 限制：不带 LMC 的 `authorization: Bearer null` 头；不判断地区。

### Claude（auto-anthropic）

- 已停用：不注册到目录，不探测（方法记录保留）。

- 请求：`GET https://claude.ai/`。主机：`claude.ai`、`www.claude.ai`。去 `www.anthropic.com` 的跳转不跟，直接拿跳转地址来判断。
- 不可用：跳到 `app-unavailable-in-region`。
- 可用：最终停在 claude.ai，状态码 2xx。
- 未知：质询页、非质询的 403、其他跳转。
- 来源：LMC `WebTest_Claude`（看最终 URL）。
- 限制：Cloudflare 质询很常见，一律算未知；不是账号判断。

### Gemini（auto-gemini）

- 已停用：不注册到目录，不探测（方法记录保留）。

- 请求：`GET https://gemini.google.com/`。主机：`gemini.google.com`。
- 可用：200 且页面数据含 `45631641,null,true`（也认页面脚本里转义成 `\"45631641\",null,true` 的写法）。如果有 `,2,1,200,"XXX"`（引号可带转义），取三字母国家码，只作展示。
- 正文读到 2 MiB（页面在 1 MB 以上，默认 256 KiB 可能读不到标记）；读满仍无标记时结论注明“正文被截断”。
- 不可用：非质询的 403（来自 GO `Gemini.go`）。
- 未知：跳到 `consent.google.com` 同意页；200 但没有标记（公开脚本算不可用，本项目无法区分“不支持该地区”和改版，记为未知并写明原因）；其他。
- 2026-11-16 修正：此前各地区出口都得到 unexpected，可能原因是标记位于默认读取上限之后或以转义形式出现；已放宽匹配并加大读取上限，仍需真实复测。
- 来源：LMC `WebTest_Gemini`；GO `Gemini.go`。
- 限制：这个标记是不透明的页面数据，随时可能改。LMC 把“没有标记”算作 No，本项目算未知，避免改版造成误降级。GO 用写死的 Cookie 绕过同意页，本项目不带 Cookie，所以欧盟等地区多半是未知。

### Microsoft Copilot（auto-copilot）

- 已停用：不注册到目录，不探测（方法记录保留）。

- 请求：`GET https://copilot.microsoft.com/c/api/user?api-version=2`，不跟随跳转。主机：`copilot.microsoft.com`。
- 不可用：302 跳回 `/`；非质询的 403。
- 可用：200 且 JSON 有两位的 `regionCode`（地区只作展示）。
- 未知：跳到其他地方（如登录）、200 但没有 `regionCode`。
- 来源：GO `Copilot.go`（LMC 没有 Copilot；1S 用的 `turing/conversation` 接口看起来已过时，没有采用）。
- 限制：只有一个公开实现可参照，接口没有公开文档。

### Perplexity（auto-perplexity）— 只做到达性

- 已停用：不注册到目录，不探测（方法记录保留）。

- 请求：`GET https://www.perplexity.ai/`。主机：`www.perplexity.ai`、`perplexity.ai`。
- 结果：非质询、非 5xx 的应答都算 `network_ok`；质询、限流、5xx 算未知。
- 为什么不给平台结论：唯一的公开方法（GO `Perplexity.go`）只是拿 cdn-cgi/trace 的 `loc` 去对照一张写死的受限国家表（CN、RU、IR、KP、CU、SY）。这张表是假设，不是平台信号，本项目出口检查已经有 `loc`。

### Grok（auto-grok）— 只做到达性

- 已停用：不注册到目录，不探测（方法记录保留）。

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

### Abema（auto-abema）— 只发 IPv4

- 组合规则：ABEMA 检查决定服务结论。Niconico 只作参考，不入库，因为这条规则的域名只有 abema；Niconico 的域名和名字也不算这个服务的（采用不会改 Niconico 规则）。TVer 不检查。服务名只写 Abema，因为结论只覆盖 ABEMA。
- ABEMA：`GET https://api.abema.io/v1/ip/check?device=android`，带固定的 Android `User-Agent`。主机：`api.abema.io`（检测接口，和站点 abema.tv 是不同主机）。
  - `isoCountryCode = "JP"` 算可用（jp）。
  - 其他国家码算不可用（“Oversea Only”，地区记为该国家码）。
  - 非质询的 403 算不可用。出口本身在日本仍得到 403 时，证据注明“多半是机房/VPN 地址被 ABEMA 封锁”（公开脚本不区分机房封锁与方法错误，本项目也无法确认，结论仍是不可用）。
  - 没有这个字段算未知。
  - 来源：LMC `MediaUnlockTest_AbemaTV`；GO `Abema.go`。
- Niconico（参考）：`GET https://www.nicovideo.jp/watch/so40278367`。主机：`www.nicovideo.jp`。页面含「同じ地域」算不可用；200 且没有这句算可用。来源：GO `NicoNico.go`。
- TVer：不支持。公开方法要么注册平台用户再走五跳令牌链（LMC 的 Brightcove 方法），要么带播放器的 API key 请求头（1S 和 GO 的 streaks 方法）。这两种都要把令牌或 key 当作请求参数，本项目不这样做。

### MyTV SUPER（auto-mytvsuper）— 只发 IPv4

- 组合规则：MyTV SUPER 检查决定服务结论。Viu 是独立的服务（`auto-viu`，见下节），MyTV SUPER 的结论不含 Viu，Viu 的域名和名字也不算这个服务的（采用不会改 Viu 规则）。ViuTV 不检查。
- MyTV SUPER：`GET https://www.mytvsuper.com/api/auth/getSession/self/`。主机：`www.mytvsuper.com`。
  - 以 `region` 为准：等于 1 算可用（hk），其他数字算不可用（blocked_marker）。`country_code` 只写进证据展示，不作为结论地区（2026-11-16 修正：日本/新加坡/美国出口上 `country_code` 给出与出口不符的地区，之前被当成平台地区）。
  - 没有 `region` 时才看 `country_code`：`HK` 算可用（hk），其他算不可用（地区不一致）。
  - 非质询的 403 算不可用。
  - 两个字段都没有算未知。
  - 来源：LMC `MediaUnlockTest_MyTVSuper`（看 country_code）；GO `MyTVSuper.go` 和 1S（看 region == 1）。
- ViuTV：不支持。公开方法要 POST 一段写死的设备标识（`deviceId`）和调用参考号，本项目不发送任何设备标识。

### Viu（auto-viu）— 只发 IPv4

- 香港服务（`Regions: hk`），只在香港地区组的出口上探测，结果独立入库、独立推荐和采用。2026-11-17 起从 MyTV SUPER 拆出：之前它是 MyTV SUPER 里的参考检查，不入库。
- Viu：`GET https://www.viu.com/`，不跟随跳转。主机：`www.viu.com`。跳转路径 `/ott/<地区>/…` 的地区与出口一致 → 可用，`/ott/no-service` → 不可用；不跳转或路径认不出 → 未知（解锁页「未测到」）。来源：GO `Viu.go`；LMC `MediaUnlockTest_ViuCom`。
- 规则归属只认 `viu.com` 及其子域、名字里有 `viu` 这个词的 geosite / 规则集 / 关键字（`ViuTV` 不算），以及规则 ID `auto-viu`。

## 覆盖表新增的适配器

以下各节由 `internal/probe` 的目录生成，与代码一致。和公开方法有意不同的地方写在「限制」里（例如不带 Cookie、对某个标记读得更严）。

### YouTube Premium（youtube-premium）

- 请求：GET `https://www.youtube.com/premium`，带固定的同意 Cookie `SOCS=…`（来源公开方法里的固定值，不含身份信息）。主机：`www.youtube.com`、`youtube.com`。
- 判断：Premium 介绍页（请求带公开方法里的固定同意 Cookie SOCS 和英文 Accept-Language）：先看同意页——跳到 consent.youtube.com / consent.google.com，或页面是指向它们的同意表单（Before you continue to YouTube）= 未知·同意页，即使页面里有 ad-free 也不算可用；再看引用 www.google.cn = 不可用（cn）；含 Premium is not available in your country（不分大小写）= 不可用；含 ad-free（不分大小写）= 可用，INNERTUBE_CONTEXT_GL 给出的地区只作展示；其他 = 未知。这一步的正文读取上限是 2 MiB（默认是 256 KiB）；读到上限还有正文且没有任何判定标记时仍是未知，证据写明正文被截断和读了多少
- 限制：只带来源里公开的固定同意值（SOCS），不带来源里同一请求的访客 / 会话标识 Cookie（YSC、VISITOR_INFO1_LIVE、VISITOR_PRIVACY_METADATA、__Secure-YEC、__Secure-BUCKET、PREF：那是某个浏览器的标识，不属于本项目）；Cookie 只发给 www.youtube.com / youtube.com，同意页主机不在固定主机里，不跟随；同意值被平台拒绝时仍会得到同意页，记为未知·同意页；只读未登录的介绍页，不是账号判断；2026-11-15 在真实平台上看到介绍页约 1 MB，ad-free 第一次出现在约 850 KB 处（页面最后五分之一，后面还有二十多处），INNERTUBE_CONTEXT_GL 在约 60 KB 处，带不带同意 Cookie 都一样——此前各出口的未知是正文只读了 256 KiB、被截断造成的，不是页面改版，也与同意 Cookie 无关，所以这一步单独放宽到 2 MiB；代价有界：每个出口每个地址族一次请求，最多读 2 MiB，超时不变；页面再变大超过上限时报未知（正文被截断）；2026-11-15 用此 Cookie 和 2 MiB 上限在真实平台上复测，六个出口判为可用且地区正确（不可用地区的应答仍未核实）
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_YouTube_Premium（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/YouTube.go YoutubeRegion（成功标记不同：看购买按钮或价格字样，未采用）（dc6c6e6）（对照日期 2026-11-15）

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
- 请求头：与 LMC 一样带 `Content-Type: application/json`（此前缺失）。
- 判断：播放开始接口（固定的匿名请求体，与 LMC 相同）：应答含 FOREIGN = 平台判为海外访问，不可用（FOREIGN 不带国家；出口本身在日本时记 `blocked_marker` 并注明多半是机房/VPN 地址被当成海外，而不是 `region_mismatch`）；含 UNAUTHORIZED = 通过地区检查、只差登录 → 可用（日本）；其他 = 未知
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
- 请求：按公开方法发送网页播放器的 `cosmo_getPlaylistUrl` 查询（含 result / resultStatus 等字段），带 `Origin`/`Referer: https://video.unext.jp`。
- 限制：2026-11-16 修正：此前自写的只含 resultStatus 的短查询在各出口都没拿到 resultStatus（unexpected）；现改回公开查询；只回 GraphQL `errors` 时记未知并附错误信息；作品下架后会变成未知；仍需真实复测
- 来源：lmc999/RegionRestrictionCheck check.sh MediaUnlockTest_unext（b6d4a6f）；HsukqiLee/MediaUnlockTest pkg/providers/UNext.go（dc6c6e6）（对照日期 2026-11-14）

### DMM（地区判定接口）（dmm）

- 请求：POST（固定请求体） `https://api.tv.dmm.com/graphql`。主机：`api.tv.dmm.com`。
- 判断：匿名 GraphQL 查询 client.isForeignAccess（按 JSON 解析，容忍空格）：false = 可用（日本），true = 海外访问，不可用；出口本身在日本却得到 true 时记 `blocked_marker` 并注明多半是机房/VPN 地址被当成海外（平台不报国家，不是地区不一致）；只回 `errors` = 未知并附错误信息；其他 = 未知
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

- 已停用：不注册到目录，不探测（方法记录保留）。

- 请求：GET `https://www.meta.ai/`。主机：`www.meta.ai`。
- 判断：首页：含 AbraGeoBlockedErrorRoot = 地区封锁，不可用；含 KadabraRootContainer 或 AbraHomeRootConversationQuery = 可用（"code":"xx_YY" 的 YY 只作展示）；跳到登录页 = 未知（login_required）；都没有 = 未知并写明缺哪些标记
- 限制：标记是页面组件名，改版会变成未知；正文读到 2 MiB（2026-11-16：此前各出口都是 unexpected，可能是标记在默认 256 KiB 之后）；不是账号判断
- 来源：lmc999/RegionRestrictionCheck check.sh WebTest_MetaAI（b6d4a6f）（对照日期 2026-11-14）

### Coze（coze）

- 已停用：不注册到目录，不探测（方法记录保留）。

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
| `not_service` | 不是流媒体或 AI 服务（地区识别、IP 信誉、CDN 位置、游戏、论坛），出口确认已经给出实际地区（AI 服务本身也不探测） |
| `not_https` | 公开方法用明文 HTTP 或非 443 端口，探测只走 https/443 |
| `discontinued` | 平台已停止或并入别的服务 |
| `fake_login` | 公开方法提交伪造的登录表单看错误码，本项目不提交任何登录请求 |
| `header_only` | 判断依据在应答头或 Set-Cookie 里，探测不把应答头和 Cookie 交给分类器 |
| `transport` | 公开方法降低 TLS 要求或直连写死的 IP 并改写 Host 头 |

各地区实现数（含参考检查）：国际（多地区） 27 项中 7 项；香港 10 项中 4 项；台湾 13 项中 7 项；日本 27 项中 9 项；新加坡（含东南亚通用项） 6 项中 1 项；美国 34 项中 9 项，共 117 项中 37 项。脚本的 AI 清单（14 项）不再列入：AI 服务不探测。Niconico 是参考检查，不入库。新加坡出口上能用的还有国际一节的 Netflix、Disney+、Prime Video、YouTube Premium、DAZN、TVBAnywhere+、NBA TV。

### 国际（多地区）

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| Netflix | LMC、1S、GO | 已实现：`auto-netflix` |  |
| Disney+ | LMC、1S、GO | 已实现：`auto-disney` |  |
| YouTube Premium | LMC、1S、GO | 已实现：`youtube-premium` |  |
| Amazon Prime Video | LMC、1S、GO | 已实现：`primevideo` |  |
| DAZN | LMC、1S、GO | 已实现：`dazn` |  |
| TVBAnywhere+ | LMC、1S、GO | 已实现：`tvbanywhere` |  |
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

### 香港

| 项目 | 脚本 | 结果 | 说明 |
|---|---|---|---|
| MyTV SUPER | LMC、1S、GO | 已实现：`auto-mytvsuper` |  |
| Viu | LMC、1S、GO | 已实现：`auto-viu` |  |
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

## 按地区探测、推荐与采用

解锁页（`GET /api/unlock/matrix`，`internal/api/unlock_matrix.go`）按地区分段，每段是一张「服务 × 出口」表。

**服务的地区写在服务定义里**（`internal/probe/scope.go`）：

- **全球服务**：覆盖表分区是 `international` 的适配器，只有国际流媒体（Netflix、Disney+、YouTube Premium、Prime Video、DAZN、TVBAnywhere+、NBA TV）。在**所有**出口上探测。AI 服务不探测（见「能力声明一览」）。
- **地区服务**：探测地区取适配器的 `Regions`；没有声明时取它的分区（`hk` / `tw` / `jp` / `sg` / `us`）。只在这些地区的出口上探测，**从不**在别的地区的出口上探测。一个服务可以属于多个地区：巴哈姆特動畫瘋是 `tw`、`hk`，B-Global 是 `sg`、`my`、`th`、`id`、`vn`、`ph`；它出现在每个所属地区的分段里。BritBox、Acorn TV、fuboTV、Tubi、Pluto TV、AMC+ 用的是美国站的检测方法，归 `us`。

**出口的地区来自它所在的地区组**：地区组的 `region` 字段（已有字段，按 `unlock.NormRegion` 归一：`HK` / `hongkong` / `Hong Kong` → `hk`，`Taiwan` → `tw`，`Japan` → `jp`，`Singapore` → `sg`，`USA` / `United States` → `us`，其余小写去空格，例如 `my`、`gb`）。一个出口在多个地区组里时，属于这些组的所有地区（香港机房组和香港住宅组都是 `hk`；同时在 `hk` 和 `jp` 组里的出口两边的地区服务都会测）。不在任何带 `region` 的地区组里的出口只测全球服务。

**分段**：「全球」（所有出口）在前，然后是香港、台湾、日本、美国、新加坡、马来西亚，其余地区按代码排序。没有出口、或没有可探测服务的地区不显示。

**探测**：页头「全部探测」发 `POST /api/unlock/run {"scope":"all"}`，每段的「探测」发 `{"scope":"<地区代码>"}`（全球段是 `"global"`）。面板按上面的规则在服务端选出口和服务（`scopedTargets`），`scope` 不能和 `services` / `exits` / `groups` 一起用；地址族、预算外的跳过、只发 IPv4 等规则与以前相同。每轮上限 1024 项。

**格子**（两个地址族中较好的那个，过了结果有效期的不算）：

| 显示 | 来自 | 说明 |
|---|---|---|
| 解锁（+ 平台读出的地区代码） | `unlocked` | 有平台的正面标记 |
| 仅本地 | `network_ok` | 只连得上，只做到达性的方法给不出解锁结论 |
| 不可用 | `not_unlocked` | 有平台的负面标记 |
| 未测到 | `failed` / `unknown` | 出口地址核对失败、超时、应答无法识别；悬停或聚焦看原因 |
| 未测 | 没有结果，或结果的出口身份与出口当前的不一致 | 见下文「出口身份」 |

**推荐**：只从「解锁」的格子里选，其他结果（仅本地、未测到）不作推荐。候选出口要在某个地区组的有效顺序里（规则要求住宅 / IPv6 时只看满足要求的组；地区服务只看本地区的组）。排序：全球服务优先选在它的规则**当前指向的地区组**里的出口；然后按稳定性（地区组健康检查的失败次数、出口离线、另一个地址族是否失败、成功的地址族数）；然后按这次探测的耗时；最后按出口 ID。

**当前走向**：每行在推荐之前单独一栏「当前」，显示服务规则现在实际指向哪里（矩阵 `current`）：指向地区组时是「<组名> · <组当前首选出口>」（例如「香港住宅 · hk-2」），钉死出口时是「<节点>（钉死）」。保存后矩阵与共享拓扑一起刷新，分流规则页同一条规则的目标随之显示新的组或钉死的节点（两页读同一份拓扑；回归 `TestUnlockManualGroup` / `TestUnlockManualPin` 读 `GET /api/topology`，前端 `unlock_manual.test.tsx` 保存后切到分流页核对）。

**确认与手动**：推荐栏后面是「确认」（采用推荐出口）和「手动」。没有推荐只有「手动」，在用的显示「在用」并保留「手动」，没有规则的服务没有操作。手动的选择器分两组：

- **出口组**（矩阵 `groups`）：该服务探测范围内的地区组（全球服务是所有地区组，地区服务是本地区的组），组里至少有一个该服务探测范围内的出口，并满足规则硬约束（住宅 → 组 `require_residential`，IPv6 → 组 `require_v6`）；每项显示组名和组当前首选出口。
- **具体节点**：该行的出口（全球服务是所有出口，地区服务是本地区的出口），解锁的排在前面，每项带结果词，其余照实显示不可用 / 仅本地 / 未测到 / 未测。

三条保存路径都发 `POST /api/unlock/adopt`：

- 确认：`{"service","exit"}`，`exit` 必须仍是当前推荐。规则指向推荐出口所在的地区组，并让该组优先这个出口（下文 1–2）。
- 手动选组：`{"service","group","manual":true,"identity"}`。组必须存在且在范围内、含范围内出口（否则 400），满足硬约束（否则 409）；`identity` 必须等于矩阵给出的组摘要（`groups[].identity`：组内范围内成员出口身份摘要的摘要，`gv2:` 前缀；任何成员身份变了、或有成员没有探测身份，都是 409）——校验依据的成员身份在保存前变化同样被拒绝。服务规则 `target_group` 设为该组、清空 `target_exit`；**不改该组**的成员顺序、模式或首选，由组自己按健康选择。
- 手动选节点：`{"service","exit","manual":true,"identity"}`。`exit` 必须在该服务的探测范围内（否则 400），`identity` 必须等于矩阵给出的出口当前身份摘要（`exits[].identity`；摘要变了或出口没有探测身份都是 409），出口本身满足硬约束（住宅 → 出口 `residential`，IPv6 → 出口 `egress_v6`；否则 409）。服务规则改为**钉死**这个出口（`target_exit` = 出口、清空 `target_group`，沿用规则钉死出口的语义与校验），不改任何地区组。**不要求解锁**：未解锁的出口也能选（运营者的明确选择），结果格照实显示原结果。

两种手动都只改服务规则，预览的 `other_rules` 为 0。

三者共用预览（`preview: true`：`kind`、`service_rules`、`other_rules`）、检查和保存：服务端在保存事务里（先取资源锁 `resMu`、再取面板状态锁、再取拓扑存储锁，与其他写入相同的顺序）读当前配置、受管服务器、探测结果、地区组运行状态和出口身份；受管服务器的地址 / 端口只在 `resMu` 下修改，所以采用核对的服务器就是写入规则时生效的那份，采用期间改服务器会等采用结束（之后改了则推荐失效），重新算一次（确认：推荐与请求的出口不一致，包括推荐因出口身份变化而消失；手动：范围、身份、硬约束），不通过就拒绝（409 / 400），规则和地区组都不改。确认通过时：

1. **属于这个服务的规则**（启用、指向地区组或单个出口；直连、拒绝和 QUIC 规则不动）：规则 ID 就是适配器 ID；或域名 / 后缀规则的值、规则的 `domains` 等于或位于服务的域名之下（**主检查**探测主机的可注册域名——参考检查（只展示、不入库）的主机不算，2026-11-17 修正：之前 MyTV SUPER 的结论会让采用改写 Viu 规则、Abema 的会改写 Niconico 规则——加上少量已知域名，例如 Netflix 的 `nflxvideo.net`；`google.com`、`microsoft.com`、`hinet.net` 这类多个服务共用的域名只认探测主机本身）；或关键字 / geosite / 规则集的名字、规则的 `geosite` / `rule_set` 里有服务自己平台名的关键字（按词比较，例如 `netflix`、`openai`、`chatgpt`、`kktv`、`viu`；每个服务只有自己的平台名，没有 `niconico` 这类参考平台名）。导入时的 mihomo 策略组标签（`mihomo_group`）**不算归属**（2026-11-17 修正：一个标签常常装着几个服务，例如 Netflix 和 Disney+ 规则都导入成「Netflix」标签，之前采用 Netflix 会连带改写 Disney+ 规则）；标签仍用于规则页的筛选和按标签批量改目标（`POST /api/rules/retarget`）。属于停用 AI 适配器的规则（例如带 `chatgpt.com` 的规则）永远不算。这些规则改指向所选出口所在的地区组。预览（`preview: true`）的 `service_rules` 与保存用的是同一份归属。
2. **地区组优先这个出口**：自动组把它移到成员首位，手动组把它设为指定成员。改的是整个地区组，指向同一组的其他规则也随之改用这个出口——它们不属于这个服务，预览里单独计数（`other_rules`），不出现在 `service_rules` 里。
3. 走规则自动生效（同一个开关 `rules_auto_apply`、合并等待、限频、忙碌有限重试、预检阻断与需确认警告、版本一致和失败关闭），授权范围精确到这次保存：服务规则的目标，确认时再加目标地区组的成员顺序 / 模式 / 指定成员 / 故障回落（见 architecture.md「规则自动生效」）。手动选组或钉死只改服务规则目标，正常直接自动安装到网关（回归 `TestUnlockManualAutoInstalls`）；若编译结果仍涉及枢纽或网关以外的文件，如实显示未自动生效原因与去部署。「将自动生效」时结果行每 3 秒查询 `GET /api/rules/auto-apply`，直到显示已生效（vN）/ 已是最新 / 未自动生效：原因。页面在保存后显示一行结果：已生效（vN）/ 将自动生效 / 未自动生效：原因 + 去部署。地区组在枢纽上切换：组的首选真的变了时，枢纽的切换脚本也要变，网关的自动安装带不上别的节点的文件，所以这时如实显示「未自动生效：地区组的首选出口由 <枢纽> 切换，需要到部署页安装」；组已经优先这个出口、只改规则目标时会自动生效。这是操作者的决定（2026-11-17）：自动生效只到网关，切换首选出口所需的枢纽安装由操作者在部署页完成；自动下发到枢纽是另一个功能，暂不做。回归 `TestUnlockManualGroupMoveNeedsHub`（确认路径）锁定这一行为。

已经采用过的推荐（规则都指向那个组、组已选中那个出口）显示「在用」。

**出口身份**（`internal/api/exit_identity.go`）：每条探测结果带创建任务时冻结的出口身份摘要（`identity`，`v2:` 加 SHA-256 前 16 字节；`v1` 摘要一律视为不同）。摘要覆盖决定流量实际从哪里出去的字段：出口的角色、WireGuard 端点（`endpoint_v4` / `endpoint_v6` / `endpoint_host`、监听端口）、**编译后的有效外层链路**（每条涉及该节点的隧道：链路、传输、模式、谁拨谁、拨号端实际用的端点——含链路 `wg_port` 对节点 `listen_port` 的覆盖、IX 的 `ingress_v4`、Mesh 地址、IPv6 外层——以及 UDP+WSS 备用腿端口和监听端 `wss_listen_port`）、出口 NAT 的出接口（`wan_interface`，未设为 `eth0`，与编译一致）、对端公钥、出口地址族、关联服务器的地址和端口、嵌套出口的中继（端点、公钥、服务器）、外部出口的承载出口（同上）与 SOCKS 目标（地址、端口、承载接口），以及网关上选中这个出口的承载配置（fwmark、过渡地址、隧道解析器、是否仅 TCP）。公钥决定 WireGuard 对端是谁，所以算进去；私钥、预共享密钥、SOCKS 凭据是秘密，不算；名称、坐标、标签、备注只是展示，改了不影响结果。

- 任务创建时冻结每个出口的探测参数和身份摘要；执行时只用冻结的参数，不按出口 ID 重新解析。面板记住每个出口的身份代次：任何一次保存（拓扑写入，或受管服务器的地址 / 端口修改）让某个出口的身份变化，代次就加一。完成时身份与冻结时相同**且**代次没变，结果才写入冻结的摘要并入库；执行中身份变过（即使随后改回），这轮结果没有摘要、不入库（`not_ingested:exit_changed`）。
- 结果按任务创建顺序保存：旧任务晚完成不会覆盖新任务的结果。
- 解锁页只认摘要与出口当前摘要相同的结果；没有摘要（升级前保存的结果不补签）或摘要不同的显示「未测」，不参与推荐，确认会被拒绝（409）；手动保存要带矩阵给出的当前摘要，摘要过期同样 409。「未测到」只表示探测了但无法判定，两者不同。
- 不新增有效期：结果有效期照旧。

**限制**：规则与服务的对应靠名字和域名，自定义的规则集名字里没有服务关键字时认不出；关键字是固定表，可能把同名的无关规则算进来（例如名字里带 `friday`）。推荐用的耗时是整个探测请求的耗时，不是业务延迟。

## 规则的自动选择

检测结果自动改变路由的地方只有**指向地区组的规则**（内置的 `auto-*` 规则就是这种）：状态以规则 ID 为键，探测项是同名适配器，用同一个状态机（`internal/unlock`）和同一个准入（`unlock.Ingest`）。服务组已移除（规则直接指向地区组），没有别的决定键。

- **候选**：规则指向的地区组的成员，按地区组的有效顺序（硬约束过滤、IX 优先）。候选范围由运营者决定：选哪个地区组、组里有哪些出口。**默认出口**是地区组自己选中的成员（自动组的首位，手动组的指定成员）。
- **钉死优先**：目标地区组是手动模式时，结果只记录和展示，不移动出口。
- **多个检测项**：先对每个绑定的判定类检测项（`verdict` / `region_verdict`）合并本轮 IPv4/IPv6 证据：任一支持的地址族有有效成功，该项才成功；没有成功而有明确失败，该项失败；否则没有结论。然后要求所有绑定判定项都成功，组合才成功；任一项失败则组合失败；其余按 `inconclusive` 入库。未知、错误、未发出、超出预算或不支持的地址族不能代替成功证据。只做到达性的检测项永远不投票。
- **地址族合并**：各检测项可以分别在不同地址族成功，两个地址族只推进一次状态机。例如 fuboTV 只支持 IPv4：IPv4 上 fuboTV 失败，即使 YouTube Premium 在 IPv6 成功，组合仍失败，不能成为可用候选，也不能开始恢复。若 fuboTV 在 IPv4 成功、YouTube Premium 仅在 IPv6 成功，则组合成功。原始逐项逐族证据保留在任务及结果中；组合结论在已发送地址族的状态记录中一致，跳过项本身不入库。
- **阈值和滞回不变**：连续两次定时失败才换成员（手动和健康补测不计）；切回首选要首选最新结果是 30 分钟内收到的成功，并且从最后一次失败之后连续成功满 30 分钟，期间任何一次失败都重新计时。
- **结果有效期**（`settings.unlock_probe.result_ttl_sec`，默认探测间隔的两倍，即 12 小时）：超过有效期的结果不是证据，既不能让一个成员成为可用备选，也不再把它排除在外。升级前保存、没有收到时间的旧结果保持原有含义，直到该成员的下一次结果把它替换。
- **备选**：首选连续两次定时失败时，没有已知可用成员时会先试一个还没测过的成员；所有候选都失败时留在默认出口，标「组内都不可用」并在面板告警，不会换地区。
- **切换的生效路径**：决定存在面板的解锁状态里（`unlock.Decisions`，键是规则 ID），只经现有的网关安装事务进入网关：默认由运营者安装（面板显示「待安装」，与内置规则相同）；打开 `auto_apply` 后，满足下节全部条件时由面板自己走同一个安装事务（见「自动安装决定」）。编译时 `planRules` 是规则目标、mark、地址集合名字的唯一来源：决定把规则改到被选成员**自己的** mark，地址集合、SmartDNS 的解析器组（被选成员的隧道解析器，不是国内解析器；该成员没有 IPv6 时照常不返回 AAAA、不声明 IPv6 集合）、嗅探服务的规则快照和目标文件都从这同一份计划生成。`internal/compile/service_select_test.go` 编译切换前后的结果，检查每个被引用的集合都已声明、没有重复声明、清单里的地址集合都已声明，嗅探服务接受编译出的快照和目标文件，覆盖 IPv4-only 与双栈目标、嵌套出口、仅 TCP 的外部出口、地区组和单出口目标。
- **没有规则的服务只展示**：一个适配器不是启用规则的探测项时，结果标「未入库：没有关联」，自动选择不会因此新增或修改任何规则；只有运营者在解锁页点「确认」或「手动」保存才改规则。

### 自动安装决定（`settings.unlock_probe.auto_apply`，默认关闭）

关闭时（默认）一切与以前相同：决定改变后标「待安装」，等运营者安装。打开后，每当决定改变（规则换成员，或恢复后切回），面板在探测一轮结束、出口报告之后、以及每分钟的定时检查里评估一次；**下面全部满足**才安装，否则决定保持待安装，面板显示是哪一条没满足（`GET /api/unlock` 的 `auto_apply.last_check`）：

1. **安装前已同步**：记录了上一次网关安装用的决定；没有未完成的宿主事务；用这些决定重新编译当前拓扑，得到的网关文件与已安装的逐个哈希相同，并且与上一次应用的快照（全部节点的规范文本）完全相同。所以自动安装除了这个决定不会带上任何别的未审阅改动。升级后还没有经面板安装过一次的网关没有这条记录，要先人工安装一次。
2. **只改规则文件**：用新决定编译，与 (1) 相比只有网关节点的这些文件不同（`compile.DecisionFiles`，由 `TestDecisionChangeTouchesOnlyRuleFiles` 在各种示例拓扑上验证决定改变只碰它们）：`etc/nftables.d/meridian.nft`、`etc/smartdns/smartdns.conf`、`etc/meridian/rules/order.conf`、`etc/meridian/rules/decide.json`、`etc/meridian/sniff/targets.json`。任何别的文件、别的节点、文件增删（密钥、WireGuard 接口文件、单元文件都不在其中）都拒绝。
3. **频率**：距上一次自动安装至少 `auto_apply_min_gap_sec`（默认 600 秒，300–86400），最近 24 小时少于 `auto_apply_daily_max` 次（默认 6，1–48）；同样的决定自动安装失败后 1 小时内不再试（换了别的决定仍受最小间隔约束）。
4. **没有别的动作**：网关节点锁（预检、下发、撤回用的那把）空闲，宿主事务锁没被占用也没有未完成的事务；否则推迟到下一次评估，不排队。
5. **预检**：在节点锁内为这次的文件运行一次宿主预检，没有阻断项。

满足后调用与 `POST /api/apply`（`install: true`）同一个函数 `applyGateway`：同样的密钥处理（只复用已有密钥，不生成）、同样的事务（失败时补偿、补偿失败则保留事务日志等待恢复）、同样的 WSS 与秘密记录；编译结果必须与检查时的完全相同，否则不执行。每次自动安装记入 `unlock_auto_apply`（时间、触发、决定、结果、改动文件）和解锁历史（标「自动安装解锁决定」）。失败后决定保持待安装、不循环重试（见第 3 条的退避）。状态机的阈值和滞回不因此改变；恢复后切回走同一条路。

对流量的影响（按代码，**未在真实网关上验证**）：安装由 `meridian-up.sh` 用一个 nft 批次整体替换 `inet meridian` 表（先 `nft -c` 检查，失败则旧表不动），替换是原子的，但表里按域名学到的地址集合随之清空，客户端重新解析后才重新填上；分类是逐包按目的地址做的，但出口由中转源地址决定：网关上所有出口 mark 都查同一张表 102，枢纽按中转源地址选出口，而中转源地址转换（`transit_snat`，nat 钩子）只在连接的第一个包上决定并记在 conntrack 里，替换规则表不改已有的转换，所以按代码已建立的连接继续从原出口出去直到结束，切换只影响新连接；解析器配置变了时网关的 SmartDNS 会重启（缓存清空）；嗅探转发服务的单元文件不变时只重载，已转发的连接保持原路。

### 分流域名与探测主机不是一回事

- **一个服务的流量走哪个出口**，只由有序规则列表决定：规则自己的域名 / 后缀 / 关键字、它引用的规则集合（订阅的 Clash / Surge 规则集）或 geosite 名单。规则的目标是地区组或单个出口。
- **探测访问哪些主机**，由适配器写死的 `hosts` 决定（例如 Netflix 只访问 `www.netflix.com`，ABEMA 访问检测接口 `api.abema.io`）。这些主机不会被加进任何分流规则，也不保证在这个服务的规则覆盖之内；探测本身固定从所选出口出去，不经过分流规则。
- 所以「检测说可用」只说明从那个出口访问那几个固定主机得到的结论；服务的其余域名是否真的走了这个出口，要看规则是否覆盖它们（规则页的「这个域名命中哪条规则」）。

## 调度与克制

`settings.unlock_probe`（都可以不填，填了要通过校验）：

| 设置 | 默认 | 范围 | 作用 |
|---|---|---|---|
| `unlock_interval_sec`（原有） | 6 小时 | 建议 ≥ 1 小时 | 定时探测周期 |
| `exit_concurrency` | 2（与以前相同） | 1–2 | 同时探测的出口数（agent 最多同时 2 个） |
| `exit_request_budget` | 40 | 6–200 | 一次**定时**探测里每个出口最多发多少个平台请求（两个地址族合计，含前后各一次出口确认）。超出的服务这一轮不探测，记「未入库：超出预算」；按候选优先级取舍：服务当前所在的出口和默认出口先测 |
| `result_ttl_sec` | 探测间隔 × 2 | 1 小时–7 天，且不短于探测间隔 | 结果有效期（见上） |

- 定时探测只跑至少有一个**能移动出口**的拥有者（未钉死的规则）的适配器，而且只在它们的候选出口上跑；手动探测可以选任何适配器，但没有关联规则的适配器必须指定出口；解锁页按地区探测（`scope`）不受这条限制，按上文「按地区探测」选出口。
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
11. 覆盖表新增的 27 个适配器：已对照固定提交的源码，但没有在真实平台上跑过；在可用和受限出口上各跑一次。U-NEXT 已改回公开方法的 GraphQL 查询，仍需复测。
12. YouTube Premium：此前在真实平台上各出口都返回未知，原因已查明：介绍页约 1 MB，ad-free 第一次出现在约 850 KB 处，而检测只读前 256 KiB，正文被截断（不是页面改版，也与同意 Cookie 无关）。这一步现在读到 2 MiB，2026-11-15 在真实平台上复测，六个出口判为可用且地区正确。仍要核对：不可用地区的应答；要求同意的地区里固定同意值是否被接受；放宽后多读的部分也参与质询页判断，要留意是否因此误报质询。
13. Disney+：2026-11-15 在真实平台上观察到首页约 1.95 MB、`"location":"XX"` 在约 860 KB 处（与出口地区一致），紧跟的 `"region":"us"` 是固定值、不是所在地。判定已改为只读 `location`（紧跟 `pageId` 键），步骤读取上限 2 MiB；修改后未在真实平台上复测，保持未验证：确认各出口给出可用（或地区不符），而不是未知（正文被截断或没有 location）；留意 `location` 的键序有没有变。
13a. Netflix：2026-11-15 观察到香港出口整页约 690 KB、`requestCountry` 在约 454,000 字节处；美国出口没有前缀、此前因正文只读 256 KiB 而未知。判定改为：URL 国家前缀，否则 `requestCountry` 对象自己的 `id`（前缀与它冲突 = 未知），步骤读取上限 2 MiB，已移除 `countryCode`。修改后未在真实平台上复测，美国出口的情形未验证：确认美国出口上 `requestCountry` 存在、取值为 US 且落在 2 MiB 内；非美国出口的前缀是否仍出现。
14. 含义不明的 region 类判据审计（2026-11-15 只列出，Netflix 一项已改；都需要在真实平台上核对该键是不是访问者所在地）：
    - Netflix（`auto-netflix`）：已处理（见 Netflix 一节）：通用 `countryCode` 已移除，只有语言的前缀不再当地区，没有前缀时只认 `requestCountry` 对象自己的 `id`。
    - MyTV SUPER（`auto-mytvsuper`）：`region` 数字（1 = 香港、其他数字 = 不可用）——数字的含义只是公开实现里的约定，不确定；与 `country_code` 并存时以 `region` 为先（`country_code` 只作展示）。
    - Viu（`auto-viu`）：首页跳转路径第二段当作地区——可能是语言或站点区域，不一定是访问者所在地。
    - NHK+（`nhk-plus`）、KKTV（`auto-kktv`）、Abema（`auto-abema`）、DAZN：读 `country_code`、`country`、`isoCountryCode`、`GeolocatedCountry`，它们来自平台自己的地理接口，名字有明确的国家含义，列在这里只为真实平台复测时顺带确认它们没有像 Disney+ 那样改成别的含义。
    - Gemini、Copilot（`regionCode`）、Bilibili 国际站（`country_code2`）等：地区只作展示，不参与可用性判断，不在此列。
15. 覆盖表本身：已按固定提交逐项读出；引用脚本之后增删的项目要在更新提交号时重读。
16. 规则自动选择与采用：在真实网关上对一条服务规则点「采用」，确认规则自动生效或面板给出部署链接、生效后该服务的流量和 DNS 都从推荐出口出去；制造首选连续两次定时失败（抓包，不经国内解析器），首选恢复 30 分钟后切回；所有候选失败时留在默认出口并告警。

## R5 自动选路证据边界

本节覆盖旧表中较宽松的“可用”措辞：原分类器保留公开脚本的原始判断供方法对照，但宿主最终结果与面板接收结果均执行更保守的证据门槛。`no_negative_marker` 的正面结果一律降为 `network_ok`；OpenAI、Claude、MyVideo、Peacock、Pluto TV、NBA TV、Sling、BritBox、AMC+、Tubi、Acorn TV、Hulu Japan 的正面结果也只算到达性。原因分别是无封锁提示、通用页面/登录页、manifest 或注册入口不足以证明解锁。这些适配器不能用于自动选路；负面限制标记仍可供诊断。限流、质询、错误、未知和仅到达性均不能让候选成为已知可用。

Apple TV+：商店/登录页面返回 200 不证明订阅作品可播放；没有无需账号的可靠正面证据，本次不伪造检测。公开方法参考仍是上文固定提交的 LMC、1S、GO；本次没有联网重新查阅或请求平台。港、日、台、新、美的已有适配器与缺项原因已逐项列在覆盖表，保留令牌、凭据、固定主机、请求预算与 HTTPS 边界。

（服务组及其映射建议已移除：服务与规则的对应改为按服务定义的域名和名字匹配，见「按地区探测、推荐与采用」。）

解锁页逐组展示固定/自动、绑定检测、候选最近证据和时间、过期、推算在用与切换原因。启用或修改自动绑定须确认弹窗并发送 `confirm_mapping: true`；后端在同一保存事务内核对确认、非空检测和可靠方法，拒绝时不保存半份修改。自动选择仍局限原地区组候选，沿用地区/住宅/IPv6 约束、失败滞回、恢复冷却和安装语义，不新增跨国家回落。

本次新增合成回归未执行；真实平台复测由主会话完成，重点核对平台改版、地区限制、登录/订阅/版权、反机器人页面和解锁后实际播放。检测成功不证明账号权益或所有作品可播。

Coze 的地区字段只作展示：必须同时收到显式的 `IsForbiddenRegion: false` 才能给出正面结论；该字段缺失时不再把布尔零值当成允许。

## 外部 SOCKS 出口的探测解析

宿主探测从出口的 `TransitV6` 向 `DNSULA:53`（外部出口为承载节点上的 `PeerULA`）发 UDP/TCP 查询。承载节点 `ext_dnat` 在 IPv6 拒绝规则之前为这一组合放行（`internal/compile/render_nested.go`，回归 `TestExternalProbeDNSException`）。旧的承载节点规则会把该查询 DNAT 到拒绝端口，探测得到 connection refused；**改动后需由主会话重新下发外部出口的承载节点**，再在真实平台复测。实现只用合成应答测试，真实平台复测不在实现中执行。
