# 从 mihomo 导入分流规则

面板「分流规则」页的「从 mihomo 导入」把 mihomo（Clash.Meta）配置里的分流规则变成面板的规则，**保持同样的先后顺序**：从上到下，第一条命中生效。实现与边界见[架构](architecture.md)「分流规则：一个有序列表」。

**状态：没有用真实配置、也没有在真实网关上执行过。** 下面的一切只经过合成配置的自动化测试和本机 Docker 里对固定版本 SmartDNS 与 nft 的测试。

## 读取什么、丢弃什么

- 只读 `rules`、`rule-providers`、`proxy-groups` 三段。可以粘贴整份配置；`proxies`（服务器地址、密码、UUID、私钥）、`proxy-providers`（带令牌的订阅地址）、`secret` 等其它内容在面板解析后立即丢弃：不保存、不写日志、不在任何应答里返回。YAML 有错时只报行号，不回显那一行。
- 导入的配置文本只在浏览器页面的内存里，不进浏览器存储；关闭导入面板即清空。预览和确认都把同一份文本再发一次（面板不保存它）。
- 保存到面板的是：规则（类型、值、原文、行号）、服务组、规则集（名称和 URL）、线路映射（mihomo 名字 → 面板的地区组或出口）。
- `rule-providers` 的 URL 带用户名密码或令牌类参数（`?token=…` 等）时，预览只显示去掉它们的 URL 和「订阅认证」的类型；确认时认证存进受限凭据存储（只写，不显示、不导出），只在下载这个规则集时发给 URL 的同一来源。见[架构](architecture.md)「规则集合的订阅认证」。

## 当前选中状态

mihomo 的选择组当前选的是哪个成员不在配置文件里。在 mihomo 网关上执行（把 `<secret>` 换成控制接口的口令，端口按你的 `external-controller`）：

```
curl -s -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

把输出整段粘贴到「当前选中状态」。面板只用其中各 `Selector` 的 `now`。用 API 时 `selection` 可以是这段 JSON 的字符串，也可以直接是 JSON 对象。不粘贴时按每个组的第一个成员映射（预览里会提示），导入后可以在「服务组」里改。

## 怎样映射

- `DIRECT` → 直连（国内解析器解析、直连出去）；`REJECT` / `REJECT-DROP` → 拒绝（照常解析，连接被网关立即拒绝：TCP 复位，其它 ICMP 端口不可达）。
- 规则直接引用的每个 `select` 组 → 一个**服务组**。服务组的指向按「选择组 → 当前选中 → 地区选择组 → 当前选中 → 线路组」一直走，直到遇到在映射表里有对应的名字。线路组（例如 `LB-HK 某提供商`）、`url-test`、单个节点必须在**映射表**里对应到面板的地区组或出口；面板按名字里的地区给建议（香港 / HK、台湾、日本、美国、新加坡，带「家宽」之类字样时优先建议住宅组）。映射会被记住，下次导入直接用。
- `MATCH` → 默认组（经同一个服务组）：它最终必须落到一个地区组，确认后面板把默认组改成它；以后在服务组里改兜底，默认组跟着改。
- 紧挨在 `MATCH` 之前的 `GEOIP,CN,DIRECT` 就是网关内置的中国地址直连，不另写规则；在别处的 `GEOIP,CN` 按它的位置写成规则。其它国家的 `GEOIP` 没有数据，不支持。
- 两种 QUIC 规则（`AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT` 和 `…(NOT,((GEOIP,CN))),REJECT`）→ 一行「QUIC 开关」，放在原来的位置：它之下的规则和默认组走隧道的 UDP 443 被拒绝，之上的规则豁免。
- `RULE-SET,<名字>,<策略>` → 一条使用规则集的规则；`rule-providers` 里的条目变成面板的规则集（同名或同 URL 的已有规则集会被复用）。规则集要先下载完才能确认（预览会在后台下载，点「刷新预览」看进度）；还没下载的可以选择「先写入但停用」。
- 在 `MATCH` 之后的规则 mihomo 永远走不到，不写入。

## 预览里的标记

逐条按原顺序列出：映射成什么、写到面板列表的第几条、与上次导入相比是新增还是变化，以及：

| 状态 | 含义 |
| --- | --- |
| 可写入 | 数据面能按列表顺序精确执行 |
| 阻止确认（`block`） | 不能执行（进程名、UA、URL 正则、端口、其它逻辑规则、没有数据的 GEOIP、二进制 `.mrs`、`type: http` 以外的规则集），或者去向没有映射。只能删掉这一行或补上映射 |
| 需要接受（`accept`） | 只能用一个明确说明的替代来执行：关键词（只匹配已下载名单里含这个词的名字）、规则集里有关键词或不能执行的条目（只部分生效）、QUIC 开关的语义差别、QUIC 开关之下的直连规则。勾选「接受」或删掉这一行；「需要接受的替代（按类型）」可以一次接受同一代码的全部行（每行仍逐条列出，接受的代码记在每条规则上，摘要见 `accept_summary`） |
| 遮蔽（信息） | 这一条被前面的规则完全遮蔽，永远不会命中；或者其中更具体的名字已被前面的规则接走。与 mihomo 相同，只是提示 |
| 不写入（信息） | MATCH、内置中国地址直连、MATCH 之后的行 |

还没有映射的行只显示映射标记（`target_unmapped`）；由此引起的校验错误（例如出口不存在）在映射补齐之后才显示。

每个标记还带机器可读的 `class`：`address_only` 表示只是因为网关按地址分类才不精确（以后按名字判断的转发器可以放宽），`unsupported` 表示任何方式都不能执行。

确认时面板重新计算预览，只有和你看到的那次完全一致（`digest` 相同）且没有阻止项时才写入；否则要求重新预览。手工规则不会被改动；上次导入的规则整体换成这次的（预览里列出会被移除的）；勾选时停用面板的内置默认规则（不删除）。写入后照常「安装」才在网关生效。

## 网关和 mihomo 的固有差别

mihomo 按每个连接请求的名字判断；这台网关按 DNS 解析出的目的地址判断。两个去向不同的名字解析到同一个地址时，网关分不清它们的连接，这个地址按列表里更靠前的规则走。内置国内名单（geosite cn）和中国地址直连排在所有规则之后、默认组之前：没有规则命中、但地址在中国的连接直连（等于 mihomo 末尾的 `GEOIP,CN,DIRECT`）。

## 用 API 做同样的事

1. `POST /api/rules/import/preview`，正文 `{"config": "<YAML>", "selection": "<GET /proxies 的输出>", "mapping": {"LB-HK 某提供商": "group:hk-residential", …}, "drop": [行号…], "accept": {"行号": ["keyword_expanded", …]}, "accept_codes": ["ruleset_partial", …], "disable_builtin": true, "fetch_rule_sets": true}`。`accept_codes` 接受这些代码的全部行（只能是 `keyword_expanded`、`ruleset_keywords`、`ruleset_partial`、`ruleset_unavailable`、`quic_semantics`、`quic_direct_below`，其它返回 422 `bad_accept`）；它和逐行接受得到同样的计划和 `digest`。应答：`rows`（每个标记带 `accepted`）、`mapping`（需要对应的名字和建议）、`services`、`rule_sets`（下载状态、`auth` 类型）、`accept_summary`、`blocking`、`can_confirm`、`digest`。字段类型不对时 400 的错误说明是哪个字段。
2. 补 `mapping`、`drop`、`accept`，去掉 `fetch_rule_sets` 再预览，直到 `can_confirm` 为 true 且 `rule_sets` 都是 `available`。
3. `POST /api/rules/import/confirm`，正文同上再加 `"digest": "<最后一次预览的 digest>"`。`409 stale_preview`：预览变了，重做第 2 步；`422 blocked`：还有阻止项。
4. `GET /api/service-groups`、`PATCH /api/service-groups/{id}`（`{"target": "group:<id>" | "exit:<id>" | "direct" | "reject"}`）调整指向；`POST /api/rules/test`（`{"name": "…", "address": "…"}`）检查某个名字落到哪一条。
5. 保存后照常安装。
