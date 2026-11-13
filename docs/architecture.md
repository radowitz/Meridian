# 数据面

本文说明编译器实际生成的转发方式，方便对照设计方案验收。二期和三期加在同一套表和脚本上，不另起一套数据面。

## 路径

主路径必须能排成：网关 → 阿里云中继 → IX → 香港枢纽 → 出口。校验失败时面板拒绝保存（草稿除外），编译也会失败。

两条 IX 替换 WSS 在部署时就写进配置并拉起接口，但 `IXReplacementMode` 关闭时，阿里云向东的默认路由仍指向 IX 上的直连 WireGuard。健康脚本在 IX 连续失败后才切到待命 WSS，并带回滞，避免来回抖。家宽到枢纽的那条 WSS 只在阿里云本身也不可达时使用。Mesh 边如果不是「枢纽 → 出口」且待命，直接拒绝。

## 为什么网关要做一次中转地址改写

WireGuard 不携带 fwmark。家宽到阿里云只有一条逻辑隧道，枢纽却要根据目标选择不同出口。编译器让网关按策略把局域网源地址改写到每个出口独立的中转地址：

- IPv4：`10.66.200.0/24` 里的一个 /32
- IPv6：`fd66:0:0:ff::/64` 里的一个地址

阿里云和枢纽按这个源地址选路。回到客户端时，网关上的连接跟踪再还原成原来的局域网地址。对公网可见的 NAT44 / NAT66 只发生在出口。国内流量不改写，下一跳仍是 `192.168.100.1`。

`fd66::/48` 的路由不会指向 ROS。误送到 ROS 的 ULA 即使撞上可选的 `fd00::/8` 黑洞，也不该从 Meridian 送出去。

网关的 `classify` 链对受管入口（局域网口，打开远程接入时再加 `mra`）进来的包，按这个顺序处理 IPv6 目的地址：先把设备池（打开远程接入时）标成国内 mark；如果局域网 IPv6 前缀（`settings.lan_ipv6_prefix`）本身是 ULA（在 `fc00::/7` 里），紧接着把**恰好这个前缀**标成国内 mark（`ip6 daddr <局域网 ULA 前缀> meta mark set 0x64 return comment "ULA LAN prefix: home hosts only"`）；然后 `ip6 daddr fc00::/7 drop` 丢掉其余所有 ULA（隧道 `fd66::/48`、中转 `fd66:0:0:ff::/64`、`ula_prefix`、设备池之外和其他任何 ULA）。国内 mark 查表 100，表 100 里局域网前缀是 `dev <局域网口>` 的直连路由，兜底表只放国内 mark 从局域网口出去，所以这条只通往家里的主机，不会走 ROS 的默认路由。没有它时，从 `mra` 访问家里的 ULA 主机、家里主机回给网关地址（设备访问家里主机时的 masquerade 地址）的包，以及发往网关自己 ULA 地址的包（DNS 等），都会在这条 ULA 丢弃里被丢掉。局域网前缀是 GUA（常见情况，也是示例拓扑）时不生成这一条，局域网前缀那条仍在私有 IPv4 段之后、编译结果与之前逐字节相同。校验相应收紧：局域网 IPv6 前缀必须是 IPv6；不能包含整个 `fc00::/7`（`::/0`、`fc00::/6` 之类直接拒绝）；是 ULA 时必须写成网络地址、长度 /48–/128，并且不能与 `fd66::/48`（含中转 /64，即使 `ula_prefix` 改在别处）、`ula_prefix`、`transit_v6_prefix`、NAT64 前缀和设备池重叠。

## 每一跳

| 跳 | 传输 | MTU |
| --- | --- | --- |
| 家宽 → 阿里云 | UDP WG 与 WSS 两套接口，优先 UDP | 1412 / 1360，TCP MSS 按更小的那条夹 |
| 阿里云 → IX → 枢纽 | 直连 WG，外层 IPv4 | 1420 |
| 枢纽 → 出口 | 公网直连 WG。NAT 节点反过来拨 | 1420 |
| IX 替换 | 预置 WSS，`timeout_sec=0`，`restrict-to` 本机 WG 端口，正式证书 | 1360 |

所有 WireGuard 接口都是 `Table = off`，避免 `wg-quick` 把机器自己的默认路由抢走。外层端点在网关上有一条经 `192.168.100.1` 的主机路由，避免隧道把自己的握手包卷进去。

台湾和家宽出口的配置里，枢纽侧没有 `Endpoint`。出口侧 `PersistentKeepalive = 25`，更新用 `wg syncconf`。

## DNS

SmartDNS 只绑在网关的局域网地址上。

- `223.5.5.5` 和 `1.12.12.12` 的 DoT 解析国内名单，结果写入 `direct4` / `direct6`，走 ROS。
- 各服务名单经对应出口隧道上的解析器查询，再写入该规则的 nftset。规则指向枢纽可切换的地区组时，问的是组自己的解析地址，跟着枢纽当前选中的成员走，见「地区组的解析」。
- 没命中的名字走默认组（示例里是香港机房组），写入默认集合；默认组可切换时同样经组的解析地址。
- 出口没有 `egress_v6` 时，该规则加 `-address #6`，不返回 AAAA，也不改到别的国家。
- nftables 把测试设备发往任意地址的 UDP/TCP 53 和 TCP 853 重定向到本机。
- 已知 DoH 域名返回 SOA，已知 DoH 地址的 443 在转发链上被拒绝。这只覆盖清单，不能说绝对防住了 DoH。

chnroute 来自 gaoyifan/china-operator-ip（MIT），geosite 分类来自 v2fly/domain-list-community（MIT）。GPL 的规则包只作为可选数据源，不放进仓库，也不链进面板。下载、展开和发布见下一节「名单源」。

## 名单源

### 策略与地址

拓扑设置里的 `list_source` 只有三个值，空等于 `automatic`：

| 值 | 尝试顺序 |
| --- | --- |
| `domestic`（国内） | 只用国内镜像 |
| `overseas`（海外） | 只用 GitHub raw |
| `automatic`（全自动） | 先国内镜像，失败再 GitHub raw |

地址写死在 `internal/lists`，请求里没有任何 URL：

| 源 | geosite（`<base>/<分类名>`） | China IP（`<base>/china.txt`、`<base>/china6.txt`） |
| --- | --- | --- |
| 国内 | `https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data` | `https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists` |
| 海外 | `https://raw.githubusercontent.com/v2fly/domain-list-community/master/data` | `https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists` |

国内源不经过 `raw.githubusercontent.com`。2026-11-12 从用户网关实测 jsDelivr 这两个路径可达（china.txt 约 97 KB / 0.8 s），GitHub raw 大多超时；这只是一次观测，换线路或换时间要重测。宿主上 `meridian-host.service` 的环境变量 `MERIDIAN_GEOSITE_BASE_URL` / `MERIDIAN_CHNROUTE_BASE_URL`（只接受带主机名的 http/https）可以把**国内**源换成局域网副本；面板和请求改不了它。

本轮覆盖的“名单”只有这两类。GeoIP / ASN 规则仍然不写进数据面（校验给 `match_not_enforced` 警告），所以没有 GeoIP 或 ASN 数据要下载。其余联网下载不按名单源处理，原样保留：出口上的 regioncheck 镜像（`docker pull`，由运维在出口上做，属于镜像而非名单）、解锁探测访问的服务首页（探测目标，不是数据）、SmartDNS / Mesh 容器镜像、`install.sh` 的 apt 包。

### 一次更新

只有手动：面板「立即更新」（`POST /api/lists/update`）或宿主上 root 运行 `meridian-update-geosite.sh` / `meridian-update-chnroute.sh`。两个脚本只是 `exec meridian lists-update …`，走的是同一个 host agent 固定动作 `/v1/lists`。本轮不加定时任务。

1. 下载与检查（不持锁、不改宿主）：每个名单按策略顺序逐个源尝试。geosite 分类在**同一个源**上把它的 include 闭包整个取齐（并发 6，每个文件连接 10 s、单次 60 s、5xx/网络错误重试 1 次、上限 8 MiB；每个名单在每个源上总共 5 min），展开、校验通过才算这个源成功；任何一个子文件失败，整个名单换下一个源重来，不会把两个源的文件拼在一起。China IP 两个地址族各自独立选源。
2. 发布（持 host agent 的动作锁，最多等 `LockWait`，和安装/回滚互斥）：geosite / 关键词文件各自写临时文件后 `rename`，一个名单要么全新要么全旧；chnroute 把所有通过的地址族放进**一个** `nft -f` 事务（每族 `flush set` + `add element`），nft 接受后才替换 `/var/lib/meridian/lists/china*.txt` 和重载副本 `lists/chnroute.nft`。有 geosite/关键词文件变化时重启 SmartDNS（它只在启动时读 domain-set 文件），仍在锁内。
3. 结果写进宿主 `/var/lib/meridian/lists/status.json`：每个名单当前生效的版本（来源、URL、时间、条数）和最近一次更新的完整报告（每个源的尝试、耗时、错误、是否保留旧版）。

失败的名单保留上一份完整版本；从未存在的 geosite 文件建成空文件，只为让 SmartDNS 能启动。只有一个更新能同时运行；第二个请求得到 503。

### v2fly 格式的处理

按 v2fly/domain-list-community README（2026-11-12 读取）：

| 条目 | 处理 |
| --- | --- |
| 无前缀域名、`domain:` | 写入 domain-set（SmartDNS 按后缀匹配，与 v2fly 语义相同） |
| `full:` | 写入 domain-set。SmartDNS 的 domain-set 没有精确匹配，所以它的子域也会命中，是略宽的近似 |
| `keyword:`、`regexp:` | 丢弃并计数（报告里 `dropped`）：domain-set 表达不了子串和正则。正则仍要能编译，否则整个文件算格式错误 |
| `@attr` | 记在条目上，只用于 include 过滤；发布整个分类时不按属性筛 |
| `include:x` | 递归展开 x 的完整结果 |
| `include:x @a @-b` | 只取同时带 `@a`、不带 `@b` 的条目（属性名可以带 `!`，如 `@-!cn`） |
| `&list`（归属） | 忽略：它把条目加进**另一个**名单，只有扫描全部文件才能实现。被别处 `&` 归属进来的条目因此缺失 |
| `#` 注释 | 行内任意位置起到行尾 |

整份文件只要有一行不是注释、空行或上面这些合法条目（未知前缀、非法域名、多余的词、HTML），就算格式错误。界限：include 深度 16，单个分类闭包 2048 个文件（2026-11-12 实测 `cn` 用到 361 个，`geolocation-!cn` 超过 512），展开后 50 万条；循环（含自身包含）、缺失的 include、超界都让这个名单在这个源上失败。菱形包含不是循环。名单发布到 `geosite/<名称里非字母数字换成 _>.txt`，请求的是真实名称（`category-ads-all`），两个名称落到同一个文件时校验报错。

### 信任边界

镜像是第三方，服务的是决定流量走向的数据。内容检查只证明“形状对”，不证明“内容真”：

- 能挡住：HTML 错误页 / 门户页（Content-Type 或内容形状）、二进制、空文件、截断（Content-Length 不符、行不完整、China IP 少于 1000 条 IPv4 / 300 条 IPv6）、比上一版少一半以上（上一版至少 200 条时）、China IP 里与保留地址重叠、短于 /8（v4）或 /16（v6）的前缀、IPv4 总量超过 6 亿地址、https 跳转到 http。
- 挡不住：恶意或过期镜像给出格式正确但内容错误的数据。往 `cn` 里加境外域名，会让这些名字走国内 DoT 并写入 `direct4/6`，即绕过隧道直连；往 China IP 里加境外网段（在上面的上限之内）同理。删掉条目只会让国内流量绕路。jsDelivr 对分支引用有缓存，不同文件可能来自上游不同的提交，也可能比 GitHub 落后。
- 所以报告里写的是“来源”，不是“已验证”。需要更强保证时，用自己核对过的局域网副本替换国内源。

### API

错误体与其他资源一致：`{"error","code","field"?}`。

| 方法 路径 | 说明 |
| --- | --- |
| `GET /api/lists` | `policy`、`saved`（是否显式保存过）、`policies`、`order`（本策略的尝试顺序）、`sources`（编译进程序的地址；宿主 drop-in 的覆盖只出现在报告的 `attempts[].url` 里）、`lists`（`geosite` 分类名、`keywords`、`chnroute`）、`host_available`、`job`（正在跑或最近一次） |
| `PUT /api/lists/policy` | `{"policy":"domestic|overseas|automatic"}`，写入拓扑设置并返回同上；422 `invalid_field`/`policy`，400 `bad_request` |
| `POST /api/lists/update` | 可选 `{"lists":["geosite","chnroute"],"policy":"…"}`（空体 = 两类、已保存的策略）。202 `{"job"}`；409 `update_running`（带当前 job）；503 `host_unavailable`；422 `invalid_field`（`lists`/`policy`）或 `invalid_lists`（拓扑里的名称无法提交） |
| `GET /api/lists/job` | `{"job"}`：`state` 为 `running` / `done`（宿主执行了，逐个名单看 `report.lists`）/ `failed`（宿主不可达、忙或拒绝，什么都没改）；最近一次在面板重启后仍可读 |
| `GET /api/lists/status` | 宿主 `status.json`：`published`（每个名单当前生效的来源、URL、时间、条数）和 `last`（最近一次报告，不论从面板还是脚本发起）；503/502 `host_unavailable` |

报告里每个名单：`list`（`geosite:<名>`、`keyword:<id>`、`chnroute4`、`chnroute6`）、`updated`、`kept`、`source`、`url`、`count`、`files`、`dropped`、`current`、`attempts[]`（源、URL、是否成功、错误、耗时）、`error`；整体还有 `ok`、`partial`、`dns_changed`、`dns_restart`、`warnings`。进度只有 running → done/failed 两段，不报告单个文件的进度。

宿主侧固定动作 `POST /v1/lists`（`request_id`、`policy`、`lists`、`geosite`、`keywords`，未知字段拒绝）与只读的 `POST /v1/lists/status`，同样需要 agent 口令和 uid 0。分类名只能是 `[a-z0-9][a-z0-9!_-]{0,63}`，最多 64 个，落到同一文件的名称拒绝；关键词 id `[a-z0-9_]{1,80}`、值 `[A-Za-z0-9._-]{1,64}`，最多 64 个；整个更新 15 分钟上限，调用方断开也会跑完并记录。

### 重载后 chnroute

每次 `meridian.service` 重载都重建 `inet meridian`。网关的 `meridian-up.sh` 在检查前把 `lists/chnroute.nft`（只允许 `flush set` / `add element` 两个 chnroute 集合的行）接在编译出的规则后面，生成 `lists/.boot.nft`，仍然只做一次 `nft -c -f` 和一次 `nft -f`；副本有别的行、或与当前规则合起来 `nft -c` 不通过时，忽略副本，只加载编译出的规则（chnroute 为空，直到下次更新）。

## IPv6 和 ROS

网关是 SLAAC 客户端：`accept_ra=2`，因为开了转发之后只有 2 才会收下 RA。不要在这块网卡上跑 radvd，也不要再开一个 DHCP。

测试设备必须自己把 IPv6 默认路由指到网关的链路本地地址，并关掉路由器发现。否则 ROS 的 RA（生存期 2700 秒）会把默认路由写回去，AAAA 和 WebRTC 都会从运营商前缀漏出去。

国内 IPv6 的下一跳是 ROS 在 bridge 上的链路本地地址。示例里写成 `fe80::1`，上线前改成真实地址。

## 下发顺序

1. NAT 拨出的出口（先把隧道拨起来）
2. 其他出口
3. 香港枢纽
4. 阿里云
5. 家宽网关

以后改拓扑也按这个顺序：先下发受影响的远端节点，再安装网关。地区组的解析要求成员出口已经装上应答组解析地址的规则（「地区组的解析」），新地区组的中转地址要求枢纽已经有那张组表；网关先装，组内的名字在出口更新前解析不了（不会改问国内或别的出口），组流量在枢纽更新前进黑洞。`APPLY_ORDER.txt` 在有可切换地区组时也写明这一点。

差分看的是上一份已应用文本和这一份编译结果。面板不在宿主上直接执行命令：安装和运行态回滚写入 Meridian 自己的文件后，经宿主上的 `meridian-host`（固定的 activate / health / rollback / withdraw 动作，只接受受管资源名；只读的安装前预检 `/v1/preflight`，只接受校验过的受管路径，见「装机前预检」；另有名单更新 `/v1/lists`、只读的名单状态 `/v1/lists/status`、解锁探测 `/v1/probe` 和远程接入运行状态 `/v1/remote-access/status`，见「名单源」「解锁」「远程接入」）完成 daemon-reload、启动 `meridian.service` 和相关 unit、健康检查，以及删除旧清单独有的接口、unit、nft 表和路由表。每次安装都记录受管清单（文件、接口、unit、nft 表、路由表、sidecar 和版本），回滚按清单求差并只激活目标清单里的接口，不再扫描 `/etc/wireguard/m*.conf`。数据目录快照和宿主网络在同一份持久事务里，失败即补偿，进程重启时恢复；面板的回滚必须明确选择「含宿主网络」或「只回滚数据目录」（后者在已安装时需要显式 `snapshot_only`）。开机时转发保持关闭，`meridian-guard.service` 先装兜底表，`meridian-up.sh` 在防火墙就绪后才打开转发。`meridian.nft` 是单个 nft 事务，只替换 `inet meridian`（网关上还有 `inet meridian_guard` 兜底表），加载失败时旧表原样保留；`meridian-up.sh` 先 `nft -c` 再 `nft -f`，并且在打开转发和装路由之前完成。网关在路由层没有按入口接口的 `iif … unreachable` 规则（IPv4 和 IPv6 都没有）：从局域网（或 `mra`）转发、既没有国内 mark 也没有出口 mark 的包由兜底表在 forward 上丢弃，原因见下面「局域网兜底」。细节和尚未在 Linux 上验证的部分见 [验收清单](verification.md#防火墙原子替换与-lan-兜底)。

### 局域网兜底

两层，IPv4 和 IPv6 相同：

- **`inet meridian_guard`**（独立的 nft 表，forward 钩子，优先级 -200）：在打开转发之前加载，开机时由 `meridian-guard.service` 先于主表加载。从受管入口（局域网口，打开远程接入时再加 `mra`）转发的包，只有「国内 mark 从局域网口出」和「出口/地区组 mark 进网关自己的 WireGuard 接口」两种放行，其余（未分类或走错接口）全部丢弃。
- **每个出口和地区组 mark 的 `fwmark X unreachable`**（查完表 102 之后）：隧道路由不在时，已分类的境外流量不会落到主表经 ROS 出去；表 102 和表 100 末尾还有 metric 32767 的黑洞。

旧版本在 IPv4 上另有 `17850: iif <局域网口> unreachable`（打开远程接入时还有 `17851: iif mra unreachable`），想做第二道路由层兜底。它是错的：`rp_filter=2` 时内核校验转发包的源地址，反查用的是 iif = 这个包的**出接口**、mark = 0（`src_valid_mark=0`），于是所有从局域网口（或 `mra`）转发**出去**的 IPv4 包都会命中这条规则、反查失败，被以 `EXDEV`（`ip route get` 显示 `Invalid cross-device link`）丢掉——国内直连的回绕、隧道回到局域网客户端的回程、设备的国内流量和回程都不通。以前的测试只数出去的包、国内只测了 IPv6，所以没发现。这两条规则已删除，`meridian-routes.sh` 每次运行都按优先级、接口和动作删掉旧版本留下的那两条（升级不用重启就恢复）；`meridian-verify.sh` 发现它们时报 `FAIL no_stale_iif_rule`，并用 `ip route get … iif …` 让内核实际判一次这些路径（`route_*` 各项）。`fwmark X unreachable` 不受影响（反查的 mark 是 0），保留。`rp_filter` 仍是 2。

没选的两种做法：保留规则、把每个接口的 `rp_filter` 设成 0（能通，但正确性依赖每个接口的 sysctl 都是 0，漏一个接口 IPv4 就静默黑洞）；保留规则、开 `src_valid_mark=1` 再给回程打 mark（在防泄露的关键路径上多出几处耦合的部件）。

代价：IPv4 对**没有 mark** 的局域网转发流量不再有路由层兜底，和 IPv6 一样只靠 nft。两张 Meridian 表都被删掉而转发仍开着时（例如有人执行 `nft flush ruleset`，或启用了 Debian 自带、配置以清空整个规则集开头的 `nftables.service`），IPv4 会和 IPv6 一样直接经 ROS 出去。`meridian-up.sh` 不会在兜底表缺失时打开转发；`meridian-verify.sh` 在兜底表缺失时 FAIL，在 `nftables.service` 已启用且 `/etc/nftables.conf` 会清空规则集时打印 `WARN nftables_service_flush`。这些都不是强制手段：运行中有人删表，只能靠检查发现。

### 分类链先决定的目的地址（校验）

网关的 `classify` 链在查规则集合之前就决定了几类目的地址：远程接入设备池（交给设备）、隧道端点集合 `underlay4`（丢弃）、`10.66.0.0/16`（丢弃）、ULA 局域网前缀（判为国内）、`fc00::/7`（丢弃）、链路本地 / 组播 / 环回 / 广播（不打标记）。因此：

- 网关局域网 IPv4（`settings.gateway_lan_ipv4`、网关节点的 `lan_ipv4`）与 `10.66.0.0/16` 或自定义的 `transit_v4_prefix` 重叠时是 `prefix_conflict` 错误——否则发往局域网主机的包在私有地址那一行之前就被 `ip daddr 10.66.0.0/16 drop` 丢掉，与有没有隧道地址落在局域网里无关。
- 启用的 CIDR 规则，整个目的范围都落在上面某一类里时是 `rule_unreachable` 错误（`rule_id`、`field: match_value`），文字给出规则名和原因；它永远不会命中。只部分重叠（例如 `10.0.0.0/8`）不报，其余部分照常生效。隧道端点按「启用的 WireGuard 链路两端节点的 `endpoint_v4`，IX 端换成专线邻居」推算，与编译器的 `underlay4` 一致（`TestUnderlayRulesReportedUnreachable` 交叉核对）。

这两项都只是校验，编译出的 `meridian.nft` 不变。

### 面板状态（`GET /api/status`）

只读、无副作用，供顶栏轮询（默认 20 秒，有任务运行时 5 秒）。不算 Mesh 计划、不带探测目录和任务明细。

| 字段 | 含义 |
| --- | --- |
| `agent` | `{configured, ok, error}`：对 host agent 做一次 health（3 秒超时）。`configured=false` 表示面板没有宿主执行通道 |
| `lists_available` / `probe_available` | 名单更新 / 解锁探测此刻能否执行（动作已配置且 agent 应答） |
| `probe_reason` / `probe_error` | `probe_available=false` 的原因：`not_configured`（面板启动时没有探测通道）或 `agent_unreachable`（配置了，但 agent 的 health 没有应答，`probe_error` 是那次的错误）。概览的「解锁探测」卡片按这两项显示，不再看 `GET /api/unlock/jobs` 的 `available`——后者只说明配置了探测通道，不检查 agent 是否应答 |
| `install.state` | 存储的拓扑与**已安装清单**比较（`Manifest.canonical_sha256`，不是已应用快照）：`in_sync`、`changed`、`not_installed`（宿主上什么都没装）、`invalid`（拓扑无法编译，附 `error` 和错误级 `issues`）、`unknown`（接管的旧版安装没有摘要，无法比较） |
| `install.installed_version` / `installed_at` / `origin` | 已安装清单的版本、时间、来源；未安装为 `null` |
| `install.applied` / `applied_matches` | 是否应用过，以及存储的拓扑是否等于上一次应用的快照。`changed` 且 `applied_matches=true` 即「已应用（写入数据目录）但未安装」——`/api/diff` 在这种情况下显示没有变化 |
| `previous_available` | 数据目录里有上一份快照，回滚有东西可回；为 `false` 时面板不提供回滚 |
| `pending` | 未完成的宿主事务（同 `GET /api/host`） |
| `jobs.lists` / `jobs.unlock` / `jobs.mesh` | `{state, running, id, started_at, finished_at, error}`：名单任务、解锁探测（运行中的或最近一轮）和 Mesh 部署记录的状态；没有时 `state: "none"`，记录损坏时 `state: "error"` |

`POST /api/diff` 除了与上一次应用的快照逐行比较的 `diff`，还返回 `installed`：安装会让网关的**已安装清单**新增、修改、删除哪些文件和资源（`files_added` / `files_changed` / `files_removed`、接口、unit、nft 表、路由表，按清单里的文件哈希比较；没有安装时为 `null`）。已应用但未安装时 `diff` 为空，面板据此列出安装会改的文件；这种情况下没有逐行内容差分（已安装副本不经 API 读出）。

### 受管 sysctl：写入、生效与显示

- **写入**：每次安装（和运行态回滚）都把网关的 `etc/sysctl.d/99-meridian.conf` 和 `etc/meridian/forwarding.conf` 按编译结果**整份**写入，不管内容是否变化（事务的 converge 写目标清单里的每一个文件）。`install.sh` 或旧版本留在文件里的行在第一次面板安装之后就不在文件里了。
- **生效**：`meridian.service` 运行 `meridian-up.sh`，它在防火墙和兜底表就绪之后逐行 `sysctl -w` 应用 `99-meridian.conf`（开机转发两行 `ip_forward=0` / `all.forwarding=0` 跳过，它们只给 systemd-sysctl 开机时用），内核没有的键跳过并打印 `skip sysctl: …`，最后打印 `meridian-sysctl: applied N, skipped M from …`；之后才按 `forwarding.conf` 打开转发。不运行 `sysctl --system`。删掉的行不会恢复内核里的旧值。
- **显示**：事务提交后，面板逐键从运行中的内核读回（容器是 host 网络，`/proc/sys/net` 就是宿主的；测试根目录不读），放进安装结果 `host.sysctl`：`written[]` 每项 `{file, key, want, got, state}`，`state` 是 `in_effect`、`differs`、`missing`（内核没有这个键）、`boot_only`（开机转发两行）或 `not_checked`；`removed[]` 是安装前宿主上的旧文件里有、新文件不再设置的键（`stale`，附当前内核值）；`problems` 是 `differs` + `missing` 的数量。每个问题和旧文件遗留也作为 `host.warnings` 显示。这只是读回，不是泄漏证据，没有在真实网关上执行过。

### 面板开机时等待局域网地址

`cmd/meridian` 在开始服务之前调用 `api.ListenLAN`：`MERIDIAN_BIND` 先经 `CheckBind`（拒绝 `0.0.0.0` / `::`，没有回落）；绑定得到 `EADDRNOTAVAIL`（地址还没分配到任何接口，DHCP 租约未到）时每秒重试，最多 `MERIDIAN_BIND_WAIT`（默认 3 分钟），日志开始时和之后每 10 秒一行 `meridian-bind-waiting`，成功时一行 `meridian-bind-ready`，超时以 `meridian-bind-not-ready` 退出；其他错误立即退出。这样开机时容器处于「运行、在等地址」的可诊断状态，而不是靠 Docker 反复重启一个崩溃的进程。

### 安装与回滚的错误码（`POST /api/apply`、`POST /api/rollback`、`POST /api/host/recover`）

错误体是 `{"error","code",…}`，面板只按 `code` 判断，不匹配文字。HTTP 状态不变。

| `code` | 状态 | 含义 |
| --- | --- | --- |
| `host_unavailable` | 503 / 500 | 没有宿主执行通道（503），或 host agent 的健康检查失败（500）；什么都没写 |
| `legacy_install_refused` | 409 | 宿主上有旧版数据面，无法可靠接管（见下节）；宿主、快照、数据目录都没改 |
| `transaction_pending` | 409 | 上一次宿主事务没有完成，先 `POST /api/host/recover` |
| `peer_keys_missing` | 422 | 网关的 WireGuard 配置里有对端没有可用公钥；带 `peer_key_problems[]`（`peer`、`file`、`problem`），在生成网关密钥之前拒绝 |
| `topology_invalid` | 422 | 存储的拓扑校验不通过；带 `issues`，安装时在生成网关密钥之前拒绝 |
| `lan_interface_mismatch` | 422 | 同上，错误里有网关节点与 `settings.lan_interface` 不一致 |
| `activation_failed_compensated` | 500 | 激活或健康检查失败，已补偿回事务前；带 `host` 报告和 `compensated: true` |
| `activation_failed_uncompensated` | 500 | 激活失败且补偿也失败；事务日志保留，之后的安装和回滚都是 `transaction_pending`，直到恢复 |
| `commit_failed` | 500 | 宿主已生效、只有提交记录失败；恢复会完成提交 |
| `nothing_to_rollback` | 409 | 没有上一份快照（`GET /api/status` 的 `previous_available=false`） |
| `rollback_mode_required` | 409 | 网关已安装，回滚必须 `install=true`，或显式 `snapshot_only=true` |
| `gateway_key_unavailable` | 409 | 网关私钥无法取得或生成 |
| `host_state_malformed` | 500 | 宿主事务状态文件损坏 |
| `bad_request` | 400 | 请求体格式错误，或同时设置了 `install` 和 `snapshot_only` |
| `apply_failed` | 按情况 | 以上之外的失败，原文在 `error` |

### 旧版安装的接管

旧版（没有受管清单的版本）直接把文件写进宿主，`DataDir/host/installed/` 里没有清单。新版第一次「安装到本机」时，在快照轮换和任何宿主写入之前，先在事务锁内判断宿主上是否有旧版数据面（以 `usr/local/sbin/meridian-up.sh` 存在为准）：

1. 收集旧版可能拥有的文件：旧快照 `applied/`、`previous/` 里网关的文件、本次要写入的文件，以及宿主上 Meridian 命名的文件（`etc/wireguard/m*.conf`、`usr/local/sbin/meridian-*`、`etc/nftables.d/meridian*.nft`、Meridian 生成的 unit、`rt_tables.d/meridian.conf`、`sysctl.d/99-meridian.conf`、`etc/meridian/forwarding.conf`）。只收宿主上真实存在的。
2. 用这些文件推出旧版清单（接口、unit、nft 表、路由表、DNS），名字必须通过 `meridian-host` 的校验，否则拒绝。
3. WireGuard 配置里的 `PrivateKey` 必须正好是面板保存的网关私钥，恢复副本里换成占位符（和其他已安装副本一样不含私钥，恢复时在安装边界注入，得到逐字节相同的文件）。私钥不同、仍是占位符或无法识别时拒绝接管：面板没有别处可以安全保存另一把私钥，不能保证恢复。
4. 旧版的启动脚本在每次启动时按 `99-meridian.conf` 设置转发。升级脚本会把这个文件里开机即转发的行改成 0；如果宿主当前双栈转发都开着，恢复副本里这两行记成 1，补偿后重新启动旧版时转发和升级前一样打开（这也恢复了旧版「开机即转发」的行为，接管成功并完成新版安装后就被新版文件替换）。
5. 经 `meridian-host` 的只读 `health` 检查旧版资源（`meridian.service`、unit、接口、nft 表、DNS）。不健康就拒绝：没有一个在运行的旧版可以恢复。
6. 旧版有新拓扑不再包含的 unit 或接口时拒绝：宿主 agent 只移除自己激活过的资源，这些旧资源会被拒绝移除。先让新拓扑保留它们完成接管，下一次安装再删除。
7. 以上都通过才把旧版清单（`origin: "legacy"`）和恢复副本原子地写成 `host/installed/`，之后的安装就是普通的「旧清单 → 新清单」事务：激活失败时补偿把文件逐字节写回、移除新版独有的接口/unit/表（`inet meridian_guard` 移除前先关转发），再经 `meridian-host` 激活旧清单并做健康检查。

任何一步拒绝时宿主、快照和数据目录都没有改动，错误里列出发现的旧版文件和原因。恢复副本放在 `DataDir/host/installed/`（目录 0750、文件 0640，与其他已安装副本相同，不含私钥），不在快照目录里，也不经 API 返回。

## 服务器、SSH 凭据与 Cloudflare 账户

拓扑节点描述数据面里的一跳；「怎么登录这台机器」和「用哪个 Cloudflare 账户」是另外三类对象，由面板单独管理，节点只按 ID 引用。

### 对象

| 对象 | ID | 字段 | 引用 |
| --- | --- | --- | --- |
| 服务器 `Server` | `srv-…` | 名称、地址（主机名或 IP，不能以 `-` 开头）、端口（默认 22）、用户（默认 root）、认证方式 `password` / `key`、`credential_id`、标签、备注、主机指纹记录、`migrated_from` | 引用一个 SSH 凭据（种类必须与认证方式一致）；被至多一个拓扑节点通过 `node.server_id` 引用 |
| SSH 凭据 `SSHCredential` | `key-…` | 名称、种类 `password` / `private_key`、备注；私钥另有派生的公开信息：密钥类型、`authorized_keys` 格式公钥、SHA256 指纹、注释、是否带口令、是否面板生成；创建 / 更新 / 轮换时间、`secret_set` | 被服务器引用 |
| Cloudflare 账户 `CloudflareAccount` | `cf-…` | 名称、Cloudflare account id（32 位十六进制）、备注、`token_set`、权限检查结果 `permission_check`、时间 | 一个账户可被选为 Mesh 使用的账户；未撤回完的 Mesh 部署按 account id 绑定账户 |

网关节点（`role=gateway`）是本机，不是远端服务器，不能带 `server_id`。两个节点不能共用一台服务器：每台服务器只对应数据面里的一个角色，指纹、凭据和部署记录都按这一对一关系解释。

主机指纹状态：`unknown`（从未连接）→ `discovered`（「发现指纹」看到了指纹，尚未确认）→ `trusted`（用户在面板里明确确认了这一个指纹，已固定）；已固定后看到不同指纹记为 `mismatch`，原固定值保留，连接拒绝，直到用户确认新指纹或清除记录。确认时必须提交与 `discovered`（或 `mismatch` 时看到的新指纹）完全相同的值，防止确认到中途被替换的值。改服务器地址或端口会把指纹清回 `unknown`。迁移时从 Mesh 部署记录导入的指纹直接是 `trusted`（`source: "mesh_journal"`），照常使用。

### 连接（`internal/sshexec`）

面板连接远端服务器只有一条路径：`sshexec.Connector`。调用方只给服务器 ID（Mesh 撤回另给部署记录固定的凭据 ID、地址、端口、用户和指纹）；地址、端口、用户、凭据都从存储里取，请求里不能带私钥、密码、目标或命令。

- **发现**（`Discover`）：TCP 连上后只做到密钥交换，在主机密钥回调里记下公钥就中止握手——不提供任何认证方式，不执行任何东西。结果经 `ObserveHostKey` 记录，返回密钥类型和 SHA256 指纹给用户比对。
- **执行**（`RunScript`、`Test`）：连接前要求服务器状态是 `trusted`（`mismatch` 返回 `host_key_mismatch`，其余返回 `host_key_untrusted`），要求选了凭据（`no_credential`）。握手时主机密钥回调再调一次 `ObserveHostKey`：指纹不同就记为 `mismatch`、保留原固定值并断开——这一步发生在认证之前，密码或私钥根本不会被读取。只请求固定指纹那种主机密钥算法，避免多密钥主机换出另一把。
- **秘密只在认证回调里读取**：`ssh.PasswordCallback` / `KeyboardInteractive`（只回答不回显的提示）或 `ssh.PublicKeysCallback`（带口令的私钥在这里解密），都在主机密钥通过之后才调用 `ResolveSSHWith`，读的是凭据的当前一代，所以原地轮换后立即生效。
- **脚本走标准输入**：`bash -s`，WireGuard 私钥、Mesh 节点令牌不出现在远端进程列表里。输出最多 1 MiB。输出和所有错误文本都用 `credentials.Scrub` 去掉这次用到的密码、私钥（含逐行）和口令，长度再短也替换。
- 拨号 10 秒、握手 20 秒超时；执行超时由调用方的 context 决定（装机 15 分钟，Mesh 每个动作 10 分钟），超时会发 SIGKILL 并断开。错误码：`unreachable`、`timeout`、`auth_failed`（服务器尝试并拒绝了这份凭据）、`auth_method_unavailable`（服务器根本不提供这份凭据的登录方式，例如 `PasswordAuthentication no` 时的密码凭据；凭据没有被尝试，错误文字列出服务器提供的方式并说明改用密钥/密码或在服务器上开启对应方式。客户端在自己的方式之后附加只探测、不发送任何凭据的方式来得知服务器提供哪些）、`command_failed`、`not_ssh`、`host_key_untrusted`、`host_key_mismatch`、`host_key_not_pinned_by_deployment`、`target_changed`、`no_credential`、`not_found`。
- **连接测试**：登录后只运行固定命令 `sshexec.TestCommand`（`uname -m`、`uname -r`、`/etc/os-release` 的 `PRETTY_NAME`），30 秒超时；结果（时间、成功与否、认证方式、系统、内核、架构、耗时、错误码与脱敏后的错误）记在服务器的 `last_test` 上。改地址、端口、用户、认证方式、凭据或原地轮换凭据都会清掉 `last_test`。

服务器从「已添加」到「就绪」：建凭据 → 建服务器并选凭据 → `POST …/host-key/discover` → 用户核对指纹后 `POST …/host-key/trust`（提交同一个指纹）→ `POST …/test` 成功。视图里 `operable`（凭据 + 已确认指纹，装机和 Mesh 部署要求的条件）和 `ready`（再加上最近一次测试成功）。

### Cloudflare 令牌权限检查

`POST /api/cloudflare/accounts/{id}/check` 用存储的 token 只调用 Cloudflare 文档里的只读接口（2026-11-13 查对）：

1. `GET /accounts/{account_id}/tokens/verify`（账户令牌）；被拒时再试 `GET /user/tokens/verify`（用户令牌）。要求 `status: active`。
2. `GET /accounts/{account_id}/warp_connector?per_page=1`：能否读取这个账户的 Mesh 节点（接受 Connectors Read / Write、Connector: WARP Read / Write）。
3. `GET /accounts/{account_id}/teamnet/routes?per_page=1&is_deleted=false`：能否读取路由（接受 Networks Read / Write、Tunnel Read / Write）。

它能证明：token 有效且 active、在这个账户可用、能读 Mesh 节点和路由。**它不能证明写权限**：两个列表接口同时接受 Read 和 Write；读取 token 自己的权限清单要额外的「API Tokens Read」权限，面板不要求也不读取；要证明写权限只能真的创建东西，检查从不这样做。缺写权限会在部署的「创建 Cloudflare 节点」阶段失败并被补偿。结果 `{checked_at, ok, token_status, token_kind, confirmed[], unconfirmed[], missing[], checks[{name, endpoint, status: pass|denied|error|skipped, detail}], detail}` 存在账户上：`ok` 表示执行的每一项都通过（不等于写权限已证实）；`denied`（4xx）把对应权限列进 `missing`；网络错误、429、5xx 记为 `error`，不算缺权限。token 不出现在结果和错误里。所需权限和创建步骤由 `GET /api/cloudflare/requirements` 提供（`mesh.RequiredPermissions`、`mesh.TokenHowTo`）：账户级 `Cloudflare One Connectors Write` 和 `Cloudflare One Networks Write`。

Cloudflare 账户支持多个：同一面板可能要换账户、或者先录入新账户再撤回旧部署。任何时刻最多一个 Mesh 部署记录，它绑定一个 account id；被选为 Mesh 使用的账户只有一个（`mesh_account`）。规则沿用之前的绑定：部署处于进行中、已发布或未撤回完时，绑定的账户不能删除、不能改 account id、Mesh 选择不能切到别的 account id；同一账户可以随时轮换 token。

### 存储

元数据（三类对象与 `mesh_account`）在 `<secrets>/index.json`，每份密文在 `<secrets>/secrets/<id>-<代>.json`。`<secrets>` 默认是 `DataDir/secrets`，Docker 部署用单独的命名卷 `meridian-secrets`（`MERIDIAN_SECRETS_DIR=/var/lib/meridian-secrets`）。

- 目录 0700（打开时收紧），文件 0600，写入走同目录临时文件 + fsync + rename；读取时文件权限带 group/other 位就拒绝使用。
- 轮换写新一代密文文件，再原子替换索引，最后删旧文件；中途中断时索引仍指向完整的旧一代，下次打开清掉没有被索引引用的密文文件。
- 不在快照目录（`applied/`、`previous/`、`host/`）里，不进拓扑、编译产物、差异和数据库；API 只返回元数据和 `secret_set` / `token_set`。
- 没有做静态加密：面板要无人值守地使用这些凭据，解密密钥只能放在同一台机器、同一个进程能读到的地方。gateway 上的 root、能读 Docker 卷的人、拿到面板口令的人都能用到它们；单独的卷和权限只防止它们随数据目录、快照、日志或导出被带走。这和数据库里的 WireGuard 私钥是同一信任级别。

### 脱敏

请求里的密码、私钥、口令和 token 只写进密文文件。API 的错误信息是固定文本，不回显输入；所有经过这些接口的错误文本再按请求里的每个密文做一次替换（不论长短，4 个字符的密码也替换）。JSON 解析错误统一为「请求格式错误」。日志只记录数量和 ID。

### API

所有响应都是 JSON。错误为 `{"error": 中文说明, "code": 机器可读代码, "field"?: 字段, "in_use_by"?: [{"kind","id","name"}]}`。

| 方法与路径 | 请求 | 成功响应 |
| --- | --- | --- |
| `GET /api/servers` | | `{"servers":[服务器视图]}` |
| `GET /api/servers/{id}` | | `{"server":视图}` |
| `POST /api/servers` | `name, address, port?, user?, auth, credential_id?, tags?, notes?` | 201 `{"server"}` |
| `PATCH /api/servers/{id}` | 同上任意字段 | `{"server"}` |
| `DELETE /api/servers/{id}` | | `{"deleted":id}`；被节点或未撤回完的 Mesh 部署引用时 409 `in_use` |
| `PATCH /api/servers/{id}`（地址、端口、用户、认证方式、凭据） | | 被未撤回完的部署固定时 409 `in_use`；名称、标签、备注照常可改 |
| `POST /api/servers/{id}/host-key/trust` | `fingerprint` | `{"server"}`；409 `host_key_not_discovered` / `host_key_changed` |
| `DELETE /api/servers/{id}/host-key` | | `{"server"}`（回到 `unknown`） |
| `POST /api/servers/{id}/host-key/discover` | 无 | `{"discovery":{"key_type","fingerprint","matches_pinned"},"server"}`；502 `unreachable` / `timeout` / `not_ssh` |
| `POST /api/servers/{id}/test` | 无 | `{"test":连接测试结果,"server"}`（测试执行了就是 200，看 `test.ok`；失败时 `test.code` 是 SSH 错误码之一，例如 `auth_failed` 与 `auth_method_unavailable` 要分开处理）；409 `host_key_untrusted` / `no_credential` |
| `GET /api/cloudflare/requirements` | | `{"permissions":[{"name","scope","why"}],"how_to":[…],"check":{"does":[…],"does_not":[…]}}` |
| `POST /api/cloudflare/accounts/{id}/check` | 无 | `{"check":权限检查结果,"account"}` |
| `GET /api/ssh-credentials`、`GET …/{id}` | | `{"credentials":[…]}` / `{"credential"}` |
| `POST /api/ssh-credentials` | `name, kind:"password", password` 或 `name, kind:"private_key", private_key, passphrase?, comment?` 或 `name, kind:"private_key", generate:true, comment?` | 201 `{"credential"}`（生成时视图里就有公钥） |
| `PATCH /api/ssh-credentials/{id}` | `name?, notes?, comment?` | `{"credential"}` |
| `PUT /api/ssh-credentials/{id}/secret` | 与创建相同的密文字段（种类不变） | `{"credential"}`，ID 不变 |
| `DELETE /api/ssh-credentials/{id}` | | 被服务器或未撤回完的部署引用时 409 `in_use` |
| `GET /api/cloudflare/accounts`、`GET …/{id}` | | `{"accounts":[…],"mesh_account":id 或 null}` / `{"account"}` |
| `POST /api/cloudflare/accounts` | `name, account_id, api_token` | 201 `{"account"}` |
| `PATCH /api/cloudflare/accounts/{id}` | `name?, notes?, account_id?` | 409 `account_locked` |
| `PUT /api/cloudflare/accounts/{id}/token` | `api_token` | `{"account"}` |
| `DELETE /api/cloudflare/accounts/{id}` | | 409 `in_use` |
| `PUT /api/cloudflare/mesh-account` | `account`（ID 或空） | `{"mesh_account"}`；409 `account_locked` |

`PUT /api/topology` 检查节点引用，失败时 422：`gateway_server`（网关带了服务器）、`unknown_server`、`server_shared`、`ssh_fields_moved`。凭据存储打不开时，带 `server_id` 的拓扑不能保存，其他照常保存并在响应里给出 `migration_error`。

服务器视图另带 `credential`（`id`、`name`、`kind`）、`in_use_by`、`last_test`、`operable`、`ready` 与 `missing`（`credential`、`host_key`、`connection_test`）。

部署引用由存储自己检查：面板把 Mesh 部署记录里未撤回完的固定主机（`server_id`、`credential_id`、地址、端口、用户）交给 `credentials.Store.SetDeploymentPins`，删除服务器、改它的地址 / 端口 / 用户 / 认证方式 / 凭据、删除凭据都在存储锁内先查这份列表，命中就返回 409 `in_use` 和引用者（`mesh_deployment`）。schema 2 的旧记录没有 `server_id` 时按地址和端口匹配服务器、按该服务器当前的凭据匹配凭据。部署记录读不出来时所有服务器和凭据都算被引用。原地轮换凭据不受限制。凭据和账户视图带 `in_use_by`、`used_for_mesh`、`bound_deployment`。原来的 `PUT/DELETE /api/mesh/credentials` 仍可用，作用于当前 Mesh 账户（同 account id 时轮换 token，否则新建并选中）。

装机 `POST /api/provision`：`{node_id, dry_run?, generate_keys?, preflight_id?}`。`dry_run: true` 只返回带占位符、拒绝运行的预览脚本，不需要服务器。真正执行前要过「装机前预检」（下一节）：先检查节点关联了服务器（409 `no_server`）、指纹已确认、选了凭据；第一次装机必须带审阅过的 `preflight_id`（409 `preflight_required`）；随后在同一个固定身份上重新预检——这些都在生成或轮换 WireGuard 密钥之前。然后经连接器以 `bash -s` 执行，成功响应 `{dry_run:false, outcome:"installed", node_id, server_id, auth_method, host_key, public_key, preflight_id, run, output}`；失败 `{error, code, outcome, node_id, server_id, auth_method, leftovers, kept, output, login_help?}`（409 主机身份类与预检类，502 连接 / 认证 / 执行类）。旧字段 `ssh_host`、`ssh_port`、`ssh_user`、`private_key_pem`、`trust_new_host` 一律 400 `field_removed`，未知字段 400 `unknown_field`。

代码：`internal/model`（`Server`、`HostKey`、`ConnectionTest`）、`internal/credentials`（存储、校验、迁移、部署引用）、`internal/sshexec`（连接）、`internal/mesh/permissions.go`（权限检查）、`internal/api/resources.go`、`internal/api/ssh_ops.go`。

### 迁移

面板启动时和每次保存拓扑后运行，可重复执行：

- `DataDir/mesh/cloudflare.json` 导入为 ID 固定的账户 `cf-mesh`，未选择 Mesh 账户时选中它，索引写入成功后才删除旧文件。中断后重跑：账户已在就只删旧文件；文件权限过宽或内容损坏时保留文件并记录原因，不导入。Mesh 部署记录不变，仍按 account id 绑定，迁移后的账户 account id 相同，撤回照常。
- 带 `ssh_host` 的非网关节点变成服务器（ID 优先用 `srv-<节点 ID>`，`migrated_from: "node:<ID>"`，认证方式 `key`，凭据待选），节点写入 `server_id` 并清空 `ssh_*`。先写服务器索引，再保存拓扑；中断后重跑会认出 `migrated_from` 相同的服务器直接关联，不会重复。保留域名 `.invalid` 的示例地址不迁移。Mesh 部署记录里该节点固定过的主机指纹（地址和端口一致时）作为 `trusted` 导入。
- Mesh 部署记录 schema 2 升级到 3（见「Mesh」）：每个固定主机补上 `server_id` 和 `credential_id`，其余不变。
- 已有 `server_id` 的节点再带 `ssh_*` 时，保存被拒绝（422 `ssh_fields_moved`），避免两处地址不一致。


## 装机前预检

在面板第一次给远端节点装机、更新它，以及安装到网关之前，都要先看清**要做什么、会和什么冲突**；不能确认可以和主机上已有的服务安全共存时，面板拒绝执行并说明处理办法，而不是覆盖。预检本身**只读**。这一节描述的行为只在仓库里的自动化测试（进程内 SSH 服务器、假宿主代理、本机沙箱）里跑过，**还没有在任何真实主机上执行过**。

### 流程：脚本 → 报告 → 评估 → 关卡

1. **脚本**（`internal/preflight` 的 `Script()`）：一份固定、可审阅的 bash 脚本，对所有节点是同一段文本，拓扑、目标和请求里的东西都不插进去。唯一的参数是这个节点的包要写的主机路径：每个都要过 `preflight.ValidatePaths`（绝对路径、已规范化、只含字母数字和 `._/@+-`、不含 `..`、只在 Meridian 写的那几个目录下、最多 256 个），由 `preflight.Args` 单引号包好；`sshexec.RunPreflight` 连接前再按同样的形状检查一遍，脚本里也再判一次（被拒的参数只报告 `note path argument refused`，不碰）。脚本经已固定指纹的 SSH 通道以 `bash -s -- <路径>` 从标准输入执行。它只运行打印状态的命令（`id`、`uname`、`ip … show`、`ss -Hlntup`、`nft list chains`、`iptables -S`、`systemctl is-active/is-enabled/show -p MainPID`、`dpkg-query`、`apt-cache policy`、`sha256sum`、`head`、`grep`），每条 15 秒上限、标准输入是 `/dev/null`，不写任何文件，**不输出文件内容**（WireGuard 配置里有私钥：只报告类型、大小、前 12 行是否提到 Meridian、SHA-256），整份输出截在 256 KiB + 1 字节。
2. **报告**：按行的 `键 值…` 格式，首行 `meridian-preflight 1`，末行 `meridian-preflight-end`。`preflight.Parse` 不会失败：报告头之前的登录横幅被忽略；没有报告头、没有结束行、超长或超行数的报告标为不完整；每个值去掉控制字符、双向控制符和非法 UTF-8 并截到 400 个字符；地址、端口、路径、单元名、表名都按各自的形状校验，不符就丢掉；结束行之后的内容、清单块之外的清单行一律忽略。
3. **评估**（`preflight.FootprintOf` + `preflight.Evaluate`）：从这个节点**编译出来的文件**推出它会建的东西——接口和地址、监听端口（WireGuard `ListenPort`、wstunnel 服务端和客户端、SmartDNS 的 `bind`）、main 表路由和黑洞兜底、策略规则与优先级、路由表号与名字、防火墙标记、nft 表、systemd 单元、要装的软件包和必须已存在的二进制——再和报告逐项对比，得到带严重度（阻断 / 警告 / 信息）、稳定代码、中文说明（发现了什么）、处理办法和受影响资源的结论，外加「拟执行的变更」清单。
4. **关卡**（`internal/api/preflight.go`、`provision_api.go`）：见下面「执行前复核」。

网关走同样的评估：`meridian-host` 新增只读动作 `POST /v1/preflight`（参数只有同样校验过的路径；程序只从固定表里取：`ip`、`nft`、`ss`、`iptables`、`ip6tables`、`systemctl`、`wg`，参数固定；文件直接读、不回传内容；不占动作锁），用 `preflight.Line` 输出同一种报告。网关的「属于谁」来自安装清单（`apply.Installed`），带 Meridian 标记但不在清单里的文件交给安装事务的旧版接管去决定。

### 它检查什么

| 代码 | 严重度 | 条件 |
| --- | --- | --- |
| `report_incomplete` | 阻断 | 报告没有头、没有结束行、被截断或超限 |
| `not_root` | 阻断 | 登录用户不是 uid 0（这一版不支持 sudo） |
| `os_unsupported` | 阻断 | 不是 Debian 12 / 13（或读不到 `/etc/os-release`）：装机脚本用 apt 装 wireguard-tools、nftables、smartdns，其他发行版的包名和 SmartDNS 版本没有验证 |
| `arch_unsupported` | 阻断 | 不是 x86_64 / aarch64 |
| `kernel_too_old` | 阻断 | 内核早于 5.6（没有内置 WireGuard） |
| `no_systemd` | 阻断 | 不是 systemd 系统 |
| `no_apt` | 阻断 | 缺命令要装包，但没有 apt-get |
| `smartdns_unavailable` | 阻断 | 节点要跑出口解析器，没装且 apt 查不到候选版本 |
| `wstunnel_missing` | 阻断 | 节点有 wstunnel 单元但主机上没有 wstunnel（面板不下载二进制；提示按架构选 linux_amd64 / linux_arm64） |
| `forward_policy_drop` | 阻断 | 节点要转发，而 iptables/ip6tables 的 FORWARD 策略是 DROP/REJECT，或别的 nft 表有 `hook forward` 且 `policy drop` 的链（通常是 Docker）。Meridian 自己的转发链 `policy accept` 救不回被别的表丢掉的包；面板**不会**替你改 Docker 或别的防火墙 |
| `interface_exists` | 阻断 | 要建的接口名已存在且不在受管清单里 |
| `port_in_use` | 阻断 | 要绑定的 协议/地址/端口 已有监听：通配地址和同端口任何监听冲突，具体地址只和同地址或通配监听冲突（回环上的 systemd-resolved、WARP 不算冲突）；只有「有证据属于这次安装」的不算（见下面「什么算我们的」） |
| `address_overlap` | 阻断 | 要配置的隧道地址和别的接口上的地址**精确重叠**（不是「同一个 /8」） |
| `route_overlap` | 阻断 | 要加的 main 表路由会替换、截走或被已有的非默认路由截走；兜底黑洞只在比已有路由更具体（或同前缀同 metric）时算冲突 |
| `route_table_in_use` | 阻断 | 要独占的路由表里已有路由且不归 Meridian |
| `fwmark_in_use` | 阻断 | 已有策略规则用了 Meridian 要用的防火墙标记 |
| `nft_table_exists` | 阻断 | `inet meridian` / `inet meridian_mesh` 已存在但不在受管清单里（装机会整表替换） |
| `path_occupied` | 阻断 | 要写的路径上有不属于 Meridian 的文件（不在清单、没有 Meridian 标记）、目录或链接，例如另一份 SmartDNS 配置 |
| `managed_by_other` | 阻断 | 主机上的节点清单属于另一个节点或另一个面板（部署 ID 不同） |
| `manifest_unreadable` | 阻断 | 有清单但读不懂 |
| `legacy_install` | 阻断 | 有带 Meridian 标记的文件但没有清单（旧版或手工装的）：无法确认归属，也无法准确补偿 |
| `previous_run_incomplete` | 阻断 | 上一次装机的 journal 停在 `running` / `incomplete` |
| `rule_precedes` | 警告 | 一条「几乎全匹配」的规则排在 Meridian 依赖的规则（含 main 表）之前，查的表有默认路由（例如 WARP 的 `not fwmark … lookup 65743`） |
| `rule_priority_shared` | 警告 | 已有规则和 Meridian 的规则同优先级 |
| `route_table_name_conflict` | 警告 | 表号已有别的名字 |
| `input_policy_drop` | 警告 | INPUT 策略是 DROP 而节点要在公网监听（放行规则是否覆盖看不到） |
| `low_memory` / `low_disk` | 警告 | 可用内存 < 256 MB 或总内存 < 512 MB；根分区 < 200 MB |
| `nftables_flush_on_reload` | 警告 | nftables.service 启用且 `/etc/nftables.conf` 以 `flush ruleset` 开头 |
| `firewall_manager` | 警告 | ufw / firewalld 在运行 |
| `modified_since_install` | 警告 | 受管文件在上次装机后被改过，会被覆盖 |
| `previous_run_leftovers` | 警告 | 上一次失败已补偿，但 journal 记了残留（例如保留的软件包） |
| `docker_present`、`docker_missing`、`cloudflare_warp`、`wireguard_present`、`dns_listeners`、`nft_tables_present`、`netfilter_persistent`、`iptables_legacy`、`existing_install`、`forwarding_enable`、`host_summary` | 信息 | 认出来并说明是什么：Docker、主机级 WARP（`warp-svc`、`CloudflareWARP`、`inet cloudflare-warp`、100.96.0.0/12 地址）、别的 WireGuard 接口和端口、53 端口上不冲突的监听、别的 nft 表、legacy iptables、这次会全局打开转发等 |

**不检查**（随每个结果返回，面板里也显示）：放行规则是否覆盖 Meridian 的端口；云厂商安全组和上游 NAT；别的服务以后会不会改网络（Docker 重启、WARP 重连、nftables 重载）；SmartDNS 上游、wstunnel 证书和域名；sudo。预检不修改任何东西，发现的冲突由你处理。

### 什么算「我们的」

只有在主机上已有**本节点、本面板**（远端：节点清单的节点和部署 ID 都对上；网关：面板的安装清单）的安装时，才会有资源被认作这次安装自己的，而且每一项都要有证据，否则照常算冲突：

- 文件、接口、单元、nft 表、路由表：在受管清单里。
- 监听：所在 WireGuard 接口在清单里（`wg show all listen-port`）；或套接字所在的 cgroup（`ss -Hlntu --cgroup`，经 sock_diag 读取，不需要访问进程）是清单里的单元；或监听解析器端口的是清单里有解析器配置时的 `smartdns.service`，网关上则是 docker compose 管的固定容器 `meridian-smartdns`（宿主代理用固定参数 `docker inspect --format '{{.Id}} {{.State.Running}}' meridian-smartdns` 取它的 ID，与套接字 cgroup 里的容器 ID 比对）。宿主代理的 systemd 单元只有 CAP_NET_ADMIN，`ss -p` 看不到进程名，所以网关上靠 cgroup；读不到 cgroup（旧版 iproute2）时不认，仍报冲突。
- 地址和路由：在清单里的接口上；或这份包自己写的 lo 中转地址（`ip addr replace … dev lo`）及内核为它加的路由；与包里完全相同的路由。
- 策略规则：查清单里的路由表、`iif` 是清单里的接口，或与包里同优先级、同标记的规则。

第一次安装、`managed_by_other`、没有清单的旧版安装都不认任何东西。网关安装本身不装软件包：缺 `wg`、`nft`、`ip` 时报 `gateway_tools_missing`（阻断）；SmartDNS 不要求 apt 包，报告它由容器、宿主服务运行还是还没启动（`gateway_dns_runtime`，信息）。

### 执行前复核

- 结果绑定到**目标身份**（服务器 ID、地址、端口、用户、固定的主机指纹、凭据 ID）和这个节点包的**摘要**（`preflight.BundleDigest`：按路径排序的文件哈希，私钥仍是占位符），有效 10 分钟，存在面板数据库（`preflight/<节点>`，只有地址、名字、端口和哈希，不含秘密）。
- `POST /api/provision` / `POST /api/apply {install:true}`：第一次装机（这台服务器上这个节点从没成功过；网关上没有安装清单）没有 `preflight_id` → 409 `preflight_required`。带了 `preflight_id` 就检查：记录不存在或已被替换、过期 → `preflight_stale`；身份变了 → `target_changed`；包变了 → `bundle_changed`；审阅的结果有阻断 → `preflight_blocked`。然后**在同一个固定身份上重新预检**：有阻断 → `preflight_blocked`；出现了审阅时没有的警告或阻断 → `preflight_changed`（响应里带新的结果）。更新（之前成功过）可以不带 `preflight_id`，但重新预检照样要过。阻断项不能在面板里跳过。
- 远端脚本本身在动手前再复核一次（`provision.ScriptWith`）：必须是 root；不能有没结束的上一次装机；预检时没有清单（第一次）就要求现在也没有、要建的接口和 nft 表也没有冒出来（`MERIDIAN_REFUSED manifest_appeared` / `interface_appeared` / `nft_table_appeared`，退出码 3，什么都没改）；预检时是本节点的清单就要求现在仍是（`manifest_changed`）。
- 同一个节点同时只能有一个预检或装机（409 `node_busy`）。

### 失败的装机：补偿或明确残留

远端脚本在 `/var/lib/meridian/node/` 下记 journal（`state running`），先记下装机前的接口、nft 表、规则、路由、相关 sysctl 和单元状态，替换的文件先备份。任何一步失败、或 SSH 会话断开（`HUP`/`PIPE` 被忽略，补偿照样跑完），`EXIT` 陷阱就补偿：停用这次启用的单元、删除这次新建的接口和 nft 表、删掉这次新增且属于 Meridian 优先级的规则、清空这次才有路由的受管表、删掉这次新增的 main 表 Meridian 路由、恢复 sysctl、删除这次新建的文件和目录、恢复被替换的文件（更新时再跑一次恢复后的 `meridian-up.sh`）。装上的软件包**按设计保留**（`MERIDIAN_KEPT package …`，卸载可能牵连别的软件）。撤不掉的逐项打印 `MERIDIAN_LEFTOVER …` 并写进 journal，状态记为 `incomplete`；全部撤掉记为 `compensated`。面板据此返回 `provision_failed_compensated` 或 `provision_failed_leftovers`（带 `leftovers`、`kept`），连接中断等看不到标记时 `outcome: "unknown"`——**任何情况下都不把没有 `MERIDIAN_PROVISION_OK` 的执行当成成功**。下一次预检读到 `incomplete` / `running` 的 journal 会阻断，`compensated` 带残留时给警告。成功时写受管清单 `/var/lib/meridian/node/manifest`（节点、部署 ID、服务器、包摘要、每个文件的 SHA-256、接口、单元、nft 表、路由表、Meridian 装的包；上一版有而这一版没有的文件记为 `orphan`），下一次预检据此区分「本面板、同一节点」与其他情况。

中断的装机由面板恢复（journal 模式）、旧版安装由面板清理（legacy 模式）、已装好的节点由面板撤回，见下一节「撤回与失败后的恢复」。

### 登录方式不被接受

`auth_failed`（服务器试了并拒绝这份凭据）和 `auth_method_unavailable`（服务器根本不提供这种登录方式）分开报告。连接测试、预检和装机在这两种情况下都附带 `login_help`：凭据是密钥时给出它的公钥（`authorized_keys` 一行）和该做的步骤（必要时先开 `PubkeyAuthentication`）；凭据是密码而服务器只收密钥时，列出面板里已有密钥凭据的公钥，没有就提示先生成一把。只含公钥，不含任何秘密。

### API

| 方法与路径 | 请求 | 成功响应 |
| --- | --- | --- |
| `POST /api/provision/preflight` | `{node_id, generate_keys?}` | `{"preflight": 预检结果}`：`id`、`kind`、`target`（身份）、`bundle`、`first_install`、`at`、`expires_at`、`host`、`footprint`（受管资源）、`ownership`、`blocking`、`counts`、`findings[]`、`changes[]`、`not_checked[]`；登录失败 502 带 `login_help` |
| `GET /api/provision/preflight/{node}` | | `{"preflight", "stale"}` |
| `GET /api/provision/state` | | `{"nodes": {节点: 最近一次装机的结果}}` |
| `POST /api/host/preflight` | `{}`（不接受任何字段） | `{"preflight": 预检结果}`；503 `host_unavailable`，502 `preflight_failed` |
| `POST /api/provision` | `{node_id, generate_keys?, preflight_id?}` | 见上；预检类拒绝 409 `preflight_required` / `preflight_stale` / `preflight_blocked` / `preflight_changed` / `bundle_changed` / `target_changed` / `node_busy`，远端复核拒绝 409 `provision_refused`，失败 502 `provision_failed_compensated` / `provision_failed_leftovers` |
| `POST /api/apply` | `{install:true, preflight_id?}` | 同样的预检类拒绝；宿主代理不支持预检时 503 `host_unavailable` |

代码：`internal/preflight`（脚本、解析、评估）、`internal/provision`（装机脚本的复核、journal、补偿、清单）、`internal/sshexec`（`RunPreflight`）、`internal/hostexec/preflight.go`（网关预检动作）、`internal/api/preflight.go` 与 `provision_api.go`（关卡、记录、登录帮助）、`web/src/Preflight.tsx`（审阅界面）。

## 撤回与失败后的恢复

「从拓扑删除节点」和「撤回装在它服务器上的东西」是两件事，面板分开处理。这一节描述的行为只在仓库的自动化测试里跑过（本机沙箱里真跑撤回脚本、进程内 SSH 服务器、模拟宿主上的真实 `meridian-host` 代理），**还没有在任何真实主机上执行过**。

### 部署记录与绑定

- 每个远端节点的部署记录（面板数据库 `provision_state`）保存装机时绑定的**完整身份**：服务器 ID、地址、端口、用户、固定的主机指纹、凭据 ID、面板部署 ID，以及最近一次装机和撤回的结果。节点从拓扑删除、或在拓扑里改指到另一台服务器，记录都不变；撤回**只去记录里的主机**，不去节点现在指向的服务器。
- 只要服务器上可能还有东西（装成功过且没撤回、补偿留有残留、结果不明、撤回进行中 / 部分完成 / 结果不明），记录就固定这台服务器和这份凭据：和 Mesh 部署一样，经 `credentials.Store` 的部署固定（`node_deployment` 引用），服务器不能删除、不能改地址 / 端口 / 用户 / 认证方式 / 凭据，凭据不能删除（可以原地轮换）。这样撤回时一定还连得上**那台**主机。
- 节点仍装在旧服务器上时，在新服务器上预检或装机被拒绝（409 `deployed_elsewhere`）：先撤回旧的，不会静默留下一份安装。
- 撤回前再核对一次：服务器当前的地址 / 端口 / 用户必须等于记录（否则 409 `target_changed`），它现在信任的指纹必须等于记录（忘记指纹、换成另一把都 409 `host_key_not_pinned_by_deployment`），连接器握手时还要看到这把指纹。服务器上的清单里的 `node`、`deployment`、`server` 三项都要等于本面板的值，否则脚本拒绝（`manifest_other`、`manifest_other_server`）。
- 服务器确实已经不存在（VPS 已删）时可以「放弃」：输入节点 ID 确认后记录标为 `abandoned`，解除固定；面板明确说明**没有核实**服务器上是否还留有安装，从不把它显示为已撤回。

### 远端节点：一份固定脚本，三种模式

`provision.WithdrawScript` 是一份固定、可审阅的 bash 脚本。只有经 `CheckWithdrawOptions` 校验过的值以单引号赋值放在开头（节点 ID、部署 ID、服务器 ID、运行 ID：`[A-Za-z0-9._-]{1,64}`；模式和动作：固定枚举；摘要：64 位十六进制）。要删什么**从主机自己读**，不从请求里来；没有任意命令接口。脚本经固定指纹的 SSH 以 `bash -s` 从标准输入执行。

每种模式都有两个动作：`plan` 只读，打印将要移除的内容（`MERIDIAN_PLAN …`，每项带 present / absent / changed）和它所依据状态的摘要（`MERIDIAN_PLAN_DIGEST`）；`run` 重新计算摘要，与操作员确认的不同就拒绝（`plan_changed`，什么都不改）。

- **清单模式（`manifest`，默认）**：按装机成功时写的 `/var/lib/meridian/node/manifest`。每个条目在脚本里再校验一次——接口 `m\d{2,3}w?|mmesh|mmesh-c`、单元 `meridian-*` / `wstunnel-meridian` / `wstunnel-client-*` 的 `.service|.timer`、nft 表 `inet meridian[_…]`、路由表 100–252、路径只在 Meridian 写的那几个目录下且不含 `..`；有一条不认识就整次拒绝（`bad_manifest_entry`）。顺序：停用并停止单元 → 清单记录了「SmartDNS 是 Meridian 装的」时停用 `smartdns.service`（软件包保留）→ 清单里有 Mesh sidecar 的 compose 文件时 `docker compose -f … down`（只这一个项目）→ 删除接口 → 删除指向清单路由表的规则并清空这些表 → 删除清单记录的 main 表黑洞路由（新装机的清单才有 `route` 行）→ 删除清单里的 nft 表 → 删除文件（**只在 SHA-256 仍等于清单时**；装机后被改过的文件保留并列为没能移除）→ 需要时 `daemon-reload`、删掉空的 `/etc/meridian` → 复核接口、nft 表、单元确实不在了。全部完成才删除清单，journal 记为 `withdrawn`；有任何没能移除的东西时清单保留、journal 记为 `withdraw_incomplete`（下一次装机和预检会拒绝，提示继续撤回），撤回可以重复执行，已经不在的东西跳过。再撤回一次时脚本回答 `MERIDIAN_WITHDRAW_ALREADY`。
- **journal 模式（恢复中断的装机）**：journal 为 `running`（会话被硬切断、进程被杀）或 `incomplete`（补偿没做完）时，按这次运行的工作目录（`run-<ID>/`：actions、备份、装机前的 pre-* 状态、`params`）跑**与装机失败时完全相同的补偿**（两边共用 `compensateLib`）：新建的文件和目录删除、被替换的文件恢复、这次新建的接口和 nft 表删除、新增的规则和路由删除、sysctl 恢复、更新时重跑恢复后的 `meridian-up.sh`；每一步可以重复执行。`params` 是装机开 journal 时最后写的：没有它就说明这次运行还没动过主机，恢复只关闭 journal。工作目录不见了、或有动作却没有 `params`，拒绝（`journal_unrecoverable`），只能登录服务器按 journal 手工处理。恢复完成后，之前完整装好的版本（如果有）照旧在，之后可以再按清单撤回。
- **旧版清理（`legacy`）**：给没有清单的旧版安装。**只看固定路径和名字**：`/etc/wireguard/mNN[w].conf`、`meridian-*` / `wstunnel-meridian*` / `wstunnel-client-*` 单元文件、`/usr/local/sbin/meridian-*`、`/etc/nftables.d/meridian*.nft`、`/etc/sysctl.d/99-meridian.conf`、`/etc/iproute2/rt_tables.d/meridian.conf`、`/etc/smartdns/smartdns.conf`——每个都必须是普通文件且前 12 行提到 Meridian——以及 `/etc/meridian/` 下的文件；接口只取这些 WireGuard 配置的，nft 表只取这些 nft 文件里声明的，路由表只取这个 rt_tables 文件列出的。不带标记的同名文件（例如别人的 `m15.conf`）不碰。旧版的 main 表黑洞路由没有任何记录，脚本**不猜**，只提示去查 `ip route show type blackhole`。确认的清单在执行前重新扫描，有变化就拒绝。界面上要输入节点 ID 并单独提示这是旧版清理。

保留（**按设计**）：装机时装上的软件包（wireguard-tools、nftables、smartdns 等，卸载可能牵连别的软件）；运行中的 sysctl 值（转发、rp_filter，到重启或你自己改之前保持）；SmartDNS 不是 Meridian 装的时它的服务（配置被删，继续用内存里的旧配置直到重启）；清单之外的一切——Docker 和容器、别的 WireGuard 接口、WARP、别的 nft 表、别的文件。每次结果都列出「已移除 / 保留 / 没能移除」。

### 状态与持久化

撤回运行前，记录先写成 `running`（面板在执行中崩溃时显示「撤回中断」，不会是「已撤回」）；然后按脚本标记更新为：`withdrawn` / `already_withdrawn`（已验证，解除固定）、`partial`（列出没能移除的，继续固定）、`refused`（带原因代码，主机没改）、`not_started`（连不上、目标变了，主机没改）、`unknown`（没有结论性标记：连接中断或超时，不当作完成，继续固定）、`recovered` / `recovery_incomplete`（journal 模式）、`abandoned`（放弃）。计划存为 `withdraw_plan/<节点>`，绑定身份、部署 ID 和摘要，10 分钟有效，用一次即作废。服务器端的状态在 `/var/lib/meridian/node/journal`（`kind withdraw`、`state withdrawing|withdrawn|withdraw_incomplete`），预检据此阻断或放行。

### 网关：经安装事务撤回到兜底表

`apply.Applier.Withdraw` 是一份普通的宿主事务（`/var/lib/meridian/host/journal.json`，`kind withdraw`）：从已安装清单收敛到一份只剩兜底表的「已撤回清单」（`origin: withdrawn`，文件只有 `etc/nftables.d/meridian-guard.nft`，nft 表只有 `inet meridian_guard`）。移除经 `meridian-host` 新增的固定动作 `withdraw`：先关 IPv4 / IPv6 转发 → `systemctl stop meridian.service`（它没有 ExecStop，只是取消开机重试、清掉 active 状态；单元保持启用，`meridian-up.sh` 删除后开机会被条件跳过）→ 按清单删除单元、接口、规则和路由表、`inet meridian`（与 rollback 一样只动账本里激活过的名字）→ 确认 `inet meridian_guard` 仍在，不在就重启固定的 `meridian-guard.service`（只从开机文件加载这一张表）再确认，确认不了就失败。这个动作拒绝任何点名兜底表或解析器的请求。之后删除清单里的文件（兜底文件除外），再调一次 `withdraw` 复核。任何一步失败都补偿回撤回前（从已安装副本重写文件并重新激活数据面）；补偿也失败时保留 journal，拒绝新的安装、回滚和撤回，面板「恢复」或重启时处理。为保证总能补偿，撤回前先确认已安装副本能用网关私钥和远程接入密钥还原，否则拒绝、什么都不改。

**兜底表的决定：撤回之后局域网保持 fail-closed。** 兜底表丢弃 Meridian 没有分类的局域网转发流量；撤回后不再有分类，它就丢弃全部局域网转发——仍把这台机器当网关的设备断网，而不是经 ROS 不受保护地直出。`meridian-guard.service` 开机照样加载它，所以重启（或 Docker 开机打开转发）也不会漏。转发保持关闭。移除兜底表是**单独的一步**（`POST /api/host/withdraw {release_guard:true}`），只在撤回完成后提供：经已有的 `rollback` 动作（先关转发再删表）删除 `inet meridian_guard` 和它的开机文件，之后安装清单为空；面板明确提示此后局域网不再由 Meridian 兜底。

撤回后：`GET /api/status` 的 `install.state` 是 `withdrawn`；运行态回滚被拒绝（409 `gateway_withdrawn`，恢复走重新安装）；重新「安装到网关」按第一次安装处理，要先做安装前预检。没有安装清单的旧版网关拒绝撤回（409 `legacy_install`）：先用安装接管它，再撤回。安装清单里没有兜底表的版本拒绝撤回（409 `guard_missing`）。保留：`meridian.service`、`meridian-guard.service`、`meridian-host.service`（install.sh 装的宿主部分）、面板容器、数据目录和配置快照、Docker、SmartDNS 软件包或容器（配置文件若在清单里会被删除）、其他 nft 表和 WireGuard 接口。

### 与 Mesh 的组合

Mesh 撤回仍按 Mesh 部署记录固定的主机、凭据、指纹和 Cloudflare 账户进行（没有改动、没有放宽）。节点撤回（清单模式和旧版清理）在 Mesh 部署记录还忙（运行中、已发布、补偿未完成）且固定了这个节点的主机时拒绝（409 `mesh_deployed`），记录读不了也拒绝：**先撤回 Mesh，再撤回节点**——sidecar 跑在节点的接口上，Cloudflare 上还有它的节点和路由。Mesh 撤回失败时记录保持「补偿未完成」，节点撤回继续被挡住，直到 Mesh 撤回重试成功。journal 模式只撤销那次中断的装机，不碰之前完整安装的 sidecar，所以不受这条限制。网关撤回同样检查 Mesh 是否固定了网关。

### 解锁结果

拓扑里已经没有的出口，它的探测结果不再当作当前结果：`GET /api/unlock/results` 默认不列出（`include_removed=1` 时列出并带 `exit_removed: true`、`is_active: false`），另给 `removed_exits`（每个出口的条数）；`POST /api/unlock/results/prune` 删除这些结果。`GET /api/unlock` 带 `removed_exits`，界面把历史和状态里这些出口标为「已删除的出口」。清理只动面板的结果矩阵；`unlock.Snapshot` 里的准入记录（`Latest`、`Applied`）和历史保留，所以 `unlock.Ingest` 的准入规则不变：同一个出口 ID 以后再出现时，旧的结果也不能从它下面插进来（`TestRemovedExitsMarkedAdmissionKept`）。

### API

| 方法与路径 | 请求 | 响应 |
| --- | --- | --- |
| `GET /api/deployments` | | `{nodes: [记录 + node_name、in_topology、server_name、current_server_id、on_host、status、identity_problem、mesh_bound、plan?], gateway: {installed, withdrawn, version, plan, kept, pending, last, mesh_bound}}` |
| `POST /api/provision/withdraw/plan` | `{node_id, mode?: manifest\|journal\|legacy}` | `{plan: {id, mode, target, digest, owner, items[], expires_at}}`；已撤回时 `{plan, already_withdrawn: true}`；脚本拒绝 409 `withdraw_refused`（`reason`）；身份不符 409 `target_changed` / `host_key_not_pinned_by_deployment`；连不上 502（带 `login_help`） |
| `POST /api/provision/withdraw` | `{node_id, plan_id, confirm: <节点 ID>}` | `{outcome, removed[], kept[], leftovers[], message, reason, code, restored_previous, output}`；200 `withdrawn` / `already_withdrawn` / `recovered`；409 `confirm_required`（400）、`withdraw_plan_stale`、`mesh_deployed`、`withdraw_refused`、`target_changed`；502 `withdraw_partial`、`withdraw_unknown`、`recovery_incomplete`、`not_started` |
| `POST /api/provision/withdraw/abandon` | `{node_id, confirm: <节点 ID>}` | `{deployment, changed}` |
| `DELETE /api/provision/state/{node}` | | `{deleted}`；还可能在主机上时 409 `still_on_host` |
| `POST /api/host/withdraw` | `{confirm: "gw", release_guard?}` | `{status: withdrawn\|already_withdrawn\|guard_released\|not_installed, removed, kept, host}`；409 `nothing_installed` / `legacy_install` / `guard_missing` / `not_withdrawn` / `transaction_pending` / `mesh_deployed`；500 `activation_failed_compensated` / `activation_failed_uncompensated`（带 `host`） |
| `POST /api/unlock/results/prune` | | `{removed, exits}` |

代码：`internal/provision/withdraw.go`（脚本与解析）、`internal/provision/provision.go`（共用补偿、清单的 `prio` / `route` 行、`params`）、`internal/apply/withdraw.go`（网关事务）、`internal/hostexec/hostexec.go`（`withdraw` 动作）、`internal/api/withdraw.go`、`internal/unlock/report.go`（`ReferencedExits` / `RemovedExits`）。

## 地区组（出口的选择与切换）

用户的需求：出口按国家或地区（香港、美国……）分成大组，每个组里有多个出口节点；每个组要么由用户指定用哪一个，要么自动切换，自动切换的顺序由用户手工排。以下是这一版定下来的领域决策，代码在 `internal/model/groups.go`（对象和迁移）、`internal/pool`（有效顺序、选择、状态机）、`internal/compile`（标记、路由、枢纽切换脚本）、`internal/api/region_groups.go`（REST）。

### 对象

`region_groups[]`，每个组：

| 字段 | 含义 |
| --- | --- |
| `id` | 稳定 ID（小写字母、数字、短横线），规则用它引用 |
| `name` / `region` | 显示名和地区（`hk`、`us`……）。同一地区允许多个组，例如香港机房组和香港家宽组。显示名可以重复：面板在任何列出或选择地区组的地方（出口页卡片、规则的目标选择和列表、拓扑、解锁的选择器和结果矩阵、概览）发现同名（去空格、不分大小写）时显示成「名称（地区 · ID）」，出口页卡片另有「同名」标签，新建 / 编辑时提示已有同名组；只有一个时显示原名 |
| `members` | 成员出口 ID，按用户排的顺序。一个出口可以属于多个组 |
| `mode` | `auto`（自动）或 `manual`（手动） |
| `chosen` | 手动模式下用户指定的成员；自动模式必须为空 |
| `on_failure` | 只在手动模式有意义：`hold`（默认，保持指定成员并告警）或 `fallback`（临时回落到有效顺序里的下一个可用成员并告警，恢复后按自动模式同样的规则切回） |
| `require_residential` / `exclude_residential` / `require_v6` | 组的硬约束（家宽必须 / 家宽排除 / 必须有 IPv6 出口）。前两者互斥 |
| `migrated_from` | 迁移来源，`pool:<旧池名>#<模式>[-resi][-v6]`，迁移重跑靠它认出已有的组 |

`settings.default_group` 是不匹配任何规则的境外流量用的组（原来固定是 `hk` 池）。

规则只能二选一：`target_group`（引用组）或 `target_exit`（显式钉死一个出口）。规则不再有自己的 `mode`；组是手动/自动的唯一事实来源。规则上的 `require_residential` / `require_v6` 保留，但不再是第二个配置点：它们是对所引用组的断言，组没有相同约束时校验报错（`residential_required` / `constraint_conflict`），不会出现"规则说要家宽、组里却能切到机房"的情况。同时带 `target_group` 和 `mode`、或同时带 `target_group` 和 `target_exit` 的规则被拒绝（`rule_mode_removed` / `rule_target_conflict`）。

### 包装还是替换旧的池

替换。旧的「池」只是节点上的一个名字（`pool` / `pool_priority`），规则用 `target_pool` + `mode` 指向它。地区组是独立对象；迁移后节点的 `pool` / `pool_priority`、规则的 `target_pool` / `mode` 全部清空。这几个旧字段只作为输入保留：旧面板或旧导出再写进来时，读入时立刻并入组（见下），不会形成第二份配置。没有迁移的文档（规则仍带 `target_pool`）校验直接报错 `legacy_pool_target`。

### 迁移

`model.MigrateRegionGroups`，在 `store.Load`（每次读库）和 API 收到整份拓扑（`PUT /api/topology`、带拓扑的 validate/compile/diff）时运行。它是纯内存变换，结果随一次整行写入保存，所以中断不会留下半份数据；对已经迁移的文档再跑是空操作。

1. 每个旧池按原来的首选顺序收集成员：IX 绑定优先，然后 `pool_priority` 小的在前，再按 ID。这就是迁移后组的 `members` 顺序，所以迁移前后有效顺序完全一样（IX 优先、稳定排序）。
2. 指向同一个池的规则按「模式 + 家宽要求 + IPv6 要求」分成变体，每个变体一个组。同池不同模式时生成独立的组，行为不丢：
   - `auto` → 自动组；
   - `pin` → 手动组，`chosen` 是原来的首选成员，`on_failure: fallback`。原来钉死规则用的是首选成员的 mark，而枢纽的链路切换会改这张表的下一跳，所以钉死规则其实会随链路故障临时换到同池备成员、恢复后切回，但不受解锁结果影响。手动 + 回落正是这个行为。
3. 基本变体（优先自动、无额外约束）的组 ID 就是池名，其余是 `池名-pin`、`池名-auto-resi` 这类；与已有 ID 冲突时加序号。没有规则引用的池也生成一个自动组，节点归属不丢。
4. 池 `hk` 的组带 `exclude_residential`（原来 `hk` 池不收家宽）；被要求家宽的规则（`require_residential` 或名字里有 Netflix / Disney）对应的组带 `require_residential`。原来这样的池里若有机房成员会直接报错，所以加约束不改变任何能通过校验的拓扑的行为。
5. `settings.default_group` 为空时设为 `hk` 的自动组。
6. 已有组时，带旧字段的输入并进来：节点的 `pool` 加到所有 `migrated_from` 是该池的组（追加在末尾），规则的 `target_pool` + `mode` 找到对应变体的组，没有就新建。然后清空旧字段。

面板保存的解锁状态（按规则）和链路状态（按名字）不迁移：基本变体的组 ID 与旧池名相同，状态继续可用；新 ID 的组从冷启动开始。

### 有效顺序

`pool.Effective(topology, group)`：

1. 先按硬约束过滤：节点不存在或不是出口（`missing`）、重复（`duplicate`）、组要求家宽而它不是（`residential_required`）、组排除家宽而它是（`residential_excluded`）、组要求 IPv6 而它没有 `egress_v6`（`v6_required`）。被排除的成员留在列表里，`position: -1`，带原因。
2. 剩下的按 IX 绑定优先、其余保持用户顺序（稳定排序）。被 IX 提前的成员带 `ix_first`，因此被往后挤的带 `after_ix`。
3. 枢纽不能直接切到的成员（只能经双栈中继或纯 Mesh 到达）仍可被静态选中，但带 `not_switchable`，不进动态候选。

API 同时返回 `effective_order` 和每个成员的 `reasons`，界面直接用来解释"为什么它排在这里 / 为什么灰掉"。

### 选择（静态编译）

- 自动：有效顺序第一个（`preferred`）。
- 手动：`chosen`（`chosen`）。`chosen` 不在成员里或被约束排除时校验报错 `chosen_not_eligible`；运行时万一出现，就用有效顺序第一个并标 `constraint`。
- 没有可用成员：`none`，引用它的规则校验报错。

自动组里的规则仍按服务跟随解锁映射（`internal/unlock`），只在本组的有效顺序内移动；手动组的规则不受解锁结果影响（只记录）。组的有效首选变了（改顺序、改成员、改约束）时，该服务的解锁状态按新首选重新对齐（`unlock.Reconcile`）：新首选最近一次结果是失败、而组里有已知可用的成员时，保持降级在那个成员上，切回仍要满足完整的恢复条件；对不齐的旧状态不产生任何映射（`unlock.Decisions` 要求状态的首选与当前首选一致）。

### 运行时状态机（枢纽上 `meridian-failover.sh` 的 `group_step`，面板里同一份 `pool.StepGroup`）

每个成员一组滞回计数：连续 3 次失败判死，连续 5 次成功判活（`FailsNeed` / `RecoversNeed`）。另外记录最近一次样本是否成功（`last_ok`）和当前连续成功的起点（`ok_since`，任何一次失败清零）。

- 自动：当前成员判死时立即换到试探顺序里下一个判活的成员；全部 WireGuard 成员判死且该组有待命 Mesh 边时换到 `mmesh`；都没有时不动（靠黑洞兜底，不换国家）。切回首选需要同时满足：首选判活、最近一次样本成功、`ok_since` 起连续成功满 120 秒、距上次切换满 120 秒。首选任何一次失败都清空恢复计时，当前不健康（最近一次样本失败）就不切回——即使它在滞回意义上仍是「活」的。
- 手动 + `hold`：永远停在 `chosen`，不切到别的成员也不切到 Mesh。`chosen` 判死时状态是 `held`，`alert: true`。
- 手动 + `fallback`：试探顺序是 `chosen` 在前，然后是有效顺序里的其余成员。行为与自动完全相同（包括 Mesh 和切回条件），只是首选换成 `chosen`；离开 `chosen` 期间状态是 `fallback`，`alert: true`，回到 `chosen` 后告警消失。

状态原因（`actual.reason`、`model.reason`）：`preferred`、`chosen`、`failover`、`fallback`、`held`、`mesh`、`constraint`、`none`。枢纽为每个组记录切换器选中的成员（`active`）、路由表里实际的下一跳（`hop`）、原因、上次切换时间和每个成员的计数；面板的推算记录同样的字段和每个成员的健康。两者怎样分开见下面「实际状态与面板推算」。

界面必须显示：

- 自动：当前实际成员；不是首选时显示「故障切换」以及首选为什么还没切回（未判活 / 最近一次失败 / 恢复计时还剩多少）。
- 手动 + 保持：实际成员永远是指定成员；它判死时显示红色告警「指定成员不可用，按设置保持不切换」，并给出改成回落或换成员的入口。
- 手动 + 回落：正常时同「手动」；回落期间显示告警「指定成员不可用，临时使用 X」，以及切回所需条件。

「实际成员」只能来自枢纽报告（`actual.state == "ok"`）；读不到、过期、版本不一致或切换失败时显示「未知」和原因。告警以枢纽报告为准；「首选为什么还没切回」和剩余时间只有面板推算能给出，界面上写作「面板推算还没有切回 …」。

### 实际状态与面板推算（两个来源，分开显示）

每个组的视图（`GET /api/region-groups`、`GET /api/region-groups/{id}`）有两块，互不混用：

- **`actual`：枢纽报告的实际状态。** 只有它能显示成「实际使用」。来自枢纽自己写下的记录，经面板读回（见下）。
- **`model`：面板推算。** 面板用 `POST /api/region-groups/health` 收到的样本按同一规则（`pool.StepGroup`）算出来的（`model.source: "panel_model"`）。输入和枢纽不同步，它从来不是观测结果，界面上一律标「面板推算」；没有样本时是「按配置应使用」+「未验证」。成员行上 `model_active` 是推算的成员，`actual_active` 只在 `actual.state == "ok"` 时为真。

**枢纽写什么。** 枢纽 `meridian-failover.sh` 的 `group_step` 每一轮（循环间隔 `sleep 5`，`compile.HubLoopInterval`）在切换判断之后调用 `group_record`，它只读内核、只写 `/run/meridian`，不改路由，切换行为与以前完全相同。每个可切换组写 `/run/meridian/group/<id>/report`，先写临时文件再 `mv`（读的人不会看到半个文件）：

```
meridian-group-report 1
group <组 ID>
plan <部署标识>            运行中的脚本的 GROUP_PLAN
beat <epoch>               本轮时间（心跳）
hop <成员 ID | mmesh | blackhole | none | other | split | unreadable>
active <成员 ID | mmesh>   切换器的选择
reason <preferred|chosen|constraint|failover|fallback|held|mesh>
alert <0|1>
switched <epoch | 0>       上次成功切换；0 = 启动以来没有切换
result <ok | failed | diverged>
want <成员 ID | mmesh>     只在 result=failed 时：想切到谁
lastfail <成员 ID | mmesh> <epoch>   最近一次切换失败（有过才写）
end
```

`hop` 每轮从内核读（`ip -4/-6 route show table <组表>`）：不算 metric 32767 兜底黑洞的那条默认路由，按它的接口对回成员（`mmesh` 是 Mesh veth）；黑洞默认或只剩兜底是 `blackhole`，表里没有默认路由是 `none`，接口不是成员是 `other`，v4 与 v6 不一致是 `split`。所以它描述的是路由表里真实的内容，不是脚本想要的。`result=failed`：本轮决定切换但 `group_hop` 失败（`active`、`switched` 不变，`hop` 仍是表里原来的成员）；`result=diverged`：表里的内容与切换器的选择不一致（选 Mesh 而 Mesh 未封装、表是黑洞，这是设计行为，不算不一致）。另外服务启动时 `reset_groups` 装好编译目标后写一次 `/run/meridian/group-plan`：`plan <部署标识> <epoch>`。安装时 `meridian-up.sh` 会重启这个服务。

**部署标识。** `compile.GroupPlanID`：枢纽编译出的地区组切换段（组表、成员接口与对端、试探顺序、策略标志和脚本本身）的 SHA-256 前 24 位十六进制，作为 `GROUP_PLAN=` 写进枢纽的 `meridian-failover.sh`。不含任何秘密。面板对当前存储的拓扑算同一个值来比较；与组无关的改动（规则、名单等）不改变它。

**面板怎么读。** `POST /api/region-groups/runtime/refresh` 不接受任何参数（请求体被忽略），目标是拓扑里的枢纽节点，经它关联的受管服务器、用已有的 SSH 连接器（主机指纹必须已确认并固定，凭据在执行边界从凭据库取出，输出去敏）执行一条固定的只读命令 `sshexec.GroupStateCommand`：

```
{ printf 'meridian-group-state 1\nnow %s\n' "$(date +%s)"; cat /run/meridian/group-plan; for f in /run/meridian/group/*/report; do if [ -f "$f" ]; then cat "$f"; fi; done; echo meridian-group-state-end; } 2>/dev/null | head -c 65537
```

总超时 30 秒，输出在枢纽上截到 64 KiB + 1 字节，超过 64 KiB 即判为过大。同一时间只允许一次读取（并发返回 409 `refresh_in_progress`）。结果（或读不到的原因）连同读取时间存进面板数据库，页面重新加载后仍显示，并标明读取时间。枢纽打出来的东西只按含义采信（`internal/hubstate`）：逐行严格语法、只允许可打印 ASCII、值是受限字符的短标记、时间必须晚于 2020-01-01 且不晚于枢纽自己的 `now` 5 秒、`switched` 不晚于心跳；任何一行不合格整份拒绝（`parse_error`）。拓扑里没有的组 ID 不显示（`hub_state.last_read.ignored`）；成员 ID 必须在该组编译出的切换顺序里（`mmesh` 只在组有 Mesh 边时），否则这个组是 `invalid_report`。

**读取结果绑定枢纽身份。** 每次读取都记下它是从哪个枢纽读的（`hubstate.Identity`）：枢纽节点 ID、服务器 ID、规范化后的地址（去空白和方括号、小写、去掉末尾的点，IP 字面量写成规范形式，IPv4 映射的 IPv6 写成 IPv4）、SSH 端口（0 视为 22）和固定的主机指纹。身份在读取开始前从当前拓扑和服务器记录取出（`internal/api` 的 `serverIdentity`；指纹只在主机指纹是「已确认」或「不一致」时算作固定，其余状态为空——改地址或端口、清除或重新发现指纹都会清掉它）。三处用同一个身份：

1. 连接：SSH 连接钉在这个身份上（`sshexec.Target` 带地址、端口、用户和指纹），服务器记录在此期间被改过、或主机出示的不是这把钥匙，连接器拒绝（`target_changed` / `host_key_not_pinned_by_deployment`），不会以旧身份读到新主机。
2. 存储：读取结束后重新取当前身份；与开始时不同，这次结果丢弃、不存为当前状态，接口返回 409 `hub_identity_changed`（「读取期间枢纽的……已变更」），原来存的那次读取保持不变。并发刷新本来就只允许一次（`refresh_in_progress`）。
3. 显示：每次 `GET /api/region-groups`、`GET /api/region-groups/{id}`、概览和解锁矩阵都把存储的读取与此刻的身份比较；任何一项不同，这次读取对每个可切换组都是 `unavailable` / `hub_identity_changed`，没有成员、原因和切换时间，界面显示「实际使用 未知 · 未验证 · 枢纽已变更」和原因，直到对当前枢纽读取成功。这个比较在 10 分钟的 `read_old` 之前，立即生效；它也兜住了「检查之后、存储之前」身份又变化的窗口。主机出示了与固定指纹不同的钥匙（「不一致」）时身份不变，但成功的报告同样不再采信。`hub_state.last_read.current_hub: false` 加 `identity_code` / `identity_message` 告诉界面那次读取不是当前枢纽的，枢纽状态条上标「不是当前枢纽」，并且不受「1 分钟内读过就不自动读」的限制。

改名、改标签或备注不改变身份；把枢纽节点改到另一台服务器、原地修改同一台服务器的地址或端口（即使之后确认的仍是同一把钥匙）、重新确认成另一把钥匙或清除指纹，都会让旧报告立即变成未知。身份变回原样（例如改回原地址并确认同一把钥匙）时，原来那次读取重新与当前身份一致，仍受部署标识、心跳和 10 分钟读取时效的检查。更早版本存下的读取没有地址和指纹，一律视为身份不同。

**每个组的 `actual.state`**（按顺序判定）：

| 状态 | 条件 | 界面 |
| --- | --- | --- |
| `not_switchable` | 组不由枢纽切换（静态选择只能经中继或纯 Mesh 到达，或没有可用成员），枢纽上没有它的状态 | 「不适用 · 枢纽不切换」 |
| `never_read` | 还没有读过 | 未知 · 未验证 |
| `unavailable` / `hub_identity_changed` | 存储的读取不是当前枢纽身份（枢纽节点、服务器、地址、SSH 端口、固定指纹任一不同，或主机指纹现在不一致），见上 | 未知 · 未验证 · 枢纽已变更；可读时「重新读取」，否则链到服务器页 / 拓扑 |
| `unavailable` | `code`：`no_hub`、`hub_no_server`、`server_not_ready`（指纹未确认 / 不一致、没有凭据，带 `ssh_code`）、`ssh_failed`（带 `ssh_code`）、`parse_error`、`state_missing`（枢纽上没有这个组的记录或没有 `group-plan`）、`invalid_report`、`plan_unavailable`（面板编译不出当前计划） | 未知 · 未验证，原因和修复入口 |
| `version_mismatch` | 枢纽的 `group-plan` 或该组报告的 `plan` 不等于面板现在编译出的部署标识（`deployed_matches: false`）：枢纽还没按当前拓扑装机 | 未知 · 未验证，链到部署页 |
| `stale` | `heartbeat_old`：枢纽的 `now` 减心跳超过 `compile.HubStaleAfter`；或 `read_old`：读取已超过 10 分钟 | 未知 · 未验证，重新读取 |
| `switch_failed` | `hop_failed`（`result=failed`）或 `table_diverged`（`result=diverged`，或面板自己核对 `hop` 与 `active` 不一致） | 失败；`reported` 里给出枢纽报告的表内容和想切到的成员，标「枢纽报告（未确认）」 |
| `ok` | 以上都不是 | 「实际使用 X · 原因 · 上次切换 · 读取于」 |

只有 `ok` 带 `active`、`hop`、`reason`、`alert`、`last_switch`、`running_since`；`active` 是成员 ID、`mmesh`，或表是黑洞时为空（`hop: "blackhole"`，界面写明流量被丢弃）。

**过期阈值。** `HubStaleAfter` = 3 × 一轮最坏耗时，至少 60 秒；一轮最坏耗时 = 循环间隔 5 秒 + 每次 ping 至多 2 秒 ×（3 条西向隧道 + 所有可切换组的成员数）+ 10 秒（Mesh 封装检查）。示例拓扑（`defaults.Example`）是 135 秒。阈值和循环间隔在 `hub_state` 里返回给界面。

**时钟。** 心跳和枢纽 `now` 来自同一次读取、同一个时钟，过期判断不受两边时钟差影响。显示的时间按读取时刻换算到面板时钟（枢纽时间 + 读取时刻 − 枢纽 `now`），差值作为 `clock_skew_sec` 返回；超过 300 秒时界面提示。时间合理性检查用的是枢纽自己的 `now`。

**页面。** 「出口」页顶部的「枢纽运行状态」条显示枢纽、服务器、上次读取和「读取枢纽状态」按钮；枢纽读不了时说明原因并链到修复处（拓扑、服务器页）。打开页面时，如果枢纽可读且上次读取早于 1 分钟，自动读一次（每次进入页面最多一次，不轮询）。概览的地区组卡片同样只在 `ok` 时写成员名，其余显示「实际未知 · …」。解锁矩阵里实心圆点只表示枢纽报告在用，空心圆点是面板推算。

**只有真实枢纽能证明的**：枢纽真的按报告切换了流量（报告只说明枢纽内核里组表的内容）；`ip` 在真实内核上的输出被正确解析（隔离 Linux 测试 `TestNetnsGroupDNSFailover` 会核对报告里的 `hop`）；真实 SSH 登录到枢纽和读取路径。见[验收清单](verification.md#地区组和-mesh)。

### 静态编译与动态切换一致

- 每个出口保留自己的 mark、中转地址和枢纽路由表（索引按出口 ID 排序，和以前一样）。这些出口表从此只指向自己的出口，不再被动态改写。显式钉死出口的规则、被解锁映射移到某个成员的规则，都用成员自己的 mark，所以不会被链路切换悄悄带走。
- 每个组另有一个 mark / 中转地址 / 枢纽路由表，索引接在出口后面（按组 ID 排序）。规则和默认流量在组的静态选择可以由枢纽切换时用组的 mark；静态选择只能经中继或纯 Mesh 到达时，退回该成员自己的 mark（没有动态切换，`not_switchable`）。
- 网关：组 mark 和出口 mark 一样进表 102、SNAT 到组的中转地址；`inet meridian_guard` 的出口 mark 范围按实际最大的 mark（出口加组）计算，选择器清理循环也覆盖到同一上限，所以增删组成员和组时兜底表的 mark 范围随编译更新。允许的接口集合是网关自己的 WireGuard 接口，与组成员无关；它不包含 `mmesh`。
- 枢纽：静态路由脚本把组表的默认路由装到编译时的选择上，并清掉该组的运行时状态；切换脚本启动时同样清掉状态并重新装一遍编译时的选择，之后只改组表。两边用同一个 `group_hop` 函数和同一组每成员下一跳（直连 WireGuard 用 `dev <接口>`；Mesh 用 `via $MESH_NH4` / `via $MESH_NH6 dev $MESH_DEV`，并且要先有密封标记，否则黑洞）。表 100、102、150、main 以及任何出口自己的表都会被拒绝。
- 下发：改组只改拓扑，生效要经安装事务（`meridian-up.sh` 会重启 `meridian-failover.service`，让切换脚本拿到新的策略）。枢纽上的切换是安装好的脚本自己做的，地区组没有给 `meridian-host` 增加任何动作。
- DNS 跟随实际成员：可切换组的规则（和可切换的默认组）问组自己的解析地址，查询走组的数据路径，枢纽切到哪个成员就由哪个成员解析，见下一节。钉死出口的规则、被解锁映射移到某个成员的规则、不可切换的组，仍问那个成员自己的隧道解析器。

### 地区组的解析

以前可切换组的规则用编译时首选成员的隧道解析器（`server <首选的 DNSULA> -group g_<首选>`），网关按目的地址把查询送到首选。首选整机或隧道故障时枢纽把组表切到备成员，数据能走，但新名字仍问已失效的首选，切换等于没用。现在组的 DNS 和组的数据走同一条路，网关上不需要任何运行时状态：

1. **保留地址。** `fd66::53:0/112`（在 `fd66::/64` 里）不属于任何节点。组的解析地址是 `fd66::53:<组索引+1>`（组索引就是给组的 mark、中转地址和枢纽表编号的那个；示例里 `us` 组是 `fd66::53:13`，mark `0x113`）。每组一个地址，是为了不让两个 SmartDNS 上游只差 mark、地址相同（SmartDNS 会不会把它们当成同一个服务器，没有核实，干脆避开）。隧道地址分配器从不分配 `fd66::/64`（链路是 `fd66:0:0:<n>::/64`，n ≥ 1；WSS 备腿 `fd66:0:0:<0x80+i>::/64`；中转 `fd66:0:0:ff::/64`），校验（`group_resolver_conflict`）拒绝落在 `fd66::/64` 里的链路隧道地址、中转前缀和 NAT64 前缀；局域网 IPv6 前缀和远程接入地址池本来就不能碰 `fd66::/48`，Mesh 路由由 Mesh 计划拒绝。
2. **网关 SmartDNS。** 每个可切换组一行 `server fd66::53:<k> -group rg_<组> -exclude-default-group -set-mark <组 mark 的十进制>`；只有默认组可切换时它那一行不带 `-exclude-default-group`，成为没命中规则的名字的唯一上游（这时默认组首选出口自己的那行改带 `-exclude-default-group`）。规则指向可切换组时 `-nameserver rg_<组>`。mark 必须写十进制：在真实网关上用 `pymumu/smartdns:latest`（1.2026.11.09）实测，`-set-mark 19824` 和 `server-tcp` 形式都给每个上游包打上了 0x4d70，写成 `-set-mark 0x4d70` 时 SmartDNS 不报错、也一个 mark 都不打。SmartDNS 容器有 `NET_ADMIN`、用宿主网络（`deploy/docker-compose.yml`）。国内 DoT 只在 `domestic` 组里，任何 `rg_` 组只有组自己的解析地址。
3. **网关的出路（本机发出，兜底表不管）。** 兜底表只挂 forward，本机发出的包靠路由层。带组 mark 的查询：`fwmark <组 mark> lookup 102`（v4/v6 都有）→ 表 102 的 IPv6 只有局域网前缀（不含 `fd66`，校验保证）、`default dev <西向隧道>` 和 metric 32767 的黑洞；隧道路由不在时落到黑洞，再后面还有 `fwmark <组 mark> unreachable`。所以带 mark 的组查询只能进西向隧道或被拒，不会查到表 100 或 main，不会经 ROS。没带 mark 的（例如 SmartDNS 没打上 mark）查 main：`fd66::/48 dev <西向隧道>` 加 metric 32767 的黑洞，同样进不了 ROS；它不会被改写源地址，枢纽也就不会把它送进任何组表（运行时测试里它在隧道里绕到跳数用完），所以表现为解析失败，而不是问错成员。
4. **网关的源地址。** 枢纽按源地址选组表，本机查询的源地址是隧道接口地址。`transit_snat` 加一条：`ip6 daddr fd66::53:<k> meta mark <组 mark> meta l4proto { tcp, udp } th dport 53 snat ip6 to <组的中转 IPv6>`。只认组 mark、组自己的解析地址、53。能带组 mark 的只有两种包：分类链打的（只在局域网口和 `mra` 入口上跑，而分类链在任何规则之前就丢弃 `fc00::/7` 目的地址，所以转发流量不可能带着组 mark 去解析地址；兜底表也丢弃转发的 53/853）和本机套接字自己设的。回包由 conntrack 改回原来的隧道接口地址，入站链只限制目的端口 53/853，回包不受影响。`internal/probe` 的探测走另一条路（直接绑在 `lo` 的中转地址上，不需要 SNAT），组的中转地址同样在 `lo` 上，不冲突。
5. **枢纽（没改）。** 组的中转 IPv6 有 `from <中转>/128 lookup <组表>`（优先级 18200+索引，在它前面只有其他中转地址的同类规则）；组表里只有局域网、中转前缀（`fd66:0:0:ff::/64`，不含解析地址）、`group_hop` 装的 `default dev <成员接口>`（v4/v6 一起切）和黑洞。所以发往 `fd66::53:<k>` 的查询进当前成员；回包目的地址是组的中转地址，枢纽 main 里 `fd66:0:0:ff::/64 dev <西向>`，原路回网关。枢纽的 nft 不过滤转发。WireGuard 的 AllowedIPs：西侧对东侧是 `::/0`，东侧对西侧含 `fd66::/48`，正反方向都放行。
6. **出口。** 每个能被枢纽切换到的出口（枢纽直连 WireGuard），在拓扑里有可切换组时，`table inet meridian` 多一个 `group_dns` 链：`iifname { <枢纽隧道> } ip6 daddr fd66::53:0/112 meta l4proto { tcp, udp } th dport 53 dnat ip6 to <本出口隧道解析地址>`（nat prerouting）。目标就是出口 SmartDNS 绑定的 `[<DNSULA>]:53`；回包源地址由 conntrack 改回组解析地址，不依赖解析器怎么选源地址，也不加第二个监听（在 `[::]` 之外再绑具体地址在这个 SmartDNS 上会失败）。出口没有 input 过滤；回包发往组的中转地址，出口路由 `fd66:0:0:ff::/64 dev <隧道>`，与组数据的回程相同。整个 `/112` 都应答，所以出口加入别的组时不用改出口配置；从 WAN 或别的接口进来的不改写。Mesh 入口 `mmesh` 只在组的 Mesh 解析成员上改写，见下一条。
7. **组在 Mesh 上。** 每个有 Mesh 边的可切换组有一个 **Mesh 解析成员**（`GroupPlan.MeshResolver`）：组的有效顺序里第一个与枢纽有待命 Mesh 边、并且有隧道解析器的成员（示例里 `us` 组是 `us`，`hk` 组是 `hk-ix`）。组切到 `mmesh` 后，查询走和组数据相同的 Mesh 路径，由这个出口应答：
   - **发布。** 这个出口编译出的 `meridian-mesh-up.sh` 带一行 `# meridian-mesh-publish fd66::53:<k>/128 group=<组>`。面板的 Mesh 部署（`mesh.BuildPlan`）把它当作这个出口的 Cloudflare 路由发布（`purpose: "group_resolver"`），和运营者在 `mesh_routes` 里填的路由并列；`fd66::/48` 仍然不能手填。发布行只能是 `fd66::53:0/112` 里的单个 /128，并且每个地址只交给一个出口，否则计划报 `mesh_publish_invalid` / `mesh_route_overlap`。改了组或 Mesh 边之后，要重新下发这个出口并重新部署 Mesh（`APPLY_ORDER.txt` 写明）。
   - **枢纽去程。** 组表是 `default via fe80::66:2 dev mmesh`（只在 `/run/meridian/mesh-sealed` 存在时，否则黑洞），和组数据同一条；枢纽 sidecar 的表 170 里是 warp 设备上的 `fd66::53:<k>/128`（发布后重新密封时复制）。`group_step` 停留在 Mesh 上时每一轮都重新执行 `group_hop`（不算切换，不改 `active` / `switched`），所以组表跟着密封状态走：sidecar 密封后转到它的下一跳，失去密封后下一轮就回到黑洞。以前组在未密封时切到 Mesh，之后即使密封了，组表也一直是黑洞。
   - **出口入口。** Mesh 解析成员的 `group_dns` 多一条 `iifname "mmesh" ip6 daddr fd66::53:0/112 … dnat ip6 to <本出口隧道解析地址>`。出口只认这两个受管入口（枢纽隧道和 `mmesh`），别的接口进来的不改写。
   - **出口回程。** 回包不能按目的地址查表：查询到达出口时的源地址可能是组的中转地址（主路由表里指向已经失效的枢纽隧道），也可能是枢纽 Mesh 节点的地址（出口没有路由，会落到 WAN 默认路由）。所以从 `mmesh` 进来的查询连接打 ct mark `0x4d6d`，在 input 上把源地址改成 `fd66::4d:1`（`fd66::/64` 里不属于任何节点的锚地址），解析器的套接字发回包时就命中 `to fd66::4d:1 lookup 171`；route 类型的 output 链给这个连接的每个回包打 mark `0x4d6d`，conntrack 把目的地址还原后仍按 `fwmark 0x4d6d lookup 171` 走。表 171 只有 `default via fe80::66:2 dev mmesh`（只在密封时）和 metric 32767 的黑洞：回包只回到本机的 sidecar，从不进枢纽隧道，也不从 WAN 出去。表 171 由 `mesh_dns_return` 维护，路由脚本和 `meridian-mesh-up.sh` 共用同一段（后者在每次退出时执行）。出口没有故障切换循环，所以多一个 `meridian-mesh-seal.timer`，每分钟重新密封一次，让 sidecar 表 170 学到 Cloudflare 在 sidecar 启动之后才装上的路由；面板 Mesh 部署的 activate 阶段也先重新密封这些出口，再重新密封枢纽。
   - **回到枢纽。** 出口 sidecar 从 `mmesh-c` 收到的回包按表 170 走 warp 设备，目的地址是查询到达出口时的源地址。枢纽 sidecar 把进入 Mesh 的流量做源地址转换（compose 里的 `SRCNAT_ENABLED=true`）时，这是枢纽 Mesh 节点的地址，表 170 有它的路由；不做转换时是组的中转地址，Mesh 里没有它的路由，回包在出口 sidecar 不可达，查询超时。组的 Mesh 数据回程依赖的是同一个性质。Cloudflare 连接器在这里到底做不做源地址转换、IPv6 能不能经 Mesh 转发，**没有核实**。
   - **失败。** Mesh 不通、sidecar 未密封、组没有 Mesh 解析成员（例如组里有 Mesh 边的成员都没有隧道解析器，枢纽路由脚本的注释会写明）时，查询超时或不可达：不改问国内、别的成员或别的国家，也不从局域网口出去。
   - **证据。** 结构测试（`TestGroupDNSExitDNAT`、`TestGroupDNSMeshResolverPublication`、`TestGroupDNSMeshReturnPath`、`TestGroupDNSMeshReturnFollowsSeal`、`TestHubGroupOnMeshFollowsSeal`、`internal/mesh` 的 `TestPlanPublishesGroupResolvers` 等）只证明生成结果。`TestNetnsGroupDNSFailover` 的第 7–9 阶段在命名空间里用编译出的 `meridian-mesh-up.sh`、两个替身 sidecar 和一个模拟的 Mesh（两个 tun 设备）跑完整条路径，2026-11-13 在一台 Debian 13 上通过（`docs/evidence/2026-11-13-debian13-mesh-dns/`）；它模拟的源地址转换是假设。没有任何真实 Cloudflare Mesh 证据。
8. **手动组。** `hold`：组表永远指向 `chosen`，DNS 也只问它，它坏了解析和数据一起失败。`fallback`：和自动组一样跟随切换。
9. **远程接入设备** 的 DNS 被劫持到同一个网关 SmartDNS，行为与局域网客户端相同。
10. **升级顺序。** 网关装上这一版后，组的查询发往只有重新下发过的出口才会应答的地址；还没更新的出口不应答，组内名字解析失败（不会回落到旧的「问首选成员」的做法——那正是要修的不一致）。所以先下发出口和枢纽，再安装网关（「下发顺序」，面板「部署」页的推荐顺序同样写了）。编译无法知道远端已经是哪一版，所以不出校验问题；`APPLY_ORDER.txt` 在有可切换组时写明这一点，`meridian-verify.sh` 的 `PENDING-HUMAN group_dns_failover` 要求实测。

没有可切换组的拓扑，编译结果里没有这些行（测试 `TestGroupDNSAbsentWithoutSwitchableGroup`）。运行时测试 `TestNetnsGroupDNSFailover`（见[验收清单](verification.md#地区组的解析)）在网络命名空间里用编译出的网关、阿里云、枢纽、两个成员出口的 nft 和路由以及枢纽的 `group_step` 跑完整条路径；成员之间的切换部分 2026-11-13 跑通过一次（见 `docs/evidence/2026-11-13-debian13/netns-group-dns.log`）；之后加入的 Mesh 阶段（第 7–9 阶段，替身 sidecar 和两个 tun 之间的转发，不是真实 Cloudflare Mesh）在同一天晚些时候连同前 6 个阶段跑通过一次（见 `docs/evidence/2026-11-13-debian13-mesh-dns/netns-group-dns.log`），那次第一遍运行发现编译出的 `meridian-mesh-up.sh` 把封装成功与失败判反，修好后才通过。成员出口上的解析器在测试里是替身，真实出口、真实枢纽和真实 Mesh 上的行为仍是待人工签收。

### 兼容

`GET /api/pools` 和 `POST /api/pools/health` 保留，数据来自地区组（`id` 是组 ID，`priority` 是用户顺序里的位置）。面板已经重建（见「面板信息架构」），地区组在「出口」页用 `/api/region-groups` 编辑；这两个旧接口只为旧脚本保留。

## Mesh

### 面板部署与撤回

`POST /api/mesh/deploy` 的请求只有 `{account?, fail_after?}`：`account` 是存储里的 Cloudflare 账户 ID，省略时用当前选为 Mesh 的账户（都没有时 409 `no_mesh_account`）；给出的账户与当前选择不同时，部署在部署锁内、确认没有绑定中的部署后把它选为 Mesh 账户。响应带 `account: {id, name, account_id, source: "request"|"selected", permission_check}`。计划里每个节点只经它关联的服务器连接（地址、端口、用户、凭据、已确认指纹都从服务器取）；计划本身有效时，任何节点没有服务器、没有凭据或指纹未确认都 409 `servers_not_ready`（附 `not_ready` 列表），一个阶段都不执行。`GET /api/mesh` 另给 `plan_servers`（每个节点的 `server_id`、`ready`、`missing`、将要固定的 `host_key`）和 `mesh_account`。

部署记录（`DataDir/mesh/deploy.json`，schema 3）在开始时为每个计划节点固定 `server_id`、`credential_id`、地址、端口、用户和服务器已确认的指纹，记录账户 `account_id` 和 `account_ref`（存储里的账户 ID）。之后部署的每一步和撤回都只连这些固定目标：连接器要求服务器当前的地址 / 端口 / 用户与固定值一致（否则 `target_changed`），服务器信任的指纹与固定值一致，握手看到的也是这个指纹。

`POST /api/mesh/withdraw` 不接受任何字段：账户按记录绑定（当前 Mesh 账户的 account id 必须相同，否则 409 `account_mismatch`），主机按记录固定。撤回前先在部署锁内升级旧记录，再检查每台还没恢复的主机：固定的服务器和凭据都还在、服务器仍指向固定的地址。任何一台不满足都 409 `hosts_blocked`，列出原因，**什么也不撤回、不标记任何东西为已移除**。凭据原地轮换不影响撤回（读的是同一 ID 的当前一代）；删除或改指向被存储拒绝（见「服务器、SSH 凭据与 Cloudflare 账户」）。旧请求字段 `private_key_pem`、`trust_new_host`、`nodes`、`ssh_*`（撤回另有 `fail_after`、`account`）一律 400 `field_removed`。

节点撤回与 Mesh 撤回的先后见「撤回与失败后的恢复」→「与 Mesh 的组合」：Mesh 还固定着某个节点的主机时，那个节点不能撤回。

schema 2 → 3 升级（`Deployer.UpgradeJournal`，启动时和每次撤回前运行，可重复）：只处理 `server_id` 为空的固定主机；按「节点当前关联的服务器且地址 / 端口 / 用户一致」→「`migrated_from: node:<ID>` 且一致」→「唯一一台地址 / 端口 / 用户一致的服务器」找服务器，凭据取它当前的凭据；`owned remotes` 里的副本同步更新。找不到的保持为空，撤回时被 `hosts_blocked` 挡住，用户在服务器管理里补上同一台主机后重试即可。已有 `server_id` 的固定值从不被改写；比本程序新的记录被拒绝（`journal_too_new`）。

Mesh 的 Compose 只生成在枢纽和对应出口上。镜像默认是官方的 `cloudflare/mesh:latest`（Cloudflare Mesh 节点，原先的 WARP connector）。要钉版本就在拓扑里写 `mesh_image`，例如 `cloudflare/mesh:2026.10.0` 或带 `@sha256:` 的摘要，不要另起一个不存在的名字。容器要 `NET_ADMIN`、`NET_RAW`、`/dev/net/tun`、`SRCNAT_ENABLED=true`，卷在 `/var/lib/cloudflare-warp`，并且打开 IPv4 转发和 IPv6 `all` / `default` 转发。网络是自己的 `meridian_mesh`，不是 host 网络。令牌放在 `/etc/meridian/mesh.env`（权限 0600），仓库里只有空的示例。

家宽网关的启动脚本和故障切换都不会拉起这个 sidecar；脚本若发现本机有 `192.168.100.88/24` 会直接退出。枢纽脚本如果被要求把 Mesh 装进表 100、102、150 或 main，会拒绝。这三张表仍是国内、境外主路径和 IX 东向，Mesh 进不去。

`mmesh` 是一根 veth（`169.254.66.0/30`，不落在隧道的 `10.66.0.0/16` 里）。宿主只在「sidecar 已密封」之后，才让某张出口表的默认路由指向它。密封做在容器自己的网络命名空间里：从这根 veth 进来的包走优先级 17000 的表 170，里面只有 WARP 设备上的路由，默认是 unreachable；转发出去时，除了 WARP 设备以外一律 drop。这样容器里那条 docker 网桥默认路由（会 NAT 到宿主机的 WAN，在枢纽上就是 VPS 的默认路由）带不走客户流量。WARP 还没装上到对端的路由时，这张表保持黑洞，而不是改走别的国家。要让备路真正通，需要在 Cloudflare 里为这条枢纽到出口的跳发布路由；没有这条路由，流量停在黑洞里。表 170 的路由是密封时从 warp 设备复制的：`ip route show dev <warp>` 的输出不带 `dev`，复制时补上（以前没补：按 iproute2 的输出格式，链路作用域的路由加不进去，表 170 实际上只剩 unreachable；这一点和修正都还没在真实 sidecar 上看过）。另一个从 5b01903 起就有的错误：`meridian-mesh-up.sh` 判断 sidecar 内密封块结果的条件是反的（`if ! nsenter … bash -s`），密封块成功时报「mesh seal failed」并解除密封，失败时反而去 ping 下一跳并写 `mesh-sealed`。2026-11-13 的命名空间测试第一次运行编译出的脚本时暴露，已改正，`TestMeshUpSealFollowsSidecarBlock` 在 bash 里带桩运行脚本并锁住它。在这之前，任何真实部署都不可能得到正确的密封状态。枢纽每 5 秒重新密封一次（故障切换循环）；是某个地区组 Mesh 解析成员的出口靠 `meridian-mesh-seal.timer` 每分钟重新密封一次（见「地区组的解析」第 7 条）。

## 解锁

出口上的 timer 每 6 小时跑一次；面板也每 6 小时经 `meridian-host` 自己探测一轮（见下文）。流媒体调用独立容器 `lmc999/regioncheck:latest`（AGPL，不链进面板）。官方镜像的入口是 `bash -lc /check.sh`，额外参数进不去，不带参数时会停在交互菜单上，所以探测脚本改用 `--entrypoint /check.sh`，并传 `-R 66`（全部平台）以及 `-M 4` / `-M 6`。镜像名可以用 `regioncheck_image` 换成你核对过的标签。出口脚本里的 AI curl 只做到达性探测（HTTP 状态码），面板只记录、不推动解锁状态机（既不降级也不恢复）。面板探测的检测方法、证据分级和每个适配器的能力声明见 [unlock-methods.md](unlock-methods.md)；所有适配器都只在合成样本上测试过，真实平台待人工核对。结果里如果写了 `Region:`，必须和出口自己的地区一致，否则算失败，避免目录地区被悄悄换掉。

连续两次定时失败才把自动规则改到同池的下一个成员。备成员自己再连续两次定时失败，就换同池里下一个还能解锁的，没有的话标成不可用并回到首选，不改国家。手动测试和健康变化不计入这两次。钉死的手动规则不进这张映射。切回首选需要首选当前健康（面板收到的首选最新结果是成功，且是 30 分钟内收到的），并且从最后一次失败之后的第一次成功起连续成功满 30 分钟；首选任何一次失败都会把这段恢复计时清零。这些时间都用面板自己的时钟，报告里的 `at` 只用于排序和有效期（早于收到时间 1 小时以上即拒绝），不能把冷却提前用完。报告按服务、出口和地址族排序，迟到的旧结果、重复报告和过期报告只记入历史，不改状态；规则见 `internal/unlock/report.go` 和[验收清单](verification.md)「切回判定与报告规则」。映射变化后要在面板里下发，数据面才会换成新的 mark。

面板自己的探测（「解锁 → 面板探测」的立即测试，以及面板每 6 小时的定时）不在面板进程里发流量，也不再运行外部命令（`MERIDIAN_UNLOCK_EXEC` 已删除）：面板经 `meridian-host` 的只读 `/v1/probe` 请求一次「一个出口 + 一个地址族 + 目录表里的服务」，agent 用该出口的 fwmark 和 `lo` 上的中转地址建连（只用 `tcp4` 或 `tcp6`），名字经出口的隧道解析器解析，每条连接先确认路由出口是 Meridian 隧道，访问平台前后都用固定的出口检查确认实际公网地址和地区属于该出口；确认不了就是「探测失败」，不回落到默认出口或另一个地址族，也不当作平台结论。结果经 `unlock.Ingest` 入库，定时记为 `scheduled`、手动记为 `manual`，所有地址族都没有平台结论时记为 `inconclusive`（不计失败次数，但清掉首选的恢复计时）。`activate` / `rollback` 会先取消正在跑的探测，执行期间不接受新探测。细节、限制和仍需人工核实的平台行为见[验收清单](verification.md#面板发起的解锁探测)。

出口上的定时探测（regioncheck 容器，覆盖面板没有适配器的台湾、日本平台）仍然可用；要把结果送回面板，把口令写进该出口的 `/etc/meridian/unlock-report.env`（0600），URL 固定是编译出来的网关地址，不会跟着这个文件改。出口报告不再推动面板的下一次定时。

## 纯 IPv6 和 v6 入 v4 出

枢纽 `path_v6=false`。只选了绕行名字、没有把链路接上，仍然拒绝保存。

- 双栈中继：枢纽用 v4 WireGuard 连中继，中继用 v6 去拨纯 v6 出口的 `EndpointV6`（示例是 `2001:db8::70`）。内层 ULA 从枢纽的一条 /128 主机路由进中继，再进出口，然后 NAT66。这条路径仍经过 IX。
- Mesh：纯 v6 或「v6 入、v4 出」没有 v4 隧道时，枢纽只在该出口自己的表里把默认路由指向 `mmesh`，而且要先有 `/run/meridian/mesh-sealed`。设备不存在或还没密封就黑洞，不落到别的默认路由，也不从枢纽的 WAN 出去。
- v4 前置：出口填一个文档用的 IPv4 端点，枢纽按普通 v4 WireGuard 去拨。这是把纯 v6 主机变成 v4 可达，不是让枢纽自己拥有 IPv6。

## NAT64

枢纽上有 `nat64.reserved.conf`。`enabled=false` 时前缀为空。即便在面板里打开，路由脚本也不安装这个前缀，IPv4 默认路由保持原样。真正的转换器要等以后单独做。

## 远程接入（WireGuard 回家）

出门在外的手机、笔记本经一个独立的 WireGuard 接口连回家里的网关。网关只把它当作和局域网同等的第二个受管入口：同一套分类、DNS 劫持、策略路由和 `inet meridian_guard`，国内直连、境外走隧道、未分类拒绝。默认关闭；关闭（或拓扑里没有 `remote_access`）时，所有节点的编译产物与没有这个功能时逐字节相同。

### 决定

| 事项 | 选择与理由 |
| --- | --- |
| 接口名 | 固定 `mra`。host agent 的接口校验只多认这一个名字（`^(m[0-9]{2,3}w?\|mmesh\|mra)$`），不和 `mNN` 隧道或 `mmesh` 冲突。它**不**算网关的隧道接口：境外 mark 永远不能从 `mra` 出去。 |
| 网关侧私钥 | 单独一把，不复用网关节点私钥。设备配置（会被截图、扫码、转发）里写的是这把公钥；轮换骨干节点私钥不会让所有手机配置失效，反之亦然。私钥放在受限凭据存储（`internal/credentials`，0700/0600），拓扑里只有它的公钥和存储 ID；编译产物、快照、预览、差异和 API 里只有占位符 `__MERIDIAN_SECRET_<id>__`，只在安装边界（`apply.Applier.Secrets`）写进 0600 的 `/etc/wireguard/mra.conf`。 |
| 设备私钥 | 在面板进程里生成（与节点密钥同一种 X25519 生成方式），只出现在创建或重新生成的那一次响应的完整客户端配置里，不落盘、不进日志、不进拓扑和快照。之后 API 只给公钥和元数据，`config_available` 恒为 `false`；要再拿配置只能「重新生成」，旧公钥在下一次安装后从网关上失效。 |
| 预共享密钥（可选） | 每台设备一把，放受限凭据存储，拓扑里只记存储 ID；网关配置里是占位符，安装边界注入；客户端配置只在那一次响应里带它。重新生成时换新的一把（新 ID）。旧 ID 在没有任何快照、已安装副本或拓扑再引用之后才删除，所以失败补偿和回滚仍能写回上一份 peer 集合。 |
| 地址 | 设备池默认 `10.67.0.0/24` 与 `fd67::/64`，都在现有私有规划（`10.66.0.0/16`、`fd66::/48`、`169.254.66.0/30`、`100.96.0.0/12`、局域网）之外；校验要求 IPv4 池在 RFC1918 内、IPv6 池在 `fc00::/7` 内，并证明它们与局域网 v4/v6、`10.66.0.0/16`、中转前缀、`fd66::/48`（及 `ula_prefix`）、Mesh `169.254.66.0/30`、Cloudflare `100.96.0.0/12`、NAT64 前缀、每条链路的隧道地址、CIDR 规则、Mesh 路由、ROS 地址和公网端点都不重叠。网关自己用池里的第一个地址（`.1` / `::1`），也是设备的 DNS。每台设备取最小的空闲主机号（从 2 起），v4 和 v6 用同一个主机号；地址存在设备记录里，设备存在期间不变（重新生成也不变），删除后才可能给新设备。池有设备时不能改池。 |
| 上限 | 最多 64 台设备。 |
| 设备之间 | 不互通：从 `mra` 进、再从 `mra` 出的包被守卫丢弃。 |
| 零设备 | 打开功能就创建接口并监听端口（没有 peer，什么都进不来）；这样端口转发可以先验证，加设备只改 peer。 |
| 关闭功能 | 下一次安装删除 `mra.conf`、接口（经受管清单由 host agent 删除）、全部 `mra` 相关 nft 规则、入站端口放行和启动脚本里的那一段。设备记录、网关私钥和预共享密钥留在面板，重新打开后原配置继续可用。旧池的黑洞路由留到下次重启，它只作用于不再使用的私有前缀。旧版本装的 `iif mra unreachable` 规则不论开关都由路由脚本删除（见「局域网兜底」）。 |
| Endpoint 与端口 | 必须由用户填写（DDNS 名或地址），面板不猜公网地址，也不碰路由器。端口不得与网关上任何隧道监听端口、WSS 失败切换腿端口、wstunnel 本地端口、WSS 监听端口、面板端口、22/53/67/68/123/546/547/853/5353 冲突。API 返回需要在路由器上做的转发说明（UDP、外部端口、网关局域网地址、内部端口），IPv6 直连则需要路由器防火墙放行到网关全局地址的同一 UDP 端口。 |
| 客户端模式 | `full`（全隧道）：`AllowedIPs = 0.0.0.0/0, ::/0`，DNS 指向网关。`home`（仅家网）：`AllowedIPs` 只有局域网 v4/v6 前缀和网关的两个 DNS 地址，DNS 仍写网关。仅家网模式不接管客户端的公网流量，也不保证接管它的全部 DNS（是否把所有查询交给隧道 DNS 取决于客户端系统），所以 Meridian 的分流和防泄漏规则对那部分流量不起作用。默认 `MTU = 1380`、`PersistentKeepalive = 25`。 |
| 运行时状态 | 每台设备的最近握手和流量经 host agent 无参数的只读动作 `/v1/remote-access/status` 读取（见下面 API 表）；读不到时 API 给出原因，不伪造数值。 |

### 数据面

只在打开时出现，全部写在网关的 `meridian.nft`（一个 nft 事务）、早启动的 `meridian-guard.nft`、`meridian-routes.sh` 和 `meridian-up.sh` 里：

- **守卫**（`inet meridian_guard`，forward，优先级 -200）：入口集合从 `iifname "<LAN>"` 变成 `iifname { "<LAN>", "mra" }`，规则不变——DNS/DoT 转发一律丢；国内 mark 只能从局域网口出去；出口与地区组 mark 只能进网关的 WireGuard 隧道接口（`mra` 不在其中）；其余全丢。之前多两条窄放行：`iifname "<LAN>" oifname "mra" ip daddr <设备 v4 池> return` 和 v6 同样一条，用于家里主机访问设备以及国内直连流量的回程。设备访问家里主机走的是「国内 mark 从局域网口出」那条，不需要额外放行。设备之间、设备到 `mra` 都没有放行。`iifname` 按名字匹配，接口还不存在时规则照样加载，不会失败也不会放行任何东西。
- **分类**：`prerouting` 对两个入口都 `jump classify`。`classify` 开头先把目的地是设备池的包标成国内 mark（于是走表 100 里那条 `dev mra` 路由，守卫只在入口是局域网口时放行），然后与局域网完全相同：局域网 IPv6 前缀是 ULA 时，它在 `fc00::/7` 丢弃之前被标成国内 mark（只这一个前缀），所以设备访问家里的 ULA 主机和家里主机的回程都不会被 ULA 丢弃挡住；其他 ULA 照旧丢弃（见「为什么网关要做一次中转地址改写」后面的分类顺序）。
- **DNS**：`dns_hijack` 对 `mra` 进来的 53/853 做同样的重定向（目标是 `mra` 上的网关地址，SmartDNS 已经绑在 `[::]`）；`input` 链「DNS 只给局域网」的源地址白名单加上两个设备池；DoH 地址的 443 在转发链上同样拒绝。面板端口仍只对局域网开放，设备不能访问面板。
- **入站端口**：`input` 链 `iifname "<LAN>" udp dport <端口> accept`，随后 `udp dport <端口> drop`（只在局域网口接受，包括经 ROS 转进来的 IPv6）。
- **地址改写**：境外：`transit_snat` 对设备池源地址按每个出口/地区组 mark 改写到同一中转地址（v4 和 v6），上游只见中转地址。国内直连和访问家里主机：`oifname "<LAN>" ip saddr <设备 v4 池> masquerade`、v6 同理（ROS 没有回设备池的路由；局域网客户端本来就在 ROS 的子网上，所以对它们不加改写，行为不变）。
- **MSS**：`mss` 链对进出 `mra` 的 SYN 按 `mra` 的 MTU 夹到 MTU-40 / MTU-60。
- **路由**：主表和表 100 各有 `<池> dev mra` 与同前缀的 `blackhole … metric 32767`（接口不在时不会落到 ROS）；没有 `iif mra unreachable`（它会让经 `mra` 转发出去的 IPv4 过不了源地址校验，见「局域网兜底」），来自 `mra` 的未分类流量由守卫丢弃。策略规则不变：国内 mark → 表 100，境外 mark → 表 102，之后 unreachable。
- **启动顺序**：`meridian-up.sh` 不变的顺序——先 `nft -c` 再 `nft -f`（守卫和主表同一批）、确认守卫在、等局域网、开转发，然后才拉 WireGuard。`mra` 放在接口列表第一个（先占住监听端口），存在就 `wg syncconf`（删掉的 peer 立即从运行接口上消失），不存在就 `wg-quick up`；随后把 `mra` 的地址和 MTU 对齐到配置（`syncconf` 不改地址）、打开 `mra` 的 IPv6 转发，最后跑路由脚本。早启动的 `meridian-guard.service` 加载的守卫文件里已经带 `mra`，所以开机时在主表加载之前，设备流量同样只会被丢弃。
- **加载失败**：两张表在同一批里，失败时内核整批回退，旧守卫和旧分类都在；启动脚本在此停下，不碰路由、转发和接口。

### 设备生命周期与撤销

设备的增删、停用、重新生成只改拓扑（`apply_required: true`），经 `POST /api/apply` 的受管事务生效：`mra.conf` 的新 peer 集合写入（0600，注入私钥和预共享密钥），`meridian.service` 重启跑 `meridian-up.sh`，`wg syncconf` 把运行中的 peer 集合换成文件里的那一份——停用或删除的设备在这一步就从接口上消失。激活或健康检查失败时事务补偿：写回上一份 `mra.conf`（预共享密钥仍在存储里），再激活一次，运行中的 peer 回到之前的集合。关闭整个功能时 `mra` 不在新清单里，host agent 先删除接口再写文件。

### API

`internal/api/remote_access.go`。错误体是 `{"error","code","field"?,"in_use_by"?}`；改动都返回 `apply_required: true`，经 `POST /api/apply` 生效。

| 方法与路径 | 说明 |
| --- | --- |
| `GET /api/remote-access` | `settings`（enabled、endpoint、listen_port、ipv4_prefix、ipv6_prefix、mtu、keepalive、interface、gateway_ipv4/ipv6、dns、public_key、max_devices、device_count、defaults、modes 说明）、`router_forward`、`devices`、`issues`（按已启用校验的问题列表） |
| `PUT /api/remote-access` | 部分更新上述设置。打开时必须已有 endpoint 和端口（`remote_not_configured`）；第一次保存生成网关密钥。校验错误码：`remote_endpoint`、`remote_port`、`remote_port_conflict`、`remote_prefix`、`remote_prefix_conflict`、`remote_mtu`、`remote_keepalive`、`remote_lan_interface`；池里有设备时改池是 `in_use`（409，列出设备）。 |
| `GET /api/remote-access/devices`、`GET …/{id}` | 设备元数据：id、name、notes、mode、enabled、public_key、ipv4、ipv6、preshared_key（布尔）、时间戳、`config_available: false`、`config_outdated`、`runtime`、`runtime_state`；响应另带顶层 `runtime`。运行状态经 host agent 无参数的 `POST /v1/remote-access/status` 读取（只跑 `ip -o link show dev mra`、`wg show mra latest-handshakes`、`wg show mra transfer`，从不 `dump`），按公钥匹配：`runtime: {last_handshake_at（无握手为 null）, rx_bytes, tx_bytes, online（180 秒内有握手）}`；`runtime_state` 为 `ok`、`disabled`、`not_installed`（接口上还没有这个 peer）、`unavailable`、`not_read`（增删改的响应不读运行状态）。顶层 `runtime: {available, state: ok\|disabled\|agent_unavailable\|interface_absent\|error, reason, interface, read_at}`。读不到时不编造数值。 |
| `POST /api/remote-access/devices` | `{name, notes?, mode?: full\|home, enabled?: true, preshared_key?: true}` → 201 `{device, config:{text, filename, mode, explanation, shown_once:true}, router_forward, apply_required}`。`config.text` 是唯一一次带私钥（和预共享密钥）的完整配置，二维码由面板从这段文字生成。上限 `remote_device_limit`，池满 `remote_pool_full`。 |
| `PATCH …/{id}` | `{name?, notes?, mode?, enabled?}`；不返回配置。改模式只影响下一次重新生成的配置（`config_outdated` 变真）。 |
| `DELETE …/{id}` | 删除设备；下一次安装后 peer 从运行接口消失。 |
| `POST …/{id}/regenerate` | `{preshared_key?}`（缺省沿用原设置）→ 新密钥对、新预共享密钥，地址不变，响应同创建（200）。旧公钥下一次安装后失效。 |

带配置的响应有 `Cache-Control: no-store`。`PUT /api/topology` 不改 `remote_access`（以存储里的为准），远程接入只经这组接口修改。

### 验证状态

结构测试在 `internal/compile/remote_access_test.go`（守卫按包逐条求值、分类、DNS、入站端口、地址改写、路由、启动顺序、关闭时逐字节相同）、`internal/apply/txn_test.go`（peer 随事务增删、失败补偿回到上一份 peer 集合、关闭功能删除接口、缺密钥在写文件前失败）和 API 测试里。`internal/compile/ula_lan_test.go` 对 ULA 局域网前缀按包求值分类链和守卫（设备 ↔ 家里主机双向放行，`fd66::/48`、中转 /64、相邻的 ULA 和其他 ULA 仍丢弃，规则恰好等于配置的前缀；GUA 前缀时分类链不变）。`TestNetnsULALANHomeAccess`（Linux、root、`MERIDIAN_NETNS_TEST=1`，与 `TestNetnsReloadNoLeak` 共用同一套命名空间搭建）在真实内核上检查同一件事，2026-11-13 跑通过一次（见 `docs/evidence/2026-11-13-debian13/`）。`TestNetnsReloadNoLeak` 加了远程设备命名空间（`mra` 用 veth 代替 WireGuard），还加了地区组切换阶段（G），只能在 Linux 上以 root 运行；这一版的运行日志已于 2026-11-13 归档在 `docs/evidence/2026-11-13-debian13/`（`netns-reload.log`、`netns-ula-lan.log`）；`docs/evidence/2026-11-12-debian13/netns-reload.log` 是加入远程接入之前的版本，不覆盖它。命名空间里的通过记录不等于真实设备拨入的证据，那仍是待人工签收。网关上的 `meridian-verify.sh` 打开时核对 `mra`、对端公钥、守卫入口、DNS、端口、规则、路由和地址改写，关闭时确认没有 `mra` 接口；手机实测和路由器转发是人工签收项，步骤见 [remote-access.md](remote-access.md)。

## 面板信息架构

面板是一个单页应用（`web/src/App.tsx`，hash 路由），侧边栏按用途分组。每一页只用上面各节描述的 API，不在浏览器里做数据面判断；顶栏按 `GET /api/status` 显示 host agent、安装状态和正在运行的任务。

| 分组 | 页面（hash） | 用途 |
| --- | --- | --- |
| — | 概览（`#/`） | 安装状态（`in_sync` / `changed` / `not_installed` / `invalid` / `unknown`）、host agent、未完成事务、名单 / 解锁 / Mesh 任务的最近状态和下一步该做什么 |
| 网络 | 拓扑（`#/topology`） | 节点、链路和网关设置（局域网口、前缀、NAT64 预留）；节点只按 ID 引用服务器 |
| 网络 | 出口（`#/exits`） | 出口节点与地区组：成员顺序、自动 / 手动、`on_failure`、硬约束、有效顺序与原因、默认境外组 |
| 网络 | 分流规则（`#/rules`） | 规则（目标是地区组或显式出口）与解锁映射 |
| 网络 | 名单（`#/lists`） | 名单源策略、立即更新（经 `meridian-host`）、宿主记录的每个名单的来源 / 时间 / 条数 |
| 资源 | 服务器（`#/servers`） | 服务器、发现与确认主机指纹、连接测试、装机 |
| 资源 | 密钥（`#/keys`） | SSH 凭据（密码、导入或生成的私钥）；只写不读 |
| 资源 | Cloudflare（`#/cloudflare`） | Cloudflare 账户、令牌权限检查、Mesh 账户选择、Mesh 部署与撤回 |
| 接入 | 远程接入（`#/remote`） | 端点、端口、地址池、设备（一次性配置与二维码、重新生成、停用）、路由器转发说明、运行状态 |
| 运维 | 部署（`#/deploy`） | 校验、差分、写入数据目录、安装到本机、回滚（含宿主网络或只回滚数据目录）、宿主事务恢复 |
| 运维 | 解锁（`#/unlock`） | 面板探测（立即测试）、结果与证据分级、出口报告 |
| 运维 | 防泄露（`#/leak`） | 四类检查：生成配置核对（只说明配置包含）、隔离 Linux 集成（永远「未执行」）、人工签收（永远「待人工签收」）、已知限制；任何一项都不证明不泄露 |
