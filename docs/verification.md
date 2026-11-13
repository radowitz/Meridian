# 验收清单

在[测试设备](test-device.md)上做。网关和 DNS 都已经指向 `192.168.100.88`，IPv6 默认路由指向网关的链路本地地址，路由器发现已关闭。

## 证据的三种等级

整份清单只用下面三种说法，不混用：

| 等级 | 是什么 | 谁来跑 | 能说明什么 |
| --- | --- | --- | --- |
| **自动化回归** | `go test ./...` 里的单元/脚本测试，以及面板「防泄露」页的「生成配置核对」 | CI、任何开发机 | 生成的文本、脚本控制流和状态机符合设计。**不能**说明规则已经加载到网关，**更不能**说明不泄漏。 |
| **隔离 Linux 集成证据** | netns 测试（`TestNetnsReloadNoLeak`）、`deploy/verify-smartdns.sh`、`deploy/verify-host-exec.sh`、`deploy/verify-mesh-veth.sh`、网关上的 `meridian-verify.sh` | 人在 Linux 主机或网关上以 root 运行 | 只有真的运行过、并把完整日志/证据目录存档后才算数。没有存档就是「未执行」/「未验证」。 |
| **实机人工签收** | 真实测试机上的 DNS 泄漏和 WebRTC、ROS 上的 `fd00::/8` 只读查询、断隧道、抓包；真实出口与地区组切换、真实 Cloudflare Mesh、路由器端口转发、手机蜂窝拨入、流媒体 / AI 平台的真实解锁结果 | 用户或主会话，在真实网络上 | 唯一能支撑「这台测试机在这些条件下没有看到泄漏」的证据。签收时写下日期、拓扑版本、截图/命令输出/pcap 的存档位置。 |

面板「防泄露」页按这三类分组：生成配置核对显示「配置包含 / 失败」，集成项一律显示「未执行」，实机项一律显示「待人工签收」——面板不运行它们，也不会把它们标成通过。发布前三类都要有证据；只有第一类绿，不能写成「已验证无泄漏」。

### 每个命令能证明什么

| 命令 | 证明 | 不证明 |
| --- | --- | --- |
| `go test ./...`（任何平台） | 代码级：模型与迁移、编译出的文本（nft、路由、SmartDNS、WireGuard 占位符）、bash 里带桩执行的生成脚本（`meridian-up.sh`、`meridian-verify.sh`、枢纽 `group_step`）、状态机、API 契约（秘密不出现在响应 / 日志 / 快照 / 编译产物 / 差异、引用阻止删除、迁移、安装 / 回滚事务用模拟宿主）、host agent 的校验与动作顺序 | 规则已加载到任何主机；真实 nft / iproute2 的输出格式；真实 SSH 服务器以外的远端；Cloudflare；任何平台；任何泄漏结论 |
| `go test ./...` 在非 root 或非 Linux 上 | 同上 | `TestNetnsReloadNoLeak` 和 `TestNetnsULALANHomeAccess` 只在 Linux 编译（`//go:build linux`），没有 `MERIDIAN_NETNS_TEST=1` 或不是 root 时**跳过**。跳过不是通过：日志里是 `--- SKIP`，在交付记录里必须写成「跳过（权限不足 / 非 Linux）」。没有 bash 的机器上脚本类测试也会跳过 |
| `npm --prefix web run build` | 面板 TypeScript 类型检查通过、能打包 | 任何运行时行为 |
| `npm --prefix web test`（vitest + jsdom，假 API） | 面板用例：秘密只发送一次且不留在浏览器存储；服务器「发现 → 确认同一指纹 → 测试」流程与指纹不符的处理；被引用时删除被拒并列出引用者；Cloudflare 权限检查显示「写权限未确认」、Mesh「已发布」不显示为可用；名单策略与保留旧版；安装状态指示；地区组排序、手动 / 回落、删除被拒；规则只有一个目标；拓扑节点只选服务器、不发 `ssh_*`；远程接入一次性配置、重新生成、停用删除、运行状态不可用时说明原因；部署失败与补偿、回滚方式；解锁到达性不算解锁；防泄露页集成项永远「未执行」、人工项永远「待人工签收」 | 后端行为（API 是假的）；真实浏览器；可用性 |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsReloadNoLeak`（Linux root） | 隔离命名空间里，生成的 nft 和路由在首次加载、200 次重载、两种加载失败注入、地区组来回切换（含路由脚本重跑）、只剩兜底表时，局域网和远程设备的境外流量不到 ROS | 真实隧道、真实客户端、真实 ROS |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsGroupDNSFailover`（Linux root，需要 python3；2026-11-13 在一台 Debian 13 上跑通，日志在 `docs/evidence/2026-11-13-debian13/netns-group-dns.log`；含 Mesh 阶段的版本同日晚些时候跑通，日志在 `docs/evidence/2026-11-13-debian13-mesh-dns/netns-group-dns.log`） | 命名空间里用编译出的网关、阿里云、枢纽、两个成员出口的 nft 和路由，以及枢纽编译出的 `group_step`：切换前组查询（UDP、TCP）由首选成员应答、数据经首选；首选整机断开（解析器、隧道、WAN）后枢纽把组切到备成员，同样的查询由备成员应答、新连接经备成员；两个成员都断时查询失败；整个过程没有组查询到 ROS 或国内解析地址、没有从局域网口出去、没有不带 mark 离开网关（见「地区组的解析」）。之后加入的第 7–9 阶段（2026-11-13 晚执行过一次并通过，见 mesh-dns 记录）：枢纽和出口 `us` 运行编译出的 `meridian-mesh-up.sh`（对着替身 sidecar 命名空间密封），两个 sidecar 之间用一对 tun 设备模拟 Mesh；组在 Mesh 上时 UDP、TCP 查询由 `us` 经 `mmesh` 应答、回包从 `mmesh` 回去（不进枢纽隧道、不出 WAN），新连接经 Mesh 承载；模拟的 Mesh 断开、或 sidecar 失去密封时查询超时、枢纽组表回到黑洞，同样没有泄漏 | 真实 WireGuard（AllowedIPs 只有单元测试）、真实 SmartDNS 的 `-set-mark`（只在真实网关上用计数器核实过一次，见架构文档）、真实出口、真实 Cloudflare Mesh（连接器是否做源地址转换、IPv6 是否经 Mesh 转发，测试里是假设）和真实 sidecar 镜像 |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsULALANHomeAccess`（Linux root；2026-11-13 在一台 Debian 13 上跑通，日志在 `docs/evidence/2026-11-13-debian13/netns-ula-lan.log`） | 同样的命名空间、局域网 IPv6 前缀换成 ULA，加载一次后：设备 ↔ 家里主机 IPv6 双向有回包；前缀之外的 ULA（含隧道、中转）从设备和局域网客户端发出时到了网关、没有被转发、ROS 一个也没收到 | 同上；GUA 局域网前缀（由上一行覆盖） |
| 网关上 `meridian-verify.sh` | 这台网关此刻加载的状态（见下面「meridian-verify.sh」） | 真实客户端不泄漏；路由器；手机 |

### 已存档的执行记录

| 日期 | 环境 | 范围 | 存档 |
| --- | --- | --- | --- |
| 2026-11-12 | 全新 Debian 13 虚拟机（内核 6.12、nftables 1.1.3、systemd 257），示例拓扑，隧道未握手 | 第二类（隔离 Linux 集成证据）的五个入口各跑通一次，外加首次安装、升级、回滚、重启的手工核对 | [docs/evidence/2026-11-12-debian13](evidence/2026-11-12-debian13/README.md) |
| 2026-11-13 | 同一台主机，从上一版升级；示例拓扑加地区组、远程接入（两个测试设备，没有设备真的拨入），隧道未握手 | 第二类的五个入口在面板重做之后的版本上各跑通一次（netns 测试含远程设备、地区组切换和端到端回复；验收脚本 47 项本地检查；地区组解析的故障切换测试；ULA 家网测试），外加升级、迁移、密钥与密码登录、名单更新、远程接入安装、重启的手工核对 | [docs/evidence/2026-11-13-debian13](evidence/2026-11-13-debian13/README.md) |
| 2026-11-13（晚） | 同一台主机，只在临时网络命名空间里 | 只有三个 netns 测试：`TestNetnsGroupDNSFailover`（含 Mesh 第 7–9 阶段）、`TestNetnsReloadNoLeak`、`TestNetnsULALANHomeAccess`，全部 PASS。没有安装、没有跑任何验收脚本 | [docs/evidence/2026-11-13-debian13-mesh-dns](evidence/2026-11-13-debian13-mesh-dns/README.md) |

三份记录都只覆盖第二类，而且只对各自那一版代码和那台主机成立（每份覆盖哪一版代码，见下面「交接记录」）。2026-11-13 那份对应面板重做之后、删除 IPv4 `iif … unreachable` 规则之后的版本（见它的 README）；在它之后再改防火墙、路由、安装脚本、宿主执行或验收脚本就要重跑。它没有覆盖的东西在它的 README 里逐条列出：没有真实隧道和出口、没有设备真的拨入、没有调用过 Cloudflare、没有对真实平台探测、对真实远端节点的下发只测了连接、全新主机的首次安装这次没有重走。

2026-11-12 那份是用提交 `d9b8556` 产生的，**早于**地区组、名单源、远程接入、14 个解锁适配器和面板重建；这些功能都不在它的范围内，它的 `meridian-verify.sh` 日志（17 PASS / 5 PENDING-HUMAN / 4 NOT-RUN-HERE）也是旧版脚本的输出，没有本版新增的检查。之后改过的防火墙（守卫标记范围、`mra` 入口）、路由（地区组标记）、启动脚本（chnroute 重新加入）、安装脚本（`meridian-secrets` 卷）、宿主执行（名单动作、远程接入状态）和验证脚本本身都要重跑：下面的「真实网关重跑清单」列出顺序。存档目录里的原始日志和 README 不改写。

第三类（实机人工签收）至今没有任何记录：下面标着「待人工签收」的每一项都还没做。真实出口切换、Cloudflare Mesh 的真实部署、路由器转发、手机蜂窝拨入、解锁探测的真实平台判定和防泄漏抓包都没有执行过，它们是用户或主会话另行执行的待签收项。

### 交接记录（本版）

截至这一版，证据与代码版本的对应关系如下。存档目录里的原始日志和 README 都不改写；后续在真实主机上发现的问题按复现逐条修复，修好并重跑之后才在新的证据目录里记为通过，不预写结果。所有记录都不含真实地址、主机名和凭据。

| 证据目录 | 覆盖的代码版本 | 覆盖什么 |
| --- | --- | --- |
| `docs/evidence/2026-11-12-debian13/` | 提交 `d9b8556` 的构建 | 当时的第二类五个入口、首次安装、升级、回滚、重启。早于面板重做，不覆盖之后的任何功能 |
| `docs/evidence/2026-11-13-debian13/` | 提交 `233e17b` 的最后一次构建 | 面板重做之后的第二类五个入口（含 47 项本地检查的 `meridian-verify.sh`、`verify-host-exec.sh`、`verify-smartdns.sh`、`verify-mesh-veth.sh`）和 README 里列出的手工核对 |
| `docs/evidence/2026-11-13-debian13-mesh-dns/` | `233e17b` 之上、地区组解析经 Mesh 备路的改动之后（第一次包含该目录的提交） | **只有**三个 netns 测试：`TestNetnsGroupDNSFailover`（含 Mesh 第 7–9 阶段）、`TestNetnsReloadNoLeak`、`TestNetnsULALANHomeAccess`，在 Debian 13 上全部 PASS。第一次运行 Mesh 阶段时暴露了一个真实的产品缺陷（编译出的 `meridian-mesh-up.sh` 把封装条件判反），修好后才是那次通过的运行 |

**之后的改动没有在任何真实主机上执行过**，只有仓库里的自动化回归（进程内 SSH 服务器、模拟宿主、本机沙箱、假 API）：

- 枢纽实际状态与当前枢纽身份（服务器、地址、端口、固定指纹）的绑定；
- 装机前预检：远端的固定只读脚本，网关经 `meridian-host` 的 `/v1/preflight`；登录方式不被接受时的公钥提示；
- 远端第一次装机失败时的补偿和残留清单；
- 撤回：远端节点（清单模式、中断恢复、旧版清理）和网关（撤回到兜底表、移除兜底表）；
- 面板开机时等待局域网地址（`meridian-bind-waiting` / `ready` / `not-ready`）；
- 安装结果里的「内核参数」读回和 `meridian-up.sh` 的 `meridian-sysctl:` 汇总行；
- 概览解锁卡片按宿主代理可达性显示探测通道、同名地区组附带地区和 ID。

`meridian-verify.sh`、`verify-host-exec.sh`、`verify-smartdns.sh`、`verify-mesh-veth.sh` 都没有在这一版上重跑；这一版还没有安装到任何主机上。`meridian-up.sh` 在 mesh-dns 记录之后又改过（受管 sysctl 的汇总行），所以三个 netns 测试也要在这一版上重跑才算覆盖它。

**至今完全没有验证过的**（第三类，或连第二类都没有）：真实出口和真实隧道（所有记录里隧道都没有握手）、真实枢纽的故障切换、真实 Cloudflare Mesh（含连接器是否做源地址转换）、手机拨入（远程接入）、ROS 一侧（端口转发、`fd00::/8` 黑洞的只读查询）、流媒体 / AI 平台的真实解锁判定、真实测试机上的 DNS / WebRTC 泄漏和抓包。

**已知限制（未解决，也未在真实主机上观察过）：**

- 远端节点的下发包里没有开机时重新运行 `meridian-up.sh` 的单元：远端节点重启之后，它的数据面很可能不会自己恢复（网关有 `meridian.service`，远端没有对应物）。
- `meridian-up.sh` 把 rp_filter / 重定向相关的 sysctl 设到每一个接口上，包括 Docker 和 WARP 的接口。
- 主机上的 nftables 配置是发行版默认的 `flush ruleset` 时，`systemctl reload nftables`（或重启 nftables.service）会清掉 Meridian 的表；预检会提示（`nftables_flush_on_reload`），但不阻止也不修改那份配置。
- Docker 把 iptables FORWARD 策略改成 DROP 的主机会被预检识别并拒绝（`forward_policy_drop`），但还没有与 Docker 共存的方案。
- 被攻破的远端主机可以打印伪造的成功标记（`MERIDIAN_PROVISION_OK`、`MERIDIAN_WITHDRAW_OK` 等）；面板只能如实转述远端的回答。
- Mesh 的数据和 DNS 回程依赖 Cloudflare 连接器对进入 Mesh 的流量做源地址转换，这一点没有验证。
- 从 Mesh 进入枢纽 sidecar 的流量没有过滤。
- 删除受管 sysctl 行不会恢复内核里的旧值（安装结果会列出这些键，直到重启前保持原值）。

### 真实网关重跑清单（主会话执行；本仓库的开发与 QA 不连接网关）

按顺序，每一步把完整输出存进新的证据目录（例如 `docs/evidence/<日期>-debian13/`），没有存档就仍是「未验证」：

1. 开发机：`GOOS=linux go test -c -o compile.test ./internal/compile`，拷到一台可以建命名空间的 Linux 主机（不要在网关本机上跑），`sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsReloadNoLeak$' -test.v`。通过的样子：每个阶段（对照、首次安装、200 次重载、失败注入、20 次地区组切换、切换后 20 次路由重跑、只剩兜底表、只有开机兜底文件）都有 `EVIDENCE` 行，首次安装、200 次重载后和地区组切换后各有一组 `e2e ok` 行和一行路由校验通过，远程设备 `raw_at_ros=0`，最后一行 `meridian-netns-reload-test-ok`。同一个 `compile.test` 再跑 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsGroupDNSFailover$' -test.v`（地区组的解析；需要 python3；2026-11-13 跑通过一次，见已存档的执行记录）。通过的样子：`EVIDENCE before`、`EVIDENCE after failover` 各有 UDP、TCP 查询和连接三行（之前是 `198.18.1.1` / `100.64.1.2`，之后是 `198.18.1.2` / `100.64.2.2`），`hub active member of group us: us-2`、`hub report: hop in table us: us-2`、`hub report: result: ok`，`all members down` 阶段查询 `TIMEOUT`、`hub active hop of group us: mmesh`、`hub report: hop in table us (Mesh unsealed): blackhole`；Mesh 阶段（还要 `nsenter` 和 `/dev/net/tun`，缺了整个测试跳过；2026-11-13 晚在 Mesh 解析改动之后跑通过一次，见 [mesh-dns 记录](evidence/2026-11-13-debian13-mesh-dns/README.md)，那次的第一遍运行暴露了编译出的 `meridian-mesh-up.sh` 把封装成功和失败判反的产品缺陷，修好后才通过；这些阶段用的是命名空间里两个 tun 之间的转发，不是真实 Cloudflare Mesh）有 `EVIDENCE mesh: us table 171:`（`default via fe80::66:2 dev mmesh` 和黑洞）、`hub report: hop in table us (Mesh sealed): mmesh`、`hub report: result: ok`，UDP / TCP 查询 `198.18.1.1`、连接 `100.64.1.2`，`EVIDENCE mesh Mesh counters` 里 `us q_tun`、`us r_tun`、`us r_wan`、`hub sidecar docker bridge` 都是 0 且 `q_mesh`、`r_mesh` 增长；`mesh down` 阶段查询和连接 `TIMEOUT`、`hop` 仍是 `mmesh`；`unsealed` 阶段 `hop` 是 `blackhole`、查询 `TIMEOUT`、`us` 的表 171 不再指向 sidecar；每个阶段的计数行里 `gw unmarked`、`gw lan`、`gw domestic`、`ros domestic`、`ros group` 都是 0，`--- PASS: TestNetnsGroupDNSFailover`，stderr 最后一行 `meridian-netns-group-dns-test-ok`。失败时日志里有 `DIAG` 段（各命名空间的规则、路由、nft、枢纽的组状态文件和解析器日志）。再跑 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsULALANHomeAccess$' -test.v`（ULA 局域网前缀；2026-11-13 跑通过一次，见已存档的执行记录）。通过的样子：两行 `EVIDENCE ula-lan e2e ok`（设备 → 家里主机、家里主机 → 设备），一行 `EVIDENCE ula-lan outside-prefix ULA … arrived_at_gateway=<不小于 20> forwarded=0 at_ros=0`，`--- PASS: TestNetnsULALANHomeAccess`，stderr 最后一行 `meridian-netns-ula-lan-test-ok`。
2. 网关：按 [安装](install-debian13.md)「升级」重跑 `install.sh`（全程转发不掉、`meridian-restore-ok`；它同时换掉宿主上的 `meridian` 二进制并重启 `meridian-host`——这一版的网关安装需要 agent 的 `/v1/preflight`，旧 agent 会让安装以 `host_unavailable` 拒绝），用新镜像重建面板容器；`docker compose logs meridian` 里应有凭据迁移和地区组迁移的日志（只有数量和 ID）。
3. 面板：密钥 → 服务器 → 发现并核对指纹 → 确认 → 连接测试（就绪）；Cloudflare 账户 → 检查权限（预期：令牌有效、可读节点和路由，写权限「未确认」）。
4. 面板「部署」：差分、「安装前预检」（审阅报告，核对与 `ss -lntup`、`nft list tables`、`iptables -S FORWARD` 一致）、安装到网关。安装结果里「内核参数」一块：写入项应全部「已生效」，开机转发两行显示为「开机值」，旧 `install.sh` 写过、新文件不再写的键列为「旧文件遗留」（内核保留到重启）；把这块和 `journalctl -u meridian.service` 里的 `meridian-sysctl: applied N, skipped M` 一起存档。然后「名单 → 立即更新」一次（选网关上能到达的策略）。
5. 网关：`sudo /usr/local/sbin/meridian-verify.sh`。通过的样子：退出码 0、最后一行 `meridian-verify-local-ok`；`PASS policy_marks`（数量等于出口数加地区组数）、`PASS guard_mark_range`、`PASS guard_ingress`、`PASS guard_boot_file`、`PASS fallback_blackholes`、`PASS no_stale_iif_rule`、`PASS route_lan_domestic4`、`PASS route_tunnel_reply4`（局域网有 IPv6 前缀时还有 `route_lan_domestic6`、`route_tunnel_reply6`）、`PASS chnroute_loaded`（和 `chnroute6_loaded`）、`PASS geosite_cn`、`PASS dns_listener`；有可切换地区组时还有 `PASS group_dns_snat`、`PASS group_dns_upstream`、`PASS group_dns_route`，以及 `PENDING-HUMAN group_dns_failover`、`NOT-RUN-HERE netns_group_dns`；`INFO list …` 行与面板「名单」页一致；远程接入关闭时 `PASS remote_absent`，打开时 `remote_*` 全部 PASS 且多四条 `PENDING-HUMAN remote_*`。旧版 17 项里任何一项变成 `FAIL` 都要查原因（真实 `nft list` 格式与本仓库桩不同只会导致 FAIL，不会误报 PASS）。
6. 网关：`sudo bash deploy/verify-smartdns.sh`、`sudo bash deploy/verify-host-exec.sh`，重启后 `--boot`；重启后再跑一次 `meridian-verify.sh`，`chnroute_loaded` 仍为 PASS（证明重载时重新加入了保存的批次）。重启后还要存 `docker compose logs meridian`：局域网口用 DHCP 时应看到 `meridian-bind-waiting` 若干行和一行 `meridian-bind-ready`，`docker inspect -f '{{.RestartCount}}'` 为 0（以前这里是几次 `bind: cannot assign requested address` 崩溃重启）；租约一直不来时应在 `MERIDIAN_BIND_WAIT` 后看到 `meridian-bind-not-ready` 一次。
7. 隔离 Linux 主机：`sudo bash deploy/verify-mesh-veth.sh`（它按固定命令搭这一跳，不运行编译出的 `meridian-mesh-up.sh`；后者这次有改动——表 170 复制路由时补上设备、Mesh 解析成员出口的表 171——由上面 `TestNetnsGroupDNSFailover` 的 Mesh 阶段运行）。
8. 在可以随意重装的主机上（不是生产网关、不是在跑别的服务的出口）：远端节点「预检 → 第一次装机 → 撤回」，网关「撤回 → 重新预检 → 安装」，按下面「装机前预检」「撤回与恢复」的实机项核对并存档。
9. 人工签收（各自存档）：测试机 DNS / WebRTC / 断隧道 / 抓包；真实出口与地区组切换；Cloudflare Mesh 部署、健康、撤回；路由器转发；手机蜂窝拨入两种模式（[远程接入](remote-access.md)「验证」）；解锁平台结论（[unlock-methods.md](unlock-methods.md)「需要人工在真实平台上核对的事项」）。

## 路径

- [ ] `ip route` 只有一条 IPv4 默认路由，下一跳是 `192.168.100.88`。
- [ ] `ip -6 route` 的默认路由是网关的 `fe80::`，不是 ROS。
- [ ] 访问一个国内站点，源地址仍走家庭网络，不进隧道。
- [ ] 访问一个普通境外站点，出口 IP 是默认地区组（示例 `hk`）当前选中的那台（自动组默认是 IX 绑定的那台），而不是家宽、阿里云或 ROS。
- [ ] 面板里把 IX 那条边删掉后，保存被拒绝，并提示必经 IX。
- [ ] IX 替换模式关掉时，阿里云上的默认向东接口是 IX 隧道，不是 WSS。WSS 接口处于 up，但没有被选成默认路由。

## DNS

等级：实机人工签收。仓库里的测试和 `meridian-verify.sh` 都不运行这些页面；结果以截图和 WAN 抓包存档为准。

在测试机上打开：

- https://dnsleaktest.com
- https://ipleak.net

预期：

- [ ] IPv4 和 IPv6 的 DNS 与出口 IP 都属于当前选中的出口地区。
- [ ] 结果里没有家庭宽带的公网地址，也没有 ROS `192.168.100.1` 的出口。
- [ ] 在 ROS 或家庭光猫的 WAN 上看，这台测试机没有发往境外的 53/853 查询。查询应停在 `192.168.100.88`。
- [ ] 对一个没有 `egress_v6` 的出口（示例里的台湾、新加坡），对应域名没有 AAAA，页面仍从该出口的 IPv4 打开。

### SmartDNS 容器与 nftset（网关上做，需要 Linux + Docker）

单元测试只能证明 Compose 文件挂载了配置引用的每个目录并给了 `NET_ADMIN`，不能证明镜像真能启动、真能写集合。首次 `install=true` 应用之后，在网关上以 root 运行：

```
sudo bash deploy/verify-smartdns.sh            # 自动从 geosite/cn.txt 取一个测试域名
sudo bash deploy/verify-smartdns.sh qq.com     # 或者指定域名
```

- [ ] 配置里每个 `-file` 以及 `bind-cert-file` / `bind-cert-key-file` 在主机上存在，容器内同路径可读；容器日志没有 `unknown bind option` 或 `Address already in use`。
- [ ] 容器持续运行，带 `NET_ADMIN`。
- [ ] 在已加载生成的防火墙（含 input 链）的情况下，网关局域网地址（以该地址为源，UDP 与 TCP）和 `127.0.0.1:53` 都有应答。
- [ ] 解析测试域名后，它的 A 记录出现在 `nft list set inet meridian direct4` 里。
- [ ] 最后一行是 `meridian-smartdns-verify-ok`。

境外出口上的解析器由 SSH 装机安装（`apt-get install smartdns`，装机期间用临时 `policy-rc.d` 挡住发行版默认配置的自启），`meridian-up.sh` 在隧道起来后重启它，装机输出里应有 `MERIDIAN_SMARTDNS_ACTIVE`。在网关上用 `dig @<出口隧道 ULA> example.com` 应有应答。

DoH 只能拦截清单内的公共解析器。用非常见的 DoH 地址仍可能绕过，这是已知边界，不要把它写成「绝对不泄漏」。

## WebRTC

等级：实机人工签收。

用浏览器打开 ipleak 或 browserleaks 的 WebRTC 测试。

- [ ] srflx / 出口候选是当前出口地址，不是家庭 WAN。
- [ ] 境外 STUN 和同一目标的 TCP 走同一个出口。

已知限制：host 候选里仍可能出现 ROS 通告的 GUA，因为测试机还拿着那条 /64。这是单条运营商前缀加 SLAAC 的结果。要去掉它，只能让测试机不用 GUA、改用 ULA 再在网关做 NAT66，国内 IPv6 就不再端到端。一期把这件事记在验收说明里，不把它当成失败。

## 规则

- [ ] 手动规则优先于自动表。示例里的 `api.example.com` 钉在美国池。
- [ ] 把 Netflix 改到机房出口时，校验报 `residential_required`，不能保存。
- [ ] 台湾规则失败时不会自动改去日本。解锁结果只在同一个地区组里换成员。

## 回滚

- [ ] 面板「回滚」之后，阿里云向东的首选路由回到上一份。
- [ ] 测试机把网关和 DNS 改回 `192.168.100.1` 后，立刻回到原来的 mihomo 路径，ROS 不需要改配置。

## 同网段：重定向和 rp_filter

网关 `192.168.100.88/24` 和 ROS `192.168.100.1` 在同一个二层。国内回程可能由 ROS 直接交给客户端，所以 `rp_filter` 必须是 loose（2）。本机发送 ICMP 重定向必须关掉，否则境外目的有可能被指去 `.1`。

### meridian-verify.sh（隔离 Linux 集成证据，网关上以 root 运行；本版于 2026-11-13 执行过，见已存档的执行记录）

```bash
sudo /usr/local/sbin/meridian-verify.sh
# 让脚本顺带只读查询 ROS 的 ULA 黑洞（需要已配置的 SSH 密钥登录）：
sudo MERIDIAN_ROS_SSH=admin@192.168.100.1 /usr/local/sbin/meridian-verify.sh
```

脚本只报告它自己真正执行过的检查，每条命令的原始输出存进证据目录（默认 `/var/log/meridian-verify/<UTC 时间>/`，可用 `MERIDIAN_VERIFY_EVIDENCE_DIR` 改），`summary.txt` 是全部结论行。每行的前缀：

| 前缀 | 含义 |
| --- | --- |
| `PASS` | 本次运行实际执行并满足条件，证据文件名写在行里 |
| `FAIL` | 实际执行且不满足，或者该有的东西不存在 |
| `UNKNOWN` | 想查但没能执行（例如没有 `sysctl`/`ip`、SSH 连不上 ROS），没有结论 |
| `PENDING-HUMAN` | 这个脚本不可能执行，需要实机人工签收 |
| `NOT-RUN-HERE` | 属于别的集成测试，要单独跑并存档 |

本机检查（会执行）。2026-11-12 的存档只覆盖前五条；其余是之后加的，于 2026-11-13 在测试网关上跑过一次（远程接入打开，47 项 PASS，重启后再跑结果相同），见已存档的执行记录：

- 运行中的 `rp_filter=2`（all、default、局域网口）、IPv4 `send_redirects=0`（all、局域网口）、v4/v6 `accept_redirects=0`、`ip_forward=1` 和 `ipv6 all.forwarding=1`（转发只在兜底表加载之后由 `meridian-up.sh` 打开，所以它为 1 也间接说明 up 脚本走完了）。
- 网关地址在局域网口上；`ip route get <ROS>` 是同链路邻居（没有 `via`）。
- `ip -6 route show table all` 里没有任何 ULA（`fc00::/7`）路由走局域网口或指向 ROS 的链路本地地址。局域网 IPv6 前缀本身是 ULA 时，落在这个前缀里的路由和本机地址（它的直连路由、表 100/102 里的同一条、`local`/`anycast`）按设计在局域网口上，单独存为 `ula-routes-lan.txt`、不算走局域网口；它们也不能指向 ROS。前缀之外的 ULA（包括包含这个前缀的更宽路由）照旧检查。
- **防火墙必须存在**：没有 `nft` 命令、`inet meridian_guard` 不在、或 `inet meridian` 不在，都是 `FAIL`，不再是 SKIP。兜底表要有 forward 钩子、优先级 -200 和 `fail closed` 那条丢弃；主表要有 53/853 的 `redirect`、非局域网 DNS 的 input 丢弃和 `ip6 daddr fc00::/7 drop`。`ula_drop` 读的是已加载的 `classify` 链：丢弃必须在链里，丢弃之前的 IPv6 规则只能是设备池那条，以及局域网 IPv6 前缀是 ULA 时恰好这个前缀的那条（这时它必须在，否则家里的 ULA 主机经网关不可达，也是 `FAIL`）；任何别的、或更宽的 IPv6 规则排在丢弃之前都是 `FAIL`。
- **策略路由覆盖每个编译出的标记**（`policy_marks`）：`ip -4/-6 rule show` 里每个出口和地区组标记都有 `fwmark <标记> lookup 102`（或表名 `meridian_foreign`）和其后优先级的 `unreachable`，优先级与编译结果一致；缺哪个就列出 `exit/<ID>` 或 `group/<ID>`。`ip rule` 读不出来是 `FAIL`。
- **没有旧的 iif 规则**（`no_stale_iif_rule`）：`ip -4 rule show` 里优先级 17850/17851 不能有 `iif <接口> unreachable`。旧版本装过这两条，它们让经局域网口或 `mra` 转发出去的 IPv4 过不了内核的源地址校验（见架构「局域网兜底」）；在就是 `FAIL`，并说明原因（重跑 `meridian-routes.sh` 会删掉）。
- **路由探测**（`route_*`）：用 `ip route get <目的> from <源> iif <入接口> [mark 0x64]` 让内核实际判一次转发（包括 `rp_filter` 的源地址校验），结果必须是经指定接口出去的单播路由；报错（例如 `Invalid cross-device link`）、`unreachable`/`blackhole`、或从别的接口出去都是 `FAIL`，原始输出存为 `rtget-<项>.txt`。地址：局域网客户端取局域网前缀里最后一个既不是网关也不是 ROS 的地址（示例 `192.168.100.254`），IPv6 取局域网前缀里的 `::fffe`；国内 IPv4 目的地就是 ROS 的地址（带国内 mark 查表 100）；境外一侧和国内 IPv6 目的地只用文档地址 `192.0.2.1`、`2001:db8:ffff::2`、`2001:db8:ffff::1`；设备地址取设备池里网关之后的那个（示例 `10.67.0.2`、`fd67::2`）。各项：`route_lan_domestic4`（客户端到国内，出局域网口）、`route_tunnel_reply4`（每个网关隧道接口回到客户端的回程，出局域网口）；局域网有 IPv6 前缀时 `route_lan_domestic6`、`route_tunnel_reply6`；远程接入打开时 `route_remote_domestic4`（设备到国内，出局域网口）、`route_remote_reply4` / `route_remote_reply6`（国内回程到设备，出 `mra`）、`route_remote_domestic6`（局域网有 IPv6 前缀时）、`route_tunnel_reply_device4` / `route_tunnel_reply_device6`（每个隧道回到设备，出 `mra`）。
- **另一个会清空规则集的加载器**（`WARN nftables_service_flush`）：`nftables.service` 已启用、且 `/etc/nftables.conf` 里有清空整个规则集的那一行时打印 `WARN`。它只是提醒，不影响退出码：它在 Meridian 加载之后运行时会删掉两张 Meridian 表，转发仍开着，局域网的 IPv4 和 IPv6 都会不受兜底地经 ROS 出去。
- **表尾黑洞**（`fallback_blackholes`）：表 102 的 v4、v6 和表 100 的 v4 都有 metric 32767 的 `blackhole default`。
- **守卫的标记范围**（`guard_mark_range`）：从 `nft list table inet meridian_guard` 读出放行进隧道的标记范围（`nft` 打印成 `0x00000101` 这种形式，按数值比较），必须等于编译出的范围（出口加地区组的最大标记，至少到 `0x140`），并且包含每个编译出的标记。
- **守卫的入口**（`guard_ingress`）：远程接入关闭时守卫里没有 `mra`；打开时 DNS 丢弃、国内标记、出口标记和最后的 fail-closed 丢弃都以 `{ 局域网口, mra }` 为入口，只有两条局域网到设备池的放行单独写局域网口。
- **国内名单不为空**（`chnroute_loaded`、局域网有 IPv6 前缀或启用远程接入时还有 `chnroute6_loaded`、`geosite_cn`）：`inet meridian` 里的 `chnroute` 集合要有元素，`/var/lib/meridian/geosite/cn.txt` 要有域名。空集合但保存的批次 `lists/chnroute.nft` 里有它时，失败信息指出「重载没有重新加入」；从没更新过名单时指出要去更新。这两项在新装、还没更新过名单的网关上一定失败——那时分流确实不对。
- **名单版本**（`INFO list <名单>`）：从 `/var/lib/meridian/lists/status.json` 读出每个名单当前生效的来源、条数和时间，只是信息，不算检查；没有这个文件时 `INFO lists`。
- **开机兜底文件**（`guard_boot_file`）：已安装的 `/etc/nftables.d/meridian-guard.nft` 里的守卫与 `meridian.nft` 里的逐字相同；缺文件或不同都是 `FAIL`。
- **DNS 有人接**（`dns_listener`）：`ss` 显示 UDP 和 TCP 53 都有监听；没有 `ss` 是 `UNKNOWN`。是否答得对是 `verify-smartdns.sh` 的事。
- **远程接入打开时**：`remote_iface`（`mra` 存在且 up）、上面的 `route_remote_*` / `route_tunnel_reply_device*`、`remote_pool_routes`（设备池在 main 和表 100 路由到 `mra`）、`remote_dns`（`mra` 的 53/853 重定向，DNS 白名单含两个设备池）、`remote_port_lan_only`（监听端口只在局域网口接受）、`remote_nat`（设备池对每个标记都有中转 SNAT，另有局域网口 masquerade）、`remote_wg` / `remote_listen`（`wg show mra listen-port` 等于配置）、`remote_peers`（`wg show mra peers` 恰好是已启用设备的公钥：缺的按设备 ID 列出，多出来的只报数量；只比较公钥，从不运行 `wg show … dump`，不打印也不保存任何私钥或预共享密钥）。**关闭时**：`remote_absent`（没有 `mra` 接口）。旧版本遗留的 `iif mra unreachable` 由路由脚本删除，还在就是 `FAIL no_stale_iif_rule`（以前显示为 `INFO remote_leftover`，这一项已去掉）。
- ROS `fd00::/8` 黑洞：只有设置了 `MERIDIAN_ROS_SSH` 时才执行一条只读的 `/ipv6 route print terse where blackhole`，输出里有 `dst-address=fd00::/8` 或 `fc00::/7` 才 `PASS`；ROS 回答了但没有这条是 `FAIL`；连不上是 `UNKNOWN`。没设置就是 `PENDING-HUMAN`。

一定是 `PENDING-HUMAN`（脚本不跑浏览器、不抓包、不断隧道、看不到路由器和手机）：`dns_leak_client`、`webrtc_srflx`、`redirect_on_wire`、`tunnel_cut`；远程接入打开时还有 `remote_phone_full`、`remote_phone_home`、`remote_router_forward`、`remote_ipv6`。一定是 `NOT-RUN-HERE`：netns 重载测试、`verify-smartdns.sh`、`verify-host-exec.sh`、`verify-mesh-veth.sh`。

退出码：有 `FAIL` 为 1（最后一行 `meridian-verify-failed`）；没有 `FAIL` 但有 `UNKNOWN` 为 2（`meridian-verify-incomplete`，在没有 `/proc`、`sysctl` 或 `ip` 的容器里就是这样，不再退出 0）；全部本机检查通过才是 0，最后一行 `meridian-verify-local-ok`。这一行只代表本机检查，**不是**防泄露结论，也不是发布签收；脚本不再打印旧的 `meridian-verify-ok`。

自动化回归（`go test ./...`，`internal/compile/verify_script_test.go`）：`TestVerifyScriptExecutedChecks`、`TestVerifyScriptRemoteAccess` 和 `TestVerifyScriptULALAN` 用桩程序（`sysctl`/`ip`/`nft`/`wg`/`ss`/`ssh`）和临时根目录（`MERIDIAN_VERIFY_ROOT`，只给测试用）在 bash 里真的执行生成的脚本。覆盖：全部通过、没有 nft、缺主表、缺兜底表、转发关闭、不在网关上（`UNKNOWN`、退出 2）、ULA 指向 ROS、ROS 有/没有黑洞、ROS 连不上、`MERIDIAN_ROS_SSH` 注入被拒；地区组标记的规则缺失、`ip rule` 读不出、表 102 缺黑洞、守卫范围比地区组标记窄、远程接入关闭时有残留 `mra`（失败）与残留 `iif mra unreachable`（`FAIL no_stale_iif_rule`）、旧版的 `iif eth0 unreachable` 加上内核随之给出的 `Invalid cross-device link`（`no_stale_iif_rule` 和 `route_lan_domestic4`、`route_tunnel_reply4` 都 FAIL，IPv6 两项仍 PASS）、某个隧道的回程从别的接口出去、路由探测落到黑洞、没有路由探测的结果（全部 FAIL，不出现任何 `PASS route_`）、`nftables.service` 启用且会清空规则集（`WARN`，退出码仍是 0）与启用但不清空 / 未启用（没有 `WARN`）、chnroute 为空（有保存的批次 / 从没更新过）、`cn.txt` 为空、开机兜底文件不同或缺失、53 没人监听；远程接入打开时全部通过、停用设备仍是 peer、启用设备缺 peer、`mra` 不在、端口不对、没有 `wg`、守卫不含 `mra`、主表缺远程规则、设备池路由缺失、残留 `iif mra unreachable`（`FAIL no_stale_iif_rule`，设备回程的探测 `Invalid cross-device link`）、设备到国内被源地址校验拒绝；局域网 IPv6 前缀是 ULA 时全部通过、前缀之外的 ULA 路由在局域网口上、包含前缀的更宽 ULA 路由、`fd66::/48` 在局域网口上、前缀路由指向 ROS、已加载的分类链缺这条前缀规则、前缀规则被换成更宽的、丢弃不在（都 FAIL），以及 GUA 前缀时丢弃之前多出一条 ULA 规则（FAIL）。每个用例都断言脚本不能执行的项从不出现 `PASS`。桩里的 nft 输出是编译文本加上真实 `nft list` 的两处格式（标记补零成 8 位、集合元素跨行），真实 `nft list` / `ip rule` / `ss` 的其他格式差异要在网关上跑一次确认（格式不同只会让对应项 `FAIL`，不会误报通过）。

这些测试找到过一个真实问题：打开远程接入后守卫最后一条是 `iifname { "eth0", "mra" } … drop`，旧版 `nft_guard` 的匹配只认 `iifname "eth0"`，会在每台打开远程接入的网关上误报 `FAIL`；已改为两种写法都认。

- [ ] 在网关上运行一次，最后一行是 `meridian-verify-local-ok`，证据目录已存档。
- [ ] 临时 `nft delete table inet meridian_guard` 之后再运行（只在测试网关上做，做完重新安装）：`nft_guard` 为 `FAIL`，退出码 1。

面板「防泄露」页对生成配置做同样的文本检查，那是自动化回归，不替代上面的运行结果。下面这些打勾项里，标了「实机」的没法在仓库的单元测试里做。

- [ ] `sysctl net.ipv4.conf.all.rp_filter` 和每个接口（含 `eth0`）都是 2。生成配置和 `meridian-verify.sh` 会查；实机上再看一遍运行值。
- [ ] `net.ipv4.conf.all.send_redirects` 以及对应接口都是 0。IPv6 没有这个开关，见下面「已知边界」。
- [ ] `accept_redirects` 为 0。ROS 自己仍可能对客户端发重定向，这不由本机控制，实机上在测试机抓包确认。
- [ ] 网关地址不是 `192.168.100.1`，两者在 `192.168.100.0/24`。
- [ ] 没有在这块网卡上跑 radvd 或第二个 DHCP。

## 防火墙原子替换与 LAN 兜底

状态：**隔离环境里通过过一次，实机未签收**。下面的运行时测试于 2026-11-12 在一台 Debian 13（内核 6.12、nftables 1.1.3）上跑通，完整日志在 [docs/evidence/2026-11-12-debian13/netns-reload.log](evidence/2026-11-12-debian13/netns-reload.log)。它只证明这套规则在网络命名空间里的行为，对应的是当时那一版生成结果；之后改过 `render_nft.go`、`render_routes.go` 或 up 脚本的加载段就要重跑并替换存档。真实测试机、ROS 和断隧道下的「重载不漏」仍是待人工签收，不要在面板或发布说明里写成已验证无泄漏。

### 生成的结构

- 网关的 `/etc/nftables.d/meridian.nft` 本身就是一个 nft 事务：先 `table inet meridian_guard` / `delete table inet meridian_guard` / 重建，再对 `inet meridian` 做同样三步。首次安装时 `table` 先建出空表，所以 `delete` 不会失败；已有表时 `table` 什么都不做。整份文件是同一个 netlink 批次，任何一行被内核拒绝，整批作废，旧的两张表原样保留。出口和中转节点的文件也用同样的写法，只是没有兜底表。
- `meridian-up.sh` 第一件事就是 `nft -c -f`，通过后 `nft -f`，没有单独的 `nft delete table` 进程。任一步失败，脚本在这里退出：不跑 `sysctl`（不打开转发）、不起 WireGuard、不改策略路由。网关上文件缺失，或加载后 `inet meridian_guard` 不在，也按失败处理。
- 兜底表 `inet meridian_guard` 不引用 `inet meridian` 的任何集合或链，只看包上的 fwmark 和出接口。它挂在 forward 钩子，优先级 -200（在 Meridian 的 mss（-150）、doh（0）以及常见 filter 优先级的链之前）。真正让它不能被绕过的是 nft 的语义：任何基础链里的 drop 都是终结的，别的表里的 accept 只结束那一条链，包仍会经过兜底链。
- 允许的路径（入接口都是局域网口，示例 `eth0`），IPv4 和 IPv6 相同：
  1. 先丢弃转发出去的 TCP/UDP 53、853。正常情况下它们已被劫持到本机（input），不会出现在 forward 上。
  2. `meta mark 0x64`（国内）且出接口是局域网口：经表 100 直连 ROS 或局域网。这是设计里允许直出的那部分 IPv6（chnroute6、direct6、局域网前缀）。
  3. 出口 mark（`0x101`–`0x140`，出口更多时随之扩大）且出接口是网关自己的 WireGuard 接口（示例 `m02`、`m02w`、`m03`，含故障切换的备接口）。被路由到 ROS 的出口 mark 包会被丢弃。
  4. 其余从局域网口转发的包一律丢弃并计数：没有 mark（分类表不在、或者走了 main 表经 ROS 的 IPv6 默认路由）以及走错出接口的包。
- 兜底只挂 forward，不影响 RA、ND 和访问网关本机（input）的流量，也不匹配从隧道回来的流量。IPv4 和 IPv6 都**没有** `ip rule iif <局域网口> unreachable`：旧版本在 IPv4 上有这一条（打开远程接入时还有 `iif mra`），它让内核对经局域网口（或 `mra`）转发出去的 IPv4 做源地址校验时反查失败（`rp_filter=2`，反查的 iif 是出接口、mark 是 0），国内直连、隧道回程、设备的国内流量和回程全部被丢，已删除（见架构「局域网兜底」）。未分类流量的兜底只靠这张 nft 表；已分类的境外流量还有每个 mark 的 `fwmark … unreachable` 和表尾黑洞。

仓库里能跑的（macOS / 任意平台，`go test ./...` 会跑）：

- `TestNFTAtomicReplace`：每份 nft 文件都是「建-删-重建」写法，每张表只定义一次，没有 `flush`，兜底表在被保护的表之前。
- `TestGatewayGuardStructure`：兜底表的四条规则、优先级、没有跨表引用、最后一条不带协议族限定的 drop；路由脚本不加任何 `iif` 规则（v4、v6），按优先级、接口和动作删除旧版的 17850/17851 两条，每个出口 mark 后面仍有 `fwmark … unreachable`。`TestRemoteRoutesAndUpOrder` 对打开远程接入的拓扑做同样的断言；面板检查项 `no_iif_unreachable`（`internal/verify`）在生成配置里出现 iif 规则、缺少旧规则清理或缺少兜底表时失败。
- `TestUpScriptLoadsFirewallFirst`：`nft -c` 在 `nft -f` 之前，二者都在 `sysctl`、`wg-quick`、路由脚本之前，脚本里没有别的 nft 改动命令。
- `TestUpScriptFailurePreservesState`：用桩程序在 bash 里真的执行网关的 `meridian-up.sh`，分别让检查失败、加载失败、兜底表缺失、文件缺失，确认脚本停下、不调用 `sysctl`/`wg`/`ip`/路由脚本、也从不发 delete。
- `TestInstallSurfacesFirewallLoadFailure`（internal/apply）：激活失败会作为错误返回给调用方。

这些只证明生成的文本和脚本控制流。内核是否真的整批回滚、持续流量下是否真的没有一个包漏到 ROS，只能在 Linux 上验证。

### 运行时测试（Linux，root；本版于 2026-11-13 执行过，见已存档的执行记录）

在一台可以随便建网络命名空间的 Linux 机器上（不要在网关本机上跑），需要 `ip`、`nft`、`ping`、`bash` 和 Go：

```
sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsReloadNoLeak -count=1 -v
```

它只在自己建的五个命名空间里动（客户端、网关、ROS、一台远程设备，加一个放网桥的），结束时删掉。网关命名空间里装的是编译出来的 `meridian-routes.sh` 和 `meridian.nft`，隧道用 dummy 接口代替，并给网关加一条经 ROS 链路本地地址的 IPv6 main 默认路由（就是审计里的泄漏路径）。客户端持续向「境外」v4/v6 地址和写进 `direct4` / `direct6` 的「国内」v4/v6 地址发 ping，ROS 上计数。ROS 在 dummy 接口上拥有这些测试地址，局域网 v4/v6 前缀对它是同链路（能回给客户端和网关的地址改写地址），但**没有**到设备池的路由（测试开头断言），所以设备的国内流量只有经网关改写才回得来。

只数出去的包不够：旧版的 `iif <局域网口> unreachable` 让经局域网口转发出去的 IPv4 全部过不了源地址校验，而旧测试只数到 ROS 的包、国内只测 IPv6，没有发现。现在首次安装、200 次重载后和地区组切换后各跑一次 `e2e`：真实的 ping 必须收到回复——客户端到国内 v4/v6、设备到国内 v4/v6（回复经网关的地址改写从 `mra` 出去）、客户端到设备和设备到客户端 v4/v6；dummy 隧道回不了包，所以隧道回程用 `ip route get <客户端/设备> from <境外地址> iif <每个隧道接口>` 让内核判，必须分别从局域网口和 `mra` 出去；加载的规则里不能有 `iif … unreachable`。任一项失败都会打出网关和 ROS 命名空间的规则、路由和 `ip route get` 诊断。另外在第一次跑路由脚本之前先手工装上旧版的 17850/17851 两条，确认路由脚本把它们删掉。

- [ ] 对照：没有任何 Meridian 表时（路由已装、转发已开），客户端的境外 IPv4 和 IPv6 都能到 ROS（`foreign4>0`、`foreign6>0`），设备未改写的 v4 和 v6 也能到（`raw4_at_ros>0`，且 `raw_at_ros` 大于它）。这是两张表要挡住的基线：路由层没有 iif 规则后，IPv4 和 IPv6 一样只靠 nft。不满足就说明测试环境没覆盖到泄漏路径，结果作废。
- [ ] 首次安装：加载后境外 v4/v6 到 ROS 为 0，国内 IPv4 和 IPv6 都能到 ROS，隧道接口有发送；`e2e` 全部通过。
- [ ] 持续流量下连续重载 200 次：境外 v4/v6 到 ROS 为 0；之后 `e2e` 全部通过。
- [ ] 加载失败注入（批次末尾一条坏规则；兜底表和主表之间一条坏规则）：`nft -c` 和 `nft -f` 都失败，两张表的内容（除计数值）与之前完全一致，`meridian-up.sh` 的加载段停下，期间境外为 0，国内路径仍通。
- [ ] 只删 `inet meridian`（模拟旧流程两次 nft 之间的空窗）：只靠兜底表，境外和国内都到不了 ROS。
- [ ] 远程设备（第五个命名空间，`mra` 用 veth 代替）：各阶段设备的原地址从不到 ROS（`raw_at_ros=0`）；加载后国内 v4/v6 经地址改写到 ROS、境外进隧道；只剩兜底表时设备流量全部丢弃。
- [ ] 地区组切换（阶段 G）：同一拓扑把默认地区组换成另一个组再编译，在持续流量下来回加载 20 次（每次 `nft -c`、`nft -f`、重跑路由脚本），境外 v4/v6 到 ROS 为 0、设备原地址到 ROS 为 0；停在切换后的版本，`classify` 链里默认流量的标记是新组的；再重跑路由脚本 20 次后国内 IPv4 和 IPv6 仍到 ROS、隧道仍有发送，`e2e` 全部通过。
- [ ] 日志里有每一阶段的 `EVIDENCE` 行，最后一行是 `meridian-netns-reload-test-ok`。把整份日志存档；没有存档就仍是「未验证」。

远程设备命名空间、阶段 G（地区组切换）和 `e2e` 回复 / 路由校验加入之后，这个测试于 2026-11-13 在一台 Debian 13（内核 6.12、nftables 1.1.3）上跑通，日志在 [docs/evidence/2026-11-13-debian13/netns-reload.log](evidence/2026-11-13-debian13/netns-reload.log)。第一次在真实内核上运行时它失败了三回，每一回都改了东西：一回暴露出 IPv4 `iif … unreachable` 规则的缺陷（已删除，见架构「局域网兜底」），另外两回是测试装置自己的问题——设备的流量必须在规则加载之后才开始，充当隧道的 dummy 接口必须带上编译配置里的地址，重载之后要把运行时集合里的测试地址加回去；这些都写在测试的注释里。2026-11-12 的存档日志是这一切之前的版本，没有测过国内 IPv4，也没有测过任何回程，不能证明现在的版本（存档文件保持原样，不改）。它仍然只是命名空间里的证据：真实客户端、ROS 和断隧道下的行为是待人工签收。

### 已知边界（仍未解决）

- 开机空窗（已改；2026-11-12 在一台 Debian 13 上重启核对过加载顺序，见已存档的执行记录）：`99-meridian.conf` 不再打开转发，网关上反而显式写 `ip_forward=0` / `all.forwarding=0`；转发只由 `meridian-up.sh` 在 nft 批次和兜底表确认之后，从 `/etc/meridian/forwarding.conf` 打开。另有 `meridian-guard.service`（`DefaultDependencies=no`，排在 systemd-sysctl、Docker 和 meridian.service 之前）开机先只加载 `meridian-guard.nft` 里的兜底表；安装脚本给新的 `daemon.json` 加了 `"ip-forward": false`。验证见下面「宿主执行与运行态回滚」。
- 每次重载会重建集合，SmartDNS 写入的 `direct*`/`r*`/`default*` 会被清空，直到再次解析。这段时间国内目标会被当成境外走默认出口，不会漏到 ROS，但国内流量会绕路。chnroute 已改为在重载时从上次成功加载的副本（`/var/lib/meridian/lists/chnroute.nft`）装回；从未成功更新过名单的网关上仍然是空的。只在本地用桩 nft 测过；2026-11-13 在测试网关上更新名单后重载和重启各核对过一次，集合都还在（见已存档的执行记录）。
- geosite 的 `include:` 现在递归展开（含属性过滤、循环与缺失检测）；`keyword:` / `regexp:` 条目和 `&` 归属仍然丢弃（见架构「名单源」）。2026-11-13 在测试网关上用全自动策略更新过一次：全部来自国内源，`cn` 从 361 个文件展开出 8519 个域名（见已存档的执行记录）；海外源和回退路径没有在真实线路上走过。
- 名单源可选国内（jsDelivr）、海外（GitHub raw）、全自动（先国内后海外），默认全自动；只有手动更新，没有定时任务。镜像内容只做形状检查，不是“已验证”的数据（见架构「名单源」的信任边界）。
- 同一条连接中途改变分类时会断。分类标记按包打，地址转换按连接在建立时定下；重载清空运行时集合后，一条持续的连接可能先被当成境外（转换成中转地址），等它的目的地址重新进入国内集合后又从局域网口出去，沿用的却是旧的转换，对端的回程回不来，直到这条连接在连接跟踪里超时。目的地是国内地址，不构成境外泄漏；新建的连接不受影响。2026-11-13 的 netns 运行里看到过（测试因此在重载后重启设备的流量）。要根治得把分类结果存进连接标记，尚未做。
- 网关不阻止发送 **IPv6** ICMP 重定向。Linux 没有 `net.ipv6.conf.*.send_redirects`（这个键只有 IPv4 有）：转发路径在包从进来的同一个接口出去时直接发 IPv6 重定向，没有 sysctl 开关。以前生成的 sysctl 文件和安装脚本写过这个不存在的键（日志里的 `skip sysctl` / `cannot stat` 噪音），防泄露页还把「关闭 IPv6 发送重定向」列为「配置包含」——这个保护从来不存在；现在三处都已删除，不再声称。IPv6 重定向是否出现，只能靠「同网段 ICMP 重定向抓包」那条人工签收（IPv4 和 IPv6 都要抓）。要真正挡住，需要在 nft 里丢弃发往局域网的 `nd-redirect`，尚未做。
- 兜底只管从局域网口进来的转发。如果以后在网关上用非 host 网络的 Docker 发布端口给局域网，兜底会把它丢掉（出接口不是局域网口）。
- IPv4 对**没有 mark** 的局域网转发流量已经没有路由层兜底（旧的 `iif <局域网口> unreachable` 因为会挡掉所有经局域网口转发出去的 IPv4 而删除，见架构「局域网兜底」），和 IPv6 一样只靠 `inet meridian_guard`。两张 Meridian 表都被删掉而转发仍开着时（有人执行 `nft flush ruleset`，或启用了 Debian 自带、配置以清空规则集开头的 `nftables.service`），IPv4 会和 IPv6 一样直接经 ROS 出去。`meridian-up.sh` 不会在兜底表缺失时打开转发，`meridian-verify.sh` 在兜底表缺失时 `FAIL`、在 `nftables.service` 已启用且会清空规则集时 `WARN`；运行中有人删表不会被阻止，只能靠检查发现。

## 宿主执行与运行态回滚

面板（容器或裸机进程）不在宿主上直接执行任何命令。所有运行态动作都经宿主上的 `meridian-host`（`meridian host-agent`，`deploy/debian/meridian-host.service`）：只有 `activate`、`health`、`rollback`、`withdraw` 四个动作（`withdraw` 先关转发、停 `meridian.service`、按清单删除，永远保留并核对 `inet meridian_guard`；另有只读的安装前预检 `/v1/preflight`，只接受校验过的受管路径、只跑固定的只读命令；名单更新 `/v1/lists` 与只读的 `/v1/lists/status`、只读的解锁探测 `/v1/probe`、只读的远程接入状态 `/v1/remote-access/status`），参数只能是受管资源名（`m00`/`m00w`/`mmesh` 接口、`meridian-*`/`wstunnel-*` unit、`inet meridian`/`inet meridian_guard`、100–252 号路由表），不接受命令、shell 或路径；root-only Unix socket（目录 0700、socket 0600）+ 口令 + Linux 上要求对端 uid 0；串行执行，每步和整个动作都有超时，同一 `request_id` 重试只回放结果，不重复执行。`rollback` 只删除 agent 账本里激活过的资源；从未激活但同名且正在运行/存在的资源整单拒绝，什么都不改。

安装与回滚都是一份持久事务（`/var/lib/meridian/host/journal.json`）：受管清单（文件+哈希、接口、unit、nft 表、路由表、sidecar、版本）前后求差，先删旧清单独有的运行资源和文件，再写新文件，最后 `activate`（daemon-reload → `reset-failed` 后重启 `meridian.service` 跑 `meridian-up.sh`（失败时 `stop` 取消它的自动重试，免得和补偿并发） → 启用并重启清单里的 unit → 需要时重启 SmartDNS → 两次采样的健康检查）。任一步失败就把宿主和数据目录快照一起补偿回事务前；补偿也失败时保留日志、拒绝新的安装和回滚，面板「恢复」或进程重启时再补偿。到了提交阶段才中断的事务在恢复时补完提交，不撤回。

仓库里能跑的（`go test ./...`）：

- `internal/hostexec`：拒绝非受管名字、额外字段、错误口令；固定步骤顺序；第一处失败即停并带上 journal；步骤超时和整体超时；串行；`request_id` 回放与冲突；账本外资源的拒绝/跳过；删兜底表前先关转发；SmartDNS 两种形态与缺失时的告警；丢失响应后重试只执行一次；部署文件的接线（静态）。
- `internal/apply` 的 `txn_test.go`：用真的 agent 加模拟宿主跑首次激活失败（补偿到「未安装」）、激活超时（补偿到上一版）、健康失败、重复与并发调用、拓扑删除链路后删除其文件/接口/unit 且不碰非受管的 `m99`、新增资源后运行态回滚把它们删掉且 up 脚本只激活旧清单、补偿失败不报成功并阻止新事务、回滚中途进程退出后重启恢复、提交阶段中断后补完提交、旧快照升级。
- `internal/api`：已安装时 `{}` 回滚被拒绝；`install` 与 `snapshot_only` 互斥；没有宿主执行能力时 503 且不写快照；失败返回带补偿结果的事务报告。
- `internal/compile`：up 脚本只列清单里的接口，缺文件即失败；没有 systemd 时 `meridian-systemd-missing` 失败而不是跳过；sysctl.d 不开转发，转发在兜底检查之后。

### 实机（Debian 13 网关，root；本版于 2026-11-13 执行过，见已存档的执行记录）

```
sudo bash deploy/verify-host-exec.sh          # 接线、权限、容器无特权、agent 拒绝非法请求
sudo reboot
sudo bash deploy/verify-host-exec.sh --boot   # 兜底表先于 systemd-sysctl 和 dockerd，开机后转发由 meridian.service 打开
```

另外手工确认（结果存档前都算「未验证」）：

- [ ] 首次「安装到本机」后 `systemctl is-active meridian.service meridian-failover.service wstunnel-client-*.service` 都是 active，`wg show` 只有清单里的接口。
- [ ] 停掉 `meridian-host` 后点安装：面板报「没有宿主执行能力」，`/etc/wireguard` 和快照都没变。
- [ ] 删掉一条网关链路再安装：对应 `mXX` 接口、`.conf` 和 wstunnel unit 都消失；在 `/etc/wireguard` 放一个手写的 `m99.conf` 并 `ip link add m99 type dummy`，它们保持不动。
- [ ] 安装一个会让 `meridian-failover.service` 起不来的版本：面板报失败且「已补偿」，宿主回到上一版（接口、unit、`nft list ruleset` 里 Meridian 两张表）。
- [ ] 「回滚（含宿主网络）」后，新版本引入的接口和 unit 被删除，`meridian-up.sh` 里不再列它们。
- [ ] 回滚过程中 `docker restart` 面板容器：重启后日志有 `recovered host transaction`，宿主回到回滚前的版本，`/var/lib/meridian/host/journal.json` 不存在。
- [ ] 局域网地址晚到（DHCP）时重启：`journalctl -b -u meridian.service` 先有 `meridian-lan-not-ready`、退出码 75，之间转发保持关闭，随后自动重试成功；`verify-host-exec.sh --boot` 只在 `meridian.service` active 时才判转发。
- [ ] 已安装并在转发的网关上再跑一次 `install.sh`（升级）：全程 `net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding` 不掉成 0，脚本输出 `meridian-restore-ok`；转发原本关闭的主机跑完仍是关闭。
- [ ] 新装 Debian 13 跑 `install.sh` 后（不重启）：转发为 0，`iptables -S FORWARD` 不是 `-P FORWARD DROP`。
- [ ] 名单：面板「立即更新」（或 `meridian-update-*.sh`）在三种策略下的结果与 `status.json` 一致；`geosite/cn.txt` 非空（数千条）；chnroute 两个集合有元素；源不可达时在限定时间内结束，已有名单文件和集合不变；`systemctl restart meridian.service` 之后 chnroute 仍有元素；`meridian-host` 沙箱（`ReadWritePaths`）下写名单、`nft -f`、重启 SmartDNS 都成功。
- [ ] `meridian-host` 的沙箱（`ProtectSystem=strict`、只留 `CAP_NET_ADMIN`）下 `systemctl enable`/`restart`/`reset-failed`/`stop`、`ip link del`、`nft delete table`、`sysctl -w`、`journalctl`、`docker restart meridian-smartdns` 都能成功；任何一个失败就要放宽对应选项并记录。

已知边界：

- 第一次用这一版安装到一台用旧版本装过的网关时，宿主上没有旧清单。此时安装失败的补偿会把 Meridian 全部移除（先关转发再删兜底表），而不是回到旧版本；旧版本留下但新清单里没有的 `m*.conf` 不会被删除，也不会再被 up 脚本拉起。
- agent 重启会丢掉 `request_id` 缓存；面板此时重试会重新执行该动作。所有动作本身是幂等的（重启、存在才删）。
- `meridian-up.sh` 在 `/usr/local/sbin`，面板容器可写，并由 `meridian.service` 以 root 执行。边界保证的是「面板只能让宿主执行它自己写的 Meridian 脚本和固定动作」，不是「面板被攻破后宿主安全」。
- SmartDNS 两种形态都不存在时，安装成功但带告警（DNS 分流未生效），因为 Compose 的 dns profile 本来就要等首次安装写好配置后才启动。

## 面板开机等待局域网地址、受管 sysctl、概览探测通道

以下只有自动化回归，**没有在真实网关上执行过**。

- 自动化回归（`go test ./internal/api -run 'ListenLAN|StatusProbe'`）：地址未分配（`EADDRNOTAVAIL`）时等待并在出现后监听、日志有 `meridian-bind-waiting` 和 `meridian-bind-ready`；等满以 `meridian-bind-not-ready` 失败且说明不回落 `0.0.0.0`；端口被占用等其他错误立即失败；通配地址在监听之前被拒；本机未分配的文档地址由真实内核给出 `EADDRNOTAVAIL`。`GET /api/status` 在没有探测通道时 `probe_reason=not_configured`，agent 不应答时 `agent_unreachable` 并附错误，应答时可用且没有原因。
- 自动化回归（`go test ./internal/apply -run Sysctl`、`go test ./internal/compile -run TestUpAppliesManagedSysctl`）：已有网关上 `install.sh` 写过的 `99-meridian.conf` 在安装后被整份替换；读回内核后被改掉的键为 `differs`、内核没有的键为 `missing`、开机转发两行为 `boot_only`、旧文件独有的键列为 `stale`，问题和遗留都成为警告；第二次安装全部生效时没有警告；测试根目录下不读内核也不声称生效。编译出的 `meridian-up.sh` 循环（带假 `sysctl`）应用整份文件、跳过开机转发两行、跳过失败的键并打印 `meridian-sysctl: applied N, skipped 1`。
- 自动化回归（`npm --prefix web test`）：概览「解锁探测」卡片在 agent 不应答时显示「不可用」和原因，即使探测通道已配置；同名地区组在出口页卡片（「同名」标签和带地区、ID 的标签）、规则列表和目标选择、解锁的地区组选择里附带地区和 ID；安装结果的「内核参数」块（写入 / 已生效 / 未生效 / 开机值 / 旧文件遗留，只列出有问题的键；没读内核时不说生效）。
- [ ] 实机（主会话）：局域网口用 DHCP 的网关重启后，`docker compose logs meridian` 有 `meridian-bind-waiting` 和一行 `meridian-bind-ready`，容器重启计数为 0；拔掉局域网线开机时在 `MERIDIAN_BIND_WAIT` 之后有一行 `meridian-bind-not-ready`，面板从不监听 `0.0.0.0`（`ss -lntp | grep 8787`）。
- [ ] 实机（主会话）：从 `install.sh` 准备过的网关第一次「安装到网关」，安装结果的「内核参数」与 `sysctl -a | grep -F -f <(cut -d= -f1 /etc/sysctl.d/99-meridian.conf)` 一致，`journalctl -u meridian.service` 有 `meridian-sysctl:` 汇总行；旧文件遗留的键在重启后回到发行版默认值。
- [ ] 实机（主会话）：停掉 `meridian-host` 后概览「解锁探测」显示「不可用 · meridian-host 连不上」，启动后恢复「可用」。

## 地区组和 Mesh

- [ ] 香港机房组里有多台非家宽出口，面板上首选是 IX 绑定的那台。家宽在另一个组，至少两台。
- [ ] 把首选成员的探测连续打失败 3 次，枢纽上该组自己的路由表（`ip route show table <组表>`）下一跳换成同组备成员。只失败 1 次时下一跳不变。各出口自己的表不变。（实机：看 `/run/meridian/group/<组 ID>/report`，或在面板「出口」页读取枢纽状态。仓库里用状态机单测和在 bash 里带桩运行生成的 `group_step` 覆盖了同一规则：`go test ./internal/pool ./internal/compile -run 'Group|Hub'`。）
- [ ] 首选恢复后，要连续成功满 120 秒、最近一次探测成功、并且距上次切换满 120 秒才切回；恢复期间首选再失败一次，恢复计时清零。首选已经判死时，这 120 秒不会把下一跳留在另一台也已经判死的成员上。
- [ ] 手动组「保持」：指定成员判死后下一跳不变，`reason=held`、`alert=1`。「回落」：切到有效顺序里的下一个成员，`reason=fallback`、`alert=1`，恢复后按上一条切回。
- [ ] 组内 WireGuard 都失败且该组有 Mesh 边时，下一跳才是 `mmesh`，并且只有 `/run/meridian/mesh-sealed` 存在时才装这条路由。没有密封或没有 Mesh 时，这张表是黑洞，不改去别的国家，也不从枢纽的默认路由出去。
- [ ] 改组（顺序、指定成员、成员）后下发：`meridian-failover.service` 被重启，组表回到编译时的选择。

### 枢纽实际状态回读（面板「实际使用」）

机制见[架构](architecture.md#实际状态与面板推算两个来源分开显示)。

- 自动化回归（`go test ./internal/compile ./internal/hubstate ./internal/api`）：
  - 枢纽侧，在 bash 里带桩（`ip` 按表保存路由并可对某张组表注入失败、`ping`、`date`）运行**生成的**切换脚本，再用面板的固定命令读回并交给面板解析器：`TestHubStateRecordsSwitch`（启动写入部署标识；心跳每轮前进；成功切换记录新成员、原因、时间，面板判为 `ok`；Mesh 未封装时报告 `blackhole`）、`TestHubStateRecordsFailedSwitch`（组表的路由命令失败：`result failed`、`want`、`hop` 仍是原成员，切换器状态不变，面板判为 `switch_failed`；之后恢复切换成功；表被外部改动判为 `diverged`）、`TestHubStateStaleAndVersion`（心跳超过阈值为 `stale`、恰好在阈值内仍是 `ok`；改了组的顺序为 `version_mismatch`；与组无关的改动不改部署标识）、`TestHubStateWritesAreAtomic`（写入期间并发读取从未读到半个报告）、`TestHubStateScriptShape`（循环间隔与阈值一致；只有枢纽的切换脚本带记录）。
  - 解析与判定：`internal/hubstate` 的 `TestEvaluateStates`、`TestEvaluateClock`、`TestEvaluateIdentity`（枢纽节点、服务器、地址、端口、指纹任一变化、指纹未固定、无枢纽、旧格式读取都判为 `hub_identity_changed`，成功和失败的读取都一样；规范化后相同的地址不算变化）、`TestNormalizeAddress`、`TestParseRejects`（未知成员、Mesh 边不存在时的 `mmesh`、格式错误、控制字符、shell 字符、重复字段 / 组、不完整、过大、时间不合理）。
  - 面板侧，对进程内 SSH 测试服务器的固定命令给出预设输出：`TestHubStateReadStates`（`ok`、`stale`、`version_mismatch`、`switch_failed`、未知成员、缺记录、格式错误、过大、命令失败、密码错误、主机指纹变了；发出的命令永远是那条常量，请求体里的东西不会进入命令；非 `ok` 状态没有任何成员被标为实际使用；模型与实际分开；密码不在响应、日志和存储里）、`TestHubStateUnreachable`（指纹未确认时不登录、枢纽没有服务器、静态组为 `not_switchable`）、`TestHubStateRefreshSerialised`（并发读取 409）、`TestHubStateLimitsAgree`；身份绑定：`TestHubStateIdentityRelink`（枢纽节点改到另一台服务器后旧报告立即未知，读取后显示新主机的报告；改回去同样未知）、`TestHubStateIdentityAddressEdit`（改名不影响；原地改地址立即未知，重新确认同一把钥匙后仍未知，直到在新地址读取成功）、`TestHubStateIdentityPortEdit`、`TestHubStateIdentityFingerprint`（指纹不一致、重新确认另一把钥匙、清除指纹）、`TestHubStateIdentityLateResult`（读取进行中改指向 / 重新确认指纹 / 改地址 / 改端口：读取期间的 GET 已显示未知，迟到的结果返回 409 `hub_identity_changed` 且不入库，存储的仍是之前那次读取）。这些包用 `go test -race ./internal/api ./internal/hubstate` 跑。
  - 界面（`npm --prefix web test`）：只有模型时显示「面板推算」和「未验证」，不出现「实际使用 <成员>」和「使用中」；`actual.ok` 时显示成员、原因、上次切换、读取时间；过期 / 版本不一致 / 切换失败各自的原因和修复入口；读取不是当前枢纽时显示「未验证 · 枢纽已变更」和原因、状态条标「不是当前枢纽」、即使刚读过也自动读一次，读取期间枢纽又变了（409）时提示结果已丢弃并重新加载；枢纽暂时读不了时链到服务器页且不自动读；打开页面自动读一次、按钮再读、不轮询；概览卡片同样只在 `ok` 时写成员。
- 隔离 Linux 集成：`TestNetnsGroupDNSFailover` 在真实内核的命名空间里跑编译出的 `group_step`，并核对报告：切换后 `hub report: hop in table us: us-2`、`hub report: result: ok`，全部成员断开且 Mesh 未封装时 `hub report: hop in table us (Mesh unsealed): blackhole`；Mesh 阶段（2026-11-13 跑通，见 `docs/evidence/2026-11-13-debian13-mesh-dns/`）在密封后 `hop` 是 `mmesh`，失去密封后回到 `blackhole`。
- 自动化回归：`TestHubGroupOnMeshFollowsSeal`（组停在 Mesh 上时，密封出现后下一轮组表转到 sidecar 的下一跳，密封消失后下一轮回到黑洞，`active` / `switched` 不变）。
- [ ] 实机（待人工签收）：在真实枢纽上让某个可切换组的首选成员失效，枢纽切换后在面板「出口」页点「读取枢纽状态」，该组显示「实际使用 <备成员>」、原因「故障切换」、上次切换时间与枢纽上 `ip route show table <组表>` 和 `/run/meridian/group/<组>/report` 一致；同时在测试机上确认流量确实从备成员出去（`ipleak`）。再停掉 `meridian-failover.service` 超过阈值后读取，显示「状态过期」而不是成员；改一下组的顺序但不装机，读取显示「枢纽不是当前配置」。再在服务器页改枢纽服务器的地址（或把枢纽节点改到另一台服务器），不读取，刷新页面：每个可切换组立即显示「枢纽已变更」而不是成员。签收时记录读取时间和枢纽上的报告原文。身份绑定目前只有上面的自动化测试（进程内 SSH 测试服务器），没有在真实枢纽上执行过。
- [ ] 家宽网关上没有 `cloudflare/mesh`，也没有 `dev mmesh`。Mesh 只在枢纽和出口的独立网络命名空间里。本机地址是 `192.168.100.88/24` 时，mesh 脚本拒绝启动。
- [ ] `/etc/meridian/mesh.env` 权限 0600，令牌不在 git 里，由面板部署写入（经 SSH 标准输入传送，不出现在远端进程列表）。文件为空时 sidecar 不启动，其余隧道照常。
- [ ] 删掉 IX 或把 Mesh 从家宽画到出口，保存被拒绝。

### 地区组的解析

机制见[架构](architecture.md#地区组的解析)。可切换组的名字经组的解析地址（`fd66::53:<k>`）、带组 mark 查询，网关把源地址改成组的中转地址，枢纽按源地址送进当前成员，成员把它 DNAT 到自己的隧道解析器。

- 自动化回归（`go test ./internal/compile ./internal/validate`）：`TestGroupDNSSmartDNS`（每组一个上游、只有组解析地址、mark 是十进制、钉死 / 解锁移动 / 不可切换组仍用成员解析器、国内解析器不在任何组上游里、默认组里只有默认地区组的上游）、`TestGroupDNSGatewaySNAT`（SNAT 在一组包上求值：只有组 mark + 组解析地址 + 53 被改写；局域网和设备入口对解析地址一律丢弃；带 mark 的出路只有西向隧道和黑洞）、`TestGroupDNSExitDNAT`、`TestGroupDNSHubPath`、`TestGroupDNSAbsentWithoutSwitchableGroup`、`TestGroupResolverAddresses`、`TestGroupResolverReserved`，以及验收脚本的桩测试。它们只证明生成结果。
- Mesh 备路（机制见架构「地区组的解析」第 7 条）的自动化回归：`TestGroupDNSExitDNAT`（出口只认枢纽隧道和 `mmesh` 两个入口，`mmesh` 只在组的 Mesh 解析成员上；回包 mark 只用在 `mmesh` 进来的连接上）、`TestGroupDNSMeshResolverPublication`（每个有 Mesh 边的可切换组恰好一个 Mesh 解析成员，只有它的 `meridian-mesh-up.sh` 带发布行，`mesh.BuildPlan` 只把这些发布成该出口的路由）、`TestGroupDNSMeshReturnPath`（表 171 只有 sidecar 下一跳和黑洞，从不经枢纽隧道或 WAN；路由脚本和 `meridian-mesh-up.sh` 共用 `mesh_dns_return`；出口有重新密封的 timer；别的出口什么都没有；`bash -n`）、`TestGroupDNSMeshReturnFollowsSeal`（带桩 `ip`：只有 `mmesh` 存在且已密封时才装 sidecar 下一跳）、`internal/mesh` 的 `TestPlanPublishesGroupResolvers`、`TestPlanRejectsForeignPublishLines`、`TestActivateRefreshesGroupResolverExits`。它们只证明生成结果和控制流。
- 隔离 Linux 集成：`TestNetnsGroupDNSFailover`（上面「每个命令能证明什么」）。成员切换部分 2026-11-13 在一台 Debian 13 上跑通（见已存档的执行记录）；Mesh 阶段（第 7–9 阶段）是之后加的，同一天在同一台主机上跑通（`docs/evidence/2026-11-13-debian13-mesh-dns/`）；第一次运行时暴露了编译出的封装脚本把成功和失败判反的缺陷，修正后才通过。它用的是编译出的规则和脚本，但成员出口上的解析器是替身，隧道是 veth，Mesh 是两个 tun 设备之间的转发，连接器的源地址转换是假设：真实出口上的解析器、真实枢纽、真实 Cloudflare Mesh 和带客户端的真实故障切换仍是待人工签收。
- 网关本地（`meridian-verify.sh`）：`group_dns_snat`（已加载的主表里每个可切换组都有解析 SNAT）、`group_dns_upstream`（`/etc/smartdns/smartdns.conf` 里每组有带十进制 mark 的上游，出现十六进制 mark 即 FAIL）、`group_dns_route`（`ip -6 route get <解析地址> mark <组 mark>` 落在网关的隧道接口上，落到局域网口、黑洞或不可达都是 FAIL）。它们看不到成员是否应答。
- [ ] 实机（待人工签收）：选一个可切换组，把它当前成员的隧道和解析器都停掉，等枢纽切换（`/run/meridian/group/<组>/active` 变成备成员）；在测试机上解析一个此前没解析过的、命中该组规则的名字，能得到地址并能打开，`ipleak` 显示备成员的出口；同时在网关局域网口抓包，没有这个名字的查询发往国内解析器或 ROS。再把组内成员全部停掉：这个名字解析失败（不是从别处得到答案）。
- [ ] 升级顺序：先下发出口和枢纽，再安装网关。网关先装、出口还是旧版本时，组内新名字解析失败，这是预期的（不回落）。
- [ ] 实机（待人工签收，需要真实 Cloudflare Mesh）：部署 Mesh 后，Cloudflare 上 Mesh 解析成员的节点有 `fd66::53:<k>/128` 这条路由（面板部署记录里 `purpose: group_resolver`）；让该组所有 WireGuard 成员失效，枢纽 `/run/meridian/group/<组>/report` 里 `hop mmesh`；测试机解析一个新的、命中该组规则的名字能得到地址并能打开；同时在 Mesh 解析成员上抓 `mmesh`，看到查询进来、回包从 `mmesh` 出去，枢纽隧道和 WAN 上没有这些回包；在网关局域网口抓包，没有这个名字的查询发往国内解析器或 ROS。再停掉 Mesh 解析成员的 sidecar：查询失败（不是从别处得到答案）。签收时同时记下枢纽 sidecar 有没有对进入 Mesh 的流量做源地址转换（出口 `mmesh` 上查询的源地址）。

`docs/evidence/` 下 2026-11-12 的存档早于这一改动，不覆盖它。2026-11-13 的存档是加入它之后的最后一次构建：`meridian-verify.sh` 的日志里有 `group_dns_*` 三项（共 47 项本地检查），`netns-group-dns.log` 是上面那个命名空间测试的通过记录，另有一次用真实 SmartDNS 观察出站路径的手工核对（见该目录的 README）。真实出口、真实枢纽和带客户端的故障切换不在其中。

### Mesh veth 下一跳（审计 P1）

`mmesh` 是以太网 veth，不是点对点隧道。以前的 `default dev mmesh` 没有下一跳，内核会对每个公网目的地址在 veth 上做 ARP / 邻居发现，而没有任何代理 ARP/ND 或静态邻居来回答；IPv6 也根本没有 veth 下一跳。在 Cloudflare 发布路由修不了这一段。现在：

| | 主机端 `mmesh` | sidecar 端 `mmesh-c` | 主机出口表 |
| --- | --- | --- | --- |
| IPv4 | `169.254.66.1/30` | `169.254.66.2/30` | `default via 169.254.66.2 dev mmesh table N` |
| IPv6 | `fe80::66:1/64 nodad` | `fe80::66:2/64 nodad` | `default via fe80::66:2 dev mmesh table N`（链路本地，作用域由 `dev mmesh` 给出） |
| MAC / 邻居 | `02:6d:65:73:68:01`，永久邻居指向 `…:02` | `02:6d:65:73:68:02`，永久邻居指向 `…:01` | — |

静态路由（`meridian-routes.sh`）和动态出口切换（`meridian-failover.sh` 的 `group_hop`，与路由脚本共用同一段 `MESH_NH4` / `MESH_NH6` 定义）用同一组下一跳。sidecar 的回程（网关局域网、`10.66.0.0/16`、`fd66::/48`、局域网 IPv6 前缀）`via 169.254.66.1` / `via fe80::66:1 dev mmesh-c`。`meridian-mesh-up.sh` 只在主机侧 ping 通两个下一跳之后才写 `/run/meridian/mesh-sealed`；sidecar 内的 `inet meridian_mesh` 改成一个 nft 事务（建表 → 删表 → 重建）。

- **自动化回归**：`go test ./internal/compile -run 'TestMeshVethNextHops|TestMeshUpSealFollowsSidecarBlock'`（后者在 bash 里带桩运行编译出的 `meridian-mesh-up.sh`：只有 sidecar 内的密封块成功且两个下一跳都通时才写 `mesh-sealed`；修正了此前反过来的判断）、`go test ./internal/verify -run TestMeshItemsNeverClaimForwarding`、`go test ./internal/mesh`（地址与冲突校验、阶段顺序、每个阶段的故障注入与补偿、补偿失败可重试、只撤回本次拥有的资源、凭据不落盘/不回显；撤回只去部署时固定的主机与主机指纹、主机上没有本次备份目录不算已恢复、撤回前核对 Cloudflare 账户、撤回完成前不能切换账户且与凭据修改串行）。只说明生成的文本和控制流正确。
- **隔离 Linux 集成证据（2026-11-12 和 2026-11-13 各执行过一次，见已存档的执行记录）**：`sudo bash deploy/verify-mesh-veth.sh`。在四个临时 netns 里按生成的命令搭出 主机 ↔ sidecar ↔「warp」，v4 / v6 的 ICMP 和 TCP 都要经 `169.254.66.2` / `fe80::66:2%mmesh` 转发，`mmesh` 上只解析这两个下一跳；同时把出口表换成旧写法 `default dev mmesh` 作为对照，对照必须不通。最后一行应是 `meridian-mesh-veth-verify-ok`，把证据目录存档。它于 2026-11-12 在一台 Debian 13 上跑通（8 项 PASS，存档在 [docs/evidence/2026-11-12-debian13/mesh-veth.log](evidence/2026-11-12-debian13/mesh-veth.log)），证明的只是命名空间里主机到 sidecar 这一跳；改过 Mesh 的地址、路由或 `meridian-mesh-up.sh` 之后要重跑。Cloudflare、真实 sidecar 镜像和真实出口都不在这项测试里，Mesh 备路的真实转发仍是待人工签收。面板「防泄露」页的「Mesh veth 下一跳双栈转发（netns）」一律显示「未执行」，因为面板不运行它，也不读取存档。
- **实机人工签收（待签收）**：「Mesh 备路真实转发（v4 / v6）」。让池里所有 WireGuard 成员失效、出口表切到 `mmesh` 后，在枢纽 `mmesh` 和出口上抓包，v4 / v6 测试流量从出口离开，`mmesh` 上没有对公网目的地址的 ARP / NS。

在这两类证据存档之前，Mesh 数据面在代码、面板和文档里都是 **未验证**。面板部署的结果「路由已发布」只表示 Cloudflare 路由已经发布，不等于「Mesh 可用」。

### 面板部署 Mesh（资源 → Cloudflare → Mesh 部署）

- [ ] 账户：account id + API token 存在 `meridian-secrets` 卷（`<secrets>/index.json` 与 `secrets/<id>-<代>.json`，0600，目录 0700），任何接口都不回显 token；权限比 0600 宽的文件会被拒绝使用。还有已发布或补偿未完成的部署时不能删除这个账户、不能改它的 account id、不能把 Mesh 切到别的账户；同一账户可以替换 token。旧的 `mesh/cloudflare.json` 在升级时迁移成账户 `cf-mesh` 并删除。
- [ ] 「检查权限」只调用只读接口：结果是令牌有效、可读节点和路由，写权限显示「未确认」；被拒的接口列成缺少的权限。
- [ ] 计划里任何节点没有关联「就绪」的服务器（缺凭据、缺已确认指纹）时，部署 409 `servers_not_ready`，一个阶段都不执行。
- [ ] 计划阶段报出：Mesh 边没有 `mesh_routes`、路由与 `10.66.0.0/16` / `fd66::/48` / 局域网 / `100.96.0.0/12` / veth 链路重叠、两条边路由重叠、默认路由、拓扑地址落在 `169.254.66.0/30`。有任何一项时「部署 Mesh」不可点，后端也会在计划阶段停下，不碰任何主机和 Cloudflare。
- [ ] 预检报冲突（已有 `mmesh` / `meridian-mesh` 容器 / `meridian_mesh_lib` 卷 / 非空令牌、`169.254.66.0/30` 或 `fe80::66:1/2` 已被占用、枢纽脚本仍是 `default dev mmesh`）时停下，Cloudflare 没有任何调用。
- [ ] 健康检查不过（任一下一跳不通、`mmesh` 上出现别的邻居、warp-cli 未连接、Cloudflare 节点不是 healthy）时，没有任何路由被发布，本次创建的节点和 sidecar 被撤回。
- [ ] 故障注入演练：面板进程带 `MERIDIAN_MESH_FAULT_INJECTION=1` 启动后，对每个阶段选「在该阶段后失败」各跑一次：后续阶段都是「未执行」，Cloudflare 上本次创建的节点 / 路由都被删除，主机上的 `mesh-sidecar.compose.yml`、`meridian-mesh-up.sh`、`mesh.env` 恢复成部署前的内容，别人的节点和路由不动。
- [ ] 部署后删掉拓扑里的某个 Mesh 节点再撤回：面板仍连接部署记录固定的服务器、凭据、地址并要求原主机指纹；被固定的服务器不能删除或改地址 / 端口 / 用户 / 凭据（409 `in_use`），凭据可以原地轮换；把同一地址换成另一台机器（指纹变了）时撤回被拒绝、记录保留为「补偿未完成」。发布后把 Mesh 切到另一个 Cloudflare 账户被拒绝（409 `account_locked`），同一账户换 token 可以。
- [ ] 补偿失败（例如撤回路由时 Cloudflare 报错、SSH 不通）时，面板单独列出没撤回的资源，状态是「补偿未完成」，不能开始新部署；修复后再点「撤回 / 重试补偿」，已完成的步骤不会重复。
- [ ] 部署记录 `mesh/deploy.json`（0600，schema 3）里有每个阶段的状态、本次拥有的外部资源（Cloudflare 节点 id、路由 id、写过的主机）和固定的服务器 / 凭据 ID，没有 API token、节点令牌、SSH 密码或私钥。

## 服务器、密钥与 Cloudflare 账户

- 自动化回归（`go test ./internal/credentials ./internal/sshexec ./internal/api`）：存储权限与原子写、轮换、引用；指纹状态（未见过 → 发现 → 确认 → 不符）；发现不认证、指纹不符在认证之前拒绝、部署固定的指纹与目标；密码 / 私钥 / 口令从输出和错误里去掉；`sshtest` 进程内 SSH 服务器上的连接测试与装机（密码和带口令的私钥两种凭据）；Cloudflare 权限检查用假 HTTP 服务。
- [ ] 实机（主会话）：对一台真实远端服务器做一次「发现 → 核对（与远端 `ssh-keygen -lf` 一致）→ 确认 → 测试」，再「装机」；改远端主机密钥后连接在认证之前被拒绝。
- [ ] 实机（主会话）：真实 Cloudflare 账户的权限检查结果与令牌实际权限一致；缺写权限时部署在「创建节点」阶段失败并被补偿。
- 自动化回归（`go test ./internal/sshexec -run 'RateLimited|PreBanner|Pool'`、`go test ./internal/api -run 'TestSSHFlowReusesOneLogin|TestSSHRateLimitedAcrossOperations'`）：`sshtest` 的 `RefuseBeforeBanner` 模式在 SSH 版本行之前写一行 `Not allowed at this time` 并断开；发现、测试、预检、装机、枢纽读取、Mesh 远端操作都报 `ssh_rate_limited`（不是 EOF、不是登录或指纹问题），没有尝试凭据、固定指纹不变，冷却期间不再建立 TCP 连接（按接受的连接数计），冷却过后恢复；别的握手前文字附在说明里、不触发冷却。连接复用：连接测试 + 两次预检 + 装机脚本只有一次登录；一次装机请求、撤回计划 + 执行共用一次登录；轮换密码、换凭据、改用户、清除并重新确认指纹、部署固定的指纹不同时都不复用；修改服务器、轮换凭据立即关闭空闲连接；命令失败、空闲超时、超过最长存活、取消的操作都关闭连接。`npm --prefix web test`：限速时连接测试和「获取指纹」按钮显示倒计时并停用、预检对话框的「重新预检」和执行停用、端口冲突结论链接到拓扑里对应的链路字段、链路编辑器里的「wstunnel 本地端口」、出口节点的「WSS 监听端口」。
- [ ] 实机（主会话）：**限速识别和连接复用都还没有在真实主机上运行过。** 在经端口转发、OpenSSH 9.8+ 的服务器上，「测试连接 → 预检 → 装机」只产生一次登录（服务器 `journalctl -u ssh` 里一条 `Accepted`），被限速时面板显示「服务器暂时拒绝面板的来源地址（限速）」而不是「SSH 握手失败：EOF」，倒计时结束前不再连接。

## 装机前预检

预检只读；除了下面单独写明的 2026-11-13 只读运行，以下都是仓库里的自动化证据，没有在真实主机上执行过。

- 自动化回归（`go test ./internal/preflight`）：脚本参数校验（所有示例节点的路径都接受；`..`、相对路径、shell 元字符、引号、空格、换行、通配、目录外路径、超长、超量、重复一律拒绝）；脚本 `bash -n`（装了 shellcheck 时也跑）；静态检查脚本里没有任何改动主机的命令或写文件的重定向；在本机用 `bash -s --` 真跑一遍脚本，报告完整、被拒参数由脚本自己拒绝、不含文件内容；解析器对垃圾、截断、超长、超行数、控制字符 / 双向控制符 / 非法 UTF-8、伪造路径、清单块外的清单行、结束行之后的内容的处理；评估器对夹具 `testdata/*.txt`：干净的 Debian 13、Ubuntu 20.04 aarch64（无 nft、legacy iptables、内存 440 MB）、Docker `FORWARD DROP`（iptables-nft 与纯 nft 两种来源，每个协议族只报一次）、已有 `wg0/wg1/wg2`（51820 被占、10.66.11.0/24 与 10.66.0.0/16 重叠、10.67.0.0/24 与 10.8.0.0/24 不误报）、443/80 被 nginx 占用和另一个 wstunnel、53 端口（resolved / WARP 不冲突，通配或同地址冲突）、主机级 WARP（规则排在 main 之前）、空中继（转发将被打开）、忙中继（端口转发器不误报）、root / 架构 / 内核 / systemd / 发行版 / apt / SmartDNS 候选、清单三种归属与旧版标记文件、journal 中断与带残留的补偿、网关模式（安装清单的归属、标记文件交给接管、防火墙标记冲突）。
- 自动化回归（`go test ./internal/provision`）：装机脚本在本机沙箱里（主机路径挪到临时目录，`ip`、`nft`、`systemctl`、`wg-quick`、`apt-get` 等换成有状态的桩）真跑：成功写受管清单并能被预检读回；同一节点的更新通过复核、别的节点被 `manifest_changed` 拒绝、第一次装机遇到已有清单被 `manifest_appeared` 拒绝；`systemctl` 失败时补偿（新文件和目录删除、被替换的文件恢复、新接口和 nft 表删除、单元停用、sysctl 恢复、软件包保留并列出、journal 为 `compensated`）；接口删不掉时列为残留、journal 为 `incomplete`，再跑被脚本自己拒绝；没有绑定目标的脚本拒绝运行。
- 自动化回归（`go test ./internal/api -run 'Preflight|Provision|LoginHelp|Gateway'`）：计划视图里的目标身份、受管资源和变更；第一次装机缺 `preflight_id`、过期、记录被替换、包摘要变化、目标身份变化（换凭据）、审阅结果有阻断、执行前重跑出现阻断、出现新警告都被拒绝，且都没有生成密钥、没有发送装机脚本；通过时脚本绑定到预检（`M_EXPECT`、`M_BUNDLE`）；之后的更新照样重跑预检；补偿 / 残留 / 远端复核拒绝 / 没有成功标记各自的代码和 `outcome`；响应、日志和数据目录里没有密码和私钥；登录方式不被接受时给出公钥；网关安装的第一次必须预检、阻断时不激活、宿主代理不支持预检时 503。`go test ./internal/hostexec -run Preflight`：网关预检动作只运行固定的只读命令、不回传文件内容、拒绝坏路径和未知字段、输出触顶时报告不完整。
- 自动化回归（`npm --prefix web test`）：远端节点的预检对话框（目标、按严重度分组的发现和处理办法、变更清单、阻断时执行按钮不可用并写明原因、重新预检后带 `preflight_id` 执行、执行前复核出现新问题时留在对话框里显示新结果、残留与保留项、登录帮助里的公钥）；网关第一次安装前必须预检、带 `preflight_id` 安装；服务器页连接测试失败时显示可复制的公钥。
- [ ] 实机（主会话）：对每台真实服务器先「预检」，核对报告与 `ss -lntup`、`ip rule`、`nft list tables`、`iptables -S FORWARD` 手工结果一致；有 Docker 的出口被 `forward_policy_drop` 拒绝、Ubuntu 20.04 被 `os_unsupported` 拒绝；没有阻断的服务器装机成功并写出 `/var/lib/meridian/node/manifest`；之后的预检显示 `existing_install`。
- [ ] 实机（主会话）：在一台可以随意重装的服务器上制造一次失败的第一次装机（例如先让 `smartdns.service` 起不来），确认补偿后主机回到装机前（接口、nft 表、规则、文件、sysctl），journal 为 `compensated`；断开 SSH 中途的情形单独验证。
- 自动化回归（`go test ./internal/preflight -run 'UpdateOfOwnInstall'`、`go test ./internal/api -run TestGatewayUpdateGateOnOwnInstall`）：脱敏的实机网关报告（已有安装、SmartDNS 是 compose 容器、wstunnel 客户端是安装的单元、lo 上的中转地址，进程名不可见、按 cgroup 归属）评估为非阻断，更新安装经重新预检后通过；旁边多一个别人的 :53、别的容器、清单外的单元、读不到 cgroup、没有清单（第一次）都仍然阻断；远端「本节点、本面板」更新（枢纽、中继、出口）非阻断，换成别的部署 ID 全部阻断。
- [ ] 实机（主会话）：网关上「安装前预检」经 `meridian-host` 的 `/v1/preflight` 得到完整报告（需要先升级宿主上的 meridian-host）。
- 已发生的实机运行（主会话，2026-11-13，只读）：预检从面板对 11 台真实服务器和网关各执行过一次，拦下了 Docker 把 FORWARD 设为 DROP 的主机、51820 被已有 WireGuard 占用的主机、Ubuntu 20.04、缺 wstunnel 的中继，并对低内存主机给出提示；暴露的「网关把自己的资源报为冲突」随后修复并在网关上复跑为非阻断（归属 `same`）。没有在任何真实主机上装机、补偿或撤回。
- 自动化回归（`go test ./internal/preflight -run 'Port'`、`go test ./internal/validate`、`go test ./internal/api -run TestGatewayPortConflictNamesTheField`）：每个示例节点的端口计划与它编译出的包读回的监听完全一致；`existing-wireguard` 夹具上 51820/51821 被占时结论带指向链路 `wg_port` 的 `fix`，把端口改掉后监听端的配置、拨号端的 `Endpoint` 和预检读出的监听一起变化，冲突消失；节点 `listen_port` 只在唯一一条没设 `wg_port` 的链路上生效；同一节点自己的端口冲突、保留端口、`listen_port` 二义都被校验拒绝；网关的 wstunnel 本地端口被占时结论指向链路 `wss_local_port`，改掉后包摘要变化、不再阻断。
- [ ] 实机（主会话）：在一台 51820 已被占用的真实服务器上，按预检结论的「去拓扑修改」换端口，重新预检不再报 `port_in_use`，对端（网关或枢纽）重新安装 / 下发后握手成功。

## 撤回与恢复

以下都是仓库里的自动化证据（本机沙箱真跑脚本、进程内 SSH 服务器、模拟宿主上的真实 `meridian-host` 代理），**没有任何一项在真实服务器或网关上执行过**。

- 自动化回归（`go test ./internal/provision -run Withdraw`）：参数校验（节点 / 部署 / 服务器 / 运行 ID 的形状、模式与动作枚举、`run` 必须带 64 位摘要、`plan` 不带）和坏参数时脚本在做任何事之前拒绝；三种模式两种动作的脚本 `bash -n`（装了 shellcheck 时也跑）；`M_ROOT` 是固定字面量。沙箱里先用真的装机脚本装上节点 `tw`，再真跑撤回脚本：计划只读、摘要不符时 `plan_changed` 且什么都没改；撤回只删清单里的接口、单元、nft 表、规则、路由表、黑洞路由和文件，旁边的 `wg0` 接口和配置、`inet other` / `inet docker` 表、`other.nft` 不动，不卸载软件包；journal 为 `withdrawn`、清单删除；再计划 / 再执行都回答「已撤回」，之后第一次装机又能通过复核。别的节点、别的部署、别的服务器、清单里有 `eth0` 或 `/etc/cron.d` 这样的条目、没有清单的空主机都被拒绝且主机不变。装机后被改过的文件保留、接口删不掉时为 `withdraw_incomplete`，期间装机脚本以 `withdraw_incomplete` 拒绝，处理后同一份计划再执行完成。中断的装机（`incomplete` 改成 `running` 模拟被杀）由 journal 模式补偿、之后能再装；没有 `params` 的运行只关闭 journal；有动作没参数或工作目录不在时拒绝。旧版清理只处理带标记的固定路径（不带标记的 `m15.conf`、提到 Meridian 的 `ssh.service` 不动），清单变化后拒绝，并提示黑洞路由要人工查。
- 自动化回归（`go test ./internal/apply -run GatewayWithdraw`、`go test ./internal/hostexec -run Withdraw`）：网关撤回只删安装清单里的东西，`wg0` 和别的 nft 表不动；先关两种转发、再停 `meridian.service`、再删接口；兜底表和它的开机文件保留，从不删兜底表、从不打开转发；安装清单变为 `withdrawn`；再撤回只复查；撤回后运行态回滚被拒绝、重新安装可以；中途失败补偿回原来的运行状态；补偿也失败时 journal 保留（`kind withdraw`）、拒绝新的撤回，重启后恢复；没有安装 / 旧版 / 没有网关私钥（无法补偿）时拒绝且不动宿主；移除兜底表只在撤回之后、先关转发再删表。宿主代理：`withdraw` 拒绝点名兜底表、解析器、非受管名字；账本外存在的接口被拒绝；兜底表不在时重启 `meridian-guard.service`，仍不在就失败。
- 自动化回归（`go test ./internal/api -run 'Withdraw|RemovedExits'`）：部署记录绑定身份并固定服务器和凭据（改指向、删凭据 409）；计划 → 缺确认 / 计划不存在 / 计划重复使用被拒绝 → 部分完成（继续固定）→ 重新计划 → 完成（解除固定，下次装机要预检）→ 再计划回答已撤回 → 删除记录；脚本里只有校验过的身份值和计划摘要；节点改指到另一台服务器时新服务器上的预检被 `deployed_elsewhere` 拒绝、撤回仍去原服务器；忘记指纹、换成另一把指纹时拒绝且不发送脚本；远端拒绝（属于别的节点、没有清单）、结果不明、连不上都不算撤回；放弃要输入节点 ID、明说未核实；Mesh 记录还固定着节点时拒绝、Mesh 撤回后可以；中断的装机经 journal 模式恢复；网关撤回、再撤回、回滚被拒、移除兜底表、之后没有安装；解锁结果里已删除出口默认不列出、可选列出并标记、可清理，历史与准入记录保留。`go test ./internal/unlock -run RemovedExits`：标记已删除出口不改变准入，旧结果仍被 `out_of_order` 拒绝。
- [ ] 实机（主会话）：在一台可以随意重装、上面另外跑着 Docker 和一个自己的 WireGuard 接口的服务器上，装机 → 撤回，确认 `ip link`、`ip rule`、`ip route show table all`、`nft list tables`、`systemctl list-units 'meridian*'`、`ls /etc/meridian /etc/wireguard` 只少了清单里的东西，Docker、别的接口和别的 nft 表都在，软件包都在；再撤回一次显示「已撤回」。
- [ ] 实机（主会话）：撤回途中断开 SSH：服务器 journal 为 `withdrawing` 或 `withdraw_incomplete`，面板显示「撤回中断 / 结果不明」，再生成计划并执行能完成。
- [ ] 实机（主会话）：装机途中 `kill -9` 远端 bash，journal 停在 `running`；面板「恢复中断的装机」后主机回到装机前。
- [ ] 实机（主会话）：网关撤回后，局域网测试机 IPv4 与 IPv6 都没有任何流量经 ROS 直出（抓包），`nft list table inet meridian_guard` 仍在，`sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` 都是 0；重启网关后同样（`meridian-guard.service` active、`meridian.service` 被条件跳过）；然后「移除兜底表」，确认表和 `/etc/nftables.d/meridian-guard.nft` 都不在；最后重新预检并安装回来。
- [ ] 实机（主会话）：需要先升级宿主上的 `meridian-host`（新增 `withdraw` 动作）；旧版代理会以「不支持的宿主动作」拒绝，面板显示失败并补偿，不会显示已撤回。

## 名单

- 自动化回归：`go test ./internal/lists ./internal/hostexec ./internal/api -run 'List|Lists'`（v2fly 解析与 include 展开、形状检查、换源、保留旧版、单个 nft 事务、动作锁、状态文件）；`go test ./internal/compile -run TestUpScriptReaddsSavedChnroute`（重载时把保存的批次接到规则后面，坏副本被忽略）；`meridian-verify.sh` 的 `chnroute_loaded` / `geosite_cn` 判定（见上）。
- [ ] 实机（主会话）：三种策略各更新一次，`status.json`、面板「名单」页和 `meridian-verify.sh` 的 `INFO list` 行一致；`cn.txt` 有数千条；`systemctl restart meridian.service` 后 `chnroute_loaded` 仍为 PASS。

## 远程接入

步骤和签收项见 [remote-access.md](remote-access.md)「验证」。

- 自动化回归：`go test ./internal/compile -run 'Remote|VerifyScriptRemote'`、`go test ./internal/apply -run Remote`、`go test ./internal/api -run 'RemoteAccess|RegeneratedDevice'`、`go test ./internal/validate`。
- 隔离 Linux 集成：`TestNetnsReloadNoLeak` 的远程设备命名空间、网关上 `meridian-verify.sh` 的 `remote_*` 检查，都于 2026-11-13 执行过（见已存档的执行记录）。当时 `mra` 上有两个 peer，但没有任何设备真的拨入。
- [ ] 实机人工签收（未执行）：路由器转发、手机蜂窝两种模式、IPv6、停用和重新生成后旧配置失效。

## 解锁

- [ ] 面板「解锁」能看到各服务的首选、当前出口、下一次 6 小时定时，以及历史。
- [ ] 定时失败一次，自动规则不动。连续两次，才换成同池备成员。AI 仍在美国，Netflix / Disney+ 仍在香港家宽，台湾服务仍在 TW。
- [ ] 钉死的手动规则（示例 `api.example.com`）不跟着映射走。
- [ ] 池里没有成员能解锁时标成不可用，不会改到日本或别的国家。
- [ ] 切回首选前，首选已经再次成功，并且过了 30 分钟。
- [ ] 首选恢复成功之后又失败一次（定时或手动都算）：恢复计时清零，即使已过 30 分钟也不切回；之后要重新连续成功满 30 分钟。

### 切回判定与报告规则（自动化回归）

规则在 `internal/unlock`（包注释和 `report.go`），`/api/unlock/report` 和面板发起的探测（下一节）都经过 `unlock.Ingest`：

- 切回首选需要同时满足：处于滞回中；面板收到的首选**最新**结果是成功；这条结果是 30 分钟内（`ResultFreshFor`）收到的；从最后一次失败之后的第一次成功起连续成功满 30 分钟（`ReturnCooldown`）。首选任何一次失败（定时、手动、健康补测）都会立刻清掉恢复起点。备选是否成功不参与切回判定。
- 冷却和新鲜度只用面板时钟（收到报告的时间，单调递增）。报告里的 `at` 是探测开始时间，只用于排序和有效期。
- 按「服务 + 出口 + 地址族（ipv4 / ipv6 / any）」排序：比已采纳结果更旧的报告记为 `out_of_order`，同一时刻的重复报告记为 `duplicate`（同一时刻失败可以覆盖成功，成功不能覆盖失败）；`at` 早于收到时间 1 小时以上（`MaxReportAge`，覆盖出口上最长 55 分钟的探测）记为 `stale`，晚于收到时间 2 分钟以上记为 `future`。被拒的结果写进历史，不改状态。
- 同一服务、同一出口每一轮探测只推进状态机一次：同一轮里各地址族的结果取「任一族解锁即可」。比该出口已推进过的那一轮更早的结果（哪怕是另一个地址族）记为 `superseded`，所以旧一轮的 IPv6 成功不能抹掉新一轮的 IPv4 失败。同一轮的各族结果要在同一份报告里送达。
- 并发：所有写入都在面板的同一把锁里做「读 → Ingest → 写」，采纳与否只看探测时间，不看到达先后。

`go test` 覆盖：审计复现（首选成功后在 31 分钟时失败，不切回）、失败后计时重来、过期的首选成功不触发切回、迟到成功不能覆盖新失败、有效期、重复报告只计一次、同时刻失败优先、地址族分键但旧一轮不能推翻新一轮、乱序并发投递（单元与 API 两层）。这些是状态机测试，不是实机解锁测试。
- [ ] 映射变化后，下发之前数据面仍是旧的 mark。下发之后 SmartDNS 和 nft 的出口一起换。
- [ ] 实机：在出口上跑 `meridian-unlock-probe.sh`。没有 Docker 或本地没有 `lmc999/regioncheck` 镜像时，脚本只写下说明，不编造成功，也不会停在区域菜单上。报告里带探测开始时间 `at`，IPv4/IPv6 两轮分别放在 `raw4`/`raw6`。
- [ ] 报告里的 `Region:` 和出口地区不一致时，记为失败，不把这条自动规则留在「已解锁」上。

### 面板发起的解锁探测

面板「解锁 → 面板探测」的「立即测试」和每 6 小时的定时走同一条链：

```
立即测试 (POST /api/unlock/run, kind=manual) ┐
定时 tickUnlock (kind=scheduled)            ┴→ startProbeJob：服务 × 出口 × 地址族，校验、上限、只允许一轮
  → runProbeJob：同时最多 2 个出口
    → runProbeGroup（一个出口）：每个地址族一次 hostexec.Client.Probe（不重试）
      → meridian-host POST /v1/probe → probe.Prober.Run：出口检查 → 各平台适配器 → 再次出口检查
    → unlock.Ingest：每个服务一份 Observation，带这一轮全部地址族；在面板写锁内「读 → Ingest → 写」
```

- **只接受枚举值**：面板只能选 `internal/probe` 目录表里的 14 个适配器（每个适配器能给出哪一级结论、只做到达性的是哪些、哪些只发 IPv4，见 [unlock-methods.md](unlock-methods.md)「能力声明一览」）、拓扑里的出口和 `ipv4` / `ipv6`。请求体有多余字段（`url`、`command`……）直接 400。agent 侧 `ValidateProbe` 再校验一遍：出口 mark 必须在 `0x101`–`0x140`，中转地址必须在 `10.66.200.0/24` / `fd66:0:0:ff::/64`，解析器必须是 `fd66::/48` 里的出口隧道地址，服务必须在目录表里，最多 16 个。没有 URL、主机、端口、请求头、命令或路径参数；`MERIDIAN_UNLOCK_EXEC` 已删除，设置了也只会在日志里提示不再使用。
- **强制出口与地址族**：socket 带该出口的 fwmark（`SO_MARK`，需要 agent 的 `CAP_NET_ADMIN`），从该出口在 `lo` 上的中转地址发出，按地址族只用 `tcp4` 或 `tcp6`；名字经该出口的隧道解析器（ULA，同样带 mark 和中转源地址）只查 A 或 AAAA。网关上这个 mark 命中 `lookup 102`（默认路由是西向隧道，后面是 `unreachable`），阿里云和枢纽按中转源地址选出口，和局域网流量被 SNAT 之后走的路一样。本机发出的流量走 output 路径，不经过 `inet meridian_guard` 的 forward 兜底，所以每条连接前还要做路由检查：`ip -4|-6 route get <目的> from <中转地址> mark <mark>` 的出口设备必须是 Meridian 隧道接口（`m00`/`m00w`/`mmesh` 这一类），否则不连接。中转地址不在本机 `lo` 上（网关还没装这个出口）时什么都不发。
- **验证实际出口**：访问平台之前先请求固定的 `https://www.cloudflare.com/cdn-cgi/trace`，返回的公网地址必须是所选地址族，地区必须等于出口地区；拓扑里有该地址族的公网端点（`endpoint_v4` / `endpoint_v6`）时地址还必须等于端点。全部平台请求结束后再查一次，地址变了（例如枢纽把这张表切到了同池别的成员）整轮作废。出口确认不了的项一律是「探测失败」，从不作为平台结论。
- **结果类别**：网络可达（非平台判定）/ 平台明确解锁（带平台给出的地区和依据）/ 平台明确未解锁 / 探测失败（超时、传输错误、出口不对、地址族不对、取消）/ 未知（应答无法识别）。面板按服务、出口、地址族显示开始与完成时间、结果、平台地区、证据（状态码、主机和路径、命中的标记，不含查询串和正文）、出口确认、错误，以及入库结果。
- **入库规则**：解锁和网络可达记为成功，明确未解锁记为失败，`kind` 分别是 `scheduled` / `manual`，只有定时结果计入「连续两次定时失败」。一个服务在一个出口上这一轮所有地址族都没有平台结论（失败或未知）时，记为 `inconclusive`：不计失败次数、不会触发降级，但会立刻清掉首选的恢复计时，也不会被当成已知可用的备成员。同一轮里一个地址族有结论、另一个没有时，只有有结论的进入 Observation，另一个标「未入库：该地址族没有平台结论」。取消或超时的项不入库。定时任务开始时就把下一次定时推后一个周期；出口上的 `/api/unlock/report` 不再推动面板的定时。
- **限制**：每个服务 20 秒、每次 agent 请求 2 分钟（面板侧 150 秒）、整轮 15 分钟；同一时间只有一轮，同一轮最多 2 个出口并行，每个出口内最多 3 个服务并行，agent 同时最多 2 个探测；面板上可以取消，取消会断开到 agent 的请求，agent 随之取消探测。
- **与安装/回滚的关系**：探测不占 agent 的动作锁。`activate` / `rollback` 开始时取消正在跑的探测（最多等 15 秒）并在执行期间拒绝新探测（503），所以安装不会被探测拖住，也不会有探测流量和 `meridian-up.sh` 的重载交叠；`health` 只读，不影响探测。
- **凭据**：不接受也不保存任何流媒体或 AI 平台的 Cookie、账号或令牌；没有 cookie jar，固定请求头，证据里不带查询串、正文和 `Set-Cookie`。

自动化回归（`go test ./...`，只证明控制流和判定逻辑，不证明真实出口或真实平台）：

- `internal/probe`：各适配器对合成样例的判定（Netflix 403/404/200 地区一致与不一致/无标记，Disney+ unavailable/地区，OpenAI `unsupported_country`，Claude `app-unavailable-in-region` 与质询页，到达性服务从不给平台结论）；出口检查（地址族不对、地区是 CN、端点地址不对、什么都比不了）；用 httptest TLS 服务和假网络跑完整流程：路由不在隧道上时不建连也不碰平台、出口地区不对时不碰平台、v4 探测只拨 v4（解析器只有 AAAA 时失败而不是改用 v6）、v6 探测只拨 v6、v6 探测出口却是 v4 时失败、中途出口变化整轮作废、单服务超时不拖累其他服务、并发上限、取消、跨主机跳转不跟随、不回传 Cookie；非 Linux 上带 mark 的拨号一定失败而不是退回普通 socket。
- `internal/hostexec`：`ValidateProbe` 拒绝 `any` 地址族、越界 mark、非中转地址、公网解析器、URL 当服务名、重复/过多服务等；`/v1/probe` 要口令、拒绝多余字段；出口没装（`lo` 上没有中转地址）时不发任何东西；`ip route get` 解析出口设备，`unreachable` 是错误、`eth0` 不算隧道；`activate` 不等探测、会取消探测且被取消的探测没有平台结论；安装期间拒绝探测；`health` 不影响探测；并发上限；调用方断开即取消；客户端在 agent 不在时报 `ErrUnavailable`。
- `internal/api`：手动一轮按服务 × 出口 × 地址族生成项、请求带对出口的 mark / 中转地址 / 解析器 / 地区、每个出口一轮只推进一次状态且不计失败次数；定时与手动同链、结果真实入库、两次定时明确未解锁才降级、定时推后、没有 agent 时只记一条说明；无平台结论记为 `inconclusive` 且不降级、agent 声称解锁但出口未确认时降为失败；取消后不入库、同时只允许一轮、整轮超时；任意 URL / 命令 / 无适配器服务 / 非出口 / `any` 地址族被拒、出口不支持的地址族只记录不发送；探测入库与 10 份并发出口报告在同一把锁里都不丢、agent 并发不超过 2。
- `internal/unlock`：`inconclusive` 三次也不降级，但会清掉首选的恢复计时。

实机（Debian 13 网关，root，**未执行**；在存档证据之前一律算「未验证」）：

- [ ] `meridian-host` 新的沙箱（`RestrictAddressFamilies` 增加了 `AF_INET AF_INET6`，仍只有 `CAP_NET_ADMIN`）下 `SO_MARK` 可以设置、能绑定 `lo` 上的中转地址、能读系统 CA。
- [ ] 对每个出口、每个地址族点一次「立即测试」，面板「出口确认」里的公网地址就是该出口（在出口上 `curl -4/-6 https://www.cloudflare.com/cdn-cgi/trace` 对照），接口是西向隧道；同时在网关 LAN 口和 ROS 上抓包，没有任何探测流量（包括 DNS）从 `192.168.100.1` 出去。
- [ ] 把某个出口的西向隧道停掉（或删掉该 mark 的 `ip rule`）再测：结果是「探测失败」（路由检查或出口检查不过），不是平台结论，也没有流量走 ROS。
- [ ] 对没有 IPv6 出口能力的出口勾选 IPv6：只记录「未发出」；对有 IPv6 的出口，IPv6 一轮的出口地址是 IPv6，断掉出口的 IPv6 后是失败而不是改走 IPv4。
- [ ] 测试进行中在面板「安装到本机」：安装立即开始，测试项变成「已取消」，没有入库。
- [ ] 枢纽把某个池切到备成员期间测首选：有端点的出口应报「实际公网地址不是该出口的端点」；没有端点的出口（NAT 拨出、家宽）只能按地区确认，**同地区池内切换分辨不出来**，这是已知边界。
- [ ] 名字解析始终经出口隧道解析器的 ULA（IPv6 传输，带同一 mark 和中转源地址），IPv4 探测也是如此；该出口的 smartdns 没起来时整轮失败而不是改用本机解析器。Go 解析器会先看网关的 `/etc/hosts`，不要在网关上为这些平台写 hosts 条目。回程依赖网关 `rp_filter=2`（宽松），与局域网流量相同。
- [ ] 出口的出站公网地址和 `endpoint_v4` 不是同一个地址（多 IP 主机）时，该出口的面板探测会一直报出口不一致；需要人工确认后调整端点或接受这个限制。

真实平台行为（只能由人对照真实页面核实，仓库里没有向真实平台发过任何请求，14 个适配器全部基于公开的检测思路和合成样例；每个平台要核对的事项以 [unlock-methods.md](unlock-methods.md)「需要人工在真实平台上核对的事项」为准，下面只列最早的四个）：

- [ ] Netflix：自制剧标题 `81280792` 在解锁地区返回 200 且页面带 `requestCountry` / `countryCode`（或 URL 带 `/xx-yy/` 前缀），仅自制剧地区 404，被封 IP 403。美国目录 URL 没有前缀时，只能靠页面标记；页面结构变化会落到「未知」。
- [ ] Disney+：不可用地区是否跳到含 `unavailable` 的路径；可用时页面是否带 `countryCode` / `region` 或 `/语言-地区` 前缀。没有这些标记时只会是「未知」。
- [ ] OpenAI：`api.openai.com/compliance/cookie_requirements` 在不支持的地区是否返回 `unsupported_country`（不带任何令牌时）；支持地区的应答只算网络可达。
- [ ] Claude：不支持的地区是否跳到 `/app-unavailable-in-region`；Cloudflare 质询会让结果变成「未知」。
- [ ] Gemini / Copilot / Perplexity / Grok：只说明经该出口能收到 HTTP 应答，不说明账号或地区可用。
- [ ] 平台对机房 IP 的 Cloudflare 质询、地区跳转和页面结构随时会变；任何一个适配器连续出现「未知」时，按上面的方法人工复核后再改适配器。

## 纯 IPv6、v6 入 v4 出、NAT64

- [ ] 纯 IPv6 出口不选绕行，或只选了名字却没有中继 / Mesh / v4 前置，保存被拒绝，并说明枢纽没有 IPv6。
- [ ] 双栈中继路径仍包含阿里云、IX、枢纽。枢纽的 WireGuard 里没有纯 v6 出口的 `2001:db8::` 端点；中继的配置里有 `[2001:db8::…]:端口`。
- [ ] 「v6 入 v4 出」的枢纽下一跳只在该出口自己的表里指向 `mmesh`，`mmesh` 不存在时这张表是黑洞。
- [ ] `nat64.reserved.conf` 存在，`meridian-routes.sh` 里没有 NAT64 路由。打开面板上的占位开关再编译，IPv4 默认路由仍不包含该前缀。

## 防泄露清单

面板「防泄露」页分四组：「自动化回归：生成配置核对」（配置包含 / 失败）、「隔离 Linux 集成证据」（一律未执行）、「实机人工签收」（一律待人工签收）、「已知限制」。第一组全绿只说明生成的配置里有这些规则。下面的打勾项按等级标注，实机项要附存档位置。

- [ ] 53/853 被劫持到本机，非局域网来源的 53/853 在 input 被丢弃。
- [ ] 不 `flush ruleset`，策略路由优先级从 17000 起，境外表有黑洞默认路由。
- [ ] 网关 nft 文件是单个事务（建-删-重建），带独立的 `inet meridian_guard` 兜底表。运行中重载不漏在命名空间里有存档的通过记录（2026-11-13），真实客户端、ROS 和抓包下仍是待人工签收，见上面「防火墙原子替换与 LAN 兜底」。
- [ ] `fd66::/48` 不指向 ROS。
- [ ] 已知 DoH 域名返回 SOA，已知地址的 443 被拒绝。这不是全部 DoH。
- [ ] WebRTC：srflx / 中继候选是出口地址（实机人工签收，ipleak 或 browserleaks）。
- [ ] WebRTC host 候选里可能出现 ROS 通告的 GUA。这是单条运营商 /64 加 SLAAC 的结果，验收时记为已知限制，不当成失败。要去掉它，只能让测试机不用 GUA、改用 ULA 再在网关做 NAT66，国内 IPv6 就不再端到端。
- [ ] 实机人工签收：dnsleaktest.com 与 ipleak.net 的 v4/v6 都属于当前出口地区，没有家庭宽带公网地址。
- [ ] 实机人工签收：ROS 上 `fd00::/8`（或 `fc00::/7`）黑洞的只读查询输出已存档（或 `meridian-verify.sh` 带 `MERIDIAN_ROS_SSH` 的 `PASS ros_ula_blackhole` 及其证据文件）。
- [ ] 实机人工签收：断隧道时测试机不通、ROS / 家庭 WAN 抓包里没有境外流量。
- [ ] 隔离 Linux 集成证据：`meridian-verify.sh` 在网关上 `meridian-verify-local-ok`，证据目录已存档。
- [ ] 自动化回归：网关路由脚本不装任何 `iif … unreachable` 规则、删除旧版的 17850/17851 两条、并且有兜底表（`no_iif_unreachable`）；网关上由 `meridian-verify.sh` 的 `no_stale_iif_rule` 和 `route_*` 路由探测按内核实际结果核对。
- [ ] 自动化回归：每个出口和地区组标记都有 v4/v6 的 102 表规则和其后的 unreachable，并在守卫范围内（`group_marks_routed`）；开机兜底文件与主规则的守卫一致（`boot_guard_matches`）；启动脚本重新加入保存的 chnroute（`chnroute_readd`）；编译产物里的私钥和预共享密钥都是占位符（`bundle_keys_placeholder`）；远程接入的生成配置（`remote_access_config`，关闭时为「不适用」且配置里没有 `mra`）。
- [ ] 隔离 Linux 集成证据：名单更新后重载，`chnroute_loaded` / `geosite_cn` 仍为 PASS（`lists_update_runtime`）。
- [ ] 实机人工签收：真实出口与地区组切换（`real_exit_switch`）；平台解锁结果按 unlock-methods.md 核对（`unlock_platform_verdicts`）；启用远程接入时手机两种模式、路由器转发、IPv6（`remote_phone_full`、`remote_phone_home`、`remote_router_forward`、`remote_ipv6`）。
- [ ] 已知限制：凭据库只靠文件权限保护、没有静态加密（`secrets_at_rest`）；远程接入「仅回家」模式不保护设备的上网流量（`remote_home_mode`）。

## 跨模块契约在哪里测试

都是本地测试（假宿主、进程内 SSH 服务器、假 Cloudflare，不连接任何远端），属于「自动化回归」。

| 契约 | 测试 |
| --- | --- |
| 秘密不出现在 API 响应、日志、数据库 / 快照、拓扑、编译产物、差异：服务器 → 装机（密码） | `internal/api/ssh_ops_test.go` `TestServerReadinessAndProvisionOverPassword` |
| 同上：带口令的私钥 → 连接测试 → 装机（口令和私钥只在 `secrets/`，WireGuard 私钥只进装机脚本的标准输入） | `internal/api/secrets_seams_test.go` `TestKeyCredentialProvisionKeepsKeyInStore` |
| 同上：Cloudflare 账户 → Mesh 部署（含注入失败）→ 撤回（API token、SSH 密码只在 `secrets/`，节点令牌哪里都没有，日志干净） | `secrets_seams_test.go` `TestMeshSecretsAcrossDeployAndWithdraw`；`internal/api/mesh_test.go` `TestMeshDeployAndWithdrawByID`；`internal/mesh/deploy_test.go` `TestSecretsNeverPersistedOrReturned` |
| 同上：远程设备创建 → 安装 → 停用 → 重新生成 → 失败补偿 | `internal/api/remote_access_test.go` `TestRemoteAccessLifecycleAndSecrets` |
| 设备私钥从不落盘（含 `secrets/` 和已安装的宿主目录），重新生成后旧预共享密钥不在 `mra.conf` | `secrets_seams_test.go` `TestRegeneratedDeviceKeysAreNeverStored` |
| 账户与凭据创建、错误信息、快照、编译、差异 | `internal/api/resources_test.go` `TestResourceLifecycleAndReferences`、`TestSecretsStayOutOfSnapshotsAndBundles`、`TestErrorsScrubShortSecrets` |
| 网关和节点 WireGuard 私钥只在安装边界注入 | `internal/api/server_test.go` `TestApplyInstallInjectsStoredKey`；`internal/apply` `TestInstallInjectsKeyAndKeepsSnapshotsRedacted`、`TestRemotePeersFollowTransaction`；`internal/compile` `TestStoredPrivateKeyStaysOutOfBundle`、`TestRemoteBundleCarriesNoSecrets`；面板「防泄露」的 `bundle_keys_placeholder` |
| 改版前数据目录一次升级（池 → 地区组、节点 `ssh_*` → 服务器、`mesh/cloudflare.json` → 账户、Mesh 记录 schema 2 → 3），按 `cmd/meridian` 的启动顺序，第二次启动不改任何东西 | `internal/api/upgrade_test.go` `TestUpgradeFromPreRedesignDataDir`（固件是 `5b01903` 的仓库示例）；各自的单项：`internal/store/store_test.go`、`internal/credentials/store_test.go` `TestMigrateNodesIdempotentAndInterrupted` / `TestMigrateLegacyCloudflareIdempotent`、`internal/mesh/upgrade_test.go`、`resources_test.go` `TestMigrationKeepsDeploymentsAndIsIdempotent` |
| 被引用时拒绝删除：服务器、凭据、Cloudflare 账户、地区组（含只被默认组引用） | `TestResourceLifecycleAndReferences`、`TestCloudflareAccountBinding`、`TestMeshDeployAndWithdrawByID`、`internal/api/region_groups_test.go` `TestRegionGroupCreatePatchDelete`、`upgrade_test.go` `TestDefaultGroupReferenceBlocksDeletion` |
| 主机指纹固定：未确认拒绝、指纹不符在认证前拒绝 | `TestServerReadinessAndProvisionOverPassword`、`internal/credentials` `TestHostKeyStates`、`internal/sshexec` `TestMismatchRefusedBeforeAuthentication`、`TestDeploymentPinEnforced` |
| 节点撤回绑定部署时的主机（服务器、地址、端口、用户、指纹、凭据），只删清单内容，状态如实 | `internal/api/withdraw_test.go` `TestNodeWithdrawStateMachine`、`TestNodeWithdrawIdentityBinding`、`TestNodeWithdrawRefusedUnreachableUnknown`；`internal/provision/withdraw_test.go` |
| 网关撤回保留兜底表、先关转发、可补偿 | `internal/apply/withdraw_test.go`；`internal/hostexec/restore_test.go` `TestWithdraw*`；`withdraw_test.go` `TestGatewayWithdrawAPI` |
| 节点撤回等 Mesh 撤回完成 | `withdraw_test.go` `TestNodeWithdrawWaitsForMesh` |
| Mesh 撤回绑定部署时的主机与账户 | `TestMeshDeployAndWithdrawByID`、`TestMeshDeployWithExplicitAccount`、`TestMeshWithdrawBlockedWhenPinnedServerOrCredentialMissing`、`internal/mesh/withdraw_test.go` |
| 缺防火墙验证失败 | `verify_script_test.go`（nft 缺失、缺主表、缺兜底表）；`internal/compile/leak_test.go` `TestUpScriptFailurePreservesState` |
| 没有宿主执行能力时安装明确失败（503，不写快照） | `server_test.go` `TestApplyInstallWithoutHostExecFails`；`internal/apply` `TestNoHostExecFailsBeforeAnything` |
| 回滚恢复上一份资源集合 | `internal/apply/txn_test.go` `TestRuntimeRollbackRemovesNewResources` 等；`server_test.go` `TestRollbackModeIsExplicitAfterInstall` |
| 整条面板流程按顺序走一遍、每一步在前提之前被拒：凭据 → 服务器 → 指纹 → 连接测试 → 拓扑绑定 → 远端预检 → 第一次装机 → 网关预检（预检之后改拓扑即失效）→ 安装（经真实 `hostexec.Client` 到真实 `hostexec.Agent`，Unix socket，命令执行模拟）→ 远端撤回 → 网关撤回；响应里没有密码和私钥 | `internal/api/e2e_flow_test.go` `TestPanelFlowEndToEnd` |
| 安装后受管 sysctl 的写入、读回内核和旧文件遗留；`meridian-up.sh` 应用整份文件（开机转发两行除外）并写汇总行 | `internal/apply/sysctl_test.go`；`internal/compile/gateway_round2_test.go` `TestUpAppliesManagedSysctlAndSummarises`；`web/src/pages.test.tsx`「deploy: managed sysctl after an install」 |
| 面板开机等待局域网地址：等待、超时失败、其他错误立即失败、拒绝通配地址 | `internal/api/listen_test.go` |
| 概览的探测通道跟随宿主代理可达性 | `internal/api/status_test.go` `TestStatusProbeFollowsAgentReachability`；`pages.test.tsx`「overview: unlock probe channel」 |
| 同名地区组在卡片、规则目标选择、规则列表、解锁选择器里附带地区和 ID | `pages.test.tsx`「region groups with the same name」「rules: same-named region groups」 |
| 防泄露清单不把未执行的证据标成通过 | `internal/verify/verify_test.go` `TestChecklistDoesNotClaimUnexecutedEvidence`、`TestNewWorkItemsAndScopes`；`server_test.go` `TestPoolsUnlockAndLeakcheck`；`web/src/pages.test.tsx`「leak check」 |

尚未覆盖、留给后续的：除 `TestPanelFlowEndToEnd` 之外，API 层的安装测试都用激活桩；那个测试经真实 `hostexec.Client` 安装，但只检查了面板响应里没有秘密，没有检查 agent 收到的请求；Mesh 的真实 SSH 执行器（`sshRemote`）没有从 API 跑过（只用了假 Remote）；`/api/apply` 的 `dry_run`、`/api/rollback` 只检查了节点私钥。
