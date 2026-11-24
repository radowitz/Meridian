# 验收清单

在[测试设备](test-device.md)上做。网关和 DNS 都已经指向 `192.0.2.88`，IPv6 默认路由指向网关的链路本地地址，路由器发现已关闭。

## 证据的三种等级

整份清单只用下面三种说法，不混用：

| 等级 | 是什么 | 谁来跑 | 能说明什么 |
| --- | --- | --- | --- |
| **自动化回归** | `go test ./...` 里的单元/脚本测试，以及面板「防泄露」页的「生成配置核对」 | CI、任何开发机 | 生成的文本、脚本控制流和状态机符合设计。**不能**说明规则已经加载到网关，**更不能**说明不泄漏。 |
| **隔离 Linux 集成证据** | netns 测试（`TestNetnsReloadNoLeak`）、`deploy/verify-smartdns.sh`、`deploy/verify-host-exec.sh`、`deploy/verify-mesh-veth.sh`、`deploy/verify-sniff-systemd.sh`、网关上的 `meridian-verify.sh` | 人在 Linux 主机或网关上以 root 运行 | 只有真的运行过、并把完整日志/证据目录存档后才算数。没有存档就是「未执行」/「未验证」。 |
| **实机人工签收** | 真实测试机上的 DNS 泄漏和 WebRTC、ROS 上的 `fd00::/8` 只读查询、断隧道、抓包；真实出口与地区组切换、真实 Cloudflare Mesh、路由器端口转发、手机蜂窝拨入、流媒体 / AI 平台的真实解锁结果 | 用户或主会话，在真实网络上 | 唯一能支撑「这台测试机在这些条件下没有看到泄漏」的证据。签收时写下日期、拓扑版本、截图/命令输出/pcap 的存档位置。 |

面板「防泄露」页按这三类分组：生成配置核对显示「配置包含 / 失败」，集成项一律显示「未执行」，实机项一律显示「待人工签收」——面板不运行它们，也不会把它们标成通过。每一行的最后一列链接到面板「验收」页里对应的一项（见下面「验收目录」）：在那里按步骤做完并签收后，这一列显示签收记录和时间；这一行自己的状态不因此改变。发布前三类都要有证据；只有第一类绿，不能写成「已验证无泄漏」。

### 每个命令能证明什么

| 命令 | 证明 | 不证明 |
| --- | --- | --- |
| `go test ./...`（任何平台） | 代码级：模型与迁移、编译出的文本（nft、路由、SmartDNS、WireGuard 占位符）、bash 里带桩执行的生成脚本（`meridian-up.sh`、`meridian-verify.sh`、枢纽 `group_step`）、状态机、API 契约（秘密不出现在响应 / 日志 / 快照 / 编译产物 / 差异、引用阻止删除、迁移、安装 / 回滚事务用模拟宿主）、host agent 的校验与动作顺序 | 规则已加载到任何主机；真实 nft / iproute2 的输出格式；真实 SSH 服务器以外的远端；Cloudflare；任何平台；任何泄漏结论 |
| `go test ./...` 在非 root 或非 Linux 上 | 同上 | `TestNetnsReloadNoLeak` 和 `TestNetnsULALANHomeAccess` 只在 Linux 编译（`//go:build linux`），没有 `MERIDIAN_NETNS_TEST=1` 或不是 root 时**跳过**。跳过不是通过：日志里是 `--- SKIP`，在交付记录里必须写成「跳过（权限不足 / 非 Linux）」。没有 bash 的机器上脚本类测试也会跳过 |
| `npm --prefix web run build` | 面板 TypeScript 类型检查通过、能打包；各块大小和首屏要下载的文件（构建测量，见 `web/README.md`「首屏与拆包」） | 任何运行时行为；真实网关上的首屏时间、离线时懒加载页面之间的跳转、升级后旧标签页的表现（要在真实浏览器里检查） |
| `npm --prefix web test`（vitest + jsdom，假 API） | 面板用例：秘密只发送一次且不留在浏览器存储；服务器「发现 → 确认同一指纹 → 测试」流程与指纹不符的处理；被引用时删除被拒并列出引用者；Cloudflare 权限检查显示「写权限未确认」、Mesh「已发布」不显示为可用；名单策略与保留旧版；安装状态指示；地区组排序、手动 / 回落、删除被拒；规则只有一个目标；拓扑节点只选服务器、不发 `ssh_*`；远程接入一次性配置、重新生成、停用删除、运行状态不可用时说明原因；部署失败与补偿、回滚方式；解锁到达性不算解锁；防泄露页集成项永远「未执行」、人工项永远「待人工签收」；每条路由加载自己的页面模块，页面文件加载失败时显示「面板已更新，请刷新」和「刷新」（`lazy_routes.test.tsx`） | 后端行为（API 是假的）；真实浏览器；可用性；真实的分块下载和缓存 |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsReloadNoLeak`（Linux root） | 隔离命名空间里，生成的 nft 和路由在首次加载、200 次重载、两种加载失败注入、地区组来回切换（含路由脚本重跑）、只剩兜底表时，局域网和远程设备的境外流量不到 ROS | 真实隧道、真实客户端、真实 ROS |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsGroupDNSFailover`（Linux root，需要 python3；2026-11-13 在一台 Debian 13 上跑通，日志在 `docs/evidence/2026-11-13-debian13/netns-group-dns.log`；含 Mesh 阶段的版本同日晚些时候跑通，日志在 `docs/evidence/2026-11-13-debian13-mesh-dns/netns-group-dns.log`） | 命名空间里用编译出的网关、国内中继、枢纽、两个成员出口的 nft 和路由，以及枢纽编译出的 `group_step`：切换前组查询（UDP、TCP）由首选成员应答、数据经首选；首选整机断开（解析器、隧道、WAN）后枢纽把组切到备成员，同样的查询由备成员应答、新连接经备成员；两个成员都断时查询失败；整个过程没有组查询到 ROS 或国内解析地址、没有从局域网口出去、没有不带 mark 离开网关（见「地区组的解析」）。2026-11-13 晚的版本还有旧结构的 Mesh 阶段（第 7–9 阶段：组表指向 `mmesh`，见 mesh-dns 记录）；Mesh 改为 WireGuard 的底层承载后这些阶段已删除，第 5 阶段改为断言「成员全部失效时组停在原成员上、组表不指向 `mmesh`」。这一版 2026-11-16 在开发机的特权 Linux 容器里通过（见下面的执行记录） | 真实 WireGuard（AllowedIPs 只有单元测试）、真实 SmartDNS 的 `-set-mark`（只在真实网关上用计数器核实过一次，见架构文档）、真实出口、真实 Cloudflare Mesh（连接器是否做源地址转换、IPv6 是否经 Mesh 转发，测试里是假设）和真实 sidecar 镜像 |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run '^TestNetnsMeshLeg$'`（Linux root，需要 python3、nsenter、wg、`/dev/net/tun`；2026-11-16 在开发机的特权 Linux 容器里通过，日志在 `docs/evidence/2026-11-16-netns-mesh-leg/`） | 架在 Mesh 上的 WireGuard 腿，用示例拓扑里枢纽和出口 `us` **编译出的** WireGuard 配置（真实 WireGuard 接口、临时生成的密钥）、路由脚本、nft 和 `meridian-mesh-up.sh`：枢纽的 Mesh 腿经两端 sidecar 握手，外层包不出现在枢纽的 WAN 上（建接口之前先装黑洞）；带出口中转源地址的连接走直连腿、走 Mesh 腿、直连腿被切断后走 Mesh 腿，服务端看到的都是出口自己的 WAN 地址，回包从 Mesh 腿回去；地区组解析查询（IPv6）经 Mesh 腿由出口应答；1216 字节的内层包不分片，1217 和 1280 字节由外层分片承载；密封：别的端口、ICMP、手工指到 veth 上的别的目的地都过不去，sidecar 的 docker 网桥上没有任何包，出口不转发从 sidecar 来的包；Mesh 断开或失去密封时这条腿不通、没有泄漏，枢纽到出口 Mesh 地址的路由回到黑洞 | **真实 Cloudflare Mesh**：两个 sidecar 是命名空间，Mesh 是两个 tun 设备（MTU 1280）之间的转发。它不能说明 Cloudflare 是否把发布的 /32 路由到出口节点、是否放行这条 WireGuard UDP 和外层分片、真实 WARP 设备的名字和策略路由、`SRCNAT_ENABLED` 的叠加效果。原 2026-11-16 存档主要手工把出口表指到 Mesh 腿；R3 新增自动选择、双断与恢复阶段，尚未执行，不由旧存档证明 |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run '^TestNetnsDualHub$'`（Linux root，需要 python3；2026-11-13 在一台 Debian 13 上通过，日志在 `docs/evidence/2026-11-13-debian13-dual-hub/`） | 命名空间里用 `defaults.DualHubExample` 编译出的网关、中继、IX 主枢纽、备用枢纽和两个出口的 nft 与路由，网关的选路用编译出的 `meridian-failover.sh`（`upstream_step`，真实 ping）：主链路时组连接、钉死 dc2 的连接、组解析（带 mark）和 dc2 与枢纽无关的解析地址都经 ix，备用枢纽没有流量；中继 → IX 被切断后第 3 轮切到备用枢纽，同样四项经 hkb，出口只从 hkb 的隧道回包、不往 ix 的隧道回（回程对称）；两边都断时留在原路径，四项都超时，局域网口和 ROS 上计数为 0；主链路恢复后第 5 轮切回 | 真实 WireGuard 和 wstunnel（备用 WSS 链路用 veth 代替）、真实 SmartDNS、Mesh（主枢纽的 Mesh 腿由上一行的测试覆盖；备用枢纽 hkb → 出口的 Mesh 腿只有合成编译 / 计划测试 `TestMeshLegFromBackupHub`、`TestPlanBackupHubMeshEnd`，命名空间和真实 Mesh 上都未验证）、切回冷却（单元测试覆盖）、真实 IX 的双地址路由 |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run '^TestNetnsRelaySharing$' -v`（Linux root，需要 python3 和 `timeout`；`tc`/netem 只有第 5 阶段需要，没有时这一阶段跳过并在日志里写 `SKIP phase loss`） | 命名空间里用 `defaults.SharedRelaysExample`（两台中继 + IX 主枢纽 + 备用枢纽，远程接入打开，控制程序的计时缩短）编译出的全部节点的 nft 与路由，网关的控制是编译出的 `meridian-failover.sh` 的 `share_step` 调用本测试二进制充当的 `meridian path-step`（真实测量，合成时钟每轮 5 秒）：200 个新连接在两台中继间各占 35–65%（n = 200、p = 0.5，±15 个百分点超过 4 个标准差）且网关上没有回包从非分配的中继进来、主枢纽没有把回包送进别的中继的隧道；一个长连接在所有新连接被改到另一台中继时两个方向都留在原中继、不断；ali2 只放行 ICMP（「小包通、没有速率」）时在有业务的情况下被剔除（原因 `no_delivery`，ping 照常应答），清理规则出现、新连接避开它；恢复不立即加回，之后以 1/4 权重加回再爬到等分；（有 netem 时）50% 丢包剔除（`poor_loss`）；两台中继到主枢纽都断时切到备用枢纽（表 102、新连接、出口从 hkb 隧道回包）；全部断开时记录 `down`、所有测试流超时、局域网口和 ROS 计数为 0；主链路恢复后过了切回时间才回，远程设备的连接和本机带 mark 的组解析查询经中继（组解析经指定中继） | 真实 WireGuard / wstunnel（隧道用 veth）、真实限速（用丢弃非 ICMP 和 netem 模拟）、ICMP 吞吐探测与真实 TCP 吞吐的关系、默认阈值是否适合真实线路、真实 SmartDNS |
| `sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsULALANHomeAccess`（Linux root；2026-11-13 在一台 Debian 13 上跑通，日志在 `docs/evidence/2026-11-13-debian13/netns-ula-lan.log`） | 同样的命名空间、局域网 IPv6 前缀换成 ULA，加载一次后：设备 ↔ 家里主机 IPv6 双向有回包；前缀之外的 ULA（含隧道、中转）从设备和局域网客户端发出时到了网关、没有被转发、ROS 一个也没收到 | 同上；GUA 局域网前缀（由上一行覆盖） |
| 网关上 `meridian-verify.sh` | 这台网关此刻加载的状态（见下面「meridian-verify.sh」） | 真实客户端不泄漏；路由器；手机 |

### 已存档的执行记录

| 日期 | 环境 | 范围 | 存档 |
| --- | --- | --- | --- |
| 2026-11-12 | 全新 Debian 13 虚拟机（内核 6.12、nftables 1.1.3、systemd 257），示例拓扑，隧道未握手 | 第二类（隔离 Linux 集成证据）的五个入口各跑通一次，外加首次安装、升级、回滚、重启的手工核对 | [docs/evidence/2026-11-12-debian13](evidence/2026-11-12-debian13/README.md) |
| 2026-11-13 | 同一台主机，从上一版升级；示例拓扑加地区组、远程接入（两个测试设备，没有设备真的拨入），隧道未握手 | 第二类的五个入口在面板重做之后的版本上各跑通一次（netns 测试含远程设备、地区组切换和端到端回复；验收脚本 47 项本地检查；地区组解析的故障切换测试；ULA 家网测试），外加升级、迁移、密钥与密码登录、名单更新、远程接入安装、重启的手工核对 | [docs/evidence/2026-11-13-debian13](evidence/2026-11-13-debian13/README.md) |
| 2026-11-13（晚） | 同一台主机，只在临时网络命名空间里 | 只有三个 netns 测试：`TestNetnsGroupDNSFailover`（含 Mesh 第 7–9 阶段）、`TestNetnsReloadNoLeak`、`TestNetnsULALANHomeAccess`，全部 PASS。没有安装、没有跑任何验收脚本。**其中的 Mesh 阶段是旧结构（组表指向 `mmesh`），已被取代** | [docs/evidence/2026-11-13-debian13-mesh-dns](evidence/2026-11-13-debian13-mesh-dns/README.md) |
| 2026-11-16 | 开发机上的特权 Linux 容器（Docker Desktop 的 Linux 6.10 内核，arm64；Debian 13 用户态，nftables 1.1.3，内核 WireGuard），只在临时网络命名空间里，不联网 | Mesh 改为 WireGuard 底层承载之后的 netns 测试：`TestNetnsMeshLeg`（新）、`TestNetnsGroupDNSFailover`（去掉旧 Mesh 阶段后）、`TestNetnsDualHub`、`TestNetnsNestedExit`、`TestNetnsRelaySharing`、`TestNetnsReloadNoLeak`、`TestNetnsULALANHomeAccess`、`TestNetnsSniff*`、`TestNetnsLocalMSS*` 等，结果逐项见该目录的 README（含一个在改动前的提交上同样失败的用例）。没有安装到任何主机、没有跑任何验收脚本、没有连接 Cloudflare 或任何远端主机 | [docs/evidence/2026-11-16-netns-mesh-leg](evidence/2026-11-16-netns-mesh-leg/README.md) |

这几份记录都只覆盖第二类，而且只对各自那一版代码和那台主机成立（每份覆盖哪一版代码，见下面「交接记录」）。2026-11-13 那份对应面板重做之后、删除 IPv4 `iif … unreachable` 规则之后的版本（见它的 README）；在它之后再改防火墙、路由、安装脚本、宿主执行或验收脚本就要重跑。它没有覆盖的东西在它的 README 里逐条列出：没有真实隧道和出口、没有设备真的拨入、没有调用过 Cloudflare、没有对真实平台探测、对真实远端节点的下发只测了连接、全新主机的首次安装这次没有重走。

2026-11-12 那份是用提交 `d9b8556` 产生的，**早于**地区组、名单源、远程接入、14 个解锁适配器和面板重建；这些功能都不在它的范围内，它的 `meridian-verify.sh` 日志（17 PASS / 5 PENDING-HUMAN / 4 NOT-RUN-HERE）也是旧版脚本的输出，没有本版新增的检查。之后改过的防火墙（守卫标记范围、`mra` 入口）、路由（地区组标记）、启动脚本（chnroute 重新加入）、安装脚本（`meridian-secrets` 卷）、宿主执行（名单动作、远程接入状态）和验证脚本本身都要重跑：下面的「真实网关重跑清单」列出顺序。存档目录里的原始日志和 README 不改写。

沿用主机上已有 Mesh 节点的部署（N2）只有合成覆盖：`go test ./internal/mesh -run MeshReuse`（两端沿用不注册不装不发布、只出口沿用须确认且只装枢纽、沿用节点地址变化时健康失败且补偿不碰它、叠加只认可沿用的 Mesh 端）、`go test ./internal/compile -run MeshReuse`（三种组合的 Endpoint、sidecar 文件、黑洞 + 接口路由 + nft 出接口密封；无 Mesh 拓扑逐字节不变）、`go test ./internal/api -run TestMeshDeployReusesExistingExitNode`。没有命名空间测试覆盖主机级 WARP 接口；真实主机级节点承载 WireGuard UDP、拔接口后的黑洞、撤回后节点原样保留，都是 `mesh-e2e` 的人工步骤，ix 与美国出口的真实 UDP 承载由主会话执行。

第三类（实机人工签收）至今没有任何记录：下面标着「待人工签收」的每一项都还没做。真实出口切换、Cloudflare Mesh 的真实部署、路由器转发、手机蜂窝拨入、解锁探测的真实平台判定和防泄漏抓包都没有执行过，它们是用户或主会话另行执行的待签收项。

### 静态文件缓存与升级提示（自动化回归；没有在真实浏览器里验证）

`go test ./internal/api -run TestStatic`：入口 `no-cache` 与 304、清单内哈希资源 immutable、清单外文件（含旧构建的哈希名、无清单）不 immutable、缺失路径 404 + `no-store` 且不是 HTML、无目录列表、`/api/` 不受影响。`panel_update.test.tsx`、`lazy_routes.test.tsx`：版本变化显示「面板已更新」和「刷新」、监听与计时器在卸载时清理、分块失败显示「面板已更新，请刷新」、不自动刷新。未验证：真实浏览器的缓存行为（升级后是否真的不再需要强制刷新）、从旧版本第一次升级时的表现（预期仍需手动刷新一次）。

### 交接记录（本版）

截至这一版，证据与代码版本的对应关系如下。存档目录里的原始日志和 README 都不改写；后续在真实主机上发现的问题按复现逐条修复，修好并重跑之后才在新的证据目录里记为通过，不预写结果。所有记录都不含真实地址、主机名和凭据。

| 证据目录 | 覆盖的代码版本 | 覆盖什么 |
| --- | --- | --- |
| `docs/evidence/2026-11-12-debian13/` | 提交 `d9b8556` 的构建 | 当时的第二类五个入口、首次安装、升级、回滚、重启。早于面板重做，不覆盖之后的任何功能 |
| `docs/evidence/2026-11-13-debian13/` | 提交 `233e17b` 的最后一次构建 | 面板重做之后的第二类五个入口（含 47 项本地检查的 `meridian-verify.sh`、`verify-host-exec.sh`、`verify-smartdns.sh`、`verify-mesh-veth.sh`）和 README 里列出的手工核对 |
| `docs/evidence/2026-11-13-debian13-mesh-dns/` | `233e17b` 之上、地区组解析经 Mesh 备路的改动之后（第一次包含该目录的提交） | **只有**三个 netns 测试：`TestNetnsGroupDNSFailover`（含 Mesh 第 7–9 阶段）、`TestNetnsReloadNoLeak`、`TestNetnsULALANHomeAccess`，在 Debian 13 上全部 PASS。第一次运行 Mesh 阶段时暴露了一个真实的产品缺陷（编译出的 `meridian-mesh-up.sh` 把封装条件判反），修好后才是那次通过的运行 |

**之后的改动没有在任何真实主机上执行过**，只有仓库里的自动化回归（进程内 SSH 服务器、模拟宿主、本机沙箱、假 API）：

- 枢纽实际状态与当前枢纽身份（服务器、地址、端口、固定指纹）的绑定；
- 下发前预检：远端的固定只读脚本，网关经 `meridian-host` 的 `/v1/preflight`；登录方式不被接受时的公钥提示；
- 远端第一次下发失败时的补偿和残留清单；
- 撤回：远端节点（清单模式、中断恢复、旧版清理）和网关（撤回到兜底表、移除兜底表）；
- 面板开机时等待局域网地址（`meridian-bind-waiting` / `ready` / `not-ready`）；
- 安装结果里的「内核参数」读回和 `meridian-up.sh` 的 `meridian-sysctl:` 汇总行；
- 概览解锁卡片按宿主代理可达性显示探测通道、同名地区组附带地区和 ID；
- 链路接口名、默认端口、隧道网段和出口 / 地区组标记按持久化的序号分配（`allocations` 表）、升级时按当前位置迁移、统一的地址 / 接口名冲突校验（见 [架构](architecture.md)「接口名、端口和网段的分配」）。自动化证据：`internal/compile/tunnel_test.go`（迁移后编译逐字节相同、未重新生成的 golden、重排不变、加链路只改两端、删链路只改两端、同一次保存删加、出口和地区组不动、序号用尽被拒）、`internal/model/link_allocations_test.go`、`internal/store/store_test.go`（读取时迁移、只写一次、保存时存表优先、导出导入往返）、`internal/api/allocations_test.go`、`internal/validate/validate_test.go`（手工地址落进自动网段 `subnet_overlap` 带字段、`link_addr_reserved`、`iface_name_conflict`）。真实网关当前装的是按位置编号编译的结果，升级后必须保持不变，下面重跑清单第 2 步有对应核对。

`meridian-verify.sh`、`verify-host-exec.sh`、`verify-smartdns.sh`、`verify-mesh-veth.sh` 都没有在这一版上重跑；这一版还没有安装到任何主机上。`meridian-up.sh` 在 mesh-dns 记录之后又改过（受管 sysctl 的汇总行），所以三个 netns 测试也要在这一版上重跑才算覆盖它。

**至今完全没有验证过的**（第三类，或连第二类都没有）：真实出口和真实隧道（所有记录里隧道都没有握手）、真实枢纽的故障切换、真实 Cloudflare Mesh（含连接器是否做源地址转换）、手机拨入（远程接入）、ROS 一侧（端口转发、`fd00::/8` 黑洞的只读查询）、流媒体 / AI 平台的真实解锁判定、真实测试机上的 DNS / WebRTC 泄漏和抓包。

**已知限制（未解决，也未在真实主机上观察过）：**

- （S1 已改，未实机）远端节点的开机恢复单元 `meridian-node.service`、只改受管接口的 sysctl、nftables.service 会清空规则集时阻断、Docker FORWARD DROP 时在 DOCKER-USER 加带注释的放行规则：见下面「与已有业务共存」。都只有自动化证据。仍然存在的：有人手动启动或重载一个**没启用**的 nftables.service 会清掉 Meridian 的表（预检不阻断这种默认状态）；旧版本写到别的接口上的 sysctl 运行值保留到重启。
- 被攻破的远端主机可以打印伪造的成功标记（`MERIDIAN_PROVISION_OK`、`MERIDIAN_WITHDRAW_OK` 等）；面板只能如实转述远端的回答。
- Mesh 腿依赖 Cloudflare Mesh 把出口发布的 /32 路由到出口节点并放行两个节点之间的 WireGuard UDP，这一点没有在真实 Mesh 上验证。密封里自己做源地址转换（枢纽 sidecar 进 Mesh 时伪装成本节点的 Mesh 地址，出口 sidecar 交给宿主时伪装成 veth 地址），不再依赖连接器的 `SRCNAT_ENABLED`；两者叠加后的实际行为没有观察过。
- Mesh 腿的接口 MTU 是 1280，Mesh 路径留给它的只有 1216：1217–1280 字节的非 TCP 内层包靠外层分片通过，真实 Mesh 是否放行分片没有验证（见「Mesh 腿」一节）。
- R3 已实现同出口双腿质量切换；真实 Cloudflare Mesh 上的自动切换和默认阈值仍未验证（见下方 R3 回归与实机清单）。
- 删除受管 sysctl 行不会恢复内核里的旧值（安装结果会列出这些键，直到重启前保持原值）。

### 真实网关重跑清单（主会话执行；本仓库的开发与 QA 不连接网关）

按顺序，每一步把完整输出存进新的证据目录（例如 `docs/evidence/<日期>-debian13/`），没有存档就仍是「未验证」：

1. 开发机：`GOOS=linux go test -c -o compile.test ./internal/compile`，拷到一台可以建命名空间的 Linux 主机（不要在网关本机上跑），`sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsReloadNoLeak$' -test.v`。通过的样子：每个阶段（对照、首次安装、200 次重载、失败注入、20 次地区组切换、切换后 20 次路由重跑、只剩兜底表、只有开机兜底文件）都有 `EVIDENCE` 行，首次安装、200 次重载后和地区组切换后各有一组 `e2e ok` 行和一行路由校验通过，远程设备 `raw_at_ros=0`，最后一行 `meridian-netns-reload-test-ok`。同一个 `compile.test` 再跑 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsGroupDNSFailover$' -test.v`（地区组的解析；需要 python3；2026-11-13 跑通过一次，见已存档的执行记录）。通过的样子：`EVIDENCE before`、`EVIDENCE after failover` 各有 UDP、TCP 查询和连接三行（之前是 `198.18.1.1` / `100.64.1.2`，之后是 `198.18.1.2` / `100.64.2.2`），`hub active member of group us: us-2`、`hub report: hop in table us: us-2`、`hub report: result: ok`，`all members down` 阶段查询 `TIMEOUT`、`hub active hop of group us: mmesh`、`hub report: hop in table us (Mesh unsealed): blackhole`；Mesh 阶段（还要 `nsenter` 和 `/dev/net/tun`，缺了整个测试跳过；2026-11-13 晚在 Mesh 解析改动之后跑通过一次，见 [mesh-dns 记录](evidence/2026-11-13-debian13-mesh-dns/README.md)，那次的第一遍运行暴露了编译出的 `meridian-mesh-up.sh` 把封装成功和失败判反的产品缺陷，修好后才通过；这些阶段用的是命名空间里两个 tun 之间的转发，不是真实 Cloudflare Mesh）有 `EVIDENCE mesh: us table 171:`（`default via fe80::66:2 dev mmesh` 和黑洞）、`hub report: hop in table us (Mesh sealed): mmesh`、`hub report: result: ok`，UDP / TCP 查询 `198.18.1.1`、连接 `100.64.1.2`，`EVIDENCE mesh Mesh counters` 里 `us q_tun`、`us r_tun`、`us r_wan`、`hub sidecar docker bridge` 都是 0 且 `q_mesh`、`r_mesh` 增长；`mesh down` 阶段查询和连接 `TIMEOUT`、`hop` 仍是 `mmesh`；`unsealed` 阶段 `hop` 是 `blackhole`、查询 `TIMEOUT`、`us` 的表 171 不再指向 sidecar；每个阶段的计数行里 `gw unmarked`、`gw lan`、`gw domestic`、`ros domestic`、`ros group` 都是 0，`--- PASS: TestNetnsGroupDNSFailover`，stderr 最后一行 `meridian-netns-group-dns-test-ok`。失败时日志里有 `DIAG` 段（各命名空间的规则、路由、nft、枢纽的组状态文件和解析器日志）。再跑 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsDualHub$' -test.v`（主枢纽与备用枢纽；需要 python3；**还没有执行过**）。通过的样子：`EVIDENCE main:` 四行（组连接 `100.64.1.2`、钉死连接 `100.64.2.2`、组解析 `198.18.1.1`、dc2 解析地址 `198.18.1.2`）和 `failover keeps the main path: udp`、`upstream record: hub: ix`；`EVIDENCE ix cut:` 里 `two passes: still on the main path (FAILS_NEED is 3): udp`、`third pass: backup hub: backup`、`upstream record: hub: hkb`，同样四行结果；`EVIDENCE all down:` 里四项 `TIMEOUT`、`upstream record: state: down`；`EVIDENCE main back:` 里 `four passes: still on the backup (RECOVERS_NEED is 5): backup`、`five passes: main path again: udp`，同样四行结果；`--- PASS: TestNetnsDualHub`。失败时有 `DIAG` 段（各命名空间的规则、路由、表 172 / 173、nft、网关的上游记录和替身日志）。再跑 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsULALANHomeAccess$' -test.v`（ULA 局域网前缀；2026-11-13 跑通过一次，见已存档的执行记录）。通过的样子：两行 `EVIDENCE ula-lan e2e ok`（设备 → 家里主机、家里主机 → 设备），一行 `EVIDENCE ula-lan outside-prefix ULA … arrived_at_gateway=<不小于 20> forwarded=0 at_ros=0`，`--- PASS: TestNetnsULALANHomeAccess`，stderr 最后一行 `meridian-netns-ula-lan-test-ok`。
2. 网关：按 [安装](install-debian13.md)「升级」重跑 `install.sh`（全程转发不掉、`meridian-restore-ok`；它同时换掉宿主上的 `meridian` 二进制并重启 `meridian-host`——这一版的网关安装需要 agent 的 `/v1/preflight`，旧 agent 会让安装以 `host_unavailable` 拒绝），用新镜像重建面板容器；`docker compose logs meridian` 里应有凭据迁移和地区组迁移的日志（只有数量和 ID），以及一行 `allocation migration: stored the current interface, port, subnet and mark numbering`（只在第一次启动）。**分配表迁移不得改变任何东西**：升级前后各存一份 `GET /api/status` 的 `install`（`state` 应保持 `in_sync`，或保持升级前的值）和 `POST /api/diff`（请求体 `{}`）的 `diff` 与 `installed`（应为没有变化），以及「部署」页每个远端节点的待下发状态；升级后 `GET /api/topology` 里的 `allocations.links` 每条链路的 `slot` 对应的 `m%02d` 应与网关和各节点上 `wg show interfaces` 的接口名一致（`POST /api/topology/allocations` 请求体 `{}` 直接列出每条链路的接口、端口和地址，`changes` 应为空）。任何一项出现变化都先不要安装，存档后排查。
3. 面板：密钥 → 服务器 → 发现并核对指纹 → 确认 → 连接测试（就绪）；Cloudflare 账户 → 检查权限（预期：令牌有效、可读节点和路由，写权限「未确认」）。
4. 面板「部署」：差分、「安装前预检」（审阅报告，核对与 `ss -lntup`、`nft list tables`、`iptables -S FORWARD` 一致）、安装到网关。安装结果里「内核参数」一块：写入项应全部「已生效」，开机转发两行显示为「开机值」，旧 `install.sh` 写过、新文件不再写的键列为「旧文件遗留」（内核保留到重启）；把这块和 `journalctl -u meridian.service` 里的 `meridian-sysctl: applied N, skipped M` 一起存档。然后「名单 → 立即更新」一次（选网关上能到达的策略）。
5. 网关：`sudo /usr/local/sbin/meridian-verify.sh`。通过的样子：退出码 0、最后一行 `meridian-verify-local-ok`；`PASS policy_marks`（数量等于出口数加地区组数）、`PASS guard_mark_range`、`PASS guard_ingress`、`PASS guard_boot_file`、`PASS fallback_blackholes`、`PASS no_stale_iif_rule`、`PASS route_lan_domestic4`、`PASS route_tunnel_reply4`（局域网有 IPv6 前缀时还有 `route_lan_domestic6`、`route_tunnel_reply6`）、`PASS chnroute_loaded`（和 `chnroute6_loaded`）、`PASS geosite_cn`、`PASS dns_listener`、`PASS dns_aaaa_tunnelled`（`clients_ipv6_via_gateway` 关闭时；打开时是 `INFO`）；`unlisted_domestic_dns` 打开时还有 `PASS dns_split_active`、`PASS unlisted_domestic_lists`；有可切换地区组时还有 `PASS group_dns_snat`、`PASS group_dns_upstream`、`PASS group_dns_route`，以及 `PENDING-HUMAN group_dns_failover`、`NOT-RUN-HERE netns_group_dns`；`INFO list …` 行与面板「名单」页一致；远程接入关闭时 `PASS remote_absent`，打开时 `remote_*` 全部 PASS 且多四条 `PENDING-HUMAN remote_*`。旧版 17 项里任何一项变成 `FAIL` 都要查原因（真实 `nft list` 格式与本仓库桩不同只会导致 FAIL，不会误报 PASS）。
6. 网关：`sudo bash deploy/verify-smartdns.sh`、`sudo bash deploy/verify-host-exec.sh`，重启后 `--boot`；重启后再跑一次 `meridian-verify.sh`，`chnroute_loaded` 仍为 PASS（证明重载时重新加入了保存的批次）。重启后还要存 `docker compose logs meridian`：局域网口用 DHCP 时应看到 `meridian-bind-waiting` 若干行和一行 `meridian-bind-ready`，`docker inspect -f '{{.RestartCount}}'` 为 0（以前这里是几次 `bind: cannot assign requested address` 崩溃重启）；租约一直不来时应在 `MERIDIAN_BIND_WAIT` 后看到 `meridian-bind-not-ready` 一次。
7. 隔离 Linux 主机：`sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsMeshLeg$' -test.v`（它运行编译出的 `meridian-mesh-up.sh`、路由脚本和 nft，见「Mesh 腿」一节）。`sudo bash deploy/verify-mesh-veth.sh` 检查的是旧结构（经 veth 下一跳的默认路由转发）：veth 的寻址和邻居项没有变，但它不再代表 Mesh 数据面，随部署流程的更新一并改写之前不必重跑。
8. 在可以随意重装的主机上（不是生产网关、不是在跑别的服务的出口）：远端节点「预检 → 第一次下发 → 撤回」，网关「撤回 → 重新预检 → 安装」，按下面「下发前预检」「撤回与恢复」的实机项核对并存档。
9. 按域名嗅探（只在开启时）：**开启之前**先在网关上 `sudo bash deploy/verify-sniff-systemd.sh`（真实 systemd 上的单元布局、账号、状态套接字访问；见下面「按域名嗅探」，尚未执行）；隔离 Linux 主机或网关的内核上 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^(TestNetnsSniff|TestNetnsSniffRelaySharing|TestNetnsSniffWireGuard|TestNetnsSniffWireGuardRelaySharing|TestNetnsSniffFallback)$' -test.v`（后两个需要内核的 WireGuard 和 `wg`；通过的样子见下面「按域名嗅探」），网关上按同一节的实机项核对。
10. 人工签收（各自存档）：测试机 DNS / WebRTC / 断隧道 / 抓包；真实出口与地区组切换；Cloudflare Mesh 部署、健康、撤回；路由器转发；手机蜂窝拨入两种模式（[远程接入](remote-access.md)「验证」）；解锁平台结论（[unlock-methods.md](unlock-methods.md)「需要人工在真实平台上核对的事项」）。

## 验收目录（面板「验收」页；自动化回归用替身，开发与 QA 没有在任何真实主机上执行过演练）

面板「验收」页（`#/acceptance`，`#/acceptance/<id>` 直接打开某一项）把实机检查集中在一处：每一项写明会不会打断上网、要多久，能由网关宿主代理用固定动作执行的就在页面上执行并保存结果，不能自动执行的给出步骤，由操作者签收「通过 / 不通过」并写备注。其它页面的「未验证」提示旁边有到对应项的链接，并显示该项在当前配置下最近一次有效的结果。目录是代码里的一张固定表（`internal/acceptance/catalog.go`），下表由 `TestCatalogIsPublishedInDocs` 逐行对照，改目录就要改这里。

三种执行方式：

- **自动（只读）**：一次点击。只用宿主代理早已有的固定请求（`health`、出口解析检查、解锁探测）和一个新增的只读隧道路径检查，不改动网关。
- **自动演练**：会在有限时间内改动运行中的网关，结束后由网关宿主自己恢复。要二次确认。
- **人工签收**：面板不执行，只列步骤和证据来源；操作者做完后记录结果。

| id | 检查 | 来源页面 | 影响 / 预计耗时 | 方式 | 固定动作与参数校验 | 确认 / 恢复 | 结果失效 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `config-audit` | 生成配置核对 | 防泄露、部署 | 不打断；约 10 秒 | 自动（只读） | `panel_config_audit`：面板读自己编译出来的配置文本，不调用任何宿主动作。校验：没有参数 | 不需要确认；不改动网关 | 配置或已安装版本变化后标为过期 |
| `gateway-health` | 网关数据面健康 | 部署、概览 | 不打断；约 30 秒 | 自动（只读） | `health`：宿主代理的 health 动作：只读，采样两次。校验：资源名只取自已安装清单里的单元、接口和 nft 表，逐个按受管名字的格式校验 | 不需要确认；不改动网关 | 配置或已安装版本变化后标为过期 |
| `ipv6-firewall-reload` | 防火墙重载时 IPv6 不外泄 | 防泄露 | 可能短断，最多 120 秒；最多 120 秒 | 自动演练（二次确认） + 人工签收 | `drill_firewall_reload`：宿主代理重启 meridian.service（与安装时相同的 meridian-up.sh），期间按固定间隔采样两张表和转发开关。校验：没有目标和时长参数；网关必须已安装、数据面在运行、没有未完成的安装事务 | 二次确认（绑定动作、目标、配置指纹，120 秒有效）；宿主记录原状态并自行恢复，核对快照后才算恢复（见下） | 配置或已安装版本变化后标为过期 |
| `dns-leak` | DNS 不泄漏 | 解析设置、防泄露 | 不打断；约 2–5 分钟 | 自动（只读） + 人工签收 | `dns_check`：宿主代理向每个出口的隧道解析器问一个固定的名字（example.com）。校验：出口只取自拓扑里可检查的受管出口，解析器地址由编译结果给出，宿主代理只接受已安装的 SmartDNS 配置里转发到的地址；每次最多 16 个出口 | 不需要确认；不改动网关 | 配置或已安装版本变化后标为过期 |
| `mesh-e2e` | Mesh 端到端 | Cloudflare（Mesh 部署）、拓扑 | 不打断；约 1–3 分钟 | 自动（只读） + 人工签收 | `check_tunnel_paths`：宿主代理只读地读网关各隧道接口的状态、握手时间和收发字节（不返回任何密钥），面板再读本地的 Mesh 部署记录。校验：接口只取自已安装清单里的隧道接口，逐个按受管名字校验并且必须在宿主的受管记录里；每次最多 16 个 | 不需要确认；不改动网关 | 配置或已安装版本变化后标为过期 |
| `relay-removal` | 中继剔除 | 拓扑、部署 | 可能短断，最多 180 秒；最多 180 秒，另加约 3–5 分钟等待恢复核对 | 自动演练（二次确认） | `drill_relay_isolation`：宿主代理在自己的一张 nft 表里丢弃本机发往这台中继隧道端点的包，观察上游记录，到时删除。校验：目标只能是上游记录里正在分担的一台中继，它的隧道接口必须在已安装清单和宿主的受管记录里，并且还有另一台在分担；被隔离的地址由宿主从隧道端点读出，不是参数；时长 20–90 秒 | 二次确认（绑定动作、目标、配置指纹，120 秒有效）；宿主记录原状态并自行恢复，核对快照后才算恢复（见下） | 配置或已安装版本变化后标为过期 |
| `hub-failover` | 主链路切到备用枢纽 | 拓扑、部署 | 可能短断，最多 180 秒；最多 180 秒，另加约 3–5 分钟等待切回核对 | 自动演练（二次确认） | `drill_hub_isolation`：宿主代理在自己的一张 nft 表里丢弃本机发往主链路全部中继隧道端点的包，观察是否切到备用枢纽，到时删除。校验：目标必须正好是上游记录里主链路的全部中继隧道，备用枢纽的隧道必须在已安装清单里并且当前可用（否则拒绝，不会制造全断）；被隔离的地址由宿主读出，不是参数；时长 20–90 秒 | 二次确认（绑定动作、目标、配置指纹，120 秒有效）；宿主记录原状态并自行恢复，核对快照后才算恢复（见下） | 配置或已安装版本变化后标为过期 |
| `unlock` | 解锁检测 | 解锁 | 不打断；约 1–5 分钟 | 自动（只读） + 人工签收 | `probe`：宿主代理的只读探测：固定目录里的平台，经所选出口发出。校验：平台只能是探测目录里的 id，出口只能是拓扑里的出口；数量受探测任务自己的上限约束 | 不需要确认；不改动网关 | 配置或已安装版本变化后标为过期 |
| `remote-access` | 远程接入（手机蜂窝拨入） | 远程接入 | 不打断现有上网；约 5–10 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `tunnel-cut` | 断隧道时不回落到路由器 | 防泄露 | 会打断测试机的境外访问（人工操作）；约 10 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `webrtc` | WebRTC 的 srflx 是出口地址 | 防泄露 | 不打断；约 5 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `router-ula` | 路由器上的 ULA 黑洞 | 防泄露 | 不打断；约 5 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `exit-switch` | 真实出口与地区组切换 | 防泄露 | 会打断该地区组的流量（人工操作）；约 15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `redirect-capture` | 同网段 ICMP 重定向抓包 | 防泄露 | 不打断；约 10 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `sniff-client` | 按域名嗅探的真实设备表现 | 防泄露 | 停服务的一步会打断网页连接（人工操作）；约 15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-gateway-verify` | 网关上运行 meridian-verify.sh | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-netns-reload` | 持续流量下 nft 重载不漏（命名空间测试） | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-smartdns` | SmartDNS 容器启动并写入 nftset | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-mesh-veth` | Mesh WireGuard 腿（命名空间） | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-host-exec` | 宿主执行、开机兜底与运行态回滚 | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-lists-update` | 名单更新与重载后国内地址仍在 | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |
| `integration-netns-sniff` | 按域名嗅探的命名空间测试 | 防泄露 | 不打断（在隔离主机或网关上人工运行）；约 5–15 分钟 | 人工签收 | 无（面板不执行；按步骤人工做） | 操作者签收通过 / 不通过并写备注 | 配置或已安装版本变化后标为过期 |

`id` 是稳定的：存储的结果、页面间的链接和这份文档都用它。「防泄露」清单里的每一个隔离 Linux 集成项和实机人工签收项都对应目录里自己的一项（`TestCatalogCoversLeakChecklist`），不合并成一条笼统的「通过」；`remote-access` 本轮明确没有执行，页面上写着「本轮没有执行」，保持未验证。

### 证据分四部分，互不替代

每一项的证据分开保存、分开显示，任何一部分都不能替另一部分「通过」：

| 部分 | 来源 | 能说明 | 不能说明 |
| --- | --- | --- | --- |
| 配置证据 | `config-audit` 读编译出来的配置（`verify.CheckBundle`），顺带填好每一项相关的配置检查 | 生成的配置文本里有这些规则 | 规则已经加载；实机不泄露。**配置核对通过不等于实机通过** |
| 实测 | 只读检查或演练在网关宿主上看到的结果 | 执行那一刻宿主上的状态（单元在、解析器回答了、中继被剔除又恢复了） | 客户端一侧的任何事：`dns-leak` 的解析器能回答不等于没有泄漏；`ipv6-firewall-reload` 的采样看不到客户端的包 |
| 人工签收 | 操作者按步骤做完后记录的结果与备注 | 这个人在这个配置下做过这项检查 | 面板没有核对证据本身；存档位置写在备注里 |
| 已知限制 | 「防泄露」清单里的限制项 | 设计边界 | 不算失败，也不算解决 |

一项需要哪几部分写在目录里（页面上每一部分各占一格）。只有需要的每一部分在**当前配置**下都有通过的结果，这一项才显示「已验证」；只有其中一部分通过显示「部分完成」。演练的恢复没有核验通过时，无论演练本身观察到了什么，这一项都是「未通过」。

### 结果的保存与过期

每条结果保存：执行方式（自动 / 演练 / 人工）、固定动作与目标、结果、时间、用时、摘要与证据行、脱敏后的备注，以及当时的**配置指纹**和已安装版本。指纹由三样东西算出：当前拓扑编译结果的摘要、已安装清单记录的摘要、已安装版本号。任何一样变了（改了拓扑使生成的配置变化，或重新安装），旧结果**保留**并标为「已过期」，不再计入状态；要在新配置下重做。每项最多保留 20 条。备注在保存时脱敏：地址、MAC、链接、邮箱、域名、跟在「密码 / token / key」之类词后面的内容和任何长串都被替换（`acceptance.RedactNote`）；证据本身不要贴进备注，备注只写谁做的、存档在哪。证据行由面板生成，只含节点 id、接口名和计数。

### 演练的安全边界

三个演练都是宿主代理（`meridian-host`）的固定动作（`internal/hostexec/acceptance.go`）。没有任何通用执行入口：

- **参数**只有受管的隧道接口名和有界的时长。面板把请求里的中继节点 id 换成接口名之前先核对：它是拓扑里的中继、网关自己的上游记录里有它、它的接口在已安装清单里；宿主代理再核对一次接口在自己的受管记录里、在上游记录里。请求里没有命令、路径、主机或 URL 字段，出现未知字段整个请求被拒绝（`TestAcceptanceRejectsFreeForm`、`TestDrillEndpointsRefuseUnknownFields`）。**被隔离的地址不是参数**：宿主代理从 `wg show <接口> endpoints` 读出；回环地址（经本机 WSS 承载的隧道）、链路本地、组播和 Meridian 自己的隧道网段永远不会被隔离，这样的链路只能人工演练。
- **前置条件**在宿主上按实际状态检查，不满足就拒绝且不留任何改动：数据面在运行、两张表都在、故障切换循环的心跳在 60 秒内、当前在主链路上且状态是 `ok`；隔离一台中继时必须还有另一台在分担；隔离主枢纽时备用枢纽必须可用（否则会造成全断）。
- **二次确认**：先说明后果，再由面板签发一个确认，绑定这一项、这个动作、这个目标与时长、当时的配置指纹，120 秒有效，只能用一次；任何一样不符或过期都要重新确认。
- **互斥**：演练全程占着网关的节点锁和宿主事务锁（`apply.Applier.Hold`），面板上的安装、回滚、恢复、撤回、预检和第二个演练都被拒绝；宿主代理一侧同样拒绝 `activate` / `rollback` / `withdraw` 和第二个演练。已有安装在执行时演练不会开始。
- **先记录后改动**：改动之前，宿主代理把原状态（nft 表及其规则的摘要、策略规则、路由表、受管接口、上游记录里的路径 / 枢纽 / 每个中继的状态，权重只作记录）、恢复计划、截止时间和阶段写到 `/var/lib/meridian-host/drill.json`（0600，里面没有地址）。写不下去就不改动。
- **隔离的做法**：代理自己的一张表 `inet meridian_drill`（一次 `nft -f`，先 `nft -c` 检查），output 钩子丢弃发往集合里地址的包。集合里每个地址带**内核超时**（时长加 15 秒）：代理被杀掉时这道阻断也会自己失效，这是独立于代理的保险。重启机器后这张表不存在（它不在任何开机文件里）。
- **每条出路都恢复**：到时、取消、步骤失败、超时都走同一个恢复；面板或浏览器断开不影响，宿主代理按自己的时钟结束；代理重启后先恢复未完成的记录，这期间拒绝一切变更。
- **恢复要核对快照，不看健康检查**：删除阻断表并确认它不在了，然后等故障切换循环回到原状，把宿主与快照逐项比对。数据面「健康」不算恢复：承载路径、枢纽、每个中继的状态（被隔离的中继要重新 `active`）、规则、路由、接口有一样与快照不同就不算；中继权重由质量控制器动态调整，不比较，只把与演练前不同的权重写进观察。等待（300→360 秒）覆盖故障切换循环自己的恢复（连续 5 次成功 + 120 秒冷却，实测约 4 分钟），在此之前不触发重新激活。等待之后仍不一致时，经 `meridian.service` 重新激活数据面（与升级时 `RestoreDataPlane` 相同的步骤）再比对一次（`hostexec.RestoreTopology`）。
- **核对不过就保持阻断**：记录停在「恢复未核验」，列出每一处差异，新的演练和宿主变更都被拒绝，跨代理重启保持。可以**重试恢复**；只有在阻断表已确认不在时才能**解除阻断**（要输入 `release`），解除后这一项仍然记为「恢复未核验」，**永远不会显示为已恢复**，之后应重新安装一次让网关回到已知状态。

`ipv6-firewall-reload` 没有阻断表：它重启 `meridian.service`（与安装时相同的 `meridian-up.sh`），期间每 250 毫秒采样一次兜底表、主表和转发开关。只要有一次采样看不到兜底表就判为未通过。采样有间隔，也看不到客户端的包，所以这一项另有一个独立的人工步骤（路由器 WAN 口抓包），两部分都通过才算已验证。

### 自动化回归覆盖了什么（全部用替身，不连接任何主机）

| 测试 | 内容 |
| --- | --- |
| `internal/hostexec` `TestValidateDrillRejectsFreeForm`、`TestDrillEndpointsRefuseUnknownFields`、`TestDrillPreconditions`、`TestDrillSingleRelayRecord` | 只接受三种演练、隧道接口名和 20–90 秒；每个前置条件不满足时拒绝且宿主上没有任何命令改动、不留记录 |
| `TestRelayIsolationBlocksObservesAndRestores`、`TestHubIsolationSwitchesToBackupAndBack` | 地址来自宿主而不是请求、带内核超时、记录里没有地址；观察到剔除 / 切换；调用方离开后仍按时恢复并核对快照 |
| `TestDrillRefusesOverlap`、`TestDrillCancelRestores`、`TestDrillActionFailureRestores` | 与安装 / 回滚 / 撤回 / 第二个演练互斥；取消立即恢复；步骤失败时恢复、不留文件；记录写不下去时不改动 |
| `TestDrillCrashRestartRestoresBeforeNewChanges` | 代理中途「死掉」：新进程先恢复，恢复结束前拒绝一切变更；只写了「已准备」的记录同样恢复；记录损坏时保持阻断 |
| `TestDrillRestoreFailurePersistsBlocksAndRetries`、`TestDrillHealthyButNotSnapshotIsNotRestored`、`TestRestoreTopologyHealthIsNotTheCriterion`、`TestDrillDiffNamesWhatDiffers` | 阻断表删不掉：绝不报告已恢复，差异落盘、跨重启阻断、可重试；数据面健康但没回到快照：重新激活一次、仍不一致则阻断并列出差异；解除只在阻断表不在时允许且不等于恢复 |
| `TestFirewallReloadDrill`、`TestPathCheck` | 重载期间的采样与结论；路径检查只读受管接口、不返回密钥和地址 |
| `internal/api` `TestAcceptanceDrillConfirmLocksAndResult`、`TestAcceptanceDrillTargetsComeFromInstalledState`、`TestAcceptanceDrillRefusedByHost`、`TestAcceptanceDrillCancel` | 确认缺失 / 换了目标 / 换了时长 / 别的项 / 过期 / 配置变了都被拒绝；演练期间两把锁都被占着、安装等被拒绝；宿主拒绝或不可达时不留任何占用 |
| `TestAcceptanceDrillRestoreFailedRetryRelease`、`TestAcceptanceAdoptsDrillAfterPanelRestart`、`TestAcceptanceDrillFollowTimesOut` | 恢复未核验不记为通过；面板重启后从宿主记录取回结果（只取一次）；宿主不回答时写「结果不明」而不是通过 |
| `TestAcceptanceConfigAuditAndSignoff`、`TestAcceptanceReadOnlyChecks`、`TestAcceptanceMeshPathCheck` | 各部分分开计；重新安装或配置变化后结果保留并过期；备注脱敏；只读检查只用已安装的资源 |
| `internal/acceptance` | 目录完整性、与「防泄露」清单逐项对应、与本表一致、存储、过期、脱敏、确认的绑定与一次性 |
| `web/src/acceptance.test.tsx` | 页面：影响与耗时、各部分分开、过期不计、二次确认、签收、恢复未核验的阻断状态；其它页面上的链接与最近结果 |

### 没有验证的

- 开发与 QA **没有**在任何真实主机上执行过这三个演练，也没有在真实内核上加载过 `inet meridian_drill`；`nft` 的集合超时语法、`nft -s -t list table` 在同一份规则下前后一致、`wg show … endpoints` 的输出格式都只在替身上测过。第一次在真实网关上演练要有人在场，并准备好在网关上手工 `nft delete table inet meridian_drill`。
- 快照比对不再比较中继权重（实机演练前 474/526、恢复后 487/513 曾被误判 `restore_failed`）：上游记录的权重不比，nft 规则摘要去掉分担映射里的权重区间（权重同时写在 `relay_assign` / `relay_redirect` 的映射里，只放宽记录不够）；中继状态精确比较（QA 修正：原先 `active` / `reduced` / `recovering` 互相视为一致，会在中继仍 `recovering` 时报 `restored`），必须回到演练前状态，`recovering` / `reduced` / `evicted` / `standby` / `disabled` 都不一致，差异同时记进观察；`DrillVerifyWait` 覆盖实测约 1 分钟的 `recovering`→`active` 爬升。改动失败后的恢复与重试恢复同样等到循环恢复窗口结束才可能重新激活（`drillRecoveryWait`）。合成测试：`TestNormShareMapsIgnoresWeightsOnly`、`TestRelayIsolationRestoredWithOtherWeights`、`TestDrillRecoveryWait`、`TestDrillDiffIgnoresWeightsButNotRelayStatus`；`TestDrillDiffIgnoresWeightsButNotRelayStatus` 覆盖 active→recovering/reduced 未恢复、回到 active 通过；`TestDrillDiffRetainedReasonIsAState`：快照记中继原因，`reduced/retained_best` 与普通 `reduced` 不算同一状态（演练前置要求状态 `ok`，保留时是 `degraded`，不会开始演练）。Mesh 默认路由检测：主机侧按 WARP 接口与 WARP 策略表（含 65743）过滤两族全部默认路由，读取失败或超出上限输出 `defread` / `deftrunc` 并阻断（`TestDetectFindsWARPDefaultAfterManyOrdinaryRoutes`、`TestDetectDefaultRouteReadFailureOrTruncationBlocks`）；安装期检查读取失败也失败（`global_default_read_v4/6`）。
- 经本机 WSS 承载的隧道（端点在回环上）不能这样隔离；中继的 UDP 与 WSS 两条腿不同地址时，只隔离到 UDP 那个地址，演练会如实得到「没有观察到预期的变化」。
- 一次手工演练的观察（主会话在一台真实网关上手工做的，不是这里的固定动作；这里只记数量级，不含地址）：故障切换循环每 5 秒探测一次，连续 3 次失败剔除、连续 5 次成功并过 120 秒冷却后恢复；丢弃发往一台中继公网地址的出站包后，它的权重约 5 秒内降为 0、约 25 秒时状态变为 `evicted`，上网没有中断；两台都丢弃后约 25–30 秒切到备用枢纽（约 20 秒不通）；撤掉丢弃规则约 3 分钟后回到主链路和原来的权重。演练的默认时长（45 秒）和恢复等待（现为 360 秒）按这个数量级取。
- `mesh-e2e` 的实测只看到网关一侧的隧道握手和本地的 Mesh 部署记录；Mesh 在枢纽与出口之间的转发仍是人工项。真实的 Cloudflare Mesh 部署由主会话在真实环境执行。

## 路径

- [ ] `ip route` 只有一条 IPv4 默认路由，下一跳是 `192.0.2.88`。
- [ ] `ip -6 route` 的默认路由是网关的 `fe80::`，不是 ROS。
- [ ] 访问一个国内站点，源地址仍走家庭网络，不进隧道。
- [ ] 访问一个普通境外站点，出口 IP 是默认地区组（示例 `hk`）当前选中的那台（自动组默认是 IX 绑定的那台），而不是本地宽带、国内中继或 ROS。
- [ ] 面板里把 IX 那条边删掉后，保存被拒绝，并提示必经 IX。
- [ ] IX 替换模式关掉时，国内中继上的默认向东接口是 IX 隧道，不是 WSS。WSS 接口处于 up，但没有被选成默认路由。

## DNS

等级：实机人工签收。仓库里的测试和 `meridian-verify.sh` 都不运行这些页面；结果以截图和 WAN 抓包存档为准。

在测试机上打开：

- https://dnsleaktest.com
- https://ipleak.net

预期按两个解析设置（[架构](architecture.md)「客户端 IPv6 与 AAAA」「未列名单域名的国内解析」）分开写；签收时记下当时两者的值。

`unlisted_domestic_dns` 关闭（默认，严格）：

- [ ] IPv4 和 IPv6 的 DNS 与出口 IP 都属于当前选中的出口地区。
- [ ] 结果里没有家庭宽带的公网地址，也没有 ROS `192.0.2.1` 的出口。
- [ ] 在 ROS 或家庭光猫的 WAN 上看，这台测试机没有发往境外的 53/853 查询。查询应停在 `192.0.2.88`。

`unlisted_domestic_dns` 打开（保证变了，不能再按上面签收）：

- [ ] 出口 IP 属于当前选中的出口地区，结果里没有家庭宽带的公网地址。
- [ ] DNS 一栏**会**同时出现国内解析器（`domestic_dot`，默认 AliDNS / 腾讯 DNSPod）和出口的解析器：泄漏测试的名字不在名单里，网关把它们也发给国内解析器。这是这个设置的预期结果，不是测试机泄漏；签收时写明设置是打开的。
- [ ] 在 WAN 上看，**测试机自己**没有发出 53/853；网关（`192.0.2.88`）会向国内解析器发出名单外域名的查询（含国外域名），这正是打开时接受的代价。
- [ ] 一个名单外的国内网站（自己挑一个不在 `geosite/cn.txt` 里的）解析到的地址在 `nft list set inet meridian chnroute` 里，访问不进隧道；一个被封的国外网站解析到的是出口给的地址，不是国内解析器的污染结果（对比 `dig @223.5.5.5` 的回答）。
- [ ] 国内解析器回答「CNAME + 国外地址」的名字（第一版失败的 `www.wikipedia.org`、`www.facebook.com`、`www.bbc.com`）：`dig @192.0.2.88 A <名字>` 有地址，不是只有 CNAME；地址不是 `dig @223.5.5.5` 给的那个。
- [ ] 冷的国外名字（换一批没查过的）解析时间接近直接问出口解析器的时间（加不到 30 ms），不是固定的约 400 ms；`journalctl -u meridian-dns-split` 里每 10 分钟一行 `meridian-dns-split-stats`，`exit` 一项的 p50 不在 400 ms 附近，`silent domestic resolvers` 显示有没有国内解析器不回答。
- [ ] 关掉设置、重新安装后，上面这些名字立即按严格模式回答（网关配置有 `cache-persist no`，重启不再带着旧缓存）。

AAAA（`clients_ipv6_via_gateway`）：

- [ ] 关闭（默认）时：在一台只手填了 IPv4 网关和 DNS、IPv6 仍由 ROS 通告的手机上，`google.com`、`youtube.com` 之类没有 AAAA（`dig @192.0.2.88 AAAA www.google.com` 是 NOERROR、没有回答），ipleak.net 的 IPv6 一栏不是本地宽带地址（检测不到 IPv6 或只有出口）；国内名单里的域名（如 `qq.com`）仍有 AAAA。网关上 `meridian-verify.sh` 的 `dns_aaaa_tunnelled` 为 PASS。
- [ ] 打开时（测试机的 IPv6 默认路由指向网关）：对一个没有 `egress_v6` 的出口（示例里的台湾、新加坡），对应域名没有 AAAA，页面仍从该出口的 IPv4 打开；有 `egress_v6` 的出口返回 AAAA，经隧道走 IPv6。

### 解析配置视图、出口加密上游与直连目标的解析器（修订 19）

等级：自动化回归（本机）；真实 SmartDNS 二进制测试在本机**没有运行**（没有 Linux 和固定的二进制）；真实网关、出口和提供方上**全部未验证**。

已测（`go test ./...`、`npm --prefix web test`）：

- 解析器竞速与健康（`internal/sniff`）：`TestResolverHedgeAndHealth`（假时钟驱动对冲计时器：沉默的第一个解析器不被串行等待；降级后不再先问它；`HealthDemoteFor` 之后恢复顺序；一次回答解除降级；`PurgeHealth`）、`TestResolverTimeBounds`（三个都沉默时约一个超时内失败，而不是三个超时；SERVFAIL 立即换下一个，不等计时器）、原有 `TestResolverBudget`（`LookupBudget` 到期时报告超时、不缓存）。
- 自检逐解析器结果：`TestSelfCheckKnownSilentResolver`（第一次按完整超时、第二次按 500 ms 复查并标记「已知不应答」，周期运行不再等满完整超时；结果带健康记录；恢复回答后解除）。
- 出站限制：没有新端口，`sniff_confine`、目标文件和 verify 脚本的生成结果不变（原有 golden 与 `verify_sniff_test.go`、`sniff_test.go` 不变即为证据）。
- 无配置逐字节不变：`TestExitDNSUnconfiguredIdentical`（四个示例拓扑；全部出口覆盖为 builtin 也不变；配置后只有出口的 `etc/smartdns/smartdns.conf` 变化，网关文件不变）。
- 生成的行与路径约束：`TestExitDNSRendered`（只有 `server-tls` / `server-https` 行，没有明文 `server`、`-fallback`、`-set-mark`、`-proxy`、`-interface`、`-no-check-certificate`、`-bootstrap-dns`，没有国内解析器地址；带 `ca-file` 和 `-tls-host-verify`；外部出口的组不变；DoH 的 URL、`-http-host`；单出口覆盖与 builtin）。
- 校验与「没有跳过校验」：`TestExitDNSValidation`（模型里没有 skip/insecure/fallback/bootstrap 一类字段；私有、ULA、本机、CGNAT、组播、链路本地、国内解析器地址，`{account}` 的位置和次数、凭据缺失或多余、DoT 带路径、DoH 带查询串、网关或外部出口上的覆盖都被拒绝）。
- 秘密隔离：`TestDNSAccountSeams`（值只出现在出口的下发脚本里，并在该文件写成 0600；创建响应、保存响应、预检记录与其变更列表（只显示「‹账户标识已隐藏›」）、下发响应、`/api/compile`、`/api/diff`、`/api/validate`、`/api/dns`、`/api/dns/config`、`/api/dns-accounts`、各只读视图、面板数据目录里 `secrets/` 以外的所有文件（拓扑、快照、预检和安装记录）和日志都没有它）、`TestDNSAccountLifecycle`（索引和列表里没有值，只在一个 0600 文件里，轮换和删除后旧值不在磁盘上，与校验对值形状的定义一致）、`TestInjectDNSAccount`（只有 SmartDNS 配置能引用它，它不能引用别的秘密，畸形值不回显）、`TestDemoFixturesNoDNSAccount`（演示数据里没有演示用的值，但有虚构的 example.net 上游）。
- 轮换后的待下发：`TestDNSAccountRotationMarksExitsPending`（轮换后引用它的出口「有变更」、原因写明轮换和版本，不引用的节点（覆盖为 builtin 的出口、中继）摘要不变；部署计划里是安装步骤，不是只核对；轮换前审阅的预检下发被拒绝且没有执行脚本；新预检的变更列表带新版本；重新安装注入新值、恢复一致、记录版本 2；解析配置视图计划/已安装版本 2/1 → 2/2；旧值和新值都不在任何响应、`/api/compile`、`/api/diff`、`/api/deploy`、日志和 `secrets/` 以外的数据文件里）、`TestDNSAccountRotationStalesDeployVersion`（轮换使部署计划版本变化；没有账户时计划版本就是拓扑版本）、`TestDNSAccountVersionUpgrade`（没有账户的节点编译结果不带版本行、旧安装记录仍一致；引用账户、旧记录没有版本的出口按待下发并说明原因）、`TestDNSAccountVersionStamp`（版本行只写进带 `dnsacct-` 占位符和受限标记的配置，读回一致，不含占位符或值）、`TestDNSAccountRotateValidation`（轮换和修改要面板口令，畸形值不回显，未知凭据 404，被拒的轮换不改版本）。
- 接口：`TestDNSAuthAndCheck`（所有新接口都要面板口令；没有宿主代理时检查不运行；未知出口被拒；视图的各类行）、`TestDNSUpstreamIsIndependent`（整份拓扑保存省略时保留、不同时 409、相同时通过）。
- 固定检查：`TestDNSCheckIsFixed`（只接受 fd66::/48 里、且出现在已安装网关配置 `server … -group` 行里的地址；名字和类型固定；不在配置里或配置读不到时不发出任何查询；沉默的解析器在时限内报告超时；安装进行时不运行）。
- 面板：`web/src/dns_view.test.tsx`（各类行与传输、计划/已安装、已知不应答的解析器、检查前「未检查」、检查后「实测」、转发服务没有测量时「未验证」、原文只读且打码、账户值只发送一次且页面上不出现、保存走 `/api/dns/upstream`）、`topology_contract.test.tsx`（整份保存不带 `exit_dns`）。
- 按出口设置（修订 20）：`TestDNSUpstreamPerExitKeepsOthers`（只带 `exits` 的保存保留全局设置和其它出口的覆盖；`changed_exits` 只列生效上游变了的出口，相同的值再存一次为空；坏的覆盖 422 且不写入；网关上的覆盖 422、未知节点 404、空请求 400；`null` 让出口回到全局设置；显式 `"global": null` 仍清除全局，覆盖为 builtin 的出口不算变化）。面板 `web/src/dns_view.test.tsx` 的「per-exit upstream」：每行的来源、打码摘要、计划/已安装与账户标识版本（1/1 一致，2/1 显示不同和待重新安装）、只经 Mesh 的出口不能检查并写明原因、网关和外部 SOCKS 出口「不可设置」且没有按钮；三种选择各自的初始状态和来回切换（单独设置时字段与全局表单相同、DoH 才有路径）；保存的请求体逐字核对（`{exits:{jp-a:{protocol:"builtin"}}}`、自定义 DoH、`{exits:{sg1:null}}`，都没有 `global` 键），保存后列出待下发的出口、除保存外没有别的写请求；422 时显示校验问题（全局表单相同）；就地新建账户标识只发送一次、值不出现在页面和保存请求里；从行内发起解析检查；桌面宽度表格在预算内、手机宽度是卡片且不横向溢出。演示数据：`sg1` 带一个单独设置的 DoH 上游（虚构的 doh.example.org，文档地址段，没有账户标识）。

真实 SmartDNS 二进制（Linux，需要 `MERIDIAN_SMARTDNS_BIN`；本机未运行，本轮报告为 NOT RUN）：

```
MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
  go test ./internal/compile -run 'TestSmartDNSRealExitUpstream' -v
```

`TestSmartDNSRealExitUpstream` 用生成的上游行（地址改成 127.0.0.1 上的测试桩，`ca-file` 改成测试 CA）检查：固定版本接受这些指令；证书名字正确时经 DoT 和 DoH 都能解析（DoT 也测通配证书）、DoH 问的是注入后的路径和 Host；证书是别的名字时解析失败、桩没有收到任何查询；证书来自不在 `ca-file` 里的 CA 时同样失败。通配证书能否按 `-tls-host-verify` 匹配是本轮的假设，以这个测试的真实运行结果为准。

真实主机上未验证（主会话或操作者执行）：

- [ ] 转发服务装上新版本后，周期自检的 `duration_ms` 不再因为不应答明文 53 的国内解析器固定 ≥ 2000；面板「解析配置 → 嗅探转发服务的逐解析器结果」里它显示「已知不应答」，另一个显示有回答和时延。
- [ ] 配置出口加密上游、预检（变更列表只显示打码的上游）、确认安装到一个出口之后：出口上 `/etc/smartdns/smartdns.conf` 是 0600、`server-tls`/`server-https` 行带真实账户标识；`journalctl -u meridian-smartdns` 没有证书错误；面板「解析检查」显示「实测：有回答」。
- [ ] **确认加密服务真的在用**：在提供方自己的控制台 / 查询日志里看到来自该出口公网地址的查询（时间与「解析检查」或测试机访问一致）；或在出口上 `tcpdump -ni <上联> port 53` 看不到明文 53，只有到配置地址的 853 / 443。提供方提供「是否在用本服务」的测试名字时，在测试机上用一条指向该出口的规则访问它（网关会经隧道问这个出口的解析器）。面板的检查本身证明不了是哪个上游回答的。
- [ ] 把配置的上游地址在出口上临时挡掉（或填一个不应答的地址重新安装）后，该出口的名字解析失败，不出现内置公共解析器或国内解析器的回答（不回落）。
- [ ] 真实提供方的证书在 Debian/Ubuntu 的 `ca-certificates` 下校验通过（`ca-file` 路径存在）。
- [ ] 轮换账户标识后：部署页上引用它的出口显示待下发（原因是已轮换），重新预检、安装后出口上 `server-tls`/`server-https` 行是新值，`# meridian-account-version:` 行是新版本，面板「解析配置」计划/已安装版本一致；提供方控制台里查询记在新账户下。
- 外部 SOCKS 凭据的同类缺口（轮换后承载节点仍显示一致）已按同样的办法补上，见「外部 SOCKS 凭据轮换后承载节点待下发」；真实主机上未验证。

对已有拓扑生成文件的变化：

- (a) 什么都不配置、嗅探打开：**没有生成文件变化**（目标文件、`sniff_confine` 等 nft 规则、verify 脚本、SmartDNS 配置都与修订 19 之前相同）；变化只在 `meridian` 二进制的行为里（竞速、健康记录、自检多出的字段）。
- (b) 配置了出口上游之后：每个使用它的受管出口（没有覆盖为 builtin）的 `nodes/<出口>/etc/smartdns/smartdns.conf`，且只有它；网关、外部 SOCKS 出口的承载配置（gost）和其它文件不变。带账户标识时下发脚本把这个文件写成 0600，面板编译时在受限标记后加一行账户标识版本（轮换后这一行变化）。

### 网关解析器的真实二进制测试

等级：在固定版本 SmartDNS 上真实执行的本机测试（替身上游，只在回环上）；不是网关上的证据。`TestSmartDNSRealBinary` 用本仓库编译出的网关解析器配置（两个设置的四种组合）运行 SmartDNS；三个替身上游扮演两个国内解析器（`domestic_dot` 的两个地址，可以回答得不一样）和出口解析器；打开 `unlisted_domestic_dns` 时 `meridian-dns-split` 在测试进程里按编译出的单元参数运行（只把上游地址、mark 和名单路径换成替身）。逐项检查：

- 名单里的国内名字照常有 AAAA。
- 名单外的名字（设置打开时）：国内回答全是中国地址时采用——单独的 A、CNAME 链末端的 A、国内比出口慢 80 ms、另一个国内解析器先回了被污染的地址而中国回答在它的 30 ms settle 之内到达（晚于决定时间到达则用出口的，`split-dom-late`）；冷的国外名字在出口回答时决定（`cname-foreign` 要求 200 ms 以内，测得 52 ms），不再等 400 ms；**CNAME 链末端是国外地址（真实网关上失败的情况）**、中国与国外混合、NODATA、被污染的 A、国内不回答时都用出口的回答；出口不回答时 SERVFAIL、没有地址；从来没有只有 CNAME 的回答，也没有国内的国外地址；重复查询（缓存）结果相同。
- AAAA 和 HTTPS 的 IPv6 提示只在 `clients_ipv6_via_gateway` 打开且目标有 IPv6 时出现；空的 China 名单时全部用出口。
- 规则命中的名字（包括一条指向默认组本身的规则）在四种组合下都只问它目标的上游：替身国内解析器对这些名字一次查询都没收到（替身逐名计数），即使国内回答会被采用（全是中国地址）；目标不回答的规则名字解析失败，不回落到国内。
- 策略变化与缓存：设置打开时缓存下来的国内回答，在 SIGTERM（`docker restart` 发的就是它）后用关闭设置的配置启动，按新策略回答；对照组（去掉 `cache-persist no`，即 SmartDNS 默认）里旧回答仍被返回。
- 去掉 `force-AAAA-SOA`（以前的配置）时默认组的 AAAA 会被返回。

China 名单用了与真实名单同量级的条目数（8193 条 IPv4、4097 条 IPv6）。第一版（SmartDNS 自己的 `-whitelist-ip` + `-fallback`）对「CNAME + 国外 A」在两个二进制上都返回只有 CNAME 的回答，原因见[架构](architecture.md)「未列名单域名的国内解析」。

```
MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 go test ./internal/compile -run TestSmartDNSRealBinary -v
# 没有这个二进制的机器（如 macOS）：在面板镜像里跑交叉编译的测试二进制
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
docker run --rm --network none --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro \
  -e MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
  --entrypoint /compile.test meridian:local -test.run TestSmartDNSRealBinary -test.v
```

网关的容器镜像：同一条命令换成 `pymumu/smartdns:latest`、`MERIDIAN_SMARTDNS_BIN=/usr/sbin/smartdns`。没有 `MERIDIAN_SMARTDNS_BIN` 时跳过（`--- SKIP`，不是通过）。2026-11-13 在开发机上用 `meridian:local` 里的 Release48.4 和本机的 `pymumu/smartdns:latest`（1.2026.11.09-1240）都跑通过。测试改动了配置里与环境有关的部分（监听改到回环端口、上游地址指向替身、去掉 `-set-mark` 和 nftset、文件和缓存文件挪到临时目录；`meridian-dns-split` 不带 mark），所以它不证明 mark、nftset 写入、systemd 单元和真实上游的行为。接入本分支后（加了规则名字的检查）2026-11-13 在开发机上用同样两个二进制（`meridian:local` 的 Release48.4 和 `pymumu/smartdns:latest` 1.2026.11.09-1240）重新跑通过。`clients_ipv6_via_gateway` 关闭的行为在真实网关上确认过（`dns_aaaa_tunnelled` PASS）；`unlisted_domestic_dns` 的第一版在真实网关上失败。

**真实网关上的观测（2026-11-13，主会话在用户网关上测过一次，没有存档的日志，不是可复现的证据）**：网关运行的是独立分支上的同一套 `meridian-dns-split`（含上面的决定时机）。20 个冷的国外名字全部解析到出口给的地址，用时 52–72 ms（上一版时机下每个约 400 ms：两个国内解析器里有一个从不回答这类查询）；之前只得到 CNAME 的三个名字解析正确；带国内 CDN 节点的名单外名字由国内解析器回答，约 8 ms，并直连；走隧道的名字没有 AAAA，名单内的国内名字有 AAAA；关掉设置立即生效，没有旧回答；`meridian-verify.sh` 通过（`dns_aaaa_tunnelled`、`dns_split_active`）。外部出口、挂靠出口、多中继、Mesh 和远程接入下的这项功能都没有在真实环境里用过；iOS 的「无线局域网没有接入互联网」**不知道是否已经解决**，复测和抓包步骤见[测试设备](test-device.md)「iOS 联网检测复测」。

### meridian-dns-split 在命名空间里跟着地区组走

等级：隔离 Linux 集成（本机 Linux 容器，不是测试网关，没有存档的日志）。`TestNetnsGroupDNSFailover` 在网关命名空间里按编译出的单元参数（同一拓扑、默认组设成 us）运行 `meridian dns-split`（测试二进制作为辅助进程），问一个名单外的名字：切换前由 us 回答，枢纽切到 us-2 后由 us-2 回答，两个成员都断时 SERVFAIL；组切到 Mesh 备路时经 Mesh 由 us 回答，Mesh 断时 SERVFAIL。它的出口查询带组标记（Go 的 `SO_MARK`），在网关上被计为带组标记的查询并到达 us，组自己的查询仍然一次都没有到国内解析器（服务为名单外名字发出的国内查询单独计数，扣除后为 0）。国内一侧在这个实验里不回答（ROS 拥有那两个地址但没有监听）。2026-11-13 在开发机的 arm64 特权容器里跑通过一次；同一天 `TestNetnsExternalExit`（真实 gost 3.2.6 与 SmartDNS）也在那里跑通过，其中用 **UDP** 从组的中转源和独立解析地址问外部出口的解析组得到了经 SOCKS 用 TCP 解析的回答——这正是 `meridian-dns-split` 的出口查询在网关 SNAT 之后的样子。

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
docker run --rm --privileged -v /tmp/compile.test:/compile.test:ro -e MERIDIAN_NETNS_TEST=1 \
  --entrypoint /compile.test <有 ip、nft、python3、nsenter 的 Debian 13 镜像> -test.run '^TestNetnsGroupDNSFailover$' -test.v
```

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

境外出口上的解析器是面板下发的固定版本 SmartDNS（1.2026.08.05-0921，按架构选 x86_64 / aarch64，经 SSH 传输、主机上核对 SHA-256 后装到 `/usr/local/sbin/meridian-smartdns`），由 `meridian-smartdns.service` 运行，不再从 apt 安装；`meridian-up.sh` 在隧道起来后重启它，下发输出里应有 `MERIDIAN_SMARTDNS_ACTIVE`。在网关上用 `dig @<出口隧道 ULA> example.com` 应有应答。**这一项在真实出口上还没有执行过。**

## 面板下发的二进制与支持平台

等级：自动化测试（已有）+ 实机人工签收（未执行）。

自动化测试覆盖（不下载任何东西，用假二进制和进程内 SSH 服务器）：

- `internal/artifacts`：锁文件解析与拒绝、按架构选择、加载时缺文件 / 大小不符 / 摘要不符 / `manifest.txt` 不一致各自不可用、使用时再校验（`TestLoadAndRead`）；`deploy/fetch-artifacts.sh` 用本地副本通过、上游或二进制摘要不符时构建失败、缺本地副本时去下载（桩 `curl` 失败）（`TestFetchScriptVerifiesWithoutDownloading`）。
- `internal/preflight`：Debian 12、Debian 13、Ubuntu 20.04 aarch64 的夹具和不支持的组合（`TestPlatformMatrix`）、二进制计划（传输 / 已是固定摘要不传输 / 别人的文件阻断 / 面板副本不可用阻断）、内存预算、解析器绑定、已有安装（含受管容器与新解析器单元）的更新不被阻断。
- `internal/provision`（沙箱）：暂存文件摘要不符在激活前拒绝且主机不变、已是固定摘要时只核对不安装、别人的文件不覆盖、替换后重启用它的单元且失败时补偿放回旧文件、旧版 `smartdns.service` 的停用与恢复、撤回删除二进制。
- `internal/api`：经连接池的一次登录完成预检复跑、传输、下发；面板副本加载后被改动时 409 拒绝且什么都没发送；网关安装写入并记录 wstunnel；登录提示的各种组合。
- `internal/apply`：网关二进制在安装事务里写入、失败补偿放回旧版本、不再需要时删除、别人的同名文件不覆盖。

镜像构建：在 Mac 上 `docker buildx build --platform linux/amd64 -f deploy/Dockerfile .` 时，`artifacts` 阶段从 GitHub 下载并核对了四个固定文件（见提交说明里的构建记录）；这只证明下载地址和摘要正确。

实机签收（**都还没有做**）：

- [ ] 在一台 Debian 12 x86_64、一台 Debian 13 x86_64 和那台 Ubuntu 20.04 aarch64 上预检：「安装计划」的平台、架构、包和二进制动作与主机一致。
- [ ] 下发输出有 `MERIDIAN_SMARTDNS_ACTIVE`；`sha256sum /usr/local/sbin/meridian-smartdns` 等于锁文件对应架构的值；`ss -lunp` 里 53 只在隧道地址上，进程是 `meridian-smartd`。
- [ ] 中继（WSS）下发后 `wstunnel-meridian.service` 在运行，`/usr/local/sbin/meridian-wstunnel --version` 是 11.1.0；主机上原有的 `/usr/local/bin/wstunnel` 未被改动。
- [ ] 再装一次：预检显示二进制「已是固定版本，不传输」。
- [ ] Ubuntu 20.04：装了 nftables 之后 `update-alternatives --display iptables` 仍是 legacy，legacy 规则（`iptables-legacy-save`）与下发前相同，`nft -c -f /etc/nftables.d/meridian.nft` 通过。
- [ ] 撤回后 `/usr/local/sbin/meridian-*` 和 `meridian-smartdns.service` 不在了，别的服务的 wstunnel / smartdns 仍在。
- [ ] 网关有 WSS 链路时「安装到网关」写入 `/usr/local/sbin/meridian-wstunnel`，`wstunnel-client-*.service` 在运行。

DoH 只能拦截清单内的公共解析器。用非常见的 DoH 地址仍可能绕过，这是已知边界，不要把它写成「绝对不泄漏」。

## WSS 承载：随机路径、自签证书与轮换

等级：自动化测试（已有）+ 本机容器里真实 wstunnel 二进制的回环测试（已执行，见下）+ 实机人工签收（**都还没有做**）。机制见 architecture.md「WSS 承载：随机路径与自签证书」。

自动化测试（不连接任何远端）：

- `go test ./internal/credentials -run WSS`：路径格式与熵（2000 个互不相同、48 位十六进制）、证书参数（P-256、SHA-256、非 CA、唯一 SAN、有效期、指纹）、Go TLS 按客户端同样的信任模型拒绝别的自签证书 / 别的名字 / 过期证书并接受轮换中的双根；生成幂等、秘密只在 0600 的生成文件里不在索引里；链路和监听删除后秘密变成未使用；**轮换状态机的随机化测试**（60 个种子，安装成功 / 补偿失败 / 结果不明随机交替，每一步检查两端实际运行的阶段都能互通，最终完成并释放旧密钥）；固定顺序的中断与补偿；回滚与撤回的标记；注入时钟的到期轮换；旧版迁移（部署过的监听进入迁移、旧前缀不是纯 token 时不带过去、幂等、之后不再进入迁移）。
- `go test ./internal/compile -run WSS`：渲染出的服务端 / 客户端单元参数逐字比对（单枢纽、中继、双枢纽的备用枢纽 WSS 链路、中继的故障切换 WSS 腿）：服务端只用 `--restrict-config`，每条链路一条规则、只放行 UDP 到 `127.0.0.1` 上自己的 WG 端口；客户端有 `--tls-verify-certificate`、`--tls-sni-override ${MERIDIAN_WSS_SNI}`、`SSL_CERT_FILE` 指向信任文件、`SSL_CERT_DIR=` 为空，命令行里没有路径前缀；解析后的包里没有任何秘密；轮换阶段 1 的服务端接受两个前缀、仍出示旧证书，客户端信任两张证书；没有材料时记号保留且被两条安装路径和预览脚本拒绝；路径和私钥不能注入到错误的文件，远程接入密钥不能发给远端节点；**结构性的否定用例**：用注入后的真实文件，自己的前缀只到自己的端口，别的链路的前缀、旧固定前缀、截断 / 加长 / 大写的前缀都被拒绝；按信任文件和 `.env` 里的名字做的 TLS 握手接受本监听、拒绝别的监听的信任文件和别的名字。
- `go test ./internal/provision -run WSS`（沙箱里真跑下发脚本）：WSS 目录 0700、`server.yaml` / `server.key` / `.env` 0600、证书 0644；清单记录这些文件但不含秘密；只重启 WSS 文件真的变了的那个单元；换证书时服务端重启失败 → 补偿恢复旧证书和私钥并在恢复的文件上再重启一次；撤回删掉 WSS 文件和目录。
- `go test ./internal/api -run WSS`：网关安装把前缀写进宿主的 0600 文件，API（各个只读视图、`/api/wss`、编译、差异、校验、宿主状态、下发记录）、日志、数据目录（数据库和快照）里都没有 WSS 秘密，`/api/wss` 也不返回秘密在凭据存储里的 id；证书轮换经网关安装完成，旧私钥在不再被任何快照引用后删除；运行时回滚后网关一端显示「配置不确定」并列为下一步；旧版拓扑的迁移（字段移出、迁移状态、服务端接受新旧前缀、幂等、之后导入的旧字段同样移出）；远端下发只把这个节点的 WSS 秘密放进下发脚本的标准输入，别的节点的不放，预览只有占位符且拒绝运行。
- `npm --prefix web test`（`pages_rules_topology.test.tsx`「WSS carriers」）：部署页显示指纹、合成名称、到期、路径「已设置」，重新生成证书后显示下一步、两端不一致和各端阶段；迁移和过期证书的告警；重新生成路径；拓扑页没有路径和证书路径输入框，链路编辑器显示 WSS 状态。

真实二进制（可选，Linux）：`TestWstunnelRealBinary` 用编译器渲染出的参数和环境、注入后的真实文件，在回环上跑固定版本的 wstunnel：正确的证书 + 名字 + 路径时 UDP 包能过；另一个监听的证书（服务端日志 `received fatal alert: UnknownCA`）、另一个名字（`BadCertificate`）、另一个路径和旧固定路径（`Rejecting connection with not allowed destination`，客户端 `Invalid status code: 400`）都过不去；去掉 `--tls-verify-certificate` 的对照组用错误证书能过；轮换用的双根信任文件能过；对服务端发普通请求和错误路径的升级请求都回 `400 "Invalid request"`、没有 `Server` 头。运行方式（在有这个二进制的 Linux 主机上；仓库里的 Go 1.22+）：

```
MERIDIAN_WSTUNNEL_BIN=/usr/local/sbin/meridian-wstunnel go test ./internal/compile -run TestWstunnelRealBinary -v
# 或用镜像里的副本：
MERIDIAN_WSTUNNEL_BIN=/usr/share/meridian/artifacts/wstunnel-x86_64 go test ./internal/compile -run TestWstunnelRealBinary -v
```

只在回环上监听（随机端口），不连接外网，不改系统配置；没有这个变量时测试跳过。也可以在 Mac 上交叉编译后放进镜像跑：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile`，`docker run --rm --platform linux/amd64 --network none -v $PWD/compile.test:/t/compile.test:ro -e MERIDIAN_WSTUNNEL_BIN=/usr/share/meridian/artifacts/wstunnel-x86_64 --entrypoint /t/compile.test meridian:local -test.run TestWstunnelRealBinary -test.v`。2026-11-13 在开发机上用本地镜像 `meridian:local`（linux/amd64 仿真，wstunnel 11.1.0）这样跑过，全部通过；这是本机容器里的回环，**不是**真实主机或真实网络路径。

实机签收（**都还没有做**）：

- [ ] 升级后第一次打开面板：拓扑里不再有 `wss_path_prefix` / `tls_*`；「部署」页的「WSS 承载」对以前装过的监听显示「从旧版固定路径迁移中」和下一步。
- [ ] 按下一步依次重新下发服务端、客户端、服务端；每一步之后 WSS 腿仍然可用（`wg show` 的 WSS 接口最近握手在更新），最后旧前缀不再被接受。
- [ ] 中继上 `ls -l /etc/meridian/wss` 是 0700，`server.key`、`server.yaml`、`client-*.env` 是 0600；`ps -o args -C meridian-wstunnel` 里没有路径前缀。
- [ ] 从外部 `curl -vk https://<中继>:<WSS 端口>/` 得到 400，证书是自签、名字是 `.invalid`；`openssl s_client -connect <中继>:<端口> -servername x.invalid` 能看到同一张证书（证书对任何人可见）。
- [ ] 把网关上一条链路的信任文件换成别的证书后重启客户端：服务端日志出现 `UnknownCA`，WSS 腿不通；恢复后通。
- [ ] 手动重新生成证书并按下一步完成轮换；途中只下发一端时面板显示「两端暂不一致」而 WSS 腿仍通；每次下发时 WSS 腿中断的时长（预计几秒）记下来。
- [ ] 证书到期前 30 天的自动轮换：把面板的时钟（或用一张短有效期的证书，需要临时改代码）推到到期前，确认面板告警且没有自动改动主机。

## 多中继同时分担

设计见[架构文档「多中继同时分担」](architecture.md#多中继同时分担)。

**自动化回归（任何平台）：**

- `go test ./internal/pathquality`：状态机和权重（质量相近时等分、按质量加权、轻度劣化先降权再暂停分配且从不清空集合、低于下限剔除并清理、噪声输入下不会恢复也不会抖动、滞回后 25% → 50% → 100% 逐步加回、所有中继完全不通切备用枢纽；在备用枢纽上任一启用中继任一腿连续 3 轮（约 15 秒）可达且距上次切换满 `min_dwell_sec`（120 秒）即切回，不要求质量良好，切回后由保留规则决定分担（`TestBackupReturnsWhenRelaysReachableButPoor`：60% / 20% 丢包仍可达，满间隔前不回、满后回且保留较好者；`TestBackupNoReturnBeforeThreeReachablePasses`；等待期间告警 `on_backup_returning`，状态里 `switch_reason` 为 `all_relays_down` / `relay_reachable` / `backup_down`）、质量剔除从不清空集合：两台都差时保留分数最好且仍可达的一台（`reduced` / `retained_best`、独占权重、不清理、不切备线，即使备用分数更好：`TestAllPoorBackupBetterStaysOnBestRelay`、`TestAllPoorBackupNotBetterStaysAndAlerts`）、一差一好只剔除差者（`TestOnePoorOneGoodEvictsThePoorOnly`）、保留者随后完全不通立即切备线并在恢复后按原规则切回与爬坡（`TestRetainedThenFullyDownTakesBackupAndRecovers`）、别的中继恢复后释放保留者（`TestRetainedReleasedWhenAnotherRecovers`）、TCP 无回包 / 吞吐探测不达标属质量失败只保留不切换、UDP 腿不通而 WSS 腿仍应答不算不通（`TestQualityFailuresRetainLegAnswersIsNotDown`、`TestThroughputFailureBothRelaysRetains`）、停用的中继不被保留、旧版持久状态进入新策略、旧的「因分数优势停在备线」状态按可达规则 3 轮后切回（`TestOldStateAllEvictedRetainsAndReturnsFromScoreBackup`）、什么都不通时不动且记录 `down`、负载下 RTT 膨胀触发吞吐探测、探测不达标剔除并在加回前要求一次通过的探测、有业务时 TCP 无回包剔除而上传不误判、探测关闭和预算用完时不探测、腿的 UDP/WSS 滞回、手动停用和固定权重、配置变化重置状态）、严格的配置和决定解析、ping 和 nft JSON 解析、探测开销估算。
- `go test ./internal/compile -run 'Share|Sharing'`：编译出的规则（按连接的 `jhash … map` 只在 `ct state new` 时查、每个包从 ct mark 恢复、中继位在 -300 清掉、兜底表包含每条腿和备用接口且仍以 drop 结束、每台中继的 fwmark 规则和表、中继和主枢纽按入接口的回程标记与表、本机应答的 route 链、单中继拓扑一个字都不变）；带桩执行的 shell：`share_map` 与编译器逐字一致、`share_apply` 一次 nft 批次和九种拒绝（拒绝时 nft 和 ip 都没被调用、nft 拒绝批次时路由不变）、同一决定只下发一次、引用非编译接口的决定被拒绝并改用应急规则、没有控制程序时的应急规则（等权重、3 轮剔除、5 轮加回、没有中继时走备用、冷却后切回）；安装与应急规则写的状态记录能被 meridian-host 严格解析；校验（缺到主枢纽的隧道、重复链路、IX 替换模式、各项设置越界、覆盖指向非中继、全部停用、预算放不下一次探测）。
- `go test ./internal/hostexec -run Upstream`：第二种状态记录的严格解析（未知状态、字段多一个少一个、权重和丢包越界、重复中继、未知行、接口名里的 shell 字符、超长等都拒绝）。
- `go test ./internal/api -run 'Sharing|PathQuality'`：`GET /api/upstream` 的 `sharing`（测量值、备用路径、按设置估算的探测开销、断连影响；记录过期或格式与拓扑不符时未知）、单枢纽分担、保存拓扑时设置被校验。
- `npm --prefix web test`：出口页的分担表（份额、状态、原因和时间、清理中、网关测量的值和时间、探测结果和当天字节、备用路径、断连影响、标明「面板估算」的探测开销）、应急规则和告警的提示、记录未知、概览卡片、网关设置里改阈值和探测预算（估算随之变化、保存的只是改过的字段）。

**隔离 Linux 集成证据：** `TestNetnsRelaySharing`（命令和覆盖范围见上表）。开发时它在一台 Mac 上的 Docker 容器里（Debian 13 用户态经 amd64 模拟、linuxkit 6.10 内核、有 netem）通过过，同一容器里 `TestNetnsDualHub`、`TestNetnsReloadNoLeak`、`TestNetnsGroupDNSFailover`、`TestNetnsULALANHomeAccess` 也通过；这**不是**存档的证据（没有日志存档、不是目标发行版的内核），在 Debian 13 主机上跑通并存档之前，按「未执行」对待。

**实机人工签收（未做）：** 两台真实国内中继同时承载、晚高峰真实限速下的降权 / 剔除 / 恢复、吞吐探测的真实流量开销（对照中继的计费）、剔除时应用重连的体验、真实 WireGuard / wstunnel 腿的切换、备用枢纽接管和切回。

## WebRTC

等级：实机人工签收。

用浏览器打开 ipleak 或 browserleaks 的 WebRTC 测试。

- [ ] srflx / 出口候选是当前出口地址，不是家庭 WAN。
- [ ] 境外 STUN 和同一目标的 TCP 走同一个出口。

已知限制：host 候选里仍可能出现 ROS 通告的 GUA，因为测试机还拿着那条 /64。这是单条运营商前缀加 SLAAC 的结果。要去掉它，只能让测试机不用 GUA、改用 ULA 再在网关做 NAT66，国内 IPv6 就不再端到端。一期把这件事记在验收说明里，不把它当成失败。

## 规则

### 有序列表、导入、规则集（自动化回归与本机 Docker；没有在真实网关或真实 mihomo 配置上执行过）

等级：代码级回归，加上本机容器里对固定版本 SmartDNS（Release48.4）和 nft 1.1.3 的真实执行；**不是网关上的证据**，也从没用操作者的真实配置跑过。

- `go test ./internal/ordered`：参考解释器与数据面模型（派生的 domain-set 由 SmartDNS 最长键模型选择 + 分类链按集合顺序）的差分测试：3000 个生成的列表（每个 1–8 条规则、1–4 个条目：精确名、后缀、子域名、嵌套和重叠的 CIDR、GEOIP,CN，三层名字空间里大量重复后缀、先具体后一般、先一般后具体、同名的精确 / 后缀对、单个名字例外在包含它的规则之前；随机的国内名单），共 28.2 万个探测（每个名字和它的下级各一个新地址，四分之一取自 CIDR 池以覆盖域名与 IP 交叉，另有只给地址的探测），全部一致；故意把过滤改坏时测试失败（手工变异检查过一次）。手写的形状：重复后缀、先具体后一般、单名例外、精确与后缀同名、IP 规则夹在域名规则之间、规则先于国内名单、GEOIP,CN 在中间。共享地址按「更靠前的规则赢」写成测试；关键词不执行的差别也写成测试。`Decide`（索引版）与 `Reference` 在 2000 个含关键词、子域名、按设备规则的生成列表上比较了 112.8 万次判断，全部一致。基准：`go test ./internal/ordered -bench .`。
- `go test ./internal/compile -run 'Ordered|RejectDirect|RulesBefore'`：用**真实渲染出来的** `order.conf`、`smartdns.conf`、nft 分类链（含静态集合元素）和 `decide.json`，400 个生成的拓扑规则列表（精确、后缀、CIDR、规则集〔精确 / 后缀 / 子域名 / CIDR 条目〕、GEOIP,CN；去向为地区组、服务组、直连、拒绝）共 4400 个探测，渲染出的标记 == 参考解释器 == `Decide`。拒绝的兜底表行、QUIC 链的豁免、没有新功能时 nft 不变、规则优先于国内名单、没有 `gs_apple`。
- 真实 SmartDNS（opt-in，本机 Docker，2026-11-13 在开发机上用 `meridian:local` 的 Release48.4 跑通）：

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
docker run --rm --network none --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro \
  -e MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
  --entrypoint /compile.test meridian:local -test.run 'TestOrderedRealSmartDNS|TestSmartDNSRealBinary' -test.v
```

  `TestOrderedRealSmartDNS`：25 个生成的列表（精确 / 后缀 / 子域名，`-.d` 与 `*.d` 写在 domain-set 文件里）装进真实 SmartDNS，1100 个名字逐个查询：SmartDNS 的选择 == `DNSModel` == 参考解释器；再装 16 万个键（10 万规则集名字 + 6 万国内名字），启动约 0.1 秒内开始应答，抽查的名字（规则集之前的精确例外、规则集、同时在国内名单里的名字、国内名字）都对。单层名字（例如 `example`）SmartDNS 不按规则回答，测试不用。`TestSmartDNSRealBinary`（已有）改为用派生的集合后同样通过。
- nft（opt-in，特权容器）：`docker run --rm --privileged --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro -e MERIDIAN_NFT_TEST=1 --entrypoint /compile.test meridian:local -test.run TestRuleSetNFTLoadLarge -test.v`：带规则集、拒绝和 QUIC 开关的整份网关规则集 `nft -c` / `nft -f` 通过；6 万条 IPv4 + 2 万条 IPv6 规则集前缀（含重叠）合并后约 0.27 秒装入，再装一次（重启时）也通过。
- `go test ./internal/ruleset`：每种格式（Clash yaml 三种行为、Clash text 三种、Surge .list 与 DOMAIN-SET）、CRLF、BOM、注释、行内策略字段、大小写混用、IPv6、超大内容、二进制 / .mrs、重定向到私网和回环被拒绝、默认守卫拒绝回环源。
- `go test ./internal/mihomo`：锚点、合并键、流式映射、带空格的名字、注释；假的密码 / UUID / 私钥 / 订阅令牌 / 控制口令不出现在解析结果、预览或计划里；经选中状态的映射链；遮蔽；重复导入的差异；写入后能通过校验；导入的列表与 mihomo 的第一条命中给出相同去向；`address_only` 等标记分类。
- `go test ./internal/api -run 'Import|ServiceGroup|RuleSet|RuleTester'`：预览 → 规则集后台下载 → 接受 → 摘要不符被拒 → 确认；秘密不在任何应答、日志、数据库文件或数据目录的任何文件里；拓扑整份保存省略服务组和规则集时保留它们（带了不同的值整个拒绝，见 `TestTopologySaveIndependentContract`）；服务组改指向时住宅要求被校验；规则集被使用时不能删、失败保留旧版、关键词变多的新版本被暂缓、确认后启用；测试器用 `Decide`。
- `npm --prefix web test`：`src/rules_ordered.test.tsx`（跨类移动并按列表顺序保存、来源和服务组去向、遮蔽列、服务组改指向、测试器、导入：阻止 → 接受 → 刷新 → 带摘要确认、粘贴的文本不进浏览器存储）。
- [ ] 实机（主会话，未执行）：安装这一版后 `ls /var/lib/meridian/geosite/ordered/` 有每条规则一个文件和 `gs_cn.txt`；`journalctl -u meridian.service` 有 `meridian-lists-derive-ready`；规则页测试器和 `dig @<网关> <名字>` + `nft get element inet meridian r<n> { <地址> }` 对几个有先后关系的名字一致；名单更新后 `status.json` 的 `rules` 一项为已更新。
- [ ] 实机（主会话，未执行）：用真实 mihomo 配置导入，预览里没有出现任何 `proxies` 段的内容；确认、安装后，原来排在 QUIC 规则之前的规则的 UDP 443 不被拒绝、之后的被拒绝（`nft list chain inet meridian quic` 计数）。
- [ ] 实机（主会话，未执行）：iOS「无可用互联网」复测时注意，`captive.apple.com` 现在没有规则时走默认组（内置 Apple 直连已去掉）。

### 原有项

- [ ] 手动规则优先于自动表。示例里的 `api.example.com` 钉在美国池。
- [ ] 把 Netflix 改到机房出口时，校验报 `residential_required`，不能保存。
- [ ] 台湾规则失败时不会自动改去日本。解锁结果只在同一个地区组里换成员。

## 按域名嗅探（settings.sniff）

等级：代码级回归，加上本机 Docker 特权容器（`meridian:local`，linux/amd64 模拟，内核 6.10 linuxkit，nft 1.1.3）里的命名空间测试；**不是网关上的证据**，没有真实客户端、真实隧道或真实出口。

**真实网关上的第一次开启失败过（主会话，Debian 13 / systemd 257）**：预检无阻断，安装事务在启动 `meridian-sniff.service` 时失败（`Failed to determine user credentials: No such process`、`status=217/USER`：systemd 在执行任何 Exec 行之前就解析 `User=`，带 `+` 的 `ExecStartPre` 也来不及建账号），补偿成功、数据面未受影响，留下一个空的 `/etc/meridian/sniff`。另外从单元属性推断出 host agent（root、只有 `CAP_NET_ADMIN`）进不了 0750 的运行目录、连不上 0600 的套接字。本版改为独立的 root oneshot 账号单元、运行目录 0755 + 套接字 0666 + 只回答 uid 0 的对端凭据检查、补偿和撤回删掉变空的 `/etc/meridian/sniff`（设计见架构文档「单元与账号」「状态套接字的访问」）。**这些改动还没有在任何真实 systemd 上运行过**：下面的 `deploy/verify-sniff-systemd.sh` 由主会话先在网关上执行，通过之后才再次开启嗅探。

**嗅探出站限制拦截了 WireGuard 外层包（第二次开启，主会话，Debian 13 / 内核 6.12 / nft 1.1.3，真实隧道）**：上面的单元问题修好、安装成功、面板读得到状态之后，开启约四十分钟内转发服务判断的连接里，去向是直连的全部成功，去向是任何地区组的全部失败：按名字的连接在解析这一步 2 秒超时，按地址回落的连接连上游 18 秒超时，`sniff_confine` 的 `sniff_denied` 与失败几乎一一对应、每次一个约 156 字节的包。主会话随即关闭了嗅探。根因（主会话在真实隧道上用临时表和测试 uid 证实，没有改动受管表）：经 WireGuard 接口发出的包加密后的外层 UDP 包仍带着发出内层包的套接字，`meta skuid` 对外层包同样成立；外层包（`fwmark 0x4d72`，发往中继公网端点的 WireGuard 端口，或 WSS 承载时 `127.0.0.1` 上的 wstunnel 端口）不符合任何放行规则，落到「非 TCP 一律丢弃」。对照：只有原放行规则时查询超时、拒绝计数加一个 156 字节的包；在前面加一条按 fwmark 放行的 UDP 规则后同一查询 46 毫秒成功。之前的命名空间测试没发现，因为那里的「隧道」是 veth，没有封装、没有带属主的外层包。修复与审计见架构文档「封装后的外层包」：只按「标记 + UDP + 出口接口 + 每条网关隧道的端点地址和端口（WSS 为 `lo` 上的 wstunnel 本地端口）」放行，计数 `sniff_wg_outer`。**真实网关上重新开启并由真实客户端验证之前，这个修复是未验证的**：先在网关内核上跑下面带 WireGuard 的命名空间测试，通过后由主会话按面板流程开启，核对 `sniff_wg_outer` 增长、`sniff_denied` 不再随经隧道的连接增长、地区组目标的连接成功。

**这类故障现在在安装时就被发现并回退（转发服务自检，未在真实网关上验证）**：嗅探开启的安装在健康检查的最后要求转发服务自己的路径自检（架构文档「转发服务自检」）：转发服务以 uid 65530、自己的标记、在 `sniff_confine` 之下，向每个目标的解析器问 `. IN NS`，并经默认地区组的隧道建一次 TCP 连接；结果必须属于本次安装的目标文件、是本次请求之后跑的、不超过 2 分钟。按这次事故的情形：默认地区组的解析器查询超时（外层包被丢弃），`sniff self-check` 步骤失败（`default_failed`），事务几秒内补偿回安装前的版本，错误写明「默认目标 group:… 的路径不通：解析器 … 超时，没有任何回应」；自检不能执行或没有按时回答同样回退（`unavailable` / `timeout`），只有别的目标不通时安装保留并给出告警。面板的嗅探卡片把「运行中」和「路径是否可用」分开，显示最近一次自检、各目标最近的解析和连接失败数、`sniff_denied` 是否在增长、`sniff_wg_outer`，失败集中在隧道目标而直连正常时直接说明是转发服务自己的隧道路径出了问题；验收脚本多了 `sniff_selfcheck`、`sniff_selfcheck_targets`、`sniff_wg_outer`、`sniff_denied`（自检前后各读一次，默认相隔 5 秒）。这些都只在单元测试、伪造宿主和命名空间里执行过；**真实网关上重新开启嗅探、由真实客户端验证之前，安装时的自检、面板诊断和验收脚本的新检查都是未验证的**。

- `go test ./internal/sniff -run 'SelfCheck|TargetStats'`：用伪造的解析器（回答、NXDOMAIN、SERVFAIL、超时、本机拒绝发送、端口不可达、答非所问）分类每种结果；混合目标（默认可用、其它不通 → 告警；默认不通或连接试探超时 → 失败）；有界（所有解析器都不回答时一次查询时限内结束；40 个目标、预算短于工作量时剩下的记为 `not_run`、结果 `incomplete`、默认目标失败；同时进行的探测不超过 8 个）；没有解析器的默认目标是「未检查」而不是失败；规则代：结果带目标文件的哈希，改写目标文件并重载后后台重跑的结果带新哈希，旧结果对新的一对被判为 `stale_generation`，早于请求或超过 2 分钟的被判为陈旧，没有结果是 `unavailable`；`POST /v1/selfcheck` 不接受参数、GET 被拒；按目标的计数（总数、15 分钟窗口、最近一次失败，离开目标文件的目标被删除）。
- `go test ./internal/hostexec -run Sniff`：activate 在转发服务启动或重载后附上自检结果但自己不判断；转发服务还报告旧的一对时等待；一直没有载入时不请求自检、代码 `not_loaded`；请求被拒 `no_answer`；没有套接字 `no_socket`；不涉及转发服务的 activate 没有自检；名单发布后重载并自检，通过时无告警，失败时两条告警（默认目标、其它目标）而发布不失败；状态读取多了两个 nft 计数器和更早的 `sniff_denied` 读数（至少 30 秒、至多 30 分钟，计数变小时清空）；`/v1/sniff/selfcheck` 不接受参数。
- `go test ./internal/apply -run SniffSelfCheck`（伪造宿主上跑真实的 agent，转发服务的状态套接字由模拟器应答）：全部可用 → 安装、`sniff self-check` 步骤通过，规则变化重载后再自检一次；其它目标不通 → 安装保留、告警写明目标；默认目标不通、自检被拒（超时）、结果属于另一版规则 → 补偿回上一版本、转发服务的一切都不在、错误码分别是 `default_failed`、`timeout`、`stale_generation`；上一版本也开着嗅探时补偿不以它的自检为条件（步骤标为跳过、告警说明）；agent 没有返回自检 → `unavailable`、失败关闭。
- `go test ./internal/api -run 'TestDemoFixtures|TestSniff'` 和 `web/src/sniff_paths.test.tsx`：面板的诊断（路径可用、事故情形：一条错误提示、`sniff_denied` 在增长、默认目标的原因；其它目标不通；自检不属于当前规则；立即自检后刷新；概览块同时显示运行中和路径状态；表格在宽度预算内）。演示数据：正常场景所有目标可达，降级场景一个非默认出口的解析器超时。
- `go test ./internal/compile -run TestSniffSelfCheckSamePathAsLookup`：6 种嗅探拓扑加两个变体（钉住嵌套出口 twnat、钉住外部 SOCKS 出口 myext）里每种目标：真实解析（`Resolver.Lookup`，让每个解析器都失败以走完全部）问到的（解析器，查询标记）集合与自检问到的完全相同，并且每一对都是 `sniff_confine` 放行的解析器；没有解析器的目标是「未检查」而不是失败；拒绝目标不检查。两者经同一个函数 `Resolver.exchange` 发出。
- `go test ./internal/compile -run TestVerifyScriptSniffSelfCheck`：验收脚本里新检查的判定（用桩代替 `meridian sniff-selfcheck` 和 nft 计数器）：通过；别的目标不通 → WARN 并列出；事故 → `sniff_selfcheck` 和 `sniff_denied` 都 FAIL；规则没按时载入 → FAIL；没有套接字、旧二进制、没有目标文件、计数器读不到 → UNKNOWN（不是 PASS）；没有 `sniff_wg_outer` → FAIL；嗅探关闭时脚本里没有这些检查。

- `go test ./internal/sniff`（含 `-race`）：按标记匹配目标（静态组与成员出口共用、没有解析器的目标、未列出的标记拒绝安装）、ECH 公共名字与外层名字、快照与目标文件成对（哈希不符时保留旧规则）、`--addr-mark-bit` / `--ech-public-names` 参数、`MarkFromSocket` 读不到时报 `read_failed`、没有接管位时报 `without_bit`（从不当成分类）。原有 `TestInstallChecks` 的「没有解析器」一项从「拒绝」移到「接受」（只经 Mesh 的出口没有隧道解析器），按名字决定到它的连接仍然失败（`TestNoResolverTarget`）。
- 名字解析不到与接管位缺失（`go test ./internal/sniff -run 'ResolveFailureFallsBackByAddress|FallbackNotABypass|MarkMissing|AddrMark|LookupBudget|ResolverBudget'`）：NXDOMAIN、没有可用地址、SERVFAIL 都按地址转发到原目的地址，不再用名字规则的目标，记录写 `name_unresolved`、原因和名字的判断；不存在的名字放在直连规则下、地址被分类到默认组 → 默认组，从不直连；分类器判直连的地址 → 直连；存在的名字照旧；拒绝规则先于解析；分类器的拒绝在回退里同样生效；缺接管位 / 读不出标记：不论自己的判断是默认组（模拟被拒绝规则学到、转发服务看不到的地址）、CIDR 隧道、直连还是拒绝，一律拒绝（`mark_missing`、`classification_unconfirmed`），上游一次都不拨，记录原始标记和自己判断的规则；标记可信时照常转发；带接管位但不在目标表里 → `unknown_mark`；查询时限：三条并发连接等同一个永不回答的查询，都在 200 毫秒时限后按地址转发，单次查询超时先到时记 `resolver_failed`；超时不缓存。`go test ./internal/compile -run TestSniffNFTShape`：`sniff_input` 里补位规则在丢弃规则之后、清零规则之前，只有这两条改标记。`TestLinuxSocketOptions`（root、`MERIDIAN_NETNS_TEST=1`，在 `unshare -n` 的私有命名空间里）新增：本命名空间的 `tcp_fwmark_accept=1` 下，IPv4 和 IPv6 回环上带接管位的 SYN 接受后读出 `ok` 和分类标记，不带的读出 `without_bit`。
- [ ] 实机（主会话，未执行）：装上这一版后，网关上 `nft list counter inet meridian sniff_resyn` 的读数、面板近期决策里 `name_unresolved` 和 `mark_status` 不是 `ok` 的记录（展开看原始标记）；原来以 `resolve_failed nxdomain` 重置的应用自带解析请求能连通、按目的地址分流；以 `unknown_mark` 重置的连接不再出现，或者出现时带着原始标记和 `mark_status`，可以据此定位。
- `go test ./internal/compile -run 'Sniff|RuleSetNamesUnique'`：关闭时逐字节不变（6 种拓扑：示例、远程接入、主备枢纽、多中继分担、嵌套出口、仅 TCP 的外部出口，都带直连、拒绝、服务组、CIDR、关键词规则；示例里同时有只带 IPv4 和双栈的目标）；目标文件完整（转发核心自己的 `Install` 接受编译出的一对、分类链设置的每个标记都有目标、解析器与网关 SmartDNS 一致、输出链放行的正是这些解析器和查询标记）；链的顺序、兜底表不变、每个出口和组标记的转发服务 SNAT、所有网关隧道都在合法出口里；单元的命令行能被转发核心的参数解析接受；校验拒绝的设置；`meridian-verify.sh` 只在开启时多出检查并能被 `bash -n` 解析；规则数 ≥17 时集合名不再重复。WireGuard 外层包（`TestSniffWGOuterEndpoints`、`TestSniffWGOuterFailClosed`、`TestSniffOwnerRulesSkipOuterPackets`）：6 种拓扑里每条网关隧道的 `Endpoint`（地址和端口）和每个网关 wstunnel 客户端的本地端口各有且只有一条放行（局域网口 / `lo`），没有别的规则带 `0x4d72`，配置的 `FwMark` 是它，直连端点被路由脚本钉在局域网口，放行在「非 TCP 一律丢弃」之前；没有 `Endpoint`（对端拨入、没有端点）和端点是域名的隧道没有放行、链里有说明，IPv6 端点是 `ip6` 规则；规则集里每一条 `meta skuid` 都在审计清单里（`sniff_route` 只看 TCP 和出口标记范围、`sniff_mss` 只看 TCP SYN、转发服务的 SNAT 只看出口和组标记，`0x4d72` 不在出口和组标记里、不带中继位和接管位）。
- `go test ./internal/hostexec ./internal/apply -run 'Sniff|Reload|OwnedDir'`：`reload` 只能用于 activate 且必须在单元列表里；账号单元 `meridian-sniff-account.service` 不能被请求点名（`TestSniffAccountUnitReserved`）；activate 在 `meridian.service` 之后对它 `reload-or-restart`，否则按固定顺序 stop 服务 → stop 账号单元（检查 `ExecStop`）→ `reset-failed` → start，失败时带两个单元的日志（`TestActivateRestartsSniffWithAccount`）；移除时 `disable --now` → 停账号单元 → `reset-failed`，账号删除失败时动作失败，账号单元曾因冲突失败时不误报（`TestRollbackSniffAccount`）；状态读取（没有套接字、正常、非 JSON、对端不回答、不接受参数）；名单发布后只给正在运行的服务发重载。安装事务（真 agent + 按 systemd 依赖语义建模的模拟宿主：`Requires=`/`After=` 先启动账号单元，冲突时依赖失败，`StopWhenUnneeded` 视为异步、只有显式 stop 删账号）：两个单元文件、账号脚本、目标文件都是清单文件、只有服务单元在单元列表里（`TestSniffManifest`）；重载规则（`TestSniffReloadRule`）；`TestSniffLifecycle` 逐个转换核对命令顺序和结束状态：首次开启、只改规则时重载（账号不动）、改设置时重启（账号删了再建）、运行态回滚、关闭（`disable --now` → 停账号单元 → `reset-failed` → 删文件和空目录 → `daemon-reload`）、回滚再装回、撤回；`TestSniffFailedStartCompensates`：单元在但启动失败、以及账号冲突两种情形，补偿之后两个单元都不在运行或 failed、文件、脚本、账号、sysctl、空的 `/etc/meridian/sniff` 都不在，上一版在运行，修好后再装能起来；`TestOwnedDirRemoval`。
- `go test ./internal/sniff -run 'Status|VerifyFixture'`：状态套接字是 0666，只回答对端 uid 0，其他 uid（含转发账号自己）和读不到凭据的连接不回答就关闭（`TestStatusPeerCheck`）；Linux 上用真实 `SO_PEERCRED` 的 `TestStatusPeerCredLinux`（只在 Linux 上编译运行，这台开发机是 macOS，**没有执行过**）；检验脚本用的合成规则对能被载入。
- `go test ./internal/compile -run 'SniffUnitLayout|SniffSpecRender'`、`go test ./cmd/meridian -run SniffVerify`：两个单元的指令（`Requires=`/`After=` 账号单元、`StopWhenUnneeded=yes`、`Type=oneshot`、`RemainAfterExit=yes`、账号单元没有 `User=`/`[Install]`、服务单元里没有账号脚本、`RuntimeDirectoryMode=0755`、`+sysctl` 两行）；编译出的单元就是 `RenderSniffUnit(网关规格)`；`meridian sniff-verify-render` 写出的文件与同一组渲染函数一致，拒绝放在 `/run`、`/tmp`、`/home`、`/root` 下的路径，不覆盖已有文件。
- `go test ./internal/api -run 'Sniff|RuleTester'`、`go test ./internal/mihomo -run NameAware`：设置接口与校验、运行状态透传、测试器按 MAC；导入时只有关键词标记被放宽，QUIC 仍阻止。
- 命名空间测试（opt-in，root）：

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
docker run --rm --privileged --network none --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro \
  -e MERIDIAN_NETNS_TEST=1 -e MERIDIAN_NFT_TEST=1 --entrypoint /compile.test meridian:local \
  -test.run '^(TestNetnsSniff|TestNetnsSniffRelaySharing|TestNetnsSniffWireGuard|TestNetnsSniffWireGuardRelaySharing|TestNetnsSniffFallback|TestSniffNFTLoadAll)$' -test.v
```

  需要 `ip`、`nft`、`bash`、`setpriv`（不需要 ping 和 python3）；带 WireGuard 的两个还需要 `wg`（wireguard-tools）和能建 WireGuard 接口的内核，缺任何一个时 `--- SKIP` 并写明「NOT RUN」，**跳过不是通过**。`TestNetnsSniff`：局域网口叫 `enp3s0`，隧道是两端同 MAC、关闭 ARP 的 veth（像 WireGuard 一样的三层链路），对端命名空间按中转源地址判断出口；转发服务就是 `meridian sniff`，以 uid 65530、只带 `CAP_NET_ADMIN` 运行。阶段与通过的样子：A 开启前建立的连接开启后继续回显；B 同一个地址 `203.0.113.110` 上两个名字（HTTP Host 和 TLS SNI 各一次）分别从 hk 组和 us 组的中转地址出去，IPv6 客户端、关键词规则也对；C 读不到名字时与分类链一致（CIDR 规则、解析器学进某规则集合的地址、默认组），关掉 `tcp_fwmark_accept`（套接字上没有接管位）时这种连接被拒绝（转发服务自己的地址判断虽然给出隧道目标），记录里 `result: mark_missing`、`error: classification_unconfirmed`、`mark_status: without_bit`、`raw_mark: 0x0`、`view: own_address_view`；D 每个名字只在自己目标的解析器上被问，国内解析器只看到直连名字，直连连接从网关的局域网地址到 ROS，拒绝规则被拒绝；E 远程接入设备同样；F 转发服务自己不带标记、端口不对、目的是私有地址、标记不在任何目标里、DNS 标记不对的出站都被丢弃且 `sniff_denied` 计数增加，合法的一条通过，root 的连接不受影响；G 规则热更新（nft 加载 + 改写一对文件 + SIGHUP）期间持续新建连接，全部成功，先旧目标后新目标；H 杀掉转发服务后被接管的连接约 0.1 秒内被拒绝，对端和 ROS 都没有看到包；全程 ROS 没有收到任何发往境外测试地址的包。最后一行 `meridian-netns-sniff-test-ok`。`TestNetnsSniffRelaySharing`：两条中继分担时转发服务的 24 条连接分布在两条中继的腿上、源地址是默认组的中转地址、没有走备用枢纽；`share_apply backup …` 之后的 8 条只走备用枢纽的腿。最后一行 `meridian-netns-sniff-sharing-test-ok`。这两个测试的隧道是 veth，**看不到 WireGuard 封装**：把外层包放行规则去掉后它们照样通过（下面的变异检查），所以它们证明的是接管、分流和失败关闭，不证明经隧道的流量真的能出去。
  `TestNetnsSniffWireGuard`（`netns_sniff_wg_linux_test.go`）：同一个实验室，网关的隧道换成内核 WireGuard 接口：网关用**编译出的配置**（`FwMark = 0x4d72`、`Endpoint`、`AllowedIPs`、`PersistentKeepalive` 原样，只换成测试里生成的密钥），对端命名空间 `far` 为每条网关隧道建一个 WireGuard 接口，在编译出的端点端口上监听；ROS 经一条 veth 底层把端点地址路由到 `far` 并像家用路由器一样做源地址转换。WSS 承载的 `Endpoint` 是 `127.0.0.1:<本地端口>`，网关命名空间里由一个 UDP 中转（`udprelay`，root 运行，每个来源地址一条关联）代替 wstunnel 客户端，把数据报经底层送到 `far`。阶段：W1 直连 WireGuard 腿上按名字到地区组（名字在组的解析器上经隧道解析、到上游的 TCP 经隧道）、第二个组的 TLS 名字、按地址回落（CIDR 规则）、IPv6 客户端，全部成功，`sniff_wg_outer` 增长（证明内核把外层包算在转发服务的 uid 上）而 `sniff_denied` 不变；W2 以转发服务的 uid 伪造的数据报：带 `0x4d72` 发往非端点地址、发往端点地址的别的端口、发往回环上不是 wstunnel 的端口、不带标记发往端点，各被拒绝（`operation not permitted`）且 `sniff_denied` 加一；带标记恰好发往端点或本机 wstunnel 端口的被放行，但只到那个 WireGuard 端口、被丢弃，`far` 上的服务什么都没看到，隧道照常工作；另外记录 uid 65530 加 `CAP_NET_ADMIN` 能经 netlink 读到接口私钥（只记长度，说明见架构文档）；W3 **事故复现**：从已加载的规则集里删掉外层包放行，按名字的连接约 2.1 秒失败（解析超时）、按地址回落的连接超时，`sniff_denied` 增长；重新加载后恢复；W4 切到同一中继的 WSS 腿（回环形态），W1 的连接经 wstunnel 替身全部成功，再做一次 W3。另外 S（转发服务自检，经状态套接字按安装时 agent 的同样方式请求，按安装事务的同样规则判断，`sniffLab.selfCheck`：有解析器的目标除了明确列出的都必须 ok，直连也不例外）：S0 在 ROS 上的国内解析器（`198.18.0.53`）还没启动时，直连目标失败、判定仍是 ok 并带一条告警（直连不是默认目标），证据是 ROS 的 `Udp NoPorts` 增长而网关的 `sniff_denied` 不变——查询带着国内标记出去了，是 ROS 回了端口不可达；S1 解析器启动后、W1 之后所有目标（直连、各组）都 ok，默认目标（组 hk）的 TCP 连接建立；W3 和 W4 删掉外层包放行之后，所有经隧道的目标都失败、判定为 `default_failed`——**也就是这次的安装会被回退**——直连照样 ok；重新加载规则集后再次全部通过。veth 的 `TestNetnsSniff` 同样在 F 之后、G 的新一对规则之后检查全部 ok，再停掉国内解析器检查直连失败、判定 ok 带一条告警。（第一版的 S1 证据里直连是「被对端拒绝」，测试把它豁免了：原因是带 WireGuard 的实验室从来没启动 ROS 上的国内解析器，不是自检的路径和真实解析不同；豁免已去掉。）全程 ROS 没有收到发往境外测试地址的包。最后一行 `meridian-netns-sniff-wg-test-ok`。`TestNetnsSniffWireGuardRelaySharing`：`TestNetnsSniffRelaySharing` 的同一流程跑在 WireGuard 上（两台中继各一条直连 WireGuard、备用枢纽经 WSS 承载即回环形态）：24 条连接分在两台中继、`share_apply backup` 后 8 条只走备用枢纽（替身转发了数据报），`sniff_denied` 不变、`sniff_wg_outer` 增长，ROS 为 0。最后一行 `meridian-netns-sniff-wg-sharing-test-ok`。
  `TestSniffNFTLoadAll`（`-e MERIDIAN_NFT_TEST=1`）：上面 6 种拓扑开启后的网关规则集（都有 WSS 承载；含两台中继、备用枢纽、嵌套出口、外部出口）各在一个新命名空间里 `nft -c` / `nft -f` 通过。
  `TestNetnsSniffFallback`（同一个实验室，在所有名字规则之后多一条把 ROS 的 `198.18.0.2/32` 判为直连的 CIDR 规则；还需要 `ss`；开始前先用 `decide.json` 核对每个阶段的有序判定，顺序假设不成立时直接失败）：N1 直连规则下不存在的名字（国内替身解析器回 NXDOMAIN）连 `203.0.113.111:80`，从默认组 hk 的中转地址出去，不直连，记录 `why: name_unresolved`、`error: nxdomain`、`name_rule.target: direct`；N2 hk 名字规则下不存在的名字连 `198.18.0.2:80`（有序判定先命中名字规则 `sn-a`，直连 CIDR 规则排在它之后；分类器按地址判直连），从网关局域网地址到 ROS，记录 `name_rule.target: group:hk`、`target: direct`、`mark_status: ok`；N3 存在的名字照旧；N4 解析器永不回答的名字在一次查询超时（2 秒）后按地址转发，客户端等待不超过时限加 3 秒；N5 默认组承载 IPv6 时，没有名字的 IPv6 连接的套接字带接管位；M1 关掉 `tcp_fwmark_accept`：没有名字的连接一律被拒绝，不论转发服务自己的判断是 CIDR 规则的隧道（`sn-cidr`）还是直连（`sn-rosdirect`），记录 `mark_missing` / `classification_unconfirmed` / `without_bit` / `view: own_address_view` 和自己判断的规则，对端一条连接都没收到；M2 复用 4 元组：第一条连接的 FIN/RST 被实验室表在连接跟踪之前丢掉、用 `ss -K` 去掉转发服务的套接字，再从同一端口连 `203.0.113.115`（已学进 us 规则集合）：`sniff_redirected` 不变、`sniff_resyn` 增加、记录 `mark_status: ok`、从 us 出去（修之前会缺接管位而被拒绝）——`ss -K` 不可用时这一段记「NOT RUN」；M3 第一轮 SYN-ACK 被丢掉、客户端重发 SYN：连接仍从 us 出去，记录 `mark_status: ok`。最后一行 `meridian-netns-sniff-fallback-test-ok`。实验室表 `inet msnlab` 只建在网关命名空间里。
  2026-11-14 在开发机的这个容器里各跑通过（日志没有存档到 `docs/evidence/`）；在 Debian 13 真实内核上**没有执行过**。2026-11-15 加了外层包放行之后，在同一个容器（内核 6.10 linuxkit，带 WireGuard，`wg` 在镜像里）里上面 5 个测试全部通过（`TestNetnsSniffWireGuard` 约 34 秒、`TestNetnsSniffWireGuardRelaySharing` 约 14 秒）。**变异检查**：把外层包放行的渲染去掉重新编译，`TestNetnsSniffWireGuard`（W1 第一条按名字的连接 `connection reset by peer`）和 `TestNetnsSniffWireGuardRelaySharing`（第一条连接）都失败，而 veth 的 `TestNetnsSniff`、`TestNetnsSniffRelaySharing` 照样通过——带 WireGuard 的测试能抓到这次事故，原来的不能。
  2026-11-15 加了自检之后，在同一个容器里 `TestNetnsSniffWireGuard`（含 S 阶段）通过：S1 默认目标 `group:hk` 解析器 `answer`、TCP `connected`，其余组目标 `answer`；W3、W4 删掉放行后默认目标 `timeout`（解析器和 TCP），判定 `default_failed`，自检约 3 秒结束；重新加载后 `ok`。在用户网关的内核上运行（主会话；需要 root、`ip`、`nft`、`setpriv`、`wg`、能建 WireGuard 接口的内核）：

  ```
  go test -c -o compile.test ./internal/compile   # 或交叉编译 GOOS=linux GOARCH=amd64
  sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^(TestNetnsSniffWireGuard|TestNetnsSniffWireGuardRelaySharing|TestNetnsSniff|TestNetnsSniffRelaySharing)$' -test.v
  ```

  最后分别打印 `meridian-netns-sniff-wg-test-ok`、`meridian-netns-sniff-wg-sharing-test-ok`、`meridian-netns-sniff-test-ok`、`meridian-netns-sniff-sharing-test-ok`；日志里 `EVIDENCE … S2 … verdict default_failed` 那几行就是「事故在安装时会被回退」的证据。
  带 WireGuard 的测试**没有覆盖**：真实 wstunnel 二进制（回环形态由 UDP 中转代替，wstunnel 本身见 `TestWstunnelRealBinary`）；IPv6 外层端点（没有示例拓扑有，只有渲染的单元测试）；没有固定端点的隧道（对端拨入、域名端点，只有渲染的单元测试）；远程接入 `mra` 的外层包（实验室里设备侧是 veth）；真实的中继、枢纽和出口（`far` 是一个命名空间，替它们全部应答）；安装事务里端点变化的那段时间（规则集先换、`wg syncconf` 后做，只按代码顺序说明）；内核 6.12（容器是 6.10）。
- [ ] 网关的内核（主会话，未执行；**再次开启嗅探之前必须通过**）：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile`，拷到网关，`sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^(TestNetnsSniffWireGuard|TestNetnsSniffWireGuardRelaySharing|TestNetnsSniff|TestNetnsSniffRelaySharing|TestSniffNFTLoadAll)$' -test.v 2>&1 | tee sniff-netns.log`。测试只在自己建的命名空间（`msn*`）里建接口、加载 nft、改 sysctl，不碰主机命名空间的规则集、路由和受管的隧道；要求 `wg` 和 `setpriv` 在、嗅探在网关上处于关闭状态。两个 WireGuard 测试出现 `--- SKIP`（`NOT RUN`）时不算通过。存档日志。
- [ ] 实机重新开启（主会话，未执行，上一项通过之后）：按面板流程开启嗅探，用真实客户端访问一个去向是地区组的站点（按名字）和一个只有地址的连接，确认成功；`nft list counter inet meridian sniff_wg_outer` 增长、`sniff_denied` 不随这些连接增长；之后才能把这个修复写成已验证。
- [ ] 隔离 Linux 主机（主会话，未执行）：上面的命令换成真实内核：`sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^(TestNetnsSniff|TestNetnsSniffRelaySharing|TestNetnsSniffWireGuard|TestNetnsSniffWireGuardRelaySharing|TestSniffNFTLoadAll)$' -test.v`，再用 `go test -c ./internal/sniff` 的二进制跑 `sudo MERIDIAN_NETNS_TEST=1 ./sniff.test -test.run '^TestLinuxSocketOptions$' -test.v`，存档日志。
- [ ] **真实 systemd 检验（主会话，未执行；再次开启嗅探之前在网关上先跑它）**：

```
sudo bash deploy/verify-sniff-systemd.sh                 # tcp_fwmark_accept 只写回当前值
sudo bash deploy/verify-sniff-systemd.sh --flip-sysctl   # 另外证明 1/0 的开关（只在真服务没运行且当前为 0 时才真的切换）
```

  需要 root、systemd、这次构建的 `/usr/local/bin/meridian`（或 `MERIDIAN_BIN=…`，不能放在 `/tmp`、`/run`、`/home`、`/root` 下）。它用临时单元名 `meridian-vfy-sniff-<随机>.service` / `…-account.service`（单元文件放 `/run/systemd/system`，只是单元文件，不从 `/run` 执行任何东西）、65520–65529 里空闲的临时 uid/gid、`127.0.0.1` 上一个空闲端口、`/var/lib/meridian-vfy-sniff.XXXXXX` 里的账号脚本和合成规则对（一条规则都没有）；单元和脚本由 `meridian sniff-verify-render` 用安装同一组渲染函数生成，不是手写副本。每项打印 `PASS`/`FAIL`/`SKIP`，有任何 `FAIL` 时退出码非 0；正常结束和中途失败（`trap`）都清理它建的一切，最后一项 `cleanup` 核对什么都没留下。检查项：两个单元 `systemd-analyze verify`；`start` 成功（不再 217/USER）；账号和组以临时号被账号单元建出、账号单元 active；转发服务就绪并在端口上监听；进程的 Uid/Gid 四个值都是临时号、没有别的附加组、`CapEff`/`CapPrm`/`CapAmb`/`CapBnd` 都只有 `CAP_NET_ADMIN`、`NoNewPrivs=1`；同一沙箱里的同类账号能进入 `/etc/meridian`、`/var/lib/meridian` 并读 `decide.json`、目标文件、geosite / 规则集 / 关键词 / 中国名单的 `*.txt` 和二进制（主机上不存在的路径记为 `SKIP`）；运行目录 0755、套接字 0666、属主都是临时号；以 `systemd-run` 复制 host agent 的身份和沙箱（装了 `meridian-host.service` 时取它的 `User`、`CapabilityBoundingSet`、`AmbientCapabilities`、`NoNewPrivileges`、`ProtectSystem`、`ProtectHome`、`PrivateTmp`、`PrivateDevices`、`ReadWritePaths`、`RestrictAddressFamilies`、`UMask` 等现值，否则用仓库里的值），先确认它是 uid 0、`CapEff` 只有 `CAP_NET_ADMIN`，再用 agent 自己的读取代码（`meridian sniff-verify-read` → `hostexec.ReadSniffSocket`）读到 `/v1/health` 和 `/v1/recent`；`nobody` 能连上但拿不到回答；`systemctl reload`（SIGHUP）后进程号不变、监听还在、规则代数加一；`tcp_fwmark_accept` 在运行时是写入的值（`--flip-sysctl` 时为 1）；`stop` 之后账号单元由 systemd 自己停掉（`StopWhenUnneeded`）、账号和组被删、运行目录消失、sysctl 回到原值；临时 uid 被别人占用、临时名字以别的 uid 存在时，启动失败、账号单元日志里有 `meridian-sniff-user-conflict` 那一行、服务不在运行也不监听。它**不碰** `inet meridian` / `inet meridian_guard`、Meridian 的单元、路由和任何流量，不发起任何外连（转发服务没有被连接过，合成规则对里的解析器从不被问）；`meridian-sniff.service` 正在运行时绝不切换 `tcp_fwmark_accept`。
  它证明的：这套单元布局在这台主机的 systemd 上能启动、账号生命周期、能力与沙箱、文件可读、宿主代理在它现有沙箱下读得到状态而别的用户读不到、重载、停止清理、冲突拒绝。它**不证明**接管和分流（重定向、标记、出站限制、在出口解析、失败关闭时没有包漏出去）：那些由上面的命名空间测试和网关上的 `meridian-verify.sh` 覆盖；也不证明面板安装事务在真机上的执行（用下一项）。
- [ ] 实机（主会话，未执行，在上一项通过之后）：开启后安装，`meridian-verify.sh` 里 `PASS sniff_active`、`PASS sniff_account_unit`、`PASS sniff_account`、`PASS sniff_status_socket`、`PASS sniff_confine`、`PASS sniff_fwmark_accept`；`id meridian-sniff` 是 65530；面板规则页的状态为运行中（证明 agent 读得到状态套接字）；关闭设置再安装后 `getent passwd meridian-sniff` 为空、`systemctl status meridian-sniff.service meridian-sniff-account.service` 都是未加载或 inactive、`/etc/meridian/sniff` 不存在、`sysctl net.ipv4.tcp_fwmark_accept` 为 0、`nft list chain inet meridian sniff_mark` 不存在。
- [ ] 人工签收（未执行）：见[测试设备](test-device.md)「按域名嗅探」。

### 修订 19 装到真实主机后的结果（修订 20 提供的事实，主会话执行；不含地址）

- 网关：安装后嗅探转发服务带日志目录（`--journal-dir`）重启并通过自检；自检耗时由约 2 秒降到约 0.5 秒（只在明文 53 上不应答的国内解析器不再被等满超时）。日志目录为 0700、属转发服务的固定用户。
- 网关验收脚本 `meridian-verify.sh` 全部通过，包括新增的 `tunnel_mtu`、`sniff_journal_dir`、`local_mss`。
- 外部 SOCKS 预检：已部署的承载节点在外部代理对端离线时为告警，节点正常安装（见「外部代理不可达」）。
- 部署引导：网关之后的 12 个节点由引导逐台预检、确认、下发，每台只有 `meridian-up.sh` 变化，全部读回一致，引导以完成结束。
- 采用上联 MTU 建议值（2026-11-15，主会话在面板里执行）：面板对上联 MTU 为 1472 的那台节点的三条链路给出 1408 的建议，采用后四台相关节点变为待下发；预检的变更列表写明"MTU 1420 → 1408（就地调整，不重建接口、不断开隧道）"并给出 `tunnel_mtu_drift` 告警；四台下发后读回一致，该节点上三条隧道运行中的 MTU 为 1408、握手时间是新的（隧道没有中断）；之后面板不再有待采用的建议。从网关经该出口发不允许分片的包：1408 字节通过，1412 字节收到"需要分片（mtu = 1408）"的回应——采用之前这种包是被静默丢弃的。
- 解锁检测（真实平台，2026-11-15）：Netflix 在美国出口上判为可用，证据是页面的 requestCountry；香港、日本、台湾出口上 URL 前缀与 requestCountry 一致。Disney+、YouTube Premium 在五个出口上判为可用。
- 设备连接日志：真实网关上能按设备读到一台真实设备的连接记录和汇总（去向、结束方式、双向字节、MAC），名字记录关闭时记录里没有名字；`sniff_resyn` 计数器在真实流量里有增长，没有出现 `mark_missing` / `unknown_mark`。记录条数还很少，保留上限、清空、名字记录开关、服务被强制杀死后的提示都**没有在真实网关上执行过**。
- 仍**未验证**：出口上游解析器在真实服务商上的效果（含按出口单独设置）；应用自带的 HTTP 解析请求在修复后是否恢复（安装后还没有观察到这类连接）；出口经 Mesh 腿承载时的实际效果。

### 设备连接日志（代码级回归；没有在真实网关上执行过）

- `go test ./internal/sniff -run 'Journal|ParseArgsJournal'`（含 `-race`，伪时钟）：条数上限（1000 条进上限 100：盘上从不超过，最新的保留，查询最多 100 条）；时间上限（按 1 小时跨度换段；24 小时以前的不显示；写入和定时清理删除过期段，唯一的活动段整段过期时也删）；字节上限（1 MiB 上限下灌 20000 条最长字段的记录，每 500 条检查盘上文件合计加每个文件 4 KiB 余量不超过上限、段数不超过 32）；重启后记录还在、`id` 接着编号；末尾半行在打开时切掉、旧段里的坏行跳过、之后写入的每行都能解析；清空删掉全部文件、之后照常写；目录 0700（原来 0755 的也改回）、文件 0600；每个字段的字节上限和控制字符；写入方卡住时 1000 次 `Add` 在 0.5 秒内返回、丢弃被计数、`finish` 不阻塞；关闭名字记录时一个名字都不写，开着记录的名字在关闭后重开时被删掉（文件字节里查不到）；按设备、去向、结果类别、`failed`、`name_unresolved`、时间、名字文本筛选，游标翻页，非法参数拒绝；按设备汇总；状态套接字上的三个请求（参数校验、未知参数、清空不带参数、没有日志时 404）；这三个请求同样只回答 uid 0（`TestJournalStatusRootOnly`，伪造对端 uid）；`--journal-dir` 只接受规范的绝对路径。
- `go test ./internal/hostexec -run 'AgentSniffJournal|RollbackSniffCleansJournal'`：宿主代理只发三个固定请求，参数先校验，非法请求（未知字段、坏地址、目标里带分号、超大 `limit`、汇总带别的字段、清空带参数）返回 400 且没有一个到达转发服务；没有套接字 / 没有日志分别说明；需要口令；读日志不运行任何命令；移除转发服务时在删除账号之后 `systemctl clean --what=state meridian-sniff.service`，失败不让移除失败。
- `go test ./internal/api -run 'SniffJournal|SniffDeviceLabels'`：口令（五个接口都 401）；翻页和筛选透传；未知和非法参数 400；汇总；清空只在 `{"confirm": true}` 时执行；关闭名字记录时任何回答里都没有名字、按名字搜索被拒；开启时可搜索；备注名的增改删、非法地址和非法备注拒绝、IPv6 地址经转义的路径；备注名不在拓扑里；`TestSniffJournalNeverLeaves`：读过日志、设过备注之后，演示用到的所有读取接口、只读 POST、`POST /api/compile`、存储的拓扑和面板日志里都查不到日志内容（名字、规则 id、备注）。
- `go test ./internal/compile -run 'SniffJournalDir|SniffSpecRender|SniffUnitLayout'`、`go test ./cmd/meridian -run SniffVerify`、`go test ./internal/verify`：单元的 `StateDirectory=meridian-sniff`、`StateDirectoryMode=0700`、`--journal-dir /var/lib/meridian-sniff`，没有 `ReadWritePaths` 等别的可写路径；网关验收脚本里的 `sniff_journal_dir` 检查（`bash -n`）；嗅探关闭时没有任何日志相关内容；`deploy/verify-sniff-systemd.sh` 新增 `journal_dir`（临时 StateDirectory 0700、属临时 uid）和 `journal_other`（nobody 列不出目录），清理时删除临时目录。
- `web/src/sniff_journal.test.tsx`：按需读取；设备列表（备注、MAC、IPv6）；范围说明（不含 UDP / QUIC、DNS 查询）；设备详情（按设备查询、「未记录名字」、名字搜索不可用、名字解析不到的说明、翻页）；开启名字时显示和搜索；备注保存；清空先确认、只发 `{"confirm": true}`；切换名字记录时保存前弹出说明（开启 / 关闭两种文字）；手机宽度下两张表都是卡片、没有横向溢出；没有日志时的说明。表格在宽度预算内。
- 演示数据：`MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1` 重新生成了 `web/src/demo/generated/healthy.json`、`unavailable.json`（新增日志读取的回答）。
- 连接结果（一条连接一条最终记录，`internal/sniff/relay_test.go`，回环上的合成连接和进程内的假上游，`go test -race ./internal/sniff`）：`TestRelayResults` 逐一构造上游在回应前重置（`relay_failed`、`upstream_reset`、`read_reset`）、回应后重置（`ok`）、客户端回应后重置（`ok`、`client_reset`）、客户端在回应前重置（`no_response`）、客户端正常关闭、上游正常关闭、上游不回应就关闭（`no_response`）、客户端什么都没发就离开（`client_closed`）、上游读出错（`upstream_error`、`read_no_route`）、写首包出错（`write_denied`），并核对内存记录、日志、计数器 `result_*` / `end_*`、各目标统计、按设备汇总和「全部失败」筛选对每条连接给出同一个结果、每条只算一次（日志行数等于连接数）；`TestRelayIdleTimeout`（空闲超时：没有回应是 `no_response`，有过回应是 `ok`）；`TestDialFailureClasses`（拒绝、超时、网络不可达、没有路由、重置、地址族不可用、本机拒绝、其它；记下最后尝试的地址）；`TestRelayShutdownAndActiveView`（正在转发的连接只在活动视图、日志第一页和汇总的 `active` 里，不进任何计数；`Close` 把它们以 `shutdown` 写进各处）；`TestJournalUncleanStop`（按被 `SIGKILL` 时的磁盘状态重开：仍打开的那条没有记录、也没有被记成成功，报告上次没有正常退出和当时的连接数；正常关闭不报告；清空后不再报告）；`TestLegacyOKIsEndedUnknown`（上一版的 `ok` 记录归入「结束情况未知」）；`TestRelayNamesOff`（不记录名字时活动视图、内存记录和日志文件里都没有名字）；`TestRelayCountedOnceInBounds`（条数上限按连接计）。`web/src/sniff_journal.test.tsx` 另有：结果列显示结束方式和原因、图例、「正在转发」、设备的失败数不含客户端关闭和拒绝、上次没有正常退出的提示、连接失败的原因和最后尝试的地址。
- [ ] 实机（主会话，未执行）：装上这一版后用一台设备正常浏览，日志里成功的记录带 `end` 和双向字节；在面板里看到长连接（例如视频）在「正在转发」里，结束后成为一条记录；`systemctl restart meridian-sniff` 后那时开着的连接以「服务停止时中断」出现；`systemctl kill -s KILL meridian-sniff` 后重新启动，日志上方出现「上次没有正常退出」的提示。真实流量下各结果类别的比例（特别是 `no_response` 是否把正常的客户端放弃算多了）是**未验证**。
- [ ] 实机（主会话，未执行）：装上这一版（转发服务会重启一次），`meridian-verify.sh` 里 `PASS sniff_journal_dir`；`sudo bash deploy/verify-sniff-systemd.sh` 里 `journal_dir`、`journal_other` 通过；面板里打开设备连接日志，用一台设备访问几个站点后能在它名下看到记录；`systemctl restart meridian-sniff` 之后记录还在；`sudo -u nobody ls /var/lib/meridian-sniff` 被拒绝；「清空日志」之后目录里没有段文件；开启再关闭名字记录并安装后，`sudo grep -c '"name"' /var/lib/meridian-sniff/*.jsonl` 为 0；关闭嗅探并安装后 `/var/lib/meridian-sniff` 不存在。在这些执行之前，日志在真实网关上的行为（包括 `systemctl clean` 在 Debian 13 / systemd 257 上的效果、真实流量下的写入速率和丢弃数）都是**未验证**。

### 网关解析日志（设置 `dns_log`；自动化回归，加本机 Docker 里同一版本解析器的无网络临时容器；真实网关上的安装未执行）

证据分三种，分开写：

**一、自动化回归（本机 `go test`，不需要解析器二进制）。**

- `go test ./internal/dnsjournal`（含 `-race`，伪时钟）。解析：`TestParseObservedLines`（2026-11-15 在网关上观察到的四行：A、AAAA、空结果 3 ms、空结果 2005 ms 及其组名）、`TestParseUnobservedShapes`（多个应答的三种分隔、应答里混有非地址、IPv6 / IPv4 映射 / 带方括号和端口的客户端、大写和末尾的点、超过 253 字节的名字被截断、名字里自带一段完整的「type…result」也改不了本行的类型和组、控制字符不进记录）、`TestParseBadLines`（十二种坏行都只返回同一个错误）、`TestClassify`、`TestReadRotatedGzip`（gzip 轮转文件读回同样的行；截断的压缩包给出能读的部分；有上限；符号链接不跟随）。结构化日志：条数上限（1000 条进上限 100，盘上从不超过）、时间上限（24 小时以前的不显示、过期段被删、唯一的段整段过期也删）、字节上限（512 KiB 上限下灌 20000 条最长字段的记录，每 500 条核对文件合计加每个文件 4 KiB 不超过上限、段数不超过 32）、重启后记录还在且 id 接着编号、末尾半行被切掉、坏行跳过、目录 0700 / 文件 0600（被改成别的也改回）、清空、写入方卡住时 5000 次 `Add` 在 2 秒内返回且「已写 + 已丢 = 5000」、每个字段的字节上限、筛选（设备含 IPv4 映射写法、MAC、三种结果和 `no_answer_any`、组、时间、名字文本）和游标翻页、十三种非法查询和未知 / 重复参数拒绝、按设备汇总（同一地址两个 MAC、无 MAC 条数、最常问的名字）及其上限（设备 128、组 16、名字 10、回答小于 1 MiB）、`TestSplitBudget`（32 MiB = 8 + 2 + 22；`audit-size` × (1 + `audit-num`) 按五成超出算仍在审计一侧的份额内）。读取服务：`TestTailFollowsObservedLines`、`TestTailEstablishesZone`（+8、−5、+5:30、0 四种容器时区都换算回真实时间；行与写入时间相差太远时用读到的时间并标 `time_approx`）、`TestTailPartialBadAndLongLines`、`TestTailSurvivesRotation`（改名并压缩之后旧文件剩下的行和新文件的行各一次；审计文件暂时不存在时等待）、`TestTailSurvivesTruncation`、`TestTailRestartKeepsPosition`、`TestTailRestartCatchesUpFromGzip`（停机期间轮转：没读过的行从 gzip 里补上、读过的不重复、补读的行没有 MAC；没有读取位置的第一次启动不翻旧的轮转文件）、`TestTailKeepsModesAndRawBudget`（目录改回 0700、0640 的文件改回 0600、FIFO 和符号链接被删；审计一侧超出份额时先删最旧的轮转副本，审计文件自己超出时被截断且仍是同一个文件；50 轮洪水里每一轮之后都不超过份额）、`TestTailFloodIsBounded`（2 MiB 的积压一次只读 256 KiB，写入方卡住时队列满、其余丢弃并计数，「已写 + 已丢 = 已解析」）、`TestTailGivesUpOversizedRotatedRemainder`、`TestTailClear`。审计一侧的时间上限（伪时钟）：`TestTailRawAgeLowTraffic`（每小时一条查询连续 80 小时、从不轮转：每一轮之后 `raw/` 里没有超过 24 小时的行，80 条各一次、不丢不重，截断 3 次，文件始终是同一个 0600 的普通文件；时间戳定不出时区、文件一直有写入时靠「打开或上次为空起满 24 小时」；上限取配置的值）、`TestTailRawAgeIdle`（写完之后 23 小时还在、25 小时清空；读取服务停着的时候写入的一行，30 小时后启动先读出来再清空；截断后不经正常退出就重启，新内容比旧偏移长也从头读、一条不少；定不出时区且末尾有半行时靠文件的最后写入时间）、`TestTailRawAgeAcrossRestarts`（每 10 小时重启一次，交替正常退出和直接停止：第 25 小时仍然清空——靠第一行的时间戳，不需要一直运行；40 条各一次）、`TestTailRawAgeRotatedCopies`（第一行过期而最后写入未过期的副本被删；读不出内容的副本、别的名字的文件、修改时间在未来的文件各在最后写入或第一次见到之后满 24 小时被删、之前不删；停机期间轮转出的旧副本先补读再删）、`TestTailRawAgeTruncatesOnlyAfterIngest`（三倍于一次读取量的过期积压：读完之前文件不变，清空时行数恰好是全部；有正在写的半行时不清空，补完之后该行有记录、然后清空；长度变了、换了文件、符号链接、FIFO 都不截断，FIFO 不阻塞）。审计文件：`TestPrepareAndCheckSink`（不存在 / 0640 / 目录 0755 / FIFO / 符号链接 / 目录本身是符号链接 / 审计路径是目录 / 属主不对，各自被拒绝或被换成 0600 的普通文件，符号链接指向的文件不被碰）、`TestPurgeData`。进程：`TestParseArgs`（含 `--prepare` 只准备审计文件就退出）、`TestDaemonEndToEnd`（审计行 → 记录 → 状态套接字上的四个请求；非法参数 400、方法不对 405、清空不接受参数；健康读数里没有名字和地址；重启后不重复；清空之后两个目录的文件里都查不到名字；每个文件 0600、每个目录 0700；进程日志里没有名字和地址）、`TestDaemonRawFollowsMaxAge`（`--max-age` 传到审计一侧：记录过期之后那个名字不在这个功能的任何文件里，重启后接着读）、`TestDaemonWithoutJournal`、`TestDaemonStatusRootOnly`（伪造对端 uid：只有 0 得到回答）。门槛：`TestGate`（七种不可用各自的代码和原因；节点制品的版本 1.2026.08.05-0921 **不**被接受；本机记录只对同一个镜像 id 有效；`smartdns -v` 输出的解析；审计指令的识别）。`TestAuditCheckScript`：`deploy/verify-smartdns.sh --audit-check` 的行模式与解析器对同一批样本结论一致、记录文件就是门槛读的那个、每个 `docker run` 都带 `--network none`、不拉取、不重启、不碰运行中的解析器、只有合成名字和文档地址、冻结之前先确认是自己的 loop 挂载、`bash -n`、错误参数退出码 2。
- 清空如实报告（`go test -race ./internal/dnsjournal -run 'Clear|PurgeData|BoundKeeps'`，合成的文件系统故障：测试钩子让清空的某一次列目录 / 看文件 / 删除 / 截断返回带路径的系统错误，不依赖 chmod，root 下同样有效；没有连接任何主机）。
  - 结构化日志：`TestJournalClearKeepsWhatItCouldNotDelete`（四段里一段删不掉：报告删掉 25 条、留下 1 段 10 条和一条 `journal / remove / permission`，报告里没有路径、文件名和系统报错；盘上和索引里都只剩那一段，仍能查到；之后写入照常、id 接着编；故障还在时再清一次仍报告残留；故障消失后的重试清干净，标记文件也没了）、`TestJournalClearResidueSurvivesRestart`（全部删不掉 → 重启两次，每次都认出同样的 3 段残留和清空时间，清空之后写的那条不算残留；每分钟的清理不动清空留下的残留；重试成功；id 不回退）、`TestJournalBoundKeepsUndeletableSegment`（上限到期时删除失败：分段留在索引里、盘上没有索引之外的文件、不算清空残留；故障消失后清理把它删掉）、`TestJournalClearTakesTheQueue`（写入方卡住时排队的 50 条不会在清空之后写进日志）。
  - 审计一侧：`TestTailClearCopyNotDeleted`（副本删不掉：不算成功，残留计数正确；副本里没读过的行在下一轮和重启后的补读里都不回来，新副本里清空之后的行照常补读；重试清干净）、`TestTailClearAuditNotTruncated`（截断失败，时区已知和未知各一遍：文件不变、从当时的末尾接着读、重启后也是、被解析器轮转走之后旧行仍不回来；重试后清空）、`TestTailClearUnreadNotCaughtUp`（截断失败后立刻重启并被轮转压缩：清空之前没读过的行不回来）、`TestTailClearRetryResetsOffset`（重试成功后从文件开头读，不沿用上一次留下的偏移）、`TestTailClearCannotListOrLook`（列目录失败、看文件失败：不算成功并标 `unknown`，审计文件按固定路径照样清空；审计文件本身看不了时从末尾接着读）、`TestTailClearResidueExpires`（残留随 24 小时上限删除，提示随之消失）。
  - 读取服务整体：`TestDaemonClearPartialThenRestartThenRetry`（分段、副本、审计文件同时清不掉：回答 `complete: false`、残留和三条原因，回答里没有名字、地址、路径和系统报错；记录仍能查到、健康读数带残留；没截断的审计文件不被重读、新行只读一次；带着故障重启后残留仍被认出；故障消失后重试完成，目录里不再有任何名字，日志里没有内容）、`TestDaemonClearWhileWriting`（「解析器」持续追加、读取不停、其间 6 次清空且其中两次截断失败，`-race`：没有一行被记两次，顺序不乱，最后一次清空之前写的行不在日志里，之后的行读得到）、`TestDaemonClearWithoutJournal`、`TestPurgeDataReportsWhatIsLeft`（宿主代理的直接删除：分段 / 副本 / 审计文件清不掉、列目录失败都如实报告；之后启动的读取服务认出残留、不读入没清掉的审计内容，它的清空完成）。
  - 宿主代理（`go test ./internal/hostexec -run 'DNSJournalClear'`）：`TestDNSJournalClearWithoutReaderIncomplete`（`clear_incomplete`，文字里有数量和原因、没有路径；状态读取仍显示数据；重试完成）、`TestDNSJournalClearThroughReaderIncomplete`（读取服务的未完成回答原样带回；回答里没有 `complete` 的旧版读取服务是 `clear_unconfirmed`，不当作成功）。
  - 面板（`go test ./internal/api -run 'DNSLogClearIncomplete'`）：未完成是 500 `dns_log_clear_incomplete`，带 `complete: false`、残留和原因，回答、状态和面板日志里都没有名字、地址、路径；记录仍能读到；`GET /api/dns-log` 带 `runtime.clear_residual`；重试 200 `complete: true`；无法确认和通道失败是 503；关闭后的自动清空未完成时警告写明还留着什么。
  - 界面（`web/src/log_pages.test.tsx`）：清空未完成时不显示成功，提示里有残留数量、原因和「重试清空」，列表重新读取并仍显示留下的记录；重试时通道失败提示仍在；重试完成后提示消失；提示可以只来自网关状态（刷新 / 读取服务重启之后）；解析日志关闭而有残留时清空未完成，提示和「清空网关上留下的数据」都保留。
  - 没有验证的：真实文件系统上的只读挂载、不可变属性或磁盘错误（这里全是注入的错误）；真实网关上没有执行过任何清空。
- `go test ./internal/compile -run 'DNSLog|DNSJournal'`：关闭（未设置或设为关）时十个拓扑的编译结果逐字节相同、任何文件里都没有相关内容；打开时恰好新增一个文件、改两个文件，`smartdns.conf` 只多出注释和四条指令、别的行不变，验收脚本只多出那一段；单元的每一行（没有 capability、没有网络、`ExecStartPre` 在 `ExecStart` 之前准备审计文件、参数能被读取服务自己的解析函数接受、默认上限 24 小时 / 50000 条 / 32 MiB）；Compose 里解析器只有这一个可写挂载、看不到 `journal/`；`install.sh` 以 0700 建目录；验收脚本 `bash -n`，并把其中的 `dns_log_sink` 检查拿出来对着准备好的目录实际执行（0600 通过、0640 通过、0644 / 符号链接 / FIFO / 目录 0755 失败；本机是 BSD 的 `stat` / `find`，测试里用等价写法垫了一层，网关上的 GNU 写法没有在本机执行）；配置里出现的每个组名都有面板的名字。
- `go test ./internal/hostexec -run 'DNSJournal|GuardsResolverAudit|RollbackOfReader|DeployWiring'`：状态读取只运行三条固定的 docker 命令（逐字核对），各种门槛结论（版本没核对过、读不到、没有可写挂载、只读挂载、从别的宿主路径挂载、容器没运行、没有容器、宿主单元；含本机记录对同一镜像有效、对别的镜像无效；宿主单元时不进容器执行任何东西）；四个请求都要口令；十二种非法请求 400 且没有一个到达读取服务、也没有运行任何命令；回答原样转交；旧版宿主代理（没有这些请求）被识别；没有读取服务时清空只删两个固定目录里的文件、目录保留、旁边的目录不碰，读取服务的单元在运行却没有套接字时不删，配置仍开着审计时审计文件被清空而不是删除；`activate`：没有审计指令时与以前逐条相同，有审计指令时顺序是「重启读取服务 → 读版本 → 重启解析器 → 问一个固定问题」，十二种不满足（版本没核对过、读不到、没有可写挂载、宿主单元、没有解析器、审计文件不是固定路径、目录不存在、文件不存在、目录 0755、文件 0644、符号链接、FIFO）都**没有重启解析器**，解析器重启后不应答时安装失败；移除读取服务的单元不删数据。
- `go test ./internal/api -run 'DNSLog|LogRelated'`：开关默认关；没有宿主代理、宿主代理是旧版、读取出错、版本没核对过时都打不开且不保存，原因在回答里；打开必须带 `acknowledge`；关闭不需要门槛，关闭后存储的拓扑里没有这个字段；七个接口都要口令；筛选和翻页透传，十一种非法查询在问宿主代理之前拒绝；汇总带共用的备注名；清空只在 `{"confirm": true}` 时执行；双向跳转（同一 MAC、另一个 MAC 被排除并计数、没有 MAC 的保留、不带 MAC 时只按地址并标明、时间窗和上限、参数校验）；`TestDNSLogInstallLifecycle`（打开：预检显示两个改动的文件和一个新增的单元及说明，安装前宿主不变；审阅之后门槛变为不满足时安装被拒绝、宿主不变；安装后配置带审计指令；关闭：预检说明，取消后仍在记录、没有清空；安装失败并补偿后仍在记录、没有清空；安装成功后配置与打开之前逐字节相同、单元文件没了、**恰好清空一次**；之后的安装不再清空；清空失败时安装成功并带警告；运行时回滚到开着的快照不清空，再回到关着的快照才清空）；`TestDNSLogTopologyContract`（整份保存、导入、草稿都不能改开关；省略 / `null` / 相同则保留；没有受管网关时打不开）；`TestDNSLogNeverLeaves`。
- `go test ./cmd/meridian`、`web/src/topology_contract.test.tsx`：宿主代理沙箱的副本与单元文件一致；面板的整份保存不带 `settings.dns_log`。

**二、同一版本解析器的真实二进制，本机 Docker 的无网络临时容器**（2026-11-15，开发工作站；镜像是本机已有的、报告 `smartdns 1.2026.11.09-1240` 的 amd64 镜像，在 arm64 上仿真运行；没有连接任何主机，没有拉取）。这些只说明这个版本在这种环境里的行为：

- （工作站）`bash deploy/verify-smartdns.sh --audit-check <镜像>`：格式七项、轮转三项、截断两项、写满一项、只读目录、目录不存在全部 `OK`；`frozen` **跳过**（需要 Linux root 和 `fsfreeze`），所以结论是 `meridian-smartdns-audit-verify-incomplete`、退出码 3、没有记录；FIFO 一项报告「这里没有卡住」。
- （真实网关，2026-11-15，主会话以 root 执行，不是本仓库的开发或 QA）`sudo bash deploy/verify-smartdns.sh --audit-check`，镜像取自网关上的 `meridian-smartdns` 容器，没有带 `--record`：每一项都 `OK`，包括 `frozen`——格式（10 行全部符合；应答地址；AAAA 为类型 28；多个应答同一行、逗号加空格分隔；无应答时结果为空；被 `address` 规则拦下的名字不写审计行；IPv6 客户端写成地址）、`INFO mode` 640、轮转（1 个 `audit.log-YYYYMMDD-HHMMSS.gz`，有效 gzip，222 行同一格式）、截断（照常应答，从文件开头接着写）、写满（200/200）、冻结（60/60，1 秒内；解冻后 63 行）、只读目录、目录不存在（之后是 0750 的目录）；`INFO fifo`：FIFO **没有**让解析器停止应答。退出码 0，结论 `meridian-smartdns-audit-verify-ok version=1.2026.11.09-1240 image=sha256:<镜像 id>`；因为没有 `--record`，本机记录文件没有写入（这个版本本来就在内置清单里）。
- `TestSmartDNSAuditRealBinary`（见下面的命令；在该镜像的容器里以 `MERIDIAN_SMARTDNS_BIN=/usr/sbin/smartdns` 运行交叉编译的测试程序，三次都通过）：编译器渲染的四条审计指令被这个二进制接受；读取服务把每一行都解析出来（0 坏行）；A、AAAA、三个应答、空结果、长名字各如预期，被规则拦下的名字没有记录；`audit-size 32k` 下 900 次查询跨一到两次真实轮转恰好 900 条记录。
- 同一个容器里以 Linux 程序运行 `internal/dnsjournal` 的全部测试和 `internal/hostexec` 里解析日志的测试：通过（root，FIFO、`O_NOFOLLOW` 等在 Linux 上的行为）。

**三、真实二进制测试的命令**（Linux；不设变量时跳过，输出里写明「没有检查」）：

```
MERIDIAN_SMARTDNS_BIN=/path/to/smartdns go test ./internal/compile -run TestSmartDNSAuditRealBinary -v
```

它**只覆盖变量指向的那个二进制**的审计行格式、轮转和读取服务对它的解析——指向面板下发给节点的固定制品（1.2026.08.05-0921）时就是那个制品，测试输出里写出版本以及它是否在网关的允许清单里。它不说明网关容器里的版本，也不检查写满或卡住的文件系统是否拖住解析（那是 `--audit-check` 的事）。用节点制品执行过一次（2026-11-15，开发工作站 Docker 的无网络容器；`smartdns-aarch64`，SHA-256 与 `artifacts.lock` 的固定值相同，报告 `smartdns 1.2026.08.05-0921 (Release48.4)`）：通过，格式与网关镜像的版本相同、900 次查询跨一次轮转 900 条记录。这只说明该制品的格式；它不在允许清单里，门槛不接受它，网关的行为也不从它推断。x86_64 的制品没有执行。

**未验证（除标了已执行的那一项以外，主会话在真实网关上执行之前，下面每一项都是未验证）：**

- [x] 真实网关上 `sudo bash deploy/verify-smartdns.sh --audit-check` 全部通过（含 `frozen`）：2026-11-15 已执行，见上面「真实网关」一条。冻结更久、解析器内存缓冲写满之后的行为仍然没有观察过。
- [ ] 用新的 Compose 文件重建解析器容器后 `GET /api/dns-log` 的门槛为可用；没有重建时为 `no_mount`。
- [ ] 打开 → 预检 → 安装：预检里是三处差异；安装步骤里有 `dns audit gate`、`dns audit sink`、`resolver answers after restart`；`meridian-verify.sh` 里 `dns_log_*` 各项 `PASS`；用一台设备查询几个名字后能在它名下看到记录，MAC 与连接日志一致；`sudo -u nobody ls /var/lib/meridian-dnslog` 被拒绝。
- [ ] 解析中断的实际时长；真实流量下的写入速率、丢弃数、`raw_bytes` 的实际大小、`audit-size 2048k` 时的超出量；读取服务的 CPU / 内存占用。
- [ ] 容器时区与宿主不同的真实网关上记录时间正确（`zone_offset_s`）。
- [ ] 审计一侧的时间上限在真实网关上的效果：查询少、超过 24 小时不轮转的网关上 `raw_age_truncated` 增加、审计文件被截断后解析器接着写、读取服务接着读且不丢不重。目前的依据只有伪时钟下的自动化测试，加上此前对真实解析器的观察（别的进程截断审计文件之后它照常应答并从文件开头接着写）；读取服务自己按时间截断这条路径**没有**对着真实解析器执行过。
- [ ] 关闭 → 预检 → 安装之后 `/var/lib/meridian-dnslog` 下没有数据文件；取消预检时仍在记录。
- 关于 FIFO：早先一次手工试验（对审计路径是 FIFO 的容器跑 3000 次查询，没有在时限内跑完）曾被当成「解析器卡住」，但当时没有确认查询是否真的没有应答，**没有结论**；脚本化的核对在真实网关和工作站上都发现解析器照常应答。审计路径仍然只会是普通文件：特殊文件在那里没有正当用途，它的行为也不是可以依赖的东西。别的 SmartDNS 版本对 FIFO 的行为没有观察过。
- [ ] 启用 userns-remap 的 Docker、宿主 `smartdns.service`、其它 SmartDNS 版本：没有观察过；前两种情况门槛或权限会让功能不可用或读不到文件，没有实测。
- [ ] 面板页面（导航入口、列表、筛选、跳转）只有 jsdom 里的小范围渲染测试和演示数据上的渲染测试（见下面「三种日志的演示、跨功能回归与文档」），没有在真实浏览器里执行。
- 真实网关上的现状（主会话提供的事实，2026-11-16）：面板已升级到带解析日志页面的版本（提交 `52a125b`），解析器容器已用新的 Compose 文件重建、带可写的审计挂载，重建后解析正常应答。解析日志**没有打开**，带读取服务的网关安装**没有执行**，所以上面未勾选的各项仍是未验证。

### 链路日志（没有开关；自动化回归，加本机 Docker 里的命名空间测试；真实网关上的安装和真实故障未验证）

证据分三种，分开写：

**一、自动化回归（本机 `go test`）。**

- `go test ./internal/linkjournal`（`-race` 同样通过）：
  - 读数到事件（假时钟）：基线不产生事件（`TestBaselineProducesNoEvent`）；变化与时长（`TestTransitionAndDurations`）；重启后检查点一致不产生事件、短暂重启期间真的变了记一条（`TestRestartWithCheckpoint`）；长时间停止记一条空窗、时长不跨空窗、没变的对象重新计时（`TestRestartAfterLongStopIsAGap`）；没有检查点时重启是基线（`TestRestartWithoutCheckpointIsBaseline`）；事件与检查点之间崩溃不重复记（`TestCrashBetweenEventAndCheckpoint`）；单个对象的空窗（`TestGapOfOneObject`）；采集停顿与时钟回拨不产生负时长（`TestStallAndClockStep`）。
  - 抖动：前 4 次单独记、其余合并成一条带次数和首末时间的记录，文字写明不是连续中断，合并中可见，结束后的下一次变化时长正确（`TestFlapMerging`）；只有一次变化的合并记录按普通事件写（`TestFlapWithOneChangeIsAPlainEvent`）；一直不安静时每小时一条、未结束的记录跨重启保留（`TestFlapNeverQuietAndRestart`）；每小时写入上限、丢弃计数、状态不丢（`TestWriteBudget`）。
  - 上限：300 个对象在假时钟上变化 100 小时，每一步条数、目录字节数（按文件系统块计）、分段数都在上限内（`TestBoundsUnderFlood`）；默认上限下写 24000 条最大的事件，留下 19904 条、约 13.3 MiB（`TestDefaultBoundsWorstCase`）；小预算下字节上限先到（`TestByteBoundDecides`）；过期事件不返回并从磁盘删除，两次清理之间查询自己过滤（`TestMaxAge`、`TestMaxAgeBetweenTrims`）；单条不超过 1024 字节、检查点不超过 256 KiB、对象数上限（`TestEventLineBound`、`TestObjectBound`）；预算拆分（`TestSplitBudget`）。
  - 清空后下一次采集是基线（`TestClear`）；目录 0700、文件 0600、符号链接的目录被拒绝、符号链接的文件不读不写（`TestPermissionsAndLinks`）；末行写了一半只丢那一行（`TestTornTail`）；读不了的分段只丢它自己的事件，日志照常打开（`TestUnreadableSegmentDoesNotStopTheJournal`）；筛选、时间范围、翻页每条恰好一次、参数校验（`TestQueryFiltersAndPaging`、`TestQueryValidation`）；对象清单更新（`TestSetDigest`）；并发（`TestConcurrentUse`）。
  - 各来源的合成序列：有备用枢纽时主路径 → 备用枢纽 → 全部不通 → 切回、切换判断中不产生事件（`TestSourceUpstreamDualHub`）；故障切换服务心跳停止后来源记为读不到、对象变为未知、恢复后发现的变化带空窗标记，文件缺失 / 格式不对 / 格式与拓扑不符都是读取失败（`TestSourceUpstreamHeartbeatStops`）；分担里中继被剔除、恢复、降权、换腿、路由表跟随的中继变化、切到备用枢纽、勉强承载、控制器回退写进依据（`TestSourceRelaySharing`）；单中继拓扑从路由表读承载的腿（`TestSourceRouteTableSingle`）；握手超时恰好在超过阈值后记下、恢复、从未握手、接口消失，关闭保活的隧道不读，`wg` 本身失败不编造状态（`TestSourceTunnelHandshake`）；WSS 承载连接 / 断开 / 停止 / 仅运行（`TestSourceWSSCarrier`）；外部出口自检失败三小时再恢复只有两条事件，依据写明是网关自检、带解析器最后一次有回答的时间、不断言代理不通（`TestSourceSelfCheckExternalExit`）；自检没来得及检查、结果里没有该目标、未检查都不算失败，自检结果过旧时来源记为读不到（`TestSourceSelfCheckInconclusive`）；慢来源每三轮读一次、单次读取失败不产生事件（`TestCadenceAndDebounce`）。
  - 固定命令：采集服务执行过的每条命令都是三种固定形式之一；`mra`、`mmesh`、`eth0`、带空格或选项的名字、其它单元在执行前被拒绝；程序表只有三个绝对路径程序（`TestFixedArgumentLists`）。对象清单的校验和未知字段拒绝（`TestConfigValidation`）；记录、握手、路由输出的解析（`TestParseUpstreamRecord`、`TestParseHandshakesAndRoute`）；来源清单每类齐全、外部出口一行不写成已确认的远端故障、承载节点健康检查列在范围外（`TestInventory`）；状态目录（`TestKindsCatalogue`）；状态套接字的四个请求、其它方法和参数被拒绝、清空后是基线（`TestStatusHandler`）；回答不超过状态套接字的上限（`TestAnswerSizes`）；命令行和对象清单读取、没有有效清单时不创建状态目录（`TestParseArgsAndLoadConfig`）。
  - 变异检查（手工改一处再跑、之后恢复）：忽略空窗、取消抖动合并、取消写入上限、取消崩溃后的修正、把没来得及检查算作失败、握手阈值放大十倍、取消条数上限、取消字节上限、查询不过滤过期事件、基线也产生事件、时长跨过空窗——每一种都有测试失败。
- `go test ./internal/hostexec -run 'LinkJournal|UpstreamParsers'`：四个固定请求都要口令；参数在代理里校验，被拒绝的请求既没有到达采集服务也没有执行任何命令；整个功能代理只执行 `systemctl is-active meridian-link-journal.service`；清空交给采集服务；旧版代理（没有这些请求）被识别；采集服务没有运行时代理不碰它的目录；采集服务可读的接口名和单元名范围（不含 `mra`、`mmesh`、非客户端单元）；采集服务与代理对上游记录的两个解析器在每种合法格式和畸形输入上结论一致（`TestUpstreamParsersAgree`；采集服务不读中继的测量字段，所以只有「丢包越界」一种输入仅代理拒绝）。
- `go test ./internal/compile -run 'LinkJournal|Golden|DecisionChange|VerifyScript'`：六种示例拓扑、嗅探开和关，网关都有单元和对象清单，清单里的隧道恰是网关的 WireGuard 文件（不含 `mra`）、WSS 单元恰是网关的 wstunnel 客户端单元、承载路径与该拓扑的故障切换脚本一致、外部出口带承载节点；网关的其它文件和所有远端节点都不提到它（`TestLinkJournalFiles`）；解锁决定不改对象清单（`TestLinkJournalConfigIgnoresDecisions`、`TestDecisionChangeTouchesOnlyRuleFiles`）；外部出口是否有网关自己的检查（`TestLinkJournalExternals`）；单元的指令、没有 `AF_INET`、没有依赖、各包的固定路径一致、对象清单的数量上限不低于拓扑能编译出的数量（`TestLinkJournalUnit`）；验收脚本的一段：没有 systemctl 时不检查、采集服务没运行是 `WARN` 且退出码不变（`TestLinkJournalVerifyScript`）；三个 golden 文件各只变三行。
- `go test ./internal/api -run LinkLog`：范围、上限、时间参数、对象清单、各种没有数据的原因（`TestLinkLogView`）；当前状态（承载路径及时长、异常对象及时长和依据、状态未知的对象）、时间线的筛选和翻页、参数校验在到达代理之前（`TestLinkLogCurrentAndEvents`）；清空要确认（`TestLinkLogClear`）；每个接口都要面板口令（`TestLinkLogAuth`）；预检不往宿主写东西、宿主程序过旧时阻断且什么都没写、安装写入单元和清单并成为清单单元、旧安装升级后状态为有待安装而宿主上没有任何东西、预检恰好列出两个新增文件和一条说明、安装后不再提示（`TestLinkLogInstallLifecycle`）；日志内容不进入任何别的接口、存储、宿主文件和面板日志（`TestLinkLogNeverLeaves`）。

**二、命名空间测试（root、Linux、opt-in；2026-11-15 在开发机的 Docker 特权容器里通过，没有在真实网关的内核上执行）。**

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile
sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^(TestNetnsLinkJournalHandshake|TestNetnsLinkJournalBackupSwitch)$' -test.v
```

两个测试只在自己建的命名空间（`mlj…`，以及双枢纽实验室的 `mrd…`）和测试的临时目录里建接口、加载 nft、改 sysctl、写文件；不建、不改、不读宿主命名空间的接口、路由、规则集、sysctl、单元，不使用任何固定的套接字或状态路径（veth 直接建在两个命名空间里，不经过宿主命名空间；采集服务的程序经 `ip netns exec` 在命名空间里执行，`systemctl` 在实验室里被拒绝执行）。缺环境变量、不是 root、缺工具或内核建不了 WireGuard 接口时 `--- SKIP` 并写明「NOT RUN」，**跳过不是通过**。

- `TestNetnsLinkJournalHandshake`（需要 `ip`、`wg`、`ping` 和能建 WireGuard 接口的内核；约 16 秒）：两个命名空间之间一条内核 WireGuard 隧道，网关一侧的接口叫 `m00`，采集服务像在网关上一样读它（`wg show m00 latest-handshakes`、`ip -4 -o route show table 102`）。H1 握手完成后第一次采集是基线、没有事件；H2 切断底层链路，握手时间超过阈值后记一条 `ok → stale`，依据是内核给出的握手时间，记录时刻在超过阈值之后 6 秒以内；H3 底层仍然切断时重建对端，握不上手，记一条 `stale → never`；H4 恢复底层并有流量，新的握手，记一条 `never → ok`；H5 关闭并从磁盘重新打开日志、换一个采集实例，状态没变，没有事件；H6 删除接口，记一条 `ok → absent`，承载路径变为「没有路由」。最后一行 `meridian-netns-link-journal-handshake-test-ok`。**阈值在这里是 10 秒**（网关上是 180 秒）：它证明的是从内核的握手时间到事件这条链，不证明 180 秒对一条健康的隧道是合适的（WireGuard 约每 120 秒续一次会话，这里没有观察那么久），也不覆盖 WSS 承载（命名空间里没有单元）。
- `TestNetnsLinkJournalBackupSwitch`（需要 `ip`、`nft`、`ping`、`bash`、`python3`；约 60 秒）：整个 `TestNetnsDualHub` 的实验室（编译出的网关故障切换脚本用真实的 ping 做决定），采集服务按**编译出的对象清单**读那个脚本写的上游记录。主路径阶段是基线、没有事件；切断中继到枢纽之后记一条 `udp → backup`（依据里是备用枢纽），此时重启采集服务不增加事件；全部不通时路径不变、记一条探测结论 `ok → down`；恢复后记 `backup → udp` 和 `down → ok`，事件里「在备用枢纽上的时长」等于两次切换之间的时间。最后一行 `meridian-netns-link-journal-backup-test-ok`。实验室的隧道是 veth、没有单元，所以清单里的隧道和 WSS 承载在这里被去掉，空窗和心跳阈值被放大（实验室的每个阶段要跑完它自己的流量检查）。为了让这个测试复用实验室，`TestNetnsDualHub` 的主体改成了带回调的 `runNetnsDualHub`（只多了四处回调），同一次运行里 `TestNetnsDualHub` 本身照常通过（约 59 秒）。
- 2026-11-15 的运行：开发机 Docker 特权容器（`--privileged --network none`，内核 6.10 linuxkit，arm64 构建的测试二进制，容器里有 `wg` 和内核 WireGuard），上面两个测试和 `TestNetnsDualHub` 全部通过；不带两个环境变量时两个测试 `--- SKIP`「NOT RUN」。日志没有存档到 `docs/evidence/`。中继分担的实验室（`TestNetnsRelaySharing`）没有接上采集服务：中继被剔除和恢复只有合成序列的回归。

**三、没有验证的（主会话或实机）。**

- [x] 用户网关的内核上运行上面的命令：主会话提供的事实——两个命名空间测试已在真实网关的内核上通过。日志没有存档到 `docs/evidence/`，执行日期没有记在这里；它证明的仍只是「从内核读数到事件」这条链（阈值在测试里是 10 秒），不是网关上已安装的采集服务。
- [ ] 升级后的第一次网关安装：预检里是两个新增文件、验收脚本一处变更和 `link_log_add` 说明；安装后 `systemctl is-active meridian-link-journal.service`、`meridian-verify.sh` 里 `link_log_*` 各项 `PASS`；`sudo -u nobody ls /var/lib/meridian-linklog` 被拒绝。
- [ ] 单元的沙箱在真实 systemd 下的行为：只有 `CAP_NET_ADMIN`、`ProtectSystem=strict`、`RestrictAddressFamilies=AF_UNIX AF_NETLINK` 时 `wg show`、`systemctl is-active`、`ip route show` 和读嗅探状态套接字是否都能工作，**没有在任何 systemd 主机上执行过**；不能工作时对应来源会显示为读不到，不影响转发。
- [ ] 真实故障与记录的对照：中继被切断、握手超时、WSS 客户端断开、外部出口不通，各自记下的时间与实际相差多少；180 秒的握手阈值在真实链路上有没有误报；采集服务的 CPU、内存和实际写入量。
- [ ] 宿主程序比面板旧时预检的阻断项在真实升级顺序里是否如预期出现。
- [ ] 面板页面（导航入口、当前状态、时间线、筛选）只有 jsdom 里的渲染测试，没有在真实浏览器里执行。演示数据里的时间线由真实的采集服务在合成来源上记下（见下面「三种日志的演示、跨功能回归与文档」）。
- 真实网关上的现状（主会话提供的事实，2026-11-16）：面板已升级，网关因此显示有待安装的变更；带采集服务的网关安装**没有执行**，采集服务没有在任何真实网关上运行过。

### 三种日志的演示、跨功能回归与文档（自动化回归；真实浏览器和带新单元的网关安装未验证）

给操作者的说明在 [logging.md](logging.md)。这一节记录收尾时增加的回归和它们能说明什么。全部在本机执行，不连接任何主机；数据都是合成的（演示局域网和文档保留地址段、RFC 7042 文档 MAC、`example` 名字、测试里随机生成的秘密）。

**逐字节回归（`go test ./internal/compile`）。**

- `TestCompileUnchangedSinceBeforeTheLogs`：五种示例拓扑（单枢纽示例、双枢纽、多中继分担、挂靠出口、外部 SOCKS 出口），嗅探开和关，对照这一轮开始之前的编译器（提交 `4824a78`；摘要是在那个提交的源码树上用同一个 `goldenDigest` 算出的，记在 `preLogCompile`）。没有出口加密上游、解析日志关闭时，去掉网关的链路日志两个文件和验收脚本里的那一段之后，每个节点的每个文件与那时逐字节相同；把解析日志明写成「关」、把每个出口的上游明写成 `builtin` 也一样；编译结果里没有审计指令、解析日志目录或凭据版本行。
- `TestExternalCarrierUnchangedWithoutRotation`：外部出口示例的承载节点上，重定向配置、两个单元和健康脚本的摘要与 `4824a78` 相同；打开解析日志、嗅探、出口上游（单独和一起）都不改变它们；编译器自己从不写版本行，配置里恰好两个占位符，别的文件不提这个凭据。「已有 SOCKS 但没有超过迁移基线」在面板一层由原有的 `TestSOCKSVersionUpgrade` 对照（旧存储升级后每个文件与没有版本这一步时逐字节相同）。
- `TestJournalsAndExitUpstreamAreIndependent`：六种拓扑 × 嗅探开关 × 三种出口上游（没有、全局 DoT 带账户、单个出口自己的 DoH）。打开解析日志只改网关的同样三个文件，网关的文件在三种上游下逐字节相同，网关以外没有一个文件变化，链路日志的对象清单在每种组合下相同。
- `TestJournalFilesCarryNamesOnly`：所有功能同时打开时，两种日志给网关增加的三个文件（两个单元、对象清单）里没有拓扑里的任何地址、端点、WireGuard 公钥、凭据 id、秘密占位符；网关以外的节点没有任何日志相关的路径或指令。

**泄漏面（`go test ./internal/api`）。**

- `TestSecretsAndJournalsStayInTheirChannels`：机制见[架构](architecture.md)「三种日志与秘密之间的边界」。核对的通道：26 个配置和状态视图、`POST /api/compile`、`/api/diff`、`/api/validate`、`/api/topology/allocations`、两次网关预检和安装的回答、存储的拓扑和预检记录、宿主根目录和数据目录下 `secrets/` 以外的每个文件（包括数据库文件）、面板日志；日志自己的八个读取各自确实带着内容（否则测试失败）。摘要：读日志和日志增长不改变任何节点；打开解析日志只改网关；两次 SOCKS 轮换（第二次用同样的值）各只改承载节点，配置里的版本行从 1 到 2 到 3。
- `TestExportHoldsSwitchesAndReferencesOnly`：导出的文档只带开关和引用，原样导入不改变任何摘要。
- `TestDemoFixturesLogContentStaysInLogResponses`：提交的演示数据里，日志内容只在三种日志自己接口的回答里；五种状态各有场景。
- 手工变异（改一处再跑、之后恢复）：把链路日志的事件接口加进「别处」的视图清单，`TestSecretsAndJournalsStayInTheirChannels` 在三个阶段都失败；演示接口去掉 MAC 排除、去掉翻页游标、让没有数据的场景回落到基础场景的按设备页面，`demo.test.tsx` 各有用例失败。

**演示数据（`MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1`）。**

- 三种日志由真实的服务代码在合成输入上产生（[架构](architecture.md)两节的「演示数据」）：连接日志 `sniff.Journal`，解析日志 `dnsjournal.Daemon` 读合成审计文件，链路日志 `linkjournal.Collector` 读合成来源。场景：`healthy`（正常）、`degraded`（观测缺口）、`unavailable`（读不到）、`logs-off`（关闭 / 没有安装）、`logs-empty`（在记录，没有数据）。
- 生成对时钟敏感：合成记录按生成时刻的整分钟排布，时间在写入时按分钟取整。在整分钟刚过时开始（整个生成约 25 秒，要在同一分钟内跑完）连续生成两次，12 个原有文件和 2 个新文件逐字节相同；在一分钟的后半段开始，会有相差一分钟的时间值。
- 这次重新生成改变了的文件：`healthy.json`、`degraded.json`、`unavailable.json`（新增三种日志的回答；`healthy` 另有解析日志的开关、钉死到外部出口的一条规则、故障切换记录里与拓扑一致的接口名、连接日志范围说明里关于解析日志的新句子）、`deploy-*.json` 和 `preflight-blocked.json`（它们带的拓扑、差异和预检随上面两处变化），新增 `logs-off.json`、`logs-empty.json`；`save-refused.json` 不变。
- 演示里的筛选、翻页和跳转由浏览器内的演示接口在生成的整份列表上按服务的规则回答（`web/src/demo/api.ts`）；`demo.test.tsx` 核对：每个场景的十个日志读取都有生成的回答（没有手写的「没有数据」替身）、解析日志的设备 / 结果 / 解析组 / 名字 / 时间筛选和游标翻页、链路时间线的类别和对象筛选及翻页（仍在合并的记录只在第一页）、两个方向的跳转与处理函数生成的那一次回答一致、不带 MAC 时标为仅按地址、另一个 MAC 的记录被排除并计数、没有数据的场景不会显示基础场景的记录。
- 页面：`demo_pages_{healthy,degraded,unavailable,states}.test.tsx` 在每个场景里渲染三个日志页并核对它显示的是哪种状态（空状态的 `data-state`、能力门槛的原因和处理办法、「上次没有正常退出」、采集空窗 / 空窗后才发现 / 合并记录 / 状态未知 / 抖动）；`demo_phone.test.tsx` 在手机宽度下核对三个日志页的表都是卡片（降级场景的链路日志另测一次）。

**本地执行记录（2026-11-16，开发工作站 macOS / arm64，Go 1.26.1；没有连接任何主机）。** `gofmt -l .` 没有输出；`go build ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 go vet ./...` 退出码 0；`go test ./... -count=1` 退出码 0（30 个包通过，其中 `internal/api` 约 124 秒、`internal/compile` 约 99 秒；`TestDemoFixtures` 的结构核对单独跑约 12 秒，之前约 8 秒）；`npm --prefix web run build` 退出码 0；`npm --prefix web test` 退出码 0（31 个文件、431 条用例，没有超时）；`npm --prefix web run demo:build` 退出码 0。演示数据在整分钟刚过时生成了三次，三次的 14 个文件逐字节相同。

**没有验证的。**

- [ ] 真实浏览器：三个日志页在各场景和各宽度下的排版、筛选和跳转的实际操作、演示构建在浏览器里的表现，都没有看过。jsdom 不计算布局。
- [ ] 真实网关：带链路日志采集服务的网关安装、打开解析日志并安装、关闭后清除记录，都没有执行（面板已升级、解析器容器已重建，见上面两节的「真实网关上的现状」）。
- [ ] 受限的命名空间检查没有在本机重跑：开发工作站不是 Linux，`TestNetnsLinkJournalHandshake`、`TestNetnsLinkJournalBackupSwitch`（`//go:build linux`）在这次 `go test ./...` 里没有执行，没有执行不是通过。
- [ ] 演示数据里的链路时间线是合成来源上的采集结果，说明的是采集服务的记录规则，不是任何真实链路的行为；合成的握手间隔、自检周期与真实网关不同（采集每 20 秒一次而不是 10 秒）。

### 远程接入设备变动的快速生效（自动化回归，全部用替身；没有在真实网关上执行过 `wg syncconf`）

- 已回归：`go test ./internal/api -run RemoteFast`（新增 / 删除即安装：版本 +1、可回滚、面板与网关一致、没有 activate 即不重启；改端口、有其他待装改动、网关忙、超频率、宿主代理不支持时不走快速通道；同步失败写回上一份 `mra.conf` 并再次同步、版本不变；秘密不进响应、记录、日志）、`go test ./internal/hostexec -run PeerSync`（只接受事务 id 与摘要，未知参数 400；`mra.conf` 必须 0600 且摘要一致；接口不在时拒绝；不运行 systemctl；临时文件 0600 且删除；工具输出里的密钥被隐去）、vitest「已生效」/ 失败原因各一行。
- [ ] 真实网关上新增一台设备后 `wg show mra peers` 立刻多出它、已有设备的握手不中断；删除后立即消失。
- [ ] 真实 `wg-quick strip` 的输出与 `wg syncconf` 的组合在网关的 wireguard-tools 版本上可用。

## 回滚

- [ ] 面板「回滚」之后，国内中继向东的首选路由回到上一份。
- [ ] 测试机把网关和 DNS 改回 `192.0.2.1` 后，立刻回到原来的 mihomo 路径，ROS 不需要改配置。

## 同网段：重定向和 rp_filter

网关 `192.0.2.88/24` 和 ROS `192.0.2.1` 在同一个二层。国内回程可能由 ROS 直接交给客户端，所以 `rp_filter` 必须是 loose（2）。本机发送 ICMP 重定向必须关掉，否则境外目的有可能被指去 `.1`。

### meridian-verify.sh（隔离 Linux 集成证据，网关上以 root 运行；本版于 2026-11-13 执行过，见已存档的执行记录）

```bash
sudo /usr/local/sbin/meridian-verify.sh
# 让脚本顺带只读查询 ROS 的 ULA 黑洞（需要已配置的 SSH 密钥登录）：
sudo MERIDIAN_ROS_SSH=admin@192.0.2.1 /usr/local/sbin/meridian-verify.sh
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
- **路由探测**（`route_*`）：用 `ip route get <目的> from <源> iif <入接口> [mark 0x64]` 让内核实际判一次转发（包括 `rp_filter` 的源地址校验），结果必须是经指定接口出去的单播路由；报错（例如 `Invalid cross-device link`）、`unreachable`/`blackhole`、或从别的接口出去都是 `FAIL`，原始输出存为 `rtget-<项>.txt`。地址：局域网客户端取局域网前缀里最后一个既不是网关也不是 ROS 的地址（示例 `192.0.2.254`），IPv6 取局域网前缀里的 `::fffe`；国内 IPv4 目的地就是 ROS 的地址（带国内 mark 查表 100）；境外一侧和国内 IPv6 目的地只用文档地址 `192.0.2.1`、`2001:db8:ffff::2`、`2001:db8:ffff::1`；设备地址取设备池里网关之后的那个（示例 `10.67.0.2`、`fd67::2`）。各项：`route_lan_domestic4`（客户端到国内，出局域网口）、`route_tunnel_reply4`（每个网关隧道接口回到客户端的回程，出局域网口）；局域网有 IPv6 前缀时 `route_lan_domestic6`、`route_tunnel_reply6`；远程接入打开时 `route_remote_domestic4`（设备到国内，出局域网口）、`route_remote_reply4` / `route_remote_reply6`（国内回程到设备，出 `mra`）、`route_remote_domestic6`（局域网有 IPv6 前缀时）、`route_tunnel_reply_device4` / `route_tunnel_reply_device6`（每个隧道回到设备，出 `mra`）。
- **另一个会清空规则集的加载器**（`WARN nftables_service_flush`）：`nftables.service` 已启用、且 `/etc/nftables.conf` 里有清空整个规则集的那一行时打印 `WARN`。它只是提醒，不影响退出码：它在 Meridian 加载之后运行时会删掉两张 Meridian 表，转发仍开着，局域网的 IPv4 和 IPv6 都会不受兜底地经 ROS 出去。
- **表尾黑洞**（`fallback_blackholes`）：表 102 的 v4、v6 和表 100 的 v4 都有 metric 32767 的 `blackhole default`。
- **守卫的标记范围**（`guard_mark_range`）：从 `nft list table inet meridian_guard` 读出放行进隧道的标记范围（`nft` 打印成 `0x00000101` 这种形式，按数值比较），必须等于编译出的范围（出口加地区组的最大标记，至少到 `0x140`），并且包含每个编译出的标记。
- **守卫的入口**（`guard_ingress`）：远程接入关闭时守卫里没有 `mra`；打开时 DNS 丢弃、国内标记、出口标记和最后的 fail-closed 丢弃都以 `{ 局域网口, mra }` 为入口，只有两条局域网到设备池的放行单独写局域网口。
- **国内名单不为空**（`chnroute_loaded`、局域网有 IPv6 前缀或启用远程接入时还有 `chnroute6_loaded`、`geosite_cn`）：`inet meridian` 里的 `chnroute` 集合要有元素，`/var/lib/meridian/geosite/cn.txt` 要有域名。空集合但保存的批次 `lists/chnroute.nft` 里有它时，失败信息指出「重载没有重新加入」；从没更新过名单时指出要去更新。这两项在新装、还没更新过名单的网关上一定失败——那时分流确实不对。
- **名单版本**（`INFO list <名单>`）：从 `/var/lib/meridian/lists/status.json` 读出每个名单当前生效的来源、条数和时间，只是信息，不算检查；没有这个文件时 `INFO lists`。
- **开机兜底文件**（`guard_boot_file`）：已安装的 `/etc/nftables.d/meridian-guard.nft` 里的守卫与 `meridian.nft` 里的逐字相同；缺文件或不同都是 `FAIL`。
- **DNS 有人接**（`dns_listener`）：`ss` 显示 UDP 和 TCP 53 都有监听；没有 `ss` 是 `UNKNOWN`。是否答得对是 `verify-smartdns.sh` 的事。
- **走隧道的域名没有 AAAA**（`dns_aaaa_tunnelled`；2026-11-13 主会话在用户网关上执行过一次并通过，没有存档的输出）：`clients_ipv6_via_gateway` 关闭时真实执行 `dig +time=3 +tries=1 @127.0.0.1 AAAA www.google.com`（名字可用 `MERIDIAN_VERIFY_AAAA_NAME` 换成别的国外主机名，只接受主机名），回答是 NOERROR 且没有 AAAA 才 `PASS`；有 AAAA 是 `FAIL`；没回答、不是 NOERROR、没有 `dig`、或测试名字在 `cn`/`apple` 名单里是 `UNKNOWN`。打开时只打印 `INFO`，不查询、不算通过。
- **未列名单域名的国内解析**（`dns_split_active`、`unlisted_domestic_lists`，本版新加，只在 `unlisted_domestic_dns` 打开时）：`systemctl is-active meridian-dns-split.service` 为 active 才 `PASS`，否则 `FAIL`（名单外的名字会全部 SERVFAIL），没有 `systemctl` 是 `UNKNOWN`；`/var/lib/meridian/lists/china.txt` 和 `china6.txt` 都有条目才 `PASS`，缺失或为空是 `FAIL`（那时国内回答一个都不会被采用）；另打印 `INFO unlisted_domestic_dns`，说明国内解析器会看到所有名单外的域名。打开时 `PENDING-HUMAN dns_leak_client` 的说明也换成新的保证（泄漏测试网站会列出国内解析器；只要求测试机自己不发 53/853）。
- **远程接入打开时**：`remote_iface`（`mra` 存在且 up）、上面的 `route_remote_*` / `route_tunnel_reply_device*`、`remote_pool_routes`（设备池在 main 和表 100 路由到 `mra`）、`remote_dns`（`mra` 的 53/853 重定向，DNS 白名单含两个设备池）、`remote_port_lan_only`（监听端口只在局域网口接受）、`remote_nat`（设备池对每个标记都有中转 SNAT，另有局域网口 masquerade）、`remote_wg` / `remote_listen`（`wg show mra listen-port` 等于配置）、`remote_peers`（`wg show mra peers` 恰好是已启用设备的公钥：缺的按设备 ID 列出，多出来的只报数量；只比较公钥，从不运行 `wg show … dump`，不打印也不保存任何私钥或预共享密钥）。**关闭时**：`remote_absent`（没有 `mra` 接口）。旧版本遗留的 `iif mra unreachable` 由路由脚本删除，还在就是 `FAIL no_stale_iif_rule`（以前显示为 `INFO remote_leftover`，这一项已去掉）。
- ROS `fd00::/8` 黑洞：只有设置了 `MERIDIAN_ROS_SSH` 时才执行一条只读的 `/ipv6 route print terse where blackhole`，输出里有 `dst-address=fd00::/8` 或 `fc00::/7` 才 `PASS`；ROS 回答了但没有这条是 `FAIL`；连不上是 `UNKNOWN`。没设置就是 `PENDING-HUMAN`。

一定是 `PENDING-HUMAN`（脚本不跑浏览器、不抓包、不断隧道、看不到路由器和手机）：`dns_leak_client`、`webrtc_srflx`、`redirect_on_wire`、`tunnel_cut`；远程接入打开时还有 `remote_phone_full`、`remote_phone_home`、`remote_router_forward`、`remote_ipv6`。一定是 `NOT-RUN-HERE`：netns 重载测试、`verify-smartdns.sh`、`verify-host-exec.sh`、`verify-mesh-veth.sh`。

退出码：有 `FAIL` 为 1（最后一行 `meridian-verify-failed`）；没有 `FAIL` 但有 `UNKNOWN` 为 2（`meridian-verify-incomplete`，在没有 `/proc`、`sysctl` 或 `ip` 的容器里就是这样，不再退出 0）；全部本机检查通过才是 0，最后一行 `meridian-verify-local-ok`。这一行只代表本机检查，**不是**防泄露结论，也不是发布签收；脚本不再打印旧的 `meridian-verify-ok`。

自动化回归（`go test ./...`，`internal/compile/verify_script_test.go`）：`TestVerifyScriptExecutedChecks`、`TestVerifyScriptRemoteAccess` 和 `TestVerifyScriptULALAN` 用桩程序（`sysctl`/`ip`/`nft`/`wg`/`ss`/`ssh`）和临时根目录（`MERIDIAN_VERIFY_ROOT`，只给测试用）在 bash 里真的执行生成的脚本。覆盖：全部通过、没有 nft、缺主表、AAAA 检查（解析器返回 AAAA 时 FAIL；不回答、SERVFAIL、没有 `dig`、测试名字在国内名单里时 UNKNOWN；环境变量换名字、注入被拒；`TestVerifyScriptResolverSettings`：两个设置打开时只打印 `INFO`、China 名单为空或缺失时 FAIL、泄漏项说明换成新的保证）、缺兜底表、转发关闭、不在网关上（`UNKNOWN`、退出 2）、ULA 指向 ROS、ROS 有/没有黑洞、ROS 连不上、`MERIDIAN_ROS_SSH` 注入被拒；地区组标记的规则缺失、`ip rule` 读不出、表 102 缺黑洞、守卫范围比地区组标记窄、远程接入关闭时有残留 `mra`（失败）与残留 `iif mra unreachable`（`FAIL no_stale_iif_rule`）、旧版的 `iif eth0 unreachable` 加上内核随之给出的 `Invalid cross-device link`（`no_stale_iif_rule` 和 `route_lan_domestic4`、`route_tunnel_reply4` 都 FAIL，IPv6 两项仍 PASS）、某个隧道的回程从别的接口出去、路由探测落到黑洞、没有路由探测的结果（全部 FAIL，不出现任何 `PASS route_`）、`nftables.service` 启用且会清空规则集（`WARN`，退出码仍是 0）与启用但不清空 / 未启用（没有 `WARN`）、chnroute 为空（有保存的批次 / 从没更新过）、`cn.txt` 为空、开机兜底文件不同或缺失、53 没人监听；远程接入打开时全部通过、停用设备仍是 peer、启用设备缺 peer、`mra` 不在、端口不对、没有 `wg`、守卫不含 `mra`、主表缺远程规则、设备池路由缺失、残留 `iif mra unreachable`（`FAIL no_stale_iif_rule`，设备回程的探测 `Invalid cross-device link`）、设备到国内被源地址校验拒绝；局域网 IPv6 前缀是 ULA 时全部通过、前缀之外的 ULA 路由在局域网口上、包含前缀的更宽 ULA 路由、`fd66::/48` 在局域网口上、前缀路由指向 ROS、已加载的分类链缺这条前缀规则、前缀规则被换成更宽的、丢弃不在（都 FAIL），以及 GUA 前缀时丢弃之前多出一条 ULA 规则（FAIL）。每个用例都断言脚本不能执行的项从不出现 `PASS`。桩里的 nft 输出是编译文本加上真实 `nft list` 的两处格式（标记补零成 8 位、集合元素跨行），真实 `nft list` / `ip rule` / `ss` 的其他格式差异要在网关上跑一次确认（格式不同只会让对应项 `FAIL`，不会误报通过）。

这些测试找到过一个真实问题：打开远程接入后守卫最后一条是 `iifname { "eth0", "mra" } … drop`，旧版 `nft_guard` 的匹配只认 `iifname "eth0"`，会在每台打开远程接入的网关上误报 `FAIL`；已改为两种写法都认。

- [ ] 在网关上运行一次，最后一行是 `meridian-verify-local-ok`，证据目录已存档。
- [ ] 临时 `nft delete table inet meridian_guard` 之后再运行（只在测试网关上做，做完重新安装）：`nft_guard` 为 `FAIL`，退出码 1。

面板「防泄露」页对生成配置做同样的文本检查，那是自动化回归，不替代上面的运行结果。下面这些打勾项里，标了「实机」的没法在仓库的单元测试里做。

- [ ] `sysctl net.ipv4.conf.all.rp_filter` 和局域网口、隧道接口、`mra` 都是 2（网关的路由脚本只设这些接口，Docker 等别的接口不再设；all=2 使它们的有效值仍是 2）。生成配置和 `meridian-verify.sh` 会查；实机上再看一遍运行值。
- [ ] `net.ipv4.conf.all.send_redirects` 以及对应接口都是 0。IPv6 没有这个开关，见下面「已知边界」。
- [ ] `accept_redirects` 为 0。ROS 自己仍可能对客户端发重定向，这不由本机控制，实机上在测试机抓包确认。
- [ ] 网关地址不是 `192.0.2.1`，两者在 `192.0.2.0/24`。
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

## 本机发起连接的 MSS 钳制（修订 16；自动化回归；2026-11-15 已在真实网关上验证，见本节末尾）

背景与规则见架构「MSS 钳制：转发流量与本机发起的连接」。2026-11-15 在真实网关上观察到：面板的解锁检测（本机发起、带出口标记）在路径 MTU 1408 的出口上 TLS 握手超时，转发流量正常。

仓库里能跑的（`go test ./...` 会跑）：

- `TestLocalMSSGatewayRules`（`internal/compile/local_mss_test.go`）：12 种拓扑（示例、远程接入、主备枢纽、多中继分担、嵌套出口、外部出口，各自再加打开 `settings.sniff` 的一份）里网关都有 `local_mss`（output -140）和 `local_mss_in`（input mangle）；两条链的钳制值与 `mss` 链完全相同；每条规则只匹配 TCP SYN、屏蔽中继位后的出口/组标记范围（`0x101` 到兜底表上界）和网关全部隧道接口；没有规则提到 UDP、`0x4d72` 或属主；只降不升；`local_mss_in` 只看回程目的为中转网段的连接；打开嗅探时转发服务的链（`sniff_mss`、`sniff_out`、`sniff_confine`、mangle 处的 `sniff_route`）仍在。
- `TestLocalMSSFollowsPath`：把一条链路的 MTU 调小后，`mss`、`local_mss`、`local_mss_in` 和中继的 `tunnel_mss_out` 一起变成新的全路径值（没有第二个写死的数）。
- `TestNodeMSSRules`：每个有隧道的远端节点都有 `tunnel_mss_out` / `tunnel_mss_in`，接口集合恰好是它自己的隧道接口，值是网关的转发钳制值（有 Mesh 腿的出口取它更低的值），不提 WAN、`mmesh` 或 UDP；没有隧道的节点不生成。
- `TestVerifyScriptExecutedChecks`：`meridian-verify.sh` 新增 `local_mss` 检查——加载的 `local_mss`（hook output）和 `local_mss_in`（hook input）必须存在，`mss` 链必须含编译出的 IPv4/IPv6 值，三条链的取值集合必须相同（不计 `mra` 的规则）；缺链、值不同、转发值不是编译值各有一个失败用例。脚本同时列出 `NOT-RUN-HERE netns_local_mss`。
- 单跳金样（`MERIDIAN_UPDATE_GOLDEN=1` 重写）：`single_hub_example.golden`、`single_hub_groupdns.golden`、`single_hub_remote_access.golden` 里所有节点的 `etc/nftables.d/meridian.nft` 和网关的 `usr/local/sbin/meridian-verify.sh` 摘要变了，其它文件不变。

命名空间回归（Linux，root，内核 WireGuard，`internal/compile/netns_mss_linux_test.go`；**本仓库的开发机是 macOS，没有执行过**）：

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile
sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^TestNetnsLocalMSS' -test.v
```

- `TestNetnsLocalMSSGateway`：示例拓扑编译出的网关规则集，`m02` 用编译出的配置（MTU 1412、FwMark、Endpoint，测试密钥）连到对端命名空间；中间的路由命名空间静默丢弃长度超过「钳制后的段能用」的外层包（不发 ICMP）。L0：把 `local_mss` / `local_mss_in` 清空后，带默认组标记和中转源地址的本机连接（IPv4、IPv6，各方向 64 KiB）在 4 秒内失败，且黑洞计数增长；L1：重新加载生成的规则集后同样的连接成功，对端看到的 SYN MSS 和网关自己的发送 MSS 都不超过转发钳制值，黑洞不丢包；U：不带标记的本机连接（到局域网主机，经隧道到对端隧道地址）MSS 不变；W：带 WireGuard 标记 `0x4d72` 经下层的 TCP（wstunnel 承载的形状）MSS 不变，WireGuard 外层包只在 L0 被丢；F：转发的局域网连接仍被 `mss` 链夹住并成功。
- `TestNetnsLocalMSSNode`：对端加载中继（ali）编译出的规则集前，它自己经隧道到网关本机套接字的连接失败；加载后（`tunnel_mss_out` / `tunnel_mss_in`）成功且两端 MSS 都被夹住。
- 缺 root、缺两个环境变量、缺 `ip`/`nft`/`wg`、内核不能建 WireGuard 接口或不能装 MSS 规则时跳过并标明 NOT RUN，跳过不算通过。全部超时有上限，单个测试预计十几秒。

**2026-11-15 在真实主机上已验证**（主会话提供的事实）：修订 16 装到真实网关后，此前握手超时的两个路径 MTU 偏小的出口上，面板的解锁检测恢复正常；网关验收脚本的 `local_mss` 检查通过。

仍未验证：真实出口的解锁定时报告；外部 SOCKS 代理那一跳的 MTU（不在钳制范围内，见架构）；出口和地区组经 Mesh 腿时的钳制（见「Mesh 腿的 MTU」）。下一次预检会显示：网关和每个有隧道的远端节点的 `etc/nftables.d/meridian.nft`、网关的 `usr/local/sbin/meridian-verify.sh` 有差异；隧道配置（`etc/wireguard/*.conf`，含 `MTU =`）不变。

## 上联 MTU（修订 16 第二部分；自动化回归；预检已在真实主机上验证，采用建议值后的下发未验证）

背景与规则见架构「上联 MTU：两端预检、建议与显式确认」。2026-11-15 的观察：一个出口上联网卡 MTU 1472、隧道 MTU 1420，不允许分片的 1408 字节包通、1412 不通。

仓库里能跑的（`go test ./...` 会跑）：

- `internal/mtu/mtu_test.go`：IPv4 / IPv6 外层开销（60 / 80），补齐边界（截在 MTU 处），1472 → 内层最大 1408、超出 8 字节、建议 1408（IPv6：1392、超出 28），1500 的取值，所有 MTU × 上联组合对逐字节暴力枚举的一致性，WSS 估算（数据报、MSS、段数，上联 MTU 只改变段数），`Carrier` 的路由参数和「同一计划」。
- `internal/preflight`：`TestParseUplinkLines`、`TestValidRoute`（含恶意参数、重复、超过 64 个）、`TestScriptRunsLocally`（脚本对 `route4:` / `route6:` 参数给出回答，恶意参数由脚本自己拒绝）、`TestUplinkMTUEvaluation`（能承载 / 承载不了且未部署 → 阻断，消息含节点、网卡、1472、1480、超出 8 字节、1408，修复指向链路 `mtu`；路由 MTU 更小时取路由 MTU）、`TestUplinkMTUUnknown`（旧报告、没有路由结果、没有路由、查不到接口 MTU、报告不完整：都是未知、信息级、不阻断）、`TestUplinkMTUDeployedDefaultRouteV6WSS`（已部署的腿只警告；监听端按最小 metric 的默认路由；IPv6 外层；WSS 腿只给分段估算；同一观察按建议值重判为能承载）。`TestScriptSyntaxAndReadOnly` 仍然只允许打印状态的命令。
- `internal/hostexec`：`TestAgentPreflightRoutes`（接口 MTU、每个地址一次 `ip -o -4|-6 route get … mark 0x4d72`，非法参数在执行任何命令前拒绝）、`TestClientPreflightRoutesFallsBack`（旧 agent 拒绝 `routes` 字段时去掉它重发）。`internal/sshexec`：路由参数被 SSH 通道接受，带命令、错族、zone、非规范、未加引号的被拒。
- `internal/compile/carry_mtu_test.go`：`TestClampsFollowEveryCarryingPath`——路径 MTU 是所有承载路径的最小值（架构「出口的路径 MTU：所有承载路径的最小值」）。每例只把一条链路调到 1280（先确认它**不在**报告的首选路径上，否则测试不成立）：多中继分担里非首选中继的网关链路、它到 IX 的链路、它的 WSS 腿（`wss_mtu`）；主备枢纽里备用枢纽到出口的链路（单中继和分担两种）；网关故障切换链路的 WSS 腿；中继自己的 IX 替换 WSS；嵌套出口的内层链路。每例都要求：该出口的路径报告 1280、MSS 1240/1220，网关 `mss`、`sniff_mss`（打开嗅探）、`local_mss`、`local_mss_in` 和每个远端节点的 `tunnel_mss_out` / `tunnel_mss_in` 一起变成 1240/1220。前五例在旧代码上失败（MSS 停在 1320/1300）。`TestCarryingPathExcludesOtherLinks`（反例）：别的出口的枢纽链路只降低那个出口的报告；双栈中继到纯 IPv6 出口的链路不改其它出口的报告，也不改 Mesh 出口按标记的钳制；网关到第三台中继的待命链路调小后，任何出口的报告和转发钳制都不变。
- `internal/api/uplink_mtu_carry_test.go`：`TestMTUPreviewFollowsEveryCarryingPath`——采用预览（`mtuProposalFor`）对同样的情形列出路径 MTU 1360 → 1280、MSS 1240/1220，且不列出这条链路承载不了的出口。
- `internal/compile/mtu_test.go`：`TestUplinkCarriersExample`（拨号端用对端地址、拨入的监听端按默认路由、一个枢纽多条腿、网关带 `0x4d72`、故障切换的 UDP 与 WSS 两条腿、外层 IPv6，每条腿的 MTU 等于编译出的 `MTU =`）、`TestClampsFollowAdoptedLinkMTU`（把一条链路调到 1344：网关 `mss`、`sniff_mss`、`local_mss`、`local_mss_in` 和每个节点的 `tunnel_mss_out` 都变成 1304/1284，不再有旧值；只有这条链路两端的 `wg` 配置变）、`TestWSSLegMTUIsThePathMTU`、`TestLegMTUDefaults`。
- `internal/api`：`TestUplinkMTUSuggestionAndAdoption`（预检命令带 `route4:` 参数；首次安装阻断；两端视图、建议、逐节点文件差异；查看不改拓扑也不碰主机；值不符、字段不符、别的链路、空请求都被拒且不写；正确的采用只改这条链路的 `mtu`，没有任何下发脚本发出；之后同一观察判为能承载、没有可采用项、再次采用被拒；下一次预检不再报）、`TestUplinkMTUFactBinding`（未知、超过 24 小时、别的节点的记录、别的面板实例、对端地址变了、服务器凭据变了：都是未验证，不给建议）、`TestGatewayUplinkMTU`（网关的路由查询到达 agent；未装的腿阻断首次安装；已装的腿只警告、更新照常；网关一端的建议）。
- `web/src/topology_contract.test.tsx`：上联 MTU 卡片显示两端和建议；「采用建议值…」先展示逐条变更和逐节点文件差异、此时不发请求；确认后只发送 `{changes:[{link_id, field, from, to}]}`，提示没有下发并链接到部署页；拓扑有未保存修改时不能采用。
- 金样：没有设 MTU 的拓扑编译结果逐字节不变（单跳金样没有改）。演示数据重新生成：新增 `GET /api/mtu/uplinks` 的回答和预检记录里的 `uplinks` / `uplink_mtu_unknown`；生成器给随机值分配的占位符因此整体重新编号（公钥、摘要），不是编译结果的变化。

命名空间回归（Linux，root，内核 WireGuard，`internal/compile/netns_uplink_mtu_linux_test.go`；**本仓库的开发机是 macOS，没有执行过**）：

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile
sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^TestNetnsUplinkMTU$' -test.v
```

两个命名空间：出口一侧网卡 MTU 1472，枢纽一侧 1500；`wg4`（外层 IPv4）和 `wg6`（外层 IPv6）隧道 MTU 都是示例里直连链路的 1420。P1：在出口命名空间里运行固定预检脚本（带两个路由参数）并评估：两条腿都承载不了、网卡 `ua`、超出 8 / 28、建议 1408 / 1392、阻断；枢纽一端能承载。B：1420 时不允许分片的 1408 字节包通、1412 和 1420 不通（IPv4 外层），IPv6 外层 1420 不通。A：两端换成建议值后，满长（1408 / 1392）的不允许分片包两条腿都通，同一评估判为能承载。通过的样子：`EVIDENCE P1`、`EVIDENCE B`、`EVIDENCE A` 行，stderr 最后一行 `meridian-netns-uplink-mtu-test-ok`。缺 root、两个环境变量、`ip`/`nft`/`wg`/`ping`/`bash`/`timeout`，或内核不能建 WireGuard 接口时跳过并标明 NOT RUN。预计不到一分钟。

**没有实现链路健康里的主动有效 MTU 探测。** 预检只证明每一端本机的约束（外层包从哪块网卡出去、网卡和路由的 MTU），不证明整条底层路径。人工核对（两端各做一次，丢包可能只发生在接收方向）：

1. 每一端：`ip route get <对端公网地址>`（网关加 `mark 0x4d72`）看出接口，`ip link show <接口>` 看 MTU。
2. 经隧道，从这一端 ping 对端的隧道地址，不允许分片，内层正好等于隧道 MTU：IPv4 `ping -M do -c 3 -s $((MTU-28)) <对端隧道 IPv4>`，IPv6 `ping -6 -M do -c 3 -s $((MTU-48)) <对端隧道 ULA>`。必须通；超时（不是 `message too long`）就是路径上有更小的 MTU 静默丢包。再从对端反方向做一次。
3. 定位时二分：减 4、减 16 再试，找到能通的最大值 `N`；隧道 MTU 不应超过 `N`，取 16 的倍数。底层路径本身可以用 `ping -M do -s $((上联MTU-28)) <对端公网地址>` 对照（对端可能不回 ICMP，不通不一定是 MTU）。
4. 结果存档；需要改时在拓扑页采用建议值或手改链路 MTU，再经部署页预检、确认下发。

**2026-11-15 在真实主机上已验证**（主会话提供的事实）：在上联网卡 MTU 为 1472 的真实节点上，预检正确报出三条链路各超出 8 字节、建议 1408（这些链路已部署，所以是警告）；网关和其它节点报为可承载。

仍未验证：网关 agent 升级前的回退路径只在测试里跑过；在真实节点上采用建议值并下发后的效果（修订 16 的激活脚本不会改变运行中接口的 MTU，修订 19 修好，见「采用的隧道 MTU 在运行中的接口上生效」；主会话会在修好并装上之后执行并补充结果）；WSS 分段估算与真实 wstunnel 的差别。

## Mesh 腿的 MTU：按出口和按组标记的钳制（自动化回归；命名空间里验证过外层分片；真实 Mesh 上未验证）

背景与规则见架构「Mesh 腿的 MTU：按出口和按组标记的钳制」。两个值：接口 MTU 1280（IPv6 需要），路径值 1216（Mesh 路径 1280 − WireGuard 60 = 1220，取 16 的整数倍），MSS 1176 / 1156。

仓库里能跑的（`go test ./...` 会跑）：

- `internal/mtu`：`TestMeshLeg`——各种 Mesh 路径下的两个值；路径值恰好是这样一个接口上不分片的最大内层包（再大一个字节外层就超过 Mesh 路径）。
- `internal/validate`：`TestMeshLegMTU`（`hopMTU` 用路径值、`LegMTU` 用接口值；默认路径下每条 Mesh 腿一条 `mesh_leg_fragments` 警告，Mesh 路径 1340 时没有；Mesh 腿自己的小值不触发 `mtu_too_low`，`cf_mesh` 链路的 `mtu` 低于 1280 仍然拒绝）、`TestGroupMeshHopMTU`、`TestExampleTopologyHasNoErrors`（有 Mesh 腿的出口路径 MTU 1216 并列出 `mesh_links`，其余 1360）。
- `internal/compile/mesh_transport_test.go`：`TestMeshLegMTUClamps`——全局值不因 Mesh 腿而变（1320/1300，与去掉 Mesh 边的同一拓扑相同）；有 Mesh 腿的出口按自己的标记在 `mss`、`local_mss`、`local_mss_in` 里夹到 1176/1156，没有的出口没有按标记的规则；能切到这种出口的组的报告 `mesh: true`、1216、按组标记夹，其余组不夹；枢纽对每条 Mesh 腿的接口另有 1176/1156，出口节点用自己的值，没有 Mesh 腿的节点仍是 1320/1300；Mesh 路径 1340 时接口和路径值都是 1280（夹到 1240/1220），1420 时 1360、不再夹。
- `internal/compile/carry_mtu_test.go`：`TestGroupMeshClampOnEveryChain`（18 种拓扑上逐链核对，含打开嗅探的 `sniff_mss`）、`TestGroupMeshClampOnlyWithFallback`（示例里 `hk`、`us`、`us-pin`、`v6-nat` 四个组被夹；停用 `hk` 成员的 Mesh 边后 `hk` 不再夹；Mesh 路径调到 1420 的那条腿不再让它的组被夹）、`TestCarryingPathExcludesOtherLinks`。
- `internal/api/uplink_mtu_carry_test.go`：`TestMTUPreviewGroupMeshPath`——`hub-us-mesh` 的 Mesh 路径 1280 → 1300 时出口 `us` 和组 `us`、`us-pin` 从 1216 变 1232，别的不变；网关上联降到 1300 时没有 Mesh 腿的出口和组变成 1300，有 Mesh 腿的仍是 1216、不列出。
- 金样：示例拓扑带 Mesh 边，三份金样和 `preLogCompile["example"]` 随这次改动重写；没有 Mesh 边的拓扑由 `TestNoMeshCompileUnchangedByMeshTransport` 单独钉在改动前（见「Mesh 腿」一节）。

命名空间里（`TestNetnsMeshLeg`，2026-11-16 通过）：经 Mesh 腿、Mesh 设备 MTU 1280 时，1216 字节的内层包在出口 sidecar 入口看不到任何 IP 分片；1217 和 1280 字节各有分片并得到应答。`TestNetnsLocalMSS*`（`netns_mss_linux_test.go`，含 `TestNetnsLocalMSSGroupMesh`：它把「更小的一跳」建成一条 MTU 1280、不回送 ICMP 的链路，验证的是按组标记的钳制让连接完成，与 Mesh 腿的封装无关）同日在同一容器里的结果见 `docs/evidence/2026-11-16-netns-mesh-leg/README.md`。

仍未验证：真实 Cloudflare Mesh 的路径 MTU 是否就是 `cf_mesh` 链路配置的值；真实 Mesh 是否放行 WireGuard 外层包的 IP 分片（不放行时 1217–1280 字节的非 TCP 包丢失，TCP 不受影响）。

## 采用的隧道 MTU 在运行中的接口上生效（修订 19；自动化回归，命名空间测试未在本机执行，真实节点上的采用与下发未验证）

背景与规则见架构「上联 MTU」里的「采用之后在运行中的接口上生效」。事实：修订 16 的激活脚本对已存在的受管隧道接口只执行 `wg syncconf`，不改变接口 MTU；主会话核对下发脚本时发现，因此暂时没有在真实节点上采用建议值。

仓库里能跑的（`go test ./...` 会跑）：

- `internal/compile/mtu_test.go`：`TestActivationAlignsTunnelMTU`——示例、远程接入、主备枢纽、多中继分担的每个节点，`meridian-up.sh` 里每个隧道接口的 MTU 恰好等于它配置的 `MTU =`，没有 `mra`；采用一条链路（`hub-jp` → 1408）只改变这条链路两端的配置和脚本里的值，其它值都不变。`TestActivationMTUScript`：在 bash 里用假的 `ip` / `wg` / `wg-quick` 和假的 sysfs 执行生成的一步：运行 MTU 不同的已有接口先 `wg syncconf` 再 `ip link set dev … mtu`，相同的只 syncconf，不存在的由 `wg-quick up` 建立；没有 `wg-quick down`、没有删接口。
- `internal/compile/verify_script_test.go`：验收脚本的 `tunnel_mtu`——全部一致时 PASS；一个接口的运行 MTU 不同、一个接口不在时 FAIL，且整个脚本不再是 `meridian-verify-local-ok`。脚本同时列出 `NOT-RUN-HERE netns_live_mtu`。
- `internal/preflight`：`TestTunnelMTUChangeAndDrift`（运行 MTU 与配置不同：变更列表写「MTU A → B」并有警告 `tunnel_mtu_drift`；相同：「MTU N 不变」、没有警告；报告里没有运行 MTU：不下结论）、`TestTunnelMTUDriftAndNodeState`（偏差的计算；节点状态回答里的 `linkmtu` 行，坏的名字和数值被丢弃）。
- `internal/api/node_state_test.go`：`TestNodeReadBackTunnelMTU`——安装后读回的运行 MTU 与配置不同：读回「不一致」、节点不是「已同步」；主机按配置运行后重新安装：已同步、已核对；之后运行 MTU 又偏了：下一次只读预检的变更列表写出 `MTU … → …` 并警告，节点不再是「已同步」。测试里的假主机按安装脚本里每个配置的 `MTU =` 给出运行 MTU。

命名空间回归（Linux，root，内核 WireGuard，`internal/compile/netns_live_mtu_linux_test.go`；**本仓库的开发机是 macOS，没有执行过**）：

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile
sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 ./compile.test -test.run '^TestNetnsLiveMTU$' -test.v
```

`TestNetnsLiveMTU`：本机 MSS 实验网的 `m02`（编译出的配置 MTU 1412、测试密钥）握手完成。底层静默丢弃长于 L = 1446 字节的 IPv4 外层包（L − 60 不是 16 的倍数，与真实的 1472 上联同类），1412 承载不了。拓扑给这条链路采用 L 的建议值 `mtu.SuggestUDP(L) = 1376`（与面板采用写入的字段相同），重新编译，把新的 `m02.conf` 放进临时目录（不写 `/etc`），在网关命名空间里执行生成的 WireGuard 一步（由生成 `meridian-up.sh` 的同一个函数给出，`wg_conf_mtu` 的值和 syncconf / `ip link set` 两行与生成的脚本比对过）。对端在 V、R 两段一直保持旧 MTU（只装了一端）。V0：各方向 64 KiB 的新连接在底层失败且有丢包；运行 MTU 是旧值，生成的验收脚本的 `tunnel_mtu` 段 FAIL，固定节点状态命令的 `linkmtu` 读回有偏差；A：这一步打印 `meridian-wg-mtu: m02 1412 -> 1376`；V1：运行 MTU 是新值、接口序号不变（没有重建）、最近一次握手时间没有被重置、改动之前打开的长连接完成；对端仍是 1412 时各方向 64 KiB 的新连接成功、底层不丢包；`tunnel_mtu` PASS，读回没有偏差，再执行一次这一步什么都不改。R：底层限制临时放开，对端（1412）发一个 1412 字节不允许分片的 ping，逐级计数：对端 `m02` 发出、底层放行、网关 `u0` 收到外层、网关 `m02` 交出内层、网关发出应答，再加 ping 的结果和网关 `m02` 的接收错误计数；断言的只是实验网把外层送到了网关，网关是否收下比自己 MTU 长的包按观察记录为 `EVIDENCE R receive-larger: ACCEPTED` 或 `NOT DELIVERED`（2026-11-15 在真实网关的内核上的结果是 `NOT DELIVERED`：外层包到达了网关，但 MTU 1376 的 `m02` 没有交出这个 1412 字节的内层包，也没有应答；部署说明据此写明，见架构「下发顺序」）。P：手工值 L − 60 = 1386（不是 16 的倍数）只装在网关：网关自己的上传通过；对端把 1386 字节的段补齐到 1392，外层 1452 > 1446，下载失败且有丢包；对端也改成 1386 后下载通过。通过的样子：`EVIDENCE lab`、`EVIDENCE V0`、`EVIDENCE A`、`EVIDENCE V1`、`EVIDENCE R`（各级计数和 receive-larger 结论）、`EVIDENCE P2`、`EVIDENCE P3` 行，stderr 最后一行 `meridian-netns-live-mtu-test-ok`。除本机 MSS 实验网的条件外还要 `wg-quick` 和 `ping`，缺了跳过并标明 NOT RUN。全部在自己的命名空间和临时目录里，不碰主机的接口和 `/etc`。预计二三十秒。

第一次在真实网关内核上运行时，旧版本的这个测试在 V1 的新连接上失败：它把网关调低到 1380（不是 16 的倍数），对端仍是 1412，把 1380 字节的段补齐到 1392，外层 1452 超过实验网底层的 1446。这不是激活脚本的缺陷，而是只装一端时、手工值不是 16 的倍数的真实现象（上面的 P 段现在专门证明它），也说明修订 19 文档里「没改的一端和改之前一样」的说法不完整，已改写（架构「下发顺序」）。测试现在用建议值（16 的倍数），按与真实情况同类的底层证明只装一端时两个方向都通。

下一次预检会显示：每个有隧道的节点的 `usr/local/sbin/meridian-up.sh`、网关的 `usr/local/sbin/meridian-verify.sh` 有差异；拓扑里有 Mesh 腿时网关的 `etc/nftables.d/meridian.nft` 也有差异（见上一节）；`etc/wireguard/*.conf` 和其中的 `MTU =` 不变。已存在接口的变更行会写出运行 MTU 与配置是否一致。

仍未验证：在真实节点上采用建议值、按引导下发并读回（主会话在这一项装上之后执行，在那之前未验证）；真实主机上 `ip link set … mtu` 对运行中 WireGuard 会话的影响（只在命名空间测试里，且本机没有执行）。

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

- [ ] 香港机房组里有多台非住宅出口，面板上首选是 IX 绑定的那台。住宅出口在另一个组，至少两台。
- [ ] 把首选成员的探测连续打失败 3 次，枢纽上该组自己的路由表（`ip route show table <组表>`）下一跳换成同组备成员。只失败 1 次时下一跳不变。各出口自己的表不变。（实机：看 `/run/meridian/group/<组 ID>/report`，或在面板「出口」页读取枢纽状态。仓库里用状态机单测和在 bash 里带桩运行生成的 `group_step` 覆盖了同一规则：`go test ./internal/pool ./internal/compile -run 'Group|Hub'`。）
- [ ] 首选恢复后，要连续成功满 120 秒、最近一次探测成功、并且距上次切换满 120 秒才切回；恢复期间首选再失败一次，恢复计时清零。首选已经判死时，这 120 秒不会把下一跳留在另一台也已经判死的成员上。
- [ ] 手动组「保持」：指定成员判死后下一跳不变，`reason=held`、`alert=1`。「回落」：切到有效顺序里的下一个成员，`reason=fallback`、`alert=1`，恢复后按上一条切回。
- [ ] 组内成员都失败时，组表停在原成员上（那条隧道不通，流量被丢弃），不改去别的国家，也不从枢纽的默认路由出去；任何情况下组表和出口表的默认路由都不指向 `mmesh`（`ip route show table all | grep mmesh` 只有到各出口 Mesh 专用地址的 /32）。自动化：`TestHubGroupStepMatchesStateMachine`（sidecar 存在且已密封时全部成员失效，状态机和枢纽脚本都不去 `mmesh`）、`TestHubGroupHopRefusesMeshVeth`、`TestMeshNoDefaultRouteOntoVeth`；命名空间：`TestNetnsGroupDNSFailover` 第 5 阶段。
- [ ] 改组（顺序、指定成员、成员）后下发：`meridian-failover.service` 被重启，组表回到编译时的选择。

### 枢纽实际状态回读（面板「实际使用」）

机制见[架构](architecture.md#实际状态与面板推算两个来源分开显示)。

- 自动化回归（`go test ./internal/compile ./internal/hubstate ./internal/api`）：
  - 枢纽侧，在 bash 里带桩（`ip` 按表保存路由并可对某张组表注入失败、`ping`、`date`）运行**生成的**切换脚本，再用面板的固定命令读回并交给面板解析器：`TestHubStateRecordsSwitch`（启动写入部署标识；心跳每轮前进；成功切换记录新成员、原因、时间，面板判为 `ok`；Mesh 未封装时报告 `blackhole`）、`TestHubStateRecordsFailedSwitch`（组表的路由命令失败：`result failed`、`want`、`hop` 仍是原成员，切换器状态不变，面板判为 `switch_failed`；之后恢复切换成功；表被外部改动判为 `diverged`）、`TestHubStateStaleAndVersion`（心跳超过阈值为 `stale`、恰好在阈值内仍是 `ok`；改了组的顺序为 `version_mismatch`；与组无关的改动不改部署标识）、`TestHubStateWritesAreAtomic`（写入期间并发读取从未读到半个报告）、`TestHubStateScriptShape`（循环间隔与阈值一致；只有枢纽的切换脚本带记录）。
  - 解析与判定：`internal/hubstate` 的 `TestEvaluateStates`、`TestEvaluateClock`、`TestEvaluateIdentity`（枢纽节点、服务器、地址、端口、指纹任一变化、指纹未固定、无枢纽、旧格式读取都判为 `hub_identity_changed`，成功和失败的读取都一样；规范化后相同的地址不算变化）、`TestNormalizeAddress`、`TestParseRejects`（未知成员、Mesh 边不存在时的 `mmesh`、格式错误、控制字符、shell 字符、重复字段 / 组、不完整、过大、时间不合理）。
  - 面板侧，对进程内 SSH 测试服务器的固定命令给出预设输出：`TestHubStateReadStates`（`ok`、`stale`、`version_mismatch`、`switch_failed`、未知成员、缺记录、格式错误、过大、命令失败、密码错误、主机指纹变了；发出的命令永远是那条常量，请求体里的东西不会进入命令；非 `ok` 状态没有任何成员被标为实际使用；模型与实际分开；密码不在响应、日志和存储里）、`TestHubStateUnreachable`（指纹未确认时不登录、枢纽没有服务器、静态组为 `not_switchable`）、`TestHubStateRefreshSerialised`（并发读取 409）、`TestHubStateLimitsAgree`；身份绑定：`TestHubStateIdentityRelink`（枢纽节点改到另一台服务器后旧报告立即未知，读取后显示新主机的报告；改回去同样未知）、`TestHubStateIdentityAddressEdit`（改名不影响；原地改地址立即未知，重新确认同一把钥匙后仍未知，直到在新地址读取成功）、`TestHubStateIdentityPortEdit`、`TestHubStateIdentityFingerprint`（指纹不一致、重新确认另一把钥匙、清除指纹）、`TestHubStateIdentityLateResult`（读取进行中改指向 / 重新确认指纹 / 改地址 / 改端口：读取期间的 GET 已显示未知，迟到的结果返回 409 `hub_identity_changed` 且不入库，存储的仍是之前那次读取）。这些包用 `go test -race ./internal/api ./internal/hubstate` 跑。
  - 界面（`npm --prefix web test`）：只有模型时显示「面板推算」和「未验证」，不出现「实际使用 <成员>」和「使用中」；`actual.ok` 时显示成员、原因、上次切换、读取时间；过期 / 版本不一致 / 切换失败各自的原因和修复入口；读取不是当前枢纽时显示「未验证 · 枢纽已变更」和原因、状态条标「不是当前枢纽」、即使刚读过也自动读一次，读取期间枢纽又变了（409）时提示结果已丢弃并重新加载；枢纽暂时读不了时链到服务器页且不自动读；打开页面自动读一次、按钮再读、不轮询；概览卡片同样只在 `ok` 时写成员。
- 隔离 Linux 集成：`TestNetnsGroupDNSFailover` 在真实内核的命名空间里跑编译出的 `group_step`，并核对报告：切换后 `hub report: hop in table us: us-2`、`hub report: result: ok`，全部成员断开且 Mesh 未封装时 `hub report: hop in table us (Mesh unsealed): blackhole`；Mesh 阶段（2026-11-13 跑通，见 `docs/evidence/2026-11-13-debian13-mesh-dns/`）在密封后 `hop` 是 `mmesh`，失去密封后回到 `blackhole`。
- [ ] 实机（待人工签收）：在真实枢纽上让某个可切换组的首选成员失效，枢纽切换后在面板「出口」页点「读取枢纽状态」，该组显示「实际使用 <备成员>」、原因「故障切换」、上次切换时间与枢纽上 `ip route show table <组表>` 和 `/run/meridian/group/<组>/report` 一致；同时在测试机上确认流量确实从备成员出去（`ipleak`）。再停掉 `meridian-failover.service` 超过阈值后读取，显示「状态过期」而不是成员；改一下组的顺序但不下发，读取显示「枢纽不是当前配置」。再在服务器页改枢纽服务器的地址（或把枢纽节点改到另一台服务器），不读取，刷新页面：每个可切换组立即显示「枢纽已变更」而不是成员。签收时记录读取时间和枢纽上的报告原文。身份绑定目前只有上面的自动化测试（进程内 SSH 测试服务器），没有在真实枢纽上执行过。
- [ ] 网关上没有 `cloudflare/mesh`，也没有 `dev mmesh`。Mesh 只在枢纽和出口的独立网络命名空间里。本机地址是 `192.0.2.88/24` 时，mesh 脚本拒绝启动。
- [ ] `/etc/meridian/mesh.env` 权限 0600，令牌不在 git 里，由面板部署写入（经 SSH 标准输入传送，不出现在远端进程列表）。文件为空时 sidecar 不启动，其余隧道照常。
- [ ] 删掉 IX 或把 Mesh 从本地宽带画到出口，保存被拒绝。

### 主枢纽与备用枢纽（IX 受管主枢纽、备用枢纽、承载枢纽的实际状态）

状态：**结构测试与单元测试通过；命名空间测试已写好但没有在任何 Linux 主机上执行过；没有任何真实主机证据。** 设计见架构文档「主枢纽与备用枢纽」。

- 自动化（`go test ./...`）：`internal/compile/dualhub_test.go`（IX 枢纽入口 / 出口地址、两个枢纽的同号表与各自接口、出口的回程对称规则与表只指向本枢纽隧道、网关上游的一处决定与两份脚本逐字节相同、兜底表包含备用路径且仍以丢弃结尾、bash 桩驱动的接管与切回滞回、双枢纽校验错误、迁移幂等）、`golden_single_hub_test.go`（旧单枢纽拓扑编译结果的逐文件摘要不变）、`internal/preflight/ixhub_test.go`、`internal/hostexec/upstream_test.go`、`internal/api/dualhub_runtime_test.go`（承载枢纽决定 `actual`、未知时不显示实际使用、每个枢纽的身份变化各自立即失效）。
- 隔离 Linux 集成：`TestNetnsDualHub`（上面「每个命令能证明什么」），2026-11-13 在一台 Debian 13 上通过（`docs/evidence/2026-11-13-debian13-dual-hub/`）。备用路径在测试里是 veth 而不是 wstunnel；真实的 IX、备用枢纽和出口仍未验证。
- 待人工签收：真实 IX（经中继端口转发、仅密码登录）上的预检与下发、真实的主链路中断与接管、备用 WSS 的真实握手、出口真实的回程对称、面板显示的承载枢纽与网关实际一致。

### 地区组的解析

机制见[架构](architecture.md#地区组的解析)。可切换组的名字经组的解析地址（`fd66::53:<k>`）、带组 mark 查询，网关把源地址改成组的中转地址，枢纽按源地址送进当前成员，成员把它 DNAT 到自己的隧道解析器。

- 自动化回归（`go test ./internal/compile ./internal/validate`）：`TestGroupDNSSmartDNS`（每组一个上游、只有组解析地址、mark 是十进制、钉死 / 解锁移动 / 不可切换组仍用成员解析器、国内解析器不在任何组上游里、默认组里只有默认地区组的上游）、`TestGroupDNSGatewaySNAT`（SNAT 在一组包上求值：只有组 mark + 组解析地址 + 53 被改写；局域网和设备入口对解析地址一律丢弃；带 mark 的出路只有西向隧道和黑洞）、`TestGroupDNSExitDNAT`、`TestGroupDNSHubPath`、`TestGroupDNSAbsentWithoutSwitchableGroup`、`TestGroupResolverAddresses`、`TestGroupResolverReserved`，以及验收脚本的桩测试。它们只证明生成结果。
- 成员的 Mesh 腿（机制见架构「地区组的解析」第 7 条）：`TestGroupDNSExitDNAT`（出口在枢纽的直连隧道和 Mesh 腿两个接口上应答组解析地址，`mmesh` 上不应答；旧结构的标记 `0x4d6d`、锚地址和 `group_dns_mesh_*` 链都不再出现）、`TestMeshExitReturnAndVeth`（回包按入接口的连接标记从来的那条腿回去）。命名空间：`TestNetnsMeshLeg` 里一条组解析查询经 Mesh 腿到达出口并得到应答。
- 隔离 Linux 集成：`TestNetnsGroupDNSFailover`（上面「每个命令能证明什么」）。成员切换部分 2026-11-13 在一台 Debian 13 上跑通（见已存档的执行记录）；去掉旧 Mesh 阶段后的版本 2026-11-16 在开发机的特权 Linux 容器里通过。它用的是编译出的规则和脚本，但成员出口上的解析器是替身，隧道是 veth：真实出口上的解析器、真实枢纽和带客户端的真实故障切换仍是待人工签收。
- 网关本地（`meridian-verify.sh`）：`group_dns_snat`（已加载的主表里每个可切换组都有解析 SNAT）、`group_dns_upstream`（`/etc/smartdns/smartdns.conf` 里每组有带十进制 mark 的上游，出现十六进制 mark 即 FAIL）、`group_dns_route`（`ip -6 route get <解析地址> mark <组 mark>` 落在网关的隧道接口上，落到局域网口、黑洞或不可达都是 FAIL）。它们看不到成员是否应答。
- [ ] 实机（待人工签收）：选一个可切换组，把它当前成员的隧道和解析器都停掉，等枢纽切换（`/run/meridian/group/<组>/active` 变成备成员）；在测试机上解析一个此前没解析过的、命中该组规则的名字，能得到地址并能打开，`ipleak` 显示备成员的出口；同时在网关局域网口抓包，没有这个名字的查询发往国内解析器或 ROS。再把组内成员全部停掉：这个名字解析失败（不是从别处得到答案）。
- [ ] 升级顺序：先下发出口和枢纽，再安装网关。网关先装、出口还是旧版本时，组内新名字解析失败，这是预期的（不回落）。
- [ ] 实机（待人工签收，需要真实 Cloudflare Mesh）：见下面「Mesh 腿」一节的实机步骤；组解析不再经 `mmesh` 应答，Cloudflare 上不应再有任何 `fd66::53:<k>/128` 路由（旧部署留下的要撤回）。

`docs/evidence/` 下 2026-11-12 的存档早于这一改动，不覆盖它。2026-11-13 的存档是加入它之后的最后一次构建：`meridian-verify.sh` 的日志里有 `group_dns_*` 三项（共 47 项本地检查），`netns-group-dns.log` 是上面那个命名空间测试的通过记录，另有一次用真实 SmartDNS 观察出站路径的手工核对（见该目录的 README）。真实出口、真实枢纽和带客户端的故障切换不在其中。

### Mesh 腿：WireGuard 架在 Mesh 上（密封、路由、回程）

> 修订 5 起不再编译和安装 sidecar：本节和下面「面板部署 Mesh」中关于 sidecar、veth、表 170、`meridian-mesh-up.sh`、发布路由的条目只适用于旧部署的撤回；主机级节点见「主机级 Mesh 节点」。`TestMeshSealOnlyWireGuardUnderlay`、`TestMeshUpSealFollowsSidecarBlock` 已删除，`TestNetnsMeshLeg` 仍基于旧 sidecar 结构，未针对主机级节点改写（需要 Linux root）。

结构见架构「Mesh」→「Cloudflare Mesh：WireGuard 的底层承载」。`mmesh` 仍是以太网 veth（`169.254.66.1/30` ↔ `169.254.66.2/30`，`fe80::66:1` ↔ `fe80::66:2`，固定 MAC 和永久邻居），但上面不再有任何默认路由：只有枢纽到各出口 Mesh 专用地址的 /32（`via 169.254.66.2 dev mmesh`，密封后才装，后面有黑洞）。

**没有 Mesh 边的拓扑逐字节不变**（单独断言，不与带 Mesh 边的金样共用文件，也没有更新开关）：`go test ./internal/compile -run TestNoMeshCompileUnchangedByMeshTransport`。十份拓扑（示例去掉 Mesh 边后的四个变体——原样、打开嗅探、带组解析规则和解锁决定、远程接入——及其写入分配表后的形态；主备枢纽及其打开嗅探；多中继分担；嵌套出口；外部出口）每份的全部文件（含网关）摘要等于改动前的编译器（提交 `516d115`）生成的值，并且文件里没有任何 Mesh 腿的痕迹。`TestCompileUnchangedSinceBeforeTheLogs` 里另外四个没有 Mesh 边的示例的摘要也没有动。

自动化回归（`go test ./...` 会跑）：

- 模型与分配（`internal/model`）：`TestMeshUnderlayAllocation`（每个有 Mesh 边的出口一个序号、一个 /32；没有 Mesh 边的拓扑没有 Mesh 分配表，存储的文档不变）、`TestMeshUnderlaySlotsAreStable`（增删、停用别的 Mesh 边不移动地址；删除的序号退休；客户端送回的表不能改已有分配）、`TestMeshUnderlayPrefixAndAddr`、`TestMigrateAllocationsIsPositions`（旧文档里 Mesh 链路排在别的链路之后取号）。
- 校验（`internal/validate/mesh_test.go`）：`TestMeshLegacyRoutesRefusedWithMigration`（带 `mesh_routes` 的链路被拒绝，消息含迁移步骤；清空后通过）、`TestMeshUnderlayPoolConflicts`（地址池与 `10.66.0.0/16`、中转前缀、`100.96.0.0/12`、`169.254.66.0/30`、局域网、节点局域网、手工隧道地址、节点端点、远程接入地址池重叠，公网段、IPv6、非网络地址、过宽过窄都被拒绝；没有 Mesh 边的拓扑不受这个设置影响）、`TestMeshUnderlayAddressesDoNotOverlapPlans`、`TestMeshLegStructure`（重复、缺直连腿、不支持的出口类型、备用枢纽）、`TestMeshLegEndsAndPorts`（NAT 拨出的出口照样由枢纽拨、出口监听；不占用也不扰动 `listen_port`；别的链路的端口不变）、`TestNATDialOutExitMeshEdge`、`TestMeshAllocationTableChecks`。
- 编译（`internal/compile/mesh_transport_test.go`）：`TestMeshLegIsAWireGuardLeg`（枢纽的 Endpoint 是出口的 Mesh 地址、出口监听、不出现出口的公网端点）、`TestMeshExitEgressIsTheExitsOwnUplink`（出口表指向 WireGuard 接口；出口的公网 NAT 和解析器配置与没有 Mesh 腿时相同）、`TestMeshNoDefaultRouteOntoVeth`（所有节点的所有脚本里没有指向 veth 的默认路由；枢纽建 WireGuard 接口之前先装黑洞、先密封后跑路由脚本；所有枢纽的 `group_hop` 拒绝 `mmesh`；组策略的 Mesh 项恒为 0）、`TestMeshPublishesOneAddressPerExit`、`TestMeshExitReturnAndVeth`、`TestMeshLegWithBackupHub`、`TestMeshLegWithSharedHops`、`TestMeshLegChangesOnlyItsEnds`（加一条 Mesh 腿只改变枢纽、该出口和网关的钳制）、`TestMeshEdgesDoNotMoveOtherLinks`。
- 带桩的 bash：`TestMeshSealOnlyWireGuardUnderlay`（运行编译出的密封块：表 170 只有对端地址的路由和 unreachable；转发链只放行每条腿的地址和端口；旧版留下的复制路由、回程路由被删除；没有 WARP 设备时全部丢弃）、`TestMeshUnderlayRoutesFollowTheSeal`（密封时装 /32，未密封或没有 veth 时删掉只留黑洞，清掉经 sidecar 的别的路由，不碰任何策略表）、`TestHubGroupHopRefusesMeshVeth`、`TestMeshUpSealFollowsSidecarBlock`。
- 部署计划与配置核对：`go test ./internal/mesh -run 'TestPlan'`（每个出口只计划一个 /32，带旧 `mesh_routes`、地址落在保留段、编译文件的发布行与拓扑不一致都拒绝出计划）、`go test ./internal/verify -run TestMeshItemsNeverClaimForwarding`（配置核对里任何指向 veth 的默认路由、缺黑洞都判失败；转发证据永远不由配置核对给出）。

隔离 Linux 集成：`TestNetnsMeshLeg`（上面「每个命令能证明什么」）。2026-11-16 在开发机的特权 Linux 容器里通过，原始输出在 `docs/evidence/2026-11-16-netns-mesh-leg/`。第一次运行时它抓到一个真实问题：Mesh 腿的接口一建好就发握手，而到出口 Mesh 地址的黑洞当时要等路由脚本才装，握手包从枢纽的默认路由漏出去一个；现在 `meridian-up.sh` 在建 WireGuard 接口之前先装黑洞，测试按同样的顺序执行并断言 Internet 侧一个这样的包都没有。

**实机人工签收（待签收；需要真实 Cloudflare Mesh，由主会话先在一个出口上做）：**

- [ ] 部署：拓扑里给一个出口（先做美国）加一条待命的 `cf_mesh` 边，保存后在链路上看到分配的 Mesh 地址；下发枢纽、该出口和网关；在 Cloudflare 页部署 Mesh。Cloudflare 上该出口的节点只有一条 /32 路由（面板部署记录里 `purpose: wg_underlay`），枢纽节点没有路由，没有默认路由，没有 `fd66::53:*` 路由。
- [ ] 密封：两台主机上 `/run/meridian/mesh-sealed` 存在；`nsenter` 进 sidecar 看 `ip route show table 170`（枢纽：对端 /32 和 unreachable；出口：`100.96.0.0/12` 和 unreachable）和 `nft list table inet meridian_mesh`；记录 WARP 设备的名字和 `ip -d link` 的类型（脚本按 `link/none` 认它）、sidecar 里 `ip rule` 的全部内容（确认 WARP 自己的规则没有抢在「出口地址交给宿主」之前）。
- [ ] 承载：枢纽上 `wg show <Mesh 腿接口> latest-handshakes` 有近期握手，`ping -I <Mesh 腿接口> <出口在这条腿上的隧道地址>` 通；出口上 `wg show <接口> endpoints` 显示对端是 `169.254.66.2:<端口>`。枢纽 WAN 口抓包，没有发往 Mesh 地址或 Mesh 腿端口的包。
- [ ] 出口 IP：在枢纽上手工把该出口的表指到 Mesh 腿（`ip route replace default dev <Mesh 腿接口> table <出口表>`，IPv6 同样），测试机访问显示出口 IP 的站点，看到的是**这个出口自己的公网地址**（与直连腿相同），不是 Cloudflare 的；解析一个命中该出口规则的新名字成功。恢复原路由（重新运行路由脚本）。
- [ ] 分片：经 Mesh 腿 `ping -M dont -s 1188`（1216 字节）和 `-s 1252`（1280 字节）到出口后面的地址；后者不通说明 Mesh 不放行分片，把结果记下（TCP 不受影响；可把链路 `mtu` 调到实际路径值）。
- [ ] 撤回：Mesh 撤回后枢纽上 `ip route get <出口 Mesh 地址>` 是黑洞，直连腿不受影响。

在这些存档之前，Mesh 数据面在代码、面板和文档里都是 **未验证**。面板部署的结果「路由已发布」只表示 Cloudflare 路由已经发布，不等于「Mesh 可用」。部署流程按共享 sidecar 和逐腿发布 / 撤回记录；下面「面板部署 Mesh」的清单里凡是提到 `mesh_routes`、组解析路由的条目按新结构理解：计划阶段现在拒绝的是带 `mesh_routes` 的链路、落在保留段的 Mesh 地址、与拓扑不一致的发布行。

### 面板部署 Mesh（资源 → Cloudflare → Mesh 部署）

- [ ] 账户：account id + API token 存在 `meridian-secrets` 卷（`<secrets>/index.json` 与 `secrets/<id>-<代>.json`，0600，目录 0700），任何接口都不回显 token；权限比 0600 宽的文件会被拒绝使用。还有已发布或补偿未完成的部署时不能删除这个账户、不能改它的 account id、不能把 Mesh 切到别的账户；同一账户可以替换 token。旧的 `mesh/cloudflare.json` 在升级时迁移成账户 `cf-mesh` 并删除。
- [ ] 「检查权限」只调用只读接口：结果是令牌有效、可读节点和路由，写权限显示「未确认」；被拒的接口列成缺少的权限。
- [ ] 计划里任何节点没有关联「就绪」的服务器（缺凭据、缺已确认指纹）时，部署 409 `servers_not_ready`，一个阶段都不执行。
- [ ] 计划阶段报出：Mesh 边还带着旧的 `mesh_routes`、出口的 Mesh 专用地址与 `10.66.0.0/16` / 局域网 / `100.96.0.0/12` / veth 链路重叠、出口没有分配到地址、编译出的发布行与拓扑不一致、拓扑地址落在 `169.254.66.0/30`。有任何一项时「部署 Mesh」不可点，后端也会在计划阶段停下，不碰任何主机和 Cloudflare。
- [ ] 预检报冲突（已有 `mmesh` / `meridian-mesh` 容器 / `meridian_mesh_lib` 卷 / 非空令牌、`169.254.66.0/30` 或 `fe80::66:1/2` 已被占用、枢纽脚本仍是 `default dev mmesh`）时停下，Cloudflare 没有任何调用。
- [ ] 健康检查不过（任一下一跳不通、`mmesh` 上出现别的邻居、warp-cli 未连接、Cloudflare 节点不是 healthy）时，没有任何路由被发布，本次创建的节点和 sidecar 被撤回。
- [ ] 故障注入演练：面板进程带 `MERIDIAN_MESH_FAULT_INJECTION=1` 启动后，对每个阶段选「在该阶段后失败」各跑一次：后续阶段都是「未执行」，Cloudflare 上本次创建的节点 / 路由都被删除，主机上的 `mesh-sidecar.compose.yml`、`meridian-mesh-up.sh`、`mesh.env` 恢复成部署前的内容，别人的节点和路由不动。
- [ ] 部署后删掉拓扑里的某个 Mesh 节点再撤回：面板仍连接部署记录固定的服务器、凭据、地址并要求原主机指纹；被固定的服务器不能删除或改地址 / 端口 / 用户 / 凭据（409 `in_use`），凭据可以原地轮换；把同一地址换成另一台机器（指纹变了）时撤回被拒绝、记录保留为「补偿未完成」。发布后把 Mesh 切到另一个 Cloudflare 账户被拒绝（409 `account_locked`），同一账户换 token 可以。
- [ ] 补偿失败（例如撤回路由时 Cloudflare 报错、SSH 不通）时，面板单独列出没撤回的资源，状态是「补偿未完成」，不能开始新部署；修复后再点「撤回 / 重试补偿」，已完成的步骤不会重复。
- [ ] 部署记录 `mesh/deploy.json`（0600，schema 3）里有每个阶段的状态、本次拥有的外部资源（Cloudflare 节点 id、路由 id、写过的主机）和固定的服务器 / 凭据 ID，没有 API token、节点令牌、SSH 密码或私钥。

### 检测主机上已有的 Mesh 节点（N1；自动化用合成输出，实机未验证）

- [x] 自动化：`internal/mesh/warp_test.go`（模式、账户一致/不一致/未知、Mesh 地址缺失或越界、表/优先级/标记/全局默认路由冲突、ix 无 Docker、低内存、输出不完整、桩命令运行脚本）、`internal/api/mesh_test.go` `TestMeshDetectHostNodes`、`web/src/host_mesh.test.tsx`。
- [ ] 实机（主会话，先 ix ↔ us-west）：us-west 检测为 `existing_node`、地址在 `100.96.0.0/12`、接口名正确；账户与面板选定账户比对结果（warp-cli 是否给出账户 ID）；共存核对无误报；ix 显示主机级 Linux 节点的安装计划（源可达性在 ix 自身实测）并要求确认；检测前后主机上 WARP 设置、规则和文件不变。

### 主机级 Mesh 节点：面板安装 Linux connector（修订 5；自动化用合成数据与桩，实机未验证）

- [x] 自动化：`go test ./internal/mesh`（`TestParseHostMesh` 安装计划只有 `host_connector`、完整安装内容与各阻断条件，`TestDetectScriptStubs` 源检查用桩 curl；`connector_test.go`：安装脚本固定、令牌只在一个 heredoc 和 0600 临时文件里、坏参数拒绝、撤回脚本按标记逐项撤销、安装失败补偿、新装节点记为 panel-owned 且撤回后过期、旧 sidecar 记录只能撤回；`TestDeployHappyPathOrderAndUnverifiedDataplane` 阶段顺序、无路由、腿 `pending_provision`；`lifecycle_test.go` 共享主机节点的增量与逐腿撤回、中断恢复；`TestMeshReuseExitOnlyInstallsConnectorOnHub` 沿用端不被触碰、未确认或被阻断的安装停止）、`go test ./internal/compile -run 'Mesh|Golden'`（`TestMeshReuseCompile` 四种所有权组合、`TestMeshHostUnderlayFollowsWARPInterface` 带桩 bash：接口消失时路由被删只留黑洞、待安装腿从不装路由）、`go test ./internal/api -run 'Mesh|Demo'`（`TestMeshDeployReusesExistingExitNode`：确认后安装、panel-owned 记录、撤回后过期）、`web/src/host_mesh.test.tsx`。
- [ ] 实机（主会话，先 ix ↔ us-west）：在面板进程设置核对过的 `MERIDIAN_CF_REPO_KEY_FPR`；检测 ix 为 `no_node` 且源可达、系统/架构受支持；预检确认页列出的源、指纹、包、服务、内存；部署后 ix 上 `warp-cli` 为 connector、`CloudflareWARP` 有 `100.96.0.0/12` 地址、表 65743 无默认路由、`ip rule` 与 Meridian 无冲突；us-west 的注册与设置前后不变；重新下发枢纽与出口、再部署一次后腿为已发布；经 Mesh 腿握手、最终公网地址与直连腿一致；拔 WARP 接口时外层包被黑洞、不从默认路由出去；撤回后 ix 上只移除面板装的包/源/key/注册，us-west 不动。
- [ ] 未验证：令牌在 `warp-cli connector new` 运行瞬间出现在主机进程参数里（主机本地）；`apt-get purge` 后的残留；内存估计。

## 服务器、密钥与 Cloudflare 账户

- 自动化回归（`go test ./internal/credentials ./internal/sshexec ./internal/api`）：存储权限与原子写、轮换、引用；指纹状态（未见过 → 发现 → 确认 → 不符）；发现不认证、指纹不符在认证之前拒绝、部署固定的指纹与目标；密码 / 私钥 / 口令从输出和错误里去掉；`sshtest` 进程内 SSH 服务器上的连接测试与下发（密码和带口令的私钥两种凭据）；Cloudflare 权限检查用假 HTTP 服务。
- [ ] 实机（主会话）：对一台真实远端服务器做一次「发现 → 核对（与远端 `ssh-keygen -lf` 一致）→ 确认 → 测试」，再「下发」；改远端主机密钥后连接在认证之前被拒绝。
- [ ] 实机（主会话）：真实 Cloudflare 账户的权限检查结果与令牌实际权限一致；缺写权限时部署在「创建节点」阶段失败并被补偿。
- 自动化回归（`go test ./internal/sshexec -run 'RateLimited|PreBanner|Pool'`、`go test ./internal/api -run 'TestSSHFlowReusesOneLogin|TestSSHRateLimitedAcrossOperations'`）：`sshtest` 的 `RefuseBeforeBanner` 模式在 SSH 版本行之前写一行 `Not allowed at this time` 并断开；发现、测试、预检、下发、枢纽读取、Mesh 远端操作都报 `ssh_rate_limited`（不是 EOF、不是登录或指纹问题），没有尝试凭据、固定指纹不变，冷却期间不再建立 TCP 连接（按接受的连接数计），冷却过后恢复；别的握手前文字附在说明里、不触发冷却。连接复用：连接测试 + 两次预检 + 下发脚本只有一次登录；一次下发请求、撤回计划 + 执行共用一次登录；轮换密码、换凭据、改用户、清除并重新确认指纹、部署固定的指纹不同时都不复用；修改服务器、轮换凭据立即关闭空闲连接；命令失败、空闲超时、超过最长存活、取消的操作都关闭连接。`npm --prefix web test`：限速时连接测试和「获取指纹」按钮显示倒计时并停用、预检对话框的「重新预检」和执行停用、端口冲突结论链接到拓扑里对应的链路字段、链路编辑器里的「wstunnel 本地端口」、出口节点的「WSS 监听端口」。
- [ ] 实机（主会话）：**限速识别和连接复用都还没有在真实主机上运行过。** 在经端口转发、OpenSSH 9.8+ 的服务器上，「测试连接 → 预检 → 下发」只产生一次登录（服务器 `journalctl -u ssh` 里一条 `Accepted`），被限速时面板显示「服务器暂时拒绝面板的来源地址（限速）」而不是「SSH 握手失败：EOF」，倒计时结束前不再连接。

## 下发前预检

预检只读；除了下面单独写明的 2026-11-13 只读运行，以下都是仓库里的自动化证据，没有在真实主机上执行过。

- 自动化回归（`go test ./internal/preflight`）：脚本参数校验（所有示例节点的路径都接受；`..`、相对路径、shell 元字符、引号、空格、换行、通配、目录外路径、超长、超量、重复一律拒绝）；脚本 `bash -n`（装了 shellcheck 时也跑）；静态检查脚本里没有任何改动主机的命令或写文件的重定向；在本机用 `bash -s --` 真跑一遍脚本，报告完整、被拒参数由脚本自己拒绝、不含文件内容；解析器对垃圾、截断、超长、超行数、控制字符 / 双向控制符 / 非法 UTF-8、伪造路径、清单块外的清单行、结束行之后的内容的处理；评估器对夹具 `testdata/*.txt`：干净的 Debian 13、Debian 12（可用内存约 200 MB）、Ubuntu 20.04 aarch64（支持的平台：无 nft 时 nftables 列进安装计划、legacy iptables 不切换、内存 440 MB；Docker 的 FORWARD DROP 仍阻断）、Docker `FORWARD DROP`（iptables-nft 与纯 nft 两种来源，每个协议族只报一次）、已有 `wg0/wg1/wg2`（51820 被占、10.66.11.0/24 与 10.66.0.0/16 重叠、10.67.0.0/24 与 10.8.0.0/24 不误报）、443/80 被 nginx 占用和另一个 wstunnel、53 端口（resolved / WARP 不冲突，通配或同地址冲突）、主机级 WARP（规则排在 main 之前）、空中继（转发将被打开）、忙中继（端口转发器不误报）、root / 架构 / 内核 / systemd / 发行版与支持平台矩阵 / apt 与包候选 / 面板下发二进制的可用性、按架构选择和「已是固定摘要不传输」 / 内存预算 / 解析器绑定、清单三种归属与旧版标记文件、journal 中断与带残留的补偿、网关模式（安装清单的归属、标记文件交给接管、防火墙标记冲突）。
- 自动化回归（`go test ./internal/provision`）：下发脚本在本机沙箱里（主机路径挪到临时目录，`ip`、`nft`、`systemctl`、`wg-quick`、`apt-get` 等换成有状态的桩）真跑：成功写受管清单并能被预检读回；同一节点的更新通过复核、别的节点被 `manifest_changed` 拒绝、第一次下发遇到已有清单被 `manifest_appeared` 拒绝；`systemctl` 失败时补偿（新文件和目录删除、被替换的文件恢复、新接口和 nft 表删除、单元停用、sysctl 恢复、软件包保留并列出、journal 为 `compensated`）；接口删不掉时列为残留、journal 为 `incomplete`，再跑被脚本自己拒绝；没有绑定目标的脚本拒绝运行。
- 自动化回归（`go test ./internal/api -run 'Preflight|Provision|LoginHelp|Gateway'`）：计划视图里的目标身份、受管资源和变更；第一次下发缺 `preflight_id`、过期、记录被替换、包摘要变化、目标身份变化（换凭据）、审阅结果有阻断、执行前重跑出现阻断、出现新警告都被拒绝，且都没有生成密钥、没有发送下发脚本；通过时脚本绑定到预检（`M_EXPECT`、`M_BUNDLE`）；之后的更新照样重跑预检；补偿 / 残留 / 远端复核拒绝 / 没有成功标记各自的代码和 `outcome`；响应、日志和数据目录里没有密码和私钥；登录方式不被接受时给出公钥；网关安装的第一次必须预检、阻断时不激活、宿主代理不支持预检时 503。`go test ./internal/hostexec -run Preflight`：网关预检动作只运行固定的只读命令、不回传文件内容、拒绝坏路径和未知字段、输出触顶时报告不完整。
- 自动化回归（`npm --prefix web test`）：远端节点的预检对话框（目标、按严重度分组的发现和处理办法、变更清单、阻断时执行按钮不可用并写明原因、重新预检后带 `preflight_id` 执行、执行前复核出现新问题时留在对话框里显示新结果、残留与保留项、登录帮助里的公钥）；网关第一次安装前必须预检、带 `preflight_id` 安装；服务器页连接测试失败时显示可复制的公钥。
- [ ] 实机（主会话）：对每台真实服务器先「预检」，核对报告与 `ss -lntup`、`ip rule`、`nft list tables`、`iptables -S FORWARD` 手工结果一致；有 Docker 的出口：`forward_policy_drop` 在有 DOCKER-USER、没有 ufw / firewalld 时为警告并列出规则（否则阻断）；没有阻断的服务器下发成功并写出 `/var/lib/meridian/node/manifest`；之后的预检显示 `existing_install`。
- [ ] 实机（主会话）：在一台可以随意重装的服务器上制造一次失败的第一次下发（例如先让 `smartdns.service` 起不来），确认补偿后主机回到下发前（接口、nft 表、规则、文件、sysctl），journal 为 `compensated`；断开 SSH 中途的情形单独验证。
- 自动化回归（`go test ./internal/preflight -run 'UpdateOfOwnInstall'`、`go test ./internal/api -run TestGatewayUpdateGateOnOwnInstall`）：脱敏的实机网关报告（已有安装、SmartDNS 是 compose 容器、wstunnel 客户端是安装的单元、lo 上的中转地址，进程名不可见、按 cgroup 归属）评估为非阻断，更新安装经重新预检后通过；旁边多一个别人的 :53、别的容器、清单外的单元、读不到 cgroup、没有清单（第一次）都仍然阻断；远端「本节点、本面板」更新（枢纽、中继、出口）非阻断，换成别的部署 ID 全部阻断。
- [ ] 实机（主会话）：网关上「安装前预检」经 `meridian-host` 的 `/v1/preflight` 得到完整报告（需要先升级宿主上的 meridian-host）。
- 已发生的实机运行（主会话，2026-11-13，只读）：预检从面板对 11 台真实服务器和网关各执行过一次，拦下了 Docker 把 FORWARD 设为 DROP 的主机、51820 被已有 WireGuard 占用的主机、Ubuntu 20.04、缺 wstunnel 的中继，并对低内存主机给出提示；暴露的「网关把自己的资源报为冲突」随后修复并在网关上复跑为非阻断（归属 `same`）。没有在任何真实主机上下发、补偿或撤回。
- 自动化回归（`go test ./internal/preflight -run 'Port'`、`go test ./internal/validate`、`go test ./internal/api -run TestGatewayPortConflictNamesTheField`）：每个示例节点的端口计划与它编译出的包读回的监听完全一致；`existing-wireguard` 夹具上 51820/51821 被占时结论带指向链路 `wg_port` 的 `fix`，把端口改掉后监听端的配置、拨号端的 `Endpoint` 和预检读出的监听一起变化，冲突消失；节点 `listen_port` 只在唯一一条没设 `wg_port` 的链路上生效；同一节点自己的端口冲突、保留端口、`listen_port` 二义都被校验拒绝；网关的 wstunnel 本地端口被占时结论指向链路 `wss_local_port`，改掉后包摘要变化、不再阻断。
- [ ] 实机（主会话）：在一台 51820 已被占用的真实服务器上，按预检结论的「去拓扑修改」换端口，重新预检不再报 `port_in_use`，对端（网关或枢纽）重新安装 / 下发后握手成功。

## 与已有业务共存（Docker FORWARD DROP、开机恢复、内核参数范围、nftables 整表清空、WARP）

以下机制**没有在任何真实主机上执行过**；只有仓库里的自动化证据。Linux 网络命名空间测试 `TestNetnsFWCompatDockerUser` 写好了但**没有执行过**（这里不能运行；它只保证能编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /dev/null ./internal/compile`）。

- 自动化回归（`go test ./internal/provision -run 'FWCompat|SysctlScope|Flushing'`）：沙箱里用有状态的假 `iptables` / `ip6tables` 真跑下发：IPv4 FORWARD DROP + DOCKER-USER（iptables-nft 的空链和 legacy 的 `-j RETURN` 两种形状）时 Meridian 的两条规则插在链顶、你自己的规则和 RETURN 原样在后面，IPv6（策略 ACCEPT、没有链）什么都不加，没有任何 `-F` / `-P` / `-X` / `-N` 或对 FORWARD、Docker 链的调用；清单有 `fw ipv4|ipv6 DOCKER-USER`、两个新单元和脚本；开机单元和 Docker 单元只 `enable`，不启动；模拟 Docker 重启（链里只剩 Docker 的东西）后 `meridian-fwcompat.sh apply` 加回、再跑一次不重复；IPv6 后来变成 DROP 时加上、变回 ACCEPT 时删掉；撤回只删带 Meridian 注释的规则（你的规则、RETURN 和注释形状不对的「像」规则都在）、先停用 `meridian-fwcompat.service`；旧规则集（另一个注释）被替换；DROP 而没有 DOCKER-USER 时 `meridian-up.sh` 在打开转发和建隧道之前失败，下发补偿；第一次下发失败时补偿删掉这次加的规则、规则删不掉时列为残留（journal `incomplete`）；用记录调用的假 `sysctl` 跑编译出的脚本，写到的键**正好**是受管接口（m14）、拓扑网卡（eth0）、`all.send_redirects` 和两个转发键，沙箱里另放的 `docker0`、`CloudflareWARP`、`veth…` 一个都没碰，补偿只恢复记录过的键；`/etc/nftables.conf` 有 `flush ruleset` 而服务启用时脚本在改动任何东西之前拒绝（`nftables_flush_on_reload`）。
- 自动化回归（`go test ./internal/preflight -run 'DockerUser|NFTFlush|WARP|SysctlPreview'`）：iptables-nft 和 legacy 夹具上 Docker 的 IPv4 DROP 变为警告、规则逐条列进变更、IPv6 ACCEPT 说明不加规则；两族都 DROP 时两族都加；IPv6 DROP 没有 ip6 DOCKER-USER 时 IPv6 阻断；没有 DOCKER-USER、没报告、ufw / firewalld 在运行、跳转之前有 DROP、不跳到 DOCKER-USER、别的 nft 表丢弃、网关：都阻断且写明原因；已有本节点规则的更新是「更新」不阻断；nftables.service 启用 + 配置清空、运行 + ExecStop 清空（远端和网关）阻断，启用但都不清空、没启用没运行、masked、未安装不报告；WARP 夹具列出优先级 32765、表 65743 有默认路由、依赖线索（进程名、resolv.conf）、`2606:4700:cf1::/48` 地址，不冲突时为信息、Meridian 规则同优先级时阻断、带 Mesh sidecar 的包警告 `warp_sidecar_conflict`；sysctl 预览逐项列出全局键（含当前值）和只改的接口，没有「所有接口」。
- 自动化回归（`go test ./internal/compile -run 'NodeBootUnit|FWRules|SysctlScope|TransportHeader|GroupDNSExitDNAT'`）：每个远端节点的开机单元 `After=network-online.target nftables.service docker.service`、`Wants=network-online.target`、`WantedBy=multi-user.target`、oneshot；`meridian-up.sh` 不启动它自己，内部顺序是 nft → sysctl → DOCKER-USER 规则 → 转发 → WireGuard → 路由；Docker 单元 `BindsTo` / `After` / `WantedBy=docker.service`；规则只提到受管接口（出口才有 WAN，且 WAN 进只放行已建立的连接）；路由脚本的 `harden_sysctl` 是写死的接口表，不再遍历 `/proc/sys/.../conf/*`；远端 `99-meridian.conf` 除 `all.send_redirects` 外不写 all/default；远端规则集里没有 `th dport` / `meta l4proto {`（出口地区组 DNAT 和 Mesh 回程改成同义的 udp / tcp 两条）。`go test ./internal/mesh -run HostWARP`：主机上有 WARP 时 Mesh 部署预检报 `host_warp` 并拒绝。`go test ./internal/hostexec`：网关预检报告 nftables.service 的 ExecStop 是否清空；`meridian-guard.service` 和 `meridian.service` 排在 nftables.service 之后。
- 自动化回归（`npm --prefix web test`）：预检对话框单独列出要加进 DOCKER-USER 的规则、阻断的 nftables.service 带处理办法、WARP 依赖线索、sysctl 只改的接口，「受管资源」里有规则条数和注释、内核参数接口。
- [ ] 实机（主会话），下发前（只读）：`iptables -V`；`iptables -S FORWARD`、`ip6tables -S FORWARD`（第一行是策略，`-A FORWARD -j DOCKER-USER` 应在任何 DROP 之前）；`iptables -S DOCKER-USER`、`ip6tables -S DOCKER-USER`；`systemctl is-active ufw firewalld nftables docker`；`systemctl is-enabled nftables`；`systemctl show -p ExecStop nftables.service`；`grep -n 'flush ruleset' /etc/nftables.conf`；`nft list chains | grep -B2 'hook forward'`。和预检报告逐项对照。
- [ ] 实机（主会话），下发后：`iptables -S DOCKER-USER | grep meridian-fw-`（条数等于预检列出的，在链顶）、`ip6tables -S DOCKER-USER | grep -c meridian-fw-`（IPv6 策略 ACCEPT 时为 0）、`/usr/local/sbin/meridian-fwcompat.sh status`；`systemctl is-enabled meridian-node.service meridian-fwcompat.service`；`systemctl cat meridian-node.service`；从隧道另一端（枢纽）经这台出口访问外网能通（`wg show` 有握手、出口 WAN 上 `tcpdump -ni <wan> host <测试目的地>` 看到 NAT 后的包）；`sysctl -a 2>/dev/null | grep -E 'conf\.(docker0|CloudflareWARP|veth[^.]*)\.(rp_filter|send_redirects|accept_redirects)'` 的值与下发前一样。
- [ ] 实机（主会话），Docker 重启：`systemctl restart docker` 后 `systemctl status meridian-fwcompat.service`（active (exited)，日志里没有 failed）、`iptables -S DOCKER-USER | grep -c meridian-fw-` 不变、隧道转发仍通。
- [ ] 实机（主会话），重启主机：`systemctl is-active meridian-node.service`（active）、`systemctl is-failed meridian-node.service`（不应是 failed）、`journalctl -b -u meridian-node.service -u meridian-fwcompat.service -u docker.service -o short-monotonic` 里 meridian-node 在 docker 之后启动、`meridian-up-complete` 出现；`systemd-analyze critical-chain meridian-node.service`；`wg show` 有握手、规则在。
- [ ] 实机（主会话），撤回：之后 `iptables -S DOCKER-USER`、`ip6tables -S DOCKER-USER` 没有 `meridian-fw-`，Docker 自己的规则、你自己的规则、`-P FORWARD DROP` 都在；`systemctl list-unit-files 'meridian*'` 为空；`systemctl restart docker` 之后规则也没有回来。
- [ ] 实机（主会话），nftables：在一台 nftables.service 启用的测试机上预检应阻断；按处理办法改完（`systemctl disable nftables` + 重启，或改配置 + 空 `ExecStop=`）后预检放行。
- [ ] 实机（主会话），WARP：在三台跑主机 WARP 的出口上，预检列出的规则优先级和 `ip rule`、`ip route show table 65743 | head` 一致，依赖线索与 `ss -tnp state established '( dport = :40000 )'`、`grep nameserver /etc/resolv.conf` 一致；下发后 `ss -lunp 'sport = :53'` 里 meridian-smartdns 只在隧道地址上；在这些主机上部署 Mesh 被 `host_warp` 拒绝。
- 自动化回归（`go test ./internal/provision -run 'RAKept|KeepsAcceptRA|RechecksWAN'`、`go test ./internal/preflight -run 'RAPlan|WANInterface'`、`go test ./internal/compile -run IPv6ForwardingScope`）：IPv6 默认路由来自 RA、`accept_ra=1`、转发为 0 的沙箱里，记录调用的假 `sysctl` 看到 `net/ipv6/conf/eth0/accept_ra=2` 排在两个转发键之前，写到的键正好是受管键加这一个；记录文件让「重启时 RA 还没到」也先设 2；第一次下发失败恢复成 1 并删掉记录；`accept_ra=0` 时不打开任何转发；没有 RA 时不碰 `accept_ra`；不转发 IPv6 的出口（tw）既不碰 `accept_ra` 也不碰 IPv6 转发；撤回删记录、保留 2。预检计划里 `accept_ra=2` 排在 IPv6 转发之前，`accept_ra` 为 0 / 读不到时阻断。WAN：名字不对、没填而主机是 eth0（通过）、没填而主机是 enp0s6（阻断并写出 enp0s6）、IPv4 和 IPv6 默认路由分在两块网卡上（阻断），都带 `wan_interface` 的 `fix`；下发脚本对缺接口、默认路由不在它上面都在动手前拒绝。
- [ ] 实机（主会话），RA：在靠路由通告拿 IPv6 的出口上，下发前 `ip -6 route show table main proto ra`、`sysctl net.ipv6.conf.<网卡>.accept_ra net.ipv6.conf.all.forwarding`；下发后 `accept_ra` 为 2、`cat /var/lib/meridian/node/ra-accept`；过了路由通告的有效期（`ip -6 route show default` 里的 `expires`，或至少几小时）之后 `ip -6 route show default` 仍在、`ping -6 -c 3 2001:4860:4860::8888` 能通；重启后同样。
- [ ] 实机（主会话），WAN：网卡不叫 eth0 的主机上预检给出 `wan_interface_missing` 并写出真实网卡名；按链接填好后通过，下发后 `nft list table inet meridian` 里的 `oifname` 和 `iptables -S DOCKER-USER` 里的 `-o` 都是那块网卡。
- [ ] 实机（主会话），Ubuntu 20.04（legacy）：下发后 `nft -v` 为 0.9.3、`nft list table inet meridian` 加载成功（规则集被 0.9.3 接受的第一份真实证据）、`iptables -V` 仍是 legacy、`update-alternatives --display iptables` 未变。

## 撤回与恢复

以下都是仓库里的自动化证据（本机沙箱真跑脚本、进程内 SSH 服务器、模拟宿主上的真实 `meridian-host` 代理），**没有任何一项在真实服务器或网关上执行过**。

- 自动化回归（`go test ./internal/provision -run Withdraw`）：参数校验（节点 / 部署 / 服务器 / 运行 ID 的形状、模式与动作枚举、`run` 必须带 64 位摘要、`plan` 不带）和坏参数时脚本在做任何事之前拒绝；三种模式两种动作的脚本 `bash -n`（装了 shellcheck 时也跑）；`M_ROOT` 是固定字面量。沙箱里先用真的下发脚本装上节点 `tw`，再真跑撤回脚本：计划只读、摘要不符时 `plan_changed` 且什么都没改；撤回只删清单里的接口、单元、nft 表、规则、路由表、黑洞路由和文件，旁边的 `wg0` 接口和配置、`inet other` / `inet docker` 表、`other.nft` 不动，不卸载软件包；journal 为 `withdrawn`、清单删除；再计划 / 再执行都回答「已撤回」，之后第一次下发又能通过复核。别的节点、别的部署、别的服务器、清单里有 `eth0` 或 `/etc/cron.d` 这样的条目、没有清单的空主机都被拒绝且主机不变。下发后被改过的文件保留、接口删不掉时为 `withdraw_incomplete`，期间下发脚本以 `withdraw_incomplete` 拒绝，处理后同一份计划再执行完成。中断的下发（`incomplete` 改成 `running` 模拟被杀）由 journal 模式补偿、之后能再装；没有 `params` 的运行只关闭 journal；有动作没参数或工作目录不在时拒绝。旧版清理只处理带标记的固定路径（不带标记的 `m15.conf`、提到 Meridian 的 `ssh.service` 不动），清单变化后拒绝，并提示黑洞路由要人工查。
- 自动化回归（`go test ./internal/apply -run GatewayWithdraw`、`go test ./internal/hostexec -run Withdraw`）：网关撤回只删安装清单里的东西，`wg0` 和别的 nft 表不动；先关两种转发、再停 `meridian.service`、再删接口；兜底表和它的开机文件保留，从不删兜底表、从不打开转发；安装清单变为 `withdrawn`；再撤回只复查；撤回后运行态回滚被拒绝、重新安装可以；中途失败补偿回原来的运行状态；补偿也失败时 journal 保留（`kind withdraw`）、拒绝新的撤回，重启后恢复；没有安装 / 旧版 / 没有网关私钥（无法补偿）时拒绝且不动宿主；移除兜底表只在撤回之后、先关转发再删表。宿主代理：`withdraw` 拒绝点名兜底表、解析器、非受管名字；账本外存在的接口被拒绝；兜底表不在时重启 `meridian-guard.service`，仍不在就失败。
- 自动化回归（`go test ./internal/api -run 'Withdraw|RemovedExits'`）：部署记录绑定身份并固定服务器和凭据（改指向、删凭据 409）；计划 → 缺确认 / 计划不存在 / 计划重复使用被拒绝 → 部分完成（继续固定）→ 重新计划 → 完成（解除固定，下次下发要预检）→ 再计划回答已撤回 → 删除记录；脚本里只有校验过的身份值和计划摘要；节点改指到另一台服务器时新服务器上的预检被 `deployed_elsewhere` 拒绝、撤回仍去原服务器；忘记指纹、换成另一把指纹时拒绝且不发送脚本；远端拒绝（属于别的节点、没有清单）、结果不明、连不上都不算撤回；放弃要输入节点 ID、明说未核实；Mesh 记录还固定着节点时拒绝、Mesh 撤回后可以；中断的下发经 journal 模式恢复；网关撤回、再撤回、回滚被拒、移除兜底表、之后没有安装；解锁结果里已删除出口默认不列出、可选列出并标记、可清理，历史与准入记录保留。`go test ./internal/unlock -run RemovedExits`：标记已删除出口不改变准入，旧结果仍被 `out_of_order` 拒绝。
- [ ] 实机（主会话）：在一台可以随意重装、上面另外跑着 Docker 和一个自己的 WireGuard 接口的服务器上，下发 → 撤回，确认 `ip link`、`ip rule`、`ip route show table all`、`nft list tables`、`systemctl list-units 'meridian*'`、`ls /etc/meridian /etc/wireguard` 只少了清单里的东西，Docker、别的接口和别的 nft 表都在，软件包都在；再撤回一次显示「已撤回」。
- [ ] 实机（主会话）：撤回途中断开 SSH：服务器 journal 为 `withdrawing` 或 `withdraw_incomplete`，面板显示「撤回中断 / 结果不明」，再生成计划并执行能完成。
- [ ] 实机（主会话）：下发途中 `kill -9` 远端 bash，journal 停在 `running`；面板「恢复中断的下发」后主机回到下发前。
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
- [ ] 定时失败一次，自动规则不动。连续两次，才换成同池备成员。AI 仍在美国，Netflix / Disney+ 仍在香港住宅，台湾服务仍在 TW。
- [ ] 钉死的手动规则（示例 `api.example.com`）不跟着映射走。
- [ ] 池里没有成员能解锁时标成不可用，不会改到日本或别的国家。
- [ ] 切回首选前，首选已经再次成功，并且过了 30 分钟。
- [ ] 首选恢复成功之后又失败一次（定时或手动都算）：恢复计时清零，即使已过 30 分钟也不切回；之后要重新连续成功满 30 分钟。
- [x] YouTube Premium（`youtube-premium`）：2026-11-15 已在真实平台上复测，六个出口判为可用且地区正确（可用 / 地区这一项已对真实平台验证）。此前各出口返回未知的原因是介绍页约 1 MB、ad-free 第一次出现在约 850 KB 处，而检测只读前 256 KiB，正文被截断；这一步的正文上限改为 2 MiB（其他检测项仍是 256 KiB），请求带公开方法里的固定同意 Cookie（不带访客 / 会话标识）。仍未核实的：不可用地区的应答、要求同意的地区里固定同意值是否被接受。

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
  → runProbeJob：同时最多 exit_concurrency（默认 2）个出口
    → runProbeGroup（一个出口）：每个地址族一次 hostexec.Client.Probe（不重试）
      → meridian-host POST /v1/probe → probe.Prober.Run：出口检查 → 各平台适配器 → 再次出口检查
    → unlock.Ingest：每个服务一份 Observation，带这一轮全部地址族；在面板写锁内「读 → Ingest → 写」
```

- **只接受枚举值**：面板只能选 `internal/probe` 目录表里的适配器（目前 41 个）（每个适配器能给出哪一级结论、只做到达性的是哪些、哪些只发 IPv4，见 [unlock-methods.md](unlock-methods.md)「能力声明一览」）、拓扑里的出口和 `ipv4` / `ipv6`。请求体有多余字段（`url`、`command`……）直接 400。agent 侧 `ValidateProbe` 再校验一遍：出口 mark 必须在 `0x101`–`0x140`，中转地址必须在 `10.66.200.0/24` / `fd66:0:0:ff::/64`，解析器必须是 `fd66::/48` 里的出口隧道地址，服务必须在目录表里，最多 16 个。没有 URL、主机、端口、请求头、命令或路径参数；`MERIDIAN_UNLOCK_EXEC` 已删除，设置了也只会在日志里提示不再使用。
- **强制出口与地址族**：socket 带该出口的 fwmark（`SO_MARK`，需要 agent 的 `CAP_NET_ADMIN`），从该出口在 `lo` 上的中转地址发出，按地址族只用 `tcp4` 或 `tcp6`；名字经该出口的隧道解析器（ULA，同样带 mark 和中转源地址）只查 A 或 AAAA。网关上这个 mark 命中 `lookup 102`（默认路由是西向隧道，后面是 `unreachable`），国内中继和枢纽按中转源地址选出口，和局域网流量被 SNAT 之后走的路一样。本机发出的流量走 output 路径，不经过 `inet meridian_guard` 的 forward 兜底，所以每条连接前还要做路由检查：`ip -4|-6 route get <目的> from <中转地址> mark <mark>` 的出口设备必须是 Meridian 隧道接口（`m00`/`m00w`/`mmesh` 这一类），否则不连接。中转地址不在本机 `lo` 上（网关还没装这个出口）时什么都不发。
- **验证实际出口**：访问平台之前先请求固定的 `https://www.cloudflare.com/cdn-cgi/trace`，返回的公网地址必须是所选地址族，地区必须等于出口地区；拓扑里有该地址族的公网端点（`endpoint_v4` / `endpoint_v6`）时地址还必须等于端点。全部平台请求结束后再查一次，地址变了（例如枢纽把这张表切到了同池别的成员）整轮作废。出口确认不了的项一律是「探测失败」，从不作为平台结论。
- **结果类别**：网络可达（非平台判定）/ 平台明确解锁（带平台给出的地区和依据）/ 平台明确未解锁 / 探测失败（超时、传输错误、出口不对、地址族不对、取消）/ 未知（应答无法识别）。面板按服务、出口、地址族显示开始与完成时间、结果、平台地区、证据（状态码、主机和路径、命中的标记，不含查询串和正文）、出口确认、错误，以及入库结果。
- **入库规则**：解锁和网络可达记为成功，明确未解锁记为失败，`kind` 分别是 `scheduled` / `manual`，只有定时结果计入「连续两次定时失败」。一个服务在一个出口上这一轮所有地址族都没有平台结论（失败或未知）时，记为 `inconclusive`：不计失败次数、不会触发降级，但会立刻清掉首选的恢复计时，也不会被当成已知可用的备成员。同一轮里一个地址族有结论、另一个没有时，只有有结论的进入 Observation，另一个标「未入库：该地址族没有平台结论」。取消或超时的项不入库。定时任务开始时就把下一次定时推后一个周期；出口上的 `/api/unlock/report` 不再推动面板的定时。
- **限制**：每个服务 20 秒、每次 agent 请求 2 分钟（面板侧 150 秒）、整轮 15 分钟；同一时间只有一轮，同一轮最多 2 个出口并行，每个出口内最多 3 个服务并行，agent 同时最多 2 个探测；面板上可以取消，取消会断开到 agent 的请求，agent 随之取消探测。
- **与安装/回滚的关系**：探测不占 agent 的动作锁。`activate` / `rollback` 开始时取消正在跑的探测（最多等 15 秒）并在执行期间拒绝新探测（503），所以安装不会被探测拖住，也不会有探测流量和 `meridian-up.sh` 的重载交叠；`health` 只读，不影响探测。
- **凭据**：不接受也不保存任何流媒体或 AI 平台的 Cookie、账号或令牌；没有 cookie jar，固定请求头，证据里不带查询串、正文和 `Set-Cookie`。

自动化回归（`go test ./...`，只证明控制流和判定逻辑，不证明真实出口或真实平台）：

- `internal/probe`：各适配器对合成样例的判定（Netflix 403/404/200 地区一致与不一致/无标记、美国无前缀靠 requestCountry（256 KiB 之后、2 MiB 之内与之外）、误导的 countryCode、冲突标记、前缀与 requestCountry 不一致、只有语言的前缀，Disney+ unavailable/地区，OpenAI `unsupported_country`，Claude `app-unavailable-in-region` 与质询页，到达性服务从不给平台结论）；出口检查（地址族不对、地区是 CN、端点地址不对、什么都比不了）；用 httptest TLS 服务和假网络跑完整流程：路由不在隧道上时不建连也不碰平台、出口地区不对时不碰平台、v4 探测只拨 v4（解析器只有 AAAA 时失败而不是改用 v6）、v6 探测只拨 v6、v6 探测出口却是 v4 时失败、中途出口变化整轮作废、单服务超时不拖累其他服务、并发上限、取消、跨主机跳转不跟随、不回传 Cookie；非 Linux 上带 mark 的拨号一定失败而不是退回普通 socket。
- `internal/hostexec`：`ValidateProbe` 拒绝 `any` 地址族、越界 mark、非中转地址、公网解析器、URL 当服务名、重复/过多服务等；`/v1/probe` 要口令、拒绝多余字段；出口没装（`lo` 上没有中转地址）时不发任何东西；`ip route get` 解析出口设备，`unreachable` 是错误、`eth0` 不算隧道；`activate` 不等探测、会取消探测且被取消的探测没有平台结论；安装期间拒绝探测；`health` 不影响探测；并发上限；调用方断开即取消；客户端在 agent 不在时报 `ErrUnavailable`。
- `internal/api`：手动一轮按服务 × 出口 × 地址族生成项、请求带对出口的 mark / 中转地址 / 解析器 / 地区、每个出口一轮只推进一次状态且不计失败次数；定时与手动同链、结果真实入库、两次定时明确未解锁才降级、定时推后、没有 agent 时只记一条说明；无平台结论记为 `inconclusive` 且不降级、agent 声称解锁但出口未确认时降为失败；取消后不入库、同时只允许一轮、整轮超时；任意 URL / 命令 / 无适配器服务 / 非出口 / `any` 地址族被拒、出口不支持的地址族只记录不发送；探测入库与 10 份并发出口报告在同一把锁里都不丢、agent 并发不超过 2。
- `internal/unlock`：`inconclusive` 三次也不降级，但会清掉首选的恢复计时。

### 按地区探测、推荐与采用（P2）

做法见 [unlock-methods.md](unlock-methods.md)「按地区探测、推荐与采用」。

- `go test ./internal/probe -run 'ProbeScope|ServiceMatching'`：每个适配器要么全球（任何出口都测）要么地区（没有地区的出口不测）；KKTV 不在日本 / 香港出口上测；B-Global 属于多个东南亚地区；服务域名不匹配 `com`、`notnetflix.com`，共用域名（`google.com`）只认探测主机。
- `go test ./internal/api -run 'ScopedTargets|ScopedRunAll|MatrixRecommendation|UnlockAdopt'`：地区服务从不在别的地区出口上探测、全球服务在全部出口上探测、`scope` 与 `services` 不能同用；推荐优先规则当前指向的组、遵守住宅要求、稳定性和耗时排序、未测到 / 仅本地 / 过期结果不推荐；采用只改属于该服务的规则（规则 ID、主检查域名、自己平台名的规则集 / geosite；mihomo 标签不算；直连规则和无关规则不动），地区组把出口排到首位，推荐已变化时 409 且拓扑不变。
- `npm --prefix web test`：`src/pages_remote_unlock.test.tsx`「unlock by region」（按地区分表、没有复选框 / 服务组 / 失败关闭说明、格子文字与未测到原因、全部探测与分段探测的请求、采用后显示生效状态或部署链接并变成「在用」）；`src/layout_pages.test.tsx` 41 个服务 × 9 个出口的表格。
- `go test ./internal/api -run 'UnlockAdoptIgnoresSharedMihomoLabel|RulesRetarget'`：Netflix 与 Disney+ 规则同一 mihomo 标签，采用 Netflix 及其预览都不含 Disney+；按标签批量改目标仍同时移动两条。
- `go test ./internal/api -run 'TestIdentity'`：同一出口 ID 换端点后旧结果「未测」、推荐消失、采用与预览 409 且拓扑不变；无摘要的旧结果「未测」；执行中换目标再改回，这轮结果不带摘要、不入库，其他出口不受影响；旧任务晚完成不覆盖新结果；改名、坐标、私钥、SOCKS 凭据不改摘要、采用照常成功，SOCKS 目标、承载出口端点 / 公钥、服务器地址改摘要。
- `go test ./internal/api -run 'TestViu'`、`go test ./internal/probe -run 'Coverage|ServiceMatching|MultiCheck'`：香港 MyTV SUPER 解锁、Viu 不可用时两行各自正确，Viu 无推荐、采用被拒，采用 MyTV SUPER 不改 Viu 规则；Viu 无法判定显示「未测到」。
- `npx vitest run src/pages_remote_unlock.test.tsx`（单独执行）「unlock: evidence and Hong Kong services」：409 用现有错误提示、不显示「在用」；身份失效的格子「未测」且没有采用按钮；香港分段 MyTV SUPER 与 Viu 各一行，无法判定的 Viu 只显示「未测到」。演示数据：degraded 场景 myext 换 SOCKS 目标后结果「未测」；OpenAI 与 Claude 规则共用一个 mihomo 标签；Viu 独立一行。
- [ ] 真实网关：按地区探测一轮，核对香港 / 台湾 / 日本出口上地区服务的结论与人工访问一致；对一个全球服务点「采用」，确认规则生效后该服务的连接从推荐出口出去。

### 服务组自动选择与覆盖表（R4）

做法见 [unlock-methods.md](unlock-methods.md)「规则的自动选择」「调度与克制」「覆盖表」。

自动化回归（只证明控制流和判定逻辑，不证明真实平台或真实网关）：

- `go test ./internal/unlock -run AutoSelect`：可注入时钟下的失效切换（一次定时失败不动、手动失败不计、两次定时失败才换并记录原因和时间）、滞回切回（30 分钟连续成功，期间失败重新计时）、全部候选失效（留在默认出口、标不可用、不去没测过的成员）、钉死优先、结果过期（过期的成功不作为备选证据）、旧的未带时间的结果保持原含义。
- `go test ./internal/probe -run 'AdapterFixtures|Capability|CoverageTable|RegionsAndCost'`：新增 27 个适配器的合成应答（可用、不可用、地区不符、质询、限流、改版）；覆盖表每一项要么对应目录里的适配器（或其中的参考检查）要么有原因，每个适配器都在覆盖表和本文档里，每一步都是 https 且主机在固定名单里，请求头只用允许的名字。
- `go test ./internal/compile -run ServiceGroupDecision`：服务组决定把它的规则改到被选成员的 mark 和解析器（不是国内解析器），按规则 ID 写的决定无效，候选外的决定和固定服务组被忽略；切换前后每个被引用的 nft 集合都已声明、没有重复声明、清单里的地址集合都已声明，嗅探服务接受编译出的快照和目标文件；覆盖 IPv4-only 与双栈目标、嵌套出口、仅 TCP 的外部出口、地区组、单出口目标。
- `go test ./internal/api -run 'ServiceGroupAuto|ServiceGroupAll|UnownedAdapter|ScheduledBudget|AutoServiceGroupOwner|ProbeSplits'`：两个检测项的组合、两次定时失败切换、路由视图（候选证据、推算出口、原因与时间、调度设置）、改成固定后决定立即消失、全部失效时告警、没有关联的适配器只展示且不新增规则、每出口请求预算、内置规则与服务组同时决定同一服务被拒绝、超过 16 个服务时拆成多次 agent 请求。

- `go test ./internal/api -run AutoApply`（假宿主、可注入时钟）：设置关闭时什么都不变；条件全满足时经同一安装函数安装并记录、再次评估不重装、恢复后切回同样自动安装；逐一拒绝：安装前不同步、允许列表外的网关文件、别的节点的文件、预检阻断、节点锁被占；最小间隔与每日上限；安装失败被补偿、决定保持待安装、退避期内每分钟的评估不重试、退避后再试一次。`go test ./internal/compile -run DecisionChange`：各示例拓扑里决定改变只碰允许列表的文件。

实机（**未执行**，在存档证据之前一律算「未验证」）：

- [ ] 覆盖表新增的 27 个适配器（已对照固定提交的源码）在真实平台的可用 / 受限出口上各跑一次；U-NEXT 的缩短查询先确认平台接受。
- [ ] 在真实网关上把一个服务组设为自动：首选连续两次定时失败后面板显示待安装；安装后该服务组规则的连接和 DNS 都从被选出口出去（抓包，确认没有查询发往国内解析器）；首选恢复满 30 分钟后切回；所有候选失效时留在默认出口并告警。
- [ ] 默认设置下定时一轮对每个出口发出的平台请求不超过预算（agent 日志或抓包计数）。
- [ ] 打开 `auto_apply` 后在真实网关上让一个服务组切换：确认自动安装只替换了允许列表里的文件、已建立的连接如文档所述断开重连、DNS 重新学到地址后走新出口，失败时补偿成功且没有重试循环。

实机（Debian 13 网关，root，**未执行**；在存档证据之前一律算「未验证」）：

- [ ] `meridian-host` 新的沙箱（`RestrictAddressFamilies` 增加了 `AF_INET AF_INET6`，仍只有 `CAP_NET_ADMIN`）下 `SO_MARK` 可以设置、能绑定 `lo` 上的中转地址、能读系统 CA。
- [ ] 对每个出口、每个地址族点一次「立即测试」，面板「出口确认」里的公网地址就是该出口（在出口上 `curl -4/-6 https://www.cloudflare.com/cdn-cgi/trace` 对照），接口是西向隧道；同时在网关 LAN 口和 ROS 上抓包，没有任何探测流量（包括 DNS）从 `192.0.2.1` 出去。
- [ ] 把某个出口的西向隧道停掉（或删掉该 mark 的 `ip rule`）再测：结果是「探测失败」（路由检查或出口检查不过），不是平台结论，也没有流量走 ROS。
- [ ] 对没有 IPv6 出口能力的出口勾选 IPv6：只记录「未发出」；对有 IPv6 的出口，IPv6 一轮的出口地址是 IPv6，断掉出口的 IPv6 后是失败而不是改走 IPv4。
- [ ] 测试进行中在面板「安装到本机」：安装立即开始，测试项变成「已取消」，没有入库。
- [ ] 枢纽把某个池切到备成员期间测首选：有端点的出口应报「实际公网地址不是该出口的端点」；没有端点的出口（NAT 拨出、住宅）只能按地区确认，**同地区池内切换分辨不出来**，这是已知边界。
- [ ] 名字解析始终经出口隧道解析器的 ULA（IPv6 传输，带同一 mark 和中转源地址），IPv4 探测也是如此；该出口的 smartdns 没起来时整轮失败而不是改用本机解析器。Go 解析器会先看网关的 `/etc/hosts`，不要在网关上为这些平台写 hosts 条目。回程依赖网关 `rp_filter=2`（宽松），与局域网流量相同。
- [ ] 出口的出站公网地址和 `endpoint_v4` 不是同一个地址（多 IP 主机）时，该出口的面板探测会一直报出口不一致；需要人工确认后调整端点或接受这个限制。

真实平台行为（只能由人对照真实页面核实，仓库里没有向真实平台发过任何请求，全部 41 个适配器都基于公开的检测方法和合成样例（覆盖表新增的 27 个已在 2026-11-14 对照固定提交的源码，但同样没有请求过真实平台）；每个平台要核对的事项以 [unlock-methods.md](unlock-methods.md)「需要人工在真实平台上核对的事项」为准，下面只列最早的四个）：

- [ ] Netflix（`auto-netflix`）：自制剧标题 `81280792` 在非美国出口上重定向到 `/hk-en/`、`/tw-en/` 这类国家前缀路径，靠前缀判定（香港、台湾出口 2026-11-15 已在真实平台上用过）；仅自制剧地区 404，被封 IP 403。**美国出口未验证**：美国站点没有前缀，修改后靠页面内嵌的 `"requestCountry":{…"id":"XX"…}`（只认该对象自己的 `id`；前缀与它不一致、或多处取值不同 = 未知），步骤读取上限 2 MiB，已移除通用 `countryCode`。2026-11-15 观察（只是观察）：香港出口整页约 690 KB，`requestCountry` 在约 454,000 字节处，页面里没有 `countryCode`；美国出口上同一结构没有直接观察过。待做：在美国出口上确认给出可用，而不是未知（正文被截断或没有标记）；非美国出口的判定不变。
- [ ] Disney+（`auto-disney`）**2026-11-15 已在四个真实出口上验证地区判定**（主会话提供的事实：四个出口读到的所在地与出口地区一致）；下面的「待做」里其余各项仍未验证：2026-11-15 观察到首页约 1.95 MB，页面内嵌的 `"location":"XX"`（访问者所在地，与出口地区一致）在约 860 KB 处，紧跟的 `"region":"us"` 是固定值；此前的未知是正文被截断（只读 256 KiB）。判定已改为只读 `location`（紧跟 `pageId` 键），不再读 `countryCode` / `region` / URL 语言-地区前缀，这一步读取上限 2 MiB；只有固定 `region` 没有 `location` 时是「未知」。待做：各出口上给出可用（或地区不符）；不可用地区是否跳到含 `unavailable` 的路径。
- [ ] OpenAI：`api.openai.com/compliance/cookie_requirements` 在不支持的地区是否返回 `unsupported_country`（不带任何令牌时）；支持地区的应答只算网络可达。
- [ ] Claude：不支持的地区是否跳到 `/app-unavailable-in-region`；Cloudflare 质询会让结果变成「未知」。
- [ ] Gemini / Copilot / Perplexity / Grok：只说明经该出口能收到 HTTP 应答，不说明账号或地区可用。
- [ ] 平台对机房 IP 的 Cloudflare 质询、地区跳转和页面结构随时会变；任何一个适配器连续出现「未知」时，按上面的方法人工复核后再改适配器。

## 纯 IPv6、v6 入 v4 出、NAT64

- [ ] 纯 IPv6 出口不选绕行，或只选了名字却没有中继 / Mesh / v4 前置，保存被拒绝，并说明枢纽没有 IPv6。
- [ ] 双栈中继路径仍包含国内中继、IX、枢纽。枢纽的 WireGuard 里没有纯 v6 出口的 `2001:db8::` 端点；中继的配置里有 `[2001:db8::…]:端口`。
- [ ] 「v6 入 v4 出」（选了 Mesh 绕行的纯 IPv6 出口）的枢纽下一跳是它的 Mesh 腿的 WireGuard 接口，不是 `mmesh`；sidecar 不在或未密封时这条腿不通，这张表只剩黑洞。
- [ ] `nat64.reserved.conf` 存在，`meridian-routes.sh` 里没有 NAT64 路由。打开面板上的占位开关再编译，IPv4 默认路由仍不包含该前缀。

## 防泄露清单

面板「防泄露」页分四组：「自动化回归：生成配置核对」（配置包含 / 失败）、「隔离 Linux 集成证据」（一律未执行）、「实机人工签收」（一律待人工签收）、「已知限制」。第一组全绿只说明生成的配置里有这些规则。下面的打勾项按等级标注，实机项要附存档位置。集成项和实机项在面板「验收」页各有自己的一项（步骤、证据来源、签收记录），对应关系见「验收目录」。

- [ ] 53/853 被劫持到本机，非局域网来源的 53/853 在 input 被丢弃。
- [ ] 不 `flush ruleset`，策略路由优先级从 17000 起，境外表有黑洞默认路由。
- [ ] 网关 nft 文件是单个事务（建-删-重建），带独立的 `inet meridian_guard` 兜底表。运行中重载不漏在命名空间里有存档的通过记录（2026-11-13），真实客户端、ROS 和抓包下仍是待人工签收，见上面「防火墙原子替换与 LAN 兜底」。
- [ ] `fd66::/48` 不指向 ROS。
- [ ] 已知 DoH 域名返回 SOA，已知地址的 443 被拒绝。这不是全部 DoH。
- [ ] WebRTC：srflx / 中继候选是出口地址（实机人工签收，ipleak 或 browserleaks）。
- [ ] WebRTC host 候选里可能出现 ROS 通告的 GUA。这是单条运营商 /64 加 SLAAC 的结果，验收时记为已知限制，不当成失败。要去掉它，只能让测试机不用 GUA、改用 ULA 再在网关做 NAT66，国内 IPv6 就不再端到端。
- [ ] 实机人工签收：dnsleaktest.com 与 ipleak.net 的 v4/v6 都属于当前出口地区，没有家庭宽带公网地址。`unlisted_domestic_dns` 打开时 DNS 一栏还会出现国内解析器（预期，见上面「DNS」），签收时写明设置值。
- [ ] `clients_ipv6_via_gateway` 关闭时走隧道的域名没有 AAAA：自动化回归（`TestGatewayDNSSettingsCombinations`、`TestGatewayDNSPolicyAcrossDefaults`：静态默认出口、可切换组、两个枢纽、多中继、挂靠出口、外部出口各自乘四种设置，规则名字从不进国内组、外部出口永不返回 AAAA、dns-split 与默认组那一行同址同标记；面板「防泄露」页的生成配置核对 `dns_aaaa_policy`、`unlisted_domestic_dns`）、真实二进制（`TestSmartDNSRealBinary`）、网关上 `meridian-verify.sh` 的 `dns_aaaa_tunnelled`（真实查询，只有执行过才算）。
- [ ] 实机人工签收：ROS 上 `fd00::/8`（或 `fc00::/7`）黑洞的只读查询输出已存档（或 `meridian-verify.sh` 带 `MERIDIAN_ROS_SSH` 的 `PASS ros_ula_blackhole` 及其证据文件）。
- [ ] 实机人工签收：断隧道时测试机不通、ROS / 家庭 WAN 抓包里没有境外流量。
- [ ] 隔离 Linux 集成证据：`meridian-verify.sh` 在网关上 `meridian-verify-local-ok`，证据目录已存档。
- [ ] 自动化回归：网关路由脚本不装任何 `iif … unreachable` 规则、删除旧版的 17850/17851 两条、并且有兜底表（`no_iif_unreachable`）；网关上由 `meridian-verify.sh` 的 `no_stale_iif_rule` 和 `route_*` 路由探测按内核实际结果核对。
- [ ] 自动化回归：每个出口和地区组标记都有 v4/v6 的 102 表规则和其后的 unreachable，并在守卫范围内（`group_marks_routed`）；开机兜底文件与主规则的守卫一致（`boot_guard_matches`）；启动脚本重新加入保存的 chnroute（`chnroute_readd`）；编译产物里的私钥和预共享密钥都是占位符（`bundle_keys_placeholder`）；远程接入的生成配置（`remote_access_config`，关闭时为「不适用」且配置里没有 `mra`）。
- [ ] 隔离 Linux 集成证据：名单更新后重载，`chnroute_loaded` / `geosite_cn` 仍为 PASS（`lists_update_runtime`）。
- [ ] 实机人工签收：真实出口与地区组切换（`real_exit_switch`）；平台解锁结果按 unlock-methods.md 核对（`unlock_platform_verdicts`）；启用远程接入时手机两种模式、路由器转发、IPv6（`remote_phone_full`、`remote_phone_home`、`remote_router_forward`、`remote_ipv6`）。
- [ ] 已知限制：凭据库只靠文件权限保护、没有静态加密（`secrets_at_rest`）；远程接入「仅回家」模式不保护设备的上网流量（`remote_home_mode`）。

## 挂在中继出口后面的出口与外部 SOCKS 出口

- [x] 自动化回归：`internal/compile/external_exit_test.go`（隧道方向和端口、枢纽的下一跳形式和 `nested_snat`、中继出口的转发表和 `nested_guard`、挂靠出口的路由 / AllowedIPs / 解析 DNAT、承载节点的 nft / 路由 / gost 配置 / 解析组 / 健康脚本、足迹、凭据只以占位符出现、`bash -n`、没有这两类出口时什么都不渲染、动态域名端点刷新）；`internal/validate/nested_test.go`（环路、深度、缺承载节点、凭据、链路形状，新增出口不重排已有编号）；`internal/credentials/socks_test.go`；`internal/api/secrets_seams_test.go` `TestSOCKSCredentialSeams`（只写、被引用时拒绝删除、未知凭据拒绝保存、视图 / 编译 / 差异 / 数据目录 / 日志里没有凭据）；`internal/provision/nested_test.go`（承载节点和中继出口的沙箱下发、补偿和撤回，含 lo 地址段）。没有这两类出口的拓扑（单枢纽示例、双枢纽、多中继）编译结果与上一版逐字节相同。
- [x] 隔离 Linux 集成证据（Docker Desktop 的 Linux 虚拟机里以 `--privileged` 运行，arm64，**不是**真实主机，没有存档执行记录）：
  - `MERIDIAN_NETNS_TEST=1 … -test.run 'TestNetnsNestedExit$'`：主枢纽、备用枢纽接管（回包只走来路）、中继出口下线后组切走、挂靠隧道没了时失败关闭。通过时打印 `EVIDENCE primary: …` / `EVIDENCE backup: …` / `EVIDENCE relay down: …` / `EVIDENCE nested gone: …` 并以 `PASS` 结束。
  - `MERIDIAN_NETNS_TEST=1 MERIDIAN_GOST_BIN=… MERIDIAN_SMARTDNS_BIN=… … -test.run 'TestNetnsExternalExit$'`：TCP 经 SOCKS 出去、UDP 当场拒绝、解析经 SOCKS、SOCKS 下线和隧道消失时失败关闭、承载节点 WAN 上零包。通过时打印 `EVIDENCE proxy up / proxy down / tunnel gone: …`。
  - `MERIDIAN_GOST_BIN=… MERIDIAN_SMARTDNS_BIN=… … -test.run TestExternalExitRealBinaries`（root、nft）：固定版本 gost 的透明转发、认证失败、SOCKS 下线、重定向器下线、没有 UDP 套接字；固定版本 SmartDNS 的解析组经 SOCKS 回答、SOCKS 不通时失败、从不用承载节点自己的上游。
- [ ] 实机人工签收：真实的 NAT 挂靠出口和中继出口、真实的路由器和它的 SOCKS、真实双枢纽切换下的回程、动态域名端点的重新解析——都没有做过。

### 外部 SOCKS 凭据轮换后承载节点待下发（自动化回归；真实主机上未验证）

机制见[架构](architecture.md)「轮换 SOCKS 凭据：版本、基线与待下发」。全部用本地 SSH 替身（`sshtest`）和临时目录里的凭据存储，不连接任何远端主机；凭据都是测试里随机生成的值。

- 基线的一次性迁移（`go test -race ./internal/credentials -run SOCKS`）：`TestSOCKSVersionBaselineMigration`（没有基线的存储不跟踪任何凭据；写索引失败时迁移报错、记下原因、不留基线、索引文件里没有它；重启后迁移成功，基线是当时每个凭据的 id 和版本；再次调用、再次重启都不重取；基线里的凭据第一次轮换后被跟踪，之后每次加一；新建的凭据从创建起跟踪且不在基线里；改名、删除不改基线；有基线之后存储再坏，迁移不写、轮换被拒绝且版本和基线都不变，修好重启后仍是同一条基线；索引里只有 id 和计数、0600）、`TestSOCKSVersionBaselineWithFirstChange`（没有迁移时第一次轮换或新建把基线写进同一次索引写入，记的是变更之前的版本；存不进去的轮换不留基线；全新存储的基线为空）、`TestSOCKSVersionMigrationRacesRotation`（迁移与轮换并发：基线只有一条、每个凭据的基线版本是它确实有过的版本、被跟踪当且仅当轮换超过基线）。
- 版本行与摘要：`TestSOCKSVersionStamp`（只为被跟踪的凭据写、读回一致、没有被跟踪的凭据时逐字节不变、不重复写、占位符都还在、只认 `gost.yaml`）、`TestSOCKSDigestIsOfVersionNotMaterial`（两个存储值不同、计数相同时承载配置相同；换成别的值和换成同样的值，配置的变化相同；编译结果里没有任何值）、`TestSOCKSVersionNoExternalExit`（没有外部出口的拓扑与没有这一步时逐字节相同、整包不被复制；轮换一个没人用的凭据不产生待下发）。
- 轮换端到端：`TestSOCKSRotationMarksCarriersPending`（两个承载节点用同一凭据：轮换后两者「有变更」、原因写明已安装和现在的版本、在部署计划里是安装步骤；不承载外部出口的节点摘要不变、状态里没有任何 SOCKS 字段；轮换前审阅的预检下发被拒绝且没有执行脚本；新预检的变更列表带新版本；重装一个节点后它一致并记录版本 2，**另一个仍是待下发、记录仍是版本 1**，直到它自己重装；新旧两对用户名密码不在任何响应、`/api/compile`、`/api/diff`、`/api/validate`、预检记录、部署计划、日志和 `secrets/` 以外的数据文件里）、`TestSOCKSRotationStalesDeployVersion`（轮换使部署计划版本变化；没有外部出口、或凭据都在基线里且未轮换时，计划版本就是拓扑版本）、`TestSOCKSRotateValidation`（要面板口令、畸形值不回显、未知凭据 404、被拒的轮换和改名都不改版本）。
- 升级兼容：`TestSOCKSVersionUpgrade`（旧存储升级后每个文件与上一版的编译结果逐字节相同、没有版本行；按旧记录——没有版本——安装的承载节点仍然一致、不在计划里，状态带 `socks_unrecorded` 和「没有记录……不能证明」的说明；只轮换其中一个凭据：只有它的承载节点待下发并写明原因，另一个承载节点摘要和状态不变；重装后一致、版本 2、说明消失；没有轮换的承载节点重装一次：摘要不变、预检写明这次会记下版本、说明消失；再轮换显示「已安装版本 2，现在是版本 3」；重启后基线不重取、状态不变）、`TestSOCKSMigrationFailureAndRestart`（迁移失败：错误被报告、`version_tracking.ready` 为 false、编译结果是旧字节、存不进去的轮换被拒绝；重启后迁移成功、再重启不重取、摘要不变；之后第一次轮换使承载节点待下发；不重启时第一次轮换自己写入基线，结果相同）。
- 安装期间的轮换：`TestSOCKSInstallSnapshot`（秘密和版本一次读出；文件是轮换之前编译的就拒绝——无论凭据此前是否被跟踪；缺凭据不算轮换）、`TestSOCKSInstallRacesRotation`（`-race`：脚本运行期间轮换，这次安装用的、记录的都是它读到的那一版，装完后节点待下发；安装自己的预检期间轮换，下发被拒绝且没有脚本；轮换与一连串安装不同步地并发时，每个成功的安装记录的版本就是脚本里那对用户名密码的版本、与审阅的预检一致，输掉的在任何脚本之前被拒绝）。
- 下发脚本：`go test ./internal/provision -run TestInjectKeepsSOCKSVersionLine`（带版本行的 `gost.yaml`：注入结果只比不带的多这一行，占位符全部替换，仍按「安装时注入」对待，沙箱下发后文件是 0600、带这一行和注入的凭据，这一行进入整包摘要）。
- 秘密隔离回归：`TestSOCKSCredentialSeams`（创建和轮换之后，新旧值都不在各视图、编译结果、差异、校验、数据目录 `secrets/` 以外的文件和日志里；编译结果带占位符和版本；索引里只有计数；旧值在磁盘上已经没有）、`TestDemoFixturesNoSOCKSMaterial`（演示数据里没有演示用的用户名和密码，有版本字段）。
- 界面（`web/src/socks_version.test.tsx`，小范围渲染）：旧部署的承载节点显示「已是最新」加「凭据版本未记录」，说明写明不能证明、升级不算待下发；轮换后显示「有待下发的变更」和原因，重装后恢复；凭据页点名列出记录版本之前就有的凭据（手机宽度）、基线写不进去时的警告、轮换后给出待下发的承载节点且页面上没有用户名和密码。

对已有拓扑生成文件的变化：只有承载节点的 `nodes/<承载节点>/etc/meridian/ext/gost.yaml`，而且只在它引用的凭据被跟踪时（升级后新建的，或升级后轮换过的）多一行注释；其它节点和其它文件不变。升级本身不改变任何已部署节点的文件。

真实主机上没有做过（未验证）：

- [ ] 升级到这一版后，已部署的承载节点在部署页仍是「已是最新」并带「凭据版本未记录」，凭据页列出对应的凭据；`index.json` 里出现 `socks_version_baseline`，重启面板后不变。
- [ ] 轮换一个在用的 SOCKS 凭据后：承载节点显示待下发和原因，旧预检不能用；重新预检的变更列表里 `gost.yaml` 一项写明版本；安装后承载节点上 `gost.yaml` 是新的用户名和密码、带 `# meridian-socks-version:` 行、仍是 0600，`meridian-ext-proxy.service` 重启后经该外部出口的 TCP 恢复，面板恢复一致。
- [ ] 固定版本的 gost 读取带这一行注释的配置（它是 YAML 注释；隔离环境的真实二进制测试没有用带版本行的配置重跑）。

### 外部代理不可达：按安装身份判定阻断或告警（修订 19；自动化回归，真实主机上未验证）

规则：承载节点预检时外部 SOCKS 代理连不上（`external_proxy_unreachable`），只有主机自己的安装记录证明「同一个外部出口已经部署在这台主机上」时才是告警，否则阻断。「已经部署」要同时满足：主机清单属于本面板的这个节点和部署（归属 `same`）并记着这次预检所连的服务器；最近一次下发的 journal 为 `done`（或没有）；清单记着 `/usr/local/sbin/meridian-up.sh` 的哈希，主机上这个文件现在的哈希与之相同（安装后没被改过）；这个文件里有同一个外部出口 ID、同一 SOCKS 地址、端口和承载接口的 `# meridian-ext:` 标记（预检脚本只读地把它们报成 `extinstalled` 行）。地址、端口或接口在这次改动里变了，是新的代理配置，仍然阻断。SOCKS 凭据不在判定里：预检只做不带凭据的 TCP 连接，连通与否与凭据无关，已装的凭据只在 0600 的重定向器配置里、无法比较。面板自己的记录（「已安装」）不能把它降为告警。告警写明只有经该外部出口的流量受影响、这次安装既不会造成也不能修复。

- `go test ./internal/preflight -run 'ExternalProxy|ExtInstalled'`：首次启用（没有清单、已装配置里没有这个出口、只装了别的外部出口）阻断；同一配置已部署为告警、消息内容；端口、地址、接口改变阻断；清单读不懂、别的部署、别的服务器、评估不知道服务器、journal 未完成、meridian-up.sh 安装后被改、清单没记它的哈希、主机上没有它，都阻断；代理可达仍为信息、没有探测结果仍为告警；`extinstalled` 行的解析拒绝畸形行；脚本里的提取在本机对样例文件运行，只取真正的标记行。
- `go test ./internal/api -run TestCarrierPreflightExternalProxyByInstallIdentity`（本地 SSH 替身）：经面板预检承载节点 dc2：没有主机记录阻断；本节点 / 部署 / 服务器的记录加未改动的 meridian-up.sh 和同一标记为告警；端口改了阻断；记录属于别的服务器阻断；面板记录为已安装但主机没有记录时仍阻断。
- **已在真实主机上验证（修订 20 提供的事实，主会话）**：一台承载外部 SOCKS 出口的已部署节点，在外部代理对端再次离线时，预检识别出主机上已装着同一个外部出口，给出告警而不是阻断，该节点正常完成安装（修订 16 时同样情形是阻断）。真实主机上 `extinstalled` 的原始输出没有存档。

## 按顺序部署引导（自动化回归；没有对真实主机执行过）

`go test ./internal/api -run 'Deploy|TopologyVersion'`（本地 SSH 替身 `sshtest`、模拟的宿主预检和激活；不连接任何远端主机）：

- 顺序：嵌套出口 → 中继出口 → 出口 → 备用枢纽 → 主枢纽（IX）→ 两台中继 → 网关；外部 SOCKS 出口没有步骤；没有变化的节点不改变其余节点的顺序（`TestDeployOrderNestedRelaysHubs`）。管理通道：经中继跳转的节点先于中继，经别的节点主机端口转发的节点被提前并写明原因，经隧道管理的警告（含网关未装时隧道不存在），矛盾的通道按基本顺序并说明（`TestDeployOrderManagementChannels`）。拓扑版本不受画布位置、私钥和远程接入影响（`TestTopologyVersionIgnoresPositionsKeysAndRemoteAccess`）。
- 运行：没有变化的节点跳过；不按顺序、没有审阅过的预检都被拒绝；逐台预检、审阅、确认、下发、读回健康结果，网关最后；每台服务器的登录不超过单节点流程的两次；全部一致后不能再开始（`TestDeployRunHappyPath`）。补偿后停下、下一台不能开始、不重新核对不能重装、核对后再确认成功（`TestDeployRunStopsOnCompensationAndRecovers`）。结果不明后停下，核对时服务器记录显示内容已装上就采纳、不重跑脚本，节点状态变为一致（`TestDeployRunUnknownThenAdoptsHostRecord`）。拓扑保存使运行过期、拒绝安装、重新计划保留未受影响的预检并作废受影响的（`TestDeployPlanInvalidatedByTopologyChange`）；服务器身份（凭据）变化使确认失效并写明原因（`TestDeployConfirmationInvalidatedByIdentityChange`）。不能同时开始两个运行、执行中的一步挡住其它动作（`TestDeployNoDoubleStart`）。面板重启时执行中的下发显示为结果不明并停下、被打断的预检回到待预检，且持久化（`TestDeployRestartWithStepInFlight`）。限速时等待 `retry_after`、期间不连接（`TestDeployRespectsRetryAfter`）。与无人值守解锁自动安装互斥、网关激活失败补偿后停下再恢复（`TestDeployGatewayAndUnattendedInstall`）。状态栏的 `deploy_run`（`TestDeployRunInStatus`）。脚本报告成功但装完后读回服务器记录失败或回答不完整：这一步为结果不明、运行停下、下一台不可操作、重新计划保留它，重新核对读到记录后采纳且脚本只执行过一次（`TestDeployUnverifiedReadBackStopsAndRecovers`）；核对时仍读不到内容就重新审阅、确认后再装（`TestDeployUnverifiedReadBackRecheckWithoutRecord`）；面板记录为已安装但没有读回一致记录的节点不被跳过，预检后采纳、不装（`TestDeployPlanUnverifiedInSyncNodeGetsStep`）。运行以安装和采纳混合结束时，保存的结论、最后一条事件和重启后读到的结论都只把实际安装的节点说成通过健康检查，并点名采纳的节点（`TestDeployRunSummaryWithAdoptedStep`）；全部采纳时不说任何节点安装或通过检查（`TestDeploySummaryAllAdopted`）；全部实际安装时保留完整结论（`TestDeployRunHappyPath`）。
- 界面（`web/src/deployment_guide.test.tsx`，内存里的假 API）：计划的顺序、原因和跳过原因，开始时带上看到的计划版本；只用审阅过的预检确认一台；停下时只提供重新核对；过期时说明原因并重新计划；限速时倒计时、不发请求。「已安装 / 已采纳都不是端到端验证」和远程接入是独立资源的说明都看得见；运行完成时有采纳节点就点名说明没有重新检查健康、不写「全部健康」，全部实际安装时才保留完整结论。

- 跳过与依赖（修订 19；`go test ./internal/api -run 'DeploySkip'`，本地 SSH 替身，不连接任何远端主机）：依赖规则——网关依赖所有步骤；备用枢纽、主枢纽、IX、中继依赖比它们更早层级的每一步；中继出口依赖挂在它后面的出口；经某节点的服务器跳转或主机端口转发管理的节点被该节点依赖；同层出口之间、中继之间、与不是其中继出口的出口之间只是顺序偏好；等待会传递；规则之前存下的运行把之前的每一步都当依赖（`TestDeploySkipDependencies`）。被预检阻断的出口跳过后，与它无关的出口继续并装好，枢纽和网关等待并写明在等它、不能开始、没有登录过；跳过的节点不算完成、不采纳，运行以 `partial` 结束（不是 `done`），总结列出跳过的节点和原因、等待的节点和它们在等谁；重启后跳过仍在；「回到这一台」重新打开运行、从新的预检开始，装好后依赖它的节点轮到，已完成的不重装，最后才是 `done`（`TestDeploySkipBlockedNodeContinuesIndependentOnes`）。限速等待中的一台可以跳过，回到它时等待仍然有效、不连接；登录失败的一台记为「连不上」可以跳过（`TestDeploySkipUnreachableAndWaiting`）。不能跳过：结果不明（包括重新核对时连不上之后仍是结果不明）、失败、已审阅没有阻断、没预检过、已完成、只需核对、执行中、不是当前一步；未知节点 / 运行 404、未知字段 400、没有令牌 401（`TestDeploySkipRefusals`）。跳过在重新计划和面板重启后保留；重启打断的下发仍是结果不明、排在最前且不能跳过（`TestDeploySkipSurvivesReplanAndRestart`）。附带修正：对失败或结果不明的一步重新核对却没连上时，原来会退回「待预检」，现在保持失败 / 结果不明。界面（`web/src/deployment_guide.test.tsx`）：被阻断的当前一步给出「跳过这一台，继续其余节点」，确认框列出会继续等待的节点并发送跳过；跳过的行写明原因、可以「回到这一台」，等待的行写明在等谁；结果不明时不提供跳过；`partial` 的总结列出跳过和等待的节点；手机宽度下每行一张卡片、跳过提示和行内文字可换行。演示场景 `deploy-skipped`（合成）：一台被预检阻断、一台连不上，两台都被跳过，一台独立出口已装好，下一台此刻被阻断可跳过，枢纽、中继和网关在等待。
- **未验证（跳过）**：真实主机上的一次带跳过的运行（真实的阻断、真实的连不上和限速），以及跳过一台出口后用单节点流程手工处理枢纽 / 网关是否合适。
- 只需核对的步骤（`go test ./internal/api -run 'TestDeployVerify'`，本地 SSH 替身，不连接任何远端主机）：只需核对的步骤不在安装顺序里、从不是当前一步，安装步骤停在哪里都能单独核对；全部核对时一台连不上（替身已关闭）记为连不上并继续，被限速的一台记为等待、等待期间的第二次批量不连接它、单独核对返回 `deploy_wait`；安装步骤的顺序和确认不变，核对不执行任何下发脚本（`TestDeployVerifyOnlyOutsideOrder`）。记录内容摘要不同：不采纳，变成排在网关之前的安装步骤，确认前不下发，重新计划后仍是安装步骤（`TestDeployVerifyDiffersBecomesInstall`）。绑定：拓扑保存后的核对、计划时的主机指纹与现在不同的核对都被拒绝且不连接；记录属于别的服务器时不采纳；安装步骤不能当核对（`TestDeployVerifyBinding`）。只有核对步骤的运行在全部核对后完成，结论把它们列为采纳、每台一次登录（`TestDeployVerifyCompletesRun`）。界面（`web/src/deployment_guide_verify.test.tsx`）：只需核对的一组与按顺序安装的表格分开，各状态、一条提示、单行和全部核对、记录不同的标注。
- 经隧道管理的地址候选（`go test ./internal/compile -run TestMgmt`、`go test ./internal/api -run TestTunnel`、`go test ./internal/sshexec -run TestTunnelChannelCandidate`）：每个示例拓扑、每个节点、每个地址和每种承载状态下，推导与从渲染出的文件重新构造的网络结果完全一致，可用的每一跳对照渲染出的 AllowedIPs（`TestMgmtCandidatesMatchRenderedConfigs`）；挂在枢纽上的出口、嵌套出口、中继、主枢纽、备用枢纽和单枢纽、多中继分担的具体结论与原因（`TestMgmtCandidateCases`）；不受管的对端为无法判断（`TestMgmtCandidateUnknown`）；接口返回候选和读得到 / 读不到的承载状态，推导不拨号（`TestTunnelCandidatesAPI`）；各承载状态下的失败提示（`TestTunnelPathNotePerCarryingState`）；保存前测试：未固定指纹时拒绝且不拨号、经候选地址的发现只记为待确认、测试成功不记录到服务器也不改通道、只拨候选地址、失败时带承载状态提示、限速期间不再连接（`TestTunnelCandidateConnectionTest`、`TestTunnelChannelCandidate`）。界面（`web/src/channels_candidates.test.tsx`）：可用候选可选并写明链路与依赖，不可用 / 无法判断的可见但不可选并带原因，手工地址标注未经推导，保存前测试发送的通道和失败提示，未固定指纹时指向原有流程。

**未验证**：只需核对的批量在真实服务器（含一台真实连不上、一台真实被 sshd 限速）上的表现；推导为可用的隧道地址在真实网关上能否 SSH 登录（隧道握手、节点 sshd 是否监听隧道地址、节点防火墙）；推导为不可达的地址在真实网关上确实不通；网关切到备用枢纽时失败提示是否与实际一致。这些要由主会话在真实环境里执行并留下不含私密信息的记录后才算数。真实服务器上按这个顺序的一次完整部署；经隧道管理的节点在自己安装时会话是否被切断；真实 sshd 限速下的倒计时是否足够；运行期间面板真实重启。这些要由主会话在真实环境里执行并留下不含私密信息的记录后才算数。

## 跨模块契约在哪里测试

都是本地测试（假宿主、进程内 SSH 服务器、假 Cloudflare，不连接任何远端），属于「自动化回归」。

| 契约 | 测试 |
| --- | --- |
| 秘密不出现在 API 响应、日志、数据库 / 快照、拓扑、编译产物、差异：服务器 → 下发（密码） | `internal/api/ssh_ops_test.go` `TestServerReadinessAndProvisionOverPassword` |
| 同上：带口令的私钥 → 连接测试 → 下发（口令和私钥只在 `secrets/`，WireGuard 私钥只进下发脚本的标准输入） | `internal/api/secrets_seams_test.go` `TestKeyCredentialProvisionKeepsKeyInStore` |
| 同上：Cloudflare 账户 → Mesh 部署（含注入失败）→ 撤回（API token、SSH 密码只在 `secrets/`，节点令牌哪里都没有，日志干净） | `secrets_seams_test.go` `TestMeshSecretsAcrossDeployAndWithdraw`；`internal/api/mesh_test.go` `TestMeshDeployAndWithdrawByID`；`internal/mesh/deploy_test.go` `TestSecretsNeverPersistedOrReturned` |
| 同上：远程设备创建 → 安装 → 停用 → 重新生成 → 失败补偿 | `internal/api/remote_access_test.go` `TestRemoteAccessLifecycleAndSecrets` |
| 设备私钥从不落盘（含 `secrets/` 和已安装的宿主目录），重新生成后旧预共享密钥不在 `mra.conf` | `secrets_seams_test.go` `TestRegeneratedDeviceKeysAreNeverStored` |
| 账户与凭据创建、错误信息、快照、编译、差异 | `internal/api/resources_test.go` `TestResourceLifecycleAndReferences`、`TestSecretsStayOutOfSnapshotsAndBundles`、`TestErrorsScrubShortSecrets` |
| WSS 路径前缀和证书私钥只在安装边界注入（网关安装事务、远端下发脚本），不在 API、日志、数据库 / 快照、拓扑、编译产物、差异、`/api/wss`、清单里；远端只收到自己的 WSS 秘密 | `internal/api/wss_test.go` `TestWSSGatewayInstallSecretsAndRotation`、`TestWSSProvisionInjectsOnlyIntoTheScript`；`internal/compile/wss_test.go` `TestWSSResolveRendersOnePathPerLinkAndNoSecretInBundle`；`internal/provision/wss_test.go`；`internal/credentials/wss_test.go` `TestEnsureWSSGeneratesAndIsIdempotent` |
| WSS 轮换两端始终互通、失败补偿保留旧凭据、迁移幂等 | `internal/credentials/wss_test.go` `TestWSSCertRotationNeverBreaksTheCarrier`、`TestWSSRotationSequenceAndCompensation`、`TestWSSLegacyMigration`；`internal/api/wss_test.go` `TestWSSLegacyMigrationThroughThePanel` |
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
| 整条面板流程按顺序走一遍、每一步在前提之前被拒：凭据 → 服务器 → 指纹 → 连接测试 → 拓扑绑定 → 远端预检 → 第一次下发 → 网关预检（预检之后改拓扑即失效）→ 安装（经真实 `hostexec.Client` 到真实 `hostexec.Agent`，Unix socket，命令执行模拟）→ 远端撤回 → 网关撤回；响应里没有密码和私钥 | `internal/api/e2e_flow_test.go` `TestPanelFlowEndToEnd` |
| 安装后受管 sysctl 的写入、读回内核和旧文件遗留；`meridian-up.sh` 应用整份文件（开机转发两行除外）并写汇总行 | `internal/apply/sysctl_test.go`；`internal/compile/gateway_round2_test.go` `TestUpAppliesManagedSysctlAndSummarises`；`web/src/pages_deploy.test.tsx`「deploy: managed sysctl after an install」 |
| 面板开机等待局域网地址：等待、超时失败、其他错误立即失败、拒绝通配地址 | `internal/api/listen_test.go` |
| 概览的探测通道跟随宿主代理可达性 | `internal/api/status_test.go` `TestStatusProbeFollowsAgentReachability`；`pages_exits.test.tsx`「overview: unlock probe channel」 |
| 同名地区组在卡片、规则目标选择、规则列表、解锁选择器里附带地区和 ID | `pages_exits.test.tsx`「region groups with the same name」、`pages_rules_topology.test.tsx`「rules: same-named region groups」 |
| 秘密与三种日志的内容在同一台网关上各守各的通道；节点摘要只随配置和凭据版本变化，不随日志内容、秘密本身变化 | `internal/api/secrets_seams_test.go` `TestSecretsAndJournalsStayInTheirChannels`；各日志单独的 `TestSniffJournalNeverLeaves`、`TestDNSLogNeverLeaves`、`TestLinkLogNeverLeaves` |
| 导出的文档只带开关和引用；原样导入不改变任何节点的摘要 | `internal/api/topology_contract_test.go` `TestExportHoldsSwitchesAndReferencesOnly`；`dns_journal_test.go` `TestDNSLogTopologyContract` |
| 没有出口加密上游、解析日志关闭（有没有外部 SOCKS 出口都一样）时，编译结果与日志和凭据版本之前逐字节相同，只多网关的链路日志 | `internal/compile/golden_single_hub_test.go` `TestCompileUnchangedSinceBeforeTheLogs`；`external_exit_test.go` `TestExternalCarrierUnchangedWithoutRotation`；`dns_settings_test.go` `TestJournalsAndExitUpstreamAreIndependent`；`internal/api/socks_version_test.go` `TestSOCKSVersionUpgrade` |
| 日志采集不让网关以外的节点出现差异；日志给网关增加的文件只有名字 | `dns_settings_test.go` `TestJournalsAndExitUpstreamAreIndependent`；`leak_test.go` `TestJournalFilesCarryNamesOnly`；`dns_log_test.go`、`link_log_test.go` |
| 演示数据里日志内容只在日志自己的回答里，没有秘密 | `internal/api/demo_fixtures_test.go` `TestDemoFixturesLogContentStaysInLogResponses`；`TestDemoFixturesNoSOCKSMaterial`、`TestDemoFixturesNoDNSAccount`；`web/src/demo/demo.test.tsx`「demo logs」 |
| 防泄露清单不把未执行的证据标成通过 | `internal/verify/verify_test.go` `TestChecklistDoesNotClaimUnexecutedEvidence`、`TestNewWorkItemsAndScopes`；`server_test.go` `TestPoolsUnlockAndLeakcheck`；`web/src/pages_remote_unlock.test.tsx`「leak check」 |

尚未覆盖、留给后续的：除 `TestPanelFlowEndToEnd` 之外，API 层的安装测试都用激活桩；那个测试经真实 `hostexec.Client` 安装，但只检查了面板响应里没有秘密，没有检查 agent 收到的请求；Mesh 的真实 SSH 执行器（`sshRemote`）没有从 API 跑过（只用了假 Remote）；`/api/apply` 的 `dry_run`、`/api/rollback` 只检查了节点私钥。

## 面板排版（全部页面与弹层）

范围：`docs/ui-layout.md` 的统一排版规则应用到概览、拓扑、出口（含中继分担）、分流规则（含导入、嗅探、规则集、服务组、规则测试器）、名单、服务器、密钥、Cloudflare 与 Mesh、远程接入、部署（含部署引导、预检、撤回、WSS）、解锁（含自动路由、服务 × 出口矩阵、平台目录、覆盖表）、防泄露、登录页，以及这些页面里的抽屉和对话框。只改显示层：没有改任何 API 调用、请求体或数据语义。

| 证据 | 等级 | 状态 |
| --- | --- | --- |
| `npm --prefix web test` 里的 `web/src/layout_pages.test.tsx`（合成数据：15 个节点、7 个地区组、165 条规则、56 个规则集、17 个服务组、41 个适配器、矩阵里 9 个出口、约 130 项覆盖表）：规则表分页且编号跨页连续、上移 / 移到第 N 条跨页后跟到所在页；规则表关键列和声明宽度；被截断的文字可聚焦并带全文；页头只有一个主操作，其余在「更多操作」；矩阵在可滚动区域里、紧凑单元格、按出口筛选；覆盖表按地区筛选；出口页同一原因只说一次、标签只放短状态；概览地区组行；拓扑自动排列不重叠；任何安全提示都不在折叠区里 | 自动化回归（jsdom，假 API） | 每次跑测试都覆盖 |
| `web/src/ui_layout.test.tsx`：共享组件的类名、结构和交互 | 自动化回归 | 同上 |
| 真实浏览器逐页检查：1440、1280、1024 下文档无横向滚动、内容不超出卡片 / 对话框 / 视口、没有竖排文字、固定列和吸顶条不遮挡内容、1280 及以上数据表关键列无需横滚；768、390 下文档不横向滚动、表格只在自己的容器里滚动、所有操作够得着；浅色和深色主题 | 实机人工（主会话在本机面板上，用真实规模的数据和 `web/tools/ui-audit.js`） | **待验证**：实现任务没有浏览器，以上宽度、折行、吸顶和遮挡都没有在浏览器里看过，不能写成已验证。逐项清单见 `docs/ui-layout.md`「Checks only a real browser can prove」 |

## 面板显示第二轮（修订 12 第一部分）

范围：`docs/ui-layout.md`「Second pass」——手机宽度下逐条操作的表格改为堆叠卡片（`DataTable` 统一实现）、概览卡片行的长名称省略、规则表列宽与「要求与遮蔽」移入展开详情、导入抽屉的中文上传控件和真正的多行占位、远程接入的模式卡片和页面提示、每页最多一条主要提示、出口成员行和中继分担表、解锁矩阵表头、部署表格里的溢出、拓扑自动排列的连线、深色主题遗留的浅色。只改显示层：没有改 API 调用、请求体、数据语义或演示夹具（`TestDemoFixtures` 照常通过）。

| 证据 | 等级 | 状态 |
| --- | --- | --- |
| `web/src/ui_layout.test.tsx`「DataTable at phone width」、`web/src/demo/demo_phone.test.tsx`：手机宽度下规则、服务器、SSH 与 SOCKS 密钥、远程设备、部署远端节点、部署记录是卡片（没有表格、没有固定列），每张卡片有标题和全部操作；规则卡片里上移、编辑、翻页（第 2 页从 51 开始）可用；受控 / 非受控的分页与展开 | 自动化回归（jsdom，演示夹具） | 每次跑测试都覆盖 |
| `web/src/demo/testkit.tsx` 的 `layoutChecks()`：所有演示场景的每个页面最多一条页面级提示、每个区块最多一条提示；安全提示不在任何折叠区里；被截断的文字都带全文（可聚焦或含链接） | 自动化回归 | 同上 |
| `web/src/second_pass.test.tsx`：导入抽屉是中文上传按钮、在浏览器里读文件且不发请求、占位是真正的三行示例；远程接入两种模式各一句话、长说明折叠、仅家网的安全说明可见、页面不再叠三条提示；拓扑自动排列的错位列与绕开卡片的连线几何 | 自动化回归 | 同上 |
| 真实浏览器验收：演示预览全部场景 × 浅色 / 深色 × 1440 / 1280 / 1024 / 768 / 390，用 `web/tools/ui-audit.js` 的 `__auditDemo`（新增 `stack`、`alerts` 两类发现）和目测，逐项见 `docs/ui-layout.md`「Browser acceptance」 | 实机人工（主会话） | **未验证**：实现任务没有浏览器，卡片在 390 下是否不横向溢出、规则名列在 1280 / 1440 实际多宽、矩阵 9 个出口在 1280 是否不滚动、5 px / 3 px 溢出是否消失、拓扑连线是否真的不压卡片、深色主题的颜色，都没有看过，不能写成已验证 |


### R2 共享 Mesh 生命周期回归（本次编写，未执行）

- `TestSharedSidecarIncrementAndLegWithdrawal`：增加第二条腿不重装共享枢纽；单腿撤回保留其他腿，最后撤回使用原始备份所有者。
- `TestIncrementFailureAndRestartPreservePublishedLeg`：逐阶段注入失败；主机恢复失败后用新部署器重试，只补偿增量资源，保留原已发布腿。
- `TestIncrementProcessInterruptionRecoversOriginalOwnership`、`TestDeploymentCancellationUsesIndependentRecoveryContext`：在写主机过程中模拟进程中断，或取消请求；重启恢复读取持久边界，取消后恢复使用独立上下文。
- `TestLegWithdrawalFailureRestartRetriesSameSelection`：路由删除失败时不删除对应主机或注册；重启后继续原单腿选择。
- `TestUnderlayPreflightCoversLegsAndRejectsBadParameters`：内部 Endpoint、出口 UDP 监听、接口 / 路径 MTU、黑洞与密封摘要；拒绝非 /32 或命令片段。
- 沿用验收固定动作、参数校验和演练的二次确认、取消 / 失败 / 重启恢复回归；不新增任意命令入口。网关握手与已发布记录只能构成局部实测，人工签收必须另证实 Mesh 内的 WireGuard UDP、同一出口公网地址、解析与恢复。

本写入任务没有执行 Go 测试套件、前端测试或构建。`go test ./...`、`npm --prefix web run build` 及相关前端回归交由 Concord 后续执行；不得将本段作为通过记录。真实 Cloudflare Mesh 的 UDP、路径 MTU 和分片仍待主会话先用美国出口实机验证。


### R3 同出口双腿质量回归（本次编写，测试未执行）

- `internal/pathquality/mesh_test.go`：完整采样窗口前保持直连、质量优势切到 Mesh、恢复计时被失败清零、冷却后切回、完全无响应立即切换、双断黑洞、恢复可达；旧样本不被修改。
- `internal/compile/mesh_quality_test.go`：生成脚本用合成 ping / 路由桩逐轮对照 Go 决策；事件包含切换原因与双腿读数；双族黑洞；切换器只编译到主枢纽；策略改变使旧读数失效；当前成员双断时保持出口，别的组不被吸引到不可达成员。
- `TestNetnsMeshLeg` 增量阶段：用真实命名空间内的 ping 测量两条实际 WireGuard 腿；直连被断时自动使用 Mesh 腿、Mesh 失效时自动回到可达直连、双断时出口表双族黑洞且不向 WAN 泄漏、直连恢复。测试中的 Mesh 仍是 tun 转发替身，不是 Cloudflare。旧的存档不覆盖这些新增阶段。
- `internal/hubstate` / `internal/api`：固定读取新增的报告严格校验；未知出口、旧策略、过期心跳不当作当前质量；沿用主机身份变更后的失效规则。
- 面板 `pages_exits.test.tsx` / `topology_contract.test.tsx`：当前腿、双腿质量、原因、未知状态、切换历史、窗口设置和重新下发提示。手机使用可换行区块，没有新增宽表。
- 带 Mesh 的三份编译金样仅更新主枢纽故障切换脚本摘要；不含 Mesh 的摘要固定值保留，继续由 `TestNoMeshCompileUnchangedByMeshTransport` 保护。

**委托 Concord，写入者未执行**：`go test ./...`、`npm --prefix web run build`、前端测试；命名空间阶段需要有本地监听和特权网络命名空间权限的隔离 Linux 环境。只做过离线编译、类型和脚本语法检查，不是测试通过记录，也不是部署批准。

**主会话实机签收（待做；在既有 mesh-e2e 验收项内记录）**：先仅美国出口；在出口 / 拓扑 / 链路日志读取当前腿与双腿读数；制造持续丢包或高延迟，观察完整窗口与优势 / 冷却规则；单独完全切断直连，观察本轮切到 Mesh；恢复后核对连续达标与冷却结束才切回（中途失败应清零）；双腿同时断开，核对 IPv4 / IPv6 黑洞、出口 / 国家未变化且没有转到别的出口或枢纽 WAN。每次存档切换时间、原因、双腿读数、路由、出口公网地址与解析结果。恢复后重新读取状态并签收；这些操作不由本编码任务执行。

### R4 外部 SOCKS 出口的探测 DNS（本次编写，未执行）

宿主探测使用出口的 `TransitV6 → DNSULA:53`，外部出口的 `DNSULA = PeerULA`。承载节点 `ext_dnat` 现在在 IPv6 拒绝之前，仅对受管枢纽入口、该出口中转源、该出口解析地址、UDP/TCP 53 终止 NAT 求值，交给已有的本机解析组。其余 IPv6 数据的拒绝和 SOCKS 仅承载 IPv4 TCP 的边界保持。

- `TestExternalProbeDNSException`：单枢纽与双枢纽的实际探测参数、完整规则、顺序、源 / 目的 / 端口限制。
- `TestNetnsExternalExit`：新增实际探测地址对的 UDP/TCP DNS 查询；不同目的或端口仍收到拒绝；用合成 DNS 回答的地址经 SOCKS 到达合成平台服务。到达平台只证明到达性，不是解锁通过。使用本地命名空间与替身，不连接远端。
- **需要重新下发外部出口的承载节点**：其 `etc/nftables.d/meridian.nft` 增加每出口两条精确例外。升级面板本身不会修改已部署节点。
- 此差异独立于 Mesh：历史无 Mesh 摘要断言先核对并剥离这两条精确规则，再比较原摘要；不更新摘要值或无关金样，其余文件保持原有约束。

**委托 Concord，写入者未执行**：`go test ./...`、`npm --prefix web run build`、相关前端测试及需要特权 Linux、本地监听和固定 gost / SmartDNS 二进制的命名空间回归。真实外部 SOCKS 出口的复测由主会话重新下发后执行；本报告不是验证或批准。

### R5 服务组解锁映射（本次编码，测试未执行）

- 盘点并沿用已有港、日、台、新、美及 AI 检测与逐项覆盖/缺项原因；Apple TV+ 明确缺少可靠无账号证据，保持固定。
- 合成回归：`TestSuggestedMappingsRequireConfirmation` 覆盖主流名称建议、无可靠映射、未确认/弱检测拒绝、不保存半份修改、确认启用；`TestAutomaticRoutingEvidenceBoundary` 和 `TestWeakPositiveCannotDriveRouting` 覆盖弱正面信号降为仅到达性、不入选路状态机。
- 原服务组组合选路回归改用有明确平台标记的 fuboTV；保留地区候选、组合检测、过期、失败滞回与切回语义。界面回归要求确认前不发请求，确认后发送精确检测项及确认字段。
- **委托 Concord，写入者未执行**：`go test ./...`、`npm --prefix web run build`、前端测试。未连接平台、Cloudflare 或任何远端主机。真实解锁、版权/订阅播放与在线切换由主会话复测并在验收项记录。

R5 另含 `TestServiceMappingChangeRequiresFreshEvidence`：更换检测映射后旧证据不能移动新服务，重排同一检测集合不改变绑定；服务组候选的最近检测类别与已知有效选路证据分别展示。Coze 合成样本覆盖仅返回国家、缺少显式允许字段时为未知。离线 `go build ./...`、API/probe/unlock 测试二进制的仅编译（`go test -c`，没有执行）与 `tsc --noEmit` 只用于静态检查，不构成测试或实机验证。

## 面板收敛为“干净”布局（修订 6；自动化回归，真实浏览器待复核）

只改前端呈现，API 语义不变。

- 页头只有标题（每页唯一的 h1）和操作：不再显示副标题；`description` / `help` 合在一个「说明」开关后面。次要操作收进图标「…」（「更多操作」）。区块标题是 h2，区块之间只用留白和一条细线分隔，不再有卡片边框和阴影；字号四级（页面标题、区块标题、正文、数据 / 小字）；页面底色与卡片同为中性色，强调色只有一个。
- 每行重复的彩色标签改成一个弱化的状态词（`.state-word`）：解析页每行的「计划（未验证）」（整节只说一次）与传输 / 来源 / 范围标签，出口页成员的「使用中 / 推算在用 / 目标 / 指定 / IX 绑定 / 住宅 / IPv6 / 外部 SOCKS / 中继」，分流规则的来源与去向种类，服务组与规则集的「导入」等，解锁页的「仅 TCP / 手动组：只记录」与自动 / 固定，验收页的打断影响与「没有结果 / 待人工签收」。
- `Explain` 组件删除，统一用 `Note`；`firstSentence` 等不再使用的代码删除。名单页的分裂按钮改为一个主操作「立即更新」加「…」菜单（无名的下拉触发按钮去掉）。表格的操作列没有标题时补一个只给读屏器的「操作」表头。
- 导航分成 5 组（概览 / 网络 / 日志 / 运维 / 资源），侧栏在 `nav[aria-label=主导航]` 里；全部 URL 不变（`#/conn-log`、`#/dns-log`、`#/link-log`、`#/dns`、`#/acceptance` 等）。

| 证据 | 等级 | 状态 |
| --- | --- | --- |
| `web/src/nav_routes.test.tsx`：菜单恰好是固定的 17 个 URL；每个 URL 渲染一个名字与菜单项相同的 h1、在 main 里、菜单项选中、文档标题一致、区块标题都是 h2；未知路由显示「没有这个页面」 | 自动化回归（jsdom，假 API） | 每次跑测试都覆盖 |
| `web/src/prose_budget.test.tsx`：每个路由页默认 0 句说明（空数据和真实规模数据），抽屉 / 对话框至多 1 句；手机宽度无超宽固定宽度 | 自动化回归 | 同上 |
| `web/src/demo/testkit.tsx` 的 `layoutChecks` + `structureChecks`（全部演示场景、全部页面，含手机宽度场景）：默认 0 句说明；表格外的标签 ≤ 36、整页标签 ≤ 170；一个 h1、一个 main、主导航 landmark、页头至多一个主按钮、可聚焦按钮都有名字、表头都有文字 | 自动化回归 | 同上 |
| 桌面（1440 / 1280）与手机（390）宽度前后截图：`npm --prefix web run demo:dev` 后打开 `/?scenario=healthy`、`/?scenario=degraded`、`/?scenario=unavailable` 逐页对比（含抽屉和确认对话框），检查横向滚动、留白、字号层级和颜色 | 实机人工（主会话在真实浏览器里） | **待验证**：实现任务没有浏览器 |

### 主机级 Mesh：策略规则与默认路由的完整扫描（修订 7）

检测脚本完整读取 IPv4/IPv6 的 `ip rule`，先把制表符换成空格（真实输出在优先级冒号后是制表符），再在主机侧筛出 WARP 标记规则及指向这些规则所查表（总含 65743）的规则，最多输出 64 条并附总数；读取失败报 `ruleread`、超过 64 条报 `ruletrunc`，两者都阻断共存与沿用。默认路由筛选使用同一份完整的 WARP 表集合。连接器安装前预检读取规则失败时报 `rule_read` 并阻断。回归：`internal/mesh/rulescan_test.go`、`defaultroutes_test.go`。真实主机上的 `ip rule` 输出格式与 WARP 实际使用的表、标记仍待主会话在 ix ↔ us-west 上核对。

## 局域网到隧道端点（合成回归）

`internal/compile/endpoint_access_test.go` 用示例拓扑（文档地址段，无实机）核对：国内中继和 IX 国内入口判国内直连；境外枢纽/出口在规则和 chnroute 之前固定为默认组标记（出口标记范围内），从不进国内直连集合；网关自己直拨的境外端点（备用枢纽）同样经默认组隧道标记，且网关外层包仍带 underlay fwmark、classify 只挂在局域网入口；默认组不承载的地址族丢弃；端点规则位于 `10.66.0.0/16`、`fc00::/7` 丢弃之后；守卫表和网关 WireGuard 配置（underlay fwmark、Endpoint）不变，只有网关 `meridian.nft` 引用端点集合；嗅探开启时端点不交给转发器。`TestUnderlayRulesReportedUnreachable` 交叉核对编译器集合与 `rule_unreachable`。命名空间里的报文级回归：`internal/compile/netns_endpoint_access_linux_test.go`（`TestNetnsEndpointAccess`，Linux root、需要 python3，没有 `MERIDIAN_NETNS_TEST=1` 或不是 root 时跳过）。用主备枢纽示例（加两个合成 IPv6 端点），网关、ROS（本地宽带）、客户端、中继、IX、备用枢纽、两个出口和一个「互联网」命名空间都装编译出的 nft 和路由，每个节点的公网地址在它连到「互联网」的 WAN 上，ROS 也连到「互联网」（所以泄漏会连通并被看到）。核对：国内端点经局域网口和 ROS、服务端看到客户端的局域网地址、隧道 0；境外端点经默认组隧道、局域网口和 ROS 计数 0；备用枢纽承载默认组时客户端到它的公网地址经备用隧道，网关自己带 `0x4d72` 的包和不带标记的 TCP 走主表出局域网口、进隧道 0，N 个客户端包在隧道上恰好 N 个；默认组不承载的 IPv6 端点和「默认组没有出口目标」时的全部境外端点丢弃，局域网口和 ROS 0。

运行（Mac 上的 Docker Desktop，2026-11-16 通过，日志和变异检查在 [docs/evidence/2026-11-16-netns-endpoint-access](evidence/2026-11-16-netns-endpoint-access/README.md)）：

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile
docker run --rm --privileged --network none -v $PWD/compile.test:/compile.test:ro \
  -e MERIDIAN_NETNS_TEST=1 --entrypoint /compile.test meridian-p2-lab:latest \
  -test.run '^TestNetnsEndpointAccess$' -test.v
```

（镜像只需要 iproute2、nftables、python3、bash、ping；Linux 主机上直接 `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsEndpointAccess$' -test.v`。）通过的样子：四行 `EVIDENCE loaded set`，`EVIDENCE main:` / `backup:` / `fail-closed:` 各项，stderr 有 `meridian-netns-endpoint-access-test-ok`，最后 `--- PASS: TestNetnsEndpointAccess`；失败时有 `DIAG` 段。没有覆盖：默认组经隧道承载 IPv6（示例只有 IPv4）、真实 WireGuard / wstunnel（隧道是 veth，外层包是同类标记的替身）、Debian 13 真实内核。

## 规则自动生效与中继测速的面板（修订 15 R4；自动化回归，真实网关与浏览器待主会话复核）

- `rules_ordered.test.tsx`：服务组改指向回答 `fast_apply: applied` 时只显示一行「已生效（v8）」、没有去部署链接；mihomo 导入回答 `required` 时显示「未自动生效：<原因>」和指向 `#/deploy` 的链接。拓扑保存（文档栏）同样用这一行（`RulesApplyLine`，`ui_base.tsx`）。
- `pages_exits.test.tsx`：每台中继一行测速（正常为纯文字 `186 Mbit/s`，限速为红色标签 `限速 38 Mbit/s`），「说明」里有测速流量估算；网关设置里改测速间隔和每台标称带宽，保存出 `speed_test_interval_sec` 与 `overrides[].nominal_mbps`（只有标称带宽的覆盖保持自动）。
- `table_budget.test.tsx`：中继表第四列改为「测速」，宽度预算不变。
- 复核（V1–V3，合成数据）：`go test ./internal/compile -run RuleChange`——`TestRuleChangeZeroToOneRule` 覆盖各示例拓扑 0↔1 条规则双向都按纯规则改动接受，同一测试里给 smartdns.conf / meridian.nft 加一处规则段以外的改动则两个方向都拒绝；`TestRuleChangeRefusesOutside` 另加规则段紧前面的注释、classify 规则行之间的注释都拒绝（`maskDNS` 只去掉规则段固定的三行注释，不再吞掉前面任意的注释行；只有规则段前的空行多少不比较）。`TestRuleSetContentIsBundleNeutral`：开关关着时规则集内容下载也照常写入，编译结果不变、不安装、不升版本、没有自动安装记录。`go test ./internal/pathquality -run SpeedTest`——`TestSpeedTestPartialThenStallIsNotMeasured`、`TestSpeedTestShortAndTimeout`、`TestSpeedTestStallAndResetDoNotThrottle`（停滞原因为 `short` 且两次停滞不动判定、到期不足 1 MiB 未测到、中途被重置未测到；到期且 ≥ 1 MiB 为有效低速样本）。`go test ./internal/api -run RuleAuto`——`TestRuleAutoBusyThenApplied`、`TestRuleAutoBusyVersionChangedRefused`、`TestRuleAutoBusyConditionChangedRefused`（非规则配置、开关关闭、预检阻断、预检警告）、`TestRuleAutoBusyRetriesExhausted`（恰好 5 次重试后 `skipped`「网关正忙」，需要安装）、`TestRuleAutoBusySingleTransaction`（等待期间再保存：事务不重叠、最终一致）；测试经 `rulesAutoBusyWait` / `rulesAutoSleep` 缩短等待。`TestRuleAutoApplyVersionMovedMeanwhile` 以 `-count=5` 通过。
- 未验证：真实网关上的自动安装（白名单拒绝、合并等待、限流）、测速流量与 QoS 判定、shell 兜底下的显示，都要主会话实机确认。

## P6 回归（自动化；未在真实浏览器或主机上执行）

- `POST /api/unlock/adopt` 带 `preview:true` 不保存，返回 `service_rules` 与 `other_rules`（同地区组、首选出口会变时受影响的其他规则数）：`TestUnlockAdoptRetargetsExactlyTheServiceRules`、`TestAdoptImpactCountsOtherGroupRules`。
- 演示 healthy 场景概览显示「防泄露 正常」：verify 的 `group_marks_routed` 不再把拒绝标记 0x65 与「未分类」0 当作出口标记；`mesh_not_on_gateway` 认可中继分担的故障切换脚本（它只在中继与备用枢纽间选择）。编译输出字节不变。
- 去掉时间窗：`TestRuleAutoApplyConcurrentChangeRefused` 把合并运行排到一小时后，并发改动落地后手动触发；演示 degraded/unavailable 概览检查等待状态而不是时钟。
- 兼容：旧路由 `#/leak`、`#/acceptance`、`#/service-groups` 重定向；`/api/service-groups` 410；含 `service_groups` 的旧拓扑可加载（已有测试）。


## 391aa50 审查基线（T1 修订 3）

[审查工作记录](review-391aa50.md)列出固定合成输入、切换失败契约、提案四类问题的静态复核和全库文件清单。完整产物字节、逐文件摘要及应用顺序保存在 [baseline-bundles.json](evidence/review-391aa50/baseline-bundles.json)，原 golden 与证据文件摘要见 [baseline.sha256](evidence/review-391aa50/baseline.sha256)。比较入口是 `TestReviewTopologyBaseline`，不自动更新基线。

该基线由 HEAD `391aa50c05d2b8e444875c08bd8bc3766922ef3b` 编译器在生产修改前生成，仅含合成数据和占位凭据。NAT 以合成映射端点表示，管理目标以合成中继 TCP 转发表示；不证明 NAT/SSH 执行链可达。未执行联网、实机或隔离 Linux 数据面检查。按用户修订 3，未查清项已在矩阵和逐文件清单中分配给 T2–T6，T6 负责收尾；T1 仅交付基线、矩阵、四类缺陷静态复核及失败契约，不表示全库审查完成。本记录不是验证、批准或部署结论，Concord 后续独立执行检查与 QA。

## 391aa50 审查 T3–T6（自动化回归；未在真实主机、浏览器或 Linux 数据面执行）

逐项见[审查工作记录](review-391aa50.md)“T3–T6 完成记录”。

- 事务：`TestCrashAtEveryHostStepRecovers` 在一次成功安装的每个宿主步骤（正向与补偿）注入进程崩溃，新进程恢复后版本与宿主一致、幂等、未清日志拒绝新安装。
- 规则自动生效：`TestRuleAutoApplyScheduledLostOnRestart`、`TestRuleAutoApplyLegacyScheduledRecord`（重启后 scheduled 持久化为中断）；`rules_apply_line.test.tsx`（结果待确认、卸载、新保存竞争）。
- 解锁：`unlock_polling.test.tsx`（不重叠、乱序丢弃、卸载、再次探测）、`TestUnlockRecommendationReachesRoute`、`TestUnlockConfirmStaleRecommendationRefused`。
- 名单：`lists_polling.test.tsx`。
- 编译产物与 T1 基线逐字节一致（仅 T2 登记差异）。macOS 上无网络命名空间：数据面结论未验证，见审查记录建议 R1。
