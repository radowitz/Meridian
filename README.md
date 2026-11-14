# Meridian

Meridian 是一台跑在局域网里的多出口 WireGuard 策略路由网关。测试设备把 IPv4 网关和 DNS 指到 `192.168.100.88` 之后，国内流量仍从 ROS `192.168.100.1` 直连，境外流量必须经过「家宽 → 阿里云上海 → 深港 IX → 香港枢纽 → 出口」。现有的 mihomo 网关和 RouterOS 配置都不改，Meridian 与它们并行。

数据面用内核 WireGuard 和 nftables，不用 Fake-IP。域名由 SmartDNS 做国内 / 境外实解析，并把结果写入 nftset。控制面是只监听局域网的 Go API 加 React Flow 拓扑面板。

```mermaid
flowchart LR
  lan["测试客户端"] --> gw["网关 Debian 13<br/>192.168.100.88"]
  gw -->|"国内 chnroute<br/>下一跳 .1"| ros["ROS 192.168.100.1"]
  ros --> cn["国内互联网"]
  gw -->|"UDP WG + WSS 自动切换<br/>外层 v4，内层 fd66"| ali["阿里云上海"]
  ali --> ix["深港 IX 专线"]
  ix -->|"直连 WG"| hub["香港枢纽<br/>无 IPv6"]
  gw -.->|"IX 替换 WSS 待命"| hub
  ali -.->|"IX 替换 WSS 待命"| hub
  hub --> hkix["香港地区组<br/>优先 IX 绑定"]
  hub --> resi["香港家宽<br/>Netflix / Disney+"]
  hub --> jp["日本"]
  hub --> sg["新加坡"]
  hub --> us["美国<br/>主流 AI"]
  tw["台湾 NAT 拨出"] -->|"PersistentKeepalive"| hub
  hkix --> inet["国际互联网"]
  resi --> inet
  jp --> inet
  sg --> inet
  us --> inet
  tw --> inet
```

实线是主路。虚线是预先配好、默认不进路由表的 IX 替换隧道。Mesh 只允许作为「枢纽 → 出口」的备路，跑在枢纽和出口上的独立网络命名空间里，不能绕过 IX，也不装在这台家宽网关上。出门在外的手机和笔记本可以经网关上的 WireGuard 远程接入回家，按局域网同样的规则分流。

## 这一期有什么

- 每出口一张路由表和 fwmark。国内走 chnroute / chnroute6，默认境外走默认地区组（示例是香港，自动组优先 IX 绑定的出口）。
- 地区组：出口按地区分组，组可以自动（按用户排的顺序切换，IX 优先，带滞回）或手动（指定成员，失效时保持或回落）；每个组有自己的标记、中转地址和枢纽路由表。旧的出口池在升级时迁移成组。
- 名单源：国内镜像、海外（GitHub raw）或全自动；geosite 的 `include:` 递归展开；更新经宿主上的 `meridian-host` 执行，失败保留旧版，重载时重新加入上次的 chnroute；宿主记录每个名单的来源、时间和条数。
- 服务器、密钥与 Cloudflare：远端机器是面板里的「服务器」（密码或私钥登录、主机指纹先发现再确认、连接测试），装机和 Mesh 部署只按 ID 引用；Cloudflare 账户带只读权限检查。秘密放在单独的 `meridian-secrets` 卷，只靠文件权限保护，没有静态加密。
- 远程接入：网关上的 `mra` 接口作为第二个受管入口，和局域网同一套分类、DNS 和兜底表；设备之间不互通，面板不对设备开放；设备配置只显示一次。路由器端口转发由你自己做。
- 解锁探测：面板经 `meridian-host` 从所选出口探测 41 个流媒体 / AI 适配器（覆盖表按固定提交逐项对照三个公开脚本的地区清单），结果按证据分级、可驱动服务组的自动选择，真实平台结论待人工核对（[unlock-methods.md](docs/unlock-methods.md)）。
- 家宽到阿里云同时生成 UDP WireGuard 和 WG-over-WSS，按握手和探测切换，带回滞。MTU 按 PPPoE 1492 规划：UDP 1412，WSS 1360，低于 1280 拒绝。
- IX 替换用的两条 WSS（阿里云 → 枢纽、家宽 → 枢纽）随配置一起生成并探测，替换模式关掉时不是默认下一跳。
- WSS 承载的路径和证书由面板生成：每条链路一个 192 位随机路径前缀（服务端只放行这个前缀到这条链路自己的 WireGuard 端口，其他请求一律 400），每个监听一张自签证书（P-256，365 天，合成名称 `….invalid`），客户端把它作为唯一信任根并校验名字（wstunnel 11.1.0 没有指纹固定，用 `SSL_CERT_FILE` + `--tls-verify-certificate` + `--tls-sni-override`）。不用 ACME、不需要域名。路径和私钥在面板凭据存储里，只在安装边界注入；面板只显示「已设置」、指纹和到期时间。重新生成和到期前的自动轮换分阶段进行，两端交替下发、任何时候都能互通、失败保留旧凭据；旧版固定路径和自备证书幂等迁移。自签证书对任何连上来的人都可见，SNI 是明文的合成名称，不伪装成网站。真实 wstunnel 二进制只在本机容器的回环测试里跑过，**没有在真实主机或真实网络路径上执行过**（[架构](docs/architecture.md)「WSS 承载：随机路径与自签证书」）。
- 隧道内使用 `fd66::/48`。这条 ULA 不会指向 ROS。有 IPv6 的出口做 NAT66，没有的出口过滤 AAAA，仍走同一出口的 v4。
- 客户端 IPv6：网关设置「客户端 IPv6 经本网关」默认关闭，因为手机只能手填 IPv4 网关和 DNS、IPv6 仍来自 ROS。关闭时解析器对国内名单以外的所有域名都不返回 AAAA，国外访问只走 IPv4 进隧道，不会从家宽 IPv6 绕过隧道；国内域名照常有 AAAA。只有客户端的 IPv6 默认路由指向网关时才打开（[测试设备](docs/test-device.md)）。
- 未列名单的域名：网关设置「未列名单的域名也问国内 DNS」默认关闭（严格：名单外的名字只经隧道解析）。打开后名单外的名字由网关上的 `meridian-dns-split` 同时问国内和出口解析器，只有国内回答里的地址全是中国地址时才采用并直连，其余（CNAME 指向国外、混合、被污染）用出口的；代价是国内解析器能看到所有名单外的域名（包括国外的），DNS 泄漏测试里会出现它们。「客户端 IPv6」关闭的行为在真实网关上确认过；未列名单的国内解析第一版（SmartDNS 自己过滤）在真实网关上把「CNAME + 国外地址」变成没有地址的回答，现在这一版 2026-11-13 由主会话在真实网关上测过一次（冷的国外名字 52–72 ms 解析到出口地址、原先只剩 CNAME 的名字正确、名单外的国内 CDN 名字约 8 ms 直连、关掉立即生效、`meridian-verify.sh` 通过），没有存档的日志；外部出口、挂靠出口、多中继、Mesh 和远程接入下没有在真实环境里用过。规则命中的名字（包括指向默认组的规则）只问自己目标的解析器，打开这个设置也不会发给国内解析器。iOS 提示「无线局域网没有接入互联网」**不知道是否已经解决**，没有设备上的证据，复测和脱敏抓包步骤见[测试设备](docs/test-device.md)「iOS 联网检测复测」（[架构](docs/architecture.md)「客户端 IPv6 与 AAAA」「未列名单域名的国内解析」）。
- IX 可以画成受管的主枢纽（「IX 即主枢纽」：国内入口地址给中继拨，香港出口地址连出口，经中继端口转发、仅密码登录也能管理），另加一个备用枢纽：主链路（网关 → 中继 → IX）端到端不通时网关经 WG over WSS 改走备用枢纽，出口按连接从来的那个枢纽回包，面板显示当前承载的枢纽并从它读取地区组的实际状态。这部分只有自动化测试，命名空间测试写好未执行，没有真实主机证据；详见[架构](docs/architecture.md)「主枢纽与备用枢纽」。
- 多台国内中继同时分担主链路：每个新连接在建立时按流哈希分到一台中继（同一连接始终走同一台，回程在中继和主枢纽按入接口沿来路返回），权重由网关按测得的路径质量自动设定（端到端丢包和时延、负载下的时延膨胀、有业务时 TCP 收不到回包，可疑时才做受预算限制的短时吞吐探测，面板写明它消耗的计费流量）；轻度劣化先降权、再停止分配新连接，低于可用下限一段时间后剔除并默认重置该中继上的 TCP 连接，恢复后经滞回逐步加回；所有中继都持续不好用时才改走备用枢纽，备用不更好时留在相对较好的中继上并告警，全部不通时失败关闭。测量和决定在网关上（宿主机的 `meridian path-step`，面板停掉不影响），面板显示每台中继的份额、测量值和时间、流量、剔除原因和断连影响。只有自动化测试和命名空间测试，没有真实中继和真实限速的证据；详见[架构](docs/architecture.md)「多中继同时分担」。
- 挂在中继出口后面的出口：只能主动拨出、连不上枢纽的出口（`via_exit`）只有一条隧道，拨向一台受管的中继出口；中继出口在自己的枢纽隧道和这条隧道之间转发，同时照常做地区组成员。只支持一层。枢纽按下一跳区分它和中继出口（`via … onlink` 加源地址改写），回包按连接从来的枢纽返回，组解析和独立解析地址在挂靠出口自己那里解析，中继出口下线时组按原规则切走，没有路径时失败关闭（中继出口的 WAN 永远不出挂靠出口的流量）。出口可以填动态域名端点（`endpoint_host`），拨号的一端握手超过 150 秒就重新解析。
- 外部 SOCKS 出口：面板不登录、不下发安装包的设备（例如已经拨入某台受管出口、在隧道地址上提供带认证 SOCKS5 的小路由器），只承载 **IPv4 的 TCP**：承载节点上的固定版本 gost 3.2.6 透明重定向到 SOCKS，UDP（含 QUIC）和 IPv6 在承载节点上当场拒绝，从不经承载节点的 WAN 或别的出口出去；发往它的域名在承载节点上解析，上游查询经 SOCKS 用 TCP 问 1.1.1.1 / 8.8.8.8，不回落、不返回 AAAA；健康 = 经 SOCKS 的 DNS over TCP 查询；用户名和密码只在受限凭据存储里，只在承载节点的装机边界注入；解锁探测标为「仅 TCP」。两项功能都只在本机容器的命名空间测试和固定版本二进制测试里跑过，**真实的 NAT 出口、中继出口和路由器都没用过**（[架构](docs/architecture.md)「挂在中继出口后面的出口」「外部 SOCKS 出口」）。
- 台湾和香港家宽按「由对端拨向枢纽」生成配置：枢纽不写公网 Endpoint，PersistentKeepalive 必须打开。
- DNS 劫持 53/853，并按已知清单拦截 DoH。清单不能覆盖所有 DoH，文档里写明了这个边界。
- 面板（概览、拓扑、出口与地区组、分流规则、名单、服务器、密钥、Cloudflare、远程接入、部署、解锁、防泄露）可以加节点、拉线选择传输、校验必经 IX、编译配置、看差分、安装到本机和回滚，并带手动规则和 geosite 默认表；顶栏显示宿主执行通道和安装状态。
- SSH 装机经面板里的服务器执行（脚本走标准输入），用 `wg syncconf` 更新，避免拆掉 NAT 映射。演练模式不连接远端。
- 装机前预检：远端节点（经已固定指纹的 SSH 跑固定的只读脚本）和网关（经 `meridian-host` 的只读 `/v1/preflight`）在动手之前列出将要做的变更和与主机上已有东西的冲突，有阻断项就拒绝并说明怎么处理，不覆盖别的服务；执行前再复核一次。第一次装机失败时补偿或逐项列出残留。
- 面板下发的二进制与支持平台：wstunnel 11.1.0、SmartDNS 1.2026.08.05-0921（Release48.4）和 gost 3.2.6（外部 SOCKS 出口的重定向器，只装在承载节点上）由面板按架构（x86_64 / aarch64）提供固定版本，版本和 SHA-256 只写在 `internal/artifacts/artifacts.lock` 一处；镜像构建时下载并核对（或从 `deploy/artifacts/` 取离线副本），面板启动和每次发送前再核对，经已固定指纹的 SSH 连接传到主机，主机在激活前再核对，不符就拒绝。主机从不自己下载；二进制装在 Meridian 自己的 `/usr/local/sbin/meridian-*`，出口解析器由 `meridian-smartdns.service` 运行、只绑隧道地址，主机上别人的 wstunnel / smartdns 不覆盖也不删除；网关的 WSS 客户端也由安装事务写入同一份 wstunnel。远端节点支持 Debian 12 / 13（x86_64）和 Ubuntu 20.04（aarch64，内核 5.15，legacy iptables 不切换），其他系统拒绝；缺的 nftables / wireguard-tools 列进安装计划；要跑解析器的节点内存低于预算时阻断。登录方式不被接受时，只在服务器提供公钥登录时才建议改用密钥。这些只在自动化测试里跑过，**没有在真实主机上执行过**（[架构](docs/architecture.md)「面板下发的二进制与支持的平台」）。
- 撤回与恢复：远端节点按装机时写下的清单撤回（绑定部署时的主机和指纹，先列计划再确认），中断的装机可以恢复，旧版本装过的节点有「旧版清理」；网关撤回到只剩局域网兜底表。
- 面板开机时局域网地址还没就绪（DHCP）会有界地等待并在日志里说明，不再靠容器崩溃重启；永远只绑局域网地址。安装结果会读回受管 sysctl 在内核里是否生效。
- 二期：同一组里可以有多台香港出口和多条家宽。健康检查在枢纽上做，连续失败才换下一跳，并带回滞。Mesh 以 sidecar 跑在枢纽和出口上。
- 三期：纯 IPv6 出口经双栈中继或 Mesh 到达；NAT64 只生成占位文件；面板有防泄露清单，并写明 WebRTC host 候选的 GUA 限制。
- 验收分三级：`go test` / 面板测试的自动化回归、在 Linux 上实际运行并存档的集成证据（netns 测试、`meridian-verify.sh` 等），以及测试机 / ROS / 断隧道 / 抓包 / 真实出口切换 / Cloudflare / 路由器转发 / 手机拨入 / 平台解锁的人工签收。单元测试和面板的「配置包含」都不证明没有泄漏，见[验收清单](docs/verification.md)。仓库里存档了三份 Debian 13 执行记录（都只是第二级的集成证据）：2026-11-12 对应提交 `d9b8556`，2026-11-13 对应提交 `233e17b` 的最后一次构建，2026-11-13 晚的 mesh-dns 记录只有 Mesh 解析改动之后的三个 netns 测试。装机前预检、补偿、撤回、开机等待、sysctl 读回和枢纽身份绑定都还**没有在任何真实主机上执行过**，这一版也还没有装到任何主机上；交接记录和已知限制见[验收清单](docs/verification.md)「交接记录」。

## 路线图

| 阶段 | 内容 |
| --- | --- |
| 一期 | 必经 IX 的 WG、UDP/WSS、预置替换隧道、香港池、ULA、默认规则和手动规则、台湾拨出、家宽属性 |
| 二期（本仓库） | 多港机与多家宽池化、按成员做健康检查和滞回、Mesh sidecar、每 6 小时解锁测试、同网段 rp_filter / 重定向验收 |
| 三期（本仓库） | 纯 IPv6 与「v6 入 v4 出」走双栈中继或 Mesh；NAT64 只预留、不进路由表；防泄露清单，含 WebRTC host 候选的 GUA 限制 |
| 面板改版（本仓库；隔离集成证据见 2026-11-13 的执行记录，实机人工签收未做） | 服务器 / 密钥 / Cloudflare 账户与秘密存储、旧安装接管、地区组替换出口池、可选名单源、远程 WireGuard 接入、14 个解锁适配器与证据分级、面板重建与 `GET /api/status` |
| 部署收口（本仓库；只有自动化回归，没有在真实主机上执行过） | 装机前预检（远端与网关）、失败补偿、撤回与恢复、旧版清理、枢纽状态绑定身份、开机等待局域网地址、受管 sysctl 读回、整条面板流程的端到端测试 |

纯 IPv6 出口在枢纽没有 IPv6、又没有把绕行真正接上时，面板会拒绝保存。家宽网关不运行 Mesh。NAT64 即使在面板里标成启用，也不会改写现有 IPv4 路由。

## 快速开始

在全新的 Debian 13 上，地址固定为 `192.168.100.88/24`，与 ROS 同一二层。不要把这台机器的上游接到旧的 mihomo 后面。

```bash
sudo bash deploy/debian/install.sh
sudo docker compose -f deploy/docker-compose.yml up -d --build
```

面板口令在面板容器的命名卷里，宿主上直接 `cat /var/lib/meridian/panel.token` 通常读不到，要从容器里读：

```bash
sudo docker compose -f deploy/docker-compose.yml exec meridian cat /var/lib/meridian/panel.token
```

浏览器打开 `http://192.168.100.88:8787`。第一次部署按面板的顺序走：密钥 → 服务器 → 确认主机指纹 → 连接测试 → 拓扑里为节点选服务器 → 远端预检 → 远端第一次装机 → 网关预检 → 安装到网关 → 更新名单 → `meridian-verify.sh`（细节和冲突处理见 [安装](docs/install-debian13.md)「第一次部署：按面板的顺序」「预检发现冲突时怎么办」）。示例拓扑里的 `203.0.113.0/24`、`198.51.100.0/24`、`2001:db8::/32` 和 `example.invalid` 都是文档占位，下发前必须换成你自己的端点。不要把真实地址、密钥或 token 提交进仓库。

继续阅读：

- [Debian 13 安装](docs/install-debian13.md)
- [测试设备](docs/test-device.md)
- [验收清单](docs/verification.md)
- [数据面说明](docs/architecture.md)
- [远程接入](docs/remote-access.md)
- [解锁探测方法与证据分级](docs/unlock-methods.md)

本地开发和测试：

```bash
go test ./...                     # 代码级回归；netns 测试在这里跳过（需要 Linux root 和 MERIDIAN_NETNS_TEST=1）
npm --prefix web ci
npm --prefix web run build        # 类型检查 + 打包
npm --prefix web test             # 面板用例（vitest，假 API）
MERIDIAN_BIND=127.0.0.1:8787 MERIDIAN_DATA=/tmp/meridian MERIDIAN_WEB_DIR=web/dist go run ./cmd/meridian
```

这些只提供代码级证据，见[验收清单](docs/verification.md)「每个命令能证明什么」。

## English

Meridian is a LAN policy-routing gateway. Test clients use `192.168.100.88` as their IPv4 gateway and DNS. China prefixes go straight out via RouterOS `192.168.100.1`. Everything else must cross Aliyun Shanghai, the Shenzhen–Hong Kong IX, and the Hong Kong hub before it reaches an exit. The existing mihomo host and RouterOS stay untouched.

The compiler covers the IX path, region groups (manual or automatic exit selection per region, migrated from the old pools), selectable list sources, remote WireGuard access for the user's own devices (a second managed ingress with the LAN's rules), managed servers / SSH credentials / Cloudflare accounts (secrets in a separate volume protected by file permissions only, no encryption at rest), a Mesh sidecar that cannot bypass the IX, six-hour unlock hysteresis, and pure-IPv6 reachability through a dual-stack relay or Mesh. With two or more domestic relays the gateway shares the main path across all of them: each new connection is pinned to one relay by flow hash (replies return the way they came on the relays and the primary hub), weights follow quality the gateway measures itself (end-to-end loss and RTT, RTT inflation under load, TCP without replies under demand, and a budgeted throughput probe only when those look suspicious); degraded relays are de-weighted, then evicted (their TCP connections reset by default) and re-admitted gradually; the backup hub takes over only when every relay is persistently below the floor, and everything fails closed when nothing answers. This has unit and namespace tests only, no real relays or real throttling. Streaming/AI unlock tests can be started from the panel (解锁 → 面板探测) and run on the same chain as the six-hour schedule: meridian-host sends them through the chosen exit's fwmark and transit address over a forced IPv4 or IPv6, confirms the actual egress before and after, and only fixed catalog targets are probed; real-platform verdicts and the on-gateway egress still need human sign-off (docs/verification.md). NAT64 is reserved and is not installed into the routing table. Two resolver settings, both off by default: `clients_ipv6_via_gateway` (off: the gateway resolver returns no AAAA for any name outside the domestic lists, so phones that take IPv6 from the home router cannot bypass the tunnel over IPv6) and `unlisted_domestic_dns` (on: unlisted names go to a small gateway service, `meridian-dns-split`, which asks the domestic resolvers and the default exit's resolver and uses the domestic answer only when every address in it is a China address; the domestic resolvers then see every unlisted name, foreign ones included). The AAAA behaviour was confirmed on the real gateway; the first version of the unlisted-name check (SmartDNS's own whitelist) failed there on CNAME answers; the current one was measured once on the operator's gateway by the main session on 2026-11-13 (cold foreign names resolved to the exit's address in 52–72 ms, the CNAME-only names fixed, unlisted names with China CDN nodes answered domestically in about 8 ms and routed direct, the setting takes effect at once, the gateway verify script passes) with no archived log, and has not been used with external, nested, shared-relay, Mesh or remote-access paths on real hosts. Rule-targeted names (including a rule aimed at the default group) only ever go to their own target's resolver, also with the split on. The iOS "Wi-Fi has no internet" report is not known to be fixed: there is no device evidence (retest and sanitized capture steps in docs/test-device.md). Documentation addresses only; do not commit real endpoints or keys. Read the panel token from inside the container (`docker compose -f deploy/docker-compose.yml exec meridian cat /var/lib/meridian/panel.token`); it lives in a named volume, not on the host path. Unit tests and the panel checklist only check generated configuration; they do not prove the absence of leaks. Release needs the gateway `meridian-verify.sh` output, isolated Linux integration logs and human sign-off on a real client, ROS, a tunnel cut and packet captures, plus real exit switching, Cloudflare Mesh, the router forward and a phone on cellular (docs/verification.md, docs/remote-access.md). The panel walks a first deployment in a fixed order (key → server → host-key fingerprint → connection test → topology binding → remote pre-check → first provision → gateway pre-check → gateway install), refuses each step before its prerequisite, refuses and explains conflicts with what already runs on a host instead of overwriting it, and can withdraw remote nodes (bound to the host they were provisioned on) and the gateway (down to the LAN guard). Three Debian 13 records are archived, all isolated-integration evidence only: 2026-11-12 covers commit `d9b8556`, 2026-11-13 covers the final build of commit `233e17b`, and the later 2026-11-13 mesh-dns record covers only three netns tests after the Mesh DNS change. Pre-checks, provisioning compensation, withdraw, the boot-time LAN wait, the sysctl read-back and hub identity binding have not been executed on any real host, and this version has not been installed anywhere yet; see the hand-over record in docs/verification.md.
