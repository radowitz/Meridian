# 验收清单

在[测试设备](test-device.md)上做。网关和 DNS 都已经指向 `192.168.100.88`，IPv6 默认路由指向网关的链路本地地址，路由器发现已关闭。

## 证据的三种等级

整份清单只用下面三种说法，不混用：

| 等级 | 是什么 | 谁来跑 | 能说明什么 |
| --- | --- | --- | --- |
| **自动化回归** | `go test ./...` 里的单元/脚本测试，以及面板「防泄露」页的「生成配置核对」 | CI、任何开发机 | 生成的文本、脚本控制流和状态机符合设计。**不能**说明规则已经加载到网关，**更不能**说明不泄漏。 |
| **隔离 Linux 集成证据** | netns 测试（`TestNetnsReloadNoLeak`）、`deploy/verify-smartdns.sh`、`deploy/verify-host-exec.sh`、`deploy/verify-mesh-veth.sh`、网关上的 `meridian-verify.sh` | 人在 Linux 主机或网关上以 root 运行 | 只有真的运行过、并把完整日志/证据目录存档后才算数。没有存档就是「未执行」/「未验证」。 |
| **实机人工签收** | 真实测试机上的 DNS 泄漏和 WebRTC、ROS 上的 `fd00::/8` 只读查询、断隧道、抓包 | 人，在真实网络上 | 唯一能支撑「这台测试机在这些条件下没有看到泄漏」的证据。签收时写下日期、拓扑版本、截图/命令输出/pcap 的存档位置。 |

面板「防泄露」页按这三类分组：生成配置核对显示「配置包含 / 失败」，集成项一律显示「未执行」，实机项一律显示「待人工签收」——面板不运行它们，也不会把它们标成通过。发布前三类都要有证据；只有第一类绿，不能写成「已验证无泄漏」。

### 已存档的执行记录

| 日期 | 环境 | 范围 | 存档 |
| --- | --- | --- | --- |
| 2026-11-12 | 全新 Debian 13 虚拟机（内核 6.12、nftables 1.1.3、systemd 257），示例拓扑，隧道未握手 | 第二类（隔离 Linux 集成证据）的五个入口各跑通一次，外加首次安装、升级、回滚、重启的手工核对 | [docs/evidence/2026-11-12-debian13](evidence/2026-11-12-debian13/README.md) |

这份记录只覆盖第二类，而且只对当时那一版代码和那台主机成立；改了防火墙、路由、安装脚本或宿主执行之后要重跑。第三类（实机人工签收）至今没有任何记录：下面标着「待人工签收」的每一项都还没做。Cloudflare Mesh 的真实部署和解锁探测的真实平台判定也没有执行过。

## 路径

- [ ] `ip route` 只有一条 IPv4 默认路由，下一跳是 `192.168.100.88`。
- [ ] `ip -6 route` 的默认路由是网关的 `fe80::`，不是 ROS。
- [ ] 访问一个国内站点，源地址仍走家庭网络，不进隧道。
- [ ] 访问一个普通境外站点，出口 IP 是香港池里 IX 绑定的那台，而不是家宽、阿里云或 ROS。
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
- [ ] 台湾规则失败时不会自动改去日本。解锁结果只在同一池里换成员。

## 回滚

- [ ] 面板「回滚」之后，阿里云向东的首选路由回到上一份。
- [ ] 测试机把网关和 DNS 改回 `192.168.100.1` 后，立刻回到原来的 mihomo 路径，ROS 不需要改配置。

## 同网段：重定向和 rp_filter

网关 `192.168.100.88/24` 和 ROS `192.168.100.1` 在同一个二层。国内回程可能由 ROS 直接交给客户端，所以 `rp_filter` 必须是 loose（2）。本机发送 ICMP 重定向必须关掉，否则境外目的有可能被指去 `.1`。

### meridian-verify.sh（隔离 Linux 集成证据，网关上以 root 运行；2026-11-12 执行过一次，见已存档的执行记录）

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

本机检查（会执行）：

- 运行中的 `rp_filter=2`（all、default、局域网口）、`send_redirects=0`（all、局域网口）、v4/v6 `accept_redirects=0`、`ip_forward=1` 和 `ipv6 all.forwarding=1`（转发只在兜底表加载之后由 `meridian-up.sh` 打开，所以它为 1 也间接说明 up 脚本走完了）。
- 网关地址在局域网口上；`ip route get <ROS>` 是同链路邻居（没有 `via`）。
- `ip -6 route show table all` 里没有任何 ULA（`fc00::/7`）路由走局域网口或指向 ROS 的链路本地地址。
- **防火墙必须存在**：没有 `nft` 命令、`inet meridian_guard` 不在、或 `inet meridian` 不在，都是 `FAIL`，不再是 SKIP。兜底表要有 forward 钩子、优先级 -200 和 `fail closed` 那条丢弃；主表要有 53/853 的 `redirect`、非局域网 DNS 的 input 丢弃和 `ip6 daddr fc00::/7 drop`。
- ROS `fd00::/8` 黑洞：只有设置了 `MERIDIAN_ROS_SSH` 时才执行一条只读的 `/ipv6 route print terse where blackhole`，输出里有 `dst-address=fd00::/8` 或 `fc00::/7` 才 `PASS`；ROS 回答了但没有这条是 `FAIL`；连不上是 `UNKNOWN`。没设置就是 `PENDING-HUMAN`。

一定是 `PENDING-HUMAN`（脚本不跑浏览器、不抓包、不断隧道）：`dns_leak_client`、`webrtc_srflx`、`redirect_on_wire`、`tunnel_cut`。一定是 `NOT-RUN-HERE`：netns 重载测试、`verify-smartdns.sh`、`verify-host-exec.sh`。

退出码：有 `FAIL` 为 1（最后一行 `meridian-verify-failed`）；没有 `FAIL` 但有 `UNKNOWN` 为 2（`meridian-verify-incomplete`，在没有 `/proc`、`sysctl` 或 `ip` 的容器里就是这样，不再退出 0）；全部本机检查通过才是 0，最后一行 `meridian-verify-local-ok`。这一行只代表本机检查，**不是**防泄露结论，也不是发布签收；脚本不再打印旧的 `meridian-verify-ok`。

自动化回归（`go test ./...`）：`TestVerifyScriptExecutedChecks` 用桩程序（`sysctl`/`ip`/`nft`/`ssh`）在 bash 里真的执行生成的脚本，覆盖：全部通过、没有 nft、缺主表、缺兜底表、转发关闭、不在网关上（`UNKNOWN`、退出 2）、ULA 指向 ROS、ROS 有/没有黑洞、ROS 连不上、`MERIDIAN_ROS_SSH` 注入被拒。它只证明脚本的判定逻辑；桩里喂的是编译出来的 nft 文本，真实 `nft list` 的输出格式是否被这些匹配接受，要在网关上跑一次确认（格式不同只会让对应项 `FAIL`，不会误报通过）。

- [ ] 在网关上运行一次，最后一行是 `meridian-verify-local-ok`，证据目录已存档。
- [ ] 临时 `nft delete table inet meridian_guard` 之后再运行（只在测试网关上做，做完重新安装）：`nft_guard` 为 `FAIL`，退出码 1。

面板「防泄露」页对生成配置做同样的文本检查，那是自动化回归，不替代上面的运行结果。下面这些打勾项里，标了「实机」的没法在仓库的单元测试里做。

- [ ] `sysctl net.ipv4.conf.all.rp_filter` 和每个接口（含 `eth0`）都是 2。生成配置和 `meridian-verify.sh` 会查；实机上再看一遍运行值。
- [ ] `net.ipv4.conf.all.send_redirects`、`net.ipv6.conf.all.send_redirects` 以及对应接口都是 0。
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
- 兜底只挂 forward，不影响 RA、ND 和访问网关本机（input）的流量，也不匹配从隧道回来的流量。IPv4 原有的 `ip rule iif eth0 unreachable` 保留，作为路由层的第二道；IPv6 仍然不加这条规则，因为没有证明过它不会吃掉 RA/ND，IPv6 的兜底只靠 nft 这张表。

仓库里能跑的（macOS / 任意平台，`go test ./...` 会跑）：

- `TestNFTAtomicReplace`：每份 nft 文件都是「建-删-重建」写法，每张表只定义一次，没有 `flush`，兜底表在被保护的表之前。
- `TestGatewayGuardStructure`：兜底表的四条规则、优先级、没有跨表引用、最后一条不带协议族限定的 drop，以及 IPv6 没有 iif 规则。
- `TestUpScriptLoadsFirewallFirst`：`nft -c` 在 `nft -f` 之前，二者都在 `sysctl`、`wg-quick`、路由脚本之前，脚本里没有别的 nft 改动命令。
- `TestUpScriptFailurePreservesState`：用桩程序在 bash 里真的执行网关的 `meridian-up.sh`，分别让检查失败、加载失败、兜底表缺失、文件缺失，确认脚本停下、不调用 `sysctl`/`wg`/`ip`/路由脚本、也从不发 delete。
- `TestInstallSurfacesFirewallLoadFailure`（internal/apply）：激活失败会作为错误返回给调用方。

这些只证明生成的文本和脚本控制流。内核是否真的整批回滚、持续流量下是否真的没有一个包漏到 ROS，只能在 Linux 上验证。

### 运行时测试（Linux，root；2026-11-12 执行过一次，见已存档的执行记录）

在一台可以随便建网络命名空间的 Linux 机器上（不要在网关本机上跑），需要 `ip`、`nft`、`ping`、`bash` 和 Go：

```
sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsReloadNoLeak -count=1 -v
```

它只在自己建的四个命名空间里动（客户端、网关、ROS，加一个放网桥的），结束时删掉。网关命名空间里装的是编译出来的 `meridian-routes.sh` 和 `meridian.nft`，隧道用 dummy 接口代替，并给网关加一条经 ROS 链路本地地址的 IPv6 main 默认路由（就是审计里的泄漏路径）。客户端持续向「境外」v4/v6 地址和一个写进 `direct6` 的「国内」v6 地址发 ping，ROS 上计数。

- [ ] 对照：没有任何 Meridian 表时，境外 IPv6 能到 ROS（`foreign6>0`）。不满足就说明测试环境没覆盖到泄漏路径，结果作废。
- [ ] 首次安装：加载后境外 v4/v6 到 ROS 为 0，国内 IPv6 能到 ROS，隧道接口有发送。
- [ ] 持续流量下连续重载 200 次：境外 v4/v6 到 ROS 为 0。
- [ ] 加载失败注入（批次末尾一条坏规则；兜底表和主表之间一条坏规则）：`nft -c` 和 `nft -f` 都失败，两张表的内容（除计数值）与之前完全一致，`meridian-up.sh` 的加载段停下，期间境外为 0，国内路径仍通。
- [ ] 只删 `inet meridian`（模拟旧流程两次 nft 之间的空窗）：只靠兜底表，境外和国内都到不了 ROS。
- [ ] 日志里有每一阶段的 `EVIDENCE` 行，最后一行是 `meridian-netns-reload-test-ok`。把整份日志存档；没有存档就仍是「未验证」。

### 已知边界（仍未解决）

- 开机空窗（已改；2026-11-12 在一台 Debian 13 上重启核对过加载顺序，见已存档的执行记录）：`99-meridian.conf` 不再打开转发，网关上反而显式写 `ip_forward=0` / `all.forwarding=0`；转发只由 `meridian-up.sh` 在 nft 批次和兜底表确认之后，从 `/etc/meridian/forwarding.conf` 打开。另有 `meridian-guard.service`（`DefaultDependencies=no`，排在 systemd-sysctl、Docker 和 meridian.service 之前）开机先只加载 `meridian-guard.nft` 里的兜底表；安装脚本给新的 `daemon.json` 加了 `"ip-forward": false`。验证见下面「宿主执行与运行态回滚」。
- 每次重载会重建集合，SmartDNS 写入的 `direct*`/`r*`/`default*` 和 chnroute 都会被清空，直到再次解析或重跑 `meridian-update-chnroute.sh`。这段时间国内目标会被当成境外走默认出口，不会漏到 ROS，但国内流量会绕路。
- geosite 名单不展开 `include:`。`meridian-update-geosite.sh` 跳过所有 `include:` 行，而 v2fly 的 `cn` 只有两行 include（`tld-cn`、`geolocation-cn`，后者又包含一百多个子文件），所以 `geosite/cn.txt` 实际上总是空的：脚本会报「cn has no domains」并保留旧文件。国内域名因此不走国内 DoT 上游、也进不了 `direct4`/`direct6`；按地址的 chnroute 分流不受影响，所以是国内域名绕路解析，不是泄漏。尚未修。
- 默认名单源 `raw.githubusercontent.com` 在走国内线路的网关上通常连不上。脚本现在会限时失败并保留旧数据，可以用 `MERIDIAN_GEOSITE_BASE_URL` / `MERIDIAN_CHNROUTE_BASE_URL` 换源（见安装文档），但没有自动选源，也没有定时任务。
- `net.ipv6.conf.*.send_redirects` 在 Linux 上不存在。生成的 sysctl 文件和安装脚本仍会写它，结果是几行 `skip sysctl` / `cannot stat` 的噪音，不影响别的键。
- 面板探测失败时，错误文字里的 `lookup … on <系统 DNS>:53` 是 Go 解析器套用的名义地址；实际的查询发往出口解析器（同一行后半段的套接字地址）。文字容易误读，尚未改。
- 兜底只管从局域网口进来的转发。如果以后在网关上用非 host 网络的 Docker 发布端口给局域网，兜底会把它丢掉（出接口不是局域网口）。

## 宿主执行与运行态回滚

面板（容器或裸机进程）不在宿主上直接执行任何命令。所有运行态动作都经宿主上的 `meridian-host`（`meridian host-agent`，`deploy/debian/meridian-host.service`）：只有 `activate`、`health`、`rollback` 三个动作（另有只读的解锁探测 `/v1/probe`，见「面板发起的解锁探测」），参数只能是受管资源名（`m00`/`m00w`/`mmesh` 接口、`meridian-*`/`wstunnel-*` unit、`inet meridian`/`inet meridian_guard`、100–252 号路由表），不接受命令、shell 或路径；root-only Unix socket（目录 0700、socket 0600）+ 口令 + Linux 上要求对端 uid 0；串行执行，每步和整个动作都有超时，同一 `request_id` 重试只回放结果，不重复执行。`rollback` 只删除 agent 账本里激活过的资源；从未激活但同名且正在运行/存在的资源整单拒绝，什么都不改。

安装与回滚都是一份持久事务（`/var/lib/meridian/host/journal.json`）：受管清单（文件+哈希、接口、unit、nft 表、路由表、sidecar、版本）前后求差，先删旧清单独有的运行资源和文件，再写新文件，最后 `activate`（daemon-reload → `reset-failed` 后重启 `meridian.service` 跑 `meridian-up.sh`（失败时 `stop` 取消它的自动重试，免得和补偿并发） → 启用并重启清单里的 unit → 需要时重启 SmartDNS → 两次采样的健康检查）。任一步失败就把宿主和数据目录快照一起补偿回事务前；补偿也失败时保留日志、拒绝新的安装和回滚，面板「恢复」或进程重启时再补偿。到了提交阶段才中断的事务在恢复时补完提交，不撤回。

仓库里能跑的（`go test ./...`）：

- `internal/hostexec`：拒绝非受管名字、额外字段、错误口令；固定步骤顺序；第一处失败即停并带上 journal；步骤超时和整体超时；串行；`request_id` 回放与冲突；账本外资源的拒绝/跳过；删兜底表前先关转发；SmartDNS 两种形态与缺失时的告警；丢失响应后重试只执行一次；部署文件的接线（静态）。
- `internal/apply` 的 `txn_test.go`：用真的 agent 加模拟宿主跑首次激活失败（补偿到「未安装」）、激活超时（补偿到上一版）、健康失败、重复与并发调用、拓扑删除链路后删除其文件/接口/unit 且不碰非受管的 `m99`、新增资源后运行态回滚把它们删掉且 up 脚本只激活旧清单、补偿失败不报成功并阻止新事务、回滚中途进程退出后重启恢复、提交阶段中断后补完提交、旧快照升级。
- `internal/api`：已安装时 `{}` 回滚被拒绝；`install` 与 `snapshot_only` 互斥；没有宿主执行能力时 503 且不写快照；失败返回带补偿结果的事务报告。
- `internal/compile`：up 脚本只列清单里的接口，缺文件即失败；没有 systemd 时 `meridian-systemd-missing` 失败而不是跳过；sysctl.d 不开转发，转发在兜底检查之后。

### 实机（Debian 13 网关，root；2026-11-12 执行过一次，见已存档的执行记录）

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
- [ ] 名单源不可达时 `meridian-update-chnroute.sh` / `meridian-update-geosite.sh` 在超时内退出（1），已有名单文件和 chnroute 集合不变；设置 `MERIDIAN_*_BASE_URL` 指向可达副本后正常更新。
- [ ] `meridian-host` 的沙箱（`ProtectSystem=strict`、只留 `CAP_NET_ADMIN`）下 `systemctl enable`/`restart`/`reset-failed`/`stop`、`ip link del`、`nft delete table`、`sysctl -w`、`journalctl`、`docker restart meridian-smartdns` 都能成功；任何一个失败就要放宽对应选项并记录。

已知边界：

- 第一次用这一版安装到一台用旧版本装过的网关时，宿主上没有旧清单。此时安装失败的补偿会把 Meridian 全部移除（先关转发再删兜底表），而不是回到旧版本；旧版本留下但新清单里没有的 `m*.conf` 不会被删除，也不会再被 up 脚本拉起。
- agent 重启会丢掉 `request_id` 缓存；面板此时重试会重新执行该动作。所有动作本身是幂等的（重启、存在才删）。
- `meridian-up.sh` 在 `/usr/local/sbin`，面板容器可写，并由 `meridian.service` 以 root 执行。边界保证的是「面板只能让宿主执行它自己写的 Meridian 脚本和固定动作」，不是「面板被攻破后宿主安全」。
- SmartDNS 两种形态都不存在时，安装成功但带告警（DNS 分流未生效），因为 Compose 的 dns profile 本来就要等首次安装写好配置后才启动。

## 出口池和 Mesh

- [ ] 香港池里有多台非家宽出口，面板上首选是 IX 绑定的那台。家宽在另一个池，至少两台。
- [ ] 把首选成员的探测连续打失败 3 次，枢纽上该池的路由表下一跳换成同池备成员。只失败 1 次时下一跳不变。（实机：看 `/run/meridian/pool`。仓库里用状态机单测覆盖了同一规则。）
- [ ] 备成员连续成功 5 次后，120 秒冷却未到，不会切回首选。首选已经判死时，这 120 秒不会把下一跳留在另一台也已经判死的成员上。
- [ ] 池内 WireGuard 都失败且该池有 Mesh 边时，下一跳才是 `mmesh`，并且只有 `/run/meridian/mesh-sealed` 存在时才装这条路由。没有密封或没有 Mesh 时，这张表是黑洞，不改去别的国家，也不从枢纽的默认路由出去。
- [ ] 家宽网关上没有 `cloudflare/mesh`，也没有 `dev mmesh`。Mesh 只在枢纽和出口的独立网络命名空间里。本机地址是 `192.168.100.88/24` 时，mesh 脚本拒绝启动。
- [ ] `/etc/meridian/mesh.env` 权限 0600，令牌不在 git 里，由面板部署写入（经 SSH 标准输入传送，不出现在远端进程列表）。文件为空时 sidecar 不启动，其余隧道照常。
- [ ] 删掉 IX 或把 Mesh 从家宽画到出口，保存被拒绝。

### Mesh veth 下一跳（审计 P1）

`mmesh` 是以太网 veth，不是点对点隧道。以前的 `default dev mmesh` 没有下一跳，内核会对每个公网目的地址在 veth 上做 ARP / 邻居发现，而没有任何代理 ARP/ND 或静态邻居来回答；IPv6 也根本没有 veth 下一跳。在 Cloudflare 发布路由修不了这一段。现在：

| | 主机端 `mmesh` | sidecar 端 `mmesh-c` | 主机出口表 |
| --- | --- | --- | --- |
| IPv4 | `169.254.66.1/30` | `169.254.66.2/30` | `default via 169.254.66.2 dev mmesh table N` |
| IPv6 | `fe80::66:1/64 nodad` | `fe80::66:2/64 nodad` | `default via fe80::66:2 dev mmesh table N`（链路本地，作用域由 `dev mmesh` 给出） |
| MAC / 邻居 | `02:6d:65:73:68:01`，永久邻居指向 `…:02` | `02:6d:65:73:68:02`，永久邻居指向 `…:01` | — |

静态路由（`meridian-routes.sh`）和动态出口切换（`meridian-failover.sh` 的 `apply_pool_hop`，`MESH_NH4` / `MESH_NH6`）用同一组下一跳。sidecar 的回程（网关局域网、`10.66.0.0/16`、`fd66::/48`、局域网 IPv6 前缀）`via 169.254.66.1` / `via fe80::66:1 dev mmesh-c`。`meridian-mesh-up.sh` 只在主机侧 ping 通两个下一跳之后才写 `/run/meridian/mesh-sealed`；sidecar 内的 `inet meridian_mesh` 改成一个 nft 事务（建表 → 删表 → 重建）。

- **自动化回归**：`go test ./internal/compile -run TestMeshVethNextHops`、`go test ./internal/verify -run TestMeshItemsNeverClaimForwarding`、`go test ./internal/mesh`（地址与冲突校验、阶段顺序、每个阶段的故障注入与补偿、补偿失败可重试、只撤回本次拥有的资源、凭据不落盘/不回显；撤回只去部署时固定的主机与主机指纹、主机上没有本次备份目录不算已恢复、撤回前核对 Cloudflare 账户、撤回完成前不能切换账户且与凭据修改串行）。只说明生成的文本和控制流正确。
- **隔离 Linux 集成证据（2026-11-12 执行过一次，见已存档的执行记录）**：`sudo bash deploy/verify-mesh-veth.sh`。在四个临时 netns 里按生成的命令搭出 主机 ↔ sidecar ↔「warp」，v4 / v6 的 ICMP 和 TCP 都要经 `169.254.66.2` / `fe80::66:2%mmesh` 转发，`mmesh` 上只解析这两个下一跳；同时把出口表换成旧写法 `default dev mmesh` 作为对照，对照必须不通。最后一行应是 `meridian-mesh-veth-verify-ok`，把证据目录存档。它于 2026-11-12 在一台 Debian 13 上跑通（8 项 PASS，存档在 [docs/evidence/2026-11-12-debian13/mesh-veth.log](evidence/2026-11-12-debian13/mesh-veth.log)），证明的只是命名空间里主机到 sidecar 这一跳；改过 Mesh 的地址、路由或 `meridian-mesh-up.sh` 之后要重跑。Cloudflare、真实 sidecar 镜像和真实出口都不在这项测试里，Mesh 备路的真实转发仍是待人工签收。面板「防泄露」页的「Mesh veth 下一跳双栈转发（netns）」一律显示「未执行」，因为面板不运行它，也不读取存档。
- **实机人工签收（待签收）**：「Mesh 备路真实转发（v4 / v6）」。让池里所有 WireGuard 成员失效、出口表切到 `mmesh` 后，在枢纽 `mmesh` 和出口上抓包，v4 / v6 测试流量从出口离开，`mmesh` 上没有对公网目的地址的 ARP / NS。

在这两类证据存档之前，Mesh 数据面在代码、面板和文档里都是 **未验证**。面板部署的结果「路由已发布」只表示 Cloudflare 路由已经发布，不等于「Mesh 可用」。

### 面板部署 Mesh（部署 → Cloudflare Mesh 部署）

- [ ] 凭据：账户 id + API token 保存在数据目录 `mesh/cloudflare.json`（0600，目录 0700），任何接口都不回显 token；权限比 0600 宽的文件会被拒绝使用。还有已发布或补偿未完成的部署时不能删除凭据。
- [ ] 计划阶段报出：Mesh 边没有 `mesh_routes`、路由与 `10.66.0.0/16` / `fd66::/48` / 局域网 / `100.96.0.0/12` / veth 链路重叠、两条边路由重叠、默认路由、拓扑地址落在 `169.254.66.0/30`。有任何一项时「部署 Mesh」不可点，后端也会在计划阶段停下，不碰任何主机和 Cloudflare。
- [ ] 预检报冲突（已有 `mmesh` / `meridian-mesh` 容器 / `meridian_mesh_lib` 卷 / 非空令牌、`169.254.66.0/30` 或 `fe80::66:1/2` 已被占用、枢纽脚本仍是 `default dev mmesh`）时停下，Cloudflare 没有任何调用。
- [ ] 健康检查不过（任一下一跳不通、`mmesh` 上出现别的邻居、warp-cli 未连接、Cloudflare 节点不是 healthy）时，没有任何路由被发布，本次创建的节点和 sidecar 被撤回。
- [ ] 故障注入演练：面板进程带 `MERIDIAN_MESH_FAULT_INJECTION=1` 启动后，对每个阶段选「在该阶段后失败」各跑一次：后续阶段都是「未执行」，Cloudflare 上本次创建的节点 / 路由都被删除，主机上的 `mesh-sidecar.compose.yml`、`meridian-mesh-up.sh`、`mesh.env` 恢复成部署前的内容，别人的节点和路由不动。
- [ ] 部署后在拓扑里改掉某台 Mesh 主机的 SSH 地址（或删掉该节点）再撤回：面板仍连接部署时的地址并要求原主机指纹；把同一地址换成另一台机器时撤回被拒绝、记录保留为「补偿未完成」。发布后保存另一个 Cloudflare 账户的凭据被拒绝（409），同一账户换 token 可以。
- [ ] 补偿失败（例如撤回路由时 Cloudflare 报错、SSH 不通）时，面板单独列出没撤回的资源，状态是「补偿未完成」，不能开始新部署；修复后再点「撤回 / 重试补偿」，已完成的步骤不会重复。
- [ ] 部署记录 `mesh/deploy.json`（0600）里有每个阶段的状态和本次拥有的外部资源（Cloudflare 节点 id、路由 id、写过的主机），没有 API token、节点令牌或 SSH 私钥。

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

- **只接受枚举值**：面板只能选 `internal/probe` 目录表里的服务（Netflix、Disney+、OpenAI、Claude 有平台判定；Gemini、Copilot、Perplexity、Grok 只做到达性）、拓扑里的出口和 `ipv4` / `ipv6`。请求体有多余字段（`url`、`command`……）直接 400。agent 侧 `ValidateProbe` 再校验一遍：出口 mark 必须在 `0x101`–`0x140`，中转地址必须在 `10.66.200.0/24` / `fd66:0:0:ff::/64`，解析器必须是 `fd66::/48` 里的出口隧道地址，服务必须在目录表里，最多 16 个。没有 URL、主机、端口、请求头、命令或路径参数；`MERIDIAN_UNLOCK_EXEC` 已删除，设置了也只会在日志里提示不再使用。
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

真实平台行为（只能由人对照真实页面核实，仓库里没有向真实平台发过任何请求，适配器全部基于公开的检测思路和合成样例）：

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
- [ ] 网关 nft 文件是单个事务（建-删-重建），带独立的 `inet meridian_guard` 兜底表。运行中重载不漏仍是「未验证」，见上面「防火墙原子替换与 LAN 兜底」。
- [ ] `fd66::/48` 不指向 ROS。
- [ ] 已知 DoH 域名返回 SOA，已知地址的 443 被拒绝。这不是全部 DoH。
- [ ] WebRTC：srflx / 中继候选是出口地址（实机人工签收，ipleak 或 browserleaks）。
- [ ] WebRTC host 候选里可能出现 ROS 通告的 GUA。这是单条运营商 /64 加 SLAAC 的结果，验收时记为已知限制，不当成失败。要去掉它，只能让测试机不用 GUA、改用 ULA 再在网关做 NAT66，国内 IPv6 就不再端到端。
- [ ] 实机人工签收：dnsleaktest.com 与 ipleak.net 的 v4/v6 都属于当前出口地区，没有家庭宽带公网地址。
- [ ] 实机人工签收：ROS 上 `fd00::/8`（或 `fc00::/7`）黑洞的只读查询输出已存档（或 `meridian-verify.sh` 带 `MERIDIAN_ROS_SSH` 的 `PASS ros_ula_blackhole` 及其证据文件）。
- [ ] 实机人工签收：断隧道时测试机不通、ROS / 家庭 WAN 抓包里没有境外流量。
- [ ] 隔离 Linux 集成证据：`meridian-verify.sh` 在网关上 `meridian-verify-local-ok`，证据目录已存档。
