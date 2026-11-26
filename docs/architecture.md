# 数据面

本文说明编译器实际生成的转发方式，方便对照设计方案验收。二期和三期加在同一套表和脚本上，不另起一套数据面。

## 路径

主路径必须能排成：网关 → 国内中继 → IX → 香港枢纽 → 出口。校验失败时面板拒绝保存（草稿除外），编译也会失败。

**没有 IX 的拓扑。** 拓扑里既没有 `ix` 节点也没有 `ix_line` 枢纽时（`model.Topology.HasIX`；IX 的链路全部停用也仍算有 IX，照上一段的规则和报错文本校验），主路径是：网关 → 中继 → 指定的主枢纽 → 出口，每一段都是启用、非待命的链路（`validate/noix.go`）。网关的第一跳必须是中继，中继的下一跳必须是主枢纽本身；缺中继（`path_missing_relay`）、缺主枢纽或拿备用枢纽充当主路径（`path_missing_hub`）、顺序不对（`path_order`）、链路全部停用（`path_not_found`）都拒绝，Mesh 边、待命链路（包括网关到备用枢纽的 WG over WSS）不能代替主路径。这些报错只写角色和节点的实际名称，不提 IX。中继到普通主枢纽可以用 `direct_wg`、`wg_over_wss` 或 `udp_wss_failover`（多台中继同时分担时仍只支持 `direct_wg`，见「多中继同时分担」）；中继拨主枢纽的 `endpoint_v4`（WSS 端口是主枢纽的 `wss_listen_port`），`dial_egress` 在这种链路上只指向这个地址、要求它存在。没有 IX 时 IX 替换 WSS 不是必需的（不再提示 `ix_replacement_not_provisioned`，除非打开了替换模式）。示例：`defaults.NoIXExample`（编译摘要 `internal/compile/testdata/noix_example.golden`）。

数据面和有 IX 的拓扑共用同一套产物：中继的东向（表 150、`meridian-failover.sh` 的 `EAST_IX`）指向它到主枢纽的隧道，`udp_wss_failover` 时 `EAST_WSS` 是同一条链路的 WSS 腿，由中继自己按健康检查切换；主枢纽把家里的前缀路由回中继隧道，`udp_wss_failover` 时（无论几台中继）对两条腿都装入口回程标记（`ingressReturns`，与多中继分担同一机制），回包和本机应答都从连接进来的那条腿回去。网关的端到端探测目标是主枢纽在中继 ↔ 主枢纽隧道上的地址；国内中继的端点归 `endpoint_direct4`，主枢纽和出口的境外端点归 `endpoint_tunnel4`，网关自己拨的备用枢纽端点保留经本地宽带上联的主机路由，不会递归进隧道。链路全部停用的中继不参与探测和分担，部署计划也跳过它（`inactive`）。

两条 IX 替换 WSS 在部署时就写进配置并拉起接口，但 `IXReplacementMode` 关闭时，国内中继向东的默认路由仍指向 IX 上的直连 WireGuard。健康脚本在 IX 连续失败后才切到待命 WSS，并带回滞，避免来回抖。本地宽带到枢纽的那条 WSS 只在国内中继本身也不可达时使用。Mesh 边如果不是「枢纽 → 出口」且待命，直接拒绝。

IX 有两种画法：不可登录的专线仍是 `ix` 角色（中继 → IX 的 `dedicated_line` 加 IX → 枢纽的 `direct_wg` 合成一条中继 ↔ 枢纽的 WireGuard）；IX 本身是一台可登录的服务器并且承担枢纽工作时，把它画成**主枢纽**并打开「IX 即主枢纽」（`ix_line`），中继用 `direct_wg` 直接连它，见下一节。

## 直连出口与单中继

除了「中继 → 枢纽」和「中继 → IX → 枢纽」，拓扑还有两种更简单的形态，首次配置的模板直接生成（`defaults.Templates`，`GET /api/templates`，`POST /api/templates/{id}/preview` 只返回拓扑和校验结果，不保存）。

**直连出口**（`model.Topology.DirectExits`：拓扑里没有任何中继、枢纽或 IX 节点）。网关自己拨每个出口，每个出口一条启用、非待命的 `direct_wg`；主路径是「网关 → 出口」。编译时网关就是这些出口的枢纽（`compile.primaryHubID` 返回网关）：

- 分流：每个出口和地区组仍有自己的 mark、表和中转地址；网关上 `fwmark → 该 mark 自己的表`（经枢纽时是表 102），表里默认路由指向那个出口的隧道，下面垫 `blackhole default metric 32767`；表 102 只有黑洞。
- 防泄露：隧道断开时设备路由消失，命中黑洞而不是 ROS；`fwmark … unreachable` 与转发守卫（出口 mark 只能从隧道出去）照旧；`10.66.0.0/16`、`fd66::/48` 只有黑洞兜底，隧道子网是各接口的直连路由。到出口的密文仍走 `fwmark 0x4d72 → main` 和 `endpoint/32 via ROS`。
- 故障切换：没有西向路径可切；网关的 `meridian-failover.sh` 只跑枢纽那套地区组切换（`group_step`，同样的滞回），组表在成员的隧道之间切换。
- DNS：出口解析器在各自隧道上直连；地区组解析地址经组表到当前成员，出口在来自网关隧道的入口上 DNAT 到自己的解析器（`group_dns`）。
- 测速与多中继分担：只测中继，直连拓扑没有中继，所以不编译（`TestDirectNoRelayMachinery`）。
- 暂不支持（校验报 `direct_unsupported`）：挂在中继出口后面的出口、外部 SOCKS 出口、纯 IPv6 的绕行、WSS / 待命 / Mesh 链路。面板读组运行状态只经 SSH 读枢纽，直连拓扑的组状态在网关上，状态页会说明暂不读取。

**单中继**（拓扑有枢纽、没有中继和 IX）。唯一一台国内服务器既接网关又选出口，所以它在拓扑里是主枢纽；主路径是「网关 → 主枢纽 → 出口」，网关到它是一条常开的 `direct_wg`（网关把它当西向路径，枢纽把它当回家的路）。不支持备用枢纽和 UDP/WSS 双腿（校验报 `relayless_unsupported`）；需要这些时用「中继 + 枢纽」。

含中继、枢纽或 IX 的拓扑编译结果不受影响：既有 golden 与固定摘要只因示例去名化重生成（见 `docs/privacy-inventory.md`「T3 处理结果」），`TestStoredLegacyTopologyCompileUnchanged` 用 T3 改代码前的编译器生成的摘要锁定一份旧格式已存拓扑。回归：`internal/compile/direct_test.go`、`templates_test.go`，合成示例 `defaults.DirectExample`（`examples/topology.direct.example.json`），golden `internal/compile/testdata/direct_example.golden`。这些是生成文件的回归，不是真实网络验证。

## 主枢纽与备用枢纽

拓扑里最多两个枢纽：`hub_tier: primary`（主枢纽）和 `hub_tier: backup`（备用枢纽）。只有一个枢纽且没写层级时它就是主枢纽，迁移会把 `primary` 写进去（幂等，编译结果不变）。

**IX 作为受管主枢纽**（`ix_line`，只能设在主枢纽上，必须是受管节点）：

- 管理目标是它的服务器记录（`server_id`），可以是某台中继上的 TCP 端口转发，只接受密码登录也可以（经转发到达时 sshd 的来源限速按 `ssh_rate_limited` 处理，见「登录方式不被接受」）。
- `ingress_v4` 是国内入口地址，只接受中继连入：中继到它的 WireGuard `Endpoint` 和 WSS 客户端都用这个地址（`Tunnel.DialV4`），网关把它归为国内隧道端点（`endpoint_direct4`），局域网客户端经本地宽带国内直连它（见「局域网到隧道端点」）。
- 链路级 `dial_egress: true`（只能设在中继 → IX 枢纽的链路上，IX 枢纽要同时有 `ingress_v4` 和 `endpoint_v4`，否则 `dial_egress_not_relay_ix` / `dial_egress_without_ingress` / `dial_egress_without_endpoint`）让这条链路的中继改拨 `endpoint_v4`（香港出口一侧）：WireGuard `Endpoint`、WSS 客户端和出口身份摘要（`EgressLegs`）都随 `Tunnel.DialV4` 变。外层包从中继本机按它自己的默认路由发出；IX 的 WireGuard 监听所有地址、香港一侧本来就收隧道，IX 的 nft、回程标记和 `ingress_interface` 加固都不变；网关仍把 `endpoint_v4` 当境外端点（局域网到它走隧道）、`ingress_v4` 当国内端点。不设或 `false` 时编译产物逐字节不变。
- `endpoint_v4` 是香港出口地址：以 NAT 方式拨入的出口拨这个地址；它到出口的隧道从香港一侧发出。源地址由主机路由决定，Meridian 不改主机的路由；预检核对两边（见「WAN 接口」）。
- 可选的 `ingress_interface` 是带国内入口地址的网卡：预检要求地址确实在它上面，路由脚本像 WAN 一样给它设 `rp_filter=2`、关重定向。
- 路径校验把 IX 枢纽同时当作 IX 和枢纽：网关 → 中继 → IX 枢纽 → 出口是一条完整的主路径。拓扑里再有 `ix` 节点、或者有 `dedicated_line` 连着 IX 枢纽时拒绝（`ix_role_with_ix_hub`、`ix_hub_dedicated_line`）。
- 开机单元、DOCKER-USER 共存规则、端口规划、内核参数范围对它和对其他远端枢纽完全一样。

**备用枢纽**（另一台公网机器，不能是 IX）：

- 网关到它画一条 `ix_replacement_wss`、待命（`standby`）的链路：WG over WSS，WSS 端口是备用枢纽的 `wss_listen_port`（N1 的端口模型），wstunnel 客户端端口是链路的 `wss_local_port`。只能有一条（`backup_hub_not_wired`、`backup_hub_ambiguous`）；有备用枢纽时 WSS 备路不能再指向主枢纽（`replacement_to_primary`），网关到备用枢纽也不能用别的传输。
- 每个出口都要和**两个**枢纽各有一条启用的、非待命的 WireGuard（`exit_missing_hub_tunnel`）。NAT 后面的出口两条都由它主动拨出。
- 两个枢纽各自编译同一份地区组计划：同样的组、顺序、约束、mark、表号、中转地址和组解析地址（`compile.planGroupsHub`），只有通往成员的接口不同，所以两边的计划标识（`GROUP_PLAN`）不同，各自上报自己的。出口的表号、mark、中转地址同理（`planExitsHub`）。
- 这一版有备用枢纽时**拒绝**（校验错误，不会半编译）：中继与备用枢纽之间的链路（`backup_hub_relay_link_unsupported`）、经双栈中继 / Mesh / v4 前置到达的纯 IPv6 出口或自己是双栈中继的出口（`dual_hub_unsupported_exit`）、「IX 替换模式」开关（`ix_replacement_mode_dual_hub`：切换是自动的）、枢纽之间的链路（`hub_to_hub_link`）、多于两个枢纽（`too_many_hubs`）。

**网关上选哪条路（一处决定）。** `compile.planUpstream` 列出网关出表 102 的所有路径：主链路的中继腿（UDP，再 WSS），然后备用枢纽。路由脚本和切换脚本带同一段 shell（`UP_*` 数组、`upstream_apply`、`upstream_record`，逐字节相同）：安装时用 `upstream_apply` 把表 102 指向第一条，切换循环用同一个函数移动它，别处不再改表 102（结构测试检查）。两台及以上中继时不用这段，改用「多中继同时分担」的 `compile.planShare`（同样一处决定、同一段 shell 供安装和切换共用）；只有一台中继时编译结果和以前完全一样。

- **主链路按端到端检查**：网关经每条中继腿（`ping -I <腿>`）去 ping 主枢纽在中继 ↔ 主枢纽隧道上的地址，源地址是专用的中转地址 `10.66.200.2`（在 `lo` 上，每条腿一条 `… dev <腿> src 10.66.200.2 metric 10+i` 的主机路由；主枢纽把中转 /24 送回家）。中继活着而它后面的 IX 不通，也算主链路不通。备用路径检查备用枢纽的隧道地址。
- **接管**：没有任何主链路腿应答，连续 `FAILS_NEED`（3）轮后切到备用枢纽。**切回**：主链路腿重新应答连续 `RECOVERS_NEED`（5）轮、并且距上次切换满 `COOLDOWN`（120 秒）。离开一条不通的路不等冷却。
- **全部不通**：表 102 留在原处。每条路径都是 WireGuard 接口加 metric 32767 的黑洞兜底，兜底表只允许出口 mark 从网关的隧道接口出去（备用枢纽的接口也在这个集合里），所以包被丢在隧道里，不会从局域网口出去。
- **记录**：每一轮写 `/run/meridian/upstream`（`compile.UpstreamStateFile`，先写临时文件再 `mv`）：`meridian-upstream 1`、`beat`、`path`、`iface`、`hub`、`tier`、`since`、`state <static|ok|switching|down>`、`end`。安装时写 `static`（还没有测量）。面板经 meridian-host 固定的、不带参数的 `POST /v1/upstream/status` 读这个文件（`hostexec.UpstreamStatus`，限长、严格语法，不执行任何命令），`GET /api/upstream` 和地区组视图里的 `carrying` 显示当前承载的枢纽。记录 60 秒没更新、指向拓扑里不是那一层的节点、读不到时，承载枢纽一律算**未知**，不猜。
- 网关上每个出口的解析器改成与枢纽无关的地址 `fd66::54:<i+1>`（`validate.ExitResolverNet`，在保留的 `fd66::/64` 里，不属于任何节点）：两个枢纽都把它路由到各自通往该出口的隧道，出口在两个枢纽的隧道入口上把它 DNAT 到自己的隧道解析器（`exit_dns` 链）。所以钉死到某个出口的规则在备用枢纽接管后照样能解析。单枢纽拓扑仍问出口的隧道地址，编译结果不变。

**出口上的回程对称**（`render_dualhub.go`）：从某个枢纽隧道进来的每个原方向包把连接的 ct mark 设成那个枢纽的 mark（主 `0x4d50`、备 `0x4d51`）；连接的每个回包（从 WAN 进来转发的，或本机应答的，如解析器和枢纽的健康 ping）在 prerouting / output 路由钩子上带上同一个 fwmark，查那个枢纽自己的表（172 / 173，优先级 17060 / 17061）。表里只有家里的前缀（局域网、`10.66.0.0/16`、`fd66::/48`、局域网 IPv6）指向那个枢纽的隧道，再加黑洞默认路由：回包只会回到它来的那个枢纽，不会串到另一个枢纽，也不会从 WAN 出去。因为跟着的是最近一次进来的接口，网关换枢纽后，已有连接的回包随之换到新枢纽（公网 NAT 在出口，源地址不变）。原方向不打 fwmark，去公网的流量照常走主表的 WAN。已知限制：这个 ct mark 覆盖整个连接标记，主机上如果别的程序也给这些连接用 ct mark，会互相覆盖。

**地区组、组解析与 Mesh。** 网关的组 mark、组解析地址、规则都只编译一份；组的查询经当前承载的枢纽（表 102 指向哪条路就到哪个枢纽），那个枢纽按中转源地址查自己的组表，指向它选中的成员，成员在两个枢纽的隧道入口上都把组解析地址 DNAT 到自己的解析器（`group_dns` 链列出两个枢纽的接口），回包按上面的回程对称回到那个枢纽。所以组的解析始终跟着「实际承载流量的枢纽上实际承载这个组的成员」，不会回落到国内解析器。Mesh 腿可以从主枢纽或备用枢纽连到出口，两边语义相同：WireGuard 的 Endpoint 是出口的 Mesh 地址（出口只有这一个地址，两个枢纽的腿都拨它），各自独立的接口、端口和隧道子网（来自各自链路的分配），出口解封后从自己的上联出去；外层包两端都只能经 WARP 接口发往对端 Mesh 地址，否则黑洞 / 丢弃；不发布路由，没有默认路由指向 Mesh 接口。每个枢纽在自己的 `meridian-failover.sh` 里按同一套质量、滞回和冷却参数（`settings.path_quality`）切换自己到该出口的直连 / Mesh 两腿，完全不通立即切另一腿，两腿皆断黑洞，不更换出口；`MQ_PLAN` 按枢纽计算（`compile.MeshQualityPlanIDForHub`），面板按读到的枢纽核对。出口上每条回程一张表、一个 mark、一个优先级：主枢纽直连 172/0x4d50、备用枢纽直连 173/0x4d51、主枢纽 Mesh 腿 169/0x4d52、备用枢纽 Mesh 腿 168/0x4d53（`meridian_return_mesh_backup`，只在有这条边时出现），枢纽无关解析地址在所有入口上应答（`TestMeshLegWithBackupHub`、`TestMeshLegFromBackupHub`、`TestMeshLegOnlyFromBackupHub`）。出口路径 MTU 和组 MTU/MSS 把两个枢纽的 Mesh 腿都算进去。部署计划把备用枢纽当作主机级 Mesh 端（同一套检测 / 沿用 / 安装规则），只在有边连到它时加入计划；同一枢纽到同一出口只能一条 Mesh 腿。不含备用枢纽 Mesh 边的拓扑编译结果逐字节不变（`TestNoMeshCompileUnchangedByMeshTransport`）。

**实际状态。** 面板分别读两个枢纽（`POST /api/region-groups/runtime/refresh` 依次读每个枢纽，每次读取各自绑定那个枢纽的身份，分别存放：主枢纽用原来的存储键，备用枢纽用 `group_hub_state_backup`），各自按自己的计划标识判断（`hub_states`、每个组的 `actual_by_hub`）。组的 `actual` 只取网关记录的承载枢纽的判断，并写明读自哪个枢纽和服务器（`actual.hub_tier`、`hub_node`、`server_name`）；承载枢纽未知时 `actual` 是 `unavailable`、`code: carrying_unknown`，不把任何一个枢纽的报告显示成实际使用。身份（节点、服务器、地址、端口、固定指纹）任何一项变化都只让那个枢纽的读取立即失效；两个节点互换服务器时两边都失效。

## 主备中继分组

备用枢纽有两种接法，二选一（同时出现报 `backup_hub_mixed`）：网关自己经待命的 WG over WSS（`ix_replacement_wss`）直连备用枢纽（原有形态，字节不变）；或者**只经中继**到达备用枢纽——网关不连备用枢纽，有一组中继各自用启用、非待命的 `wg_over_wss`（或 `direct_wg`）连到备用枢纽。

**分组**（`model.Topology.RelayGroupOf`）：网关连着的中继里，有到主枢纽（或 IX）的启用隧道的属于**主组**；只有到备用枢纽的启用隧道的属于**备用组**。同时连两个枢纽的中继含混，拒绝（`relay_group_ambiguous`）；停用的链路不参与分组。示例：`defaults.RelayBackupExample`（主组 1 台 `direct_wg` 到主枢纽，备用组 2 台 `wg_over_wss` 到备用枢纽，网关到三台都是 `udp_wss_failover`；编译摘要 `internal/compile/testdata/relay_backup_example.golden`）。多中继分担对备用组放宽「中继到枢纽只支持 `direct_wg`」：备用组到备用枢纽可以是 `direct_wg` 或 `wg_over_wss`。

**主备路径。** 平时只有主组分担（新连接的权重只落在主组）；备用组照常测量、测速，但不承载。网关对每条腿的端到端探测指向该中继所连枢纽隧道的枢纽端地址（主组：主枢纽；备用组：备用枢纽）。按原有规则，主组**所有中继的所有腿都完全不通**（本轮即可确认，或持续 `backup_after_sec`）才切到备用组；部分腿或部分中继失败不切。备用组承载时和主组一样分担：同一张分配映射、各自的路由表、测速与 QoS 判定，路由表 102 跟随备用组里权重最大的中继。主组有中继连续 3 轮可达、且距上次切换满 `min_dwell_sec`（默认 120 秒）后切回主组；备用组也全部不通时留在主组并告警 `nothing_reachable`，流量在隧道里丢弃。没有控制器时，壳层回退按能否 ping 通在两组之间做同样的切换（`compile/share_groups.go`）。

**备用枢纽一侧。** 备用枢纽为每条中继隧道装入口回程标记（与主枢纽同一机制 `ingressReturns`），回包和本机对探测的应答都从连接进来的那条隧道回去；它的 wstunnel 服务端为每条备用组链路各有一条限制规则，中继一侧各有一个 WSS 客户端；出口身份摘要（`EgressLegs`）包含这些 WSS 腿。

**运行态与面板。** 网关的上游记录多一行 `backup_group <备用枢纽> <中继>…`（只在这种拓扑出现，旧记录照常解析）；`path backup` 时 `hub`/`tier` 是备用枢纽、`iface` 是备用组指定中继的腿。`GET /api/upstream` 的 `sharing.backup_group` 和每台中继的 `group` 区分两组；概览「当前路径」显示实际承载的枢纽，出口页和概览的中继视图按组列出并标出承载组；链路日志在承载路径从 main 变 backup（或反向）时记录切换，证据里写明备用组的中继。

**部署顺序**：出口 → 备用枢纽（先把 WSS 服务端和凭据就绪）→ 主枢纽 → 中继（主组，然后备用组的 WSS 客户端）→ 网关。

## 多中继同时分担

网关连着**两台及以上**国内中继时（`model.Topology.SharingRelays`：角色 relay、有一条启用且非待命的网关链路），这些中继**同时**承载主链路（网关 → 中继 → 主枢纽），新连接按测得的路径质量自动加权分到各中继；质量差的中继在还有别的中继可用时被剔除，但质量剔除从不清空分担集合（全部低于下限时保留最好且仍可达的一台），只有所有中继都**完全不通**时才改走备用枢纽。只有一台中继时什么都不变（`planShare` 为 nil，编译结果逐字节和以前一样，仍是上面「主枢纽与备用枢纽」的单中继切换）。有没有备用枢纽都可以；中继可以随时再加（加一台、重新安装即可）。

**模型与校验**（`validate/sharing.go`）：

- 每台中继只能有一条启用的网关链路（`direct_wg`、`wg_over_wss`，或 `udp_wss_failover` 的 UDP + WSS 两条腿；`sharing_relay_multiple_links`），并且要有自己到主枢纽的一条 `direct_wg` 隧道（`sharing_relay_no_hub_link`、`sharing_relay_multiple_hub_links`、`sharing_relay_hub_transport`：中继自己的东向切换只认 `direct_wg`；旧模型里经 `ix` 节点的专线也算）。网关要经每台中继各自对主枢纽做端到端测量，所以缺这一段就拒绝，不猜。
- 最多 12 台（`too_many_relays`）。「IX 替换模式」开关在分担时拒绝（`ix_replacement_mode_sharing`）。
- 设置 `settings.path_quality`（`model.PathQuality`，全部可省，0 = 默认）无论是否分担都校验（`invalid_path_quality`）：每项的范围、轻度阈值必须小于下限阈值、降权不晚于停止分配、吞吐下限不高于探测速率、一次探测要放得进每天的预算、手动覆盖只能指向分担中的中继、不能全部停用。
- 测速与 QoS（修订 15）：`speed_test_interval_sec` 300–86400（默认 1800）、`speed_test_mb` 只许 5/10/20/50（默认 20）、`qos_throttle_pct` 5–90（25）< `qos_recover_pct` 10–100（50）、`qos_baseline_days` 1–30（7）、`nominal_mbps` 与 `overrides[].nominal_mbps` 1–100000（200）。基准是窗口内有效测速的 P90，测速不够时用标称带宽；连续两次低于阈值判「限速」（`qos_throttled`，暂停分配），一次达到恢复阈值即 `qos_recovered`；全部限速时保留最近测速最好的一台（`all_relays_throttled`），不切备用枢纽。可用中继之间等权分担；时延 / 丢包只显示，不再降权。测速结果的判定：连不上、路径不对、读取出错、传输中连续 10 秒没有新数据（停滞）都记「未测到」，既不延长也不打断连续低速计数；一直有数据、到 60 秒整体期限仍没传完但已收到至少 1 MiB 的，是有效的低速样本，参与「连续两次低于基准 25%」的判定；不到 1 MiB 也记「未测到」。shell 兜底不测速，只按通断剔除。

**面板（修订 15）。** 出口页「国内中继分担」和概览卡每台中继一行测速：`186 Mbit/s · 12 分钟前`，只有限速着色（`限速 38 Mbit/s`），基准与阈值在悬停里；时延 / 丢包降为次要灰字。测速设置（开关、间隔、大小、阈值、基准窗口、全局与每台标称带宽）在网关设置抽屉「多中继分担与路径质量」里，下方一行灰字是按设置估算的每天测速流量；页面「说明」里同一估算来自 `sharing.speed_test_cost`。规则页、规则集与 mihomo 导入保存后只显示一行：`已生效（vN）`、`将自动生效`（合并等待）或 `未自动生效：<原因>` + 去部署链接（只有这时才出现）；网关设置抽屉「其他」里的「规则改动自动生效」写 `settings.rules_auto_apply`（缺省 = 开，关 = false）。规则自动安装只接受 `compile.RuleChange` 的精确白名单（网关规则清单、规则决策快照、嗅探目标、smartdns.conf 与 meridian.nft 的规则段），走与人工相同的预检与安装事务。解锁页的「确认」/「手动」保存（`POST /api/unlock/adopt`）走同一条通道，授权范围按字段精确到这次保存：服务规则的目标（`target_group` / `target_exit`），确认时再加目标地区组的成员顺序、模式、指定成员和故障回落；手动选组（规则跟随该组，组不变）和手动钉死节点（规则 `target_exit`，不改任何组）只授权规则目标。保存事务（`resMu` → 面板状态锁 → 存储锁）内重新读配置、结果和出口身份，确认还复核推荐，任何拒绝都不改规则或地区组。保存前的组字段随基准一起记录，重建已安装状态时还原，所以「没有其他待装改动」的核对照旧成立；组的成员集合变了、或（都是解锁保存时）除这些规则的目标外还有别的规则差异，都拒绝自动安装；文件层面 `compile.RuleChange` 只对这个组放行 meridian.nft 里的组注释行（`# group <id> … target <出口>`、`# default-exit <出口> group <id>`，mark 与中转地址仍逐字比较）。地区组在枢纽上切换，组首选真变了时枢纽脚本也变，那是别的节点的文件，照旧拒绝，结果为「未自动生效：地区组的首选出口由 <枢纽> 切换，需要到部署页安装」；只改规则目标时自动生效。远程接入的快速通道是另一条独立通道（只改运行时，不升版本）。合并等待后执行的那次自动安装遇到「有未完成的宿主事务」或「网关正忙」（只有这两种）时，每 2 秒重试一次、最多 5 次（约 10 秒）；每次重试都重新做全部核对（安装版本与网关一致、规则白名单、其它待装改动、演练 / 部署引导 / 节点锁互斥、预检阻断与需确认警告、开关与限频），期间有真实的版本变化、配置变化或安全条件变化就失败关闭，不按旧快照安装；重试用完记为「未自动生效」，不会报已生效；安装经节点锁与 `autoMu` 串行，事务不重叠。规则集订阅的下载与定时更新不在这条路上：内容不进编译结果（`TestRuleSetContentIsBundleNeutral`），经 `applyRuleSetsOnHost` 让宿主重新派生名单，不进安装事务、不升版本，也不受 `rules_auto_apply` 控制——这个开关只约束操作者保存的、会改变编译结果的规则配置。

**按连接分担，从不按包。** 网关 `inet meridian` 表里（`compile/share.go`）：

```
chain prerouting { … iifname <LAN/mra> jump classify
                       iifname <LAN/mra> meta mark 0x101-<末个出口 mark> jump relay_share
                       ct direction reply meta l4proto tcp jump relay_count_in }
chain relay_share {
  jump relay_redirect                              # 动态：被剔除中继的非 TCP 流改哈希
  ct state new jump relay_assign                   # 动态：只对新连接查一次映射
  ct state new ct mark 0x00010000 counter name "share_r1_new"   …
  meta l4proto tcp ct mark 0x00010000 counter name "share_r1_tcp_out" …
  ct mark 0x00010000 meta mark set meta mark | 0x00010000 return   # 每个包从连接恢复中继位
  …   ct mark 0x00fe0000 …                          # 备用枢纽
}
chain relay_assign {
  meta nfproto ipv4 ct mark set jhash ip saddr . ip daddr . th sport . th dport mod 1000 seed 0x4d52 map { 0-499 : 0x00010000, 500-999 : 0x00020000 }
  meta nfproto ipv6 ct mark set jhash ip6 saddr . ip6 daddr . th sport . th dport mod 1000 seed 0x4d52 map { … }
}
chain relay_strip   { type filter hook forward priority -300; meta mark & 0x00ff0000 != 0 meta mark set meta mark & 0xff00ffff }
chain share_forward { type filter hook forward priority filter; jump relay_drain }   # 动态：剔除时重置 TCP
```

- 连接在**建立时**由五元组哈希落到某台中继，结果存进连接标记（ct mark，网关上别处不用它），之后这个连接的每个包（两个方向都由 conntrack 关联）都从 ct mark 恢复中继位。改权重只影响新连接。
- 中继位在 fwmark 的 `0x00ff0000`（中继 i 是 `i << 16`，备用枢纽 `0xfe << 16`），出口 mark 仍在低位。路由脚本给每台中继一条 `ip rule fwmark <位>/0xff0000 lookup 110+i priority 17150+i`（备用枢纽 `lookup 109 priority 17150`），排在出口规则（17200+）之前；每张表只有「默认 dev <这台中继当前用的腿>」加 metric 32767 的黑洞。
- 中继位只用来选路由：forward 钩子 -300 处（兜底表 -200 之前）把它清掉，所以兜底表、MSS 钳制、中转 SNAT 看到的还是原来那些出口 mark，规则一个字没改。兜底表允许的接口集合本来就是网关全部隧道接口（每台中继的每条腿和备用枢纽），最后一条仍是 `counter drop`。
- 没有中继位的出口 mark 包查表 102：网关**自己**的组解析查询（SmartDNS 带 `-set-mark` 的上游）和安装前就存在的连接。表 102 跟着**指定中继**（权重最大的那台，并列取第一台；在备用枢纽上时是备用枢纽），本机到 `10.66.0.0/16`、`fd66::/48` 的路由同理。远程接入设备从 `mra` 进来，和局域网走同一套分类和按连接分担。网关自己的探测用 `ping -I <腿>` 和每条腿的主机路由，确定地走那条腿。

**回程沿来路。** 中继和主枢纽按入接口记连接标记（`ingressReturns`）：中继上每条来自网关的腿、主枢纽上每条来自中继的隧道（含中继待命的 WSS 替代隧道）各有一个 mark（`0x4e00 + j`）和一张表（`174 + j`，优先级 `17070 + j`）。每个从该接口进来的**原方向**包把 ct mark 设成它（跟最近一次进来的接口，网关把连接换腿时回程随之换）；连接的每个回包——转发的，以及本机应答的（`type route hook output`，例如主枢纽回网关的探测）——带上同一个 fwmark，查那张表：表里只有家里的前缀（局域网、`10.66.0.0/16`、`fd66::/48`、局域网 IPv6）指向那条隧道，再加黑洞。所以回包一定从连接进来的那条隧道回去，`rp_filter` 和 NAT 看到的是对称路径。出口一侧不变（有备用枢纽时仍按枢纽分回程，见上）。备用枢纽只由网关直连，没有这部分。

**权重怎么改：一次事务。** 安装时 nft 文件里就带着等权重的映射，所以从加载那一刻起映射就不是空的。之后只有网关的 `meridian-failover.sh` 改它，用路由脚本和切换脚本逐字节共用的 `share_apply`：先按编译出的数组逐项核对（中继名、腿必须是这台中继的编译接口、权重 0–1000 且主链路时和为 1000、标志 0/1、备用枢纽时权重全 0），任何一项不对就拒绝（返回 1，什么都不动）；然后**一次** `nft -f -`：`flush chain relay_assign` + 新映射、`flush chain relay_redirect` + 规则、`flush chain relay_drain` + 规则，内核整批接受或整批拒绝（拒绝返回 2，旧映射留着）；接受后才改各中继表和表 102。同样的决定不重复下发（`/run/meridian/pathq/applied`），但大约每分钟（每 12 轮）无条件重下发一次，被别处改动的映射或路由会自己恢复；切换服务每次启动时也清掉这个标记，所以重新加载 nft 后下一轮就重新下发。

**测量**（每轮 5 秒，`internal/pathquality` 的 `Measurer`，全部在网关上做）：

- 每台中继的每条腿、以及备用路径，并行发一串 5 个小 ICMP（间隔 0.2 秒）：中继腿的目标是主枢纽在**这台中继**的中继 ↔ 主枢纽隧道上的地址，源地址 `10.66.200.2`（端到端：中继活着而它到 IX 的那段不通也算不通）；备用路径的目标是备用枢纽的隧道地址。得到这一轮的丢包和平均 RTT，再做指数平滑（α = 0.3）。测量和业务流量同时发生，所以有业务时 RTT 反映的就是负载下的情况；另外记一个空闲基线 RTT，用来判断「负载下 RTT 膨胀」。
- 每条腿的接口字节计数（`/sys/class/net/<腿>/statistics`），算出每台中继的上下行速率和累计流量；nft 计数器 `share_r<i>_new`（分到它的新连接）、`share_r<i>_tcp_out` / `_tcp_in`（它的连接的 TCP 原方向 / 回包数）；WireGuard 最近握手（只作参考）。

**「小包通、没有速率」怎么发现。** 被限速的中继照样握手、小包照样通，所以只看 ping 不够。被动信号：

1. **有业务但 TCP 收不到回包**：一轮里发进这台中继的 TCP 包至少 20 个、回包不到 5%，连续 3 轮 → 低于下限（`no_delivery`）。只看 TCP（单向的 UDP 本来就可能没有回包）；上传时 ACK 也算回包。
2. **负载下 RTT 膨胀**：这台中继在承载（≥ 64 KB/s）时 RTT 到基线的 3 倍以上且至少高 50 ms → 轻度劣化并标为可疑。
3. **单位权重的下行量远低于其他中继**：另一台每单位权重的下行速率是它的 4 倍以上（且至少 128 KB/s）→ 可疑。
4. 平滑后的丢包或 RTT 过了轻度阈值 → 可疑。

可疑且这台中继有业务（≥ 16 KB/s）时，下一轮对它做一次**吞吐探测**作为仲裁：在**隧道里**按设定速率（默认 4000 kbit/s）发一串 1200 字节的 ICMP，共约 `probe_bytes`（默认 512 KiB）。在运营商看来这是普通的 WireGuard UDP，和业务数据受同样的 QoS。送达率低于 `probe_floor_kbps`（默认 1000 kbit/s）或丢包超过 `probe_loss_permille`（默认 30%）→ 这条路径「没有速率」（`no_throughput`），在下一次允许探测之前都算低于下限。限制：同一台中继两次探测至少隔 `probe_min_interval_sec`（默认 900 秒），每台每天不超过 `probe_daily_budget_mb`（默认 64 MB），可以整体关掉（`probe_off`）。**流量开销**（计费）：一次约 1.1 MB（上下行合计，含 IP/ICMP/WireGuard 包头，`pathquality.ProbeCostEstimate`），默认每台中继每天最多 59 次、约 63 MB；面板按设置估算并标明是估算，网关记录每台当天实际用掉的探测字节。因吞吐不足被剔除的中继，在重新加入前要先通过一次探测（探测关掉或预算用完时只按 ping 质量加回，再由业务信号把关）。

**状态机**（`pathquality.Step`，纯函数：编译出的配置 + 上一轮状态 + 本轮测量 + 时钟 → 新状态 + 决定；单元测试用合成测量和注入的时钟）。每轮先给每条路径评级：`down`（这一轮一个回包都没有）、`poor`（低于下限）、`mild`（轻度劣化）、`good`。离开一个等级要低于它阈值的 70%（滞回），所以在阈值附近抖动的路径不会每轮翻等级。

| 状态 | 进入条件（默认值） | 新连接 | 已有连接 |
|---|---|---|---|
| `active` 分担中 | 初始；`reduced` 良好满 `recover_after_sec`（120 秒）；`recovering` 爬坡完成 | 质量权重 | 不动 |
| `reduced` 已降权 | 轻度劣化（丢包 ≥ 3% 或 RTT ≥ 200 ms 或负载下膨胀）满 `reduce_after_sec`（20 秒） | 权重最多 25（/100） | 不动 |
| `standby` 暂停分配 | 轻度劣化满 `standby_after_sec`（60 秒），且有良好的中继在集合里 | 0 | 不动 |
| `evicted` 已剔除 | 低于下限（丢包 ≥ 15% 或 RTT ≥ 400 ms 或吞吐探测不达标或 TCP 无回包）满 `evict_after_sec`（30 秒）；或完全不通满 `down_after_sec`（15 秒）；或爬坡中又变差 | 0 | 默认清理（见下） |
| `recovering` 逐步加回 | `evicted` / `standby` 后良好满 `recover_after_sec`（120 秒）；吞吐原因被剔除的还要先通过一次探测 | 25% → 50% → 100%，每步 `ramp_step_sec`（30 秒） | 不动 |
| `disabled` 手动停用 | 手动覆盖 | 0 | 不动 |

一直在探测：被剔除的中继每轮照样 ping，满足条件再加回；爬坡中只要一轮不是良好就退回（轻度 → `reduced`，更差 → `evicted`）。

**权重。** 分数 = 平滑 RTT（毫秒）+ 平滑丢包（‰），即 1% 丢包相当于 10 ms（权重用更慢的平滑 α = 0.1，免得追着噪声跑）。分数在最好的那台的 1.3 倍以内、或者只差不到 10 的都给 100（质量相近时等分）；更差的按比例下降、取 5 的倍数、最低 10。再按状态封顶（`reduced` ≤ 25，`recovering` 乘爬坡比例），最后按最大余数法归一到 1000 个桶。只因质量变化的权重至少 30 秒才变一次、且要变动 ≥ 10 才发布；状态变化立即发布。手动覆盖（`overrides`，默认没有）：停用某台，或给某台固定权重 1–100（不通时仍会被剔除）。

**已有连接。** 改权重、降权、暂停分配、恢复、爬坡**从不**迁移已有连接。剔除（`evicted` 且不再分到新连接）时，默认规则（`keep_connections_on_evict` 为假）清理这台中继的已有连接，让应用到健康的中继上重连：`relay_drain` 在 forward 钩子里对从局域网 / `mra` 进来、属于这台中继的 TCP 原方向包 `reject with tcp reset`（RST 发给局域网里的客户端，不会发往公网）；非 TCP 的流（UDP/QUIC）由 `relay_redirect` 在下一个包重新按映射哈希到分担集合里的中继——中继不做地址转换，网关的中转 SNAT 按出口不按中继，主枢纽按最近的入接口回包，所以这些流的地址端到端不变。卡在一条没有速率的路径上比重连更糟，所以默认是清理；打开 `keep_connections_on_evict` 后只停止分配新连接。备用枢纽上的连接在回到主链路后保留，直到备用路径完全不通满 `down_after_sec` 才同样清理。

**保留最佳中继。** 质量剔除（丢包、时延、吞吐探测不达标、TCP 无回包）只在还有别的中继在集合里（或待命）时生效。若剔除会让集合变空，`path-step` 保留分数最好、仍能应答（这一轮不是 `down`，也不是因不通被剔除后仍未好转）且没有被手动停用的那一台：状态 `reduced`、原因 `retained_best`，独占全部 1000 个桶，不设清理、不重置它的连接；已保留的那台只有别的候选分数好过它 `switch_advantage_pct` 才换人。完全不通的中继从不被保留：保留者这一轮完全不通就以 `down` 剔除。别的中继回到集合后保留者被释放（仍低于下限就按自己的原因剔除，否则交回正常状态机）；保留者自己良好满 `recover_after_sec` 直接回到 `active`。告警 `all_relays_poor`（状态 `degraded`）。

**主链路与备用枢纽。** 只有所有启用的中继都**完全不通**才切到备用枢纽：这一轮全部不应答且都已被剔除（快速路径，离开不通的主链路不等 `min_dwell_sec`），或者全部完全不通（含因不通被剔除后只偶尔、低于下限地应答）持续 `backup_after_sec`（30 秒）且满足最短间隔。备用路径的分数好过中继**不会**单独触发切换（旧的 `all_relays_poor_backup_not_better` 不再在主链路上产生）；备用路径也不通时告警 `nothing_reachable` 或 `all_relays_poor_backup_unusable`。旧版本持久化的状态（全部中继因质量被剔除、没有 `all_down_since`）下一轮直接进入保留；已因分数优势在备用枢纽上的旧状态按下面的切回规则回来（缺少计数字段时从 0 数起，3 轮后切回）。在备用枢纽上时，**任一启用中继任一腿应答**（`reachable`）连续 3 轮（约 15 秒）且距上次切换满 `min_dwell_sec`（120 秒）就切回，**不要求中继质量良好**——切回后由上面的保留规则决定分担（全部低于下限时保留最好且可达的一台独占承载）；等待期间告警 `on_backup_returning`。备用路径完全不通满 `down_after_sec` 而中继还有能应答的，立即切回。切换原因一行记在状态 `switch_reason`：`all_relays_down`（接管）、`relay_reachable`（可达切回）、`backup_down`（备线不通切回）；`return_after_sec` 不再参与中继切回。在备用枢纽上，所有新连接的映射是 `0-999 : 0x00fe0000`（表 109 指向备用枢纽的接口），已有的中继连接按剔除规则处理。**什么都不通**时不动：各表仍指向隧道（加黑洞兜底），兜底表只允许出口 mark 从隧道出去，记录 `state down`、告警 `nothing_reachable`——失败关闭，不会出现绕过隧道的路径。

**控制程序在哪里运行。** 测量和决定都在网关上，不在面板里：网关的 `meridian-failover.sh`（root，安装事务装的 systemd 服务，开机自启）每轮调用一次宿主机上的 `meridian path-step`（就是 `install.sh` 装的 `/usr/local/bin/meridian`，和 meridian-host 同一个二进制）。它读编译出的 `/etc/meridian/path-quality.json`（严格解码，安装事务下发）、读写 `/run/meridian/pathq/state.json`、测量、决定、写状态记录，然后在标准输出打印决定；shell 核对后用 `share_apply` 执行。面板容器停掉不影响它。

- **兜底**：`path-step` 不存在、出错、超时（25 秒）或给出的决定被 shell 拒绝时，这一轮改用 shell 自己的应急规则：可达的中继（任一腿能 ping 通）**等权重**分担，只按通断剔除（连续 3 轮不通剔除、连续 5 轮通加回），没有中继能通且备用枢纽能通时走备用，回主链路至少隔 120 秒；记录里 `controller shell`、告警 `controller_unavailable`，面板显示「应急规则在运行」。脚本调用时带 `MERIDIAN_BIND=-`：比 path-step 旧的二进制会在自己的监听地址检查处直接退出，不会打开数据库或做任何别的事。
- **重启**：状态在 `/run`，重启后从安装时的等权重开始（nft 文件和路由脚本就是这个状态），每台中继重新测量；配置变了（重新安装、改设置、加减中继）也从头开始（配置摘要不同）。
- 变更只经两条路：安装事务（nft 文件、路由脚本、配置文件），以及切换服务的 `share_apply`（只改三个动态链、各中继表和表 102）。面板不能改它们，meridian-host 也没有新增任何可写动作。

**状态记录与面板。** 分担时状态记录换成第二种格式（`meridian-upstream 2`，`pathquality.FormatStatus`）：前 7 行同第一种，加 `controller`、`alert`、`switched`（上次切换枢纽）、`designated`，每台中继一行 `relay …`（腿、状态、权重、是否在清理、原因、状态起始时间、等级、平滑 RTT 和丢包、本轮 RTT 和丢包、测量时间、累计和当前流量、新连接数、可疑信号、最近一次吞吐探测的时间 / 速率 / 丢包 / 是否达标、当天探测字节），以及备用路径一行。meridian-host 仍用那个固定、无参数的读取（限 8 KiB，每行字段数和取值都严格核对，`-` 表示没测量），`GET /api/upstream` 的 `sharing` 和地区组视图的 `carrying.sharing` 把它连同设置、按设置估算的探测开销（`probe_cost.source: estimated`）、剔除对已有连接的影响一起给面板。概览有「国内中继分担」卡片，出口页有完整的表（承载的枢纽、每台中继的份额、是否在集合里、网关测量的 RTT / 丢包和时间、流量、吞吐探测、降权 / 剔除原因和时间、上次切换时间、断连影响、探测开销）；记录超过 60 秒没更新、格式和拓扑对不上（例如加了中继还没安装）时一律显示**未知**。设置在拓扑页「网关设置」的「多中继分担与路径质量」里，留空即默认，保存后要安装到网关才生效。

**没有验证的。** 以上没有在真实主机上运行过：没有真实的中继、真实的晚高峰限速、真实的 WireGuard / wstunnel 腿。命名空间测试（`TestNetnsRelaySharing`）用 veth 代替隧道、用「只放行 ICMP」模拟「小包通、没有速率」、用 `tc netem` 模拟丢包；ICMP 吞吐探测与真实 TCP 吞吐的相关性、默认阈值对真实线路是否合适、真实限速下被动信号的灵敏度，都还没有观察过。

## 为什么网关要做一次中转地址改写

WireGuard 不携带 fwmark。本地宽带到国内中继只有一条逻辑隧道，枢纽却要根据目标选择不同出口。编译器让网关按策略把局域网源地址改写到每个出口独立的中转地址：

- IPv4：`10.66.200.0/24` 里的一个 /32
- IPv6：`fd66:0:0:ff::/64` 里的一个地址

国内中继和枢纽按这个源地址选路。回到客户端时，网关上的连接跟踪再还原成原来的局域网地址。对公网可见的 NAT44 / NAT66 只发生在出口。国内流量不改写，下一跳仍是 `192.0.2.1`。

`fd66::/48` 的路由不会指向 ROS。误送到 ROS 的 ULA 即使撞上可选的 `fd00::/8` 黑洞，也不该从 Meridian 送出去。

网关的 `classify` 链对受管入口（局域网口，打开远程接入时再加 `mra`）进来的包，按这个顺序处理 IPv6 目的地址：先把设备池（打开远程接入时）标成国内 mark；如果局域网 IPv6 前缀（`settings.lan_ipv6_prefix`）本身是 ULA（在 `fc00::/7` 里），紧接着把**恰好这个前缀**标成国内 mark（`ip6 daddr <局域网 ULA 前缀> meta mark set 0x64 return comment "ULA LAN prefix: home hosts only"`）；然后 `ip6 daddr fc00::/7 drop` 丢掉其余所有 ULA（隧道 `fd66::/48`、中转 `fd66:0:0:ff::/64`、`ula_prefix`、设备池之外和其他任何 ULA）。国内 mark 查表 100，表 100 里局域网前缀是 `dev <局域网口>` 的直连路由，兜底表只放国内 mark 从局域网口出去，所以这条只通往家里的主机，不会走 ROS 的默认路由。没有它时，从 `mra` 访问家里的 ULA 主机、家里主机回给网关地址（设备访问家里主机时的 masquerade 地址）的包，以及发往网关自己 ULA 地址的包（DNS 等），都会在这条 ULA 丢弃里被丢掉。局域网前缀是 GUA（常见情况，也是示例拓扑）时不生成这一条，局域网前缀那条仍在私有 IPv4 段之后、编译结果与之前逐字节相同。校验相应收紧：局域网 IPv6 前缀必须是 IPv6；不能包含整个 `fc00::/7`（`::/0`、`fc00::/6` 之类直接拒绝）；是 ULA 时必须写成网络地址、长度 /48–/128，并且不能与 `fd66::/48`（含中转 /64，即使 `ula_prefix` 改在别处）、`ula_prefix`、`transit_v6_prefix`、NAT64 前缀和设备池重叠。

## 每一跳

| 跳 | 传输 | MTU |
| --- | --- | --- |
| 本地宽带 → 国内中继 | UDP WG 与 WSS 两套接口，优先 UDP | 1412 / 1360，TCP MSS 按更小的那条夹 |
| 国内中继 → IX → 枢纽 | 直连 WG，外层 IPv4 | 1420 |
| 枢纽 → 出口 | 公网直连 WG。NAT 节点反过来拨 | 1420 |
| IX 替换 | 预置 WSS，`timeout_sec=0`，每条链路一个随机路径、只放行到本机该链路的 WG 端口；面板生成的自签证书，客户端只信任它（见「WSS 承载：随机路径与自签证书」） | 1360 |

### MSS 钳制：转发流量与本机发起的连接

钳制值只有一套：编译器按每个出口**所有能承载它的路径**算出最小 MSS（`validate` 的路径报告，`compile.mssFloor`：所有没有 Mesh 腿的出口里最小的 IPv4 / IPv6 MSS；有 Mesh 腿的出口路径更小时另有按出口标记的更低值，能切到这种出口的地区组另有按组标记的更低值，见「Mesh 腿的 MTU」）。「能承载」的规则见下文「出口的路径 MTU：所有承载路径的最小值」。规则只**降低**（`size > N set N`），从不抬高。

- 转发流量：网关 `inet meridian` 的 `mss` 链（forward，priority mangle）对 SYN 和 SYN-ACK 按这套值夹（打开远程接入时另有 `mra` 自己的值）。中继位在 forward -300 处已清掉，所以按出口标记比较。按标记的更低值（有 Mesh 腿的出口、能切到它的地区组）：SYN 按标记匹配；从隧道回来的 SYN-ACK 不带标记（只有局域网入口做分类），按连接跟踪的回程目的地址——该标记的中转地址（`transit_snat` 给每条带标记的局域网连接换成它）——匹配，与 `local_mss_in` 的做法相同。以前这条回程规则不存在，局域网客户端学到的是全局值，往小路径发的段仍然偏大（修订 19 一并补上）。
- 网关本机发起、带出口或地区组标记、从隧道出去的 TCP（面板的解锁检测由宿主代理以 root、`SO_MARK` 和出口的中转源地址发起；SmartDNS 带组标记的 TCP 查询；其它带这类标记的本机连接）：不经过 forward，以前 SYN 里是按隧道接口算出的 MSS（MTU 1412 → 1372）。2026-11-15 在真实网关上看到：实际路径 MTU 只有 1408 的出口上，对端发回的 1412 字节包被静默丢弃，TLS 握手超时；同一连接把 MSS 设成 1320 后约 220 毫秒成功。现在：
  - `local_mss`（output，filter，priority -140 = mangle+10）：SYN。输出方向的 route 链（打开中继分担时 `sniff_route` → `relay_share`）在 mangle 处可能改标记，内核随后重新选路，所以到 -140 时包上已是最终标记和出接口（与 `sniff_mss` 同一位置）。匹配条件：`meta mark & 0xff00ffff` 在出口/地区组标记范围（`0x101` 到兜底表的上界，出口更多时随之扩大；中继位被屏蔽）且出接口是网关自己的 WireGuard 接口（含故障切换的备接口和备用枢纽的接口，所以表 102 被切换到哪条都覆盖）。值与 `mss` 链相同（含 Mesh 出口按标记的更低值）。
  - `local_mss_in`（input，filter，priority mangle）：这些连接的 SYN-ACK，使网关自己发出的段也不超过钳制值（forward 方向的 `mss` 链同样夹两个方向）。进来的包没有套接字标记，所以按连接跟踪的回程元组识别：回程目的地址在中转网段（`10.66.200.0/24`、`fd66:0:0:ff::/64`）——探测自己绑定中转地址，转发服务和 SmartDNS 的组连接经 SNAT 得到它；只有带出口/组标记的连接用这些地址。input 只看本机连接，局域网发往同一中转地址的流量走 forward，仍由 `mss` 链处理。
  - 不匹配：没有标记的本机连接（面板、SSH、DNS、宿主代理的其它工作），国内和拒绝标记，WireGuard 自己的外层 UDP（标记 `0x4d72`、不是 TCP、从局域网口或 `lo` 出去），wstunnel 的 TCP 承载（没有出口标记，从局域网口出去）。
  - 为什么另起一条链而不是把 `sniff_mss` 推广：`sniff_mss` 只在打开 `settings.sniff` 时生成（关闭时整份文件要与以前逐字节相同），并按属主匹配转发服务的全部 SYN（包括从局域网口直出的国内连接）。转发服务进隧道的 SYN 两条链都会匹配，二者都只降到同一个值，结果相同；转发服务的出站限制（`sniff_out` / `sniff_confine`）没有改。
- 远端节点（出口、枢纽、中继）：`tunnel_mss_out`（output，priority -140，在出口上把本机回包改道到某个枢纽/中继隧道的 route 链之后）和 `tunnel_mss_in`（input）对**本机**经 Meridian 隧道接口收发的 SYN / SYN-ACK 按同一套值夹（节点是有 Mesh 腿的出口时取它自己更低的值；枢纽对它每条 Mesh 腿的接口另加一条该腿的更低值）。节点上没有出口标记，匹配的是接口。覆盖：出口解锁定时任务把结果报给网关面板（出口 → 隧道 → 网关局域网地址，网关那端是本机面板，不经 forward）、出口解析器对网关 TCP 查询的回答、外部出口承载节点上的 `meridian-ext-proxy`（gost）和解析组对枢纽隧道的应答。不覆盖、也不需要：节点 WAN 口（解锁定时任务的 regioncheck 和 curl 探测、SmartDNS 的上游都直接从出口自己的 WAN 出去，不进隧道）、gost 到外部 SOCKS 代理那一跳（走操作者自己管理的接口 `external.interface`，Meridian 不知道它的路径 MTU，没有可用的计算值；那条接口的 MTU 要由操作者按实际路径设好）、外部出口健康检查（连本机 `lo` 上的服务地址，再经上一条）、Mesh 的 `mmesh`（不是 Meridian 的隧道接口，上面只有 WireGuard 的外层 UDP；Mesh 腿本身是一个普通的隧道接口，按上面的规则夹）、WireGuard 外层 UDP 和 wstunnel 承载（走 WAN）。转发流量在节点的 input/output 钩子里看不到，不受影响。
- 这次只加钳制规则，不改任何隧道 MTU：已部署节点 `wg` 配置里的 `MTU =` 不变。
- 所有钳制值来自同一个计算：每条链路每条腿的隧道 MTU 只有一个来源 `validate.LegMTU`（编译器写进 `wg` 配置的 `MTU =` 也是它），出口的路径 MTU 是它所有承载路径上各腿的最小值（`validate.exitPathMTU`，见下），`compile.mssFloor` 再取所有没有 Mesh 腿的出口的最小值（Mesh 腿的两个值见「Mesh 腿的 MTU」）。链路的 MTU 被调小（包括显式采用下面的上联建议）时，`mss`、`sniff_mss`、`local_mss` / `local_mss_in` 和各节点的 `tunnel_mss_out` / `tunnel_mss_in` 一起变。以前 `wg_over_wss` / `ix_replacement_wss` 链路设了 `wss_mtu` 时，接口用它而路径计算忽略它；现在两处一致（只影响显式设了 `wss_mtu` 的拓扑）。


### 出口的路径 MTU：所有承载路径的最小值

面板显示的路径（`PathReport.nodes` / `links`）是一条首选路径，但一个出口的流量不止走这一条：中继分担时连接按中继分配，网关和中继的故障切换会换到 WSS 腿或 IX 替换 WSS，主路径整体失败时走备用枢纽。以前路径 MTU 只量首选路径（另加全拓扑的 IX 替换 WSS），把非首选中继、备用枢纽到出口的链路采用为更小的 MTU（例如 1280）后，MSS 仍停在 1320/1300，分到那台中继或切到备路的连接又会遇到大包丢弃和握手超时。

现在 `validate.exitPathMTU` 是唯一的计算（路径报告、`mss` / `sniff_mss` / `local_mss` / `local_mss_in`、各节点 `tunnel_mss_out` / `tunnel_mss_in`、上联 MTU 的采用预览都读它的结果）。它取以下所有链路的 `hopMTU`（故障切换链路取 UDP 与 WSS 两条腿里更小的，腿的 MTU 来自 `validate.LegMTU`）的最小值，再并上首选路径本身的链路（结果不会高于以前）。「能承载」沿用编译器里网关故障切换 / 中继分担的承载状态（`planUpstream`、`planShare`、`mgmtStates`）和中继自己的切换：

- 进入主枢纽：每台分担中继（`SharingRelays`：网关有启用、非待命隧道连过去的中继；只有一台时就是它）的每条网关—中继链路，加上该中继到主枢纽的路（只经 IX 节点的启用、非待命链路，以及中继自己的 IX 替换 WSS）；
- 网关自己的 IX 替换 WSS 进入的枢纽（单枢纽的本地宽带直连兜底、备用枢纽）；
- 从上面能进入的每个枢纽出发：枢纽到出口的启用、非待命、非 Mesh 链路，在主枢纽上再加这个出口的 Mesh 腿（启用的 `cf_mesh` 链路：枢纽可能改用它承载这个出口）；嵌套出口是枢纽到它的中继出口的链路加中继出口到它的链路；经双栈中继的纯 IPv6 出口是枢纽到双栈中继的直连 WG 加中继到出口的链路；选了 Mesh 绕行的纯 IPv6 出口只算主枢纽到它的 Mesh 腿（它唯一的一腿）；外部出口取承载它的出口。
- 链路方向（拨入或拨出）不影响结果。

不算的：网关到中继的待命链路、别的出口或别的枢纽的链路、网关进不去的枢纽。路径报告的 `mesh_links` 列出除首选路径外计入的 Mesh 腿。有 Mesh 腿的出口不进全局值，见下一节。

### Mesh 腿的 MTU：按出口和按组标记的钳制

Mesh 腿是架在 Cloudflare Mesh 上的一条 WireGuard（见「Mesh」）。`cf_mesh` 链路的 `mtu` 填的是 **Mesh 路径**的 MTU（默认 1280，WARP 设备的 MTU），腿本身的 MTU 由它减去 WireGuard 的开销得到（`mtu.MeshLeg`、`validate.MeshLegMTU`；外层是到出口 Mesh 专用 IPv4 地址的 UDP，开销 60）。这里有两个值：

- **接口 MTU（`device`）**：`Mesh 路径 − 60`，但不低于 1280。默认路径下 1280 − 60 = 1220，低于 IPv6 的最小链路 MTU：Linux 会把 IPv6 从低于 1280 的接口上去掉，而出口的解析地址、地区组的解析地址都是 IPv6（`fd66::…`），所以接口保持 1280。编译器写进 `wg` 配置 `MTU =` 的是这个值（`validate.LegMTU` 对 `cf_mesh` 返回它）。
- **路径值（`payload`）**：这样一个接口上不让外层包分片的最大内层包。WireGuard 把明文补齐到 16 的倍数、只在接口 MTU 处截断，所以接口是 1280 时 1217–1220 字节的内层包会被补到 1232、外层 1292，放不进 1280；路径值取 16 的整数倍，默认 **1216**（`mtu.LargestInnerUDP(1280, 1280, 4)`）。它是 `hopMTU`：出口的路径报告、地区组的路径报告和所有 MSS 钳制用的都是它，默认 MSS **1176 / 1156**。
- Mesh 路径 ≥ 1340 时两个值相同（`路径 − 60`），不再需要外层分片；例如 1420 得到 1360。

TCP 被夹到路径值，不产生分片。大于路径值、不超过接口 MTU 的非 TCP 内层包（大的 UDP / QUIC、ICMP）靠 **WireGuard 外层包的 IP 分片**通过：WireGuard 发外层包不置 DF，枢纽 sidecar 把它转发进 MTU 1280 的 WARP 设备时分片。这在命名空间里验证过（`TestNetnsMeshLeg`：1216 字节无分片，1217 和 1280 字节各由分片承载并得到应答）；**真实 Cloudflare Mesh 是否放行这些分片没有证据**，校验为每条这样的 Mesh 腿给出警告 `mesh_leg_fragments`。分片不通时受影响的只是这段大小的非 TCP 包（例如 QUIC 会失败并回落到 TCP）；把链路 `mtu` 改成 Mesh 路径实际能承载的更大值（≥ 1340）可以完全避免。

钳制规则（`compile.meshLegExits`、`groupPathReports` / `groupClamps`、`validate.GroupMeshHopMTU`）：

- 有 Mesh 腿的出口：路径 MTU 是它所有承载路径（含 Mesh 腿）的最小值，默认 1216。它**不进全局值**（否则每个出口都被压到 1176/1156），而是按它自己的出口标记夹（`mss`、`sniff_mss`、`local_mss` / `local_mss_in`，SYN-ACK 按它的中转地址）。两条腿用同一个标记，所以它走直连腿时也按更小的值夹：这是切换腿之后已有连接不必重建的代价。
- 能切到这种出口的地区组：组路径报告（`Bundle.GroupPaths`）的 MTU 是切换顺序里每个成员路径 MTU 的最小值，`mesh: true`、`mesh_links`、`mesh_mtu` 说明是哪些腿、多小；按组标记在同样三处夹。
- 出口节点自己：`tunnel_mss_out` / `tunnel_mss_in` 用它自己的更小值。枢纽：对每条 Mesh 腿的接口各加一条该腿的值，其余接口不变。
- 其余不变：没有 Mesh 腿的出口、不含这种成员的组、全局值。`mtu_too_low`（路径 MTU 低于 1280）只看 Mesh 腿以外的链路；`cf_mesh` 链路的 `mtu` 自己仍不能低于 1280。
- 采用预览（`POST /api/mtu/adopt` 前的确认面板）除各出口外也列出组路径 MTU / MSS 的前后值（`group_paths`），值与组报告和网关规则集一致。

对示例拓扑：`hk-ix`、`hk-2`、`us`（直连腿加 Mesh 腿）和 `v6-v4out`（只有 Mesh 腿）的路径 MTU 是 1216，`hk`、`us`、`us-pin`、`v6-nat` 四个组按组标记夹到 1176/1156；其余出口和组、全局值 1320/1300 不变。主备枢纽、多中继分担、嵌套出口、外部出口这几个示例没有 Mesh 边，编译结果逐字节不变。

已知的限制：Mesh 路径的 MTU 用的是拓扑里 `cf_mesh` 链路的值，Cloudflare Mesh 实际的路径 MTU 面板看不到（上联 MTU 预检不覆盖 Mesh 腿：它的外层包先到本机 sidecar）；见「Mesh」的未验证清单。

对现有拓扑：示例、远程接入、主备枢纽、多中继分担、嵌套出口、外部出口（各自加打开嗅探的一份）的各出口路径 MTU 与以前逐个相同，金样不变；只有在非首选路径上某条链路的 MTU 比现在的最小值更小时，结果才变小。

### 上联 MTU：两端预检、建议与显式确认

2026-11-15 在真实部署上看到：一个出口的上联网卡 MTU 是 1472，不是 1500，面板给它的链路分配的隧道 MTU 是 1420。WireGuard 经 IPv4 外层加 60 字节（IP 20 + UDP 8 + WireGuard 头 16 + 认证标签 16），并把明文补齐到 16 的倍数（不超过接口 MTU）：内层 1408 字节封装后 1468，刚好能过；1412 补齐后 1420、封装后 1480，超过 1472 被静默丢弃，发送方收不到 ICMP。用不允许分片的 ping 实测与此一致（经该出口 1408 通、1412 不通；其它出口 1412 通）。转发流量靠 MSS 钳制（1320）掩盖了它，UDP 大包和未钳制的连接仍会断。外层是 IPv6 时开销是 80。

**唯一的开销计算**在 `internal/mtu`（纯计算，单元测试覆盖）：

- `Padded(inner, mtu) = min(mtu, ⌈inner/16⌉·16)`；`UDPOuterLen = Padded + 60（IPv4）/ 80（IPv6）`。
- 隧道 MTU `M` 能经上联 MTU `U` 发出（`FitsUDP`）当且仅当 `M + 开销 ≤ U`；超出的字节数 `ShortfallUDP`；能发出的最大内层包 `LargestInnerUDP`（不够时是 `⌊(U − 开销)/16⌋·16`）。
- 建议值 `SuggestUDP(U) = ⌊(U − 开销)/16⌋·16`：16 的倍数不会被补齐，所以不论实现是否把补齐截在 MTU 处都成立（1472 → IPv4 1408、IPv6 1392；1500 → 1440 / 1408）。低于 1280（IPv6 最小链路 MTU，`validate` 不接受更低）时不给可采用的建议，只提示这条上联承载不了 UDP 隧道。
- WSS（`mtu.WSS`）单独算：WireGuard 的 UDP 只到本机 `127.0.0.1` 上的 wstunnel（`lo` 的 MTU 65536），真正走上联的是 wstunnel 的 TCP（TLS + WebSocket 帧）。TCP 按上联 MSS 分段，上联 MTU 不会让 WSS 腿丢包，只决定一个隧道包在线上是几个段。给出的是估算（数据报 = 补齐后的内层 + 32，加 WebSocket 帧头 8 和 TLS 1.3 记录开销 22，MSS 按上联 MTU − IP − TCP − 时间戳选项 12）：TLS 记录可能合并或拆分，TCP 选项可能不同，段数可能差一。所以 WSS 腿从不因为上联 MTU 被判为承载不了，也不给建议值。
- `netns_mss_linux_test.go` 的外层长度也调用它，没有第二个公式。

**采集**（固定只读预检，见「下发前预检」）：

- 编译器给每个节点列出它的隧道腿（`compile.UplinkCarriers`）：接口、承载（`udp` 是 WireGuard 的 UDP，`wss` 是 wstunnel 的 TCP）、外层地址族、外层包发往的地址、设置它的链路字段（`mtu` / `wss_mtu`）。地址是这个节点的包实际发往的那个：拨号端用监听端的拨号地址（中继拨 IX 主枢纽时是国内入口地址，外层 IPv6 的腿用 `endpoint_v6`）；监听端用拨号端在拓扑里的固定地址；拨号端没有固定地址（NAT 拨出、家里的网关）或对端是动态 DNS 域名（面板不解析）时没有地址，按这一端该地址族的默认路由（最小 metric）判断，并在结果里写明。一个枢纽连多个出口或中继时每条链路一条，UDP+WSS 故障切换的链路有 UDP 和 WSS 两条。网关的 WireGuard 套接字带底层标记 `0x4d72`，它的查询也带这个标记。
- 远端节点：固定脚本多两类只读输出：每个接口的 MTU（`ip -o link show` 里的 `mtu`，`linkmtu` 行）；对每个有地址的腿一次 `ip -o -4|-6 route get <地址>`（内核查表，不发任何包），报告出接口和路由上显示的 MTU（锁定的路由 MTU 或缓存的路径 MTU），`uproute` 行。地址作为参数 `route4:<IPv4>` / `route6:<IPv6>` 传入：规范写法、不带 zone，面板、SSH 通道（`sshexec`）和脚本自己各检查一次，最多 64 个。脚本仍然是同一份固定文本，不执行任意命令。
- 网关：`meridian-host` 的固定预检动作多一个可选字段 `routes`（同样校验），对每个地址执行 `ip -o -4|-6 route get <地址> mark 0x4d72`，接口 MTU 来自它本来就执行的 `ip -o link show`。旧版 agent 不认识这个字段（400）时，面板去掉它重发一次：预检照常，网关的腿是「未知」。
- 上联 MTU = 接口 MTU，路由 MTU 更小时取路由 MTU。

**评估与严重程度**（`preflight.Evaluate`，代码稳定、面板按代码判断）：

- `uplink_mtu_too_small`：UDP 腿满长包封装后超过上联。消息写明哪一端（节点）、经哪块网卡、上联 MTU、封装后长度、超出多少字节、能发出的最大内层包和建议的隧道 MTU；修复入口指向这条链路的 MTU 字段。**阻断**：这条腿的接口还不是这台主机上 Meridian 的（新装或新加的链路）——按现在的 MTU 装上去会静默丢包。**警告**：接口已经是这台主机上 Meridian 的（已部署）——不能因为升级后多了这项检查就突然挡住别的操作（警告不阻断；只有「执行前复核新出现的警告」照旧要求重新审阅），面板也不会自己改。
- `uplink_mtu`（信息）：能承载的腿；`uplink_mtu_wss`（信息）：WSS 腿及分段估算；`uplink_mtu_unknown`（信息，「未验证」）：报告不完整、主机上的预检是旧版本（没有接口 MTU 或没有路由结果）、没有到对端的路由、查不到接口 MTU。未知从不算通过，也从不触发任何修改。
- 预检记录里另有 `uplinks`：每条腿的观察（接口、MTU）和判定。

**两端合并与建议**（`GET /api/mtu/uplinks`）：每条腿两端各取最近一次预检的观察，只有同时满足才算数：记录属于这个节点、这个面板实例；不超过 24 小时；远端节点的服务器、地址、端口、用户、主机指纹、凭据与现在一致；预检时这条腿的计划（接口、地址族、对端地址、标记）与现在相同。否则是「已过期」或「没有预检」，都不算验证。观察按这条腿**现在**的隧道 MTU 重新判定（采用建议后同一观察即判为能承载，不必重新预检两端）。任一端承载不了时，建议值取承载不了的各端建议的最小值；另一端未验证时在说明里写明。建议附带采用后的影响：重新编译拓扑，逐节点列出内容会变的文件，以及各出口路径 MTU / MSS 的前后值。

**显式采用**（`POST /api/mtu/adopt`）：请求必须逐条写出链路、字段、操作者看到的当前值和建议值，与服务器此刻的建议完全一致才写（否则 409 `mtu_suggestion_changed`，什么都不写）；写入是对当前值的比较后写入，写入后拓扑必须通过校验。它只改拓扑里已有的 `mtu` 字段，不碰任何主机：生效要经过部署页已有的流程（预检、逐节点审阅变更、确认）。面板拓扑页的「上联 MTU（两端预检）」卡片显示承载不了的腿、两端状态和建议值；「采用建议值…」先展开确认面板（逐条变更、逐节点文件差异、路径 MTU / MSS 变化），再点「确认写入拓扑」；拓扑编辑器有未保存的修改时不能采用。

**采用之后在运行中的接口上生效**（修订 19）：以前激活脚本对已存在的受管隧道接口只执行 `wg syncconf`，它替换对端集合但保留接口 MTU；只有远程接入接口 `mra` 有一条显式的 `ip link set … mtu`。于是采用建议值并下发后配置文件变了、面板显示已同步，运行中的接口却仍是旧 MTU，要等接口重建才生效。现在：

- 激活（`meridian-up.sh` 的 WireGuard 一步，`compile.wgActivateCommands`）：对清单里每个已存在的隧道接口（含 WSS 伴随接口）在 `wg syncconf` 之后读运行中的 MTU（`/sys/class/net/<接口>/mtu`），与配置的 `MTU =` 不同时执行 `ip link set dev <接口> mtu <配置值>` 并打印 `meridian-wg-mtu: <接口> 旧 -> 新`。值由编译器写进脚本（`wg_conf_mtu`），与写进配置 `MTU =` 的是同一个 `Tunnel.MTU`（`validate.LegMTU`）。不重建接口、不 `wg-quick down`、不动密钥和对端，会话保持；只动清单里列出的接口；`mra` 不在这张表里（它仍由自己的命令设置）。新接口照旧由 `wg-quick up` 按配置建立。失败时激活失败（`set -e`），不留下与配置不同的运行 MTU。
- 预检的变更列表：已存在、受管的隧道接口写「wg syncconf 更新，不断开；MTU A → B（ip link set 就地调整，不重建接口、不断开隧道）」，相同时写「MTU N 不变」，预检没读到运行 MTU 时不下结论。数据来自只读预检已经采集的 `linkmtu` 行（修订 16），没有新命令。运行 MTU 与配置不同还是一条警告 `tunnel_mtu_drift`：节点文件没有变化、本来「已同步」时也会报。
- 读回：远端节点安装后同一登录里读的固定只读命令（`sshexec.NodeStateCommand`）多读一项 `ip -o link show` 的 `linkmtu`（与预检同一条 awk），面板把装上去的每个隧道接口的运行 MTU 与它配置的 `MTU =` 比较（`preflight.TunnelMTUDrift`）：不一致是「不一致」（`verify.mtu_drift` 列出接口），没读到是「未核对」；只读预检读到的偏差同样写进读回（只在装上去的就是现在的内容时比较）。读回列出 MTU 偏差的节点状态不是「已同步」而是「有变化」，需要重新安装（引导不会把它当成已同步跳过）。网关的验收脚本多一项 `tunnel_mtu`：每个隧道接口（`ip link show dev`）的运行 MTU 必须等于配置值，不一致或接口不在都是 FAIL，不会 PASS。
- 下发顺序：两端先后安装之间，一端（A）已是新值 `M`，另一端（B）仍是旧值 `M0 > M`。WireGuard 把明文补齐到 16 的倍数、但不超过**发送端**接口的 MTU，所以外层长度 = min(发送端 MTU, ⌈内层/16⌉·16) + 60（IPv4；IPv6 是 80）。逐个方向：
  - A 发出的包：补齐不超过 `M`，外层不超过 `M + 60`；`M` 是 A 一侧上联的建议值时一定能过。
  - B 发出的包：对任意给定内层长度，B 的行为与改之前完全相同（补齐上限仍是 `M0`），所以不会比改之前更坏；变化在于经隧道到 A 的 TCP 从 A 学到更小的 MSS，满长段的内层是 `M`，B 把它补齐到 min(`M0`, ⌈`M`/16⌉·16)。`M` 是 16 的倍数时（所有建议值都是，`mtu.SuggestUDP`）不再补齐，外层 `M + 60`，B 一侧路径同样承载 `M` 时就能过：采用建议值后只装了一端，这些连接两个方向都已经通。`M` 不是 16 的倍数时（只可能是手工填的值）B 会补到下一个 16 的倍数，外层最多比 `M + 60` 多 15 字节：路径只比 `M + 60` 宽不到 16 字节时，这些包在 B 也装上之前仍被丢弃（之后补齐上限变成 `M`，就能过）。不经 TCP MSS 的包（UDP、ICMP）B 照旧最长按 `M0` 发，直到 B 也装上。
  - A 收到的包：B 发来的、内层比 A 的新 MTU `M` 长的包（只可能是不经 MSS 的 UDP、ICMP 等，或 B 本机未夹的连接）A **不会收下**。读内核 WireGuard 的接收代码看不到按本端 MTU 的检查，但 2026-11-15 在真实网关的内核（Debian 13）上运行 `TestNetnsLiveMTU` 的 R 段逐级计数的结果是：B 发出了 1412 字节的包、底层放行、外层包到达 A，而 A 的 `m02`（MTU 1376）没有交出任何内层包，也没有应答（`EVIDENCE R receive-larger: NOT DELIVERED`）。所以只装一端期间，B 发出的内层长于 `M` 的非 TCP 包会丢失。这些包里，内层长于路径能承载的（> 上联 − 60）改之前本来就丢；改之前能过、现在可能丢的只有内层在 (`M`, 上联 − 60] 之间的——`M` 是建议值时这个区间不到 16 字节。两端都装完后不再有这个问题。
  所以引导现有的依赖顺序（出口先于枢纽、中继和网关）对建议值足够，不需要额外的顺序，预检的「MTU A → B」已经说明哪些接口会变；完全生效要等两端都装完。**手工填的隧道 MTU 要取 16 的倍数**：不是 16 的倍数在两端都装好之后没有问题（补齐上限是本端 MTU），但只装了一端时会出现上面的丢包。校验没有为此加新的警告或错误（默认值 1420、1412 本身就不是 16 的倍数，两端相同时没有这个问题；对已有拓扑的校验结果不变）。手工把 MTU 调大时先装的一端会先发更大的包，另一端或路径承载不了时会丢，直到两端都装完：这种改动要先按验证说明确认两端上联都能承载。两端都装完之前，读回和验收各自只看本端。
- 对现有拓扑的编译结果：每个有隧道的节点的 `usr/local/sbin/meridian-up.sh` 变了（多了 `wg_conf_mtu` 和就地调整），网关的 `usr/local/sbin/meridian-verify.sh` 变了（`tunnel_mtu`）；隧道配置 `etc/wireguard/*.conf` 和其中的 `MTU =` 一个都不变。下一次预检会显示这些文件的差异；只有在运行 MTU 与配置本来就不同的接口上（例如以前采用过但没有生效）安装才会真的改 MTU。

**什么都不会自己变**：上联 MTU 未知时保持配置值；升级、预检、后台任务都不写隧道 MTU；编译结果只取决于拓扑里的字段，没有设 MTU 的现有拓扑升级后逐字节相同（单跳金样未变）。

**证明范围**：预检只证明每一端**本机**的约束（外层包从哪块网卡出去、这块网卡和路由的 MTU）。路径上更小的 MTU（运营商、云厂商的网络、别的隧道）看不到；链路健康检查里没有实现主动的有效 MTU 探测。人工核对步骤见验证说明「上联 MTU」。

所有 WireGuard 接口都是 `Table = off`，避免 `wg-quick` 把机器自己的默认路由抢走。外层端点在网关上有一条经 `192.0.2.1` 的主机路由，避免隧道把自己的握手包卷进去。

台湾和住宅出口的配置里，枢纽侧没有 `Endpoint`。出口侧 `PersistentKeepalive = 25`，更新用 `wg syncconf`。

## 接口名、端口和网段的分配

每条隧道链路（`direct_wg`、`wg_over_wss`、`udp_wss_failover`、`ix_replacement_wss`，以及架在 Mesh 上的 WireGuard 腿 `cf_mesh`）有一个**链路序号**，每个出口和每个地区组有一个**标记序号**（出口和组共用一套）。序号在对象第一次保存时分配，按对象 ID 存进拓扑的 `allocations` 表，之后**只要对象还在就不变**：增删、重排、启用或停用别的链路（或出口、地区组）都不会改变它。以前这些值取自对象在按 ID 排好的列表里的位置，加一条 ID 排在前面的链路就会让后面所有链路改名、换端口、换网段，相关节点全部要重新下发（真实部署里给已有出口加第二条枢纽链路时，出口原来的 `m02` 变成了 `m05`）。

由链路序号 `s` 决定的（链路或节点上明确填写的值仍然优先）：

| 资源 | 值 | 覆盖项 |
| --- | --- | --- |
| 接口名 | `m%02d`（`m00`、`m01`…）；`udp_wss_failover` 的 WSS 腿 `m%02dw` | 无（名字只来自序号） |
| 监听端 WireGuard 端口 | `51820 + s`；`udp_wss_failover` 的 WSS 腿再 +1 | 链路 `wg_port`；监听节点 `listen_port`（只在它只监听这一条没设 `wg_port` 的链路时） |
| 拨号端 wstunnel 本地端口 | `52000 + s` | 链路 `wss_local_port` |
| 隧道 IPv4 | `10.66.(s+1).1` / `.2`（`/30`，西端 `.1`） | 链路 `from_v4` / `to_v4` |
| 隧道 ULA | `fd66:0:0:(s+1)::1` / `::2` | 链路 `from_ula` / `to_ula` |
| WSS 腿地址 | `10.66.(100+s).1` / `.2`、`fd66:0:0:(0x80+s)::1` / `::2` | 无 |

链路序号最多 99 个（0–98）：再往上主腿网段会碰到 WSS 腿的 `10.66.100–198`。由标记序号 `m` 决定的：fwmark `0x101 + m`、枢纽路由表 `201 + m`、中转地址 `10.66.200.(10+m)` / `fd66:0:0:ff::(10+m)`、解析地址 `fd66::54:(m+1)`（出口）或 `fd66::53:(m+1)`（地区组）、策略规则优先级 `17200 + m` 等，最多 240 个。

**表的形状**（`GET /api/topology` 里，随导出和导入走；面板只读）：

```json
"allocations": {
  "links":  { "gw-access": { "slot": 0 }, "access-ix": { "slot": 1 } },
  "exits":  { "dc1": { "slot": 0 } },
  "groups": { "hk":  { "slot": 2 } },
  "retired_links": [5],
  "retired_marks": []
}
```

**谁拥有它。** 面板（`store.Save`，`model.ReconcileAllocations`）：一次保存里，已存表里有的对象保留存表里的序号，不管提交的文档里写的是什么（旧标签页、没有这个字段的客户端、被改过的表都一样）；存表里有、文档里已经没有的对象，其序号进 `retired_*`；新对象拿**最小的、从没用过的**序号，并且跳过与手工填写的隧道地址、任何链路或节点上设置或默认占用的端口、主机上被命名为 `mNN` 的接口相冲突的序号（按 ID 顺序，结果确定）。编译、校验、差分和预览（`POST /api/compile` 等带文档的请求）都先按同一规则对照已存表，所以预览看到的就是保存后的结果。

**复用规则。** 被删除对象的序号只有在没用过的序号全部用完之后才会复用（最早退休的先用），而且**绝不在退休它的同一次保存里复用**：同一次保存里删一条链路、加一条链路，新链路一定拿到别的接口名——旧接口在没有重新下发的旧端点上可能还带着别的对端和密钥。删除本身仍经已有的受管清单和事务清理：远端更新时先撤掉新包里没有的旧隧道接口（`TestProvisionUpdateRemovesStaleInterfaces`），网关按安装清单的差分移除。序号全部用完时校验报 `link_alloc_exhausted` / `mark_alloc_exhausted`，拒绝编译。

**迁移。** 没有这张表的拓扑（升级前存的、旧导出、仓库示例和测试里直接构造的）按它当时的位置编号：启用的隧道链路按 ID 排序依次得到 0、1、…，出口按 ID 得到 0…E-1，地区组接着 E、E+1、…——正是旧编译器的编号，所以**升级后第一次编译与升级前逐字节相同**（`TestAllocationMigrationCompilesIdentically`、`TestGoldenSingleHubUnchangedAfterMigration` 用未重新生成的 golden 文件验证）。停用的隧道链路以前没有编号，迁移时给它们最小的空闲序号（它们不生成配置，所以不影响输出）。面板启动时把迁移结果写回数据库（`store.MigrateAllocations`，在地区组迁移之后；只写一次，再跑不变）；在那之前每次读取也在内存里做同样的迁移。`PUT /api/topology?import=1` 是整份替换（把导出的文档带回来）：文档自带的表在合法范围内就照用，没有表的旧导出按位置编号，原来存表里所有序号都记为退休，所以文档里没有序号的对象不会拿到它们。

**顺序。** 编译器按链路序号（而不是链路 ID）的顺序处理隧道。迁移后的拓扑里两者相同；之后新加的链路排在已有链路后面，所以它不会抢走已有链路「第一条」的角色（枢纽到出口的直连隧道、网关探测中继用的那条隧道），也不会打乱其他节点上按隧道顺序写出的列表。结果是：加一条链路只改变它两端的节点（`TestAllocationAddLinkChangesOnlyItsEnds`），删一条后加的链路也只改变两端（`TestAllocationRemoveLinkChangesOnlyItsEnds`）。仍然存在的例外：删掉在网关隧道顺序里**最靠前**、提到某个端点的链路，会让网关隧道端点集合（`endpoint_*`）里元素的排列变化（集合内容不变，属于纯文本变化，但网关会显示待安装）；删掉某台中继到枢纽的第一条隧道，会改变网关对这台中继的探测目标（这是真实变化）。加一个出口或地区组改变网关和枢纽（新标记、新表），不再改变其他出口。

**统一的冲突校验**（错误级别，带 `link_id` / `node_id` / `group_id` 和 `field`，面板据此跳到对应编辑器）：

- `subnet_overlap`：两条链路的隧道网段重叠，不论哪一边是手工填写、哪一边是序号给的（主腿 IPv4 `/30`、ULA `/64`、WSS 腿各算一段；以前只比较两条都手工填写、而且实际上从不会触发的情况，所以手工地址落进别的链路自动网段时没有被拦下）。问题挂在手工填写的那条链路和那个字段上。
- `link_addr_reserved`：手工隧道地址落在中转前缀（含探测源地址 `10.66.200.2`）、IPv6 中转前缀、链路本地（Mesh veth `169.254.66.0/30`、`fe80::66:*`）、Cloudflare Mesh 段、远程接入设备地址池（`10.67.0.0/24`、`fd67::/64` 或配置的值）、局域网 IPv6 前缀、节点局域网、NAT64 前缀、环回或组播里。局域网 IPv4、ROS 地址、ULA 前缀和解析保留段 `fd66::/64` 继续由原来的 `prefix_conflict`、`ula_via_ros`、`group_resolver_conflict` 检查（现在也带 `field`）。
- `iface_name_conflict`：节点上填写的局域网 / WAN / 国内入口接口名与这台主机上的隧道接口同名，或用了保留名 `mra`、`mmesh`、`mmesh-c`。
- 端口：仍由 `checkPorts` 按序号给出的端口检查（`port_conflict` 等，见「端口从哪里来」）。
- `link_alloc_invalid` / `mark_alloc_invalid`：存表里两个对象同一个序号或序号越界（只会在手工改过数据库时出现）；`link_alloc_exhausted` / `mark_alloc_exhausted`：分不到序号。

宿主上的检查（主机上已有的接口、端口）仍是预检的事，不变。

**面板。** 链路编辑器里「接口与地址（只读）」显示这条链路的序号、接口名、端口（以及端口来自哪里）、wstunnel 本地端口和每条腿两端的隧道地址（`POST /api/topology/allocations`，对工作副本算，带 `new`：保存时才分配）。工作副本会改变某条**已保存**链路的接口、端口或地址时（只可能来自明确的编辑：端口、地址、传输方式、启用），编辑器和拓扑页顶部都会列出改动，提示两端要重新下发。「已保存」指面板数据库里的拓扑，不是各节点实际装上的内容（按节点记录实际下发内容是另一项工作）。

以上全部只有仓库里的自动化回归，**没有在任何真实主机上执行过**。

## DNS

SmartDNS 只绑在网关的局域网地址上。

- `223.5.5.5` 和 `1.12.12.12` 的 DoT 解析内置国内名单（geosite `cn`），结果写入 `direct4` / `direct6`，走 ROS。这个名单排在**所有规则之后**：规则命中的名字已经从它里面去掉（见「分流规则：一个有序列表」）。以前还内置了 `apple` 名单直连，已经去掉：苹果的名字不是国内名字，要直连就写一条指向直连的规则（规则页「添加规则」，匹配 geosite `apple`，去向「直连」；不默认启用）。
- 各服务名单经对应出口隧道上的解析器查询，再写入该规则的 nftset。规则指向枢纽可切换的地区组时，问的是组自己的解析地址，跟着枢纽当前选中的成员走，见「地区组的解析」。
- 没命中的名字走默认组（示例里是香港机房组），写入默认集合；默认组可切换时同样经组的解析地址。打开「未列名单域名的国内解析」时先问国内解析器，见下文。
- AAAA 由「客户端 IPv6 经本网关」决定，见下文。打开它之后，出口没有 `egress_v6` 的规则仍加 `-address #6`，不返回 AAAA，也不改到别的国家。
- nftables 把测试设备发往任意地址的 UDP/TCP 53 和 TCP 853 重定向到本机。
- 已知 DoH 域名返回 SOA，已知 DoH 地址的 443 在转发链上被拒绝。这只覆盖清单，不能说绝对防住了 DoH。

### 客户端 IPv6 与 AAAA

网关设置 `clients_ipv6_via_gateway`（面板「网关设置 → 解析（DNS）→ 客户端 IPv6 经本网关」），默认**关闭**；在它出现之前保存的拓扑读进来就是关闭。

为什么默认关：手机（iOS/Android）在 Wi-Fi 里只能手填 IPv4 网关和 DNS，IPv6 地址和 IPv6 默认路由仍来自家里路由器（ROS）的 RA。网关解析器只要给国外域名返回 AAAA，手机就优先用 IPv6，从本地宽带的 IPv6 直接出去，**不经过网关、也不进隧道**：被封的网站先卡住、等回落到 IPv4 才打开（“开头慢”），没被封的国外网站则静默地从本地宽带直连。以前只有规则级的 AAAA 过滤（出口没有 `egress_v6`），没命中规则的默认组不过滤，所以只配了一个纯 IPv4 出口时 google、youtube、netflix 之类仍拿得到 AAAA。

| 设置 | 走隧道的域名（默认组、每条规则、地区组、钉死出口） | 国内域名（内置 `cn` 名单、指向直连的规则，及下文被采用的国内答案） |
| --- | --- | --- |
| 关闭（默认） | 一律不返回 AAAA（空的 NOERROR + SOA），HTTPS 记录里的 IPv6 提示也去掉；客户端只用 IPv4 经网关进隧道 | 照常返回 AAAA，经家里路由器直连 |
| 打开 | 出口（地区组按全部可切换成员）能端到端承载 IPv6（`egress_v6`）时返回 AAAA，否则同上 | 同上 |

打开的前提是客户端的 IPv6 默认路由确实指向网关的链路本地地址（[测试设备](test-device.md)「IPv6」），否则打开就等于把上面那个泄漏放回去。校验给 `aaaa_filtered` 警告：关闭时一条拓扑级警告说明所有非国内域名都只有 IPv4；打开时对出口没有 `egress_v6` 的规则和默认组各一条；打开但没填局域网 IPv6 前缀时 `clients_ipv6_no_prefix`。

SmartDNS 里的写法（固定版本 Release48.4，源码 `src/dns_server/soa.c` 的 `_dns_server_is_return_soa_qtype`）：

- 默认组不能有 AAAA（设置关闭，或默认组没有 IPv6）时全局 `force-AAAA-SOA yes`。它对每个 AAAA 回空的 NOERROR（SOA），不问上游；HTTPS 记录的 `ipv6hint` 因同一个判断被丢掉。
- 例外按域名规则给：内置 `cn` 名单（以前还有 `apple`）和指向直连的规则的 `domain-rules` 加 `-address -6`（`DOMAIN_FLAG_ADDR_IPV6_IGN`，在 force-AAAA-SOA 之前判断）；允许 IPv6 的规则同样加 `-address -6`，并照旧写 `#6:` 的 nftset。
- 不允许 IPv6 的规则仍是 `-address #6`，它比上面两者都优先。默认组不能有 AAAA 时不再写 `nftset #6:…#default6`。
- 打开且默认组有 IPv6 时不写 force-AAAA-SOA，生成结果和以前相同。

真实二进制的测试（`TestSmartDNSRealBinary`，见[验收清单](verification.md#网关解析器的真实二进制测试)）证明：`force-AAAA-SOA` 下默认组的 AAAA 为空、`cn` 名单的 AAAA 照常返回（即使那个地址不在中国）、规则按各自的标志处理；去掉这一行（以前的配置）时默认组的 AAAA 会被返回。

现有拓扑升级后网关解析器的生成结果会变（这就是修复）：加 `force-AAAA-SOA yes`、`cache-persist no`（见下一节「缓存与策略变化」），`cn`/`apple` 加 `-address -6`，每条规则都变成 `-address #6`，去掉 `default6` 的 nftset。nft、路由和其他节点不变。`meridian-verify.sh` 在设置关闭时真实地问一次本机解析器（`dig @127.0.0.1 AAAA www.google.com`，可用 `MERIDIAN_VERIFY_AAAA_NAME` 换成别的国外名字），回答里有 AAAA 就 FAIL（`dns_aaaa_tunnelled`）。

### 未列名单域名的国内解析

网关设置 `unlisted_domestic_dns`（面板「网关设置 → 解析（DNS）→ 未列名单的域名也问国内 DNS」），默认**关闭**（严格）。

关闭时不在任何名单、也没有命中规则的名字只经隧道由默认出口的解析器解析：名单外的国内网站拿到的是面向海外的 CDN 节点，要么被送进隧道，要么直连到一个很差的节点（“国内网站开头慢、不像直连”）。

打开时，这类名字的 A/AAAA 同时问国内解析器和默认出口的解析器，**只有国内回答里的每一个地址都是中国地址（chnroute 名单）时才采用**，整份回答要么全收要么全不收；收下的地址在 `chnroute` / `chnroute6` 里，分类链（`chnroute` 在 `default4` 之前）让它直连。其余情况一律用出口解析器的回答、走隧道：CNAME 链最后是国外地址、中国与国外混合、NODATA / NXDOMAIN、被污染的地址、国内不回答。出口不回答时客户端得到 SERVFAIL，国内的国外地址永远不会被返回。

**为什么不是 SmartDNS 自己做（第一版的做法，在真实网关上失败了）。** 第一版用 SmartDNS 的 `-whitelist-ip`（国内上游只收白名单地址）加出口上游 `-fallback`。在真实网关上（SmartDNS 1.2026.11.09）`www.wikipedia.org`、`www.facebook.com`、`www.bbc.com` 只得到一条没有地址的 CNAME，并被缓存。用固定版本和替身上游复现了（`TestSmartDNSRealBinary` 的 `cname-foreign`，Release48.4 和 1.2026.11.09 都一样）：诚实的国内解析器回答「CNAME + 国外 A」时，白名单只丢掉 A；`_dns_server_process_answer`（`src/dns_server/answer.c`）处理 CNAME 时已经把请求的 rcode 设成 NOERROR，而「地址全被跳过就重试」那一支要求 rcode 还是 SERVFAIL，所以不重试，回调返回 OK、`query->has_result` 置位，`_dns_client_retry_dns_query` 不再发送，`-fallback` 的出口一次都没被问到，请求以只有 CNAME 的回答结束并进缓存。`blacklist-ip` 命中同样只跳过地址（CNAME 照样设了 rcode），`bogus-nxdomain` 会把回答变成 NXDOMAIN；这个版本没有“只要有一个地址不合格就丢掉整份回答”的选项。之前的测试只覆盖了单独一条被污染的 A，那时“全部跳过→重试”恰好成立。

**现在的做法：网关上的一个小服务 `meridian-dns-split`**（`internal/dnssplit`，`/usr/local/bin/meridian dns-split`，systemd 单元 `meridian-dns-split.service`，只在设置打开时编译和安装）。网关 SmartDNS 的默认组只有它一个上游：

```
server 127.0.0.1:5356 -group unlisted_split          # 默认组：名单外的名字
server fd66::53:d -group rg_hk -exclude-default-group -set-mark 269   # 默认组自己的规则仍直接问它
```

单元的 `ExecStart` 带着编译出的参数：`--domestic 223.5.5.5:53,1.12.12.12:53`（`domestic_dot`，UDP 53）、`--exit` 默认组的解析地址（或静态默认出口的隧道解析地址）和 `--exit-mark`（与 SmartDNS 那一行的 `-set-mark` 相同，十进制；所以需要 root 的 `CAP_NET_ADMIN`，单元只保留这一个能力）、`--china4/--china6` 名单更新保存在宿主 `/var/lib/meridian/lists/` 的两个文件。规则：

- 只处理 A 和 AAAA；其他类型（HTTPS、SVCB、TXT…）只问出口。
- 国内和出口同时发出，尽早决定（参数都写在单元的 `ExecStart` 里，下面是默认值）：
  - 任何一个国内解析器给出合格回答，立即用它（只要还没决定），不管出口是否已经回答（国内比出口慢也一样，测试 `unl-cn-slow`）。
  - 一个国内解析器回了不合格的回答之后，再在同一个查询上等 `--settle 30ms`：明文 UDP 上可能先到一个被注入的伪造回答、后到真正的回答，这段时间里到的合格回答仍会被采用（测试 `forged-then-genuine`、`split-dom`）。之后它就算“答完了”。
  - 出口已经回答，并且（所有国内解析器都答完或超时，或者至少有一个国内解析器回答过并已 settle）时，立即用出口的回答。所以一个不回答的国内解析器不会拖住结果：另一个已回答并 settle 后就不再等它。`--domestic-timeout 400ms` 只在**没有任何**国内解析器回答时才是等待上限。
  - 出口不回答时等所有国内解析器（中国回答仍可用），然后 SERVFAIL；出口单次 `--exit-timeout 2s`，UDP 截断时改走 TCP。
  - 判错的方向只有一种是可以接受的：真正的中国回答来得太晚（晚于另一解析器 settle 和出口回答），这个名字就走出口的回答、进隧道，而不是直连——不是泄漏。返回带国外地址的国内回答在任何时序下都不会发生：国内回答只有合格时才会被返回。
  - 本机测得的决定时间（替身上游，`internal/dnssplit` 的 `TestDecisionTimes`）：两个国内 10 ms 回国外、出口 50 ms → 51 ms；出口 5 ms → 42 ms（10 + 30 settle）；出口 150 ms → 151 ms；一个国内不回答、另一个 10 ms 回国外、出口 20 ms → 42 ms；伪造 5 ms、真中国 20 ms → 21 ms 采用国内；国内都不回答 → 400 ms。
  - `--stats-interval 10m`：每段时间一行汇总日志（`meridian-dns-split-stats`）：各结果的次数、决定时间的 p50/p90/p99、不回答的国内解析器次数、伪造后又收到合格回答的次数；**不记录任何域名**。
- 合格：rcode NOERROR、没有截断、回答段里至少一个所问类型的地址，并且回答段里**每一条** A/AAAA 都在中国名单里（不管属于 CNAME 链上哪个名字）。
- 名单在启动时读；读不到或为空时不收任何国内回答（等于关闭，直到名单更新）。不需要给 SmartDNS 容器挂载名单目录。

AAAA 仍先由 SmartDNS 按第 1 节决定（`force-AAAA-SOA`），只有允许 AAAA 时 AAAA 查询才会到这个服务；所以「客户端 IPv6 经本网关」关闭时，被采用的国内回答也只有 A（没有域名规则能豁免名单外的名字；按回答判断 AAAA 的 `ignore-ip ::/0` 办法实测让每个国外名字的 AAAA 等 0.5–1 秒）。

**缓存与策略变化。** SmartDNS 默认 `cache-persist` 是 auto：空间够就把缓存存到容器里的 `/var/cache/smartdns/`，启动时读回。安装时的 `docker restart` 因此不会清空缓存——真实网关上关掉设置、重装、SmartDNS 被重启之后，仍在回答旧策略缓存下来的 CNAME。真实二进制测试复现了（SIGTERM 后用另一份配置启动，旧回答仍被返回）。网关配置现在固定 `cache-persist no`（两个设置怎么改都一样），重启后从空缓存开始，测试证明换配置重启后按新策略回答。名单更新替换了 China 文件、且安装的配置用了这个服务时，host agent 先重启 `meridian-dns-split` 再重启 SmartDNS（`chnroute_changed`，经合并限频的自动读入，见「名单与 SmartDNS 自动读入」）；设置关闭时 chnroute 更新不碰解析器。

**代价，打开前要知道：**

- 国内解析器能看到**所有名单外的域名，包括国外的**，这些查询从网关经本地宽带以明文 UDP 53 发出（服务不用 DoT）。这与“国外域名的 DNS 不经本地宽带发出”的严格保证相反：打开后它不再成立，`meridian-verify.sh` 和 [验收清单](verification.md) 的 DNS 泄漏项按新的保证描述——泄漏测试网站会同时列出国内解析器和出口的解析器，这是预期结果；仍要求测试设备自己不向外发 53/853。
- 国外名字的冷查询要等到出口回答和国内回答后的 30 ms settle（两者取后者）；两个国内解析器都不回答时等 400 ms；出口解析器不通时 SERVFAIL 要等约 2 秒。第一版服务（2026-11-13 在真实网关上）对每个冷的国外名字都等满 400 ms，因为它只在所有国内解析器都给出结论后才决定；正好 400 ms 说明有一个国内解析器（从服务发出的查询看）没有回答，具体是哪个、为什么没有在网关上核实。现在已回答的那个 settle 之后就不再等它，统计行里的 `silent domestic resolvers` 能看出这种情况。
- 中国地址的判断只看 chnroute 名单：落在名单里的伪造地址会被采用；国内 CDN 把国外网站解析到中国节点时也会直连。
- 它用宿主上的 `/usr/local/bin/meridian`（`deploy/debian/install.sh` 从面板镜像拷出来的那一份）。打开设置之前要先用新镜像重跑一次 `install.sh`：旧的宿主二进制不认识 `dns-split`，会把它当成启动面板，所以单元先 `grep -q meridian-dns-split-ready /usr/local/bin/meridian`，旧二进制时不启动（名单外的名字随之 SERVFAIL，`dns_split_active` FAIL）。
- 多了一个必须运行的宿主服务：它停了，名单外的名字全部 SERVFAIL（`meridian-verify.sh` 的 `dns_split_active`）。监听固定 127.0.0.1:5356（UDP/TCP），预检按这个单元的端口检查占用，校验把 5356 列为保留端口。默认组没有解析器时不生成这个服务，名单外的名字仍走严格路径。

**和其他部分的关系（地区组、两个枢纽、多中继、挂靠出口、外部出口、Mesh、远程接入）。** 原则只有一条：`meridian-dns-split` 问出口时用的地址和标记，与 SmartDNS 里默认组那一行**完全相同**，所以它走的路径就是默认组自己的解析查询的路径；变化都发生在这台网关之后。`TestGatewayDNSPolicyAcrossDefaults` 对下面每种默认（加上每种设置组合）核对 `--exit`/`--exit-mark` 与那一行的地址和 `-set-mark` 逐字相同。

- **地区组与切换**：默认组可切换时 `--exit` 是组的解析地址、`--exit-mark` 是组标记（十进制）。网关的 `transit_snat` 按「组标记 + 组解析地址 + 53」把本机的查询改成组的中转源（对任何本机套接字都一样，不认进程），枢纽按源进组表、到当前成员、成员 DNAT 到自己的解析器。枢纽切换成员不需要网关上任何变化。换默认组（面板改 `default_group`）会改单元的参数，安装时重启它。命名空间测试 `TestNetnsGroupDNSFailover` 在网关命名空间里用编译出的单元参数跑这个服务：切换前问到 us，枢纽切到 us-2 后问到 us-2，两个成员都断时 SERVFAIL，组自己的查询仍然一次都没到国内解析器（服务为名单外名字发的国内查询单独计数）。
- **两个枢纽、多中继分担**：静态默认出口在有备用枢纽时用与枢纽无关的解析地址（`ExitPlan.Resolver`），与 SmartDNS 那一行相同；组标记的本机套接字按 102 表走指定中继（多中继时是最重的那台或备用枢纽），没有标记的走本机到隧道前缀的路由——两者都与 SmartDNS 自己的上游查询相同。
- **挂靠出口（`via_exit`）**：组切到挂靠出口时，枢纽把组的中转源换成挂靠出口的（`nested_snat`），中继出口放行，解析在挂靠出口自己完成。服务不知道也不需要知道这一层。
- **外部 TCP 出口**：服务问出口用明文 UDP（截断时 TCP）。这能用，原因是：发往外部出口解析地址的 DNS 不是它的“数据”——承载节点的 `ext_dnat` 先把「这个出口的中转源 → 组解析网段」和（有备用枢纽时）「→ 它的独立解析地址」的 UDP **和** TCP 53 DNAT 到承载节点上这个出口的解析组（SmartDNS 同时 `bind` 和 `bind-tcp`），这两条排在拒绝它其余 UDP 和全部 IPv6 的规则**之前**；单枢纽的静态情形直接发往承载节点 lo 上的解析地址，同样有 UDP 监听。承载节点的解析组再经 SOCKS 用 TCP 去问公共解析器——UDP 只出现在网关到承载节点的隧道里，从不经过 SOCKS 设备。结构测试核对这条规则顺序和两个监听，`TestNetnsExternalExit` 用 UDP 查询从组的中转源和独立解析地址实际问到过（只在本机 Linux 容器里，P2）。外部出口只回答 A：它在组里时组不算能承载 IPv6，`force-AAAA-SOA` 保持打开，规则一律 `-address #6`；编译器另外把外部出口一律算作没有 IPv6（`carriesV6`），即使 `egress_v6` 绕过了校验（`external_v6`）也不会给通向它的名字返回 AAAA。
- **Mesh 腿**：成员经 Mesh 腿承载时，组的解析查询仍由这个成员自己的解析器应答（「地区组的解析」第 7 条）；服务带同一个组标记，走同一条路。Mesh 不承载或未密封时失败，不回落。真实 Cloudflare Mesh 没有证据（同那一节）。
- **组的解析不回落国内**：分流只作用于**没有命中任何名单和规则**的名字（默认组的兜底）。规则命中的名字——包括指向默认组本身的规则——只问它目标的上游组，那个组里只有组解析地址或出口解析地址，既没有国内解析器也没有这个服务；目标不回答时解析失败，不会换去问国内。结构测试对每条规则核对它的 `-nameserver` 组成员；真实二进制测试（打开设置时）用会被采用的中国回答引诱，统计替身国内解析器收到的查询：规则名字一次都没有被问到，目标不回答的规则名字解析失败。
- **国内回答写进哪个集合**：服务采用的国内回答由 SmartDNS 的默认组写进 `default4`（以及允许 AAAA 时的 `default6`）。没有东西依赖这一点：这些地址都在 chnroute 名单里，分类链里 `chnroute` / `chnroute6` 在 `default4` / `default6` 之前，所以它们按 chnroute 直连；`default4` 里的这些条目从不起作用。唯一的差别是服务读的是名单**文件**，nft 的 `chnroute` 集合是名单更新加载的：两者不一致（例如 nft 加载失败而文件已替换）时，一个被采用的中国地址可能不在 nft 集合里，这时它按 `default4` 进隧道——方向是安全的（进隧道，不是绕过隧道）。
- **远程接入设备**：它们用网关在 `mra` 上的地址做 DNS（劫持和准入与局域网相同），问的是同一个 SmartDNS，得到同一套策略；打开远程接入不改变解析器配置和这个单元（`TestGatewayDNSPolicyRemoteAccessSame`）。「客户端 IPv6 经本网关」说的是**局域网**客户端，它仍是全局唯一的开关，不按设备区分：全隧道模式（`::/0`）的远程设备的 IPv6 确实经过网关、按同样的规则分流，所以对它们来说打开这个设置是安全的；但设置关闭（默认）时它们同样拿不到走隧道域名的 AAAA，只用 IPv4 经隧道——不丢连通性，也不泄漏。不为远程设备单独放开 AAAA：那需要按客户端区分的解析视图，而局域网手机的默认情形（IPv6 来自家里路由器）必须保持关闭。仅家里网段模式的设备本来就只把家里网段送进隧道，其余流量（包括 IPv6）走设备自己的网络，不受这台网关的分流管。
- **单元的能力**：以 root 运行，`CapabilityBoundingSet=CAP_NET_ADMIN`（给 `SO_MARK`；只在组标记非 0 时用），`AmbientCapabilities=` 为空，`NoNewPrivileges=yes`、`ProtectSystem=strict`（只读名单文件、只监听回环端口）、`ProtectHome=yes`、`PrivateTmp=yes`。

真实二进制测试覆盖上面每一种回答（见[验收清单](verification.md#网关解析器的真实二进制测试)），`internal/dnssplit` 的单元测试另外覆盖 NXDOMAIN、出口截断改 TCP、非 A/AAAA 只问出口、TCP 监听、像外部出口那样只回答 A 的出口解析器和拒绝连接的出口端口。这些在本机容器里用替身上游跑过。

**真实网关上的结果（2026-11-13，由主会话在用户的网关上测过一次；没有存档的日志）。** 网关运行的是独立分支上的同一套实现（`meridian-dns-split` 加上面的决定时机）：20 个冷的国外名字全部解析到出口给的地址，用时 52–72 ms（上一版时机下每个约 400 ms，因为两个国内解析器里有一个从不回答这类查询）；之前只得到 CNAME 的三个名字解析正确；带国内 CDN 节点的名单外名字由国内解析器回答，约 8 ms，并直连；走隧道的名字没有 AAAA，名单内的国内名字保留 AAAA；关掉设置立即生效，没有旧回答；网关的 `meridian-verify.sh` 通过（`dns_aaaa_tunnelled`、`dns_split_active`）。这是一次人工观测，不是可复现的记录；外部出口、挂靠出口、多中继、Mesh 和远程接入下的这项功能都**没有**在真实环境里用过。iOS 的「无线局域网没有接入互联网」**不知道是否已经解决**，见[测试设备](test-device.md)「iOS 联网检测复测」。

chnroute 来自 gaoyifan/china-operator-ip（MIT），geosite 分类来自 v2fly/domain-list-community（MIT）。GPL 的规则包只作为可选数据源，不放进仓库，也不链进面板。下载、展开和发布见下一节「名单源」。

## 分流规则：一个有序列表

和 Clash、mihomo、Surge 一样，面板的分流规则是**一个有序列表，从上到下，第一条命中的规则决定去向**。手工规则、内置规则、从 mihomo 导入的规则、使用规则集的规则都在同一个列表里；规则页的表格顺序就是语义。所有规则之后依次是：内置国内名单（geosite `cn`，国内解析器、直连）、中国地址直连（chnroute，相当于 `GEOIP,CN,DIRECT`）、默认组（相当于 `MATCH`）。

### 模型

- `Topology.Rules` 的**切片顺序**就是求值顺序（`rules_ordered: true`）。旧拓扑读进来时按以前编译器用的顺序排好（手工在前、再按优先级、再按 ID，`model.MigrateRuleOrder`），所以 nft 分类链和每条规则的集合 `r<n>` 编号与升级前完全相同；`priority` 只保留原值，不再决定顺序。
- 规则的去向：地区组、出口、**直连**、**拒绝**（`target_action`）。从 mihomo 导入的规则另带 `mihomo_group`：原策略组名，只是规则页筛选和批量改指向的标签，不是路由对象。匹配方式多了**规则集**（`match_type: ruleset`、`rule_set`）和 **QUIC 开关行**（`quic_reject`，没有去向）。导入的规则 `origin: "mihomo"`，带 `source_line` / `source_text`。
- 参考解释器在 `internal/ordered`（不依赖面板的任何包）：`ordered.Reference` 是线性的规格；`ordered.Compile(rules, tail, quicAt)` 建出不可变的索引（精确名、后缀、子域名各一个哈希表，按名字的每一级查一次；关键词用 Aho-Corasick 一次扫描；CIDR 按前缀长度各一个表），`(*Compiled).Decide(Request{Name, Addr, Proto, Port, Source})` 返回 `{index, id, target, mark, reason, quic_rejected}`，并发安全；`ordered.Engine` 原子替换。安装写出序列化形式 `/etc/meridian/rules/decide.json`（`ordered.Snapshot`：每条规则的去向已经解析成 mark，静态条目内联，规则集 / geosite / 关键词展开按引用，`ordered.LoadSnapshot` 用和 derive 相同的文件读取）。规则页的「哪条规则会命中？」调用的就是 `Decide`。测得：60 条规则共 6 万条后缀、9600 个关键词、1.8 万条 CIDR，一次判断约 1 µs，建索引约 17 ms（`go test ./internal/ordered -bench .`，开发机）。

### 数据面怎样保持「第一条命中」

网关不是按连接看名字，而是两步：SmartDNS 为被查询的名字选一条域名规则，把答案地址写进那条规则的 nft 集合；分类链再按目的地址在集合里查。两者本身都不按列表顺序：

- **SmartDNS 选最长的匹配键**（Release48.4 `_config_setup_domain_key` / `_dns_server_get_rules`：键是倒序的名字，普通键覆盖名字本身和下级，`*.d` 只覆盖下级，`-.d` 只覆盖名字本身；查询时从短到长走过所有前缀键，同一类规则后面的覆盖前面的；标志位按位或累加）。
- 所以安装时不再把域名直接写进 `domain-rules`：编译器写出规则的**有序来源清单** `/etc/meridian/rules/order.conf`（每条规则一个集合：静态名字、geosite 分类、关键词展开、规则集；最后是 `cn`），网关上的 `meridian lists-derive`（`meridian-up.sh` 在 nft 加载之后、打开转发之前执行；名单更新和规则集启用之后宿主代理也会重做）把它变成 `/var/lib/meridian/geosite/ordered/<集合>.txt`。**规则（优先级过滤）**：按列表顺序处理，每个名字键有「名字本身」和「下级名字」两部分；某个上级名字的「下级」已经属于更早的集合时整条丢掉；否则只保留还没有归属的部分，写成 `k`、`-.k` 或 `*.k`。于是每个 SmartDNS 键只出现一次，而且属于第一条匹配它的规则；最长匹配就等于第一条命中（`ordered.Derive` 的注释里有证明）。内置国内名单最后处理，所以规则里出现过的名字（包括它的下级）不会再被当成国内名字——规则总是优先。
- **分类链**按列表顺序放每条规则的集合（`r<n>`、`r<n>6`，规则集的地址条目在 `r<n>c` / `r<n>c6`，由 derive 写入，不过期；`GEOIP,CN` 规则在它的位置查 `chnroute`），再是 `direct4/6`、`chnroute`、私网、`default4/6`。一个名字的地址只会被写进第一条匹配它的规则的集合，而地址规则和名字规则在链里按列表顺序排，所以「名字规则在前、地址规则在后」和「地址规则在前」都与第一条命中一致（域名与 IP 规则交叉不需要特别处理）。

**唯一的固有差别（请记住）**：Clash / Surge 按每个连接请求的名字判断；网关按 DNS 学到的目的地址判断。两个去向不同的名字解析到**同一个地址**时，网关分不清它们的连接：这个地址按列表里**更靠前**的规则走（分类链里更早的集合先命中），直到集合里的条目按 TTL 过期。这是确定的，测试里按这个行为写（`TestSharedAddressEarlierRuleWins`）；运行时不统计这种碰撞（没有便宜的办法从 SmartDNS 的写入里看出来，没有做）。另外，客户端不经网关解析、直接连地址时，只有地址规则和别的名字已经学到的地址起作用。一个后续任务会加按 SNI / Host 判断的转发器，届时有名字的 TCP 连接按 `Decide` 直接判断。

其它与列表语义不同、并在规则页 / 导入预览里逐条标出的地方：

- **关键词**：SmartDNS 不能按子串匹配（没有正则、没有通配）。面板的关键词规则沿用以前的做法：用已下载的 geosite 名单里含这个词的名字（按后缀）代替；名单之外含这个词的名字不会命中。导入的 `DOMAIN-KEYWORD` 只有在操作者接受这个替代后才能写入；规则集里的关键词条目不执行，计数显示。

  **关键词在嗅探关闭 / 开启时匹配什么。** 嗅探关闭：只有上面的近似（已下载名单里含这个词的名字，按后缀）；规则集里的关键词条目不执行。嗅探开启并真正生效：接管端口（默认 TCP 80、443）上读得到 TLS SNI 或 HTTP Host 的连接按子串匹配，规则集里的关键词条目也按子串执行；仍然近似的是 UDP（含 QUIC）、其它端口和读不到名字的连接（它们只有地址，关键词规则靠名单展开，规则集里的关键词条目不执行）。“真正生效”不是只看已保存的开关，而是后端算出的三态（`internal/api/keyword_state.go`）：`off`（开关关闭）；`on`（开关开启，网关文件与已保存的拓扑一致即安装的是当前设置，转发服务在运行且就绪，路径诊断为可用或降级即默认目标可用）；`pending`（开关开启但尚未按当前设置安装、没有运行、路径失败或未自检，或安装状态、运行状态读不到——读不到一律按 `pending`，不会当作已生效）。三种说明只有一处措辞（`ordered.KeywordNote`、`ordered.KeywordEntriesNote`），规则列表的逐条说明、新建/编辑抽屉的帮助（`GET /api/rules/analysis` 的 `keyword_state`、`keyword_note`、每行的 `keyword_note`、`keywords_note`）、规则集预览里的关键词条目说明和导入分析都取自它；规则集里存下来的说明按关闭状态写，显示时按当前状态改写。只改显示文字，不改规则求值和生成的文件。
- **AAAA 的标志位会继承**：SmartDNS 的 `-address #6` / `-address -6` 按位或，上级名字的标志也作用到下级。规则不返回 AAAA 时（默认）这只会让某些名字少拿 AAAA（安全方向），不会让该隧道的名字拿到 AAAA。
- **没有隧道内解析器的出口**（现在只剩没有接上隧道的出口；选了 Mesh 绕行的纯 IPv6 出口有 Mesh 腿，也就有隧道解析器）：它的规则以 `-address #`（SOA）实现，这个标志同样继承给列表里更早、但名字更具体的规则——这种组合目前没有拦下，是已知缺口。
- 规则集的 IPv6 地址条目、IPv6 CIDR 规则：去向不能承载 IPv6（`FilterAAAA`）时不写 IPv6 集合（与以前的 CIDR 规则相同），这些 IPv6 目的地落到后面的规则。

### 去向的语义

- **直连**：名字由国内解析器（DoT）解析，地址写进这条规则自己的集合 `r<n>`，在规则的位置打国内标记，经 ROS 直出；AAAA 照常返回（与内置国内名单相同）。只作用于规则（或内置国内名单）明确列出的名字：其它名字一律由出口的解析器解析、走隧道，**即使出口给的是中国地址**——唯一的例外是没有任何规则命中的名字，它的地址在中国时按 chnroute 直连（就是 mihomo 列表末尾 `GEOIP,CN,DIRECT` 在 `MATCH` 之前的效果）。`unlisted_domestic_dns`（dns-split）照旧是可选设置，默认关闭，导入不依赖它。
- **拒绝**：名字照常由默认组的解析器解析（只给 IPv4，`-address #6`，免得客户端拿 IPv6 从本地宽带绕过），地址进这条规则的集合并打标记 `0x65`；兜底表（`inet meridian_guard` 的 forward 链，在最后的丢弃之前）对这个标记的 TCP 回 RST、其它协议回 ICMP 端口不可达。客户端看到的是「连接被拒绝」，立即失败，不是超时。没有任何路由规则认识 `0x65`，被拒绝之前它不会离开网关。只有用到拒绝的拓扑才生成这两行。
- **服务组已移除**（原 `service_groups` / 规则的 `target_service`）。规则直接指向地区组、出口、直连或拒绝。旧拓扑在解码时（`model.Topology.UnmarshalJSON`，存储、`PUT /api/topology`、导入都经过它）迁移：每条经服务组的规则取该服务组当时的指向，服务组名记进 `mihomo_group`；服务组连同 `select` / `probes` 丢弃，之后不再写出；导入映射里 `service:` 开头的值删除。服务组缺失或没有指向的规则无法迁移，解码失败并指出规则名（这种文档以前也通不过校验）。迁移幂等；示例拓扑逐条规则的出口（mark）和整个编译结果在迁移前后相同（`TestLegacyServiceGroupsMigrateWithSameExits`）。`/api/service-groups*` 返回 410；按原策略组批量改指向用 `POST /api/rules/retarget`（`{"mihomo_group": "…", "target": "group:<id>" | "exit:<id>" | "direct" | "reject"}`），同时把选择记进导入映射，下次导入同一份配置按它解析。

### QUIC 开关

导入时只认两种写法（忽略空格，国家 / 分类不分大小写）：`AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT` 和同样以 `GEOIP,CN` 结尾的那条；它们变成列表里的一行 `quic_reject`。网关在 `inet meridian` 里加一条 forward 链：来自局域网和远程接入（`mra`）、带出口或地区组标记的 UDP 443 回 ICMP 端口不可达（客户端立即改用 TCP）；**这一行之上的规则的集合豁免**（地址在它们的集合里就放行），国内标记的流量不受影响。所以 mihomo 里有意排在 QUIC 规则之前的规则（例如 AI）在网关上同样不被拒绝。与 mihomo 的差别（预览里要求接受）：mihomo 按「不是国内」判断，网关按「走隧道」判断——开关之下指向直连的规则不拒绝 UDP 443；开关之下指向代理、但名字在 geosite cn 里或地址在中国的连接会被拒绝。其它逻辑规则一律不支持。

### 规则集

`rule_sets`：`{id, name, url, format, behavior, source, interval_sec, allow_lan, origin, exclude}`，由 `/api/rule-sets` 管理（拓扑保存保留这个块）。视图另带 `auth`（订阅认证的元数据 `{kind, secret_set, updated_at}` 或 `null`，从不带内容），有排除条目时另带 `exclusions`（见下面「规则集的排除条目」）。

- 格式（先看内容，再看扩展名；可手动指定）：Clash/mihomo 的 yaml（`payload:`，classical / domain / ipcidr）和 text 形式；Surge `.list`（`TYPE,值[,选项…]`，`#` 与 `//` 注释，附带的策略字段忽略并计数）；Surge DOMAIN-SET（`example.com` 只是这个名字，`.example.com` 是名字和下级）。domain 行为里 `+.x` = 名字和下级，`.x` = 只有下级（SmartDNS `*.x`），`x` = 只有这个名字，`*.x`（恰好一级）不能表达，计为不支持。Surge `DOMAIN-WILDCARD,*.x` = 所有下级，其它通配不支持。`.mrs` 二进制规则集识别出来并拒绝。BOM、CRLF、大小写混用的类型都接受。
- 能执行的：`DOMAIN`、`DOMAIN-SUFFIX`、子域名条目、`IP-CIDR`/`IP-CIDR6`（`no-resolve` 计数，没有影响）。`DOMAIN-KEYWORD` 保留但不执行。其它（`PROCESS-NAME`、`USER-AGENT`、`URL-REGEX`、`IP-ASN`、`GEOIP`、端口、逻辑规则……）按类型计数；不会让整个规则集失败，但规则页和预览显示「只部分生效」和数字。
- 下载在面板里进行（`internal/ruleset`）：URL 里能找到 GitHub 原始文件时（也包括 `https://<加速前缀>/https://raw.githubusercontent.com/…` 这种），按名单的下载策略试 jsDelivr（国内源）/ raw.githubusercontent.com（海外源），最后试原 URL；`source: url` 只用原 URL。上限 16 MiB、50 万条、60 秒；不用环境里的代理；最多 5 次重定向且只允许 http/https；**每次建立连接时**检查目的地址（所以重定向后的地址也查）：拒绝回环、链路本地、组播、未指定、本机任何接口地址，以及私网（RFC 1918、100.64/10、fc00::/7）——后者在规则集打开 `allow_lan` 时允许。**网关自身和内部的地址即使打开 `allow_lan` 也拒绝**（`gatewayDeny`，从拓扑算出：网关的局域网地址、每条隧道链路的地址和自动分配的 /30、/64 块、中转网段 `transit_v4/v6_prefix`、远程接入地址池）；局域网里别的主机（例如放名单的 NAS）仍由 `allow_lan` 决定。导入 mihomo 时的预下载同样带这份拒绝列表、不允许局域网源。内容只当数据解析，从不执行。测试：`TestFetchRedirectToPrivateRefused`、`TestAddrAllowedDeny`、`TestGatewayDeny`。
- 启用：解析成功才把规范化内容（`ordered.MarshalEntries`）原子写到 `/var/lib/meridian/geosite/rulesets/<id>.txt`（宿主共享目录），然后请宿主执行器做一次 `rules`（只重做 derive、装载 CIDR 批次、按需重启 SmartDNS，不下载）。失败时旧版本不动。新版本里网关执行不了的条目比当前版本多（关键词或不支持的条目增多）时**暂缓**，状态显示原因，要操作者「启用暂缓的版本」。按 `interval_sec`（默认 24 小时）自动更新：每 10 分钟检查一次，上次尝试（成功或失败）距今超过间隔的就下载（`dueRuleSets`，`TestDueRuleSets`）。被规则使用的规则集不能删除（返回使用它的规则，`TestRuleSetLifecycle`）。

#### 规则集的排除条目

订阅一个公开规则集、但其中个别条目（例如两个很宽的后缀）不该跟着这条规则走时，在规则集上写**排除条目**（`exclude`），不必放弃订阅、改写成手工规则。

- **写法**：和规则集条目一样，一行一条，经同一个解析器（`ruleset.ParseExclusions`）：任何规则集都可以写带类型的行（`DOMAIN-SUFFIX,example.com`、`DOMAIN,a.example.com`、`DOMAIN-WILDCARD,*.example.com`、`DOMAIN-KEYWORD,ads`、`IP-CIDR,198.51.100.0/24`、`IP-CIDR6,…`）；域名或地址列表格式的规则集还可以写它自己的写法（Clash domain 的 `+.x` / `.x` / `x`，Surge DOMAIN-SET 的 `.x` / `x`，ipcidr 的地址段）。格式按规则集指定的格式，没有指定就用上次下载识别出的格式；两者都没有时只接受带类型的行和地址段（`.x` 在不同格式里意思不同）。规则集自己的解析器会拒绝或不执行的写法（错误的名字、`*.x` 恰好一级、其它通配、`PROCESS-NAME` 等）、这种格式不会有的条目类型（domain 列表里的关键词或地址段、ipcidr 列表里的域名、DOMAIN-SET 里的子域名通配）都被拒绝，接口按行返回（`422 {code: "bad_exclude", lines: [{line, text, error}]}`），规则页逐行显示。保存为统一的带类型写法（`ruleset.ExclusionLine`），最多 500 条；拓扑校验拒绝不是这种写法的条目。
- **语义**（`internal/ordered/exclude.go`）：排除条目把它**覆盖**的条目（它匹配的名字或地址包含这条条目匹配的全部）从规则集的有效条目里去掉；地址段排除还把它的地址从包含它的地址段条目里挖掉。只经被去掉的条目（或被挖掉的地址）才命中这个规则集的名字或地址，不再命中这条规则，落到后面的规则（以及国内名单、中国地址、默认组）。逐项：
  - 排除等于某条条目：去掉它。
  - 排除比条目宽（后缀 `example.com`）：去掉它下面的所有条目——完整域名 `a.example.com`、后缀 `b.example.com`、子域名通配 `*.c.example.com`；`example.com` 下面的名字不再经这个规则集的任何条目命中（关键词条目除外，见下）。后面的规则集逐条列出的名字（例如 `x.example.com`）照常按那条规则走。
  - 排除比条目窄（条目是后缀 `example.com`，排除 `a.example.com`）：**不提供**。网关的解析器（SmartDNS）按最长后缀选规则，无法在一个后缀条目里挖掉一部分、让它落到后面的规则或默认组；只在嗅探路径上生效会让两条路径不一致。所以这种排除什么都不去掉：添加时被拒绝（错误里写明覆盖它的条目和替代做法：排除整个后缀，或在这条规则之前加一条规则指定这些名字的去向）；规则集更新后才变成这样的，预览里标出「仍被某条条目覆盖」。子域名通配排除 `*.example.com` 对后缀条目 `example.com` 同样如此。
  - 关键词排除 `ads`：去掉值里含这个词的域名条目（它们匹配的名字都含这个词）和含这个词的关键词条目；不去掉剩下的后缀条目下面恰好含这个词的名字。
  - 关键词条目（例如 `DOMAIN-KEYWORD,exam`）不会被域名排除去掉（它还匹配别处的名字）。嗅探路径按子串执行关键词条目，解析器路径不执行（见上面「关键词」）——这是关键词条目本来就有的差别，排除没有增加新的差别：域名排除被关键词条目覆盖时（排除 `example.com`、条目 `exam`），预览标出「仍被覆盖」。
  - 地址段：排除包含或等于条目时去掉条目；排除在条目里面时只挖掉排除的部分（`198.51.100.0/24` 排除 `198.51.100.0/26` 后是 `198.51.100.64/26` 和 `198.51.100.128/25`），每条路径都精确。
  - 域名排除不影响地址段条目，地址段排除不影响域名条目：名字被排除、但地址落在这个规则集的地址段里的连接仍命中它（这是「去掉条目」的定义，不是按连接取反）。
  - 排除只作用于规则集的内容，不作用于这条规则自己的显式域名（`domains`）。
- **唯一的推导**：`ordered.ApplyExclusions(内容, 排除)` 是有效条目的唯一来源（被覆盖的条目去掉，地址段按排除切开）。编译器把排除条目写进有序来源清单 `order.conf`（`ruleset <id>` 下面的 `exclude-<种类> <值>` 行）和 `decide.json`（规则集来源的 `exclude` 字段），二者都由 `compile.RuleSetExclusions` 从拓扑取得；网关上的 `meridian lists-derive`（`ordered.Derive`：解析器的 domain-set 和 nft 地址集合 `r<n>c`/`r<n>c6`）、转发服务（`ordered.LoadSnapshot`）、面板的规则测试和遮蔽分析（`refList`）、导入预览都调用它。没有排除条目时两份文件与以前逐字节相同。排除条目是安装清单里的数据：改了之后要安装才在网关上生效（宿主不需要新能力，`lists-derive` 读的就是安装写下的清单）；预览和规则测试立刻按新的排除计算。旧版本的 `meridian` 读到带排除行的清单会拒绝（未知行），`meridian-up.sh` 因此在打开转发之前停止——失败关闭。
- **证明**：`ordered.Reference` 带 `Rule.Exclude` 时逐字执行上面的定义；`TestApplyExclusionsEqualsDefinition`（生成的列表，排除与条目相等、更宽、更窄、关键词、地址段，规则互相遮蔽）证明定义 = `ApplyExclusions` = `Compile/Decide` = `decide.json` = 网关模型（清单的排除行 → `Derive` → SmartDNS 最长后缀模型 → nft 分类链）；`TestExclusionFallsThroughToLaterRuleSet` 是上面的动机场景；`TestCoversAgreesWithMatches` 用名字全集核对「覆盖」；`TestRuleSetExclusionsRenderedMatchReference` 对真实编译出的网关文件做同样的比较；`TestRuleSetExclusionsCompileCheck` 编译 24 条规则集规则（越过集合重名的门槛）并检查每个集合只声明一次、清单与解析器配置和 nft 声明的集合一致、清单与 `decide.json` 带同样的规则集和排除、转发服务接受编出的一对、没有排除的规则集编出的文件不变；`TestRuleSetExclusions`（接口：逐行拒绝、更窄的排除被拒、预览数字、更新保留、更新失败保留旧版、规则测试）。
- **预览**（规则集视图的 `exclusions`）：`{checked, fetched, effective, removed, stale, inside, items: [{line, removed, trimmed, inside, stale, notice}]}`——当前生效内容的条目数、排除后的有效条目数（切开的地址段可能多于一条）、每条排除去掉 / 切开了几条；`stale` 表示当前内容里已经没有与它对应的条目（提示，不是错误，排除照样保留）。还没下载过时 `checked: false`，只列出排除条目。
- **订阅更新**：排除属于规则集的定义（拓扑），下载只换内容文件，所以更新后排除照样生效；失败保留旧版、原子启用、暂缓机制都不变。重新导入 mihomo 配置时已有规则集的排除保留。下载的安全边界（SSRF 规则、认证、大小限制）没有改变。

### 规则集合的订阅认证

私有的规则集 URL 需要认证时，认证**不放在 URL 里**：

- 存储的 URL 不能带用户信息（`https://user:pw@…`），也不能带名字像秘密的查询参数（名字里含 token、key、secret、pass、pwd、auth、sig、credential、session、ticket、otp、code，不分大小写；`ruleset.SecretQueryKey`）。新建 / 修改时这样的 URL 返回 422 `url_has_secret`，错误不回显 URL；校验（`bad_rule_set`）同样拒绝。判断是保守的：名字恰好含这些字样的公开参数也要放进认证。
- 认证三种：`bearer`（`Authorization: Bearer …`）、`basic`（HTTP Basic）、`query`（`k=v&k2=v2`，下载时附加到 URL）。`POST /api/rule-sets` 和 `PATCH` 可带 `auth`，或用 `PUT /api/rule-sets/{id}/auth`、`DELETE /api/rule-sets/{id}/auth`。内容存在受限凭据存储（`credentials.SetRuleSetAuth`，0600 文件、只写），不进拓扑、快照、导出、状态、错误和日志。
- 只通过 https、只发给配置的 URL 的**同一来源**（协议、主机、端口）：按名单下载策略生成的镜像候选（jsDelivr 等）不带认证；重定向到别的来源时去掉 `Authorization` 头（Go 默认还会发给子域名，这里不发）。`PATCH` 把 URL 改到另一个来源而没有同时给新认证时，已存的认证被删除——只写的秘密不能跟着 URL 被送到编辑者选的主机。删除规则集同时删除认证。
- 下载出错的文字一律经 `ruleset.Redact`（去掉用户信息，查询串换成 `?…`）并替换掉认证的值；状态里的来源 URL、候选 URL 同样处理（旧版本写下的状态读出时也处理）。
- 迁移：启动时（以及 `PUT /api/topology` 之后）把旧拓扑里 URL 带的用户信息 / 秘密参数移进凭据存储，拓扑只留干净的 URL（`migrateRuleSetSecrets`，可重复）。从 mihomo 导入时 `rule-providers` 的 URL 也这样拆开：预览只显示干净的 URL 和认证类型，确认时写入凭据存储。拓扑应答（`store.Redact`）对仍带秘密的 URL 只显示去掉秘密的形式。
- 已知不足：迁移之前数据库里旧值所在的页、以前的拓扑快照可能还留着旧 URL；面板不重写历史。
- 测试：`TestSplitSecretAndRedact`、`TestFetchAuthOriginOnly`、`TestRuleSetAuthLifecycle`、`TestRuleSetAuthWriteOnly`、`TestRuleSetSecretURLMigration`、`TestImportProviderURLSecret`。

### 导入 mihomo

见[从 mihomo 导入](mihomo-import.md)。实现：`internal/mihomo`（YAML 用 `gopkg.in/yaml.v3`，只解码 `rules`、`rule-providers`、`proxy-groups` 三个键；其它键的树在解析后丢弃；YAML 错误只返回行号，不返回那一行的内容）。策略按「策略组 → 当前选中 → 地区选择组 → 当前选中 → 线路组」解析，第一个在映射表里有对应的名字为止；规则直接写成解析到的地区组（或出口），原策略组名记在 `mihomo_group`，不生成服务组。解析不到时，策略组本身（和它最终停在的线路）列进映射表，由操作者选地区组。预览的每个标记带机器可读的 `class`：`address_only`（只因为按地址分类而不精确：关键词、规则集里的关键词、QUIC 的逐条豁免）、`unsupported`（任何方式都不能执行）、`data`（规则集还没下载）、`mapping`（去向没有对应）、`info`；`Options.NameAware`（今天总是 false）打开时 `address_only` 不再阻止确认。

### 迁移与现有拓扑

- 规则顺序：见上。一对规则以前由 SmartDNS 选更长的名字、现在由列表里更早的规则决定、而且去向不同的情况（例如手工后缀 `example.com` 指向 A 在 `a.example.com` 指向 B 之前），`GET /api/rules/analysis` 对后面那条给出 `legacy_lost`（个数）和 `legacy_lost_to`（接走它们的规则），规则页「遮蔽」列显示「升级后变化」（`ordered.RuleAnalysis.LegacyLost`，`TestAnalyzeLegacyDifference` 用最长名字解释器对照）。面板不自动调整顺序。只比较名字条目；关键词和内置国内名单之间的变化不计。
- 规则页显示 `upgrade_notes`：苹果和联网检测名字不再内置直连；靠前的规则优先于更长的后缀；`unlisted_domestic_dns` 默认关闭且不被依赖（`TestUnlistedDomesticDNSDefaultOff`）。
- 规则命中的名字不会进入直连集合：派生后的 `gs_cn` 去掉了规则覆盖的名字，分类链里规则的集合在 `direct4` 和 `chnroute` 之前，所以即使出口的解析器回答中国地址，连接仍打规则的标记（`TestProxyRuleNameNeverDirect`，在编译出的文件上判断）。
- 去掉内置 Apple 直连。现有网关的生成结果变化的文件：`nodes/gw/etc/smartdns/smartdns.conf`（域名规则改成派生的 domain-set、没有 `gs_apple`）、`nodes/gw/usr/local/sbin/meridian-up.sh`（派生步骤）、`nodes/gw/usr/local/sbin/meridian-update-geosite.sh`（不再下载 `apple`，除非有规则用它）、`nodes/gw/usr/local/sbin/meridian-verify.sh`（AAAA 测试名的国内判断看派生的 `gs_cn`），新增 `nodes/gw/etc/meridian/rules/order.conf` 和 `decide.json`。nft、路由、其他节点不变。没有使用新功能的拓扑，nft 分类链和兜底表逐字不变。
- 苹果的联网检测名字（`captive.apple.com` 等）以前随 `apple` 名单直连，现在没有规则时走默认组。需要直连时加一条指向直连的规则。
- 主机上的 `meridian` 二进制必须是这一版（`meridian-up.sh` 检查 `meridian-lists-derive-ready`，旧版在打开转发之前失败）。

以上只有仓库里的自动化回归和本机 Docker 里对固定版本 SmartDNS、nft 的测试，**没有在任何真实网关上执行过，也没有用过操作者真实的 mihomo 配置**。

### 按域名嗅探的转发核心（`meridian sniff`，`internal/sniff`）

这一节描述转发核心本身（子命令、解析、决定、在目标处重新解析、限制、状态）。它怎样接进网关的数据面（接管、标记、失败关闭、安装、更新、面板）见下一节「按域名嗅探的转发（受管数据面）」。设置关闭时网关的数据面与之前完全相同，只按地址分类。

**分工。** 能从连接本身读到名字的 TCP 由它按名字决定；读不到名字的 TCP 按原目的地址决定；UDP（包括 QUIC）不经过它，继续由分类链按地址集合打标记。它只选择标记：打上标记之后的隧道、中继分担、主备枢纽和出口切换仍由内核数据面负责。

**解析（按公开规范独立实现，没有参照或复制 mihomo、sing-box 或 SmartDNS 的代码）。** TLS：RFC 8446 §5.1 的记录层，ClientHello 可以跨多条握手记录、也可以跨多个 TCP 段到达，在 ClientHello 完整之前出现别的记录类型、长度为 0 或超过 2^14 的记录都算畸形；§4.1.2 的 ClientHello 和 §4.2 的扩展（同一扩展出现两次算畸形），RFC 6066 的 `server_name`（两个 `host_name` 算畸形，地址字面量不算名字）。HTTP/1：RFC 9112 的请求行和头部字段（obs-fold、冒号前的空白、多个 `Host` 都算畸形；可以接受单独的 LF），absolute-form 和 CONNECT 的 authority 优先于 `Host`（§3.2.2），`Host` 里的端口去掉，地址字面量不算名字。`PRI * HTTP/2.0`（h2c 直连前言）没有可读的名字。用标准库 TLS 客户端写出的 ClientHello 做了交叉核对（`TestTLSStdlibClientHello`）。

**ECH。** 带 `encrypted_client_hello`（0xfe0d，以及旧的 0xffce）的 ClientHello，明文里的 `server_name` 是外层名字：真用 ECH 时它是 ECH 提供方的公共名字，不是用户要访问的站点；客户端只是发 GREASE ECH 扩展时它又恰好是真名字。线上无法区分这两种情况（这正是 ECH 的目的）。子命令不带参数时按原目的地址决定，外层名字只记在 `Result.OuterName` 里。`--ech-outer` 改成按外层名字决定，`--ech-public-names a,b` 列出已知的 ECH 公共名字：外层名字是其中之一（或在它之下）时仍按地址决定（近期决策里记为 `ech_public`），否则按外层名字（记为 `ech_outer`）。网关安装用的是 `--ech-outer --ech-public-names cloudflare-ech.com`（设置 `sniff.ech_public_names` 可改），理由：Chrome、Firefox 等在没有 ECH 配置时也发 GREASE ECH，只按地址会让这些浏览器的大部分 TLS 连接绕开按名字的判断。**剩余误差**：真启用 ECH、而提供方的公共名字不在列表里的连接，会按那个公共名字匹配规则（通常落到默认组），不是按用户访问的站点。

**读不到名字时。** 没有 SNI、SNI 不是主机名、ECH（默认）、既不是 TLS 也不是 HTTP/1、畸形、超过读取上限、嗅探期限内数据不够（`timeout`）或一个字节都没有（`no_data`，服务器先说话的协议）、客户端半关闭（`eof`）、目的端口不在 `--sniff-ports` 里：都按原目的地址求值，连接原目的地址，**已经读到的字节一个不少地先发给上游**。

**决定。** 与面板「这个域名/地址会命中哪条规则」和编译器对照用的是同一个求值：`ordered.LoadSnapshot` 读安装写下的 `decide.json`，`Compiled.Decide(Request{Name, Addr: 原目的地址, Proto: "tcp", Port, Source: 客户端地址, SourceMAC})`，结果等于参考解释器 `ordered.Reference`（`TestDecisionsMatchReference`：生成的规则列表，含完整域名、后缀、子域名、关键词、CIDR、GEOIP,CN、按地址和按 MAC 的设备规则、尾部，约 15 万个决定逐一相等，另有 90 条真实转发的连接记录与参考一致）。关键词规则在这里真正按子串执行（`decide.json` 里关键词规则现在带着关键词本身；按地址的路径只能靠名单展开）。`Decision.By` 说明是什么决定的：`name`（名字条目、内置国内名单）、`addr`（CIDR、GEOIP,CN、中国地址）、`default`（没有命中）。

**设备规则与 MAC。** 以前 `LoadSnapshot` 跳过按 MAC 限定的规则，按名字决定的进程会把这台设备的规则当作不存在。现在保留它们：`Rule.SourceMAC` 与 nft 的 `ether saddr` 语义一致（同时写了地址时两者都要满足；不知道 MAC 的客户端——远程接入、没有邻居项——不命中 MAC 规则，正如三层包不命中 `ether saddr`）。客户端地址取自被接管连接的源地址（TPROXY 和 REDIRECT 都保留它）；MAC 取自内核邻居表（rtnetlink，只认 `--neigh-if` 列出的接口上可用状态的项，最多 1 秒的缓存，读不到时视为不知道）。信任程度与 `ether saddr` 相同：同时伪造别人地址和 MAC 的设备两条路径都骗得过；只伪造地址时邻居项会来回变，那段时间里的连接可能用到另一台设备的规则——设备规则是分流偏好，不是访问控制。不可解析的源地址或 MAC 让整份快照载入失败（以前不可解析的源地址会让设备规则变成对所有客户端生效）。

**在目标处重新解析。** 按名字决定（`By` 是 `name`，或 `default` 且有名字）时，用目标自己的解析器、带目标的标记查询这个名字，再连接查到的地址：出口用 `fd66::54:<i>`、地区组用 `fd66::53:<k>`、直连用国内解析器，具体地址和查询标记由目标文件给出（见下）。先问与客户端同族的记录（目标不承载 IPv6 时只问 A，IPv6 客户端经 IPv4 连出），没有地址时再问目标允许的另一族。同一目标的多个解析器按顺序问，只有失败或 SERVFAIL 才问下一个；缓存按「目标名 + 查询标记 + 解析器列表」隔离，不同目标的答案互不复用，重载后不再存在或变了解析器的目标的缓存被丢弃；NXDOMAIN 和空回答缓存 10 秒，失败不缓存，TTL 限制在 5 秒到 10 分钟。解析时不问别的目标的解析器、不问国内解析器。决定本身是按地址作出的（`By` 是 `addr`，例如列表里更早的 CIDR 规则命中了原目的地址）时不解析，连接原目的地址。名字解析不到时见下一段。

**名字解析不到时按地址处理。** 目标的解析器对这个名字给不出地址——名字不存在（NXDOMAIN）、没有可用地址族的地址、所有解析器都失败、或整个查询超过时限——时，连接**不再被重置**，而是按「读不到名字」处理：用地址分类器给这条连接的标记（下一节第 4 步，套接字上的分类标记）和**原目的地址**，与嗅探关闭时这条连接的结果相同。近期决策里记为 `why: name_unresolved`，`error` 和 `name_rule.error` 写原因（`nxdomain`、`no_address`、`resolver_failed`、`timeout`），`name_rule` 保留名字命中的规则和目标（只供诊断，不采用）；计数器 `name_unresolved_<原因>`、`decided_by_address_name_unresolved`。`resolver_failed` 和 `timeout` 还记在名字那个目标的「解析失败」计数里（那是目标的路径问题）；NXDOMAIN 和空回答是解析器正常作答，不算。

- **为什么这不是绕过规则的通道**：回退后用的是内核地址分类的结果，不是名字规则给的去向。编造一个不存在的名字（例如放在直连规则下）不能把连接引到直连：它只会得到这个目的地址本来就会得到的目标；目的地址本来就被分类成直连的，嗅探关闭时也是直连。名字规则的**拒绝**在解析之前就判定了，存在或不存在的名字都照样拒绝；分类器对这个地址的拒绝在回退里同样生效。测试：`TestFallbackNotABypass`（不存在的名字放在直连规则下 + 境外地址 → 默认组，从不直连；不存在的名字 + 分类器判直连的地址 → 直连；存在的名字照旧在目标解析器解析、连接解析到的地址；拒绝规则先于解析；回退时套接字标记不可信 → 下面「接管位缺失」的规则），`TestResolveFailureFallsBackByAddress`，命名空间测试 `TestNetnsSniffFallback`。
- **时限**：一个名字的整次查询（目标的所有解析器、两个地址族）共享 `LookupBudget` = 3 秒（`DefaultLookupBudget`：一个超时的解析器 2 秒，再给下一个解析器或另一族 1 秒）；单次查询仍受 `--resolve-timeout 2s` 限制。时限用完时进行中的查询被放弃（它的套接字随上下文关闭），结果不缓存；正在等同一个查询的其它连接拿到同样的「超时」并各自按地址处理，它们自己的时限也一样约束它们。所以名字解析最多让客户端多等 3 秒，再加上游连接的 `--dial-timeout`。测试：`TestLookupBudget`（两个永不回答的解析器、200 毫秒时限：三条并发连接都在时限后按地址转发；时限更大而单次查询超时时记为 `resolver_failed`）、`TestResolverBudget`。
- **仍然失败的情况**：目标根本没有解析器（没有隧道解析地址的出口，`ErrNoResolvers`）时结果仍是 `resolve_failed`（RST）：那条规则的每个名字都会按地址走，等于规则不存在，这不是「这个名字解析不到」。

**客户端从别处得到的地址。** 名字决定目标 X、而客户端连接的地址来自别处（自己的加密 DNS、缓存、写死的地址）时，转发核心连接 X 的解析器返回的地址，不是客户端的地址。好处：出口看到的是从出口一侧解析的、就近的地址，共用 CDN 地址的两个站点各走各的目标，客户端不经网关 DNS 也按名字分流。代价：如果客户端特意连某个地址（固定的节点、测试某台服务器、DNS 污染之外另有用途的 IP），它到的可能是另一台服务器；SNI 与证书仍由客户端校验，所以名字对得上的服务器才能完成握手，结果最多是连到同名服务的另一台机器。

**限制与默认值。** 每条连接决定前最多读 `--max-sniff-bytes 16384` 字节（声明长度放不下时立即判为超限，不等数据）；嗅探期限 `--sniff-timeout 1s`（整个分片 ClientHello 或 HTTP 头部都要在这段时间内到达；服务器先说话的协议因此晚 1 秒连接，安装可用 `--sniff-ports` 只嗅探 80/443 等）；上游连接 `--dial-timeout 10s`（最多试 4 个地址）；单次查询 `--resolve-timeout 2s`；两个方向都没有数据 `--idle-timeout 2h` 后关闭（0 表示不限）；同时最多 `--max-conns 2048` 条、每个客户端地址最多 `--max-per-source 512` 条，超出的立即 RST；转发缓冲每方向 16 KiB（池化）。直接连到监听端口本身（会形成环）、未指定、组播和广播目的地址直接 RST。

**规则切换与健康。** 规则快照和目标文件作为一对原子替换（`Server.Install`）：正在决定的连接用它开始时的那一对，下一条用新的，任何时刻都有规则。载入时核对：快照里能决定的每个目标（拒绝除外）都在目标文件里、标记相同、至少有一个解析器，标记不重复；不一致时整对不生效，旧规则继续用，`last_reload_error` 说明原因。启动时第一次载入失败则进程以 `meridian-sniff-failed` 退出，不会以无规则状态监听。`SIGHUP` 重新读文件。`--status-socket`（Unix 套接字，0666，只回答对端 uid 0，见下一节「状态套接字的访问」）提供 `GET /v1/health`（就绪、代数、规则数、目标、是否有 MAC 规则、是否能查 MAC、计数器）和 `GET /v1/recent`（最近结束的 `--recent 256` 条连接的最终记录，只在内存里：源地址、原目的地址、协议、是否按名字、读不到名字的原因、命中的规则、目标、标记、上游地址、结果、结束方式和原因、时长、双向字节数；另附 `active`：正在转发的连接，最多 100 条，和总数 `active_total`；见下文「连接结果」）。**默认不记录名字**；`--record-names` 打开后名字进这份内存记录和下面的连接日志（「设备连接日志」）。系统日志和每 `--stats-interval 10m` 一行的计数器从不含名字。

**命令行。** `meridian sniff --listen <地址:端口> --mode tproxy|redirect --snapshot /etc/meridian/rules/decide.json --targets <目标文件> [--lists-dir /var/lib/meridian] [--status-socket …] [--neigh-if <局域网口>] [--sniff-ports 80,443] …`。就绪行以 `meridian-sniff-ready` 开头。目标文件：

```json
{"version": 1, "targets": [
  {"target": "direct",   "mark": 100, "resolvers": ["192.0.2.53:53"], "ipv6": true},
  {"target": "group:hk", "mark": 266, "resolvers": ["[fd66::53:a]:53"]},
  {"target": "exit:jp",  "mark": 258, "resolvers": ["[fd66::54:2]:53"], "dns_mark": 0},
  {"target": "reject",   "mark": 101, "reject": true}
]}
```

`dns_mark` 省略时等于 `mark`；组的解析地址需要组标记（`transit_snat` 认它），出口解析地址在网关的 SmartDNS 里是不带标记问的，安装要按实际路由选择。

**留给接管与安装的接口。** `--mode tproxy` 时监听套接字设 `IP_TRANSPARENT`/`IPV6_TRANSPARENT`，原目的地址是连接的本地地址（`OrigDstLocal`）；`--mode redirect` 时用 `SO_ORIGINAL_DST`（`OrigDstRedirect`）。出站套接字带 `SO_MARK`（需要 `CAP_NET_ADMIN`；非 Linux 上非零标记一律失败，不会无标记发出）。转发核心对读不到名字的连接自己按地址求值，但这个求值看不到 SmartDNS 运行时写进各规则集合的地址（按名字学到的地址），所以「名字规则的站点 + 读不到名字」的连接会落到 CIDR/中国地址/默认组，而不是分类链会给的那条规则。要与按地址的路径完全一致，安装让分类链先打标记、经 `net.ipv4.tcp_fwmark_accept` 把 SYN 的标记带到接受的套接字，子命令的 `--addr-mark-bit` 设置 `Server.AddrMark`（`MarkFromSocket`，用 `SocketMark` 读出）；标记不可用时的处理见下一节「接管位缺失」。

以上只有单元测试、回环上的转发测试和本机 Docker 里（特权容器、无网络）对 `SO_MARK`、透明监听、邻居表读取和 nft redirect 后 `SO_ORIGINAL_DST` 的测试（`TestLinuxSocketOptions`，需 `MERIDIAN_NETNS_TEST=1` 和 root），**没有在任何真实网关上运行过**。

### 按域名嗅探的转发（受管数据面，设置 `sniff`）

**设置。** 拓扑设置 `settings.sniff = {enabled, ports, ech_public_names, record_names}`，默认关闭；端口默认 80、443（最多 16 个，22、53、853 和转发服务自己的端口 5358 被拒绝），ECH 公共名字默认 `cloudflare-ech.com`，记录名字默认关闭。关闭（或缺省）时编译出的每个文件与没有这个设置时逐字节相同（`TestSniffOffByteIdentical`，加上原有的 golden 测试不变）。面板的 `PUT /api/sniff` 保存它；整份拓扑保存不会改动它（与远程接入一样由自己的接口管理：请求里带了不同的值就整个拒绝，见「整份拓扑保存与独立资源」）。下一次安装到网关时生效。

**接管方式：REDIRECT。** 选它而不是 TPROXY 的原因：NAT 只对新连接求值，所以开启前已经建立的连接保持原来的路径、开启后被重定向的连接一直被重定向到它结束；被重定向的包变成发往本机的包，不再经过转发钩子，服务停止时内核直接回 RST，不可能落回按地址的转发路径。全部规则都在 `table inet meridian` 里，与其余规则同一个 nft 事务原子加载；兜底表 `inet meridian_guard` 和开机兜底文件一字不改。

**标记。** 新增一个位 `0x01000000`（接管位）：在 0x00ff0000（中继分担位）之上，与出口标记 0x101…、国内 0x64、拒绝 0x65、0x4d72 等都不重叠。链的顺序：

1. `prerouting`（mangle）：`classify` 之后、`relay_share` 之前跳到 `sniff_mark`：只对新连接的第一个 SYN（`ct state new`，`tcp flags` 只有 SYN），目的端口在接管列表里，已有分类标记，目的不是本机地址（`fib daddr type local`），不是私有、组播、局域网（含 IPv6 前缀）、远程接入地址池、`fc00::/7`、`fe80::/10`，也不是已知 DoH 地址的 443（那些仍由 `doh` 链拒绝）。满足时 `meta mark |= 0x01000000`，分类标记留在低位。带接管位的包不在出口标记范围里，所以不进 `relay_share`（不分配中继、不计数），也不匹配任何 `fwmark` 路由规则或兜底表的放行规则——即使重定向因故没有发生，兜底表也会把它丢掉。
2. `sniff_redirect`（nat，dstnat）：带接管位的包 `redirect to :5358`（v4、v6 各一条）。
3. `sniff_input`（input，优先级 -10）：发往 5358 但不是重定向来的连接丢弃（`ct status & dnat == 0`）；被重定向过、却不是这条连接第一个 SYN 的 SYN 补上接管位（计数 `sniff_resyn`，见下面「接管位缺失」）；其余本机收到的、不带接管位的 TCP 包把标记清零。原因见下一条。
4. 服务单元在启动前打开 `net.ipv4.tcp_fwmark_accept=1`、停止后关闭：被接受的套接字带着 SYN 的 fwmark（分类标记 | 接管位）。转发核心的 `--addr-mark-bit 0x1000000` 读出它（`MarkFromSocket`），去掉接管位，就是分类链给这条连接的标记；读不到名字的连接（以及名字解析不到、按地址处理的连接）直接用这个标记对应的目标——包括解析器运行时学进各规则集合的地址（转发核心自己的地址判断看不到这些集合），所以与按地址的路径完全一致。标记带接管位、却不在目标文件里：连接被重置（`unknown_mark`，失败关闭：多半是规则对与规则集来自不同代）。没有接管位或读不出标记：见下面「接管位缺失」。第 3 步的清零保证打开这个全局开关后，网关上其他监听（SSH、面板、DNS 的 TCP）接受的连接仍是标记 0，和以前一样。

**接管位缺失。** 真实网关上曾在十分钟内有 30 条没有名字的连接以 `unknown_mark` 被重置：分类器能设的每个标记都在目标表里，没有 SYN cookie、监听队列没有溢出，所以只能是接受的套接字上的标记缺接管位（或读取失败）而被当成 0。当时记录里没有原始标记，具体情形没有定位。现在的诊断与处理：

- 记录与计数区分三种情形：`mark_status` 为 `read_failed`（`SO_MARK` 读不出）、`without_bit`（读出了但缺接管位）、`unknown_target`（带接管位、不在目标表里，结果 `unknown_mark`）；正常时为 `ok`。`raw_mark` 是读到的原始标记（十六进制，读不出时没有），`dest` 是原目的地址，`why` 是没有名字的原因；计数器 `mark_ok`、`mark_without_bit`、`mark_read_failed`、`mark_unknown_target`，以及被拒绝时转发核心自己的地址判断会选什么：`mark_missing_own_view_tunnel`、`mark_missing_own_view_reject`、`mark_missing_own_view_direct`。名字仍只在打开记录名字时出现。
- **逐一审查过的成因**（内核：已接受套接字的标记来自创建请求套接字的那个 SYN——`tcp_conn_request` → `inet_request_mark`，监听套接字自己没有标记且 `tcp_fwmark_accept=1` 时取 `skb->mark`；子套接字在第三次握手时由 `inet_csk_clone_lock` 从请求套接字复制，之后的包不再改变它；快速打开（TFO）走同一条路径，而且网关的监听没有开 TFO）：

  | 情形 | 会不会缺接管位 | 复现 | 处理 |
  |---|---|---|---|
  | 回 SYN-ACK 之后客户端重发 SYN（SYN-ACK 在无线上丢失） | 重发的 SYN 不是 `ct state new`，`sniff_mark` 不给它接管位、`sniff_input` 清零；但请求套接字还在，标记取自第一个 SYN，**不缺** | 命名空间测试 M3（丢掉第一轮 SYN-ACK） | 无需修；重发的 SYN 现在也会被补上接管位 |
  | 同上，但请求套接字已经没了（SYN-ACK 重传用尽、转发服务在两次 SYN 之间重启） | **会缺**：新的请求套接字取自没有接管位的 SYN | 没有单独复现（与下一行同一机制） | `sniff_input` 补位（下一段） |
  | 客户端复用一个仍在连接跟踪里的 4 元组（旧连接的 FIN/RST 没被网关看到、条目还是 ESTABLISHED/FIN_WAIT 等，转发服务这边的套接字已经没了） | **会缺**：连接跟踪把新 SYN 当作「忽略的 SYN」放行，它不是 `ct state new`，没有接管位，却沿用旧条目的重定向到达 5358 | 命名空间测试 M2（丢掉旧连接的 FIN/RST、用 `ss -K` 去掉转发服务的套接字、从同一端口重连）：修之前这条连接会因缺接管位被拒绝（`mark_missing`），修之后走分类链给的目标 | **已修**：`sniff_input` 补位 |
  | 连接跟踪条目处于 TIME_WAIT/CLOSE 时复用 4 元组 | 不缺：连接跟踪删掉旧条目、新 SYN 是 `ct state new` | — | — |
  | IPv6 | 不缺：`tcp_fwmark_accept` 虽在 `net.ipv4` 下，`inet_request_mark` 对 IPv4、IPv6 共用；规则集的 `sniff_mark`、`sniff_redirect`、`sniff_input` 都覆盖两族 | `TestLinuxSocketOptions`（`::1` 上带位 / 不带位的 SYN）、命名空间测试 N5 | — |
  | `sniff_input` 清零与 TCP 复制标记的先后 | 不缺：清零只针对不带接管位的包，TCP 在全部 input 钩子之后才读 `skb->mark` | 命名空间测试（所有按地址的阶段） | — |
  | 远程接入接口 `mra` 进来的连接 | 不缺：`sniff_mark`、`sniff_redirect` 对局域网口和 `mra` 用同一个入口匹配 | `TestNetnsSniff` 阶段 E | — |
  | `tcp_fwmark_accept` 被别的东西关掉（单元只在启动前打开、停止后关闭） | **会缺**（所有套接字） | 命名空间测试 M1、`TestNetnsSniff` 阶段 C | 失败关闭（下面）；`meridian-verify.sh` 的 `sniff_fwmark_accept` 会报出来 |
  | SYN cookie、监听队列溢出 | 会缺 | 没有复现；真实网关的计数为 0 | 失败关闭（下面） |

  **补位**：`sniff_input` 在「非重定向连接丢弃」之后、「清零」之前多了一条：发往 5358、被重定向过（`ct status & dnat != 0`）、只带 SYN、缺接管位、带分类标记的包，标记改为 `(标记 & 0xfe00ffff) | 0x01000000`，计数 `sniff_resyn`。分类链对每个包都按原目的地址打标记（`prerouting` 的 mangle 在 dstnat 之前），所以这就是这个 SYN 自己的分类结果，中继位被清掉。到 5358 的 DNAT 只来自 `sniff_redirect`，所以这条规则碰不到别的连接。真实网关上 `nft list counter inet meridian sniff_resyn` 不为 0 就说明发生过上表里的情形。
- **没有可信分类时（缺接管位、读不出标记）连接被拒绝**（RST，结果 `mark_missing`，`error: classification_unconfirmed`），不论转发核心自己的地址判断（有序规则表不带名字：CIDR 规则、GEOIP,CN 与中国地址、默认组）给出隧道、直连还是拒绝。理由：自己的判断看不到解析器运行时学进各规则集合的地址——名字规则的回答（包括**拒绝规则**的：拒绝规则的名字由默认组解析、回答进它的集合，分类链据此拒绝）和国内名单的回答（`@direct4/6`）。对这种地址自己的判断会落到 CIDR / 中国地址 / 默认组：被拒绝规则学到的地址在它看来只是个默认组地址，被代理规则学到、却在中国地址表里的地址在它看来是直连。所以按它转发——哪怕只送进隧道——都可能绕过拒绝规则或把该走代理的流量直连出去，只有重置是安全的。不新增从转发核心读内核集合的机制。记录里保留自己的判断供诊断：规则序号和编号、目标、`by`、标记，`view: own_address_view` 表示这些字段是没有被采用的自己的判断，另有 `mark_status`、`raw_mark`。上面的补位让被重定向、却丢了接管位的 SYN 重新带上它，所以这种拒绝只剩 `tcp_fwmark_accept` 被关掉或 `SO_MARK` 确实读不出这两种情形。名字解析不到、按地址处理的连接遇到同样的标记缺失时也照此拒绝；标记可信时它的行为不变。测试：`TestMarkMissing`（自己的判断为默认组——模拟被拒绝规则学到的地址——、CIDR 隧道、直连、拒绝，缺接管位和读取失败各自都被拒绝、上游一次都没有拨；标记可信时照常转发）、`TestFallbackNotABypass` (d)、命名空间测试 `TestNetnsSniff` 阶段 C 与 `TestNetnsSniffFallback` 阶段 M1。

**转发服务自己的出站。** 服务以固定的 uid/gid 65530（账号 `meridian-sniff`，在 systemd 动态用户范围 61184–65519 之外、`nobody` 之下）运行，只有 `CAP_NET_ADMIN`（给套接字打 `SO_MARK`）。规则集按数字 uid 匹配（`meta skuid 65530`），所以加载规则集从不依赖账号数据库。账号见下面「单元与账号」。它的出站：

- `sniff_route`（route，只在中继分担时）：带出口标记的 TCP（目的端口不是 53）跳到 `relay_share`：与转发流量同一张按权重的分配表、同一组中继表；切到备用枢纽时（`share_apply`）新连接也跟着走。没有中继分担时用表 102，与网关自己的组解析查询一样跟着主备枢纽切换。
- `sniff_mss`（output）：SYN 的 MSS 按 `mss` 链同样的数值压低（含 Mesh 出口的按标记压低）。
- `sniff_out` / `sniff_confine`（output，优先级 10，在路由链改标记之后）：只放行 ① 被接管连接上的回包（`ct direction reply`）；② 这些隧道流量的 WireGuard 外层包：带隧道接口的 fwmark `0x4d72`、UDP、发往这台网关某条隧道的对端端点（地址和端口，从局域网口出去）或某个 WSS 承载的本机 wstunnel 端口（`127.0.0.1`，从 `lo` 出去），计数 `sniff_wg_outer`（见下面「封装后的外层包」）；③ 目标文件里每个解析器、按它自己的查询标记的 DNS（TCP/UDP 53）；④ 国内标记、目的端口在接管列表里、从局域网口出去的 TCP；⑤ 出口或地区组标记（去掉中继位后在出口标记范围内）、目的端口在接管列表里、目的不是私有或特殊地址、从网关的某条隧道出去的 TCP。其余一律计数（`sniff_denied`）并丢弃。
- `transit_snat`：它的出口和地区组标记的连接换成该标记的中转源地址（与局域网流量相同），枢纽据此选出口。

**封装后的外层包。** 转发服务送进隧道的包（到地区组或出口解析器的查询、到上游的连接）由内核的 WireGuard 加密成一个外层 UDP 包；这个外层包**仍然带着发出内层包的那个套接字**，所以 output 钩子里 `meta skuid 65530` 对外层包同样成立。外层包带隧道接口的 fwmark `0x4d72`（网关的 WireGuard 配置里的 `FwMark`，策略规则 `fwmark 0x4d72 lookup main` 把它送进主表），发往隧道的对端端点：直连 WireGuard 是中继或枢纽的公网地址和 WireGuard 端口，从局域网口出去（路由脚本把每个端点 `/32` 钉在局域网口上）；WSS 承载是本机 wstunnel 客户端的 `127.0.0.1:<本地端口>`，从 `lo` 出去，由 wstunnel（root 运行，不是转发服务的套接字）经 TLS 送到同一个监听端的 WireGuard 端口。第一版的 `sniff_confine` 没有考虑这一点：内层包被正确放行并做了源地址转换，外层包却落到「非 TCP 一律丢弃」。真实网关上开启后，凡是经隧道的目标全部失败（按名字的连接在解析这一步 2 秒超时，按地址回落的连接连上游 18 秒超时，每次失败 `sniff_denied` 加一个约 156 字节的包），直连全部正常；主会话在真实隧道上用临时表和测试 uid 复现过：同一个查询只有现有放行规则时超时、在前面加一条按 fwmark 放行的 UDP 规则后 46 毫秒成功。命名空间测试当时的「隧道」是 veth，没有封装，所以没发现（见 [verification.md](verification.md)「按域名嗅探」）。

现在 `sniff_confine` 在回包规则之后、「非 TCP 一律丢弃」之前，为每个端点渲染一条：

```
meta mark 0x00004d72 oifname "<局域网口>" ip daddr <端点地址> udp dport <端点端口> counter name "sniff_wg_outer" accept comment "WireGuard outer packets of m02: its peer endpoint"
meta mark 0x00004d72 oifname "lo" ip daddr 127.0.0.1 udp dport <wstunnel 本地端口> counter name "sniff_wg_outer" accept comment "WireGuard outer packets of m02w: its local wstunnel client"
```

（IPv6 端点是 `ip6 daddr`。）端点列表只有一个来源：`gatewayWGOuter` 对每条网关隧道调用 `peerEndpoint`，就是写出这条隧道 WireGuard 配置里 `Endpoint =` 那一行的同一个函数；WSS 承载的端点端口就是 wstunnel 客户端单元 `-L udp://127.0.0.1:<端口>` 的端口（同一个 `Tunnel.ClientUDP`）。`TestSniffWGOuterEndpoints` 在 6 种拓扑上核对：每条网关隧道的 `Endpoint`（地址和端口）和每个网关 wstunnel 客户端的本地端口都有且只有一条放行，没有别的规则带这个 fwmark，配置里的 `FwMark` 就是它，直连端点被路由脚本钉在局域网口。

**为什么这条放行不是绕过隧道的通道。** 转发服务有 `CAP_NET_ADMIN`，可以给自己的任何套接字设 `0x4d72`。即使这样，这条放行能送出去的只是：发往**这台网关自己的隧道对端**的 WireGuard 端口的 UDP（从局域网口），或发往本机 wstunnel 端口的 UDP（从 `lo`，wstunnel 把它带到同一个监听端的 WireGuard 端口，监听端的 `restrict-config` 只允许这条链路的 WireGuard 端口）。对端的 WireGuard 对不是用网关密钥正确加密的数据直接丢弃，不回答、不转发，所以这样的包到不了任何别的主机或端口。带这个标记发往任何别的地址、别的端口、别的接口，或者不带标记发往端点，都落到「非 TCP 一律丢弃」并计数（`TestNetnsSniffWireGuard` W2 阶段逐项证明，含「端点地址、别的端口」和「回环、不是 wstunnel 端口」）。转发核心自己只为 DNS 建 UDP 套接字（目的端口 53、目标文件里的解析器），客户端无法引导它往别处发 UDP。

要说清楚的限制：在网关的网络命名空间里有 `CAP_NET_ADMIN` 的进程，本来就能改写规则集和路由，也能经 netlink 读出 WireGuard 接口的私钥（`TestNetnsSniffWireGuard` 在命名空间里以 uid 65530 加这个能力读到了测试密钥，日志里只记长度）。所以出站限制（有没有这条放行都一样）防的是**被引导或出错的**转发服务——目的地址由客户端决定、标记算错、解析器选错——而不是转发服务进程里被执行了任意代码；后者需要的是去掉 `CAP_NET_ADMIN`（例如改用由 root 预先打标记的套接字），不在这次修改的范围内。

**端点变化与失败关闭。** 放行规则是 `meridian.nft` 的一部分，端点变化（改中继地址或端口、加减链路、换 WSS 本地端口）与 WireGuard 配置在同一次安装事务里写好，`meridian-up.sh` 先原子替换规则集，之后才 `wg syncconf` 各隧道，两者之间的这段时间里 WireGuard 还在往旧端点发，新规则集只放行新端点，转发服务这期间经这条隧道的外层包被拒绝并计数（失败关闭，不会放宽；`wg syncconf` 之后恢复）。没有固定端点的网关隧道（配置里没有 `Endpoint`：对端主动拨入；或端点是域名）没有放行规则，链里留一行注释写明原因，经这条隧道的转发失败关闭：`sniff_denied` 增长、转发服务的最近决策里是解析或连接失败；一条放行都没有时面板的「生成配置」核对（`sniff_config`）失败。对端主动拨入的隧道和远程接入接口 `mra`（同样带 `0x4d72`，设备的端点是动态的）实际上由第一条 `ct direction reply` 放行：外层流的连接跟踪条目是对端先建的，网关发出的外层包是回包方向；设备的 `PersistentKeepalive = 25` 让条目一直在，条目过期后网关先发的外层包会被拒绝并计数（不放宽）。

**其余按属主匹配的规则对外层包的审计**（`TestSniffOwnerRulesSkipOuterPackets` 列举规则集里每一条 `meta skuid`，出现未审计的就失败）：

- `sniff_route`（route 类型，output）：只匹配 TCP、目的端口不是 53、标记在出口范围 `0x101`–上限（最多 `0x101 + 239`）里。外层包是 UDP、标记 `0x4d72`，不匹配，标记不变；route 类型的链只在标记等被改动时重新选路，外层包不会被改标记或改道，仍按 `0x4d72` 走主表到端点。
- `sniff_mss`：只匹配 TCP SYN。
- `transit_snat` 里转发服务的规则：`meta mark & 0xff00ffff == <出口或地区组标记>`，`0x4d72` 不是任何出口或组标记，也不带中继位、接管位，外层包永远不会被换成中转源地址。另外 NAT 只对一个连接跟踪条目的第一个包求值，外层流的第一个包是 WireGuard 自己的握手（不带套接字）。其余 `transit_snat` 规则按局域网、远程接入源地址和出口标记匹配，外层包的源是网关的局域网地址、标记 `0x4d72`，也不匹配。
- `sniff_out`：只是跳到 `sniff_confine`（上面）。
- 回来的外层包（入站）：是发往网关 WireGuard 端口的 UDP，入站时没有属主，它的连接跟踪条目是外层流的（这条隧道上所有流量共用），与内层是不是转发服务的连接无关：`sniff_input` 只处理 TCP；`prerouting` 的 `classify` 像对待任何发往网关自身地址的包一样给它打国内标记，`sniff_mark` 只看 TCP；兜底表只挂 forward 钩子，本机收发的包不经过它。解密后的内层回包从隧道接口进来，属于转发服务自己的连接，由连接跟踪送回它的套接字。WSS 时回包由 wstunnel 经 `lo` 交给 WireGuard，同样与转发服务无关。

**单元与账号。** systemd 在执行一个单元的任何 Exec 行之前（带 `+` 的也一样）就解析 `User=`；账号不存在时以 217/USER 失败，写成不在用户库里的数字 uid 也一样（真实网关 Debian 13 / systemd 257 上见到并用临时单元复现过）。所以账号不能由转发服务自己的单元创建，而是由一个独立的 root oneshot 单元提供：

- `meridian-sniff-account.service`：`Type=oneshot`、`RemainAfterExit=yes`、`StopWhenUnneeded=yes`，`ExecStart=/usr/local/sbin/meridian-sniff-user.sh add`、`ExecStop=… del`，没有 `[Install]`、没有 `User=`（root）。脚本只建、只删 `meridian-sniff`/65530 这一对：名字或 uid/gid 已属于别人时 `add` 以 `meridian-sniff-user-conflict: …` 失败；`add` 中途失败时撤销自己建的组；`del` 只删名字和号都对得上的账号与组。
- `meridian-sniff.service`：`Requires=` 并 `After=` 账号单元；`User=`/`Group=meridian-sniff`、`AmbientCapabilities=CAP_NET_ADMIN`、`CapabilityBoundingSet=CAP_NET_ADMIN`、`NoNewPrivileges=yes`、`ProtectSystem=strict`、`ProtectHome=yes`、`PrivateTmp=yes`、`RuntimeDirectory=meridian-sniff`、`RuntimeDirectoryMode=0755`、`Restart=always`；`ExecStartPre=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=1`、`ExecStopPost=+… =0`（root，账号此时已存在）。

启动转发服务时 systemd 先启动账号单元（建账号），再启动转发服务；转发服务停止（或崩溃重试用完、进入 failed）后账号单元不再被需要，由 systemd 停止并删掉账号；崩溃重试期间（`activating`）账号保留。停止的顺序与启动相反：先转发服务（`ExecStopPost` 收回 sysctl），后账号单元。账号单元失败（账号冲突）时转发服务不启动（依赖失败），被接管的连接失败关闭。账号号固定、规则集按号匹配、服务不运行时没有账号，这三点不变。断电等异常关机时 `del` 没有执行，账号留到下一次启动或停止时被同一脚本接受或删除。

**转发服务自检（`internal/sniff/selfcheck.go`）。** 「服务在运行」不等于「路径可用」：上面的事故里单元是 active、验收脚本通过、面板显示运行中，而凡是经隧道的目标全部失败。所以转发服务自己检查它真实用到的路径：由它自己的进程——它的 uid、它的套接字标记、在 `sniff_confine` 的限制之下、经它的连接实际走的路由、中转源地址转换和 WireGuard 隧道——向目标文件里每个有解析器的目标的每个解析器（每个目标最多 4 个，最多 64 个目标）用该目标的查询标记问一个固定问题，并对默认目标（默认地区组）经它的隧道建一次 TCP 连接。

- 问题是 `. IN NS`（根域的名字服务器，带 RD 和 EDNS0）：不涉及任何网站、不带任何能区分运营者的内容，每个递归解析器都能从根提示回答，枢纽上的地区组解析器和出口的解析器都没有会特殊对待它的规则；除了转发服务本来就在用的目标解析器，不联系任何人。来自那个解析器的任何格式正确的回答——NOERROR、NXDOMAIN、SERVFAIL、REFUSED 都算——说明这条路径当时是通的：查询带着目标的标记出去，被出站限制放行，经过隧道（包括外层包），回答回来了。超时、本机拒绝发送（`EPERM`：在出站路径上被丢弃）、不可达、ICMP 端口不可达、与问题不符的回答都不算。例外是「慢」：UDP 问题超时，但随后经同一个标记到同一个解析器 53 端口的 TCP 握手成功（`slow`）——路径已被证明可达，只是解析器对这个问题回答得慢（真实网关上出口的 SmartDNS 要 2–3 秒才对 `. NS` 回 SERVFAIL，而 A 查询 30–180 毫秒）；目标仍算 ok，但带一条告警（结果里的 `warning`、转发服务日志一行、安装报告的告警），不挡安装。TCP 也超时、被拒或没跑到时照旧失败（失败关闭）。
- 连接试探：对默认目标第一个解析器的 53 端口做一次 TCP 握手，带这个目标的查询标记，建立后立即关闭，不发任何字节。地区组的查询标记就是组的连接标记，所以它走的正是转发服务到这个组的连接的路径：标记、策略路由、中转源地址转换、MSS 钳制、隧道和外层包、枢纽的回程；出站限制本来就放行目标文件里的解析器（TCP/UDP 53），不需要新的放行，也不联系第三方。它**不覆盖**中继分担（`sniff_route` 跳过 53 端口）和隧道之后的任何网站。
- 界限：同一时刻只跑一次（请求排在正在跑的那次后面，排队中的触发合并）；最多 16 个探测同时进行；每次查询 5 秒（已知不回答的解析器复查 2 秒）、连接试探和超时后的 TCP 跟进各 3 秒、整次 20 秒，到时还没跑的探测记为 `not_run`（结果标 `incomplete`）。它在自己的 goroutine 里跑，不占用转发需要的任何东西。
- 什么时候跑：启动时、每次 SIGHUP 重载成功后（后台，不挡转发）、运行中每 15 分钟（`--selfcheck-interval`，0 关闭）、以及经状态套接字 `POST /v1/selfcheck` 按请求（不接受任何参数，回答受 1 MiB 上限）。最近一次的结果放在 `/v1/health` 的 `self_check` 里。
- 结果：开始和结束时间、触发原因、转发服务内部的规则代、**目标文件的 SHA-256**（这一对规则在安装里的身份：目标文件里写着快照的哈希）、问题、默认目标、每个目标的状态（ok / failed / unchecked）和原因、每个探测的服务器、结果（answer、nxdomain、rcode、connected、timeout、slow、send_refused、refused、unreachable、malformed、error、not_run）、rcode 和耗时。没有解析器的目标记为 unchecked（按名字判断到它的连接本来就会失败）。
- 与真实解析走同一条路：自检的每次查询和转发服务按名字解析时一样，经 `Resolver.exchange` 发出——同一个交换函数（转发服务自己的套接字，UDP，截断时 TCP）、目标文件里这个目标的解析器地址和它的查询标记；真实解析按顺序问解析器、前一个失败才问下一个，所以一个目标只要有一个解析器回答，按名字的连接就能解析，自检的「任一解析器可达即 ok」与此一致。各类目标：直连——国内解析器（`DomesticDoT` 的地址:53）、国内标记 `0x64`，从局域网口出去；地区组（可切换的组、静态组、钉住的组）——组解析器 `fd66::53:<k>`、组标记（经中转源地址转换进隧道）；出口（钉住的出口、解锁移走的规则、嵌套出口、外部 SOCKS 出口）——出口解析器 `fd66::54:<i>`（备用枢纽时是与枢纽无关的地址），标记 0、主表经隧道，外部出口的这个地址由枢纽转到它的解析器组；没有自己解析器的出口（只经 Mesh 到达）——「未检查」，不算失败（按名字判断到它的连接本来就因为没有解析器而失败，自检说不出更多）；拒绝目标——不检查；关闭 IPv6 的目标——只影响真实解析问 A 还是 AAAA，不影响查询走的地址族和路径，自检一样。`TestSniffSelfCheckSamePathAsLookup` 在编译出的目标文件上逐类核对。
- 证明什么、不证明什么：它证明在那一刻每个目标的解析器从转发服务可达，并且默认目标经隧道能建 TCP 连接；不证明某个网站能打开、出口能上网、或解析回答是对的。

**安装事务怎样用它。** 嗅探开启时，host agent 的 activate 在启动或重载转发服务、两次健康采样都通过之后：读磁盘上的目标文件算出哈希，等转发服务的 `/v1/health` 报告的 `targets_sha256` 等于它（最多 20 秒；SIGHUP 是异步的），然后 `POST /v1/selfcheck`，把结果原样附在回答里（`Result.SniffCheck`），自己不做判断——不新增任何命令能力，读的仍是那个只回答 uid 0 的状态套接字。安装事务（`apply.checkSniff`、`hostexec.EvaluateSniffCheck`、`sniff.EvaluateSelfCheck`）判断：结果必须属于本次安装的目标文件（清单里的哈希）、开始时间不早于本次请求、结束不超过 2 分钟（都按宿主自己的时钟），否则按陈旧拒绝（`stale_generation` / `stale`）；agent 没有结果（`unavailable`：没有套接字、读不到目标文件、agent 太旧没有返回自检）或没有按时得到（`timeout`：规则没在时限内载入、自检请求没有回答）都按失败处理（失败关闭），原因各不相同；默认目标失败（`default_failed`）——这一步失败，事务按原有路径补偿回到上一版本，错误里写明哪个目标、哪个解析器、什么结果；其它目标失败只记告警（某个出口当时确实不通不应该挡住整次安装），安装保留。报告里多一个步骤 `sniff self-check`。补偿时恢复的上一版本如果也运行转发服务，它的自检照样执行并报告，但**不作为补偿的条件**（隧道真的断了时不能把主机卡在刚失败的版本上），结果写进告警。运行时回滚（回到上一版本）走同一个安装路径，也要求自检通过。上面的事故按现在的做法会这样结束：安装的最后一步自检报告默认地区组的解析器超时，几秒内补偿回安装前的版本，面板说明原因。

**只重载的更新。** 规则、规则集合改动都经安装事务（上面的重载路径也要求自检通过）。名单或规则集的发布不经事务：host agent 发布文件、加载 nft 集合、对正在运行的转发服务 `try-reload-or-restart` 之后，等它的健康状态报告一次不早于这次信号的重载，再请求一次自检；不通过时**不撤回名单**（名单不是这次故障的可补偿单位，也没有事务可以补偿），而是作为名单任务的告警返回，同时转发服务自己的最近一次自检（面板显示）就是失败的那次。

**状态套接字的访问。** host agent（`meridian-host.service`）以 root 运行，但能力只有 `CAP_NET_ADMIN`，没有 `CAP_DAC_OVERRIDE` / `CAP_DAC_READ_SEARCH`，`ProtectSystem=strict`：它对别人的文件只有「其他人」那一组权限位。所以运行目录 `/run/meridian-sniff` 是 0755（属主是转发账号，由 systemd 建、停止后删），状态套接字 `status.sock` 是 0666；谁能拿到回答由转发服务自己决定：每个连接接受后读对端凭据（`SO_PEERCRED`，连接时由内核记录，按转发服务所在的 user namespace 换算），只回答 uid 0，其余连接不读不写直接关闭（`sniff.ListenStatus`、`PeerListener`）。主机上其他本地用户能打开连接但拿不到任何内容；能读状态的只有 root 进程（root 本来就能读这个进程的内存）。开启「记录名字」时，最近决策里的名字因此只对 root 和经 host agent 认证的面板可见。没有选附加属组的做法：agent 开机就启动，远早于转发账号和它的组存在，而 systemd 对解析不了的 `SupplementaryGroups=` 和 `User=` 一样拒绝启动；也不需要给 agent 加能力或放宽沙箱（只读挂载的 `/run` 不妨碍连接 Unix 套接字）。agent 的单元和 `deploy/debian/install.sh` 都没有改动，升级不涉及它。

**目标文件与 DNS 标记。** 编译器为快照里每个标记写一个目标（`/etc/meridian/sniff/targets.json`，与 `decide.json` 成对，文件里记着快照的 SHA-256），解析器与网关 SmartDNS 的选择一致：出口用它的隧道解析地址（有备用枢纽时用 `fd66::54:<i>`），**不带标记**（主表的 `fd66::/48` 指向当前的西向隧道，与 SmartDNS 一样）；没有隧道解析地址的出口（只经 Mesh）没有解析器，按名字决定到它的连接失败（SmartDNS 对这类名字也只回 SOA）；可切换的地区组用 `fd66::53:<k>`，带组标记（`transit_snat` 已有的那条规则把它换成组的中转源地址）；不可切换的组用目标成员出口的标记和解析器；直连用国内解析器，带国内标记 0x64；拒绝没有解析器。转发核心现在按**标记**匹配目标（标记决定数据面怎么走、谁来解析）：静态地区组和它的成员出口、被解锁结果移到某成员的组规则，共用一个目标项。

**更新顺序。** 规则、规则集合改动都经安装事务：所有文件先写好（每个文件临时文件 + 改名），然后 `meridian.service`（`meridian-up.sh`）原子加载新规则集，再由 host agent 对转发服务 `systemctl reload-or-restart`（SIGHUP；条件是转发服务在上一个版本里、两个单元文件和账号脚本都没变）。否则按固定顺序重启：`systemctl stop meridian-sniff.service`、`systemctl stop meridian-sniff-account.service`（删账号，并检查它的 `ExecStop` 没有失败）、`reset-failed` 两个单元、`systemctl start meridian-sniff.service`（systemd 先启动账号单元建账号）；失败时步骤里带两个单元的日志，事务补偿。健康检查同时要求两个单元都是 active。所以先是 nft 有新标记和集合、紧接着转发服务换成新的一对规则，差距是一次 SIGHUP 的时间；转发核心只接受快照与目标文件哈希相符的一对，读到一新一旧时保留旧的一对（重载）或不启动（启动时，systemd 1 秒后重试）。名单或规则集更新经 host agent 的固定名单动作：文件发布、派生、加载 nft 集合之后，对正在运行的转发服务 `try-reload-or-restart`。

**失败关闭。** 服务停止或崩溃：被重定向的 SYN 收到 RST（`TestNetnsSniff` H 阶段，约 0.1 秒），不会经地址路径转出去；`Restart=always`，1 秒后重启。`inet meridian` 整张表不在时没有重定向，兜底表照旧丢弃所有未分类的转发。表在而服务的出站不合规：`sniff_confine` 丢弃（经隧道的流量的 WireGuard 外层包只按端点放行，见上面「封装后的外层包」）。客户端绕不开：只接管 SYN，一个 TCP 连接没有 SYN 就建立不起来；不在接管列表里的端口、UDP（含 QUIC）按设计走地址路径。

**安装、撤回、回滚、补偿。** 两个单元文件、`meridian-sniff-user.sh`（0755）、目标文件都是安装清单里的文件；清单的单元列表里只有 `meridian-sniff.service`。账号单元不在单元列表里，请求里也不能点名它（host agent 的 `reservedUnits`，与 `meridian.service` 等一样），agent 只在处理 `meridian-sniff.service` 时用固定步骤启动、停止它，没有新的命令能力。各个转换的顺序：

1. 首次开启：写全部文件 → `daemon-reload` → `meridian.service`（新规则集）→ `enable meridian-sniff.service` → 上面的固定重启顺序 → 健康检查（两个单元 active，两次采样）。
2. 运行中更新：只有规则对变化时 `reload-or-restart`（账号不动、连接保留）；单元文件或账号脚本变化时固定重启顺序（账号删了再建）。
3. 关闭设置、运行态回滚到没有它的版本、撤回：先 `systemctl disable --now meridian-sniff.service`（`ExecStopPost` 收回 sysctl），再 `systemctl stop meridian-sniff-account.service`（不等 systemd 异步的 `StopWhenUnneeded`，当场删账号并检查 `ExecStop` 结果；账号单元此前已失败时先再启动一次，`add` 只接受我们自己的账号，启动不了说明没有我们的账号），再 `reset-failed` 两个单元（systemd 随后卸载它们）；然后面板删掉文件，删掉变空的 `/etc/meridian/sniff`（只删清单独占、已空、目标版本里没有文件的目录，见 `ownedDirs`），再 `daemon-reload` 并激活目标版本（撤回时由撤回动作检查兜底表）。运行目录 `/run/meridian-sniff` 由 systemd 删除。
4. 补偿（例如真实网关上那次：单元在、启动失败）：与第 3 条同一条路径从目标版本回到原版本，之后两个单元都不在运行也不处于 failed，文件、脚本、账号、sysctl 和空的 `/etc/meridian/sniff` 都不留下（`TestSniffFailedStartCompensates`，含账号冲突的情形）。

规则集里的链属于 `inet meridian`，随这张表一起替换或删除。

**面板。** 规则页「按域名嗅探（TCP）」：设置、按名字 / 仍按地址 / 代价三段说明、网关上的状态（经 host agent 的无参数只读接口 `/v1/sniff/status` 读状态套接字）——「运行中」和「路径可用 / 部分目标不通 / 路径不通 / 路径未自检」分开显示：最近一次自检（时间、触发、规则代、是否属于当前安装的目标文件、默认目标的结论）、每个目标最近 15 分钟的解析失败 / 连接失败 / 成功数（转发服务按目标保留有界的计数，目标离开目标文件时删除）、`sniff_denied`（agent 用固定的 `nft list counter` 读，并与它 30 秒到 30 分钟前的读数比较是否在增长）和 `sniff_wg_outer`；失败集中在经隧道的目标而直连正常时（最近 15 分钟隧道目标至少 5 次失败且占八成以上、直连失败不超过两成）给出明确提示；同一时刻只有一条主要提示。「立即自检」经 agent 的无参数接口 `/v1/sniff/selfcheck` 让转发服务马上跑一次。还有最近决策（按名字还是按地址、原因、规则、目标、结果；名字只在打开记录时出现；展开一行可以看到名字解析不到时名字命中的规则和原因、套接字标记的状态和原始值，以及标记不可信而被拒绝时转发核心自己的地址判断会选的规则和目标）。概览有一个状态块。规则测试器可以填设备 MAC（以前忽略按 MAC 的规则）。mihomo 导入：设置开启时，只有转发服务真正覆盖的标记——关键词（`keyword_expanded`、`ruleset_keywords`）——不再阻止确认，并注明仍按地址的部分；QUIC 相关的标记照旧要接受。

**已知限制。** 中继被淘汰时，转发流量的 TCP 会被 `relay_drain` 重置以便重连，转发服务自己发起的连接不会（`relay_drain` 只看转发钩子），留在原中继上直到结束；新连接按新的权重分配。转发服务连接的是目标解析器给的地址，不是客户端自己解析的地址。所有被接管的连接经用户态转发。

### 设备连接日志（`--journal-dir`，`internal/sniff/journal.go`）

（连接日志、解析日志、链路日志三者给操作者的说明——范围、默认上限和最坏磁盘占用、权限、关闭与清空、空窗、跳转的限制——集中在 [logging.md](logging.md)；本节和后面两节是实现。）

**为什么。** 内存里的近期决策只有 256 条，一部手机正常使用约五分钟就填满；要查四十分钟前的一段失败时记录早已被覆盖。连接日志把嗅探服务经手的每条连接（`ConnRecord`：时间、来源地址、能取到时的 MAC、原目的地址和端口、协议、按名字还是按地址及原因、命中的规则、去向、标记、上游地址、结果和原因、`name_rule`、`mark_status` / `raw_mark` / `fallback`；名字见下）有界地写在网关本机，重启不丢。

**连接结果：一条连接一条最终记录。** 记录在连接**结束时**写一次（`Server.finish`）：拒绝、解析或连接失败的连接在判断时就结束；转发中的连接在任一方关闭或重置、读写出错、空闲 `--idle-timeout`（2 小时）或转发服务停止时结束。没有最长存活时间。同一处同时更新内存里的近期记录、连接日志、计数器（`result_<结果>`、`end_<结束方式>`）和各目标的统计（`recent_ok` / `recent_dial_failed` / `recent_resolve_failed` / `recent_relay_failed`，按**结束**的那一分钟），所以这几处和按设备汇总都只把一条连接算一次、结果一致（`TestRelayResults` 等逐一核对）。

- 为什么不用「先写已建立、结束再补一条」：那样每个读者（翻页、汇总、24 小时 / 5 万条 / 32 MiB 的上限）都要把两行合并成一条，转发服务被杀时还要把缺了结束行的连接判成「结束情况未知」；而一条最终记录天然只算一次，也永远不会有一条没走完的连接被记成成功。代价是长连接在结束之前不在日志里：转发服务有一个有界的**正在转发**视图（`Server.Active`，最多 `--max-conns` 条，内存中），`/v1/recent` 带最新的 100 条，日志的第一页（没有结果筛选时）带与设备 / 去向 / 时间 / 名字筛选相符的最多 50 条，按设备汇总带每台设备正在转发的条数；面板在设备详情里单列「正在转发」，它们不进任何计数。
- 停止：正常停止或重启（`SIGTERM`，包括安装新版本时的重启）先关闭所有被接管的连接，每条以结束方式和结果 `shutdown` 写入，然后才关闭日志（排队的记录写完、`fsync`）。`SIGHUP` 重载规则不打断已建立的连接，也就没有「重载中断」这种结束。**被强行终止**（`SIGKILL`、OOM、崩溃、断电）时：当时仍打开的连接**没有记录**；交接队列里还没写的记录丢失；断电时还丢最后不超过 5 秒未 `fsync` 的行。为了不让这种丢失悄无声息：转发服务打开日志时在目录里放一个标记文件 `running`，每分钟改写一次（当时的时间和正在转发的连接数），正常关闭时删除；下次打开时发现它，就在 `journal.unclean_stop` 里报告「上次没有正常退出、最后确认运行的时间、当时（最近一分钟内）还开着的连接数」，系统日志写一行警告，面板在日志上方提示，直到下一次「清空日志」。
- 结束方式（`end`）：`client_closed` / `upstream_closed`（谁先发 FIN，正常结束）、`client_reset` / `upstream_reset`、`client_error` / `upstream_error`（其它读写错误）、`idle_timeout`、`shutdown`。以第一个异常事件为准（转发服务自己因此关闭另一侧引起的错误不算）；没有异常时是先关闭的一方。`reason` 是有界的错误类别：转发中的读写为 `read_<类别>` / `write_<类别>`，写入卡住到空闲时限为 `write_stalled`；连接失败（`dial_failed`）为最后一次尝试的类别 `timeout`、`refused`、`unreachable`（网络不可达）、`no_route`（没有到主机的路由）、`reset`、`af_unavailable`（地址族 / 本地地址不可用）、`denied`（本机防火墙或权限拒绝发送，例如出站限制）、`other`，`upstream` 写最后尝试的地址（就是原目的地址或目标解析器给的地址，不增加新的敏感数据）。另有 `duration_ms`（从接受到写记录）、`bytes_up`（客户端到上游，含嗅探读到的首包）、`bytes_down`（上游到客户端）：只有数量，不含内容。
- 成功怎么算（`ok`）：上游连上**并且至少有一个字节从上游回到客户端**，之后怎样结束都算成功（例如服务器回完应答后重置）。转发后的其它结果：`no_response`（客户端发了数据，上游一个字节也没回就结束了：客户端放弃、上游关闭或空闲超时——例如路径能建连接但大包过不去）、`relay_failed`（上游在回任何字节之前重置或出错）、`client_closed`（客户端既没发数据也没收到数据就离开，例如浏览器的预连接；与「判断之前就关闭」同一结果）、`shutdown`。**失败**（汇总的 `failed`、筛选「全部失败」、面板的失败数）：`resolve_failed`、`dial_failed`、`relay_failed`、`no_response`、标记问题、`shutdown`、其它；**不算失败**：`rejected`（拒绝规则按设计拦下）、`client_closed`、`ended_unknown`（上一版转发服务在连上时就写下 `ok`、没有结束方式的记录；读取时归入「结束情况未知」，既不算成功也不算失败）。目标统计里 `relay_failed` 计数包括 `relay_failed` 和 `no_response`，诊断卡片的失败合计和「经隧道的目标集中失败」判断都把它算进去；`client_closed`、`rejected`、`shutdown` 不进目标统计的失败。

**覆盖范围。** 只有嗅探服务经手的连接：局域网和远程接入设备新建的、发往接管端口的 TCP。**不在日志里**：所有 UDP（含 QUIC）、不在接管列表里的端口和不接管的目的地址、嗅探关闭或服务停止期间的全部流量、接管之前已建立的连接。**DNS 查询不在连接日志里**：设备解析了哪些名字由单独的解析日志记录（下一节「网关解析日志」，默认关闭），面板在日志旁边写明。

**位置与权限。** 转发服务以固定 uid 65530（`SniffUID`）、只有 `CAP_NET_ADMIN`、`ProtectSystem=strict` 运行，所以日志放在它自己单元的 `StateDirectory=meridian-sniff`（`/var/lib/meridian-sniff`，`StateDirectoryMode=0700`）：systemd 每次启动时建好并交给 `User=` 的账号，在 `ProtectSystem=strict` 下仍可写，不需要 `ReadWritePaths=`。转发服务自己写文件，段文件以 0600 创建，打开时把目录强制改回 0700、已有文件改回 0600。于是只有 root（带 `CAP_DAC_OVERRIDE` 的管理员 shell）和 uid 65530 能读；其他本地用户属于「其他人」，什么也打不开。uid 固定，所以账号随服务停止删除、下次启动重建后，文件仍属于同一个 uid；账号脚本拒绝把 65530 让给别的账号（冲突时服务不启动）。宿主代理是没有 `CAP_DAC_OVERRIDE` 的 root，同样打不开这些文件——它**只经状态套接字**读日志（下面「读与清空」）。移除转发服务（回滚、撤下、补偿到没有嗅探的版本）时，宿主代理在删除账号之后执行 `systemctl clean --what=state meridian-sniff.service`，由 PID 1 删除整个目录：日志不比转发服务活得长（失败时记为跳过并说明，不让移除失败）。

**格式。** 追加写的 JSON 行，每行一个 `JournalRecord`（`ConnRecord` 加递增的 `id`），分段文件 `conn-<首个 id，20 位>.jsonl`。每个字段有字节上限（地址 64、名字 253、规则 id 和目标 96、原因 128、其它 32；控制字符去掉），整行不超过 4096 字节，超过的不写并计数（`oversized`）。

**三个上限同时生效**（默认 24 小时、50000 条、32 MiB）：

- 条数：一段满 `MaxRecords/8` 条就换新段；写入前若盘上条数（含本批待写）会超过 50000，删最旧的段。查询从不显示最新 50000 条以外的记录。
- 时间：一段的跨度达到 `MaxAge/24`（1 小时）就换新段；最新一条也早于 24 小时的段在每次写入和每分钟一次的清理时删除。查询从不显示 24 小时以前的记录；盘上一条记录最多多留一个段跨度（最坏 25 小时）。
- 字节：一段到 `MaxBytes/16`（2 MiB）就换新段；每次写入前删最旧的段，直到全部段加上这次要写的字节不超过 `MaxBytes − 一段 − 34 × 4 KiB`。留出的一段是「关闭名字记录」时改写文件用的临时副本（一次只有一个，大小不超过一段），34 × 4 KiB 是每个文件（最多 32 个段、一个临时文件和不到 100 字节的标记文件 `running`）按文件系统块取整的余量。**最坏磁盘占用**：所有文件内容合计不超过 32 MiB（数据 ≤ 32 MiB − 2 MiB − 136 KiB，临时副本 ≤ 2 MiB），按 4 KiB 块取整也在 32 MiB 之内；目录本身一个块。
- 三个上限都按**连接**计：一条连接只有一行。时间按记录写下（连接结束）的时间算：段的跨度、过期删除和查询的 24 小时都用结束时间（`ConnRecord.EndTime` = 开始 + 时长），所以一条 30 小时的长连接结束后仍保留 24 小时；列表按结束时间从新到旧。时间筛选 `from` / `to` 选的是在这段时间里**开着过**的连接（结束不早于 `from`、开始早于 `to`）。洪水压力测试（每条都是最长字段）里每 500 条检查一次，从未超过。

**从不挡连接。** `Server.finish` 把记录交给有界队列（4096 条）：`select` 非阻塞，满了（写不过来、磁盘卡住）就丢弃这一条并计数（`dropped`）。写入失败（磁盘满、I/O 错误）丢弃并计数（`write_errors`），关闭当前段，至少隔 1 秒再开新段。启动时日志打不开（目录不可写等）只记一行警告，转发服务照常运行、没有日志（`Health.journal` 为空，面板显示「没有连接日志」）。连接路径上没有任何磁盘操作。

**落盘与损坏。** 一批记录一次 `write(2)`；有未同步的写入时每 5 秒 `fsync` 一次，换段和退出时也 `fsync`，新建段和改写后 `fsync` 目录。断电最多丢最后几秒；最新一段末尾被截断的半行在下次打开时切掉（`torn_bytes`），旧段里无法解析的行读取时跳过，日志不会因此读不出来。

**名字。** 只有 `record_names` 打开（转发服务带 `--record-names`）时记录才有名字：TLS 的 SNI、HTTP 的 Host，带 ECH 时是明文的外层名字。关闭时**不保存任何名字，也不保存散列**；面板显示「未记录名字」，按名字搜索被拒绝。开关的切换走现有的保存 → 预检（单元文件的差异）→ 确认 → 安装，没有旁路；面板保存前弹出说明（开启：记什么、在哪里、保留多久、怎么清空；关闭：见下）。**关闭后已有的名字**：单元参数变了，安装重启转发服务；转发服务带着「不记录名字」打开日志时，把仍含名字的每一段改写成不含名字的副本（同目录临时文件、`fsync`、改名覆盖、`fsync` 目录，`purged_names` 计数），其余字段保留；某一段改写失败（例如磁盘满）就整段删除，名字不会因此留下。所以关闭并安装之后网关上不再有可读的名字；在安装之前，可以用「清空日志」立刻删除。删除是 unlink，不做覆写擦除。

**读与清空：只经固定的只读状态通道。** 转发服务的状态套接字（0666，只回答 uid 0，见「状态套接字的访问」）上加了三个固定请求：`GET /v1/journal`（一页，参数只有 `device`、`target`、`result`、`from`、`to`、`text`、`before`、`limit`，未知或重复参数拒绝，每个值校验：地址、目标名的字符集、结果类别枚举、RFC 3339 时间、文本 ≤ 64 字节、每页 ≤ 200 条）、`GET /v1/journal/summary`（`from`、`to`；每个设备的总数、按名字 / 按地址、名字解析不到、各结果类别、各去向的次数（最多 24 个去向，其余合计）、首次 / 最近出现、MAC；最多 128 个设备）、`POST /v1/journal/clear`（不接受任何参数；同时清空内存里最近结束的连接记录，它们和日志是同一类数据，可能带名字；正在转发的连接不是记录，结束后照常写入）。回答都小于状态套接字的 1 MiB 上限。宿主代理对应 `POST /v1/sniff/journal`、`/v1/sniff/journal/summary`、`/v1/sniff/journal/clear`：口令认证，请求体有界、拒绝未知字段，参数在问转发服务之前先校验一遍（不合格的请求不会到达转发服务），各自只发一个固定请求、回答检查是 JSON 后原样转交。宿主代理没有新的路径、命令或自由参数，也打不开日志文件；它不记录回答内容（正在转发的连接也经这三个请求的回答带出，没有新请求）。结果类别（`RecordClass`）：`ok`、`rejected`、`resolve_failed`、`dial_failed`、`relay_failed`（含上一版的 `upstream_write_failed`）、`no_response`、`client_closed`、`mark`（`unknown_mark`、`mark_missing`）、`shutdown`、`ended_unknown`、`other`；筛选另有 `failed`（上面「失败」那几类）和 `name_unresolved`（名字解析不到、已按地址处理）。汇总每台设备另有 `failed`、`by_end`（各结束方式的次数）、`bytes_up` / `bytes_down` 合计和 `active`（正在转发的条数，不在其它计数里）。

**面板。** `GET /api/sniff/journal`（同样的筛选参数，未知参数拒绝）、`GET /api/sniff/devices`（汇总加备注名）、`PUT` / `DELETE /api/sniff/devices/{地址}/label`、`POST /api/sniff/journal/clear`（请求体必须是 `{"confirm": true}`，界面先弹确认）；都走面板口令。设备就是局域网地址，能取到时带 MAC（`--neigh-if` 的邻居表）；**备注名是面板数据**，存在面板数据库自己的键 `sniff_device_labels` 下（最多 512 个、每个 1–64 个字符），不在拓扑、快照、导出里，也不写进网关的日志。日志内容只经过这几个处理函数：面板不存、不记日志，不进入拓扑、编译结果、差异、部署记录、状态和诊断读数（`TestSniffJournalNeverLeaves` 检查）。界面在嗅探卡片里按需打开（不打开就不读网关）：设备列表（备注名、地址、MAC、最近出现、连接数和正在转发数、失败数、主要去向）→ 设备详情（备注编辑、汇总（结果各类、结束方式、失败、字节）、按去向 / 结果 / 时间 / 名字筛选；「正在转发」单列；每页 50 条翻页，每条显示开始时间、目的地址、协议、判断依据——按名字时的名字或「未记录名字」、按地址时的原因——规则、去向、结果和结束方式 / 原因；展开看来源和 MAC、实际连接地址（连接失败时是最后尝试的地址）、判断耗时、时长、双向字节、失败原因、名字的判断（解析不到时）、套接字标记）。日志旁边列出「结果怎么算」「什么时候记录」（上面两段的要点）和不在日志里的流量；上次没有正常退出时显示提示。手机宽度下两张表都变成卡片。演示模式有合成的日志（演示局域网里虚构的四台设备、RFC 7042 文档 MAC、文档地址段的目的地址、example 名字），由同一个 `sniff.Journal` 生成；降级场景的那一份是按被强行终止的转发服务留下的磁盘状态重新打开的（带「上次没有正常退出」的提示），另有「没有开启」和「在运行但还没有连接」两个场景。

**生成文件的变化。** 开启嗅探的拓扑：`meridian-sniff.service` 多了 `StateDirectory=meridian-sniff`、`StateDirectoryMode=0700` 和 `ExecStart` 里的 `--journal-dir /var/lib/meridian-sniff`；网关的 `meridian-verify.sh` 多一项 `sniff_journal_dir`（目录 0700、文件 0600、属 uid 65530）。单元文件变了，所以装上这一版的第一次安装会**重启**转发服务（不是重载；已建立的被接管连接随之断开），之后规则变化照旧只重载。嗅探关闭的拓扑逐字节不变。

### 网关解析日志（设置 `dns_log`，`internal/dnsjournal`）

**是什么、范围。** 局域网设备把网关当作 DNS，所以网关上的 SmartDNS 看得到每台设备的每次查询。打开 `settings.dns_log` 后，网关 SmartDNS 写它自己的审计日志，一个独立的宿主进程 `meridian dns-journal`（单元 `meridian-dns-journal.service`）把审计行变成有界的结构化记录：时间、设备的局域网地址（能取到时带 MAC）、查询的名字和类型、有没有应答、由哪个解析组应答、耗时、应答里的地址条数（不保存地址本身）。**只记录网关上的查询**；各出口节点上解析器的查询、设备自己用的加密 DNS、被网关解析器自己的规则直接回答的名字都不在里面（见「结果」）。默认关闭；关闭时编译结果逐字节不变（`TestDNSLogOffIsByteIdenticalOnChangesThreeFiles`，既有 golden 不动）。

**能力门槛：没有核对过的解析器不能打开。** 审计日志在写失败、磁盘写满、写入卡住时会不会拖住解析，是 SmartDNS 二进制的性质。网关的解析器是 Compose 容器，镜像标签是 `latest`：它的版本**不是**面板下发给远端节点的那个固定版本（`internal/artifacts/artifacts.lock` 里的 1.2026.08.05-0921），各网关之间也可能不同。所以门槛（`dnsjournal.Evaluate`）不从标签、也不从节点制品推断任何东西，只看宿主代理读到的事实：

- 解析器必须是 Compose 的 `meridian-smartdns` 容器并在运行（宿主上的 `smartdns.service` 没有核对过：`host_unit`；没有容器：`no_resolver`；没运行：`resolver_not_running`）。
- 版本取自**正在运行的容器里的二进制自己的报告**：宿主代理固定的 `docker exec meridian-smartdns /usr/sbin/smartdns -v`（读不到：`version_unreadable`）。
- 版本必须在允许清单里：`dnsjournal.VerifiedVersions`（现在只有观察过的 `1.2026.11.09-1240`，观察日期 2026-11-15），**或者**本机记录 `/etc/meridian-host/smartdns-audit-verified` 里有一行「版本 镜像 id 日期」且镜像 id 就是运行中容器的镜像（拉了新镜像，id 变了，记录就不再算数）。否则 `version_unverified`，理由里写出读到的版本。
- 容器必须把 `/var/lib/meridian-dnslog/raw` 以**读写**方式挂在同一路径（一条固定格式的 `docker inspect`）。旧 Compose 文件创建的容器没有这个挂载：`no_mount`（或 `mount_read_only`），处理办法是用这一版的 `deploy/docker-compose.yml` 重建容器。

门槛在三处检查，任何一处不满足都不会让解析器带着审计日志重启：`PUT /api/dns-log` 打开时（不满足 409、不保存）；网关的安装前预检（不满足是阻断项 `dns_log_unavailable`，带原因和处理办法；安装前的复检同样执行，所以审阅之后镜像被换掉也会被拦下）；宿主代理在 `activate` 里**重启解析器之前**（见「安装」）。功能不可用时返回明确的原因，**从不退而去读解析器的普通日志**。读不到宿主代理、宿主代理是旧版本（没有这些请求）同样是不可用（`agent_unavailable`、`agent_old`）。

**新版本怎么核对。** `sudo bash deploy/verify-smartdns.sh --audit-check [--record] [镜像]`（默认取 `meridian-smartdns` 容器的镜像；不拉取任何东西）。它用**没有网络**的临时容器（`docker run --network none`）、容器内写入的合成配置（`example.test` 名字、文档地址段、一个永不应答的上游）逐项核对：审计行格式（与解析器同一个模式；一条应答一行；多个应答在同一行；没有应答时结果为空；被 `address /名字/#` 规则拦下的名字**不**写审计行）、轮转（`audit.log-YYYYMMDD-HHMMSS.gz`、有效的 gzip、不超过 `audit-num` 份）、别的进程截断审计文件之后解析器照常应答并从文件开头接着写、审计文件系统写满时 200 次查询全部应答、审计文件系统被 `fsfreeze` 冻结（私有的 loop 挂载 ext4，只冻结它自己建的挂载，退出时一定解冻）时 60 次查询全部应答、审计目录只读或不存在时照常应答；另外报告审计路径是 FIFO 时解析器是否还应答（只作记录，不影响结论）。全部通过且没有跳过项才输出 `meridian-smartdns-audit-verify-ok`，`--record` 才往本机记录里追加一行；有跳过项退出码 3、不记录。它不碰正在运行的解析器容器、它的配置和文件。把一个版本加进内置清单则是改 `VerifiedVersions` 并在本节写下观察。

**观察到的事实**（都用合成名字、没有网络的临时容器；真实地址、主机标识不记录）：

- 2026-11-15，真实网关（主会话执行，与网关解析器同一个镜像）：二进制报告 `smartdns 1.2026.11.09-1240`；容器的四个挂载都是只读，没有可写挂载；审计行格式如 `[2026-11-15 12:09:35,961] 192.0.2.10 query a.example.test, type 1, time 0ms, speed: -0.1ms, group default, result 192.0.2.1`（本地时间带毫秒、没有时区，客户端地址，名字，数字类型，耗时，`speed`，处理它的组，应答地址）；名字不存在和上游失败的结果**都是空**，只能靠耗时区分（约 3 ms 对约 2 s），行里没有应答码；被 `address /名字/#` 拦下的名字**没有**审计行；客户端重试会产生多行；文件默认 0640 root:root；`audit-size 32k` 时长到约 42 KB 才轮转，轮转文件是 gzip、名为 `audit.log-YYYYMMDD-HHMMSS.gz`（轮转过程中短暂有 `audit.log.pending.gz`），`audit-num 2` 最多留两份；文件系统写满（tmpfs 100%）时 200/200 查询有应答、审计文件被解析器截成 0 字节；文件系统被 `fsfreeze` 冻结时 60/60 查询在一秒内应答，解冻后 60 行都在文件里（冻结更久、内存缓冲写满之后的行为没有再推进）。当时还手工试过把审计路径换成没有读者的 FIFO：对那个容器的一轮 3000 次查询没有在时限内跑完，但**没有确认**查询是否真的没有应答，所以这次试验**没有结论**（它曾被记成「解析器一直没有开始服务」，那个说法没有依据，见下一条）。
- 2026-11-15，真实网关，`sudo bash deploy/verify-smartdns.sh --audit-check`（主会话以 root 执行，没有带 `--record`；镜像就是网关解析器容器的镜像，报告 `1.2026.11.09-1240`；退出码 0，结论 `meridian-smartdns-audit-verify-ok version=1.2026.11.09-1240 image=sha256:<镜像 id>`）：10 条审计行全部符合解析器读的格式；有应答的查询结果是它的地址；AAAA 是类型 28；多个应答写在同一行、用「逗号加空格」分隔；没有应答的名字结果为空；被 `address /名字/#` 拦下的名字没有审计行；IPv6 客户端写成它的地址；审计文件权限 640；轮转出 1 个 `audit.log-YYYYMMDD-HHMMSS.gz`（不超过 `audit-num`），是有效的 gzip，里面 222 行都是同一格式；别的进程截断审计文件之后照常应答，并从文件开头接着写（追加方式）；审计文件系统写满时 200/200 有应答；审计文件系统被冻结、每次写都阻塞时 60/60 在 1 秒内应答，解冻后文件里有 63 行；审计目录只读时照常应答；审计目录不存在时照常应答（解析器自己建出 0750 的目录）；**审计路径是 FIFO 时解析器照常应答**（没有卡住）。
- 2026-11-15，开发工作站上的 Docker（同一版本 `1.2026.11.09-1240` 的 amd64 镜像在 arm64 上仿真运行；`deploy/verify-smartdns.sh --audit-check` 和 `TestSmartDNSAuditRealBinary`）：多个应答写在同一行、用「逗号加空格」分隔，顺序会轮换；IPv6 客户端写成它的地址（`::1`），双栈监听上的 IPv4 客户端写成普通 IPv4；名字被解析器转成小写、其余**不转义**（空格、逗号照写），245 字节的名字整行约 350 字节；解析器在**打开**审计文件时把它改成 0640（启动时，以及每次轮转后的新文件；预先建好的 0600 文件也被改），其它时候不动权限；别的进程把审计文件截成 0 之后，下一行从文件开头写起（追加方式打开）；写满的 tmpfs 上 200/200 有应答；审计目录只读时照常应答（不写）；审计目录不存在时解析器自己建目录（0750）并照常应答；上游不可达时同一个名字的 A 查询等了约 2.5 秒、随后的 AAAA 查询 0–1 ms 就空着返回（所以「很快的空结果」不等于名字不存在）；轮转文件由解析器在后台压缩；**审计路径是 FIFO 时解析器照常应答**（20/20），与网关上脚本的结果一致。冻结文件系统那一项在工作站上**没有执行**（需要 Linux root）。
- 没有观察过：别的 SmartDNS 版本；宿主上的 `smartdns.service`；启用了 userns-remap 的 Docker（容器里的 root 不是宿主的 uid 0，审计文件会写不进 0700 的目录）；真实流量下的写入速率；SmartDNS 文档里的 `audit-SOA` 等其它审计选项（没有使用，也没有试）。

**谁写、谁读、文件在哪。**

- 解析器（容器里的 root，也就是宿主的 uid 0）只往 `/var/lib/meridian-dnslog/raw/audit.log` 追加，自己按 `audit-size 2048k`、`audit-num 1` 轮转。这个目录是容器**唯一的可写挂载**（`deploy/docker-compose.yml`，`compile.SmartDNSWritableDirs`；其余四个挂载仍是只读），日志关闭时是空的。`deploy/debian/install.sh` 先把它建成 0700 root（否则 Docker 会以 0755 自动建）。
- 读取服务 `meridian dns-journal`：root、**没有任何 capability**（`CapabilityBoundingSet=` 为空——审计文件属宿主 uid 0，属主位就够，不需要 `CAP_DAC_OVERRIDE`）、`ProtectSystem=strict`、只有 `AF_UNIX` 和 `AF_NETLINK`（状态套接字和邻居表）、`IPAddressDeny=any`、`Nice=10`、`CPUWeight=20`、`IOSchedulingClass=idle`、`MemoryMax=96M`。它只读（以及为守住上限或清空而删除、截断）`raw/` 里的普通文件，把记录写进 `/var/lib/meridian-dnslog/journal/`（不挂进任何容器）。为什么是独立的固定服务而不是宿主代理：宿主代理是按请求执行固定动作的边界，不该常驻读文件、也不该持有这份数据；独立进程可以没有 capability、没有网络、最低的 CPU / I/O 优先级，停了、崩了都不影响解析器（解析器只管往自己的普通文件追加）。
- 权限：`StateDirectory=meridian-dnslog`（`/var/lib/meridian-dnslog`，0700 root），`raw/` 和 `journal/` 0700，文件 0600。解析器每次打开审计文件会把它改成 0640（见上），读取服务每秒把 `raw/` 里的普通文件改回 0600、删掉任何不是普通文件的东西；任何时刻挡住其他本地用户的是 0700 的目录。只有 root 能读，没有服务账号。
- **审计文件在解析器启动前必须是普通文件，而且只会是普通文件。** 这是预防，不是因为观察到过故障：早先那次手工的 FIFO 试验没有结论，脚本化的核对在真实网关和工作站上都没有发现 FIFO 让解析器停止应答（见上）。但特殊文件在这个路径上没有任何正当用途，解析器遇到它时的行为也不是可以依赖的东西，所以路径由我们准备、由宿主代理在重启解析器之前核对。读取服务的单元在 `ExecStartPre` 里执行 `meridian dns-journal --prepare`（`dnsjournal.PrepareSink`）：目录不存在就建、改成 0700（目录路径是别的东西——包括符号链接——就报错不动）；审计路径不存在就以 `O_EXCL|O_NOFOLLOW` 建 0600 的空文件，是普通文件就只改权限、保留内容，是 FIFO、套接字、设备或符号链接就删掉换成普通文件（目录是我们自己的、只有 root 能进）。安装时宿主代理先重启读取服务（`ExecStartPre` 跑完才算启动），再用 `dnsjournal.CheckSink` 自己看一遍（不跟随链接、不改任何东西：目录是真目录、0700、属 root；文件是普通文件、0600、属 root），不满足就**不重启解析器**、安装失败并补偿。网关的 `meridian-verify.sh` 有同样的检查 `dns_log_sink`。
- 状态套接字 `/run/meridian-dns-journal/status.sock`：0666、目录 0755，只回答对端 uid 0（`SO_PEERCRED`，与嗅探服务同一个 `sniff.ListenStatus`）。

**生成文件的变化。** 开关关闭：没有任何变化。打开时网关的文件恰好变三个（别的节点一个都不变）：

- `etc/smartdns/smartdns.conf` 多出一段注释和四条指令：`audit-enable yes`、`audit-file /var/lib/meridian-dnslog/raw/audit.log`、`audit-size 2048k`、`audit-num 1`（其余行不动）；
- 新增 `etc/systemd/system/meridian-dns-journal.service`；
- `usr/local/sbin/meridian-verify.sh` 多一段检查（`dns_log_reader`、`dns_log_sink`、`dns_log_journal_dir`、`dns_log_budget`、`dns_log_status_socket`、`dns_log_config`，以及待人工执行的 `dns_log_real_binary`）。

Compose 文件里的可写挂载是**静态**的一行，不随开关变化：它由操作者重建解析器容器生效（`docker compose --profile dns up -d`，面板的安装不会、也不能重建容器），门槛据此判断；没有重建时功能不可用并说明。**安装对解析的影响**：`smartdns.conf` 变了，安装照例 `docker restart meridian-smartdns`（打开一次、关闭一次），解析中断到容器重新起来为止（约一两秒；缓存本来就不跨重启保留）；网关上的其它单元与任何一次安装一样被重启。

**记录。** `dnsjournal.Record`：`time`（见「时间」）、`client`（地址，去掉 IPv4 映射前缀）、`mac`（未知时没有）、`name`（小写，去控制字符，最多 253 字节）、`qtype`（数字；面板按 `qtypes` 表显示 A / AAAA / HTTPS…）、`result`、`group`（解析器写的组名）、`elapsed_ms`、`answers`（结果里是地址的条数）、`answers_other`（不是地址的条数）。取不到的字段留空表示未知，不编造。解析器是右锚定的：名字是 `query ` 与行尾**最后一个**「`, type N, time Nms, speed: Xms, group G, result R`」之间的全部内容，所以名字里自带这样一段文字也改不了自己这一行的类型、组和结果。不合格式的行只计数（`bad_lines`、`too_long`），**不保存、不打印、不进系统日志**。

**结果（`result`）只有三类，都来自「结果是否为空」和「耗时」**，因为审计行里没有应答码：

- `answered`：至少有一个应答。
- `no_answer`：结果为空，耗时不到 1.5 秒（`SlowEmptyMS`）。名字不存在（NXDOMAIN）是这样；名字存在但没有所问类型的记录、上游很快拒绝或不可达也是这样，**分不开**。
- `no_answer_slow`：结果为空，耗时 1.5 秒以上。上游失败或超时是这样（观察到 2–2.5 秒）；很慢的「不存在」也是这样，所以界面只说「多半是失败或超时」。
- **被规则拦下**不是一类：被网关解析器自己的规则回答的名字（屏蔽的 DoH 域名等）在观察到的版本上根本没有审计行，它们**不在日志里**，也不会被算进别的类别。`force-AAAA-SOA` 之下被空答的 AAAA 是否有审计行没有观察过。筛选另有 `no_answer_any`（两种空结果）。

**解析组。** 记录里的 `group` 是 SmartDNS 配置里的组名（`default`、`domestic`、`g_<出口>`、`rg_<地区组>`、`unlisted_split`）。面板用同一份编译计划把它们映射回对象（`compile.DNSLogGroups`，随每个日志接口返回 `groups`）：国内解析器、默认去向（默认出口 / 默认地区组；开了未列名单检查时是 meridian-dns-split）、某个出口、某个地区组。拓扑改过之后旧记录里不再存在的组名按原样显示。上游是哪一台服务器审计行里没有。

**时间。** 审计行的时间戳没有时区，而解析器容器的时区不一定是宿主的。读取服务每次读到文件末尾时用**审计文件自己的修改时间**对它的最后一行（取整到 15 分钟、±14 小时以内、两者相差不超过 5 分钟才采用）定出偏移，记录的 `time` 是换算后的 UTC；定不出偏移时记录用读到它的时间并标 `time_approx`。

**设备身份。** 与连接日志相同：设备就是局域网地址，备注名共用同一套（`sniff_device_labels`）。`mac` 是读到这一行时内核邻居表（`--neigh-if`，与嗅探服务同一个 `sniff.NeighborTable`）里的值，只对新鲜的行（30 秒以内）查；重启后从轮转文件补读的行、读得太晚的行、邻居表里没有的地址、远程接入设备（本来就没有 MAC）都是未知。按设备汇总列出一个地址在时间范围内出现过的全部 MAC（最多 4 个，多于一个说明地址换过设备）和没有 MAC 的条数。**双向跳转**不只靠地址：`GET /api/dns-log/related`（从一条查询找连接）和 `GET /api/sniff/journal/related`（从一条连接找查询）按地址加一个有界的时间窗（前后各 120 秒，最多 600 秒）查另一份日志，调用方带上这条记录的 MAC 时，另一边**带着不同 MAC**的记录被排除并计数（`other_mac`），没有 MAC 的记录保留并计数（`no_mac`）；回答里的 `identity` 说明依据：`mac`（列出的每条都是同一个 MAC）、`partial`（有的没有 MAC）、`address`（没有 MAC 可比，只按地址和时间窗）。

**上限（一个预算，先到的生效）。** 默认 24 小时、50000 条、32 MiB。字节预算覆盖这个功能持有的一切（`dnsjournal.SplitBudget`）：

- 审计一侧 8 MiB：`raw/` 里的审计文件、轮转副本和任何别的文件。解析器自己的轮转（2 MiB 一份、留 1 份）正常情况下远低于此；读取服务每秒核对一次，超出时先删最旧的轮转副本，审计文件自己就超出时把它截断（计数 `raw_deleted`、`raw_truncated`）——不依赖解析器守规矩。
- 审计一侧的时间上限就是 `--max-age`（`TailConfig.MaxAge`，与结构化日志同一个值，默认 24 小时）。只靠字节上限不够：查询少的网关上审计文件很久到不了 `audit-size`、不会轮转，里面的地址和名字会比结构化日志里对应的记录多留很久。读取服务每秒核对：
  - **轮转副本和 `raw/` 里别的文件**：最后一次写入（修改时间）早于上限就删；轮转副本的第一行（也就是最旧的一行，gzip 开头不超过 8 KiB 里的第一条审计行，每份副本只读一次）早于上限时也删，不等它最新的一行过期。副本只在重启后的第一次打开时用来补读，而补读在同一轮里先于清理，所以没读过的行先被取走。计数 `raw_expired`。
  - **审计文件本身**：只截断、不删除、不替换（`O_NOFOLLOW|O_NONBLOCK` 打开、确认是普通文件后 `ftruncate`；按字节上限的截断和「清空」也走同一个函数），它一直是解析器开着的那个 inode，解析器以追加方式接着从文件开头写（见上面的观察）。条件是**读取位置在文件末尾**（每一行都已经交给结构化日志）、没有读到一半的行，并且满足其一：第一条审计行按它自己的时间戳早于上限；读取服务打开它（或上一次看到它是空的）已经超过上限——这一条不依赖时间戳和时区，按单调时钟计算，改宿主时钟不影响；文件最后一次写入早于上限（整份都过期了，这时读到一半的行也不再等）。截断前重新打开核对一次「还是同一个 inode、长度还等于已读长度」，截断后立即保存读取位置（inode、偏移 0），重启不会拿旧偏移去读新内容。计数 `raw_age_truncated`（与 `raw_truncated` 分开：后者会丢掉没读的行，这个不会）。截断连同文件里还没到上限的行一起清掉——它们已经在结构化日志里。
  - 所以读取服务运行期间，`raw/` 里的内容最多比上限多留一个核对周期（1 秒；积压时等到读完）。**做不到的**：核对与截断之间的一瞬间解析器恰好追加的一行会丢（不让解析器等待就关不掉这个窗口；正常情况下每个保留周期至多截断一次）；时间戳定不出时区、文件又一直有写入时，退回到「打开或上次为空起满上限」，重启会让这个计时重新开始；读取服务不运行时没有任何时间上限（见下）。
- 交接队列 2 MiB（2048 条 × 每条最多 1024 字节，在读取服务的内存里）：读取与写盘之间的队列，满了就丢弃并计数（`dropped`）。
- 结构化日志 22 MiB：分段文件 `dns-<首个 id>.jsonl`，一段到 1/16 字节、1/8 条数或 1 小时就换段，写入前删最旧的段直到满足三个上限（做法与连接日志相同，按 4 KiB 块取整的余量已扣除）；查询从不显示 24 小时以前或最新 50000 条以外的记录。
- **最坏磁盘占用 30 MiB**（8 + 22；队列在内存里），外加读取位置文件不到 1 KiB。读取服务一次最多读 256 KiB（洪水时它落后、丢行，不多占内存或队列）；轮转掉的文件里超过一次读取量的剩余部分直接放弃并计数（`skipped_bytes`），所以不会长时间持有已删除的文件。**读取服务停止期间**审计一侧只由解析器自己的轮转约束（观察到 `audit-size` 有约三成的超出：约 2.7 MiB 的审计文件加一份压缩副本，压缩进行中短暂再多一份），没有时间上限（重新启动后的第一轮核对补上），结构化日志不增长。

**读取服务经得起什么。** 轮转（它一直开着文件，改名之后先把旧文件读完再从头读新文件；用真实二进制核对：900 次查询跨一到两次轮转恰好 900 条记录）；截断（文件比读取位置短就从头读；它自己为时间上限做的截断不算在 `truncations` 里）；自己重启（读取位置——inode、偏移、最后一行的时间戳——存在日志目录里；停机期间发生过轮转时，从 gzip 轮转文件里补读比最后一行新的行，最多 1500 条，其余计数）；半行（留到下一次）；超长行（跳到下一个换行，计数）；日志目录打不开（照常守住审计一侧的上限，读到的行丢弃并计数，日志请求回答 404）。写入失败丢弃并计数，至少隔 1 秒再试。

**安装：打开和关闭都走预检 → 确认 → 安装。**

- 开关只由 `PUT /api/dns-log` 写（独立资源：整份拓扑保存和导入都不能改它）。打开要求请求里带 `acknowledge: true`（界面先说明记什么、在哪、留多久）并且门槛满足；保存后**什么都还没发生**，`GET /api/dns-log` 显示 `pending: "enable"`。
- 预检显示差异（上面三个文件）和一条说明（`dns_log_enable`：解析器会重启一次、之后保存什么、核对过的版本）；门槛不满足是阻断项。
- 安装时宿主代理的 `activate`：重启各单元（读取服务的 `ExecStartPre` 准备好审计文件）→ 准备重启解析器 → 已安装的配置开启了审计时（`dnsAuditGuard`）：配置里的审计文件必须正是固定路径、门槛必须满足（代理自己重新读版本和挂载）、审计目录和文件必须如上所述，任何一项不满足这一步失败、**解析器不重启**、安装事务补偿回上一版 → `docker restart` → 向本机解析器问一个固定问题（`dns.google`，生成的配置自己回答它，不发往上游；任何格式正确的回答都算），20 秒内没有回答（解析器在运行却不服务，不论原因）安装同样失败并补偿。
- 关闭：保存后仍在记录（`pending: "disable"`）；预检说明「安装成功之后删除已有记录；取消预检或安装失败时继续记录、记录保留」（`dns_log_disable`）；安装把配置恢复成没有审计指令的样子、重启解析器、移除读取服务——**不删数据**（宿主代理移除这个单元时不做 `systemctl clean`，因为之后的补偿可能把它装回来）。安装事务**提交之后**，面板才请求宿主代理清空（`dnsLogAfterCommit`：只在这次事务提交并且移除了读取服务的单元时；运行时回滚到没有它的快照、恢复未完成的事务同理）。清空失败不影响安装，报告里给出警告，`GET /api/dns-log` 显示还留着多少数据并可以再清。取消预检、安装失败并补偿：照常记录，数据不动（`TestDNSLogInstallLifecycle`）。
- 已知边界：网关「撤回」不重启解析器（现有行为），已载入旧配置的容器会继续写审计文件直到下次重启；这时读取服务已移除，数据留在原处，面板显示有残留并可清空。解析器镜像在面板之外被换成没有核对过的版本时，已安装的采集仍在进行：`GET /api/dns-log` 标出 `unverified_running`，下一次安装会被门槛拦下，直到关闭开关或核对这个版本。

**宿主代理（`hostexec/dns_journal.go`）：只有固定请求。** `POST /v1/dns/journal/status`（不接受参数；只读：两条固定的 docker 读取、本机记录、门槛结论、已安装配置里的审计指令、审计目录和文件的状态、读取服务的单元和健康读数、两个固定目录里的文件数和字节数）、`POST /v1/dns/journal`（一页；参数只有 `device`、`mac`、`result`、`group`、`from`、`to`、`text`、`before`、`limit`，逐个校验，未知字段拒绝）、`POST /v1/dns/journal/summary`（`from`、`to`）、`POST /v1/dns/journal/clear`（不接受参数）。读取和汇总各自向读取服务的状态套接字发一个固定请求，回答有界、检查是 JSON 后原样转交，不合格的请求到不了读取服务，代理不打开日志文件、不记录回答内容。清空：读取服务在运行时经它的固定清空（记录、轮转副本、审计文件的内容——审计文件被截断而不是删除，仍是解析器开着的那个普通文件）；读取服务不在时（关闭后被移除，或已停止）代理自己从两个固定目录删除固定名字的文件（`dnsjournal.PurgeData`），这是它在那里唯一的写操作，所以 `meridian-host.service` 的 `ReadWritePaths` 多了 `/var/lib/meridian-dnslog`。没有任何路径、命令、容器名或文件名来自调用方。

**清空如实报告（`dnsjournal`：`Journal.Clear`、`Tailer.Clear`、`Daemon.Clear`、`PurgeData`）。** 清空的每一步——列目录、看文件、删除、截断——失败都进结果，不再被吞掉：

- 结果是 `ClearResult`：`complete`（全部删掉才为真）、删掉了多少、`residual`（还留着的分段数 / 条数 / 字节数，审计目录的文件数 / 字节数，`unknown` 表示有目录或文件读不到）、`errors`。错误只有固定的词——哪一侧（`journal` / `raw`）、哪种操作（`readdir` / `lstat` / `remove` / `truncate`）、哪一类原因（`permission`、`read_only`、`busy`、`no_space`、`io`、`other`）、次数——路径、文件名和系统的报错文本不离开这个包。读取服务对清空总是回答 200，是否完成只看 `complete`。
- 结构化日志只把**确实删掉**的分段移出索引。删不掉的留在索引里：仍回答查询、仍计入统计（`stats.residual`）和字节上限，下一次清空再删；它们的文件名写进日志目录的 `clear-pending.json`，重启后据此重新标成残留，而不是当成新写的记录（标记里记着当时的下一个 id，id 不会回退到与残留重名）。因上限到期而删除失败的分段同样留在索引里，随每分钟的清理重试；清空留下的残留只在超过时间上限后才由清理重试，其余等下一次清空。
- 清空在写入协程里、两批写入之间执行，排队中还没写盘的记录随清空丢弃，所以清空之前读到的行不会在清空之后写进日志。读取（`Daemon.Step`）和清空互斥：清空审计一侧与清空结构化日志之间不会插进一轮读取，两次清空也不会交叠。
- 审计一侧：先截断审计文件，再删副本（解析器此刻轮转出来的新副本由后面的几轮列目录接住）。审计文件截断不了时，读取位置定在它当时的末尾并立即存盘，重启后也从那里接着读，旧内容不会被重新读入；删不掉的副本不会被重启后的补读读回（最后写入早于清空的副本不打开，其余副本里早于清空的行按时间丢弃；时区未知时有残留期间补读整个跳过）。清空的时间和没截断的那个文件（inode、当时的长度）记在读取位置文件里；读取服务每轮核对据此数出还剩多少（`reader.clear_pending_at`、`raw_residual_files`、`raw_residual_bytes`），残留被上限删除或被下一次清空删掉后这条记录消失。
- 宿主代理：读取服务在运行时把它的回答判成成功（`complete: true`）、`clear_incomplete`（带 `ClearResult`）或 `clear_unconfirmed`（回答里没有 `complete`：旧版读取服务，不能当作已清空）；读取服务不在时 `PurgeData` 同样报告没删掉的部分，并为之后启动的读取服务留下残留标记和读取位置（没清掉的审计内容不会被读进日志）。
- 面板：`POST /api/dns-log/clear` 只在全部清除时回答 200 `{"complete": true}`；`clear_incomplete` 是 500 `dns_log_clear_incomplete`（`complete: false`、`residual`、`errors`、`removed`），其余失败是 503 `dns_log_clear_failed`。`GET /api/dns-log` 的 `runtime.clear_residual` 来自读取服务的健康读数，所以页面的残留提示和「重试清空」在刷新和读取服务重启之后仍在。关闭并安装之后的自动清空没有全部完成时，安装报告的警告写明还留着什么。

**面板 API**（都走面板口令）：`GET /api/dns-log`（开关的计划值与已安装值、`pending`、门槛结论和原因、读取服务状态、上限、范围说明、组名和类型的对照）、`PUT /api/dns-log`、`GET /api/dns-log/journal`（筛选：设备、MAC、结果类别、组、时间范围、名字文本；游标翻页，每页最多 200）、`GET /api/dns-log/devices`（按设备汇总：总数、各结果、各组、问得最多的 10 个名字、首次 / 最近出现、MAC；加备注名）、`POST /api/dns-log/clear`（`{"confirm": true}`）、`GET /api/dns-log/related` 和 `GET /api/sniff/journal/related`（双向跳转）。未知或非法参数在问宿主代理之前拒绝。页面是「解析与日志」分组里的解析日志（`#/dns-log`，`web/src/DNSLogsPage.tsx`）：开关与状态（门槛不满足时只有原因和处理办法）、按设备汇总、查询记录及筛选、清空、记录范围，以及与连接日志之间的跳转。

**演示数据。** 演示预览里的解析日志不是手写的记录：`internal/api/demo_fixtures_test.go` 的 `demoDNS` 让真实的读取服务（`dnsjournal.Daemon`：解析、时区推定、MAC 查询、有界日志）在临时目录里读一份合成的审计文件（观察到的行格式、演示局域网的地址、文档 MAC、`example` 名字），时钟由生成器推进。正常场景里每条合成连接之前两秒有同一设备对同一名字的查询，所以两份日志可以互相跳转；降级场景是一个观测不全的读取服务留下的样子（半行审计行只计数、定不出时区的记录标 `time_approx`、读取服务停止期间的行补读后没有 MAC、一个地址两个 MAC），旁边是一个版本没有核对过的解析器（`unverified_running`）。

**隐私边界。** 日志内容只经过上面几个处理函数：面板不存、不记日志，不进入拓扑、编译结果、差异、预检记录、安装报告、部署记录、状态读数、导出和演示数据（`TestDNSLogNeverLeaves`：读过日志、做过预检和安装之后，演示用到的所有读取接口、只读 POST、存储的拓扑和预检、写到宿主和数据目录的每个文件、面板日志里都查不到日志内容）。读取服务和宿主代理的系统日志只有计数和固定文字。删除是 unlink / 截断，不做覆写擦除。

### 链路日志（`internal/linkjournal`）

**是什么。** 网关上一个只读的采集服务 `meridian link-journal`（单元 `meridian-link-journal.service`），把网关的路径和链路的**状态变化**记成事件：承载路径（主链路经哪条腿或哪台中继、切到备用枢纽、切回）、中继在分担里被剔除和恢复、每条隧道的握手超时与恢复、WSS 伴随承载的连接与断开、网关对外部出口和其它自检目标的检查由通过变为失败及恢复。它记的是变化，不是周期采样：每条事件有时间、对象、从什么状态到什么状态、来源给出的原因和依据、之前那个状态被观察到持续了多久。事件里只有拓扑里的名字（链路、节点、地区组、接口）、状态词和原因；**没有任何来源读取设备地址、域名、连接或其它流量内容**。

**来源清单（`linkjournal/sources.go` 顶部的表、`linkjournal.Inventory()`、`GET /api/link-log` 的 `scope.sources` 是同一份）。** 采集服务只读网关本机的状态，不开 IP 套接字、不发任何包、不联系别的节点。

| 事件类别（`class`） | 来源 | 怎么读 | 频率 | 依据的强弱 |
| --- | --- | --- | --- | --- |
| 承载路径 `path`（有备用枢纽，或多中继分担） | 故障切换服务的记录 `upstream_record` | 读它每一轮写的固定文件 `/run/meridian/upstream`（限长 8192 字节，按固定格式严格解析；两种格式都认） | 每 10 秒读；服务每 5 秒写 | 直接：切换是故障切换服务自己的决定。「全部不通 / 勉强承载」是它经每条路径 ping 枢纽的探测结论 |
| 承载路径 `path`（单中继、无备用枢纽） | 路由表 `route_table` | 固定参数的只读命令 `ip -4 -o route show table 102` | 每 10 秒 | 直接：内核路由本身。这种拓扑的故障切换脚本不记录它的选择，所以只有切换，没有探测结论和原因 |
| 中继分担 `relay`（及每台中继用的腿、路由表 102 跟随的中继） | 同一个记录里每台中继的一行 | 同上 | 每 10 秒 | 直接：分担控制器自己的状态和原因代码；控制器不可用时是按能否 ping 通的回退结论，依据里写明 |
| 隧道握手 `tunnel` | 内核的握手时间 `wg_handshake` | 固定参数的只读命令 `wg show <接口> latest-handshakes`，接口名只取自对象清单并按 `m<两到三位数字>[w]` 校验（不含 `mra`、`mmesh`）；从不执行 `dump`，公钥读到即丢 | 每 30 秒 | 直接，但滞后：超过 180 秒（WireGuard 的 Reject-After-Time）没有新的握手才算超时，所以断开最多晚 3 分钟多才记下；只代表网关这一端 |
| WSS 伴随承载 `wss` | 单元状态 `wss_unit` 加该隧道的握手 | 固定参数的只读命令 `systemctl is-active <单元>`，单元名只取自对象清单并按 `wstunnel-client-….service` 校验 | 每 30 秒 | 间接：客户端进程在不在运行，加上它里面的隧道有没有握手成功。WebSocket 会话本身没有读取 |
| 外部出口 `external_exit` | 嗅探转发服务的自检 `sniff_selfcheck` | 读转发服务状态套接字（只回答 root）的固定请求 `GET /v1/health` 里最近一次自检的结果，取目标 `exit:<外部出口>` | 每 30 秒读；转发服务每 15 分钟自检一次 | 探测：「网关经隧道问这个出口的解析器没有得到回答」，**不是**「代理已确认不通」。开始和结束的时间最多有 15 分钟的误差，短于 15 分钟的中断可能记不到 |
| 自检目标 `sniff_target` | 同上，其余目标（地区组、出口、直连） | 同上 | 同上 | 探测：那一刻该目标的解析器可达；地区组的结果反映枢纽当时使用的成员 |
| 采集本身 `collector` | 采集服务自己 | 两次采集的间隔、每个来源的读取结果、对象清单的摘要 | 每 10 秒 | 直接 |

**不在记录范围内**（`linkjournal.NotInScope()`，接口里的 `scope.not_in_scope`，页面照此标明）：

- 承载节点上的外部出口健康检查 `meridian-ext-health`：它在承载节点上运行，结果只在那台节点的本地状态和日志里，网关没有任何现有的固定通道读得到。这一轮**不为它在远端节点新增任何能力**；最接近的是上表「外部出口」一行的网关自检。
- 地区组在枢纽上当前使用哪个成员、何时切换：由枢纽决定，面板需要时经 SSH 读一次，网关上的采集服务读不到。
- 中继和枢纽自己的故障切换、隧道对端一侧的握手。
- 解锁探测与出口确认的结果：由面板发起、存在面板里，不在网关宿主机上；这一轮没有把它们转成链路事件。
- 远程接入 `mra` 各设备的握手（那是设备是否在线，不是链路；采集服务从不读 `mra`）。
- 任何流量内容。

外部出口还有一条限制：转发服务只自检**被规则或默认去向直接指向**的出口和地区组。只作为地区组成员的外部出口没有自己的自检目标，网关不单独检查它；嗅探关闭时网关对任何出口都没有检查。`GET /api/link-log` 的 `scope.externals` 逐个外部出口写明是哪种情况，`scope.unobserved` 列出清单里有但现在没有读数的对象（关闭了保活的隧道、当前没有被自检的目标）。

**采集服务在哪里运行、为什么。** 一个独立的单元，不放进故障切换脚本、嗅探转发服务、宿主代理或面板：面板容器停止或升级时它要继续采样；它不能有能力扰动转发和故障切换，所以与它们不共用进程、不共用它写的任何文件、不共用锁，只读它们公开的状态；宿主代理保持为只按请求动作的边界，不带后台任务；它崩溃只丢读数。单元（`compile.RenderLinkJournalUnit`）：root，`CapabilityBoundingSet=CAP_NET_ADMIN`（内核只对有这个能力的调用者回答 WireGuard 设备查询，这是 `wg show` 所需；别的地方都不用它），`RestrictAddressFamilies=AF_UNIX AF_NETLINK`、`IPAddressDeny=any`（开不了 IP 套接字），`ProtectSystem=strict`（除自己的 `StateDirectory` 外全部只读，`/run/meridian` 也只读），`Nice=10`、`CPUWeight=20`、`IOSchedulingClass=idle`、`MemoryMax=96M`，没有对任何单元的依赖。它执行的程序只有三个（`wg`、`systemctl`、`ip`，各只有一种固定参数形式，绝对路径，不经 shell、不查 PATH），名字在读对象清单时校验、执行前再校验一次（`TestFixedArgumentLists`）。**如实说明**：`CAP_NET_ADMIN` 在内核看来也足以改路由和接口；采集服务的代码不做这种事，但「不能」靠的是代码里只有这三种只读调用，不是内核强制。

**对象清单 `/etc/meridian/link-journal.json`**（`compile.linkJournalConfig`）是采集服务读什么的唯一依据：网关的隧道接口（链路、对端、模式、保活）、wstunnel 客户端单元、承载路径的记录方式（`single` / `dual` / `share`）和每条路径，以及开启嗅探时每个自检目标名对应哪个出口或地区组、是不是外部出口、由谁承载。它列的是**全部可能的**自检目标名，不随解锁决定变化，所以解锁的自动安装不会因为它被拒绝（它不在 `DecisionFiles` 里，`TestLinkJournalConfigIgnoresDecisions`）；自检结果里没有的目标就没有读数。保活为 0 的隧道不读（空闲的隧道不会重新握手，握手时间说明不了通断）。采集服务读清单时逐个校验名字并拒绝未知字段；清单的数量上限高于拓扑能编译出的数量（99 条链路、240 个出口与地区组标记），所以编译得出的清单不会被拒绝——被拒绝的清单会让采集单元启动失败，进而让带着它的那次安装失败。同样的考虑下，日志目录里个别读不了的分段只丢它自己的事件，不阻止采集服务启动。

**从读数到事件（`linkjournal/journal.go`）。**

- **基线**：第一次读到某个对象只记下状态，不产生事件；不知道它何时开始，持续时间按「至少」（`since_open`、`prev_open`）。
- **变化**：读数与记下的状态不同，产生一条事件，带之前状态被观察到的时长 `prev_for_s`。
- **空窗**：某个对象超过 120 秒没有读数（采集服务没有运行、来源读不到、时钟被调回），这段时间它的状态未知。任何持续时间都不跨过空窗：状态没变的重新开始计时（标为「至少」）；变了的事件带 `after_gap`（空窗的起止），之前状态的时长只算到空窗前最后一次读数。整个采集的空窗另记一条 `collector` 事件（从 `unknown` 到 `collecting`，原因 `restart` / `stall` / `clock`）。某个来源连续 3 次读不到记一条「来源读不到」，恢复时再记一条。
- **重启**：对象的状态、开始时间和未结束的抖动合并记录都在检查点里（每条事件之后写、此外每分钟写一次，先写临时文件再改名）。重启后第一次采集与检查点比较：状态没变就没有事件，不论停了多久。没有检查点（首次启动、清空之后）时第一次采集是基线。事件写入和检查点写入之间崩溃时，重新打开会按磁盘上较新的事件修正记下的状态，不会把同一次变化记两遍。
- **抖动**：同一个对象 10 分钟内的前 4 次变化各记一条；之后的变化合并成**一条**记录，保留次数、第一次和最后一次的时间、合并前和合并后的状态，文字是「变化了 N 次……不是一次连续的中断」。对象安静 10 分钟后写入这条记录，一直不安静则每小时写一条。合并中的记录在查询和当前状态里可见（`open`）。
- **写入上限**：此外每小时最多写 600 条事件，超出的丢弃并计数（状态仍然跟踪）。

**存储与上限。** `/var/lib/meridian-linklog`（单元的 `StateDirectory`，0700，文件 0600，属 root；目录或文件是符号链接时不使用）。三重上限先到者生效：30 天、20000 条、16 MiB。16 MiB 是整个目录的预算（`SplitBudget`）：事件分段文件约 15 MiB，检查点及其临时副本 2×260 KiB，删除过期事件时重写一个分段的临时副本 516 KiB。单条事件不超过 1024 字节（文字先截短），实际最大约 700 字节，所以默认上限下先到的是条数：最坏情况约 13.3 MiB（`TestDefaultBoundsWorstCase`）。超出时删最旧的分段；过期事件每小时从最旧的分段里去掉一次，两次之间查询也不会返回过期事件。

**读取与清空。** 采集服务的状态套接字 `/run/meridian-link-journal/status.sock`（0666、目录 0755，只回答对端 uid 0）有四个固定请求：`GET /v1/health`、`GET /v1/current`、`GET /v1/events`（筛选参数逐个校验）、`POST /v1/clear`（不接受参数）。宿主代理（`hostexec/link_journal.go`）对应四个固定请求 `POST /v1/link/journal/status`、`/current`、`/v1/link/journal`、`/clear`：参数先在代理里校验，回答原样转交；代理自己不打开日志的任何文件，唯一执行的命令是固定的 `systemctl is-active meridian-link-journal.service`。采集服务没有运行时清空不做任何事并说明原因（代理不碰那个目录，`meridian-host.service` 没有为它增加可写路径）。清空删除全部事件、已记下的状态和检查点，之后的第一次采集重新建立基线。

**面板 API**（都走面板口令）：`GET /api/link-log`（是否已安装、是否有待安装、采集服务状态、上限、时间参数、范围说明、本拓扑的对象清单）、`GET /api/link-log/current`（当前状态：现在由哪条路径承载、探测结论、所有处于异常状态的对象及已持续多久和依据、读不到因而状态未知的对象、正在抖动的对象）、`GET /api/link-log/events`（时间线，新的在前；筛选 `class`、`kind`、`id`、`from`、`to`，游标 `before`，每页最多 500）、`POST /api/link-log/clear`（`{"confirm": true}`）。没有数据时返回原因而不是空白：`not_installed`、`not_running`、`agent_old`、`agent_unavailable`、`read_failed`。日志内容只经过这几个处理函数，面板不存、不记日志，不进入拓扑、快照、导出、预检记录或诊断（`TestLinkLogNeverLeaves`）。页面是链路日志（`#/link-log`，`web/src/LinkLogsPage.tsx`）：当前状态、事件时间线及筛选、观测范围。

**演示数据。** 演示预览里的时间线是真实的采集服务记下的：`demoLink`（`internal/api/demo_fixtures_test.go`）用演示拓扑编译出的对象清单建一个 `linkjournal.Collector`，来源换成合成的读数（按故障切换记录的语法写的记录、`wg show … latest-handshakes` 和 `systemctl is-active` 的回答、嗅探自检结果），在生成器推进的时钟上每 20 秒采集一次，共两小时。正常场景：到第一台中继的 UDP 腿停了 18 分钟（握手超时、改走 WSS 腿），网关对外部出口的自检失败过 45 分钟，都已恢复。降级场景在此之上：采集服务停了 9 分钟（空窗），UDP 腿在空窗里断掉（空窗后才发现）；到第二台中继的隧道每分钟抖动一次（前 4 次单独记，其余合并，仍在计数）；两台中继先后被剔除、备用枢纽承载；单元状态读不到（来源读不到、WSS 承载状态未知）；外部出口的自检再次失败。

**没有开关，但只经安装生效。** 链路日志不含流量内容，所以不设开关：采集服务是每个网关编译结果的一部分。升级到带它的版本后，**已有拓扑的网关编译结果只有三处变化**：新增 `etc/systemd/system/meridian-link-journal.service`、新增 `etc/meridian/link-journal.json`、`usr/local/sbin/meridian-verify.sh` 多一段检查（三个 golden 文件各恰好这三行，`TestLinkJournalFiles` 核对网关的其它文件和所有远端节点都不提到它）。规则集、路由、WireGuard、解析器配置、故障切换脚本和其它单元都不变。于是升级后网关显示「有待安装的变更」；面板**不会自己在宿主机上启动任何东西**，采集服务只在下一次网关安装（预检 → 确认 → 安装）之后开始运行，预检的文件差异里列出这两个新文件，并有一条说明（`link_log_add`）。安装本身与任何一次网关安装相同：宿主代理重跑 `meridian.service`（`meridian-up.sh`）并重启清单里的单元（故障切换服务、wstunnel 客户端等；嗅探转发服务在只改规则时是重载）。**链路日志没有让安装多重启任何承载流量的东西，但承载流量的单元在这次安装里照常被重启一次**，与以往的网关安装一样。宿主机上的 `meridian` 程序比面板旧（没有采集服务）时，采集单元启动不了、整次安装会失败回退，所以预检里是阻断项 `link_log_host_old`（先在网关上重新运行 `deploy/debian/install.sh`）。验收脚本里链路日志的问题是 `WARN`，不是失败项：它只记录，不承载流量。撤回网关时单元随清单移除，数据（至多 16 MiB，不含流量内容）留在原处，重新安装后接着用，空窗如实记为未知。

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
2. 发布（持 host agent 的动作锁，最多等 `LockWait`，和安装/回滚互斥）：geosite / 关键词文件各自写临时文件后 `rename`，一个名单要么全新要么全旧；chnroute 把所有通过的地址族放进**一个** `nft -f` 事务（每族 `flush set` + `add element`），nft 接受后才替换 `/var/lib/meridian/lists/china*.txt` 和重载副本 `lists/chnroute.nft`。发布后不在锁内重启 SmartDNS，而是请求一次自动读入（下面「名单与 SmartDNS 自动读入」）。

   **名单与 SmartDNS 自动读入**（`internal/hostexec/smartdns_reload.go`）。SmartDNS 只在启动时读 domain-set 文件，没有可用的重载，所以读入就是重启；面板不再提示手动重启。这是 host agent 的固定动作，没有参数、不接受命令：
   - **按内容判定**：对 `geosite/`（含 `geosite/ordered/`）、`keywords/` 下全部 `.txt` 的相对路径和内容算 sha256，等于 SmartDNS 实际读入的摘要（`loaded_digest`）就什么都不做（geosite 按原样重写不算变化）。
   - **已读入摘要只跟真实启动走**：所有受管的 SmartDNS（重）启动——自动读入，以及安装/激活里的 `systemctl restart smartdns.service` / `docker restart meridian-smartdns`（回滚、撤回后恢复都是再执行一次安装，走同一条路径）——都在动作锁内、紧挨重启之前算摘要（名单发布也持这把锁，重启前后文件不会被换），重启成功且 `127.0.0.1:53` 应答之后才记为已读入。没有解析器、重启失败、不应答都不推进摘要。自动读入拿到锁之后才读取当前基线，所以等锁期间安装把 SmartDNS 重启到新文件，它看到的是新基线。安装时没开审计日志的解析器也会被问一次（不算步骤、不让安装失败），不应答只给一条警告。回归：自动读入 A → 安装读入 B → 名单改回 A 会再重启。
   - **首次发布前的基线**：agent 启动时（任何发布之前）记下这些文件的摘要和最近修改时间；SmartDNS 的启动时刻（`systemctl show --timestamp=unix -p ActiveEnterTimestamp`，容器为 `State.StartedAt`）晚于文件最后修改、且不晚于 agent 查看文件时，就以启动时的摘要为可信基线（首次发布内容相同不重启，并把它记下）；否则用上一个 agent 最近一次受管重启记下的摘要；仍无法确定（新装、无记录、取不到启动时刻）就保守地重启一次，成功应答后记下摘要，之后同样内容不再重启。
   - **meridian-dns-split**：China IP 文件内容变了（`chnroute_changed`）时，待执行记录里持久化 `split: true` 和原因 `split_reason`（`cause: "lists"`），合并请求和 agent 重启恢复都保留。真正执行时按**当时**的配置判断是否用 `meridian-dns-split`（`unlisted_domestic_dns`）：没用就只处理 SmartDNS（按摘要）；用了就不看摘要，先重启 `meridian-dns-split`、再重启 SmartDNS（清掉按旧名单决定的缓存），等待期间设置由关变开也照此执行。`meridian-dns-split` 重启失败不阻止 SmartDNS：记下 `split_error`，照常重启 SmartDNS；`last.ok` 为假、`error` 写 dns-split 的原因（并注明 SmartDNS 已读入），`smartdns_ok` 单独表示 SmartDNS 是否重启并应答——应答了仍推进摘要，不会因 dns-split 的失败再空转重启。旧版 agent 留下的待执行记录（没有 `cause`）：SmartDNS 无论摘要都重启一次，dns-split 只在当前配置用它时重启。
   - **合并**：第一次请求后等 10 秒（`DNSReloadWindow`），其间的发布并成一次重启（结果里 `merged` 计数）。
   - **限频**：两次尝试至少隔 5 分钟（`DNSReloadMinGap`，从上次尝试开始算）。间隔内的变化不丢弃，只排一次延后的重启，在间隔结束时执行；重启进行中到来的变化在它结束后照此再排一次。agent 重启时还在等待的那一次会重新排上。
   - **执行**：持动作锁（不和安装/回滚交错；等锁超时记失败，间隔后再试一次），按现有方式找解析器：有 `smartdns.service` 用 `systemctl restart`，否则 `docker restart meridian-smartdns`；都没有就记为成功但不推进摘要（它下次启动读入什么无法确认）。之后每 300 ms 用固定问题（`dns.google A`）问 `127.0.0.1:53`，任何格式正确的应答即算恢复，最多等 20 秒。
   - **记录**：`/var/lib/meridian/lists/smartdns-reload.json`，经 `/v1/lists/status` → `GET /api/lists/status` 的 `status.dns_reload` 返回：`pending`、`due_at`、`cause`、`split`、`split_reason`、`loaded_digest`、`last`（`at`、`ok`、`target`、`merged`、`restart_ms` 重启命令耗时、`answer_ms` 从发出重启到本机第一个应答、`smartdns_ok`、`split_restarted`、`split_error`、`error`）。每次受管重启（自动读入、安装）**之前**先把 `loaded_digest` 清空并落盘：重启命令一旦执行，即使命令报错或应答检查超时，SmartDNS 也可能已经用新文件起来，旧摘要不再可信；只有 SmartDNS 重启并应答才写入新摘要，确认不了时保持未知，下一次名单发布保守地重启（`TestDNSReloadUnconfirmedRestartForgetsOldDigest`）。名单页只在 `last.ok` 为假时显示一行原因，其它情况不显示提示。更新报告的 `dns_restart` 现在只是 `scheduled`（已请求读入）。
   - **中断窗口**：重启期间网关的 DNS 不应答。预估：宿主单元 `systemctl restart` 约 0.3–1 秒，容器 `docker restart` 约 1–2 秒（默认停止等待之外，SmartDNS 收到 SIGTERM 即退出），加上读入名单文件的时间（几十万条 domain-set 时约再 1 秒）；`cache-persist no`，重启后缓存为空，随后几秒的查询要走上游。**本轮没有连接宿主实测**，数字是估计；实际值看 `dns_reload.last.answer_ms`（含 300 ms 轮询粒度，是上界）和 `restart_ms`；人工核对时可在网关上另开 `while :; do dig +time=1 +tries=1 @127.0.0.1 dns.google >/dev/null || date +%T.%N; sleep 0.1; done` 观察无应答的时段。
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

报告里每个名单：`list`（`geosite:<名>`、`keyword:<id>`、`chnroute4`、`chnroute6`）、`updated`、`kept`、`source`、`url`、`count`、`files`、`dropped`、`current`、`attempts[]`（源、URL、是否成功、错误、耗时）、`error`；整体还有 `ok`、`partial`、`dns_changed`、`dns_restart`（`scheduled`：已请求 SmartDNS 自动读入）、`warnings`。进度只有 running → done/failed 两段，不报告单个文件的进度。

宿主侧固定动作 `POST /v1/lists`（`request_id`、`policy`、`lists`、`geosite`、`keywords`，未知字段拒绝）与只读的 `POST /v1/lists/status`，同样需要 agent 口令和 uid 0。分类名只能是 `[a-z0-9][a-z0-9!_-]{0,63}`，最多 64 个，落到同一文件的名称拒绝；关键词 id `[a-z0-9_]{1,80}`、值 `[A-Za-z0-9._-]{1,64}`，最多 64 个；整个更新 15 分钟上限，调用方断开也会跑完并记录。

### 重载后 chnroute

每次 `meridian.service` 重载都重建 `inet meridian`。网关的 `meridian-up.sh` 在检查前把 `lists/chnroute.nft`（只允许 `flush set` / `add element` 两个 chnroute 集合的行）接在编译出的规则后面，生成 `lists/.boot.nft`，仍然只做一次 `nft -c -f` 和一次 `nft -f`；副本有别的行、或与当前规则合起来 `nft -c` 不通过时，忽略副本，只加载编译出的规则（chnroute 为空，直到下次更新）。

## IPv6 和 ROS

网关是 SLAAC 客户端：`accept_ra=2`，因为开了转发之后只有 2 才会收下 RA。不要在这块网卡上跑 radvd，也不要再开一个 DHCP。

测试设备必须自己把 IPv6 默认路由指到网关的链路本地地址，并关掉路由器发现。否则 ROS 的 RA（生存期 2700 秒）会把默认路由写回去，AAAA 和 WebRTC 都会从运营商前缀漏出去。做不到这一点的设备（手机）靠「客户端 IPv6 经本网关」保持关闭：解析器不给走隧道的域名 AAAA，它们的国外访问只走 IPv4 进隧道（见「客户端 IPv6 与 AAAA」）；WebRTC 和直接用 IPv6 地址的连接仍走本地宽带，这一点网关管不到。

国内 IPv6 的下一跳是 ROS 在 bridge 上的链路本地地址。示例里写成 `fe80::1`，上线前改成真实地址。

## 下发顺序

1. NAT 拨出的出口（先把隧道拨起来）
2. 其他出口
3. 香港枢纽（有备用枢纽时先备用、后主枢纽；有 IX 枢纽时它就是主枢纽）
4. 国内中继（只含有启用链路的中继）
5. 网关

没有 IX 时顺序固定为：出口 → 备用枢纽 → 主枢纽 → 启用的中继 → 网关；计划里没有 IX 步骤，已从拓扑删除的 IX 即使还留在服务器清单或安装记录里，也不会被安装、变更或撤回（撤回要在「部署记录与撤回」里明确操作）。

以后改拓扑也按这个顺序：先下发受影响的远端节点，再安装网关。地区组的解析要求成员出口已经装上应答组解析地址的规则（「地区组的解析」），新地区组的中转地址要求枢纽已经有那张组表；网关先装，组内的名字在出口更新前解析不了（不会改问国内或别的出口），组流量在枢纽更新前进黑洞。`APPLY_ORDER.txt` 在有可切换地区组时也写明这一点。

差分看的是上一份已应用文本和这一份编译结果。面板不在宿主上直接执行命令：安装和运行态回滚写入 Meridian 自己的文件后，经宿主上的 `meridian-host`（固定的 activate / health / rollback / withdraw 动作，只接受受管资源名；只读的安装前预检 `/v1/preflight`，只接受校验过的受管路径，见「下发前预检」；另有名单更新 `/v1/lists`、只读的名单状态 `/v1/lists/status`、解锁探测 `/v1/probe` 和远程接入运行状态 `/v1/remote-access/status`，见「名单源」「解锁」「远程接入」）完成 daemon-reload、启动 `meridian.service` 和相关 unit、健康检查，以及删除旧清单独有的接口、unit、nft 表和路由表。每次安装都记录受管清单（文件、接口、unit、nft 表、路由表、sidecar 和版本），回滚按清单求差并只激活目标清单里的接口，不再扫描 `/etc/wireguard/m*.conf`。数据目录快照和宿主网络在同一份持久事务里，失败即补偿，进程重启时恢复；面板的回滚必须明确选择「含宿主网络」或「只回滚数据目录」（后者在已安装时需要显式 `snapshot_only`）。开机时转发保持关闭，`meridian-guard.service` 先装兜底表，`meridian-up.sh` 在防火墙就绪后才打开转发。`meridian.nft` 是单个 nft 事务，只替换 `inet meridian`（网关上还有 `inet meridian_guard` 兜底表），加载失败时旧表原样保留；`meridian-up.sh` 先 `nft -c` 再 `nft -f`，并且在打开转发和装路由之前完成。网关在路由层没有按入口接口的 `iif … unreachable` 规则（IPv4 和 IPv6 都没有）：从局域网（或 `mra`）转发、既没有国内 mark 也没有出口 mark 的包由兜底表在 forward 上丢弃，原因见下面「局域网兜底」。细节和尚未在 Linux 上验证的部分见 [验收清单](verification.md#防火墙原子替换与-lan-兜底)。

### 局域网兜底

两层，IPv4 和 IPv6 相同：

- **`inet meridian_guard`**（独立的 nft 表，forward 钩子，优先级 -200）：在打开转发之前加载，开机时由 `meridian-guard.service` 先于主表加载。从受管入口（局域网口，打开远程接入时再加 `mra`）转发的包，只有「国内 mark 从局域网口出」和「出口/地区组 mark 进网关自己的 WireGuard 接口」两种放行，其余（未分类或走错接口）全部丢弃。
- **每个出口和地区组 mark 的 `fwmark X unreachable`**（查完表 102 之后）：隧道路由不在时，已分类的境外流量不会落到主表经 ROS 出去；表 102 和表 100 末尾还有 metric 32767 的黑洞。

旧版本在 IPv4 上另有 `17850: iif <局域网口> unreachable`（打开远程接入时还有 `17851: iif mra unreachable`），想做第二道路由层兜底。它是错的：`rp_filter=2` 时内核校验转发包的源地址，反查用的是 iif = 这个包的**出接口**、mark = 0（`src_valid_mark=0`），于是所有从局域网口（或 `mra`）转发**出去**的 IPv4 包都会命中这条规则、反查失败，被以 `EXDEV`（`ip route get` 显示 `Invalid cross-device link`）丢掉——国内直连的回绕、隧道回到局域网客户端的回程、设备的国内流量和回程都不通。以前的测试只数出去的包、国内只测了 IPv6，所以没发现。这两条规则已删除，`meridian-routes.sh` 每次运行都按优先级、接口和动作删掉旧版本留下的那两条（升级不用重启就恢复）；`meridian-verify.sh` 发现它们时报 `FAIL no_stale_iif_rule`，并用 `ip route get … iif …` 让内核实际判一次这些路径（`route_*` 各项）。`fwmark X unreachable` 不受影响（反查的 mark 是 0），保留。`rp_filter` 仍是 2。

没选的两种做法：保留规则、把每个接口的 `rp_filter` 设成 0（能通，但正确性依赖每个接口的 sysctl 都是 0，漏一个接口 IPv4 就静默黑洞）；保留规则、开 `src_valid_mark=1` 再给回程打 mark（在防泄露的关键路径上多出几处耦合的部件）。

代价：IPv4 对**没有 mark** 的局域网转发流量不再有路由层兜底，和 IPv6 一样只靠 nft。两张 Meridian 表都被删掉而转发仍开着时（例如有人执行 `nft flush ruleset`，或启用了 Debian 自带、配置以清空整个规则集开头的 `nftables.service`），IPv4 会和 IPv6 一样直接经 ROS 出去。`meridian-up.sh` 不会在兜底表缺失时打开转发；`meridian-verify.sh` 在兜底表缺失时 FAIL，在 `nftables.service` 已启用且 `/etc/nftables.conf` 会清空规则集时打印 `WARN nftables_service_flush`。这些都不是强制手段：运行中有人删表，只能靠检查发现。

### 分类链先决定的目的地址（校验）

网关的 `classify` 链在查规则集合之前就决定了几类目的地址：远程接入设备池（交给设备）、`10.66.0.0/16`（丢弃）、ULA 局域网前缀（判为国内）、`fc00::/7`（丢弃）、隧道端点（`endpoint_block*` 丢弃、`endpoint_direct*` 国内直连、`endpoint_tunnel*` 默认组）、链路本地 / 组播 / 环回 / 广播（不打标记）。因此：

- 网关局域网 IPv4（`settings.gateway_lan_ipv4`、网关节点的 `lan_ipv4`）与 `10.66.0.0/16` 或自定义的 `transit_v4_prefix` 重叠时是 `prefix_conflict` 错误——否则发往局域网主机的包在私有地址那一行之前就被 `ip daddr 10.66.0.0/16 drop` 丢掉，与有没有隧道地址落在局域网里无关。
- 启用的 CIDR 规则，整个目的范围都落在上面某一类里时是 `rule_unreachable` 错误（`rule_id`、`field: match_value`），文字给出规则名和原因；它永远不会命中。只部分重叠（例如 `10.0.0.0/8`）不报，其余部分照常生效。隧道端点按「启用的 WireGuard 链路两端节点的 `endpoint_v4`/`endpoint_v6` 和 IX 枢纽的 `ingress_v4`，IX 端换成专线邻居」推算，与编译器的 `endpoint_*` 集合一致（`TestUnderlayRulesReportedUnreachable` 交叉核对）。

这两项都只是校验，编译出的 `meridian.nft` 不变。

### 面板状态（`GET /api/status`）

只读、无副作用，供顶栏轮询（默认 20 秒，有任务运行时 5 秒）。不算 Mesh 计划、不带探测目录和任务明细。

| 字段 | 含义 |
| --- | --- |
| `agent` | `{configured, ok, error}`：对 host agent 做一次 health（3 秒超时）。`configured=false` 表示面板没有宿主执行通道 |
| `lists_available` / `probe_available` | 名单更新 / 解锁探测此刻能否执行（动作已配置且 agent 应答） |
| `probe_reason` / `probe_error` | `probe_available=false` 的原因：`not_configured`（面板启动时没有探测通道）或 `agent_unreachable`（配置了，但 agent 的 health 没有应答，`probe_error` 是那次的错误）。概览的「解锁探测」卡片按这两项显示，不再看 `GET /api/unlock/jobs` 的 `available`——后者只说明配置了探测通道，不检查 agent 是否应答 |
| `install.state` | **网关自己的文件**与网关的**已安装清单**比较（清单里每个文件的哈希，不是已应用快照，也不是整个拓扑的规范文本）：`in_sync`、`changed`、`not_installed`（宿主上什么都没装）、`invalid`（拓扑无法编译，附 `error` 和错误级 `issues`）、`unknown`（接管的旧版安装没有摘要，无法比较）。远端节点不属于网关的安装：单独给某个远端节点下发不会让这里变成 `changed`（以前比较整个拓扑的摘要，单独下发一个远端节点之后就一直显示「有待下发的变更」） |
| `nodes` / `pending_nodes` | 每个受管节点**各自**的安装状态（见「逐节点的安装状态」）和其中待处理的个数 |
| `install.installed_version` / `installed_at` / `origin` | 已安装清单的版本、时间、来源；未安装为 `null` |
| `install.applied` / `applied_matches` | 是否应用过，以及存储的拓扑是否等于上一次应用的快照。`changed` 且 `applied_matches=true` 即「已应用（写入数据目录）但未安装」——`/api/diff` 在这种情况下显示没有变化 |
| `previous_available` | 数据目录里有上一份快照，回滚有东西可回；为 `false` 时面板不提供回滚 |
| `pending` | 未完成的宿主事务（同 `GET /api/host`） |
| `jobs.lists` / `jobs.unlock` / `jobs.mesh` | `{state, running, id, started_at, finished_at, error}`：名单任务、解锁探测（运行中的或最近一轮）和 Mesh 部署记录的状态；没有时 `state: "none"`，记录损坏时 `state: "error"` |

`POST /api/diff` 除了与上一次应用的快照逐行比较的 `diff`，还返回 `installed`：安装会让网关的**已安装清单**新增、修改、删除哪些文件和资源（`files_added` / `files_changed` / `files_removed`、接口、unit、nft 表、路由表，按清单里的文件哈希比较；没有安装时为 `null`）。已应用但未安装时 `diff` 为空，面板据此列出安装会改的文件；这种情况下没有逐行内容差分（已安装副本不经 API 读出）。

### 实时吞吐：国内与国外、上行与下行（`GET /api/traffic`）

网关的 `table inet meridian` 有四个命名计数器 `traffic_up_domestic`、`traffic_up_foreign`、`traffic_down_domestic`、`traffic_down_foreign`（`compile.writeTrafficCounters`，单/双枢纽、远程接入开或关都有）。它们在单独的 `chain traffic`（forward 钩子，优先级 `filter + 10`，在兜底表的 -200 和 QUIC 链之后）里，只计数：没有判定、不改 mark 或 ct mark，所以分类、路由和防火墙结果不变；纯规则差异判定也不受影响（计数块不随规则变化）。只挂 forward，网关自己的隧道外层包（output/input）不会被算进去。

开启 `settings.sniff` 时，受管 TCP 被重定向到本机转发器（uid 65530），LAN↔转发器这一段是本机投递（input/output），不经过 forward，所以 `chain traffic` 本身看不到。计数块里于是多两条只计数的链，只算转发器↔互联网那一段（避免重复计数）：`traffic_sniff_out`（output，`filter + 20`，在 `sniff_out` 约束之后）按 `meta skuid 65530`、`ct direction original`、TCP 且目的端口不是 53，`mark & 0xff00ffff == 0x64` 且出 LAN 网卡计国内上行，出口 mark 段（去掉中继位）且进 WireGuard 隧道计国外上行；`traffic_sniff_in`（input，`filter + 10`）按 `ct direction reply`、TCP、源端口不是 53、`meta skuid 65530`（依赖 TCP early demux 找到套接字），来自 LAN 网卡计国内下行、来自隧道计国外下行。WireGuard 外层包虽带转发器 uid，但是 UDP、带底层 mark、出 LAN 网卡或 lo，两条都不匹配；wstunnel、网关自己的 DNS 和探测不是这个 uid。关闭 sniff 时输出与以前逐字节相同；这两条链在计数块里，固定摘要同样把它们剥掉。

- **上行**：从入口（局域网网卡，远程接入开时加 `mra`）进来的包；mark `0x64` 记国内，出口标记段 `0x101`–最后一个出口/组标记记国外。
- **下行**：回程包不经分类、不带 mark，按路径判断：`ct direction reply` 且从入口出去，从 WireGuard 隧道进来的记国外，从局域网网卡进来（ROS 的直连回程）的记国内。只认 reply 方向，局域网内部或局域网到 `mra` 的原始方向不会被算成下行。

读取：宿主代理固定、不带参数的 `POST /v1/traffic`（`hostexec.TrafficStatus`）只执行 `nft -j list counters table inet meridian`，只返回这四个计数器的累计 `bytes`/`packets`/`handle`、采样时间 `read_at` 和缺失的名字。面板 `GET /api/traffic` 返回 `{available, read_at, reset, counters: {up_domestic|up_foreign|down_domestic|down_foreign: {bytes, packets}}, missing, code, message}`。面板不算速率：客户端轮询，用相邻两次 `reset=false` 的样本按 Δbytes / Δread_at 计算。某个计数器变小或 nft handle 变了（安装替换了表，计数归零）时 `reset=true`，这个样本只作新的基线。`code`：`agent_unavailable`、`read_failed`、`not_installed`（还没有计数器）。

**活动连接数**（`connections`）：同一个 `POST /v1/traffic` 另外只读连接跟踪表（`hostexec/traffic_conns.go`）：先读 `/proc/net/nf_conntrack`，内核没有这个兼容文件时执行固定的 `conntrack -L -o extended`，都不接受参数。只统计局域网和远程接入设备经网关的连接，TCP 的 `TIME_WAIT`/`CLOSE` 不算活动。逐条判断（本机地址取自 `net.InterfaceAddrs`）：
- 原始方向源地址是本机：网关自己的连接（隧道外层、wstunnel、DNS 上游、探测、转发器的出站一段），不计。
- 回程源地址是本机：连接终止在网关。DNS（53/853，含劫持）、面板、SSH、远程接入 WireGuard 端口不计；原始目的不是本机的被重定向 TCP 是 sniff 转发的局域网连接，计一次 `redirected`（转发器出站那段已按上一条排除，不重复）。它走国内还是国外由转发器决定，conntrack 里没有，所以只进 `total`。
- 回程目的地址在过境网段（`10.66.200.0/24`、`fd66:0:0:ff::/64`）：`transit_snat` 给了出口/组标记的过境地址，计**国外**。
- 其余（ROS 直连、局域网内、局域网↔远程接入）计**国内**。

不新增 ct mark 位、不改规则集：包 mark 不进 conntrack，ct mark 只有中继分担位，所以按回程元组区分，分类和转发结果不变，金样不变。面板返回 `connections: {available, read_at, scope: "lan_and_remote_access", split, domestic, foreign, redirected, total, code, message}`，`total = domestic + foreign + redirected`；`split=false` 时只有总数。读取失败时 `available=false`、`code=read_failed`、各计数为 `null`（不会冒充 0），且不影响吞吐计数器；旧版宿主代理没有这项时 `connections` 为 `null`。限制：瞬时快照；UDP 按超时未到期的条目计；只经过网关但不在本机建立 conntrack 的流量（如 ROS 直接转发）看不到。

### 受管 sysctl：写入、生效与显示

- **写入**：每次安装（和运行态回滚）都把网关的 `etc/sysctl.d/99-meridian.conf` 和 `etc/meridian/forwarding.conf` 按编译结果**整份**写入，不管内容是否变化（事务的 converge 写目标清单里的每一个文件）。`install.sh` 或旧版本留在文件里的行在第一次面板安装之后就不在文件里了。
- **生效**：`meridian.service` 运行 `meridian-up.sh`，它在防火墙和兜底表就绪之后逐行 `sysctl -w` 应用 `99-meridian.conf`（开机转发两行 `ip_forward=0` / `all.forwarding=0` 跳过，它们只给 systemd-sysctl 开机时用），内核没有的键跳过并打印 `skip sysctl: …`，最后打印 `meridian-sysctl: applied N, skipped M from …`；之后才按 `forwarding.conf` 打开转发。不运行 `sysctl --system`。删掉的行不会恢复内核里的旧值。
- **显示**：事务提交后，面板逐键从运行中的内核读回（容器是 host 网络，`/proc/sys/net` 就是宿主的；测试根目录不读），放进安装结果 `host.sysctl`：`written[]` 每项 `{file, key, want, got, state}`，`state` 是 `in_effect`、`differs`、`missing`（内核没有这个键）、`boot_only`（开机转发两行）或 `not_checked`；`removed[]` 是安装前宿主上的旧文件里有、新文件不再设置的键（`stale`，附当前内核值）；`problems` 是 `differs` + `missing` 的数量。每个问题和旧文件遗留也作为 `host.warnings` 显示。这只是读回，不是泄漏证据，没有在真实网关上执行过。

### 验收（`internal/acceptance`、`GET /api/acceptance`、宿主代理的 `/v1/drill/*`）

面板「验收」页把实机检查做成一张固定目录，逐项执行、签收并保存结果。目录、各项的影响与耗时、证据的四个部分和演练的安全边界见 [verification.md「验收目录」](verification.md)；这里只说结构。

**目录与存储（`internal/acceptance`）。** `Catalog()` 是固定的条目表：稳定的 id、指向它的页面、是否打断流量与上限、执行方式（`auto` 只读检查 / `drill` 演练 / `manual` 人工）、固定动作的标识、需要的证据部分（`config` / `measured` / `signoff`）、人工步骤与证据来源。动作标识引用 `hostexec` 的定义（`ActionHealth`、`DrillFirewallReload`、`DrillRelayIsolation`、`DrillHubIsolation`、`CheckTunnelPaths`），加上三个说明性的名字（面板自己的配置核对、已有的 `/v1/dns/check` 与 `/v1/probe`）；目录不开任何执行入口。`Store` 把结果存在面板的键值库里（键 `acceptance_results`，每项最多 20 条）：部分、方式、动作、目标、结果、时间、摘要与证据行、脱敏备注、配置指纹和已安装版本。`Fingerprint(编译结果摘要, 已安装清单摘要, 已安装版本)` 变了，旧结果保留并标为过期；一项的状态只由当前指纹下的结果决定，且每个需要的部分都要通过才是 `verified`。`Confirmations` 签发演练的二次确认：绑定条目、动作、目标与时长、指纹，120 秒有效，只用一次，只在内存里。

**API（`internal/api/acceptance.go`）。**

| 请求 | 作用 |
| --- | --- |
| `GET /api/acceptance` | 目录、每项是否适用 / 现在能否执行及原因、各部分最近的有效结果与历史、当前读到的配置证据、宿主上的演练状态、正在执行的一项 |
| `GET /api/acceptance/summary` | 每项的状态与最近有效结果、「防泄露」清单行到条目的对应；其它页面的链接读它，不向宿主发任何请求 |
| `POST /api/acceptance/items/{id}/prepare` | 演练的二次确认（`target` 中继节点 id、`block_seconds`），返回确认与将要做什么 |
| `POST /api/acceptance/items/{id}/run` | 执行只读检查或已确认的演练（202，异步；同一时间只有一项） |
| `POST /api/acceptance/items/{id}/cancel` | 取消：只读检查停止；演练交给宿主恢复 |
| `POST /api/acceptance/items/{id}/signoff` | 人工签收 `{outcome, note}`（`outcome` 是 `pass` 或 `fail`）；只对有人工部分的条目 |
| `POST /api/acceptance/drill/retry`、`…/release` | 重试未核验的恢复；在阻断表已不在时解除阻断（`confirm: "release"`） |

请求体只有已安装资源的 id 和有界的时长，未知字段被拒绝。面板把它们解析成宿主代理的参数时逐个核对：中继必须是拓扑里的中继、在网关自己的上游记录里、接口在已安装清单里；出口必须是编译结果里可检查的出口；平台必须在探测目录里。错误码：`acceptance_unknown_item`（404）、`acceptance_not_applicable`、`acceptance_busy`、`acceptance_confirm`、`acceptance_refused`、`acceptance_blocked`（宿主上有未解决的演练）、`acceptance_drill_active`（409）、`acceptance_bad_target`（400），以及原有的 `node_busy`、`transaction_pending`、`host_unavailable`。演练期间 `POST /api/apply`（安装）、`POST /api/rollback`（运行时）和 `POST /api/host/recover` 以 `acceptance_drill_active` 被拒绝；撤回、预检、引导部署因节点锁被拒绝。

**宿主代理（`internal/hostexec/acceptance.go`、`restore.go`）。** 新增六个固定请求：只读的 `POST /v1/acceptance/paths`（受管接口的状态、对端数、最近握手的年龄和收发字节；复用 `wgstatus.go` 的解析，不返回公钥）和 `POST /v1/drill/start`、`/status`、`/cancel`、`/retry`、`/release`。演练的一生：

1. 校验请求；有未解决的演练记录、或另一个动作在执行，拒绝。
2. 取得代理的动作锁（整个演练期间一直占着），读快照 `DrillSnapshot`，按宿主的实际状态检查前置条件，读出要隔离的地址。
3. 把记录（阶段 `prepared`）写到 `/var/lib/meridian-host/drill.json`，然后才改动：隔离是加载代理自己的表 `inet meridian_drill`（集合元素带内核超时），重载是重启 `meridian.service`。阶段改为 `active`。
4. 后台按代理自己的时钟观察上游记录（或采样两张表），到时或被取消后进入恢复。
5. 恢复（`restoring`）：删除自己的表并确认不在；`RestoreTopology` 等宿主回到快照，仍不一致时走 `RestoreDataPlane` 的健康检查 / 重新激活再比对；最后一次健康检查（含转发）。与快照一致才是 `restored`，否则 `restore_failed` 并列出差异。比对项是 nft 表与规则、策略规则、路由表、接口、承载路径、枢纽和每个中继的状态（被隔离的中继要回到演练前的状态，如重新 `active`）；中继权重由质量控制器动态调整，不比较：上游记录里的权重不比，nft 规则摘要也先去掉中继分担映射里的权重区间（`normShareMaps`，只保留哪些标记在分担，排序后取摘要）；中继状态精确比较：必须回到演练前的状态（如 `active` → `active`），仍是 `recovering`（权重爬升中）或 `reduced` 都算未恢复，`evicted`、`standby`、`disabled` 同理。等待期间与演练前不同的权重和状态写进结论（`drillWeightNotes`）。实测解除阻断后约 1 分钟 `recovering` 回到 `active`，在下面的等待窗口之内。第一段等待 `DrillVerifyWait` = 360 秒，覆盖故障切换循环自己的恢复（连续 5 次成功 + 120 秒冷却，实测约 4 分钟），在此之前不会重新激活数据面。改动失败后的恢复和「重试恢复」的等待也用 `drillRecoveryWait`：到阻断结束（从未生效时为开始）后满 `DrillVerifyWait` 为止，至少 `DrillRetryWait` = 30 秒，所以重试不会在循环自己恢复之前触发重新激活。
6. `restore_failed` 持久阻断：`Execute` 对 `activate` / `rollback` / `withdraw` 和新的演练回答 409，直到重试核验通过或被解除（`released`，不等于恢复）。代理启动时（`RecoverDrills`，也在第一次请求时）对 `prepared` / `active` / `restoring` 的记录先恢复，期间同样拒绝变更。

面板一侧演练全程占着网关节点锁和宿主事务锁（`apply.Applier.Hold`：不等待，事务进行中或有未完成事务时拒绝）。面板只是跟随宿主的记录：它或浏览器离开不影响宿主恢复；面板重启后下一次读 `GET /api/acceptance` 会把宿主上已结束的演练取回成结果（按演练 id 只存一条，后来的状态覆盖先前的）。

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
- 拨号 10 秒、握手 20 秒超时；执行超时由调用方的 context 决定（下发 15 分钟，Mesh 每个动作 10 分钟），超时会发 SIGKILL 并断开。错误码：`unreachable`、`timeout`（TCP 连接超时）、`ssh_banner_timeout`、`ssh_handshake_timeout`、`ssh_closed_before_banner`、`run_timeout`、`run_interrupted`、`jump_forward_refused`、`channel_not_allowed`（见下「执行之前的失败」和「管理通道」）、`auth_failed`（服务器尝试并拒绝了这份凭据）、`auth_method_unavailable`（服务器根本不提供这份凭据的登录方式，例如 `PasswordAuthentication no` 时的密码凭据；凭据没有被尝试，错误文字列出服务器提供的方式并说明改用密钥/密码或在服务器上开启对应方式。客户端在自己的方式之后附加只探测、不发送任何凭据的方式来得知服务器提供哪些）、`command_failed`、`not_ssh`、`host_key_untrusted`、`host_key_mismatch`、`host_key_not_pinned_by_deployment`、`target_changed`、`no_credential`、`not_found`、`ssh_rate_limited`（见下）。
- **来源限速（`ssh_rate_limited`）**：OpenSSH 9.8 起默认开启的 `PerSourcePenalties` 会让一个来源地址在短时间内多次连接、或有连接没完成认证（只读取主机指纹、端口扫描）之后，被服务器在 SSH 版本行**之前**回一行 `Not allowed at this time` 并断开；经端口转发到达的服务器上，所有连接都来自转发器的同一个地址。`golang.org/x/crypto/ssh` 只会报 EOF，所以连接器把 TCP 连接包一层，只记录服务器在握手完成前发来的前 512 字节（版本行和明文的密钥交换初始化，不含任何凭据；握手成功后立即停止记录并丢弃），握手失败且没有看到 `SSH-` 版本行时，按其中的文字分类：是这一行就报 `ssh_rate_limited`（发现、测试、预检、下发、撤回、枢纽状态读取、Mesh 远端操作都一样），说明「服务器暂时拒绝这个来源，不是密码、密钥或指纹的问题，面板没有尝试登录」；别的文字就附在 `unreachable` / `not_ssh` 的说明后面（去掉控制字符，截到 200 字符）。这发生在密钥交换之前：没有看到主机密钥、固定指纹不受影响，也没有读取或发送凭据。之后面板对这个 `地址:端口` **冷却 60 秒**（`sshexec.Pool.Cooldown`）：期间所有会连接它的操作直接返回 `ssh_rate_limited` 和剩余秒数（`retry_after`，HTTP 503 + `Retry-After`；连接测试是 200、`test.retry_after`；枢纽读取是 `last_read.retry_after`；Mesh 是 `ssh_code` + `retry_after`），**不自动重试**。OpenSSH 的惩罚从 15 秒起累积到最长约 10 分钟，所以冷却只是下限；面板在冷却期间停用相关按钮并显示倒计时。
- **连接复用（`sshexec.Pool`）**：面板持有一个连接池，同一个操作流程里的各步共用一次登录：一次下发请求里的预检重跑和下发脚本、撤回的「生成计划」和「执行」、Mesh 部署的预检 / 安装 / 健康检查 / 补偿、连接测试之后紧接着的预检。复用严格绑定到登录时的完整身份：服务器 ID、地址、端口、用户、已确认的指纹和密钥类型及其确认时间、凭据 ID 和凭据密文的「代」；每次复用前都从存储重新解析这组身份，任何不同（服务器被修改或删除、指纹被清除或重新确认、换了凭据或原地轮换了密码 / 私钥）都关闭空闲连接、重新登录。面板对服务器和凭据的每一次修改（`PATCH`/`DELETE` 服务器、确认 / 清除指纹、轮换 / 删除凭据）还会立即关闭相关的空闲连接。连接空闲超过 60 秒、存在超过 5 分钟、所在操作以任何错误结束、操作被取消、或复用前不回应 keepalive 时都会关闭，不会复用；同一时刻一个连接只借给一个操作。连接测试总是重新登录（它测的就是登录本身），然后把这条连接留给下一步。限速冷却也记在池里。密码登录照常支持：只接受密码登录的服务器用密码凭据照常登录和复用，面板不要求改用密钥。
- **执行之前的失败**：每个 `sshexec.Error` 带 `NotExecuted`（失败发生在服务器上开始执行任何命令之前：拨号、版本行、密钥交换、登录、主机指纹、跳转的第一跳）和 `SafeToRetry`（而且属于暂时性的那几类）。API 在错误体里给出 `not_executed: true` / `safe_to_retry: true`，连接测试记在 `last_test` 上；面板据此**只在这时**写「没有执行任何操作，可以安全重试」。只有这几类算可以安全重试：握手前被限速拒绝（`ssh_rate_limited`，等 `retry_after` 之后）、TCP 连接超时（`timeout`）、连上但在超时前没有收到 SSH 版本行（`ssh_banner_timeout`）、收到版本行但密钥交换或登录没有在超时前完成（`ssh_handshake_timeout`）、在版本行之前就被一声不响地断开（`ssh_closed_before_banner`：sshd 的 `MaxStartups`、转发器后面的主机不可达）。连接被拒、登录被拒、方式不被接受、指纹不符、跳转被拒、通道不允许也是 `not_executed`（什么都没改），但不说「可以重试」——要先按原因处理。命令开始之后的任何失败都**不是** `not_executed`：退出码非零是 `command_failed`（命令跑完了）、执行超时是 `run_timeout`、执行中连接断开（没有退出状态）是 `run_interrupted`，后两者结果不明。面板**从不自动重试**，结果不明的变更尤其不会。超时由一个看门狗关闭连接来实现（经跳转转发的连接没有读写期限），所以经中继时同样有效。
- **管理通道**（`model.ManagementChannel`，服务器的 `channel`；没有就是直连，行为和以前完全一样）：操作员为每台服务器明确选择面板怎样连到它的 sshd——`direct`（直连地址:端口）、`tunnel`（经已建立的隧道：面板所在的网关去连这台服务器的隧道地址，`address` 必须是 IP，`port` 默认同 SSH 端口）、`jump`（经受管中继或枢纽跳转：先用**中继自己的**凭据和**中继自己的**固定指纹登录中继，再让中继开一条 `direct-tcpip` 转发到这台服务器的地址（`address` 可选，默认服务器地址），面板在这条转发里用**这台服务器自己的**凭据和固定指纹完成第二次握手）。约束：跳转只能经过拓扑里受管中继或枢纽节点的服务器（`JumpPolicy`；境外枢纽用来到达国内中继连不上的出口，否则 `channel_not_allowed`，什么都不拨号）；中继本身必须直连（只有一跳，不能成链或成环；中继被别的服务器当跳板时不能改成非直连，也不能删除）；中继上不执行任何命令；客户端从不请求 agent 转发，也不把任何一跳的密钥、口令交给另一跳——两次握手都在面板进程里完成，中继只看到加密字节。主机指纹仍按服务器固定：经通道连到的必须出示同一把已确认的公钥，第一次信任仍然是显式的「发现 → 核对 → 确认」（发现也走所选通道）。通道是传输方式不是身份：改通道不清指纹、不受部署固定的限制，但会清掉上一次连接测试；连接池的身份键里包含通道（模式、拨号地址、中继的完整身份），中继被修改、轮换凭据或失效时经它的空闲连接一并关闭。**没有回退**：所选通道不通就如实报告（错误文字写明是哪条通道，并说明面板不会自动改走直连），由操作员在服务器页改选。限速冷却按通道计：经隧道按隧道地址，经跳转按「中继 + 目标」（目标看到的来源是中继），中继自己的冷却照常。**经跳转已在真实主机上用过**（经香港枢纽跳转到国内中继连不上的境外出口，发现指纹、连接测试、预检和下发都走这条通道）；跳板的 `AllowTcpForwarding` 要开启。**经隧道只用本地 SSH 替身测试过，没有在真实主机上验证**：节点上的 sshd 是否监听隧道地址、节点防火墙是否放行隧道接口上的 22 端口、网关能否路由到那个地址，都要在实机上确认，面板和本文都按「未验证」标注。
- **一个流程尽量少连接**：同一个下发请求里的预检重跑、二进制传输、下发脚本、以及下发后读回服务器记录（下面的 `NodeStateCommand`）都在同一次登录上；经跳转时中继也只连一次（中继会话和目标会话同生共死，一起进池、一起关闭）。
- **连接测试**：登录后只运行固定命令 `sshexec.TestCommand`（`uname -m`、`uname -r`、`/etc/os-release` 的 `PRETTY_NAME`），30 秒超时；结果（时间、成功与否、认证方式、系统、内核、架构、耗时、错误码与脱敏后的错误）记在服务器的 `last_test` 上。改地址、端口、用户、认证方式、凭据或原地轮换凭据都会清掉 `last_test`。

服务器从「已添加」到「就绪」：建凭据 → 建服务器并选凭据 → `POST …/host-key/discover` → 用户核对指纹后 `POST …/host-key/trust`（提交同一个指纹）→ `POST …/test` 成功。视图里 `operable`（凭据 + 已确认指纹，下发和 Mesh 部署要求的条件）和 `ready`（再加上最近一次测试成功）。

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

下发 `POST /api/provision`：`{node_id, dry_run?, generate_keys?, preflight_id?}`。`dry_run: true` 只返回带占位符、拒绝运行的预览脚本，不需要服务器。真正执行前要过「下发前预检」（下一节）：先检查节点关联了服务器（409 `no_server`）、指纹已确认、选了凭据；第一次下发必须带审阅过的 `preflight_id`（409 `preflight_required`）；随后在同一个固定身份上重新预检——这些都在生成或轮换 WireGuard 密钥之前。然后经连接器以 `bash -s` 执行，成功响应 `{dry_run:false, outcome:"installed", node_id, server_id, auth_method, host_key, public_key, preflight_id, run, output}`；失败 `{error, code, outcome, node_id, server_id, auth_method, leftovers, kept, output, login_help?}`（409 主机身份类与预检类，502 连接 / 认证 / 执行类）。旧字段 `ssh_host`、`ssh_port`、`ssh_user`、`private_key_pem`、`trust_new_host` 一律 400 `field_removed`，未知字段 400 `unknown_field`。

代码：`internal/model`（`Server`、`HostKey`、`ConnectionTest`）、`internal/credentials`（存储、校验、迁移、部署引用）、`internal/sshexec`（连接）、`internal/mesh/permissions.go`（权限检查）、`internal/api/resources.go`、`internal/api/ssh_ops.go`。

### 迁移

面板启动时和每次保存拓扑后运行，可重复执行：

- `DataDir/mesh/cloudflare.json` 导入为 ID 固定的账户 `cf-mesh`，未选择 Mesh 账户时选中它，索引写入成功后才删除旧文件。中断后重跑：账户已在就只删旧文件；文件权限过宽或内容损坏时保留文件并记录原因，不导入。Mesh 部署记录不变，仍按 account id 绑定，迁移后的账户 account id 相同，撤回照常。
- 带 `ssh_host` 的非网关节点变成服务器（ID 优先用 `srv-<节点 ID>`，`migrated_from: "node:<ID>"`，认证方式 `key`，凭据待选），节点写入 `server_id` 并清空 `ssh_*`。先写服务器索引，再保存拓扑；中断后重跑会认出 `migrated_from` 相同的服务器直接关联，不会重复。保留域名 `.invalid` 的示例地址不迁移。Mesh 部署记录里该节点固定过的主机指纹（地址和端口一致时）作为 `trusted` 导入。
- Mesh 部署记录 schema 2 升级到 3（见「Mesh」）：每个固定主机补上 `server_id` 和 `credential_id`，其余不变。
- 已有 `server_id` 的节点再带 `ssh_*` 时，保存被拒绝（422 `ssh_fields_moved`），避免两处地址不一致。


## 整份拓扑保存与独立资源

`PUT /api/topology` 收整份拓扑文档（拓扑编辑器、出口页、规则页的保存都发它）。文档里有几块由**自己的接口**管理，整份保存从来不写它们。以前整份保存对这些块是「收到什么都返回 200，保留存储里的值」：在真实网关上，一个客户端在整份文档里改了独立管理的块，得到 200，实际什么都没变。现在的规则（`internal/api/topology_contract.go`）：

- 请求**省略**这个字段（或给 `null`）：保留存储的值。旧客户端和面板自己的编辑器都这样用（面板的保存把这几块去掉再发，`web/src/api.ts` 的 `topologyForSave`）。
- 请求带的值与存储的**相同**：保留，照常保存其余内容。刚读取的文档原样发回（往返）永远被接受。
- 请求带了**不同**的值：**整个保存被拒绝，什么都不写**（请求里别的改动也不写），409：

```json
{"error": "整份拓扑保存不能修改独立资源：规则集（rule_sets，用 /api/rule-sets）。没有保存任何内容。如果你没有改它们……",
 "code": "independent_resource_changed",
 "fields": [{"field": "rule_sets", "resource": "规则集", "endpoint": "/api/rule-sets",
             "methods": ["POST /api/rule-sets", "PATCH /api/rule-sets/{id}", "DELETE /api/rule-sets/{id}", "PUT /api/rule-sets/{id}/auth"],
             "items": ["rs-a"]}]}
```

  `fields` 按固定顺序列出每一个不允许改的字段；`items` 是列表里不同的条目（新增、删除或内容不同的 ID；远程接入自己的设置记为 `settings`），单值字段没有。草稿保存（`?draft=1`）同样适用；校验（422）在这之后才做。

**「相同」怎样判断。** 两边都按存储的结构解码后比较规范化的 JSON（结构体字段顺序固定，映射按键排序，`omitempty` 让 `null`、空列表和缺省一致）：

- 按 ID 的列表（规则集、远程接入的设备）**不看顺序**：顺序在这里没有含义，保存也不会改动存储的顺序。同一个 ID 出现两次算不同。
- 字段缺省、`null` 与零值相同：`settings.sniff` 缺省等于 `{"enabled": false}`，`remote_access` 缺省等于 `{"enabled": false}`，`mihomo_import` 缺省等于 `{}`。`[]`（空列表）在存储也为空时相同；存储里有条目时就是「全部删除」，拒绝。
- 规则集的 URL：读取拓扑时，仍带凭据的 URL 显示为去掉凭据的形式（`store.Redact`）；把这个形式发回算与存储相同。
- 服务器分配的字段（设备的 `created_at`、`config_fingerprint`、公钥、`key_id` 等）照读取到的原样发回即相同；它们只能由各自的接口改变。

**陈旧的文档。** 一份在别的客户端经专用接口改动这些块**之前**读取的文档，带的是旧值：与存储不同，所以**被拒绝**，错误信息写明是哪一块、哪几个条目、应该在哪里改，并说明「如果你没有改它们，说明这份文档读取得太早：重新读取后再改，或省略这些字段」。对每一块都是这样，没有一块按「接受但不写」处理：服务器分不清「旧文档里的旧值」和「客户端有意改回旧值」，接受就等于静默忽略后者，正是要去掉的行为。省略这些字段的旧客户端不受影响。检查在写入时于存储锁内**再做一次**（`store.SaveGuarded`）：处理请求期间另一个请求经专用接口改了这些块，保存同样被拒绝，不会把旧值写回、也不会悄悄成功。

**导入（`?import=1`）。** 把导出的文档整份带回来：规则集、导入映射和嗅探设置（旧文档里的服务组按上面的迁移改写进规则）按文档整份写入（与以前一样）；远程接入仍只由它的接口管理，导出文档里的 `remote_access` 与存储不同就拒绝（把它从文件里删掉即可）。

**面板。** 整份保存被拒绝时，共用的错误提示（`ApiErrorAlert`）列出每一块（规则集……）、不同的条目、面板里修改它的页面链接和接口路径。面板自己的编辑器不发这些块，所以正常使用中见不到它；它面向外部客户端和旧版面板页面。

### 字段一览

| 字段 | 谁管理 | 整份保存怎样处理 |
| --- | --- | --- |
| `settings`（下面列出的以外：局域网、地址、`domestic_dot`、`ix_replacement_mode`、`clients_ipv6_via_gateway`、`unlisted_domestic_dns`、中转前缀、`unlock_interval_sec`、`unlock_probe`、`nat64`、`mesh_image`、`mesh_underlay_prefix`、`regioncheck_image`、`path_quality`） | 拓扑编辑器（整份保存） | 写入（校验后） |
| `settings.draft` | 整份保存 | 写入；`?draft=1` 也算草稿 |
| `settings.list_source` | `PUT /api/lists/policy` **和**整份保存 | 写入。两处都能改：陈旧的文档会把它改回去（面板的名单页改动后同步编辑器的副本，所以面板自己不会） |
| `settings.default_group` | `/api/region-groups`（设为默认）、mihomo 导入的 MATCH，**和**整份保存 | 写入（校验后）；陈旧文档同上 |
| `settings.sniff` | `PUT /api/sniff` | **独立资源**：省略或相同则保留，不同则拒绝；`?import=1` 写入 |
| `settings.exit_dns` | `PUT /api/dns/upstream` | **独立资源**：省略或相同则保留，不同则拒绝；`?import=1` 写入（引用的账户标识凭据必须存在） |
| `settings.dns_log` | `PUT /api/dns-log` | **独立资源**：省略或相同则保留，不同则拒绝，`?import=1` 也一样（解析日志保存设备查询的名字，开关只能经它自己的接口改：那里核对能力门槛并要求确认） |
| `nodes[].exit_dns` | `PUT /api/dns/upstream` | **独立资源**（按节点比较）：省略则保留，不同则拒绝；`?import=1` 写入 |
| `nodes` | 拓扑编辑器、出口页 | 写入。`private_key` 为空或 `***` 时保留存储的私钥（读取时脱敏的占位）；旧的 `ssh_*` 字段保存后迁成服务器；`wss_path_prefix` / `tls_cert_path` / `tls_key_path` 保存后迁出（随机路径和证书）；`server_id` 检查引用（422） |
| `links` | 拓扑编辑器 | 写入 |
| `rules`、`rules_ordered` | 规则页（整份保存）、`POST /api/rules/retarget` | 写入；没有 `rules_ordered` 的旧文档按旧排序迁移成有序列表；带 `service_groups` 的旧文档在解码时迁移成直接指向 |
| `region_groups` | `/api/region-groups` **和**整份保存（删除节点时编辑器同时把它移出组） | 写入（校验后）；旧的池字段迁移成地区组 |
| `rule_sets` | `/api/rule-sets` | **独立资源**；`?import=1` 写入，带凭据的 URL 保存后移进凭据存储 |
| `mihomo_import` | `POST /api/rules/import/confirm` | **独立资源**；`?import=1` 写入 |
| `remote_access` | `/api/remote-access` | **独立资源**，`?import=1` 也一样 |
| `allocations` | 存储（服务器分配） | 不用请求里的值：存储的表为准，新对象分配空闲序号，删除的退休（`?import=1` 时文档的表在合法范围内照用）。它不是可编辑的字段，所以不在上面的拒绝规则里；`POST /api/topology/allocations` 显示一次保存会给出的分配 |
| 未知字段 | — | 忽略（与以前一样） |

测试：`internal/api/topology_contract_test.go`（每一块的省略 / `null` / 相同 / 不同、重新排序、一次拒绝多块、拒绝时存储逐字节不变且同一请求里别的改动也没写、草稿、导入、四种经专用接口改动后的陈旧文档、省略字段的旧客户端、URL 脱敏形式、存储锁内的复查），`web/src/topology_contract.test.tsx`（面板的保存不带这几块；拒绝的提示列出资源、条目、页面链接和接口）。

## 下发前预检

在面板第一次给远端节点下发、更新它，以及安装到网关之前，都要先看清**要做什么、会和什么冲突**；不能确认可以和主机上已有的服务安全共存时，面板拒绝执行并说明处理办法，而不是覆盖。预检本身**只读**。预检（只读部分）在 2026-11-13 由主会话从面板对 11 台真实服务器和网关各执行过一次；下发、补偿和撤回**没有在任何真实主机上执行过**。之后对「什么算我们的」、端口来源和修改指引、`ssh_rate_limited` 与连接复用的改动只在仓库里的自动化测试（进程内 SSH 服务器、假宿主代理、本机沙箱）里跑过，没有在真实主机上执行过。

### 流程：脚本 → 报告 → 评估 → 关卡

1. **脚本**（`internal/preflight` 的 `Script()`）：一份固定、可审阅的 bash 脚本，对所有节点是同一段文本，拓扑、目标和请求里的东西都不插进去。唯一的参数是这个节点的包要写的主机路径：每个都要过 `preflight.ValidatePaths`（绝对路径、已规范化、只含字母数字和 `._/@+-`、不含 `..`、只在 Meridian 写的那几个目录下、最多 256 个），由 `preflight.Args` 单引号包好；`sshexec.RunPreflight` 连接前再按同样的形状检查一遍，脚本里也再判一次（被拒的参数只报告 `note path argument refused`，不碰）。脚本经已固定指纹的 SSH 通道以 `bash -s -- <路径>` 从标准输入执行。它只运行打印状态的命令（`id`、`uname`、`ip … show`、`ip -o -4|-6 route get <隧道对端地址>`（内核查表，不发包；地址作为 `route4:` / `route6:` 参数传入，规范写法，最多 64 个，面板、SSH 通道和脚本各检查一次）、`ss -Hlntup`、`ss -Htnp state established`（只取连到 WARP 本地监听的进程名）、`nft list chains`、`iptables -S`（含 `-S DOCKER-USER`）、`systemctl is-active/is-enabled/show -p MainPID|ExecStop`、`dpkg-query`、`apt-cache policy`、`nft/wg/wstunnel --version`、`sha256sum`、`head`、`grep`），每条 15 秒上限、标准输入是 `/dev/null`，不写任何文件，**不输出文件内容**（WireGuard 配置里有私钥：只报告类型、大小、前 12 行是否提到 Meridian、SHA-256），整份输出截在 256 KiB + 1 字节。
2. **报告**：按行的 `键 值…` 格式，首行 `meridian-preflight 1`，末行 `meridian-preflight-end`。`preflight.Parse` 不会失败：报告头之前的登录横幅被忽略；没有报告头、没有结束行、超长或超行数的报告标为不完整；每个值去掉控制字符、双向控制符和非法 UTF-8 并截到 400 个字符；地址、端口、路径、单元名、表名都按各自的形状校验，不符就丢掉；结束行之后的内容、清单块之外的清单行一律忽略。
3. **评估**（`preflight.FootprintOf` + `preflight.Evaluate`）：从这个节点**编译出来的文件**推出它会建的东西——接口和地址、监听端口（WireGuard `ListenPort`、wstunnel 服务端和客户端、SmartDNS 的 `bind`）、main 表路由和黑洞兜底、策略规则与优先级、路由表号与名字、防火墙标记、nft 表、systemd 单元、要装的软件包和面板要下发的二进制（单元的 `ExecStart` 指向 `/usr/local/sbin/meridian-wstunnel` / `meridian-smartdns`）——再和报告逐项对比，得到带严重度（阻断 / 警告 / 信息）、稳定代码、中文说明（发现了什么）、处理办法和受影响资源的结论，外加「拟执行的变更」清单。
4. **关卡**（`internal/api/preflight.go`、`provision_api.go`）：见下面「执行前复核」。

网关走同样的评估：`meridian-host` 新增只读动作 `POST /v1/preflight`（参数只有同样校验过的路径；程序只从固定表里取：`ip`、`nft`、`ss`、`iptables`、`ip6tables`、`systemctl`、`wg`，参数固定；文件直接读、不回传内容；不占动作锁），用 `preflight.Line` 输出同一种报告。网关的「属于谁」来自安装清单（`apply.Installed`），带 Meridian 标记但不在清单里的文件交给安装事务的旧版接管去决定。

### 它检查什么

| 代码 | 严重度 | 条件 |
| --- | --- | --- |
| `report_incomplete` | 阻断 | 报告没有头、没有结束行、被截断或超限 |
| `not_root` | 阻断 | 登录用户不是 uid 0（这一版不支持 sudo） |
| `os_unsupported` | 阻断 | 远端节点：发行版和版本不在支持表里（Debian 12、Debian 13、Ubuntu 20.04；读不到 `/etc/os-release` 也算）。网关：不是 Debian 12 / 13。见下面「支持的平台」 |
| `arch_unsupported` | 阻断 | 不是 x86_64 / aarch64，或发行版和架构的组合不在支持表里（例如 Debian 13 aarch64、Ubuntu 20.04 x86_64 的远端节点） |
| `kernel_too_old` | 阻断 | 内核早于 5.6（没有内置 WireGuard） |
| `no_systemd` | 阻断 | 不是 systemd 系统 |
| `no_apt` | 阻断 | 缺命令要装包，但没有 apt-get |
| `smartdns_unavailable` | 阻断 | 节点要跑出口解析器，但面板没有这台主机架构的已校验 SmartDNS（镜像里缺文件、加载或发送前摘要不符、没有这个架构的固定版本）。不会跳过解析器，也不会让主机自己下载 |
| `wstunnel_missing` | 阻断 | 节点（含网关）有 wstunnel 单元，但面板没有这台主机架构的已校验 wstunnel。主机上有没有别的 wstunnel 不再相关：Meridian 只运行自己下发的 `/usr/local/sbin/meridian-wstunnel` |
| `package_unavailable` | 阻断 | 远端节点缺 `wg` / `nft` / `ip`，而 `apt-cache policy` 查不到对应包（wireguard-tools / nftables / iproute2）的候选版本 |
| `memory_budget` | 阻断 / 警告 / 信息 | 远端节点：可用内存（MemAvailable）对比这个节点的预算——基础余量 48 MB + SmartDNS 48 MB（有出口解析器时）+ wstunnel 32 MB（有 WSS 时）；更新时已经在跑的受管进程不重复计算。要本机解析器的节点低于预算（或读不到可用内存）时阻断，其他节点低于预算时警告，够用时信息 |
| `resolver_bind_unsafe` | 阻断 | 远端解析器配置没有 `bind` 行（SmartDNS 会默认绑 `[::]:53`）或绑了通配地址 |
| `forward_policy_drop` | 阻断 / 警告 | 节点要转发，而 iptables/ip6tables 的 FORWARD 策略是 DROP/REJECT，或别的 nft 表有 `hook forward` 且 `policy drop` 的链（通常是 Docker）。Meridian 自己的转发链 `policy accept` 救不回被别的表丢掉的包。**警告**（不阻断）只在这一族的 DROP 正是 iptables 的默认策略、主机上有 `DOCKER-USER` 链、FORWARD 在任何 DROP/REJECT 之前跳到它、ufw / firewalld 都没在运行、也没有别的 nft 表丢弃转发、而且是远端节点时：面板在 DOCKER-USER 顶部加带 Meridian 注释的放行规则（见下面「与已有业务共存」），规则逐条列进「拟执行的变更」。其余情况（含网关）阻断并写明是哪一条不满足；面板**不会**改 Docker、ufw、firewalld 或别的防火墙的规则和策略 |
| `interface_exists` | 阻断 | 要建的接口名已存在且不在受管清单里 |
| `uplink_mtu_too_small` | 阻断 / 警告 | 一条 UDP 隧道腿的满长包（隧道 MTU + IPv4 60 / IPv6 80 字节，含补齐）超过它出去的那块上联网卡（或路由）的 MTU：说明哪一端、差多少、建议的隧道 MTU。接口还没装在这台主机上时阻断，已部署时警告。见「上联 MTU：两端预检、建议与显式确认」 |
| `uplink_mtu` / `uplink_mtu_wss` / `uplink_mtu_unknown` | 信息 | 能承载的腿；WSS 腿（TCP 承载，只给分段估算）；没有验证的腿（旧版预检、没有路由、报告不完整：不算通过） |
| `port_in_use` | 阻断 | 要绑定的 协议/地址/端口 已有监听：通配地址和同端口任何监听冲突，具体地址只和同地址或通配监听冲突（回环上的 systemd-resolved、WARP 不算冲突）；只有「有证据属于这次安装」的不算（见下面「什么算我们的」）。占用者按进程名、容器名、systemd 单元或 WireGuard 接口名写出；端口来自拓扑字段时，结论带 `fix`（`{kind: node|link, id, field, label}`）并在处理办法里写明改哪个对象的哪个字段，面板链接到那个编辑器（见下面「端口从哪里来」）；SmartDNS 的 53/853 是固定的，处理办法是让占用者别绑通配地址 |
| `address_overlap` | 阻断 | 要配置的隧道地址和别的接口上的地址**精确重叠**（不是「同一个 /8」）；这份包要放到 lo 上的中转地址落在别的接口已有的网段里也算 |
| `route_overlap` | 阻断 | 要加的 main 表路由会替换、截走或被已有的非默认路由截走；兜底黑洞只在比已有路由更具体（或同前缀同 metric）时算冲突 |
| `route_table_in_use` | 阻断 | 要独占的路由表里已有路由且不归 Meridian |
| `fwmark_in_use` | 阻断 | 已有策略规则用了 Meridian 要用的防火墙标记 |
| `nft_table_exists` | 阻断 | `inet meridian` / `inet meridian_mesh` 已存在但不在受管清单里（下发会整表替换） |
| `path_occupied` | 阻断 | 要写的路径上有不属于 Meridian 的文件（不在清单、没有 Meridian 标记）、目录或链接，例如另一份 SmartDNS 配置 |
| `managed_by_other` | 阻断 | 主机上的节点清单属于另一个节点或另一个面板（部署 ID 不同） |
| `manifest_unreadable` | 阻断 | 有清单但读不懂 |
| `legacy_install` | 阻断 | 有带 Meridian 标记的文件但没有清单（旧版或手工装的）：无法确认归属，也无法准确补偿 |
| `previous_run_incomplete` | 阻断 | 上一次下发的 journal 停在 `running` / `incomplete` |
| `rule_precedes` | 警告 | 一条「几乎全匹配」的规则排在 Meridian 依赖的规则（含 main 表）之前，查的表有默认路由（例如 WARP 的 `not fwmark … lookup 65743`） |
| `rule_priority_shared` | 警告 | 已有规则和 Meridian 的规则同优先级 |
| `route_table_name_conflict` | 警告 | 表号已有别的名字 |
| `input_policy_drop` | 警告 | INPUT 策略是 DROP 而节点要在公网监听（放行规则是否覆盖看不到） |
| `low_memory` / `low_disk` | 警告 | 可用内存 < 256 MB 或总内存 < 512 MB；根分区 < 200 MB |
| `nftables_flush_on_reload` | 阻断 | nftables.service 已启用或正在运行，而且会清空整个规则集：`/etc/nftables.conf` 里有 `flush ruleset`（reload / restart），或它的 `ExecStop` 是 `nft flush ruleset`（stop / restart；Debian、Ubuntu 的单元就是这样）。网关和远端节点一样；下发脚本动手之前和装完软件包之后各再查一次。没启用也没运行（发行版默认）不报告 |
| `wan_interface_missing`、`wan_no_default_route` | 阻断 | 远端节点的 WAN 接口（`wan_interface`，没填为 `eth0`）不存在，或没有带上节点需要的默认路由；写出默认路由实际所在的网卡，带指向节点 `wan_interface` 的 `fix` |
| `ipv6_ra_unmanaged` | 阻断 | 节点要转发 IPv6，而某块非受管网卡的 IPv6 路由来自路由通告、`accept_ra` 却是 0 或读不到（用户态 RA 程序） |
| `ipv6_ra_kept`、`wan_interface` | 信息 | 要设 `accept_ra=2` 的网卡（在 IPv6 转发之前）；WAN 接口检查通过 |
| `warp_sidecar_conflict` | 警告 | 这个节点的包带 Mesh sidecar 的文件，主机上又有主机级 WARP 客户端：Mesh 部署的预检会拒绝这台主机（`host_warp`），节点包照常安装 |
| `firewall_manager` | 警告 | ufw / firewalld 在运行 |
| `modified_since_install` | 警告 | 受管文件在上次下发后被改过，会被覆盖 |
| `previous_run_leftovers` | 警告 | 上一次失败已补偿，但 journal 记了残留（例如保留的软件包） |
| `forward_coexistence`、`sysctl_scope` | 信息 | 每个地址族 meridian-fwcompat.sh 会做什么（策略 DROP 加规则 / ACCEPT 不加）；这次会写的内核参数、其中哪些是全局的、只改哪些接口、rp_filter 取 max(all, 接口) 的含义 |
| `cloudflare_warp` | 信息 / 阻断 | 主机级 WARP：它的策略规则（优先级、查哪张表、表里有没有默认路由）、对 Meridian 路由的含义、依赖线索（连到它本地监听的进程名、指向它的 resolv.conf）。Meridian 的标记、路由表、nft 表或规则优先级与它相同时阻断 |
| `docker_present`、`docker_missing`、`cloudflare_warp`、`wireguard_present`、`dns_listeners`、`nft_tables_present`、`netfilter_persistent`、`iptables_legacy`、`existing_install`、`forwarding_enable`、`host_summary` | 信息 | 认出来并说明是什么：Docker、主机级 WARP（`warp-svc`、`CloudflareWARP`、`inet cloudflare-warp`、100.96.0.0/12 地址）、别的 WireGuard 接口和端口、53 端口上不冲突的监听、别的 nft 表、legacy iptables（连同下面「与 iptables-legacy 共存」的说明）、这次会全局打开转发等 |
| `platform_supported`、`artifact_plan`、`foreign_binary` | 信息 | 匹配到的支持平台；每个面板下发的二进制要「传输并安装 / 已是固定版本不传输 / 替换」；主机上别的服务装的 wstunnel 或 smartdns 软件包（不使用、不覆盖、不删除） |

**不检查**（随每个结果返回，面板里也显示）：放行规则是否覆盖 Meridian 的端口；云厂商安全组和上游 NAT；别的服务以后的改动（Docker 重启由 meridian-fwcompat.service 接上；WARP 重连、有人手动启动或重载一个没启用的 nftables.service 不在预检之内）；SmartDNS 上游；WSS 两端能否握手（证书和路径由面板生成，见「WSS 承载：随机路径与自签证书」；面板下发的二进制只核对架构、路径和 SHA-256，预检里不执行它们）；预检里不执行 nft（远端规则集已避开 nft 0.9.3 不确定的写法，下发时 `meridian-up.sh` 仍先 `nft -c`）；iptables-legacy 主机上 legacy 链里的单条规则、nat 改写和 MARK；WARP 的配置和账户（只读进程名和地址）；sudo。预检不修改任何东西，发现的冲突由你处理。

预检结果（`preflight` 记录）还带 `platform`（匹配到的支持平台）、`binaries`（每个面板下发的二进制：名字、版本、架构、主机路径、SHA-256、大小、`install|keep|replace|refuse`、是否要传输）和 `package_plan`（每个发行版包：命令在不在、已装版本、apt 候选、`none|install|unavailable`），面板「安装计划」里逐项显示。

### 什么算「我们的」

只有在主机上已有**本节点、本面板**（远端：节点清单的节点和部署 ID 都对上；网关：面板的安装清单）的安装时，才会有资源被认作这次安装自己的，而且每一项都要有证据，否则照常算冲突：

- 文件、接口、单元、nft 表、路由表：在受管清单里。面板下发的二进制：清单里的 `file` 行（远端另有 `artifact <名字> <版本> <路径> <sha256>` 行；网关是安装清单的 `artifacts`）。
- 监听：所在 WireGuard 接口在清单里（`wg show all listen-port`）；或套接字所在的 cgroup（`ss -Hlntu --cgroup`，经 sock_diag 读取，不需要访问进程）是清单里的单元（新装的出口解析器是清单里的 `meridian-smartdns.service`，进程名 `meridian-smartd`）；或监听解析器端口的是清单里有解析器配置时的 `smartdns.service`（以前的版本用发行版包装的解析器），网关上则是 docker compose 管的固定容器 `meridian-smartdns`（宿主代理用固定参数 `docker inspect --format '{{.Id}} {{.State.Running}}' meridian-smartdns` 取它的 ID，与套接字 cgroup 里的容器 ID 比对）。宿主代理的 systemd 单元只有 CAP_NET_ADMIN，`ss -p` 看不到进程名，所以网关上靠 cgroup；读不到 cgroup（旧版 iproute2）时不认，仍报冲突。
- 地址和路由：在清单里的接口上；或这份包自己写的 lo 中转地址（`ip addr replace … dev lo`）及内核为它加的路由；与包里完全相同的路由。
- 策略规则：查清单里的路由表、`iif` 是清单里的接口，或与包里同优先级、同标记的规则。
- DOCKER-USER 里的放行规则：注释是 `meridian-fw-` 加 8 位十六进制（清单记 `fw <族> DOCKER-USER`）。更新时预检报告已有几条（`iptours`），把它们列为「更新」而不是冲突；meridian-fwcompat.sh 补齐当前规则集、删掉旧注释的。
- 开机单元 `meridian-node.service`、Docker 重启单元 `meridian-fwcompat.service`：和别的单元一样在清单里；从旧版本升级时它们的文件还不存在，按新建处理。

第一次安装、`managed_by_other`、没有清单的旧版安装都不认任何东西。网关安装本身不装软件包：缺 `wg`、`nft`、`ip` 时报 `gateway_tools_missing`（阻断）；SmartDNS 不要求 apt 包，报告它由容器、宿主服务运行还是还没启动（`gateway_dns_runtime`，信息）。

### 端口从哪里来

一个节点的包绑定的每个端口都由拓扑决定，而且只有一处代码决定它：`validate.TunnelPorts`，编译器（`compile.buildTunnels`）从它取端口，校验、网关的端口表（`validate.GatewayPorts`）和预检的修改指引（`validate.NodePorts` → `preflight.Context.Ports`）也用它，所以改一个字段之后，监听端的 WireGuard 配置、拨号端的 `Endpoint`（或经本地 wstunnel 到达的目标端口）、预检从编译结果读出的监听都一起变化（`TestPortReconfigurationEndToEnd`、`TestPortPlanMatchesBundle`）。

| 端口 | 来源（按顺序） | 在哪改 |
| --- | --- | --- |
| 链路监听端的 WireGuard UDP 端口 | 链路的 `wg_port`；监听节点的 `listen_port`（只在它只监听这一条没设 `wg_port` 的链路时）；`51820 + 链路序号`（链路保存在拓扑里的分配序号，不是它在列表里的位置，见「接口名、端口和网段的分配」） | 拓扑 → 链路「WireGuard 端口」，或节点「WireGuard 监听端口」 |
| UDP+WSS 故障切换的 WSS 腿 | 上面的端口 + 1 | 同上 |
| 拨号端 wstunnel 客户端（127.0.0.1，UDP） | 链路的 `wss_local_port`；`52000 + 链路序号` | 拓扑 → 链路「wstunnel 本地端口」 |
| 监听端 WSS 服务（TCP，通配地址） | 节点的 `wss_listen_port`；443 | 拓扑 → 节点「WSS 入口（高级）」→「WSS 监听端口」（枢纽、中继、出口都有） |
| SmartDNS | 固定 53（UDP/TCP）、853，只绑隧道地址 | 不可改 |

校验（`port_*` 问题，错误级别，带 `node_id` / `link_id` 和 `field`）：同一节点上两个监听用了同一协议的同一端口（WireGuard 的通配 UDP 和 wstunnel 的回环 UDP 也算冲突）→ `port_conflict`；WireGuard / wstunnel 端口用了 53、67、68、123、546、547、853、5353，WSS 端口用了 22、53、853，网关的 WSS 端口等于面板端口 → `port_reserved` / `port_conflict`；节点设了 `listen_port` 却监听多条没设 `wg_port` 的链路 → `port_ambiguous`；超出范围 → `port_invalid`。没有设置这些字段的拓扑，端口和以前完全一样（示例拓扑的编译结果不变）。

### 执行前复核

- 结果绑定到**目标身份**（服务器 ID、地址、端口、用户、固定的主机指纹、凭据 ID）和这个节点包的**摘要**（`preflight.BundleDigest`：按路径排序的文件哈希，私钥仍是占位符），有效 10 分钟，存在面板数据库（`preflight/<节点>`，只有地址、名字、端口和哈希，不含秘密）。
- `POST /api/provision` / `POST /api/apply {install:true}`：第一次下发（这台服务器上这个节点从没成功过；网关上没有安装清单）没有 `preflight_id` → 409 `preflight_required`。带了 `preflight_id` 就检查：记录不存在或已被替换、过期 → `preflight_stale`；身份变了 → `target_changed`；包变了 → `bundle_changed`；审阅的结果有阻断 → `preflight_blocked`。然后**在同一个固定身份上重新预检**：有阻断 → `preflight_blocked`；出现了审阅时没有的警告或阻断 → `preflight_changed`（响应里带新的结果）。更新（之前成功过）可以不带 `preflight_id`，但重新预检照样要过。阻断项不能在面板里跳过。
- 远端脚本本身在动手前再复核一次（`provision.ScriptWith`）：必须是 root；不能有没结束的上一次下发；预检时没有清单（第一次）就要求现在也没有、要建的接口和 nft 表也没有冒出来（`MERIDIAN_REFUSED manifest_appeared` / `interface_appeared` / `nft_table_appeared`，退出码 3，什么都没改）；预检时是本节点的清单就要求现在仍是（`manifest_changed`）。
- 同一个节点同时只能有一个预检或下发（409 `node_busy`）。

### 失败的下发：补偿或明确残留

远端脚本在 `/var/lib/meridian/node/` 下记 journal（`state running`），先记下下发前的接口、nft 表、规则、路由、相关 sysctl 和单元状态，替换的文件先备份。任何一步失败、或 SSH 会话断开（`HUP`/`PIPE` 被忽略，补偿照样跑完），`EXIT` 陷阱就补偿：停用这次启用的单元、删除这次新建的接口和 nft 表、删掉这次新增且属于 Meridian 优先级的规则、清空这次才有路由的受管表、删掉这次新增的 main 表 Meridian 路由、恢复 sysctl、删除这次新建的文件和目录、恢复被替换的文件（更新时再跑一次恢复后的 `meridian-up.sh`）。装上的软件包**按设计保留**（`MERIDIAN_KEPT package …`，卸载可能牵连别的软件）。撤不掉的逐项打印 `MERIDIAN_LEFTOVER …` 并写进 journal，状态记为 `incomplete`；全部撤掉记为 `compensated`。面板据此返回 `provision_failed_compensated` 或 `provision_failed_leftovers`（带 `leftovers`、`kept`），连接中断等看不到标记时 `outcome: "unknown"`——**任何情况下都不把没有 `MERIDIAN_PROVISION_OK` 的执行当成成功**。

标记怎样可靠地到达面板（真实部署里出过一次：主机上的 journal 是 `compensated`，面板拿到的输出里没有补偿标记，显示成「不明」）：

- 标记只从脚本的**标准输出**按行收集（`Result.Markers`）。以前标准输出和标准错误由两个协程写进同一个没有加锁的缓冲区：传输把一行切成两段时，中间插进来的错误输出会把 `MERIDIAN_COMPENSATED` 拆开，并发写还可能丢字节；输出超过 1 MiB 时最后的标记被截掉。现在合并输出只用于显示（加锁、仍截在 1 MiB），标记单独、逐行、不受截断影响；标准错误里出现的 `MERIDIAN_…` 不算数。
- 脚本**结束之后**（收到了退出状态，不论成功失败），面板在**同一次登录**里再跑一条固定的只读命令 `sshexec.NodeStateCommand`，读服务器的 journal 和清单头（节点、部署、服务器、包摘要、安装时间）。标记缺失时由 journal 决定：**这次运行**（`run` 一致）的 journal 是 `compensated` → `outcome: "compensated"`、`evidence: "host_journal"`，面板显示「失败并已补偿」并说明结论来自服务器 journal；`incomplete` → `left_behind`（带 journal 里的残留）；`done` 且清单的节点、部署、包摘要都对得上 → `installed`；别的情况（journal 是别的运行的、读不到）仍是 `unknown`。执行超时或执行中断线时不读（那时结果本来就不明，也不为了读而重连），由下一次预检显示 journal。下一次预检读到 `incomplete` / `running` 的 journal 会阻断，`compensated` 带残留时给警告。成功时写受管清单 `/var/lib/meridian/node/manifest`（节点、部署 ID、服务器、包摘要、每个文件的 SHA-256、接口、单元、nft 表、路由表、Meridian 装的包；上一版有而这一版没有的文件记为 `orphan`），下一次预检据此区分「本面板、同一节点」与其他情况。

中断的下发由面板恢复（journal 模式）、旧版安装由面板清理（legacy 模式）、已装好的节点由面板撤回，见下一节「撤回与失败后的恢复」。

### 逐节点的安装状态

每个节点都只和**它自己**实际装上去的内容比较，不和网关的快照、也不和别的节点比较（`internal/api/node_state.go`）：

- **网关**：网关的文件与网关的已安装清单按文件哈希比较（`install.state`）。
- **远端节点**：部署记录（`provision_state`）里除了最近一次尝试，还保存**最近一次成功安装**的内容摘要 `installed_bundle`（这个节点文件的 `preflight.BundleDigest`，也就是主机清单里的 `bundle`）、时间、运行号、装到的身份 `installed_target`（服务器、地址、端口、用户、指纹、凭据），以及最近一次核对主机记录的结果 `verify`（`verified` / `mismatch` / `unverified`，来源 `post_install`：装完后在同一次登录里读回；或 `preflight`：每次预检读到的主机清单）。失败的尝试（补偿回到上一版）不改这些字段。状态按「当前拓扑编译出的这个节点的摘要」对「`installed_bundle`」计算：`in_sync`、`changed`、`not_installed`、`unknown`（最近一次结果不明或有残留；或下面的迁移还没完成）、`target_changed`（节点现在指向另一台服务器或另一把指纹）。`GET /api/status` 的 `nodes` 和 `GET /api/provision/state` 的 `states` 给出每个节点一行；部署页的远端节点表格有「安装状态」一列。单独下发一个远端节点只改变它自己那一行。
- **迁移**（幂等，读取时完成，下一次写入时落盘）：旧记录里最近一次结果是成功的，直接用那次的摘要和身份；最近一次是失败（之前成功过）的，状态显示 `unknown`，操作员对这个节点做**一次预检**（只读）即可：预检读到的主机清单如果是本面板、本节点、同一台服务器，就用清单里的 `bundle` 补上。网关不需要迁移（它的状态一直来自已安装清单）。
- **经隧道管理的地址候选**（`internal/compile/mgmt_reach.go`、`GET /api/servers/{id}/tunnel-candidates`）：选「经隧道地址」时，面板列出这台服务器的节点在每条隧道上的地址，并说明每个地址从网关到不到得了——不是枚举接口地址然后碰运气。见下「经隧道管理的地址候选」。
- **枢纽报告**（地区组的实际状态，`POST /api/region-groups/runtime/refresh` 读取）照旧按节点、服务器、地址、端口和固定指纹核对读取的是哪台枢纽；管理通道只是传输方式，不改变这些身份。
- **解锁决定的自动安装**的「决定之前已同步」条件改为只看网关自己的安装状态（网关文件与按上一次决定编译的结果一致），不再比较所有节点的已应用快照：自动安装只写网关文件，而且只允许改动允许列表里的网关文件（条件 2 拒绝改动别的节点文件的决定），所以别的节点有没有单独下发、有没有待下发的改动都与它无关。以前只要单独下发过一个远端节点，它就一直以 `out_of_sync` 拒绝。升级后不需要操作员做什么；仍然需要的只有原来就有的一条：升级后至少经面板人工安装过一次网关（`no_installed_record`）。

### 预检的文件清单：只列有变化的文件

以前网关预检的变更清单把每一个受管文件都列成「替换」（约 30 行），看不出这次到底改了哪几个文件；部署页「待安装的改动」（`POST /api/diff` 的 `installed`）和逐节点状态才是准的。现在预检的文件条目来自**同一份逐文件比较**（`apply.DiffManifests`，按内容哈希；网关直接用 `POST /api/diff` 背后的 `Applier.InstalledFileDiff`），不另写比较：

- 预检结果多一块 `file_changes`：`basis`（`installed_manifest`：网关的已安装清单；`host_manifest`：远端节点自己的清单，预检时读到的）、`added`、`changed`、`removed`、`unchanged`、`not_compared`、`removed_kept`、一句话的 `summary`。只有路径和计数，不含内容和哈希。
- 变更清单（`changes`）里的文件条目：`create`（新增）、`change`（内容变化）、`remove`（不再由拓扑生成）、`not_compared`（见下）。**内容不变的文件不再列为动作**，只在 `unchanged` 里计数；面板先列有变化的文件，再显示「N 个文件内容不变」（可展开）。完全没有变化时，预检结果直接写「没有文件变化：这次安装写入的 N 个文件与已安装的内容相同」。
- 网关撤回后，已安装清单只剩兜底文件：比较照样进行，其余文件都是「新增」。没有可比较的记录（第一次安装、远端节点没有清单或清单不属于这个节点或这个部署、远端预检报告不完整）时没有 `file_changes`，文件照旧逐个列出（主机上不存在的是 `create`，受管的是 `replace`）。清单里有、主机上却已不存在的文件仍列为 `create` 并注明。
- **注入密钥的文件**：网关的已安装副本保留编译时的占位符（私钥、远程接入私钥和预共享密钥、WSS 和外部出口的秘密都在安装边界才注入），所以网关上每个文件都按注入前的形式比较，不需要、也不用到任何密钥。远端节点的清单记的是主机上写入后的副本的哈希（脚本补上末尾换行、注入了私钥或秘密）：普通文件按脚本写入的形式（`provision.HostContent`）比较；含占位符的文件（`provision.InjectedAtInstall`：WireGuard 配置、WSS 与外部出口的秘密文件）在没有密钥时无法比较——如果清单里的包摘要（覆盖注入前内容）等于这次的，它们算不变，否则列为 `not_compared`（「含安装时注入的密钥，无法与主机上的内容比较：安装会重写它」），**不是**「替换」。为了比较，面板不把任何秘密、注入后的内容或哈希发给浏览器。
- 删除：网关安装事务会删除 `removed` 里的文件；远端节点的安装不删除，它们在主机清单里记为遗留（`orphan`），撤回时移除，`removed_kept` 和条目说明写明这一点。
- 接口、路由、监听等条目照旧按这次安装要建立的状态列出（例如每个受管接口都是 `update`），**不与已安装的状态比较**——这是另一种机制（读主机的运行状态，而不是比较文件内容），这次没有改；面板在文件摘要旁写明这一点。
- 只改了报告：安装写什么、事务、预检关卡（阻断项、执行前复核、`preflight_id` 绑定）都没有变。

测试：`TestGatewayPreflightFilesMatchInstalledDiff`（安装之后依次：没有改动、改一条规则、服务组改指向、改一条链路，每一步预检的 `added` / `changed` / `removed` 与 `POST /api/diff` 的 `installed` 完全一致，文件条目里没有 `replace`，没有改动时写明「没有文件变化」；应答里没有私钥或占位符），`TestRemoteFileComparison`（远端：末尾换行、内容变化、新增、遗留、注入密钥的文件未比较、包摘要一致时全部不变、别的节点的清单不比较），`TestFileChangesFromComparison`（评估：条目和摘要），`web/src/topology_contract.test.tsx`（面板先列变化、再列不变数量；没有变化时直说）。

### 预检列出将被移除的旧接口

更新时，上一次安装有、这一次没有的接口会在安装时先被删除（远端：脚本删除本节点清单里 `m<数字>…` 和 `mmesh` 这类 Meridian 接口；网关：安装事务删除已安装清单有而新清单没有的接口）。预检的变更清单现在把它们列为 `interface remove`（「上一次安装的接口，这次的拓扑不再有它」；主机上已经不存在的注明只从清单里去掉），面板在预检结果里用「移除」标出。以前网关预检不列这些，实际安装时是正确移除的。

### 登录方式不被接受

`auth_failed`（服务器试了并拒绝这份凭据）和 `auth_method_unavailable`（服务器根本不提供这种登录方式）分开报告。握手时面板记下服务器**实际提供**的登录方式（`password` / `publickey` / `keyboard-interactive`，只探测、不发送任何东西），放进错误、连接测试结果（`offered_methods`）和 `login_help`（`offered_methods`、`publickey_offered`）。只有服务器提供 `publickey` 时才建议改用密钥、给出可复制的公钥：

| 凭据 | 结果 | `login_help` |
| --- | --- | --- |
| 密钥 | `auth_failed`（服务器收公钥，但不认这把） | 这把密钥的公钥 + 追加到 `authorized_keys` 的步骤 |
| 密钥 | `auth_method_unavailable`，服务器只提供密码（例如经端口转发才能到、只收密码的 IX） | **不给公钥**；提示给这台服务器添加密码凭据并把认证方式改为密码——用密码时面板全部功能可用；想改用密钥要先在服务器上开 `PubkeyAuthentication` |
| 密码 | `auth_failed`，服务器只提供密码 | 更新密码；不提密钥 |
| 密码 | `auth_failed`，服务器也提供公钥 | 更新密码；也可以改用密钥（列出面板密钥凭据的公钥） |
| 密码 | `auth_method_unavailable`，服务器只收公钥 | 列出面板密钥凭据的公钥，没有就提示先生成一把 |
| 密码 | `auth_method_unavailable`，也没有公钥 | 说明服务器提供的方式，检查 `sshd_config`；不提密钥 |

只含公钥，不含任何秘密。这些行为由 `TestLoginHelp` 在进程内 SSH 服务器上覆盖，没有在真实服务器上执行过。

### API

| 方法与路径 | 请求 | 成功响应 |
| --- | --- | --- |
| `POST /api/provision/preflight` | `{node_id, generate_keys?}` | `{"preflight": 预检结果}`：`id`、`kind`、`target`（身份）、`bundle`、`first_install`、`at`、`expires_at`、`host`、`footprint`（受管资源）、`ownership`、`blocking`、`counts`、`findings[]`、`changes[]`、`not_checked[]`；登录失败 502 带 `login_help` |
| `GET /api/provision/preflight/{node}` | | `{"preflight", "stale"}` |
| `GET /api/provision/state` | | `{"nodes": {节点: 最近一次下发的结果}}` |
| `POST /api/host/preflight` | `{}`（不接受任何字段） | `{"preflight": 预检结果}`；503 `host_unavailable`，502 `preflight_failed` |
| `POST /api/provision` | `{node_id, generate_keys?, preflight_id?}` | 见上；预检类拒绝 409 `preflight_required` / `preflight_stale` / `preflight_blocked` / `preflight_changed` / `bundle_changed` / `target_changed` / `node_busy`，面板的二进制副本不可用 409 `artifact_unavailable`、传输失败 502 `artifact_stage_failed`（这两种 `outcome: "not_started"`，主机上什么都没装），远端复核拒绝 409 `provision_refused`（`reason` 含 `artifact_missing` / `artifact_digest_mismatch` / `artifact_changed` / `artifact_path_foreign` / `resolver_bind_unsafe`），失败 502 `provision_failed_compensated` / `provision_failed_leftovers` |
| `GET /api/artifacts` | | `{"artifacts": [{name, version, arch, sha256, size, source_url, host_path, available, error?}]}`：面板下发的二进制和面板是否持有已校验副本（不含内容） |
| `POST /api/apply` | `{install:true, preflight_id?}` | 同样的预检类拒绝；宿主代理不支持预检时 503 `host_unavailable` |

代码：`internal/preflight`（脚本、解析、评估）、`internal/provision`（下发脚本的复核、journal、补偿、清单）、`internal/artifacts`（固定版本与校验）、`internal/sshexec`（`RunPreflight`、`Stage`）、`internal/hostexec/preflight.go`（网关预检动作）、`internal/api/preflight.go` 与 `provision_api.go`（关卡、记录、登录帮助）、`web/src/Preflight.tsx`（审阅界面）。

## 面板下发的二进制与支持的平台

### 二进制从哪里来、怎么固定

wstunnel 和 SmartDNS 由面板自己提供，目标主机**从不下载**任何东西（几台服务器连不上境外下载源，网关连不上 Docker Hub 和 raw.githubusercontent.com）。

- **唯一的固定处**：`internal/artifacts/artifacts.lock`。每行一个「名字 版本 架构 二进制 SHA-256 大小 上游下载 SHA-256 来源类型 成员 URL」。面板用 `go:embed` 把它编进二进制（`artifacts.Pins()`），镜像构建用同一个文件下载。

| 名字 | 版本 | 架构 | 二进制 SHA-256 | 大小 | 上游 |
| --- | --- | --- | --- | --- | --- |
| wstunnel | 11.1.0 | x86_64 | `62b26d0ee0f2211cef15fa1b85173fe687bc6698121842bf324359b412afc151` | 13752784 | `wstunnel_11.1.0_linux_amd64.tar.gz`（`512edf4e…`，与 release 的 checksums.txt 一致），静态 PIE |
| wstunnel | 11.1.0 | aarch64 | `a2e4e02bf63a7608ae82625b1a0a16dc00d562e0a0326c26f22b26e84a857459` | 10851944 | `wstunnel_11.1.0_linux_arm64.tar.gz`（`148895f9…`），静态 |
| smartdns | 1.2026.08.05-0921（Release48.4） | x86_64 | `8adb80ce14d3a90a852d1dcc14d6a485ff0b65622d7ef294c4b8f1d0f51eb645` | 6030712 | release 资产 `smartdns-x86_64`（GitHub 公布的资产摘要与此相同），静态 PIE |
| smartdns | 1.2026.08.05-0921（Release48.4） | aarch64 | `1208c5562046c71913c3df88ad4e3ed0a3410161ff77ce4a60cdd63936bf1b27` | 5301472 | release 资产 `smartdns-aarch64`，静态 PIE |

- **镜像构建**（`deploy/Dockerfile` 的 `artifacts` 阶段，`deploy/fetch-artifacts.sh`）：按锁文件从固定的 GitHub release URL 下载（或者用 `deploy/artifacts/` 里操作员事先放好的同名上游文件——离线构建），先核对上游文件的 SHA-256，再取出可执行文件核对大小和 SHA-256，任何一项不符构建失败；结果放进镜像里只读的 `/usr/share/meridian/artifacts/<名字>-<架构>`，旁边写 `manifest.txt`（名字 版本 架构 SHA-256 大小 文件）。构建需要能访问 `deb.debian.org`（`artifacts` 阶段装 curl）和 `github.com` / `objects.githubusercontent.com`（release 资产的下载跳转）；Mac 上 `docker buildx build --platform linux/amd64` 照常可用。二进制不进 git（`deploy/artifacts/.gitignore`）。
- **面板加载与再校验**（`artifacts.Load`）：启动时读 `MERIDIAN_ARTIFACTS_DIR`（默认 `/usr/share/meridian/artifacts`），每个文件按编进来的固定值核对大小和 SHA-256，`manifest.txt` 存在时每一项也必须与固定值一致；不符的那个二进制记为不可用并写日志。每次发送前（`Bundle.Read`）再读一遍、再核对一次；这时不符的会被标为不可用，下发以 409 `artifact_unavailable` 拒绝，什么都没发送。换目录只能换来源，换不了版本和摘要。`GET /api/artifacts` 和部署页「面板下发的二进制」显示固定版本和面板副本的状态。

### 下发：远端节点

1. **预检**多问二进制的主机路径（`/usr/local/sbin/meridian-wstunnel`、`/usr/local/sbin/meridian-smartdns`；这两个路径的 SHA-256 算到 64 MiB，其他文件仍是 4 MiB），按报告里的架构选固定版本：路径不存在 → `install`（要传输）；已经是固定摘要 → `keep`（**不传输**）；清单记着是我们的但摘要不同 → `replace`；有文件但不在清单里 → `path_occupied` 阻断；面板没有这个架构的已校验副本 → `wstunnel_missing` / `smartdns_unavailable` 阻断。
2. **传输**（`sshexec.Connector.Stage`）：在同一流程的连接池连接上（预检复跑、传输、下发脚本共用一次登录）开第二个会话，执行**固定的接收命令**：`head -c <大小>` 从标准输入读到 `/var/lib/meridian/stage/<名字>.part`（目录 0700、文件 0600），核对大小和 SHA-256，通过才改名，否则删掉部分文件。命令里只有名字（`wstunnel` / `smartdns`）、64 位十六进制摘要和大小（1 … 64 MiB）会变，构造前全部校验；面板发送前也核对一次内容。没有任意命令接口；二进制不经 shell heredoc。
3. **下发脚本**（`provision.ScriptWith`，`Options.Artifacts`）：节点的单元要用的二进制必须都在选项里，否则脚本一开始就 `MERIDIAN_REFUSED artifact_missing`。在 journal 打开**之前**（`m_art_check`）：暂存文件要存在且摘要等于固定值（不符就删掉并 `artifact_digest_mismatch`）；目标路径上已有文件而清单不记它 → `artifact_path_foreign`；`keep` 的副本要仍是固定摘要（`artifact_changed`）。拒绝时主机上什么都没改。事务里（`m_art_install`）：`m_track` 备份旧文件，复制到目标目录里的临时文件、0755、再核对一次摘要、改名就位；替换了的二进制在 `meridian-up.sh` 之后 `systemctl try-restart` 用它的单元。失败的下发补偿时恢复旧文件、删掉新文件，与其他文件一样。
4. **清单**：二进制是普通的 `file <路径> <sha256>` 行（这次没重写、保留的也照样记，不会变成 `orphan`），另加 `artifact <名字> <版本> <路径> <sha256>`。撤回按 `file` 行删除（摘要不符就保留并列出），`artifact` 行逐项校验（名字、路径、版本、摘要不认识就整次拒绝）。

### 下发：网关

网关的 WSS 客户端（`wstunnel-client-*.service`）也用同一份已校验副本。安装到网关时（`apply.Applier.Artifacts` / `Arch`，架构取面板进程的 `runtime.GOARCH`，与宿主相同），面板经已有的 `/usr/local/sbin` 绑定挂载写 `/usr/local/sbin/meridian-wstunnel`，作为安装事务的一部分：安装清单记 `artifacts`（名字、版本、架构、路径、SHA-256、大小）；`converge` 先放二进制再写单元，摘要已对的不重写，不在任何一份清单里的同名文件拒绝覆盖，替换前把旧副本存进事务的暂存目录，补偿时放回；没有单元再用它时随单元一起删除（被改过的保留并警告）。面板没有已校验副本时安装在写任何宿主文件之前被拒绝。网关上的 SmartDNS 仍然是 compose 里的容器，不变。

### 归属：只用 Meridian 自己的路径

主机上别的服务自己装的 `/usr/local/bin/wstunnel`（例如一台机器 443 上已有的 wstunnel）或发行版的 smartdns 包与 `smartdns.service`：**不使用、不覆盖、不删除**（`foreign_binary` 信息）。出口解析器改由 Meridian 自己的单元 `meridian-smartdns.service` 运行面板下发的二进制（`/usr/local/sbin/meridian-smartdns -f -x -p - -c /etc/smartdns/smartdns.conf`），远端节点不再从 apt 装 smartdns。`/etc/smartdns/smartdns.conf` 被别人的配置占着时照旧 `path_occupied` 阻断。以前的版本装过发行版 smartdns（清单有 `pkg smartdns`）的节点更新时，脚本先停用 `smartdns.service` 再启动新单元（它占着隧道地址的 53），失败的更新会按下发前的状态把它恢复；软件包保留。

### 出口解析器的配置与 SmartDNS 版本

出口（`compile.renderExitDNS`）的配置只用 `speed-check-mode none`、`cache-size 4096`、`bind <隧道 v4>:53`、`bind-tcp <隧道 v4>:53`、`bind [<隧道 ULA>]:53`、`bind-tcp [<隧道 ULA>]:53`、`server 1.1.1.1`、`server 8.8.8.8`。在固定版本 Release48.4 的源码里核对过：`src/dns_conf/dns_conf.c` 的配置表有 `bind`（`_config_bind_ip_udp`）、`bind-tcp`、`server`（`_config_server_udp`）、`speed-check-mode`、`cache-size`（`CONF_SSIZE`）；`src/dns_conf/bind.c` 的地址解析接受 `[IPv6]:端口`。同一文件里 `_config_add_default_server_if_needed` 在**没有任何 bind** 时自动绑 `[::]:53`，所以没有 bind 或绑通配地址的配置在预检（`resolver_bind_unsafe`）和下发脚本里都被拒绝。命令行 `-f`、`-x`、`-p -`、`-c` 来自这个版本的帮助文本。网关的配置用到更多指令（`-set-mark`、`nftset`、`domain-set`、`bind-tls` 等），但网关继续用 compose 里的容器镜像，不用这份二进制。**这些都只是对源码和文档的核对，固定版本没有在真实主机上运行过。**

### 出口解析上游（设置 `exit_dns`，修订 19）

默认（不设置）出口的 SmartDNS 从出口自己的上联以明文问两个固定的公共解析器（`server 1.1.1.1`、`server 8.8.8.8`），编译结果与以前逐字节相同（`TestExitDNSUnconfiguredIdentical`，原有 golden 不变）。

**设置。** `settings.exit_dns`（全局，所有受管出口）和 `nodes[].exit_dns`（单个受管出口的覆盖；`{"protocol":"builtin"}` 表示这个出口保持内置）。字段：`protocol`（`dot` / `doh`）、`addresses`（1–2 个上游 IP，由操作者给出）、`port`（缺省 853 / 443）、`tls_host_name`（证书必须带的名字，也是 SNI 和 DoH 的 HTTP Host）、`path`（只 DoH）、`account_credential`。没有「跳过证书校验」的字段。外部 SOCKS 出口不受它影响（它们的名字在承载出口上经代理问固定的公共解析器，见「挂在中继出口后面的出口」），在它们或网关上设置被校验拒绝。只经 Mesh、没有隧道解析器的出口照旧返回 SOA。

**账户标识。** 提供方用主机名的第一个标签或 URL 路径里的一段识别账户。主机名或路径里写 `{account}`，值是凭据存储里的「DNS 账户标识」（`internal/credentials/dns.go`，与 SOCKS 凭据同样：只写一次、只存在 `secrets/` 的 0600 文件里、接口只返回元数据，`/api/dns-accounts`）。编译结果里只有占位符 `__MERIDIAN_SECRET_<id>__`，所以拓扑、快照、导出、`/api/compile`、`/api/diff`、预检记录、原文查看（再把占位符换成「‹账户标识已隐藏›」）和演示数据里都没有这个值。值只在安装边界注入：`postProvision` 读取该出口引用的那一个凭据（`exitDNSCredentials`），与 WSS / SOCKS 秘密合并后交给 `provision.InjectPrivateWSS` → `apply.InjectSecrets`；`InjectSecrets` 只允许 `etc/smartdns/smartdns.conf` 引用 `dnsacct-` 凭据，这个文件也不能引用任何别的秘密，值必须是一个合法的域名标签（3–63 个字母、数字、中间的连字符）。带账户标识的配置第一行是 `ExitDNSRestrictedMarker`，下发脚本据此把它写成 0600（SmartDNS 以 root 运行）。脚本输出和错误按已有方式把值替换回占位符（`redactRemote`）。远端节点的清单记录的是注入后文件的摘要，所以预检把这个文件列为「未比较」，除非整包摘要与上次安装一致。

**轮换账户标识**（`PUT /api/dns-accounts/{id}/secret`，`internal/api/dns_version.go`）。占位符只带凭据 id，轮换后不变；只看占位符的话出口的文件、整包摘要都不变，已装的出口会一直显示「一致」，部署引导跳过它，出口继续用旧值。所以每个凭据有一个**版本**：创建时 1，每次轮换加一，是凭据索引里的计数（就是存秘密文件用的 generation），不由值推出，不含值的任何摘要。面板编译时（`compileWith` 的最后一步 `stampDNSAccounts`）在每个带 `dnsacct-` 占位符的 SmartDNS 配置里、紧接 `ExitDNSRestrictedMarker` 之后写一行 `# meridian-account-version: <版本>`。版本因此是节点文件的一部分，凡是绑定整包摘要的地方都随之变化：

- 轮换后，每个用这个凭据的受管出口（全局设置或自己的覆盖，覆盖为 builtin 的不算）的状态是「有变更」，原因写明「DNS 账户标识已轮换（已安装 … 版本 1，现在是 … 版本 2）」；不引用它的节点摘要不变、状态不变。轮换的回答里 `pending` 列出这些出口。
- 部署引导把它们排成安装步骤：不是「只核对」（状态不是一致），也不会被采纳（服务器清单记录的是旧摘要）；计划版本（`deployVersion`）把版本也算进去，所以进行中的部署引导变成「需要重新计划」。
- 轮换前做的预检绑定的是旧摘要，带它下发被拒绝（`bundle_changed`），要重新预检；下发时还核对读出的值的版本就是文件里写的版本，预检和下发之间又轮换了也拒绝。
- 成功安装（或从服务器记录采纳）时把实际用的版本记在安装记录里（`provisionOutcome.InstalledDNSAccounts`，预检记录里也有 `dns_account_versions`）；状态接口给出 `dns_account_versions` / `installed_dns_account_versions`，解析配置视图给出 `account_version` / `installed_account_version`。重新安装后恢复一致，两边都是新版本。
- 兼容：不引用账户标识的配置一行不加，没有配置上游或上游不带账户的拓扑编译结果逐字节不变，这些节点升级后不会变成待下发。在记录版本之前装好的、引用账户标识的出口，升级后摘要不同、记录里没有版本：保守地算「有变更」，原因写明「安装记录没有账户标识的版本……无法确认装上去的是当前的值」，重新预检并安装一次即可。

外部 SOCKS 出口的凭据（`PUT /api/socks-credentials/{id}/secret`）在承载节点的 gost 配置里同样只有固定的占位符，用同一个办法处理（版本写进承载节点的配置），另加一条只取一次的基线，使升级本身不把已部署的承载节点变成待下发：见「外部 SOCKS 出口」一节的「轮换 SOCKS 凭据」。WSS 的秘密轮换走分阶段的占位符（阶段变化就是文件变化），不受影响。

**生成的行**（`writeExitUpstream`，固定的 SmartDNS 1.2026.08.05-0921 / Release48.4，出口用的就是这份面板下发的二进制）：

```
# meridian-restricted: an account identifier is injected here at install (file 0600)
# meridian-account-version: 1 (version of the account identifier: +1 per rotation; not the identifier)
ca-file /etc/ssl/certs/ca-certificates.crt
server-tls 192.0.2.53:853 -host-name <名字> -tls-host-verify <名字>
server-https https://198.51.100.53/dns-query -host-name <名字> -http-host <名字> -tls-host-verify <名字>
```

- 只用这一版本支持的 `server-tls`、`server-https`、`-host-name`、`-http-host`、`-tls-host-verify`、`ca-file`。证书链按系统 CA 包（Debian/Ubuntu 的 `ca-certificates`）校验，主机名必须匹配 `tls_host_name`（含注入后的账户标签；提供方用通配证书时按 `*.` 匹配，见下面的真实二进制测试）。
- **引导（bootstrap）**：上游按操作者给的 IP 地址连接，URL 里也是地址，SmartDNS 从不解析上游自己的名字，所以不需要 `-bootstrap-dns`，也没有一条可能经别的路径发出的引导查询。
- **线路**：没有 `-set-mark`、`-proxy`、`-interface`，查询按出口的主路由表、从出口自己的上联发出，CDN 调度与出口一致；校验拒绝私有、CGNAT、本机、链路本地、组播和 ULA（含隧道的 fd66::/48）地址，也拒绝国内解析器（`domestic_dot`）的地址，所以上游不会经隧道、局域网或国内一侧。
- **不回落**：配置的上游是出口默认组里唯一的服务器，不再写 `server 1.1.1.1` / `8.8.8.8`，也没有 `-fallback`。SmartDNS 同一组里的服务器是并行询问、取最快的回答，「明文作为后备」就等于明文与加密服务一起回答，面板就看不出配置的服务是否真的在用；所以不提供这个选项。上游不应答时这个出口的名字解析失败（SERVFAIL），网关也不会改问别的出口或国内解析器（与以前的隧道解析相同）。

**生效。** `PUT /api/dns/upstream` 只把设置存进拓扑（整份拓扑保存不会改它，见「整份拓扑保存与独立资源」）；要在部署页对每个出口预检、确认并安装才生效。预检的变更列表对这个文件写一行「出口解析上游：DoT …（证书校验 ‹账户标识已隐藏›.…）；账户标识在安装时注入，文件 0600，这里和差异里都不显示」。

**只改请求里写到的部分（修订 20）。** `PUT /api/dns/upstream` 的请求体 `{"global": …, "exits": {"<id>": …}}` 里：没有 `global` 键时全局设置保持不变（`"global": null` 才清除）；`exits` 里没列出的出口保持原来的覆盖；列出的出口取值 `null` = 沿用全局设置、`{"protocol":"builtin"}` = 使用内置解析器、DoT / DoH 对象 = 单独设置。两者都没有的请求被拒（400）。修订 20 之前省略 `global` 等于把它清空，只改一个出口就必须把当前全局设置原样带上，存在覆盖并发修改的风险；现在单个出口的保存不带 `global`。校验与全局设置相同（`validate.CheckExitDNSUpstream`，网关和外部 SOCKS 出口上的覆盖 422，未知节点 404，引用不存在的账户标识凭据 409），鉴权、资源锁和「整份拓扑保存不写它」的独立资源约定（`topology_contract.go`）不变。回答多了 `changed_exits`：这次保存让哪些受管出口的生效上游（覆盖与全局合起来的结果）发生了变化；它们要预检、确认、安装后才生效，保存本身不触发任何安装。

**操作流程（名单页「解析配置 → 出口解析上游」）。** 每个受管出口一行：生效的上游和来源（全局设置 / 本出口单独设置 / 本出口保持内置 / 未设置）、打码的摘要（账户标签显示为「‹账户标识已隐藏›」）、计划与主机上已安装是否一致以及账户标识的计划 / 已安装版本（`account_version` / `installed_account_version`，轮换后不同）、行内的只读「解析检查」。网关和外部 SOCKS 出口也列出，标为「不可设置」并写明原因；只经 Mesh、没有隧道解析器的出口可以设置但不能检查。点「设置」打开这个出口的表单：沿用全局设置 / 使用内置解析器 / 单独设置；单独设置的字段与全局表单是同一个组件（协议、地址、端口、TLS 主机名、DoH 路径、账户标识凭据的选择或就地新建——新建走原有的只写接口，值只发送一次，界面上不回显）。保存后页面重新读取状态，提示「待下发的出口：…」，然后在部署页逐个预检、确认差异并安装。「解析检查」问的是已安装的配置，不是刚保存的设置。

### 解析配置视图（`GET /api/dns`，名单页「解析配置」）

只读，从编译用的同一组计划（`compile.ResolutionPlan`）得出：客户端的查询、国内名字、未列名单的名字、每个可切换的地区组、每个出口（含外部 SOCKS 出口）、拒绝规则（产品没有内置广告名单）、已知公共 DoH、网关主机自己（`/etc/resolv.conf` 不由 Meridian 管理，没有读取）——各自由谁应答、上游、传输（明文 / DoT / DoH / 隧道内明文）、从哪条线路发出、相关开关的当前值。这些行标为「计划（未验证）」。

- **计划与已安装**：网关按安装记录里这个文件的摘要（`InstalledFileDiff`，注入前的形式）；远端节点按上次成功安装的整包摘要（面板只记录整包摘要：不一致时这个文件本身是否不同要看预检的文件比较）。带账户标识的配置另外给出计划的和已安装的账户标识版本；只因轮换而不同时写明「已轮换」。
- **原文**：`GET /api/dns/config?node=<id>` 返回编译出的配置，占位符换成「‹账户标识已隐藏›」；它从不读取主机上的文件，所以不可能带出注入的值。
- **实测**：嗅探转发服务的逐解析器自检结果和健康记录（见下一节）；「解析检查」（下面）。其它都标为未验证。
- **解析检查**（`POST /api/dns/check {"exit_id"}` → 宿主代理固定动作 `POST /v1/dns/check`，`internal/hostexec/dns.go`）：网关向该出口的隧道解析地址问固定名字 `example.com` 的 A 记录，与网关 SmartDNS 转发这个出口名字的路径相同（无标记、明文、经 WireGuard 隧道），出口的 SmartDNS 再从出口自己的上联问它的上游。参数只有出口 id 和这个地址，地址必须在 fd66::/48 里并且出现在网关已安装的 SmartDNS 配置的 `server <地址> -group …` 行里；名字、类型、端口、标记都不是参数；总时限 4 秒，与探测共用互斥（安装或回滚进行时不运行）。**限度**：它证明出口解析器经隧道有回答；回答可能来自出口缓存，也不说明是哪个上游回答的——配置了加密上游时出口没有别的上游，所以一个非缓存的回答就是配置的上游给的。它不在节点上新增任何远程能力，也不直接连上游；直接核对「提供方是否收到查询」只能在提供方自己的日志或测试页上看（见[验收清单](verification.md)）。结果只保存在面板内存里。

### 直连目标的解析器（嗅探转发服务，修订 19）

网关 SmartDNS 的国内组对每个国内解析器同时写 `server-tls <ip>:853` 和 `server <ip>`，任一方式应答即可。转发服务的「直连」目标用同一组解析器的明文 53（UDP，截断时 TCP）。实际部署中默认的两个国内解析器有一个只在加密端口应答、明文 53 没有回应；以前转发服务按顺序逐个问（一个超时才问下一个），自检也对它固定等满 2 秒。

现在（`internal/sniff/resolver.go`）：

- **竞速与对冲**：一个目标的解析器先按健康排序（没被降级的在前、保持目标文件里的顺序），先问第一个；它失败（错误、SERVFAIL、REFUSED）就立刻问下一个，它 `HedgeDelay`（250 ms）内没有回答也同时问下一个；第一个 NOERROR / NXDOMAIN 胜出。每次交换仍由 `ResolveTimeout`（2 秒）约束，整个查找仍由 `LookupBudget`（3 秒）约束；两个解析器都不应答时约 2.25 秒失败，不再是串行的 4 秒。
- **健康记忆**：每个（解析器，查询标记）记下最近的结果、时延、应答 / 失败次数；没有回答（超时、被拒、不可达、发送被拒、回答不符）就降级 `HealthDemoteFor`（1 分钟）：之后的查找把它排在最后，只有前面的失败或沉默超过 250 ms 才会问它；任何一次回答立即解除。落选的交换仍按自己的超时跑完并记录结果（每次查找每个解析器至多一次）。
- **自检**：每个解析器单独报告（结果、回答码、时延、这次最多等多久、传输），自检结果附带健康记录（`resolver_health`）；已被降级的解析器用 `SelfCheckRecheckTimeout`（500 ms）复查，所以周期自检不再因为一个沉默的解析器固定多等 2 秒。目标的判定不变（任一解析器有回答即可）。
- **没有加 DoT**：SmartDNS 国内组的 `server-tls` 没有 `-host-name` / `-tls-host-verify`，即不按主机名校验；要与它一致就只能做不校验名字的 TLS，这与本轮「正确校验证书」的要求冲突（以 IP 连接时只能按证书里的 IP SAN 校验，提供方是否签了 IP SAN 没有在真实主机上核对）。所以转发服务仍只用明文 53，出站限制（`sniff_confine` 只放行目标文件里的解析器的 53）不变，没有新端口。

### 支持的平台

远端节点只支持下表；其他发行版、版本、架构组合和 5.6 以前的内核（没有内置 WireGuard）都被拒绝并说明（`os_unsupported` / `arch_unsupported` / `kernel_too_old`）。网关仍是 Debian 12 / 13（x86_64 或 aarch64），它不装软件包。

| 平台 | 说明 |
| --- | --- |
| Debian 12 x86_64 | apt 装缺的 wireguard-tools / nftables / iproute2；Debian 12 自带的较旧 smartdns 包不再使用 |
| Debian 13 x86_64 | 同上 |
| Ubuntu 20.04 aarch64 | 内核 5.15（HWE），没有 `nft`、iptables 是 legacy 后端、ufw 已装未启用、netfilter-persistent 在运行。nftables（0.9.3）和缺的 wireguard-tools 列进安装计划，经 apt 安装（`--no-install-recommends`：不会装 wireguard-dkms）|

缺的包经 `apt-get install -y --no-install-recommends` 安装；预检脚本用 `dpkg-query` 和 `apt-cache policy` 报告已装版本和候选版本（`pkg` 行），没有候选版本时 `package_unavailable` 阻断。生成的 nft 规则能否被 Ubuntu 20.04 的 nft 0.9.3 接受**没有在 0.9.3 上执行过**；远端规则集已按 0.9.3 的能力复核（见下面「nft 0.9.3」），`meridian-up.sh` 每次仍先 `nft -c`，不接受就在转发、路由和服务之前停止，下发按失败补偿。

### 与 iptables-legacy 共存

面板**不切换** iptables 后端、不改 alternatives、不装 iptables 包、不动已有的 legacy 规则；只在缺 `nft` 时装 nftables 包（它不改 alternatives，也不启用 nftables.service）。在 5.15 内核上，legacy 的 x_tables 表和 Meridian 的 nf_tables 表都注册在同一组 netfilter 钩子上：一个包在每个钩子上按优先级从小到大经过两边的链（legacy 的 mangle −150、nat 目的 −100、filter 0、nat 源 100，nft 的 `mangle` / `dstnat` / `filter` / `srcnat` 是同样的数值，同值时谁先谁后不保证）。任何一边的 `drop` 都是最终的，一边的 `accept` 只结束那一条链，救不回另一边丢掉的包；一条连接的 NAT 在第一个包上由先处理它的 nat 链决定。所以：legacy filter 表 FORWARD 的 DROP 策略（Docker 设的）照样会丢掉隧道转发——预检按 `iptables -S` 报 `forward_policy_drop`；有 Docker 的 DOCKER-USER 链时，面板用 legacy 的 `iptables` 命令（不切换后端）在里面加放行规则，见下面「与已有业务共存」。**检查的**：legacy filter 表 INPUT / FORWARD 的默认策略、DOCKER-USER 是否存在、FORWARD 跳转的先后。**不检查的**：legacy 链里的单条规则（只丢某个端口或接口的 DROP/REJECT）、legacy nat 表里可能改写隧道流量的规则、legacy mangle 表打的 MARK 是否与 Meridian 的标记冲突。

### 与已有业务共存

这一节的机制（S1）只在仓库的自动化测试里跑过（本机沙箱里用有状态的假 `iptables` / `ip6tables` / `sysctl` / `systemctl` 真跑下发、补偿、撤回和 meridian-fwcompat.sh；Linux 上可选的网络命名空间测试 `TestNetnsFWCompatDockerUser` 用真实 iptables，但**还没有执行过**），**没有在任何真实主机上执行过**。

#### Docker 的 FORWARD DROP 与 DOCKER-USER

Docker 自己打开转发时把 iptables（开了 ip6tables 时也包括 ip6tables）filter 表 FORWARD 的策略设为 DROP。远端节点的包里有 `/usr/local/sbin/meridian-fwcompat.sh`：

- 它只在 `DOCKER-USER` 里加 `ACCEPT` 规则——Docker 留给管理员、FORWARD 最先跳到、Docker 重启时**不清空**的链——每条带注释 `meridian-fw-<规则集 SHA-256 的前 8 位>`。规则只匹配 Meridian 自己的接口：出口上是「隧道进 → WAN 出」和「WAN 进 → 隧道出且 `-m conntrack --ctstate RELATED,ESTABLISHED`」；枢纽和中转是上游隧道 ↔ 下游隧道（和 Mesh 的 `mmesh`），两个方向。WAN 名用拓扑里的 `wan_interface`（缺省 `eth0`，和出口 nft 的 NAT 一致）。规则插在链顶（`-I DOCKER-USER 1`），在 Docker 旧版本加的 `-j RETURN` 和你自己的规则之前；只对 Meridian 自己的接口生效。
- **每个地址族按当时的策略决定**：FORWARD 是 `DROP` 才加；是 `ACCEPT` 就不加，并删掉这一族里之前加过的 Meridian 规则（真实主机上 IPv6 是 ACCEPT、IPv4 是 DROP，所以只加 IPv4）；读不到策略时什么都不改并失败；是 DROP 却没有 DOCKER-USER 时什么都不改，打印 `meridian-fwcompat-unsupported`，让 `meridian-up.sh` 在打开转发和建隧道之前失败（`systemctl is-failed meridian-node.service` 可见）。
- 用主机自己的 `iptables` / `ip6tables` 命令，不管后端：iptables-nft（Debian 12/13，规则在 nft 表 `ip filter` / `ip6 filter` 里）和 legacy（Ubuntu 20.04，x_tables）都是 Docker 自己用的那个命令。不改 alternatives、不切后端。
- 不碰 Docker 的链和规则，不改任何策略，不 `-F` / `-X` / `-N`，只删**注释形如 `meridian-fw-` + 8 位小写十六进制**的规则（删的时候把 `iptables -S` 打印的那一行的 `-A` 换成 `-D` 重放）。注释看起来像但形状不对的规则不是 Meridian 的。
- 幂等：每条先 `-C` 再 `-I`；新规则集（拓扑变了，注释不同）加完之后删掉旧注释的规则。两个触发者（开机单元和 Docker 单元）可能同时运行，用 `/run/meridian-fwcompat.lock` 的 `flock` 串行。
- **谁运行它**：`meridian-up.sh`（下发、更新、开机）在加载 nft 和 sysctl 之后、打开转发和建隧道之前；以及受管单元 `meridian-fwcompat.service`（`BindsTo=docker.service`、`After=docker.service`、`WantedBy=docker.service`、`Type=oneshot`）：Docker 每次启动（重启、崩溃后被 systemd 拉起、停止再启动、开机）都会把它拉起来，在 Docker 就绪（DOCKER-USER 和 FORWARD 跳转已经建好）之后再跑一次 `apply`。规则不持久：重启主机后由这两条路径在 Docker 之后重新加上。
- **预检**：只在上面「它检查什么」里 `forward_policy_drop` 为警告的条件下放行，规则逐条进「拟执行的变更」（种类 `firewall`），面板在预检结果里单独列出；ufw 或 firewalld 在运行、DOCKER-USER 不存在、FORWARD 在跳到 DOCKER-USER 之前就有 DROP/REJECT、别的 nft 表（例如 `inet filter`）有 policy drop 的转发链、网关：继续阻断并写明原因。
- **记录与移除**：清单里有 `fw ipv4 DOCKER-USER`、`fw ipv6 DOCKER-USER`、`unit meridian-fwcompat.service` 和脚本文件；撤回先停用并停止 `meridian-fwcompat.service`（之后 Docker 重启不会再加回来），再按注释删除两个族里的 Meridian 规则，最后复核一条都不剩；下发失败的补偿删除这次运行新加的规则（与下发前记录的 `pre-fw4` / `pre-fw6` 对比），更新失败时恢复后的旧 `meridian-up.sh` 再加回旧规则。删不掉的规则记为没能移除。

- **ufw 算不算在管理防火墙**：按它实际做的事判断，只读：`/etc/ufw/ufw.conf` 里 `ENABLED=yes`，或 FORWARD 跳到 `ufw-*` 链，才算启用（阻断共存，另有 `firewall_manager` 警告）；`ENABLED=no` 且 FORWARD 里没有 ufw 的链时不算——Ubuntu 上 ufw 关闭时 `ufw.service` 也是 active (exited)——只给信息 `firewall_manager_inactive`。旧报告没有 `ufw-conf` 行时仍按单元状态（保守）。网关的 `meridian-host` 直接读同一个文件。firewalld 不需要这样处理：`firewalld.service` 就是守护进程本身，active 即在运行并管理规则（等同 `firewall-cmd --state` 为 running）。
- 软件包版本按 Debian 版本号的形状解析（字母数字和 `. + ~ : -`，以数字开头），`1.0.20200513-1~20.04.2`、`1:2.3-4+b1` 这样的候选版本不再被当成「没有候选」；形状不对的值记为读不懂，不据此判定 `package_unavailable`。

限制：只看 FORWARD 的默认策略和跳转先后，不逐条判断 DOCKER-USER 或 FORWARD 里你自己的 DROP 规则会不会先命中别的流量；Docker 29 的 nftables 后端不用 DOCKER-USER（那种主机 iptables 的 FORWARD 不再是 Docker 设的 DROP，预检按实际报告判断）；`netfilter-persistent save` 会把这些规则存下来，撤回后要再保存一次；同一主机上 iptables-nft 和 legacy 两套表并存（两个后端都有规则）时，脚本只用默认的 `iptables` 命令。

#### 远端节点的开机恢复

远端节点的包里有受管单元 `meridian-node.service`（`Type=oneshot`、`RemainAfterExit=yes`、`Wants=network-online.target`、`After=network-online.target nftables.service docker.service`、`WantedBy=multi-user.target`、`ExecStart=/usr/local/sbin/meridian-up.sh`、`TimeoutStartSec=300`），由下发脚本在 `meridian-up.sh` 跑完之后 `systemctl enable`（不启动：`meridian-up.sh` 刚跑过；也从不在 `meridian-up.sh` 里启动它自己，那会在开机时等待自己）。所以装完之后它是 enabled、inactive，重启后是 active（exited）或 failed。

顺序保证：

- 在网络就绪之后；在 nftables.service 之后（开机时它加载 `/etc/nftables.conf`，可能清空整个规则集——发生在 Meridian 加载之前，而不是之后）；Docker 启用时在 docker.service 之后（DOCKER-USER 已经存在）。`After=` 只排顺序，主机上没有 Docker 或 nftables.service 时不影响。
- `meridian-up.sh` 内部：先 `nft -c` 再 `nft -f` 原子加载 Meridian 的表 → 应用受管 sysctl → meridian-fwcompat.sh → 打开转发 → 建 WireGuard 接口 → Mesh sidecar 封口 → 策略路由 → 服务（WSS、failover、解锁定时器）→ 出口解析器重启（它只绑隧道地址，接口建好之后才能绑上）。任何一步失败，单元失败，后面的不做。
- 中转 / 枢纽上**没有「转发未过滤」的窗口**这一点的含义：远端节点上 Meridian 本来就不对过境流量做过滤（它的 nft 表只有 WSS 端口的 input 丢弃、出口的 NAT 和 `egress_v6` 关闭时的 IPv6 丢弃）。保证的是：隧道接口只在 Meridian 的 nft 表、sysctl 和 DOCKER-USER 规则就位之后才出现，路由只在接口之后安装，所以任何包都不可能在 Meridian 的表加载之前从隧道进来；出口上 NAT 和 IPv6 丢弃先于接口生效，不会有未转换源地址的包从 WAN 出去。Docker 开机时自己打开 `ip_forward` 不改变这一点（那时还没有 Meridian 的接口）。网关仍是 `meridian-guard.service` + `meridian.service`，顺序没变，只各加了一条 `After=nftables.service`。

#### 内核参数的范围

- 以前路由脚本对 `/proc/sys/net/ipv4/conf/*` 里**每个接口**（含 Docker、WARP 的）写 `rp_filter=2`、关闭重定向。现在 `harden_sysctl` 只对一份写死的接口表操作：这个节点的受管 WireGuard 接口、拓扑里给它的网卡（网关的局域网口、远端节点的 `wan_interface` / `lan_interface`）、网关的 `mra`、有 Mesh 时的 `mmesh`。别的接口不碰。
- 远端节点的 `99-meridian.conf` 只写拓扑网卡的四个键和 `net.ipv4.conf.all.send_redirects=0`：内核对 send_redirects 取 all 与接口的「或」，没有它就没有接口能不发重定向（它只影响自身值为 0 的接口）。`all` / `default` 的 rp_filter、accept_redirects **不再改**：rp_filter 取 max(all, 接口)，受管接口设为 2 后不论 all 是多少都是宽松模式（2 是最大值）；IPv4 accept_redirects 在转发时取「与」，接口值 0 就够。网关保持原来的 all / default（专用主机，验收脚本按它检查）。
- 全局开关 `net.ipv4.ip_forward`、`net.ipv6.conf.all.forwarding` 只在 `forwarding.conf` 里，由 `meridian-up.sh` 在防火墙之后打开；预检把它们和每个全局键（当前值）逐项列出。
- 补偿：下发前只记录这次可能写的键（`M_SYSCTL`：两个文件里的键和受管接口的键）的值，失败时只恢复这些——不再读写别的接口。撤回不改运行中的值（Docker 等也依赖转发；删掉的隧道接口的键随接口消失；拓扑网卡的键和 all.send_redirects 保持到重启），`99-meridian.conf` 被删除，下次开机不再设置。
- 升级：`99-meridian.conf` 每次安装整份重写，旧版本写的 all/default 行从下次开机起不再生效；**旧版本已经写到别的接口上的运行值保留到重启**（Meridian 不知道原来的值，不去改）。
- 没有重新引入两个在真实网关上学到的问题：没有给没有 IPv4 地址的接口设 `rp_filter=2`（受管接口都有 IPv4 地址），也没有 `iif <局域网口> unreachable` 规则。

#### IPv6 转发与路由通告（RA）

- **哪些节点打开 IPv6 转发**：网关、枢纽、中转（ULA 中转和局域网前缀），以及有 IPv6 出口（`egress_v6`）或做双栈中继的出口。别的出口（例如只有 IPv4 出口的）`forwarding.conf` 里没有 `net.ipv6.conf.all.forwarding=1`，主机的 IPv6 转发开关保持原样——它们收到的 IPv6 只有地区组解析（DNAT 到本机）或被丢弃，不需要转发。以前所有节点都打开，这是改动。
- **问题**：`net.ipv6.conf.all.forwarding=1` 之后，内核不再处理 `accept_ra=1` 的接口上的路由通告，靠通告学来的默认路由到期后主机静默失去 IPv6（真实的本地宽带虚机和云主机就是这样拿到 IPv6 默认路由的）。
- **判定（只读，进预检报告）**：main 表里带 `proto ra` 的 IPv6 路由所在的接口（`ra6 <接口> <accept_ra> <default|prefix>`）。
- **做法**：`meridian-up.sh` 在 DOCKER-USER 规则之后、`forwarding.conf` 之前，对这些接口以及以前记录过的接口（`/var/lib/meridian/node/ra-accept`，开机时通告晚到也照样处理）：`accept_ra` 是 1 就 `sysctl -w net/ipv6/conf/<接口>/accept_ra=2`（斜杠写法，接口名带点也行），写失败就不打开转发；是 2 不动；有 RA 路由但 `accept_ra` 是 0（systemd-networkd、NetworkManager 等用户态程序在处理通告，打开转发后是否还接受无法确认）就停下，不打开转发（失败关闭：主机保住 IPv6）。持久性来自开机单元：远端节点上 IPv6 转发**只**由 `meridian-up.sh` 打开（`99-meridian.conf` 不打开转发），所以每次开机都是先设 `accept_ra=2` 再开转发；没有写进 `99-meridian.conf`，因为接口集合是这台主机的事实（不是编译结果），而记录文件已经覆盖了「通告晚到」。
- **预检**：`accept_ra` 为 1 的接口在「拟执行的变更」里列为 `net.ipv6.conf.<接口>.accept_ra=2`，排在 IPv6 转发之前；`ipv6_ra_kept`（信息）说明；`accept_ra` 为 0 或读不到时 `ipv6_ra_unmanaged` **阻断**，处理办法：关掉这个节点的 IPv6 出口、让网卡的 IPv6 不依赖通告，或把通告交回内核处理。不转发 IPv6 的节点只说明不会改。
- **补偿 / 撤回**：下发前记录这些接口的 `accept_ra`，第一次下发失败时恢复并删掉记录文件；撤回删掉记录文件，但**不改** `accept_ra`（转发仍开着，改回 1 会让 IPv6 断掉），重启后两者都回到主机自己的设置。
- **网关**：局域网口从 ROS 拿 RA，`99-meridian.conf` 一直写着 `net.ipv6.conf.<局域网口>.accept_ra=2`，`meridian-up.sh` 在打开转发之前应用（开机时 systemd-sysctl 也设好，转发那时是 0），所以网关不受影响，没有改它。

#### WAN 接口

- 远端节点的 WAN 接口是拓扑的 `wan_interface`，没填时是 `eth0`；出口 NAT、没有 IPv6 出口时的 IPv6 丢弃、DOCKER-USER 规则、内核参数都用这个名字（以前远端节点的内核参数会回落到网关的 `lan_interface`，现在一律用这个名字）。`meridian-up.sh` 带一行 `# meridian-wan: <接口> <set|default> need=<4,6|any>`。
- **预检**：接口不存在时 `wan_interface_missing`、没有带上节点需要的默认路由（出口按 IPv4 / IPv6 出口，枢纽和中转要任意一种）时 `wan_no_default_route`，都**阻断**，写出主机的默认路由实际在哪块网卡上，并带 `fix`（节点的 `wan_interface`），面板显示「去拓扑修改」。IPv4 和 IPv6 默认路由在两块网卡上而节点两种都要出时也阻断（出口只用一块 WAN 网卡）。通过时 `wan_interface`（信息）。
- **没填时**：选择「阻断并让你填」，不把报告里的网卡收进计划。理由：节点的包在预检之前编译、预检结果绑定包的摘要；把主机事实收进包会让摘要依赖预检，而在拓扑里填上一次之后，NAT、规则、单元和预检看到的都是同一个名字。没填且主机正是 `eth0` 时通过，并建议填上。
- **下发脚本复查**：动手之前再查一次接口存在、默认路由在它上面（`MERIDIAN_REFUSED wan_interface_missing` / `wan_no_default_route`）。
- **IX 枢纽有两个地址**：WAN 检查管的是香港一侧（到出口经它出去，所以默认路由要在它上面）。另外 `meridian-up.sh` 带一行 `# meridian-ix-hub: ingress=<国内入口> iface=<接口|-> egress=<香港出口|->`，预检据此核对：拓扑写了 `ingress_interface` 而主机上没有这块网卡、或入口地址在别的网卡上时**阻断**（`ix_ingress_interface`，带 `fix`）；入口地址或出口地址不在任何网卡上时**警告**（`ix_ingress_not_local` / `ix_egress_not_local`：前面有 1:1 NAT 或转发时照样能用，WireGuard 监听所有地址，但面板看不到）；都在时 `ix_hub_addresses`（信息）。

#### nftables.service 的整表清空

Debian / Ubuntu 的 `nftables.service` 停止时执行 `nft flush ruleset`，原装 `/etc/nftables.conf` 又以 `flush ruleset` 开头：reload / restart / stop 都会清掉 Meridian 的表（网关上包括兜底表 `inet meridian_guard`，而转发还开着）。在主机自己的配置之外没有办法让这个窗口失败关闭（传播的 reload 在对方之后才运行，restart 中间那一段无法挡住），所以：

- 预检（远端脚本读 `systemctl show -p ExecStop nftables.service` 和配置里有没有 `flush ruleset`；网关的 `meridian-host` 同样读）在 nftables.service **已启用或正在运行**且会清空时**阻断**，在改动任何东西之前；下发脚本动手前再查一次（`MERIDIAN_REFUSED nftables_flush_on_reload`），装完软件包后（nftables 包万一启用了服务）又查一次，失败就补偿。
- 处理办法（预检里原样给出）：不需要它就 `systemctl disable nftables.service` 然后在合适的时候重启主机——**不要** `systemctl stop nftables`，它会清空整个规则集，连 Docker 的规则一起；需要它就把 `flush ruleset` 换成只删除它自己定义的表，并用 drop-in 写一行空的 `ExecStop=`。面板不改主机自己的配置。
- 没启用也没运行（发行版默认）不报告；那时有人手动 `systemctl start` / `reload` 仍会清掉 Meridian 的表，恢复办法是重新执行 `meridian-up.sh` 或重新下发——这是已知限制。开机时 `meridian-node.service`、`meridian-guard.service`、`meridian.service` 都排在 nftables.service 之后。

#### 主机级 WARP 客户端

预检认出它（`warp-svc` 进程或单元、`CloudflareWARP` 接口、`inet cloudflare-warp` 表、100.96.0.0/12 或 2606:4700:cf1::/48 地址），并列出：它的策略规则 `not fwmark 0x100cf lookup 65743`（优先级、在 main 之前）、表 65743 有没有默认路由、依赖线索（只读进程名和地址：有连接连到 127.0.2.2 / 127.0.2.3 或 40000 端口的进程、`/etc/resolv.conf` 指向 127.0.2.x）。含义：Meridian 自己的策略规则都排在它之前，查的 Meridian 路由表不受影响；出口上经 main 表出去的流量会先查表 65743——它有默认路由（全局模式）时隧道进来的流量会从 WARP 出去（`rule_precedes` 警告），没有时只有它自己的网段进 WARP。Meridian 的标记、路由表号、nft 表或规则优先级与它相同时阻断；出口解析器只绑受管隧道地址，不与它在 127.0.2.x 和叠加地址上的 53 冲突。

Mesh sidecar：节点包带 sidecar 文件时警告 `warp_sidecar_conflict`；面板的 Mesh 部署预检在主机上有 WARP 客户端时拒绝（`MESH_CONFLICT host_warp`），因为两者的规则、路由表、标记和 53 端口能否共存没有确认。停用旧客户端是要单独确认的后续步骤，面板不会顺带停用它，也不清理 Cloudflare 账户里的旧设备。

#### nft 0.9.3

Ubuntu 20.04 的 nft 是 0.9.3。远端规则集（出口、中转、枢纽）用到的写法按 nftables 的发布说明复核过：`inet` 表里的 NAT（`masquerade`、`dnat ip6 to`、`snat ip6 to`，含 `hook input` 的 nat 链，需要内核 ≥ 5.2，这台是 5.15）、优先级名字（`mangle`、`dstnat`、`filter`、`srcnat`）、`ct mark`、`ct direction reply`、`type route hook output`、规则注释、匿名集合 `{ … }`、表的 `table` + `delete table` 原子替换，都在 0.9.3 之前就有。唯一拿不准的是传输层头表达式（`meta l4proto { tcp, udp } th dport 53`），它出现在出口的地区组解析 DNAT 和 Mesh 回程链里：已改写成同义的两条规则（`udp dport 53 …` 与 `tcp dport 53 …`），匹配的包完全相同；测试保证远端规则集里不再出现 `th dport` / `meta l4proto {`。网关只支持 Debian 12/13，保持原样。没有在 0.9.3 上实际执行过：`meridian-up.sh` 的 `nft -c` 仍是最后一道检查。

### 内存预算

远端节点的预算（`preflight.MemHeadroomKB` 等）：基础余量 48 MB（apt/dpkg、bash、wg-quick）+ 出口解析器 48 MB（固定版本的 SmartDNS，`cache-size 4096`，只绑隧道地址）+ wstunnel 32 MB；更新时已经在跑的受管进程不再计算。可用内存（MemAvailable）低于预算时：要本机解析器的节点**阻断**（`memory_budget`）——不跳过解析器、不改用国内或别的解析器、不在解析器起不来时声称节点可用（下发脚本最后检查 `meridian-smartdns.service` 必须在运行，否则失败补偿）；没有解析器的节点只警告。真实主机里最小的两台（共约 440 MB、约 940 MB，可用都约 200 MB）在预算之内；原来 `low_memory`（可用 < 256 MB 或总量 < 512 MB）的警告保留。预算数值是估计，没有在这些主机上测过实际占用。

## WSS 承载：随机路径与自签证书

每条 WSS 链路（`wg_over_wss`、`udp_wss_failover` 的 WSS 腿、`ix_replacement_wss`，包括网关到备用枢纽的那条）的升级路径前缀、每个 WSS 监听（一个节点的 `wss_listen_port` 上的一个 wstunnel 服务端）的证书都由面板生成，用户不填写任何东西。**不使用 ACME**，不需要域名，不用 Cloudflare 的 DNS 接口。这一节的行为只在仓库的自动化测试里跑过（含下面说的真实 wstunnel 二进制在本机容器里的回环测试），**没有在真实主机、也没有在真实网络路径上执行过**，数据面标为未验证。

### 固定版本的 wstunnel 支持什么

依据 wstunnel 11.1.0 的源码（`wstunnel/src/config.rs`、`protocols/tls/server.rs`、`tunnel/ca_reloader.rs`、`restrictions/`）和它锁定的 rustls-native-certs 0.8.5：

- 客户端**没有**证书指纹或公钥固定选项，也没有指定信任根文件的参数。`--tls-verify-certificate` 打开校验（默认关闭，关闭时用一个什么都接受的校验器）；信任根来自 `rustls_native_certs::load_native_certs()`，它在设置了 `SSL_CERT_FILE` 时**只**读这个文件（再加 `SSL_CERT_DIR` 里的目录，所以单元里把它设为空）。
- 校验的名字是 `--tls-sni-override` 给的名字（同时作为 SNI 发送）；不给时是连接地址。
- 路径前缀 `--http-upgrade-path-prefix` 也能从环境变量 `WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX` 读（clap 的 `env`），所以不必出现在命令行（`ps` 看得到命令行）。
- 服务端的 `--restrict-config` 是一份 YAML：每条规则用正则匹配路径前缀、并列出允许的目的地（协议、端口、网段）；文件变化时自动重载。证书和私钥文件变化时也自动重载。一个服务端进程只出示**一张**证书。

所以采用的做法是题目给的第二种：**该监听的自签证书作为唯一信任根 + 确定的合成名称校验**。真实二进制的测试证明：换成另一张自签证书（握手被客户端以 `UnknownCA` 拒绝）、换一个名字（`BadCertificate`）、换一个路径（服务端 `Rejecting connection with not allowed destination`，回 400）都建立不了隧道；同一张错误证书在去掉 `--tls-verify-certificate` 时能连上——说明拒绝确实来自证书校验。

### 渲染出来的东西

服务端（监听节点，`wstunnel-meridian.service`，参数里没有秘密）：

```
/usr/local/sbin/meridian-wstunnel server --restrict-config /etc/meridian/wss/server.yaml \
  --tls-certificate /etc/meridian/wss/server.crt --tls-private-key /etc/meridian/wss/server.key wss://0.0.0.0:<wss_listen_port>
```

`server.yaml`（0600）每条链路一条规则：`!PathPrefix "^(?:<该链路的前缀>)$"`，只允许 `Udp` 到 `127.0.0.1/32` 上**这条链路**的 WireGuard 端口——一条链路的前缀到不了别的链路的端口（以前所有链路共用一个前缀和一组 `--restrict-to`）。`server.crt`（0644）是证书，`server.key`（0600）是私钥。目录 `/etc/meridian/wss` 是 0700。

客户端（拨号节点，每条链路一个 `wstunnel-client-<链路>.service`）：

```
Environment=SSL_CERT_FILE=/etc/meridian/wss/client-<链路>.trust.pem
Environment=SSL_CERT_DIR=
EnvironmentFile=/etc/meridian/wss/client-<链路>.env
ExecStart=/usr/local/sbin/meridian-wstunnel client -L 'udp://127.0.0.1:<本地端口>:127.0.0.1:<WG 端口>?timeout_sec=0' \
  --tls-verify-certificate --tls-sni-override ${MERIDIAN_WSS_SNI} wss://<监听地址>:<WSS 端口>
```

`client-<链路>.env`（0600）里是 `WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=<前缀>` 和 `MERIDIAN_WSS_SNI=<合成名称>`；`client-<链路>.trust.pem`（0644）只有该监听的证书（轮换中是新旧两张），开头的注释写着指纹和到期时间。连接地址（`wss://` 后面的 IP）与校验名称分开。

### 材料的参数

- **路径前缀**：24 字节随机数的小写十六进制（48 个字符，192 位），每条链路一个，互不相同；只出现在服务端的 `server.yaml` 和该链路客户端的 `.env` 里。
- **证书**：ECDSA P-256、SHA-256 签名、128 位随机序列号；`CN` 和唯一的 `subjectAltName dNSName` 都是合成名称；`keyUsage digitalSignature`、`extendedKeyUsage serverAuth`、不是 CA（rustls/webpki 拒绝把 CA 证书当终端证书）；有效期从生成时刻往前 48 小时（容忍时钟偏差）到往后 365 天。面板显示 DER 的 SHA-256 指纹。
- **合成名称**：每个监听一个 `w<16 位随机十六进制>.invalid`（RFC 6761 保留的 `.invalid`，永远不会解析、不会是谁的真实域名）。

### 秘密放在哪里、怎么注入

路径前缀和私钥是凭据存储（`internal/credentials`，0700 目录、0600 文件、索引里只有元数据）里的秘密，id 前缀 `wssp-` / `wssk-`。公开状态（证书、指纹、有效期、合成名称、各端阶段、最近结果）在同一个索引的 `wss` 段里，不在拓扑里，不随数据目录快照回滚。

编译器只认拓扑：它在 WSS 文件里写记号 `__MERIDIAN_WSS_<种类>_<id>__`。面板编译时（`compileTopo` → `compile.ResolveWSS`）按 WSS 状态替换：证书、合成名称直接写进去，秘密变成 `__MERIDIAN_SECRET_<id>__` 占位符。所以编译预览、差异、快照、安装清单（网关存的是带占位符的副本）、导出和 API 都不含秘密。只有两处换成真值：网关安装事务写宿主文件时（`apply.InjectSecrets`，与远程接入密钥同一个边界），和远端下发脚本在内存里组装、经已固定指纹的 SSH 会话发送时（`provision.InjectPrivateWSS`，**只**接受 WSS 秘密，远程接入的密钥永远不会发到远端）。注入按种类限制位置：路径只能进 `/etc/meridian/wss/` 下的文件，私钥只能进 `.key`，WireGuard 配置里只能是 WireGuard 密钥。还带着 `__MERIDIAN_WSS_` 记号（没有材料、凭据存储不可用）的包被每条安装路径在写任何文件之前拒绝：WSS 承载不会在没有校验的情况下运行。

远端节点的清单（`/var/lib/meridian/node/manifest`）照旧记每个文件的 SHA-256，撤回时据此只删没被改过的文件。秘密文件的哈希不泄露秘密：内容里的秘密是 192 位随机数或 EC 私钥，SHA-256 不可逆；清单本身是 0600。预检的足迹（`secret_files`）列出这些 0600 文件。

### 主动探测者看得到什么、看不到什么

- 看得到：这个端口上有 TLS（TLS 1.3，ALPN `h2`/`http/1.1`），证书是自签的，名字是一个 `.invalid` 的合成名称（任何人连上来都能拿到证书）；客户端发出的 SNI 是同一个合成名称，在 ClientHello 里明文可见（没有用 ECH）。这和「正常网站」不一样，**不做伪装**。
- 别的路径、不带升级的请求：wstunnel 11.1.0 回 `400`，正文 `Invalid request`，没有 `Server` 头（真实二进制测试记录了这一点）。这不暴露「这是 wstunnel」的字样，但也不是一个像样的网站——一个固定的 400 本身就可能被指纹识别。
- 看不到：路径前缀（只在 TLS 里传输），因此拿不到隧道；即使拿到证书也冒充不了服务端（没有私钥），客户端也不会连到别的服务端（只信任这一张证书）。WireGuard 本身的认证照旧在里面。

### 轮换：两端都要换，任何时候两端都能互通

手动「重新生成路径」（一条链路）、「重新生成证书」（一个监听），以及证书到期前 30 天自动开始的轮换（面板每小时检查一次；它只**生成**新证书并告警，不会自己去改主机），都走同一套分阶段的状态（`model.WSSListener`）。当前路径 P、证书 C，新的 P′、C′：

| 阶段 | 服务端接受 | 服务端出示 | 客户端发送 | 客户端信任 |
| --- | --- | --- | --- | --- |
| 0 | P | C | P | C |
| 1 | P、P′ | C | P | C、C′ |
| 2 | P、P′ | C′ | P′ | C、C′ |
| 3 | P′ | C′ | P′ | C′ |

相邻两个阶段的两端总能互通。面板记录每一端最后一次**成功**安装的阶段；下一次安装渲染的目标阶段是「对端可能处于的最低阶段 + 1」，并且不比对端可能处于的最高阶段低超过 1。因此：

- 两端交替各安装大约两次（面板「下一步」按顺序列出：哪个节点、服务端还是客户端、从哪个阶段到哪个阶段），每一端都到阶段 3 后新材料自动转正、阶段归零，旧路径和旧私钥在没有任何网关快照还引用它们之后从凭据存储删除。
- **只更新了一端**（另一端还没装、或装失败）时两端处于相邻阶段，隧道照常工作；面板显示「两端暂不一致」和下一步。
- 安装失败并被补偿：那一端回到旧文件（远端脚本会把它重启过的 wstunnel 在恢复的文件上再重启一次），记录的阶段不变，面板显示失败原因；旧凭据继续有效。
- 结果不明（补偿不完整、连接中断）或网关运行时回滚：那一端的阶段记为「不确定」（可能是旧阶段也可能是目标阶段，回滚则是 0 到原阶段之间），另一端的目标按最坏情况计算，面板要求先重新下发不确定的那一端。
- 两端都没装过时重新生成直接替换，不经过阶段。轮换开始后、还没有任何一端装上新材料时可以取消。

**中断**：每次在一端安装新阶段，这一端的 wstunnel 会重启（网关的安装本来就重启所有单元；远端脚本只重启 WSS 文件内容真的变了的那个单元，`MERIDIAN_WSS_RESTARTED`），这条 WSS 承载断几秒，WireGuard 随后重新握手。这是固定版本做得到的最小中断：服务端换证书时 wstunnel 会自动重载，但客户端的信任根只在启动时读取。

**到期**：客户端校验证书有效期，证书过期后 WSS 承载建立不了。为此：到期前 30 天自动开始轮换并告警，14 天内新证书仍未装好时变成红色告警，过期后显示「已过期，WSS 承载已无法建立」。面板不会在无人操作时自己去改远端主机。

### 旧拓扑的迁移

以前的拓扑在节点上有固定的 `wss_path_prefix`（没填时实际用的是 `example-wss-path-prefix`）和操作员自备证书的路径 `tls_cert_path` / `tls_key_path`，客户端的信任根是系统 CA（自签证书时其实连不上，用公认证书时只能证明是「某个有公认证书的服务器」）。「操作员自备证书文件」**不保留**：面板无法读取远端的证书文件来固定它，保留它就意味着要用户另外上传一份证书来信任，这和面板自己生成没有区别。

规则（`migrateWSS`，面板启动时和每次保存拓扑时执行，可重复）：

1. 为每个 WSS 监听生成证书和合成名称，为每条 WSS 链路生成随机路径；然后从拓扑里删掉 `wss_path_prefix`、`tls_cert_path`、`tls_key_path`（API 和导出里不再出现）。
2. **只在第一次**（凭据存储里还没有 WSS 状态时）：一个监听或它的某个拨号端被这个面板装过（网关有安装清单，远端有成功的下发记录）就标为「迁移中」。迁移中服务端先接受「旧固定前缀 + 新前缀」、出示新证书；旧客户端不校验证书、发的是旧前缀，所以继续能连。每个装过的客户端重新下发后（新前缀、只信任新证书），服务端再下发一次去掉旧前缀，迁移结束。旧前缀不是纯字母数字/`_`/`-` 时不带过去（那条链路在两端重新下发之间会断）。谁都没装过就直接用新材料。
3. 迁移只能完成不能取消；之后再导入带这些字段的旧拓扑，只会删掉字段、生成材料，不会再进入迁移状态（两端重新下发之前那条 WSS 承载不通）。

面板在「部署」页的「WSS 承载」里显示迁移状态、旧前缀是否仍被接受和下一步。

### 面板与 API

- `GET /api/wss`：每个监听的合成名称、证书指纹、生成和到期时间（剩余天数）、新证书（轮换中）、每条链路的路径「已设置」和生成时间（**不返回路径和私钥，也不返回它们在凭据存储里的 id**）、各端已安装和下次下发的阶段、下一步、最近结果、告警。
- `POST /api/wss/links/{id}/regenerate-path`、`POST /api/wss/listeners/{id}/regenerate-cert`：开始轮换（已有一次进行中时 409 `wss_rotation_in_progress`）。`POST /api/wss/listeners/{id}/cancel`：取消还没被任何一端装上的轮换。
- 让轮换前进的只有已有的安装：网关「安装到本机」（`POST /api/apply`，安装事务）和远端「下发」（`POST /api/provision`，带预检和补偿的下发脚本）。没有新的任意命令接口。成功、失败、补偿、结果不明都会记进 WSS 状态；撤回节点后它的各端记为未安装。
- 拓扑页不再有路径和证书路径的输入框：节点的「WSS 入口（高级）」只剩监听端口和说明，WSS 链路显示路径是否已设置和监听的指纹。

网关上的 DoT 证书（SmartDNS 的 `/etc/meridian/dns/`）与这里无关，没有改动。

## 撤回与失败后的恢复

「从拓扑删除节点」和「撤回装在它服务器上的东西」是两件事，面板分开处理。这一节描述的行为只在仓库的自动化测试里跑过（本机沙箱里真跑撤回脚本、进程内 SSH 服务器、模拟宿主上的真实 `meridian-host` 代理），**还没有在任何真实主机上执行过**。

### 部署记录与绑定

- 每个远端节点的部署记录（面板数据库 `provision_state`）保存下发时绑定的**完整身份**：服务器 ID、地址、端口、用户、固定的主机指纹、凭据 ID、面板部署 ID，以及最近一次下发和撤回的结果。节点从拓扑删除、或在拓扑里改指到另一台服务器，记录都不变；撤回**只去记录里的主机**，不去节点现在指向的服务器。
- 只要服务器上可能还有东西（装成功过且没撤回、补偿留有残留、结果不明、撤回进行中 / 部分完成 / 结果不明），记录就固定这台服务器和这份凭据：和 Mesh 部署一样，经 `credentials.Store` 的部署固定（`node_deployment` 引用），服务器不能删除、不能改地址 / 端口 / 用户 / 认证方式 / 凭据，凭据不能删除（可以原地轮换）。这样撤回时一定还连得上**那台**主机。
- 节点仍装在旧服务器上时，在新服务器上预检或下发被拒绝（409 `deployed_elsewhere`）：先撤回旧的，不会静默留下一份安装。
- 撤回前再核对一次：服务器当前的地址 / 端口 / 用户必须等于记录（否则 409 `target_changed`），它现在信任的指纹必须等于记录（忘记指纹、换成另一把都 409 `host_key_not_pinned_by_deployment`），连接器握手时还要看到这把指纹。服务器上的清单里的 `node`、`deployment`、`server` 三项都要等于本面板的值，否则脚本拒绝（`manifest_other`、`manifest_other_server`）。
- 服务器确实已经不存在（VPS 已删）时可以「放弃」：输入节点 ID 确认后记录标为 `abandoned`，解除固定；面板明确说明**没有核实**服务器上是否还留有安装，从不把它显示为已撤回。

### 远端节点：一份固定脚本，三种模式

`provision.WithdrawScript` 是一份固定、可审阅的 bash 脚本。只有经 `CheckWithdrawOptions` 校验过的值以单引号赋值放在开头（节点 ID、部署 ID、服务器 ID、运行 ID：`[A-Za-z0-9._-]{1,64}`；模式和动作：固定枚举；摘要：64 位十六进制）。要删什么**从主机自己读**，不从请求里来；没有任意命令接口。脚本经固定指纹的 SSH 以 `bash -s` 从标准输入执行。

每种模式都有两个动作：`plan` 只读，打印将要移除的内容（`MERIDIAN_PLAN …`，每项带 present / absent / changed）和它所依据状态的摘要（`MERIDIAN_PLAN_DIGEST`）；`run` 重新计算摘要，与操作员确认的不同就拒绝（`plan_changed`，什么都不改）。

- **清单模式（`manifest`，默认）**：按下发成功时写的 `/var/lib/meridian/node/manifest`。每个条目在脚本里再校验一次——接口 `m\d{2,3}w?|mmesh|mmesh-c`、单元 `meridian-*` / `wstunnel-meridian` / `wstunnel-client-*` 的 `.service|.timer`、nft 表 `inet meridian[_…]`、路由表 100–252、路径只在 Meridian 写的那几个目录下且不含 `..`；有一条不认识就整次拒绝（`bad_manifest_entry`）。顺序：停用并停止单元 → 清单记录了「SmartDNS 是 Meridian 装的」时停用 `smartdns.service`（软件包保留）→ 清单里有 Mesh sidecar 的 compose 文件时 `docker compose -f … down`（只这一个项目）→ 删除接口 → 删除指向清单路由表的规则并清空这些表 → 删除清单记录的 main 表黑洞路由（新下发的清单才有 `route` 行）→ 删除清单里的 nft 表 → 删除文件（**只在 SHA-256 仍等于清单时**；下发后被改过的文件保留并列为没能移除）→ 需要时 `daemon-reload`、删掉空的 `/etc/meridian` → 复核接口、nft 表、单元确实不在了。全部完成才删除清单，journal 记为 `withdrawn`；有任何没能移除的东西时清单保留、journal 记为 `withdraw_incomplete`（下一次下发和预检会拒绝，提示继续撤回），撤回可以重复执行，已经不在的东西跳过。再撤回一次时脚本回答 `MERIDIAN_WITHDRAW_ALREADY`。
- **journal 模式（恢复中断的下发）**：journal 为 `running`（会话被硬切断、进程被杀）或 `incomplete`（补偿没做完）时，按这次运行的工作目录（`run-<ID>/`：actions、备份、下发前的 pre-* 状态、`params`）跑**与下发失败时完全相同的补偿**（两边共用 `compensateLib`）：新建的文件和目录删除、被替换的文件恢复、这次新建的接口和 nft 表删除、新增的规则和路由删除、sysctl 恢复、更新时重跑恢复后的 `meridian-up.sh`；每一步可以重复执行。`params` 是下发开 journal 时最后写的：没有它就说明这次运行还没动过主机，恢复只关闭 journal。工作目录不见了、或有动作却没有 `params`，拒绝（`journal_unrecoverable`），只能登录服务器按 journal 手工处理。恢复完成后，之前完整装好的版本（如果有）照旧在，之后可以再按清单撤回。
- **旧版清理（`legacy`）**：给没有清单的旧版安装。**只看固定路径和名字**：`/etc/wireguard/mNN[w].conf`、`meridian-*` / `wstunnel-meridian*` / `wstunnel-client-*` 单元文件、`/usr/local/sbin/meridian-*`、`/etc/nftables.d/meridian*.nft`、`/etc/sysctl.d/99-meridian.conf`、`/etc/iproute2/rt_tables.d/meridian.conf`、`/etc/smartdns/smartdns.conf`——每个都必须是普通文件且前 12 行提到 Meridian——以及 `/etc/meridian/` 下的文件；接口只取这些 WireGuard 配置的，nft 表只取这些 nft 文件里声明的，路由表只取这个 rt_tables 文件列出的。不带标记的同名文件（例如别人的 `m15.conf`）不碰。旧版的 main 表黑洞路由没有任何记录，脚本**不猜**，只提示去查 `ip route show type blackhole`。确认的清单在执行前重新扫描，有变化就拒绝。界面上要输入节点 ID 并单独提示这是旧版清理。

撤回还会：按注释删除 DOCKER-USER 里的 Meridian 规则（清单的 `fw` 行；之前先停用 `meridian-fwcompat.service`，`meridian-node.service` 和别的单元一样停用），见上面「与已有业务共存」。

保留（**按设计**）：下发时装上的软件包（wireguard-tools、nftables，以及以前的版本装的 smartdns，卸载可能牵连别的软件）；面板下发的二进制不是软件包，按清单的 `file` 行删除；运行中的 sysctl 值（`ip_forward`、`all.forwarding`——Docker 等也依赖——、`all.send_redirects` 和拓扑网卡的键，到重启或你自己改之前保持；`99-meridian.conf` 已删除，下次开机不再设置）；SmartDNS 不是 Meridian 装的时它的服务（配置被删，继续用内存里的旧配置直到重启）；清单之外的一切——Docker 和容器、别的 WireGuard 接口、WARP、别的 nft 表、别的文件。每次结果都列出「已移除 / 保留 / 没能移除」。

### 状态与持久化

撤回运行前，记录先写成 `running`（面板在执行中崩溃时显示「撤回中断」，不会是「已撤回」）；然后按脚本标记更新为：`withdrawn` / `already_withdrawn`（已验证，解除固定）、`partial`（列出没能移除的，继续固定）、`refused`（带原因代码，主机没改）、`not_started`（连不上、目标变了，主机没改）、`unknown`（没有结论性标记：连接中断或超时，不当作完成，继续固定）、`recovered` / `recovery_incomplete`（journal 模式）、`abandoned`（放弃）。计划存为 `withdraw_plan/<节点>`，绑定身份、部署 ID 和摘要，10 分钟有效，用一次即作废。服务器端的状态在 `/var/lib/meridian/node/journal`（`kind withdraw`、`state withdrawing|withdrawn|withdraw_incomplete`），预检据此阻断或放行。

### 网关：经安装事务撤回到兜底表

`apply.Applier.Withdraw` 是一份普通的宿主事务（`/var/lib/meridian/host/journal.json`，`kind withdraw`）：从已安装清单收敛到一份只剩兜底表的「已撤回清单」（`origin: withdrawn`，文件只有 `etc/nftables.d/meridian-guard.nft`，nft 表只有 `inet meridian_guard`）。移除经 `meridian-host` 新增的固定动作 `withdraw`：先关 IPv4 / IPv6 转发 → `systemctl stop meridian.service`（它没有 ExecStop，只是取消开机重试、清掉 active 状态；单元保持启用，`meridian-up.sh` 删除后开机会被条件跳过）→ 按清单删除单元、接口、规则和路由表、`inet meridian`（与 rollback 一样只动账本里激活过的名字）→ 确认 `inet meridian_guard` 仍在，不在就重启固定的 `meridian-guard.service`（只从开机文件加载这一张表）再确认，确认不了就失败。这个动作拒绝任何点名兜底表或解析器的请求。之后删除清单里的文件（兜底文件除外），再调一次 `withdraw` 复核。任何一步失败都补偿回撤回前（从已安装副本重写文件并重新激活数据面）；补偿也失败时保留 journal，拒绝新的安装、回滚和撤回，面板「恢复」或重启时处理。为保证总能补偿，撤回前先确认已安装副本能用网关私钥和远程接入密钥还原，否则拒绝、什么都不改。

**兜底表的决定：撤回之后局域网保持 fail-closed。** 兜底表丢弃 Meridian 没有分类的局域网转发流量；撤回后不再有分类，它就丢弃全部局域网转发——仍把这台机器当网关的设备断网，而不是经 ROS 不受保护地直出。`meridian-guard.service` 开机照样加载它，所以重启（或 Docker 开机打开转发）也不会漏。转发保持关闭。移除兜底表是**单独的一步**（`POST /api/host/withdraw {release_guard:true}`），只在撤回完成后提供：经已有的 `rollback` 动作（先关转发再删表）删除 `inet meridian_guard` 和它的开机文件，之后安装清单为空；面板明确提示此后局域网不再由 Meridian 兜底。

撤回后：`GET /api/status` 的 `install.state` 是 `withdrawn`；运行态回滚被拒绝（409 `gateway_withdrawn`，恢复走重新安装）；重新「安装到网关」按第一次安装处理，要先做安装前预检。没有安装清单的旧版网关拒绝撤回（409 `legacy_install`）：先用安装接管它，再撤回。安装清单里没有兜底表的版本拒绝撤回（409 `guard_missing`）。保留：`meridian.service`、`meridian-guard.service`、`meridian-host.service`（install.sh 装的宿主部分）、面板容器、数据目录和配置快照、Docker、SmartDNS 软件包或容器（配置文件若在清单里会被删除）、其他 nft 表和 WireGuard 接口。

### 与 Mesh 的组合

Mesh 撤回仍按 Mesh 部署记录固定的主机、凭据、指纹和 Cloudflare 账户进行（没有改动、没有放宽）。节点撤回（清单模式和旧版清理）在 Mesh 部署记录还忙（运行中、已发布、补偿未完成）且固定了这个节点的主机时拒绝（409 `mesh_deployed`），记录读不了也拒绝：**先撤回 Mesh，再撤回节点**——sidecar 跑在节点的接口上，Cloudflare 上还有它的节点和路由。Mesh 撤回失败时记录保持「补偿未完成」，节点撤回继续被挡住，直到 Mesh 撤回重试成功。journal 模式只撤销那次中断的下发，不碰之前完整安装的 sidecar，所以不受这条限制。网关撤回同样检查 Mesh 是否固定了网关。

### 解锁结果

拓扑里已经没有的出口，它的探测结果不再当作当前结果：`GET /api/unlock/results` 默认不列出（`include_removed=1` 时列出并带 `exit_removed: true`、`is_active: false`），另给 `removed_exits`（每个出口的条数）；`POST /api/unlock/results/prune` 删除这些结果。`GET /api/unlock` 带 `removed_exits`，界面把历史和状态里这些出口标为「已删除的出口」。清理只动面板的结果矩阵；`unlock.Snapshot` 里的准入记录（`Latest`、`Applied`）和历史保留，所以 `unlock.Ingest` 的准入规则不变：同一个出口 ID 以后再出现时，旧的结果也不能从它下面插进来（`TestRemovedExitsMarkedAdmissionKept`）。

**出口身份**（`internal/api/exit_identity.go`）：每条结果带任务创建时冻结的出口身份摘要（版本化的 SHA-256：端点、对端公钥、出口地址族、关联服务器地址/端口、中继和外部出口的承载与 SOCKS 目标、网关上选中出口的 fwmark/过渡地址/解析器/仅 TCP；不含私钥、PSK、凭据和名称、坐标、标签）。拓扑存储每次写入后通知面板（`store.OnSave`），受管服务器修改后面板也重算一次；身份变化的出口代次加一。任务完成时身份与冻结时相同且代次未变才写入摘要并入库，否则结果不带摘要（`not_ingested:exit_changed`）。结果按任务创建顺序（`seq`）保存，旧任务晚完成不覆盖新结果。解锁页只认与当前摘要相同的结果，其余为「未测」、不推荐；采用在保存事务里（面板状态锁在前、拓扑存储锁在后）重读结果和身份并重算推荐，不一致返回 409，规则和地区组都不改。不新增有效期。

**服务归属**：采用和预览的 `service_rules` 只认主检查域名、规则集 / geosite / 关键字里服务自己的平台名和规则 ID；mihomo 策略组标签不算归属，只用于规则页筛选和 `POST /api/rules/retarget`。同一地区组上随首选出口一起移动的其他规则只计入预览的 `other_rules`。Viu（`auto-viu`）是独立的香港服务，MyTV SUPER 的结论不含 Viu。

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

## 经隧道管理的地址候选

真实使用中，一台从网关直连 SSH 不通的出口改用经隧道管理后恢复了，但地址是试出来的：它在隧道里的 IPv4 地址从网关到不了（出口一端的 AllowedIPs 不包含网关自己的隧道 IPv4 地址，应答没有路回来），只有它在主枢纽那条链路上的 IPv6 地址可达，而且这个地址依赖主链路——网关切到备用枢纽时就到不了。

**推导**（`compile.ManagementCandidates`）：候选是节点在它每条隧道上的地址（每条链路一个 IPv4、一个 ULA）。对网关的每一种承载状态——单枢纽：中继的 UDP 腿、WSS 腿、本地宽带直连枢纽的 WSS 备路；有备用枢纽：主链路的 UDP / WSS 腿、备用枢纽；多中继分担：每台被指定的中继、备用枢纽——用与渲染 WireGuard 配置和路由脚本同一份计划（`buildTunnels` 的隧道与地址、`allowedIPs`、各角色 `renderRoutes` 写入的主表路由、源地址规则、按入口接口的回程表；网关的 `10.66.0.0/16` 与 `fd66::/48` 按那种状态指向对应接口，`upstream_apply` / `apply_choice` / `share_designate` 就是这样改的）逐跳走一遍请求和应答：

| 检查（每一跳） | 不满足时 |
| --- | --- |
| 网关有经自己某条隧道的路由（最长前缀、度量；源地址取路由的 `src`，否则出接口上的地址——网关的探测主机路由 `/32 src 10.66.200.2` 也算） | 不可达：没有路由 / 落到黑洞 |
| 发送方在这条隧道上对对端的 AllowedIPs 包含目的地址 | 不可达：WireGuard 不发送 |
| 接收方在这条隧道上对发送方的 AllowedIPs 包含源地址 | 不可达：包被丢弃（例如出口只接受局域网、中转网段、枢纽自己的 /32 和 `fd66::/48`，不接受网关的隧道 IPv4） |
| IPv4 的反向路径检查（各隧道接口 `rp_filter=2`）：接收方有回到源地址的非黑洞路由 | 不可达：rp_filter 丢弃 |
| 中转的 IPv6 需要那台节点转发 IPv6 | 不可达 |
| 应答从目标（以被问到的地址为源）回到网关的源地址，同样逐跳检查；在有按入口打标的节点（备用枢纽拓扑的出口、多中继分担的中继和主枢纽）应答按请求进来的隧道回去 | 不可达（理由写明是回程） |
| 遇到不受管的对端、不是 Meridian 隧道的接口 | **无法判断**（unknown），从不算可用 |
| 走回已经经过的节点 | 不可达：路由成环（没有节点有比隧道总前缀更具体的路由） |

请求走不通时，面板仍从目标按同样的规则走一遍应答，把回程上的原因也写出来（例如「出口在链路上对枢纽的 AllowedIPs 不包含目的地址 10.66.x.1」）。

**结果**：一个地址只要在至少一种承载状态下两个方向都走得通就是**可用**，并写明依赖：`own_link`（网关自己有一条终止在这台节点上的隧道，经连接路由直达，与承载状态无关）、`main`（经网关到中继的腿：主链路）、`backup_hub`（经网关到备用枢纽的 WSS）、`fallback`（单枢纽时网关直连枢纽的 WSS 备路）、`any` / `mixed`（随承载路径）。每个可用地址带着每种状态下的去程、回程和网关源地址；不可用的也列出来，带原因。在示例拓扑里：挂在枢纽上的出口，主枢纽链路上的 ULA 依赖主链路、备用枢纽链路上的 ULA 只在备用枢纽承载时可用，IPv4 不可达（中继把 `10.66.0.0/16` 落到黑洞，回程上出口的 AllowedIPs 不含网关的隧道 IPv4）；嵌套出口的 ULA 随承载路径可用，IPv4 不可达，中继出口朝它的那一端地址路由成环；中继在网关到它的链路上的地址是 `own_link`，IX 一侧的地址依赖主链路；主枢纽中继一侧的 IPv4 经网关的探测主机路由（源 10.66.200.2）可用、依赖主链路，出口一侧的 IPv4 不可达；备用枢纽在网关直连它的链路上是 `own_link`，出口一侧的地址只在它承载时可用；单枢纽时枢纽出口一侧的 IPv4 只经网关直连枢纽的 WSS 备路可用。

**「可用」说明什么、不说明什么**：说明按这份配置，网关到这个地址有经隧道的路由，沿途和回程的 AllowedIPs、路由和反向路径检查都放行。不说明隧道此刻在握手、中继或枢纽此刻在它们自己的首选链路上（推导按安装时的首选链路；中继和枢纽自己的切换不在推导里）、服务器的 sshd 监听这个地址、它自己的防火墙接受这个来源——这些只有连接测试能回答。推导不连接任何主机。

**一致性测试**（`internal/compile/mgmt_reach_test.go`）：对每个示例拓扑、每个节点、每个地址和每种承载状态，从渲染出的文件本身（WireGuard 的 `Address` / `AllowedIPs` / 对端、路由脚本的主表路由、源地址规则和表、nft 的连接标记、IPv6 转发开关）重新构造网络再走一遍，结果必须与推导完全相同；推导为可用的每一跳还逐条对照渲染出的 AllowedIPs。

**保存前测试**：`POST /api/servers/{id}/test {"channel": {"mode": "tunnel", "address": …, "port": …}}` 经候选地址登录一次并运行固定的只读测试命令：主机必须出示这台服务器已固定的指纹（还没有固定时拒绝，按原有流程「发现 → 核对 → 确认」，发现也可以带同样的 `channel` 经候选地址读取，读到的只记为待确认），用这台服务器自己的凭据，和保存后的隧道通道一样按拨号地址计限速冷却；连接不放进连接池，结果不记到服务器上（它不是服务器的通道）。只接受 `tunnel` 模式。

**失败提示**（`path_note`）：经隧道地址的连接失败时（保存前的测试、已保存通道的连接测试、引导里的核对），面板读取网关当前的承载状态（备用枢纽或多中继分担时读网关记录的上游路径；单枢纽单中继的网关不记录当前用哪条腿，如实说读不到）：地址依赖主链路而网关现在经备用枢纽承载时写明「主链路可能不通，经它到不了这个地址」，反过来依赖备用枢纽而网关经主链路承载时同样写明；当前状态下按配置走得通时说明失败不是因为承载路径切换；读不到承载状态时如实说明无法判断；手工填写、不在候选里的地址说明未经推导。面板从不自动改走别的管理通道。

**界面**（`web/src/TunnelCandidates.tsx`，服务器表单里选「经隧道地址」时）：可用的候选可以直接选，每个写明地址族、链路（哪条隧道、对端是谁）、依赖，当前承载状态下不通的另外标注；不可用和无法判断的列出来、不能选、带原因；手工填写仍然可以，不在候选里时标注「未经推导」；「保存前测试连接」显示结果和上面的提示。

## 按顺序部署引导

部署页的「按顺序部署待变更节点」把第一次部署和每次改拓扑之后「按出口 → 枢纽 → 中继 → 网关逐台点预检和下发、再自己找出受影响的节点」变成一个由面板计划、操作员逐台确认的流程（`internal/api/deploy_plan.go`，界面 `web/src/DeploymentGuide.tsx`）。它**不增加任何能力**：每一步都是已有的单节点流程，在进程内调用——远端节点是 `POST /api/provision/preflight` 加带 `preflight_id` 的 `POST /api/provision`（同一份凭据、固定指纹、管理通道、连接池里同一个登录、带补偿的下发事务、同一登录里读回服务器记录）；网关是 `POST /api/host/preflight` 加 `POST /api/apply {install:true}` 的安装（meridian-host 的固定动作、带补偿和健康检查的宿主事务）。没有任意命令，没有新的代理能力，也没有「全部确认后自动跑完」。

### 计划与顺序

- 只计划**自己的安装状态**（见「逐节点安装状态」，`node_state.go`）不是 `in_sync` 的受管节点；没有变化的节点、外部 SOCKS 出口（面板不登录、不下发，配置随承载节点下发）和不受管的跳（IX 专线）不生成步骤，列在「跳过」里并写明原因。
- 基本顺序是离网关越远越先装：挂在中继出口后面的出口 → 出口（含中继出口、外部 SOCKS 出口的承载节点）→ 备用枢纽 → 主枢纽（含 IX 线路上的受管主枢纽）→ IX（受管时）→ 国内中继 → 网关。理由写在每一步上：网关最后，因为它的配置要用到每个对端的公钥，并且路由到可切换地区组的名字经组的隧道地址解析、只有出口装好新配置后才会应答；嵌套出口先于它的中继出口，中继出口装好时它要转发的那一端已经是新配置；备用枢纽先于主枢纽，主枢纽重装出问题、主链路整体失败时接管的一方已经是新配置；多台中继一台一台装，正在重装的那台由分担的健康检查剔除，其余照常承载。同一层内按节点 ID。
- **管理通道**会加上「A 先于 B」的约束，约束优先于基本顺序（Kahn 排序，平局按层、再按 ID）：
  - 经节点 M 的服务器跳转管理的节点排在 M 之前：它在 M 仍运行着已证明能承载跳转的配置时装好；M 自己重装时重启的是隧道和服务（不是 sshd），M 装完后这次运行里不再需要经它跳转。
  - 直连地址等于节点 M 的公网端点、端口不同（M 主机上的 TCP 端口转发，例如经中继到达的 IX）的节点排在 M 之前，理由相同；地址相同但看不出哪台承载转发时只警告，不调整。
  - 经隧道地址管理的节点依赖网关和到它的每一跳，基本顺序已经把这些放在它之后；但它自己的安装会重启承载这条 SSH 会话的隧道，会话可能在安装中途断开（结果不明、服务器上的补偿在断线时运行、引导停在那里）——这一点只警告，建议安装时暂时改为直连或跳转；网关还没装时隧道根本不存在，也会警告。
  - 约束互相矛盾（成环）时按基本顺序排列，并在计划上说明。
- 计划不连接任何主机。开始运行时面板先给所有受管节点生成还没有的 WireGuard 密钥（只在面板里，和每次预检做的一样），这样逐台安装期间各节点的内容摘要不会因为对端拿到密钥而变化。

### 只需核对的步骤：不受安装顺序约束

真实使用中，升级后引导给十二个远端节点各列了一步「只需核对」（面板记录已一致，只是没有读回服务器上的记录），其中一台从网关直连 SSH 不通，引导按顺序进行，它后面互不依赖、也不需要安装的五台都轮不到。规则（`internal/api/deploy_verify.go`）：

- **哪些步骤只需核对**：远端节点自己的安装状态是 `in_sync`，最近一次读回服务器记录的结果不是「不一致」（没有读过或没读到）。这样的步骤（`verify_only`）只读服务器上的清单，内容在就采纳，**不安装任何东西**。最近一次读回明确不一致的节点不是只需核对，按顺序重新安装。网关从不是只需核对。
- **调度**：只需核对的步骤不参与安装顺序的计算（它们不重装，不构成「A 先于 B」的约束），也从不是「当前一步」；运行打开期间随时可以单独核对（`POST /api/deploy/runs/{id}/verify {node_id}`）或全部核对（`{all: true}`），不管安装步骤停在哪里、是否失败。需要安装的步骤仍按依赖顺序、逐台确认，和以前完全一样；运行在所有步骤（含核对）都完成时才完成。对只需核对的步骤调用 `…/preflight` 等同于核对它。
- **批量**：服务器端一台接一台执行（同一时刻只有一步在执行，其它请求照旧被 409 `deploy_step_running` 拒绝），每台一次登录（就是只读预检那一次），不自动重试。处在限速等待（`retry_at`）里的服务器**不连接**，结果记为「等待」并显示剩余秒数；连不上的服务器记下原因（`not_executed`，和单节点流程同样的错误码与文字；经隧道管理的服务器附上与当前承载路径相关的说明，见「经隧道管理的地址候选」），批量继续下一台。核对失败从不让运行停下。
- **绑定**：核对结果只对它所属的计划、节点、服务器和固定指纹有效：开始核对前，运行的拓扑版本必须等于当前的（否则 409 `deploy_plan_stale`），这一步计划时的内容摘要和服务器身份（地址、端口、用户、固定指纹、凭据）必须等于现在的（否则同样拒绝，什么都不连接）；读回后预检记录的内容摘要和目标身份必须等于计划时的，服务器上的清单必须记着这个节点、这次部署、这台服务器和这份内容摘要（journal 若有则为 `done`）——全部满足才采纳，并在步骤上记下绑定（`verified`：计划、内容摘要、节点、服务器、指纹、预检 ID、时间）。
- **记录不同**：服务器上没有这个节点的记录、记录属于别的节点 / 部署 / 服务器、内容摘要不同或 journal 不是 `done` 时**从不采纳**：这一步变成普通的安装步骤（`verify_diff` 写明原因），按基本顺序插到第一个还没装好、层级在它之后的安装步骤之前，带着这次只读预检的结果进入审阅，轮到它时由操作员确认才下发。
- **界面**：部署页把只需核对的步骤单独列成一组（「只需核对（N）」，每行「核对」，组上「全部核对」），和按顺序安装的表格分开；状态是待核对、核对中、已核对 · 采纳记录（未重新检查健康）、连不上（原因）、限速等待（倒计时）、记录不同 · 改为按顺序安装。一组最多一条提示。

### 运行与状态机

- 同时只有一个运行：进行中（`active`）或停下（`stopped`）的运行存在时，再开始会被拒绝（409 `deploy_run_active`）。运行可以取消（已装好的保持不变，什么都不撤回），执行中的一步不能中途取消。
- 只能操作**当前一步**（第一个没装好的安装步骤；只需核对的步骤不算，见上，409 `deploy_step_not_current`）；同一时间只有一步在执行（409 `deploy_step_running`）。每一步的阶段：`pending`（待预检）→ `preflighting` → `review`（无阻断项，等操作员确认）或 `blocked`（有阻断项）→ `installing` → `done`；失败为 `failed`（服务器上的复核拒绝、已补偿、补偿有残留；网关的激活失败）或 `unknown`（结果不明、被面板重启打断；远端节点脚本报告成功但装完后读回的服务器记录不一致、读取失败、回答不完整或无法解析——远端一步只有读回结果为 `verified` 才算装好；网关一步只有回答里带着已提交的事务报告才算装好）。
- 每台都要操作员确认：确认请求必须带上这一台最近一次审阅的 `preflight_id`（`POST /api/deploy/runs/{id}/install {node_id, preflight_id}`），确认弹窗写明只确认这一台。确认之后单节点流程照常在执行前再预检一次，结果变了就不执行并把新结果交给操作员审阅。不提供「全部确认后无人值守跑完」：预检的意义是在动手之前看清**那一刻**的主机，提前确认后面的节点等于让它们在没人看过最新预检的情况下执行，和「阻断项不能跳过、新出现的问题要重新审阅」的预检门矛盾。
- 失败、补偿或结果不明会让运行停在那一台（`stopped`），后面的节点不动，已装好的保持装好。停下的节点下一步只能是**重新核对**：再做一次预检，它读取这个节点实际的安装记录——远端是服务器上的清单（节点、部署、服务器、内容摘要）和 journal，网关是本机的安装清单（按文件哈希）。清单已经是要装的内容（并且 journal 为 `done`）就**采纳**为已装好（远端节点的部署记录据此更新，证据记为 `host_record`；标注「没有重新执行，也没有重新做健康检查」），不重做；否则按新的预检结果审阅、由操作员再次确认。有残留或中断的下发由预检的阻断项拦住，用「远端节点」预检对话框里已有的恢复操作处理。没有自动重试。
- 第一次访问某个节点前，若它在运行开始后已经在引导之外装好（自己的状态已是 `in_sync`，远端节点还要求最近一次读回服务器记录的结果是 `verified`），直接标为已装好，不连接主机。计划也按这个标准跳过节点：面板记录为已安装、但没有读回一致的服务器记录的远端节点（单节点流程在读回失败时仍报告「已安装」，引导不沿用这条更弱的规则；升级前的旧记录同理）会得到一步，它的预检读取服务器上的记录，内容已经在就直接采纳、不重装。重新计划时，停在 `failed` / `unknown` 的节点即使面板记录说一致也保留在计划里，直到重新核对。
- 「已装好」只说明安装成功：网关是宿主事务已提交、服务已启动、事务里的健康检查通过；远端是脚本完成激活并写下清单、同一登录里读回的服务器记录与装上去的一致（读回失败、不完整或不一致都不算，见上）；采纳（`adopted`）的节点依据的是预检完整读到的、内容摘要一致的服务器记录（或网关的安装清单），没有重新执行，也没有重新做健康检查，界面这样标注。它**不是**端到端验证（隧道握手、流量经出口、分流、DNS / IPv6 / WebRTC 不泄漏、解锁、远程接入设备拨入），界面在每个已装好的节点上标「端到端未验证」，运行完成时也这样写；端到端验证仍在防泄露页和解锁页，只有实际执行过的才算通过。
- 每个完成的步骤记下它**怎样**完成（`completion`）：`installed`——这次运行里实际安装，并读回了激活与健康结果（远端读回为 `verified`，网关是已提交的宿主事务及其健康检查）；`adopted`——服务器上的安装记录（远端清单、网关安装清单）已经是这份内容，没有执行，**没有重新检查健康**；`in_sync`——在引导之外已装好、面板读回的记录一致，这次没有执行，也没有重新检查健康。现有的固定只读动作里没有一个能在预检的同一登录里给出节点当前的服务健康，所以采纳的节点不做健康检查，只如实标注；本次不新增这类能力。
- 运行完成时的结论（运行的 `summary`、最后一条事件、界面的完成提示和每个节点的标签）都按 `completion` 计算，不看文字：全部是 `installed` 时才写「全部 N 个节点都在这次运行中安装：服务已启动、健康检查通过」；有采纳或已一致的节点时写「M 个节点在这次运行中安装并通过健康检查：…；K 个节点依据服务器上的安装记录采纳，没有重新执行、没有重新检查健康：…」并说明这些节点的服务现在是否在运行没有核实；没有一个节点实际安装时写「没有节点在这次运行中安装」。节点标签分别是「已安装 · 健康检查通过」「已采纳记录 · 未重新检查健康」「已一致 · 本次未执行」。`GET /api/status` 的 `deploy_run` 带 `installed` / `adopted` 计数，概览只显示进度，悬停时给出这两个数。

### 跳过被阻断或连不上的节点，依赖感知地继续

真实使用中，一台承载外部 SOCKS 出口的中继出口因为外部代理对端离线而预检被阻断（见「外部 SOCKS 出口」里修订后的规则），按顺序部署的引导停在它这一步，后面十台与这次改动无关的节点都轮不到，只能取消引导改用逐台下发。规则（`internal/api/deploy_plan.go`「Skip」「Dependencies」，`deploy_skip.go`）：

- **什么可以跳过**：只有**当前一步**，并且它的预检有阻断项（`blocked`），或服务器连不上 / 登录不了 / 主机指纹未确认 / 在限速等待（`pending` 且 `outcome: not_started`，代码属于连接、登录、指纹和 `ssh_rate_limited` 这一类——什么都没执行）。结果不明（`unknown`）或失败（`failed`）的一步**不能跳过**，要先重新核对弄清结果；只要有这样的一步，它就一直是当前一步，不管前面跳过了什么。对失败或结果不明的一步重新核对却没连上时，它保持失败 / 结果不明（以前会退回「待预检」，那样它就可能被当成普通的一步继续）。已审阅没有阻断项、还没预检过、只需核对、执行中、已完成的步骤也不能跳过。`POST /api/deploy/runs/{id}/skip {node_id}`；跳过不连接主机、不改动任何东西。
- **跳过之后**：这一台保持待处理——不算完成、不采纳，记下原因（阻断项原文 / 连不上的原因 / 限速），写进事件记录。引导继续下一个**不依赖它**的步骤；依赖它的步骤保持等待，界面和拒绝信息写明在等哪一台（传递：等待一个正在等待的步骤也算等待）。所有剩下的步骤都是跳过的或在等待的（并且只需核对的都核对完）时，运行以 `partial`（「已结束，有跳过的节点仍待处理」）结束，**不是** `done`：总结列出跳过的节点和原因、因依赖没有安装的节点和它们在等谁，`all_checked` 为假。`partial` 不算打开的运行：可以开始新的引导，无人值守的解锁自动安装不再推迟。
- **回到这一台**：`POST /api/deploy/runs/{id}/unskip {node_id}`，运行打开或以 `partial` 结束时都可以（后者重新打开运行）。它回到原来的位置、从新的预检开始（之前的预检不再使用）；限速等待仍然有效。跳过在重新计划和面板重启之后保留。
- **依赖规则**（B 依赖 A，二者都是这次运行的安装步骤；只需核对的步骤不构成依赖）：
  - B 是网关：它的配置用到每个对端的公钥，地区组的名字解析要由装了新配置的出口应答——依赖其它每一步；
  - B 是备用枢纽、主枢纽、IX 或中继，而 A 在更早的层：枢纽承载更远一层出口的隧道和地区组，中继和 IX 承载到枢纽的流量。面板不分析较近的节点用到了较远节点的哪一部分改动，所以更早层的每一步都算（保守）；
  - A 是挂在中继出口 B 后面的出口（B 转发 A 的隧道）；
  - A 经 B 的服务器跳转、或经 B 主机上的端口转发管理（B 的安装可能改变到达 A 的路径）。
   其余都是**顺序偏好**而不是依赖：同层的出口之间、中继之间（「一台一台装」是为了其余中继照常承载）、嵌套出口与不是它中继出口的出口之间、同层按 ID。这些节点的配置互不引用，一台保持旧配置不改变另一台装上新配置后的工作状态。因此跳过一台出口时，其它出口继续，枢纽、IX、中继和网关等待；跳过一台中继时，其它中继继续，网关等待；网关在任何依赖被跳过时都不会被提供。这一规则之前保存的运行（没有 `dep_model`）把前面的每一步都当依赖：在那样的运行里跳过一台会让后面全部等待，重新计划后改用新规则。
- 操作员判断等待中的节点其实与被跳过的节点无关时，可以用部署页「远端节点」里已有的单节点流程（同样的预检、确认和下发）处理它；引导本身不放宽规则。

### 绑定与失效

- 运行绑定**拓扑版本**：存储的拓扑去掉节点在画布上的位置、私钥和远程接入块之后的哈希（远程接入是独立资源，见下；它对网关文件的影响由网关这一步的内容摘要绑定兜住）。计划之后拓扑被保存过，运行就标为过期，任何一步都被拒绝（409 `deploy_plan_stale`），界面写明原因并列出内容或服务器身份变了的节点；操作员「按当前拓扑重新计划」：已装好且仍一致的节点保持装好，内容和服务器身份都没变的节点保留已审阅的预检，其余预检作废并写明原因（内容变了 / 服务器身份变了），停下的节点仍需重新核对。开始运行时可以带上操作员看到的计划的 `topology_version`，不一致就拒绝。
- 每个已审阅的步骤绑定预检时这个节点的**内容摘要**和**服务器身份**（地址、端口、用户、固定指纹、凭据）。确认时任何一项不同、或预检已过期（10 分钟），确认失效：拒绝执行（409 `deploy_confirmation_invalid`），这一步回到待预检并记下原因。内容摘要也会因为同一运行里前面的节点装好而变化（例如 WSS 材料的阶段），那同样只是让这一步重新预检。

### 重启、重载与限速

- 运行保存在面板数据库（键 `deploy_run`，不含任何秘密：节点、阶段、预检 ID、内容摘要、服务器身份、结果和事件记录）。执行中的一步带着面板进程的启动 ID；请求用不随浏览器断开而取消的上下文执行，页面重载不影响它，重载后界面看到「执行中」并每 3 秒刷新到它结束。面板重启后读到别的进程留下的执行中步骤：被打断的预检（只读）回到待预检；被打断的下发记为 `unknown`（`interrupted`）并让运行停下——**从不显示为已装好**——下一步是重新核对。
- 服务器在握手前回「Not allowed at this time」（`ssh_rate_limited`，什么都没执行）时，这一步记下 `retry_after` 截止时间，界面倒计时，引导在那之前拒绝再连接这台服务器（409 `deploy_wait`，带剩余秒数），连接池自己的冷却也照常生效。登录次数与单节点流程相同：预检一次登录，下发时执行前的再预检、二进制传输和脚本复用连接池里的同一个登录；重新核对就是重试本来就需要的那次预检，不额外连接。

### 与无人值守的解锁自动安装

两者从不同时执行。自动安装在有进行中或停下的运行时推迟，记下原因（`busy`：「按顺序部署引导 … 还没有结束」），直到运行完成或被取消；引导的网关一步从执行前的再预检到宿主事务结束一直持有网关节点锁，自动安装拿不到锁也会推迟。反过来，自动安装正在安装网关时，引导的网关预检或安装被拒绝、什么都不执行，并写明「无人值守的解锁自动安装正在安装网关」，操作员稍后再点。

### 远程接入是独立资源

远程接入的开关和设备只由 `/api/remote-access` 修改：保存整份拓扑时保留存储的远程接入块，请求里带了不同的值就整个拒绝（`putTopology`，见「整份拓扑保存与独立资源」），引导的任何一步都不打开、关闭或修改它；它的改动和别的改动一样，要随网关的安装生效。部署页（引导里）和远程接入页都这样写明。

### API

- `GET /api/deploy`：`plan`（按当前存储的拓扑现算的计划：步骤、原因、警告、跳过的节点、说明）、`run`（当前或最近一次运行及每一步的实时比对：`changes`、`confirmation_valid`、`can_preflight`、`can_install`、`wait_seconds`，当前一步审阅过的预检记录）、`limits`（能证明 / 不能证明 / 独立资源）。
- `POST /api/deploy/runs/{id}/skip {node_id}`（跳过当前被阻断或连不上的一步；409 `deploy_skip_refused` / `deploy_skip_unresolved`（失败或结果不明）/ `deploy_step_not_current` / `deploy_step_running` / `deploy_plan_stale`）、`POST /api/deploy/runs/{id}/unskip {node_id}`（409 `deploy_step_not_skipped`）。每一步带 `skip`（种类、原因、时间）、`can_skip`、`skip_holds`（跳过它时会等待的节点）、`can_unskip`、`waiting_for`（它在等的被跳过节点）；计划步骤带 `tier` 和 `after`（依赖规则的输入）；运行的 `summary` 带 `skipped_nodes` / `waiting_nodes`；`GET /api/status` 的 `deploy_run` 带 `skipped` 计数。
- `POST /api/deploy/runs {topology_version?}`、`POST /api/deploy/runs/{id}/preflight {node_id}`、`POST /api/deploy/runs/{id}/install {node_id, preflight_id}`、`POST /api/deploy/runs/{id}/verify {node_id} | {all: true}`（只需核对的步骤；回答带 `verify`：每台的 `verified` / `differs` / `unreachable` / `waiting` / `refused` 及原因）、`POST /api/deploy/runs/{id}/replan`、`POST /api/deploy/runs/{id}/cancel`。动作被引导本身拒绝时返回 4xx 和 `code`；动作执行了（不论主机上成功与否）返回 200 和整个视图，结果写在那一步上。
- `GET /api/status` 多了 `deploy_run`（打开的运行：ID、状态、当前节点、完成数 / 总数），概览页据此显示。

**验证状态**：顺序计算、跳过与依赖、只需核对步骤的调度与绑定、运行状态机、失效、重启、限速和与自动安装的互斥只在仓库的自动化测试里跑过（本地 SSH 替身、模拟的宿主预检和激活），**没有对真实主机执行过**；经隧道管理时会话被自己的安装切断这一情形没有实测。

## 地区组（出口的选择与切换）

用户的需求：出口按国家或地区（香港、美国……）分成大组，每个组里有多个出口节点；每个组要么由用户指定用哪一个，要么自动切换，自动切换的顺序由用户手工排。以下是这一版定下来的领域决策，代码在 `internal/model/groups.go`（对象和迁移）、`internal/pool`（有效顺序、选择、状态机）、`internal/compile`（标记、路由、枢纽切换脚本）、`internal/api/region_groups.go`（REST）。

### 对象

`region_groups[]`，每个组：

| 字段 | 含义 |
| --- | --- |
| `id` | 稳定 ID（小写字母、数字、短横线），规则用它引用 |
| `name` / `region` | 显示名和地区（`hk`、`us`……）。同一地区允许多个组，例如香港机房组和香港住宅组。显示名可以重复：面板在任何列出或选择地区组的地方（出口页卡片、规则的目标选择和列表、拓扑、解锁的选择器和结果矩阵、概览）发现同名（去空格、不分大小写）时显示成「名称（地区 · ID）」，出口页卡片另有「同名」标签，新建 / 编辑时提示已有同名组；只有一个时显示原名 |
| `members` | 成员出口 ID，按用户排的顺序。一个出口可以属于多个组 |
| `mode` | `auto`（自动）或 `manual`（手动） |
| `chosen` | 手动模式下用户指定的成员；自动模式必须为空 |
| `on_failure` | 只在手动模式有意义：`hold`（默认，保持指定成员并告警）或 `fallback`（临时回落到有效顺序里的下一个可用成员并告警，恢复后按自动模式同样的规则切回） |
| `require_residential` / `exclude_residential` / `require_v6` | 组的硬约束（必须住宅 / 排除住宅 / 必须有 IPv6 出口）。前两者互斥 |
| `migrated_from` | 迁移来源，`pool:<旧池名>#<模式>[-resi][-v6]`，迁移重跑靠它认出已有的组 |

`settings.default_group` 是不匹配任何规则的境外流量用的组（原来固定是 `hk` 池）。

规则只能二选一：`target_group`（引用组）或 `target_exit`（显式钉死一个出口）。规则不再有自己的 `mode`；组是手动/自动的唯一事实来源。规则上的 `require_residential` / `require_v6` 保留，但不再是第二个配置点：它们是对所引用组的断言，组没有相同约束时校验报错（`residential_required` / `constraint_conflict`），不会出现"规则说要本地宽带、组里却能切到机房"的情况。同时带 `target_group` 和 `mode`、或同时带 `target_group` 和 `target_exit` 的规则被拒绝（`rule_mode_removed` / `rule_target_conflict`）。

### 包装还是替换旧的池

替换。旧的「池」只是节点上的一个名字（`pool` / `pool_priority`），规则用 `target_pool` + `mode` 指向它。地区组是独立对象；迁移后节点的 `pool` / `pool_priority`、规则的 `target_pool` / `mode` 全部清空。这几个旧字段只作为输入保留：旧面板或旧导出再写进来时，读入时立刻并入组（见下），不会形成第二份配置。没有迁移的文档（规则仍带 `target_pool`）校验直接报错 `legacy_pool_target`。

### 迁移

`model.MigrateRegionGroups`，在 `store.Load`（每次读库）和 API 收到整份拓扑（`PUT /api/topology`、带拓扑的 validate/compile/diff）时运行。它是纯内存变换，结果随一次整行写入保存，所以中断不会留下半份数据；对已经迁移的文档再跑是空操作。

1. 每个旧池按原来的首选顺序收集成员：IX 绑定优先，然后 `pool_priority` 小的在前，再按 ID。这就是迁移后组的 `members` 顺序，所以迁移前后有效顺序完全一样（IX 优先、稳定排序）。
2. 指向同一个池的规则按「模式 + 住宅要求 + IPv6 要求」分成变体，每个变体一个组。同池不同模式时生成独立的组，行为不丢：
   - `auto` → 自动组；
   - `pin` → 手动组，`chosen` 是原来的首选成员，`on_failure: fallback`。原来钉死规则用的是首选成员的 mark，而枢纽的链路切换会改这张表的下一跳，所以钉死规则其实会随链路故障临时换到同池备成员、恢复后切回，但不受解锁结果影响。手动 + 回落正是这个行为。
3. 基本变体（优先自动、无额外约束）的组 ID 就是池名，其余是 `池名-pin`、`池名-auto-resi` 这类；与已有 ID 冲突时加序号。没有规则引用的池也生成一个自动组，节点归属不丢。
4. 池 `hk` 的组带 `exclude_residential`（原来 `hk` 池不收住宅）；被要求住宅的规则（`require_residential` 或名字里有 Netflix / Disney）对应的组带 `require_residential`。原来这样的池里若有机房成员会直接报错，所以加约束不改变任何能通过校验的拓扑的行为。
5. `settings.default_group` 为空时设为 `hk` 的自动组。
6. 已有组时，带旧字段的输入并进来：节点的 `pool` 加到所有 `migrated_from` 是该池的组（追加在末尾），规则的 `target_pool` + `mode` 找到对应变体的组，没有就新建。然后清空旧字段。

面板保存的解锁状态（按规则）和链路状态（按名字）不迁移：基本变体的组 ID 与旧池名相同，状态继续可用；新 ID 的组从冷启动开始。

### 有效顺序

`pool.Effective(topology, group)`：

1. 先按硬约束过滤：节点不存在或不是出口（`missing`）、重复（`duplicate`）、组要求住宅而它不是（`residential_required`）、组排除住宅而它是（`residential_excluded`）、组要求 IPv6 而它没有 `egress_v6`（`v6_required`）。被排除的成员留在列表里，`position: -1`，带原因。
2. 剩下的按 IX 绑定优先、其余保持用户顺序（稳定排序）。被 IX 提前的成员带 `ix_first`，因此被往后挤的带 `after_ix`。
3. 枢纽不能直接切到的成员（只能经双栈中继到达）仍可被静态选中，但带 `not_switchable`，不进动态候选。

API 同时返回 `effective_order` 和每个成员的 `reasons`，界面直接用来解释"为什么它排在这里 / 为什么灰掉"。

### 选择（静态编译）

- 自动：有效顺序第一个（`preferred`）。
- 手动：`chosen`（`chosen`）。`chosen` 不在成员里或被约束排除时校验报错 `chosen_not_eligible`；运行时万一出现，就用有效顺序第一个并标 `constraint`。
- 没有可用成员：`none`，引用它的规则校验报错。

自动组里的规则仍按服务跟随解锁映射（`internal/unlock`），只在本组的有效顺序内移动；手动组的规则不受解锁结果影响（只记录）。组的有效首选变了（改顺序、改成员、改约束）时，该服务的解锁状态按新首选重新对齐（`unlock.Reconcile`）：新首选最近一次结果是失败、而组里有已知可用的成员时，保持降级在那个成员上，切回仍要满足完整的恢复条件；对不齐的旧状态不产生任何映射（`unlock.Decisions` 要求状态的首选与当前首选一致）。

### 运行时状态机（枢纽上 `meridian-failover.sh` 的 `group_step`，面板里同一份 `pool.StepGroup`）

每个成员一组滞回计数：连续 3 次失败判死，连续 5 次成功判活（`FailsNeed` / `RecoversNeed`）。另外记录最近一次样本是否成功（`last_ok`）和当前连续成功的起点（`ok_since`，任何一次失败清零）。

- 自动：当前成员判死时立即换到试探顺序里下一个判活的成员；没有判活的成员时不动（停在原成员上，不换国家，也没有通往 Mesh 的一跳：编译出的组策略里 Mesh 一项恒为 0，状态机里 `mmesh` 这个取值只为没有 Mesh 边的拓扑保持逐字节不变而留着；有 Mesh 边的拓扑里 `group_hop` 直接拒绝 `mmesh`）。切回首选需要同时满足：首选判活、最近一次样本成功、`ok_since` 起连续成功满 120 秒、距上次切换满 120 秒。首选任何一次失败都清空恢复计时，当前不健康（最近一次样本失败）就不切回——即使它在滞回意义上仍是「活」的。
- 手动 + `hold`：永远停在 `chosen`，不切到别的成员。`chosen` 判死时状态是 `held`，`alert: true`。
- 手动 + `fallback`：试探顺序是 `chosen` 在前，然后是有效顺序里的其余成员。行为与自动完全相同（包括切回条件），只是首选换成 `chosen`；离开 `chosen` 期间状态是 `fallback`，`alert: true`，回到 `chosen` 后告警消失。

状态原因（`actual.reason`、`model.reason`）：`preferred`、`chosen`、`failover`、`fallback`、`held`、`mesh`、`constraint`、`none`。枢纽为每个组记录切换器选中的成员（`active`）、路由表里实际的下一跳（`hop`）、原因、上次切换时间和每个成员的计数；面板的推算记录同样的字段和每个成员的健康。两者怎样分开见下面「实际状态与面板推算」。

界面必须显示：

- 自动：当前实际成员；不是首选时显示「故障切换」以及首选为什么还没切回（未判活 / 最近一次失败 / 恢复计时还剩多少）。
- 手动 + 保持：实际成员永远是指定成员；它判死时显示红色告警「指定成员不可用，按设置保持不切换」，并给出改成回落或换成员的入口。
- 手动 + 回落：正常时同「手动」；回落期间显示告警「指定成员不可用，临时使用 X」，以及切回所需条件。

「实际成员」只能来自枢纽报告（`actual.state == "ok"`）；读不到、过期、版本不一致或切换失败时显示「未知」和原因。告警以枢纽报告为准；「首选为什么还没切回」和剩余时间只有面板推算能给出，界面上写作「面板推算还没有切回 …」。

### 实际状态与面板推算（两个来源，分开显示）

每个组的视图（`GET /api/region-groups`、`GET /api/region-groups/{id}`）有两块，互不混用：

- **`actual`：枢纽报告的实际状态。** 只有它能显示成「实际使用」。来自枢纽自己写下的记录，经面板读回（见下）。
- **直连出口（没有枢纽、网关直接连出口的拓扑）。** 这时切换组的是网关自己的 `meridian-failover.sh`，它写的文件与枢纽相同（`/run/meridian/group-plan`、`group/<id>/report`、`exit-legs/report`）。面板不走 SSH，而是经宿主代理不带参数的固定只读请求 `POST /v1/groups/state` 读回，回答与枢纽读取的分帧文本格式一致，用同一个解析器（`hubstate.Parse`）判断；`actual` 写明读自网关。只有单元测试覆盖，没有在真实网络上执行过。单中继拓扑同样由网关之外的那台中继/出口直连，不能有备用枢纽。
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

`hop` 每轮从内核读（`ip -4/-6 route show table <组表>`）：不算 metric 32767 兜底黑洞的那条默认路由，按它的接口对回成员（`mmesh` 是 Mesh veth：现在不会出现，见上）；黑洞默认或只剩兜底是 `blackhole`，表里没有默认路由是 `none`，接口不是成员是 `other`，v4 与 v6 不一致是 `split`。所以它描述的是路由表里真实的内容，不是脚本想要的。`result=failed`：本轮决定切换但 `group_hop` 失败（`active`、`switched` 不变，`hop` 仍是表里原来的成员）；`result=diverged`：表里的内容与切换器的选择不一致（选 Mesh 而 Mesh 未封装、表是黑洞，这是设计行为，不算不一致）。另外服务启动时 `reset_groups` 装好编译目标后写一次 `/run/meridian/group-plan`：`plan <部署标识> <epoch>`。安装时 `meridian-up.sh` 会重启这个服务。

**部署标识。** `compile.GroupPlanID`：枢纽编译出的地区组切换段（组表、成员接口与对端、试探顺序、策略标志和脚本本身）的 SHA-256 前 24 位十六进制，作为 `GROUP_PLAN=` 写进枢纽的 `meridian-failover.sh`。不含任何秘密。面板对当前存储的拓扑算同一个值来比较；与组无关的改动（规则、名单等）不改变它。

**面板怎么读。** `POST /api/region-groups/runtime/refresh` 不接受任何参数（请求体被忽略），目标是拓扑里的枢纽节点，经它关联的受管服务器、用已有的 SSH 连接器（主机指纹必须已确认并固定，凭据在执行边界从凭据库取出，输出去敏）执行一条固定的只读命令 `sshexec.GroupStateCommand`：

```
{ printf 'meridian-group-state 1\nnow %s\n' "$(date +%s)"; cat /run/meridian/group-plan; for f in /run/meridian/group/*/report; do if [ -f "$f" ]; then cat "$f"; fi; done; echo meridian-group-state-end; } 2>/dev/null | head -c 65537
```

总超时 30 秒，输出在枢纽上截到 2 MiB + 1 字节（含有界的双腿切换记录），超过 2 MiB 即判为过大。同一时间只允许一次读取（并发返回 409 `refresh_in_progress`）。结果（或读不到的原因）连同读取时间存进面板数据库，页面重新加载后仍显示，并标明读取时间。枢纽打出来的东西只按含义采信（`internal/hubstate`）：逐行严格语法、只允许可打印 ASCII、值是受限字符的短标记、时间必须晚于 2020-01-01 且不晚于枢纽自己的 `now` 5 秒、`switched` 不晚于心跳；任何一行不合格整份拒绝（`parse_error`）。拓扑里没有的组 ID 不显示（`hub_state.last_read.ignored`）；成员 ID 必须在该组编译出的切换顺序里（`mmesh` 只在组有 Mesh 边时），否则这个组是 `invalid_report`。

**读取结果绑定枢纽身份。** 每次读取都记下它是从哪个枢纽读的（`hubstate.Identity`）：枢纽节点 ID、服务器 ID、规范化后的地址（去空白和方括号、小写、去掉末尾的点，IP 字面量写成规范形式，IPv4 映射的 IPv6 写成 IPv4）、SSH 端口（0 视为 22）和固定的主机指纹。身份在读取开始前从当前拓扑和服务器记录取出（`internal/api` 的 `serverIdentity`；指纹只在主机指纹是「已确认」或「不一致」时算作固定，其余状态为空——改地址或端口、清除或重新发现指纹都会清掉它）。三处用同一个身份：

1. 连接：SSH 连接钉在这个身份上（`sshexec.Target` 带地址、端口、用户和指纹），服务器记录在此期间被改过、或主机出示的不是这把钥匙，连接器拒绝（`target_changed` / `host_key_not_pinned_by_deployment`），不会以旧身份读到新主机。
2. 存储：读取结束后重新取当前身份；与开始时不同，这次结果丢弃、不存为当前状态，接口返回 409 `hub_identity_changed`（「读取期间枢纽的……已变更」），原来存的那次读取保持不变。并发刷新本来就只允许一次（`refresh_in_progress`）。
3. 显示：每次 `GET /api/region-groups`、`GET /api/region-groups/{id}`、概览和解锁矩阵都把存储的读取与此刻的身份比较；任何一项不同，这次读取对每个可切换组都是 `unavailable` / `hub_identity_changed`，没有成员、原因和切换时间，界面显示「实际使用 未知 · 未验证 · 枢纽已变更」和原因，直到对当前枢纽读取成功。这个比较在 10 分钟的 `read_old` 之前，立即生效；它也兜住了「检查之后、存储之前」身份又变化的窗口。主机出示了与固定指纹不同的钥匙（「不一致」）时身份不变，但成功的报告同样不再采信。`hub_state.last_read.current_hub: false` 加 `identity_code` / `identity_message` 告诉界面那次读取不是当前枢纽的，枢纽状态条上标「不是当前枢纽」，并且不受「1 分钟内读过就不自动读」的限制。

改名、改标签或备注不改变身份；把枢纽节点改到另一台服务器、原地修改同一台服务器的地址或端口（即使之后确认的仍是同一把钥匙）、重新确认成另一把钥匙或清除指纹，都会让旧报告立即变成未知。身份变回原样（例如改回原地址并确认同一把钥匙）时，原来那次读取重新与当前身份一致，仍受部署标识、心跳和 10 分钟读取时效的检查。更早版本存下的读取没有地址和指纹，一律视为身份不同。

**每个组的 `actual.state`**（按顺序判定）：

| 状态 | 条件 | 界面 |
| --- | --- | --- |
| `not_switchable` | 组不由枢纽切换（静态选择只能经双栈中继到达，或没有可用成员），枢纽上没有它的状态 | 「不适用 · 枢纽不切换」 |
| `never_read` | 还没有读过 | 未知 · 未验证 |
| `unavailable` / `hub_identity_changed` | 存储的读取不是当前枢纽身份（枢纽节点、服务器、地址、SSH 端口、固定指纹任一不同，或主机指纹现在不一致），见上 | 未知 · 未验证 · 枢纽已变更；可读时「重新读取」，否则链到服务器页 / 拓扑 |
| `unavailable` | `code`：`no_hub`、`hub_no_server`、`server_not_ready`（指纹未确认 / 不一致、没有凭据，带 `ssh_code`）、`ssh_failed`（带 `ssh_code`）、`parse_error`、`state_missing`（枢纽上没有这个组的记录或没有 `group-plan`）、`invalid_report`、`plan_unavailable`（面板编译不出当前计划） | 未知 · 未验证，原因和修复入口 |
| `version_mismatch` | 枢纽的 `group-plan` 或该组报告的 `plan` 不等于面板现在编译出的部署标识（`deployed_matches: false`）：枢纽还没按当前拓扑下发 | 未知 · 未验证，链到部署页 |
| `stale` | `heartbeat_old`：枢纽的 `now` 减心跳超过 `compile.HubStaleAfter`；或 `read_old`：读取已超过 10 分钟 | 未知 · 未验证，重新读取 |
| `switch_failed` | `hop_failed`（`result=failed`）或 `table_diverged`（`result=diverged`，或面板自己核对 `hop` 与 `active` 不一致） | 失败；`reported` 里给出枢纽报告的表内容和想切到的成员，标「枢纽报告（未确认）」 |
| `ok` | 以上都不是 | 「实际使用 X · 原因 · 上次切换 · 读取于」 |

只有 `ok` 带 `active`、`hop`、`reason`、`alert`、`last_switch`、`running_since`；`active` 是成员 ID、`mmesh`，或表是黑洞时为空（`hop: "blackhole"`，界面写明流量被丢弃）。

**过期阈值。** `HubStaleAfter` = 3 × 一轮最坏耗时，至少 60 秒；一轮最坏耗时 = 循环间隔 5 秒 + 每次 ping 至多 2 秒 ×（3 条西向隧道 + 所有可切换组的成员数）+ 10 秒（Mesh 封装检查）。示例拓扑（`defaults.Example`）是 135 秒。阈值和循环间隔在 `hub_state` 里返回给界面。

**时钟。** 心跳和枢纽 `now` 来自同一次读取、同一个时钟，过期判断不受两边时钟差影响。显示的时间按读取时刻换算到面板时钟（枢纽时间 + 读取时刻 − 枢纽 `now`），差值作为 `clock_skew_sec` 返回；超过 300 秒时界面提示。时间合理性检查用的是枢纽自己的 `now`。

**页面。** 「出口」页顶部的「枢纽运行状态」条显示枢纽、服务器、上次读取和「读取枢纽状态」按钮；枢纽读不了时说明原因并链到修复处（拓扑、服务器页）。打开页面时，如果枢纽可读且上次读取早于 1 分钟，自动读一次（每次进入页面最多一次，不轮询）。概览的地区组卡片同样只在 `ok` 时写成员名，其余显示「实际未知 · …」。解锁矩阵里实心圆点只表示枢纽报告在用，空心圆点是面板推算。

**只有真实枢纽能证明的**：枢纽真的按报告切换了流量（报告只说明枢纽内核里组表的内容）；`ip` 在真实内核上的输出被正确解析（隔离 Linux 测试 `TestNetnsGroupDNSFailover` 会核对报告里的 `hop`）；真实 SSH 登录到枢纽和读取路径。见[验收清单](verification.md#地区组和-mesh)。

### 静态编译与动态切换一致

- 每个出口保留自己的 mark、中转地址和枢纽路由表（索引按出口 ID 排序，和以前一样）。这些出口表始终只指向自己的出口；有 Mesh 腿时，仅在同一出口的两条 WireGuard 腿之间动态改写，双断时黑洞。显式钉死出口的规则、被解锁映射移到某个成员的规则，都用成员自己的 mark，所以不会被链路切换悄悄带走。
- 每个组另有一个 mark / 中转地址 / 枢纽路由表，索引接在出口后面（按组 ID 排序）。规则和默认流量在组的静态选择可以由枢纽切换时用组的 mark；静态选择只能经双栈中继到达时，退回该成员自己的 mark（没有动态切换，`not_switchable`）。
- 网关：组 mark 和出口 mark 一样进表 102、SNAT 到组的中转地址；`inet meridian_guard` 的出口 mark 范围按实际最大的 mark（出口加组）计算，选择器清理循环也覆盖到同一上限，所以增删组成员和组时兜底表的 mark 范围随编译更新。允许的接口集合是网关自己的 WireGuard 接口，与组成员无关；它不包含 `mmesh`。
- 枢纽：静态路由脚本把组表的默认路由装到编译时的选择上，并清掉该组的运行时状态；切换脚本启动时同样清掉状态并重新装一遍编译时的选择，之后由成员切换只改组表，同出口的腿切换同时更新所指向的接口。两边用同一个 `group_hop` 函数和同一组每成员下一跳（直连 WireGuard 用 `dev <接口>`；Mesh 用 `via $MESH_NH4` / `via $MESH_NH6 dev $MESH_DEV`，并且要先有密封标记，否则黑洞）。表 100、102、150、main 以及任何出口自己的表都会被拒绝。
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
7. **成员的 Mesh 腿。** 地区组自己没有通往 Mesh 的一跳：组表只指向成员的 WireGuard 接口。成员有 Mesh 腿（见「Mesh」）时，它的 `group_dns` 链把这条腿的接口也列进去（`iifname { <直连隧道>, <Mesh 腿> }`），枢纽改用 Mesh 腿承载这个成员时，组的查询照样由这个成员自己的解析器应答，回包按连接标记从来的那条腿回去（「Mesh」→ 出口的回程）。以前的做法——组表默认路由指向 `mmesh`、出口的 Mesh 节点发布组解析地址的 /128、出口在 `mmesh` 上应答（标记 `0x4d6d`、表 171、锚地址 `fd66::4d:1`）——已经删除；装过那一版的出口，路由脚本会删掉留下的两条规则并清空表 171。证据：结构测试 `TestGroupDNSExitDNAT`；命名空间里 `TestNetnsMeshLeg` 用真实 WireGuard 经两端 sidecar 把组解析查询送到出口并得到应答。真实 Cloudflare Mesh 上没有证据。
8. **手动组。** `hold`：组表永远指向 `chosen`，DNS 也只问它，它坏了解析和数据一起失败。`fallback`：和自动组一样跟随切换。
9. **远程接入设备** 的 DNS 被劫持到同一个网关 SmartDNS，行为与局域网客户端相同。
10. **升级顺序。** 网关装上这一版后，组的查询发往只有重新下发过的出口才会应答的地址；还没更新的出口不应答，组内名字解析失败（不会回落到旧的「问首选成员」的做法——那正是要修的不一致）。所以先下发出口和枢纽，再安装网关（「下发顺序」，面板「部署」页的推荐顺序同样写了）。编译无法知道远端已经是哪一版，所以不出校验问题；`APPLY_ORDER.txt` 在有可切换组时写明这一点，`meridian-verify.sh` 的 `PENDING-HUMAN group_dns_failover` 要求实测。

没有可切换组的拓扑，编译结果里没有这些行（测试 `TestGroupDNSAbsentWithoutSwitchableGroup`）。运行时测试 `TestNetnsGroupDNSFailover`（见[验收清单](verification.md#地区组的解析)）在网络命名空间里用编译出的网关、国内中继、枢纽、两个成员出口的 nft 和路由以及枢纽的 `group_step` 跑完整条路径；成员之间的切换部分 2026-11-13 跑通过一次（见 `docs/evidence/2026-11-13-debian13/netns-group-dns.log`）。当时测试里还有旧结构的 Mesh 阶段（组表指向 `mmesh`；`docs/evidence/2026-11-13-debian13-mesh-dns/` 是那一版的记录，现在只有历史意义），Mesh 改为 WireGuard 的底层承载后这些阶段已删除：组没有通往 Mesh 的一跳，成员全部失效时组停在原成员上（测试第 5 阶段改为断言这一点），Mesh 腿由 `TestNetnsMeshLeg` 单独验证。成员出口上的解析器在测试里是替身，真实出口、真实枢纽上的行为仍是待人工签收。

### 兼容

`GET /api/pools` 和 `POST /api/pools/health` 保留，数据来自地区组（`id` 是组 ID，`priority` 是用户顺序里的位置）。面板已经重建（见「面板信息架构」），地区组在「出口」页用 `/api/region-groups` 编辑；这两个旧接口只为旧脚本保留。

## Mesh

### Cloudflare Mesh：WireGuard 的底层承载

Mesh 在 Meridian 里只做一件事：**承载枢纽到出口的一条 WireGuard 腿的外层 UDP 包**。客户流量从不以明文进入 Mesh，也不从 Cloudflare 的出口出去：它在出口上解封装，从出口自己的上联出去，所以出口 IP、地区、解锁结论和解析器都与直连腿相同。动机是枢纽（香港）到远处出口（日本、美国）的公网路径可能不好，Mesh 给同一个出口多一条底层路径。

以前不是这样：`cf_mesh` 边曾经意味着「出口的 Mesh 节点发布网段，枢纽把地区组表或出口表的默认路由指向 sidecar」，流量大概率从 Cloudflare 自己的出口出去，出口 IP 和地区都变了。那套语义已经删除（见下面「迁移」）。

**结构。**

```
枢纽 WireGuard（Mesh 腿，Endpoint = 出口的 Mesh 专用地址）
   └─ 外层 UDP ─▶ mmesh ─▶ 枢纽 sidecar ─▶ Cloudflare Mesh ─▶ 出口 sidecar ─▶ mmesh ─▶ 出口 WireGuard（监听）
隧道里面：和直连腿一样的客户包（中转源地址）─▶ 出口解封装 ─▶ 出口自己的 WAN（NAT / NAT66）
```

- **链路。** 拓扑里一条 `cf_mesh` 链路连接**主枢纽**和一个出口，标为待命。它编译成一条普通的 WireGuard 隧道（`compile.Tunnel.MeshLeg`）：自己的接口、端口、隧道网段（链路序号，和别的隧道链路共用一套；旧文档里没有分配表时 Mesh 链路排在所有别的链路之后取号，别的链路的接口名不变）。
- **谁拨谁。** 永远是枢纽拨、出口监听，出口在 NAT 后面也一样（两端各自连出到 Cloudflare，没有谁的公网地址被拨）：`cf_mesh` 链路不受 NAT 拨号方向检查（`TestNATDialOutExitMeshEdge`、`TestMeshLegEndsAndPorts`）。端口是链路的 `wg_port` 或序号的默认值，不占用出口的 `listen_port`。
- **出口发布的地址。** 每个有 Mesh 边的出口有一个 **Mesh 专用地址**：面板从地址池（`settings.mesh_underlay_prefix`，默认 `10.68.0.0/24`）里按出口分配一个序号（`allocations.mesh`，和别的序号一样只分配一次、不随别的对象变动、删除后先退休），地址是池里的第「序号 + 1」个主机地址。出口的 Mesh 节点**只发布这一个 /32**，不发布默认路由、不发布组解析地址、不发布任何 Meridian 网段。这一版只分配 IPv4 /32：Mesh 对 IPv6 路由的承载没有实机依据，IPv6 地址池被校验拒绝。
- **两条腿的关系。** 出口既有直连腿又有 Mesh 腿时，编译出的默认是直连腿（出口表 `default dev <直连接口>`），Mesh 腿建好、保持握手、不承载流量；把出口从一条腿换到另一条只需要改这一跳——出口表和指向这个出口的组表的 `default dev` 在两个 WireGuard 接口之间换，不改国家、不改出口；出口那边不用动（回程按入接口跟随，见下）。**按链路质量自动在两条腿之间切换**由枢纽的故障切换循环执行（见下面「同出口双腿质量」）；直连腿完全无响应时不等冷却，改用可达的 Mesh 腿。纯 IPv6、选了 Mesh 绕行的出口没有别的腿，Mesh 腿就是它的隧道（枢纽没有 IPv6，Mesh 专用地址是 IPv4）。
- **一台主机一个 sidecar。** 枢纽上的一个 sidecar（一个容器、一对 veth）服务它所有的 Mesh 腿，出口上一个。
- **面板里看得到的。** 链路的分配信息（`POST /api/topology/allocations` 的 `links[].mesh`：发布的 /32、哪个出口、Mesh 路径 MTU、腿内可用值和接口 MTU）和路径报告的 `mesh_links`。地区组视图里旧的 `mesh_backup` 字段还在，恒为 `false`（组没有 Mesh 备路这回事了）。出口、拓扑与链路日志页可以读取当前腿、两腿质量与最近切换记录；没有当前配置的有效读数时显示未知。

**绝不指向 `mmesh` 的东西。** 任何主机的任何路由表里都没有指向 `mmesh` 的默认路由：出口表、地区组表、main、静态脚本或切换脚本都没有（`TestMeshNoDefaultRouteOntoVeth`）。`mmesh` 上唯一的路由是枢纽 main 表里到各出口 Mesh 专用地址的 /32 主机路由（`mesh_underlay`，`via 169.254.66.2 dev mmesh`）：

- 只在 sidecar 已密封（`/run/meridian/mesh-sealed`）时安装；每个 /32 后面始终有同一个 /32 的黑洞（metric 32767），sidecar 不在或未密封时 Mesh 腿的外层包被丢弃，不会顺着默认路由从枢纽的 WAN 出去。`meridian-up.sh` 在建 WireGuard 接口**之前**就先装这些黑洞（Mesh 腿一起来就发握手；命名空间测试第一次运行时正是在这里抓到一个漏出去的握手包）。
- 同一个函数在路由脚本和 `meridian-mesh-up.sh` 里逐字节相同，后者在每条退出路径上运行它；经 sidecar 的、不是当前对端的路由（旧结构的默认路由、已删除的对端）会被清掉。
- 有 Mesh 边的拓扑里，每个枢纽（包括没有 sidecar 的备用枢纽）的 `group_hop` 直接拒绝 `mmesh`（`group hop refused … never a next hop`）。没有 Mesh 边的拓扑保持原来的脚本文本（逐字节不变），那里既没有 veth，也没有任何策略会要求这一跳。
- 宿主的 nft（`inet meridian` 的 `mesh_veth_forward` / `mesh_veth_input`）：不转发任何从 `mmesh` 进来或发往 `mmesh` 的包；从 `mmesh` 只接受 Mesh 腿的 WireGuard（出口：到自己 Mesh 地址、Mesh 腿端口的 UDP；枢纽：只有自己发出的连接的回包）和 ICMP（密封检查用）。出口上 Mesh 腿的端口在别的接口上被丢弃：这条腿只能经 Mesh 到达。Docker 的 FORWARD DROP 共存规则里不再有 `mmesh`（它不参与转发），Mesh 腿的 WireGuard 接口和别的隧道接口一样处理。

**密封（sidecar 网络命名空间内，`meridian-mesh-up.sh`）。** 宿主从 `mmesh` 送进去的包只查表 170（`iif mmesh-c lookup 170`，优先级 17000），永远不走容器自己的默认路由（docker 网桥，会 NAT 到宿主的 WAN）：

| | 枢纽的 sidecar | 出口的 sidecar |
| --- | --- | --- |
| 表 170 | 每个对端出口的 Mesh 专用地址 `/32 dev <WARP>`，加 `unreachable default` | `100.96.0.0/12 dev <WARP>`（回给枢纽的 Mesh 地址），加 `unreachable default` |
| 转发（`inet meridian_mesh`） | 只放行 `mmesh-c → WARP`、目的是某条腿的对端地址和那条腿的 UDP 端口；回程只放行已建立连接；其余进出 `mmesh-c` 一律丢弃 | 只放行 `WARP → mmesh-c`、目的是本出口的 Mesh 地址和 Mesh 腿端口的 UDP，以及它的回包（源是本出口地址和端口、已建立连接）；其余一律丢弃 |
| 源地址转换 | `mmesh-c → WARP` 伪装成本节点的 Mesh 地址 | `WARP → mmesh-c` 伪装成 sidecar 的 veth 地址，宿主不需要到 Mesh 地址段的路由 |
| 其它 | — | `本出口 Mesh 地址/32 via 169.254.66.1 dev mmesh-c`：交给宿主的 WireGuard 监听 |

表 170 里别的路由（旧版从 WARP 设备复制来的、已不存在的对端）每次密封时删除；不再有「Meridian 网段经 veth 回宿主」的回程路由（旧版留下的会被删掉）。重新密封不清空表、不重建规则，只在一个 nft 事务里替换 `meridian_mesh`，所以每 5 秒一次的重新密封不打断 Mesh 腿。先密封、后把 `mmesh-c` 置为 up。没有 WARP 设备时整张表只有 unreachable、转发全部丢弃。sidecar 里没有 `nft` 时密封失败（不再是悄悄跳过）。出口没有故障切换循环，每个有 Mesh 腿的出口靠 `meridian-mesh-seal.timer` 每分钟重新密封一次；枢纽在故障切换循环里每 5 秒一次。

**出口的回程。** 出口对来自枢纽的每条入口各有一张回程表：连接从哪条腿进来（`hub_return_in` 按入接口给连接打标记：主枢纽直连 `0x4d50` / 表 172，Mesh 腿 `0x4d52` / 表 169，有备用枢纽时再加 `0x4d51` / 表 173），回包就从哪条腿回去；表里只有家里的网段指向那条腿和一个黑洞默认，没有指向 WAN 或 `mmesh` 的默认路由。所以枢纽把这个出口放到 Mesh 腿上时，回包不会被送进已经不通的直连腿。只有一条腿的出口（包括只有 Mesh 腿的纯 IPv6 出口）不需要这些表。组解析地址在两条腿的接口上都 DNAT 到本出口的解析器。

**校验（`validate/mesh.go`）。**

| 代码 | 级别 | 含义 |
| --- | --- | --- |
| `mesh_legacy_routes` | 错误 | `cf_mesh` 链路还带着 `mesh_routes`（旧结构）。见「迁移」 |
| `mesh_underlay_prefix` | 错误 | 地址池不是 /16–/30 的 IPv4 网络地址，或不在 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 里 |
| `mesh_underlay_conflict` | 错误 | 地址池与已有规划重叠：`10.66.0.0/16`（含中转前缀）、`100.96.0.0/12`、`169.254.0.0/16`（含 veth 的 `169.254.66.0/30`）、网关和节点的局域网、远程接入设备地址池、手工隧道地址、节点端点、ROS、解析上游、外部 SOCKS 地址。地址池是 IPv4，所以和 `fd66::/48` 不可能相交 |
| `mesh_alloc_invalid` / `mesh_alloc_exhausted` | 错误 | 分配表被改坏（重复、越界），或地址池放不下 |
| `mesh_leg_duplicate` | 错误 | 同一枢纽到同一出口有两条 Mesh 边 |
| `mesh_leg_no_direct` | 错误 | 出口没有同一枢纽的直连 WireGuard（启用、非待命），也不是选了 Mesh 绕行的纯 IPv6 出口 |
| `mesh_leg_unsupported_exit` | 错误 | 出口是中继出口、承载外部 SOCKS 出口、是双栈中继，或是选了别的绕行的纯 IPv6 出口：这一版 Mesh 腿只用于枢纽直连的普通出口 |
| `mesh_leg_fragments` | 警告 | Mesh 路径留给腿的不足 1280（默认就是）：见「Mesh 腿的 MTU」 |
| `mesh_not_standby`、`mesh_bypasses_ix`、`mesh_not_hub_exit` | 错误 | 原有：Mesh 边要标为待命、不能连网关或中继、只能连枢纽和出口（主枢纽或备用枢纽；`mesh_backup_hub_unsupported` 已移除） |

**迁移（旧的 `cf_mesh` 语义）。**

- 带 `mesh_routes` 的链路：校验拒绝（`mesh_legacy_routes`），消息里写明做法——清空 `mesh_routes` 并保存，重新下发枢纽和该出口，再到「Cloudflare → Mesh」重新部署（旧的 Cloudflare 路由在那里撤回，换成新的专用 /32）。拓扑页在这条链路上显示同样的提示和「清空」按钮；`mesh.BuildPlan` 对这种链路也拒绝出计划。
- 不带 `mesh_routes` 的旧 Mesh 边（例如仓库示例）：不需要改文档，但含义变了——出口得到 Mesh 专用地址、链路得到序号（面板升级后第一次启动就把这些序号写回数据库：`store.MigrateAllocations` 现在也处理「已有分配表、但缺某个对象的序号」的情况，所以之后再加别的 Mesh 边不会移动它们；`TestStorePersistsMeshSlotsOfAnOlderTable`）；重新编译后枢纽、这些出口和网关（钳制）都显示待安装。已装过旧版的主机：新的路由脚本会把出口表和组表的默认路由换回 WireGuard 接口，`mesh_underlay` 清掉 main 表里经 sidecar 的旧路由，密封清掉表 170 里复制来的路由和 sidecar 里的回程路由，出口删掉 Mesh 解析用的两条规则和表 171。Cloudflare 上旧部署发布的路由（操作者填的网段、组解析地址的 /128）要靠重新部署 Mesh 撤回。
- 选了 Mesh 绕行的纯 IPv6 出口：以前出口表默认路由指向 `mmesh`，现在是经 Mesh 腿的 WireGuard；它有了隧道解析器，所在的组可以由枢纽切换（示例的 `v6-nat` 从静态变为可切换）。

**验证过的和没有验证的。**

- 生成文本与结构：`internal/compile/mesh_transport_test.go`、`internal/validate/mesh_test.go`、`internal/model`（分配）、`internal/mtu`、`internal/mesh`（计划只含每出口一个 /32）。没有 Mesh 边的拓扑编译结果逐字节不变由 `TestNoMeshCompileUnchangedByMeshTransport` 单独钉住（改动前的编译器生成的摘要，不随金样更新）。
- 带桩的 bash：密封块在有 / 没有 WARP 设备时装的路由和 nft（`TestMeshSealOnlyWireGuardUnderlay`）、`mesh_underlay` 随密封状态的行为（`TestMeshUnderlayRoutesFollowTheSeal`）、组切换拒绝 `mmesh`（`TestHubGroupHopRefusesMeshVeth`）。
- 命名空间（`TestNetnsMeshLeg`，2026-11-16 在本机 Docker Desktop 的 Linux 6.10 内核、Debian 13 用户态的特权容器里通过，见[验收清单](verification.md)）：用编译出的 WireGuard 配置（真实 WireGuard 接口）、路由脚本、nft 和 `meridian-mesh-up.sh`，两个 tun 设备（MTU 1280）之间的转发代替 Cloudflare。它证明的是编译产物在 Linux 上互相配合；**不是真实 Mesh**。
- **没有验证的（真实主机 / 真实 Cloudflare Mesh）**：Mesh 是否把发布的 /32 路由到出口的 Mesh 节点；是否放行两个 Mesh 节点之间到这个地址的 WireGuard UDP；官方镜像里 WARP 设备的名字和类型是否如密封脚本所认（`link/none`）、它自己的策略路由是否会抢在「/32 交给宿主」这条路由之前；`SRCNAT_ENABLED` 与密封里自己的伪装叠加后的实际源地址；外层 IP 分片能否通过；真实路径 MTU；重新密封对真实 sidecar 的影响。这些由主会话先在一个出口（美国）上验证。在那之前 Mesh 数据面保持「未验证」，面板部署显示「已发布」只代表 Cloudflare 路由已发布。

### 同出口双腿质量（R3，实机待验证）

主枢纽的 `meridian-failover.sh` 持续测量每个有 Mesh 腿的出口。测量与选择跟随 `internal/pathquality` 的固定 ping 批次、质量比较、连续达标与冷却框架；远端没有额外控制程序依赖，编译器生成同一决策规则的 bash / awk，合成回归逐轮对照 `pathquality.StepMesh`。每条腿直接绑定自己的 WireGuard 接口，探测对端在该腿上的隧道地址，不经过当前出口表，因此待命腿也有真实读数；同批最多并行测量八个出口，两腿并行，每腿五个小 ICMP，最多三秒。周期是既有枢纽循环的五秒休眠加本轮工作耗时。

`settings.path_quality` 的可用下限丢包 / RTT（默认 150‰ / 400 ms）、切换优势（25%）、切回连续良好时间（120 秒）、最短驻留（120 秒）同时用于这些腿；`mesh_window_samples` 是独立的滚动批次窗口，默认六轮、可设 1–60。面板在拓扑设置内提供这些项，修改后须重新下发枢纽。未指定窗口时不改变旧的 policy JSON，因此没有 Mesh 的拓扑编译仍逐字节不变。

- 常规质量比较使用窗口内的丢包率和按收到的包数加权的 RTT，得分为 `RTT(ms) + loss(‰)`。完整窗口之后，Mesh 达到所需优势且驻留结束才切到 Mesh，微小抖动不切换。
- 当前腿最新一批完全无响应，立即选另一条可达腿，跳过驻留；两条都无响应立即在该出口表的 IPv4 / IPv6 装黑洞。这里的「立即」是完成本批探测后的本轮，不是无延迟的中断检测。
- Mesh 上切回直连：最新一批与窗口平均均低于可用下限、连续达标满切回时间、驻留结束、直连质量未明显差于 Mesh，缺一不可。任何不达标批次清零连续计时。Mesh 完全无响应而直连可达属于紧急恢复，优先恢复连通性。
- 只改这个出口表、其与枢纽无关的解析 /128 路由、当前指向该出口的组表的接口。出口、国家和标记都不变。组仍选择成员 ID，`group_hop` 将该成员接口解析成它当前的腿；当前成员双断时保持该成员并黑洞，不因两条腿同时坏了而选别的出口。已经在别的成员上的组，也不会因这个不可达成员被假定健康而切回它。路由操作失败时对两族尝试黑洞并显式记录失败，绝不选择 WAN。

`/run/meridian/exit-legs/<exit>/` 保存滚动样本、选择、成功应用的接口、每轮报告与最近 32 条切换记录（本机运行期记录，重启清空）。每次切换记录目标腿、原因、时间、两腿窗口丢包 / RTT 和路由操作结果，并写入故障切换服务的标准错误（systemd journal）。`exit-legs/report` 原子汇总；既有固定、只读、总量有界的 `GroupStateCommand` 一并读取。面板严格解析并按主机身份、腿 / 策略计划指纹、心跳和读取时效筛选；旧主机、旧策略或旧读数不显示为当前状态。出口、拓扑与链路日志页共用同一呈现，链路日志页另有枢纽切换历史；它与网关本地采集器的时间线分开，不能把读取时间当作切换时间。

合成状态机、带桩的生成脚本、状态解析 / API / UI 与命名空间回归已编写，本写入步骤未执行测试套件。真实 Cloudflare Mesh 的 UDP 承载、默认阈值在线路上的表现、真实丢包下的切换及恢复均待主会话在美国出口验证。配置与状态回读不替代该签收。

### 沿用主机上已有的 Mesh 节点：检测与预检（N1；实机未验证）

- 面板经已确认指纹的 SSH 运行固定、无参数的只读脚本（`mesh.DetectScript`，动作 `detect`，`POST /api/mesh/detect`，可带 `node_id`）：读主机级 `warp-svc`（容器里的 warp-svc 按 cgroup 排除，不算主机节点）、`warp-cli status / settings / registration show`、`100.96.0.0/12` 内的地址与接口、`ip rule`、带表号的默认路由、Docker / compose、`MemAvailable`。主机输出在主机侧过滤字符集与长度，面板再按正则严格解析；主机出示的指纹与已确认的不一致时结果作废。脚本不写任何东西。
- 结果分三种：`existing_node`（warp-svc 运行且模式为 Mesh/connector 或有 Mesh 地址）、`no_node`、`detect_failed`（SSH 失败、未确认指纹、输出无结束标记）。账户分别报 `matched` / `mismatch` / `unknown`，unknown 写明原因（无 warp-cli、只有组织名、未给出账户 ID、面板未选 Mesh 账户）。只有账户一致、读到 Mesh 地址且与 Meridian 不冲突时才 `reusable`。
- 共存核对：WARP 的规则＝排除标记 `0x100cf` 的规则及查同一张表的规则；与该节点编译结果里 Meridian 的路由表（含 sidecar 表 170）、规则优先级、标记相同，或 WARP 表有默认路由（全局模式），都列为冲突并阻断沿用。面板不改沿用节点的任何 WARP 设置。
- 所有权：结果存在 `<data>/mesh/host-mesh.json`；`origin=existing_host` 的节点永远不是面板所有（不重注册、不重装、撤回不动），`panel_sidecar` 只来自部署记录里本面板创建的远端。
- 无节点的一端只给出一种安装方案：主机级 Linux 节点（`host_connector`，见下面「主机级 Mesh 节点」）。Docker sidecar 不再是安装选项（修订 5）。
- 服务器页「Mesh」列、拓扑节点抽屉、Cloudflare 页 Mesh 部署区显示检测结果。节点预检（`warp_sidecar_conflict`）改为指向这项检测。部署/撤回按检测结果沿用节点见下一节。
- 未验证：warp-cli 各版本的 `settings` / `registration show` 措辞（模式靠关键词识别，账户 ID 行可能不存在），connector 模式下的接口名与规则形态，阈值。

### 主机级 Mesh 节点：Linux connector（修订 5；实机未验证）

所有 Mesh 节点都是主机级的：主机上已有的节点原样沿用（`existing_host`），没有节点的一端由面板安装 Cloudflare 官方 Linux 客户端 `cloudflare-warp` 并注册为 connector（`panel_host`）。不再安装 Docker sidecar、不再有 veth / 密封命名空间、不再发布任何 Cloudflare 路由；两种节点在编译和数据面上是同一种形态：枢纽的 Mesh 腿 Endpoint 直接是出口的 Mesh 地址（`100.96.0.0/12`），外层包只经检测到的 WARP 接口发出。

- **安装计划（检测时给出，部署前确认）。** `mesh.DetectScript` 另读 `/etc/os-release`（ID、发行代号）、`uname -m`、apt、systemd，并从目标主机自己下载一次固定的签名公钥到 `/dev/null` 检查官方源可达性（只看 HTTP 状态）。计划列出固定的源 `https://pkg.cloudflareclient.com/`、公钥 URL、签名公钥指纹、包 `cloudflare-warp`、服务 `warp-svc.service`、写入的文件（keyring、源列表）和内存需求 **160 MB（估计值，未实机测量：warp-svc 常驻约 60–100 MB，apt 约 50 MB）**。阻断条件：源不可达或无法检查（停止，不安装）、不是带发行代号的 Debian/Ubuntu、不是 x86_64/aarch64、没有 apt 或 systemd、内存不足、主机上已有非 Mesh 模式的 WARP、Meridian 用了 WARP 固定的表 65743 或标记 `0x100cf`、签名公钥指纹未配置。`ApplyHostMesh` 对每个要安装的主机（含两端都要安装）要求检测为 `no_node` 且方案可行，并要求请求带 `confirm_install=true`。
- **签名公钥指纹。** 指纹不写死在代码里：它必须先在实机上与 Cloudflare 公布的公钥核对，再由运维在面板进程环境变量 `MERIDIAN_CF_REPO_KEY_FPR`（40 位十六进制）里设置；没有设置时所有安装都被阻断。它不是请求字段。
- **部署阶段。** 计划 → 预检（要安装的主机跑只读的 `connector_preflight`：工具、系统、架构、发行代号未变、无 WARP、内存、源可达、表 65743 未被占用、枢纽已下发 Mesh 底层路由；已是节点的主机先重新跑只读检测（与 health 同一检查，账户必须一致），再跑 `HostPreflightScript`：地址仍在接口上、腿的 MTU / 监听 / Endpoint / 黑洞 / 只经 WARP 接口的路由）→ `cf_node`（每台要安装的主机经 Cloudflare API 建一个 connector 注册）→ `install`（`connector_install`）→ `health`（重新跑只读检测：是节点、地址与接口与安装报告一致、**所有节点（沿用与新装）账户必须 `matched`，不一致或读不到账户 ID 都阻断**、与 Meridian 的表/标记/优先级不冲突、IPv4 与 IPv6 都没有被 WARP 接管的默认路由（WARP 表 65743 或 WARP 规则查的表里的默认路由，或任何表里经 `CloudflareWARP` 的默认路由）；新装节点在 Cloudflare 为 healthy）→ `activate`（把新装节点记成 `panel_host` 检测结果，不改主机）。旧的 `sidecar` / `routes` 阶段只出现在旧部署记录里。
- **安装动作（固定脚本，`mesh.ConnectorInstallScript`）。** 已有 keyring 的主公钥集合必须**正好**是固定指纹（多一把公钥即 `key_set_differs`），否则下载公钥并用 `gpg --show-keys` 校验后才装；已有源列表除注释和空行外必须**正好**是官方那一行（多一行即 `repo_list_differs`）；`apt-get update`、`apt-cache madison` 和 `apt-get install` 用同一组单源选项（只读这一个源列表、`sourceparts=-`）；版本取官方源给出的候选，没有则 `candidate_not_official`，安装 `cloudflare-warp=<该版本>` 并核对装上的就是它（其他源的更高版本不会被选中）；启动 `warp-svc`；`warp-cli connector new` 注册；`connect`；等待 `CloudflareWARP` 上出现 `100.` 地址；IPv4 或 IPv6 任一族在 WARP 表 65743 有默认路由、或有经 `CloudflareWARP` 的默认路由（全隧道）就失败（`global_default_v4/v6`），本次新装部分由补偿按所有权回滚，沿用节点不动。检测脚本两族的策略规则与默认路由都读。令牌只在安装边界注入：从 Cloudflare API 读出后加入脱敏器，写进 0700 临时目录里的 0600 文件（脚本退出时删除），只出现在这一个脚本里，不进拓扑、日志、部署记录、错误回显。注意 `warp-cli connector new "$(cat token)"` 运行的瞬间令牌在该主机的进程参数里可见（主机本地，root 权限主机）。
- **所有权与撤回。** 安装在每次变更（装 keyring、写源列表、`apt-get install`、`systemctl enable --now`、`connector new`）**之前**先在本次运行的备份目录 `/var/lib/meridian/mesh-deploy/<run>/` 写意图标记 `<资源>.intent`，记下变更前的状态（包/keyring/源原本不存在、服务原本是否 enabled/active、原本没有注册；已有注册时安装直接失败 `registration_exists`）；意图标记写不进去安装立即停止（`marker_<资源>`）。变更成功后再写 `<资源>.created` 并以 `MESH_CREATED` 行回报，部署记录的 `OwnedRemote` 记 `kind=host_connector`、`created`、Mesh 地址与接口。撤回与失败补偿运行 `connector_remove`：对有任一标记的资源**检查实际状态**，只撤销本次运行加上的部分——apt 解包后失败、`enable` 成功但启动失败、命令完成后标记写入前进程中断，都能被撤销（包只要还在就 purge；服务只回到意图里记的 enabled/active 状态）。注册最先撤销：`registration delete` 失败（或无法确认已删除）时保留客户端及其依赖（包、服务、源、keyring）和注册标记，跳过后续步骤并报告 `MESH_RESTORE_INCOMPLETE`；找不到 `warp-cli` 绝不当作注册已清除（`MESH_RESTORE_UNVERIFIED registration`），重试一直不完整，直到删除被客户端确认。每撤销一样删一对标记，部分失败后重试从断点继续；主机恢复完成前保留 Cloudflare 注册，之后经 API 删除。安装前已存在的 keyring、源、包从不撤销。沿用的 `existing_host` 节点从不注册、安装或撤回。撤回后面板把该节点的检测结果标为过期（`detect_failed`，需重新检测），不会被当成「已有节点」。
- **两步启用。** 新装节点的 Mesh 地址装好后才知道：本次运行把涉及新装端的腿记为 `pending_provision`；运维重新下发枢纽和出口（编译用新地址）后再部署一次，这次两端都是节点，腿经主机节点预检后记为已发布。
- **编译（无 sidecar）。** 编译时每个还不是节点的 Mesh 端被当作「待安装」（`NodeMeshHost.Pending`）：枢纽的这条腿只装黑洞、nft 丢弃发往占位地址的外层包；出口关闭该腿的 WireGuard 端口。两端都是节点的腿：黑洞 /32 之上只在 WARP 接口 up 时装 `dev <接口>` 路由，nft `oifname != <接口>` 丢弃，接口消失时路由被删、黑洞兜底，不经默认路由泄漏。出口一侧对枢纽的 Mesh 地址做同样的保护（出口的 WireGuard 学到枢纽 Endpoint 后，握手、保活和回包同样只经 WARP 接口）：`meridian-up.sh` 在 WireGuard 起来前装黑洞 /32（metric 32767），`mesh_underlay` 只在接口 up 时装 `dev <接口>` /32，由 `meridian-mesh-underlay.timer`（每 10 秒，出口没有故障切换循环）刷新；nft `mesh_host_output` 丢弃源端口为该腿监听端口、发往枢纽 Mesh 地址、出接口不是 WARP 接口的 UDP（腿有待安装端时直接丢弃）。枢纽还没有 Mesh 地址时出口侧不生成这些内容。地区组表和出口表从不指向 Mesh；双腿按质量切换、滞回、冷却与双断黑洞不变；Mesh 腿 MTU 仍按 1280 减 WireGuard 开销并进入组路径钳制。不含 Mesh 边的拓扑编译结果逐字节不变（含 Mesh 边的示例拓扑的金样随之更新）。
- **旧 sidecar 部署。** 部署记录里 `kind` 为空的远端是旧 sidecar：只能撤回（原恢复脚本），面板提示迁移；同一主机在撤回前不能安装主机级节点。旧编译包里残留的 sidecar 文件在预检里提示（`warp_sidecar_conflict`），重新下发即可去掉。
- **未验证（实机）。** Linux 客户端的 `connector new` 是否把主机注册为 Mesh 节点并只给出 `100.96.0.0/12` 地址而不接管默认路由；接口名是否为 `CloudflareWARP`、策略路由是否为表 65743 / 标记 `0x100cf`；官方源在各主机上的可达性与公钥指纹；内存估计；`apt-get purge` 后的残留。主会话先在 ix（新装）↔ us-west（沿用）验证。

### 沿用已有节点的部署（N2；实机未验证）

面板把 `host-mesh.json` 里 `reusable`、`origin=existing_host`、地址在 `100.96.0.0/12` 内的检测结果叠加到 Mesh 边两端（`mesh.OverlayHostMesh` → 只在内存里的 `Node.MeshHost`，不存进拓扑），编译和部署计划都看它；没有 Mesh 边的拓扑原样返回，编译结果逐字节不变（`TestMeshReuseNoMeshTopologyUnchanged` 与现有黄金摘要）。三种组合（`LegPlan.reuse`）：

- **两端都沿用（`both`）**：不装 sidecar、不建 Cloudflare 节点、不发布路由；枢纽的 WireGuard Endpoint 是出口节点自己的 Mesh 地址。
- **只有出口沿用（`exit`）**：只在枢纽装 sidecar；Endpoint 是出口的 Mesh 地址，不发布路由（枢纽 sidecar 表 170 指向该地址）。
- **只有枢纽沿用（`hub`）**：只在出口装 sidecar 并照旧发布它的专用 /32；枢纽经自己的 Mesh 接口拨这个 /32。
- 混合组合里要安装的一端须在请求里给 `confirm_install: true`，且这台主机的检测是 `no_node` 并推荐 `sidecar_docker`（面板不装主机级 connector）；否则计划阶段失败（`mesh_install_confirm_required` / `mesh_install_not_sidecar` / `mesh_install_undetected`），什么也不创建。`GET /api/mesh` 的 `plan.install_confirm` 列出需要确认的主机。两端都没有节点时保持原 sidecar 流程，不需要确认。

沿用节点的主机上，部署只做只读动作：预检（`DeploymentPreflight` 去掉 `host_warp`、TUN、docker/nsenter 与 mmesh 下一跳检查，另要求该接口上仍有检测到的地址、枢纽路由只经该接口）和健康阶段重跑固定的检测脚本（地址或接口变了即失败）。部署记录 `existing_hosts` 列出这些节点；它们从不进入 `nodes` / `remotes` / `routes`，补偿、失败回滚、单腿和整体撤回都跳过它们（不动注册、不卸载、不改 WARP 设置）。已有本面板 sidecar 的主机改为沿用时，增量部署拒绝，须先撤回原 sidecar。

密封：沿用节点的枢纽为每个对端 Mesh 地址常驻黑洞 /32（metric 32767），只在 WARP 接口 up 时加 `dev <接口>` 的 /32，故障切换循环每轮重放（接口消失时内核删掉 dev 路由，回到黑洞）；nft `mesh_host_output` 丢弃发往对端 Mesh 地址、Mesh 腿端口但出接口不是该接口的 UDP（路由冲突或 WARP 表把地址交给别处时也不经默认路由外泄）。沿用节点的出口只在该接口上、目的为自己 Mesh 地址时接受腿端口，其它接口上丢弃。同出口双腿质量切换和双断黑洞语义不变。MTU 仍按两个 Mesh 地址之间的 Cloudflare Mesh 路径（链路 `mtu`，默认 1280）计算，与端点是 sidecar 还是主机级节点无关；主机 WARP 接口的实际 MTU 没有检测，须实机核对。

未验证：主机级 WARP（connector 模式）是否接受到对端 Mesh 地址的 WireGuard UDP、它自己的策略路由是否先于 main 表接管该地址；ix 与美国出口上的真实 UDP 承载仍由主会话执行。命名空间测试 `TestNetnsMeshLeg` 只覆盖 sidecar 组合，沿用组合目前只有编译与桩测试。

### 面板部署与撤回

`POST /api/mesh/deploy` 的请求只有 `{account?, fail_after?, confirm_install?}`（`confirm_install` 见上一节）：`account` 是存储里的 Cloudflare 账户 ID，省略时用当前选为 Mesh 的账户（都没有时 409 `no_mesh_account`）；给出的账户与当前选择不同时，部署在部署锁内、确认没有绑定中的部署后把它选为 Mesh 账户。响应带 `account: {id, name, account_id, source: "request"|"selected", permission_check}`。计划里每个节点只经它关联的服务器连接（地址、端口、用户、凭据、已确认指纹都从服务器取）；计划本身有效时，任何节点没有服务器、没有凭据或指纹未确认都 409 `servers_not_ready`（附 `not_ready` 列表），一个阶段都不执行。`GET /api/mesh` 另给 `plan_servers`（每个节点的 `server_id`、`ready`、`missing`、将要固定的 `host_key`）和 `mesh_account`。

部署记录（`DataDir/mesh/deploy.json`，schema 4）在开始时为每个计划节点固定 `server_id`、`credential_id`、地址、端口、用户和服务器已确认的指纹，记录账户 `account_id` 和 `account_ref`（存储里的账户 ID）。之后部署的每一步和撤回都只连这些固定目标：连接器要求服务器当前的地址 / 端口 / 用户与固定值一致（否则 `target_changed`），服务器信任的指纹与固定值一致，握手看到的也是这个指纹。

`POST /api/mesh/withdraw` 接受可选的 `{link_id}`（仅已记录的腿 ID）；省略时撤回全部，恢复未完成时省略则重试已持久保存的选择：账户按记录绑定（当前 Mesh 账户的 account id 必须相同，否则 409 `account_mismatch`），主机按记录固定。撤回前先在部署锁内升级旧记录，再检查每台还没恢复的主机：固定的服务器和凭据都还在、服务器仍指向固定的地址。任何一台不满足都 409 `hosts_blocked`，列出原因，**什么也不撤回、不标记任何东西为已移除**。凭据原地轮换不影响撤回（读的是同一 ID 的当前一代）；删除或改指向被存储拒绝（见「服务器、SSH 凭据与 Cloudflare 账户」）。旧请求字段 `private_key_pem`、`trust_new_host`、`nodes`、`ssh_*`（撤回另有 `fail_after`、`account`）一律 400 `field_removed`。

节点撤回与 Mesh 撤回的先后见「撤回与失败后的恢复」→「与 Mesh 的组合」：Mesh 还固定着某个节点的主机时，那个节点不能撤回。

schema 2 → 3 升级（`Deployer.UpgradeJournal`，启动时和每次撤回前运行，可重复）：只处理 `server_id` 为空的固定主机；按「节点当前关联的服务器且地址 / 端口 / 用户一致」→「`migrated_from: node:<ID>` 且一致」→「唯一一台地址 / 端口 / 用户一致的服务器」找服务器，凭据取它当前的凭据；`owned remotes` 里的副本同步更新。找不到的保持为空，撤回时被 `hosts_blocked` 挡住，用户在服务器管理里补上同一台主机后重试即可。已有 `server_id` 的固定值从不被改写；比本程序新的记录被拒绝（`journal_too_new`）。

Mesh 的 Compose 只生成在枢纽和对应出口上。镜像默认是官方的 `cloudflare/mesh:latest`（Cloudflare Mesh 节点，原先的 WARP connector）。要钉版本就在拓扑里写 `mesh_image`，例如 `cloudflare/mesh:2026.10.0` 或带 `@sha256:` 的摘要，不要另起一个不存在的名字。容器要 `NET_ADMIN`、`NET_RAW`、`/dev/net/tun`、`SRCNAT_ENABLED=true`，卷在 `/var/lib/cloudflare-warp`，并且打开 IPv4 转发和 IPv6 `all` / `default` 转发。网络是自己的 `meridian_mesh`，不是 host 网络。令牌放在 `/etc/meridian/mesh.env`（权限 0600），仓库里只有空的示例。

网关的启动脚本和故障切换都不会拉起这个 sidecar；脚本若发现本机有 `192.0.2.88/24` 会直接退出。枢纽的 `group_hop` 拒绝改动表 100、102、150 和 main，在有 Mesh 边的拓扑里还拒绝把任何表指向 `mmesh`。

`mmesh` 是一根以太网 veth（`169.254.66.0/30`，不落在隧道的 `10.66.0.0/16` 里），所以上面的路由都带显式下一跳（`via 169.254.66.2`），两端固定 MAC 和永久邻居项。它上面有什么、密封是什么，见本节开头「Cloudflare Mesh：WireGuard 的底层承载」。历史上的两个错误仍然值得记住：表 170 曾经靠复制 `ip route show dev <warp>` 的输出来填（输出不带 `dev`，链路作用域的路由加不进去；现在不复制，直接写对端地址的路由）；`meridian-mesh-up.sh` 判断 sidecar 内密封块结果的条件曾经是反的（2026-11-13 的命名空间测试暴露，`TestMeshUpSealFollowsSidecarBlock` 锁住）。

部署流程已按 WireGuard 底层承载更新；目前 `mesh.BuildPlan` 已经只为每个出口计划一个专用 /32（`purpose: "wg_underlay"`），并核对出口编译出的 `meridian-mesh-up.sh` 里那一行 `# meridian-mesh-publish <地址>/32 leg=<链路>` 与拓扑的分配一致；健康检查脚本改为检查密封（表 170 的 unreachable、转发链的丢弃规则、没有旧的回程路由）。预检核对已下发密封脚本摘要、WireGuard 接口 MTU、出口 UDP 监听、枢纽内部 Endpoint、/32 黑洞与路由冲突；sidecar 启动后的健康检查再核对出口 mmesh 上的 /32、枢纽经 sidecar 的路由和 WARP 设备实际 MTU 不低于配置的 Mesh 路径 MTU。未部署前不能测得真实 Mesh 路径 MTU，配置默认值仍须实机验证。

**共享资源与逐腿恢复（schema 4）。** `legs` 保存每条腿的两端、内部 /32、接口、UDP 端口、路径 / 设备 / 载荷 MTU 和部署状态；`nodes`、`remotes` 保存每台主机唯一的注册和 sidecar 所有权，`remotes.run_id` 固定原备份目录。已发布的新结构允许增量增加腿，保持原有腿、地址和主机身份不变；同一主机复用原注册、令牌与 sidecar，不再安装第二个容器。新增前必须先重新下发相关节点，确保共享枢纽上的密封脚本包含全部腿；预检对比编译摘要，不偷偷重写共享 sidecar。改变或移除已有腿时先单独撤回该腿，再重新下发、部署。

增量运行在修改前将原发布记录写入 `baseline`。失败或取消时使用独立、有界的恢复上下文，仅补偿本次新增资源，成功后恢复原发布记录。中断后记录保留，面板显示恢复入口；重试撤回读取相同边界。单腿撤回先持久保存 `withdraw_links`，只撤回所选腿的 Cloudflare 路由和不再被其他腿引用的出口资源；最后一条腿撤回时才移除枢纽 sidecar。保留共享枢纽时其编译脚本仍包含被撤回腿的受限 /32 路由，但 Cloudflare 发布已撤回，该腿不再有已发布承载；不改其他腿的封装规则或路由。WireGuard 接口属于节点安装，不由 Mesh 撤回拆除。删除路由失败时保留对应出口主机与注册，恢复主机失败时保留其注册；每步落盘，重启后可重试。旧记录不会自动获得 `underlay` 标志，必须整体撤回再按新结构部署。

这些是实现与合成回归的语义，不是实机验证。对端内部地址上的 WireGuard UDP 能否经真实 Cloudflare Mesh 承载，仍待主会话先用美国出口验证。

## 解锁

出口上的 timer 每 6 小时跑一次；面板也每 6 小时经 `meridian-host` 自己探测一轮（见下文）。流媒体调用独立容器 `lmc999/regioncheck:latest`（AGPL，不链进面板）。官方镜像的入口是 `bash -lc /check.sh`，额外参数进不去，不带参数时会停在交互菜单上，所以探测脚本改用 `--entrypoint /check.sh`，并传 `-R 66`（全部平台）以及 `-M 4` / `-M 6`。镜像名可以用 `regioncheck_image` 换成你核对过的标签。出口脚本里的 AI curl 只做到达性探测（HTTP 状态码），面板只记录、不推动解锁状态机（既不降级也不恢复）。面板探测的检测方法、证据分级和每个适配器的能力声明见 [unlock-methods.md](unlock-methods.md)；所有适配器都只在合成样本上测试过，真实平台待人工核对。结果里如果写了 `Region:`，必须和出口自己的地区一致，否则算失败，避免目录地区被悄悄换掉。

连续两次定时失败才把自动规则改到同池的下一个成员。备成员自己再连续两次定时失败，就换同池里下一个还能解锁的，没有的话标成不可用并回到首选，不改国家。手动测试和健康变化不计入这两次。钉死的手动规则不进这张映射。切回首选需要首选当前健康（面板收到的首选最新结果是成功，且是 30 分钟内收到的），并且从最后一次失败之后的第一次成功起连续成功满 30 分钟；首选任何一次失败都会把这段恢复计时清零。这些时间都用面板自己的时钟，报告里的 `at` 只用于排序和有效期（早于收到时间 1 小时以上即拒绝），不能把冷却提前用完。报告按服务、出口和地址族排序，迟到的旧结果、重复报告和过期报告只记入历史，不改状态；规则见 `internal/unlock/report.go` 和[验收清单](verification.md)「切回判定与报告规则」。映射变化后要在面板里下发，数据面才会换成新的 mark。

面板自己的探测（「解锁 → 面板探测」的立即测试，以及面板每 6 小时的定时）不在面板进程里发流量，也不再运行外部命令（`MERIDIAN_UNLOCK_EXEC` 已删除）：面板经 `meridian-host` 的只读 `/v1/probe` 请求一次「一个出口 + 一个地址族 + 目录表里的服务」，agent 用该出口的 fwmark 和 `lo` 上的中转地址建连（只用 `tcp4` 或 `tcp6`），名字经出口的隧道解析器解析，每条连接先确认路由出口是 Meridian 隧道，访问平台前后都用固定的出口检查确认实际公网地址和地区属于该出口；确认不了就是「探测失败」，不回落到默认出口或另一个地址族，也不当作平台结论。结果经 `unlock.Ingest` 入库，定时记为 `scheduled`、手动记为 `manual`，所有地址族都没有平台结论时记为 `inconclusive`（不计失败次数，但清掉首选的恢复计时）。`activate` / `rollback` 会先取消正在跑的探测，执行期间不接受新探测。细节、限制和仍需人工核实的平台行为见[验收清单](verification.md#面板发起的解锁探测)。

服务组已移除，按服务组的自动选择随之取消：解锁决定只按规则（指向自动地区组的规则，键是规则 ID），旧的服务组状态键被忽略。解锁选路将重新设计（后续任务）。

出口上的定时探测（regioncheck 容器，覆盖面板没有适配器的台湾、日本平台）仍然可用；要把结果送回面板，把口令写进该出口的 `/etc/meridian/unlock-report.env`（0600），URL 固定是编译出来的网关地址，不会跟着这个文件改。出口报告不再推动面板的下一次定时。

## 纯 IPv6 和 v6 入 v4 出

枢纽 `path_v6=false`。只选了绕行名字、没有把链路接上，仍然拒绝保存。

- 双栈中继：枢纽用 v4 WireGuard 连中继，中继用 v6 去拨纯 v6 出口的 `EndpointV6`（示例是 `2001:db8::70`）。内层 ULA 从枢纽的一条 /128 主机路由进中继，再进出口，然后 NAT66。这条路径仍经过 IX。
- Mesh：纯 v6 或「v6 入、v4 出」没有 v4 隧道时，枢纽经一条架在 Mesh 上的 WireGuard 腿到达它（端点是出口的 Mesh 专用 IPv4 地址，见「Mesh」）；出口表的默认路由指向这条腿的 WireGuard 接口，从不指向 `mmesh`。sidecar 不在或未密封时这条腿不通，出口表只剩黑洞，不落到别的默认路由，也不从枢纽的 WAN 出去。
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

带配置的响应有 `Cache-Control: no-store`。`PUT /api/topology` 不改 `remote_access`（以存储里的为准；请求带了不同的值就整个拒绝，409 `independent_resource_changed`），远程接入只经这组接口修改。

### 验证状态

结构测试在 `internal/compile/remote_access_test.go`（守卫按包逐条求值、分类、DNS、入站端口、地址改写、路由、启动顺序、关闭时逐字节相同）、`internal/apply/txn_test.go`（peer 随事务增删、失败补偿回到上一份 peer 集合、关闭功能删除接口、缺密钥在写文件前失败）和 API 测试里。`internal/compile/ula_lan_test.go` 对 ULA 局域网前缀按包求值分类链和守卫（设备 ↔ 家里主机双向放行，`fd66::/48`、中转 /64、相邻的 ULA 和其他 ULA 仍丢弃，规则恰好等于配置的前缀；GUA 前缀时分类链不变）。`TestNetnsULALANHomeAccess`（Linux、root、`MERIDIAN_NETNS_TEST=1`，与 `TestNetnsReloadNoLeak` 共用同一套命名空间搭建）在真实内核上检查同一件事，2026-11-13 跑通过一次（见 `docs/evidence/2026-11-13-debian13/`）。`TestNetnsReloadNoLeak` 加了远程设备命名空间（`mra` 用 veth 代替 WireGuard），还加了地区组切换阶段（G），只能在 Linux 上以 root 运行；这一版的运行日志已于 2026-11-13 归档在 `docs/evidence/2026-11-13-debian13/`（`netns-reload.log`、`netns-ula-lan.log`）；`docs/evidence/2026-11-12-debian13/netns-reload.log` 是加入远程接入之前的版本，不覆盖它。命名空间里的通过记录不等于真实设备拨入的证据，那仍是待人工签收。网关上的 `meridian-verify.sh` 打开时核对 `mra`、对端公钥、守卫入口、DNS、端口、规则、路由和地址改写，关闭时确认没有 `mra` 接口；手机实测和路由器转发是人工签收项，步骤见 [remote-access.md](remote-access.md)。

## 挂在中继出口后面的出口

只能主动拨出、又连不上枢纽（或没有可用入站端口）的出口，可以挂在一台受管的「中继出口」后面（节点字段 `via_exit`）。真实场景：台湾的 NAT 机器经香港机房出口中继。

### 模型与校验

- 挂靠出口 N：`role: exit`、`nat_dial_out: true`、`path_v4: true`、`via_exit: <R>`，**只有一条**启用、非待命的 `direct_wg` 链路，方向 N → R（由 N 拨 R）。不能再有到枢纽的隧道、Mesh 边、WSS、v6 绕行，也不能自己是双栈中继或中继出口。
- 中继出口 R：受管出口，不能是挂靠出口或外部出口（**只支持一层**：更深的嵌套被 `via_exit_depth` 拒绝），要有可拨的端点（`endpoint_v4`，或动态域名 `endpoint_host`）。R 照常连两个枢纽、照常做地区组成员；R 自己也可以是主动拨出的（拨两个枢纽），这时它仍保留给 N 拨的端点（枢纽那边依然没有它的 Endpoint）。
- 校验代码：`via_exit_not_found`、`via_exit_not_exit`、`via_exit_loop`、`via_exit_depth`、`via_exit_external`、`via_exit_unmanaged`、`via_exit_not_dial_out`、`via_exit_family`、`via_exit_workaround`、`via_exit_no_endpoint`、`via_exit_link`、`via_exit_relay_unreachable`，以及沿用的 `nat_endpoint_forbidden` / `nat_keepalive_required`。有备用枢纽时，R 要和两个枢纽各有隧道（`exit_missing_hub_tunnel` 对 R 照常检查，N 豁免）。
- 编号：N 和 N→R 链路照常经 `ReconcileAllocations` 拿槽位，不重排任何已有对象（`TestNestedExternalAllocationStability`）。

### 数据面

- **隧道**：N→R 这条链路 R 在西、N 在东；R 监听，N 带 PersistentKeepalive 拨 R。N 那端的 AllowedIPs 用 `10.66.0.0/16` 代替对端 /32（枢纽的健康探测源地址在 R 后面）；N 的路由把 `10.66.0.0/16` 也指向这条隧道（它唯一的回家路）。
- **出口自己的标记**：枢纽的出口表 `default dev <枢纽→R 的隧道>`；中继出口上 `from <N 的中转地址> lookup <N 的表>`，表里只有 `default dev <R→N 的隧道>` 加兜底黑洞。nft `nested_guard` 再兜一层：N 的中转源只能从 R→N 隧道出去，其余（包括 R 的 WAN）一律丢弃。
- **地区组切到 N**：N 和 R 共用枢纽上的同一块隧道设备，枢纽用下一跳区分：`group_hop` 装 `default via <N 的隧道地址> dev <枢纽→R> onlink`（下一跳不离开枢纽，WireGuard 只看目的地址），枢纽的 `nested_snat` 链对「从这块设备、以这个下一跳离开、源是组中转地址」的包做 SNAT，换成 N 自己的中转地址；R 于是按源把它送进 N。组切回 R 时是普通的设备路由，源不变，从 R 的 WAN 出去。只有拓扑里有这类成员时才渲染这种变体脚本，其它拓扑的脚本逐字节不变（`TestNoNestedNoExternalArtifacts`、单枢纽黄金文件）。
- **回程**：N 的回包回到 R，R 的 `hub_return_in` 已按入口枢纽隧道给连接打了标记，回包按标记从来时的那个枢纽回去（`TestNetnsNestedExit` 的主/备两阶段核对了 R 只在对应枢纽隧道上回包）。
- **健康与切换**：枢纽按 N 的隧道地址经 R 去 ping（`group_step` 用 hop 的设备部分）；R 下线时 N 也 ping 不通，组按原有的滞回切到别的成员，枢纽的实际状态报告写成员名（报告解析下一跳）。
- **解析**：组解析地址的查询被枢纽改成 N 的中转源，R 的 `group_dns` 先放行这些源（不在 R 应答），由 N 自己的解析器回答；有备用枢纽时 N 的独立解析地址（`fd66::54:<i>`）两个枢纽都路由到 R，R 路由到 N，N 在 R→N 隧道上 DNAT 到自己的解析器。解析发生在 N，不在 R。
- **DOCKER-USER**：R 上自动生成枢纽隧道 ↔ R→N 隧道的放行规则。R 开 IPv6 转发（N 的解析查询）。

### 已知边界

- 只有一层；纯 IPv6 的挂靠出口不支持（用双栈中继）；N 不能有 Mesh 腿。
- **部署顺序**：先装 R（新的转发规则），再装 N，再装两个枢纽，最后网关。在 R 装上新配置之前就让枢纽把 N 的流量交给 R，R 的旧配置会把它从 R 的 WAN 伪装出去——这是唯一的顺序依赖，面板的部署说明写明了。
- 没有在真实主机上执行过；真实的台湾 NAT 机器和香港中继出口都没用过。

## 外部 SOCKS 出口

不能安装节点包的设备（真实场景：一台闪存很小的 OpenWrt 路由器，自己用 WireGuard 拨入受管的香港出口，在隧道地址上提供带用户名密码的 SOCKS5，只有 TCP）。用户的决定是沿用它的 SOCKS（「沿用tcp就行」）。面板**不登录**这台设备、**不生成**安装包、**不改**它。

### 模型

```json
{"id": "myext", "name": "马来西亚路由器", "role": "exit", "region": "my", "managed": false,
 "path_v4": true, "egress_v4": true, "egress_v6": false,
 "external": {"carrier": "dc2", "socks_address": "192.0.2.66", "socks_port": 1080,
              "interface": "wg9", "credential_id": "socks-xxxxxxxxxxxx"}}
```

- `carrier`：能到达 SOCKS 的受管出口（不能是挂靠出口或外部出口）；`socks_address:socks_port`：承载节点看到的 SOCKS 地址；`interface`：承载节点上路由这个地址的、**不由面板管理**的接口（那条隧道）；`credential_id`：受限凭据存储里的 SOCKS 凭据（用户名和密码都是秘密，只写不读，不进编译产物、预览、日志、快照、导出；只在承载节点的安装边界注入；被引用时拒绝删除）。
- 它照常有标记槽位，可以进地区组、被规则选中、做解锁探测。校验代码：`external_*`（`external_managed`、`external_has_server`、`external_flags`、`external_endpoint`、`external_v6`、`external_v4`、`external_link`、`external_carrier_missing`、`external_carrier_not_exit`、`external_carrier_nested`、`external_carrier_unmanaged`、`external_socks_address`、`external_socks_port`、`external_interface`、`external_credential_missing`、`external_nested`）。保存拓扑时还核对凭据存在（API 返回 `external_credential_missing`）。
- 承载节点上的地址（都在 lo 上，只经枢纽到承载节点的隧道可达）：服务地址 `10.66.201.<10+i>`（重定向器和 DNS 转发器监听）、健康地址 `10.66.202.<10+i>`（探测成功时才存在）、解析地址 `fd66::55:<i+1>`（这个出口的解析组）。三个网段都保留，不能手工分配给链路。

### 重定向器的选择：gost 3.2.6

固定版本的 wstunnel 11.1.0 有透明代理入口（`tproxy+tcp://`），但它只能把流量送进 wstunnel 自己的服务端，上游代理只支持 HTTP CONNECT，不能当「透明代理 → 带认证的 SOCKS5」客户端。ipt2socks 只能在命令行上传用户名密码（任何本地用户都能从 /proc 读到），redsocks 没有官方静态二进制。选用 **gost 3.2.6**（go-gost/gost，MIT，Go 静态二进制，x86_64 / aarch64 都有官方发布）：`red` 监听/处理器读取 DNAT 前的原目的地址（SO_ORIGINAL_DST），经一条只有一跳（这个出口的 SOCKS5，用户名密码）的链连出去；凭据只在配置文件里（0600，目录 0700）。固定在 `artifacts.lock`（两种架构的二进制摘要和发布包摘要，发布包摘要与官方 checksums.txt 一致），由面板随镜像下发、按架构校验，主机路径 `/usr/local/sbin/meridian-gost`。不写自研代理。

### 轮换 SOCKS 凭据：版本、基线与待下发

（`internal/credentials/socks.go`、`internal/api/socks_version.go`。自动化回归覆盖；真实主机上未验证，见[验收清单](verification.md)。给操作者的兼容约定见 [logging.md](logging.md)「外部 SOCKS 凭据版本：兼容约定」。）

承载节点的 `gost.yaml` 里只有 `__MERIDIAN_SECRET_<凭据 id>-user__` / `-pass__` 两个占位符，轮换（`PUT /api/socks-credentials/{id}/secret`）后不变。只看占位符的话承载节点的文件和整包摘要都不变，它会一直显示「一致」，部署引导跳过它，节点上继续用旧的用户名和密码。做法与 DNS 账户标识相同：每个凭据有一个**版本**（创建时 1，每次轮换加一，就是凭据索引里存秘密文件用的 generation，不由用户名或密码推出），面板编译时（`compileWith` 的最后一步 `stampSOCKS`）把它写进引用这个凭据的 `gost.yaml`，放在文件开头注释块的末尾：

```
# meridian-socks-version: socks-xxxxxxxxxxxx=2 (version of the SOCKS credential: +1 per rotation; not the username or password)
```

一个承载节点带多个外部出口时，这一行按凭据 id 列出各自的版本。版本因此是节点文件的一部分，凡是绑定整包摘要的地方都随之变化：节点状态（「有变更」，原因写明「外部 SOCKS 凭据已轮换（… 已安装版本 1，现在是版本 2）」）、部署引导（排成安装步骤，不是只核对，也不会从服务器记录采纳；计划版本把这些版本也算进去，进行中的引导变成「需要重新计划」）、预检绑定（轮换前审阅的预检带去下发被拒绝，`bundle_changed`）。轮换的回答里 `pending` 列出要重新下发的承载节点。

**基线（升级兼容）。** 外部出口在有版本之前就已经部署。给每个承载节点的配置都加上这一行，升级后所有承载节点的摘要都会变、全部变成待下发，而重新下发只是重写同样的内容。所以凭据存储的索引（`index.json`，0600，只有 id 和计数）里保留一条**基线** `socks_version_baseline`：开始记录版本那一刻已有的每个 SOCKS 凭据的 id 和当时的版本。

- 只取一次：面板启动时的迁移（`MigrateSOCKSVersions`）在没有基线时写入，与索引的其它内容一起原子替换；它和轮换用同一把锁。已经有基线时什么都不做，重启不会重取；之后改名、删除凭据都不改它。
- 写不进去（磁盘只读、空间不足）时：迁移返回错误并写进日志，`GET /api/socks-credentials` 的 `version_tracking` 给出 `ready: false` 和原因，凭据页显示出来；存储保持原样、没有基线，这时**什么都不跟踪，承载节点的配置按原来的字节编译**，状态不变。下次启动再试；在那之前如果有一次新建或轮换成功，基线随那一次写入同一个索引文件（记的是那次变更之前的版本），所以不存在「轮换成功了但没被记到」的情形。
- 版本行只为「被跟踪」的凭据写：基线之后新建的凭据从创建起就跟踪；基线里的凭据要等版本超过基线（升级后第一次轮换）才开始。**基线里、没有再轮换过的凭据，承载节点的配置与上一版逐字节相同**；没有外部 SOCKS 出口的拓扑没有 `gost.yaml`，编译结果不变。

**升级后的表现。**

- 升级、没有轮换：承载节点的摘要不变，仍是「一致」，不进部署计划。但这些节点安装时没有记录用的是哪一版凭据，升级前如果轮换过而没有重新下发，节点上仍是旧值——面板无从得知。所以它们在部署页带一个「凭据版本未记录」的标签（状态接口的 `socks_unrecorded` 和 `note`），凭据页点名列出这些凭据，写明「面板不能证明节点上的用户名和密码就是现在保存的」；这不算待下发。要确认就重新预检并安装一次（节点的整包摘要不变，重写的是同样的文件；预检的变更列表写明这次安装会记下装上去的版本），之后标签消失。
- 升级后轮换：只有引用这个凭据的承载节点变为「有变更」（原因写明「在面板开始记录版本之后轮换过……这个节点上次安装时还没有记录凭据版本」），其余节点（包括用别的凭据的承载节点）摘要不变。
- 降级到旧版本再升级：旧版本不写版本行（曾带版本行的承载节点在旧版本上会显示待下发），它改写索引时也会丢掉基线；再升级时基线重新取一次，降级期间的轮换和以前一样不被发现。

**安装边界。** `postProvision` 在一次加锁里读出该承载节点引用的凭据的用户名、密码和版本（`SOCKSSecretsVersioned`，同一个快照），并核对读到的版本正是这批文件编译时的版本（被跟踪的凭据与版本行一致，其余的没有版本行）：预检之后、读秘密之前发生的轮换在任何脚本运行之前被拒绝（`bundle_changed`）。读完之后（传二进制、脚本运行期间）才发生的轮换不影响这次安装：它装上并记录的是快照里的那一版，装完后节点立刻又是「有变更」（已安装版本 N，现在是 N+1）。

**记录。** 只有安装成功的那个节点记录它实际用的版本（安装记录的 `socks_versions` / `installed_socks_versions`，凭据 id → 版本，没有任何值）；另一个引用同一凭据的承载节点保持自己的记录，仍是待下发，直到它自己装过。从服务器记录采纳（内容已在主机上）时只记录被采纳的摘要能证明的版本，也就是版本行里的那些。

**秘密值。** 版本是计数，不是摘要：用同样的用户名密码再轮换一次，摘要的变化与换成别的值完全一样；两个存储里值不同、计数相同，编译出的承载配置相同。用户名和密码仍然只在 `secrets/` 的 0600 文件和下发脚本里，不进编译结果、差异、预检记录、安装记录、状态接口、日志、快照和演示数据（预检的变更列表对 `gost.yaml` 只写「用户名和密码在安装时注入……装上去的是 … 版本 N」）。

### 数据面（全部在承载节点上）

- 枢纽侧与挂靠出口相同：外部出口的标记表指向枢纽到承载节点的隧道；组切到它时用 `via <健康地址> onlink` 加 `nested_snat` 换成它的中转源。
- 承载节点 nft `ext_dnat`（优先级 -101，先于其它 dstnat 链）：它的 IPv4 TCP → 服务地址上的重定向器；它的组解析查询和独立解析地址 → 它的解析组；**其余 UDP（含 QUIC）和它的全部 IPv6 → 服务/解析地址上没人监听的端口 9**，内核当场回 ICMP 端口不可达（UDP）或 RST（TCP），源地址是原目的地址，客户端立刻回落。没有任何一个包被转发。`ext_reject`（forward）是第二道；它的中转源选中的策略路由表只有黑洞。`ext_local` 让服务地址只能经这条 DNAT 到达。`ext_proxy_out`：承载节点连 SOCKS 只能走配置的接口，接口或路由没了就 RST，不会走默认路由出 WAN。
- 回程：重定向器的回包按承载节点 `hub_return_*` 的连接标记从来的枢纽回去。
- **解析**：发往这个出口的域名在**承载节点**上解析——SmartDNS 里一个单独的监听（解析地址）绑定到组 `ext_<id>`，这个组只有两个上游：经重定向器的 DNS 转发器、**经 SOCKS 用 TCP** 去问 1.1.1.1:53 和 8.8.8.8:53；不在默认组里、不回落承载节点自己的上游、不问国内解析器；SOCKS 不通时名字解析失败。不返回 AAAA。拿到的地址是从 SOCKS 那台设备的方向看到的「海外公共解析器」的答案，不是那台设备自己的解析器的答案——这是 TCP SOCKS 能做到的上限。
- **健康**：承载节点的 `meridian-ext-health.service` 每 10 秒经重定向器做一次 DNS over TCP 查询（根 NS，经 SOCKS 到 1.1.1.1 / 8.8.8.8），8 秒内任一个答了就把健康地址放到 lo 上，否则删掉；变化写进 journal。枢纽 ping 健康地址决定成员上下线（不对 SOCKS 设备发 ICMP）。
- **解锁探测**：照常经真实路径（标记 → 枢纽 → 承载节点 → SOCKS）、经它的解析地址解析；结果标为 `transport: tcp_only`，并列出没测的东西（需要 UDP 的功能）；IPv6 记为「无法测试」而不是通过。结果照常经 `unlock.Ingest`。

### 安装、预检、撤回

- 全部属于承载节点的包：gost 二进制、`meridian-ext-proxy.service`、`meridian-ext-health.service`、`/etc/meridian/ext/gost.yaml`（含秘密，0600）、nft 链、lo 上的三个网段（清单记 `lonet`，失败补偿删本次加的，撤回删网段内全部地址）。下发最后核对两个单元在运行，否则失败并补偿。
- 预检（只读）：清单标记行 `# meridian-ext:` 给出 SOCKS 地址和接口；预检核对接口存在、主路由表把 SOCKS 地址路由到这个接口（`external_interface_missing`），并对 SOCKS 端口做一次 TCP 连接（`external_proxy_unreachable`，不发送任何数据和凭据；凭据是否正确下发后由健康探测确认）。连不上时按**安装身份**判定（`preflight.externalDeployed`）：只有主机自己的安装记录证明同一个外部出口已经部署在这里时是**告警**——写明只有经这个外部出口的流量受影响、这次安装既不会造成也不能修复它；否则（第一次在这台承载节点上启用它，或这次改了它的代理配置）**阻断**。「已经部署」要求：主机清单属于本面板的这个节点和部署、记着这次预检所连的服务器，最近一次下发的 journal 为 `done`（或没有）；清单记着 `meridian-up.sh` 的哈希且主机上的文件仍是这个哈希；这个已装的文件里有同一 ID、同一 SOCKS 地址、端口和承载接口的 `# meridian-ext:` 标记（预检脚本只读地以 `extinstalled` 行报出）。地址、端口或接口变了是新的代理配置。凭据不在判定里（探测不用它，已装的凭据在 0600 文件里无法比较）。没有、读不懂或属于别处的记录、旧版预检报告、安装后被改过的 `meridian-up.sh` 都保持阻断；面板自己的「已安装」记录不能降级它。编译产物不变：标记行的格式与以前相同。
- 部署顺序：先装承载节点，再装两个枢纽，最后网关（同样的顺序依赖：承载节点的旧配置会把这个出口的流量从它的 WAN 伪装出去）。
- 没有在真实主机上执行过；真实的路由器和它的 SOCKS 没用过。

## 动态域名端点

出口可以填 `endpoint_host`（动态域名），拨它的枢纽或挂靠出口用这个名字作 WireGuard Endpoint。WireGuard 只在配置接口时解析一次名字，所以拨号节点装一个 `meridian-endpoint-refresh.timer`（每分钟），对每个按名字拨的对端：最近一次握手超过 150 秒（或从没握手）就 `wg set … endpoint <名字:端口>` 重新应用（即重新解析），每次一条 journal 记录；解析失败保留原端点。只对按名字拨的链路渲染；网关和中继不拨出口，路由和 nft 里不会出现名字。

## 面板信息架构

面板是一个单页应用（`web/src/App.tsx`，hash 路由），侧边栏按用途分组。每一页只用上面各节描述的 API，不在浏览器里做数据面判断；顶栏按 `GET /api/status` 显示 host agent、安装状态和正在运行的任务。

| 分组 | 页面（hash） | 用途 |
| --- | --- | --- |
| — | 概览（`#/`） | 安装状态（`in_sync` / `changed` / `not_installed` / `invalid` / `unknown`）、host agent、未完成事务、名单 / 解锁 / Mesh 任务的最近状态和下一步该做什么 |
| 网络 | 拓扑（`#/topology`） | 节点、链路和网关设置（局域网口、前缀、NAT64 预留）；节点只按 ID 引用服务器 |
| 网络 | 出口（`#/exits`） | 出口节点与地区组：成员顺序、自动 / 手动、`on_failure`、硬约束、有效顺序与原因、默认境外组 |
| 网络 | 分流规则（`#/rules`） | 规则（目标是地区组或显式出口）与解锁映射 |
| 网络 | 名单（`#/lists`） | 名单源策略、立即更新（经 `meridian-host`）、宿主记录的每个名单的来源 / 时间 / 条数；原来页面底部的解析配置现在是下一行的独立页面，这里留一句说明和链接（旧的进入方式 `#/lists/dns`、`#/lists?section=dns` 和裸的 `#dns` 仍然有去处） |
| 解析与日志 | 解析设置（`#/dns`） | 网关和各出口实际怎样解析、出口上游解析器（可按出口单独设置）、DNS 账户标识；未配置加密上游时页面顶部说明现状并给出「设置加密上游」 |
| 解析与日志 | 解析日志（`#/dns-log`） | 网关解析器应答的查询：开关与能力门槛、按设备汇总、查询记录、清空；默认关闭（见「网关解析日志」和 [logging.md](logging.md)） |
| 解析与日志 | 连接日志（`#/conn-log`） | 嗅探转发服务经手的 TCP 连接：设备列表、设备详情、正在转发、清空；名字记录的开关仍在分流规则页的嗅探卡片（见「设备连接日志」） |
| 解析与日志 | 链路日志（`#/link-log`） | 路径和链路的状态变化：当前状态、事件时间线、观测范围和不在记录范围内的内容；没有开关（见「链路日志」） |
| 资源 | 服务器（`#/servers`） | 服务器、发现与确认主机指纹、连接测试、下发 |
| 资源 | 密钥（`#/keys`） | SSH 凭据（密码、导入或生成的私钥）；只写不读 |
| 资源 | Cloudflare（`#/cloudflare`） | Cloudflare 账户、令牌权限检查、Mesh 账户选择、Mesh 部署与撤回 |
| 接入 | 远程接入（`#/remote`） | 端点、端口、地址池、设备（一次性配置与二维码、重新生成、停用）、路由器转发说明、运行状态 |
| 运维 | 部署（`#/deploy`） | 校验、差分、写入数据目录、安装到本机、回滚（含宿主网络或只回滚数据目录）、宿主事务恢复 |
| 运维 | 解锁（`#/unlock`） | 面板探测（立即测试）、结果与证据分级、出口报告 |
| 运维 | 防泄露（`#/leak`） | 四类检查：生成配置核对（只说明配置包含）、隔离 Linux 集成（永远「未执行」）、人工签收（永远「待人工签收」）、已知限制；任何一项都不证明不泄露 |
| 运维 | 验收（`#/acceptance`，`#/acceptance/<id>` 打开某一项） | 实机检查的目录：每项的影响与耗时、只读检查一键执行、演练二次确认并由宿主恢复、人工项的步骤与签收；结果带时间和配置指纹，配置或已安装版本变化后标为过期（见「验收」） |

## 静态文件缓存与升级提示

面板的前端（`web/dist`）由 `internal/api/static.go` 提供，不再用裸 `http.FileServer`（它只给 `Last-Modified`，浏览器按启发式缓存 `index.html`，升级后继续加载旧脚本，直到手动强制刷新）。

- **哈希资源怎么认定**：`vite build` 打开 `build.manifest`，写出 `dist/.vite/manifest.json`。只有清单里列出的、位于 `assets/` 下的文件（各条目的 `file`、`css`、`assets`）回 `Cache-Control: public, max-age=31536000, immutable`。不按文件名猜：没有哈希的文件、上一版留下的旧文件、没有清单时的任何文件都不会是 immutable。清单的修改时间或大小变了就重读（替换 dist 不必重启面板）。
- **其他存在的文件**（`index.html`、`version.json`、图标等）：`Cache-Control: no-cache`，带 `ETag` 和 `Last-Modified`，条件请求未变时回 304。`/` 即 `index.html`。
- **不存在的路径**（包括升级后已删除的旧分块）：404、`Cache-Control: no-store`、纯文本，绝不回 `index.html`。目录（`/` 以外）一律 404，没有目录列表；以 `.` 开头的路径段（如 `.vite/`）不提供。
- **没有 SPA 回退**：面板用哈希路由（`#/…`），片段不发给服务端。
- 只接受 GET/HEAD；`/api/` 路由和口令检查不变；静态文件不需要口令（登录页在有口令之前就要加载）。

**版本提示**：每次生产构建生成一个不透明的随机构建号（`vite.config.ts`），编译进包里（`__MERIDIAN_BUILD__`），同时写成 `dist/version.json`（`{"build":"…"}`，按上面的规则是 `no-cache`，不需要口令，除构建号外不含任何信息）。`web/src/PanelUpdate.tsx` 在页面重新变为可见时、以及可见期间每 5 分钟读一次 `version.json`；与自己的构建号不同就在右下角显示不阻塞的「面板已更新」和「刷新」按钮，发现一次后停止检查。开发服务器、vitest、演示构建没有构建号，检查关闭。

**分块加载失败**：懒加载的页面文件下载失败（典型是升级后旧分块已 404）时，页面位置显示「面板已更新，请刷新」和「刷新」按钮，不是白屏也不是页面错误。两处都只在点击时刷新，不会自动刷新，不会循环。

**限制**：已经在运行旧代码的标签页没有以上任何处理（它的 `index.html` 也是按旧的启发式缓存拿到的），所以**升级到这个版本的第一次仍可能需要手动刷新一次**；之后的升级才完整受益。给操作者的摘要在 [logging.md](logging.md)「面板静态文件的缓存与升级」。

## 三种日志与秘密之间的边界（跨功能回归）

连接日志、解析日志、链路日志各自有「内容不离开自己的接口」的测试（`TestSniffJournalNeverLeaves`、`TestDNSLogNeverLeaves`、`TestLinkLogNeverLeaves`），秘密各自有不出现在别处的测试。把它们放在同一台网关上一起核对的是：

- `internal/api/secrets_seams_test.go` `TestSecretsAndJournalsStayInTheirChannels`：一台带外部 SOCKS 出口、出口加密上游（带账户标识）、嗅探名字记录和解析日志的网关。秘密（轮换前后的 SOCKS 用户名和密码、DNS 账户标识）不在任何视图、编译结果、差异、校验、预检、安装报告、导出、存储的文档、`secrets/` 以外的文件和面板日志里，也不在任何日志接口的回答里；日志内容（查询的名字、链路事件的依据、连接的名字、设备 MAC）只在日志自己的接口里。**每个节点的整包摘要**：读日志、日志增长、设备备注都不改变任何摘要；打开解析日志只改变网关的摘要；SOCKS 轮换只改变承载节点的摘要，改变来自版本计数（用同样的值再轮换一次，摘要再变一次），不来自秘密本身。
- `internal/api/topology_contract_test.go` `TestExportHoldsSwitchesAndReferencesOnly`：导出的文档（`GET /api/topology`）只带开关和引用（解析日志的开关、嗅探设置、凭据 id），没有凭据版本和基线、设备备注、链路日志的任何字段和秘密；原样导入不改变任何节点的摘要，凭据版本、备注和开关都保留。
- `internal/compile`：`TestCompileUnchangedSinceBeforeTheLogs`（五种示例拓扑、嗅探开和关，对照这一轮之前的编译器：没有出口加密上游、解析日志关闭时，除网关多出链路日志的两个文件和验收脚本的一段以外，每个节点的每个文件逐字节相同；把这些设置明写成「关」也一样）、`TestExternalCarrierUnchangedWithoutRotation`（外部出口承载节点的重定向配置、两个单元和健康脚本与有版本之前逐字节相同；编译器自己从不写版本行；解析日志、嗅探、出口上游都够不到它）、`TestJournalsAndExitUpstreamAreIndependent`（不论出口上游是什么，打开解析日志只改网关的同样三个文件、改成同样的字节，链路日志的对象清单在每种组合下相同）、`TestJournalFilesCarryNamesOnly`（两种日志给网关增加的文件里没有拓扑里的任何地址、公钥、凭据 id 或秘密占位符，其它节点没有任何日志相关内容）。
- 演示数据：`TestDemoFixturesLogContentStaysInLogResponses`（合成设备的地址和 MAC、它们查询和连接的名字、链路事件的文字只出现在三种日志自己接口的回答里；解析记录里只有演示局域网地址和 `example` 名字；五种状态——在记录、带缺口、读不到、关闭、没有数据——各有场景），以及原有的 `TestDemoFixturesNoSOCKSMaterial`、`TestDemoFixturesNoDNSAccount`。

面板没有单独的「诊断包」导出：文中说的诊断信息是状态和诊断读数（`GET /api/status`、`/api/host`、`/api/leakcheck`、`/api/sniff` 的诊断部分、部署状态），它们都在上面第一条核对的视图之内。

### Single-hub Mesh leg: unmarked exit DNS (2026-11-16 QA)

Single-hub pinned/static/default exit DNS still queries the exit's `DNSULA`,
without an exit mark or a `TransitV6` bind. Its main-table `/128` now follows
that exit's selected WireGuard leg, with the hub ULA on that leg as preferred
source. This overrides the direct leg's connected `/64`; it does not change
SmartDNS upstream/group selection. The initial routes script installs the same
source and a metric-32767 `/128` blackhole guard. Both-down replaces the live
DNS route with a blackhole; a failed route update attempts to blackhole both
families of the exit table and the DNS destination before publishing state.
There is no DNS fallback to WAN or another exit.

The source matters: WireGuard on the exit accepts `fd66::/48`, and the existing
exit resolver listens on `DNSULA` even when reached through the other interface.
The ingress connection mark is restored by the exit's **route output** chain
for local DNS replies; its return table routes `fd66::/48` through the ingress
leg. No new resolver DNAT or transit-source binding is needed. Dual-hub keeps
its hub-independent `Resolver` address and existing DNAT. External SOCKS exit
DNS keeps its existing resolver selection. Topologies without Mesh do not emit
these additions (the earlier intentional external DNS correction remains).

`TestMeshQualityShellMatchesSelector` replays generated controller commands
with synthetic ping/ip stubs and models the unmarked/unbound IPv6 main lookup
across Mesh, direct recovery, both-down and route failures.
`TestMeshSmartDNSActualTargetAndReturnPath` checks the compiled target/source,
listener, WireGuard acceptance and local reply hooks. These are synthetic/static
checks, not Linux packet evidence. `TestNetnsMeshLeg` additionally sends a real
unmarked, unbound UDP DNS socket request to DNSULA with direct WireGuard broken,
checks kernel main lookup/source over Mesh and switchback, and checks both-down
blackhole/timeouts. It uses namespace stand-ins, not a SmartDNS binary or real
Cloudflare hosts.

Writer sandbox validation is formatting and test-binary compilation only;
neither synthetic tests nor Linux runtime checks were executed for this QA fix.
Outer validation: run the focused compile tests, the existing no-Mesh byte
compatibility tests and dual-hub/external DNS regressions, then on isolated Linux
run `MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run '^TestNetnsMeshLeg$' -v`.
Full Go/frontend suites remain deferred to outer. The three Mesh-bearing
`single_hub_{example,groupdns,remote_access}.golden` fixtures require a targeted
outer refresh of **only** the hub routes and failover script hashes for this
change; no broad golden regeneration was performed in the writer sandbox.

## 局域网到隧道端点

网关 `classify` 链在 `10.66.0.0/16` 与 `fc00::/7` 两条丢弃之后、所有规则和 chnroute 之前，按隧道端点地址（所有隧道两端节点的 `endpoint_v4`、`endpoint_v6`，IX 枢纽的 `ingress_v4`）分三类处理局域网流量（`compile.endpointAccess`，策略在 `validate.ClassifyEndpoint`）：

- **国内直连**（`endpoint_direct4/6`，国内标记 0x64，表 100，经 ROS 本地宽带）：中继的地址、IX 的国内入口。IX 的 SSH 入口是国内中继上的端口转发，因此也走这里。
- **境外经默认组**（`endpoint_tunnel4/6`，默认组标记）：枢纽、出口的地址，IX 的香港出口地址。它们在规则和 chnroute 之前就固定交给默认组，任何列表都不能把它们改判为国内，永远不从本地宽带直出；开启嗅探时 `sniff_mark` 也对它们直接放行，不按域名重判。
- 网关自己直接拨的境外端点（例如经 WSS 直连的备用枢纽 hkb）同样归入境外经默认组：网关自己的外层包（WireGuard 带 fwmark 0x4d72、本机 wstunnel 的 TCP）是本机发出、按 main 表走的，客户端包带默认组标记进入隧道；即使这台对端正承载默认组，内层包的目的地址就是它本身，在它那里交付，不会递归。
- **继续丢弃**（`endpoint_block4/6`，带原因）：默认组不承载该地址族（默认目标不带 IPv6），或默认目标不是出口隧道时的境外端点。地址落在 `10.66.0.0/16` 或 `fc00::/7` 里的端点被前面的规则丢弃。

网关自己的外层包（WireGuard 带 underlay fwmark 0x4d72，wstunnel 的 TCP）是本机发出的，不经过 prerouting 的 `classify`，守卫表也不变，所以外层路径不受影响。面板通过 `GET /api/status` 的 `endpoint_access`（`direct`/`tunnel`/`blocked` 计数和每个端点的 `items[]`：`addr`、`family`、`node_id`、`node_name`、`class`、`reason`）展示；编译结果 `Bundle.EndpointAccess`（`endpoint_access`）是同一份列表。

**为什么以前 hk-a 会被丢弃。** 第一版（d589913，2026-11-12「一期：必经 IX 的 WireGuard 策略路由网关」）起，网关的 `underlay4` 集合就收进**拓扑里每条隧道两端**节点的 `endpoint_v4`，不只是网关自己的对端；4c40697（2026-11-13）又加入 IX 国内入口。因此任何出现在某条启用隧道一端的出口（例如枢纽到 hk-a 的出口链路）从它的链路被启用、配置被编译安装起就在集合里，局域网发往它的流量被 `clients cannot bypass the tunnel by talking to an endpoint` 丢弃。本地 git 历史只能确定代码行为的时间；hk-a 在实机上何时进入集合取决于那条链路何时启用并安装到网关，本地没有这方面的证据。


### 网关到出口的可见延迟

出口页的「网关 → 各出口延迟」和各组成员行展示网关宿主代理实际测得的 TCP 握手平均往返时间，目的地固定为编译器为该出口生成的隧道 DNS 监听器（TCP/53）。每轮每出口最多三次，每次最多两秒，同时最多测两个出口；整轮最多 45 秒。套接字绑定该出口的中转 IPv6 和 fwmark，发送前后核对内核路由必须经过同一受管隧道，拒绝 WAN、路径变化与未安装的源地址。它不询问公共 DNS，不打开网站，也不依赖域名嗅探开关。

`GET /api/exits/latency` 仅读缓存，`POST` 不接收外部指定的地址或命令，按当前已安装拓扑执行一次有界测量，十秒内重复请求复用缓存；更换拓扑后旧结果不再显示为当前结果，超过两分钟标注过期。入口还核对网关配置已同步，安装/回滚会取消测量，与既有解锁探测共用宿主动作互锁。测量不写组健康报告、不改变地区组选择。

这个数值含网关经国内中继、枢纽及当前出口腿的路径，不等于枢纽到出口的单段延迟，不含上游递归解析和平台响应。外部 SOCKS 出口只能测到其承载节点上的解析器，界面明确标注，不能据此宣称代理之后的路径已验证。失败显示未连通/不可测及原因，绝不以零毫秒代替。

面板组健康模型没有接到独立健康报告时显示「未收到组健康报告」，不把它解释为隧道失败。链路日志保留已停用规则目标的历史状态，但当前告警不把明确不在本轮自检范围的历史目标列为正在发生的未知故障；仍在观测范围内而陈旧的承载路径与隧道继续告警。
