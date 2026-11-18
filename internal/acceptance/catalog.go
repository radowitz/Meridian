// Package acceptance is the catalog of real-machine acceptance items and the
// store of their results (the panel's 验收 page; docs/verification.md
// 「验收目录」).
//
// An item says what is checked, which pages point at it, whether carrying it
// out can interrupt traffic and for how long, and how it is carried out:
//
//   - ModeAuto: a read-only check with a fixed action. It never changes the
//     host.
//   - ModeDrill: a fixed host-agent drill that changes the running host for
//     a bounded time and restores it. It needs a second confirmation bound
//     to the action, the target, the configuration fingerprint and an
//     expiry (Confirmations).
//   - ModeManual: steps a person carries out and signs off.
//
// The action of an item is an identifier defined by package hostexec (the
// only place host actions exist); the catalog opens no executor of its own.
//
// The evidence of an item is kept in separate parts that are never merged
// into one "passed": the configuration evidence (the generated text
// contains the rule), the measurement (what a check or a drill observed on
// the host), the human sign-off, and the known limits.
package acceptance

import (
	"fmt"

	"github.com/radowitz/meridian/internal/hostexec"
)

// Modes.
const (
	ModeAuto   = "auto"
	ModeDrill  = "drill"
	ModeManual = "manual"
)

// Parts of the evidence of an item.
const (
	// PartConfig: the generated configuration was read.
	PartConfig = "config"
	// PartMeasured: a fixed check or drill ran on the gateway host.
	PartMeasured = "measured"
	// PartSignoff: a person carried out the steps and recorded the result.
	PartSignoff = "signoff"
)

// Actions the panel carries out itself (no host action is involved), and
// the identifiers of the two host-agent checks that existed before the
// catalog. The drills and the path check are named by hostexec.
const (
	// ActionConfigAudit reads the compiled bundle (verify.CheckBundle).
	ActionConfigAudit = "panel_config_audit"
	// ActionResolverCheck is hostexec's fixed exit resolver check
	// (POST /v1/dns/check, hostexec.DNSCheck).
	ActionResolverCheck = "dns_check"
	// ActionProbe is hostexec's fixed-catalog unlock probe (POST /v1/probe).
	ActionProbe = "probe"
)

// Source is a page that points at an item.
type Source struct {
	// Page is the panel route key ("leak", "deploy", "" for the overview).
	Page  string `json:"page"`
	Label string `json:"label"`
}

// Item is one acceptance item. Everything here is fixed text and fixed
// identifiers; nothing is read from the topology.
type Item struct {
	// ID is stable: results, links and the documentation use it.
	ID    string `json:"id"`
	Title string `json:"title"`
	// What is one sentence on what the item establishes.
	What    string   `json:"what"`
	Sources []Source `json:"sources"`
	// Interrupts: carrying it out may interrupt traffic. Impact is the
	// wording shown; MaxSeconds the bound of that interruption (0: none);
	// Duration how long the whole item takes.
	Interrupts bool   `json:"interrupts"`
	Impact     string `json:"impact"`
	MaxSeconds int    `json:"max_seconds"`
	Duration   string `json:"duration"`
	Mode       string `json:"mode"`
	// Action is the fixed action ("" for a manual item); Validation how its
	// parameters are checked.
	Action     string `json:"action,omitempty"`
	ActionNote string `json:"action_note,omitempty"`
	Validation string `json:"validation,omitempty"`
	// Confirm and Restore describe the second confirmation and the restore
	// of a drill ("" otherwise).
	Confirm string `json:"confirm,omitempty"`
	Restore string `json:"restore,omitempty"`
	// StaleWhen says when a stored result stops counting.
	StaleWhen string `json:"stale_when"`
	// Parts are the evidence parts the item needs before it counts as
	// verified, in the order shown.
	Parts []string `json:"needs"`
	// Proves / NotProves bound what a passed measurement says.
	Proves    string `json:"proves,omitempty"`
	NotProves string `json:"not_proves,omitempty"`
	// Steps are the human steps (the sign-off part); EvidenceSource where
	// their evidence comes from and is archived.
	Steps          []string `json:"steps,omitempty"`
	EvidenceSource string   `json:"evidence_source,omitempty"`
	// ConfigChecks are verify item ids whose result is this item's
	// configuration evidence; LeakItems the verify items (integration,
	// human) this item carries out; Limits verify limitation ids shown
	// with it.
	ConfigChecks []string `json:"config_checks,omitempty"`
	LeakItems    []string `json:"leak_items,omitempty"`
	Limits       []string `json:"limits,omitempty"`
	// Deferred is set for an item that this round deliberately does not
	// carry out; the text says so wherever the item is shown.
	Deferred string `json:"deferred,omitempty"`
}

// Needs reports whether part is one of the item's parts.
func (it Item) Needs(part string) bool {
	for _, p := range it.Parts {
		if p == part {
			return true
		}
	}
	return false
}

const (
	staleConfig = "拓扑改动使生成的配置变化，或网关重新安装（已安装版本变化）后，旧结果保留但标为过期"
	staleRun    = "网关重新安装（已安装版本变化）或拓扑改动使生成的配置变化后，旧结果保留但标为过期；要重新执行"
	staleSign   = "网关重新安装或配置变化后，旧签收保留但标为过期；要重新做一遍并签收"

	drillConfirm = "二次确认。确认绑定这一个动作、这一个目标、当时的配置指纹，并在 %d 秒后失效；指纹变了或过期就要重新确认"
	drillRestore = "变更前在宿主上记录原状态、恢复计划和截止时间；到时、取消、失败、面板或浏览器断开都由宿主自己恢复，宿主代理重启后先恢复再允许别的变更。恢复后逐项核对 nft 表与规则、策略规则、路由表、接口和上游记录与原状态一致才算恢复；核对不过保持阻断并列出差异，可以重试"
)

// ConfirmTTLSeconds is how long a drill confirmation is valid.
const ConfirmTTLSeconds = 120

var (
	srcLeak     = Source{Page: "leak", Label: "防泄露"}
	srcDeploy   = Source{Page: "deploy", Label: "部署"}
	srcOverview = Source{Page: "", Label: "概览"}
	srcDNS      = Source{Page: "dns", Label: "解析设置"}
	srcTopology = Source{Page: "topology", Label: "拓扑"}
	srcCF       = Source{Page: "cloudflare", Label: "Cloudflare（Mesh 部署）"}
	srcUnlock   = Source{Page: "unlock", Label: "解锁"}
	srcRemote   = Source{Page: "remote", Label: "远程接入"}
)

var catalog = []Item{
	{
		ID: "config-audit", Title: "生成配置核对",
		What:    "编译出来的网关配置里包含防泄露需要的规则。",
		Sources: []Source{srcLeak, srcDeploy},
		Impact:  "不打断", Duration: "约 10 秒", Mode: ModeAuto,
		Action: ActionConfigAudit, ActionNote: "面板读自己编译出来的配置文本，不调用任何宿主动作",
		Validation: "没有参数",
		StaleWhen:  staleConfig, Parts: []string{PartConfig},
		Proves:    "生成的配置文本包含这些规则",
		NotProves: "不能证明规则已经加载到网关，更不能证明实机不泄露：这一项通过不等于实机通过",
	},
	{
		ID: "gateway-health", Title: "网关数据面健康",
		What:    "已安装的单元在运行，受管接口存在，两张 nft 表已加载。",
		Sources: []Source{srcDeploy, srcOverview},
		Impact:  "不打断", Duration: "约 30 秒", Mode: ModeAuto,
		Action: hostexec.ActionHealth, ActionNote: "宿主代理的 health 动作：只读，采样两次",
		Validation: "资源名只取自已安装清单里的单元、接口和 nft 表，逐个按受管名字的格式校验",
		StaleWhen:  staleRun, Parts: []string{PartMeasured},
		Proves:    "检查那一刻这些单元、接口和表都在",
		NotProves: "不说明流量走对了出口，也不说明不泄露",
	},
	{
		ID: "ipv6-firewall-reload", Title: "防火墙重载时 IPv6 不外泄",
		What:       "重新加载防火墙的过程中兜底表一直在，局域网的 IPv6 不会在规则换装的间隙经路由器出去。",
		Sources:    []Source{srcLeak},
		Interrupts: true, Impact: "可能短断", MaxSeconds: 120, Duration: "最多 120 秒", Mode: ModeDrill,
		Action: hostexec.DrillFirewallReload, ActionNote: "宿主代理重启 meridian.service（与安装时相同的 meridian-up.sh），期间按固定间隔采样两张表和转发开关",
		Validation: "没有目标和时长参数；网关必须已安装、数据面在运行、没有未完成的安装事务",
		Confirm:    fmt.Sprintf(drillConfirm, ConfirmTTLSeconds), Restore: drillRestore,
		StaleWhen: staleRun, Parts: []string{PartConfig, PartMeasured, PartSignoff},
		Proves:    "宿主上每次采样都看到兜底表在",
		NotProves: "采样有间隔，也看不到客户端的包：客户端有没有外泄要另做下面的人工步骤",
		Steps: []string{
			"在测试机上持续访问一个只有 IPv6 的境外地址（例如持续 ping6 或 curl -6），同时在路由器 WAN 口抓 IPv6 包",
			"在这一页执行「防火墙重载」演练，等它恢复",
			"检查抓包：重载期间没有这台测试机发往境外的 IPv6 包经家宽出去；测试机上的访问可以短暂中断，但不能改走家宽",
			"把抓包和时间存档，回到这里签收",
		},
		EvidenceSource: "路由器 WAN 口的抓包文件与演练记录的时间；存档位置按 docs/verification.md「已存档的执行记录」",
		ConfigChecks:   []string{"no_flush", "boot_guard_matches", "chnroute_readd", "fail_closed"},
		LeakItems:      []string{"netns_reload_no_leak"},
	},
	{
		ID: "dns-leak", Title: "DNS 不泄漏",
		What:    "境外名字经隧道由出口解析，测试机的 DNS 不出现在家宽上。",
		Sources: []Source{srcDNS, srcLeak},
		Impact:  "不打断", Duration: "约 2–5 分钟", Mode: ModeAuto,
		Action: ActionResolverCheck, ActionNote: "宿主代理向每个出口的隧道解析器问一个固定的名字（example.com）",
		Validation: "出口只取自拓扑里可检查的受管出口，解析器地址由编译结果给出，宿主代理只接受已安装的 SmartDNS 配置里转发到的地址；每次最多 16 个出口",
		StaleWhen:  staleRun, Parts: []string{PartConfig, PartMeasured, PartSignoff},
		Proves:    "出口的隧道解析器经隧道回答了",
		NotProves: "解析器能回答不等于没有泄漏：客户端自己的 DNS 走哪里，只有下面的人工步骤能看到",
		Steps: []string{
			"测试机的网关、DNS 和 IPv6 默认路由都指向网关",
			"在测试机上打开 dnsleaktest 与 ipleak 做扩展测试：v4/v6 的 DNS 与出口都属于当前出口地区，没有运营商的解析器",
			"同时在路由器 WAN 口抓 53 / 853：没有这台测试机发出的境外查询",
			"「未列名单的域名也问国内 DNS」打开时结果里会同时出现国内解析器，签收时写明这个设置",
			"截图和抓包存档，回到这里签收",
		},
		EvidenceSource: "测试机的截图与路由器 WAN 口抓包",
		ConfigChecks:   []string{"dns_hijack_53", "dns_hijack_853", "dns_input_drop", "dns_aaaa_policy", "unlisted_domestic_dns"},
		LeakItems:      []string{"dnsleak_client", "smartdns_runtime"},
		Limits:         []string{"doh_not_exhaustive"},
	},
	{
		ID: "mesh-e2e", Title: "Mesh 端到端",
		What:    "Mesh 承载同一出口的 WireGuard 腿，最终公网地址与直连腿相同。",
		Sources: []Source{srcCF, srcTopology},
		Impact:  "不打断", Duration: "约 1–3 分钟", Mode: ModeAuto,
		Action: hostexec.CheckTunnelPaths, ActionNote: "宿主代理只读地读网关各隧道接口的状态、握手时间和收发字节（不返回任何密钥），面板再读本地的 Mesh 部署记录",
		Validation: fmt.Sprintf("接口只取自已安装清单里的隧道接口，逐个按受管名字校验并且必须在宿主的受管记录里；每次最多 %d 个", hostexec.MaxPathInterfaces),
		StaleWhen:  staleRun, Parts: []string{PartConfig, PartMeasured, PartSignoff},
		Proves:    "网关一侧的隧道在握手，Mesh 节点部署记录完整",
		NotProves: "人工断腿与双断检查会打断该出口的测试流量，须在维护窗口执行并恢复；Mesh 在枢纽和出口之间，网关上看不到它的转发；节点安装成功不代表 Mesh 承载可用。跨端的转发要做下面的人工步骤",
		Steps: []string{
			"主会话先在 ix ↔ us-west 验证：us-west 沿用已有主机级节点，ix 由面板新装主机级 Linux 节点（cloudflare-warp connector）；不装 sidecar、不发布路由",
			"沿用已有 Mesh 节点的一端（来源 existing_host）：不注册、不安装；Endpoint 为对端 Mesh 地址；外层包只经该主机的 WARP 接口发往对端 Mesh 地址，拔掉该接口或改坏路由后外层包被黑洞、nft 丢弃，不经主机默认路由；撤回后该节点的注册与设置原样保留",
			"面板新装的一端（panel-owned）：预检确认官方源、签名公钥指纹、包、服务与估计内存；安装后读到 100.96.0.0/12 地址和接口，WARP 表没有默认路由；重新下发枢纽和出口后再部署一次；撤回只移除本次创建的注册、包、源和服务",
			"确认枢纽到对端 Mesh 地址的 WireGuard UDP 能经 Mesh 握手；没有出口表或地区组表的默认路由指向 Mesh",
			"按 docs/verification.md 的实机步骤让测试连接经 Mesh 腿，核对最终公网地址与同一出口直连腿一致；同时核对组解析仍由该出口应答",
			"在出口、拓扑与链路日志页读取双腿质量：模拟直连丢包 / 高时延、完全断开、冷却后切回和双断，核对当前腿、切换原因与两腿读数；出口和国家不变，双断为黑洞；恢复原路由并核对；Mesh 断开时不得回落到枢纽 WAN。抓包和结果存档后签收；路由发布不算通过",
		},
		EvidenceSource: "枢纽与出口的 WireGuard 握手、外层 UDP 抓包、同一出口公网地址对比及恢复记录；真实 Mesh 承载待主会话验证",
		ConfigChecks:   []string{"mesh_not_on_gateway", "mesh_not_ix", "mesh_nexthop"},
		LeakItems:      []string{"mesh_e2e_forwarding", "mesh_veth_forwarding"},
	},
	{
		ID: "relay-removal", Title: "中继剔除",
		What:       "一台中继不通时它被剔除，其余中继接住流量，上网不中断。",
		Sources:    []Source{srcTopology, srcDeploy},
		Interrupts: true, Impact: "可能短断", MaxSeconds: 180, Duration: "最多 180 秒，另加约 3–5 分钟等待恢复核对", Mode: ModeDrill,
		Action: hostexec.DrillRelayIsolation, ActionNote: "宿主代理在自己的一张 nft 表里丢弃本机发往这台中继隧道端点的包，观察上游记录，到时删除",
		Validation: fmt.Sprintf("目标只能是上游记录里正在分担的一台中继，它的隧道接口必须在已安装清单和宿主的受管记录里，并且还有另一台在分担；被隔离的地址由宿主从隧道端点读出，不是参数；时长 %d–%d 秒", hostexec.DrillMinBlock, hostexec.DrillMaxBlock),
		Confirm:    fmt.Sprintf(drillConfirm, ConfirmTTLSeconds), Restore: drillRestore,
		StaleWhen: staleRun, Parts: []string{PartMeasured},
		Proves:    "隔离期间这台中继被剔除，承载路径一直是主链路，之后回到原来的状态和权重",
		NotProves: "不说明真实故障（例如只丢一部分包）时的表现；经本机 WSS 承载的隧道端点在回环上，不能这样隔离",
	},
	{
		ID: "hub-failover", Title: "主链路切到备用枢纽",
		What:       "主枢纽这条路不通时网关切到备用枢纽，恢复后切回来。",
		Sources:    []Source{srcTopology, srcDeploy},
		Interrupts: true, Impact: "可能短断", MaxSeconds: 180, Duration: "最多 180 秒，另加约 3–5 分钟等待切回核对", Mode: ModeDrill,
		Action: hostexec.DrillHubIsolation, ActionNote: "宿主代理在自己的一张 nft 表里丢弃本机发往主链路全部中继隧道端点的包，观察是否切到备用枢纽，到时删除",
		Validation: fmt.Sprintf("目标必须正好是上游记录里主链路的全部中继隧道，备用枢纽的隧道必须在已安装清单里并且当前可用（否则拒绝，不会制造全断）；被隔离的地址由宿主读出，不是参数；时长 %d–%d 秒", hostexec.DrillMinBlock, hostexec.DrillMaxBlock),
		Confirm:    fmt.Sprintf(drillConfirm, ConfirmTTLSeconds), Restore: drillRestore,
		StaleWhen: staleRun, Parts: []string{PartMeasured},
		Proves:    "隔离期间承载路径切到备用枢纽，之后回到主链路和原来的权重",
		NotProves: "切换期间会有一段不通（实测约 20 秒）；不说明主枢纽本身故障而中继还通时的表现",
	},
	{
		ID: "unlock", Title: "解锁检测",
		What:    "各出口上流媒体与 AI 平台的检测结果。",
		Sources: []Source{srcUnlock},
		Impact:  "不打断", Duration: "约 1–5 分钟", Mode: ModeAuto,
		Action: ActionProbe, ActionNote: "宿主代理的只读探测：固定目录里的平台，经所选出口发出",
		Validation: "平台只能是探测目录里的 id，出口只能是拓扑里的出口；数量受探测任务自己的上限约束",
		StaleWhen:  staleRun, Parts: []string{PartMeasured, PartSignoff},
		Proves:    "探测当时各平台返回的信号（分级见 docs/unlock-methods.md）",
		NotProves: "判定规则来自公开方法和合成数据，不等于真实平台上能看：每个平台要有人在真实出口上核对一次",
		Steps: []string{
			"对每个用到的平台，在真实出口上按 docs/unlock-methods.md 的方法核对一次（能否打开、地区是否正确）",
			"外部 SOCKS 出口先重新下发承载节点的探测 DNS 例外；解析成功、能到达平台都不等于解锁通过",
			"与这一页的探测结果对照，记下不一致的平台",
			"存档后回到这里签收",
		},
		EvidenceSource: "真实设备上的截图；面板「解锁」页的探测结果",
		LeakItems:      []string{"unlock_platform_verdicts"},
	},
	{
		ID: "remote-access", Title: "远程接入（手机蜂窝拨入）",
		What:    "手机在蜂窝网络下能拨回家，流量按所选模式走。",
		Sources: []Source{srcRemote},
		Impact:  "不打断现有上网", Duration: "约 5–10 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartConfig, PartSignoff},
		NotProves: "面板看不到手机一侧，也从不修改路由器",
		Steps: []string{
			"只读查看路由器上 UDP 监听端口到网关的转发规则并存档；确认公网地址或 DDNS 指向家里",
			"手机关掉 Wi-Fi，用蜂窝网络导入「全部流量」配置并连接：握手成功，ipleak / dnsleaktest 显示出口地区、没有运营商 DNS，面板地址和其他远程设备都不通",
			"换「仅回家」配置：家里的局域网主机和网关 DNS 可达，其余流量仍走运营商（签收时写明）",
			"隧道内 IPv6 可用；端点有 AAAA 记录时从支持 IPv6 的网络再拨一次",
			"截图存档，回到这里签收",
		},
		EvidenceSource: "手机截图、路由器转发规则的只读输出；面板「远程接入」页的握手时间",
		ConfigChecks:   []string{"remote_access_config"},
		LeakItems:      []string{"remote_phone_full", "remote_phone_home", "remote_router_forward", "remote_ipv6"},
		Limits:         []string{"remote_home_mode"},
		Deferred:       "本轮没有执行：远程接入实测暂不做，这一项保持未验证，不显示为通过",
	},
	{
		ID: "tunnel-cut", Title: "断隧道时不回落到路由器",
		What:    "出口隧道断开时境外流量不通，而不是改走家宽。",
		Sources: []Source{srcLeak},
		Impact:  "会打断测试机的境外访问（人工操作）", Duration: "约 10 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartConfig, PartSignoff},
		NotProves: "面板不执行这一项，也看不到路由器上的包",
		Steps: []string{
			"测试机持续访问境外站点",
			"停掉出口隧道，在网关局域网口和路由器 WAN 口同时抓包",
			"境外流量不出现在路由器 / 家宽上，测试机得到的是不通而不是家宽出口",
			"恢复隧道，抓包存档，回到这里签收",
		},
		EvidenceSource: "网关局域网口与路由器 WAN 口的抓包",
		ConfigChecks:   []string{"fail_closed", "no_iif_unreachable", "group_marks_routed", "ula_not_via_ros"},
		LeakItems:      []string{"tunnel_cut"},
	},
	{
		ID: "webrtc", Title: "WebRTC 的 srflx 是出口地址",
		What:    "浏览器的 WebRTC 反射候选是出口地址，不是家宽地址。",
		Sources: []Source{srcLeak},
		Impact:  "不打断", Duration: "约 5 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartSignoff},
		NotProves: "host 候选里出现运营商的 IPv6 全局地址是已知限制，不算失败",
		Steps: []string{
			"在测试机浏览器打开 browserleaks 或 ipleak 的 WebRTC 测试",
			"srflx / 中继候选必须是出口地址",
			"截图存档，回到这里签收",
		},
		EvidenceSource: "测试机浏览器的截图",
		LeakItems:      []string{"webrtc_srflx"},
		Limits:         []string{"webrtc_host_gua"},
	},
	{
		ID: "router-ula", Title: "路由器上的 ULA 黑洞",
		What:    "路由器上有 fd00::/8 的黑洞路由，隧道 ULA 不会被它转走。",
		Sources: []Source{srcLeak},
		Impact:  "不打断", Duration: "约 5 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartSignoff},
		NotProves: "面板从不连接或修改路由器；有没有这条路由都不改变 Meridian 自己的路由",
		Steps: []string{
			"只查看，不改路由器：/ipv6 route print where blackhole and (dst-address=fd00::/8 or dst-address=fc00::/7)",
			"或在网关上带 MERIDIAN_ROS_SSH 运行 meridian-verify.sh，让脚本执行这条只读命令并保存输出",
			"输出存档，回到这里签收",
		},
		EvidenceSource: "路由器只读命令的输出，或 meridian-verify.sh 的证据目录",
		LeakItems:      []string{"ros_ula_blackhole"},
	},
	{
		ID: "exit-switch", Title: "真实出口与地区组切换",
		What:    "地区组当前出口失效时流量换到下一个成员，切换期间不经家宽出去。",
		Sources: []Source{srcLeak},
		Impact:  "会打断该地区组的流量（人工操作）", Duration: "约 15 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartSignoff},
		NotProves: "面板和命名空间测试都没有真实出口",
		Steps: []string{
			"在真实隧道握手的前提下，从测试机确认每个地区组当前出口的公网地址",
			"让组内当前出口失效（或手动切换），确认流量换到下一个成员",
			"切换期间路由器 WAN 口没有这台测试机的境外包",
			"存档后回到这里签收",
		},
		EvidenceSource: "测试机看到的出口地址与路由器 WAN 口抓包",
		LeakItems:      []string{"real_exit_switch"},
	},
	{
		ID: "redirect-capture", Title: "同网段 ICMP 重定向抓包",
		What:    "网关和路由器没有用重定向把测试机引回路由器。",
		Sources: []Source{srcLeak},
		Impact:  "不打断", Duration: "约 10 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartConfig, PartSignoff},
		NotProves: "IPv6 没有对应的内核开关，只能靠抓包确认",
		Steps: []string{
			"在测试机上抓 IPv4 和 IPv6 的 ICMP 重定向",
			"访问境内外站点各一段时间，确认没有把下一跳改成路由器的重定向生效",
			"抓包存档，回到这里签收",
		},
		EvidenceSource: "测试机上的抓包",
		ConfigChecks:   []string{"send_redirects", "accept_redirects", "redirect_sysctl"},
		LeakItems:      []string{"redirect_on_wire"},
	},
	{
		ID: "sniff-client", Title: "按域名嗅探的真实设备表现",
		What:    "开启嗅探后，用自己加密 DNS 的设备也按域名分流；服务停掉时连接失败而不是绕过。",
		Sources: []Source{srcLeak},
		Impact:  "停服务的一步会打断网页连接（人工操作）", Duration: "约 15 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartSignoff},
		NotProves: "只在开启按域名嗅探时适用",
		Steps: []string{
			"用一台用自己加密 DNS 的设备访问两个按规则去不同地区、共用 CDN 地址的站点，确认各自的出口地区",
			"停掉 meridian-sniff.service，确认网页连接失败而不是绕过",
			"面板「连接日志」的决策与实际一致；存档后回到这里签收",
		},
		EvidenceSource: "设备截图与面板连接日志",
		LeakItems:      []string{"sniff_real_client"},
		Limits:         []string{"sniff_ech_residual", "sniff_relay_drain"},
	},
	integration("integration-gateway-verify", "网关上运行 meridian-verify.sh", "gateway_verify_script",
		"在网关上 sudo /usr/local/sbin/meridian-verify.sh",
		"缺 nft 或缺任何一张表都会失败；最后一行 meridian-verify-local-ok 只代表本机检查通过，不是防泄露结论",
		"脚本的证据目录"),
	integration("integration-netns-reload", "持续流量下 nft 重载不漏（命名空间测试）", "netns_reload_no_leak",
		"在隔离的 Linux 主机上 sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run 'TestNetnsReloadNoLeak|TestNetnsULALANHomeAccess'",
		"跳过（非 root / 非 Linux）不是通过", "go test 的完整日志"),
	integration("integration-smartdns", "SmartDNS 容器启动并写入 nftset", "smartdns_runtime",
		"sudo bash deploy/verify-smartdns.sh", "最后一行应是 meridian-smartdns-verify-ok", "脚本日志"),
	integration("integration-mesh-veth", "Mesh WireGuard 腿（命名空间）", "mesh_veth_forwarding",
		"sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run '^TestNetnsMeshLeg$' -v", "必须执行而非跳过；同一出口直连与 Mesh 腿公网地址一致，断开 Mesh 不泄漏；替身 Mesh 不证明真实 Cloudflare UDP 承载", "完整测试日志"),
	integration("integration-host-exec", "宿主执行、开机兜底与运行态回滚", "host_exec_runtime",
		"sudo bash deploy/verify-host-exec.sh，重启后再加 --boot 跑一次", "两次都要有日志", "脚本日志"),
	integration("integration-lists-update", "名单更新与重载后国内地址仍在", "lists_update_runtime",
		"在网关上更新一次名单，重新安装或重启 meridian.service，再运行 meridian-verify.sh",
		"chnroute_loaded 与 geosite_cn 应为 PASS", "meridian-verify.sh 的证据目录"),
	integration("integration-netns-sniff", "按域名嗅探的命名空间测试", "netns_sniff",
		"sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run 'TestNetnsSniff' -v",
		"只在开启按域名嗅探时适用", "go test 的完整日志"),
}

// integration is an isolated-Linux item: a person runs a fixed command on a
// Linux host and archives the log. The panel never runs it.
func integration(id, title, leakID, command, check, evidence string) Item {
	return Item{
		ID: id, Title: title,
		What:    "隔离 Linux 集成证据：命令真的运行过并存档了日志。",
		Sources: []Source{srcLeak},
		Impact:  "不打断（在隔离主机或网关上人工运行）", Duration: "约 5–15 分钟", Mode: ModeManual,
		StaleWhen: staleSign, Parts: []string{PartSignoff},
		NotProves: "面板不代跑，也不读存档：没有存档的日志就是未执行",
		Steps: []string{
			command,
			check,
			"把完整日志存档，回到这里签收并写下存档位置",
		},
		EvidenceSource: evidence,
		LeakItems:      []string{leakID},
	}
}

// Catalog returns every item, in display order. The slice is a copy.
func Catalog() []Item {
	out := make([]Item, len(catalog))
	copy(out, catalog)
	return out
}

// Lookup finds an item by id.
func Lookup(id string) (Item, bool) {
	for _, it := range catalog {
		if it.ID == id {
			return it, true
		}
	}
	return Item{}, false
}

// ForLeakItem returns the acceptance item that carries out a leak-checklist
// (verify) item, so a row of the checklist can link to it. A manual item
// dedicated to that one leak item wins over a broader item that lists it
// as related evidence.
func ForLeakItem(leakID string) (Item, bool) {
	var related *Item
	for i := range catalog {
		it := catalog[i]
		for _, l := range it.LeakItems {
			if l != leakID {
				continue
			}
			if it.Mode == ModeManual && len(it.LeakItems) == 1 {
				return it, true
			}
			if related == nil {
				related = &catalog[i]
			}
		}
	}
	if related != nil {
		return *related, true
	}
	return Item{}, false
}
