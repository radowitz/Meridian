// Package verify is the panel's leak checklist.
//
// Every item carries a Scope that says what kind of evidence could ever
// back it, and the status never claims more than that evidence:
//
//   - ScopeAutomated: automated regression. CheckBundle reads the generated
//     configuration (and go test runs the same code). Pass means "the
//     generated text contains this rule". It does not show the rule is
//     loaded on a host, and it is never evidence that nothing leaks.
//   - ScopeIntegration: isolated Linux integration evidence (netns test,
//     deploy/verify-*.sh, meridian-verify.sh on the gateway). The panel does
//     not run these, so they are always Unknown here until someone runs them
//     and archives the log.
//   - ScopeHuman: human sign-off on a real client, on ROS, with a tunnel cut
//     or a packet capture. Always PendingSignoff here.
//   - ScopeLimitation: documented limits, status KnownLimitation.
package verify

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

const (
	Pass            = "pass"
	Fail            = "fail"
	KnownLimitation = "known_limitation"
	Skip            = "skip"
	// Unknown: the check exists but was not executed; no result.
	Unknown = "unknown"
	// PendingSignoff: needs a human with a real client, ROS or a capture.
	PendingSignoff = "pending_signoff"
)

const (
	ScopeAutomated   = "automated"
	ScopeIntegration = "integration"
	ScopeHuman       = "human"
	ScopeLimitation  = "limitation"
)

// Item is one checklist row.
type Item struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Scope  string `json:"scope"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// CheckBundle inspects a compiled topology. files is the bundle map.
func CheckBundle(t model.Topology, files map[string]string) []Item {
	gw := file(files, "nodes/gw/")
	var auto []Item
	auto = append(auto, sysctlItems(gw)...)
	auto = append(auto, sameSubnetItem(t))
	auto = append(auto, nftItems(gw)...)
	auto = append(auto, routeItems(t, gw)...)
	auto = append(auto, meshItems(files)...)
	auto = append(auto, nat64Item(files))
	auto = append(auto, pureV6Item(t, files))
	items := make([]Item, 0, len(auto)+16)
	for _, it := range auto {
		it.Scope = ScopeAutomated
		items = append(items, it)
	}
	items = append(items, integrationItems()...)
	items = append(items, humanItems()...)
	items = append(items,
		Item{
			ID: "webrtc_host_gua", Status: KnownLimitation, Scope: ScopeLimitation,
			Title:  "WebRTC host 候选里的运营商 GUA",
			Detail: "测试机继续使用 ROS 通告的 /64 时，host 候选仍可能出现家庭 GUA。这是单前缀 SLAAC 的限制，不是 srflx 走错出口。要去掉它，只能让测试机不用 GUA、改用 ULA 再在出口做 NAT66，国内 IPv6 就不再端到端。验收时只要求 srflx 是出口地址。",
		},
		Item{
			ID: "doh_not_exhaustive", Status: KnownLimitation, Scope: ScopeLimitation,
			Title:  "DoH 清单不是绝对防护",
			Detail: "只拒绝已知公共解析器的 443，并让已知 DoH 域名返回 SOA。非常见的 DoH 地址仍可能绕过。",
		},
	)
	return items
}

// integrationItems are run on Linux outside the panel. The panel has no way
// to know they ran, so they stay Unknown.
func integrationItems() []Item {
	return []Item{
		{
			ID: "gateway_verify_script", Status: Unknown, Scope: ScopeIntegration,
			Title:  "网关上运行 meridian-verify.sh",
			Detail: "未执行（面板不代跑）。在网关上 sudo /usr/local/sbin/meridian-verify.sh：缺 nft 或缺 inet meridian / inet meridian_guard 任何一张表都会失败；最后一行 meridian-verify-local-ok 只代表本机检查通过，不是防泄露结论。把证据目录存档。",
		},
		{
			ID: "netns_reload_no_leak", Status: Unknown, Scope: ScopeIntegration,
			Title:  "持续流量下 nft 重载不漏（netns）",
			Detail: "未执行。sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsReloadNoLeak，在隔离的 Linux 主机上跑并存档日志；没有日志就仍是未验证。",
		},
		{
			ID: "smartdns_runtime", Status: Unknown, Scope: ScopeIntegration,
			Title:  "SmartDNS 容器启动并写入 nftset",
			Detail: "未执行。sudo bash deploy/verify-smartdns.sh，最后一行应是 meridian-smartdns-verify-ok。",
		},
		{
			ID: "mesh_veth_forwarding", Status: Unknown, Scope: ScopeIntegration,
			Title:  "Mesh veth 下一跳双栈转发（netns）",
			Detail: "未执行（面板不代跑，也从未在 Linux 上跑过）。sudo bash deploy/verify-mesh-veth.sh：v4 / v6 经 169.254.66.2 与 fe80::66:2%mmesh 转发，mmesh 上只解析这两个下一跳，旧写法 default dev mmesh 作为对照必须不通；最后一行应是 meridian-mesh-veth-verify-ok。",
		},
		{
			ID: "host_exec_runtime", Status: Unknown, Scope: ScopeIntegration,
			Title:  "宿主执行、开机兜底与运行态回滚",
			Detail: "未执行。sudo bash deploy/verify-host-exec.sh，重启后再加 --boot 跑一次。",
		},
	}
}

// humanItems need a real client, ROS or a capture. The panel cannot run
// them and never marks them passed.
func humanItems() []Item {
	return []Item{
		{
			ID: "dnsleak_client", Status: PendingSignoff, Scope: ScopeHuman,
			Title:  "测试机 dnsleaktest / ipleak",
			Detail: "待人工签收。需要一台已经把网关、DNS 和 IPv6 默认路由指到本机的测试设备；v4/v6 的 DNS 与出口都属于当前出口地区，家庭 WAN 抓包里没有这台设备的境外 53/853。截图和抓包存档。",
		},
		{
			ID: "webrtc_srflx", Status: PendingSignoff, Scope: ScopeHuman,
			Title:  "WebRTC srflx 是出口地址",
			Detail: "待人工签收。在测试机浏览器打开 browserleaks / ipleak 的 WebRTC 测试，srflx / 中继候选必须是出口地址。host 候选里的 GUA 见已知限制。",
		},
		{
			ID: "ros_ula_blackhole", Status: PendingSignoff, Scope: ScopeHuman,
			Title:  "ROS 上的 fd00::/8 黑洞",
			Detail: "待人工签收。只查看，不改 ROS：/ipv6 route print where blackhole and (dst-address=fd00::/8 or dst-address=fc00::/7)；或在网关上用 MERIDIAN_ROS_SSH=user@192.168.100.1 运行 meridian-verify.sh，让脚本执行这条只读命令并保存输出。有没有这条都不改变 Meridian 的路由，隧道 ULA 不指向 192.168.100.1。",
		},
		{
			ID: "redirect_on_wire", Status: PendingSignoff, Scope: ScopeHuman,
			Title:  "同网段 ICMP 重定向抓包",
			Detail: "待人工签收。生成的 sysctl 关闭了 send_redirects。ROS 自己仍可能对客户端发重定向，这不在本机的控制范围内，要在测试机上抓包确认。",
		},
		{
			ID: "tunnel_cut", Status: PendingSignoff, Scope: ScopeHuman,
			Title:  "断隧道时不回落到 ROS",
			Detail: "待人工签收。测试机持续访问境外站点时停掉出口隧道，在网关局域网口和 ROS WAN 上抓包：境外流量不出现在 ROS / 家庭 WAN，测试机得到的是不通而不是家宽出口。",
		},
		{
			ID: "mesh_e2e_forwarding", Status: PendingSignoff, Scope: ScopeHuman,
			Title:  "Mesh 备路真实转发（v4 / v6）",
			Detail: "待人工签收。面板部署显示「已发布」只代表 Cloudflare 路由已发布，不代表 Mesh 可用。让池里所有 WireGuard 成员失效、使该出口表切到 mmesh 后，在枢纽 mmesh 与出口上抓包：v4 和 v6 测试流量经 169.254.66.2 / fe80::66:2 进入 sidecar 并从出口离开，mmesh 上没有对公网目的地址的 ARP / NS。没有存档证据前 Mesh 数据面保持未验证。",
		},
	}
}

func file(files map[string]string, prefix string) string {
	var b strings.Builder
	for path, body := range files {
		if strings.HasPrefix(path, prefix) {
			b.WriteString("\n# ")
			b.WriteString(path)
			b.WriteByte('\n')
			b.WriteString(body)
		}
	}
	return b.String()
}

func sysctlItems(gw string) []Item {
	checks := []struct {
		id, title, needle string
	}{
		{"rp_filter", "rp_filter 为 loose（2）", "net.ipv4.conf.all.rp_filter=2"},
		{"rp_filter_device", "局域网口 rp_filter 为 2", "rp_filter=2"},
		{"send_redirects", "关闭发送 ICMP 重定向", "net.ipv4.conf.all.send_redirects=0"},
		{"send_redirects_v6", "关闭 IPv6 发送重定向", "net.ipv6.conf.all.send_redirects=0"},
		{"accept_redirects", "不接受 ICMP 重定向", "net.ipv4.conf.all.accept_redirects=0"},
		{"accept_ra", "网关作为 SLAAC 客户端接受 RA", "accept_ra=2"},
	}
	var out []Item
	for _, c := range checks {
		status := Pass
		detail := "生成的 99-meridian.conf 里有这一项（只核对生成文本，运行值由 meridian-verify.sh 在网关上查）。"
		if !strings.Contains(gw, c.needle) {
			status = Fail
			detail = "网关 sysctl 里没有 " + c.needle
		}
		out = append(out, Item{ID: c.id, Status: status, Title: c.title, Detail: detail})
	}
	if strings.Contains(gw, "radvd") && strings.Contains(gw, "enable radvd") {
		out = append(out, Item{ID: "no_radvd", Status: Fail, Title: "网关不发 RA", Detail: "出现了启用 radvd 的字样。"})
	} else {
		out = append(out, Item{ID: "no_radvd", Status: Pass, Title: "网关不发 RA", Detail: "sysctl 注释要求不要在局域网口跑 radvd，配置里没有启用它。"})
	}
	return out
}

func sameSubnetItem(t model.Topology) Item {
	ok, detail := SameSubnet(t.Settings.GatewayLANIP, t.Settings.ROSIPv4)
	status := Pass
	if !ok {
		status = Fail
	}
	if detail == "" {
		detail = "网关与 ROS 192.168.100.1 在同一 IPv4 子网，且不是同一个地址。"
	}
	return Item{ID: "same_subnet", Status: status, Title: "与 ROS 同网段且地址不同", Detail: detail}
}

// SameSubnet reports whether the gateway and ROS share a subnet without
// being the same host. gw is a CIDR (192.168.100.88/24) and ros is a host.
func SameSubnet(gw, ros string) (bool, string) {
	p, err := netip.ParsePrefix(gw)
	if err != nil {
		if addr, err2 := netip.ParseAddr(gw); err2 == nil {
			p = netip.PrefixFrom(addr, 24)
		} else {
			return false, "网关局域网地址无法解析。"
		}
	}
	rip, err := netip.ParseAddr(ros)
	if err != nil {
		return false, "ROS 地址无法解析。"
	}
	if p.Addr() == rip {
		return false, "网关地址不能是 ROS " + ros + "。"
	}
	if !p.Contains(rip) {
		return false, fmt.Sprintf("网关 %s 与 ROS %s 不在同一子网。国内回程会不对称，rp_filter 必须是 loose，而且重定向必须关掉。", p, rip)
	}
	return true, ""
}

func nftItems(gw string) []Item {
	var out []Item
	if strings.Contains(gw, "flush ruleset") {
		out = append(out, Item{ID: "no_flush", Status: Fail, Title: "不 flush 整个 nftables", Detail: "生成结果里出现了 flush ruleset。"})
	} else {
		out = append(out, Item{ID: "no_flush", Status: Pass, Title: "不 flush 整个 nftables", Detail: "只在一个 nft 事务里替换 Meridian 自己的表（网关上是 inet meridian 和 inet meridian_guard）。运行中重载不漏尚未在 Linux 上验证。"})
	}
	need := []struct{ id, title, needle string }{
		{"dns_hijack_53", "劫持 53", "dport 53"},
		{"dns_hijack_853", "劫持 853", "dport 853"},
		{"dns_input_drop", "非局域网的 53/853 丢弃", "ip saddr != 192.168.100.0/24 drop"},
		{"ula_drop", "ULA 不转发给 ROS", "ip6 daddr fc00::/7 drop"},
	}
	for _, n := range need {
		if strings.Contains(gw, n.needle) {
			out = append(out, Item{ID: n.id, Status: Pass, Title: n.title, Detail: "生成的 nftables 规则里有这一条。是否已加载到内核由 meridian-verify.sh 检查，是否真的不漏要靠实机签收。"})
		} else {
			out = append(out, Item{ID: n.id, Status: Fail, Title: n.title, Detail: "缺少 " + n.needle})
		}
	}
	return out
}

func routeItems(t model.Topology, gw string) []Item {
	var out []Item
	bad := false
	for _, line := range strings.Split(gw, "\n") {
		if strings.Contains(line, "fd66") && strings.Contains(line, t.Settings.ROSIPv4) && !strings.Contains(line, "#") {
			bad = true
		}
	}
	if bad {
		out = append(out, Item{ID: "ula_not_via_ros", Status: Fail, Title: "fd66 不指向 ROS", Detail: "有一条 ULA 路由的下一跳是 ROS。"})
	} else {
		out = append(out, Item{ID: "ula_not_via_ros", Status: Pass, Title: "fd66 不指向 ROS", Detail: "网关脚本没有把 fd66::/48 指向 " + t.Settings.ROSIPv4 + "。"})
	}
	if strings.Contains(gw, "blackhole default metric 32767 table 102") && strings.Contains(gw, "priority 17000") {
		out = append(out, Item{ID: "fail_closed", Status: Pass, Title: "境外表黑洞且策略优先级从 17000 起", Detail: "生成的路由脚本里有黑洞和 17000 起的优先级，按设计 WireGuard 设备路由消失时不会落到 ROS 的默认路由。断隧道实测见「断隧道时不回落到 ROS」。"})
	} else {
		out = append(out, Item{ID: "fail_closed", Status: Fail, Title: "境外表黑洞且策略优先级从 17000 起", Detail: "缺少 table 102 的黑洞或 17000 优先级。"})
	}
	if strings.Contains(gw, "send_redirects=0") && strings.Contains(gw, "rp_filter=2") {
		out = append(out, Item{ID: "redirect_sysctl", Status: Pass, Title: "同网段重定向与 rp_filter 脚本", Detail: "路由脚本会对每个接口再写一次 rp_filter=2 和 send_redirects=0，避免 all 被单口覆盖。"})
	} else {
		out = append(out, Item{ID: "redirect_sysctl", Status: Fail, Title: "同网段重定向与 rp_filter 脚本", Detail: "路由脚本没有对每个接口关闭重定向。"})
	}
	return out
}

func meshItems(files map[string]string) []Item {
	gw := file(files, "nodes/gw/")
	var out []Item
	if strings.Contains(gw, "dev mmesh") || strings.Contains(gw, "cloudflare/mesh") {
		out = append(out, Item{ID: "mesh_not_on_gateway", Status: Fail, Title: "家宽网关不跑 Mesh", Detail: "网关的生成文件里出现了 Mesh 路由或镜像。"})
	} else if strings.Contains(gw, "Mesh is not a candidate") {
		out = append(out, Item{ID: "mesh_not_on_gateway", Status: Pass, Title: "家宽网关不跑 Mesh", Detail: "网关故障切换只在 UDP、WSS 和预置的家宽到枢纽 WSS 之间选择。"})
	} else {
		out = append(out, Item{ID: "mesh_not_on_gateway", Status: Fail, Title: "家宽网关不跑 Mesh", Detail: "没有找到「Mesh 不是候选」的说明，也没有确认网关文件不含 mmesh。"})
	}
	hub := file(files, "nodes/hk-hub/")
	if strings.Contains(hub, "refused on table") && strings.Contains(hub, "100|102|150") {
		out = append(out, Item{ID: "mesh_not_ix", Status: Pass, Title: "Mesh 不能替换 IX 西向路径", Detail: "枢纽脚本拒绝把 Mesh 装进 100、102、150 或 main。它只出现在某个出口表里。"})
	} else if !strings.Contains(hub, "mmesh") {
		out = append(out, Item{ID: "mesh_not_ix", Status: Skip, Title: "Mesh 不能替换 IX 西向路径", Detail: "这份拓扑没有 Mesh 备路。"})
	} else {
		out = append(out, Item{ID: "mesh_not_ix", Status: Fail, Title: "Mesh 不能替换 IX 西向路径", Detail: "枢纽引用了 mmesh，但没有拒绝把它装到 IX 表上。"})
	}
	switch {
	case !strings.Contains(hub, "mmesh"):
		out = append(out, Item{ID: "mesh_nexthop", Status: Skip, Title: "Mesh veth 路由带显式下一跳", Detail: "这份拓扑没有 Mesh 备路。"})
	case strings.Contains(hub, "default dev mmesh") || strings.Contains(hub, `default dev "$MESH_DEV"`):
		out = append(out, Item{ID: "mesh_nexthop", Status: Fail, Title: "Mesh veth 路由带显式下一跳", Detail: "枢纽脚本里有 default dev mmesh：mmesh 是以太网 veth，没有下一跳时内核会对每个公网目的地址做 ARP / 邻居发现。"})
	case strings.Contains(hub, "via 169.254.66.2 dev mmesh") && strings.Contains(hub, "via fe80::66:2 dev mmesh") && strings.Contains(hub, "MESH_NH6=fe80::66:2"):
		out = append(out, Item{ID: "mesh_nexthop", Status: Pass, Title: "Mesh veth 路由带显式下一跳", Detail: "静态路由和池切换都写成 via 169.254.66.2 / via fe80::66:2 dev mmesh，两端固定 MAC 与永久邻居。这只说明生成文本正确；实际转发见「Mesh veth 下一跳双栈转发」。"})
	default:
		out = append(out, Item{ID: "mesh_nexthop", Status: Fail, Title: "Mesh veth 路由带显式下一跳", Detail: "枢纽引用了 mmesh，但静态路由或池切换缺少 IPv4 / IPv6 下一跳。"})
	}
	return out
}

func nat64Item(files map[string]string) Item {
	all := file(files, "nodes/")
	routes := ""
	for path, body := range files {
		if strings.HasSuffix(path, "meridian-routes.sh") {
			routes += "\n" + body
		}
	}
	for _, line := range strings.Split(routes, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		low := strings.ToLower(trim)
		if strings.Contains(low, "64:ff9b") || strings.Contains(low, "nat64") {
			return Item{ID: "nat64_reserved", Status: Fail, Title: "NAT64 只是预留", Detail: "路由脚本里有 NAT64 命令：" + trim}
		}
	}
	if strings.Contains(all, "nat64.reserved") || strings.Contains(all, "NAT64 reservation") {
		return Item{ID: "nat64_reserved", Status: Pass, Title: "NAT64 只是预留", Detail: "有一份占位配置，路由脚本没有安装 NAT64 前缀，也没有改 IPv4 默认路由。"}
	}
	return Item{ID: "nat64_reserved", Status: Fail, Title: "NAT64 只是预留", Detail: "没有生成 NAT64 占位文件。"}
}

func pureV6Item(t model.Topology, files map[string]string) Item {
	var pure []model.Node
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit && !n.PathV4 && n.PathV6 {
			pure = append(pure, n)
		}
	}
	if len(pure) == 0 {
		return Item{ID: "pure_v6", Status: Skip, Title: "纯 IPv6 出口有绕行", Detail: "拓扑里没有纯 IPv6 出口。"}
	}
	for _, n := range pure {
		if n.V6Workaround == "" {
			return Item{ID: "pure_v6", Status: Fail, Title: "纯 IPv6 出口有绕行", Detail: n.Name + " 没有选择绕行。枢纽没有 IPv6。"}
		}
	}
	hub := file(files, "nodes/hk-hub/")
	if strings.Contains(hub, "pure-v6") || strings.Contains(hub, "mmesh") || strings.Contains(hub, "dualstack") {
		return Item{ID: "pure_v6", Status: Pass, Title: "纯 IPv6 出口有绕行", Detail: "枢纽侧的下一跳是双栈中继或 Mesh，不是把 IPv6 端点写在没有 IPv6 的枢纽上。"}
	}
	return Item{ID: "pure_v6", Status: Fail, Title: "纯 IPv6 出口有绕行", Detail: "绕行标志已选，但枢纽路由里没有对应的数据面。"}
}

// CheckSysctl evaluates a snapshot of sysctl values (name → value).
// Missing keys are failures. This is what meridian-verify.sh checks on the host.
func CheckSysctl(values map[string]string) []Item {
	want := []struct{ id, key, val, title string }{
		{"live_rp_filter", "net.ipv4.conf.all.rp_filter", "2", "运行中 rp_filter=2"},
		{"live_rp_filter_default", "net.ipv4.conf.default.rp_filter", "2", "default rp_filter=2"},
		{"live_send_redirects", "net.ipv4.conf.all.send_redirects", "0", "运行中 send_redirects=0"},
		{"live_send_redirects_v6", "net.ipv6.conf.all.send_redirects", "0", "运行中 IPv6 send_redirects=0"},
		{"live_accept_redirects", "net.ipv4.conf.all.accept_redirects", "0", "运行中 accept_redirects=0"},
		{"live_forward", "net.ipv4.ip_forward", "1", "IPv4 转发已开"},
	}
	var out []Item
	for _, w := range want {
		got, ok := values[w.key]
		if !ok {
			out = append(out, Item{ID: w.id, Status: Fail, Title: w.title, Detail: "没有读到 " + w.key})
			continue
		}
		if strings.TrimSpace(got) != w.val {
			out = append(out, Item{ID: w.id, Status: Fail, Title: w.title, Detail: w.key + "=" + got + "，需要 " + w.val})
			continue
		}
		out = append(out, Item{ID: w.id, Status: Pass, Title: w.title, Detail: w.key + "=" + got})
	}
	return out
}
