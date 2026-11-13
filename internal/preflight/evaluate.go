package preflight

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Severities.
const (
	Blocking = "blocking"
	Warning  = "warning"
	Info     = "info"
)

// Finding codes (stable; the panel keys on them, never on the text).
const (
	CodeReportIncomplete = "report_incomplete"
	CodeNotRoot          = "not_root"
	CodeOSUnsupported    = "os_unsupported"
	CodeArchUnsupported  = "arch_unsupported"
	CodeKernelTooOld     = "kernel_too_old"
	CodeNoSystemd        = "no_systemd"
	CodeNoApt            = "no_apt"
	CodeWstunnelMissing  = "wstunnel_missing"
	// CodeExternalIface (blocking): the unmanaged interface an external
	// SOCKS exit's proxy must be reached through does not exist on its
	// carrier, or does not route the proxy address. CodeExternalProxy
	// (blocking): the proxy port does not accept a TCP connection from the
	// carrier. CodeExternal (info): both checked.
	CodeExternalIface = "external_interface_missing"
	CodeExternalProxy = "external_proxy_unreachable"
	CodeExternal      = "external_proxy"

	CodeSmartDNSMissing    = "smartdns_unavailable"
	CodeForwardDrop        = "forward_policy_drop"
	CodeInterfaceExists    = "interface_exists"
	CodePortInUse          = "port_in_use"
	CodeAddressOverlap     = "address_overlap"
	CodeRouteOverlap       = "route_overlap"
	CodeTableInUse         = "route_table_in_use"
	CodeFwmarkInUse        = "fwmark_in_use"
	CodeNFTTableExists     = "nft_table_exists"
	CodePathOccupied       = "path_occupied"
	CodeManagedByOther     = "managed_by_other"
	CodeManifestUnreadable = "manifest_unreadable"
	CodeLegacyInstall      = "legacy_install"
	CodePreviousRun        = "previous_run_incomplete"
	CodeWithdrawIncomplete = "withdraw_incomplete"

	// CodeGatewayTools: the gateway install installs no package; the
	// tools it runs must already be there (install.sh installs them).
	CodeGatewayTools = "gateway_tools_missing"

	CodeRulePrecedes      = "rule_precedes"
	CodeRulePriority      = "rule_priority_shared"
	CodeTableName         = "route_table_name_conflict"
	CodeInputDrop         = "input_policy_drop"
	CodeLowMemory         = "low_memory"
	CodeLowDisk           = "low_disk"
	CodeNFTFlush          = "nftables_flush_on_reload"
	CodeFirewallManager   = "firewall_manager"
	CodeModifiedSince     = "modified_since_install"
	CodePreviousLeftovers = "previous_run_leftovers"

	CodeDocker          = "docker_present"
	CodeDockerMissing   = "docker_missing"
	CodeWARP            = "cloudflare_warp"
	CodeWireGuard       = "wireguard_present"
	CodeDNSListeners    = "dns_listeners"
	CodeNFTOther        = "nft_tables_present"
	CodeNetfilterPersis = "netfilter_persistent"
	CodeIptablesLegacy  = "iptables_legacy"
	CodeOwnInstall      = "existing_install"
	CodeHostSummary     = "host_summary"
	CodeForwardEnable   = "forwarding_enable"
	CodeGatewayDNS      = "gateway_dns_runtime"
	// CodeFWCompat (info): what the Docker FORWARD DROP coexistence does
	// per address family on this host.
	CodeFWCompat = "forward_coexistence"
	// CodeFirewallInactive (info): ufw.service is active but ufw is not
	// enabled (ENABLED=no, no ufw chains): it manages no rules.
	CodeFirewallInactive = "firewall_manager_inactive"
	// CodeWARPSidecar: the bundle carries the Mesh sidecar while a
	// host-level WARP client runs; the Mesh deployment refuses this host
	// until the old client is retired (a separate, confirmed step).
	CodeWARPSidecar = "warp_sidecar_conflict"
	// CodeSysctlScope (info): which kernel keys the install sets, which of
	// them are global, and the rp_filter semantics.
	CodeSysctlScope = "sysctl_scope"
	// CodeWANMissing: the node's WAN interface (wan_interface, or eth0
	// when unset) does not exist on the host. CodeWANRoute: it does not
	// carry the default route of a family the node needs. Both blocking,
	// with a fix pointing at the node's wan_interface. CodeWAN (info): the
	// WAN interface was checked.
	CodeWANMissing = "wan_interface_missing"
	CodeWANRoute   = "wan_no_default_route"
	CodeWAN        = "wan_interface"
	// CodeIXIngressIface (blocking): the IX hub's ingress interface named
	// in the topology is missing or does not carry the ingress address.
	// CodeIXIngressNotLocal / CodeIXEgressNotLocal (warning): the address is
	// on no interface of the host (a NAT or forward in front of it is fine:
	// WireGuard listens on every address, but the panel cannot see it).
	// CodeIXHub (info): both were checked.
	CodeIXIngressIface    = "ix_ingress_interface"
	CodeIXIngressNotLocal = "ix_ingress_not_local"
	CodeIXEgressNotLocal  = "ix_egress_not_local"
	CodeIXHub             = "ix_hub_addresses"
	// CodeRAKept (info): interfaces whose IPv6 comes from router
	// advertisements get accept_ra=2 before IPv6 forwarding is turned on.
	// CodeRAUnmanaged (blocking): RA-learned routes on an interface with
	// accept_ra 0 or unreadable (a userspace RA client): kept alive safely
	// with forwarding on cannot be confirmed.
	CodeRAKept      = "ipv6_ra_kept"
	CodeRAUnmanaged = "ipv6_ra_unmanaged"

	// CodePlatform (info) names the supported platform the host matched
	// and what that means for the install (packages, legacy iptables).
	CodePlatform = "platform_supported"
	// CodePackageUnavailable: a package the install needs is missing and
	// apt has no candidate for it.
	CodePackageUnavailable = "package_unavailable"
	// CodeArtifact (info) is the plan for one panel-delivered binary:
	// transfer and install, or keep (the host already has the pinned digest).
	CodeArtifact = "artifact_plan"
	// CodeForeignBinary (info): the host has its own wstunnel or SmartDNS
	// (another path, the distribution package); Meridian neither uses,
	// overwrites nor removes it.
	CodeForeignBinary = "foreign_binary"
	// CodeMemoryBudget: MemAvailable against the explicit budget of what the
	// node runs (MemHeadroomKB + MemSmartDNSKB + MemWstunnelKB). Blocking
	// when the plan needs a local resolver and the budget does not fit.
	CodeMemoryBudget = "memory_budget"
	// CodeResolverBind: the node's resolver config would bind a wildcard
	// address or nothing at all (SmartDNS then binds [::]:53 by default).
	CodeResolverBind = "resolver_bind_unsafe"
)

// Memory budget of a remote node, in KiB (MemAvailable before the install).
const (
	// MemHeadroomKB: apt-get/dpkg, bash and wg-quick while installing.
	MemHeadroomKB = 48 * 1024
	// MemSmartDNSKB: the pinned SmartDNS with the exit config (cache-size
	// 4096, two upstreams, binds on the tunnel addresses only).
	MemSmartDNSKB = 48 * 1024
	// MemWstunnelKB: one wstunnel server or client process.
	MemWstunnelKB = 32 * 1024
)

// Platform is one supported operating system release on one architecture.
type Platform struct {
	OSID    string `json:"os_id"`
	Version string `json:"os_version"`
	Arch    string `json:"arch"`
	Name    string `json:"name"`
}

// SupportedPlatforms are the platforms the install is built for. Anything
// else is refused (os_unsupported / arch_unsupported): other distributions
// and releases differ in package names and versions, and the panel-delivered
// binaries exist only for x86_64 and aarch64.
var SupportedPlatforms = []Platform{
	{OSID: "debian", Version: "12", Arch: "x86_64", Name: "Debian 12 x86_64"},
	{OSID: "debian", Version: "13", Arch: "x86_64", Name: "Debian 13 x86_64"},
	{OSID: "ubuntu", Version: "20.04", Arch: "aarch64", Name: "Ubuntu 20.04 aarch64"},
}

func supportedList() string {
	var s []string
	for _, p := range SupportedPlatforms {
		s = append(s, p.Name)
	}
	return strings.Join(s, "、")
}

// Artifact is one panel-delivered binary as the panel has it (the API fills
// Context.Artifacts from internal/artifacts).
type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	// Available: the panel holds a copy verified against the pin; Error
	// says why not.
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// Finding is one result of the evaluation.
type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	// Message says what was found; Action says what to do about it.
	Message  string `json:"message"`
	Action   string `json:"action,omitempty"`
	Resource string `json:"resource,omitempty"`
	// Fix names the topology field that resolves the finding, when one
	// does (a port the node binds): the panel links to that editor.
	Fix *Fix `json:"fix,omitempty"`
}

// Fix is the topology object and field to edit: kind "node" or "link".
type Fix struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Field string `json:"field"`
	Label string `json:"label"`
}

// PortSource says which topology field sets a port the bundle binds
// (validate.NodePorts, passed in by the API so this package stays free of
// topology types).
type PortSource struct {
	Proto    string
	Port     int
	Loopback bool
	What     string
	Kind     string // node | link
	ID       string
	Field    string
}

// Change is one intended change of the install.
type Change struct {
	Kind     string `json:"kind"`   // file | interface | listen | route | rule | nft | unit | package | sysctl | state
	Action   string `json:"action"` // create | replace | update | bind | add | enable | install | set
	Resource string `json:"resource"`
	Detail   string `json:"detail,omitempty"`
}

// Owned lists resources known to be Meridian's on this host.
type Owned struct {
	Files      map[string]string `json:"files"`
	Interfaces []string          `json:"interfaces"`
	Units      []string          `json:"units"`
	NFTTables  []string          `json:"nft_tables"`
	Tables     []int             `json:"route_tables"`
	DNS        bool              `json:"dns"`
}

// Context is what the evaluation knows besides report and footprint.
type Context struct {
	NodeID     string
	Deployment string
	// Gateway: the report comes from meridian-host on the panel's own host;
	// ownership is the install manifest (Owned), legacy Meridian files are
	// adopted or refused by the install transaction itself.
	Gateway bool
	Owned   *Owned
	// Ports are the topology sources of the ports the bundle binds; a
	// port_in_use finding names the field to change.
	Ports []PortSource
	// Artifacts are the panel-delivered binaries for every architecture.
	Artifacts []Artifact
}

// BinaryPlan is what the install does with one panel-delivered binary.
type BinaryPlan struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Size    int64  `json:"size,omitempty"`
	// Action: install (transfer, verify, install), keep (the host already
	// has exactly the pinned digest: no transfer), replace (a Meridian copy
	// with another digest is replaced), refuse.
	Action string `json:"action"`
	// Transfer: the bytes must be sent to the host.
	Transfer bool   `json:"transfer"`
	Detail   string `json:"detail,omitempty"`
}

// PackageState is one distribution package of the install plan.
type PackageState struct {
	Package   string `json:"package"`
	Command   string `json:"command"`
	Present   bool   `json:"present"`
	Installed string `json:"installed,omitempty"`
	Candidate string `json:"candidate,omitempty"`
	// Action: none (command present) | install (apt-get) | unavailable.
	Action string `json:"action"`
}

// Ownership states.
const (
	OwnNone    = "none"    // nothing of Meridian on the host
	OwnSame    = "same"    // installed by this panel for this node
	OwnOther   = "other"   // a manifest of another node or deployment
	OwnLegacy  = "legacy"  // Meridian resources without a manifest
	OwnUnknown = "unknown" // manifest present but unreadable
)

// Evaluation is the result for one node.
type Evaluation struct {
	Ownership string `json:"ownership"`
	// Platform is the supported platform the host matched ("" = none).
	Platform string `json:"platform,omitempty"`
	// Binaries is the plan for each panel-delivered binary.
	Binaries []BinaryPlan `json:"binaries,omitempty"`
	// Packages is the plan for each distribution package the install needs.
	Packages []PackageState `json:"package_plan,omitempty"`
	Blocking bool           `json:"blocking"`
	Findings []Finding      `json:"findings"`
	Changes  []Change       `json:"changes"`
	Counts   struct {
		Blocking int `json:"blocking"`
		Warning  int `json:"warning"`
		Info     int `json:"info"`
	} `json:"counts"`
}

type eval struct {
	r   Report
	fp  Footprint
	ctx Context
	own Owned
	out Evaluation
}

func (e *eval) add(sev, code, res, msg, action string) {
	e.addFix(sev, code, res, msg, action, nil)
}

func (e *eval) addFix(sev, code, res, msg, action string, fix *Fix) {
	// One finding per code and resource: the first cause is named.
	if res != "" {
		for _, f := range e.out.Findings {
			if f.Code == code && f.Resource == res {
				return
			}
		}
	}
	e.out.Findings = append(e.out.Findings, Finding{Severity: sev, Code: code, Resource: res, Message: msg, Action: action, Fix: fix})
}

// fieldLabels are the panel's names of the port fields.
var fieldLabels = map[string]string{
	"wg_port":         "「WireGuard 端口」",
	"listen_port":     "「WireGuard 监听端口」",
	"wss_listen_port": "「WSS 监听端口」",
	"wss_local_port":  "「wstunnel 本地端口」",
	"wan_interface":   "「WAN 接口」",
}

// portFix finds the topology field behind a planned listener.
func (e *eval) portFix(lp ListenPlan) (PortSource, bool) {
	loop := lp.Addr.IsLoopback()
	for _, p := range e.ctx.Ports {
		if p.Proto == lp.Proto && p.Port == lp.Port && p.Loopback == loop && p.Field != "" {
			return p, true
		}
	}
	return PortSource{}, false
}

func (e *eval) change(kind, action, res, detail string) {
	e.out.Changes = append(e.out.Changes, Change{Kind: kind, Action: action, Resource: res, Detail: detail})
}

// Evaluate turns a report and a footprint into findings and intended
// changes. An incomplete report is itself a blocking finding and nothing
// else is concluded from it beyond what it says.
func Evaluate(r Report, fp Footprint, ctx Context) Evaluation {
	e := &eval{r: r, fp: fp, ctx: ctx}
	e.out.Findings = []Finding{}
	e.out.Changes = []Change{}
	if !r.Complete {
		why := strings.Join(r.Notes, "；")
		if why == "" {
			why = "报告不完整"
		}
		e.add(Blocking, CodeReportIncomplete, "", "预检报告不完整，不能确认可以安全共存："+why+"。",
			"重新运行预检。仍然不完整时，在服务器上确认 bash、coreutils、iproute2 可用、磁盘未满、登录没有交互提示，然后再试。")
	}
	e.ownership()
	e.system()
	e.binaries()
	e.memory()
	e.paths()
	e.interfaces()
	e.wan()
	e.ixHub()
	e.external()
	e.listens()
	e.routes()
	e.rules()
	e.nft()
	e.firewall()
	e.fwCompatSummary()
	e.environment()
	e.ra()
	e.plan()
	sort.SliceStable(e.out.Findings, func(i, j int) bool {
		return sevRank(e.out.Findings[i].Severity) < sevRank(e.out.Findings[j].Severity)
	})
	for _, f := range e.out.Findings {
		switch f.Severity {
		case Blocking:
			e.out.Counts.Blocking++
		case Warning:
			e.out.Counts.Warning++
		default:
			e.out.Counts.Info++
		}
	}
	e.out.Blocking = e.out.Counts.Blocking > 0
	return e.out
}

func sevRank(s string) int {
	switch s {
	case Blocking:
		return 0
	case Warning:
		return 1
	}
	return 2
}

// ------------------------------------------------------------ ownership ---

func (e *eval) ownership() {
	e.own = Owned{Files: map[string]string{}}
	if e.ctx.Gateway {
		e.out.Ownership = OwnNone
		if e.ctx.Owned != nil && len(e.ctx.Owned.Files) > 0 {
			e.own = *e.ctx.Owned
			e.out.Ownership = OwnSame
			e.add(Info, CodeOwnInstall, "", fmt.Sprintf("网关上已有 Meridian 安装（受管清单 %d 个文件）：这次是更新，清单里的接口、表和服务按安装事务替换。", len(e.own.Files)), "")
		}
		return
	}
	m := e.r.Manifest
	if j := e.r.Journal; j != nil {
		switch j.State {
		case "done", "withdrawn":
		case "withdrawing", "withdraw_incomplete":
			left := ""
			if len(j.Leftovers) > 0 {
				left = "没有撤掉的：" + strings.Join(j.Leftovers, "；") + "。"
			}
			e.add(Blocking, CodeWithdrawIncomplete, "/var/lib/meridian/node/journal",
				fmt.Sprintf("上一次撤回（运行 %s）没有完成（状态 %s）。%s", orDash(j.Run), j.State, left),
				"在部署页对这个节点重新「撤回」（可重复执行，只处理清单里还在的东西）；按提示处理改动过的文件后再撤回一次，完成后再预检。")
		case "compensated":
			if len(j.Leftovers) > 0 {
				e.add(Warning, CodePreviousLeftovers, "/var/lib/meridian/node/journal",
					"上一次装机失败并已补偿，但记录了没有撤掉的残留："+strings.Join(j.Leftovers, "；")+"。",
					"逐项核对这些残留是否影响这台主机；确认无碍后可以继续。")
			}
		default:
			left := ""
			if len(j.Leftovers) > 0 {
				left = "记录的残留：" + strings.Join(j.Leftovers, "；") + "。"
			}
			e.add(Blocking, CodePreviousRun, "/var/lib/meridian/node/journal",
				fmt.Sprintf("上一次装机（运行 %s）没有正常结束（状态 %s）：它改了什么、补偿是否完成都无法确认。%s", orDash(j.Run), j.State, left),
				"在部署页对这个节点执行「恢复中断的装机」：面板按服务器上的 journal 和工作目录补偿这次装机（与失败时的自动补偿相同），完成后重新预检。工作目录缺失时只能登录服务器按 /var/lib/meridian/node/journal 手动处理。")
		}
	}
	switch {
	case m == nil:
		e.out.Ownership = OwnNone
	case m.Node == "":
		e.out.Ownership = OwnUnknown
		e.add(Blocking, CodeManifestUnreadable, "/var/lib/meridian/node/manifest",
			"服务器上有 Meridian 节点清单，但内容无法读懂，不能确认这台主机上的 Meridian 资源属于谁。",
			"登录服务器检查 /var/lib/meridian/node/manifest；确认后移走它（连同它描述的资源）再重新预检。")
	case m.Node == e.ctx.NodeID && m.Deployment == e.ctx.Deployment:
		e.out.Ownership = OwnSame
		e.own = Owned{Files: map[string]string{}, Interfaces: m.Interfaces, Units: m.Units, NFTTables: m.NFTTables, Tables: m.Tables}
		for p, h := range m.Files {
			e.own.Files[p] = h
		}
		for _, a := range m.Artifacts {
			if _, ok := e.own.Files[a.Path]; !ok {
				e.own.Files[a.Path] = a.SHA256
			}
		}
		_, e.own.DNS = m.Files["/etc/smartdns/smartdns.conf"]
		e.add(Info, CodeOwnInstall, "/var/lib/meridian/node/manifest",
			fmt.Sprintf("这台主机已由本面板为节点 %s 装过（清单 %d 个文件）：这次是更新，清单里的资源会被替换。", m.Node, len(m.Files)), "")
	default:
		e.out.Ownership = OwnOther
		e.add(Blocking, CodeManagedByOther, "/var/lib/meridian/node/manifest",
			fmt.Sprintf("这台主机上的 Meridian 属于节点 %s（部署 %s），不是这个面板的节点 %s。继续会覆盖另一个节点或另一个面板的配置。", m.Node, orDash(m.Deployment), e.ctx.NodeID),
			"确认那个节点或面板已不再使用这台服务器：在原面板撤回它，或登录服务器按清单移除它的资源并删除清单后重新预检；也可能是拓扑里选错了服务器。")
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// --------------------------------------------------------------- system ---

func (e *eval) system() {
	r := e.r
	if r.UID != 0 {
		who := "未知"
		if r.UID > 0 {
			who = strconv.Itoa(r.UID)
		}
		e.add(Blocking, CodeNotRoot, "uid", fmt.Sprintf("登录用户不是 root（uid %s）：装机要写 /etc、启动接口和服务，需要 root。", who),
			"把服务器的 SSH 用户改成 root（服务器页编辑），或为 root 配置密钥登录。这一版不支持经 sudo 提权。")
	}
	e.platform()
	if maj, min, ok := kernelVersion(r.Kernel); ok && (maj < 5 || maj == 5 && min < 6) {
		e.add(Blocking, CodeKernelTooOld, "kernel", fmt.Sprintf("内核 %s 早于 5.6，没有内置 WireGuard。", r.Kernel), "升级到发行版的较新内核（Debian 12/13 自带的即可）。")
	}
	if r.Systemd != "yes" {
		e.add(Blocking, CodeNoSystemd, "systemd", "这台主机没有以 systemd 运行（或读不到）：Meridian 的服务和定时器靠 systemd 启动。", "在用 systemd 的系统上部署（容器或 OpenVZ 之类的环境不支持）。")
	}
	need := []string{}
	for _, p := range e.fp.Packages {
		if !r.Commands[p.Command] {
			need = append(need, p.Package)
		}
	}
	if e.ctx.Gateway {
		// The gateway install writes files and activates units through
		// meridian-host; it installs no package. SmartDNS there is either
		// the host smartdns.service or the compose-managed container
		// meridian-smartdns (enabled after the first install), so no apt
		// package is required for it.
		var tools []string
		for _, p := range e.fp.Packages {
			if !r.Commands[p.Command] {
				tools = append(tools, p.Command+"（"+p.Package+"）")
			}
		}
		if len(tools) > 0 {
			e.add(Blocking, CodeGatewayTools, strings.Join(tools, " "), "网关上缺少安装要用的命令："+strings.Join(tools, "、")+"。安装到网关不会安装软件包。",
				"重新运行 deploy/debian/install.sh（它安装 wireguard-tools、nftables、iproute2），然后重新预检。")
		}
		if e.fp.DNS {
			c, hasC := r.Containers[GatewayDNSContainer]
			switch {
			case hasC && c.Running:
				e.add(Info, CodeGatewayDNS, GatewayDNSContainer, "网关解析器由容器 "+GatewayDNSContainer+" 运行（docker compose 的 dns profile），安装后由 meridian-host 重启它。", "")
			case r.Commands["smartdns"] || r.Units["smartdns.service"].Enabled == "enabled":
				e.add(Info, CodeGatewayDNS, "smartdns.service", "网关解析器是宿主上的 smartdns.service，安装后由 meridian-host 重启它。", "")
			default:
				e.add(Info, CodeGatewayDNS, "smartdns", "网关上还没有运行解析器：第一次安装写好 /etc/smartdns/smartdns.conf 后，按安装文档用 docker compose --profile dns up -d 启动 "+GatewayDNSContainer+"。", "")
			}
		}
		need = nil
	}
	if len(need) > 0 && !r.Commands["apt-get"] {
		e.add(Blocking, CodeNoApt, "apt-get", "需要安装 "+strings.Join(need, "、")+"，但主机上没有 apt-get。", "在支持的系统（"+supportedList()+"）上部署，或先手动装好这些软件包。")
	}
	if !e.ctx.Gateway {
		for _, p := range e.fp.Packages {
			ps := PackageState{Package: p.Package, Command: p.Command, Present: r.Commands[p.Command], Action: "none"}
			if st, ok := r.Packages[p.Package]; ok {
				ps.Installed, ps.Candidate = st.Installed, st.Candidate
			}
			if !ps.Present {
				ps.Action = "install"
				// Only a report that lists packages (pkg lines) can say that
				// apt has no candidate; an older report is not judged.
				// A value that is not a Debian version is not "no candidate".
				if st, listed := r.Packages[p.Package]; listed && !st.Unreadable && ps.Candidate == "" && r.Commands["apt-get"] {
					ps.Action = "unavailable"
					e.add(Blocking, CodePackageUnavailable, p.Package,
						fmt.Sprintf("这个节点需要 %s（命令 %s），主机上没有，apt 也查不到可安装的版本（apt-cache policy 没有 Candidate）。", p.Package, p.Command),
						"在服务器上执行 apt-get update（确认软件源可用）后重新预检；面板只经 apt 安装发行版自带的这个包。")
				}
			}
			e.out.Packages = append(e.out.Packages, ps)
		}
	}
	if r.MemAvailKB >= 0 || r.MemTotalKB >= 0 {
		msg := fmt.Sprintf("内存：共 %s，可用 %s。", kb(r.MemTotalKB), kb(r.MemAvailKB))
		if (r.MemAvailKB >= 0 && r.MemAvailKB < 256*1024) || (r.MemTotalKB >= 0 && r.MemTotalKB < 512*1024) {
			e.add(Warning, CodeLowMemory, "memory", msg+"内存很紧：SmartDNS、wstunnel 能跑，但解锁探测容器（Docker）可能因内存不足失败或挤占已有服务。",
				"确认已有服务的内存余量；必要时不要在这台机器上跑解锁探测。")
		}
	}
	if r.DiskAvailKB >= 0 && r.DiskAvailKB < 200*1024 {
		e.add(Warning, CodeLowDisk, "/", fmt.Sprintf("根分区只剩 %s：安装软件包和写配置可能失败。", kb(r.DiskAvailKB)), "先清理磁盘空间。")
	}
}

// platform checks the host against SupportedPlatforms.
func (e *eval) platform() {
	r := e.r
	name := r.OSPretty
	if name == "" {
		name = strings.TrimSpace(r.OSID + " " + r.OSVersion)
	}
	if r.OSID == "" {
		e.add(Blocking, CodeOSUnsupported, "os", "读不到发行版信息（/etc/os-release），不能确认软件包和配置兼容。",
			"在支持的系统上部署："+supportedList()+"。")
		return
	}
	if e.ctx.Gateway {
		// The gateway install (deploy/debian/install.sh) is built for
		// Debian 12/13 on x86_64 or aarch64 and installs no package; the
		// remote-node matrix below does not apply to it.
		if r.OSID != "debian" || (r.OSVersion != "12" && r.OSVersion != "13") {
			e.add(Blocking, CodeOSUnsupported, "os", fmt.Sprintf("网关系统是 %s。网关只支持 Debian 12 / 13（安装脚本 deploy/debian/install.sh 按 Debian 写）。", name), "在 Debian 12 或 13 上安装网关。")
			return
		}
		switch r.Arch {
		case "x86_64", "aarch64":
			e.out.Platform = fmt.Sprintf("Debian %s %s（网关）", r.OSVersion, r.Arch)
		default:
			e.add(Blocking, CodeArchUnsupported, "arch", fmt.Sprintf("网关的 CPU 架构 %s 不支持（只支持 x86_64 和 aarch64）。", orDash(r.Arch)), "换用 x86_64 或 aarch64 的主机。")
		}
		return
	}
	var osOK []Platform
	for _, p := range SupportedPlatforms {
		if p.OSID == r.OSID && p.Version == r.OSVersion {
			osOK = append(osOK, p)
		}
	}
	if len(osOK) == 0 {
		e.add(Blocking, CodeOSUnsupported, "os",
			fmt.Sprintf("系统是 %s，不在支持范围内（只支持 %s）。其它发行版和版本的软件包名、版本和默认防火墙没有验证过，装机脚本不会在上面运行。", name, supportedList()),
			"换用支持的系统（"+supportedList()+"），或把这台主机重装为其中之一。")
		return
	}
	switch r.Arch {
	case "":
		e.add(Blocking, CodeArchUnsupported, "arch", "读不到 CPU 架构。", "重新预检；仍然读不到时检查 uname 是否可用。")
		return
	case "x86_64", "aarch64":
	default:
		e.add(Blocking, CodeArchUnsupported, "arch", fmt.Sprintf("CPU 架构 %s 不支持（只支持 x86_64 和 aarch64；面板下发的 wstunnel 和 SmartDNS 按架构区分）。", r.Arch), "换用 x86_64 或 aarch64 的服务器。")
		return
	}
	for _, p := range osOK {
		if p.Arch == r.Arch {
			e.out.Platform = p.Name
			detail := ""
			if p.OSID == "ubuntu" {
				detail = "Ubuntu 20.04 自带的 nftables（0.9.3）和 wireguard-tools 由装机经 apt 安装（--no-install-recommends，不会装 wireguard-dkms，也不改 iptables 的 alternatives）；远端规则集已按 nft 0.9.3 复核并避开了传输层头表达式（th dport），但没有在 0.9.3 上执行过：装机时 meridian-up.sh 先 nft -c，失败会在激活前停止并补偿。"
			}
			e.add(Info, CodePlatform, "platform", "支持的平台："+p.Name+"（"+name+"）。"+detail, "")
			return
		}
	}
	var arches []string
	for _, p := range osOK {
		arches = append(arches, p.Arch)
	}
	e.add(Blocking, CodeArchUnsupported, "arch",
		fmt.Sprintf("%s 只在 %s 上支持，这台是 %s：这个组合没有验证过。", name, strings.Join(arches, "、"), r.Arch),
		"换用支持的组合（"+supportedList()+"）。")
}

// artifactFor is the panel's copy of name for the host's architecture.
func (e *eval) artifactFor(name string) (Artifact, bool) {
	for _, a := range e.ctx.Artifacts {
		if a.Name == name && a.Arch == e.r.Arch {
			return a, true
		}
	}
	return Artifact{}, false
}

// binaries plans every panel-delivered binary the bundle runs: the panel
// must hold a verified copy for this architecture; the host path is
// Meridian's own (ArtifactPath); a copy already there with exactly the
// pinned digest is kept without a transfer; a file there that the manifest
// does not record is somebody else's and refuses the install. A wstunnel
// or SmartDNS that another service installed elsewhere is only reported.
func (e *eval) binaries() {
	r := e.r
	for _, name := range e.fp.Binaries {
		path := ArtifactPath(name)
		bp := BinaryPlan{Name: name, Path: path, Arch: r.Arch, Action: "refuse"}
		a, ok := e.artifactFor(name)
		code := CodeWstunnelMissing
		what := "wstunnel（WSS 承载）"
		if name == "smartdns" {
			code = CodeSmartDNSMissing
			what = "出口解析器 SmartDNS"
		}
		switch {
		case r.Arch == "":
			bp.Detail = "架构未知"
			e.out.Binaries = append(e.out.Binaries, bp)
			continue
		case !ok:
			bp.Detail = "面板没有这个架构的固定版本"
			e.add(Blocking, code, path,
				fmt.Sprintf("这个节点要运行%s，但面板没有为 %s 固定 %s 的版本：不能下发，也不会跳过它。", what, r.Arch, name),
				"换用 x86_64 或 aarch64 的服务器。")
			e.out.Binaries = append(e.out.Binaries, bp)
			continue
		case !a.Available:
			bp.Version, bp.SHA256, bp.Size = a.Version, a.SHA256, a.Size
			bp.Detail = a.Error
			e.add(Blocking, code, path,
				fmt.Sprintf("这个节点要运行%s，但面板里 %s %s（%s）的二进制不可用：%s。面板只下发与固定摘要一致的副本，不会让主机自己下载，也不会跳过它。", what, name, a.Version, r.Arch, orDash(a.Error)),
				"用包含固定二进制的面板镜像（构建时下载并校验，见 deploy/Dockerfile；离线构建把上游文件放进 deploy/artifacts/），或把校验过的文件放进 MERIDIAN_ARTIFACTS_DIR 指定的目录后重启面板，然后重新预检。")
			e.out.Binaries = append(e.out.Binaries, bp)
			continue
		}
		bp.Version, bp.SHA256, bp.Size = a.Version, a.SHA256, a.Size
		pi, seen := r.Paths[path]
		_, owned := e.own.Files[path]
		switch {
		case !seen:
			if r.Complete {
				e.add(Blocking, CodePathOccupied, path, "预检没有报告这个路径的状态（脚本拒绝了这个参数或输出不完整）。", "重新预检。")
			}
		case !pi.Exists:
			bp.Action, bp.Transfer = "install", true
			bp.Detail = fmt.Sprintf("经 SSH 传输 %s，主机上校验 SHA-256 后安装", kb((a.Size+1023)/1024))
		case pi.Type != "file":
			e.add(Blocking, CodePathOccupied, path, fmt.Sprintf("Meridian 的二进制路径 %s 上是%s，不是普通文件。", path, pi.Type), "确认它属于谁，移走后重新预检。面板不会覆盖它。")
		case pi.SHA256 == a.SHA256:
			bp.Action = "keep"
			bp.Detail = "主机上已是固定版本（摘要一致），不传输"
		case owned:
			bp.Action, bp.Transfer = "replace", true
			bp.Detail = "受管副本的摘要与固定版本不同：传输并校验后替换（失败时恢复原文件）"
		default:
			e.add(Blocking, CodePathOccupied, path,
				fmt.Sprintf("%s 已经存在，但不在 Meridian 的受管清单里，摘要也不是固定版本（%s）。", path, orDash(pi.SHA256)),
				"确认这个文件是谁放的：不是 Meridian 装的就移走它后重新预检。面板不会覆盖不属于它的文件。")
		}
		if bp.Action != "refuse" {
			e.change("binary", bp.Action, path, fmt.Sprintf("%s %s（%s，sha256 %s）", name, a.Version, r.Arch, a.SHA256[:12]))
			e.add(Info, CodeArtifact, path, fmt.Sprintf("%s %s（%s）：%s。", name, a.Version, r.Arch, bp.Detail), "")
		}
		e.out.Binaries = append(e.out.Binaries, bp)
	}
	// Somebody else's wstunnel / SmartDNS on the host.
	var foreign []string
	if r.Commands["wstunnel"] {
		v := r.Versions["wstunnel"]
		foreign = append(foreign, "wstunnel"+paren(v))
	}
	if st, ok := r.Packages["smartdns"]; ok && st.Installed != "" {
		if e.out.Ownership != OwnSame || !e.ownsPackage("smartdns") {
			foreign = append(foreign, "smartdns 软件包 "+st.Installed)
		}
	} else if r.Commands["smartdns"] && !e.ctx.Gateway {
		foreign = append(foreign, "smartdns"+paren(r.Versions["smartdns"]))
	}
	if len(foreign) > 0 && !e.ctx.Gateway {
		e.add(Info, CodeForeignBinary, strings.Join(foreign, " "),
			"主机上已有 "+strings.Join(foreign, "、")+"。Meridian 不使用、不覆盖也不删除它们：它运行自己下发的 /usr/local/sbin/meridian-wstunnel、/usr/local/sbin/meridian-smartdns（单元 meridian-smartdns.service）；端口冲突在下面单独检查。", "")
	}
}

func paren(s string) string {
	if s == "" {
		return ""
	}
	return "（" + s + "）"
}

func (e *eval) ownsPackage(p string) bool {
	return e.r.Manifest != nil && containsStr(e.r.Manifest.Packages, p)
}

// memory checks MemAvailable against the node's budget. A node whose plan
// needs a local resolver is blocked when the budget does not fit (it never
// runs without its resolver and never falls back to another one); other
// nodes get a warning. Processes this install already runs (an update)
// are part of the used memory and not counted again.
func (e *eval) memory() {
	if e.ctx.Gateway {
		return
	}
	r := e.r
	need := int64(MemHeadroomKB)
	parts := []string{fmt.Sprintf("装机余量 %s", kb(MemHeadroomKB))}
	running := func(unit string) bool { return e.out.Ownership == OwnSame && containsStr(e.own.Units, unit) }
	if e.fp.DNS && !running("meridian-smartdns.service") {
		need += MemSmartDNSKB
		parts = append(parts, fmt.Sprintf("SmartDNS %s", kb(MemSmartDNSKB)))
	}
	if containsStr(e.fp.Binaries, "wstunnel") {
		already := false
		for _, u := range e.own.Units {
			already = already || (e.out.Ownership == OwnSame && strings.HasPrefix(u, "wstunnel-"))
		}
		if !already {
			need += MemWstunnelKB
			parts = append(parts, fmt.Sprintf("wstunnel %s", kb(MemWstunnelKB)))
		}
	}
	budget := strings.Join(parts, " + ")
	switch {
	case r.MemAvailKB < 0 && e.fp.DNS:
		e.add(Blocking, CodeMemoryBudget, "memory", "读不到可用内存（MemAvailable），不能确认出口解析器的内存预算（"+budget+"）。",
			"重新预检；仍然读不到时检查 /proc/meminfo。面板不会在不确定时去掉解析器或改用别的解析器。")
	case r.MemAvailKB < 0:
	case r.MemAvailKB < need && e.fp.DNS:
		e.add(Blocking, CodeMemoryBudget, "memory",
			fmt.Sprintf("可用内存 %s，低于这个节点的预算 %s（%s）。这个节点的配置要在本机运行出口解析器：面板不会跳过它、不会改用国内或别的解析器，也不会在它起不来时声称节点可用。", kb(r.MemAvailKB), kb(need), budget),
			"先释放内存（停掉不用的服务或容器）或换一台内存更多的服务器，然后重新预检。")
	case r.MemAvailKB < need:
		e.add(Warning, CodeMemoryBudget, "memory",
			fmt.Sprintf("可用内存 %s，低于这个节点的预算 %s（%s）：装机和隧道进程可能挤占已有服务。", kb(r.MemAvailKB), kb(need), budget),
			"确认已有服务的内存余量后再继续。")
	default:
		e.add(Info, CodeMemoryBudget, "memory", fmt.Sprintf("内存预算 %s（%s），可用 %s：够用。解析器只绑定隧道地址。", kb(need), budget, kb(r.MemAvailKB)), "")
	}
}

func kb(v int64) string {
	switch {
	case v < 0:
		return "未知"
	case v >= 1024*1024:
		return fmt.Sprintf("%.1f GB", float64(v)/1024/1024)
	default:
		return fmt.Sprintf("%d MB", v/1024)
	}
}

func kernelVersion(k string) (int, int, bool) {
	parts := strings.SplitN(k, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	minStr := parts[1]
	for i, c := range minStr {
		if c < '0' || c > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, err2 := strconv.Atoi(minStr)
	return maj, min, err1 == nil && err2 == nil
}

// ---------------------------------------------------------------- paths ---

func (e *eval) paths() {
	var legacy, occupied []string
	for _, p := range e.fp.Files {
		pi, seen := e.r.Paths[p]
		if !seen {
			if e.r.Complete {
				e.add(Blocking, CodePathOccupied, p, "预检没有报告这个路径的状态（脚本拒绝了这个参数或输出不完整）。", "重新预检。")
			}
			continue
		}
		if !pi.Exists {
			e.change("file", "create", p, "")
			continue
		}
		if h, ok := e.own.Files[p]; ok {
			if h != "" && pi.SHA256 != "" && h != pi.SHA256 {
				e.add(Warning, CodeModifiedSince, p, "这个受管文件在上次安装后被改过（哈希与清单不同），安装会覆盖这些改动。", "需要保留的改动请先在拓扑里表达或另存。")
			}
			e.change("file", "replace", p, "受管文件")
			continue
		}
		switch {
		case pi.Type != "file":
			occupied = append(occupied, p+"（"+pi.Type+"）")
		case pi.Marker && e.ctx.Gateway:
			e.change("file", "replace", p, "旧版 Meridian 文件：安装事务会接管或拒绝")
		case pi.Marker:
			legacy = append(legacy, p)
		default:
			occupied = append(occupied, p)
		}
	}
	if len(occupied) > 0 {
		e.add(Blocking, CodePathOccupied, strings.Join(occupied, " "),
			"这些路径上已经有不属于 Meridian 的文件（不在受管清单里，也没有 Meridian 标记）："+strings.Join(occupied, "、")+"。装机会覆盖它们，可能破坏已有服务（例如另一份 SmartDNS 配置）。",
			"确认它们属于哪个服务：仍在用就换一台服务器或调整拓扑；确认不用了就先备份移走（mv 到别处），再重新预检。面板不会覆盖不属于它的文件。")
	}
	if len(legacy) > 0 && !e.ctx.Gateway && e.out.Ownership == OwnNone {
		e.out.Ownership = OwnLegacy
		e.add(Blocking, CodeLegacyInstall, strings.Join(legacy, " "),
			"主机上有带 Meridian 标记的文件，但没有受管清单（旧版本或手工装的）："+strings.Join(legacy, "、")+"。无法确认它们属于这个节点，也无法在失败时准确补偿。",
			"如果确认是这个节点以前装的：在部署页对这个节点做「旧版清理」——面板先只读列出旧版在固定路径上带 Meridian 标记的文件、接口、服务、nft 表和路由表，你确认这份清单后才移除（确认后清单有变化会被拒绝）；也可以登录服务器手动停掉并移走后重新预检。不确定时换一台服务器。")
	}
}

// ----------------------------------------------------------- interfaces ---

func (e *eval) ownedIface(name string) bool {
	return containsStr(e.own.Interfaces, name)
}

func (e *eval) interfaces() {
	planned := map[string]bool{}
	for _, ip := range e.fp.Interfaces {
		planned[ip.Name] = true
		exists := containsStr(e.r.Links, ip.Name)
		switch {
		case exists && e.ownedIface(ip.Name):
			e.change("interface", "update", ip.Name, "已存在、受管：wg syncconf 更新，不断开")
		case exists:
			e.add(Blocking, CodeInterfaceExists, ip.Name,
				fmt.Sprintf("网络接口 %s 已经存在，但不在 Meridian 的受管清单里。装机会对它执行 wg syncconf / wg-quick，覆盖它现有的配置。", ip.Name),
				"确认这个接口属于谁：属于别的服务就换服务器或改拓扑让 Meridian 用别的接口号；是遗留的就先 wg-quick down / ip link del 它再重新预检。")
		default:
			e.change("interface", "create", ip.Name, joinPrefixes(ip.Addresses))
		}
	}
	// Address overlap: what an interface of the bundle would get against
	// addresses already configured on other interfaces.
	for _, ip := range e.fp.Interfaces {
		for _, a := range ip.Addresses {
			for _, x := range e.r.Addrs {
				if x.Iface == ip.Name || planned[x.Iface] && e.ownedIface(x.Iface) || e.ownedIface(x.Iface) {
					continue
				}
				if x.Prefix.Addr().IsLinkLocalUnicast() || x.Prefix.Addr().IsLoopback() {
					continue
				}
				if x.Iface == "lo" && e.ownLoAddr(x.Prefix.Addr()) {
					continue
				}
				if a.Masked().Overlaps(x.Prefix.Masked()) {
					e.add(Blocking, CodeAddressOverlap, ip.Name+" "+a.String(),
						fmt.Sprintf("%s 要配置的地址 %s 与 %s 上已有的 %s 重叠：两个接口占用同一段地址，路由会互相抢。", ip.Name, a, x.Iface, x.Prefix),
						"在拓扑里换一个不重叠的隧道网段（传输段 10.66.200.0/24、隧道前缀 10.66.x.0），或确认那个接口不再使用后移除它。")
				}
			}
		}
	}
	e.staleLoAddrs()
	// Transit addresses the scripts put on lo: an address another
	// interface already holds would be answered locally instead.
	for _, a := range e.fp.LoAddrs {
		for _, x := range e.r.Addrs {
			if x.Iface == "lo" || e.ownedIface(x.Iface) || x.Prefix.Addr().IsLinkLocalUnicast() || x.Prefix.Addr().IsLoopback() {
				continue
			}
			if x.Prefix.Contains(a.Addr()) {
				e.add(Blocking, CodeAddressOverlap, "lo "+a.String(),
					fmt.Sprintf("Meridian 要放到 lo 上的中转地址 %s 落在 %s 上已有的 %s 里：发往那段的流量会被本机截住。", a, x.Iface, x.Prefix),
					"在拓扑里换用不重叠的中转网段（10.66.200.0/24、fd66:0:0:ff::/64），或确认那个接口不再使用后移除它，然后重新预检。")
			}
		}
	}
	var foreign []string
	for _, w := range e.r.WGLinks {
		if planned[w] && e.ownedIface(w) || e.ownedIface(w) {
			continue
		}
		s := w
		if p, ok := e.r.WGPorts[w]; ok {
			s += fmt.Sprintf("（UDP %d）", p)
		}
		foreign = append(foreign, s)
	}
	if len(foreign) > 0 {
		e.add(Info, CodeWireGuard, strings.Join(foreign, " "), "主机上已有别的 WireGuard 接口："+strings.Join(foreign, "、")+"。Meridian 不会碰它们；接口名、端口、地址和路由的冲突已在上面单独检查。", "")
	}
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Addr() == a {
			return true
		}
	}
	return false
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, 0, len(ps))
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, ", ")
}

// -------------------------------------------------------------- listens ---

func listenOverlaps(lp ListenPlan, l Listener) bool {
	if lp.Proto != l.Proto || lp.Port != l.Port {
		return false
	}
	pv6Any := lp.Wildcard && lp.Addr.Is6()
	lv6Any := l.Wildcard && l.Addr.Is6()
	switch {
	case pv6Any || lv6Any:
		return true
	case lp.Wildcard:
		return l.Addr.Is4()
	case l.Wildcard:
		return lp.Addr.Unmap().Is4()
	default:
		return lp.Addr.Unmap() == l.Addr.Unmap()
	}
}

// GatewayDNSContainer is the fixed name of the compose-managed SmartDNS
// container on the gateway (hostexec.SmartDNSContainer).
const GatewayDNSContainer = "meridian-smartdns"

// listenerOwned: the socket is this install's, on evidence only — a
// WireGuard interface, a unit or the gateway's SmartDNS container that the
// managed manifest (of this node and deployment) lists. Nothing is owned
// on a host without such a manifest.
func (e *eval) listenerOwned(lp ListenPlan, l Listener) bool {
	if e.out.Ownership != OwnSame {
		return false
	}
	// A kernel WireGuard socket of an interface Meridian owns.
	for iface, port := range e.r.WGPorts {
		if port == l.Port && l.Proto == "udp" && l.Process == "" && e.ownedIface(iface) {
			return true
		}
	}
	// The cgroup of the socket: a unit the manifest lists, or (gateway)
	// the compose-managed SmartDNS container, or (remote) the smartdns
	// unit when the manifest holds the resolver config.
	if l.Cgroup != "" {
		unit := CgroupUnit(l.Cgroup)
		if unit != "" && containsStr(e.own.Units, unit) {
			return true
		}
		if lp.Owner == "smartdns" && e.own.DNS {
			if unit == "smartdns.service" || unit == "meridian-smartdns.service" {
				return true
			}
			if id := CgroupContainer(l.Cgroup); id != "" && e.ctx.Gateway {
				if c, ok := e.r.Containers[GatewayDNSContainer]; ok && c.ID == id {
					return true
				}
			}
		}
	}
	// The main process of a unit Meridian owns.
	if l.PID > 0 {
		for _, u := range e.own.Units {
			if st, ok := e.r.Units[u]; ok && st.MainPID == l.PID {
				return true
			}
		}
	}
	// ss prints the 15-character comm: "meridian-smartd" for the
	// panel-delivered binary.
	if lp.Owner == "smartdns" && (l.Process == "smartdns" || l.Process == "meridian-smartd") && e.own.DNS {
		return true
	}
	return false
}

func (e *eval) listenerWho(l Listener) string {
	if l.Process != "" {
		return "进程 " + l.Process
	}
	if l.Cgroup != "" {
		if id := CgroupContainer(l.Cgroup); id != "" {
			for name, c := range e.r.Containers {
				if c.ID == id {
					return "容器 " + name
				}
			}
			return "容器 " + id[:12]
		}
		if u := CgroupUnit(l.Cgroup); u != "" {
			return "服务 " + u
		}
		return "cgroup " + l.Cgroup + " 里的进程"
	}
	if l.Proto == "udp" {
		for iface, port := range e.r.WGPorts {
			if port == l.Port {
				return "WireGuard 接口 " + iface
			}
		}
	}
	return "一个预检看不到名字的进程"
}

func (e *eval) listens() {
	for _, lp := range e.fp.Listens {
		where := lp.Addr.String()
		if lp.Addr.Is6() {
			where = "[" + where + "]"
		}
		res := fmt.Sprintf("%s %s:%d", lp.Proto, where, lp.Port)
		conflict := false
		for _, l := range e.r.Listeners {
			if !listenOverlaps(lp, l) || e.listenerOwned(lp, l) {
				continue
			}
			conflict = true
			what := map[string]string{"udp": "WireGuard 监听端口", "tcp": "WSS 监听端口"}[lp.Proto]
			if lp.Owner == "smartdns" {
				what = "出口解析器（SmartDNS）"
			} else if strings.HasPrefix(lp.Owner, "wstunnel-client") {
				what = "wstunnel 客户端本地端口"
			} else if lp.Owner == "meridian-dns-split.service" {
				what = "名单外域名检查（127.0.0.1 上固定的 5356）"
			}
			msg := fmt.Sprintf("%s（%s）要绑定 %s，但 %s 已被%s占用。", what, lp.Owner, res, l.Raw0(), e.listenerWho(l))
			action := "在拓扑里给这个节点换一个未占用的端口（链路的「WireGuard 端口」、节点的「WireGuard 监听端口」或「WSS 监听端口」），或确认占用者可以停用后再重新预检。面板不会停掉别的服务。"
			var fix *Fix
			switch {
			case lp.Owner == "meridian-dns-split.service":
				action = "名单外域名检查固定监听 127.0.0.1:5356（UDP/TCP），给网关的 SmartDNS 用。让占用者换一个端口，或在网关设置里关掉「未列名单的域名也问国内 DNS」，然后重新预检。面板不会停掉别的服务。"
			case lp.Owner == "smartdns":
				action = "出口解析器的端口固定为 53/853，只绑定隧道地址；占用者绑定了通配地址或同一个隧道地址。让占用者只绑定它自己需要的地址（例如 127.0.0.53），或换一台服务器，然后重新预检。面板不会停掉别的服务。"
			default:
				if src, ok := e.portFix(lp); ok {
					label := fieldLabels[src.Field]
					obj := "链路 " + src.ID
					if src.Kind == "node" {
						obj = "节点 " + src.ID
					}
					fix = &Fix{Kind: src.Kind, ID: src.ID, Field: src.Field, Label: obj + " 的" + label}
					action = fmt.Sprintf("在拓扑里把%s的%s（%s）改成这台主机上未占用的端口：保存后节点配置、对端的 Endpoint 和预检看到的端口会一起变化，然后重新预检。也可以确认占用者可以停用后再重新预检。面板不会停掉别的服务。", obj, label, src.What)
				}
			}
			e.addFix(Blocking, CodePortInUse, res, msg, action, fix)
		}
		if !conflict {
			e.change("listen", "bind", res, lp.Owner)
		}
	}
	// A remote resolver binds tunnel addresses only. Without any bind line
	// SmartDNS would bind [::]:53 by default, a wildcard bind answers the
	// whole internet: both refuse the install.
	if e.fp.DNS && !e.ctx.Gateway {
		n, wild := 0, []string{}
		for _, lp := range e.fp.Listens {
			if lp.Owner != "smartdns" {
				continue
			}
			n++
			if lp.Wildcard {
				wild = append(wild, fmt.Sprintf("%s %s:%d", lp.Proto, lp.Addr, lp.Port))
			}
		}
		switch {
		case n == 0:
			e.add(Blocking, CodeResolverBind, "/etc/smartdns/smartdns.conf", "这个节点的解析器配置没有 bind 行：SmartDNS 会默认绑定 [::]:53，对整个公网应答。",
				"检查拓扑里这个出口的隧道地址（解析器只绑定隧道地址）；修正后重新预检。")
		case len(wild) > 0:
			e.add(Blocking, CodeResolverBind, "/etc/smartdns/smartdns.conf", "这个节点的解析器配置绑定了通配地址（"+strings.Join(wild, "、")+"），会对公网应答。",
				"出口解析器只能绑定隧道地址；修正拓扑后重新预检。")
		}
	}
	// Port 53 listeners that are not in the way (loopback stubs, WARP):
	// reported so the operator sees they were checked.
	var dns []string
	for _, l := range e.r.Listeners {
		if l.Port != 53 {
			continue
		}
		in := false
		for _, lp := range e.fp.Listens {
			if listenOverlaps(lp, l) {
				in = true
			}
		}
		if !in {
			who := l.Process
			if who == "" {
				who = "?"
			}
			dns = appendCapped(dns, fmt.Sprintf("%s %s:53（%s）", l.Proto, l.Addr, who))
		}
	}
	if len(dns) > 0 {
		e.add(Info, CodeDNSListeners, "53", "端口 53 上已有不冲突的监听："+strings.Join(dns, "、")+"。出口解析器只绑定隧道地址，不与它们冲突。", "")
	}
}

// Raw0 is the local address of the listener as printed.
func (l Listener) Raw0() string {
	addr := l.Addr.String()
	if l.Addr.Is6() {
		addr = "[" + addr + "]"
	}
	return fmt.Sprintf("%s %s:%d", l.Proto, addr, l.Port)
}

// --------------------------------------------------------------- routes ---

func (e *eval) routes() {
	for _, rp := range e.fp.Routes {
		if rp.Table != 0 {
			continue
		}
		for _, x := range e.r.Routes {
			if x.Family != rp.Family || x.Dst.Bits() == 0 {
				continue
			}
			if x.Dev != "" && (x.Dev == rp.Dev || e.ownedIface(x.Dev)) {
				continue
			}
			if !x.Dst.Overlaps(rp.Dst) || e.samePlannedRoute(x) || e.ownLoRoute(x) {
				continue
			}
			if rp.Blackhole {
				// A fallback blackhole only matters when it is more specific
				// than an existing route (it would capture that traffic) or
				// replaces one with the same prefix and metric.
				if x.Dst.Bits() < rp.Dst.Bits() || (x.Dst == rp.Dst && x.Metric == rp.Metric) {
					e.add(Blocking, CodeRouteOverlap, rp.Dst.String(),
						fmt.Sprintf("Meridian 的兜底黑洞路由 %s（metric %d）会截走已有路由「%s」的一部分流量。", rp.Dst, rp.Metric, x.Raw),
						"在拓扑里换用不与已有网段重叠的隧道地址段，或确认那条路由不再需要。")
				}
				continue
			}
			var how string
			switch {
			case x.Dst == rp.Dst:
				how = "会替换已有路由"
			case x.Dst.Bits() < rp.Dst.Bits():
				how = "比已有路由更具体，会截走其中一部分流量"
			default:
				how = "与已有的更具体路由重叠，这部分目的地会走已有路由而不是隧道"
			}
			e.add(Blocking, CodeRouteOverlap, rp.Dst.String(),
				fmt.Sprintf("Meridian 要加的路由 %s dev %s %s「%s」。", rp.Dst, rp.Dev, how, x.Raw),
				"在拓扑里换用不重叠的网段（局域网前缀、传输段或远程接入段），或确认已有路由的服务不再使用后再重新预检。")
		}
		desc := rp.Dst.String()
		if rp.Blackhole {
			desc = "blackhole " + desc
		}
		if rp.Dev != "" {
			desc += " dev " + rp.Dev
		}
		e.change("route", "add", desc, "main 表")
	}
	tableHas := func(n int) bool {
		if e.r.TableRoutes[strconv.Itoa(n)] {
			return true
		}
		name, ok := e.r.RTNames[n]
		return ok && e.r.TableRoutes[name]
	}
	for _, n := range e.fp.Tables {
		if name, ok := e.r.RTNames[n]; ok && e.fp.TableNames[n] != "" && name != e.fp.TableNames[n] {
			e.add(Warning, CodeTableName, strconv.Itoa(n),
				fmt.Sprintf("路由表号 %d 在这台主机上已命名为 %s，Meridian 会再给它起名 %s。", n, name, e.fp.TableNames[n]),
				"如果表 "+name+" 有别的服务在用，下面会单独报告；否则可以忽略。")
		}
		if tableHas(n) && !containsInt(e.own.Tables, n) {
			e.add(Blocking, CodeTableInUse, strconv.Itoa(n),
				fmt.Sprintf("路由表 %d 里已经有路由，而 Meridian 要独占这个表（会替换其中的默认路由并加黑洞兜底）。", n),
				"确认是谁在用表 "+strconv.Itoa(n)+"（ip route show table "+strconv.Itoa(n)+"）；仍在使用就换服务器，遗留的就清空后重新预检。")
			continue
		}
		e.change("route", "add", "table "+strconv.Itoa(n), e.fp.TableNames[n])
	}
}

// ownLoRoute: the kernel route of a transit address this bundle itself
// puts on lo, on a host this install already manages.
func (e *eval) ownLoRoute(x Route) bool {
	if x.Dev != "lo" || !x.Dst.IsSingleIP() {
		return false
	}
	return e.ownLoAddr(x.Dst.Addr())
}

// ownLoAddr: an address on lo that this install put there — one the bundle
// declares, or (a topology change removed an exit or a group) a previous
// install's transit address inside Meridian's own transit prefixes, which
// the routes script deletes. Only on a host this install already manages.
func (e *eval) ownLoAddr(a netip.Addr) bool {
	if e.out.Ownership != OwnSame {
		return false
	}
	if containsAddr(e.fp.LoAddrs, a) {
		return true
	}
	for _, n := range e.fp.LoNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// staleLoAddrs lists a previous install's transit addresses on lo that the
// new plan no longer uses, as changes (they are removed by the install).
func (e *eval) staleLoAddrs() {
	if e.out.Ownership != OwnSame {
		return
	}
	for _, x := range e.r.Addrs {
		if x.Iface != "lo" || containsAddr(e.fp.LoAddrs, x.Prefix.Addr()) {
			continue
		}
		for _, n := range e.fp.LoNets {
			if n.Contains(x.Prefix.Addr()) {
				e.change("address", "remove", "lo "+x.Prefix.String(), "上一次安装放在 lo 上的中转地址，这次的拓扑不再使用")
				break
			}
		}
	}
}

// samePlannedRoute: an existing route identical to one the bundle installs
// (the previous install's, or an equal one): replacing it changes nothing.
func (e *eval) samePlannedRoute(x Route) bool {
	for _, rp := range e.fp.Routes {
		if rp.Table != 0 || rp.Family != x.Family || rp.Dst != x.Dst {
			continue
		}
		if rp.Blackhole && x.Type != "" && rp.Metric == x.Metric {
			return true
		}
		if !rp.Blackhole && x.Type == "" && rp.Dev != "" && rp.Dev == x.Dev {
			return true
		}
	}
	return false
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- rules ---

func normMark(m string) string {
	if i := strings.Index(m, "/"); i >= 0 {
		m = m[:i]
	}
	m = strings.ToLower(m)
	if n, err := strconv.ParseUint(strings.TrimPrefix(m, "0x"), 16, 32); err == nil && strings.HasPrefix(m, "0x") {
		return fmt.Sprintf("0x%x", n)
	}
	if n, err := strconv.ParseUint(m, 10, 32); err == nil {
		return fmt.Sprintf("0x%x", n)
	}
	return m
}

func (e *eval) ruleOwned(x Rule) bool {
	// A rule that looks up a table Meridian owns, or exactly matches a
	// planned rule.
	if n, err := strconv.Atoi(x.Table); err == nil && containsInt(e.own.Tables, n) {
		return true
	}
	for n, name := range e.r.RTNames {
		if name == x.Table && containsInt(e.own.Tables, n) {
			return true
		}
	}
	if x.Iif != "" && e.ownedIface(x.Iif) {
		return true
	}
	// On a host Meridian already manages for this node, a rule at one of
	// the planned priorities with the planned mark is the previous
	// install's (e.g. "fwmark 0x101 unreachable", "fwmark 0x4d72 lookup
	// main", which name no Meridian table).
	if e.out.Ownership == OwnSame {
		for _, ru := range e.fp.Rules {
			if ru.Family == x.Family && ru.Priority == x.Priority && (ru.Fwmark == "" || normMark(ru.Fwmark) == normMark(x.Fwmark)) {
				return true
			}
		}
	}
	return false
}

func (e *eval) rules() {
	// Egress of every node uses the main table (exits) or Meridian's own
	// rules (gateway, hubs, relays): a catch-all rule before the first of
	// them, or before main, decides first.
	minPrio := 32766
	marks := map[string]bool{}
	for _, m := range e.fp.Marks {
		marks[normMark(m)] = true
	}
	for _, ru := range e.fp.Rules {
		if ru.Priority < minPrio {
			minPrio = ru.Priority
		}
		if ru.Fwmark != "" && !strings.Contains(ru.Fwmark, "$") {
			marks[normMark(ru.Fwmark)] = true
		}
	}
	shared := map[int]bool{}
	for _, x := range e.r.Rules {
		if (x.Table == "local" || x.Table == "main" || x.Table == "default") && x.Fwmark == "" {
			continue
		}
		if e.ruleOwned(x) {
			continue
		}
		if x.Fwmark != "" && marks[normMark(x.Fwmark)] {
			e.add(Blocking, CodeFwmarkInUse, normMark(x.Fwmark),
				fmt.Sprintf("已有策略规则「%s」用的防火墙标记 %s 正是 Meridian 要用的标记；两边的路由决定会互相干扰。", x.Raw, normMark(x.Fwmark)),
				"确认这条规则属于哪个服务；Meridian 的标记目前不能在面板里改，冲突时换一台服务器。")
		}
		for _, ru := range e.fp.Rules {
			if ru.Family == x.Family && ru.Priority == x.Priority && !shared[x.Priority] {
				shared[x.Priority] = true
				e.add(Warning, CodeRulePriority, strconv.Itoa(x.Priority),
					fmt.Sprintf("优先级 %d 上已有规则「%s」，Meridian 也会在这个优先级加规则；同优先级按插入先后匹配。", x.Priority, x.Raw),
					"确认两条规则的匹配条件不重叠（例如来源网段不同）；重叠时换服务器。")
			}
		}
		catchAll := (x.From == "" || x.From == "all") && x.Iif == "" && x.Oif == "" && x.To == "" && (x.Fwmark == "" || x.Not)
		if x.Priority < minPrio && catchAll && x.Table != "" && x.Table != "local" && x.Table != "main" && x.Table != "default" && e.r.TableDefault[x.Table] {
			e.add(Warning, CodeRulePrecedes, x.Raw,
				fmt.Sprintf("规则「%s」排在 Meridian 依赖的路由（优先级 %d 起，含 main 表）之前，把几乎所有流量交给表 %s，而表 %s 有默认路由：经隧道进来的流量可能从那个表（例如 WARP）出去，而不是本机 WAN。", x.Raw, minPrio, x.Table, x.Table),
				"确认这是你想要的出口方式；不想要的话调整那个服务的路由设置（例如 WARP 的排除规则）后重新预检。")
		}
	}
	for _, ru := range e.fp.Rules {
		e.change("rule", "add", fmt.Sprintf("%d: %s", ru.Priority, ru.Selector), fmt.Sprintf("IPv%d", ru.Family))
	}
}

// ------------------------------------------------------------------ nft ---

func (e *eval) nft() {
	for _, t := range e.fp.NFTTables {
		exists := containsStr(e.r.NFTTables, t)
		switch {
		case exists && containsStr(e.own.NFTTables, t):
			e.change("nft", "replace", t, "受管表：原子替换")
		case exists:
			e.add(Blocking, CodeNFTTableExists, t,
				fmt.Sprintf("nft 表 %s 已经存在但不在受管清单里；装机会整表删除并重建它。", t),
				"确认是谁建的这个表（nft list table "+t+"）；是旧版 Meridian 留下的就删除后重新预检，否则换服务器。")
		default:
			e.change("nft", "create", t, "")
		}
	}
	var other []string
	for _, t := range e.r.NFTTables {
		if !containsStr(e.fp.NFTTables, t) && !containsStr(e.own.NFTTables, t) {
			other = append(other, t)
		}
	}
	if len(other) > 0 {
		e.add(Info, CodeNFTOther, strings.Join(other, " "), "主机上已有别的 nft 表："+strings.Join(other, "、")+"。Meridian 不会碰它们；会影响转发的情况在下面单独报告。", "")
	}
}

// ------------------------------------------------------------- firewall ---

func (e *eval) firewall() {
	for _, fam := range []struct {
		name string
		on   bool
		nft  []string
	}{{"ipv4", e.fp.Forward4, []string{"ip", "inet"}}, {"ipv6", e.fp.Forward6, []string{"ip6", "inet"}}} {
		if !fam.on {
			continue
		}
		tool := "iptables"
		if fam.name == "ipv6" {
			tool = "ip6tables"
		}
		var src, other []string
		iptDrop := false
		for _, p := range e.r.Policies {
			if p.Family == fam.name && p.Chain == "FORWARD" && (p.Policy == "DROP" || p.Policy == "REJECT") {
				iptDrop = true
				src = append(src, fmt.Sprintf("%s filter 表 FORWARD 策略 %s", tool, p.Policy))
			}
		}
		for _, c := range e.r.Chains {
			fam0 := strings.SplitN(c.Table, " ", 2)[0]
			if c.Hook != "forward" || c.Policy != "drop" || !containsStr(fam.nft, fam0) || containsStr(e.fp.NFTTables, c.Table) {
				continue
			}
			if (c.Table == "ip filter" || c.Table == "ip6 filter") && c.Name == "FORWARD" {
				// iptables-nft shows the same policy as table ip filter.
				if iptDrop {
					continue
				}
				iptDrop = true
				src = append(src, fmt.Sprintf("%s filter 表 FORWARD 策略 DROP（nft 表 %s）", tool, c.Table))
				continue
			}
			s := fmt.Sprintf("nft 表 %s 的链 %s（hook forward，policy drop）", c.Table, c.Name)
			src = append(src, s)
			other = append(other, s)
		}
		if len(src) == 0 {
			continue
		}
		docker := e.dockerRunning()
		cause := ""
		if docker {
			cause = "（Docker 在运行，这通常是 Docker 设置的）"
		}
		why := e.fwCompatBlockers(fam.name, iptDrop, other)
		if len(why) == 0 {
			e.fwCompatPlan(fam.name, tool, strings.Join(src, "；")+cause)
			continue
		}
		ifaces := []string{}
		for _, ip := range e.fp.Interfaces {
			ifaces = append(ifaces, ip.Name)
		}
		e.add(Blocking, CodeForwardDrop, fam.name+" FORWARD",
			fmt.Sprintf("%s 转发会被丢弃：%s%s。Meridian 自己的 nft 转发链是 policy accept，但不能救回被别的表丢掉的包；从隧道进来、经 WAN 网卡转发出去的流量会被丢弃，节点装上也不通。面板不能在这台主机上安全地共存：%s。",
				fam.name, strings.Join(src, "；"), cause, strings.Join(why, "；")),
			"这一版面板不会替你改 Docker、ufw、firewalld 或别的防火墙的规则和策略。只有在 FORWARD 的 DROP 来自 iptables 的默认策略、主机上有 Docker 的 DOCKER-USER 链（FORWARD 先跳到它）、没有 ufw / firewalld、也没有别的 nft 表丢弃转发时，面板才会在 DOCKER-USER 里加只匹配隧道接口（"+strings.Join(ifaces, "、")+"）的放行规则。"+
				"按上面的原因处理（例如停用 ufw / firewalld 或把隧道接口的转发加进它们的放行规则），或换一台没有这类策略的服务器，然后重新预检。")
	}
}

// fwCompatBlockers says why the DOCKER-USER coexistence rules cannot be
// relied on for this family (empty: they can).
func (e *eval) fwCompatBlockers(fam string, iptDrop bool, other []string) []string {
	var why []string
	if e.ctx.Gateway {
		why = append(why, "网关不使用这套共存规则（deploy/debian/install.sh 让 Docker 不碰 iptables；网关上出现 FORWARD DROP 说明 daemon.json 没有按安装文档设置）")
		return why
	}
	if len(e.fp.FWRules) == 0 {
		why = append(why, "这个节点的配置里没有共存规则（meridian-fwcompat.sh）")
		return why
	}
	if len(other) > 0 {
		why = append(why, "丢弃来自别的 nft 表（"+strings.Join(other, "、")+"），DOCKER-USER 里的放行救不回它")
	}
	if on, how := e.ufwEnforcing(); on {
		why = append(why, "ufw 已启用（"+how+"）：它自己管理 FORWARD（重载时会重排或清掉规则），面板不与它共存")
	}
	if e.r.Units["firewalld.service"].Active == "active" {
		why = append(why, "firewalld 在运行：它自己管理 FORWARD（重载时会重排或清掉规则），面板不与它共存")
	}
	if !iptDrop {
		return why
	}
	chain, reported := e.r.IptChains[fam+" DOCKER-USER"]
	switch {
	case !reported:
		why = append(why, "预检没有报告 DOCKER-USER 链是否存在（旧版预检或 iptables 读不到）")
	case !chain:
		why = append(why, "没有 DOCKER-USER 链：这个 DROP 不是 Docker 设的，或 Docker 没有管理 iptables")
	default:
		jumped := false
		for _, t := range e.r.IptForward[fam] {
			if t == "DOCKER-USER" {
				jumped = true
				break
			}
			if t == "DROP" || t == "REJECT" {
				why = append(why, "FORWARD 链在跳到 DOCKER-USER 之前就有 "+t+" 规则")
				break
			}
		}
		if !jumped && len(why) == 0 {
			why = append(why, "FORWARD 链不跳到 DOCKER-USER（或预检没有读到 FORWARD 的规则）")
		}
	}
	return why
}

// fwCompatPlan: the drop is Docker's iptables policy and DOCKER-USER can
// carry the coexistence rules. Not blocking; the rules are part of the
// change list.
func (e *eval) fwCompatPlan(fam, tool, src string) {
	have := e.r.IptOurs[fam]
	state := "这台主机上还没有 Meridian 的规则，装机时加入"
	if have > 0 {
		state = fmt.Sprintf("DOCKER-USER 里已有 %d 条带 Meridian 注释的规则（之前的安装）：补齐缺的，删掉旧规则集的", have)
	}
	e.add(Warning, CodeForwardDrop, fam+" FORWARD",
		fmt.Sprintf("%s 转发会被 %s 丢弃。面板会在 %s 的 DOCKER-USER 链（Docker 留给管理员、FORWARD 最先跳到的链）顶部加 %d 条 ACCEPT 规则，只匹配 Meridian 自己的接口（隧道进、WAN 出及其回程；节点做中转时隧道之间），每条带注释 %s。"+
			"不改 Docker 的链和规则、不改任何策略、不清空任何链；Docker 重启重建链时由 meridian-fwcompat.service 重新加上，开机由 meridian-node.service 在 Docker 之后加上；撤回和失败补偿按注释精确删除，只删带 Meridian 注释的规则。%s。",
			fam, src, tool, len(e.fp.FWRules), e.fp.FWTag, state),
		"确认这些规则（「拟执行的变更」里的「转发放行规则」）可以接受。netfilter-persistent 之类的工具若把当前规则保存下来，这些规则也会被保存：撤回后请重新保存一次。")
	for _, r := range e.fp.FWRules {
		action := "add"
		if have > 0 {
			action = "update"
		}
		e.change("firewall", action, fmt.Sprintf("%s -I %s %s -m comment --comment %s -j ACCEPT", tool, e.fp.FWChain, r, e.fp.FWTag), fam+" FORWARD 策略 DROP")
	}
}

// fwCompatSummary says, per family, what meridian-fwcompat.sh will do on
// this host as reported (it decides again at every run).
func (e *eval) fwCompatSummary() {
	if e.ctx.Gateway || len(e.fp.FWRules) == 0 {
		return
	}
	var parts []string
	for _, fam := range []struct{ name, tool string }{{"ipv4", "iptables"}, {"ipv6", "ip6tables"}} {
		if c, ok := e.r.Commands[fam.tool]; ok && !c {
			parts = append(parts, fam.name+"：没有 "+fam.tool+"，不加规则")
			continue
		}
		pol := ""
		for _, p := range e.r.Policies {
			if p.Family == fam.name && p.Chain == "FORWARD" {
				pol = p.Policy
			}
		}
		switch pol {
		case "DROP", "REJECT":
			parts = append(parts, fmt.Sprintf("%s：FORWARD 策略 %s，在 DOCKER-USER 加 %d 条（能否共存见上）", fam.name, pol, len(e.fp.FWRules)))
		case "ACCEPT":
			parts = append(parts, fam.name+"：FORWARD 策略 ACCEPT，不加规则（之前加过的 Meridian 规则会删掉）")
		default:
			parts = append(parts, fam.name+"：读不到 FORWARD 策略")
		}
	}
	e.add(Info, CodeFWCompat, e.fp.FWChain,
		"转发共存（meridian-fwcompat.sh）："+strings.Join(parts, "；")+"。每次运行（装机、开机、Docker 重启）按当时的策略决定：以后某个族变成 DROP 时，它在下一次 Docker 启动或 meridian-up.sh 时自动补上；FORWARD 是 DROP 却没有 DOCKER-USER 时它不改任何东西，让 meridian-up.sh 失败（服务显示 failed），隧道不会起来。", "")
}

func (e *eval) dockerRunning() bool {
	return e.r.Units["docker.service"].Active == "active" || e.r.Procs["dockerd"]
}

// ---------------------------------------------------------- environment ---

func (e *eval) environment() {
	r := e.r
	if e.dockerRunning() {
		e.add(Info, CodeDocker, "docker", "Docker 在运行（可能有 host 网络的容器占用端口；端口冲突已在上面检查）。", "")
	} else if e.fp.Docker && !r.Commands["docker"] {
		e.add(Info, CodeDockerMissing, "docker", "这个节点的解锁探测或 Mesh 备路要用 Docker，主机上没有 Docker：这两项会跳过并如实报告，不影响隧道。", "需要它们时先装 Docker。")
	}
	e.warp()
	if st := r.Units["netfilter-persistent.service"]; st.Active == "active" || st.Enabled == "enabled" {
		e.add(Info, CodeNetfilterPersis, "netfilter-persistent", "netfilter-persistent 已启用：开机时会恢复保存的 iptables 规则。它不管理 Meridian 的 nft 表；如果保存的规则里 FORWARD 是 DROP，上面会报告。"+
			"注意：有人执行 netfilter-persistent save 时，Meridian 在 DOCKER-USER 里带注释的放行规则也会被存下来；撤回只删运行中的规则，撤回后请再保存一次。", "")
	}
	e.nftFlush()
	if on, how := e.ufwEnforcing(); on {
		e.add(Warning, CodeFirewallManager, "ufw.service", "ufw 已启用（"+how+"）：它管理主机防火墙，可能拦截隧道端口或转发，也可能在重载时改动规则。",
			"确认它放行了 Meridian 要监听的端口和隧道接口的转发。")
	} else if r.Units["ufw.service"].Active == "active" {
		e.add(Info, CodeFirewallInactive, "ufw.service", "ufw.service 处于 active，但 ufw 没有启用（"+how+"）：Ubuntu 上这个单元在防火墙关闭时也显示 active，它不管理任何规则，不算防火墙管理器。以后执行 ufw enable 会让它接管 FORWARD，届时需重新预检。", "")
	}
	// firewalld.service is the daemon itself (Type=dbus): active means it is
	// running and managing the rules (firewall-cmd --state = running).
	if r.Units["firewalld.service"].Active == "active" {
		e.add(Warning, CodeFirewallManager, "firewalld.service", "firewalld 在运行：它管理主机防火墙，可能拦截隧道端口或转发，也可能在重载时改动规则。",
			"确认它放行了 Meridian 要监听的端口和隧道接口的转发。")
	}
	if strings.Contains(r.Iptables, "legacy") {
		e.add(Info, CodeIptablesLegacy, "iptables",
			"iptables 用的是 legacy 后端（"+r.Iptables+"）。面板不切换后端、不改 alternatives、不动已有的 legacy 规则。"+
				"Meridian 的 nft 表（inet meridian 等）和 legacy 的 iptables 表都挂在内核同一组 netfilter 钩子上：一个包依次经过两边的链，"+
				"同一钩子上按优先级从小到大（legacy 的 mangle −150、nat 目的 −100、filter 0、nat 源 100，与 nft 的 mangle/dstnat/filter/srcnat 同值；同值时先后不保证）；"+
				"任何一边的 drop 都是最终的，一边的 accept 不能放行另一边丢弃的包；一条连接的 NAT 由先处理它的 nat 链决定。"+
				"预检检查了 legacy filter 表 INPUT/FORWARD 的默认策略（iptables -S）；不检查 legacy 链里的单条规则（例如只丢某个端口或接口的 DROP/REJECT）、legacy nat 表里会改写隧道流量的规则，以及 legacy mangle 表打的 MARK 是否与 Meridian 的标记冲突。", "")
	}
	// Input policy: a public listener behind an INPUT policy of DROP.
	var public []string
	for _, lp := range e.fp.Listens {
		if lp.Wildcard {
			public = append(public, fmt.Sprintf("%s %d", lp.Proto, lp.Port))
		}
	}
	if len(public) > 0 {
		for _, p := range r.Policies {
			if p.Chain == "INPUT" && p.Policy == "DROP" {
				e.add(Warning, CodeInputDrop, p.Family+" INPUT",
					fmt.Sprintf("%s 的 INPUT 策略是 DROP，而这个节点要在公网上监听 %s；没有放行规则时对端连不上。", p.Family, strings.Join(public, "、")),
					"确认防火墙放行了这些端口（预检看不到放行规则是否覆盖它们）。")
			}
		}
	}
	summary := fmt.Sprintf("%s，%s，内核 %s", orDash(r.OSPretty), orDash(r.Arch), orDash(r.Kernel))
	e.add(Info, CodeHostSummary, "host", "主机："+summary+"。", "")
}

// nftFlush: nftables.service would wipe Meridian's tables. Debian's and
// Ubuntu's unit flush the whole ruleset when they stop (ExecStop), and a
// stock /etc/nftables.conf starts with "flush ruleset", so a reload does
// too. Neither can be made fail-closed from outside the host's own
// configuration (on the gateway forwarding would stay on without the
// guard until meridian-up.sh runs again), so an enabled or running service
// that flushes refuses the install before anything changes. The panel does
// not edit the host's config.
func (e *eval) nftFlush() {
	r := e.r
	st, ok := r.Units["nftables.service"]
	if !ok || st.Enabled == "not-found" || st.Enabled == "masked" || (st.Enabled == "" || st.Enabled == "-") && st.Active != "active" {
		return
	}
	var how []string
	if r.NFTConf == "flush" {
		how = append(how, "/etc/nftables.conf 里有 flush ruleset：reload / restart 时清空整个规则集")
	}
	if r.NFTStop == "flush" {
		how = append(how, "它的 ExecStop 是 nft flush ruleset：stop / restart 时清空整个规则集")
	}
	if len(how) == 0 {
		return
	}
	enabled := strings.HasPrefix(st.Enabled, "enabled")
	what := "Meridian 的表（以及 Docker 写进 nft 的 iptables 规则）"
	if e.ctx.Gateway {
		what = "Meridian 的表，包括局域网兜底表 inet meridian_guard（转发仍开着，局域网流量会不经分类直接经 ROS 出去）"
	}
	if enabled || st.Active == "active" {
		state := []string{}
		if enabled {
			state = append(state, "已启用（开机启动）")
		}
		if st.Active == "active" {
			state = append(state, "正在运行")
		}
		e.add(Blocking, CodeNFTFlush, "nftables.service",
			"nftables.service "+strings.Join(state, "、")+"，而且"+strings.Join(how, "；")+"。任何人或任何软件执行 systemctl reload / restart / stop nftables 都会清掉"+what+"，直到下次下发或重新执行 meridian-up.sh。这在主机自己的配置之外无法做到失败关闭，所以在改动任何东西之前拒绝。",
			"面板不改这台主机自己的 nftables 配置。任选其一后重新预检：① 主机不靠 nftables.service 加载自己的规则：systemctl disable nftables.service，然后在合适的时候重启主机（不要执行 systemctl stop nftables：它停止时会清空整个规则集，连 Docker 的规则一起清掉）；"+
				"② 主机需要它：把 /etc/nftables.conf 里的 flush ruleset 换成只删除它自己定义的表（例如在 table inet filter { … } 之前写 table inet filter 和 delete table inet filter 两行），并用 systemctl edit nftables.service 加一个 drop-in，在 [Service] 下写一行空的 ExecStop= 去掉停止时的整表清空，然后 systemctl daemon-reload。")
		return
	}
	// Disabled and not running is the distribution default (Debian ships
	// nftables.service disabled with a flushing /etc/nftables.conf): not
	// reported, docs/architecture.md names the manual start as a limit.
}

// warp recognises a host-level Cloudflare WARP client, shows what it is
// and the dependency clues that could be read safely, and checks that
// Meridian's marks, tables and rule priorities do not collide with it.
func (e *eval) warp() {
	r := e.r
	var warp []string
	if r.Procs["warp-svc"] || r.Units["warp-svc.service"].Active == "active" {
		warp = append(warp, "进程 warp-svc")
	}
	for _, l := range r.Links {
		if strings.EqualFold(l, "CloudflareWARP") {
			warp = append(warp, "接口 "+l)
		}
	}
	for _, t := range r.NFTTables {
		if strings.Contains(t, "cloudflare") {
			warp = append(warp, "nft 表 "+t)
		}
	}
	cgnat := netip.MustParsePrefix("100.96.0.0/12")
	warp6 := netip.MustParsePrefix("2606:4700:cf1::/48")
	for _, a := range r.Addrs {
		if cgnat.Overlaps(a.Prefix.Masked()) || warp6.Overlaps(a.Prefix.Masked()) {
			warp = appendCapped(warp, "地址 "+a.Prefix.String()+"（"+a.Iface+"）")
		}
	}
	if len(warp) == 0 {
		return
	}
	// WARP's policy rule: "not fwmark 0x100cf lookup 65743" ahead of main.
	var rules, collide []string
	warpTables := map[string]bool{}
	for _, x := range r.Rules {
		if x.Not && x.Fwmark != "" && normMark(x.Fwmark) == "0x100cf" {
			rules = appendCapped(rules, fmt.Sprintf("IPv%d 优先级 %d：%s", x.Family, x.Priority, strings.TrimSpace(x.Raw[strings.Index(x.Raw, ":")+1:])))
			warpTables[x.Table] = true
			for _, ru := range e.fp.Rules {
				if ru.Family == x.Family && ru.Priority == x.Priority {
					collide = appendCapped(collide, fmt.Sprintf("Meridian 也用优先级 %d", x.Priority))
				}
			}
		}
	}
	for _, m := range e.fp.Marks {
		if normMark(m) == "0x100cf" {
			collide = appendCapped(collide, "Meridian 的标记 0x100cf 与 WARP 相同")
		}
	}
	for t := range warpTables {
		if n, err := strconv.Atoi(t); err == nil && containsInt(e.fp.Tables, n) {
			collide = appendCapped(collide, "Meridian 也用路由表 "+t)
		}
		for _, nt := range e.fp.NFTTables {
			if strings.Contains(nt, "cloudflare") {
				collide = appendCapped(collide, "nft 表 "+nt)
			}
		}
	}
	minPrio := 32766
	for _, ru := range e.fp.Rules {
		if ru.Priority < minPrio {
			minPrio = ru.Priority
		}
	}
	route := "Meridian 节点上的出口流量走 main 表：WARP 的规则排在 main 之前，未带 0x100cf 标记的包先查 WARP 的表"
	for t := range warpTables {
		if r.TableDefault[t] {
			route += "；表 " + t + " 有默认路由（全局模式），经隧道进来的流量会从 WARP 出去而不是本机 WAN（下面「规则排在前面」一项另有提示）"
		} else {
			route += "；表 " + t + " 没有默认路由，只有它自己的网段（例如 Mesh 的 100.96.0.0/12）会进 WARP，其余落回 main"
		}
	}
	if len(e.fp.Rules) > 0 {
		route += fmt.Sprintf("。Meridian 自己的策略规则从优先级 %d 起，都排在 WARP 的规则之前，它们查的 Meridian 路由表不受 WARP 影响", minPrio)
	}
	deps := "没有读到依赖线索"
	if len(r.WARPDeps) > 0 {
		deps = "依赖线索：" + strings.Join(r.WARPDeps, "、")
	}
	collision := "Meridian 的标记、路由表、nft 表和规则优先级与它不冲突"
	if len(collide) > 0 {
		collision = "冲突：" + strings.Join(collide, "、")
	}
	msg := "检测到主机级 Cloudflare WARP 客户端：" + strings.Join(warp, "、") + "。"
	if len(rules) > 0 {
		msg += "它的策略规则：" + strings.Join(rules, "；") + "。"
	}
	msg += route + "。它在 127.0.2.2 / 127.0.2.3 和自己的叠加地址上监听 53，Meridian 的出口解析器只绑定受管隧道地址，不与它冲突。" + collision + "。" + deps + "（只读进程名和地址：连到它本地监听的进程、指向它的 resolv.conf）。Meridian 不碰它，也不会停用它。"
	sev := Info
	if len(collide) > 0 {
		sev = Blocking
	}
	e.add(sev, CodeWARP, "warp-svc", msg, "冲突时换一台服务器，或先按 WARP 的文档调整它的设置后重新预检。若 WARP 的规则把出口流量引走，会在「规则排在前面」一项里提示。")
	if e.fp.Mesh {
		e.add(Warning, CodeWARPSidecar, "warp-svc",
			"这个节点的配置带 Cloudflare Mesh sidecar 的文件，而主机上已有 WARP 客户端：两者的策略规则、路由表、标记和 53 端口能否共存没有被确认，面板的 Mesh 部署会拒绝这台主机（Mesh 预检报 host_warp）。节点包本身照常安装，sidecar 没有令牌时不会启动。",
			"停用主机上的旧 WARP 客户端是一个要你单独确认的步骤（后续版本提供），面板不会在部署时顺带停用它，也不会清理 Cloudflare 账户里的旧设备；在那之前这台主机不走 Mesh 备路。")
	}
}

// ----------------------------------------------------------------- plan ---

func (e *eval) plan() {
	r := e.r
	for _, p := range e.fp.Packages {
		if !e.ctx.Gateway && !r.Commands[p.Command] {
			detail := "apt-get install --no-install-recommends（失败补偿时不卸载）"
			if st, ok := r.Packages[p.Package]; ok && st.Candidate != "" {
				detail = "apt-get install --no-install-recommends，候选版本 " + st.Candidate + "（失败补偿时不卸载）"
			}
			e.change("package", "install", p.Package, detail)
		}
	}
	if e.fp.Forward4 && r.Sysctl["net.ipv4.ip_forward"] != "1" {
		e.change("sysctl", "set", "net.ipv4.ip_forward=1", "当前 "+orDash(r.Sysctl["net.ipv4.ip_forward"]))
		e.add(Info, CodeForwardEnable, "net.ipv4.ip_forward", "这台主机现在没有开 IPv4 转发（"+orDash(r.Sysctl["net.ipv4.ip_forward"])+"）；装机会全局打开它。", "主机上若有依赖「不转发」的设置，请先评估。")
	}
	if e.fp.Forward6 && r.Sysctl["net.ipv6.conf.all.forwarding"] != "1" {
		e.change("sysctl", "set", "net.ipv6.conf.all.forwarding=1", "当前 "+orDash(r.Sysctl["net.ipv6.conf.all.forwarding"])+"；打开后这台主机不再接受 IPv6 路由通告（除非 accept_ra=2）")
	}
	e.sysctlPlan()
	for _, u := range e.fp.Units {
		e.change("unit", "enable", u, "")
	}
	if !e.ctx.Gateway {
		e.change("state", "create", "/var/lib/meridian/node/manifest", "受管清单：记录这次装的文件、接口、服务、表")
	}
}

// sysctlPlan previews the kernel keys: every global key the install sets
// (it affects every interface on the host) one by one, and the
// per-interface hardening once, with the interfaces it is limited to.
func (e *eval) sysctlPlan() {
	r := e.r
	var global []string
	for _, k := range e.fp.SysctlKeys {
		if !IsGlobalSysctl(k) || k == "net.ipv4.ip_forward" || k == "net.ipv6.conf.all.forwarding" {
			continue
		}
		global = append(global, k)
		cur := "当前未知"
		if v, ok := r.Sysctl[k]; ok {
			cur = "当前 " + v
		}
		e.change("sysctl", "set", k, "全局（影响所有接口），"+cur)
	}
	if len(e.fp.SysctlIfaces) > 0 {
		e.change("sysctl", "set", "rp_filter=2、send_redirects=0、accept_redirects=0", "只在这些接口："+strings.Join(e.fp.SysctlIfaces, " ")+"（受管隧道接口和拓扑里的网卡）；Docker、WARP 等其它接口不改")
	}
	if len(e.fp.SysctlKeys) == 0 {
		return
	}
	rp := "当前 net.ipv4.conf.all.rp_filter=" + orDash(r.Sysctl["net.ipv4.conf.all.rp_filter"])
	allRP := containsStr(e.fp.SysctlKeys, "net.ipv4.conf.all.rp_filter")
	msg := "内核参数：只改受管接口（" + strings.Join(e.fp.SysctlIfaces, " ") + "）上的 rp_filter / ICMP 重定向，其它接口（Docker、WARP、你自己的）不碰。"
	if len(global) > 0 {
		msg += "会改的全局参数：" + strings.Join(global, "、") + "。"
	}
	msg += "内核对 rp_filter 取 max(all, 接口)：受管接口设为 2 后不论 all 是多少都是宽松模式；"
	if allRP {
		msg += "这台是网关，all/default 也设为 2（" + rp + "）。"
	} else {
		msg += "这里不改 all/default（" + rp + "），其它接口保持原样。send_redirects 是 all 与接口取或，所以 all.send_redirects=0 是必需的全局项（只影响自身值为 0 的接口）。"
	}
	msg += "转发（ip_forward / all.forwarding）是全局开关，见上一项；第一次装机失败时，补偿把这些键恢复成装机前读到的值；撤回不改运行中的值（Docker 等也依赖转发），重启后不再设置。"
	e.add(Info, CodeSysctlScope, "sysctl", msg, "")
}

// wan checks a remote node's WAN interface against the host: it must exist
// and carry the default route of every family the node needs (an exit's
// egress families; any default route for a hub or relay). An unset
// wan_interface means eth0 in the compiled scripts: the panel does not
// adopt another interface silently, it blocks and names the interface the
// host's default route uses, with a link to the node's wan_interface.
func (e *eval) wan() {
	fp := e.fp
	if e.ctx.Gateway || fp.WAN == "" {
		return
	}
	defs := map[int][]string{}
	for _, rt := range e.r.Routes {
		if rt.Dst.Bits() != 0 || rt.Type != "" {
			continue
		}
		dev := rt.Dev
		if dev == "" {
			dev = "（未知接口）"
		}
		if !containsStr(defs[rt.Family], dev) {
			defs[rt.Family] = append(defs[rt.Family], dev)
		}
	}
	where := func(fam int) string {
		if len(defs[fam]) == 0 {
			return fmt.Sprintf("这台主机没有 IPv%d 默认路由", fam)
		}
		return fmt.Sprintf("IPv%d 默认路由在 %s 上", fam, strings.Join(defs[fam], "、"))
	}
	src := "拓扑里的「WAN 接口」"
	if !fp.WANSet {
		src = "「WAN 接口」没填，按默认的"
	}
	fix := &Fix{Kind: "node", ID: e.ctx.NodeID, Field: "wan_interface", Label: "节点 " + e.ctx.NodeID + " 的" + fieldLabels["wan_interface"]}
	why := "这个名字用在出口的 NAT、没有 IPv6 出口时的 IPv6 丢弃、DOCKER-USER 放行规则和内核参数里：名字不对时它们都静默落空（NAT 不生效、转发被丢弃）。"
	action := "在拓扑里把这个节点的「WAN 接口」改成主机上带默认路由的网卡（见上），保存后重新预检。面板不会自己换成别的网卡。"
	if !containsStr(e.r.Links, fp.WAN) {
		e.addFix(Blocking, CodeWANMissing, fp.WAN,
			fmt.Sprintf("%s %s 在这台主机上不存在（%s；%s）。%s", src, fp.WAN, where(4), where(6), why), action, fix)
		return
	}
	var bad []string
	for _, n := range fp.WANNeed {
		switch n {
		case "4", "6":
			fam := 4
			if n == "6" {
				fam = 6
			}
			if !containsStr(defs[fam], fp.WAN) {
				bad = append(bad, fmt.Sprintf("这个节点要从 WAN 出 IPv%d，但%s，不在 %s 上", fam, where(fam), fp.WAN))
			}
		case "any":
			if !containsStr(defs[4], fp.WAN) && !containsStr(defs[6], fp.WAN) {
				bad = append(bad, fmt.Sprintf("%s 上没有任何默认路由（%s；%s）", fp.WAN, where(4), where(6)))
			}
		}
	}
	if len(bad) > 0 {
		split := ""
		if len(defs[4]) == 1 && len(defs[6]) == 1 && defs[4][0] != defs[6][0] && len(fp.WANNeed) == 2 {
			split = "IPv4 和 IPv6 的默认路由在两块不同的网卡上，而 Meridian 的出口只用一块 WAN 网卡做两种协议的 NAT：把「WAN 接口」设成其中一块，并在这个节点上关掉另一种协议的出口（例如关掉 IPv6 出口），或换一台服务器。"
		}
		e.addFix(Blocking, CodeWANRoute, fp.WAN,
			fmt.Sprintf("%s %s：%s。%s", src, fp.WAN, strings.Join(bad, "；"), why), split+action, fix)
		return
	}
	msg := fmt.Sprintf("WAN 接口 %s 存在并带着这个节点需要的默认路由（%s；%s）。", fp.WAN, where(4), where(6))
	if !fp.WANSet {
		msg += "拓扑里没填「WAN 接口」，按 eth0，与这台主机一致；建议在拓扑里明确填上。"
	}
	e.add(Info, CodeWAN, fp.WAN, msg, "")
}

// ra previews keeping router advertisements alive. With
// net.ipv6.conf.all.forwarding=1 the kernel ignores RAs on interfaces with
// accept_ra=1; an RA-learned default route then expires and the host loses
// IPv6 minutes or hours after the install. The criterion is read-only:
// main-table IPv6 routes with "proto ra" on an interface (ra6 lines) and
// that interface's accept_ra. meridian-up.sh applies the same rule before
// the forwarding switch (and records the interfaces so a late RA at boot
// is covered).
func (e *eval) ra() {
	if e.ctx.Gateway || len(e.r.RA6) == 0 {
		return
	}
	var names []string
	for n := range e.r.RA6 {
		if !e.plannedIface(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return
	}
	if !e.fp.Forward6 {
		e.add(Info, CodeRAKept, strings.Join(names, " "),
			"这些接口的 IPv6 来自路由通告（RA）："+strings.Join(names, "、")+"。这个节点不转发 IPv6（没有 IPv6 出口、也不中转 IPv6），不会打开 IPv6 转发，所以它们照常接受 RA，什么都不改。", "")
		return
	}
	fwd := orDash(e.r.Sysctl["net.ipv6.conf.all.forwarding"])
	var kept, already []string
	for _, n := range names {
		st := e.r.RA6[n]
		what := "前缀路由"
		if st.Default {
			what = "默认路由"
		}
		switch st.AcceptRA {
		case "1":
			kept = append(kept, n+"（"+what+"）")
			e.change("sysctl", "set", "net.ipv6.conf."+n+".accept_ra=2", "在打开 IPv6 转发之前；当前 1，IPv6 "+what+"来自 RA；非受管接口")
		case "2":
			already = append(already, n)
		default:
			cur := st.AcceptRA
			if cur == "" {
				cur = "读不到"
			}
			e.add(Blocking, CodeRAUnmanaged, n,
				fmt.Sprintf("%s 的 IPv6 %s来自路由通告，但它的 accept_ra 是 %s：通告由用户态程序（systemd-networkd、NetworkManager 等）处理，打开 IPv6 转发后它是否还接受通告无法确认。这个节点要转发 IPv6，装上后这台主机的 IPv6 可能在几分钟或几小时后静默断掉，影响已有的服务。", n, what, cur),
				"任选其一后重新预检：在这个节点上关掉 IPv6 出口（拓扑里的「IPv6 出口」，不再中转 IPv6 时面板不打开 IPv6 转发）；或让这块网卡的 IPv6 不依赖通告（静态地址和默认路由）；或把内核处理通告的方式改回内核（accept_ra=1，并在网络管理程序里关掉它自己的 RA 处理）。面板不改网络管理程序的配置。")
		}
	}
	if len(kept) == 0 && len(already) == 0 {
		return
	}
	msg := "IPv6 转发（当前 net.ipv6.conf.all.forwarding=" + fwd + "）打开后，内核不再处理 accept_ra=1 的接口上的路由通告，靠通告学来的默认路由到期后这台主机就没有 IPv6 了。"
	if len(kept) > 0 {
		msg += "meridian-up.sh 在打开 IPv6 转发之前把这些接口设为 accept_ra=2（转发打开时也接受通告）：" + strings.Join(kept, "、") + "；每次运行（含开机）都在转发之前做，并记在 /var/lib/meridian/node/ra-accept 里，开机时通告晚到也照样设置。"
	}
	if len(already) > 0 {
		msg += "已经是 accept_ra=2：" + strings.Join(already, "、") + "。"
	}
	msg += "第一次装机失败时补偿恢复原值；撤回不改（转发仍开着，改回 1 会让 IPv6 断掉），重启后两者都回到主机自己的设置。"
	if fwd == "1" && len(kept) > 0 {
		msg += "注意：这台主机现在已经打开了 IPv6 转发，这些接口的通告可能已经被忽略，默认路由也许正在倒计时。"
	}
	e.add(Info, CodeRAKept, strings.Join(names, " "), msg, "")
}

func (e *eval) plannedIface(n string) bool {
	for _, ip := range e.fp.Interfaces {
		if ip.Name == n {
			return true
		}
	}
	return n == "mmesh" || n == "mmesh-c"
}

// ixHub checks the IX hub's two addresses against the host. The WAN check
// (wan) covers the egress side: the interface the exits are reached
// through carries the default route. Here: the domestic ingress address
// the relays dial must be on the named ingress interface (blocking when the
// topology names one and the host disagrees), and both addresses should be
// local; one that is not is a warning, because a 1:1 NAT or a forward in
// front of the host also works (WireGuard listens on every address) but
// the panel cannot verify it.
func (e *eval) ixHub() {
	fp := e.fp
	if e.ctx.Gateway || fp.IXIngress == "" {
		return
	}
	where := func(addr string) []string {
		var out []string
		for _, a := range e.r.Addrs {
			if a.Prefix.Addr().String() == addr && !containsStr(out, a.Iface) {
				out = append(out, a.Iface)
			}
		}
		return out
	}
	fix := &Fix{Kind: "node", ID: e.ctx.NodeID, Field: "ingress_interface", Label: "节点 " + e.ctx.NodeID + " 的「国内入口接口」"}
	in := where(fp.IXIngress)
	if fp.IXIngressIface != "" {
		if !containsStr(e.r.Links, fp.IXIngressIface) {
			e.addFix(Blocking, CodeIXIngressIface, fp.IXIngressIface,
				fmt.Sprintf("拓扑里 IX 枢纽的国内入口接口 %s 在这台主机上不存在。", fp.IXIngressIface),
				"在拓扑里改成主机上带国内入口地址的网卡，或清空这一项。", fix)
			return
		}
		if len(in) > 0 && !containsStr(in, fp.IXIngressIface) {
			e.addFix(Blocking, CodeIXIngressIface, fp.IXIngressIface,
				fmt.Sprintf("国内入口地址 %s 在 %s 上，不在拓扑写的 %s 上。", fp.IXIngress, strings.Join(in, "、"), fp.IXIngressIface),
				"在拓扑里把「国内入口接口」改成实际带这个地址的网卡。", fix)
			return
		}
	}
	if len(in) == 0 {
		e.add(Warning, CodeIXIngressNotLocal, fp.IXIngress,
			fmt.Sprintf("国内入口地址 %s 不在这台主机的任何接口上。若它是前面设备做的 1:1 NAT 或转发，中继仍能连上（WireGuard 监听所有地址），但面板看不到；否则中继连不上 IX。", fp.IXIngress),
			"确认国内入口地址（ingress_v4）填的是中继实际拨的地址。")
	}
	if fp.IXEgress != "" && len(where(fp.IXEgress)) == 0 {
		e.add(Warning, CodeIXEgressNotLocal, fp.IXEgress,
			fmt.Sprintf("香港出口地址 %s 不在这台主机的任何接口上。到出口的隧道从默认路由（%s）的地址发出；若前面有 1:1 NAT，出口看到的是 NAT 后的地址。", fp.IXEgress, fp.WAN),
			"确认 endpoint_v4 填的是这台主机的香港出口地址。")
	}
	if len(in) > 0 {
		e.add(Info, CodeIXHub, fp.IXIngress, fmt.Sprintf("国内入口地址 %s 在 %s 上；香港一侧经 WAN 接口 %s。", fp.IXIngress, strings.Join(in, "、"), fp.WAN), "")
	}
}

// ufwEnforcing decides from what ufw actually does, read-only: enabled
// when /etc/ufw/ufw.conf says ENABLED=yes or FORWARD jumps to ufw's own
// chains (ufw-before-forward and the like); disabled when the config says
// ENABLED=no and FORWARD has no ufw chain. ufw.service being active is not
// evidence: Ubuntu keeps the unit active (exited) while the firewall is
// off. Without the config line (older report) the unit state decides, as
// before (conservative).
func (e *eval) ufwEnforcing() (bool, string) {
	for _, fam := range []string{"ipv4", "ipv6"} {
		for _, t := range e.r.IptForward[fam] {
			if strings.HasPrefix(t, "ufw-") {
				return true, "FORWARD 跳到 " + t
			}
		}
	}
	switch e.r.UFWConf {
	case "yes":
		return true, "/etc/ufw/ufw.conf 里 ENABLED=yes"
	case "no":
		return false, "/etc/ufw/ufw.conf 里 ENABLED=no，FORWARD 里没有 ufw 的链"
	case "absent":
		return false, "没有 /etc/ufw/ufw.conf"
	}
	if e.r.Units["ufw.service"].Active == "active" {
		return true, "ufw.service 在运行，预检没有读到 ufw.conf"
	}
	return false, "ufw.service 没有运行"
}

// external checks, read-only, what each external SOCKS exit carried by
// this node needs from the host: its interface exists (the unmanaged
// tunnel; never touched), the main table routes the proxy address through
// it (longest match), and the proxy port accepted the preflight's one TCP
// connection (no data, no credential sent: whether the credential is right
// shows only after the install, in the health state).
func (e *eval) external() {
	for _, x := range e.fp.External {
		res := x.ID
		if !containsStr(e.r.Links, x.Iface) {
			e.add(Blocking, CodeExternalIface, res,
				fmt.Sprintf("外部 SOCKS 出口 %s 要经接口 %s 连 SOCKS %s:%d，但这台主机上没有这个接口。", x.ID, x.Iface, x.SOCKS, x.Port),
				"确认承载节点上那条不由面板管理的隧道已经建立、接口名填对（拓扑里外部出口的「承载接口」），然后重新预检。面板不会去建立或修改这条隧道。")
			continue
		}
		dev, via := "", -1
		for _, rt := range e.r.Routes {
			if rt.Family != 4 || rt.Type != "" || !rt.Dst.Contains(x.SOCKS) || rt.Dst.Bits() <= via {
				continue
			}
			dev, via = rt.Dev, rt.Dst.Bits()
		}
		if dev != x.Iface {
			where := "没有任何路由覆盖它"
			if dev != "" {
				where = "它的路由在 " + dev + " 上"
			}
			e.add(Blocking, CodeExternalIface, res,
				fmt.Sprintf("外部 SOCKS 出口 %s 的 SOCKS 地址 %s 不经接口 %s 路由（%s）。装机后承载节点只经 %s 连它，连不上就失败关闭。", x.ID, x.SOCKS, x.Iface, where, x.Iface),
				"检查那条隧道的地址和路由，或把拓扑里外部出口的「承载接口」改成真正路由这个地址的接口，然后重新预检。")
			continue
		}
		ok, probed := e.r.TCPConnect[fmt.Sprintf("%s:%d", x.SOCKS, x.Port)]
		switch {
		case !probed:
			e.add(Warning, CodeExternalProxy, res,
				fmt.Sprintf("预检没有报告到 SOCKS %s:%d 的 TCP 连接结果（较旧的预检或报告被截断）。", x.SOCKS, x.Port),
				"重新预检；装机后在出口状态里看健康探测。")
		case !ok:
			e.add(Blocking, CodeExternalProxy, res,
				fmt.Sprintf("从这台主机连不上外部 SOCKS 出口 %s 的 SOCKS %s:%d（5 秒内没有建立 TCP 连接）。", x.ID, x.SOCKS, x.Port),
				"确认那台设备在线、隧道通、SOCKS 在这个地址和端口上监听，然后重新预检。")
		default:
			e.add(Info, CodeExternal, res,
				fmt.Sprintf("外部 SOCKS 出口 %s：接口 %s 存在并路由 %s，SOCKS 端口 %d 接受 TCP 连接（预检没有发送凭据；凭据是否正确装机后由健康探测确认）。", x.ID, x.Iface, x.SOCKS, x.Port), "")
		}
	}
}
