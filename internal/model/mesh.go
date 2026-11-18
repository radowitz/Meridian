package model

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Cloudflare Mesh as an underlay (docs/architecture.md「Cloudflare Mesh：
// WireGuard 的底层承载」).
//
// A cf_mesh link joins the primary hub and an exit. It is a WireGuard leg
// like a direct_wg link, with its own interface, port and tunnel subnet
// (its link slot); only its outer UDP packets take another way: the hub's
// Endpoint for the exit is the exit's Mesh underlay address, which the
// hub's Mesh sidecar forwards into the Cloudflare Mesh and the exit's
// sidecar hands to the exit's WireGuard listener. Client traffic is still
// decapsulated on the exit and leaves through the exit's own uplink: its
// public address, region, unlock results and resolver are those of the
// direct leg.
//
// The exit's Mesh node publishes exactly one route: its Mesh underlay
// address as a /32 (MeshUnderlayAddr of its slot in Allocations.Mesh,
// inside Settings.MeshUnderlayPrefix). No default route and no other prefix
// is ever published, and no exit or region-group table ever points at the
// sidecar.

const (
	// MaxMeshSlots bounds the Mesh underlay slots (one per exit with a
	// cf_mesh link).
	MaxMeshSlots = 200
	// DefaultMeshUnderlayPrefix is the pool the exits' Mesh underlay
	// addresses come from when Settings.MeshUnderlayPrefix is empty. It
	// sits next to, and outside of, the tunnel plan 10.66.0.0/16 and the
	// default remote-access pool 10.67.0.0/24.
	DefaultMeshUnderlayPrefix = "10.68.0.0/24"
	// MeshPathMTU is the default path MTU of a Mesh hop (Link.MTU of a
	// cf_mesh link left at zero): the MTU of the WARP device.
	MeshPathMTU = 1280
)

// MeshUnderlayPrefix is the pool the Mesh underlay addresses are taken
// from: Settings.MeshUnderlayPrefix, or DefaultMeshUnderlayPrefix. The
// error is the reason the setting cannot be used (validation reports it).
func (t Topology) MeshUnderlayPrefix() (netip.Prefix, error) {
	raw := strings.TrimSpace(t.Settings.MeshUnderlayPrefix)
	if raw == "" {
		raw = DefaultMeshUnderlayPrefix
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q 不是 CIDR", raw)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s 不是 IPv4 前缀", p)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s 不是网络地址，应为 %s", p, p.Masked())
	}
	if p.Bits() < 16 || p.Bits() > 30 {
		return netip.Prefix{}, fmt.Errorf("%s 的长度要在 /16 到 /30 之间", p)
	}
	return p, nil
}

// MeshUnderlayAddr is the address of Mesh underlay slot slot in pool: host
// slot+1 (the network address is never used). ok is false when the pool
// has no such host (the last address of the pool, its broadcast address,
// is not used either).
func MeshUnderlayAddr(pool netip.Prefix, slot int) (netip.Addr, bool) {
	if !pool.IsValid() || !pool.Addr().Is4() || slot < 0 || slot >= MaxMeshSlots {
		return netip.Addr{}, false
	}
	hosts := 1<<(32-pool.Bits()) - 2
	if slot+1 > hosts {
		return netip.Addr{}, false
	}
	b := pool.Masked().Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += uint32(slot + 1)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// MeshLeg is one enabled cf_mesh link as the compiler, the validation and
// the Mesh deployment read it.
type MeshLeg struct {
	Link Link
	// Hub and Exit are the node IDs of its two ends.
	Hub, Exit string
	// Addr is the exit's Mesh underlay address (the one route its Mesh node
	// publishes, as a /32) and the address the hub's WireGuard leg dials.
	// Invalid when the exit has no slot or the pool cannot hold it.
	Addr netip.Addr
	// Sole: the leg is the exit's only way to the hub (a pure-IPv6 exit
	// with v6_workaround "mesh"); otherwise it is the alternative of the
	// hub's direct WireGuard leg to the same exit.
	Sole bool
}

// Route is the one CIDR the exit's Mesh node publishes for this leg ("" when
// Addr is not allocated).
func (m MeshLeg) Route() string {
	if !m.Addr.IsValid() {
		return ""
	}
	return netip.PrefixFrom(m.Addr, m.Addr.BitLen()).String()
}

// MeshSoleExit: n is reached from the hub by its Mesh leg alone.
func MeshSoleExit(n Node) bool {
	return n.Role == RoleExit && !n.PathV4 && n.PathV6 && n.V6Workaround == WorkaroundMesh
}

// meshEnds resolves a cf_mesh link to (hub, exit); ok is false when it does
// not join a hub and an exit.
func meshEnds(t Topology, l Link) (hub, exit Node, ok bool) {
	a, okA := t.NodeByID(l.From)
	b, okB := t.NodeByID(l.To)
	if !okA || !okB {
		return Node{}, Node{}, false
	}
	switch {
	case a.Role == RoleHub && b.Role == RoleExit:
		return a, b, true
	case b.Role == RoleHub && a.Role == RoleExit:
		return b, a, true
	}
	return Node{}, Node{}, false
}

// meshExits are the exits that own a Mesh underlay slot: every exit at the
// end of a cf_mesh link, enabled or not (a disabled edge keeps its address,
// so enabling it again changes nothing else), sorted by ID.
func meshExits(t Topology) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range t.Links {
		if l.Transport != TransportCFMesh || l.ID == "" {
			continue
		}
		if _, e, ok := meshEnds(t, l); ok && e.ID != "" && !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, e.ID)
		}
	}
	sort.Strings(out)
	return out
}

// MeshLegs lists the enabled cf_mesh links that join a hub and an exit,
// sorted by link ID, each with the exit's Mesh underlay address.
func (t Topology) MeshLegs() []MeshLeg {
	var links []Link
	for _, l := range t.Links {
		if l.Transport == TransportCFMesh && l.Enabled && l.ID != "" {
			links = append(links, l)
		}
	}
	if len(links) == 0 {
		return nil
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	pool, perr := t.MeshUnderlayPrefix()
	alloc := EffectiveAllocations(t)
	var out []MeshLeg
	for _, l := range links {
		hub, exit, ok := meshEnds(t, l)
		if !ok {
			continue
		}
		leg := MeshLeg{Link: l, Hub: hub.ID, Exit: exit.ID, Sole: MeshSoleExit(exit)}
		if slot, ok := alloc.MeshSlot(exit.ID); ok && perr == nil {
			if a, ok := MeshUnderlayAddr(pool, slot); ok {
				leg.Addr = a
			}
		}
		out = append(out, leg)
	}
	return out
}

// HasMeshLegs: some enabled cf_mesh link joins a hub and an exit.
func (t Topology) HasMeshLegs() bool { return len(t.MeshLegs()) > 0 }

// MeshLegOf is the Mesh leg between hub and exit (ok false: none).
func (t Topology) MeshLegOf(hub, exit string) (MeshLeg, bool) {
	for _, m := range t.MeshLegs() {
		if m.Hub == hub && m.Exit == exit {
			return m, true
		}
	}
	return MeshLeg{}, false
}

// MeshLegPathMTU is the Mesh path MTU a cf_mesh link is planned for:
// Link.MTU, or MeshPathMTU.
func MeshLegPathMTU(l Link) int {
	if l.MTU > 0 {
		return l.MTU
	}
	return MeshPathMTU
}

// AllocationsIncomplete: t carries an allocation table that lacks a slot
// for an object that needs one. The only way a stored table gets there
// without an edit is an upgrade that made more objects need a slot: a
// cf_mesh link saved before it became a WireGuard leg has no link slot and
// its exit no Mesh underlay slot. The store persists the missing slots once
// (store.MigrateAllocations), so they are the stable ones from then on and
// not re-derived, in exit-ID order, each time another Mesh edge is added.
// False for a document without a table (MigrateAllocations handles that)
// and when nothing more can be allocated (exhaustion stays as it is).
func AllocationsIncomplete(t Topology) bool {
	a := t.Allocations
	if a == nil {
		return false
	}
	eff := EffectiveAllocations(t)
	return len(eff.Links) != len(a.Links) || len(eff.Exits) != len(a.Exits) || len(eff.Groups) != len(a.Groups) || len(eff.Mesh) != len(a.Mesh)
}

// Host-level Cloudflare Mesh nodes (docs/architecture.md「沿用主机上已有的
// Mesh 节点」). The panel detects, over the pinned SSH channel and a fixed
// read-only script, whether a server already runs a host-level WARP client
// that joined a Mesh. A detected node is recorded with its origin: the panel
// never re-registers, reinstalls or withdraws a node it did not create.

const (
	// HostMeshExisting: a host-level WARP client runs and is a Mesh node
	// (Mesh/connector mode or a Mesh address in MeshCGNAT).
	HostMeshExisting = "existing_node"
	// HostMeshNone: no host-level Mesh node (WARP absent or not a Mesh node).
	HostMeshNone = "no_node"
	// HostMeshFailed: the detection itself failed (SSH, incomplete output).
	HostMeshFailed = "detect_failed"

	AccountMatched  = "matched"
	AccountMismatch = "mismatch"
	AccountUnknown  = "unknown"

	// Origins of a Mesh node on a host.
	MeshOriginExisting = "existing_host" // found on the host; not panel-owned
	// MeshOriginPanelHost: a host-level Linux WARP connector a panel
	// deployment run installed and registered (panel-owned).
	MeshOriginPanelHost = "panel_host"
	// MeshOriginPanel: a Docker sidecar of a deployment made before the
	// Mesh became host-level only. No plan creates one any more; such a
	// record can only be withdrawn.
	MeshOriginPanel = "panel_sidecar"
	MeshOriginNone  = "none"

	// InstallHostConnector is the only way the panel makes a host a Mesh
	// node: the official Linux cloudflare-warp package as a connector.
	InstallHostConnector = "host_connector"

	// MeshCGNAT is the address range of Cloudflare Mesh / WARP devices.
	MeshCGNAT = "100.96.0.0/12"
)

// HostMeshCoexist is the check of a host-level WARP client's policy routing
// against Meridian's tables, marks and rule priorities on that node.
type HostMeshCoexist struct {
	OK        bool     `json:"ok"`
	WARPRules []string `json:"warp_rules"`
	Tables    []int    `json:"warp_tables"`
	// GlobalDefault: a WARP table carries a default route (full-tunnel mode).
	GlobalDefault bool     `json:"global_default"`
	Conflicts     []string `json:"conflicts"`
}

// HostMeshInstallOption is how a host without a Mesh node becomes one: the
// host-level Linux connector (InstallHostConnector, the only kind).
type HostMeshInstallOption struct {
	Kind     string   `json:"kind"` // host_connector
	Feasible bool     `json:"feasible"`
	Installs []string `json:"installs"`
	Needs    []string `json:"needs"`
	Blockers []string `json:"blockers"`
	// The full install content the operator confirms.
	Repo           string   `json:"repo,omitempty"`
	KeyURL         string   `json:"key_url,omitempty"`
	KeyFingerprint string   `json:"key_fingerprint,omitempty"`
	Packages       []string `json:"packages,omitempty"`
	Services       []string `json:"services,omitempty"`
	Files          []string `json:"files,omitempty"`
	// MemEstimateMB is an estimate (MemNote says of what), not a measurement.
	MemEstimateMB int    `json:"mem_estimate_mb,omitempty"`
	MemNote       string `json:"mem_note,omitempty"`
}

// HostMeshInstallPlan is what a host without a node would need. Nothing is
// installed by the detection; the operator confirms in the deployment.
type HostMeshInstallPlan struct {
	Recommended          string                  `json:"recommended,omitempty"`
	Options              []HostMeshInstallOption `json:"options"`
	RequiresConfirmation bool                    `json:"requires_confirmation"`
}

// HostMeshDetection is the result of detecting one node's host.
type HostMeshDetection struct {
	NodeID    string `json:"node_id"`
	ServerID  string `json:"server_id,omitempty"`
	CheckedAt string `json:"checked_at"`
	HostKey   string `json:"host_key,omitempty"`
	State     string `json:"state"`
	// Reasons explain State, the account result and anything not reusable.
	Reasons       []string `json:"reasons"`
	WarpSvc       bool     `json:"warp_svc"`
	WarpCLI       bool     `json:"warp_cli"`
	Status        string   `json:"status,omitempty"`
	Mode          string   `json:"mode"` // mesh | connector | warp | proxy | unknown
	Account       string   `json:"account"`
	AccountReason string   `json:"account_reason,omitempty"`
	AccountID     string   `json:"account_id,omitempty"`
	MeshAddr      string   `json:"mesh_addr,omitempty"`
	Iface         string   `json:"iface,omitempty"`
	Docker        bool     `json:"docker"`
	Compose       bool     `json:"compose"`
	// Install prerequisites read on the host itself: OS id and codename,
	// machine architecture, apt, systemd and whether the host reaches the
	// official package source (RepoReach ok | unreachable | unknown).
	OS        string `json:"os,omitempty"`
	Codename  string `json:"codename,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Apt       bool   `json:"apt"`
	Systemd   bool   `json:"systemd"`
	RepoReach string `json:"repo_reach,omitempty"`
	// MemAvailMB is MemAvailable (-1: not read).
	MemAvailMB int                  `json:"mem_avail_mb"`
	Coexist    HostMeshCoexist      `json:"coexist"`
	Install    *HostMeshInstallPlan `json:"install,omitempty"`
	// Reusable: an existing node the Mesh leg can use as it is (account
	// matched, Mesh address known, no coexistence conflict).
	Reusable bool `json:"reusable"`
	// Origin and PanelOwned record who owns the node on this host.
	Origin     string `json:"origin"`
	PanelOwned bool   `json:"panel_owned"`
}

// NodeMeshHost is a host-level Mesh node (Node.MeshHost): one found on the
// host (reused as it is) or one the panel installed.
type NodeMeshHost struct {
	Addr  string // the node's Mesh address (in MeshCGNAT), no prefix length
	Iface string // the WARP interface carrying it (e.g. CloudflareWARP)
	// Pending: the host has no Mesh node yet (it is to be installed); Addr
	// is then only the panel's placeholder, never reachable, and every leg
	// to it stays blackholed until the node exists and is re-provisioned.
	Pending bool
	// PanelOwned: the panel installed this node (MeshOriginPanelHost).
	PanelOwned bool
}

// MeshPendingIface is the interface name of the official Linux client.
const MeshPendingIface = "CloudflareWARP"

// MeshHostOf returns the host-level node of a detection, or nil when the
// detection is not an existing, reusable host node with a usable address
// and interface name. Both a node found on the host and one the panel
// installed (MeshOriginPanelHost) qualify.
func MeshHostOf(d HostMeshDetection) *NodeMeshHost {
	if !d.Reusable || d.State != HostMeshExisting {
		return nil
	}
	if !(d.Origin == MeshOriginExisting && !d.PanelOwned) && !(d.Origin == MeshOriginPanelHost && d.PanelOwned) {
		return nil
	}
	a, err := netip.ParsePrefix(d.MeshAddr)
	var ip netip.Addr
	if err == nil {
		ip = a.Addr()
	} else if ip, err = netip.ParseAddr(d.MeshAddr); err != nil {
		return nil
	}
	if !ip.Is4() || !netip.MustParsePrefix(MeshCGNAT).Contains(ip) || !hostIfaceName(d.Iface) {
		return nil
	}
	return &NodeMeshHost{Addr: ip.String(), Iface: d.Iface, PanelOwned: d.Origin == MeshOriginPanelHost}
}

func hostIfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
