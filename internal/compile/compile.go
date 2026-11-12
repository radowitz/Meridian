// Package compile turns a validated topology into per-node configuration.
//
// Exit choice cannot ride on fwmark across WireGuard, so the gateway SNATs
// each LAN flow onto a per-exit transit address. Aliyun and the Hong Kong
// hub route that source toward the chosen exit. Public NAT and NAT66 happen
// only at the exit. ULA fd66::/48 is routed inside the tunnels and is never
// pointed at the ROS gateway.
package compile

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

const privateKeyPlaceholder = "__MERIDIAN_PRIVATE_KEY__"
const publicKeyPlaceholder = "EXAMPLE_PUBLIC_KEY_DO_NOT_USE"

// Bundle is a deterministic set of files keyed by repo-relative path
// nodes/<id>/... plus a few top-level manifests.
type Bundle struct {
	Files  map[string]string     `json:"files"`
	Order  []string              `json:"order"`
	Issues []validate.Issue      `json:"issues"`
	Paths  []validate.PathReport `json:"paths"`
}

func (b Bundle) Canonical() string {
	keys := make([]string, 0, len(b.Files))
	for k := range b.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("# apply-order: " + strings.Join(b.Order, " ") + "\n")
	for _, k := range keys {
		sb.WriteString("===== " + k + " =====\n")
		sb.WriteString(b.Files[k])
		if !strings.HasSuffix(b.Files[k], "\n") {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func (b Bundle) File(path string) string {
	return b.Files[path]
}

// ValidationError is returned when the topology cannot be compiled.
type ValidationError struct {
	Result validate.Result
}

func (e *ValidationError) Error() string {
	n := 0
	for _, iss := range e.Result.Issues {
		if iss.Severity == validate.SeverityError {
			n++
		}
	}
	return fmt.Sprintf("拓扑校验未通过（%d 个错误）", n)
}

// Compile validates and renders. A draft flag does not bypass errors:
// apply must refuse an invalid path.
func Compile(t model.Topology) (*Bundle, error) {
	res := validate.Run(t)
	if res.HasErrors() {
		return &Bundle{Issues: res.Issues, Paths: res.Paths}, &ValidationError{Result: res}
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	exits := planExits(t, tunnels)
	b := &Bundle{
		Files:  map[string]string{},
		Order:  applyOrder(t),
		Issues: res.Issues,
		Paths:  res.Paths,
	}
	mss4, mss6 := mssFloor(res.Paths)
	add := func(path, content string) {
		b.Files[path] = strings.TrimRight(content, "\n") + "\n"
	}

	add("APPLY_ORDER.txt", renderOrder(b.Order))
	add("README.txt", renderBundleReadme(t))

	for _, n := range managedNodes(t) {
		prefix := "nodes/" + n.ID + "/"
		nodeTunnels := tunnelsFor(tunnels, n.ID)
		for _, tun := range nodeTunnels {
			add(prefix+"etc/wireguard/"+tun.Iface()+".conf", renderWG(t, tun, n))
		}
		add(prefix+"etc/sysctl.d/99-meridian.conf", renderSysctl(t, n))
		add(prefix+"etc/iproute2/rt_tables.d/meridian.conf", renderRTTables(t, n, exits))
		add(prefix+"usr/local/sbin/meridian-routes.sh", renderRoutes(t, n, tunnels, exits))
		add(prefix+"usr/local/sbin/meridian-up.sh", renderUp(t, n, nodeTunnels))
		add(prefix+"etc/nftables.d/meridian.nft", renderNFT(t, n, tunnels, exits, mss4, mss6))
		if n.Role == model.RoleGateway || n.Role == model.RoleRelay || n.Role == model.RoleHub {
			add(prefix+"usr/local/sbin/meridian-failover.sh", renderFailover(t, n, tunnels))
			add(prefix+"etc/systemd/system/meridian-failover.service", renderFailoverUnit())
		}
		if srv := renderWstunnelServer(n, tunnels); srv != "" {
			add(prefix+"etc/systemd/system/wstunnel-meridian.service", srv)
		}
		for _, tun := range nodeTunnels {
			if tun.Mode != "wss" || tun.Dialer().ID != n.ID {
				continue
			}
			add(prefix+"etc/systemd/system/wstunnel-client-"+tun.LinkID+".service", renderWstunnelClient(tun))
		}
		switch n.Role {
		case model.RoleGateway:
			add(prefix+"etc/smartdns/smartdns.conf", renderGatewayDNS(t, exits))
			add(prefix+"usr/local/sbin/meridian-update-chnroute.sh", renderChnrouteScript())
			add(prefix+"usr/local/sbin/meridian-update-geosite.sh", renderGeositeScript(t))
		case model.RoleExit:
			add(prefix+"etc/smartdns/smartdns.conf", renderExitDNS(n, tunnels))
		}
	}
	return b, nil
}

func mssFloor(paths []validate.PathReport) (mss4, mss6 int) {
	mss4, mss6 = 1380, 1360
	for _, p := range paths {
		if p.MSS4 > 0 && p.MSS4 < mss4 {
			mss4 = p.MSS4
		}
		if p.MSS6 > 0 && p.MSS6 < mss6 {
			mss6 = p.MSS6
		}
	}
	return mss4, mss6
}

func managedNodes(t model.Topology) []model.Node {
	var out []model.Node
	for _, n := range t.Nodes {
		if n.Managed && n.Role != model.RoleIX {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func tunnelsFor(all []Tunnel, nodeID string) []Tunnel {
	var out []Tunnel
	for _, tun := range all {
		if tun.West.ID == nodeID || tun.East.ID == nodeID {
			out = append(out, tun)
		}
	}
	return out
}

// applyOrder publishes exits that must dial out first, then other exits,
// the hub, relays, and the gateway last.
func applyOrder(t model.Topology) []string {
	var nat, other, hubs, relays, gws []string
	for _, n := range t.Nodes {
		if !n.Managed || n.Role == model.RoleIX {
			continue
		}
		switch {
		case n.Role == model.RoleExit && n.NatDialOut:
			nat = append(nat, n.ID)
		case n.Role == model.RoleExit:
			other = append(other, n.ID)
		case n.Role == model.RoleHub:
			hubs = append(hubs, n.ID)
		case n.Role == model.RoleRelay:
			relays = append(relays, n.ID)
		case n.Role == model.RoleGateway:
			gws = append(gws, n.ID)
		}
	}
	for _, s := range [][]string{nat, other, hubs, relays, gws} {
		sort.Strings(s)
	}
	var out []string
	out = append(out, nat...)
	out = append(out, other...)
	out = append(out, hubs...)
	out = append(out, relays...)
	out = append(out, gws...)
	return out
}

func renderOrder(order []string) string {
	var sb strings.Builder
	sb.WriteString("# Publish order: NAT dial-out exits, other exits, hub, relay, gateway.\n")
	sb.WriteString("# IX is a dedicated line, not a host. Mesh is not in this list.\n")
	for i, id := range order {
		fmt.Fprintf(&sb, "%d\t%s\n", i+1, id)
	}
	return sb.String()
}

func pubkey(n model.Node) string {
	if strings.TrimSpace(n.PublicKey) == "" {
		return publicKeyPlaceholder
	}
	return n.PublicKey
}

func lanNet(t model.Topology) string {
	if p, err := netip.ParsePrefix(t.Settings.GatewayLANIP); err == nil {
		return p.Masked().String()
	}
	return "192.168.100.0/24"
}

func lanHost(t model.Topology) string {
	if p, err := netip.ParsePrefix(t.Settings.GatewayLANIP); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(t.Settings.GatewayLANIP); err == nil {
		return a.String()
	}
	return "192.168.100.88"
}
