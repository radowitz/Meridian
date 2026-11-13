// Package compile turns a validated topology into per-node configuration.
//
// Exit choice cannot ride on fwmark across WireGuard, so the gateway SNATs
// each LAN flow onto a per-exit transit address. Aliyun and the Hong Kong
// hub route that source toward the chosen exit. Public NAT and NAT66 happen
// only at the exit. ULA fd66::/48 is routed inside the tunnels and is never
// pointed at the ROS gateway.
package compile

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// PrivateKeyPlaceholder stands in for a node's WireGuard private key in every
// compiled bundle, snapshot, preview and diff. Only the install boundary
// (apply.Applier with a key, or the provision script) replaces it.
const PrivateKeyPlaceholder = "__MERIDIAN_PRIVATE_KEY__"

const privateKeyPlaceholder = PrivateKeyPlaceholder
const publicKeyPlaceholder = "EXAMPLE_PUBLIC_KEY_DO_NOT_USE"

// Bundle is a deterministic set of files keyed by repo-relative path
// nodes/<id>/... plus a few top-level manifests.
type Bundle struct {
	Files  map[string]string     `json:"files"`
	Order  []string              `json:"order"`
	Issues []validate.Issue      `json:"issues"`
	Paths  []validate.PathReport `json:"paths"`
	// WSS is set by ResolveWSS: the rotation stage each WSS party was
	// rendered at (recorded after a successful install) and unresolved
	// tokens.
	WSS *WSSPlan `json:"-"`
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

// PeerKeyProblem is one WireGuard peer of a node whose public key cannot be
// used: missing, still the placeholder, or not a 32-byte base64 key.
type PeerKeyProblem struct {
	Peer  string `json:"peer"`
	Iface string `json:"iface"`
	Key   string `json:"key,omitempty"`
}

// PeerKeyProblems inspects the WireGuard configs the bundle holds for one
// node (nodes/<id>/etc/wireguard/*.conf) and lists every peer whose
// PublicKey would make "wg setconf" fail. Compile, preview and diff accept
// such a topology; only an install to the host must refuse it, before
// anything is written.
func (b Bundle) PeerKeyProblems(nodeID string) []PeerKeyProblem {
	prefix := "nodes/" + nodeID + "/etc/wireguard/"
	var paths []string
	for p := range b.Files {
		if strings.HasPrefix(p, prefix) && strings.HasSuffix(p, ".conf") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var out []PeerKeyProblem
	for _, p := range paths {
		iface := strings.TrimSuffix(strings.TrimPrefix(p, prefix), ".conf")
		inPeer, peer, key, haveKey := false, "", "", false
		flush := func() {
			if inPeer && (!haveKey || !ValidWGKey(key)) {
				if peer == "" {
					peer = "?"
				}
				out = append(out, PeerKeyProblem{Peer: peer, Iface: iface, Key: key})
			}
		}
		for _, raw := range strings.Split(b.Files[p], "\n") {
			line := strings.TrimSpace(raw)
			switch {
			case strings.HasPrefix(line, "["):
				flush()
				inPeer, peer, key, haveKey = line == "[Peer]", "", "", false
			case inPeer && strings.HasPrefix(line, "# peer-node "):
				peer = strings.TrimSpace(strings.TrimPrefix(line, "# peer-node "))
			case inPeer && strings.HasPrefix(line, "PublicKey"):
				if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "PublicKey" {
					key, haveKey = strings.TrimSpace(v), true
				}
			}
		}
		flush()
	}
	return out
}

// ValidWGKey reports whether s is a WireGuard key: standard base64 of
// exactly 32 bytes. The placeholder and an empty string are not.
func ValidWGKey(s string) bool {
	if len(s) != 44 || s == publicKeyPlaceholder {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
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
// apply must refuse an invalid path. Unlock decisions are not applied;
// use CompileWithDecisions when the stored unlock map should move automatic
// rules inside their pool.
func Compile(t model.Topology) (*Bundle, error) {
	return compile(t, nil)
}

// CompileWithDecisions is Compile plus the unlock map. Keys are rule IDs,
// values are exit IDs in the same pool. Pinned rules ignore the map.
func CompileWithDecisions(t model.Topology, decisions map[string]string) (*Bundle, error) {
	return compile(t, decisions)
}

func compile(t model.Topology, decisions map[string]string) (*Bundle, error) {
	res := validate.Run(t)
	if res.HasErrors() {
		return &Bundle{Issues: res.Issues, Paths: res.Paths}, &ValidationError{Result: res}
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	exits := planExits(t, tunnels)
	groups := planGroups(t, exits)
	b := &Bundle{
		Files:  map[string]string{},
		Order:  applyOrder(t),
		Issues: res.Issues,
		Paths:  res.Paths,
	}
	mss4, mss6 := mssFloor(res.Paths, meshExitIDs(t))
	var clamps []mssClamp
	for _, p := range res.Paths {
		if !meshExitIDs(t)[p.ExitID] {
			continue
		}
		e, ok := exitByID(exits, p.ExitID)
		if !ok || p.MSS4 <= 0 {
			continue
		}
		if p.MSS4 < mss4 || p.MSS6 < mss6 {
			clamps = append(clamps, mssClamp{Mark: e.Mark, MSS4: p.MSS4, MSS6: p.MSS6})
		}
	}
	add := func(path, content string) {
		b.Files[path] = strings.TrimRight(content, "\n") + "\n"
	}

	add("APPLY_ORDER.txt", renderOrder(b.Order, groups))
	add("README.txt", renderBundleReadme(t))

	for _, n := range managedNodes(t) {
		prefix := "nodes/" + n.ID + "/"
		nodeTunnels := tunnelsFor(tunnels, n.ID)
		// A hub routes with its own plan: its interfaces toward the exits.
		// Everything else (and a lone or primary hub) uses the primary's.
		hubExits, hubGroups := exits, groups
		if n.Role == model.RoleHub && n.ID != primaryHubID(t) {
			hubExits = planExitsHub(t, tunnels, n.ID)
			hubGroups = planGroupsHub(t, hubExits, n.ID)
		}
		for _, tun := range nodeTunnels {
			add(prefix+"etc/wireguard/"+tun.Iface()+".conf", renderWG(t, tun, n))
		}
		add(prefix+"etc/sysctl.d/99-meridian.conf", renderSysctl(t, n))
		add(prefix+"etc/meridian/forwarding.conf", renderForwarding(t, n))
		add(prefix+"etc/iproute2/rt_tables.d/meridian.conf", renderRTTables(t, n, hubExits, hubGroups))
		add(prefix+"usr/local/sbin/meridian-routes.sh", renderRoutes(t, n, tunnels, hubExits, hubGroups))
		meshDNS := n.Role == model.RoleExit && len(meshDNSGroups(groups, n.ID)) > 0
		add(prefix+"usr/local/sbin/meridian-up.sh", renderUp(t, n, nodeTunnels, meshDNS, exits))
		nftExits, nftGroups := exits, groups
		if n.Role == model.RoleHub {
			// A hub's nested_snat chain names its own tunnels.
			nftExits, nftGroups = hubExits, hubGroups
		}
		add(prefix+"etc/nftables.d/meridian.nft", renderNFT(t, n, tunnels, nftExits, nftGroups, mss4, mss6, decisions, clamps))
		if n.Role != model.RoleGateway {
			// Remote nodes: the boot unit (the gateway has
			// deploy/debian/meridian.service) and the Docker FORWARD DROP
			// coexistence rules with their re-assert unit.
			add(prefix+"etc/systemd/system/"+NodeUnit, renderNodeUnit())
			if rules := fwRules(t, n, nodeTunnels); len(rules) > 0 {
				add(prefix+strings.TrimPrefix(FWCompatPath, "/"), renderFWCompat(rules))
				add(prefix+"etc/systemd/system/"+FWCompatUnit, renderFWCompatUnit())
			}
		}
		if n.Role == model.RoleGateway || n.Role == model.RoleRelay || n.Role == model.RoleHub {
			add(prefix+"usr/local/sbin/meridian-failover.sh", renderFailover(t, n, tunnels, hubExits, hubGroups))
			add(prefix+"etc/systemd/system/meridian-failover.service", renderFailoverUnit())
		}
		if n.Role == model.RoleGateway {
			if rp := planRemote(t); rp != nil {
				add(prefix+"etc/wireguard/"+rp.Iface+".conf", renderRemoteWG(rp))
			}
			add(prefix+"usr/local/sbin/meridian-verify.sh", renderVerifyScript(t, tunnels, exits, groups))
			add(prefix+"etc/nftables.d/meridian-guard.nft", renderGuardNFT(t, tunnels, exits, groups))
			if sp := planShare(t, tunnels); sp != nil {
				add(prefix+strings.TrimPrefix(SharePathConfig, "/"), renderShareConfig(t, sp))
			}
		}
		if n.Role == model.RoleExit {
			add(prefix+"usr/local/sbin/meridian-unlock-probe.sh", renderUnlockProbe(t, n))
			add(prefix+"etc/meridian/unlock-report.env.example", renderUnlockReportEnv())
			add(prefix+"etc/systemd/system/meridian-unlock.service", renderUnlockService())
			add(prefix+"etc/systemd/system/meridian-unlock.timer", renderUnlockTimer(t))
		}
		if n.Role == model.RoleHub {
			add(prefix+"etc/meridian/nat64.reserved.conf", renderNAT64(t))
		}
		if n.Role != model.RoleGateway && meshPeer(t, n.ID) {
			add(prefix+"etc/meridian/mesh-sidecar.compose.yml", renderMeshCompose(t))
			add(prefix+"etc/meridian/mesh.env.example", renderMeshEnvExample())
			add(prefix+"usr/local/sbin/meridian-mesh-up.sh", renderMeshUp(t, n, groups))
		}
		if meshDNS {
			add(prefix+"etc/systemd/system/meridian-mesh-seal.service", renderMeshSealService())
			add(prefix+"etc/systemd/system/meridian-mesh-seal.timer", renderMeshSealTimer())
		}
		if srv := renderWstunnelServer(n, tunnels); srv != "" {
			add(prefix+"etc/systemd/system/"+WSSServerUnit, srv)
			add(prefix+strings.TrimPrefix(WSSServerYAML, "/"), renderWSSRestrictions(n, tunnels))
			add(prefix+strings.TrimPrefix(WSSServerCert, "/"), renderWSSServerCert(n))
			add(prefix+strings.TrimPrefix(WSSServerKey, "/"), renderWSSServerKey(n))
		}
		for _, tun := range nodeTunnels {
			if tun.Mode != "wss" || tun.Dialer().ID != n.ID {
				continue
			}
			add(prefix+"etc/systemd/system/"+WSSClientUnit(tun.LinkID), renderWstunnelClient(tun))
			add(prefix+strings.TrimPrefix(WSSClientEnv(tun.LinkID), "/"), renderWSSClientEnv(tun))
			add(prefix+strings.TrimPrefix(WSSClientTrust(tun.LinkID), "/"), renderWSSClientTrust(tun))
		}
		switch n.Role {
		case model.RoleGateway:
			add(prefix+"etc/smartdns/smartdns.conf", renderGatewayDNS(t, exits, groups, decisions))
			add(prefix+strings.TrimPrefix(lists.ManifestPath, "/"), renderRuleManifest(planRules(t, exits, groups, decisions)))
			defT, _ := defaultExit(t, groups)
			add(prefix+strings.TrimPrefix(DecidePath, "/"), renderDecideSnapshot(t, planRules(t, exits, groups, decisions), defT))
			if unit, ok := renderDNSSplitUnit(t, exits, groups); ok {
				add(prefix+"etc/systemd/system/"+DNSSplitUnit, unit)
			}
			add(prefix+"usr/local/sbin/meridian-update-chnroute.sh", renderChnrouteScript(t))
			add(prefix+"usr/local/sbin/meridian-update-geosite.sh", renderGeositeScript(t))
		case model.RoleExit:
			add(prefix+"etc/smartdns/smartdns.conf", renderExitDNS(t, n, tunnels, exits))
			add(prefix+"etc/systemd/system/"+SmartDNSUnit, renderSmartDNSUnit())
		}
		if n.Role == model.RoleExit && len(externalPlans(exits, n.ID)) > 0 {
			// Carrier of external SOCKS exits (render_nested.go).
			add(prefix+strings.TrimPrefix(ExtProxyConfig, "/"), renderExtProxyConfig(exits, n.ID))
			add(prefix+"etc/systemd/system/"+ExtProxyUnit, renderExtProxyUnit())
			add(prefix+strings.TrimPrefix(ExtHealthScript, "/"), renderExtHealthScript(exits, n.ID))
			add(prefix+"etc/systemd/system/"+ExtHealthUnit, renderExtHealthUnit())
		}
		if len(refreshTunnels(n, nodeTunnels)) > 0 {
			add(prefix+strings.TrimPrefix(EndpointRefreshScript, "/"), renderEndpointRefresh(n, nodeTunnels))
			add(prefix+"etc/systemd/system/"+EndpointRefreshUnit, renderEndpointRefreshUnit())
			add(prefix+"etc/systemd/system/"+EndpointRefreshTimer, renderEndpointRefreshTimer())
		}
	}
	return b, nil
}

func mssFloor(paths []validate.PathReport, skip map[string]bool) (mss4, mss6 int) {
	mss4, mss6 = 1380, 1360
	for _, p := range paths {
		if skip[p.ExitID] {
			continue
		}
		if p.MSS4 > 0 && p.MSS4 < mss4 {
			mss4 = p.MSS4
		}
		if p.MSS6 > 0 && p.MSS6 < mss6 {
			mss6 = p.MSS6
		}
	}
	return mss4, mss6
}

func meshExitIDs(t model.Topology) map[string]bool {
	out := map[string]bool{}
	for _, n := range t.Nodes {
		if n.Role == model.RoleExit && !n.PathV4 && n.PathV6 && n.V6Workaround == model.WorkaroundMesh {
			out[n.ID] = true
		}
	}
	return out
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

func renderOrder(order []string, groups []GroupPlan) string {
	var sb strings.Builder
	sb.WriteString("# Publish order: NAT dial-out exits, other exits, hub, relay, gateway.\n")
	sb.WriteString("# IX is a dedicated line, not a host. Mesh is not in this list.\n")
	for _, g := range groups {
		if g.Dynamic {
			// The gateway cannot tell which exits already carry this; see
			// docs/architecture.md「地区组的解析」.
			fmt.Fprintf(&sb, "# Region groups resolve through %s on their members: publish the exits\n", validate.GroupResolverNet)
			sb.WriteString("# (and the hub) before the gateway. A gateway installed first gets no answer for\n")
			sb.WriteString("# group names until the member in use is re-published; it never falls back to\n")
			sb.WriteString("# another resolver.\n")
			break
		}
	}
	for _, g := range groups {
		if g.Dynamic && g.Mesh && g.MeshResolver != "" {
			fmt.Fprintf(&sb, "# Group %s on the Mesh backup resolves at exit %s: after changing groups or Mesh\n", g.Group.ID, g.MeshResolver)
			fmt.Fprintf(&sb, "# edges, publish that exit and redeploy Mesh so its node publishes %s/128.\n", g.Resolver)
		}
	}
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
