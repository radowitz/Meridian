package compile

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Synthetic regression for LAN traffic to tunnel endpoints (endpointAccess,
// validate.EndpointAccess). Addresses are the examples' documentation
// ranges; nothing here touches a real host.

var reEndpointSet = regexp.MustCompile(`(?m)^  set (endpoint_[a-z]+[46]) \{\n(?:    [^\n]*\n)*?(?:    elements = \{ ([^}]*) \}\n)?  \}`)

// endpointSets parses the gateway's endpoint_* sets.
func endpointSets(t *testing.T, nft string) map[string][]netip.Addr {
	t.Helper()
	out := map[string][]netip.Addr{}
	for _, m := range reEndpointSet.FindAllStringSubmatch(nft, -1) {
		out[m[1]] = nil
		if m[2] == "" {
			continue
		}
		for _, e := range strings.Split(m[2], ", ") {
			out[m[1]] = append(out[m[1]], netip.MustParseAddr(strings.TrimSpace(e)))
		}
	}
	for _, n := range []string{"endpoint_block4", "endpoint_block6", "endpoint_direct4", "endpoint_direct6", "endpoint_tunnel4", "endpoint_tunnel6"} {
		if _, ok := out[n]; !ok {
			t.Fatalf("no set %s", n)
		}
	}
	return out
}

// classifyEndpoint evaluates the first classify rule that names an endpoint
// set holding a: "drop", the mark set, or "" when no endpoint rule matches.
// It also returns the rule's index in the chain.
func classifyEndpoint(t *testing.T, chain []string, sets map[string][]netip.Addr, a netip.Addr) (string, int) {
	t.Helper()
	for i, l := range chain {
		rule, _, _ := strings.Cut(l, " comment ")
		f := strings.Fields(rule)
		if len(f) < 3 || !strings.HasPrefix(f[2], "@endpoint_") {
			continue
		}
		set := strings.TrimPrefix(f[2], "@")
		hit := false
		for _, e := range sets[set] {
			hit = hit || e == a
		}
		if !hit {
			continue
		}
		if strings.HasSuffix(rule, " drop") {
			return "drop", i
		}
		if m := reClsMark.FindStringSubmatch(rule); m != nil {
			return m[1], i
		}
		t.Fatalf("endpoint rule without verdict: %s", l)
	}
	return "", -1
}

func endpointTopologies() map[string]func() model.Topology {
	return map[string]func() model.Topology{
		"example": defaults.Example, "dual_hub": defaults.DualHubExample, "shared_relays": defaults.SharedRelaysExample,
		"nested": defaults.NestedExample, "external": defaults.ExternalExample,
	}
}

// Domestic endpoints (relays, the IX ingress) are direct; foreign ones take
// the default group's mark; the backup hub the gateway itself dials stays
// dropped with a reason. All of it ahead of every rule and of chnroute.
func TestEndpointAccessDualHub(t *testing.T) {
	b := dualBundle(t)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	chain := classifyChain(t, nft)
	sets := endpointSets(t, nft)
	def := regexp.MustCompile(`(?m)^# default-exit \S+ group \S+ mark (0x[0-9a-f]+)$`).FindStringSubmatch(nft)
	if def == nil {
		t.Fatal("no default-exit header")
	}
	dom := fmt.Sprintf("%#x", markDomestic)
	firstRule := len(chain)
	for i, l := range chain {
		if strings.Contains(l, "@chnroute") || strings.Contains(l, "@direct4") {
			firstRule = i
			break
		}
	}
	want := map[string]struct{ verdict, class, node string }{
		"203.0.113.10":  {dom, validate.EndpointDirect, "access"}, // domestic relay (port forward to the IX's SSH)
		"198.51.100.10": {dom, validate.EndpointDirect, "ix"},     // IX domestic ingress
		"203.0.113.20":  {def[1], validate.EndpointTunnel, "ix"},  // IX Hong Kong egress
		"203.0.113.41":  {def[1], validate.EndpointTunnel, "dc1"}, // foreign exit
		"203.0.113.42":  {def[1], validate.EndpointTunnel, "dc2"}, // foreign exit
		"203.0.113.30":  {def[1], validate.EndpointTunnel, "hkb"}, // backup hub: the gateway's own WSS peer, still via the default group
	}
	rows := map[string]validate.EndpointAccess{}
	for _, e := range b.EndpointAccess {
		rows[e.Addr] = e
	}
	if len(rows) != len(want) {
		t.Errorf("EndpointAccess has %d rows, want %d: %+v", len(rows), len(want), b.EndpointAccess)
	}
	for addr, w := range want {
		got, i := classifyEndpoint(t, chain, sets, netip.MustParseAddr(addr))
		if got != w.verdict {
			t.Errorf("%s: classify verdict %q, want %q", addr, got, w.verdict)
		}
		if i >= firstRule {
			t.Errorf("%s: endpoint rule %d is not ahead of the rules and chnroute (%d)", addr, i, firstRule)
		}
		r := rows[addr]
		if r.Class != w.class || r.NodeID != w.node || r.Reason == "" {
			t.Errorf("%s: row %+v, want class %s node %s with a reason", addr, r, w.class, w.node)
		}
	}
}

// Across every example: no foreign endpoint is ever in a direct set (no
// home-uplink leak), every tunnel-class endpoint gets an exit mark, the
// gateway's own foreign tunnel peers go to the default group too (their
// outer packets never pass classify), sets and rows agree, and the
// endpoint rules sit after the 10.66/ULA drops and before link-local.
func TestEndpointAccessNoLeakNoRecursion(t *testing.T) {
	for name, mk := range endpointTopologies() {
		topo := mk()
		model.MigrateRegionGroups(&topo)
		b := mustCompile(t, topo)
		nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
		chain := classifyChain(t, nft)
		sets := endpointSets(t, nft)
		peers := validate.EndpointGatewayPeers(topo)
		n := 0
		for _, s := range sets {
			n += len(s)
		}
		if n != len(b.EndpointAccess) {
			t.Errorf("%s: %d set elements, %d rows", name, n, len(b.EndpointAccess))
		}
		for _, e := range b.EndpointAccess {
			node, _ := topo.NodeByID(e.NodeID)
			a := netip.MustParseAddr(e.Addr)
			got, _ := classifyEndpoint(t, chain, sets, a)
			domestic := validate.EndpointDomestic(node, e.Addr)
			switch {
			case domestic:
				if e.Class != validate.EndpointDirect || got != fmt.Sprintf("%#x", markDomestic) {
					t.Errorf("%s: domestic %s (%s): class %s verdict %s", name, e.Addr, e.NodeID, e.Class, got)
				}
			case peers[e.NodeID]:
				// Client traffic to a peer the gateway itself dials (the
				// backup hub) takes the default group's tunnel mark; the
				// gateway's own outer packets to it never see classify.
				var m uint32
				fmt.Sscanf(got, "0x%x", &m)
				if e.Class != validate.EndpointTunnel || m < markExitBase {
					t.Errorf("%s: gateway peer %s (%s) must go to the default group's tunnel: class %s verdict %s", name, e.Addr, e.NodeID, e.Class, got)
				}
				outerOK := false
				for p, body := range b.Files {
					if strings.HasPrefix(p, "nodes/"+gatewayID(t, topo)+"/etc/wireguard/") && strings.Contains(body, fmt.Sprintf("FwMark = %#x", markUnderlay)) {
						outerOK = true
					}
				}
				if !outerOK {
					t.Errorf("%s: no gateway WireGuard config with the underlay fwmark", name)
				}
				for _, l := range strings.Split(nft, "\n") {
					if strings.Contains(l, "jump classify") && !strings.HasPrefix(strings.TrimSpace(l), "iifname ") {
						t.Errorf("%s: classify reached without a LAN ingress match (local outer packets would pass it): %s", name, l)
					}
					if strings.Contains(l, "hook output") && strings.Contains(l, "classify") {
						t.Errorf("%s: classify on output: %s", name, l)
					}
				}
			default:
				if got == fmt.Sprintf("%#x", markDomestic) || got == "" {
					t.Errorf("%s: foreign %s (%s) would leave on the home uplink: %q", name, e.Addr, e.NodeID, got)
				}
				if e.Class == validate.EndpointTunnel {
					var m uint32
					fmt.Sscanf(got, "0x%x", &m)
					if m < markExitBase {
						t.Errorf("%s: foreign %s got non-exit mark %s", name, e.Addr, got)
					}
				}
			}
		}
		idx := func(p string) int {
			for i, l := range chain {
				if strings.HasPrefix(l, p) {
					return i
				}
			}
			t.Fatalf("%s: no %q", name, p)
			return -1
		}
		ula, blk, tun6, ll := idx("ip6 daddr fc00::/7 drop"), idx("ip daddr @endpoint_block4 drop"), idx("ip6 daddr @endpoint_tunnel6"), idx("ip6 daddr { fe80::/10")
		if !(idx("ip daddr 10.66.0.0/16 drop") < ula && ula < blk && blk < tun6 && tun6 < ll) {
			t.Errorf("%s: endpoint rules out of place:\n%s", name, strings.Join(chain, "\n"))
		}
		if strings.Contains(nftBlock(t, nft, "meridian_guard"), "endpoint_") {
			t.Errorf("%s: the guard must not change", name)
		}
	}
}

// The gateway's own outer packets are unchanged: its WireGuard configs keep
// the underlay fwmark and dial the same endpoints (local output never
// passes classify), and nothing outside the gateway's nft names the sets.
func TestEndpointAccessOuterUnchanged(t *testing.T) {
	for name, mk := range endpointTopologies() {
		topo := mk()
		model.MigrateRegionGroups(&topo)
		b := mustCompile(t, topo)
		for p, body := range b.Files {
			if strings.Contains(body, "endpoint_block") || strings.Contains(body, "endpoint_direct") || strings.Contains(body, "endpoint_tunnel") {
				if p != "nodes/"+gatewayID(t, topo)+"/etc/nftables.d/meridian.nft" {
					t.Errorf("%s: %s names an endpoint set", name, p)
				}
			}
			if strings.HasPrefix(p, "nodes/"+gatewayID(t, topo)+"/etc/wireguard/") && strings.HasSuffix(p, ".conf") && strings.Contains(body, "Endpoint = ") {
				if !strings.Contains(body, fmt.Sprintf("FwMark = %#x", markUnderlay)) && !strings.Contains(body, fmt.Sprintf("FwMark = %d", markUnderlay)) {
					t.Errorf("%s: %s lost the underlay fwmark", name, p)
				}
			}
		}
	}
}

// A foreign endpoint whose family the default group cannot carry, and any
// foreign endpoint when the default target is not a tunnel, stays dropped;
// a domestic one is direct either way.
func TestEndpointAccessFamilyAndDefault(t *testing.T) {
	relay := model.Node{ID: "r", Role: model.RoleRelay}
	exit := model.Node{ID: "e", Role: model.RoleExit}
	ix := model.Node{ID: "ix", Role: model.RoleHub, IXLine: true, IngressV4: "198.51.100.10"}
	cases := []struct {
		n            model.Node
		addr         string
		peer, d4, d6 bool
		want         string
	}{
		{relay, "203.0.113.10", true, false, false, validate.EndpointDirect},
		{relay, "2001:db8::10", false, true, false, validate.EndpointDirect},
		{ix, "198.51.100.10", false, true, true, validate.EndpointDirect},
		{ix, "203.0.113.20", false, true, true, validate.EndpointTunnel},
		{exit, "203.0.113.40", false, true, true, validate.EndpointTunnel},
		{exit, "2001:db8::70", false, true, false, validate.EndpointBlocked},
		{exit, "203.0.113.40", false, false, false, validate.EndpointBlocked},
		{exit, "203.0.113.40", true, true, true, validate.EndpointTunnel},
		{exit, "2001:db8::70", true, true, false, validate.EndpointBlocked},
	}
	for _, c := range cases {
		got := validate.ClassifyEndpoint(c.n, c.addr, c.peer, c.d4, c.d6)
		if got.Class != c.want || got.Reason == "" {
			t.Errorf("%s %s peer=%v v4=%v v6=%v: %+v, want %s", c.n.ID, c.addr, c.peer, c.d4, c.d6, got, c.want)
		}
	}
}

// With sniffing on, a connection to a tunnel endpoint is not handed to the
// forwarder: classify's decision (direct or default group) stands and is
// never re-decided by name.
func TestEndpointAccessSniffKeepsDecision(t *testing.T) {
	topo := defaults.DualHubExample()
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
	model.MigrateRegionGroups(&topo)
	nft := mustCompile(t, topo).File("nodes/gw/etc/nftables.d/meridian.nft")
	i := strings.Index(nft, "  chain sniff_mark {\n")
	if i < 0 {
		t.Fatal("no sniff_mark")
	}
	body := nft[i : i+strings.Index(nft[i:], "\n  }\n")]
	red := strings.Index(body, "meta mark set meta mark |")
	for _, s := range []string{"ip daddr @endpoint_direct4 return", "ip daddr @endpoint_tunnel4 return", "ip6 daddr @endpoint_direct6 return", "ip6 daddr @endpoint_tunnel6 return"} {
		j := strings.Index(body, s)
		if j < 0 || j > red {
			t.Errorf("sniff_mark: %q missing or after the redirect mark", s)
		}
	}
}

// The WSS resolution copies the bundle: the endpoint list must survive it
// (the panel's status reads it from the resolved bundle).
func TestEndpointAccessSurvivesWSSResolve(t *testing.T) {
	b, err := Compile(defaults.DualHubExample())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.EndpointAccess) == 0 {
		t.Fatal("dual-hub example compiles no endpoints")
	}
	r, _ := ResolveWSS(b, model.WSSState{})
	if r == nil || len(r.EndpointAccess) != len(b.EndpointAccess) {
		t.Fatalf("ResolveWSS dropped the endpoint list")
	}
}
