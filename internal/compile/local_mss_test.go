package compile

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// chainBlock returns the body of chain name in compiled nft text ("" when
// the chain is not there).
func chainBlock(nft, name string) string {
	start := strings.Index(nft, "  chain "+name+" {\n")
	if start < 0 {
		return ""
	}
	body := nft[start:]
	end := strings.Index(body, "\n  }\n")
	if end < 0 {
		return ""
	}
	return body[:end+len("\n  }\n")]
}

var reSetMSS = regexp.MustCompile(`maxseg size set (\d+)`)

// mssValues: the distinct clamp values of a chain body, in order, without
// the remote-access (mra) rules.
func mssValues(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, "\""+model.RemoteAccessIface+"\"") {
			continue
		}
		if m := reSetMSS.FindStringSubmatch(l); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func localMSSTopologies(t *testing.T) map[string]model.Topology {
	t.Helper()
	out := map[string]model.Topology{}
	ra, _ := raExample(t)
	shared := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&shared)
	dual := defaults.DualHubExample()
	model.MigrateRegionGroups(&dual)
	for name, topo := range map[string]model.Topology{
		"example": defaults.Example(), "remote_access": ra, "dual_hub": dual, "shared_relays": shared,
		"nested": defaults.NestedExample(), "external": defaults.ExternalExample(),
	} {
		out[name] = topo
	}
	for name, topo := range sniffTopologies(t) {
		out["sniff_"+name] = topo
	}
	return out
}

// TestLocalMSSGatewayRules: on every topology shape (single hub, backup hub,
// relay sharing, remote access, nested and external exits, with and without
// the sniffing forwarder) the gateway clamps its own exit- and group-marked
// TCP into the tunnels on output (SYN) and input (SYN-ACK), with exactly
// the forward chain's values, the guard's mark range with the relay bits
// masked, and every gateway tunnel interface (failover companions and the
// backup hub's legs included). Nothing else is matched.
func TestLocalMSSGatewayRules(t *testing.T) {
	for name, topo := range localMSSTopologies(t) {
		t.Run(name, func(t *testing.T) {
			b := mustCompile(t, topo)
			nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
			tunnels := mustTunnels(t, topo)
			exits := planExits(topo, tunnels)
			groups := planGroups(topo, exits)
			fwd := mssValues(chainBlock(nft, "mss"))
			out, in := chainBlock(nft, "local_mss"), chainBlock(nft, "local_mss_in")
			if out == "" || in == "" {
				t.Fatalf("local_mss or local_mss_in missing:\n%s", nft)
			}
			if !strings.Contains(out, "type filter hook output priority -140;") {
				t.Errorf("local_mss is not at output -140 (after the route-type output chains at mangle):\n%s", out)
			}
			if !strings.Contains(in, "type filter hook input priority mangle;") {
				t.Errorf("local_mss_in is not an input chain:\n%s", in)
			}
			for what, body := range map[string]string{"local_mss": out, "local_mss_in": in} {
				if got := mssValues(body); strings.Join(got, " ") != strings.Join(fwd, " ") {
					t.Errorf("%s clamps to %v, chain mss to %v", what, got, fwd)
				}
			}
			quoted := make([]string, 0)
			for _, n := range gatewayTunnelIfaces(tunnels) {
				quoted = append(quoted, "\""+n+"\"")
			}
			ifs := "{ " + strings.Join(quoted, ", ") + " }"
			rng := fmt.Sprintf("meta mark & %s %#x-%#x ", hexMark(markNoShare), markExitBase, guardLastExitMark(exits, groups...))
			for _, l := range strings.Split(out, "\n") {
				if !strings.Contains(l, "maxseg") {
					continue
				}
				if !strings.HasPrefix(strings.TrimSpace(l), "tcp flags syn meta mark & "+hexMark(markNoShare)) || !strings.Contains(l, "oifname "+ifs+" ") {
					t.Errorf("local_mss rule without the SYN, masked-mark and tunnel match: %s", l)
				}
				if strings.Contains(l, "> ") && strings.Contains(l, " set ") {
					m := regexp.MustCompile(`size > (\d+) tcp option maxseg size set (\d+)`).FindStringSubmatch(l)
					if m == nil || m[1] != m[2] {
						t.Errorf("not a decrease-only clamp: %s", l)
					}
				}
				for _, bad := range []string{"udp", hexMark(markUnderlay), fmt.Sprintf("%#x", markUnderlay), "skuid"} {
					if strings.Contains(l, bad) {
						t.Errorf("local_mss rule mentions %s: %s", bad, l)
					}
				}
			}
			if !strings.Contains(out, rng) {
				t.Errorf("local_mss lacks the exit/group mark range %q:\n%s", rng, out)
			}
			for _, l := range strings.Split(in, "\n") {
				if !strings.Contains(l, "maxseg") {
					continue
				}
				if !strings.HasPrefix(strings.TrimSpace(l), "iifname "+ifs+" ct direction reply tcp flags syn") {
					t.Errorf("local_mss_in rule without the tunnel, reply and SYN match: %s", l)
				}
				if !strings.Contains(l, "ct reply ip daddr 10.66.200.") && !strings.Contains(l, "ct reply ip6 daddr fd66:0:0:ff::") {
					t.Errorf("local_mss_in rule not limited to transit sources: %s", l)
				}
			}
			// The ruleset still holds chain mss untouched and, with the
			// forwarder, its own clamp and confinement.
			if topo.SniffOn() {
				if chainBlock(nft, "sniff_mss") == "" || chainBlock(nft, "sniff_out") == "" || !strings.Contains(nft, "  chain sniff_confine {") {
					t.Errorf("the forwarder's chains changed")
				}
				if r := chainBlock(nft, "sniff_route"); r != "" && !strings.Contains(r, "type route hook output priority mangle;") {
					t.Errorf("sniff_route is no longer ahead of local_mss:\n%s", r)
				}
			}
		})
	}
}

// TestLocalMSSFollowsPath: the local-origin clamp is the forward clamp's
// computation, not a number of its own: a smaller link MTU on the path
// lowers chain mss, local_mss, local_mss_in and the nodes' clamps together.
func TestLocalMSSFollowsPath(t *testing.T) {
	topo := defaults.Example()
	before := mustCompile(t, topo).File("nodes/gw/etc/nftables.d/meridian.nft")
	for i := range topo.Links {
		if topo.Links[i].ID == "gw-access" {
			topo.Links[i].MTU = 1340
		}
	}
	b := mustCompile(t, topo)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	fwd := mssValues(chainBlock(nft, "mss"))
	if strings.Join(fwd, " ") == strings.Join(mssValues(chainBlock(before, "mss")), " ") {
		t.Fatalf("a smaller link MTU did not change chain mss (%v): the test does not exercise the path", fwd)
	}
	for _, c := range []string{"local_mss", "local_mss_in"} {
		if got := mssValues(chainBlock(nft, c)); strings.Join(got, " ") != strings.Join(fwd, " ") {
			t.Errorf("%s %v does not follow chain mss %v", c, got, fwd)
		}
	}
	m := regexp.MustCompile(`# mss-clamp v4 (\d+) v6 (\d+)`).FindStringSubmatch(nft)
	if m == nil {
		t.Fatal("no mss-clamp header")
	}
	access := b.File("nodes/access/etc/nftables.d/meridian.nft")
	for _, v := range []string{m[1], m[2]} {
		if !strings.Contains(chainBlock(access, "tunnel_mss_out"), "maxseg size set "+v) {
			t.Errorf("relay access's tunnel_mss_out does not clamp to %s", v)
		}
	}
}

// TestNodeMSSRules: every remote node with Meridian tunnels clamps TCP it
// terminates or opens through them (both directions), on exactly its own
// tunnel interfaces, to the gateway's forward clamp (a Mesh exit to its own
// smaller clamp). The WAN, the Mesh veth and WireGuard's outer UDP are never
// matched; nodes without a tunnel get no chain; the WireGuard MTU written
// for each tunnel is unchanged by the clamp (checked against the goldens).
func TestNodeMSSRules(t *testing.T) {
	for name, topo := range localMSSTopologies(t) {
		t.Run(name, func(t *testing.T) {
			b := mustCompile(t, topo)
			tunnels := mustTunnels(t, topo)
			exits := planExits(topo, tunnels)
			gw := b.File("nodes/gw/etc/nftables.d/meridian.nft")
			m := regexp.MustCompile(`# mss-clamp v4 (\d+) v6 (\d+)`).FindStringSubmatch(gw)
			if m == nil {
				t.Fatal("no mss-clamp header")
			}
			for _, n := range managedNodes(topo) {
				if n.Role == model.RoleGateway {
					continue
				}
				nft := b.File("nodes/" + n.ID + "/etc/nftables.d/meridian.nft")
				out, in := chainBlock(nft, "tunnel_mss_out"), chainBlock(nft, "tunnel_mss_in")
				ifaces := nodeTunnelIfaces(n, tunnels)
				if len(ifaces) == 0 {
					if out != "" || in != "" {
						t.Errorf("%s has no tunnel but a tunnel clamp", n.ID)
					}
					continue
				}
				if out == "" || in == "" {
					t.Fatalf("%s: tunnel_mss_out/in missing:\n%s", n.ID, nft)
				}
				if !strings.Contains(out, "type filter hook output priority -140;") || !strings.Contains(in, "type filter hook input priority mangle;") {
					t.Errorf("%s: hooks:\n%s%s", n.ID, out, in)
				}
				want4, want6 := m[1], m[2]
				if e, ok := exitByID(exits, n.ID); ok {
					for _, l := range strings.Split(chainBlock(gw, "mss"), "\n") {
						if strings.Contains(l, fmt.Sprintf("meta mark %#x ", e.Mark)) {
							if v := reSetMSS.FindStringSubmatch(l); v != nil {
								if strings.Contains(l, "ipv4") {
									want4 = v[1]
								} else {
									want6 = v[1]
								}
							}
						}
					}
				}
				quoted := make([]string, len(ifaces))
				for i, f := range ifaces {
					quoted[i] = "\"" + f + "\""
				}
				ifs := "{ " + strings.Join(quoted, ", ") + " }"
				for _, c := range []struct{ body, dir string }{{out, "oifname"}, {in, "iifname"}} {
					if !strings.Contains(c.body, c.dir+" "+ifs+" tcp flags syn meta nfproto ipv4 tcp option maxseg size > "+want4+" tcp option maxseg size set "+want4) ||
						!strings.Contains(c.body, c.dir+" "+ifs+" tcp flags syn meta nfproto ipv6 tcp option maxseg size > "+want6+" tcp option maxseg size set "+want6) {
						t.Errorf("%s: want %s %s clamped to %s/%s:\n%s", n.ID, c.dir, ifs, want4, want6, c.body)
					}
					wan := n.WANInterface
					if wan == "" {
						wan = "eth0"
					}
					for _, bad := range []string{"\"" + wan + "\"", "udp", "mmesh"} {
						if strings.Contains(c.body, bad) {
							t.Errorf("%s: tunnel clamp mentions %s:\n%s", n.ID, bad, c.body)
						}
					}
				}
			}
		})
	}
}
