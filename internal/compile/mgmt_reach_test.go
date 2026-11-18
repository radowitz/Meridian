package compile

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// The tunnel management candidates (mgmt_reach.go) against the rendered
// files: for every example topology, every managed node, every address and
// every carrying state of the gateway, the same walk over a network read
// back from the bundle itself (WireGuard Address / AllowedIPs / peer, the
// routes scripts' main-table routes, source rules and return tables, the
// nft connection marks, the forwarding switch) must give the same answer,
// and every way the derivation calls usable is checked hop by hop against
// the rendered AllowedIPs and the gateway's rendered route.

func mgmtExamples() map[string]model.Topology {
	return map[string]model.Topology{
		"example":  defaults.Example(),
		"dualhub":  defaults.DualHubExample(),
		"shared":   defaults.SharedRelaysExample(),
		"nested":   defaults.NestedExample(),
		"external": defaults.ExternalExample(),
	}
}

var (
	reRoute   = regexp.MustCompile(`^ip (-6 )?route replace (blackhole )?(\S+)(?: dev (\S+))?(?: src (\S+))?(?: metric (\d+))?(?: table (\d+))?$`)
	reFrom    = regexp.MustCompile(`^ip (-6 )?rule add from (\S+) lookup (\d+) priority (\d+)$`)
	reFwmark  = regexp.MustCompile(`^ip (-6 )?rule add fwmark (0x[0-9a-f]+) lookup (\d+) priority (\d+)$`)
	reCtMark  = regexp.MustCompile(`iifname "(\S+)" ct direction original ct mark set (0x[0-9a-f]+)`)
	reLoAddr  = regexp.MustCompile(`^ip (?:-6 )?addr replace (\S+) dev lo$`)
	reAddress = regexp.MustCompile(`(?m)^Address = (.+)$`)
	reAllowed = regexp.MustCompile(`(?m)^AllowedIPs = (.+)$`)
	rePeer    = regexp.MustCompile(`(?m)^# peer-node (\S+)$`)
	reLink    = regexp.MustCompile(`(?m)^# meridian link (\S+) `)
)

// renderedNet reads the network of carrying state st back from bundle b.
func renderedNet(t *testing.T, b *Bundle, st MgmtState, gw string) *rNet {
	t.Helper()
	w := &rNet{nodes: map[string]*rNode{}}
	nodes := map[string]bool{}
	for p := range b.Files {
		if strings.HasPrefix(p, "nodes/") {
			nodes[strings.SplitN(strings.TrimPrefix(p, "nodes/"), "/", 2)[0]] = true
		}
	}
	for id := range nodes {
		pre := "nodes/" + id + "/"
		n := newRNode(id)
		n.fwd6 = strings.Contains(b.Files[pre+"etc/meridian/forwarding.conf"], "net.ipv6.conf.all.forwarding=1")
		for p, body := range b.Files {
			if !strings.HasPrefix(p, pre+"etc/wireguard/") || !strings.HasSuffix(p, ".conf") {
				continue
			}
			peer := rePeer.FindStringSubmatch(body)
			if peer == nil {
				continue // remote access: no node behind it
			}
			iface := strings.TrimSuffix(strings.TrimPrefix(p, pre+"etc/wireguard/"), ".conf")
			link := ""
			if m := reLink.FindStringSubmatch(body); m != nil {
				link = m[1]
			}
			n.addIface(iface, peer[1], link, strings.Split(reAddress.FindStringSubmatch(body)[1], ","), reAllowed.FindStringSubmatch(body)[1])
		}
		n.connected()
		type key struct {
			dst    netip.Prefix
			metric int
			table  int
			hole   bool
		}
		routes := map[key]rRoute{}
		var order []key
		marks := map[string]int{}
		for _, line := range strings.Split(b.Files[pre+"usr/local/sbin/meridian-routes.sh"], "\n") {
			if strings.Contains(line, "$") || strings.HasPrefix(line, " ") {
				continue
			}
			line = strings.ReplaceAll(line, "'", "")
			if m := reRoute.FindStringSubmatch(line); m != nil {
				p, ok := mustPrefix(m[3])
				if !ok {
					if m[3] == "default" {
						p = netip.MustParsePrefix("0.0.0.0/0")
						if m[1] != "" {
							p = netip.MustParsePrefix("::/0")
						}
					} else {
						t.Fatalf("%s: route %q", id, line)
					}
				}
				r := rRoute{dst: p.Masked(), dev: m[4], blackhole: m[2] != ""}
				if m[5] != "" {
					r.src = netip.MustParseAddr(m[5])
				}
				if m[6] != "" {
					r.metric, _ = strconv.Atoi(m[6])
				}
				table := 254
				if m[7] != "" {
					table, _ = strconv.Atoi(m[7])
				}
				k := key{r.dst, r.metric, table, r.blackhole}
				if _, seen := routes[k]; !seen {
					order = append(order, k)
				}
				routes[k] = r
				continue
			}
			if m := reFrom.FindStringSubmatch(line); m != nil {
				tb, _ := strconv.Atoi(m[3])
				prio, _ := strconv.Atoi(m[4])
				p, _ := mustPrefix(m[2])
				n.rules = append(n.rules, rRule{from: p.Masked(), table: tb, prio: prio})
				continue
			}
			if m := reFwmark.FindStringSubmatch(line); m != nil {
				tb, _ := strconv.Atoi(m[3])
				marks[m[2]] = tb
				continue
			}
			if m := reLoAddr.FindStringSubmatch(line); m != nil {
				if p, ok := mustPrefix(m[1]); ok {
					n.local = append(n.local, p.Addr())
				}
			}
		}
		for _, k := range order {
			r := routes[k]
			if k.table == 254 {
				n.main = append(n.main, r)
			} else {
				n.tables[k.table] = append(n.tables[k.table], r)
			}
		}
		if id == gw {
			// What upstream_apply / apply_choice / share_designate do for st.
			var kept []rRoute
			for _, r := range n.main {
				if !r.blackhole && r.src == (netip.Addr{}) && (r.dst.String() == "10.66.0.0/16" || r.dst.String() == "fd66::/48") {
					continue
				}
				kept = append(kept, r)
			}
			n.main = kept
			n.add(&n.main, "10.66.0.0/16", st.Iface)
			n.add(&n.main, "fd66::/48", st.Iface)
		}
		for _, m := range reCtMark.FindAllStringSubmatch(b.Files[pre+"etc/nftables.d/meridian.nft"], -1) {
			if tb, ok := marks[m[2]]; ok {
				n.ret[m[1]] = n.tables[tb]
			}
		}
		w.nodes[id] = n
	}
	return w
}

// hopParts splits "a（m00）→ b".
func hopParts(h string) (from, iface, to string) {
	i, j := strings.Index(h, "（"), strings.Index(h, "）→ ")
	return h[:i], h[i+len("（") : j], h[j+len("）→ "):]
}

func confOf(b *Bundle, node, iface string) string {
	return b.Files["nodes/"+node+"/etc/wireguard/"+iface+".conf"]
}

func allowedHas(conf string, a string) bool {
	m := reAllowed.FindStringSubmatch(conf)
	if m == nil {
		return false
	}
	addr := netip.MustParseAddr(a)
	for _, x := range strings.Split(m[1], ",") {
		if p, ok := mustPrefix(strings.TrimSpace(x)); ok && p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
			return true
		}
	}
	return false
}

func TestMgmtCandidatesMatchRenderedConfigs(t *testing.T) {
	names := make([]string, 0)
	for k := range mgmtExamples() {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		topo := mgmtExamples()[name]
		t.Run(name, func(t *testing.T) {
			b := mustCompile(t, topo)
			gw, _ := gatewayNode(topo)
			usable := 0
			for _, n := range managedNodes(topo) {
				r, err := ManagementCandidates(topo, n.ID)
				if err != nil {
					t.Fatal(err)
				}
				if n.Role == model.RoleGateway {
					if len(r.Candidates) != 0 {
						t.Fatalf("gateway candidates %+v", r.Candidates)
					}
					continue
				}
				if len(r.Candidates) == 0 {
					tunnels, _ := buildTunnels(topo)
					if len(tunnelsFor(tunnels, n.ID)) != 0 {
						t.Fatalf("%s: no candidates", n.ID)
					}
					continue
				}
				nets := map[string]*rNet{}
				for _, st := range r.States {
					nets[st.ID] = renderedNet(t, b, st, gw.ID)
				}
				for _, c := range r.Candidates {
					works := map[string]MgmtPath{}
					for _, w := range c.Works {
						works[w.State] = w
					}
					fails := map[string]MgmtFailure{}
					for _, f := range c.Fails {
						fails[f.State] = f
					}
					for _, st := range r.States {
						got := nets[st.ID].roundTrip(gw.ID, n.ID, c.Iface, netip.MustParseAddr(c.Address))
						w, ok := works[st.ID]
						if got.ok != ok {
							t.Fatalf("%s %s state %s: derivation usable=%v, rendered files usable=%v (%s / %s)", n.ID, c.Address, st.ID, ok, got.ok, fails[st.ID].Reason, got.reason)
						}
						if !ok {
							if got.reason != fails[st.ID].Reason || got.unknown != fails[st.ID].Unknown {
								t.Fatalf("%s %s state %s: reason %q, rendered %q", n.ID, c.Address, st.ID, fails[st.ID].Reason, got.reason)
							}
							continue
						}
						usable++
						if strings.Join(got.hops, "|") != strings.Join(w.Hops, "|") || strings.Join(got.replyHops, "|") != strings.Join(w.ReplyHops, "|") || got.src.String() != w.Source {
							t.Fatalf("%s %s state %s: way %v/%v from %s, rendered %v/%v from %s", n.ID, c.Address, st.ID, w.Hops, w.ReplyHops, w.Source, got.hops, got.replyHops, got.src)
						}
						// Hop by hop on the files themselves: the gateway's
						// first interface exists; every request hop's sender
						// lets the address out and its receiver lets the
						// gateway's source in; every reply hop the same the
						// other way round.
						if confOf(b, gw.ID, w.Iface) == "" {
							t.Fatalf("%s %s: gateway iface %s has no configuration", n.ID, c.Address, w.Iface)
						}
						for _, h := range w.Hops {
							from, iface, to := hopParts(h)
							if !allowedHas(confOf(b, from, iface), c.Address) || !allowedHas(confOf(b, to, iface), w.Source) {
								t.Fatalf("%s %s: request hop %s not allowed by the rendered AllowedIPs", n.ID, c.Address, h)
							}
						}
						for _, h := range w.ReplyHops {
							from, iface, to := hopParts(h)
							if !allowedHas(confOf(b, from, iface), w.Source) || !allowedHas(confOf(b, to, iface), c.Address) {
								t.Fatalf("%s %s: reply hop %s not allowed by the rendered AllowedIPs", n.ID, c.Address, h)
							}
						}
					}
				}
			}
			if usable == 0 {
				t.Fatal("no usable way at all")
			}
		})
	}
}

func candidate(t *testing.T, topo model.Topology, node, addr string) MgmtCandidate {
	t.Helper()
	r, err := ManagementCandidates(topo, node)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Candidates {
		if c.Address == addr {
			return c
		}
	}
	t.Fatalf("%s has no candidate %s", node, addr)
	return MgmtCandidate{}
}

func worksIn(c MgmtCandidate) string {
	var s []string
	for _, w := range c.Works {
		s = append(s, w.State)
	}
	return strings.Join(s, ",")
}

// The cases of the derivation on the example topologies (addresses from
// internal/defaults): a hub-attached exit, a nested exit, a relay, the
// primary hub and the backup hub.
func TestMgmtCandidateCases(t *testing.T) {
	dual := defaults.NestedExample()
	cases := []struct {
		topo                model.Topology
		node, addr          string
		status, depends, ok string
		reason              []string
	}{
		// Hub-attached exit: its ULA on the link to the primary hub works on
		// the main path only; on the backup hub's link only on the backup.
		{dual, "dc1", "fd66:0:0:6::2", MgmtUsable, MgmtDependsMain, "udp,wss", nil},
		{dual, "dc1", "fd66:0:0:4::2", MgmtUsable, MgmtDependsBackup, "backup", nil},
		// … its IPv4: the relay drops 10.66/16 into a blackhole, and the
		// exit's AllowedIPs toward the hub do not include the gateway's
		// tunnel IPv4 address, so a reply could not return either.
		{dual, "dc1", "10.66.6.2", MgmtUnreachable, "", "", []string{"黑洞", "AllowedIPs 不包含目的地址 10.66.2.1"}},
		// Nested exit: its ULA follows whichever hub carries.
		{dual, "twnat", "fd66:0:0:8::2", MgmtUsable, MgmtDependsAny, "udp,wss,backup", nil},
		{dual, "twnat", "10.66.8.2", MgmtUnreachable, "", "", []string{"黑洞"}},
		// The relay exit's own address toward the nested exit: no hop has a
		// route more specific than fd66::/48, the packet loops.
		{dual, "dc1", "fd66:0:0:8::1", MgmtUnreachable, "", "", []string{"路由成环"}},
		// Relay: the gateway's own tunnel to it, and its IX-side address
		// over the main path.
		{dual, "access", "10.66.2.2", MgmtUsable, MgmtDependsOwnLink, "udp,wss,backup", nil},
		{dual, "access", "fd66:0:0:1::1", MgmtUsable, MgmtDependsMain, "udp,wss", nil},
		// Primary hub: its relay-side IPv4 by the gateway's probe route
		// (source 10.66.200.2) in every state, always over the relay.
		{dual, "ix", "10.66.1.2", MgmtUsable, MgmtDependsMain, "udp,wss,backup", nil},
		{dual, "ix", "10.66.6.1", MgmtUnreachable, "", "", []string{"黑洞"}},
		// Backup hub: the gateway's own WSS to it; its exit-side addresses
		// only while it carries.
		{dual, "hkb", "10.66.3.2", MgmtUsable, MgmtDependsOwnLink, "udp,wss,backup", nil},
		{dual, "hkb", "10.66.4.1", MgmtUsable, MgmtDependsBackup, "backup", nil},
		// Single hub: an exit's ULA works on every way (main legs and the
		// home-to-hub WSS); the hub's exit-side IPv4 only from the gateway's
		// own WSS to it.
		{defaults.Example(), "jp", "fd66:0:0:20::2", MgmtUsable, MgmtDependsAny, "udp,wss,direct", nil},
		{defaults.Example(), "hk-hub", "10.66.20.1", MgmtUsable, MgmtDependsFallback, "direct", nil},
		{defaults.Example(), "hk-hub", "fd66:0:0:4::2", MgmtUsable, MgmtDependsOwnLink, "udp,wss,direct", nil},
		// Relay sharing: a relay's IX-side IPv4 only while it is designated.
		{defaults.SharedRelaysExample(), "access2", "10.66.2.1", MgmtUsable, MgmtDependsMain, "relay:access2", nil},
	}
	for _, tc := range cases {
		c := candidate(t, tc.topo, tc.node, tc.addr)
		if c.Status != tc.status || c.Depends != tc.depends || worksIn(c) != tc.ok {
			t.Fatalf("%s %s: %s/%s works %s (want %s/%s %s) %s", tc.node, tc.addr, c.Status, c.Depends, worksIn(c), tc.status, tc.depends, tc.ok, c.Reason)
		}
		for _, r := range tc.reason {
			if !strings.Contains(c.Reason, r) {
				t.Fatalf("%s %s: reason %q lacks %q", tc.node, tc.addr, c.Reason, r)
			}
		}
		if c.Status == MgmtUsable && (c.Works[0].Source == "" || len(c.Works[0].Hops) == 0 || len(c.Works[0].ReplyHops) == 0) {
			t.Fatalf("%s %s: usable without a way %+v", tc.node, tc.addr, c.Works[0])
		}
		if c.LinkID == "" || c.PeerID == "" || (c.Family != "ipv4" && c.Family != "ipv6") {
			t.Fatalf("%s %s: link/peer/family %+v", tc.node, tc.addr, c)
		}
	}
}

// A hop the derivation cannot decide (a peer whose configuration the panel
// does not have) is unknown, never usable.
func TestMgmtCandidateUnknown(t *testing.T) {
	topo := defaults.NestedExample()
	tunnels, err := buildTunnels(topo)
	if err != nil {
		t.Fatal(err)
	}
	st := mgmtStates(topo, tunnels)[0]
	w := planNet(topo, tunnels, "gw", st)
	delete(w.nodes, "ix")
	r := w.roundTrip("gw", "dc1", "", netip.MustParseAddr("fd66:0:0:6::2"))
	if r.ok || !r.unknown || !strings.Contains(r.reason, "不是受管节点") {
		t.Fatalf("%+v", r)
	}
	c := MgmtCandidate{Fails: []MgmtFailure{{State: st.ID, Reason: r.reason, Unknown: true}}}
	classify(&c)
	if c.Status != MgmtUnknown || c.Reason == "" {
		t.Fatalf("%+v", c)
	}
	// No carrying state at all: unknown with the reason.
	c = MgmtCandidate{}
	classify(&c)
	if c.Status != MgmtUnknown || c.Reason == "" {
		t.Fatalf("%+v", c)
	}
}
