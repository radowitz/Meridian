package compile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// The path MTU of an exit is the minimum over every path that can carry its
// traffic (validate.exitPathMTU), not only the reported primary path. These
// tests lower one link that is NOT on the reported path and check that the
// path report and every clamp derived from it (chain mss, sniff_mss,
// local_mss, local_mss_in, every node's tunnel_mss_out / tunnel_mss_in)
// follow together. The adoption preview reads the same reports
// (internal/api, TestMTUPreviewFollowsEveryCarryingPath).

func pathOf(t *testing.T, b *Bundle, exit string) validate.PathReport {
	t.Helper()
	for _, p := range b.Paths {
		if p.ExitID == exit {
			return p
		}
	}
	t.Fatalf("no path report for %s", exit)
	return validate.PathReport{}
}

func setLink(t *testing.T, topo *model.Topology, id string, f func(*model.Link)) {
	t.Helper()
	for i := range topo.Links {
		if topo.Links[i].ID == id {
			f(&topo.Links[i])
			return
		}
	}
	t.Fatalf("no link %s", id)
}

func onPath(p validate.PathReport, link string) bool {
	for _, l := range p.Links {
		if l == link {
			return true
		}
	}
	return false
}

// otherRelay is the sharing relay of the shared-relays example that is not
// on dc1's reported path, with its gateway link and its link to the IX.
func otherRelay(t *testing.T, topo model.Topology) (relay, gwLink, ixLink string) {
	t.Helper()
	p := pathOf(t, mustCompile(t, topo), "dc1")
	switch {
	case onPath(p, "gw-access2"):
		return "access", "gw-access", "access-ix"
	case onPath(p, "gw-access"):
		return "access2", "gw-access2", "access2-ix"
	}
	t.Fatalf("dc1's path %v uses neither relay", p.Links)
	return "", "", ""
}

// checkAllClamps: every gateway chain and every node's tunnel clamp carries
// mss4/mss6 and the forward header says so.
func checkAllClamps(t *testing.T, topo model.Topology, b *Bundle, mss4, mss6 string) {
	t.Helper()
	gw := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	if got := clampOf(t, gw); got != mss4+"/"+mss6 {
		t.Errorf("forward clamp %s, want %s/%s", got, mss4, mss6)
	}
	chains := []string{"mss", "local_mss", "local_mss_in"}
	if topo.SniffOn() {
		chains = append(chains, "sniff_mss")
	}
	for _, c := range chains {
		body := chainBlock(gw, c)
		if body == "" {
			t.Errorf("gateway chain %s missing", c)
			continue
		}
		for _, v := range []string{mss4, mss6} {
			if !strings.Contains(body, "maxseg size set "+v) {
				t.Errorf("gateway %s does not clamp to %s:\n%s", c, v, body)
			}
		}
	}
	for _, n := range managedNodes(topo) {
		if n.Role == model.RoleGateway {
			continue
		}
		nft := b.File("nodes/" + n.ID + "/etc/nftables.d/meridian.nft")
		for _, c := range []string{"tunnel_mss_out", "tunnel_mss_in"} {
			body := chainBlock(nft, c)
			if body == "" {
				continue
			}
			want := []string{mss4, mss6}
			if meshLegExits(topo)[n.ID] {
				// An exit with a Mesh leg clamps its own TCP to its own
				// path (which counts the Mesh leg), below the floor.
				p := pathOf(t, b, n.ID)
				want = []string{fmt.Sprint(p.MSS4), fmt.Sprint(p.MSS6)}
			}
			for _, v := range want {
				if !strings.Contains(body, "maxseg size set "+v) {
					t.Errorf("%s %s does not clamp to %s:\n%s", n.ID, c, v, body)
				}
			}
		}
	}
}

func TestClampsFollowEveryCarryingPath(t *testing.T) {
	topos := sniffTopologies(t)
	type tc struct {
		name, topo, exit, link string
		set                    func(*model.Link)
		offPath                bool // the link must not be on the reported path
	}
	shared := topos["shared_relays"]
	_, otherGW, otherIX := otherRelay(t, shared)
	mtu1280 := func(l *model.Link) { l.MTU = 1280 }
	cases := []tc{
		{"non-preferred sharing relay: gateway link", "shared_relays", "dc1", otherGW, mtu1280, true},
		{"non-preferred sharing relay: relay to IX", "shared_relays", "dc1", otherIX, mtu1280, true},
		{"backup hub to exit", "dual_hub", "dc1", "hkb-dc1", mtu1280, true},
		{"backup hub to exit (relay sharing)", "shared_relays", "dc2", "hkb-dc2", mtu1280, true},
		{"WSS companion leg of the gateway's failover link", "example", "jp", "gw-access", func(l *model.Link) { l.WSSMTU = 1280 }, false},
		{"relay's own IX replacement WSS", "example", "jp", "access-hub-wss", mtu1280, true},
		{"inner link of a nested exit", "nested", "twnat", "twnat-dc1", mtu1280, false},
	}
	// The WSS companion on the relay that is not on the reported path.
	if otherGW == "gw-access" {
		cases = append(cases, tc{"WSS companion leg of the non-preferred relay", "shared_relays", "dc1", "gw-access", func(l *model.Link) { l.WSSMTU = 1280 }, true})
	} else {
		ex := shared
		setLink(t, &ex, "gw-access2", func(l *model.Link) { l.Transport = model.TransportUDPWSSFailover })
		topos["shared_relays_failover2"] = ex
		cases = append(cases, tc{"WSS companion leg of the non-preferred relay", "shared_relays_failover2", "dc1", "gw-access2", func(l *model.Link) { l.WSSMTU = 1280 }, true})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			topo := topos[c.topo]
			topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
			topo.Links = append([]model.Link(nil), topo.Links...)
			before := mustCompile(t, topo)
			p0 := pathOf(t, before, c.exit)
			if p0.MTU != 1360 || clampOf(t, before.File("nodes/gw/etc/nftables.d/meridian.nft")) != "1320/1300" {
				t.Fatalf("baseline %s MTU %d, clamp %s: want 1360 and 1320/1300", c.exit, p0.MTU, clampOf(t, before.File("nodes/gw/etc/nftables.d/meridian.nft")))
			}
			if c.offPath && onPath(p0, c.link) {
				t.Fatalf("%s is on the reported path %v: the test does not exercise an alternative path", c.link, p0.Links)
			}
			setLink(t, &topo, c.link, c.set)
			b := mustCompile(t, topo)
			if p := pathOf(t, b, c.exit); p.MTU != 1280 || p.MSS4 != 1240 || p.MSS6 != 1220 {
				t.Fatalf("%s path report %d %d/%d, want 1280 1240/1220", c.exit, p.MTU, p.MSS4, p.MSS6)
			}
			checkAllClamps(t, topo, b, "1240", "1220")
		})
	}
}

// A link that cannot carry an exit's traffic does not change that exit's
// path MTU or its own clamp.
func TestCarryingPathExcludesOtherLinks(t *testing.T) {
	topos := sniffTopologies(t)
	// Another exit's hub link: dc2's report drops, dc1's stays.
	dual := topos["dual_hub"]
	dual.Links = append([]model.Link(nil), dual.Links...)
	setLink(t, &dual, "ix-dc2", func(l *model.Link) { l.MTU = 1280 })
	b := mustCompile(t, dual)
	if p := pathOf(t, b, "dc2"); p.MTU != 1280 {
		t.Errorf("dc2 %d, want 1280", p.MTU)
	}
	if p := pathOf(t, b, "dc1"); p.MTU != 1360 || p.MSS4 != 1320 {
		t.Errorf("dc1 %d/%d changed by dc2's link", p.MTU, p.MSS4)
	}
	// The dual-stack relay's link to the pure-IPv6 exit: only v6-exit's
	// report drops; the Mesh exit keeps its own per-mark clamp (1176/1156:
	// the Mesh path's 1280 less WireGuard's 60, on a 16-byte boundary) and
	// the other exits their 1360.
	ex := topos["example"]
	ex.Links = append([]model.Link(nil), ex.Links...)
	base := mustCompile(t, ex)
	meshClamp := mssValues(chainBlockMark(t, ex, base, "v6-v4out"))
	setLink(t, &ex, "dsrelay-v6", func(l *model.Link) { l.MTU = 1300 })
	b = mustCompile(t, ex)
	if p := pathOf(t, b, "v6-exit"); p.MTU != 1300 {
		t.Errorf("v6-exit %d, want 1300", p.MTU)
	}
	for _, id := range []string{"sg", "jp", "ds-relay"} {
		if p := pathOf(t, b, id); p.MTU != 1360 {
			t.Errorf("%s %d changed by v6-exit's link", id, p.MTU)
		}
	}
	// Exits with a Mesh leg (the pure-IPv6 Mesh exit, and hk-ix next to its
	// direct leg): their path counts the leg.
	for _, id := range []string{"v6-v4out", "hk-ix"} {
		if p := pathOf(t, b, id); p.MTU != 1216 || len(p.MeshLinks)+len(p.Links) == 0 {
			t.Errorf("exit %s with a Mesh leg: path MTU %d, want 1216", id, p.MTU)
		}
	}
	if got := mssValues(chainBlockMark(t, ex, b, "v6-v4out")); strings.Join(got, " ") != strings.Join(meshClamp, " ") || strings.Join(got, " ") != "1176 1156" {
		t.Errorf("Mesh exit's clamp %v → %v", meshClamp, got)
	}
	// A standby gateway–relay link never carries (the gateway's failover
	// and relay sharing use non-standby links only): lowering it changes
	// no report and no clamp.
	sh := topos["shared_relays"]
	sh.Links = append([]model.Link(nil), sh.Links...)
	sh.Nodes = append(sh.Nodes, model.Node{ID: "access3", Name: "relay 3", Role: model.RoleRelay, Region: "cn", Managed: true, WANInterface: "eth0", EndpointV4: "203.0.113.12", PathV4: true})
	sh.Links = append(sh.Links,
		model.Link{ID: "gw-access3", From: "gw", To: "access3", Transport: model.TransportDirectWG, Enabled: true, Standby: true},
		model.Link{ID: "access3-ix", From: "access3", To: "ix", Transport: model.TransportDirectWG, Enabled: true},
	)
	b0 := mustCompile(t, sh)
	setLink(t, &sh, "gw-access3", func(l *model.Link) { l.MTU = 1280 })
	setLink(t, &sh, "access3-ix", func(l *model.Link) { l.MTU = 1280 })
	b1 := mustCompile(t, sh)
	for _, p := range b1.Paths {
		if q := pathOf(t, b0, p.ExitID); q.MTU != p.MTU {
			t.Errorf("%s %d → %d through a link that cannot carry it", p.ExitID, q.MTU, p.MTU)
		}
	}
	if a, c := clampOf(t, b0.File("nodes/gw/etc/nftables.d/meridian.nft")), clampOf(t, b1.File("nodes/gw/etc/nftables.d/meridian.nft")); a != c || a != "1320/1300" {
		t.Errorf("forward clamp %s → %s", a, c)
	}
}

// chainBlockMark: the gateway's chain mss rules for exit id's own mark.
func chainBlockMark(t *testing.T, topo model.Topology, b *Bundle, id string) string {
	t.Helper()
	e, ok := exitByID(planExits(topo, mustTunnels(t, topo)), id)
	if !ok {
		t.Fatalf("no exit plan for %s", id)
	}
	var out []string
	for _, l := range strings.Split(chainBlock(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "mss"), "\n") {
		if strings.Contains(l, fmt.Sprintf("meta mark %#x ", e.Mark)) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// A region group that can fall back to the primary hub's Mesh hop
// (GroupPlan.Mesh) is carried by that hop too: its path MTU
// (Bundle.GroupPaths) is the minimum over its members' paths and the Mesh
// hop (default 1280), and its own mark gets that clamp in chain mss,
// sniff_mss, local_mss and local_mss_in, like a Mesh exit's. The global
// floor, every exit's clamp, every node's tunnel clamp and every group
// without the fallback keep their values.

// markRules: the lines of chain c of the gateway ruleset that match mark
// (or, in local_mss_in, its transit addresses) with a per-mark clamp.
func markRules(gw, c string, m markPlan) []string {
	var out []string
	for _, l := range strings.Split(chainBlock(gw, c), "\n") {
		switch {
		case strings.Contains(l, fmt.Sprintf("meta mark %#x ", m.Mark)),
			strings.Contains(l, "== "+hexMark(m.Mark)+" "),
			m.TransitV4 != "" && strings.Contains(l, "ip daddr "+m.TransitV4+" "),
			m.TransitV6 != "" && strings.Contains(l, "ip6 daddr "+m.TransitV6+" "):
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func TestGroupMeshClampOnEveryChain(t *testing.T) {
	clamped, sniffed := 0, 0
	topos := localMSSTopologies(t)
	for name, topo := range sniffTopologies(t) {
		// localMSSTopologies' sniff_ shapes carry the rules only; these
		// run the forwarder (chain sniff_mss).
		topos["sniff_on_"+name] = sniffOn(topo)
	}
	for name, topo := range topos {
		t.Run(name, func(t *testing.T) {
			b := mustCompile(t, topo)
			gw := b.File("nodes/gw/etc/nftables.d/meridian.nft")
			tunnels := mustTunnels(t, topo)
			exits := planExits(topo, tunnels)
			groups := planGroups(topo, exits)
			floor4, floor6 := mssFloor(b.Paths, meshLegExits(topo))
			if got := clampOf(t, gw); got != fmt.Sprintf("%d/%d", floor4, floor6) {
				t.Fatalf("forward clamp %s, want the exits' floor %d/%d", got, floor4, floor6)
			}
			chains := []string{"mss", "local_mss", "local_mss_in"}
			if topo.SniffOn() {
				chains = append(chains, "sniff_mss")
			}
			reports := map[string]validate.GroupPathReport{}
			for _, r := range b.GroupPaths {
				reports[r.GroupID] = r
			}
			paths := map[string]validate.PathReport{}
			for _, p := range b.Paths {
				paths[p.ExitID] = p
			}
			for _, g := range groups {
				r, ok := reports[g.Group.ID]
				if ok != g.Dynamic {
					t.Fatalf("group %s: dynamic %v but reported %v", g.Group.ID, g.Dynamic, ok)
				}
				m := markPlan{g.Mark, g.Index, g.TransitV4, g.TransitV6}
				if !ok {
					for _, c := range chains {
						if rules := markRules(gw, c, m); len(rules) > 0 {
							t.Errorf("group %s is not switched (its rules use the target's mark) but %s clamps its mark: %q", g.Group.ID, c, rules)
						}
					}
					continue
				}
				// The report: the members' minimum, lowered by the Mesh hop.
				want := 0
				for _, e := range g.Try {
					if p := paths[e.Node.ID]; p.MTU > 0 && (want == 0 || p.MTU < want) {
						want = p.MTU
					}
				}
				// A group has a Mesh hop when a member it may switch to has
				// a Mesh leg from the primary hub.
				gMesh := false
				for _, e := range g.Try {
					gMesh = gMesh || meshLegExits(topo)[e.Node.ID]
				}
				if r.Mesh != gMesh {
					t.Fatalf("group %s: report Mesh %v, members with a Mesh leg %v", g.Group.ID, r.Mesh, gMesh)
				}
				if gMesh {
					if r.MeshMTU <= 0 || len(r.MeshLinks) == 0 {
						t.Fatalf("group %s has a member with a Mesh leg but no Mesh hop in its report: %+v", g.Group.ID, r)
					}
					want = min(want, r.MeshMTU)
				}
				if r.MTU != want || r.MSS4 != want-40 || r.MSS6 != want-60 {
					t.Fatalf("group %s: report %+v, want MTU %d", g.Group.ID, r, want)
				}
				lower := gMesh && (r.MSS4 < floor4 || r.MSS6 < floor6)
				for _, c := range chains {
					rules := markRules(gw, c, m)
					if !lower {
						if len(rules) > 0 {
							t.Errorf("group %s (Mesh %v, MSS %d/%d, floor %d/%d) must keep the floor, but %s has %q", g.Group.ID, gMesh, r.MSS4, r.MSS6, floor4, floor6, c, rules)
						}
						continue
					}
					joined := strings.Join(rules, "\n")
					for _, v := range []int{r.MSS4, r.MSS6} {
						if !strings.Contains(joined, fmt.Sprintf("maxseg size set %d", v)) {
							t.Errorf("group %s with the Mesh fallback: %s does not clamp its mark to %d:\n%s", g.Group.ID, c, v, joined)
						}
					}
				}
				if lower {
					clamped++
					if topo.SniffOn() {
						sniffed++
					}
					// The forwarded SYN-ACK comes back unmarked: chain mss
					// clamps it by the group's transit address.
					fwd := chainBlock(gw, "mss")
					for _, want := range []string{
						fmt.Sprintf("ct direction reply tcp flags syn meta nfproto ipv4 ct reply ip daddr %s tcp option maxseg size > %d tcp option maxseg size set %d", g.TransitV4, r.MSS4, r.MSS4),
						fmt.Sprintf("ct direction reply tcp flags syn meta nfproto ipv6 ct reply ip6 daddr %s tcp option maxseg size > %d tcp option maxseg size set %d", g.TransitV6, r.MSS6, r.MSS6),
					} {
						if !strings.Contains(fwd, want) {
							t.Errorf("group %s: chain mss lacks the reply clamp %q", g.Group.ID, want)
						}
					}
				}
			}
			// Exits: per-mark clamps only for Mesh exits, as before.
			for _, e := range exits {
				m := markPlan{e.Mark, e.Index, e.TransitV4, e.TransitV6}
				rules := markRules(gw, "mss", m)
				if !meshLegExits(topo)[e.Node.ID] && len(rules) > 0 {
					t.Errorf("exit %s has no Mesh hop but chain mss clamps its mark: %q", e.Node.ID, rules)
				}
			}
			// Node chains: the floor (lowered only on a Mesh exit), never a
			// group's value.
			for _, n := range managedNodes(topo) {
				if n.Role == model.RoleGateway {
					continue
				}
				nm := nodeMSSFor(n, exits, floor4, floor6, nil)
				if e, ok := exitByID(exits, n.ID); ok && meshLegExits(topo)[n.ID] {
					p := paths[e.Node.ID]
					nm = nodeMSS{min(nm.MSS4, p.MSS4), min(nm.MSS6, p.MSS6)}
				}
				body := chainBlock(b.File("nodes/"+n.ID+"/etc/nftables.d/meridian.nft"), "tunnel_mss_out")
				if body == "" {
					continue
				}
				want := fmt.Sprintf("%d %d", nm.MSS4, nm.MSS6)
				if n.Role == model.RoleHub {
					// A hub's own TCP into one of its Mesh legs: that leg's
					// smaller value first (mssValues lists each value once).
					if len(meshLegMSS(topo, n, tunnels, nm)) > 0 {
						want = "1176 1156 " + want
					}
				}
				if got := strings.Join(mssValues(body), " "); got != want {
					t.Errorf("%s tunnel_mss_out clamps %s, want %s", n.ID, got, want)
				}
			}
		})
	}
	if clamped == 0 || sniffed == 0 {
		t.Fatalf("%d groups with a Mesh fallback below the floor checked (%d with the forwarder on): the test checked nothing", clamped, sniffed)
	}
}

// TestGroupMeshClampOnlyWithFallback: on the example, groups hk, us, us-pin
// and v6-nat have a member with a Mesh leg (Mesh path 1280: 1216 inside the
// WireGuard leg) and get 1176/1156 on their own marks; the others keep the
// floor 1320/1300. Without hk's Mesh edges hk loses its clamp; a Mesh leg
// that carries as much as the members' paths adds none; nothing else moves.
func TestGroupMeshClampOnlyWithFallback(t *testing.T) {
	base := defaults.Example()
	check := func(t *testing.T, topo model.Topology, want map[string]string) {
		t.Helper()
		b := mustCompile(t, topo)
		gw := b.File("nodes/gw/etc/nftables.d/meridian.nft")
		if got := clampOf(t, gw); got != "1320/1300" {
			t.Errorf("forward clamp %s, want 1320/1300", got)
		}
		groups := planGroups(topo, planExits(topo, mustTunnels(t, topo)))
		for _, g := range groups {
			m := markPlan{g.Mark, g.Index, g.TransitV4, g.TransitV6}
			got := ""
			for _, c := range []string{"mss", "local_mss", "local_mss_in"} {
				got += c + "=" + strings.Join(mssValues(strings.Join(markRules(gw, c, m), "\n")), "/") + " "
			}
			w := want[g.Group.ID]
			if w == "" {
				w = "mss= local_mss= local_mss_in= "
			}
			if got != w {
				t.Errorf("group %s: %s, want %s", g.Group.ID, got, w)
			}
		}
		// The Mesh exit keeps its own clamp.
		if got := chainBlockMark(t, topo, b, "v6-v4out"); !strings.Contains(got, "set 1176") || !strings.Contains(got, "set 1156") {
			t.Errorf("Mesh exit v6-v4out lost its clamp:\n%s", got)
		}
	}
	mesh := "mss=1176/1156 local_mss=1176/1156 local_mss_in=1176/1156 "
	t.Run("example", func(t *testing.T) {
		check(t, base, map[string]string{"hk": mesh, "us": mesh, "us-pin": mesh, "v6-nat": mesh})
	})
	t.Run("hk without Mesh edges", func(t *testing.T) {
		topo := defaults.Example()
		for _, id := range []string{"hub-hkix-mesh", "hub-hk2-mesh"} {
			setLink(t, &topo, id, func(l *model.Link) { l.Enabled = false })
		}
		check(t, topo, map[string]string{"us": mesh, "us-pin": mesh, "v6-nat": mesh})
	})
	t.Run("Mesh leg as large as the members' paths", func(t *testing.T) {
		// A Mesh path of 1420 leaves the leg 1360, the members' own MTU.
		topo := defaults.Example()
		setLink(t, &topo, "hub-us-mesh", func(l *model.Link) { l.MTU = 1420 })
		check(t, topo, map[string]string{"hk": mesh, "v6-nat": mesh})
	})
}
