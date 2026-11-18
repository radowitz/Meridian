package validate

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func meshIssue(res Result, code string) (Issue, bool) {
	for _, iss := range res.Issues {
		if iss.Code == code {
			return iss, true
		}
	}
	return Issue{}, false
}

func errorCodes(res Result) []string {
	var out []string
	for _, iss := range res.Issues {
		if iss.Severity == SeverityError {
			out = append(out, iss.Code)
		}
	}
	return out
}

func meshLink(topo *model.Topology, id string, fn func(l *model.Link)) {
	for i := range topo.Links {
		if topo.Links[i].ID == id {
			fn(&topo.Links[i])
			return
		}
	}
	panic("no link " + id)
}

// A cf_mesh link from before the Mesh became an underlay still lists the
// routes its exit advertised. It is refused, on that link and field, with
// what the structure is now and how to migrate; the same link without the
// routes is the new structure and is accepted.
func TestMeshLegacyRoutesRefusedWithMigration(t *testing.T) {
	topo := defaults.Example()
	meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.MeshRoutes = []string{"198.51.100.0/24", "2001:db8:66::/48"} })
	res := Run(topo)
	iss, ok := meshIssue(res, "mesh_legacy_routes")
	if !ok || iss.Severity != SeverityError || iss.LinkID != "hub-us-mesh" || iss.Field != "mesh_routes" {
		t.Fatalf("legacy routes: %+v (errors %v)", iss, errorCodes(res))
	}
	for _, want := range []string{"198.51.100.0/24", "清空", "mesh_routes", "WireGuard", "专用地址", "重新下发", "重新部署"} {
		if !strings.Contains(iss.Message, want) {
			t.Errorf("migration note lacks %q:\n%s", want, iss.Message)
		}
	}
	// Also on a disabled edge: the document still carries the old meaning.
	meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.Enabled = false })
	if _, ok := meshIssue(Run(topo), "mesh_legacy_routes"); !ok {
		t.Fatal("a disabled edge with legacy routes is not reported")
	}
	// Migrated: nothing left.
	meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.Enabled, l.MeshRoutes = true, nil })
	if errs := errorCodes(Run(topo)); len(errs) != 0 {
		t.Fatalf("after clearing mesh_routes: %v", errs)
	}
}

// The pool the exits' Mesh addresses come from stays clear of every plan
// Meridian and the topology already use; so every published /32 does.
func TestMeshUnderlayPoolConflicts(t *testing.T) {
	base := privateLAN(defaults.Example())
	for pool, want := range map[string]string{
		"10.66.7.0/24":     "mesh_underlay_conflict", // tunnel plan
		"10.66.200.0/28":   "mesh_underlay_conflict", // transit prefix
		"100.100.0.0/24":   "mesh_underlay_prefix",   // Cloudflare Mesh range: not private
		"169.254.66.0/30":  "mesh_underlay_prefix",   // the veth link: not private
		"10.77.0.0/24":     "mesh_underlay_conflict", // the gateway LAN
		"10.77.0.0/16":     "mesh_underlay_conflict", // contains the LAN
		"203.0.113.0/24":   "mesh_underlay_prefix",   // public
		"fd66:0:0:99::/64": "mesh_underlay_prefix",   // IPv6 (and inside the tunnel ULA)
		"2001:db8:9::/64":  "mesh_underlay_prefix",
		"10.68.0.1/24":     "mesh_underlay_prefix", // not a network address
		"10.0.0.0/8":       "mesh_underlay_prefix", // too wide
		"10.68.0.0/31":     "mesh_underlay_prefix",
		"garbage":          "mesh_underlay_prefix",
	} {
		topo := base
		topo.Settings.MeshUnderlayPrefix = pool
		res := Run(topo)
		iss, ok := meshIssue(res, want)
		if !ok || iss.Severity != SeverityError || iss.Field != "mesh_underlay_prefix" {
			t.Errorf("pool %s: want %s, errors %v", pool, want, errorCodes(res))
		}
	}
	// 100.96.0.0/12 and 169.254.66.0/30 are also refused as plans of their
	// own, whatever the private check says.
	names := map[string]bool{}
	for _, r := range MeshUnderlayReserved(base) {
		names[r.Prefix.String()] = true
	}
	for _, must := range []string{"10.66.0.0/16", "100.96.0.0/12", "169.254.0.0/16", "10.77.0.0/24", "10.66.200.0/24"} {
		if !names[must] {
			t.Errorf("reserved ranges lack %s: %v", must, names)
		}
	}

	// Addresses the topology names: a node's LAN, a manual tunnel address, a
	// node endpoint, the remote-access pool.
	cases := map[string]func(*model.Topology){
		"node LAN": func(tp *model.Topology) {
			for i := range tp.Nodes {
				if tp.Nodes[i].ID == "us" {
					tp.Nodes[i].LANIPv4 = "10.68.0.129/25"
				}
			}
		},
		"manual tunnel address": func(tp *model.Topology) {
			meshLink(tp, "hub-jp", func(l *model.Link) { l.FromV4, l.ToV4 = "10.68.0.9", "10.68.0.10" })
		},
		"node endpoint": func(tp *model.Topology) {
			for i := range tp.Nodes {
				if tp.Nodes[i].ID == "jp" {
					tp.Nodes[i].EndpointV4 = "10.68.0.77"
				}
			}
		},
		"remote-access pool": func(tp *model.Topology) {
			tp.RemoteAccess = &model.RemoteAccess{IPv4Prefix: "10.68.0.0/25"}
		},
	}
	for name, mut := range cases {
		topo := defaults.Example()
		mut(&topo)
		if _, ok := meshIssue(Run(topo), "mesh_underlay_conflict"); !ok {
			t.Errorf("%s inside the pool: not reported (errors %v)", name, errorCodes(Run(topo)))
		}
	}
	// The default remote-access pool and the default Mesh pool do not meet.
	topo := defaults.Example()
	topo.RemoteAccess = &model.RemoteAccess{}
	if iss, ok := meshIssue(Run(topo), "mesh_underlay_conflict"); ok {
		t.Fatalf("default pools conflict: %s", iss.Message)
	}
	// A topology without Mesh edges is never judged by the pool setting.
	plain := defaults.DualHubExample()
	plain.Settings.MeshUnderlayPrefix = "10.66.7.0/24"
	for _, iss := range Run(plain).Issues {
		if strings.HasPrefix(iss.Code, "mesh_") {
			t.Fatalf("no Mesh edge, yet %s: %s", iss.Code, iss.Message)
		}
	}
}

// Each published address is a single /32 of the pool, distinct per exit and
// outside every reserved plan.
func TestMeshUnderlayAddressesDoNotOverlapPlans(t *testing.T) {
	topo := defaults.Example()
	legs := topo.MeshLegs()
	if len(legs) != 4 {
		t.Fatalf("example has %d Mesh legs", len(legs))
	}
	seen := map[string]string{}
	for _, m := range legs {
		if !m.Addr.IsValid() || !m.Addr.Is4() || !strings.HasSuffix(m.Route(), "/32") {
			t.Fatalf("leg %s publishes %q", m.Link.ID, m.Route())
		}
		if other, dup := seen[m.Route()]; dup {
			t.Fatalf("exits %s and %s publish the same address %s", other, m.Exit, m.Route())
		}
		seen[m.Route()] = m.Exit
		for _, r := range MeshUnderlayReserved(topo) {
			if r.Prefix.Contains(m.Addr) {
				t.Fatalf("leg %s address %s is inside %s", m.Link.ID, m.Addr, r.What)
			}
		}
	}
}

// What a Mesh edge may join: the primary hub and a plain exit that already
// has the hub's direct leg (or a pure-IPv6 exit with the Mesh workaround,
// whose only leg it is), once per pair.
func TestMeshLegStructure(t *testing.T) {
	add := func(tp *model.Topology, id, from, to string) {
		tp.Links = append(tp.Links, model.Link{ID: id, Name: id, From: from, To: to, Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	}
	t.Run("duplicate", func(t *testing.T) {
		topo := defaults.Example()
		add(&topo, "hub-us-mesh-2", "hk-hub", "us")
		assertError(t, Run(topo), "mesh_leg_duplicate")
	})
	t.Run("no direct leg", func(t *testing.T) {
		topo := defaults.Example()
		meshLink(&topo, "hub-us", func(l *model.Link) { l.Enabled = false })
		assertError(t, Run(topo), "mesh_leg_no_direct")
		// A standby direct link does not count either.
		topo = defaults.Example()
		meshLink(&topo, "hub-us", func(l *model.Link) { l.Standby = true })
		assertError(t, Run(topo), "mesh_leg_no_direct")
	})
	t.Run("pure IPv6 exit with another workaround", func(t *testing.T) {
		topo := defaults.Example()
		add(&topo, "hub-v6exit-mesh", "hk-hub", "v6-exit") // dual-stack relay workaround
		assertError(t, Run(topo), "mesh_leg_unsupported_exit")
	})
	t.Run("dual-stack relay", func(t *testing.T) {
		topo := defaults.Example()
		add(&topo, "hub-ds-mesh", "hk-hub", "ds-relay")
		assertError(t, Run(topo), "mesh_leg_unsupported_exit")
	})
	t.Run("relay exit and carrier", func(t *testing.T) {
		topo := defaults.NestedExample()
		add(&topo, "ix-dc1-mesh", "ix", "dc1") // dc1 carries the nested exit twnat
		assertError(t, Run(topo), "mesh_leg_unsupported_exit")
		topo = defaults.ExternalExample()
		add(&topo, "ix-dc2-mesh", "ix", "dc2") // dc2 carries the external exit myext
		assertError(t, Run(topo), "mesh_leg_unsupported_exit")
	})
	t.Run("backup hub", func(t *testing.T) {
		topo := defaults.DualHubExample()
		add(&topo, "hkb-dc1-mesh", "hkb", "dc1")
		if errs := errorCodes(Run(topo)); len(errs) != 0 {
			t.Fatalf("a Mesh leg from the backup hub: %v", errs)
		}
	})
	t.Run("both hubs to one exit", func(t *testing.T) {
		topo := defaults.DualHubExample()
		add(&topo, "ix-dc1-mesh", "ix", "dc1")
		add(&topo, "hkb-dc1-mesh", "hkb", "dc1")
		if errs := errorCodes(Run(topo)); len(errs) != 0 {
			t.Fatalf("Mesh legs from both hubs to one exit: %v", errs)
		}
	})
	t.Run("backup hub twice to one exit", func(t *testing.T) {
		topo := defaults.DualHubExample()
		add(&topo, "hkb-dc1-mesh", "hkb", "dc1")
		add(&topo, "hkb-dc1-mesh2", "hkb", "dc1")
		assertError(t, Run(topo), "mesh_leg_duplicate")
	})
	t.Run("primary hub with a backup hub", func(t *testing.T) {
		topo := defaults.DualHubExample()
		add(&topo, "ix-dc1-mesh", "ix", "dc1")
		if errs := errorCodes(Run(topo)); len(errs) != 0 {
			t.Fatalf("a Mesh leg from the primary hub with a backup hub: %v", errs)
		}
	})
	t.Run("not standby, wrong ends", func(t *testing.T) {
		topo := defaults.Example()
		meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.Standby = false })
		assertError(t, Run(topo), "mesh_not_standby")
		topo = defaults.Example()
		add(&topo, "gw-us-mesh", "gw", "us")
		assertError(t, Run(topo), "mesh_bypasses_ix")
	})
}

// A dial-out (NAT) exit takes a Mesh leg like any other: the hub dials its
// Mesh address, the exit listens for it, and none of the NAT dial rules
// apply. The leg's port is its own (the link's wg_port or the slot's
// default), never the exit's listen_port, and it does not make that port
// ambiguous for the exit's ordinary link.
func TestMeshLegEndsAndPorts(t *testing.T) {
	topo := defaults.Example()
	topo.Links = append(topo.Links, model.Link{ID: "hub-tw-mesh", Name: "mesh", From: "hk-hub", To: "tw",
		Transport: model.TransportCFMesh, Enabled: true, Standby: true})
	res := Run(topo)
	if errs := errorCodes(res); len(errs) != 0 {
		t.Fatalf("Mesh leg to a dial-out exit: %v", errs)
	}
	ports := map[string]LinkPorts{}
	for _, lp := range TunnelPorts(topo) {
		ports[lp.LinkID] = lp
	}
	tw := ports["hub-tw-mesh"]
	if tw.Listener != "tw" || tw.Dialer != "hk-hub" || tw.WGFrom != "default" || tw.WG != model.LinkDefaultWGPort(tw.Index) {
		t.Fatalf("Mesh leg to the dial-out exit: %+v", tw)
	}
	// The exit's own (dial-out) link is unchanged: the hub listens.
	if d := ports["tw-hub"]; d.Listener != "hk-hub" || d.Dialer != "tw" {
		t.Fatalf("direct link of the dial-out exit: %+v", d)
	}
	// us listens on its direct link at its listen_port 51820; the Mesh leg
	// neither takes that port nor turns it into the slot default.
	us, mesh := ports["hub-us"], ports["hub-us-mesh"]
	if us.WG != 51820 || mesh.Listener != "us" || mesh.Dialer != "hk-hub" || mesh.WG == us.WG || mesh.WGFrom != "default" {
		t.Fatalf("us ports: direct %+v mesh %+v", us, mesh)
	}
	without := defaults.Example()
	var links []model.Link
	for _, l := range without.Links {
		if l.Transport != model.TransportCFMesh {
			links = append(links, l)
		}
	}
	without.Links = links
	for _, lp := range TunnelPorts(without) {
		if got := ports[lp.LinkID]; got != lp {
			t.Fatalf("link %s ports changed by the Mesh legs: %+v → %+v", lp.LinkID, lp, got)
		}
	}
	// An explicit port on the Mesh link wins.
	meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.WGPort = 51999 })
	for _, lp := range TunnelPorts(topo) {
		if lp.LinkID == "hub-us-mesh" && (lp.WG != 51999 || lp.WGFrom != "link") {
			t.Fatalf("explicit Mesh leg port: %+v", lp)
		}
	}
}

// The Mesh leg's MTU: the Mesh path (default 1280) less WireGuard's
// overhead, as the hop MTU the path reports and every clamp follow; the
// interface stays at 1280 for IPv6, which the warning says. A Mesh path
// that leaves 1280 or more needs neither.
func TestMeshLegMTU(t *testing.T) {
	for path, want := range map[int][2]int{
		0:    {1216, 1280}, // default 1280: 1220, on WireGuard's 16-byte boundary
		1280: {1216, 1280},
		1300: {1232, 1280},
		1339: {1264, 1280},
		1340: {1280, 1280},
		1420: {1360, 1360},
		1500: {1440, 1440},
	} {
		l := model.Link{Transport: model.TransportCFMesh, MTU: path}
		payload, device := MeshLegMTU(l)
		if payload != want[0] || device != want[1] {
			t.Errorf("Mesh path %d: payload %d device %d, want %v", path, payload, device, want)
		}
		if got := hopMTU(l); got != want[0] {
			t.Errorf("Mesh path %d: hop MTU %d, want %d", path, got, want[0])
		}
		if got, field, _ := LegMTU(l, "udp"); got != want[1] || field != "mtu" {
			t.Errorf("Mesh path %d: interface MTU %d (%s), want %d", path, got, field, want[1])
		}
	}
	topo := defaults.Example()
	res := Run(topo)
	n := 0
	for _, iss := range res.Issues {
		if iss.Code != "mesh_leg_fragments" {
			continue
		}
		n++
		if iss.Severity != SeverityWarning || iss.LinkID == "" || !strings.Contains(iss.Message, "1216") || !strings.Contains(iss.Message, "1176") || !strings.Contains(iss.Message, "没有在真实 Mesh 上验证") {
			t.Fatalf("fragment warning: %+v", iss)
		}
	}
	if n != 4 {
		t.Fatalf("%d fragment warnings, want one per Mesh leg (4)", n)
	}
	// The path MTU below 1280 is the Mesh leg's own doing: no mtu_too_low.
	if hasCode(res, "mtu_too_low") {
		t.Fatalf("a Mesh leg's payload MTU is reported as mtu_too_low: %v", errorCodes(res))
	}
	for i := range topo.Links {
		if topo.Links[i].Transport == model.TransportCFMesh {
			topo.Links[i].MTU = 1340
		}
	}
	res = Run(topo)
	if _, ok := meshIssue(res, "mesh_leg_fragments"); ok {
		t.Fatal("a Mesh path of 1340 still warns about fragments")
	}
	for _, p := range res.Paths {
		if p.ExitID == "us" && p.MTU != 1280 {
			t.Fatalf("us over a 1340 Mesh path: MTU %d, want 1280", p.MTU)
		}
	}
	// Anything else below 1280 on the path is still refused.
	topo = defaults.Example()
	meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.MTU = 1200 })
	assertError(t, Run(topo), "mtu_too_low")
}

// The region-group report: a group with a member that has a Mesh leg
// reports the leg.
func TestGroupMeshHopMTU(t *testing.T) {
	topo := defaults.Example()
	m, links := GroupMeshHopMTU(topo, "hk-hub", []string{"us", "us-2"})
	if m != 1216 || len(links) != 1 || links[0] != "hub-us-mesh" {
		t.Fatalf("us group: %d %v", m, links)
	}
	if m, links := GroupMeshHopMTU(topo, "hk-hub", []string{"jp", "sg"}); m != 0 || links != nil {
		t.Fatalf("a group without Mesh legs: %d %v", m, links)
	}
	meshLink(&topo, "hub-us-mesh", func(l *model.Link) { l.Enabled = false })
	if m, _ := GroupMeshHopMTU(topo, "hk-hub", []string{"us", "us-2"}); m != 0 {
		t.Fatalf("a disabled Mesh edge still counts: %d", m)
	}
}

// A stored Mesh slot table that was edited by hand.
func TestMeshAllocationTableChecks(t *testing.T) {
	topo := defaults.Example()
	model.MigrateRegionGroups(&topo)
	model.ReconcileAllocations(nil, &topo)
	if errs := errorCodes(Run(topo)); len(errs) != 0 {
		t.Fatalf("stored example: %v", errs)
	}
	dup := topo
	dup.Allocations = topo.Allocations.Clone()
	dup.Allocations.Mesh["us"] = dup.Allocations.Mesh["hk-ix"]
	assertError(t, Run(dup), "mesh_alloc_invalid")
	out := topo
	out.Allocations = topo.Allocations.Clone()
	out.Allocations.Mesh["us"] = model.Slot{Slot: model.MaxMeshSlots}
	assertError(t, Run(out), "mesh_alloc_invalid")
	// A pool too small for the slot.
	small := topo
	small.Settings.MeshUnderlayPrefix = "10.68.0.0/30" // two hosts, four exits
	assertError(t, Run(small), "mesh_alloc_exhausted")
}

// privateLAN moves the example's gateway LAN (a documentation range) into
// a private range, for checks that only apply to private pools.
func privateLAN(t model.Topology) model.Topology {
	t.Nodes = append([]model.Node(nil), t.Nodes...)
	t.Settings.GatewayLANIP = "10.77.0.88/24"
	t.Settings.ROSIPv4 = "10.77.0.1"
	t.Settings.PanelBind = "10.77.0.88:8787"
	for i := range t.Nodes {
		if t.Nodes[i].Role == model.RoleGateway {
			t.Nodes[i].LANIPv4 = "10.77.0.88/24"
			t.Nodes[i].UnderlayNextHop = "10.77.0.1"
			if t.Nodes[i].SSHHost != "" {
				t.Nodes[i].SSHHost = "10.77.0.88"
			}
		}
	}
	return t
}
