package compile

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

func dualBundle(t *testing.T) *Bundle {
	t.Helper()
	topo := defaults.DualHubExample()
	model.MigrateRegionGroups(&topo)
	b, err := Compile(topo)
	if err != nil {
		if ve, ok := err.(*ValidationError); ok {
			for _, i := range ve.Result.Issues {
				t.Log(i.Severity, i.Code, i.Message)
			}
		}
		t.Fatal(err)
	}
	return b
}

// dualIface finds the interface on node that faces peer.
func dualIface(t *testing.T, b *Bundle, node, peer string) string {
	t.Helper()
	best := ""
	for p, body := range b.Files {
		if strings.HasPrefix(p, "nodes/"+node+"/etc/wireguard/") && strings.Contains(body, "# peer-node "+peer+"\n") {
			// The UDP leg (mNN) sorts before its WSS companion (mNNw).
			if name := strings.TrimSuffix(filepath.Base(p), ".conf"); best == "" || name < best {
				best = name
			}
		}
	}
	if best == "" {
		t.Fatalf("no interface on %s toward %s", node, peer)
	}
	return best
}

func TestDualHubExampleCompiles(t *testing.T) {
	b := dualBundle(t)
	for _, n := range []string{"gw", "ali", "ix", "hk5", "dc1", "dc2"} {
		if b.File("nodes/"+n+"/usr/local/sbin/meridian-up.sh") == "" {
			t.Errorf("no bundle for %s", n)
		}
	}
	// The IX hub is a managed node with a boot unit, fwcompat and failover.
	for _, f := range []string{"etc/systemd/system/" + NodeUnit, "usr/local/sbin/meridian-failover.sh", "etc/nftables.d/meridian.nft"} {
		if b.File("nodes/ix/"+f) == "" {
			t.Errorf("IX hub lacks %s", f)
		}
	}
	// Apply order: exits, both hubs, relay, gateway.
	want := []string{"dc1", "dc2", "hk5", "ix", "ali", "gw"}
	if strings.Join(b.Order, " ") != strings.Join(want, " ") {
		t.Errorf("order %v, want %v", b.Order, want)
	}
}

// The relay dials the IX hub at its domestic ingress, exits are reached
// from its Hong Kong egress (they dial nothing here: the hub dials them).
func TestDualHubIXIngressAndEgress(t *testing.T) {
	b := dualBundle(t)
	ifc := dualIface(t, b, "ali", "ix")
	conf := b.File("nodes/ali/etc/wireguard/" + ifc + ".conf")
	if !strings.Contains(conf, "Endpoint = 198.51.100.10:") {
		t.Errorf("relay must dial the IX ingress address:\n%s", conf)
	}
	if strings.Contains(conf, "203.0.113.20") {
		t.Errorf("relay must not dial the IX egress address:\n%s", conf)
	}
	up := b.File("nodes/ix/usr/local/sbin/meridian-up.sh")
	if !strings.Contains(up, "# meridian-ix-hub: ingress=198.51.100.10 iface=- egress=203.0.113.20\n") {
		t.Errorf("IX marker missing:\n%s", up)
	}
	// LAN clients may not talk to the ingress directly either.
	if !strings.Contains(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "198.51.100.10") {
		t.Error("IX ingress missing from the gateway's underlay4 set")
	}
	// The ingress interface, when named, is hardened like the WAN.
	topo := defaults.DualHubExample()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "ix" {
			topo.Nodes[i].IngressInterface = "ens5"
		}
	}
	b2, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^harden_sysctl .*\bens5\b`).MatchString(b2.File("nodes/ix/usr/local/sbin/meridian-routes.sh")) {
		t.Error("ingress interface not hardened")
	}
}

// Both hubs carry the same per-exit and per-group marks, tables and
// transit addresses, each through its own interface toward the exit.
func TestDualHubPerHubTables(t *testing.T) {
	b := dualBundle(t)
	topo := defaults.DualHubExample()
	for _, hub := range []string{"ix", "hk5"} {
		routes := b.File("nodes/" + hub + "/usr/local/sbin/meridian-routes.sh")
		for i, exit := range []string{"dc1", "dc2"} {
			ifc := dualIface(t, b, hub, exit)
			table := 201 + i
			if !strings.Contains(routes, "ip route replace default dev "+ifc+" table "+strconv.Itoa(table)+"\n") {
				t.Errorf("%s: table %d must default to its own tunnel %s", hub, table, ifc)
			}
			if !strings.Contains(routes, "ip rule add from 10.66.200."+strconv.Itoa(10+i)+"/32 lookup "+strconv.Itoa(table)) {
				t.Errorf("%s: transit rule for %s missing", hub, exit)
			}
			res := validate.ExitResolverAddr(i).String()
			if !strings.Contains(routes, "ip -6 route replace "+res+"/128 dev "+ifc+"\n") {
				t.Errorf("%s: exit resolver %s not routed to %s", hub, res, ifc)
			}
		}
		if !strings.Contains(routes, "group_hop 203 '"+dualIface(t, b, hub, "dc1")+"'") {
			t.Errorf("%s: group hk table 203 must start on its own tunnel to dc1", hub)
		}
		// Neither hub routes into the other hub's tunnels.
		other := map[string]string{"ix": "hk5", "hk5": "ix"}[hub]
		for _, exit := range []string{"dc1", "dc2"} {
			if strings.Contains(routes, " dev "+dualIface(t, b, other, exit)+" ") && dualIface(t, b, other, exit) != dualIface(t, b, hub, exit) {
				// interface names are global (m<index>); a hub's script may
				// only name its own
				t.Errorf("%s names %s's interface toward %s", hub, other, exit)
			}
		}
	}
	// Per-hub plans differ only in interfaces; each hub reports its own ID.
	pi, err := PlanGroupsForHub(topo, "ix")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := PlanGroupsForHub(topo, "hk5")
	if err != nil {
		t.Fatal(err)
	}
	if len(pi) != 1 || len(pb) != 1 || pi[0].Mark != pb[0].Mark || pi[0].Table != pb[0].Table || pi[0].Resolver != pb[0].Resolver || !pi[0].Dynamic || !pb[0].Dynamic {
		t.Fatalf("group plans differ between hubs: %+v / %+v", pi, pb)
	}
	if GroupPlanID(pi) == GroupPlanID(pb) {
		t.Error("the two hubs run different group plans (interfaces differ); their IDs must differ")
	}
	if !strings.Contains(b.File("nodes/hk5/usr/local/sbin/meridian-failover.sh"), "GROUP_PLAN="+GroupPlanID(pb)) {
		t.Error("backup hub failover does not carry its own plan ID")
	}
	if !strings.Contains(b.File("nodes/ix/usr/local/sbin/meridian-failover.sh"), "GROUP_PLAN="+GroupPlanID(pi)) {
		t.Error("primary hub failover does not carry its own plan ID")
	}
	// The backup hub's west is the gateway's WSS; the primary's the relay.
	if !strings.Contains(b.File("nodes/hk5/usr/local/sbin/meridian-failover.sh"), `HOME_WSS="`+dualIface(t, b, "hk5", "gw")+`"`) {
		t.Error("backup hub must return home through the gateway's WSS")
	}
	if !strings.Contains(b.File("nodes/ix/usr/local/sbin/meridian-failover.sh"), `IX="`+dualIface(t, b, "ix", "ali")+`"`) {
		t.Error("primary hub must return home through the relay")
	}
}

// Exits: replies leave through the hub the connection arrived from.
func TestDualHubExitReplySymmetry(t *testing.T) {
	b := dualBundle(t)
	for _, exit := range []string{"dc1", "dc2"} {
		pIf, bIf := dualIface(t, b, exit, "ix"), dualIface(t, b, exit, "hk5")
		nft := b.File("nodes/" + exit + "/etc/nftables.d/meridian.nft")
		for _, want := range []string{
			`iifname "` + pIf + `" ct direction original ct mark set 0x4d50`,
			`iifname "` + bIf + `" ct direction original ct mark set 0x4d51`,
			"ct direction reply ct mark 0x4d50 meta mark set 0x4d50",
			"ct direction reply ct mark 0x4d51 meta mark set 0x4d51",
			"type route hook output priority mangle",
		} {
			if !strings.Contains(nft, want) {
				t.Errorf("%s nft lacks %q", exit, want)
			}
		}
		// Group resolver and exit resolver answered on both hubs' tunnels.
		for _, chain := range []string{"group_dns", "exit_dns"} {
			blk := nftChain(t, nft, chain)
			if !strings.Contains(blk, `"`+pIf+`"`) || !strings.Contains(blk, `"`+bIf+`"`) {
				t.Errorf("%s %s must match both hub tunnels:\n%s", exit, chain, blk)
			}
		}
		routes := b.File("nodes/" + exit + "/usr/local/sbin/meridian-routes.sh")
		for table, ifc := range map[string]string{"172": pIf, "173": bIf} {
			other := map[string]string{"172": bIf, "173": pIf}[table]
			var lines []string
			for _, l := range strings.Split(routes, "\n") {
				if strings.HasSuffix(l, " table "+table) {
					lines = append(lines, l)
				}
			}
			if len(lines) == 0 {
				t.Fatalf("%s: no table %s", exit, table)
			}
			for _, l := range lines {
				if strings.Contains(l, " dev "+other+" ") || strings.Contains(l, " eth0") || strings.Contains(l, " via ") {
					t.Errorf("%s table %s leaks: %s", exit, table, l)
				}
				if !strings.Contains(l, " dev "+ifc+" ") && !strings.Contains(l, "blackhole default") {
					t.Errorf("%s table %s: unexpected %s", exit, table, l)
				}
			}
		}
		for _, want := range []string{"ip rule add fwmark 0x4d50 lookup 172 priority 17060", "ip rule add fwmark 0x4d51 lookup 173 priority 17061",
			"ip -6 rule add fwmark 0x4d50 lookup 172 priority 17060", "ip -6 rule add fwmark 0x4d51 lookup 173 priority 17061"} {
			if !strings.Contains(routes, want) {
				t.Errorf("%s routes lack %q", exit, want)
			}
		}
	}
}

// Gateway: one upstream prelude shared by routes and failover; the guard
// admits exit marks on every gateway tunnel, the backup's included, and
// still drops everything else; resolvers are hub-independent.
func TestDualHubGatewayUpstream(t *testing.T) {
	b := dualBundle(t)
	routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	fo := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	plan := planUpstream(defaults.DualHubExample(), mustTunnels(t, defaults.DualHubExample()))
	pre := upstreamPrelude(plan)
	if !strings.Contains(routes, pre) || !strings.Contains(fo, pre) {
		t.Fatal("the upstream prelude must be byte-identical in routes and failover")
	}
	udp, wss := dualIface(t, b, "gw", "ali"), dualIface(t, b, "gw", "ali")+"w"
	bk := dualIface(t, b, "gw", "hk5")
	if want := "UP_IFACE=('" + udp + "' '" + wss + "' '" + bk + "')"; !strings.Contains(pre, want) {
		t.Errorf("upstream order: want %s in\n%s", want, pre)
	}
	if !strings.Contains(pre, "UP_HUB=('ix' 'ix' 'hk5')") || !strings.Contains(pre, "UP_TIER=('primary' 'primary' 'backup')") {
		t.Errorf("upstream hubs wrong:\n%s", pre)
	}
	// Static install starts on the main path; table 102 is only changed by upstream_apply.
	if !strings.Contains(routes, "upstream_apply 'udp'\n") {
		t.Error("static install must apply the first path through upstream_apply")
	}
	for _, s := range []string{routes, fo} {
		body := strings.Replace(s, pre, "", 1)
		if regexp.MustCompile(`(?m)^\s*ip (-6 )?route replace default dev .* table 102`).MatchString(body) {
			t.Error("table 102 default changed outside upstream_apply")
		}
	}
	// End-to-end main-path probe: host routes on each leg from the probe source.
	for i, ifc := range []string{udp, wss} {
		want := "ip route replace " + plan.Paths[0].Probe + "/32 dev " + ifc + " src " + upstreamProbeSrc + " metric " + strconv.Itoa(10+i)
		if !strings.Contains(routes, want) {
			t.Errorf("missing probe route %q", want)
		}
	}
	if !strings.Contains(routes, "ip addr replace "+upstreamProbeSrc+"/32 dev lo") {
		t.Error("probe source not on lo")
	}
	guard := b.File("nodes/gw/etc/nftables.d/meridian-guard.nft")
	for _, ifc := range []string{udp, wss, bk} {
		if !strings.Contains(guard, `"`+ifc+`"`) {
			t.Errorf("guard tunnel set lacks %s:\n%s", ifc, guard)
		}
	}
	if !strings.Contains(guard, "counter drop comment \"fail closed") {
		t.Error("guard lost its fail-closed drop")
	}
	if !strings.Contains(b.File("nodes/gw/etc/nftables.d/meridian.nft"), guard[strings.Index(guard, "table inet meridian_guard {"):]) {
		t.Error("early-boot guard differs from the one in meridian.nft")
	}
	dns := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	for i, exit := range []string{"dc1", "dc2"} {
		if !strings.Contains(dns, "server "+validate.ExitResolverAddr(i).String()+" -group g_"+exit) {
			t.Errorf("exit %s must be resolved at its hub-independent address:\n%s", exit, dns)
		}
	}
	if strings.Contains(dns, "server fd66:0:0:") {
		t.Error("gateway still asks an exit's tunnel address (unreachable through the backup hub)")
	}
}

func TestDualHubScriptsSyntax(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	b := dualBundle(t)
	for p, body := range b.Files {
		if !strings.HasSuffix(p, ".sh") {
			continue
		}
		f := filepath.Join(t.TempDir(), "s.sh")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s: bash -n: %v %s", p, err, out)
		}
	}
}

// The gateway's dual-hub failover under bash with stub ping/ip/date: the
// main path is left only after FAILS_NEED passes with no main leg
// answering, the backup takes over, nothing answering keeps the current
// path, and the return to the main path waits for RECOVERS_NEED passes and
// the cooldown. Every switch goes through upstream_apply, and the record
// says which hub carries.
func TestDualHubGatewayFailoverTakeoverAndReturn(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	b := dualBundle(t)
	dir := t.TempDir()
	ctrl, bin, run := filepath.Join(dir, "ctrl"), filepath.Join(dir, "bin"), filepath.Join(dir, "run")
	for _, d := range []string{ctrl, bin, run} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("ip", "echo \"ip $*\" >> "+ctrl+"/ip.log\n")
	// ping -I <iface> ... <peer>: up when ctrl/up-<iface> exists.
	stub("ping", `[ -f `+ctrl+`/up-$2 ]`+"\n")
	stub("date", "cat "+ctrl+"/now\n")
	full := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(full, "# --- main loop ---")
	if cut < 0 {
		t.Fatal("no main-loop marker")
	}
	prog := "export PATH=" + bin + ":$PATH\n" + strings.ReplaceAll(full[:cut], "/run/meridian", run)
	udp, wss, bk := dualIface(t, b, "gw", "ali"), dualIface(t, b, "gw", "ali")+"w", dualIface(t, b, "gw", "hk5")
	// steps: for each pass, which interfaces answer; then check the path.
	type pass struct {
		up   []string
		want string
	}
	var passes []pass
	add := func(n int, up []string, want string) {
		for i := 0; i < n; i++ {
			passes = append(passes, pass{up, want})
		}
	}
	add(2, []string{udp, wss, bk}, "udp")
	add(2, []string{bk}, "udp")         // FAILS_NEED is 3: still udp
	add(1, []string{bk}, "backup")      // third pass: takeover
	add(3, nil, "backup")               // nothing answers: stay
	add(4, []string{udp, bk}, "backup") // main answers again: 4 < RECOVERS_NEED
	add(1, []string{udp, bk}, "udp")    // fifth pass, cooldown long over (passes are 60 s apart)
	var script strings.Builder
	script.WriteString(prog)
	script.WriteString("set -e\n")
	for i, p := range passes {
		script.WriteString("rm -f " + ctrl + "/up-*\n")
		for _, u := range p.up {
			script.WriteString("touch " + ctrl + "/up-" + u + "\n")
		}
		script.WriteString("echo " + strconv.Itoa(1700000000+60*i) + " > " + ctrl + "/now\n")
		script.WriteString("upstream_step\n")
		script.WriteString(`[ "$cur" = "` + p.want + `" ] || { echo "pass ` + strconv.Itoa(i) + `: cur=$cur want ` + p.want + `"; exit 1; }` + "\n")
		script.WriteString(`grep -qx "path ` + p.want + `" ` + run + `/upstream || { echo "pass ` + strconv.Itoa(i) + `: record"; cat ` + run + `/upstream; exit 1; }` + "\n")
	}
	f := filepath.Join(dir, "drive.sh")
	if err := os.WriteFile(f, []byte(script.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", f).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	log, _ := os.ReadFile(filepath.Join(ctrl, "ip.log"))
	if !strings.Contains(string(log), "ip route replace default dev "+bk+" table 102") || !strings.Contains(string(log), "ip route replace default dev "+udp+" table 102") {
		t.Errorf("switches not applied through table 102:\n%s", log)
	}
	if strings.Contains(string(log), "eth0") {
		t.Errorf("failover touched the LAN NIC:\n%s", log)
	}
	rec, _ := os.ReadFile(filepath.Join(run, "upstream"))
	if !strings.Contains(string(rec), "hub ix\ntier primary\n") || !strings.Contains(string(rec), "state switching") {
		t.Errorf("record after return:\n%s", rec)
	}
}

func dualValidate(t *testing.T, mut func(*model.Topology)) []validate.Issue {
	t.Helper()
	topo := defaults.DualHubExample()
	mut(&topo)
	return validate.Run(topo).Issues
}

func hasIssue(iss []validate.Issue, code string) bool {
	for _, i := range iss {
		if i.Code == code && i.Severity == validate.SeverityError {
			return true
		}
	}
	return false
}

func setNode(topo *model.Topology, id string, f func(*model.Node)) {
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == id {
			f(&topo.Nodes[i])
		}
	}
}

func TestDualHubValidation(t *testing.T) {
	if iss := dualValidate(t, func(*model.Topology) {}); (validate.Result{Issues: iss}).HasErrors() {
		t.Fatalf("example has errors: %+v", iss)
	}
	cases := []struct {
		code string
		mut  func(*model.Topology)
	}{
		{"exit_missing_hub_tunnel", func(tp *model.Topology) {
			var ls []model.Link
			for _, l := range tp.Links {
				if l.ID != "hk5-dc2" {
					ls = append(ls, l)
				}
			}
			tp.Links = ls
		}},
		{"mesh_backup_hub_unsupported", func(tp *model.Topology) {
			tp.Links = append(tp.Links, model.Link{ID: "hk5-dc1-mesh", From: "hk5", To: "dc1", Transport: model.TransportCFMesh, Enabled: true, Standby: true})
		}},
		{"backup_hub_not_wired", func(tp *model.Topology) {
			for i := range tp.Links {
				if tp.Links[i].ID == "gw-hk5" {
					tp.Links[i].Enabled = false
				}
			}
		}},
		{"replacement_to_primary", func(tp *model.Topology) {
			tp.Links = append(tp.Links, model.Link{ID: "gw-ix-wss", From: "gw", To: "ix", Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true})
		}},
		{"hub_tier_ambiguous", func(tp *model.Topology) { setNode(tp, "hk5", func(n *model.Node) { n.HubTier = model.HubPrimary }) }},
		{"ix_ingress_missing", func(tp *model.Topology) { setNode(tp, "ix", func(n *model.Node) { n.IngressV4 = "" }) }},
		{"ix_line_on_backup", func(tp *model.Topology) {
			setNode(tp, "hk5", func(n *model.Node) { n.IXLine, n.IngressV4 = true, "198.51.100.20" })
		}},
		{"ix_hub_unmanaged", func(tp *model.Topology) { setNode(tp, "ix", func(n *model.Node) { n.Managed = false }) }},
		{"ingress_without_ix_line", func(tp *model.Topology) { setNode(tp, "hk5", func(n *model.Node) { n.IngressV4 = "198.51.100.20" }) }},
		{"ix_role_with_ix_hub", func(tp *model.Topology) {
			tp.Nodes = append(tp.Nodes, model.Node{ID: "old-ix", Name: "old", Role: model.RoleIX})
		}},
		{"ix_replacement_mode_dual_hub", func(tp *model.Topology) { tp.Settings.IXReplacementMode = true }},
		{"dual_hub_multiple_relays", func(tp *model.Topology) {
			tp.Nodes = append(tp.Nodes, model.Node{ID: "ali2", Name: "ali2", Role: model.RoleRelay, Managed: true, PathV4: true, EndpointV4: "203.0.113.11"})
		}},
		{"backup_hub_relay_link_unsupported", func(tp *model.Topology) {
			tp.Links = append(tp.Links, model.Link{ID: "ali-hk5", From: "ali", To: "hk5", Transport: model.TransportDirectWG, Enabled: true})
		}},
		{"too_many_hubs", func(tp *model.Topology) {
			tp.Nodes = append(tp.Nodes, model.Node{ID: "hub3", Name: "hub3", Role: model.RoleHub, Managed: true, PathV4: true})
		}},
	}
	for _, c := range cases {
		if iss := dualValidate(t, c.mut); !hasIssue(iss, c.code) {
			t.Errorf("%s: not reported; got %+v", c.code, iss)
		}
	}
}

// The IX as a managed primary hub without a backup hub: the path
// gateway → relay → IX hub → exit is complete without an ix node.
func TestIXHubSingleHub(t *testing.T) {
	topo := defaults.DualHubExample()
	var nodes []model.Node
	for _, n := range topo.Nodes {
		if n.ID != "hk5" {
			nodes = append(nodes, n)
		}
	}
	topo.Nodes = nodes
	var links []model.Link
	for _, l := range topo.Links {
		if l.From != "hk5" && l.To != "hk5" {
			links = append(links, l)
		}
	}
	topo.Links = links
	b, err := Compile(topo)
	if err != nil {
		if ve, ok := err.(*ValidationError); ok {
			t.Fatalf("%+v", ve.Result.Issues)
		}
		t.Fatal(err)
	}
	if strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), "upstream_apply") {
		t.Error("single-hub topology must not use the dual-hub upstream")
	}
	if strings.Contains(b.File("nodes/dc1/etc/nftables.d/meridian.nft"), "hub_return") {
		t.Error("single-hub exit must not get per-hub return paths")
	}
	if !strings.Contains(b.File("nodes/ali/etc/wireguard/"+dualIface(t, b, "ali", "ix")+".conf"), "Endpoint = 198.51.100.10:") {
		t.Error("relay must dial the IX ingress")
	}
}

func TestHubMigrationIdempotent(t *testing.T) {
	topo := defaults.Example()
	setNode(&topo, "hk-hub", func(n *model.Node) { n.HubTier = "" })
	rep := model.MigrateRegionGroups(&topo)
	if !rep.Changed || len(rep.HubTiers) != 1 || rep.HubTiers[0] != "hk-hub" {
		t.Fatalf("first run: %+v", rep)
	}
	if rep2 := model.MigrateRegionGroups(&topo); rep2.Changed {
		t.Fatalf("second run changed: %+v", rep2)
	}
	if p, ok := topo.PrimaryHub(); !ok || p.ID != "hk-hub" || topo.DualHub() {
		t.Fatal("migrated hub is not the lone primary")
	}
	// A dual-hub document is left alone.
	d := defaults.DualHubExample()
	if rep := model.MigrateRegionGroups(&d); len(rep.HubTiers) != 0 {
		t.Fatalf("dual-hub topology migrated: %+v", rep)
	}
}

// nftChain returns the body of "chain <name> {" up to its closing brace.
func nftChain(t *testing.T, nft, name string) string {
	t.Helper()
	i := strings.Index(nft, "chain "+name+" {")
	if i < 0 {
		t.Fatalf("no chain %s", name)
	}
	j := strings.Index(nft[i:], "\n  }")
	return nft[i : i+j]
}
