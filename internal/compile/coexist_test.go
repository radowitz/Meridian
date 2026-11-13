package compile

import (
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// unitValues returns every value of key in a unit file, split on spaces.
func unitValues(unit, key string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^`+key+`=(.*)$`).FindAllStringSubmatch(unit, -1) {
		out = append(out, strings.Fields(m[1])...)
	}
	return out
}

func hasAll(have []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			found = found || h == w
		}
		if !found {
			return false
		}
	}
	return true
}

// Remote nodes get a boot unit that runs meridian-up.sh after the network,
// nftables.service (a boot-time flush happens before Meridian loads) and
// Docker (DOCKER-USER exists); a failure fails the unit. meridian-up.sh
// never starts it (that would wait for itself at boot).
func TestNodeBootUnit(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	tunnels, _ := buildTunnels(topo)
	for _, n := range managedNodes(topo) {
		prefix := "nodes/" + n.ID + "/"
		unit := b.File(prefix + "etc/systemd/system/" + NodeUnit)
		up := b.File(prefix + "usr/local/sbin/meridian-up.sh")
		if n.Role == model.RoleGateway {
			if unit != "" || b.File(prefix+strings.TrimPrefix(FWCompatPath, "/")) != "" {
				t.Fatal("the gateway uses deploy/debian/meridian.service and no DOCKER-USER rules")
			}
			continue
		}
		if !hasAll(unitValues(unit, "After"), "network-online.target", "nftables.service", "docker.service") ||
			!hasAll(unitValues(unit, "Wants"), "network-online.target") || !hasAll(unitValues(unit, "WantedBy"), "multi-user.target") ||
			!hasAll(unitValues(unit, "Type"), "oneshot") || !hasAll(unitValues(unit, "RemainAfterExit"), "yes") ||
			!hasAll(unitValues(unit, "ExecStart"), "/usr/local/sbin/meridian-up.sh") || len(unitValues(unit, "Before")) != 0 {
			t.Fatalf("%s boot unit:\n%s", n.ID, unit)
		}
		if strings.Contains(up, NodeUnit) {
			t.Fatalf("%s: meridian-up.sh must not start its own boot unit", n.ID)
		}
		// Order inside meridian-up.sh: firewall, sysctls, coexistence
		// rules, forwarding, then tunnels and routes.
		idx := func(s string) int {
			i := strings.Index(up, s)
			if i < 0 {
				t.Fatalf("%s: meridian-up.sh lacks %q", n.ID, s)
			}
			return i
		}
		steps := []int{idx("nft -f \"$MERIDIAN_NFT\""), idx("99-meridian.conf ]"), idx(FWCompatPath + " apply"), idx("MERIDIAN_FWD=/etc/meridian/forwarding.conf")}
		nt := tunnelsFor(tunnels, n.ID)
		if len(nt) > 0 {
			steps = append(steps, idx("wg-quick up"))
		}
		steps = append(steps, idx("/usr/local/sbin/meridian-routes.sh\n"))
		for i := 1; i < len(steps); i++ {
			if steps[i] <= steps[i-1] {
				t.Fatalf("%s: meridian-up.sh step %d out of order", n.ID, i)
			}
		}
		fw := b.File(prefix + "etc/systemd/system/" + FWCompatUnit)
		if len(fwRules(topo, n, nt)) == 0 {
			if fw != "" || b.File(prefix+strings.TrimPrefix(FWCompatPath, "/")) != "" {
				t.Fatalf("%s: coexistence files without rules", n.ID)
			}
			continue
		}
		if !hasAll(unitValues(fw, "BindsTo"), "docker.service") || !hasAll(unitValues(fw, "After"), "docker.service") ||
			!hasAll(unitValues(fw, "WantedBy"), "docker.service") || !hasAll(unitValues(fw, "ExecStart"), FWCompatPath, "apply") {
			t.Fatalf("%s re-assert unit:\n%s", n.ID, fw)
		}
	}
}

// The coexistence rules name only the node's managed interfaces: tunnel
// in → WAN out (and the established return) on an exit, upstream ↔
// downstream tunnels (and the Mesh veth) on a hub or relay. Nothing else.
func TestFWRulesOnlyManagedInterfaces(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	tunnels, _ := buildTunnels(topo)
	tags := map[string]string{}
	for _, n := range managedNodes(topo) {
		if n.Role == model.RoleGateway {
			continue
		}
		nt := tunnelsFor(tunnels, n.ID)
		rules := fwRules(topo, n, nt)
		script := b.File("nodes/" + n.ID + "/" + strings.TrimPrefix(FWCompatPath, "/"))
		if len(rules) == 0 {
			if script != "" {
				t.Fatalf("%s: script without rules", n.ID)
			}
			continue
		}
		managed := map[string]bool{}
		for _, i := range tunnelIfaces(nt) {
			managed[i] = true
		}
		if meshPeer(topo, n.ID) {
			managed["mmesh"] = true
		}
		wan := exitWAN(n)
		for _, r := range rules {
			f := strings.Fields(r)
			if len(f) < 4 || f[0] != "-i" || f[2] != "-o" {
				t.Fatalf("%s rule shape %q", n.ID, r)
			}
			for _, i := range []string{f[1], f[3]} {
				if !managed[i] && !(n.Role == model.RoleExit && i == wan) {
					t.Fatalf("%s rule names an interface Meridian does not manage: %q", n.ID, r)
				}
			}
			if n.Role == model.RoleExit && f[1] == wan && !strings.HasSuffix(r, "-m conntrack --ctstate RELATED,ESTABLISHED") {
				t.Fatalf("%s: WAN-in rule without the established match: %q", n.ID, r)
			}
			if n.Role != model.RoleExit && (f[1] == wan || f[3] == wan) {
				t.Fatalf("%s (%s) forwards to its WAN: %q", n.ID, n.Role, r)
			}
			if !strings.Contains(script, "  \""+r+"\"\n") {
				t.Fatalf("%s: rule %q not in the script", n.ID, r)
			}
		}
		tag := fwTag(rules)
		if !regexp.MustCompile(`^meridian-fw-[0-9a-f]{8}$`).MatchString(tag) || !strings.Contains(script, "FW_TAG="+tag+"\n") {
			t.Fatalf("%s tag %q", n.ID, tag)
		}
		tags[n.ID] = tag
		for _, bad := range []string{" -F", " -P ", " -X", " -N ", "-A FORWARD", "-I FORWARD", "-D FORWARD", "DOCKER-FORWARD", "nft flush", "flush ruleset"} {
			if strings.Contains(script, bad) {
				t.Fatalf("%s: meridian-fwcompat.sh contains %q", n.ID, bad)
			}
		}
	}
	if tags["tw"] == tags["hk-hub"] {
		t.Fatal("different rule sets share a tag")
	}
	tw, _ := topo.NodeByID("tw")
	want := []string{"-i m14 -o eth0", "-i eth0 -o m14 -m conntrack --ctstate RELATED,ESTABLISHED"}
	if got := fwRules(topo, tw, tunnelsFor(tunnels, "tw")); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tw rules %v", got)
	}
}

// sysctl scope: the routes script hardens a literal list of interfaces
// (never every interface under /proc/sys), and a remote node's sysctl file
// keeps away from all/default except all.send_redirects.
func TestSysctlScope(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	tunnels, _ := buildTunnels(topo)
	for _, n := range managedNodes(topo) {
		prefix := "nodes/" + n.ID + "/"
		routes := b.File(prefix + "usr/local/sbin/meridian-routes.sh")
		if strings.Contains(routes, "/proc/sys/net/ipv4/conf/*") || strings.Contains(routes, "/proc/sys/net/ipv6/conf/*") {
			t.Fatalf("%s hardens every interface", n.ID)
		}
		want := "harden_sysctl " + strings.Join(sysctlIfaces(topo, n, tunnelsFor(tunnels, n.ID)), " ") + "\n"
		if !strings.Contains(routes, "\n"+want) {
			t.Fatalf("%s: routes script lacks %q", n.ID, want)
		}
		sys := b.File(prefix + "etc/sysctl.d/99-meridian.conf")
		if n.Role == model.RoleGateway {
			for _, w := range []string{"net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2", "net.ipv4.ip_forward=0"} {
				if !strings.Contains(sys, w+"\n") {
					t.Fatalf("gateway sysctl lost %q", w)
				}
			}
			continue
		}
		for _, l := range strings.Split(sys, "\n") {
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if (strings.Contains(l, ".all.") || strings.Contains(l, ".default.")) && l != "net.ipv4.conf.all.send_redirects=0" {
				t.Fatalf("%s sets a global key: %s", n.ID, l)
			}
			if strings.Contains(l, "forwarding") || strings.Contains(l, "ip_forward") {
				t.Fatalf("%s: forwarding at boot: %s", n.ID, l)
			}
		}
		if !strings.Contains(sys, "net.ipv4.conf."+sysctlIface(topo, n)+".rp_filter=2\n") {
			t.Fatalf("%s sysctl misses its interface:\n%s", n.ID, sys)
		}
	}
}

// nft 0.9.3 (Ubuntu 20.04): no remote ruleset uses the transport-header
// expression; the gateway (Debian 12/13 only) may.
func TestRemoteRulesetsAvoidTransportHeader(t *testing.T) {
	b := mustCompile(t, defaults.Example())
	n := 0
	for p, body := range b.Files {
		if !strings.HasSuffix(p, ".nft") || strings.HasPrefix(p, "nodes/gw/") {
			continue
		}
		n++
		for _, bad := range []string{"th dport", "th sport", "meta l4proto {"} {
			if strings.Contains(body, bad) {
				t.Fatalf("%s uses %q", p, bad)
			}
		}
	}
	if n == 0 {
		t.Fatal("no remote rulesets")
	}
}

// IPv6 forwarding only where the role forwards IPv6; where it does, the
// router-advertisement keep runs after the coexistence rules and before the
// forwarding switch. Every remote meridian-up.sh names its WAN.
func TestIPv6ForwardingScopeAndRAOrder(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	for _, n := range managedNodes(topo) {
		prefix := "nodes/" + n.ID + "/"
		fwd := b.File(prefix + "etc/meridian/forwarding.conf")
		up := b.File(prefix + "usr/local/sbin/meridian-up.sh")
		want6 := n.Role != model.RoleExit || n.EgressV6 || n.DualstackRelay
		if got := strings.Contains(fwd, "\nnet.ipv6.conf.all.forwarding=1\n"); got != want6 {
			t.Fatalf("%s (%s, egress_v6 %v): IPv6 forwarding %v", n.ID, n.Role, n.EgressV6, got)
		}
		if n.Role == model.RoleGateway {
			if strings.Contains(up, "MERIDIAN_RA_STATE") || strings.Contains(up, "# meridian-wan:") {
				t.Fatal("gateway: RA keep / WAN marker (its LAN gets accept_ra=2 from 99-meridian.conf)")
			}
			if !strings.Contains(b.File(prefix+"etc/sysctl.d/99-meridian.conf"), "net.ipv6.conf.eth0.accept_ra=2\n") {
				t.Fatal("gateway lost accept_ra=2 on its LAN")
			}
			continue
		}
		marker := "# meridian-wan: " + nodeWAN(n) + " set need="
		if !strings.Contains(up, marker) || sysctlIface(topo, n) != nodeWAN(n) {
			t.Fatalf("%s: WAN marker / sysctl interface", n.ID)
		}
		ra := strings.Index(up, "MERIDIAN_RA_STATE=")
		if (ra >= 0) != want6 {
			t.Fatalf("%s: RA keep present %v, IPv6 forwarding %v", n.ID, ra >= 0, want6)
		}
		if want6 && !(strings.Index(up, FWCompatPath+" apply") < ra && ra < strings.Index(up, "MERIDIAN_FWD=/etc/meridian/forwarding.conf")) {
			t.Fatalf("%s: RA keep is not between the DOCKER-USER rules and forwarding", n.ID)
		}
	}
	tw, _ := topo.NodeByID("tw")
	if wanMarker(tw) != "# meridian-wan: eth0 set need=4\n" {
		t.Fatalf("tw marker %q", wanMarker(tw))
	}
	tw.WANInterface = ""
	if wanMarker(tw) != "# meridian-wan: eth0 default need=4\n" {
		t.Fatalf("unset marker %q", wanMarker(tw))
	}
}
