package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/validate"
)

// Structural checks of nested exits (behind a relay exit) and external
// SOCKS exits: what each node's bundle installs. The runtime behaviour is
// TestNetnsNestedExit / TestNetnsExternalExit (netns, opt-in) and
// TestExternalExitRealBinaries (pinned gost and SmartDNS, opt-in).

func nestedBundle(t *testing.T) (*Bundle, model.Topology) {
	t.Helper()
	topo := defaults.NestedExample()
	model.MigrateRegionGroups(&topo)
	return mustCompile(t, topo), topo
}

func externalBundle(t *testing.T) (*Bundle, model.Topology) {
	t.Helper()
	topo := defaults.ExternalExample()
	model.MigrateRegionGroups(&topo)
	return mustCompile(t, topo), topo
}

func tunnelOf(t *testing.T, topo model.Topology, link string) Tunnel {
	t.Helper()
	for _, tun := range mustTunnels(t, topo) {
		if tun.LinkID == link && tun.Mode == "udp" {
			return tun
		}
	}
	t.Fatalf("no tunnel for %s", link)
	return Tunnel{}
}

func TestNestedExitTunnelDirectionAndPorts(t *testing.T) {
	b, topo := nestedBundle(t)
	tun := tunnelOf(t, topo, "twnat-dc1")
	if tun.West.ID != "dc1" || tun.East.ID != "twnat" || !tun.DialOut || tun.Listener().ID != "dc1" || tun.Dialer().ID != "twnat" {
		t.Fatalf("tunnel ends: west %s east %s dialout %v", tun.West.ID, tun.East.ID, tun.DialOut)
	}
	var lp validate.LinkPorts
	for _, p := range validate.TunnelPorts(topo) {
		if p.LinkID == "twnat-dc1" {
			lp = p
		}
	}
	if lp.Listener != "dc1" || lp.Dialer != "twnat" || lp.WG != tun.WGPort {
		t.Fatalf("port plan %+v vs tunnel %d", lp, tun.WGPort)
	}
	ifc := tun.Iface()
	nested := b.File("nodes/twnat/etc/wireguard/" + ifc + ".conf")
	relay := b.File("nodes/dc1/etc/wireguard/" + ifc + ".conf")
	if !strings.Contains(nested, "Endpoint = 203.0.113.41:") || !strings.Contains(nested, "PersistentKeepalive = 25") || strings.Contains(nested, "ListenPort") {
		t.Errorf("nested exit must dial the relay exit's endpoint with keepalive:\n%s", nested)
	}
	// The nested exit answers the hubs' health probes (their tunnel
	// addresses are behind the relay exit).
	if !strings.Contains(nested, "AllowedIPs = 192.0.2.0/24, 10.66.200.0/24, 10.66.0.0/16, fd66::/48") {
		t.Errorf("nested exit AllowedIPs:\n%s", nested)
	}
	if !strings.Contains(relay, "ListenPort = ") || strings.Contains(relay, "Endpoint = ") {
		t.Errorf("relay exit must listen and not dial:\n%s", relay)
	}
	// Nothing on the hubs or the gateway gets the nested exit's tunnel.
	for _, n := range []string{"ix", "hkb", "gw", "access", "dc2"} {
		if b.File("nodes/"+n+"/etc/wireguard/"+ifc+".conf") != "" {
			t.Errorf("%s has the nested tunnel %s", n, ifc)
		}
	}
}

func TestNestedExitHubSide(t *testing.T) {
	b, topo := nestedBundle(t)
	exits, groups := plans(t, topo)
	twnat, _ := exitByID(exits, "twnat")
	tw := mustGroup(t, groups, "tw")
	if twnat.Nested != "dc1" || !switchable(twnat) || !tw.Dynamic || tw.Target.Node.ID != "twnat" {
		t.Fatalf("twnat plan %+v, group tw %+v", twnat, tw.Policy())
	}
	for _, hub := range []string{"ix", "hkb"} {
		up := tunnelOf(t, topo, map[string]string{"ix": "ix-dc1", "hkb": "hkb-dc1"}[hub]).Iface()
		routes := b.File("nodes/" + hub + "/usr/local/sbin/meridian-routes.sh")
		for _, want := range []string{
			"ip route replace " + twnat.PeerV4 + "/32 dev " + up + "\n",
			"ip route replace blackhole " + twnat.PeerV4 + "/32 metric 32767\n",
			"ip -6 route replace " + twnat.PeerULA + "/128 dev " + up + "\n",
			"ip route replace default dev " + up + " table " + itoa(twnat.Table) + "\n",
			"ip -6 route replace " + twnat.Resolver + "/128 dev " + up + "\n",
			"group_hop " + itoa(tw.Table) + " '" + up + "|" + twnat.PeerV4 + "|" + twnat.PeerULA + "'\n",
			`ip route replace default via "$nh4" dev "$dev" onlink table "$table"`,
		} {
			if !strings.Contains(routes, want) {
				t.Errorf("%s routes lack %q", hub, want)
			}
		}
		nft := b.File("nodes/" + hub + "/etc/nftables.d/meridian.nft")
		want := "oifname \"" + up + "\" ip saddr " + tw.TransitV4 + " rt ip nexthop " + twnat.PeerV4 + " snat ip to " + twnat.TransitV4
		if !strings.Contains(nft, want) || !strings.Contains(nft, "rt ip6 nexthop "+twnat.PeerULA+" snat ip6 to "+twnat.TransitV6) {
			t.Errorf("%s nested_snat missing (%s):\n%s", hub, want, nft)
		}
		fo := b.File("nodes/" + hub + "/usr/local/sbin/meridian-failover.sh")
		if !strings.Contains(fo, `if alive "${iface%%|*}" "$peer"; then`) || !strings.Contains(fo, `h="${p#*=}"`) {
			t.Errorf("%s failover lacks the shared-hop health probe or report", hub)
		}
		if !strings.Contains(fo, "group_step 'tw' "+itoa(tw.Table)+" 'twnat' ") || !strings.Contains(fo, "'twnat' '"+up+"|"+twnat.PeerV4+"|"+twnat.PeerULA+"' '"+twnat.PeerV4+"'") {
			t.Errorf("%s failover: group tw step lacks twnat's hop:\n%s", hub, fo)
		}
	}
}

func TestNestedExitRelaySide(t *testing.T) {
	b, topo := nestedBundle(t)
	exits, _ := plans(t, topo)
	twnat, _ := exitByID(exits, "twnat")
	down := tunnelOf(t, topo, "twnat-dc1").Iface()
	routes := b.File("nodes/dc1/usr/local/sbin/meridian-routes.sh")
	for _, want := range []string{
		"ip route replace blackhole default metric 32767 table " + itoa(twnat.Table) + "\n",
		"ip route replace default dev " + down + " table " + itoa(twnat.Table) + "\n",
		"ip -6 route replace default dev " + down + " table " + itoa(twnat.Table) + "\n",
		"ip rule add from " + twnat.TransitV4 + "/32 lookup " + itoa(twnat.Table) + " priority ",
		"ip -6 rule add from " + twnat.TransitV6 + "/128 lookup " + itoa(twnat.Table) + " priority ",
		"ip -6 route replace " + twnat.Resolver + "/128 dev " + down + "\n",
	} {
		if !strings.Contains(routes, want) {
			t.Errorf("relay exit routes lack %q", want)
		}
	}
	nft := b.File("nodes/dc1/etc/nftables.d/meridian.nft")
	for _, want := range []string{
		"ip saddr " + twnat.TransitV4 + " oifname != \"" + down + "\" counter drop",
		"ip6 saddr " + twnat.TransitV6 + " oifname != \"" + down + "\" counter drop",
		"ip6 saddr { " + twnat.TransitV6 + " } accept comment \"region-group queries of the exits behind this node",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("relay exit nft lacks %q:\n%s", want, nft)
		}
	}
	// The exclusion precedes the relay exit's own DNAT of group queries.
	if i, j := strings.Index(nft, "ip6 saddr { "+twnat.TransitV6+" } accept"), strings.Index(nft, "dport 53 dnat ip6 to"); i < 0 || j < 0 || i > j {
		t.Error("nested exits' group queries must be excluded before the relay exit answers group queries")
	}
	if !strings.Contains(b.File("nodes/dc1/etc/meridian/forwarding.conf"), "net.ipv6.conf.all.forwarding=1") {
		t.Error("relay exit must forward IPv6 (the nested exit's resolver queries)")
	}
	fw := b.File("nodes/dc1" + FWCompatPath)
	for _, hubIf := range []string{tunnelOf(t, topo, "ix-dc1").Iface(), tunnelOf(t, topo, "hkb-dc1").Iface()} {
		for _, r := range []string{"-i " + hubIf + " -o " + down, "-i " + down + " -o " + hubIf} {
			if !strings.Contains(fw, r) {
				t.Errorf("DOCKER-USER rules lack %q", r)
			}
		}
	}
	if !strings.Contains(b.File("nodes/dc1/etc/iproute2/rt_tables.d/meridian.conf"), itoa(twnat.Table)+"\tmeridian_twnat") {
		t.Error("relay exit rt_tables lacks the nested exit's table")
	}
}

func TestNestedExitOwnSide(t *testing.T) {
	b, topo := nestedBundle(t)
	exits, _ := plans(t, topo)
	twnat, _ := exitByID(exits, "twnat")
	tun := tunnelOf(t, topo, "twnat-dc1").Iface()
	routes := b.File("nodes/twnat/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(routes, "ip route replace 10.66.0.0/16 dev "+tun+"\n") || strings.Contains(routes, "fwmark 0x4d50") {
		t.Errorf("nested exit routes:\n%s", routes)
	}
	nft := b.File("nodes/twnat/etc/nftables.d/meridian.nft")
	for _, want := range []string{
		"iifname { \"" + tun + "\" } ip6 daddr " + validate.GroupResolverNet.String() + " udp dport 53 dnat ip6 to " + twnat.DNSULA,
		"iifname \"" + tun + "\" ip6 daddr " + twnat.Resolver + " udp dport 53 dnat ip6 to " + twnat.DNSULA,
		"oifname \"eth0\" ip saddr { 192.0.2.0/24, 10.66.200.0/24 } masquerade",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nested exit nft lacks %q:\n%s", want, nft)
		}
	}
	dns := b.File("nodes/twnat/etc/smartdns/smartdns.conf")
	if !strings.Contains(dns, "bind ["+twnat.DNSULA+"]:53") {
		t.Errorf("nested exit resolver must bind its own tunnel address:\n%s", dns)
	}
}

func TestNestedExitGatewayResolvesAtNestedExit(t *testing.T) {
	b, topo := nestedBundle(t)
	exits, groups := plans(t, topo)
	twnat, _ := exitByID(exits, "twnat")
	tw := mustGroup(t, groups, "tw")
	dns := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	if !strings.Contains(dns, "server "+twnat.Resolver+" -group "+twnat.Group) || !strings.Contains(dns, "server "+tw.Resolver+" -group "+tw.DNSGroup) {
		t.Errorf("gateway resolver lines:\n%s", dns)
	}
}

func TestExternalExitCarrierBundle(t *testing.T) {
	b, topo := externalBundle(t)
	exits, groups := plans(t, topo)
	myext, _ := exitByID(exits, "myext")
	my := mustGroup(t, groups, "my")
	if !myext.External || !switchable(myext) || !my.Dynamic || my.Target.Node.ID != "myext" {
		t.Fatalf("myext %+v group %+v", myext, my.Policy())
	}
	if b.File("nodes/myext/usr/local/sbin/meridian-up.sh") != "" {
		t.Fatal("an external exit must get no bundle")
	}
	for p := range b.Files {
		if strings.HasPrefix(p, "nodes/myext/") {
			t.Fatalf("bundle file for the external exit: %s", p)
		}
	}
	nft := b.File("nodes/dc2/etc/nftables.d/meridian.nft")
	for _, want := range []string{
		"type nat hook prerouting priority -101;",
		"ip saddr " + myext.TransitV4 + " meta l4proto tcp dnat ip to " + myext.ExtService + ":12301",
		"ip saddr " + myext.TransitV4 + " meta l4proto udp dnat ip to " + myext.ExtService + ":9",
		"ip6 saddr " + myext.TransitV6 + " meta l4proto { tcp, udp } dnat ip6 to [" + myext.PeerULA + "]:9",
		"ip6 saddr " + myext.TransitV6 + " ip6 daddr " + validate.GroupResolverNet.String() + " udp dport 53 dnat ip6 to [" + myext.PeerULA + "]:53",
		"ip6 daddr " + myext.Resolver + " udp dport 53 dnat ip6 to [" + myext.PeerULA + "]:53",
		"ip saddr " + myext.TransitV4 + " meta l4proto udp counter reject with icmp type port-unreachable",
		"ip daddr " + myext.ExtService + " ct status dnat accept",
		"ip daddr 198.51.100.66 tcp dport 1080 oifname != \"wg9\" counter reject with tcp reset",
		"ip6 saddr { " + myext.TransitV6 + " } accept comment \"region-group queries of the exits behind this node",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("carrier nft lacks %q", want)
		}
	}
	// DNS rules come before the catch-all refusal of the exit's IPv6.
	if i, j := strings.Index(nft, "dport 53 dnat ip6 to ["+myext.PeerULA+"]:53"), strings.Index(nft, "dnat ip6 to ["+myext.PeerULA+"]:9"); i < 0 || j < 0 || i > j {
		t.Error("the exit's resolver DNAT must precede the refusal of its IPv6")
	}
	routes := b.File("nodes/dc2/usr/local/sbin/meridian-routes.sh")
	for _, want := range []string{
		"ip addr replace " + myext.ExtService + "/32 dev lo\n",
		"ip -6 addr replace " + myext.PeerULA + "/128 dev lo\n",
		"ip route replace blackhole default table " + itoa(myext.Table) + "\n",
		"ip rule add from " + myext.TransitV4 + "/32 lookup " + itoa(myext.Table),
		"# meridian-transit: 10.66.201.0/24 10.66.202.0/24 fd66::55:0/112\n",
	} {
		if !strings.Contains(routes, want) {
			t.Errorf("carrier routes lack %q", want)
		}
	}
	if strings.Contains(routes, myext.PeerV4+"/32 dev lo") {
		t.Error("the health address is the health service's, never the routes script's")
	}
	up := b.File("nodes/dc2/usr/local/sbin/meridian-up.sh")
	for _, want := range []string{"# meridian-ext: myext socks=198.51.100.66:1080 iface=wg9\n", "enable_unit " + ExtProxyUnit, "enable_unit " + ExtHealthUnit} {
		if !strings.Contains(up, want) {
			t.Errorf("carrier up lacks %q", want)
		}
	}
	unit := b.File("nodes/dc2/etc/systemd/system/" + ExtProxyUnit)
	if !strings.Contains(unit, "ExecStart=/usr/local/sbin/meridian-gost -C "+ExtProxyConfig+"\n") {
		t.Errorf("redirector unit:\n%s", unit)
	}
	conf := b.File("nodes/dc2" + ExtProxyConfig)
	for _, want := range []string{
		"addr: \"" + myext.ExtService + ":12301\"", "type: red", "sniffing: false", "tproxy: false",
		"addr: \"198.51.100.66:1080\"", "type: socks5",
		"username: \"__MERIDIAN_SECRET_socks-example1-user__\"", "password: \"__MERIDIAN_SECRET_socks-example1-pass__\"",
		"addr: \"1.1.1.1:53\"", "addr: \"8.8.8.8:53\"",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("redirector config lacks %q:\n%s", want, conf)
		}
	}
	for _, bad := range []string{"udp", "api:", "metrics:"} {
		if strings.Contains(conf, bad) {
			t.Errorf("redirector config mentions %q", bad)
		}
	}
	dns := b.File("nodes/dc2/etc/smartdns/smartdns.conf")
	for _, want := range []string{
		"bind [" + myext.PeerULA + "]:53 -group ext_myext -no-speed-check -no-dualstack-selection -force-aaaa-soa",
		"server-tcp " + myext.ExtService + ":5301 -group ext_myext -exclude-default-group",
		"server-tcp " + myext.ExtService + ":5302 -group ext_myext -exclude-default-group",
	} {
		if !strings.Contains(dns, want) {
			t.Errorf("carrier resolver lacks %q", want)
		}
	}
	// The hubs: the next-hop form and the source rewrite for group my.
	for _, hub := range []string{"ix", "hkb"} {
		upIf := tunnelOf(t, topo, map[string]string{"ix": "ix-dc2", "hkb": "hkb-dc2"}[hub]).Iface()
		if r := b.File("nodes/" + hub + "/usr/local/sbin/meridian-routes.sh"); !strings.Contains(r, "group_hop "+itoa(my.Table)+" '"+upIf+"|"+myext.PeerV4+"|"+myext.PeerULA+"'") ||
			!strings.Contains(r, "ip route replace "+myext.PeerV4+"/32 dev "+upIf) {
			t.Errorf("%s routes for the external exit", hub)
		}
		if n := b.File("nodes/" + hub + "/etc/nftables.d/meridian.nft"); !strings.Contains(n, "rt ip nexthop "+myext.PeerV4+" snat ip to "+myext.TransitV4) {
			t.Errorf("%s nested_snat for the external exit:\n%s", hub, n)
		}
	}
	// The gateway asks the exit's resolver like any exit's.
	if dns := b.File("nodes/gw/etc/smartdns/smartdns.conf"); !strings.Contains(dns, "server "+myext.Resolver+" -group "+myext.Group) {
		t.Errorf("gateway resolver lacks the external exit")
	}
}

// The carrier's footprint names what the preflight and the provision need:
// the gost binary, its units, its listeners, the secret-bearing file and
// the proxy probe.
func TestExternalExitFootprint(t *testing.T) {
	b, _ := externalBundle(t)
	files := map[string]string{}
	for p, body := range b.Files {
		if rest, ok := strings.CutPrefix(p, "nodes/dc2/"); ok {
			files["/"+rest] = body
		}
	}
	fp := preflight.FootprintOf(files)
	has := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	if !has(fp.Binaries, "gost") || !has(fp.Binaries, "smartdns") || !has(fp.Units, ExtProxyUnit) || !has(fp.Units, ExtHealthUnit) || !has(fp.SecretFiles, ExtProxyConfig) {
		t.Fatalf("footprint: binaries %v units %v secret files %v", fp.Binaries, fp.Units, fp.SecretFiles)
	}
	listens := map[string]bool{}
	for _, l := range fp.Listens {
		listens[l.Proto+" "+l.Addr.String()+" "+itoa(l.Port)+" "+l.Owner] = true
	}
	for _, want := range []string{"tcp 10.66.201.12 12301 meridian-ext-proxy.service", "tcp 10.66.201.12 5301 meridian-ext-proxy.service", "udp fd66::55:3 53 smartdns"} {
		if !listens[want] {
			t.Errorf("footprint lacks listener %q (%v)", want, listens)
		}
	}
	if len(fp.External) != 1 || fp.External[0].Iface != "wg9" || fp.External[0].SOCKS.String() != "198.51.100.66" || fp.External[0].Port != 1080 {
		t.Fatalf("footprint external %+v", fp.External)
	}
	if p := fp.PreflightProbes(); len(p) != 1 || p[0] != "tcp4:198.51.100.66:1080" {
		t.Fatalf("probes %v", p)
	}
	nets := map[string]bool{}
	for _, n := range fp.LoNets {
		nets[n.String()] = true
	}
	for _, n := range []string{"10.66.201.0/24", "10.66.202.0/24", "fd66::55:0/112"} {
		if !nets[n] {
			t.Errorf("footprint lo nets lack %s (%v)", n, fp.LoNets)
		}
	}
}

// The proxy credential never appears in compiled output: only placeholders.
func TestExternalExitNoSecretInBundle(t *testing.T) {
	b, _ := externalBundle(t)
	canon := b.Canonical()
	if !strings.Contains(canon, "__MERIDIAN_SECRET_socks-example1-user__") {
		t.Fatal("placeholder missing")
	}
	for p, body := range b.Files {
		if strings.Contains(body, "__MERIDIAN_SECRET_socks-") && p != "nodes/dc2"+ExtProxyConfig {
			t.Errorf("SOCKS placeholder outside the redirector configuration: %s", p)
		}
	}
}

// preVersionCarrierFiles are the SHA-256 digests of what the external
// example's carrier (dc2) installs for its external exit, as the compiler
// produced them before SOCKS credential versions and the logs existed
// (commit 4824a78).
var preVersionCarrierFiles = map[string]string{
	"etc/meridian/ext/gost.yaml":                     "6f183458a98f7a13d408355f84b25698f863b42914a8a5b0ce74cdfb4c4929f0",
	"etc/systemd/system/meridian-ext-health.service": "639285d64360e749e7b275998bca9cc9306df14745a1582af9b92675162033bf",
	"etc/systemd/system/meridian-ext-proxy.service":  "da20b18486fdc717e6896e0b8d8f25f06b978178203bbae55bfd327c02a1b344",
	"usr/local/sbin/meridian-ext-health.sh":          "3e8cd87d3965769cf2399dc7d1bdd8dd70e0a3ec6884c0bce418fd280b61b075",
}

// An external exit whose credential was never rotated past the store's
// baseline compiles to the bytes it had before versions existed: the
// compiler names the credential by its two placeholders only and never
// writes the version line (the panel adds it, and only for a tracked
// credential: internal/api socks_version.go). Nothing else that came with
// the logs reaches the carrier's external-exit files either: not the query
// journal, not the forwarder, not an encrypted upstream of the exits.
func TestExternalCarrierUnchangedWithoutRotation(t *testing.T) {
	variants := map[string]func(*model.Topology){
		"as stored":        func(*model.Topology) {},
		"query journal on": func(topo *model.Topology) { topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: true} },
		"forwarder on": func(topo *model.Topology) {
			topo.Settings.Sniff = &model.SniffSettings{Enabled: true, RecordNames: true}
		},
		"exit upstream (DoT)": func(topo *model.Topology) { topo.Settings.ExitDNS = exitUpstreamDoT() },
		"all of them": func(topo *model.Topology) {
			topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
			topo.Settings.Sniff = &model.SniffSettings{Enabled: true, RecordNames: true}
			topo.Settings.ExitDNS = exitUpstreamDoT()
		},
	}
	for name, vary := range variants {
		topo := defaults.ExternalExample()
		vary(&topo)
		b := mustCompile(t, topo)
		for rel, want := range preVersionCarrierFiles {
			body, ok := b.Files["nodes/dc2/"+rel]
			sum := sha256.Sum256([]byte(body))
			if os.Getenv("MERIDIAN_UPDATE_GOLDEN") == "1" {
				// An intended change of the carrier's files: the new digests.
				t.Logf("%s: %s %s", name, rel, hex.EncodeToString(sum[:]))
			} else if !ok || hex.EncodeToString(sum[:]) != want {
				t.Errorf("%s: the carrier's %s is not what it was before credential versions (present %v)", name, rel, ok)
			}
		}
		conf := b.Files["nodes/dc2"+ExtProxyConfig]
		if strings.Contains(conf, "meridian-socks-version") || strings.Count(conf, "__MERIDIAN_SECRET_socks-example1-") != 2 {
			t.Errorf("%s: the compiled redirector config carries a version line or not exactly its two placeholders", name)
		}
		// No other file of any node names the credential, by placeholder or id.
		for p, body := range b.Files {
			if p != "nodes/dc2"+ExtProxyConfig && strings.Contains(body, "socks-example1") {
				t.Errorf("%s: %s names the SOCKS credential", name, p)
			}
		}
	}
}

func TestNestedAndExternalScriptsSyntax(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	for _, mk := range []func(*testing.T) (*Bundle, model.Topology){nestedBundle, externalBundle} {
		b, _ := mk(t)
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
}

// group_hop of the shared-hop variant installs the next-hop form for a
// nested member and the plain form for the relay exit itself (stub ip).
func TestSharedHopGroupHopShell(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	ip := filepath.Join(dir, "ip")
	if err := os.WriteFile(ip, []byte("#!/bin/bash\necho \"ip $*\" >> \""+filepath.Join(dir, "calls")+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "MESH_DEV=mmesh\nGROUP_TABLES='205'\n" + hopShell(true) + "\ngroup_hop 205 'm05|10.66.8.2|fd66:0:0:8::2'\ngroup_hop 205 'm05'\ngroup_hop 102 'm05|10.66.8.2|fd66:0:0:8::2' || echo refused\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	for _, want := range []string{
		"ip route replace default via 10.66.8.2 dev m05 onlink table 205",
		"ip -6 route replace default via fd66:0:0:8::2 dev m05 onlink table 205",
		"ip route replace default dev m05 table 205",
	} {
		if !strings.Contains(string(calls), want+"\n") {
			t.Errorf("group_hop calls lack %q:\n%s", want, calls)
		}
	}
	if !strings.Contains(string(out), "refused") || strings.Contains(string(calls), "table 102") {
		t.Errorf("group_hop must refuse table 102:\n%s\n%s", out, calls)
	}
	// Without shared hops the shell is byte for byte the original.
	if hopShell(false) != groupHopShell || stepShell(false) != groupStepShell || reportShell(false) != groupReportShell {
		t.Error("the plain variants must be the original shell")
	}
}

// Topologies without nested or external exits render none of it.
func TestNoNestedNoExternalArtifacts(t *testing.T) {
	for _, topo := range []model.Topology{defaults.Example(), defaults.DualHubExample(), defaults.SharedRelaysExample()} {
		model.MigrateRegionGroups(&topo)
		b := mustCompile(t, topo)
		for p, body := range b.Files {
			for _, bad := range []string{"nested_snat", "nested_guard", "ext_dnat", "meridian-gost", "meridian-ext-", "# meridian-ext:", `"${iface%%|*}"`, "meridian-endpoint-refresh"} {
				if strings.Contains(body, bad) || strings.Contains(p, bad) {
					t.Errorf("%s carries %q without nested or external exits", p, bad)
				}
			}
		}
	}
}

// A DNS-name endpoint: dialers use the name and re-apply it when the
// handshake goes stale; nothing else changes.
func TestEndpointHostRefresh(t *testing.T) {
	topo := defaults.NestedExample()
	model.MigrateRegionGroups(&topo)
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "dc1" {
			topo.Nodes[i].EndpointHost = "relay.example.net"
		}
	}
	b := mustCompile(t, topo)
	tun := tunnelOf(t, topo, "twnat-dc1")
	conf := b.File("nodes/twnat/etc/wireguard/" + tun.Iface() + ".conf")
	if !strings.Contains(conf, "Endpoint = relay.example.net:"+itoa(tun.WGPort)+"\n") {
		t.Fatalf("nested exit endpoint:\n%s", conf)
	}
	for _, hub := range []string{"ix", "hkb"} {
		// The hubs dial dc1 too (dc1 listens on its hub links).
		ifc := tunnelOf(t, topo, hub+"-dc1").Iface()
		if c := b.File("nodes/" + hub + "/etc/wireguard/" + ifc + ".conf"); !strings.Contains(c, "Endpoint = relay.example.net:") {
			t.Errorf("%s endpoint:\n%s", hub, c)
		}
		if b.File("nodes/"+hub+EndpointRefreshScript) == "" || b.File("nodes/"+hub+"/etc/systemd/system/"+EndpointRefreshTimer) == "" {
			t.Errorf("%s lacks the endpoint refresh", hub)
		}
	}
	script := b.File("nodes/twnat" + EndpointRefreshScript)
	if !regexp.MustCompile(`(?m)^refresh '` + tun.Iface() + `' '[^']+' 'relay\.example\.net:\d+'$`).MatchString(script) {
		t.Fatalf("refresh script:\n%s", script)
	}
	if !strings.Contains(b.File("nodes/twnat/usr/local/sbin/meridian-up.sh"), "enable_unit "+EndpointRefreshTimer) {
		t.Error("the refresh timer is not enabled")
	}
	// The gateway's underlay set and routes never see the name.
	if strings.Contains(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "relay.example.net") || strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), "relay.example.net") {
		t.Error("the gateway must not see the name")
	}
	if bashOK() {
		// Stale handshake: re-applied; fresh: left alone (stub wg/ip/date).
		dir := t.TempDir()
		for name, body := range map[string]string{
			"ip":   "exit 0",
			"wg":   `if [ "$2" = latest-handshakes ] || [ "$1" = show ]; then echo "PUB $HS"; exit 0; fi; echo "wg $*" >> "` + filepath.Join(dir, "calls") + `"`,
			"date": "echo 1000",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		s := regexp.MustCompile(`(?m)^refresh '([^']+)' '[^']+' '([^']+)'$`).ReplaceAllString(script, "refresh '$1' 'PUB' '$2'")
		for _, c := range []struct {
			hs   string
			want bool
		}{{"0", true}, {"700", true}, {"900", false}} {
			_ = os.Remove(filepath.Join(dir, "calls"))
			cmd := exec.Command("bash", "-c", s)
			cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "HS=" + c.hs}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("hs %s: %v %s", c.hs, err, out)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			got := strings.Contains(string(calls), "wg set "+tun.Iface()+" peer PUB endpoint relay.example.net:")
			if got != c.want {
				t.Errorf("latest handshake %s: re-applied %v, want %v (%s / %s)", c.hs, got, c.want, calls, out)
			}
		}
	}
}

// R4's intentional carrier-only delta is excluded from older byte-stability
// assertions, independently of Mesh. Exact lines are required before removal;
// no digest or unrelated golden file is regenerated.
func withoutProbeDNSException(t *testing.T, topo model.Topology, b *Bundle) *Bundle {
	t.Helper()
	copyBundle := *b
	copyBundle.Files = make(map[string]string, len(b.Files))
	for p, body := range b.Files {
		copyBundle.Files[p] = body
	}
	tunnels := mustTunnels(t, topo)
	for _, n := range topo.Nodes {
		for _, e := range externalPlans(planExits(topo, tunnels), n.ID) {
			p := "nodes/" + n.ID + "/etc/nftables.d/meridian.nft"
			for _, proto := range []string{"udp", "tcp"} {
				line := probeDNSRule(n, tunnels, e, proto)
				if strings.Count(copyBundle.Files[p], line) != 1 {
					t.Fatalf("R4 expected exactly one rule: %s", line)
				}
				copyBundle.Files[p] = strings.Replace(copyBundle.Files[p], line, "", 1)
			}
		}
	}
	return &copyBundle
}

func probeDNSRule(n model.Node, tunnels []Tunnel, e ExitPlan, proto string) string {
	return "    iifname { " + strings.Join(carrierHubIfaces(n, tunnels), ", ") + " } ip6 saddr " + e.TransitV6 + " ip6 daddr " + e.PeerULA + " " + proto + " dport 53 accept comment \"external exit " + verifyLabel(e.Node.ID) + ": pinned probe DNS only\"\n"
}

func TestExternalProbeDNSException(t *testing.T) {
	for _, single := range []bool{false, true} {
		topo := defaults.ExternalExample()
		if single {
			// Retain only the primary hub and its links.
			var nodes []model.Node
			for _, n := range topo.Nodes {
				if n.ID != "hkb" {
					nodes = append(nodes, n)
				}
			}
			topo.Nodes = nodes
			var links []model.Link
			for _, l := range topo.Links {
				if l.From != "hkb" && l.To != "hkb" {
					links = append(links, l)
				}
			}
			topo.Links = links
		}
		model.MigrateRegionGroups(&topo)
		b := mustCompile(t, topo)
		tunnels := mustTunnels(t, topo)
		targets, err := ProbeExits(topo)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range topo.Nodes {
			for _, e := range externalPlans(planExits(topo, tunnels), n.ID) {
				p := targets[e.Node.ID]
				if p.TransitV6 != e.TransitV6 || p.Resolver != e.PeerULA || e.DNSULA != e.PeerULA || !p.TCPOnly {
					t.Fatalf("probe and carrier disagree: %+v / %+v", p, e)
				}
				body := b.File("nodes/" + n.ID + "/etc/nftables.d/meridian.nft")
				refuse := strings.Index(body, "ip6 saddr "+p.TransitV6+" meta l4proto { tcp, udp } dnat")
				for _, proto := range []string{"udp", "tcp"} {
					line := probeDNSRule(n, tunnels, e, proto)
					at := strings.Index(body, line)
					if at < 0 || refuse < at {
						t.Fatalf("DNS exception absent or after refusal: %s", line)
					}
					// Evaluate its exact tuple predicate; a neighbouring exit,
					// resolver or port must never receive this exception.
					for _, c := range []struct {
						src, dst string
						port     int
						want     bool
					}{
						{p.TransitV6, p.Resolver, 53, true},
						{p.TransitV6, "fd66::55:ffff", 53, false},
						{"fd66:0:0:ff::ffff", p.Resolver, 53, false},
						{p.TransitV6, p.Resolver, 853, false},
						{p.TransitV6, p.Resolver, 443, false},
					} {
						fields := strings.Fields(line)
						source, dest, port := "", "", ""
						for i := 0; i+1 < len(fields); i++ {
							switch fields[i] {
							case "saddr":
								source = fields[i+1]
							case "daddr":
								dest = fields[i+1]
							case "dport":
								port = fields[i+1]
							}
						}
						got := c.src == source && c.dst == dest && itoa(c.port) == port
						if got != c.want {
							t.Fatalf("exception predicate: %+v", c)
						}
					}
				}
			}
		}
	}
}
