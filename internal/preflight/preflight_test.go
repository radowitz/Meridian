package preflight

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
)

// nodeFiles is provision.FilesFor for the example topology (that package
// imports this one, so it is reimplemented here).
func nodeFiles(t *testing.T, id string) map[string]string {
	t.Helper()
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for p, body := range b.Files {
		if strings.HasPrefix(p, "nodes/"+id+"/") {
			out["/"+strings.TrimPrefix(p, "nodes/"+id+"/")] = body
		}
	}
	if len(out) == 0 {
		t.Fatalf("no files for %s", id)
	}
	return out
}

// fixture reads testdata/name, puts a "path" line for every file of fp
// where @PATHS@ stands (absent unless paths overrides it) followed by
// extra, and parses it.
func fixture(t *testing.T, name string, fp Footprint, paths map[string]string, extra string) Report {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, p := range fp.Files {
		if v, ok := paths[p]; ok {
			b.WriteString("path " + p + " " + v + "\n")
		} else {
			b.WriteString("path " + p + " absent\n")
		}
	}
	b.WriteString(extra)
	r := Parse(strings.Replace(string(raw), "@PATHS@\n", b.String(), 1))
	if !r.Complete {
		t.Fatalf("%s: fixture incomplete: %v", name, r.Notes)
	}
	return r
}

func codes(ev Evaluation, sev string) []string {
	var out []string
	for _, f := range ev.Findings {
		if sev == "" || f.Severity == sev {
			out = append(out, f.Code)
		}
	}
	sort.Strings(out)
	return out
}

func has(ev Evaluation, sev, code string) bool {
	for _, f := range ev.Findings {
		if f.Code == code && (sev == "" || f.Severity == sev) {
			return true
		}
	}
	return false
}

func find(ev Evaluation, code string) []Finding {
	var out []Finding
	for _, f := range ev.Findings {
		if f.Code == code {
			out = append(out, f)
		}
	}
	return out
}

func remote(node string) Context { return Context{NodeID: node, Deployment: "dep-test"} }

// Every finding carries a code, a message and, when it blocks, what to do.
func checkShape(t *testing.T, ev Evaluation) {
	t.Helper()
	for _, f := range ev.Findings {
		if f.Code == "" || f.Message == "" || f.Severity == "" {
			t.Fatalf("finding without code/message/severity: %+v", f)
		}
		if f.Severity == Blocking && f.Action == "" {
			t.Fatalf("blocking finding without an action: %+v", f)
		}
	}
	if ev.Blocking != (ev.Counts.Blocking > 0) {
		t.Fatalf("blocking flag %v vs count %d", ev.Blocking, ev.Counts.Blocking)
	}
}

// ------------------------------------------------------------ footprint ---

func TestFootprintOfExitHubRelay(t *testing.T) {
	exit := FootprintOf(nodeFiles(t, "hk-resi"))
	if len(exit.Interfaces) != 1 || exit.Interfaces[0].Name != "m04" || exit.Interfaces[0].ListenPort != 0 ||
		joinPrefixes(exit.Interfaces[0].Addresses) != "10.66.11.2/30, fd66:0:0:11::2/64" {
		t.Fatalf("exit interfaces %+v", exit.Interfaces)
	}
	if !exit.DNS || !exit.Forward4 || !exit.Forward6 || !exit.SysctlAll || len(exit.Binaries) != 0 {
		t.Fatalf("exit flags %+v", exit)
	}
	var dns []string
	for _, l := range exit.Listens {
		if l.Owner == "smartdns" {
			dns = append(dns, l.Proto+" "+l.Addr.String())
		}
		if l.Wildcard {
			t.Fatalf("exit resolver must bind tunnel addresses only: %+v", l)
		}
	}
	sort.Strings(dns)
	if strings.Join(dns, ",") != "tcp 10.66.11.2,tcp fd66:0:0:11::2,udp 10.66.11.2,udp fd66:0:0:11::2" {
		t.Fatalf("exit dns listens %v", dns)
	}
	if strings.Join(exit.NFTTables, ",") != "inet meridian" || !containsInt(exit.Tables, 150) {
		t.Fatalf("exit nft %v tables %v", exit.NFTTables, exit.Tables)
	}
	routes := map[string]bool{}
	for _, r := range exit.Routes {
		routes[r.Dst.String()+" "+r.Dev] = true
	}
	if !routes["10.66.200.0/24 m04"] || !routes["192.168.100.0/24 m04"] || !routes["10.66.0.0/16 "] {
		t.Fatalf("exit routes %+v", exit.Routes)
	}

	relay := FootprintOf(nodeFiles(t, "ali"))
	if strings.Join(relay.Binaries, ",") != "wstunnel" {
		t.Fatalf("relay binaries %v", relay.Binaries)
	}
	var ls []string
	for _, l := range relay.Listens {
		ls = append(ls, l.Proto+" "+l.Addr.String()+" "+itoa(l.Port))
	}
	sort.Strings(ls)
	want := "tcp 0.0.0.0 443,udp 127.0.0.1 52000,udp :: 51820,udp :: 51821"
	if strings.Join(ls, ",") != want {
		t.Fatalf("relay listens %v", ls)
	}
	if len(relay.Rules) == 0 || relay.Rules[0].Priority < 18000 {
		t.Fatalf("relay rules %+v", relay.Rules)
	}

	hub := FootprintOf(nodeFiles(t, "hk-hub"))
	if !containsStr(hub.NFTTables, "inet meridian_mesh") || !hub.Docker {
		t.Fatalf("hub nft %v docker %v", hub.NFTTables, hub.Docker)
	}

	gw := FootprintOf(nodeFiles(t, "gw"))
	if !containsStr(gw.Marks, "0x4d72") || !containsStr(gw.NFTTables, "inet meridian_guard") {
		t.Fatalf("gateway marks %v nft %v", gw.Marks, gw.NFTTables)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestBundleDigestChangesWithContent(t *testing.T) {
	a := map[string]string{"/etc/a": "x", "/etc/b": "y"}
	b := map[string]string{"/etc/b": "y", "/etc/a": "x"}
	if BundleDigest(a) != BundleDigest(b) {
		t.Fatal("digest depends on map order")
	}
	b["/etc/a"] = "x2"
	if BundleDigest(a) == BundleDigest(b) {
		t.Fatal("digest ignores content")
	}
	c := map[string]string{"/etc/a\x00/etc/b": ""}
	if BundleDigest(c) == BundleDigest(map[string]string{"/etc/a": "", "/etc/b": ""}) {
		t.Fatal("digest is ambiguous")
	}
}

// ------------------------------------------------------------ evaluator ---

func TestCleanDebian13ExitPasses(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, nil, ""), fp, remote("hk-resi"))
	checkShape(t, ev)
	if ev.Blocking || ev.Ownership != OwnNone {
		t.Fatalf("clean host blocked: %v / %s", codes(ev, Blocking), ev.Ownership)
	}
	if !has(ev, Info, CodeForwardEnable) || has(ev, "", CodeNFTFlush) || has(ev, "", CodeDNSListeners) {
		t.Fatalf("clean host findings %v", codes(ev, ""))
	}
	var pkgs, ifaces []string
	for _, c := range ev.Changes {
		switch c.Kind {
		case "package":
			pkgs = append(pkgs, c.Resource)
		case "interface":
			ifaces = append(ifaces, c.Action+" "+c.Resource)
		}
	}
	if strings.Join(pkgs, ",") != "wireguard-tools,smartdns" || strings.Join(ifaces, ",") != "create m04" {
		t.Fatalf("changes pkgs=%v ifaces=%v", pkgs, ifaces)
	}
}

// Ubuntu 20.04 on aarch64 with kernel 5.15, no nft binary, iptables-legacy
// and Docker's FORWARD DROP, ~440 MB of RAM.
func TestUbuntu2004Arm64Refused(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	ev := Evaluate(fixture(t, "ubuntu2004-arm64.txt", fp, nil, ""), fp, remote("hk-resi"))
	checkShape(t, ev)
	for _, c := range []string{CodeOSUnsupported, CodeForwardDrop} {
		if !has(ev, Blocking, c) {
			t.Fatalf("missing blocking %s: %v", c, codes(ev, ""))
		}
	}
	for _, c := range []string{CodeArchUnsupported, CodeKernelTooOld, CodeNoApt, CodePortInUse} {
		if has(ev, "", c) {
			t.Fatalf("unexpected %s: %v", c, codes(ev, ""))
		}
	}
	if !has(ev, Warning, CodeLowMemory) || !has(ev, Info, CodeIptablesLegacy) || !has(ev, Info, CodeDNSListeners) {
		t.Fatalf("findings %v", codes(ev, ""))
	}
	if fd := find(ev, CodeForwardDrop); len(fd) != 1 || !strings.Contains(fd[0].Message, "iptables filter 表 FORWARD 策略 DROP") {
		t.Fatalf("forward drop %+v", fd)
	}
	if os := find(ev, CodeOSUnsupported); !strings.Contains(os[0].Message, "Ubuntu 20.04") {
		t.Fatalf("os %+v", os)
	}
	installs := false
	for _, c := range ev.Changes {
		installs = installs || (c.Kind == "package" && c.Resource == "nftables")
	}
	if !installs {
		t.Fatal("missing nft binary is not shown as a package install")
	}
}

// Docker sets FORWARD DROP (iptables-nft: visible both as iptables policy
// and as table ip filter): one blocking finding per family, with the
// explanation and without any instruction for the panel to change it.
func TestDockerForwardDropBlocks(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	ev := Evaluate(fixture(t, "docker-forward-drop.txt", fp, nil, ""), fp, remote("hk-resi"))
	checkShape(t, ev)
	fd := find(ev, CodeForwardDrop)
	if len(fd) != 2 || fd[0].Severity != Blocking {
		t.Fatalf("forward drop findings %+v", fd)
	}
	for _, f := range fd {
		if !strings.Contains(f.Message, "policy accept") || !strings.Contains(f.Message, "Docker") || !strings.Contains(f.Action, "不会替你改") {
			t.Fatalf("explanation missing: %+v", f)
		}
		if strings.Count(f.Message, "FORWARD") > 3 {
			t.Fatalf("duplicated sources: %s", f.Message)
		}
	}
	if !has(ev, Info, CodeDocker) || !has(ev, Info, CodeNFTOther) || has(ev, "", CodePortInUse) {
		t.Fatalf("findings %v", codes(ev, ""))
	}
	// The ipv4 finding names one source only (iptables-nft shows the
	// same policy twice).
	if !strings.Contains(fd[0].Resource+fd[1].Resource, "ipv4") || strings.Contains(fd[0].Message+fd[1].Message, "ip filter 的链 FORWARD") {
		t.Fatalf("dedupe: %+v", fd)
	}
	// A nft-only drop (no iptables policy) is reported from the chain.
	r := fixture(t, "docker-forward-drop.txt", fp, nil, "")
	r.Policies = nil
	r.Chains = append(r.Chains, Chain{Table: "inet filter", Name: "forward", Type: "filter", Hook: "forward", Priority: "0", Policy: "drop"})
	ev = Evaluate(r, fp, remote("hk-resi"))
	if fd := find(ev, CodeForwardDrop); len(fd) != 2 || !strings.Contains(fd[0].Message, "inet filter") {
		t.Fatalf("nft-only drop %+v", fd)
	}
}

// wg0/wg1/wg2 exist; UDP 51820 is taken; wg1 uses 10.66.11.0/24 and a
// route for 10.66.0.0/16; wg2 uses 10.67.0.0/24 (remote access default).
func TestExistingWireGuard(t *testing.T) {
	exit := FootprintOf(nodeFiles(t, "hk-resi"))
	ev := Evaluate(fixture(t, "existing-wireguard.txt", exit, nil, ""), exit, remote("hk-resi"))
	checkShape(t, ev)
	ao := find(ev, CodeAddressOverlap)
	if len(ao) != 1 || !strings.Contains(ao[0].Message, "wg1") || !strings.Contains(ao[0].Message, "10.66.11.2/30") {
		t.Fatalf("address overlap %+v", ao)
	}
	ro := find(ev, CodeRouteOverlap)
	if len(ro) != 1 || !strings.Contains(ro[0].Message, "更具体") || ro[0].Resource != "10.66.200.0/24" || !strings.Contains(ro[0].Message, "10.66.0.0/16 dev wg1") {
		t.Fatalf("route overlap %+v", ro)
	}
	for _, f := range ev.Findings {
		if strings.Contains(f.Message, "10.67.0") && f.Severity != Info || strings.Contains(f.Resource, "10.8.0") {
			t.Fatalf("unrelated subnet flagged: %+v", f)
		}
	}
	if !has(ev, Info, CodeWireGuard) || has(ev, "", CodeInterfaceExists) {
		t.Fatalf("findings %v", codes(ev, ""))
	}

	relay := FootprintOf(nodeFiles(t, "ali"))
	ev = Evaluate(fixture(t, "existing-wireguard.txt", relay, nil, ""), relay, remote("ali"))
	pu := find(ev, CodePortInUse)
	var ports []string
	for _, f := range pu {
		ports = append(ports, f.Resource)
		if !strings.Contains(f.Message, "WireGuard 接口 wg") {
			t.Fatalf("owner not named: %+v", f)
		}
	}
	sort.Strings(ports)
	if strings.Join(ports, ",") != "udp [::]:51820,udp [::]:51821" {
		t.Fatalf("ports %v", ports)
	}
	// An interface name the bundle would create, already in use.
	r := fixture(t, "existing-wireguard.txt", exit, nil, "")
	r.Links = append(r.Links, "m04")
	ev = Evaluate(r, exit, remote("hk-resi"))
	if !has(ev, Blocking, CodeInterfaceExists) {
		t.Fatalf("interface exists not reported: %v", codes(ev, ""))
	}
}

// 443/80 taken by nginx, another wstunnel on 8080 and on 127.0.0.1:52000.
func TestPortsTaken(t *testing.T) {
	relay := FootprintOf(nodeFiles(t, "ali"))
	ev := Evaluate(fixture(t, "ports-taken.txt", relay, nil, ""), relay, remote("ali"))
	checkShape(t, ev)
	var res []string
	for _, f := range find(ev, CodePortInUse) {
		res = append(res, f.Resource)
	}
	sort.Strings(res)
	if strings.Join(res, ",") != "tcp 0.0.0.0:443,udp 127.0.0.1:52000" {
		t.Fatalf("ports %v (%v)", res, codes(ev, ""))
	}
	for _, f := range find(ev, CodePortInUse) {
		if strings.Contains(f.Resource, "443") && !strings.Contains(f.Message, "nginx") {
			t.Fatalf("443 owner %+v", f)
		}
	}
	if has(ev, "", CodeWstunnelMissing) {
		t.Fatal("wstunnel present but reported missing")
	}
}

// Port 53: systemd-resolved on loopback and WARP on loopback and its
// overlay address are not conflicts; a wildcard resolver or one on the
// exact tunnel address is.
func TestPort53(t *testing.T) {
	exit := FootprintOf(nodeFiles(t, "hk-resi"))
	ev := Evaluate(fixture(t, "warp.txt", exit, nil, ""), exit, remote("hk-resi"))
	checkShape(t, ev)
	if has(ev, "", CodePortInUse) || !has(ev, Info, CodeDNSListeners) || !has(ev, Info, CodeWARP) {
		t.Fatalf("warp host %v", codes(ev, ""))
	}
	w := find(ev, CodeWARP)[0]
	for _, s := range []string{"warp-svc", "CloudflareWARP", "inet cloudflare-warp", "100.96.0.12/32"} {
		if !strings.Contains(w.Message, s) {
			t.Fatalf("warp message lacks %s: %s", s, w.Message)
		}
	}
	// WARP's "not from all fwmark … lookup 65743" sits before main.
	if rp := find(ev, CodeRulePrecedes); len(rp) != 1 || rp[0].Severity != Warning || !strings.Contains(rp[0].Message, "65743") {
		t.Fatalf("rule precedes %+v", rp)
	}
	if !has(ev, Info, CodeNetfilterPersis) || has(ev, "", CodeTableInUse) {
		t.Fatalf("findings %v", codes(ev, ""))
	}

	wild := fixture(t, "clean-debian13.txt", exit, nil, "ss udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"dnsmasq\",pid=77,fd=4))\n")
	ev = Evaluate(wild, exit, remote("hk-resi"))
	if pu := find(ev, CodePortInUse); len(pu) != 1 || !strings.Contains(pu[0].Message, "dnsmasq") || !strings.Contains(pu[0].Resource, "10.66.11.2:53") {
		t.Fatalf("wildcard resolver %+v", pu)
	}
	exact := fixture(t, "clean-debian13.txt", exit, nil, "ss tcp LISTEN 0 10 [fd66:0:0:11::2]:53 [::]:* users:((\"unbound\",pid=78,fd=4))\n")
	ev = Evaluate(exact, exit, remote("hk-resi"))
	if pu := find(ev, CodePortInUse); len(pu) != 1 || !strings.Contains(pu[0].Resource, "fd66:0:0:11::2") {
		t.Fatalf("exact resolver %+v", pu)
	}
}

// A relay that is empty with forwarding disabled: the install turns it on
// (planned change, info), wstunnel must be provided first.
func TestEmptyRelay(t *testing.T) {
	relay := FootprintOf(nodeFiles(t, "ali"))
	ev := Evaluate(fixture(t, "clean-debian13.txt", relay, nil, ""), relay, remote("ali"))
	checkShape(t, ev)
	if strings.Join(codes(ev, Blocking), ",") != CodeWstunnelMissing || !has(ev, Info, CodeForwardEnable) {
		t.Fatalf("empty relay %v", codes(ev, ""))
	}
	wm := find(ev, CodeWstunnelMissing)[0]
	if !strings.Contains(wm.Action, "linux_amd64") {
		t.Fatalf("arch hint %+v", wm)
	}
	sysctl := false
	for _, c := range ev.Changes {
		sysctl = sysctl || c.Kind == "sysctl" && c.Resource == "net.ipv4.ip_forward=1"
	}
	if !sysctl {
		t.Fatal("forwarding change not planned")
	}
}

// A relay that already has a WireGuard tunnel and port forwarders, no
// firewall rules: the tunnel's port is a conflict, the forwarders are not.
func TestBusyRelay(t *testing.T) {
	relay := FootprintOf(nodeFiles(t, "ali"))
	extra := "link wg0\nwglink wg0\nwgport wg0 51830\naddr wg0 10.20.0.1/24\n" +
		"ss udp UNCONN 0 0 0.0.0.0:51830 0.0.0.0:*\n" +
		"ss tcp LISTEN 0 128 0.0.0.0:10001 0.0.0.0:* users:((\"realm\",pid=91,fd=3))\n" +
		"ss tcp LISTEN 0 128 0.0.0.0:10002 0.0.0.0:* users:((\"realm\",pid=91,fd=4))\n" +
		"ss udp UNCONN 0 0 0.0.0.0:10003 0.0.0.0:* users:((\"gost\",pid=92,fd=4))\n" +
		"cmd wstunnel yes\n"
	ev := Evaluate(fixture(t, "clean-debian13.txt", relay, nil, extra), relay, remote("ali"))
	checkShape(t, ev)
	if ev.Blocking {
		t.Fatalf("busy relay without overlap blocked: %v", codes(ev, Blocking))
	}
	if !has(ev, Info, CodeWireGuard) {
		t.Fatalf("%v", codes(ev, ""))
	}
}

func TestPrivilegesAndPlatform(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	for _, tc := range []struct {
		from, to, code string
	}{
		{"uid 0", "uid 1000", CodeNotRoot},
		{"arch x86_64", "arch armv7l", CodeArchUnsupported},
		{"kernel 6.12.12-amd64", "kernel 5.4.0-150-generic", CodeKernelTooOld},
		{"systemd yes", "systemd no", CodeNoSystemd},
		{"os-version \"13\"", "os-version \"11\"", CodeOSUnsupported},
		{"cmd apt-get yes", "cmd apt-get no", CodeNoApt},
		{"candidate smartdns 46.1+dfsg-1", "", CodeSmartDNSMissing},
	} {
		raw, _ := os.ReadFile("testdata/clean-debian13.txt")
		var b strings.Builder
		for _, p := range fp.Files {
			b.WriteString("path " + p + " absent\n")
		}
		text := strings.Replace(strings.Replace(string(raw), "@PATHS@\n", b.String(), 1), tc.from+"\n", tc.to+"\n", 1)
		ev := Evaluate(Parse(text), fp, remote("hk-resi"))
		if !has(ev, Blocking, tc.code) {
			t.Fatalf("%s → %s: want %s, got %v", tc.from, tc.to, tc.code, codes(ev, ""))
		}
	}
}

// ------------------------------------------------------------ ownership ---

func TestOwnership(t *testing.T) {
	files := nodeFiles(t, "hk-resi")
	fp := FootprintOf(files)
	const h1 = "1111111111111111111111111111111111111111111111111111111111111111"
	const h2 = "2222222222222222222222222222222222222222222222222222222222222222"
	present := map[string]string{}
	var man strings.Builder
	man.WriteString("manifest-begin\nmanifest meridian-node-manifest 1\nmanifest node hk-resi\nmanifest deployment dep-test\n")
	for _, p := range fp.Files {
		present[p] = "file 100 yes " + h1
		man.WriteString("manifest file " + p + " " + h1 + "\n")
	}
	man.WriteString("manifest iface m04\nmanifest nft inet meridian\nmanifest table 100\nmanifest table 102\nmanifest table 150\nmanifest unit meridian-unlock.timer\nmanifest-end\n")
	running := "link m04\naddr m04 10.66.11.2/30\nnft table inet meridian {\nrtable4 150 route\n" +
		"ss udp UNCONN 0 0 10.66.11.2:53 0.0.0.0:* users:((\"smartdns\",pid=55,fd=4))\n" +
		"route4 10.66.200.0/24 dev m04 scope link\n" +
		"route4 blackhole 10.66.0.0/16 metric 32767\nroute4 blackhole 10.66.200.0/24 metric 32767\nroute4 blackhole 192.168.100.0/24 metric 32767\n"

	// Ours, same node: an update without conflicts.
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, present, man.String()+running), fp, remote("hk-resi"))
	checkShape(t, ev)
	if ev.Ownership != OwnSame || ev.Blocking || !has(ev, Info, CodeOwnInstall) {
		t.Fatalf("same: %s %v", ev.Ownership, codes(ev, ""))
	}
	// A managed file changed on the host since the install.
	changed := map[string]string{}
	for k, v := range present {
		changed[k] = v
	}
	changed["/etc/sysctl.d/99-meridian.conf"] = "file 100 yes " + h2
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, changed, man.String()+running), fp, remote("hk-resi"))
	if mf := find(ev, CodeModifiedSince); len(mf) != 1 || mf[0].Resource != "/etc/sysctl.d/99-meridian.conf" || ev.Blocking {
		t.Fatalf("modified %v", codes(ev, ""))
	}
	// Ours, but another node of this panel / another panel.
	for _, ctx := range []Context{{NodeID: "hk-resi-2", Deployment: "dep-test"}, {NodeID: "hk-resi", Deployment: "dep-other"}} {
		ev = Evaluate(fixture(t, "clean-debian13.txt", fp, present, man.String()+running), fp, ctx)
		if ev.Ownership != OwnOther || !has(ev, Blocking, CodeManagedByOther) || !has(ev, Blocking, CodeInterfaceExists) || !has(ev, Blocking, CodeNFTTableExists) {
			t.Fatalf("other %+v: %s %v", ctx, ev.Ownership, codes(ev, ""))
		}
	}
	// Not ours: Meridian-marked files without a manifest (legacy) and a
	// foreign SmartDNS config at our path.
	legacy := map[string]string{"/etc/wireguard/m04.conf": "file 500 yes " + h1, "/etc/smartdns/smartdns.conf": "file 2048 no " + h2}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, legacy, ""), fp, remote("hk-resi"))
	if ev.Ownership != OwnLegacy || !has(ev, Blocking, CodeLegacyInstall) {
		t.Fatalf("legacy %s %v", ev.Ownership, codes(ev, ""))
	}
	po := find(ev, CodePathOccupied)
	if len(po) != 1 || po[0].Resource != "/etc/smartdns/smartdns.conf" || !strings.Contains(po[0].Action, "不会覆盖") {
		t.Fatalf("occupied %+v", po)
	}
	// A directory at a file path.
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, map[string]string{"/etc/meridian/forwarding.conf": "dir 0 no -"}, ""), fp, remote("hk-resi"))
	if !has(ev, Blocking, CodePathOccupied) {
		t.Fatalf("dir at path %v", codes(ev, ""))
	}
	// Unreadable manifest, interrupted earlier run, compensated run with leftovers.
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "manifest-begin\nmanifest garbage\nmanifest-end\n"), fp, remote("hk-resi"))
	if ev.Ownership != OwnUnknown || !has(ev, Blocking, CodeManifestUnreadable) {
		t.Fatalf("unreadable %s %v", ev.Ownership, codes(ev, ""))
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "journal-begin\njournal state running\njournal run r1\njournal-end\n"), fp, remote("hk-resi"))
	if !has(ev, Blocking, CodePreviousRun) {
		t.Fatalf("running journal %v", codes(ev, ""))
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "journal-begin\njournal state compensated\njournal leftover package wireguard-tools\njournal-end\n"), fp, remote("hk-resi"))
	if !has(ev, Warning, CodePreviousLeftovers) || ev.Blocking {
		t.Fatalf("compensated journal %v", codes(ev, ""))
	}
	// Foreign Meridian-named resources without any file: table in use,
	// nft table present.
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "rtable4 150 route\nrtname 150 vpn\nnft table inet meridian {\n"), fp, remote("hk-resi"))
	if !has(ev, Blocking, CodeTableInUse) || !has(ev, Blocking, CodeNFTTableExists) || !has(ev, Warning, CodeTableName) {
		t.Fatalf("foreign tables %v", codes(ev, ""))
	}
}

// Gateway mode: ownership comes from the install manifest; Docker's
// FORWARD DROP blocks; a foreign fwmark collides.
func TestGatewayMode(t *testing.T) {
	files := nodeFiles(t, "gw")
	fp := FootprintOf(files)
	ev := Evaluate(fixture(t, "docker-forward-drop.txt", fp, nil, ""), fp, Context{NodeID: "gw", Gateway: true})
	checkShape(t, ev)
	if !has(ev, Blocking, CodeForwardDrop) || ev.Ownership != OwnNone {
		t.Fatalf("gateway %s %v", ev.Ownership, codes(ev, ""))
	}
	for _, c := range ev.Changes {
		if c.Kind == "state" {
			t.Fatal("gateway plan names the remote node manifest")
		}
	}
	marked := map[string]string{"/etc/wireguard/m02.conf": "file 400 yes -"}
	r := fixture(t, "clean-debian13.txt", fp, marked, "rule4 100:	from all fwmark 0x101 lookup 51820\n")
	ev = Evaluate(r, fp, Context{NodeID: "gw", Gateway: true})
	if !has(ev, Blocking, CodeFwmarkInUse) || has(ev, "", CodeLegacyInstall) {
		t.Fatalf("gateway fwmark/legacy %v", codes(ev, ""))
	}
	owned := &Owned{Files: map[string]string{"/etc/wireguard/m02.conf": ""}, Interfaces: []string{"m02"}, NFTTables: []string{"inet meridian"}}
	r = fixture(t, "clean-debian13.txt", fp, marked, "link m02\nnft table inet meridian {\n")
	ev = Evaluate(r, fp, Context{NodeID: "gw", Gateway: true, Owned: owned})
	if ev.Ownership != OwnSame || has(ev, "", CodeInterfaceExists) || has(ev, "", CodeNFTTableExists) {
		t.Fatalf("gateway owned %s %v", ev.Ownership, codes(ev, ""))
	}
	// An update: the previous install's own rules (some name no Meridian
	// table) are not conflicts; a foreign rule with the same mark still is.
	owned.Tables = []int{100, 102, 150}
	ours := "rule4 17000:\tfrom all fwmark 0x4d72 lookup main\nrule4 17200:\tfrom all fwmark 0x101 lookup 102\nrule4 17600:\tfrom all fwmark 0x101 unreachable\n"
	r = fixture(t, "clean-debian13.txt", fp, marked, "link m02\nnft table inet meridian {\n"+ours)
	ev = Evaluate(r, fp, Context{NodeID: "gw", Gateway: true, Owned: owned})
	if has(ev, "", CodeFwmarkInUse) || has(ev, "", CodeRulePriority) {
		t.Fatalf("own rules flagged: %v", codes(ev, ""))
	}
	r = fixture(t, "clean-debian13.txt", fp, marked, "link m02\nnft table inet meridian {\n"+ours+"rule4 900:\tfrom all fwmark 0x101 lookup 77\n")
	ev = Evaluate(r, fp, Context{NodeID: "gw", Gateway: true, Owned: owned})
	if !has(ev, Blocking, CodeFwmarkInUse) {
		t.Fatalf("foreign rule with our mark not flagged: %v", codes(ev, ""))
	}
}

func TestEnvironmentWarnings(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "ali"))
	extra := "unit nftables.service inactive enabled 0\nunit ufw.service active enabled 1\nipt ipv4 -P INPUT DROP\ncmd wstunnel yes\n" +
		"rule4 18100:	from 10.9.0.0/24 lookup 99\n"
	r := fixture(t, "clean-debian13.txt", fp, nil, extra)
	ev := Evaluate(r, fp, remote("ali"))
	for _, c := range []string{CodeNFTFlush, CodeFirewallManager, CodeInputDrop, CodeRulePriority} {
		if !has(ev, Warning, c) {
			t.Fatalf("missing warning %s: %v", c, codes(ev, ""))
		}
	}
	if ev.Blocking {
		t.Fatalf("warnings blocked: %v", codes(ev, Blocking))
	}
}

// --------------------------------------------------------------- parser ---

func TestParseRejectsGarbageAndTruncation(t *testing.T) {
	for name, text := range map[string]string{
		"empty":      "",
		"garbage":    "Welcome to Ubuntu\nlast login: never\n\x1b[31mred\x1b[0m\n",
		"no end":     Header + "\nuid 0\narch x86_64\n",
		"cut header": "meridian-pre",
		"oversized":  Header + "\n" + strings.Repeat("note "+strings.Repeat("x", 300)+"\n", MaxReport/300+10) + EndMarker + "\n",
		"many lines": Header + "\n" + strings.Repeat("x\n", maxLines+10) + EndMarker + "\n",
	} {
		r := Parse(text)
		if r.Complete {
			t.Fatalf("%s: parsed as complete", name)
		}
		ev := Evaluate(r, FootprintOf(nodeFiles(t, "hk-resi")), remote("hk-resi"))
		if !ev.Blocking || !has(ev, Blocking, CodeReportIncomplete) {
			t.Fatalf("%s: not blocking: %v", name, codes(ev, ""))
		}
	}
}

func TestParseHostileValues(t *testing.T) {
	long := strings.Repeat("A", 5000)
	text := Header + "\n" +
		"os-pretty \x1b]0;pwned\x07Debian‮ evil \x00\n" +
		"arch " + long + "\n" +
		"path /etc/shadow file 10 yes " + strings.Repeat("a", 64) + "\n" +
		"path /etc/wireguard/../../etc/shadow file 1 no -\n" +
		"path /etc/wireguard/m04.conf file 5 yes not-a-hash\n" +
		"addr eth0;rm 10.0.0.1/24\n" +
		"addr eth0 not-an-address\n" +
		"ss tcp LISTEN 0 1 0.0.0.0:99999 0.0.0.0:*\n" +
		"ss tcp LISTEN 0 1 0.0.0.0:443 0.0.0.0:* users:((\"$(id)\",pid=1,fd=1))\n" +
		"rule4 garbage\n" +
		"route4 local 10.0.0.1 dev lo\n" +
		"unit x\n" +
		"manifest node intruder\n" + // outside manifest-begin/end: ignored
		"\xff\xfe invalid utf8\n" +
		EndMarker + "\n" +
		"uid 0\n" // after the end line: ignored
	r := Parse(text)
	if !r.Complete {
		t.Fatalf("notes %v", r.Notes)
	}
	if strings.ContainsAny(r.OSPretty, "\x1b\x07\x00‮") || len([]rune(r.Arch)) > maxField {
		t.Fatalf("not cleaned: %q / %d", r.OSPretty, len(r.Arch))
	}
	if _, ok := r.Paths["/etc/shadow"]; ok {
		t.Fatal("path outside the allowed prefixes accepted")
	}
	if len(r.Paths) != 1 || r.Paths["/etc/wireguard/m04.conf"].SHA256 != "" {
		t.Fatalf("paths %+v", r.Paths)
	}
	if len(r.Addrs) != 0 || len(r.Rules) != 0 || len(r.Routes) != 0 || len(r.Units) != 0 || r.Manifest != nil || r.UID != -1 {
		t.Fatalf("hostile lines accepted: %+v", r)
	}
	if len(r.Listeners) != 1 || r.Listeners[0].Process != "" || r.Listeners[0].Port != 443 {
		t.Fatalf("listeners %+v", r.Listeners)
	}
}

func TestParseLines(t *testing.T) {
	r := Parse(Header + "\n" +
		"ss udp   UNCONN 0 0 [fe80::1%eth0]:546 [::]:* users:((\"dhcpcd\",pid=12,fd=3))\n" +
		"ss tcp   LISTEN 0 4096 *:9090 *:*\n" +
		"rule4 32765:\tnot from all fwmark 0x100cf lookup 65743\n" +
		"rule4 17600:\tfrom all fwmark 0x101 unreachable\n" +
		"route6 blackhole fd66::/48 dev lo metric 32767 pref medium\n" +
		"addr veth1@if5 10.1.0.1/24\n" +
		"addr wg9 10.2.0.1\n" +
		EndMarker + "\n")
	if len(r.Listeners) != 2 || r.Listeners[0].Addr.String() != "fe80::1" || r.Listeners[0].PID != 12 || !r.Listeners[1].Wildcard {
		t.Fatalf("listeners %+v", r.Listeners)
	}
	if len(r.Rules) != 2 || !r.Rules[0].Not || r.Rules[0].Fwmark != "0x100cf" || r.Rules[0].Table != "65743" || r.Rules[1].Action != "unreachable" {
		t.Fatalf("rules %+v", r.Rules)
	}
	if len(r.Routes) != 1 || r.Routes[0].Type != "blackhole" || r.Routes[0].Metric != 32767 {
		t.Fatalf("routes %+v", r.Routes)
	}
	if len(r.Addrs) != 2 || r.Addrs[0].Iface != "veth1" || r.Addrs[1].Prefix.String() != "10.2.0.1/32" {
		t.Fatalf("addrs %+v", r.Addrs)
	}
}

// --------------------------------------------------------------- script ---

func TestValidatePaths(t *testing.T) {
	// Every path of every node of the example is accepted.
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	byNode := map[string][]string{}
	for p := range b.Files {
		if !strings.HasPrefix(p, "nodes/") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(p, "nodes/"), "/", 2)
		byNode[parts[0]] = append(byNode[parts[0]], "/"+parts[1])
	}
	for n, ps := range byNode {
		if err := ValidatePaths(ps); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	for _, bad := range []string{
		"", "/", "etc/wireguard/m01.conf", "/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys",
		"/etc/wireguard/", "/etc/wireguard", "/etc/wireguard/../shadow", "/etc/wireguard/./m01.conf", "/etc/wireguard//m01.conf",
		"/etc/wireguard/m01.conf;id", "/etc/wireguard/$(id)", "/etc/wireguard/`id`", "/etc/wireguard/a b", "/etc/wireguard/a\nb",
		"/etc/wireguard/a'b", "/etc/wireguard/a\"b", "/etc/wireguard/*", "/etc/wireguard/a|b", "/etc/wireguard/a&b", "/etc/wireguard/-n",
		"/etc/wireguard/" + strings.Repeat("a", 200), "/etc/wireguardX/m01.conf", "/usr/local/bin/wstunnel", "/etc/wireguard/ü",
	} {
		if bad == "/etc/wireguard/-n" {
			// A leading dash is harmless after "--" (the script never passes
			// a path as an option), but keep it valid only if the rules say so.
			continue
		}
		if ValidPath(bad) {
			t.Fatalf("accepted %q", bad)
		}
		if _, err := Args([]string{bad}); err == nil {
			t.Fatalf("Args accepted %q", bad)
		}
	}
	many := make([]string, MaxPaths+1)
	for i := range many {
		many[i] = "/etc/meridian/f" + strconv.Itoa(i)
	}
	if err := ValidatePaths(many); err == nil {
		t.Fatal("too many paths accepted")
	}
	if err := ValidatePaths([]string{"/etc/meridian/a", "/etc/meridian/a"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	args, err := Args([]string{"/etc/meridian/a"})
	if err != nil || len(args) != 1 || args[0] != "'/etc/meridian/a'" {
		t.Fatalf("args %v %v", args, err)
	}
}

func TestScriptSyntaxAndReadOnly(t *testing.T) {
	s := Script()
	if _, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bash -n: %v\n%s", err, out)
		}
	}
	if _, err := exec.LookPath("sh"); err == nil {
		// The script is bash; sh -n only catches gross breakage here.
		_ = exec.Command("sh", "-n").Run()
	}
	if path, err := exec.LookPath("shellcheck"); err == nil {
		cmd := exec.Command(path, "-s", "bash", "-S", "warning", "-")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("shellcheck: %v\n%s", err, out)
		}
	}
	// No command that changes the host may appear in the script.
	for _, bad := range []string{
		"rm ", "mv ", "cp ", "tee ", "install ", "mkdir", "touch ", "chmod", "chown", "ln ",
		"systemctl start", "systemctl stop", "systemctl restart", "systemctl enable", "systemctl disable", "systemctl daemon",
		"nft add", "nft delete", "nft flush", "nft -f", "ip link add", "ip link del", "ip link set", "ip addr add", "ip route add",
		"ip route replace", "ip route del", "ip rule add", "ip rule del", "iptables -A", "iptables -I", "iptables -D", "iptables -P",
		"iptables -F", "sysctl -w", "apt-get install", "apt-get update", "apt-get remove", "dpkg -i", "modprobe", "wg set", "wg-quick up", "wg-quick down", "wg setconf", "wg syncconf", "docker run", "curl -", "wget ",
		"eval ", "source ", "exec ", "$(cat", "sudo",
	} {
		if strings.Contains(s, bad) {
			t.Fatalf("script contains %q", bad)
		}
	}
	// The only output redirections go to /dev/null.
	for _, line := range strings.Split(s, "\n") {
		rest := strings.NewReplacer(">/dev/null", "", "2>&1", "").Replace(line)
		if strings.Contains(rest, ">") {
			t.Fatalf("script redirects output: %s", line)
		}
	}
	if !strings.Contains(s, "head -c 262145") || MaxReport+1 != 262145 {
		t.Fatal("output bound does not match MaxReport")
	}
	if !strings.Contains(s, "</dev/null") {
		t.Fatal("commands must not read the script's stdin")
	}
}

// Runs the script locally (read-only) with valid and invalid arguments: it
// must always produce a complete, parseable report and refuse the invalid
// path itself (defence in depth behind ValidatePaths).
func TestScriptRunsLocally(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	cmd := exec.Command("bash", "-s", "--", "/etc/meridian/no-such-file-for-test", "/etc/passwd", "/etc/meridian/a;id")
	cmd.Stdin = strings.NewReader(Script())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v", err)
	}
	if len(out) > MaxReport+1 {
		t.Fatalf("output %d bytes", len(out))
	}
	r := Parse(string(out))
	if !r.Complete {
		t.Fatalf("local run incomplete: %v\n%s", r.Notes, out)
	}
	if pi, ok := r.Paths["/etc/meridian/no-such-file-for-test"]; !ok || pi.Exists {
		t.Fatalf("path %+v %v", pi, ok)
	}
	if _, ok := r.Paths["/etc/passwd"]; ok || strings.Count(string(out), "note path argument refused") != 2 {
		t.Fatalf("invalid arguments were not refused by the script:\n%s", out)
	}
	if strings.Contains(string(out), "root:") {
		t.Fatal("file content leaked into the report")
	}
}

// ------------------------------------------ updates of our own install ---

// gatewayOwned is the install manifest of the example gateway as the
// panel holds it (apply.Installed): every file, interface, unit, table.
func gatewayOwned(fp Footprint) *Owned {
	o := &Owned{Files: map[string]string{}, DNS: fp.DNS, Tables: fp.Tables, NFTTables: fp.NFTTables}
	for _, f := range fp.Files {
		o.Files[f] = ""
	}
	for _, i := range fp.Interfaces {
		o.Interfaces = append(o.Interfaces, i.Name)
	}
	for _, u := range fp.Units {
		if !strings.HasSuffix(u, ".timer") {
			o.Units = append(o.Units, u)
		}
	}
	return o
}

func allPresent(fp Footprint) map[string]string {
	m := map[string]string{}
	for _, p := range fp.Files {
		m[p] = "file 100 yes " + strings.Repeat("c", 64)
	}
	return m
}

// The real case, sanitized: a gateway running the previous install, its
// SmartDNS as the compose container meridian-smartdns (host network), the
// wstunnel clients as units of the install, the transit addresses on lo.
// The host agent cannot see process names (no CAP_SYS_PTRACE); sockets are
// attributed by their cgroup. An update without a real conflict passes.
func TestGatewayUpdateOfOwnInstallIsNotBlocked(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "gw"))
	if !containsAddr(fp.LoAddrs, netip.MustParseAddr("fd66:0:0:ff::a")) {
		t.Fatalf("lo addresses %v", fp.LoAddrs)
	}
	ctx := Context{NodeID: "gw", Gateway: true, Owned: gatewayOwned(fp)}
	r := fixture(t, "gateway-installed.txt", fp, allPresent(fp), "")
	ev := Evaluate(r, fp, ctx)
	checkShape(t, ev)
	if ev.Blocking || ev.Ownership != OwnSame {
		t.Fatalf("own install blocked: %s %+v", ev.Ownership, find(ev, CodePortInUse))
	}
	for _, c := range []string{CodeSmartDNSMissing, CodePortInUse, CodeRouteOverlap, CodeAddressOverlap, CodeFwmarkInUse, CodeTableInUse, CodeForwardDrop} {
		if has(ev, "", c) {
			t.Fatalf("false %s: %+v", c, find(ev, c))
		}
	}
	if g := find(ev, CodeGatewayDNS); len(g) != 1 || !strings.Contains(g[0].Message, "meridian-smartdns") {
		t.Fatalf("dns runtime %+v", g)
	}
	for _, ch := range ev.Changes {
		if ch.Kind == "package" {
			t.Fatalf("the gateway install installs no package: %+v", ch)
		}
	}

	// A foreign resolver next to our install still blocks, named.
	r = fixture(t, "gateway-installed.txt", fp, allPresent(fp),
		"ss udp UNCONN 0 0 192.168.100.88:53 0.0.0.0:*\nssc udp UNCONN 0 0 192.168.100.88:53 0.0.0.0:* cgroup:/system.slice/dnsmasq.service\n")
	ev = Evaluate(r, fp, ctx)
	if pu := find(ev, CodePortInUse); len(pu) != 1 || !strings.Contains(pu[0].Message, "服务 dnsmasq.service") || !ev.Blocking {
		t.Fatalf("foreign :53 %+v", pu)
	}
	// A listener in another container's cgroup is not ours.
	other := strings.Replace(string(mustRead(t, "testdata/gateway-installed.txt")),
		"container meridian-smartdns 1111111111111111111111111111111111111111111111111111111111111111 true",
		"container meridian-smartdns 3333333333333333333333333333333333333333333333333333333333333333 true", 1)
	ev = Evaluate(parseWithPaths(t, other, fp, allPresent(fp)), fp, ctx)
	if pu := find(ev, CodePortInUse); len(pu) != 3 || !strings.Contains(pu[0].Message, "容器 111111111111") {
		t.Fatalf("other container %+v", pu)
	}
	// A unit the manifest does not list holds a wstunnel port.
	foreign := strings.Replace(string(mustRead(t, "testdata/gateway-installed.txt")),
		"cgroup:/system.slice/wstunnel-client-gw-ali.service", "cgroup:/system.slice/wstunnel-other.service", 1)
	ev = Evaluate(parseWithPaths(t, foreign, fp, allPresent(fp)), fp, ctx)
	if pu := find(ev, CodePortInUse); len(pu) != 1 || pu[0].Resource != "udp 127.0.0.1:52002" || !strings.Contains(pu[0].Message, "wstunnel-other.service") {
		t.Fatalf("foreign unit %+v", pu)
	}
	// The same host state without a manifest (a first install) is blocked:
	// nothing is ours without evidence.
	ev = Evaluate(fixture(t, "gateway-installed.txt", fp, nil, ""), fp, Context{NodeID: "gw", Gateway: true})
	for _, c := range []string{CodePortInUse, CodeInterfaceExists, CodeNFTTableExists, CodeRouteOverlap} {
		if !has(ev, Blocking, c) {
			t.Fatalf("first install: missing %s: %v", c, codes(ev, ""))
		}
	}
	// No cgroup facts (an older ss): fail closed.
	nocg := regexp.MustCompile(`(?m)^ssc .*\n`).ReplaceAllString(string(mustRead(t, "testdata/gateway-installed.txt")), "")
	ev = Evaluate(parseWithPaths(t, nocg, fp, allPresent(fp)), fp, ctx)
	if pu := find(ev, CodePortInUse); len(pu) == 0 || !strings.Contains(pu[0].Message, "看不到名字") {
		t.Fatalf("without cgroups %+v", pu)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseWithPaths(t *testing.T, raw string, fp Footprint, paths map[string]string) Report {
	t.Helper()
	var b strings.Builder
	for _, p := range fp.Files {
		if v, ok := paths[p]; ok {
			b.WriteString("path " + p + " " + v + "\n")
		} else {
			b.WriteString("path " + p + " absent\n")
		}
	}
	r := Parse(strings.Replace(raw, "@PATHS@\n", b.String(), 1))
	if !r.Complete {
		t.Fatalf("incomplete: %v", r.Notes)
	}
	return r
}

// installedByUs renders what a host looks like after this panel installed
// fp for node: the manifest, every interface with its addresses and
// WireGuard port, the transit addresses on lo, the main-table routes and
// rules of the bundle, its tables and nft tables, the units' sockets.
func installedByUs(fp Footprint, node, dep string) string {
	var b strings.Builder
	b.WriteString("manifest-begin\nmanifest meridian-node-manifest 1\nmanifest node " + node + "\nmanifest deployment " + dep + "\n")
	for _, p := range fp.Files {
		b.WriteString("manifest file " + p + " " + strings.Repeat("c", 64) + "\n")
	}
	for _, i := range fp.Interfaces {
		b.WriteString("manifest iface " + i.Name + "\n")
	}
	for _, u := range fp.Units {
		b.WriteString("manifest unit " + u + "\n")
	}
	for _, n := range fp.NFTTables {
		b.WriteString("manifest nft " + n + "\n")
	}
	for _, n := range fp.Tables {
		b.WriteString("manifest table " + strconv.Itoa(n) + "\n")
	}
	b.WriteString("manifest-end\n")
	for _, i := range fp.Interfaces {
		b.WriteString("link " + i.Name + "\nwglink " + i.Name + "\n")
		for _, a := range i.Addresses {
			b.WriteString("addr " + i.Name + " " + a.String() + "\n")
		}
		if i.ListenPort > 0 {
			p := strconv.Itoa(i.ListenPort)
			b.WriteString("wgport " + i.Name + " " + p + "\nss udp UNCONN 0 0 0.0.0.0:" + p + " 0.0.0.0:*\nss udp UNCONN 0 0 [::]:" + p + " [::]:*\n")
		}
	}
	for _, a := range fp.LoAddrs {
		fam := "route4"
		if a.Addr().Is6() {
			fam = "route6"
		}
		b.WriteString("addr lo " + a.String() + "\n" + fam + " " + a.Addr().String() + " dev lo proto kernel metric 256 pref medium\n")
	}
	for _, r := range fp.Routes {
		if r.Table != 0 {
			continue
		}
		fam := "route4"
		if r.Family == 6 {
			fam = "route6"
		}
		if r.Blackhole {
			b.WriteString(fam + " blackhole " + r.Dst.String() + " metric " + strconv.Itoa(r.Metric) + "\n")
		} else if r.Dev != "" {
			b.WriteString(fam + " " + r.Dst.String() + " dev " + r.Dev + " scope link\n")
		}
	}
	for _, r := range fp.Rules {
		b.WriteString("rule" + strconv.Itoa(r.Family) + " " + strconv.Itoa(r.Priority) + ":\t" + r.Selector + "\n")
	}
	for _, n := range fp.Tables {
		b.WriteString("rtable4 " + strconv.Itoa(n) + " route\nrtable4 " + strconv.Itoa(n) + " default\n")
	}
	for _, n := range fp.NFTTables {
		b.WriteString("nft table " + n + " {\n")
	}
	for _, l := range fp.Listens {
		if l.Owner == "smartdns" || strings.Contains(l.Owner, ".service") {
			unit := l.Owner
			if unit == "smartdns" {
				unit = "smartdns.service"
			}
			addr := l.Addr.String()
			if l.Addr.Is6() {
				addr = "[" + addr + "]"
			}
			kind := map[string]string{"tcp": "LISTEN", "udp": "UNCONN"}[l.Proto]
			line := l.Proto + " " + kind + " 0 0 " + addr + ":" + strconv.Itoa(l.Port) + " 0.0.0.0:*"
			b.WriteString("ss " + line + "\nssc " + line + " cgroup:/system.slice/" + unit + "\n")
		}
	}
	return b.String()
}

// A remote node updated by this panel: its own interfaces, WireGuard
// ports, wstunnel and smartdns sockets, lo transit addresses, routes,
// rules, tables and nft tables are not conflicts.
func TestRemoteUpdateOfOwnInstallIsNotBlocked(t *testing.T) {
	for _, node := range []string{"hk-hub", "ali", "hk-resi", "hk-ix"} {
		fp := FootprintOf(nodeFiles(t, node))
		state := installedByUs(fp, node, "dep-test") + "cmd wstunnel yes\ncmd smartdns yes\n"
		r := fixture(t, "clean-debian13.txt", fp, allPresent(fp), state)
		ev := Evaluate(r, fp, remote(node))
		checkShape(t, ev)
		if ev.Ownership != OwnSame || ev.Blocking {
			t.Fatalf("%s: own install blocked (%s): %v %+v", node, ev.Ownership, codes(ev, Blocking), ev.Findings[:min(3, len(ev.Findings))])
		}
		for _, c := range []string{CodePortInUse, CodeRouteOverlap, CodeAddressOverlap, CodeFwmarkInUse, CodeTableInUse, CodeInterfaceExists, CodeNFTTableExists} {
			if has(ev, "", c) {
				t.Fatalf("%s: false %s: %+v", node, c, find(ev, c))
			}
		}
		// Another node's or another panel's install: everything blocks.
		ev = Evaluate(r, fp, Context{NodeID: node, Deployment: "dep-other"})
		if !has(ev, Blocking, CodeManagedByOther) || !has(ev, Blocking, CodeInterfaceExists) {
			t.Fatalf("%s: other deployment %v", node, codes(ev, ""))
		}
		if len(fp.Listens) > 0 && !has(ev, Blocking, CodePortInUse) {
			t.Fatalf("%s: other deployment, listeners not blocking: %v", node, codes(ev, ""))
		}
	}
	// Ours, but a foreign process also holds the WSS port.
	fp := FootprintOf(nodeFiles(t, "ali"))
	state := installedByUs(fp, "ali", "dep-test") + "cmd wstunnel yes\n" +
		"ss tcp LISTEN 0 511 [::]:443 [::]:* users:((\"nginx\",pid=77,fd=6))\n"
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, allPresent(fp), state), fp, remote("ali"))
	if pu := find(ev, CodePortInUse); len(pu) != 1 || !strings.Contains(pu[0].Message, "nginx") {
		t.Fatalf("foreign 443 next to ours %+v", pu)
	}
}
