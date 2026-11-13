package compile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
)

// verifyHost is the host state the stub programs report to the generated
// meridian-verify.sh. A nil map means the program is not installed; a
// command missing from a map fails with exit 1 (like "ip link show dev mra"
// for an interface that does not exist).
type verifyHost struct {
	sysctl map[string]string
	ip     map[string]string
	nft    map[string]string
	wg     map[string]string
	ss     map[string]string
	dig    map[string]string
	// systemctl is nil on most hosts here: the WARN check is then skipped.
	systemctl map[string]string
	ssh       string
	// sshFail makes ssh time out.
	sshFail bool
	// files are installed files under MERIDIAN_VERIFY_ROOT.
	files map[string]string
	env   []string
}

var (
	reRuleAdd = regexp.MustCompile(`(?m)^ip (-6 )?rule add (.+) priority (\d+)$`)
	reNftMark = regexp.MustCompile(`(meta mark (?:set )?)0x([0-9a-f]+)(?:-0x([0-9a-f]+))?`)
)

// nftListing turns compiled nft text into what "nft list" prints for the
// parts the script reads: marks as 0x%08x, and filled chnroute sets.
func nftListing(s string) string {
	s = reNftMark.ReplaceAllStringFunc(s, func(m string) string {
		p := reNftMark.FindStringSubmatch(m)
		lo, _ := strconv.ParseUint(p[2], 16, 32)
		out := fmt.Sprintf("%s0x%08x", p[1], lo)
		if p[3] != "" {
			hi, _ := strconv.ParseUint(p[3], 16, 32)
			out += fmt.Sprintf("-0x%08x", hi)
		}
		return out
	})
	s = strings.Replace(s, "  set chnroute {\n    type ipv4_addr\n    flags interval\n  }",
		"  set chnroute {\n    type ipv4_addr\n    flags interval\n    elements = { 1.0.1.0/24,\n\t\t     1.0.2.0/23 }\n  }", 1)
	s = strings.Replace(s, "  set chnroute6 {\n    type ipv6_addr\n    flags interval\n  }",
		"  set chnroute6 {\n    type ipv6_addr\n    flags interval\n    elements = { 2400:3200::/32 }\n  }", 1)
	return s
}

// ipRules renders "ip rule show" for one family from the compiled routes
// script, the way iproute2 prints it (table names from rt_tables.d).
func ipRules(routes string, v6 bool) string {
	type rule struct {
		prio int
		text string
	}
	rs := []rule{{0, "from all lookup local"}, {32766, "from all lookup main"}}
	for _, m := range reRuleAdd.FindAllStringSubmatch(routes, -1) {
		if (m[1] != "") != v6 {
			continue
		}
		p, _ := strconv.Atoi(m[3])
		sel := strings.ReplaceAll(m[2], "'", "")
		sel = strings.Replace(sel, "lookup 102", "lookup meridian_foreign", 1)
		sel = strings.Replace(sel, "lookup 100", "lookup meridian_domestic", 1)
		rs = append(rs, rule{p, "from all " + sel})
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].prio < rs[j].prio })
	var sb strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&sb, "%d:\t%s\n", r.prio, r.text)
	}
	return sb.String()
}

// goodHost is a gateway on which the bundle is installed and every local
// check holds.
func goodHost(t *testing.T, b *Bundle, topo model.Topology) verifyHost {
	t.Helper()
	nftFile := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	guardAt := strings.Index(nftFile, "table inet meridian_guard {")
	mainAt := strings.Index(nftFile, "table inet meridian {")
	if guardAt < 0 || mainAt < guardAt {
		t.Fatal("unexpected nft layout")
	}
	guard := nftFile[guardAt:strings.LastIndex(nftFile[:mainAt], "table inet meridian\n")]
	routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	h := verifyHost{
		sysctl: map[string]string{
			"net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2", "net.ipv4.conf.eth0.rp_filter": "2",
			"net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.eth0.send_redirects": "0",
			"net.ipv4.conf.all.accept_redirects": "0", "net.ipv6.conf.all.accept_redirects": "0",
			"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1",
		},
		ip: map[string]string{
			"-4 -o addr show dev eth0":   "2: eth0    inet 192.168.100.88/24 brd 192.168.100.255 scope global eth0\n",
			"-4 route get 192.168.100.1": "192.168.100.1 dev eth0 src 192.168.100.88 uid 0\n",
			"-6 route show table all":    "default via fe80::1 dev eth0 proto ra metric 1024\nfd66:0:0:2::/64 dev m02 proto kernel metric 256\n",
			"-4 rule show":               ipRules(routes, false),
			"-6 rule show":               ipRules(routes, true),
			"-4 route show table 102":    "default dev m02 scope link\nblackhole default metric 32767\n192.168.100.0/24 dev eth0 scope link\n",
			"-6 route show table 102":    "2001:db8:100::/64 dev eth0 metric 1024 pref medium\ndefault dev m02 metric 1024 pref medium\nblackhole default dev lo metric 32767 pref medium\n",
			"-4 route show table 100":    "default via 192.168.100.1 dev eth0\nblackhole default metric 32767\n192.168.100.0/24 dev eth0 scope link\n",
			"-4 route show table main":   "default via 192.168.100.1 dev eth0 proto dhcp\n10.66.0.0/16 dev m02 scope link\n",
			"-6 route show table main":   "default via fe80::1 dev eth0 proto ra metric 1024\n",
			"-6 route show table 100":    "default via fe80::1 dev eth0 metric 1024 pref medium\n",
		},
		nft: map[string]string{
			"list table inet meridian_guard": nftListing(guard),
			"list table inet meridian":       nftListing(nftFile[mainAt:]),
		},
		dig: map[string]string{digAAAAArgs: digEmptyAAAA},
		ss: map[string]string{
			"-H -lnu": "UNCONN 0      0         0.0.0.0:53        0.0.0.0:*\nUNCONN 0      0            [::]:53           [::]:*\n",
			"-H -lnt": "LISTEN 0      4096      0.0.0.0:53        0.0.0.0:*\n",
		},
		files: map[string]string{
			"etc/nftables.d/meridian.nft":       nftFile,
			"etc/nftables.d/meridian-guard.nft": b.File("nodes/gw/etc/nftables.d/meridian-guard.nft"),
			"var/lib/meridian/geosite/cn.txt":   "example.cn\nexample.com.cn\n",
		},
	}
	st := lists.Status{Published: map[string]lists.Published{
		"chnroute4":  {Source: "github", URL: "https://example.invalid/china.txt", UpdatedAt: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC), Count: 8000},
		"geosite:cn": {Source: "github", URL: "https://example.invalid/cn", UpdatedAt: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC), Count: 2},
	}}
	raw, err := json.MarshalIndent(st, "", "  ") // what lists.Updater writes
	if err != nil {
		t.Fatal(err)
	}
	h.files["var/lib/meridian/lists/status.json"] = string(raw)
	if rp := planRemote(topo); rp != nil {
		h.ip["link show dev mra"] = "9: mra: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/none\n"
		h.ip["-4 route show table main"] += rp.V4.String() + " dev mra scope link\nblackhole " + rp.V4.String() + " metric 32767\n"
		h.ip["-4 route show table 100"] += rp.V4.String() + " dev mra scope link\n"
		h.ip["-6 route show table main"] += rp.V6.String() + " dev mra proto kernel metric 256 pref medium\nblackhole " + rp.V6.String() + " dev lo metric 32767 pref medium\n"
		h.ip["-6 route show table 100"] += rp.V6.String() + " dev mra metric 1024 pref medium\n"
		var peers []string
		for _, d := range rp.Devices {
			peers = append(peers, d.PublicKey)
		}
		h.wg = map[string]string{
			"show mra listen-port": fmt.Sprintf("%d\n", rp.Port),
			"show mra peers":       strings.Join(peers, "\n") + "\n",
		}
	}
	routeProbes(t, b.File("nodes/gw/usr/local/sbin/meridian-verify.sh"), h.ip)
	// Region-group resolvers: SmartDNS's config, and the marked lookup of
	// each resolver address the way iproute2 prints it.
	h.files["etc/smartdns/smartdns.conf"] = b.File("nodes/gw/etc/smartdns/smartdns.conf")
	groups, err := PlanGroups(topo)
	if err != nil {
		t.Fatal(err)
	}
	west := strings.Fields(strings.Join(gatewayTunnelIfaces(mustTunnels(t, topo)), " "))[0]
	for _, g := range groups {
		if g.Dynamic {
			h.ip[fmt.Sprintf("-6 route get %s mark %#x", g.Resolver, g.Mark)] = fmt.Sprintf("%s from :: dev %s table meridian_foreign proto kernel src fd66:0:0:1::1 metric 1024 pref medium\n", g.Resolver, west)
		}
	}
	return h
}

// The AAAA query meridian-verify.sh sends for a tunnelled name, and what dig
// prints for the empty NOERROR (SOA) answer force-AAAA-SOA gives and for a
// real AAAA answer.
const (
	digAAAAArgs  = "+time=3 +tries=1 @127.0.0.1 AAAA www.google.com"
	digEmptyAAAA = `; <<>> DiG 9.20.11 <<>> +time=3 +tries=1 @127.0.0.1 AAAA www.google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;www.google.com.			IN	AAAA

;; AUTHORITY SECTION:
google.com.		30	IN	SOA	a.gtld-servers.net. nstld.verisign-grs.com. 1800 1800 900 604800 86400

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
`
	digRealAAAA = `; <<>> DiG 9.20.11 <<>> +time=3 +tries=1 @127.0.0.1 AAAA www.google.com
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4243
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;www.google.com.			IN	AAAA

;; ANSWER SECTION:
www.google.com.		60	IN	AAAA	2001:db8:e::1
`
)

// Route-probe answers, the way iproute2 prints a resolved "route get … iif"
// (the probe addresses are read from the compiled script).
var reVerifyVar = regexp.MustCompile(`(?m)^(lan_client4|lan_client6|has_lan6|tun_ifaces|ra_dev4|ra_dev6|ra_enabled)='?([^'\n]*)'?$`)

// probeKeys returns the ip arguments of every route probe the script runs,
// mapped to the interface the answer must name.
func probeKeys(t *testing.T, script string) map[string]string {
	t.Helper()
	v := map[string]string{}
	for _, m := range reVerifyVar.FindAllStringSubmatch(script, -1) {
		v[m[1]] = m[2]
	}
	if v["lan_client4"] == "" {
		t.Fatal("no lan_client4 in the verify script")
	}
	k := map[string]string{
		"-4 route get 192.168.100.1 from " + v["lan_client4"] + " iif eth0 mark 0x64": "eth0",
	}
	tuns := strings.Fields(v["tun_ifaces"])
	for _, tun := range tuns {
		k["-4 route get "+v["lan_client4"]+" from 192.0.2.1 iif "+tun] = "eth0"
	}
	if v["has_lan6"] == "1" {
		k["-6 route get 2001:db8:ffff::1 from "+v["lan_client6"]+" iif eth0 mark 0x64"] = "eth0"
		for _, tun := range tuns {
			k["-6 route get "+v["lan_client6"]+" from 2001:db8:ffff::2 iif "+tun] = "eth0"
		}
	}
	if v["ra_enabled"] == "1" {
		k["-4 route get 192.168.100.1 from "+v["ra_dev4"]+" iif mra mark 0x64"] = "eth0"
		k["-4 route get "+v["ra_dev4"]+" from 192.168.100.1 iif eth0 mark 0x64"] = "mra"
		k["-6 route get "+v["ra_dev6"]+" from 2001:db8:ffff::1 iif eth0 mark 0x64"] = "mra"
		if v["has_lan6"] == "1" {
			k["-6 route get 2001:db8:ffff::1 from "+v["ra_dev6"]+" iif mra mark 0x64"] = "eth0"
		}
		for _, tun := range tuns {
			k["-4 route get "+v["ra_dev4"]+" from 192.0.2.1 iif "+tun] = "mra"
			k["-6 route get "+v["ra_dev6"]+" from 2001:db8:ffff::2 iif "+tun] = "mra"
		}
	}
	return k
}

func routeProbes(t *testing.T, script string, ip map[string]string) {
	t.Helper()
	for args, dev := range probeKeys(t, script) {
		f := strings.Fields(args) // -4 route get DST from SRC iif IIF [mark M]
		ans := f[3] + " from " + f[5] + " dev " + dev
		if len(f) > 9 {
			ans += " table meridian_domestic mark " + f[9]
		}
		ip[args] = ans + " uid 0\n    cache iif " + f[7] + "\n"
	}
}

// exdev makes every probe whose arguments contain needle fail the way the
// kernel does when source validation rejects the packet.
func exdev(h *verifyHost, needle string) {
	for k := range h.ip {
		if strings.Contains(k, " route get ") && strings.Contains(k, " iif ") && strings.Contains(k, needle) {
			h.ip[k] = "ERR:RTNETLINK answers: Invalid cross-device link\n"
		}
	}
}

// stubCases writes a stub that answers exactly the argument strings in m.
func stubCases(t *testing.T, dir, bin, name string, m map[string]string) {
	t.Helper()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\ncase \"$*\" in\n")
	for i, k := range keys {
		f := filepath.Join(dir, fmt.Sprintf("%s-%d.out", name, i))
		if err := os.WriteFile(f, []byte(m[k]), 0o644); err != nil {
			t.Fatal(err)
		}
		if body, ok := strings.CutPrefix(m[k], "ERR:"); ok {
			// A failing command: the text on stderr, exit 2 (like ip).
			if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&sb, "'%s') cat '%s' >&2; exit 2 ;;\n", k, f)
			continue
		}
		fmt.Fprintf(&sb, "'%s') cat '%s' ;;\n", k, f)
	}
	sb.WriteString("*) echo \"" + name + ": $*: not available\" >&2; exit 1 ;;\nesac\n")
	if err := os.WriteFile(filepath.Join(bin, name), []byte(sb.String()), 0o755); err != nil {
		t.Fatal(err)
	}
}

// runVerify runs script in bash against h's stubs; it returns the exit
// code, the output and the evidence directory.
func runVerify(t *testing.T, script string, h verifyHost) (int, string, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	ev := filepath.Join(dir, "evidence")
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"date", "mkdir", "grep", "mktemp", "cat"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skip(tool + " not installed")
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if h.sysctl != nil {
		var sb strings.Builder
		for k, v := range h.sysctl {
			sb.WriteString(k + "=" + v + "\n")
		}
		_ = os.WriteFile(filepath.Join(dir, "sysctl.txt"), []byte(sb.String()), 0o644)
		_ = os.WriteFile(filepath.Join(bin, "sysctl"), []byte(`#!/bin/bash
[ "$1" = "-n" ] || exit 2
while IFS='=' read -r k v; do [ "$k" = "$2" ] && { echo "$v"; exit 0; }; done < "$D/sysctl.txt"
exit 1
`), 0o755)
	}
	for name, m := range map[string]map[string]string{"ip": h.ip, "nft": h.nft, "wg": h.wg, "ss": h.ss, "systemctl": h.systemctl, "dig": h.dig} {
		if m != nil {
			stubCases(t, dir, bin, name, m)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "ssh.txt"), []byte(h.ssh), 0o644)
	sshBody := `cat "$D/ssh.txt"`
	if h.sshFail {
		sshBody = `echo "ssh: connect to host: timed out" >&2; exit 255`
	}
	_ = os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/bash\n"+sshBody+"\n"), 0o755)
	for p, body := range h.files {
		f := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(bash, "-c", script)
	cmd.Env = append([]string{"PATH=" + bin, "D=" + dir, "MERIDIAN_VERIFY_EVIDENCE_DIR=" + ev, "MERIDIAN_VERIFY_ROOT=" + root}, h.env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(filepath.Join(ev, "summary.txt"))
	if err != nil || !strings.Contains(string(summary), "evidence: "+ev) {
		t.Fatalf("no evidence summary: %v\n%s", err, summary)
	}
	return code, string(out), ev
}

type verifyCase struct {
	name      string
	mutate    func(h *verifyHost)
	wantCode  int
	want      []string
	forbidden []string
}

func runVerifyCases(t *testing.T, script string, base func() verifyHost, cases []verifyCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := base()
			if c.mutate != nil {
				c.mutate(&h)
			}
			code, out, _ := runVerify(t, script, h)
			if code != c.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, c.wantCode, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q\n%s", w, out)
				}
			}
			for _, f := range c.forbidden {
				if strings.Contains(out, f) {
					t.Errorf("output must not contain %q\n%s", f, out)
				}
			}
			// Every PASS is a check the script ran; nothing it cannot run
			// (client DNS, WebRTC, captures, phones, the router) passes.
			for _, never := range []string{"PASS dns_leak", "PASS webrtc", "PASS redirect_on_wire", "PASS tunnel_cut", "PASS remote_phone", "PASS remote_router", "PASS remote_ipv6", "PASS netns", "PASS group_dns_failover", "meridian-verify-ok"} {
				if strings.Contains(out, never) {
					t.Errorf("unexecuted check reported as passed: %q\n%s", never, out)
				}
			}
		})
	}
}

// TestVerifyScriptExecutedChecks runs the generated meridian-verify.sh in
// bash against stub sysctl/ip/nft/ss/ssh programs and installed files
// under a temporary root, for the example topology (remote access off). It
// proves the script's decision logic only: a missing firewall fails, policy
// rules must cover every compiled exit and region-group mark, the guard's
// range and ingress must be the compiled ones, empty domestic lists fail,
// a stale mra fails, unexecuted client/ROS checks are never reported as
// passed, and the success line is limited to local checks. It is not
// evidence about a real gateway or a real leak.
func TestVerifyScriptExecutedChecks(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	base := func() verifyHost { return goodHost(t, b, topo) }
	pendings := []string{"PENDING-HUMAN dns_leak_client", "PENDING-HUMAN webrtc_srflx", "PENDING-HUMAN tunnel_cut", "PENDING-HUMAN redirect_on_wire", "NOT-RUN-HERE netns_reload_no_leak"}
	dropLines := func(s, needle string) string {
		var keep []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.Contains(l, needle) {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	emptyChn := func(h *verifyHost) {
		h.nft["list table inet meridian"] = nftListing(strings.SplitN(h.files["etc/nftables.d/meridian.nft"], "table inet meridian {", 2)[1])
		h.nft["list table inet meridian"] = strings.Replace(h.nft["list table inet meridian"], "elements = { 1.0.1.0/24,\n\t\t     1.0.2.0/23 }\n", "", 1)
	}
	runVerifyCases(t, script, base, []verifyCase{
		{name: "all local checks pass", wantCode: 0,
			want: append([]string{"meridian-verify-local-ok", "PASS nft_guard", "PASS dns_hijack_853", "PASS ula_not_via_ros",
				"PASS policy_marks: all 22 compiled", "PASS no_stale_iif_rule", "PASS fallback_blackholes", "PASS remote_absent",
				"PASS route_lan_domestic4: a LAN client (192.168.100.254) to a domestic destination (192.168.100.1, mark 0x64) resolves out of eth0",
				"PASS route_tunnel_reply4: a reply from 192.0.2.1 to the LAN client 192.168.100.254 from each tunnel (m02 m02w m03) resolves out of eth0",
				"PASS route_lan_domestic6", "PASS route_tunnel_reply6",
				"PASS guard_mark_range", "PASS guard_ingress: the guard's ingress is eth0 only", "PASS chnroute_loaded", "PASS chnroute6_loaded",
				"PASS guard_boot_file", "PASS geosite_cn", "PASS dns_listener",
				"PASS dns_aaaa_tunnelled: AAAA for www.google.com is empty (NOERROR, no address)",
				"PASS group_dns_snat", "PASS group_dns_upstream: ", "PASS group_dns_route: a lookup of each group resolver address with the group mark resolves into a tunnel (m02 m02w m03), not eth0",
				"PENDING-HUMAN group_dns_failover", "NOT-RUN-HERE netns_group_dns",
				"INFO list chnroute4: source=github count=8000 updated=2026-11-12T03:00:00Z", "INFO list geosite:cn: source=github count=2",
				"PENDING-HUMAN ros_ula_blackhole"}, pendings...),
			forbidden: []string{"PASS ros_ula", "PENDING-HUMAN remote_", "FAIL", "UNKNOWN"}},
		{name: "nft not installed", mutate: func(h *verifyHost) { h.nft = nil }, wantCode: 1,
			want: []string{"FAIL nft:", "meridian-verify-failed"}, forbidden: []string{"local-ok", "PASS chnroute"}},
		{name: "main table missing", mutate: func(h *verifyHost) { delete(h.nft, "list table inet meridian") }, wantCode: 1,
			want: []string{"FAIL nft_meridian", "PASS nft_guard"}, forbidden: []string{"local-ok"}},
		{name: "guard table missing", mutate: func(h *verifyHost) { delete(h.nft, "list table inet meridian_guard") }, wantCode: 1,
			want: []string{"FAIL nft_guard"}, forbidden: []string{"local-ok", "PASS guard_mark_range", "PASS guard_ingress"}},
		{name: "forwarding off", mutate: func(h *verifyHost) { h.sysctl["net.ipv4.ip_forward"] = "0" }, wantCode: 1,
			want: []string{"FAIL sysctl net.ipv4.ip_forward: 0, want 1"}},
		{name: "not a gateway", mutate: func(h *verifyHost) { h.sysctl, h.ip, h.ss = nil, nil, nil }, wantCode: 2,
			want: []string{"UNKNOWN sysctl", "UNKNOWN routes", "UNKNOWN dns_listener", "meridian-verify-incomplete"}, forbidden: []string{"local-ok", "PASS policy_marks"}},
		{name: "ula via ros", mutate: func(h *verifyHost) { h.ip["-6 route show table all"] += "fd66::/48 via fe80::1 dev eth0 metric 1024\n" }, wantCode: 1,
			want: []string{"FAIL ula_not_via_ros"}},
		{name: "ros blackhole present", mutate: func(h *verifyHost) {
			h.env = []string{"MERIDIAN_ROS_SSH=admin@192.168.100.1"}
			h.ssh = " 0 Xb  dst-address=fd00::/8 blackhole distance=1\n"
		}, wantCode: 0, want: []string{"PASS ros_ula_blackhole", "local-ok"}},
		{name: "ros blackhole absent", mutate: func(h *verifyHost) {
			h.env = []string{"MERIDIAN_ROS_SSH=admin@192.168.100.1"}
			h.ssh = " 0 As  dst-address=::/0 gateway=fe80::2\n"
		}, wantCode: 1, want: []string{"FAIL ros_ula_blackhole"}},
		{name: "ros unreachable", mutate: func(h *verifyHost) {
			h.env = []string{"MERIDIAN_ROS_SSH=admin@192.168.100.1"}
			h.sshFail = true
		}, wantCode: 2, want: []string{"UNKNOWN ros_ula_blackhole"}, forbidden: []string{"PASS ros_ula", "local-ok"}},
		{name: "ros target refused", mutate: func(h *verifyHost) { h.env = []string{"MERIDIAN_ROS_SSH=-oProxyCommand=x"} }, wantCode: 1,
			want: []string{"FAIL ros_ula_blackhole: MERIDIAN_ROS_SSH refused"}},
		{name: "group mark rule missing", mutate: func(h *verifyHost) {
			h.ip["-6 rule show"] = dropLines(h.ip["-6 rule show"], "fwmark 0x10f unreachable")
			h.ip["-4 rule show"] = dropLines(h.ip["-4 rule show"], "fwmark 0x10f lookup")
		}, wantCode: 1, want: []string{"FAIL policy_marks: loaded policy rules miss: group/jp/v4-lookup group/jp/v6-unreachable"}},
		{name: "ip rule unreadable", mutate: func(h *verifyHost) { delete(h.ip, "-4 rule show") }, wantCode: 1,
			want: []string{"FAIL policy_marks: ip rule show failed"}, forbidden: []string{"PASS no_stale_iif_rule"}},
		{name: "foreign table without blackhole", mutate: func(h *verifyHost) {
			h.ip["-6 route show table 102"] = dropLines(h.ip["-6 route show table 102"], "blackhole")
		}, wantCode: 1, want: []string{"FAIL fallback_blackholes"}},
		{name: "guard range narrower than the group marks", mutate: func(h *verifyHost) {
			h.nft["list table inet meridian_guard"] = strings.Replace(h.nft["list table inet meridian_guard"], "-0x00000140", "-0x00000110", 1)
		}, wantCode: 1, want: []string{"FAIL guard_mark_range: guard range is 0x101-0x110, compiled 0x101-0x140; marks outside: 0x111"}},
		{name: "stale mra while remote access is off", mutate: func(h *verifyHost) {
			h.ip["link show dev mra"] = "9: mra: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380\n"
		}, wantCode: 1, want: []string{"FAIL remote_absent: remote access is off but interface mra exists"}},
		{name: "leftover iif mra rule after switching remote access off", mutate: func(h *verifyHost) {
			h.ip["-4 rule show"] += "17851:\tfrom all iif mra [detached] unreachable\n"
		}, wantCode: 1, want: []string{"PASS remote_absent", "FAIL no_stale_iif_rule: a stale IPv4 'iif … unreachable' rule is loaded (17851: from all iif mra [detached] unreachable)"},
			forbidden: []string{"local-ok"}},
		{name: "stale LAN iif rule from an older install", mutate: func(h *verifyHost) {
			h.ip["-4 rule show"] = strings.Replace(h.ip["-4 rule show"], "32766:", "17850:\tfrom all iif eth0 unreachable\n32766:", 1)
			// What the kernel then answers for the paths out of eth0.
			exdev(h, "-4 route get ")
		}, wantCode: 1, want: []string{"FAIL no_stale_iif_rule: a stale IPv4 'iif … unreachable' rule is loaded (17850: from all iif eth0 unreachable)",
			"FAIL route_lan_domestic4: a LAN client (192.168.100.254) to a domestic destination (192.168.100.1, mark 0x64): ip -4 route get 192.168.100.1 from 192.168.100.254 iif eth0 mark 0x64 answered: RTNETLINK answers: Invalid cross-device link (source validation failed",
			"FAIL route_tunnel_reply4: a reply from 192.0.2.1 to the LAN client 192.168.100.254 does not resolve out of eth0 for: m02: RTNETLINK answers: Invalid cross-device link",
			"PASS route_lan_domestic6", "PASS route_tunnel_reply6", "PASS ros_neighbour"},
			forbidden: []string{"local-ok", "PASS route_lan_domestic4", "PASS route_tunnel_reply4"}},
		{name: "tunnel reply answered from the wrong interface", mutate: func(h *verifyHost) {
			h.ip["-4 route get 192.168.100.254 from 192.0.2.1 iif m03"] = "192.168.100.254 from 192.0.2.1 dev m02 uid 0\n"
		}, wantCode: 1, want: []string{"FAIL route_tunnel_reply4: a reply from 192.0.2.1 to the LAN client 192.168.100.254 does not resolve out of eth0 for: m03: 192.168.100.254 from 192.0.2.1 dev m02 uid 0 (not via eth0)"},
			forbidden: []string{"PASS route_tunnel_reply4"}},
		{name: "route probe resolves to a blackhole", mutate: func(h *verifyHost) {
			h.ip["-6 route get 2001:db8:ffff::1 from 2001:db8:100::fffe iif eth0 mark 0x64"] = "blackhole 2001:db8:ffff::1 from 2001:db8:100::fffe dev lo table meridian_domestic\n"
		}, wantCode: 1, want: []string{"FAIL route_lan_domestic6", "answered: blackhole 2001:db8:ffff::1"}, forbidden: []string{"PASS route_lan_domestic6"}},
		{name: "route probes without ip route get", mutate: func(h *verifyHost) {
			for k := range h.ip {
				if strings.Contains(k, " route get ") && strings.Contains(k, " iif ") {
					delete(h.ip, k)
				}
			}
		}, wantCode: 1, want: []string{"FAIL route_lan_domestic4", "not available (ip exited 1)", "FAIL route_tunnel_reply6"},
			forbidden: []string{"PASS route_"}},
		{name: "stock nftables.service enabled with a flush", mutate: func(h *verifyHost) {
			h.systemctl = map[string]string{"is-enabled nftables.service": "enabled\n"}
			h.files["etc/nftables.conf"] = "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n}\n"
		}, wantCode: 0, want: []string{"WARN nftables_service_flush: nftables.service is enabled", "local-ok"}},
		{name: "stock nftables.service enabled without a flush", mutate: func(h *verifyHost) {
			h.systemctl = map[string]string{"is-enabled nftables.service": "enabled\n"}
			h.files["etc/nftables.conf"] = "#!/usr/sbin/nft -f\n# flush ruleset\ntable inet filter {\n}\n"
		}, wantCode: 0, want: []string{"local-ok"}, forbidden: []string{"WARN"}},
		{name: "stock nftables.service disabled", mutate: func(h *verifyHost) {
			h.systemctl = map[string]string{}
			h.files["etc/nftables.conf"] = "flush ruleset\n"
		}, wantCode: 0, want: []string{"local-ok"}, forbidden: []string{"WARN"}},
		{name: "chnroute empty with a saved batch", mutate: func(h *verifyHost) {
			emptyChn(h)
			h.files["var/lib/meridian/lists/chnroute.nft"] = "flush set inet meridian chnroute\nadd element inet meridian chnroute { 1.0.1.0/24 }\n"
		}, wantCode: 1, want: []string{"FAIL chnroute_loaded: nft set chnroute is empty although the saved batch", "PASS chnroute6_loaded"}},
		{name: "chnroute never loaded", mutate: func(h *verifyHost) {
			emptyChn(h)
			delete(h.files, "var/lib/meridian/lists/status.json")
		}, wantCode: 1, want: []string{"FAIL chnroute_loaded: nft set chnroute is empty: no list update", "INFO lists: no "}},
		{name: "geosite cn empty", mutate: func(h *verifyHost) { h.files["var/lib/meridian/geosite/cn.txt"] = "" }, wantCode: 1,
			want: []string{"FAIL geosite_cn"}},
		{name: "early-boot guard differs", mutate: func(h *verifyHost) {
			h.files["etc/nftables.d/meridian-guard.nft"] = strings.Replace(h.files["etc/nftables.d/meridian-guard.nft"], "0x101-0x140", "0x101-0x120", 1)
		}, wantCode: 1, want: []string{"FAIL guard_boot_file: the early-boot guard differs"}},
		{name: "early-boot guard missing", mutate: func(h *verifyHost) { delete(h.files, "etc/nftables.d/meridian-guard.nft") }, wantCode: 1,
			want: []string{"FAIL guard_boot_file"}},
		{name: "no resolver on 53", mutate: func(h *verifyHost) { h.ss["-H -lnt"] = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" }, wantCode: 1,
			want: []string{"FAIL dns_listener"}},
		{name: "AAAA returned for a tunnelled name", mutate: func(h *verifyHost) { h.dig[digAAAAArgs] = digRealAAAA }, wantCode: 1,
			want: []string{"FAIL dns_aaaa_tunnelled: the resolver returned AAAA for www.google.com"}, forbidden: []string{"PASS dns_aaaa", "local-ok"}},
		{name: "AAAA query not answered", mutate: func(h *verifyHost) {
			h.dig[digAAAAArgs] = "ERR:;; communications error to 127.0.0.1#53: timed out\n"
		}, wantCode: 2, want: []string{"UNKNOWN dns_aaaa_tunnelled: dig @127.0.0.1 AAAA www.google.com got no answer"}, forbidden: []string{"PASS dns_aaaa", "local-ok"}},
		{name: "AAAA query SERVFAIL", mutate: func(h *verifyHost) {
			h.dig[digAAAAArgs] = strings.Replace(digEmptyAAAA, "status: NOERROR", "status: SERVFAIL", 1)
		}, wantCode: 2, want: []string{"UNKNOWN dns_aaaa_tunnelled: the resolver did not answer"}, forbidden: []string{"PASS dns_aaaa"}},
		{name: "dig not installed", mutate: func(h *verifyHost) { h.dig = nil }, wantCode: 2,
			want: []string{"UNKNOWN dns_aaaa_tunnelled: dig not found"}, forbidden: []string{"PASS dns_aaaa"}},
		{name: "AAAA test name is domestic", mutate: func(h *verifyHost) {
			// The derived domestic list SmartDNS loads (names a rule matches are removed).
			h.files["var/lib/meridian/geosite/ordered/gs_cn.txt"] += "google.com\n"
		}, wantCode: 2, want: []string{"UNKNOWN dns_aaaa_tunnelled: the test name www.google.com is a domestic name (google.com in "}, forbidden: []string{"PASS dns_aaaa"}},
		{name: "AAAA test name from the environment", mutate: func(h *verifyHost) {
			h.env = []string{"MERIDIAN_VERIFY_AAAA_NAME=www.example.net"}
			h.dig["+time=3 +tries=1 @127.0.0.1 AAAA www.example.net"] = strings.ReplaceAll(digEmptyAAAA, "www.google.com", "www.example.net")
		}, wantCode: 0, want: []string{"PASS dns_aaaa_tunnelled: AAAA for www.example.net is empty", "local-ok"}},
		{name: "AAAA test name refused", mutate: func(h *verifyHost) { h.env = []string{"MERIDIAN_VERIFY_AAAA_NAME=-x;rm"} }, wantCode: 1,
			want: []string{"FAIL dns_aaaa_tunnelled: MERIDIAN_VERIFY_AAAA_NAME refused"}},
		{name: "group resolver SNAT missing", mutate: func(h *verifyHost) {
			h.nft["list table inet meridian"] = dropLines(h.nft["list table inet meridian"], "ip6 daddr fd66::53:13 ")
		}, wantCode: 1, want: []string{"FAIL group_dns_snat: no resolver SNAT loaded for group(s): us (evidence nft-meridian.txt)", "PASS group_dns_upstream", "PASS group_dns_route"},
			forbidden: []string{"PASS group_dns_snat"}},
		{name: "group resolver mark in hex", mutate: func(h *verifyHost) {
			h.files["etc/smartdns/smartdns.conf"] = strings.Replace(h.files["etc/smartdns/smartdns.conf"], "-set-mark 275", "-set-mark 0x113", 1)
		}, wantCode: 1, want: []string{"FAIL group_dns_upstream", "applies no mark"}, forbidden: []string{"PASS group_dns_upstream"}},
		{name: "group resolver upstream missing", mutate: func(h *verifyHost) {
			h.files["etc/smartdns/smartdns.conf"] = dropLines(h.files["etc/smartdns/smartdns.conf"], "-group rg_jp ")
		}, wantCode: 1, want: []string{"FAIL group_dns_upstream: ", "/etc/smartdns/smartdns.conf has no marked resolver upstream for group(s): jp"}},
		{name: "smartdns config unreadable", mutate: func(h *verifyHost) { delete(h.files, "etc/smartdns/smartdns.conf") }, wantCode: 2,
			want: []string{"UNKNOWN group_dns_upstream"}, forbidden: []string{"PASS group_dns_upstream", "local-ok"}},
		{name: "group resolver routed out of the LAN port", mutate: func(h *verifyHost) {
			h.ip["-6 route get fd66::53:13 mark 0x113"] = "fd66::53:13 from :: via fe80::1 dev eth0 proto ra metric 1024 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL group_dns_route: a marked lookup of a group resolver address does not enter a tunnel: us: fd66::53:13 from :: via fe80::1 dev eth0"},
			forbidden: []string{"PASS group_dns_route"}},
		{name: "group resolver unreachable", mutate: func(h *verifyHost) {
			h.ip["-6 route get fd66::53:d mark 0x10d"] = "ERR:RTNETLINK answers: Network is unreachable\n"
		}, wantCode: 1, want: []string{"FAIL group_dns_route", "hk: RTNETLINK answers: Network is unreachable"}},
	})
}

// TestVerifyScriptRemoteAccess: with remote access on, the script checks
// mra, its peers (public keys only), the guard ingress, DNS, the port, the
// rule, the pool routes and the NAT from what the host reports, and adds
// the phone/router/IPv6 items as PENDING-HUMAN.
func TestVerifyScriptRemoteAccess(t *testing.T) {
	topo, privs := raExample(t)
	b := mustCompile(t, topo)
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	for _, p := range privs {
		if strings.Contains(script, p) {
			t.Fatal("a private key is in the verify script")
		}
	}
	if strings.Contains(script, topo.RemoteAccess.Devices[2].PublicKey) {
		t.Fatal("the disabled device's key is expected as a peer")
	}
	base := func() verifyHost { return goodHost(t, b, topo) }
	offB := mustCompile(t, defaults.Example())
	offNft := offB.File("nodes/gw/etc/nftables.d/meridian.nft")
	offGuard := offNft[strings.Index(offNft, "table inet meridian_guard {"):strings.Index(offNft, "table inet meridian\ndelete")]
	runVerifyCases(t, script, base, []verifyCase{
		{name: "all local checks pass", wantCode: 0,
			want: []string{"meridian-verify-local-ok", "PASS remote_iface", "PASS no_stale_iif_rule", "PASS remote_pool_routes",
				"PASS route_remote_domestic4: a device (10.67.0.2) to a domestic destination (192.168.100.1, mark 0x64) resolves out of eth0",
				"PASS route_remote_reply4: a domestic reply (192.168.100.1, mark 0x64) to a device (10.67.0.2) resolves out of mra",
				"PASS route_remote_domestic6", "PASS route_remote_reply6", "PASS route_tunnel_reply_device4", "PASS route_tunnel_reply_device6",
				"PASS route_lan_domestic4", "PASS route_tunnel_reply4",
				"PASS guard_ingress: the guard's ingress is { eth0, mra }", "PASS remote_dns", "PASS remote_port_lan_only",
				"PASS remote_nat: device pools have a transit SNAT for each of the 22 marks", "PASS remote_listen: mra listens on UDP 51900",
				"PASS remote_peers: mra has exactly the 2 enabled devices", "PASS chnroute6_loaded",
				"PENDING-HUMAN remote_phone_full", "PENDING-HUMAN remote_phone_home", "PENDING-HUMAN remote_router_forward", "PENDING-HUMAN remote_ipv6"},
			forbidden: []string{"FAIL", "UNKNOWN", "remote_absent"}},
		{name: "a disabled device is still a peer", mutate: func(h *verifyHost) {
			h.wg["show mra peers"] += topo.RemoteAccess.Devices[2].PublicKey + "\n"
		}, wantCode: 1, want: []string{"FAIL remote_peers: mra peers differ from the enabled devices: 1 unexpected"},
			forbidden: []string{topo.RemoteAccess.Devices[2].PublicKey}},
		{name: "an enabled device is missing", mutate: func(h *verifyHost) {
			h.wg["show mra peers"] = topo.RemoteAccess.Devices[0].PublicKey + "\n"
		}, wantCode: 1, want: []string{"FAIL remote_peers: mra peers differ from the enabled devices: missing dev-bbbb; 0 unexpected"}},
		{name: "mra missing", mutate: func(h *verifyHost) {
			delete(h.ip, "link show dev mra")
			h.wg = map[string]string{}
		}, wantCode: 1, want: []string{"FAIL remote_iface", "FAIL remote_listen", "FAIL remote_peers"}},
		{name: "wrong listen port", mutate: func(h *verifyHost) { h.wg["show mra listen-port"] = "51820\n" }, wantCode: 1,
			want: []string{"FAIL remote_listen"}},
		{name: "wg not installed", mutate: func(h *verifyHost) { h.wg = nil }, wantCode: 1,
			want: []string{"FAIL remote_wg"}, forbidden: []string{"PASS remote_listen", "PASS remote_peers"}},
		{name: "guard without mra", mutate: func(h *verifyHost) { h.nft["list table inet meridian_guard"] = nftListing(offGuard) }, wantCode: 1,
			want: []string{"FAIL guard_ingress: remote access is on but the guard does not treat mra like eth0"}},
		{name: "main table without the remote rules", mutate: func(h *verifyHost) {
			h.nft["list table inet meridian"] = nftListing(offNft[strings.Index(offNft, "table inet meridian {"):])
		}, wantCode: 1, want: []string{"FAIL remote_dns", "FAIL remote_port_lan_only", "FAIL remote_nat: device-pool NAT incomplete: 0/22 v4"}},
		{name: "pool route gone", mutate: func(h *verifyHost) {
			h.ip["-6 route show table 100"] = "default via fe80::1 dev eth0 metric 1024 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL remote_pool_routes"}},
		{name: "stale iif mra rule while remote access is on", mutate: func(h *verifyHost) {
			h.ip["-4 rule show"] = strings.Replace(h.ip["-4 rule show"], "32766:", "17851:\tfrom all iif mra unreachable\n32766:", 1)
			exdev(h, "-4 route get 10.67.0.2 from")
		}, wantCode: 1, want: []string{"FAIL no_stale_iif_rule: a stale IPv4 'iif … unreachable' rule is loaded (17851: from all iif mra unreachable)",
			"FAIL route_remote_reply4: a domestic reply (192.168.100.1, mark 0x64) to a device (10.67.0.2): ip -4 route get 10.67.0.2 from 192.168.100.1 iif eth0 mark 0x64 answered: RTNETLINK answers: Invalid cross-device link",
			"FAIL route_tunnel_reply_device4", "PASS route_remote_domestic4", "PASS route_remote_reply6"},
			forbidden: []string{"local-ok", "PASS route_remote_reply4"}},
		{name: "device to domestic rejected by source validation", mutate: func(h *verifyHost) {
			exdev(h, "from 10.67.0.2 iif mra")
		}, wantCode: 1, want: []string{"FAIL route_remote_domestic4", "Invalid cross-device link", "PASS no_stale_iif_rule"},
			forbidden: []string{"PASS route_remote_domestic4"}},
	})
}

// TestVerifyScriptULALAN: with a ULA LAN prefix the loaded classifier must
// mark exactly that prefix ahead of the ULA drop, its on-link routes on the
// LAN NIC are not a ULA leak, and any other ULA route on the LAN NIC, any
// ULA route via ROS, a missing LAN rule or a wider rule ahead of the drop
// still fails. With a global prefix a rule ahead of the drop fails too.
func TestVerifyScriptULALAN(t *testing.T) {
	topo := ulaLANExample(t)
	b := mustCompile(t, topo)
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	for _, need := range []string{"lan6_ula='" + ulaLAN + "'", "lan6_ula_hex='fd123456789a00010000000000000000'", "lan6_ula_bits=64"} {
		if !strings.Contains(script, need) {
			t.Fatalf("verify script lacks %q", need)
		}
	}
	lanRule := `ip6 daddr ` + ulaLAN + ` meta mark set 0x00000064 return comment "ULA LAN prefix: home hosts only"`
	base := func() verifyHost {
		h := goodHost(t, b, topo)
		if !strings.Contains(h.nft["list table inet meridian"], lanRule) {
			t.Fatalf("listing lacks %q", lanRule)
		}
		// What the kernel lists for an on-link ULA LAN prefix.
		h.ip["-6 route show table all"] += ulaLAN + " dev eth0 proto kernel metric 256 pref medium\n" +
			ulaLAN + " dev eth0 table meridian_domestic metric 1024 pref medium\n" +
			ulaLAN + " dev eth0 table meridian_foreign metric 1024 pref medium\n" +
			"local fd12:3456:789a:1::88 dev eth0 table local proto kernel metric 0 pref medium\n" +
			"anycast fd12:3456:789a:1:: dev eth0 table local proto kernel metric 0 pref medium\n" +
			"blackhole " + ulaLAN + " dev lo metric 32767 pref medium\n"
		return h
	}
	replaceNft := func(old, new string) func(h *verifyHost) {
		return func(h *verifyHost) {
			s := h.nft["list table inet meridian"]
			if !strings.Contains(s, old) {
				t.Fatalf("listing lacks %q", old)
			}
			h.nft["list table inet meridian"] = strings.Replace(s, old, new, 1)
		}
	}
	runVerifyCases(t, script, base, []verifyCase{
		{name: "all local checks pass", wantCode: 0,
			want: []string{"meridian-verify-local-ok",
				"PASS ula_drop: forwarded ULA is dropped, except the ULA LAN prefix " + ulaLAN,
				"PASS ula_not_via_ros: no ULA route in any table points at ROS, and none outside the LAN prefix " + ulaLAN + " uses eth0",
				"PASS route_lan_domestic6: a LAN client (fd12:3456:789a:1::fffe)", "PASS route_remote_domestic6"},
			forbidden: []string{"FAIL", "UNKNOWN"}},
		{name: "another ULA on the LAN NIC", mutate: func(h *verifyHost) {
			h.ip["-6 route show table all"] += "fd12:3456:789a:2::/64 dev eth0 metric 1024 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL ula_not_via_ros: a ULA route leaves via eth0"}},
		{name: "a wider ULA route containing the LAN prefix", mutate: func(h *verifyHost) {
			h.ip["-6 route show table all"] += "fd12:3456:789a::/48 dev eth0 metric 1024 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL ula_not_via_ros: a ULA route leaves via eth0"}},
		{name: "tunnel ULA on the LAN NIC", mutate: func(h *verifyHost) {
			h.ip["-6 route show table all"] += "fd66::/48 dev eth0 metric 1024 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL ula_not_via_ros: a ULA route leaves via eth0"}},
		{name: "LAN prefix pointed at ROS", mutate: func(h *verifyHost) {
			h.ip["-6 route show table all"] += ulaLAN + " via fe80::1 dev eth0 table meridian_domestic metric 1 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL ula_not_via_ros: a ULA route points at ROS fe80::1"}},
		{name: "LAN rule missing from the loaded classifier", mutate: replaceNft(lanRule+"\n", ""), wantCode: 1,
			want:      []string{"FAIL ula_drop: the ULA LAN prefix " + ulaLAN + " is not classified ahead of the fc00::/7 drop"},
			forbidden: []string{"PASS ula_drop"}},
		{name: "wider rule ahead of the drop", mutate: replaceNft(lanRule, strings.Replace(lanRule, ulaLAN, "fd12:3456:789a::/48", 1)), wantCode: 1,
			want:      []string{"FAIL ula_drop: an IPv6 rule ahead of the fc00::/7 drop lets other addresses past it: ip6 daddr fd12:3456:789a::/48"},
			forbidden: []string{"PASS ula_drop"}},
		{name: "drop missing", mutate: replaceNft("ip6 daddr fc00::/7 drop", "ip6 daddr fc00::/7 counter"), wantCode: 1,
			want: []string{"FAIL ula_drop: no fc00::/7 drop in the classify chain"}},
	})

	gtopo, _ := raExample(t)
	gb := mustCompile(t, gtopo)
	gscript := gb.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	if !strings.Contains(gscript, "lan6_ula=''") {
		t.Fatal("a global LAN prefix must leave lan6_ula empty")
	}
	runVerifyCases(t, gscript, func() verifyHost { return goodHost(t, gb, gtopo) }, []verifyCase{
		{name: "global: all local checks pass", wantCode: 0,
			want: []string{"PASS ula_drop: forwarded ULA is dropped", "PASS ula_not_via_ros: no ULA route in any table uses eth0 or ROS"}, forbidden: []string{"FAIL", "except the ULA LAN"}},
		{name: "global: a ULA rule ahead of the drop", mutate: func(h *verifyHost) {
			h.nft["list table inet meridian"] = strings.Replace(h.nft["list table inet meridian"], "ip6 daddr fc00::/7 drop",
				"ip6 daddr fd12:3456:789a:1::/64 meta mark set 0x00000064 return\n    ip6 daddr fc00::/7 drop", 1)
		}, wantCode: 1, want: []string{"FAIL ula_drop: an IPv6 rule ahead of the fc00::/7 drop lets other addresses past it: ip6 daddr fd12:3456:789a:1::/64"}},
		{name: "global: a ULA LAN-looking route on eth0 still fails", mutate: func(h *verifyHost) {
			h.ip["-6 route show table all"] += ulaLAN + " dev eth0 metric 1024 pref medium\n"
		}, wantCode: 1, want: []string{"FAIL ula_not_via_ros: a ULA route leaves via eth0"}},
	})
}

// Both netns tests are named on the NOT-RUN-HERE line.
func TestVerifyScriptNamesBothNetnsTests(t *testing.T) {
	b := mustCompile(t, defaults.Example())
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	for _, l := range strings.Split(script, "\n") {
		if strings.HasPrefix(l, "notrun netns_reload_no_leak ") {
			if !strings.Contains(l, "TestNetnsReloadNoLeak") || !strings.Contains(l, "TestNetnsULALANHomeAccess") {
				t.Fatalf("line names only one test: %s", l)
			}
			return
		}
	}
	t.Fatal("no notrun netns_reload_no_leak line")
}

// TestVerifyScriptResolverSettings: with clients_ipv6_via_gateway on the
// AAAA check is information only (nothing is queried, nothing passes); with
// unlisted_domestic_dns on the China lists the resolver loads must be
// non-empty, and the DNS leak item states the changed guarantee instead of
// the strict one.
func TestVerifyScriptResolverSettings(t *testing.T) {
	topo := defaults.Example()
	topo.Settings.ClientsIPv6ViaGateway = true
	topo.Settings.UnlistedDomesticDNS = true
	b := mustCompile(t, topo)
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	base := func() verifyHost {
		h := goodHost(t, b, topo)
		h.dig = nil
		h.files["var/lib/meridian/lists/china.txt"] = "1.0.1.0/24\n1.0.2.0/23\n"
		h.files["var/lib/meridian/lists/china6.txt"] = "2400:3200::/32\n"
		h.systemctl = map[string]string{"is-active meridian-dns-split.service": "active\n"}
		return h
	}
	runVerifyCases(t, script, base, []verifyCase{
		{name: "both on", wantCode: 0,
			want: []string{"INFO dns_aaaa_tunnelled: clients_ipv6_via_gateway is on", "PASS unlisted_domestic_lists", "PASS dns_split_active",
				"INFO unlisted_domestic_dns: on: the domestic resolvers see every unlisted name",
				"PENDING-HUMAN dns_leak_client", "the leak sites list the domestic resolvers next to the exit's", "local-ok"},
			forbidden: []string{"PASS dns_aaaa", "UNKNOWN", "FAIL", "with no 53/853 from it;"}},
		{name: "china6 list empty", mutate: func(h *verifyHost) { h.files["var/lib/meridian/lists/china6.txt"] = "" }, wantCode: 1,
			want: []string{"FAIL unlisted_domestic_lists: missing or empty: ", "china6.txt"}, forbidden: []string{"PASS unlisted_domestic_lists", "local-ok"}},
		{name: "dns-split not running", mutate: func(h *verifyHost) { h.systemctl = map[string]string{} }, wantCode: 1,
			want: []string{"FAIL dns_split_active: meridian-dns-split.service is not active"}, forbidden: []string{"PASS dns_split_active", "local-ok"}},
		{name: "no systemctl", mutate: func(h *verifyHost) { h.systemctl = nil }, wantCode: 2,
			want: []string{"UNKNOWN dns_split_active"}, forbidden: []string{"PASS dns_split_active"}},
		{name: "china list missing", mutate: func(h *verifyHost) { delete(h.files, "var/lib/meridian/lists/china.txt") }, wantCode: 1,
			want: []string{"FAIL unlisted_domestic_lists", "china.txt"}},
	})
	// Off (the default): no unlisted-domain check, the strict leak text.
	off := mustCompile(t, defaults.Example()).File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	if !strings.Contains(off, "unlisted_dns=0\n") || !strings.Contains(off, "clients_v6=0\n") {
		t.Fatal("defaults do not compile both settings off")
	}
}
