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
	ssh    string
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
	return h
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
	for name, m := range map[string]map[string]string{"ip": h.ip, "nft": h.nft, "wg": h.wg, "ss": h.ss} {
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
			for _, never := range []string{"PASS dns_leak", "PASS webrtc", "PASS redirect_on_wire", "PASS tunnel_cut", "PASS remote_phone", "PASS remote_router", "PASS remote_ipv6", "PASS netns", "meridian-verify-ok"} {
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
				"PASS policy_marks: all 22 compiled", "PASS lan_iif_unreachable", "PASS fallback_blackholes", "PASS remote_absent",
				"PASS guard_mark_range", "PASS guard_ingress: the guard's ingress is eth0 only", "PASS chnroute_loaded", "PASS chnroute6_loaded",
				"PASS guard_boot_file", "PASS geosite_cn", "PASS dns_listener",
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
			want: []string{"FAIL policy_marks: ip rule show failed"}, forbidden: []string{"PASS lan_iif_unreachable"}},
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
		}, wantCode: 0, want: []string{"PASS remote_absent", "INFO remote_leftover", "local-ok"}},
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
			want: []string{"meridian-verify-local-ok", "PASS remote_iface", "PASS remote_iif_unreachable", "PASS remote_pool_routes",
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
		{name: "no iif mra rule", mutate: func(h *verifyHost) {
			h.ip["-4 rule show"] = strings.Replace(h.ip["-4 rule show"], "iif mra unreachable", "iif mra lookup main", 1)
		}, wantCode: 1, want: []string{"FAIL remote_iif_unreachable"}},
	})
}
