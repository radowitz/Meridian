package preflight

import (
	"strings"
	"testing"
)

// S1: Docker FORWARD DROP coexistence (iptables-nft and legacy, IPv4-only
// DROP, missing DOCKER-USER, ufw / firewalld, a DROP before the jump,
// another nft table's drop, the gateway), nftables flush refusal, WARP
// recognition and collisions, the sysctl preview, and an own update with
// the coexistence rules already in place.

// dockerUserNft is Debian 12 with Docker (iptables-nft): IPv4 FORWARD DROP
// with DOCKER-USER jumped to first; IPv6 FORWARD ACCEPT, as on the
// operator's real hosts.
func dockerUserNft(t *testing.T, fp Footprint, extra string) Report {
	t.Helper()
	raw := string(mustRead(t, "testdata/docker-forward-drop.txt"))
	raw = strings.Replace(raw, "ipt ipv6 -P FORWARD DROP\n", "ipt ipv6 -P FORWARD ACCEPT\n", 1)
	raw = strings.Replace(raw, "nft table ip6 filter {\nnft chain FORWARD {\nnft type filter hook forward priority filter; policy drop;\n", "nft table ip6 filter {\n", 1)
	raw = strings.Replace(raw, "@PATHS@\n", "iptchain ipv4 DOCKER-USER yes\niptfwd ipv4 1 DOCKER-USER plain\niptfwd ipv4 2 DOCKER-FORWARD plain\niptours ipv4 0\niptchain ipv6 DOCKER-USER no\niptours ipv6 0\n"+extra+"@PATHS@\n", 1)
	return parseWithPaths(t, raw, fp, nil)
}

func fwChanges(ev Evaluation) []Change {
	var out []Change
	for _, c := range ev.Changes {
		if c.Kind == "firewall" {
			out = append(out, c)
		}
	}
	return out
}

func TestDockerUserCoexistenceIptablesNft(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	if len(fp.FWRules) != 2 || fp.FWChain != "DOCKER-USER" || !strings.HasPrefix(fp.FWTag, "meridian-fw-") {
		t.Fatalf("footprint %v %q %q", fp.FWRules, fp.FWChain, fp.FWTag)
	}
	ev := Evaluate(dockerUserNft(t, fp, ""), fp, remote("hk-resi"))
	checkShape(t, ev)
	if ev.Blocking {
		t.Fatalf("Docker's IPv4 FORWARD DROP with DOCKER-USER blocked: %v %+v", codes(ev, Blocking), find(ev, CodeForwardDrop))
	}
	fd := find(ev, CodeForwardDrop)
	if len(fd) != 1 || fd[0].Severity != Warning || fd[0].Resource != "ipv4 FORWARD" || !strings.Contains(fd[0].Message, fp.FWTag) ||
		!strings.Contains(fd[0].Message, "不改 Docker 的链和规则") {
		t.Fatalf("IPv4-only drop: %+v", fd)
	}
	ch := fwChanges(ev)
	if len(ch) != len(fp.FWRules) {
		t.Fatalf("planned rules %+v", ch)
	}
	for i, c := range ch {
		want := "iptables -I DOCKER-USER " + fp.FWRules[i] + " -m comment --comment " + fp.FWTag + " -j ACCEPT"
		if c.Action != "add" || c.Resource != want {
			t.Fatalf("change %d: %+v, want %s", i, c, want)
		}
	}
	sum := find(ev, CodeFWCompat)
	if len(sum) != 1 || !strings.Contains(sum[0].Message, "ipv6：FORWARD 策略 ACCEPT，不加规则") || !strings.Contains(sum[0].Message, "ipv4：FORWARD 策略 DROP") {
		t.Fatalf("summary %+v", sum)
	}
	// Both families DROP, each with DOCKER-USER: two warnings, rules for
	// iptables and ip6tables.
	raw := string(mustRead(t, "testdata/docker-forward-drop.txt"))
	raw = strings.Replace(raw, "@PATHS@\n", "iptchain ipv4 DOCKER-USER yes\niptfwd ipv4 1 DOCKER-USER plain\niptchain ipv6 DOCKER-USER yes\niptfwd ipv6 1 DOCKER-USER plain\n@PATHS@\n", 1)
	ev = Evaluate(parseWithPaths(t, raw, fp, nil), fp, remote("hk-resi"))
	if ev.Blocking || len(find(ev, CodeForwardDrop)) != 2 || len(fwChanges(ev)) != 2*len(fp.FWRules) || !strings.HasPrefix(fwChanges(ev)[len(fp.FWRules)].Resource, "ip6tables -I DOCKER-USER") {
		t.Fatalf("dual-family: %v %+v", codes(ev, Blocking), fwChanges(ev))
	}
	// IPv6 DROP without an ip6 DOCKER-USER: IPv4 is handled, IPv6 refuses.
	raw = string(mustRead(t, "testdata/docker-forward-drop.txt"))
	raw = strings.Replace(raw, "@PATHS@\n", "iptchain ipv4 DOCKER-USER yes\niptfwd ipv4 1 DOCKER-USER plain\niptchain ipv6 DOCKER-USER no\n@PATHS@\n", 1)
	ev = Evaluate(parseWithPaths(t, raw, fp, nil), fp, remote("hk-resi"))
	if fb := find(ev, CodeForwardDrop); len(fb) != 2 || !ev.Blocking || fb[0].Resource != "ipv6 FORWARD" || fb[0].Severity != Blocking || !strings.Contains(fb[0].Message, "没有 DOCKER-USER 链") {
		t.Fatalf("v6 without chain: %+v", fb)
	}
}

func TestDockerUserCoexistenceLegacy(t *testing.T) {
	fp := FootprintOf(filesWAN(t, "hk-resi", "enp0s6"))
	raw := strings.Replace(string(mustRead(t, "testdata/ubuntu2004-arm64.txt")), "@PATHS@\n", "iptchain ipv4 DOCKER-USER yes\niptfwd ipv4 1 DOCKER-USER plain\niptfwd ipv4 2 DOCKER-ISOLATION-STAGE-1 plain\niptchain ipv6 DOCKER-USER no\n@PATHS@\n", 1)
	ev := Evaluate(parseWithPaths(t, raw, fp, nil), fp, remote("hk-resi"))
	checkShape(t, ev)
	if ev.Blocking {
		t.Fatalf("legacy Docker host blocked: %v", codes(ev, Blocking))
	}
	if fd := find(ev, CodeForwardDrop); len(fd) != 1 || fd[0].Severity != Warning || len(fwChanges(ev)) != len(fp.FWRules) || !strings.HasPrefix(fwChanges(ev)[0].Resource, "iptables -I DOCKER-USER") {
		t.Fatalf("legacy: %+v %+v", fd, fwChanges(ev))
	}
	// The legacy backend statement and the nftables package install stay.
	if !has(ev, Info, CodeIptablesLegacy) || !has(ev, Info, CodeNetfilterPersis) || !strings.Contains(find(ev, CodeNetfilterPersis)[0].Message, "netfilter-persistent save") {
		t.Fatalf("legacy findings %v", codes(ev, ""))
	}
}

// Everything that keeps the DROP refusing, each with its reason.
func TestDockerUserCoexistenceRefusals(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	for name, c := range map[string]struct {
		extra, why string
		edit       func(*Report)
	}{
		"missing DOCKER-USER": {"", "没有 DOCKER-USER 链", func(r *Report) { r.IptChains["ipv4 DOCKER-USER"] = false }},
		"not reported":        {"", "预检没有报告 DOCKER-USER", func(r *Report) { delete(r.IptChains, "ipv4 DOCKER-USER") }},
		"ufw active":          {"unit ufw.service active enabled 1\n", "ufw 在运行", nil},
		"firewalld active":    {"unit firewalld.service active enabled 1\n", "firewalld 在运行", nil},
		"drop before jump":    {"", "跳到 DOCKER-USER 之前就有 DROP", func(r *Report) { r.IptForward["ipv4"] = []string{"DROP", "DOCKER-USER"} }},
		"no jump":             {"", "FORWARD 链不跳到 DOCKER-USER", func(r *Report) { r.IptForward["ipv4"] = []string{"DOCKER-FORWARD"} }},
		"other nft table": {"", "丢弃来自别的 nft 表", func(r *Report) {
			r.Chains = append(r.Chains, Chain{Table: "inet filter", Name: "forward", Type: "filter", Hook: "forward", Priority: "0", Policy: "drop"})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := dockerUserNft(t, fp, c.extra)
			if c.edit != nil {
				c.edit(&r)
			}
			ev := Evaluate(r, fp, remote("hk-resi"))
			checkShape(t, ev)
			fd := find(ev, CodeForwardDrop)
			// An inet table's drop hits both families.
			want := 1
			if name == "other nft table" {
				want = 2
			}
			if len(fd) != want || len(fwChanges(ev)) != 0 {
				t.Fatalf("%s: %+v changes %+v", name, fd, fwChanges(ev))
			}
			for _, f := range fd {
				if f.Severity != Blocking || !strings.Contains(f.Message, c.why) {
					t.Fatalf("%s: %+v", name, f)
				}
			}
		})
	}
	// The gateway never uses the coexistence rules.
	gfp := FootprintOf(nodeFiles(t, "gw"))
	if len(gfp.FWRules) != 0 {
		t.Fatal("gateway footprint has coexistence rules")
	}
	ev := Evaluate(dockerUserNft(t, gfp, ""), gfp, Context{Artifacts: testArts, NodeID: "gw", Gateway: true})
	if fd := find(ev, CodeForwardDrop); len(fd) != 1 || fd[0].Severity != Blocking || !strings.Contains(fd[0].Message, "网关不使用这套共存规则") {
		t.Fatalf("gateway: %+v", fd)
	}
}

// An update of our own install on a Docker host with our rules already
// in DOCKER-USER: not blocking, the rules are an update.
func TestDockerUserOwnUpdateNotBlocked(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	r := dockerUserNft(t, fp, installedByUs(fp, "hk-resi", "dep-test")+"cmd smartdns yes\n")
	r.IptOurs["ipv4"] = len(fp.FWRules)
	for p := range allPresent(fp) {
		r.Paths[p] = PathInfo{Exists: true, Type: "file", Size: 10, Marker: true, SHA256: strings.Repeat("c", 64)}
	}
	ev := Evaluate(r, fp, remote("hk-resi"))
	checkShape(t, ev)
	if ev.Ownership != OwnSame || ev.Blocking {
		t.Fatalf("own update blocked: %s %v", ev.Ownership, codes(ev, Blocking))
	}
	ch := fwChanges(ev)
	if len(ch) != len(fp.FWRules) || ch[0].Action != "update" || !strings.Contains(find(ev, CodeForwardDrop)[0].Message, "已有 2 条带 Meridian 注释的规则") {
		t.Fatalf("update plan %+v", ch)
	}
	for _, u := range []string{"meridian-node.service", "meridian-fwcompat.service"} {
		if !containsStr(fp.Units, u) {
			t.Fatalf("footprint lacks %s: %v", u, fp.Units)
		}
	}
}

// nftables.service that would flush the whole ruleset blocks before
// anything changes (remote node and gateway); the distribution default
// (disabled, not running) is not reported.
func TestNFTFlushBlocks(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	for name, c := range map[string]struct {
		extra string
		sev   string
		why   string
	}{
		"enabled + flush config":    {"unit nftables.service inactive enabled 0\n", Blocking, "flush ruleset：reload"},
		"active + ExecStop flush":   {"unit nftables.service active disabled 0\nnftables-conf noflush\nnftables-stop flush\n", Blocking, "ExecStop 是 nft flush ruleset"},
		"enabled, nothing flushes":  {"unit nftables.service active enabled 0\nnftables-conf noflush\nnftables-stop noflush\n", "", ""},
		"disabled, not running":     {"unit nftables.service inactive disabled 0\nnftables-stop flush\n", "", ""},
		"masked":                    {"unit nftables.service inactive masked 0\nnftables-stop flush\n", "", ""},
		"not installed (not-found)": {"unit nftables.service inactive not-found 0\n", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			ev := Evaluate(fixture(t, "clean-debian13.txt", fp, nil, c.extra), fp, remote("hk-resi"))
			checkShape(t, ev)
			f := find(ev, CodeNFTFlush)
			if c.sev == "" {
				if len(f) != 0 {
					t.Fatalf("%s: unexpected %+v", name, f)
				}
				return
			}
			if len(f) != 1 || f[0].Severity != c.sev || !strings.Contains(f[0].Message, c.why) || !strings.Contains(f[0].Action, "systemctl disable nftables.service") ||
				!strings.Contains(f[0].Action, "不要执行 systemctl stop nftables") || !strings.Contains(f[0].Action, "ExecStop=") {
				t.Fatalf("%s: %+v", name, f)
			}
		})
	}
	gfp := FootprintOf(nodeFiles(t, "gw"))
	ev := Evaluate(fixture(t, "clean-debian13.txt", gfp, nil, "unit nftables.service active enabled 0\n"), gfp, Context{Artifacts: testArts, NodeID: "gw", Gateway: true})
	if f := find(ev, CodeNFTFlush); len(f) != 1 || f[0].Severity != Blocking || !strings.Contains(f[0].Message, "inet meridian_guard") {
		t.Fatalf("gateway flush: %+v", f)
	}
}

// WARP: recognised with its rule, table mode and dependency clues; no
// collision with Meridian is informational; a collision blocks; a bundle
// with the Mesh sidecar on a WARP host gets the sidecar warning.
func TestWARPRecognition(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	extra := "warpdep conn 127.0.0.1:40000 xray\nwarpdep resolv 127.0.2.2\naddr CloudflareWARP 2606:4700:cf1:1::12/128\n"
	ev := Evaluate(fixture(t, "warp.txt", fp, nil, extra), fp, remote("hk-resi"))
	checkShape(t, ev)
	w := find(ev, CodeWARP)
	if len(w) != 1 || w[0].Severity != Info {
		t.Fatalf("warp %+v", w)
	}
	for _, s := range []string{"优先级 32765", "表 65743 有默认路由", "127.0.0.1:40000 xray", "resolv 127.0.2.2", "2606:4700:cf1:1::12/128", "只绑定受管隧道地址", "不冲突", "不会停用它"} {
		if !strings.Contains(w[0].Message, s) {
			t.Fatalf("warp message lacks %q: %s", s, w[0].Message)
		}
	}
	if has(ev, "", CodeWARPSidecar) {
		t.Fatal("no Mesh sidecar in this bundle")
	}
	// The resolver binds tunnel addresses only, never WARP's 53.
	if has(ev, "", CodeResolverBind) || has(ev, "", CodePortInUse) {
		t.Fatalf("resolver vs WARP listeners: %v", codes(ev, ""))
	}
	// A Meridian rule at WARP's priority collides: blocking.
	hub := FootprintOf(nodeFiles(t, "hk-hub"))
	if len(hub.Rules) == 0 || !hub.Mesh {
		t.Fatal("hub has no rules or no Mesh sidecar")
	}
	prio := itoa(hub.Rules[0].Priority)
	raw := strings.Replace(string(mustRead(t, "testdata/warp.txt")), "rule4 32765:\tnot from all fwmark 0x100cf lookup 65743", "rule"+itoa(hub.Rules[0].Family)+" "+prio+":\tnot from all fwmark 0x100cf lookup 65743", 1)
	ev = Evaluate(parseWithPaths(t, raw, hub, nil), hub, remote("hk-hub"))
	if w := find(ev, CodeWARP); len(w) != 1 || w[0].Severity != Blocking || !strings.Contains(w[0].Message, "Meridian 也用优先级 "+prio) {
		t.Fatalf("collision %+v", w)
	}
	// Mesh sidecar files next to a host WARP client: the sidecar warning.
	ev = Evaluate(parseWithPaths(t, string(mustRead(t, "testdata/warp.txt")), hub, nil), hub, remote("hk-hub"))
	if s := find(ev, CodeWARPSidecar); len(s) != 1 || s[0].Severity != Warning || !strings.Contains(s[0].Message, "host_warp") {
		t.Fatalf("sidecar %+v", s)
	}
}

// The sysctl preview lists each global key and the interface list; it
// never says "every interface".
func TestSysctlPreview(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "sysctl net.ipv4.conf.all.send_redirects 1\n"), fp, remote("hk-resi"))
	var sys []Change
	for _, c := range ev.Changes {
		if c.Kind == "sysctl" {
			sys = append(sys, c)
		}
	}
	got := map[string]string{}
	for _, c := range sys {
		got[c.Resource] = c.Detail
		if strings.Contains(c.Detail, "所有接口") && !strings.Contains(c.Detail, "影响所有接口") {
			t.Fatalf("every-interface change %+v", c)
		}
	}
	if d := got["net.ipv4.conf.all.send_redirects"]; !strings.Contains(d, "全局") || !strings.Contains(d, "当前 1") {
		t.Fatalf("global key preview %q (%+v)", d, sys)
	}
	if d := got["rp_filter=2、send_redirects=0、accept_redirects=0"]; !strings.Contains(d, "eth0 m04") || !strings.Contains(d, "Docker、WARP 等其它接口不改") {
		t.Fatalf("interface preview %q", d)
	}
	if _, ok := got["net.ipv4.conf.all.rp_filter"]; ok {
		t.Fatal("remote node previews all.rp_filter")
	}
	s := find(ev, CodeSysctlScope)
	if len(s) != 1 || !strings.Contains(s[0].Message, "max(all, 接口)") || !strings.Contains(s[0].Message, "撤回不改运行中的值") {
		t.Fatalf("scope %+v", s)
	}
}

// Router advertisements: an RA-dependent interface (accept_ra 1) gets
// accept_ra=2 in the plan before IPv6 forwarding; none without RA; a
// userspace RA client blocks; a node that forwards no IPv6 changes nothing.
func TestRAPlan(t *testing.T) {
	fp := FootprintOf(nodeFiles(t, "hk-resi"))
	if !fp.RAKeep || !fp.Forward6 {
		t.Fatalf("hk-resi footprint ra=%v fwd6=%v", fp.RAKeep, fp.Forward6)
	}
	sysChanges := func(ev Evaluation) []string {
		var out []string
		for _, c := range ev.Changes {
			if c.Kind == "sysctl" {
				out = append(out, c.Resource)
			}
		}
		return out
	}
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "sysctl net.ipv6.conf.all.forwarding 0\nra6 eth0 1 default\nra6 eth0 1 prefix\n"), fp, remote("hk-resi"))
	checkShape(t, ev)
	ch := sysChanges(ev)
	ra, fwd := -1, -1
	for i, c := range ch {
		switch c {
		case "net.ipv6.conf.eth0.accept_ra=2":
			ra = i
		case "net.ipv6.conf.all.forwarding=1":
			fwd = i
		}
	}
	if ev.Blocking || ra < 0 || fwd < 0 || ra > fwd {
		t.Fatalf("plan %v (blocking %v)", ch, codes(ev, Blocking))
	}
	if k := find(ev, CodeRAKept); len(k) != 1 || !strings.Contains(k[0].Message, "eth0（默认路由）") || !strings.Contains(k[0].Message, "撤回不改") {
		t.Fatalf("ra finding %+v", k)
	}
	// No RA: nothing.
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "sysctl net.ipv6.conf.all.forwarding 0\n"), fp, remote("hk-resi"))
	if has(ev, "", CodeRAKept) || strings.Contains(strings.Join(sysChanges(ev), " "), "accept_ra") {
		t.Fatalf("no RA: %v", sysChanges(ev))
	}
	// Already 2: nothing to change, stated.
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "ra6 eth0 2 default\n"), fp, remote("hk-resi"))
	if strings.Contains(strings.Join(sysChanges(ev), " "), "accept_ra") || !strings.Contains(find(ev, CodeRAKept)[0].Message, "已经是 accept_ra=2：eth0") {
		t.Fatalf("already 2: %v", sysChanges(ev))
	}
	// Userspace RA client (accept_ra 0) or unreadable: blocking.
	for _, v := range []string{"0", "-"} {
		ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, "ra6 eth0 "+v+" default\n"), fp, remote("hk-resi"))
		if u := find(ev, CodeRAUnmanaged); len(u) != 1 || u[0].Severity != Blocking || !strings.Contains(u[0].Action, "IPv6 出口") {
			t.Fatalf("accept_ra %s: %+v", v, u)
		}
	}
	// tw forwards no IPv6: informational, no change, no IPv6 forwarding.
	tw := FootprintOf(nodeFiles(t, "tw"))
	ev = Evaluate(fixture(t, "clean-debian13.txt", tw, nil, "sysctl net.ipv6.conf.all.forwarding 0\nra6 eth0 0 default\n"), tw, remote("tw"))
	if tw.Forward6 || tw.RAKeep || ev.Blocking || strings.Contains(strings.Join(sysChanges(ev), " "), "ipv6") || !strings.Contains(find(ev, CodeRAKept)[0].Message, "不会打开 IPv6 转发") {
		t.Fatalf("tw: fwd6=%v %v %v", tw.Forward6, codes(ev, Blocking), sysChanges(ev))
	}
}

// WAN interface: wrong name, unset with eth0 present, unset with a
// different NIC, IPv4 and IPv6 defaults on different interfaces.
func TestWANInterfaceCheck(t *testing.T) {
	wantFix := func(t *testing.T, f Finding) {
		t.Helper()
		if f.Fix == nil || f.Fix.Kind != "node" || f.Fix.ID != "hk-resi" || f.Fix.Field != "wan_interface" || !strings.Contains(f.Fix.Label, "「WAN 接口」") {
			t.Fatalf("fix %+v", f.Fix)
		}
	}
	// Wrong name.
	fp := FootprintOf(filesWAN(t, "hk-resi", "ens9"))
	if fp.WAN != "ens9" || !fp.WANSet || strings.Join(fp.WANNeed, ",") != "4,6" {
		t.Fatalf("footprint %q %v %v", fp.WAN, fp.WANSet, fp.WANNeed)
	}
	ev := Evaluate(fixture(t, "clean-debian13.txt", fp, nil, ""), fp, remote("hk-resi"))
	if m := find(ev, CodeWANMissing); len(m) != 1 || m[0].Severity != Blocking || !strings.Contains(m[0].Message, "ens9 在这台主机上不存在") || !strings.Contains(m[0].Message, "IPv4 默认路由在 eth0 上") {
		t.Fatalf("wrong name %+v", m)
	} else {
		wantFix(t, m[0])
	}
	// Unset, eth0 present with both defaults: passes, says so.
	fp = FootprintOf(filesWAN(t, "hk-resi", ""))
	if fp.WAN != "eth0" || fp.WANSet {
		t.Fatalf("unset footprint %q %v", fp.WAN, fp.WANSet)
	}
	ev = Evaluate(fixture(t, "clean-debian13.txt", fp, nil, ""), fp, remote("hk-resi"))
	if ev.Blocking || !strings.Contains(find(ev, CodeWAN)[0].Message, "没填「WAN 接口」，按 eth0，与这台主机一致") {
		t.Fatalf("unset eth0: %v %+v", codes(ev, Blocking), find(ev, CodeWAN))
	}
	// Unset on a host whose NIC is enp0s6: blocks and names enp0s6.
	ev = Evaluate(fixture(t, "ubuntu2004-arm64.txt", fp, nil, ""), fp, remote("hk-resi"))
	if m := find(ev, CodeWANMissing); len(m) != 1 || !strings.Contains(m[0].Message, "没填") || !strings.Contains(m[0].Message, "enp0s6") {
		t.Fatalf("unset other NIC %+v", m)
	} else {
		wantFix(t, m[0])
	}
	// IPv4 default on eth0, IPv6 default on eth1: the IPv6 egress cannot
	// leave through eth0.
	raw := strings.Replace(string(mustRead(t, "testdata/clean-debian13.txt")), "route6 default via fe80::1 dev eth0", "route6 default via fe80::1 dev eth1", 1)
	raw = strings.Replace(raw, "link eth0\n", "link eth0\nlink eth1\n", 1)
	fp = FootprintOf(nodeFiles(t, "hk-resi"))
	ev = Evaluate(parseWithPaths(t, raw, fp, nil), fp, remote("hk-resi"))
	if m := find(ev, CodeWANRoute); len(m) != 1 || m[0].Severity != Blocking || !strings.Contains(m[0].Message, "IPv6 默认路由在 eth1 上") || !strings.Contains(m[0].Action, "两块不同的网卡") {
		t.Fatalf("split defaults %+v", m)
	} else {
		wantFix(t, m[0])
	}
	// An exit with IPv4 egress only does not need the IPv6 default there.
	tw := FootprintOf(nodeFiles(t, "tw"))
	if ev := Evaluate(parseWithPaths(t, raw, tw, nil), tw, remote("tw")); has(ev, "", CodeWANRoute) || has(ev, "", CodeWANMissing) {
		t.Fatalf("tw: %v", codes(ev, ""))
	}
	// The gateway is not checked here (its LAN is settings.lan_interface).
	gw := FootprintOf(nodeFiles(t, "gw"))
	if gw.WAN != "" {
		t.Fatalf("gateway WAN %q", gw.WAN)
	}
}
