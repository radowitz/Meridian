package compile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
	"github.com/radowitz/meridian/internal/validate"
)

func sharedTopo(t *testing.T) model.Topology {
	t.Helper()
	topo := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&topo)
	return topo
}

func sharedBundle(t *testing.T) (*Bundle, *sharePlan) {
	t.Helper()
	topo := sharedTopo(t)
	b, err := Compile(topo)
	if err != nil {
		t.Fatalf("%v %+v", err, b.Issues)
	}
	return b, planShare(topo, mustTunnels(t, topo))
}

func TestSharePlanAndConfig(t *testing.T) {
	b, p := sharedBundle(t)
	if p == nil || len(p.Relays) != 2 || p.Backup == nil {
		t.Fatalf("plan %+v", p)
	}
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relays[0].ID != "ali" || len(cfg.Relays[0].Legs) != 2 || cfg.Relays[0].Legs[1].Mode != "wss" || cfg.Relays[1].ID != "ali2" || len(cfg.Relays[1].Legs) != 1 {
		t.Fatalf("relays %+v", cfg.Relays)
	}
	if cfg.Backup == nil || cfg.Backup.Hub != "hk5" || cfg.Settings.EvictAfterSec != model.PathQualityDefaults().EvictAfterSec || cfg.Settings.ProbeBytes != model.PathQualityDefaults().ProbeBytes {
		t.Fatalf("backup/settings %+v %+v", cfg.Backup, cfg.Settings)
	}
	// The probe targets are the primary hub's addresses on each relay's
	// own tunnel (end to end through that relay).
	if cfg.Relays[0].Probe == cfg.Relays[1].Probe {
		t.Fatal("both relays probe the same address")
	}
	if pathquality.MaxRelays != validate.MaxSharingRelays {
		t.Fatal("relay limits differ")
	}
	// Single relay: nothing of this is compiled.
	single := defaults.DualHubExample()
	model.MigrateRegionGroups(&single)
	sb, err := Compile(single)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range sb.Files {
		if strings.Contains(path, "path-quality") || strings.Contains(body, "relay_share") || strings.Contains(body, "ingress_return") || strings.Contains(body, "SH_NAME") {
			t.Fatalf("single relay compiled sharing in %s", path)
		}
	}
}

func TestShareGatewayNFT(t *testing.T) {
	b, p := sharedBundle(t)
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	for _, want := range []string{
		// assignment once per connection, by flow hash, equal weights
		"    ct state new jump relay_assign\n",
		"    meta nfproto ipv4 ct mark set jhash ip saddr . ip daddr . th sport . th dport mod 1000 seed 0x4d52 map { 0-499 : 0x00010000, 500-999 : 0x00020000 }\n",
		"    meta nfproto ipv6 ct mark set jhash ip6 saddr . ip6 daddr . th sport . th dport mod 1000 seed 0x4d52 map { 0-499 : 0x00010000, 500-999 : 0x00020000 }\n",
		// restore onto every packet of the connection
		"    ct mark 0x00010000 meta mark set meta mark | 0x00010000 return",
		"    ct mark 0x00020000 meta mark set meta mark | 0x00020000 return",
		"    ct mark 0x00fe0000 meta mark set meta mark | 0x00fe0000 return",
		// after classification, exit marks only
		"    iifname \"eth0\" jump classify\n    iifname \"eth0\" meta mark 0x101-0x140 jump relay_share",
		// stripped before the guard (-200)
		"type filter hook forward priority -300; policy accept;\n    meta mark & 0x00ff0000 != 0x00000000 meta mark set meta mark & 0xff00ffff",
		"  chain share_forward {\n    type filter hook forward priority filter; policy accept;\n    jump relay_drain\n  }",
		"counter share_r1_tcp_out", "counter share_r2_tcp_in", "counter share_bk_new",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("gateway nft lacks %q", want)
		}
	}
	// Never per packet: the map is only consulted for new connections.
	if regexp.MustCompile(`(?m)^\s+meta mark set jhash|numgen`).MatchString(nft) {
		t.Error("per-packet assignment found")
	}
	// The guard admits every relay leg and the backup, and still ends in drop.
	guard := b.File("nodes/gw/etc/nftables.d/meridian-guard.nft")
	ifs := []string{}
	for _, r := range p.Relays {
		for _, l := range r.Legs {
			ifs = append(ifs, l.Iface())
		}
	}
	ifs = append(ifs, p.Backup.Tun.Iface())
	m := regexp.MustCompile(`oifname \{ ([^}]*) \} return comment "exit marks: WireGuard only"`).FindStringSubmatch(guard)
	if m == nil {
		t.Fatalf("guard:\n%s", guard)
	}
	for _, i := range ifs {
		if !strings.Contains(m[1], `"`+i+`"`) {
			t.Errorf("guard does not admit %s: %s", i, m[1])
		}
	}
	lines := strings.Split(strings.TrimSpace(guard), "\n")
	if !strings.Contains(strings.Join(lines[len(lines)-4:], "\n"), "counter drop comment \"fail closed") {
		t.Error("guard no longer ends in drop")
	}
	if !strings.Contains(nft, guard[strings.Index(guard, "table inet meridian_guard\n"):]) {
		t.Error("guard in meridian.nft differs from the early-boot copy")
	}
}

func TestShareRoutesAndReplySymmetry(t *testing.T) {
	b, p := sharedBundle(t)
	gw := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	for _, want := range []string{
		"ip rule add fwmark 0x10000/0xff0000 lookup 111 priority 17151\n",
		"ip -6 rule add fwmark 0x20000/0xff0000 lookup 112 priority 17152\n",
		"ip rule add fwmark 0xfe0000/0xff0000 lookup 109 priority 17150\n",
		"share_tables 'm02' 'm03'\n",
		"share_designate 'm02'\n",
		"ip route replace 10.66.1.2/32 dev m02 src 10.66.200.2 metric 10\n",
		"ip route replace 10.66.1.2/32 dev m02w src 10.66.200.2 metric 11\n",
		"ip route replace 10.66.2.2/32 dev m03 src 10.66.200.2 metric 12\n",
		"share_record static shell main 'ali'",
	} {
		if !strings.Contains(gw, want) {
			t.Errorf("gateway routes lack %q", want)
		}
	}
	if strings.Contains(gw, "UP_NAME=") {
		t.Error("the single-relay upstream prelude is compiled next to sharing")
	}
	rt := b.File("nodes/gw/etc/iproute2/rt_tables.d/meridian.conf")
	for _, want := range []string{"109\tmeridian_share_backup", "111\tmeridian_share_r1", "112\tmeridian_share_r2"} {
		if !strings.Contains(rt, want) {
			t.Errorf("rt_tables lacks %q", want)
		}
	}
	// The primary hub: a ct mark per relay tunnel and the reply table.
	ixNFT := b.File("nodes/ix/etc/nftables.d/meridian.nft")
	ixRoutes := b.File("nodes/ix/usr/local/sbin/meridian-routes.sh")
	for i, r := range p.Relays {
		hubTun := relayHubTunnel(mustTunnels(t, sharedTopo(t)), r.Node.ID, "ix")
		mark := markIngressBase + uint32(i)
		for _, want := range []string{
			"iifname \"" + hubTun.Iface() + "\" ct direction original ct mark set " + hexOf(mark),
			"ct direction reply ct mark " + hexOf(mark) + " meta mark set " + hexOf(mark),
		} {
			if !strings.Contains(ixNFT, want) {
				t.Errorf("ix nft lacks %q", want)
			}
		}
		if !strings.Contains(ixRoutes, "ip route replace 10.66.0.0/16 dev "+hubTun.Iface()+" table ") {
			t.Errorf("ix lacks the reply table on %s", hubTun.Iface())
		}
	}
	if !strings.Contains(ixNFT, "type route hook output priority mangle") {
		t.Error("ix: local replies (the gateway's probes) are not rerouted by ingress")
	}
	// A relay: its legs from the gateway.
	for _, relay := range []string{"ali", "ali2"} {
		nft := b.File("nodes/" + relay + "/etc/nftables.d/meridian.nft")
		if !strings.Contains(nft, "ct direction original ct mark set 0x4e00") || !strings.Contains(nft, "arrived from gw") {
			t.Errorf("%s nft lacks the ingress mark:\n%s", relay, nft)
		}
	}
	if !strings.Contains(b.File("nodes/ali/etc/nftables.d/meridian.nft"), "ct mark set 0x4e01") {
		t.Error("ali's WSS leg has no ingress mark")
	}
	// The exits keep their per-hub return (dual hub) unchanged.
	if !strings.Contains(b.File("nodes/dc1/etc/nftables.d/meridian.nft"), "chain hub_return_in") {
		t.Error("exit hub return missing")
	}
	// The backup hub is reached only by the gateway: no relay ingress.
	if strings.Contains(b.File("nodes/hk5/etc/nftables.d/meridian.nft"), "ingress_return") {
		t.Error("backup hub got relay ingress marks")
	}
}

func hexOf(v uint32) string { return fmt.Sprintf("%#x", v) }

// shellLab writes stubs (ip, nft, ping, date, timeout, meridian) and the
// part of the compiled failover script before its main loop.
type shellLab struct {
	t              *testing.T
	dir, ctrl, bin string
	run, prog      string
	b              *Bundle
}

func newShellLab(t *testing.T) *shellLab {
	t.Helper()
	if !bashOK() {
		t.Skip("bash not available")
	}
	b, _ := sharedBundle(t)
	l := &shellLab{t: t, b: b, dir: t.TempDir()}
	l.ctrl, l.bin, l.run = filepath.Join(l.dir, "ctrl"), filepath.Join(l.dir, "bin"), filepath.Join(l.dir, "run")
	for _, d := range []string{l.ctrl, l.bin, l.run} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub := func(name, body string) {
		if err := os.WriteFile(filepath.Join(l.bin, name), []byte("#!/bin/bash\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("ip", "echo \"ip $*\" >> "+l.ctrl+"/ip.log\n")
	stub("nft", "if [ \"$1\" = -f ] && [ \"$2\" = - ]; then { echo '--- batch'; cat; } >> "+l.ctrl+"/nft.log; [ ! -f "+l.ctrl+"/nft-fail ]; exit; fi\necho \"nft $*\" >> "+l.ctrl+"/nft.log\n")
	// ping -n -q -I <iface> …: answers when ctrl/up-<iface> exists.
	stub("ping", `[ -f `+l.ctrl+`/up-$4 ]`+"\n")
	stub("date", "cat "+l.ctrl+"/now\n")
	stub("timeout", "shift; exec \"$@\"\n")
	// The controller stub: prints ctrl/decision, or fails without one.
	stub("meridian", "[ \"$1\" = path-step ] || exit 9\n[ \"$MERIDIAN_BIND\" = - ] || exit 8\n[ -f "+l.ctrl+"/decision ] || exit 1\ncat "+l.ctrl+"/decision\n")
	full := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	cut := strings.Index(full, "# --- main loop ---")
	if cut < 0 {
		t.Fatal("no main-loop marker")
	}
	l.prog = "export PATH=" + l.bin + ":$PATH\n" + strings.ReplaceAll(full[:cut], "/run/meridian", l.run) +
		"MERIDIAN_BIN=" + filepath.Join(l.bin, "meridian") + "\n"
	l.write("now", "1700000000\n")
	return l
}

func (l *shellLab) write(name, body string) {
	l.t.Helper()
	if err := os.WriteFile(filepath.Join(l.ctrl, name), []byte(body), 0o644); err != nil {
		l.t.Fatal(err)
	}
}

func (l *shellLab) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(l.ctrl, name))
	return string(b)
}

func (l *shellLab) bash(script string) (string, error) {
	f := filepath.Join(l.dir, "drive.sh")
	if err := os.WriteFile(f, []byte(l.prog+script), 0o600); err != nil {
		l.t.Fatal(err)
	}
	out, err := exec.Command("bash", f).CombinedOutput()
	return string(out), err
}

func TestShareShellMapMatchesCompiler(t *testing.T) {
	l := newShellLab(t)
	_, p := sharedBundle(t)
	for _, w := range [][]int{{500, 500}, {1000, 0}, {0, 1000}, {200, 800}, {0, 0}} {
		out, err := l.bash(fmt.Sprintf("share_map %d %d\n", w[0], w[1]))
		if err != nil {
			t.Fatalf("%v: %v\n%s", w, err, out)
		}
		if got, want := strings.TrimSpace(out), shareMap(p, w); got != want {
			t.Errorf("weights %v: shell %q, compiler %q", w, got, want)
		}
	}
}

func TestShareApplyOneBatchAndRefusals(t *testing.T) {
	l := newShellLab(t)
	out, err := l.bash("share_apply main ali m02w 700 0 m03 300 1 0\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	nft := l.read("nft.log")
	_, p := sharedBundle(t)
	v4, v6 := shareAssignRules(p, []int{700, 300})
	want := "--- batch\nflush chain inet meridian relay_assign\nadd rule inet meridian relay_assign " + v4 + "\nadd rule inet meridian relay_assign " + v6 +
		"\nflush chain inet meridian relay_redirect\n" +
		"add rule inet meridian relay_redirect ct mark 0x00020000 meta l4proto != tcp meta nfproto ipv4 ct mark set " + shareHash4 + " " + shareMap(p, []int{700, 300}) + "\n" +
		"add rule inet meridian relay_redirect ct mark 0x00020000 meta l4proto != tcp meta nfproto ipv6 ct mark set " + shareHash6 + " " + shareMap(p, []int{700, 300}) + "\n" +
		"flush chain inet meridian relay_drain\n" +
		"add rule inet meridian relay_drain iifname \"eth0\" ct direction original ct mark 0x00020000 meta l4proto tcp reject with tcp reset\n"
	if nft != want {
		t.Fatalf("nft batch:\n%s\nwant:\n%s", nft, want)
	}
	ip := l.read("ip.log")
	for _, w := range []string{"ip route replace default dev m02w table 111", "ip route replace default dev m03 table 112", "ip route replace default dev m02w table 102", "ip -6 route replace fd66::/48 dev m02w"} {
		if !strings.Contains(ip, w) {
			t.Errorf("ip log lacks %q:\n%s", w, ip)
		}
	}
	if strings.Contains(ip, "eth0") {
		t.Errorf("share_apply touched the LAN NIC:\n%s", ip)
	}
	// Backup: every new connection to the backup hub, table 102 on it.
	if out, err := l.bash("share_apply backup backup m02 0 1 m03 0 1 0\n"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(l.read("nft.log"), "map { 0-999 : 0x00fe0000 }") || !strings.Contains(l.read("ip.log"), "default dev m04 table 102") {
		t.Fatal("backup decision not applied")
	}
	// Refusals: nothing reaches nft or ip.
	for _, bad := range []string{
		"share_apply main ali eth0 500 0 m03 500 0 0",       // not a leg
		"share_apply main ali m02 500 0 m03 400 0 0",        // sum
		"share_apply main hk5 m02 500 0 m03 500 0 0",        // designated not a relay
		"share_apply backup backup m02 500 0 m03 500 0 0",   // backup with weights
		"share_apply main ali m02 500 0 m03 500 0",          // count
		"share_apply main ali m02 500 x m03 500 0 0",        // flag
		"share_apply main ali m02 -5 0 m03 1005 0 0",        // weight
		"share_apply sideways ali m02 500 0 m03 500 0 0",    // upstream
		"share_apply main ali 'm02 m02w' 500 0 m03 500 0 0", // two legs in one
	} {
		before := l.read("nft.log") + l.read("ip.log")
		if out, err := l.bash(bad + "\n"); err == nil {
			t.Errorf("accepted %s\n%s", bad, out)
		}
		if l.read("nft.log")+l.read("ip.log") != before {
			t.Errorf("%s changed something", bad)
		}
	}
	// nft refuses the batch: no route changes either.
	l.write("nft-fail", "")
	before := l.read("ip.log")
	if _, err := l.bash("share_apply main ali m02 500 0 m03 500 0 0\n"); err == nil {
		t.Error("a refused batch must fail share_apply")
	}
	if l.read("ip.log") != before {
		t.Error("routes changed although the map was refused")
	}
}

func TestShareFailoverDecisionAndFallback(t *testing.T) {
	l := newShellLab(t)
	// 1. The controller decides; the same decision twice is applied once.
	l.write("decision", "meridian-pathq 1\nupstream main\ndesignated ali2\nrelay ali m02 300 0\nrelay ali2 m03 700 0\nbackup 0\nend\n")
	if out, err := l.bash("share_step\nshare_step\n"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if n := strings.Count(l.read("nft.log"), "--- batch"); n != 1 {
		t.Fatalf("%d batches for one decision", n)
	}
	if !strings.Contains(l.read("ip.log"), "default dev m03 table 102") {
		t.Fatal("designated relay not applied to table 102")
	}
	// 2. A decision naming a foreign interface is refused: fallback.
	l.write("decision", "meridian-pathq 1\nupstream main\ndesignated ali\nrelay ali eth0 500 0\nrelay ali2 m03 500 0\nbackup 0\nend\n")
	l.write("up-m02", "")
	l.write("up-m03", "")
	out, err := l.bash("share_step\ncat " + l.run + "/upstream\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "controller shell") || strings.Contains(l.read("ip.log"), "eth0 table") {
		t.Fatalf("refused decision not replaced by the fallback:\n%s", out)
	}
	// 3. No controller: equal weights over the relays that answer;
	// FAILS_NEED passes to evict; the backup only while none answers;
	// back after COOLDOWN.
	os.Remove(filepath.Join(l.ctrl, "decision"))
	var sb strings.Builder
	step := func(now int, up []string, wantUp, wantW string) {
		sb.WriteString("rm -f " + l.ctrl + "/up-*\n")
		for _, u := range up {
			sb.WriteString("touch " + l.ctrl + "/up-" + u + "\n")
		}
		sb.WriteString("echo " + itoa(1700000000+now) + " > " + l.ctrl + "/now\n")
		sb.WriteString("share_step\n")
		sb.WriteString(`[ "$fb_up" = ` + wantUp + ` ] && [ "${SH_R_W[*]}" = "` + wantW + `" ] || { echo "t+` + itoa(now) + `: up=$fb_up w=${SH_R_W[*]} want ` + wantUp + ` ` + wantW + `"; exit 1; }` + "\n")
	}
	step(5, []string{"m02", "m03", "m04"}, "main", "500 500")
	step(10, []string{"m03", "m04"}, "main", "500 500")
	step(15, []string{"m03", "m04"}, "main", "500 500")
	step(20, []string{"m03", "m04"}, "main", "0 1000") // third failed pass: ali out
	step(25, []string{"m02w", "m03", "m04"}, "main", "0 1000")
	step(30, []string{"m04"}, "main", "0 1000")
	step(35, []string{"m04"}, "main", "0 1000")
	step(40, []string{"m04"}, "backup", "500 500") // none in: backup
	step(45, nil, "backup", "500 500")             // nothing answers: stay
	for i := 0; i < 4; i++ {
		step(50+5*i, []string{"m03", "m04"}, "backup", "500 500") // ali2 not back yet (RECOVERS_NEED)
	}
	step(70, []string{"m03", "m04"}, "backup", "0 1000") // ali2 back in; the cooldown keeps the backup
	step(200, []string{"m03", "m04"}, "main", "0 1000")
	out, err = l.bash(sb.String() + "cat " + l.run + "/upstream\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	rec := out[strings.Index(out, "meridian-upstream 2"):]
	st, err := hostexec.ParseUpstream(rec)
	if err != nil {
		t.Fatalf("fallback record refused: %v\n%s", err, rec)
	}
	if st.Controller != "shell" || st.Alert != "controller_unavailable" || st.Path != "main" || st.Designated != "ali2" || len(st.Relays) != 2 || st.Relays[0].Status != "evicted" {
		t.Fatalf("record %+v", st)
	}
	if strings.Contains(l.read("ip.log"), "dev eth0 table") {
		t.Fatal("fallback routed a table at the LAN NIC")
	}
}

func itoa(n int) string { return fmt.Sprint(n) }

// The status record the install writes is accepted by meridian-host.
func TestShareStaticRecordParses(t *testing.T) {
	l := newShellLab(t)
	out, err := l.bash("share_record static shell main ali 1700000000 0 -\ncat " + l.run + "/upstream\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := hostexec.ParseUpstream(out)
	if err != nil || st.Version != 2 || st.State != "static" || st.Hub != "ix" || st.Iface != "m02" {
		t.Fatalf("%v %+v\n%s", err, st, out)
	}
	// And the controller's record (pathquality.FormatStatus).
	b, _ := sharedBundle(t)
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	ps := pathquality.NewState(cfg, 1700000000)
	m := pathquality.Measurement{Now: 1700000005, Relays: map[string]pathquality.PathSample{
		"ali":  {Legs: []pathquality.LegSample{{Iface: "m02", Sent: 5, Recv: 5, RTTus: 31000}, {Iface: "m02w", Sent: 5, Recv: 5, RTTus: 40000}}},
		"ali2": {Legs: []pathquality.LegSample{{Iface: "m03", Sent: 5, Recv: 4, RTTus: 35000}}},
	}, Backup: &pathquality.PathSample{Legs: []pathquality.LegSample{{Iface: "m04", Sent: 5, Recv: 0}}}}
	ps, _ = pathquality.Step(cfg, ps, m)
	rec := pathquality.FormatStatus(cfg, ps, 1700000005, "go")
	st, err = hostexec.ParseUpstream(rec)
	if err != nil {
		t.Fatalf("%v\n%s", err, rec)
	}
	if st.Relays[1].LossPermille == nil || *st.Relays[1].LossPermille != 200 || st.Backup == nil || st.Backup.Grade != "down" {
		t.Fatalf("%+v\n%s", st, rec)
	}
	if len(rec) > hostexec.MaxUpstreamFile/4 {
		t.Fatalf("record of two relays is %d bytes", len(rec))
	}
}

func TestShareScriptsSyntax(t *testing.T) {
	if !bashOK() {
		t.Skip("bash not available")
	}
	b, _ := sharedBundle(t)
	dir := t.TempDir()
	for _, node := range []string{"gw", "ali", "ali2", "ix", "hk5"} {
		for _, s := range []string{"meridian-routes.sh", "meridian-failover.sh"} {
			body := b.File("nodes/" + node + "/usr/local/sbin/" + s)
			if body == "" {
				continue
			}
			f := filepath.Join(dir, node+"-"+s)
			if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
				t.Errorf("%s %s: %v\n%s", node, s, err, out)
			}
		}
	}
	// The shared prelude is byte-identical in both gateway scripts.
	pre := sharePrelude(planShare(sharedTopo(t), mustTunnels(t, sharedTopo(t))))
	for _, s := range []string{"meridian-routes.sh", "meridian-failover.sh"} {
		if !strings.Contains(b.File("nodes/gw/usr/local/sbin/"+s), pre) {
			t.Errorf("%s does not carry the shared prelude", s)
		}
	}
}

func TestSharingValidation(t *testing.T) {
	base := sharedTopo(t)
	if res := validate.Run(base); res.HasErrors() {
		t.Fatalf("example: %+v", res.Issues)
	}
	// Without the backup hub: still valid (single-hub sharing).
	single := sharedTopo(t)
	var nodes []model.Node
	for _, n := range single.Nodes {
		if n.ID != "hk5" {
			nodes = append(nodes, n)
		}
	}
	single.Nodes = nodes
	var links []model.Link
	for _, l := range single.Links {
		if l.From != "hk5" && l.To != "hk5" {
			links = append(links, l)
		}
	}
	single.Links = links
	if res := validate.Run(single); res.HasErrors() {
		t.Fatalf("single-hub sharing: %+v", res.Issues)
	}
	b, err := Compile(single)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil || cfg.Backup != nil {
		t.Fatalf("single-hub config: %v %+v", err, cfg.Backup)
	}
	if strings.Contains(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "share_bk_new") {
		t.Error("backup counter without a backup hub")
	}
	cases := []struct {
		code string
		mut  func(*model.Topology)
	}{
		{"sharing_relay_no_hub_link", func(tp *model.Topology) {
			for i := range tp.Links {
				if tp.Links[i].ID == "ali2-ix" {
					tp.Links[i].Enabled = false
				}
			}
		}},
		{"sharing_relay_multiple_links", func(tp *model.Topology) {
			tp.Links = append(tp.Links, model.Link{ID: "gw-ali2b", From: "gw", To: "ali2", Transport: model.TransportDirectWG, Enabled: true})
		}},
		{"ix_replacement_mode_sharing", func(tp *model.Topology) { tp.Settings.IXReplacementMode = true }},
		{"sharing_relay_hub_transport", func(tp *model.Topology) {
			for i := range tp.Links {
				if tp.Links[i].ID == "ali2-ix" {
					tp.Links[i].Transport = model.TransportUDPWSSFailover
				}
			}
		}},
		{"invalid_path_quality", func(tp *model.Topology) {
			tp.Settings.PathQuality = &model.PathQuality{MildLossPermille: 200, PoorLossPermille: 100}
		}},
		{"invalid_path_quality", func(tp *model.Topology) { tp.Settings.PathQuality = &model.PathQuality{ProbeBytes: 10} }},
		{"invalid_path_quality", func(tp *model.Topology) {
			tp.Settings.PathQuality = &model.PathQuality{ProbeFloorKbps: 5000, ProbeRateKbps: 1000}
		}},
		{"invalid_path_quality", func(tp *model.Topology) {
			tp.Settings.PathQuality = &model.PathQuality{Overrides: []model.RelayOverride{{Relay: "dc1", Disabled: true}}}
		}},
		{"invalid_path_quality", func(tp *model.Topology) {
			tp.Settings.PathQuality = &model.PathQuality{Overrides: []model.RelayOverride{{Relay: "ali", Disabled: true}, {Relay: "ali2", Disabled: true}}}
		}},
		{"invalid_path_quality", func(tp *model.Topology) {
			tp.Settings.PathQuality = &model.PathQuality{ProbeDailyBudgetMB: 1, ProbeBytes: 4 * 1024 * 1024}
		}},
	}
	for _, c := range cases {
		tp := sharedTopo(t)
		c.mut(&tp)
		found := false
		for _, iss := range validate.Run(tp).Issues {
			found = found || (iss.Code == c.code && iss.Severity == validate.SeverityError)
		}
		if !found {
			t.Errorf("%s not reported", c.code)
		}
	}
	// Valid settings and an override compile into the config.
	tp := sharedTopo(t)
	tp.Settings.PathQuality = &model.PathQuality{EvictAfterSec: 60, ProbeOff: true, Overrides: []model.RelayOverride{{Relay: "ali2", Weight: 40}}}
	b, err = Compile(tp)
	if err != nil {
		t.Fatalf("%v %+v", err, b.Issues)
	}
	cfg, err = pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil || cfg.Settings.EvictAfterSec != 60 || !cfg.Settings.ProbeOff || cfg.Settings.DownAfterSec != 15 || len(cfg.Settings.Overrides) != 1 {
		t.Fatalf("%v %+v", err, cfg.Settings)
	}
}
