package compile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// The backup hub reached only through relays (defaults.RelayBackupExample,
// synthetic): main group "access" → primary hub (direct_wg), backup group
// "bk1", "bk2" → backup hub "hkb" (wg_over_wss), no IX, no gateway-direct
// backup link.

func relayBackupTopo(mut func(t *model.Topology)) model.Topology {
	t := defaults.RelayBackupExample()
	if mut != nil {
		mut(&t)
	}
	model.MigrateRegionGroups(&t)
	return t
}

func TestGoldenRelayBackup(t *testing.T) {
	b := noIXCompile(t, relayBackupTopo(nil))
	if dir := os.Getenv("MERIDIAN_DUMP"); dir != "" {
		for p, body := range b.Files {
			os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
			os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644)
		}
	}
	checkGolden(t, "relay_backup_example.golden", b)
}

func TestRelayBackupCompiled(t *testing.T) {
	topo := relayBackupTopo(nil)
	b := noIXCompile(t, topo)
	// Main relay dials the primary hub's endpoint_v4; the backup-group
	// relays dial the backup hub over their local wstunnel client.
	if c := wgConf(t, b, "access", "access-hub", "udp"); !strings.Contains(c, "Endpoint = 203.0.113.20:") {
		t.Fatalf("access → hub endpoint:\n%s", c)
	}
	for _, r := range []string{"bk1", "bk2"} {
		if c := wgConf(t, b, r, r+"-hkb", "wss"); !strings.Contains(c, "Endpoint = 127.0.0.1:") {
			t.Fatalf("%s → hkb:\n%s", r, c)
		}
		env := b.File("nodes/" + r + "/etc/meridian/wss/client-" + r + "-hkb.env")
		if env == "" || b.File("nodes/"+r+"/etc/systemd/system/wstunnel-client-"+r+"-hkb.service") == "" {
			t.Fatalf("%s: no WSS client", r)
		}
		if !strings.Contains(b.File("nodes/hkb/etc/meridian/wss/server.yaml"), `name: "`+r+`-hkb"`) {
			t.Fatalf("hkb WSS server has no rule for %s", r)
		}
	}
	if !strings.Contains(b.File("nodes/hkb/etc/systemd/system/wstunnel-meridian.service"), "wss://0.0.0.0:8443") {
		t.Fatal("hkb WSS server not listening")
	}
	// Both hubs answer each relay tunnel on the tunnel it arrived on.
	hkb := b.File("nodes/hkb/usr/local/sbin/meridian-routes.sh")
	for _, w := range []string{"# meridian-west-preferred: backup-relay ", "# from bk1: mark 0x4e00", "# from bk2: mark 0x4e01"} {
		if !strings.Contains(hkb, w) {
			t.Fatalf("hkb routes lack %q", w)
		}
	}
	if !strings.Contains(b.File("nodes/hkb/etc/nftables.d/meridian.nft"), "chain ingress_return_in") {
		t.Fatal("hkb has no ingress marks")
	}
	if !strings.Contains(b.File("nodes/hub/usr/local/sbin/meridian-routes.sh"), "# from access: mark") {
		t.Fatal("primary hub has no relay return")
	}
	// The gateway: groups, probes toward each relay's own hub, initial
	// weights on the main group.
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BackupHub != "hkb" || cfg.Backup != nil || len(cfg.Relays) != 3 || cfg.Relays[0].ID != "access" || cfg.Relays[0].Group != "" ||
		cfg.Relays[1].Group != pathquality.GroupBackup || cfg.Relays[2].Group != pathquality.GroupBackup {
		t.Fatalf("config %+v", cfg)
	}
	tunnels, _ := buildTunnels(topo)
	if want := relayHubTunnel(tunnels, "access", "hub").EastV4; cfg.Relays[0].Probe != want || want == "" {
		t.Fatalf("access probe %s, want %s", cfg.Relays[0].Probe, want)
	}
	for i, r := range []string{"bk1", "bk2"} {
		if want := relayHubTunnel(tunnels, r, "hkb").EastV4; cfg.Relays[i+1].Probe != want || want == "" {
			t.Fatalf("%s probe %s, want %s", r, cfg.Relays[i+1].Probe, want)
		}
	}
	gw := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	for _, w := range []string{"SH_GROUP=(main backup backup)\n", "SH_BK_GROUP='bk1 bk2'\n", "SH_BK_HUB='hkb'\n", "SH_BK_IFACE=''\n", "SH_R_W=(1000 0 0)\n"} {
		if !strings.Contains(gw, w) {
			t.Fatalf("gateway routes lack %q", w)
		}
	}
	if !strings.Contains(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "map { 0-999 : 0x00010000 }") {
		t.Fatal("initial map is not on the main group")
	}
	// The identity digest names the relay → backup hub WSS legs.
	legs, err := EgressLegs(topo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(legs["hkb"], "\n"), "bk1-hkb|wg_over_wss|wss|bk1>hkb") {
		t.Fatalf("hkb legs %v", legs["hkb"])
	}
}

// A disabled backup-group link drops that relay; with every backup-group
// link disabled the topology is a main group only and compiles like any
// sharing-free single relay with a backup hub never reached.
func TestRelayBackupDisabledLinks(t *testing.T) {
	topo := relayBackupTopo(func(t *model.Topology) {
		noIXLink(t, "bk2-hkb", func(l *model.Link) { l.Enabled = false })
		noIXLink(t, "gw-bk2", func(l *model.Link) { l.Enabled = false })
	})
	b := noIXCompile(t, topo)
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Relays) != 2 || cfg.Relays[1].ID != "bk1" || cfg.BackupHub != "hkb" {
		t.Fatalf("config %+v", cfg)
	}
	if strings.Contains(b.File("nodes/hkb/usr/local/sbin/meridian-routes.sh"), "from bk2") {
		t.Fatal("disabled bk2 still has a return path")
	}
}

// Only a main group (two relays to the primary hub): the plain sharing
// shell, no group fields.
func TestRelayBackupMainOnlyUnchanged(t *testing.T) {
	topo := noIXTopo(enableAli2)
	b := noIXCompile(t, topo)
	if topo.RelayBackup() {
		t.Fatal("main only reported a backup group")
	}
	gw := b.File("nodes/gw/usr/local/sbin/meridian-failover.sh")
	if strings.Contains(gw, "SH_GROUP") || strings.Contains(gw, "backup_group") || strings.Count(gw, "share_fallback_step()") != 1 {
		t.Fatal("group shell in a main-only topology")
	}
	if strings.Contains(b.File("nodes/gw/etc/meridian/path-quality.json"), "group") {
		t.Fatal("group fields in a main-only config")
	}
}

func TestRelayBackupShell(t *testing.T) {
	l := newShellLabFor(t, noIXCompile(t, relayBackupTopo(nil)))
	// The backup group shares: weights over bk1/bk2, table 102 on bk1.
	if out, err := l.bash("share_apply_raw backup bk1 m05 0 1 m06 500 0 m07w 500 0 0\n"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(l.read("nft.log"), "map { 0-499 : 0x00020000, 500-999 : 0x00030000 }") || !strings.Contains(l.read("ip.log"), "default dev m06 table 102") {
		t.Fatalf("backup group not applied:\n%s\n%s", l.read("nft.log"), l.read("ip.log"))
	}
	for _, bad := range []string{
		"share_apply_raw backup backup m05 0 0 m06 0 0 m07 0 0 0",     // the old backup form
		"share_apply_raw backup bk1 m05 100 0 m06 400 0 m07 500 0 0",  // main relay weighted on backup
		"share_apply_raw main access m05 500 0 m06 500 0 m07 0 0 0",   // backup relay weighted on main
		"share_apply_raw backup access m05 0 0 m06 500 0 m07 500 0 0", // designated outside the group
		"share_apply_raw main bk1 m05 1000 0 m06 0 0 m07 0 0 0",       // designated outside the group
	} {
		before := l.read("nft.log") + l.read("ip.log")
		if out, err := l.bash(bad + "\n"); err == nil {
			t.Errorf("accepted %s\n%s", bad, out)
		}
		if l.read("nft.log")+l.read("ip.log") != before {
			t.Errorf("%s changed something", bad)
		}
	}
	// Fallback without the controller: main all down → backup group;
	// back to main after 3 passes and COOLDOWN.
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
	all := []string{"m05", "m06", "m07"}
	bk := []string{"m06", "m07"}
	step(5, all, "main", "1000 0 0")
	step(10, bk, "main", "1000 0 0")
	step(15, bk, "main", "1000 0 0")
	step(20, bk, "backup", "0 500 500")
	step(25, []string{"m06"}, "backup", "0 500 500")
	step(30, []string{"m06"}, "backup", "0 500 500")
	step(35, []string{"m06"}, "backup", "0 1000 0")
	// Back to main: the main group answering 3 consecutive passes and at
	// least COOLDOWN (120 s) since the switch at t+20 — not before.
	for now := 40; now < 140; now += 5 {
		step(now, []string{"m05", "m06"}, "backup", "0 1000 0")
	}
	step(140, []string{"m05", "m06"}, "main", "1000 0 0")
	// Main down 3 passes → backup group again (switch at t+155).
	step(145, []string{"m06"}, "main", "1000 0 0")
	step(150, []string{"m06"}, "main", "1000 0 0")
	step(155, []string{"m06"}, "backup", "0 1000 0")
	// Long after the dwell: 2 passes are not enough, the 3rd returns.
	step(400, []string{"m06"}, "backup", "0 1000 0")
	step(405, []string{"m05", "m06"}, "backup", "0 1000 0")
	step(410, []string{"m05", "m06"}, "backup", "0 1000 0")
	step(415, []string{"m05", "m06"}, "main", "1000 0 0")
	out, err := l.bash(sb.String() + "cat " + l.run + "/upstream\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	rec := out[strings.Index(out, "meridian-upstream 2"):]
	st, err := hostexec.ParseUpstream(rec)
	if err != nil {
		t.Fatalf("record refused: %v\n%s", err, rec)
	}
	if st.Path != "main" || st.Hub != "hub" || st.BackupGroup == nil || st.BackupGroup.Hub != "hkb" || st.Relays[1].Group != "backup" || st.Relays[0].Group != "main" {
		t.Fatalf("record %+v", st)
	}
	// While on the backup group the record names the backup hub.
	out, err = l.bash("SH_R_LEG=(m05 m06 m07)\nshare_record ok shell backup bk1 1700000000 1700000000 -\ncat " + l.run + "/upstream\n")
	if err != nil {
		t.Fatal(err)
	}
	if st, err = hostexec.ParseUpstream(out); err != nil || st.Hub != "hkb" || st.Tier != "backup" || st.Iface != "m06" {
		t.Fatalf("%v %+v\n%s", err, st, out)
	}
}

// The sole main-group relay may reach the primary hub over WSS or the
// UDP+WSS dual leg: relay endpoint / WSS client, hub return, SH_PROBE on
// the relay's preferred hub tunnel.
func TestRelayBackupMainRelayWSS(t *testing.T) {
	for _, tr := range []model.Transport{model.TransportWGOverWSS, model.TransportUDPWSSFailover} {
		t.Run(string(tr), func(t *testing.T) {
			topo := relayBackupTopo(func(t *model.Topology) {
				for i := range t.Links {
					if t.Links[i].ID == "access-hub" {
						t.Links[i].Transport = tr
					}
				}
			})
			b := noIXCompile(t, topo)
			if c := wgConf(t, b, "access", "access-hub", "wss"); !strings.Contains(c, "Endpoint = 127.0.0.1:") {
				t.Fatalf("access → hub over WSS:\n%s", c)
			}
			if b.File("nodes/access/etc/meridian/wss/client-access-hub.env") == "" || b.File("nodes/access/etc/systemd/system/wstunnel-client-access-hub.service") == "" {
				t.Fatal("access: no WSS client")
			}
			if !strings.Contains(b.File("nodes/hub/etc/meridian/wss/server.yaml"), `name: "access-hub"`) {
				t.Fatal("hub WSS server has no rule for access")
			}
			if tr == model.TransportUDPWSSFailover {
				if c := wgConf(t, b, "access", "access-hub", "udp"); !strings.Contains(c, "Endpoint = 203.0.113.20:") {
					t.Fatalf("access → hub UDP leg:\n%s", c)
				}
			}
			if !strings.Contains(b.File("nodes/hub/usr/local/sbin/meridian-routes.sh"), "# from access: mark") {
				t.Fatal("primary hub has no relay return")
			}
			cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
			if err != nil {
				t.Fatal(err)
			}
			tunnels, _ := buildTunnels(topo)
			want := relayHubTunnel(tunnels, "access", "hub")
			if want.EastV4 == "" || cfg.Relays[0].Probe != want.EastV4 || (tr == model.TransportUDPWSSFailover) != (want.Mode == "udp") {
				t.Fatalf("access probe %s (%s), want %s", cfg.Relays[0].Probe, want.Mode, want.EastV4)
			}
			if !strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"), want.EastV4) {
				t.Fatal("SH_PROBE lacks the access → hub target")
			}
		})
	}
}

// The controller's applied decision is the fallback's state: after the
// controller switched groups and then failed, the fallback continues from
// that switch, never from its startup state.
func TestRelayBackupControllerSync(t *testing.T) {
	l := newShellLabFor(t, noIXCompile(t, relayBackupTopo(nil)))
	const (
		decMain = "meridian-pathq 1\nupstream main\ndesignated access\nrelay access m05 1000 0\nrelay bk1 m06 0 0\nrelay bk2 m07 0 0\nbackup 0\nend\n"
		decBk   = "meridian-pathq 1\nupstream backup\ndesignated bk1\nrelay access m05 0 0\nrelay bk1 m06 500 0\nrelay bk2 m07 500 0\nbackup 0\nend\n"
	)
	var sb strings.Builder
	step := func(now int, dec string, up []string, wantUp, wantW string, wantSwitched int) {
		sb.WriteString("rm -f " + l.ctrl + "/up-* " + l.ctrl + "/decision\n")
		if dec != "" {
			sb.WriteString("printf '%s' '" + dec + "' > " + l.ctrl + "/decision\n")
		}
		for _, u := range up {
			sb.WriteString("touch " + l.ctrl + "/up-" + u + "\n")
		}
		sb.WriteString("echo " + itoa(1700000000+now) + " > " + l.ctrl + "/now\n")
		sb.WriteString("share_step\n")
		sw := "0"
		if wantSwitched >= 0 {
			sw = itoa(1700000000 + wantSwitched)
		}
		sb.WriteString(`[ "$fb_up" = ` + wantUp + ` ] && [ "${SH_R_W[*]}" = "` + wantW + `" ] && [ "$fb_switched" = ` + sw + ` ] || { echo "t+` + itoa(now) + `: up=$fb_up w=${SH_R_W[*]} sw=$fb_switched want ` + wantUp + ` ` + wantW + ` ` + sw + `"; exit 1; }` + "\n")
	}
	all := []string{"m05", "m06", "m07"}
	bk := []string{"m06", "m07"}
	step(0, decMain, all, "main", "1000 0 0", -1)
	step(10, decBk, bk, "backup", "0 500 500", 10)
	// (a) The controller fails, main still down: the backup group stays.
	for now := 15; now <= 400; now += 5 {
		step(now, "", bk, "backup", "0 500 500", 10)
	}
	// (b) The controller switches back and forth; main recovers right after
	// its switch at t+500: 3 consecutive passes and COOLDOWN since t+500.
	step(450, decMain, all, "main", "1000 0 0", 450)
	step(500, decBk, all, "backup", "0 500 500", 500)
	for now := 505; now < 620; now += 5 {
		step(now, "", all, "backup", "0 500 500", 500)
	}
	step(620, "", all, "main", "1000 0 0", 620)
	// Long after the controller's switch, main answering while the
	// controller still holds backup is no evidence: 3 passes of its own.
	step(700, decBk, bk, "backup", "0 500 500", 700)
	step(1000, decBk, all, "backup", "0 500 500", 700)
	step(1005, "", all, "backup", "0 500 500", 700)
	step(1010, "", all, "backup", "0 500 500", 700)
	step(1015, "", all, "main", "1000 0 0", 1015)
	// (c) The shell switches to backup; the controller recovers on main:
	// main is in again, the switch time is the controller's, and a later
	// fallback needs FAILS_NEED passes down before leaving main.
	step(1020, "", bk, "main", "1000 0 0", 1015)
	step(1025, "", bk, "main", "1000 0 0", 1015)
	step(1030, "", bk, "backup", "0 500 500", 1030)
	step(1035, decMain, all, "main", "1000 0 0", 1035)
	step(1040, "", bk, "main", "1000 0 0", 1035)
	step(1045, "", bk, "main", "1000 0 0", 1035)
	step(1050, "", bk, "backup", "0 500 500", 1050)
	step(1055, "", all, "backup", "0 500 500", 1050)
	step(1060, "", all, "backup", "0 500 500", 1050)
	step(1065, "", all, "backup", "0 500 500", 1050)
	step(1170, "", all, "main", "1000 0 0", 1170)
	if out, err := l.bash(sb.String()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
