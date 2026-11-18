package compile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
	"github.com/radowitz/meridian/internal/preflight"
)

func TestSpeedEndpointOnSharingRelaysOnly(t *testing.T) {
	b, _ := sharedBundle(t)
	sock := b.File("nodes/access/etc/systemd/system/" + SpeedSocketUnit)
	for _, want := range []string{"ListenStream=10.66.3.2:9277\n", "ListenStream=10.66.102.2:9277\n", "Accept=yes\n", "IPAddressDeny=any\n", "IPAddressAllow=10.66.3.1/32\n", "IPAddressAllow=10.66.102.1/32\n", "FreeBind=yes\n"} {
		if !strings.Contains(sock, want) {
			t.Errorf("socket lacks %q:\n%s", want, sock)
		}
	}
	if strings.Contains(sock, "0.0.0.0") || strings.Contains(sock, "[::]") {
		t.Errorf("socket binds a wildcard:\n%s", sock)
	}
	svc := b.File("nodes/access/etc/systemd/system/" + SpeedServiceUnit)
	if !strings.Contains(svc, "ExecStart=/usr/bin/head -c 20971520 /dev/zero\n") || !strings.Contains(svc, "DynamicUser=yes") || !strings.Contains(svc, "RuntimeMaxSec=") {
		t.Errorf("service:\n%s", svc)
	}
	// Only the fixed size, no input: no %i / $ / arguments from the connection.
	if strings.ContainsAny(strings.SplitN(svc, "ExecStart=", 2)[1][:40], "%$") {
		t.Error("service takes input")
	}
	nft := b.File("nodes/access/etc/nftables.d/meridian.nft")
	for _, want := range []string{
		`iifname "m02" ip saddr 10.66.3.1 ip daddr 10.66.3.2 tcp dport 9277 accept`,
		`iifname "m02w" ip saddr 10.66.102.1 ip daddr 10.66.102.2 tcp dport 9277 accept`,
		"    tcp dport 9277 drop comment",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("relay nft lacks %q", want)
		}
	}
	if !strings.Contains(b.File("nodes/access/usr/local/sbin/meridian-up.sh"), "enable_unit "+SpeedSocketUnit) {
		t.Error("meridian-up.sh does not start the endpoint")
	}
	if !strings.Contains(b.File("nodes/gw/etc/nftables.d/meridian.nft"), "ip daddr { 10.66.3.2, 10.66.102.2, 10.66.4.2 } tcp dport 9277 drop") {
		t.Error("gateway forwards to the endpoints")
	}
	for _, n := range []string{"gw", "ix", "hkb"} {
		if b.File("nodes/"+n+"/etc/systemd/system/"+SpeedSocketUnit) != "" {
			t.Errorf("%s got the endpoint", n)
		}
	}
	// The footprint owns the socket (enabled, withdrawn) and its listens;
	// the template is a plain file.
	fp := preflight.FootprintOf(speedNodeFiles(b, "access"))
	hasUnit := func(u string) bool {
		for _, x := range fp.Units {
			if x == u {
				return true
			}
		}
		return false
	}
	if !hasUnit(SpeedSocketUnit) || hasUnit(SpeedServiceUnit) {
		t.Errorf("units %v", fp.Units)
	}
	n := 0
	for _, l := range fp.Listens {
		if l.Port == pathquality.SpeedPort && l.Proto == "tcp" && !l.Wildcard {
			n++
		}
	}
	if n != 2 {
		t.Errorf("listens %+v", fp.Listens)
	}
	// The controller config carries the leg addresses and the port.
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil || cfg.SpeedPort != pathquality.SpeedPort || cfg.Relays[0].Legs[1].Remote != "10.66.102.2" || cfg.Relays[0].Legs[1].Local != "10.66.102.1" {
		t.Fatalf("%v %+v", err, cfg.Relays)
	}
}

func speedNodeFiles(b *Bundle, node string) map[string]string {
	out := map[string]string{}
	pre := "nodes/" + node
	for p, c := range b.Files {
		if strings.HasPrefix(p, pre+"/") {
			out[strings.TrimPrefix(p, pre)] = c
		}
	}
	return out
}

func TestSpeedEndpointWithdrawnWhenOff(t *testing.T) {
	topo := sharedTopo(t)
	topo.Settings.PathQuality = &model.PathQuality{SpeedTestOff: true}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	for p, c := range b.Files {
		if strings.Contains(p, "speedtest") || strings.Contains(c, "9277") || strings.Contains(c, "path-speedtest") && !strings.Contains(c, "SH_QOS_ON=0") {
			t.Errorf("%s still has the speed test", p)
		}
	}
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil || cfg.SpeedPort != 0 || cfg.Relays[0].Legs[0].Remote != "" {
		t.Fatalf("%v %+v", err, cfg)
	}
}

// The shell fallback reads only the saved verdict: throttled relays carry
// nothing while another reachable relay does; all throttled → the fastest
// alone; reachability alone decides the backup; a broken file is ignored.
// The same inputs give the Go controller's steady state.
func TestShareFallbackReadsQoSLikeGo(t *testing.T) {
	l := newShellLab(t)
	qos := filepath.Join(l.ctrl, "qos")
	l.prog += "QOS_FILE=" + qos + "\n"
	write := func(a, b string, ak, bk int) {
		_, p := sharedBundle(t)
		c := pathquality.Config{Relays: []pathquality.RelayConfig{{ID: p.Relays[0].Node.ID}, {ID: p.Relays[1].Node.ID}}}
		v := map[string]*pathquality.QoSVerdict{
			"access":  {State: a, LastKbps: ak, LastAt: 1700000000, BaselineKbps: 180000, BaselineSrc: "p90"},
			"access2": {State: b, LastKbps: bk, LastAt: 1700000000, BaselineKbps: 180000, BaselineSrc: "p90"},
		}
		if err := os.WriteFile(qos, []byte(pathquality.FormatQoS(c, v)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(up []string, wantW, wantUp string) hostexec.UpstreamState {
		t.Helper()
		script := "rm -f " + l.ctrl + "/up-*\n"
		for _, u := range up {
			script += "touch " + l.ctrl + "/up-" + u + "\n"
		}
		script += "for i in 1 2 3 4 5 6; do share_step; done\n" +
			`[ "${SH_R_W[*]}" = "` + wantW + `" ] && [ "$fb_up" = ` + wantUp + ` ] || { echo "w=${SH_R_W[*]} up=$fb_up"; exit 1; }` + "\ncat " + l.run + "/upstream\n"
		out, err := l.bash(script)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		st, err := hostexec.ParseUpstream(out[strings.Index(out, "meridian-upstream 2"):])
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return st
	}
	write("ok", "throttled", 150000, 9000)
	st := run([]string{"m02", "m03", "m04"}, "1000 0", "main")
	if st.Relays[1].Reason != "qos_throttled" || st.Relays[1].QoS != "throttled" || *st.Relays[1].SpeedKbps != 9000 {
		t.Fatalf("%+v", st.Relays[1])
	}
	write("throttled", "throttled", 8000, 9000)
	st = run([]string{"m02", "m03", "m04"}, "0 1000", "main")
	if st.Relays[1].Reason != "retained_best" {
		t.Fatalf("%+v", st.Relays)
	}
	// Garbage: ignored, equal shares.
	if err := os.WriteFile(qos, []byte("meridian-qos 1\nrelay access throttled 0 5 1 1 p90\nend\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run([]string{"m02", "m03", "m04"}, "500 500", "main")

	// Go: same verdicts, steady state.
	b, _ := sharedBundle(t)
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a, b   string
		ak, bk int
		want   [2]int
	}{{"ok", "throttled", 150000, 9000, [2]int{1000, 0}}, {"throttled", "throttled", 8000, 9000, [2]int{0, 1000}}} {
		var st *pathquality.State
		var d pathquality.Decision
		for i := int64(0); i < 10; i++ {
			m := pathquality.Measurement{Now: 1700000005 + 5*i, Relays: map[string]pathquality.PathSample{
				"access":  {Legs: []pathquality.LegSample{{Iface: "m02", Sent: 5, Recv: 5, RTTus: 30000}, {Iface: "m02w", Sent: 5, Recv: 5, RTTus: 30000}}},
				"access2": {Legs: []pathquality.LegSample{{Iface: "m03", Sent: 5, Recv: 5, RTTus: 30000}}},
			}, Backup: &pathquality.PathSample{Legs: []pathquality.LegSample{{Iface: "m04", Sent: 5, Recv: 5, RTTus: 60000}}},
				QoS: map[string]pathquality.QoSEntry{
					"access":  {ID: "access", State: tc.a, LastKbps: tc.ak, LastAt: 1700000000, BaselineKbps: 180000, BaselineSrc: "p90"},
					"access2": {ID: "access2", State: tc.b, LastKbps: tc.bk, LastAt: 1700000000, BaselineKbps: 180000, BaselineSrc: "p90"},
				}}
			st, d = pathquality.Step(cfg, st, m)
		}
		if d.Relays[0].Weight != tc.want[0] || d.Relays[1].Weight != tc.want[1] || d.Upstream != "main" {
			t.Fatalf("go %v: %+v", tc, d)
		}
	}
}
