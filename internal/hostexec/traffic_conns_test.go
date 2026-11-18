package hostexec

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Gateway: LAN 192.168.50.5, transit 10.66.200.1 (local on wg), WAN-side none.
// Clients: 192.168.50.20 (LAN), 10.77.0.2 (remote access).
const sampleConntrack = `ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=142.250.1.1 sport=50000 dport=443 src=142.250.1.1 dst=10.66.200.1 sport=443 dport=50000 [ASSURED] mark=257 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=110.242.68.66 sport=50001 dport=443 src=110.242.68.66 dst=192.168.50.20 sport=443 dport=50001 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 30 src=10.77.0.2 dst=223.5.5.5 sport=40000 dport=443 src=223.5.5.5 dst=10.77.0.2 sport=443 dport=40000 mark=0 zone=0 use=2
ipv6     10 tcp      6 300 ESTABLISHED src=fd00::20 dst=2001:db8::1 sport=50002 dport=443 src=2001:db8::1 dst=fd66:0:0:ff::1 sport=443 dport=50002 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 100 TIME_WAIT src=192.168.50.20 dst=142.250.1.2 sport=50003 dport=443 src=142.250.1.2 dst=10.66.200.1 sport=443 dport=50003 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 170 src=192.168.50.5 dst=203.0.113.9 sport=51820 dport=51820 src=203.0.113.9 dst=192.168.50.5 sport=51820 dport=51820 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=142.250.1.3 sport=50004 dport=443 src=192.168.50.5 dst=192.168.50.20 sport=12345 dport=50004 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.5 dst=142.250.1.3 sport=40001 dport=443 src=142.250.1.3 dst=10.66.200.1 sport=443 dport=40001 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 20 src=192.168.50.20 dst=8.8.8.8 sport=5353 dport=53 src=192.168.50.5 dst=192.168.50.20 sport=53 dport=5353 mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=192.168.50.5 sport=50005 dport=8080 src=192.168.50.5 dst=192.168.50.20 sport=8080 dport=50005 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 170 src=203.0.113.50 dst=192.168.50.5 sport=4000 dport=51821 src=192.168.50.5 dst=203.0.113.50 sport=51821 dport=4000 [ASSURED] mark=0 zone=0 use=2
garbage line
`

func sampleLocal() map[netip.Addr]bool {
	return map[netip.Addr]bool{netip.MustParseAddr("192.168.50.5"): true, netip.MustParseAddr("10.66.200.1"): true, netip.MustParseAddr("127.0.0.1"): true}
}

func TestCountConntrack(t *testing.T) {
	d, f, r := CountConntrack(sampleConntrack, sampleLocal())
	// foreign: v4 transit, v6 transit; domestic: LAN direct, remote-access UDP;
	// redirected: the sniff leg. Excluded: TIME_WAIT, gateway WG/forwarder
	// outbound, DNS hijack, panel, inbound remote-access WG.
	if d != 2 || f != 2 || r != 1 {
		t.Fatalf("d=%d f=%d r=%d", d, f, r)
	}
	// conntrack -L -o extended prints the same tuples.
	ext := sampleConntrack + "conntrack v1.4.7 (conntrack-tools): 11 flow entries have been shown.\n"
	if d2, f2, r2 := CountConntrack(ext, sampleLocal()); d2 != d || f2 != f || r2 != r {
		t.Fatal("extended output differs")
	}
}

func TestConnStatusSources(t *testing.T) {
	oldP, oldL := conntrackPath, localAddrsFunc
	defer func() { conntrackPath, localAddrsFunc = oldP, oldL }()
	localAddrsFunc = func() (map[netip.Addr]bool, error) { return sampleLocal(), nil }
	dir := t.TempDir()
	conntrackPath = filepath.Join(dir, "nf_conntrack")
	if err := os.WriteFile(conntrackPath, []byte(sampleConntrack), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &trafficRunner{}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: r}
	c := a.ConnStatus(context.Background())
	if c.Source != "proc" || *c.Total != 5 || len(r.cmds) != 0 {
		t.Fatalf("%+v %v", c, r.cmds)
	}
	conntrackPath = filepath.Join(dir, "absent")
	r.out = sampleConntrack
	c = a.ConnStatus(context.Background())
	if c.Source != "conntrack" || *c.Foreign != 2 || len(r.cmds) != 1 || r.cmds[0] != "conntrack -L -o extended" {
		t.Fatalf("%+v %v", c, r.cmds)
	}
	r.err = errors.New("not found")
	c = a.ConnStatus(context.Background())
	if c.Error == "" || c.Total != nil || c.Domestic != nil {
		t.Fatalf("%+v", c)
	}
}

// Every field comes from the right tuple: realistic proc lines (with
// [ASSURED], [UNREPLIED], mark=, zone=, use=, secctx-less) and the
// `conntrack -L -o extended` form.
func TestParseConntrackTuples(t *testing.T) {
	type want struct {
		proto, state string
		orig, reply  ctTuple
	}
	tp := func(s, d, sp, dp string) ctTuple {
		return ctTuple{src: netip.MustParseAddr(s), dst: netip.MustParseAddr(d), sport: sp, dport: dp}
	}
	cases := map[string]want{
		"ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=192.168.50.5 sport=50010 dport=853 src=192.168.50.5 dst=192.168.50.20 sport=853 dport=50010 [ASSURED] mark=0 zone=0 use=2": {"tcp", "ESTABLISHED", tp("192.168.50.20", "192.168.50.5", "50010", "853"), tp("192.168.50.5", "192.168.50.20", "853", "50010")},
		"ipv6     10 tcp      6 300 ESTABLISHED src=fd00::20 dst=2001:db8::1 sport=50002 dport=443 src=2001:db8::1 dst=fd66:0:0:ff::1 sport=443 dport=50002 [ASSURED] mark=257 zone=0 use=2":       {"tcp", "ESTABLISHED", tp("fd00::20", "2001:db8::1", "50002", "443"), tp("2001:db8::1", "fd66:0:0:ff::1", "443", "50002")},
		"ipv4     2 udp      17 25 src=192.168.50.20 dst=8.8.8.8 sport=5353 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.50.20 sport=53 dport=5353 mark=0 zone=3 use=1":                            {"udp", "", tp("192.168.50.20", "8.8.8.8", "5353", "53"), tp("8.8.8.8", "192.168.50.20", "53", "5353")},
		"ipv6     10 udp      17 170 src=fd00::20 dst=2001:db8::53 sport=40000 dport=443 src=2001:db8::53 dst=fd00::20 sport=443 dport=40000 [ASSURED] mark=0 zone=0 use=2":                        {"udp", "", tp("fd00::20", "2001:db8::53", "40000", "443"), tp("2001:db8::53", "fd00::20", "443", "40000")},
		// conntrack -L -o extended
		"ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=142.250.1.1 sport=50000 dport=443 src=142.250.1.1 dst=10.66.200.1 sport=443 dport=50000 [ASSURED] mark=0 use=1": {"tcp", "ESTABLISHED", tp("192.168.50.20", "142.250.1.1", "50000", "443"), tp("142.250.1.1", "10.66.200.1", "443", "50000")},
		"ipv6     10 tcp      6 119 SYN_SENT src=fd00::20 dst=fd00::5 sport=50011 dport=53 [UNREPLIED] src=fd00::5 dst=fd00::20 sport=53 dport=50011 mark=0 use=1":                      {"tcp", "SYN_SENT", tp("fd00::20", "fd00::5", "50011", "53"), tp("fd00::5", "fd00::20", "53", "50011")},
	}
	for line, w := range cases {
		proto, state, o, r, ok := parseConntrackLine(line)
		if !ok || proto != w.proto || state != w.state || o != w.orig || r != w.reply {
			t.Errorf("%s\n got %v %q %q %+v %+v", line, ok, proto, state, o, r)
		}
	}
}

// TCP 53/853 hijacked to the gateway (original destination elsewhere,
// reply from the gateway) is DNS, never redirected or in total; a
// sniff-forwarded 443 is redirected. Proc and extended forms agree.
func TestCountConntrackDNSHijackExcluded(t *testing.T) {
	local := sampleLocal()
	local[netip.MustParseAddr("fd00::5")] = true
	text := `ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=8.8.8.8 sport=50020 dport=53 src=192.168.50.5 dst=192.168.50.20 sport=53 dport=50020 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=1.1.1.1 sport=50021 dport=853 src=192.168.50.5 dst=192.168.50.20 sport=853 dport=50021 [ASSURED] mark=0 zone=0 use=2
ipv6     10 tcp      6 431999 ESTABLISHED src=fd00::20 dst=2001:4860:4860::8888 sport=50022 dport=853 src=fd00::5 dst=fd00::20 sport=853 dport=50022 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.20 dst=142.250.1.3 sport=50023 dport=443 src=192.168.50.5 dst=192.168.50.20 sport=12345 dport=50023 [ASSURED] mark=0 zone=0 use=2
`
	if d, f, r := CountConntrack(text, local); d != 0 || f != 0 || r != 1 {
		t.Fatalf("proc d=%d f=%d r=%d", d, f, r)
	}
	ext := strings.ReplaceAll(text, " zone=0 use=2", " use=1") +
		"conntrack v1.4.8 (conntrack-tools): 4 flow entries have been shown.\n"
	if d, f, r := CountConntrack(ext, local); d != 0 || f != 0 || r != 1 {
		t.Fatalf("extended d=%d f=%d r=%d", d, f, r)
	}
}

// Proc file absent and the conntrack command missing: no counts, an error
// naming the package (the API maps it to code read_failed).
func TestConnStatusConntrackMissing(t *testing.T) {
	oldP, oldL := conntrackPath, localAddrsFunc
	defer func() { conntrackPath, localAddrsFunc = oldP, oldL }()
	localAddrsFunc = func() (map[netip.Addr]bool, error) { return sampleLocal(), nil }
	conntrackPath = filepath.Join(t.TempDir(), "absent")
	r := &trafficRunner{err: errors.New(`exec: "conntrack": executable file not found in $PATH`)}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: r}
	c := a.ConnStatus(context.Background())
	if c.Total != nil || c.Domestic != nil || c.Foreign != nil || c.Redirected != nil || c.Source != "" ||
		!strings.Contains(c.Error, "conntrack 软件包") || !strings.Contains(c.Error, "apt-get install conntrack") {
		t.Fatalf("%+v", c)
	}
}

// The host install puts the conntrack command (package conntrack) in place.
func TestInstallScriptInstallsConntrack(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "debian", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "apt-get install -y ") {
			for _, f := range strings.Fields(line) {
				if f == "conntrack" {
					return
				}
			}
			t.Fatalf("install list lacks conntrack: %s", line)
		}
	}
	t.Fatal("no apt-get install line")
}
