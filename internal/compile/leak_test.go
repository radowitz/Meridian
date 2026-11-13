package compile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

func TestGatewayFailClosed(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	routes := b.File("nodes/gw/usr/local/sbin/meridian-routes.sh")
	dns := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	wg := fileContaining(b, "nodes/gw/etc/wireguard/", "Table = off")

	for _, needle := range []string{
		"ip6 daddr fc00::/7 drop",
		"ip daddr 10.66.0.0/16 drop",
		"tcp option maxseg size > 1320 tcp option maxseg size set 1320",
		"udp dport { 53, 853 } redirect to :53",
		"tcp dport 853 redirect to :853",
		"ip saddr != 192.168.100.0/24 drop",
		"meta mark set 0x64",
	} {
		if !strings.Contains(nft, needle) {
			t.Errorf("nft missing %q", needle)
		}
	}
	if strings.Contains(nft, "flush ruleset") {
		t.Fatal("nft flushes the ruleset")
	}
	for _, needle := range []string{
		"blackhole default metric 32767 table 102",
		"blackhole fd66::/48 metric 32767",
		"fwmark 0x4d72 lookup main",
		"fwmark 0x101 unreachable",
		"table 100",
	} {
		if !strings.Contains(routes, needle) {
			t.Errorf("routes missing %q", needle)
		}
	}
	for _, line := range strings.Split(routes, "\n") {
		if strings.Contains(line, "fd66") && strings.Contains(line, "192.168.100.1") {
			t.Fatalf("ULA pointed at ROS: %s", line)
		}
	}
	if strings.Contains(dns, "server 10.66.") {
		t.Fatal("gateway DNS must not query an unrouted tunnel v4 address")
	}
	if strings.Contains(dns, "192.168.100.1") {
		t.Fatal("gateway DNS falls back to ROS")
	}
	if !strings.Contains(dns, "bind [::]:53") {
		t.Fatal("smartdns does not listen for hijacked IPv6 queries")
	}
	if !strings.Contains(wg, "FwMark = 0x4d72") {
		t.Fatal("gateway wireguard has no outer fwmark")
	}
	if nftBin, err := exec.LookPath("nft"); err == nil {
		for path := range b.Files {
			if !strings.HasSuffix(path, ".nft") {
				continue
			}
			cmd := exec.Command(nftBin, "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(b.File(path))
			out, err := cmd.CombinedOutput()
			if err != nil && strings.Contains(string(out), "Operation not permitted") {
				t.Log("nft -c needs CAP_NET_ADMIN; syntax was not checked")
				return
			}
			if err != nil {
				t.Errorf("nft -c %s: %v\n%s\n%s", path, err, out, b.File(path))
			}
		}
	}
	// VPS configs must not grow a gateway fwmark rule that could capture
	// packets an existing Shadowsocks policy route is using.
	ali := b.File("nodes/ali/usr/local/sbin/meridian-routes.sh")
	if strings.Contains(ali, "fwmark 0x4d72") {
		t.Fatal("relay script installs the gateway underlay mark")
	}
	if !strings.Contains(ali, "blackhole default metric 32767 table 150") {
		t.Fatal("relay foreign table can fall through to the VPS default route")
	}
}

func TestShellScriptsParse(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	for path, body := range b.Files {
		if !strings.HasSuffix(path, ".sh") {
			continue
		}
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", path, err, out)
		}
	}
}

func TestWSSLegDoesNotInheritUDPMTU(t *testing.T) {
	topo := defaults.Example()
	for i := range topo.Links {
		if topo.Links[i].Transport == model.TransportUDPWSSFailover {
			topo.Links[i].MTU = 1412
			topo.Links[i].WSSMTU = 0
		}
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	wss := fileContaining(b, "nodes/gw/etc/wireguard/", "mode wss")
	if !strings.Contains(wss, "MTU = 1360") {
		t.Fatalf("WSS leg picked up the UDP MTU:\n%s", wss)
	}
}

// nftBlock returns the body of "table inet <name> { ... }" up to its
// closing brace at column 0.
func nftBlock(t *testing.T, nft, name string) string {
	t.Helper()
	head := "table inet " + name + " {\n"
	i := strings.Index(nft, head)
	if i < 0 {
		t.Fatalf("no %q in:\n%s", head, nft)
	}
	j := strings.Index(nft[i:], "\n}\n")
	if j < 0 {
		t.Fatalf("table %s is not closed", name)
	}
	return nft[i : i+j+3]
}

// Every rendered nft file must replace its tables inside its own batch:
// create-if-absent, delete, recreate. A table may not be defined twice and
// nothing outside Meridian's tables may be deleted or flushed.
func TestNFTAtomicReplace(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for path, body := range b.Files {
		if !strings.HasSuffix(path, ".nft") {
			continue
		}
		n++
		if strings.Contains(body, "flush ruleset") || strings.Contains(body, "flush table") {
			t.Errorf("%s flushes", path)
		}
		tables := []string{"meridian"}
		switch {
		case strings.HasSuffix(path, "/meridian-guard.nft"):
			// Early-boot guard only (meridian-guard.service).
			tables = []string{"meridian_guard"}
			if strings.Contains(body, "table inet meridian {") {
				t.Errorf("%s: the early-boot file must not carry the main table", path)
			}
		case strings.HasPrefix(path, "nodes/gw/"):
			tables = []string{"meridian_guard", "meridian"}
		}
		last := -1
		for _, tb := range tables {
			idiom := "table inet " + tb + "\ndelete table inet " + tb + "\ntable inet " + tb + " {\n"
			at := strings.Index(body, idiom)
			if at < 0 {
				t.Errorf("%s: table %s is not replaced atomically:\n%s", path, tb, body)
				continue
			}
			if strings.Count(body, "table inet "+tb+" {") != 1 {
				t.Errorf("%s: table %s defined more than once", path, tb)
			}
			if at < last {
				t.Errorf("%s: guard must come before the table it backs up", path)
			}
			last = at
		}
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "delete ") && !strings.HasPrefix(line, "delete table inet meridian") {
				t.Errorf("%s: unexpected delete %q", path, line)
			}
		}
	}
	if n == 0 {
		t.Fatal("no nft files rendered")
	}
}

// The guard sits in its own table, references nothing in table inet
// meridian, and only lets domestic-marked traffic out of the LAN NIC and
// exit-marked traffic into a gateway WireGuard interface. Everything else
// forwarded from the LAN, either family, is dropped.
func TestGatewayGuardStructure(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	guard := nftBlock(t, nft, "meridian_guard")
	if strings.Contains(guard, "@") || strings.Contains(guard, "jump") || strings.Contains(guard, "goto") {
		t.Fatalf("guard depends on another table's sets or chains:\n%s", guard)
	}
	if strings.Count(guard, "type filter hook") != 1 || !strings.Contains(guard, "type filter hook forward priority -200; policy accept;") {
		t.Fatalf("guard must be one forward base chain at priority -200:\n%s", guard)
	}
	// It must sort ahead of every forward chain in the replaced table.
	main := nftBlock(t, nft, "meridian")
	for _, line := range strings.Split(main, "\n") {
		if !strings.Contains(line, "hook forward") {
			continue
		}
		if !strings.Contains(line, "priority mangle") && !strings.Contains(line, "priority filter") {
			t.Errorf("unexpected forward priority in main table: %s", line)
		}
	}
	var rules []string
	for _, line := range strings.Split(guard, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "iifname") {
			rules = append(rules, line)
		}
	}
	if len(rules) != 4 {
		t.Fatalf("want 4 guard rules, got %d:\n%s", len(rules), guard)
	}
	for _, r := range rules {
		if !strings.HasPrefix(r, `iifname "eth0" `) {
			t.Errorf("guard rule not scoped to the LAN NIC: %s", r)
		}
		if strings.Contains(r, " accept") {
			t.Errorf("guard must not accept, only return or drop: %s", r)
		}
	}
	if !strings.Contains(rules[0], "th dport { 53, 853 } drop") {
		t.Errorf("first rule should drop forwarded DNS: %s", rules[0])
	}
	if !strings.Contains(rules[1], `meta mark 0x64 oifname "eth0" return`) {
		t.Errorf("domestic path must be limited to the LAN NIC: %s", rules[1])
	}
	var ifaces []string
	for path := range b.Files {
		if strings.HasPrefix(path, "nodes/gw/etc/wireguard/") {
			ifaces = append(ifaces, `"`+strings.TrimSuffix(filepath.Base(path), ".conf")+`"`)
		}
	}
	sort.Strings(ifaces)
	want := "meta mark 0x101-0x140 oifname { " + strings.Join(ifaces, ", ") + " } return"
	if !strings.Contains(rules[2], want) {
		t.Errorf("exit path should be %q, got %s", want, rules[2])
	}
	if strings.Count(rules[2], `"eth0"`) > 1 {
		t.Errorf("exit marks may not leave on the LAN NIC: %s", rules[2])
	}
	// The final drop has no family qualifier, so it covers IPv4 and IPv6.
	if rules[3] != `iifname "eth0" counter drop comment "fail closed: unclassified or misrouted LAN traffic, v4 and v6"` {
		t.Errorf("last guard rule must be an unqualified drop: %s", rules[3])
	}
	// No "iif <LAN> unreachable" rule in either family: the kernel's source
	// validation of a packet forwarded OUT of the LAN NIC looks the source
	// up with that iif and mark 0, so the IPv4 rule dropped domestic
	// traffic and tunnel replies (EXDEV). The guard above is what closes
	// the main-table default via ROS, v4 and v6; the per-mark unreachable
	// rules keep classified traffic out of main.
	assertNoIIFRules(t, b.File("nodes/gw/usr/local/sbin/meridian-routes.sh"))
}

// assertNoIIFRules: the gateway routes script adds no "iif" policy rule,
// deletes the two that older versions installed (by priority, interface
// and action), and keeps an unreachable rule behind every exit mark.
func assertNoIIFRules(t *testing.T, routes string) {
	t.Helper()
	for _, l := range strings.Split(routes, "\n") {
		if strings.Contains(l, "rule add") && strings.Contains(l, " iif ") {
			t.Errorf("routes add an iif rule (breaks source validation of forwarded IPv4): %s", l)
		}
	}
	for _, need := range []string{
		"del_rule ip -4 rule del priority 17850 iif 'eth0' unreachable\n",
		"del_rule ip -4 rule del priority 17851 iif mra unreachable\n",
		"ip rule add fwmark 0x101 unreachable priority 17600\n",
		"ip -6 rule add fwmark 0x101 unreachable priority 17600\n",
	} {
		if !strings.Contains(routes, need) {
			t.Errorf("routes missing %q", need)
		}
	}
}

func TestGuardExitRange(t *testing.T) {
	if got := guardLastExitMark(nil); got != 0x140 {
		t.Fatalf("default last mark %#x", got)
	}
	if got := guardLastExitMark([]ExitPlan{{Mark: 0x150}}); got != 0x150 {
		t.Fatalf("guard must widen to cover every exit mark, got %#x", got)
	}
	var sb strings.Builder
	writeGuardTable(&sb, "lan0", nil, 0x140, nil)
	if strings.Contains(sb.String(), "0x101-") {
		t.Fatalf("no tunnel interfaces, no exit return path:\n%s", sb.String())
	}
	if !strings.Contains(sb.String(), `iifname "lan0" counter drop`) {
		t.Fatal("guard without tunnels must still drop")
	}
}

// meridian-up must load the firewall before forwarding and routes, in one
// nft -f after an nft -c, with no separate delete.
func TestUpScriptLoadsFirewallFirst(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for path, up := range b.Files {
		if !strings.HasSuffix(path, "/usr/local/sbin/meridian-up.sh") {
			continue
		}
		if strings.Contains(up, "delete table") {
			t.Errorf("%s still deletes the table in a separate nft process", path)
		}
		for _, line := range strings.Split(up, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "if ! nft ") {
				l = strings.TrimPrefix(l, "if ! ")
			}
			if strings.HasPrefix(l, "nft ") &&
				!strings.HasPrefix(l, `nft -c -f "$MERIDIAN_NFT"`) &&
				!strings.HasPrefix(l, `nft -f "$MERIDIAN_NFT"`) &&
				!strings.HasPrefix(l, "nft list table ") {
				t.Errorf("%s: extra nft command outside the batch: %s", path, l)
			}
		}
		check := strings.Index(up, `nft -c -f "$MERIDIAN_NFT"`)
		load := strings.Index(up, `nft -f "$MERIDIAN_NFT"`)
		if check < 0 || load < 0 || check > load {
			t.Errorf("%s: nft -c must run before nft -f", path)
			continue
		}
		for _, later := range []string{"sysctl --system", "wg-quick up", "/usr/local/sbin/meridian-routes.sh"} {
			if i := strings.Index(up, later); i >= 0 && i < load {
				t.Errorf("%s: %q runs before the firewall is loaded", path, later)
			}
		}
	}
}

// Runs the rendered gateway meridian-up.sh under bash with stub binaries.
// It cannot prove kernel batch semantics (see the Linux netns test); it
// proves the script stops before sysctl, WireGuard and routes whenever the
// check or the load fails, never issues a delete, and refuses to continue
// on the gateway without the guard table.
func TestUpScriptFailurePreservesState(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	up := b.File("nodes/gw/usr/local/sbin/meridian-up.sh")
	cases := []struct {
		name     string
		env      []string
		noFile   bool
		noSysd   bool
		wantOK   bool
		wantMsg  string
		wantLoad bool
		// wantTouch: the failure happens after sysctl/wg/routes ran.
		wantTouch bool
		// wantExit, when non-zero, is the required exit status.
		wantExit int
		// lanWait: only read-only "ip" queries may run after the load.
		lanWait bool
	}{
		{name: "check fails", env: []string{"NFT_FAIL_CHECK=1"}, wantMsg: "meridian-nft-check-failed"},
		{name: "load fails", env: []string{"NFT_FAIL_LOAD=1"}, wantMsg: "meridian-nft-load-failed", wantLoad: true},
		{name: "guard missing", env: []string{"NFT_NO_GUARD=1"}, wantMsg: "meridian-guard-missing", wantLoad: true},
		{name: "file missing", noFile: true, wantMsg: "meridian-nft-missing"},
		{name: "ok", wantOK: true, wantMsg: "meridian-up-complete", wantLoad: true},
		// Late DHCP at boot: the LAN never gets its address within the
		// bound. The script fails with its own marker and exit status, after
		// the firewall and guard, without forwarding or routes.
		{name: "lan address missing", env: []string{"LAN_NO_ADDR=1"}, wantMsg: "meridian-lan-not-ready", wantLoad: true, wantExit: LANNotReadyExit, lanWait: true},
		{name: "lan interface missing", env: []string{"LAN_NO_LINK=1"}, wantMsg: "meridian-lan-not-ready", wantLoad: true, wantExit: LANNotReadyExit, lanWait: true},
		{name: "ros not on-link", env: []string{"ROS_VIA=1"}, wantMsg: "meridian-lan-not-ready", wantLoad: true, wantExit: LANNotReadyExit, lanWait: true},
		// The address arrives while the script waits: it proceeds.
		{name: "lan address arrives late", env: []string{"LAN_ADDR_AFTER=2"}, wantOK: true, wantMsg: "meridian-up-complete", wantLoad: true},
		// Without systemd (the panel container) the failover unit cannot be
		// started: the script must fail, not report completion.
		{name: "no systemd", noSysd: true, wantMsg: "meridian-systemd-missing", wantLoad: true, wantTouch: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls.log")
			bin := filepath.Join(dir, "bin")
			for _, d := range []string{bin, filepath.Join(dir, "nftables.d"), filepath.Join(dir, "wireguard")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stub := func(name, body string) {
				script := "#!/bin/sh\necho \"" + name + " $*\" >> \"$CALL_LOG\"\n" + body
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stub("nft", `case "$1" in
  -c) [ -z "$NFT_FAIL_CHECK" ] || exit 1 ;;
  -f) [ -z "$NFT_FAIL_LOAD" ] || exit 1 ;;
  list) [ -z "$NFT_NO_GUARD" ] || exit 1 ;;
  *) exit 2 ;;
esac
exit 0
`)
			for _, name := range []string{"sysctl", "wg", "wg-quick", "openssl", "systemctl"} {
				stub(name, "exit 0\n")
			}
			// ip answers the LAN readiness queries like a ready gateway
			// unless told otherwise; every other ip call succeeds silently.
			// LAN_ADDR_AFTER=N: the address shows up on the N-th query.
			stub("ip", `case "$*" in
  "-o link show dev eth0")
    [ -z "$LAN_NO_LINK" ] || exit 1
    echo "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP" ;;
  "-4 -o addr show dev eth0")
    if [ -n "$LAN_ADDR_AFTER" ]; then
      n=$(cat "$CALL_LOG.addr" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$CALL_LOG.addr"
      [ "$n" -ge "$LAN_ADDR_AFTER" ] || exit 0
    fi
    [ -n "$LAN_NO_ADDR" ] || echo "2: eth0    inet 192.168.100.88/24 brd 192.168.100.255 scope global eth0" ;;
  "-4 route get 192.168.100.1")
    if [ -n "$ROS_VIA" ]; then echo "192.168.100.1 via 192.168.100.254 dev eth0 src 192.168.100.88"; else echo "192.168.100.1 dev eth0 src 192.168.100.88 uid 0"; fi ;;
esac
exit 0
`)
			routes := filepath.Join(dir, "routes.sh")
			if err := os.WriteFile(routes, []byte("#!/bin/sh\necho routes >> \"$CALL_LOG\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			// The manifest's WireGuard configs, the forwarding file and a
			// systemd marker exist, as after a real install on a systemd host.
			sysd := []string{"etc-meridian", "run-systemd"}
			if tc.noSysd {
				sysd = sysd[:1]
			}
			for _, d := range sysd {
				if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for p, body := range b.Files {
				if strings.HasPrefix(p, "nodes/gw/etc/wireguard/") {
					if err := os.WriteFile(filepath.Join(dir, "wireguard", filepath.Base(p)), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "etc-meridian", "forwarding.conf"), []byte(b.File("nodes/gw/etc/meridian/forwarding.conf")), 0o644); err != nil {
				t.Fatal(err)
			}
			nftFile := filepath.Join(dir, "nftables.d", "meridian.nft")
			if !tc.noFile {
				if err := os.WriteFile(nftFile, []byte(b.File("nodes/gw/etc/nftables.d/meridian.nft")), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.NewReplacer(
				"/etc/nftables.d/meridian.nft", nftFile,
				"/usr/local/sbin/meridian-routes.sh", routes,
				"/etc/sysctl.d/99-meridian.conf", filepath.Join(dir, "sysctl.conf"),
				"/var/lib/meridian", filepath.Join(dir, "var"),
				"/etc/meridian", filepath.Join(dir, "etc-meridian"),
				"/etc/wireguard", filepath.Join(dir, "wireguard"),
				"/run/systemd/system", filepath.Join(dir, "run-systemd"),
			).Replace(up)
			cmd := exec.Command(bash, "-c", script)
			cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "CALL_LOG=" + log, "MERIDIAN_LAN_WAIT_SEC=3"}, tc.env...)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("exit err=%v, want ok=%v\n%s", err, tc.wantOK, out)
			}
			if tc.wantExit != 0 {
				var ee *exec.ExitError
				if !errors.As(err, &ee) || ee.ExitCode() != tc.wantExit {
					t.Fatalf("exit %v, want status %d\n%s", err, tc.wantExit, out)
				}
			}
			if !strings.Contains(string(out), tc.wantMsg) {
				t.Fatalf("output missing %q:\n%s", tc.wantMsg, out)
			}
			raw, _ := os.ReadFile(log)
			calls := string(raw)
			if strings.Contains(calls, "delete") {
				t.Fatalf("script issued a delete:\n%s", calls)
			}
			loaded := strings.Contains(calls, "nft -f ")
			if loaded != tc.wantLoad {
				t.Fatalf("nft -f called=%v, want %v:\n%s", loaded, tc.wantLoad, calls)
			}
			touched := false
			for _, line := range strings.Split(calls, "\n") {
				if tc.lanWait && (line == "ip -o link show dev eth0" || line == "ip -4 -o addr show dev eth0" || line == "ip -4 route get 192.168.100.1") {
					continue // read-only readiness queries
				}
				for _, p := range []string{"sysctl ", "routes", "wg ", "wg-quick ", "ip "} {
					if strings.HasPrefix(line, p) {
						touched = true
					}
				}
			}
			if tc.lanWait && !strings.Contains(calls, "ip -o link show dev eth0") {
				t.Fatalf("LAN readiness was never queried:\n%s", calls)
			}
			if (tc.wantOK || tc.wantTouch) != touched {
				t.Fatalf("sysctl/wg/routes touched=%v after outcome ok=%v:\n%s", touched, tc.wantOK, calls)
			}
			if tc.wantOK {
				order := []string{"nft -c -f", "nft -f", "nft list table inet meridian_guard", "ip -4 route get 192.168.100.1", "sysctl", "routes"}
				pos := -1
				for _, want := range order {
					i := strings.Index(calls, want)
					if i <= pos {
						t.Fatalf("call order wrong at %q:\n%s", want, calls)
					}
					pos = i
				}
			}
		})
	}
}

// Linux has no net.ipv6.conf.*.send_redirects; writing it only produced
// "skip sysctl" / "cannot stat" noise and a leak-check item that claimed a
// protection that did not exist. Nothing generated or installed may name it.
func TestNoIPv6SendRedirects(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range b.Files {
		if strings.Contains(body, "ipv6.conf") && strings.Contains(body, "send_redirects") {
			for _, line := range strings.Split(body, "\n") {
				if strings.Contains(line, "ipv6.conf") && strings.Contains(line, "send_redirects") && !strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
					t.Errorf("%s writes a key Linux does not have: %s", path, line)
				}
			}
		}
	}
	gw := b.File("nodes/gw/etc/sysctl.d/99-meridian.conf")
	if !strings.Contains(gw, "net.ipv4.conf.all.send_redirects=0") {
		t.Fatalf("IPv4 send_redirects must stay:\n%s", gw)
	}
	inst, err := os.ReadFile(filepath.Join("..", "..", "deploy", "debian", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(inst), "\n") {
		if strings.Contains(line, "ipv6.conf") && strings.Contains(line, "send_redirects") {
			t.Errorf("install.sh writes a key Linux does not have: %s", line)
		}
	}
}

// validate's rule_unreachable check mirrors what the classify chain drops
// before the rules. Every address the compiler puts into underlay4 must be
// reported for a rule that targets it, or the two have drifted apart.
func TestUnderlayRulesReportedUnreachable(t *testing.T) {
	topo := defaults.Example()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	nft := b.File("nodes/gw/etc/nftables.d/meridian.nft")
	i := strings.Index(nft, "set underlay4 {")
	if i < 0 {
		t.Fatal("no underlay4 set")
	}
	block := nft[i:]
	block = block[:strings.Index(block, "}\n")]
	j := strings.Index(block, "elements = { ")
	if j < 0 {
		t.Fatal("underlay4 is empty in the example")
	}
	elems := strings.Split(strings.TrimSuffix(strings.TrimSpace(block[j+len("elements = { "):]), " }"), ", ")
	for _, ep := range elems {
		ep = strings.TrimSpace(strings.TrimSuffix(ep, "}"))
		cand := topo
		cand.Rules = append(append([]model.Rule(nil), topo.Rules...), model.Rule{ID: "ep", Name: "ep", Manual: true, Enabled: true,
			MatchType: model.MatchCIDR, MatchValue: ep + "/32", TargetGroup: topo.Settings.DefaultGroup})
		found := false
		for _, iss := range validate.Run(cand).Issues {
			if iss.Code == "rule_unreachable" && iss.RuleID == "ep" {
				found = true
			}
		}
		if !found {
			t.Errorf("underlay endpoint %s: rule not reported unreachable", ep)
		}
	}
}
