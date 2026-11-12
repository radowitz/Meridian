package compile

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func exampleBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SmartDNS rejects per-bind certificate options ("unknown bind option:
// -cert-file") and fails when an IPv4-specific bind precedes the dual-stack
// [::] wildcard on the same port ("Address already in use"). The gateway
// config therefore has exactly one wildcard listener per port/protocol and
// the certificate as global bind-cert-* directives.
func TestGatewaySmartDNSBindsAndCertificate(t *testing.T) {
	conf := exampleBundle(t).File("nodes/gw/etc/smartdns/smartdns.conf")
	var binds []string
	for _, line := range strings.Split(conf, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		for _, w := range f {
			if w == "-cert-file" || w == "-key-file" {
				t.Fatalf("per-bind certificate option is rejected by SmartDNS: %s", l)
			}
		}
		if len(f) > 0 && (f[0] == "bind" || f[0] == "bind-tcp" || f[0] == "bind-tls") {
			if len(f) != 2 {
				t.Fatalf("bind line with options: %s", l)
			}
			binds = append(binds, f[0]+" "+f[1])
		}
	}
	want := []string{"bind [::]:53", "bind-tcp [::]:53", "bind-tls [::]:853"}
	if strings.Join(binds, "|") != strings.Join(want, "|") {
		t.Fatalf("binds = %v, want %v", binds, want)
	}
	certAt := strings.Index(conf, "\nbind-cert-file /etc/meridian/dns/cert.pem\n")
	keyAt := strings.Index(conf, "\nbind-cert-key-file /etc/meridian/dns/key.pem\n")
	tlsAt := strings.Index(conf, "\nbind-tls [::]:853\n")
	if certAt < 0 || keyAt < 0 || tlsAt < certAt || tlsAt < keyAt {
		t.Fatalf("certificate directives missing or after bind-tls:\n%s", conf)
	}
	refs := SmartDNSFileRefs(conf)
	for _, want := range []string{"/etc/meridian/dns/cert.pem", "/etc/meridian/dns/key.pem", "/var/lib/meridian/geosite/cn.txt"} {
		found := false
		for _, r := range refs {
			found = found || r == want
		}
		if !found {
			t.Fatalf("SmartDNSFileRefs misses %s: %v", want, refs)
		}
	}
}

// deploy/verify-smartdns.sh checks the same file list as the Go side.
func TestVerifySmartDNSListsSameRefs(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	conf := exampleBundle(t).File("nodes/gw/etc/smartdns/smartdns.conf")
	path := filepath.Join(t.TempDir(), "smartdns.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bash, filepath.Join("..", "..", "deploy", "verify-smartdns.sh"), "--list-refs", path).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := strings.Fields(string(out))
	want := SmartDNSFileRefs(conf)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("verify-smartdns.sh lists %v, Go lists %v", got, want)
	}
	script := repoFile(t, "deploy/verify-smartdns.sh")
	// With the generated firewall loaded the check must use paths that the
	// input chain allows: the LAN address as source, and loopback (accepted
	// by the chain's lo rule).
	if !strings.Contains(script, `dig -b "$gw" +time=3 +tries=2 @"$gw"`) {
		t.Fatal("verify-smartdns.sh does not query the gateway LAN address from that address")
	}
	if !strings.Contains(script, "DNS only from the LAN") {
		t.Fatal("verify-smartdns.sh does not require the real input chain to be loaded")
	}
}

// The image has no ENTRYPOINT; flags alone fail with
// `exec: "-f": executable file not found`.
func TestComposeSmartDNSCommandNamesBinary(t *testing.T) {
	svc := composeService(repoFile(t, "deploy/docker-compose.yml"), "smartdns")
	m := regexp.MustCompile(`(?m)^\s+command:\s*\[\s*"([^"]+)"`).FindStringSubmatch(svc)
	if m == nil {
		t.Fatalf("smartdns service has no exec-form command:\n%s", svc)
	}
	if m[1] != "/usr/sbin/smartdns" {
		t.Fatalf("smartdns command starts with %q, want the binary /usr/sbin/smartdns", m[1])
	}
	if !strings.Contains(svc, `"-c", "/etc/smartdns/smartdns.conf"`) {
		t.Fatal("smartdns command does not load the generated config")
	}
}

// SmartDNS listens on the wildcard, so the input chain is the source
// restriction. Loopback (this host's own queries) is accepted before the
// LAN-only drops, and only for iifname "lo" and DNS ports.
func TestInputChainAllowsLoopbackDNSOnly(t *testing.T) {
	nft := exampleBundle(t).File("nodes/gw/etc/nftables.d/meridian.nft")
	start := strings.Index(nft, "  chain input {")
	if start < 0 {
		t.Fatal("no input chain")
	}
	chain := nft[start:]
	chain = chain[:strings.Index(chain, "\n  }\n")]
	lo := strings.Index(chain, `iifname "lo" meta l4proto { tcp, udp } th dport { 53, 853 } accept`)
	drop := strings.Index(chain, `tcp dport { 53, 853 } ip saddr != 192.168.100.0/24 drop comment "DNS only from the LAN"`)
	if lo < 0 || drop < 0 || lo > drop {
		t.Fatalf("loopback accept must precede the LAN-only drop:\n%s", chain)
	}
	for _, line := range strings.Split(chain, "\n") {
		if strings.Contains(line, "accept") && !strings.Contains(line, `iifname "lo"`) && !strings.Contains(line, "policy accept") {
			t.Fatalf("unexpected accept in input chain: %s", line)
		}
	}
	for _, still := range []string{
		`udp dport { 53, 853 } ip saddr != 192.168.100.0/24 drop`,
		`tcp dport { 53, 853 } ip6 saddr != {`,
		`udp dport { 53, 853 } ip6 saddr != {`,
	} {
		if !strings.Contains(chain, still) {
			t.Fatalf("LAN-only DNS drop weakened, missing %q:\n%s", still, chain)
		}
	}
}

// G6: the gateway up script waits for the LAN after the firewall and guard
// and before forwarding and routes; meridian.service retries only that exit
// status and its timeout leaves room for the wait.
func TestUpScriptWaitsForLANBeforeForwarding(t *testing.T) {
	b := exampleBundle(t)
	up := b.File("nodes/gw/usr/local/sbin/meridian-up.sh")
	guard := strings.Index(up, "meridian-guard-missing")
	wait := strings.Index(up, "until lan_ready; do")
	fwd := strings.Index(up, "MERIDIAN_FWD=")
	sysctl := strings.Index(up, "/etc/sysctl.d/99-meridian.conf")
	routes := strings.Index(up, "/usr/local/sbin/meridian-routes.sh")
	if guard < 0 || wait < guard || fwd < wait || sysctl < wait || routes < wait {
		t.Fatalf("LAN wait must sit after the guard check and before sysctl, forwarding and routes:\n%s", up)
	}
	if !strings.Contains(up, "exit "+strconv.Itoa(LANNotReadyExit)) || !strings.Contains(up, "meridian-lan-not-ready:") {
		t.Fatal("LAN wait has no distinct marker / exit status")
	}
	for _, need := range []string{"lan_if='eth0'", "lan_addr='192.168.100.88'", "ros4='192.168.100.1'"} {
		if !strings.Contains(up, need) {
			t.Fatalf("LAN wait does not use the configured %s", need)
		}
	}
	for path, other := range b.Files {
		if strings.HasSuffix(path, "/usr/local/sbin/meridian-up.sh") && !strings.HasPrefix(path, "nodes/gw/") && strings.Contains(other, "lan_ready") {
			t.Fatalf("%s: only the gateway waits for the LAN", path)
		}
	}

	unit := repoFile(t, "deploy/debian/meridian.service")
	val := func(key string) string {
		m := regexp.MustCompile(`(?m)^` + key + `=(.*)$`).FindStringSubmatch(unit)
		if m == nil {
			t.Fatalf("meridian.service has no %s", key)
		}
		return strings.TrimSpace(m[1])
	}
	if val("RestartForceExitStatus") != strconv.Itoa(LANNotReadyExit) {
		t.Fatalf("RestartForceExitStatus=%s, want %d", val("RestartForceExitStatus"), LANNotReadyExit)
	}
	if val("Restart") != "no" {
		t.Fatal("only the LAN-not-ready status may be retried (Restart=no)")
	}
	timeout, err := strconv.Atoi(val("TimeoutStartSec"))
	if err != nil || timeout < LANWaitDefaultSec+60 {
		t.Fatalf("TimeoutStartSec=%s leaves no room after the %ds LAN wait", val("TimeoutStartSec"), LANWaitDefaultSec)
	}
	if val("StartLimitBurst") == "" || val("RestartSec") == "" || val("StartLimitIntervalSec") == "" {
		t.Fatal("retries need RestartSec and start limits")
	}
}

// G7: settings.lan_interface is the one source; a gateway node naming a
// different NIC is refused, and the gateway sysctls follow settings even
// when the node names a WAN interface.
func TestGatewayLANInterfaceSingleSource(t *testing.T) {
	topo := defaults.Example()
	topo.Settings.LANInterface = "ens192"
	res := validate.Run(topo)
	found := false
	for _, iss := range res.Issues {
		if iss.Code == "lan_interface_mismatch" && iss.Severity == validate.SeverityError &&
			strings.Contains(iss.Message, `"eth0"`) && strings.Contains(iss.Message, `"ens192"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("mismatched gateway lan_interface not refused: %+v", res.Issues)
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "gw" {
			topo.Nodes[i].LANInterface = ""
			topo.Nodes[i].WANInterface = "eth9"
		}
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"nodes/gw/etc/sysctl.d/99-meridian.conf", "nodes/gw/etc/meridian/forwarding.conf"} {
		body := b.File(path)
		if strings.Contains(body, "eth0") || strings.Contains(body, "eth9") || !strings.Contains(body, ".ens192.") {
			t.Fatalf("%s does not follow settings.lan_interface:\n%s", path, body)
		}
	}
	if !strings.Contains(b.File("nodes/gw/etc/sysctl.d/99-meridian.conf"), "net.ipv6.conf.ens192.accept_ra=2") {
		t.Fatal("accept_ra=2 not on the settings LAN interface")
	}
	if !strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-up.sh"), "lan_if='ens192'") {
		t.Fatal("LAN wait does not follow settings.lan_interface")
	}
	// Same name on both is fine.
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "gw" {
			topo.Nodes[i].LANInterface = "ens192"
		}
	}
	if _, err := Compile(topo); err != nil {
		t.Fatalf("matching names refused: %v", err)
	}
}

// G8: the install boundary can tell which peers of the local node lack a
// usable public key; the stock topology has placeholders everywhere.
func TestPeerKeyProblems(t *testing.T) {
	topo := defaults.Example()
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	probs := b.PeerKeyProblems("gw")
	peers := map[string]bool{}
	for _, p := range probs {
		peers[p.Peer] = true
		if p.Iface == "" {
			t.Fatalf("problem without interface: %+v", p)
		}
	}
	if !peers["ali"] || !peers["hk-hub"] || peers["gw"] {
		t.Fatalf("stock peers not reported: %+v", probs)
	}
	good := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	for i := range topo.Nodes {
		topo.Nodes[i].PublicKey = good
	}
	b, err = Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	if probs := b.PeerKeyProblems("gw"); len(probs) != 0 {
		t.Fatalf("valid keys reported: %+v", probs)
	}
	for _, bad := range []string{"", publicKeyPlaceholder, "AQEB", good[:43] + "!", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=="} {
		if ValidWGKey(bad) {
			t.Fatalf("ValidWGKey(%q) = true", bad)
		}
	}
	if !ValidWGKey(good) {
		t.Fatal("valid key refused")
	}
}

// The list scripts no longer download anything themselves: they hand the
// request to the host agent's fixed list action, where internal/lists
// keeps the guarantees the old shell had (bounded downloads, nothing
// replaced or flushed on a failed/empty/HTML download, one nft transaction
// for chnroute; see internal/lists/lists_test.go and
// internal/hostexec/hostexec_test.go).
func TestListScriptsUseHostAgentAction(t *testing.T) {
	topo := defaults.Example()
	topo.Rules = append(topo.Rules, model.Rule{ID: "r-ads", Name: "ads", Enabled: true, MatchType: model.MatchGeosite, Geosite: "category-ads-all", TargetGroup: topo.Settings.DefaultGroup})
	topo.Settings.ListSource = "domestic"
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	geo := b.File("nodes/gw/usr/local/sbin/meridian-update-geosite.sh")
	chn := b.File("nodes/gw/usr/local/sbin/meridian-update-chnroute.sh")
	for name, s := range map[string]string{"geosite": geo, "chnroute": chn} {
		if !strings.Contains(s, "exec /usr/local/bin/meridian lists-update --lists "+name+" --policy \"$policy\"") {
			t.Fatalf("%s script does not use the host agent action:\n%s", name, s)
		}
		if !strings.Contains(s, "policy=${MERIDIAN_LIST_SOURCE:-domestic}") {
			t.Fatalf("%s script lacks the compiled policy:\n%s", name, s)
		}
		var code []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "#") {
				code = append(code, l)
			}
		}
		for _, banned := range []string{"curl", "wget", "nft ", "http", "mv ", "awk"} {
			if strings.Contains(strings.Join(code, "\n"), banned) {
				t.Fatalf("%s script still does %q itself:\n%s", name, banned, s)
			}
		}
	}
	// Real v2fly names are requested (the old script fetched the
	// sanitized file stem, "category_ads_all", which does not exist);
	// SmartDNS reads the sanitized file.
	if !regexp.MustCompile(`--geosite '([a-z0-9,-]*,)?apple,([a-z0-9,-]*,)?category-ads-all,([a-z0-9,-]*,)?cn(,[a-z0-9,-]*)?'`).MatchString(geo) {
		t.Fatalf("geosite names:\n%s", geo)
	}
	if !strings.Contains(b.File("nodes/gw/etc/smartdns/smartdns.conf"), "/var/lib/meridian/geosite/category_ads_all.txt") {
		t.Fatal("SmartDNS does not read the sanitized file")
	}
	if !strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-up.sh"), "[ -f /var/lib/meridian/geosite/category_ads_all.txt ]") {
		t.Fatal("up script does not seed the sanitized file")
	}
}

// The gateway loader appends the saved chnroute batch, so a reload does not
// empty chnroute; a saved file with foreign lines, or one nft -c rejects
// together with the ruleset, is ignored and the compiled ruleset alone is
// checked and loaded. Exits stay unchanged (no extra nft step).
func TestUpScriptReaddsSavedChnroute(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if strings.Contains(nftLoadCommands(false), "chnroute") {
		t.Fatal("non-gateway nodes must not read the chnroute copy")
	}
	good := "flush set inet meridian chnroute\nadd element inet meridian chnroute { 1.0.1.0/24, 1.0.2.0/23 }\n" +
		"flush set inet meridian chnroute6\nadd element inet meridian chnroute6 { 2400:3200::/32 }\n"
	cases := []struct {
		name, saved, env, wantFile, wantMsg string
	}{
		{name: "no saved copy", wantFile: "meridian.nft"},
		{name: "saved copy re-added", saved: good, wantFile: ".boot.nft"},
		{name: "foreign line ignored", saved: good + "add rule inet meridian forward accept\n", wantFile: "meridian.nft", wantMsg: "meridian-chnroute-saved-ignored"},
		{name: "combination rejected", saved: good, env: "NFT_FAIL_BOOT=1", wantFile: "meridian.nft", wantMsg: "meridian-chnroute-saved-ignored"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			for _, d := range []string{bin, filepath.Join(dir, "var", "lists")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			base := filepath.Join(dir, "meridian.nft")
			if err := os.WriteFile(base, []byte("table inet meridian {}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.saved != "" {
				if err := os.WriteFile(filepath.Join(dir, "var", "lists", "chnroute.nft"), []byte(tc.saved), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stub := "#!/bin/sh\necho \"nft $*\" >> \"$CALL_LOG\"\n" +
				"case \"$*\" in *.boot.nft*) [ -z \"$NFT_FAIL_BOOT\" ] || exit 1 ;; esac\nexit 0\n"
			if err := os.WriteFile(filepath.Join(bin, "nft"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			loader := strings.NewReplacer("/etc/nftables.d/meridian.nft", base, "/var/lib/meridian", filepath.Join(dir, "var")).Replace(nftLoadCommands(true))
			log := filepath.Join(dir, "calls.log")
			cmd := exec.Command(bash, "-c", "set -euo pipefail\n"+loader+"echo \"loaded=$MERIDIAN_NFT\"\n")
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "CALL_LOG=" + log, tc.env}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("loader failed: %v\n%s", err, out)
			}
			calls, _ := os.ReadFile(log)
			if !strings.Contains(string(out), "loaded=") || !strings.HasSuffix(strings.TrimSpace(string(out)), tc.wantFile) {
				t.Fatalf("loaded the wrong file (want %s):\n%s\n%s", tc.wantFile, out, calls)
			}
			if !strings.Contains(string(calls), "nft -f "+filepath.Dir(base)) || strings.Count(string(calls), "nft -f ") != 1 {
				t.Fatalf("want exactly one nft -f:\n%s", calls)
			}
			if tc.wantMsg != "" && !strings.Contains(string(out), tc.wantMsg) {
				t.Fatalf("missing %q:\n%s", tc.wantMsg, out)
			}
			if tc.wantFile == ".boot.nft" {
				b, _ := os.ReadFile(filepath.Join(dir, "var", "lists", ".boot.nft"))
				if !strings.HasPrefix(string(b), "table inet meridian {}\n") || !strings.HasSuffix(string(b), good) {
					t.Fatalf("combined ruleset:\n%s", b)
				}
			}
		})
	}
}

// G5 / QA-2 / G10: static checks on install.sh (it needs root, apt and
// systemd, so it is not executed here).
func TestInstallScriptOrderingAndModes(t *testing.T) {
	s := repoFile(t, "deploy/debian/install.sh")
	daemon := strings.Index(s, "cat > /etc/docker/daemon.json")
	apt := strings.Index(s, "apt-get install -y docker.io")
	if daemon < 0 || apt < 0 || daemon > apt {
		t.Fatal("daemon.json must be written before docker.io is installed")
	}
	restart := strings.Index(s, "  systemctl restart docker\n")
	offAfter := strings.Index(s[restart:], "off_unless_was_on")
	if restart < 0 || offAfter < 0 {
		t.Fatal("forwarding must be checked off again after Docker starts")
	}
	if !strings.Contains(s, `-P FORWARD DROP`) || !strings.Contains(s, "重启本机") {
		t.Fatal("a leftover FORWARD DROP policy must be reported with the reboot hint")
	}
	if !strings.Contains(s, "install -d -m 0700 /etc/wireguard") || !strings.Contains(s, "chmod 0700 /etc/wireguard") {
		t.Fatal("/etc/wireguard must be 0700")
	}
	if regexp.MustCompile(`install -d [^\n]*/etc/wireguard[^\n]*\\?\n`).FindString(s) != "install -d -m 0700 /etc/wireguard\n" {
		t.Fatal("/etc/wireguard is created together with 0755 directories")
	}
	// sysctl --system (which applies forwarding=0) only in the prepare branch.
	prep := strings.Index(s, `if [[ "${mode}" == prepare ]]; then
  write_boot_sysctl`)
	elseAt := strings.Index(s[prep:], "\nelse\n")
	if prep < 0 || elseAt < 0 {
		t.Fatal("no explicit prepare/upgrade split")
	}
	code := regexp.MustCompile(`(?m)^\s*sysctl --system`)
	if all := code.FindAllStringIndex(s, -1); len(all) != 1 || all[0][0] > prep+elseAt || all[0][0] < prep {
		t.Fatal("sysctl --system must only run when preparing a fresh host")
	}
	if !strings.Contains(s, `mode=upgrade`) || !strings.Contains(s, "-x /usr/local/sbin/meridian-up.sh && -f /etc/systemd/system/meridian.service") {
		t.Fatal("existing install is not detected from the host's state")
	}
	if !strings.Contains(s, "/usr/local/bin/meridian host-restore; then") || !strings.Contains(s, "/usr/local/bin/meridian host-restore --health-only") {
		t.Fatal("upgrade must check / restore the data plane through meridian-host")
	}
	if !strings.Contains(s, "rollback_upgrade") || !strings.Contains(s, `"${bak}/meridian"`) {
		t.Fatal("a failed upgrade must put the previous binary back")
	}
	// The only writes of forwarding to the kernel switch it off, and only
	// when it was off before (or on a fresh host).
	for _, m := range regexp.MustCompile(`sysctl -q?w net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)=(\d)`).FindAllStringSubmatch(s, -1) {
		if m[2] != "0" {
			t.Fatalf("install.sh turns forwarding on: %s", m[0])
		}
	}
}

func TestVerifyHostExecJudgesForwardingOnlyWhenActive(t *testing.T) {
	s := repoFile(t, "deploy/verify-host-exec.sh")
	active := strings.Index(s, "if systemctl is-active --quiet meridian.service; then")
	fwd := strings.Index(s, `on after meridian.service`)
	elseAt := strings.Index(s[active:], "\n  else\n")
	if active < 0 || fwd < active || elseAt < 0 || fwd > active+elseAt {
		t.Fatal("forwarding must only be reported ok inside the meridian.service-active branch")
	}
}
