package compile

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func TestCompileExample(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	all := b.Canonical()
	for _, needle := range []string{
		"Table = off",
		"fd66:0:0:1::1",
		"fd66::/48",
		"192.168.100.1",
		"chnroute",
		"dport 53",
		"dport 853",
		"1.1.1.1",
		"timeout_sec=0",
		"--restrict-to",
		"--tls-verify-certificate",
		"PersistentKeepalive = 25",
		"default-exit hk-ix",
		"comment \"NAT66\"",
		"MTU = 1412",
		"MTU = 1360",
		"maxseg size set 1320",
		"maxseg size set 1300",
		"rp_filter=2",
		"send_redirects=0",
		"accept_ra=2",
		"223.5.5.5",
		"1.12.12.12",
		"openai",
		"example-wss-path-prefix",
		privateKeyPlaceholder,
		"china-operator-ip",
		"-address #6",
		"meridian-east-preferred: ix ",
		"__MERIDIAN_PRIVATE_KEY__",
	} {
		if !strings.Contains(all, needle) {
			t.Errorf("compiled bundle missing %q", needle)
		}
	}
	if strings.Contains(all, "flush ruleset") {
		t.Fatal("must not flush the entire nftables ruleset")
	}
	for _, line := range strings.Split(all, "\n") {
		if strings.Contains(line, "fd66") && strings.Contains(line, "192.168.100.1") && !strings.Contains(line, "never") && !strings.Contains(line, "#") {
			t.Fatalf("ULA routed toward ROS: %s", line)
		}
	}

	hubTW := fileContaining(b, "nodes/hk-hub/etc/wireguard/", "link tw-hub")
	if strings.Contains(hubTW, "Endpoint =") {
		t.Fatalf("hub peer for TW must not set Endpoint:\n%s", hubTW)
	}
	tw := fileContaining(b, "nodes/tw/etc/wireguard/", "link tw-hub")
	if !strings.Contains(tw, "Endpoint = 203.0.113.20:") {
		t.Fatalf("TW must dial the hub:\n%s", tw)
	}
	if !strings.Contains(tw, "PersistentKeepalive = 25") {
		t.Fatalf("TW keepalive missing:\n%s", tw)
	}
	if !strings.Contains(tw, "10.66.50.1/32") {
		t.Fatalf("TW must accept the hub tunnel address:\n%s", tw)
	}

	order := strings.Join(b.Order, ",")
	for _, earlier := range []string{"tw", "hk-resi", "hk-ix"} {
		if indexOf(b.Order, earlier) > indexOf(b.Order, "hk-hub") {
			t.Fatalf("order %s puts %s after the hub", order, earlier)
		}
	}
	if indexOf(b.Order, "hk-hub") > indexOf(b.Order, "ali") || indexOf(b.Order, "ali") > indexOf(b.Order, "gw") {
		t.Fatalf("order = %s", order)
	}

	sg := b.File("nodes/sg/etc/nftables.d/meridian.nft")
	if !strings.Contains(sg, "meta nfproto ipv6 drop") {
		t.Fatalf("v4-only exit should drop forwarded v6:\n%s", sg)
	}
	hk := b.File("nodes/hk-ix/etc/nftables.d/meridian.nft")
	if strings.Contains(hk, "drop") {
		t.Fatalf("v6-capable exit should NAT66, not drop v6:\n%s", hk)
	}

	dns := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	if !strings.Contains(dns, "domain-rules /ani.gamer.com.tw/ -nameserver rg_tw -address #6") {
		t.Fatalf("TW rule should filter AAAA:\n%s", dns)
	}
	if !strings.Contains(dns, "domain-rules /netflix.com/ -nameserver rg_hk_residential ") || strings.Contains(lineWith(dns, "netflix.com"), "-address #6") {
		t.Fatalf("residential netflix should keep AAAA:\n%s", lineWith(dns, "netflix.com"))
	}
}

func TestIXReplacementModeChangesPreferredRoute(t *testing.T) {
	topo := defaults.Example()
	topo.Settings.IXReplacementMode = true
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	routes := b.File("nodes/ali/usr/local/sbin/meridian-routes.sh")
	if !strings.Contains(routes, "meridian-east-preferred: ix-replacement ") {
		t.Fatalf("replacement mode should select the standby WSS:\n%s", routes)
	}
	if strings.Contains(routes, "meridian-east-preferred: ix ") {
		t.Fatal("primary IX route still marked preferred")
	}
	// The standby tunnel is still rendered so it can be probed.
	if !strings.Contains(b.Canonical(), "ali-hub-wss") {
		t.Fatal("standby WSS config missing")
	}
}

func TestCompileRejectsBypass(t *testing.T) {
	topo := defaults.Example()
	var links []model.Link
	for _, l := range topo.Links {
		if l.ID == "ali-ix" || l.ID == "ix-hub" {
			continue
		}
		links = append(links, l)
	}
	topo.Links = links
	_, err := Compile(topo)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("error type %T", err)
	}
}

func fileContaining(b *Bundle, prefix, needle string) string {
	for path, body := range b.Files {
		if strings.HasPrefix(path, prefix) && strings.Contains(body, needle) {
			return body
		}
	}
	return ""
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

func lineWith(body, needle string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

// Regression for the review repro (compile_repro_test.go): a node with a
// stored private key must not leak it into the compiled bundle. The bundle,
// previews, diffs and snapshots stay redacted; the key is injected only at the
// install boundary (apply.Applier.PrivateKey / provision.InjectPrivate), which
// internal/apply and internal/api test end to end.
func TestStoredPrivateKeyStaysOutOfBundle(t *testing.T) {
	topo := defaults.Example()
	keys := map[string]string{}
	for i := range topo.Nodes {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		k := base64.StdEncoding.EncodeToString(raw[:])
		topo.Nodes[i].PrivateKey = k
		keys[topo.Nodes[i].ID] = k
	}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	canon := b.Canonical()
	for id, k := range keys {
		if strings.Contains(canon, k) {
			t.Fatalf("stored private key of %s leaked into the bundle", id)
		}
	}
	n := 0
	for p, s := range b.Files {
		if !strings.Contains(p, "/etc/wireguard/") {
			continue
		}
		n++
		if !strings.Contains(s, "PrivateKey = "+PrivateKeyPlaceholder+"\n") {
			t.Fatalf("%s must carry the placeholder for install-time injection", p)
		}
	}
	if n == 0 {
		t.Fatal("no WireGuard configs rendered")
	}
}

// The Compose SmartDNS service must see every file the generated config
// loads, at the same path, and hold NET_ADMIN for nftset. Whether the image
// actually starts and fills the sets is checked by deploy/verify-smartdns.sh
// on a Linux host.
func TestSmartDNSComposeMountsEveryReference(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	conf := b.File("nodes/gw/etc/smartdns/smartdns.conf")
	refs := SmartDNSFileRefs(conf)
	if len(refs) < 4 {
		t.Fatalf("expected cert, key and domain-set refs, got %v", refs)
	}
	under := func(p string) bool {
		for _, d := range SmartDNSSharedDirs {
			if strings.HasPrefix(p, d+"/") {
				return true
			}
		}
		return false
	}
	for _, r := range refs {
		if !under(r) {
			t.Fatalf("smartdns.conf loads %s outside SmartDNSSharedDirs", r)
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	svc := composeService(string(raw), "smartdns")
	if svc == "" {
		t.Fatal("no smartdns service in docker-compose.yml")
	}
	if !strings.Contains(svc, "- NET_ADMIN") {
		t.Fatal("smartdns service needs cap NET_ADMIN for nftset")
	}
	for _, d := range SmartDNSSharedDirs {
		if !strings.Contains(svc, "- "+d+":"+d+":ro") {
			t.Fatalf("smartdns service does not mount %s read-only", d)
		}
	}
	// The controller writes the domain sets; they must be the same host dirs,
	// not a path inside its private named volume.
	ctl := composeService(string(raw), "meridian")
	for _, d := range []string{"/var/lib/meridian/geosite", "/var/lib/meridian/keywords", "/etc/meridian"} {
		if !strings.Contains(ctl, "- "+d+":"+d+"\n") {
			t.Fatalf("controller does not share %s with the host", d)
		}
	}
	if strings.Contains(svc, "meridian-data") {
		t.Fatal("smartdns must not mount the panel database volume")
	}
}

// composeService returns the indented block of one top-level service.
func composeService(doc, name string) string {
	start := strings.Index(doc, "\n  "+name+":\n")
	if start < 0 {
		return ""
	}
	rest := doc[start+1:]
	lines := strings.Split(rest, "\n")
	var out []string
	out = append(out, lines[0])
	for _, l := range lines[1:] {
		if l != "" && !strings.HasPrefix(l, "    ") && !strings.HasPrefix(l, "  #") {
			break
		}
		if strings.HasPrefix(l, "  #") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n"
}

func TestExitUpRestartsSmartDNSAfterTunnels(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	up := b.File("nodes/tw/usr/local/sbin/meridian-up.sh")
	wg := strings.Index(up, "wg-quick up")
	restart := strings.Index(up, "systemctl restart meridian-smartdns.service")
	if wg < 0 || restart < wg {
		t.Fatal("exit meridian-up.sh must restart smartdns after WireGuard is up")
	}
	// The resolver is the panel-delivered binary under Meridian's own unit;
	// the distribution's smartdns.service is never touched on a remote node.
	if regexp.MustCompile(`(^|[^-])smartdns\.service`).MatchString(up) {
		t.Fatal("exit meridian-up.sh must not use the distribution's smartdns.service")
	}
	unit := b.File("nodes/tw/etc/systemd/system/meridian-smartdns.service")
	if !strings.Contains(unit, "ExecStart=/usr/local/sbin/meridian-smartdns -f -x -p - -c /etc/smartdns/smartdns.conf") {
		t.Fatalf("exit resolver unit:\n%s", unit)
	}
	for _, f := range []string{"nodes/ali/etc/systemd/system/wstunnel-meridian.service", "nodes/ali/etc/systemd/system/wstunnel-client-ali-hub-wss.service", "nodes/gw/etc/systemd/system/wstunnel-client-gw-ali.service"} {
		if body := b.File(f); body == "" || (!strings.Contains(body, "ExecStart=/usr/local/sbin/meridian-wstunnel ") || strings.Contains(body, "/usr/local/bin/wstunnel")) {
			t.Fatalf("%s must run the panel-delivered wstunnel:\n%s", f, body)
		}
	}
	if b.File("nodes/tw/etc/smartdns/smartdns.conf") == "" {
		t.Fatal("exit has no resolver config")
	}
	if strings.Contains(b.File("nodes/gw/usr/local/sbin/meridian-up.sh"), "systemctl restart smartdns") {
		t.Fatal("gateway SmartDNS runs in Compose; its up script must not restart a host unit")
	}
}

// The up script activates exactly the manifest's interfaces (no m*.conf
// glob, so a config left by a rolled-back apply is not restarted) and fails
// on a listed config that is missing.
func TestUpScriptActivatesListedInterfacesOnly(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for path, up := range b.Files {
		if !strings.HasSuffix(path, "/usr/local/sbin/meridian-up.sh") {
			continue
		}
		node := strings.Split(path, "/")[1]
		if strings.Contains(up, "m*.conf") || strings.Contains(up, "nullglob") {
			t.Errorf("%s still scans tunnel files", path)
		}
		var want []string
		for p := range b.Files {
			if strings.HasPrefix(p, "nodes/"+node+"/etc/wireguard/") {
				want = append(want, strings.TrimSuffix(filepath.Base(p), ".conf"))
			}
		}
		sort.Strings(want)
		if len(want) > 0 && !strings.Contains(up, "for iface in "+strings.Join(want, " ")+"; do\n") {
			t.Errorf("%s does not list exactly %v", path, want)
		}
		if len(want) > 0 && !strings.Contains(up, "meridian-wg-missing") {
			t.Errorf("%s must fail on a missing listed config", path)
		}
		if !strings.Contains(up, "meridian-systemd-missing") {
			t.Errorf("%s must fail explicitly without systemd", path)
		}
	}
}

// Boot window: systemd-sysctl applies /etc/sysctl.d before meridian.service
// loads the guard, so no sysctl.d file may turn forwarding on; on the
// gateway it is explicitly off. Forwarding comes from forwarding.conf,
// applied by the up script after the guard check. The early-boot guard file
// exists for meridian-guard.service.
func TestForwardingOnlyAfterGuard(t *testing.T) {
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range b.Files {
		if !strings.HasSuffix(path, "/etc/sysctl.d/99-meridian.conf") {
			continue
		}
		for _, line := range strings.Split(body, "\n") {
			if (strings.Contains(line, "forwarding=") || strings.Contains(line, "ip_forward=")) && !strings.HasSuffix(line, "=0") {
				t.Errorf("%s enables forwarding at boot: %s", path, line)
			}
		}
		node := strings.Split(path, "/")[1]
		if !strings.Contains(b.File("nodes/"+node+"/etc/meridian/forwarding.conf"), "net.ipv4.ip_forward=1") {
			t.Errorf("%s: forwarding.conf missing", node)
		}
	}
	gw := b.File("nodes/gw/etc/sysctl.d/99-meridian.conf")
	if !strings.Contains(gw, "net.ipv4.ip_forward=0") || !strings.Contains(gw, "net.ipv6.conf.all.forwarding=0") {
		t.Fatal("gateway must keep forwarding off at boot")
	}
	up := b.File("nodes/gw/usr/local/sbin/meridian-up.sh")
	guard := strings.Index(up, "meridian-guard-missing")
	fwd := strings.Index(up, "MERIDIAN_FWD=")
	if guard < 0 || fwd < guard {
		t.Fatal("gateway forwarding must be enabled only after the guard check")
	}
	if strings.Contains(up, "sysctl --system") {
		t.Fatal("sysctl --system would re-apply the boot-time forwarding=0")
	}
	g := b.File("nodes/gw/etc/nftables.d/meridian-guard.nft")
	if !strings.Contains(g, "table inet meridian_guard {") || strings.Contains(g, "table inet meridian {") {
		t.Fatal("early-boot guard file must hold only the guard table")
	}
}
