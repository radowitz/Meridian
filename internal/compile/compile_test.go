package compile

import (
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
	if !strings.Contains(dns, "domain-rules /ani.gamer.com.tw/ -nameserver g_tw -address #6") {
		t.Fatalf("TW rule should filter AAAA:\n%s", dns)
	}
	if !strings.Contains(dns, "domain-rules /netflix.com/ -nameserver g_hk_resi ") || strings.Contains(lineWith(dns, "netflix.com"), "-address #6") {
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
