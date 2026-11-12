package compile

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
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
		"iif 'eth0' unreachable",
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
