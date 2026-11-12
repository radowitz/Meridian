package remoteaccess

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"golang.org/x/crypto/curve25519"
)

func TestKeypairMatches(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := base64.StdEncoding.DecodeString(kp.Private)
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	if base64.StdEncoding.EncodeToString(pub) != kp.Public || len(priv) != 32 {
		t.Fatal("public key does not match the private key")
	}
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Fatal("private key not clamped")
	}
	a, _ := GeneratePSK()
	b, _ := GeneratePSK()
	if a == b || len(a) != 44 {
		t.Fatal("bad PSK")
	}
}

func TestAllocateAddresses(t *testing.T) {
	ra := model.RemoteAccess{}
	a4, a6, err := AllocateAddresses(ra)
	if err != nil || a4.String() != "10.67.0.2" || a6.String() != "fd67::2" {
		t.Fatalf("%v %v %v", a4, a6, err)
	}
	ra.Devices = []model.RemoteDevice{{IPv4: "10.67.0.2", IPv6: "fd67::2"}, {IPv4: "10.67.0.4", IPv6: "fd67::4"}}
	a4, a6, _ = AllocateAddresses(ra)
	if a4.String() != "10.67.0.3" || a6.String() != "fd67::3" {
		t.Fatalf("lowest free host: %v %v", a4, a6)
	}
	ra.Devices = append(ra.Devices, model.RemoteDevice{IPv4: "10.67.0.3", IPv6: "fd67::5"})
	a4, a6, _ = AllocateAddresses(ra)
	if a4.String() != "10.67.0.6" || a6.String() != "fd67::6" {
		t.Fatalf("a host number used in either pool is skipped: %v %v", a4, a6)
	}
	small := model.RemoteAccess{IPv4Prefix: "10.67.0.0/29"}
	for i := 0; i < 5; i++ {
		a4, a6, err := AllocateAddresses(small)
		if err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
		small.Devices = append(small.Devices, model.RemoteDevice{IPv4: a4.String(), IPv6: a6.String()})
	}
	if _, _, err := AllocateAddresses(small); err != ErrPoolFull {
		t.Fatalf("a /29 holds 5 devices: %v", err)
	}
	if small.Devices[4].IPv4 != "10.67.0.6" {
		t.Fatalf("broadcast or gateway handed out: %+v", small.Devices)
	}
}

func raTopo() model.Topology {
	t := defaults.Example()
	t.RemoteAccess = &model.RemoteAccess{Enabled: true, Endpoint: "home.example.net", ListenPort: 51900, PublicKey: strings.Repeat("A", 43) + "=", KeyID: "ra-key-x"}
	return t
}

func TestClientConfig(t *testing.T) {
	topo := raTopo()
	d := model.RemoteDevice{ID: "dev-0011aabb", Mode: model.RemoteModeFull, IPv4: "10.67.0.2", IPv6: "fd67::2"}
	c := RenderClient(topo, d, "PRIVATE-TEST", "PSK-TEST")
	for _, need := range []string{
		"PrivateKey = PRIVATE-TEST", "Address = 10.67.0.2/32, fd67::2/128", "DNS = 10.67.0.1, fd67::1", "MTU = 1380",
		"PresharedKey = PSK-TEST", "Endpoint = home.example.net:51900", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(c.Text, need) {
			t.Errorf("full config missing %q:\n%s", need, c.Text)
		}
	}
	if !c.ShownOnce || len(strings.TrimSuffix(c.Filename, ".conf")) > 15 {
		t.Fatalf("filename %q (wg-quick interface names are at most 15 characters)", c.Filename)
	}
	d.Mode = model.RemoteModeHome
	c = RenderClient(topo, d, "PRIVATE-TEST", "")
	if !strings.Contains(c.Text, "AllowedIPs = 192.168.100.0/24, 2001:db8:100::/64, 10.67.0.1/32, fd67::1/128") || strings.Contains(c.Text, "PresharedKey") {
		t.Fatalf("home config:\n%s", c.Text)
	}
	if !strings.Contains(c.Explanation, "不经过 Meridian") || !strings.Contains(c.Explanation, "DNS") {
		t.Fatal("home mode must explain what it does not cover")
	}
	topo.RemoteAccess.Endpoint = "2001:db8::1"
	if !strings.Contains(RenderClient(topo, d, "p", "").Text, "Endpoint = [2001:db8::1]:51900") {
		t.Fatal("IPv6 endpoint not bracketed")
	}
	f := Forward(topo)
	if f.Protocol != "udp" || f.ExternalPort != 51900 || f.InternalPort != 51900 || f.InternalAddress != "192.168.100.88" {
		t.Fatalf("%+v", f)
	}
	// The fingerprint follows every server-side value the client embeds.
	before := Fingerprint(topo, d)
	topo.RemoteAccess.ListenPort = 51901
	if Fingerprint(topo, d) == before {
		t.Fatal("port change not reflected")
	}
}
