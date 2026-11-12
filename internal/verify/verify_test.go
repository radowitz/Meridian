package verify

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
)

func TestExampleChecklistPasses(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	items := CheckBundle(defaults.Example(), b.Files)
	for _, it := range items {
		if it.Status == Fail {
			t.Errorf("%s: %s", it.ID, it.Detail)
		}
	}
	found := false
	for _, it := range items {
		if it.ID == "webrtc_host_gua" && it.Status == KnownLimitation {
			found = true
		}
	}
	if !found {
		t.Fatal("WebRTC GUA host-candidate limitation missing")
	}
}

func TestSameSubnet(t *testing.T) {
	ok, _ := SameSubnet("192.168.100.88/24", "192.168.100.1")
	if !ok {
		t.Fatal("gateway and ROS should share 192.168.100.0/24")
	}
	ok, msg := SameSubnet("192.168.100.88/24", "192.168.100.88")
	if ok || !strings.Contains(msg, "不能") {
		t.Fatalf("same address accepted: %v %s", ok, msg)
	}
	ok, _ = SameSubnet("192.168.100.88/24", "203.0.113.1")
	if ok {
		t.Fatal("different subnet accepted")
	}
}

func TestSysctlSnapshot(t *testing.T) {
	good := map[string]string{
		"net.ipv4.conf.all.rp_filter":        "2",
		"net.ipv4.conf.default.rp_filter":    "2",
		"net.ipv4.conf.all.send_redirects":   "0",
		"net.ipv6.conf.all.send_redirects":   "0",
		"net.ipv4.conf.all.accept_redirects": "0",
		"net.ipv4.ip_forward":                "1",
	}
	for _, it := range CheckSysctl(good) {
		if it.Status != Pass {
			t.Errorf("%s %s", it.ID, it.Detail)
		}
	}
	bad := map[string]string{
		"net.ipv4.conf.all.rp_filter": "1",
	}
	failed := false
	for _, it := range CheckSysctl(bad) {
		if it.ID == "live_rp_filter" && it.Status == Fail {
			failed = true
		}
	}
	if !failed {
		t.Fatal("strict rp_filter was accepted")
	}
}
