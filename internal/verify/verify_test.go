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

// The panel never runs integration tests, real clients, ROS queries or
// captures, so none of those items may say "pass": they are unknown or
// pending human sign-off. Automated items only read generated text.
func TestChecklistDoesNotClaimUnexecutedEvidence(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	items := CheckBundle(defaults.Example(), b.Files)
	seen := map[string]Item{}
	for _, it := range items {
		seen[it.ID] = it
		switch it.Scope {
		case ScopeAutomated:
			if it.Status == Unknown || it.Status == PendingSignoff {
				t.Errorf("%s: automated item with status %s", it.ID, it.Status)
			}
		case ScopeIntegration:
			if it.Status != Unknown {
				t.Errorf("%s: integration evidence the panel did not run is %s, want unknown", it.ID, it.Status)
			}
		case ScopeHuman:
			if it.Status != PendingSignoff {
				t.Errorf("%s: human item is %s, want pending_signoff", it.ID, it.Status)
			}
		case ScopeLimitation:
			if it.Status != KnownLimitation {
				t.Errorf("%s: %s", it.ID, it.Status)
			}
		default:
			t.Errorf("%s has no evidence scope", it.ID)
		}
		if strings.Contains(it.Detail, "不泄漏") && !strings.Contains(it.Detail, "不是") {
			t.Errorf("%s claims no leak: %s", it.ID, it.Detail)
		}
	}
	for id, scope := range map[string]string{
		"dnsleak_client": ScopeHuman, "webrtc_srflx": ScopeHuman, "ros_ula_blackhole": ScopeHuman,
		"tunnel_cut": ScopeHuman, "redirect_on_wire": ScopeHuman,
		"netns_reload_no_leak": ScopeIntegration, "gateway_verify_script": ScopeIntegration,
	} {
		if it, ok := seen[id]; !ok || it.Scope != scope {
			t.Errorf("%s missing or in the wrong scope: %+v", id, it)
		}
	}
}

// Mesh: the generated next-hops are an automated pass at most; the
// forwarding evidence is integration (unknown) and human (pending), never pass.
func TestMeshItemsNeverClaimForwarding(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Item{}
	for _, it := range CheckBundle(defaults.Example(), b.Files) {
		got[it.ID] = it
	}
	if it := got["mesh_nexthop"]; it.Status != Pass || it.Scope != ScopeAutomated {
		t.Fatalf("mesh_nexthop %+v", it)
	}
	if it := got["mesh_veth_forwarding"]; it.Status != Unknown || it.Scope != ScopeIntegration {
		t.Fatalf("mesh_veth_forwarding %+v", it)
	}
	if it := got["mesh_e2e_forwarding"]; it.Status != PendingSignoff || it.Scope != ScopeHuman {
		t.Fatalf("mesh_e2e_forwarding %+v", it)
	}
	files := map[string]string{}
	for k, v := range b.Files {
		files[k] = v
	}
	p := "nodes/hk-hub/usr/local/sbin/meridian-routes.sh"
	files[p] = strings.ReplaceAll(files[p], "default via 169.254.66.2 dev mmesh", "default dev mmesh")
	for _, it := range CheckBundle(defaults.Example(), files) {
		if it.ID == "mesh_nexthop" && it.Status != Fail {
			t.Fatalf("default dev mmesh not flagged: %+v", it)
		}
	}
}
