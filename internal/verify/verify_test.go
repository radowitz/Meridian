package verify

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/remoteaccess"
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

func itemsByID(items []Item) map[string]Item {
	got := map[string]Item{}
	for _, it := range items {
		got[it.ID] = it
	}
	return got
}

// raTopology is the example with remote access on and one enabled device.
func raTopology(t *testing.T) model.Topology {
	t.Helper()
	topo := defaults.Example()
	gw, err := remoteaccess.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := remoteaccess.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	topo.RemoteAccess = &model.RemoteAccess{Enabled: true, Endpoint: "home.example.net", ListenPort: 51900, PublicKey: gw.Public, KeyID: "ra-key-test",
		Devices: []model.RemoteDevice{{ID: "dev-aaaa", Name: "phone", Mode: model.RemoteModeFull, Enabled: true, PublicKey: dev.Public, IPv4: "10.67.0.2", IPv6: "fd67::2"}}}
	return topo
}

// Region groups, the boot guard, the chnroute re-add, key placeholders
// and remote access are automated checks of the generated text; remote
// access adds human items (phone, router, IPv6) that are never pass, and a
// limitation for home-only mode. With the feature off nothing about it is
// claimed beyond "not enabled".
func TestNewWorkItemsAndScopes(t *testing.T) {
	off := defaults.Example()
	b, err := compile.Compile(off)
	if err != nil {
		t.Fatal(err)
	}
	got := itemsByID(CheckBundle(off, b.Files))
	for _, id := range []string{"group_marks_routed", "boot_guard_matches", "chnroute_readd", "bundle_keys_placeholder"} {
		if it := got[id]; it.Status != Pass || it.Scope != ScopeAutomated {
			t.Errorf("%s: %+v", id, it)
		}
	}
	if it := got["remote_access_config"]; it.Status != Skip || it.Scope != ScopeAutomated {
		t.Errorf("remote off: %+v", got["remote_access_config"])
	}
	for _, id := range []string{"remote_phone_full", "remote_router_forward", "remote_home_mode"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s listed without remote access", id)
		}
	}
	for id, scope := range map[string]string{"real_exit_switch": ScopeHuman, "unlock_platform_verdicts": ScopeHuman, "lists_update_runtime": ScopeIntegration, "secrets_at_rest": ScopeLimitation} {
		if it, ok := got[id]; !ok || it.Scope != scope {
			t.Errorf("%s: %+v", id, it)
		}
	}

	on := raTopology(t)
	b, err = compile.Compile(on)
	if err != nil {
		t.Fatal(err)
	}
	items := CheckBundle(on, b.Files)
	got = itemsByID(items)
	if it := got["remote_access_config"]; it.Status != Pass {
		t.Fatalf("remote on: %+v", it)
	}
	for _, id := range []string{"remote_phone_full", "remote_phone_home", "remote_router_forward", "remote_ipv6"} {
		if it := got[id]; it.Status != PendingSignoff || it.Scope != ScopeHuman {
			t.Errorf("%s: %+v", id, it)
		}
	}
	if it := got["remote_home_mode"]; it.Status != KnownLimitation {
		t.Errorf("remote_home_mode: %+v", it)
	}
	for _, it := range items {
		if it.Status == Fail {
			t.Errorf("%s fails on a valid topology: %s", it.ID, it.Detail)
		}
		if (it.Scope == ScopeIntegration || it.Scope == ScopeHuman) && it.Status == Pass {
			t.Errorf("%s claims an unexecuted check passed", it.ID)
		}
	}

	// Broken generated text is caught.
	mut := func(path, old, new string) map[string]string {
		files := map[string]string{}
		for k, v := range b.Files {
			files[k] = v
		}
		files[path] = strings.Replace(files[path], old, new, 1)
		return files
	}
	for name, c := range map[string]struct {
		files map[string]string
		id    string
	}{
		"group rule dropped": {mut("nodes/gw/usr/local/sbin/meridian-routes.sh", "ip -6 rule add fwmark 0x10f unreachable", "true"), "group_marks_routed"},
		"guard range short":  {mut("nodes/gw/etc/nftables.d/meridian.nft", "0x101-0x140", "0x101-0x110"), "group_marks_routed"},
		"boot guard differs": {mut("nodes/gw/etc/nftables.d/meridian-guard.nft", `"mra"`, `"mrb"`), "boot_guard_matches"},
		"no chnroute readd":  {mut("nodes/gw/usr/local/sbin/meridian-up.sh", "MERIDIAN_CHNROUTE_SAVED=", "X="), "chnroute_readd"},
		"key in bundle":      {mut("nodes/gw/etc/wireguard/mra.conf", "PrivateKey = __MERIDIAN_SECRET_ra-key-test__", "PrivateKey = "+on.RemoteAccess.PublicKey), "bundle_keys_placeholder"},
		"mra not in guard":   {mut("nodes/gw/etc/nftables.d/meridian.nft", `iifname { "eth0", "mra" } counter drop`, `iifname "eth0" counter drop`), "remote_access_config"},
	} {
		if it := itemsByID(CheckBundle(on, c.files))[c.id]; it.Status != Fail {
			t.Errorf("%s: %s not flagged: %+v", name, c.id, it)
		}
	}
	stale := mut("nodes/gw/usr/local/sbin/meridian-routes.sh", "# failover companions", "ip link set 'mra' up\n# failover companions")
	if it := itemsByID(CheckBundle(off, stale))["remote_access_config"]; it.Status != Fail {
		t.Errorf("mra in the files of a topology without remote access not flagged: %+v", it)
	}
}
