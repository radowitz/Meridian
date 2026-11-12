package validate

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

func TestExampleTopologyHasNoErrors(t *testing.T) {
	res := Run(defaults.Example())
	var errs []Issue
	for _, iss := range res.Issues {
		if iss.Severity == SeverityError {
			errs = append(errs, iss)
		}
	}
	if len(errs) > 0 {
		t.Fatalf("example topology has errors: %+v", errs)
	}
	exits := 0
	for _, n := range defaults.Example().Nodes {
		if n.Role == model.RoleExit {
			exits++
		}
	}
	if len(res.Paths) != exits {
		t.Fatalf("paths = %d, want %d (one per exit)", len(res.Paths), exits)
	}
	for _, p := range res.Paths {
		joined := strings.Join(p.Nodes, ",")
		for _, id := range []string{"gw", "ali", "ix", "hk-hub", p.ExitID} {
			if !strings.Contains(joined, id) {
				t.Fatalf("path to %s = %s, missing %s", p.ExitID, joined, id)
			}
		}
		if p.MTU < 1280 {
			t.Fatalf("mtu %d", p.MTU)
		}
		want := 1360
		if p.ExitID == "v6-v4out" {
			want = 1280
		}
		if p.MTU != want {
			t.Fatalf("path %s mtu = %d, want %d", p.ExitID, p.MTU, want)
		}
	}
	hk, ok := GroupTarget(defaults.Example(), "hk")
	if !ok || hk.ID != "hk-ix" {
		t.Fatalf("default hk exit = %+v", hk)
	}
}

func TestRejectsPathThatSkipsIX(t *testing.T) {
	topo := defaults.Example()
	var links []model.Link
	for _, l := range topo.Links {
		if l.ID == "ali-ix" || l.ID == "ix-hub" {
			continue
		}
		links = append(links, l)
	}
	// A direct public WG from Aliyun to the hub would skip the IX.
	links = append(links, model.Link{
		ID: "ali-hub-direct", From: "ali", To: "hk-hub",
		Transport: model.TransportDirectWG, Enabled: true, MTU: 1420, WGPort: 51900,
	})
	topo.Links = links
	assertError(t, Run(topo), "path_missing_ix")
}

func TestRejectsMeshFromHomeOrAsIXBackup(t *testing.T) {
	topo := defaults.Example()
	topo.Links = append(topo.Links, model.Link{
		ID: "gw-us-mesh", From: "gw", To: "us",
		Transport: model.TransportCFMesh, Enabled: true, Standby: true, MTU: 1280,
	})
	assertError(t, Run(topo), "mesh_bypasses_ix")

	topo = defaults.Example()
	topo.Links = append(topo.Links, model.Link{
		ID: "ali-hub-mesh", From: "ali", To: "hk-hub",
		Transport: model.TransportCFMesh, Enabled: true, MTU: 1280,
	})
	res := Run(topo)
	assertError(t, res, "mesh_bypasses_ix")
	assertError(t, res, "mesh_not_standby")
}

func TestIXReplacementMustBeProvisionedBeforeModeOn(t *testing.T) {
	topo := defaults.Example()
	var links []model.Link
	for _, l := range topo.Links {
		if l.Transport == model.TransportIXReplacementWSS {
			continue
		}
		links = append(links, l)
	}
	topo.Links = links
	res := Run(topo)
	assertSeverity(t, res, "ix_replacement_not_provisioned", SeverityWarning)

	topo.Settings.IXReplacementMode = true
	assertError(t, Run(topo), "ix_replacement_not_provisioned")
}

func TestReplacementWSSCannotBeActiveByDefault(t *testing.T) {
	topo := defaults.Example()
	for i := range topo.Links {
		if topo.Links[i].ID == "ali-hub-wss" {
			topo.Links[i].Standby = false
		}
	}
	assertError(t, Run(topo), "ix_replacement_not_standby")
}

func TestNATDialOutRules(t *testing.T) {
	topo := defaults.Example()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].EndpointV4 = "198.51.100.50"
		}
	}
	assertError(t, Run(topo), "nat_endpoint_forbidden")

	topo = defaults.Example()
	for i := range topo.Links {
		if topo.Links[i].ID == "tw-hub" {
			topo.Links[i].From = "hk-hub"
			topo.Links[i].To = "tw"
			zero := 0
			topo.Links[i].Keepalive = &zero
		}
	}
	res := Run(topo)
	assertError(t, res, "nat_dial_direction")
	assertError(t, res, "nat_keepalive_required")
}

func TestNetflixRequiresResidential(t *testing.T) {
	topo := defaults.Example()
	for i := range topo.Rules {
		if topo.Rules[i].ID == "auto-netflix" {
			topo.Rules[i].TargetGroup = ""
			topo.Rules[i].TargetExit = "hk-ix"
		}
	}
	assertError(t, Run(topo), "residential_required")
	// Aimed at a group without require_residential: same refusal.
	topo = defaults.Example()
	for i := range topo.Rules {
		if topo.Rules[i].ID == "auto-netflix" {
			topo.Rules[i].TargetGroup = "hk"
		}
	}
	assertError(t, Run(topo), "residential_required")
}

func TestPureV6ExitNeedsWorkaround(t *testing.T) {
	topo := defaults.Example()
	topo.Nodes = append(topo.Nodes, model.Node{
		ID: "v6only", Name: "纯 v6 出口", Role: model.RoleExit, Region: "us",
		Managed: true, PathV4: false, PathV6: true, EgressV4: false, EgressV6: true,
	})
	topo.Links = append(topo.Links, model.Link{
		ID: "hub-v6", From: "hk-hub", To: "v6only",
		Transport: model.TransportDirectWG, Enabled: true, MTU: 1420, WGPort: 51910,
	})
	assertError(t, Run(topo), "pure_v6_unreachable")

	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "v6only" {
			topo.Nodes[i].V6Workaround = model.WorkaroundDualstackRelay
		}
	}
	res := Run(topo)
	if hasCode(res, "pure_v6_unreachable") {
		t.Fatal("selecting a workaround should clear pure_v6_unreachable")
	}
	if !hasCode(res, "workaround_not_wired") {
		t.Fatal("an unwired dual-stack relay must still be rejected")
	}
}

func TestMTUBelow1280Rejected(t *testing.T) {
	topo := defaults.Example()
	for i := range topo.Links {
		if topo.Links[i].ID == "gw-ali" {
			topo.Links[i].WSSMTU = 1200
		}
	}
	assertError(t, Run(topo), "mtu_too_low")
}

func TestULAMustNotCollideWithLAN(t *testing.T) {
	topo := defaults.Example()
	topo.Settings.LANIPv6Prefix = "fd66:0:0:1::/64"
	assertError(t, Run(topo), "prefix_conflict")

	topo = defaults.Example()
	for i := range topo.Links {
		if topo.Links[i].ID == "gw-ali" {
			topo.Links[i].FromV4 = "192.168.100.20"
		}
	}
	assertError(t, Run(topo), "prefix_conflict")
}

func TestAAAAFilterIsWarningNotACountryChange(t *testing.T) {
	res := Run(defaults.Example())
	found := false
	for _, iss := range res.Issues {
		if iss.Code == "aaaa_filtered" {
			found = true
			if iss.Severity != SeverityWarning {
				t.Fatalf("severity %s", iss.Severity)
			}
			if strings.Contains(iss.Message, "别的国家") == false && strings.Contains(iss.Message, "同一出口") == false {
				t.Fatal(iss.Message)
			}
		}
	}
	if !found {
		t.Fatal("expected aaaa_filtered warning for the v4-only TW/SG exits")
	}
}

func TestImageAndNAT64Prefix(t *testing.T) {
	topo := defaults.Example()
	topo.Settings.MeshImage = "cloudflare/mesh:latest"
	topo.Settings.RegioncheckImage = "lmc999/regioncheck:2024.1"
	if Run(topo).HasErrors() {
		t.Fatal(Run(topo).Issues)
	}
	topo.Settings.MeshImage = "cloudflare/mesh:latest;rm"
	assertError(t, Run(topo), "bad_image")
	topo = defaults.Example()
	topo.Settings.NAT64.Prefix = "64:ff9b::/96\nip route replace default via 192.168.100.1"
	assertError(t, Run(topo), "nat64_prefix")
}

func assertError(t *testing.T, res Result, code string) {
	t.Helper()
	for _, iss := range res.Issues {
		if iss.Code == code && iss.Severity == SeverityError {
			return
		}
	}
	t.Fatalf("missing error %s in %+v", code, res.Issues)
}

func assertSeverity(t *testing.T, res Result, code, sev string) {
	t.Helper()
	for _, iss := range res.Issues {
		if iss.Code == code && iss.Severity == sev {
			return
		}
	}
	t.Fatalf("missing %s/%s in %+v", code, sev, res.Issues)
}

func hasCode(res Result, code string) bool {
	for _, iss := range res.Issues {
		if iss.Code == code && iss.Severity == SeverityError {
			return true
		}
	}
	return false
}

func setGroup(topo *model.Topology, id string, fn func(g *model.RegionGroup)) {
	for i := range topo.Groups {
		if topo.Groups[i].ID == id {
			fn(&topo.Groups[i])
		}
	}
}

func setRule(topo *model.Topology, id string, fn func(r *model.Rule)) {
	for i := range topo.Rules {
		if topo.Rules[i].ID == id {
			fn(&topo.Rules[i])
		}
	}
}

func TestExampleGroupsValidate(t *testing.T) {
	res := Run(defaults.Example())
	for _, iss := range res.Issues {
		if iss.GroupID != "" && iss.Severity == SeverityError {
			t.Errorf("example group issue: %+v", iss)
		}
	}
}

// Group modes, choices and constraints that contradict each other, and
// rules that would configure a second place, are refused.
func TestRegionGroupConflicts(t *testing.T) {
	cases := []struct {
		name string
		code string
		edit func(topo *model.Topology)
	}{
		{"chosen in auto", "chosen_in_auto", func(topo *model.Topology) {
			setGroup(topo, "us", func(g *model.RegionGroup) { g.Chosen = "us-2" })
		}},
		{"on_failure in auto", "on_failure_in_auto", func(topo *model.Topology) {
			setGroup(topo, "us", func(g *model.RegionGroup) { g.OnFailure = model.OnFailureHold })
		}},
		{"manual without choice", "chosen_not_eligible", func(topo *model.Topology) {
			setGroup(topo, "us-pin", func(g *model.RegionGroup) { g.Chosen = "" })
		}},
		{"manual choice outside the group", "chosen_not_eligible", func(topo *model.Topology) {
			setGroup(topo, "us-pin", func(g *model.RegionGroup) { g.Chosen = "jp" })
		}},
		{"manual choice excluded by a constraint", "chosen_not_eligible", func(topo *model.Topology) {
			setGroup(topo, "hk", func(g *model.RegionGroup) {
				g.Mode, g.Chosen, g.Members = model.GroupManual, "hk-resi", append(g.Members, "hk-resi")
			})
		}},
		{"require and exclude residential", "constraint_conflict", func(topo *model.Topology) {
			setGroup(topo, "hk", func(g *model.RegionGroup) { g.RequireResidential = true })
		}},
		{"rule needs v6, group does not require it", "constraint_conflict", func(topo *model.Topology) {
			setRule(topo, "auto-openai", func(r *model.Rule) { r.RequireV6 = true })
		}},
		{"rule pinned to an exit without v6", "constraint_conflict", func(topo *model.Topology) {
			setRule(topo, "auto-openai", func(r *model.Rule) { r.RequireV6, r.TargetGroup, r.TargetExit = true, "", "sg" })
		}},
		{"rule still carries a mode", "rule_mode_removed", func(topo *model.Topology) {
			setRule(topo, "auto-openai", func(r *model.Rule) { r.Mode = model.ModePin })
		}},
		{"rule not migrated", "legacy_pool_target", func(topo *model.Topology) {
			setRule(topo, "auto-openai", func(r *model.Rule) { r.TargetPool, r.TargetGroup = "us", "" })
		}},
		{"rule aims at a group and an exit", "rule_target_conflict", func(topo *model.Topology) {
			setRule(topo, "auto-openai", func(r *model.Rule) { r.TargetExit = "us" })
		}},
		{"unknown group", "group_not_found", func(topo *model.Topology) {
			setRule(topo, "auto-openai", func(r *model.Rule) { r.TargetGroup = "nope" })
		}},
		{"unknown member", "group_member_invalid", func(topo *model.Topology) {
			setGroup(topo, "us", func(g *model.RegionGroup) { g.Members = append(g.Members, "ghost") })
		}},
		{"no default group", "no_default_exit", func(topo *model.Topology) { topo.Settings.DefaultGroup = "" }},
		{"default group without eligible member", "no_default_exit", func(topo *model.Topology) {
			setGroup(topo, "hk", func(g *model.RegionGroup) { g.RequireV6, g.Members = false, []string{"hk-resi"} })
		}},
		{"bad group id", "bad_id", func(topo *model.Topology) {
			topo.Groups = append(topo.Groups, model.RegionGroup{ID: "Bad ID", Mode: model.GroupAuto})
		}},
		{"bad mode", "invalid_field", func(topo *model.Topology) {
			setGroup(topo, "jp", func(g *model.RegionGroup) { g.Mode = "sometimes" })
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			topo := defaults.Example()
			c.edit(&topo)
			assertError(t, Run(topo), c.code)
		})
	}
}

// Several groups per region are fine, and an exit may be in several groups.
func TestSeveralGroupsPerRegion(t *testing.T) {
	topo := defaults.Example()
	topo.Groups = append(topo.Groups, model.RegionGroup{
		ID: "hk-all", Name: "香港全部", Region: "hk", Mode: model.GroupManual, Chosen: "hk-resi",
		Members: []string{"hk-2", "hk-resi", "hk-ix"},
	})
	for _, iss := range Run(topo).Issues {
		if iss.GroupID == "hk-all" && iss.Severity == SeverityError {
			t.Fatalf("unexpected: %+v", iss)
		}
	}
	n, ok := GroupTarget(topo, "hk-all")
	if !ok || n.ID != "hk-resi" {
		t.Fatalf("manual target = %+v", n)
	}
}

func TestTooManyMarks(t *testing.T) {
	topo := defaults.Example()
	for i := 0; i < 240; i++ {
		topo.Groups = append(topo.Groups, model.RegionGroup{ID: "g" + strconv.Itoa(i), Name: "g", Mode: model.GroupAuto, Members: []string{"jp"}})
	}
	assertError(t, Run(topo), "too_many_marks")
}

func TestListSourceAndGeositeFiles(t *testing.T) {
	has := func(r Result, code string) bool {
		for _, i := range r.Issues {
			if i.Code == code {
				return true
			}
		}
		return false
	}
	topo := defaults.Example()
	for _, ok := range []string{"", "domestic", "overseas", "automatic"} {
		topo.Settings.ListSource = ok
		if has(Run(topo), "bad_list_source") {
			t.Fatalf("%q refused", ok)
		}
	}
	topo.Settings.ListSource = "https://mirror.example"
	if !has(Run(topo), "bad_list_source") {
		t.Fatal("bad list source accepted")
	}
	topo = defaults.Example()
	base := topo.Rules[0]
	a, b := base, base
	a.ID, a.MatchType, a.Geosite = "ga", model.MatchGeosite, "foo-bar"
	b.ID, b.MatchType, b.Geosite = "gb", model.MatchGeosite, "foo_bar"
	topo.Rules = append(topo.Rules, a, b)
	if !has(Run(topo), "geosite_name_collision") {
		t.Fatal("two geosite names on one file accepted")
	}
}

func raKey(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

// raTopo is the example with a valid, enabled remote-access block. The keys
// are public keys (not secrets) made of fixed bytes.
func raTopo() model.Topology {
	t := defaults.Example()
	t.RemoteAccess = &model.RemoteAccess{Enabled: true, Endpoint: "home.example.net", ListenPort: 51900,
		PublicKey: raKey(1), KeyID: "ra-key-test",
		Devices: []model.RemoteDevice{
			{ID: "dev-a", Name: "phone", Mode: model.RemoteModeFull, Enabled: true, PublicKey: raKey(2), IPv4: "10.67.0.2", IPv6: "fd67::2"},
			{ID: "dev-b", Name: "laptop", Mode: model.RemoteModeHome, Enabled: true, PublicKey: raKey(3), IPv4: "10.67.0.3", IPv6: "fd67::3"},
		}}
	return t
}

func remoteErrs(t model.Topology) []Issue {
	var out []Issue
	for _, i := range Run(t).Issues {
		if i.Severity == SeverityError && strings.HasPrefix(i.Code, "remote_") {
			out = append(out, i)
		}
	}
	return out
}

func TestRemoteAccessValid(t *testing.T) {
	if errs := remoteErrs(raTopo()); len(errs) != 0 {
		t.Fatalf("%+v", errs)
	}
	for _, i := range Run(raTopo()).Issues {
		if i.Severity == SeverityError {
			t.Fatalf("unexpected error %+v", i)
		}
	}
	off := raTopo()
	off.RemoteAccess.Enabled = false
	off.RemoteAccess.ListenPort = 53
	if errs := remoteErrs(off); len(errs) != 0 {
		t.Fatalf("a disabled block is not compiled and must not block the topology: %+v", errs)
	}
	if len(CheckRemoteAccessConfig(off)) == 0 {
		t.Fatal("the API check must still see the conflict")
	}
}

func TestRemoteAccessConflicts(t *testing.T) {
	ports := GatewayPorts(raTopo())
	var tunnelPort, localPort int
	for p, why := range ports {
		if strings.Contains(why, "WireGuard 端口") && tunnelPort == 0 {
			tunnelPort = p
		}
		if strings.Contains(why, "wstunnel") && localPort == 0 {
			localPort = p
		}
	}
	if tunnelPort == 0 || localPort == 0 {
		t.Fatalf("example gateway ports not found: %v", ports)
	}
	cases := []struct {
		name  string
		edit  func(t *model.Topology)
		code  string
		field string
	}{
		{"no endpoint", func(t *model.Topology) { t.RemoteAccess.Endpoint = "" }, "remote_endpoint", "endpoint"},
		{"endpoint with port", func(t *model.Topology) { t.RemoteAccess.Endpoint = "home.example.net:51900" }, "remote_endpoint", "endpoint"},
		{"endpoint with space", func(t *model.Topology) { t.RemoteAccess.Endpoint = "home example" }, "remote_endpoint", "endpoint"},
		{"no port", func(t *model.Topology) { t.RemoteAccess.ListenPort = 0 }, "remote_port", "listen_port"},
		{"port range", func(t *model.Topology) { t.RemoteAccess.ListenPort = 70000 }, "remote_port", "listen_port"},
		{"dns port", func(t *model.Topology) { t.RemoteAccess.ListenPort = 53 }, "remote_port_conflict", "listen_port"},
		{"dot port", func(t *model.Topology) { t.RemoteAccess.ListenPort = 853 }, "remote_port_conflict", "listen_port"},
		{"panel port", func(t *model.Topology) { t.RemoteAccess.ListenPort = 8787 }, "remote_port_conflict", "listen_port"},
		{"tunnel port", func(t *model.Topology) { t.RemoteAccess.ListenPort = tunnelPort }, "remote_port_conflict", "listen_port"},
		{"wstunnel port", func(t *model.Topology) { t.RemoteAccess.ListenPort = localPort }, "remote_port_conflict", "listen_port"},
		{"wss listen", func(t *model.Topology) {
			for i := range t.Nodes {
				if t.Nodes[i].ID == "gw" {
					t.Nodes[i].WSSListenPort = 51900
				}
			}
		}, "remote_port_conflict", "listen_port"},
		{"v4 in LAN", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "192.168.100.128/25" }, "remote_prefix_conflict", "ipv4_prefix"},
		{"v4 covers LAN", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "192.168.0.0/16" }, "remote_prefix_conflict", "ipv4_prefix"},
		{"v4 in tunnel plan", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "10.66.5.0/24" }, "remote_prefix_conflict", "ipv4_prefix"},
		{"v4 covers tunnel plan", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "10.0.0.0/16" }, "", ""},
		{"v4 transit", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "10.66.200.0/24" }, "remote_prefix_conflict", "ipv4_prefix"},
		{"v4 mesh", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "169.254.66.0/29" }, "remote_prefix", "ipv4_prefix"},
		{"v4 cloudflare", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "100.96.0.0/24" }, "remote_prefix", "ipv4_prefix"},
		{"v4 public", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "198.51.100.0/24" }, "remote_prefix", "ipv4_prefix"},
		{"v4 not masked", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "10.67.0.1/24" }, "remote_prefix", "ipv4_prefix"},
		{"v4 too small", func(t *model.Topology) { t.RemoteAccess.IPv4Prefix = "10.67.0.0/30" }, "remote_prefix", "ipv4_prefix"},
		{"v4 rule cidr", func(t *model.Topology) {
			t.Rules = append(t.Rules, model.Rule{ID: "c1", Name: "c", Manual: true, Enabled: true, MatchType: model.MatchCIDR, MatchValue: "10.67.0.128/25", TargetGroup: t.Settings.DefaultGroup})
		}, "remote_prefix_conflict", "ipv4_prefix"},
		{"v4 link address", func(t *model.Topology) {
			t.Links[0].FromV4, t.Links[0].ToV4 = "10.67.0.250", "10.67.0.249"
		}, "remote_prefix_conflict", "ipv4_prefix"},
		{"v6 in fd66", func(t *model.Topology) { t.RemoteAccess.IPv6Prefix = "fd66:0:0:5::/64" }, "remote_prefix_conflict", "ipv6_prefix"},
		{"v6 covers fd66", func(t *model.Topology) { t.RemoteAccess.IPv6Prefix = "fd00::/48" }, "", ""},
		{"v6 transit", func(t *model.Topology) { t.RemoteAccess.IPv6Prefix = "fd66:0:0:ff::/64" }, "remote_prefix_conflict", "ipv6_prefix"},
		{"v6 LAN", func(t *model.Topology) { t.RemoteAccess.IPv6Prefix = "2001:db8:100::/64" }, "remote_prefix", "ipv6_prefix"},
		{"v6 not ULA", func(t *model.Topology) { t.RemoteAccess.IPv6Prefix = "2001:db8:5::/64" }, "remote_prefix", "ipv6_prefix"},
		{"v6 NAT64", func(t *model.Topology) {
			t.Settings.NAT64.Prefix = "fd67::/96"
		}, "remote_prefix_conflict", "ipv6_prefix"},
		{"v6 mesh route", func(t *model.Topology) {
			t.Links[0].MeshRoutes = []string{"fd67::/80"}
		}, "remote_prefix_conflict", "ipv6_prefix"},
		{"lan iface", func(t *model.Topology) {
			t.Settings.LANInterface = "mra"
			for i := range t.Nodes {
				if t.Nodes[i].Role == model.RoleGateway {
					t.Nodes[i].LANInterface = ""
				}
			}
		}, "remote_lan_interface", "lan_interface"},
		{"no key", func(t *model.Topology) { t.RemoteAccess.PublicKey = "" }, "remote_key", "public_key"},
		{"dup address", func(t *model.Topology) { t.RemoteAccess.Devices[1].IPv4 = "10.67.0.2" }, "remote_device", "ipv4"},
		{"gateway address", func(t *model.Topology) { t.RemoteAccess.Devices[1].IPv4 = "10.67.0.1" }, "remote_device", "ipv4"},
		{"broadcast", func(t *model.Topology) { t.RemoteAccess.Devices[1].IPv4 = "10.67.0.255" }, "remote_device", "ipv4"},
		{"outside pool", func(t *model.Topology) { t.RemoteAccess.Devices[1].IPv6 = "fd68::3" }, "remote_device", "ipv6"},
		{"dup key", func(t *model.Topology) { t.RemoteAccess.Devices[1].PublicKey = raKey(2) }, "remote_device", "public_key"},
		{"gateway key", func(t *model.Topology) { t.RemoteAccess.Devices[1].PublicKey = raKey(1) }, "remote_device", "public_key"},
		{"bad mode", func(t *model.Topology) { t.RemoteAccess.Devices[1].Mode = "split" }, "remote_device", "mode"},
		{"dup id", func(t *model.Topology) { t.RemoteAccess.Devices[1].ID = "dev-a" }, "remote_device", "id"},
		{"too many", func(t *model.Topology) {
			for i := 0; i < model.MaxRemoteDevices; i++ {
				t.RemoteAccess.Devices = append(t.RemoteAccess.Devices, model.RemoteDevice{ID: "dev-x" + strconv.Itoa(i), Name: "x", Mode: model.RemoteModeFull,
					PublicKey: raKey(byte(10 + i)), IPv4: "10.67.0." + strconv.Itoa(10+i), IPv6: "fd67::" + strconv.FormatInt(int64(10+i), 16)})
			}
		}, "remote_device_limit", "devices"},
	}
	for _, c := range cases {
		topo := raTopo()
		c.edit(&topo)
		errs := remoteErrs(topo)
		if c.code == "" {
			// Overlap rules are symmetric: a pool containing a planned
			// block is refused as well.
			if len(errs) == 0 {
				t.Errorf("%s: no error", c.name)
			}
			continue
		}
		found := false
		for _, e := range errs {
			found = found || (e.Code == c.code && e.Field == c.field)
		}
		if !found {
			t.Errorf("%s: want %s/%s, got %+v", c.name, c.code, c.field, errs)
		}
	}
}
