package validate

import (
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
	hk, ok := SelectExit(defaults.Example(), "hk")
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
			topo.Rules[i].TargetPool = "hk"
			topo.Rules[i].TargetExit = "hk-ix"
		}
	}
	assertError(t, Run(topo), "residential_required")
}

func TestPureV6ExitNeedsWorkaround(t *testing.T) {
	topo := defaults.Example()
	topo.Nodes = append(topo.Nodes, model.Node{
		ID: "v6only", Name: "纯 v6 出口", Role: model.RoleExit, Region: "us",
		Managed: true, PathV4: false, PathV6: true, EgressV4: false, EgressV6: true,
		Pool: "v6",
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
