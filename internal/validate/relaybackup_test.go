package validate

import (
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// The backup hub reached only through relays (defaults.RelayBackupExample).

func relayBackupRun(mut func(t *model.Topology)) map[string]Issue {
	topo := defaults.RelayBackupExample()
	if mut != nil {
		mut(&topo)
	}
	model.MigrateRegionGroups(&topo)
	return noixErrs(Run(topo))
}

func TestRelayBackupGroups(t *testing.T) {
	topo := defaults.RelayBackupExample()
	if !topo.RelayBackup() || len(topo.MainGroupRelays()) != 1 || len(topo.BackupGroupRelays()) != 2 {
		t.Fatalf("groups main %v backup %v", topo.MainGroupRelays(), topo.BackupGroupRelays())
	}
	if g := topo.RelayGroupOf("bk1"); g != model.RelayGroupBackup {
		t.Fatalf("bk1 group %q", g)
	}
	if g := topo.RelayGroupOf("hub"); g != "" {
		t.Fatalf("hub group %q", g)
	}
	// A disabled relay → hub link does not group the relay.
	noixSetLink(&topo, "bk1-hkb", func(l *model.Link) { l.Enabled = false })
	if g := topo.RelayGroupOf("bk1"); g != model.RelayGroupMain {
		t.Fatalf("bk1 with a disabled link: %q", g)
	}
	if defaults.NoIXExample().RelayBackup() || defaults.DualHubExample().RelayBackup() {
		t.Fatal("gateway-direct backup reported as a backup group")
	}
}

func TestRelayBackupAccepted(t *testing.T) {
	if errs := relayBackupRun(nil); len(errs) != 0 {
		t.Fatalf("refused: %v", errs)
	}
	// The gateway-direct form is still accepted.
	topo := defaults.NoIXExample()
	model.MigrateRegionGroups(&topo)
	if errs := noixErrs(Run(topo)); len(errs) != 0 {
		t.Fatalf("gateway-direct backup refused: %v", errs)
	}
	// One backup-group relay over plain WireGuard is fine too.
	if errs := relayBackupRun(func(t *model.Topology) {
		noixSetLink(t, "bk2-hkb", func(l *model.Link) { l.Transport = model.TransportDirectWG })
	}); len(errs) != 0 {
		t.Fatalf("direct_wg backup group refused: %v", errs)
	}
}

func TestRelayBackupRefused(t *testing.T) {
	cases := []struct {
		name string
		mut  func(t *model.Topology)
		code string
	}{
		{"relay tunnelled to both hubs", func(t *model.Topology) {
			t.Links = append(t.Links, model.Link{ID: "bk1-hub", From: "bk1", To: "hub", Transport: model.TransportDirectWG, Enabled: true})
		}, "relay_group_ambiguous"},
		{"both backup forms", func(t *model.Topology) {
			t.Links = append(t.Links, model.Link{ID: "gw-hkb", From: "gw", To: "hkb", Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true})
		}, "backup_hub_mixed"},
		{"standby relay link", func(t *model.Topology) {
			noixSetLink(t, "bk1-hkb", func(l *model.Link) { l.Standby = true })
		}, "backup_hub_relay_link_unsupported"},
		{"no backup at all", func(t *model.Topology) {
			noixSetLink(t, "bk1-hkb", func(l *model.Link) { l.Enabled = false })
			noixSetLink(t, "bk2-hkb", func(l *model.Link) { l.Enabled = false })
		}, "backup_hub_not_wired"},
	}
	for _, c := range cases {
		if _, ok := relayBackupRun(c.mut)[c.code]; !ok {
			t.Errorf("%s: %s not reported: %v", c.name, c.code, relayBackupRun(c.mut))
		}
	}
}

// A sole main-group relay may reach the primary hub over WSS or the
// UDP+WSS dual leg; with two main-group relays the restriction stays.
func TestRelayBackupMainRelayTransports(t *testing.T) {
	for _, tr := range []model.Transport{model.TransportWGOverWSS, model.TransportUDPWSSFailover} {
		if errs := relayBackupRun(func(t *model.Topology) {
			noixSetLink(t, "access-hub", func(l *model.Link) { l.Transport = tr })
		}); len(errs) != 0 {
			t.Errorf("%s main relay refused: %v", tr, errs)
		}
	}
	errs := relayBackupRun(func(t *model.Topology) {
		noixSetLink(t, "access-hub", func(l *model.Link) { l.Transport = model.TransportWGOverWSS })
		t.Nodes = append(t.Nodes, model.Node{ID: "access2", Name: "access2", Role: model.RoleRelay, Region: "cn", Managed: true})
		t.Links = append(t.Links,
			model.Link{ID: "gw-access2", From: "gw", To: "access2", Transport: model.TransportDirectWG, Enabled: true},
			model.Link{ID: "access2-hub", From: "access2", To: "hub", Transport: model.TransportDirectWG, Enabled: true})
	})
	if _, ok := errs["sharing_relay_hub_transport"]; !ok {
		t.Errorf("two main relays with wg_over_wss accepted: %v", errs)
	}
}
