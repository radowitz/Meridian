package mesh_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
)

func rewrite(t *testing.T, d *mesh.Deployer, mut func(j *mesh.Journal)) {
	t.Helper()
	j, err := d.Load()
	if err != nil || j == nil {
		t.Fatal(err)
	}
	mut(j)
	b, _ := json.Marshal(j)
	if err := os.WriteFile(filepath.Join(d.Dir, "deploy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A schema-2 journal (pins without server and credential) is upgraded by
// the resolver; pins it cannot place stay empty; an existing server id is
// never replaced; the run itself is untouched.
func TestUpgradeSchema2Journal(t *testing.T) {
	f, srv := newFakeCF(t)
	d := newDeployer(t, f, srv, &fakeRemote{})
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	rewrite(t, d, func(j *mesh.Journal) {
		j.Schema = 2
		for i := range j.Hosts {
			j.Hosts[i].ServerID, j.Hosts[i].CredentialID = "", ""
		}
		for i := range j.Remotes {
			j.Remotes[i].Host.ServerID, j.Remotes[i].Host.CredentialID = "", ""
		}
	})
	before, _ := d.Load()
	d.ResolvePin = func(h mesh.HostPin) (string, string, bool) {
		if h.NodeID == "hk-hub" {
			return "", "", false
		}
		return "srv-" + h.NodeID, "key-1", true
	}
	j, err := d.UpgradeJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.Schema != 3 || j.RunID != before.RunID || j.State != before.State || j.AccountID != before.AccountID || len(j.Routes) != len(before.Routes) {
		t.Fatalf("%+v", j)
	}
	for i, h := range j.Hosts {
		want := before.Hosts[i]
		if h.NodeID != "hk-hub" {
			want.ServerID, want.CredentialID = "srv-"+h.NodeID, "key-1"
		}
		if h != want {
			t.Fatalf("pin %+v want %+v", h, want)
		}
	}
	for _, rm := range j.Remotes {
		if (rm.NodeID == "hk-hub") != (rm.Host.ServerID == "") {
			t.Fatalf("remote copy %+v", rm)
		}
	}
	// Idempotent; and a resolver naming another server never re-points.
	d.ResolvePin = func(h mesh.HostPin) (string, string, bool) { return "srv-other", "key-2", true }
	j, _ = d.UpgradeJournal()
	for _, h := range j.Hosts {
		if h.NodeID != "hk-hub" && (h.ServerID != "srv-"+h.NodeID || h.CredentialID != "key-1") {
			t.Fatalf("re-pointed %+v", h)
		}
	}
	// A journal from a newer program is refused.
	rewrite(t, d, func(j *mesh.Journal) { j.Schema = 99 })
	if _, err := d.Load(); !errors.Is(err, mesh.ErrJournalTooNew) {
		t.Fatalf("%v", err)
	}
}

// CheckHosts stops a withdrawal before anything is compensated.
func TestCheckHostsBlocksWithdrawal(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	restores := rem.count(mesh.ActRestore)
	d.CheckHosts = func(*mesh.Journal) error { return errors.New("server srv-x is gone") }
	j, err := d.Withdraw(context.Background())
	if !errors.Is(err, mesh.ErrHostsBlocked) || j.State != mesh.StatePublished || rem.count(mesh.ActRestore) != restores {
		t.Fatalf("%v %s", err, j.State)
	}
	for _, r := range j.Routes {
		if r.State == mesh.ResRemoved {
			t.Fatal("route removed")
		}
	}
	d.CheckHosts = nil
	if j, err := d.Withdraw(context.Background()); err != nil || j.State != mesh.StateWithdrawn {
		t.Fatalf("%v", err)
	}
}
