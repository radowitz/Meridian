package mesh_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/mesh"
)

// Withdrawal acts on the SSH targets pinned at deploy time (after overrides
// and defaults), with the host key each host presented on first contact.
func TestWithdrawUsesPinnedTargets(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	d := newDeployer(t, f, srv, rem)
	p := meshPlan(t)
	// A request-level override for the hub (what the API applies to the plan).
	hub := 0
	for i, n := range p.Nodes {
		if n.ID == "hk-hub" {
			hub = i
		}
	}
	p.Nodes[hub].SSHHost, p.Nodes[hub].SSHPort, p.Nodes[hub].SSHUser = "198.51.100.7", 2222, "ops"
	j, err := d.Deploy(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if j.AccountID != f.account || j.Schema != mesh.JournalSchema {
		t.Fatalf("account %q schema %d", j.AccountID, j.Schema)
	}
	pins := map[string]mesh.HostPin{}
	for _, h := range j.Hosts {
		pins[h.NodeID] = h
		if h.HostKey != "SHA256:fake-"+h.NodeID {
			t.Fatalf("%s pinned key %q", h.NodeID, h.HostKey)
		}
	}
	if h := pins["hk-hub"]; h.SSHHost != "198.51.100.7" || h.SSHPort != 2222 || h.SSHUser != "ops" {
		t.Fatalf("hub pin %+v", h)
	}
	for _, n := range p.Nodes {
		if n.ID != "hk-hub" {
			if h := pins[n.ID]; h.SSHHost != n.SSHHost || h.SSHPort != 22 || h.SSHUser != "root" {
				t.Fatalf("%s pin %+v (defaults not applied)", n.ID, h)
			}
		}
	}
	for _, rm := range j.Remotes {
		if rm.Host != pins[rm.NodeID] {
			t.Fatalf("remote %s records %+v, pinned %+v", rm.NodeID, rm.Host, pins[rm.NodeID])
		}
	}
	raw, _ := os.ReadFile(filepath.Join(d.Dir, "deploy.json"))
	for _, want := range []string{`"account_id": "` + f.account, `"host_key": "SHA256:fake-hk-hub"`, `"ssh_host": "198.51.100.7"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("journal missing %s", want)
		}
	}
	// Every action after preflight already required the pinned key.
	for i, tg := range rem.targets {
		if !strings.HasPrefix(rem.calls[i], "preflight/") && tg.HostKey == "" {
			t.Fatalf("%s ran without a pinned host key", rem.calls[i])
		}
	}
	before := len(rem.calls)
	if j, err = d.Withdraw(context.Background()); err != nil || j.State != mesh.StateWithdrawn {
		t.Fatalf("withdraw: %v %s", err, j.State)
	}
	restores := 0
	for i := before; i < len(rem.calls); i++ {
		if !strings.HasPrefix(rem.calls[i], "restore/") {
			continue
		}
		restores++
		tg := rem.targets[i]
		h := pins[tg.ID]
		if tg.SSHHost != h.SSHHost || tg.SSHPort != h.SSHPort || tg.SSHUser != h.SSHUser || tg.HostKey != h.HostKey {
			t.Fatalf("restore %s went to %+v, pinned %+v", tg.ID, tg, h)
		}
	}
	if restores != len(p.Nodes) {
		t.Fatalf("%d restores for %d hosts", restores, len(p.Nodes))
	}
}

// A different machine at the pinned address (another host key) is refused:
// nothing runs there, the record stays, and the withdrawal reports failure.
func TestWithdrawRefusesDifferentHostKey(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{hostKeys: map[string]string{}}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	rem.hostKeys["hk-hub"] = "SHA256:someone-else"
	j, err := d.Withdraw(context.Background())
	var se *mesh.StageError
	if !errors.As(err, &se) || j.State != mesh.StateCompensationFailed {
		t.Fatalf("withdraw on a swapped host: %v %s", err, j.State)
	}
	if rem.has("restore/hk-hub") {
		t.Fatal("restore ran on a host with a different key")
	}
	refused := false
	for _, k := range rem.refused {
		refused = refused || k == "restore/hk-hub"
	}
	if !refused {
		t.Fatal("swapped host was not refused")
	}
	for _, rm := range j.Remotes {
		if rm.NodeID == "hk-hub" && (rm.State == mesh.ResRemoved || rm.Error == "") {
			t.Fatalf("hub recorded as restored: %+v", rm)
		}
	}
	// The real host is back: the retry restores it.
	delete(rem.hostKeys, "hk-hub")
	if j, err = d.Withdraw(context.Background()); err != nil || j.State != mesh.StateWithdrawn {
		t.Fatalf("retry: %v %s", err, j.State)
	}
	if !rem.has("restore/hk-hub") {
		t.Fatal("hub never restored")
	}
}

// A host swapped between stages of the same run is refused too, and the
// compensation does not restore the impostor.
func TestHostKeyChangeDuringRunIsRefused(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{hostKeys: map[string]string{}}
	rem.after = func(r *fakeRemote, key string) {
		if key == "install/hk-hub" {
			r.hostKeys["hk-hub"] = "SHA256:impostor"
		}
	}
	d := newDeployer(t, f, srv, rem)
	j, err := d.Deploy(context.Background(), meshPlan(t))
	if err == nil || j.State != mesh.StateCompensationFailed {
		t.Fatalf("deploy across a host swap: %v %s", err, j.State)
	}
	if rem.has("health/hk-hub") || rem.has("restore/hk-hub") {
		t.Fatalf("ran on the swapped host: %v", rem.calls)
	}
	if len(f.routes) != 0 {
		t.Fatal("routes published")
	}
}

// A host the journal says this run installed on, but which has no backup
// directory for the run, is not counted as restored.
func TestRestoreWithoutBackupDirIsNotRestored(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{absent: map[string]bool{}}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	rem.absent["hk-hub"] = true
	j, err := d.Withdraw(context.Background())
	if err == nil || j.State != mesh.StateCompensationFailed {
		t.Fatalf("absent backup accepted: %v %s", err, j.State)
	}
	for _, rm := range j.Remotes {
		if rm.NodeID == "hk-hub" && (rm.State != mesh.ResCreated || !strings.Contains(rm.Error, "备份目录")) {
			t.Fatalf("hub record %+v", rm)
		}
	}
	rem.absent["hk-hub"] = false
	if j, err = d.Withdraw(context.Background()); err != nil || j.State != mesh.StateWithdrawn {
		t.Fatalf("retry: %v %s", err, j.State)
	}

	// An install that never got confirmed and left nothing on the host is
	// legitimately absent.
	f2, srv2 := newFakeCF(t)
	rem2 := &fakeRemote{failOnce: map[string]bool{"install/hk-hub": true}, absent: map[string]bool{"hk-hub": true}}
	d2 := newDeployer(t, f2, srv2, rem2)
	j, err = d2.Deploy(context.Background(), meshPlan(t))
	var se *mesh.StageError
	if !errors.As(err, &se) || !se.Compensated || j.State != mesh.StateFailed {
		t.Fatalf("unconfirmed install: %v %s", err, j.State)
	}
}

func TestRestoreScriptMarksAndDistinguishesAbsent(t *testing.T) {
	rs, _ := mesh.RestoreScript("0123456789abcdef", mesh.DefaultAddressing())
	for _, want := range []string{"MESH_RESTORE_ABSENT", `"$bk.restored"`, "already restored"} {
		if !strings.Contains(rs, want) {
			t.Errorf("restore script missing %q", want)
		}
	}
	if strings.Contains(rs, "MESH_RESTORE_OK nothing") {
		t.Error("a host without the run's backup still reports OK")
	}
}

// The deployment is bound to its Cloudflare account: the token of that
// account can be rotated while published, another account cannot be stored
// until the run is fully withdrawn, and a withdrawal never runs with
// credentials for another account.
func TestCloudflareAccountBinding(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	other := dummy("", 16)
	if err := d.SaveCredentials(mesh.Credentials{AccountID: other, APIToken: dummy("tok", 16)}); !errors.Is(err, mesh.ErrAccountLocked) {
		t.Fatalf("account switch while published: %v", err)
	}
	if c, _ := d.Creds.Load(); c.AccountID != f.account || c.APIToken != f.token {
		t.Fatal("refused switch changed the stored credentials")
	}
	if err := d.DeleteCredentials(); !errors.Is(err, mesh.ErrCredentialsInUse) {
		t.Fatalf("delete while published: %v", err)
	}
	// Same-account rotation.
	newTok := dummy("rot", 16)
	if err := d.SaveCredentials(mesh.Credentials{AccountID: f.account, APIToken: newTok}); err != nil {
		t.Fatalf("token rotation refused: %v", err)
	}
	f.mu.Lock()
	f.token = newTok
	f.mu.Unlock()
	j, err := d.Withdraw(context.Background())
	if err != nil || j.State != mesh.StateWithdrawn || len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatalf("withdraw after rotation: %v %s", err, j.State)
	}
	if err := d.SaveCredentials(mesh.Credentials{AccountID: other, APIToken: dummy("tok", 16)}); err != nil {
		t.Fatalf("switch after withdrawal: %v", err)
	}
}

func TestAccountSwitchRefusedWhileCompensationPending(t *testing.T) {
	f, srv := newFakeCF(t)
	d := newDeployer(t, f, srv, &fakeRemote{})
	f.failCreateRoute = 2
	f.failDeleteRoute = 100
	j, err := d.Deploy(context.Background(), meshPlan(t))
	if err == nil || j.State != mesh.StateCompensationFailed {
		t.Fatalf("state %s err %v", j.State, err)
	}
	if err := d.SaveCredentials(mesh.Credentials{AccountID: dummy("", 16), APIToken: dummy("tok", 16)}); !errors.Is(err, mesh.ErrAccountLocked) {
		t.Fatalf("account switch with compensation pending: %v", err)
	}
	f.mu.Lock()
	f.failDeleteRoute = 0
	f.mu.Unlock()
	if j, err = d.Withdraw(context.Background()); err != nil || j.State != mesh.StateFailed || len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatalf("retry: %v %s", err, j.State)
	}
}

// Credentials for another account that reached the store anyway (written
// around the lock) are never used to withdraw: "not found" in that account
// would otherwise be taken for "already removed".
func TestWithdrawRefusesCredentialsForAnotherAccount(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	d := newDeployer(t, f, srv, rem)
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	if err := d.Creds.Save(mesh.Credentials{AccountID: dummy("", 16), APIToken: f.token}); err != nil {
		t.Fatal(err)
	}
	restores := rem.count(mesh.ActRestore)
	j, err := d.Withdraw(context.Background())
	if !errors.Is(err, mesh.ErrAccountMismatch) {
		t.Fatalf("withdraw with another account: %v", err)
	}
	j, _ = d.Load()
	if j.State != mesh.StatePublished || rem.count(mesh.ActRestore) != restores {
		t.Fatalf("withdrawal acted: state %s", j.State)
	}
	for _, r := range j.Routes {
		if r.State != mesh.ResCreated {
			t.Fatalf("route %s recorded %s", r.Network, r.State)
		}
	}
	for _, n := range j.Nodes {
		if n.State != mesh.ResCreated {
			t.Fatalf("node %s recorded %s", n.Name, n.State)
		}
	}
	if len(f.routes) == 0 || len(f.nodes) == 0 {
		t.Fatal("resources vanished")
	}
	// Restoring the original account's credentials makes it withdrawable.
	if err := d.SaveCredentials(mesh.Credentials{AccountID: f.account, APIToken: f.token}); err != nil {
		t.Fatal(err)
	}
	if j, err = d.Withdraw(context.Background()); err != nil || j.State != mesh.StateWithdrawn || len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatalf("withdraw: %v", err)
	}
}

// A credential change racing a withdrawal waits for the deployment lock: the
// withdrawal finishes in the original account, then the change is applied.
func TestCredentialChangeRacingWithdrawal(t *testing.T) {
	f, srv := newFakeCF(t)
	d := newDeployer(t, f, srv, &fakeRemote{})
	if _, err := d.Deploy(context.Background(), meshPlan(t)); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	f.mu.Lock()
	f.blockDelete, f.enteredDelete = release, make(chan struct{})
	entered := f.enteredDelete
	f.mu.Unlock()
	type res struct {
		j   *mesh.Journal
		err error
	}
	wd := make(chan res, 1)
	go func() {
		j, err := d.Withdraw(context.Background())
		wd <- res{j, err}
	}()
	<-entered
	other := dummy("", 16)
	saved := make(chan error, 1)
	go func() {
		d2 := *d // a separate request (same store, same lock)
		saved <- d2.SaveCredentials(mesh.Credentials{AccountID: other, APIToken: dummy("tok", 16)})
	}()
	select {
	case err := <-saved:
		t.Fatalf("credential change did not wait for the withdrawal: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if c, _ := d.Creds.Load(); c.AccountID != f.account {
		t.Fatal("credentials changed during the withdrawal")
	}
	close(release)
	r := <-wd
	if r.err != nil || r.j.State != mesh.StateWithdrawn || len(f.routes) != 0 || len(f.nodes) != 0 {
		t.Fatalf("withdraw: %v", r.err)
	}
	if err := <-saved; err != nil {
		t.Fatalf("change after the withdrawal: %v", err)
	}
	if c, _ := d.Creds.Load(); c.AccountID != other {
		t.Fatal("change not applied")
	}
}
