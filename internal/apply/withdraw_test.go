package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
)

func cmdIndex(cmds []string, prefix string) int {
	for i, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// A gateway withdraw removes exactly what the installed manifest lists,
// turns forwarding off before removing anything, keeps the LAN guard (file
// and table) loaded, leaves foreign resources alone, and is idempotent.
func TestGatewayWithdrawKeepsGuardAndForeign(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(r.host, "etc", "wireguard", "wg0.conf")
	if err := os.WriteFile(foreign, []byte("someone else's\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.sim.links["wg0"] = true
	r.sim.nft["inet docker_other"] = true
	r.sim.cmds = nil

	res, err := r.applier().Withdraw()
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "withdrawn" || res.Host == nil || !res.Host.Committed {
		t.Fatalf("%+v", res)
	}
	if strings.Join(res.Removed.Interfaces, ",") != "m02,m02w,m03" || strings.Join(res.Removed.NFTTables, ",") != "inet meridian" {
		t.Fatalf("removed %+v", res.Removed)
	}
	for _, f := range res.Removed.Files {
		if f == "/"+hostexec.GuardBootFile {
			t.Fatal("the guard file is listed as removed")
		}
	}
	// Host: Meridian runtime gone, guard and foreign resources kept.
	if strings.Join(r.sim.liveLinks(), ",") != "wg0" {
		t.Fatalf("live links %v", r.sim.liveLinks())
	}
	if r.sim.nft["inet meridian"] || !r.sim.nft["inet meridian_guard"] || !r.sim.nft["inet docker_other"] {
		t.Fatalf("nft %v", r.sim.nft)
	}
	if !exists(filepath.Join(r.host, "etc", "nftables.d", "meridian-guard.nft")) {
		t.Fatal("guard boot file removed")
	}
	for _, rel := range []string{"etc/nftables.d/meridian.nft", "usr/local/sbin/meridian-up.sh", "etc/wireguard/m02.conf", "etc/sysctl.d/99-meridian.conf"} {
		if exists(filepath.Join(r.host, filepath.FromSlash(rel))) {
			t.Fatalf("%s left", rel)
		}
	}
	if !exists(foreign) {
		t.Fatal("foreign WireGuard config removed")
	}
	fwd := cmdIndex(r.sim.cmds, "sysctl -w net.ipv4.ip_forward=0")
	stop := cmdIndex(r.sim.cmds, "systemctl stop meridian.service")
	del := cmdIndex(r.sim.cmds, "ip link del dev m02")
	if fwd < 0 || cmdIndex(r.sim.cmds, "sysctl -w net.ipv6.conf.all.forwarding=0") < 0 || stop < fwd || del < stop {
		t.Fatalf("forwarding off / stop must precede removal:\n%s", strings.Join(r.sim.cmds, "\n"))
	}
	if cmdIndex(r.sim.cmds, "nft delete table inet meridian_guard") >= 0 || cmdIndex(r.sim.cmds, "sysctl -w net.ipv4.ip_forward=1") >= 0 {
		t.Fatal("withdraw touched the guard or turned forwarding on")
	}
	inst, _ := r.applier().Installed()
	if !inst.Withdrawn() || len(inst.Files) != 1 || inst.Files[0].Path != hostexec.GuardBootFile || strings.Join(inst.NFTTables, ",") != hostexec.GuardTable {
		t.Fatalf("installed %+v", inst)
	}
	if p, _ := r.applier().Pending(); p != nil {
		t.Fatalf("journal left: %+v", p)
	}
	assertNoSecret(t, r.data, r.key)

	// Idempotent: a second withdraw only re-checks.
	before := len(r.rt.reqs)
	again, err := r.applier().Withdraw()
	if err != nil || again.State != "already_withdrawn" {
		t.Fatalf("%+v %v", again, err)
	}
	for _, q := range r.rt.reqs[before:] {
		if q.Action == hostexec.ActionWithdraw && !q.Resources.Empty() {
			t.Fatalf("re-run removed something: %+v", q)
		}
	}
	// No runtime rollback from the withdrawn state.
	if _, err := r.applier().RollbackReport(); !errors.Is(err, ErrWithdrawnState) {
		t.Fatalf("rollback after withdraw: %v", err)
	}
	// A reinstall converges from the guard-only manifest.
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	if inst, _ := r.applier().Installed(); inst.Withdrawn() || strings.Join(r.sim.liveLinks(), ",") != "m02,m02w,m03,wg0" {
		t.Fatalf("reinstall: %+v %v", inst.Origin, r.sim.liveLinks())
	}
}

// Releasing the guard is a separate step, only after a withdraw; the agent
// turns forwarding off before the table goes.
func TestGatewayWithdrawGuardRelease(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applier().WithdrawGuard(); !errors.Is(err, ErrNotWithdrawn) {
		t.Fatalf("guard release before withdraw: %v", err)
	}
	if _, err := r.applier().Withdraw(); err != nil {
		t.Fatal(err)
	}
	r.sim.cmds = nil
	res, err := r.applier().WithdrawGuard()
	if err != nil || res.State != "guard_released" {
		t.Fatalf("%+v %v", res, err)
	}
	if r.sim.nft["inet meridian_guard"] || exists(filepath.Join(r.host, "etc", "nftables.d", "meridian-guard.nft")) {
		t.Fatal("guard left")
	}
	fwd, del := cmdIndex(r.sim.cmds, "sysctl -w net.ipv4.ip_forward=0"), cmdIndex(r.sim.cmds, "nft delete table inet meridian_guard")
	if fwd < 0 || del < fwd {
		t.Fatalf("forwarding must go off before the guard:\n%s", strings.Join(r.sim.cmds, "\n"))
	}
	if inst, _ := r.applier().Installed(); !inst.Empty() {
		t.Fatalf("installed %+v", inst)
	}
	if res, err := r.applier().WithdrawGuard(); err != nil || res.State != "not_installed" {
		t.Fatalf("second release: %+v %v", res, err)
	}
	if _, err := r.applier().Withdraw(); !errors.Is(err, ErrNothingInstalled) {
		t.Fatalf("withdraw with nothing installed: %v", err)
	}
}

// A failure part-way compensates back to the running install.
func TestGatewayWithdrawFailureCompensates(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	up := readHost(t, r.host, "usr/local/sbin/meridian-up.sh")
	r.sim.failOnce["ip link del dev m02w"] = true
	_, err := r.applier().Withdraw()
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("got %v", err)
	}
	if readHost(t, r.host, "usr/local/sbin/meridian-up.sh") != up || strings.Join(r.sim.liveLinks(), ",") != "m02,m02w,m03" || !r.sim.nft["inet meridian"] {
		t.Fatalf("not restored: %v %v", r.sim.liveLinks(), r.sim.nft)
	}
	inst, _ := r.applier().Installed()
	if inst.Withdrawn() || inst.Version != 1 {
		t.Fatalf("installed %+v", inst)
	}
	if p, _ := r.applier().Pending(); p != nil {
		t.Fatal("journal left after compensation")
	}
}

// A failed compensation is not success: the journal stays (kind withdraw),
// new work is refused until Recover.
func TestGatewayWithdrawCompensationFailurePending(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	r.rt.fail["fwd-guard"] = errors.New("agent lost")
	r.rt.fail["comp-activate"] = errors.New("agent lost again")
	_, err := r.applier().Withdraw()
	var te *TxnError
	if !errors.As(err, &te) || te.Compensated || te.CompErr == nil {
		t.Fatalf("got %v", err)
	}
	p, _ := r.applier().Pending()
	if p == nil || p.Kind != "withdraw" || p.Phase != phaseCompensate {
		t.Fatalf("pending %+v", p)
	}
	if _, err := r.applier().Withdraw(); !errors.Is(err, ErrPending) {
		t.Fatalf("withdraw while pending: %v", err)
	}
	r.restart()
	rep, err := r.applier().Recover()
	if err != nil || rep == nil {
		t.Fatalf("recover: %v", err)
	}
	if inst, _ := r.applier().Installed(); inst.Withdrawn() || strings.Join(r.sim.liveLinks(), ",") != "m02,m02w,m03" {
		t.Fatalf("after recover %+v %v", inst.Origin, r.sim.liveLinks())
	}
}

// Refusals change nothing.
func TestGatewayWithdrawRefusals(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier().Withdraw(); !errors.Is(err, ErrNothingInstalled) {
		t.Fatalf("nothing installed: %v", err)
	}
	// Pre-manifest data plane: refused, install (adoption) first.
	if err := os.MkdirAll(filepath.Join(r.host, "usr", "local", "sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.host, "usr", "local", "sbin", "meridian-up.sh"), []byte("#!/bin/bash\n# meridian\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.applier().Withdraw(); !errors.Is(err, ErrWithdrawLegacy) {
		t.Fatalf("legacy: %v", err)
	}
	if len(r.rt.reqs) > 2 {
		t.Fatalf("legacy refusal acted on the host: %+v", r.rt.reqs)
	}

	// Without the gateway key a failure could not be compensated: refused.
	r2 := newRig(t)
	if _, err := r2.applier().Apply(compileTopo(t, defaults.Example()), false); err != nil {
		t.Fatal(err)
	}
	ap := r2.applier()
	ap.PrivateKey = ""
	n := len(r2.rt.reqs)
	if _, err := ap.Withdraw(); err == nil || !strings.Contains(err.Error(), "无法恢复") {
		t.Fatalf("no key: %v", err)
	}
	for _, q := range r2.rt.reqs[n:] {
		if q.Action != hostexec.ActionHealth {
			t.Fatalf("refused withdraw acted: %+v", q)
		}
	}
	if inst, _ := r2.applier().Installed(); inst.Withdrawn() {
		t.Fatal("refused withdraw changed the manifest")
	}
}
