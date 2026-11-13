package provision

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Withdraw tests run the real scripts in the provision sandbox. The
// withdraw script is not path-rewritten: its fixed M_ROOT is pointed at the
// sandbox, and manifests written by a sandboxed provision are turned back
// into host paths, exactly as they are on a host.

// withdrawStubs replaces systemctl, ip, nft and docker with stubs that keep
// state in the sandbox: units are active while $SANDBOX/active-<unit>
// exists, rules exist while rule-<fam>-<table> exists, blackhole routes
// while bh-<dst> exists (/ and : as _).
func withdrawStubs(t *testing.T, sb *sandbox) {
	t.Helper()
	write := func(name, body string) {
		script := "#!/bin/bash\necho \"" + name + " $*\" >> \"$SANDBOX/calls.log\"\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(sb.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("systemctl", `[ "$FAIL_SYSTEMCTL" = 1 ] && exit 1
last=""; for a in "$@"; do last=$a; done
case "$1" in
  is-active) [ -f "$SANDBOX/active-$last" ] && exit 0; exit 3 ;;
  is-enabled) [ -f "$SANDBOX/enabled-$last" ] && exit 0; exit 1 ;;
  enable) [ "$FAIL_ENABLE" = 1 ] && exit 1; [ "$2" = --now ] && touch "$SANDBOX/active-$last"; touch "$SANDBOX/enabled-$last" ;;
  start|restart) touch "$SANDBOX/active-$last" ;;
  stop) rm -f "$SANDBOX/active-$last" ;;
  disable) [ "$FAIL_DISABLE" = "$last" ] && exit 1; rm -f "$SANDBOX/enabled-$last"; [ "$2" = --now ] && rm -f "$SANDBOX/active-$last" ;;
esac
exit 0`)
	write("ip", `case "$*" in
  "link show "*) [ -f "$SANDBOX/link-$3" ] && exit 0; exit 1 ;;
  "-o link show") echo "1: lo: <UP>"; echo "2: eth0: <UP>"; for f in "$SANDBOX"/link-*; do [ -f "$f" ] && echo "9: ${f##*/link-}: <UP>"; done ;;
  "link del "*) [ "$FAIL_IPDEL" = 1 ] && exit 1; rm -f "$SANDBOX/link-$3" ;;
  -4\ rule\ del\ lookup\ *|-6\ rule\ del\ lookup\ *) f="$SANDBOX/rule${1#-}-$5"; [ -f "$f" ] || exit 2; rm -f "$f" ;;
  -4\ route\ del\ blackhole\ *|-6\ route\ del\ blackhole\ *) f="$SANDBOX/bh-$(printf '%s' "$5" | tr '/:' '__')"; [ -f "$f" ] || exit 2; rm -f "$f" ;;
esac
exit 0`)
}

func (sb *sandbox) runRaw(script string, env ...string) (string, int) {
	sb.t.Helper()
	script = strings.Replace(script, "M_ROOT=''", "M_ROOT='"+sb.root+"'", 1)
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append([]string{"PATH=" + sb.bin + ":/usr/bin:/bin:/usr/sbin:/sbin", "SANDBOX=" + sb.root, "LC_ALL=C"}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		sb.t.Fatal(err)
	}
	return string(out), code
}

func (sb *sandbox) touch(names ...string) {
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(sb.root, n), nil, 0o644); err != nil {
			sb.t.Fatal(err)
		}
	}
}

func (sb *sandbox) write(p, body string) {
	sb.t.Helper()
	full := filepath.Join(sb.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		sb.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		sb.t.Fatal(err)
	}
}

// hostPaths turns the sandboxed manifest back into host paths.
func (sb *sandbox) hostPaths(p string) {
	sb.t.Helper()
	sb.write(p, strings.ReplaceAll(sb.read(p), sb.root, ""))
}

func wopts(node, mode, action, digest string) WithdrawOptions {
	return WithdrawOptions{NodeID: node, Deployment: "dep-1", ServerID: "srv-1", Run: "wd-1", Mode: mode, Action: action, Digest: digest}
}

// provisioned installs node "tw" in a fresh sandbox with stateful stubs and
// returns it with the manifest in host paths.
func provisioned(t *testing.T) (*sandbox, map[string]string) {
	t.Helper()
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	script, files := testScript(t, "tw", "none")
	if out, code := sb.run(script); code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") {
		t.Fatalf("provision: %d\n%s", code, out)
	}
	sb.hostPaths("/var/lib/meridian/node/manifest")
	return sb, files
}

func plan(t *testing.T, sb *sandbox, o WithdrawOptions) WithdrawOutcome {
	t.Helper()
	out, code := sb.runRaw(WithdrawScript(o))
	w := ParseWithdrawOutput(out)
	if code != 0 || !w.PlanOK || w.Digest == "" {
		t.Fatalf("plan %d\n%s", code, out)
	}
	return w
}

func TestWithdrawOptionsAndSyntax(t *testing.T) {
	good := wopts("tw", WithdrawManifest, WithdrawRun, strings.Repeat("a", 64))
	if err := CheckWithdrawOptions(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []WithdrawOptions{
		wopts("tw'; id; '", WithdrawManifest, WithdrawPlan, ""),
		wopts("tw", "everything", WithdrawPlan, ""),
		wopts("tw", WithdrawManifest, "exec", ""),
		wopts("tw", WithdrawManifest, WithdrawRun, ""),
		wopts("tw", WithdrawManifest, WithdrawRun, "zz"),
		wopts("tw", WithdrawManifest, WithdrawPlan, strings.Repeat("a", 64)),
		{NodeID: "tw", Deployment: "", ServerID: "s", Run: "r", Mode: WithdrawManifest, Action: WithdrawPlan},
	} {
		if CheckWithdrawOptions(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
		s := WithdrawScript(bad)
		if !strings.Contains(s, "MERIDIAN_REFUSED bad_options") || strings.Contains(s, "; id;") || strings.Contains(s, "m_compensate") {
			t.Fatalf("bad options rendered: %+v\n%s", bad, s)
		}
	}
	for _, mode := range []string{WithdrawManifest, WithdrawJournal, WithdrawLegacy} {
		for _, act := range []string{WithdrawPlan, WithdrawRun} {
			d := ""
			if act == WithdrawRun {
				d = strings.Repeat("b", 64)
			}
			s := WithdrawScript(wopts("tw", mode, act, d))
			cmd := exec.Command("bash", "-n")
			cmd.Stdin = strings.NewReader(s)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("bash -n %s/%s: %v\n%s", mode, act, err, out)
			}
			if path, err := exec.LookPath("shellcheck"); err == nil {
				cmd := exec.Command(path, "-s", "bash", "-S", "error", "-")
				cmd.Stdin = strings.NewReader(s)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("shellcheck: %v\n%s", err, out)
				}
			}
			// Nothing of the request is a command: only the fixed assignments vary.
			if strings.Count(s, "M_ROOT=''") != 1 {
				t.Fatal("M_ROOT must be a fixed literal")
			}
		}
	}
}

// Manifest withdraw: plan, refused on a changed digest, then removes only
// what the manifest lists; foreign interfaces, tables and files stay; a
// second run says "already withdrawn".
func TestWithdrawManifestScopedAndIdempotent(t *testing.T) {
	sb, files := provisioned(t)
	// Foreign resources next to ours.
	sb.write("/etc/wireguard/wg0.conf", "[Interface]\n# someone else's\n")
	sb.write("/etc/nftables.d/other.nft", "table inet other {}\n")
	sb.touch("link-wg0", "nft-other", "nft-docker")
	// Rules and blackholes the routes script would have added.
	sb.touch("rule4-150", "rule6-150", "bh-10.66.0.0_16", "bh-fd66___48")
	if !sb.exists("/link-m14") || !sb.exists("/nft-meridian") {
		t.Fatal("setup: provision did not bring m14 / inet meridian up")
	}

	p := plan(t, sb, wopts("tw", WithdrawManifest, WithdrawPlan, ""))
	joined := strings.Join(p.Plan, "\n")
	for _, want := range []string{"iface m14 present", "nft inet meridian present", "file /etc/wireguard/m14.conf present", "table 150 flush", "route 10.66.0.0/16 blackhole"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("plan lacks %q:\n%s", want, joined)
		}
	}
	if p.Owner != "tw dep-1 srv-1" {
		t.Fatalf("owner %q", p.Owner)
	}
	if !sb.exists("/link-m14") {
		t.Fatal("plan changed the host")
	}

	// A digest the operator did not review is refused before anything changes.
	out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawRun, strings.Repeat("0", 64))))
	if code != 3 || ParseWithdrawOutput(out).Refused != "plan_changed" || !sb.exists("/link-m14") {
		t.Fatalf("stale digest: %d\n%s", code, out)
	}

	out, code = sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawRun, p.Digest)))
	w := ParseWithdrawOutput(out)
	if code != 0 || !w.OK || len(w.Leftovers) != 0 {
		t.Fatalf("run %d\n%s", code, out)
	}
	for p := range files {
		if sb.exists(p) {
			t.Fatalf("%s left behind", p)
		}
	}
	for _, gone := range []string{"/link-m14", "/nft-meridian", "/rule4-150", "/rule6-150", "/bh-10.66.0.0_16", "/bh-fd66___48", "/active-meridian-unlock.timer", "/var/lib/meridian/node/manifest", "/etc/meridian"} {
		if sb.exists(gone) {
			t.Fatalf("%s left", gone)
		}
	}
	for _, kept := range []string{"/link-wg0", "/nft-other", "/nft-docker", "/etc/wireguard/wg0.conf", "/etc/nftables.d/other.nft"} {
		if !sb.exists(kept) {
			t.Fatalf("foreign %s removed", kept)
		}
	}
	calls := sb.read("/calls.log")
	if strings.Contains(calls, "ip link del wg0") || strings.Contains(calls, "nft delete table inet other") || strings.Contains(calls, "apt-get remove") || strings.Contains(calls, "apt-get purge") {
		t.Fatalf("touched foreign resources or packages:\n%s", calls)
	}
	if !strings.Contains(strings.Join(w.Kept, "\n"), "sysctl") {
		t.Fatalf("kept not reported: %v", w.Kept)
	}
	if j := sb.read("/var/lib/meridian/node/journal"); !strings.Contains(j, "state withdrawn") || !strings.Contains(j, "kind withdraw") {
		t.Fatalf("journal %s", j)
	}

	// Idempotent: plan and run again answer "already withdrawn".
	for _, act := range []string{WithdrawPlan, WithdrawRun} {
		d := ""
		if act == WithdrawRun {
			d = p.Digest
		}
		out, code = sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, act, d)))
		if code != 0 || !ParseWithdrawOutput(out).Already {
			t.Fatalf("second %s: %d\n%s", act, code, out)
		}
	}
	// The next first install is accepted again.
	script, _ := testScript(t, "tw", "none")
	if out, code := sb.run(script); code != 0 {
		t.Fatalf("provision after withdraw: %d\n%s", code, out)
	}
}

// Identity: another node, deployment or server, or an entry the script does
// not accept, is refused with a reason and changes nothing.
func TestWithdrawRefusesOtherOwners(t *testing.T) {
	sb, _ := provisioned(t)
	for _, c := range []struct {
		o    WithdrawOptions
		code string
	}{
		{wopts("jp", WithdrawManifest, WithdrawPlan, ""), "manifest_other"},
		{WithdrawOptions{NodeID: "tw", Deployment: "dep-2", ServerID: "srv-1", Run: "r", Mode: WithdrawManifest, Action: WithdrawPlan}, "manifest_other"},
		{WithdrawOptions{NodeID: "tw", Deployment: "dep-1", ServerID: "srv-2", Run: "r", Mode: WithdrawManifest, Action: WithdrawPlan}, "manifest_other_server"},
		{wopts("tw", WithdrawLegacy, WithdrawPlan, ""), "manifest_present"},
		{wopts("tw", WithdrawJournal, WithdrawPlan, ""), "journal_clean"},
	} {
		out, code := sb.runRaw(WithdrawScript(c.o))
		if code != 3 || ParseWithdrawOutput(out).Refused != c.code {
			t.Fatalf("%+v: %d\n%s", c.o, code, out)
		}
	}
	man := sb.read("/var/lib/meridian/node/manifest")
	sb.write("/var/lib/meridian/node/manifest", man+"iface eth0\n")
	out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawPlan, "")))
	if code != 3 || ParseWithdrawOutput(out).Refused != "bad_manifest_entry" {
		t.Fatalf("eth0 in manifest: %d\n%s", code, out)
	}
	sb.write("/var/lib/meridian/node/manifest", man+"file /etc/cron.d/x "+strings.Repeat("a", 64)+"\n")
	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "bad_manifest_entry" {
		t.Fatalf("cron path in manifest: %d\n%s", code, out)
	}
	if !sb.exists("/link-m14") || !sb.exists("/etc/wireguard/m14.conf") {
		t.Fatal("a refused withdraw changed the host")
	}
	// No manifest and no Meridian files: refused, not "done".
	sb2 := newSandbox(t)
	if out, code := sb2.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "manifest_missing" {
		t.Fatalf("empty host: %d\n%s", code, out)
	}
}

// A file changed since the install is kept and reported; the run is
// partial, the manifest stays, a provision is refused until the withdraw is
// finished, and the re-run completes once the file is dealt with.
func TestWithdrawPartialThenRerun(t *testing.T) {
	sb, _ := provisioned(t)
	p := plan(t, sb, wopts("tw", WithdrawManifest, WithdrawPlan, ""))
	sb.write("/etc/sysctl.d/99-meridian.conf", sb.read("/etc/sysctl.d/99-meridian.conf")+"# operator edit\n")
	out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawRun, p.Digest)), "FAIL_IPDEL=1")
	w := ParseWithdrawOutput(out)
	if code != 4 || !w.Partial || w.OK {
		t.Fatalf("partial: %d\n%s", code, out)
	}
	left := strings.Join(w.Leftovers, "\n")
	if !strings.Contains(left, "/etc/sysctl.d/99-meridian.conf (changed since the install") || !strings.Contains(left, "iface m14") {
		t.Fatalf("leftovers %v", w.Leftovers)
	}
	if !sb.exists("/var/lib/meridian/node/manifest") || !sb.exists("/etc/sysctl.d/99-meridian.conf") {
		t.Fatal("partial run removed the manifest or the changed file")
	}
	if j := sb.read("/var/lib/meridian/node/journal"); !strings.Contains(j, "state withdraw_incomplete") {
		t.Fatalf("journal %s", j)
	}
	// Provisioning is refused while the withdraw is unfinished.
	upd, _ := testScript(t, "tw", "same")
	if out, code := sb.run(upd); code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED withdraw_incomplete") {
		t.Fatalf("provision during partial withdraw: %d\n%s", code, out)
	}
	// The operator moves the edited file away; the same plan still applies
	// (the manifest did not change) and the re-run finishes.
	os.Remove(filepath.Join(sb.root, "etc/sysctl.d/99-meridian.conf"))
	again := plan(t, sb, wopts("tw", WithdrawManifest, WithdrawPlan, ""))
	if again.Digest != p.Digest {
		t.Fatal("the manifest digest changed after a partial run")
	}
	out, code = sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawRun, p.Digest)))
	if code != 0 || !ParseWithdrawOutput(out).OK || sb.exists("/link-m14") {
		t.Fatalf("re-run: %d\n%s", code, out)
	}
}

// An interrupted provision (journal "incomplete" or "running") is finished
// from the panel with the same compensation; afterwards provisioning runs.
func TestWithdrawJournalRecoversInterruptedRun(t *testing.T) {
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	script, files := testScript(t, "tw", "none")
	// The interface comes up, cannot be deleted during the first compensation.
	out, code := sb.run(script, "FAIL_IPDEL=1", "FAIL_ENABLE=1")
	if code == 0 || !strings.Contains(out, "MERIDIAN_COMPENSATION_INCOMPLETE") {
		t.Fatalf("setup: %d\n%s", code, out)
	}
	// Simulate a hard kill as well: the journal still says "running".
	sb.write("/var/lib/meridian/node/journal", strings.Replace(sb.read("/var/lib/meridian/node/journal"), "state incomplete", "state running", 1))
	if out, code := sb.run(script); code != 3 || !strings.Contains(out, "previous_run_incomplete") {
		t.Fatalf("provision before recovery: %d\n%s", code, out)
	}
	// Manifest mode points at the journal mode.
	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "journal_incomplete" {
		t.Fatalf("manifest mode on an interrupted run: %d\n%s", code, out)
	}
	if out, code := sb.runRaw(WithdrawScript(wopts("jp", WithdrawJournal, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "journal_other" {
		t.Fatalf("other node: %d\n%s", code, out)
	}
	p := plan(t, sb, wopts("tw", WithdrawJournal, WithdrawPlan, ""))
	if !strings.Contains(strings.Join(p.Plan, "\n"), "remove file") {
		t.Fatalf("journal plan %v", p.Plan)
	}
	out, _ = sb.runRaw(WithdrawScript(wopts("tw", WithdrawJournal, WithdrawRun, p.Digest)))
	w := ParseWithdrawOutput(out)
	if !w.Compensated || w.Incomplete {
		t.Fatalf("recovery:\n%s", out)
	}
	for p := range files {
		if sb.exists(p) && p != "/etc/sysctl.d/99-meridian.conf" {
			t.Fatalf("%s left", p)
		}
	}
	if sb.exists("/link-m14") || sb.exists("/var/lib/meridian/node/run-run-1") {
		t.Fatal("interface or work directory left")
	}
	if j := sb.read("/var/lib/meridian/node/journal"); !strings.Contains(j, "state compensated") || !strings.Contains(j, "recovery wd-1") {
		t.Fatalf("journal %s", j)
	}
	if out, code := sb.run(script); code != 0 {
		t.Fatalf("provision after recovery: %d\n%s", code, out)
	}
}

// A run killed before m_begin finished (no params) changed nothing: the
// recovery only closes the journal.
func TestWithdrawJournalNothingChanged(t *testing.T) {
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	sb.write("/var/lib/meridian/node/journal", "meridian-node-journal 1\nstate running\nnode tw\ndeployment dep-1\nrun run-9\n")
	sb.write("/var/lib/meridian/node/run-run-9/actions", "")
	p := plan(t, sb, wopts("tw", WithdrawJournal, WithdrawPlan, ""))
	out, _ := sb.runRaw(WithdrawScript(wopts("tw", WithdrawJournal, WithdrawRun, p.Digest)))
	if !ParseWithdrawOutput(out).Compensated || sb.exists("/var/lib/meridian/node/run-run-9") {
		t.Fatalf("%s", out)
	}
	// Actions without params: refused, never guessed.
	sb.write("/var/lib/meridian/node/journal", "meridian-node-journal 1\nstate running\nnode tw\ndeployment dep-1\nrun run-8\n")
	sb.write("/var/lib/meridian/node/run-run-8/actions", "file-new /etc/meridian/x\n")
	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawJournal, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "journal_unrecoverable" {
		t.Fatalf("%d %s", code, out)
	}
	// No work directory at all: refused.
	sb.write("/var/lib/meridian/node/journal", "meridian-node-journal 1\nstate running\nnode tw\ndeployment dep-1\nrun run-7\n")
	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawJournal, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "journal_unrecoverable" {
		t.Fatalf("%d %s", code, out)
	}
}

// Legacy cleanup: only Meridian-marked files at the well-known paths and
// what they declare; an unmarked WireGuard config with an "m" name stays.
func TestWithdrawLegacyCleanup(t *testing.T) {
	sb := newSandbox(t)
	withdrawStubs(t, sb)
	sb.write("/etc/wireguard/m14.conf", "# meridian link x\n[Interface]\n")
	sb.write("/etc/wireguard/m15.conf", "[Interface]\n# not ours\n")
	sb.write("/etc/systemd/system/meridian-unlock.timer", "# Meridian unlock\n[Timer]\n")
	sb.write("/etc/systemd/system/ssh.service", "# meridian mention in a foreign unit\n")
	sb.write("/etc/nftables.d/meridian.nft", "#!/usr/sbin/nft -f\n# Meridian\ntable inet meridian {\n}\n")
	sb.write("/etc/iproute2/rt_tables.d/meridian.conf", "100\tmeridian_domestic\n150\tmeridian_east\n")
	sb.write("/usr/local/sbin/meridian-up.sh", "#!/bin/bash\n# Meridian up\n")
	sb.touch("link-m14", "link-m15", "nft-meridian", "active-meridian-unlock.timer", "rule4-150")

	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawPlan, ""))); code != 3 || ParseWithdrawOutput(out).Refused != "legacy_install" {
		t.Fatalf("manifest mode on legacy: %d\n%s", code, out)
	}
	p := plan(t, sb, wopts("tw", WithdrawLegacy, WithdrawPlan, ""))
	joined := strings.Join(p.Plan, "\n")
	if strings.Contains(joined, "m15") || strings.Contains(joined, "ssh.service") {
		t.Fatalf("legacy plan reaches beyond marked well-known paths:\n%s", joined)
	}
	for _, want := range []string{"iface m14", "unit meridian-unlock.timer", "nft inet meridian", "table 150", "file /usr/local/sbin/meridian-up.sh"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("legacy plan lacks %q:\n%s", want, joined)
		}
	}
	// The host changes after the review: refused.
	sb.write("/etc/meridian/extra.conf", "x\n")
	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawLegacy, WithdrawRun, p.Digest))); code != 3 || ParseWithdrawOutput(out).Refused != "plan_changed" {
		t.Fatalf("changed legacy host: %d\n%s", code, out)
	}
	p = plan(t, sb, wopts("tw", WithdrawLegacy, WithdrawPlan, ""))
	out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawLegacy, WithdrawRun, p.Digest)))
	w := ParseWithdrawOutput(out)
	if code != 0 || !w.OK {
		t.Fatalf("legacy run %d\n%s", code, out)
	}
	for _, gone := range []string{"/etc/wireguard/m14.conf", "/link-m14", "/nft-meridian", "/etc/systemd/system/meridian-unlock.timer", "/usr/local/sbin/meridian-up.sh", "/rule4-150", "/etc/meridian/extra.conf"} {
		if sb.exists(gone) {
			t.Fatalf("%s left", gone)
		}
	}
	for _, kept := range []string{"/etc/wireguard/m15.conf", "/link-m15", "/etc/systemd/system/ssh.service"} {
		if !sb.exists(kept) {
			t.Fatalf("%s removed", kept)
		}
	}
	if !strings.Contains(strings.Join(w.Kept, "\n"), "blackhole") {
		t.Fatalf("legacy must report the unknown blackhole routes: %v", w.Kept)
	}
	if out, code := sb.runRaw(WithdrawScript(wopts("tw", WithdrawLegacy, WithdrawPlan, ""))); code != 0 || !ParseWithdrawOutput(out).Already {
		t.Fatalf("second legacy plan: %d\n%s", code, out)
	}
}
