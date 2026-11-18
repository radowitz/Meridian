package compile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fault injection for the protected relay-sharing switch. Every bash run is a
// fresh process (a controller restart): only the files under the switch
// directory, the upstream record and the success marker carry state.

type txnCase struct {
	name       string
	lab        func(t *testing.T) *shellLab
	decA, decB string // decA succeeds first; decB is the injected switch
	argsA      string // share_apply arguments of decA (the success marker)
	pathA      string
	routeCalls int // ip calls of one share_apply_raw of decB
}

func txnCases() []txnCase {
	return []txnCase{
		{
			name:  "ungrouped",
			lab:   newShellLab,
			decA:  "meridian-pathq 1\nupstream main\ndesignated access\nrelay access m02 500 0\nrelay access2 m03 500 0\nbackup 0\nend\n",
			decB:  "meridian-pathq 1\nupstream backup\ndesignated backup\nrelay access m02 0 1\nrelay access2 m03 0 1\nbackup 0\nend\n",
			argsA: "main access m02 500 0 m03 500 0 0", pathA: "main", routeCalls: 20,
		},
		{
			name:  "grouped",
			lab:   func(t *testing.T) *shellLab { return newShellLabFor(t, noIXCompile(t, relayBackupTopo(nil))) },
			decA:  "meridian-pathq 1\nupstream main\ndesignated access\nrelay access m05 1000 0\nrelay bk1 m06 0 0\nrelay bk2 m07 0 0\nbackup 0\nend\n",
			decB:  "meridian-pathq 1\nupstream backup\ndesignated bk1\nrelay access m05 0 0\nrelay bk1 m06 500 0\nrelay bk2 m07 500 0\nbackup 0\nend\n",
			argsA: "main access m05 1000 0 m06 0 0 m07 0 0 0", pathA: "main", routeCalls: 20,
		},
	}
}

// faultPrelude overrides ip/nft inside the driven shell. ctrl/ip-arm K fails
// the K-th armed ip call (ctrl/ip-all: and every later one, so compensation
// fails too); ctrl/nft-once refuses the next relay assignment batch once;
// ctrl/nft-assign-fail refuses every assignment batch.
func faultPrelude(l *shellLab) string {
	c := l.ctrl
	return fmt.Sprintf(`ip() {
  echo "ip $*" >> %[1]s/ip.log
  [ -f %[1]s/ip-arm ] || [ -f %[1]s/ip-kill ] || return 0
  local n k=0
  n=$(( $(cat %[1]s/ip-n 2>/dev/null || echo 0) + 1 )); echo "$n" > %[1]s/ip-n
  [ ! -f %[1]s/ip-arm ] || k=$(cat %[1]s/ip-arm)
  if [ -f %[1]s/ip-kill ] && [ "$n" -eq "$(cat %[1]s/ip-kill)" ]; then kill -9 $$; fi
  if [ -f %[1]s/ip-all ]; then [ "$n" -lt "$k" ]; else [ "$n" -ne "$k" ]; fi
}
rm() {
  if [ -f %[1]s/kill-unpend ] && [ "$*" != "${*%%/switch/pending*}" ]; then kill -9 $$; fi
  command rm "$@"
}
mv() {
  if [ -f %[1]s/kill-marker ] && [ "${*: -1}" = "$SH_APPLIED" ]; then kill -9 $$; fi
  command mv "$@"
}
nft() {
  if [ "$1" = -f ] && [ "$2" = - ]; then
    local b; b=$(cat); { echo '--- batch'; printf '%%s\n' "$b"; } >> %[1]s/nft.log
    case "$b" in *relay_assign*)
      if [ -f %[1]s/nft-once ]; then rm -f %[1]s/nft-once; echo REFUSED >> %[1]s/nft.log; return 1; fi
      if [ -f %[1]s/nft-assign-fail ]; then echo REFUSED >> %[1]s/nft.log; return 1; fi ;;
    esac
    return 0
  fi
  echo "nft $*" >> %[1]s/nft.log
}
`, c)
}

type txnRun struct {
	t *testing.T
	l *shellLab
	c txnCase
}

func newTxnRun(t *testing.T, c txnCase) *txnRun {
	r := &txnRun{t: t, l: c.lab(t), c: c}
	r.l.write("decision", c.decA)
	if rc := r.step(); rc != 0 {
		t.Fatalf("first apply rc %d\n%s", rc, r.status())
	}
	if r.applied() != c.argsA || r.file("pathq/switch/current") == "" {
		t.Fatalf("no success snapshot: applied %q", r.applied())
	}
	return r
}

// step runs one share_step in a fresh process and returns its status.
func (r *txnRun) step() int {
	r.t.Helper()
	out, err := r.l.bash(faultPrelude(r.l) + "share_step\necho \"rc=$?\"\n")
	if err != nil {
		r.t.Fatalf("%v\n%s", err, out)
	}
	i := strings.LastIndex(out, "rc=")
	var rc int
	fmt.Sscanf(out[i:], "rc=%d", &rc)
	return rc
}

func (r *txnRun) file(rel string) string {
	b, _ := os.ReadFile(filepath.Join(r.l.run, rel))
	return strings.TrimSpace(string(b))
}
func (r *txnRun) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(r.l.run, rel))
	return err == nil
}
func (r *txnRun) applied() string { return r.file("pathq/applied") }
func (r *txnRun) status() string  { return r.file("upstream") }
func (r *txnRun) field(k string) string {
	for _, line := range strings.Split(r.status(), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == k {
			return f[1]
		}
	}
	return ""
}

// fenced: the last action on the independent guard table installed it.
func (r *txnRun) fenced() bool {
	log := r.l.read("nft.log")
	on := strings.LastIndex(log, "table inet meridian_switch {")
	off := strings.LastIndex(log, "nft delete table inet meridian_switch")
	return on > off
}

func (r *txnRun) assignBatches() int {
	return strings.Count(r.l.read("nft.log"), "flush chain inet meridian relay_assign")
}

func (r *txnRun) arm(k int, all bool) {
	os.Remove(filepath.Join(r.l.ctrl, "ip-n"))
	r.l.write("ip-arm", fmt.Sprint(k))
	if all {
		r.l.write("ip-all", "")
	}
}
func (r *txnRun) disarm() {
	for _, f := range []string{"ip-arm", "ip-all", "ip-n", "ip-kill", "kill-unpend", "kill-marker", "nft-assign-fail", "nft-once"} {
		os.Remove(filepath.Join(r.l.ctrl, f))
	}
}

// heldOnA: the compensated outcome. The previous successful path is back and
// unfenced, the target was never published, switching is held.
func (r *txnRun) heldOnA(before map[string]string) {
	r.t.Helper()
	for _, k := range []string{"path", "designated", "since", "switched"} {
		if r.field(k) != before[k] {
			r.t.Fatalf("%s published %q, last success %q\n%s", k, r.field(k), before[k], r.status())
		}
	}
	if r.field("state") != "degraded" || r.field("alert") != "apply_failed" {
		r.t.Fatalf("failure not visible\n%s", r.status())
	}
	if r.applied() != r.c.argsA || r.exists("pathq/switch/blocked") || r.exists("pathq/switch/pending") || !r.exists("pathq/switch/failed") {
		r.t.Fatalf("marker %q blocked %v pending %v failed %v", r.applied(), r.exists("pathq/switch/blocked"), r.exists("pathq/switch/pending"), r.exists("pathq/switch/failed"))
	}
	if r.fenced() {
		r.t.Fatal("fence left after a complete compensation")
	}
}

// blockedDown: no trusted way back. Fence on, no success marker, the old
// record kept only as history with state down.
func (r *txnRun) blockedDown(before map[string]string) {
	r.t.Helper()
	if !r.fenced() || !r.exists("pathq/switch/blocked") || r.exists("pathq/applied") {
		r.t.Fatalf("fenced %v blocked %v marker %q", r.fenced(), r.exists("pathq/switch/blocked"), r.applied())
	}
	if r.field("state") != "down" || r.field("alert") != "recovery_blocked" || r.field("path") != before["path"] || r.field("switched") != before["switched"] {
		r.t.Fatalf("blocked record\n%s", r.status())
	}
}

func (r *txnRun) snapshot() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"path", "designated", "since", "switched"} {
		m[k] = r.field(k)
	}
	return m
}

func TestShareTxnRouteFailureCompensates(t *testing.T) {
	for _, c := range txnCases() {
		for k := 1; k <= c.routeCalls; k++ {
			c, k := c, k
			t.Run(fmt.Sprintf("%s/ip%d", c.name, k), func(t *testing.T) {
				t.Parallel()
				r := newTxnRun(t, c)
				before := r.snapshot()
				r.l.write("now", "1700000100\n")
				r.l.write("decision", c.decB)
				r.arm(k, false)
				if rc := r.step(); rc != 3 {
					t.Fatalf("route failure %d: rc %d\n%s", k, rc, r.status())
				}
				r.heldOnA(before)
				// The compensation replayed the success snapshot: its last
				// table-102 route is decA's designated leg again.
				ip := r.l.read("ip.log")
				last := ip[strings.LastIndex(ip, "route replace default dev "):]
				desLeg := strings.Fields(c.argsA)[2]
				if !strings.HasPrefix(last, "route replace default dev "+desLeg+" table 102") && !strings.Contains(ip[strings.LastIndex(ip, "REFUSED")+1:], "default dev "+desLeg+" table 102") {
					t.Fatalf("snapshot not replayed (want %s):\n%s", desLeg, last)
				}
				// Hold: no mutation within the backoff, even across restart.
				r.disarm()
				n := r.assignBatches()
				if rc := r.step(); rc != 5 || r.assignBatches() != n {
					t.Fatalf("held pass rc %d, batches %d→%d", rc, n, r.assignBatches())
				}
				// After the backoff one retry; it succeeds and clears the hold.
				r.l.write("now", "1700000200\n")
				if rc := r.step(); rc != 0 || r.field("path") != "backup" || r.exists("pathq/switch/failed") || r.field("state") == "degraded" {
					t.Fatalf("retry rc %d\n%s", rc, r.status())
				}
				if r.field("switched") != "1700000200" {
					t.Fatalf("switch time is not the applied time\n%s", r.status())
				}
			})
		}
	}
}

func TestShareTxnCompensationFailureBlocks(t *testing.T) {
	for _, c := range txnCases() {
		for _, k := range []int{1, 3, 10, c.routeCalls} {
			c, k := c, k
			t.Run(fmt.Sprintf("%s/ip%d", c.name, k), func(t *testing.T) {
				t.Parallel()
				r := newTxnRun(t, c)
				before := r.snapshot()
				r.l.write("decision", c.decB)
				r.arm(k, true)
				if rc := r.step(); rc != 3 {
					t.Fatalf("rc %d", rc)
				}
				r.blockedDown(before)
				// Restart and healthy kernel: still blocked, no new attempt.
				r.disarm()
				n := r.assignBatches()
				r.l.write("now", "1700009999\n")
				if rc := r.step(); rc != 4 || r.assignBatches() != n {
					t.Fatalf("blocked pass rc %d batches %d→%d", rc, n, r.assignBatches())
				}
				r.blockedDown(before)
				// Only an explicit complete install clears it.
				out, err := r.l.bash("share_lock; SH_LOCKED=1; share_candidate; ( UP_STATE=\"$SH_CANDIDATE/status\"; share_record static shell main " +
					strings.Fields(c.argsA)[1] + " \"$(date +%s)\" 0 - ); SH_INSTALL=1 share_apply " + c.argsA + "\n")
				if err != nil {
					t.Fatalf("install: %v\n%s", err, out)
				}
				if r.exists("pathq/switch/blocked") || r.fenced() || r.applied() != c.argsA {
					t.Fatal("install did not clear the block")
				}
			})
		}
	}
}

func TestShareTxnNftRefusal(t *testing.T) {
	for _, c := range txnCases() {
		t.Run(c.name, func(t *testing.T) {
			r := newTxnRun(t, c)
			before := r.snapshot()
			ipBefore := r.l.read("ip.log")
			r.l.write("decision", c.decB)
			r.l.write("nft-once", "")
			if rc := r.step(); rc != 2 {
				t.Fatalf("rc %d", rc)
			}
			// No route of the refused target was touched before compensation.
			newIP := r.l.read("ip.log")[len(ipBefore):]
			if strings.Contains(newIP, "default dev m06 table 102") && c.name == "grouped" {
				t.Fatal("route toward the refused target")
			}
			r.heldOnA(before)
			// Compensation refused too: blocked and fenced.
			r2 := newTxnRun(t, c)
			b2 := r2.snapshot()
			r2.l.write("decision", c.decB)
			r2.l.write("nft-assign-fail", "")
			if rc := r2.step(); rc != 2 {
				t.Fatalf("rc %d", rc)
			}
			r2.blockedDown(b2)
		})
	}
}

func TestShareTxnRetryBudget(t *testing.T) {
	c := txnCases()[0]
	r := newTxnRun(t, c)
	before := r.snapshot()
	r.l.write("decision", c.decB)
	now := 1700000100
	for i := 0; i < 3; i++ {
		r.arm(1, false)
		r.l.write("now", fmt.Sprintln(now))
		if rc := r.step(); rc != 3 {
			t.Fatalf("attempt %d rc %d", i, rc)
		}
		r.heldOnA(before)
		now += 1000
	}
	r.disarm()
	n := r.assignBatches()
	r.l.write("now", fmt.Sprintln(now+100000))
	if rc := r.step(); rc != 5 || r.assignBatches() != n {
		t.Fatalf("spent budget still retried: rc %d", rc)
	}
}

func TestShareTxnFirstApplyFailureAndCrash(t *testing.T) {
	for _, c := range txnCases() {
		t.Run(c.name, func(t *testing.T) {
			// No success snapshot yet: nothing to compensate to.
			l := c.lab(t)
			r := &txnRun{t: t, l: l, c: c}
			l.write("decision", c.decA)
			r.arm(2, false)
			if rc := r.step(); rc != 3 {
				t.Fatalf("rc %d", rc)
			}
			if !r.fenced() || !r.exists("pathq/switch/blocked") || r.exists("pathq/applied") || r.exists("upstream") && r.field("state") != "down" {
				t.Fatalf("first failure not blocked\n%s", r.status())
			}
			// A pass killed mid-transaction leaves pending: fenced and blocked.
			r2 := newTxnRun(t, c)
			b2 := r2.snapshot()
			if err := os.WriteFile(filepath.Join(r2.l.run, "pathq/switch/pending"), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			n := r2.assignBatches()
			if rc := r2.step(); rc != 4 || r2.assignBatches() != n {
				t.Fatalf("crash recovery rc %d", rc)
			}
			r2.blockedDown(b2)
		})
	}
}

func TestShareTxnStatusPublishFailure(t *testing.T) {
	c := txnCases()[0]
	r := newTxnRun(t, c)
	r.l.write("decision", c.decB)
	// The record cannot be replaced: the applied target must not count.
	if err := os.Mkdir(filepath.Join(r.l.run, "upstream.next"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.l.run, "upstream.next", "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := r.step(); rc != 4 {
		t.Fatalf("rc %d", rc)
	}
	if r.field("path") != c.pathA || !r.fenced() || !r.exists("pathq/switch/blocked") || r.exists("pathq/applied") {
		t.Fatalf("publish failure\n%s", r.status())
	}
}

// The grouped fallback (controller gone) publishes fb_up/fb_switched only
// after its switch applied. The main group's only relay is down while both
// backup-group relays are in: the third pass (FAILS_NEED) evicts it and is a
// real main→backup group switch, and that switch fails. The failed pass changes no
// fallback state at all, eviction/recovery counters included.
func TestShareTxnFallbackFailureKeepsCarrying(t *testing.T) {
	c := txnCases()[1]
	r := newTxnRun(t, c)
	os.Remove(filepath.Join(r.l.ctrl, "decision"))
	var sb strings.Builder
	sb.WriteString(faultPrelude(r.l))
	sb.WriteString("[ \"$FAILS_NEED\" = 3 ] || { echo bad-thresholds; exit 1; }\n")
	for i, now := range []int{1700000005, 1700000010, 1700000015} {
		fmt.Fprintf(&sb, "rm -f %[1]s/up-*; touch %[1]s/up-m06 %[1]s/up-m07; echo %d > %[1]s/now\n", r.l.ctrl, now)
		if i == 2 {
			sb.WriteString(`echo "pre-up=$fb_up in=${fb_in[*]} fails=${fb_fails[*]}"` + "\n")
			sb.WriteString(`before=$(declare -p fb_in fb_goods fb_fails fb_up fb_des fb_since fb_switched SH_R_STATUS SH_R_W)` + "\n")
			fmt.Fprintf(&sb, "rm -f %[1]s/ip-n; : > %[1]s/ip.log; echo '=== failing pass' >> %[1]s/nft.log; echo 1 > %[1]s/ip-arm\n", r.l.ctrl)
		}
		sb.WriteString("share_step; rc=$?\n")
	}
	sb.WriteString(`after=$(declare -p fb_in fb_goods fb_fails fb_up fb_des fb_since fb_switched SH_R_STATUS SH_R_W)` + "\n")
	sb.WriteString(`[ "$before" = "$after" ] && echo state-kept || printf 'state-changed\n%s\n%s\n' "$before" "$after"` + "\n")
	sb.WriteString(`echo "rc=$rc up=$fb_up sw=$fb_switched"` + "\n")
	out, err := r.l.bash(sb.String())
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// Before the failing pass the main relay has failed FAILS_NEED-1 passes
	// and both backup-group relays are in: the pass attempts the switch.
	if !strings.Contains(out, "pre-up=main in=1 1 1 fails=2 0 0") {
		t.Fatalf("backup group not eligible before the switch:\n%s", out)
	}
	nl := r.l.read("nft.log")
	i := strings.LastIndex(nl, "=== failing pass")
	if i < 0 {
		t.Fatal("no failing-pass marker in nft.log")
	}
	// The attempted switch's assignment batch carries the backup-group
	// weights (m06 → 0x00020000, m07 → 0x00030000, half each, nothing on
	// m05); the compensation batch that follows returns all to m05 (main).
	asg := strings.Split(nl[i:], "flush chain inet meridian relay_assign")
	if len(asg) != 3 {
		t.Fatalf("want switch + compensation assignment batches, got %d:\n%s", len(asg)-1, nl[i:])
	}
	sw, comp := asg[1], asg[2]
	if !strings.Contains(sw, "map { 0-499 : 0x00020000, 500-999 : 0x00030000 }") || strings.Contains(sw, "0x00010000") {
		t.Fatalf("switch batch is not the backup group:\n%s", sw)
	}
	if !strings.Contains(comp, "map { 0-999 : 0x00010000 }") || strings.Contains(comp, "0x00020000") || strings.Contains(comp, "0x00030000") {
		t.Fatalf("compensation batch is not back on the main group:\n%s", comp)
	}
	if !strings.Contains(out, "rc=3 up=main sw=0") || !strings.Contains(out, "state-kept") {
		t.Fatalf("fallback published or counted an unapplied switch:\n%s", out)
	}
	if r.field("path") != "main" || r.field("switched") != "0" {
		t.Fatalf("record\n%s", r.status())
	}
}

// Two appliers never interleave: the switch lock serialises them.
func TestShareTxnSerialised(t *testing.T) {
	c := txnCases()[0]
	r := newTxnRun(t, c)
	ctrl := r.l.ctrl
	out, err := r.l.bash(fmt.Sprintf(`( share_lock; touch %[1]s/locked; sleep 1; echo held >> %[1]s/order ) &
while [ ! -f %[1]s/locked ]; do sleep 0.05; done
share_step; echo step >> %[1]s/order
wait
`, ctrl))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := r.l.read("order"); got != "held\nstep\n" {
		t.Fatalf("order %q", got)
	}
}

// killedStep runs one share_step that the injected SIGKILL ends.
func (r *txnRun) killedStep() {
	r.t.Helper()
	out, err := r.l.bash(faultPrelude(r.l) + "share_step\necho \"rc=$?\"\n")
	if err == nil || strings.Contains(out, "rc=") {
		r.t.Fatalf("pass not killed (%v)\n%s", err, out)
	}
	r.disarm()
}

// A pass killed after its commit point ("current" names the pending
// target) finishes the commit on restart without a fence or an install;
// one killed before the kernel switch completed stays fenced and blocked.
func TestShareTxnKilledAfterCommitRecovers(t *testing.T) {
	argsB := map[string]string{
		"ungrouped": "backup backup m02 0 1 m03 0 1 0",
		"grouped":   "backup bk1 m05 0 0 m06 500 0 m07 500 0 0",
	}
	for _, c := range txnCases() {
		for _, window := range []string{"kill-marker", "kill-unpend"} {
			c, window := c, window
			t.Run(c.name+"/"+window, func(t *testing.T) {
				t.Parallel()
				r := newTxnRun(t, c)
				r.l.write("now", "1700000100\n")
				r.l.write("decision", c.decB)
				r.l.write(window, "")
				r.killedStep()
				if !r.exists("pathq/switch/pending") {
					t.Fatal("kill left no pending marker")
				}
				pend := strings.Fields(r.file("pathq/switch/pending"))
				if len(pend) != 2 || pend[1] != r.file("pathq/switch/current") {
					t.Fatalf("pending %q current %q", pend, r.file("pathq/switch/current"))
				}
				n := r.assignBatches()
				if rc := r.step(); rc != 0 {
					t.Fatalf("restart rc %d\n%s", rc, r.status())
				}
				if r.fenced() || r.exists("pathq/switch/blocked") || r.exists("pathq/switch/pending") || r.applied() != argsB[c.name] {
					t.Fatalf("not recovered: fenced %v blocked %v pending %v marker %q", r.fenced(), r.exists("pathq/switch/blocked"), r.exists("pathq/switch/pending"), r.applied())
				}
				if r.assignBatches() <= n || r.field("path") != "backup" || r.field("state") == "down" {
					t.Fatalf("kernel not verified or record wrong\n%s", r.status())
				}
			})
		}
	}
}

func TestShareTxnKilledBeforeCommitBlocks(t *testing.T) {
	for _, c := range txnCases() {
		for _, k := range []int{1, 5, c.routeCalls} {
			c, k := c, k
			t.Run(fmt.Sprintf("%s/ip%d", c.name, k), func(t *testing.T) {
				t.Parallel()
				r := newTxnRun(t, c)
				before := r.snapshot()
				r.l.write("decision", c.decB)
				os.Remove(filepath.Join(r.l.ctrl, "ip-n"))
				r.l.write("ip-kill", fmt.Sprint(k))
				r.killedStep()
				n := r.assignBatches()
				if rc := r.step(); rc != 4 || r.assignBatches() != n {
					t.Fatalf("restart rc %d batches %d→%d", rc, n, r.assignBatches())
				}
				r.blockedDown(before)
			})
		}
	}
}

// pending names the committed snapshot but cannot be proven complete: a
// different compiled version, a snapshot of another version, a missing args
// file, a missing status, current naming another snapshot, empty or invalid
// args/weights, or a kernel that refuses the replay. Each stays fenced and
// blocked.
func TestShareTxnPendingMismatchBlocks(t *testing.T) {
	for _, c := range txnCases() {
		for _, bad := range []string{"pending-version", "snapshot-version", "no-args", "no-status", "other-current", "empty-args", "invalid-args", "invalid-weights", "replay-fails"} {
			c, bad := c, bad
			t.Run(c.name+"/"+bad, func(t *testing.T) {
				t.Parallel()
				r := newTxnRun(t, c)
				before := r.snapshot()
				cur := r.file("pathq/switch/current")
				ver := r.file("pathq/switch/" + cur + "/version")
				pend := ver + " " + cur + "\n"
				switch bad {
				case "pending-version":
					pend = "0000 " + cur + "\n"
				case "snapshot-version":
					if err := os.WriteFile(filepath.Join(r.l.run, "pathq/switch", cur, "version"), []byte("0000\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "no-args":
					os.Remove(filepath.Join(r.l.run, "pathq/switch", cur, "args"))
				case "no-status":
					os.Remove(filepath.Join(r.l.run, "pathq/switch", cur, "status"))
				case "other-current":
					// A well-formed name, but not the committed snapshot.
					pend = ver + " snapshot-other\n"
				case "empty-args", "invalid-args", "invalid-weights":
					args := map[string]string{
						"empty-args":      "\n",
						"invalid-args":    "sideways nobody m99 1 2\n",
						"invalid-weights": strings.Replace(c.argsA, " 0 ", " x ", 1) + "\n",
					}[bad]
					if err := os.WriteFile(filepath.Join(r.l.run, "pathq/switch", cur, "args"), []byte(args), 0o600); err != nil {
						t.Fatal(err)
					}
				case "replay-fails":
					r.arm(1, true)
				}
				if err := os.WriteFile(filepath.Join(r.l.run, "pathq/switch/pending"), []byte(pend), 0o600); err != nil {
					t.Fatal(err)
				}
				os.Remove(filepath.Join(r.l.run, "pathq/applied"))
				if rc := r.step(); rc != 4 {
					t.Fatalf("rc %d", rc)
				}
				r.blockedDown(before)
				if !r.exists("pathq/switch/pending") {
					t.Fatal("unprovable pending was cleared")
				}
			})
		}
	}
}
