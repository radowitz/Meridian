package provision

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/preflight"
)

// Coexistence with what already runs on a host (S1): Docker's FORWARD
// DROP (iptables-nft and legacy look the same through the iptables
// binary), IPv4-only DROP, a missing DOCKER-USER, a Docker daemon restart,
// withdraw and compensation removing exactly Meridian's tagged rules, the
// sysctl scope, nftables flush refusal and the boot unit. Every run uses the
// sandbox's stateful iptables stub; nothing touches a real host.

// tw's coexistence rules as iptables -S prints them.
func twRules(t *testing.T, files map[string]string) []string {
	t.Helper()
	fp := preflight.FootprintOf(files)
	if fp.FWChain != compile.FWChain || !strings.HasPrefix(fp.FWTag, compile.FWTagPrefix) || len(fp.FWRules) != 2 {
		t.Fatalf("footprint %q %q %v", fp.FWChain, fp.FWTag, fp.FWRules)
	}
	var out []string
	for _, r := range fp.FWRules {
		out = append(out, "-A DOCKER-USER "+r+" -m comment --comment "+fp.FWTag+" -j ACCEPT")
	}
	return out
}

func (sb *sandbox) lines(p string) []string {
	sb.t.Helper()
	b, err := os.ReadFile(filepath.Join(sb.root, p))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// dockerHost: IPv4 FORWARD DROP with DOCKER-USER (operator and Docker
// entries already in it); IPv6 policy ACCEPT and no ip6 DOCKER-USER, as on
// the operator's real hosts.
func dockerHost(sb *sandbox, docker string) {
	sb.write("/ipt4-policy", "DROP\n")
	sb.write("/ipt4-FORWARD", "-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n")
	sb.write("/ipt4-DOCKER-USER", docker)
}

const operatorRule = "-A DOCKER-USER -s 198.51.100.0/24 -m comment --comment keep-me -j DROP\n"

func TestFWCompatDockerDropIPv4Only(t *testing.T) {
	for name, existing := range map[string]string{
		// iptables-nft (Debian 12/13, Docker 2x): empty chain apart from
		// the operator's own rule.
		"nft": operatorRule,
		// legacy (Ubuntu 20.04, older Docker): a trailing RETURN.
		"legacy": operatorRule + "-A DOCKER-USER -j RETURN\n",
	} {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			dockerHost(sb, existing)
			script, files := testScript(t, "tw", "none")
			out, code := sb.run(script)
			if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") {
				t.Fatalf("exit %d\n%s", code, out)
			}
			want := append(twRules(t, files), strings.Split(strings.TrimRight(existing, "\n"), "\n")...)
			if got := sb.lines("/ipt4-DOCKER-USER"); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("DOCKER-USER:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			// IPv6: policy ACCEPT, no chain: nothing inserted anywhere.
			if sb.exists("/ipt6-DOCKER-USER") {
				t.Fatal("an ip6 DOCKER-USER appeared")
			}
			calls := sb.read("/calls.log")
			for _, bad := range []string{" -F", " -P ", " -X", " -N", "-D FORWARD", "-I FORWARD", "-A FORWARD", "DOCKER-FORWARD"} {
				if strings.Contains(calls, "iptables -w 5"+bad) || strings.Contains(calls, "ip6tables -w 5"+bad) {
					t.Fatalf("touched something that is not Meridian's (%q):\n%s", bad, calls)
				}
			}
			if strings.Contains(calls, "ip6tables -w 5 -I") {
				t.Fatalf("inserted into ip6tables with policy ACCEPT:\n%s", calls)
			}
			man := strings.ReplaceAll(sb.read("/var/lib/meridian/node/manifest"), sb.root, "")
			for _, w := range []string{"fw ipv4 DOCKER-USER", "fw ipv6 DOCKER-USER", "unit meridian-node.service", "unit meridian-fwcompat.service", "file /usr/local/sbin/meridian-fwcompat.sh "} {
				if !strings.Contains(man, w) {
					t.Fatalf("manifest lacks %q:\n%s", w, man)
				}
			}
			if r := preflight.Parse(preflight.Header + "\nmanifest-begin\n" + prefixLines("manifest ", man) + "manifest-end\n" + preflight.EndMarker + "\n"); strings.Join(r.Manifest.FWChains, ",") != "ipv4 DOCKER-USER,ipv6 DOCKER-USER" {
				t.Fatalf("manifest fw round trip %v", r.Manifest.FWChains)
			}
			// The boot and re-assert units are enabled (never started from
			// meridian-up.sh, which would deadlock at boot).
			if !strings.Contains(calls, "systemctl enable meridian-node.service\n") || !strings.Contains(calls, "systemctl enable meridian-fwcompat.service\n") ||
				strings.Contains(calls, "enable --now meridian-node.service") || strings.Contains(calls, "start meridian-node.service") {
				t.Fatalf("boot units:\n%s", calls)
			}

			// Docker restart (or a reboot): Docker recreates DOCKER-USER
			// without our rules; the re-assert unit runs the same script.
			sb.write("/ipt4-DOCKER-USER", existing)
			fw := filepath.Join(sb.root, "usr/local/sbin/meridian-fwcompat.sh")
			for i := 0; i < 2; i++ {
				out, code = sb.runRaw("exec bash " + fw + " apply\n")
				if code != 0 {
					t.Fatalf("re-assert %d: %d\n%s", i, code, out)
				}
				if got := sb.lines("/ipt4-DOCKER-USER"); strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Fatalf("after re-assert %d:\n%s", i, strings.Join(got, "\n"))
				}
			}
			// Docker later sets the IPv6 policy to DROP too: the next run
			// covers that family as well, by what it finds then.
			sb.write("/ipt6-policy", "DROP\n")
			sb.write("/ipt6-FORWARD", "-A FORWARD -j DOCKER-USER\n")
			sb.write("/ipt6-DOCKER-USER", "")
			if out, code = sb.runRaw("exec bash " + fw + " apply\n"); code != 0 {
				t.Fatalf("v6: %d\n%s", code, out)
			}
			if got := sb.lines("/ipt6-DOCKER-USER"); strings.Join(got, "\n") != strings.Join(twRules(t, files), "\n") {
				t.Fatalf("ip6 DOCKER-USER:\n%s", strings.Join(got, "\n"))
			}
			// And back to ACCEPT: Meridian's rules leave that family.
			sb.write("/ipt6-policy", "ACCEPT\n")
			if out, code = sb.runRaw("exec bash " + fw + " apply\n"); code != 0 || len(sb.lines("/ipt6-DOCKER-USER")) != 0 {
				t.Fatalf("v6 accept: %d %v\n%s", code, sb.lines("/ipt6-DOCKER-USER"), out)
			}

			// Withdraw removes exactly the tagged rules: the operator's
			// rule and Docker's RETURN stay, and nothing else is called.
			sb.hostPaths("/var/lib/meridian/node/manifest")
			withdrawStubs(t, sb)
			sb.touch("enabled-meridian-fwcompat.service")
			os.Remove(filepath.Join(sb.root, "calls.log"))
			w := plan(t, sb, wopts("tw", WithdrawManifest, WithdrawPlan, ""))
			if !strings.Contains(strings.Join(w.Plan, "\n"), "fwrules IPv4 DOCKER-USER 2 tagged") {
				t.Fatalf("plan %v", w.Plan)
			}
			out, code = sb.runRaw(WithdrawScript(wopts("tw", WithdrawManifest, WithdrawRun, w.Digest)))
			if code != 0 || !strings.Contains(out, "MERIDIAN_WITHDRAW_OK") || !strings.Contains(out, "MERIDIAN_REMOVED fwrule IPv4 DOCKER-USER -i m14 -o eth0") {
				t.Fatalf("withdraw %d\n%s", code, out)
			}
			if got := strings.Join(sb.lines("/ipt4-DOCKER-USER"), "\n"); got != strings.TrimRight(existing, "\n") {
				t.Fatalf("after withdraw DOCKER-USER:\n%s", got)
			}
			calls = sb.read("/calls.log")
			for _, l := range strings.Split(calls, "\n") {
				if strings.Contains(l, "iptables -w 5 -D") && !strings.Contains(l, "--comment meridian-fw-") {
					t.Fatalf("withdraw deleted an untagged rule: %s", l)
				}
				if strings.Contains(l, "iptables") && (strings.Contains(l, " -F") || strings.Contains(l, " -P ") || strings.Contains(l, " -X")) {
					t.Fatalf("withdraw flushed or changed a policy: %s", l)
				}
			}
			if !strings.Contains(calls, "systemctl disable --now meridian-fwcompat.service") {
				t.Fatalf("re-assert unit not disabled:\n%s", calls)
			}
		})
	}
}

// A rule set from an earlier install (another tag) is replaced; a rule
// that only looks similar (wrong tag shape) is not Meridian's and stays.
func TestFWCompatReplacesStaleTagOnly(t *testing.T) {
	sb := newSandbox(t)
	stale := "-A DOCKER-USER -i m99 -o eth0 -m comment --comment meridian-fw-0000abcd -j ACCEPT\n"
	lookalike := "-A DOCKER-USER -i m98 -o eth0 -m comment --comment meridian-fw-NOTHEX -j ACCEPT\n"
	dockerHost(sb, stale+lookalike+"-A DOCKER-USER -j RETURN\n")
	script, files := testScript(t, "tw", "none")
	if out, code := sb.run(script); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	want := append(twRules(t, files), strings.TrimRight(lookalike, "\n"), "-A DOCKER-USER -j RETURN")
	if got := sb.lines("/ipt4-DOCKER-USER"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("DOCKER-USER:\n%s", strings.Join(got, "\n"))
	}
}

// FORWARD DROP without DOCKER-USER: meridian-up.sh fails before
// forwarding and tunnels, the run is compensated and nothing of
// Meridian's stays in iptables.
func TestFWCompatMissingDockerUserFailsClosed(t *testing.T) {
	sb := newSandbox(t)
	sb.write("/ipt4-policy", "DROP\n")
	script, _ := testScript(t, "tw", "none")
	out, code := sb.run(script)
	if code == 0 || !strings.Contains(out, "meridian-fwcompat-unsupported") || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	calls := sb.read("/calls.log")
	if strings.Contains(calls, "wg-quick up") || strings.Contains(calls, "sysctl -w net.ipv4.ip_forward=1") || strings.Contains(calls, "iptables -w 5 -I") {
		t.Fatalf("went past the coexistence step:\n%s", calls)
	}
}

// A failed first install removes the rules it added, keeps the operator's
// and restores the sysctls it recorded.
func TestFWCompatCompensation(t *testing.T) {
	sb := newSandbox(t)
	dockerHost(sb, operatorRule)
	script, _ := testScript(t, "tw", "none")
	out, code := sb.run(script, "FAIL_SYSTEMCTL=1")
	if code == 0 || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got := strings.Join(sb.lines("/ipt4-DOCKER-USER"), "\n"); got != strings.TrimRight(operatorRule, "\n") {
		t.Fatalf("after compensation DOCKER-USER:\n%s", got)
	}
	calls := sb.read("/calls.log")
	if !strings.Contains(calls, "iptables -w 5 -I DOCKER-USER 1") || !strings.Contains(calls, "iptables -w 5 -D DOCKER-USER -i m14 -o eth0") {
		t.Fatalf("rules not added then removed:\n%s", calls)
	}
	// A rule that cannot be removed is a named leftover.
	sb2 := newSandbox(t)
	dockerHost(sb2, operatorRule)
	out, code = sb2.run(script, "FAIL_SYSTEMCTL=1", "FAIL_IPT_DELETE=1")
	if code == 0 || !strings.Contains(out, "MERIDIAN_LEFTOVER firewall IPv4 DOCKER-USER -i m14 -o eth0") || !strings.Contains(out, "MERIDIAN_COMPENSATION_INCOMPLETE") {
		t.Fatalf("undeletable rule: %d\n%s", code, out)
	}
}

// sysctl scope: the compiled scripts, run with a recording sysctl, write
// exactly the managed keys, on the managed interfaces and the topology's
// interface only. Docker, WARP and veth interfaces on the host are never
// named; compensation restores only recorded keys.
func TestSysctlScopeOnlyManagedInterfaces(t *testing.T) {
	sb := newSandbox(t)
	for _, i := range []string{"eth0", "docker0", "CloudflareWARP", "veth1a2b3c"} {
		for _, fam := range []string{"ipv4", "ipv6"} {
			os.MkdirAll(filepath.Join(sb.root, "proc/sys/net", fam, "conf", i), 0o755)
			os.WriteFile(filepath.Join(sb.root, "proc/sys/net", fam, "conf", i, "accept_redirects"), []byte("1\n"), 0o644)
		}
		os.WriteFile(filepath.Join(sb.root, "proc/sys/net/ipv4/conf", i, "rp_filter"), []byte("0\n"), 0o644)
	}
	script, files := testScript(t, "tw", "none")
	if out, code := sb.run(script); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	got := map[string]bool{}
	for _, l := range strings.Split(sb.read("/calls.log"), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "sysctl" {
			continue
		}
		for _, a := range f[1:] {
			if k, _, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "net.") {
				got[k] = true
			}
		}
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{
		"net.ipv4.conf.all.send_redirects",
		"net.ipv4.conf.eth0.accept_redirects", "net.ipv4.conf.eth0.rp_filter", "net.ipv4.conf.eth0.send_redirects",
		"net.ipv4.conf.m14.accept_redirects", "net.ipv4.conf.m14.rp_filter", "net.ipv4.conf.m14.send_redirects",
		// tw has no IPv6 egress and relays no IPv6: IPv6 forwarding is
		// never touched there.
		"net.ipv4.ip_forward",
		"net.ipv6.conf.eth0.accept_redirects", "net.ipv6.conf.m14.accept_redirects",
	}
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Fatalf("sysctl keys written:\n%s\nwant:\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}
	if fp := preflight.FootprintOf(files); strings.Join(fp.SysctlKeys, " ") != strings.Join(want, " ") {
		t.Fatalf("footprint keys %v", fp.SysctlKeys)
	}
	// The values recorded for compensation are the scoped keys only.
	sb2 := newSandbox(t)
	for _, i := range []string{"docker0", "eth0"} {
		os.MkdirAll(filepath.Join(sb2.root, "proc/sys/net/ipv4/conf", i), 0o755)
		os.WriteFile(filepath.Join(sb2.root, "proc/sys/net/ipv4/conf", i, "rp_filter"), []byte("1\n"), 0o644)
	}
	if !strings.Contains(script, "/proc/sys/net/ipv4/conf/eth0/rp_filter") || strings.Contains(script, "/proc/sys/net/ipv4/conf/*") {
		t.Fatal("pre-sysctl is not scoped")
	}
	// Simulate a run that changes both values and then fails: only eth0
	// (recorded) is restored; docker0 is never written.
	sys := "#!/bin/bash\necho \"sysctl $*\" >> \"$SANDBOX/calls.log\"\nfor a in \"$@\"; do case \"$a\" in net.*=*) k=${a%%=*}; v=${a#*=}; p=\"$SANDBOX/proc/sys/$(echo \"$k\" | tr . /)\"; [ -f \"$p\" ] && echo \"$v\" > \"$p\";; esac; done\nexit 0\n"
	os.WriteFile(filepath.Join(sb2.bin, "sysctl"), []byte(sys), 0o755)
	os.WriteFile(filepath.Join(sb2.root, "proc/sys/net/ipv4/conf/docker0/rp_filter"), []byte("1\n"), 0o644)
	out, code := sb2.run(script, "FAIL_SYSTEMCTL=1")
	if code == 0 || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if v := strings.TrimSpace(sb2.read("/proc/sys/net/ipv4/conf/eth0/rp_filter")); v != "1" {
		t.Fatalf("eth0 rp_filter not restored: %q", v)
	}
	if v := strings.TrimSpace(sb2.read("/proc/sys/net/ipv4/conf/docker0/rp_filter")); v != "1" || strings.Contains(sb2.read("/calls.log"), "docker0") {
		t.Fatalf("docker0 touched: %q", v)
	}
}

// nftables.service that would flush the ruleset: refused before anything
// changes, in the script's own re-check as well as in the preflight.
func TestProvisionRefusesFlushingNftablesService(t *testing.T) {
	sb := newSandbox(t)
	sb.write("/etc/nftables.conf", "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n}\n")
	script, _ := testScript(t, "tw", "none")
	out, code := sb.run(script)
	if code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED nftables_flush_on_reload") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if sb.exists("/var/lib/meridian/node/journal") || sb.exists("/etc/wireguard") {
		t.Fatal("refusal changed something")
	}
	// Without the whole-ruleset flush (and with an ExecStop that does not
	// flush, the stub prints nothing) the install goes ahead.
	sb.write("/etc/nftables.conf", "#!/usr/sbin/nft -f\ntable inet filter\ndelete table inet filter\ntable inet filter {\n}\n")
	if out, code := sb.run(script); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// writingSysctl records every call and writes "key=value" arguments
// (dotted or slash form) into the sandbox's /proc/sys.
const writingSysctl = "#!/bin/bash\necho \"sysctl $*\" >> \"$SANDBOX/calls.log\"\n[ \"$FAIL_SYSCTL_RA\" = 1 ] && case \"$*\" in *accept_ra*) exit 1;; esac\nfor a in \"$@\"; do case \"$a\" in net*=*) k=${a%%=*}; v=${a#*=}; p=\"$SANDBOX/proc/sys/$(echo \"$k\" | tr . /)\"; [ -f \"$p\" ] && echo \"$v\" > \"$p\";; esac; done\nexit 0\n"

// raHost: eth0's IPv6 default route comes from router advertisements and
// accept_ra is the given value; IPv6 forwarding is off.
func raHost(t *testing.T, acceptRA string) *sandbox {
	sb := newSandbox(t)
	os.MkdirAll(filepath.Join(sb.root, "proc/sys/net/ipv6/conf/eth0"), 0o755)
	sb.write("/proc/sys/net/ipv6/conf/eth0/accept_ra", acceptRA+"\n")
	sb.write("/ra6", "default via fe80::1 dev eth0 proto ra metric 1024 expires 1790sec pref medium\n2001:db8:5::/64 dev eth0 proto ra metric 256 expires 86390sec pref medium\n")
	os.WriteFile(filepath.Join(sb.bin, "sysctl"), []byte(writingSysctl), 0o755)
	return sb
}

func sysctlCalls(sb *sandbox) []string {
	var out []string
	for _, l := range strings.Split(sb.read("/calls.log"), "\n") {
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "sysctl" && f[1] == "-w" {
			out = append(out, f[2])
		}
	}
	return out
}

func indexOf(s []string, prefix string) int {
	for i, v := range s {
		if strings.HasPrefix(v, prefix) {
			return i
		}
	}
	return -1
}

// An exit with IPv6 egress on a host whose IPv6 comes from RA: accept_ra=2
// on that interface before IPv6 forwarding, recorded for later boots,
// exactly the managed keys plus that one; a late RA at boot is covered by
// the record; a failed first install restores accept_ra and drops the
// record; accept_ra 0 (userspace RA client) stops before forwarding.
func TestRAKeptBeforeIPv6Forwarding(t *testing.T) {
	sb := raHost(t, "1")
	script, files := testScript(t, "hk-resi", "none")
	out, code := sb.run(script)
	if code != 0 || !strings.Contains(out, "meridian-ra: eth0 accept_ra 1 -> 2") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	calls := sysctlCalls(sb)
	ra, fwd6, fwd4 := indexOf(calls, "net/ipv6/conf/eth0/accept_ra=2"), indexOf(calls, "net.ipv6.conf.all.forwarding=1"), indexOf(calls, "net.ipv4.ip_forward=1")
	if ra < 0 || fwd6 < 0 || ra > fwd6 || ra > fwd4 {
		t.Fatalf("accept_ra=2 must come before forwarding: %v", calls)
	}
	got := map[string]bool{}
	for _, c := range calls {
		k, _, _ := strings.Cut(c, "=")
		got[strings.ReplaceAll(k, "/", ".")] = true
	}
	want := map[string]bool{"net.ipv6.conf.eth0.accept_ra": true}
	for _, k := range preflight.FootprintOf(files).SysctlKeys {
		want[k] = true
	}
	for k := range got {
		if !want[k] {
			t.Fatalf("unexpected key %s (calls %v)", k, calls)
		}
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("key %s not written (calls %v)", k, calls)
		}
	}
	if v := strings.TrimSpace(sb.read("/proc/sys/net/ipv6/conf/eth0/accept_ra")); v != "2" || strings.TrimSpace(sb.read("/var/lib/meridian/node/ra-accept")) != "eth0" {
		t.Fatalf("accept_ra %q, record %q", v, sb.read("/var/lib/meridian/node/ra-accept"))
	}
	// Reboot with the RA not there yet: the record still switches eth0
	// before forwarding.
	os.Remove(filepath.Join(sb.root, "ra6"))
	sb.write("/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	os.Remove(filepath.Join(sb.root, "calls.log"))
	if out, code := sb.runRaw("exec bash " + filepath.Join(sb.root, "usr/local/sbin/meridian-up.sh") + "\n"); code != 0 {
		t.Fatalf("boot run %d\n%s", code, out)
	}
	calls = sysctlCalls(sb)
	if ra, fwd6 := indexOf(calls, "net/ipv6/conf/eth0/accept_ra=2"), indexOf(calls, "net.ipv6.conf.all.forwarding=1"); ra < 0 || ra > fwd6 {
		t.Fatalf("boot: %v", calls)
	}

	// Failed first install: accept_ra back to 1, record gone.
	sb2 := raHost(t, "1")
	out, code = sb2.run(script, "FAIL_SYSTEMCTL=1")
	if code == 0 || !strings.Contains(out, "MERIDIAN_COMPENSATED") || !strings.Contains(sb2.read("/calls.log"), "accept_ra=2") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if v := strings.TrimSpace(sb2.read("/proc/sys/net/ipv6/conf/eth0/accept_ra")); v != "1" || sb2.exists("/var/lib/meridian/node/ra-accept") {
		t.Fatalf("not restored: accept_ra %q record %v", v, sb2.exists("/var/lib/meridian/node/ra-accept"))
	}

	// Userspace RA client (accept_ra 0): stop before any forwarding.
	sb3 := raHost(t, "0")
	out, code = sb3.run(script)
	if code == 0 || !strings.Contains(out, "meridian-ra-unmanaged: eth0") || indexOf(sysctlCalls(sb3), "net.ipv6.conf.all.forwarding=1") >= 0 || indexOf(sysctlCalls(sb3), "net.ipv4.ip_forward=1") >= 0 {
		t.Fatalf("accept_ra 0: %d %v\n%s", code, sysctlCalls(sb3), out)
	}

	// No RA on the host: no accept_ra key at all.
	sb4 := newSandbox(t)
	os.WriteFile(filepath.Join(sb4.bin, "sysctl"), []byte(writingSysctl), 0o755)
	if out, code := sb4.run(script); code != 0 || strings.Contains(sb4.read("/calls.log"), "accept_ra") || sb4.exists("/var/lib/meridian/node/ra-accept") {
		t.Fatalf("no RA: %d\n%s", code, out)
	}
	// An exit that forwards no IPv6 never touches accept_ra or IPv6 forwarding.
	sb5 := raHost(t, "1")
	tw, _ := testScript(t, "tw", "none")
	if out, code := sb5.run(tw); code != 0 || strings.Contains(sb5.read("/calls.log"), "accept_ra") || strings.Contains(sb5.read("/calls.log"), "net.ipv6.conf.all.forwarding") {
		t.Fatalf("tw: %d\n%s", code, out)
	}
}

// Withdraw removes the record and leaves accept_ra=2 (forwarding stays on).
func TestWithdrawKeepsAcceptRA(t *testing.T) {
	sb := raHost(t, "1")
	withdrawStubs(t, sb)
	os.WriteFile(filepath.Join(sb.bin, "sysctl"), []byte(writingSysctl), 0o755)
	script, _ := testScript(t, "hk-resi", "none")
	if out, code := sb.run(script); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	sb.hostPaths("/var/lib/meridian/node/manifest")
	w := plan(t, sb, wopts("hk-resi", WithdrawManifest, WithdrawPlan, ""))
	out, code := sb.runRaw(WithdrawScript(wopts("hk-resi", WithdrawManifest, WithdrawRun, w.Digest)))
	if code != 0 || !strings.Contains(out, "MERIDIAN_KEPT sysctl accept_ra=2 stays on eth0") || sb.exists("/var/lib/meridian/node/ra-accept") {
		t.Fatalf("withdraw %d\n%s", code, out)
	}
	if v := strings.TrimSpace(sb.read("/proc/sys/net/ipv6/conf/eth0/accept_ra")); v != "2" {
		t.Fatalf("accept_ra %q", v)
	}
}

// The WAN interface is re-checked on the host before anything changes.
func TestProvisionRechecksWAN(t *testing.T) {
	script, _ := testScript(t, "hk-resi", "none")
	for name, c := range map[string]struct {
		setup func(*sandbox)
		code  string
	}{
		"missing":          {func(sb *sandbox) { sb.touch("no-eth0") }, "wan_interface_missing"},
		"v4 default ens5":  {func(sb *sandbox) { sb.write("/route4-default", "default via 192.0.2.1 dev ens5\n") }, "wan_no_default_route"},
		"no v6 default":    {func(sb *sandbox) { sb.write("/route6-default", "") }, "wan_no_default_route"},
		"v6 on other NIC ": {func(sb *sandbox) { sb.write("/route6-default", "default via fe80::1 dev eth1 proto ra\n") }, "wan_no_default_route"},
	} {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			c.setup(sb)
			out, code := sb.run(script)
			if code != 3 || !strings.Contains(out, "MERIDIAN_REFUSED "+c.code) || sb.exists("/var/lib/meridian/node/journal") {
				t.Fatalf("exit %d\n%s", code, out)
			}
		})
	}
}

// A host without Docker (seen on a real hub, Debian 13 / systemd 257):
// "systemctl enable" of a unit that is WantedBy=docker.service exits 1
// there ("added as a dependency to a non-existent unit docker.service"),
// which failed the whole first install. The re-assert unit is only enabled
// where docker.service exists; the boot unit is enabled everywhere, and
// meridian-up.sh still runs the compatibility script on every start.
func TestProvisionWithoutDockerDoesNotEnableReassertUnit(t *testing.T) {
	sb := newSandbox(t)
	script, _ := testScript(t, "tw", "none")
	sys := "#!/bin/bash\necho \"systemctl $*\" >> \"$SANDBOX/calls.log\"\n" +
		"case \"$*\" in\n" +
		"  \"cat docker.service\") exit 1 ;;\n" +
		"  \"enable meridian-fwcompat.service\") echo 'Unit meridian-fwcompat.service is added as a dependency to a non-existent unit docker.service.' >&2; exit 1 ;;\n" +
		"esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(sb.bin, "systemctl"), []byte(sys), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := sb.run(script)
	if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	calls := sb.read("/calls.log")
	if strings.Contains(calls, "systemctl enable meridian-fwcompat.service") {
		t.Fatalf("enabled the re-assert unit on a host without docker.service:\n%s", calls)
	}
	if !strings.Contains(calls, "systemctl enable meridian-node.service\n") {
		t.Fatalf("boot unit not enabled:\n%s", calls)
	}
	if !strings.Contains(out, "no docker.service on this host") {
		t.Fatalf("the skip is not reported:\n%s", out)
	}
	// The unit file is still installed and in the manifest, so a later
	// update (after Docker is installed) only has to enable it and a
	// withdraw removes it.
	man := sb.read("/var/lib/meridian/node/manifest")
	if !strings.Contains(man, "unit meridian-fwcompat.service") {
		t.Fatalf("manifest lacks the unit:\n%s", man)
	}
}
