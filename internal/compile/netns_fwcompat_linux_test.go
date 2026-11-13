//go:build linux

package compile

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
)

// TestNetnsFWCompatDockerUser runs the compiled meridian-fwcompat.sh of an
// exit against the real iptables of this machine (iptables-nft or legacy,
// whichever the binary is) in an isolated namespace that imitates Docker:
// FORWARD policy DROP, a DOCKER-USER chain jumped to first, an operator rule
// in it and a trailing RETURN. Traffic from a namespace behind the exit's
// tunnel interface (a veth named like the tunnel) to one behind its WAN must
// be dropped before, pass after "apply", survive a simulated Docker restart
// (chain rebuilt without our rules, "apply" again), and be dropped again
// after "remove", which must leave the operator rule and the RETURN alone.
// Opt-in like the other netns tests (MERIDIAN_NETNS_TEST=1, root); it has
// not been run in this repository's CI.
func TestNetnsFWCompatDockerUser(t *testing.T) {
	netnsPrereqs(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not installed")
	}
	b, err := Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	script := b.File("nodes/tw/" + strings.TrimPrefix(FWCompatPath, "/"))
	if script == "" {
		t.Fatal("tw has no meridian-fwcompat.sh")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fwcompat.sh")
	mustWrite(t, path, script)
	l := &netnsLab{t: t, dir: dir, ns: map[string]string{}}
	for _, n := range []string{"tun", "exit", "wan"} {
		name := "mfw-" + n
		l.ns[n] = name
		_, _ = l.sh("ip", "netns", "del", name)
		l.must("ip", "netns", "add", name)
		t.Cleanup(func() { _, _ = l.sh("ip", "netns", "del", name) })
	}
	// tun:c0 <-> exit:m14 ; exit:eth0 <-> wan:w0
	l.must("ip", "link", "add", "c0", "netns", l.ns["tun"], "type", "veth", "peer", "name", "m14", "netns", l.ns["exit"])
	l.must("ip", "link", "add", "eth0", "netns", l.ns["exit"], "type", "veth", "peer", "name", "w0", "netns", l.ns["wan"])
	for _, c := range [][]string{
		l.in("tun", "ip", "addr", "add", "192.0.2.2/24", "dev", "c0"),
		l.in("tun", "ip", "link", "set", "c0", "up"),
		l.in("tun", "ip", "route", "add", "default", "via", "192.0.2.1"),
		l.in("exit", "ip", "addr", "add", "192.0.2.1/24", "dev", "m14"),
		l.in("exit", "ip", "addr", "add", "198.51.100.1/24", "dev", "eth0"),
		l.in("exit", "ip", "link", "set", "m14", "up"),
		l.in("exit", "ip", "link", "set", "eth0", "up"),
		l.in("exit", "sysctl", "-qw", "net.ipv4.ip_forward=1"),
		l.in("wan", "ip", "addr", "add", "198.51.100.2/24", "dev", "w0"),
		l.in("wan", "ip", "link", "set", "w0", "up"),
		l.in("wan", "ip", "route", "add", "192.0.2.0/24", "via", "198.51.100.1"),
		// Docker's shape.
		l.in("exit", "iptables", "-w", "5", "-P", "FORWARD", "DROP"),
		l.in("exit", "iptables", "-w", "5", "-N", "DOCKER-USER"),
		l.in("exit", "iptables", "-w", "5", "-A", "DOCKER-USER", "-s", "203.0.113.0/24", "-m", "comment", "--comment", "keep-me", "-j", "DROP"),
		l.in("exit", "iptables", "-w", "5", "-A", "DOCKER-USER", "-j", "RETURN"),
		l.in("exit", "iptables", "-w", "5", "-I", "FORWARD", "1", "-j", "DOCKER-USER"),
	} {
		l.must(c...)
	}
	ping := func() bool {
		_, err := l.sh(l.in("tun", "ping", "-c", "1", "-W", "1", "-n", "198.51.100.2")...)
		return err == nil
	}
	dockerUser := func() string { return l.must(l.in("exit", "iptables", "-w", "5", "-S", "DOCKER-USER")...) }
	if ping() {
		t.Fatal("control: forwarding passed FORWARD DROP without Meridian's rules")
	}
	for i := 0; i < 2; i++ {
		out := l.must(l.in("exit", "bash", path, "apply")...)
		if !ping() {
			t.Fatalf("apply %d: tunnel -> WAN still dropped\n%s\n%s", i, out, dockerUser())
		}
	}
	if n := strings.Count(dockerUser(), "--comment meridian-fw-"); n != 2 {
		t.Fatalf("want 2 tagged rules after two applies, got %d:\n%s", n, dockerUser())
	}
	// Docker restart: the chain comes back without our rules.
	l.must(l.in("exit", "iptables", "-w", "5", "-F", "DOCKER-USER")...)
	l.must(l.in("exit", "iptables", "-w", "5", "-A", "DOCKER-USER", "-j", "RETURN")...)
	if ping() {
		t.Fatal("rebuilt chain still passes")
	}
	l.must(l.in("exit", "bash", path, "apply")...)
	if !ping() {
		t.Fatalf("re-assert after a Docker restart failed:\n%s", dockerUser())
	}
	l.must(l.in("exit", "iptables", "-w", "5", "-I", "DOCKER-USER", "2", "-s", "203.0.113.0/24", "-m", "comment", "--comment", "keep-me", "-j", "DROP")...)
	l.must(l.in("exit", "bash", path, "remove")...)
	if ping() {
		t.Fatal("remove left forwarding open")
	}
	left := dockerUser()
	if strings.Contains(left, "meridian-fw-") || !strings.Contains(left, "keep-me") || !strings.Contains(left, "-A DOCKER-USER -j RETURN") {
		t.Fatalf("remove did not remove exactly Meridian's rules:\n%s", left)
	}
	if pol := l.must(l.in("exit", "iptables", "-w", "5", "-S", "FORWARD")...); !strings.HasPrefix(pol, "-P FORWARD DROP") || !strings.Contains(pol, "-A FORWARD -j DOCKER-USER") {
		t.Fatalf("FORWARD changed:\n%s", pol)
	}
}
