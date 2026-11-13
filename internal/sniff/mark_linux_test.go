//go:build linux

package sniff

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in (root, MERIDIAN_NETNS_TEST=1, docs/verification.md): SO_MARK on
// the forwarder's sockets, the IP_TRANSPARENT listener, the neighbour dump
// and SO_ORIGINAL_DST behind an nft redirect, in a private network
// namespace (unshare -n) so the host's rules are not touched.
func TestLinuxSocketOptions(t *testing.T) {
	if os.Getenv("MERIDIAN_SNIFF_NETNS_HELPER") == "1" {
		linuxHelper(t)
		return
	}
	if os.Getenv("MERIDIAN_NETNS_TEST") != "1" {
		t.Skip("runtime netns test: run as root with MERIDIAN_NETNS_TEST=1 (docs/verification.md)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, bin := range []string{"unshare", "nft", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run=^TestLinuxSocketOptions$", "-test.v")
	cmd.Env = append(os.Environ(), "MERIDIAN_SNIFF_NETNS_HELPER=1")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil || !strings.Contains(string(out), "--- PASS") {
		t.Fatalf("helper: %v", err)
	}
}

func linuxHelper(t *testing.T) {
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("lo up: %v %s", err, out)
	}
	// SO_MARK on an outbound socket.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c, err := DialMarked(context.Background(), "tcp", l.Addr().String(), 0x113)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := SocketMark(c); err != nil || m != 0x113 {
		t.Fatalf("mark %#x %v", m, err)
	}
	c.Close()
	// IP_TRANSPARENT listener.
	tl, err := Listen(context.Background(), Config{Mode: "tproxy", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("transparent listen: %v", err)
	}
	tl.Close()
	// Neighbour dump works (an empty namespace has no entries).
	if _, err := neighDump(); err != nil {
		t.Fatalf("neighbour dump: %v", err)
	}
	// SO_ORIGINAL_DST behind a redirect of locally generated traffic.
	rl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	port := rl.Addr().(*net.TCPAddr).Port
	rules := "table ip sniff_test { chain out { type nat hook output priority -100; ip daddr 127.0.0.2 tcp dport 9443 redirect to :" + strconv.Itoa(port) + "; }; }"
	if out, err := exec.Command("nft", rules).CombinedOutput(); err != nil {
		t.Fatalf("nft: %v %s", err, out)
	}
	got := make(chan netip.AddrPort, 1)
	go func() {
		c, err := rl.Accept()
		if err != nil {
			got <- netip.AddrPort{}
			return
		}
		ap, err := OrigDstRedirect(c)
		if err != nil {
			t.Errorf("SO_ORIGINAL_DST: %v", err)
		}
		got <- ap
		c.Close()
	}()
	cc, err := net.DialTimeout("tcp", "127.0.0.2:9443", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if ap := <-got; ap != netip.MustParseAddrPort("127.0.0.2:9443") {
		t.Fatalf("original destination %v", ap)
	}
}
