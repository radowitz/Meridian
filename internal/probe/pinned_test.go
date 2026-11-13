package probe

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/unlock"
)

// A failed lookup must name the exit's resolver, never the nominal system
// resolver Go puts in *net.DNSError ("lookup x on 192.168.100.1:53"): an
// operator reads that as a query to the home router.
func TestResolveErrorNamesExitResolver(t *testing.T) {
	res := netip.MustParseAddr("fd66:0:0:10::2")
	de := &net.DNSError{
		Name:      "www.cloudflare.com",
		Server:    "192.168.100.1:53",
		Err:       "read udp6 [fd66:0:0:ff::c]:60206->[fd66:0:0:10::2]:53: i/o timeout",
		IsTimeout: true,
	}
	msg := resolveError(res, de).Error()
	if strings.Contains(msg, "192.168.100.1") || strings.Contains(msg, " on ") {
		t.Fatalf("message names the system resolver: %q", msg)
	}
	for _, want := range []string{"[fd66:0:0:10::2]:53", "查询超时", "i/o timeout"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
	nf := resolveError(res, &net.DNSError{Name: "x.invalid", Server: "10.0.0.1:53", Err: "no such host", IsNotFound: true}).Error()
	if strings.Contains(nf, "10.0.0.1") || !strings.Contains(nf, "没有这个域名") {
		t.Fatalf("not-found message: %q", nf)
	}
}

// The real Resolve path: whatever the host's resolv.conf says, the error
// names the resolver the query was actually sent to.
func TestPinnedResolveErrorNamesResolver(t *testing.T) {
	// Grab a free UDP port's address on ::1 and close it, so nothing answers.
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	pc.Close()
	p := Pinned{
		Family:   unlock.FamilyIPv4,
		Src6:     netip.MustParseAddr("::1"),
		Resolver: netip.MustParseAddr("::1"),
		Timeout:  300 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = p.Resolve(ctx, "meridian-probe-test.invalid")
	if err == nil {
		t.Skip("something on [::1]:53 answered")
	}
	msg := err.Error()
	if !strings.Contains(msg, "出口解析器 [::1]:53") {
		t.Fatalf("message does not name the exit resolver: %q", msg)
	}
	if strings.Contains(msg, "lookup ") || strings.Contains(msg, " on ") {
		t.Fatalf("message carries Go's nominal-resolver text: %q", msg)
	}
}
