//go:build linux

package compile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
)

// TestExternalExitRealBinaries runs the pinned gost (3.2.6) with exactly the
// redirector configuration the compiler renders for a carrier of an
// external SOCKS exit (only the proxy address and the DNS upstreams are
// pointed at local stubs, and the credential placeholders are replaced the
// way the install boundary does), against a synthetic SOCKS5 server with
// username/password authentication. It checks:
//
//   - transparent TCP: a connection DNATed to the exit's service address
//     reaches the original destination through the proxy (CONNECT names
//     the original address and port), data flows both ways;
//   - the DNS forwarders relay DNS over TCP through the proxy, and the
//     rendered health probe (ext_probe of meridian-ext-health.sh) reports
//     up exactly while that works;
//   - a wrong password: the proxy refuses, the client gets no data;
//   - the proxy down: the client's connection is closed without data and
//     the health probe reports down (fail closed);
//   - the redirector opens no UDP socket;
//   - with MERIDIAN_SMARTDNS_BIN also set: the carrier's resolver group for
//     the exit answers through the proxy, and when the proxy is down the
//     name fails: never an answer from the carrier's own default servers.
//
// Needs root (it puts the service address on lo and adds a DNAT in a
// private nft table) and nft. Opt-in:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
//	docker run --rm --privileged --network none -v /tmp/compile.test:/compile.test:ro \
//	  -v <gost>:/gost:ro -v <smartdns>:/smartdns:ro debian:13 sh -c \
//	  'apt-get install -y nftables iproute2 >/dev/null; MERIDIAN_GOST_BIN=/gost MERIDIAN_SMARTDNS_BIN=/smartdns /compile.test -test.run TestExternalExitRealBinaries -test.v'
func TestExternalExitRealBinaries(t *testing.T) {
	bin := os.Getenv("MERIDIAN_GOST_BIN")
	if bin == "" {
		t.Skip("MERIDIAN_GOST_BIN not set (path to the pinned gost 3.2.6)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root (service address on lo, nft DNAT)")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command(bin, "-V").CombinedOutput(); err != nil {
		t.Fatalf("%s -V: %v %s", bin, err, out)
	} else {
		t.Logf("binary: %s", strings.TrimSpace(string(out)))
	}

	topo := defaults.ExternalExample()
	exits, _ := plans(t, topo)
	var ext ExitPlan
	for _, e := range exits {
		if e.External {
			ext = e
		}
	}
	if ext.ExtService == "" {
		t.Fatal("no external exit in the example")
	}
	b := mustCompile(t, topo)
	conf := b.File("nodes/dc2" + ExtProxyConfig)
	health := b.File("nodes/dc2" + ExtHealthScript)

	// Local stand-ins: a TCP echo service (the "internet" destination), a
	// DNS-over-TCP resolver (stands in for 1.1.1.1 / 8.8.8.8), the proxy.
	echo := startTCPEcho(t)
	dnsTCP := startTCPDNS(t)
	const user, pass = "meridian-test", "Pa55-word.x"
	newProxy := func(t *testing.T) *socksStub {
		return startSOCKS5(t, user, pass, map[string]string{
			ExtUpstream1 + ":53": dnsTCP,
			ExtUpstream2 + ":53": dnsTCP,
			"198.51.100.7:80":    echo,
		})
	}

	run(t, "ip", "addr", "replace", ext.ExtService+"/32", "dev", "lo")
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", ext.ExtService+"/32", "dev", "lo").Run() })
	// The "internet" destination needs a route for the first lookup (the
	// container has no default route); the DNAT then re-routes locally.
	run(t, "ip", "route", "replace", "198.51.100.7/32", "dev", "lo")
	t.Cleanup(func() { _ = exec.Command("ip", "route", "del", "198.51.100.7/32", "dev", "lo").Run() })
	// Locally originated connections to 198.51.100.7:80 are DNATed to the
	// redirector, the same as the carrier's ext_dnat does for the exit's
	// transit source (output hook here: the client is on this host).
	nft := fmt.Sprintf(`table ip meridian_test_ext {
  chain out { type nat hook output priority -100; policy accept;
    ip daddr 198.51.100.7 tcp dport 80 dnat to %s:%d
  }
}
`, ext.ExtService, ExtRedirPort)
	runIn(t, nft, "nft", "-f", "-")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip", "meridian_test_ext").Run() })

	lab := func(proxy *socksStub, password string) string {
		c := strings.ReplaceAll(conf, "192.0.2.66:1080", proxy.addr)
		c = strings.ReplaceAll(c, "__MERIDIAN_SECRET_socks-example1-user__", user)
		c = strings.ReplaceAll(c, "__MERIDIAN_SECRET_socks-example1-pass__", password)
		return c
	}

	t.Run("relay", func(t *testing.T) {
		proxy := newProxy(t)
		g := startGost(t, bin, lab(proxy, pass))
		got := tcpRoundTrip(t, "198.51.100.7:80", "hello through the proxy")
		if got != "hello through the proxy" {
			t.Fatalf("echo through the redirector: %q", got)
		}
		if !proxy.saw("198.51.100.7:80") {
			t.Fatalf("CONNECT targets %v: the original destination never reached the proxy", proxy.targets())
		}
		if !healthProbe(t, health, ext.ExtService, ExtDNSPort1) || !healthProbe(t, health, ext.ExtService, ExtDNSPort2) {
			t.Fatal("health probe down although the proxy relays DNS over TCP")
		}
		if !proxy.saw(ExtUpstream1+":53") || !proxy.saw(ExtUpstream2+":53") {
			t.Fatalf("CONNECT targets %v: DNS forwarders did not go through the proxy", proxy.targets())
		}
		if udp := g.udpSockets(t); udp != "" {
			t.Fatalf("the redirector opened UDP sockets:\n%s", udp)
		}
		if sbin := os.Getenv("MERIDIAN_SMARTDNS_BIN"); sbin != "" {
			testCarrierResolver(t, sbin, b.File("nodes/dc2/etc/smartdns/smartdns.conf"), proxy)
		} else {
			t.Log("MERIDIAN_SMARTDNS_BIN not set: carrier resolver group not exercised")
		}
	})
	t.Run("wrong-password", func(t *testing.T) {
		proxy := newProxy(t)
		startGost(t, bin, lab(proxy, "wrong-"+pass))
		if got := tcpRoundTrip(t, "198.51.100.7:80", "must not pass"); got != "" {
			t.Fatalf("data with a refused credential: %q", got)
		}
		if proxy.authFailures() == 0 {
			t.Fatal("the proxy saw no failed authentication")
		}
		if healthProbe(t, health, ext.ExtService, ExtDNSPort1) {
			t.Fatal("health probe up with a refused credential")
		}
		if proxy.saw("198.51.100.7:80") {
			t.Fatal("a CONNECT got through with a refused credential")
		}
	})
	t.Run("proxy-down", func(t *testing.T) {
		proxy := newProxy(t)
		startGost(t, bin, lab(proxy, pass))
		proxy.stop()
		if got := tcpRoundTrip(t, "198.51.100.7:80", "must not pass"); got != "" {
			t.Fatalf("data with the proxy down: %q", got)
		}
		if healthProbe(t, health, ext.ExtService, ExtDNSPort1) {
			t.Fatal("health probe up with the proxy down")
		}
	})
	t.Run("redirector-down", func(t *testing.T) {
		// No redirector at all: the DNAT target refuses (fail closed, fast).
		start := time.Now()
		if got := tcpRoundTrip(t, "198.51.100.7:80", "must not pass"); got != "" {
			t.Fatalf("data without a redirector: %q", got)
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("no fast failure without the redirector (%v)", time.Since(start))
		}
	})
}

// testCarrierResolver: the exit's resolver group on the carrier answers
// through the proxy; with the proxy down the name fails and the carrier's
// own default servers (a stub that would answer) are never used for it.
func testCarrierResolver(t *testing.T, bin, conf string, proxy *socksStub) {
	own := startDNSStub(t)
	own.set("ready.example.net", stubAnswer{A: []string{"192.0.2.99"}})
	own.set("ext.example.net", stubAnswer{A: []string{"192.0.2.98"}})
	own.set("ext-down.example.net", stubAnswer{A: []string{"192.0.2.98"}})
	extPort := freeUDPPort(t)
	ownPort := freeUDPPort(t)
	logPath := filepath.Join(t.TempDir(), "smartdns.log")
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("smartdns log:\n%s", b)
		}
	})
	out := []string{"log-level info", "log-file " + logPath, fmt.Sprintf("bind 127.0.0.2:%d", ownPort)}
	var extBind string
	for _, l := range strings.Split(conf, "\n") {
		switch {
		case strings.HasPrefix(l, "bind ") && strings.Contains(l, " -group ext_"):
			extBind = fmt.Sprintf("bind 127.0.0.1:%d%s", extPort, l[strings.Index(l, " -group"):])
			continue
		case strings.HasPrefix(l, "bind"):
			continue
		case l == "server 1.1.1.1" || l == "server 8.8.8.8":
			l = "server " + own.addr
		}
		out = append(out, l)
	}
	if extBind == "" {
		t.Fatal("no resolver group listener for the external exit in the carrier's config")
	}
	// startSmartDNS asks the last "bind" line: the exit's listener.
	out = append(out, extBind)
	sd := startSmartDNS(t, bin, strings.Join(out, "\n")+"\n")
	if !strings.HasSuffix(sd.addr, fmt.Sprintf(":%d", extPort)) {
		t.Fatalf("lab config: smartdns probed %s, not the exit listener", sd.addr)
	}
	sd.expect(t, "ext.example.net", qA, "203.0.113.77")
	sd.expect(t, "ext.example.net", qAAAA) // the exit is IPv4 only: no AAAA
	// The carrier's own listener uses its own servers (control).
	ownRun := &smartDNSRun{addr: fmt.Sprintf("127.0.0.2:%d", ownPort)}
	ownRun.expect(t, "ext.example.net", qA, "192.0.2.98")
	proxy.stop()
	sd.expectFail(t, "ext-down.example.net", qA, "192.0.2.98")
}

// healthProbe runs ext_probe from the rendered health script.
func healthProbe(t *testing.T, script, addr string, port int) bool {
	t.Helper()
	i := strings.Index(script, "ext_probe() {")
	j := strings.Index(script[i:], "\n}\n")
	if i < 0 || j < 0 {
		t.Fatal("ext_probe not found in the health script")
	}
	fn := script[i : i+j+3]
	cmd := exec.Command("bash", "-c", "TIMEOUT=5\n"+fn+"ext_probe \"$1\" \"$2\"", "probe", addr, strconv.Itoa(port))
	err := cmd.Run()
	t.Logf("health probe %s:%d -> %v", addr, port, err == nil)
	return err == nil
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, out)
	}
}

func runIn(t *testing.T, stdin, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v %s\n%s", name, args, err, out, stdin)
	}
}

func tcpRoundTrip(t *testing.T, addr, msg string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Logf("dial %s: %v", addr, err)
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return ""
	}
	buf := make([]byte, len(msg))
	n, err := io.ReadFull(c, buf)
	t.Logf("round trip %s: %d bytes, %v", addr, n, err)
	return string(buf[:n])
}

type gostRun struct {
	cmd *exec.Cmd
}

func startGost(t *testing.T, bin, conf string) *gostRun {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "gost.yaml")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-C", p)
	var logb bytes.Buffer
	var mu sync.Mutex
	cmd.Stdout = lockedWriter{&mu, &logb}
	cmd.Stderr = lockedWriter{&mu, &logb}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		if t.Failed() {
			mu.Lock()
			t.Logf("gost output:\n%s", logb.String())
			mu.Unlock()
		}
	})
	// Ready when the redirector port accepts connections.
	addr := ""
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "  addr: \"") && strings.HasSuffix(l, fmt.Sprintf(":%d\"", ExtRedirPort)) {
			addr = strings.Trim(strings.TrimPrefix(l, "  addr: "), "\"")
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-exited:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("gost exited: %v\n%s", err, logb.String())
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return &gostRun{cmd: cmd}
		}
		if time.Now().After(deadline) {
			t.Fatalf("gost does not listen on %s", addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// udpSockets lists the UDP sockets the process holds (from /proc).
func (g *gostRun) udpSockets(t *testing.T) string {
	inodes := map[string]bool{}
	fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", g.cmd.Process.Pid))
	for _, fd := range fds {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", g.cmd.Process.Pid, fd.Name())); err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	var out []string
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fs := strings.Fields(line)
			if len(fs) > 9 && inodes[fs[9]] {
				out = append(out, line)
			}
		}
	}
	return strings.Join(out, "\n")
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// startTCPDNS answers DNS over TCP: the root NS query of the health probe
// (an empty NOERROR answer), ready/ext names with 203.0.113.77, AAAA empty.
func startTCPDNS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					name, qt, end, ok := dnsQuestion(q)
					if !ok {
						return
					}
					a := stubAnswer{}
					if name != "" && qt == qA {
						a.A = []string{"203.0.113.77"}
					}
					r := dnsReply(q, end, qt, a)
					var out [2]byte
					binary.BigEndian.PutUint16(out[:], uint16(len(r)))
					if _, err := c.Write(append(out[:], r...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// socksStub is a minimal SOCKS5 server (RFC 1928, username/password RFC
// 1929, CONNECT only). Targets are relayed to the address the map names
// (the test's stand-ins), anything else is refused.
type socksStub struct {
	addr   string
	ln     net.Listener
	mu     sync.Mutex
	seen   []string
	fails  int
	closed bool
	conns  []net.Conn
}

func startSOCKS5(t *testing.T, user, pass string, targets map[string]string) *socksStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksStub{addr: ln.Addr().String(), ln: ln}
	t.Cleanup(s.stop)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, user, pass, targets)
		}
	}()
	return s
}

func (s *socksStub) serve(c net.Conn, user, pass string, targets map[string]string) {
	defer c.Close()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.conns = append(s.conns, c)
	s.mu.Unlock()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil || !bytes.Contains(methods, []byte{2}) {
		_, _ = c.Write([]byte{5, 0xff})
		return
	}
	_, _ = c.Write([]byte{5, 2})
	v := make([]byte, 2)
	if _, err := io.ReadFull(c, v); err != nil || v[0] != 1 {
		return
	}
	u := make([]byte, v[1])
	_, _ = io.ReadFull(c, u)
	pl := make([]byte, 1)
	_, _ = io.ReadFull(c, pl)
	p := make([]byte, pl[0])
	_, _ = io.ReadFull(c, p)
	if string(u) != user || string(p) != pass {
		s.mu.Lock()
		s.fails++
		s.mu.Unlock()
		_, _ = c.Write([]byte{1, 1})
		return
	}
	_, _ = c.Write([]byte{1, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		a := make([]byte, 4)
		_, _ = io.ReadFull(c, a)
		host = net.IP(a).String()
	case 3:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		d := make([]byte, l[0])
		_, _ = io.ReadFull(c, d)
		host = string(d)
	default:
		return
	}
	pb := make([]byte, 2)
	_, _ = io.ReadFull(c, pb)
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	s.mu.Lock()
	s.seen = append(s.seen, target)
	s.mu.Unlock()
	dst, ok := targets[target]
	if !ok {
		_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", dst, 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (s *socksStub) saw(target string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.seen {
		if x == target {
			return true
		}
	}
	return false
}

func (s *socksStub) targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func (s *socksStub) authFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fails
}

func (s *socksStub) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		_ = s.ln.Close()
		// A proxy that goes down takes its relayed connections with it.
		for _, c := range s.conns {
			_ = c.Close()
		}
	}
}
