//go:build linux

package compile_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
)

// TestWstunnelRealBinary runs the pinned wstunnel (11.1.0) with exactly the
// arguments and environment the units render, on loopback only:
//
//	MERIDIAN_WSTUNNEL_BIN=/usr/local/sbin/meridian-wstunnel \
//	  go test ./internal/compile -run TestWstunnelRealBinary -v
//
// (or the image's /usr/share/meridian/artifacts/wstunnel-x86_64). It checks
// that a UDP datagram crosses the carrier with the right certificate, name
// and prefix, and does not with another listener's certificate, another
// name or another prefix; a control run without --tls-verify-certificate
// shows the certificate check is what refuses. Without the variable the
// test is skipped.
func TestWstunnelRealBinary(t *testing.T) {
	bin := os.Getenv("MERIDIAN_WSTUNNEL_BIN")
	if bin == "" {
		t.Skip("MERIDIAN_WSTUNNEL_BIN not set (path to the pinned wstunnel 11.1.0)")
	}
	r := resolveFresh(t, defaults.Example())
	hub := r.host(t, "hk-hub")
	gw := r.host(t, "gw")
	dir := t.TempDir()

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], a)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	// The rendered restrictions, with the gw-hub-wss rule pointed at the
	// echo server (the rule structure is the rendered one).
	yaml := hub["/etc/meridian/wss/server.yaml"]
	var gwRule prefixRule
	for _, x := range parseRules(t, yaml) {
		if x.link == "gw-hub-wss" {
			gwRule = x
		}
	}
	yaml = strings.Replace(yaml, `- "`+gwRule.port+`"`, `- "`+strconv.Itoa(echoPort)+`"`, 1)
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	yamlP := write("server.yaml", yaml, 0o600)
	certP := write("server.crt", hub["/etc/meridian/wss/server.crt"], 0o644)
	keyP := write("server.key", hub["/etc/meridian/wss/server.key"], 0o600)
	trustP := write("trust.pem", gw["/etc/meridian/wss/client-gw-hub-wss.trust.pem"], 0o644)
	otherTrustP := write("other.pem", gw["/etc/meridian/wss/client-gw-ali.trust.pem"], 0o644)
	// A rotation's overlap trust file: two roots, either is accepted.
	bothP := write("both.pem", gw["/etc/meridian/wss/client-gw-ali.trust.pem"]+gw["/etc/meridian/wss/client-gw-hub-wss.trust.pem"], 0o644)
	env := gw["/etc/meridian/wss/client-gw-hub-wss.env"]
	path := envValue(env, "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX")
	sni := envValue(env, "MERIDIAN_WSS_SNI")

	srvPort := freePort(t, "tcp")
	srvLog := start(t, bin, compile.WstunnelServerArgs(yamlP, certP, keyP, "127.0.0.1:"+strconv.Itoa(srvPort)), nil)
	waitTCP(t, srvPort)

	type tc struct {
		name   string
		trust  string
		sni    string
		path   string
		verify bool
		want   bool
		// marker: what the server logs for this refusal (wstunnel's client
		// retries silently; the reason is in the server's journal).
		marker string
	}
	otherPath, _ := credentials.GenerateWSSPath()
	cases := []tc{
		{"accept", trustP, sni, path, true, true, ""},
		{"wrong certificate (another listener's trust file)", otherTrustP, sni, path, true, false, "received fatal alert: UnknownCA"},
		{"wrong name", trustP, "w0000000000000000.invalid", path, true, false, "received fatal alert: BadCertificate"},
		{"wrong path", trustP, sni, otherPath, true, false, "Rejecting connection with not allowed destination"},
		{"old fixed path", trustP, sni, credentials.LegacyWSSDefaultPath, true, false, "Rejecting connection with not allowed destination"},
		{"control: wrong certificate without verification connects", otherTrustP, sni, path, false, true, ""},
		{"overlap trust file (rotation stage 1/2)", bothP, sni, path, true, true, ""},
		{"accept again", trustP, sni, path, true, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local := freePort(t, "udp")
			args := compile.WstunnelClientArgs(local, echoPort, c.sni, "127.0.0.1", srvPort)
			if !c.verify {
				var a []string
				for _, x := range args {
					if x != "--tls-verify-certificate" {
						a = append(a, x)
					}
				}
				args = a
			}
			envv := append(compile.WstunnelClientEnv(c.trust), "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX="+c.path)
			mark := len(srvLog.String())
			cl := start(t, bin, args, envv)
			got := udpRoundTrip(t, local, 4*time.Second)
			if got != c.want {
				t.Fatalf("datagram crossed=%v, want %v\nclient log:\n%s\nserver log:\n%s", got, c.want, cl.String(), srvLog.String())
			}
			if c.marker != "" && !strings.Contains(srvLog.String()[mark:], c.marker) {
				t.Fatalf("server log lacks %q:\n%s", c.marker, srvLog.String()[mark:])
			}
			t.Logf("client log tail: %s", tail(cl.String(), 300))
		})
	}

	// What an active prober sees for any other request (no upgrade, or an
	// upgrade with another prefix): the server's own plain HTTP answer.
	cli := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // probing as an outsider
	for _, p := range []string{"/", "/" + otherPath + "/events"} {
		resp, err := cli.Get("https://127.0.0.1:" + strconv.Itoa(srvPort) + p)
		if err != nil {
			t.Fatalf("probe %s: %v", p, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		t.Logf("probe GET %s → %d %q (server %q)", p, resp.StatusCode, body, resp.Header.Get("Server"))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("probe %s: status %d", p, resp.StatusCode)
		}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func start(t *testing.T, bin string, args, env []string) *syncBuf {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	// A clean environment: nothing inherited (no SSL_CERT_DIR, no proxy).
	lvl := os.Getenv("MERIDIAN_WSTUNNEL_LOG")
	if lvl == "" {
		lvl = "info"
	}
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "RUST_LOG=" + lvl, "NO_COLOR=true"}, env...)
	out := &syncBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	return out
}

func freePort(t *testing.T, proto string) int {
	t.Helper()
	if proto == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("wstunnel server did not listen")
}

// udpRoundTrip sends datagrams to the client's local port until one comes
// back or the time is up.
func udpRoundTrip(t *testing.T, local int, d time.Duration) bool {
	t.Helper()
	c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(local))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(d)
	buf := make([]byte, 64)
	for time.Now().Before(deadline) {
		_, _ = c.Write([]byte("meridian-wss-probe"))
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, err := c.Read(buf); err == nil && string(buf[:n]) == "meridian-wss-probe" {
			return true
		}
	}
	return false
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
