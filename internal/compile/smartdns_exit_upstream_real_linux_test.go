//go:build linux

package compile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// TestSmartDNSRealExitUpstream runs the pinned SmartDNS (1.2026.08.05-0921,
// Release48.4) with the exit upstream lines this compiler renders
// (writeExitUpstream: server-tls / server-https, -host-name, -http-host,
// -tls-host-verify, ca-file) against local DoT and DoH stubs with
// certificates of a test CA, on loopback only. Edits: the upstream address
// is 127.0.0.1 and the stub's port (validation refuses loopback for a real
// upstream), ca-file is the test CA, the account placeholder is replaced
// the way the install does. A plain "ready" group answers the start-up
// probe. It checks:
//
//   - the directives are accepted and a name resolves through the DoT and
//     the DoH stub when the certificate carries the verified name (exact,
//     and a wildcard certificate for the account label);
//   - DoH asks the configured path (the account segment) with the
//     configured HTTP host;
//   - a certificate for another name fails (no answer, nothing else asked);
//   - a certificate from a CA that is not in ca-file fails.
//
// Opt-in; skipped unless MERIDIAN_SMARTDNS_BIN names the binary (as
// TestSmartDNSRealBinary):
//
//	MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
//	  go test ./internal/compile -run TestSmartDNSRealExitUpstream -v
func TestSmartDNSRealExitUpstream(t *testing.T) {
	bin := os.Getenv("MERIDIAN_SMARTDNS_BIN")
	if bin == "" {
		t.Skip("MERIDIAN_SMARTDNS_BIN not set (path to the pinned SmartDNS 1.2026.08.05-0921)")
	}
	if out, err := exec.Command(bin, "-v").CombinedOutput(); err != nil {
		t.Fatalf("%s -v: %v %s", bin, err, out)
	}
	dir := t.TempDir()
	ca, caKey, caPEM := testCA(t, "meridian test CA")
	_, _, otherPEM := testCA(t, "other CA")
	caFile := filepath.Join(dir, "ca.pem")
	otherFile := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(caFile, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherFile, otherPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	const acct = "acct1"
	ready := startDNSStub(t)
	ready.set("ready.example.net", stubAnswer{A: []string{"192.0.2.99"}})

	for _, c := range []struct {
		name, proto string
		certNames   []string
		caFile      string
		ok          bool
	}{
		{"dot exact name", model.ExitDNSDoT, []string{acct + ".dns.example.net"}, caFile, true},
		{"dot wildcard certificate", model.ExitDNSDoT, []string{"*.dns.example.net"}, caFile, true},
		{"dot other name", model.ExitDNSDoT, []string{"other.example.org"}, caFile, false},
		{"dot untrusted CA", model.ExitDNSDoT, []string{acct + ".dns.example.net"}, otherFile, false},
		{"doh exact name", model.ExitDNSDoH, []string{"dns.example.net"}, caFile, true},
		{"doh other name", model.ExitDNSDoH, []string{"other.example.org"}, caFile, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cert := testLeaf(t, ca, caKey, c.certNames)
			var port int
			var asked *atomic.Int64
			u := model.ExitDNSUpstream{Protocol: c.proto, Addresses: []string{"127.0.0.1"}, AccountCredential: "dnsacct-0a1b2c3d4e5f"}
			if c.proto == model.ExitDNSDoT {
				u.TLSHostName = "{account}.dns.example.net"
				port, asked = startDoTStub(t, cert)
			} else {
				u.TLSHostName, u.Path = "dns.example.net", "/{account}"
				port, asked = startDoHStub(t, cert, "/"+acct, "dns.example.net")
			}
			u.Port = port
			var sb strings.Builder
			writeExitUpstream(&sb, u)
			up := strings.ReplaceAll(sb.String(), model.SecretPlaceholder(u.AccountCredential), acct)
			up = strings.Replace(up, "ca-file "+ExitDNSCAFile, "ca-file "+c.caFile, 1)
			lp := freeUDPPort(t)
			conf := fmt.Sprintf("bind 127.0.0.1:%d\nbind-tcp 127.0.0.1:%d\nspeed-check-mode none\ncache-persist no\nlog-level debug\n"+
				"server %s -group ready -exclude-default-group\ndomain-rules /ready.example.net/ -nameserver ready\n%s", lp, lp, ready.addr, up)
			sd := startSmartDNS(t, bin, conf)
			name := "probe-" + strings.ReplaceAll(c.name, " ", "-") + ".example.net"
			if c.ok {
				sd.expect(t, name, qA, "192.0.2.1")
				if asked.Load() == 0 {
					t.Fatal("the stub was not asked")
				}
				return
			}
			sd.expectFail(t, name, qA, "192.0.2.1")
			if n := asked.Load(); n != 0 {
				t.Fatalf("%d queries reached a stub whose certificate must have been refused", n)
			}
		})
	}
}

func testCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// stubReply answers every A question with 192.0.2.1.
func stubReply(q []byte) ([]byte, bool) {
	_, qt, end, ok := dnsQuestion(q)
	if !ok {
		return nil, false
	}
	return dnsReply(q, end, qt, stubAnswer{A: []string{"192.0.2.1"}}), true
}

// startDoTStub: DNS over TLS (RFC 7858) on loopback; asked counts the
// queries that arrived after a completed handshake.
func startDoTStub(t *testing.T, cert tls.Certificate) (int, *atomic.Int64) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var asked atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					var lb [2]byte
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(lb[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					asked.Add(1)
					r, ok := stubReply(q)
					if !ok {
						return
					}
					_, _ = c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
				}
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, &asked
}

// startDoHStub: DNS over HTTPS (RFC 8484, GET and POST) answering only on
// path with Host host.
func startDoHStub(t *testing.T, cert tls.Certificate, path, host string) (int, *atomic.Int64) {
	t.Helper()
	var asked atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || strings.Split(r.Host, ":")[0] != host {
			http.NotFound(w, r)
			return
		}
		var q []byte
		var err error
		if r.Method == http.MethodPost {
			q, err = io.ReadAll(io.LimitReader(r.Body, 4096))
		} else {
			q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		}
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		asked.Add(1)
		resp, ok := stubReply(q)
		if !ok {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	t.Cleanup(func() { srv.Close() })
	return l.Addr().(*net.TCPAddr).Port, &asked
}
