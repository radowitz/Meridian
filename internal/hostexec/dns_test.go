package hostexec

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func goodDNSCheck() DNSCheckRequest {
	return DNSCheckRequest{RequestID: "dns-1", ExitID: "hk-resi", Resolver: "fd66::54:3"}
}

// The check takes an exit id and a tunnel resolver address only, and only
// an address the installed gateway SmartDNS forwards to; the question is
// fixed. A silent resolver ends with "timeout" within DNSCheckTimeout.
func TestDNSCheckIsFixed(t *testing.T) {
	if err := ValidateDNSCheck(goodDNSCheck()); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*DNSCheckRequest){
		"public resolver":  func(r *DNSCheckRequest) { r.Resolver = "192.0.2.53" },
		"lan":              func(r *DNSCheckRequest) { r.Resolver = "192.168.1.1" },
		"transit":          func(r *DNSCheckRequest) { r.Resolver = "fd66:0:0:ff::3" },
		"other ula":        func(r *DNSCheckRequest) { r.Resolver = "fd00::1" },
		"zone":             func(r *DNSCheckRequest) { r.Resolver = "fd66::54:3%eth0" },
		"exit id":          func(r *DNSCheckRequest) { r.ExitID = "../x" },
		"request id":       func(r *DNSCheckRequest) { r.RequestID = "a b" },
		"resolver w/ port": func(r *DNSCheckRequest) { r.Resolver = "[fd66::54:3]:5353" },
	} {
		r := goodDNSCheck()
		f(&r)
		if ValidateDNSCheck(r) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(conf, []byte("server-tls 223.5.5.5:853 -group domestic -exclude-default-group\nserver fd66::54:3 -group e_hk_resi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	mode := "answer"
	a := &Agent{Token: func() (string, error) { return "x", nil }, SmartDNSConf: conf,
		DNSCheckExchange: func(ctx context.Context, server string, mark uint32, q []byte) ([]byte, error) {
			mu.Lock()
			asked = append(asked, server)
			m := mode
			mu.Unlock()
			if mark != 0 {
				t.Errorf("mark %#x", mark)
			}
			if m == "silent" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			r := append([]byte(nil), q...)
			r[2] |= 0x80
			if m == "servfail" {
				r[3] = 0x82
			} else {
				r[3] = 0x80
				r[7] = 1 // one answer (count only: not parsed)
			}
			return r, nil
		}}
	res, code := a.DNSCheck(context.Background(), goodDNSCheck())
	if code != http.StatusOK || res.Outcome != "answer" || res.Answers != 1 || res.Name != DNSCheckName || res.QType != "A" {
		t.Fatalf("%d %+v", code, res)
	}
	if len(asked) != 1 || asked[0] != "[fd66::54:3]:53" {
		t.Fatalf("asked %v", asked)
	}
	mode = "servfail"
	if res, _ = a.DNSCheck(context.Background(), goodDNSCheck()); res.Outcome != "rcode" || res.Rcode != 2 {
		t.Fatalf("%+v", res)
	}
	// Not in the installed config: nothing is sent.
	r := goodDNSCheck()
	r.Resolver = "fd66::54:9"
	if res, code = a.DNSCheck(context.Background(), r); code != http.StatusOK || res.Outcome != "not_allowed" || len(asked) != 2 {
		t.Fatalf("%d %+v %v", code, res, asked)
	}
	a.SmartDNSConf = filepath.Join(dir, "missing.conf")
	if res, _ = a.DNSCheck(context.Background(), goodDNSCheck()); res.Outcome != "not_allowed" || len(asked) != 2 {
		t.Fatalf("missing conf: %+v", res)
	}
	a.SmartDNSConf = conf
	if res, code = a.DNSCheck(context.Background(), DNSCheckRequest{RequestID: "x", ExitID: "hk", Resolver: "8.8.8.8"}); code != http.StatusBadRequest || !strings.Contains(res.Error, "fd66") {
		t.Fatalf("%d %+v", code, res)
	}
	mode = "silent"
	start := time.Now()
	res, _ = a.DNSCheck(context.Background(), goodDNSCheck())
	if res.Outcome != "timeout" || time.Since(start) > DNSCheckTimeout+time.Second {
		t.Fatalf("%+v after %v", res, time.Since(start))
	}
	// While an install runs, no check starts.
	a.beginAction()
	if _, code = a.DNSCheck(context.Background(), goodDNSCheck()); code != http.StatusServiceUnavailable {
		t.Fatalf("during an action: %d", code)
	}
	a.endAction()
}
