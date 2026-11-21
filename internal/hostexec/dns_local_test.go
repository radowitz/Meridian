package hostexec

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

func TestDNSLocalAppliesHostsAndFlushesCache(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	a.PreflightRoot = t.TempDir()
	cfg := a.hostPath("/etc/smartdns/smartdns.conf")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	config := "# Meridian SmartDNS.\ncache-persist no\n" + model.DNSHostsInclude + "\n"
	if err := os.WriteFile(cfg, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(action string, record DNSHost, code int) DNSLocalResult {
		t.Helper()
		res, status := a.dnsLocal(context.Background(), DNSLocalRequest{Action: action, Host: record})
		if status != code {
			t.Fatalf("%s returned %d, want %d: %+v", action, status, code, res)
		}
		return res
	}
	rec := DNSHost{Name: "NAS.Example.", IP: "192.0.2.5"}
	if state := run("status", DNSHost{}, 200); !state.CacheEnabled || !state.HostsEnabled || len(state.Hosts) != 0 {
		t.Fatalf("unexpected readiness: %+v", state)
	}
	run("add", DNSHost{Name: "bad/name", IP: "192.0.2.1"}, http.StatusBadRequest)
	run("add", rec, 200)
	run("add", rec, 200)
	run("add", DNSHost{Name: "nas.example", IP: "2001:db8::5"}, 200)
	before, err := os.ReadFile(a.hostPath(dnsHostsFile))
	if err != nil || string(before) != "address /-.nas.example/192.0.2.5,2001:db8::5\n" {
		t.Fatalf("unexpected resolver file: %q, %v", before, err)
	}
	run("flush", DNSHost{}, 200)
	if state := run("delete", rec, 200); len(state.Hosts) != 1 || state.Hosts[0].IP != "2001:db8::5" {
		t.Fatalf("unexpected deletion: %+v", state)
	}
	if n := f.ran("systemctl restart smartdns.service"); n != 4 {
		t.Fatalf("want 4 restarts, got %d: %v", n, f.commands())
	}
	a.DNSLivenessWait = time.Millisecond
	a.DNSCheckExchange = func(ctx context.Context, addr string, mark uint32, q []byte) ([]byte, error) {
		conf, readErr := os.ReadFile(a.hostPath(dnsHostsFile))
		if readErr != nil || string(conf) != "address /-.nas.example/2001:db8::5\n" {
			return nil, errors.New("resolver failed with changed hosts")
		}
		return answeringResolver(ctx, addr, mark, q)
	}
	run("add", rec, http.StatusServiceUnavailable)
	if state := run("status", DNSHost{}, 200); len(state.Hosts) != 1 || state.Hosts[0].IP != "2001:db8::5" {
		t.Fatalf("previous state was not restored: %+v", state)
	}
}
