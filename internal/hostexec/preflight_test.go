package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/radowitz/meridian/internal/preflight"
)

// pfRunner answers the pre-check's fixed commands and records every call.
type pfRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
}

func (p *pfRunner) Run(_ context.Context, prog string, args ...string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	line := prog + " " + strings.Join(args, " ")
	p.calls = append(p.calls, line)
	return p.out[line], nil
}

func pfRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":                  "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n",
		"proc/meminfo":                    "MemTotal:        2015040 kB\nMemAvailable:    1650220 kB\n",
		"proc/sys/kernel/osrelease":       "6.12.12-amd64\n",
		"proc/sys/net/ipv4/ip_forward":    "1\n",
		"etc/wireguard/m02.conf":          "# meridian link gw-hub\n[Interface]\nPrivateKey = SECRETSECRETSECRETSECRETSECRETSECRETSECRE=\n",
		"etc/smartdns/smartdns.conf":      "bind :53\nserver 192.0.2.53\n",
		"etc/iproute2/rt_tables.d/x.conf": "150 vpn\n",
		"usr/sbin/nft":                    "#!/bin/sh\n",
		"usr/bin/docker":                  "#!/bin/sh\n",
	}
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAgentPreflightReport(t *testing.T) {
	run := &pfRunner{out: map[string]string{
		"iptables -w 5 -S FORWARD": "-P FORWARD DROP\n-N DOCKER\n",
		"ip -o link show":          "1: lo: <LOOPBACK,UP>\n2: eth0: <UP>\n3: veth1@if4: <UP>\n",
		"ip -o addr show":          "2: eth0    inet 192.168.100.88/24 brd 192.168.100.255 scope global eth0\n",
		"ss -Hlntup":               "tcp LISTEN 0 4096 192.168.100.88:8787 0.0.0.0:* users:((\"meridian\",pid=10,fd=3))\n",
		"ss -Hlntu --cgroup":       "udp UNCONN 0 0 *:53 *:* cgroup:/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope\n",
		"docker inspect --format {{.Id}} {{.State.Running}} meridian-smartdns": strings.Repeat("ab", 32) + " true\n",
		"nft list chains":                                     "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n",
		"systemctl is-active docker.service":                  "active\n",
		"systemctl show -p ExecStop --value nftables.service": "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush ruleset ; ignore_errors=no }\n",
	}}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: run, PreflightRoot: pfRoot(t)}
	res := a.Preflight(context.Background(), PreflightRequest{Paths: []string{"/etc/wireguard/m02.conf", "/etc/smartdns/smartdns.conf", "/etc/meridian/forwarding.conf"}})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if strings.Contains(res.Report, "SECRETSECRET") || strings.Contains(res.Report, "server 192.0.2.53") {
		t.Fatal("file content in the report")
	}
	r := preflight.Parse(res.Report)
	if !r.Complete || r.OSID != "debian" || r.OSVersion != "13" || r.Systemd != "yes" || r.MemAvailKB != 1650220 || !r.Commands["nft"] || r.Commands["wg"] {
		t.Fatalf("report %+v\n%s", r, res.Report)
	}
	if pi := r.Paths["/etc/wireguard/m02.conf"]; !pi.Exists || !pi.Marker || len(pi.SHA256) != 64 {
		t.Fatalf("m02 %+v", pi)
	}
	if pi := r.Paths["/etc/smartdns/smartdns.conf"]; !pi.Exists || pi.Marker {
		t.Fatalf("smartdns %+v", pi)
	}
	if pi := r.Paths["/etc/meridian/forwarding.conf"]; pi.Exists {
		t.Fatalf("forwarding %+v", pi)
	}
	if r.NFTStop != "flush" {
		t.Fatalf("nftables.service ExecStop flush not reported: %q", r.NFTStop)
	}
	if len(r.Policies) != 1 || r.Policies[0].Policy != "DROP" || len(r.Chains) != 1 || r.Chains[0].Policy != "drop" {
		t.Fatalf("firewall %+v %+v", r.Policies, r.Chains)
	}
	if c := r.Containers["meridian-smartdns"]; c.ID != strings.Repeat("ab", 32) || !c.Running || preflight.GatewayDNSContainer != SmartDNSContainer {
		t.Fatalf("container %+v", r.Containers)
	}
	var dns *preflight.Listener
	for i := range r.Listeners {
		if r.Listeners[i].Port == 53 {
			dns = &r.Listeners[i]
		}
	}
	if dns == nil || preflight.CgroupContainer(dns.Cgroup) != strings.Repeat("ab", 32) {
		t.Fatalf("listeners %+v", r.Listeners)
	}
	if r.RTNames[150] != "vpn" || !containsStr(r.Links, "veth1") || r.Units["docker.service"].Active != "active" {
		t.Fatalf("links %v rt %v units %v", r.Links, r.RTNames, r.Units)
	}
	// Only fixed, read-only invocations.
	for _, c := range run.calls {
		f := strings.Fields(c)
		ok := false
		switch f[0] {
		case "ip":
			ok = strings.Contains(c, " show")
		case "nft":
			ok = c == "nft list chains"
		case "ss":
			ok = c == "ss -Hlntup" || c == "ss -Hlntu --cgroup"
		case "iptables", "ip6tables":
			ok = c == f[0]+" -V" || strings.HasPrefix(c, f[0]+" -w 5 -S ")
		case "systemctl":
			ok = f[1] == "is-active" || f[1] == "is-enabled" || (f[1] == "show" && f[2] == "-p" && f[3] == "MainPID") ||
				c == "systemctl show -p ExecStop --value nftables.service"
		case "wg":
			ok = c == "wg show all listen-port"
		case "docker":
			ok = c == "docker inspect --format {{.Id}} {{.State.Running}} "+SmartDNSContainer
		}
		if !ok {
			t.Fatalf("unexpected command %q", c)
		}
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestAgentPreflightRefusesBadPaths(t *testing.T) {
	run := &pfRunner{out: map[string]string{}}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: run}
	for _, paths := range [][]string{{"/etc/shadow"}, {"/etc/wireguard/../shadow"}, {"/etc/wireguard/a;id"}, {"relative"}} {
		if res := a.Preflight(context.Background(), PreflightRequest{Paths: paths}); res.Error == "" {
			t.Fatalf("accepted %v", paths)
		}
	}
	if len(run.calls) != 0 {
		t.Fatalf("commands ran for a refused request: %v", run.calls)
	}
	// Over HTTP: unknown fields and bad paths are 400.
	h := a.Handler()
	for _, body := range []string{`{"paths":["/etc/shadow"]}`, `{"paths":[],"command":"id"}`, `not json`} {
		req := httptest.NewRequest(http.MethodPost, "/v1/preflight", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer tok")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", bytes.NewBufferString(`{"paths":[]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/preflight", bytes.NewBufferString(`{"paths":["/etc/meridian/forwarding.conf"]}`))
	req.Header.Set("Authorization", "Bearer tok")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var res PreflightResult
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &res) != nil || !strings.HasPrefix(res.Report, preflight.Header) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

// An answer at the runner's cap may be cut: the report is not complete.
func TestAgentPreflightCappedOutputIsIncomplete(t *testing.T) {
	run := &pfRunner{out: map[string]string{"ss -Hlntup": strings.Repeat("x", 16<<10)}}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: run, PreflightRoot: pfRoot(t)}
	res := a.Preflight(context.Background(), PreflightRequest{})
	if r := preflight.Parse(res.Report); r.Complete {
		t.Fatal("capped output parsed as complete")
	}
}
