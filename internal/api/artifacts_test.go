package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/sshexec"
)

// fakeArtifact is the test stand-in for a panel-delivered binary.
func fakeArtifact(name, arch string) []byte {
	return []byte("#!/bin/sh\n# fake " + name + " " + arch + " for tests\nexit 0\n")
}

// testArtifacts is a verified artifact directory of fake binaries with
// their own pins (the embedded pins name the real upstream builds, which
// tests never download).
func testArtifacts(t *testing.T, dir string) *artifacts.Bundle {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var pins []artifacts.Pin
	for _, p := range artifacts.Pins() {
		data := fakeArtifact(p.Name, p.Arch)
		fp := artifacts.Pin{Name: p.Name, Version: "1.0-test", Arch: p.Arch, SHA256: artifacts.SHA256Of(data), Size: int64(len(data)), SourceKind: "raw", URL: p.URL}
		if err := os.WriteFile(filepath.Join(dir, fp.File()), data, 0o444); err != nil {
			t.Fatal(err)
		}
		pins = append(pins, fp)
	}
	return artifacts.LoadPins(dir, pins)
}

// The host lacks the resolver binary: the panel stages the verified copy
// over the same pooled login as the preflight re-run and the script (one
// login for the flow), with the fixed receive command, and the script
// verifies it on the host before anything is activated.
func TestProvisionStagesBinaries(t *testing.T) {
	f := newGateFix(t)
	data := fakeArtifact("smartdns", "x86_64")
	sum := artifacts.SHA256Of(data)
	var staged []string
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if out, ok := cleanPreflight(cmd, stdin, ""); ok {
			// The binary is absent on this host.
			return strings.Replace(out, fmt.Sprintf("path /usr/local/sbin/meridian-smartdns file %d no %s\n", len(data), sum), "path /usr/local/sbin/meridian-smartdns absent\n", 1), 0
		}
		if want, _ := sshexec.StageCommand("smartdns", sum, int64(len(data))); cmd == want {
			staged = append(staged, stdin)
			return "MERIDIAN_STAGED " + sum + "\n", 0
		}
		if cmd == "bash -s" && strings.Contains(stdin, "echo MERIDIAN_PROVISION_OK") {
			if !strings.Contains(stdin, "m_art_check 'smartdns' '/usr/local/sbin/meridian-smartdns' '"+sum+"' staged") {
				return "script does not verify the staged binary", 1
			}
			return "MERIDIAN_PROVISION_OK\n", 0
		}
		return "unexpected " + cmd, 1
	})
	rec := f.preflight(t)
	if len(rec.Binaries) != 1 || rec.Binaries[0].Action != "install" || !rec.Binaries[0].Transfer || rec.Binaries[0].SHA256 != sum {
		t.Fatalf("plan %+v", rec.Binaries)
	}
	logins := f.srv.Logins()
	rr := f.provision(rec.ID)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"outcome":"installed"`) {
		t.Fatalf("provision: %d %s", rr.Code, rr.Body.String())
	}
	if len(staged) != 1 || staged[0] != string(data) {
		t.Fatalf("staged %d transfers", len(staged))
	}
	// Re-run, transfer and script share the pooled connection of the
	// reviewed preflight: no further login (at most one if it expired).
	if got := f.srv.Logins() - logins; got > 1 {
		t.Fatalf("the flow used %d logins, want at most 1 (pooled connection)", got)
	}
	cmd, _ := sshexec.StageCommand("smartdns", sum, int64(len(data)))
	if !strings.Contains(cmd, "/var/lib/meridian/stage/smartdns") || !strings.Contains(cmd, fmt.Sprintf("head -c %d", len(data))) {
		t.Fatalf("receive command %s", cmd)
	}
	for _, bad := range []struct {
		name, sum string
		size      int64
	}{{"bash", sum, 10}, {"smartdns", "zz", 10}, {"smartdns", sum, 0}, {"smartdns", sum, artifacts.MaxSize + 1}, {"smartdns;id", sum, 10}} {
		if _, err := sshexec.StageCommand(bad.name, bad.sum, bad.size); err == nil {
			t.Fatalf("receive command accepted %+v", bad)
		}
	}
}

// The panel's copy changed after it was loaded (digest mismatch at use):
// the provision is refused before the script runs, nothing is sent.
func TestProvisionRefusesTamperedArtifact(t *testing.T) {
	f := newGateFix(t)
	data := fakeArtifact("smartdns", "x86_64")
	sum := artifacts.SHA256Of(data)
	f.srv.SetHandler(func(cmd, stdin string) (string, uint32) {
		if out, ok := cleanPreflight(cmd, stdin, ""); ok {
			return strings.Replace(out, fmt.Sprintf("path /usr/local/sbin/meridian-smartdns file %d no %s\n", len(data), sum), "path /usr/local/sbin/meridian-smartdns absent\n", 1), 0
		}
		return "unexpected " + cmd, 1
	})
	rec := f.preflight(t)
	// Same size, other bytes.
	tampered := []byte(strings.Replace(string(data), "fake", "evil", 1))
	p := filepath.Join(f.s.Artifacts.Dir(), "smartdns-x86_64")
	os.Remove(p)
	if err := os.WriteFile(p, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	rr := f.provision(rec.ID)
	if rr.Code != 409 || !strings.Contains(rr.Body.String(), `"code":"artifact_unavailable"`) || !strings.Contains(rr.Body.String(), `"outcome":"not_started"`) {
		t.Fatalf("tampered artifact: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range f.srv.Commands() {
		if strings.Contains(c, "head -c") {
			t.Fatal("a tampered binary was sent")
		}
	}
	if f.provisionScripts() != 0 {
		t.Fatal("the script ran")
	}
	// From now on that binary is unavailable and the preflight says so.
	if st := f.s.Artifacts.Status("smartdns", "x86_64"); st.Available {
		t.Fatal("tampered binary still marked available")
	}
	rec = f.preflight(t)
	if !rec.Blocking || len(find(rec, "smartdns_unavailable")) != 1 {
		t.Fatalf("preflight after tampering %+v", rec.Findings)
	}
}

func find(rec preflightRecord, code string) []string {
	var out []string
	for _, f := range rec.Findings {
		if f.Code == code {
			out = append(out, f.Message)
		}
	}
	return out
}

// GET /api/artifacts lists the pins and their state, no bytes.
func TestArtifactsEndpoint(t *testing.T) {
	s := newTest(t)
	rr := do(s, "GET", "/api/artifacts", nil)
	var out struct {
		Artifacts []struct {
			Name      string `json:"name"`
			HostPath  string `json:"host_path"`
			Available bool   `json:"available"`
		}
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil || len(out.Artifacts) != 4 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "exit 0") {
		t.Fatal("binary content in the listing")
	}
}

// The gateway's WSS client runs the panel-delivered wstunnel: the install
// transaction writes the verified copy (0755) and records it in the
// manifest; the next preflight sees it as ours with the pinned digest; an
// unavailable copy refuses the install before any host file is written.
func TestGatewayInstallDeliversWstunnel(t *testing.T) {
	s, root, activated := installTest(t)
	arch := artifacts.UnameArch(runtime.GOARCH)
	if arch == "" {
		t.Skip("no pinned architecture for this test machine")
	}
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var out struct{ Preflight preflightRecord }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != 200 || out.Preflight.Blocking || len(out.Preflight.Binaries) != 1 || out.Preflight.Binaries[0].Name != "wstunnel" || out.Preflight.Binaries[0].Action != "install" {
		t.Fatalf("gateway preflight: %d %+v %v", rr.Code, out.Preflight.Binaries, out.Preflight.Findings)
	}
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": out.Preflight.ID})); rr.Code != 200 || *activated != 1 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
	bin := filepath.Join(root, "usr/local/sbin/meridian-wstunnel")
	got, err := os.ReadFile(bin)
	if err != nil || string(got) != string(fakeArtifact("wstunnel", arch)) {
		t.Fatalf("wstunnel not delivered: %v %q", err, got)
	}
	if st, _ := os.Stat(bin); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", st.Mode())
	}
	unit, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/wstunnel-client-gw-ali.service"))
	if !strings.Contains(string(unit), "ExecStart=/usr/local/sbin/meridian-wstunnel client") {
		t.Fatalf("unit %s", unit)
	}
	inst, _ := s.applier(true).Installed()
	if len(inst.Artifacts) != 1 || inst.Artifacts[0].SHA256 != artifacts.SHA256Of(got) {
		t.Fatalf("manifest artifacts %+v", inst.Artifacts)
	}
	if o := ownedOf(inst); o.Files["/usr/local/sbin/meridian-wstunnel"] != artifacts.SHA256Of(got) {
		t.Fatalf("owned %+v", o.Files)
	}

	// A fresh gateway whose panel has no usable wstunnel: refused, nothing written.
	s2, root2, _ := installTest(t)
	s2.HostPreflight = &fakeHostPreflight{}
	p := filepath.Join(s2.Artifacts.Dir(), "wstunnel-"+arch)
	os.Remove(p)
	s2.Artifacts = artifacts.LoadPins(s2.Artifacts.Dir(), nil)
	rr = do(s2, http.MethodPost, "/api/host/preflight", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if !out.Preflight.Blocking || len(find(out.Preflight, "wstunnel_missing")) != 1 {
		t.Fatalf("gateway without wstunnel: %+v", out.Preflight.Findings)
	}
	if _, err := os.Stat(filepath.Join(root2, "usr/local/sbin/meridian-wstunnel")); err == nil {
		t.Fatal("binary written without a verified copy")
	}
}
