package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reload: only for activate and only for units of the request.
func TestReloadValidation(t *testing.T) {
	ok := Request{Action: ActionActivate, RequestID: "r", Resources: Resources{Units: []string{SniffUnit}, Reload: []string{SniffUnit}}}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]Request{
		"not in units": {Action: ActionActivate, RequestID: "r", Resources: Resources{Units: []string{"meridian-failover.service"}, Reload: []string{SniffUnit}}},
		"rollback":     {Action: ActionRollback, RequestID: "r", Resources: Resources{Units: []string{SniffUnit}, Reload: []string{SniffUnit}}},
		"bad name":     {Action: ActionActivate, RequestID: "r", Resources: Resources{Units: []string{"sshd.service"}, Reload: []string{"sshd.service"}}},
	} {
		if Validate(req) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, b := ok, ok
	b.Resources.Reload = nil
	if fingerprint(a) == fingerprint(b) {
		t.Fatal("reload is not part of the request fingerprint")
	}
}

// Activate reloads a unit named in Reload (after meridian.service, i.e.
// after the ruleset), restarts the others.
func TestActivateReloadsSniff(t *testing.T) {
	f := newFakeHost()
	f.units[SniffUnit] = "active"
	f.units["meridian-failover.service"] = "inactive"
	a := newAgent(f)
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r1",
		Resources: Resources{Units: []string{"meridian-failover.service", SniffUnit}, Reload: []string{SniffUnit}}})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	cmds := strings.Join(f.commands(), "\n")
	core := strings.Index(cmds, "systemctl restart meridian.service")
	rel := strings.Index(cmds, "systemctl reload-or-restart "+SniffUnit)
	if core < 0 || rel < core || strings.Contains(cmds, "systemctl restart "+SniffUnit) || !strings.Contains(cmds, "systemctl restart meridian-failover.service") {
		t.Fatalf("%s", cmds)
	}
}

// The status read: absent socket, a forwarder answering, a non-JSON
// answer; the endpoint takes no parameters.
func TestAgentSniffStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "sn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	f := newFakeHost()
	a := newAgent(f)
	a.SniffSocketPath = sock
	if st := a.SniffStatus(context.Background()); st.Present || st.Error != "" {
		t.Fatalf("absent: %+v", st)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	health := `{"ready":true,"generation":3}`
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(health)) })
	mux.HandleFunc("/v1/recent", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"record_names":false,"connections":[]}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()
	st := a.SniffStatus(context.Background())
	if !st.Present || st.Error != "" || string(st.Health) != health || !strings.Contains(string(st.Recent), "connections") {
		t.Fatalf("%+v", st)
	}
	health = "not json"
	if st := a.SniffStatus(context.Background()); st.Error == "" || st.Health != nil {
		t.Fatalf("non-JSON accepted: %+v", st)
	}
	hs := httptest.NewServer(a.Handler())
	defer hs.Close()
	req, _ := http.NewRequest("POST", hs.URL+"/v1/sniff/status", bytes.NewBufferString(`{"socket":"/etc/shadow"}`))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out SniffStatus
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("parameters accepted: %d", resp.StatusCode)
	}
}

// After a list publication the running forwarder is told to re-read; a
// stopped one is left alone.
func TestReloadSniffAfterLists(t *testing.T) {
	f := newFakeHost()
	a := newAgent(f)
	a.init()
	x := &run{a: a, ctx: context.Background()}
	if w := x.reloadSniff(); w != "" || f.ran("systemctl try-reload-or-restart") != 0 {
		t.Fatalf("stopped forwarder signalled: %q %v", w, f.commands())
	}
	f.units[SniffUnit] = "active"
	if w := x.reloadSniff(); w != "" || f.ran("systemctl try-reload-or-restart "+SniffUnit) != 1 {
		t.Fatalf("%q %v", w, f.commands())
	}
}
