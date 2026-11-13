package hostexec

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
)

const goodUpstream = "meridian-upstream 1\nbeat 1700000100\npath backup\niface m02\nhub hk5\ntier backup\nsince 1700000050\nstate ok\nend\n"

func TestUpstreamFileMatchesCompile(t *testing.T) {
	if UpstreamStateFile != compile.UpstreamStateFile {
		t.Fatal("hostexec and compile disagree on the upstream record path")
	}
}

func TestParseUpstream(t *testing.T) {
	st, err := ParseUpstream(goodUpstream)
	if err != nil || st.Hub != "hk5" || st.Tier != "backup" || st.Path != "backup" || st.State != UpstreamOK || st.Since != 1700000050 {
		t.Fatalf("%+v %v", st, err)
	}
	bad := []string{
		"",
		strings.Replace(goodUpstream, "tier backup", "tier other", 1),
		strings.Replace(goodUpstream, "state ok", "state maybe", 1),
		strings.Replace(goodUpstream, "hub hk5", "hub $(reboot)", 1),
		strings.Replace(goodUpstream, "since 1700000050", "since 1700000200", 1),
		strings.Replace(goodUpstream, "end\n", "", 1),
		strings.Replace(goodUpstream, "path backup\n", "path backup\npath udp\n", 1),
		goodUpstream + strings.Repeat("x", MaxUpstreamFile),
	}
	for _, b := range bad {
		if _, err := ParseUpstream(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestAgentUpstreamStatus(t *testing.T) {
	root := t.TempDir()
	a := &Agent{Token: func() (string, error) { return "tok", nil }, PreflightRoot: root}
	if st := a.UpstreamStatus(context.Background()); st.Present || st.Error != "" {
		t.Fatalf("absent file: %+v", st)
	}
	p := filepath.Join(root, UpstreamStateFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(goodUpstream), 0o644); err != nil {
		t.Fatal(err)
	}
	st := a.UpstreamStatus(context.Background())
	if !st.Present || st.Record == nil || st.Record.Hub != "hk5" {
		t.Fatalf("%+v", st)
	}
	os.WriteFile(p, []byte("garbage"), 0o644)
	if st := a.UpstreamStatus(context.Background()); st.Record != nil || st.Error == "" {
		t.Fatalf("garbage accepted: %+v", st)
	}
	// The endpoint takes no parameters.
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/upstream/status", bytes.NewBufferString(`{"path":"/etc/shadow"}`))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("parameters accepted: %d", resp.StatusCode)
	}
}
