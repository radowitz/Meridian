package pathquality

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// path-step never publishes: without the locked applier's candidate
// directory it refuses before touching state or status.
func TestRunStepRequiresCandidate(t *testing.T) {
	dir := t.TempDir()
	state, status := filepath.Join(dir, "state.json"), filepath.Join(dir, "upstream")
	var out, errb bytes.Buffer
	if rc := RunStep([]string{"--config", filepath.Join(dir, "none.json"), "--state", state, "--status", status}, &out, &errb); rc != 2 {
		t.Fatalf("rc %d", rc)
	}
	for _, p := range []string{state, status} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s written without an applied switch", p)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("decision printed: %q", out.String())
	}
}

// After a shell fallback (no Go state), the controller resumes from the last
// applied record: carrying path, designated relay, since and switch time.
func TestStateFromAppliedStatus(t *testing.T) {
	c := testConfig(t, nil)
	st := NewState(c, 1700000000)
	st.Upstream, st.Designated, st.UpstreamSince, st.LastSwitch = "main", "access2", 1700000050, 1700000050
	st.Relays["access"].Weight, st.Relays["access2"].Weight = 300, 700
	p := filepath.Join(t.TempDir(), "upstream")
	if err := os.WriteFile(p, []byte(FormatStatus(c, st, 1700000100, "shell")), 0o600); err != nil {
		t.Fatal(err)
	}
	got := stateFromAppliedStatus(c, p, 1700000100)
	if got == nil || got.Upstream != "main" || got.Designated != "access2" || got.UpstreamSince != 1700000050 || got.LastSwitch != 1700000050 ||
		got.Relays["access2"].Weight != 700 {
		t.Fatalf("%+v", got)
	}
	if err := os.WriteFile(p, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if stateFromAppliedStatus(c, p, 1) != nil {
		t.Fatal("an unreadable record seeded a state")
	}
}
