package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleSetAuthLifecycle(t *testing.T) {
	s, dir := open(t)
	tok := "fake-rs-bearer-7c6b5a"
	m, err := s.SetRuleSetAuth("rs-abc123", RuleSetAuthInput{Kind: "bearer", Token: tok})
	if err != nil || !m.SecretSet || m.Kind != "bearer" || m.RuleSetID != "rs-abc123" {
		t.Fatalf("%+v %v", m, err)
	}
	// Metadata never carries the material; the secret file is the only place.
	b, _ := json.Marshal(s.RuleSetAuths())
	idx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	for _, txt := range []string{string(b), string(idx)} {
		if strings.Contains(txt, tok) {
			t.Fatalf("material in metadata: %s", txt)
		}
	}
	hits := grepDir(t, dir, tok)
	if len(hits) != 1 {
		t.Fatalf("token stored in %v", hits)
	}
	if fi, _ := os.Stat(hits[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	in, ok, err := s.RuleSetAuthSecret("rs-abc123")
	if err != nil || !ok || in.Token != tok {
		t.Fatalf("read back %v %v", ok, err)
	}
	// Rotation to another kind replaces the file.
	if _, err := s.SetRuleSetAuth("rs-abc123", RuleSetAuthInput{Kind: "query", Query: "token=fake-q-1234"}); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, tok); len(hits) != 0 {
		t.Fatalf("old token left in %v", hits)
	}
	in, _, _ = s.RuleSetAuthSecret("rs-abc123")
	if in.Kind != "query" || in.Query != "token=fake-q-1234" || in.Token != "" {
		t.Fatalf("rotated %+v", in.Kind)
	}
	if _, err := s.SetRuleSetAuth("rs-abc123", RuleSetAuthInput{Kind: "cookie"}); codeOf(err) != CodeInvalid {
		t.Fatalf("bad kind: %v", err)
	}
	// Survives a reopen; delete removes the material.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s2.RuleSetAuthSecret("rs-abc123"); !ok || err != nil {
		t.Fatalf("after reopen %v %v", ok, err)
	}
	if err := s2.DeleteRuleSetAuth("rs-abc123"); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, "fake-q-1234"); len(hits) != 0 {
		t.Fatalf("material left after delete: %v", hits)
	}
	if _, ok, _ := s2.RuleSetAuthSecret("rs-abc123"); ok {
		t.Fatal("credential still present")
	}
}
