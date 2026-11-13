package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSOCKSCredentialLifecycle(t *testing.T) {
	s, dir := open(t)
	user, pass := "router-user", "S0cks.Pass-word"
	c, err := s.CreateSOCKSCredential("马来西亚路由器", "", SOCKSSecretInput{Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSOCKSValue(user) || !strings.HasPrefix(c.ID, SOCKSIDPrefix+"-") || !c.SecretSet {
		t.Fatalf("credential %+v", c)
	}
	// The metadata (index, list) never carries the material.
	b, _ := json.Marshal(s.SOCKSCredentials())
	idx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	for _, txt := range []string{string(b), string(idx)} {
		if strings.Contains(txt, user) || strings.Contains(txt, pass) {
			t.Fatalf("material in metadata: %s", txt)
		}
	}
	// The secret file is the only place, mode 0600.
	hits := grepDir(t, dir, pass)
	if len(hits) != 1 {
		t.Fatalf("password stored in %v", hits)
	}
	if fi, _ := os.Stat(hits[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %v", fi.Mode().Perm())
	}
	sec, err := s.SOCKSSecrets([]string{c.ID})
	if err != nil || sec[c.ID+"-user"] != user || sec[c.ID+"-pass"] != pass || !IsSOCKSSecretID(c.ID+"-user") || IsSOCKSSecretID(c.ID) {
		t.Fatalf("secrets %v %v", sec, err)
	}
	// Rotation replaces both halves; the old ones are gone from disk.
	if _, err := s.RotateSOCKSCredential(c.ID, SOCKSSecretInput{Username: "u2", Password: "p2-new"}); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, pass); len(hits) != 0 {
		t.Fatalf("old password left in %v", hits)
	}
	sec, _ = s.SOCKSSecrets([]string{c.ID})
	if sec[c.ID+"-user"] != "u2" || sec[c.ID+"-pass"] != "p2-new" {
		t.Fatalf("rotated %v", sec)
	}
	// Characters that would need escaping are refused, never echoed.
	for _, bad := range []string{"", "has space", "a@b", "x:y", `q"uote`, "back\\slash", "50%", "a&b", strings.Repeat("a", 256)} {
		_, err := s.CreateSOCKSCredential("bad", "", SOCKSSecretInput{Username: "u", Password: bad})
		if codeOf(err) != CodeInvalid || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Errorf("password %q: %v", bad, err)
		}
	}
	// Delete refused while referenced, allowed afterwards.
	err = s.DeleteSOCKSCredential(c.ID, []Ref{{Kind: "node", ID: "my1", Name: "马来西亚"}})
	if codeOf(err) != CodeInUse || !strings.Contains(err.Error(), "马来西亚") {
		t.Fatalf("delete in use: %v", err)
	}
	if err := s.DeleteSOCKSCredential(c.ID, nil); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, "p2-new"); len(hits) != 0 {
		t.Fatalf("material left after delete: %v", hits)
	}
	if _, err := s.SOCKSSecrets([]string{c.ID}); codeOf(err) != CodeNotFound {
		t.Fatalf("secrets of a deleted credential: %v", err)
	}
	// Reopening keeps the store consistent (orphan cleanup keeps live files).
	c2, _ := s.CreateSOCKSCredential("again", "", SOCKSSecretInput{Username: "u", Password: "pw"})
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sec, err := s2.SOCKSSecrets([]string{c2.ID}); err != nil || sec[c2.ID+"-pass"] != "pw" {
		t.Fatalf("after reopen: %v %v", sec, err)
	}
}
