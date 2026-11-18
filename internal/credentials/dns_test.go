package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/validate"
)

func TestDNSAccountLifecycle(t *testing.T) {
	s, dir := open(t)
	v := "a1b2c3"
	c, err := s.CreateDNSAccountCredential("示例解析服务", "", DNSAccountInput{Account: v})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.ID, DNSAccountIDPrefix+"-") || !c.SecretSet || !IsDNSAccountSecretID(c.ID) || IsSOCKSSecretID(c.ID) {
		t.Fatalf("credential %+v", c)
	}
	b, _ := json.Marshal(s.DNSAccountCredentials())
	idx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	for _, txt := range []string{string(b), string(idx)} {
		if strings.Contains(txt, v) {
			t.Fatalf("value in metadata: %s", txt)
		}
	}
	hits := grepDir(t, dir, v)
	if len(hits) != 1 {
		t.Fatalf("value stored in %v", hits)
	}
	if fi, _ := os.Stat(hits[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %v", fi.Mode().Perm())
	}
	if sec, err := s.DNSAccountSecrets([]string{c.ID}); err != nil || sec[c.ID] != v {
		t.Fatalf("secrets %v %v", sec, err)
	}
	if _, err := s.RotateDNSAccountCredential(c.ID, DNSAccountInput{Account: "z9y8x7"}); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, v); len(hits) != 0 {
		t.Fatalf("old value left in %v", hits)
	}
	for _, bad := range []string{"", "ab", "-abc", "abc-", "a/b", "a.b", "a b", "a?b", strings.Repeat("a", 64)} {
		_, err := s.CreateDNSAccountCredential("bad", "", DNSAccountInput{Account: bad})
		if codeOf(err) != CodeInvalid || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Errorf("value %q: %v", bad, err)
		}
		if validate.ExitDNSAccountValid.MatchString(bad) != ValidDNSAccount(bad) {
			t.Errorf("validate and credentials disagree on %q", bad)
		}
	}
	if err := s.DeleteDNSAccountCredential(c.ID, []Ref{{Kind: "setting", ID: "exit_dns", Name: "全局出口解析上游"}}); codeOf(err) != CodeInUse {
		t.Fatalf("delete in use: %v", err)
	}
	if err := s.DeleteDNSAccountCredential(c.ID, nil); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, "z9y8x7"); len(hits) != 0 {
		t.Fatalf("value left after delete: %v", hits)
	}
	c2, _ := s.CreateDNSAccountCredential("again", "", DNSAccountInput{Account: "kept1"})
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sec, err := s2.DNSAccountSecrets([]string{c2.ID}); err != nil || sec[c2.ID] != "kept1" {
		t.Fatalf("after reopen: %v %v", sec, err)
	}
}
