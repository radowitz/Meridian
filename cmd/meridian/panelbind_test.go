package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPanelBindCmd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MERIDIAN_DATA", dir)
	t.Setenv("MERIDIAN_BIND", "")
	var out, errb bytes.Buffer
	if code := panelBindCmd(&out, &errb); code != 0 || strings.TrimSpace(out.String()) != defaultBind {
		t.Fatalf("fresh: %d %q %q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "meridian.db")); err == nil {
		t.Fatal("panel-bind created a database on a fresh install")
	}
	out.Reset()
	t.Setenv("MERIDIAN_BIND", "192.0.2.1:8787")
	if code := panelBindCmd(&out, &errb); code != 0 || strings.TrimSpace(out.String()) != "192.0.2.1:8787" {
		t.Fatalf("env: %d %q", code, out.String())
	}
	out.Reset()
	t.Setenv("MERIDIAN_BIND", "0.0.0.0:8787")
	if code := panelBindCmd(&out, &errb); code != 1 {
		t.Fatalf("wildcard accepted: %q", out.String())
	}
}
