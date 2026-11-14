package api

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
)

func sortedCopy(xs []string) []string {
	out := append([]string{}, xs...)
	sort.Strings(out)
	return out
}

func slashed(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, "/"+x)
	}
	sort.Strings(out)
	return out
}

// The gateway preflight's file list and the per-file comparison of POST
// /api/diff ("installed", what the deploy page shows as 待安装的改动) agree
// for every kind of edit, and an install with no change says so.
func TestGatewayPreflightFilesMatchInstalledDiff(t *testing.T) {
	s, _, activated := installTest(t)
	hp := &fakeHostPreflight{}
	s.HostPreflight = hp
	// A service group with a rule pointing at it, before the first install.
	topo, _, _ := s.Store.Load()
	topo.ServiceGroups = append(topo.ServiceGroups, model.ServiceGroup{ID: "svc-x", Name: "服务 X", TargetGroup: "hk"})
	topo.Rules = append(topo.Rules, model.Rule{ID: "svc-rule", Name: "服务 X 的域名", Manual: true, Priority: 15, Enabled: true,
		MatchType: model.MatchDomain, MatchValue: "svc.example.com", Domains: []string{"svc.example.com"}, TargetService: "svc-x"})
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodPost, "/api/host/preflight", nil)
	var first struct{ Preflight preflightRecord }
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &first) != nil {
		t.Fatalf("first preflight: %d %s", rr.Code, rr.Body.String())
	}
	if first.Preflight.FileChanges != nil {
		t.Fatal("first install: there is nothing to compare with")
	}
	if rr := do(s, http.MethodPost, "/api/apply", mustJSON(map[string]any{"install": true, "preflight_id": first.Preflight.ID})); rr.Code != 200 || *activated != 1 {
		t.Fatalf("install: %d %s", rr.Code, rr.Body.String())
	}
	raw, err := os.ReadFile("../preflight/testdata/gateway-installed.txt")
	if err != nil {
		t.Fatal(err)
	}
	hp.mu.Lock()
	hp.raw = string(raw)
	hp.mu.Unlock()

	edit := func(fn func(t *model.Topology)) func() {
		return func() {
			topo, _, _ := s.Store.Load()
			fn(&topo)
			if err := s.Store.Save(topo); err != nil {
				t.Fatal(err)
			}
		}
	}
	steps := []struct {
		name    string
		do      func()
		changes bool
	}{
		{"no change", func() {}, false},
		{"rule change", edit(func(t *model.Topology) {
			for i := range t.Rules {
				if t.Rules[i].ID == "manual-example" {
					t.Rules[i].MatchValue, t.Rules[i].Domains = "api2.example.com", []string{"api2.example.com"}
				}
			}
		}), true},
		{"service group retarget", func() {
			if rr := do(s, http.MethodPatch, "/api/service-groups/svc-x", []byte(`{"target":"group:us"}`)); rr.Code != 200 {
				t.Fatalf("retarget: %d %s", rr.Code, rr.Body.String())
			}
		}, true},
		{"link change", edit(func(t *model.Topology) {
			for i := range t.Links {
				if t.Links[i].ID == "gw-ali" {
					t.Links[i].MTU = 1380
				}
			}
		}), true},
	}
	for _, st := range steps {
		st.do()
		rr := do(s, http.MethodPost, "/api/diff", []byte(`{}`))
		var diff struct {
			Installed *apply.ManifestDiff `json:"installed"`
		}
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &diff) != nil || diff.Installed == nil {
			t.Fatalf("%s: diff %d %s", st.name, rr.Code, rr.Body.String())
		}
		rr = do(s, http.MethodPost, "/api/host/preflight", nil)
		var out struct{ Preflight preflightRecord }
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("%s: preflight %d %s", st.name, rr.Code, rr.Body.String())
		}
		fc := out.Preflight.FileChanges
		if fc == nil || fc.Basis != preflight.BasisInstalled {
			t.Fatalf("%s: no file comparison: %s", st.name, rr.Body.String())
		}
		t.Logf("%s: %s changed=%v", st.name, fc.Summary, fc.Changed)
		d := diff.Installed
		for _, c := range []struct {
			what      string
			got, want []string
		}{{"added", fc.Added, slashed(d.FilesAdded)}, {"changed", fc.Changed, slashed(d.FilesChanged)}, {"removed", fc.Removed, slashed(d.FilesRemoved)}} {
			if strings.Join(sortedCopy(c.got), " ") != strings.Join(c.want, " ") {
				t.Fatalf("%s: preflight %s %v, per-file comparison %v", st.name, c.what, c.got, c.want)
			}
		}
		if len(fc.NotCompared) != 0 {
			t.Fatalf("%s: the gateway compares every file: %v", st.name, fc.NotCompared)
		}
		files, _ := s.gatewayFiles()
		if len(fc.Added)+len(fc.Changed)+len(fc.Unchanged) != len(files) {
			t.Fatalf("%s: %d+%d+%d files, bundle has %d", st.name, len(fc.Added), len(fc.Changed), len(fc.Unchanged), len(files))
		}
		if (fc.Changes() > 0) != st.changes {
			t.Fatalf("%s: changes %d", st.name, fc.Changes())
		}
		// The change list names exactly the files that differ; none is a
		// blanket "replace".
		var listed []string
		for _, c := range out.Preflight.Changes {
			if c.Kind != "file" {
				continue
			}
			if c.Action == "replace" {
				t.Fatalf("%s: file listed as replace: %+v", st.name, c)
			}
			listed = append(listed, c.Resource)
		}
		want := append(append(append([]string{}, fc.Added...), fc.Changed...), fc.Removed...)
		if strings.Join(sortedCopy(listed), " ") != strings.Join(sortedCopy(want), " ") {
			t.Fatalf("%s: change list %v, comparison %v", st.name, listed, want)
		}
		if !st.changes && !strings.HasPrefix(fc.Summary, "没有文件变化") {
			t.Fatalf("no change not said plainly: %q", fc.Summary)
		}
		if st.changes && len(fc.Changed) == 0 {
			t.Fatalf("%s: nothing reported changed", st.name)
		}
		// Nothing secret is part of the answer: paths and counts only.
		if strings.Contains(rr.Body.String(), compile.PrivateKeyPlaceholder) {
			t.Fatalf("%s: file content in the preflight answer", st.name)
		}
		if gw := storedNode(t, s, localNodeID); gw.PrivateKey != "" && strings.Contains(rr.Body.String(), gw.PrivateKey) {
			t.Fatalf("%s: gateway key in the preflight answer", st.name)
		}
		// Install the change so the next step starts in sync.
		if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
			t.Fatalf("%s: install %d %s", st.name, rr.Code, rr.Body.String())
		}
	}
}

// A remote node's preflight compares with the node's own manifest: files
// the host wrote unchanged are counted, a changed plain file is "changed",
// a file that gets a secret injected is "not compared" unless the whole
// bundle is the installed one, and files the bundle no longer has stay on
// the host (orphans).
func TestRemoteFileComparison(t *testing.T) {
	files := map[string]string{
		"/etc/meridian/a.conf":     "alpha",
		"/etc/meridian/b.conf":     "beta\n",
		"/etc/wireguard/wg0.conf":  "[Interface]\nPrivateKey = " + compile.PrivateKeyPlaceholder + "\n",
		"/etc/meridian/new.conf":   "new\n",
		"/usr/local/bin/wstunnel0": "",
	}
	delete(files, "/usr/local/bin/wstunnel0")
	hostHash := func(body string) string { return apply.FileHash(provision.HostContent(body)) }
	m := &preflight.NodeManifest{Node: "n1", Deployment: "d1", Files: map[string]string{
		"/etc/meridian/a.conf":    hostHash("alpha"), // the script added the final newline
		"/etc/meridian/b.conf":    hostHash("beta-old\n"),
		"/etc/wireguard/wg0.conf": apply.FileHash("[Interface]\nPrivateKey = fake-injected-key\n"),
		"/etc/meridian/old.conf":  hostHash("old\n"),
		"/usr/local/bin/tool":     strings.Repeat("a", 64),
	}, Artifacts: []preflight.ManifestArtifact{{Name: "tool", Path: "/usr/local/bin/tool"}}}
	if remoteFileComparison(m, "other", "d1", files) != nil || remoteFileComparison(nil, "n1", "d1", files) != nil {
		t.Fatal("compared with another node's manifest")
	}
	c := remoteFileComparison(m, "n1", "d1", files)
	got := func(xs []string) string { return strings.Join(sortedCopy(xs), " ") }
	if got(c.Unchanged) != "/etc/meridian/a.conf" || got(c.Changed) != "/etc/meridian/b.conf" || got(c.Added) != "/etc/meridian/new.conf" ||
		got(c.Removed) != "/etc/meridian/old.conf" || got(c.NotCompared) != "/etc/wireguard/wg0.conf" || !c.RemovedKept {
		t.Fatalf("%+v", c)
	}
	// The installed bundle is exactly this one: every file is unchanged,
	// the injected one included.
	m.Bundle = preflight.BundleDigest(files)
	m.Files["/etc/meridian/b.conf"] = hostHash("beta\n")
	m.Files["/etc/meridian/new.conf"] = hostHash("new\n")
	delete(m.Files, "/etc/meridian/old.conf")
	c = remoteFileComparison(m, "n1", "d1", files)
	if c.Changes() != 0 || len(c.Unchanged) != len(files) {
		t.Fatalf("%+v", c)
	}
}
