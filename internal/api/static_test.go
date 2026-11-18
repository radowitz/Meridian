package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// webDir writes a small fake build: index.html, version.json, one current
// hashed asset listed in the manifest, one asset left over from an older
// build (on disk but not in the manifest) and an unhashed file under assets/.
func webDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"index.html":                 `<!doctype html><script type="module" src="/assets/index-AbC123.js"></script>`,
		"version.json":               `{"build":"b1"}`,
		"favicon.svg":                `<svg/>`,
		"assets/index-AbC123.js":     `console.log(1)`,
		"assets/index-AbC123.css":    `body{}`,
		"assets/Stale-Old999.js":     `console.log(0)`,
		"assets/plain.js":            `console.log(2)`,
		".vite/manifest.json":        `{"index.html":{"file":"assets/index-AbC123.js","css":["assets/index-AbC123.css"],"isEntry":true},"x":{"file":"../outside.js"}}`,
		"assets/sub/nested-Zz11.png": `png`,
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func staticGet(t *testing.T, s *Server, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func staticServer(t *testing.T) *Server {
	s := newTest(t)
	s.WebDir = webDir(t)
	s.Token = "secret-token"
	return s
}

func TestStaticEntryNoCache(t *testing.T) {
	s := staticServer(t)
	for _, p := range []string{"/", "/index.html"} {
		rr := staticGet(t, s, p, nil)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<!doctype html>") {
			t.Fatalf("%s: %d %q", p, rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("%s: Cache-Control %q", p, got)
		}
		if rr.Header().Get("Last-Modified") == "" || rr.Header().Get("ETag") == "" {
			t.Fatalf("%s: validators missing: %v", p, rr.Header())
		}
	}
	rr := staticGet(t, s, "/version.json", nil)
	if rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("version.json: %d %v", rr.Code, rr.Header())
	}
}

func TestStaticConditional304(t *testing.T) {
	s := staticServer(t)
	first := staticGet(t, s, "/", nil)
	etag, lm := first.Header().Get("ETag"), first.Header().Get("Last-Modified")
	rr := staticGet(t, s, "/", map[string]string{"If-None-Match": etag})
	if rr.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", rr.Code)
	}
	if rr.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("304 Cache-Control %q", rr.Header().Get("Cache-Control"))
	}
	rr = staticGet(t, s, "/", map[string]string{"If-Modified-Since": lm})
	if rr.Code != http.StatusNotModified {
		t.Fatalf("If-Modified-Since: %d", rr.Code)
	}
	// A changed file is served again.
	idx := filepath.Join(s.WebDir, "index.html")
	later := time.Now().Add(time.Hour)
	if err := os.WriteFile(idx, []byte("<!doctype html>new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(idx, later, later); err != nil {
		t.Fatal(err)
	}
	rr = staticGet(t, s, "/", map[string]string{"If-None-Match": etag})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "new") {
		t.Fatalf("changed index: %d %q", rr.Code, rr.Body.String())
	}
}

func TestStaticHashedAssetImmutable(t *testing.T) {
	s := staticServer(t)
	for _, p := range []string{"/assets/index-AbC123.js", "/assets/index-AbC123.css"} {
		rr := staticGet(t, s, p, nil)
		if rr.Code != 200 || rr.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("%s: %d %v", p, rr.Code, rr.Header())
		}
	}
}

func TestStaticUnrecognisedNotImmutable(t *testing.T) {
	s := staticServer(t)
	// On disk but not in the current manifest: a plain name, an older build's
	// hashed-looking name, a nested file, the favicon.
	for _, p := range []string{"/assets/plain.js", "/assets/Stale-Old999.js", "/assets/sub/nested-Zz11.png", "/favicon.svg"} {
		rr := staticGet(t, s, p, nil)
		if rr.Code != 200 {
			t.Fatalf("%s: %d", p, rr.Code)
		}
		if cc := rr.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") || cc != "no-cache" {
			t.Fatalf("%s: Cache-Control %q", p, cc)
		}
	}
	// No manifest at all: nothing is immutable.
	if err := os.Remove(filepath.Join(s.WebDir, ".vite", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	rr := staticGet(t, s, "/assets/index-AbC123.js", nil)
	if strings.Contains(rr.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("immutable without manifest: %v", rr.Header())
	}
}

func TestStaticMissingIs404NotIndex(t *testing.T) {
	s := staticServer(t)
	for _, p := range []string{
		"/assets/RulesPage-Gone42.js", // an old chunk removed by the upgrade
		"/lists",                      // no SPA fallback
		"/nope/deeper.js",
		"/.vite/manifest.json", // build internals are not served
		"/etc/passwd",
	} {
		rr := staticGet(t, s, p, nil)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "<!doctype html>") || strings.Contains(rr.Header().Get("Content-Type"), "html") {
			t.Fatalf("%s answered with HTML: %v %q", p, rr.Header(), rr.Body.String())
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s: Cache-Control %q", p, cc)
		}
	}
}

func TestStaticNoDirectoryListing(t *testing.T) {
	s := staticServer(t)
	for _, p := range []string{"/assets", "/assets/", "/assets/sub/"} {
		rr := staticGet(t, s, p, nil)
		if rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "index-AbC123") {
			t.Fatalf("%s: %d %q", p, rr.Code, rr.Body.String())
		}
	}
}

func TestStaticAPIUnaffected(t *testing.T) {
	s := staticServer(t)
	if rr := staticGet(t, s, "/api/health", nil); rr.Code != 200 {
		t.Fatalf("health: %d", rr.Code)
	}
	if rr := staticGet(t, s, "/api/topology", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("topology without token: %d", rr.Code)
	}
	rr := staticGet(t, s, "/api/topology", map[string]string{"Authorization": "Bearer secret-token"})
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "<!doctype html>") {
		t.Fatalf("topology with token: %d", rr.Code)
	}
	// The static files need no token (the login page loads before one exists).
	if rr := staticGet(t, s, "/version.json", nil); rr.Code != 200 {
		t.Fatalf("version.json: %d", rr.Code)
	}
}
