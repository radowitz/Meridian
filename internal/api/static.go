package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Static serving of the built panel (web/dist). It replaces a bare
// http.FileServer, whose responses carried only Last-Modified: browsers then
// cached index.html heuristically and kept loading the previous build's
// scripts after an upgrade until a manual hard refresh.
//
// Cache classes:
//   - files listed in the CURRENT build's Vite manifest (dist/.vite/manifest.json,
//     written by `vite build` with build.manifest) under assets/: their names
//     carry a content hash, so they get "public, max-age=31536000, immutable".
//     The set is read from the manifest, never guessed from file names, so a
//     file without a hash (or one left over from an older build) can never be
//     marked immutable. No manifest → nothing is immutable.
//   - every other existing file (index.html, version.json, favicon …):
//     "no-cache" — the browser may keep it but must revalidate; conditional
//     requests (If-Modified-Since / If-None-Match) answer 304 when unchanged.
//   - anything that does not exist (including an old build's chunk after an
//     upgrade): 404 with "no-store", plain text — never index.html, so a
//     missing script is never answered with HTML that gets cached or run.
//
// There is deliberately no SPA fallback to index.html: the panel uses hash
// routing (#/…), the fragment never reaches the server, so every real request
// names a real file. Directories other than "/" are 404 (no listings).
//
// Limit: a tab already running a build older than this handler got its
// index.html under the old heuristic caching and has no update notice; the
// first upgrade to this version may still need one manual refresh. Later
// upgrades revalidate index.html and show the notice (web/src/PanelUpdate.tsx).

const (
	cacheImmutable = "public, max-age=31536000, immutable"
	cacheRevalid   = "no-cache"
	cacheNone      = "no-store"
	manifestPath   = ".vite/manifest.json"
)

type staticHandler struct {
	root string

	mu         sync.Mutex
	manModTime time.Time
	manSize    int64
	hashed     map[string]bool // slash paths relative to root, e.g. "assets/App-abc123.js"
}

func newStaticHandler(root string) *staticHandler {
	return &staticHandler{root: root, hashed: map[string]bool{}}
}

// hashedSet returns the current build's hashed files, reloading the manifest
// when it changed on disk (the dist directory can be replaced without a
// panel restart).
func (h *staticHandler) hashedSet() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := filepath.Join(h.root, filepath.FromSlash(manifestPath))
	st, err := os.Stat(p)
	if err != nil {
		h.hashed, h.manModTime, h.manSize = map[string]bool{}, time.Time{}, 0
		return h.hashed
	}
	if st.ModTime().Equal(h.manModTime) && st.Size() == h.manSize {
		return h.hashed
	}
	set := map[string]bool{}
	if b, err := os.ReadFile(p); err == nil {
		var man map[string]struct {
			File   string   `json:"file"`
			CSS    []string `json:"css"`
			Assets []string `json:"assets"`
		}
		if json.Unmarshal(b, &man) == nil {
			add := func(f string) {
				f = path.Clean(f)
				if strings.HasPrefix(f, "assets/") {
					set[f] = true
				}
			}
			for _, e := range man {
				add(e.File)
				for _, f := range e.CSS {
					add(f)
				}
				for _, f := range e.Assets {
					add(f)
				}
			}
		}
	}
	h.hashed, h.manModTime, h.manSize = set, st.ModTime(), st.Size()
	return set
}

func staticNotFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheNone)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found\n"))
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if rel == "" {
		rel = "index.html"
	}
	// Dot segments (.vite/manifest.json and the like) are build internals.
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasPrefix(seg, ".") {
			staticNotFound(w)
			return
		}
	}
	f, err := http.Dir(h.root).Open("/" + rel)
	if err != nil {
		staticNotFound(w)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() || !st.Mode().IsRegular() {
		staticNotFound(w) // no directory listings
		return
	}
	cc := cacheRevalid
	if h.hashedSet()[rel] {
		cc = cacheImmutable
	}
	w.Header().Set("Cache-Control", cc)
	w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, st.ModTime().UnixNano(), st.Size()))
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}
