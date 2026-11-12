package lists

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParsePolicy(t *testing.T) {
	for _, s := range []string{"domestic", "overseas", "automatic"} {
		if _, ok := ParsePolicy(s); !ok {
			t.Fatalf("%s refused", s)
		}
	}
	for _, s := range []string{"", "auto", "Domestic", "https://x"} {
		if _, ok := ParsePolicy(s); ok {
			t.Fatalf("%q accepted", s)
		}
	}
	if Effective("") != PolicyAutomatic || Effective("overseas") != PolicyOverseas {
		t.Fatal("Effective")
	}
	if o := Order(PolicyAutomatic); len(o) != 2 || o[0].Name != SourceDomestic || o[1].Name != SourceOverseas {
		t.Fatalf("automatic order %+v", o)
	}
	for _, s := range []Source{Domestic} {
		if strings.Contains(s.GeositeBase+s.ChnrouteBase, "githubusercontent") {
			t.Fatal("domestic source depends on raw.githubusercontent.com")
		}
	}
}

func TestWithEnvChecksBase(t *testing.T) {
	env := map[string]string{EnvGeositeBase: "http://mirror.lan/data/"}
	got, err := WithEnv(Order(PolicyAutomatic), func(k string) string { return env[k] })
	if err != nil || got[0].GeositeBase != "http://mirror.lan/data" || got[1].GeositeBase != Overseas.GeositeBase {
		t.Fatalf("%v %+v", err, got)
	}
	for _, bad := range []string{"file:///etc", "http://", "https://h/x?y=1", "https://u:p@h/", "https://h/ x"} {
		env[EnvChnrouteBase] = bad
		if _, err := WithEnv(Order(PolicyDomestic), func(k string) string { return env[k] }); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseV2fly(t *testing.T) {
	f, err := ParseV2fly([]byte(`# comment
example.com
domain:Sub.Example.org @cn # trailing comment
full:www.example.net @ads @!cn
keyword:tracker
regexp:^ad[0-9]+\.example\.com$
shop.example.cn &other-list
include:geolocation-!cn @-!cn
include:tld-cn
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 6 || len(f.Includes) != 2 || f.Affiliations != 1 {
		t.Fatalf("%+v", f)
	}
	if f.Entries[1].Value != "sub.example.org" || !f.Entries[1].has("cn") || !f.Entries[2].has("!cn") {
		t.Fatalf("attrs %+v", f.Entries)
	}
	if inc := f.Includes[0]; inc.Name != "geolocation-!cn" || len(inc.Not) != 1 || inc.Not[0] != "!cn" {
		t.Fatalf("include %+v", inc)
	}
	for name, body := range map[string]string{
		"html":          "<!DOCTYPE html>\n<html><body>blocked</body></html>\n",
		"unknown type":  "foo:bar.com\n",
		"bad domain":    "exa mple.com\n",
		"double dot":    "a..b.com\n",
		"minus on rule": "a.com @-cn\n",
		"stray token":   "a.com b.com\n",
		"bad include":   "include:../etc\n",
		"bad regexp":    "regexp:([\n",
		"cut domain":    "full:www.example.\n",
	} {
		if _, err := ParseV2fly([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func parsed(t *testing.T, files map[string]string) map[string]File {
	out := map[string]File{}
	for n, b := range files {
		f, err := ParseV2fly([]byte(b))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		out[n] = f
	}
	return out
}

func TestExpandIncludesAndAttributes(t *testing.T) {
	files := parsed(t, map[string]string{
		// The shape of v2fly's cn: nothing but includes.
		"cn":             "include:tld-cn\ninclude:geolocation-cn\n",
		"tld-cn":         "cn\nxn--fiqs8s\n",
		"geolocation-cn": "baidu.com\ninclude:jd @-!cn\ninclude:apple @cn\ninclude:shared\n",
		"jd":             "jd.com\njd.hk @!cn\nkeyword:jdcdn\n",
		"apple":          "apple.com\napple.cn @cn\nfull:cn-apple.example @cn @ads\nregexp:^x$ @cn\n",
		"shared":         "include:leaf\n",
		"leaf":           "leaf.cn\njd.com\n",
	})
	ex, err := Expand("cn", files, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := "apple.cn baidu.com cn cn-apple.example jd.com leaf.cn xn--fiqs8s"
	if got := strings.Join(ex.Domains, " "); got != want {
		t.Fatalf("domains\n got %s\nwant %s", got, want)
	}
	if ex.Files != 7 || ex.Dropped[TypeKeyword] != 1 || ex.Dropped[TypeRegexp] != 1 {
		t.Fatalf("files %d dropped %v", ex.Files, ex.Dropped)
	}
	// Several attributes: all must match.
	files2 := parsed(t, map[string]string{
		"top":   "include:apple @cn @ads\n",
		"apple": "apple.com\napple.cn @cn\nfull:cn-apple.example @cn @ads\n",
	})
	ex, err = Expand("top", files2, Limits{})
	if err != nil || strings.Join(ex.Domains, " ") != "cn-apple.example" {
		t.Fatalf("%v %v", err, ex.Domains)
	}
}

func TestExpandFailures(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		lim   Limits
		want  string
	}{
		"cycle":        {files: map[string]string{"a": "include:b\n", "b": "x.com\ninclude:c\n", "c": "include:a\n"}, want: "include cycle: a > b > c > a"},
		"self cycle":   {files: map[string]string{"a": "x.com\ninclude:a\n"}, want: "include cycle"},
		"missing":      {files: map[string]string{"a": "x.com\ninclude:gone\n"}, want: "missing include gone (from a)"},
		"depth":        {files: map[string]string{"a": "include:b\n", "b": "include:c\n", "c": "z.com\n"}, lim: Limits{MaxDepth: 1}, want: "depth"},
		"files":        {files: map[string]string{"a": "include:b\ninclude:c\n", "b": "b.com\n", "c": "c.com\n"}, lim: Limits{MaxFiles: 2}, want: "more than 2 files"},
		"entries":      {files: map[string]string{"a": "a.com\ninclude:b\n", "b": "b.com\nc.com\n"}, lim: Limits{MaxEntries: 2}, want: "more than 2 entries"},
		"missing root": {files: map[string]string{}, want: "not found"},
	}
	for name, tc := range cases {
		_, err := Expand("a", parsed(t, tc.files), tc.lim)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
	// A diamond is not a cycle.
	if _, err := Expand("a", parsed(t, map[string]string{"a": "include:b\ninclude:c\n", "b": "include:d\n", "c": "include:d\n", "d": "d.com\n"}), Limits{}); err != nil {
		t.Fatal(err)
	}
}

func TestParsePrefixes(t *testing.T) {
	ok := "1.0.1.0/24\n# c\n1.0.2.0/23\n\n36.0.0.0/10\n"
	if ps, err := ParsePrefixes(true, []byte(ok), 3); err != nil || len(ps) != 3 {
		t.Fatalf("%v %v", err, ps)
	}
	for name, tc := range map[string]struct {
		v4   bool
		body string
	}{
		"html":       {true, "<html>\n"},
		"empty":      {true, ""},
		"too few":    {true, "1.0.1.0/24\n"},
		"family":     {true, "1.0.1.0/24\n2400:3200::/32\n1.0.2.0/23\n"},
		"host bits":  {true, "1.0.1.1/24\n1.0.2.0/23\n1.0.4.0/22\n"},
		"default":    {true, "0.0.0.0/0\n1.0.2.0/23\n1.0.4.0/22\n"},
		"half":       {true, "128.0.0.0/1\n1.0.2.0/23\n1.0.4.0/22\n"},
		"private":    {true, "192.168.0.0/24\n1.0.2.0/23\n1.0.4.0/22\n"},
		"truncated":  {true, "1.0.1.0/24\n1.0.2.0/23\n1.0.4.\n"},
		"ula":        {false, "fd00::/8\n2400:3200::/32\n240e::/20\n"},
		"v6 default": {false, "::/0\n2400:3200::/32\n240e::/20\n"},
		"v6 too big": {false, "2000::/3\n2400:3200::/32\n240e::/20\n"},
	} {
		if _, err := ParsePrefixes(tc.v4, []byte(tc.body), 3); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Too much address space in total.
	var sb strings.Builder
	for i := 1; i < 60; i++ {
		if i == 10 || i == 100 || i == 127 {
			continue
		}
		fmt.Fprintf(&sb, "%d.0.0.0/8\n", i)
	}
	if _, err := ParsePrefixes(true, []byte(sb.String()), 3); err == nil || !strings.Contains(err.Error(), "covers") {
		t.Fatalf("oversized coverage: %v", err)
	}
}

// ------------------------------------------------- synthetic sources ---

// mirror is a local source: files by path, plus failure modes.
type mirror struct {
	mu    sync.Mutex
	files map[string]string
	mode  map[string]string // path -> 404 | 500 | html | slow
	hits  []string
}

func (m *mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.hits = append(m.hits, r.URL.Path)
	body, ok := m.files[r.URL.Path]
	mode := m.mode[r.URL.Path]
	if mode == "" {
		mode = m.mode["*"]
	}
	m.mu.Unlock()
	switch {
	case mode == "500":
		w.WriteHeader(500)
		return
	case mode == "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><body>captive portal</body></html>")
		return
	case mode == "htmlplain":
		fmt.Fprint(w, "<html><body>captive portal</body></html>")
		return
	case mode == "truncate":
		w.Header().Set("Content-Length", "100000")
		fmt.Fprint(w, body)
		return
	case mode == "slow":
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		return
	case mode == "404" || !ok:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, body)
}

func (m *mirror) set(path, mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == nil {
		m.mode = map[string]string{}
	}
	m.mode[path] = mode
}

func (m *mirror) hit(prefix string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range m.hits {
		if strings.HasPrefix(h, prefix) {
			return true
		}
	}
	return false
}

func chinaFixture(v4 bool, n int, salt int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		if v4 {
			fmt.Fprintf(&sb, "%d.%d.%d.0/24\n", 36+salt, i/256, i%256)
		} else {
			fmt.Fprintf(&sb, "2400:%x::/32\n", 0x3200+i+salt*0x100)
		}
	}
	return sb.String()
}

// fixture: two sources with distinguishable content (the domestic one
// says "dom", the overseas one "ovs").
func fixture(t *testing.T) (*mirror, *mirror, *Updater, *[]string) {
	t.Helper()
	files := func(tag string, salt int) map[string]string {
		return map[string]string{
			"/data/cn":             "# for geosite:cn\ninclude:tld-cn\ninclude:geolocation-cn\n",
			"/data/tld-cn":         "cn\n",
			"/data/geolocation-cn": tag + "-baidu.com\ninclude:jd @-!cn\n",
			"/data/jd":             tag + "-jd.com\njd.hk @!cn\n",
			"/data/apple":          tag + "-apple.com\napple.cn @cn\n",
			"/ip/china.txt":        chinaFixture(true, 20, salt),
			"/ip/china6.txt":       chinaFixture(false, 10, salt),
		}
	}
	dom := &mirror{files: files("dom", 0)}
	ovs := &mirror{files: files("ovs", 1)}
	ds, os_ := httptest.NewServer(dom), httptest.NewServer(ovs)
	t.Cleanup(ds.Close)
	t.Cleanup(os_.Close)
	var loads []string
	u := &Updater{
		Dir: t.TempDir(),
		Get: &Fetcher{Client: ds.Client(), FileTimeout: time.Second, Retries: -1},
		Sources: func(p Policy) ([]Source, error) {
			srcs := map[string]Source{
				SourceDomestic: {Name: SourceDomestic, GeositeBase: ds.URL + "/data", ChnrouteBase: ds.URL + "/ip"},
				SourceOverseas: {Name: SourceOverseas, GeositeBase: os_.URL + "/data", ChnrouteBase: os_.URL + "/ip"},
			}
			var out []Source
			for _, s := range Order(p) {
				out = append(out, srcs[s.Name])
			}
			return out, nil
		},
		LoadNFT: func(_ context.Context, path string) error {
			b, err := os.ReadFile(path)
			loads = append(loads, string(b))
			return err
		},
		MinChnroute4: 5, MinChnroute6: 5,
	}
	return dom, ovs, u, &loads
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func result(rep Report, list string) ListResult {
	for _, l := range rep.Lists {
		if l.List == list {
			return l
		}
	}
	return ListResult{}
}

func TestUpdateDomesticExpandsCN(t *testing.T) {
	_, ovs, u, loads := fixture(t)
	rep := u.Run(context.Background(), Request{Policy: PolicyDomestic, Geosite: []string{"cn", "apple"}, Keywords: []Keyword{{ID: "r_jd", Value: "JD"}}, Chnroute: true})
	if !rep.OK || rep.Partial || rep.Error != "" {
		t.Fatalf("%+v", rep)
	}
	if got := read(t, filepath.Join(u.Dir, "geosite", "cn.txt")); got != "cn\ndom-baidu.com\ndom-jd.com\n" {
		t.Fatalf("cn.txt = %q", got)
	}
	cn := result(rep, "geosite:cn")
	if cn.Source != SourceDomestic || cn.Count != 3 || cn.Files != 4 || cn.Current == nil || cn.Current.Source != SourceDomestic {
		t.Fatalf("cn result %+v", cn)
	}
	if got := read(t, filepath.Join(u.Dir, "keywords", "r_jd.txt")); got != "dom-jd.com\n" {
		t.Fatalf("keyword list %q", got)
	}
	if !rep.DNSChanged {
		t.Fatal("DNSChanged not set")
	}
	if ovs.hit("/") {
		t.Fatal("domestic policy contacted the overseas source")
	}
	if len(*loads) != 1 || !strings.Contains((*loads)[0], "flush set inet meridian chnroute\n") || !strings.Contains((*loads)[0], "flush set inet meridian chnroute6\n") {
		t.Fatalf("want both families in one nft batch: %q", *loads)
	}
	saved := read(t, SavedBatchPath(u.Dir))
	if saved != (*loads)[0] {
		t.Fatal("saved reload copy differs from the loaded batch")
	}
	st, err := ReadStatus(u.Dir)
	if err != nil || st.Published["chnroute6"].Source != SourceDomestic || st.Last == nil {
		t.Fatalf("status %v %+v", err, st)
	}
}

func TestAutomaticFallsBackPerList(t *testing.T) {
	for _, mode := range []string{"500", "html", "htmlplain", "404", "slow", "truncate"} {
		t.Run(mode, func(t *testing.T) {
			dom, _, u, _ := fixture(t)
			dom.set("/data/jd", mode)       // a nested include fails on domestic
			dom.set("/ip/china6.txt", mode) // and one chnroute family
			start := time.Now()
			rep := u.Run(context.Background(), Request{Policy: PolicyAutomatic, Geosite: []string{"cn", "apple"}, Chnroute: true})
			if time.Since(start) > 8*time.Second {
				t.Fatalf("not bounded: %s", time.Since(start))
			}
			if !rep.OK {
				t.Fatalf("%+v", rep)
			}
			// The whole cn closure comes from one source: no mix.
			if got := read(t, filepath.Join(u.Dir, "geosite", "cn.txt")); got != "cn\novs-baidu.com\novs-jd.com\n" {
				t.Fatalf("cn.txt mixes sources or is wrong: %q", got)
			}
			cn := result(rep, "geosite:cn")
			if cn.Source != SourceOverseas || len(cn.Attempts) != 2 || cn.Attempts[0].OK || cn.Attempts[0].Error == "" {
				t.Fatalf("cn %+v", cn)
			}
			if a := result(rep, "geosite:apple"); a.Source != SourceDomestic {
				t.Fatalf("apple did not stay on domestic: %+v", a)
			}
			if c := result(rep, "chnroute6"); c.Source != SourceOverseas {
				t.Fatalf("chnroute6 %+v", c)
			}
			if c := result(rep, "chnroute4"); c.Source != SourceDomestic {
				t.Fatalf("chnroute4 %+v", c)
			}
		})
	}
}

func TestFailureKeepsPreviousVersion(t *testing.T) {
	dom, _, u, loads := fixture(t)
	if r := u.Run(context.Background(), Request{Policy: PolicyDomestic, Geosite: []string{"cn"}, Chnroute: true}); !r.OK {
		t.Fatalf("seed: %+v", r)
	}
	cnBefore := read(t, filepath.Join(u.Dir, "geosite", "cn.txt"))
	chinaBefore := read(t, filepath.Join(u.Dir, "lists", "china.txt"))
	savedBefore := read(t, SavedBatchPath(u.Dir))
	*loads = nil

	dom.set("/data/jd", "404")       // missing include
	dom.set("/ip/china.txt", "html") // HTML page
	dom.set("/ip/china6.txt", "404")
	rep := u.Run(context.Background(), Request{Policy: PolicyDomestic, Geosite: []string{"cn", "newlist"}, Chnroute: true})
	if rep.OK || rep.Partial {
		t.Fatalf("%+v", rep)
	}
	cn := result(rep, "geosite:cn")
	if !cn.Kept || cn.Updated || !strings.Contains(cn.Error, "missing include jd") || cn.Current == nil || cn.Current.Count != 3 {
		t.Fatalf("cn %+v", cn)
	}
	if got := read(t, filepath.Join(u.Dir, "geosite", "cn.txt")); got != cnBefore {
		t.Fatalf("cn.txt replaced: %q", got)
	}
	// A list that never existed is created empty so SmartDNS starts.
	if got := read(t, filepath.Join(u.Dir, "geosite", "newlist.txt")); got != "" {
		t.Fatalf("newlist %q", got)
	}
	if len(*loads) != 0 {
		t.Fatalf("nft called after failed downloads: %q", *loads)
	}
	if read(t, filepath.Join(u.Dir, "lists", "china.txt")) != chinaBefore || read(t, SavedBatchPath(u.Dir)) != savedBefore {
		t.Fatal("saved China list or reload copy changed")
	}
	st, _ := ReadStatus(u.Dir)
	if st.Published["geosite:cn"].Count != 3 || st.Last == nil || st.Last.OK {
		t.Fatalf("status %+v", st)
	}
}

func TestNFTFailureAndShrinkKeepSets(t *testing.T) {
	dom, _, u, _ := fixture(t)
	u.LoadNFT = func(context.Context, string) error { return errors.New("syntax error") }
	rep := u.Run(context.Background(), Request{Policy: PolicyDomestic, Chnroute: true})
	if rep.OK || !strings.Contains(result(rep, "chnroute4").Error, "nft rejected") {
		t.Fatalf("%+v", rep)
	}
	for _, p := range []string{filepath.Join(u.Dir, "lists", "china.txt"), SavedBatchPath(u.Dir)} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s written although nft failed", p)
		}
	}
	// Shrink guard: a sizeable list does not get replaced by a stub.
	_, _, u2, loads := fixture(t)
	u2.Get = u.Get
	big := chinaFixture(true, 400, 0)
	if err := os.MkdirAll(filepath.Join(u2.Dir, "lists"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u2.Dir, "lists", "china.txt"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	u2.Sources = u.Sources
	dom.set("/ip/china6.txt", "404")
	rep = u2.Run(context.Background(), Request{Policy: PolicyDomestic, Chnroute: true})
	if r := result(rep, "chnroute4"); r.Updated || !strings.Contains(r.Error, "shrink") {
		t.Fatalf("shrink accepted: %+v", r)
	}
	if len(*loads) != 0 {
		t.Fatal("nft called")
	}
}

func TestLockFailurePublishesNothing(t *testing.T) {
	_, _, u, loads := fixture(t)
	u.Lock = func(context.Context) (func(), error) { return nil, errors.New("install running") }
	rep := u.Run(context.Background(), Request{Policy: PolicyDomestic, Geosite: []string{"cn"}, Chnroute: true})
	if rep.OK || !strings.Contains(rep.Error, "install running") || len(*loads) != 0 {
		t.Fatalf("%+v", rep)
	}
	if _, err := os.Stat(filepath.Join(u.Dir, "geosite", "cn.txt")); err == nil {
		t.Fatal("published without the lock")
	}
	for _, l := range rep.Lists {
		if !l.Kept || l.Error == "" {
			t.Fatalf("%+v", l)
		}
	}
}

func TestFetcherBoundsAndShape(t *testing.T) {
	m := &mirror{files: map[string]string{"/ok": "a.com\n", "/big": strings.Repeat("a.com\n", 100)}}
	m.set("/slow", "slow")
	m.set("/html", "html")
	m.set("/trunc", "truncate")
	m.files["/trunc"] = "a.com\n"
	srv := httptest.NewServer(m)
	defer srv.Close()
	f := &Fetcher{Client: srv.Client(), FileTimeout: 300 * time.Millisecond, Retries: -1, MaxBytes: 64}
	if b, err := f.Get(context.Background(), srv.URL+"/ok"); err != nil || string(b) != "a.com\n" {
		t.Fatalf("%v %q", err, b)
	}
	start := time.Now()
	if _, err := f.Get(context.Background(), srv.URL+"/slow"); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("slow: %v after %s", err, time.Since(start))
	}
	for _, p := range []string{"/html", "/big", "/trunc"} {
		if _, err := f.Get(context.Background(), srv.URL+p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	if _, err := f.Get(context.Background(), srv.URL+"/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
}
