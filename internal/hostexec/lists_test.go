package hostexec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/lists"
)

func TestValidateListsRequest(t *testing.T) {
	ok := ListsRequest{RequestID: "lists-1", Policy: "automatic", Lists: []string{"geosite", "chnroute"},
		Geosite: []string{"cn", "geolocation-!cn", "category-ads-all"}, Keywords: []lists.Keyword{{ID: "r_x", Value: "Example.co"}}}
	if err := ValidateLists(ok); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLists(ListsRequest{RequestID: "x", Policy: "overseas", Lists: []string{"chnroute"}}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*ListsRequest){
		"policy empty":      func(r *ListsRequest) { r.Policy = "" },
		"policy url":        func(r *ListsRequest) { r.Policy = "https://evil.example/" },
		"no lists":          func(r *ListsRequest) { r.Lists = nil },
		"unknown list":      func(r *ListsRequest) { r.Lists = []string{"geoip"} },
		"duplicate list":    func(r *ListsRequest) { r.Lists = []string{"geosite", "geosite"} },
		"geosite missing":   func(r *ListsRequest) { r.Geosite = nil },
		"names w/o geosite": func(r *ListsRequest) { r.Lists = []string{"chnroute"} },
		"path name":         func(r *ListsRequest) { r.Geosite = []string{"../../etc/passwd"} },
		"url name":          func(r *ListsRequest) { r.Geosite = []string{"https://x"} },
		"upper name":        func(r *ListsRequest) { r.Geosite = []string{"CN"} },
		"slash name":        func(r *ListsRequest) { r.Geosite = []string{"a/b"} },
		"file collision":    func(r *ListsRequest) { r.Geosite = []string{"a-b", "a!b"} },
		"duplicate name":    func(r *ListsRequest) { r.Geosite = []string{"cn", "cn"} },
		"keyword id path":   func(r *ListsRequest) { r.Keywords = []lists.Keyword{{ID: "../x", Value: "a"}} },
		"keyword shell":     func(r *ListsRequest) { r.Keywords = []lists.Keyword{{ID: "a", Value: "$(id)"}} },
		"keyword dup":       func(r *ListsRequest) { r.Keywords = []lists.Keyword{{ID: "a", Value: "x"}, {ID: "a", Value: "y"}} },
		"request id":        func(r *ListsRequest) { r.RequestID = "a b" },
		"too many": func(r *ListsRequest) {
			r.Geosite = nil
			for i := 0; i <= maxCategories; i++ {
				r.Geosite = append(r.Geosite, fmt.Sprintf("l%d", i))
			}
		},
	}
	for name, mut := range bad {
		r := ok
		r.Lists = append([]string(nil), ok.Lists...)
		mut(&r)
		if err := ValidateLists(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Unknown fields (a URL, a path) are refused by the decoder.
	f := newFakeHost()
	a := newAgent(f)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	for _, body := range []string{
		`{"request_id":"x","policy":"domestic","lists":["chnroute"],"url":"http://evil/"}`,
		`{"request_id":"x","policy":"domestic","lists":["chnroute"],"dir":"/etc"}`,
	} {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/lists", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status %d", body, resp.StatusCode)
		}
	}
	// No token, no update.
	resp, err := http.Post(srv.URL+"/v1/lists", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || len(f.commands()) != 0 {
		t.Fatalf("status %d cmds %v", resp.StatusCode, f.commands())
	}
}

// listsAgent: a fake host with inet meridian loaded and a SmartDNS unit,
// and one local source serving everything.
func listsAgent(t *testing.T, handler http.Handler) (*fakeHost, *Agent) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	f := newFakeHost()
	f.nft["inet meridian"] = true
	f.dns = "unit"
	a := newAgent(f)
	a.ListsDir = t.TempDir()
	a.LockWait = 200 * time.Millisecond
	a.ListsGetter = &lists.Fetcher{Client: srv.Client(), FileTimeout: time.Second, Retries: -1}
	a.ListsSources = func(p lists.Policy) ([]lists.Source, error) {
		return []lists.Source{{Name: lists.SourceDomestic, GeositeBase: srv.URL + "/data", ChnrouteBase: srv.URL + "/ip"}}, nil
	}
	return f, a
}

func listsMux(china string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/cn", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "include:geolocation-cn\n") })
	mux.HandleFunc("/data/geolocation-cn", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "baidu.com\n") })
	mux.HandleFunc("/ip/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, china) })
	return mux
}

func TestListsUpdatePublishesUnderLockAndRestartsDNS(t *testing.T) {
	var v4 strings.Builder
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&v4, "36.%d.%d.0/24\n", i/256, i%256)
	}
	f, a := listsAgent(t, listsMux(v4.String()))
	rep, code := a.UpdateLists(context.Background(), ListsRequest{RequestID: "u1", Policy: "domestic", Lists: []string{"geosite", "chnroute"}, Geosite: []string{"cn"}})
	if code != http.StatusOK {
		t.Fatalf("%d %+v", code, rep)
	}
	if b, _ := os.ReadFile(filepath.Join(a.ListsDir, "geosite", "cn.txt")); string(b) != "baidu.com\n" {
		t.Fatalf("cn.txt %q", b)
	}
	// IPv4 loaded through one fixed nft -f on a derived path; china6 (the
	// same body) is the wrong family and is kept.
	if f.ran("nft -f "+filepath.Join(a.ListsDir, "lists")) != 1 || f.ran("nft list table inet meridian") != 1 {
		t.Fatalf("nft calls %v", f.commands())
	}
	if r := rep.Lists[len(rep.Lists)-1]; r.List != "chnroute6" || r.Updated || !r.Kept {
		t.Fatalf("chnroute6 %+v", r)
	}
	if !rep.Partial || rep.DNSRestart != "smartdns.service" || f.ran("systemctl restart smartdns.service") != 1 {
		t.Fatalf("%+v %v", rep, f.commands())
	}
	st, err := a.ListsStatus()
	if err != nil || st.Published["geosite:cn"].Source != lists.SourceDomestic || st.Last == nil {
		t.Fatalf("%v %+v", err, st)
	}
}

func TestListsUpdateWaitsForActionAndIsSingle(t *testing.T) {
	block := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/data/cn", func(w http.ResponseWriter, r *http.Request) {
		<-block
		fmt.Fprint(w, "baidu.com\n")
	})
	f, a := listsAgent(t, mux)
	a.ListsGetter = &lists.Fetcher{FileTimeout: 5 * time.Second, Retries: -1}
	a.init()
	req := ListsRequest{RequestID: "u2", Policy: "domestic", Lists: []string{"geosite"}, Geosite: []string{"cn"}}
	done := make(chan lists.Report, 1)
	go func() { rep, _ := a.UpdateLists(context.Background(), req); done <- rep }()
	time.Sleep(100 * time.Millisecond)
	// A second update while the first downloads: refused, nothing run.
	if _, code := a.UpdateLists(context.Background(), ListsRequest{RequestID: "u3", Policy: "domestic", Lists: []string{"chnroute"}}); code != http.StatusServiceUnavailable {
		t.Fatalf("second update: %d", code)
	}
	// An install holds the action lock across the publish: the update gives
	// up after LockWait and publishes nothing.
	a.sem <- struct{}{}
	close(block)
	rep := <-done
	<-a.sem
	if rep.OK || !strings.Contains(rep.Error, "等待超时") {
		t.Fatalf("%+v", rep)
	}
	if _, err := os.Stat(filepath.Join(a.ListsDir, "geosite", "cn.txt")); err == nil {
		t.Fatal("published while an action held the lock")
	}
	if f.ran("systemctl restart") != 0 {
		t.Fatalf("restarted DNS: %v", f.commands())
	}
	// The download phase itself did not hold the lock: the test could
	// take the semaphore while the download was still blocked.
}

// A chnroute update restarts meridian-dns-split and then SmartDNS (flushing
// answers made under the old lists) only when the installed config uses the
// check (unlisted_domestic_dns), and only when a list file actually changed.
func TestListsChnrouteRestartsDNSOnlyWhenItReadsTheLists(t *testing.T) {
	var v4 strings.Builder
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&v4, "36.%d.%d.0/24\n", i/256, i%256)
	}
	for _, c := range []struct {
		name    string
		conf    string
		restart bool
	}{
		{"config without China lists", "server 127.0.0.1\ndomain-set -name gs_cn -file /var/lib/meridian/geosite/cn.txt\n", false},
		{"config using dns-split", "server 223.5.5.5 -group domestic -exclude-default-group\nserver 127.0.0.1:5356 -group unlisted_split\n", true},
		{"no config", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, a := listsAgent(t, listsMux(v4.String()))
			a.SmartDNSConf = filepath.Join(t.TempDir(), "smartdns.conf")
			if c.conf != "" {
				if err := os.WriteFile(a.SmartDNSConf, []byte(c.conf), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			req := ListsRequest{RequestID: "c1", Policy: "domestic", Lists: []string{"chnroute"}}
			rep, code := a.UpdateLists(context.Background(), req)
			if code != http.StatusOK || !rep.ChnrouteChanged || rep.DNSChanged {
				t.Fatalf("%d %+v", code, rep)
			}
			if got := f.ran("systemctl restart smartdns.service"); got != map[bool]int{false: 0, true: 1}[c.restart] {
				t.Fatalf("restarts %d, want restart=%v: %v", got, c.restart, f.commands())
			}
			if got := f.ran("systemctl restart meridian-dns-split.service"); got != map[bool]int{false: 0, true: 1}[c.restart] {
				t.Fatalf("dns-split restarts %d, want restart=%v: %v", got, c.restart, f.commands())
			}
			// The same list again: nothing changed, no restart.
			req.RequestID = "c2"
			rep, _ = a.UpdateLists(context.Background(), req)
			if rep.ChnrouteChanged {
				t.Fatalf("unchanged list reported as changed: %+v", rep)
			}
			if got := f.ran("systemctl restart smartdns.service"); got != map[bool]int{false: 0, true: 1}[c.restart] {
				t.Fatalf("restarted for an unchanged list: %v", f.commands())
			}
		})
	}
}
