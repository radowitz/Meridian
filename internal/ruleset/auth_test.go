package ruleset

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestSplitSecretAndRedact(t *testing.T) {
	for _, c := range []struct {
		in, clean, kind string
	}{
		{"https://rules.example.org/a.list", "https://rules.example.org/a.list", ""},
		{"https://rules.example.org/a.list?raw=1", "https://rules.example.org/a.list?raw=1", ""},
		{"https://rules.example.org/a.list?raw=1&token=fake-t-1#frag", "https://rules.example.org/a.list?raw=1", AuthQuery},
		{"https://rules.example.org/a.list?Access_Token=fake-t-2", "https://rules.example.org/a.list", AuthQuery},
		{"https://user:fake-pw-3@rules.example.org/a.list", "https://rules.example.org/a.list", AuthBasic},
	} {
		clean, a, err := SplitSecret(c.in)
		if err != nil || clean != c.clean || (a == nil) != (c.kind == "") || (a != nil && a.Kind != c.kind) {
			t.Errorf("%s: %q %+v %v", c.in, clean, a, err)
		}
		if HasSecret(clean) {
			t.Errorf("%s: clean URL still has a secret", c.in)
		}
		if (c.kind != "") != HasSecret(c.in) {
			t.Errorf("%s: HasSecret", c.in)
		}
		if (c.kind != "") != errors.Is(CheckURL(c.in), ErrURLSecret) {
			t.Errorf("%s: CheckURL %v", c.in, CheckURL(c.in))
		}
	}
	if _, a, _ := SplitSecret("https://rules.example.org/a.list?raw=1&token=fake-t-1"); a.Query != "token=fake-t-1" {
		t.Errorf("query %q", a.Query)
	}
	if _, _, err := SplitSecret("https://u:p@rules.example.org/a?token=x1234"); err == nil {
		t.Error("userinfo and token together accepted")
	}
	for in, want := range map[string]string{
		"https://u:pw@rules.example.org/a.list?token=x#f": "https://rules.example.org/a.list?…",
		"https://rules.example.org/a.list":                "https://rules.example.org/a.list",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%s) = %s", in, got)
		}
	}
	// CheckURL's message never quotes the URL.
	if err := CheckURL("https://rules.example.org/a?token=fake-t-9"); err == nil || strings.Contains(err.Error(), "fake-t-9") {
		t.Errorf("CheckURL: %v", err)
	}
	for _, a := range []*Auth{{Kind: AuthBearer}, {Kind: AuthBearer, Token: "has space"}, {Kind: AuthBasic, Username: "a:b", Password: "x"}, {Kind: AuthQuery, Query: "noequals#"}, {Kind: "cookie"}} {
		if a.Check() == nil {
			t.Errorf("%+v accepted", a.Kind)
		}
	}
}

// The credential reaches the configured origin only, only over https, is
// dropped on a redirect to another origin, and never appears in an error.
func TestFetchAuthOriginOnly(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // path -> Authorization + "|" + query
	record := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[name+r.URL.Path] = r.Header.Get("Authorization") + "|" + r.URL.RawQuery
			mu.Unlock()
			switch r.URL.Path {
			case "/fail":
				http.Error(w, "nope", http.StatusForbidden)
			default:
				fmt.Fprint(w, "DOMAIN-SUFFIX,example.com\n")
			}
		}
	}
	other := httptest.NewTLSServer(record("other"))
	defer other.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
			return
		}
		record("origin")(w, r)
	}))
	defer origin.Close()
	// One transport trusting both test certificates.
	tr := origin.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.RootCAs.AddCert(other.Certificate())

	tok := "fake-bearer-5d4c3b"
	f := &Fetcher{Transport: tr, Auth: &Auth{Kind: AuthBearer, Token: tok}, AuthOrigin: Origin(origin.URL + "/x.list")}
	if _, err := f.Get(context.Background(), origin.URL+"/x.list"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(context.Background(), other.URL+"/mirror.list"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(context.Background(), origin.URL+"/away"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if seen["origin/x.list"] != "Bearer "+tok+"|" {
		t.Errorf("origin got %q", seen["origin/x.list"])
	}
	if seen["other/mirror.list"] != "|" {
		t.Errorf("another origin got the credential: %q", seen["other/mirror.list"])
	}
	if seen["other/landed"] != "|" {
		t.Errorf("redirect target got the credential: %q", seen["other/landed"])
	}
	mu.Unlock()

	// Query credential: appended for the origin only; errors never show it.
	q := &Fetcher{Transport: tr, Auth: &Auth{Kind: AuthQuery, Query: "token=fake-q-8e7f6a"}, AuthOrigin: Origin(origin.URL)}
	if _, err := q.Get(context.Background(), origin.URL+"/q.list?raw=1"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if seen["origin/q.list"] != "|raw=1&token=fake-q-8e7f6a" {
		t.Errorf("query credential: %q", seen["origin/q.list"])
	}
	mu.Unlock()
	if _, err := q.Get(context.Background(), origin.URL+"/fail"); err == nil || strings.Contains(err.Error(), "fake-q-8e7f6a") {
		t.Errorf("error: %v", err)
	}
	// A transport failure (url.Error quotes the URL) is redacted.
	dead := &Fetcher{Transport: tr, Auth: &Auth{Kind: AuthQuery, Query: "token=fake-q-8e7f6a"}, AuthOrigin: "https://127.0.0.1:1"}
	if _, err := dead.Get(context.Background(), "https://127.0.0.1:1/x.list?k=public"); err == nil || strings.Contains(err.Error(), "fake-q-8e7f6a") || strings.Contains(err.Error(), "k=public") {
		t.Errorf("transport error: %v", err)
	}
	// Never over plain http.
	plain := &Fetcher{Auth: &Auth{Kind: AuthBearer, Token: tok}, AuthOrigin: "http://rules.example.org"}
	if _, err := plain.Get(context.Background(), "http://rules.example.org/x.list"); err == nil || !strings.Contains(err.Error(), "https") || strings.Contains(err.Error(), tok) {
		t.Errorf("http with credential: %v", err)
	}
}

// The gateway's own and internal ranges stay refused even when the
// rule-set allows a LAN source; other private addresses are then allowed.
func TestAddrAllowedDeny(t *testing.T) {
	deny := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("10.66.0.0/16")}
	if AddrAllowedDeny(netip.MustParseAddr("192.0.2.1"), true, deny) == nil {
		t.Error("gateway LAN address allowed with AllowLAN")
	}
	if AddrAllowedDeny(netip.MustParseAddr("10.66.3.2"), true, deny) == nil {
		t.Error("tunnel address allowed with AllowLAN")
	}
	if AddrAllowedDeny(netip.MustParseAddr("10.1.2.3"), true, deny) != nil {
		t.Error("other LAN address refused with AllowLAN")
	}
	if AddrAllowedDeny(netip.MustParseAddr("10.1.2.3"), false, deny) == nil {
		t.Error("LAN address allowed without AllowLAN")
	}
	if AddrAllowedDeny(netip.MustParseAddr("198.51.100.1"), false, deny) != nil {
		t.Error("public refused")
	}
	// Connect-time: a name resolving into a denied range is refused (the
	// guard sees the address actually dialled).
	f := &Fetcher{AllowLAN: true, Deny: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	if _, err := f.Get(context.Background(), "http://127.0.0.1:9/x.list"); !errors.Is(err, ErrBlocked) {
		t.Errorf("denied address dialled: %v", err)
	}
}
