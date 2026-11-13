package ruleset

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/ordered"
)

func entries(p Parsed) string {
	var s []string
	for _, e := range p.Entries {
		s = append(s, e.String())
	}
	return strings.Join(s, " ")
}

func TestParseFormats(t *testing.T) {
	cases := []struct {
		name, data, behavior, file, format, want string
		unsupported                              map[string]int
	}{
		{"clash classical yaml", "payload:\n  - DOMAIN-SUFFIX,Example.COM\n  - 'DOMAIN,api.example.org'\n  - DOMAIN-KEYWORD,vendor\n  - IP-CIDR,198.51.100.0/24,no-resolve\n  - IP-CIDR6,2001:DB8::/32\n  - PROCESS-NAME,app.exe\n  - USER-AGENT,Foo*\n  - IP-ASN,64496\n  - DST-PORT,443\n", "", "x.yaml",
			FormatClashClassical, "suffix:example.com exact:api.example.org keyword:vendor cidr:198.51.100.0/24 cidr:2001:db8::/32",
			map[string]int{"PROCESS-NAME": 1, "USER-AGENT": 1, "IP-ASN": 1, "DST-PORT": 1}},
		{"clash domain yaml", "payload:\n  - '+.example.com'\n  - '.sub.example.net'\n  - 'host.example.org'\n  - '*.one.example'\n  - 'a*b.example'\n", "", "x.yaml",
			FormatClashDomain, "suffix:example.com sub:sub.example.net exact:host.example.org",
			map[string]int{"wildcard-one-label": 1, "wildcard": 1}},
		{"clash ipcidr yaml", "payload:\n  - 198.51.100.0/24\n  - '2001:db8:1::/48'\n  - 203.0.113.9\n", "", "x.yaml",
			FormatClashIPCIDR, "cidr:198.51.100.0/24 cidr:2001:db8:1::/48 cidr:203.0.113.9/32", nil},
		{"clash text classical with CRLF and BOM", "\xef\xbb\xbf# comment\r\nDOMAIN-SUFFIX,example.com\r\n\r\ndomain,a.example.org\r\n", "classical", "x.txt",
			FormatClashTextClassic, "suffix:example.com exact:a.example.org", nil},
		{"clash text domain", "+.example.com\n.example.net\nexample.org\n", "domain", "x.txt",
			FormatClashTextDomain, "suffix:example.com sub:example.net exact:example.org", nil},
		{"clash text ipcidr", "198.51.100.0/24\n2001:db8::/32\n", "ipcidr", "x.txt",
			FormatClashTextIPCIDR, "cidr:198.51.100.0/24 cidr:2001:db8::/32", nil},
		{"surge list with policy fields and comments", "# c\n// c2\nDOMAIN-SUFFIX,example.com,Proxy\nDOMAIN,host.example.org // trailing\nDOMAIN-WILDCARD,*.wild.example\nDOMAIN-WILDCARD,a?.example\nIP-CIDR,198.51.100.0/24,no-resolve\nURL-REGEX,^http://x\nAND,((DOMAIN,a),(NETWORK,UDP))\nip-cidr6,2001:db8::/32,DIRECT,no-resolve\n", "", "x.list",
			FormatSurgeList, "suffix:example.com exact:host.example.org sub:wild.example cidr:198.51.100.0/24 cidr:2001:db8::/32",
			map[string]int{"DOMAIN-WILDCARD": 1, "URL-REGEX": 1, "AND": 1}},
		{"surge domain set", "example.com\n.example.net\n# c\n", "", "x.txt",
			FormatSurgeDomainSet, "exact:example.com suffix:example.net", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse([]byte(c.data), "", c.behavior, c.file)
			if err != nil {
				t.Fatal(err)
			}
			if p.Format != c.format {
				t.Fatalf("format %s, want %s", p.Format, c.format)
			}
			if got := entries(p); got != c.want {
				t.Fatalf("entries\n got %s\nwant %s", got, c.want)
			}
			for k, v := range c.unsupported {
				if p.Unsupported[k] != v {
					t.Errorf("unsupported[%s] = %d, want %d (%v)", k, p.Unsupported[k], v, p.Unsupported)
				}
			}
		})
	}
}

func TestParseSurgeNotes(t *testing.T) {
	p, err := Parse([]byte("DOMAIN-SUFFIX,example.com,Proxy\nIP-CIDR,198.51.100.0/24,no-resolve\nDOMAIN-KEYWORD,kw\n"), FormatSurgeList, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.PolicyIgnored != 1 || p.NoResolve != 1 || p.Counts["keyword"] != 1 || len(p.Notes) != 3 {
		t.Fatalf("%+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := Parse([]byte{0x28, 0xb5, 0x2f, 0xfd, 1, 2}, "", "", "x.mrs"); !errors.Is(err, ErrMRS) {
		t.Fatalf("mrs: %v", err)
	}
	big := strings.Repeat("a", MaxBytes+1)
	if _, err := Parse([]byte(big), "", "", ""); err == nil {
		t.Fatal("oversized accepted")
	}
	if _, err := Parse([]byte("x\x00y"), "", "", ""); err == nil {
		t.Fatal("binary accepted")
	}
	if _, err := Parse([]byte("payload: [\n"), FormatClashClassical, "", ""); err == nil {
		t.Fatal("broken yaml accepted")
	}
}

func TestNormalizedRoundTrip(t *testing.T) {
	p, err := Parse([]byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,example.com\n  - DOMAIN-KEYWORD,kw\n  - IP-CIDR,198.51.100.7/24\n"), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b := ordered.MarshalEntries(p.Entries)
	back, err := ordered.UnmarshalEntries(b)
	if err != nil || len(back) != 4 {
		t.Fatalf("%v %v", back, err)
	}
	for _, bad := range []string{"exec rm -rf\n", "suffix ../x\n", "cidr 198.51.100.7/24\n"} {
		if _, err := ordered.UnmarshalEntries([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestGitHubRawAndCandidates(t *testing.T) {
	u := "https://mirror.example.net/https://raw.githubusercontent.com/org/repo/main/rules/Some%20Set.yaml"
	org, repo, ref, file, ok := GitHubRaw(u)
	if !ok || org != "org" || repo != "repo" || ref != "main" || file != "rules/Some%20Set.yaml" {
		t.Fatal(org, repo, ref, file, ok)
	}
	if _, _, ref, _, ok := GitHubRaw("https://raw.githubusercontent.com/o/r/refs/heads/dev/a.list"); !ok || ref != "dev" {
		t.Fatal("refs/heads form")
	}
	c := Candidates(u, SourcePolicy, lists.PolicyAutomatic)
	if len(c) != 3 || c[0].Source != "domestic" || !strings.HasPrefix(c[0].URL, "https://cdn.jsdelivr.net/gh/org/repo@main/") || c[1].Source != "overseas" || c[2].URL != u {
		t.Fatalf("%+v", c)
	}
	if c := Candidates(u, SourceURL, lists.PolicyAutomatic); len(c) != 1 || c[0].URL != u {
		t.Fatalf("%+v", c)
	}
	if c := Candidates("https://example.org/x.list", SourcePolicy, lists.PolicyDomestic); len(c) != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestAddrAllowed(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "169.254.1.1", "fe80::1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "100.64.0.1", "fd00::1", "0.0.0.0", "224.0.0.1"} {
		if AddrAllowed(netip.MustParseAddr(s), false) == nil {
			t.Errorf("%s allowed", s)
		}
	}
	if AddrAllowed(netip.MustParseAddr("10.1.2.3"), true) != nil {
		t.Error("LAN source not allowed with AllowLAN")
	}
	if AddrAllowed(netip.MustParseAddr("127.0.0.1"), true) == nil {
		t.Error("loopback allowed with AllowLAN")
	}
	if AddrAllowed(netip.MustParseAddr("198.51.100.1"), false) != nil {
		t.Error("public refused")
	}
}

// A public-looking source (the test server, admitted by the guard) that
// redirects to a private address or to loopback is refused at connect time.
func TestFetchRedirectToPrivateRefused(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "DOMAIN,secret.example\n") }))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-private":
			http.Redirect(w, r, "http://10.255.0.1:"+strings.Split(inner.Listener.Addr().String(), ":")[1]+"/", http.StatusFound)
		case "/to-loopback":
			http.Redirect(w, r, inner.URL+"/", http.StatusFound)
		case "/big":
			fmt.Fprint(w, strings.Repeat("a", 2048))
		default:
			fmt.Fprint(w, "DOMAIN-SUFFIX,example.com\n")
		}
	}))
	defer outer.Close()
	allowed := netip.MustParseAddrPort(outer.Listener.Addr().String())
	f := &Fetcher{Guard: func(ap netip.AddrPort) error {
		if ap == allowed {
			return nil
		}
		return AddrAllowed(ap.Addr(), false)
	}, MaxBytes: 1024}
	if b, err := f.Get(context.Background(), outer.URL+"/ok"); err != nil || !strings.Contains(string(b), "example.com") {
		t.Fatalf("ok: %v", err)
	}
	for _, p := range []string{"/to-private", "/to-loopback"} {
		if _, err := f.Get(context.Background(), outer.URL+p); err == nil || !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := f.Get(context.Background(), outer.URL+"/big"); err == nil {
		t.Error("oversized download accepted")
	}
	// Default guard: the loopback test server itself is refused.
	if _, err := (&Fetcher{}).Get(context.Background(), outer.URL+"/ok"); !errors.Is(err, ErrBlocked) {
		t.Errorf("loopback source: %v", err)
	}
	for _, u := range []string{"ftp://example.org/x", "https://user:pw@example.org/x", "https://exa mple.org/"} {
		if _, err := f.Get(context.Background(), u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

var _ = ordered.Exact
