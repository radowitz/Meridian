package ruleset

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/radowitz/meridian/internal/lists"
)

// Source modes of a rule-set.
const (
	// SourceURL: only the URL exactly as the operator gave it.
	SourceURL = "url"
	// SourcePolicy: a GitHub raw file found in the URL (also behind an
	// acceleration prefix) is fetched through the panel's list source policy
	// (国内源 = jsDelivr, 海外源 = raw.githubusercontent.com, 全自动 = both in
	// that order), then the URL as given.
	SourcePolicy = "policy"
)

// Candidate is one URL to try.
type Candidate struct {
	Source string `json:"source"` // domestic, overseas, url
	URL    string `json:"url"`
}

// CheckURL accepts an absolute http(s) URL with a host, no credentials and
// no whitespace.
func CheckURL(s string) error {
	if len(s) > 2048 || strings.ContainsAny(s, " \t\r\n\"'`\\<>") {
		return errors.New("URL 含有空白、引号或过长")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("URL 必须是带主机名的 http:// 或 https://，不能带用户名密码")
	}
	return nil
}

// GitHubRaw extracts the GitHub file a URL points at: a
// raw.githubusercontent.com URL, possibly behind an acceleration prefix
// ("https://<mirror>/https://raw.githubusercontent.com/…"), or a
// github.com/<org>/<repo>/raw|blob/<ref>/<path> URL. ok is false otherwise.
func GitHubRaw(s string) (org, repo, ref, file string, ok bool) {
	for _, host := range []string{"raw.githubusercontent.com/", "github.com/"} {
		i := strings.LastIndex(s, "://"+host)
		if i < 0 {
			continue
		}
		rest := trimQuery(s[i+3+len(host):])
		seg := strings.Split(rest, "/")
		if host == "github.com/" {
			if len(seg) < 5 || (seg[2] != "raw" && seg[2] != "blob") {
				continue
			}
			seg = append(seg[:2], seg[3:]...)
		}
		if len(seg) >= 6 && seg[2] == "refs" && seg[3] == "heads" {
			seg = append([]string{seg[0], seg[1], seg[4]}, seg[5:]...)
		}
		if len(seg) < 4 {
			continue
		}
		for _, x := range seg {
			if x == "" || x == ".." || x == "." {
				return "", "", "", "", false
			}
		}
		return seg[0], seg[1], seg[2], strings.Join(seg[3:], "/"), true
	}
	return "", "", "", "", false
}

// Candidates is the ordered URL list for one fetch.
func Candidates(raw, mode string, p lists.Policy) []Candidate {
	var out []Candidate
	if mode == SourcePolicy {
		if org, repo, ref, file, ok := GitHubRaw(raw); ok {
			jsd := Candidate{Source: lists.SourceDomestic, URL: fmt.Sprintf("https://cdn.jsdelivr.net/gh/%s/%s@%s/%s", org, repo, ref, file)}
			gh := Candidate{Source: lists.SourceOverseas, URL: fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", org, repo, ref, file)}
			switch p {
			case lists.PolicyDomestic:
				out = append(out, jsd)
			case lists.PolicyOverseas:
				out = append(out, gh)
			default:
				out = append(out, jsd, gh)
			}
		}
	}
	for _, c := range out {
		if c.URL == raw {
			return out
		}
	}
	return append(out, Candidate{Source: SourceURL, URL: raw})
}

// Fetcher downloads one rule-set. It refuses, at connect time (so redirect
// targets are checked too), every address that is loopback, link-local,
// multicast, unspecified, private (RFC 1918, CGNAT 100.64/10, ULA fc00::/7)
// or one of this host's own addresses; private ranges only when AllowLAN is
// false. It uses no proxy from the environment, follows at most 5 redirects
// (http/https only), reads at most MaxBytes, and gives up after Timeout.
type Fetcher struct {
	Timeout  time.Duration
	MaxBytes int64
	AllowLAN bool
	// Guard replaces the address check (tests); nil = AddrAllowed.
	Guard func(netip.AddrPort) error
	// Transport replaces the dialer entirely (tests only).
	Transport http.RoundTripper
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// ownAddrs is this host's interface addresses.
func ownAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	as, _ := net.InterfaceAddrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}
	return out
}

// AddrAllowed is the default connect-time check.
func AddrAllowed(a netip.Addr, allowLAN bool) error {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified():
		return errors.New("未指定地址")
	case a.IsLoopback():
		return errors.New("回环地址")
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast(), a.IsInterfaceLocalMulticast():
		return errors.New("链路本地或组播地址")
	case a.Is4() && a.As4()[0] == 0:
		return errors.New("0.0.0.0/8")
	}
	if ownAddrs()[a] {
		return errors.New("本机地址")
	}
	if (a.IsPrivate() || cgnat.Contains(a)) && !allowLAN {
		return errors.New("局域网 / 私有地址（这个规则集没有允许局域网源）")
	}
	return nil
}

// ErrBlocked marks a refused destination.
var ErrBlocked = errors.New("目的地址被拒绝")

func (f *Fetcher) client() *http.Client {
	tr := f.Transport
	if tr == nil {
		guard := f.Guard
		if guard == nil {
			guard = func(ap netip.AddrPort) error { return AddrAllowed(ap.Addr(), f.AllowLAN) }
		}
		d := &net.Dialer{
			Timeout: 15 * time.Second,
			Control: func(network, address string, _ syscall.RawConn) error {
				ap, err := netip.ParseAddrPort(address)
				if err != nil {
					return fmt.Errorf("%w：%s", ErrBlocked, address)
				}
				if err := guard(ap); err != nil {
					return fmt.Errorf("%w：%s（%v）", ErrBlocked, ap.Addr(), err)
				}
				return nil
			},
		}
		tr = &http.Transport{
			Proxy:                 nil,
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("重定向超过 5 次")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" || req.URL.User != nil {
				return errors.New("重定向到不允许的地址")
			}
			return nil
		},
	}
}

// Get downloads u.
func (f *Fetcher) Get(ctx context.Context, u string) ([]byte, error) {
	if err := CheckURL(u); err != nil {
		return nil, err
	}
	to := f.Timeout
	if to <= 0 {
		to = 60 * time.Second
	}
	max := f.MaxBytes
	if max <= 0 {
		max = MaxBytes
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "meridian-ruleset")
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("超过大小上限 %d 字节", max)
	}
	return b, nil
}
