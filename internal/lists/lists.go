// Package lists downloads, checks and publishes the routing lists the
// gateway consumes: v2fly geosite categories (SmartDNS domain-set files) and
// the China IP lists (nft sets chnroute / chnroute6).
//
// Source policy. Every list comes from one of two fixed sources compiled
// into this package: "domestic" (jsDelivr's mirror of the same GitHub
// repositories, reachable from mainland lines) and "overseas" (GitHub raw).
// The persisted policy is domestic, overseas or automatic; automatic tries
// domestic, then overseas. Nothing in a request names a URL.
//
// Trust. A mirror is a third party serving security-relevant routing data.
// Content is checked for shape (a list, not an HTML page, not truncated, not
// empty, no prefix covering reserved or absurdly large space, no sudden
// shrink), never for truth: a hostile or stale mirror can still add or omit
// well-formed entries. See docs/architecture.md「名单源」.
//
// Atomicity. One update downloads and expands everything a list needs from
// one source, checks it, and only then publishes it with a rename (one file
// per list) or one nft transaction (chnroute). A list whose closure failed
// on every allowed source keeps its previous published version.
package lists

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Policy is the persisted source choice.
type Policy string

const (
	PolicyDomestic  Policy = "domestic"
	PolicyOverseas  Policy = "overseas"
	PolicyAutomatic Policy = "automatic"
	// DefaultPolicy applies while none was saved: the gateway sits on a
	// mainland line where GitHub raw mostly times out.
	DefaultPolicy = PolicyAutomatic
)

// Policies lists every accepted value, in display order.
var Policies = []Policy{PolicyDomestic, PolicyOverseas, PolicyAutomatic}

// ParsePolicy accepts exactly one of the three values.
func ParsePolicy(s string) (Policy, bool) {
	for _, p := range Policies {
		if string(p) == s {
			return p, true
		}
	}
	return "", false
}

// Effective maps the stored setting ("" = never saved) to a policy.
func Effective(s string) Policy {
	if p, ok := ParsePolicy(s); ok {
		return p
	}
	return DefaultPolicy
}

// List kinds a request may name.
const (
	KindGeosite  = "geosite"
	KindChnroute = "chnroute"
)

// Source is one place every list can be downloaded from.
type Source struct {
	Name string `json:"name"`
	// GeositeBase + "/" + category name is a v2fly data file.
	GeositeBase string `json:"geosite_base"`
	// ChnrouteBase + "/china.txt" and "/china6.txt".
	ChnrouteBase string `json:"chnroute_base"`
}

const (
	SourceDomestic = "domestic"
	SourceOverseas = "overseas"
)

// Domestic and Overseas are the compiled-in sources. jsDelivr's "gh"
// endpoint serves files of public GitHub repositories at a branch.
var (
	Domestic = Source{
		Name:         SourceDomestic,
		GeositeBase:  "https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data",
		ChnrouteBase: "https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists",
	}
	Overseas = Source{
		Name:         SourceOverseas,
		GeositeBase:  "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data",
		ChnrouteBase: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists",
	}
)

// Order is the source sequence a policy tries.
func Order(p Policy) []Source {
	switch p {
	case PolicyDomestic:
		return []Source{Domestic}
	case PolicyOverseas:
		return []Source{Overseas}
	default:
		return []Source{Domestic, Overseas}
	}
}

// Environment overrides of the domestic source (a LAN copy, say). They are
// read by the host-side updater from its own environment (the meridian-host
// unit), never from a request or a file the panel can write.
const (
	EnvGeositeBase  = "MERIDIAN_GEOSITE_BASE_URL"
	EnvChnrouteBase = "MERIDIAN_CHNROUTE_BASE_URL"
)

// WithEnv returns srcs with the domestic bases replaced by the environment
// overrides, after checking them.
func WithEnv(srcs []Source, getenv func(string) string) ([]Source, error) {
	out := append([]Source(nil), srcs...)
	for i := range out {
		if out[i].Name != SourceDomestic {
			continue
		}
		if v := getenv(EnvGeositeBase); v != "" {
			if err := CheckBase(v); err != nil {
				return nil, fmt.Errorf("%s: %w", EnvGeositeBase, err)
			}
			out[i].GeositeBase = strings.TrimRight(v, "/")
		}
		if v := getenv(EnvChnrouteBase); v != "" {
			if err := CheckBase(v); err != nil {
				return nil, fmt.Errorf("%s: %w", EnvChnrouteBase, err)
			}
			out[i].ChnrouteBase = strings.TrimRight(v, "/")
		}
	}
	return out, nil
}

// CheckBase accepts an absolute http(s) URL with a host and no query,
// fragment, credentials or whitespace.
func CheckBase(s string) error {
	if strings.ContainsAny(s, " \t\r\n\"'`\\") {
		return errors.New("base URL contains whitespace or quotes")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base URL must be http:// or https:// with a host")
	}
	return nil
}

// ------------------------------------------------------------ names ---

var (
	// CategoryRe is a v2fly list name ("cn", "geolocation-!cn").
	CategoryRe = regexp.MustCompile(`^[a-z0-9][a-z0-9!_-]{0,63}$`)
	attrRe     = regexp.MustCompile(`^[a-z0-9!][a-z0-9!_-]{0,63}$`)
	// A label may carry "_" (service names); no empty label, no leading or
	// trailing "-"/".", at most 253 bytes.
	domainRe  = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$`)
	keywordRe = regexp.MustCompile(`^[a-z0-9._-]{1,253}$`)
)

// FileName is the published file stem of a category: lower case, every
// character outside [a-z0-9] replaced by "_" (compile's sanitize).
func FileName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// ------------------------------------------------------------ fetch ---

// ErrNotFound is a definite "no such file" (HTTP 404/410) from a source.
var ErrNotFound = errors.New("not found")

// Getter downloads one URL completely or fails.
type Getter interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// Fetcher is the real Getter: bounded connect and per-file time, small
// retry on transport errors and 5xx, size cap, and a refusal of anything
// that is not plain text (HTML pages, binary data, a downgrade redirect).
type Fetcher struct {
	Client         *http.Client
	ConnectTimeout time.Duration // default 10s
	FileTimeout    time.Duration // one attempt; default 60s
	Retries        int           // extra attempts; default 1, negative = 0
	MaxBytes       int64         // default 8 MiB
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	ct := f.ConnectTimeout
	if ct <= 0 {
		ct = 10 * time.Second
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: ct}).DialContext,
			TLSHandshakeTimeout: ct,
			MaxIdleConnsPerHost: 4,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: refuseDowngrade,
	}
}

func refuseDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" && (len(via) == 0 || via[0].URL.Scheme == "https") {
		return errors.New("redirect leaves https")
	}
	return nil
}

func (f *Fetcher) Get(ctx context.Context, u string) ([]byte, error) {
	retries := f.Retries
	if retries == 0 {
		retries = 1
	}
	if retries < 0 {
		retries = 0
	}
	var last error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		b, retry, err := f.once(ctx, u)
		if err == nil {
			return b, nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (f *Fetcher) once(ctx context.Context, u string) ([]byte, bool, error) {
	ft := f.FileTimeout
	if ft <= 0 {
		ft = 60 * time.Second
	}
	max := f.MaxBytes
	if max <= 0 {
		max = 8 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, ft)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "meridian-lists")
	req.Header.Set("Accept", "text/plain, */*;q=0.1")
	resp, err := f.client().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, true, fmt.Errorf("timed out after %s", ft)
		}
		return nil, true, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, false, ErrNotFound
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("HTTP %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "html") {
		return nil, false, fmt.Errorf("content type %q is not a list", ct)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		// Includes a body shorter than its Content-Length (truncated).
		if ctx.Err() != nil {
			return nil, true, fmt.Errorf("timed out after %s", ft)
		}
		return nil, true, fmt.Errorf("incomplete download: %v", err)
	}
	if int64(len(b)) > max {
		return nil, false, fmt.Errorf("larger than %d bytes", max)
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, false, errors.New("not a text file")
	}
	return b, false, nil
}

// ------------------------------------------------------- v2fly parse ---

// Entry types kept from a v2fly file.
const (
	TypeDomain  = "domain"
	TypeFull    = "full"
	TypeKeyword = "keyword"
	TypeRegexp  = "regexp"
)

// Entry is one rule of a category after parsing.
type Entry struct {
	Type  string
	Value string
	Attrs []string
}

func (e Entry) has(attr string) bool {
	for _, a := range e.Attrs {
		if a == attr {
			return true
		}
	}
	return false
}

// Include is "include:name @a @-b": the entries of name (fully expanded)
// that carry every Must attribute and none of the Not attributes.
type Include struct {
	Name string
	Must []string
	Not  []string
}

// File is one parsed category file.
type File struct {
	Entries  []Entry
	Includes []Include
	// Affiliations counts "&list" markers: they add the entry to another
	// list, which only a scan of every file could honour. Ignored here.
	Affiliations int
}

// ParseV2fly parses one data file strictly: any line that is not a comment,
// blank, a known rule with a valid value, or followed by anything but
// attributes / affiliations fails the whole file (an HTML page, a captive
// portal or a cut-off line cannot pass as a list).
func ParseV2fly(data []byte) (File, error) {
	var f File
	for i, raw := range strings.Split(string(data), "\n") {
		line := raw
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 0 {
			continue
		}
		bad := func(why string) (File, error) {
			return File{}, fmt.Errorf("line %d: %s", i+1, why)
		}
		typ, val := TypeDomain, fields[0]
		if k := strings.IndexByte(fields[0], ':'); k >= 0 {
			typ, val = fields[0][:k], fields[0][k+1:]
		}
		var attrs, not []string
		affil := 0
		for _, tok := range fields[1:] {
			switch {
			case strings.HasPrefix(tok, "@-") && attrRe.MatchString(tok[2:]):
				not = append(not, tok[2:])
			case strings.HasPrefix(tok, "@") && attrRe.MatchString(tok[1:]):
				attrs = append(attrs, tok[1:])
			case strings.HasPrefix(tok, "&") && CategoryRe.MatchString(tok[1:]):
				affil++
			default:
				return bad("unexpected token after the rule")
			}
		}
		switch typ {
		case "include":
			if !CategoryRe.MatchString(val) {
				return bad("include of an invalid list name")
			}
			if affil > 0 {
				return bad("affiliation on an include")
			}
			f.Includes = append(f.Includes, Include{Name: val, Must: attrs, Not: not})
			continue
		case TypeDomain, TypeFull:
			if len(val) > 253 || !domainRe.MatchString(val) {
				return bad("invalid domain")
			}
		case TypeKeyword:
			if !keywordRe.MatchString(val) {
				return bad("invalid keyword")
			}
		case TypeRegexp:
			// Lower-casing can only break a pattern that relied on upper-case
			// escapes; such a file is refused rather than misread.
			orig := strings.Fields(line)[0]
			orig = orig[strings.IndexByte(orig, ':')+1:]
			if _, err := regexp.Compile(orig); err != nil || val == "" {
				return bad("invalid regexp")
			}
		default:
			return bad("unknown rule type")
		}
		if len(not) > 0 {
			return bad("@- is only valid on an include")
		}
		f.Affiliations += affil
		f.Entries = append(f.Entries, Entry{Type: typ, Value: val, Attrs: attrs})
	}
	return f, nil
}

// ------------------------------------------------------------ expand ---

// Limits bound one category's expansion.
type Limits struct {
	MaxDepth   int // include nesting; default 16
	MaxFiles   int // distinct files in one closure; default 2048
	MaxEntries int // expanded entries; default 500000
}

func (l Limits) norm() Limits {
	if l.MaxDepth <= 0 {
		l.MaxDepth = 16
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = 2048
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = 500000
	}
	return l
}

// Expanded is a category resolved through all of its includes.
type Expanded struct {
	// Domains is what a SmartDNS domain-set file can hold: domain: and
	// full: values, lower case, sorted, unique.
	Domains []string
	Files   int
	// Dropped counts entries SmartDNS domain-set cannot express.
	Dropped map[string]int
}

// Expand resolves root over files (already fetched and parsed). Every name
// reachable from root must be present; a missing one, a cycle, a nesting
// deeper than MaxDepth or a result over MaxEntries fails the whole list.
func Expand(root string, files map[string]File, lim Limits) (Expanded, error) {
	lim = lim.norm()
	memo := map[string][]Entry{}
	onPath := map[string]bool{}
	var path []string
	var resolve func(name string, depth int) ([]Entry, error)
	resolve = func(name string, depth int) ([]Entry, error) {
		if depth > lim.MaxDepth {
			return nil, fmt.Errorf("include depth over %d at %s", lim.MaxDepth, strings.Join(append(path, name), " > "))
		}
		if onPath[name] {
			return nil, fmt.Errorf("include cycle: %s", strings.Join(append(path, name), " > "))
		}
		if e, ok := memo[name]; ok {
			return e, nil
		}
		f, ok := files[name]
		if !ok {
			if len(path) == 0 {
				return nil, fmt.Errorf("list %s not found", name)
			}
			return nil, fmt.Errorf("missing include %s (from %s)", name, path[len(path)-1])
		}
		onPath[name] = true
		path = append(path, name)
		defer func() { onPath[name] = false; path = path[:len(path)-1] }()
		out := append([]Entry(nil), f.Entries...)
		for _, inc := range f.Includes {
			sub, err := resolve(inc.Name, depth+1)
			if err != nil {
				return nil, err
			}
			for _, e := range sub {
				if keep(e, inc) {
					out = append(out, e)
				}
			}
			if len(out) > lim.MaxEntries {
				return nil, fmt.Errorf("more than %d entries", lim.MaxEntries)
			}
		}
		memo[name] = out
		return out, nil
	}
	entries, err := resolve(root, 0)
	if err != nil {
		return Expanded{}, err
	}
	if len(memo) > lim.MaxFiles {
		return Expanded{}, fmt.Errorf("more than %d files", lim.MaxFiles)
	}
	ex := Expanded{Files: len(memo), Dropped: map[string]int{}}
	seen := map[string]bool{}
	for _, e := range entries {
		switch e.Type {
		case TypeDomain, TypeFull:
			if !seen[e.Value] {
				seen[e.Value] = true
				ex.Domains = append(ex.Domains, e.Value)
			}
		default:
			ex.Dropped[e.Type]++
		}
	}
	sort.Strings(ex.Domains)
	return ex, nil
}

func keep(e Entry, inc Include) bool {
	for _, a := range inc.Must {
		if !e.has(a) {
			return false
		}
	}
	for _, a := range inc.Not {
		if e.has(a) {
			return false
		}
	}
	return true
}

// closure fetches root and everything it includes from one source, level
// by level with bounded concurrency, through a per-source cache shared by
// the lists of one update. The first failure (download, parse, bounds)
// stops it.
type closure struct {
	get   Getter
	base  string
	lim   Limits
	conc  int
	mu    sync.Mutex
	files map[string]File
	errs  map[string]error
}

func newClosure(get Getter, base string, lim Limits, conc int) *closure {
	if conc <= 0 {
		conc = 6
	}
	return &closure{get: get, base: base, lim: lim.norm(), conc: conc, files: map[string]File{}, errs: map[string]error{}}
}

func (c *closure) fetch(ctx context.Context, root string) (map[string]File, error) {
	need := map[string]File{}
	level := []string{root}
	seen := map[string]bool{root: true}
	for depth := 0; len(level) > 0; depth++ {
		if depth > c.lim.MaxDepth {
			return nil, fmt.Errorf("include depth over %d", c.lim.MaxDepth)
		}
		if len(seen) > c.lim.MaxFiles {
			return nil, fmt.Errorf("more than %d files", c.lim.MaxFiles)
		}
		c.load(ctx, level)
		var next []string
		for _, name := range level {
			c.mu.Lock()
			f, ok := c.files[name]
			err := c.errs[name]
			c.mu.Unlock()
			if !ok {
				if errors.Is(err, ErrNotFound) {
					if name == root {
						return nil, fmt.Errorf("list %s not found at %s", name, c.base)
					}
					return nil, fmt.Errorf("missing include %s at %s", name, c.base)
				}
				return nil, fmt.Errorf("%s/%s: %v", c.base, name, err)
			}
			need[name] = f
			for _, inc := range f.Includes {
				if !seen[inc.Name] {
					seen[inc.Name] = true
					next = append(next, inc.Name)
				}
			}
		}
		level = next
	}
	return need, nil
}

func (c *closure) load(ctx context.Context, names []string) {
	sem := make(chan struct{}, c.conc)
	var wg sync.WaitGroup
	for _, name := range names {
		c.mu.Lock()
		_, done := c.files[name]
		_, failed := c.errs[name]
		c.mu.Unlock()
		if done || failed {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer func() { <-sem; wg.Done() }()
			b, err := c.get.Get(ctx, c.base+"/"+name)
			var f File
			if err == nil {
				f, err = ParseV2fly(b)
				if err != nil {
					err = fmt.Errorf("not a v2fly list: %v", err)
				}
			}
			c.mu.Lock()
			if err != nil {
				c.errs[name] = err
			} else {
				c.files[name] = f
			}
			c.mu.Unlock()
		}(name)
	}
	wg.Wait()
}

// ---------------------------------------------------------- chnroute ---

// Families of the China IP lists.
var chnFamilies = []struct {
	List, File, Set string
	V4              bool
}{
	{"chnroute4", "china.txt", "chnroute", true},
	{"chnroute6", "china6.txt", "chnroute6", false},
}

// Minimum entries a China list must have: the real lists have thousands
// (6217 IPv4 / 3423 IPv6 observed 2026-11-12). A shorter file is
// truncated or wrong.
const (
	MinChnroute4 = 1000
	MinChnroute6 = 300
	// maxV4Addrs caps the IPv4 space chnroute may cover (mainland China
	// holds about 3.4e8 addresses). A list covering far more would send
	// foreign traffic out of the home line untunnelled.
	maxV4Addrs = 6e8
)

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/8"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// ParsePrefixes checks a China IP list strictly: every non-comment line is
// one canonical prefix (or address) of the family, none overlapping
// reserved space or shorter than /8 (IPv4) or /16 (IPv6), at least min
// entries, and the IPv4 total under maxV4Addrs.
func ParsePrefixes(v4 bool, data []byte, min int) ([]netip.Prefix, error) {
	var out []netip.Prefix
	var total float64
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, err2 := netip.ParseAddr(line)
			if err2 != nil {
				return nil, fmt.Errorf("line %d: not an address or prefix", i+1)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4() != v4 || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return nil, fmt.Errorf("line %d: wrong address family", i+1)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("line %d: host bits set", i+1)
		}
		if (v4 && p.Bits() < 8) || (!v4 && p.Bits() < 16) {
			return nil, fmt.Errorf("line %d: prefix /%d is implausibly large", i+1, p.Bits())
		}
		for _, r := range reserved {
			if r.Overlaps(p) {
				return nil, fmt.Errorf("line %d: overlaps reserved %s", i+1, r)
			}
		}
		if v4 {
			total += float64(uint64(1) << (32 - p.Bits()))
		}
		out = append(out, p)
	}
	if len(out) < min {
		return nil, fmt.Errorf("only %d entries (at least %d expected): truncated or not the China list", len(out), min)
	}
	if total > maxV4Addrs {
		return nil, fmt.Errorf("covers %.0f IPv4 addresses, more than mainland China holds", total)
	}
	return out, nil
}

// ChnrouteBatch renders the flush + add statements for the given sets
// (set name -> prefixes) in a stable order, elements in chunks.
func ChnrouteBatch(sets map[string][]netip.Prefix) string {
	var sb strings.Builder
	for _, fam := range chnFamilies {
		ps, ok := sets[fam.Set]
		if !ok {
			continue
		}
		fmt.Fprintf(&sb, "flush set inet meridian %s\n", fam.Set)
		for i := 0; i < len(ps); i += 512 {
			j := min(i+512, len(ps))
			parts := make([]string, 0, j-i)
			for _, p := range ps[i:j] {
				parts = append(parts, p.String())
			}
			fmt.Fprintf(&sb, "add element inet meridian %s { %s }\n", fam.Set, strings.Join(parts, ", "))
		}
	}
	return sb.String()
}

// ------------------------------------------------------------ update ---

// Keyword is one keyword rule: its file stem and the substring.
type Keyword struct {
	ID    string `json:"id"`
	Value string `json:"keyword"`
}

// Request is one update. The caller's choices are the policy, which kinds
// and (geosite) which categories; sources and paths come from this package.
type Request struct {
	Policy   Policy
	Geosite  []string // v2fly names; published as geosite/<FileName>.txt
	Keywords []Keyword
	Chnroute bool
}

// Attempt is one source tried for one list.
type Attempt struct {
	Source     string `json:"source"`
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Published describes the version of a list that is live on the host.
type Published struct {
	Source    string    `json:"source"`
	URL       string    `json:"url"`
	UpdatedAt time.Time `json:"updated_at"`
	Count     int       `json:"count"`
	Files     int       `json:"files,omitempty"`
}

// ListResult is the outcome for one list in one update.
type ListResult struct {
	// List: "geosite:<name>", "keyword:<id>", "chnroute4", "chnroute6".
	List string `json:"list"`
	Kind string `json:"kind"`
	// Updated: this run published a new version. Kept: it did not, and the
	// previous version (Current, if any) stays live.
	Updated bool `json:"updated"`
	Kept    bool `json:"kept"`
	// Source/URL/Count describe what this run published (Updated only).
	Source  string         `json:"source,omitempty"`
	URL     string         `json:"url,omitempty"`
	Count   int            `json:"count,omitempty"`
	Files   int            `json:"files,omitempty"`
	Dropped map[string]int `json:"dropped,omitempty"`
	// Current is the live version after this run (new or kept).
	Current  *Published `json:"current,omitempty"`
	Attempts []Attempt  `json:"attempts,omitempty"`
	Error    string     `json:"error,omitempty"`
}

// Report is the result of one update.
type Report struct {
	Policy     Policy    `json:"policy"`
	Sources    []string  `json:"sources"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	// OK: every requested list updated. Partial: some did.
	OK      bool         `json:"ok"`
	Partial bool         `json:"partial"`
	Lists   []ListResult `json:"lists"`
	Error   string       `json:"error,omitempty"`
	// DNSChanged: a geosite or keyword file was replaced; SmartDNS reads
	// them only at start and must be restarted.
	DNSChanged bool `json:"dns_changed"`
	// Set by the host agent after the update.
	DNSRestart string   `json:"dns_restart,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Status is what the host keeps between updates (lists/status.json).
type Status struct {
	Published map[string]Published `json:"published"`
	Last      *Report              `json:"last,omitempty"`
}

// Updater runs updates against Dir (/var/lib/meridian on the gateway):
// geosite/, keywords/ (read by SmartDNS) and lists/ (saved China lists,
// the saved chnroute batch the up script re-adds, status.json).
type Updater struct {
	Dir    string
	Get    Getter
	Limits Limits
	// Sources replaces Order(policy) (tests; env overrides).
	Sources func(Policy) ([]Source, error)
	// Concurrency of downloads within one closure; default 6.
	Concurrency int
	// SourceTimeout bounds one list on one source; default 5m.
	SourceTimeout time.Duration
	// LoadNFT loads an nft batch file (chnroute). Nil: chnroute fails.
	LoadNFT func(ctx context.Context, path string) error
	// Lock is held while publishing (the host agent's action lock), so a
	// publication never interleaves with an install or rollback.
	Lock func(ctx context.Context) (unlock func(), err error)
	// AfterPublish runs while the lock is still held, after every file
	// and nft change (the host agent restarts SmartDNS here).
	AfterPublish func(ctx context.Context, rep *Report)
	Now          func() time.Time
	// MinChnroute overrides MinChnroute4/6 (tests).
	MinChnroute4, MinChnroute6 int
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now().UTC()
	}
	return time.Now().UTC()
}

func (u *Updater) geoDir() string   { return filepath.Join(u.Dir, "geosite") }
func (u *Updater) kwDir() string    { return filepath.Join(u.Dir, "keywords") }
func (u *Updater) stateDir() string { return filepath.Join(u.Dir, "lists") }

// StatusPath is the persisted status file under dir.
func StatusPath(dir string) string { return filepath.Join(dir, "lists", "status.json") }

// SavedBatchPath is the last chnroute batch nft accepted; meridian-up.sh
// appends it to the ruleset it loads so a reload does not empty chnroute.
func SavedBatchPath(dir string) string { return filepath.Join(dir, "lists", "chnroute.nft") }

// ReadStatus loads dir's status (empty when none was written).
func ReadStatus(dir string) (Status, error) {
	st := Status{Published: map[string]Published{}}
	b, err := os.ReadFile(StatusPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return Status{Published: map[string]Published{}}, fmt.Errorf("status.json: %v", err)
	}
	if st.Published == nil {
		st.Published = map[string]Published{}
	}
	return st, nil
}

type geoCandidate struct {
	res *ListResult
	ex  Expanded
	src Source
	url string
}

type chnCandidate struct {
	res *ListResult
	ps  []netip.Prefix
	raw []byte
	src Source
	url string
}

// Run performs one update. It never returns an error: everything is in
// the report, list by list.
func (u *Updater) Run(ctx context.Context, req Request) Report {
	rep := Report{Policy: req.Policy, StartedAt: u.now()}
	finish := func() Report {
		rep.FinishedAt = u.now()
		return rep
	}
	order := Order
	if u.Sources != nil {
		order = func(p Policy) []Source {
			s, err := u.Sources(p)
			if err != nil {
				rep.Error = err.Error()
				return nil
			}
			return s
		}
	}
	srcs := order(req.Policy)
	if len(srcs) == 0 {
		if rep.Error == "" {
			rep.Error = "no source for policy " + string(req.Policy)
		}
		return finish()
	}
	for _, s := range srcs {
		rep.Sources = append(rep.Sources, s.Name)
	}
	st, err := ReadStatus(u.Dir)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "previous status unreadable, starting a new one: "+err.Error())
	}

	// 1. Download and check, nothing published yet.
	// Candidates point into rep.Lists: its capacity covers every list, so
	// no later append moves it.
	rep.Lists = make([]ListResult, 0, len(req.Geosite)+len(chnFamilies)+len(req.Keywords))
	var geos []*geoCandidate
	closures := map[string]*closure{}
	for _, name := range req.Geosite {
		rep.Lists = append(rep.Lists, ListResult{List: "geosite:" + name, Kind: KindGeosite})
	}
	for i, name := range req.Geosite {
		res := &rep.Lists[i]
		prev := countLines(filepath.Join(u.geoDir(), FileName(name)+".txt"))
		for _, src := range srcs {
			c := closures[src.Name]
			if c == nil {
				c = newClosure(u.Get, src.GeositeBase, u.Limits, u.Concurrency)
				closures[src.Name] = c
			}
			start := time.Now()
			url := src.GeositeBase + "/" + name
			ex, err := u.expandFrom(ctx, c, name)
			if err == nil && len(ex.Domains) == 0 {
				err = errors.New("no domain a SmartDNS domain-set can hold")
			}
			if err == nil {
				err = shrinkCheck(prev, len(ex.Domains))
			}
			res.Attempts = append(res.Attempts, attempt(src, url, start, err))
			if err == nil {
				geos = append(geos, &geoCandidate{res: res, ex: ex, src: src, url: url})
				break
			}
		}
	}
	var chns []*chnCandidate
	if req.Chnroute {
		for _, fam := range chnFamilies {
			rep.Lists = append(rep.Lists, ListResult{List: fam.List, Kind: KindChnroute})
		}
		base := len(rep.Lists) - len(chnFamilies)
		for i, fam := range chnFamilies {
			res := &rep.Lists[base+i]
			minN := MinChnroute4
			if u.MinChnroute4 > 0 {
				minN = u.MinChnroute4
			}
			if !fam.V4 {
				minN = MinChnroute6
				if u.MinChnroute6 > 0 {
					minN = u.MinChnroute6
				}
			}
			prev := countLines(filepath.Join(u.stateDir(), fam.File))
			for _, src := range srcs {
				start := time.Now()
				url := src.ChnrouteBase + "/" + fam.File
				sctx, cancel := context.WithTimeout(ctx, u.sourceTimeout())
				b, err := u.Get.Get(sctx, url)
				cancel()
				var ps []netip.Prefix
				if err == nil {
					ps, err = ParsePrefixes(fam.V4, b, minN)
				}
				if err == nil {
					err = shrinkCheck(prev, len(ps))
				}
				res.Attempts = append(res.Attempts, attempt(src, url, start, err))
				if err == nil {
					chns = append(chns, &chnCandidate{res: res, ps: ps, raw: b, src: src, url: url})
					break
				}
			}
		}
	}

	// 2. Publish under the lock.
	unlock := func() {}
	locked := true
	if u.Lock != nil {
		ul, err := u.Lock(ctx)
		if err != nil {
			// Nothing on the host is touched, not even an empty seed file.
			rep.Error = "not published: " + err.Error()
			locked = false
		} else {
			unlock = ul
		}
	}
	func() {
		defer unlock()
		if !locked {
			return
		}
		if err := os.MkdirAll(u.stateDir(), 0o755); err != nil {
			rep.Error = err.Error()
			geos, chns = nil, nil
		}
		for _, g := range geos {
			name := strings.TrimPrefix(g.res.List, "geosite:")
			body := strings.Join(g.ex.Domains, "\n") + "\n"
			if err := writeAtomic(filepath.Join(u.geoDir(), FileName(name)+".txt"), []byte(body), 0o644); err != nil {
				g.res.Error = "publish: " + err.Error()
				continue
			}
			g.res.Updated, g.res.Source, g.res.URL = true, g.src.Name, g.url
			g.res.Count, g.res.Files = len(g.ex.Domains), g.ex.Files
			if len(g.ex.Dropped) > 0 {
				g.res.Dropped = g.ex.Dropped
			}
			st.Published[g.res.List] = Published{Source: g.src.Name, URL: g.url, UpdatedAt: u.now(), Count: len(g.ex.Domains), Files: g.ex.Files}
			rep.DNSChanged = true
		}
		// SmartDNS must find every configured file; a missing one is
		// created empty (the previous behaviour), never a populated one.
		for _, name := range req.Geosite {
			p := filepath.Join(u.geoDir(), FileName(name)+".txt")
			if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
				_ = os.MkdirAll(u.geoDir(), 0o755)
				_ = os.WriteFile(p, nil, 0o644)
			}
		}
		if len(req.Keywords) > 0 {
			rep.Lists = append(rep.Lists, u.keywords(req.Keywords, &st, &rep)...)
		}
		if len(chns) > 0 {
			u.publishChnroute(ctx, chns, &st)
		}
		if u.AfterPublish != nil && rep.Error == "" {
			u.AfterPublish(ctx, &rep)
		}
	}()

	// 3. Results and status.
	updated, total := 0, 0
	for i := range rep.Lists {
		r := &rep.Lists[i]
		total++
		if r.Updated {
			updated++
		} else {
			r.Kept = true
			if r.Error == "" {
				r.Error = lastError(r.Attempts)
			}
			if r.Error == "" && rep.Error != "" {
				r.Error = rep.Error
			}
		}
		if p, ok := st.Published[r.List]; ok {
			p := p
			r.Current = &p
		}
	}
	rep.OK = total > 0 && updated == total && rep.Error == ""
	rep.Partial = updated > 0 && updated < total
	if total == 0 && rep.Error == "" {
		rep.Error = "nothing to update"
	}
	rep = finish()
	last := rep
	st.Last = &last
	if err := u.writeStatus(st); err != nil {
		rep.Warnings = append(rep.Warnings, "status not saved: "+err.Error())
	}
	return rep
}

func (u *Updater) sourceTimeout() time.Duration {
	if u.SourceTimeout > 0 {
		return u.SourceTimeout
	}
	return 5 * time.Minute
}

func (u *Updater) expandFrom(ctx context.Context, c *closure, name string) (Expanded, error) {
	sctx, cancel := context.WithTimeout(ctx, u.sourceTimeout())
	defer cancel()
	files, err := c.fetch(sctx, name)
	if err != nil {
		return Expanded{}, err
	}
	return Expand(name, files, u.Limits)
}

func (u *Updater) keywords(kws []Keyword, st *Status, rep *Report) []ListResult {
	var out []ListResult
	entries, _ := os.ReadDir(u.geoDir())
	var domains []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(u.geoDir(), e.Name()))
		if err != nil {
			continue
		}
		domains = append(domains, strings.Fields(string(b))...)
	}
	for _, kw := range kws {
		r := ListResult{List: "keyword:" + kw.ID, Kind: "keyword"}
		needle := strings.ToLower(kw.Value)
		set := map[string]bool{}
		for _, d := range domains {
			if strings.Contains(d, needle) {
				set[d] = true
			}
		}
		var hits []string
		for d := range set {
			hits = append(hits, d)
		}
		sort.Strings(hits)
		p := filepath.Join(u.kwDir(), kw.ID+".txt")
		switch {
		case len(hits) == 0:
			// An empty result never replaces a populated keyword list.
			r.Error = "no published geosite domain contains " + kw.Value
			if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
				_ = os.MkdirAll(u.kwDir(), 0o755)
				_ = os.WriteFile(p, nil, 0o644)
			}
		default:
			body := []byte(strings.Join(hits, "\n") + "\n")
			if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, body) {
				r.Updated, r.Source, r.Count = true, "derived", len(hits)
				break
			}
			if err := writeAtomic(p, body, 0o644); err != nil {
				r.Error = "publish: " + err.Error()
				break
			}
			r.Updated, r.Source, r.Count = true, "derived", len(hits)
			st.Published[r.List] = Published{Source: "derived", UpdatedAt: u.now(), Count: len(hits)}
			rep.DNSChanged = true
		}
		out = append(out, r)
	}
	return out
}

// publishChnroute loads every validated family in ONE nft transaction
// (flush + add per family); the saved lists and the saved batch are only
// replaced after nft accepted it.
func (u *Updater) publishChnroute(ctx context.Context, chns []*chnCandidate, st *Status) {
	fail := func(msg string) {
		for _, c := range chns {
			c.res.Error = msg
		}
	}
	if u.LoadNFT == nil {
		fail("this updater cannot load nft sets")
		return
	}
	sets := map[string][]netip.Prefix{}
	for _, c := range chns {
		sets[setOf(c.res.List)] = c.ps
	}
	batch := ChnrouteBatch(sets)
	tmp := filepath.Join(u.stateDir(), ".chnroute-batch.nft")
	if err := writeAtomic(tmp, []byte(batch), 0o600); err != nil {
		fail("publish: " + err.Error())
		return
	}
	defer os.Remove(tmp)
	if err := u.LoadNFT(ctx, tmp); err != nil {
		fail("nft rejected the batch; sets keep their previous elements: " + err.Error())
		return
	}
	for _, c := range chns {
		file := fileOf(c.res.List)
		if err := writeAtomic(filepath.Join(u.stateDir(), file), c.raw, 0o644); err != nil {
			c.res.Error = "loaded, but saving the list failed: " + err.Error()
		}
		c.res.Updated, c.res.Source, c.res.URL, c.res.Count = true, c.src.Name, c.url, len(c.ps)
		st.Published[c.res.List] = Published{Source: c.src.Name, URL: c.url, UpdatedAt: u.now(), Count: len(c.ps)}
	}
	// The saved batch holds both families as they are now live: the new
	// ones, plus the saved list of a family this run did not update.
	all := map[string][]netip.Prefix{}
	for _, fam := range chnFamilies {
		if ps, ok := sets[fam.Set]; ok {
			all[fam.Set] = ps
			continue
		}
		if b, err := os.ReadFile(filepath.Join(u.stateDir(), fam.File)); err == nil {
			if ps, err := ParsePrefixes(fam.V4, b, 1); err == nil {
				all[fam.Set] = ps
			}
		}
	}
	if err := writeAtomic(SavedBatchPath(u.Dir), []byte(ChnrouteBatch(all)), 0o600); err != nil {
		for _, c := range chns {
			if c.res.Error == "" {
				c.res.Error = "loaded, but the reload copy was not saved: " + err.Error()
			}
		}
	}
}

func setOf(list string) string {
	for _, f := range chnFamilies {
		if f.List == list {
			return f.Set
		}
	}
	return ""
}

func fileOf(list string) string {
	for _, f := range chnFamilies {
		if f.List == list {
			return f.File
		}
	}
	return ""
}

func (u *Updater) writeStatus(st Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(StatusPath(u.Dir), b, 0o644)
}

// shrinkCheck refuses a list that lost more than half of a sizeable
// previous version: the typical shape of a truncated or wrong file.
func shrinkCheck(prev, next int) error {
	if prev >= 200 && next*2 < prev {
		return fmt.Errorf("only %d entries where the published list has %d: refusing a shrink by more than half", next, prev)
	}
	return nil
}

func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}

func attempt(src Source, url string, start time.Time, err error) Attempt {
	a := Attempt{Source: src.Name, URL: url, OK: err == nil, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		a.Error = err.Error()
	}
	return a
}

func lastError(as []Attempt) string {
	var parts []string
	for _, a := range as {
		if a.Error != "" {
			parts = append(parts, a.Source+": "+a.Error)
		}
	}
	return strings.Join(parts, "; ")
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
