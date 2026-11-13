// Package ruleset parses subscribed rule-sets (Clash/mihomo rule providers
// and Surge rule lists) into the ordered model's match entries, and fetches
// them with the panel's source policy and SSRF guard (fetch.go).
//
// Formats, detected by content first and by the URL's extension second:
//
//   - clash-classical: provider YAML, payload of "TYPE,value[,no-resolve]".
//   - clash-domain: provider YAML, payload of domain patterns. "example.com"
//     is that name only; "+.example.com" the name and every name below it;
//     ".example.com" every name below it, not the name itself; "*.example.com"
//     exactly one label below it, which SmartDNS cannot express (it has no
//     single-label wildcard): counted unsupported. Any other "*" or "+" is
//     unsupported.
//   - clash-ipcidr: provider YAML, payload of IPv4/IPv6 CIDRs.
//   - clash-text-classical / clash-text-domain / clash-text-ipcidr: the same
//     three without the YAML wrapper, one entry per line (format: text).
//   - surge-list: Surge rule list, "TYPE,value[,options…]", "#" and "//"
//     comments. A policy as an extra field ("DOMAIN-SUFFIX,x,Proxy") is
//     ignored and counted (the rule using the set decides the target).
//     DOMAIN-WILDCARD "*.example.com" is every name below example.com (Surge
//     "*" matches any characters, dots included); other wildcards are
//     unsupported.
//   - surge-domain-set: plain lines, "example.com" is that name only,
//     ".example.com" the name and every name below it.
//   - mrs: mihomo's binary rule-set format. Not supported; detected and
//     reported.
//
// Executable entries: DOMAIN (exact), DOMAIN-SUFFIX (suffix), sub-domain
// patterns, IP-CIDR / IP-CIDR6 (no-resolve is noted: the gateway always sees
// the destination address). DOMAIN-KEYWORD entries are kept and reported but
// SmartDNS cannot match a substring, so they are not executed. Every other
// type (PROCESS-NAME, USER-AGENT, URL-REGEX, IP-ASN, GEOIP, DST-PORT,
// logical rules …) is counted per type as unsupported; it never fails the
// whole set.
package ruleset

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/radowitz/meridian/internal/ordered"
)

// Format names.
const (
	FormatAuto              = ""
	FormatClashClassical    = "clash-classical"
	FormatClashDomain       = "clash-domain"
	FormatClashIPCIDR       = "clash-ipcidr"
	FormatClashTextClassic  = "clash-text-classical"
	FormatClashTextDomain   = "clash-text-domain"
	FormatClashTextIPCIDR   = "clash-text-ipcidr"
	FormatSurgeList         = "surge-list"
	FormatSurgeDomainSet    = "surge-domain-set"
	FormatMRS               = "mrs"
	MaxBytes                = 16 << 20
	MaxEntries              = 500000
	unsupportedPolicyField  = "policy-field"
	unsupportedInvalidEntry = "invalid"
)

// Formats lists the accepted explicit formats.
var Formats = []string{FormatClashClassical, FormatClashDomain, FormatClashIPCIDR, FormatClashTextClassic,
	FormatClashTextDomain, FormatClashTextIPCIDR, FormatSurgeList, FormatSurgeDomainSet}

// FormatOK reports whether f is "" (auto) or an explicit format.
func FormatOK(f string) bool {
	if f == FormatAuto {
		return true
	}
	for _, x := range Formats {
		if x == f {
			return true
		}
	}
	return false
}

// Parsed is one parsed rule-set.
type Parsed struct {
	Format  string          `json:"format"`
	Entries []ordered.Entry `json:"-"`
	// Counts are executable entries per kind (exact, suffix, sub, cidr)
	// plus keyword (kept, not executed).
	Counts map[string]int `json:"counts"`
	// Unsupported counts entries that cannot be executed, per type.
	Unsupported map[string]int `json:"unsupported,omitempty"`
	// NoResolve counts IP entries with no-resolve (no effect here).
	NoResolve int `json:"no_resolve,omitempty"`
	// PolicyIgnored counts entries that carried a policy field.
	PolicyIgnored int      `json:"policy_ignored,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// Executable is the number of entries the data plane executes.
func (p Parsed) Executable() int {
	return p.Counts["exact"] + p.Counts["suffix"] + p.Counts["sub"] + p.Counts["cidr"]
}

// ErrMRS is returned for a binary .mrs rule-set.
var ErrMRS = errors.New("mihomo 二进制规则集（.mrs）不支持：请改用同一规则集的 yaml 或 text 版本")

func (p *Parsed) unsupported(t string) {
	if p.Unsupported == nil {
		p.Unsupported = map[string]int{}
	}
	p.Unsupported[t]++
}

func (p *Parsed) add(e ordered.Entry) {
	p.Entries = append(p.Entries, e)
	p.Counts[string(e.Kind)]++
}

// Parse parses data. format is "" (detect) or one of Formats; behavior is
// the provider's behavior when known (mihomo rule-providers), else "";
// name is the URL or file name (for the extension).
func Parse(data []byte, format, behavior, name string) (Parsed, error) {
	p := Parsed{Counts: map[string]int{}}
	if len(data) > MaxBytes {
		return p, fmt.Errorf("规则集超过 %d MiB", MaxBytes>>20)
	}
	if isMRS(data, name) {
		p.Format = FormatMRS
		return p, ErrMRS
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return p, errors.New("内容不是文本（二进制或编码错误）")
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if format == FormatAuto {
		format = detect(text, behavior, name)
	}
	if !FormatOK(format) {
		return p, fmt.Errorf("未知格式 %q", format)
	}
	p.Format = format
	var items []string
	switch format {
	case FormatClashClassical, FormatClashDomain, FormatClashIPCIDR:
		var doc struct {
			Payload []any `yaml:"payload"`
		}
		if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
			return p, fmt.Errorf("YAML 无法解析：%v", firstLine(err.Error()))
		}
		if doc.Payload == nil {
			return p, errors.New("YAML 里没有 payload 列表")
		}
		for _, it := range doc.Payload {
			s, ok := it.(string)
			if !ok {
				p.unsupported(unsupportedInvalidEntry)
				continue
			}
			items = append(items, s)
		}
	default:
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") || strings.HasPrefix(l, ";") {
				continue
			}
			if format == FormatSurgeList || format == FormatClashTextClassic {
				if i := strings.Index(l, " //"); i >= 0 {
					l = strings.TrimSpace(l[:i])
				}
			}
			items = append(items, l)
		}
	}
	if len(items) > MaxEntries {
		return p, fmt.Errorf("规则集条目超过 %d 条", MaxEntries)
	}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		switch format {
		case FormatClashClassical, FormatClashTextClassic, FormatSurgeList:
			p.classical(it, format == FormatSurgeList)
		case FormatClashDomain, FormatClashTextDomain:
			p.clashDomain(it)
		case FormatClashIPCIDR, FormatClashTextIPCIDR:
			p.cidr(it)
		case FormatSurgeDomainSet:
			p.surgeDomain(it)
		}
	}
	if p.Counts["keyword"] > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("%d 条 DOMAIN-KEYWORD：SmartDNS 不能按子串匹配，这些条目不执行", p.Counts["keyword"]))
	}
	if p.PolicyIgnored > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("%d 条带策略字段：作为规则集使用时忽略，目标由使用它的规则决定", p.PolicyIgnored))
	}
	if p.NoResolve > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("%d 条 no-resolve：网关总是按目的地址匹配 IP 条目，no-resolve 没有影响", p.NoResolve))
	}
	return p, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func isMRS(data []byte, name string) bool {
	// .mrs files are zstd frames (magic 28 b5 2f fd).
	if len(data) >= 4 && data[0] == 0x28 && data[1] == 0xb5 && data[2] == 0x2f && data[3] == 0xfd {
		return true
	}
	return strings.EqualFold(path.Ext(trimQuery(name)), ".mrs") && !utf8.Valid(data)
}

func trimQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

var classicalTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-WILDCARD": true, "DOMAIN-REGEX": true,
	"IP-CIDR": true, "IP-CIDR6": true, "IP-ASN": true, "GEOIP": true, "GEOSITE": true, "IP-SUFFIX": true,
	"USER-AGENT": true, "URL-REGEX": true, "PROCESS-NAME": true, "PROCESS-PATH": true, "PROCESS-NAME-REGEX": true,
	"DST-PORT": true, "DEST-PORT": true, "SRC-PORT": true, "IN-PORT": true, "SRC-IP-CIDR": true, "SRC-IP": true,
	"SRC-GEOIP": true, "SRC-IP-ASN": true, "NETWORK": true, "PROTOCOL": true, "AND": true, "OR": true, "NOT": true,
	"UID": true, "IN-TYPE": true, "IN-USER": true, "IN-NAME": true, "DSCP": true, "SUBNET": true, "HOSTNAME-TYPE": true,
	"CELLULAR-RADIO": true, "DEVICE-NAME": true, "SCRIPT": true, "RULE-SET": true, "DOMAIN-SET": true,
}

func ruleType(line string) string {
	i := strings.IndexByte(line, ',')
	if i <= 0 {
		return ""
	}
	t := strings.ToUpper(strings.TrimSpace(line[:i]))
	if classicalTypes[t] {
		return t
	}
	return ""
}

func detect(text, behavior, name string) string {
	ext := strings.ToLower(path.Ext(trimQuery(name)))
	yamlDoc := false
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		yamlDoc = strings.HasPrefix(t, "payload:")
		break
	}
	var sample []string
	if yamlDoc {
		var doc struct {
			Payload []any `yaml:"payload"`
		}
		_ = yaml.Unmarshal([]byte(text), &doc)
		for _, it := range doc.Payload {
			if s, ok := it.(string); ok {
				sample = append(sample, strings.TrimSpace(s))
			}
		}
	} else {
		for _, l := range strings.Split(text, "\n") {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
				continue
			}
			sample = append(sample, t)
		}
	}
	kind := ""
	switch strings.ToLower(behavior) {
	case "classical":
		kind = "classical"
	case "domain":
		kind = "domain"
	case "ipcidr":
		kind = "ipcidr"
	}
	if kind == "" {
		typed, cidrs, clashWild := 0, 0, 0
		for _, s := range sample {
			if ruleType(s) != "" {
				typed++
			}
			if _, err := netip.ParsePrefix(s); err == nil {
				cidrs++
			} else if _, err := netip.ParseAddr(s); err == nil {
				cidrs++
			}
			if strings.HasPrefix(s, "+.") || strings.HasPrefix(s, "*.") {
				clashWild++
			}
		}
		switch {
		case len(sample) > 0 && typed*2 >= len(sample):
			kind = "classical"
		case len(sample) > 0 && cidrs*2 >= len(sample):
			kind = "ipcidr"
		default:
			kind = "domain"
			if !yamlDoc && clashWild == 0 && ext != ".yaml" && ext != ".yml" {
				return FormatSurgeDomainSet
			}
		}
	}
	if yamlDoc {
		return map[string]string{"classical": FormatClashClassical, "domain": FormatClashDomain, "ipcidr": FormatClashIPCIDR}[kind]
	}
	switch kind {
	case "classical":
		if ext == ".list" || ext == ".conf" || hasSurgeOnly(sample) {
			return FormatSurgeList
		}
		return FormatClashTextClassic
	case "ipcidr":
		return FormatClashTextIPCIDR
	}
	return FormatClashTextDomain
}

func hasSurgeOnly(sample []string) bool {
	for _, s := range sample {
		switch ruleType(s) {
		case "DOMAIN-WILDCARD", "USER-AGENT", "URL-REGEX", "DEST-PORT", "DOMAIN-SET", "CELLULAR-RADIO", "DEVICE-NAME", "SCRIPT":
			return true
		}
	}
	return false
}

func splitFields(s string) []string {
	f := strings.Split(s, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

// Options a classical line may carry after the value.
var lineOptions = map[string]bool{
	"no-resolve": true, "extended-matching": true, "pre-matching": true, "src": true,
}

func (p *Parsed) classical(line string, surge bool) {
	t := ruleType(line)
	if t == "" {
		p.unsupported(unsupportedInvalidEntry)
		return
	}
	switch t {
	case "AND", "OR", "NOT":
		p.unsupported(t)
		return
	}
	f := splitFields(line)
	if len(f) < 2 || f[1] == "" {
		p.unsupported(unsupportedInvalidEntry)
		return
	}
	val := f[1]
	noResolve, policy := false, false
	for _, o := range f[2:] {
		switch {
		case strings.EqualFold(o, "no-resolve"):
			noResolve = true
		case lineOptions[strings.ToLower(o)]:
		case o == "":
		default:
			policy = true
		}
	}
	if policy {
		p.PolicyIgnored++
	}
	switch t {
	case "DOMAIN", "DOMAIN-SUFFIX":
		d, ok := ordered.NormDomain(strings.TrimPrefix(val, "."))
		if !ok {
			p.unsupported(unsupportedInvalidEntry)
			return
		}
		k := ordered.Exact
		if t == "DOMAIN-SUFFIX" {
			k = ordered.Suffix
		}
		p.add(ordered.Entry{Kind: k, Value: d})
	case "DOMAIN-KEYWORD":
		k, ok := ordered.NormKeyword(val)
		if !ok {
			p.unsupported(unsupportedInvalidEntry)
			return
		}
		p.add(ordered.Entry{Kind: ordered.Keyword, Value: k})
	case "DOMAIN-WILDCARD":
		if strings.HasPrefix(val, "*.") && !strings.ContainsAny(val[2:], "*?") {
			if d, ok := ordered.NormDomain(val[2:]); ok {
				p.add(ordered.Entry{Kind: ordered.Sub, Value: d})
				return
			}
		}
		if !strings.ContainsAny(val, "*?") {
			if d, ok := ordered.NormDomain(val); ok {
				p.add(ordered.Entry{Kind: ordered.Exact, Value: d})
				return
			}
		}
		p.unsupported("DOMAIN-WILDCARD")
	case "IP-CIDR", "IP-CIDR6":
		pr, ok := parseCIDR(val)
		if !ok {
			p.unsupported(unsupportedInvalidEntry)
			return
		}
		if noResolve {
			p.NoResolve++
		}
		p.add(ordered.Entry{Kind: ordered.CIDR, Prefix: pr})
	default:
		p.unsupported(t)
	}
}

func parseCIDR(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if pr, err := netip.ParsePrefix(s); err == nil {
		pr = pr.Masked()
		if pr.Addr().Is4In6() {
			a := pr.Addr().Unmap()
			b := pr.Bits() - 96
			if b < 0 {
				return netip.Prefix{}, false
			}
			pr = netip.PrefixFrom(a, b)
		}
		return pr, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func (p *Parsed) cidr(s string) {
	if pr, ok := parseCIDR(s); ok {
		p.add(ordered.Entry{Kind: ordered.CIDR, Prefix: pr})
		return
	}
	p.unsupported(unsupportedInvalidEntry)
}

func (p *Parsed) clashDomain(s string) {
	var k ordered.Kind
	switch {
	case strings.HasPrefix(s, "+."):
		k, s = ordered.Suffix, s[2:]
	case strings.HasPrefix(s, "*."):
		// One label exactly: not expressible in SmartDNS.
		p.unsupported("wildcard-one-label")
		return
	case strings.HasPrefix(s, "."):
		k, s = ordered.Sub, s[1:]
	default:
		k = ordered.Exact
	}
	if strings.ContainsAny(s, "*+") {
		p.unsupported("wildcard")
		return
	}
	d, ok := ordered.NormDomain(s)
	if !ok {
		p.unsupported(unsupportedInvalidEntry)
		return
	}
	p.add(ordered.Entry{Kind: k, Value: d})
}

func (p *Parsed) surgeDomain(s string) {
	k := ordered.Exact
	if strings.HasPrefix(s, ".") {
		k, s = ordered.Suffix, s[1:]
	}
	if strings.ContainsAny(s, "*?+") {
		p.unsupported("wildcard")
		return
	}
	d, ok := ordered.NormDomain(s)
	if !ok {
		p.unsupported(unsupportedInvalidEntry)
		return
	}
	p.add(ordered.Entry{Kind: k, Value: d})
}
