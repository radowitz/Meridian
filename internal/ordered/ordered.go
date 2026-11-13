// Package ordered is the first-match model of the gateway's rule list.
//
// The panel's rules are one ordered list, evaluated top to bottom; the first
// rule that matches a connection decides its target, exactly as in Clash,
// mihomo and Surge. The gateway executes that list with two engines that do
// not evaluate in order by themselves:
//
//   - SmartDNS chooses, for a queried name, the domain rule with the LONGEST
//     matching key (per rule type), whatever order the rules were written in,
//     and writes the answer addresses into that rule's nft set;
//   - nft's classify chain checks destination addresses against the rule sets
//     in chain order and the first set that holds the address marks it.
//
// This package keeps both exact with respect to list order:
//
//   - Reference is the reference interpreter: list order, first match wins.
//   - Derive turns the ordered domain sources (static keys, geosite and
//     keyword files, rule-set contents, the built-in domestic list) into
//     SmartDNS domain-set files in which every key appears once, owned by the
//     first rule that matches it; a key is dropped when an earlier rule
//     already covers every name under it ("priority filtering"). Longest-key
//     selection over the filtered union then equals first match in list
//     order (see Derive for the argument and DNSModel for the matcher).
//   - Chain is the classify chain in list order; with one owner per name,
//     an address learned for a name lands in the set of the first rule that
//     matches the name, and an IP rule earlier in the list wins over a later
//     domain rule (and the other way round) because sets are checked in list
//     order.
//
// What cannot be exact is stated, not approximated: two names with different
// targets that resolve to the same address cannot be told apart by address
// (the earlier rule in list order wins for that address, deterministic,
// encoded in Gateway), keyword entries are not expressible in SmartDNS, and
// the data plane only sees what was resolved through the gateway.
package ordered

import (
	"net/netip"
	"strings"
)

// Kind is the kind of one match entry.
type Kind string

const (
	// Exact matches one name.
	Exact Kind = "exact"
	// Suffix matches a name and every name under it.
	Suffix Kind = "suffix"
	// Sub matches every name strictly below the value, not the value
	// itself (Clash "domain" behaviour ".example.com", Surge
	// DOMAIN-WILDCARD "*.example.com"; SmartDNS "*.example.com").
	Sub Kind = "sub"
	// Keyword matches every name containing the value (mihomo
	// DOMAIN-KEYWORD). SmartDNS cannot express it (no substring or regex
	// match in Release48.4: _config_setup_domain_key only knows plain,
	// "*." and "-." keys).
	Keyword Kind = "keyword"
	// CIDR matches destination addresses.
	CIDR Kind = "cidr"
)

// Entry is one match entry of a rule.
type Entry struct {
	Kind   Kind
	Value  string       // lower-case domain or keyword
	Prefix netip.Prefix // CIDR only (masked)
}

// String is the entry in rule-set notation.
func (e Entry) String() string {
	if e.Kind == CIDR {
		return "cidr:" + e.Prefix.String()
	}
	return string(e.Kind) + ":" + e.Value
}

// NormDomain lower-cases a domain, drops one trailing dot and checks that it
// is a name SmartDNS and nft can carry: labels of [a-z0-9_-], no empty label,
// no leading or trailing "-", at most 253 bytes.
func NormDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return s, true
}

// NormKeyword lower-cases a keyword and checks it is printable and short.
func NormKeyword(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 64 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", false
		}
	}
	return s, true
}

// Under reports whether name equals d or lies below it.
func Under(name, d string) bool {
	return name == d || strings.HasSuffix(name, "."+d)
}

// Rule is one position of the ordered list as the interpreters see it.
// Entries hold everything the rule matches at this moment: its own static
// entries and the current content of its rule-set, geosite category or
// keyword expansion.
type Rule struct {
	ID     string
	Target string
	// Entries in any order; all of them sit at this rule's position.
	Entries []Entry
	// GeoIPCN matches China destination addresses (Tail.China).
	GeoIPCN bool
	// Mark is the data-plane mark of the target (Decide reports it);
	// Action is "direct" or "reject" for those targets.
	Mark   uint32
	Action string
	// Sources restricts the rule to these client addresses (device rules);
	// empty: every client.
	Sources []netip.Prefix
}

// Tail is what follows the last rule: the built-in domestic list (suffix
// keys, resolved by the domestic resolvers, direct), the China address list
// (direct) and the default target (MATCH).
type Tail struct {
	Domestic []string
	China    []netip.Prefix
	// DirectTarget labels the domestic list and the China fallback.
	DirectTarget string
	Default      string
	DirectMark   uint32
	DefaultMark  uint32
}

// Query is one connection: the name the client resolved (empty when it
// connected to an address it did not resolve through the gateway) and the
// destination address.
type Query struct {
	Name string
	Addr netip.Addr
	// Source is the client address (device rules).
	Source netip.Addr
}

// Match is the decision for one query.
type Match struct {
	// Index of the matching rule, -1 for the tail.
	Index  int
	Target string
	// Entry is the matching entry (rules only).
	Entry Entry
	// Reason in words (for the panel's tester).
	Reason string
}

// Matches reports whether e matches q (mihomo semantics: domain entries
// test the name, CIDR entries the destination address).
func (e Entry) Matches(q Query) bool {
	switch e.Kind {
	case Exact:
		return q.Name != "" && q.Name == e.Value
	case Suffix:
		return q.Name != "" && Under(q.Name, e.Value)
	case Sub:
		return q.Name != "" && strings.HasSuffix(q.Name, "."+e.Value)
	case Keyword:
		return q.Name != "" && strings.Contains(q.Name, e.Value)
	case CIDR:
		return q.Addr.IsValid() && e.Prefix.Contains(q.Addr.Unmap())
	}
	return false
}

func inChina(china []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range china {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Reference is the reference interpreter: the rules in list order, the
// first one with a matching entry wins; then the domestic list, the China
// addresses, the default. It is what the panel's "which rule matches"
// tester runs and what every compiled artefact is checked against.
func Reference(rules []Rule, tail Tail, q Query) Match {
	q.Name, _ = NormDomain(q.Name)
	for i, r := range rules {
		if !sourceOK(r, q.Source) {
			continue
		}
		for _, e := range r.Entries {
			if e.Matches(q) {
				return Match{Index: i, Target: r.Target, Entry: e, Reason: reason(e)}
			}
		}
		if r.GeoIPCN && inChina(tail.China, q.Addr) {
			return Match{Index: i, Target: r.Target, Reason: "目的地址属于中国（GEOIP,CN）"}
		}
	}
	if q.Name != "" {
		for _, d := range tail.Domestic {
			if Under(q.Name, d) {
				return Match{Index: -1, Target: tail.DirectTarget, Reason: "内置国内名单（规则之后）：" + d}
			}
		}
	}
	if inChina(tail.China, q.Addr) {
		return Match{Index: -1, Target: tail.DirectTarget, Reason: "目的地址属于中国（规则和国内名单之后）"}
	}
	return Match{Index: -1, Target: tail.Default, Reason: "没有规则命中：默认组（MATCH）"}
}

func reason(e Entry) string {
	switch e.Kind {
	case Exact:
		return "完整域名 " + e.Value
	case Suffix:
		return "域名后缀 " + e.Value
	case Sub:
		return "子域名 *." + e.Value
	case Keyword:
		return "关键词 " + e.Value
	case CIDR:
		return "目的地址在 " + e.Prefix.String()
	}
	return string(e.Kind)
}
