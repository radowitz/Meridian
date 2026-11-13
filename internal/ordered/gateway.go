package ordered

import (
	"fmt"
	"io/fs"
	"net/netip"
	"strings"
)

// DNSModel reproduces how SmartDNS Release48.4 picks the domain rule of a
// query (src/dns_conf/domain_rule.c _config_setup_domain_key,
// src/dns_server/rules.c _dns_server_get_rules): every configured key is
// the reversed domain with a leading "."; a plain key also gets a trailing
// "." (the name and everything under it), "*.d" keeps the trailing "." but
// only applies to names below d, "-.d" has no trailing "." and only applies
// to d itself. The lookup key of a name is "." + reversed name + "."; every
// stored key that is a prefix of it is visited from the shortest to the
// longest, and each visited rule of a type overwrites the previous one, so
// the longest applicable key wins (per rule type; the gateway gives every
// domain rule the same types, nameserver and nftset). The opt-in test with
// the real binary (internal/compile TestOrderedRealSmartDNS) checks this
// model against the pinned executable.
type DNSModel struct {
	nodes map[string]dnsNode
}

type dnsNode struct {
	set      string
	rootOnly bool
	subOnly  bool
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// NewDNSModel returns an empty model.
func NewDNSModel() *DNSModel { return &DNSModel{nodes: map[string]dnsNode{}} }

// Add loads one domain-set line for set. A second line with the same key
// is an error: Derive never writes one (two rules on one key would make the
// result depend on SmartDNS's load order).
func (m *DNSModel) Add(line, set string) error {
	n := dnsNode{set: set}
	var key string
	switch {
	case strings.HasPrefix(line, "*."):
		n.subOnly = true
		key = "." + reverse(line[2:]) + "."
	case strings.HasPrefix(line, "-."):
		n.rootOnly = true
		key = "." + reverse(line[2:])
	default:
		key = "." + reverse(strings.TrimPrefix(line, ".")) + "."
	}
	if old, ok := m.nodes[key]; ok {
		return fmt.Errorf("key %q of set %s already belongs to set %s", line, set, old.set)
	}
	m.nodes[key] = n
	return nil
}

// Lookup returns the set whose rule SmartDNS applies to name ("" none).
func (m *DNSModel) Lookup(name string) string {
	lk := "." + reverse(name) + "."
	full := len(lk)
	got := ""
	for l := 1; l <= full; l++ {
		n, ok := m.nodes[lk[:l]]
		if !ok {
			continue
		}
		sub := !(l == full || l == full-1)
		if n.subOnly && !sub || n.rootOnly && sub {
			continue
		}
		got = n.set
	}
	return got
}

// Link is one classify-chain position: the nft sets checked there and the
// mark (target) they set.
type Link struct {
	// Sets are the address sets of this position (learned from DNS: the
	// set SmartDNS writes into; static: CIDR elements).
	Sets   []string
	Static []netip.Prefix
	China  bool
	Target string
	// Index is the rule's list position (-1: the tail).
	Index int
}

// Gateway is the data-plane model: SmartDNS's rule choice (DNSModel) feeding
// learned addresses into nft sets, and the classify chain checking them in
// order. State persists across queries, as on the gateway: an address
// learned for one name stays in its set (until its TTL) and is seen by
// every later connection to it.
type Gateway struct {
	DNS     *DNSModel
	Chain   []Link
	Default string
	China   []netip.Prefix
	learned map[string]map[netip.Addr]bool
}

// Resolve is a query for name answered with addr: SmartDNS writes addr into
// the set of the rule it picked for name.
func (g *Gateway) Resolve(name string, addr netip.Addr) {
	set := g.DNS.Lookup(name)
	if set == "" {
		set = "default"
	}
	if g.learned == nil {
		g.learned = map[string]map[netip.Addr]bool{}
	}
	if g.learned[set] == nil {
		g.learned[set] = map[netip.Addr]bool{}
	}
	g.learned[set][addr.Unmap()] = true
}

// Classify is the classify chain for one destination address.
func (g *Gateway) Classify(addr netip.Addr) Match {
	addr = addr.Unmap()
	for _, l := range g.Chain {
		hit := false
		for _, s := range l.Sets {
			if g.learned[s][addr] {
				hit = true
			}
		}
		for _, p := range l.Static {
			if p.Contains(addr) {
				hit = true
			}
		}
		if l.China && inChina(g.China, addr) {
			hit = true
		}
		if hit {
			return Match{Index: l.Index, Target: l.Target}
		}
	}
	return Match{Index: -1, Target: g.Default}
}

// Query is one connection: the client resolves q.Name (when set) through
// the gateway, then connects to q.Addr.
func (g *Gateway) Query(q Query) Match {
	q.Name, _ = NormDomain(q.Name)
	if q.Name != "" {
		g.Resolve(q.Name, q.Addr)
	}
	return g.Classify(q.Addr)
}

// MemReader serves dynamic sources from memory (tests, the panel tester).
type MemReader struct {
	Geo      map[string][]string
	Kw       map[string][]string
	RuleSets map[string][]Entry
}

func notExist(kind, n string) error { return fmt.Errorf("%s %s: %w", kind, n, fs.ErrNotExist) }

// Geosite implements Reader.
func (r MemReader) Geosite(stem string) ([]string, error) {
	v, ok := r.Geo[stem]
	if !ok {
		return nil, notExist("geosite", stem)
	}
	return v, nil
}

// Keyword implements Reader.
func (r MemReader) Keyword(stem string) ([]string, error) {
	v, ok := r.Kw[stem]
	if !ok {
		return nil, notExist("keyword", stem)
	}
	return v, nil
}

// RuleSet implements Reader.
func (r MemReader) RuleSet(id string) ([]Entry, error) {
	v, ok := r.RuleSets[id]
	if !ok {
		return nil, notExist("ruleset", id)
	}
	return v, nil
}

// Plan is the generic compile of an ordered rule list: one manifest set
// and one chain link per rule (named r<i>, CIDR sets r<i>c), then the
// domestic list (set gs_cn, addresses into direct) and the China fallback.
// internal/compile renders the same shape into smartdns.conf and the nft
// classify chain; Plan is what the property tests and the panel tester use.
func Plan(rules []Rule, tail Tail) (Manifest, []Link, MemReader) {
	var m Manifest
	var chain []Link
	rd := MemReader{RuleSets: map[string][]Entry{}, Geo: map[string][]string{}}
	for i, r := range rules {
		name := fmt.Sprintf("r%d", i)
		set := ManifestSet{Name: name}
		var static []netip.Prefix
		var dyn []Entry
		for _, e := range r.Entries {
			switch e.Kind {
			case Exact:
				set.Add(SrcExact, e.Value)
			case Suffix:
				set.Add(SrcSuffix, e.Value)
			case CIDR:
				static = append(static, e.Prefix)
			case Keyword, Sub:
				dyn = append(dyn, e)
			}
		}
		if len(dyn) > 0 {
			id := fmt.Sprintf("rs-%d", i)
			rd.RuleSets[id] = dyn
			set.Add(SrcRuleSet, id)
		}
		m.Sets = append(m.Sets, set)
		chain = append(chain, Link{Sets: []string{name}, Static: static, China: r.GeoIPCN, Target: r.Target, Index: i})
	}
	dom := ManifestSet{Name: "gs_cn"}
	dom.Add(SrcGeosite, "cn")
	rd.Geo["cn"] = tail.Domestic
	m.Sets = append(m.Sets, dom)
	chain = append(chain,
		Link{Sets: []string{"gs_cn"}, Target: tail.DirectTarget, Index: -1},
		Link{China: true, Target: tail.DirectTarget, Index: -1})
	return m, chain, rd
}

// NewGateway loads derived files into a DNSModel and returns the data-plane
// model for chain.
func NewGateway(d Derived, chain []Link, tail Tail) (*Gateway, error) {
	dm := NewDNSModel()
	for _, set := range d.Order {
		for _, l := range d.Files[set] {
			if err := dm.Add(l, set); err != nil {
				return nil, err
			}
		}
	}
	return &Gateway{DNS: dm, Chain: chain, Default: tail.Default, China: tail.China}, nil
}
