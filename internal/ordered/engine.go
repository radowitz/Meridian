package ordered

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"strings"
	"sync/atomic"
)

// Compiled is an immutable, indexed form of an ordered rule list for fast
// first-match decisions (Decide). It is safe for concurrent use. Build it
// with Compile; swap it atomically with Engine.
//
// Indexes: exact / suffix / sub keys in hash maps keyed by the name (a name
// is looked up once per ancestor, so a decision costs O(labels)); keywords
// in an Aho-Corasick automaton (one pass over the name); CIDRs in one map
// per prefix length (at most 33 / 129 lookups); every index keeps the
// lowest rule index per key, so the first match in list order wins.
type Compiled struct {
	rules   []Rule
	exact   map[string]int
	suffix  map[string]int
	sub     map[string]int
	kw      *acMachine
	cidr    prefixIndex
	geoip   int // first GEOIP,CN rule, -1 none
	china   prefixIndex
	dom     map[string]bool
	tail    Tail
	quicAt  int
	sources []int // rules with a source restriction
}

type prefixIndex struct {
	v4 [33]map[netip.Prefix]int
	v6 [129]map[netip.Prefix]int
}

func (p *prefixIndex) add(pr netip.Prefix, i int) {
	pr = pr.Masked()
	b := pr.Bits()
	tab := &p.v6
	if pr.Addr().Is4() {
		m := &p.v4[b]
		if *m == nil {
			*m = map[netip.Prefix]int{}
		}
		if _, ok := (*m)[pr]; !ok {
			(*m)[pr] = i
		}
		return
	}
	if tab[b] == nil {
		tab[b] = map[netip.Prefix]int{}
	}
	if _, ok := tab[b][pr]; !ok {
		tab[b][pr] = i
	}
}

// lookup returns the lowest index of a prefix containing a (-1 none).
func (p *prefixIndex) lookup(a netip.Addr) int {
	best := -1
	a = a.Unmap()
	if a.Is4() {
		for b := 0; b <= 32; b++ {
			if m := p.v4[b]; m != nil {
				pr, _ := a.Prefix(b)
				if i, ok := m[pr]; ok && (best < 0 || i < best) {
					best = i
				}
			}
		}
		return best
	}
	for b := 0; b <= 128; b++ {
		if m := p.v6[b]; m != nil {
			pr, _ := a.Prefix(b)
			if i, ok := m[pr]; ok && (best < 0 || i < best) {
				best = i
			}
		}
	}
	return best
}

// Compile indexes rules (in list order) with tail. quicAt is the number of
// rules above the QUIC switch row (-1: no switch).
func Compile(rules []Rule, tail Tail, quicAt int) *Compiled {
	c := &Compiled{rules: rules, exact: map[string]int{}, suffix: map[string]int{}, sub: map[string]int{}, geoip: -1, dom: map[string]bool{}, tail: tail, quicAt: quicAt}
	var kws []string
	var kwIdx []int
	first := func(m map[string]int, k string, i int) {
		if _, ok := m[k]; !ok {
			m[k] = i
		}
	}
	for i, r := range rules {
		if len(r.Sources) > 0 {
			c.sources = append(c.sources, i)
		}
		if r.GeoIPCN && c.geoip < 0 && len(r.Sources) == 0 {
			c.geoip = i
		}
		if len(r.Sources) > 0 {
			continue // checked one by one (rare: device rules)
		}
		for _, e := range r.Entries {
			switch e.Kind {
			case Exact:
				first(c.exact, e.Value, i)
			case Suffix:
				first(c.suffix, e.Value, i)
			case Sub:
				first(c.sub, e.Value, i)
			case Keyword:
				kws, kwIdx = append(kws, e.Value), append(kwIdx, i)
			case CIDR:
				c.cidr.add(e.Prefix, i)
			}
		}
	}
	c.kw = newAC(kws, kwIdx)
	for _, p := range tail.China {
		c.china.add(p, 0)
	}
	for _, d := range tail.Domestic {
		if n, ok := NormDomain(d); ok {
			c.dom[n] = true
		}
	}
	return c
}

// Request is one connection as the decision sees it.
type Request struct {
	Name   string
	Addr   netip.Addr
	Proto  string // "tcp", "udp" or ""
	Port   int
	Source netip.Addr
}

// Decision is the result of Decide.
type Decision struct {
	Index  int    `json:"index"` // -1: the tail
	ID     string `json:"id,omitempty"`
	Target string `json:"target"`
	Mark   uint32 `json:"mark,omitempty"`
	Reason string `json:"reason"`
	// QUICRejected: UDP 443 refused by the QUIC switch.
	QUICRejected bool `json:"quic_rejected,omitempty"`
}

func (c *Compiled) nameMatch(name string) (int, Entry) {
	best, be := -1, Entry{}
	try := func(i int, e Entry) {
		if i >= 0 && (best < 0 || i < best) {
			best, be = i, e
		}
	}
	if i, ok := c.exact[name]; ok {
		try(i, Entry{Kind: Exact, Value: name})
	}
	for x, strict := name, false; ; strict = true {
		if i, ok := c.suffix[x]; ok {
			try(i, Entry{Kind: Suffix, Value: x})
		}
		if strict {
			if i, ok := c.sub[x]; ok {
				try(i, Entry{Kind: Sub, Value: x})
			}
		}
		j := strings.IndexByte(x, '.')
		if j < 0 {
			break
		}
		x = x[j+1:]
	}
	if i, kw := c.kw.first(name); i >= 0 {
		try(i, Entry{Kind: Keyword, Value: kw})
	}
	return best, be
}

// Decide is the first-match decision of the ordered list for one
// connection: the lowest-index rule with a matching entry (domain entries
// test the name, CIDR entries and GEOIP,CN the destination address, a
// source restriction the client address), else the tail (domestic list,
// China addresses, default). Equal to Reference (TestDecideMatchesReference).
func (c *Compiled) Decide(q Request) Decision {
	name, _ := NormDomain(q.Name)
	best, be := -1, Entry{}
	if name != "" {
		best, be = c.nameMatch(name)
	}
	if q.Addr.IsValid() {
		if i := c.cidr.lookup(q.Addr); i >= 0 && (best < 0 || i < best) {
			best, be = i, Entry{Kind: CIDR}
			for _, e := range c.rules[i].Entries {
				if e.Kind == CIDR && e.Prefix.Contains(q.Addr.Unmap()) {
					be = e
					break
				}
			}
		}
		if c.geoip >= 0 && (best < 0 || c.geoip < best) && c.china.lookup(q.Addr) >= 0 {
			best, be = c.geoip, Entry{}
		}
	}
	// Device rules (source restriction): checked one by one, only where
	// they could still win.
	for _, i := range c.sources {
		if best >= 0 && i > best {
			break
		}
		r := c.rules[i]
		if !sourceOK(r, q.Source) {
			continue
		}
		qq := Query{Name: name, Addr: q.Addr}
		for _, e := range r.Entries {
			if e.Matches(qq) {
				best, be = i, e
				break
			}
		}
		if r.GeoIPCN && q.Addr.IsValid() && c.china.lookup(q.Addr) >= 0 {
			best, be = i, Entry{}
		}
		if best == i {
			break
		}
	}
	var d Decision
	if best >= 0 {
		r := c.rules[best]
		d = Decision{Index: best, ID: r.ID, Target: r.Target, Mark: r.Mark, Reason: reason(be)}
		if be.Kind == "" {
			d.Reason = "目的地址属于中国（GEOIP,CN）"
		}
		if r.Action == "direct" {
			return d
		}
	} else {
		d = c.tailDecision(name, q.Addr)
		if d.Target == c.tail.DirectTarget {
			return d
		}
	}
	if c.quicAt >= 0 && strings.EqualFold(q.Proto, "udp") && q.Port == 443 && (best < 0 || best >= c.quicAt) && c.rules != nil {
		if best < 0 || c.rules[best].Action != "reject" {
			d.QUICRejected = true
			d.Reason += "；UDP 443 被 QUIC 开关拒绝"
		}
	}
	return d
}

func sourceOK(r Rule, src netip.Addr) bool {
	if len(r.Sources) == 0 {
		return true
	}
	for _, p := range r.Sources {
		if src.IsValid() && p.Contains(src.Unmap()) {
			return true
		}
	}
	return false
}

func (c *Compiled) tailDecision(name string, a netip.Addr) Decision {
	if name != "" {
		for x := name; ; {
			if c.dom[x] {
				return Decision{Index: -1, Target: c.tail.DirectTarget, Mark: c.tail.DirectMark, Reason: "内置国内名单（规则之后）：" + x}
			}
			j := strings.IndexByte(x, '.')
			if j < 0 {
				break
			}
			x = x[j+1:]
		}
	}
	if a.IsValid() && c.china.lookup(a) >= 0 {
		return Decision{Index: -1, Target: c.tail.DirectTarget, Mark: c.tail.DirectMark, Reason: "目的地址属于中国（规则和国内名单之后）"}
	}
	return Decision{Index: -1, Target: c.tail.Default, Mark: c.tail.DefaultMark, Reason: "没有规则命中：默认组（MATCH）"}
}

// Engine holds the current Compiled value; Swap replaces it atomically
// (a decision in flight keeps using the value it started with).
type Engine struct{ p atomic.Pointer[Compiled] }

// Swap installs c.
func (e *Engine) Swap(c *Compiled) { e.p.Store(c) }

// Decide uses the current value; ok false before the first Swap.
func (e *Engine) Decide(q Request) (Decision, bool) {
	c := e.p.Load()
	if c == nil {
		return Decision{}, false
	}
	return c.Decide(q), true
}

// ------------------------------------------------- serialized form ---

// SnapshotVersion is the version of the serialized rule list.
const SnapshotVersion = 1

// Snapshot is the serialized ordered rule list the gateway install writes
// (/etc/meridian/rules/decide.json, internal/compile): every enabled rule
// in list order with its target resolved through its service group to a
// mark, its static entries (MarshalEntries text) and references to its
// dynamic content (rule-set, geosite category, keyword expansion — the same
// files the derive step reads), the QUIC switch position and the tail.
// LoadSnapshot resolves the references through a Reader.
type Snapshot struct {
	Version int            `json:"version"`
	Rules   []SnapshotRule `json:"rules"`
	QUICAt  int            `json:"quic_at"`
	Tail    SnapshotTail   `json:"tail"`
}

// SnapshotRule is one rule.
type SnapshotRule struct {
	ID      string   `json:"id"`
	Target  string   `json:"target"` // "group:hk", "exit:jp", "direct", "reject"
	Mark    uint32   `json:"mark"`
	Action  string   `json:"action,omitempty"`
	Entries string   `json:"entries,omitempty"` // MarshalEntries form
	Sources []Source `json:"sources,omitempty"` // dynamic content
	GeoIPCN bool     `json:"geoip_cn,omitempty"`
	// SourceAddrs restricts the rule to clients (device rules). A rule
	// restricted by MAC address (SourceMAC) is left out by LoadSnapshot: a
	// decision by name does not see the client's MAC.
	SourceAddrs []string `json:"source_addrs,omitempty"`
	SourceMAC   string   `json:"source_mac,omitempty"`
}

// SnapshotTail is the tail after the rules.
type SnapshotTail struct {
	DomesticGeosite string `json:"domestic_geosite"` // geosite stem ("cn")
	DirectMark      uint32 `json:"direct_mark"`
	Default         string `json:"default"`
	DefaultMark     uint32 `json:"default_mark"`
}

// MarshalJSON of Source keeps the manifest kinds.
func (s Source) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"kind": string(s.Kind), "value": s.Value})
}

// UnmarshalJSON of Source.
func (s *Source) UnmarshalJSON(b []byte) error {
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s.Kind, s.Value = SourceKind(m["kind"]), m["value"]
	return nil
}

// LoadSnapshot parses a snapshot and resolves its dynamic sources with r
// (missing files count as empty, as for Derive), returning a Compiled
// value. china is the China address list (lists/china*.txt).
func LoadSnapshot(b []byte, r Reader, china []netip.Prefix) (*Compiled, error) {
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Version != SnapshotVersion {
		return nil, fmt.Errorf("snapshot version %d", s.Version)
	}
	rules := make([]Rule, 0, len(s.Rules))
	for _, sr := range s.Rules {
		if sr.SourceMAC != "" {
			continue
		}
		es, err := UnmarshalEntries([]byte(sr.Entries))
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", sr.ID, err)
		}
		for _, src := range sr.Sources {
			var more []Entry
			switch src.Kind {
			case SrcGeosite, SrcKeyword:
				get := r.Geosite
				if src.Kind == SrcKeyword {
					get = r.Keyword
				}
				names, err := get(src.Value)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return nil, err
				}
				for _, n := range names {
					if d, ok := NormDomain(n); ok {
						more = append(more, Entry{Kind: Suffix, Value: d})
					}
				}
			case SrcRuleSet:
				x, err := r.RuleSet(src.Value)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return nil, err
				}
				more = x
			}
			es = append(es, more...)
		}
		rule := Rule{ID: sr.ID, Target: sr.Target, Mark: sr.Mark, Action: sr.Action, Entries: es, GeoIPCN: sr.GeoIPCN}
		for _, a := range sr.SourceAddrs {
			if p, err := netip.ParsePrefix(a); err == nil {
				rule.Sources = append(rule.Sources, p)
			} else if ad, err := netip.ParseAddr(a); err == nil {
				rule.Sources = append(rule.Sources, netip.PrefixFrom(ad, ad.BitLen()))
			}
		}
		rules = append(rules, rule)
	}
	tail := Tail{China: china, DirectTarget: "direct", DirectMark: s.Tail.DirectMark, Default: s.Tail.Default, DefaultMark: s.Tail.DefaultMark}
	if s.Tail.DomesticGeosite != "" {
		names, err := r.Geosite(s.Tail.DomesticGeosite)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		tail.Domestic = names
	}
	return Compile(rules, tail, s.QUICAt), nil
}

// ------------------------------------------------------ Aho-Corasick ---

type acMachine struct {
	next []map[byte]int
	fail []int
	out  []int // lowest rule index ending here (via fail links), -1 none
	word []string
}

func newAC(words []string, idx []int) *acMachine {
	m := &acMachine{next: []map[byte]int{{}}, fail: []int{0}, out: []int{-1}, word: []string{""}}
	for k, w := range words {
		s := 0
		for i := 0; i < len(w); i++ {
			n, ok := m.next[s][w[i]]
			if !ok {
				m.next = append(m.next, map[byte]int{})
				m.fail = append(m.fail, 0)
				m.out = append(m.out, -1)
				m.word = append(m.word, "")
				n = len(m.next) - 1
				m.next[s][w[i]] = n
			}
			s = n
		}
		if m.out[s] < 0 || idx[k] < m.out[s] {
			m.out[s], m.word[s] = idx[k], w
		}
	}
	// BFS for failure links; out takes the minimum along them.
	queue := []int{}
	for _, n := range m.next[0] {
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c, n := range m.next[s] {
			f := m.fail[s]
			for f > 0 {
				if _, ok := m.next[f][c]; ok {
					break
				}
				f = m.fail[f]
			}
			if x, ok := m.next[f][c]; ok && x != n {
				m.fail[n] = x
			}
			if o := m.out[m.fail[n]]; o >= 0 && (m.out[n] < 0 || o < m.out[n]) {
				m.out[n], m.word[n] = o, m.word[m.fail[n]]
			}
			queue = append(queue, n)
		}
	}
	return m
}

// first returns the lowest rule index of a keyword contained in s.
func (m *acMachine) first(s string) (int, string) {
	best, w := -1, ""
	if len(m.next) == 1 {
		return -1, ""
	}
	st := 0
	for i := 0; i < len(s); i++ {
		for st > 0 {
			if _, ok := m.next[st][s[i]]; ok {
				break
			}
			st = m.fail[st]
		}
		if n, ok := m.next[st][s[i]]; ok {
			st = n
		}
		if o := m.out[st]; o >= 0 && (best < 0 || o < best) {
			best, w = o, m.word[st]
		}
	}
	return best, w
}
