package ordered

import (
	"net/netip"
	"strings"
)

// Exclusions of a rule-set (model.RuleSet.Exclude, docs/architecture.md
// 「规则集的排除条目」).
//
// Definition. An exclusion x removes from the set's effective entries every
// entry it covers (Covers(x, e): every name, or address, e matches is also
// matched by x); a CIDR exclusion also removes its addresses from every CIDR
// entry that contains it. A name or address that the set matched only
// through removed entries (or removed addresses) no longer matches the set's
// rule and falls through to later rules. Precisely, for one rule:
//
//   - a domain entry e (exact, suffix, sub, keyword) matches a name n when
//     e.Matches(n) and no exclusion covers e;
//   - a CIDR entry e matches an address a when e contains a and no CIDR
//     exclusion contains a.
//
// Reference applies this definition literally (Rule.Exclude);
// ApplyExclusions turns it into a plain entry list (covered entries dropped,
// CIDR entries cut around CIDR exclusions) which every other evaluation path
// uses: the host's derive step (resolver domain-sets and nft address sets,
// Derive), the forwarder's decide.json (LoadSnapshot), the panel's tester
// and analysis. TestApplyExclusionsEqualsDefinition proves the two forms
// equal.
//
// Edge cases, all from the definition:
//
//   - An exclusion equal to an entry removes it.
//   - A broader exclusion (suffix example.com) removes every entry under it:
//     exact a.example.com, suffix b.example.com, sub c.example.com, and
//     keyword entries containing it do not count (a keyword matches names
//     elsewhere too).
//   - A keyword exclusion removes the domain entries whose value contains it
//     (every name they match contains it) and keyword entries containing it;
//     it does not remove names below a remaining suffix that happen to
//     contain it.
//   - A narrower domain exclusion (a.example.com inside the entry suffix
//     example.com) removes nothing: the names under it still match through
//     the wider entry. The resolver picks the longest key and has no way to
//     cut a hole into a suffix entry that falls through to later rules or
//     the default, so this is not offered: ExclusionStat.Inside names the
//     covering entry, the panel refuses such an exclusion when it is added
//     and reports it when an update made it so.
//   - A narrower CIDR exclusion (198.51.100.0/26 inside the entry
//     198.51.100.0/24) is cut out exactly (198.51.100.64/26 and
//     198.51.100.128/25 remain), so addresses inside it fall through on every
//     path.
//   - A domain exclusion never touches CIDR entries and a CIDR exclusion
//     never touches domain entries: an address that a CIDR entry of the set
//     matches still matches the set when its name was excluded.

// MaxExclusions is the most exclusions one rule-set may have.
const MaxExclusions = 500

// Covers reports whether every name (or address) b matches is also matched
// by a.
func Covers(a, b Entry) bool {
	switch a.Kind {
	case CIDR:
		return b.Kind == CIDR && a.Prefix.Bits() <= b.Prefix.Bits() && a.Prefix.Contains(b.Prefix.Addr())
	case Keyword:
		switch b.Kind {
		case Exact, Suffix, Sub, Keyword:
			// Every name b matches contains b.Value (for sub and suffix as
			// its tail), hence a.Value.
			return strings.Contains(b.Value, a.Value)
		}
	case Exact:
		return b.Kind == Exact && b.Value == a.Value
	case Suffix:
		switch b.Kind {
		case Exact, Suffix, Sub:
			return Under(b.Value, a.Value)
		}
	case Sub:
		switch b.Kind {
		case Exact, Suffix:
			return strings.HasSuffix(b.Value, "."+a.Value)
		case Sub:
			return Under(b.Value, a.Value)
		}
	}
	return false
}

// excludedFor is the definition for one entry and one query (Reference).
func excludedFor(excl []Entry, e Entry, q Query) bool {
	for _, x := range excl {
		if e.Kind == CIDR {
			if x.Kind == CIDR && q.Addr.IsValid() && x.Prefix.Contains(q.Addr.Unmap()) {
				return true
			}
			continue
		}
		if x.Kind != CIDR && Covers(x, e) {
			return true
		}
	}
	return false
}

// ExclusionStat is what one exclusion did to a set's content.
type ExclusionStat struct {
	Exclusion Entry `json:"-"`
	// Removed entries (covered by the exclusion).
	Removed int `json:"removed"`
	// Trimmed CIDR entries the exclusion was cut out of.
	Trimmed int `json:"trimmed,omitempty"`
	// Inside is a remaining entry that covers the exclusion: the names it
	// names still match the set through that entry (nil: none).
	Inside *Entry `json:"-"`
}

// Stale: the exclusion corresponds to nothing in the content (it removes,
// trims and lies inside nothing).
func (s ExclusionStat) Stale() bool { return s.Removed == 0 && s.Trimmed == 0 && s.Inside == nil }

// Excluded is the result of ApplyExclusions.
type Excluded struct {
	// Entries are the effective entries.
	Entries []Entry
	// Stats, one per exclusion, in the order given.
	Stats []ExclusionStat
	// Removed is the number of entries dropped whole.
	Removed int
}

// ApplyExclusions is the one derivation of a rule-set's effective entries
// from its content and its exclusions (see the definition above). Entries
// keep their order; a CIDR entry cut by an exclusion is replaced, in place,
// by the prefixes that remain. Without exclusions the content is returned
// as it is.
func ApplyExclusions(entries, excl []Entry) Excluded {
	out := Excluded{Stats: make([]ExclusionStat, len(excl))}
	if len(excl) == 0 {
		out.Entries = entries
		return out
	}
	for i, x := range excl {
		out.Stats[i].Exclusion = x
	}
	// Domain exclusions by kind (looked up per ancestor of an entry);
	// keywords and CIDRs are few and scanned.
	exact, suffix, sub := map[string][]int{}, map[string][]int{}, map[string][]int{}
	var kws, nets []int
	for i, x := range excl {
		switch x.Kind {
		case Exact:
			exact[x.Value] = append(exact[x.Value], i)
		case Suffix:
			suffix[x.Value] = append(suffix[x.Value], i)
		case Sub:
			sub[x.Value] = append(sub[x.Value], i)
		case Keyword:
			kws = append(kws, i)
		case CIDR:
			nets = append(nets, i)
		}
	}
	coveredBy := func(e Entry) []int {
		var by []int
		if e.Kind == Keyword {
			for _, i := range kws {
				if Covers(excl[i], e) {
					by = append(by, i)
				}
			}
			return by
		}
		if e.Kind == Exact {
			by = append(by, exact[e.Value]...)
		}
		for x, strict := e.Value, false; ; strict = true {
			by = append(by, suffix[x]...)
			// sub x covers names strictly below x: an exact or suffix
			// entry strictly below, a sub entry at x or below.
			if strict || e.Kind == Sub {
				by = append(by, sub[x]...)
			}
			j := strings.IndexByte(x, '.')
			if j < 0 {
				break
			}
			x = x[j+1:]
		}
		for _, i := range kws {
			if Covers(excl[i], e) {
				by = append(by, i)
			}
		}
		return by
	}
	for _, e := range entries {
		if e.Kind == CIDR {
			var cut []netip.Prefix
			whole := false
			for _, i := range nets {
				x := excl[i].Prefix
				if !x.Overlaps(e.Prefix) {
					continue
				}
				if x.Bits() <= e.Prefix.Bits() {
					out.Stats[i].Removed++
					whole = true
					continue
				}
				out.Stats[i].Trimmed++
				cut = append(cut, x)
			}
			if whole {
				out.Removed++
				continue
			}
			if len(cut) == 0 {
				out.Entries = append(out.Entries, e)
				continue
			}
			for _, p := range subtractPrefixes(e.Prefix, cut) {
				out.Entries = append(out.Entries, Entry{Kind: CIDR, Prefix: p})
			}
			continue
		}
		by := coveredBy(e)
		if len(by) == 0 {
			out.Entries = append(out.Entries, e)
			continue
		}
		out.Removed++
		seen := map[int]bool{}
		for _, i := range by {
			if !seen[i] {
				seen[i] = true
				out.Stats[i].Removed++
			}
		}
	}
	// Narrower domain exclusions: a remaining entry still covers them.
	var remainKw []Entry
	rexact, rsuffix, rsub := map[string]Entry{}, map[string]Entry{}, map[string]Entry{}
	for _, e := range out.Entries {
		switch e.Kind {
		case Exact:
			rexact[e.Value] = e
		case Suffix:
			rsuffix[e.Value] = e
		case Sub:
			rsub[e.Value] = e
		case Keyword:
			remainKw = append(remainKw, e)
		}
	}
	for i, x := range excl {
		if x.Kind == CIDR {
			continue
		}
		var in *Entry
		if x.Kind != Keyword {
			if e, ok := rexact[x.Value]; ok && x.Kind == Exact {
				in = &e
			}
			for a, strict := x.Value, false; in == nil; strict = true {
				if e, ok := rsuffix[a]; ok {
					in = &e
					break
				}
				if e, ok := rsub[a]; ok && (strict || x.Kind == Sub) {
					in = &e
					break
				}
				j := strings.IndexByte(a, '.')
				if j < 0 {
					break
				}
				a = a[j+1:]
			}
		}
		for k := 0; in == nil && k < len(remainKw); k++ {
			if Covers(remainKw[k], x) {
				e := remainKw[k]
				in = &e
			}
		}
		out.Stats[i].Inside = in
	}
	return out
}

// subtractPrefixes returns the parts of p outside every prefix in cut (each
// strictly inside p or disjoint from it), as disjoint prefixes in address
// order.
func subtractPrefixes(p netip.Prefix, cut []netip.Prefix) []netip.Prefix {
	for _, x := range cut {
		if !x.Overlaps(p) {
			continue
		}
		if x.Bits() <= p.Bits() {
			return nil
		}
		lo, hi := halves(p)
		return append(subtractPrefixes(lo, cut), subtractPrefixes(hi, cut)...)
	}
	return []netip.Prefix{p}
}

// halves splits p into its two prefixes one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	b := p.Bits()
	lo := netip.PrefixFrom(p.Addr(), b+1)
	a := p.Addr().As16()
	off := 0
	if p.Addr().Is4() {
		off = 12
	}
	a[off+b/8] |= 0x80 >> (b % 8)
	ha := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		ha = ha.Unmap()
	}
	return lo, netip.PrefixFrom(ha, b+1)
}

// effectiveRules applies each rule's Exclude to its entries (a copy of the
// list when any rule has exclusions).
func effectiveRules(rules []Rule) []Rule {
	has := false
	for _, r := range rules {
		if len(r.Exclude) > 0 {
			has = true
			break
		}
	}
	if !has {
		return rules
	}
	out := make([]Rule, len(rules))
	for i, r := range rules {
		if len(r.Exclude) > 0 {
			r.Entries = ApplyExclusions(r.Entries, r.Exclude).Entries
			r.Exclude = nil
		}
		out[i] = r
	}
	return out
}
