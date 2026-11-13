package ordered

import (
	"net/netip"
	"sort"
	"strings"
)

// RuleAnalysis is the static ordering analysis of one rule: how much of it
// earlier rules already decide, and what the data plane cannot execute.
type RuleAnalysis struct {
	Index int `json:"index"`
	// Entries is the number of match entries (static plus the rule-set,
	// geosite or keyword content the analysis was given).
	Entries int `json:"entries"`
	// Shadowed entries can never match: an earlier rule matches every name
	// or address they match.
	Shadowed int `json:"shadowed"`
	// FullyShadowed: every entry is shadowed (the rule never matches).
	FullyShadowed bool `json:"fully_shadowed"`
	// ShadowedBy are the earlier rules (indexes) that shadow entries;
	// PartlyBy the earlier rules that take only part of an entry (a more
	// specific name or a smaller network listed earlier).
	ShadowedBy []int `json:"shadowed_by,omitempty"`
	PartlyBy   []int `json:"partly_by,omitempty"`
	// Keywords are keyword entries: SmartDNS cannot match a substring, so
	// they do not execute in list order (see Keyword).
	Keywords int `json:"keywords,omitempty"`
}

type keyIndex struct {
	suffix  map[string]int // key -> first rule
	exact   map[string]int
	sub     map[string]int
	below   map[string][]int // ancestor -> rules with a key strictly under it
	keyword []struct {
		v string
		i int
	}
	cidr map[netip.Prefix]int
}

// Analyze computes RuleAnalysis for every rule of an ordered list.
func Analyze(rules []Rule) []RuleAnalysis {
	ix := keyIndex{suffix: map[string]int{}, exact: map[string]int{}, sub: map[string]int{}, below: map[string][]int{}, cidr: map[netip.Prefix]int{}}
	out := make([]RuleAnalysis, len(rules))
	for i, r := range rules {
		a := RuleAnalysis{Index: i, Entries: len(r.Entries)}
		by, part := map[int]bool{}, map[int]bool{}
		for _, e := range r.Entries {
			if e.Kind == Keyword {
				a.Keywords++
			}
			if j, ok := ix.covers(e); ok {
				a.Shadowed++
				by[j] = true
				continue
			}
			for _, j := range ix.partly(e) {
				part[j] = true
			}
		}
		for _, e := range r.Entries {
			ix.add(e, i)
		}
		a.FullyShadowed = a.Entries > 0 && a.Shadowed == a.Entries && !r.GeoIPCN
		a.ShadowedBy, a.PartlyBy = keys(by), keys(part)
		out[i] = a
	}
	return out
}

func keys(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func ancestors(d string) []string {
	var out []string
	for x := d; ; {
		out = append(out, x)
		i := strings.IndexByte(x, '.')
		if i < 0 {
			return out
		}
		x = x[i+1:]
	}
}

// covers: an earlier entry matches everything e matches.
func (ix *keyIndex) covers(e Entry) (int, bool) {
	switch e.Kind {
	case Exact, Suffix, Sub:
		for _, a := range ancestors(e.Value) {
			if j, ok := ix.suffix[a]; ok {
				return j, true
			}
		}
		for _, a := range ancestors(e.Value)[1:] {
			if j, ok := ix.sub[a]; ok {
				return j, true
			}
		}
		if e.Kind == Sub {
			if j, ok := ix.sub[e.Value]; ok {
				return j, true
			}
		}
		if e.Kind == Exact {
			if j, ok := ix.exact[e.Value]; ok {
				return j, true
			}
		}
		for _, k := range ix.keyword {
			if strings.Contains(e.Value, k.v) {
				return k.i, true
			}
		}
	case Keyword:
		for _, k := range ix.keyword {
			if strings.Contains(e.Value, k.v) {
				return k.i, true
			}
		}
	case CIDR:
		p := e.Prefix
		for b := 0; b <= p.Bits(); b++ {
			q, err := p.Addr().Prefix(b)
			if err != nil {
				continue
			}
			if j, ok := ix.cidr[q]; ok {
				return j, true
			}
		}
	}
	return 0, false
}

// partly: earlier entries that take a part of what e matches.
func (ix *keyIndex) partly(e Entry) []int {
	switch e.Kind {
	case Suffix, Sub:
		return ix.below[e.Value]
	case CIDR:
		var out []int
		for q, j := range ix.cidr {
			if q.Addr().Is4() == e.Prefix.Addr().Is4() && q.Bits() > e.Prefix.Bits() && e.Prefix.Contains(q.Addr()) {
				out = append(out, j)
			}
		}
		return out
	}
	return nil
}

func (ix *keyIndex) add(e Entry, i int) {
	switch e.Kind {
	case Exact, Suffix, Sub:
		m := ix.suffix
		if e.Kind == Exact {
			m = ix.exact
		} else if e.Kind == Sub {
			m = ix.sub
		}
		if _, ok := m[e.Value]; !ok {
			m[e.Value] = i
		}
		for _, a := range ancestors(e.Value)[1:] {
			l := ix.below[a]
			if len(l) == 0 || l[len(l)-1] != i {
				ix.below[a] = append(l, i)
			}
		}
		if e.Kind == Exact {
			// An exact key under-or-equal a later suffix takes the name
			// itself from it.
			l := ix.below[e.Value]
			if len(l) == 0 || l[len(l)-1] != i {
				ix.below[e.Value] = append(l, i)
			}
		}
	case Keyword:
		ix.keyword = append(ix.keyword, struct {
			v string
			i int
		}{e.Value, i})
	case CIDR:
		if _, ok := ix.cidr[e.Prefix]; !ok {
			ix.cidr[e.Prefix] = i
		}
	}
}
