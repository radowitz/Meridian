package ordered

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// The manifest is the ordered list of domain sources the gateway compile
// writes (/etc/meridian/rules/order.conf) and the host turns into SmartDNS
// domain-set files with Derive: at install (meridian-up.sh runs
// "meridian lists-derive") and after every list or rule-set update. It is
// data only: set names, domains, category and file stems, rule-set IDs.
//
//	# meridian ordered domain sources v1
//	set r0
//	exact api.example.com
//	suffix example.com
//	geosite openai        # /var/lib/meridian/geosite/openai.txt
//	keyword kw_r3         # /var/lib/meridian/keywords/kw_r3.txt
//	ruleset rs-ads        # /var/lib/meridian/geosite/rulesets/rs-ads.txt
//	cidr4 r0c             # IPv4 entries of this set's rule-sets: nft set r0c
//	cidr6 r0c6
//	set r1
//	ruleset rs-video
//	exclude-suffix ads.example.com   # exclusions of the rule-set above
//	exclude-cidr 198.51.100.0/26
//	set gs_cn
//	geosite cn
//
// Sets appear in list order; the last one is the built-in domestic list.
// "exclude-<kind> <value>" lines (kind exact, suffix, sub, keyword, cidr)
// follow a ruleset line and are that rule-set's exclusions
// (model.RuleSet.Exclude): Derive applies them with ApplyExclusions. A
// manifest without exclusions is the same text as before they existed.
const ManifestHeader = "# meridian ordered domain sources v1"

// ExcludePrefix starts a manifest exclusion line.
const ExcludePrefix = "exclude-"

// SourceKind is the kind of one manifest source line.
type SourceKind string

const (
	SrcExact   SourceKind = "exact"
	SrcSuffix  SourceKind = "suffix"
	SrcGeosite SourceKind = "geosite"
	SrcKeyword SourceKind = "keyword"
	SrcRuleSet SourceKind = "ruleset"
)

// Source is one manifest line inside a set.
type Source struct {
	Kind  SourceKind
	Value string
	// Exclude are the exclusions of a ruleset source (ApplyExclusions).
	Exclude []Entry
}

// ManifestSet is one rule (or the domestic list) in list order.
type ManifestSet struct {
	Name  string
	Srcs  []Source
	CIDR4 string
	CIDR6 string
}

// Manifest is the whole ordered source list.
type Manifest struct {
	Sets []ManifestSet
}

var (
	setNameRe = regexp.MustCompile(`^[a-z0-9_]{1,48}$`)
	stemRe    = regexp.MustCompile(`^[a-z0-9_]{1,80}$`)
	rsIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// RuleSetIDOK reports whether id may name a rule-set file.
func RuleSetIDOK(id string) bool { return rsIDRe.MatchString(id) }

// Render writes the manifest text.
func (m Manifest) Render() string {
	var sb strings.Builder
	sb.WriteString(ManifestHeader + "\n")
	for _, s := range m.Sets {
		fmt.Fprintf(&sb, "set %s\n", s.Name)
		for _, src := range s.Sources() {
			fmt.Fprintf(&sb, "%s %s\n", src.Kind, src.Value)
			for _, x := range src.Exclude {
				fmt.Fprintf(&sb, "%s%s %s\n", ExcludePrefix, x.Kind, entryValue(x))
			}
		}
		if s.CIDR4 != "" {
			fmt.Fprintf(&sb, "cidr4 %s\n", s.CIDR4)
		}
		if s.CIDR6 != "" {
			fmt.Fprintf(&sb, "cidr6 %s\n", s.CIDR6)
		}
	}
	return sb.String()
}

// Sources returns the set's sources.
func (s ManifestSet) Sources() []Source { return s.Srcs }

// Add appends a source.
func (s *ManifestSet) Add(k SourceKind, v string) { s.Srcs = append(s.Srcs, Source{Kind: k, Value: v}) }

// AddRuleSet appends a ruleset source with its exclusions.
func (s *ManifestSet) AddRuleSet(id string, exclude []Entry) {
	s.Srcs = append(s.Srcs, Source{Kind: SrcRuleSet, Value: id, Exclude: exclude})
}

func entryValue(e Entry) string {
	if e.Kind == CIDR {
		return e.Prefix.String()
	}
	return e.Value
}

// ParseEntry reads one entry in its stored form (kind and value, as
// MarshalEntries writes them), strictly.
func ParseEntry(kind, v string) (Entry, error) {
	switch Kind(kind) {
	case Exact, Suffix, Sub:
		d, ok := NormDomain(v)
		if !ok || d != v {
			return Entry{}, errors.New("bad domain")
		}
		return Entry{Kind: Kind(kind), Value: d}, nil
	case Keyword:
		k, ok := NormKeyword(v)
		if !ok || k != v {
			return Entry{}, errors.New("bad keyword")
		}
		return Entry{Kind: Keyword, Value: k}, nil
	case CIDR:
		pr, err := netip.ParsePrefix(v)
		if err != nil || pr != pr.Masked() || pr.Addr().Is4In6() || pr.Addr().Zone() != "" {
			return Entry{}, errors.New("bad cidr")
		}
		return Entry{Kind: CIDR, Prefix: pr}, nil
	}
	return Entry{}, errors.New("unknown kind")
}

// ParseManifest parses and checks a manifest completely; anything unknown is
// an error (the host never guesses).
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	names := map[string]bool{}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != ManifestHeader {
		return m, errors.New("manifest: missing header")
	}
	for i, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 2 {
			return m, fmt.Errorf("manifest line %d: want two fields", i+2)
		}
		k, v := f[0], f[1]
		if strings.HasPrefix(k, ExcludePrefix) {
			if len(m.Sets) == 0 {
				return m, fmt.Errorf("manifest line %d: exclusion before any set", i+2)
			}
			s := &m.Sets[len(m.Sets)-1]
			if len(s.Srcs) == 0 || s.Srcs[len(s.Srcs)-1].Kind != SrcRuleSet {
				return m, fmt.Errorf("manifest line %d: exclusion not after a ruleset line", i+2)
			}
			e, err := ParseEntry(strings.TrimPrefix(k, ExcludePrefix), v)
			if err != nil {
				return m, fmt.Errorf("manifest line %d: %v", i+2, err)
			}
			src := &s.Srcs[len(s.Srcs)-1]
			if len(src.Exclude) >= MaxExclusions {
				return m, fmt.Errorf("manifest line %d: too many exclusions", i+2)
			}
			src.Exclude = append(src.Exclude, e)
			continue
		}
		if k == "set" {
			if !setNameRe.MatchString(v) || names[v] {
				return m, fmt.Errorf("manifest line %d: bad or repeated set %q", i+2, v)
			}
			names[v] = true
			m.Sets = append(m.Sets, ManifestSet{Name: v})
			continue
		}
		if len(m.Sets) == 0 {
			return m, fmt.Errorf("manifest line %d: source before any set", i+2)
		}
		s := &m.Sets[len(m.Sets)-1]
		switch SourceKind(k) {
		case SrcExact, SrcSuffix:
			if _, ok := NormDomain(v); !ok {
				return m, fmt.Errorf("manifest line %d: bad domain", i+2)
			}
		case SrcGeosite, SrcKeyword:
			if !stemRe.MatchString(v) {
				return m, fmt.Errorf("manifest line %d: bad file stem", i+2)
			}
		case SrcRuleSet:
			if !rsIDRe.MatchString(v) {
				return m, fmt.Errorf("manifest line %d: bad rule-set id", i+2)
			}
		default:
			switch k {
			case "cidr4", "cidr6":
				if !setNameRe.MatchString(v) {
					return m, fmt.Errorf("manifest line %d: bad nft set", i+2)
				}
				if k == "cidr4" {
					s.CIDR4 = v
				} else {
					s.CIDR6 = v
				}
				continue
			}
			return m, fmt.Errorf("manifest line %d: unknown kind %q", i+2, k)
		}
		s.Add(SourceKind(k), v)
	}
	return m, nil
}

// Reader returns the current content of a dynamic source. A source that
// does not exist yet returns an error wrapping fs.ErrNotExist and counts as
// empty (SmartDNS starts with an empty file, as before).
type Reader interface {
	// Geosite and Keyword return the published file's names (suffix keys).
	Geosite(stem string) ([]string, error)
	Keyword(stem string) ([]string, error)
	// RuleSet returns the active normalized content of a rule-set.
	RuleSet(id string) ([]Entry, error)
}

// SetStats describes one derived set.
type SetStats struct {
	// Kept keys written to the set's file; Shadowed keys dropped because an
	// earlier rule already covers every name under them; Keyword entries of
	// rule-sets, which SmartDNS cannot match (not executed).
	Kept     int      `json:"kept"`
	Shadowed int      `json:"shadowed"`
	CIDR     int      `json:"cidr"`
	Keywords int      `json:"keywords,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	// ShadowedBy counts dropped keys per earlier set.
	ShadowedBy map[string]int `json:"shadowed_by,omitempty"`
}

// Derived is the host's output: one SmartDNS domain-set file per set and
// the CIDR elements of rule-set sets.
type Derived struct {
	Order []string
	Files map[string][]string
	CIDR  map[string][]netip.Prefix
	Stats map[string]*SetStats
}

// Derive filters the ordered sources so that SmartDNS's longest-key choice
// equals first match in list order, and returns the domain-set lines.
//
// Every key k covers two parts: the name k itself ("root") and the names
// strictly below k ("sub"); a suffix key covers both, an exact key the
// root, a sub key the names below. Keys are processed set by set in list
// order. A key is dropped when an earlier set owns the sub part of a
// strict ancestor of k (every name it could match is decided earlier);
// otherwise only the parts of k no earlier set owns are kept, and written
// as "k" (both), "-.k" (root only) or "*.k" (sub only), so no two sets ever
// write the same SmartDNS key. Argument: for a name n let j be the first set
// that matches n, through the kept part of key a. Any kept key b of a later
// set that also matches n is n or an ancestor of n, as is a. If b is a
// strict ancestor of a, SmartDNS's longest key prefers a. If b is under a
// strictly, a's sub part covers b and b was dropped. If b == a, the part of
// b that matches n is the same part a owns, so it was not kept. Hence
// SmartDNS (longest applicable key, DNSModel) applies a, set j.
func Derive(m Manifest, r Reader) (Derived, error) {
	d := Derived{Files: map[string][]string{}, CIDR: map[string][]netip.Prefix{}, Stats: map[string]*SetStats{}}
	// Ownership per name: who owns the name itself (root) and who owns
	// every name strictly below it (sub). A suffix key owns both, an exact
	// key the root, a sub key the names below.
	rootOwner := map[string]string{}
	subOwner := map[string]string{}
	coveredAbove := func(name string) (string, bool) {
		for x := name; ; {
			i := strings.IndexByte(x, '.')
			if i < 0 {
				return "", false
			}
			x = x[i+1:]
			if s, ok := subOwner[x]; ok {
				return s, true
			}
		}
	}
	for _, set := range m.Sets {
		st := &SetStats{}
		d.Stats[set.Name] = st
		d.Order = append(d.Order, set.Name)
		var keys []Entry
		var v4, v6 []netip.Prefix
		for _, src := range set.Sources() {
			switch src.Kind {
			case SrcExact:
				keys = append(keys, Entry{Kind: Exact, Value: src.Value})
			case SrcSuffix:
				keys = append(keys, Entry{Kind: Suffix, Value: src.Value})
			case SrcGeosite, SrcKeyword:
				get := r.Geosite
				if src.Kind == SrcKeyword {
					get = r.Keyword
				}
				names, err := get(src.Value)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						st.Missing = append(st.Missing, string(src.Kind)+":"+src.Value)
						continue
					}
					return d, fmt.Errorf("%s %s: %w", src.Kind, src.Value, err)
				}
				for _, n := range names {
					keys = append(keys, Entry{Kind: Suffix, Value: n})
				}
			case SrcRuleSet:
				es, err := r.RuleSet(src.Value)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						st.Missing = append(st.Missing, "ruleset:"+src.Value)
						continue
					}
					return d, fmt.Errorf("ruleset %s: %w", src.Value, err)
				}
				for _, e := range ApplyExclusions(es, src.Exclude).Entries {
					switch e.Kind {
					case Exact, Suffix, Sub:
						keys = append(keys, e)
					case Keyword:
						st.Keywords++
					case CIDR:
						if e.Prefix.Addr().Is4() {
							v4 = append(v4, e.Prefix)
						} else {
							v6 = append(v6, e.Prefix)
						}
					}
				}
			}
		}
		// Within one set the order of keys does not matter (one target);
		// suffixes first keeps the files small.
		sort.SliceStable(keys, func(i, j int) bool { return keys[i].Kind == Suffix && keys[j].Kind != Suffix })
		var lines []string
		drop := func(by string) {
			if by == set.Name {
				return
			}
			st.Shadowed++
			if st.ShadowedBy == nil {
				st.ShadowedBy = map[string]int{}
			}
			st.ShadowedBy[by]++
		}
		for _, e := range keys {
			k, ok := NormDomain(e.Value)
			if !ok {
				continue
			}
			if by, hit := coveredAbove(k); hit {
				drop(by)
				continue
			}
			wantRoot := e.Kind == Suffix || e.Kind == Exact
			wantSub := e.Kind == Suffix || e.Kind == Sub
			by := ""
			if o, ok := rootOwner[k]; ok && wantRoot {
				wantRoot, by = false, o
			}
			if o, ok := subOwner[k]; ok && wantSub {
				wantSub, by = false, o
			}
			switch {
			case wantRoot && wantSub:
				lines = append(lines, k)
			case wantRoot:
				lines = append(lines, "-."+k)
			case wantSub:
				lines = append(lines, "*."+k)
			default:
				drop(by)
				continue
			}
			if wantRoot {
				rootOwner[k] = set.Name
			}
			if wantSub {
				subOwner[k] = set.Name
			}
		}
		sort.Strings(lines)
		st.Kept = len(lines)
		d.Files[set.Name] = lines
		if set.CIDR4 != "" {
			d.CIDR[set.CIDR4] = MergePrefixes(v4)
			st.CIDR += len(d.CIDR[set.CIDR4])
		}
		if set.CIDR6 != "" {
			d.CIDR[set.CIDR6] = MergePrefixes(v6)
			st.CIDR += len(d.CIDR[set.CIDR6])
		}
	}
	return d, nil
}

// MergePrefixes masks, sorts and removes prefixes contained in another one,
// and joins adjacent siblings, so an nft interval set accepts them (nft
// refuses overlapping intervals in one transaction).
func MergePrefixes(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	in := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.IsValid() {
			in = append(in, p.Masked())
		}
	}
	sort.Slice(in, func(i, j int) bool {
		if c := in[i].Addr().Compare(in[j].Addr()); c != 0 {
			return c < 0
		}
		return in[i].Bits() < in[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range in {
		if n := len(out); n > 0 && out[n-1].Contains(p.Addr()) && out[n-1].Bits() <= p.Bits() {
			continue
		}
		out = append(out, p)
		// Join siblings bottom-up.
		for len(out) >= 2 {
			a, b := out[len(out)-2], out[len(out)-1]
			if a.Bits() != b.Bits() || a.Bits() == 0 {
				break
			}
			parent, err := a.Addr().Prefix(a.Bits() - 1)
			if err != nil || parent.Addr() != a.Addr() || !parent.Contains(b.Addr()) {
				break
			}
			out = append(out[:len(out)-2], parent)
		}
	}
	return out
}
