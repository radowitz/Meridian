package ordered

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const maxStoredEntries = 1000000

// Normalized is the stored form of a parsed rule-set (one entry per line:
// "exact x", "suffix x", "sub x", "keyword x", "cidr p"), sorted, so the
// same content always has the same digest.
func MarshalEntries(es []Entry) []byte {
	lines := make([]string, 0, len(es))
	seen := map[string]bool{}
	for _, e := range es {
		v := e.Value
		if e.Kind == CIDR {
			v = e.Prefix.String()
		}
		l := string(e.Kind) + " " + v
		if !seen[l] {
			seen[l] = true
			lines = append(lines, l)
		}
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

// ParseNormalized reads the stored form back, strictly: the host treats the
// file as untrusted data.
func UnmarshalEntries(b []byte) ([]Entry, error) {
	var out []Entry
	for i, l := range strings.Split(string(b), "\n") {
		if l == "" {
			continue
		}
		k, v, ok := strings.Cut(l, " ")
		if !ok {
			return nil, fmt.Errorf("line %d: malformed", i+1)
		}
		switch Kind(k) {
		case Exact, Suffix, Sub:
			d, ok := NormDomain(v)
			if !ok || d != v {
				return nil, fmt.Errorf("line %d: bad domain", i+1)
			}
			out = append(out, Entry{Kind: Kind(k), Value: d})
		case Keyword:
			kw, ok := NormKeyword(v)
			if !ok {
				return nil, fmt.Errorf("line %d: bad keyword", i+1)
			}
			out = append(out, Entry{Kind: Keyword, Value: kw})
		case CIDR:
			pr, err := netip.ParsePrefix(v)
			if err != nil || pr != pr.Masked() {
				return nil, fmt.Errorf("line %d: bad cidr", i+1)
			}
			out = append(out, Entry{Kind: CIDR, Prefix: pr})
		default:
			return nil, fmt.Errorf("line %d: unknown kind", i+1)
		}
		if len(out) > maxStoredEntries {
			return nil, errors.New("too many entries")
		}
	}
	return out, nil
}
