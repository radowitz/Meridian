package lists

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/ordered"
)

// Ordered domain sets (internal/ordered). The gateway compile writes the
// manifest of the rule list's domain sources in list order; Derive turns it
// and the published files (geosite categories, keyword expansions,
// rule-set contents) into one SmartDNS domain-set per rule in which every
// key belongs to the first rule that matches it. It runs at install
// (meridian-up.sh: "meridian lists-derive"), after every geosite update and
// after a rule-set activation (the agent's "rules" list kind).
const (
	// ManifestPath is written by the gateway bundle.
	ManifestPath = "/etc/meridian/rules/order.conf"
	// OrderedDir (under the lists dir) holds the derived domain-sets; it is
	// inside geosite/ because that directory is mounted into the SmartDNS
	// container (compile.SmartDNSSharedDirs).
	OrderedSubdir = "geosite/ordered"
	// RuleSetSubdir holds each rule-set's active content (the panel writes
	// it; ordered.MarshalEntries format).
	RuleSetSubdir = "geosite/rulesets"
	// RulesBatch is the nft batch of rule-set CIDR sets the last derive
	// loaded (re-loaded by meridian-up.sh through lists-derive).
	RulesBatch = "lists/rules.nft"
	// DeriveReadyMarker is printed by "meridian lists-derive"; the compiled
	// meridian-up.sh refuses an older binary that does not contain it.
	DeriveReadyMarker = "meridian-lists-derive-ready"
)

// DeriveResult is one derive run.
type DeriveResult struct {
	// Changed: some derived domain-set file now has other contents
	// (SmartDNS reads them only at start).
	Changed bool `json:"changed"`
	// Batch is the nft batch for the rule-set CIDR sets ("" none).
	Batch string                       `json:"-"`
	Stats map[string]*ordered.SetStats `json:"stats"`
}

type fileReader struct{ dir string }

func readNames(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, strings.TrimPrefix(l, "."))
	}
	return out, sc.Err()
}

func (r fileReader) Geosite(stem string) ([]string, error) {
	return readNames(filepath.Join(r.dir, "geosite", stem+".txt"))
}

func (r fileReader) Keyword(stem string) ([]string, error) {
	return readNames(filepath.Join(r.dir, "keywords", stem+".txt"))
}

func (r fileReader) RuleSet(id string) ([]ordered.Entry, error) {
	if !ordered.RuleSetIDOK(id) {
		return nil, fmt.Errorf("bad rule-set id %q", id)
	}
	b, err := os.ReadFile(filepath.Join(r.dir, RuleSetSubdir, id+".txt"))
	if err != nil {
		return nil, err
	}
	return ordered.UnmarshalEntries(b)
}

// FileReader reads dynamic sources from a lists dir (/var/lib/meridian).
func FileReader(dir string) ordered.Reader { return fileReader{dir: dir} }

// DeriveOrdered reads the manifest and the sources under dir, writes the
// derived domain-set files (each atomically; files of sets no longer in
// the manifest are removed) and the rule-set CIDR batch. A missing manifest
// (no install yet) is not an error and changes nothing.
func DeriveOrdered(dir, manifest string) (DeriveResult, error) {
	res := DeriveResult{}
	b, err := os.ReadFile(manifest)
	if errors.Is(err, fs.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	m, err := ordered.ParseManifest(b)
	if err != nil {
		return res, err
	}
	d, err := ordered.Derive(m, fileReader{dir: dir})
	if err != nil {
		return res, err
	}
	res.Stats = d.Stats
	out := filepath.Join(dir, OrderedSubdir)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return res, err
	}
	keep := map[string]bool{}
	for _, name := range d.Order {
		keep[name+".txt"] = true
		body := []byte(strings.Join(d.Files[name], "\n"))
		if len(body) > 0 {
			body = append(body, '\n')
		}
		p := filepath.Join(out, name+".txt")
		if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, body) {
			continue
		}
		if err := writeAtomic(p, body, 0o644); err != nil {
			return res, err
		}
		res.Changed = true
	}
	if ents, err := os.ReadDir(out); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") && !keep[e.Name()] {
				_ = os.Remove(filepath.Join(out, e.Name()))
				res.Changed = true
			}
		}
	}
	res.Batch = RulesBatchText(d.CIDR)
	if err := writeAtomic(filepath.Join(dir, RulesBatch), []byte(res.Batch), 0o600); err != nil {
		return res, err
	}
	return res, nil
}

// RulesBatchText flushes and refills every rule-set CIDR set in one batch.
func RulesBatchText(sets map[string][]netip.Prefix) string {
	names := make([]string, 0, len(sets))
	for n := range sets {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sb, "flush set inet meridian %s\n", n)
		ps := sets[n]
		for i := 0; i < len(ps); i += 2000 {
			j := i + 2000
			if j > len(ps) {
				j = len(ps)
			}
			parts := make([]string, 0, j-i)
			for _, p := range ps[i:j] {
				parts = append(parts, p.String())
			}
			fmt.Fprintf(&sb, "add element inet meridian %s { %s }\n", n, strings.Join(parts, ", "))
		}
	}
	return sb.String()
}

// derive is the updater's step after publishing: re-derive the ordered
// domain-sets from the (new) files and load the rule-set CIDR batch.
func (u *Updater) derive(ctx context.Context, rep *Report) ListResult {
	r := ListResult{List: "rules", Kind: KindRules}
	if _, err := os.Stat(u.Manifest); err != nil {
		r.Error = "网关还没有安装带规则顺序清单的版本（" + u.Manifest + "）：先安装"
		return r
	}
	res, err := DeriveOrdered(u.Dir, u.Manifest)
	if err != nil {
		r.Error = "规则顺序集合未生成，旧版本保留：" + err.Error()
		return r
	}
	if res.Batch != "" {
		if u.LoadNFT == nil {
			r.Error = "this updater cannot load nft sets"
			return r
		}
		tmp := filepath.Join(u.stateDir(), ".rules-batch.nft")
		if err := writeAtomic(tmp, []byte(res.Batch), 0o600); err != nil {
			r.Error = err.Error()
			return r
		}
		defer os.Remove(tmp)
		if err := u.LoadNFT(ctx, tmp); err != nil {
			r.Error = "nft 拒绝规则集地址批次，集合保留旧元素：" + err.Error()
			return r
		}
	}
	if res.Changed {
		rep.DNSChanged = true
	}
	n := 0
	for _, st := range res.Stats {
		n += st.Kept
	}
	r.Updated, r.Source, r.Count = true, "derived", n
	return r
}
