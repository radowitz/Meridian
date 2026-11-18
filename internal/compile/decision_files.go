package compile

import (
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/lists"
)

// DecisionFiles are the gateway files an unlock decision may change: the
// rule-derived files only (the nft ruleset with the per-rule marks and
// sets, the gateway resolver configuration, the rule manifest, the rule
// snapshot and the sniffing forwarder's target file). Paths are relative
// to the node directory. A change outside this list, on another node, or
// a file appearing or disappearing is not a decision change (see
// DecisionChange); the panel's automatic install refuses it. The list is
// what TestDecisionChangeTouchesOnlyRuleFiles finds a decision change to
// touch across the example topologies; key material, WireGuard interface
// files and unit files are never in it.
var DecisionFiles = []string{
	"etc/nftables.d/meridian.nft",
	"etc/smartdns/smartdns.conf",
	strings.TrimPrefix(lists.ManifestPath, "/"),
	strings.TrimPrefix(DecidePath, "/"),
	strings.TrimPrefix(SniffTargetsPath, "/"),
}

// DecisionChange compares two compiles of the same topology that differ in
// their unlock decisions. changed lists the gateway (node) files that
// differ and are allowed; refused lists every other difference (another
// node's file, a gateway file outside DecisionFiles, a file added or
// removed), as bundle paths.
func DecisionChange(prev, next *Bundle, node string) (changed, refused []string) {
	allowed := map[string]bool{}
	for _, f := range DecisionFiles {
		allowed["nodes/"+node+"/"+f] = true
	}
	seen := map[string]bool{}
	visit := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		a, inA := prev.Files[p]
		b, inB := next.Files[p]
		if inA && inB && a == b {
			return
		}
		if inA && inB && allowed[p] {
			changed = append(changed, p)
			return
		}
		refused = append(refused, p)
	}
	for p := range prev.Files {
		visit(p)
	}
	for p := range next.Files {
		visit(p)
	}
	sort.Strings(changed)
	sort.Strings(refused)
	return changed, refused
}
