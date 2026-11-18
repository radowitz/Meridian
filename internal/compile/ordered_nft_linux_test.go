//go:build linux

package compile

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
)

// TestRuleSetNFTLoadLarge loads the compiled gateway ruleset of a topology
// with a rule-set rule, a REJECT rule and the QUIC switch into the kernel
// (nft -c, then nft -f), then the derive step's CIDR batch for a rule-set
// of 60 000 IPv4 and 20 000 IPv6 prefixes (overlapping and adjacent ones
// included; ordered.MergePrefixes must make them loadable into an interval
// set), and checks an element is there.
//
// Opt-in: root in a network namespace of its own (a privileged container):
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
//	docker run --rm --privileged --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro \
//	  -e MERIDIAN_NFT_TEST=1 --entrypoint /compile.test meridian:local -test.run TestRuleSetNFTLoadLarge -test.v
func TestRuleSetNFTLoadLarge(t *testing.T) {
	if os.Getenv("MERIDIAN_NFT_TEST") != "1" {
		t.Skip("MERIDIAN_NFT_TEST not set")
	}
	rules := []model.Rule{
		rr("ai", model.MatchSuffix, "ai.example.net", "us"),
		{ID: "quic", Name: "QUIC", Enabled: true, MatchType: model.MatchQUICReject},
		rr("big", model.MatchRuleSet, "", "hk"),
		rr("ads", model.MatchSuffix, "ads.example.net", ""),
	}
	rules[2].RuleSet = "big"
	rules[3].TargetAction = model.ActionReject
	topo := orderedTopo(rules)
	topo.RuleSets = []model.RuleSet{{ID: "big", Name: "big", URL: "https://example.org/big.list"}}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rs := filepath.Join(dir, "meridian.nft")
	if err := os.WriteFile(rs, []byte(b.File("nodes/gw/etc/nftables.d/meridian.nft")), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-c", "-f", rs}, {"-f", rs}} {
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, out)
		}
	}
	var es []ordered.Entry
	for i := 0; i < 60000; i++ {
		es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.%d/30", i>>10&0xff, i>>2&0xff, (i&3)<<6))})
	}
	es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix("10.0.0.0/24")}) // overlaps
	for i := 0; i < 20000; i++ {
		es = append(es, ordered.Entry{Kind: ordered.CIDR, Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x:%x::/64", i>>8, i&0xff))})
	}
	m, err := ordered.ParseManifest([]byte(b.File("nodes/gw/" + strings.TrimPrefix(lists.ManifestPath, "/"))))
	if err != nil {
		t.Fatal(err)
	}
	d, err := ordered.Derive(m, ordered.MemReader{RuleSets: map[string][]ordered.Entry{"big": es}})
	if err != nil {
		t.Fatal(err)
	}
	batch := filepath.Join(dir, "rules.nft")
	if err := os.WriteFile(batch, []byte(lists.RulesBatchText(d.CIDR)), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if out, err := exec.Command("nft", "-f", batch).CombinedOutput(); err != nil {
		t.Fatalf("batch: %v\n%s", err, out)
	}
	t.Logf("rule-set batch (%d v4 + %d v6 merged prefixes) loaded in %v", len(d.CIDR["r1c"]), len(d.CIDR["r1c6"]), time.Since(start).Round(time.Millisecond))
	for _, e := range []string{"10.0.0.5", "10.0.1.65"} {
		if out, err := exec.Command("nft", "get", "element", "inet", "meridian", "r1c", "{ "+e+" }").CombinedOutput(); err != nil {
			t.Fatalf("element %s missing: %v %s", e, err, out)
		}
	}
	// Loading it again (meridian-up.sh at the next boot) works: flush + add.
	if out, err := exec.Command("nft", "-f", batch).CombinedOutput(); err != nil {
		t.Fatalf("reload: %v\n%s", err, out)
	}
}
