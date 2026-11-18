//go:build linux

package compile

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/ordered"
)

// TestOrderedRealSmartDNS checks ordered.DNSModel (the matcher the
// first-match proofs rely on) against the pinned SmartDNS binary: generated
// ordered rule lists are derived (ordered.Plan + ordered.Derive, the host's
// derive step), loaded into SmartDNS as domain-set files exactly as the
// gateway config does, each set answering with its own address
// (-address 198.18.x.y; the rule choice is the same walk for every rule
// type), and every probe name is queried. The answer must be the set
// DNSModel predicts, which by TestDifferentialGenerated is the rule the
// reference interpreter picks. A second part loads a large rule-set
// (100 000 names) plus a 60 000-name domestic list and measures startup.
//
// Opt-in, like TestSmartDNSRealBinary:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/compile.test ./internal/compile
//	docker run --rm --network none --platform linux/amd64 -v /tmp/compile.test:/compile.test:ro \
//	  -e MERIDIAN_SMARTDNS_BIN=/usr/share/meridian/artifacts/smartdns-x86_64 \
//	  --entrypoint /compile.test meridian:local -test.run 'TestOrderedRealSmartDNS' -test.v
func TestOrderedRealSmartDNS(t *testing.T) {
	bin := os.Getenv("MERIDIAN_SMARTDNS_BIN")
	if bin == "" {
		t.Skip("MERIDIAN_SMARTDNS_BIN not set")
	}
	labels := []string{"a", "b"}
	var uni []string
	// Single-label names are left out: SmartDNS does not answer them from
	// rules (no answer at all for "example"), and no rule list uses them.
	for _, tld := range []string{"r.example", "r.test"} {
		uni = append(uni, tld)
		for _, l1 := range labels {
			uni = append(uni, l1+"."+tld)
			for _, l2 := range labels {
				uni = append(uni, l2+"."+l1+"."+tld, "c."+l2+"."+l1+"."+tld)
			}
		}
	}
	rng := rand.New(rand.NewSource(11))
	lists, probes := 0, 0
	for iter := 0; iter < 25; iter++ {
		var rules []ordered.Rule
		for i, n := 0, 2+rng.Intn(6); i < n; i++ {
			r := ordered.Rule{Target: fmt.Sprint(i)}
			for k := 1 + rng.Intn(4); k > 0; k-- {
				v := uni[rng.Intn(len(uni))]
				kind := []ordered.Kind{ordered.Exact, ordered.Suffix, ordered.Sub}[rng.Intn(3)]
				r.Entries = append(r.Entries, ordered.Entry{Kind: kind, Value: v})
			}
			rules = append(rules, r)
		}
		tail := ordered.Tail{Domestic: []string{uni[rng.Intn(len(uni))]}, DirectTarget: "D", Default: "M"}
		m, _, rd := ordered.Plan(rules, tail)
		d, err := ordered.Derive(m, rd)
		if err != nil {
			t.Fatal(err)
		}
		model := ordered.NewDNSModel()
		for _, set := range d.Order {
			for _, l := range d.Files[set] {
				if err := model.Add(l, set); err != nil {
					t.Fatal(err)
				}
			}
		}
		dir := t.TempDir()
		answer := map[string]string{"": "192.0.2.254"}
		port := freeUDPPort(t)
		conf := []string{fmt.Sprintf("bind 127.0.0.1:%d", port), "speed-check-mode none", "cache-size 0", "log-level warn",
			"log-file " + filepath.Join(dir, "smartdns.log"), "address /ready.example.net/203.0.113.1", "address /example/192.0.2.254", "address /test/192.0.2.254"}
		for i, set := range d.Order {
			f := filepath.Join(dir, set+".txt")
			if err := os.WriteFile(f, []byte(strings.Join(d.Files[set], "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			a := fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
			answer[set] = a
			conf = append(conf, "domain-set -name "+set+" -file "+f, fmt.Sprintf("domain-rules /domain-set:%s/ -address %s", set, a))
		}
		sd := startSmartDNS(t, bin, strings.Join(conf, "\n")+"\n")
		for _, n := range uni {
			for _, name := range []string{n, "z." + n} {
				want := answer[model.Lookup(name)]
				r, err := dnsQuery(sd.addr, name, qA, 3*time.Second)
				if err != nil || len(r.addrs) != 1 || r.addrs[0] != want {
					for i, rr := range rules {
						t.Logf("rule %d %v", i, rr.Entries)
					}
					t.Fatalf("%s: SmartDNS %v (err %v), model set %q (%s)", name, r.addrs, err, model.Lookup(name), want)
				}
				// And the model's choice is the reference's first match.
				ref := ordered.Reference(rules, tail, ordered.Query{Name: name, Addr: netip.MustParseAddr("100.64.0.1")})
				wantSet := "gs_cn"
				switch {
				case ref.Index >= 0:
					wantSet = fmt.Sprintf("r%d", ref.Index)
				case ref.Target == "M":
					wantSet = ""
				}
				if model.Lookup(name) != wantSet {
					t.Fatalf("%s: model %q, reference %q", name, model.Lookup(name), wantSet)
				}
				probes++
			}
		}
		sd.stop()
		lists++
	}
	t.Logf("%d generated lists, %d names queried: SmartDNS == DNSModel == reference", lists, probes)

	// Large sets: 100 000 rule-set names (some under a specific rule
	// before it), 60 000 domestic names.
	var big []ordered.Entry
	for i := 0; i < 100000; i++ {
		big = append(big, ordered.Entry{Kind: ordered.Suffix, Value: fmt.Sprintf("h%d.s%d.example", i, i%500)})
	}
	var cn []string
	for i := 0; i < 60000; i++ {
		cn = append(cn, fmt.Sprintf("d%d.cn%d.example", i, i%300))
	}
	cn = append(cn, "h7.s7.example")
	rules := []ordered.Rule{{Target: "A", Entries: []ordered.Entry{{Kind: ordered.Exact, Value: "h5.s5.example"}}}, {Target: "B", Entries: big}}
	m, _, rd := ordered.Plan(rules, ordered.Tail{Domestic: cn})
	d, err := ordered.Derive(m, rd)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	port := freeUDPPort(t)
	conf := []string{fmt.Sprintf("bind 127.0.0.1:%d", port), "speed-check-mode none", "log-level warn",
		"log-file " + filepath.Join(dir, "smartdns.log"), "address /ready.example.net/203.0.113.1", "address /example/192.0.2.254", "address /test/192.0.2.254"}
	ans := map[string]string{"r0": "198.18.0.1", "r1": "198.18.0.2", "gs_cn": "198.18.0.3"}
	total := 0
	for _, set := range d.Order {
		f := filepath.Join(dir, set+".txt")
		total += len(d.Files[set])
		if err := os.WriteFile(f, []byte(strings.Join(d.Files[set], "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		conf = append(conf, "domain-set -name "+set+" -file "+f, fmt.Sprintf("domain-rules /domain-set:%s/ -address %s", set, ans[set]))
	}
	start := time.Now()
	sd := startSmartDNS(t, bin, strings.Join(conf, "\n")+"\n")
	t.Logf("large sets: %d keys loaded, answering after %v", total, time.Since(start).Round(time.Millisecond))
	for name, want := range map[string]string{
		"h5.s5.example":        "198.18.0.1", // the exact rule before the set
		"x.h5.s5.example":      "198.18.0.2", // below it: the set's suffix
		"h99999.s499.example":  "198.18.0.2",
		"h7.s7.example":        "198.18.0.2", // in the domestic list too: the rule wins
		"d59999.cn299.example": "198.18.0.3",
		"other.example":        "192.0.2.254",
	} {
		r, err := dnsQuery(sd.addr, name, qA, 3*time.Second)
		if err != nil || len(r.addrs) != 1 || r.addrs[0] != want {
			t.Fatalf("%s: %v %v, want %s", name, r.addrs, err, want)
		}
	}
	sd.stop()
}
