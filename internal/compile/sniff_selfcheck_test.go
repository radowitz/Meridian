package compile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/sniff"
)

var confineDNS = regexp.MustCompile(`(?m)^\s*ip6? daddr (\S+) meta mark (0x[0-9a-f]+) meta l4proto \{ tcp, udp \} th dport 53 accept`)

// The self-check asks every resolver of every target exactly as the
// forwarder's real resolution of that target does (the same server, the
// same query mark, through the same exchange: sniff.Resolver.exchange), and
// only what the output chain allows: for every target kind the six sniff
// topologies compile (direct, switchable and static region groups, pinned
// exits with their own resolver, IPv4-only targets, nested and TCP-only
// external exits, reject), the (server, mark) pairs of a real Lookup and of
// the self-check are the same, and each is a resolver accept of
// sniff_confine. A target without a resolver is "unchecked", never failed;
// reject targets are not checked. The table of what each kind gets is
// logged.
func TestSniffSelfCheckSamePathAsLookup(t *testing.T) {
	topos := sniffTopologies(t)
	// Pinned nested and external exits as targets of their own (in the
	// shared set they appear behind their region groups only).
	pin := func(topo model.Topology, exit string) model.Topology {
		topo.Rules = append(topo.Rules, model.Rule{ID: "sn-pin-" + exit, Name: "pin " + exit, Enabled: true, MatchType: model.MatchSuffix,
			MatchValue: exit + ".pin.example.net", TargetExit: exit, Priority: 7})
		return topo
	}
	topos["nested_pinned"] = pin(topos["nested"], "twnat")
	topos["external_pinned"] = pin(topos["external"], "myext")
	for name, topo := range topos {
		t.Run(name, func(t *testing.T) {
			_, f := sniffCompile(t, topo)
			var tf sniff.TargetsFile
			dec := json.NewDecoder(strings.NewReader(f.targets))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&tf); err != nil {
				t.Fatal(err)
			}
			c, err := ordered.LoadSnapshot([]byte(f.decide), ordered.MemReader{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			allowed := map[string]bool{}
			for _, m := range confineDNS.FindAllStringSubmatch(sniffConfine(t, f.nft), -1) {
				var v uint32
				fmt.Sscanf(m[2], "0x%x", &v)
				allowed[fmt.Sprintf("%s|%#x", m[1], v)] = true
			}
			var mu sync.Mutex
			asked := map[string]bool{}
			// While real lookups run every resolver fails, so a lookup walks
			// all of a target's resolvers in order (it moves to the next one
			// only after a failure), the whole set the self-check asks.
			failAll := true
			s := sniff.New(sniff.Config{})
			defer s.Close()
			s.Resolver.Exchange = func(_ context.Context, server string, mark uint32, q []byte) ([]byte, error) {
				ap := netip.MustParseAddrPort(server)
				mu.Lock()
				asked[fmt.Sprintf("%s|%#x", ap.Addr(), mark)] = true
				fail := failAll
				mu.Unlock()
				if fail {
					return nil, fmt.Errorf("test: unanswered")
				}
				r := append([]byte(nil), q...)
				r[2] |= 0x80
				return r, nil
			}
			s.Dial = func(context.Context, string, string, uint32) (net.Conn, error) {
				a, b := net.Pipe()
				b.Close()
				return a, nil
			}
			if err := s.Install(c, tf.Targets); err != nil {
				t.Fatal(err)
			}
			byName := map[string]sniff.Target{}
			lookups := map[string]map[string]bool{}
			for _, tg := range tf.Targets {
				byName[tg.Name] = tg
				if tg.Reject || len(tg.Resolvers) == 0 {
					continue
				}
				mu.Lock()
				asked = map[string]bool{}
				mu.Unlock()
				_, _ = s.Resolver.Lookup(context.Background(), tg, "selfcheck-path-"+strings.NewReplacer(":", "-").Replace(tg.Name)+".example.net", false)
				mu.Lock()
				lookups[tg.Name] = asked
				mu.Unlock()
			}
			mu.Lock()
			asked, failAll = map[string]bool{}, false
			mu.Unlock()
			res, err := s.RunSelfCheck(context.Background(), sniff.TriggerRequest)
			if err != nil {
				t.Fatal(err)
			}
			union := map[string]bool{}
			var rows []string
			for _, x := range res.Targets {
				tg := byName[x.Target]
				kind := targetKind(tg, x.Default)
				if len(tg.Resolvers) == 0 {
					if x.Status != sniff.TargetUnchecked {
						t.Fatalf("%s (%s) has no resolver but is %s", x.Target, kind, x.Status)
					}
					rows = append(rows, fmt.Sprintf("%-26s %-34s no resolver -> unchecked (%s)", x.Target, kind, x.Reason))
					continue
				}
				if x.Status != sniff.TargetOK {
					t.Fatalf("%s: %s %s", x.Target, x.Status, x.Reason)
				}
				for k := range lookups[x.Target] {
					union[k] = true
					if !allowed[k] {
						t.Fatalf("%s: real resolution asks %s, which sniff_confine does not allow", x.Target, k)
					}
				}
				var ks []string
				for k := range lookups[x.Target] {
					ks = append(ks, k)
				}
				sort.Strings(ks)
				rows = append(rows, fmt.Sprintf("%-26s %-34s resolvers %s (ipv6 %v) -> %s", x.Target, kind, strings.Join(ks, " "), tg.IPv6, x.Status))
			}
			for _, x := range tf.Targets {
				if x.Reject {
					rows = append(rows, fmt.Sprintf("%-26s %-34s not checked (no resolver, refused by design)", x.Name, "reject"))
				}
			}
			mu.Lock()
			got := asked
			mu.Unlock()
			if fmt.Sprint(sortedSet(got)) != fmt.Sprint(sortedSet(union)) {
				t.Fatalf("the self-check asked %v, real resolution %v", sortedSet(got), sortedSet(union))
			}
			if !res.OK {
				t.Fatalf("%+v", res)
			}
			sort.Strings(rows)
			t.Logf("self-check per target (%s):\n%s", name, strings.Join(rows, "\n"))
		})
	}
}

func targetKind(t sniff.Target, def bool) string {
	k := "?"
	switch {
	case t.Reject:
		k = "reject"
	case t.Name == "direct":
		k = "direct (domestic resolvers)"
	case strings.HasPrefix(t.Name, "group:"):
		k = "region group (group resolver)"
	case strings.HasPrefix(t.Name, "exit:"):
		k = "exit (its own resolver)"
	}
	if def {
		k += ", default"
	}
	return k
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
