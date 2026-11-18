package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// trafficBlock returns the counter declarations plus chain traffic of a
// gateway's meridian.nft, or "" when absent.
func trafficBlock(body string) string {
	start := strings.Index(body, "  counter traffic_up_domestic {\n")
	if start < 0 {
		return ""
	}
	chain := strings.Index(body[start:], "  chain traffic {\n")
	if chain < 0 {
		return ""
	}
	end := strings.Index(body[start+chain:], "  }\n\n")
	if end < 0 {
		return ""
	}
	return body[start : start+chain+end+len("  }\n\n")]
}

// withoutTrafficCounters drops the traffic counter block from every
// gateway's meridian.nft, failing unless it is there exactly once. Pins of
// earlier compilers stay valid: the counters are purely additive.
func withoutTrafficCounters(t *testing.T, topo model.Topology, b *Bundle) *Bundle {
	t.Helper()
	out := *b
	out.Files = make(map[string]string, len(b.Files))
	for p, body := range b.Files {
		out.Files[p] = body
	}
	for _, n := range topo.Nodes {
		if n.Role != model.RoleGateway {
			continue
		}
		p := "nodes/" + n.ID + "/etc/nftables.d/meridian.nft"
		blk := trafficBlock(out.Files[p])
		if blk == "" || strings.Count(out.Files[p], blk) != 1 {
			t.Fatalf("%s: traffic counter block missing or repeated", p)
		}
		out.Files[p] = strings.Replace(out.Files[p], blk, "", 1)
	}
	return &out
}

func gatewayNFT(t *testing.T, topo model.Topology, b *Bundle) string {
	t.Helper()
	for _, n := range topo.Nodes {
		if n.Role == model.RoleGateway {
			return b.Files["nodes/"+n.ID+"/etc/nftables.d/meridian.nft"]
		}
	}
	t.Fatal("no gateway")
	return ""
}

func TestTrafficCountersPresentAllVariants(t *testing.T) {
	cases := map[string]func(t *testing.T) model.Topology{
		"single":        func(*testing.T) model.Topology { return defaults.Example() },
		"dual_hub":      func(*testing.T) model.Topology { return defaults.DualHubExample() },
		"shared_relays": func(*testing.T) model.Topology { return defaults.SharedRelaysExample() },
		"remote_access": func(t *testing.T) model.Topology { topo, _ := raExample(t); return topo },
	}
	for name, mk := range cases {
		topo := mk(t)
		model.MigrateRegionGroups(&topo)
		b, err := Compile(topo)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body := gatewayNFT(t, topo, b)
		blk := trafficBlock(body)
		if blk == "" {
			t.Fatalf("%s: no traffic counters", name)
		}
		for _, c := range TrafficCounterNames {
			if !strings.Contains(blk, "  counter "+c+" {\n") || !strings.Contains(blk, "counter name \""+c+"\"\n") {
				t.Errorf("%s: counter %s not declared and used", name, c)
			}
		}
		// Count only: no verdict, no mark or ct mark change.
		for _, bad := range []string{" set ", "accept", "drop", "reject", "return", "jump", "goto"} {
			if strings.Contains(strings.Replace(blk, "policy accept;", "", 1), bad) {
				t.Errorf("%s: traffic chain contains %q", name, bad)
			}
		}
		if !strings.Contains(blk, "hook forward priority filter + 10;") {
			t.Errorf("%s: traffic chain not on forward after guard and quic", name)
		}
		ra := planRemote(topo) != nil
		if ra != strings.Contains(blk, "\""+model.RemoteAccessIface+"\"") {
			t.Errorf("%s: remote access %v but mra ingress in counters %v", name, ra, !ra)
		}
		if name == "remote_access" && !ra {
			t.Errorf("remote_access example has remote access off")
		}
		if !strings.Contains(blk, "ct direction reply iifname {") {
			t.Errorf("%s: no foreign download counter", name)
		}
	}
}

// With sniff on, the forwarder's Internet leg is counted in output/input,
// by its uid and mark; with sniff off, nothing of that is rendered.
func TestTrafficCountersSniff(t *testing.T) {
	for _, on := range []bool{false, true} {
		for name, mk := range map[string]func() model.Topology{
			"single":        defaults.Example,
			"dual_hub":      defaults.DualHubExample,
			"shared_relays": defaults.SharedRelaysExample,
		} {
			topo := mk()
			model.MigrateRegionGroups(&topo)
			if on {
				topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
			} else {
				topo.Settings.Sniff = nil
			}
			b, err := Compile(topo)
			if err != nil {
				t.Fatalf("%s/%v: %v", name, on, err)
			}
			body := gatewayNFT(t, topo, b)
			blk := trafficBlock(body)
			if blk == "" || strings.Count(body, blk) != 1 {
				t.Fatalf("%s/%v: traffic block missing or repeated", name, on)
			}
			has := strings.Contains(body, "skuid 65530") && strings.Contains(body, "chain sniff_out {")
			if has != on {
				t.Fatalf("%s/%v: sniff rendered %v", name, on, has)
			}
			for _, c := range []string{"chain traffic_sniff_out {", "chain traffic_sniff_in {"} {
				if strings.Contains(blk, c) != on || strings.Count(body, c) != map[bool]int{false: 0, true: 1}[on] {
					t.Errorf("%s/%v: %s presence wrong", name, on, c)
				}
			}
			for _, bad := range []string{" set ", "accept", "drop", "reject", "return", "jump", "goto"} {
				if strings.Contains(strings.ReplaceAll(blk, "policy accept;", ""), bad) {
					t.Errorf("%s/%v: traffic chains contain %q", name, on, bad)
				}
			}
			if !on {
				continue
			}
			out := blk[strings.Index(blk, "chain traffic_sniff_out {"):strings.Index(blk, "chain traffic_sniff_in {")]
			in := blk[strings.Index(blk, "chain traffic_sniff_in {"):]
			if !strings.Contains(out, "hook output priority filter + 20;") || !strings.Contains(in, "hook input priority filter + 10;") {
				t.Errorf("%s: hooks wrong:\n%s", name, blk)
			}
			for _, sec := range []struct{ s, dir, want string }{
				{out, "ct direction original", "traffic_up_"}, {in, "ct direction reply", "traffic_down_"},
			} {
				lines := 0
				for _, l := range strings.Split(sec.s, "\n") {
					if !strings.Contains(l, "counter name") {
						continue
					}
					lines++
					// Only the forwarder's TCP, no DNS, one leg (Internet side):
					// original direction out, reply direction in.
					for _, w := range []string{"meta skuid 65530", "meta l4proto tcp", "!= 53", sec.dir, sec.want} {
						if !strings.Contains(l, w) {
							t.Errorf("%s: %q lacks %q", name, l, w)
						}
					}
				}
				if lines != 2 {
					t.Errorf("%s: want domestic+foreign counters, got %d:\n%s", name, lines, sec.s)
				}
			}
			if !strings.Contains(out, "meta mark & 0xff00ffff == 0x64") && !strings.Contains(out, "== 0x64 oifname") {
				t.Errorf("%s: domestic upload not by mark 0x64:\n%s", name, out)
			}
		}
	}
}
