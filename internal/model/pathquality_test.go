package model

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The panel shows the defaults as placeholders (web/src/types.ts
// PATH_QUALITY_DEFAULTS); they must be the ones the compiler fills in.
func TestPathQualityDefaultsMatchThePanel(t *testing.T) {
	src, err := os.ReadFile("../../web/src/types.ts")
	if err != nil {
		t.Skip("web sources not present")
	}
	s := string(src)
	i := strings.Index(s, "export const PATH_QUALITY_DEFAULTS")
	if i < 0 {
		t.Fatal("PATH_QUALITY_DEFAULTS not found")
	}
	block := s[i : i+strings.Index(s[i:], "};")]
	web := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z_]+): (\d+),`).FindAllStringSubmatch(block, -1) {
		v, _ := strconv.Atoi(m[2])
		web[m[1]] = v
	}
	b, _ := json.Marshal(PathQualityDefaults())
	var goSide map[string]any
	_ = json.Unmarshal(b, &goSide)
	for k, v := range goSide {
		f, ok := v.(float64)
		if !ok {
			continue
		}
		if web[k] != int(f) {
			t.Errorf("%s: panel %d, Go %d", k, web[k], int(f))
		}
	}
	if len(web) != len(goSide) {
		t.Errorf("panel has %d defaults, Go %d", len(web), len(goSide))
	}
}

func TestPathQualityEffectiveAndSharingRelays(t *testing.T) {
	var p *PathQuality
	if e := p.Effective(); e.EvictAfterSec != 30 || e.ProbeBytes != 512*1024 || e.Overrides != nil {
		t.Fatal("nil is the defaults")
	}
	e := (&PathQuality{EvictAfterSec: 90, ProbeOff: true, Overrides: []RelayOverride{{Relay: "a", Weight: 10}}}).Effective()
	if e.EvictAfterSec != 90 || !e.ProbeOff || e.DownAfterSec != 15 || len(e.Overrides) != 1 {
		t.Fatalf("%+v", e)
	}
	topo := Topology{
		Nodes: []Node{{ID: "gw", Role: RoleGateway}, {ID: "r2", Role: RoleRelay}, {ID: "r1", Role: RoleRelay}, {ID: "r3", Role: RoleRelay}},
		Links: []Link{
			{ID: "a", From: "gw", To: "r2", Transport: TransportDirectWG, Enabled: true},
			{ID: "b", From: "r1", To: "gw", Transport: TransportUDPWSSFailover, Enabled: true},
			{ID: "c", From: "gw", To: "r3", Transport: TransportDirectWG, Enabled: true, Standby: true},
		},
	}
	rs := topo.SharingRelays()
	if len(rs) != 2 || rs[0].ID != "r1" || rs[1].ID != "r2" || !topo.RelaySharing() {
		t.Fatalf("%+v", rs)
	}
}
