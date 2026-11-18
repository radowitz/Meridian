package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// Regional services are never probed on exits of other regions; global
// services are probed on every exit; a scope narrows both.
func TestScopedTargetsByRegion(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	tp := mustTopo(t, s)
	exits, err := compile.ProbeExits(tp)
	if err != nil {
		t.Fatal(err)
	}
	regions := exitRegions(tp)
	all := scopedTargets(tp, exits, "")
	for id := range exits {
		for _, a := range probe.Catalog {
			if !probe.Probeable(a.Service) {
				continue
			}
			want := a.Global() || a.ProbesOn(regions[id])
			if containsStr(all[id], a.Service) != want {
				t.Fatalf("%s on %s (regions %v): got %v want %v", a.Service, id, regions[id], !want, want)
			}
		}
		if !containsStr(all[id], "auto-netflix") || !containsStr(all[id], "youtube-premium") {
			t.Fatalf("global service missing on %s: %v", id, all[id])
		}
	}
	if containsStr(all["jp"], "auto-mytvsuper") || containsStr(all["us"], "auto-kktv") || !containsStr(all["tw"], "auto-kktv") || !containsStr(all["jp"], "auto-abema") {
		t.Fatalf("regional placement: jp=%v us=%v tw=%v", all["jp"], all["us"], all["tw"])
	}
	// Bahamut speaks for TW and HK: probed on both, nowhere else.
	if !containsStr(all["hk-ix"], "auto-bahamut") || !containsStr(all["tw"], "auto-bahamut") || containsStr(all["sg"], "auto-bahamut") {
		t.Fatal("multi-region service")
	}
	hk := scopedTargets(tp, exits, "hk")
	for id, list := range hk {
		if !containsStr(regions[id], "hk") {
			t.Fatalf("hk scope reached %s", id)
		}
		for _, a := range list {
			ad, _ := probe.Lookup(a)
			if ad.Global() || !ad.InScope("hk") {
				t.Fatalf("hk scope sent %s", a)
			}
		}
	}
	glob := scopedTargets(tp, exits, probe.RegionGlobal)
	if len(glob) != len(exits) {
		t.Fatalf("global scope: %d of %d exits", len(glob), len(exits))
	}
	for _, list := range glob {
		for _, a := range list {
			if ad, _ := probe.Lookup(a); !ad.Global() {
				t.Fatalf("global scope sent regional %s", a)
			}
		}
	}

	// Through the API: a TW run only touches the TW exit with TW services.
	job := runJob(t, s, `{"scope":"tw","families":["ipv4"]}`)
	if len(job.Items) == 0 {
		t.Fatal("empty tw run")
	}
	for _, it := range job.Items {
		ad, _ := probe.Lookup(it.Service)
		if it.ExitID != "tw" || ad.Global() || !ad.InScope("tw") {
			t.Fatalf("tw run item: %s on %s", it.Service, it.ExitID)
		}
	}
	if rr := do(s, http.MethodPost, "/api/unlock/run", []byte(`{"scope":"tw","services":["auto-kktv"]}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("scope with services: %d", rr.Code)
	}
}

func item(svc, exit string, fam unlock.Family, cat probe.Category, ms int, now time.Time) probeJobItem {
	start := now.Add(-time.Duration(ms) * time.Millisecond)
	return probeJobItem{Service: svc, ExitID: exit, Family: fam, State: itemDone, Category: cat, StartedAt: &start, FinishedAt: &now}
}

// stampItems gives items the current identity digest of their exits.
func stampItems(s *Server, items ...probeJobItem) []probeJobItem {
	tp, _ := s.topology()
	idents, _ := s.noteIdentities(tp)
	return stampWith(idents, items...)
}

func stampWith(idents map[string]string, items ...probeJobItem) []probeJobItem {
	for i := range items {
		items[i].Identity = idents[items[i].ExitID]
	}
	return items
}

func docOf(items ...probeJobItem) probeResultsDoc {
	d := probeResultsDoc{Items: map[string]probeJobItem{}}
	for _, it := range items {
		d.Items[resultKey(it)] = it
	}
	return d
}

func recOf(t *testing.T, regions []matrixRegion, svc string) *matrixRec {
	t.Helper()
	r, found := findRec(regions, svc)
	if !found {
		t.Fatalf("%s not in matrix", svc)
	}
	return r
}

func TestMatrixRecommendation(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	tp := mustTopo(t, s)
	now := time.Now().UTC()
	pol := unlockPolicy(tp)
	v4 := unlock.FamilyIPv4
	idents := exitIdentities(tp, nil)
	doc := docOf(stampWith(idents,
		// OpenAI rules target "us": us-2 wins over a faster jp.
		item("youtube-premium", "jp", v4, probe.CatUnlocked, 50, now),
		item("youtube-premium", "us-2", v4, probe.CatUnlocked, 900, now),
		item("youtube-premium", "us", v4, probe.CatNotUnlocked, 10, now),
		// Netflix needs a residential group (jp is not eligible). hk-resi is
		// in use and unlocked: it stays recommended although hk-resi-2
		// answered faster (probe latency noise is no reason to move).
		item("auto-netflix", "hk-resi", v4, probe.CatUnlocked, 500, now),
		item("auto-netflix", "hk-resi-2", v4, probe.CatUnlocked, 100, now),
		item("auto-netflix", "jp", v4, probe.CatUnlocked, 10, now),
		// Inconclusive results are never recommended.
		item("auto-kktv", "tw", v4, probe.CatUnknown, 10, now),
		item("tubi", "us", v4, probe.CatNetworkOK, 10, now),
		// Stability: a failure on the other family loses to a clean exit.
		item("peacock", "us", v4, probe.CatUnlocked, 10, now),
		item("peacock", "us", unlock.FamilyIPv6, probe.CatFailed, 10, now),
		item("peacock", "us-2", v4, probe.CatUnlocked, 300, now),
	)...)
	regions := buildMatrix(tp, doc, nil, idents, now, pol)
	if regions[0].Code != probe.RegionGlobal {
		t.Fatalf("first section %s", regions[0].Code)
	}
	for _, r := range regions {
		if len(r.Exits) == 0 {
			t.Fatalf("empty region %s shown", r.Code)
		}
	}
	if r := recOf(t, regions, "youtube-premium"); r == nil || r.ExitID != "us-2" || r.Group != "us" {
		t.Fatalf("openai: %+v", r)
	}
	if r := recOf(t, regions, "auto-netflix"); r == nil || r.ExitID != "hk-resi" || r.Group != "hk-residential" || !r.Adopted {
		t.Fatalf("netflix keeps the exit in use: %+v", r)
	}
	// The exit in use no longer unlocks: the best unlocked one is recommended.
	doc2 := docOf(stampWith(idents,
		item("auto-netflix", "hk-resi", v4, probe.CatNotUnlocked, 500, now),
		item("auto-netflix", "hk-resi-2", v4, probe.CatUnlocked, 100, now),
	)...)
	if r := recOf(t, buildMatrix(tp, doc2, nil, idents, now, pol), "auto-netflix"); r == nil || r.ExitID != "hk-resi-2" || r.Adopted {
		t.Fatalf("netflix moves off a locked exit: %+v", r)
	}
	if r := recOf(t, regions, "peacock"); r == nil || r.ExitID != "us-2" {
		t.Fatalf("gemini: %+v", r)
	}
	for _, id := range []string{"auto-kktv", "tubi", "auto-abema"} {
		if r := recOf(t, regions, id); r != nil {
			t.Fatalf("%s recommended without an unlock: %+v", id, r)
		}
	}
	// Cells: states and the reason of an unverified one.
	for _, reg := range regions {
		for _, svc := range reg.Services {
			for _, c := range svc.Cells {
				if svc.ID == "auto-kktv" && c.ExitID == "tw" && (c.State != cellUnverified || c.Reason == "") {
					t.Fatalf("kktv cell: %+v", c)
				}
				if svc.ID == "tubi" && c.ExitID == "us" && c.State != cellLocal {
					t.Fatalf("perplexity cell: %+v", c)
				}
				if svc.ID == "youtube-premium" && c.ExitID == "sg" && c.State != cellUntested {
					t.Fatalf("untested cell: %+v", c)
				}
			}
			ad, _ := probe.Lookup(svc.ID)
			if reg.Code != probe.RegionGlobal && ad.Global() {
				t.Fatalf("global service %s in %s", svc.ID, reg.Code)
			}
		}
	}
	// Expired results are not evidence.
	old := now.Add(-pol.TTL - time.Hour)
	if r := recOf(t, buildMatrix(tp, docOf(stampWith(idents, item("youtube-premium", "jp", v4, probe.CatUnlocked, 10, old))...), nil, idents, now, pol), "youtube-premium"); r != nil {
		t.Fatalf("expired result recommended: %+v", r)
	}
}

func TestUnlockAdoptRetargetsExactlyTheServiceRules(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules,
			model.Rule{ID: "u-chatgpt", Name: "chatgpt", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "youtube.com", TargetGroup: "us"},
			model.Rule{ID: "u-label", Name: "imported", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "ytimg.com", TargetExit: "us", MihomoGroup: "OpenAI"},
			model.Rule{ID: "u-jp", Name: "jp-bound", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "jp.example.com", TargetGroup: "jp"},
			model.Rule{ID: "u-other", Name: "other", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "example.com", TargetGroup: "us"},
			model.Rule{ID: "u-direct", Name: "direct", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "youtu.be", TargetAction: model.ActionDirect},
		)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 50, now)))
	s.mu.Unlock()
	before := mustTopo(t, s)

	// A stale recommendation changes nothing.
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"us"}`)); rr.Code != http.StatusConflict {
		t.Fatalf("stale adopt: %d %s", rr.Code, rr.Body.String())
	}
	if canonJSON(mustTopo(t, s)) != canonJSON(before) {
		t.Fatal("stale adopt changed the topology")
	}

	// The preview names the service rules and counts the others that move
	// with the group, and changes nothing.
	pv := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp","preview":true}`))
	var prev struct {
		Preview      bool     `json:"preview"`
		ServiceRules []string `json:"service_rules"`
		OtherRules   int      `json:"other_rules"`
	}
	_ = json.Unmarshal(pv.Body.Bytes(), &prev)
	if pv.Code != http.StatusOK || !prev.Preview || len(prev.ServiceRules) != 3 || prev.OtherRules != 0 {
		t.Fatalf("preview: %d %s", pv.Code, pv.Body.String())
	}
	if canonJSON(mustTopo(t, s)) != canonJSON(before) {
		t.Fatal("preview changed the topology")
	}

	rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Updated       int  `json:"updated"`
		ApplyRequired bool `json:"apply_required"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Updated != 3 || !out.ApplyRequired {
		t.Fatalf("adopt answer: %s", rr.Body.String())
	}
	after := mustTopo(t, s)
	moved := map[string]bool{"youtube-premium": true, "u-chatgpt": true, "u-label": true}
	for i, r := range after.Rules {
		b := before.Rules[i]
		if moved[r.ID] {
			if r.TargetGroup != "jp" || r.TargetExit != "" {
				t.Fatalf("%s not retargeted: %+v", r.ID, r)
			}
			continue
		}
		if r.TargetGroup != b.TargetGroup || r.TargetExit != b.TargetExit || r.TargetAction != b.TargetAction {
			t.Fatalf("%s changed: %+v -> %+v", r.ID, b, r)
		}
	}
	g, _ := after.GroupByID("jp")
	if g.Members[0] != "jp" {
		t.Fatalf("group does not prefer exit: %+v", g)
	}
	_, regions, _ := s.matrixNow()
	if r := recOf(t, regions, "youtube-premium"); r == nil || !r.Adopted {
		t.Fatalf("not shown as adopted: %+v", r)
	}
}

// An auto group with an IX-bound member: moving the recommended ordinary
// exit to the front is not enough (IX-bound members sort first), so adopt
// pins it with fallback, and the selector really picks it.
func TestUnlockAdoptPinsPastIXBound(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	var ix, plain string
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Groups {
			g := &tp.Groups[i]
			if g.ID != "us" {
				continue
			}
			for _, n := range tp.Nodes {
				if n.Role == model.RoleExit && n.ID != "us" && ix == "" {
					ix = n.ID
				}
			}
			plain = "us"
			g.Members = []string{ix, plain}
			g.Mode = model.GroupAuto
		}
		for i := range tp.Nodes {
			if tp.Nodes[i].ID == ix {
				tp.Nodes[i].IXBound = true
			}
		}
		tp.Rules = append(tp.Rules, model.Rule{ID: "u-chatgpt", Name: "chatgpt", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "youtube.com", TargetGroup: "us"})
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if ix == "" {
		t.Skip("example topology has no second exit")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", plain, unlock.FamilyIPv4, probe.CatUnlocked, 50, now)))
	s.mu.Unlock()
	_, regions, _ := s.matrixNow()
	r := recOf(t, regions, "youtube-premium")
	if r == nil || r.ExitID != plain {
		t.Fatalf("recommendation: %+v", r)
	}
	if g, _ := mustTopo(t, s).GroupByID(r.Group); groupPrefers(mustTopo(t, s), g, plain) {
		t.Fatalf("setup: group already prefers %s", plain)
	}
	rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"`+plain+`"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	after := mustTopo(t, s)
	g, _ := after.GroupByID(r.Group)
	if !groupPrefers(after, g, plain) || g.Mode != model.GroupManual || g.Chosen != plain || g.OnFailure != model.OnFailureFallback {
		t.Fatalf("group not pinned with fallback: %+v", g)
	}
	_, regions, _ = s.matrixNow()
	if r := recOf(t, regions, "youtube-premium"); r == nil || !r.Adopted {
		t.Fatalf("not shown as adopted: %+v", r)
	}
}

// A probe of everything sends each regional service only to its region.
func TestScopedRunAll(t *testing.T) {
	f := &fakeProber{answer: func(req hostexec.ProbeRequest, svc string) probe.Category { return probe.CatUnlocked }}
	s := probeServer(t, f)
	job := runJob(t, s, `{"scope":"all","families":["ipv4"]}`)
	regions := exitRegions(mustTopo(t, s))
	for _, it := range job.Items {
		ad, _ := probe.Lookup(it.Service)
		if !ad.ProbesOn(regions[it.ExitID]) {
			t.Fatalf("%s probed on %s", it.Service, it.ExitID)
		}
	}
}

// Other rules on the group count only when the group's preferred exit moves.
func TestAdoptImpactCountsOtherGroupRules(t *testing.T) {
	a, _ := probe.Lookup("youtube-premium")
	tp := model.Topology{
		Nodes:  []model.Node{{ID: "jp-a", Role: model.RoleExit}, {ID: "jp-b", Role: model.RoleExit}},
		Groups: []model.RegionGroup{{ID: "jp", Members: []string{"jp-b", "jp-a"}}},
		Rules: []model.Rule{
			{ID: "o1", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "x.example.com", TargetGroup: "jp"},
			{ID: "o2", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "y.example.com", TargetGroup: "jp"},
			{ID: "o3", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "z.example.com", TargetGroup: "us"},
		},
	}
	if _, n := adoptImpact(tp, a, adoptChoice{Kind: "confirm", Group: "jp", ExitID: "jp-a"}); n != 2 {
		t.Fatalf("others %d", n)
	}
	if _, n := adoptImpact(tp, a, adoptChoice{Kind: "confirm", Group: "jp", ExitID: "jp-b"}); n != 0 {
		t.Fatalf("already preferred: %d", n)
	}
}

// A verdict covers only its adapter's primary check: MyTV SUPER unlocked
// says nothing about Viu, ABEMA unlocked nothing about Niconico. 采用 and
// its preview must never pick up a reference platform's rules.
func TestUnlockAdoptIgnoresReferencePlatformRules(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules,
			model.Rule{ID: "u-viu", Name: "Viu", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "viu.com", TargetExit: "hk-ix"},
			model.Rule{ID: "u-viu-geo", Name: "viu", Enabled: true, MatchType: model.MatchGeosite, MatchValue: "viu", Geosite: "viu", TargetExit: "hk-ix", MihomoGroup: "Viu"},
			model.Rule{ID: "u-nico", Name: "Niconico", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "nicovideo.jp", TargetExit: "hk-ix", MihomoGroup: "Niconico"},
		)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	tp := mustTopo(t, s)
	for _, svc := range []string{"auto-mytvsuper", "auto-abema"} {
		a, _ := probe.Lookup(svc)
		for _, i := range serviceRules(tp, a) {
			if id := tp.Rules[i].ID; id == "u-viu" || id == "u-viu-geo" || id == "u-nico" {
				t.Fatalf("%s claims reference rule %s", svc, id)
			}
		}
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("auto-mytvsuper", "hk-2", unlock.FamilyIPv4, probe.CatUnlocked, 50, now)))
	s.mu.Unlock()
	before := mustTopo(t, s)
	pv := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"auto-mytvsuper","exit":"hk-2","preview":true}`))
	var prev struct {
		ServiceRules []string `json:"service_rules"`
	}
	_ = json.Unmarshal(pv.Body.Bytes(), &prev)
	if pv.Code != http.StatusOK || len(prev.ServiceRules) != 1 || prev.ServiceRules[0] != "auto-mytvsuper" {
		t.Fatalf("preview: %d %s", pv.Code, pv.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"auto-mytvsuper","exit":"hk-2"}`)); rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	after := mustTopo(t, s)
	for i, r := range after.Rules {
		if r.ID == "u-viu" || r.ID == "u-viu-geo" || r.ID == "u-nico" {
			if canonJSON(r) != canonJSON(before.Rules[i]) {
				t.Fatalf("reference rule %s changed: %+v", r.ID, r)
			}
		}
	}
}

// A mihomo policy-group label is not service ownership: Netflix and
// Disney+ rules imported under one label "Netflix" stay apart. Adopting
// Netflix and its preview leave the Disney+ rule out; the label still
// drives POST /api/rules/retarget.
func TestUnlockAdoptIgnoresSharedMihomoLabel(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules,
			model.Rule{ID: "u-nf", Name: "nf", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "netflix.com", TargetExit: "hk-ix", MihomoGroup: "Netflix"},
			model.Rule{ID: "u-dis", Name: "dis", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "disneyplus.com", TargetExit: "hk-ix", MihomoGroup: "Netflix"},
		)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	tp := mustTopo(t, s)
	nf, _ := probe.Lookup("auto-netflix")
	dis, _ := probe.Lookup("auto-disney")
	owned := func(a probe.Adapter, id string) bool {
		for _, i := range serviceRules(tp, a) {
			if tp.Rules[i].ID == id {
				return true
			}
		}
		return false
	}
	if !owned(nf, "u-nf") || owned(nf, "u-dis") || !owned(dis, "u-dis") || owned(dis, "u-nf") {
		t.Fatal("ownership follows the shared label")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("auto-netflix", "hk-resi-2", unlock.FamilyIPv4, probe.CatUnlocked, 50, now)))
	s.mu.Unlock()
	_, regions, _ := s.matrixNow()
	rec := recOf(t, regions, "auto-netflix")
	if rec == nil {
		t.Fatal("no netflix recommendation")
	}
	pv := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"auto-netflix","exit":"`+rec.ExitID+`","preview":true}`))
	var prev struct {
		ServiceRules []string `json:"service_rules"`
	}
	_ = json.Unmarshal(pv.Body.Bytes(), &prev)
	if pv.Code != http.StatusOK || !containsStr(prev.ServiceRules, "u-nf") || containsStr(prev.ServiceRules, "u-dis") {
		t.Fatalf("preview: %d %s", pv.Code, pv.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"auto-netflix","exit":"`+rec.ExitID+`"}`)); rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	after := mustTopo(t, s)
	for _, r := range after.Rules {
		if r.ID == "u-dis" && (r.TargetExit != "hk-ix" || r.TargetGroup != "") {
			t.Fatalf("disney rule moved: %+v", r)
		}
		if r.ID == "u-nf" && r.TargetGroup != rec.Group {
			t.Fatalf("netflix rule not moved: %+v", r)
		}
	}
	// The label still selects both for a bulk retarget.
	if rr := do(s, http.MethodPost, "/api/rules/retarget", []byte(`{"mihomo_group":"Netflix","target":"group:hk-residential"}`)); rr.Code != http.StatusOK {
		t.Fatalf("retarget: %d %s", rr.Code, rr.Body.String())
	}
	for _, r := range mustTopo(t, s).Rules {
		if (r.ID == "u-dis" || r.ID == "u-nf") && r.TargetGroup != "hk-residential" {
			t.Fatalf("label retarget missed %s: %+v", r.ID, r)
		}
	}
}

// Viu is its own Hong Kong service: MyTV SUPER unlocked and Viu not
// available on the same exit give two correct rows; Viu has no
// recommendation; adopting MyTV SUPER leaves the Viu rules alone.
func TestViuIndependentOfMyTVSuper(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules,
			model.Rule{ID: "u-viu", Name: "Viu", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "viu.com", TargetExit: "hk-ix"},
			model.Rule{ID: "u-viu-geo", Name: "viu", Enabled: true, MatchType: model.MatchGeosite, MatchValue: "viu", Geosite: "viu", TargetExit: "hk-ix"},
		)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s,
		item("auto-mytvsuper", "hk-2", unlock.FamilyIPv4, probe.CatUnlocked, 50, now),
		item("auto-viu", "hk-2", unlock.FamilyIPv4, probe.CatNotUnlocked, 50, now)))
	s.mu.Unlock()
	_, regions, _ := s.matrixNow()
	var hk *matrixRegion
	for i := range regions {
		if regions[i].Code == "hk" {
			hk = &regions[i]
		}
	}
	if hk == nil {
		t.Fatal("no hk section")
	}
	rows := map[string]matrixService{}
	for _, sv := range hk.Services {
		rows[sv.ID] = sv
	}
	my, viu := rows["auto-mytvsuper"], rows["auto-viu"]
	if viu.ID == "" || viu.Name != "Viu" {
		t.Fatalf("no Viu row: %+v", hk.Services)
	}
	if c := cellAt(t, regions, "auto-mytvsuper", "hk-2"); c.State != cellUnlocked {
		t.Fatalf("mytvsuper cell: %+v", c)
	}
	if c := cellAt(t, regions, "auto-viu", "hk-2"); c.State != cellBlocked {
		t.Fatalf("viu cell: %+v", c)
	}
	if viu.Recommend != nil || my.Recommend == nil {
		t.Fatalf("recommendations: mytv %+v viu %+v", my.Recommend, viu.Recommend)
	}
	if !containsStr(viu.Rules, "u-viu") || !containsStr(viu.Rules, "u-viu-geo") || containsStr(my.Rules, "u-viu") {
		t.Fatalf("rules: mytv %v viu %v", my.Rules, viu.Rules)
	}
	before := mustTopo(t, s)
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"auto-mytvsuper","exit":"hk-2"}`)); rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"auto-viu","exit":"hk-2"}`)); rr.Code != http.StatusConflict {
		t.Fatalf("viu adopt: %d", rr.Code)
	}
	after := mustTopo(t, s)
	for i, r := range after.Rules {
		if (r.ID == "u-viu" || r.ID == "u-viu-geo") && canonJSON(r) != canonJSON(before.Rules[i]) {
			t.Fatalf("viu rule changed: %+v", r)
		}
	}
}

// An undecidable Viu answer is 未测到 (probed, no verdict), not 未测.
func TestViuUndecidableIsUnverified(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("auto-viu", "hk-2", unlock.FamilyIPv4, probe.CatUnknown, 50, now)))
	s.mu.Unlock()
	_, regions, _ := s.matrixNow()
	if c := cellAt(t, regions, "auto-viu", "hk-2"); c.State != cellUnverified || c.Reason == "" {
		t.Fatalf("viu cell: %+v", c)
	}
	if r := recOf(t, regions, "auto-viu"); r != nil {
		t.Fatalf("recommended: %+v", r)
	}
}

// Rule-set rules store the rule set by ID: ownership is decided on the rule
// set's name. "RULE-SET Netflix" (rs-1 named Netflix) belongs to Netflix;
// a broad "Amazon" set is not Prime Video's; "ViuTV" is not Viu's; "Hulu
// Japan" is Hulu Japan's.
func TestRuleOfServiceResolvesRuleSetName(t *testing.T) {
	tp := model.Topology{RuleSets: []model.RuleSet{
		{ID: "rs-1", Name: "Netflix"}, {ID: "rs-2", Name: "Amazon"}, {ID: "rs-3", Name: "ViuTV"}, {ID: "rs-4", Name: "Hulu Japan"},
	}}
	rule := func(rs string) model.Rule {
		return model.Rule{ID: "r-" + rs, Enabled: true, MatchType: model.MatchRuleSet, RuleSet: rs, TargetGroup: "us"}
	}
	cases := []struct {
		svc, rs string
		want    bool
	}{
		{"auto-netflix", "rs-1", true},
		{"primevideo", "rs-2", false},
		{"auto-viu", "rs-3", false},
		{"hulu-jp", "rs-4", true},
		{"auto-disney", "rs-1", false},
	}
	for _, c := range cases {
		a, ok := probe.Lookup(c.svc)
		if !ok {
			t.Fatalf("no adapter %s", c.svc)
		}
		if got := ruleOfService(tp, rule(c.rs), a); got != c.want {
			t.Fatalf("%s owns %s: got %v want %v", c.svc, c.rs, got, c.want)
		}
	}
}

// The current direction follows every service rule as the compiler does:
// rules split over a group and a pinned exit list both directions; a
// per-rule unlock decision inside an automatic group shows the decided
// member, not the group's preferred one.
func TestCurrentOfMixedAndDecisions(t *testing.T) {
	tp := model.Topology{
		Nodes:  []model.Node{{ID: "a", Name: "A", Role: model.RoleExit}, {ID: "b", Name: "B", Role: model.RoleExit}},
		Groups: []model.RegionGroup{{ID: "g", Name: "G", Mode: model.GroupAuto, Members: []string{"a", "b"}}},
		Rules: []model.Rule{
			{ID: "r1", Enabled: true, TargetGroup: "g"},
			{ID: "r2", Enabled: true, TargetExit: "b"},
		},
	}
	if c := currentOf(tp, []int{0}, nil); c == nil || c.Exit != "a" || c.Group != "g" || len(c.Mixed) != 0 {
		t.Fatalf("single: %+v", c)
	}
	if c := currentOf(tp, []int{0}, map[string]string{"r1": "b"}); c == nil || c.Exit != "b" || c.Group != "g" {
		t.Fatalf("decision: %+v", c)
	}
	c := currentOf(tp, []int{0, 1}, nil)
	if c == nil || len(c.Mixed) != 2 || c.Mixed[0].Exit != "a" || !c.Mixed[1].Pinned || c.Mixed[1].Exit != "b" {
		t.Fatalf("mixed: %+v", c)
	}
	// Same direction twice collapses to one.
	tp.Rules = append(tp.Rules, model.Rule{ID: "r3", Enabled: true, TargetGroup: "g"})
	if c := currentOf(tp, []int{0, 2}, nil); c == nil || len(c.Mixed) != 0 || c.Exit != "a" {
		t.Fatalf("collapsed: %+v", c)
	}
}
