package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// sharedRecord compiles the topology and renders the controller's record
// for one pass (ali good, ali2 losing 2 of 5, backup good) at beat.
func sharedRecord(t *testing.T, topo model.Topology, beat int64) *hostexec.UpstreamState {
	t.Helper()
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	st := pathquality.NewState(cfg, beat-10)
	m := pathquality.Measurement{Now: beat, Relays: map[string]pathquality.PathSample{
		"ali":  {Legs: []pathquality.LegSample{{Iface: "m02", Sent: 5, Recv: 5, RTTus: 31000, RxBytes: 1 << 20}, {Iface: "m02w", Sent: 5, Recv: 5, RTTus: 40000}}},
		"ali2": {Legs: []pathquality.LegSample{{Iface: "m03", Sent: 5, Recv: 3, RTTus: 35000}}},
	}}
	if cfg.Backup != nil {
		m.Backup = &pathquality.PathSample{Legs: []pathquality.LegSample{{Iface: cfg.Backup.Iface, Sent: 5, Recv: 5, RTTus: 60000}}}
	}
	st, _ = pathquality.Step(cfg, st, m)
	rec, err := hostexec.ParseUpstream(pathquality.FormatStatus(cfg, st, beat, "go"))
	if err != nil {
		t.Fatal(err)
	}
	return &rec
}

type sharingBody struct {
	Mode    string `json:"mode"`
	Known   bool   `json:"known"`
	Code    string `json:"code"`
	Tier    string `json:"tier"`
	Sharing *struct {
		Known      bool   `json:"known"`
		Code       string `json:"code"`
		Controller string `json:"controller"`
		Path       string `json:"path"`
		Designated string `json:"designated"`
		Relays     []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Status   string `json:"status"`
			Weight   int    `json:"weight"`
			InSet    bool   `json:"in_set"`
			Grade    string `json:"grade"`
			Measured *struct {
				RTTms   *float64 `json:"rtt_ms"`
				LossPct *float64 `json:"loss_pct"`
				At      string   `json:"at"`
			} `json:"measured"`
		} `json:"relays"`
		Backup *struct {
			Name  string `json:"name"`
			Grade string `json:"grade"`
		} `json:"backup"`
		ProbeCost struct {
			Enabled       bool   `json:"enabled"`
			BytesPerProbe int64  `json:"bytes_per_probe"`
			Source        string `json:"source"`
		} `json:"probe_cost"`
		EvictionImpact string `json:"eviction_impact"`
		Settings       struct {
			EvictAfterSec int `json:"evict_after_sec"`
		} `json:"settings"`
	} `json:"sharing"`
}

func getSharing(t *testing.T, s *Server) sharingBody {
	t.Helper()
	rr := do(s, http.MethodGet, "/api/upstream", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var b sharingBody
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUpstreamSharingView(t *testing.T) {
	s := newTest(t)
	up := &fakeUpstream{}
	s.Upstream = up
	topo := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&topo)
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	up.st = hostexec.UpstreamStatus{Present: true, Record: sharedRecord(t, topo, now)}
	b := getSharing(t, s)
	if b.Mode != "dual" || !b.Known || b.Tier != "primary" || b.Sharing == nil {
		t.Fatalf("%+v", b)
	}
	sh := b.Sharing
	if !sh.Known || sh.Controller != "go" || sh.Path != "main" || len(sh.Relays) != 2 || sh.Relays[0].Name != "国内中继" || sh.Relays[1].Name != "国内中继 2" {
		t.Fatalf("%+v", sh)
	}
	if m := sh.Relays[1].Measured; m == nil || m.LossPct == nil || *m.LossPct != 40 || m.At == "" {
		t.Fatalf("measured %+v", sh.Relays[1].Measured)
	}
	if sh.Backup == nil || sh.Backup.Name != "备用枢纽" || sh.Backup.Grade != "good" {
		t.Fatalf("backup %+v", sh.Backup)
	}
	if !sh.ProbeCost.Enabled || sh.ProbeCost.Source != "estimated" || sh.ProbeCost.BytesPerProbe < 1_000_000 {
		t.Fatalf("probe cost %+v", sh.ProbeCost)
	}
	if !strings.Contains(sh.EvictionImpact, "重置") || sh.Settings.EvictAfterSec != 30 {
		t.Fatalf("impact %q settings %+v", sh.EvictionImpact, sh.Settings)
	}
	// A stale record: the carrying hub and the relays are not known.
	up.st = hostexec.UpstreamStatus{Present: true, Record: sharedRecord(t, topo, now-600)}
	if b := getSharing(t, s); b.Known || b.Code != "stale" || b.Sharing == nil || b.Sharing.Known {
		t.Fatalf("stale: %+v", b)
	}
	// A single-relay record under a sharing topology: not installed yet.
	up.st = hostexec.UpstreamStatus{Present: true, Record: &hostexec.UpstreamState{Version: 1, Beat: now, Path: "udp", Iface: "m02", Hub: "ix", Tier: "primary", Since: now, State: "ok"}}
	if b := getSharing(t, s); b.Known || b.Code != "record_mismatch" {
		t.Fatalf("mismatch: %+v", b)
	}
}

func TestUpstreamSharingSingleHub(t *testing.T) {
	s := newTest(t)
	up := &fakeUpstream{}
	s.Upstream = up
	topo := defaults.SharedRelaysExample()
	var nodes []model.Node
	for _, n := range topo.Nodes {
		if n.ID != "hk5" {
			nodes = append(nodes, n)
		}
	}
	topo.Nodes = nodes
	var links []model.Link
	for _, l := range topo.Links {
		if l.From != "hk5" && l.To != "hk5" {
			links = append(links, l)
		}
	}
	topo.Links = links
	model.MigrateRegionGroups(&topo)
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	b := getSharing(t, s)
	if b.Mode != "single" || !b.Known || b.Sharing == nil || b.Sharing.Known || b.Sharing.Code != "not_recorded" || len(b.Sharing.Relays) != 2 {
		t.Fatalf("before install: %+v", b)
	}
	up.st = hostexec.UpstreamStatus{Present: true, Record: sharedRecord(t, topo, time.Now().Unix())}
	b = getSharing(t, s)
	if b.Sharing == nil || !b.Sharing.Known || b.Sharing.Backup != nil || b.Sharing.Relays[0].Status != "active" {
		t.Fatalf("after: %+v", b.Sharing)
	}
}

// The settings are validated when the topology is saved.
func TestPathQualitySettingsValidatedOnSave(t *testing.T) {
	s := newTest(t)
	topo := defaults.SharedRelaysExample()
	model.MigrateRegionGroups(&topo)
	topo.Settings.PathQuality = &model.PathQuality{MildRTTMS: 500, PoorRTTMS: 300}
	rr := do(s, http.MethodPut, "/api/topology", mustJSON(topo))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "invalid_path_quality") {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	topo.Settings.PathQuality = &model.PathQuality{EvictAfterSec: 45, ProbeDailyBudgetMB: 16}
	rr = do(s, http.MethodPut, "/api/topology", mustJSON(topo))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	saved, err := s.topology()
	if err != nil || saved.Settings.PathQuality == nil || saved.Settings.PathQuality.EvictAfterSec != 45 {
		t.Fatalf("%v %+v", err, saved.Settings.PathQuality)
	}
}
