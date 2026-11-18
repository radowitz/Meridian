package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// GET /api/upstream with the backup hub reached through relays: the
// gateway's record (synthetic passes: the main group down long enough to
// switch) says which group carries, on which hub, and the groups.
func TestUpstreamRelayBackupView(t *testing.T) {
	s := newTest(t)
	up := &fakeUpstream{}
	s.Upstream = up
	topo := defaults.RelayBackupExample()
	model.MigrateRegionGroups(&topo)
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pathquality.ParseConfig([]byte(b.File("nodes/gw/etc/meridian/path-quality.json")))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	leg := func(iface string, recv int) pathquality.LegSample {
		return pathquality.LegSample{Iface: iface, Sent: 5, Recv: recv, RTTus: int64(30000 * min(recv, 1))}
	}
	record := func(mainUp bool, passes int) {
		st := pathquality.NewState(cfg, now-int64(passes*5)-10)
		r := 0
		if mainUp {
			r = 5
		}
		for i := passes; i >= 0; i-- {
			m := pathquality.Measurement{Now: now - int64(i*5), Relays: map[string]pathquality.PathSample{
				"access": {Legs: []pathquality.LegSample{leg("m05", r), leg("m05w", r)}},
				"bk1":    {Legs: []pathquality.LegSample{leg("m06", 5), leg("m06w", 5)}},
				"bk2":    {Legs: []pathquality.LegSample{leg("m07", 5), leg("m07w", 5)}},
			}}
			st, _ = pathquality.Step(cfg, st, m)
		}
		rec, err := hostexec.ParseUpstream(pathquality.FormatStatus(cfg, st, now, "go"))
		if err != nil {
			t.Fatal(err)
		}
		up.st = hostexec.UpstreamStatus{Present: true, Record: &rec}
	}
	type view struct {
		Mode    string `json:"mode"`
		Known   bool   `json:"known"`
		Tier    string `json:"tier"`
		HubName string `json:"hub_name"`
		Sharing struct {
			Path        string `json:"path"`
			AlertText   string `json:"alert_text"`
			BackupGroup *struct {
				Hub    string   `json:"hub"`
				Name   string   `json:"name"`
				Relays []string `json:"relays"`
			} `json:"backup_group"`
			Relays []struct {
				ID     string `json:"id"`
				Group  string `json:"group"`
				Weight int    `json:"weight"`
				InSet  bool   `json:"in_set"`
			} `json:"relays"`
		} `json:"sharing"`
	}
	get := func() view {
		rr := do(s, http.MethodGet, "/api/upstream", nil)
		var v view
		if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	record(true, 3)
	v := get()
	if !v.Known || v.Tier != "primary" || v.HubName != "主枢纽" || v.Sharing.Path != "main" || v.Sharing.BackupGroup == nil ||
		v.Sharing.BackupGroup.Name != "备用枢纽" || len(v.Sharing.BackupGroup.Relays) != 2 || v.Sharing.Relays[0].Group != "main" || v.Sharing.Relays[1].Group != "backup" ||
		!v.Sharing.Relays[0].InSet || v.Sharing.Relays[1].InSet {
		t.Fatalf("main: %+v", v)
	}
	record(false, 20)
	v = get()
	if !v.Known || v.Tier != "backup" || v.HubName != "备用枢纽" || v.Sharing.Path != "backup" ||
		v.Sharing.Relays[0].Weight != 0 || !v.Sharing.Relays[1].InSet || !v.Sharing.Relays[2].InSet || v.Sharing.AlertText == "" {
		t.Fatalf("backup: %+v", v)
	}
}
