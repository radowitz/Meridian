package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

type fakeSniffRT struct {
	st  hostexec.SniffStatus
	err error
}

func (f fakeSniffRT) SniffStatus(context.Context) (hostexec.SniffStatus, error) { return f.st, f.err }

// GET/PUT /api/sniff: the setting with its defaults, coverage text, the
// runtime passed through; an invalid setting is refused and not saved.
func TestSniffAPI(t *testing.T) {
	s, _ := importServer(t)
	rr := do(s, http.MethodGet, "/api/sniff", nil)
	var out struct {
		Setting  sniffSettingView `json:"setting"`
		Runtime  sniffRuntimeView `json:"runtime"`
		Coverage struct {
			AddressOnly []string `json:"address_only"`
		} `json:"coverage"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatal(rr.Body.String())
	}
	if out.Setting.Enabled || len(out.Setting.Ports) != 2 || out.Runtime.Code != "agent_unavailable" || len(out.Coverage.AddressOnly) == 0 {
		t.Fatalf("%+v", out)
	}
	if rr := do(s, http.MethodPut, "/api/sniff", []byte(`{"enabled":true,"ports":[53]}`)); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("port 53 saved: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPut, "/api/sniff", []byte(`{"enabled":true,"record_names":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	tp, _ := s.topology()
	if !tp.SniffOn() || !tp.Settings.Sniff.RecordNames {
		t.Fatalf("%+v", tp.Settings.Sniff)
	}
	s.Sniff = fakeSniffRT{st: hostexec.SniffStatus{Present: true, Active: "active", Health: json.RawMessage(`{"ready":true}`), Recent: json.RawMessage(`{"connections":[]}`)}}
	rr = do(s, http.MethodGet, "/api/sniff", nil)
	if !strings.Contains(rr.Body.String(), `"ready":true`) || !strings.Contains(rr.Body.String(), `"available":true`) {
		t.Fatal(rr.Body.String())
	}
	s.Sniff = fakeSniffRT{st: hostexec.SniffStatus{}}
	if rr := do(s, http.MethodGet, "/api/sniff", nil); !strings.Contains(rr.Body.String(), `"code":"not_running"`) {
		t.Fatal(rr.Body.String())
	}
}

// The rule tester honours device rules by MAC (it used to ignore them and
// treat the rule as one for every client).
func TestRuleTesterSourceMAC(t *testing.T) {
	s, _ := importServer(t)
	s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append([]model.Rule{
			{ID: "mac", Name: "mac", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "example.net", TargetGroup: "jp", SourceMAC: "02:00:00:00:00:01"},
			{ID: "all", Name: "all", Enabled: true, Manual: true, MatchType: model.MatchSuffix, MatchValue: "example.net", TargetGroup: "us"},
		}, tp.Rules...)
		return true, nil
	})
	for body, want := range map[string]string{
		`{"name":"x.example.net"}`:                                  `"id":"all"`,
		`{"name":"x.example.net","source_mac":"02:00:00:00:00:02"}`: `"id":"all"`,
		`{"name":"x.example.net","source_mac":"02:00:00:00:00:01"}`: `"id":"mac"`,
	} {
		rr := do(s, http.MethodPost, "/api/rules/test", []byte(body))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Errorf("%s: %s", body, rr.Body.String())
		}
	}
	if rr := do(s, http.MethodPost, "/api/rules/test", []byte(`{"name":"x.example.net","source_mac":"nope"}`)); rr.Code != http.StatusUnprocessableEntity {
		t.Fatal(rr.Body.String())
	}
}
