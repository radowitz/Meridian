package hostexec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
)

const sampleCounters = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
{"counter": {"family": "inet", "name": "share_r1_new", "table": "meridian", "handle": 9, "packets": 5, "bytes": 300}},
{"counter": {"family": "inet", "name": "traffic_up_domestic", "table": "meridian", "handle": 11, "packets": 10, "bytes": 1000}},
{"counter": {"family": "inet", "name": "traffic_up_foreign", "table": "meridian", "handle": 12, "packets": 20, "bytes": 2000}},
{"counter": {"family": "inet", "name": "traffic_down_domestic", "table": "meridian", "handle": 13, "packets": 30, "bytes": 30000}},
{"counter": {"family": "inet", "name": "traffic_down_foreign", "table": "other", "handle": 14, "packets": 1, "bytes": 1}}]}`

type trafficRunner struct {
	out  string
	err  error
	cmds []string
}

func (r *trafficRunner) Run(_ context.Context, prog string, args ...string) (string, error) {
	r.cmds = append(r.cmds, prog+" "+strings.Join(args, " "))
	return r.out, r.err
}

func TestTrafficNamesMatchCompile(t *testing.T) {
	if !reflect.DeepEqual(TrafficCounterNames, compile.TrafficCounterNames) {
		t.Fatal("hostexec and compile disagree on the traffic counter names")
	}
}

func TestParseTrafficCounters(t *testing.T) {
	got, missing, err := ParseTrafficCounters(sampleCounters)
	if err != nil {
		t.Fatal(err)
	}
	want := []TrafficCounter{
		{Name: "traffic_up_domestic", Bytes: 1000, Packets: 10, Handle: 11},
		{Name: "traffic_up_foreign", Bytes: 2000, Packets: 20, Handle: 12},
		{Name: "traffic_down_domestic", Bytes: 30000, Packets: 30, Handle: 13},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
	// The other table's counter of the same name does not count.
	if !reflect.DeepEqual(missing, []string{"traffic_down_foreign"}) {
		t.Fatalf("missing %v", missing)
	}
	if _, _, err := ParseTrafficCounters("not json"); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestTrafficStatusFixedCommand(t *testing.T) {
	r := &trafficRunner{out: sampleCounters}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: r}
	st := a.TrafficStatus(context.Background())
	if len(st.Counters) != 3 || st.ReadAt == "" || st.Error != "" {
		t.Fatalf("%+v", st)
	}
	if len(r.cmds) != 1 || r.cmds[0] != "nft -j list counters table inet meridian" {
		t.Fatalf("%v", r.cmds)
	}
	r.err = errors.New("No such file or directory")
	st = a.TrafficStatus(context.Background())
	if st.Error == "" || len(st.Missing) != 4 || st.Counters == nil {
		t.Fatalf("%+v", st)
	}
}

func TestServeTrafficRejectsParameters(t *testing.T) {
	r := &trafficRunner{out: sampleCounters}
	a := &Agent{Token: func() (string, error) { return "tok", nil }, Runner: r}
	h := a.Handler()
	req := httptest.NewRequest("POST", "/v1/traffic", strings.NewReader(`{"table":"filter"}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || len(r.cmds) != 0 {
		t.Fatalf("%d %v", rec.Code, r.cmds)
	}
	req = httptest.NewRequest("POST", "/v1/traffic", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "traffic_up_foreign") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
