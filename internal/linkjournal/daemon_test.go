package linkjournal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

func get(t *testing.T, h http.Handler, method, target, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, b
}

// The status socket's four fixed requests.
func TestStatusHandler(t *testing.T) {
	w := &world{ck: newClock(), units: map[string]string{"wstunnel-client-gw-access.service": "active"}, route: "default dev m00 \\\n"}
	w.hs = map[string]int64{"m00": w.ck.now().Unix(), "m00w": w.ck.now().Unix()}
	cfg := tunnelCfg()
	cfg.Paths = []PathConfig{{Name: "udp", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "hk", Tier: "primary", Mode: "udp"}}
	c, _ := w.collector(t, cfg)
	h := c.StatusHandler()

	code, b := get(t, h, "GET", "/v1/health", "")
	var hl Health
	if code != 200 || json.Unmarshal(b, &hl) != nil || hl.Ready || hl.Passes != 0 || hl.Gateway != "gw" {
		t.Fatalf("health before the first pass: %d %s", code, b)
	}
	w.pass(c, 1, 10*time.Second)
	delete(w.hs, "m00")
	w.pass(c, 1, 10*time.Second)

	code, b = get(t, h, "GET", "/v1/health", "")
	if code != 200 || json.Unmarshal(b, &hl) != nil || !hl.Ready || hl.Journal.Events != 1 || hl.Journal.MaxEvents != DefaultMaxEvents || hl.Journal.Budget.Total != DefaultMaxBytes || len(hl.Sources) != 3 {
		t.Fatalf("health: %d %s", code, b)
	}
	code, b = get(t, h, "GET", "/v1/current", "")
	var cur Current
	if code != 200 || json.Unmarshal(b, &cur) != nil || len(cur.Objects) != 7 || cur.LastPass == nil {
		t.Fatalf("current: %d %s", code, b)
	}
	code, b = get(t, h, "GET", "/v1/events?class=tunnel&limit=10", "")
	var page Page
	if code != 200 || json.Unmarshal(b, &page) != nil || len(page.Events) != 1 || page.Events[0].To != TunnelAbsent {
		t.Fatalf("events: %d %s", code, b)
	}
	if len(b) > sniff.MaxStatusAnswer {
		t.Fatal("answer too long")
	}
	// Refused: other methods, unknown parameters, parameters where none
	// are taken, a body on the clear.
	for _, c := range []struct {
		method, target, body string
		want                 int
	}{
		{"POST", "/v1/health", "", 405}, {"POST", "/v1/current", "", 405}, {"POST", "/v1/events", "", 405}, {"GET", "/v1/clear", "", 405},
		{"GET", "/v1/health?x=1", "", 400}, {"GET", "/v1/current?id=m00", "", 400}, {"GET", "/v1/events?path=/etc/passwd", "", 400},
		{"GET", "/v1/events?limit=100000", "", 400}, {"GET", "/v1/events?class=a%20b", "", 400}, {"POST", "/v1/clear?all=1", "", 400},
		{"POST", "/v1/clear", `{"dir":"/"}`, 400}, {"GET", "/v1/run", "", 404}, {"GET", "/", "", 404},
	} {
		if code, _ := get(t, h, c.method, c.target, c.body); code != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.target, code, c.want)
		}
	}
	code, b = get(t, h, "POST", "/v1/clear", "")
	var cr ClearResult
	if code != 200 || json.Unmarshal(b, &cr) != nil || cr.Cleared != 1 || cr.Stats.Events != 0 || cr.Stats.ClearedAt == nil {
		t.Fatalf("clear: %d %s", code, b)
	}
	if _, b = get(t, h, "GET", "/v1/events", ""); !strings.Contains(string(b), `"events":[]`) {
		t.Fatalf("events after the clear: %s", b)
	}
	// The pass after a clear is a baseline again (the missing interface
	// included: no event for it).
	w.pass(c, 3, 10*time.Second)
	if _, b = get(t, h, "GET", "/v1/events", ""); !strings.Contains(string(b), `"events":[]`) {
		t.Fatalf("events after the clear and three passes: %s", b)
	}
}

// A page of the largest events and the fullest current view stay below the
// status socket's answer limit.
func TestAnswerSizes(t *testing.T) {
	if PageMax*MaxLine+64<<10 > sniff.MaxStatusAnswer {
		t.Fatalf("a full page (%d bytes) does not fit the status answer limit", PageMax*MaxLine)
	}
	ck := newClock()
	j := openJ(t, t.TempDir(), ck, nil)
	var obs []Observation
	for i := 0; i < MaxObjects; i++ {
		o := tun(strings.Repeat("x", 60)+string(rune('a'+i%26))+strings.Repeat("y", i%7), TunnelStale)
		o.ID = o.ID + "-" + strings.Repeat("z", i%5) + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+(i/100)%10))
		o.Evidence, o.Label, o.Reason = strings.Repeat("证", 400), strings.Repeat("标", 100), strings.Repeat("r", 60)
		obs = append(obs, o)
	}
	j.Observe(ck.now(), obs)
	b, err := json.Marshal(j.Current())
	if err != nil || len(b) > sniff.MaxStatusAnswer {
		t.Fatalf("the current view of %d objects has %d bytes (limit %d): %v", len(j.Current().Objects), len(b), sniff.MaxStatusAnswer, err)
	}
}

func TestParseArgsAndLoadConfig(t *testing.T) {
	c, err := ParseArgs(nil)
	if err != nil || c.ConfigPath != ConfigPath || c.Dir != StateDir || c.MaxEvents != DefaultMaxEvents || c.MaxAge != DefaultMaxAge || c.MaxBytes != DefaultMaxBytes || c.StatusSocket != "" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if c, err := ParseArgs([]string{"--config", "/etc/x.json", "--dir", "/var/lib/x", "--status-socket", "/run/x/s.sock", "--max-events", "100", "--max-age", "48h", "--max-bytes", "4194304"}); err != nil || c.MaxEvents != 100 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range [][]string{
		{"--dir", "relative"}, {"--dir", "/var/lib/../etc"}, {"--config", "x.json"}, {"--status-socket", "s.sock"}, {"--max-events", "1"},
		{"--max-age", "1m"}, {"--max-bytes", "1024"}, {"--exec", "x"}, {"extra"},
	} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "link-journal.json")
	good, _ := json.Marshal(tunnelCfg())
	if err := os.WriteFile(p, good, 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadConfig(p); err != nil || len(cfg.Tunnels) != 3 {
		t.Fatalf("%+v %v", cfg, err)
	}
	for name, body := range map[string]string{
		"not json":      "{",
		"unknown field": strings.Replace(string(good), `"version":1`, `"version":1,"exec":"/bin/sh"`, 1),
		"bad iface":     strings.Replace(string(good), `"iface":"m00"`, `"iface":"eth0"`, 1),
	} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing object list was accepted")
	}
	// Main refuses to start without a valid object list (exit 1) and on a
	// bad flag (exit 2); nothing is written anywhere.
	if code := Main([]string{"--config", filepath.Join(dir, "missing.json"), "--dir", filepath.Join(dir, "state")}); code != 1 {
		t.Fatalf("Main without an object list: exit %d", code)
	}
	if code := Main([]string{"--bogus"}); code != 2 {
		t.Fatalf("Main with a bad flag: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Fatal("Main created the state directory before it had a valid object list")
	}
}

// The real file read: bounded, and a missing record is a failed read with a
// reason, not a state.
func TestReaderUpstreamFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "upstream")
	r := Reader{UpstreamFile: p}
	if _, err := r.Upstream(); err == nil || !strings.Contains(err.Error(), "没有记录文件") {
		t.Fatalf("missing record: %v", err)
	}
	now := time.Now().Unix()
	text := "meridian-upstream 1\nbeat " + itoa(now) + "\npath udp\niface m00\nhub ix\ntier primary\nsince " + itoa(now-5) + "\nstate ok\nend\n"
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := r.Upstream()
	if err != nil || rec.Path != "udp" || rec.Beat != now {
		t.Fatalf("%+v %v", rec, err)
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("x", MaxUpstreamFile+10)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Upstream(); err == nil {
		t.Fatal("an oversized record was accepted")
	}
	// The status socket that is not there.
	if _, err := (Reader{SniffSocket: filepath.Join(dir, "none.sock")}).SelfCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "没有状态套接字") {
		t.Fatalf("missing socket: %v", err)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
