package hostexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/linkjournal"
)

func linkTestConfig() linkjournal.Config {
	return linkjournal.Config{Version: 1, Gateway: "gw", IntervalS: 10, SlowEvery: 3, HandshakeStaleS: 180, UpstreamStaleS: 60, Mode: linkjournal.ModeDual,
		Paths:   []linkjournal.PathConfig{{Name: "udp", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "ix", Tier: "primary", Mode: "udp"}},
		Tunnels: []linkjournal.TunnelConfig{{Iface: "m00", Link: "gw-access", Mode: "udp", Peer: "access", KeepaliveS: 25}}}
}

// linkCollector is a real collector (journal in a temporary directory, no
// source read) behind a Unix socket, recording what it is asked.
type linkCollector struct {
	j     *linkjournal.Journal
	sock  string
	dir   string
	mu    sync.Mutex
	asked []string
}

func newLinkCollector(t *testing.T) *linkCollector {
	t.Helper()
	base, err := os.MkdirTemp("", "lj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	lc := &linkCollector{sock: filepath.Join(base, "s.sock"), dir: filepath.Join(base, "journal")}
	j, err := linkjournal.Open(linkjournal.Options{Dir: lc.dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	lc.j = j
	c := linkjournal.NewCollector(linkTestConfig(), j, linkjournal.Reader{})
	l, err := net.Listen("unix", lc.sock)
	if err != nil {
		t.Fatal(err)
	}
	h := c.StatusHandler()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lc.mu.Lock()
		lc.asked = append(lc.asked, r.Method+" "+r.URL.RequestURI())
		lc.mu.Unlock()
		h.ServeHTTP(w, r)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return lc
}

func (lc *linkCollector) requests() []string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return append([]string(nil), lc.asked...)
}

func tunnelObs(state string) linkjournal.Observation {
	return linkjournal.Observation{Class: linkjournal.ClassTunnel, Kind: linkjournal.KindTunnel, ID: "m00", Label: "隧道 m00", State: state, Source: linkjournal.SourceHandshake, Evidence: "synthetic"}
}

// The link journal through the agent: four fixed requests, authenticated,
// parameters validated before the collector is asked, its answer passed on
// unchanged; the agent runs no command and opens no file for them.
func TestAgentLinkJournalRequests(t *testing.T) {
	h := newFakeHost()
	root := t.TempDir()
	a := &Agent{Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: h, PreflightRoot: root,
		LinkJournalSocketPath: "/nonexistent-meridian-test/link.sock"}
	hs := httptest.NewServer(a.Handler())
	defer hs.Close()
	post := func(path, body string, auth bool) (int, LinkJournalAnswer) {
		t.Helper()
		req, _ := http.NewRequest("POST", hs.URL+path, bytes.NewBufferString(body))
		if auth {
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out LinkJournalAnswer
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	paths := []string{"/v1/link/journal", "/v1/link/journal/current", "/v1/link/journal/clear", "/v1/link/journal/status"}
	for _, p := range paths {
		if code, _ := post(p, `{}`, false); code != http.StatusUnauthorized {
			t.Fatalf("%s without the token: %d", p, code)
		}
	}
	// No collector: every journal request says so; the clear clears nothing.
	for _, p := range paths[:3] {
		if code, ans := post(p, `{}`, true); code != 200 || ans.Present || ans.Code != "no_socket" || ans.Body != nil {
			t.Fatalf("%s without a collector: %d %+v", p, code, ans)
		}
	}
	if _, ans := post("/v1/link/journal/clear", `{}`, true); !strings.Contains(ans.Error, "没有清空") {
		t.Fatalf("clear without a collector: %+v", ans)
	}
	st := a.LinkJournalStatus(context.Background())
	if st.Present || st.ConfigInstalled || st.Health != nil || st.UnitActive != "inactive" {
		t.Fatalf("status without a collector: %+v", st)
	}

	lc := newLinkCollector(t)
	a.LinkJournalSocketPath = lc.sock
	now := time.Now()
	lc.j.Observe(now.Add(-30*time.Second), []linkjournal.Observation{tunnelObs(linkjournal.TunnelOK)})
	lc.j.Observe(now.Add(-10*time.Second), []linkjournal.Observation{tunnelObs(linkjournal.TunnelStale)})
	if err := os.MkdirAll(filepath.Join(root, "etc/meridian"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, strings.TrimPrefix(linkjournal.ConfigPath, "/")), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.units[LinkJournalUnit] = "active"

	code, ans := post("/v1/link/journal", `{"class":"tunnel","kind":"tunnel","id":"m00","limit":10}`, true)
	var page linkjournal.Page
	if code != 200 || !ans.Present || ans.Code != "" || json.Unmarshal(ans.Body, &page) != nil || len(page.Events) != 1 || page.Events[0].To != linkjournal.TunnelStale || page.Events[0].From != linkjournal.TunnelOK {
		t.Fatalf("page: %d %+v", code, ans)
	}
	if got := lc.requests(); got[len(got)-1] != "GET /v1/events?class=tunnel&id=m00&kind=tunnel&limit=10" {
		t.Fatalf("the collector was asked %q", got[len(got)-1])
	}
	if code, ans := post("/v1/link/journal", `{"class":"relay"}`, true); code != 200 || !bytes.Contains(ans.Body, []byte(`"events":[]`)) {
		t.Fatalf("filtered page: %d %+v", code, ans)
	}
	code, ans = post("/v1/link/journal/current", `{}`, true)
	var cur linkjournal.Current
	if code != 200 || json.Unmarshal(ans.Body, &cur) != nil || len(cur.Objects) != 1 || cur.Objects[0].State != linkjournal.TunnelStale || cur.Objects[0].Level != linkjournal.LevelAbnormal {
		t.Fatalf("current: %d %+v", code, ans)
	}
	st = a.LinkJournalStatus(context.Background())
	if !st.Present || !st.ConfigInstalled || st.UnitActive != "active" || !bytes.Contains(st.Health, []byte(`"events":1`)) || st.Error != "" {
		t.Fatalf("status: %+v", st)
	}

	// Refused before anything is asked or run.
	asked, cmds := len(lc.requests()), len(h.commands())
	for _, c := range []struct{ path, body string }{
		{"/v1/link/journal", `{"id":"m00; reboot"}`},
		{"/v1/link/journal", `{"class":"../../etc"}`},
		{"/v1/link/journal", `{"limit":100000}`},
		{"/v1/link/journal", `{"from":"yesterday"}`},
		{"/v1/link/journal", `{"before":"x"}`},
		{"/v1/link/journal", `{"path":"/var/lib/meridian-linklog/checkpoint.json"}`},
		{"/v1/link/journal", `{"command":"wg show all dump"}`},
		{"/v1/link/journal", `{"iface":"mra"}`},
		{"/v1/link/journal", `not json`},
		{"/v1/link/journal/current", `{"id":"m00"}`},
		{"/v1/link/journal/clear", `{"dir":"/var/lib"}`},
		{"/v1/link/journal/status", `{"unit":"ssh.service"}`},
	} {
		if code, _ := post(c.path, c.body, true); code != http.StatusBadRequest {
			t.Errorf("%s %s: %d", c.path, c.body, code)
		}
	}
	if got := lc.requests(); len(got) != asked {
		t.Fatalf("a refused request reached the collector: %v", got[asked:])
	}
	if got := h.commands(); len(got) != cmds {
		t.Fatalf("a refused request ran a command: %v", got[cmds:])
	}
	// The only command of the whole feature is the fixed is-active of the
	// collector's own unit (status read).
	for _, c := range h.commands() {
		if c != "systemctl is-active "+LinkJournalUnit {
			t.Fatalf("unexpected command %q", c)
		}
	}

	// Clear goes to the collector.
	code, ans = post("/v1/link/journal/clear", `{}`, true)
	if code != 200 || ans.Code != "" || !bytes.Contains(ans.Body, []byte(`"cleared":1`)) {
		t.Fatalf("clear: %d %+v", code, ans)
	}
	if got := lc.requests(); got[len(got)-1] != "POST /v1/clear" {
		t.Fatalf("clear asked %q", got[len(got)-1])
	}
	if _, ans := post("/v1/link/journal", `{}`, true); !bytes.Contains(ans.Body, []byte(`"events":[]`)) {
		t.Fatalf("after the clear: %+v", ans)
	}

	// The client side, over the agent's socket.
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	go a.Serve(l)
	defer l.Close()
	tok := filepath.Join(filepath.Dir(sock), "tok")
	os.WriteFile(tok, []byte(strings.Repeat("t", 64)), 0o600)
	c := &Client{Socket: sock, TokenFile: tok}
	if st, err := c.LinkJournalStatus(context.Background()); err != nil || !st.Present {
		t.Fatalf("client status: %+v %v", st, err)
	}
	if ans, err := c.LinkJournalCurrent(context.Background()); err != nil || ans.Code != "" || !bytes.Contains(ans.Body, []byte(`"objects"`)) {
		t.Fatalf("client current: %+v %v", ans, err)
	}
	if ans, err := c.LinkJournal(context.Background(), linkjournal.Query{Class: "tunnel", Limit: 5}); err != nil || ans.Code != "" {
		t.Fatalf("client page: %+v %v", ans, err)
	}
	if ans, err := c.LinkJournal(context.Background(), linkjournal.Query{Class: "a b"}); err != nil || ans.Code != "bad_request" {
		t.Fatalf("client bad query: %+v %v", ans, err)
	}
	if ans, err := c.LinkJournalClear(context.Background()); err != nil || ans.Code != "" {
		t.Fatalf("client clear: %+v %v", ans, err)
	}
	none := &Client{Socket: filepath.Join(filepath.Dir(sock), "none.sock"), TokenFile: tok}
	if _, err := none.LinkJournalStatus(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// An agent without the requests (an older binary) is told apart.
func TestLinkJournalClientOldAgent(t *testing.T) {
	dir, err := os.MkdirTemp("", "lj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/action", func(w http.ResponseWriter, r *http.Request) {})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()
	tok := filepath.Join(dir, "tok")
	os.WriteFile(tok, []byte(strings.Repeat("t", 64)), 0o600)
	c := &Client{Socket: sock, TokenFile: tok}
	if _, err := c.LinkJournalStatus(context.Background()); !errors.Is(err, ErrLinkJournalUnsupported) {
		t.Fatalf("status: %v", err)
	}
	if _, err := c.LinkJournalCurrent(context.Background()); !errors.Is(err, ErrLinkJournalUnsupported) {
		t.Fatalf("current: %v", err)
	}
	if _, err := c.LinkJournal(context.Background(), linkjournal.Query{}); !errors.Is(err, ErrLinkJournalUnsupported) {
		t.Fatalf("journal: %v", err)
	}
	if _, err := c.LinkJournalClear(context.Background()); !errors.Is(err, ErrLinkJournalUnsupported) {
		t.Fatalf("clear: %v", err)
	}
}

// Without a running collector the agent does not touch the journal's
// directory: a clear leaves every file as it is.
func TestLinkJournalClearWithoutCollectorTouchesNothing(t *testing.T) {
	h := newFakeHost()
	root := t.TempDir()
	dir := filepath.Join(root, strings.TrimPrefix(linkjournal.StateDir, "/"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"events-00000000000000000001.jsonl", "checkpoint.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("kept\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := &Agent{Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: h, PreflightRoot: root,
		LinkJournalSocketPath: "/nonexistent-meridian-test/link.sock"}
	a.init()
	ans := a.linkJournalCall(context.Background(), http.MethodPost, "/v1/clear")
	if ans.Code != "no_socket" || ans.Present {
		t.Fatalf("%+v", ans)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 || len(h.commands()) != 0 {
		t.Fatalf("the agent touched the journal's directory or ran a command: %v %v", ents, h.commands())
	}
}

// The collector's unit is a unit the agent accepts by name, and nothing
// about it is reserved.
func TestLinkJournalUnitIsManaged(t *testing.T) {
	if !ValidUnit(LinkJournalUnit) || LinkJournalUnit != "meridian-link-journal.service" {
		t.Fatalf("unit %q", LinkJournalUnit)
	}
	if linkjournal.UpstreamFile != UpstreamStateFile || linkjournal.MaxUpstreamFile != MaxUpstreamFile {
		t.Fatal("the collector and the agent disagree on the upstream record")
	}
	// Every interface the collector may read is a managed interface, and it
	// never reads the remote-access or the Mesh interface.
	for _, i := range []string{"m00", "m05w", "m123"} {
		if !linkjournal.IfaceRe.MatchString(i) || !ValidInterface(i) {
			t.Errorf("%s", i)
		}
	}
	for _, i := range []string{RemoteAccessIface, "mmesh", "eth0", "m1", "m00x"} {
		if linkjournal.IfaceRe.MatchString(i) {
			t.Errorf("the collector would read %s", i)
		}
	}
	for _, u := range []string{"wstunnel-client-gw-access.service"} {
		if !linkjournal.UnitRe.MatchString(u) || !ValidUnit(u) {
			t.Errorf("%s", u)
		}
	}
	for _, u := range []string{"wstunnel-meridian.service", "meridian-failover.service", "meridian.service", "meridian-host.service"} {
		if linkjournal.UnitRe.MatchString(u) {
			t.Errorf("the collector would read %s", u)
		}
	}
}

// The collector's parser of the upstream record and the agent's agree: on
// every record form the gateway writes, and on malformed ones. (The
// collector does not read a relay's measurement fields, so it does not
// check their values: "loss" below is the one case only the agent refuses.)
func TestUpstreamParsersAgree(t *testing.T) {
	good := []string{goodUpstreamRec, rec2,
		strings.Replace(rec2, "state ok", "state degraded", 1),
		strings.Replace(strings.Replace(rec2, "controller go", "controller shell", 1), "alert -", "alert controller_unavailable", 1),
		strings.Replace(goodUpstreamRec, "state ok", "state switching", 1),
		strings.Replace(goodUpstreamRec, "state ok", "state static", 1),
		strings.Replace(goodUpstreamRec, "state ok", "state down", 1),
		"meridian-upstream 1\nstate ok\nsince 1700000050\ntier backup\nhub hkb\niface m02\npath backup\nbeat 1700000100\nend\n",
	}
	for _, text := range good {
		a, errA := ParseUpstream(text)
		c, errC := linkjournal.ParseUpstreamRecord(text)
		if errA != nil || errC != nil {
			t.Fatalf("a good record was refused (agent: %v, collector: %v):\n%s", errA, errC, text)
		}
		if a.Version != c.Version || a.Beat != c.Beat || a.Path != c.Path || a.Iface != c.Iface || a.Hub != c.Hub || a.Tier != c.Tier || a.Since != c.Since || a.State != c.State ||
			a.Controller != c.Controller || a.Alert != c.Alert || a.Switched != c.Switched || a.Designated != c.Designated || len(a.Relays) != len(c.Relays) {
			t.Fatalf("the parsers read different values:\nagent %+v\ncollector %+v", a, c)
		}
		for i, r := range a.Relays {
			x := c.Relays[i]
			if r.ID != x.ID || r.Iface != x.Iface || r.Status != x.Status || r.Weight != x.Weight || r.Reason != x.Reason || r.StatusSince != x.StatusSince || r.Grade != x.Grade {
				t.Fatalf("relay %d: agent %+v collector %+v", i, r, x)
			}
		}
		if (a.Backup == nil) != (c.BackupHub == "") {
			t.Fatalf("backup line: agent %+v collector %q", a.Backup, c.BackupHub)
		}
	}
	bad := map[string]string{
		"unknown state":    strings.Replace(rec2, "state ok", "state great", 1),
		"bad controller":   strings.Replace(rec2, "controller go", "controller panel", 1),
		"weight":           strings.Replace(rec2, "active 500", "active 2000", 1),
		"status":           strings.Replace(rec2, "active 500", "happy 500", 1),
		"extra field":      strings.Replace(rec2, "640136\n", "640136 x\n", 1),
		"missing field":    strings.Replace(rec2, " 640136\n", "\n", 1),
		"duplicate":        strings.Replace(rec2, "relay access2 m03", "relay access m03", 1),
		"no end":           strings.TrimSuffix(rec2, "end\n"),
		"unknown line":     strings.Replace(rec2, "end\n", "exec rm\nend\n", 1),
		"no relays":        strings.Join(strings.Split(rec2, "\n")[:12], "\n") + "\nend\n",
		"since after beat": strings.Replace(rec2, "since 1700000000", "since 1800000000", 1),
		"iface shell":      strings.Replace(rec2, "iface m02", "iface $(id)", 1),
		"alert shape":      strings.Replace(rec2, "alert -", "alert ALL-BAD", 1),
		"relay after bk":   strings.Replace(rec2, "end\n", "relay x m09 active 0 0 - 0 none - - - - 0 0 0 0 0 0 - 0 - - - 0\nend\n", 1),
		"too long":         rec2 + strings.Repeat("x", MaxUpstreamFile),
		"path":             strings.Replace(rec2, "path main", "path udp", 1),
		"v1 header":        strings.Replace(goodUpstreamRec, "meridian-upstream 1", "meridian-upstream 9", 1),
		"v1 extra":         strings.Replace(goodUpstreamRec, "end\n", "x y\nend\n", 1),
		"v1 dup":           strings.Replace(goodUpstreamRec, "hub hkb", "path backup", 1),
		"v1 degraded":      strings.Replace(goodUpstreamRec, "state ok", "state degraded", 1),
		"v1 tier":          strings.Replace(goodUpstreamRec, "tier backup", "tier third", 1),
		"v1 since":         strings.Replace(goodUpstreamRec, "since 1700000050", "since 1900000000", 1),
		"empty":            "",
	}
	for name, text := range bad {
		_, errA := ParseUpstream(text)
		_, errC := linkjournal.ParseUpstreamRecord(text)
		if errA == nil || errC == nil {
			t.Errorf("%s: agent %v, collector %v (both must refuse)", name, errA, errC)
		}
	}
	loss := strings.Replace(rec2, "31000 4 30500", "31000 4000 30500", 1)
	if _, err := ParseUpstream(loss); err == nil {
		t.Error("the agent accepted an out-of-range loss")
	}
}

const goodUpstreamRec = "meridian-upstream 1\nbeat 1700000100\npath backup\niface m02\nhub hkb\ntier backup\nsince 1700000050\nstate ok\nend\n"
