package hostexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// fakeForwarder answers the forwarder's status socket: /v1/health with the
// rule pair it reports, POST /v1/selfcheck with a result built by check.
type fakeForwarder struct {
	mu       sync.Mutex
	sha      string // reported by /v1/health
	reloadAt *time.Time
	check    func(sha string) (int, any)
	posts    int
}

func startForwarder(t *testing.T, sock string, f *fakeForwarder) {
	t.Helper()
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(sniff.Health{Ready: true, TargetsSHA256: f.sha, LastReloadAt: f.reloadAt})
	})
	mux.HandleFunc("/v1/selfcheck", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		f.mu.Lock()
		f.posts++
		code, body := f.check(f.sha)
		f.mu.Unlock()
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := &http.Server{Handler: mux}
	done := make(chan struct{})
	go func() { _ = srv.Serve(l); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })
}

// result is a self-check of sha with the default target ok or failed and
// another target failed when other is set.
func result(sha string, defaultOK, other bool) *sniff.SelfCheck {
	now := time.Now()
	st := func(ok bool) string {
		if ok {
			return sniff.TargetOK
		}
		return sniff.TargetFailed
	}
	c := &sniff.SelfCheck{Version: sniff.SelfCheckVersion, Trigger: sniff.TriggerRequest, StartedAt: now, FinishedAt: now.Add(40 * time.Millisecond),
		Generation: 3, TargetsSHA256: sha, QName: ".", QType: "NS", Default: "group:hk", OK: defaultOK,
		Targets: []sniff.SelfCheckTarget{
			{Target: "group:hk", Mark: 0x10a, DNSMark: 0x10a, Default: true, Status: st(defaultOK), Reason: map[bool]string{false: "解析器 [fd66::53:a]:53 超时，没有任何回应"}[defaultOK]},
			{Target: "exit:jp", Mark: 0x102, Status: st(!other), Reason: map[bool]string{true: "解析器 [fd66::54:2]:53 超时，没有任何回应"}[other]},
		}}
	return c
}

// sniffRig: an agent whose host root holds a target file and whose
// forwarder socket is served by a fakeForwarder.
func sniffRig(t *testing.T) (*Agent, *fakeHost, *fakeForwarder, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "snc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	root := filepath.Join(dir, "root")
	tf := filepath.Join(root, strings.TrimPrefix(SniffTargets, "/"))
	if err := os.MkdirAll(filepath.Dir(tf), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":1,"targets":[]}` + "\n")
	if err := os.WriteFile(tf, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	f := newFakeHost()
	f.units[SniffUnit], f.units[SniffAccountUnit] = "active", "active"
	a := newAgent(f)
	a.PreflightRoot, a.SniffSocketPath = root, filepath.Join(dir, "s.sock")
	fw := &fakeForwarder{sha: sha, check: func(s string) (int, any) { return 200, result(s, true, false) }}
	startForwarder(t, a.SniffSocketPath, fw)
	return a, f, fw, sha
}

func activateSniff(a *Agent, id string, reload bool) Result {
	r := Resources{Units: []string{SniffUnit}}
	if reload {
		r.Reload = []string{SniffUnit}
	}
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: id, Resources: r})
	return res
}

// activate (start and reload) attaches the forwarder's self-check of the
// pair on disk, without judging it: the action stays OK when the default
// target failed (the transaction decides). A forwarder that reports
// another pair is waited for; one that never loads it, a missing socket or
// a refused request give a report without result and a distinct code.
func TestActivateSniffSelfCheck(t *testing.T) {
	a, _, fw, sha := sniffRig(t)
	res := activateSniff(a, "r1", false)
	c := res.SniffCheck
	if !res.OK || c == nil || c.Result == nil || c.TargetsSHA256 != sha || c.Code != "" {
		t.Fatalf("%+v %+v", res, c)
	}
	if v := EvaluateSniffCheck(c, sha); !v.OK || v.Code != sniff.VerdictOK {
		t.Fatalf("%+v", v)
	}
	if v := EvaluateSniffCheck(c, "other"); v.OK || v.Code != sniff.VerdictStaleGeneration {
		t.Fatalf("other pair accepted: %+v", v)
	}

	fw.mu.Lock()
	fw.check = func(s string) (int, any) { return 200, result(s, false, true) }
	fw.mu.Unlock()
	res = activateSniff(a, "r2", true)
	if !res.OK || res.SniffCheck.Result == nil {
		t.Fatalf("the agent judged the result: %+v", res)
	}
	v := EvaluateSniffCheck(res.SniffCheck, sha)
	if v.OK || v.Code != sniff.VerdictDefaultFailed || !strings.Contains(v.Reason, "group:hk") || len(v.Failing) != 1 {
		t.Fatalf("%+v", v)
	}

	// The forwarder still reports the old pair for a while, then the new.
	fw.mu.Lock()
	fw.sha = "old"
	fw.check = func(s string) (int, any) { return 200, result(s, true, false) }
	fw.mu.Unlock()
	a.SniffSelfCheckWait = 3 * time.Second
	go func() {
		time.Sleep(400 * time.Millisecond)
		fw.mu.Lock()
		fw.sha = sha
		fw.mu.Unlock()
	}()
	res = activateSniff(a, "r3", true)
	if c := res.SniffCheck; c.Result == nil || c.Result.TargetsSHA256 != sha {
		t.Fatalf("did not wait for the new pair: %+v", c)
	}

	// Never loaded: no self-check request, code not_loaded.
	fw.mu.Lock()
	fw.sha, fw.posts = "old", 0
	fw.mu.Unlock()
	a.SniffSelfCheckWait = 300 * time.Millisecond
	res = activateSniff(a, "r4", true)
	if c := res.SniffCheck; c.Result != nil || c.Code != sniff.CheckNotLoaded || fw.posts != 0 {
		t.Fatalf("%+v posts=%d", c, fw.posts)
	}
	if v := EvaluateSniffCheck(res.SniffCheck, sha); v.OK || v.Code != sniff.VerdictTimeout {
		t.Fatalf("%+v", v)
	}

	// The request is refused: no_answer.
	fw.mu.Lock()
	fw.sha = sha
	fw.check = func(string) (int, any) { return 503, "self-check not run" }
	fw.mu.Unlock()
	res = activateSniff(a, "r5", true)
	if c := res.SniffCheck; c.Result != nil || c.Code != sniff.CheckNoAnswer {
		t.Fatalf("%+v", c)
	}

	// No socket at all.
	a.SniffSocketPath = a.SniffSocketPath + ".gone"
	res = activateSniff(a, "r6", true)
	if c := res.SniffCheck; c.Result != nil || c.Code != sniff.CheckNoSocket {
		t.Fatalf("%+v", c)
	}
	if v := EvaluateSniffCheck(res.SniffCheck, sha); v.OK || v.Code != sniff.VerdictUnavailable {
		t.Fatalf("%+v", v)
	}
	if v := EvaluateSniffCheck(nil, sha); v.OK || v.Code != sniff.VerdictUnavailable {
		t.Fatalf("%+v", v)
	}

	// Without the forwarder in the request there is no self-check.
	res, _ = a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "r7", Resources: Resources{Units: []string{"meridian-failover.service"}}})
	if res.SniffCheck != nil {
		t.Fatalf("%+v", res.SniffCheck)
	}
}

// A list publish reloads the forwarder and has it check the reloaded
// rules: nothing when it passes, warnings (never a failure of the publish)
// when the default or another target fails.
func TestReloadSniffSelfCheck(t *testing.T) {
	a, _, fw, _ := sniffRig(t)
	a.init()
	now := time.Now().Add(time.Second)
	fw.reloadAt = &now
	x := &run{a: a, ctx: context.Background()}
	if w := x.reloadSniff(); len(w) != 0 || fw.posts != 1 {
		t.Fatalf("%q posts=%d", w, fw.posts)
	}
	fw.mu.Lock()
	fw.check = func(s string) (int, any) { return 200, result(s, false, true) }
	fw.mu.Unlock()
	w := x.reloadSniff()
	if len(w) != 2 || !strings.Contains(w[0], "默认目标 group:hk") || !strings.Contains(w[1], "exit:jp") {
		t.Fatalf("%q", w)
	}
}

// The status read adds the nft counters and an earlier sniff_denied
// sample; the on-demand self-check takes no parameters.
func TestAgentSniffCountersAndSelfCheckEndpoint(t *testing.T) {
	a, f, _, sha := sniffRig(t)
	f.counters["sniff_denied"] = "packets 12 bytes 1872"
	f.counters["sniff_wg_outer"] = "packets 9000 bytes 1200000"
	st := a.SniffStatus(context.Background())
	if d := st.Counters["sniff_denied"]; !d.Present || d.Packets != 12 || d.Bytes != 1872 || !st.Counters["sniff_wg_outer"].Present || st.DeniedSince != nil || st.TargetsSHA256 != sha {
		t.Fatalf("%+v", st)
	}
	delete(f.counters, "sniff_wg_outer")
	if st := a.SniffStatus(context.Background()); st.Counters["sniff_wg_outer"].Present {
		t.Fatalf("absent counter reported: %+v", st.Counters)
	}

	hs := httptest.NewServer(a.Handler())
	defer hs.Close()
	post := func(body string) (*http.Response, SniffCheckReport) {
		req, _ := http.NewRequest("POST", hs.URL+"/v1/sniff/selfcheck", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var rep SniffCheckReport
		_ = json.NewDecoder(resp.Body).Decode(&rep)
		resp.Body.Close()
		return resp, rep
	}
	if resp, _ := post(`{"target":"group:hk"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("parameters accepted: %d", resp.StatusCode)
	}
	resp, rep := post(`{}`)
	if resp.StatusCode != 200 || rep.Result == nil || rep.TargetsSHA256 != sha {
		t.Fatalf("%d %+v", resp.StatusCode, rep)
	}
}

// The earlier sample: at least 30 s and at most 30 min old; a counter that
// went down (ruleset reloaded) drops the history.
func TestSniffDeniedHistory(t *testing.T) {
	var h sniffHistory
	t0 := time.Unix(1_800_000_000, 0)
	if s := h.note(t0, 5); s != nil {
		t.Fatalf("%+v", s)
	}
	if s := h.note(t0.Add(10*time.Second), 5); s != nil {
		t.Fatalf("too recent: %+v", s)
	}
	if s := h.note(t0.Add(time.Minute), 9); s == nil || s.Packets != 5 || !s.At.Equal(t0) {
		t.Fatalf("%+v", s)
	}
	if s := h.note(t0.Add(40*time.Minute), 9); s != nil {
		t.Fatalf("too old: %+v", s)
	}
	if s := h.note(t0.Add(41*time.Minute), 2); s != nil {
		t.Fatalf("after a reset: %+v", s)
	}
}
