package sniff

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/ordered"
)

// fakeResolvers answers the self-check's question per server: "answer",
// "nxdomain", "servfail", "timeout" (nothing until the deadline), "eperm"
// (the kernel refused the send), "refused" (ICMP port unreachable),
// "garbage" (a reply to another question). It records the questions, the
// marks and the most queries in flight at once.
type fakeResolvers struct {
	mu       sync.Mutex
	mode     map[string]string
	connect  map[string]string // "ok", "timeout", "refused"
	asked    []string
	marks    map[string]uint32
	inflight atomic.Int32
	peak     atomic.Int32
}

func newFakeResolvers(mode map[string]string) *fakeResolvers {
	return &fakeResolvers{mode: mode, connect: map[string]string{}, marks: map[string]uint32{}}
}

func (f *fakeResolvers) exchange(ctx context.Context, server string, mark uint32, q []byte) ([]byte, error) {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	f.mu.Lock()
	m := f.mode[server]
	f.asked = append(f.asked, server)
	f.marks[server] = mark
	f.mu.Unlock()
	if len(q) < 17 || q[12] != 0 || binary.BigEndian.Uint16(q[13:]) != selfCheckQType {
		return nil, errors.New("not the self-check question")
	}
	reply := func(rcode byte) []byte {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		r[3] = 0x80 | rcode
		return r
	}
	switch m {
	case "answer":
		return reply(0), nil
	case "nxdomain":
		return reply(3), nil
	case "servfail":
		return reply(2), nil
	case "eperm":
		return nil, &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmsg", syscall.EPERM)}
	case "refused":
		return nil, &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvmsg", syscall.ECONNREFUSED)}
	case "garbage":
		r := reply(0)
		r[14] = 1 // type 1 (A), not NS
		return r, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *fakeResolvers) dial(ctx context.Context, network, addr string, mark uint32) (net.Conn, error) {
	f.mu.Lock()
	m := f.connect[addr]
	f.marks["connect "+addr] = mark
	f.mu.Unlock()
	switch m {
	case "", "ok":
		a, b := net.Pipe()
		b.Close()
		return a, nil
	case "refused":
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func checkServer(t *testing.T, f *fakeResolvers) *Server {
	t.Helper()
	s := New(Config{})
	t.Cleanup(s.Close)
	s.Resolver.Exchange = f.exchange
	s.Dial = f.dial
	s.sc.queryTimeout, s.sc.connectTimeout, s.sc.budget = 150*time.Millisecond, 150*time.Millisecond, 2*time.Second
	rules, tail := fixtureRules()
	if err := s.Install(ordered.Compile(rules, tail, -1), fixtureTargets()); err != nil {
		t.Fatal(err)
	}
	return s
}

func allModes(m string) map[string]string {
	return map[string]string{rsDom: m, rsJP: m, rsHK: m, rsUS: m}
}

func byTarget(c *SelfCheck) map[string]SelfCheckTarget {
	out := map[string]SelfCheckTarget{}
	for _, t := range c.Targets {
		out[t.Target] = t
	}
	return out
}

// Every resolver answers: every target ok, the default (group:hk) also
// connected over TCP with its query mark; the fixed question only; reject
// targets are not checked; the result carries the generation.
func TestSelfCheckAllOK(t *testing.T) {
	f := newFakeResolvers(allModes("answer"))
	s := checkServer(t, f)
	res, err := s.RunSelfCheck(context.Background(), TriggerRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Incomplete || res.Default != "group:hk" || res.QName != "." || res.QType != "NS" || res.Generation != s.Health().Generation || res.Version != SelfCheckVersion {
		t.Fatalf("%+v", res)
	}
	got := byTarget(res)
	if len(got) != 4 || got["reject"].Target != "" {
		t.Fatalf("targets %+v", res.Targets)
	}
	if res.Targets[0].Target != "group:hk" || !res.Targets[0].Default {
		t.Fatalf("default not first: %+v", res.Targets[0])
	}
	for n, x := range got {
		if x.Status != TargetOK || len(x.Resolvers) != 1 || x.Resolvers[0].Outcome != OutcomeAnswer || !x.Resolvers[0].Reached {
			t.Fatalf("%s: %+v", n, x)
		}
		if (x.Connect != nil) != (n == "group:hk") {
			t.Fatalf("%s: connect probe %+v", n, x.Connect)
		}
	}
	if c := got["group:hk"].Connect; c.Outcome != OutcomeConnected || c.Server != rsHK || f.marks["connect "+rsHK] != mHK {
		t.Fatalf("connect %+v mark %#x", c, f.marks["connect "+rsHK])
	}
	if f.marks[rsDom] != mDirect || f.marks[rsJP] != mJP {
		t.Fatalf("query marks %v", f.marks)
	}
	if h := s.Health(); h.SelfCheck == nil || h.SelfCheck.StartedAt != res.StartedAt {
		t.Fatalf("health does not carry the last result: %+v", h.SelfCheck)
	}
	v := EvaluateSelfCheck(res, "", time.Time{}, time.Now())
	if v.Code != VerdictStaleGeneration {
		t.Fatalf("a result without a target file identity was accepted: %+v", v)
	}
}

// Each outcome is classified; any well-formed reply proves the path.
func TestSelfCheckOutcomes(t *testing.T) {
	for mode, want := range map[string]struct {
		outcome string
		ok      bool
	}{
		"answer":   {OutcomeAnswer, true},
		"nxdomain": {OutcomeNXDomain, true},
		"servfail": {OutcomeRcode, true},
		"timeout":  {OutcomeTimeout, false},
		"eperm":    {OutcomeSendRefused, false},
		"refused":  {OutcomeRefused, false},
		"garbage":  {OutcomeMalformed, false},
	} {
		t.Run(mode, func(t *testing.T) {
			s := checkServer(t, newFakeResolvers(allModes(mode)))
			res, _ := s.RunSelfCheck(context.Background(), TriggerRequest)
			x := byTarget(res)["group:us"]
			if x.Resolvers[0].Outcome != want.outcome || x.Resolvers[0].Reached != want.ok || (x.Status == TargetOK) != want.ok || res.OK != want.ok {
				t.Fatalf("%+v ok=%v", x, res.OK)
			}
			if !want.ok && (x.Reason == "" || !strings.Contains(x.Reason, rsUS)) {
				t.Fatalf("no reason naming the resolver: %q", x.Reason)
			}
		})
	}
}

// Mixed: another target failing is a warning; the default failing (DNS or
// the TCP probe) fails the result; the verdict says which.
func TestSelfCheckMixedTargets(t *testing.T) {
	f := newFakeResolvers(map[string]string{rsDom: "answer", rsJP: "timeout", rsHK: "answer", rsUS: "eperm"})
	s := checkServer(t, f)
	res, _ := s.RunSelfCheck(context.Background(), TriggerRequest)
	if !res.OK || len(res.Failing()) != 2 {
		t.Fatalf("%+v", res)
	}
	now := time.Now()
	res.TargetsSHA256 = "abc"
	v := EvaluateSelfCheck(res, "ABC", now.Add(-time.Minute), now)
	if !v.OK || v.Code != VerdictOK || len(v.Failing) != 2 || !strings.Contains(strings.Join(v.Failing, "|"), "exit:jp") {
		t.Fatalf("%+v", v)
	}

	f = newFakeResolvers(map[string]string{rsDom: "answer", rsJP: "answer", rsHK: "timeout", rsUS: "answer"})
	s = checkServer(t, f)
	res, _ = s.RunSelfCheck(context.Background(), TriggerRequest)
	res.TargetsSHA256 = "abc"
	v = EvaluateSelfCheck(res, "abc", time.Time{}, time.Now())
	if res.OK || v.OK || v.Code != VerdictDefaultFailed || !strings.Contains(v.Reason, "group:hk") || !strings.Contains(v.Reason, "超时") {
		t.Fatalf("%+v / %+v", res, v)
	}

	f = newFakeResolvers(allModes("answer"))
	f.connect[rsHK] = "timeout"
	s = checkServer(t, f)
	res, _ = s.RunSelfCheck(context.Background(), TriggerRequest)
	d := res.DefaultResult()
	if res.OK || d.Status != TargetFailed || d.Connect.Outcome != OutcomeTimeout || !strings.Contains(d.Reason, "TCP") {
		t.Fatalf("connect probe: %+v", d)
	}
}

// The run is bounded: every query hanging ends within the query timeout;
// a budget shorter than the work leaves probes "not_run" (incomplete), and
// a default target not reached is a failure; concurrency is capped.
func TestSelfCheckBounded(t *testing.T) {
	f := newFakeResolvers(allModes("timeout"))
	s := checkServer(t, f)
	start := time.Now()
	res, _ := s.RunSelfCheck(context.Background(), TriggerRequest)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("hanging resolvers took %v", el)
	}
	if res.OK || res.Incomplete {
		t.Fatalf("%+v", res)
	}
	if d := res.DefaultResult(); d.Resolvers[0].DurationMS < 100 {
		t.Fatalf("a timed-out probe reports %d ms", d.Resolvers[0].DurationMS)
	}

	var ts []Target
	modes := map[string]string{}
	rules := []ordered.Rule{}
	for i := 0; i < 40; i++ {
		srv := "[fd66::53:" + hex.EncodeToString([]byte{byte(i)}) + "]:53"
		name := "group:g" + hex.EncodeToString([]byte{byte(i)})
		mark := uint32(0x200 + i)
		ts = append(ts, Target{Name: name, Mark: mark, Resolvers: []string{srv}})
		rules = append(rules, ordered.Rule{ID: name, Target: name, Mark: mark, Entries: []ordered.Entry{sfx(name[6:] + ".example.net")}})
		modes[srv] = "timeout"
	}
	f = newFakeResolvers(modes)
	s = New(Config{})
	t.Cleanup(s.Close)
	s.Resolver.Exchange, s.Dial = f.exchange, f.dial
	s.sc.queryTimeout, s.sc.connectTimeout, s.sc.budget = 100*time.Millisecond, 100*time.Millisecond, 250*time.Millisecond
	if err := s.Install(ordered.Compile(rules, ordered.Tail{DirectTarget: "group:g00", DirectMark: 0x200, Default: "group:g00", DefaultMark: 0x200}, -1), ts); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	res, _ = s.RunSelfCheck(context.Background(), TriggerRequest)
	if el := time.Since(start); el > 2*time.Second { // budget 250 ms; without it 40 resolvers / 8 at a time × 2 × 100 ms ≥ 1 s per round, many rounds
		t.Fatalf("budget not kept: %v", el)
	}
	if !res.Incomplete || res.OK || f.peak.Load() > SelfCheckConcurrency {
		t.Fatalf("incomplete=%v ok=%v peak=%d", res.Incomplete, res.OK, f.peak.Load())
	}
	notRun := 0
	for _, x := range res.Targets {
		if x.Resolvers[0].Outcome == OutcomeNotRun {
			notRun++
		}
	}
	if notRun == 0 {
		t.Fatal("no probe reported as not run")
	}
}

// A target without resolvers is unchecked, not failed; an unchecked default
// is a note, not a failure.
func TestSelfCheckUnchecked(t *testing.T) {
	f := newFakeResolvers(allModes("answer"))
	s := New(Config{})
	t.Cleanup(s.Close)
	s.Resolver.Exchange, s.Dial = f.exchange, f.dial
	rules, tail := fixtureRules()
	ts := fixtureTargets()
	ts[2].Resolvers = nil // group:hk, the default
	if err := s.Install(ordered.Compile(rules, tail, -1), ts); err != nil {
		t.Fatal(err)
	}
	res, _ := s.RunSelfCheck(context.Background(), TriggerRequest)
	d := res.DefaultResult()
	if !res.OK || d.Status != TargetUnchecked || d.Connect != nil {
		t.Fatalf("%+v", d)
	}
	res.TargetsSHA256 = "x"
	if v := EvaluateSelfCheck(res, "x", time.Time{}, time.Now()); !v.OK || len(v.Notes) == 0 {
		t.Fatalf("%+v", v)
	}
}

// writePair writes the verify fixture's rule pair (targets with extra bytes
// when variant is set, a different file with the same targets) and returns
// the config and the target file's hash.
func writePair(t *testing.T, d string, variant string) (Config, string) {
	t.Helper()
	snap, targets := VerifyFixture()
	targets = append(targets, []byte(variant)...)
	cfg := Config{SnapshotPath: filepath.Join(d, "decide.json"), TargetsPath: filepath.Join(d, "targets.json"), ListsDir: d}
	if err := os.WriteFile(cfg.SnapshotPath, snap, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.TargetsPath, targets, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(targets)
	return cfg, hex.EncodeToString(sum[:])
}

// Generation tagging and reload: a result names the target file it ran
// against; after a reload to a new pair the background re-run (as SIGHUP
// triggers it) carries the new identity, and the old result is refused as
// evidence for the new pair; stale and pre-request results are refused.
func TestSelfCheckGenerationAndReload(t *testing.T) {
	d := t.TempDir()
	cfg, sha1 := writePair(t, d, "")
	s := New(cfg)
	t.Cleanup(s.Close)
	s.Resolver.Exchange = func(ctx context.Context, server string, mark uint32, q []byte) ([]byte, error) {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		return r, nil
	}
	s.Dial = func(ctx context.Context, network, addr string, mark uint32) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Health().TargetsSHA256 != sha1 {
		t.Fatalf("health %q, want %q", s.Health().TargetsSHA256, sha1)
	}
	asked := time.Now()
	first, err := s.RunSelfCheck(context.Background(), TriggerRequest)
	if err != nil || first.TargetsSHA256 != sha1 {
		t.Fatalf("%v %+v", err, first)
	}
	if v := EvaluateSelfCheck(first, sha1, asked, time.Now()); !v.OK {
		t.Fatalf("%+v", v)
	}
	// A new pair (the target file changes), reload, background re-run.
	_, sha2 := writePair(t, d, "\n")
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	s.TriggerSelfCheck(TriggerReload)
	s.TriggerSelfCheck(TriggerReload) // merged with the pending one
	deadline := time.Now().Add(3 * time.Second)
	var got *SelfCheck
	for time.Now().Before(deadline) {
		if got = s.LastSelfCheck(); got != nil && got.TargetsSHA256 == sha2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got == nil || got.TargetsSHA256 != sha2 || got.Trigger != TriggerReload || got.Generation <= first.Generation {
		t.Fatalf("no re-run after the reload: %+v", got)
	}
	if v := EvaluateSelfCheck(first, sha2, time.Time{}, time.Now()); v.OK || v.Code != VerdictStaleGeneration {
		t.Fatalf("the old generation's result was accepted: %+v", v)
	}
	if v := EvaluateSelfCheck(got, sha2, time.Now().Add(time.Minute), time.Now()); v.OK || v.Code != VerdictStale {
		t.Fatalf("a result from before the request was accepted: %+v", v)
	}
	if v := EvaluateSelfCheck(got, sha2, time.Time{}, time.Now().Add(SelfCheckMaxAge+time.Minute)); v.OK || v.Code != VerdictStale {
		t.Fatalf("an old result was accepted: %+v", v)
	}
	if v := EvaluateSelfCheck(nil, sha2, time.Time{}, time.Now()); v.OK || v.Code != VerdictUnavailable {
		t.Fatalf("%+v", v)
	}
}

// POST /v1/selfcheck runs it and answers the result; nothing else is
// accepted on that path.
func TestSelfCheckEndpoint(t *testing.T) {
	s := checkServer(t, newFakeResolvers(allModes("nxdomain")))
	srv := httptest.NewServer(s.StatusHandler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/selfcheck", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var res SelfCheck
	err = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !res.OK || res.Trigger != TriggerRequest {
		t.Fatalf("%d %v %+v", resp.StatusCode, err, res)
	}
	if r, _ := http.Get(srv.URL + "/v1/selfcheck"); r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", r.StatusCode)
	}
	if r, _ := http.Post(srv.URL+"/v1/selfcheck", "application/json", strings.NewReader(`{"targets":["x"]}`)); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("parameters accepted: %d", r.StatusCode)
	}
	if r, _ := http.Post(srv.URL+"/v1/selfcheck?target=x", "", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("query accepted: %d", r.StatusCode)
	}
}

// Per-target counters: totals and the recent window, failures with when and
// what; targets that leave the target file are dropped.
func TestTargetStats(t *testing.T) {
	s := checkServer(t, newFakeResolvers(allModes("answer")))
	now := time.Now()
	old := now.Add(-time.Hour)
	for _, r := range []ConnRecord{
		{Start: now, Target: "group:hk", Sniffed: true},
		{Start: now, Target: "group:hk", Sniffed: true, Error: "timeout"},
		{Start: old, Target: "group:hk", Sniffed: true},
		{Start: now, Target: "direct", Sniffed: true},
	} {
		res := "ok"
		if r.Error != "" {
			res = "resolve_failed"
		}
		s.Now = nil
		if r.Start.Equal(old) {
			// Finished an hour ago: counted in that minute, not recently.
			res = "dial_failed"
			s.Now = func() time.Time { return old }
		}
		s.finish(&r, res)
	}
	s.Now = nil
	got := map[string]TargetStat{}
	for _, x := range s.Health().TargetStats {
		got[x.Target] = x
	}
	hk := got["group:hk"]
	if hk.OK != 1 || hk.ResolveFailed != 1 || hk.DialFailed != 1 || hk.RecentOK != 1 || hk.RecentResolveFailed != 1 || hk.RecentDialFailed != 0 || hk.LastFailureAt == nil || hk.LastFailure != "resolve_failed timeout" {
		t.Fatalf("%+v", hk)
	}
	if got["direct"].RecentOK != 1 || s.Health().StatsWindowS != 900 {
		t.Fatalf("%+v", got["direct"])
	}
	rules, tail := fixtureRules()
	ts := fixtureTargets()
	ts[0].Name = "domestic" // "direct" leaves the file
	rules[5].Target, tail.DirectTarget = "domestic", "domestic"
	if err := s.Install(ordered.Compile(rules, tail, -1), ts); err != nil {
		t.Fatal(err)
	}
	for _, x := range s.Health().TargetStats {
		if x.Target == "direct" {
			t.Fatal("a target that left the file kept its counters")
		}
	}
}

// A resolver that stays silent is reported per resolver (outcome,
// duration, timeout used); once it is known silent the next run re-checks
// it with SelfCheckRecheckTimeout instead of the full query timeout, so a
// periodic run no longer waits the full timeout because of it; the result
// carries the per-resolver health record. An answer clears it.
func TestSelfCheckKnownSilentResolver(t *testing.T) {
	f := newFakeResolvers(map[string]string{rsDom: "timeout", rsJP: "answer", rsHK: "answer", rsUS: "answer"})
	s := checkServer(t, f)
	s.sc.queryTimeout, s.sc.recheckTimeout = time.Second, 40*time.Millisecond
	res, _ := s.RunSelfCheck(context.Background(), TriggerStart)
	p := byTarget(res)["direct"].Resolvers[0]
	if p.Outcome != OutcomeTimeout || p.KnownSilent || p.TimeoutMS != 1000 || p.Transport != "udp" || p.DurationMS < 950 {
		t.Fatalf("first run: %+v", p)
	}
	var h *ResolverHealth
	for i := range res.ResolverHealth {
		if res.ResolverHealth[i].Server == rsDom {
			h = &res.ResolverHealth[i]
		}
	}
	if h == nil || h.LastOutcome != OutcomeTimeout || h.Source != "selfcheck" || h.DemotedUntil.IsZero() {
		t.Fatalf("health %+v", res.ResolverHealth)
	}
	start := time.Now()
	res, _ = s.RunSelfCheck(context.Background(), TriggerPeriodic)
	if el := time.Since(start); el >= 900*time.Millisecond { // the full query timeout is 1 s
		t.Fatalf("periodic run waited %v for a known-silent resolver", el)
	}
	p = byTarget(res)["direct"].Resolvers[0]
	if p.Outcome != OutcomeTimeout || !p.KnownSilent || p.TimeoutMS != 40 {
		t.Fatalf("second run: %+v", p)
	}
	f.mu.Lock()
	f.mode[rsDom] = "answer"
	f.mu.Unlock()
	res, _ = s.RunSelfCheck(context.Background(), TriggerPeriodic)
	if p = byTarget(res)["direct"].Resolvers[0]; !p.Reached || s.Resolver.demoted(rsDom, mDirect) {
		t.Fatalf("answer did not clear it: %+v", p)
	}
}
