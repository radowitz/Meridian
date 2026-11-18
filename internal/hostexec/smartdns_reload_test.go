package hostexec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// answeringResolver answers every question (QR bit, same ID).
func answeringResolver(_ context.Context, _ string, _ uint32, q []byte) ([]byte, error) {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	return r, nil
}

// waitDNSReload waits until no SmartDNS restart is scheduled or running.
func waitDNSReload(t *testing.T, a *Agent) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r := &a.dnsReload
		r.mu.Lock()
		idle := !r.running && r.timer == nil && !r.st.Pending
		r.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("SmartDNS restart still pending")
}

func geoReq(id string) ListsRequest {
	return ListsRequest{RequestID: id, Policy: "domestic", Lists: []string{"geosite"}, Geosite: []string{"cn"}}
}

// Same content again: the geosite file is rewritten but its digest equals
// what SmartDNS loaded, so nothing restarts.
func TestDNSReloadNoChangeNoRestart(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	if _, code := a.UpdateLists(context.Background(), geoReq("n1")); code != http.StatusOK {
		t.Fatal(code)
	}
	waitDNSReload(t, a)
	if f.ran("systemctl restart smartdns.service") != 1 {
		t.Fatalf("first publication: %v", f.commands())
	}
	rep, _ := a.UpdateLists(context.Background(), geoReq("n2"))
	waitDNSReload(t, a)
	if !rep.DNSChanged || f.ran("systemctl restart smartdns.service") != 1 {
		t.Fatalf("restarted for identical files: %+v %v", rep, f.commands())
	}
	st, _ := a.ListsStatus()
	if st.DNSReload == nil || st.DNSReload.Last == nil || !st.DNSReload.Last.OK || st.DNSReload.Last.Target != "smartdns.service" || st.DNSReload.LoadedDigest == "" {
		t.Fatalf("%+v", st.DNSReload)
	}
}

// Several publications inside the window are one restart.
func TestDNSReloadMergesChanges(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	a.DNSReloadWindow = 300 * time.Millisecond
	a.init()
	for _, body := range []string{"a.com\n", "b.com\n", "c.com\n"} {
		os.MkdirAll(filepath.Join(a.ListsDir, "geosite"), 0o755)
		os.WriteFile(filepath.Join(a.ListsDir, "geosite", "x.txt"), []byte(body), 0o644)
		a.requestDNSReload(false)
	}
	waitDNSReload(t, a)
	if f.ran("systemctl restart smartdns.service") != 1 {
		t.Fatalf("%v", f.commands())
	}
	if l := a.dnsReloadStatus().Last; l == nil || l.Merged != 3 || !l.OK {
		t.Fatalf("%+v", l)
	}
}

// Inside the minimum gap a change is deferred to the gap's end, once, and
// is not lost.
func TestDNSReloadRateLimitDefersOnce(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	a.DNSReloadMinGap = 400 * time.Millisecond
	a.init()
	write := func(body string) {
		os.MkdirAll(filepath.Join(a.ListsDir, "keywords"), 0o755)
		os.WriteFile(filepath.Join(a.ListsDir, "keywords", "r.txt"), []byte(body), 0o644)
	}
	write("a\n")
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	first := a.dnsReloadStatus().Last.At
	write("b\n")
	a.requestDNSReload(false)
	write("c\n")
	a.requestDNSReload(false)
	st := a.dnsReloadStatus()
	if !st.Pending || st.DueAt.Sub(first) < 390*time.Millisecond {
		t.Fatalf("not deferred to the gap: %+v (first %v)", st, first)
	}
	time.Sleep(100 * time.Millisecond)
	if f.ran("systemctl restart smartdns.service") != 1 {
		t.Fatalf("ran inside the gap: %v", f.commands())
	}
	waitDNSReload(t, a)
	l := a.dnsReloadStatus().Last
	if f.ran("systemctl restart smartdns.service") != 2 || l.Merged != 2 || l.At.Sub(first) < 390*time.Millisecond {
		t.Fatalf("%+v %v", l, f.commands())
	}
}

// A failed restart and a resolver that never answers are recorded with
// their reason; the digest is not taken as loaded.
func TestDNSReloadFailureSurfaced(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	a.init()
	os.MkdirAll(filepath.Join(a.ListsDir, "geosite"), 0o755)
	os.WriteFile(filepath.Join(a.ListsDir, "geosite", "x.txt"), []byte("a\n"), 0o644)
	f.mu.Lock()
	f.fail["systemctl restart smartdns.service"] = true
	f.mu.Unlock()
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	st, _ := a.ListsStatus()
	if l := st.DNSReload.Last; l == nil || l.OK || !strings.Contains(l.Error, "重启 smartdns.service 失败") || st.DNSReload.LoadedDigest != "" {
		t.Fatalf("%+v", st.DNSReload)
	}

	f.mu.Lock()
	delete(f.fail, "systemctl restart smartdns.service")
	f.mu.Unlock()
	var asked atomic.Int32
	a.DNSCheckExchange = func(context.Context, string, uint32, []byte) ([]byte, error) {
		asked.Add(1)
		return nil, errors.New("connection refused")
	}
	a.DNSLivenessWait = 400 * time.Millisecond
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	l := a.dnsReloadStatus().Last
	if l.OK || !strings.Contains(l.Error, "没有应答") || asked.Load() < 2 {
		t.Fatalf("%+v asked %d", l, asked.Load())
	}

	// Answering again: the next request succeeds and reports durations.
	a.DNSCheckExchange = answeringResolver
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	if l := a.dnsReloadStatus().Last; !l.OK || l.Error != "" || l.AnswerMS < l.RestartMS {
		t.Fatalf("%+v", l)
	}
}

// A restart that was pending when the agent stopped runs after it starts.
func TestDNSReloadPendingSurvivesAgentRestart(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	os.MkdirAll(filepath.Join(a.ListsDir, "lists"), 0o755)
	os.WriteFile(filepath.Join(a.ListsDir, "lists", dnsReloadFile), []byte(`{"loaded_digest":"x","pending":true}`), 0o644)
	if st, _ := a.ListsStatus(); st.DNSReload == nil {
		t.Fatal("no state")
	}
	waitDNSReload(t, a)
	if f.ran("systemctl restart smartdns.service") != 1 {
		t.Fatalf("%v", f.commands())
	}
}

// A restart pending when the previous agent exited runs once the new agent
// serves, without anyone asking for the status; serving twice does not
// schedule it twice.
func TestDNSReloadPendingResumedOnStart(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	os.MkdirAll(filepath.Join(a.ListsDir, "lists"), 0o755)
	os.WriteFile(filepath.Join(a.ListsDir, "lists", dnsReloadFile), []byte(`{"loaded_digest":"x","pending":true}`), 0o644)
	_ = a.Handler()
	_ = a.Handler()
	deadline := time.Now().Add(5 * time.Second)
	for f.ran("systemctl restart smartdns.service") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	r := &a.dnsReload
	for time.Now().Before(deadline) {
		r.mu.Lock()
		idle := !r.running && r.timer == nil
		r.mu.Unlock()
		if idle {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := f.ran("systemctl restart smartdns.service"); n != 1 {
		t.Fatalf("restarts=%d %v", n, f.commands())
	}
	b, _ := os.ReadFile(filepath.Join(a.ListsDir, "lists", dnsReloadFile))
	if strings.Contains(string(b), `"pending": true`) {
		t.Fatalf("still pending: %s", b)
	}
}

// writeDNSFile writes one SmartDNS file under the lists directory.
func writeDNSFile(t *testing.T, a *Agent, rel, body string) {
	t.Helper()
	p := filepath.Join(a.ListsDir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ageDNSFiles moves the modification times of the lists directory's
// SmartDNS files and directories d into the past.
func ageDNSFiles(t *testing.T, a *Agent, d time.Duration) {
	t.Helper()
	old := time.Now().Add(-d)
	for _, sub := range []string{"geosite", "keywords"} {
		filepath.WalkDir(filepath.Join(a.ListsDir, sub), func(p string, _ os.DirEntry, err error) error {
			if err == nil {
				os.Chtimes(p, old, old)
			}
			return nil
		})
	}
}

func smartdnsRestarts(f *fakeHost) int { return f.ran("systemctl restart smartdns.service") }

func loadedDigest(a *Agent) string {
	if st := a.dnsReloadStatus(); st != nil {
		return st.LoadedDigest
	}
	return ""
}

func writeConf(t *testing.T, a *Agent, split bool) {
	t.Helper()
	conf := "server 127.0.0.1\n"
	if split {
		conf = "server 223.5.5.5 -group domestic -exclude-default-group\nserver 127.0.0.1:5356 -group unlisted_split\n"
	}
	if a.SmartDNSConf == "" {
		a.SmartDNSConf = filepath.Join(t.TempDir(), "smartdns.conf")
	}
	if err := os.WriteFile(a.SmartDNSConf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The first publication rewrites the files SmartDNS demonstrably loaded
// (it started after their last change, before the agent looked): the
// start baseline holds, nothing restarts, and the baseline is recorded.
func TestDNSReloadStartBaselineIdenticalFirstPublication(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	writeDNSFile(t, a, "geosite/cn.txt", "baidu.com\n")
	ageDNSFiles(t, a, time.Hour)
	f.started = fmt.Sprintf("@%d", time.Now().Add(-10*time.Minute).Unix())
	a.init()
	want, _ := dnsFilesDigest(a.ListsDir)
	rep, _ := a.UpdateLists(context.Background(), geoReq("b1"))
	waitDNSReload(t, a)
	if !rep.DNSChanged || smartdnsRestarts(f) != 0 {
		t.Fatalf("identical first publication restarted: %+v %v", rep, f.commands())
	}
	if got := loadedDigest(a); got != want {
		t.Fatalf("baseline %q, want %q", got, want)
	}
	// A real change afterwards restarts.
	writeDNSFile(t, a, "keywords/k.txt", "x\n")
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	if smartdnsRestarts(f) != 1 {
		t.Fatalf("%v", f.commands())
	}
}

// SmartDNS started before the files' last change, or its start is
// unknown: the baseline is undeterminable, one conservative restart, then
// identical publications restart nothing.
func TestDNSReloadUnknownBaselineRestartsOnce(t *testing.T) {
	for name, started := range map[string]string{"unknown": "", "older than files": fmt.Sprintf("@%d", time.Now().Add(-2*time.Hour).Unix())} {
		t.Run(name, func(t *testing.T) {
			f, a := listsAgent(t, listsMux(""))
			writeDNSFile(t, a, "geosite/cn.txt", "baidu.com\n")
			ageDNSFiles(t, a, time.Hour)
			f.started = started
			a.init()
			a.UpdateLists(context.Background(), geoReq("u1"))
			waitDNSReload(t, a)
			a.UpdateLists(context.Background(), geoReq("u2"))
			waitDNSReload(t, a)
			if smartdnsRestarts(f) != 1 || loadedDigest(a) == "" {
				t.Fatalf("restarts %d digest %q: %v", smartdnsRestarts(f), loadedDigest(a), f.commands())
			}
		})
	}
}

// Auto re-read loads A, an install restarts SmartDNS on B, the lists go
// back to A: SmartDNS runs B, so A restarts it again.
func TestDNSReloadInstallRestartRecordsLoaded(t *testing.T) {
	for _, dns := range []string{"unit", "container"} {
		t.Run(dns, func(t *testing.T) {
			f, a := listsAgent(t, listsMux(""))
			f.dns = dns
			restarts := func() int {
				if dns == "unit" {
					return smartdnsRestarts(f)
				}
				return f.ran("docker restart " + SmartDNSContainer)
			}
			a.init()
			writeDNSFile(t, a, "geosite/x.txt", "a\n")
			a.requestDNSReload(false)
			waitDNSReload(t, a)
			digestA := loadedDigest(a)
			writeDNSFile(t, a, "geosite/x.txt", "b\n")
			res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "i1", Resources: Resources{DNS: true}})
			digestB, _ := dnsFilesDigest(a.ListsDir)
			if !res.OK || restarts() != 2 || loadedDigest(a) != digestB || digestA == digestB {
				t.Fatalf("install: %+v restarts %d loaded %q B %q", res, restarts(), loadedDigest(a), digestB)
			}
			writeDNSFile(t, a, "geosite/x.txt", "a\n")
			a.requestDNSReload(false)
			waitDNSReload(t, a)
			if restarts() != 3 || loadedDigest(a) != digestA {
				t.Fatalf("back to A: restarts %d %v", restarts(), f.commands())
			}
			// The install's own restart already loaded what is there now.
			a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "i2", Resources: Resources{DNS: true}})
			a.requestDNSReload(false)
			waitDNSReload(t, a)
			if restarts() != 4 {
				t.Fatalf("after install with current files: restarts %d", restarts())
			}
		})
	}
}

// An install (or a rollback/restore, which reinstalls) restarts SmartDNS
// on new files while the re-read waits for the lock: the re-read reads
// the baseline under the lock and finds nothing left to do.
func TestDNSReloadBaselineReadUnderLock(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	a.LockWait = 5 * time.Second
	a.init()
	writeDNSFile(t, a, "geosite/x.txt", "a\n")
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	a.sem <- struct{}{} // an install is running
	writeDNSFile(t, a, "geosite/x.txt", "b\n")
	a.requestDNSReload(false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := &a.dnsReload
		r.mu.Lock()
		running := r.running
		r.mu.Unlock()
		if running || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	// The install restarts SmartDNS on B and records it (as activate does).
	d, _ := dnsFilesDigest(a.ListsDir)
	a.dnsSetLoaded(d)
	<-a.sem
	waitDNSReload(t, a)
	if smartdnsRestarts(f) != 1 {
		t.Fatalf("re-read used a stale baseline: %v", f.commands())
	}
}

// No resolver, a failed install restart or no answer never advance the
// loaded digest.
func TestDNSReloadDigestNotAdvancedWithoutAnswer(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	f.dns = ""
	a.init()
	writeDNSFile(t, a, "geosite/x.txt", "a\n")
	a.requestDNSReload(false)
	waitDNSReload(t, a)
	if l := a.dnsReloadStatus().Last; l == nil || !l.OK || loadedDigest(a) != "" {
		t.Fatalf("no resolver: %+v %q", l, loadedDigest(a))
	}
	f.dns = "unit"
	a.DNSCheckExchange = func(context.Context, string, uint32, []byte) ([]byte, error) { return nil, errors.New("refused") }
	a.DNSLivenessWait = 300 * time.Millisecond
	res, _ := a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "n1", Resources: Resources{DNS: true}})
	if !res.OK || len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "名单读入未确认") || loadedDigest(a) != "" {
		t.Fatalf("no answer after install: %+v %q", res, loadedDigest(a))
	}
	a.DNSCheckExchange = answeringResolver
	f.mu.Lock()
	f.fail["systemctl restart smartdns.service"] = true
	f.mu.Unlock()
	res, _ = a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "n2", Resources: Resources{DNS: true}})
	if res.OK || loadedDigest(a) != "" {
		t.Fatalf("failed install restart: %+v %q", res, loadedDigest(a))
	}
}

// Loaded A, then a restart on B whose answer check times out (SmartDNS may
// still have come up on B), then the lists go back to A: the old digest A
// must not survive the unconfirmed restart, so A restarts again. Covers the
// install path and the automatic re-read path.
func TestDNSReloadUnconfirmedRestartForgetsOldDigest(t *testing.T) {
	refuse := func(context.Context, string, uint32, []byte) ([]byte, error) { return nil, errors.New("timeout") }
	for _, path := range []string{"install", "reread"} {
		t.Run(path, func(t *testing.T) {
			f, a := listsAgent(t, listsMux(""))
			a.DNSLivenessWait = 300 * time.Millisecond
			a.init()
			writeDNSFile(t, a, "geosite/x.txt", "a\n")
			a.requestDNSReload(false)
			waitDNSReload(t, a)
			digestA := loadedDigest(a)
			if digestA == "" || smartdnsRestarts(f) != 1 {
				t.Fatalf("setup: loaded %q restarts %d", digestA, smartdnsRestarts(f))
			}
			writeDNSFile(t, a, "geosite/x.txt", "b\n")
			a.DNSCheckExchange = refuse
			if path == "install" {
				a.Execute(context.Background(), Request{Action: ActionActivate, RequestID: "u1", Resources: Resources{DNS: true}})
			} else {
				a.requestDNSReload(false)
				waitDNSReload(t, a)
			}
			if smartdnsRestarts(f) != 2 || loadedDigest(a) == digestA {
				t.Fatalf("unconfirmed restart kept old digest: restarts %d loaded %q", smartdnsRestarts(f), loadedDigest(a))
			}
			a.DNSCheckExchange = answeringResolver
			writeDNSFile(t, a, "geosite/x.txt", "a\n")
			a.requestDNSReload(false)
			waitDNSReload(t, a)
			if smartdnsRestarts(f) != 3 || loadedDigest(a) != digestA {
				t.Fatalf("back to A skipped: restarts %d loaded %q %v", smartdnsRestarts(f), loadedDigest(a), f.commands())
			}
		})
	}
}

// A publication waiting for its restart and the needs it carries survive
// an agent restart: the record keeps cause, split and reason.
func TestDNSReloadPersistsSplitNeed(t *testing.T) {
	_, a := listsAgent(t, listsMux(""))
	a.DNSReloadWindow = time.Hour
	a.init()
	a.requestDNSReload(true)
	a.requestDNSReload(false) // merging keeps the need
	b, _ := os.ReadFile(a.dnsReloadPath())
	for _, want := range []string{`"pending": true`, `"cause": "lists"`, `"split": true`, splitReasonChnroute} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %s: %s", want, b)
		}
	}
	a.dnsReload.mu.Lock()
	a.dnsReload.timer.Stop()
	a.dnsReload.mu.Unlock()
}

// resumed builds a restarted agent on a saved pending record.
func resumed(t *testing.T, record string, split bool) (*fakeHost, *Agent) {
	t.Helper()
	f, a := listsAgent(t, listsMux(""))
	writeConf(t, a, split)
	writeDNSFile(t, a, "geosite/x.txt", "a\n")
	d, _ := dnsFilesDigest(a.ListsDir)
	writeDNSFile(t, a, "lists/"+dnsReloadFile, strings.ReplaceAll(record, "$D", d))
	_ = a.Handler()
	waitDNSReload(t, a)
	return f, a
}

// dns-split not in use: a resumed restart with a split need restarts
// SmartDNS only; in use: dns-split first, then SmartDNS, even with an
// unchanged domain-set digest.
func TestDNSReloadResumeSplitFollowsConfig(t *testing.T) {
	rec := `{"loaded_digest":"x","pending":true,"cause":"lists","split":true,"split_reason":"r"}`
	f, a := resumed(t, rec, false)
	if smartdnsRestarts(f) != 1 || f.ran("systemctl restart "+DNSSplitUnit) != 0 || !a.dnsReloadStatus().Last.OK {
		t.Fatalf("not enabled: %v", f.commands())
	}
	f, _ = resumed(t, `{"loaded_digest":"$D","pending":true,"cause":"lists","split":true,"split_reason":"r"}`, true)
	indexOrder(t, f.commands(), "systemctl restart "+DNSSplitUnit, "systemctl restart smartdns.service")
	if smartdnsRestarts(f) != 1 || f.ran("systemctl restart "+DNSSplitUnit) != 1 {
		t.Fatalf("enabled: %v", f.commands())
	}
	// Equal digest, split need but not in use: nothing to do.
	f, _ = resumed(t, `{"loaded_digest":"$D","pending":true,"cause":"lists","split":true}`, false)
	if smartdnsRestarts(f) != 0 || f.ran("systemctl restart "+DNSSplitUnit) != 0 {
		t.Fatalf("nothing to do: %v", f.commands())
	}
}

// A record of an older agent (no cause, no split field): SmartDNS once,
// dns-split only when the config uses it.
func TestDNSReloadLegacyRecord(t *testing.T) {
	for _, split := range []bool{false, true} {
		f, _ := resumed(t, `{"loaded_digest":"$D","pending":true}`, split)
		want := map[bool]int{false: 0, true: 1}[split]
		if smartdnsRestarts(f) != 1 || f.ran("systemctl restart "+DNSSplitUnit) != want {
			t.Fatalf("split=%v: %v", split, f.commands())
		}
	}
}

// The config switches dns-split on while a chnroute restart waits: the
// config in force when it runs decides.
func TestDNSReloadSplitEnabledWhileWaiting(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	writeConf(t, a, false)
	a.DNSReloadWindow = 200 * time.Millisecond
	a.init()
	writeDNSFile(t, a, "geosite/x.txt", "a\n")
	a.requestDNSReload(true)
	writeConf(t, a, true)
	waitDNSReload(t, a)
	indexOrder(t, f.commands(), "systemctl restart "+DNSSplitUnit, "systemctl restart smartdns.service")
	if f.ran("systemctl restart "+DNSSplitUnit) != 1 {
		t.Fatalf("%v", f.commands())
	}
}

// dns-split fails: SmartDNS is still restarted and loads the files; the
// result is failed with the dns-split reason (kept through the status),
// and no further restart is scheduled for it. With SmartDNS failing too,
// both reasons are kept and nothing is taken as loaded.
func TestDNSReloadSplitFailureStillRestartsSmartDNS(t *testing.T) {
	f, a := listsAgent(t, listsMux(""))
	writeConf(t, a, true)
	a.init()
	f.mu.Lock()
	f.fail["systemctl restart "+DNSSplitUnit] = true
	f.mu.Unlock()
	writeDNSFile(t, a, "geosite/x.txt", "a\n")
	a.requestDNSReload(true)
	waitDNSReload(t, a)
	d, _ := dnsFilesDigest(a.ListsDir)
	st, _ := a.ListsStatus()
	l := st.DNSReload.Last
	if smartdnsRestarts(f) != 1 || l.OK || !l.SmartDNSOK || l.SplitRestarted || !strings.Contains(l.Error, DNSSplitUnit) ||
		!strings.Contains(l.SplitError, DNSSplitUnit) || st.DNSReload.LoadedDigest != d || st.DNSReload.Pending {
		t.Fatalf("%+v %+v %v", st.DNSReload, l, f.commands())
	}
	time.Sleep(50 * time.Millisecond)
	if smartdnsRestarts(f) != 1 || f.ran("systemctl restart "+DNSSplitUnit) != 1 {
		t.Fatalf("restarted again for the failure: %v", f.commands())
	}

	f.mu.Lock()
	f.fail["systemctl restart smartdns.service"] = true
	f.mu.Unlock()
	writeDNSFile(t, a, "geosite/x.txt", "b\n")
	a.requestDNSReload(true)
	waitDNSReload(t, a)
	l = a.dnsReloadStatus().Last
	if l.OK || l.SmartDNSOK || !strings.Contains(l.Error, DNSSplitUnit) || !strings.Contains(l.Error, "重启 smartdns.service 失败") || loadedDigest(a) != "" {
		// A failed restart may still have started SmartDNS on b: the old digest is forgotten.
		t.Fatalf("%+v", l)
	}
}
