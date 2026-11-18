package api

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

func setNode(t *testing.T, s *Server, id string, f func(n *model.Node)) {
	t.Helper()
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		for i := range tp.Nodes {
			if tp.Nodes[i].ID == id {
				f(&tp.Nodes[i])
			}
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func cellAt(t *testing.T, regions []matrixRegion, svc, exit string) matrixCell {
	t.Helper()
	for _, reg := range regions {
		for _, sv := range reg.Services {
			if sv.ID != svc {
				continue
			}
			for _, c := range sv.Cells {
				if c.ExitID == exit {
					return c
				}
			}
		}
	}
	t.Fatalf("no cell %s/%s", svc, exit)
	return matrixCell{}
}

func addChatGPTRule(t *testing.T, s *Server) {
	t.Helper()
	if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
		tp.Rules = append(tp.Rules, model.Rule{ID: "u-chatgpt", Name: "chatgpt", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "youtube.com", TargetGroup: "us"})
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Same exit ID, replaced target: the old result is 未测, the recommendation
// is gone and 采用 is refused without touching rules or groups.
func TestIdentityReplacedTargetVoidsResult(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	addChatGPTRule(t, s)
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 50, now)))
	s.mu.Unlock()
	_, regions, _ := s.matrixNow()
	if r := recOf(t, regions, "youtube-premium"); r == nil || r.ExitID != "jp" {
		t.Fatalf("setup recommendation: %+v", r)
	}
	setNode(t, s, "jp", func(n *model.Node) { n.EndpointV4 = "198.51.100.77" })
	_, regions, _ = s.matrixNow()
	if c := cellAt(t, regions, "youtube-premium", "jp"); c.State != cellUntested {
		t.Fatalf("cell after replacement: %+v", c)
	}
	if r := recOf(t, regions, "youtube-premium"); r != nil {
		t.Fatalf("recommendation survived: %+v", r)
	}
	before := mustTopo(t, s)
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp"}`)); rr.Code != http.StatusConflict {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp","preview":true}`)); rr.Code != http.StatusConflict {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
	}
	if canonJSON(mustTopo(t, s)) != canonJSON(before) {
		t.Fatal("refused adopt changed the topology")
	}
}

func nodeIndex(t model.Topology, id string) int {
	for i, n := range t.Nodes {
		if n.ID == id {
			return i
		}
	}
	return -1
}

// A result stored before digests existed is 未测.
func TestIdentityMissingDigestIsUntested(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults([]probeJobItem{item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 50, now)})
	s.mu.Unlock()
	_, regions, _ := s.matrixNow()
	if c := cellAt(t, regions, "youtube-premium", "jp"); c.State != cellUntested {
		t.Fatalf("cell: %+v", c)
	}
	if r := recOf(t, regions, "youtube-premium"); r != nil {
		t.Fatalf("recommended: %+v", r)
	}
}

// Display fields do not change the digest; the server address, the peer
// public key and an external exit's SOCKS target and carrier do. Private
// keys never count.
func TestIdentityFields(t *testing.T) {
	tp := defaults.ExternalExample()
	base := exitIdentities(tp, nil)
	if base["myext"] == "" {
		t.Fatal("external exit has no identity")
	}
	mut := func(f func(tp *model.Topology)) map[string]string {
		c := defaults.ExternalExample()
		f(&c)
		return exitIdentities(c, nil)
	}
	node := func(c *model.Topology, id string) *model.Node { return &c.Nodes[nodeIndex(*c, id)] }
	same := []func(*model.Topology){
		func(c *model.Topology) { node(c, "myext").Name = "改名" },
		func(c *model.Topology) { node(c, "myext").X, node(c, "myext").Y = 1, 2 },
		func(c *model.Topology) { node(c, "myext").PrivateKey = "secret" },
		func(c *model.Topology) { node(c, "myext").External.CredentialID = "other" },
	}
	for i, f := range same {
		if mut(f)["myext"] != base["myext"] {
			t.Fatalf("display/secret change %d changed the digest", i)
		}
	}
	diff := []func(*model.Topology){
		func(c *model.Topology) { node(c, "myext").External.SOCKSAddress = "198.51.100.67" },
		func(c *model.Topology) { node(c, "myext").External.SOCKSPort = 1081 },
		func(c *model.Topology) { node(c, node(c, "myext").External.Carrier).EndpointV4 = "198.51.100.9" },
		func(c *model.Topology) { node(c, node(c, "myext").External.Carrier).PublicKey = "otherkey=" },
	}
	for i, f := range diff {
		if mut(f)["myext"] == base["myext"] {
			t.Fatalf("identity change %d kept the digest", i)
		}
	}
	ex := defaults.Example()
	id := exitIdentities(ex, nil)["jp"]
	sv := map[string]model.Server{"s1": {ID: "s1", Address: "198.51.100.1", Port: 22}}
	ex.Nodes[nodeIndex(ex, "jp")].ServerID = "s1"
	a := exitIdentities(ex, sv)["jp"]
	sv["s1"] = model.Server{ID: "s1", Address: "198.51.100.2", Port: 22}
	if b := exitIdentities(ex, sv)["jp"]; a == id || a == b {
		t.Fatal("server address not in the digest")
	}
}

// A rename keeps the result and 采用 works.
func TestIdentityRenameKeepsResult(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	addChatGPTRule(t, s)
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 50, now)))
	s.mu.Unlock()
	setNode(t, s, "jp", func(n *model.Node) { n.Name = "东京新名字" })
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp"}`)); rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
}

// The target changes during the run and is changed back before it ends:
// the run's results stay without a digest (未测) and are not ingested.
func TestIdentityChangedDuringRun(t *testing.T) {
	f := &fakeProber{}
	s := probeServer(t, f)
	orig := mustTopo(t, s).Nodes[nodeIndex(mustTopo(t, s), "jp")].EndpointV4
	var once sync.Once
	f.onProbe = func(req hostexec.ProbeRequest) {
		if req.ExitID != "jp" {
			return
		}
		once.Do(func() {
			setNode(t, s, "jp", func(n *model.Node) { n.EndpointV4 = "198.51.100.77" })
			setNode(t, s, "jp", func(n *model.Node) { n.EndpointV4 = orig })
		})
	}
	job := runJob(t, s, `{"services":["youtube-premium"],"exits":["jp","us"],"families":["ipv4"]}`)
	saw := false
	for _, it := range job.Items {
		if it.ExitID == "jp" && it.State == itemDone {
			saw = true
			if it.Identity != "" || (len(it.Owners) > 0 && it.Ingest != "not_ingested:exit_changed") {
				t.Fatalf("changed exit item: %+v", it)
			}
		}
		if it.ExitID == "us" && it.State == itemDone && it.Identity == "" {
			t.Fatalf("untouched exit lost its digest: %+v", it)
		}
	}
	if !saw {
		t.Fatalf("jp not probed: %+v", job.Items)
	}
	_, regions, _ := s.matrixNow()
	if c := cellAt(t, regions, "youtube-premium", "jp"); c.State != cellUntested {
		t.Fatalf("jp cell: %+v", c)
	}
	if c := cellAt(t, regions, "youtube-premium", "us"); c.State == cellUntested {
		t.Fatalf("us cell: %+v", c)
	}
}

// An older job that finishes late does not replace a newer job's result.
func TestIdentityOlderJobDoesNotOverwrite(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	now := time.Now().UTC()
	newer := stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatNotUnlocked, 50, now))[0]
	newer.Seq = 200
	older := stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 50, now))[0]
	older.Seq = 100
	s.mu.Lock()
	s.recordResults([]probeJobItem{newer})
	s.recordResults([]probeJobItem{older})
	got := s.loadResults().Items[resultKey(newer)]
	s.mu.Unlock()
	if got.Seq != 200 || got.Category != probe.CatNotUnlocked {
		t.Fatalf("older job overwrote: %+v", got)
	}
}
