package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/unlock"
)

// jpServer binds exit jp to a managed server and returns its id.
func jpServer(t *testing.T, s *Server) (*credentials.Store, string) {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/ssh-credentials", mustJSON(map[string]any{"name": "pw", "kind": "password", "password": "pw-synthetic-1"}))
	var c struct{ Credential credView }
	decode(t, rr, &c)
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	sv, err := cs.CreateServer(credentials.ServerInput{Name: "jp 机器", Address: "198.51.100.20", Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: c.Credential.ID})
	if err != nil {
		t.Fatal(err)
	}
	setNode(t, s, "jp", func(n *model.Node) { n.ServerID = sv.ID })
	return cs, sv.ID
}

func recordJP(t *testing.T, s *Server) {
	t.Helper()
	s.mu.Lock()
	s.recordResults(stampItems(s, item("youtube-premium", "jp", unlock.FamilyIPv4, probe.CatUnlocked, 50, time.Now().UTC())))
	s.mu.Unlock()
	if _, regions, _ := s.matrixNow(); recOf(t, regions, "youtube-premium") == nil || recOf(t, regions, "youtube-premium").ExitID != "jp" {
		t.Fatal("setup: jp not recommended")
	}
}

// The panel's snapshot recommends jp; then the managed server's address is
// replaced (in the store, without the identity notification patchServer
// sends); then 采用 → 409 and nothing changes: adopt reads the servers
// itself, under the lock that serialises server edits.
func TestAdoptServerAddressReplacedAfterSnapshot(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	addChatGPTRule(t, s)
	cs, sid := jpServer(t, s)
	recordJP(t, s)
	addr := "198.51.100.21"
	if _, err := cs.UpdateServer(sid, credentials.ServerPatch{Address: &addr}); err != nil {
		t.Fatal(err)
	}
	before := mustTopo(t, s)
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp"}`)); rr.Code != http.StatusConflict {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	if canonJSON(mustTopo(t, s)) != canonJSON(before) {
		t.Fatal("refused adopt changed the topology")
	}
}

// Inside 采用, once the servers are read, a server edit cannot proceed
// (patchServer needs resMu) until the rules are written: the servers adopt
// checked are the ones in force at the write. Deterministic: TryLock.
func TestAdoptHoldsServerLock(t *testing.T) {
	s := probeServer(t, &fakeProber{})
	addChatGPTRule(t, s)
	jpServer(t, s)
	recordJP(t, s)
	ran := false
	adoptLockedHook = func(s *Server) {
		ran = true
		if s.resMu.TryLock() {
			s.resMu.Unlock()
			t.Error("server edits are not excluded during adopt")
		}
	}
	defer func() { adoptLockedHook = nil }()
	if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp"}`)); rr.Code != http.StatusOK {
		t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
	}
	if !ran {
		t.Fatal("hook not run")
	}
	// After adopt: an address edit through the API goes through.
	if rr := do(s, http.MethodPatch, "/api/servers/"+mustTopo(t, s).Nodes[nodeIndex(mustTopo(t, s), "jp")].ServerID, []byte(`{"address":"198.51.100.22"}`)); rr.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
}

// Only the link's wg_port (overriding the node's listen_port) or only the
// exit's wan_interface changes: the digest changes, the cell is 未测 and
// 采用 is refused without changes.
func TestIdentityEffectiveEgressFields(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server){
		"wg_port": func(t *testing.T, s *Server) {
			if _, err := s.Store.Update(func(tp *model.Topology) (bool, error) {
				for i := range tp.Links {
					l := &tp.Links[i]
					if l.Enabled && (l.From == "jp" || l.To == "jp") {
						l.WGPort = 40123
						return true, nil
					}
				}
				t.Fatal("no link to jp")
				return false, nil
			}); err != nil {
				t.Fatal(err)
			}
		},
		"wan_interface": func(t *testing.T, s *Server) {
			setNode(t, s, "jp", func(n *model.Node) { n.WANInterface = "ens5" })
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := probeServer(t, &fakeProber{})
			addChatGPTRule(t, s)
			old := exitIdentities(mustTopo(t, s), nil)["jp"]
			recordJP(t, s)
			change(t, s)
			if exitIdentities(mustTopo(t, s), nil)["jp"] == old {
				t.Fatal("digest unchanged")
			}
			_, regions, _ := s.matrixNow()
			if c := cellAt(t, regions, "youtube-premium", "jp"); c.State != cellUntested {
				t.Fatalf("cell: %+v", c)
			}
			before := mustTopo(t, s)
			if rr := do(s, http.MethodPost, "/api/unlock/adopt", []byte(`{"service":"youtube-premium","exit":"jp"}`)); rr.Code != http.StatusConflict {
				t.Fatalf("adopt: %d %s", rr.Code, rr.Body.String())
			}
			if canonJSON(mustTopo(t, s)) != canonJSON(before) {
				t.Fatal("refused adopt changed the topology")
			}
		})
	}
}
