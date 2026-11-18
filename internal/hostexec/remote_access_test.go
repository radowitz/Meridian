package hostexec

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// syncRunner scripts the peer sync's commands: the interface, the strip
// output (the config minus wg-quick keys), syncconf and the running peers.
type syncRunner struct {
	mu       sync.Mutex
	cmds     []string
	up       bool
	failSync bool
	peers    string // "wg show mra peers" output
	strip    string
	synced   string // the temp file's content seen by syncconf
}

func (r *syncRunner) Run(_ context.Context, prog string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := prog + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, line)
	switch {
	case prog == "ip" && strings.Join(args, " ") == "-o link show dev mra":
		if !r.up {
			return "", errors.New("exit status 1")
		}
		return "5: mra: <POINTOPOINT,UP>", nil
	case prog == "wg-quick" && strings.Join(args, " ") == "strip mra":
		return r.strip, nil
	case prog == "wg" && len(args) == 3 && args[0] == "syncconf" && args[1] == "mra":
		b, _ := os.ReadFile(args[2])
		r.synced = string(b)
		if fi, err := os.Stat(args[2]); err != nil || fi.Mode().Perm() != 0o600 {
			return "", errors.New("temp file not 0600")
		}
		if r.failSync {
			return "Line unrecognized: `PresharedKey=" + key(9) + "'", errors.New("exit status 1")
		}
		return "", nil
	case prog == "wg" && strings.Join(args, " ") == "show mra peers":
		return r.peers, nil
	}
	return "", errors.New("unexpected command " + line)
}

func key(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func syncRig(t *testing.T, mode os.FileMode) (*Agent, *syncRunner, string, string) {
	t.Helper()
	root := t.TempDir()
	conf := "[Interface]\nPrivateKey = " + key(1) + "\nListenPort = 51999\n\n[Peer]\nPublicKey = " + key(2) +
		"\nPresharedKey = " + key(3) + "\nAllowedIPs = 10.67.0.2/32\n\n[Peer]\nPublicKey = " + key(4) + "\nAllowedIPs = 10.67.0.3/32\n"
	p := filepath.Join(root, "etc", "wireguard", "mra.conf")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(conf), mode); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, mode)
	r := &syncRunner{up: true, strip: conf, peers: key(4) + "\n" + key(2) + "\n"}
	a := &Agent{Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: r, PreflightRoot: root}
	return a, r, conf, root
}

func noSecret(t *testing.T, res Result) {
	t.Helper()
	all := res.Error + strings.Join(res.Warnings, " ")
	for _, s := range res.Steps {
		all += s.Name + s.Detail
	}
	for _, b := range []byte{1, 3, 9} {
		if strings.Contains(all, key(b)) {
			t.Fatalf("secret in result: %s", all)
		}
	}
}

func TestPeerSyncAppliesWithoutRestart(t *testing.T) {
	a, r, conf, root := syncRig(t, 0o600)
	res, code := a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-1/0/fwd", Digest: FileDigest([]byte(conf))})
	if code != 200 || !res.OK {
		t.Fatalf("%d %+v", code, res)
	}
	noSecret(t, res)
	if r.synced != conf {
		t.Fatal("syncconf did not get the stripped config")
	}
	for _, c := range r.cmds {
		if strings.HasPrefix(c, "systemctl") || strings.Contains(c, "down") || strings.HasPrefix(c, "wg-quick up") {
			t.Fatalf("interface restarted: %s", c)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(root, "etc", "wireguard"))
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
	// Same transaction, same digest: replayed, not rerun.
	n := len(r.cmds)
	res, _ = a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-1/0/fwd", Digest: FileDigest([]byte(conf))})
	if !res.Replayed || len(r.cmds) != n {
		t.Fatal("retry reran the sync")
	}
	if _, code := a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-1/0/fwd", Digest: strings.Repeat("0", 64)}); code != http.StatusConflict {
		t.Fatalf("reused transaction with another digest: %d", code)
	}
}

func TestPeerSyncRefusals(t *testing.T) {
	a, r, conf, _ := syncRig(t, 0o644)
	res, _ := a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-2", Digest: FileDigest([]byte(conf))})
	if res.OK || len(r.cmds) != 0 || !strings.Contains(res.Error, "0600") {
		t.Fatalf("0644 config accepted: %+v %v", res, r.cmds)
	}
	a, r, _, _ = syncRig(t, 0o600)
	if res, _ := a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-3", Digest: strings.Repeat("a", 64)}); res.OK || len(r.cmds) != 0 {
		t.Fatalf("digest mismatch accepted: %+v", res)
	}
	for _, bad := range []PeerSyncRequest{{Transaction: "", Digest: strings.Repeat("a", 64)}, {Transaction: "tx;rm", Digest: strings.Repeat("a", 64)}, {Transaction: "tx-4", Digest: "../etc/passwd"}} {
		if _, code := a.PeerSync(context.Background(), bad); code != http.StatusBadRequest {
			t.Fatalf("%+v: %d", bad, code)
		}
	}
	// Interface down: no start, the fast path needs a full install.
	a, r, conf, _ = syncRig(t, 0o600)
	r.up = false
	if res, _ := a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-5", Digest: FileDigest([]byte(conf))}); res.OK {
		t.Fatal("down interface synced")
	}
	// syncconf failure: reported, without the key the tool echoed.
	a, r, conf, _ = syncRig(t, 0o600)
	r.failSync = true
	res, _ = a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-6", Digest: FileDigest([]byte(conf))})
	if res.OK {
		t.Fatal("failed syncconf reported OK")
	}
	noSecret(t, res)
	// Running peers that differ from the file fail the sync.
	a, r, conf, _ = syncRig(t, 0o600)
	r.peers = key(2)
	if res, _ := a.PeerSync(context.Background(), PeerSyncRequest{Transaction: "tx-7", Digest: FileDigest([]byte(conf))}); res.OK {
		t.Fatal("peer mismatch reported OK")
	}
}

// The HTTP endpoint accepts exactly transaction and digest.
func TestPeerSyncRejectsUnknownParams(t *testing.T) {
	a, r, _, _ := syncRig(t, 0o600)
	h := a.Handler()
	for _, body := range []string{
		`{"transaction":"tx-1","digest":"` + strings.Repeat("a", 64) + `","path":"/etc/shadow"}`,
		`{"transaction":"tx-1","digest":"` + strings.Repeat("a", 64) + `","command":"wg-quick down mra"}`,
		`{"transaction":"tx-1","digest":"` + strings.Repeat("a", 64) + `","interface":"m01"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/remote-access/sync", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	if len(r.cmds) != 0 {
		t.Fatalf("commands ran: %v", r.cmds)
	}
}
