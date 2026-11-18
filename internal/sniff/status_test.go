package sniff

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortDir: Unix socket paths are limited to about 100 bytes; t.TempDir()
// can be longer on some systems.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "snst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// statusGet asks the socket for /v1/health; refused peers see the
// connection closed without an answer.
func statusGet(sock string) (int, error) {
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
	resp, err := hc.Get("http://s/v1/health")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// serveStatus serves a forwarder's status handler on l until the test ends.
func serveStatus(t *testing.T, l net.Listener) {
	t.Helper()
	s := New(DefaultConfig())
	srv := &http.Server{Handler: s.StatusHandler(), ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { _ = srv.Serve(l); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })
}

// The peer check decides who is answered: the allowed uid gets the status,
// anyone else a closed connection; a peer whose credentials cannot be read
// is refused (fail closed). The socket file is 0666 (reachable through the
// "other" bits by a root without CAP_DAC_OVERRIDE).
func TestStatusPeerCheck(t *testing.T) {
	for _, c := range []struct {
		name   string
		peer   func(net.Conn) (int, error)
		answer bool
	}{
		{"root", func(net.Conn) (int, error) { return 0, nil }, true},
		{"other user", func(net.Conn) (int, error) { return 1000, nil }, false},
		{"the forwarder's own uid", func(net.Conn) (int, error) { return 65530, nil }, false},
		{"unknown", func(net.Conn) (int, error) { return -1, errors.New("no credentials") }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sock := filepath.Join(shortDir(t), "status.sock")
			l, err := ListenStatus(sock, StatusRootOnly)
			if err != nil {
				t.Fatal(err)
			}
			if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != StatusSocketMode || fi.Mode()&os.ModeSocket == 0 {
				t.Fatalf("socket mode %v %v", fi.Mode(), err)
			}
			l.Peer = c.peer
			serveStatus(t, l)
			code, err := statusGet(sock)
			if c.answer && (err != nil || code != http.StatusServiceUnavailable) { // not ready: 503 with a body
				t.Fatalf("allowed peer: %d %v", code, err)
			}
			if !c.answer && err == nil {
				t.Fatalf("refused peer got HTTP %d", code)
			}
			if !c.answer && l.Refused.Load() == 0 {
				t.Fatal("refusal not counted")
			}
		})
	}
}

// A stale socket file is replaced; anything else at the path is refused.
func TestListenStatusReplacesOnlySockets(t *testing.T) {
	d := shortDir(t)
	sock := filepath.Join(d, "status.sock")
	l, err := ListenStatus(sock, StatusRootOnly)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := os.Lstat(sock); err != nil {
		// Go removes the file on Close for listeners it created; recreate a
		// stale one.
		raw, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		raw.(*net.UnixListener).SetUnlinkOnClose(false)
		raw.Close()
	}
	l2, err := ListenStatus(sock, StatusRootOnly)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l2.Close()
	file := filepath.Join(d, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenStatus(file, StatusRootOnly); err == nil {
		t.Fatal("a regular file was replaced")
	}
}

// The rule pair the real-systemd verification starts the forwarder with
// loads and installs like a compiled one.
func TestVerifyFixtureLoads(t *testing.T) {
	d := t.TempDir()
	snap, targets := VerifyFixture()
	cfg := Config{SnapshotPath: filepath.Join(d, "decide.json"), TargetsPath: filepath.Join(d, "targets.json"), ListsDir: d}
	if err := os.WriteFile(cfg.SnapshotPath, snap, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.TargetsPath, targets, 0o644); err != nil {
		t.Fatal(err)
	}
	c, ts, err := LoadFiles(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(cfg).Install(c, ts); err != nil {
		t.Fatal(err)
	}
}
