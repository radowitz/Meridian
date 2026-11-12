package hostexec

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func wgKey(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(b), 32)))
}

func TestParseWGOutputs(t *testing.T) {
	a, b := wgKey('a'), wgKey('b')
	hs, err := ParseLatestHandshakes(a + "\t1731400000\n" + b + "\t0\n")
	if err != nil || hs[a] != 1731400000 || hs[b] != 0 || len(hs) != 2 {
		t.Fatalf("%v %v", hs, err)
	}
	tr, err := ParseTransfer(a + "\t100\t200\n\n")
	if err != nil || tr[a] != [2]int64{100, 200} {
		t.Fatalf("%v %v", tr, err)
	}
	for _, bad := range []string{"notakey\t1\n", a + "\tx\n", a + "\t-1\n", a + "\t1\t2\n"} {
		if _, err := ParseLatestHandshakes(bad); err == nil {
			t.Errorf("handshakes accepted %q", bad)
		}
	}
	for _, bad := range []string{a + "\t1\n", a + "\t1\tz\n", "private\t1\t2\n"} {
		if _, err := ParseTransfer(bad); err == nil {
			t.Errorf("transfer accepted %q", bad)
		}
	}
}

func TestRemoteAccessStatusRunsOnlyFixedReads(t *testing.T) {
	a, b := wgKey('a'), wgKey('b')
	var mu sync.Mutex
	var cmds []string
	present := true
	r := runnerFunc(func(_ context.Context, prog string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		line := prog + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		switch line {
		case "ip -o link show dev mra":
			if !present {
				return "Device \"mra\" does not exist.", errors.New("exit status 1")
			}
			return "9: mra: <POINTOPOINT,NOARP,UP>", nil
		case "wg show mra latest-handshakes":
			return b + "\t0\n" + a + "\t1731400000\n", nil
		case "wg show mra transfer":
			return a + "\t10\t20\n" + b + "\t0\t0\n", nil
		}
		return "", errors.New("unexpected " + line)
	})
	ag := &Agent{Token: func() (string, error) { return strings.Repeat("t", 64), nil }, Runner: r}
	st := ag.RemoteAccessStatus(context.Background())
	if !st.Present || st.Error != "" || len(st.Peers) != 2 || st.Peers[0].PublicKey != a || st.Peers[0].LatestHandshake != 1731400000 || st.Peers[0].RxBytes != 10 || st.Peers[0].TxBytes != 20 || st.Peers[1].LatestHandshake != 0 {
		t.Fatalf("%+v", st)
	}
	for _, c := range cmds {
		if strings.Contains(c, "dump") || strings.Contains(c, "private") || strings.Contains(c, "preshared") {
			t.Fatalf("ran %q", c)
		}
	}
	present = false
	st = ag.RemoteAccessStatus(context.Background())
	if st.Present || st.Error != "" || len(st.Peers) != 0 {
		t.Fatalf("absent: %+v", st)
	}

	// Over the socket: token required, no parameters accepted.
	sock := shortSocket(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	go ag.Serve(l)
	t.Cleanup(func() { l.Close() })
	hc := unixHTTP(sock)
	post := func(tok, body string) int {
		req, _ := http.NewRequest(http.MethodPost, "http://x/v1/remote-access/status", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good := strings.Repeat("t", 64)
	n := len(cmds)
	if c := post("wrong", `{}`); c != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", c)
	}
	if c := post(good, `{"interface":"wg0"}`); c != http.StatusBadRequest {
		t.Fatalf("parameter accepted: %d", c)
	}
	if len(cmds) != n {
		t.Fatal("refused request ran commands")
	}
	if c := post(good, `{}`); c != http.StatusOK {
		t.Fatalf("good: %d", c)
	}
	cl := &Client{Socket: sock, TokenFile: writeTokenFile(t, good)}
	if _, err := cl.RemoteAccessStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Client{Socket: sock + ".missing", TokenFile: "/nonexistent"}).RemoteAccessStatus(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
}

func writeTokenFile(t *testing.T, tok string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
