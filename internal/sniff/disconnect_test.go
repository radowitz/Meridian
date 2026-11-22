package sniff

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSniffDisconnectClosesOnlyActiveConnections(t *testing.T) {
	s := &Server{active: make(map[uint64]*activeConn)}
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	ac := s.addActive(ConnRecord{Conn: 1}, client, upstream)
	call := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.StatusHandler().ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	path := "/v1/connections/disconnect"
	if w := call(http.MethodGet, path); w.Code != http.StatusMethodNotAllowed || ac.disconnected.Load() {
		t.Fatal("GET changed the active connection")
	}
	if w := call(http.MethodPost, path+"?id=1"); w.Code != http.StatusBadRequest || ac.disconnected.Load() {
		t.Fatal("unexpected parameter was accepted")
	}
	if w := call(http.MethodPost, path); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"disconnected":1`) {
		t.Fatalf("disconnect: %d %s", w.Code, w.Body.String())
	}
	for _, conn := range []net.Conn{clientPeer, upstreamPeer} {
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("socket remained open: %v", err)
		}
	}
	if got := s.DisconnectActive(); got != 0 {
		t.Fatalf("duplicate disconnect: %d", got)
	}
	laterClient, peer := net.Pipe()
	laterUpstream, upstreamEnd := net.Pipe()
	defer laterClient.Close()
	defer peer.Close()
	defer laterUpstream.Close()
	defer upstreamEnd.Close()
	later := s.addActive(ConnRecord{Conn: 2}, laterClient, laterUpstream)
	if later.disconnected.Load() {
		t.Fatal("newly accepted connections were blocked")
	}
}
