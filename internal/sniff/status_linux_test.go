//go:build linux

package sniff

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// With real SO_PEERCRED: the test process's own uid is answered when it is
// the allowed one and refused otherwise.
func TestStatusPeerCredLinux(t *testing.T) {
	me := os.Getuid()
	for _, c := range []struct {
		name   string
		allow  func(int) bool
		answer bool
	}{
		{"allowed", func(uid int) bool { return uid == me }, true},
		{"not allowed", func(uid int) bool { return uid == me+1 }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sock := filepath.Join(shortDir(t), "status.sock")
			l, err := ListenStatus(sock, c.allow)
			if err != nil {
				t.Fatal(err)
			}
			serveStatus(t, l)
			_, err = statusGet(sock)
			if c.answer != (err == nil) {
				t.Fatalf("answer %v, err %v", c.answer, err)
			}
		})
	}
	// peerUID reads the connecting process's uid.
	sock := filepath.Join(shortDir(t), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- -2
			return
		}
		uid, _ := peerUID(c)
		c.Close()
		got <- uid
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if uid := <-got; uid != me {
		t.Fatalf("peer uid %d, want %d", uid, me)
	}
}
