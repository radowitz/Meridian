package sniff

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
)

// The status socket (GET /v1/health, GET /v1/recent) and who may read it.
//
// The reader is the host agent (meridian-host.service): root, but with
// CapabilityBoundingSet=CAP_NET_ADMIN only, so without CAP_DAC_OVERRIDE or
// CAP_DAC_READ_SEARCH it is subject to the ordinary permission bits of a
// directory and a socket that belong to the forwarder's account. It gets in
// through the "other" bits: the runtime directory is 0755 (unit:
// RuntimeDirectoryMode=0755) and the socket 0666. Who is answered is then
// decided here, by the peer's credentials at connect time (SO_PEERCRED):
// only uid 0. Every other local user can open a connection, which is closed
// at once without a byte read or written. A group-based design was rejected:
// the agent starts at boot long before the forwarder's account (and its
// group) exists, and systemd refuses SupplementaryGroups= / User= entries it
// cannot resolve, as it refused the forwarder's User= on a real host.

// StatusRootOnly answers uid 0 only (the host agent).
func StatusRootOnly(uid int) bool { return uid == 0 }

// StatusSocketMode is the socket's mode: connectable by every local user;
// the peer check decides who is answered.
const StatusSocketMode = 0o666

// ListenStatus opens the status socket (replacing a stale socket file) and
// returns a listener that hands out only connections whose peer uid passes
// allow; the others are closed unanswered.
func ListenStatus(path string, allow func(uid int) bool) (*PeerListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, StatusSocketMode); err != nil {
		l.Close()
		return nil, err
	}
	return &PeerListener{Listener: l, Allow: allow, Peer: peerUID}, nil
}

// PeerListener filters accepted Unix connections by the peer's uid.
type PeerListener struct {
	net.Listener
	Allow func(uid int) bool
	// Peer returns the peer's uid (SO_PEERCRED on Linux; elsewhere an
	// error, which refuses the connection).
	Peer func(net.Conn) (int, error)
	// Refused counts closed connections.
	Refused atomic.Uint64
}

// Accept returns the next connection whose peer is allowed.
func (l *PeerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := l.Peer(c)
		if err == nil && l.Allow != nil && l.Allow(uid) {
			return c, nil
		}
		l.Refused.Add(1)
		c.Close()
	}
}
