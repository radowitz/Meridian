//go:build !linux

package hostexec

import (
	"errors"
	"net"
)

// peerUID is only implemented on Linux, where the agent runs. Elsewhere a
// configured PeerUID rejects every connection rather than skipping the check.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials unsupported on this platform")
}
