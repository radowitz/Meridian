//go:build !linux

package sniff

import (
	"errors"
	"net"
)

// peerUID is only implemented on Linux, where the forwarder runs; elsewhere
// every status connection is refused.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials unsupported on this platform")
}
