//go:build !linux

package sniff

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

var errLinux = errors.New("needs Linux")

// markControl: fwmarks exist only on Linux; a marked socket fails here, so
// nothing ever leaves unmarked by accident. Mark 0 is allowed (tests).
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(string, string, syscall.RawConn) error { return errLinux }
}

// SocketMark needs Linux.
func SocketMark(net.Conn) (uint32, error) { return 0, errLinux }

// OrigDstRedirect needs Linux (conntrack).
func OrigDstRedirect(net.Conn) (netip.AddrPort, error) { return netip.AddrPort{}, errLinux }

func transparentControl(string, string, syscall.RawConn) error { return errLinux }

func neighDump() ([]Neighbor, error) { return nil, errLinux }

func ifIndex(string) (int, error) { return 0, errLinux }
