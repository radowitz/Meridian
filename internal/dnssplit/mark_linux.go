//go:build linux

package dnssplit

import "syscall"

// markControl puts the exit's fwmark on the upstream socket, as SmartDNS's
// -set-mark does (needs CAP_NET_ADMIN).
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return serr
	}
}
