//go:build linux

package pathquality

import (
	"context"
	"net"
	"strconv"
	"syscall"
)

// dialMarked connects from the leg's gateway address to the relay's
// endpoint with the relay's route mark, bound to the leg's interface.
func dialMarked(ctx context.Context, leg Leg, mark uint32, port int) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(leg.Local)},
		Control: func(_, _ string, rc syscall.RawConn) error {
			var serr error
			err := rc.Control(func(fd uintptr) {
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); serr != nil {
					return
				}
				serr = syscall.BindToDevice(int(fd), leg.Iface)
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	return d.DialContext(ctx, "tcp4", net.JoinHostPort(leg.Remote, strconv.Itoa(port)))
}
