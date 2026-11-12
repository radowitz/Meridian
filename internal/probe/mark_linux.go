//go:build linux

package probe

import (
	"fmt"
	"syscall"
)

// markControl sets SO_MARK before connect (needs CAP_NET_ADMIN). A socket
// whose mark cannot be set is not used: it would follow the main table.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("%w：设置 SO_MARK %#x 失败：%v", ErrEgress, mark, serr)
		}
		return nil
	}
}
