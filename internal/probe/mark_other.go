//go:build !linux

package probe

import (
	"fmt"
	"syscall"
)

// markControl refuses every socket: without SO_MARK the connection would
// follow the default route, which is exactly what a pinned probe must not do.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return fmt.Errorf("%w：fwmark %#x 只能在 Linux 网关上设置", ErrEgress, mark)
	}
}
