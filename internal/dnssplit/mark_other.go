//go:build !linux

package dnssplit

import (
	"errors"
	"syscall"
)

// markControl: fwmarks exist only on Linux; a marked exit fails here.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(string, string, syscall.RawConn) error { return errors.New("fwmark needs Linux") }
}
