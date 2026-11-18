//go:build !linux

package pathquality

import (
	"context"
	"errors"
	"net"
)

// dialMarked needs SO_MARK and SO_BINDTODEVICE (Linux): elsewhere every
// test is "not measured".
func dialMarked(context.Context, Leg, uint32, int) (net.Conn, error) {
	return nil, errors.New("speed test: marked dial needs Linux")
}
