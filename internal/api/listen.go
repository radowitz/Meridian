package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// DefaultBindWait is how long the panel waits at start for its LAN address
// to appear (MERIDIAN_BIND_WAIT). On a gateway whose LAN NIC is
// "allow-hotplug" + DHCP, Docker starts the container before the lease, and
// binding the LAN address fails with EADDRNOTAVAIL until it is assigned.
const DefaultBindWait = 3 * time.Minute

// bindPoll is the retry interval while the address is not assigned yet;
// bindLogEvery throttles the waiting log line. Variables for tests.
var (
	bindPoll     = time.Second
	bindLogEvery = 10 * time.Second
	listenTCP    = func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
)

// ErrBindNotReady marks the bounded wait for the LAN address running out.
var ErrBindNotReady = errors.New("meridian-bind-not-ready")

// ListenLAN opens the panel's listener on bind, which must be a LAN
// address (CheckBind: never 0.0.0.0 / ::, and there is no fallback to
// them). While the address is not assigned to any interface of this host
// yet ("cannot assign requested address"), it retries every second for at
// most wait, logging one "meridian-bind-waiting" line at the start and then
// every ten seconds, and "meridian-bind-ready" once the listener is open.
// When wait runs out it returns an error wrapping ErrBindNotReady that
// names the address and what to check; any other listen error (address in
// use, permission) is returned at once without retrying.
func ListenLAN(ctx context.Context, bind string, wait time.Duration, logf func(format string, args ...any)) (net.Listener, error) {
	if err := CheckBind(bind); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	start := time.Now()
	deadline := start.Add(wait)
	var lastLog time.Time
	for attempt := 1; ; attempt++ {
		l, err := listenTCP(bind)
		if err == nil {
			if attempt > 1 {
				logf("meridian-bind-ready: %s is assigned now, listening after waiting %s (%d attempts)", bind, time.Since(start).Round(time.Second), attempt)
			}
			return l, nil
		}
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return nil, fmt.Errorf("listen on %s: %w", bind, err)
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, fmt.Errorf("%w: %s is still not assigned to any interface of this host after %s (%v). "+
				"Check the LAN interface and its DHCP lease or static address (ip -br addr), or set MERIDIAN_BIND to the gateway's LAN address; "+
				"the panel never falls back to 0.0.0.0. MERIDIAN_BIND_WAIT sets how long to wait",
				ErrBindNotReady, bind, wait, err)
		}
		if lastLog.IsZero() || time.Since(lastLog) >= bindLogEvery {
			logf("meridian-bind-waiting: %s is not assigned to any interface yet (LAN not up or no DHCP lease); retrying, %s left", bind, left.Round(time.Second))
			lastLog = time.Now()
		}
		pause := bindPoll
		if left < pause {
			pause = left
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("listen on %s: %w", bind, ctx.Err())
		case <-time.After(pause):
		}
	}
}
