package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func withListen(t *testing.T, f func(addr string) (net.Listener, error)) {
	t.Helper()
	oldL, oldP, oldE := listenTCP, bindPoll, bindLogEvery
	listenTCP, bindPoll, bindLogEvery = f, time.Millisecond, 0
	t.Cleanup(func() { listenTCP, bindPoll, bindLogEvery = oldL, oldP, oldE })
}

func notAvail(addr string) error {
	return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRNOTAVAIL)}
}

// The LAN address appears after a few attempts (DHCP lease at boot): the
// panel waits, logs that it waits, and then listens — no crash, no restart.
func TestListenLANWaitsForAddress(t *testing.T) {
	calls := 0
	withListen(t, func(addr string) (net.Listener, error) {
		calls++
		if calls < 4 {
			return nil, notAvail(addr)
		}
		return net.Listen("tcp", "127.0.0.1:0")
	})
	var logs []string
	l, err := ListenLAN(context.Background(), "192.0.2.10:8787", time.Minute, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	joined := strings.Join(logs, "\n")
	if calls != 4 || !strings.Contains(joined, "meridian-bind-waiting: 192.0.2.10:8787") || !strings.Contains(joined, "meridian-bind-ready") {
		t.Fatalf("calls=%d logs:\n%s", calls, joined)
	}
}

// The wait is bounded and ends with a clear, named failure.
func TestListenLANTimesOutClearly(t *testing.T) {
	withListen(t, func(addr string) (net.Listener, error) { return nil, notAvail(addr) })
	_, err := ListenLAN(context.Background(), "192.0.2.10:8787", 20*time.Millisecond, nil)
	if !errors.Is(err, ErrBindNotReady) || !strings.Contains(err.Error(), "192.0.2.10:8787") || !strings.Contains(err.Error(), "never falls back to 0.0.0.0") {
		t.Fatalf("%v", err)
	}
}

// Other listen errors are not a "LAN not ready" situation: no waiting.
func TestListenLANOtherErrorsFailAtOnce(t *testing.T) {
	calls := 0
	withListen(t, func(addr string) (net.Listener, error) {
		calls++
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	})
	_, err := ListenLAN(context.Background(), "192.0.2.10:8787", time.Minute, nil)
	if err == nil || errors.Is(err, ErrBindNotReady) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

// "LAN only" stays: a wildcard address is refused before any listen.
func TestListenLANRefusesWildcard(t *testing.T) {
	withListen(t, func(addr string) (net.Listener, error) {
		t.Fatalf("listened on %s", addr)
		return nil, nil
	})
	t.Setenv("MERIDIAN_ALLOW_ANY_BIND", "")
	for _, b := range []string{"0.0.0.0:8787", ":8787", "[::]:8787"} {
		if _, err := ListenLAN(context.Background(), b, time.Minute, nil); err == nil {
			t.Fatalf("%s accepted", b)
		}
	}
}

// Against the real network stack: an address of TEST-NET-1 is not assigned
// to this machine, so the kernel answers EADDRNOTAVAIL and the wait runs out.
func TestListenLANRealUnassignedAddress(t *testing.T) {
	old := bindPoll
	bindPoll = 5 * time.Millisecond
	t.Cleanup(func() { bindPoll = old })
	l, err := ListenLAN(context.Background(), "192.0.2.123:0", 30*time.Millisecond, nil)
	if err == nil {
		l.Close()
		t.Skip("this machine has 192.0.2.123 assigned")
	}
	if !errors.Is(err, ErrBindNotReady) {
		t.Skipf("kernel did not answer EADDRNOTAVAIL here: %v", err)
	}
}
