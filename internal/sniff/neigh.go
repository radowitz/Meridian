package sniff

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Neighbor is one kernel neighbour entry (ARP / NDP).
type Neighbor struct {
	Addr    netip.Addr
	MAC     string // ordered.NormMAC form
	Ifindex int
	State   uint16
}

// Neighbour states (linux/neighbour.h).
const (
	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudDelay      = 0x08
	nudProbe      = 0x10
	nudFailed     = 0x20
	nudNoARP      = 0x40
	nudPermanent  = 0x80
	// usable: the kernel holds a link-layer address it uses (or used) for
	// this neighbour.
	nudUsable = nudReachable | nudStale | nudDelay | nudProbe | nudPermanent

	ndaDst    = 1
	ndaLLAddr = 2
)

// parseNeighMsg reads an RTM_NEWNEIGH body: struct ndmsg (12 bytes:
// family, pad, pad16, ifindex int32, state u16, flags u8, type u8) and
// rtattrs (4-byte aligned).
func parseNeighMsg(b []byte) (Neighbor, bool) {
	if len(b) < 12 {
		return Neighbor{}, false
	}
	n := Neighbor{Ifindex: int(int32(binary.NativeEndian.Uint32(b[4:]))), State: binary.NativeEndian.Uint16(b[8:])}
	var ll []byte
	for i := 12; i+4 <= len(b); {
		l := int(binary.NativeEndian.Uint16(b[i:]))
		typ := binary.NativeEndian.Uint16(b[i+2:]) & 0x3fff
		if l < 4 || i+l > len(b) {
			return Neighbor{}, false
		}
		v := b[i+4 : i+l]
		switch typ {
		case ndaDst:
			if a, ok := netip.AddrFromSlice(v); ok {
				n.Addr = a.Unmap()
			}
		case ndaLLAddr:
			ll = v
		}
		i += (l + 3) &^ 3
	}
	if !n.Addr.IsValid() || len(ll) != 6 || n.State&nudUsable == 0 {
		return Neighbor{}, false
	}
	n.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", ll[0], ll[1], ll[2], ll[3], ll[4], ll[5])
	return n, true
}

// NeighborTable answers "which MAC has this client address" from the
// kernel's neighbour table, refreshed at most every MaxAge. Only entries
// on the listed interfaces count (the LAN; a remote-access peer has no
// neighbour entry and no MAC, so a MAC rule does not match it, as on the
// address path).
//
// Trust: the entry is what the kernel learned from the client's own ARP /
// NDP traffic, the same frames the address path's "ether saddr" match
// sees. A client that spoofs another device's IP and MAC defeats both
// equally; a client that spoofs only another device's IP while the real
// device is present makes the entry flap, and a connection decided in that
// window may get the other device's rule. Device rules are a routing
// preference, not access control.
type NeighborTable struct {
	// Ifindexes the entries must be on (empty: any interface).
	Ifindexes []int
	MaxAge    time.Duration
	// Dump (nil: the rtnetlink dump; Linux only).
	Dump func() ([]Neighbor, error)
	Now  func() time.Time

	mu   sync.Mutex
	at   time.Time
	byIP map[netip.Addr]string
	err  error
}

// NewNeighborTable for the named interfaces (Linux).
func NewNeighborTable(ifaces []string) (*NeighborTable, error) {
	t := &NeighborTable{MaxAge: time.Second}
	for _, n := range ifaces {
		i, err := ifIndex(n)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", n, err)
		}
		t.Ifindexes = append(t.Ifindexes, i)
	}
	if _, err := neighDump(); err != nil {
		return nil, err
	}
	return t, nil
}

// Lookup returns the MAC of a, "" when unknown.
func (t *NeighborTable) Lookup(a netip.Addr) string {
	a = a.Unmap()
	now := time.Now()
	if t.Now != nil {
		now = t.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byIP == nil || now.Sub(t.at) >= t.MaxAge {
		dump := t.Dump
		if dump == nil {
			dump = neighDump
		}
		ns, err := dump()
		t.at, t.err = now, err
		if err == nil {
			m := make(map[netip.Addr]string, len(ns))
			for _, n := range ns {
				if t.ifOK(n.Ifindex) {
					m[n.Addr] = n.MAC
				}
			}
			t.byIP = m
		} else {
			// No stale answers: an unreadable table means no MAC known.
			t.byIP = map[netip.Addr]string{}
		}
	}
	return t.byIP[a]
}

func (t *NeighborTable) ifOK(i int) bool {
	if len(t.Ifindexes) == 0 {
		return true
	}
	for _, x := range t.Ifindexes {
		if x == i {
			return true
		}
	}
	return false
}
