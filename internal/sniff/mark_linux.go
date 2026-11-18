//go:build linux

package sniff

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

const (
	// SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST (linux/netfilter_ipv4.h,
	// linux/netfilter_ipv6/ip6_tables.h): the destination before REDIRECT.
	soOriginalDst = 80
	// IPV6_TRANSPARENT (linux/in6.h).
	ipv6Transparent = 75
)

// markControl puts mark on a socket before it connects (SO_MARK, needs
// CAP_NET_ADMIN). Mark 0 leaves the socket unmarked.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return serr
	}
}

// SocketMark reads SO_MARK of a connected socket. With the sysctl
// net.ipv4.tcp_fwmark_accept=1 an accepted socket carries the fwmark of
// the client's SYN, which lets the install hand the forwarder the mark the
// address classifier gave the connection (see Config.AddrMark).
func SocketMark(c net.Conn) (uint32, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, errors.New("not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var m int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		m, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}); err != nil {
		return 0, err
	}
	return uint32(m), serr
}

// OrigDstRedirect is the original destination of a connection the kernel
// redirected (nft "redirect" / iptables REDIRECT, DNAT to the listener):
// SO_ORIGINAL_DST from conntrack.
func OrigDstRedirect(c net.Conn) (netip.AddrPort, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	local, _ := netip.ParseAddrPort(c.LocalAddr().String())
	var out netip.AddrPort
	var serr error
	err = raw.Control(func(fd uintptr) {
		if local.Addr().Unmap().Is4() {
			// sockaddr_in (16 bytes) fits in the 20-byte IPv6Mreq.
			m, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, soOriginalDst)
			if err != nil {
				serr = err
				return
			}
			b := m.Multiaddr
			port := uint16(b[2])<<8 | uint16(b[3])
			out = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port)
			return
		}
		// sockaddr_in6 (28 bytes) fits in the 32-byte IPv6MTUInfo.
		m, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.SOL_IPV6, soOriginalDst)
		if err != nil {
			serr = err
			return
		}
		a := m.Addr
		pb := (*[2]byte)(unsafe.Pointer(&a.Port)) // network order in memory
		port := uint16(pb[0])<<8 | uint16(pb[1])
		out = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), port)
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, serr
	}
	return netip.AddrPortFrom(out.Addr().Unmap(), out.Port()), nil
}

// transparentControl sets IP_TRANSPARENT (and IPV6_TRANSPARENT on IPv6
// sockets) on a listening socket so that TPROXY can deliver connections
// for foreign destinations to it (needs CAP_NET_ADMIN).
func transparentControl(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		v6 := network == "tcp6"
		if !v6 {
			if ap, err := netip.ParseAddrPort(address); err == nil && ap.Addr().Is6() && !ap.Addr().Is4In6() {
				v6 = true
			}
		}
		if v6 {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6Transparent, 1)
			return
		}
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// neighDump reads the kernel neighbour table (ARP and NDP) over rtnetlink.
func neighDump() ([]Neighbor, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	var out []Neighbor
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH {
			continue
		}
		if n, ok := parseNeighMsg(m.Data); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

func ifIndex(name string) (int, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}
