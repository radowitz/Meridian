package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/radowitz/meridian/internal/unlock"
)

// Pinned dials sockets that carry an exit's fwmark and its transit source
// address, so the gateway's policy rules (fwmark → table 102 → west tunnel,
// then the unreachable rule) and the hub's source-based selection both send
// them to that exit. It is the host agent's Resolve/Dial half of Network;
// Route is answered by the agent with `ip route get`.
type Pinned struct {
	Mark   uint32
	Family unlock.Family
	// Src4 / Src6 are the exit's transit addresses on the gateway's lo.
	Src4, Src6 netip.Addr
	// Resolver is the exit's tunnel resolver (a ULA). DNS goes there over
	// IPv6 from Src6 with the same mark, so names resolve where the exit is
	// and the query never reaches the domestic resolver.
	Resolver netip.Addr
	Timeout  time.Duration
}

func (p Pinned) dialer(local net.Addr) *net.Dialer {
	t := p.Timeout
	if t <= 0 {
		t = 10 * time.Second
	}
	return &net.Dialer{Timeout: t, LocalAddr: local, Control: markControl(p.Mark)}
}

// Dial opens tcp4 or tcp6 (never the other one) from the family's transit
// address to dst.
func (p Pinned) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	switch {
	case p.Family == unlock.FamilyIPv4 && dst.Addr().Is4():
		return p.dialer(&net.TCPAddr{IP: p.Src4.AsSlice()}).DialContext(ctx, "tcp4", dst.String())
	case p.Family == unlock.FamilyIPv6 && dst.Addr().Is6() && !dst.Addr().Is4In6():
		return p.dialer(&net.TCPAddr{IP: p.Src6.AsSlice()}).DialContext(ctx, "tcp6", dst.String())
	default:
		return nil, fmt.Errorf("%w：%s 不是 %s 地址", ErrEgress, dst.Addr(), p.Family)
	}
}

// Resolve asks the exit's resolver for A (ipv4) or AAAA (ipv6) records only.
func (p Pinned) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if !p.Resolver.IsValid() || !p.Src6.IsValid() {
		return nil, errors.New("出口没有隧道解析器地址，不用本机解析器代替")
	}
	r := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The server address from resolv.conf is ignored on purpose.
			var local net.Addr = &net.UDPAddr{IP: p.Src6.AsSlice()}
			n := "udp6"
			if network == "tcp" || network == "tcp4" || network == "tcp6" {
				local, n = &net.TCPAddr{IP: p.Src6.AsSlice()}, "tcp6"
			}
			return p.dialer(local).DialContext(ctx, n, netip.AddrPortFrom(p.Resolver, 53).String())
		},
	}
	ipnet := "ip4"
	if p.Family == unlock.FamilyIPv6 {
		ipnet = "ip6"
	}
	addrs, err := r.LookupNetIP(ctx, ipnet, host)
	if err != nil {
		return nil, resolveError(p.Resolver, err)
	}
	out := addrs[:0]
	for _, a := range addrs {
		a = a.Unmap()
		if (p.Family == unlock.FamilyIPv4) == a.Is4() {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 没有 %s 记录", host, p.Family)
	}
	return out, nil
}

// resolveError describes a failed lookup by the resolver that was really
// asked. Go's *net.DNSError prints "lookup <host> on <server>", where
// <server> is the nominal system resolver from resolv.conf; Resolve's Dial
// ignores that address and always talks to the exit's tunnel resolver, so
// printing it would read as a query to the home router (a leak) when none
// happened. The server field is therefore never used.
func resolveError(resolver netip.Addr, err error) error {
	at := netip.AddrPortFrom(resolver, 53).String()
	var de *net.DNSError
	if !errors.As(err, &de) {
		return fmt.Errorf("出口解析器 %s：%v", at, err)
	}
	var what string
	switch {
	case de.IsTimeout:
		what = "查询超时"
	case de.IsNotFound:
		what = "没有这个域名或没有对应记录"
	case de.IsTemporary:
		what = "暂时失败"
	default:
		what = "查询失败"
	}
	if de.Err != "" {
		return fmt.Errorf("出口解析器 %s %s（%s）", at, what, de.Err)
	}
	return fmt.Errorf("出口解析器 %s %s", at, what)
}
