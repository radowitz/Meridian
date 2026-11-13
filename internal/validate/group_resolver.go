package validate

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Region-group resolver addresses (docs/architecture.md「地区组的解析」).
//
// A region group the hub can switch resolves its names through its own data
// path: the gateway's SmartDNS asks GroupResolverAddr(i) with the group's
// fwmark, the gateway SNATs the query to the group's transit address, the
// hub routes it by that source into whichever member the group table points
// at, and that member DNATs it to its own tunnel resolver. The addresses
// belong to no node. They sit in GroupResolverNet, inside fd66::/64, which
// the tunnel address plan never allocates (links get fd66:0:0:<n>::/64 with
// n >= 1, the WSS companions fd66:0:0:<0x80+i>::/64, the transit prefix is
// fd66:0:0:ff::/64). The whole /64 is reserved: a tunnel interface address
// in it would give some node an on-link route to the resolver addresses.
var (
	GroupResolverNet  = netip.MustParsePrefix("fd66::53:0/112")
	groupResolverLink = netip.MustParsePrefix("fd66::/64")
)

// ExitResolverNet holds the per-exit resolver addresses a gateway with a
// backup hub asks instead of an exit's tunnel address
// (compile.ExitPlan.Resolver): fd66::54:<i+1> for the exit with plan index
// i. Like the group addresses they belong to no node and sit in the
// reserved fd66::/64; both hubs route each one to their tunnel to that exit,
// which DNATs it to its own resolver.
var ExitResolverNet = netip.MustParsePrefix("fd66::54:0/112")

// ExitResolverAddr is the resolver address of the exit with plan index i.
func ExitResolverAddr(index int) netip.Addr {
	b := ExitResolverNet.Addr().As16()
	v := uint16(index + 1)
	b[14], b[15] = byte(v>>8), byte(v)
	return netip.AddrFrom16(b)
}

// GroupResolverAddr is the resolver address of the region group with plan
// index i (the index that also numbers its mark, transit address and hub
// table): fd66::53:<i+1>. One address per group, so that no two SmartDNS
// upstream servers share an address and differ only in their fwmark.
func GroupResolverAddr(index int) netip.Addr {
	b := GroupResolverNet.Addr().As16()
	v := uint16(index + 1)
	b[14], b[15] = byte(v>>8), byte(v)
	return netip.AddrFrom16(b)
}

// checkGroupResolver keeps fd66::/64 (and so every group resolver address)
// free of tunnel addresses and configured prefixes.
func checkGroupResolver(t model.Topology) []Issue {
	var out []Issue
	conflict := func(linkID, what string) {
		out = append(out, Issue{Code: "group_resolver_conflict", Severity: SeverityError, LinkID: linkID,
			Message: fmt.Sprintf("%s 落在 %s 里。这一段保留给地区组的解析地址（%s，不属于任何节点），隧道地址和其他前缀都不能用它。", what, groupResolverLink, GroupResolverNet)})
	}
	for _, l := range t.Links {
		for _, s := range []string{l.FromULA, l.ToULA} {
			if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && groupResolverLink.Contains(a) {
				conflict(l.ID, "链路 "+l.ID+" 的隧道地址 "+a.String())
			}
		}
	}
	// The LAN IPv6 prefix and the remote-access device pool are already
	// refused anywhere in fd66::/48 (checkLANIPv6, checkRemoteV6), and Mesh
	// routes by the Mesh plan; these two are not.
	for _, v := range []struct{ s, what string }{
		{t.Settings.TransitV6Prefix, "中转前缀"},
		{t.Settings.NAT64.Prefix, "NAT64 前缀"},
	} {
		if p, err := netip.ParsePrefix(strings.TrimSpace(v.s)); err == nil && p.Addr().Is6() && p.Overlaps(groupResolverLink) {
			conflict("", v.what+" "+p.Masked().String())
		}
	}
	return out
}
