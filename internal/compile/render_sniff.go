package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
	"github.com/radowitz/meridian/internal/sniff"
	"github.com/radowitz/meridian/internal/validate"
)

// The gateway's name-sniffing TCP forwarder (settings.sniff,
// docs/architecture.md「按域名嗅探的转发」). Off: nothing here is rendered
// and every file is byte-identical to a topology without the setting.
//
// Interception (table inet meridian, one nft transaction with the rest):
//
//   - prerouting (mangle, after classify, before relay_share): chain
//     sniff_mark sets markSniff on the first SYN of a new TCP connection
//     from the LAN or mra to a sniffed port whose destination is not this
//     host, not a LAN, private, multicast, device-pool or ULA address and
//     not a known DoH address. The classification mark stays in the low
//     bits; with markSniff set the packet matches no relay_share jump, no
//     fwmark rule and no guard accept.
//   - prerouting (dstnat): chain sniff_redirect redirects exactly those
//     SYNs to the forwarder's port (REDIRECT: the connection is NATed once,
//     when new; a flow established before the install keeps its path, and
//     a redirected flow stays redirected until it ends).
//   - input: chain sniff_input refuses connections to the port that were
//     not redirected, and clears the mark of every other TCP packet
//     delivered locally, so the host-wide net.ipv4.tcp_fwmark_accept the
//     forwarder's unit turns on gives other listeners mark 0, as before.
//
// The forwarder's own sockets (user SniffUser):
//
//   - output (route, with relay sharing): its exit-marked TCP gets a relay
//     from relay_assign exactly like forwarded traffic (chain sniff_route).
//   - output (filter): chain sniff_mss clamps its SYNs like chain mss;
//     chain sniff_out lets out only replies on redirected connections, DNS
//     to the target file's resolvers with each one's query mark, TCP to a
//     sniffed port with the domestic mark on the LAN NIC, and TCP to a
//     sniffed, non-special destination with an exit or region-group mark on
//     a gateway tunnel; everything else is counted (sniff_denied) and
//     dropped.
//   - postrouting (transit_snat): its exit- and group-marked connections
//     get the mark's transit source, as the LAN's do, so the hub routes them
//     to the same exit.
const (
	SniffUnit       = "meridian-sniff.service"
	SniffUser       = "meridian-sniff"
	SniffUserScript = "/usr/local/sbin/meridian-sniff-user.sh"
	// SniffUID is the forwarder's fixed UID and GID. The ruleset matches
	// its sockets by this number (meta skuid), so loading the ruleset never
	// depends on the account database; the account itself exists only while
	// the unit runs (SniffUserScript add/del), so stopping, disabling or
	// removing the unit removes it. 65520–65533 is outside systemd's
	// dynamic-user range (61184–65519) and below nobody (65534); a clash
	// with an existing account stops the unit from starting.
	SniffUID          = 65530
	SniffTargetsPath  = "/etc/meridian/sniff/targets.json"
	SniffStatusSocket = "/run/meridian-sniff/status.sock"
	// markSniff is the interception bit: above the relay bits (0x00ff0000),
	// the exit marks (0x101…) and every other mark Meridian uses.
	markSniff uint32 = 0x01000000
	// markNoShare clears the relay bits of a mark (output and SNAT compare
	// the forwarder's marks with it; relay_strip does the same on forward).
	markNoShare = ^markShareMask
)

// sniffPlan is the forwarder as compiled for one gateway.
type sniffPlan struct {
	Ports   []int
	ECH     []string
	Record  bool
	Targets []sniff.Target
	// DNS are the (resolver address, query mark) pairs the output chain
	// allows.
	DNS []sniffDNS
	// Last is the top of the exit/group mark range (guardLastExitMark).
	Last uint32
}

type sniffDNS struct {
	Addr netip.Addr
	Mark uint32
}

// planSniff is nil when the forwarder is off.
func planSniff(t model.Topology, exits []ExitPlan, groups []GroupPlan, decisions map[string]string) *sniffPlan {
	if !t.SniffOn() {
		return nil
	}
	s := t.Settings.Sniff
	p := &sniffPlan{Ports: s.EffectivePorts(), ECH: s.EffectiveECHPublicNames(), Record: s.RecordNames, Last: guardLastExitMark(exits, groups...)}
	sort.Ints(p.Ports)
	seen := map[uint32]bool{}
	add := func(tg sniff.Target) {
		if seen[tg.Mark] {
			return
		}
		seen[tg.Mark] = true
		p.Targets = append(p.Targets, tg)
	}
	mark := func(m uint32) *uint32 { return &m }
	direct := func() {
		var rs []string
		for _, ip := range domesticDoT(t) {
			rs = append(rs, bracketHostPort(ip, 53))
		}
		add(sniff.Target{Name: "direct", Mark: markDomestic, Resolvers: rs, DNSMark: mark(markDomestic), IPv6: true})
	}
	exit := func(e ExitPlan) {
		tg := sniff.Target{Name: "exit:" + e.Node.ID, Mark: e.Mark, DNSMark: mark(0), IPv6: carriesV6(e)}
		// The gateway resolver's own choice (renderGatewayDNS): the exit's
		// tunnel resolver, its hub-independent address with a backup hub,
		// none for an exit without one (a Mesh-only exit).
		if e.DNSULA != "" {
			addr := e.DNSULA
			if t.DualHub() {
				addr = e.Resolver
			}
			tg.Resolvers = []string{bracketHostPort(addr, 53)}
		}
		add(tg)
	}
	group := func(g GroupPlan, v6 bool) {
		add(sniff.Target{Name: "group:" + g.Group.ID, Mark: g.Mark, Resolvers: []string{bracketHostPort(g.Resolver, 53)}, DNSMark: mark(g.Mark), IPv6: v6})
	}
	for _, rp := range planRules(t, exits, groups, decisions) {
		switch {
		case rp.QUIC:
		case rp.Action == model.ActionDirect:
			direct()
		case rp.Action == model.ActionReject:
			add(sniff.Target{Name: "reject", Mark: markReject, Reject: true})
		case rp.ViaGroup != nil:
			group(*rp.ViaGroup, !rp.FilterAAAA)
		default:
			exit(rp.Exit)
		}
	}
	direct()
	if def, ok := defaultExit(t, groups); ok {
		if def.Group != nil {
			group(*def.Group, def.V6)
		} else {
			exit(def.Exit)
		}
	}
	for _, tg := range p.Targets {
		for _, r := range tg.Resolvers {
			if ap, err := netip.ParseAddrPort(r); err == nil {
				p.DNS = append(p.DNS, sniffDNS{Addr: ap.Addr(), Mark: *tg.DNSMark})
			}
		}
	}
	return p
}

// renderSniffTargets is the forwarder's target file, paired with the
// snapshot it was compiled with (sniff.TargetsFile.SnapshotSHA256).
func renderSniffTargets(p *sniffPlan, snapshot string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(snapshot, "\n") + "\n"))
	tf := sniff.TargetsFile{Version: sniff.TargetsVersion, SnapshotSHA256: hex.EncodeToString(sum[:]), Targets: p.Targets}
	b, err := json.MarshalIndent(tf, "", " ")
	if err != nil {
		panic(err) // plain structs: cannot fail
	}
	return string(b) + "\n"
}

func joinInts(ns []int, sep string) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, sep)
}

// renderSniffUnit runs the forwarder as SniffUser with CAP_NET_ADMIN only
// (SO_MARK on its sockets). The unit turns tcp_fwmark_accept on before it
// listens and off after it stops (the input chain sniff_input keeps every
// other listener at mark 0 while it is on). SIGHUP (systemctl reload)
// re-reads the snapshot and the target file as a pair.
func renderSniffUnit(t model.Topology, p *sniffPlan) string {
	args := []string{
		"--listen", fmt.Sprintf("[::]:%d", validate.SniffListenPort),
		"--mode", "redirect",
		"--snapshot", DecidePath,
		"--targets", SniffTargetsPath,
		"--lists-dir", "/var/lib/meridian",
		"--status-socket", SniffStatusSocket,
		"--neigh-if", gatewayLAN(t),
		"--sniff-ports", joinInts(p.Ports, ","),
		"--addr-mark-bit", fmt.Sprintf("%#x", markSniff),
		"--ech-outer",
	}
	if len(p.ECH) > 0 {
		args = append(args, "--ech-public-names", strings.Join(p.ECH, ","))
	}
	if p.Record {
		args = append(args, "--record-names")
	}
	return fmt.Sprintf(`# Meridian name-sniffing TCP forwarder (settings.sniff). The gateway's nft
# ruleset redirects new TCP connections from the LAN and remote access to
# ports %[1]s here; see docs/architecture.md「按域名嗅探的转发」.
# Stopped or crashed: the redirected connections are refused (nothing
# listens on the port), they never fall back to the address path.
[Unit]
Description=Meridian name-sniffing TCP forwarder
After=network-online.target meridian.service
Wants=network-online.target

[Service]
Type=simple
# An older host binary has no sniff subcommand and would start the panel.
ExecStartPre=/bin/grep -q %[2]s /usr/local/bin/meridian
# The accepted socket carries the SYN's mark (the address classification
# for connections without a name); off again once the forwarder is down.
ExecStartPre=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=1
# The account (uid %[5]d, which the ruleset confines) exists only while
# the unit runs.
ExecStartPre=+%[6]s add
ExecStart=/usr/local/bin/meridian sniff %[3]s
ExecReload=/bin/kill -HUP $MAINPID
ExecStopPost=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=0
ExecStopPost=+%[6]s del
User=%[4]s
Group=%[4]s
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
RuntimeDirectory=meridian-sniff
RuntimeDirectoryMode=0750
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=65536
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`, joinInts(p.Ports, ","), sniff.ReadyMarker, strings.Join(args, " "), SniffUser, SniffUID, SniffUserScript)
}

// sniffUserScript adds and removes the forwarder's account (SniffUser,
// SniffUID): the unit runs "add" before the forwarder starts and "del"
// after it stopped, both as root ("+"). A name or an id that belongs to
// someone else is refused (the unit does not start; redirected
// connections are refused, nothing bypasses the forwarder). Only the
// account this script would create is ever removed.
var sniffUserScript = fmt.Sprintf(`#!/bin/bash
# meridian-sniff-user.sh add|del: the account of meridian-sniff.service
# (uid and gid %[1]d) exists exactly while the unit runs.
set -uo pipefail
name=%[2]s
id=%[1]d
by_name=$(getent passwd "$name" | cut -d: -f3)
by_id=$(getent passwd "$id" | cut -d: -f1)
grp_id=$(getent group "$id" | cut -d: -f1)
case "${1:-}" in
  add)
    if [ -n "$by_name" ] && [ "$by_name" != "$id" ]; then
      echo "meridian-sniff-user-conflict: account $name exists with uid $by_name, not $id" >&2; exit 1
    fi
    if [ -n "$by_id" ] && [ "$by_id" != "$name" ]; then
      echo "meridian-sniff-user-conflict: uid $id belongs to $by_id" >&2; exit 1
    fi
    if [ -n "$grp_id" ] && [ "$grp_id" != "$name" ]; then
      echo "meridian-sniff-user-conflict: gid $id belongs to group $grp_id" >&2; exit 1
    fi
    if [ -z "$by_name" ]; then
      [ -n "$grp_id" ] || groupadd --system --gid "$id" "$name" || exit 1
      useradd --system --uid "$id" --gid "$id" --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "Meridian sniffing forwarder" "$name" 2>/dev/null || exit 1
    fi
    ;;
  del)
    if [ "$by_name" = "$id" ]; then userdel "$name" || exit 1; fi
    if [ "$(getent group "$id" | cut -d: -f1)" = "$name" ]; then groupdel "$name" || exit 1; fi
    ;;
  *) echo "usage: $0 add|del" >&2; exit 2 ;;
esac
exit 0
`, SniffUID, SniffUser)

// sniffSkipV4/V6 are destinations never intercepted: the classifier's
// private and special ranges (domestic or dropped there), the LAN, the
// device pools.
func sniffSkip(t model.Topology, rp *remotePlan) (v4, v6 []string) {
	var p4, p6 []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
		p4 = append(p4, netip.MustParsePrefix(s))
	}
	if p, err := netip.ParsePrefix(lanNet(t)); err == nil {
		p4 = append(p4, p)
	}
	for _, s := range []string{"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		p6 = append(p6, netip.MustParsePrefix(s))
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(t.Settings.LANIPv6Prefix)); err == nil && p.Addr().Is6() {
		p6 = append(p6, p)
	}
	if rp != nil {
		p4 = append(p4, rp.V4)
		p6 = append(p6, rp.V6)
	}
	for _, p := range ordered.MergePrefixes(p4) {
		v4 = append(v4, p.String())
	}
	for _, p := range ordered.MergePrefixes(p6) {
		v6 = append(v6, p.String())
	}
	return v4, v6
}

// writeSniffNFT renders the forwarder's chains into table inet meridian
// (see the comment at the top of this file). in is the managed ingress
// match, tunnels the gateway's WireGuard interfaces, share whether relay
// sharing is on, clamps and mss4/mss6 the forward chain's clamps.
func writeSniffNFT(sb *strings.Builder, t model.Topology, p *sniffPlan, in string, rp *remotePlan, tunnels []string, share bool, mss4, mss6 int, clamps []mssClamp) {
	lan := gatewayLAN(t)
	ports := "{ " + joinInts(p.Ports, ", ") + " }"
	skip4, skip6 := sniffSkip(t, rp)
	user := fmt.Sprint(SniffUID)
	fmt.Fprintf(sb, "  # name-sniffing forwarder (settings.sniff, compile/render_sniff.go)\n")
	sb.WriteString("  counter sniff_redirected {\n  }\n  counter sniff_denied {\n  }\n")
	sb.WriteString("  chain sniff_mark {\n")
	sb.WriteString("    tcp flags & (fin | syn | rst | ack) != syn return comment \"only a connection's first SYN is redirected\"\n")
	sb.WriteString("    ct state != new return\n")
	fmt.Fprintf(sb, "    tcp dport != %s return\n", ports)
	sb.WriteString("    meta mark 0x00000000 return comment \"unclassified (link-local, multicast)\"\n")
	sb.WriteString("    fib daddr type local return comment \"this gateway's own addresses\"\n")
	fmt.Fprintf(sb, "    ip daddr { %s } return comment \"LAN, private, special and device-pool destinations\"\n", strings.Join(skip4, ", "))
	fmt.Fprintf(sb, "    ip6 daddr { %s } return\n", strings.Join(skip6, ", "))
	sb.WriteString("    ip daddr @doh4 tcp dport 443 return comment \"known DoH: refused by chain doh\"\n")
	sb.WriteString("    ip6 daddr @doh6 tcp dport 443 return\n")
	fmt.Fprintf(sb, "    meta mark set meta mark | %s counter name \"sniff_redirected\" comment \"to the forwarder; the classification mark stays in the low bits\"\n", hexMark(markSniff))
	sb.WriteString("  }\n")
	fmt.Fprintf(sb, "  chain sniff_redirect {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, fam := range []string{"ipv4", "ipv6"} {
		fmt.Fprintf(sb, "    iifname %s meta mark & %s == %s meta nfproto %s meta l4proto tcp redirect to :%d\n", in, hexMark(markSniff), hexMark(markSniff), fam, validate.SniffListenPort)
	}
	sb.WriteString("  }\n")
	fmt.Fprintf(sb, `  chain sniff_input {
    type filter hook input priority -10; policy accept;
    tcp dport %d ct status & dnat == 0 drop comment "the forwarder takes only redirected connections"
    meta l4proto tcp meta mark & %s == 0x00000000 meta mark set 0x00000000 comment "tcp_fwmark_accept is on: other listeners keep mark 0"
  }
`, validate.SniffListenPort, hexMark(markSniff))
	if share {
		fmt.Fprintf(sb, "  chain sniff_route {\n    type route hook output priority mangle; policy accept;\n")
		fmt.Fprintf(sb, "    meta skuid %s meta l4proto tcp tcp dport != 53 meta mark %#x-%#x jump relay_share comment \"the forwarder's connections share the relays like forwarded ones\"\n", user, markExitBase, p.Last)
		sb.WriteString("  }\n")
	}
	fmt.Fprintf(sb, "  chain sniff_mss {\n    type filter hook output priority -140; policy accept;\n")
	for _, c := range clamps {
		if c.MSS4 > 0 {
			fmt.Fprintf(sb, "    meta skuid %s tcp flags syn meta mark & %s == %s meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", user, hexMark(markNoShare), hexMark(c.Mark), c.MSS4, c.MSS4)
		}
		if c.MSS6 > 0 {
			fmt.Fprintf(sb, "    meta skuid %s tcp flags syn meta mark & %s == %s meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", user, hexMark(markNoShare), hexMark(c.Mark), c.MSS6, c.MSS6)
		}
	}
	fmt.Fprintf(sb, "    meta skuid %s tcp flags syn meta nfproto ipv4 tcp option maxseg size > %d tcp option maxseg size set %d\n", user, mss4, mss4)
	fmt.Fprintf(sb, "    meta skuid %s tcp flags syn meta nfproto ipv6 tcp option maxseg size > %d tcp option maxseg size set %d\n", user, mss6, mss6)
	sb.WriteString("  }\n")
	fmt.Fprintf(sb, "  chain sniff_out {\n    type filter hook output priority 10; policy accept;\n    meta skuid %s jump sniff_confine\n  }\n", user)
	sb.WriteString("  chain sniff_confine {\n")
	sb.WriteString("    ct direction reply accept comment \"replies on the redirected client connections\"\n")
	for _, d := range p.DNS {
		fam := "ip"
		if d.Addr.Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(sb, "    %s daddr %s meta mark %s meta l4proto { tcp, udp } th dport 53 accept comment \"resolver of the target file\"\n", fam, d.Addr, hexMark(d.Mark))
	}
	fmt.Fprintf(sb, "    meta l4proto != tcp counter name \"sniff_denied\" drop\n")
	fmt.Fprintf(sb, "    tcp dport != %s counter name \"sniff_denied\" drop comment \"connections only to the sniffed ports\"\n", ports)
	fmt.Fprintf(sb, "    meta mark %s oifname \"%s\" accept comment \"direct: the LAN NIC only\"\n", hexMark(markDomestic), lan)
	fmt.Fprintf(sb, "    ip daddr { %s } counter name \"sniff_denied\" drop comment \"never into a tunnel: what the classifier treats as domestic or drops\"\n", strings.Join(sniffSpecial4, ", "))
	fmt.Fprintf(sb, "    ip6 daddr { %s } counter name \"sniff_denied\" drop\n", strings.Join(sniffSpecial6, ", "))
	if len(tunnels) > 0 {
		quoted := make([]string, len(tunnels))
		for i, n := range tunnels {
			quoted[i] = "\"" + n + "\""
		}
		fmt.Fprintf(sb, "    meta mark & %s %#x-%#x oifname { %s } accept comment \"exit and region-group marks: WireGuard only\"\n", hexMark(markNoShare), markExitBase, p.Last, strings.Join(quoted, ", "))
	}
	sb.WriteString("    counter name \"sniff_denied\" drop comment \"fail closed: no legal target mark or path\"\n")
	sb.WriteString("  }\n\n")
}

// Destinations the forwarder may never reach through a tunnel.
var (
	sniffSpecial4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"}
	sniffSpecial6 = []string{"::/127", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// writeSniffSNAT adds the forwarder's transit source translation to
// chain transit_snat: one pair per exit and group mark (relay bits masked).
func writeSniffSNAT(sb *strings.Builder, marks []markPlan) {
	for _, m := range marks {
		fmt.Fprintf(sb, "    meta skuid %d meta mark & %s == %s meta nfproto ipv4 snat ip to %s comment \"the forwarder's connections: the mark's transit source\"\n", SniffUID, hexMark(markNoShare), hexMark(m.Mark), m.TransitV4)
		fmt.Fprintf(sb, "    meta skuid %d meta mark & %s == %s meta nfproto ipv6 snat ip6 to %s\n", SniffUID, hexMark(markNoShare), hexMark(m.Mark), m.TransitV6)
	}
}
