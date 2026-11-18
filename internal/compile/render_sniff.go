package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
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
//     not redirected, puts the takeover bit back on a redirected SYN that
//     was not its connection's first (a reused 4-tuple on a live conntrack
//     entry, a SYN repeated after the reply was seen: counter sniff_resyn),
//     and clears the mark of every other TCP packet delivered locally
//     without the bit, so the host-wide net.ipv4.tcp_fwmark_accept the
//     forwarder's unit turns on gives other listeners mark 0, as before.
//
// The forwarder's own sockets (user SniffUser, uid SniffUID):
//
//   - output (route, with relay sharing): its exit-marked TCP gets a relay
//     from relay_assign exactly like forwarded traffic (chain sniff_route).
//   - output (filter): chain sniff_mss clamps its SYNs like chain mss;
//     chain sniff_out lets out only replies on redirected connections, DNS
//     to the target file's resolvers with each one's query mark, TCP to a
//     sniffed port with the domestic mark on the LAN NIC, TCP to a sniffed,
//     non-special destination with an exit or region-group mark on a
//     gateway tunnel, and WireGuard's own outer packets of that tunnelled
//     traffic (below); everything else is counted (sniff_denied) and
//     dropped.
//   - postrouting (transit_snat): its exit- and group-marked connections
//     get the mark's transit source, as the LAN's do, so the hub routes them
//     to the same exit.
//
// WireGuard's outer packets. A packet the forwarder sends into a gateway
// tunnel is encrypted by the kernel into an outer UDP packet that still
// carries the forwarder's socket, so "meta skuid SniffUID" matches the outer
// packet in the output hook too (seen on a real gateway: every tunnelled
// query and connection of the forwarder lost its outer packet in
// sniff_confine). The outer packet carries the tunnel interfaces' fwmark
// (markUnderlay, "FwMark =" in renderWG) and goes to the tunnel's peer
// endpoint, the "Endpoint =" renderWG writes (peerEndpoint): the relay's or
// hub's address and WireGuard port, out of the LAN NIC, or for a WSS carrier
// 127.0.0.1 and the local wstunnel client's port, out of lo. sniff_confine
// accepts exactly those (gatewayWGOuter: mark, UDP, interface, address and
// port of each endpoint) and nothing else carrying the mark. The forwarder
// has CAP_NET_ADMIN and can put that mark on any socket of its own; what
// such a datagram can reach is still only a WireGuard port of this
// gateway's own peers (directly, or through the local wstunnel client that
// carries it to the same listener's WireGuard port), where a datagram that
// is not WireGuard under the gateway's key is discarded by the peer. To any
// other address, port or interface it is counted (sniff_denied) and
// dropped. A tunnel without a fixed endpoint (none written, or a DNS name)
// gets no accept: the forwarder's traffic through it fails closed and shows
// as sniff_denied growth. The other owner matches cannot see an outer
// packet: sniff_route and sniff_mss match TCP only and transit_snat only the
// exit and group marks, which never include markUnderlay
// (docs/architecture.md「封装后的外层包」).
const (
	SniffUnit = "meridian-sniff.service"
	// SniffAccountUnit is the root oneshot that creates the forwarder's
	// account before SniffUnit starts and removes it after SniffUnit stopped
	// (SniffUnit Requires= and is After= it; it is StopWhenUnneeded=). It is
	// a managed file but not a manifest unit: the host agent starts and
	// stops it only together with SniffUnit (hostexec.SniffAccountUnit).
	SniffAccountUnit = "meridian-sniff-account.service"
	SniffUser        = "meridian-sniff"
	SniffUserScript  = "/usr/local/sbin/meridian-sniff-user.sh"
	// SniffUID is the forwarder's fixed UID and GID. The ruleset matches
	// its sockets by this number (meta skuid), so loading the ruleset never
	// depends on the account database; the account itself exists only while
	// SniffAccountUnit is active (SniffUserScript add/del), that is while
	// the forwarder runs. 65520–65533 is outside systemd's dynamic-user
	// range (61184–65519) and below nobody (65534); a clash with an existing
	// account fails SniffAccountUnit, so the forwarder does not start.
	SniffUID          = 65530
	SniffTargetsPath  = "/etc/meridian/sniff/targets.json"
	SniffRuntimeDir   = "meridian-sniff"
	SniffStatusSocket = "/run/" + SniffRuntimeDir + "/status.sock"
	// SniffStateDir is the forwarder's StateDirectory, which holds its
	// connection journal (sniff/journal.go; docs/architecture.md「设备连接
	// 日志」): /var/lib/meridian-sniff, created by systemd at the unit's
	// start with StateDirectoryMode=0700 and owned by SniffUID; the journal
	// files are 0600. Only root and the forwarder's uid can read it (another
	// local user is "other" and gets nothing; the host agent, root without
	// CAP_DAC_OVERRIDE, reads the journal only through the status socket).
	// SniffUID is fixed, so a recreated account owns the same files.
	// Removing the forwarder (rollback, withdraw) removes the directory
	// (hostexec: systemctl clean --what=state).
	SniffStateDir   = "meridian-sniff"
	SniffJournalDir = "/var/lib/" + SniffStateDir
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
		// none for an exit without one (an exit without a tunnel).
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

// SniffUnitSpec is everything the forwarder's two units and its account
// script are rendered from. The gateway install uses gatewaySniffSpec (the
// fixed names below); deploy/verify-sniff-systemd.sh renders the same text
// with temporary names, ids and port ("meridian sniff-verify-render"), so
// what it starts on a real systemd is this code's output, not a copy.
type SniffUnitSpec struct {
	// Unit is the forwarder's service, AccountUnit the root oneshot that
	// creates its account before it starts and removes it after it stopped.
	Unit, AccountUnit string
	// User is the account name; UID its uid and gid (the ruleset matches
	// the forwarder's sockets by this number).
	User string
	UID  int
	// AccountScript is the absolute path of the add/del script the account
	// unit runs (never under /run: noexec there).
	AccountScript string
	// RuntimeDir is the RuntimeDirectory name (/run/<RuntimeDir>), which
	// holds the status socket.
	RuntimeDir string
	// StateDir is the StateDirectory name (/var/lib/<StateDir>, mode 0700,
	// owned by UID), which holds the connection journal; "" none.
	StateDir string
	// Binary is the meridian executable.
	Binary string
	// Listen is the forwarder's address:port.
	Listen                               string
	Snapshot, Targets, ListsDir, NeighIf string
	Ports                                []int
	ECH                                  []string
	Record                               bool
	// FwmarkAcceptOn and FwmarkAcceptOff are written to
	// net.ipv4.tcp_fwmark_accept before the forwarder starts and after it
	// stopped ("1" and "0" on the gateway).
	FwmarkAcceptOn, FwmarkAcceptOff string
}

// StatusSocket is the forwarder's status socket under its runtime
// directory.
func (s SniffUnitSpec) StatusSocket() string { return "/run/" + s.RuntimeDir + "/status.sock" }

// JournalDir is the connection journal's directory ("" without StateDir).
func (s SniffUnitSpec) JournalDir() string {
	if s.StateDir == "" {
		return ""
	}
	return "/var/lib/" + s.StateDir
}

func gatewaySniffSpec(t model.Topology, p *sniffPlan) SniffUnitSpec {
	return SniffUnitSpec{
		Unit: SniffUnit, AccountUnit: SniffAccountUnit, User: SniffUser, UID: SniffUID, AccountScript: SniffUserScript,
		RuntimeDir: SniffRuntimeDir, StateDir: SniffStateDir, Binary: "/usr/local/bin/meridian", Listen: fmt.Sprintf("[::]:%d", validate.SniffListenPort),
		Snapshot: DecidePath, Targets: SniffTargetsPath, ListsDir: "/var/lib/meridian", NeighIf: gatewayLAN(t),
		Ports: p.Ports, ECH: p.ECH, Record: p.Record, FwmarkAcceptOn: "1", FwmarkAcceptOff: "0",
	}
}

// RenderSniffUnit runs the forwarder as s.User with CAP_NET_ADMIN only
// (SO_MARK on its sockets). The account must exist before systemd spawns
// anything for this unit: systemd resolves User= before every Exec line,
// "+" ones included (a missing account fails at step USER, 217/USER), so
// the account comes from s.AccountUnit, which this unit requires and is
// ordered after; that unit stops (and removes the account) once this one
// is stopped or failed for good (StopWhenUnneeded). The unit turns
// tcp_fwmark_accept on before it listens and off after it stops, as root
// ("+"; the input chain sniff_input keeps every other listener at mark 0
// while it is on). SIGHUP (systemctl reload) re-reads the snapshot and the
// target file as a pair. The status socket's directory is 0755 and the
// socket answers only uid 0 (SO_PEERCRED): the host agent is root without
// CAP_DAC_OVERRIDE, so it needs the "other" bits (sniff.ListenStatus).
func RenderSniffUnit(s SniffUnitSpec) string {
	args := []string{
		"--listen", s.Listen,
		"--mode", "redirect",
		"--snapshot", s.Snapshot,
		"--targets", s.Targets,
		"--lists-dir", s.ListsDir,
		"--status-socket", s.StatusSocket(),
	}
	if s.StateDir != "" {
		args = append(args, "--journal-dir", s.JournalDir())
	}
	if s.NeighIf != "" {
		args = append(args, "--neigh-if", s.NeighIf)
	}
	args = append(args,
		"--sniff-ports", joinInts(s.Ports, ","),
		"--addr-mark-bit", fmt.Sprintf("%#x", markSniff),
		"--ech-outer",
	)
	if len(s.ECH) > 0 {
		args = append(args, "--ech-public-names", strings.Join(s.ECH, ","))
	}
	if s.Record {
		args = append(args, "--record-names")
	}
	return fmt.Sprintf(`# Meridian name-sniffing TCP forwarder (settings.sniff). The gateway's nft
# ruleset redirects new TCP connections from the LAN and remote access to
# ports %[1]s here; see docs/architecture.md「按域名嗅探的转发」.
# Stopped or crashed: the redirected connections are refused (nothing
# listens on the port), they never fall back to the address path.
[Unit]
Description=Meridian name-sniffing TCP forwarder
# The account (uid %[5]d, which the ruleset confines) exists only while
# this unit runs: %[6]s creates it before this unit starts and removes it
# after this unit stopped. systemd resolves User= before it spawns any
# Exec line of this unit, "+" ones included, so the account cannot be
# created from here.
Requires=%[6]s
After=%[6]s network-online.target meridian.service
Wants=network-online.target

[Service]
Type=simple
# An older host binary has no sniff subcommand and would start the panel.
ExecStartPre=/bin/grep -q %[2]s %[7]s
# The accepted socket carries the SYN's mark (the address classification
# for connections without a name); off again once the forwarder is down.
ExecStartPre=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=%[8]s
ExecStart=%[7]s sniff %[3]s
ExecReload=/bin/kill -HUP $MAINPID
ExecStopPost=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=%[9]s
User=%[4]s
Group=%[4]s
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
# Status socket: the directory is traversable by everyone (0755), the
# socket is writable by everyone (0666) and answers only uid 0 (the
# forwarder checks SO_PEERCRED and closes every other connection). The host
# agent is root without CAP_DAC_OVERRIDE: it gets in through the "other"
# bits, never through a group or a capability.
RuntimeDirectory=%[10]s
RuntimeDirectoryMode=0755
%[11]sProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=65536
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`, joinInts(s.Ports, ","), sniff.ReadyMarker, strings.Join(args, " "), s.User, s.UID, s.AccountUnit, s.Binary, s.FwmarkAcceptOn, s.FwmarkAcceptOff, s.RuntimeDir, stateLines(s))
}

// stateLines are the unit's StateDirectory lines (the connection journal).
func stateLines(s SniffUnitSpec) string {
	if s.StateDir == "" {
		return ""
	}
	return fmt.Sprintf(`# Connection journal (docs/architecture.md「设备连接日志」): %[1]s is owned
# by the forwarder's uid and 0700, its files 0600: only root and this account
# can read them, never another local user. The host agent reads the journal
# only through the status socket's fixed queries. Bounded to 24 h, 50000
# records and 32 MiB including rotated segments; writable here despite
# ProtectSystem=strict.
StateDirectory=%[2]s
StateDirectoryMode=0700
`, s.JournalDir(), s.StateDir)
}

// RenderSniffAccountUnit is the root oneshot that holds the forwarder's
// account: started (account added) when the forwarder's unit starts, which
// requires it; stopped (account removed) when no unit needs it any more,
// that is after the forwarder's unit stopped or failed for good. A crash
// loop (Restart=always) still needs it. It has no [Install]: nothing else
// starts it. A name or an id that belongs to someone else fails it, so the
// forwarder does not start and redirected connections are refused.
func RenderSniffAccountUnit(s SniffUnitSpec) string {
	return fmt.Sprintf(`# Meridian: the account of %[1]s (user %[2]s, uid and gid %[3]d).
# Pulled in by %[1]s (Requires=, After=), stopped once nothing needs it;
# the account exists exactly while this unit is active.
[Unit]
Description=Meridian name-sniffing forwarder account (%[2]s)
StopWhenUnneeded=yes

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%[4]s add
ExecStop=%[4]s del
`, s.Unit, s.User, s.UID, s.AccountScript)
}

// RenderSniffAccountScript adds and removes the forwarder's account
// (s.User, s.UID): the account unit runs "add" when it starts and "del"
// when it stops, both as root. A name or an id that belongs to someone
// else is refused (the forwarder does not start; redirected connections
// are refused, nothing bypasses the forwarder). Only the account this
// script would create is ever removed; a half-done "add" is undone.
func RenderSniffAccountScript(s SniffUnitSpec) string {
	return fmt.Sprintf(`#!/bin/bash
# %[3]s add|del: the account of %[4]s (uid and gid %[1]d), run by
# %[5]s; it exists exactly while that unit is active.
set -uo pipefail
name=%[2]s
id=%[1]d
by_name=$(getent passwd "$name" | cut -d: -f3)
by_id=$(getent passwd "$id" | cut -d: -f1)
grp_id=$(getent group "$id" | cut -d: -f1)
grp_name=$(getent group "$name" | cut -d: -f3)
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
    if [ -n "$grp_name" ] && [ "$grp_name" != "$id" ]; then
      echo "meridian-sniff-user-conflict: group $name exists with gid $grp_name, not $id" >&2; exit 1
    fi
    if [ -z "$by_name" ]; then
      made_group=
      if [ -z "$grp_id" ]; then
        groupadd --system --gid "$id" "$name" || exit 1
        made_group=1
      fi
      if ! useradd --system --uid "$id" --gid "$id" --no-create-home --home-dir /nonexistent         --shell /usr/sbin/nologin --comment "Meridian sniffing forwarder" "$name"; then
        [ -z "$made_group" ] || groupdel "$name"
        echo "meridian-sniff-user-failed: useradd $name" >&2; exit 1
      fi
    fi
    ;;
  del)
    if [ "$by_name" = "$id" ]; then userdel "$name" || exit 1; fi
    if [ "$(getent group "$id" | cut -d: -f1)" = "$name" ]; then groupdel "$name" || exit 1; fi
    ;;
  *) echo "usage: $0 add|del" >&2; exit 2 ;;
esac
exit 0
`, s.UID, s.User, s.AccountScript, s.Unit, s.AccountUnit)
}

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

// wgOuter is one destination of WireGuard's outer packets on the gateway:
// the peer endpoint of one or more gateway tunnels and the interface the
// outer packets leave through.
type wgOuter struct {
	Ifaces []string
	Oif    string
	Addr   netip.Addr
	Port   uint16
	WSS    bool
}

// wgNoEndpoint is a gateway tunnel whose outer packets have no fixed
// destination, with the reason.
type wgNoEndpoint struct {
	Iface, Why string
}

// gatewayWGOuter lists where the gateway's WireGuard interfaces send their
// outer packets, from peerEndpoint: the same function renderWG uses for each
// interface's "Endpoint =" line, whose WSS form is the local port the
// wstunnel client listens on (Tunnel.ClientUDP, renderWstunnelClient). A
// direct endpoint leaves through the LAN NIC (the routes script pins every
// gateway endpoint there, and the fwmark rule sends outer packets to the
// main table), a WSS one through lo. Tunnels without a literal endpoint are
// returned separately: nothing is accepted for them.
func gatewayWGOuter(t model.Topology, tunnels []Tunnel) ([]wgOuter, []wgNoEndpoint) {
	var out []wgOuter
	var none []wgNoEndpoint
	at := map[string]int{}
	seen := map[string]bool{}
	for _, tun := range tunnels {
		var self model.Node
		switch {
		case tun.West.Role == model.RoleGateway:
			self = tun.West
		case tun.East.Role == model.RoleGateway:
			self = tun.East
		default:
			continue
		}
		ifc := tun.Iface()
		if seen[ifc] {
			continue
		}
		seen[ifc] = true
		ep := peerEndpoint(tun, self)
		ap, err := netip.ParseAddrPort(ep)
		switch {
		case ep == "":
			none = append(none, wgNoEndpoint{ifc, "no Endpoint in its configuration (the peer dials this gateway)"})
			continue
		case err != nil:
			none = append(none, wgNoEndpoint{ifc, "its Endpoint is a name, not an address"})
			continue
		}
		o := wgOuter{Ifaces: []string{ifc}, Oif: gatewayLAN(t), Addr: ap.Addr().Unmap(), Port: ap.Port(), WSS: tun.Mode == "wss"}
		if o.WSS {
			if !o.Addr.IsLoopback() {
				none = append(none, wgNoEndpoint{ifc, "a WSS carrier whose Endpoint is not on loopback"})
				continue
			}
			o.Oif = "lo"
		}
		key := fmt.Sprintf("%s|%s|%d", o.Oif, o.Addr, o.Port)
		if i, ok := at[key]; ok {
			out[i].Ifaces = append(out[i].Ifaces, ifc)
			continue
		}
		at[key] = len(out)
		out = append(out, o)
	}
	return out, none
}

// writeSniffWGOuter renders the accepts for WireGuard's outer packets of the
// forwarder's tunnelled traffic (see the comment at the top of this file).
func writeSniffWGOuter(sb *strings.Builder, outer []wgOuter, none []wgNoEndpoint) {
	for _, o := range outer {
		fam := "ip"
		if o.Addr.Is6() {
			fam = "ip6"
		}
		what := "its peer endpoint"
		if o.WSS {
			what = "its local wstunnel client"
		}
		fmt.Fprintf(sb, "    meta mark %s oifname \"%s\" %s daddr %s udp dport %d counter name \"sniff_wg_outer\" accept comment \"WireGuard outer packets of %s: %s\"\n",
			hexMark(markUnderlay), o.Oif, fam, o.Addr, o.Port, strings.Join(o.Ifaces, " "), what)
	}
	for _, n := range none {
		fmt.Fprintf(sb, "    # %s: %s; its outer packets of the forwarder's traffic are not accepted (sniff_denied)\n", n.Iface, n.Why)
	}
}

// writeSniffNFT renders the forwarder's chains into table inet meridian
// (see the comment at the top of this file). in is the managed ingress
// match, tunnels the gateway's WireGuard interfaces and outer/none where
// they send their outer packets (gatewayWGOuter), share whether relay
// sharing is on, clamps and mss4/mss6 the forward chain's clamps.
func writeSniffNFT(sb *strings.Builder, t model.Topology, p *sniffPlan, in string, rp *remotePlan, tunnels []string, outer []wgOuter, none []wgNoEndpoint, share bool, mss4, mss6 int, clamps []mssClamp) {
	lan := gatewayLAN(t)
	ports := "{ " + joinInts(p.Ports, ", ") + " }"
	skip4, skip6 := sniffSkip(t, rp)
	user := fmt.Sprint(SniffUID)
	fmt.Fprintf(sb, "  # name-sniffing forwarder (settings.sniff, compile/render_sniff.go)\n")
	sb.WriteString("  counter sniff_redirected {\n  }\n  counter sniff_resyn {\n  }\n  counter sniff_denied {\n  }\n  counter sniff_wg_outer {\n  }\n")
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
	sb.WriteString("    ip daddr @endpoint_direct4 return comment \"tunnel endpoints keep classify's decision, never re-decided by name\"\n")
	sb.WriteString("    ip daddr @endpoint_tunnel4 return\n")
	sb.WriteString("    ip6 daddr @endpoint_direct6 return\n")
	sb.WriteString("    ip6 daddr @endpoint_tunnel6 return\n")
	fmt.Fprintf(sb, "    meta mark set meta mark | %s counter name \"sniff_redirected\" comment \"to the forwarder; the classification mark stays in the low bits\"\n", hexMark(markSniff))
	sb.WriteString("  }\n")
	fmt.Fprintf(sb, "  chain sniff_redirect {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, fam := range []string{"ipv4", "ipv6"} {
		fmt.Fprintf(sb, "    iifname %s meta mark & %s == %s meta nfproto %s meta l4proto tcp redirect to :%d\n", in, hexMark(markSniff), hexMark(markSniff), fam, validate.SniffListenPort)
	}
	sb.WriteString("  }\n")
	// The SYN that creates the forwarder's socket gives it its mark
	// (tcp_fwmark_accept). That is not always the first SYN sniff_mark saw:
	// a SYN on a conntrack entry that is no longer new (the client reuses
	// the 4-tuple of a redirected connection whose entry is still alive, or
	// repeats its SYN after the forwarder's SYN-ACK was seen and the request
	// socket is gone) keeps the entry's redirect but gets no takeover bit.
	// classify has marked that very SYN by its original destination in
	// prerouting (it runs on every packet), so the bit is put back here,
	// with the relay bits cleared, before the clearing rule below.
	fmt.Fprintf(sb, `  chain sniff_input {
    type filter hook input priority -10; policy accept;
    tcp dport %[1]d ct status & dnat == 0 drop comment "the forwarder takes only redirected connections"
    tcp dport %[1]d ct status & dnat != 0 tcp flags & (fin | syn | rst | ack) == syn meta mark & %[2]s == 0x00000000 meta mark & %[3]s != 0x00000000 meta mark set meta mark & %[3]s | %[2]s counter name "sniff_resyn" comment "a redirected SYN that was not its connection's first: its own classification and the takeover bit"
    meta l4proto tcp meta mark & %[2]s == 0x00000000 meta mark set 0x00000000 comment "tcp_fwmark_accept is on: other listeners keep mark 0"
  }
`, validate.SniffListenPort, hexMark(markSniff), hexMark(markNoShare&^markSniff))
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
	writeSniffWGOuter(sb, outer, none)
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

var (
	sniffSpecUnitRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,60}\.service$`)
	sniffSpecUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	sniffSpecDirRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,60}$`)
	sniffSpecIfRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)
)

// Validate checks a spec before it is rendered (the verify subcommand takes
// its names from the command line). Paths the forwarder or the account unit
// use must be absolute and plain, and outside what their sandbox hides or
// cannot execute: /run, /dev/shm and /tmp, /var/tmp are noexec or private
// there; /home and /root are hidden (ProtectHome=yes).
func (s SniffUnitSpec) Validate() error {
	switch {
	case !sniffSpecUnitRe.MatchString(s.Unit) || !sniffSpecUnitRe.MatchString(s.AccountUnit) || s.Unit == s.AccountUnit:
		return fmt.Errorf("unit names: two different <name>.service, not %q and %q", s.Unit, s.AccountUnit)
	case !sniffSpecUserRe.MatchString(s.User) || s.User == "root":
		return fmt.Errorf("user: not an account name for this purpose: %q", s.User)
	case s.UID < 100 || s.UID > 65533:
		return fmt.Errorf("uid %d: 100..65533", s.UID)
	case !sniffSpecDirRe.MatchString(s.RuntimeDir):
		return fmt.Errorf("runtime directory name %q", s.RuntimeDir)
	case s.StateDir != "" && !sniffSpecDirRe.MatchString(s.StateDir):
		return fmt.Errorf("state directory name %q", s.StateDir)
	case len(s.Ports) == 0:
		return errors.New("no sniffed port")
	case s.FwmarkAcceptOn != "0" && s.FwmarkAcceptOn != "1" || s.FwmarkAcceptOff != "0" && s.FwmarkAcceptOff != "1":
		return errors.New("tcp_fwmark_accept values: 0 or 1")
	case s.NeighIf != "" && !sniffSpecIfRe.MatchString(s.NeighIf):
		return fmt.Errorf("interface %q", s.NeighIf)
	}
	if _, err := netip.ParseAddrPort(s.Listen); err != nil {
		return fmt.Errorf("listen %q: %v", s.Listen, err)
	}
	for _, p := range s.Ports {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("port %d", p)
		}
	}
	for _, p := range []struct{ name, path string }{
		{"account script", s.AccountScript}, {"binary", s.Binary}, {"snapshot", s.Snapshot}, {"targets", s.Targets}, {"lists dir", s.ListsDir},
	} {
		if err := sniffSpecPath(p.path); err != nil {
			return fmt.Errorf("%s: %v", p.name, err)
		}
	}
	return nil
}

func sniffSpecPath(p string) error {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, " \t\n\"'\\$%;") {
		return fmt.Errorf("%q is not a plain absolute path", p)
	}
	for _, bad := range []string{"/run", "/dev/shm", "/tmp", "/var/tmp", "/home", "/root"} {
		if p == bad || strings.HasPrefix(p, bad+"/") {
			return fmt.Errorf("%q is under %s (noexec, private or hidden in the units' sandbox)", p, bad)
		}
	}
	return nil
}
