package compile

import "strings"

// Marks Meridian installs. Exit marks are 0x101 and up, one per exit.
// 0x4d72 is reserved for the ciphertext of the gateway's own WireGuard
// sockets so an fwmark rule cannot feed that packet back into the tunnel.
// 0x64 is domestic traffic, forwarded to ROS.
const (
	markUnderlay uint32 = 0x4d72
	markDomestic uint32 = 0x64
	markExitBase uint32 = 0x101
)

// Priorities sit well above the local table (0) and well below main
// (32766). The low hundreds are left alone: existing Shadowsocks policy
// rules on a VPS often use them, and these scripts also run there.
const (
	prioUnderlay    = 17000
	prioDomestic    = 17100
	prioExitBase    = 17200
	prioExitDrop    = 17600
	prioRelayFrom   = 18100
	prioHubExitFrom = 18200
)

// Priorities of the IPv4 "iif <LAN> unreachable" and "iif mra unreachable"
// rules older versions installed. They broke source validation of IPv4
// forwarded out of the LAN NIC or mra and are no longer generated; the
// routes script deletes them, and the verify script fails if they are back.
const (
	prioStaleLANDrop    = 17850
	prioStaleRemoteDrop = 17851
)

// Mesh ingress of region-group resolver queries on an exit (render_nft.go
// writeGroupResolverDNAT, render_routes.go meshDNSReturnShell). A query to
// the resolver range that arrives on mmesh gets ct mark markMeshDNS; its
// source is rewritten on input to meshDNSAnchor, an address of the
// reserved fd66::/64 that no node owns, so the resolver's reply has a
// route at the socket (rule "to meshDNSAnchor lookup tableMeshDNS");
// every reply packet of such a connection carries markMeshDNS (rule
// "fwmark markMeshDNS lookup tableMeshDNS"), so after conntrack restores
// the original destination it still leaves on mmesh. tableMeshDNS holds
// only "default via <sidecar> dev mmesh" while the sidecar is sealed and a
// blackhole: never the hub tunnel, never the WAN.
const (
	markMeshDNS   uint32 = 0x4d6d
	tableMeshDNS         = 171
	prioMeshDNS          = 17050
	meshDNSAnchor        = "fd66::4d:1"
)

func exitMark(index int) uint32 { return markExitBase + uint32(index) }

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Per-hub return paths on an exit with a backup hub (render_dualhub.go).
// Every original-direction packet arriving on the exit's tunnel from a hub
// sets the connection's ct mark to that hub's mark; every reply packet of
// the connection (forwarded from the WAN, or answered locally such as a
// resolver query) carries it as fwmark and is routed by that hub's table,
// which only holds the home prefixes on that hub's tunnel and a blackhole.
// A connection's replies therefore leave through the hub it last arrived
// from, never through the other hub, never out of the WAN.
const (
	markHubReturnPrimary  uint32 = 0x4d50
	markHubReturnBackup   uint32 = 0x4d51
	tableHubReturnPrimary        = 172
	tableHubReturnBackup         = 173
	prioHubReturn                = 17060 // primary; backup is 17061
)
