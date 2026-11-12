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
	prioLANDrop     = 17850
	prioRelayFrom   = 18100
	prioHubExitFrom = 18200
)

func exitMark(index int) uint32 { return markExitBase + uint32(index) }

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
