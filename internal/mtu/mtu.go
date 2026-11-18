// Package mtu is the one place that knows how much a tunnel carrier adds to
// an inner packet and, from that, which tunnel MTU an uplink can carry. The
// preflight evaluation (internal/preflight), the panel's uplink suggestions
// (internal/api) and the namespace tests all use it; nothing else computes
// a WireGuard overhead on its own.
//
// It also defines Carrier: one tunnel leg as it leaves one node (the
// interface, the outer address family and the address the outer packets
// are sent to), which compile derives from the topology and the preflight
// uses to ask the host which uplink those packets take.
//
// The package is pure: no I/O, no other Meridian package.
package mtu

import "fmt"

// Header sizes, in bytes.
const (
	IPv4Header = 20
	IPv6Header = 40
	UDPHeader  = 8
	TCPHeader  = 20
	// WGDataHeader is a WireGuard transport data message's header (type 4,
	// reserved 3, receiver index 4, counter 8); WGTag the ChaCha20-Poly1305
	// tag after the ciphertext.
	WGDataHeader = 16
	WGTag        = 16
	// WGPadding: the plaintext is padded to a multiple of 16 before
	// encryption, but never beyond the WireGuard interface's MTU (Linux
	// drivers/net/wireguard/send.c calculate_skb_padding; wireguard-go
	// calculatePaddingSize does the same).
	WGPadding = 16
	// MinTunnel is the smallest tunnel MTU Meridian accepts: IPv6's minimum
	// link MTU (validate refuses anything lower).
	MinTunnel = 1280
	// Loopback is the default MTU of lo, which the WireGuard UDP of a WSS
	// leg crosses on its way to the local wstunnel client.
	Loopback = 65536
)

// Carrier modes.
const (
	ModeUDP = "udp"
	ModeWSS = "wss"
)

// IPHeader is the IP header of the given family (4 or 6).
func IPHeader(family int) int {
	if family == 6 {
		return IPv6Header
	}
	return IPv4Header
}

// UDPOverhead is what WireGuard over UDP adds to a padded inner packet:
// outer IP + UDP + data header + tag. 60 over IPv4, 80 over IPv6.
func UDPOverhead(family int) int {
	return IPHeader(family) + UDPHeader + WGDataHeader + WGTag
}

// Padded is the plaintext length WireGuard encrypts for an inner packet of
// inner bytes on an interface of MTU tunnelMTU: rounded up to 16, but not
// beyond the MTU (tunnelMTU <= 0: no cap).
func Padded(inner, tunnelMTU int) int {
	p := (inner + WGPadding - 1) / WGPadding * WGPadding
	if tunnelMTU > 0 && p > tunnelMTU {
		p = tunnelMTU
	}
	return p
}

// UDPOuterLen is the length of the outer IP packet that carries an inner
// packet of inner bytes through a WireGuard interface of MTU tunnelMTU
// over UDP of the given outer family.
func UDPOuterLen(inner, tunnelMTU, family int) int {
	return Padded(inner, tunnelMTU) + UDPOverhead(family)
}

// FitsUDP reports whether every inner packet a WireGuard interface of MTU
// tunnelMTU may send fits an uplink of MTU underlay without fragmentation:
// the largest inner packet is tunnelMTU itself, padded to at most the MTU.
func FitsUDP(tunnelMTU, underlay, family int) bool {
	return UDPOuterLen(tunnelMTU, tunnelMTU, family) <= underlay
}

// ShortfallUDP is by how many bytes the outer packet of a full-size inner
// packet exceeds the uplink (0 when it fits).
func ShortfallUDP(tunnelMTU, underlay, family int) int {
	if d := UDPOuterLen(tunnelMTU, tunnelMTU, family) - underlay; d > 0 {
		return d
	}
	return 0
}

// LargestInnerUDP is the largest inner packet (at most tunnelMTU) whose
// outer packet still fits underlay; 0 when none does. With the padding
// this is a multiple of 16 whenever the tunnel MTU is too large: an uplink
// of 1472 over IPv4 carries inner packets up to 1408 (1408 → 1468) while
// 1412 is padded to 1424 (or to the MTU, 1420) and needs 1484 (1480).
func LargestInnerUDP(tunnelMTU, underlay, family int) int {
	if tunnelMTU <= 0 || underlay <= 0 {
		return 0
	}
	if FitsUDP(tunnelMTU, underlay, family) {
		return tunnelMTU
	}
	// The MTU does not fit, so the cap at the MTU never applies below it:
	// the padded size must be at most underlay - overhead.
	n := floor16(underlay - UDPOverhead(family))
	if n > tunnelMTU {
		n = tunnelMTU
	}
	if n < 0 {
		return 0
	}
	return n
}

// SuggestUDP is the tunnel MTU Meridian suggests for an uplink of MTU
// underlay: the largest multiple of 16 not above underlay - overhead. A
// multiple of 16 is never padded, so the suggestion holds whether or not
// an implementation caps the padding at the MTU (1472 over IPv4 → 1408,
// over IPv6 → 1392; 1500 → 1440 / 1420). It may be below MinTunnel: the
// uplink then cannot carry a UDP tunnel Meridian accepts.
func SuggestUDP(underlay, family int) int {
	if underlay <= 0 {
		return 0
	}
	n := floor16(underlay - UDPOverhead(family))
	if n < 0 {
		return 0
	}
	return n
}

// MeshPath is the default path MTU of a Cloudflare Mesh hop: the MTU of the
// WARP device the Mesh node forwards through.
const MeshPath = 1280

// MeshLeg is the MTU of a WireGuard leg whose outer UDP packets cross a
// Cloudflare Mesh path of MTU meshPath to an underlay address of the given
// family (meshPath <= 0: MeshPath).
//
// The Mesh path leaves meshPath minus UDPOverhead for the inner packet
// (1280 → 1220 over IPv4, 1200 over IPv6). When that is at least MinTunnel
// the interface simply gets it: payload and device are equal (a Mesh path
// of 1340 over IPv4 gives 1280 / 1280).
//
// Below MinTunnel the interface cannot follow: Linux refuses IPv6 on a
// device below 1280, and Meridian's resolver addresses are IPv6. device
// then stays at MinTunnel, and payload is the largest inner packet whose
// outer packet still fits the Mesh path unfragmented on such an interface
// (LargestInnerUDP: WireGuard pads the plaintext to a multiple of 16 and
// only caps the padding at the interface MTU, so 1217…1220 would be padded
// to 1232 and need 1292): 1216 over the default path. payload is the hop
// MTU the path MTU and every MSS clamp use, so TCP never needs a
// fragment; an inner packet between payload and device (large UDP, never
// clamped TCP) is carried by fragmenting WireGuard's outer packet, which
// WireGuard sends without DF.
func MeshLeg(meshPath, family int) (payload, device int) {
	if meshPath <= 0 {
		meshPath = MeshPath
	}
	raw := meshPath - UDPOverhead(family)
	if raw >= MinTunnel {
		return raw, raw
	}
	return LargestInnerUDP(MinTunnel, meshPath, family), MinTunnel
}

// MeshLegFragments reports whether a Mesh leg over a path of MTU meshPath
// relies on fragmenting the outer packet for its largest inner packets
// (payload below the interface MTU).
func MeshLegFragments(meshPath, family int) bool {
	payload, device := MeshLeg(meshPath, family)
	return payload < device
}

func floor16(n int) int {
	if n < 0 {
		return n
	}
	return n / WGPadding * WGPadding
}

// WSS framing, in bytes. A WSS leg's WireGuard datagrams go to wstunnel on
// 127.0.0.1; wstunnel sends each as one WebSocket binary frame inside TLS
// over TCP to the listener.
const (
	// WSFrameMax is the largest WebSocket frame header for a payload of
	// 126…65535 bytes: 2 + 2 (extended length) + 4 (client mask).
	WSFrameMax = 8
	// TLSRecordMax is a TLS 1.3 AEAD record's overhead: 5 header + 1 inner
	// content type + 16 tag. TLS 1.2 or other ciphers differ by a few
	// bytes; this is an estimate, not a bound.
	TLSRecordMax = 22
	// TCPOptions is room for the TCP timestamp option (12 bytes with
	// padding) that Linux sends by default.
	TCPOptions = 12
)

// WSSEstimate is what a WSS leg looks like on the uplink. It is an
// estimate: TCP segments the stream to the uplink's MSS, so the uplink MTU
// never makes a WSS leg drop packets the way it does a UDP leg; it only
// decides how many segments one tunnel packet becomes. TLS may coalesce or
// split records and the kernel may use other TCP options, so the segment
// count can differ by one.
type WSSEstimate struct {
	// Datagram is the largest WireGuard message the leg sends (padded
	// inner + header + tag) to the local wstunnel.
	Datagram int `json:"datagram"`
	// LoopbackFits: that datagram fits lo (always, for any tunnel MTU
	// Meridian accepts).
	LoopbackFits bool `json:"loopback_fits"`
	// Stream is the estimated bytes on the TCP stream for that datagram
	// (WebSocket frame header + TLS record overhead added).
	Stream int `json:"stream"`
	// MSS is the TCP payload per segment on the uplink (uplink MTU − IP −
	// TCP − timestamp option); Segments the estimated segments per
	// full-size tunnel packet.
	MSS      int `json:"mss"`
	Segments int `json:"segments"`
}

// WSS estimates a WSS leg of tunnel MTU tunnelMTU over an uplink of MTU
// underlay (outer family family). underlay <= 0: MSS and Segments are 0.
func WSS(tunnelMTU, underlay, family int) WSSEstimate {
	d := Padded(tunnelMTU, tunnelMTU) + WGDataHeader + WGTag
	e := WSSEstimate{Datagram: d, LoopbackFits: d+IPv4Header+UDPHeader <= Loopback, Stream: d + WSFrameMax + TLSRecordMax}
	if underlay > 0 {
		e.MSS = underlay - IPHeader(family) - TCPHeader - TCPOptions
		if e.MSS > 0 {
			e.Segments = (e.Stream + e.MSS - 1) / e.MSS
		}
	}
	return e
}

// Carrier is one tunnel leg as seen from one of its nodes: which interface
// it is, how its packets leave the host and what limits them.
type Carrier struct {
	LinkID   string `json:"link_id"`
	LinkName string `json:"link_name,omitempty"`
	// Iface is the WireGuard interface of the leg on this node.
	Iface string `json:"iface"`
	// Mode: udp (WireGuard's UDP is the carrier) or wss (wstunnel's TCP
	// is; WireGuard's UDP only reaches 127.0.0.1).
	Mode string `json:"mode"`
	// Family is the outer address family (4 or 6).
	Family int `json:"family"`
	// Peer is the address the outer packets (or wstunnel's TCP) go to, an
	// IP literal; "" when it is not known in advance (the other end dials
	// in from an address the topology does not fix, or is a DNS name):
	// the uplink is then the default route of Family.
	Peer string `json:"peer,omitempty"`
	// PeerNode is the node at the other end; PeerWhy says why Peer is
	// empty.
	PeerNode string `json:"peer_node,omitempty"`
	PeerWhy  string `json:"peer_why,omitempty"`
	// Dials: this node opens the leg (WireGuard Endpoint or wstunnel
	// client); false: it listens.
	Dials bool `json:"dials"`
	// Mark is the fwmark the outer packets carry on this node ("" none):
	// the gateway's WireGuard sockets carry the underlay mark, so the
	// route lookup must use it.
	Mark string `json:"mark,omitempty"`
	// TunnelMTU is the leg's effective WireGuard MTU; Field the link field
	// that sets it ("mtu" or "wss_mtu"); Configured that field's value (0:
	// the transport default).
	TunnelMTU  int    `json:"tunnel_mtu"`
	Field      string `json:"field"`
	Configured int    `json:"configured,omitempty"`
}

// Key identifies the leg (a failover link has a udp and a wss leg).
func (c Carrier) Key() string { return c.LinkID + "/" + c.Mode }

// RouteArg is the preflight argument that asks the host for the route to
// Peer ("route4:<IPv4>" / "route6:<IPv6>"), "" without a Peer.
func (c Carrier) RouteArg() string {
	if c.Peer == "" {
		return ""
	}
	return fmt.Sprintf("route%d:%s", c.Family, c.Peer)
}

// SamePlan reports whether two carriers describe the same uplink question
// (leg, interface, family, peer, mark): an observation made for one is
// valid for the other whatever their tunnel MTUs.
func (c Carrier) SamePlan(o Carrier) bool {
	return c.LinkID == o.LinkID && c.Mode == o.Mode && c.Iface == o.Iface && c.Family == o.Family && c.Peer == o.Peer && c.Mark == o.Mark
}
