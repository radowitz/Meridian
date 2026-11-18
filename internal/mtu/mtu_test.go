package mtu

import "testing"

func TestUDPOverhead(t *testing.T) {
	if got := UDPOverhead(4); got != 60 {
		t.Fatalf("IPv4 overhead %d, want 60 (20 IP + 8 UDP + 16 header + 16 tag)", got)
	}
	if got := UDPOverhead(6); got != 80 {
		t.Fatalf("IPv6 overhead %d, want 80", got)
	}
}

func TestPadding(t *testing.T) {
	for _, c := range []struct{ inner, mtu, want int }{
		{1408, 1420, 1408}, // multiple of 16: no padding
		{1409, 1420, 1420}, // 1424 capped at the MTU
		{1412, 1420, 1420},
		{1412, 1440, 1424},
		{1412, 0, 1424}, // no MTU known: no cap
		{1, 1420, 16},
		{0, 1420, 0},
		{1420, 1420, 1420},
	} {
		if got := Padded(c.inner, c.mtu); got != c.want {
			t.Errorf("Padded(%d, %d) = %d, want %d", c.inner, c.mtu, got, c.want)
		}
	}
}

// The measured case: an uplink of 1472, tunnel MTU 1420, outer IPv4. 1408
// passes (1468), 1412 does not (padded to 1420 by the cap → 1480; 1424 →
// 1484 without it); the largest safe tunnel MTU suggested is 1408.
func TestUplink1472(t *testing.T) {
	if got := UDPOuterLen(1408, 1420, 4); got != 1468 {
		t.Fatalf("outer of 1408: %d", got)
	}
	if got := UDPOuterLen(1412, 1420, 4); got <= 1472 {
		t.Fatalf("outer of 1412 = %d fits 1472", got)
	}
	if FitsUDP(1420, 1472, 4) {
		t.Fatal("1420 fits 1472 over IPv4")
	}
	if got := ShortfallUDP(1420, 1472, 4); got != 8 {
		t.Fatalf("shortfall %d, want 8", got)
	}
	if got := LargestInnerUDP(1420, 1472, 4); got != 1408 {
		t.Fatalf("largest inner %d, want 1408", got)
	}
	if got := SuggestUDP(1472, 4); got != 1408 {
		t.Fatalf("suggestion %d, want 1408", got)
	}
	if !FitsUDP(1408, 1472, 4) {
		t.Fatal("the suggestion does not fit")
	}
	// IPv6 outer: 80 bytes.
	if got := SuggestUDP(1472, 6); got != 1392 {
		t.Fatalf("IPv6 suggestion %d, want 1392", got)
	}
	if got := ShortfallUDP(1420, 1472, 6); got != 28 {
		t.Fatalf("IPv6 shortfall %d, want 28", got)
	}
	if got := LargestInnerUDP(1420, 1472, 6); got != 1392 {
		t.Fatalf("IPv6 largest inner %d", got)
	}
	// A normal uplink carries the defaults.
	for _, m := range []int{1420, 1412, 1360} {
		if !FitsUDP(m, 1500, 4) {
			t.Fatalf("%d does not fit 1500", m)
		}
	}
	if !FitsUDP(1420, 1500, 6) || FitsUDP(1440, 1500, 6) {
		t.Fatal("IPv6 1500: 1420 must fit, 1440 must not")
	}
	if got := SuggestUDP(1500, 4); got != 1440 {
		t.Fatalf("1500 suggestion %d", got)
	}
	if got := SuggestUDP(1500, 6); got != 1408 {
		t.Fatalf("1500 IPv6 suggestion %d", got)
	}
}

// Padding boundaries, checked against a brute force over every inner size.
func TestLargestInnerBruteForce(t *testing.T) {
	for _, fam := range []int{4, 6} {
		for _, m := range []int{1280, 1360, 1400, 1408, 1412, 1419, 1420, 1440} {
			for u := 1300; u <= 1520; u++ {
				want := 0
				for l := 1; l <= m; l++ {
					if UDPOuterLen(l, m, fam) <= u {
						want = l
					}
				}
				// Outer lengths are monotonic in the inner size, so the
				// largest fitting size is the boundary.
				if got := LargestInnerUDP(m, u, fam); got != want {
					t.Fatalf("LargestInnerUDP(%d, %d, %d) = %d, brute force %d", m, u, fam, got, want)
				}
				if FitsUDP(m, u, fam) != (want == m) {
					t.Fatalf("FitsUDP(%d, %d, %d) disagrees with the brute force", m, u, fam)
				}
				s := SuggestUDP(u, fam)
				if s > 0 && (!FitsUDP(s, u, fam) || s%16 != 0 || FitsUDP(s+16, u, fam)) {
					t.Fatalf("SuggestUDP(%d, %d) = %d is not the largest fitting multiple of 16", u, fam, s)
				}
			}
		}
	}
}

func TestWSSEstimate(t *testing.T) {
	e := WSS(1360, 1472, 4)
	if e.Datagram != 1360+32 || !e.LoopbackFits {
		t.Fatalf("datagram %+v", e)
	}
	if e.Stream != 1392+WSFrameMax+TLSRecordMax {
		t.Fatalf("stream %d", e.Stream)
	}
	if e.MSS != 1472-20-20-12 || e.Segments != 2 {
		t.Fatalf("mss/segments %+v", e)
	}
	// An uplink MTU never makes a WSS leg "not fit": it only changes the
	// segment count.
	if e6 := WSS(1360, 1472, 6); e6.MSS != 1472-40-20-12 || e6.Segments != 2 {
		t.Fatalf("IPv6 %+v", e6)
	}
	if e0 := WSS(1360, 0, 4); e0.MSS != 0 || e0.Segments != 0 {
		t.Fatalf("unknown uplink %+v", e0)
	}
	// Padding applies to the WSS leg's datagram as well (capped at the MTU).
	if WSS(1361, 1500, 4).Datagram != 1361+32 || WSS(1350, 1500, 4).Datagram != 1350+32 || Padded(1350, 1400) != 1360 {
		t.Fatal("WSS datagram padding")
	}
}

func TestCarrierRouteArg(t *testing.T) {
	c := Carrier{LinkID: "l1", Mode: ModeUDP, Iface: "m01", Family: 4, Peer: "192.0.2.10"}
	if c.RouteArg() != "route4:192.0.2.10" || c.Key() != "l1/udp" {
		t.Fatal(c.RouteArg(), c.Key())
	}
	c6 := Carrier{Family: 6, Peer: "2001:db8::1"}
	if c6.RouteArg() != "route6:2001:db8::1" {
		t.Fatal(c6.RouteArg())
	}
	if (Carrier{Family: 4}).RouteArg() != "" {
		t.Fatal("no peer: no route argument")
	}
	d := c
	d.TunnelMTU = 1408
	if !c.SamePlan(d) {
		t.Fatal("a different tunnel MTU is the same uplink question")
	}
	d.Peer = "192.0.2.11"
	if c.SamePlan(d) {
		t.Fatal("another peer is another question")
	}
}

// A WireGuard leg carried over a Cloudflare Mesh path: the Mesh path less
// WireGuard's overhead. Over the default path (1280) that is below IPv6's
// minimum: the interface stays at 1280 and the payload is what such an
// interface sends without fragmenting the outer packet (a multiple of 16,
// because the padding is only capped at the interface MTU).
func TestMeshLeg(t *testing.T) {
	for _, c := range []struct{ path, family, payload, device int }{
		{0, 4, 1216, 1280}, // default MeshPath
		{1280, 4, 1216, 1280},
		{1280, 6, 1200, 1280}, // 1280 - 80 is a multiple of 16
		{1300, 4, 1232, 1280},
		{1339, 4, 1264, 1280},
		{1340, 4, 1280, 1280}, // exactly MinTunnel + overhead: no fragment
		{1360, 6, 1280, 1280},
		{1420, 4, 1360, 1360},
		{1500, 4, 1440, 1440},
		{50, 4, 0, 1280},
	} {
		payload, device := MeshLeg(c.path, c.family)
		if payload != c.payload || device != c.device {
			t.Errorf("MeshLeg(%d, %d) = %d, %d; want %d, %d", c.path, c.family, payload, device, c.payload, c.device)
		}
		path := c.path
		if path <= 0 {
			path = MeshPath
		}
		// The payload always fits the Mesh path unfragmented on an interface
		// of the device MTU, and it is the largest inner packet that does.
		if payload > 0 && UDPOuterLen(payload, device, c.family) > path {
			t.Errorf("MeshLeg(%d, %d): payload %d needs an outer packet of %d", c.path, c.family, payload, UDPOuterLen(payload, device, c.family))
		}
		if payload < device && UDPOuterLen(payload+1, device, c.family) <= path {
			t.Errorf("MeshLeg(%d, %d): %d would still fit", c.path, c.family, payload+1)
		}
		if got := MeshLegFragments(c.path, c.family); got != (payload < device) {
			t.Errorf("MeshLegFragments(%d, %d) = %v", c.path, c.family, got)
		}
		if device < MinTunnel {
			t.Errorf("MeshLeg(%d, %d): device %d below the IPv6 minimum", c.path, c.family, device)
		}
	}
	// The default: 1280 - 60 = 1220; TCP clamps to 1216 - 40 / - 60.
	if MeshPath-UDPOverhead(4) != 1220 {
		t.Fatal("the Mesh path less WireGuard's IPv4 overhead is not 1220")
	}
}
