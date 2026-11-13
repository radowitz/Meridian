package compile

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// remotePlan is the compiled remote-access entrance (docs/architecture.md
// 「远程接入」). nil when disabled: every renderer then emits exactly what it
// emitted before the feature existed.
type remotePlan struct {
	Iface    string
	V4, V6   netip.Prefix
	GW4, GW6 netip.Addr
	Port     int
	MTU      int
	KeyID    string
	// Devices are the enabled devices, sorted by ID. Disabled and deleted
	// devices are absent, so wg syncconf removes their peers.
	Devices []model.RemoteDevice
}

func planRemote(t model.Topology) *remotePlan {
	ra := t.RemoteAccess
	if !ra.Active() {
		return nil
	}
	gw4, p4, ok4 := ra.GatewayV4()
	gw6, p6, ok6 := ra.GatewayV6()
	if !ok4 || !ok6 {
		return nil
	}
	rp := &remotePlan{Iface: model.RemoteAccessIface, V4: p4, V6: p6, GW4: gw4, GW6: gw6,
		Port: ra.ListenPort, MTU: ra.EffectiveMTU(), KeyID: ra.KeyID}
	for _, d := range ra.Devices {
		if d.Enabled {
			rp.Devices = append(rp.Devices, d)
		}
	}
	sort.Slice(rp.Devices, func(i, j int) bool { return rp.Devices[i].ID < rp.Devices[j].ID })
	return rp
}

// MSS for TCP through mra: its MTU minus the IPv4/IPv6 + TCP headers.
func (rp *remotePlan) mss4() int { return rp.MTU - 40 }
func (rp *remotePlan) mss6() int { return rp.MTU - 60 }

// renderRemoteWG is /etc/wireguard/mra.conf. The private key and every
// pre-shared key are placeholders; only the install boundary
// (apply.Applier.Secrets) replaces them.
func renderRemoteWG(rp *remotePlan) string {
	var sb strings.Builder
	sb.WriteString("# meridian remote access: road-warrior devices; treated like the LAN by the guard.\n")
	sb.WriteString("# Table=off: routes for the device pools are installed by meridian-routes.sh.\n")
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", model.SecretPlaceholder(rp.KeyID))
	fmt.Fprintf(&sb, "Address = %s/%d, %s/%d\n", rp.GW4, rp.V4.Bits(), rp.GW6, rp.V6.Bits())
	fmt.Fprintf(&sb, "MTU = %d\n", rp.MTU)
	sb.WriteString("Table = off\n")
	fmt.Fprintf(&sb, "FwMark = %#x\n", markUnderlay)
	fmt.Fprintf(&sb, "ListenPort = %d\n", rp.Port)
	for _, d := range rp.Devices {
		sb.WriteString("\n[Peer]\n")
		fmt.Fprintf(&sb, "# peer-node device:%s\n", d.ID)
		fmt.Fprintf(&sb, "PublicKey = %s\n", d.PublicKey)
		if d.PSKID != "" {
			fmt.Fprintf(&sb, "PresharedKey = %s\n", model.SecretPlaceholder(d.PSKID))
		}
		fmt.Fprintf(&sb, "AllowedIPs = %s/32, %s/128\n", d.IPv4, d.IPv6)
	}
	return sb.String()
}

// remoteUpCommands runs right after the WireGuard loop: syncconf does not
// change addresses or MTU, so align them with the config, drop any other
// global address (an old pool) and turn on IPv6 forwarding for mra (it may
// not have existed when forwarding.conf was applied).
func remoteUpCommands(rp *remotePlan) string {
	return strings.NewReplacer(
		"@IF@", rp.Iface,
		"@A4@", fmt.Sprintf("%s/%d", rp.GW4, rp.V4.Bits()),
		"@A6@", fmt.Sprintf("%s/%d", rp.GW6, rp.V6.Bits()),
		"@MTU@", fmt.Sprint(rp.MTU),
	).Replace(`# remote access: align mra with its config (wg syncconf keeps addresses and MTU).
ip link set dev @IF@ mtu @MTU@
ip address replace @A4@ dev @IF@
ip -6 address replace @A6@ dev @IF@ nodad
ra_addrs=$(ip -o address show dev @IF@ scope global) || ra_addrs=""
while read -r _ _ _ ra_a _; do
  case "$ra_a" in ''|@A4@|@A6@) continue ;; esac
  ip address del "$ra_a" dev @IF@ || echo "meridian-remote: could not remove stale $ra_a" >&2
done <<< "$ra_addrs"
ip link set dev @IF@ up
sysctl -w net.ipv6.conf.@IF@.forwarding=1 >/dev/null
`)
}

// remoteRouteCommands: the device pools are on-link on mra in main (tunnel
// replies, unmarked) and in table 100 (domestic-marked: LAN to device, and
// direct replies from ROS after de-NAT). Each has a metric-32767 blackhole,
// so with mra gone nothing falls through to ROS. There is no "iif mra
// unreachable" rule (see removeStaleIIFRules): the guard table drops
// unclassified traffic from mra.
func remoteRouteCommands(sb *strings.Builder, rp *remotePlan) {
	ifQ := shQuote(rp.Iface)
	fmt.Fprintf(sb, "# remote access %s: pools %s %s\n", rp.Iface, rp.V4, rp.V6)
	for _, tbl := range []string{"", " table 100"} {
		fmt.Fprintf(sb, "ip route replace %s dev %s%s\n", rp.V4, ifQ, tbl)
		fmt.Fprintf(sb, "ip route replace blackhole %s metric 32767%s\n", rp.V4, tbl)
		fmt.Fprintf(sb, "ip -6 route replace %s dev %s%s\n", rp.V6, ifQ, tbl)
		fmt.Fprintf(sb, "ip -6 route replace blackhole %s metric 32767%s\n", rp.V6, tbl)
	}
}

// removeStaleIIFRules deletes the IPv4 "iif <LAN> unreachable" (17850) and
// "iif mra unreachable" (17851) rules older versions installed, by
// priority, interface and action, so nothing else is touched; del_rule
// makes it idempotent. It runs whether remote access is on or off, so a
// gateway that had it on also loses the mra rule. The mra name is written
// unquoted: it is a fixed identifier, and a quoted 'mra' in a gateway
// without remote access is what the leak check treats as a leftover.
func removeStaleIIFRules(sb *strings.Builder, lanQ string) {
	fmt.Fprintf(sb, "del_rule ip -4 rule del priority %d iif %s unreachable\n", prioStaleLANDrop, lanQ)
	fmt.Fprintf(sb, "del_rule ip -4 rule del priority %d iif %s unreachable\n", prioStaleRemoteDrop, model.RemoteAccessIface)
}
