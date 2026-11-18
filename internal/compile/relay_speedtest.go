package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// The relays' download speed-test endpoint (docs/architecture.md
// 「多中继同时分担」, pathquality/speedtest.go). Only with relay sharing and
// speed tests on; every sharing relay gets:
//
//   - SpeedSocketUnit: a systemd socket that listens only on the relay's
//     tunnel addresses toward the gateway (FreeBind: before the interface
//     is up), port pathquality.SpeedPort, one connection per instance
//     (Accept=yes, at most two at a time), and lets only the gateway's
//     tunnel addresses connect (IPAddressDeny=any + IPAddressAllow).
//   - SpeedServiceUnit: the per-connection service. It writes exactly
//     speed_test_mb MiB of zeros to the connection and exits: it reads
//     nothing (no URL, path, size or command), runs as a dynamic user with
//     no privileges, a read-only system, bounded memory and run time.
//   - chain speedtest_in in its nft table: the port is accepted only from
//     the gateway's tunnel address on the matching leg to the relay's
//     address, and dropped for everything else (IPv4 and IPv6, every
//     interface: public, LAN or forwarded clients).
//
// The gateway drops forwarded traffic to those addresses and port
// (share_forward), so a LAN or remote-access client cannot trigger a test
// through the tunnel either. meridian-up.sh enables and restarts the
// socket; the provision installs it like any other unit, and a withdraw
// stops and removes it with the node.

const (
	SpeedSocketUnit  = "meridian-speedtest.socket"
	SpeedServiceUnit = "meridian-speedtest@.service"
)

// speedLeg is one gateway→relay tunnel of the speed test.
type speedLeg struct {
	Iface  string // the relay's interface
	Local  string // the gateway's address
	Remote string // the relay's address (bound)
}

// speedTestOn: the topology compiles the speed-test endpoint.
func speedTestOn(t model.Topology, p *sharePlan) bool {
	return p != nil && !t.Settings.PathQuality.Effective().SpeedTestOff
}

// relaySpeedLegs is relay id's legs from the gateway (nil when the relay
// does not share, or the speed tests are off).
func relaySpeedLegs(t model.Topology, p *sharePlan, id string) []speedLeg {
	if !speedTestOn(t, p) {
		return nil
	}
	for _, r := range p.Relays {
		if r.Node.ID != id {
			continue
		}
		var out []speedLeg
		for _, l := range r.Legs {
			out = append(out, speedLeg{Iface: l.Iface(), Local: l.WestV4, Remote: l.EastV4})
		}
		return out
	}
	return nil
}

func speedBytes(t model.Topology) int64 {
	return int64(t.Settings.PathQuality.Effective().SpeedTestMB) << 20
}

func renderSpeedSocket(legs []speedLeg) string {
	var sb strings.Builder
	sb.WriteString("[Unit]\nDescription=Meridian relay speed-test endpoint (tunnel addresses only)\n\n[Socket]\n")
	for _, l := range legs {
		fmt.Fprintf(&sb, "ListenStream=%s:%d\n", l.Remote, pathquality.SpeedPort)
	}
	sb.WriteString("FreeBind=yes\nAccept=yes\nMaxConnections=2\nMaxConnectionsPerSource=1\nIPAddressDeny=any\n")
	for _, l := range legs {
		fmt.Fprintf(&sb, "IPAddressAllow=%s/32\n", l.Local)
	}
	sb.WriteString("\n[Install]\nWantedBy=sockets.target\n")
	return sb.String()
}

func renderSpeedService(bytes int64) string {
	return fmt.Sprintf(`[Unit]
Description=Meridian relay speed test: a fixed %d MiB download, no input

[Service]
Type=simple
ExecStart=/usr/bin/head -c %d /dev/zero
StandardInput=socket
StandardOutput=socket
StandardError=journal
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX
MemoryMax=32M
TasksMax=4
RuntimeMaxSec=%d
`, bytes>>20, bytes, int(pathquality.SpeedTimeout.Seconds())+30)
}

// writeSpeedTestNFT is the relay's chain speedtest_in.
func writeSpeedTestNFT(sb *strings.Builder, legs []speedLeg) {
	if len(legs) == 0 {
		return
	}
	sb.WriteString("  chain speedtest_in {\n    type filter hook input priority filter - 5; policy accept;\n")
	for _, l := range legs {
		fmt.Fprintf(sb, "    iifname \"%s\" ip saddr %s ip daddr %s tcp dport %d accept comment \"speed test: the gateway on this leg only\"\n", l.Iface, l.Local, l.Remote, pathquality.SpeedPort)
	}
	fmt.Fprintf(sb, "    tcp dport %d drop comment \"speed-test endpoint: nothing else (public, LAN, forwarded, IPv6)\"\n  }\n", pathquality.SpeedPort)
}

// writeGatewaySpeedGuard: forwarded traffic never reaches a relay's
// endpoint (only the gateway's own test, which is not forwarded).
func writeGatewaySpeedGuard(sb *strings.Builder, t model.Topology, p *sharePlan) {
	if !speedTestOn(t, p) {
		return
	}
	var addrs []string
	for _, r := range p.Relays {
		for _, l := range r.Legs {
			addrs = append(addrs, l.EastV4)
		}
	}
	fmt.Fprintf(sb, "    ip daddr { %s } tcp dport %d drop comment \"relay speed-test endpoints: not for forwarded clients\"\n", strings.Join(addrs, ", "), pathquality.SpeedPort)
}

// relaySpeedFiles adds the endpoint's units to a sharing relay's files.
func relaySpeedFiles(t model.Topology, n model.Node, tunnels []Tunnel, add func(path, content string)) {
	if n.Role != model.RoleRelay {
		return
	}
	legs := relaySpeedLegs(t, planShare(t, tunnels), n.ID)
	if len(legs) == 0 {
		return
	}
	add("etc/systemd/system/"+SpeedSocketUnit, renderSpeedSocket(legs))
	add("etc/systemd/system/"+SpeedServiceUnit, renderSpeedService(speedBytes(t)))
}
