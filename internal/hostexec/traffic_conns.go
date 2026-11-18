package hostexec

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Active connections of LAN and remote-access devices through the gateway,
// read by the same fixed, parameterless /v1/traffic action. Read-only: the
// ruleset is not changed (no ct mark bits are added, so relay sharing's ct
// mark usage and classification stay exactly as compiled).
//
// Source: /proc/net/nf_conntrack, or, when the kernel has no proc compat
// file, the fixed `conntrack -L -o extended`. Both print the original tuple
// first and the reply tuple second as key=value pairs.
//
// Classification of one entry (TCP in TIME_WAIT/CLOSE is not active and is
// skipped):
//   - original source is a local address: the gateway's own connection
//     (tunnels, wstunnel, DNS upstreams, probes, the sniff forwarder's
//     outbound leg): excluded.
//   - reply source is local: the connection terminates on the gateway. DNS
//     (port 53/853, hijacked or not), the panel, SSH and the remote-access
//     WireGuard port are excluded; a redirected TCP connection whose original
//     destination is not local is a sniff-forwarded LAN connection and counts
//     once, as "redirected" (its forwarder leg is excluded above, so no double
//     count). Its domestic/foreign side is decided by the forwarder, which
//     conntrack does not record, so it is in total only.
//   - reply destination is in the transit networks (10.66.200.0/24,
//     fd66:0:0:ff::/64): transit_snat gave it an exit/group mark's transit
//     address, so it is foreign.
//   - otherwise it is forwarded without transit NAT: domestic (direct via
//     ROS, the LAN, or LAN <-> remote access).
//
// Packet marks are not in conntrack and the ct mark carries only relay
// sharing bits, which is why the split is by reply tuple.

var (
	conntrackPath  = "/proc/net/nf_conntrack"
	localAddrsFunc = localAddrs
	transitNets    = []netip.Prefix{netip.MustParsePrefix("10.66.200.0/24"), netip.MustParsePrefix("fd66:0:0:ff::/64")}
)

// ConnCounts is the read of active connections. Domestic/Foreign/Total are
// nil when unknown (Error set). Redirected is part of Total only.
type ConnCounts struct {
	ReadAt     string `json:"read_at"`
	Source     string `json:"source,omitempty"` // proc | conntrack
	Domestic   *int   `json:"domestic"`
	Foreign    *int   `json:"foreign"`
	Redirected *int   `json:"redirected"`
	Total      *int   `json:"total"`
	Error      string `json:"error,omitempty"`
}

func localAddrs() (map[netip.Addr]bool, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	m := map[netip.Addr]bool{}
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			m[p.Addr().Unmap()] = true
		}
	}
	return m, nil
}

func inTransit(a netip.Addr) bool {
	for _, p := range transitNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type ctTuple struct {
	src, dst     netip.Addr
	sport, dport string
}

// parseConntrackLine returns the protocol, TCP state, original and reply
// tuples; ok is false for lines that are not entries.
func parseConntrackLine(line string) (proto, state string, orig, reply ctTuple, ok bool) {
	fs := strings.Fields(line)
	n, srcs := 0, 0
	for i, f := range fs {
		k, v, kv := strings.Cut(f, "=")
		if !kv {
			switch {
			case f == "tcp" || f == "udp" || f == "icmp" || f == "icmpv6" || f == "sctp" || f == "udplite" || f == "dccp" || f == "gre" || f == "unknown":
				if proto == "" && i+1 < len(fs) {
					proto = f
				}
			case proto == "tcp" && state == "" && n == 0 && strings.ToUpper(f) == f && !strings.HasPrefix(f, "[") && (f[0] < '0' || f[0] > '9'):
				state = f
			}
			continue
		}
		// The reply tuple starts at the second src=; sport/dport after the
		// original dst= still belong to the original tuple.
		if k == "src" {
			srcs++
		}
		t := &orig
		if srcs >= 2 {
			t = &reply
		}
		switch k {
		case "src", "dst":
			a, err := netip.ParseAddr(v)
			if err != nil {
				return "", "", orig, reply, false
			}
			if k == "src" {
				t.src = a.Unmap()
			} else {
				t.dst = a.Unmap()
			}
			n++
		case "sport":
			t.sport = v
		case "dport":
			t.dport = v
		}
	}
	return proto, state, orig, reply, proto != "" && n == 4
}

// CountConntrack classifies conntrack text (proc or `conntrack -L -o
// extended`) against the gateway's local addresses.
func CountConntrack(text string, local map[netip.Addr]bool) (domestic, foreign, redirected int) {
	for _, line := range strings.Split(text, "\n") {
		proto, state, o, r, ok := parseConntrackLine(line)
		if !ok || (proto == "tcp" && (state == "TIME_WAIT" || state == "CLOSE")) {
			continue
		}
		switch {
		case local[o.src]:
		case local[r.src]:
			if proto == "tcp" && !local[o.dst] && o.dport != "53" && o.dport != "853" {
				redirected++
			}
		case local[o.dst]:
		case inTransit(r.dst):
			foreign++
		default:
			domestic++
		}
	}
	return
}

// ConnStatus reads and counts the active connections.
func (a *Agent) ConnStatus(ctx context.Context) ConnCounts {
	a.init()
	c := ConnCounts{ReadAt: time.Now().UTC().Format(time.RFC3339Nano)}
	local, err := localAddrsFunc()
	if err != nil {
		c.Error = "读取本机地址失败：" + err.Error()
		return c
	}
	text, src := "", "proc"
	if b, err := os.ReadFile(conntrackPath); err == nil {
		text = string(b)
	} else {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		out, err2 := a.Runner.Run(ctx, "conntrack", "-L", "-o", "extended")
		if err2 != nil {
			c.Error = "读取连接跟踪表失败：" + err.Error() + "；备用命令 conntrack 也不可用（" + err2.Error() + "），请安装 conntrack 软件包（apt-get install conntrack，或重新运行 deploy/debian/install.sh）"
			return c
		}
		text, src = out, "conntrack"
	}
	d, f, r := CountConntrack(text, local)
	t := d + f + r
	c.Source, c.Domestic, c.Foreign, c.Redirected, c.Total = src, &d, &f, &r, &t
	return c
}
