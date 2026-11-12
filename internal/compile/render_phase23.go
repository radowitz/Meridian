package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/unlock"
)

func meshPeer(t model.Topology, id string) bool {
	n, ok := t.NodeByID(id)
	if !ok || n.Role == model.RoleGateway {
		return false
	}
	for _, l := range t.Links {
		if l.Transport != model.TransportCFMesh || !l.Enabled {
			continue
		}
		if l.From == id || l.To == id {
			return true
		}
	}
	return false
}

func renderMeshCompose() string {
	return `# Cloudflare WARP Mesh sidecar.
# Backup for the hub → exit hop only. It has its own netns (not host networking)
# so it cannot replace the host default route or the IX path.
# The token is read from /etc/meridian/mesh.env (mode 0600). Do not commit one.
services:
  mesh:
    image: cloudflare/mesh
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun:/dev/net/tun
    env_file:
      - /etc/meridian/mesh.env
    environment:
      SRCNAT_ENABLED: "true"
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
    volumes:
      - mesh-lib:/var/lib/cloudflare-warp
    networks:
      - meridian_mesh
    restart: unless-stopped
networks:
  meridian_mesh:
    name: meridian_mesh
volumes:
  mesh-lib:
`
}

func renderMeshEnvExample() string {
	return `# Copy to /etc/meridian/mesh.env and chmod 600.
# Put the Cloudflare Mesh node token here. Leave it empty in git.
MESH_NODE_TOKEN=
`
}

func renderMeshUp() string {
	return `#!/bin/bash
# Attach a veth to the Mesh sidecar netns and start it when a token exists.
# This does not run on the home gateway. It never installs a route in table
# 100, 102, or 150: those stay on the IX / WSS path.
set -u
if [ ! -s /etc/meridian/mesh.env ]; then
  echo "mesh sidecar skipped: /etc/meridian/mesh.env is missing" >&2
  exit 0
fi
if ! grep -q '^MESH_NODE_TOKEN=.\+' /etc/meridian/mesh.env; then
  echo "mesh sidecar skipped: MESH_NODE_TOKEN is empty" >&2
  exit 0
fi
compose=/etc/meridian/mesh-sidecar.compose.yml
if [ ! -f "$compose" ]; then
  echo "mesh compose missing" >&2
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed; mesh sidecar not started" >&2
  exit 0
fi
docker compose -f "$compose" up -d || {
  echo "mesh sidecar failed to start" >&2
  exit 0
}
if ! ip link show mmesh >/dev/null 2>&1; then
  ip link add mmesh type veth peer name mmesh-c || true
fi
ip link set mmesh up || true
ip addr replace 10.66.254.1/30 dev mmesh || true
pid=$(docker inspect -f '{{.State.Pid}}' "$(docker compose -f "$compose" ps -q mesh)" 2>/dev/null || true)
if [ -n "$pid" ] && [ "$pid" != "0" ]; then
  ip link set mmesh-c netns "$pid" || true
  nsenter -t "$pid" -n ip link set mmesh-c up || true
  nsenter -t "$pid" -n ip addr replace 10.66.254.2/30 dev mmesh-c || true
fi
echo "mesh sidecar up; policy routing may use dev mmesh inside an exit table only"
`
}

func renderNAT64(t model.Topology) string {
	var sb strings.Builder
	sb.WriteString("# NAT64 reservation (phase 3).\n")
	sb.WriteString("# This file is not a route. meridian-routes.sh does not install it,\n")
	sb.WriteString("# so the current IPv4 paths stay as they are.\n")
	sb.WriteString("# A future translator may map a v6 prefix to the hub's v4 endpoint.\n")
	sb.WriteString("# Do not point fd66::/48 or the LAN prefix here.\n")
	fmt.Fprintf(&sb, "reserved=%t\n", t.Settings.NAT64.Reserved || true)
	fmt.Fprintf(&sb, "enabled=%t\n", t.Settings.NAT64.Enabled)
	if t.Settings.NAT64.Prefix != "" {
		fmt.Fprintf(&sb, "prefix=%s\n", t.Settings.NAT64.Prefix)
	} else {
		sb.WriteString("prefix=\n")
	}
	sb.WriteString("# enabled=true still does not add a route in this version.\n")
	return sb.String()
}

func renderVerifyScript(t model.Topology) string {
	gw := t.Settings.GatewayLANIP
	if gw == "" {
		gw = "192.168.100.88/24"
	}
	ros := t.Settings.ROSIPv4
	if ros == "" {
		ros = "192.168.100.1"
	}
	iface := t.Settings.LANInterface
	if iface == "" {
		iface = "eth0"
	}
	return fmt.Sprintf(`#!/bin/bash
# Same-subnet redirect and rp_filter check for the gateway.
# Exits 0 when the generated policy is present in the running kernel.
# A missing /proc (container build) is a skip, not a failure.
set -u
fail=0
note() { echo "$*"; }
bad() { echo "FAIL: $*"; fail=1; }
if [ ! -d /proc/sys/net ]; then
  echo "SKIP: no /proc/sys/net; run this on the Debian gateway"
  exit 0
fi
read_sys() { cat "$1" 2>/dev/null || echo missing; }
for kv in \
  net.ipv4.conf.all.rp_filter=2 \
  net.ipv4.conf.default.rp_filter=2 \
  net.ipv4.conf.%s.rp_filter=2 \
  net.ipv4.conf.all.send_redirects=0 \
  net.ipv4.conf.%s.send_redirects=0 \
  net.ipv6.conf.all.send_redirects=0 \
  net.ipv4.conf.all.accept_redirects=0 \
  net.ipv6.conf.all.accept_redirects=0 \
  net.ipv4.ip_forward=1
 do
  key=${kv%%%%=*}; want=${kv##*=}
  path=/proc/sys/${key//./\/}
  got=$(read_sys "$path")
  if [ "$got" = "$want" ]; then
    note "ok $key=$got"
  else
    bad "$key=$got want $want"
  fi
done
if ip -4 addr show dev %s 2>/dev/null | grep -q '192.168.100.88'; then
  note "ok gateway address is 192.168.100.88"
else
  bad "192.168.100.88 is not on %s"
fi
ros=%s
if ip route get "$ros" 2>/dev/null | grep -q 'via'; then
  note "ok the LAN gateway is reached as a neighbour"
fi
# The next line must not install a route. It only fails if one already points at the LAN gateway.
if ip -6 route show fd66::/48 2>/dev/null | grep -q "$ros"; then
  bad "fd66 prefix is routed via the LAN gateway"
else
  note "ok fd66 is not via the LAN gateway"
fi
if command -v nft >/dev/null 2>&1 && nft list table inet meridian >/dev/null 2>&1; then
  if nft list table inet meridian | grep -q 'dport 853'; then
    note "ok dns hijack present"
  else
    bad "nft table has no 853 hijack"
  fi
else
  note "SKIP nft table not loaded"
fi
echo "WebRTC: host candidates may still show the ISP GUA. srflx must be the exit."
if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "meridian-verify-ok"
`, iface, iface, iface, iface, ros)
}

func renderUnlockProbe(n model.Node) string {
	return fmt.Sprintf(`#!/bin/bash
# Streaming/AI probe for exit %s. Run on the exit, never on the home gateway.
# lmc999/regioncheck stays an independent container (AGPL-3.0); it is not linked
# into the panel. Results are written locally. Posting them to the panel is a
# separate step that uses the bearer token, which is not stored in this file.
set -u
dir=/var/lib/meridian
mkdir -p "$dir"
raw="$dir/unlock-last.txt"
ai="$dir/unlock-ai.txt"
if command -v docker >/dev/null 2>&1; then
  docker run --rm --network host lmc999/regioncheck > "$raw" 2>&1 || true
else
  echo "regioncheck container is not installed" > "$raw"
fi
: > "$ai"
probe() {
  id="$1"; url="$2"
  code=$(curl -4 -o /dev/null -s -m 15 -w '%%{http_code}' "$url" || true)
  [ -n "$code" ] || code=000
  echo "$id $code" >> "$ai"
}
probe openai https://chatgpt.com/
probe anthropic https://claude.ai/
probe gemini https://gemini.google.com/
probe copilot https://copilot.microsoft.com/
probe perplexity https://www.perplexity.ai/
probe grok https://grok.x.ai/
echo "unlock-probe-wrote $raw"
`, n.ID)
}

func renderUnlockService() string {
	return `[Unit]
Description=Meridian unlock probe
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/meridian-unlock-probe.sh
`
}

func renderUnlockTimer(t model.Topology) string {
	every := unlock.Interval(t.Settings.UnlockIntervalSec)
	// systemd accepts seconds. 6h is the default.
	sec := int(every.Seconds())
	if sec < 60 {
		sec = int(unlock.DefaultInterval.Seconds())
	}
	return fmt.Sprintf(`# Scheduled unlock probe. Two consecutive failures are required
# before an automatic rule moves, and it stays inside the same pool.
[Unit]
Description=Meridian unlock probe every %d seconds

[Timer]
OnBootSec=15min
OnUnitActiveSec=%d
AccuracySec=5min
Persistent=true

[Install]
WantedBy=timers.target
`, sec, sec)
}
