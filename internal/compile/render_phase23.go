package compile

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/unlock"
)

const (
	// DefaultMeshImage is the official Cloudflare Mesh node (WARP connector).
	// https://developers.cloudflare.com/mesh/guides/run-mesh-in-containers/
	DefaultMeshImage = "cloudflare/mesh:latest"
	// DefaultRegioncheckImage is lmc999/RegionRestrictionCheck's published image.
	// It is not linked into the panel (AGPL-3.0).
	DefaultRegioncheckImage = "lmc999/regioncheck:latest"
)

func meshImage(t model.Topology) string {
	if t.Settings.MeshImage != "" {
		return t.Settings.MeshImage
	}
	return DefaultMeshImage
}

func regioncheckImage(t model.Topology) string {
	if t.Settings.RegioncheckImage != "" {
		return t.Settings.RegioncheckImage
	}
	return DefaultRegioncheckImage
}

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

func renderMeshCompose(t model.Topology) string {
	return fmt.Sprintf(`# Cloudflare Mesh sidecar (official image).
# Backup for the hub → exit hop only. Its own bridge netns, never host
# networking, so it cannot replace the host default route or the IX path.
# Do not deploy this file on the home gateway.
# The token is read from /etc/meridian/mesh.env (mode 0600). Do not commit one.
# Pin settings.mesh_image to a digest after you have pulled a tag you trust.
services:
  mesh:
    image: %s
    container_name: meridian-mesh
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
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
      net.ipv6.conf.default.forwarding: "1"
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
`, meshImage(t))
}

func renderMeshEnvExample() string {
	return `# Copy to /etc/meridian/mesh.env and chmod 600.
# Put the Cloudflare Mesh node token here. Leave it empty in git.
MESH_NODE_TOKEN=
`
}

func renderMeshUp() string {
	// 169.254.66.0/30 is link-local on the veth only. It is outside 10.66.0.0/16
	// (tunnel aggregate, routed west) and outside the LAN, so a missing
	// connected route cannot send this hop toward Aliyun or ROS.
	return `#!/bin/bash
# Attach a veth to the Mesh sidecar netns and seal it.
# Traffic the host injects on mmesh must not follow the container's default
# route: that route is the docker bridge, which NATs onto this machine's WAN.
# On the hub, that WAN is the VPS default route and would skip the exit.
# The seal sends injected packets into table 170 (warp routes, or unreachable)
# at priority 17000. It never installs a route in table 100, 102, 150, or main.
# This script refuses to run on the home gateway (192.168.100.88).
set -u
seal_only=0
if [ "${1:-}" = "--seal-only" ]; then
  seal_only=1
fi
unseal() {
  rm -f /run/meridian/mesh-sealed
}
if ip -4 addr show 2>/dev/null | grep -q 'inet 192.168.100.88/'; then
  echo "refusing to start mesh on the home gateway" >&2
  unseal
  exit 0
fi
if [ ! -s /etc/meridian/mesh.env ]; then
  echo "mesh sidecar skipped: /etc/meridian/mesh.env is missing" >&2
  unseal
  exit 0
fi
if ! grep -q '^MESH_NODE_TOKEN=.\+' /etc/meridian/mesh.env; then
  echo "mesh sidecar skipped: MESH_NODE_TOKEN is empty" >&2
  unseal
  exit 0
fi
compose=/etc/meridian/mesh-sidecar.compose.yml
if [ ! -f "$compose" ]; then
  echo "mesh compose missing" >&2
  unseal
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed; mesh sidecar not started" >&2
  unseal
  exit 0
fi
if [ "$seal_only" -eq 0 ]; then
  docker compose -f "$compose" up -d || {
    echo "mesh sidecar failed to start" >&2
    unseal
    exit 0
  }
fi
cid=$(docker compose -f "$compose" ps -q mesh 2>/dev/null || true)
pid=$(docker inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null || true)
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  echo "mesh sidecar is not running" >&2
  unseal
  exit 0
fi
if ip link show mmesh >/dev/null 2>&1; then
  if ! nsenter -t "$pid" -n ip link show mmesh-c >/dev/null 2>&1; then
    ip link del mmesh >/dev/null 2>&1 || true
  fi
fi
if ! ip link show mmesh >/dev/null 2>&1; then
  ip link add mmesh type veth peer name mmesh-c || {
    echo "mesh veth failed" >&2
    unseal
    exit 0
  }
fi
ip link set mmesh up || true
ip addr replace 169.254.66.1/30 dev mmesh || true
if ip link show mmesh-c >/dev/null 2>&1; then
  ip link set mmesh-c netns "$pid" || true
fi
# rp_filter lives in the container's netns. Loose mode matches the host.
# A strict filter here would drop transit sources; writing 2 is also what
# the host already wants if this path is not a separate proc.
for key in net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.mmesh-c.rp_filter; do
  path="/proc/$pid/root/proc/sys/${key//./\/}"
  if [ -e "$path" ]; then
    echo 2 > "$path" || true
  fi
done
if ! nsenter -t "$pid" -n bash -s <<'EOS'
set -eu
ip link set mmesh-c up
ip addr replace 169.254.66.2/30 dev mmesh-c
ip route flush table 170 2>/dev/null || true
ip route replace unreachable default metric 32767 table 170
ip -6 route flush table 170 2>/dev/null || true
ip -6 route replace unreachable default metric 32767 table 170
warp=""
for d in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
  case "$d" in
    lo|eth*|mmesh-c|docker*|br-*|veth*) continue ;;
  esac
  if ip -d link show "$d" 2>/dev/null | grep -q 'link/none'; then
    warp=$d
    break
  fi
done
copy_routes() {
  fam="$1"
  dev="$2"
  [ -n "$dev" ] || return 0
  ip $fam route show dev "$dev" | while IFS= read -r spec; do
    [ -n "$spec" ] || continue
    case "$spec" in
      *'dev eth'*|*'dev docker'*|*'dev br-'*|*'dev veth'*) continue ;;
    esac
    # shellcheck disable=SC2086
    ip $fam route replace $spec table 170 || true
  done
}
copy_routes -4 "$warp"
copy_routes -6 "$warp"
ip route replace 169.254.66.0/30 dev mmesh-c table 170 || true
while ip rule del iif mmesh-c lookup 170 >/dev/null 2>&1; do :; done || true
ip rule add iif mmesh-c lookup 170 priority 17000
while ip -6 rule del iif mmesh-c lookup 170 >/dev/null 2>&1; do :; done || true
ip -6 rule add iif mmesh-c lookup 170 priority 17000
if command -v nft >/dev/null 2>&1; then
  nft delete table inet meridian_mesh >/dev/null 2>&1 || true
  nft add table inet meridian_mesh
  nft add chain inet meridian_mesh forward '{ type filter hook forward priority filter; policy accept; }'
  if [ -n "$warp" ]; then
    nft add rule inet meridian_mesh forward iifname "mmesh-c" oifname != "$warp" drop
  else
    nft add rule inet meridian_mesh forward iifname "mmesh-c" drop
  fi
fi
EOS
then
  mkdir -p /run/meridian
  : > /run/meridian/mesh-sealed
  echo "mesh sidecar sealed; exit tables may use dev mmesh, IX tables may not"
else
  echo "mesh seal failed; exit tables stay blackholed" >&2
  unseal
fi
exit 0
`
}

func renderNAT64(t model.Topology) string {
	var sb strings.Builder
	sb.WriteString("# NAT64 reservation (phase 3).\n")
	sb.WriteString("# This file is not a route. meridian-routes.sh does not install it,\n")
	sb.WriteString("# so the current IPv4 paths stay as they are.\n")
	sb.WriteString("# A future translator may map a v6 prefix to the hub's v4 endpoint.\n")
	sb.WriteString("# Do not point fd66::/48 or the LAN prefix here.\n")
	sb.WriteString("reserved=true\n")
	fmt.Fprintf(&sb, "enabled=%t\n", t.Settings.NAT64.Enabled)
	prefix := ""
	if p, err := netip.ParsePrefix(t.Settings.NAT64.Prefix); err == nil && p.Addr().Is6() && !strings.ContainsAny(t.Settings.NAT64.Prefix, " \t\r\n") {
		prefix = p.Masked().String()
	}
	fmt.Fprintf(&sb, "prefix=%s\n", prefix)
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

func renderUnlockReportEnv() string {
	return `# Copy to /etc/meridian/unlock-report.env and chmod 600.
# The probe POSTs to the gateway panel over the tunnel. The URL is compiled
# into the probe; this file only holds the bearer token. Leave it empty in git.
MERIDIAN_PANEL_TOKEN=
`
}

func renderUnlockProbe(t model.Topology, n model.Node) string {
	panel := fmt.Sprintf("http://%s:%d", lanHost(t), panelPort(t))
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Streaming/AI probe for one exit. Run on the exit, never on the home gateway.\n")
	sb.WriteString("# lmc999/regioncheck stays an independent container (AGPL-3.0). Its published\n")
	sb.WriteString("# ENTRYPOINT is \"bash -lc /check.sh\", which drops extra arguments and then\n")
	sb.WriteString("# reads an interactive region menu. Override the entrypoint and pass -R 66\n")
	sb.WriteString("# (all platforms) plus -M 4 and -M 6 so a timer cannot block on read().\n")
	sb.WriteString("# The panel token is read from /etc/meridian/unlock-report.env (mode 0600).\n")
	sb.WriteString("# It is not written into this file, and the URL is not taken from that file.\n")
	sb.WriteString("set -u\n")
	fmt.Fprintf(&sb, "exit_id=%s\n", shQuote(n.ID))
	fmt.Fprintf(&sb, "image=%s\n", shQuote(regioncheckImage(t)))
	fmt.Fprintf(&sb, "panel=%s\n", shQuote(panel))
	sb.WriteString(`dir=/var/lib/meridian
mkdir -p "$dir"
raw="$dir/unlock-last.txt"
ai="$dir/unlock-ai.txt"
: > "$raw"
run_rc() {
  family="$1"
  if ! command -v docker >/dev/null 2>&1; then
    echo "regioncheck container is not installed" >> "$raw"
    return 0
  fi
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "regioncheck image is not present locally: $image" >> "$raw"
    echo "pull it on this exit with: docker pull $image" >> "$raw"
    return 0
  fi
  timeout 25m docker run --rm --network host --entrypoint /check.sh \
    "$image" -R 66 -M "$family" -E en >> "$raw" 2>&1 || true
}
run_rc 4
run_rc 6
: > "$ai"
probe() {
  id="$1"; url="$2"
  code=$(curl -4 -o /dev/null -s -m 15 -w '%{http_code}' "$url" || true)
  [ -n "$code" ] || code=000
  echo "$id $code" >> "$ai"
}
probe openai https://chatgpt.com/
probe anthropic https://claude.ai/
probe gemini https://gemini.google.com/
probe copilot https://copilot.microsoft.com/
probe perplexity https://www.perplexity.ai/
probe grok https://grok.x.ai/
token_file=/etc/meridian/unlock-report.env
if [ -f "$token_file" ] && command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  tok=$(sed -n 's/^MERIDIAN_PANEL_TOKEN=//p' "$token_file" | head -n 1 | tr -d '\r')
  case "$tok" in
    ''|*[!A-Za-z0-9._~/+-]*)
      echo "unlock report skipped: token missing or refused" >&2
      ;;
    *)
      body=$(EXIT_ID="$exit_id" RAW="$raw" AI="$ai" python3 - <<'PY'
import json, os
def slurp(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()[-200000:]
    except OSError:
        return ""
print(json.dumps({
    "exit_id": os.environ["EXIT_ID"],
    "kind": "scheduled",
    "raw": slurp(os.environ["RAW"]),
    "ai": slurp(os.environ["AI"]),
}))
PY
)
      hdr=$(mktemp)
      chmod 600 "$hdr"
      printf 'header = "Authorization: Bearer %s"\n' "$tok" > "$hdr"
      curl --silent --show-error --max-time 20 --config "$hdr" \
        -H 'Content-Type: application/json' \
        --data-binary "$body" \
        "$panel/api/unlock/report" >/dev/null || true
      rm -f "$hdr"
      ;;
  esac
fi
echo "unlock-probe-wrote $raw"
`)
	return sb.String()
}

func renderUnlockService() string {
	return `[Unit]
Description=Meridian unlock probe
After=network-online.target

[Service]
Type=oneshot
# The upstream script fetches remote snippets after the checks. Bound the
# oneshot so a hung menu or a hung fetch cannot stall the 6-hour timer.
TimeoutStartSec=55min
StandardInput=null
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
