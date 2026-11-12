package compile

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/mesh"
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
# The panel's Mesh deployment writes that file; it never stores the token.
# Pin settings.mesh_image to a digest after you have pulled a tag you trust.
name: meridian-mesh
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
    name: meridian_mesh_lib
`, meshImage(t))
}

func renderMeshEnvExample() string {
	return `# Copy to /etc/meridian/mesh.env and chmod 600.
# Put the Cloudflare Mesh node token here. Leave it empty in git.
# The panel's Mesh deployment (部署 → Mesh) writes this file itself.
MESH_NODE_TOKEN=
`
}

// renderMeshUp attaches the veth to the sidecar and seals it. The veth is
// an Ethernet device, so both ends get fixed MACs, IPv4 and IPv6 link
// addresses and permanent neighbour entries for each other; the host's
// exit tables then use "via <sidecar> dev mmesh" (see mesh.Addressing).
// The seal is only written after both next-hops answered a ping.
func renderMeshUp(t model.Topology) string {
	a := mesh.DefaultAddressing()
	ret4, ret6 := mesh.ReturnPrefixes(t)
	return strings.NewReplacer(
		"@HOST4@", a.HostV4CIDR(),
		"@SIDE4@", a.SidecarV4CIDR(),
		"@NH4@", a.NextHopV4(),
		"@HOSTIP4@", a.HostV4.String(),
		"@HOST6@", a.HostV6CIDR(),
		"@SIDE6@", a.SidecarV6CIDR(),
		"@NH6@", a.NextHopV6(),
		"@HOSTIP6@", a.HostV6.String(),
		"@HOSTMAC@", a.HostMAC,
		"@SIDEMAC@", a.SidecarMAC,
		"@LINK4@", a.LinkV4.String(),
		"@TABLE@", fmt.Sprint(mesh.SidecarTable),
		"@RET4@", strings.Join(ret4, " "),
		"@RET6@", strings.Join(ret6, " "),
	).Replace(meshUpBody)
}

// 169.254.66.0/30 and fe80::66:1/2 exist on the veth only. The IPv4 link is
// outside 10.66.0.0/16 (tunnel aggregate, routed west) and outside the LAN,
// so a missing connected route cannot send this hop toward Aliyun or ROS.
const meshUpBody = `#!/bin/bash
# Attach a veth to the Mesh sidecar netns and seal it.
# Traffic the host injects on mmesh must not follow the container's default
# route: that route is the docker bridge, which NATs onto this machine's WAN.
# On the hub, that WAN is the VPS default route and would skip the exit.
# The seal sends injected packets into table @TABLE@ (warp routes, or unreachable)
# at priority 17000. It never installs a route in table 100, 102, 150, or main.
#
# mmesh is an Ethernet veth, not a point-to-point tunnel. Routes onto it
# must name a next-hop: via @NH4@ dev mmesh and via @NH6@ dev mmesh.
# Both ends have fixed MACs and permanent neighbour entries, so no ARP/ND
# is sent for public destinations and no proxy ARP/ND is needed.
# The seal (/run/meridian/mesh-sealed) is only written when both next-hops
# answer from the host.
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
  ip link add mmesh address @HOSTMAC@ type veth peer name mmesh-c address @SIDEMAC@ || {
    echo "mesh veth failed" >&2
    unseal
    exit 0
  }
fi
ip link set mmesh address @HOSTMAC@ || true
ip link set mmesh addrgenmode none >/dev/null 2>&1 || true
sysctl -qw net.ipv6.conf.mmesh.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -qw net.ipv6.conf.mmesh.accept_ra=0 >/dev/null 2>&1 || true
ip link set mmesh up || true
ip addr replace @HOST4@ dev mmesh || true
ip -6 addr replace @HOST6@ dev mmesh nodad || true
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
ip link set mmesh-c address @SIDEMAC@
ip link set mmesh-c addrgenmode none >/dev/null 2>&1 || true
ip link set mmesh-c up
ip addr replace @SIDE4@ dev mmesh-c
ip -6 addr replace @SIDE6@ dev mmesh-c nodad
ip neigh replace @HOSTIP4@ lladdr @HOSTMAC@ dev mmesh-c nud permanent
ip -6 neigh replace @HOSTIP6@ lladdr @HOSTMAC@ dev mmesh-c nud permanent
# Return path: replies for Meridian prefixes go back to the host end of the
# veth (explicit next-hop), not out of the docker bridge.
for p in @RET4@; do
  ip route replace "$p" via @HOSTIP4@ dev mmesh-c
done
for p in @RET6@; do
  ip -6 route replace "$p" via @HOSTIP6@ dev mmesh-c
done
ip route flush table @TABLE@ 2>/dev/null || true
ip route replace unreachable default metric 32767 table @TABLE@
ip -6 route flush table @TABLE@ 2>/dev/null || true
ip -6 route replace unreachable default metric 32767 table @TABLE@
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
    ip $fam route replace $spec table @TABLE@ || true
  done
}
copy_routes -4 "$warp"
copy_routes -6 "$warp"
ip route replace @LINK4@ dev mmesh-c table @TABLE@ || true
while ip rule del iif mmesh-c lookup @TABLE@ >/dev/null 2>&1; do :; done || true
ip rule add iif mmesh-c lookup @TABLE@ priority 17000
while ip -6 rule del iif mmesh-c lookup @TABLE@ >/dev/null 2>&1; do :; done || true
ip -6 rule add iif mmesh-c lookup @TABLE@ priority 17000
if command -v nft >/dev/null 2>&1; then
  # One nft transaction: create-if-missing, delete, recreate. Either the
  # whole batch commits or the previous table stays.
  if [ -n "$warp" ]; then
    rule="iifname \"mmesh-c\" oifname != \"$warp\" drop"
  else
    rule="iifname \"mmesh-c\" drop"
  fi
  nft -f - <<NFT
table inet meridian_mesh
delete table inet meridian_mesh
table inet meridian_mesh {
  chain forward {
    type filter hook forward priority filter; policy accept;
    $rule
  }
}
NFT
fi
EOS
then
  ip neigh replace @NH4@ lladdr @SIDEMAC@ dev mmesh nud permanent || true
  ip -6 neigh replace @NH6@ lladdr @SIDEMAC@ dev mmesh nud permanent || true
  if ping -c 1 -W 2 -n -I mmesh @NH4@ >/dev/null 2>&1 && ping -6 -c 1 -W 2 -n @NH6@%mmesh >/dev/null 2>&1; then
    mkdir -p /run/meridian
    : > /run/meridian/mesh-sealed
    echo "mesh sidecar sealed; next-hops @NH4@ and @NH6@%mmesh answer; exit tables may use them, IX tables may not"
  else
    echo "mesh next-hop @NH4@ or @NH6@%mmesh does not answer; exit tables stay blackholed" >&2
    unseal
  fi
else
  echo "mesh seal failed; exit tables stay blackholed" >&2
  unseal
fi
exit 0
`

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

// renderVerifyScript is meridian-verify.sh: checks that the script itself
// executes on the Debian gateway, each with its raw output saved as
// evidence. It never reports a check it did not run as passed. A missing
// nft binary or a missing Meridian table is a failure. Client DNS leak,
// WebRTC, ICMP redirect captures and tunnel-cut tests cannot be executed
// from here and are printed as PENDING-HUMAN; the ROS fd00::/8 check runs
// only when MERIDIAN_ROS_SSH is set, otherwise it is PENDING-HUMAN too.
// The final line is meridian-verify-local-ok only when every local check
// passed; that line is not a leak test and not a release sign-off.
//
// The compiled expectations it compares the host against: every exit and
// region-group mark with its lookup and unreachable priorities, the guard's
// exit-mark range, whether the domestic IPv6 set is needed, and the remote
// access entrance (port, device pools, the enabled devices' public keys —
// never a private key or PSK). With remote access off it asserts that no
// mra interface, rule or guard ingress exists.
func renderVerifyScript(t model.Topology, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan) string {
	gw := t.Settings.GatewayLANIP
	if gw == "" {
		gw = "192.168.100.88/24"
	}
	gwAddr := gw
	if p, err := netip.ParsePrefix(gw); err == nil {
		gwAddr = p.Addr().String()
	} else if a, err := netip.ParseAddr(gw); err == nil {
		gwAddr = a.String()
	}
	ros := t.Settings.ROSIPv4
	if ros == "" {
		ros = "192.168.100.1"
	}
	ros6 := ""
	if a, err := netip.ParseAddr(t.Settings.ROSv6LLA); err == nil && a.Is6() {
		ros6 = a.String()
	}
	iface := t.Settings.LANInterface
	if iface == "" {
		iface = "eth0"
	}
	// mark:lookup-priority:unreachable-priority:label, one per exit and
	// region group, in the order the routes script installs them.
	var marks []string
	for _, e := range exits {
		marks = append(marks, fmt.Sprintf("%#x:%d:%d:exit/%s", e.Mark, prioExitBase+e.Index, prioExitDrop+e.Index, verifyLabel(e.Node.ID)))
	}
	for _, g := range groups {
		marks = append(marks, fmt.Sprintf("%#x:%d:%d:group/%s", g.Mark, prioExitBase+g.Index, prioExitDrop+g.Index, verifyLabel(g.Group.ID)))
	}
	guardExit := "0"
	if len(gatewayTunnelIfaces(tunnels)) > 0 {
		guardExit = "1"
	}
	rp := planRemote(t)
	chn6 := "0"
	if t.Settings.LANIPv6Prefix != "" || rp != nil {
		chn6 = "1"
	}
	ra, raPort, raPool4, raPool6, raPeers := "0", "", "", "", ""
	if rp != nil {
		ra = "1"
		raPort = fmt.Sprint(rp.Port)
		raPool4, raPool6 = rp.V4.String(), rp.V6.String()
		var peers []string
		for _, d := range rp.Devices {
			// Public keys only; ValidWGKey keeps anything odd out of the script.
			if ValidWGKey(d.PublicKey) {
				peers = append(peers, d.PublicKey+" "+verifyLabel(d.ID))
			}
		}
		raPeers = strings.Join(peers, "\n")
	}
	return strings.NewReplacer(
		"@IFACE@", shQuote(iface),
		"@GWADDR@", shQuote(gwAddr),
		"@ROS4@", shQuote(ros),
		"@ROS6@", shQuote(ros6),
		"@MARKS@", shQuote(strings.Join(marks, " ")),
		"@GUARDLO@", fmt.Sprintf("%#x", markExitBase),
		"@GUARDHI@", fmt.Sprintf("%#x", guardLastExitMark(exits, groups...)),
		"@GUARDEXIT@", guardExit,
		"@CHN6@", chn6,
		"@RA@", ra,
		"@RAPORT@", shQuote(raPort),
		"@RAPOOL4@", shQuote(raPool4),
		"@RAPOOL6@", shQuote(raPool6),
		"@RAPEERS@", shQuote(raPeers),
		"@RAIF@", model.RemoteAccessIface,
	).Replace(verifyScriptBody)
}

// verifyLabel keeps an ID printable in the verify script's output.
func verifyLabel(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

const verifyScriptBody = `#!/bin/bash
# meridian-verify.sh: local checks on the Debian gateway (run as root).
#
# What this script can establish: the running kernel's sysctls, the LAN
# address, that ROS is an on-link neighbour, that no ULA route points at
# ROS or out of the LAN port, that nft tables inet meridian and
# inet meridian_guard are loaded with the DNS hijack, the DNS input drop,
# the ULA drop and the fail-closed forward guard, that the loaded policy
# rules cover every compiled exit and region-group mark with an unreachable
# behind it, that the guard's mark range is the compiled one, that the
# foreign and domestic tables end in a blackhole, that the early-boot guard
# file is the guard of the main ruleset, that the domestic lists the split
# needs are not empty, that something listens on port 53, and — with
# remote access on — that mra, its peers (public keys only), its guard
# ingress, DNS, port, rules, routes and NAT are what was compiled; with it
# off, that no mra exists. Every command's raw output is saved under the
# evidence directory. INFO lines (list versions) are information, not checks.
#
# What it cannot establish: that a real client does not leak. DNS leak and
# WebRTC tests need a browser on the test device; ICMP redirects and tunnel
# cuts need a packet capture; remote access needs a real phone on a
# cellular network and the router's port forward. Those are printed as
# PENDING-HUMAN and must be signed off with archived evidence
# (docs/verification.md). The ROS fd00::/8 check only runs when
# MERIDIAN_ROS_SSH=user@host is set (one read-only "/ipv6 route print");
# otherwise it is PENDING-HUMAN as well.
#
# Exit status: 0 every local check passed (meridian-verify-local-ok),
# 1 at least one FAIL, 2 no FAIL but something could not be checked.
set -u
iface=@IFACE@
gw_addr=@GWADDR@
ros4=@ROS4@
ros6=@ROS6@
# Compiled expectations. marks: mark:lookup-prio:unreachable-prio:label.
marks=@MARKS@
guard_lo=@GUARDLO@
guard_hi=@GUARDHI@
guard_has_exit=@GUARDEXIT@
need_chn6=@CHN6@
ra_enabled=@RA@
ra_if=@RAIF@
ra_port=@RAPORT@
ra_pool4=@RAPOOL4@
ra_pool6=@RAPOOL6@
# One "public-key device-id" per line: public keys only, never key material.
ra_peers=@RAPEERS@
# Installed files are read under this root (tests point it elsewhere).
root=${MERIDIAN_VERIFY_ROOT:-}
nftdir="$root/etc/nftables.d"
listsdir="$root/var/lib/meridian"
ts=$(date -u +%Y%m%dT%H%M%SZ)
evdir=${MERIDIAN_VERIFY_EVIDENCE_DIR:-/var/log/meridian-verify/$ts}
if ! mkdir -p "$evdir" 2>/dev/null; then
  evdir=$(mktemp -d) || { echo "FAIL evidence: cannot create an evidence directory"; exit 1; }
fi
summary="$evdir/summary.txt"
: > "$summary"
fails=0
unknowns=0
emit() { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$summary"; }
pass() { emit "PASS $1: $2"; }
fail() { emit "FAIL $1: $2"; fails=$((fails + 1)); }
unknown() { emit "UNKNOWN $1: $2"; unknowns=$((unknowns + 1)); }
pending() { emit "PENDING-HUMAN $1: $2"; }
notrun() { emit "NOT-RUN-HERE $1: $2"; }
info() { emit "INFO $1: $2"; }
# set_has_elements FILE SET: the listed nft set has an elements line.
set_has_elements() {
  local in=0 l re="^[[:space:]]*set $2 [{]\$" end='^[[:space:]]*[}]$'
  while IFS= read -r l; do
    if [ "$in" = 0 ]; then
      [[ $l =~ $re ]] && in=1
      continue
    fi
    case "$l" in *"elements = {"*) return 0 ;; esac
    [[ $l =~ $end ]] && return 1
  done < "$1"
  return 1
}
# guard_block FILE: the text of table inet meridian_guard in an nft file.
guard_block() {
  local in=0 l
  while IFS= read -r l; do
    [ "$l" = "table inet meridian_guard {" ] && in=1
    if [ "$in" = 1 ]; then
      printf '%s\n' "$l"
      [ "$l" = "}" ] && return 0
    fi
  done < "$1"
  return 1
}
# out_of FILE: the command output without the exit= line run appends.
out_of() { grep -v '^exit=[0-9]*$' "$1"; }
# run NAME CMD...: raw output to $evdir/NAME.txt, exit status kept.
run() {
  name=$1; shift
  "$@" > "$evdir/$name.txt" 2>&1
  rc=$?
  echo "exit=$rc" >> "$evdir/$name.txt"
  return $rc
}
emit "meridian-verify $ts iface=$iface gateway=$gw_addr ros=$ros4 ros6=${ros6:-unset}"

# --- kernel settings -------------------------------------------------------
if ! command -v sysctl >/dev/null 2>&1; then
  unknown sysctl "sysctl not found; no kernel setting was checked (run this on the gateway)"
else
  for kv in \
    net.ipv4.conf.all.rp_filter=2 \
    net.ipv4.conf.default.rp_filter=2 \
    "net.ipv4.conf.$iface.rp_filter=2" \
    net.ipv4.conf.all.send_redirects=0 \
    "net.ipv4.conf.$iface.send_redirects=0" \
    net.ipv4.conf.all.accept_redirects=0 \
    net.ipv6.conf.all.accept_redirects=0 \
    net.ipv4.ip_forward=1 \
    net.ipv6.conf.all.forwarding=1
  do
    key=${kv%=*}; want=${kv##*=}
    if got=$(sysctl -n "$key" 2>/dev/null); then
      echo "$key=$got" >> "$evdir/sysctl.txt"
      if [ "$got" = "$want" ]; then
        pass "sysctl $key" "$got"
      else
        fail "sysctl $key" "$got, want $want"
      fi
    else
      echo "$key=<unreadable>" >> "$evdir/sysctl.txt"
      fail "sysctl $key" "not readable"
    fi
  done
fi

# --- addresses and routes --------------------------------------------------
if ! command -v ip >/dev/null 2>&1; then
  unknown routes "ip not found; address, neighbour and ULA route checks not run"
else
  if run ip-addr ip -4 -o addr show dev "$iface" && grep -qF " $gw_addr/" "$evdir/ip-addr.txt"; then
    pass gateway_address "$gw_addr is on $iface"
  else
    fail gateway_address "$gw_addr is not on $iface (evidence ip-addr.txt)"
  fi
  if run ros-route ip -4 route get "$ros4" && grep -qE " dev $iface( |\$)" "$evdir/ros-route.txt" && ! grep -q " via " "$evdir/ros-route.txt"; then
    pass ros_neighbour "$ros4 is reached on-link via $iface"
  else
    fail ros_neighbour "$ros4 is not an on-link neighbour on $iface (evidence ros-route.txt)"
  fi
  if run ip6-routes ip -6 route show table all; then
    grep -E '^((unreachable|blackhole|prohibit|throw|local|anycast) )?f[cd][0-9a-f]{0,2}:' "$evdir/ip6-routes.txt" > "$evdir/ula-routes.txt" || true
    bad=""
    if grep -qE " dev $iface( |\$)" "$evdir/ula-routes.txt"; then bad="leaves via $iface"; fi
    if [ -n "$ros6" ] && grep -qF "via $ros6 " "$evdir/ula-routes.txt"; then bad="points at ROS $ros6"; fi
    if [ -n "$bad" ]; then
      fail ula_not_via_ros "a ULA route $bad (evidence ula-routes.txt)"
    else
      pass ula_not_via_ros "no ULA route in any table uses $iface or ROS (evidence ula-routes.txt)"
    fi
  else
    fail ula_not_via_ros "ip -6 route show table all failed (evidence ip6-routes.txt)"
  fi

  # Policy rules as loaded: every compiled exit and region-group mark goes to
  # the foreign table (102), with an unreachable rule right behind it, v4
  # and v6. Table 102 may be listed by its name meridian_foreign.
  rules_ok=1
  run ip-rules4 ip -4 rule show || rules_ok=0
  run ip-rules6 ip -6 rule show || rules_ok=0
  if [ "$rules_ok" = 0 ]; then
    fail policy_marks "ip rule show failed; no policy rule was checked (evidence ip-rules4.txt ip-rules6.txt)"
  elif [ -n "$marks" ]; then
    missing=""
    nmarks=0
    for spec in $marks; do
      IFS=: read -r m pl pu label <<< "$spec"
      nmarks=$((nmarks + 1))
      for fam in 4 6; do
        f="$evdir/ip-rules$fam.txt"
        grep -qE "^$pl:[[:space:]]+from all fwmark $m lookup (102|meridian_foreign)([[:space:]]|\$)" "$f" || missing="$missing $label/v$fam-lookup"
        grep -qE "^$pu:[[:space:]]+from all fwmark $m unreachable([[:space:]]|\$)" "$f" || missing="$missing $label/v$fam-unreachable"
      done
    done
    if [ -z "$missing" ]; then
      pass policy_marks "all $nmarks compiled exit and region-group marks route to table 102 with an unreachable behind them, v4 and v6"
    else
      fail policy_marks "loaded policy rules miss:$missing (evidence ip-rules4.txt ip-rules6.txt)"
    fi
  fi
  if [ "$rules_ok" = 1 ]; then
    if grep -qE "^17850:[[:space:]]+from all iif $iface unreachable([[:space:]]|\$)" "$evdir/ip-rules4.txt"; then
      pass lan_iif_unreachable "IPv4 from $iface without a Meridian mark is unreachable (priority 17850)"
    else
      fail lan_iif_unreachable "no 'iif $iface unreachable' rule at priority 17850 (evidence ip-rules4.txt)"
    fi
  fi

  # Fallback: the foreign table (v4, v6) and the domestic table (v4) end in
  # a blackhole, so a vanished tunnel or ROS route never falls through.
  if run route4-102 ip -4 route show table 102 && run route6-102 ip -6 route show table 102 && run route4-100 ip -4 route show table 100; then
    bh='^blackhole default( .*)? metric 32767([[:space:]]|$)'
    if grep -qE "$bh" "$evdir/route4-102.txt" && grep -qE "$bh" "$evdir/route6-102.txt" && grep -qE "$bh" "$evdir/route4-100.txt"; then
      pass fallback_blackholes "tables 102 (v4, v6) and 100 (v4) end in a metric-32767 blackhole"
    else
      fail fallback_blackholes "a metric-32767 blackhole default is missing in table 102 or 100 (evidence route4-102.txt route6-102.txt route4-100.txt)"
    fi
  else
    fail fallback_blackholes "ip route show table 102/100 failed (evidence route4-102.txt route6-102.txt route4-100.txt)"
  fi

  # Remote access: present and wired when enabled, absent when not.
  if [ "$ra_enabled" = 1 ]; then
    if run mra-link ip link show dev "$ra_if" && grep -qE '[<,]UP[,>]' "$evdir/mra-link.txt"; then
      pass remote_iface "$ra_if exists and is up"
    else
      fail remote_iface "$ra_if is missing or down (evidence mra-link.txt)"
    fi
    if [ "$rules_ok" = 1 ] && grep -qE "^17851:[[:space:]]+from all iif $ra_if( \[detached\])? unreachable([[:space:]]|\$)" "$evdir/ip-rules4.txt"; then
      pass remote_iif_unreachable "IPv4 from $ra_if without a Meridian mark is unreachable (priority 17851)"
    else
      fail remote_iif_unreachable "no 'iif $ra_if unreachable' rule at priority 17851 (evidence ip-rules4.txt)"
    fi
    p4re=${ra_pool4//./\\.}
    if run ra-route4-main ip -4 route show table main && run ra-route6-main ip -6 route show table main && run ra-route6-100 ip -6 route show table 100 &&
      grep -qE "^$p4re dev $ra_if( |\$)" "$evdir/ra-route4-main.txt" &&
      grep -qE "^$p4re dev $ra_if( |\$)" "$evdir/route4-100.txt" &&
      grep -qF "$ra_pool6 dev $ra_if " "$evdir/ra-route6-main.txt" &&
      grep -qF "$ra_pool6 dev $ra_if " "$evdir/ra-route6-100.txt"; then
      pass remote_pool_routes "device pools $ra_pool4 and $ra_pool6 are routed to $ra_if in main and table 100"
    else
      fail remote_pool_routes "a device-pool route to $ra_if is missing in main or table 100 (evidence ra-route4-main.txt route4-100.txt ra-route6-main.txt ra-route6-100.txt)"
    fi
  else
    # A stale interface would forward outside the guard's ingress; a
    # leftover "iif mra unreachable" rule after switching the feature off
    # only drops (it stays until reboot by design) and is reported as INFO.
    if run mra-link ip link show dev "$ra_if"; then
      fail remote_absent "remote access is off but interface $ra_if exists; the guard does not cover it (evidence mra-link.txt)"
    else
      pass remote_absent "remote access is off and there is no $ra_if interface"
    fi
    if [ "$rules_ok" = 1 ] && grep -qE "iif $ra_if( |\$)" "$evdir/ip-rules4.txt"; then
      info remote_leftover "a leftover 'iif $ra_if unreachable' rule from when remote access was on; it only drops and goes away at the next reboot"
    fi
  fi
fi

# --- firewall: both tables are required ------------------------------------
if ! command -v nft >/dev/null 2>&1; then
  fail nft "nft is not installed: there is no Meridian firewall on this host"
else
  if run nft-guard nft list table inet meridian_guard; then
    g="$evdir/nft-guard.txt"
    if grep -qE 'hook forward priority (-200|filter - 200);' "$g" && grep -q 'fail closed' "$g" && grep -qE "iifname (\"$iface\"|[{] [^}]*\"$iface\"[^}]* [}]) .*drop" "$g"; then
      pass nft_guard "inet meridian_guard is loaded: forward hook at -200 with the fail-closed LAN drop"
    else
      fail nft_guard "inet meridian_guard is loaded but its forward hook or fail-closed drop is missing (evidence nft-guard.txt)"
    fi
    # The exit-mark range the guard lets into a tunnel is the compiled one
    # and holds every compiled mark (nft lists marks as 0x00000101).
    if [ "$guard_has_exit" = 1 ]; then
      re='meta mark (0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+) oifname'
      gl=$(grep -E 'meta mark 0x[0-9a-fA-F]+-0x[0-9a-fA-F]+ oifname' "$g")
      if [[ $gl =~ $re ]]; then
        lo=$((BASH_REMATCH[1])); hi=$((BASH_REMATCH[2])); outside=""
        for spec in $marks; do
          m=${spec%%:*}
          if [ $((m)) -lt "$lo" ] || [ $((m)) -gt "$hi" ]; then outside="$outside $m"; fi
        done
        if [ "$lo" -eq $((guard_lo)) ] && [ "$hi" -eq $((guard_hi)) ] && [ -z "$outside" ]; then
          pass guard_mark_range "guard admits exit marks $guard_lo-$guard_hi into the tunnels, covering every compiled exit and group mark"
        else
          fail guard_mark_range "guard range is $(printf '0x%x-0x%x' "$lo" "$hi"), compiled $guard_lo-$guard_hi${outside:+; marks outside:$outside} (evidence nft-guard.txt)"
        fi
      else
        fail guard_mark_range "the guard has no exit-mark range towards the tunnels (evidence nft-guard.txt)"
      fi
    fi
    # Ingress: the LAN NIC, plus mra with the same rules when remote access
    # is on; never mra when it is off. Only the two LAN-to-device returns
    # may name the LAN NIC alone.
    both="iifname [{] (\"$iface\", \"$ra_if\"|\"$ra_if\", \"$iface\") [}]"
    if [ "$ra_enabled" = 1 ]; then
      if grep -E "$both .*drop" "$g" | grep -q 'fail closed' &&
        grep -qE "$both meta l4proto [{] tcp, udp [}] th dport [{] 53, 853 [}] drop" "$g" &&
        grep -qE "$both meta mark 0x0*64 oifname \"$iface\"" "$g" &&
        { [ "$guard_has_exit" = 0 ] || grep -qE "$both meta mark 0x[0-9a-fA-F]+-0x[0-9a-fA-F]+ oifname" "$g"; } &&
        ! grep -E "iifname \"$iface\"" "$g" | grep -qv "oifname \"$ra_if\""; then
        pass guard_ingress "the guard's ingress is { $iface, $ra_if } with the same DNS drop, mark rules and fail-closed drop"
      else
        fail guard_ingress "remote access is on but the guard does not treat $ra_if like $iface (evidence nft-guard.txt)"
      fi
    else
      if grep -q "\"$ra_if\"" "$g"; then
        fail guard_ingress "remote access is off but the loaded guard names $ra_if (evidence nft-guard.txt)"
      else
        pass guard_ingress "the guard's ingress is $iface only"
      fi
    fi
  else
    fail nft_guard "table inet meridian_guard is not loaded (or not readable; run as root) (evidence nft-guard.txt)"
  fi
  if run nft-meridian nft list table inet meridian; then
    m="$evdir/nft-meridian.txt"
    if grep -q 'redirect to :53' "$m"; then pass dns_hijack_53 "LAN 53 is redirected to the local resolver"; else fail dns_hijack_53 "no 53 redirect in inet meridian"; fi
    if grep -q 'redirect to :853' "$m"; then pass dns_hijack_853 "LAN 853 is redirected locally"; else fail dns_hijack_853 "no 853 redirect in inet meridian"; fi
    if grep -q 'DNS only from the LAN' "$m"; then pass dns_input_drop "non-LAN 53/853 is dropped on input"; else fail dns_input_drop "no non-LAN DNS drop on input"; fi
    if grep -q 'ip6 daddr fc00::/7 drop' "$m"; then pass ula_drop "forwarded ULA is dropped"; else fail ula_drop "no fc00::/7 drop in inet meridian"; fi
    # Domestic split: chnroute (and chnroute6 when clients have IPv6) must
    # hold elements. They are filled only by a list update and re-added
    # from the saved batch on every reload; empty means every domestic
    # address not in another list goes to the default exit.
    saved="$listsdir/lists/chnroute.nft"
    for set in chnroute chnroute6; do
      [ "$set" = chnroute6 ] && [ "$need_chn6" != 1 ] && continue
      if set_has_elements "$m" "$set"; then
        pass "${set}_loaded" "nft set $set holds elements"
      elif [ -s "$saved" ] && grep -q "add element inet meridian $set {" "$saved"; then
        fail "${set}_loaded" "nft set $set is empty although the saved batch $saved has it: the reload did not re-add it (check meridian-up.sh output for meridian-chnroute-saved-ignored)"
      else
        fail "${set}_loaded" "nft set $set is empty: no list update has loaded it on this host (panel 名单 → 更新, or meridian-update-chnroute.sh)"
      fi
    done
    if [ "$ra_enabled" = 1 ]; then
      if grep -qE "iifname \"$ra_if\" .*redirect to :53" "$m" && grep -qE "iifname \"$ra_if\" .*redirect to :853" "$m" &&
        grep -E 'dport [{] 53, 853 [}] ip saddr != ' "$m" | grep -qF "$ra_pool4" &&
        grep -E 'dport [{] 53, 853 [}] ip6 saddr != ' "$m" | grep -qF "$ra_pool6"; then
        pass remote_dns "53/853 from $ra_if is redirected locally and the DNS input allow-list holds $ra_pool4 and $ra_pool6"
      else
        fail remote_dns "the DNS hijack for $ra_if or the device pools in the DNS input allow-list are missing (evidence nft-meridian.txt)"
      fi
      if grep -qE "iifname \"$iface\" udp dport $ra_port accept" "$m" && grep -qE "^[[:space:]]*udp dport $ra_port drop" "$m"; then
        pass remote_port_lan_only "UDP $ra_port is accepted on $iface only"
      else
        fail remote_port_lan_only "the input rules accepting UDP $ra_port on $iface only are missing (evidence nft-meridian.txt)"
      fi
      set -- $marks
      n4=$(grep -F "ip saddr $ra_pool4 meta mark " "$m" | grep -cE ' snat (ip )?to ')
      n6=$(grep -F "ip6 saddr $ra_pool6 meta mark " "$m" | grep -cE ' snat (ip6 )?to ')
      if [ "$n4" -eq $# ] && [ "$n6" -eq $# ] && grep -qF "oifname \"$iface\" ip saddr $ra_pool4 masquerade" "$m" && grep -qF "oifname \"$iface\" ip6 saddr $ra_pool6 masquerade" "$m"; then
        pass remote_nat "device pools have a transit SNAT for each of the $# marks and a masquerade on $iface"
      else
        fail remote_nat "device-pool NAT incomplete: $n4/$# v4 and $n6/$# v6 transit SNAT rules, masquerade on $iface required (evidence nft-meridian.txt)"
      fi
    fi
  else
    fail nft_meridian "table inet meridian is not loaded (or not readable; run as root) (evidence nft-meridian.txt)"
  fi
fi

# --- installed files: the early-boot guard is the main ruleset's guard -----
if [ ! -f "$nftdir/meridian-guard.nft" ] || [ ! -f "$nftdir/meridian.nft" ]; then
  fail guard_boot_file "$nftdir/meridian-guard.nft or meridian.nft is missing: meridian-guard.service has nothing to load at boot"
elif bg=$(guard_block "$nftdir/meridian-guard.nft") && mg=$(guard_block "$nftdir/meridian.nft") && [ "$bg" = "$mg" ]; then
  printf '%s\n' "$bg" > "$evdir/guard-boot-block.txt"
  pass guard_boot_file "meridian-guard.nft holds exactly the guard of meridian.nft"
else
  printf '%s\n' "${bg:-}" > "$evdir/guard-boot-block.txt"
  printf '%s\n' "${mg:-}" > "$evdir/guard-main-block.txt"
  fail guard_boot_file "the early-boot guard differs from the guard in meridian.nft (evidence guard-boot-block.txt guard-main-block.txt)"
fi

# --- lists: versions are information; an empty domestic domain list fails --
st="$listsdir/lists/status.json"
if [ -f "$st" ] && run lists-status cat "$st"; then
  in=0; name=""; src=""; cnt=""; upd=""; nlist=0
  while IFS= read -r l; do
    if [ "$in" = 0 ]; then
      [ "$l" = '  "published": {' ] && in=1
      continue
    fi
    case "$l" in
      '  }'*) in=0 ;;
      '    "'*'": {') name=${l#    \"}; name=${name%\": \{}; src=""; cnt=""; upd="" ;;
      '      "source": "'*) src=${l#*: \"}; src=${src%\",} ;;
      '      "updated_at": "'*) upd=${l#*: \"}; upd=${upd%\",} ;;
      '      "count": '*) cnt=${l#*: }; cnt=${cnt%,} ;;
      '    }'*) info "list $name" "source=$src count=$cnt updated=$upd"; nlist=$((nlist + 1)) ;;
    esac
  done < "$st"
  [ "$nlist" -gt 0 ] || info lists "status.json records no published list (evidence lists-status.txt)"
else
  info lists "no $st: no list update has run on this host since list sources were added"
fi
cn="$listsdir/geosite/cn.txt"
if [ -f "$cn" ] && grep -qvE '^[[:space:]]*(#|$)' "$cn"; then
  pass geosite_cn "$cn has domains (SmartDNS answers domestic names from domestic resolvers)"
else
  fail geosite_cn "$cn is missing or empty: domestic names are resolved abroad; run the list update (panel 名单 → 更新, or meridian-update-geosite.sh)"
fi

# --- DNS: something listens on 53 for the hijack to land on ----------------
if ! command -v ss >/dev/null 2>&1; then
  unknown dns_listener "ss not found; the port 53 listener was not checked"
elif run ss-udp ss -H -lnu && run ss-tcp ss -H -lnt; then
  if grep -qE ':53[[:space:]]' "$evdir/ss-udp.txt" && grep -qE ':53[[:space:]]' "$evdir/ss-tcp.txt"; then
    pass dns_listener "a resolver listens on UDP and TCP 53 (whether it answers correctly is deploy/verify-smartdns.sh)"
  else
    fail dns_listener "nothing listens on UDP and TCP 53: the DNS hijack has no resolver behind it (evidence ss-udp.txt ss-tcp.txt)"
  fi
else
  fail dns_listener "ss failed (evidence ss-udp.txt ss-tcp.txt)"
fi

# --- remote access: WireGuard state of mra (public keys only) --------------
if [ "$ra_enabled" = 1 ]; then
  if ! command -v wg >/dev/null 2>&1; then
    fail remote_wg "wg (wireguard-tools) is not installed: $ra_if cannot be configured"
  else
    if run mra-port wg show "$ra_if" listen-port && [ "$(out_of "$evdir/mra-port.txt")" = "$ra_port" ]; then
      pass remote_listen "$ra_if listens on UDP $ra_port"
    else
      fail remote_listen "$ra_if does not listen on UDP $ra_port (evidence mra-port.txt)"
    fi
    if run mra-peers wg show "$ra_if" peers; then
      missing=""; extra=0; npeer=0
      while read -r k id; do
        [ -n "$k" ] || continue
        npeer=$((npeer + 1))
        grep -qxF -- "$k" "$evdir/mra-peers.txt" || missing="$missing $id"
      done <<< "$ra_peers"
      while IFS= read -r k; do
        case "$k" in ''|exit=*) continue ;; esac
        case "$ra_peers" in "$k "*|*"
$k "*) ;; *) extra=$((extra + 1)) ;; esac
      done < "$evdir/mra-peers.txt"
      if [ -z "$missing" ] && [ "$extra" = 0 ]; then
        pass remote_peers "$ra_if has exactly the $npeer enabled devices as peers (public keys compared)"
      else
        fail remote_peers "$ra_if peers differ from the enabled devices:${missing:+ missing$missing;} $extra unexpected (evidence mra-peers.txt)"
      fi
    else
      fail remote_peers "wg show $ra_if peers failed (evidence mra-peers.txt)"
    fi
  fi
fi

# --- ROS fd00::/8 blackhole: only from a real read-only query --------------
ros_ssh=${MERIDIAN_ROS_SSH:-}
if [ -z "$ros_ssh" ]; then
  pending ros_ula_blackhole "not executed. On ROS (read-only): /ipv6 route print where blackhole and (dst-address=fd00::/8 or dst-address=fc00::/7); archive the output, or rerun with MERIDIAN_ROS_SSH=user@$ros4"
else
  case "$ros_ssh" in
    -*|*[!A-Za-z0-9@._:-]*)
      fail ros_ula_blackhole "MERIDIAN_ROS_SSH refused: only user@host"
      ;;
    *)
      if command -v ssh >/dev/null 2>&1 && run ros-ipv6-blackhole ssh -o BatchMode=yes -o ConnectTimeout=8 -- "$ros_ssh" '/ipv6 route print terse where blackhole'; then
        if grep -qE 'dst-address=(fd00::/8|fc00::/7)' "$evdir/ros-ipv6-blackhole.txt"; then
          pass ros_ula_blackhole "ROS has a ULA blackhole (evidence ros-ipv6-blackhole.txt)"
        else
          fail ros_ula_blackhole "ROS answered but has no fd00::/8 or fc00::/7 blackhole (evidence ros-ipv6-blackhole.txt)"
        fi
      else
        unknown ros_ula_blackhole "could not query ROS over ssh; nothing was checked (evidence ros-ipv6-blackhole.txt)"
      fi
      ;;
  esac
fi

# --- not executable from this script ---------------------------------------
pending dns_leak_client "dnsleaktest.com and ipleak.net on the test device (v4 and v6), plus a WAN capture with no 53/853 from it; this script runs no browser"
pending webrtc_srflx "browserleaks/ipleak WebRTC on the test device: srflx must be the exit address; a host GUA is a known limitation"
pending redirect_on_wire "capture on the test device while browsing: no ICMP redirect from $gw_addr pointing at $ros4"
pending tunnel_cut "take the exit tunnel down while the test device keeps browsing; capture on $iface: nothing foreign leaves towards $ros4, and the device gets no answer instead of a home-WAN answer"
notrun netns_reload_no_leak "isolated Linux integration: sudo MERIDIAN_NETNS_TEST=1 go test ./internal/compile -run TestNetnsReloadNoLeak (archive the log)"
notrun smartdns "sudo bash deploy/verify-smartdns.sh (archive the output)"
notrun host_exec "sudo bash deploy/verify-host-exec.sh and --boot after a reboot (archive the output)"
notrun mesh_veth "isolated Linux integration: sudo bash deploy/verify-mesh-veth.sh (dual-stack forwarding through the mmesh next-hops; archive the output). Mesh stays unverified until then"
if [ "$ra_enabled" = 1 ]; then
  pending remote_phone_full "a real phone on cellular (Wi-Fi off) in full mode: handshake on UDP $ra_port, ipleak/dnsleaktest show the exit region and no carrier DNS, the panel and the other devices are unreachable (docs/remote-access.md)"
  pending remote_phone_home "the same phone in home-only mode: LAN hosts and the gateway DNS answer; its other Internet traffic stays on the carrier and is not covered by Meridian"
  pending remote_router_forward "the router forwards UDP $ra_port to $gw_addr; this script cannot see the router (show its NAT/port-forward rule read-only and archive it)"
  pending remote_ipv6 "IPv6 inside the tunnel ($ra_pool6) and, if the endpoint has an AAAA record, dialing over IPv6 from a phone; neither is visible from here"
fi

emit "evidence: $evdir"
if [ "$fails" -ne 0 ]; then
  emit "meridian-verify-failed: $fails failed, $unknowns unknown"
  exit 1
fi
if [ "$unknowns" -ne 0 ]; then
  emit "meridian-verify-incomplete: $unknowns local checks could not run"
  exit 2
fi
emit "meridian-verify-local-ok: local gateway checks passed. This is not a leak test; release still needs every PENDING-HUMAN and NOT-RUN-HERE item signed off with archived evidence."
exit 0
`

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
# When the probe started. The panel orders reports by this time (a late
# report cannot overwrite a newer one) and rejects reports older than one
# hour; its 30-minute return cooldown still runs on the panel's own clock.
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
raw="$dir/unlock-last.txt"
raw4="$dir/unlock-last-v4.txt"
raw6="$dir/unlock-last-v6.txt"
ai="$dir/unlock-ai.txt"
: > "$raw4"
: > "$raw6"
run_rc() {
  family="$1"; out="$2"
  if ! command -v docker >/dev/null 2>&1; then
    echo "regioncheck container is not installed" >> "$out"
    return 0
  fi
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "regioncheck image is not present locally: $image" >> "$out"
    echo "pull it on this exit with: docker pull $image" >> "$out"
    return 0
  fi
  timeout 25m docker run --rm --network host --entrypoint /check.sh \
    "$image" -R 66 -M "$family" -E en >> "$out" 2>&1 || true
}
run_rc 4 "$raw4"
run_rc 6 "$raw6"
cat "$raw4" "$raw6" > "$raw"
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
      body=$(EXIT_ID="$exit_id" STARTED="$started" RAW4="$raw4" RAW6="$raw6" AI="$ai" python3 - <<'PY'
import json, os
def slurp(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()[-100000:]
    except OSError:
        return ""
# raw4/raw6 are the -M 4 / -M 6 runs; the AI probes use curl -4.
print(json.dumps({
    "exit_id": os.environ["EXIT_ID"],
    "kind": "scheduled",
    "at": os.environ["STARTED"],
    "family": "ipv4",
    "raw4": slurp(os.environ["RAW4"]),
    "raw6": slurp(os.environ["RAW6"]),
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
