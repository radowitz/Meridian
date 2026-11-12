#!/bin/bash
# verify-mesh-veth.sh: isolated dual-stack check of the Mesh host <-> sidecar
# hop, in throw-away network namespaces on a Linux host (run as root).
#
# Status: isolated evidence only. It passed once on Debian 13 on 2026-11-12
# (docs/evidence/2026-11-12-debian13/mesh-veth.log); rerun and re-archive
# after changing the Mesh addressing, routes or meridian-mesh-up.sh. It
# covers the host <-> sidecar hop in namespaces and nothing else: the Mesh
# data plane through Cloudflare, the real sidecar image and a real exit is
# still 未验证, and a successful Cloudflare route publication is not
# evidence that Mesh carries traffic.
#
# Topology (all private to this script; nothing on the host is touched):
#
#   mmv-client --c0/h0-- mmv-host --mmesh/mmesh-c-- mmv-side --w0/f0-- mmv-far
#   10.66.200.2           exit table 1101:            table 170:           198.51.100.1
#   fd66:0:0:ff::2        default via 169.254.66.2     198.51.100.0/24      2001:db8:66::1
#                         default via fe80::66:2       2001:db8:66::/64
#                         (dev mmesh)                  (the "warp" device)
#
# mmesh/mmesh-c use exactly what meridian-mesh-up.sh renders: 169.254.66.1/30
# and 169.254.66.2/30, fe80::66:1/64 and fe80::66:2/64 (nodad), fixed MACs
# 02:6d:65:73:68:01 / 02:6d:65:73:68:02, permanent neighbours on both ends,
# "iif mmesh-c lookup 170" in the sidecar and return routes for 10.66.0.0/16
# and fd66::/48 via the host end.
#
# Checks (each prints PASS / FAIL with the raw output in the evidence dir):
#   forward_v4 / forward_v6     client reaches the far host through the veth
#                               next-hops (ICMP and a TCP connect)
#   no_stray_neigh_v4 / _v6     the host resolved only the next-hops on mmesh
#   control_dev_only_v4 / _v6   the old form "default dev mmesh" (no via)
#                               does NOT forward: the host ARP/ND-probes the
#                               public destination and nothing answers
#
# Exit status: 0 every check passed (meridian-mesh-veth-verify-ok), 1 any FAIL,
# 2 not runnable here (not root, not Linux, missing ip/ping).
set -u
ts=$(date -u +%Y%m%dT%H%M%SZ)
evdir=${MERIDIAN_VERIFY_EVIDENCE_DIR:-/var/log/meridian-verify/mesh-veth-$ts}
mkdir -p "$evdir" 2>/dev/null || evdir=$(mktemp -d)
summary="$evdir/summary.txt"
: > "$summary"
fails=0
emit() { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$summary"; }
pass() { emit "PASS $1: $2"; }
fail() { emit "FAIL $1: $2"; fails=$((fails + 1)); }

if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ]; then
  emit "NOT-RUN-HERE mesh_veth: needs Linux and root (network namespaces)"
  exit 2
fi
for b in ip ping; do
  command -v "$b" >/dev/null 2>&1 || { emit "NOT-RUN-HERE mesh_veth: $b not found"; exit 2; }
done

C=mmv-client H=mmv-host S=mmv-side F=mmv-far
HOSTMAC=02:6d:65:73:68:01
SIDEMAC=02:6d:65:73:68:02
cleanup() {
  for ns in $C $H $S $F; do ip netns del "$ns" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
cleanup
for ns in $C $H $S $F; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
done
for ns in $H $S; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2
done

# client <-> host (stands in for the tunnel carrying transit traffic)
ip link add c0 netns $C type veth peer name h0 netns $H
ip -n $C link set c0 up
ip -n $H link set h0 up
ip -n $C addr add 10.66.200.2/24 dev c0
ip -n $H addr add 10.66.200.1/24 dev h0
ip -n $C -6 addr add fd66:0:0:ff::2/64 dev c0 nodad
ip -n $H -6 addr add fd66:0:0:ff::1/64 dev h0 nodad
ip -n $C route add default via 10.66.200.1
ip -n $C -6 route add default via fd66:0:0:ff::1

# host <-> sidecar: same commands as meridian-mesh-up.sh
ip link add mmesh netns $H address $HOSTMAC type veth peer name mmesh-c netns $S address $SIDEMAC
ip -n $H link set mmesh addrgenmode none 2>/dev/null || true
ip -n $S link set mmesh-c addrgenmode none 2>/dev/null || true
ip -n $H link set mmesh up
ip -n $S link set mmesh-c up
ip -n $H addr replace 169.254.66.1/30 dev mmesh
ip -n $H -6 addr replace fe80::66:1/64 dev mmesh nodad
ip -n $S addr replace 169.254.66.2/30 dev mmesh-c
ip -n $S -6 addr replace fe80::66:2/64 dev mmesh-c nodad
ip -n $H neigh replace 169.254.66.2 lladdr $SIDEMAC dev mmesh nud permanent
ip -n $H -6 neigh replace fe80::66:2 lladdr $SIDEMAC dev mmesh nud permanent
ip -n $S neigh replace 169.254.66.1 lladdr $HOSTMAC dev mmesh-c nud permanent
ip -n $S -6 neigh replace fe80::66:1 lladdr $HOSTMAC dev mmesh-c nud permanent
ip -n $S route replace 10.66.0.0/16 via 169.254.66.1 dev mmesh-c
ip -n $S -6 route replace fd66::/48 via fe80::66:1 dev mmesh-c

# sidecar <-> far (stands in for the warp device and the Mesh)
ip link add w0 netns $S type veth peer name f0 netns $F
ip -n $S link set w0 up
ip -n $F link set f0 up
ip -n $S addr add 198.51.100.254/24 dev w0
ip -n $F addr add 198.51.100.1/24 dev f0
ip -n $S -6 addr add 2001:db8:66::fe/64 dev w0 nodad
ip -n $F -6 addr add 2001:db8:66::1/64 dev f0 nodad
ip -n $F route add 10.66.0.0/16 via 198.51.100.254
ip -n $F -6 route add fd66::/48 via 2001:db8:66::fe
# Only what arrives on mmesh-c is policy-routed to the "warp" device.
ip -n $S route add 198.51.100.0/24 dev w0 table 170
ip -n $S -6 route add 2001:db8:66::/64 dev w0 table 170
ip -n $S route add unreachable default metric 32767 table 170
ip -n $S -6 route add unreachable default metric 32767 table 170
ip -n $S rule add iif mmesh-c lookup 170 priority 17000
ip -n $S -6 rule add iif mmesh-c lookup 170 priority 17000
# Return traffic from the far side reaches the sidecar on w0 and follows
# main, where 10.66.0.0/16 and fd66::/48 point back via the host end.

# host: a WAN default route in main, as on the real hub (loose rp_filter
# needs some route back to a public source), then the exit table like
# meridian-routes.sh renders it for a Mesh exit.
ip -n $H link add wan0 type dummy
ip -n $H link set wan0 up
ip -n $H addr add 203.0.113.2/24 dev wan0
ip -n $H route add default via 203.0.113.1 dev wan0
ip -n $H rule add iif h0 lookup 1101 priority 17000
ip -n $H -6 rule add iif h0 lookup 1101 priority 17000
set_exit_table() {
  ip -n $H route flush table 1101 2>/dev/null || true
  ip -n $H -6 route flush table 1101 2>/dev/null || true
  ip -n $H route add blackhole default metric 32767 table 1101
  ip -n $H -6 route add blackhole default metric 32767 table 1101
  if [ "$1" = via ]; then
    ip -n $H route replace default via 169.254.66.2 dev mmesh table 1101
    ip -n $H -6 route replace default via fe80::66:2 dev mmesh table 1101
  else
    ip -n $H route replace default dev mmesh table 1101
    ip -n $H -6 route replace default dev mmesh table 1101
  fi
  ip -n $H neigh flush dev mmesh nud reachable nud stale nud failed nud incomplete 2>/dev/null || true
  ip -n $H -6 neigh flush dev mmesh nud reachable nud stale nud failed nud incomplete 2>/dev/null || true
}

run() { name=$1; shift; "$@" > "$evdir/$name.txt" 2>&1; rc=$?; echo "exit=$rc" >> "$evdir/$name.txt"; return $rc; }
tcp_probe() {
  # $1 family flag, $2 address. Uses bash /dev/tcp from the client against a
  # listener on the far host when python3 is available; otherwise skipped.
  command -v python3 >/dev/null 2>&1 || return 3
  ip netns exec $F python3 -c "import socket,sys;s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],8066));s.listen(1);s.settimeout(6);c,_=s.accept();c.close()" "$2" &
  lp=$!
  sleep 0.5
  ip netns exec $C python3 -c "import socket,sys;s=socket.create_connection((sys.argv[1],8066),timeout=4);s.close()" "$2"
  rc=$?
  wait $lp 2>/dev/null
  return $rc
}

ip -n $H addr > "$evdir/host-addr.txt" 2>&1
ip -n $S addr > "$evdir/side-addr.txt" 2>&1

# --- fixed form: explicit next-hops ---------------------------------------
set_exit_table via
ip -n $H route show table 1101 > "$evdir/table-1101-via.txt"
ip -n $H -6 route show table 1101 >> "$evdir/table-1101-via.txt"
if run forward-v4 ip netns exec $C ping -c 3 -W 2 -n 198.51.100.1; then
  pass forward_v4 "10.66.200.2 -> 198.51.100.1 via 169.254.66.2 dev mmesh (evidence forward-v4.txt)"
else
  fail forward_v4 "no IPv4 forwarding through the veth next-hop (evidence forward-v4.txt)"
fi
if run forward-v6 ip netns exec $C ping -6 -c 3 -W 2 -n 2001:db8:66::1; then
  pass forward_v6 "fd66:0:0:ff::2 -> 2001:db8:66::1 via fe80::66:2 dev mmesh (evidence forward-v6.txt)"
else
  fail forward_v6 "no IPv6 forwarding through the veth next-hop (evidence forward-v6.txt)"
fi
tcp_probe -4 198.51.100.1 > "$evdir/tcp-v4.txt" 2>&1; rc=$?
case $rc in 0) pass tcp_v4 "TCP connect to 198.51.100.1:8066" ;; 3) emit "NOT-RUN-HERE tcp_v4: python3 missing" ;; *) fail tcp_v4 "TCP connect failed (evidence tcp-v4.txt)" ;; esac
tcp_probe -6 2001:db8:66::1 > "$evdir/tcp-v6.txt" 2>&1; rc=$?
case $rc in 0) pass tcp_v6 "TCP connect to [2001:db8:66::1]:8066" ;; 3) emit "NOT-RUN-HERE tcp_v6: python3 missing" ;; *) fail tcp_v6 "TCP connect failed (evidence tcp-v6.txt)" ;; esac
ip -n $H -4 neigh show dev mmesh > "$evdir/neigh-v4-via.txt" 2>&1
ip -n $H -6 neigh show dev mmesh > "$evdir/neigh-v6-via.txt" 2>&1
stray4=$(awk '$1 != "169.254.66.2" {print $1}' "$evdir/neigh-v4-via.txt" | tr '\n' ' ')
stray6=$(awk '$1 != "fe80::66:2" {print $1}' "$evdir/neigh-v6-via.txt" | tr '\n' ' ')
if [ -z "$stray4" ]; then pass no_stray_neigh_v4 "only 169.254.66.2 resolved on mmesh"; else fail no_stray_neigh_v4 "extra entries: $stray4"; fi
if [ -z "$stray6" ]; then pass no_stray_neigh_v6 "only fe80::66:2 resolved on mmesh"; else fail no_stray_neigh_v6 "extra entries: $stray6"; fi

# --- control: the audited form without a next-hop must not forward ---------
set_exit_table dev
if run control-v4 ip netns exec $C ping -c 2 -W 2 -n 198.51.100.1; then
  fail control_dev_only_v4 "default dev mmesh forwarded; the control did not reproduce the finding (evidence control-v4.txt)"
else
  ip -n $H -4 neigh show dev mmesh > "$evdir/neigh-v4-dev.txt" 2>&1
  if grep -q '^198\.51\.100\.1 ' "$evdir/neigh-v4-dev.txt"; then
    pass control_dev_only_v4 "default dev mmesh: host ARP-probed 198.51.100.1 on the veth and nothing answered"
  else
    pass control_dev_only_v4 "default dev mmesh did not forward (no neighbour entry captured; evidence neigh-v4-dev.txt)"
  fi
fi
if run control-v6 ip netns exec $C ping -6 -c 2 -W 2 -n 2001:db8:66::1; then
  fail control_dev_only_v6 "default dev mmesh forwarded IPv6; the control did not reproduce the finding (evidence control-v6.txt)"
else
  ip -n $H -6 neigh show dev mmesh > "$evdir/neigh-v6-dev.txt" 2>&1
  pass control_dev_only_v6 "default dev mmesh (IPv6) did not forward (evidence neigh-v6-dev.txt)"
fi

emit "evidence: $evdir"
if [ "$fails" -ne 0 ]; then
  emit "meridian-mesh-veth-verify-failed: $fails failed"
  exit 1
fi
emit "meridian-mesh-veth-verify-ok: the host <-> sidecar hop forwards IPv4 and IPv6 through explicit next-hops in namespaces. This does not test Cloudflare, the real sidecar image or a real exit."
exit 0
