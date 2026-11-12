#!/bin/bash
# Integration check for the Compose SmartDNS service on the gateway host.
# Run as root on the Debian gateway after one install (POST /api/apply with
# install=true) has written /etc/smartdns/smartdns.conf and loaded the
# inet meridian nft table (the real generated firewall, input chain included):
#
#   sudo bash deploy/verify-smartdns.sh [test-domain]
#   sudo MERIDIAN_GW_ADDR=192.168.100.88 bash deploy/verify-smartdns.sh   # gateway LAN address (default shown)
#   bash deploy/verify-smartdns.sh --list-refs FILE   # print the files a config loads (used by go test)
#
# It proves, in the actual image and with the firewall loaded:
#   1. every file the generated config loads (domain-set -file,
#      bind-cert-file, bind-cert-key-file) exists on the host and is visible
#      inside the container at the same path;
#   2. the container has NET_ADMIN and stays running;
#   3. the resolver answers on the gateway LAN address from that address
#      (the path LAN clients use) and on 127.0.0.1 (this host's own queries;
#      the input chain accepts loopback before its LAN-only drop);
#   4. resolving a domain from geosite/cn.txt (or the argument) adds its
#      address to nft set inet meridian direct4 (nftset write path).
# It changes nothing except starting the smartdns profile container.
# Exit status 0 only when all checks pass.
set -euo pipefail

# Files a SmartDNS config loads; must match compile.SmartDNSFileRefs.
list_refs() {
  awk '!/^[[:space:]]*#/ {
    if (($1 == "bind-cert-file" || $1 == "bind-cert-key-file") && NF >= 2) { print $2; next }
    for (i = 1; i < NF; i++) if ($i == "-file") print $(i + 1)
  }' "$1"
}
if [[ "${1:-}" == "--list-refs" ]]; then
  list_refs "${2:?usage: --list-refs FILE}"
  exit 0
fi

here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose -f "${here}/docker-compose.yml" --profile dns)
conf=/etc/smartdns/smartdns.conf
gw="${MERIDIAN_GW_ADDR:-192.168.100.88}"
fail=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*" >&2; fail=1; }

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
for bin in docker nft dig; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing $bin (apt-get install -y docker.io nftables bind9-dnsutils)" >&2; exit 2; }
done
[[ -s "$conf" ]] || { echo "missing $conf: apply with install=true first" >&2; exit 2; }
nft list table inet meridian >/dev/null 2>&1 || { echo "nft table inet meridian is not loaded: apply with install=true first" >&2; exit 2; }

input_chain="$(nft list chain inet meridian input 2>/dev/null || true)"
if [[ "$input_chain" != *"DNS only from the LAN"* ]]; then
  echo "inet meridian has no DNS input restriction: load the generated firewall (install) first" >&2; exit 2
fi
addrs4="$(ip -4 -o addr show 2>/dev/null || true)"
[[ "$addrs4" == *" ${gw}/"* ]] || { echo "this host does not carry ${gw}; set MERIDIAN_GW_ADDR to the gateway LAN address" >&2; exit 2; }

# 1. host-side prerequisites referenced by the config.
mapfile -t refs < <(list_refs "$conf" | sort -u)
for f in "${refs[@]}"; do
  if [[ -e "$f" ]]; then ok "host has $f"; else bad "host is missing $f"; fi
done

# 2. start the container and check privileges / liveness.
"${compose[@]}" up -d smartdns
cid="$("${compose[@]}" ps -q smartdns)"
[[ -n "$cid" ]] || { bad "smartdns container not created"; exit 1; }
sleep 3
if [[ "$(docker inspect -f '{{.State.Running}}' "$cid")" == "true" ]]; then ok "container running"; else bad "container exited"; docker logs --tail 50 "$cid" >&2 || true; fi
if docker inspect -f '{{.HostConfig.CapAdd}}' "$cid" | grep -q NET_ADMIN; then ok "NET_ADMIN granted"; else bad "NET_ADMIN not granted"; fi
for f in "${refs[@]}"; do
  if docker exec "$cid" test -r "$f"; then ok "container reads $f"; else bad "container cannot read $f"; fi
done

# 3. resolver answers with the firewall loaded: from the LAN address (as a
#    LAN client is seen by the input chain) and over loopback.
if dig -b "$gw" +time=3 +tries=2 @"$gw" example.com A >/dev/null; then ok "resolver answers on ${gw}:53 (source ${gw})"; else bad "no answer on ${gw}:53"; fi
if dig +tcp -b "$gw" +time=3 +tries=2 @"$gw" example.com A >/dev/null; then ok "resolver answers on ${gw}:53/tcp"; else bad "no TCP answer on ${gw}:53"; fi
if dig +time=3 +tries=2 @127.0.0.1 example.com A >/dev/null; then ok "resolver answers on 127.0.0.1:53"; else bad "no answer on 127.0.0.1:53 (input chain loopback accept missing?)"; fi

# 4. nftset population.
domain="${1:-}"
if [[ -z "$domain" ]]; then
  domain="$(grep -m1 -E '^[a-z0-9.-]+\.[a-z]+$' /var/lib/meridian/geosite/cn.txt 2>/dev/null || true)"
fi
if [[ -z "$domain" ]]; then
  bad "no test domain: geosite/cn.txt is empty (run meridian-update-geosite.sh) and none was given"
else
  mapfile -t addrs < <(dig -b "$gw" +short +time=3 @"$gw" "$domain" A | grep -E '^[0-9.]+$' || true)
  if [[ ${#addrs[@]} -eq 0 ]]; then
    bad "$domain did not resolve to A records"
  else
    set_dump="$(nft list set inet meridian direct4)"
    hit=0
    for a in "${addrs[@]}"; do
      if grep -qw -- "$a" <<<"$set_dump"; then hit=1; fi
    done
    if [[ $hit -eq 1 ]]; then ok "$domain address is in inet meridian direct4"; else bad "$domain (${addrs[*]}) not added to inet meridian direct4"; fi
  fi
fi

if [[ $fail -eq 0 ]]; then
  echo meridian-smartdns-verify-ok
else
  echo meridian-smartdns-verify-failed >&2
  exit 1
fi
