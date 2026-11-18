#!/bin/bash
# Integration check for the Compose SmartDNS service on the gateway host.
# Run as root on the Debian gateway after one install (POST /api/apply with
# install=true) has written /etc/smartdns/smartdns.conf and loaded the
# inet meridian nft table (the real generated firewall, input chain included):
#
#   sudo bash deploy/verify-smartdns.sh [test-domain]
#   sudo MERIDIAN_GW_ADDR=<gateway LAN IPv4> bash deploy/verify-smartdns.sh   # required
#   bash deploy/verify-smartdns.sh --list-refs FILE   # print the files a config loads (used by go test)
#   sudo bash deploy/verify-smartdns.sh --audit-check [--record] [IMAGE]   # is the resolver image's audit log safe to turn on (see below)
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

# --audit-check [--record] [IMAGE]: is the audit log of a resolver image safe
# to turn on (the DNS query journal, settings dns_log)? The panel's
# capability gate accepts a SmartDNS version only when its audit behaviour
# was verified: the versions listed in internal/dnsjournal/gate.go, or a
# version this mode verified on this host and recorded with --record.
#
# It starts throw-away containers of the image WITHOUT a network (docker run
# --network none), with a synthetic config (names under example.test,
# documentation addresses, an upstream that never answers) written inside
# the container, and asks them questions from inside. It never touches the
# running meridian-smartdns container, its config or its files, pulls
# nothing and sends nothing anywhere. IMAGE defaults to the image the
# meridian-smartdns container was created from. Checks:
#
#   format     every audit line matches the pattern the journal's parser
#              reads; one line per answered query; several answers on one
#              line; an empty result for a name without an answer; a name
#              blocked by an "address /name/#" rule is NOT audited
#   rotation   at audit-size the file is rotated to audit.log-YYYYMMDD-HHMMSS.gz
#              (valid gzip, same lines), at most audit-num copies are kept
#   truncate   after another process truncates the audit file the resolver
#              keeps answering and writes on from the start of the file (what
#              the journal's "clear" and its byte budget rely on)
#   full       with the audit filesystem full, 200 of 200 queries are answered
#   frozen     with every write to the audit filesystem blocked (fsfreeze on a
#              private loop-mounted ext4), 60 of 60 queries are answered
#              (Linux, root, fsfreeze and mkfs.ext4; SKIP otherwise)
#   readonly   with a read-only audit directory the resolver answers
#   missing    with a missing audit directory the resolver answers
#   fifo       informational: whether the resolver still answers with a FIFO
#              at the audit path. On 2026-11-15 this check found no stall,
#              on a real gateway and on a workstation (an earlier manual
#              experiment had been inconclusive). The journal only ever
#              lets the path be a regular file all the same: a special file
#              there has no legitimate use and its behaviour is not
#              something to depend on
#
# Exit 0 and "meridian-smartdns-audit-verify-ok version=… image=…" only when
# every check passed and none was skipped; --record then appends
# "<version> <image id> <date>" to /etc/meridian-host/smartdns-audit-verified
# (root). Exit 3 when nothing failed but a check was skipped (nothing is
# recorded), 1 when a check failed, 2 when it could not run.
audit_re='^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}\] [^ ]+ query .*, type [0-9]+, time [0-9]+ms, speed: -?[0-9.]+ms, group [^ ]*, result .*$'
audit_record=/etc/meridian-host/smartdns-audit-verified
audit_check() {
  set +e
  local record=0 image="" image_id version
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --record) record=1 ;;
      -*) echo "usage: verify-smartdns.sh --audit-check [--record] [IMAGE]" >&2; return 2 ;;
      *) image="$1" ;;
    esac
    shift
  done
  command -v docker >/dev/null 2>&1 || { echo "missing docker" >&2; return 2; }
  if [[ -z "$image" ]]; then
    image="$(docker inspect --type container -f '{{.Image}}' meridian-smartdns 2>/dev/null)"
    [[ -n "$image" ]] || { echo "no meridian-smartdns container on this host: name the image to check" >&2; return 2; }
  fi
  image_id="$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null)"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "image ${image} is not on this host (nothing is pulled)" >&2; return 2; }
  version="$(docker run --rm --network none --entrypoint /usr/sbin/smartdns "$image_id" -v 2>/dev/null | awk '$1 == "smartdns" && NF >= 2 { print $2; exit }')"
  [[ "$version" =~ ^[0-9][0-9A-Za-z.+_-]{2,40}$ ]] || { echo "the image's /usr/sbin/smartdns -v gives no version" >&2; return 2; }
  echo "image ${image_id}"
  echo "version ${version}"

  local conf prefix="meridian-audit-check-$$" seq=0 cur="" afail=0 askip=0
  local work="" mnt="" mounted=0 frozen=0 watchdog=""
  conf='bind [::]:53
bind-tcp [::]:53
cache-size 0
speed-check-mode none
address /a.example.test/192.0.2.1
address /b.example.test/2001:db8::1
address /multi.example.test/192.0.2.1,192.0.2.2,192.0.2.3
address /blocked.example.test/#
server 127.0.0.1:9
audit-enable yes
audit-file /audit/audit.log
audit-size 32k
audit-num 2'
  a_ok() { echo "OK   $1: $2"; }
  a_bad() { echo "FAIL $1: $2" >&2; afail=$((afail + 1)); }
  a_skip() { echo "SKIP $1: $2"; askip=$((askip + 1)); }
  a_info() { echo "INFO $1: $2"; }
  # a_start PRE DOCKER_ARGS...: a container without a network; PRE runs
  # inside it before the resolver starts.
  a_start() {
    local pre="$1"
    shift
    seq=$((seq + 1))
    cur="${prefix}-${seq}"
    docker run -d --rm --network none --name "$cur" -e "AUDIT_CONF=${conf}" "$@" "$image_id" \
      sh -c "${pre} printf '%s\\n' \"\$AUDIT_CONF\" > /tmp/smartdns.conf && exec /usr/sbin/smartdns -f -x -c /tmp/smartdns.conf" >/dev/null 2>&1
    sleep 3
  }
  a_stop() {
    [[ -n "$cur" ]] && docker rm -f "$cur" >/dev/null 2>&1
    cur=""
  }
  a_in() { docker exec "$cur" sh -c "$1" 2>/dev/null; }
  # a_ask NAME COUNT: how many of COUNT questions for NAME got 192.0.2.1.
  a_ask() {
    a_in "n=0; i=0; while [ \$i -lt $2 ]; do timeout 3 nslookup $1 127.0.0.1 2>/dev/null | grep -q 192.0.2.1 && n=\$((n+1)); i=\$((i+1)); done; echo \$n"
  }
  a_cleanup() {
    local c
    [[ -n "$watchdog" ]] && kill "$watchdog" >/dev/null 2>&1
    [[ "$frozen" -eq 1 ]] && fsfreeze -u "$mnt" >/dev/null 2>&1
    frozen=0
    for c in $(docker ps -aq --filter "name=${prefix}-" 2>/dev/null); do docker rm -f "$c" >/dev/null 2>&1; done
    [[ "$mounted" -eq 1 ]] && umount "$mnt" >/dev/null 2>&1
    mounted=0
    [[ -n "$work" && "$work" == */meridian-audit-check.* ]] && rm -rf "$work"
    work=""
  }
  trap a_cleanup EXIT

  # format
  local log total good n
  a_start "" --tmpfs /audit:rw,size=4m,mode=0700
  if [[ "$(a_ask a.example.test 1)" != 1 ]]; then
    a_bad format "the resolver did not answer in the test container: nothing was checked"
    a_cleanup
    return 1
  fi
  a_in 'nslookup -type=aaaa b.example.test 127.0.0.1; nslookup multi.example.test 127.0.0.1; nslookup blocked.example.test 127.0.0.1; nslookup nx.example.test 127.0.0.1; nslookup a.example.test ::1' >/dev/null 2>&1
  sleep 4
  log="$(a_in 'cat /audit/audit.log')"
  total="$(grep -c . <<<"$log")"
  good="$(grep -Ec "$audit_re" <<<"$log")"
  if [[ "$total" -gt 0 && "$good" -eq "$total" ]]; then a_ok format "${total} audit lines, all in the format the journal reads"; else a_bad format "${good} of ${total} audit lines are in the format the journal reads"; fi
  if grep -Eq ' query a\.example\.test, type 1, .*, result 192\.0\.2\.1$' <<<"$log"; then a_ok format "an answered query has its address as the result"; else a_bad format "no line for the answered A query"; fi
  if grep -Eq ' query b\.example\.test, type 28, .*, result 2001:db8::1$' <<<"$log"; then a_ok format "an AAAA query is type 28"; else a_bad format "no line for the answered AAAA query"; fi
  if grep -Eq ' query multi\.example\.test, type 1, .*, result (192\.0\.2\.[123], ){2}192\.0\.2\.[123]$' <<<"$log"; then a_ok format "several answers are on one line, separated by a comma and a blank"; else a_bad format "several answers are not written as \"a, b, c\""; fi
  if grep -Eq ' query nx\.example\.test, type [0-9]+, .*, result $' <<<"$log"; then a_ok format "a name without an answer has an empty result"; else a_bad format "no empty-result line for a name without an answer"; fi
  if grep -q 'blocked\.example\.test' <<<"$log"; then a_bad format "a name blocked by an address rule IS audited by this version: the journal says such names are absent"; else a_ok format "a name blocked by an address rule is not audited"; fi
  if grep -Eq '\] ::1 query a\.example\.test' <<<"$log"; then a_ok format "an IPv6 client is written as its address"; else a_info format "no IPv6 loopback in the test container: an IPv6 client's line was not seen"; fi
  a_info mode "the resolver's audit file is mode $(a_in 'stat -c %a /audit/audit.log') (the journal keeps it in a 0700 directory and sets it back to 0600)"

  # rotation
  local names rotated
  a_in 'i=0; while [ $i -lt 500 ]; do nslookup multi.example.test 127.0.0.1 >/dev/null 2>&1; i=$((i+1)); done'
  sleep 4
  names="$(a_in 'ls /audit')"
  rotated="$(grep -Ec '^audit\.log-[0-9]{8}-[0-9]{6}\.gz$' <<<"$names")"
  n="$(grep -Evc '^(audit\.log|audit\.log-[0-9]{8}-[0-9]{6}\.gz|audit\.log\.pending\.gz)$' <<<"$names")"
  if [[ "$rotated" -ge 1 && "$rotated" -le 2 && "$n" -eq 0 ]]; then a_ok rotation "${rotated} rotated file(s) named audit.log-YYYYMMDD-HHMMSS.gz, at most audit-num"; else a_bad rotation "unexpected files after rotation: $(tr '\n' ' ' <<<"$names")"; fi
  if a_in 'for f in /audit/audit.log-*.gz; do gzip -t "$f" || exit 1; done'; then a_ok rotation "the rotated files are valid gzip"; else a_bad rotation "a rotated file is not valid gzip"; fi
  log="$(a_in 'zcat /audit/audit.log-*.gz')"
  total="$(grep -c . <<<"$log")"
  good="$(grep -Ec "$audit_re" <<<"$log")"
  if [[ "$total" -gt 0 && "$good" -eq "$total" ]]; then a_ok rotation "${total} lines in the rotated files, all in the same format"; else a_bad rotation "${good} of ${total} rotated lines are in the format the journal reads"; fi

  # truncate
  a_in ': > /audit/audit.log'
  if [[ "$(a_ask a.example.test 5)" == 5 ]]; then a_ok truncate "the resolver answers after another process truncated the audit file"; else a_bad truncate "the resolver stopped answering after the audit file was truncated"; fi
  sleep 3
  if [[ "$(a_in 'head -c 1 /audit/audit.log')" == "[" && "$(a_in 'stat -c %s /audit/audit.log')" -lt 8192 ]]; then
    a_ok truncate "it writes on from the start of the truncated file (append mode)"
  else
    a_bad truncate "after a truncation the file does not start with a new line (a sparse file): the journal's clear and byte budget cannot rely on truncation"
  fi
  a_stop

  # full
  a_start "" --tmpfs /audit:rw,size=256k,mode=0700
  a_ask a.example.test 3 >/dev/null
  a_in 'dd if=/dev/zero of=/audit/fill bs=1k 2>/dev/null; true'
  if [[ "$(a_in 'echo x > /audit/probe 2>/dev/null && echo writable || echo full')" != full ]]; then
    a_skip full "the audit filesystem could not be filled"
  else
    n="$(a_ask a.example.test 200)"
    if [[ "$n" == 200 ]]; then a_ok full "200 of 200 queries answered with the audit filesystem full (audit file now $(a_in 'stat -c %s /audit/audit.log') bytes)"; else a_bad full "${n:-0} of 200 queries answered with the audit filesystem full"; fi
  fi
  a_stop

  # frozen
  if [[ "$(uname -s)" != Linux || "${EUID}" -ne 0 ]] || ! command -v fsfreeze >/dev/null 2>&1 || ! command -v mkfs.ext4 >/dev/null 2>&1 || ! command -v findmnt >/dev/null 2>&1; then
    a_skip frozen "needs Linux, root, fsfreeze, mkfs.ext4 and findmnt: a blocked audit write was not checked"
  else
    work="$(mktemp -d /var/tmp/meridian-audit-check.XXXXXX)"
    mnt="${work}/mnt"
    mkdir "$mnt"
    if truncate -s 32M "${work}/fs.img" && mkfs.ext4 -q -F "${work}/fs.img" && mount -o loop "${work}/fs.img" "$mnt"; then
      mounted=1
      # Only ever freeze the private loop mount made above.
      if [[ "$(findmnt -n -o TARGET --target "$mnt")" != "$mnt" || "$(findmnt -n -o SOURCE --target "$mnt")" != /dev/loop* ]]; then
        a_skip frozen "the private loop mount is not what findmnt reports: nothing was frozen"
      else
        mkdir -m 0700 "${mnt}/audit"
        a_start "" -v "${mnt}/audit:/audit"
        a_ask a.example.test 3 >/dev/null
        local t0 t1
        if fsfreeze -f "$mnt"; then
          frozen=1
          # Unfreeze whatever happens to this script.
          (sleep 90; fsfreeze -u "$mnt") >/dev/null 2>&1 &
          watchdog=$!
          t0="$(date +%s)"
          n="$(a_ask a.example.test 60)"
          t1="$(date +%s)"
          fsfreeze -u "$mnt"
          frozen=0
          kill "$watchdog" >/dev/null 2>&1
          watchdog=""
          sleep 3
          if [[ "$n" == 60 && $((t1 - t0)) -le 30 ]]; then
            a_ok frozen "60 of 60 queries answered in $((t1 - t0)) s while every write to the audit filesystem blocked; $(grep -c 'query a\.example\.test' "${mnt}/audit/audit.log" 2>/dev/null) lines in the file after unfreezing"
          else
            a_bad frozen "${n:-0} of 60 queries answered in $((t1 - t0)) s while the audit filesystem was frozen"
          fi
        else
          a_skip frozen "fsfreeze -f failed on the private loop mount"
        fi
        a_stop
      fi
      umount "$mnt" >/dev/null 2>&1 && mounted=0
    else
      a_skip frozen "a private loop-mounted ext4 could not be made"
    fi
    rm -rf "$work"
    work=""
  fi

  # readonly, missing
  a_start "" --tmpfs /audit:ro,size=256k,mode=0700
  n="$(a_ask a.example.test 5)"
  if [[ "$n" == 5 ]]; then a_ok readonly "the resolver answers with a read-only audit directory"; else a_bad readonly "${n:-0} of 5 queries answered with a read-only audit directory"; fi
  a_stop
  a_start ""
  n="$(a_ask a.example.test 5)"
  if [[ "$n" == 5 ]]; then a_ok missing "the resolver answers when the audit directory does not exist (it is now $(a_in 'stat -c "%F %a" /audit' || echo absent))"; else a_bad missing "${n:-0} of 5 queries answered with a missing audit directory"; fi
  a_stop

  # fifo (informational)
  a_start "mkfifo /audit/audit.log;" --tmpfs /audit:rw,size=256k,mode=0700
  n="$(a_ask a.example.test 5)"
  if [[ "$n" == 5 ]]; then
    a_info fifo "the resolver answers with a FIFO at the audit path (5 of 5); the journal still only ever lets the path be a regular file"
  else
    a_info fifo "with a FIFO at the audit path only ${n:-0} of 5 queries were answered: the journal only ever lets the path be a regular file"
  fi
  a_stop
  a_cleanup
  trap - EXIT

  if [[ "$afail" -gt 0 ]]; then
    echo "meridian-smartdns-audit-verify-failed version=${version} image=${image_id}" >&2
    return 1
  fi
  if [[ "$askip" -gt 0 ]]; then
    echo "meridian-smartdns-audit-verify-incomplete version=${version} image=${image_id} skipped=${askip} (nothing is recorded)"
    return 3
  fi
  echo "meridian-smartdns-audit-verify-ok version=${version} image=${image_id}"
  if [[ "$record" -eq 1 ]]; then
    [[ "${EUID}" -eq 0 ]] || { echo "--record needs root" >&2; return 2; }
    install -d -m 0700 "$(dirname "$audit_record")"
    if ! grep -qsF "${version} ${image_id} " "$audit_record"; then
      echo "${version} ${image_id} $(date -u +%Y-%m-%d)" >>"$audit_record"
    fi
    chmod 0600 "$audit_record"
    echo "recorded in ${audit_record}"
  fi
  return 0
}
if [[ "${1:-}" == "--audit-check" ]]; then
  shift
  audit_check "$@"
  exit $?
fi

here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose -f "${here}/docker-compose.yml" --profile dns)
conf=/etc/smartdns/smartdns.conf
gw="${MERIDIAN_GW_ADDR:?set MERIDIAN_GW_ADDR to the gateway LAN IPv4 address}"
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
