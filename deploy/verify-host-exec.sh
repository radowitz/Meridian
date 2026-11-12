#!/bin/bash
# Verify the host execution boundary and the boot ordering on the real
# Debian 13 gateway, after deploy/debian/install.sh and `docker compose up -d`.
# Read-only except for two harmless requests to meridian-host (a health
# probe and a deliberately invalid action). It does not install, restart or
# remove anything, and never prints the agent token.
#
#   sudo bash deploy/verify-host-exec.sh            # wiring checks
#   sudo bash deploy/verify-host-exec.sh --boot     # also boot-order checks (run right after a reboot)
#
# Exit 0 only when every check passed.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
if docker compose version >/dev/null 2>&1; then
  compose=(docker compose -f "${here}/docker-compose.yml")
else
  compose=(docker-compose -f "${here}/docker-compose.yml")
fi

sock=/run/meridian-host/agent.sock
tok=/etc/meridian-host/agent.token

# 1. agent service, socket and token permissions.
systemctl is-active --quiet meridian-host.service && ok "meridian-host active" || bad "meridian-host not active"
[[ -S "$sock" ]] && ok "socket present" || bad "no socket at $sock"
[[ "$(stat -c '%a %U' "$sock" 2>/dev/null)" == "600 root" ]] && ok "socket 0600 root" || bad "socket mode/owner: $(stat -c '%a %U' "$sock" 2>/dev/null)"
[[ "$(stat -c '%a %U' /run/meridian-host 2>/dev/null)" == "700 root" ]] && ok "socket dir 0700 root" || bad "socket dir mode/owner"
[[ "$(stat -c '%a %U' "$tok" 2>/dev/null)" == "600 root" ]] && ok "token 0600 root" || bad "token mode/owner"
for u in meridian-host.service meridian-guard.service meridian.service; do
  if systemd-analyze verify "/etc/systemd/system/$u" >/dev/null 2>&1; then ok "systemd-analyze verify $u"; else bad "systemd-analyze verify $u: $(systemd-analyze verify /etc/systemd/system/$u 2>&1 | head -3)"; fi
done
systemctl is-enabled --quiet meridian-guard.service && ok "meridian-guard enabled" || bad "meridian-guard not enabled"
systemctl is-enabled --quiet meridian.service && ok "meridian.service enabled" || bad "meridian.service not enabled"

# 2. the panel container: no host privileges, but it can reach the agent.
cid="$("${compose[@]}" ps -q meridian 2>/dev/null)"
if [[ -z "$cid" ]]; then
  bad "panel container not running"
else
  caps="$(docker inspect -f '{{.HostConfig.CapAdd}}' "$cid")"
  [[ "$caps" != *NET_ADMIN* ]] && ok "panel has no NET_ADMIN" || bad "panel still has NET_ADMIN: $caps"
  if docker exec "$cid" sh -c 'command -v systemctl' >/dev/null 2>&1; then bad "panel image has systemctl"; else ok "panel has no systemctl"; fi
  probe() { # $1 = JSON body; prints the HTTP status; the token stays inside the container
    docker exec -i "$cid" sh -c 'curl -s -o /dev/null -w "%{http_code}" --unix-socket /run/meridian-host/agent.sock \
      -H "Authorization: Bearer $(cat /run/secrets/meridian-host.token)" -H "Content-Type: application/json" \
      --data-binary @- http://meridian-host/v1/action' <<<"$1"
  }
  code="$(probe '{"action":"health","request_id":"verify-health-'"$$"'"}')"
  [[ "$code" == 200 ]] && ok "panel -> agent health probe" || bad "health probe HTTP $code"
  code="$(probe '{"action":"run","request_id":"verify-bad-'"$$"'"}')"
  [[ "$code" == 400 ]] && ok "unknown action refused" || bad "unknown action HTTP $code"
  code="$(probe '{"action":"health","request_id":"verify-x-'"$$"'","command":"id"}')"
  [[ "$code" == 400 ]] && ok "extra field refused" || bad "extra field HTTP $code"
  code="$(docker exec "$cid" sh -c 'curl -s -o /dev/null -w "%{http_code}" --unix-socket /run/meridian-host/agent.sock -d "{\"action\":\"health\",\"request_id\":\"n\"}" http://meridian-host/v1/action')"
  [[ "$code" == 401 ]] && ok "request without token refused" || bad "no-token HTTP $code"
fi

# 3. forwarding is never switched on by sysctl.d at boot.
if grep -RhsE '^\s*net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)\s*=\s*1' /etc/sysctl.d /etc/sysctl.conf /run/sysctl.d /usr/lib/sysctl.d >/dev/null; then
  bad "a sysctl file enables forwarding at boot: $(grep -RlsE '^\s*net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)\s*=\s*1' /etc/sysctl.d /etc/sysctl.conf /run/sysctl.d /usr/lib/sysctl.d | tr '\n' ' ')"
else
  ok "no sysctl file enables forwarding"
fi
grep -q '"ip-forward": *false' /etc/docker/daemon.json 2>/dev/null && ok "dockerd ip-forward false" || bad "dockerd may enable forwarding at start (/etc/docker/daemon.json)"

# 4. after a reboot: the guard was loaded before systemd-sysctl and before
#    forwarding came on; meridian.service then turned forwarding on.
if [[ "${1:-}" == "--boot" ]]; then
  g="$(systemctl show -p ExecMainExitTimestampMonotonic --value meridian-guard.service)"
  s="$(systemctl show -p ExecMainStartTimestampMonotonic --value systemd-sysctl.service)"
  d="$(systemctl show -p ExecMainStartTimestampMonotonic --value docker.service)"
  if [[ "$g" -gt 0 && "$g" -le "$s" ]]; then ok "guard loaded before systemd-sysctl ($g <= $s)"; else bad "guard not before systemd-sysctl (guard exit $g, sysctl start $s)"; fi
  if [[ "$g" -gt 0 && "$g" -le "$d" ]]; then ok "guard loaded before dockerd ($g <= $d)"; else bad "guard not before dockerd (guard exit $g, docker start $d)"; fi
  nft list table inet meridian_guard >/dev/null 2>&1 && ok "inet meridian_guard loaded" || bad "inet meridian_guard missing"
  restarts="$(systemctl show -p NRestarts --value meridian.service 2>/dev/null)"
  [[ -n "$restarts" && "$restarts" != 0 ]] && echo "info meridian.service was retried $restarts time(s) at boot (meridian-lan-not-ready in: journalctl -b -u meridian.service)"
  if systemctl is-active --quiet meridian.service; then
    ok "meridian.service active"
    for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
      [[ "$(sysctl -n "$key")" == 1 ]] && ok "$key on after meridian.service" || bad "$key off although meridian.service is active"
    done
  else
    # No forwarding verdict without an active data plane: "forwarding on"
    # would not mean the gateway works.
    bad "meridian.service not active ($(systemctl is-active meridian.service 2>/dev/null)); forwarding not judged (ipv4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) ipv6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)); journalctl -b -u meridian.service"
  fi
fi

exit "$fail"
