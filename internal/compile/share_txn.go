package compile

// The switch owns only the three relay chains, relay defaults, table 102's
// defaults and the two aggregate tunnel routes. A successful argument vector
// plus its compiled version is a complete snapshot of these objects: replay
// never captures a partially changed kernel state. Other nft tables/routes,
// including management host routes and Mesh seals, are never restored/flushed.
const shareTransactionShell = `
SH_TXN="${SH_APPLIED%/*}/switch"
share_lock() {
  mkdir -p "$SH_TXN" || return 4
  chmod 700 "$SH_TXN" || return 4
  exec 8>>"$SH_TXN/lock" || return 4
  flock -w 30 8 || return 4
}
share_guard_on() {
  # Independent table: neither the assignment batch nor installation of the
  # base rules can remove this fence. Existing guards still evaluate returns.
  nft -f - <<'SH_GUARD'
table inet meridian_switch
delete table inet meridian_switch
table inet meridian_switch {
  chain forward {
    type filter hook forward priority -310; policy accept;
    ip daddr 10.66.0.0/16 tcp dport 22 return
    ip6 daddr fd66::/48 tcp dport 22 return
    ip saddr 10.66.0.0/16 tcp sport 22 ct state established return
    ip6 saddr fd66::/48 tcp sport 22 ct state established return
    counter drop
  }
  chain output {
    type filter hook output priority -10; policy accept;
    oifname "lo" return
    meta mark 0x4d72 return
    ip daddr 10.66.0.0/16 tcp dport 22 return
    ip6 daddr fd66::/48 tcp dport 22 return
    ip daddr 10.66.0.0/16 tcp sport 22 return
    ip6 daddr fd66::/48 tcp sport 22 return
    udp dport 53 drop
    tcp dport 53 drop
    meta mark & 0x00ff0000 != 0 drop
    meta mark & 0x0000ffff >= 0x100 meta mark & 0x0000ffff <= 0x1fff drop
    ip daddr 10.66.0.0/16 drop
    ip6 daddr fd66::/48 drop
  }
}
SH_GUARD
}
share_guard_off() { nft delete table inet meridian_switch; }
share_atomic_copy() {
  local src="$1" dst="$2"
  mkdir -p "${dst%/*}" || return 4
  cp "$src" "$dst.next" && mv -f "$dst.next" "$dst" || return 4
}
share_error() {
  local code="$1" state="$2" tmp="$UP_STATE.error"
  echo "meridian-switch: $code; automatic switching blocked until a complete install" >&2
  # Keep the old carrying decision/times as history; down means not confirmed.
  if [ -f "$UP_STATE" ]; then
    sed -e "s/^state .*/state $state/" -e "s/^alert .*/alert $code/" "$UP_STATE" > "$tmp" && mv -f "$tmp" "$UP_STATE" || return 4
  fi
}
share_restore() {
  local old="$1" args=()
  [ -f "$old/version" ] && [ "$(cat "$old/version")" = "$SH_VERSION" ] || return 4
  read -r -a args < "$old/args" || return 4
  share_apply_raw "${args[@]}" || return 4
  share_atomic_copy "$old/status" "$UP_STATE" || return 4
  if [ -f "$old/state" ]; then
    share_atomic_copy "$old/state" "${PQ_STATE:-${SH_APPLIED%/*}/state.json}" || return 4
  else
    rm -f "${PQ_STATE:-${SH_APPLIED%/*}/state.json}" || return 4
  fi
}
share_publish() {
  # The caller prepared status/state in a private generation directory.
  share_atomic_copy "$SH_CANDIDATE/status" "$UP_STATE" || return 4
  if [ -f "$SH_CANDIDATE/state" ]; then
    share_atomic_copy "$SH_CANDIDATE/state" "${PQ_STATE:-${SH_APPLIED%/*}/state.json}" || return 4
  else
    rm -f "${PQ_STATE:-${SH_APPLIED%/*}/state.json}" || return 4
  fi
}
share_apply() {
  # Direct callers use the same serialization as controller/install callers.
  if [ "${SH_LOCKED:-0}" != 1 ]; then
    ( share_lock || exit $?; SH_LOCKED=1; share_apply "$@" )
    return $?
  fi
  local old="" rc=0 recovered=0
  [ -n "${SH_CANDIDATE:-}" ] && [ -f "$SH_CANDIDATE/status" ] || return 4
  # Validate before installing a fence or touching files/kernel state.
  SH_VALIDATE=1 share_apply_raw "$@" || return $?
  if [ "${SH_INSTALL:-0}" != 1 ] && [ -e "$SH_TXN/pending" ] && [ ! -e "$SH_TXN/blocked" ]; then share_finish_pending || true; fi
  if [ "${SH_INSTALL:-0}" != 1 ] && { [ -e "$SH_TXN/blocked" ] || [ -e "$SH_TXN/pending" ]; }; then
    share_guard_on || return 4
    rm -f "$SH_APPLIED"
    touch "$SH_TXN/blocked"
    share_error recovery_blocked down
    return 4
  fi
  if [ "${SH_INSTALL:-0}" != 1 ] && [ -f "$SH_TXN/current" ]; then
    read -r old < "$SH_TXN/current" || return 4
    case "$old" in *[!A-Za-z0-9-]*|'') return 4 ;; snapshot-*) ;; *) return 4 ;; esac
    old="$SH_TXN/$old"
    [ "$(cat "$old/version" 2>/dev/null)" = "$SH_VERSION" ] || { touch "$SH_TXN/blocked"; share_error config_changed down; return 4; }
  fi
  if [ -f "$UP_STATE" ]; then cp "$UP_STATE" "$SH_CANDIDATE/history" || return 4; fi
  # Persist intent before the first mutation. SIGKILL leaves pending behind;
  # restart fences and blocks instead of taking the partial state as success.
  printf '%s %s\n' "$SH_VERSION" "${SH_CANDIDATE##*/}" > "$SH_TXN/pending" || return 4
  rm -f "$SH_APPLIED" || return 4
  share_guard_on || { touch "$SH_TXN/blocked"; share_error guard_failed down; return 4; }
  share_apply_raw "$@" || rc=$?
  # Arguments were validated: a refusal now is a failed mutation.
  [ "$rc" -ne 1 ] || rc=3
  if [ "$rc" -eq 0 ]; then
    share_publish || rc=4
  fi
  if [ "$rc" -eq 0 ]; then
    printf '%s\n' "$SH_VERSION" > "$SH_CANDIDATE/version" && printf '%s\n' "$*" > "$SH_CANDIDATE/args" || rc=4
  fi
  if [ "$rc" -eq 0 ]; then share_guard_off || rc=4; fi
  if [ "$rc" -eq 0 ]; then
    printf '%s\n' "${SH_CANDIDATE##*/}" > "$SH_TXN/current.next" && mv -f "$SH_TXN/current.next" "$SH_TXN/current" || rc=4
  fi
  if [ "$rc" -eq 0 ]; then
    printf '%s\n' "$*" > "$SH_APPLIED.next" && mv -f "$SH_APPLIED.next" "$SH_APPLIED" && rm -f "$SH_TXN/pending" "$SH_TXN/blocked" "$SH_TXN/failed" || rc=4
  fi
  if [ "$rc" -eq 0 ]; then
    [ -z "$old" ] || [ "$old" = "$SH_CANDIDATE" ] || rm -rf "$old"
    return 0
  fi
  # One compensation per attempt. A failed compensation keeps the independent
  # fence and latches blocked. Never restore a candidate or the partial site.
  touch "$SH_TXN/blocked"
  rm -f "$SH_APPLIED"
  if share_guard_on && [ -n "$old" ] && share_restore "$old" && share_guard_off; then recovered=1; fi
  if [ "$recovered" = 1 ]; then
    # Back on the last successful snapshot, unfenced. Automatic switching is
    # held: retry after a bounded backoff (30 s, then 60 s), at most
    # SH_RETRIES failed attempts, then only a complete install clears it.
    local count=0 next
    rm -f "$SH_TXN/blocked"
    [ ! -f "$SH_TXN/failed" ] || read -r count next < "$SH_TXN/failed" || count=0
    case "$count" in ''|*[!0-9]*) count=0 ;; esac
    count=$((count + 1))
    next=$(( $(date +%s) + 30 * (1 << (count - 1)) ))
    printf '%s %s\n' "$count" "$next" > "$SH_TXN/failed" || touch "$SH_TXN/blocked"
    printf '%s\n' "${old##*/}" > "$SH_TXN/current.next" && mv -f "$SH_TXN/current.next" "$SH_TXN/current" || touch "$SH_TXN/blocked"
    rm -f "$SH_TXN/pending"
    share_drop_candidate
    [ -e "$SH_TXN/blocked" ] || printf '%s\n' "$(cat "$old/args")" > "$SH_APPLIED"
    share_error apply_failed degraded
  else
    share_guard_on || true
    # Restore the historical record even when route compensation failed.
    if [ -n "$old" ]; then share_atomic_copy "$old/status" "$UP_STATE" || true
    elif [ -f "$SH_CANDIDATE/history" ]; then share_atomic_copy "$SH_CANDIDATE/history" "$UP_STATE" || true; fi
    share_error recovery_blocked down
  fi
  return "$rc"
}
# share_finish_pending: a pending marker left by a killed pass. The commit
# point is "current" naming the pending target: it is written only after the
# kernel switch, publication and fence removal all succeeded. When it does,
# and the snapshot is complete for this compiled version, the kernel state is
# verified by replaying the snapshot under the fence (the switch's own
# commands; any failure keeps the fence and blocks). Then the commit finishes
# without a full install. Anything unprovable stays pending: fenced, blocked.
share_finish_pending() {
  local pv pt cur snap args=()
  read -r pv pt < "$SH_TXN/pending" || return 4
  [ "$pv" = "$SH_VERSION" ] || return 4
  case "$pt" in *[!A-Za-z0-9-]*|'') return 4 ;; snapshot-*) ;; *) return 4 ;; esac
  [ -f "$SH_TXN/current" ] && read -r cur < "$SH_TXN/current" || return 4
  [ "$cur" = "$pt" ] || return 4
  snap="$SH_TXN/$pt"
  [ -f "$snap/status" ] && [ -f "$snap/args" ] && [ "$(cat "$snap/version" 2>/dev/null)" = "$SH_VERSION" ] || return 4
  read -r -a args < "$snap/args" || return 4
  [ "${#args[@]}" -gt 0 ] || return 4
  SH_VALIDATE=1 share_apply_raw "${args[@]}" || return 4
  share_guard_on || return 4
  if ! share_apply_raw "${args[@]}"; then touch "$SH_TXN/blocked"; return 4; fi
  share_guard_off || { touch "$SH_TXN/blocked"; return 4; }
  printf '%s\n' "${args[*]}" > "$SH_APPLIED.next" && mv -f "$SH_APPLIED.next" "$SH_APPLIED" || return 4
  rm -f "$SH_TXN/pending"
}
SH_RETRIES=3
# share_held: 0 while a compensated failure holds automatic switching (backoff
# not over, or the retry budget spent). The last successful path stays applied.
share_held() {
  local count next
  [ -f "$SH_TXN/failed" ] || return 1
  read -r count next < "$SH_TXN/failed" || return 0
  case "$count$next" in ''|*[!0-9]*) return 0 ;; esac
  [ "$count" -ge "$SH_RETRIES" ] || [ "$(date +%s)" -lt "$next" ]
}
# share_drop_candidate: remove an unpublished candidate (never the current).
share_drop_candidate() {
  local cur=""
  [ -n "${SH_CANDIDATE:-}" ] && [ -d "$SH_CANDIDATE" ] || return 0
  [ ! -f "$SH_TXN/current" ] || read -r cur < "$SH_TXN/current" || return 0
  [ "${SH_CANDIDATE##*/}" = "$cur" ] || rm -rf "$SH_CANDIDATE"
}
share_candidate() {
  SH_CANDIDATE=$(mktemp -d "$SH_TXN/snapshot-XXXXXXXX") || return 4
}
# share_once KEY UP DES ARGS…: the same applied decision is not re-applied
# (no fence, no kernel change); its fresh status is published onto the current
# snapshot. Every 12th call re-applies in full (a protected transaction) so a
# map or route changed behind the loop's back heals. A held or blocked switch
# never takes the shortcut.
SH_ONCE=0
share_once() {
  local key="$1" cur
  shift
  SH_ONCE=$((SH_ONCE + 1))
  if [ "${SH_LOCKED:-0}" = 1 ] && [ $((SH_ONCE % 12)) -ne 0 ] && [ -f "$SH_APPLIED" ] && [ "$key" = "$(cat "$SH_APPLIED")" ] &&
    [ ! -e "$SH_TXN/blocked" ] && [ ! -e "$SH_TXN/pending" ] && [ ! -e "$SH_TXN/failed" ] && [ -f "$SH_TXN/current" ]; then
    read -r cur < "$SH_TXN/current" || return 4
    [ -n "${SH_CANDIDATE:-}" ] && [ -f "$SH_CANDIDATE/status" ] || return 4
    share_publish || return 4
    share_atomic_copy "$SH_CANDIDATE/status" "$SH_TXN/$cur/status" || return 4
    if [ -f "$SH_CANDIDATE/state" ]; then share_atomic_copy "$SH_CANDIDATE/state" "$SH_TXN/$cur/state" || return 4; fi
    rm -rf "$SH_CANDIDATE"
    return 0
  fi
  share_apply "$@"
}
`
