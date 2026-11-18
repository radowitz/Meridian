#!/bin/bash
# Verify the name-sniffing forwarder's systemd layout on the real Debian
# host, before the forwarder is enabled through the panel. It starts a
# throw-away copy of the forwarder under temporary unit names, a temporary
# account (uid/gid from 65520-65529) and a temporary loopback port, with
# unit files and an account script rendered by the same code the install
# uses ("meridian sniff-verify-render": compile.RenderSniffUnit,
# RenderSniffAccountUnit, RenderSniffAccountScript), and a synthetic rule
# pair with no rule.
#
#   sudo bash deploy/verify-sniff-systemd.sh                 # sysctl left as it is
#   sudo bash deploy/verify-sniff-systemd.sh --flip-sysctl   # also prove the 1/0 cycle
#   MERIDIAN_BIN=/usr/local/bin/meridian (default) selects the binary to test.
#
# It does not touch the managed nft tables, Meridian's units, routes or any
# traffic, and opens no outbound connection: the forwarder listens on
# 127.0.0.1 only, nothing is redirected to it and it is never connected to;
# the status socket is a local Unix socket. net.ipv4.tcp_fwmark_accept is
# written with its current value unless --flip-sysctl is given AND
# meridian-sniff.service is not running AND the value is 0; then the
# temporary unit turns it on and off again and the script restores it on
# any exit. Everything it creates is removed on success and on failure.
# Output: PASS/FAIL/SKIP per check; exit 0 only when no check failed.
set -uo pipefail

bin=${MERIDIAN_BIN:-/usr/local/bin/meridian}
neigh_if=${MERIDIAN_VERIFY_NEIGH_IF:-lo}
flip=0
[[ "${1:-}" == "--flip-sysctl" ]] && flip=1
fail=0
pass() { echo "PASS $1: $2"; }
bad() { echo "FAIL $1: $2"; fail=1; }
skip() { echo "SKIP $1: $2"; }

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
for c in systemctl systemd-run systemd-analyze journalctl getent useradd groupadd userdel groupdel ss stat findmnt sysctl; do
  command -v "$c" >/dev/null 2>&1 || { echo "missing command: $c" >&2; exit 2; }
done
# An older binary has no hidden subcommand and would start the panel.
[[ -x "$bin" ]] && grep -q sniff-verify-render "$bin" || { echo "$bin is not a meridian binary with sniff-verify-render" >&2; exit 2; }

# --- temporary names --------------------------------------------------------
tag=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
unit=meridian-vfy-sniff-$tag.service
acct_unit=meridian-vfy-sniff-$tag-account.service
user=mvfysn$tag
rtdir=meridian-vfy-sniff-$tag
unitdir=/run/systemd/system          # unit files only; nothing is executed from /run
free_id() { # free_id EXCLUDE: an id in 65520-65529 used by no account and no group
  local i
  for i in 65520 65521 65522 65523 65524 65525 65526 65527 65528 65529; do
    [[ "$i" == "${1:-}" ]] && continue
    getent passwd "$i" >/dev/null || getent group "$i" >/dev/null || { echo "$i"; return 0; }
  done
  return 1
}
uid=$(free_id) || { echo "no free id in 65520-65529" >&2; exit 2; }
other_id=$(free_id "$uid") || { echo "no second free id in 65520-65529" >&2; exit 2; }
getent passwd "$user" >/dev/null || getent group "$user" >/dev/null && { echo "name $user taken, run again" >&2; exit 2; }
port=
for _ in $(seq 1 50); do
  p=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 10000))
  [[ -z "$(ss -Htln "sport = :$p")" ]] && { port=$p; break; }
done
[[ -n "$port" ]] || { echo "no free port" >&2; exit 2; }
# The account script must live where it can be executed: not /run (noexec),
# not /tmp (private in units). /var/lib must not be noexec.
if findmnt -no OPTIONS --target /var/lib | tr ',' '\n' | grep -qx noexec; then
  echo "/var/lib is mounted noexec; the account script cannot run from there" >&2; exit 2
fi
workdir=$(mktemp -d /var/lib/meridian-vfy-sniff.XXXXXX) || exit 2
chmod 0755 "$workdir"

orig_fwmark=$(sysctl -n net.ipv4.tcp_fwmark_accept)
real_running=0
systemctl is-active --quiet meridian-sniff.service && real_running=1
fw_on=$orig_fwmark fw_off=$orig_fwmark flipped=0
if [[ $flip == 1 && $real_running == 0 && "$orig_fwmark" == 0 ]]; then
  fw_on=1 fw_off=0 flipped=1
fi
created_users=()

cleanup() {
  systemctl stop "$unit" "$acct_unit" >/dev/null 2>&1
  systemctl reset-failed "$unit" "$acct_unit" >/dev/null 2>&1
  rm -f "$unitdir/$unit" "$unitdir/$acct_unit"
  systemctl daemon-reload >/dev/null 2>&1
  # Only accounts this script made: the temporary name with the temporary
  # id, and the conflict accounts it created.
  [[ "$(getent passwd "$user" | cut -d: -f3)" == "$uid" ]] && userdel "$user" >/dev/null 2>&1
  [[ "$(getent group "$uid" | cut -d: -f1)" == "$user" ]] && groupdel "$user" >/dev/null 2>&1
  local u
  for u in "${created_users[@]}"; do
    userdel "$u" >/dev/null 2>&1
    getent group "$u" >/dev/null && groupdel "$u" >/dev/null 2>&1
  done
  created_users=()
  [[ -n "$workdir" && -d "$workdir" ]] && rm -rf "$workdir"
  [[ -d "/run/$rtdir" ]] && rm -rf "/run/${rtdir:?}"
  [[ -d "/var/lib/$rtdir" ]] && rm -rf "/var/lib/${rtdir:?}"
  if [[ $flipped == 1 && "$(sysctl -n net.ipv4.tcp_fwmark_accept)" != "$orig_fwmark" ]]; then
    sysctl -q -w net.ipv4.tcp_fwmark_accept="$orig_fwmark"
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

echo "info unit=$unit account-unit=$acct_unit user=$user uid=$uid port=127.0.0.1:$port workdir=$workdir"
echo "info tcp_fwmark_accept=$orig_fwmark meridian-sniff.service running=$real_running written at start/stop: $fw_on/$fw_off"

# --- 1. render ---------------------------------------------------------------
sock=$("$bin" sniff-verify-render --unit-dir "$unitdir" --fixture-dir "$workdir" \
  --unit "$unit" --account-unit "$acct_unit" --user "$user" --uid "$uid" \
  --script "$workdir/account.sh" --runtime-dir "$rtdir" --binary "$bin" \
  --listen "127.0.0.1:$port" --neigh-if "$neigh_if" \
  --fwmark-accept-on "$fw_on" --fwmark-accept-off "$fw_off")
if [[ $? -ne 0 || "$sock" != "/run/$rtdir/status.sock" ]]; then
  bad render "meridian sniff-verify-render failed"; exit 1
fi
pass render "units, account script and rule pair rendered by the install's code"
for u in "$unit" "$acct_unit"; do
  if out=$(systemd-analyze verify "$unitdir/$u" 2>&1); then pass "analyze $u" "systemd-analyze verify"; else bad "analyze $u" "$(echo "$out" | head -3)"; fi
done
systemctl daemon-reload

# --- 2. start: the account exists before User= is resolved --------------------
if out=$(systemctl start "$unit" 2>&1); then
  pass start "$unit started (no 217/USER)"
else
  bad start "$out; $(journalctl -u "$acct_unit" -u "$unit" -n 20 --no-pager -o cat 2>&1 | tr '\n' ' ')"
  exit 1
fi
[[ "$(getent passwd "$user" | cut -d: -f3)" == "$uid" && "$(getent group "$user" | cut -d: -f3)" == "$uid" ]] \
  && pass account "account and group $user with uid/gid $uid created by $acct_unit" || bad account "account $user/$uid missing"
systemctl is-active --quiet "$acct_unit" && pass account_unit "$acct_unit active" || bad account_unit "$acct_unit $(systemctl is-active "$acct_unit")"
ready=0
for _ in $(seq 1 50); do
  [[ -S "$sock" ]] && journalctl -u "$unit" --no-pager -o cat | grep -q meridian-sniff-ready && { ready=1; break; }
  systemctl is-active --quiet "$unit" || break
  sleep 0.2
done
[[ $ready == 1 ]] && pass ready "forwarder listening (127.0.0.1:$port) with its rule pair loaded" \
  || bad ready "forwarder not ready: $(systemctl is-active "$unit"); $(journalctl -u "$unit" -n 10 --no-pager -o cat | tr '\n' ' ')"
[[ -n "$(ss -Htln "sport = :$port")" ]] && pass listen "listener on 127.0.0.1:$port" || bad listen "no listener on 127.0.0.1:$port"

# --- 3. the process: account, capabilities, nothing more ----------------------
pid=$(systemctl show -p MainPID --value "$unit")
if [[ -n "$pid" && "$pid" != 0 && -r "/proc/$pid/status" ]]; then
  st=$(cat "/proc/$pid/status")
  f() { awk -v k="$1:" '$1 == k { $1 = ""; sub(/^ /, ""); print }' <<<"$st"; }
  [[ "$(f Uid)" == "$uid $uid $uid $uid" ]] && pass uid "runs as uid $uid (real, effective, saved, fs)" || bad uid "Uid: $(f Uid)"
  [[ "$(f Gid)" == "$uid $uid $uid $uid" ]] && pass gid "runs as gid $uid" || bad gid "Gid: $(f Gid)"
  # initgroups() lists the account's own group; nothing else may be there.
  g=$(f Groups); g=${g% }
  [[ -z "$g" || "$g" == "$uid" ]] && pass groups "no other group (Groups: ${g:-none})" || bad groups "Groups: $g"
  want=0000000000001000 # CAP_NET_ADMIN only
  for k in CapEff CapPrm CapAmb CapBnd; do
    [[ "$(f "$k")" == "$want" ]] && pass "$k" "$k=$want (CAP_NET_ADMIN only)" || bad "$k" "$k=$(f "$k"), want $want"
  done
  [[ "$(f NoNewPrivs)" == 1 ]] && pass no_new_privs "NoNewPrivs=1" || bad no_new_privs "NoNewPrivs=$(f NoNewPrivs)"
else
  bad process "no main process ($pid)"
fi

# --- 4. the files the real forwarder reads, as an account in the same sandbox -
# (another uid than 65530, in the same "other" permission class). t: a
# directory it only traverses; c: a directory whose *.txt it reads (rule
# sets, geosite categories, keywords, China lists); f: a file it reads.
read_paths=(t:/etc/meridian t:/etc/meridian/rules f:/etc/meridian/rules/decide.json t:/etc/meridian/sniff f:/etc/meridian/sniff/targets.json
  t:/var/lib/meridian c:/var/lib/meridian/geosite c:/var/lib/meridian/geosite/rulesets c:/var/lib/meridian/keywords c:/var/lib/meridian/lists
  "f:$bin")
out=$(systemd-run --wait --pipe --quiet --collect -p User="$user" -p Group="$user" -p NoNewPrivileges=yes \
  -p CapabilityBoundingSet=CAP_NET_ADMIN -p AmbientCapabilities=CAP_NET_ADMIN -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
  /bin/sh -c 'for a; do
      k=${a%%:*} p=${a#*:}
      if [ ! -e "$p" ]; then echo "absent $p"; continue; fi
      case $k in
        t) if [ -x "$p" ]; then echo "ok $p (traverse)"; else echo "unreadable $p (no traverse)"; fi ;;
        f) if [ -r "$p" ]; then echo "ok $p"; else echo "unreadable $p"; fi ;;
        c) if [ -x "$p" ] && [ -r "$p" ]; then
             bad=; n=0
             for g in "$p"/*.txt; do [ -f "$g" ] || continue; n=$((n+1)); [ -r "$g" ] || bad="$bad $g"; done
             if [ -n "$bad" ]; then echo "unreadable$bad"; else echo "ok $p ($n files)"; fi
           else echo "unreadable $p (directory)"; fi ;;
      esac
    done' sh "${read_paths[@]}" 2>&1)
while IFS= read -r l; do
  case "$l" in
    ok\ *) pass readable "${l#ok }" ;;
    absent\ *) skip readable "${l#absent } does not exist on this host" ;;
    *) bad readable "$l" ;;
  esac
done <<<"$out"

# --- 5. status socket: modes, the agent's sandbox reads it, others are refused -
[[ "$(stat -c '%a %u' "/run/$rtdir" 2>/dev/null)" == "755 $uid" ]] && pass runtime_dir "/run/$rtdir 0755 uid $uid" \
  || bad runtime_dir "/run/$rtdir: $(stat -c '%a %u' "/run/$rtdir" 2>&1)"
[[ "$(stat -c '%a %u' "$sock" 2>/dev/null)" == "666 $uid" ]] && pass socket_mode "$sock 0666 uid $uid" || bad socket_mode "$sock: $(stat -c '%a %u' "$sock" 2>&1)"
# The connection journal's StateDirectory: 0700 owned by the account (the
# rendered unit names it after the runtime directory here). Another user
# cannot list it; the files appear with the first connection.
[[ "$(stat -c '%a %u' "/var/lib/$rtdir" 2>/dev/null)" == "700 $uid" ]] && pass journal_dir "/var/lib/$rtdir 0700 uid $uid" \
  || bad journal_dir "/var/lib/$rtdir: $(stat -c '%a %u' "/var/lib/$rtdir" 2>&1)"
if systemd-run --wait --pipe --quiet --collect -p User=nobody -p NoNewPrivileges=yes /bin/ls "/var/lib/$rtdir" >/dev/null 2>&1; then
  bad journal_other "user nobody can list /var/lib/$rtdir"
else
  pass journal_other "user nobody cannot list /var/lib/$rtdir"
fi
# The host agent's sandbox: the installed meridian-host.service's values
# when it is loaded, else deploy/debian/meridian-host.service's.
agent_props=(User=root Group= SupplementaryGroups= CapabilityBoundingSet=CAP_NET_ADMIN AmbientCapabilities= NoNewPrivileges=yes
  ProtectSystem=strict ProtectHome=yes PrivateTmp=yes PrivateDevices=yes UMask=0077
  "ReadWritePaths=-/var/lib/meridian/geosite -/var/lib/meridian/keywords -/var/lib/meridian/lists -/var/lib/meridian-dnslog"
  "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6")
if [[ "$(systemctl show -p LoadState --value meridian-host.service 2>/dev/null)" == loaded ]]; then
  for i in "${!agent_props[@]}"; do
    k=${agent_props[$i]%%=*}
    v=$(systemctl show -p "$k" --value meridian-host.service 2>/dev/null) && agent_props[$i]="$k=$v"
  done
  echo "info reader sandbox taken from the installed meridian-host.service"
else
  echo "info meridian-host.service not loaded; reader sandbox from deploy/debian/meridian-host.service"
fi
run_as_agent() { systemd-run --wait --pipe --quiet --collect "${agent_props[@]/#/-p}" "$@"; }
caps=$(run_as_agent /bin/sh -c 'grep -E "^(Uid|CapEff|CapBnd):" /proc/self/status' 2>&1)
if grep -qP '^Uid:\s+0\s' <<<"$caps" && grep -qP '^CapEff:\s+0000000000001000$' <<<"$caps"; then
  pass agent_sandbox "reader runs as uid 0 with CAP_NET_ADMIN only (no CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH)"
else
  bad agent_sandbox "reader sandbox is not the agent's: $(tr '\n' ' ' <<<"$caps")"
fi
if health=$(run_as_agent "$bin" sniff-verify-read --socket "$sock" 2>&1) && grep -q '"ready":true' <<<"$health"; then
  pass agent_read "the host agent's reader (hostexec.ReadSniffSocket) gets /v1/health and /v1/recent in the agent's sandbox"
else
  bad agent_read "agent-sandbox read failed: $health"
fi
# The health answer carries the rule generation twice: the forwarder's own
# and the one its last self-check ran against (which lags right after a
# reload). The larger one is the forwarder's.
gen_of() { grep -o '"generation":[0-9]*' <<<"$1" | cut -d: -f2 | sort -n | tail -1; }
gen1=$(gen_of "$health")
if out=$(systemd-run --wait --pipe --quiet --collect -p User=nobody -p NoNewPrivileges=yes "$bin" sniff-verify-read --socket "$sock" 2>&1); then
  bad other_user "user nobody was answered: $out"
elif grep -qi 'permission denied' <<<"$out"; then
  bad other_user "user nobody could not even connect (modes differ from the design): $out"
else
  pass other_user "user nobody connects and is closed unanswered (peer check): $(head -c 160 <<<"$out")"
fi

# --- 6. reload (SIGHUP) keeps process and listener ---------------------------
if systemctl reload "$unit"; then
  sleep 1
  pid2=$(systemctl show -p MainPID --value "$unit")
  health2=$(run_as_agent "$bin" sniff-verify-read --socket "$sock" 2>&1)
  gen2=$(gen_of "$health2")
  if [[ "$pid2" == "$pid" && -n "$(ss -Htln "sport = :$port")" && -n "$gen1" && -n "$gen2" && "$gen2" -gt "$gen1" ]]; then
    pass reload "SIGHUP: same process ($pid), listener kept, rule generation $gen1 -> $gen2"
  else
    bad reload "pid $pid -> $pid2, generation $gen1 -> $gen2, listener: $(ss -Htln "sport = :$port" | wc -l)"
  fi
else
  bad reload "systemctl reload $unit failed"
fi

# --- 7. sysctl while running -------------------------------------------------
cur=$(sysctl -n net.ipv4.tcp_fwmark_accept)
if [[ $flipped == 1 ]]; then
  [[ "$cur" == 1 ]] && pass fwmark_on "the unit's +sysctl (root) set tcp_fwmark_accept=1" || bad fwmark_on "tcp_fwmark_accept=$cur while running"
else
  [[ "$cur" == "$orig_fwmark" ]] && pass fwmark_root "the unit's +sysctl lines ran as root (the start needs them) and left tcp_fwmark_accept=$cur" \
    || bad fwmark_root "tcp_fwmark_accept changed to $cur"
  skip fwmark_cycle "not flipped ($( [[ $real_running == 1 ]] && echo "meridian-sniff.service is running" || echo "run with --flip-sysctl on a host where it is 0"))"
fi

# --- 8. stop: account unit stops when unneeded, account and directory removed --
systemctl stop "$unit"
gone=0
# Wait for the end state, not for "no longer active": while its ExecStop
# (the account removal) runs the unit is "deactivating", and checking the
# account then is too early (seen on a real host: the removal took 0.14 s).
for _ in $(seq 1 50); do
  case "$(systemctl show -p ActiveState --value "$acct_unit")" in
    inactive|failed) gone=1; break ;;
  esac
  sleep 0.2
done
[[ $gone == 1 ]] && pass account_unit_stop "$acct_unit stopped by itself after $unit stopped (StopWhenUnneeded)" \
  || bad account_unit_stop "$acct_unit still $(systemctl is-active "$acct_unit")"
[[ -z "$(getent passwd "$user")" && -z "$(getent group "$user")" ]] && pass account_removed "account and group $user removed" \
  || bad account_removed "account or group $user still there"
[[ ! -e "/run/$rtdir" ]] && pass runtime_dir_removed "/run/$rtdir removed" || bad runtime_dir_removed "/run/$rtdir still there"
cur=$(sysctl -n net.ipv4.tcp_fwmark_accept)
if [[ $flipped == 1 ]]; then
  [[ "$cur" == 0 ]] && pass fwmark_off "ExecStopPost=+sysctl set tcp_fwmark_accept back to 0" || bad fwmark_off "tcp_fwmark_accept=$cur after stop"
else
  [[ "$cur" == "$orig_fwmark" ]] && pass fwmark_unchanged "tcp_fwmark_accept=$cur as before" || bad fwmark_unchanged "tcp_fwmark_accept=$cur, was $orig_fwmark"
fi

# --- 9. a taken uid or name: the start fails with the conflict message --------
conflict() { # conflict LABEL EXPECT: start must fail, the account unit must log EXPECT
  local since
  since=$(date '+%Y-%m-%d %H:%M:%S')
  sleep 1
  if systemctl start "$unit" >/dev/null 2>&1; then
    bad "$1" "$unit started although $1"
  elif journalctl -u "$acct_unit" --since "$since" --no-pager -o cat | grep -q "meridian-sniff-user-conflict: $2"; then
    if systemctl is-active --quiet "$unit" || [[ -n "$(ss -Htln "sport = :$port")" ]]; then
      bad "$1" "start failed but something runs or listens"
    else
      pass "$1" "start refused: $(journalctl -u "$acct_unit" --since "$since" --no-pager -o cat | grep -m1 meridian-sniff-user-conflict)"
    fi
  else
    bad "$1" "start failed without the conflict message: $(journalctl -u "$acct_unit" -u "$unit" --since "$since" -n 10 --no-pager -o cat | tr '\n' ' ')"
  fi
  systemctl stop "$unit" "$acct_unit" >/dev/null 2>&1
  systemctl reset-failed "$unit" "$acct_unit" >/dev/null 2>&1
}
cu=mvfysc$tag
if useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --uid "$uid" --no-user-group --gid nogroup "$cu"; then
  created_users+=("$cu")
  conflict uid_taken "uid $uid belongs to $cu"
  userdel "$cu" && created_users=()
else
  bad uid_taken "could not create the conflicting account"
fi
if useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --uid "$other_id" --no-user-group --gid nogroup "$user"; then
  created_users+=("$user")
  conflict name_taken "account $user exists with uid $other_id"
  userdel "$user" && created_users=()
else
  bad name_taken "could not create the conflicting account"
fi

# --- 10. clean up and check ---------------------------------------------------
cleanup
trap - EXIT
left=()
[[ -e "$unitdir/$unit" || -e "$unitdir/$acct_unit" ]] && left+=("unit files")
[[ "$(systemctl show -p LoadState --value "$unit")" == loaded || "$(systemctl show -p LoadState --value "$acct_unit")" == loaded ]] && left+=("loaded units")
getent passwd "$user" >/dev/null && left+=("account $user")
getent passwd "$uid" >/dev/null && left+=("uid $uid")
getent group "$uid" >/dev/null && left+=("gid $uid")
[[ -e "$workdir" ]] && left+=("$workdir")
[[ -e "/run/$rtdir" ]] && left+=("/run/$rtdir")
[[ "$(sysctl -n net.ipv4.tcp_fwmark_accept)" == "$orig_fwmark" ]] || left+=("tcp_fwmark_accept")
if [[ ${#left[@]} -eq 0 ]]; then pass cleanup "nothing of the run is left"; else bad cleanup "left: ${left[*]}"; fi

exit "$fail"
