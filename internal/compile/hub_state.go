package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Hub group state: what the hub's failover loop records about every
// switchable region group, and what the panel reads back with the fixed
// command sshexec.GroupStateCommand (see docs/architecture.md「地区组」).
//
// Files under /run/meridian (all written whole to a temporary file and
// renamed, so a reader never sees half a file):
//
//	group-plan            "plan <GroupPlanID> <epoch>", written by reset_groups
//	                      when the failover service starts (after an install
//	                      it is restarted), after the compiled targets are in
//	                      place.
//	group/<id>/report     written by group_step at the end of every pass of
//	                      the loop for that group:
//
//	  meridian-group-report 1
//	  group <id>
//	  plan <GroupPlanID of the running script>
//	  beat <epoch of this pass>                       (heartbeat)
//	  hop <member ID | mmesh | blackhole | none | other | split | unreadable>
//	  active <member ID | mmesh>                      (the switcher's choice)
//	  reason <preferred|chosen|constraint|failover|fallback|held|mesh>
//	  alert <0|1>
//	  switched <epoch of the last successful switch, 0 = none since start>
//	  result <ok | failed | diverged>
//	  want <member ID | mmesh>                        (only when result failed)
//	  lastfail <member ID | mmesh> <epoch>            (latest failed switch, if any)
//	  end
//
// hop is read from the kernel each pass (ip -4/-6 route show table <n>),
// not from what the script intended: the default route that is not the
// metric-32767 floor, mapped back to the member whose hub interface it
// uses, mmesh for the Mesh veth, blackhole for a blackhole default or only
// the floor, none when the table has no default at all, other for an
// interface that is no member, split when IPv4 and IPv6 disagree. result
// is failed when this pass decided a switch and group_hop failed (the
// previous hop is still what hop shows), diverged when the table does not
// hold what the switcher believes is active.

// HubLoopInterval is the sleep between two passes of the hub's failover
// loop (the "sleep 5" in failoverLoopHub; a test keeps them equal).
const HubLoopInterval = 5 * time.Second

// hubPingTimeout is ping -W in the loop: the most one liveness check can
// add to a pass.
const hubPingTimeout = 2 * time.Second

// HubStaleAfter is how old a group report's heartbeat may be, measured on
// the hub's own clock, before the panel calls it stale: three worst-case
// passes of the loop (the sleep, three west-tunnel pings, one ping per
// member of every switchable group, ten seconds for the Mesh seal check),
// and never less than 60 seconds.
func HubStaleAfter(groups []GroupPlan) time.Duration {
	pings := 3
	for _, g := range groups {
		if g.Dynamic {
			pings += len(g.Try)
		}
	}
	pass := HubLoopInterval + time.Duration(pings)*hubPingTimeout + 10*time.Second
	if d := 3 * pass; d > 60*time.Second {
		return d
	}
	return 60 * time.Second
}

// GroupPlanID identifies a hub group plan: the first 24 hex digits of the
// SHA-256 of the hub's compiled group-switch section (tables, member
// interfaces and peers, order, policy flags and the shell itself). It holds
// no secret. The panel computes it from the stored topology and compares it
// with what the running hub script reports; a difference means the hub has
// not been provisioned with the current topology.
func GroupPlanID(groups []GroupPlan) string {
	sum := sha256.Sum256([]byte(renderGroupChecks(groups)))
	return hex.EncodeToString(sum[:])[:24]
}

// groupReportShell records the hub's group state for the panel. It only
// reads the kernel and writes under /run/meridian; it never changes a
// route, so group_step switches exactly as before.
const groupReportShell = `
group_table_default() {
  local fam="$1" table="$2" out line floor=0 i
  local -a w
  out=$(ip "$fam" route show table "$table" 2>/dev/null) || { echo unreadable; return 0; }
  while IFS= read -r line; do
    read -r -a w <<< "$line"
    [ "${#w[@]}" -gt 0 ] || continue
    case " $line " in
      *" metric 32767 "*)
        [ "${w[0]}" = blackhole ] && floor=1
        continue
        ;;
    esac
    if [ "${w[0]}" = default ]; then
      for ((i=1; i<${#w[@]}-1; i++)); do
        if [ "${w[$i]}" = dev ]; then echo "dev:${w[$((i+1))]}"; return 0; fi
      done
      echo other; return 0
    fi
    if [ "${w[1]:-}" = default ]; then
      case "${w[0]}" in
        blackhole) echo blackhole ;;
        *) echo other ;;
      esac
      return 0
    fi
  done <<< "$out"
  if [ "$floor" = 1 ]; then echo blackhole; else echo none; fi
}
group_table_hop() {
  local a b
  a=$(group_table_default -4 "$1")
  b=$(group_table_default -6 "$1")
  if [ "$a" = "$b" ]; then echo "$a"; else echo split; fi
}
group_record() {
  local dir="$1" gid="$2" table="$3" now="$4" active="$5" reason="$6" hfail="$7" pairs="$8"
  local tbl hop p result=ok expect alert switched lastfail tmp
  tbl=$(group_table_hop "$table")
  case "$tbl" in
    blackhole|none|split|unreadable|other) hop="$tbl" ;;
    "dev:$MESH_DEV") hop=mmesh ;;
    dev:*)
      hop=other
      for p in $pairs; do
        if [ "dev:${p#*=}" = "$tbl" ]; then hop="${p%%=*}"; break; fi
      done
      ;;
    *) hop=unreadable ;;
  esac
  if [ -n "$hfail" ]; then
    result=failed
    echo "$hfail $now" > "$dir/hopfail.tmp" && mv -f "$dir/hopfail.tmp" "$dir/hopfail"
  else
    expect="$active"
    if [ "$active" = "mmesh" ] && [ "$hop" = "blackhole" ]; then expect=blackhole; fi
    [ "$hop" = "$expect" ] || result=diverged
  fi
  alert=$(cat "$dir/alert" 2>/dev/null || echo 0)
  case "$alert" in 1) ;; *) alert=0 ;; esac
  switched=$(cat "$dir/switched" 2>/dev/null || echo 0)
  case "$switched" in ''|*[!0-9]*) switched=0 ;; esac
  lastfail=$(cat "$dir/hopfail" 2>/dev/null || true)
  tmp="$dir/.report.$$"
  {
    echo "meridian-group-report 1"
    echo "group $gid"
    echo "plan $GROUP_PLAN"
    echo "beat $now"
    echo "hop $hop"
    echo "active $active"
    echo "reason $reason"
    echo "alert $alert"
    echo "switched $switched"
    echo "result $result"
    if [ -n "$hfail" ]; then echo "want $hfail"; fi
    if [ -n "$lastfail" ]; then echo "lastfail $lastfail"; fi
    echo "end"
  } > "$tmp" && mv -f "$tmp" "$dir/report" || rm -f "$tmp"
  return 0
}
group_plan_record() {
  local tmp="/run/meridian/.group-plan.$$"
  mkdir -p /run/meridian
  printf 'plan %s %s\n' "$GROUP_PLAN" "$(date +%s)" > "$tmp" && mv -f "$tmp" /run/meridian/group-plan
}
`
