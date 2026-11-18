package compile

import "strings"

// The backup group (docs/architecture.md「主备中继分组」): the backup hub is
// reached through relays of its own. The gateway shares across the main
// group (relays tunnelled to the primary hub); only while every main-group
// relay is completely unreachable it shares across the backup group
// instead, with the same map, tables, speed tests and QoS. The shell is the
// sharing shell with three changes, made only for such a topology (every
// other topology keeps shareShell byte for byte): share_apply accepts
// "backup" with weights over the backup group, share_record names the
// backup hub and the backup group, and the fallback step switches between
// the groups.

// shareGroupShell is shareShell for a topology with a backup group.
func shareGroupShell() string {
	return groupReplace(groupReplace(groupReplace(shareShell, groupApplyOld, groupApplyNew), groupRecordOld, groupRecordNew), groupRecordBackupOld, groupRecordBackupNew)
}

// shareGroupLoopShell is shareLoopShell with the group fallback step.
func shareGroupLoopShell() string {
	s := groupReplace(shareLoopShell, groupDecideOld, groupDecideNew)
	return groupReplace(s, "# --- main loop ---\n", shareGroupFallback+"# --- main loop ---\n")
}

// An applied record (controller or fallback) becomes the fallback's state
// through share_load_applied; with groups only the carrying group's relays
// take their membership from it (all relays are main-group otherwise).
const groupDecideOld = `        if [ main = "$fb_up" ]; then
`

const groupDecideNew = `        if [ "${SH_GROUP[$i]}" = "$fb_up" ]; then
`

func groupReplace(s, old, new string) string {
	if strings.Count(s, old) != 1 {
		panic("compile: share shell changed: " + old)
	}
	return strings.Replace(s, old, new, 1)
}

const groupApplyOld = `  case "$up" in
    main)
      [ "$sum" -eq 1000 ] || { echo "share_apply: weights must sum to 1000" >&2; return 1; }
      i=$(share_index "$des") || { echo "share_apply: $des is not a relay" >&2; return 1; }
      desif="${legs[$i]}"
      ;;
    backup)
      [ -n "$SH_BK_IFACE" ] && [ "$sum" -eq 0 ] && [ "$des" = backup ] || { echo "share_apply: bad backup decision" >&2; return 1; }
      desif="$SH_BK_IFACE"
      ;;
    *) echo "share_apply: bad upstream" >&2; return 1 ;;
  esac
`

const groupApplyNew = `  # Groups: the carrying group's weights sum to 1000, the other's are 0.
  case "$up" in main|backup) ;; *) echo "share_apply: bad upstream" >&2; return 1 ;; esac
  for ((i = 0; i < n; i++)); do
    [ "${ws[$i]}" -eq 0 ] || [ "${SH_GROUP[$i]}" = "$up" ] || { echo "share_apply: ${SH_NAME[$i]} is not in the $up group" >&2; return 1; }
  done
  [ "$sum" -eq 1000 ] || { echo "share_apply: weights must sum to 1000" >&2; return 1; }
  i=$(share_index "$des") && [ "${SH_GROUP[$i]}" = "$up" ] || { echo "share_apply: $des is not a relay of the $up group" >&2; return 1; }
  desif="${legs[$i]}"
`

const groupRecordOld = `  if [ "$up" = backup ]; then
    iface="$SH_BK_IFACE"; hub="$SH_BK_HUB"; tier=backup
  else
    i=$(share_index "$des") || i=0
    iface="${SH_R_LEG[$i]}"; hub="$SH_PRIMARY"; tier=primary
  fi
`

const groupRecordNew = `  i=$(share_index "$des") || i=0
  iface="${SH_R_LEG[$i]}"; hub="$SH_PRIMARY"; tier=primary
  if [ "$up" = backup ]; then hub="$SH_BK_HUB"; tier=backup; fi
`

const groupRecordBackupOld = `    if [ -n "$SH_BK_IFACE" ]; then echo "backup $SH_BK_HUB $SH_BK_IFACE ${SH_BK_GRADE:-none} - - - - 0 0 0 0"; fi
`

const groupRecordBackupNew = `    echo "backup_group $SH_BK_HUB $SH_BK_GROUP"
`

// shareGroupFallback redefines share_fallback_step: reachability only, the
// main group while some main-group relay is in, the backup group while no
// main-group relay is in and some backup-group relay is, back to the main
// group once some main-group relay has answered MAIN_RETURN_NEED (3)
// consecutive passes and COOLDOWN (120 s) has passed since the last switch.
// While the main group carries, a relay rejoins after RECOVERS_NEED passes
// as in the ungrouped shell.
//
// The controller's applied record reaches the fallback through
// share_load_applied (switch time and since come from the published record;
// counters restart when the carrying group changed). While the backup group
// carries, the main group is out with no recovery counted.
const shareGroupFallback = `MAIN_RETURN_NEED=3
share_fallback_candidate() {
  local n=${#SH_NAME[@]} i l alive now cnt=0 bkcnt=0 up des state=ok w args=() share rest first=-1 need
  now=$(date +%s)
  for ((i = 0; i < n; i++)); do
    alive=""
    for l in ${SH_LEGS[$i]}; do
      if share_alive "$l" "${SH_PROBE[$i]}"; then alive="$l"; break; fi
    done
    if [ -n "$alive" ]; then
      SH_R_LEG[$i]="$alive"; SH_R_GRADE[$i]=good; fb_fails[$i]=0
      if [ "${fb_in[$i]}" = 0 ]; then
        fb_goods[$i]=$((fb_goods[$i] + 1))
        need="$RECOVERS_NEED"
        if [ "$fb_up" = backup ] && [ "${SH_GROUP[$i]}" = main ]; then need="$MAIN_RETURN_NEED"; fi
        if [ "${fb_goods[$i]}" -ge "$need" ]; then fb_in[$i]=1; fb_goods[$i]=0; fi
      fi
    else
      SH_R_GRADE[$i]=down; fb_goods[$i]=0
      if [ "${fb_in[$i]}" = 1 ]; then
        fb_fails[$i]=$((fb_fails[$i] + 1))
        if [ "${fb_fails[$i]}" -ge "$FAILS_NEED" ]; then fb_in[$i]=0; fb_fails[$i]=0; fi
      fi
    fi
    if [ "${fb_in[$i]}" = 1 ]; then
      SH_R_STATUS[$i]=active; SH_R_REASON[$i]=-
      if [ "${SH_GROUP[$i]}" = main ]; then cnt=$((cnt + 1)); else bkcnt=$((bkcnt + 1)); fi
    else
      SH_R_STATUS[$i]=evicted; SH_R_REASON[$i]=down
    fi
  done
  share_qos_read
  up="$fb_up"
  if [ "$up" = main ] && [ "$cnt" -eq 0 ] && [ "$bkcnt" -gt 0 ]; then
    up=backup
  elif [ "$up" = backup ] && [ "$cnt" -gt 0 ] && { [ "$fb_switched" -eq 0 ] || [ $((now - fb_switched)) -ge "$COOLDOWN" ]; }; then
    up=main
  fi
  if [ "$up" != "$fb_up" ]; then
    fb_switched=$now; fb_since=$now
    for ((i = 0; i < n; i++)); do fb_goods[$i]=0; fb_fails[$i]=0; done
  fi
  fb_up="$up"
  # Equal weights over the carrying group's relays in; none in: equal over
  # the whole group (the traffic is dropped in the tunnels either way).
  local sel=() m=0
  for ((i = 0; i < n; i++)); do
    sel[$i]=0
    [ "${SH_GROUP[$i]}" = "$up" ] && sel[$i]="${fb_in[$i]}"
  done
  share_qos_select
  for ((i = 0; i < n; i++)); do
    [ "${sel[$i]}" = 1 ] && m=$((m + 1))
  done
  if [ "$m" -eq 0 ]; then
    for ((i = 0; i < n; i++)); do
      if [ "${SH_GROUP[$i]}" = "$up" ]; then sel[$i]=1; m=$((m + 1)); fi
    done
  fi
  share=$((1000 / m)); rest=$((1000 - share * m))
  for ((i = 0; i < n; i++)); do
    if [ "${sel[$i]}" = 1 ]; then
      SH_R_W[$i]=$((share + rest)); rest=0
      [ "$first" -ge 0 ] || first=$i
    else
      SH_R_W[$i]=0
    fi
  done
  des="${SH_NAME[$first]}"
  fb_des="$des"
  if [ "$up" = backup ] && [ "$bkcnt" -eq 0 ]; then state=down; fi
  if [ "$up" = main ] && [ "$cnt" -eq 0 ]; then state=down; fi
  for ((i = 0; i < n; i++)); do
    args+=("${SH_R_LEG[$i]}" "${SH_R_W[$i]}" 0)
  done
  share_candidate || return 4
  ( UP_STATE="$SH_CANDIDATE/status"; share_record "$state" shell "$up" "$des" "$fb_since" "$fb_switched" controller_unavailable ) || return 4
  share_once "$up $des ${args[*]} 0" "$up" "$des" "${args[@]}" 0 || return $?

}
`
