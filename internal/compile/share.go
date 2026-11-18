package compile

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// Relay sharing (docs/architecture.md「多中继同时分担」): with two or more
// relays the gateway carries the main path over all of them at once.
//
//   - Assignment: a new exit-marked connection from the LAN or mra gets
//     its ct mark from "jhash <5-tuple> mod 1000 map { ranges : relay }"
//     (chain relay_assign), never per packet. Every later packet of the
//     connection restores the relay bits into its fwmark (relay_share);
//     an ip rule per relay sends those to the relay's own table, which only
//     points at that relay's leg in use. The bits are stripped in the
//     forward hook at priority -300 (relay_strip), before the guard, the
//     MSS clamp and the transit SNAT look at the mark.
//   - Weights: the map's ranges are the weights. The install ships equal
//     weights in the nft file; afterwards only meridian-failover.sh changes
//     them, with one nft batch (flush + add of relay_assign, relay_redirect
//     and relay_drain together, so there is never a moment without a map)
//     built by share_apply from the decision of "meridian path-step"
//     (internal/pathquality), which measures every path each pass.
//   - Eviction: an evicted relay gets no new connections (weight 0); with
//     the default rule its existing TCP connections from the LAN are reset
//     (relay_drain, forward hook) and its other flows are re-hashed onto
//     the sharing set (relay_redirect).
//   - Replies: the relays and the primary hub mark each connection with
//     the tunnel it arrived on and route its replies back into that tunnel
//     (ingressReturns), so every connection is symmetric end to end.
//   - Table 102 follows the designated relay (the heaviest; or the backup
//     hub): this host's own exit-marked sockets (SmartDNS group upstreams
//     with -set-mark) and connections older than the install use it.
//
// A topology with one relay compiles exactly as before (planShare is nil).

// shareRelay is one sharing relay as the gateway sees it.
type shareRelay struct {
	Node  model.Node
	Index int // 1-based
	Legs  []Tunnel
	// Probe is the primary hub's address on this relay's relay→hub tunnel.
	Probe string
	Value uint32
	Table int
	Prio  int
	// Group is model.RelayGroupBackup for a backup-group relay (Probe is
	// then the backup hub's address on its relay→hub tunnel), else main.
	Group string
}

type shareBackup struct {
	Hub   model.Node
	Tun   Tunnel
	Value uint32
	Table int
	Prio  int
}

type sharePlan struct {
	Primary model.Node
	Relays  []shareRelay
	Backup  *shareBackup
	// BackupHub is the backup hub reached through the backup group of
	// relays (nil Backup then); zero without one.
	BackupHub model.Node
	// In is the managed ingress match ("eth0" or { "eth0", "mra" }).
	In string
}

// planShare is nil unless the topology shares the main path across two or
// more relays (model.Topology.RelaySharing).
func planShare(t model.Topology, tunnels []Tunnel) *sharePlan {
	if !t.RelaySharing() {
		return nil
	}
	primary, _ := t.PrimaryHub()
	p := &sharePlan{Primary: primary}
	lan := gatewayLAN(t)
	p.In = fmt.Sprintf("\"%s\"", lan)
	if rp := planRemote(t); rp != nil {
		p.In = fmt.Sprintf("{ \"%s\", \"%s\" }", lan, rp.Iface)
	}
	relays := t.SharingRelays()
	if t.RelayBackup() {
		// The main group first (table 102 starts on its first relay), then
		// the backup group.
		p.BackupHub, _ = t.BackupHub()
		relays = append(t.MainGroupRelays(), t.BackupGroupRelays()...)
	}
	for i, n := range relays {
		r := shareRelay{Node: n, Index: i + 1, Value: pathquality.RelayMark(i + 1), Table: tableShareBase + i + 1, Prio: prioShare + i + 1, Group: model.RelayGroupMain}
		hub := primary.ID
		if t.RelayBackup() && t.RelayGroupOf(n.ID) == model.RelayGroupBackup {
			r.Group, hub = model.RelayGroupBackup, p.BackupHub.ID
		}
		var udp, wss []Tunnel
		for _, tun := range tunnels {
			if tun.West.Role != model.RoleGateway || tun.East.ID != n.ID || tun.Standby {
				continue
			}
			if tun.Mode == "udp" {
				udp = append(udp, tun)
			} else {
				wss = append(wss, tun)
			}
		}
		r.Legs = append(udp, wss...)
		if len(r.Legs) > 2 {
			r.Legs = r.Legs[:2]
		}
		r.Probe = relayHubTunnel(tunnels, n.ID, hub).EastV4
		p.Relays = append(p.Relays, r)
	}
	if b, ok := t.BackupHub(); ok && p.BackupHub.ID == "" {
		for _, tun := range tunnels {
			if tun.West.Role == model.RoleGateway && tun.East.ID == b.ID && tun.Transport == model.TransportIXReplacementWSS {
				p.Backup = &shareBackup{Hub: b, Tun: tun, Value: pathquality.BackupMark, Table: tableShareBackup, Prio: prioShare}
				break
			}
		}
	}
	return p
}

// relayHubTunnel is the relay's preferred tunnel to the hub: direct
// WireGuard (or the UDP leg of a failover link) first, then WSS.
func relayHubTunnel(tunnels []Tunnel, relay, hub string) Tunnel {
	var best Tunnel
	for _, tun := range tunnels {
		if tun.West.ID != relay || tun.East.ID != hub {
			continue
		}
		if best.LinkID == "" || (best.Mode == "wss" && tun.Mode == "udp") {
			best = tun
		}
	}
	return best
}

// shareConfig is the compiled controller config (path-quality.json).
func shareConfig(t model.Topology, p *sharePlan) pathquality.Config {
	c := pathquality.Config{
		Version: pathquality.ConfigVersion, Interval: pathquality.PassInterval, ProbeSource: upstreamProbeSrc,
		PrimaryHub: p.Primary.ID, Settings: t.Settings.PathQuality.Effective(),
	}
	for _, r := range p.Relays {
		rc := pathquality.RelayConfig{ID: r.Node.ID, Index: r.Index, Probe: r.Probe, Value: r.Value, Table: r.Table}
		for _, l := range r.Legs {
			leg := pathquality.Leg{Iface: l.Iface(), Mode: l.Mode}
			if speedTestOn(t, p) {
				leg.Local, leg.Remote = l.WestV4, l.EastV4
			}
			rc.Legs = append(rc.Legs, leg)
		}
		if r.Group == model.RelayGroupBackup {
			rc.Group = pathquality.GroupBackup
		}
		c.Relays = append(c.Relays, rc)
	}
	if speedTestOn(t, p) {
		c.SpeedPort = pathquality.SpeedPort
	}
	c.BackupHub = p.BackupHub.ID
	if b := p.Backup; b != nil {
		c.Backup = &pathquality.BackupConfig{Hub: b.Hub.ID, Iface: b.Tun.Iface(), Probe: b.Tun.EastV4, Value: b.Value, Table: b.Table}
	}
	return c
}

func renderShareConfig(t model.Topology, p *sharePlan) string {
	b, err := json.MarshalIndent(shareConfig(t, p), "", "  ")
	if err != nil {
		panic(err) // plain structs: cannot fail
	}
	return string(b) + "\n"
}

// SharePathConfig is where the gateway reads the controller config.
const SharePathConfig = "/etc/meridian/path-quality.json"

const (
	shareHash4 = "jhash ip saddr . ip daddr . th sport . th dport mod 1000 seed 0x4d52"
	shareHash6 = "jhash ip6 saddr . ip6 daddr . th sport . th dport mod 1000 seed 0x4d52"
)

func hexMark(v uint32) string { return fmt.Sprintf("0x%08x", v) }

// shareMap is the nft map for the weights (relay order); all zero sends
// every new connection to the backup hub. share_map in the shell prelude
// prints the same text (a test compares them).
func shareMap(p *sharePlan, weights []int) string {
	var parts []string
	lo := 0
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d : %s", lo, lo+w-1, hexMark(p.Relays[i].Value)))
		lo += w
	}
	if len(parts) == 0 {
		parts = []string{"0-999 : " + hexMark(pathquality.BackupMark)}
	}
	return "map { " + strings.Join(parts, ", ") + " }"
}

func shareAssignRules(p *sharePlan, weights []int) (v4, v6 string) {
	m := shareMap(p, weights)
	return "meta nfproto ipv4 ct mark set " + shareHash4 + " " + m, "meta nfproto ipv6 ct mark set " + shareHash6 + " " + m
}

// initialWeights: equal over the relays (with a backup group: over the
// main group, the backup group at zero).
func initialWeights(p *sharePlan) []int {
	if p.BackupHub.ID == "" {
		return pathquality.EqualWeights(len(p.Relays))
	}
	c := pathquality.Config{BackupHub: p.BackupHub.ID}
	for _, r := range p.Relays {
		rc := pathquality.RelayConfig{ID: r.Node.ID}
		if r.Group == model.RelayGroupBackup {
			rc.Group = pathquality.GroupBackup
		}
		c.Relays = append(c.Relays, rc)
	}
	return pathquality.InitialWeights(c)
}

// writeShareNFT renders the gateway's relay-sharing chains into table inet
// meridian (only with relay sharing).
func writeShareNFT(sb *strings.Builder, t model.Topology, p *sharePlan) {
	sb.WriteString("  # relay sharing (compile.planShare): per-connection weighted assignment\n")
	for _, r := range p.Relays {
		for _, c := range []string{"new", "tcp_out", "tcp_in"} {
			fmt.Fprintf(sb, "  counter share_r%d_%s {\n  }\n", r.Index, c)
		}
	}
	if p.Backup != nil {
		sb.WriteString("  counter share_bk_new {\n  }\n")
	}
	v4, v6 := shareAssignRules(p, initialWeights(p))
	sb.WriteString("  chain relay_assign {\n")
	sb.WriteString("    " + v4 + "\n    " + v6 + "\n  }\n")
	sb.WriteString("  chain relay_redirect {\n  }\n")
	sb.WriteString("  chain relay_drain {\n  }\n")
	sb.WriteString("  chain relay_share {\n")
	sb.WriteString("    jump relay_redirect\n")
	sb.WriteString("    ct state new jump relay_assign\n")
	vals := shareValues(p)
	for _, v := range vals {
		fmt.Fprintf(sb, "    ct state new ct mark %s counter name \"%s_new\"\n", hexMark(v.value), v.counter)
	}
	for _, v := range vals {
		if v.relay {
			fmt.Fprintf(sb, "    meta l4proto tcp ct mark %s counter name \"%s_tcp_out\"\n", hexMark(v.value), v.counter)
		}
	}
	for _, v := range vals {
		fmt.Fprintf(sb, "    ct mark %s meta mark set meta mark | %s return comment \"%s\"\n", hexMark(v.value), hexMark(v.value), v.label)
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain relay_count_in {\n")
	for _, v := range vals {
		if v.relay {
			fmt.Fprintf(sb, "    ct mark %s counter name \"%s_tcp_in\"\n", hexMark(v.value), v.counter)
		}
	}
	sb.WriteString("  }\n")
	fmt.Fprintf(sb, "  chain relay_strip {\n    type filter hook forward priority -300; policy accept;\n    meta mark & %s != 0x00000000 meta mark set meta mark & %#08x comment \"relay bits only steer routing; the guard, MSS and SNAT see the exit mark\"\n  }\n",
		hexMark(markShareMask), ^markShareMask)
	sb.WriteString("  chain share_forward {\n    type filter hook forward priority filter; policy accept;\n")
	writeGatewaySpeedGuard(sb, t, p)
	sb.WriteString("    jump relay_drain\n  }\n\n")
}

type shareValue struct {
	value   uint32
	counter string
	label   string
	relay   bool
}

func shareValues(p *sharePlan) []shareValue {
	var out []shareValue
	for _, r := range p.Relays {
		out = append(out, shareValue{r.Value, fmt.Sprintf("share_r%d", r.Index), "relay " + verifyLabel(r.Node.ID) + ": table " + fmt.Sprint(r.Table), true})
	}
	if p.Backup != nil {
		out = append(out, shareValue{p.Backup.Value, "share_bk", "backup hub " + verifyLabel(p.Backup.Hub.ID) + ": table " + fmt.Sprint(p.Backup.Table), false})
	}
	return out
}

// sharePrelude is shared byte for byte by the gateway's routes script and
// its failover script: the compiled arrays, share_apply (the only function
// that changes the assignment map, the relay tables and table 102 at run
// time), share_tables/share_designate (also used by the install) and
// share_record (the status record written by the install and by the
// shell fallback).
func sharePrelude(p *sharePlan) string {
	var names, legs, probes, tables, values []string
	for _, r := range p.Relays {
		names = append(names, shQuote(r.Node.ID))
		var ls []string
		for _, l := range r.Legs {
			ls = append(ls, l.Iface())
		}
		legs = append(legs, shQuote(strings.Join(ls, " ")))
		probes = append(probes, shQuote(r.Probe))
		tables = append(tables, fmt.Sprint(r.Table))
		values = append(values, hexMark(r.Value))
	}
	bkHub, bkIface, bkProbe, bkTable, bkValue := p.BackupHub.ID, "", "", "", ""
	if b := p.Backup; b != nil {
		bkHub, bkIface, bkProbe, bkTable, bkValue = b.Hub.ID, b.Tun.Iface(), b.Tun.EastV4, fmt.Sprint(b.Table), hexMark(b.Value)
	}
	var sb strings.Builder
	sb.WriteString("# relay sharing (compile.planShare); only share_apply changes the map and the relay tables at run time\n")
	fmt.Fprintf(&sb, "SH_NAME=(%s)\nSH_LEGS=(%s)\nSH_PROBE=(%s)\nSH_TABLE=(%s)\nSH_VALUE=(%s)\n",
		strings.Join(names, " "), strings.Join(legs, " "), strings.Join(probes, " "), strings.Join(tables, " "), strings.Join(values, " "))
	fmt.Fprintf(&sb, "SH_BK_HUB=%s\nSH_BK_IFACE=%s\nSH_BK_PROBE=%s\nSH_BK_TABLE=%s\nSH_BK_VALUE=%s\n",
		shQuote(bkHub), shQuote(bkIface), shQuote(bkProbe), shQuote(bkTable), shQuote(bkValue))
	fmt.Fprintf(&sb, "SH_PRIMARY=%s\nSH_IN=%s\nSH_HASH4=%s\nSH_HASH6=%s\n", shQuote(p.Primary.ID), shQuote(p.In), shQuote(shareHash4), shQuote(shareHash6))
	fmt.Fprintf(&sb, "UP_STATE=%s\nSH_APPLIED=/run/meridian/pathq/applied\n", UpstreamStateFile)
	var groupVersion strings.Builder
	for _, r := range p.Relays {
		fmt.Fprintf(&groupVersion, "%s:%s\n", r.Node.ID, r.Group)
	}
	version := sha256.Sum256([]byte(sb.String() + groupVersion.String() + shareGroupShell() + shareTransactionShell + shareGroupLoopShell()))
	fmt.Fprintf(&sb, "SH_VERSION=%x\n", version)
	sb.WriteString(shareTransactionShell)
	if p.BackupHub.ID == "" {
		sb.WriteString(shareShell)
		return sb.String()
	}
	var groups, bkIDs []string
	for _, r := range p.Relays {
		groups = append(groups, r.Group)
		if r.Group == model.RelayGroupBackup {
			bkIDs = append(bkIDs, r.Node.ID)
		}
	}
	fmt.Fprintf(&sb, "SH_GROUP=(%s)\nSH_BK_GROUP=%s\n", strings.Join(groups, " "), shQuote(strings.Join(bkIDs, " ")))
	sb.WriteString(shareGroupShell())
	return sb.String()
}

// shareQoSPrelude: the speed tests' verdict file and how the shell reads it
// (only with the speed tests on; share_record prints "off" otherwise).
func shareQoSPrelude(t model.Topology, p *sharePlan) string {
	if !speedTestOn(t, p) {
		return "SH_QOS_ON=0\nSH_QOS_DEF=off\n"
	}
	return fmt.Sprintf("SH_QOS_ON=1\nSH_QOS_DEF=unknown\nQOS_FILE=%s\nQOS_MAX_AGE=%d\n", pathquality.QoSPath, pathquality.QoSMaxAge(t.Settings.PathQuality.Effective()))
}

const shareShell = `share_index() {
  local i
  for ((i = 0; i < ${#SH_NAME[@]}; i++)); do
    if [ "${SH_NAME[$i]}" = "$1" ]; then echo "$i"; return 0; fi
  done
  return 1
}
share_leg_ok() {
  case "$2" in ''|*[!A-Za-z0-9_.-]*) return 1 ;; esac
  case " ${SH_LEGS[$1]} " in *" $2 "*) return 0 ;; esac
  return 1
}
share_table_route() {
  ip route replace default dev "$2" table "$1" || return 3
  ip route replace blackhole default metric 32767 table "$1" || return 3
  ip -6 route replace default dev "$2" table "$1" || return 3
  ip -6 route replace blackhole default metric 32767 table "$1" || return 3
}
# share_tables LEG_1 … LEG_n: each relay's table on the given leg; the backup table.
share_tables() {
  local i=0 leg
  for leg in "$@"; do
    share_leg_ok "$i" "$leg" || { echo "share_tables: $leg is not a leg of ${SH_NAME[$i]}" >&2; return 1; }
    share_table_route "${SH_TABLE[$i]}" "$leg" || return $?
    i=$((i + 1))
  done
  if [ -n "$SH_BK_IFACE" ]; then share_table_route "$SH_BK_TABLE" "$SH_BK_IFACE" || return $?; fi
  return 0
}
# share_designate IFACE: table 102 and this host's routes to the tunnel prefixes.
share_designate() {
  local iface="$1"
  [ -n "$iface" ] || return 1
  ip route replace default dev "$iface" table 102 || return 3
  ip route replace blackhole default metric 32767 table 102 || return 3
  ip -6 route replace default dev "$iface" table 102 || return 3
  ip -6 route replace blackhole default metric 32767 table 102 || return 3
  ip route replace 10.66.0.0/16 dev "$iface" || return 3
  ip route replace blackhole 10.66.0.0/16 metric 32767 || return 3
  ip -6 route replace fd66::/48 dev "$iface" || return 3
  ip -6 route replace blackhole fd66::/48 metric 32767 || return 3
}
# share_map W_1 … W_n: the assignment map (ranges of jhash … mod 1000).
share_map() {
  local i=0 lo=0 w parts=""
  for w in "$@"; do
    if [ "$w" -gt 0 ]; then
      parts="${parts:+$parts, }$lo-$((lo + w - 1)) : ${SH_VALUE[$i]}"
      lo=$((lo + w))
    fi
    i=$((i + 1))
  done
  [ -n "$parts" ] || parts="0-999 : $SH_BK_VALUE"
  echo "map { $parts }"
}
# share_apply UP DESIGNATED LEG_1 W_1 D_1 … LEG_n W_n D_n BACKUP_DRAIN
# Checks every value against the compiled arrays (1: refused), then
# changes the map, the redirect and drain rules in ONE nft batch (refused
# whole or applied whole; 2: nft refused it, nothing changed), the relay
# tables and table 102. Nothing else.
share_apply_raw() {
  local up="$1" des="$2" n=${#SH_NAME[@]} i sum=0 leg w d bk map desif redirect="" drain="" v
  shift 2
  if [ $# -ne $((3 * n + 1)) ]; then echo "share_apply: wrong argument count" >&2; return 1; fi
  local legs=() ws=() ds=()
  for ((i = 0; i < n; i++)); do
    leg="$1"; w="$2"; d="$3"; shift 3
    share_leg_ok "$i" "$leg" || { echo "share_apply: $leg is not a leg of ${SH_NAME[$i]}" >&2; return 1; }
    case "$w" in ''|*[!0-9]*) echo "share_apply: bad weight" >&2; return 1 ;; esac
    [ "$w" -le 1000 ] || { echo "share_apply: bad weight" >&2; return 1; }
    case "$d" in 0|1) ;; *) echo "share_apply: bad drain flag" >&2; return 1 ;; esac
    legs+=("$leg"); ws+=("$w"); ds+=("$d"); sum=$((sum + w))
  done
  bk="$1"
  case "$bk" in 0|1) ;; *) echo "share_apply: bad backup drain flag" >&2; return 1 ;; esac
  case "$up" in
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
  [ "${SH_VALIDATE:-0}" != 1 ] || return 0
  map=$(share_map "${ws[@]}")
  for ((i = 0; i <= n; i++)); do
    if [ "$i" -lt "$n" ]; then
      [ "${ds[$i]}" = 1 ] || continue
      v="${SH_VALUE[$i]}"
    else
      [ "$bk" = 1 ] && [ -n "$SH_BK_IFACE" ] || continue
      v="$SH_BK_VALUE"
    fi
    redirect="${redirect}add rule inet meridian relay_redirect ct mark $v meta l4proto != tcp meta nfproto ipv4 ct mark set $SH_HASH4 $map
add rule inet meridian relay_redirect ct mark $v meta l4proto != tcp meta nfproto ipv6 ct mark set $SH_HASH6 $map
"
    drain="${drain}add rule inet meridian relay_drain iifname $SH_IN ct direction original ct mark $v meta l4proto tcp reject with tcp reset
"
  done
  if ! printf 'flush chain inet meridian relay_assign\nadd rule inet meridian relay_assign meta nfproto ipv4 ct mark set %s %s\nadd rule inet meridian relay_assign meta nfproto ipv6 ct mark set %s %s\nflush chain inet meridian relay_redirect\n%sflush chain inet meridian relay_drain\n%s' \
    "$SH_HASH4" "$map" "$SH_HASH6" "$map" "$redirect" "$drain" | nft -f -; then
    echo "share_apply: nft refused the batch; the previous map stays" >&2
    return 2
  fi
  share_tables "${legs[@]}" || return $?
  share_designate "$desif"
}
# share_record STATE CONTROLLER UP DESIGNATED SINCE SWITCHED ALERT: the
# upstream record from the shell (the install, and the fallback when
# path-step is unavailable); relay lines from SH_R_* (no measurements).
share_record() {
  local state="$1" ctl="$2" up="$3" des="$4" since="$5" sw="$6" alert="$7" i tmp iface hub tier
  if [ "$up" = backup ]; then
    iface="$SH_BK_IFACE"; hub="$SH_BK_HUB"; tier=backup
  else
    i=$(share_index "$des") || i=0
    iface="${SH_R_LEG[$i]}"; hub="$SH_PRIMARY"; tier=primary
  fi
  mkdir -p "${UP_STATE%/*}" || return 4
  tmp="${UP_STATE%/*}/.upstream.$$"
  {
    echo "meridian-upstream 2"
    echo "beat $(date +%s)"
    echo "path $up"
    echo "iface $iface"
    echo "hub $hub"
    echo "tier $tier"
    echo "since $since"
    echo "state $state"
    echo "controller $ctl"
    echo "alert $alert"
    echo "switched $sw"
    echo "designated $des"
    for ((i = 0; i < ${#SH_NAME[@]}; i++)); do
      echo "relay ${SH_NAME[$i]} ${SH_R_LEG[$i]} ${SH_R_STATUS[$i]} ${SH_R_W[$i]} 0 ${SH_R_REASON[$i]} $since ${SH_R_GRADE[$i]} - - - - 0 0 0 0 0 0 - 0 - - - 0 ${SH_R_QOS[$i]:-$SH_QOS_DEF} ${SH_R_SPEED[$i]:--} ${SH_R_SPAT[$i]:-0} ${SH_R_BASE[$i]:-0} ${SH_R_BSRC[$i]:--}"
    done
    if [ -n "$SH_BK_IFACE" ]; then echo "backup $SH_BK_HUB $SH_BK_IFACE ${SH_BK_GRADE:-none} - - - - 0 0 0 0"; fi
    echo "end"
  } > "$tmp" && mv -f "$tmp" "$UP_STATE" || { rm -f "$tmp"; return 4; }
  return 0
}
`

// shareInitArrays are the SH_R_* arrays at the compiled start: preferred
// legs, equal weights, every relay active.
func shareInitArrays(p *sharePlan) string {
	var legs, ws, st, gr, rs []string
	for i, r := range p.Relays {
		legs = append(legs, r.Legs[0].Iface())
		ws = append(ws, fmt.Sprint(initialWeights(p)[i]))
		st = append(st, "active")
		gr = append(gr, "none")
		rs = append(rs, "-")
	}
	return fmt.Sprintf("SH_R_LEG=(%s)\nSH_R_W=(%s)\nSH_R_STATUS=(%s)\nSH_R_GRADE=(%s)\nSH_R_REASON=(%s)\n",
		strings.Join(legs, " "), strings.Join(ws, " "), strings.Join(st, " "), strings.Join(gr, " "), strings.Join(rs, " "))
}

// renderShareRoutes is the gateway's relay-sharing part of
// meridian-routes.sh: the prelude, the probe source and host routes, one
// ip rule per relay (and the backup), the tables on the preferred legs,
// table 102 on the first relay and a "static" record. The map itself is in
// the nft file (equal weights), loaded before this script runs.
func renderShareRoutes(sb *strings.Builder, t model.Topology, p *sharePlan) {
	sb.WriteString(shareQoSPrelude(t, p))
	sb.WriteString(shareInitArrays(p))
	fmt.Fprintf(sb, "ip addr replace %s/32 dev lo\n", upstreamProbeSrc)
	metric := 10
	for _, r := range p.Relays {
		for _, l := range r.Legs {
			// Only ping -I <leg> uses these: the end-to-end check of each
			// relay leg, from the probe source the primary hub routes home.
			fmt.Fprintf(sb, "ip route replace %s/32 dev %s src %s metric %d\n", r.Probe, l.Iface(), upstreamProbeSrc, metric)
			metric++
		}
	}
	type rule struct {
		value uint32
		table int
		prio  int
	}
	var rules []rule
	if b := p.Backup; b != nil {
		rules = append(rules, rule{b.Value, b.Table, b.Prio})
	}
	for _, r := range p.Relays {
		rules = append(rules, rule{r.Value, r.Table, r.Prio})
	}
	for _, r := range rules {
		for _, fam := range []string{"ip", "ip -6"} {
			fmt.Fprintf(sb, "del_rule %s rule del fwmark %#x/%#x lookup %d\n", fam, r.value, markShareMask, r.table)
			fmt.Fprintf(sb, "%s rule add fwmark %#x/%#x lookup %d priority %d\n", fam, r.value, markShareMask, r.table, r.prio)
		}
	}
	fmt.Fprintf(sb, "# meridian-share-first: %s %s hub %s\n", p.Relays[0].Node.ID, p.Relays[0].Legs[0].Iface(), p.Primary.ID)

}

// renderGatewayFailoverShare is meridian-failover.sh with relay sharing:
// each pass runs "meridian path-step" (measure, decide, record) and applies
// its decision with share_apply; when path-step is unavailable or its
// decision is refused, the pass falls back to equal weights over the relays
// that answer a ping (reachability only, FAILS_NEED/RECOVERS_NEED passes),
// the backup hub only while no relay answers, back after COOLDOWN.
func renderGatewayFailoverShare(t model.Topology, p *sharePlan) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Relay sharing: every relay carries new connections at the weight the controller\n")
	sb.WriteString("# (meridian path-step: measure, decide, record) sets from measured path quality; the\n")
	sb.WriteString("# backup hub only while every relay is persistently below the usable floor.\n")
	sb.WriteString("# Fallback when path-step is unavailable: equal weights over the relays that answer,\n")
	sb.WriteString("# reachability only. Nothing answering: tables stay on tunnels (never the LAN NIC).\n")
	sb.WriteString("set -u\n")
	sb.WriteString(sharePrelude(p))
	sb.WriteString(shareQoSPrelude(t, p))
	sb.WriteString(shareInitArrays(p))
	fmt.Fprintf(&sb, "MERIDIAN_BIN=/usr/local/bin/meridian\nPQ_CONFIG=%s\nPQ_STATE=/run/meridian/pathq/state.json\n", SharePathConfig)
	fmt.Fprintf(&sb, "INTERVAL=%d\nFAILS_NEED=3\nRECOVERS_NEED=5\nCOOLDOWN=120\n", pathquality.PassInterval)
	var zeros, ones []string
	for range p.Relays {
		zeros = append(zeros, "0")
		ones = append(ones, "1")
	}
	fmt.Fprintf(&sb, "fb_up=main\nfb_des=%s\nfb_since=$(date +%%s)\nfb_switched=0\nfb_fails=(%s)\nfb_goods=(%s)\nfb_in=(%s)\nSH_BK_GRADE=none\n",
		shQuote(p.Relays[0].Node.ID), strings.Join(zeros, " "), strings.Join(zeros, " "), strings.Join(ones, " "))
	if p.BackupHub.ID != "" {
		sb.WriteString(shareGroupLoopShell())
	} else {
		sb.WriteString(shareLoopShell)
	}
	return sb.String()
}

const shareLoopShell = `share_alive() {
  ping -n -q -I "$1" -c 1 -W 2 "$2" >/dev/null 2>&1
}
# share_decide TEXT: 0 applied (or unchanged), 1 refused (use the
# fallback), 2 valid but not applied (logged; the previous state stays).
share_decide() {
  local text="$1" up="" des="" bk="" n=${#SH_NAME[@]} i=0 args=() f first=1
  while read -r -a f; do
    if [ "$first" = 1 ]; then
      [ "${f[*]:-}" = "meridian-pathq 1" ] || return 1
      first=0
      continue
    fi
    case "${f[0]:-}" in
      upstream) up="${f[1]:-}" ;;
      designated) des="${f[1]:-}" ;;
      relay)
        [ "$i" -lt "$n" ] && [ "${f[1]:-}" = "${SH_NAME[$i]}" ] && [ "${#f[@]}" -eq 5 ] || return 1
        args+=("${f[2]}" "${f[3]}" "${f[4]}")
        i=$((i + 1))
        ;;
      backup) bk="${f[1]:-}" ;;
      end) ;;
      *) return 1 ;;
    esac
  done <<< "$text"
  [ "$first" = 0 ] && [ "$i" -eq "$n" ] && [ -n "$up" ] && [ -n "$des" ] && [ -n "$bk" ] || return 1
  share_once "$up $des ${args[*]} $bk" "$up" "$des" "${args[@]}" "$bk" || return $?
  for ((i = 0; i < n; i++)); do
    SH_R_LEG[$i]="${args[$((3 * i))]}"
    SH_R_W[$i]="${args[$((3 * i + 1))]}"
  done
  share_load_applied
  return $?
}
share_fallback_candidate() {
  local n=${#SH_NAME[@]} i l alive now cnt=0 bk_alive=0 up des state=ok w args=() share rest first=-1
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
        if [ "${fb_goods[$i]}" -ge "$RECOVERS_NEED" ]; then fb_in[$i]=1; fb_goods[$i]=0; fi
      fi
    else
      SH_R_GRADE[$i]=down; fb_goods[$i]=0
      if [ "${fb_in[$i]}" = 1 ]; then
        fb_fails[$i]=$((fb_fails[$i] + 1))
        if [ "${fb_fails[$i]}" -ge "$FAILS_NEED" ]; then fb_in[$i]=0; fb_fails[$i]=0; fi
      fi
    fi
    if [ "${fb_in[$i]}" = 1 ]; then cnt=$((cnt + 1)); SH_R_STATUS[$i]=active; SH_R_REASON[$i]=-; else SH_R_STATUS[$i]=evicted; SH_R_REASON[$i]=down; fi
  done
  # The speed tests' saved verdict decides which of the reachable relays
  # carry (share_qos_select); throttling never decides the backup hub.
  share_qos_read
  SH_BK_GRADE=none
  if [ -n "$SH_BK_IFACE" ]; then
    if share_alive "$SH_BK_IFACE" "$SH_BK_PROBE"; then bk_alive=1; SH_BK_GRADE=good; else SH_BK_GRADE=down; fi
  fi
  up="$fb_up"
  if [ "$up" = main ] && [ "$cnt" -eq 0 ] && [ "$bk_alive" = 1 ]; then
    up=backup
  elif [ "$up" = backup ] && [ "$cnt" -gt 0 ] && { [ "$fb_switched" -eq 0 ] || [ $((now - fb_switched)) -ge "$COOLDOWN" ]; }; then
    up=main
  fi
  if [ "$up" != "$fb_up" ]; then fb_switched=$now; fb_since=$now; fi
  fb_up="$up"
  # Equal weights over the relays in; none in: equal over all (the traffic
  # is dropped in the tunnels either way).
  local sel=() m=0
  for ((i = 0; i < n; i++)); do
    sel[$i]="${fb_in[$i]}"
  done
  share_qos_select
  for ((i = 0; i < n; i++)); do
    [ "${sel[$i]}" = 1 ] && m=$((m + 1))
  done
  if [ "$m" -eq 0 ]; then
    for ((i = 0; i < n; i++)); do sel[$i]=1; done
    m=$n
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
  fb_des="${SH_NAME[$first]}"
  des="$fb_des"
  if [ "$up" = backup ]; then
    des=backup
    [ "$bk_alive" = 1 ] || state=down
  elif [ "$cnt" -eq 0 ]; then
    state=down
  fi
  for ((i = 0; i < n; i++)); do
    w="${SH_R_W[$i]}"
    [ "$up" = backup ] && w=0
    args+=("${SH_R_LEG[$i]}" "$w" 0)
  done
  share_candidate || return 4
  ( UP_STATE="$SH_CANDIDATE/status"; share_record "$state" shell "$up" "$des" "$fb_since" "$fb_switched" controller_unavailable ) || return 4
  share_once "$up $des ${args[*]} 0" "$up" "$des" "${args[@]}" 0 || return $?

}
# share_qos_read: the speed tests' verdict file into SH_R_QOS/SPEED/SPAT/
# BASE/BSRC and QOS_T (1: throttled and fresh). The same grammar as
# pathquality.ParseQoS: any deviation ignores the whole file (no relay is
# then throttled). Only the file is read; nothing is measured or inferred.
share_qos_read() {
  local n=${#SH_NAME[@]} i v line now done=0 f
  local tq=() ts=() tk=() ta=() tb=() tr=()
  SH_R_QOS=(); SH_R_SPEED=(); SH_R_SPAT=(); SH_R_BASE=(); SH_R_BSRC=(); QOS_T=()
  for ((i = 0; i < n; i++)); do SH_R_QOS[$i]=$SH_QOS_DEF; SH_R_SPEED[$i]=-; SH_R_SPAT[$i]=0; SH_R_BASE[$i]=0; SH_R_BSRC[$i]=-; QOS_T[$i]=0; done
  [ "$SH_QOS_ON" = 1 ] && [ -f "$QOS_FILE" ] || return 0
  i=-1
  while IFS= read -r line; do
    if [ "$i" -lt 0 ]; then [ "$line" = "meridian-qos 1" ] || return 0; i=0; continue; fi
    if [ "$line" = end ]; then [ "$i" -eq "$n" ] && done=1; break; fi
    read -r -a f <<< "$line"
    [ "$i" -lt "$n" ] && [ "${#f[@]}" -eq 8 ] && [ "${f[0]}" = relay ] && [ "${f[1]}" = "${SH_NAME[$i]}" ] || return 0
    case "${f[2]}" in ok|throttled|unknown) ;; *) return 0 ;; esac
    case "${f[7]}" in nominal|p90) ;; *) return 0 ;; esac
    for v in "${f[3]}" "${f[5]}" "${f[6]}"; do case "$v" in ''|*[!0-9]*) return 0 ;; esac; done
    case "${f[4]}" in -) ;; ''|*[!0-9]*) return 0 ;; esac
    tq[$i]="${f[2]}"; tk[$i]="${f[4]}"; ta[$i]="${f[5]}"; tb[$i]="${f[6]}"; tr[$i]="${f[7]}"
    i=$((i + 1))
  done < "$QOS_FILE"
  [ "$done" = 1 ] || return 0
  now=$(date +%s)
  for ((i = 0; i < n; i++)); do
    SH_R_QOS[$i]="${tq[$i]}"; SH_R_SPEED[$i]="${tk[$i]}"; SH_R_SPAT[$i]="${ta[$i]}"; SH_R_BASE[$i]="${tb[$i]}"; SH_R_BSRC[$i]="${tr[$i]}"
    if [ "${tq[$i]}" = throttled ]; then
      if [ "${ta[$i]}" -gt 0 ] && [ $((now - ta[$i])) -le "$QOS_MAX_AGE" ]; then QOS_T[$i]=1; else SH_R_QOS[$i]=unknown; fi
    fi
  done
}
# share_qos_select: among the selected (reachable) relays, the throttled
# ones carry nothing while another carries; when all of them are throttled
# only the one with the best last test carries (ties: the first).
share_qos_select() {
  local n=${#SH_NAME[@]} i k=0 best=-1 bk=-1 sp
  for ((i = 0; i < n; i++)); do
    [ "${sel[$i]}" = 1 ] || continue
    if [ "${QOS_T[$i]:-0}" = 0 ]; then k=$((k + 1)); fi
  done
  for ((i = 0; i < n; i++)); do
    [ "${sel[$i]}" = 1 ] && [ "${QOS_T[$i]:-0}" = 1 ] || continue
    sp="${SH_R_SPEED[$i]}"; [ "$sp" != - ] || sp=0
    if [ "$k" -eq 0 ] && [ "$sp" -gt "$bk" ]; then best=$i; bk=$sp; fi
  done
  for ((i = 0; i < n; i++)); do
    [ "${sel[$i]}" = 1 ] && [ "${QOS_T[$i]:-0}" = 1 ] || continue
    if [ "$i" = "$best" ]; then
      SH_R_STATUS[$i]=reduced; SH_R_REASON[$i]=retained_best
    else
      sel[$i]=0; SH_R_STATUS[$i]=reduced; SH_R_REASON[$i]=qos_throttled
    fi
  done
}
# share_speedtest_kick: one background run of the speed tests (at most one
# test per run, under the controller's lock; nothing due: it exits at once).
share_speedtest_kick() {
  [ "$SH_QOS_ON" = 1 ] || return 0
  ( MERIDIAN_BIND=- timeout 120 "$MERIDIAN_BIN" path-speedtest --config "$PQ_CONFIG" --state "$PQ_STATE" >/dev/null 2>&1 & )
}
share_fallback_step() {
  # A failed switch changes no fallback state: carrying decision, times and
  # the eviction/recovery counters all return to their values before it.
  local s_up="$fb_up" s_des="$fb_des" s_since="$fb_since" s_sw="$fb_switched"
  local s_in=("${fb_in[@]}") s_goods=("${fb_goods[@]}") s_fails=("${fb_fails[@]}")
  local s_leg=("${SH_R_LEG[@]}") s_w=("${SH_R_W[@]}") s_st=("${SH_R_STATUS[@]}") s_re=("${SH_R_REASON[@]}") s_gr=("${SH_R_GRADE[@]}")
  share_fallback_candidate
  local rc=$?
  if [ "$rc" -eq 0 ]; then read -r SH_LOADED < "$SH_TXN/current" || return 4; return 0; fi
  fb_up="$s_up"; fb_des="$s_des"; fb_since="$s_since"; fb_switched="$s_sw"
  fb_in=("${s_in[@]}"); fb_goods=("${s_goods[@]}"); fb_fails=("${s_fails[@]}")
  SH_R_LEG=("${s_leg[@]}"); SH_R_W=("${s_w[@]}"); SH_R_STATUS=("${s_st[@]}"); SH_R_REASON=("${s_re[@]}"); SH_R_GRADE=("${s_gr[@]}")
  return "$rc"
}
share_load_applied() {
  local generation key value rest i prev="$fb_up"
  [ -f "$SH_TXN/current" ] || return 0
  read -r generation < "$SH_TXN/current" || return 4
  case "$generation" in *[!A-Za-z0-9-]*|'') return 4 ;; snapshot-*) ;; *) return 4 ;; esac
  [ "${SH_LOADED:-}" != "$generation" ] || return 0
  [ "$(cat "$SH_TXN/$generation/version")" = "$SH_VERSION" ] || return 4
  while read -r key value rest; do
    case "$key" in
      path) fb_up="$value" ;;
      designated) fb_des="$value" ;;
      since) fb_since="$value" ;;
      switched) fb_switched="$value" ;;
      relay)
        i=$(share_index "$value") || return 4
        read -r "SH_R_LEG[$i]" "SH_R_STATUS[$i]" "SH_R_W[$i]" rest <<< "$rest"
        # Only the carrying group's membership is known from an applied
        # record; other relays keep the fallback's own liveness history.
        if [ main = "$fb_up" ]; then
          fb_fails[$i]=0; fb_goods[$i]=0; fb_in[$i]=0
          [ "${SH_R_W[$i]}" -eq 0 ] || fb_in[$i]=1
        elif [ "$fb_up" = backup ]; then
          fb_fails[$i]=0; fb_goods[$i]=0; fb_in[$i]=0
        fi
        ;;
    esac
  done < "$SH_TXN/$generation/status"
  if [ "$prev" != "$fb_up" ]; then
    for ((i = 0; i < ${#SH_NAME[@]}; i++)); do fb_fails[$i]=0; fb_goods[$i]=0; done
  fi
  SH_LOADED="$generation"
}
share_step_locked() {
  local out rc extra=()
  [ ! -e "$SH_TXN/pending" ] || [ -e "$SH_TXN/blocked" ] || share_finish_pending || true
  if [ -e "$SH_TXN/blocked" ] || [ -e "$SH_TXN/pending" ]; then
    share_guard_on || return 4
    rm -f "$SH_APPLIED"
    touch "$SH_TXN/blocked"
    share_error recovery_blocked down
    return 4
  fi
  share_load_applied || { share_guard_on; rm -f "$SH_APPLIED"; touch "$SH_TXN/blocked"; share_error config_changed down; return 4; }
  # Compensated failure: hold the last successful path, no new mutation.
  if share_held; then return 5; fi
  [ -z "${PQ_NOW:-}" ] || extra=(--now "$PQ_NOW")
  share_candidate || return 4
  if out=$(MERIDIAN_BIND=- timeout 25 "$MERIDIAN_BIN" path-step --config "$PQ_CONFIG" --state "$PQ_STATE" --status "$UP_STATE" --candidate "$SH_CANDIDATE" ${extra[@]+"${extra[@]}"}); then
    share_decide "$out"
    rc=$?
    [ "$rc" -eq 1 ] || { share_drop_candidate; return "$rc"; }
    echo "path-step decision refused; this pass uses the fallback" >&2
  fi
  rm -rf "$SH_CANDIDATE"
  share_fallback_step
}
share_step() {
  share_lock || return $?
  local SH_LOCKED=1 rc
  share_step_locked; rc=$?
  flock -u 8
  exec 8>&-
  return "$rc"
}
# --- main loop ---
mkdir -p "${SH_APPLIED%/*}"
SH_PASS=0
while true; do
  share_step
  SH_PASS=$((SH_PASS + 1))
  if [ $((SH_PASS % 12)) -eq 1 ]; then share_speedtest_kick; fi
  sleep "$INTERVAL"
done
`

// ingressReturn is one west tunnel of a relay (a gateway leg) or of the
// primary hub (a relay tunnel) with relay sharing.
type ingressReturn struct {
	Iface string
	From  string
	Mark  uint32
	Table int
	Prio  int
}

// maxIngressReturns bounds the tables (174..197) and marks per node.
const maxIngressReturns = 24

// ingressReturns lists the west tunnels whose connections must get their
// replies back on the same tunnel: on a sharing relay its legs from the
// gateway, on the primary hub its tunnels from the relays. Nil without
// relay sharing (or on any other node).
func ingressReturns(t model.Topology, n model.Node, tunnels []Tunnel) []ingressReturn {
	if !t.RelaySharing() && !hubFailoverWest(t, n, tunnels) {
		return nil
	}
	if n.Role == model.RoleHub && n.ID != primaryHubID(t) && !backupGroupHub(t, n) {
		return nil
	}
	var out []ingressReturn
	seen := map[string]bool{}
	for _, tun := range tunnels {
		if tun.East.ID != n.ID {
			continue
		}
		switch {
		case n.Role == model.RoleRelay && tun.West.Role == model.RoleGateway && !tun.Standby:
		case n.Role == model.RoleHub && n.ID == primaryHubID(t) && tun.West.Role == model.RoleRelay,
			backupGroupHub(t, n) && tun.West.Role == model.RoleRelay:
			// Standby relay→hub tunnels too: a relay's own failover may
			// move its east side onto one.
		default:
			continue
		}
		if seen[tun.Iface()] || len(out) == maxIngressReturns {
			continue
		}
		seen[tun.Iface()] = true
		j := len(out)
		out = append(out, ingressReturn{Iface: tun.Iface(), From: tun.West.ID, Mark: markIngressBase + uint32(j), Table: tableIngressBase + j, Prio: prioIngress + j})
	}
	return out
}

// hubFailoverWest: n is the primary hub and a relay reaches it over a
// udp_wss_failover link. The relay alone picks the leg (its failover), so
// the hub answers on the leg a connection arrived on — the same ingress
// marks as relay sharing — whether or not several relays share.
func hubFailoverWest(t model.Topology, n model.Node, tunnels []Tunnel) bool {
	if n.Role != model.RoleHub || n.ID != primaryHubID(t) {
		return false
	}
	for _, tun := range tunnels {
		if tun.East.ID == n.ID && relayHubCompanion(tun) {
			return true
		}
	}
	return false
}

// renderIngressReturnRoutes installs one table per west tunnel: the home
// prefixes (the LAN, 10.66.0.0/16 with the transit and tunnel addresses,
// fd66::/48, the LAN IPv6 prefix) on that tunnel over a blackhole, and the
// fwmark rule that selects it.
func renderIngressReturnRoutes(sb *strings.Builder, t model.Topology, rets []ingressReturn) {
	sb.WriteString("# ingress return paths (relay sharing): a reply leaves through the tunnel its connection arrived on\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "# from %s: mark %#x table %d dev %s\n", r.From, r.Mark, r.Table, r.Iface)
		fmt.Fprintf(sb, "ip route replace %s dev %s table %d\n", lanNet(t), r.Iface, r.Table)
		fmt.Fprintf(sb, "ip route replace 10.66.0.0/16 dev %s table %d\n", r.Iface, r.Table)
		fmt.Fprintf(sb, "ip -6 route replace fd66::/48 dev %s table %d\n", r.Iface, r.Table)
		if t.Settings.LANIPv6Prefix != "" {
			fmt.Fprintf(sb, "ip -6 route replace %s dev %s table %d\n", t.Settings.LANIPv6Prefix, r.Iface, r.Table)
		}
		fmt.Fprintf(sb, "ip route replace blackhole default metric 32767 table %d\n", r.Table)
		fmt.Fprintf(sb, "ip -6 route replace blackhole default metric 32767 table %d\n", r.Table)
		fmt.Fprintf(sb, "del_rule ip rule del fwmark %#x lookup %d\n", r.Mark, r.Table)
		fmt.Fprintf(sb, "ip rule add fwmark %#x lookup %d priority %d\n", r.Mark, r.Table, r.Prio)
		fmt.Fprintf(sb, "del_rule ip -6 rule del fwmark %#x lookup %d\n", r.Mark, r.Table)
		fmt.Fprintf(sb, "ip -6 rule add fwmark %#x lookup %d priority %d\n", r.Mark, r.Table, r.Prio)
	}
}

// writeIngressReturnNFT: the connection mark by west tunnel (every
// original-direction packet, so a connection the gateway moved to another
// leg follows it) and its restoration onto every reply packet, forwarded
// (prerouting) and local (output, rerouted by the route hook: the hub's
// answers to the gateway's end-to-end probes).
func writeIngressReturnNFT(sb *strings.Builder, rets []ingressReturn) {
	sb.WriteString("  chain ingress_return_in {\n    type filter hook prerouting priority mangle; policy accept;\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "    iifname \"%s\" ct direction original ct mark set %#x comment \"arrived from %s\"\n", r.Iface, r.Mark, verifyLabel(r.From))
	}
	for _, r := range rets {
		fmt.Fprintf(sb, "    ct direction reply ct mark %#x meta mark set %#x comment \"reply: back into %s\"\n", r.Mark, r.Mark, r.Iface)
	}
	sb.WriteString("  }\n  chain ingress_return_out {\n    type route hook output priority mangle; policy accept;\n")
	for _, r := range rets {
		fmt.Fprintf(sb, "    ct direction reply ct mark %#x meta mark set %#x comment \"local reply: back into %s\"\n", r.Mark, r.Mark, r.Iface)
	}
	sb.WriteString("  }\n")
}

func writeShareRTTables(sb *strings.Builder, t model.Topology) {
	tunnels, err := buildTunnels(t)
	if err != nil {
		return
	}
	p := planShare(t, tunnels)
	if p == nil {
		return
	}
	if p.Backup != nil {
		fmt.Fprintf(sb, "%d\tmeridian_share_backup\n", p.Backup.Table)
	}
	for _, r := range p.Relays {
		fmt.Fprintf(sb, "%d\tmeridian_share_r%d\n", r.Table, r.Index)
	}
}

// backupGroupHub: n is the backup hub reached through the backup group:
// like the primary hub, it answers each connection on the relay tunnel it
// arrived on (several relays, each with its own tunnel).
func backupGroupHub(t model.Topology, n model.Node) bool {
	if n.Role != model.RoleHub || !t.RelayBackup() {
		return false
	}
	b, _ := t.BackupHub()
	return n.ID == b.ID
}

func ingressReturnsFor(t model.Topology, n model.Node) []ingressReturn {
	if !t.RelaySharing() && !(n.Role == model.RoleHub && n.ID == primaryHubID(t)) {
		return nil
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil
	}
	return ingressReturns(t, n, tunnels)
}

// Explicit installation is the only automatic path allowed to clear a latched
// switch error. Its guard and lock begin before any base nft/routes change.
func shareInstallBegin(p *sharePlan) string {
	return sharePrelude(p) + `if [ "${MERIDIAN_SHARE_PARENT:-0}" != 1 ]; then share_lock || exit $?; fi
SH_LOCKED=1
printf '%s\n' "$SH_VERSION" > "$SH_TXN/pending"
rm -f "$SH_APPLIED"
share_guard_on || exit 4
trap 'touch "$SH_TXN/blocked"; share_error install_failed down' ERR
`
}
func shareInstallFinish(p *sharePlan) string {
	var sb strings.Builder
	sb.WriteString("share_candidate\n")
	fmt.Fprintf(&sb, "( UP_STATE=\"$SH_CANDIDATE/status\"; share_record static shell main %s \"$(date +%%s)\" 0 - )\n", shQuote(p.Relays[0].Node.ID))
	fmt.Fprintf(&sb, "SH_INSTALL=1 share_apply main %s", shQuote(p.Relays[0].Node.ID))
	for i, r := range p.Relays {
		fmt.Fprintf(&sb, " %s %d 0", shQuote(r.Legs[0].Iface()), initialWeights(p)[i])
	}
	sb.WriteString(" 0\ntrap - ERR\n")
	return sb.String()
}
