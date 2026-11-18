package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// The gateway's upstream path with a backup hub
// (docs/architecture.md「主枢纽与备用枢纽」).
//
// planUpstream is the one place that decides which ways out of table 102
// exist, in which order, through which interface and to which hub, and how
// each is checked. upstreamPrelude turns it into shell (UP_* arrays,
// upstream_apply, upstream_record) that the static routes script and the
// failover script both carry byte for byte: the install points table 102 at
// the first path with upstream_apply, and the failover loop moves it with
// the same function, so static install and dynamic switching cannot
// disagree about the route, and nothing else changes table 102. A later
// version (several relays sharing the main path) extends planUpstream; the
// shell keeps a single entry point.
//
// The main path is checked end to end: through each relay leg the gateway
// pings the primary hub's address on the relay→hub tunnel, from a dedicated
// transit address (upstreamProbeSrc) the hub routes back home. A relay that
// is up while the IX behind it is not therefore counts as down. The backup
// path is checked by pinging the backup hub's tunnel address. Only when no
// main leg answers does the gateway move to the backup hub; it returns once
// a main leg answers again for RECOVERS_NEED passes and COOLDOWN has passed
// since the last switch. When nothing answers, table 102 stays where it is:
// every path is a WireGuard interface over a blackhole floor, so traffic
// is dropped, never routed out of the LAN NIC (the guard admits exit marks
// only on the gateway's tunnels).

// upstreamProbeSrc is the gateway's source address for the end-to-end main
// path check: a transit address no exit or group uses (those start at
// 10.66.200.10), on lo; the primary hub routes the transit /24 home.
const upstreamProbeSrc = "10.66.200.2"

// UpstreamStateFile is where the gateway records the path in use (read by
// meridian-host's fixed upstream status read, hostexec.UpstreamStatus).
const UpstreamStateFile = "/run/meridian/upstream"

// upstreamPath is one way out of table 102.
type upstreamPath struct {
	Name  string // udp | wss (main path legs) | backup
	Iface string
	// Probe is the address pinged through Iface (ping -I) to call the path
	// usable; ProbeVia is set when Probe is beyond the tunnel peer and needs
	// a host route on Iface with source upstreamProbeSrc.
	Probe    string
	ProbeVia bool
	Hub      string
	Tier     model.HubTier
}

type upstreamPlan struct {
	Paths []upstreamPath
}

// planUpstream lists the gateway's paths in preference order: the main
// path legs toward the relay (UDP, then WSS), then the backup hub.
func planUpstream(t model.Topology, tunnels []Tunnel) upstreamPlan {
	primary, _ := t.PrimaryHub()
	backup, _ := t.BackupHub()
	var plan upstreamPlan
	hubPeer := hubWestTunnel(tunnels, primary.ID, false).EastV4
	var udp, wss, other []Tunnel
	for _, tun := range tunnels {
		if tun.West.Role != model.RoleGateway || tun.East.Role != model.RoleRelay || tun.Standby {
			continue
		}
		switch {
		case tun.Mode == "udp":
			udp = append(udp, tun)
		case tun.Mode == "wss":
			wss = append(wss, tun)
		default:
			other = append(other, tun)
		}
	}
	for _, tun := range append(append(udp, wss...), other...) {
		plan.Paths = append(plan.Paths, upstreamPath{Name: tun.Mode, Iface: tun.Iface(), Probe: hubPeer, ProbeVia: true, Hub: primary.ID, Tier: model.HubPrimary})
	}
	for _, tun := range tunnels {
		if tun.West.Role == model.RoleGateway && tun.East.ID == backup.ID && backup.ID != "" && tun.Transport == model.TransportIXReplacementWSS {
			plan.Paths = append(plan.Paths, upstreamPath{Name: "backup", Iface: tun.Iface(), Probe: tun.EastV4, Hub: backup.ID, Tier: model.HubBackup})
			break
		}
	}
	return plan
}

// first is the path the install starts on.
func (p upstreamPlan) first() upstreamPath {
	if len(p.Paths) == 0 {
		return upstreamPath{}
	}
	return p.Paths[0]
}

// upstreamPrelude is shared by the gateway's routes and failover scripts.
func upstreamPrelude(p upstreamPlan) string {
	var names, ifaces, probes, hubs, tiers []string
	for _, u := range p.Paths {
		names = append(names, shQuote(u.Name))
		ifaces = append(ifaces, shQuote(u.Iface))
		probes = append(probes, shQuote(u.Probe))
		hubs = append(hubs, shQuote(u.Hub))
		tiers = append(tiers, shQuote(string(u.Tier)))
	}
	var sb strings.Builder
	sb.WriteString("# upstream paths in preference order (compile.planUpstream); only upstream_apply moves table 102\n")
	fmt.Fprintf(&sb, "UP_NAME=(%s)\nUP_IFACE=(%s)\nUP_PROBE=(%s)\nUP_HUB=(%s)\nUP_TIER=(%s)\n",
		strings.Join(names, " "), strings.Join(ifaces, " "), strings.Join(probes, " "), strings.Join(hubs, " "), strings.Join(tiers, " "))
	fmt.Fprintf(&sb, "UP_STATE=%s\n", UpstreamStateFile)
	sb.WriteString(upstreamShell)
	return sb.String()
}

const upstreamShell = `upstream_index() {
  local i
  for ((i = 0; i < ${#UP_NAME[@]}; i++)); do
    if [ "${UP_NAME[$i]}" = "$1" ]; then echo "$i"; return 0; fi
  done
  return 1
}
upstream_apply() {
  local i iface
  if ! i=$(upstream_index "$1"); then
    echo "upstream path $1 refused: not a compiled path" >&2
    return 1
  fi
  iface="${UP_IFACE[$i]}"
  [ -n "$iface" ] || return 1
  ip route replace default dev "$iface" table 102
  ip route replace blackhole default metric 32767 table 102
  ip -6 route replace default dev "$iface" table 102
  ip -6 route replace blackhole default metric 32767 table 102
  ip route replace 10.66.0.0/16 dev "$iface"
  ip route replace blackhole 10.66.0.0/16 metric 32767
  ip -6 route replace fd66::/48 dev "$iface"
  ip -6 route replace blackhole fd66::/48 metric 32767
}
upstream_record() {
  local i tmp
  i=$(upstream_index "$1") || return 0
  mkdir -p "${UP_STATE%/*}"
  tmp="${UP_STATE%/*}/.upstream.$$"
  {
    echo "meridian-upstream 1"
    echo "beat $(date +%s)"
    echo "path $1"
    echo "iface ${UP_IFACE[$i]}"
    echo "hub ${UP_HUB[$i]}"
    echo "tier ${UP_TIER[$i]}"
    echo "since $2"
    echo "state $3"
    echo "end"
  } > "$tmp" && mv -f "$tmp" "$UP_STATE" || rm -f "$tmp"
  return 0
}
`

// renderUpstreamRoutes is the dual-hub replacement of the gateway's static
// table 102 and tunnel-prefix routes: the shared prelude, the probe source
// and host routes, the first path, and a "static" record (the failover
// loop overwrites it with what it measures).
func renderUpstreamRoutes(sb *strings.Builder, p upstreamPlan) {
	sb.WriteString(upstreamPrelude(p))
	fmt.Fprintf(sb, "ip addr replace %s/32 dev lo\n", upstreamProbeSrc)
	metric := 10
	for _, u := range p.Paths {
		if !u.ProbeVia || u.Probe == "" || u.Iface == "" {
			continue
		}
		// Only ping -I <iface> uses these (a socket bound to the interface
		// finds the route of its interface): the end-to-end check of each
		// main leg, from the probe source the primary hub routes home.
		fmt.Fprintf(sb, "ip route replace %s/32 dev %s src %s metric %d\n", u.Probe, u.Iface, upstreamProbeSrc, metric)
		metric++
	}
	first := p.first()
	fmt.Fprintf(sb, "# meridian-upstream-first: %s %s hub %s\n", first.Name, first.Iface, first.Hub)
	fmt.Fprintf(sb, "upstream_apply %s\n", shQuote(first.Name))
	fmt.Fprintf(sb, "upstream_record %s \"$(date +%%s)\" static\n", shQuote(first.Name))
}

func renderGatewayFailoverDual(p upstreamPlan) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Main path (gateway -> relay -> IX -> primary hub) first, checked end to end;\n")
	sb.WriteString("# the backup hub (WG over WSS) only while no main leg answers. Mesh is not a candidate.\n")
	sb.WriteString("# Leaving a dead path needs FAILS_NEED passes; returning to a better one needs\n")
	sb.WriteString("# RECOVERS_NEED passes and COOLDOWN seconds since the last switch. Nothing answering:\n")
	sb.WriteString("# table 102 stays (tunnel or blackhole only, never the LAN NIC).\n")
	sb.WriteString("set -u\n")
	sb.WriteString(upstreamPrelude(p))
	sb.WriteString("FAILS_NEED=3\nRECOVERS_NEED=5\nCOOLDOWN=120\n")
	sb.WriteString(failoverLoopGatewayDual)
	return sb.String()
}

const failoverLoopGatewayDual = `alive() {
  local iface="$1" peer="$2"
  [ -n "$iface" ] && [ -n "$peer" ] || return 1
  ping -I "$iface" -c 1 -W 2 -n "$peer" >/dev/null 2>&1
}
pick() {
  local i
  for ((i = 0; i < ${#UP_NAME[@]}; i++)); do
    if alive "${UP_IFACE[$i]}" "${UP_PROBE[$i]}"; then echo "${UP_NAME[$i]}"; return; fi
  done
  echo none
}
# One pass: cur, since, bad and last_switch carry the state between passes.
upstream_step() {
  local want now wi ci ready
  want=$(pick)
  now=$(date +%s)
  if [ "$want" = none ]; then
    bad=0
    upstream_record "$cur" "$since" down
    return 0
  fi
  if [ "$want" = "$cur" ]; then
    bad=0
    upstream_record "$cur" "$since" ok
    return 0
  fi
  bad=$((bad+1))
  wi=$(upstream_index "$want")
  ci=$(upstream_index "$cur")
  ready=0
  if [ "$wi" -lt "$ci" ]; then
    # A better path answers again: RECOVERS_NEED passes and the cooldown.
    if [ "$bad" -ge "$RECOVERS_NEED" ] && { [ "$last_switch" -eq 0 ] || [ $((now-last_switch)) -ge "$COOLDOWN" ]; }; then ready=1; fi
  elif [ "$bad" -ge "$FAILS_NEED" ]; then
    # The current path does not answer: leave it after FAILS_NEED passes.
    ready=1
  fi
  if [ "$ready" = 1 ]; then
    if upstream_apply "$want"; then
      cur="$want"
      since=$now
      last_switch=$now
    fi
    bad=0
  fi
  upstream_record "$cur" "$since" switching
}
cur="${UP_NAME[0]}"
since=$(date +%s)
bad=0
last_switch=0
# --- main loop ---
mkdir -p /run/meridian
upstream_apply "$cur" || true
while true; do
  upstream_step
  sleep 5
done
`
