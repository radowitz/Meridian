package compile

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

// MeshQualityPlanID binds the read-only reports to the current legs and policy
// of the primary hub (see MeshQualityPlanIDForHub).
func MeshQualityPlanID(t model.Topology) string {
	return MeshQualityPlanIDForHub(t, primaryHubID(t))
}

// MeshQualityPlanIDForHub is the MQ_PLAN the given hub's failover loop runs:
// each hub selects between its own direct and Mesh legs to an exit, so the
// backup hub's plan names its own interfaces and differs from the primary's.
func MeshQualityPlanIDForHub(t model.Topology, hub string) string {
	ts, err := buildTunnels(t)
	if err != nil {
		return ""
	}
	return meshQualityID(t, planExitsHub(t, ts, hub))
}
func meshQualityID(t model.Topology, exits []ExitPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%+v", meshPlanSettings(t.Settings.PathQuality.Effective()))
	for _, e := range exits {
		if e.MeshIface != "" {
			fmt.Fprintf(&b, "%s/%s/%s/%s/%s/%d/%s", e.Node.ID, e.HubIface, e.PeerV4, e.MeshIface, e.MeshPeerV4, e.Table, e.Resolver)
			target, ds, ms := meshDNSRoute(t, e)
			fmt.Fprintf(&b, "/dns/%s/%s/%s", target, ds, ms)
		}
	}
	b.WriteString(meshQualityShell)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(b.String())))[:24]
}

// meshDNSRoute selects the address actually queried by unmarked SmartDNS.
// A leg-local hub ULA is accepted by the exit's WireGuard AllowedIPs and
// returns through its existing conntrack-marked local-output route.
func meshDNSRoute(t model.Topology, e ExitPlan) (target, directSrc, meshSrc string) {
	if t.DualHub() {
		return e.Resolver, "", ""
	}
	ts, _ := buildTunnels(t)
	for _, tun := range ts {
		if tun.Iface() == e.HubIface {
			directSrc = tun.WestULA
		}
		if tun.Iface() == e.MeshIface {
			meshSrc = tun.WestULA
		}
	}
	return e.DNSULA, directSrc, meshSrc
}

func renderMeshQuality(t model.Topology, exits []ExitPlan) string {
	var b strings.Builder
	p := t.Settings.PathQuality.Effective()
	fmt.Fprintf(&b, "MQ_PLAN=%s\nMQ_WINDOW=%d\nMQ_LOSS=%d\nMQ_RTT=%d\nMQ_RETURN=%d\nMQ_DWELL=%d\nMQ_ADV=%d\n", meshQualityID(t, exits), pathquality.MeshWindow(p), p.PoorLossPermille, p.PoorRTTMS, p.ReturnAfterSec, p.MinDwellSec, p.SwitchAdvantagePct)
	b.WriteString(meshQualityShell)
	b.WriteString("mesh_managed() {\n case \"$1\" in\n")
	for _, e := range exits {
		if e.MeshIface != "" {
			fmt.Fprintf(&b, " %s) return 0 ;;\n", shQuote(e.Node.ID))
		}
	}
	b.WriteString(" *) return 1 ;;\n esac\n}\nmesh_member_alive() {\n local id=\"$1\" iface=\"$2\" peer=\"$3\" gid=\"$4\" target=\"$5\" active\n if mesh_managed \"$id\"; then\n  [ \"$(mesh_selected \"$iface\")\" != blackhole ] && return 0\n  active=$(cat \"/run/meridian/group/$gid/active\" 2>/dev/null || echo \"$target\")\n  [ \"$active\" = \"$id\" ]; return\n fi\n alive \"$iface\" \"$peer\"\n}\nmesh_selected() {\n case \"$1\" in\n")
	for _, e := range exits {
		if e.MeshIface != "" {
			fmt.Fprintf(&b, " %s|%s) cat /run/meridian/exit-legs/%s/iface 2>/dev/null || echo blackhole ;;\n", shQuote(e.HubIface), shQuote(e.MeshIface), e.Node.ID)
		}
	}
	b.WriteString(" *) echo \"$1\" ;;\n esac\n}\ncheck_mesh_legs() {\n local -a mq_jobs=()\n local mq_pid\n mkdir -p /run/meridian/exit-legs\n")
	for _, e := range exits {
		if e.MeshIface != "" {
			direct, probe := e.HubIface, e.PeerV4
			if e.MeshSole {
				direct = ""
				probe = ""
			}
			target, directSrc, meshSrc := meshDNSRoute(t, e)
			fmt.Fprintf(&b, " mesh_leg_step %s %d %s %s %s %s %s %s %s &\n mq_jobs+=(\"$!\")\n if [ ${#mq_jobs[@]} -ge 8 ]; then for mq_pid in \"${mq_jobs[@]}\"; do wait \"$mq_pid\" || true; done; mq_jobs=(); fi\n", shQuote(e.Node.ID), e.Table, shQuote(direct), shQuote(probe), shQuote(e.MeshIface), shQuote(e.MeshPeerV4), shQuote(target), shQuote(directSrc), shQuote(meshSrc))
		}
	}
	b.WriteString(" for mq_pid in \"${mq_jobs[@]}\"; do wait \"$mq_pid\" || true; done\n {\n")
	for _, e := range exits {
		if e.MeshIface != "" {
			fmt.Fprintf(&b, " cat %s %s\n", shQuote("/run/meridian/exit-legs/"+e.Node.ID+"/report"), shQuote("/run/meridian/exit-legs/"+e.Node.ID+"/events"))
		}
	}
	b.WriteString(" } 2>/dev/null > /run/meridian/exit-legs/report.tmp\n mv -f /run/meridian/exit-legs/report.tmp /run/meridian/exit-legs/report\n}\n")
	return b.String()
}

// Shell runs on remote hubs without requiring an extra binary. Five small
// echoes use the same burst and parser semantics as pathquality.Measurer.
// All route tables, interfaces and peers are compiler constants. The selected
// device can only be one of this exit's two legs, or blackhole.
const meshQualityShell = `
mesh_sample() {
 local iface="$1" peer="$2" file="$3" out
 if [ -z "$iface" ]; then echo '5 0 0' > "$file"; return; fi
 out=$(LC_ALL=C ping -n -q -I "$iface" -c 5 -i 0.2 -W 1 -w 3 "$peer" 2>/dev/null || true)
 awk '/packets transmitted/ {s=$1;r=$4} /min\/avg\/max/ {split($4,a,"/"); ms=int(a[2])} END {if(s<1)s=5; print s,r+0,ms+0}' <<< "$out" > "$file"
}
mesh_route() {
 local table="$1" dev="$2" fam failed=0
 for fam in -4 -6; do
  ip "$fam" route replace blackhole default metric 32767 table "$table" || failed=1
  if [ "$dev" = blackhole ]; then
   ip "$fam" route replace blackhole default table "$table" || failed=1
  else
   ip "$fam" route replace default dev "$dev" table "$table" || failed=1
  fi
 done
 if [ "$failed" = 1 ]; then
  # A partial dual-stack update must fail closed on both families.
  ip -4 route replace blackhole default table "$table" || true
  ip -6 route replace blackhole default table "$table" || true
  return 1
 fi
}
mesh_leg_step() {
 local id="$1" table="$2" direct="$3" dp="$4" mesh="$5" mp="$6" resolver="$7" ds="${8:-}" ms="${9:-}" src
 local dir="/run/meridian/exit-legs/$id" now old=direct switched=0 good=0 active reason dl dr ml mr dev result=ok tmp
 mkdir -p "$dir"
 now=$(date +%s)
 if [ "$(cat "$dir/plan" 2>/dev/null)" != "$MQ_PLAN" ]; then
  rm -f "$dir/window" "$dir/state" "$dir/events"
  echo "$MQ_PLAN" > "$dir/plan"
 fi
 if [ -f "$dir/state" ]; then read -r old switched good < "$dir/state"; fi
 case "$old" in direct|mesh|blackhole) ;; *) old=blackhole; switched=0; good=0 ;; esac
 mesh_sample "$direct" "$dp" "$dir/d" & local pid=$!
 mesh_sample "$mesh" "$mp" "$dir/m"
 wait "$pid"
 paste -d ' ' "$dir/d" "$dir/m" >> "$dir/window"
 tail -n "$MQ_WINDOW" "$dir/window" > "$dir/window.tmp" && mv -f "$dir/window.tmp" "$dir/window"
 read -r active switched good reason dl dr ml mr < <(awk -v now="$now" -v old="$old" -v sw="$switched" -v good="$good" -v win="$MQ_WINDOW" -v loss="$MQ_LOSS" -v rtt="$MQ_RTT" -v ret="$MQ_RETURN" -v dwell="$MQ_DWELL" -v adv="$MQ_ADV" '
 {ds+=$1;dc+=$2;dt+=$2*$3;ms+=$4;mc+=$5;mt+=$5*$6;du=($2>0);mu=($5>0);lastgood=du && ($1-$2)*1000/$1<loss && $3<rtt}
 END {
 dl=ds?int((ds-dc)*1000/ds):1000;dr=dc?int(dt/dc):0;ml=ms?int((ms-mc)*1000/ms):1000;mr=mc?int(mt/mc):0
 ok=du && dl<loss && dr<rtt && lastgood
 if(ok){if(!good)good=now}else good=0
 want=old;why="stable";ready=(!sw || now-sw>=dwell)
 better=(dl==0 && ml==0) ? (mr<dr && mr*100<=dr*95) : ((mr+ml)*(100+adv)<(dr+dl)*100)
 if(!du && !mu){want="blackhole";why="both_down"}
 else if(old=="direct" && !du){want="mesh";why="direct_down"}
 else if(old=="mesh" && !mu && du){want="direct";why="mesh_down"}
 else if(old=="blackhole"){want=du?"direct":"mesh";why="reachable"}
 else if(old=="direct" && mu && NR>=win && ready && better){want="mesh";why="quality"}
 else if(old=="mesh" && ok && NR>=win && good && now-good>=ret && ready && !better){want="direct";why="direct_recovered"}
 if(want!=old)sw=now
 print want,sw,good,why,dl,dr,ml,mr
 }' "$dir/window")
 case "$active" in direct) dev="$direct" ;; mesh) dev="$mesh" ;; *) active=blackhole; dev=blackhole ;; esac
 [ -n "$dev" ] || { active=blackhole; dev=blackhole; }
 if ! mesh_route "$table" "$dev"; then active=blackhole; dev=blackhole; result=failed; reason=route_failed; fi
 if [ -n "$resolver" ]; then
  src="$ds"; [ "$dev" != "$mesh" ] || src="$ms"
  ip -6 route replace blackhole "$resolver/128" metric 32767 || result=failed
  if [ "$dev" = blackhole ]; then
   ip -6 route replace blackhole "$resolver/128" || result=failed
  else
   ip -6 route replace "$resolver/128" dev "$dev" ${src:+src "$src"} || result=failed
  fi
  if [ "$result" = failed ]; then
   active=blackhole; dev=blackhole; reason=route_failed
   mesh_route "$table" blackhole || true
   ip -6 route replace blackhole "$resolver/128" || true
  fi
 fi
 # Only publish a device that was applied successfully. Groups fail closed.
 echo "$dev" > "$dir/iface.tmp" && mv -f "$dir/iface.tmp" "$dir/iface"
 echo "$active $switched $good" > "$dir/state.tmp" && mv -f "$dir/state.tmp" "$dir/state"
 tmp="$dir/report.tmp"
 echo "leg $MQ_PLAN $id $now $active $reason $switched $dl $dr $ml $mr $result" > "$tmp" && mv -f "$tmp" "$dir/report"
 if [ "$old" != "$active" ] || [ "$result" != ok ]; then
  echo "leg-event $MQ_PLAN $id $now $active $reason $switched $dl $dr $ml $mr $result" >> "$dir/events"
  tail -n 32 "$dir/events" > "$dir/events.tmp" && mv -f "$dir/events.tmp" "$dir/events"
  echo "exit-leg $id $old -> $active reason=$reason direct_loss=$dl direct_rtt_ms=$dr mesh_loss=$ml mesh_rtt_ms=$mr result=$result" >&2
 fi
}
`

// meshPlanSettingsV1 mirrors model.PathQuality as it was before the relay
// speed tests: the plan id hashes exactly these fields, so settings that
// only concern the relays' speed tests (and the relays' nominal bandwidth)
// neither change a hub's compiled files nor restart its Mesh quality loop.
type meshPlanSettingsV1 struct {
	MeshWindowSamples                                                  int
	MildLossPermille, MildRTTMS, PoorLossPermille, PoorRTTMS           int
	ReduceAfterSec, StandbyAfterSec, EvictAfterSec, DownAfterSec       int
	RecoverAfterSec, RampStepSec                                       int
	KeepConnectionsOnEvict                                             bool
	BackupAfterSec, ReturnAfterSec, MinDwellSec, SwitchAdvantagePct    int
	ProbeOff                                                           bool
	ProbeBytes, ProbeRateKbps, ProbeMinIntervalSec, ProbeDailyBudgetMB int
	ProbeFloorKbps, ProbeLossPermille                                  int
	Overrides                                                          []meshPlanOverrideV1
}

type meshPlanOverrideV1 struct {
	Relay    string
	Disabled bool
	Weight   int
}

func meshPlanSettings(p model.PathQuality) meshPlanSettingsV1 {
	v := meshPlanSettingsV1{p.MeshWindowSamples, p.MildLossPermille, p.MildRTTMS, p.PoorLossPermille, p.PoorRTTMS,
		p.ReduceAfterSec, p.StandbyAfterSec, p.EvictAfterSec, p.DownAfterSec, p.RecoverAfterSec, p.RampStepSec,
		p.KeepConnectionsOnEvict, p.BackupAfterSec, p.ReturnAfterSec, p.MinDwellSec, p.SwitchAdvantagePct,
		p.ProbeOff, p.ProbeBytes, p.ProbeRateKbps, p.ProbeMinIntervalSec, p.ProbeDailyBudgetMB, p.ProbeFloorKbps, p.ProbeLossPermille, nil}
	for _, o := range p.Overrides {
		v.Overrides = append(v.Overrides, meshPlanOverrideV1{o.Relay, o.Disabled, o.Weight})
	}
	return v
}
