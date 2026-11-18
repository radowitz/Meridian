package compile

import (
	"encoding/json"
	"fmt"

	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// The gateway's link journal (internal/linkjournal, docs/architecture.md
// 「链路日志」): a record of path and link state changes. It is always part
// of a gateway's files — it holds no user traffic content, so there is no
// switch — and it reaches a host only the way every other gateway file
// does: preflight (which lists the new files), confirmation, install.
//
// For a gateway, exactly three things are rendered for it:
//
//   - LinkJournalUnit: "meridian link-journal", the collector;
//   - LinkJournalConfigPath: the object list the collector reads — which
//     interfaces are the gateway's tunnels, which units its wstunnel
//     clients, which self-check target is which exit or group, and how the
//     carrying path is recorded on this topology (linkJournalConfig);
//   - meridian-verify.sh gets the checks of linkLogVerifyBlock.
//
// Nothing else changes: no rule set, no route, no WireGuard or resolver
// configuration, no failover script, no other unit. The collector only
// reads what those publish (linkjournal/sources.go). No other node gets
// anything.
const (
	LinkJournalUnit       = linkjournal.Unit
	LinkJournalConfigPath = linkjournal.ConfigPath
)

// linkJournalConfig is the object list of the gateway: every name in it
// comes from the same plans the gateway's other files are rendered from.
func linkJournalConfig(t model.Topology, tunnels []Tunnel, exits []ExitPlan, groups []GroupPlan, sniffOn bool) linkjournal.Config {
	gw, _ := gatewayNode(t)
	c := linkjournal.Config{Version: 1, Gateway: gw.ID, IntervalS: linkjournal.DefaultIntervalS, SlowEvery: linkjournal.DefaultSlowEvery,
		HandshakeStaleS: linkjournal.DefaultHandshakeStaleS, UpstreamStaleS: linkjournal.DefaultUpstreamStaleS,
		Mode: linkjournal.ModeSingle, Paths: []linkjournal.PathConfig{}, Tunnels: []linkjournal.TunnelConfig{}, WSS: []linkjournal.WSSConfig{}}
	byIface := map[string]Tunnel{}
	for _, tun := range tunnels {
		if tun.West.ID == gw.ID || tun.East.ID == gw.ID {
			byIface[tun.Iface()] = tun
		}
	}
	peerOf := func(tun Tunnel) model.Node {
		if tun.West.ID == gw.ID {
			return tun.East
		}
		return tun.West
	}
	path := func(name string, tun Tunnel, hub string, tier model.HubTier) {
		if tun.LinkID == "" {
			return
		}
		c.Paths = append(c.Paths, linkjournal.PathConfig{Name: name, Iface: tun.Iface(), Link: tun.LinkID, Peer: peerOf(tun).ID, Hub: hub, Tier: string(tier), Mode: tun.Mode})
	}
	switch share := planShare(t, tunnels); {
	case share != nil:
		// Relay sharing: the controller's record names each relay's leg
		// (pathquality.FormatStatus).
		c.Mode = linkjournal.ModeShare
		for _, r := range share.Relays {
			hub, tier := share.Primary.ID, model.HubPrimary
			if r.Group == model.RelayGroupBackup {
				hub, tier = share.BackupHub.ID, model.HubBackup
			}
			for _, l := range r.Legs {
				path("relay", l, hub, tier)
			}
		}
		if b := share.Backup; b != nil {
			path("backup", b.Tun, b.Hub.ID, model.HubBackup)
		}
	case t.DualHub():
		// A backup hub: the failover loop's record names the path
		// (upstream_record).
		c.Mode = linkjournal.ModeDual
		for _, p := range planUpstream(t, tunnels).Paths {
			path(p.Name, byIface[p.Iface], p.Hub, p.Tier)
		}
	default:
		// One relay, no backup hub: the loop records nothing; the collector
		// reads which leg table 102 points at.
		udp, wss, direct := gatewayIfaces(tunnels)
		hub := primaryHubID(t)
		path("udp", udp, hub, model.HubPrimary)
		path("wss", wss, hub, model.HubPrimary)
		path("direct", direct, hub, model.HubPrimary)
	}
	seen := map[string]bool{}
	for _, tun := range tunnelsFor(tunnels, gw.ID) {
		if seen[tun.Iface()] {
			continue
		}
		seen[tun.Iface()] = true
		peer := peerOf(tun)
		c.Tunnels = append(c.Tunnels, linkjournal.TunnelConfig{Iface: tun.Iface(), Link: tun.LinkID, Mode: tun.Mode, Peer: peer.ID, PeerRole: string(peer.Role), Standby: tun.Standby, KeepaliveS: tun.Keepalive})
		if tun.Mode == "wss" && tun.Dialer().ID == gw.ID {
			c.WSS = append(c.WSS, linkjournal.WSSConfig{Unit: WSSClientUnit(tun.LinkID), Link: tun.LinkID, Iface: tun.Iface(), Peer: peer.ID})
		}
	}
	if sniffOn {
		// Every name the forwarder's self-check can report (planSniff:
		// "direct", "exit:<id>", "group:<id>") and what it is: which exit or
		// region group, and whether the exit is an external SOCKS exit and
		// on which carrier. Which of them the forwarder checks at a given
		// moment follows the rules and the unlock decisions; this list does
		// not, so a decision change never touches this file
		// (DecisionFiles). A target the self-check does not report gives no
		// reading.
		sn := &linkjournal.SniffConfig{SelfCheckMaxAgeS: linkjournal.DefaultSelfCheckMaxAgeS, Targets: []linkjournal.SniffTarget{{Target: "direct", Kind: "direct"}}}
		for _, e := range exits {
			st := linkjournal.SniffTarget{Target: "exit:" + e.Node.ID, Kind: "exit", ID: e.Node.ID}
			if e.External {
				st.External, st.Carrier = true, model.HubSideOf(e.Node)
			}
			sn.Targets = append(sn.Targets, st)
		}
		for _, g := range groups {
			sn.Targets = append(sn.Targets, linkjournal.SniffTarget{Target: "group:" + g.Group.ID, Kind: "region_group", ID: g.Group.ID})
		}
		c.Sniff = sn
	}
	return c
}

func renderLinkJournalConfig(c linkjournal.Config) string {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(err) // plain structs: cannot fail
	}
	return string(b) + "\n"
}

// LinkJournalExternal says, for one external SOCKS exit of the topology,
// whether the gateway has a check of its own for it.
type LinkJournalExternal struct {
	ID      string `json:"id"`
	Carrier string `json:"carrier"`
	// Observed: the forwarder's self-check has a target for this exit (a
	// rule or the default destination points at it directly).
	Observed bool   `json:"observed"`
	Note     string `json:"note"`
}

// LinkJournalInfo is what the panel says about the journal of a topology.
type LinkJournalInfo struct {
	// Config is the object list the gateway is compiled with.
	Config linkjournal.Config
	// Objects: every object of the list; Observed false for the ones the
	// gateway does not read now (a tunnel without keepalive, a self-check
	// target the forwarder does not check with the current rules and
	// unlock decisions).
	Objects []linkjournal.Object
	// Externals: every external exit and what the gateway sees of it.
	Externals []LinkJournalExternal
}

// LinkJournalFor describes the link journal of t's gateway under the given
// unlock decisions.
func LinkJournalFor(t model.Topology, decisions map[string]string) (LinkJournalInfo, error) {
	var info LinkJournalInfo
	res := validate.Run(t)
	if res.HasErrors() {
		return info, &ValidationError{Result: res}
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return info, err
	}
	exits := planExits(t, tunnels)
	groups := planGroups(t, exits)
	info.Config = linkJournalConfig(t, tunnels, exits, groups, t.SniffOn())
	// What the forwarder checks now: the targets of its target file.
	active := map[string]bool{}
	if sp := planSniff(t, exits, groups, decisions); sp != nil {
		for _, tg := range sp.Targets {
			if !tg.Reject {
				active[tg.Name] = true
			}
		}
	}
	byObject := map[string]string{}
	if sn := info.Config.Sniff; sn != nil {
		for _, tg := range sn.Targets {
			_, kind, id := tg.Object()
			byObject[kind+"\x00"+id] = tg.Target
		}
	}
	for _, o := range info.Config.Objects() {
		if name, ok := byObject[o.Kind+"\x00"+o.ID]; ok && !active[name] {
			o.Observed = false
			o.Note = "现在没有规则或默认去向直接指向它：嗅探转发服务不自检这个目标，所以没有读数"
		}
		info.Objects = append(info.Objects, o)
	}
	info.Externals = []LinkJournalExternal{}
	for _, n := range t.Nodes {
		if !model.IsExternal(n) {
			continue
		}
		x := LinkJournalExternal{ID: n.ID, Carrier: model.HubSideOf(n), Observed: active["exit:"+n.ID]}
		switch {
		case !t.SniffOn():
			x.Note = "按域名嗅探没有开启：网关没有针对这个出口的任何检查，它的通断不记录"
		case x.Observed:
			x.Note = "有规则或默认去向直接指向这个出口：嗅探转发服务的自检会经隧道问它的解析器，结果记为「外部出口」事件（依据是网关自检，不是承载节点上的健康检查）"
		default:
			x.Note = "没有规则或默认去向直接指向这个出口（它只作为地区组的成员）：网关不单独检查它；所在地区组的自检反映的是枢纽当时使用的成员"
		}
		info.Externals = append(info.Externals, x)
	}
	return info, nil
}

// LinkJournalUnitSpec is what the collector's unit is rendered from.
type LinkJournalUnitSpec struct {
	Unit, Binary, Config string
	StateDir, RuntimeDir string
}

// StatusSocket is the collector's status socket.
func (s LinkJournalUnitSpec) StatusSocket() string { return "/run/" + s.RuntimeDir + "/status.sock" }

func gatewayLinkJournalSpec() LinkJournalUnitSpec {
	return LinkJournalUnitSpec{Unit: LinkJournalUnit, Binary: "/usr/local/bin/meridian", Config: LinkJournalConfigPath,
		StateDir: linkjournal.StateDirName, RuntimeDir: linkjournal.RuntimeDirName}
}

// RenderLinkJournalUnit runs the collector as root with CAP_NET_ADMIN only:
// the kernel answers the WireGuard device query ("wg show <iface>
// latest-handshakes") to no one without it. It is used for nothing else —
// the collector's three programs and their argument lists are fixed
// (linkjournal/sources.go), none of them changes anything. The unit cannot
// open an IP socket (Unix and netlink only, IPAddressDeny=any), writes only
// its StateDirectory (the rest of the file system, /run/meridian included,
// is read-only for it), and runs at low CPU and idle I/O priority under a
// memory cap. It shares no file it writes, no lock and no process with the
// failover service or the forwarder; stopped or crashed, nothing is
// recorded and nothing else is affected.
func RenderLinkJournalUnit(s LinkJournalUnitSpec) string {
	return fmt.Sprintf(`# Meridian gateway link journal: records state changes of the gateway's paths
# and links (which path carries, relay sharing, tunnel handshakes, WSS carriers,
# the forwarder's self-check) in %[5]s; see docs/architecture.md「链路日志」.
# Read-only: it changes no route, rule, interface or unit. Stopped or crashed:
# nothing is recorded; forwarding and failover are not affected.
[Unit]
Description=Meridian gateway link journal
After=local-fs.target

[Service]
Type=simple
# An older host binary has no link-journal subcommand and would start the panel.
ExecStartPre=/bin/grep -q %[2]s %[3]s
ExecStart=%[3]s link-journal --config %[4]s --dir %[5]s --status-socket %[6]s
User=root
# CAP_NET_ADMIN only: the kernel answers "wg show <iface> latest-handshakes"
# to no one without it. Nothing else here uses it.
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes
# %[5]s is root-only (0700), its files 0600: the events, the
# checkpoint and their temporary copies. Together at most 16 MiB, 30 days,
# 20000 events.
StateDirectory=%[7]s
StateDirectoryMode=0700
# Status socket: 0666 in a 0755 directory, answering uid 0 only (SO_PEERCRED);
# the host agent is root without CAP_DAC_OVERRIDE.
RuntimeDirectory=%[8]s
RuntimeDirectoryMode=0755
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
UMask=0077
Nice=10
CPUWeight=20
IOSchedulingClass=idle
MemoryMax=96M
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, s.Unit, linkjournal.ReadyMarker, s.Binary, s.Config, "/var/lib/"+s.StateDir, s.StatusSocket(), s.StateDir, s.RuntimeDir)
}

// linkLogVerifyBlock: the link journal on the gateway. A problem here is a
// WARN, never a failed check: the collector records, it carries nothing, so
// the data plane's acceptance does not depend on it. Without systemctl (not
// a systemd host) nothing is checked.
var linkLogVerifyBlock = fmt.Sprintf(`# --- link journal (records path and link changes; carries nothing) --------------
if command -v systemctl >/dev/null 2>&1; then
  if run link-log-collector systemctl is-active %[1]s; then
    pass link_log_collector "%[1]s is active (evidence link-log-collector.txt)"
    if [ -s "$root"%[2]s ]; then
      pass link_log_config "object list $root%[2]s is installed"
    else
      warn link_log_config "object list $root%[2]s is missing or empty: the collector cannot start again"
    fi
    linklog_dir="$root"%[3]s
    if [ -L "$linklog_dir" ] || [ ! -d "$linklog_dir" ]; then
      warn link_log_dir "journal directory $linklog_dir is missing or not a real directory (the collector's unit creates it)"
    elif [ "$(stat -c '%%a %%u' "$linklog_dir" 2>/dev/null)" != "700 0" ]; then
      warn link_log_dir "journal directory $linklog_dir is $(stat -c '%%a %%u' "$linklog_dir" 2>/dev/null), not 0700 owned by root"
    elif [ -n "$(find "$linklog_dir" -mindepth 1 \( ! -type f -o ! -user 0 -o -perm /077 \) -print 2>/dev/null | head -n 1)" ]; then
      warn link_log_dir "an entry in $linklog_dir is not a 0600 root-owned regular file: $(find "$linklog_dir" -mindepth 1 \( ! -type f -o ! -user 0 -o -perm /077 \) -print 2>/dev/null | head -n 1)"
    else
      pass link_log_dir "journal $linklog_dir: directory 0700, files 0600, owned by root (the panel reads it through the collector's status socket)"
    fi
    linklog_total=$(du -sk "$linklog_dir" 2>/dev/null | cut -f1)
    case $linklog_total in ''|*[!0-9]*) warn link_log_budget "the size of $linklog_dir could not be read" ;;
      *) if [ "$linklog_total" -le %[4]d ]; then
           pass link_log_budget "$linklog_dir holds ${linklog_total} KiB (budget %[4]d KiB for the events, the checkpoint and their temporary copies)"
         else
           warn link_log_budget "$linklog_dir holds ${linklog_total} KiB, over the %[4]d KiB budget"
         fi ;;
    esac
    linklog_sock=%[5]s
    if [ -S "$linklog_sock" ] && [ "$(stat -c '%%a %%u' "$linklog_sock" 2>/dev/null)" = "666 0" ]; then
      pass link_log_status_socket "status socket $linklog_sock: 0666 owned by root; the collector answers uid 0 only (SO_PEERCRED)"
    else
      warn link_log_status_socket "status socket $linklog_sock missing or with other owner/mode ($(stat -c '%%a %%u' "$linklog_sock" 2>/dev/null)): the panel cannot read the link journal"
    fi
  else
    warn link_log_collector "%[1]s is not active: path and link changes are not recorded; forwarding and failover are not affected (journalctl -u %[1]s)"
  fi
fi
notrun netns_link_journal "isolated Linux integration (a kernel WireGuard handshake going stale and recovering; the compiled failover moving to the backup hub and back): sudo MERIDIAN_NETNS_TEST=1 MERIDIAN_NFT_TEST=1 go test ./internal/compile -run '^TestNetnsLinkJournal' -v (archive the log)"
pending link_log_real_events "what the collector records has not been compared with a real failure on this gateway (a relay cut, a handshake timeout, an external exit going away): compare the next one with the link journal page"
`, LinkJournalUnit, LinkJournalConfigPath, linkjournal.StateDir, linkjournal.DefaultMaxBytes>>10, linkjournal.StatusSocket)
