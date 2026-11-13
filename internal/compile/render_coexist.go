package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

// Coexistence of a remote node with what already runs on its host.
//
// Docker FORWARD DROP. Docker sets the iptables (and, with ip6tables on,
// the ip6tables) filter FORWARD policy to DROP when it enables forwarding
// itself. Meridian's own nft forward chains are policy accept and cannot
// accept a packet another table drops, so on such a host nothing a tunnel
// forwards gets through. The fix is the chain Docker reserves for the
// operator: DOCKER-USER, which Docker jumps to first from FORWARD and never
// flushes. meridian-fwcompat.sh puts a minimal set of ACCEPT rules at its top
// that match only Meridian's managed interfaces (tunnel in → WAN out on an
// exit and the established/related return, tunnel ↔ tunnel where the node
// relays), each carrying the tag FWTagPrefix+<digest of the set>. It never
// touches Docker's chains or rules, never sets a policy and never flushes
// anything; it adds rules only in a family whose FORWARD policy is DROP and
// removes its own tagged rules everywhere else. It uses the host's iptables
// and ip6tables binaries, whatever backend they are (iptables-nft writes into
// nft table ip/ip6 filter, legacy into the x_tables filter table): the same
// binary Docker uses for its chains.
//
// It runs from meridian-up.sh (install, update and boot through
// meridian-node.service, which is ordered after docker.service) and from
// meridian-fwcompat.service, which docker.service wants and which is bound
// to it: every time the Docker daemon (re)starts and rebuilds its chains the
// rules are asserted again. Rules are not persistent across a reboot; boot
// order re-creates them after Docker has created DOCKER-USER.

// FWChain is the iptables chain the coexistence rules live in.
const FWChain = "DOCKER-USER"

// FWTagPrefix starts the comment every coexistence rule carries; the rest is
// the first 8 hex digits of the SHA-256 of the rule set.
const FWTagPrefix = "meridian-fw-"

// Unit names of the remote-node boot and coexistence units.
const (
	NodeUnit     = "meridian-node.service"
	FWCompatUnit = "meridian-fwcompat.service"
	FWCompatPath = "/usr/local/sbin/meridian-fwcompat.sh"
)

// fwRules are the coexistence rule specs (without the tag and the target)
// for one remote node, in a fixed order. Empty for the gateway: its install
// (deploy/debian/install.sh) keeps Docker away from iptables, and a FORWARD
// DROP there is refused by the preflight.
func fwRules(t model.Topology, n model.Node, nodeTunnels []Tunnel) []string {
	if n.Role == model.RoleGateway {
		return nil
	}
	var up, down []string
	seen := map[string]bool{}
	for _, tun := range nodeTunnels {
		name := tun.Iface()
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if tun.East.ID == n.ID {
			up = append(up, name)
		} else {
			down = append(down, name)
		}
	}
	if meshPeer(t, n.ID) {
		// The Mesh veth is a downstream hop on a hub or relay and an
		// upstream (ingress) hop on an exit.
		if n.Role == model.RoleExit {
			up = append(up, mesh.HostIface)
		} else {
			down = append(down, mesh.HostIface)
		}
	}
	sortStrings(up)
	sortStrings(down)
	var out []string
	for _, u := range up {
		for _, d := range down {
			out = append(out, fmt.Sprintf("-i %s -o %s", u, d), fmt.Sprintf("-i %s -o %s", d, u))
		}
	}
	if n.Role == model.RoleExit {
		wan := exitWAN(n)
		for _, u := range up {
			out = append(out,
				fmt.Sprintf("-i %s -o %s", u, wan),
				fmt.Sprintf("-i %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED", wan, u))
		}
	}
	return out
}

// exitWAN is the WAN interface name an exit's nft NAT uses (nodeWAN).
func exitWAN(n model.Node) string { return nodeWAN(n) }

// nodeWAN is a remote node's WAN interface: wan_interface, or eth0 when it
// is unset. The preflight blocks when this interface does not exist on the
// host or does not carry the default route the node needs (it never adopts
// another name silently), and the provision script checks again.
func nodeWAN(n model.Node) string {
	if n.WANInterface != "" {
		return n.WANInterface
	}
	return "eth0"
}

// fwTag is the comment of every rule of the set.
func fwTag(rules []string) string {
	sum := sha256.Sum256([]byte(strings.Join(rules, "\n")))
	return FWTagPrefix + hex.EncodeToString(sum[:])[:8]
}

// renderFWCompat is /usr/local/sbin/meridian-fwcompat.sh. The shell helpers
// that recognise and delete tagged rules are the same text the provision
// compensation and the withdraw script use (FWShellLib).
func renderFWCompat(rules []string) string {
	var sb strings.Builder
	sb.WriteString(`#!/bin/bash
# Meridian forwarding coexistence with a FORWARD policy of DROP (Docker).
# Managed by Meridian (node manifest). It only adds ACCEPT rules for
# Meridian's own interfaces at the top of DOCKER-USER, the chain Docker
# reserves for the operator and jumps to first from FORWARD. It never
# touches Docker's chains, never sets a policy and never flushes anything:
# every rule it adds carries the tag below, and only tagged rules are ever
# deleted. A family (iptables / ip6tables) whose FORWARD policy is not DROP
# gets no rule. Run by meridian-up.sh and by meridian-fwcompat.service each
# time docker.service (re)starts.
#   meridian-fwcompat.sh apply    add the missing rules, remove stale tagged ones
#   meridian-fwcompat.sh remove   remove every Meridian-tagged rule
#   meridian-fwcompat.sh status   print the tagged rules present
set -u
`)
	fmt.Fprintf(&sb, "FW_TAG=%s\nFW_CHAIN=%s\n", fwTag(rules), FWChain)
	sb.WriteString("FW_RULES=(\n")
	for _, r := range rules {
		fmt.Fprintf(&sb, "  \"%s\"\n", r)
	}
	sb.WriteString(")\n")
	sb.WriteString(FWShellLib)
	sb.WriteString(`fw_apply_family() {
  local fam=$1 tool pol out i rc=0 line
  local -a spec
  tool=$(m_fw_tool "$fam")
  command -v "$tool" >/dev/null 2>&1 || return 0
  if ! out=$("$tool" -w 5 -S FORWARD 2>/dev/null); then
    echo "meridian-fwcompat-failed: $tool -S FORWARD failed; rules left as they are" >&2
    return 1
  fi
  # The policy line, not the first line: iptables-nft may print a comment
  # ("# Warning: iptables-legacy tables present …") before it.
  pol=$(printf '%s\n' "$out" | grep -m 1 -- '^-P FORWARD ' || true)
  case "$pol" in
    "-P FORWARD DROP") ;;
    "-P FORWARD ACCEPT")
      # Nothing to work around in this family: no rule of ours belongs here.
      m_fw_remove_tagged "$fam" ""
      return $? ;;
    *)
      echo "meridian-fwcompat-failed: IPv$fam FORWARD policy unreadable ($pol); rules left as they are" >&2
      return 1 ;;
  esac
  if ! "$tool" -w 5 -S "$FW_CHAIN" >/dev/null 2>&1; then
    echo "meridian-fwcompat-unsupported: IPv$fam FORWARD policy is DROP and there is no $FW_CHAIN chain (not Docker, or Docker without its iptables rules); forwarded tunnel traffic is dropped, nothing was changed" >&2
    return 1
  fi
  for ((i=${#FW_RULES[@]}-1; i>=0; i--)); do
    set -f
    read -r -a spec <<< "${FW_RULES[$i]}"
    set +f
    if ! "$tool" -w 5 -C "$FW_CHAIN" "${spec[@]}" -m comment --comment "$FW_TAG" -j ACCEPT >/dev/null 2>&1; then
      if "$tool" -w 5 -I "$FW_CHAIN" 1 "${spec[@]}" -m comment --comment "$FW_TAG" -j ACCEPT; then
        echo "meridian-fwcompat: IPv$fam $FW_CHAIN + ${FW_RULES[$i]}"
      else
        echo "meridian-fwcompat-failed: could not insert into IPv$fam $FW_CHAIN: ${FW_RULES[$i]}" >&2
        rc=1
      fi
    fi
  done
  # Rules of an earlier rule set (another tag) go; the current set stays.
  m_fw_remove_tagged "$fam" "$FW_TAG" || rc=1
  return $rc
}
# meridian-node.service and meridian-fwcompat.service can both run at boot:
# one at a time, so a check-then-insert cannot add a rule twice.
fw_lock() {
  if command -v flock >/dev/null 2>&1 && [ -w /run ]; then
    exec 9>>/run/meridian-fwcompat.lock || return 0
    flock -w 30 9 || true
  fi
}
rc=0
case "${1:-apply}" in
  apply)
    fw_lock
    for fam in 4 6; do fw_apply_family "$fam" || rc=1; done ;;
  remove)
    fw_lock
    for fam in 4 6; do m_fw_remove_tagged "$fam" "" || rc=1; done ;;
  status)
    for fam in 4 6; do m_fw_tagged "$fam" | sed "s/^/IPv$fam /"; done ;;
  *) echo "usage: $0 apply|remove|status" >&2; rc=2 ;;
esac
exit $rc
`)
	return sb.String()
}

// FWShellLib recognises and deletes Meridian-tagged rules of FW_CHAIN. It
// is part of meridian-fwcompat.sh and, verbatim, of the provision
// compensation and the withdraw script (which never run a host file). A
// rule is Meridian's exactly when its comment is FWTagPrefix followed by 8
// lower-case hex digits; nothing else is ever deleted. Deletion replays the
// rule as iptables -S prints it with -A turned into -D.
const FWShellLib = `m_fw_tool() { case "$1" in 4) echo iptables ;; 6) echo ip6tables ;; esac; }
# m_fw_tagged FAM: the -S lines of DOCKER-USER that carry a Meridian tag.
m_fw_tagged() {
  local tool out
  tool=$(m_fw_tool "$1")
  command -v "$tool" >/dev/null 2>&1 || return 0
  out=$("$tool" -w 5 -S DOCKER-USER 2>/dev/null) || return 0
  printf '%s\n' "$out" | grep -E -- '^-A DOCKER-USER .*--comment "?meridian-fw-[0-9a-f]{8}"?( |$)' || true
}
# m_fw_remove_tagged FAM KEEP: delete every tagged rule except those tagged KEEP.
m_fw_remove_tagged() {
  local fam=$1 keep=$2 tool line rc=0
  local -a args
  tool=$(m_fw_tool "$fam")
  command -v "$tool" >/dev/null 2>&1 || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ -n "$keep" ]; then
      case " $line " in *" --comment $keep "*) continue ;; esac
    fi
    set -f
    read -r -a args <<< "$line"
    set +f
    args[0]=-D
    if "$tool" -w 5 "${args[@]}" >/dev/null 2>&1; then
      echo "meridian-fwcompat: IPv$fam removed ${line#-A }"
    else
      echo "meridian-fwcompat-failed: could not remove IPv$fam ${line#-A }" >&2
      rc=1
    fi
  done < <(m_fw_tagged "$fam")
  return $rc
}
`

// renderFWCompatUnit re-asserts the rules whenever docker.service starts:
// docker.service wants it (WantedBy), it starts after the daemon is up
// (After; Docker creates DOCKER-USER and its FORWARD jump before it reports
// ready) and stops with it (BindsTo), so a daemon restart, a crash with
// systemd's automatic restart, and a stop/start all run it again.
func renderFWCompatUnit() string {
	return `# Meridian: forwarding rules in DOCKER-USER, re-applied whenever Docker starts.
[Unit]
Description=Meridian forwarding coexistence with Docker (DOCKER-USER rules)
BindsTo=docker.service
After=docker.service
ConditionFileIsExecutable=` + FWCompatPath + `

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + FWCompatPath + ` apply

[Install]
WantedBy=docker.service
`
}

// renderNodeUnit is the remote node's boot unit: it runs meridian-up.sh
// once the network is online, after nftables.service (whose boot-time load
// of /etc/nftables.conf may flush the ruleset: Meridian loads after it) and
// after docker.service when Docker is enabled (DOCKER-USER must exist
// before meridian-fwcompat.sh can use it). meridian-up.sh loads the nft
// batch, applies the sysctls and the coexistence rules, turns forwarding on,
// and only then brings the WireGuard interfaces up and installs the routes,
// so no packet can arrive on a tunnel before Meridian's tables are loaded.
// Any failure fails the unit (systemctl is-failed). It is enabled by the
// provision script, never started from meridian-up.sh itself.
func renderNodeUnit() string {
	return `# Meridian node data plane at boot (meridian-up.sh).
[Unit]
Description=Meridian node data plane restore (meridian-up.sh)
Wants=network-online.target
After=network-online.target nftables.service docker.service
ConditionFileIsExecutable=/usr/local/sbin/meridian-up.sh

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/meridian-up.sh
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
`
}

// sysctlIfaces are the interfaces the routes script hardens (rp_filter=2,
// no ICMP redirects): the node's managed WireGuard interfaces, the
// interface the topology names for this node (the gateway LAN, a remote
// node's WAN), remote access on the gateway and the Mesh veth. Docker,
// WARP and every other interface on the host keep their settings.
func sysctlIfaces(t model.Topology, n model.Node, nodeTunnels []Tunnel) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(sysctlIface(t, n))
	if model.IsIXHub(n) {
		add(n.IngressInterface)
	}
	if n.Role == model.RoleGateway {
		for _, name := range gatewayTunnelIfaces(nodeTunnels) {
			add(name)
		}
		if rp := planRemote(t); rp != nil {
			add(rp.Iface)
		}
	} else {
		for _, name := range tunnelIfaces(nodeTunnels) {
			add(name)
		}
		if meshPeer(t, n.ID) {
			add(mesh.HostIface)
		}
	}
	return out
}

// wanMarker is the line meridian-up.sh carries for the preflight and the
// provision re-check: "# meridian-wan: <iface> <set|default> need=<4,6|any>".
func wanMarker(n model.Node) string {
	src := "default"
	if n.WANInterface != "" {
		src = "set"
	}
	var need []string
	if n.Role == model.RoleExit {
		if n.EgressV4 {
			need = append(need, "4")
		}
		if n.EgressV6 {
			need = append(need, "6")
		}
	}
	if len(need) == 0 {
		need = []string{"any"}
	}
	return fmt.Sprintf("# meridian-wan: %s %s need=%s\n", nodeWAN(n), src, strings.Join(need, ","))
}
