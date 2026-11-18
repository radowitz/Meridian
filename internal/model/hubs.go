package model

import "sort"

// HubTier says which hub a hub node is.
type HubTier string

const (
	// HubPrimary carries traffic on the main path (gateway → relay → IX →
	// primary hub → exit; without an IX gateway → relay → primary hub →
	// exit). A lone hub without a tier is the primary.
	HubPrimary HubTier = "primary"
	// HubBackup carries only while the whole main path is down: reached
	// from the gateway by WG over WSS directly, or through the backup
	// group of relays (RelayGroupOf); it reaches the same exits.
	HubBackup HubTier = "backup"
)

// Hubs lists the hub nodes sorted by ID.
func (t Topology) Hubs() []Node {
	var out []Node
	for _, n := range t.Nodes {
		if n.Role == RoleHub {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EffectiveHubTier is the node's tier with the lone-hub default applied:
// an untiered hub is the primary unless another hub claims that tier.
func (t Topology) EffectiveHubTier(n Node) HubTier {
	if n.Role != RoleHub {
		return ""
	}
	if n.HubTier != "" {
		return n.HubTier
	}
	for _, o := range t.Nodes {
		if o.Role == RoleHub && o.ID != n.ID && o.HubTier == HubPrimary {
			return ""
		}
	}
	return HubPrimary
}

// PrimaryHub is the hub that carries the main path: the hub with tier
// primary, else the first untiered hub (sorted by ID). Validation refuses
// a topology where this is ambiguous.
func (t Topology) PrimaryHub() (Node, bool) {
	hubs := t.Hubs()
	for _, n := range hubs {
		if n.HubTier == HubPrimary {
			return n, true
		}
	}
	for _, n := range hubs {
		if n.HubTier == "" {
			return n, true
		}
	}
	return Node{}, false
}

// BackupHub is the hub with tier backup.
func (t Topology) BackupHub() (Node, bool) {
	for _, n := range t.Hubs() {
		if n.HubTier == HubBackup {
			return n, true
		}
	}
	return Node{}, false
}

// DualHub: the topology has a backup hub. Everything the backup hub adds
// (exit tunnels to both hubs, per-hub return paths on exits, the gateway's
// end-to-end main-path check and upstream record) is compiled only then; a
// single-hub topology compiles exactly as before.
func (t Topology) DualHub() bool {
	_, ok := t.BackupHub()
	return ok
}

// IsIXHub: n is a hub on the IX line (the managed IX itself).
func IsIXHub(n Node) bool { return n.Role == RoleHub && n.IXLine }

// migrateHubs writes the primary tier on a lone untiered hub. It is pure
// and idempotent: the second run finds the tier set and changes nothing.
// Nothing compiled depends on the written tier (a lone hub is the primary
// either way), so an old single-hub topology compiles exactly as before.
func migrateHubs(t *Topology) []string {
	var hubs []int
	for i, n := range t.Nodes {
		if n.Role == RoleHub {
			hubs = append(hubs, i)
		}
	}
	if len(hubs) != 1 || t.Nodes[hubs[0]].HubTier != "" {
		return nil
	}
	t.Nodes[hubs[0]].HubTier = HubPrimary
	return []string{t.Nodes[hubs[0]].ID}
}

// HasIX: the topology has an IX, as an unmanaged ix node or as an ix_line
// hub, whether or not its links are enabled. With an IX the main path must
// pass it (gateway → relay → IX → primary hub → exit); without one it is
// gateway → relay → primary hub → exit.
func (t Topology) HasIX() bool {
	for _, n := range t.Nodes {
		if n.Role == RoleIX || IsIXHub(n) {
			return true
		}
	}
	return false
}

// Relay groups (docs/architecture.md「主备中继分组」). A gateway-linked relay
// (SharingRelays) belongs to the main group when it has an enabled,
// non-standby tunnel to the primary hub (or the IX), to the backup group
// when it has one to the backup hub only. The gateway shares the main path
// over the main group; only when every main-group relay is completely
// unreachable does it switch to the backup group (the backup hub reached
// through relays). A relay tunnelled to both hubs is ambiguous and refused
// by validation; here it counts as main. Disabled links never count.
const (
	RelayGroupMain   = "main"
	RelayGroupBackup = "backup"
)

// relayHubTunnel: an enabled, non-standby tunnel link joins relay and hub.
func (t Topology) relayHubTunnel(relay, hub string) bool {
	for _, l := range t.Links {
		if !l.Enabled || l.Standby {
			continue
		}
		switch l.Transport {
		case TransportDirectWG, TransportWGOverWSS, TransportUDPWSSFailover, TransportDedicatedLine:
		default:
			continue
		}
		if (l.From == relay && l.To == hub) || (l.To == relay && l.From == hub) {
			return true
		}
	}
	return false
}

// relayMainLinked: the relay has a tunnel to the primary hub or an IX node.
func (t Topology) relayMainLinked(relay string) bool {
	if p, ok := t.PrimaryHub(); ok && t.relayHubTunnel(relay, p.ID) {
		return true
	}
	for _, n := range t.Nodes {
		if n.Role == RoleIX && t.relayHubTunnel(relay, n.ID) {
			return true
		}
	}
	return false
}

// RelayGroupOf is the group of a gateway-linked relay ("" for any other
// node).
func (t Topology) RelayGroupOf(id string) string {
	for _, n := range t.SharingRelays() {
		if n.ID == id {
			if b, ok := t.BackupHub(); ok && !t.relayMainLinked(id) && t.relayHubTunnel(id, b.ID) {
				return RelayGroupBackup
			}
			return RelayGroupMain
		}
	}
	return ""
}

// RelayGroupAmbiguous: the relay has tunnels to both hubs.
func (t Topology) RelayGroupAmbiguous(id string) bool {
	b, ok := t.BackupHub()
	return ok && t.relayMainLinked(id) && t.relayHubTunnel(id, b.ID)
}

// MainGroupRelays / BackupGroupRelays split SharingRelays by group (each
// sorted by ID).
func (t Topology) MainGroupRelays() []Node   { return t.relaysOf(RelayGroupMain) }
func (t Topology) BackupGroupRelays() []Node { return t.relaysOf(RelayGroupBackup) }

func (t Topology) relaysOf(group string) []Node {
	var out []Node
	for _, n := range t.SharingRelays() {
		if t.RelayGroupOf(n.ID) == group {
			out = append(out, n)
		}
	}
	return out
}

// RelayBackup: the backup hub is reached through a backup group of relays
// (rather than by the gateway's own WG over WSS).
func (t Topology) RelayBackup() bool { return len(t.BackupGroupRelays()) > 0 }

// DirectExits: the gateway reaches its exits without any relay, hub or IX
// (docs/architecture.md「直连出口与单中继」). The topology has no node of those
// roles at all; the gateway itself then does what a hub does for the
// exits: one tunnel per exit, one table per exit and region group, and the
// group switching (compile: the gateway is its own primary hub). Every
// topology with a relay, a hub or an IX is not direct and compiles exactly
// as before.
func (t Topology) DirectExits() bool {
	gw := false
	for _, n := range t.Nodes {
		switch n.Role {
		case RoleRelay, RoleHub, RoleIX:
			return false
		case RoleGateway:
			gw = true
		}
	}
	return gw
}
