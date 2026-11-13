package model

import "sort"

// HubTier says which hub a hub node is.
type HubTier string

const (
	// HubPrimary carries traffic on the main path (gateway → relay → IX →
	// primary hub → exit). A lone hub without a tier is the primary.
	HubPrimary HubTier = "primary"
	// HubBackup is reached from the gateway by WG over WSS directly, only
	// while the whole main path is down; it reaches the same exits.
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
