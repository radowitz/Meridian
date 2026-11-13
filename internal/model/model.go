// Package model is the control-plane document for Meridian.
// Private keys, tokens, and real VPS addresses must not be committed.
// Examples use documentation prefixes (RFC 5737 / RFC 3849) and RFC 2606 names.
package model

type Role string

const (
	RoleGateway Role = "gateway"
	RoleRelay   Role = "relay"
	RoleIX      Role = "ix"
	RoleHub     Role = "hub"
	RoleExit    Role = "exit"
)

type Transport string

const (
	TransportDirectWG         Transport = "direct_wg"
	TransportWGOverWSS        Transport = "wg_over_wss"
	TransportUDPWSSFailover   Transport = "udp_wss_failover"
	TransportCFMesh           Transport = "cf_mesh"
	TransportIXReplacementWSS Transport = "ix_replacement_wss"
	TransportDedicatedLine    Transport = "dedicated_line"
)

type V6Workaround string

const (
	WorkaroundNone           V6Workaround = ""
	WorkaroundDualstackRelay V6Workaround = "dualstack_relay"
	WorkaroundMesh           V6Workaround = "mesh"
	WorkaroundV4Front        V6Workaround = "v4_front"
)

type MatchType string

const (
	MatchDomain  MatchType = "domain"
	MatchSuffix  MatchType = "suffix"
	MatchKeyword MatchType = "keyword"
	MatchGeosite MatchType = "geosite"
	MatchCIDR    MatchType = "cidr"
	MatchGeoIP   MatchType = "geoip"
	MatchASN     MatchType = "asn"
)

// RuleMode is the pre-region-group rule mode. It is legacy input only:
// MigrateRegionGroups turns pin/auto into a group's mode and clears it. A
// migrated rule never carries a mode (the group is the single source of
// truth); validation rejects one that does.
type RuleMode string

const (
	ModePin  RuleMode = "pin"
	ModeAuto RuleMode = "auto"
)

// Node is one box or a logical hop (the IX dedicated line has no SSH target).
type Node struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Role    Role    `json:"role"`
	Region  string  `json:"region,omitempty"`
	Managed bool    `json:"managed"`
	X       float64 `json:"x,omitempty"`
	Y       float64 `json:"y,omitempty"`

	LANInterface    string `json:"lan_interface,omitempty"`
	LANIPv4         string `json:"lan_ipv4,omitempty"`
	LANIPv6Prefix   string `json:"lan_ipv6_prefix,omitempty"`
	UnderlayNextHop string `json:"underlay_nexthop,omitempty"`
	WANInterface    string `json:"wan_interface,omitempty"`

	PathV4       bool         `json:"path_v4"`
	PathV6       bool         `json:"path_v6"`
	EgressV4     bool         `json:"egress_v4"`
	EgressV6     bool         `json:"egress_v6"`
	NatDialOut   bool         `json:"nat_dial_out"`
	Residential  bool         `json:"residential"`
	IXBound      bool         `json:"ix_bound"`
	V6Workaround V6Workaround `json:"v6_workaround,omitempty"`
	// DualstackRelay is an IX-after hop with both address families. The hub
	// reaches it with v4; a pure-v6 exit dials it with v6. It is not a way
	// around the IX.
	DualstackRelay bool `json:"dualstack_relay,omitempty"`
	// Pool and PoolPriority are legacy input only. Membership and order live
	// in Topology.Groups; MigrateRegionGroups adds the node to the groups
	// migrated from this pool (IX-bound first, then lower PoolPriority,
	// then ID) and clears both fields.
	Pool         string `json:"pool,omitempty"`
	PoolPriority int    `json:"pool_priority,omitempty"`

	// PublicKey is safe to store. PrivateKey is generated on apply and
	// redacted by the API. Leave both empty in git.
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`

	// EndpointV4 is the public IPv4 peers dial. It must stay empty on
	// nat_dial_out nodes: the hub must not learn a public endpoint for them.
	EndpointV4 string `json:"endpoint_v4,omitempty"`
	// EndpointV6 is the public IPv6 a dual-stack relay dials. The Hong Kong
	// hub has no IPv6 and must not be given this address as an Endpoint.
	// Examples use 2001:db8::/32.
	EndpointV6 string `json:"endpoint_v6,omitempty"`
	// EndpointHost (exits only) is a DNS name (dynamic DNS) a dialing hub or
	// nested exit uses instead of EndpointV4. The dialer re-applies it, and
	// so re-resolves it, whenever its handshake with this node is older than
	// a bound (meridian-endpoint-refresh.timer). The gateway and relays never
	// dial exits, so no route or nft set needs the address.
	EndpointHost string `json:"endpoint_host,omitempty"`
	// ViaExit (exits only) names the managed relay exit this exit's single
	// tunnel goes to instead of a hub (nested.go). The exit must dial out
	// (nat_dial_out); the relay exit listens for it at its endpoint.
	ViaExit string `json:"via_exit,omitempty"`
	// External (exits only, unmanaged) makes this an external SOCKS exit
	// reached through a managed carrier exit (nested.go). It has no links,
	// no server and no bundle.
	External *ExternalExit `json:"external,omitempty"`
	// ListenPort is the WireGuard UDP port of the one link this node
	// listens on when that link has no wg_port of its own (a node that
	// listens on several links needs wg_port on each; validation refuses
	// the ambiguity). WSSListenPort (default 443) is its WSS server port.
	ListenPort int `json:"listen_port,omitempty"`

	// ServerID names the managed server (internal/credentials) this node
	// runs on: address, SSH login and pinned host key live there. The
	// gateway is the local host and never has one; two nodes never share
	// one. See docs/architecture.md「服务器、SSH 凭据与 Cloudflare 账户」.
	ServerID string `json:"server_id,omitempty"`

	// SSHHost, SSHPort and SSHUser are the pre-server SSH target. They are
	// migrated into a Server (and cleared) when the panel starts or the
	// topology is saved; a node with ServerID must leave them empty.
	SSHHost string `json:"ssh_host,omitempty"`
	SSHPort int    `json:"ssh_port,omitempty"`
	SSHUser string `json:"ssh_user,omitempty"`

	// HubTier (hub nodes only) is "primary" or "backup". A topology has at
	// most one of each; a lone hub without a tier is the primary (the
	// migration writes it). The primary carries traffic on the main path
	// (gateway → relay → IX → primary); the backup is reached from the
	// gateway by WG over WSS when the whole main path is down. See hubs.go
	// and docs/architecture.md「主枢纽与备用枢纽」.
	HubTier HubTier `json:"hub_tier,omitempty"`
	// IXLine marks the primary hub that IS the IX: a managed, loginable
	// server on the dedicated line. Relays reach it with direct WireGuard
	// at IngressV4 (its domestic-side address, which only accepts the
	// relays); EndpointV4 is its Hong Kong egress address, the one exits
	// that dial in target and the one its tunnels to exits leave from. Its
	// management target is the server record (ServerID), which may be a
	// TCP port-forward on another host. An unmanaged dedicated line keeps
	// the ix role instead.
	IXLine bool `json:"ix_line,omitempty"`
	// IngressV4 (IX-line hub only) is the domestic ingress address relays
	// dial. IngressInterface optionally names the interface that carries
	// it (checked by the preflight, hardened like the WAN interface).
	IngressV4        string `json:"ingress_v4,omitempty"`
	IngressInterface string `json:"ingress_interface,omitempty"`

	WSSListenPort int `json:"wss_listen_port,omitempty"`
	// WSSPathPrefix, TLSCertPath and TLSKeyPath are legacy input only (the
	// fixed path and operator certificate files of the versions before the
	// panel generated them). The panel moves them out of the stored
	// topology when it starts and on every save (api.migrateWSS); the path
	// and the certificate now come from the WSS state (model.WSSState) and
	// the credential store. The compiler never reads them.
	WSSPathPrefix string `json:"wss_path_prefix,omitempty"`
	TLSCertPath   string `json:"tls_cert_path,omitempty"`
	TLSKeyPath    string `json:"tls_key_path,omitempty"`
}

// Link is a drawn edge. Standby links are provisioned and health-checked
// but are not installed as the default route until their mode is selected.
type Link struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Transport Transport `json:"transport"`
	Enabled   bool      `json:"enabled"`
	Standby   bool      `json:"standby"`

	// MTU is the WireGuard interface MTU. Zero selects the transport default.
	// WSSMTU is the second leg of udp_wss_failover (default 1360).
	MTU    int `json:"mtu,omitempty"`
	WSSMTU int `json:"wss_mtu,omitempty"`
	// WGPort is the WireGuard UDP port on the listening end (zero: the
	// listening node's listen_port when it listens on this link only,
	// else 51820 + the link's slot; a UDP+WSS failover link also uses
	// WGPort+1). WSSLocalPort is the wstunnel client's UDP port on
	// 127.0.0.1 of the dialing end (zero: 52000 + slot). The slot is the
	// link's persisted allocation (Topology.Allocations), not its
	// position. See validate.TunnelPorts.
	WGPort       int `json:"wg_port,omitempty"`
	WSSLocalPort int `json:"wss_local_port,omitempty"`

	// Keepalive nil means "use the default (25)". Zero on a NAT dial-out
	// link is an error: PersistentKeepalive must stay on.
	Keepalive *int `json:"keepalive,omitempty"`

	// FromV4 … ToULA override the slot's default tunnel addresses
	// (validation refuses one that overlaps another link's subnet, manual
	// or automatic, or a reserved range).
	FromV4  string `json:"from_v4,omitempty"`
	ToV4    string `json:"to_v4,omitempty"`
	FromULA string `json:"from_ula,omitempty"`
	ToULA   string `json:"to_ula,omitempty"`

	// MeshRoutes (cf_mesh links only) are the CIDRs the exit end's
	// Cloudflare Mesh node advertises. The panel deployment publishes them
	// as Cloudflare routes for this run and withdraws them on failure.
	MeshRoutes []string `json:"mesh_routes,omitempty"`
}

// Rule is either a manual entry (higher priority) or one row of the
// built-in geosite default table.
type Rule struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Manual     bool      `json:"manual"`
	Priority   int       `json:"priority"`
	Enabled    bool      `json:"enabled"`
	Overridden bool      `json:"overridden"`
	MatchType  MatchType `json:"match_type"`
	MatchValue string    `json:"match_value"`

	SourceMAC  string `json:"source_mac,omitempty"`
	SourceIPv4 string `json:"source_ipv4,omitempty"`
	SourceIPv6 string `json:"source_ipv6,omitempty"`

	// TargetGroup or TargetExit, exactly one. TargetExit pins one exit
	// (its own mark; never moved by health or unlock results). TargetGroup
	// follows the group's mode, choice and failover.
	TargetGroup string `json:"target_group,omitempty"`
	TargetExit  string `json:"target_exit,omitempty"`
	// TargetPool and Mode are legacy input only (see MigrateRegionGroups).
	TargetPool string   `json:"target_pool,omitempty"`
	Mode       RuleMode `json:"mode,omitempty"`

	// RequireResidential / RequireV6 are assertions about the target: a
	// target group must carry the same constraint, a target exit must
	// satisfy it. They are not a second place to configure the group.
	RequireResidential bool   `json:"require_residential"`
	RequireV6          bool   `json:"require_v6"`
	Notes              string `json:"notes,omitempty"`

	// Domains are explicit names always emitted into SmartDNS, even before
	// a geosite snapshot is downloaded.
	Domains []string `json:"domains,omitempty"`
	Geosite string   `json:"geosite,omitempty"`

	// RuleSet is the rule-set a MatchRuleSet rule uses (rules.go).
	RuleSet string `json:"rule_set,omitempty"`
	// TargetService points at a service group; TargetAction is "direct" or
	// "reject" (rules.go). With TargetGroup and TargetExit exactly one of
	// the four is set (none for a MatchQUICReject row).
	TargetService string `json:"target_service,omitempty"`
	TargetAction  string `json:"target_action,omitempty"`
	// Origin is "" for a rule made in the panel (or a built-in row) and
	// "mihomo" for a rule written by an import; SourceLine and SourceText
	// are the imported line (1-based) and its text.
	Origin     string `json:"origin,omitempty"`
	SourceLine int    `json:"source_line,omitempty"`
	SourceText string `json:"source_text,omitempty"`
	// Accepted lists the ordering notices the operator accepted for this
	// rule (codes from the import preview, such as "keyword_expanded").
	Accepted []string `json:"accepted,omitempty"`
}

// Settings is the gateway-wide policy that nodes do not repeat.
type Settings struct {
	// Draft allows the editor to persist an incomplete drawing.
	// Apply still refuses while validation errors exist.
	Draft bool `json:"draft"`

	// IXReplacementMode moves traffic onto the pre-provisioned WSS
	// (Aliyun to HK hub first). It does not create tunnels on demand.
	IXReplacementMode bool `json:"ix_replacement_mode"`

	LANInterface  string `json:"lan_interface"`
	GatewayLANIP  string `json:"gateway_lan_ipv4"`
	ROSIPv4       string `json:"ros_ipv4"`
	ROSv6LLA      string `json:"ros_v6_lla"`
	LANIPv6Prefix string `json:"lan_ipv6_prefix"`
	ULAPrefix     string `json:"ula_prefix"`
	PanelBind     string `json:"panel_bind"`

	DomesticDoT []string `json:"domestic_dot"`

	// ClientsIPv6ViaGateway is the operator's statement that LAN clients
	// use this gateway as their IPv6 router (their IPv6 default route points
	// at the gateway's link-local address, docs/test-device.md). False (the
	// default, and every topology saved before the setting existed) means
	// clients take IPv6 from the home router's RA, so IPv6 to a tunnelled
	// destination would leave over the home line, bypassing the gateway:
	// the gateway resolver then returns no AAAA (empty NOERROR) for any
	// name that is not domestic. True returns AAAA for a tunnelled name
	// only when its exit or group carries IPv6 end to end (egress_v6).
	// Domestic names keep their AAAA either way. See docs/architecture.md
	// 「客户端 IPv6 与 AAAA」.
	ClientsIPv6ViaGateway bool `json:"clients_ipv6_via_gateway,omitempty"`

	// UnlistedDomesticDNS asks the domestic resolvers too for a name that
	// no list and no rule matches, and uses their answer only when every
	// address in it is a China address (the chnroute lists); otherwise the
	// default exit's resolver answers. False (the default) keeps the strict
	// behaviour: unlisted names are resolved only through the tunnel. With
	// it on the domestic resolvers see every unlisted name, foreign ones
	// included, and those queries leave over the home line. See
	// docs/architecture.md「未列名单域名的国内解析」.
	UnlistedDomesticDNS bool `json:"unlisted_domestic_dns,omitempty"`

	// TransitV4Prefix and TransitV6Prefix carry the exit choice across
	// hops. WireGuard does not preserve fwmark, so the gateway SNATs LAN
	// sources onto a per-exit transit address. Public NAT/NAT66 still
	// happens only at the exit.
	TransitV4Prefix string `json:"transit_v4_prefix"`
	TransitV6Prefix string `json:"transit_v6_prefix"`

	// UnlockIntervalSec is the scheduled streaming/AI probe period.
	// Zero means 6 hours. Manual rules are not moved by the results.
	UnlockIntervalSec int `json:"unlock_interval_sec,omitempty"`

	// NAT64 is a phase-3 reservation. Enabled must stay false until a
	// translator is actually deployed; the compiler will not install a
	// NAT64 route, so current v4 paths keep working.
	NAT64 NAT64 `json:"nat64"`

	// MeshImage is the OCI image for the hub/exit sidecar. Empty means
	// the official Cloudflare Mesh node, cloudflare/mesh:latest.
	// Pin a tag or digest here; do not invent a name.
	MeshImage string `json:"mesh_image,omitempty"`
	// RegioncheckImage is the OCI image for the exit unlock probe.
	// Empty means lmc999/regioncheck:latest. It stays a separate container.
	RegioncheckImage string `json:"regioncheck_image,omitempty"`

	// ListSource is where geosite categories and the China IP lists are
	// downloaded from: "domestic" (jsDelivr mirror), "overseas" (GitHub
	// raw) or "automatic" (domestic, then overseas). Empty means automatic.
	// The URLs are fixed in internal/lists; see docs/architecture.md「名单源」.
	ListSource string `json:"list_source,omitempty"`

	// DefaultGroup carries foreign traffic no rule matched (formerly the
	// fixed "hk" pool). MigrateRegionGroups sets it to the hk auto group.
	DefaultGroup string `json:"default_group,omitempty"`

	// PathQuality is the relay-sharing policy (pathquality.go). Nil means
	// the defaults; only used with two or more relays.
	PathQuality *PathQuality `json:"path_quality,omitempty"`

	// Sniff is the name-sniffing TCP forwarder (sniff.go). Nil means off.
	Sniff *SniffSettings `json:"sniff,omitempty"`
}

// NAT64 is the placeholder for a future translator in front of a pure-v6
// host. The prefix is not added to any routing table by this version.
type NAT64 struct {
	Reserved bool   `json:"reserved"`
	Enabled  bool   `json:"enabled"`
	Prefix   string `json:"prefix,omitempty"`
}

// Topology is the whole document the panel edits.
type Topology struct {
	Settings Settings `json:"settings"`
	Nodes    []Node   `json:"nodes"`
	Links    []Link   `json:"links"`
	Rules    []Rule   `json:"rules"`
	// RulesOrdered: Rules is in evaluation order (first match wins, top to
	// bottom). False only in a document from before the explicit list,
	// whose order is LegacyRuleLess (MigrateRuleOrder).
	RulesOrdered bool `json:"rules_ordered,omitempty"`
	// RuleSets are the subscribed rule-sets rules can match on;
	// ServiceGroups the switchable targets; MihomoImport the remembered
	// import mapping (rules.go). Their own APIs own them: a whole-document
	// save keeps the stored blocks.
	RuleSets      []RuleSet      `json:"rule_sets,omitempty"`
	ServiceGroups []ServiceGroup `json:"service_groups,omitempty"`
	MihomoImport  *MihomoImport  `json:"mihomo_import,omitempty"`
	// Groups are the region groups exits are selected through. See
	// groups.go and docs/architecture.md「地区组」.
	Groups []RegionGroup `json:"region_groups,omitempty"`
	// RemoteAccess is the road-warrior WireGuard entrance on the gateway
	// (remote_access.go). Nil or disabled compiles to exactly what a
	// topology without it compiles to.
	RemoteAccess *RemoteAccess `json:"remote_access,omitempty"`
	// Allocations is the persisted slot table: the interface, default
	// ports and tunnel subnets of each link and the mark, table and transit
	// addresses of each exit and group (link_allocations.go). The store
	// owns it: a save keeps every stored entry whatever the document says.
	// Nil only in a document from before it existed, whose slots are then
	// its positions (MigrateAllocations).
	Allocations *Allocations `json:"allocations,omitempty"`
}

// Auth methods of a Server.
const (
	AuthPassword = "password"
	AuthKey      = "key"
)

// Host key states of a Server.
const (
	// HostKeyUnknown: never contacted (or the record was cleared).
	HostKeyUnknown = "unknown"
	// HostKeyDiscovered: a fingerprint was seen and awaits explicit
	// confirmation by the operator. Nothing is pinned yet.
	HostKeyDiscovered = "discovered"
	// HostKeyTrusted: the operator confirmed Fingerprint; every connection
	// must present exactly this key.
	HostKeyTrusted = "trusted"
	// HostKeyMismatch: a pinned server presented another key. Connections
	// are refused until the operator confirms the new key or clears the pin.
	HostKeyMismatch = "mismatch"
)

// HostKey is the SSH host identity record of a Server. Fingerprints are
// ssh.FingerprintSHA256 values ("SHA256:…"); none of this is secret.
type HostKey struct {
	State string `json:"state"`
	// Fingerprint is the pinned key (trusted and mismatch states).
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	PinnedAt    string `json:"pinned_at,omitempty"`
	// Source says where the pin came from: "operator" or "mesh_journal"
	// (imported from a Mesh deployment's pinned host during migration).
	Source string `json:"source,omitempty"`
	// Seen is the last fingerprint presented that is not pinned: the one
	// awaiting confirmation (discovered) or the conflicting one (mismatch).
	Seen        string `json:"seen_fingerprint,omitempty"`
	SeenKeyType string `json:"seen_key_type,omitempty"`
	SeenAt      string `json:"seen_at,omitempty"`
}

// Server is a managed remote host (relay, hub, exit…), independent of the
// topology. It carries no secret: CredentialID refers to an SSH credential
// whose material lives only in the restricted credential store.
type Server struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	Port         int      `json:"port"`
	User         string   `json:"user"`
	Auth         string   `json:"auth"`
	CredentialID string   `json:"credential_id,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	HostKey      HostKey  `json:"host_key"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	// MigratedFrom is "node:<id>" for a server created from a topology
	// node's old ssh_* fields.
	MigratedFrom string `json:"migrated_from,omitempty"`
	// LastTest is the last "test connection" result. It is cleared when the
	// endpoint, user, auth method or credential changes, or the credential
	// is rotated: the old result no longer says anything about them.
	LastTest *ConnectionTest `json:"last_test,omitempty"`
}

// ConnectionTest is the outcome of the fixed, read-only "test connection"
// command on a trusted server. Error is scrubbed of every secret.
type ConnectionTest struct {
	At         string `json:"at"`
	OK         bool   `json:"ok"`
	AuthMethod string `json:"auth_method,omitempty"` // password | key
	// Code classifies a failure: unreachable, timeout, auth_failed,
	// auth_method_unavailable, host_key_mismatch, host_key_untrusted,
	// command_failed, ssh_rate_limited.
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
	// RetryAfter (seconds, ssh_rate_limited only): the panel does not
	// connect to this server again before At + RetryAfter.
	RetryAfter int `json:"retry_after,omitempty"`
	// Offered are the login methods the server offered when the login
	// failed (auth_failed / auth_method_unavailable), as far as known.
	Offered    []string `json:"offered_methods,omitempty"`
	OS         string   `json:"os,omitempty"`
	Kernel     string   `json:"kernel,omitempty"`
	Arch       string   `json:"arch,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

func (t Topology) NodeByID(id string) (Node, bool) {
	for _, n := range t.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func (t Topology) GroupByID(id string) (RegionGroup, bool) {
	for _, g := range t.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return RegionGroup{}, false
}

func (t Topology) LinkByID(id string) (Link, bool) {
	for _, l := range t.Links {
		if l.ID == id {
			return l, true
		}
	}
	return Link{}, false
}
