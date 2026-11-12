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
	DualstackRelay bool   `json:"dualstack_relay,omitempty"`
	Pool           string `json:"pool,omitempty"`
	// PoolPriority breaks ties inside a pool. IX-bound members still win.
	// Lower numbers are tried first. Zero is the default.
	PoolPriority int `json:"pool_priority,omitempty"`

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
	ListenPort int    `json:"listen_port,omitempty"`

	SSHHost string `json:"ssh_host,omitempty"`
	SSHPort int    `json:"ssh_port,omitempty"`
	SSHUser string `json:"ssh_user,omitempty"`

	WSSListenPort int    `json:"wss_listen_port,omitempty"`
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
	WGPort int `json:"wg_port,omitempty"`

	// Keepalive nil means "use the default (25)". Zero on a NAT dial-out
	// link is an error: PersistentKeepalive must stay on.
	Keepalive *int `json:"keepalive,omitempty"`

	FromV4  string `json:"from_v4,omitempty"`
	ToV4    string `json:"to_v4,omitempty"`
	FromULA string `json:"from_ula,omitempty"`
	ToULA   string `json:"to_ula,omitempty"`
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

	TargetPool string   `json:"target_pool,omitempty"`
	TargetExit string   `json:"target_exit,omitempty"`
	Mode       RuleMode `json:"mode"`

	RequireResidential bool   `json:"require_residential"`
	RequireV6          bool   `json:"require_v6"`
	Notes              string `json:"notes,omitempty"`

	// Domains are explicit names always emitted into SmartDNS, even before
	// a geosite snapshot is downloaded.
	Domains []string `json:"domains,omitempty"`
	Geosite string   `json:"geosite,omitempty"`
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
}

func (t Topology) NodeByID(id string) (Node, bool) {
	for _, n := range t.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func (t Topology) LinkByID(id string) (Link, bool) {
	for _, l := range t.Links {
		if l.ID == id {
			return l, true
		}
	}
	return Link{}, false
}
