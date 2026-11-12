package model

import (
	"net/netip"
	"regexp"
)

// Remote access: devices (phones, laptops) outside the home dial the
// gateway over one WireGuard interface and are treated exactly like LAN
// clients. See docs/architecture.md「远程接入」. Nothing here is secret: the
// gateway's remote-access private key and the optional pre-shared keys live
// in the restricted credential store and are referenced by ID only; device
// private keys are never stored at all.

// RemoteAccessIface is the fixed name of the remote-access interface. It is
// not a gateway tunnel interface: no exit mark may ever leave through it.
const RemoteAccessIface = "mra"

// Defaults of the remote-access settings.
const (
	DefaultRemoteV4Prefix  = "10.67.0.0/24"
	DefaultRemoteV6Prefix  = "fd67::/64"
	DefaultRemoteMTU       = 1380
	DefaultRemoteKeepalive = 25
	// MaxRemoteDevices bounds the device list.
	MaxRemoteDevices = 64
)

// Client modes.
const (
	// RemoteModeFull: AllowedIPs 0.0.0.0/0, ::/0; DNS is the gateway.
	RemoteModeFull = "full"
	// RemoteModeHome: AllowedIPs are the LAN prefixes and the gateway's DNS
	// addresses only. The client's Internet traffic stays outside Meridian.
	RemoteModeHome = "home"
)

// RemoteAccess is the gateway's remote-access entrance.
type RemoteAccess struct {
	Enabled bool `json:"enabled"`
	// Endpoint is what clients dial: a DNS name or an address the user
	// typed. The panel never guesses it.
	Endpoint string `json:"endpoint,omitempty"`
	// ListenPort is the UDP port mra listens on (and the router forwards).
	ListenPort int `json:"listen_port,omitempty"`
	// IPv4Prefix / IPv6Prefix are the device pools; empty means the
	// defaults. The gateway takes the first host of each.
	IPv4Prefix string `json:"ipv4_prefix,omitempty"`
	IPv6Prefix string `json:"ipv6_prefix,omitempty"`
	// MTU and Keepalive go into the client configuration (MTU also on mra).
	// Zero means the default.
	MTU       int `json:"mtu,omitempty"`
	Keepalive int `json:"keepalive,omitempty"`
	// PublicKey is the gateway's remote-access public key; KeyID names its
	// private key in the credential store.
	PublicKey string         `json:"public_key,omitempty"`
	KeyID     string         `json:"key_id,omitempty"`
	Devices   []RemoteDevice `json:"devices,omitempty"`
}

// RemoteDevice is one client peer. Its private key is not stored anywhere.
type RemoteDevice struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Notes   string `json:"notes,omitempty"`
	Mode    string `json:"mode"`
	Enabled bool   `json:"enabled"`
	// PublicKey is the device's WireGuard public key (not secret).
	PublicKey string `json:"public_key"`
	// IPv4 / IPv6 are host addresses inside the pools (no prefix length).
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
	// PSKID names the optional pre-shared key in the credential store.
	PSKID string `json:"psk_id,omitempty"`
	// ConfigFingerprint identifies the server-side values the last
	// delivered client configuration was rendered with (endpoint, port,
	// keys, pools, mode, MTU, keepalive); a mismatch means the client must
	// be regenerated.
	ConfigFingerprint string `json:"config_fingerprint,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	KeyCreatedAt      string `json:"key_created_at,omitempty"`
}

// Active reports whether the entrance is compiled into the data plane.
func (r *RemoteAccess) Active() bool { return r != nil && r.Enabled }

// V4Prefix is the IPv4 device pool (default when empty).
func (r RemoteAccess) V4Prefix() string {
	if r.IPv4Prefix != "" {
		return r.IPv4Prefix
	}
	return DefaultRemoteV4Prefix
}

// V6Prefix is the IPv6 device pool (default when empty).
func (r RemoteAccess) V6Prefix() string {
	if r.IPv6Prefix != "" {
		return r.IPv6Prefix
	}
	return DefaultRemoteV6Prefix
}

// EffectiveMTU is the MTU of mra and of the client configuration.
func (r RemoteAccess) EffectiveMTU() int {
	if r.MTU > 0 {
		return r.MTU
	}
	return DefaultRemoteMTU
}

// EffectiveKeepalive is the client's PersistentKeepalive.
func (r RemoteAccess) EffectiveKeepalive() int {
	if r.Keepalive > 0 {
		return r.Keepalive
	}
	return DefaultRemoteKeepalive
}

// GatewayV4 is the gateway's address in the IPv4 pool (first host).
func (r RemoteAccess) GatewayV4() (netip.Addr, netip.Prefix, bool) {
	p, err := netip.ParsePrefix(r.V4Prefix())
	if err != nil || !p.Addr().Is4() {
		return netip.Addr{}, netip.Prefix{}, false
	}
	p = p.Masked()
	return p.Addr().Next(), p, true
}

// GatewayV6 is the gateway's address in the IPv6 pool (first host).
func (r RemoteAccess) GatewayV6() (netip.Addr, netip.Prefix, bool) {
	p, err := netip.ParsePrefix(r.V6Prefix())
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		return netip.Addr{}, netip.Prefix{}, false
	}
	p = p.Masked()
	return p.Addr().Next(), p, true
}

// DeviceByID finds a device.
func (r RemoteAccess) DeviceByID(id string) (RemoteDevice, bool) {
	for _, d := range r.Devices {
		if d.ID == id {
			return d, true
		}
	}
	return RemoteDevice{}, false
}

// Clone is a deep copy.
func (r *RemoteAccess) Clone() *RemoteAccess {
	if r == nil {
		return nil
	}
	c := *r
	c.Devices = append([]RemoteDevice(nil), r.Devices...)
	return &c
}

// secretIDRe is the shape of a credential-store ID a placeholder may name.
var secretIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

// SecretPlaceholderPrefix starts every secret placeholder the compiler
// writes into a WireGuard config. Only the install boundary replaces it.
const SecretPlaceholderPrefix = "__MERIDIAN_SECRET_"

// SecretPlaceholderRe matches one placeholder and captures the store ID.
var SecretPlaceholderRe = regexp.MustCompile(`__MERIDIAN_SECRET_([a-z][a-z0-9-]{1,63})__`)

// SecretPlaceholder is the stand-in for the credential-store secret id.
// An invalid id yields "" (the compiler never renders one).
func SecretPlaceholder(id string) string {
	if !secretIDRe.MatchString(id) {
		return ""
	}
	return SecretPlaceholderPrefix + id + "__"
}
