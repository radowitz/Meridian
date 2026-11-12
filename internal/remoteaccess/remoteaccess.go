// Package remoteaccess holds the control-plane logic of the gateway's
// remote-access entrance: key generation, device address assignment, the
// one-time client configuration and the router-forward description. The
// data plane is rendered by internal/compile; see docs/architecture.md
// 「远程接入」.
//
// Secrets handled here (a device's private key, a pre-shared key) only
// ever exist in memory and in the single API response that delivers the
// client configuration. Nothing in this package logs or stores them.
package remoteaccess

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"golang.org/x/crypto/curve25519"
)

// Keypair is a WireGuard key pair generated in-process.
type Keypair struct {
	Private string
	Public  string
}

// GenerateKeypair makes a clamped X25519 key pair (what "wg genkey" does).
func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: base64.StdEncoding.EncodeToString(priv[:]), Public: base64.StdEncoding.EncodeToString(pub)}, nil
}

// GeneratePSK makes a 32-byte pre-shared key ("wg genpsk").
func GeneratePSK() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// NewDeviceID returns "dev-" plus 8 random hex digits not in taken.
func NewDeviceID(taken func(string) bool) string {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		id := "dev-" + hex.EncodeToString(b[:])
		if taken == nil || !taken(id) {
			return id
		}
	}
}

// ErrPoolFull means no host number is free in one of the pools.
var ErrPoolFull = errors.New("设备地址池已满")

// AllocateAddresses picks the lowest host number (from 2; the gateway is 1)
// that no existing device uses in either pool, and returns that host in
// both pools. Existing devices keep their addresses.
func AllocateAddresses(ra model.RemoteAccess) (netip.Addr, netip.Addr, error) {
	_, p4, ok4 := ra.GatewayV4()
	_, p6, ok6 := ra.GatewayV6()
	if !ok4 || !ok6 {
		return netip.Addr{}, netip.Addr{}, errors.New("设备地址池无法解析")
	}
	used := map[uint64]bool{}
	for _, d := range ra.Devices {
		if a, err := netip.ParseAddr(d.IPv4); err == nil && p4.Contains(a) {
			used[hostNum4(p4, a)] = true
		}
		if a, err := netip.ParseAddr(d.IPv6); err == nil && p6.Contains(a) {
			used[hostNum6(a)] = true
		}
	}
	max4 := uint64(1)<<(32-p4.Bits()) - 2 // last usable host number
	v6bits := 128 - p6.Bits()
	for h := uint64(2); h <= max4; h++ {
		if v6bits < 64 && h >= uint64(1)<<v6bits {
			break
		}
		if used[h] {
			continue
		}
		return addHost4(p4, h), addHost6(p6, h), nil
	}
	return netip.Addr{}, netip.Addr{}, ErrPoolFull
}

func hostNum4(p netip.Prefix, a netip.Addr) uint64 {
	x, y := a.As4(), p.Masked().Addr().As4()
	return uint64(be32(x) - be32(y))
}

func hostNum6(a netip.Addr) uint64 {
	b := a.As16()
	var v uint64
	for _, c := range b[8:] {
		v = v<<8 | uint64(c)
	}
	return v
}

func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func addHost4(p netip.Prefix, h uint64) netip.Addr {
	v := be32(p.Masked().Addr().As4()) + uint32(h)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func addHost6(p netip.Prefix, h uint64) netip.Addr {
	b := p.Masked().Addr().As16()
	for i := 15; i >= 8 && h > 0; i-- {
		s := uint64(b[i]) + h&0xff
		b[i] = byte(s)
		h = h>>8 + s>>8
	}
	return netip.AddrFrom16(b)
}

// EndpointString formats endpoint:port, bracketing an IPv6 literal.
func EndpointString(endpoint string, port int) string {
	if a, err := netip.ParseAddr(endpoint); err == nil && a.Is6() {
		return fmt.Sprintf("[%s]:%d", a, port)
	}
	return fmt.Sprintf("%s:%d", endpoint, port)
}

// AllowedIPs is the client's AllowedIPs for a mode.
func AllowedIPs(t model.Topology, mode string) []string {
	ra := *t.RemoteAccess
	if mode == model.RemoteModeFull {
		return []string{"0.0.0.0/0", "::/0"}
	}
	var out []string
	if p, err := netip.ParsePrefix(t.Settings.GatewayLANIP); err == nil {
		out = append(out, p.Masked().String())
	} else {
		out = append(out, "192.168.100.0/24")
	}
	if t.Settings.LANIPv6Prefix != "" {
		out = append(out, t.Settings.LANIPv6Prefix)
	}
	gw4, _, _ := ra.GatewayV4()
	gw6, _, _ := ra.GatewayV6()
	return append(out, gw4.String()+"/32", gw6.String()+"/128")
}

// DNS is the resolver a client uses: the gateway's addresses in the pools.
func DNS(ra model.RemoteAccess) []string {
	gw4, _, _ := ra.GatewayV4()
	gw6, _, _ := ra.GatewayV6()
	return []string{gw4.String(), gw6.String()}
}

// Fingerprint identifies every server-side value a delivered client
// configuration embeds. When it changes, the client must be regenerated.
func Fingerprint(t model.Topology, d model.RemoteDevice) string {
	ra := *t.RemoteAccess
	h := sha256.New()
	for _, v := range []string{
		ra.Endpoint, fmt.Sprint(ra.ListenPort), ra.PublicKey, ra.V4Prefix(), ra.V6Prefix(),
		fmt.Sprint(ra.EffectiveMTU()), fmt.Sprint(ra.EffectiveKeepalive()),
		d.Mode, d.PublicKey, d.IPv4, d.IPv6, d.PSKID, strings.Join(AllowedIPs(t, d.Mode), ","),
	} {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ClientConfig is the one-time configuration of a device: the only place
// its private key (and pre-shared key) ever appears.
type ClientConfig struct {
	Text     string `json:"text"`
	Filename string `json:"filename"`
	Mode     string `json:"mode"`
	// Explanation says what the mode does and does not cover.
	Explanation string `json:"explanation"`
	// ShownOnce: this text is not stored; it cannot be fetched again.
	ShownOnce bool `json:"shown_once"`
}

// RenderClient builds the wg-quick configuration for d. private and psk
// are the device's secrets (psk may be empty).
func RenderClient(t model.Topology, d model.RemoteDevice, private, psk string) ClientConfig {
	ra := *t.RemoteAccess
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Meridian remote access, device %s (%s)\n", d.ID, d.Mode)
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", private)
	fmt.Fprintf(&sb, "Address = %s/32, %s/128\n", d.IPv4, d.IPv6)
	fmt.Fprintf(&sb, "DNS = %s\n", strings.Join(DNS(ra), ", "))
	fmt.Fprintf(&sb, "MTU = %d\n", ra.EffectiveMTU())
	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", ra.PublicKey)
	if psk != "" {
		fmt.Fprintf(&sb, "PresharedKey = %s\n", psk)
	}
	fmt.Fprintf(&sb, "Endpoint = %s\n", EndpointString(ra.Endpoint, ra.ListenPort))
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", strings.Join(AllowedIPs(t, d.Mode), ", "))
	fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", ra.EffectiveKeepalive())
	return ClientConfig{
		Text:        sb.String(),
		Filename:    Filename(d.ID),
		Mode:        d.Mode,
		Explanation: ModeExplanation(d.Mode),
		ShownOnce:   true,
	}
}

// Filename is a suggested file name. wg-quick on Linux uses the file name
// as the interface name (at most 15 characters).
func Filename(deviceID string) string {
	id := strings.TrimPrefix(deviceID, "dev-")
	if len(id) > 10 {
		id = id[:10]
	}
	return "mrd" + id + ".conf"
}

// ModeExplanation is shown with every configuration.
func ModeExplanation(mode string) string {
	if mode == model.RemoteModeHome {
		return "仅家网模式：只有家里局域网的地址和网关的 DNS 地址走隧道。手机访问公网仍走它当前的网络（蜂窝或别处的 Wi-Fi），" +
			"不经过 Meridian，国内直连、境外走隧道和防泄漏规则都不作用于这部分流量；DNS 是否全部交给网关取决于手机系统，" +
			"部分查询可能仍走当前网络的 DNS。要让 Meridian 接管全部流量请用全隧道模式。"
	}
	return "全隧道模式：手机的全部 IPv4/IPv6 流量和 DNS 都进隧道，由网关按家里局域网的规则处理：国内直连（从家里宽带出去）、" +
		"境外走 Meridian 隧道、未分类拒绝，DNS 只能用网关。设备之间不能互访；面板只对家里局域网开放。"
}

// RouterForward describes the forward the user must create on the home
// router. The panel never changes the router and never guesses the public
// address.
type RouterForward struct {
	Protocol        string `json:"protocol"`
	ExternalPort    int    `json:"external_port"`
	InternalAddress string `json:"internal_address"`
	InternalPort    int    `json:"internal_port"`
	Description     string `json:"description"`
	IPv6Note        string `json:"ipv6_note"`
}

// Forward is the router-forward description for the current settings.
func Forward(t model.Topology) RouterForward {
	ra := t.RemoteAccess
	port := 0
	if ra != nil {
		port = ra.ListenPort
	}
	gw := "192.168.100.88"
	if p, err := netip.ParsePrefix(t.Settings.GatewayLANIP); err == nil {
		gw = p.Addr().String()
	} else if a, err := netip.ParseAddr(t.Settings.GatewayLANIP); err == nil {
		gw = a.String()
	}
	f := RouterForward{Protocol: "udp", ExternalPort: port, InternalAddress: gw, InternalPort: port}
	if port == 0 {
		f.Description = "先填写监听端口，才能给出路由器上的转发设置。"
		return f
	}
	f.Description = fmt.Sprintf("在家里的路由器上添加端口转发（dst-nat）：协议 UDP，外部端口 %d → 内部地址 %s，内部端口 %d。"+
		"外部端口必须等于设备配置里的端口 %d。如果网关的局域网地址是 DHCP 分配的，请在路由器上把它固定下来。面板不会修改路由器。",
		port, gw, port, port)
	f.IPv6Note = fmt.Sprintf("如果 Endpoint 用的是网关的 IPv6 全局地址（或指向它的 AAAA 记录），路由器的 IPv6 防火墙还要放行到该地址的 UDP %d；"+
		"网关的 IPv6 地址来自 SLAAC，可能随前缀变化，面板不猜测它。", port)
	return f
}
