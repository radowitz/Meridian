// Package pathquality is the gateway's relay-sharing controller
// (docs/architecture.md「多中继同时分担」): several domestic relays carry the
// main path (gateway → relay → primary hub) at the same time, each new
// connection is assigned to one relay by flow hash with weights the
// controller sets from measured path quality, and the backup hub takes
// over only when every relay is persistently below the usable floor.
//
// The decision (Step) is a pure function of the compiled Config, the
// previous State and one pass of Measurements, with the clock passed in:
// it is unit-tested with synthetic measurements. The gateway runs it once
// per pass from its compiled failover loop (meridian-failover.sh) as
// "meridian path-step": that process measures (Measure), decides, writes the
// status record /run/meridian/upstream (read by meridian-host's fixed,
// parameterless upstream status read) and prints the decision; the shell
// loop validates the decision against its compiled arrays and applies it
// with the same functions the install uses (one nft batch for the
// assignment map, ip route replace for the relay tables and table 102).
// The panel is not involved: it neither measures nor decides.
package pathquality

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"

	"github.com/radowitz/meridian/internal/model"
)

// ConfigVersion is the compiled config's format.
const ConfigVersion = 1

// Defaults the compiler writes into the config.
const (
	// Buckets is the size of the assignment hash space: weights are
	// normalised to this sum and become ranges of jhash … mod Buckets.
	Buckets = 1000
	// PassInterval is the failover loop's pass period (seconds).
	PassInterval = 5
	// PingCount and PingInterval: the per-pass burst of small echoes on
	// each leg (about one second at 0.2 s spacing).
	PingCount = 5
	// MaxRelays bounds the relays one gateway shares across.
	MaxRelays = 12
)

// Leg is one gateway interface toward a relay (the UDP or the WSS leg of a
// link, or a plain WireGuard link). The first leg is preferred.
type Leg struct {
	Iface string `json:"iface"`
	Mode  string `json:"mode"`
	// Local / Remote are the gateway's and the relay's IPv4 addresses on
	// this leg's tunnel: the download speed test connects from Local to
	// Remote:Config.SpeedPort (the relay's endpoint binds only Remote).
	// Empty without a speed test.
	Local  string `json:"local,omitempty"`
	Remote string `json:"remote,omitempty"`
}

// RelayConfig is one sharing relay as compiled.
type RelayConfig struct {
	ID string `json:"id"`
	// Index is the 1-based position (the nft counter names share_r<i>_*).
	Index int   `json:"index"`
	Legs  []Leg `json:"legs"`
	// Probe is the primary hub's address on this relay's relay→hub tunnel:
	// pinged through each leg from ProbeSource, so a relay that is up while
	// the hub behind it is not counts as down.
	Probe string `json:"probe"`
	// Value is the connection mark (and fwmark bits) of this relay;
	// Table is its routing table on the gateway.
	Value uint32 `json:"value"`
	Table int    `json:"table"`
	// Group is "backup" for a relay of the backup group (tunnelled to the
	// backup hub; Probe is then the backup hub's address on that tunnel),
	// empty for the main group.
	Group string `json:"group,omitempty"`
}

// GroupBackup is RelayConfig.Group of a backup-group relay.
const GroupBackup = "backup"

// BackupConfig is the backup hub's WG over WSS path.
type BackupConfig struct {
	Hub   string `json:"hub"`
	Iface string `json:"iface"`
	Probe string `json:"probe"`
	Value uint32 `json:"value"`
	Table int    `json:"table"`
}

// Config is /etc/meridian/path-quality.json.
type Config struct {
	Version     int           `json:"version"`
	Interval    int           `json:"interval_sec"`
	ProbeSource string        `json:"probe_source"`
	PrimaryHub  string        `json:"primary_hub"`
	Relays      []RelayConfig `json:"relays"`
	Backup      *BackupConfig `json:"backup,omitempty"`
	// BackupHub is set when the backup hub is reached through the backup
	// group of relays (no Backup then): while every main-group relay is
	// completely unreachable the backup group shares the traffic.
	BackupHub string            `json:"backup_hub,omitempty"`
	Settings  model.PathQuality `json:"settings"`
	// SpeedPort is the TCP port of the relays' download endpoint (0: no
	// speed test compiled).
	SpeedPort int `json:"speed_port,omitempty"`

	hash string
}

// Hash identifies the config a state was built for.
func (c Config) Hash() string { return c.hash }

var (
	reIface = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	reID    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
)

// RelayMark is the connection mark of the relay at 1-based index i.
func RelayMark(i int) uint32 { return uint32(i) << 16 }

// BackupMark is the connection mark of connections on the backup hub.
const BackupMark uint32 = 0xfe << 16

// MarkMask selects the relay bits of a mark.
const MarkMask uint32 = 0x00ff0000

// ParseConfig decodes and checks a compiled config strictly.
func ParseConfig(b []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("path-quality config: %w", err)
	}
	if err := c.check(); err != nil {
		return c, err
	}
	sum := sha256.Sum256(b)
	c.hash = hex.EncodeToString(sum[:8])
	return c, nil
}

// LoadConfig reads ParseConfig from a file.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(b)
}

func (c Config) check() error {
	if c.Version != ConfigVersion {
		return fmt.Errorf("path-quality config: version %d, want %d", c.Version, ConfigVersion)
	}
	if c.Interval < 1 || c.Interval > 60 {
		return errors.New("path-quality config: interval out of range")
	}
	if a, err := netip.ParseAddr(c.ProbeSource); err != nil || !a.Is4() {
		return errors.New("path-quality config: probe source is not an IPv4 address")
	}
	if !reID.MatchString(c.PrimaryHub) {
		return errors.New("path-quality config: primary hub id")
	}
	if len(c.Relays) < 1 || len(c.Relays) > MaxRelays {
		return errors.New("path-quality config: relay count out of range")
	}
	seen := map[string]bool{}
	for i, r := range c.Relays {
		if !reID.MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("path-quality config: relay %d id", i+1)
		}
		seen[r.ID] = true
		if r.Index != i+1 || r.Value != RelayMark(i+1) {
			return fmt.Errorf("path-quality config: relay %s index or mark", r.ID)
		}
		if len(r.Legs) < 1 || len(r.Legs) > 2 {
			return fmt.Errorf("path-quality config: relay %s legs", r.ID)
		}
		for _, l := range r.Legs {
			if !reIface.MatchString(l.Iface) || (l.Mode != "udp" && l.Mode != "wss") {
				return fmt.Errorf("path-quality config: relay %s leg", r.ID)
			}
			if c.SpeedPort != 0 {
				lo, err1 := netip.ParseAddr(l.Local)
				re, err2 := netip.ParseAddr(l.Remote)
				if err1 != nil || err2 != nil || !lo.Is4() || !re.Is4() || lo == re {
					return fmt.Errorf("path-quality config: relay %s leg speed-test addresses", r.ID)
				}
			} else if l.Local != "" || l.Remote != "" {
				return fmt.Errorf("path-quality config: relay %s leg addresses without a speed port", r.ID)
			}
		}
		if a, err := netip.ParseAddr(r.Probe); err != nil || !a.Is4() {
			return fmt.Errorf("path-quality config: relay %s probe", r.ID)
		}
		if r.Table < 100 || r.Table > 252 {
			return fmt.Errorf("path-quality config: relay %s table", r.ID)
		}
	}
	if c.BackupHub != "" || hasGroup(c.Relays, GroupBackup) {
		if !reID.MatchString(c.BackupHub) || c.Backup != nil || !hasGroup(c.Relays, GroupBackup) || !hasGroup(c.Relays, "") {
			return errors.New("path-quality config: backup group")
		}
	}
	for _, r := range c.Relays {
		if r.Group != "" && r.Group != GroupBackup {
			return fmt.Errorf("path-quality config: relay %s group", r.ID)
		}
	}
	if c.SpeedPort != 0 && (c.SpeedPort < 1024 || c.SpeedPort > 65535) {
		return errors.New("path-quality config: speed port")
	}
	if b := c.Backup; b != nil {
		if !reID.MatchString(b.Hub) || !reIface.MatchString(b.Iface) || b.Value != BackupMark || b.Table < 100 || b.Table > 252 {
			return errors.New("path-quality config: backup")
		}
		if a, err := netip.ParseAddr(b.Probe); err != nil || !a.Is4() {
			return errors.New("path-quality config: backup probe")
		}
	}
	return nil
}

// RelayByID finds a relay's config.
func (c Config) RelayByID(id string) (RelayConfig, bool) {
	for _, r := range c.Relays {
		if r.ID == id {
			return r, true
		}
	}
	return RelayConfig{}, false
}

func hasGroup(rs []RelayConfig, g string) bool {
	for _, r := range rs {
		if r.Group == g {
			return true
		}
	}
	return false
}

// Grouped: the backup hub is reached through the backup group of relays.
func (c Config) Grouped() bool { return c.BackupHub != "" }

// InGroup: relay r belongs to the group that carries on upstream up
// (every relay without groups).
func (c Config) InGroup(r RelayConfig, up string) bool {
	if !c.Grouped() {
		return true
	}
	return (r.Group == GroupBackup) == (up == UpstreamBackup)
}

// groupOf is c with only the relays of the group carrying on up.
func (c Config) groupOf(up string) Config {
	if !c.Grouped() {
		return c
	}
	g := c
	g.Relays = nil
	for _, r := range c.Relays {
		if c.InGroup(r, up) {
			g.Relays = append(g.Relays, r)
		}
	}
	return g
}

// InitialWeights are the weights an install starts with: equal over the
// main group (every relay without groups), zero for the backup group.
func InitialWeights(c Config) []int {
	out := make([]int, len(c.Relays))
	var idx []int
	for i, r := range c.Relays {
		if c.InGroup(r, UpstreamMain) {
			idx = append(idx, i)
		}
	}
	for k, w := range EqualWeights(len(idx)) {
		out[idx[k]] = w
	}
	return out
}
