package linkjournal

// The source inventory: every event class, the fixed source on the gateway
// it is read from, how, how often, and how strong the evidence is. The
// collector reads local state only; it opens no IP socket, sends nothing
// and contacts no other node. Inventory() carries the same table for the
// panel and docs/architecture.md「链路日志」repeats it.
//
//	class          source (Source* below)   read how                                   cadence        evidence
//	-------------  -----------------------  -----------------------------------------  -------------  -----------------------------------------
//	path           upstream_record          UpstreamFile, the record the gateway's     every pass     the failover loop's own decision and its
//	(dual hub /                             failover loop writes each pass (bounded    (10 s; the     end-to-end ping of each path: direct for
//	 relay                                  read, strict grammar): path in use, hub,   loop writes    "which path carries", a probe result for
//	 sharing)                               tier, health of the last pass              every 5 s)     "down / degraded"
//	path           route_table              "ip -4 -o route show table 102" (fixed     every pass     the kernel's route itself: direct. A
//	(one relay,                             argv): the interface the foreign default                  single-relay gateway's loop records
//	 no backup)                             route points at                                           nothing, so there is no health or reason
//	relay          upstream_record          the relay lines of the same record         every pass     the sharing controller's own status and
//	                                        (relay sharing only): status, reason,                     reason (measured loss, RTT, delivery)
//	                                        weight, the leg in use
//	tunnel         wg_handshake             "wg show <iface> latest-handshakes" for    every 3rd      the kernel's handshake time: direct for
//	                                        each tunnel interface of the compiled      pass (30 s)    "no session"; a tunnel is called stale
//	                                        object list (names checked against the                    only after HandshakeStaleS without a new
//	                                        managed pattern; never "dump")                            handshake, so up to that late
//	wss            wss_unit + wg_handshake  "systemctl is-active <unit>" for each      every 3rd      indirect: the client process runs, and
//	                                        wstunnel client unit of the object list,   pass           the tunnel inside it has (not) completed
//	                                        with the handshake of the tunnel it                       a handshake. The WebSocket session
//	                                        carries                                                   itself is not read
//	external_exit  sniff_selfcheck          GET /v1/health on the forwarder's status   every 3rd      the gateway's own check of that exit's
//	                                        socket (uid 0 only): the last self-check   pass; the      resolver through the tunnel path. It says
//	                                        result of the target "exit:<id>" of an     forwarder      "the gateway's check failed", not "the
//	                                        external SOCKS exit                        checks every   proxy is down": the carrier's own health
//	                                                                                   15 min         check is not readable from here
//	sniff_target   sniff_selfcheck          the same answer, every other target        same           the same check for a region group, an
//	                                        (group, exit, direct)                                     exit or the domestic resolver
//	collector      (the collector itself)   a pass later than GapAfter after the       every pass     direct
//	                                        previous one; a source that stopped
//	                                        answering; a new object list
//
// Not readable through any existing fixed channel, and therefore not
// recorded (NotInScope): the carrier's health check of an external exit
// (meridian-ext-health on the carrier node), a hub's choice of member for a
// region group (read by the panel over SSH on demand, not by the gateway),
// the relays' and hubs' own failover, the remote end's handshakes, and the
// results of the panel's unlock probes (stored by the panel, not on the
// host). No capability is added to a remote node for any of them.
//
// Programs. The collector runs three programs, each with one fixed
// argument list built here (wgArgs, unitArgs, routeArgs) from names that
// passed the object list's validation; no shell, no PATH lookup, no
// argument from a request. Reading a WireGuard interface needs
// CAP_NET_ADMIN (the kernel answers the device query to no one else),
// which is the collector unit's only capability; nothing here changes an
// interface, a route, a rule set or a unit.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// Sources.
const (
	SourceUpstream  = "upstream_record"
	SourceRoute     = "route_table"
	SourceHandshake = "wg_handshake"
	SourceWSSUnit   = "wss_unit"
	SourceSelfCheck = "sniff_selfcheck"
	SourceCollector = "collector"
)

// Fixed places the collector reads (a test in package compile keeps them
// equal to what the gateway's files use).
const (
	// UpstreamFile is the record of the gateway's failover loop
	// (compile.UpstreamStateFile).
	UpstreamFile = "/run/meridian/upstream"
	// MaxUpstreamFile bounds the read of it.
	MaxUpstreamFile = 8192
	// SniffSocket is the forwarder's status socket (compile.SniffStatusSocket).
	SniffSocket = "/run/meridian-sniff/status.sock"
	// ForeignTable is the gateway's policy table of the foreign path.
	ForeignTable = 102
	// MaxConfig bounds the object list file.
	MaxConfig = 256 << 10
)

// Object kinds.
const (
	KindUpstream  = "upstream"
	KindHealth    = "upstream_health"
	KindDesignate = "designated"
	KindRelayLeg  = "relay_leg"
	KindRelay     = "relay"
	KindRelayQoS  = "relay_qos"
	KindTunnel    = "tunnel"
	KindWSS       = "wss"
	KindExternal  = "external_exit"
	KindTarget    = "sniff_target"
	// GatewayID is the id of the gateway-wide objects of class path.
	GatewayID = "gateway"
)

// States the collector derives itself (the others are the source's words).
const (
	HealthOK       = "ok"
	HealthDown     = "down"
	HealthDegraded = "degraded"
	PathNone       = "none"
	PathOther      = "other"

	TunnelOK     = "ok"
	TunnelStale  = "stale"
	TunnelNever  = "never"
	TunnelAbsent = "absent"

	WSSConnected    = "connected"
	WSSDisconnected = "disconnected"
	WSSStopped      = "stopped"
	// WSSRunning: the client runs and its tunnel has no keepalive, so the
	// tunnel's handshake is not judged.
	WSSRunning = "running"

	CheckOK        = "check_ok"
	CheckFailed    = "check_failed"
	CheckUnchecked = "unchecked"
)

// Upstream modes of the object list.
const (
	ModeSingle = "single"
	ModeDual   = "dual"
	ModeShare  = "share"
)

// Defaults of the object list.
const (
	DefaultIntervalS = 10
	DefaultSlowEvery = 3
	// DefaultHandshakeStaleS is WireGuard's Reject-After-Time: a session
	// without a new handshake for this long carries nothing any more.
	DefaultHandshakeStaleS = 180
	// DefaultUpstreamStaleS: the failover loop writes its record every 5 s;
	// a record older than this means the loop is not running.
	DefaultUpstreamStaleS = 60
	// DefaultSelfCheckMaxAgeS: the forwarder checks every 15 minutes; a
	// result older than this is not a reading any more.
	DefaultSelfCheckMaxAgeS = 40 * 60
	// SourceFailPasses: a source must fail this many reads in a row before
	// it is recorded as unavailable.
	SourceFailPasses = 3
)

// Config is the compiled object list (ConfigPath): what the collector
// reads and what each object is. It holds topology names only.
type Config struct {
	Version int    `json:"version"`
	Gateway string `json:"gateway"`
	// IntervalS is the pass period; the handshake, unit and self-check
	// sources are read every SlowEvery-th pass.
	IntervalS       int `json:"interval_s"`
	SlowEvery       int `json:"slow_every"`
	HandshakeStaleS int `json:"handshake_stale_s"`
	UpstreamStaleS  int `json:"upstream_stale_s"`
	// Mode: single (one relay, no backup hub: the route table is read),
	// dual (a backup hub) or share (relay sharing): the failover record.
	Mode    string         `json:"mode"`
	Paths   []PathConfig   `json:"paths"`
	Tunnels []TunnelConfig `json:"tunnels"`
	WSS     []WSSConfig    `json:"wss"`
	// Sniff is set when the name-sniffing forwarder is installed.
	Sniff *SniffConfig `json:"sniff,omitempty"`
}

// PathConfig is one way out of the foreign table.
type PathConfig struct {
	// Name: the failover loop's name of the path (udp, wss, backup, direct),
	// or "relay" for a sharing relay's leg.
	Name  string `json:"name"`
	Iface string `json:"iface"`
	Link  string `json:"link,omitempty"`
	// Peer is the node on the other end (the relay, or the backup hub).
	Peer string `json:"peer,omitempty"`
	Hub  string `json:"hub,omitempty"`
	Tier string `json:"tier,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// TunnelConfig is one WireGuard interface of the gateway.
type TunnelConfig struct {
	Iface    string `json:"iface"`
	Link     string `json:"link"`
	Mode     string `json:"mode"`
	Peer     string `json:"peer"`
	PeerRole string `json:"peer_role,omitempty"`
	Standby  bool   `json:"standby,omitempty"`
	// KeepaliveS is the interface's PersistentKeepalive. 0: an idle tunnel
	// has no reason to handshake, so its handshake age says nothing and it
	// is not read.
	KeepaliveS int `json:"keepalive_s"`
}

// WSSConfig is one wstunnel client of the gateway.
type WSSConfig struct {
	Unit  string `json:"unit"`
	Link  string `json:"link"`
	Iface string `json:"iface"`
	Peer  string `json:"peer,omitempty"`
}

// SniffConfig says what the forwarder's self-check targets are.
type SniffConfig struct {
	SelfCheckMaxAgeS int           `json:"selfcheck_max_age_s"`
	Targets          []SniffTarget `json:"targets"`
}

// SniffTarget is one self-check target: an exit, a region group or the
// domestic resolver ("direct").
type SniffTarget struct {
	Target string `json:"target"`
	// Kind: exit | region_group | direct.
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
	// External: an external SOCKS exit; Carrier the node that carries it.
	External bool   `json:"external,omitempty"`
	Carrier  string `json:"carrier,omitempty"`
}

var (
	// IfaceRe: a managed tunnel interface (never mra or mmesh).
	IfaceRe = regexp.MustCompile(`^m[0-9]{2,3}w?$`)
	// UnitRe: a wstunnel client unit.
	UnitRe   = regexp.MustCompile(`^wstunnel-client-[a-z0-9][a-z0-9-]{0,40}\.service$`)
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	targetRe = regexp.MustCompile(`^(direct|(exit|group):[A-Za-z0-9][A-Za-z0-9._@-]{0,63})$`)
)

// Limits of the object list. They are above what a topology can compile to
// (99 link slots of at most two interfaces each, 240 exit and group marks):
// a list the compiler can produce is never refused here, because a refused
// list would keep the collector's unit from starting and fail the install
// that carries it (a test in package compile keeps the two in step).
const (
	MaxPaths   = 200
	MaxTunnels = 200
	MaxWSS     = 100
	MaxTargets = 256
)

// Validate checks every name of the object list against the pattern the
// compiler can produce. Nothing else is ever passed to a program.
func (c Config) Validate() error {
	name := func(what, v string, optional bool) error {
		if v == "" && optional {
			return nil
		}
		if !nameRe.MatchString(v) {
			return fmt.Errorf("%s %q is not a name", what, v)
		}
		return nil
	}
	switch {
	case c.Version != 1:
		return fmt.Errorf("version %d is not supported", c.Version)
	case c.Mode != ModeSingle && c.Mode != ModeDual && c.Mode != ModeShare:
		return fmt.Errorf("mode %q", c.Mode)
	case c.IntervalS < 2 || c.IntervalS > 300:
		return errors.New("interval_s: 2..300")
	case c.SlowEvery < 1 || c.SlowEvery > 30:
		return errors.New("slow_every: 1..30")
	case c.HandshakeStaleS < 5 || c.HandshakeStaleS > 3600:
		return errors.New("handshake_stale_s: 5..3600")
	case c.UpstreamStaleS < 5 || c.UpstreamStaleS > 3600:
		return errors.New("upstream_stale_s: 5..3600")
	case len(c.Paths) > MaxPaths || len(c.Tunnels) > MaxTunnels || len(c.WSS) > MaxWSS:
		return errors.New("too many paths, tunnels or WSS carriers")
	}
	if err := name("gateway", c.Gateway, false); err != nil {
		return err
	}
	for _, p := range c.Paths {
		if !IfaceRe.MatchString(p.Iface) {
			return fmt.Errorf("path interface %q is not a managed tunnel interface", p.Iface)
		}
		for what, v := range map[string]string{"path name": p.Name, "path link": p.Link, "path peer": p.Peer, "path hub": p.Hub, "path tier": p.Tier, "path mode": p.Mode} {
			if err := name(what, v, what != "path name"); err != nil {
				return err
			}
		}
	}
	seen := map[string]bool{}
	for _, t := range c.Tunnels {
		if !IfaceRe.MatchString(t.Iface) || seen[t.Iface] {
			return fmt.Errorf("tunnel interface %q is not a managed tunnel interface or is listed twice", t.Iface)
		}
		seen[t.Iface] = true
		for what, v := range map[string]string{"tunnel link": t.Link, "tunnel mode": t.Mode, "tunnel peer": t.Peer, "tunnel peer role": t.PeerRole} {
			if err := name(what, v, what == "tunnel peer role"); err != nil {
				return err
			}
		}
		if t.KeepaliveS < 0 || t.KeepaliveS > 65535 {
			return errors.New("tunnel keepalive_s")
		}
	}
	units := map[string]bool{}
	for _, w := range c.WSS {
		if !UnitRe.MatchString(w.Unit) || units[w.Unit] {
			return fmt.Errorf("unit %q is not a wstunnel client unit or is listed twice", w.Unit)
		}
		units[w.Unit] = true
		if !IfaceRe.MatchString(w.Iface) {
			return fmt.Errorf("WSS interface %q is not a managed tunnel interface", w.Iface)
		}
		if err := name("WSS link", w.Link, false); err != nil {
			return err
		}
		if err := name("WSS peer", w.Peer, true); err != nil {
			return err
		}
	}
	if s := c.Sniff; s != nil {
		if s.SelfCheckMaxAgeS < 60 || s.SelfCheckMaxAgeS > 86400 || len(s.Targets) > MaxTargets {
			return errors.New("sniff: selfcheck_max_age_s 60..86400, at most " + strconv.Itoa(MaxTargets) + " targets")
		}
		ts := map[string]bool{}
		for _, t := range s.Targets {
			if !targetRe.MatchString(t.Target) || ts[t.Target] {
				return fmt.Errorf("self-check target %q is not a target name or is listed twice", t.Target)
			}
			ts[t.Target] = true
			if t.Kind != "exit" && t.Kind != "region_group" && t.Kind != "direct" {
				return fmt.Errorf("self-check target kind %q", t.Kind)
			}
			if err := name("target id", t.ID, t.Kind == "direct"); err != nil {
				return err
			}
			if err := name("target carrier", t.Carrier, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseConfig reads an object list strictly (unknown fields refused).
func ParseConfig(b []byte) (Config, error) {
	var c Config
	if len(b) > MaxConfig {
		return c, errors.New("object list too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("object list: %w", err)
	}
	return c, c.Validate()
}

// Digest identifies the object list.
func (c Config) Digest() string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// Object is one object the list names: what the journal can hold events of.
type Object struct {
	Class string `json:"class"`
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
	// Observed false: listed, but not read (Note says why).
	Observed bool   `json:"observed"`
	Note     string `json:"note,omitempty"`
}

// Objects lists every object of the list, observed or not.
func (c Config) Objects() []Object {
	var out []Object
	add := func(class, kind, id, label string) {
		out = append(out, Object{Class: class, Kind: kind, ID: id, Label: label, Observed: true})
	}
	add(ClassPath, KindUpstream, GatewayID, "承载路径")
	if c.Mode != ModeSingle {
		add(ClassPath, KindHealth, GatewayID, "承载路径的探测结果")
	}
	if c.Mode == ModeShare {
		add(ClassPath, KindDesignate, GatewayID, "路由表 102 跟随的中继")
		for _, r := range c.relays() {
			add(ClassRelay, KindRelay, r, "中继 "+r+"（分担）")
			add(ClassPath, KindRelayLeg, r, "到中继 "+r+" 使用的腿")
			add(ClassRelay, KindRelayQoS, r, "中继 "+r+" 的测速结论")
		}
	}
	for _, t := range c.Tunnels {
		o := Object{Class: ClassTunnel, Kind: KindTunnel, ID: t.Iface, Label: t.label(), Observed: t.KeepaliveS > 0}
		if !o.Observed {
			o.Note = "这条链路关闭了保活（keepalive 为 0）：空闲的隧道不会重新握手，握手时间说明不了通断，所以不记录"
		}
		out = append(out, o)
	}
	for _, w := range c.WSS {
		add(ClassWSS, KindWSS, w.Link, w.label())
	}
	if c.Sniff != nil {
		for _, t := range c.Sniff.Targets {
			class, kind, id := t.Object()
			add(class, kind, id, t.label())
		}
	}
	return out
}

// Known reports whether the list names the object.
func (c Config) Known(kind, id string) bool {
	for _, o := range c.Objects() {
		if o.Kind == kind && o.ID == id {
			return true
		}
	}
	return false
}

func (c Config) relays() []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range c.Paths {
		if p.Name == "relay" && p.Peer != "" && !seen[p.Peer] {
			seen[p.Peer] = true
			out = append(out, p.Peer)
		}
	}
	return out
}

func modeText(m string) string {
	switch m {
	case "udp":
		return "UDP 腿"
	case "wss":
		return "WSS 腿"
	}
	return m
}

func (t TunnelConfig) label() string {
	s := fmt.Sprintf("隧道 %s：链路 %s，到 %s（%s）", t.Iface, t.Link, t.Peer, modeText(t.Mode))
	if t.Standby {
		s += "，备用"
	}
	return s
}

func (w WSSConfig) label() string {
	return fmt.Sprintf("WSS 承载 %s：%s，承载隧道 %s", w.Link, w.Unit, w.Iface)
}

// Object is the journal object a self-check target is recorded as.
func (t SniffTarget) Object() (class, kind, id string) {
	if t.External && t.Kind == "exit" {
		return ClassExternalExit, KindExternal, t.ID
	}
	return ClassSniffTarget, KindTarget, t.Target
}

func (t SniffTarget) label() string {
	switch {
	case t.External && t.Kind == "exit" && t.Carrier != "":
		return "外部出口 " + t.ID + "（由 " + t.Carrier + " 承载）"
	case t.External && t.Kind == "exit":
		return "外部出口 " + t.ID
	case t.Kind == "exit":
		return "自检目标：出口 " + t.ID
	case t.Kind == "region_group":
		return "自检目标：地区组 " + t.ID
	}
	return "自检目标：直连（国内解析器）"
}

// ------------------------------------------------------ states and levels ---

// Levels of a state.
const (
	LevelOK       = "ok"
	LevelAbnormal = "abnormal"
	LevelInfo     = "info"
)

// StateInfo names one state of a kind.
type StateInfo struct {
	State string `json:"state"`
	Label string `json:"label"`
	Level string `json:"level"`
}

// KindInfo describes one object kind: its class, what it is and its states.
// Open: its states are topology names (a path, a relay) beyond the listed
// ones.
type KindInfo struct {
	Class  string      `json:"class"`
	Kind   string      `json:"kind"`
	Label  string      `json:"label"`
	Open   bool        `json:"open,omitempty"`
	States []StateInfo `json:"states"`
}

// Kinds is the catalogue of object kinds and their states.
var Kinds = []KindInfo{
	{Class: ClassPath, Kind: KindUpstream, Label: "承载路径（网关的境外流量现在走哪条路）", Open: true, States: []StateInfo{
		{"udp", "主链路，到中继走 UDP 腿", LevelOK}, {"wss", "主链路，到中继走 WSS 腿", LevelInfo}, {"main", "主链路（经分担中的中继）", LevelOK},
		{"direct", "家里直连枢纽的 WSS", LevelInfo}, {"backup", "备用枢纽", LevelAbnormal}, {PathNone, "路由表里没有可用的路径（只剩黑洞）", LevelAbnormal}, {PathOther, "不在对象清单里的接口", LevelInfo}}},
	{Class: ClassPath, Kind: KindHealth, Label: "承载路径的探测结果（故障切换服务上一轮的结论）", States: []StateInfo{
		{HealthOK, "当前路径有应答", LevelOK}, {HealthDegraded, "所有中继都低于可用下限，勉强承载", LevelAbnormal}, {HealthDown, "没有任何路径应答", LevelAbnormal}}},
	{Class: ClassPath, Kind: KindDesignate, Label: "路由表 102 跟随的中继（本机发起的连接走它）", Open: true, States: []StateInfo{{"backup", "备用枢纽", LevelAbnormal}}},
	{Class: ClassPath, Kind: KindRelayLeg, Label: "到某台中继使用的腿", Open: true, States: []StateInfo{{"udp", "UDP 腿", LevelOK}, {"wss", "WSS 腿（伴随承载接管）", LevelInfo}}},
	{Class: ClassRelay, Kind: KindRelay, Label: "中继在分担里的状态（分担控制器的结论）", States: []StateInfo{
		{"active", "在分担中", LevelOK}, {"reduced", "轻度变差，权重被压低", LevelInfo}, {"standby", "轻度变差，不再接新连接", LevelInfo},
		{"evicted", "被剔除（低于可用下限或没有应答）", LevelAbnormal}, {"recovering", "恢复中，权重逐步加回", LevelInfo}, {"disabled", "手动停用", LevelInfo}}},
	{Class: ClassRelay, Kind: KindRelayQoS, Label: "中继的测速结论（每半小时下载测速判定是否被限速）", States: []StateInfo{
		{"ok", "测速正常", LevelOK}, {"throttled", "连续两次低于基准的阈值：判定被限速（qos_throttled），其他中继承载", LevelAbnormal},
		{"unknown", "还没有有效测速", LevelInfo}, {"off", "测速已关闭", LevelInfo}}},
	{Class: ClassTunnel, Kind: KindTunnel, Label: "隧道握手", States: []StateInfo{
		{TunnelOK, "握手正常", LevelOK}, {TunnelStale, "握手超时（视为不通）", LevelAbnormal}, {TunnelNever, "接口起来之后还没有握手成功过", LevelAbnormal}, {TunnelAbsent, "接口不存在", LevelAbnormal}}},
	{Class: ClassWSS, Kind: KindWSS, Label: "WSS 伴随承载（wstunnel 客户端）", States: []StateInfo{
		{WSSConnected, "客户端在运行，里面的隧道握手正常", LevelOK}, {WSSDisconnected, "客户端在运行，但里面的隧道握手超时", LevelAbnormal}, {WSSStopped, "客户端没有运行", LevelAbnormal},
		{WSSRunning, "客户端在运行（这条链路关闭了保活，隧道握手不作判断）", LevelInfo}}},
	{Class: ClassExternalExit, Kind: KindExternal, Label: "外部出口（网关自检的结果，不是承载节点上的健康检查）", States: []StateInfo{
		{CheckOK, "网关自检通过", LevelOK}, {CheckFailed, "网关自检失败", LevelAbnormal}, {CheckUnchecked, "没有检查", LevelInfo}}},
	{Class: ClassSniffTarget, Kind: KindTarget, Label: "嗅探转发服务的自检目标", States: []StateInfo{
		{CheckOK, "自检通过", LevelOK}, {CheckFailed, "自检失败", LevelAbnormal}, {CheckUnchecked, "没有检查", LevelInfo}}},
	{Class: ClassCollector, Kind: KindCollector, Label: "采集空窗", States: []StateInfo{{StateUnknown, "未知（没有采集）", LevelAbnormal}, {StateCollecting, "采集中", LevelOK}}},
	{Class: ClassCollector, Kind: KindSource, Label: "数据来源是否可读", States: []StateInfo{{StateSourceOK, "可读", LevelOK}, {StateUnavailable, "读不到", LevelAbnormal}}},
	{Class: ClassCollector, Kind: KindConfig, Label: "对象清单更新", Open: true, States: []StateInfo{}},
}

// Level judges a state of a kind: ok, abnormal or info (a state of an open
// kind that is not listed is a topology name: info).
func Level(kind, state string) string {
	for _, k := range Kinds {
		if k.Kind != kind {
			continue
		}
		for _, s := range k.States {
			if s.State == state {
				return s.Level
			}
		}
	}
	return LevelInfo
}

// SourceInfo is one row of the source inventory.
type SourceInfo struct {
	Class      string `json:"class"`
	ClassLabel string `json:"class_label"`
	// Events: what is recorded.
	Events string `json:"events"`
	Source string `json:"source"`
	// How it is read; Cadence how often; Evidence how strong it is and what
	// it does not prove.
	How      string `json:"how"`
	Cadence  string `json:"cadence"`
	Strength string `json:"strength"`
	Evidence string `json:"evidence"`
}

// Excluded is something the gateway cannot read through an existing fixed
// channel: not recorded.
type Excluded struct {
	What string `json:"what"`
	Why  string `json:"why"`
	// Instead: what the journal records that is nearest to it ("" nothing).
	Instead string `json:"instead,omitempty"`
}

// Evidence strengths.
const (
	StrengthDirect   = "direct"
	StrengthProbe    = "probe"
	StrengthIndirect = "indirect"
)

// Inventory is the source inventory (the table at the top of this file).
func Inventory() []SourceInfo {
	return []SourceInfo{
		{Class: ClassPath, ClassLabel: "承载路径", Events: "网关的境外流量走哪条路径：主链路经哪条腿或哪台中继、切到备用枢纽、切回；以及故障切换服务对路径的探测结论（有应答 / 全部不通 / 勉强承载）",
			Source: SourceUpstream, How: "读网关故障切换服务每一轮写的固定文件 " + UpstreamFile + "（限长、按固定格式解析，不执行任何命令）；只有一台中继且没有备用枢纽的网关不写这个文件，改读路由表（见下一行）",
			Cadence: "每 10 秒读一次；故障切换服务每 5 秒写一次", Strength: StrengthDirect,
			Evidence: "切换是故障切换服务自己的决定，读到的就是它记下的结果；「不通 / 勉强承载」是它经每条路径 ping 枢纽的探测结果，不是对流量的直接观察"},
		{Class: ClassPath, ClassLabel: "承载路径（单中继、无备用枢纽）", Events: "路由表 102 的默认路由指向哪条腿（UDP / WSS / 家里直连枢纽的 WSS）",
			Source: SourceRoute, How: "固定参数的只读命令 ip -4 -o route show table 102", Cadence: "每 10 秒", Strength: StrengthDirect,
			Evidence: "内核路由表本身；这种拓扑的故障切换服务不记录原因，所以只有切换，没有探测结论和原因"},
		{Class: ClassRelay, ClassLabel: "中继分担", Events: "某台中继被分担的健康检查剔除、恢复、降权、转为不接新连接，以及它使用的腿和路由表 102 跟随的中继",
			Source: SourceUpstream, How: "同一个文件里每台中继的一行（仅多中继分担时有）", Cadence: "每 10 秒读一次", Strength: StrengthDirect,
			Evidence: "分担控制器自己的状态和原因代码（丢包、时延、送达、吞吐）；控制器不可用时是按能否 ping 通的回退结论，依据里会写明"},
		{Class: ClassTunnel, ClassLabel: "隧道握手", Events: "每条隧道的握手由正常变为超时（视为不通）、恢复、接口消失",
			Source: SourceHandshake, How: "固定参数的只读命令 wg show <接口> latest-handshakes，接口名只取自已安装的对象清单并按受管接口的命名规则校验；从不执行 dump", Cadence: "每 30 秒", Strength: StrengthDirect,
			Evidence: "内核记录的最近一次握手时间。超过 180 秒没有新的握手才算超时，所以断开最多晚 3 分钟多才记下；只代表网关这一端的会话，对端另有问题时看不出来。关闭了保活的链路不记录"},
		{Class: ClassWSS, ClassLabel: "WSS 伴随承载", Events: "wstunnel 客户端停止 / 运行，以及它承载的隧道握手是否正常（记为连接 / 断开）",
			Source: SourceWSSUnit, How: "固定参数的只读命令 systemctl is-active <单元>，单元名只取自对象清单并校验；加上该隧道的握手时间", Cadence: "每 30 秒", Strength: StrengthIndirect,
			Evidence: "间接：客户端进程在不在运行，加上它里面的隧道有没有握手成功。WebSocket 会话本身的连接状态没有读取"},
		{Class: ClassExternalExit, ClassLabel: "外部出口", Events: "网关对某个外部 SOCKS 出口的自检由通过变为失败、恢复",
			Source: SourceSelfCheck, How: "读嗅探转发服务状态套接字（只回答 root）的固定请求 GET /v1/health 里最近一次自检的结果", Cadence: "每 30 秒读一次；转发服务每 15 分钟自检一次（启动和规则重载后各一次）", Strength: StrengthProbe,
			Evidence: "这是「网关经隧道问这个出口的解析器没有得到回答」，不是「代理已经确认不通」：承载节点自己的健康检查网关读不到。开始和结束的时间最多有 15 分钟的误差，短于 15 分钟的中断可能记不到；只有被规则或默认去向直接指向的外部出口才有这项自检，嗅探关闭时没有"},
		{Class: ClassSniffTarget, ClassLabel: "嗅探自检目标", Events: "自检里某个目标（地区组、出口、直连）由通过变为失败、恢复",
			Source: SourceSelfCheck, How: "同上", Cadence: "同上", Strength: StrengthProbe,
			Evidence: "转发服务经真实路径问该目标的解析器（默认目标另加一次 TCP 连接）。证明的是那一刻解析器可达，不证明某个网站可用；地区组的结果反映枢纽当时使用的成员"},
		{Class: ClassCollector, ClassLabel: "采集本身", Events: "采集空窗（采集服务没有运行、停顿、时钟被调回）、某个来源读不到及恢复、对象清单更新",
			Source: SourceCollector, How: "采集服务自己的两次采集之间的间隔和每个来源的读取结果", Cadence: "每 10 秒", Strength: StrengthDirect,
			Evidence: "空窗期间的状态记为未知，任何持续时间都不跨过空窗"},
	}
}

// NotInScope lists what is not recorded and why.
func NotInScope() []Excluded {
	return []Excluded{
		{What: "承载节点上的外部出口健康检查（meridian-ext-health）", Why: "它在承载节点上运行，结果只在那台节点的本地状态和日志里；网关没有任何现有的固定通道能读到，这一轮不为它在远端节点新增能力",
			Instead: "网关自己的检查（外部出口这一类）：依据写明是网关自检"},
		{Why: "由枢纽的故障切换服务决定，面板在需要时经 SSH 读取一次（地区组页面显示的「当前成员」），网关上的采集服务读不到", What: "地区组在枢纽上当前使用哪个成员、何时切换"},
		{What: "中继和枢纽自己的故障切换（中继到枢纽走 IX 还是 WSS、枢纽的回程路径）", Why: "发生在远端节点上，网关读不到",
			Instead: "网关经每条路径探测枢纽的结论（承载路径的探测结果）"},
		{What: "隧道对端一侧的握手和链路状态", Why: "只读取网关自己的接口", Instead: "网关这一端的握手时间"},
		{What: "解锁探测与出口确认的结果", Why: "由面板按计划或手动发起，结果保存在面板里（解锁页面），不在网关宿主机上，采集服务读不到；这一轮没有把它们转成链路事件"},
		{What: "远程接入（mra）各设备的握手", Why: "那是设备的在线情况，不是链路；链路日志不读取 mra"},
		{What: "任何流量内容", Why: "链路日志不读取连接、名字、地址或设备信息"},
	}
}

// ---------------------------------------------------------------- parsers ---

// UpstreamRelay is one relay line of a relay-sharing record (the fields
// the journal uses).
type UpstreamRelay struct {
	ID, Iface, Status, Reason, Grade string
	Weight                           int
	StatusSince                      int64
	// QoS verdict of the speed tests ("" in an older record) and the last
	// valid test (kbit/s, 0 none; its time) and the baseline (kbit/s).
	QoS                     string
	SpeedKbps, BaselineKbps int64
	SpeedAt                 int64
}

// UpstreamRecord is the gateway's upstream record (hostexec.ParseUpstream
// reads the same file for the panel; a test there keeps the two parsers in
// agreement).
type UpstreamRecord struct {
	Version                        int
	Beat, Since, Switched          int64
	Path, Iface, Hub, Tier, State  string
	Controller, Alert, Designated  string
	Relays                         []UpstreamRelay
	BackupHub, BackupIface, BGrade string
	// BackupGroup: the relays that reach the backup hub (backup_group
	// line; BackupHub names the hub, BackupIface stays empty).
	BackupGroup []string
}

var (
	upTokenRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	upEpochRe = regexp.MustCompile(`^[0-9]{1,12}$`)
	upCodeRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	// upQoSStates: the speed tests' verdicts (pathquality.QoS*).
	upQoSStates = map[string]bool{"ok": true, "throttled": true, "unknown": true, "off": true}
	upNumRe     = regexp.MustCompile(`^[0-9]{1,15}$`)

	upStates  = map[string]bool{"static": true, "ok": true, "switching": true, "down": true, "degraded": true}
	upRelaySt = map[string]bool{"active": true, "reduced": true, "standby": true, "evicted": true, "recovering": true, "disabled": true}
	upGrades  = map[string]bool{"good": true, "mild": true, "poor": true, "down": true, "none": true}
)

const (
	upRelayFields  = 25
	upRelayFieldsQ = 30
	upBackupFields = 12
	upMaxRelays    = 12
)

// ParseUpstreamRecord checks the record against its grammar (both forms)
// and returns the fields the journal uses. Any deviation refuses the whole
// record.
func ParseUpstreamRecord(text string) (UpstreamRecord, error) {
	var r UpstreamRecord
	bad := errors.New("upstream record: format")
	if len(text) > MaxUpstreamFile {
		return r, errors.New("upstream record: too long")
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) < 9 || lines[len(lines)-1] != "end" {
		return r, bad
	}
	var head []string
	switch lines[0] {
	case "meridian-upstream 1":
		r.Version, head = 1, []string{"beat", "path", "iface", "hub", "tier", "since", "state"}
		if len(lines) != 9 {
			return r, bad
		}
	case "meridian-upstream 2":
		r.Version, head = 2, []string{"beat", "path", "iface", "hub", "tier", "since", "state", "controller", "alert", "switched", "designated"}
		if len(lines) < 14 {
			return r, bad
		}
	default:
		return r, bad
	}
	seen := map[string]bool{}
	for i := 1; i <= len(head); i++ {
		f := strings.Fields(lines[i])
		if len(f) != 2 || strings.Join(f, " ") != lines[i] || seen[f[0]] {
			return r, bad
		}
		k, v := f[0], f[1]
		// The first form's lines may come in any order; the second form's
		// are fixed.
		if r.Version == 2 && k != head[i-1] {
			return r, bad
		}
		seen[k] = true
		epoch := func(dst *int64) error {
			if !upEpochRe.MatchString(v) {
				return bad
			}
			*dst, _ = strconv.ParseInt(v, 10, 64)
			return nil
		}
		token := func(dst *string) error {
			if !upTokenRe.MatchString(v) {
				return bad
			}
			*dst = v
			return nil
		}
		var err error
		switch k {
		case "beat":
			err = epoch(&r.Beat)
		case "since":
			err = epoch(&r.Since)
		case "path":
			if err = token(&r.Path); err == nil && r.Version == 2 && v != "main" && v != "backup" {
				err = bad
			}
		case "iface":
			err = token(&r.Iface)
		case "hub":
			err = token(&r.Hub)
		case "tier":
			if v != "primary" && v != "backup" {
				return r, bad
			}
			r.Tier = v
		case "state":
			if !upStates[v] || r.Version == 1 && v == "degraded" {
				return r, bad
			}
			r.State = v
		default:
			if r.Version != 2 {
				return r, bad
			}
			switch k {
			case "switched":
				err = epoch(&r.Switched)
			case "designated":
				err = token(&r.Designated)
			case "controller":
				if v != "go" && v != "shell" {
					return r, bad
				}
				r.Controller = v
			case "alert":
				if v != "-" {
					if !upCodeRe.MatchString(v) {
						return r, bad
					}
					r.Alert = v
				}
			default:
				return r, bad
			}
		}
		if err != nil {
			return r, err
		}
	}
	if len(seen) != len(head) {
		return r, bad
	}
	if r.Version == 2 {
		ids := map[string]bool{}
		backup := false
		for _, l := range lines[1+len(head) : len(lines)-1] {
			f := strings.Fields(l)
			if len(f) == 0 || strings.Join(f, " ") != l {
				return r, bad
			}
			switch {
			case f[0] == "relay" && (len(f) == upRelayFields || len(f) == upRelayFieldsQ) && !backup:
				x := UpstreamRelay{ID: f[1], Iface: f[2], Status: f[3], Grade: f[8]}
				if !upTokenRe.MatchString(x.ID) || !upTokenRe.MatchString(x.Iface) || !upRelaySt[x.Status] || !upGrades[x.Grade] ||
					!upNumRe.MatchString(f[4]) || !upNumRe.MatchString(f[7]) || (f[5] != "0" && f[5] != "1") || ids[x.ID] || len(r.Relays) == upMaxRelays {
					return r, bad
				}
				if f[6] != "-" {
					if !upCodeRe.MatchString(f[6]) {
						return r, bad
					}
					x.Reason = f[6]
				}
				if len(f) == upRelayFieldsQ {
					if !upQoSStates[f[25]] || (f[26] != "-" && !upNumRe.MatchString(f[26])) || !upNumRe.MatchString(f[27]) || !upNumRe.MatchString(f[28]) {
						return r, bad
					}
					x.QoS = f[25]
					if f[26] != "-" {
						x.SpeedKbps, _ = strconv.ParseInt(f[26], 10, 64)
					}
					x.SpeedAt, _ = strconv.ParseInt(f[27], 10, 64)
					x.BaselineKbps, _ = strconv.ParseInt(f[28], 10, 64)
				}
				x.Weight, _ = strconv.Atoi(f[4])
				x.StatusSince, _ = strconv.ParseInt(f[7], 10, 64)
				if x.Weight > 1000 {
					return r, bad
				}
				ids[x.ID] = true
				r.Relays = append(r.Relays, x)
			case f[0] == "backup_group" && len(f) >= 3 && !backup:
				if !upTokenRe.MatchString(f[1]) {
					return r, bad
				}
				for _, id := range f[2:] {
					if !ids[id] {
						return r, bad
					}
				}
				r.BackupHub, r.BackupGroup, backup = f[1], f[2:], true
			case f[0] == "backup" && len(f) == upBackupFields && !backup:
				if !upTokenRe.MatchString(f[1]) || !upTokenRe.MatchString(f[2]) || !upGrades[f[3]] {
					return r, bad
				}
				r.BackupHub, r.BackupIface, r.BGrade, backup = f[1], f[2], f[3], true
			default:
				return r, bad
			}
		}
		if len(r.Relays) == 0 {
			return r, bad
		}
	}
	if r.Since > r.Beat || r.Switched > r.Beat {
		return r, bad
	}
	return r, nil
}

func validWGKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// ParseHandshakes reads "wg show <iface> latest-handshakes" ("<public
// key>\t<unix seconds>" per peer): the newest handshake of the interface
// (0: none yet) and its peer count. The keys are checked and dropped.
func ParseHandshakes(out string) (latest int64, peers int, err error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !validWGKey(f[0]) || !upEpochRe.MatchString(f[1]) {
			return 0, 0, errors.New("latest-handshakes: unexpected output")
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		peers++
		if v > latest {
			latest = v
		}
	}
	return latest, peers, nil
}

var routeDefaultRe = regexp.MustCompile(`^default(?: via \S+)? dev (\S+)`)

// ParseRouteDefault reads "ip -4 -o route show table 102": the interface of
// the default route that is not the blackhole floor ("" when only the
// floor, or nothing, is there).
func ParseRouteDefault(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if m := routeDefaultRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1]
		}
	}
	return ""
}

// The three fixed argument lists.
func wgArgs(iface string) []string  { return []string{"show", iface, "latest-handshakes"} }
func unitArgs(unit string) []string { return []string{"is-active", unit} }
func routeArgs() []string {
	return []string{"-4", "-o", "route", "show", "table", strconv.Itoa(ForeignTable)}
}

// ------------------------------------------------- readings → observations ---

func tierText(t string) string {
	if t == "backup" {
		return "备用枢纽"
	}
	return "主枢纽"
}

func (c Config) pathByIface(iface string) (PathConfig, bool) {
	for _, p := range c.Paths {
		if p.Iface == iface {
			return p, true
		}
	}
	return PathConfig{}, false
}

func at(epoch int64) time.Time {
	if epoch <= 0 {
		return time.Time{}
	}
	return time.Unix(epoch, 0).UTC()
}

// upstreamObservations turns a fresh record into the readings of class
// path and relay.
func (c Config) upstreamObservations(r UpstreamRecord) []Observation {
	var out []Observation
	state := r.Path
	ev := fmt.Sprintf("网关故障切换服务的记录：路径 %s，接口 %s，枢纽 %s（%s），自 %s", r.Path, r.Iface, r.Hub, tierText(r.Tier), stamp(at(r.Since)))
	if r.Version == 2 {
		ev += "；路由表 102 跟随 " + r.Designated
		if r.Controller == "shell" {
			ev += "（分担控制器不可用，这是按能否 ping 通的回退结论）"
		}
	}
	reason := ""
	if len(r.BackupGroup) > 0 {
		if r.Tier == "backup" {
			ev += "；备用组（" + strings.Join(r.BackupGroup, "、") + "）经中继承载到备用枢纽 " + r.BackupHub
		} else {
			ev += "；主组承载，备用组（" + strings.Join(r.BackupGroup, "、") + "）待命"
		}
	}
	if r.Tier == "backup" {
		reason = "on_backup"
		if r.Alert == "on_backup_returning" {
			// Some relay answers again: back after 3 reachable passes and
			// min_dwell_sec (quality not required).
			reason = r.Alert
			ev += "；已有中继重新应答，连续 3 轮可达且满最短间隔即切回主链路"
		}
	}
	out = append(out, Observation{Class: ClassPath, Kind: KindUpstream, ID: GatewayID, Label: "承载路径", State: state, Source: SourceUpstream, Reason: reason, Evidence: ev, SourceAt: at(r.Since)})
	// "static" is the install's record: nothing has been measured yet.
	if r.State != "static" {
		h := Observation{Class: ClassPath, Kind: KindHealth, ID: GatewayID, Label: "承载路径的探测结果", Source: SourceUpstream, State: HealthOK, Reason: r.Alert}
		switch r.State {
		case "down":
			h.State, h.Evidence = HealthDown, "故障切换服务上一轮经每条路径探测枢纽都没有应答；路由表保持在 "+r.Path+"（流量在隧道里被丢弃，不会从局域网口出去）"
		case "degraded":
			h.State, h.Evidence = HealthDegraded, "分担控制器：所有中继都低于可用下限，备用枢纽不更好或不可用，由相对最好的中继勉强承载"
		case "switching":
			h.Reason, h.Evidence = "switching", "故障切换服务上一轮处在切换判断中（刚完成一次切换，或另一条路径更合适、正在等够确认轮数）；有路径应答"
		default:
			h.Evidence = "故障切换服务上一轮探测当前路径有应答"
		}
		if r.Alert != "" {
			h.Evidence += "（告警 " + r.Alert + "）"
		}
		out = append(out, h)
	}
	if r.Version != 2 {
		return out
	}
	out = append(out, Observation{Class: ClassPath, Kind: KindDesignate, ID: GatewayID, Label: "路由表 102 跟随的中继", State: r.Designated, Source: SourceUpstream,
		Evidence: "分担控制器把路由表 102（本机发起的连接和安装前已有的连接）指向 " + r.Designated})
	for _, x := range r.Relays {
		e := fmt.Sprintf("分担控制器：状态 %s，质量 %s，权重 %d/1000，使用接口 %s", x.Status, x.Grade, x.Weight, x.Iface)
		if x.Reason != "" {
			e += "，原因 " + x.Reason
			if x.Reason == "retained_best" {
				e += "（全部中继低于下限，保留最好且仍可达的这一台独占承载，不切备用枢纽）"
			}
		}
		if r.Controller == "shell" {
			e += "（控制器不可用，按能否 ping 通的回退结论）"
		}
		if x.Reason == "qos_throttled" {
			e += "（测速连续两次低于基准的阈值，判定被限速；其他中继承载它的份额）"
		}
		out = append(out, Observation{Class: ClassRelay, Kind: KindRelay, ID: x.ID, Label: "中继 " + x.ID + "（分担）", State: x.Status, Source: SourceUpstream, Reason: x.Reason, Evidence: e, SourceAt: at(x.StatusSince)})
		if x.QoS != "" {
			q := Observation{Class: ClassRelay, Kind: KindRelayQoS, ID: x.ID, Label: "中继 " + x.ID + " 的测速结论", State: x.QoS, Source: SourceUpstream, SourceAt: at(x.SpeedAt)}
			switch {
			case x.QoS == "off":
				q.Evidence = "测速已关闭：不按测速判定限速"
			case x.SpeedKbps > 0:
				age := r.Beat - x.SpeedAt
				if age < 0 {
					age = 0
				}
				q.Evidence = fmt.Sprintf("最近一次有效测速 %.1f Mbit/s（%s，%d 分钟前），基准 %.1f Mbit/s", float64(x.SpeedKbps)/1000, stamp(at(x.SpeedAt)), age/60, float64(x.BaselineKbps)/1000)
			default:
				q.Evidence = fmt.Sprintf("还没有有效测速；基准 %.1f Mbit/s", float64(x.BaselineKbps)/1000)
			}
			if x.QoS == "throttled" {
				q.Reason = "qos_throttled"
			}
			if r.Controller == "shell" {
				q.Evidence += "（控制器不可用：回退逻辑只读取已保存的测速结论）"
			}
			out = append(out, q)
		}
		leg := x.Iface
		if p, ok := c.pathByIface(x.Iface); ok && p.Mode != "" {
			leg = p.Mode
		}
		out = append(out, Observation{Class: ClassPath, Kind: KindRelayLeg, ID: x.ID, Label: "到中继 " + x.ID + " 使用的腿", State: leg, Source: SourceUpstream,
			Evidence: "分担控制器记录到中继 " + x.ID + " 的流量走接口 " + x.Iface})
	}
	return out
}

// routeObservation is the single-relay gateway's carrying path, from the
// foreign table's default route.
func (c Config) routeObservation(iface string) Observation {
	o := Observation{Class: ClassPath, Kind: KindUpstream, ID: GatewayID, Label: "承载路径", Source: SourceRoute}
	switch p, ok := c.pathByIface(iface); {
	case iface == "":
		o.State, o.Reason, o.Evidence = PathNone, "no_route", fmt.Sprintf("路由表 %d 里没有指向隧道的默认路由（只剩黑洞）", ForeignTable)
	case ok:
		o.State, o.Evidence = p.Name, fmt.Sprintf("路由表 %d 的默认路由指向 %s（链路 %s，到 %s）", ForeignTable, iface, p.Link, p.Peer)
	default:
		o.State, o.Evidence = PathOther, fmt.Sprintf("路由表 %d 的默认路由指向 %s，不是对象清单里的路径", ForeignTable, iface)
	}
	return o
}

// tunnelState judges one handshake reading.
func tunnelState(latest int64, now time.Time, staleS int) (state, reason, evidence string) {
	if latest <= 0 {
		return TunnelNever, "no_handshake", "内核里这个接口还没有一次成功的握手"
	}
	age := now.Unix() - latest
	if age < 0 {
		age = 0
	}
	ev := fmt.Sprintf("最近一次握手在 %s（%d 秒前；超过 %d 秒没有新的握手算超时）", stamp(at(latest)), age, staleS)
	if age > int64(staleS) {
		return TunnelStale, "handshake_timeout", ev
	}
	return TunnelOK, "", ev
}

func (c Config) tunnelObservation(t TunnelConfig, state, reason, evidence string, latest int64) Observation {
	return Observation{Class: ClassTunnel, Kind: KindTunnel, ID: t.Iface, Label: t.label(), State: state, Source: SourceHandshake, Reason: reason, Evidence: evidence, SourceAt: at(latest)}
}

// wssObservation combines the client unit's state with the handshake state
// of the tunnel it carries (judged false: that tunnel has no keepalive and
// is not read; tunnel "" with judged: it was not read this pass, so there is
// no reading).
func (c Config) wssObservation(w WSSConfig, unitState, tunnel string, judged bool) Observation {
	o := Observation{Class: ClassWSS, Kind: KindWSS, ID: w.Link, Label: w.label(), Source: SourceWSSUnit}
	switch {
	case unitState != "active":
		o.State, o.Reason = WSSStopped, "unit_"+unitState
		o.Evidence = fmt.Sprintf("%s 的状态是 %s（不在运行）", w.Unit, unitState)
	case !judged:
		o.State = WSSRunning
		o.Evidence = fmt.Sprintf("%s 在运行；它承载的隧道 %s 关闭了保活，握手不作判断", w.Unit, w.Iface)
	case tunnel == TunnelOK:
		o.State = WSSConnected
		o.Evidence = fmt.Sprintf("%s 在运行，它承载的隧道 %s 握手正常（间接依据：没有读取 WebSocket 会话本身）", w.Unit, w.Iface)
	case tunnel == "":
		return Observation{}
	default:
		o.State, o.Reason = WSSDisconnected, "tunnel_"+tunnel
		o.Evidence = fmt.Sprintf("%s 在运行，但它承载的隧道 %s 握手状态是 %s（间接依据：没有读取 WebSocket 会话本身）", w.Unit, w.Iface, tunnel)
	}
	return o
}

// selfCheckObservations turns the forwarder's last self-check into the
// readings of its targets. A target the result does not name, or whose
// failure is only "not checked in time", gives no reading.
func (c Config) selfCheckObservations(sc *sniff.SelfCheck) []Observation {
	if c.Sniff == nil || sc == nil {
		return nil
	}
	by := map[string]*sniff.SelfCheckTarget{}
	for i := range sc.Targets {
		by[sc.Targets[i].Target] = &sc.Targets[i]
	}
	lastAnswer := func(t *sniff.SelfCheckTarget) (time.Time, bool) {
		var best time.Time
		found := false
		for _, p := range t.Resolvers {
			for _, h := range sc.ResolverHealth {
				if h.Server == p.Server && h.Mark == t.DNSMark {
					found = true
					if h.LastAnswerAt.After(best) {
						best = h.LastAnswerAt
					}
				}
			}
		}
		return best, found
	}
	var out []Observation
	for _, tg := range c.Sniff.Targets {
		t := by[tg.Target]
		if t == nil {
			continue
		}
		class, kind, id := tg.Object()
		o := Observation{Class: class, Kind: kind, ID: id, Label: tg.label(), Source: SourceSelfCheck, SourceAt: sc.FinishedAt}
		who := "网关嗅探转发服务的自检（" + stamp(sc.FinishedAt) + "）"
		switch t.Status {
		case sniff.TargetOK:
			o.State, o.Evidence = CheckOK, who+"：这个目标的解析器经隧道有回答"
			if t.Connect != nil && t.Connect.Reached {
				o.Evidence += "，到解析器的 TCP 连接也能建立"
			}
		case sniff.TargetUnchecked:
			o.State, o.Reason, o.Evidence = CheckUnchecked, "unchecked", who+"没有检查这个目标："+t.Reason
		case sniff.TargetFailed:
			inconclusive := false
			for _, p := range t.Resolvers {
				if !p.Reached && o.Reason == "" {
					o.Reason = p.Outcome
				}
				inconclusive = inconclusive || p.Outcome == sniff.OutcomeNotRun
			}
			if t.Connect != nil && !t.Connect.Reached {
				inconclusive = inconclusive || t.Connect.Outcome == sniff.OutcomeNotRun
				if o.Reason == "" {
					o.Reason = "connect_" + t.Connect.Outcome
				}
			}
			if inconclusive {
				// The run's time budget ended before this target was asked:
				// that is not a failed check.
				continue
			}
			o.State, o.Evidence = CheckFailed, who+"失败："+t.Reason
			if la, ok := lastAnswer(t); ok {
				if la.IsZero() {
					o.Evidence += "；转发服务这次运行以来这个目标的解析器从未有过回答"
				} else {
					o.Evidence += "；这个目标的解析器最后一次有回答在 " + stamp(la)
				}
			}
			if tg.External {
				o.Evidence += "。这是网关自己的检查，不是承载节点上的健康检查：代理是否不通没有被证实"
			}
		default:
			continue
		}
		out = append(out, o)
	}
	return out
}

// ----------------------------------------------------------------- reader ---

// Runner runs one program of the fixed table with arguments built by this
// package. Tests use a fake; the namespace tests one that enters a network
// namespace first.
type Runner interface {
	Run(ctx context.Context, prog string, args ...string) (string, error)
}

// Reader is how the collector reads its sources. The zero value reads the
// real ones.
type Reader struct {
	// Runner: nil is ExecRunner.
	Runner Runner
	// UpstreamFile and SniffSocket replace the fixed places (tests only).
	UpstreamFile string
	SniffSocket  string
	// ReadFile and Status replace the bounded file read and the status
	// socket request (tests only).
	ReadFile func(path string, max int64) ([]byte, error)
	Status   func(ctx context.Context, socket, path string) ([]byte, int, error)
}

// ErrAbsent: the interface does not exist.
var ErrAbsent = errors.New("interface does not exist")
