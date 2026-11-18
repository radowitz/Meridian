package linkjournal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// world is a synthetic gateway: what the three programs print, what the
// failover record holds and what the forwarder's status socket answers.
type world struct {
	ck *clock
	// upstream is the record's text ("": no file).
	upstream string
	// hs: interface → newest handshake (unix seconds; absent key: the
	// interface does not exist). wgFail: wg itself fails.
	hs     map[string]int64
	wgFail bool
	units  map[string]string
	// route is what "ip route show table 102" prints.
	route    string
	routeErr bool
	// health is the forwarder's answer (nil: no socket).
	health *sniff.Health
	calls  []string
}

var testKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func (w *world) Run(_ context.Context, prog string, args ...string) (string, error) {
	w.calls = append(w.calls, prog+" "+strings.Join(args, " "))
	switch prog {
	case "wg":
		if w.wgFail {
			return "Unable to access interface: Operation not permitted\n", errors.New("exit status 1")
		}
		v, ok := w.hs[args[1]]
		if !ok {
			return "Unable to access interface: No such device\n", errors.New("exit status 1")
		}
		return fmt.Sprintf("%s\t%d\n", testKey, v), nil
	case "systemctl":
		st, ok := w.units[args[1]]
		if !ok {
			return "", errors.New("exit status 1")
		}
		if st != "active" {
			return st + "\n", errors.New("exit status 3")
		}
		return st + "\n", nil
	case "ip":
		if w.routeErr {
			return "", errors.New("exit status 1")
		}
		return w.route, nil
	}
	return "", errors.New("not a program of the table")
}

func (w *world) reader() Reader {
	return Reader{Runner: w,
		ReadFile: func(string, int64) ([]byte, error) {
			if w.upstream == "" {
				return nil, os.ErrNotExist
			}
			return []byte(w.upstream), nil
		},
		Status: func(context.Context, string, string) ([]byte, int, error) {
			if w.health == nil {
				return nil, 0, errors.New("no socket")
			}
			b, _ := json.Marshal(w.health)
			return b, 200, nil
		}}
}

func (w *world) collector(t *testing.T, cfg Config) (*Collector, *Journal) {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test object list: %v", err)
	}
	j := openJ(t, t.TempDir(), w.ck, nil)
	return NewCollector(cfg, j, w.reader()), j
}

// pass advances the clock by d and runs n passes d apart.
func (w *world) pass(c *Collector, n int, d time.Duration) {
	for i := 0; i < n; i++ {
		c.Step(context.Background(), w.ck.add(d))
	}
}

func baseCfg(mode string) Config {
	return Config{Version: 1, Gateway: "gw", IntervalS: DefaultIntervalS, SlowEvery: 1, HandshakeStaleS: DefaultHandshakeStaleS, UpstreamStaleS: DefaultUpstreamStaleS, Mode: mode}
}

func rec1(w *world, path, iface, hub, tier, state string, since time.Time) {
	w.upstream = fmt.Sprintf("meridian-upstream 1\nbeat %d\npath %s\niface %s\nhub %s\ntier %s\nsince %d\nstate %s\nend\n", w.ck.now().Unix(), path, iface, hub, tier, since.Unix(), state)
}

type relayLine struct {
	id, iface, status, reason, grade string
	weight                           int
	since                            time.Time
}

func rec2(w *world, path, iface, hub, tier, state, controller, alert, designated string, since time.Time, relays []relayLine, backup bool) {
	var sb strings.Builder
	if alert == "" {
		alert = "-"
	}
	fmt.Fprintf(&sb, "meridian-upstream 2\nbeat %d\npath %s\niface %s\nhub %s\ntier %s\nsince %d\nstate %s\ncontroller %s\nalert %s\nswitched 0\ndesignated %s\n",
		w.ck.now().Unix(), path, iface, hub, tier, since.Unix(), state, controller, alert, designated)
	for _, r := range relays {
		reason := r.reason
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(&sb, "relay %s %s %s %d 0 %s %d %s 12000 3 11000 0 %d 100 200 10 20 5 - 0 - - - 0\n", r.id, r.iface, r.status, r.weight, reason, r.since.Unix(), r.grade, w.ck.now().Unix())
	}
	if backup {
		fmt.Fprintf(&sb, "backup hkb m03 good 30000 0 29000 0 %d 10 20 0\n", w.ck.now().Unix())
	}
	sb.WriteString("end\n")
	w.upstream = sb.String()
}

func find(evs []Event, kind, id string) []Event {
	var out []Event
	for _, e := range evs {
		if e.Kind == kind && e.ID == id {
			out = append(out, e)
		}
	}
	return out
}

// Carrying state with a backup hub: the main path, the switch to the backup
// hub, "everything down", and the way back — from the failover loop's record.
func TestSourceUpstreamDualHub(t *testing.T) {
	w := &world{ck: newClock()}
	cfg := baseCfg(ModeDual)
	cfg.Paths = []PathConfig{{Name: "udp", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "ix", Tier: "primary", Mode: "udp"},
		{Name: "wss", Iface: "m00w", Link: "gw-access", Peer: "access", Hub: "ix", Tier: "primary", Mode: "wss"},
		{Name: "backup", Iface: "m03", Link: "gw-hkb", Peer: "hkb", Hub: "hkb", Tier: "backup", Mode: "wss"}}
	c, j := w.collector(t, cfg)
	t0 := w.ck.now()
	// The install's record ("static"), then the loop's first measurements.
	rec1(w, "udp", "m00", "ix", "primary", "static", t0)
	w.pass(c, 1, 10*time.Second)
	for i := 0; i < 6; i++ {
		rec1(w, "udp", "m00", "ix", "primary", "ok", t0)
		w.pass(c, 1, 10*time.Second)
	}
	mustEvents(t, j, 0)
	if o := current(t, j, KindUpstream, GatewayID); o.State != "udp" || o.Level != LevelOK || !strings.Contains(o.Evidence, "枢纽 ix（主枢纽）") {
		t.Fatalf("carrying: %+v", o)
	}
	if o := current(t, j, KindHealth, GatewayID); o.State != HealthOK {
		t.Fatalf("health: %+v", o)
	}
	// The loop is deciding (the current path stopped answering): no event.
	rec1(w, "udp", "m00", "ix", "primary", "switching", t0)
	w.pass(c, 1, 10*time.Second)
	mustEvents(t, j, 0)
	// It moved to the backup hub.
	sw := w.ck.now()
	rec1(w, "backup", "m03", "hkb", "backup", "ok", sw)
	w.pass(c, 1, 10*time.Second)
	evs := mustEvents(t, j, 1)
	e := evs[0]
	if e.Class != ClassPath || e.Kind != KindUpstream || e.From != "udp" || e.To != "backup" || e.Source != SourceUpstream || e.Reason != "on_backup" ||
		e.SourceAt == nil || !e.SourceAt.Equal(sw) || prevFor(e) != 80 || !e.PrevOpen || !strings.Contains(e.Evidence, "枢纽 hkb（备用枢纽）") {
		t.Fatalf("switch to the backup hub: %+v", e)
	}
	if o := current(t, j, KindUpstream, GatewayID); o.Level != LevelAbnormal {
		t.Fatalf("on the backup hub is abnormal: %+v", o)
	}
	// Nothing answers any more: the path stays, the probe result changes.
	for i := 0; i < 3; i++ {
		rec1(w, "backup", "m03", "hkb", "backup", "down", sw)
		w.pass(c, 1, 10*time.Second)
	}
	evs = mustEvents(t, j, 2)
	if e := find(evs, KindHealth, GatewayID); len(e) != 1 || e[0].From != HealthOK || e[0].To != HealthDown || !strings.Contains(e[0].Evidence, "没有应答") {
		t.Fatalf("down: %+v", e)
	}
	// Back to the main path.
	back := w.ck.now()
	rec1(w, "udp", "m00", "ix", "primary", "ok", back)
	w.pass(c, 1, 10*time.Second)
	evs = mustEvents(t, j, 4)
	up := find(evs, KindUpstream, GatewayID)
	if len(up) != 2 || up[0].From != "backup" || up[0].To != "udp" || prevFor(up[0]) != 40 || up[0].PrevOpen {
		t.Fatalf("back to the main path: %+v", up)
	}
	if h := find(evs, KindHealth, GatewayID); len(h) != 2 || h[0].To != HealthOK || prevFor(h[0]) != 30 {
		t.Fatalf("health back: %+v", h)
	}
	// The WSS leg of the main path is a path of its own.
	rec1(w, "wss", "m00w", "ix", "primary", "ok", w.ck.now())
	w.pass(c, 1, 10*time.Second)
	if up := find(mustEvents(t, j, 5), KindUpstream, GatewayID); up[0].To != "wss" {
		t.Fatalf("wss leg: %+v", up[0])
	}
}

// The failover loop stops writing: after three failed reads the source is
// recorded as unavailable, its objects go stale, and nothing is invented.
func TestSourceUpstreamHeartbeatStops(t *testing.T) {
	w := &world{ck: newClock()}
	cfg := baseCfg(ModeDual)
	cfg.Paths = []PathConfig{{Name: "udp", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "ix", Tier: "primary"}}
	c, j := w.collector(t, cfg)
	rec1(w, "udp", "m00", "ix", "primary", "ok", w.ck.now())
	w.pass(c, 1, 10*time.Second)
	// The record is left as it is: its heartbeat ages.
	w.pass(c, 7, 10*time.Second) // 70 s: one failed read (the threshold is 60 s)
	mustEvents(t, j, 0)
	w.pass(c, 2, 10*time.Second)
	evs := mustEvents(t, j, 1)
	if e := evs[0]; e.Class != ClassCollector || e.Kind != KindSource || e.ID != SourceUpstream || e.From != StateSourceOK || e.To != StateUnavailable || !strings.Contains(e.Evidence, "心跳已停") {
		t.Fatalf("source unavailable: %+v", e)
	}
	w.pass(c, 12, 10*time.Second)
	if o := current(t, j, KindUpstream, GatewayID); !o.Stale || o.State != "udp" {
		t.Fatalf("the carrying path is unknown now (last read: udp): %+v", o)
	}
	// The loop runs again, on the backup hub by now.
	rec1(w, "backup", "m03", "hkb", "backup", "ok", w.ck.now())
	w.pass(c, 1, 10*time.Second)
	evs = mustEvents(t, j, 3)
	if s := find(evs, KindSource, SourceUpstream); len(s) != 2 || s[0].To != StateSourceOK {
		t.Fatalf("source back: %+v", s)
	}
	up := find(evs, KindUpstream, GatewayID)
	if len(up) != 1 || up[0].AfterGap == nil || !up[0].PrevOpen || up[0].From != "udp" || up[0].To != "backup" {
		t.Fatalf("the change found after the source's gap: %+v", up)
	}
	// No file at all, a malformed file, the other form: failed reads.
	for _, text := range []string{"", "garbage\n", "meridian-upstream 2\nbeat 1\nend\n"} {
		w.upstream = text
		w.pass(c, 1, 10*time.Second)
	}
	if h := c.Health(); len(h.Sources) != 1 || h.Sources[0].OK || h.Sources[0].Fails != 3 || h.Sources[0].Error == "" {
		t.Fatalf("health: %+v", h.Sources)
	}
}

// Relay sharing: a relay evicted by the health check and restored, the leg
// a relay uses, the relay table 102 follows, the move to the backup hub.
func TestSourceRelaySharing(t *testing.T) {
	w := &world{ck: newClock()}
	cfg := baseCfg(ModeShare)
	cfg.Paths = []PathConfig{{Name: "relay", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "ix", Tier: "primary", Mode: "udp"},
		{Name: "relay", Iface: "m00w", Link: "gw-access", Peer: "access", Hub: "ix", Tier: "primary", Mode: "wss"},
		{Name: "relay", Iface: "m01", Link: "gw-access2", Peer: "access2", Hub: "ix", Tier: "primary", Mode: "udp"},
		{Name: "backup", Iface: "m03", Link: "gw-hkb", Peer: "hkb", Hub: "hkb", Tier: "backup", Mode: "wss"}}
	c, j := w.collector(t, cfg)
	t0 := w.ck.now()
	both := func(a, b relayLine) {
		rec2(w, "main", "m00", "ix", "primary", "ok", "go", "", "access", t0, []relayLine{a, b}, true)
	}
	access := relayLine{id: "access", iface: "m00", status: "active", grade: "good", weight: 500, since: t0}
	access2 := relayLine{id: "access2", iface: "m01", status: "active", grade: "good", weight: 500, since: t0}
	both(access, access2)
	w.pass(c, 1, 10*time.Second)
	mustEvents(t, j, 0)
	if got := len(j.Current().Objects); got != 8 { // upstream, health, designated, 2 relays, 2 legs, the source
		t.Fatalf("%d objects", got)
	}
	// access2 is evicted for loss.
	ev := w.ck.now()
	both(relayLine{id: "access", iface: "m00", status: "active", grade: "good", weight: 1000, since: t0}, relayLine{id: "access2", iface: "m01", status: "evicted", reason: "poor_loss", grade: "poor", since: ev})
	w.pass(c, 1, 10*time.Second)
	evs := mustEvents(t, j, 1)
	e := evs[0]
	if e.Class != ClassRelay || e.Kind != KindRelay || e.ID != "access2" || e.From != "active" || e.To != "evicted" || e.Reason != "poor_loss" ||
		e.SourceAt == nil || !e.SourceAt.Equal(ev) || !strings.Contains(e.Evidence, "质量 poor") || !strings.Contains(e.Evidence, "原因 poor_loss") {
		t.Fatalf("evicted: %+v", e)
	}
	if o := current(t, j, KindRelay, "access2"); o.Level != LevelAbnormal {
		t.Fatalf("%+v", o)
	}
	// It recovers: re-admitted, then active.
	w.pass(c, 3, 10*time.Second)
	both(relayLine{id: "access", iface: "m00", status: "active", grade: "good", weight: 800, since: t0}, relayLine{id: "access2", iface: "m01", status: "recovering", reason: "recovered", grade: "good", weight: 200, since: w.ck.now()})
	w.pass(c, 1, 10*time.Second)
	both(access, access2)
	w.pass(c, 1, 10*time.Second)
	r := find(mustEvents(t, j, 3), KindRelay, "access2")
	if len(r) != 3 || r[1].To != "recovering" || prevFor(r[1]) != 40 || r[0].To != "active" || prevFor(r[0]) != 10 {
		t.Fatalf("recovery: %+v", r)
	}
	// access moves to its WSS leg; the weights changing alone is no event.
	both(relayLine{id: "access", iface: "m00w", status: "active", grade: "mild", weight: 300, since: t0}, relayLine{id: "access2", iface: "m01", status: "active", grade: "good", weight: 700, since: t0})
	w.pass(c, 1, 10*time.Second)
	evs = mustEvents(t, j, 4)
	if l := find(evs, KindRelayLeg, "access"); len(l) != 1 || l[0].From != "udp" || l[0].To != "wss" || l[0].Class != ClassPath {
		t.Fatalf("leg: %+v", l)
	}
	// Table 102 follows the other relay.
	rec2(w, "main", "m01", "ix", "primary", "ok", "go", "", "access2", t0, []relayLine{{id: "access", iface: "m00w", status: "reduced", reason: "mild_loss", grade: "mild", weight: 200, since: w.ck.now()}, access2}, true)
	w.pass(c, 1, 10*time.Second)
	evs = mustEvents(t, j, 6)
	if d := find(evs, KindDesignate, GatewayID); len(d) != 1 || d[0].From != "access" || d[0].To != "access2" {
		t.Fatalf("designated: %+v", d)
	}
	if r := find(evs, KindRelay, "access"); len(r) != 1 || r[0].To != "reduced" || r[0].Reason != "mild_loss" {
		t.Fatalf("reduced: %+v", r)
	}
	// Every relay below the floor: the backup hub carries.
	sw := w.ck.now()
	rec2(w, "backup", "m03", "hkb", "backup", "ok", "go", "on_backup", "backup", sw, []relayLine{{id: "access", iface: "m00w", status: "evicted", reason: "down", grade: "down", since: sw}, {id: "access2", iface: "m01", status: "evicted", reason: "down", grade: "down", since: sw}}, true)
	w.pass(c, 1, 10*time.Second)
	evs = events(t, j, Query{Limit: PageMax})
	if u := find(evs, KindUpstream, GatewayID); len(u) != 1 || u[0].From != "main" || u[0].To != "backup" || u[0].Reason != "on_backup" {
		t.Fatalf("backup: %+v", u)
	}
	if d := find(evs, KindDesignate, GatewayID); len(d) != 2 || d[0].To != "backup" {
		t.Fatalf("designated backup: %+v", d)
	}
	// Degraded, and the shell fallback says so in its evidence.
	rec2(w, "main", "m00", "ix", "primary", "degraded", "shell", "all_relays_poor", "access", w.ck.now(), []relayLine{{id: "access", iface: "m00", status: "active", grade: "poor", weight: 1000, since: sw}, {id: "access2", iface: "m01", status: "evicted", reason: "down", grade: "down", since: sw}}, true)
	w.pass(c, 1, 10*time.Second)
	evs = events(t, j, Query{Limit: PageMax})
	if h := find(evs, KindHealth, GatewayID); len(h) != 1 || h[0].To != HealthDegraded || h[0].Reason != "all_relays_poor" {
		t.Fatalf("degraded: %+v", h)
	}
	if r := find(evs, KindRelay, "access"); !strings.Contains(r[0].Evidence, "回退结论") {
		t.Fatalf("the fallback must be named: %+v", r[0])
	}
}

// One relay, no backup hub: the loop records nothing, the route table says
// which leg carries.
func TestSourceRouteTableSingle(t *testing.T) {
	w := &world{ck: newClock()}
	cfg := baseCfg(ModeSingle)
	cfg.Paths = []PathConfig{{Name: "udp", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "hk", Tier: "primary", Mode: "udp"},
		{Name: "wss", Iface: "m00w", Link: "gw-access", Peer: "access", Hub: "hk", Tier: "primary", Mode: "wss"},
		{Name: "direct", Iface: "m05", Link: "gw-hk", Peer: "hk", Hub: "hk", Tier: "primary", Mode: "wss"}}
	c, j := w.collector(t, cfg)
	w.route = "default dev m00 scope link \\\nblackhole default metric 32767 \\\n192.0.2.0/24 dev eth0 scope link \\\n"
	w.pass(c, 3, 10*time.Second)
	mustEvents(t, j, 0)
	if o := current(t, j, KindUpstream, GatewayID); o.State != "udp" || o.Source != SourceRoute {
		t.Fatalf("%+v", o)
	}
	w.route = "default dev m00w scope link \\\nblackhole default metric 32767 \\\n"
	w.pass(c, 1, 10*time.Second)
	w.route = "default dev m05 scope link \\\nblackhole default metric 32767 \\\n"
	w.pass(c, 1, 10*time.Second)
	w.route = "blackhole default metric 32767 \\\n"
	w.pass(c, 1, 10*time.Second)
	w.route = "default dev m09 scope link \\\n"
	w.pass(c, 1, 10*time.Second)
	evs := mustEvents(t, j, 4)
	var tos []string
	for i := len(evs) - 1; i >= 0; i-- {
		tos = append(tos, evs[i].To)
	}
	if !reflect.DeepEqual(tos, []string{"wss", "direct", PathNone, PathOther}) {
		t.Fatalf("carrying legs: %v", tos)
	}
	if Level(KindUpstream, PathNone) != LevelAbnormal {
		t.Fatal("no route is abnormal")
	}
	// No health object on this topology, and the record is never read.
	for _, o := range j.Current().Objects {
		if o.Kind == KindHealth {
			t.Fatalf("a single-relay gateway has no probe result: %+v", o)
		}
	}
	// ip failing three times: the source is unavailable.
	w.routeErr = true
	w.pass(c, 3, 10*time.Second)
	if s := find(events(t, j, Query{}), KindSource, SourceRoute); len(s) != 1 || s[0].To != StateUnavailable {
		t.Fatalf("%+v", s)
	}
}

func tunnelCfg() Config {
	cfg := baseCfg(ModeSingle)
	cfg.Tunnels = []TunnelConfig{{Iface: "m00", Link: "gw-access", Mode: "udp", Peer: "access", PeerRole: "relay", KeepaliveS: 25},
		{Iface: "m00w", Link: "gw-access", Mode: "wss", Peer: "access", PeerRole: "relay", Standby: true, KeepaliveS: 25},
		{Iface: "m07", Link: "gw-x", Mode: "udp", Peer: "x", KeepaliveS: 0}}
	cfg.WSS = []WSSConfig{{Unit: "wstunnel-client-gw-access.service", Link: "gw-access", Iface: "m00w", Peer: "access"}}
	return cfg
}

// A tunnel's handshake goes stale and recovers; never; the interface goes.
func TestSourceTunnelHandshake(t *testing.T) {
	w := &world{ck: newClock(), units: map[string]string{"wstunnel-client-gw-access.service": "active"}}
	now := func() int64 { return w.ck.now().Unix() }
	w.hs = map[string]int64{"m00": now(), "m00w": now(), "m07": 0}
	c, j := w.collector(t, tunnelCfg())
	w.pass(c, 1, 10*time.Second)
	mustEvents(t, j, 0)
	// A healthy tunnel: a new handshake about every two minutes.
	for i := 0; i < 30; i++ {
		if i%12 == 0 {
			w.hs["m00"], w.hs["m00w"] = now(), now()
		}
		w.pass(c, 1, 10*time.Second)
	}
	mustEvents(t, j, 0)
	// The peer goes away: no new handshake on m00.
	last := w.hs["m00"]
	for i := 0; i < 20; i++ {
		w.hs["m00w"] = now()
		w.pass(c, 1, 10*time.Second)
	}
	evs := mustEvents(t, j, 1)
	e := evs[0]
	if e.Class != ClassTunnel || e.Kind != KindTunnel || e.ID != "m00" || e.From != TunnelOK || e.To != TunnelStale || e.Reason != "handshake_timeout" || e.Source != SourceHandshake ||
		e.SourceAt == nil || e.SourceAt.Unix() != last || !strings.Contains(e.Evidence, "最近一次握手在") || !strings.Contains(e.Label, "链路 gw-access") {
		t.Fatalf("stale: %+v", e)
	}
	// It is recorded when the age passes the threshold, not before.
	if d := e.At.Unix() - last; d <= DefaultHandshakeStaleS || d > DefaultHandshakeStaleS+10 {
		t.Fatalf("recorded %d s after the last handshake", d)
	}
	// Recovery.
	w.hs["m00"] = now()
	w.pass(c, 1, 10*time.Second)
	evs = mustEvents(t, j, 2)
	if e := evs[0]; e.From != TunnelStale || e.To != TunnelOK || e.PrevForS == nil || e.PrevOpen {
		t.Fatalf("recovered: %+v", e)
	}
	// The interface is re-created (no handshake yet), then removed.
	w.hs["m00"] = 0
	w.pass(c, 1, 10*time.Second)
	delete(w.hs, "m00")
	w.pass(c, 1, 10*time.Second)
	evs = mustEvents(t, j, 4)
	if evs[1].To != TunnelNever || evs[0].To != TunnelAbsent || evs[0].Reason != "no_interface" {
		t.Fatalf("never / absent: %+v %+v", evs[1], evs[0])
	}
	// The tunnel without keepalive is not read at all.
	for _, call := range w.calls {
		if strings.Contains(call, "m07") {
			t.Fatalf("a tunnel without keepalive was read: %s", call)
		}
	}
	for _, o := range j.Current().Objects {
		if o.ID == "m07" {
			t.Fatalf("%+v", o)
		}
	}
	// wg itself failing (not installed, no permission): no state is
	// invented, the source becomes unavailable.
	w.wgFail = true
	w.pass(c, 3, 10*time.Second)
	evs = events(t, j, Query{Limit: PageMax})
	if s := find(evs, KindSource, SourceHandshake); len(s) != 1 || s[0].To != StateUnavailable {
		t.Fatalf("%+v", s)
	}
	if got := find(evs, KindTunnel, "m00"); len(got) != 4 {
		t.Fatalf("a failed read produced a tunnel event: %+v", got[0])
	}
}

// A WSS carrier: connected, disconnected (its tunnel stale), stopped.
func TestSourceWSSCarrier(t *testing.T) {
	w := &world{ck: newClock(), units: map[string]string{"wstunnel-client-gw-access.service": "active"}}
	now := func() int64 { return w.ck.now().Unix() }
	w.hs = map[string]int64{"m00": now(), "m00w": now()}
	c, j := w.collector(t, tunnelCfg())
	w.pass(c, 1, 10*time.Second)
	if o := current(t, j, KindWSS, "gw-access"); o.State != WSSConnected || o.Class != ClassWSS || !strings.Contains(o.Evidence, "间接依据") {
		t.Fatalf("%+v", o)
	}
	// The client keeps running, the tunnel inside it stops handshaking.
	for i := 0; i < 20; i++ {
		w.hs["m00"] = now()
		w.pass(c, 1, 10*time.Second)
	}
	evs := events(t, j, Query{Limit: PageMax})
	ws := find(evs, KindWSS, "gw-access")
	if len(ws) != 1 || ws[0].From != WSSConnected || ws[0].To != WSSDisconnected || ws[0].Reason != "tunnel_stale" || ws[0].Source != SourceWSSUnit {
		t.Fatalf("disconnected: %+v", ws)
	}
	// The client fails.
	w.units["wstunnel-client-gw-access.service"] = "failed"
	w.pass(c, 1, 10*time.Second)
	ws = find(events(t, j, Query{Limit: PageMax}), KindWSS, "gw-access")
	if len(ws) != 2 || ws[0].To != WSSStopped || ws[0].Reason != "unit_failed" {
		t.Fatalf("stopped: %+v", ws)
	}
	// It runs again and the tunnel handshakes.
	w.units["wstunnel-client-gw-access.service"] = "active"
	w.hs["m00w"] = now()
	w.pass(c, 1, 10*time.Second)
	ws = find(events(t, j, Query{Limit: PageMax}), KindWSS, "gw-access")
	if len(ws) != 3 || ws[0].To != WSSConnected {
		t.Fatalf("connected again: %+v", ws)
	}
	// The carrier of a tunnel without keepalive: running, not judged.
	cfg := tunnelCfg()
	cfg.Tunnels[1].KeepaliveS = 0
	c2, j2 := w.collector(t, cfg)
	w.pass(c2, 1, 10*time.Second)
	if o := current(t, j2, KindWSS, "gw-access"); o.State != WSSRunning || o.Level != LevelInfo {
		t.Fatalf("%+v", o)
	}
	// systemctl giving no state: the source fails, no state is invented.
	delete(w.units, "wstunnel-client-gw-access.service")
	w.pass(c, 3, 10*time.Second)
	evs = events(t, j, Query{Limit: PageMax})
	if s := find(evs, KindSource, SourceWSSUnit); len(s) != 1 || s[0].To != StateUnavailable {
		t.Fatalf("%+v", s)
	}
	if ws := find(evs, KindWSS, "gw-access"); len(ws) != 3 {
		t.Fatalf("%+v", ws)
	}
}

func selfCheck(w *world, at time.Time, targets ...sniff.SelfCheckTarget) {
	sc := &sniff.SelfCheck{Version: sniff.SelfCheckVersion, Trigger: sniff.TriggerPeriodic, StartedAt: at.Add(-2 * time.Second), FinishedAt: at, Targets: targets, OK: true}
	w.health = &sniff.Health{Ready: true, SelfCheck: sc}
}

func scTarget(name, status, reason, outcome string) sniff.SelfCheckTarget {
	t := sniff.SelfCheckTarget{Target: name, Mark: 0x101, DNSMark: 7, Status: status, Reason: reason}
	if outcome != "" {
		t.Resolvers = []sniff.SelfCheckProbe{{Server: "[fd66::53:1]:53", Outcome: outcome, Reached: outcome == sniff.OutcomeAnswer}}
	}
	return t
}

func sniffCfg() Config {
	cfg := baseCfg(ModeSingle)
	cfg.SlowEvery = 3
	cfg.Sniff = &SniffConfig{SelfCheckMaxAgeS: DefaultSelfCheckMaxAgeS, Targets: []SniffTarget{{Target: "direct", Kind: "direct"},
		{Target: "exit:jp-a", Kind: "exit", ID: "jp-a"}, {Target: "exit:ext1", Kind: "exit", ID: "ext1", External: true, Carrier: "car1"},
		{Target: "exit:unused", Kind: "exit", ID: "unused"}, {Target: "group:hk", Kind: "region_group", ID: "hk"}}}
	return cfg
}

// The forwarder's self-check: an external exit's target failing and
// recovering is recorded as the gateway's own check, never as a confirmed
// remote failure; other targets likewise.
func TestSourceSelfCheckExternalExit(t *testing.T) {
	w := &world{ck: newClock(), route: "default dev m00 \\\n"}
	c, j := w.collector(t, sniffCfg())
	ok := func() {
		selfCheck(w, w.ck.now(), scTarget("direct", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("exit:jp-a", sniff.TargetOK, "", sniff.OutcomeAnswer),
			scTarget("exit:ext1", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("group:hk", sniff.TargetOK, "", sniff.OutcomeAnswer))
	}
	ok()
	w.pass(c, 6, 10*time.Second)
	mustEvents(t, j, 0)
	ext := current(t, j, KindExternal, "ext1")
	if ext.Class != ClassExternalExit || ext.State != CheckOK || ext.Label != "外部出口 ext1（由 car1 承载）" || ext.Source != SourceSelfCheck {
		t.Fatalf("external exit: %+v", ext)
	}
	if o := current(t, j, KindTarget, "group:hk"); o.Class != ClassSniffTarget || o.State != CheckOK {
		t.Fatalf("%+v", o)
	}
	// A target the forwarder does not check has no object at all.
	for _, o := range j.Current().Objects {
		if strings.Contains(o.ID, "unused") {
			t.Fatalf("%+v", o)
		}
	}
	// The next periodic self-check: the external exit's resolver is silent.
	w.pass(c, 84, 10*time.Second) // 15 minutes later
	lastAnswer := w.ck.now().Add(-9 * time.Minute)
	failAt := w.ck.now()
	selfCheck(w, failAt, scTarget("direct", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("exit:jp-a", sniff.TargetOK, "", sniff.OutcomeAnswer),
		scTarget("exit:ext1", sniff.TargetFailed, "解析器 [fd66::53:1]:53 超时，没有任何回应", sniff.OutcomeTimeout), scTarget("group:hk", sniff.TargetOK, "", sniff.OutcomeAnswer))
	w.health.SelfCheck.ResolverHealth = []sniff.ResolverHealth{{Server: "[fd66::53:1]:53", Mark: 7, LastAnswerAt: lastAnswer}}
	w.pass(c, 3, 10*time.Second)
	evs := mustEvents(t, j, 1)
	e := evs[0]
	if e.Class != ClassExternalExit || e.Kind != KindExternal || e.ID != "ext1" || e.From != CheckOK || e.To != CheckFailed || e.Reason != sniff.OutcomeTimeout || e.Source != SourceSelfCheck ||
		e.SourceAt == nil || !e.SourceAt.Equal(failAt) {
		t.Fatalf("external exit failed: %+v", e)
	}
	// The wording: the gateway's check, what it saw, when the resolver last
	// answered, and that the proxy being down is not proven.
	for _, want := range []string{"网关嗅探转发服务的自检", "超时，没有任何回应", "最后一次有回答在 " + stamp(lastAnswer), "不是承载节点上的健康检查", "没有被证实"} {
		if !strings.Contains(e.Evidence, want) {
			t.Errorf("evidence lacks %q: %s", want, e.Evidence)
		}
	}
	if strings.Contains(e.Evidence, "代理不通") || strings.Contains(e.Evidence, "已确认") {
		t.Errorf("the evidence asserts a remote failure: %s", e.Evidence)
	}
	// Three hours of failing checks: no further event.
	for i := 0; i < 12; i++ {
		w.pass(c, 87, 10*time.Second)
		selfCheck(w, w.ck.now(), scTarget("direct", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("exit:jp-a", sniff.TargetOK, "", sniff.OutcomeAnswer),
			scTarget("exit:ext1", sniff.TargetFailed, "解析器 [fd66::53:1]:53 超时，没有任何回应", sniff.OutcomeTimeout), scTarget("group:hk", sniff.TargetOK, "", sniff.OutcomeAnswer))
		w.pass(c, 3, 10*time.Second)
	}
	mustEvents(t, j, 1)
	if o := current(t, j, KindExternal, "ext1"); o.State != CheckFailed || o.Level != LevelAbnormal || o.ForS < 3*3600 || o.SinceOpen {
		t.Fatalf("down for three hours: %+v", o)
	}
	// Recovery.
	ok()
	w.pass(c, 3, 10*time.Second)
	evs = mustEvents(t, j, 2)
	if e := evs[0]; e.To != CheckOK || e.From != CheckFailed || prevFor(e) < 3*3600 || prevFor(e) > 3*3600+900 || e.PrevOpen {
		t.Fatalf("recovered: %+v", e)
	}
	// A region group's target failing is its own class and says so.
	selfCheck(w, w.ck.now(), scTarget("direct", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("exit:jp-a", sniff.TargetOK, "", sniff.OutcomeAnswer),
		scTarget("exit:ext1", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("group:hk", sniff.TargetFailed, "解析器 [fd66::54:1]:53 发送被本机拒绝", sniff.OutcomeSendRefused))
	w.pass(c, 3, 10*time.Second)
	evs = mustEvents(t, j, 3)
	if e := evs[0]; e.Class != ClassSniffTarget || e.Kind != KindTarget || e.ID != "group:hk" || e.To != CheckFailed || e.Reason != sniff.OutcomeSendRefused || strings.Contains(e.Evidence, "承载节点") {
		t.Fatalf("group target: %+v", e)
	}
}

// What is not a failed check: a run whose time budget ended before the
// target was asked, a target the result does not name, an unchecked target;
// and a result that stopped being renewed is not a reading.
func TestSourceSelfCheckInconclusive(t *testing.T) {
	w := &world{ck: newClock(), route: "default dev m00 \\\n"}
	cfg := sniffCfg()
	cfg.SlowEvery = 1
	c, j := w.collector(t, cfg)
	selfCheck(w, w.ck.now(), scTarget("exit:jp-a", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("exit:ext1", sniff.TargetOK, "", sniff.OutcomeAnswer), scTarget("group:hk", sniff.TargetOK, "", sniff.OutcomeAnswer))
	w.pass(c, 1, 10*time.Second)
	// Not run in time; missing from the result.
	selfCheck(w, w.ck.now(), scTarget("exit:jp-a", sniff.TargetFailed, "解析器 没有来得及检查（自检总时限已到）", sniff.OutcomeNotRun), scTarget("group:hk", sniff.TargetUnchecked, "这个目标没有解析器", ""))
	w.pass(c, 1, 10*time.Second)
	evs := mustEvents(t, j, 1)
	if e := evs[0]; e.ID != "group:hk" || e.To != CheckUnchecked || Level(KindTarget, CheckUnchecked) != LevelInfo {
		t.Fatalf("%+v", e)
	}
	if o := current(t, j, KindTarget, "exit:jp-a"); o.State != CheckOK {
		t.Fatalf("an unfinished run must not fail a target: %+v", o)
	}
	if o := current(t, j, KindExternal, "ext1"); o.State != CheckOK {
		t.Fatalf("a target missing from the result keeps its state: %+v", o)
	}
	// The forwarder stops checking (or stops): the result ages past the
	// limit, the source becomes unavailable, the targets go stale.
	w.pass(c, 239, 10*time.Second) // just under 40 minutes
	if s := find(events(t, j, Query{Limit: PageMax}), KindSource, SourceSelfCheck); len(s) != 0 {
		t.Fatalf("%+v", s)
	}
	w.pass(c, 5, 10*time.Second)
	if s := find(events(t, j, Query{Limit: PageMax}), KindSource, SourceSelfCheck); len(s) != 1 || s[0].To != StateUnavailable || !strings.Contains(s[0].Evidence, "分钟前") {
		t.Fatalf("%+v", s)
	}
	w.pass(c, 12, 10*time.Second)
	if o := current(t, j, KindExternal, "ext1"); !o.Stale {
		t.Fatalf("%+v", o)
	}
	// No socket at all (the forwarder is not running) and no result yet.
	w.health = nil
	w.pass(c, 1, 10*time.Second)
	if h := c.Health(); len(h.Sources) < 2 {
		t.Fatalf("%+v", h.Sources)
	}
	w.health = &sniff.Health{Ready: true}
	w.pass(c, 1, 10*time.Second)
	for _, s := range c.Health().Sources {
		if s.Source == SourceSelfCheck && (s.OK || !strings.Contains(s.Error, "还没有自检结果")) {
			t.Fatalf("%+v", s)
		}
	}
}

// The slow sources are read every SlowEvery-th pass only, and one failed
// read is not an event.
func TestCadenceAndDebounce(t *testing.T) {
	w := &world{ck: newClock(), units: map[string]string{"wstunnel-client-gw-access.service": "active"}, route: "default dev m00 \\\n"}
	w.hs = map[string]int64{"m00": w.ck.now().Unix(), "m00w": w.ck.now().Unix()}
	cfg := tunnelCfg()
	cfg.SlowEvery = 3
	c, j := w.collector(t, cfg)
	w.pass(c, 9, 10*time.Second)
	n := map[string]int{}
	for _, call := range w.calls {
		n[strings.Fields(call)[0]]++
	}
	if n["ip"] != 9 || n["wg"] != 6 || n["systemctl"] != 3 {
		t.Fatalf("calls: %v", n)
	}
	w.wgFail = true
	w.pass(c, 6, 10*time.Second) // two failed reads of the slow source
	mustEvents(t, j, 0)
	w.wgFail = false
	w.hs["m00"], w.hs["m00w"] = w.ck.now().Unix(), w.ck.now().Unix()
	w.pass(c, 3, 10*time.Second)
	mustEvents(t, j, 0)
	h := c.Health()
	if !h.Ready || h.Passes != 18 || h.IntervalS != 10 || h.SlowS != 30 || h.Mode != ModeSingle || h.Digest != cfg.Digest() {
		t.Fatalf("%+v", h)
	}
}

// Every command the collector runs is one of three fixed argument lists
// with a name that passed the object list's validation.
func TestFixedArgumentLists(t *testing.T) {
	w := &world{ck: newClock(), units: map[string]string{"wstunnel-client-gw-access.service": "active"}, route: "default dev m00 \\\n"}
	w.hs = map[string]int64{"m00": 1, "m00w": 1}
	c, _ := w.collector(t, tunnelCfg())
	w.pass(c, 4, 10*time.Second)
	allowed := map[string]bool{"ip -4 -o route show table 102": true, "wg show m00 latest-handshakes": true, "wg show m00w latest-handshakes": true,
		"systemctl is-active wstunnel-client-gw-access.service": true}
	seen := map[string]bool{}
	for _, call := range w.calls {
		if !allowed[call] {
			t.Fatalf("unexpected command: %q", call)
		}
		seen[call] = true
	}
	if len(seen) != len(allowed) {
		t.Fatalf("commands run: %v", seen)
	}
	// The reader refuses a name outside the managed patterns before any
	// program runs, whatever the object list says.
	w.calls = nil
	r := w.reader()
	for _, iface := range []string{"mra", "mmesh", "eth0", "wg0", "m00; reboot", "m00 dump", "-a", "all", ""} {
		if _, err := r.Handshake(context.Background(), iface); err == nil {
			t.Errorf("handshake read of %q accepted", iface)
		}
	}
	for _, unit := range []string{"meridian.service", "meridian-failover.service", "ssh.service", "wstunnel-client-a.service --now", "wstunnel-client-.service", "../x.service", ""} {
		if _, err := r.UnitState(context.Background(), unit); err == nil {
			t.Errorf("unit read of %q accepted", unit)
		}
	}
	if len(w.calls) != 0 {
		t.Fatalf("a refused name reached a program: %v", w.calls)
	}
	// The real runner knows three programs and nothing else.
	if _, err := (ExecRunner{}).Run(context.Background(), "sh", "-c", "true"); err == nil {
		t.Fatal("ExecRunner ran a program outside its table")
	}
	if len(programs) != 3 || programs["wg"] == nil || programs["systemctl"] == nil || programs["ip"] == nil {
		t.Fatalf("program table: %v", programs)
	}
	for _, cands := range programs {
		for _, p := range cands {
			if !strings.HasPrefix(p, "/") {
				t.Fatalf("%q is not an absolute path", p)
			}
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := tunnelCfg()
	good.Sniff = sniffCfg().Sniff
	good.Paths = []PathConfig{{Name: "udp", Iface: "m00", Link: "gw-access", Peer: "access", Hub: "hk", Tier: "primary", Mode: "udp"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(good)
	back, err := ParseConfig(b)
	if err != nil || !reflect.DeepEqual(back, good) || back.Digest() != good.Digest() {
		t.Fatalf("round trip: %v", err)
	}
	mut := func(f func(c *Config)) Config {
		var c Config
		_ = json.Unmarshal(b, &c)
		f(&c)
		return c
	}
	bad := map[string]Config{
		"version":            mut(func(c *Config) { c.Version = 2 }),
		"mode":               mut(func(c *Config) { c.Mode = "auto" }),
		"interval":           mut(func(c *Config) { c.IntervalS = 0 }),
		"slow":               mut(func(c *Config) { c.SlowEvery = 0 }),
		"stale":              mut(func(c *Config) { c.HandshakeStaleS = 1 }),
		"gateway":            mut(func(c *Config) { c.Gateway = "gw one" }),
		"tunnel mra":         mut(func(c *Config) { c.Tunnels[0].Iface = "mra" }),
		"tunnel eth0":        mut(func(c *Config) { c.Tunnels[0].Iface = "eth0" }),
		"tunnel injection":   mut(func(c *Config) { c.Tunnels[0].Iface = "m00 dump" }),
		"tunnel twice":       mut(func(c *Config) { c.Tunnels[1].Iface = "m00" }),
		"tunnel link":        mut(func(c *Config) { c.Tunnels[0].Link = "a/b" }),
		"path iface":         mut(func(c *Config) { c.Paths[0].Iface = "lo" }),
		"path name":          mut(func(c *Config) { c.Paths[0].Name = "" }),
		"unit":               mut(func(c *Config) { c.WSS[0].Unit = "meridian-failover.service" }),
		"unit option":        mut(func(c *Config) { c.WSS[0].Unit = "wstunnel-client-a.service --now" }),
		"unit iface":         mut(func(c *Config) { c.WSS[0].Iface = "docker0" }),
		"target":             mut(func(c *Config) { c.Sniff.Targets[1].Target = "exit:a b" }),
		"target kind":        mut(func(c *Config) { c.Sniff.Targets[1].Kind = "node" }),
		"target twice":       mut(func(c *Config) { c.Sniff.Targets[2].Target = "exit:jp-a" }),
		"self-check max age": mut(func(c *Config) { c.Sniff.SelfCheckMaxAgeS = 5 }),
	}
	for name, c := range bad {
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unknown fields and oversized lists are refused.
	if _, err := ParseConfig([]byte(strings.Replace(string(b), `"version":1`, `"version":1,"command":"x"`, 1))); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := ParseConfig(make([]byte, MaxConfig+1)); err == nil {
		t.Error("an oversized list was accepted")
	}
	many := mut(func(c *Config) {
		for i := 0; i < MaxTunnels+1; i++ {
			c.Tunnels = append(c.Tunnels, TunnelConfig{Iface: fmt.Sprintf("m%03d", 100+i), Link: "l", Mode: "udp", Peer: "p", KeepaliveS: 25})
		}
	})
	if many.Validate() == nil {
		t.Error("too many tunnels accepted")
	}
	// Objects: observed or not, and why.
	objs := good.Objects()
	var m07, ext *Object
	for i := range objs {
		switch {
		case objs[i].ID == "m07":
			m07 = &objs[i]
		case objs[i].Kind == KindExternal:
			ext = &objs[i]
		}
	}
	if m07 == nil || m07.Observed || !strings.Contains(m07.Note, "保活") || ext == nil || ext.ID != "ext1" || !good.Known(KindWSS, "gw-access") || good.Known(KindTunnel, "m99") {
		t.Fatalf("objects: %+v", objs)
	}
}

func TestParseUpstreamRecord(t *testing.T) {
	w := &world{ck: newClock()}
	rec1(w, "backup", "m03", "hkb", "backup", "switching", w.ck.now())
	r, err := ParseUpstreamRecord(w.upstream)
	if err != nil || r.Version != 1 || r.Path != "backup" || r.Iface != "m03" || r.Hub != "hkb" || r.Tier != "backup" || r.State != "switching" || r.Beat != w.ck.now().Unix() {
		t.Fatalf("%+v %v", r, err)
	}
	rec2(w, "main", "m00", "ix", "primary", "degraded", "shell", "all_relays_poor", "access", w.ck.now(),
		[]relayLine{{id: "access", iface: "m00", status: "reduced", reason: "mild_rtt", grade: "mild", weight: 400, since: w.ck.now()}, {id: "access2", iface: "m01", status: "active", grade: "good", weight: 600, since: w.ck.now()}}, true)
	good2 := w.upstream
	r, err = ParseUpstreamRecord(good2)
	if err != nil || r.Version != 2 || r.Controller != "shell" || r.Alert != "all_relays_poor" || r.Designated != "access" || len(r.Relays) != 2 ||
		r.Relays[0] != (UpstreamRelay{ID: "access", Iface: "m00", Status: "reduced", Reason: "mild_rtt", Grade: "mild", Weight: 400, StatusSince: w.ck.now().Unix()}) || r.BackupHub != "hkb" {
		t.Fatalf("%+v %v", r, err)
	}
	rec1(w, "udp", "m00", "ix", "primary", "ok", w.ck.now())
	good1 := w.upstream
	bad := map[string]string{
		"empty":            "",
		"header":           strings.Replace(good1, "meridian-upstream 1", "meridian-upstream 3", 1),
		"no end":           strings.TrimSuffix(good1, "end\n"),
		"extra line":       strings.Replace(good1, "end\n", "note x\nend\n", 1),
		"duplicate":        strings.Replace(good1, "hub ix", "path udp", 1),
		"state":            strings.Replace(good1, "state ok", "state fine", 1),
		"v1 degraded":      strings.Replace(good1, "state ok", "state degraded", 1),
		"tier":             strings.Replace(good1, "tier primary", "tier first", 1),
		"since after beat": strings.Replace(good1, "since ", "since 9", 1),
		"spaces":           strings.Replace(good1, "path udp", "path  udp", 1),
		"token":            strings.Replace(good1, "iface m00", "iface m00;x", 1),
		"too long":         good1 + strings.Repeat("x", MaxUpstreamFile),
		"v2 path":          strings.Replace(good2, "path main", "path udp", 1),
		"v2 order":         strings.Replace(strings.Replace(good2, "controller shell\n", "", 1), "designated access\n", "designated access\ncontroller shell\n", 1),
		"v2 relay status":  strings.Replace(good2, " reduced ", " broken ", 1),
		"v2 relay fields":  strings.Replace(good2, " - 0 - - - 0\n", " - 0 - - -\n", 1),
		"v2 relay twice":   strings.Replace(good2, "relay access2 m01", "relay access m01", 1),
		"v2 weight":        strings.Replace(good2, " reduced 400 ", " reduced 4000 ", 1),
		"v2 no relays":     strings.Join(strings.Split(good2, "\n")[:12], "\n") + "\nbackup hkb m03 good 30000 0 29000 0 1 10 20 0\nend\n",
		"v2 controller":    strings.Replace(good2, "controller shell", "controller bash", 1),
		"v2 alert":         strings.Replace(good2, "alert all_relays_poor", "alert All-Poor", 1),
		"v2 backup fields": strings.Replace(good2, "backup hkb m03 good", "backup hkb m03", 1),
	}
	for name, text := range bad {
		if _, err := ParseUpstreamRecord(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseHandshakesAndRoute(t *testing.T) {
	k2 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	latest, peers, err := ParseHandshakes(testKey + "\t1700000000\n" + k2 + "\t1700000300\n\n")
	if err != nil || latest != 1700000300 || peers != 2 {
		t.Fatalf("%d %d %v", latest, peers, err)
	}
	if latest, peers, err := ParseHandshakes(testKey + "\t0\n"); err != nil || latest != 0 || peers != 1 {
		t.Fatalf("no handshake yet: %d %d %v", latest, peers, err)
	}
	if latest, peers, err := ParseHandshakes(""); err != nil || latest != 0 || peers != 0 {
		t.Fatalf("no peers: %d %d %v", latest, peers, err)
	}
	for _, bad := range []string{"notakey\t1\n", testKey + "\n", testKey + "\t-1\n", testKey + "\t1\textra\n", "private key: abc\n", "m00\t" + testKey + "\t1\n"} {
		if _, _, err := ParseHandshakes(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for out, want := range map[string]string{
		"default dev m00 scope link \\\nblackhole default metric 32767 \\\n":  "m00",
		"blackhole default metric 32767 \\\ndefault dev m03 scope link \\\n":  "m03",
		"default via 100.64.0.1 dev mmesh \\\n":                               "mmesh",
		"blackhole default metric 32767 \\\n192.0.2.0/24 dev eth0 scope link": "",
		"": "",
	} {
		if got := ParseRouteDefault(out); got != want {
			t.Errorf("ParseRouteDefault(%q) = %q, want %q", out, got, want)
		}
	}
	if st, reason, _ := tunnelState(0, time.Unix(1700000000, 0), 180); st != TunnelNever || reason == "" {
		t.Fatal(st)
	}
	if st, _, _ := tunnelState(1700000000, time.Unix(1700000180, 0), 180); st != TunnelOK {
		t.Fatal("exactly at the threshold is not stale yet")
	}
	if st, _, _ := tunnelState(1700000000, time.Unix(1700000181, 0), 180); st != TunnelStale {
		t.Fatal("one second past the threshold is stale")
	}
	if st, _, _ := tunnelState(1700000500, time.Unix(1700000000, 0), 180); st != TunnelOK {
		t.Fatal("a handshake newer than the clock is not stale")
	}
}

// The inventory names every class with its source, how it is read, how
// often and how strong the evidence is; the excluded things say why.
func TestInventory(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Inventory() {
		if s.Class == "" || s.ClassLabel == "" || s.Events == "" || s.Source == "" || s.How == "" || s.Cadence == "" || s.Evidence == "" ||
			(s.Strength != StrengthDirect && s.Strength != StrengthProbe && s.Strength != StrengthIndirect) {
			t.Errorf("incomplete row: %+v", s)
		}
		seen[s.Class] = true
	}
	for _, c := range []string{ClassPath, ClassRelay, ClassTunnel, ClassWSS, ClassExternalExit, ClassSniffTarget, ClassCollector} {
		if !seen[c] {
			t.Errorf("class %s has no row", c)
		}
	}
	for _, s := range Inventory() {
		// The external exit's evidence must never read as a confirmed
		// remote failure.
		if s.Class == ClassExternalExit && (s.Strength != StrengthProbe || !strings.Contains(s.Evidence, "不是「代理已经确认不通」")) {
			t.Errorf("external exit row: %+v", s)
		}
		if s.Class == ClassWSS && s.Strength != StrengthIndirect {
			t.Errorf("WSS row: %+v", s)
		}
	}
	var carrier bool
	for _, x := range NotInScope() {
		if x.What == "" || x.Why == "" {
			t.Errorf("incomplete: %+v", x)
		}
		carrier = carrier || strings.Contains(x.What, "meridian-ext-health")
	}
	if !carrier {
		t.Error("the carrier's health check must be listed as not in scope")
	}
}

// The backup group's record line: the backup hub reached through relays.
func TestParseUpstreamRecordBackupGroup(t *testing.T) {
	w := &world{ck: newClock()}
	rec2(w, "backup", "m06", "hkb", "backup", "ok", "go", "on_backup", "bk1", w.ck.now(),
		[]relayLine{{id: "access", iface: "m05", status: "evicted", reason: "down", grade: "down", since: w.ck.now()},
			{id: "bk1", iface: "m06", status: "active", grade: "good", weight: 500, since: w.ck.now()},
			{id: "bk2", iface: "m07", status: "active", grade: "good", weight: 500, since: w.ck.now()}}, false)
	rec := strings.Replace(w.upstream, "end\n", "backup_group hkb bk1 bk2\nend\n", 1)
	r, err := ParseUpstreamRecord(rec)
	if err != nil || r.BackupHub != "hkb" || strings.Join(r.BackupGroup, ",") != "bk1,bk2" || r.Tier != "backup" {
		t.Fatalf("%+v %v", r, err)
	}
	obs := Config{}.upstreamObservations(r)
	if obs[0].State != "backup" || !strings.Contains(obs[0].Evidence, "备用组（bk1、bk2）经中继承载到备用枢纽 hkb") {
		t.Fatalf("%+v", obs[0])
	}
	for _, bad := range []string{
		strings.Replace(rec, "backup_group hkb bk1 bk2", "backup_group hkb bk9", 1),
		strings.Replace(rec, "backup_group hkb bk1 bk2", "backup_group hkb", 1),
	} {
		if _, err := ParseUpstreamRecord(bad); err == nil {
			t.Fatalf("accepted\n%s", bad)
		}
	}
}
