package pathquality

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner runs one fixed program (ping, wg, nft) and returns its output.
type Runner interface {
	Run(ctx context.Context, prog string, args ...string) (string, error)
}

// ExecRunner runs programs from PATH.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, prog string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
	return string(out), err
}

// Measurer gathers one pass: a burst of small echoes on every leg and on
// the backup path (in parallel), the interfaces' byte counters, the
// WireGuard handshakes, the per-relay nft counters, and the throughput
// probes the previous pass asked for.
type Measurer struct {
	Run Runner
	// SysRoot prefixes /sys/class/net (tests).
	SysRoot string
	// Clock is the wall clock used to time probes (tests may fix it).
	Clock func() time.Time
}

var (
	rePingCount = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received`)
	rePingRTT   = regexp.MustCompile(`= [0-9.]+/([0-9.]+)/`)
)

// ParsePing reads ping's -q summary: sent, received and the average RTT.
func ParsePing(out string) (sent, recv int, rttUS int64) {
	m := rePingCount.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, 0
	}
	sent, _ = strconv.Atoi(m[1])
	recv, _ = strconv.Atoi(m[2])
	if r := rePingRTT.FindStringSubmatch(out); r != nil && recv > 0 {
		if v, err := strconv.ParseFloat(r[1], 64); err == nil {
			rttUS = int64(v*1000 + 0.5)
		}
	}
	return sent, recv, rttUS
}

// ParseNFTCounters reads "nft -j list counters table inet meridian":
// name → (packets).
func ParseNFTCounters(out string) map[string]uint64 {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Table   string `json:"table"`
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	res := map[string]uint64{}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return res
	}
	for _, o := range doc.Nftables {
		if o.Counter != nil && o.Counter.Table == "meridian" {
			res[o.Counter.Name] = o.Counter.Packets
		}
	}
	return res
}

func (ms Measurer) ping(ctx context.Context, iface, addr string) LegSample {
	ls := LegSample{Iface: iface}
	out, _ := ms.Run.Run(ctx, "ping", "-n", "-q", "-I", iface, "-c", strconv.Itoa(PingCount), "-i", "0.2", "-W", "1", addr)
	ls.Sent, ls.Recv, ls.RTTus = ParsePing(out)
	if ls.Sent == 0 {
		ls.Sent = PingCount
	}
	return ls
}

// probe runs one throughput probe: Settings.ProbeBytes in packets of
// probePacketBytes, paced at Settings.ProbeRateKbps.
func (ms Measurer) probe(ctx context.Context, c Config, iface, addr string) ProbeResult {
	s := c.Settings
	n := probePackets(s)
	interval := float64(probePacketBytes*8) / float64(s.ProbeRateKbps*1000)
	if interval < 0.002 {
		interval = 0.002
	}
	deadline := int(float64(n)*interval) + 3
	start := ms.now()
	out, _ := ms.Run.Run(ctx, "ping", "-n", "-q", "-I", iface, "-c", strconv.Itoa(n), "-i", strconv.FormatFloat(interval, 'f', 3, 64),
		"-s", strconv.Itoa(probePacketBytes), "-W", "1", "-w", strconv.Itoa(deadline), addr)
	elapsed := ms.now().Sub(start).Milliseconds()
	sent, recv, _ := ParsePing(out)
	if sent == 0 {
		sent = n
	}
	return ProbeResult{Sent: sent, Recv: recv, PacketBytes: probePacketBytes, ElapsedMS: elapsed}
}

func (ms Measurer) now() time.Time {
	if ms.Clock != nil {
		return ms.Clock()
	}
	return time.Now()
}

func (ms Measurer) counter(iface, name string) uint64 {
	b, err := os.ReadFile(filepath.Join(ms.SysRoot, "/sys/class/net", iface, "statistics", name))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func (ms Measurer) handshake(ctx context.Context, iface string) int64 {
	out, err := ms.Run.Run(ctx, "wg", "show", iface, "latest-handshakes")
	if err != nil {
		return 0
	}
	var latest int64
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil && v > latest {
				latest = v
			}
		}
	}
	return latest
}

// Measure gathers one pass. st (may be nil) says which probes are wanted.
func (ms Measurer) Measure(ctx context.Context, c Config, st *State, now int64) Measurement {
	if ms.Run == nil {
		ms.Run = ExecRunner{}
	}
	m := Measurement{Now: now, Relays: map[string]PathSample{}}
	type job struct {
		relay int // -1: backup
		leg   int
	}
	var jobs []job
	for i, r := range c.Relays {
		for j := range r.Legs {
			jobs = append(jobs, job{i, j})
		}
	}
	if c.Backup != nil {
		jobs = append(jobs, job{-1, 0})
	}
	results := make([]LegSample, len(jobs))
	var wg sync.WaitGroup
	pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for k, jb := range jobs {
		wg.Add(1)
		go func(k int, jb job) {
			defer wg.Done()
			if jb.relay < 0 {
				results[k] = ms.ping(pctx, c.Backup.Iface, c.Backup.Probe)
			} else {
				r := c.Relays[jb.relay]
				results[k] = ms.ping(pctx, r.Legs[jb.leg].Iface, r.Probe)
			}
		}(k, jb)
	}
	wg.Wait()
	counters := map[string]uint64{}
	if out, err := ms.Run.Run(ctx, "nft", "-j", "list", "counters", "table", "inet", "meridian"); err == nil {
		counters = ParseNFTCounters(out)
	}
	fill := func(ls LegSample) LegSample {
		ls.RxBytes, ls.TxBytes = ms.counter(ls.Iface, "rx_bytes"), ms.counter(ls.Iface, "tx_bytes")
		ls.Handshake = ms.handshake(ctx, ls.Iface)
		return ls
	}
	for k, jb := range jobs {
		results[k] = fill(results[k])
		if jb.relay < 0 {
			ps := PathSample{Legs: []LegSample{results[k]}}
			ps.New = counters["share_bk_new"]
			m.Backup = &ps
			continue
		}
		r := c.Relays[jb.relay]
		ps := m.Relays[r.ID]
		ps.Legs = append(ps.Legs, results[k])
		pre := fmt.Sprintf("share_r%d_", r.Index)
		ps.TCPOut, ps.TCPIn, ps.New = counters[pre+"tcp_out"], counters[pre+"tcp_in"], counters[pre+"new"]
		m.Relays[r.ID] = ps
	}
	// Throughput probes, one relay at a time (they would compete for the
	// same access line otherwise), on the leg in use.
	if st != nil {
		for _, r := range c.Relays {
			rs := st.Relays[r.ID]
			if rs == nil || !rs.ProbeWanted || c.Settings.ProbeOff {
				continue
			}
			leg := rs.Leg
			if leg == "" {
				leg = r.Legs[0].Iface
			}
			p := ms.probe(ctx, c, leg, r.Probe)
			ps := m.Relays[r.ID]
			ps.Probe = &p
			m.Relays[r.ID] = ps
		}
	}
	return m
}
