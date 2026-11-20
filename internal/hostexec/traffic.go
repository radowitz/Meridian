package hostexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Forwarded-throughput counters of the gateway (compile.writeTrafficCounters).
// The read is fixed and parameterless: the agent runs exactly
// `nft -j list counters table inet meridian` and returns only the four
// traffic_* counters. No table, counter name or path comes from the caller.

// TrafficCounterNames mirrors compile.TrafficCounterNames (hostexec does not
// import compile).
var TrafficCounterNames = []string{"traffic_up_domestic", "traffic_up_foreign", "traffic_down_domestic", "traffic_down_foreign"}

// TrafficCounter is one cumulative nft named counter.
type TrafficCounter struct {
	Name    string `json:"name"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	// Handle is the nft object handle: it changes when the table is
	// replaced (an apply), which also zeroes the counter.
	Handle uint64 `json:"handle"`
}

// TrafficStatus is the agent's answer. Counters holds the traffic_*
// counters found, in TrafficCounterNames order; Missing names those absent
// (table not installed yet, or an older ruleset without counters).
type TrafficStatus struct {
	ReadAt   string           `json:"read_at"`
	BootID   string           `json:"boot_id,omitempty"`
	Counters []TrafficCounter `json:"counters"`
	Missing  []string         `json:"missing,omitempty"`
	Error    string           `json:"error,omitempty"`
	// Connections is the active-connection read (traffic_conns.go); its
	// failure is its own Error and does not fail the counters.
	Connections *ConnCounts `json:"connections,omitempty"`
}

// ParseTrafficCounters parses `nft -j list counters` output.
func ParseTrafficCounters(out string) ([]TrafficCounter, []string, error) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Name    string `json:"name"`
				Handle  uint64 `json:"handle"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, nil, fmt.Errorf("nft 计数器输出无法解析：%w", err)
	}
	found := map[string]TrafficCounter{}
	for _, e := range doc.Nftables {
		c := e.Counter
		if c == nil || c.Family != "inet" || c.Table != "meridian" {
			continue
		}
		found[c.Name] = TrafficCounter{Name: c.Name, Bytes: c.Bytes, Packets: c.Packets, Handle: c.Handle}
	}
	var got []TrafficCounter
	var missing []string
	for _, n := range TrafficCounterNames {
		if c, ok := found[n]; ok {
			got = append(got, c)
		} else {
			missing = append(missing, n)
		}
	}
	return got, missing, nil
}

// TrafficStatus reads the counters.
func (a *Agent) TrafficStatus(ctx context.Context) TrafficStatus {
	a.init()
	st := TrafficStatus{ReadAt: time.Now().UTC().Format(time.RFC3339Nano), Counters: []TrafficCounter{}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := a.Runner.Run(ctx, "nft", "-j", "list", "counters", "table", "inet", "meridian")
	if err != nil {
		st.Missing = append([]string(nil), TrafficCounterNames...)
		st.Error = "读取计数器失败（表可能还没安装）：" + err.Error()
		return st
	}
	got, missing, err := ParseTrafficCounters(out)
	if err != nil {
		st.Missing = append([]string(nil), TrafficCounterNames...)
		st.Error = err.Error()
		return st
	}
	st.Counters, st.Missing = append(st.Counters, got...), missing
	if id, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		st.BootID = strings.TrimSpace(string(id))
	}
	return st
}

func (a *Agent) serveTraffic(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	// The only accepted body is an empty object: no caller-supplied value.
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	var empty struct{}
	if err := dec.Decode(&empty); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, TrafficStatus{Error: "请求格式不正确（不接受任何参数）"})
		return
	}
	st := a.TrafficStatus(r.Context())
	cc := a.cachedTrafficConnections(r.Context())
	st.Connections = &cc
	writeJSON(w, http.StatusOK, st)
}

type trafficConnectionsCache struct {
	mu     sync.Mutex
	at     time.Time
	counts ConnCounts
}

// Connection counting scans conntrack. Reuse it for a few traffic samples
// while byte counters are read at one-second resolution.
func (a *Agent) cachedTrafficConnections(ctx context.Context) ConnCounts {
	cache := &a.trafficConnections
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if time.Since(cache.at) >= 5*time.Second {
		cache.counts = a.ConnStatus(ctx)
		cache.at = time.Now()
	}
	return cache.counts
}

// TrafficStatus asks the agent for the traffic counters.
func (c *Client) TrafficStatus(ctx context.Context) (TrafficStatus, error) {
	var st TrafficStatus
	code, err := c.post(ctx, "/v1/traffic", struct{}{}, 10*time.Second, &st)
	if err != nil {
		return st, err
	}
	if code != http.StatusOK {
		return st, fmt.Errorf("host agent 读取流量计数失败（%d）：%s", code, st.Error)
	}
	return st, nil
}
