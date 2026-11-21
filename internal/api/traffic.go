package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
)

// GET /api/traffic: the gateway's cumulative forwarded-throughput counters
// (domestic / foreign, up / down; compile.writeTrafficCounters), read
// through the host agent's fixed /v1/traffic. The panel does not compute
// rates: a client polls, and rate = Δbytes / Δread_at between two samples
// whose reset is false. reset is true when any counter went backwards or its
// nft handle changed since the previous read the panel served (an apply
// replaces table inet meridian and zeroes the counters); such a sample is a
// new baseline, not a rate.
//
//	{"available": true, "read_at": "2026-11-17T01:02:03.123Z", "reset": false,
//	 "counters": {"up_domestic": {"bytes": 1, "packets": 1}, ...},
//	 "missing": ["down_foreign"], "code": "", "message": "",
//	 "connections": {"available": true, "read_at": "...", "scope": "lan_and_remote_access",
//	                 "split": true, "domestic": 12, "foreign": 30, "redirected": 4, "total": 46}}
//
// connections: active conntrack entries of LAN and remote-access devices
// through the gateway (hostexec/traffic_conns.go). total = domestic +
// foreign + redirected; redirected are sniff-forwarded TCP connections whose
// side conntrack does not record. On a failed read available is false and the
// counts are null (never 0) with code "read_failed"; it is independent of the
// counters' availability.

// TrafficRuntime is the host agent's counter read (hostexec.Client in main).
type TrafficRuntime interface {
	TrafficStatus(ctx context.Context) (hostexec.TrafficStatus, error)
}

type trafficSample struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

type trafficView struct {
	Available bool                     `json:"available"`
	ReadAt    string                   `json:"read_at,omitempty"`
	Reset     bool                     `json:"reset"`
	Epoch     uint64                   `json:"counter_epoch,omitempty"`
	Counters  map[string]trafficSample `json:"counters"`
	Missing   []string                 `json:"missing,omitempty"`
	Code      string                   `json:"code,omitempty"`
	Message   string                   `json:"message,omitempty"`
	// Connections is null when the agent is unreachable or too old to read them.
	Connections *connView            `json:"connections"`
	UsageSince  map[string]time.Time `json:"usage_since,omitempty"`
	Usage       map[string]uint64    `json:"usage_bytes,omitempty"`
}

type connView struct {
	Available  bool   `json:"available"`
	ReadAt     string `json:"read_at,omitempty"`
	Scope      string `json:"scope"`
	Split      bool   `json:"split"`
	Domestic   *int   `json:"domestic"`
	Foreign    *int   `json:"foreign"`
	Redirected *int   `json:"redirected"`
	Total      *int   `json:"total"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
}

func connectionsView(c *hostexec.ConnCounts) *connView {
	if c == nil {
		return nil
	}
	v := &connView{ReadAt: c.ReadAt, Scope: "lan_and_remote_access"}
	if c.Error != "" || c.Total == nil {
		v.Code, v.Message = "read_failed", c.Error
		return v
	}
	v.Available, v.Total, v.Redirected = true, c.Total, c.Redirected
	if c.Domestic != nil && c.Foreign != nil {
		v.Split, v.Domestic, v.Foreign = true, c.Domestic, c.Foreign
	}
	return v
}

const trafficUsageKey = "gateway_traffic_usage"

type trafficUsageCounter struct {
	Total     uint64
	Sample    hostexec.TrafficCounter
	BootID    string
	StartedAt time.Time
}

type trafficLast struct {
	mu       sync.Mutex
	seen     map[string]hostexec.TrafficCounter
	bootID   string
	epoch    uint64
	sampling bool
	latest   trafficView
	usage    map[string]trafficUsageCounter
	savedAt  time.Time
	dirty    bool
}

// StartTrafficSampler shares a single host probe among all dashboard tabs and
// collects usage even when the dashboard is closed.
func (s *Server) StartTrafficSampler(ctx context.Context) {
	if s.Traffic == nil {
		return
	}
	s.traffic.mu.Lock()
	if s.traffic.sampling {
		s.traffic.mu.Unlock()
		return
	}
	s.traffic.sampling = true
	s.traffic.latest = trafficView{Counters: map[string]trafficSample{}}
	s.traffic.mu.Unlock()
	go s.sampleTraffic(ctx)
}

func (s *Server) sampleTraffic(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		v := s.readTraffic(ctx)
		s.traffic.mu.Lock()
		s.traffic.latest = v
		s.traffic.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	s.traffic.mu.Lock()
	s.saveTrafficUsage(time.Now(), true)
	s.traffic.mu.Unlock()
}

func (s *Server) loadTrafficUsage() {
	if s.traffic.usage != nil {
		return
	}
	var usage map[string]trafficUsageCounter
	if s.Store != nil {
		if raw, ok, err := s.Store.Get(trafficUsageKey); err == nil && ok {
			if err := json.Unmarshal([]byte(raw), &usage); err != nil {
				log.Printf("load traffic usage: %v", err)
			}
		}
	}
	if usage == nil {
		usage = make(map[string]trafficUsageCounter)
	}
	s.traffic.usage = usage
}

func (s *Server) saveTrafficUsage(now time.Time, checkpoint bool) {
	if s.Store == nil || !s.traffic.dirty || (!checkpoint && now.Sub(s.traffic.savedAt) < 30*time.Second) {
		return
	}
	s.traffic.savedAt = now
	raw, err := json.Marshal(s.traffic.usage)
	if err == nil {
		err = s.Store.Put(trafficUsageKey, string(raw))
	}
	if err != nil {
		log.Printf("save traffic usage: %v", err)
		return
	}
	s.traffic.dirty = false
}

func (s *Server) trafficUsageView() map[string]uint64 {
	usage := map[string]uint64{}
	for _, region := range []string{"domestic", "foreign"} {
		up, hasUp := s.traffic.usage["traffic_up_"+region]
		down, hasDown := s.traffic.usage["traffic_down_"+region]
		if hasUp && hasDown {
			usage[region] = up.Total + down.Total
		}
	}
	return usage
}

func (s *Server) populateTrafficUsage(v *trafficView) {
	v.Usage = s.trafficUsageView()
	for region := range v.Usage {
		var since time.Time
		for _, direction := range []string{"up", "down"} {
			counter, ok := s.traffic.usage["traffic_"+direction+"_"+region]
			if !ok {
				continue
			}
			if counter.StartedAt.IsZero() {
				since = time.Time{}
				break
			}
			if since.IsZero() || counter.StartedAt.Before(since) {
				since = counter.StartedAt
			}
		}
		if !since.IsZero() {
			if v.UsageSince == nil {
				v.UsageSince = make(map[string]time.Time)
			}
			v.UsageSince[region] = since
		}
	}
}

// trafficKey drops the "traffic_" prefix of the nft counter name.
func trafficKey(name string) string {
	const p = "traffic_"
	if len(name) > len(p) && name[:len(p)] == p {
		return name[len(p):]
	}
	return name
}

func (s *Server) getTraffic(w http.ResponseWriter, r *http.Request) {
	s.traffic.mu.Lock()
	sampling, v := s.traffic.sampling, s.traffic.latest
	s.traffic.mu.Unlock()
	if !sampling {
		v = s.readTraffic(r.Context())
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) readTraffic(ctx context.Context) trafficView {
	v := trafficView{Counters: map[string]trafficSample{}}
	if s.Traffic == nil {
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到流量计数"
		return v
	}
	ctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
	defer cancel()
	st, err := s.Traffic.TrafficStatus(ctx)
	v.ReadAt = st.ReadAt
	if err == nil {
		v.Connections = connectionsView(st.Connections)
	}
	switch {
	case err != nil && errors.Is(err, hostexec.ErrUnavailable):
		v.Code, v.Message = "agent_unavailable", err.Error()
	case err != nil:
		v.Code, v.Message = "read_failed", err.Error()
	case st.Error != "":
		v.Code, v.Message = "read_failed", st.Error
	}
	s.traffic.mu.Lock()
	defer s.traffic.mu.Unlock()
	s.loadTrafficUsage()
	defer func() { s.saveTrafficUsage(time.Now(), v.Reset) }()
	if v.Code != "" {
		s.populateTrafficUsage(&v)
		return v
	}
	for _, m := range st.Missing {
		v.Missing = append(v.Missing, trafficKey(m))
	}
	if len(st.Counters) == 0 {
		v.Code, v.Message = "not_installed", "网关还没有流量计数器（还没有按当前版本安装）"
		s.populateTrafficUsage(&v)
		return v
	}
	v.Available = true
	bootChanged := st.BootID != "" && s.traffic.bootID != "" && st.BootID != s.traffic.bootID
	v.Reset = bootChanged
	next := make(map[string]hostexec.TrafficCounter, len(st.Counters))
	for _, c := range st.Counters {
		next[c.Name] = c
		v.Counters[trafficKey(c.Name)] = trafficSample{Bytes: c.Bytes, Packets: c.Packets}
		if p, ok := s.traffic.seen[c.Name]; ok && counterReset(p, c) {
			v.Reset = true
		}
		p, known := s.traffic.usage[c.Name]
		delta := c.Bytes
		if known && !counterReset(p.Sample, c) && (p.BootID == "" || st.BootID == "" || p.BootID == st.BootID) {
			delta -= p.Sample.Bytes
		}
		if !known || p.Sample != c || (st.BootID != "" && p.BootID != st.BootID) {
			bootID := p.BootID
			if st.BootID != "" {
				bootID = st.BootID
			}
			if !known {
				p.StartedAt, _ = time.Parse(time.RFC3339Nano, st.ReadAt)
				if p.StartedAt.IsZero() {
					p.StartedAt = time.Now()
				}
			}
			s.traffic.usage[c.Name] = trafficUsageCounter{Total: p.Total + delta, Sample: c, BootID: bootID, StartedAt: p.StartedAt}
			s.traffic.dirty = true
		}
	}
	s.traffic.seen = next
	if v.Reset {
		s.traffic.epoch++
	}
	v.Epoch = s.traffic.epoch
	if st.BootID != "" {
		s.traffic.bootID = st.BootID
	}
	s.populateTrafficUsage(&v)
	return v
}

func counterReset(p, c hostexec.TrafficCounter) bool {
	return p.Handle != c.Handle || c.Bytes < p.Bytes || c.Packets < p.Packets
}
