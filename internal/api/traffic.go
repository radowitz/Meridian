package api

import (
	"context"
	"errors"
	"net/http"
	"sync"

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
	Counters  map[string]trafficSample `json:"counters"`
	Missing   []string                 `json:"missing,omitempty"`
	Code      string                   `json:"code,omitempty"`
	Message   string                   `json:"message,omitempty"`
	// Connections is null when the agent is unreachable or too old to read them.
	Connections *connView `json:"connections"`
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

// trafficLast is the previous sample served, for reset detection.
type trafficLast struct {
	mu   sync.Mutex
	seen map[string]hostexec.TrafficCounter
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
	v := trafficView{Counters: map[string]trafficSample{}}
	if s.Traffic == nil {
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到流量计数"
		writeJSON(w, http.StatusOK, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), statusAgentTimeout)
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
	if v.Code != "" {
		writeJSON(w, http.StatusOK, v)
		return
	}
	for _, m := range st.Missing {
		v.Missing = append(v.Missing, trafficKey(m))
	}
	if len(st.Counters) == 0 {
		v.Code, v.Message = "not_installed", "网关还没有流量计数器（还没有按当前版本安装）"
		writeJSON(w, http.StatusOK, v)
		return
	}
	v.Available = true
	s.traffic.mu.Lock()
	next := make(map[string]hostexec.TrafficCounter, len(st.Counters))
	for _, c := range st.Counters {
		next[c.Name] = c
		v.Counters[trafficKey(c.Name)] = trafficSample{Bytes: c.Bytes, Packets: c.Packets}
		if p, ok := s.traffic.seen[c.Name]; ok && (p.Handle != c.Handle || c.Bytes < p.Bytes || c.Packets < p.Packets) {
			v.Reset = true
		}
	}
	s.traffic.seen = next
	s.traffic.mu.Unlock()
	writeJSON(w, http.StatusOK, v)
}
