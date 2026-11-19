package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

type ExitLatencyRuntime interface {
	ExitLatency(context.Context, hostexec.ExitLatencyRequest) (hostexec.ExitLatencyResult, error)
}
type cachedExitLatency struct {
	Key    string
	Result hostexec.ExitLatencyResult
}
type exitLatencyRow struct {
	hostexec.ExitLatencyResult
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Stale bool   `json:"stale"`
}
type exitLatencyView struct {
	Available bool             `json:"available"`
	Running   bool             `json:"running"`
	Rows      []exitLatencyRow `json:"rows"`
}

func latencyTopologyKey(t model.Topology) string {
	model.MigrateRegionGroups(&t)
	model.MigrateAllocations(&t)
	model.MigrateRuleOrder(&t)
	b, _ := json.Marshal(t)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func latencyKey(p compile.ProbeExit) string {
	return fmt.Sprintf("%d|%s|%s|%s", p.Mark, p.TransitV4, p.TransitV6, p.Resolver)
}
func (s *Server) latencyView(t model.Topology, ps map[string]compile.ProbeExit) exitLatencyView {
	s.latencyMu.Lock()
	defer s.latencyMu.Unlock()
	topologyKey := latencyTopologyKey(t)
	out := exitLatencyView{Available: s.ExitLatency != nil, Running: s.latencyBusy, Rows: []exitLatencyRow{}}
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit {
			continue
		}
		p, ok := ps[n.ID]
		if !ok {
			continue
		}
		row := exitLatencyRow{ExitLatencyResult: hostexec.ExitLatencyResult{ExitID: n.ID, State: "not_measured"}, Name: n.Name, Scope: "exit_resolver"}
		if p.TCPOnly {
			row.Scope = "carrier_resolver"
		}
		if c, ok := s.latencyCache[n.ID]; ok && c.Key == latencyKey(p)+"|"+topologyKey {
			row.ExitLatencyResult = c.Result
			row.Stale = c.Result.MeasuredAt.IsZero() || time.Since(c.Result.MeasuredAt) > 2*time.Minute || time.Until(c.Result.MeasuredAt) > 10*time.Second
		}
		out.Rows = append(out.Rows, row)
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].ExitID < out.Rows[j].ExitID })
	return out
}
func (s *Server) latencyPlan(w http.ResponseWriter) (model.Topology, map[string]compile.ProbeExit, bool) {
	t, err := s.topology()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return t, nil, false
	}
	ps, err := compile.ProbeExits(t)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "拓扑无法生成出口测量路径", "code": "invalid_topology"})
		return t, nil, false
	}
	return t, ps, true
}
func (s *Server) getExitLatency(w http.ResponseWriter, r *http.Request) {
	t, p, ok := s.latencyPlan(w)
	if ok {
		writeJSON(w, 200, s.latencyView(t, p))
	}
}
func (s *Server) measureExitLatency(w http.ResponseWriter, r *http.Request) {
	var in struct{}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "测量不接受自定义目标或参数", "code": "invalid_request"})
		return
	}
	t, ps, ok := s.latencyPlan(w)
	if !ok {
		return
	}
	if s.ExitLatency == nil {
		writeJSON(w, 503, map[string]string{"error": "宿主代理尚不支持出口延迟测量，请同时升级面板与 meridian-host", "code": "host_unavailable"})
		return
	}
	if !s.sniffInstalledCurrent(t) {
		writeJSON(w, 409, map[string]string{"error": "网关配置与当前拓扑不一致，请先安装再测量", "code": "gateway_not_in_sync"})
		return
	}
	s.latencyMu.Lock()
	if s.latencyBusy {
		s.latencyMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "已有一轮延迟测量在进行", "code": "measurement_running"})
		return
	}
	if time.Since(s.latencyLast) < 10*time.Second {
		s.latencyMu.Unlock()
		writeJSON(w, 200, s.latencyView(t, ps))
		return
	}
	s.latencyBusy = true
	s.latencyLast = time.Now()
	s.latencyMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	topologyKey := latencyTopologyKey(t)
	jobs := make(chan compile.ProbeExit)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				req := hostexec.ExitLatencyRequest{RequestID: fmt.Sprintf("latency-%d/%s", time.Now().UnixNano(), p.ID), ExitID: p.ID, Mark: p.Mark, TransitV4: p.TransitV4, TransitV6: p.TransitV6, Resolver: p.Resolver}
				sample, err := s.ExitLatency.ExitLatency(ctx, req)
				if err != nil {
					sample = hostexec.ExitLatencyResult{ExitID: p.ID, State: "unavailable", MeasuredAt: time.Now().UTC(), Error: "宿主测量失败：" + err.Error()}
				}
				if sample.ExitID != p.ID {
					sample = hostexec.ExitLatencyResult{ExitID: p.ID, State: "unavailable", MeasuredAt: time.Now().UTC(), Error: "宿主返回了不匹配的出口"}
				}
				s.latencyMu.Lock()
				if s.latencyCache == nil {
					s.latencyCache = map[string]cachedExitLatency{}
				}
				s.latencyCache[p.ID] = cachedExitLatency{latencyKey(p) + "|" + topologyKey, sample}
				s.latencyMu.Unlock()
			}
		}()
	}
	ids := make([]string, 0, len(ps))
	for id := range ps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		select {
		case jobs <- ps[id]:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	// Re-read the topology so a sample from a changed path cannot appear current.
	current, err := s.topology()
	if err == nil {
		if planned, e := compile.ProbeExits(current); e == nil {
			t, ps = current, planned
		}
	}
	s.latencyMu.Lock()
	s.latencyBusy = false
	s.latencyMu.Unlock()
	writeJSON(w, 200, s.latencyView(t, ps))
}
