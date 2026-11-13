package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

// Which hub carries the gateway's traffic. With a backup hub only the
// gateway knows: its failover loop records the path in use in a fixed file
// (compile.planUpstream), which meridian-host reads with its fixed,
// parameterless upstream status read. The panel never infers the carrying
// hub from anything else (docs/architecture.md「主枢纽与备用枢纽」).

// UpstreamRuntime is the host agent's upstream status read
// (hostexec.Client in main).
type UpstreamRuntime interface {
	UpstreamStatus(ctx context.Context) (hostexec.UpstreamStatus, error)
}

// upstreamFresh: a record whose heartbeat is older than this (the
// gateway's own clock, which is the panel's: they run on the same host)
// no longer says which hub carries: the failover loop writes every pass
// (about every 5 to 20 seconds).
const upstreamFresh = 60 * time.Second

// carryingView answers "which hub carries the traffic now".
type carryingView struct {
	// Mode: single (one hub, it carries everything) or dual.
	Mode string `json:"mode"`
	// Known: the carrying hub is known (always for single).
	Known   bool          `json:"known"`
	Tier    model.HubTier `json:"tier,omitempty"`
	HubNode string        `json:"hub_node,omitempty"`
	HubName string        `json:"hub_name,omitempty"`
	// Path, Iface, State, Since, Beat: the gateway's record (dual).
	Path  string     `json:"path,omitempty"`
	Iface string     `json:"iface,omitempty"`
	State string     `json:"state,omitempty"`
	Since *time.Time `json:"since,omitempty"`
	Beat  *time.Time `json:"beat,omitempty"`
	// Source: topology (single), gateway (the gateway's record).
	Source string `json:"source"`
	// Code / Message: why it is not known, or a caveat (static, down).
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	ReadAt  string `json:"read_at,omitempty"`
}

func (s *Server) carryingHub(ctx context.Context, t model.Topology) carryingView {
	if !t.DualHub() {
		v := carryingView{Mode: "single", Source: "topology"}
		if p, ok := t.PrimaryHub(); ok {
			v.Known, v.Tier, v.HubNode, v.HubName = true, model.HubPrimary, p.ID, p.Name
		}
		return v
	}
	v := carryingView{Mode: "dual", Source: "gateway"}
	if s.Upstream == nil {
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到网关记录的上游路径"
		return v
	}
	ctx, cancel := context.WithTimeout(ctx, statusAgentTimeout)
	defer cancel()
	st, err := s.Upstream.UpstreamStatus(ctx)
	v.ReadAt = st.ReadAt
	switch {
	case err != nil && errors.Is(err, hostexec.ErrUnavailable):
		v.Code, v.Message = "agent_unavailable", err.Error()
		return v
	case err != nil:
		v.Code, v.Message = "read_failed", err.Error()
		return v
	case !st.Present:
		v.Code, v.Message = "not_recorded", "网关还没有上游记录（还没有按带备用枢纽的拓扑安装到本机，或切换服务没有运行）"
		return v
	case st.Record == nil:
		v.Code, v.Message = "invalid_record", "网关的上游记录无法解析："+st.Error
		return v
	}
	rec := st.Record
	since, beat := time.Unix(rec.Since, 0).UTC(), time.Unix(rec.Beat, 0).UTC()
	v.Path, v.Iface, v.State, v.Since, v.Beat = rec.Path, rec.Iface, rec.State, &since, &beat
	hub, ok := hubByTier(t, model.HubTier(rec.Tier))
	if !ok || hub.ID != rec.Hub {
		v.Code, v.Message = "record_mismatch", "网关记录的枢纽（"+rec.Hub+"）与当前拓扑的"+tierText(model.HubTier(rec.Tier))+"不一致：网关还没有按当前拓扑安装"
		return v
	}
	if age := time.Since(beat); age > upstreamFresh {
		v.Code, v.Message = "stale", "网关的上游记录已超过 60 秒没有更新（切换服务可能没有运行）"
		return v
	}
	v.Known, v.Tier, v.HubNode, v.HubName = true, model.HubTier(rec.Tier), hub.ID, hub.Name
	switch rec.State {
	case hostexec.UpstreamStatic:
		v.Message = "安装时设定的路径，切换服务还没有报告测量结果"
	case hostexec.UpstreamDown:
		v.Message = "上一轮没有任何路径应答：流量停在这条隧道里被丢弃，不会从局域网口直出"
	case hostexec.UpstreamSwitching:
		v.Message = "正在等待切换的滞回条件"
	}
	return v
}

// getUpstream: GET /api/upstream, the carrying hub alone (overview page).
func (s *Server) getUpstream(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.carryingHub(r.Context(), t))
}
