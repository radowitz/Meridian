package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sshexec"
)

// The hub's actual region-group state. POST /api/region-groups/runtime/refresh
// logs in to the hub node's managed server over the existing SSH connector
// (trusted, pinned host key; stored credential) and runs the one fixed,
// read-only command sshexec.GroupStateCommand. Nothing from the request
// reaches the command. The parsed answer (or why there is none) is stored
// with the time of the read and judged per group on every GET against the
// topology the panel would deploy now (hubstate.Evaluate). See
// docs/architecture.md「地区组」.
//
// Every read is bound to the hub identity it was taken from
// (hubstate.Identity: hub node, server ID, normalised address, SSH port,
// pinned host-key fingerprint). The identity is captured before the read,
// the SSH connection is pinned to it (sshexec.Target), a result whose
// identity is no longer the current one when the read ends is discarded
// (hub_identity_changed, nothing stored), and every display compares the
// stored read's identity with the current one, so a change of any field
// makes the old report unknown at once — not after ReadMaxAge.

const groupHubKey = "group_hub_state"

// groupHub is the stored read and what is needed to judge it: current is
// the hub identity the panel would read now.
type groupHub struct {
	read       *hubstate.Read
	current    hubstate.Identity
	refreshing bool
	now        time.Time
}

func (h groupHub) actual(plans groupPlans, spec hubstate.GroupSpec) hubstate.Actual {
	if !plans.compiled {
		// Without a compiled plan the panel cannot tell which groups the
		// hub switches, nor which version it should run.
		a := hubstate.Actual{State: hubstate.StateUnavailable, Code: hubstate.CodePlanUnavailable,
			Message: "面板无法编译当前拓扑的地区组计划，不能核对枢纽的运行状态"}
		if h.read != nil {
			a.ReadAt = &h.read.ReadAt
		}
		return a
	}
	return hubstate.Evaluate(spec, h.read, h.current, plans.planID, plans.staleAfter, h.now)
}

func (s *Server) loadGroupHub() *hubstate.Read {
	raw, ok, err := s.Store.Get(groupHubKey)
	if err != nil || !ok {
		return nil
	}
	var rd hubstate.Read
	if json.Unmarshal([]byte(raw), &rd) != nil || rd.ReadAt.IsZero() {
		return nil
	}
	return &rd
}

func (s *Server) saveGroupHub(rd hubstate.Read) error {
	buf, err := json.Marshal(rd)
	if err != nil {
		return err
	}
	return s.Store.Put(groupHubKey, string(buf))
}

// groupHub loads the stored read with the identity of t's hub as it is now.
func (s *Server) groupHub(t model.Topology) groupHub {
	s.groupHubMu.Lock()
	refreshing := s.groupHubBusy
	s.groupHubMu.Unlock()
	return groupHub{read: s.loadGroupHub(), current: s.hubReachability(t).identity, refreshing: refreshing, now: time.Now().UTC()}
}

func hubNode(t model.Topology) (model.Node, bool) {
	for _, n := range t.Nodes {
		if n.Role == model.RoleHub {
			return n, true
		}
	}
	return model.Node{}, false
}

// hubReach says whether the hub can be read now, and if not why (a
// hubstate code and a message).
type hubReach struct {
	node   model.Node
	server model.Server
	// identity is the hub the panel would read now; its fingerprint is set
	// only while the server's host key is trusted.
	identity hubstate.Identity
	code     string
	sshCode  string
	msg      string
	readable bool
}

func (s *Server) hubReachability(t model.Topology) hubReach {
	n, ok := hubNode(t)
	if !ok {
		return hubReach{code: hubstate.CodeNoHub, msg: "拓扑里没有枢纽节点"}
	}
	r := hubReach{node: n, identity: hubstate.Identity{HubNode: n.ID, ServerID: n.ServerID}}
	if n.ServerID == "" {
		r.code, r.msg = hubstate.CodeHubNoServer, fmt.Sprintf("枢纽节点 %s 还没有关联服务器；在拓扑里为它选择服务器", nodeName(t, n.ID))
		return r
	}
	cs, err := s.credStore()
	if err != nil {
		r.code, r.msg = hubstate.CodeServerNotReady, "读不到服务器与凭据存储"
		return r
	}
	sv, err := cs.Server(n.ServerID)
	if err != nil {
		r.code, r.msg = hubstate.CodeHubNoServer, fmt.Sprintf("枢纽节点 %s 关联的服务器不存在", nodeName(t, n.ID))
		return r
	}
	r.server = sv
	r.identity = serverIdentity(n.ID, sv)
	if err := serverOperable(cs, sv); err != nil {
		r.code, r.sshCode, r.msg = hubstate.CodeServerNotReady, resCode(err), err.Error()
		return r
	}
	r.readable = true
	return r
}

// serverIdentity is the identity of hub node nodeID on server sv. The pin
// is the trusted fingerprint, or the pinned one the host contradicted
// (mismatch: same pin, not trusted). Any other key state has no pin: an
// address or port edit, forgetting the key or discovering a new one all
// clear it.
func serverIdentity(nodeID string, sv model.Server) hubstate.Identity {
	fp := ""
	switch sv.HostKey.State {
	case model.HostKeyTrusted, model.HostKeyMismatch:
		fp = sv.HostKey.Fingerprint
	}
	id := hubstate.NewIdentity(nodeID, sv.ID, sv.Address, sv.Port, fp)
	id.Trusted = fp != "" && sv.HostKey.State == model.HostKeyTrusted
	return id
}

type hubStateView struct {
	HubNode       string `json:"hub_node,omitempty"`
	HubName       string `json:"hub_name,omitempty"`
	ServerID      string `json:"server_id,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	Readable      bool   `json:"readable"`
	NotReadable   string `json:"not_readable_code,omitempty"`
	NotReadableSC string `json:"not_readable_ssh_code,omitempty"`
	NotReadableMs string `json:"not_readable_message,omitempty"`
	// LastRead is the stored read: when, and why it failed if it did.
	LastRead *lastReadView `json:"last_read"`
	// Refreshing: a read is running now.
	Refreshing bool `json:"refreshing"`
	// The rules the states follow (seconds).
	LoopIntervalSec int `json:"loop_interval_sec"`
	StaleAfterSec   int `json:"stale_after_sec"`
	ReadMaxAgeSec   int `json:"read_max_age_sec"`
	SkewWarnSec     int `json:"skew_warn_sec"`
	// Counts of actual states over the groups.
	Counts map[string]int `json:"counts"`
}

type lastReadView struct {
	ReadAt       time.Time `json:"read_at"`
	OK           bool      `json:"ok"`
	ErrorCode    string    `json:"error_code,omitempty"`
	SSHCode      string    `json:"ssh_code,omitempty"`
	RetryAfter   int       `json:"retry_after,omitempty"`
	Error        string    `json:"error,omitempty"`
	ClockSkewSec *int64    `json:"clock_skew_sec,omitempty"`
	// CurrentHub is false when the read was taken from another hub
	// identity than the current one (code hub_identity_changed); its
	// result then says nothing about the current hub.
	CurrentHub bool `json:"current_hub"`
	// IdentityCode / IdentityMessage say why, when CurrentHub is false.
	IdentityCode    string `json:"identity_code,omitempty"`
	IdentityMessage string `json:"identity_message,omitempty"`
	// Ignored are group IDs the hub reported that the topology does not
	// have (left over from an earlier plan); they are not shown.
	Ignored []string `json:"ignored"`
}

func (h groupHub) view(t model.Topology, reach hubReach, plans groupPlans) hubStateView {
	v := hubStateView{
		HubNode: reach.node.ID, HubName: reach.node.Name, ServerID: reach.server.ID, ServerName: reach.server.Name,
		Readable: reach.readable, NotReadable: reach.code, NotReadableSC: reach.sshCode, NotReadableMs: reach.msg,
		Refreshing:      h.refreshing,
		LoopIntervalSec: int(compile.HubLoopInterval / time.Second),
		StaleAfterSec:   int(plans.staleAfter / time.Second),
		ReadMaxAgeSec:   int(hubstate.ReadMaxAge / time.Second),
		SkewWarnSec:     int(hubstate.SkewWarn / time.Second),
		Counts:          map[string]int{},
	}
	if v.ServerID == "" {
		v.ServerID = reach.node.ServerID
	}
	if rd := h.read; rd != nil {
		lr := &lastReadView{ReadAt: rd.ReadAt, ErrorCode: rd.ErrorCode, SSHCode: rd.SSHCode, RetryAfter: rd.RetryAfter, Error: rd.Error, Ignored: []string{}}
		lr.OK = rd.ErrorCode == "" && rd.Snapshot != nil
		lr.CurrentHub = rd.Bound(h.current)
		if !lr.CurrentHub {
			lr.IdentityCode, lr.IdentityMessage = hubstate.CodeIdentityChanged, hubstate.IdentityMessage(rd.Identity, h.current)
		}
		if rd.Snapshot != nil && lr.CurrentHub {
			sk := int64(rd.Skew() / time.Second)
			lr.ClockSkewSec = &sk
			for id := range rd.Snapshot.Reports {
				if _, ok := t.GroupByID(id); !ok {
					lr.Ignored = append(lr.Ignored, id)
				}
			}
			sort.Strings(lr.Ignored)
		}
		v.LastRead = lr
	}
	return v
}

func (s *Server) groupsBody(t model.Topology) map[string]any {
	plans, rt := plansOf(t), s.groupRuntime()
	hub := s.groupHub(t)
	out := []groupView{}
	for _, g := range sortedGroups(t) {
		out = append(out, viewGroup(t, g, plans, rt, hub))
	}
	hv := hub.view(t, s.hubReachability(t), plans)
	for _, g := range out {
		hv.Counts[g.Actual.State]++
	}
	return map[string]any{
		"groups": out, "default_group": t.Settings.DefaultGroup, "thresholds": thresholds(), "hub_state": hv,
	}
}

func (s *Server) oneGroupView(t model.Topology, g model.RegionGroup) groupView {
	plans := plansOf(t)
	return viewGroup(t, g, plans, s.groupRuntime(), s.groupHub(t))
}

// refreshGroupRuntime reads the hub's group state once. 200 with the
// groups whatever the outcome (the outcome is stored and shown per group);
// 409 refresh_in_progress while another read runs; 409
// hub_identity_changed when the hub identity changed while the read ran
// (the late result is discarded, nothing is stored). The body is ignored:
// the target is the topology's hub node and the command is a constant.
func (s *Server) refreshGroupRuntime(w http.ResponseWriter, r *http.Request) {
	s.groupHubMu.Lock()
	if s.groupHubBusy {
		s.groupHubMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"code": hubstate.CodeRefreshInProgress, "error": "正在读取枢纽状态，请稍后"})
		return
	}
	s.groupHubBusy = true
	s.groupHubMu.Unlock()
	defer func() {
		s.groupHubMu.Lock()
		s.groupHubBusy = false
		s.groupHubMu.Unlock()
	}()
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	reach := s.hubReachability(t)
	rd := s.readHub(r.Context(), reach)
	// Late-result guard: the read describes reach.identity only. If the
	// hub node, its server, the address, port or pinned key changed while
	// it ran, the result is not stored as the current state. (A change
	// after this check is still caught: the stored read carries its
	// identity and every display compares it with the current one.)
	t2, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	if now := s.hubReachability(t2).identity; !now.Equal(rd.Identity) {
		writeJSON(w, http.StatusConflict, map[string]any{"code": hubstate.CodeIdentityChanged,
			"error": "读取期间枢纽的" + strings.Join(rd.Identity.Differs(now), "、") + "已变更，这次读取的结果已丢弃，没有作为当前状态保存；请对当前枢纽重新读取"})
		return
	}
	if err := s.saveGroupHub(rd); err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.groupsBody(t2))
}

// readHub performs the read against the identity in reach; every failure
// becomes a result bound to that identity.
func (s *Server) readHub(ctx context.Context, reach hubReach) hubstate.Read {
	rd := hubstate.Read{Identity: reach.identity}
	if !reach.readable {
		rd.ReadAt = time.Now().UTC()
		rd.ErrorCode, rd.SSHCode, rd.Error = reach.code, reach.sshCode, reach.msg
		return rd
	}
	cs, err := s.credStore()
	if err != nil {
		rd.ReadAt = time.Now().UTC()
		rd.ErrorCode, rd.Error = hubstate.CodeServerNotReady, "读不到服务器与凭据存储"
		return rd
	}
	// Pinned to the captured identity: the connector refuses a server whose
	// endpoint or trusted key changed since, and a host presenting another
	// key than reach.identity.Fingerprint.
	sv := reach.server
	out, err := s.connector(cs).ReadGroupState(ctx, sshexec.Target{ServerID: sv.ID, Address: sv.Address, Port: sv.Port, User: sv.User, Fingerprint: reach.identity.Fingerprint})
	rd.ReadAt = time.Now().UTC()
	if err != nil {
		code := sshexec.CodeOf(err)
		switch code {
		case sshexec.CodeUntrusted, sshexec.CodeMismatch, sshexec.CodeNoCredential, sshexec.CodeTargetChanged, sshexec.CodePinMismatch:
			rd.ErrorCode = hubstate.CodeServerNotReady
		default:
			rd.ErrorCode = hubstate.CodeSSHFailed
		}
		if code == "" {
			code = sshexec.CodeCommandFailed
		}
		// sshexec errors are already scrubbed of the credential.
		rd.SSHCode, rd.Error, rd.RetryAfter = code, "读取枢纽状态失败："+err.Error(), sshexec.RetryAfterOf(err)
		return rd
	}
	snap, err := hubstate.Parse(out)
	if err != nil {
		var pe *hubstate.ParseError
		msg := "枢纽输出无法解析"
		if errors.As(err, &pe) {
			msg += "（" + pe.Msg + "）"
		}
		rd.ErrorCode, rd.Error = hubstate.CodeParseError, msg
		return rd
	}
	rd.Snapshot = &snap
	return rd
}
