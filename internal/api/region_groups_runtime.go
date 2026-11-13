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

// groupHubKeyBackup holds the backup hub's read (the primary keeps the
// original key, so a stored single-hub read stays where it was; it is
// bound to its hub node anyway).
const groupHubKeyBackup = "group_hub_state_backup"

func hubStoreKey(tier model.HubTier) string {
	if tier == model.HubBackup {
		return groupHubKeyBackup
	}
	return groupHubKey
}

// groupHub is one hub's stored read and what is needed to judge it:
// current is the identity of that hub as the panel would read it now.
type groupHub struct {
	tier       model.HubTier
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

func (s *Server) loadGroupHub(tier model.HubTier) *hubstate.Read {
	raw, ok, err := s.Store.Get(hubStoreKey(tier))
	if err != nil || !ok {
		return nil
	}
	var rd hubstate.Read
	if json.Unmarshal([]byte(raw), &rd) != nil || rd.ReadAt.IsZero() {
		return nil
	}
	return &rd
}

func (s *Server) saveGroupHub(tier model.HubTier, rd hubstate.Read) error {
	buf, err := json.Marshal(rd)
	if err != nil {
		return err
	}
	return s.Store.Put(hubStoreKey(tier), string(buf))
}

// groupHub loads the primary hub's stored read with its identity as it is now.
func (s *Server) groupHub(t model.Topology) groupHub {
	return s.groupHubTier(t, model.HubPrimary)
}

func (s *Server) groupHubTier(t model.Topology, tier model.HubTier) groupHub {
	s.groupHubMu.Lock()
	refreshing := s.groupHubBusy
	s.groupHubMu.Unlock()
	return groupHub{tier: tier, read: s.loadGroupHub(tier), current: s.hubReachabilityTier(t, tier).identity, refreshing: refreshing, now: time.Now().UTC()}
}

// hubByTier is the topology's primary or backup hub.
func hubByTier(t model.Topology, tier model.HubTier) (model.Node, bool) {
	if tier == model.HubBackup {
		return t.BackupHub()
	}
	return t.PrimaryHub()
}

// hubTiers are the tiers the topology has, primary first.
func hubTiers(t model.Topology) []model.HubTier {
	var out []model.HubTier
	if _, ok := t.PrimaryHub(); ok {
		out = append(out, model.HubPrimary)
	}
	if t.DualHub() {
		out = append(out, model.HubBackup)
	}
	return out
}

func tierText(tier model.HubTier) string {
	if tier == model.HubBackup {
		return "备用枢纽"
	}
	return "主枢纽"
}

// hubReach says whether the hub can be read now, and if not why (a
// hubstate code and a message).
type hubReach struct {
	tier   model.HubTier
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
	return s.hubReachabilityTier(t, model.HubPrimary)
}

func (s *Server) hubReachabilityTier(t model.Topology, tier model.HubTier) hubReach {
	n, ok := hubByTier(t, tier)
	if !ok {
		return hubReach{tier: tier, code: hubstate.CodeNoHub, msg: "拓扑里没有" + tierText(tier) + "节点"}
	}
	r := hubReach{tier: tier, node: n, identity: hubstate.Identity{HubNode: n.ID, ServerID: n.ServerID}}
	if n.ServerID == "" {
		r.code, r.msg = hubstate.CodeHubNoServer, fmt.Sprintf("%s %s 还没有关联服务器；在拓扑里为它选择服务器", tierText(tier), nodeName(t, n.ID))
		return r
	}
	cs, err := s.credStore()
	if err != nil {
		r.code, r.msg = hubstate.CodeServerNotReady, "读不到服务器与凭据存储"
		return r
	}
	sv, err := cs.Server(n.ServerID)
	if err != nil {
		r.code, r.msg = hubstate.CodeHubNoServer, fmt.Sprintf("%s %s 关联的服务器不存在", tierText(tier), nodeName(t, n.ID))
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
	// Tier is primary or backup.
	Tier          model.HubTier `json:"tier"`
	HubNode       string        `json:"hub_node,omitempty"`
	HubName       string        `json:"hub_name,omitempty"`
	ServerID      string        `json:"server_id,omitempty"`
	ServerName    string        `json:"server_name,omitempty"`
	Readable      bool          `json:"readable"`
	NotReadable   string        `json:"not_readable_code,omitempty"`
	NotReadableSC string        `json:"not_readable_ssh_code,omitempty"`
	NotReadableMs string        `json:"not_readable_message,omitempty"`
	// Carrying: this hub carries the gateway's traffic now, as the gateway
	// recorded it (always true for a lone hub).
	Carrying bool `json:"carrying"`
	// LastRead is the stored read: when, and why it failed if it did.
	LastRead *lastReadView `json:"last_read"`
	// Refreshing: a read is running now.
	Refreshing bool `json:"refreshing"`
	// PlanID is the group plan the panel would deploy to this hub now.
	PlanID string `json:"plan_id,omitempty"`
	// The rules the states follow (seconds).
	LoopIntervalSec int `json:"loop_interval_sec"`
	StaleAfterSec   int `json:"stale_after_sec"`
	ReadMaxAgeSec   int `json:"read_max_age_sec"`
	SkewWarnSec     int `json:"skew_warn_sec"`
	// Counts of actual states over the groups (this hub's own judgement).
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
		Tier:    reach.tier,
		HubNode: reach.node.ID, HubName: reach.node.Name, ServerID: reach.server.ID, ServerName: reach.server.Name,
		Readable: reach.readable, NotReadable: reach.code, NotReadableSC: reach.sshCode, NotReadableMs: reach.msg,
		Refreshing:      h.refreshing,
		PlanID:          plans.planID,
		LoopIntervalSec: int(compile.HubLoopInterval / time.Second),
		StaleAfterSec:   int(plans.staleAfter / time.Second),
		ReadMaxAgeSec:   int(hubstate.ReadMaxAge / time.Second),
		SkewWarnSec:     int(hubstate.SkewWarn / time.Second),
		Counts:          map[string]int{},
	}
	if v.Tier == "" {
		v.Tier = model.HubPrimary
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

// hubCtx is one hub as one request sees it.
type hubCtx struct {
	tier  model.HubTier
	reach hubReach
	hub   groupHub
	plans groupPlans
}

// hubSet is every hub of the topology plus which one carries the traffic.
type hubSet struct {
	dual     bool
	hubs     []hubCtx
	carrying carryingView
}

// hubSet builds the per-hub reads and plans and asks the gateway which hub
// carries the traffic (dual-hub topologies only).
func (s *Server) hubSet(ctx context.Context, t model.Topology) hubSet {
	hs := hubSet{dual: t.DualHub()}
	for _, tier := range hubTiers(t) {
		n, _ := hubByTier(t, tier)
		plans := plansOf(t)
		if tier != model.HubPrimary {
			plans = plansForHub(t, n.ID)
		}
		hs.hubs = append(hs.hubs, hubCtx{tier: tier, reach: s.hubReachabilityTier(t, tier), hub: s.groupHubTier(t, tier), plans: plans})
	}
	hs.carrying = s.carryingHub(ctx, t)
	return hs
}

// carrier is the hub whose state is the group's actual state: the lone
// hub, or the hub the gateway recorded as carrying; nil when that is not
// known (the state is then not shown as measured).
func (hs hubSet) carrier() *hubCtx {
	if len(hs.hubs) == 0 {
		return nil
	}
	if !hs.dual {
		return &hs.hubs[0]
	}
	if !hs.carrying.Known {
		return nil
	}
	for i := range hs.hubs {
		if hs.hubs[i].tier == hs.carrying.Tier {
			return &hs.hubs[i]
		}
	}
	return nil
}

// hubActual is one hub's judgement of a group (dual-hub views).
type hubActual struct {
	Tier    model.HubTier `json:"tier"`
	HubNode string        `json:"hub_node"`
	HubName string        `json:"hub_name,omitempty"`
	hubstate.Actual
	Carrying bool `json:"carrying"`
}

// actualOf judges group g on the carrying hub, plus every hub separately.
func (hs hubSet) actualOf(t model.Topology, g model.RegionGroup) (actualView, []hubActual) {
	var by []hubActual
	if hs.dual {
		for _, h := range hs.hubs {
			by = append(by, hubActual{Tier: h.tier, HubNode: h.reach.node.ID, HubName: h.reach.node.Name,
				Actual: h.hub.actual(h.plans, h.plans.spec(t, g)), Carrying: hs.carrying.Known && hs.carrying.Tier == h.tier})
		}
	}
	c := hs.carrier()
	if c == nil {
		a := actualView{Actual: hubstate.Actual{State: hubstate.StateUnavailable, Code: CodeCarryingUnknown,
			Message: "不知道现在由哪个枢纽承载（" + hs.carrying.Message + "）；不把任一枢纽的报告当作实际使用"}}
		return a, by
	}
	a := actualView{Actual: c.hub.actual(c.plans, c.plans.spec(t, g)), HubTier: c.tier, HubNode: c.reach.node.ID, HubName: c.reach.node.Name, ServerName: c.reach.server.Name}
	return a, by
}

// CodeCarryingUnknown: with a backup hub, the gateway did not tell which
// hub carries the traffic (agent unreachable, no or stale record), so no
// hub's report is shown as the member in use.
const CodeCarryingUnknown = "carrying_unknown"

func (s *Server) groupsBody(ctx context.Context, t model.Topology) map[string]any {
	plans, rt := plansOf(t), s.groupRuntime()
	hs := s.hubSet(ctx, t)
	out := []groupView{}
	for _, g := range sortedGroups(t) {
		out = append(out, viewGroup(t, g, plans, rt, hs))
	}
	views := hs.views(t)
	for _, g := range out {
		if len(views) > 0 {
			views[0].Counts[g.Actual.State]++
		}
	}
	if hs.dual {
		// Per-hub counts are each hub's own judgement.
		for i := range views {
			views[i].Counts = map[string]int{}
		}
		for _, g := range out {
			for _, a := range g.ActualByHub {
				for i := range views {
					if views[i].Tier == a.Tier {
						views[i].Counts[a.State]++
					}
				}
			}
		}
	}
	body := map[string]any{
		"groups": out, "default_group": t.Settings.DefaultGroup, "thresholds": thresholds(),
		"hub_states": views, "carrying": hs.carrying,
	}
	if len(views) > 0 {
		body["hub_state"] = views[0]
	} else {
		body["hub_state"] = s.groupHub(t).view(t, s.hubReachability(t), plans)
	}
	return body
}

// views are the per-hub state views, primary first.
func (hs hubSet) views(t model.Topology) []hubStateView {
	out := []hubStateView{}
	for _, h := range hs.hubs {
		v := h.hub.view(t, h.reach, h.plans)
		v.Carrying = !hs.dual || (hs.carrying.Known && hs.carrying.Tier == h.tier)
		out = append(out, v)
	}
	return out
}

func (s *Server) oneGroupView(ctx context.Context, t model.Topology, g model.RegionGroup) groupView {
	plans := plansOf(t)
	return viewGroup(t, g, plans, s.groupRuntime(), s.hubSet(ctx, t))
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
	// Every hub of the topology, one after the other; each read is bound to
	// its own hub's identity and stored under its tier.
	var discarded []string
	for _, tier := range hubTiers(t) {
		reach := s.hubReachabilityTier(t, tier)
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
		if now := s.hubReachabilityTier(t2, tier).identity; !now.Equal(rd.Identity) {
			discarded = append(discarded, fmt.Sprintf("%s的%s", tierText(tier), strings.Join(rd.Identity.Differs(now), "、")))
			continue
		}
		if err := s.saveGroupHub(tier, rd); err != nil {
			writeResErr(w, err)
			return
		}
	}
	if len(discarded) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"code": hubstate.CodeIdentityChanged,
			"error": "读取期间" + strings.Join(discarded, "；") + "已变更，这次读取的结果已丢弃，没有作为当前状态保存；请对当前枢纽重新读取"})
		return
	}
	t2, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.groupsBody(r.Context(), t2))
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
