package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/mtu"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/store"
	"github.com/radowitz/meridian/internal/validate"
)

// The uplink MTU of both ends of every tunnel leg, and the explicit
// adoption of a suggested tunnel MTU (docs/architecture.md「上联 MTU」).
//
//   - GET /api/mtu/uplinks combines, per leg, what the latest preflight of
//     each end found about its uplink (preflight.UplinkFact). A fact counts
//     only while it is bound to the same node identity (deployment, server,
//     address, pinned key, credential), is at most uplinkFactTTL old and
//     was taken for the same plan (mtu.Carrier.SamePlan: interface,
//     family, peer address, mark); anything else is "stale" or "unknown",
//     never verified. It is judged against the leg's current tunnel MTU,
//     and where an end cannot carry it the smallest end's suggestion is
//     offered, with the per-node file differences and the path MTU / MSS
//     changes adopting it would cause.
//   - POST /api/mtu/adopt writes exactly the shown suggestions into the
//     links' existing MTU field, compare-and-set on the value the operator
//     saw. It changes the stored topology only: nothing reaches a host
//     until the deploy page's own review and confirmation (preflight,
//     per-node changes). Nothing else ever changes a tunnel MTU: an unknown
//     uplink keeps the configured value, and no upgrade, preflight or
//     background job writes one.

// uplinkFactTTL is how long a preflight's uplink observation is used for
// suggestions. An install itself always runs a fresh preflight.
const uplinkFactTTL = 24 * time.Hour

const (
	codeMTUSuggestionChanged = "mtu_suggestion_changed"
	codeMTUNothing           = "mtu_nothing_to_adopt"
)

// Uplink end statuses besides the preflight's (fits, too_small, unknown,
// tcp_carrier).
const (
	uplinkStale       = "stale"
	uplinkNoPreflight = "no_preflight"
)

type uplinkEnd struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	// Status: fits | too_small | tcp_carrier | unknown | stale |
	// no_preflight. Only fits / too_small / tcp_carrier are verified.
	Status      string           `json:"status"`
	Reason      string           `json:"reason,omitempty"`
	Dev         string           `json:"dev,omitempty"`
	UplinkMTU   int              `json:"uplink_mtu,omitempty"`
	Family      int              `json:"family"`
	Peer        string           `json:"peer,omitempty"`
	MaxInner    int              `json:"max_inner,omitempty"`
	Shortfall   int              `json:"shortfall,omitempty"`
	Suggested   int              `json:"suggested,omitempty"`
	WSS         *mtu.WSSEstimate `json:"wss,omitempty"`
	PreflightID string           `json:"preflight_id,omitempty"`
	At          *time.Time       `json:"at,omitempty"`
}

type uplinkLeg struct {
	LinkID   string `json:"link_id"`
	LinkName string `json:"link_name,omitempty"`
	Mode     string `json:"mode"`
	Iface    string `json:"iface"`
	// Field / Configured: the link field that sets TunnelMTU and its value
	// (0 = the transport default).
	Field      string      `json:"field"`
	Configured int         `json:"configured"`
	TunnelMTU  int         `json:"tunnel_mtu"`
	Ends       []uplinkEnd `json:"ends"`
	// Status: too_small when an end cannot carry TunnelMTU; fits when both
	// ends were verified to; tcp_carrier for WSS; unknown otherwise.
	Status string `json:"status"`
	// Suggested is the smallest suggestion of the ends that cannot carry
	// the MTU; Limiting the node it comes from. Adoptable: it can be
	// written into Field (≥ 1280 and lower than TunnelMTU, UDP leg).
	Suggested int    `json:"suggested,omitempty"`
	Limiting  string `json:"limiting,omitempty"`
	Adoptable bool   `json:"adoptable"`
	Note      string `json:"note,omitempty"`
}

type mtuChange struct {
	LinkID string `json:"link_id"`
	Field  string `json:"field"`
	// From is the field's value the operator saw (0 = default), To the
	// value written.
	From int `json:"from"`
	To   int `json:"to"`
	// FromEffective is the tunnel MTU From stands for.
	FromEffective int `json:"from_effective,omitempty"`
}

type nodeFileDiff struct {
	NodeID   string   `json:"node_id"`
	NodeName string   `json:"node_name"`
	Files    []string `json:"files"`
}

type pathMTUDiff struct {
	ExitID     string `json:"exit_id"`
	MTUBefore  int    `json:"mtu_before"`
	MTUAfter   int    `json:"mtu_after"`
	MSS4Before int    `json:"mss4_before"`
	MSS4After  int    `json:"mss4_after"`
	MSS6Before int    `json:"mss6_before"`
	MSS6After  int    `json:"mss6_after"`
}

// groupPathMTUDiff is a region group's path MTU before and after
// (compile.Bundle.GroupPaths: its members' paths and its Mesh fallback);
// the group's own clamp follows it where it is below the global clamp.
type groupPathMTUDiff struct {
	GroupID    string `json:"group_id"`
	Mesh       bool   `json:"mesh"`
	MTUBefore  int    `json:"mtu_before"`
	MTUAfter   int    `json:"mtu_after"`
	MSS4Before int    `json:"mss4_before"`
	MSS4After  int    `json:"mss4_after"`
	MSS6Before int    `json:"mss6_before"`
	MSS6After  int    `json:"mss6_after"`
}

type mtuProposal struct {
	Changes    []mtuChange        `json:"changes"`
	Nodes      []nodeFileDiff     `json:"nodes"`
	Paths      []pathMTUDiff      `json:"paths"`
	GroupPaths []groupPathMTUDiff `json:"group_paths"`
	Error      string             `json:"error,omitempty"`
}

type uplinkMTUView struct {
	Legs        []uplinkLeg  `json:"legs"`
	Proposal    *mtuProposal `json:"proposal,omitempty"`
	TTLHours    int          `json:"ttl_hours"`
	NotVerified []string     `json:"not_verified"`
}

var uplinkNotVerified = []string{
	"预检只证明每一端本机的约束：隧道包从哪块网卡出去、这块网卡（和路由）的 MTU 是多少。路径上更小的 MTU（运营商、隧道、云厂商的网络）看不到：按验证说明用不允许分片的 ping 人工核对",
	"WSS 隧道由 wstunnel 的 TCP 承载：上联 MTU 只决定分段，不会丢包；给出的段数是估算",
	"对端用域名、或对端拨入且拓扑里没有它的固定地址时，按这一端的默认路由判断",
	"采用建议只改拓扑里的 MTU 字段；要在部署页预检、审阅每个节点的变更并确认后才会下发",
}

// endFact finds the verified fact of carrier c on node n from its latest
// preflight, or says why there is none.
func (s *Server) endFact(n model.Node, c mtu.Carrier, dep string, cs *credentials.Store, now time.Time) uplinkEnd {
	end := uplinkEnd{NodeID: n.ID, NodeName: n.Name, Family: c.Family, Peer: c.Peer, Status: preflight.UplinkUnknown}
	key := n.ID
	if n.Role == model.RoleGateway {
		key = localNodeID
	}
	rec := s.loadPreflight(key)
	if rec == nil {
		end.Status, end.Reason = uplinkNoPreflight, "这个节点还没有预检"
		return end
	}
	at := rec.At
	end.PreflightID, end.At = rec.ID, &at
	switch {
	case rec.NodeID != key || rec.Deployment != dep:
		end.Status, end.Reason = uplinkStale, "预检记录不属于这个节点或这个面板"
		return end
	case now.Sub(rec.At) > uplinkFactTTL:
		end.Status, end.Reason = uplinkStale, fmt.Sprintf("预检结果超过 %d 小时，重新预检", int(uplinkFactTTL.Hours()))
		return end
	case n.Role != model.RoleGateway:
		if cs == nil {
			end.Status, end.Reason = uplinkStale, "凭据库不可用，不能确认预检时的目标就是现在的服务器"
			return end
		}
		ident, err := identityOf(cs, n)
		if err != nil || rec.Target == nil || !rec.Target.same(ident) {
			end.Status, end.Reason = uplinkStale, "预检之后这个节点的服务器、地址、主机指纹或凭据变了，重新预检"
			return end
		}
	}
	if rec.Uplinks == nil {
		end.Reason = "这条预检记录没有上联信息（早于这项检查，或主机上的预检是旧版本）"
		return end
	}
	for _, f := range rec.Uplinks {
		if f.Key() != c.Key() {
			continue
		}
		if !f.SamePlan(c) {
			end.Status, end.Reason = uplinkStale, "预检之后这条隧道的走向变了（接口、地址族、对端地址），重新预检"
			return end
		}
		j := f.Rejudge(c)
		end.Status, end.Reason, end.Dev, end.UplinkMTU = j.Status, j.Reason, j.Dev, j.UplinkMTU
		end.MaxInner, end.Shortfall, end.Suggested, end.WSS = j.MaxInner, j.Shortfall, j.Suggested, j.WSS
		return end
	}
	end.Status, end.Reason = uplinkStale, "预检时还没有这条隧道，重新预检"
	return end
}

// uplinkLegs combines both ends of every tunnel leg of t.
func (s *Server) uplinkLegs(t model.Topology, now time.Time) []uplinkLeg {
	dep, _ := s.deploymentID()
	cs, _ := s.credStore()
	byKey := map[string]*uplinkLeg{}
	var order []string
	for _, n := range t.Nodes {
		if !n.Managed && n.Role != model.RoleGateway {
			continue
		}
		carriers, err := compile.UplinkCarriers(t, n.ID)
		if err != nil {
			continue
		}
		for _, c := range carriers {
			leg, ok := byKey[c.Key()]
			if !ok {
				leg = &uplinkLeg{LinkID: c.LinkID, LinkName: c.LinkName, Mode: c.Mode, Iface: c.Iface, Field: c.Field, Configured: c.Configured, TunnelMTU: c.TunnelMTU}
				byKey[c.Key()] = leg
				order = append(order, c.Key())
			}
			leg.Ends = append(leg.Ends, s.endFact(n, c, dep, cs, now))
		}
	}
	sort.Strings(order)
	out := make([]uplinkLeg, 0, len(order))
	for _, k := range order {
		leg := byKey[k]
		verified := 0
		for _, e := range leg.Ends {
			switch e.Status {
			case preflight.UplinkTooSmall:
				leg.Status = preflight.UplinkTooSmall
				if leg.Suggested == 0 || e.Suggested < leg.Suggested {
					leg.Suggested, leg.Limiting = e.Suggested, e.NodeID
				}
			case preflight.UplinkFits, preflight.UplinkTCP:
				verified++
			}
		}
		switch {
		case leg.Status == preflight.UplinkTooSmall:
		case leg.Mode == mtu.ModeWSS && verified == len(leg.Ends):
			leg.Status = preflight.UplinkTCP
		case verified == len(leg.Ends) && verified > 0:
			leg.Status = preflight.UplinkFits
		default:
			leg.Status = preflight.UplinkUnknown
		}
		if leg.Status == preflight.UplinkTooSmall {
			switch {
			case leg.Suggested < mtu.MinTunnel:
				leg.Note = fmt.Sprintf("能承载的隧道 MTU 只有 %d，低于 %d：这条上联承载不了 UDP 隧道，改用 WSS 传输或换上联", leg.Suggested, mtu.MinTunnel)
			case leg.Mode != mtu.ModeUDP || leg.Field != "mtu" || leg.Suggested >= leg.TunnelMTU:
				leg.Note = "建议值不能写入这条链路的 MTU 字段"
			default:
				leg.Adoptable = true
			}
			for _, e := range leg.Ends {
				if e.Status != preflight.UplinkTooSmall && e.Status != preflight.UplinkFits {
					leg.Note = strings.TrimPrefix(leg.Note+"；"+e.NodeName+" 一端的上联还没有验证（"+e.Status+"）：建议值只按已验证的一端算", "；")
				}
			}
		}
		out = append(out, *leg)
	}
	return out
}

// mtuProposalFor compiles t with the changes applied and lists, per node,
// the files that differ and, per exit and per switched region group (its
// Mesh fallback included), the path MTU and MSS before and after (every
// clamp follows the path minimum).
func mtuProposalFor(t model.Topology, changes []mtuChange) *mtuProposal {
	p := &mtuProposal{Changes: changes, Nodes: []nodeFileDiff{}, Paths: []pathMTUDiff{}, GroupPaths: []groupPathMTUDiff{}}
	before, err := compile.Compile(t)
	if err != nil {
		p.Error = "现在的拓扑不能编译，算不出各节点的差异：" + err.Error()
		return p
	}
	next := applyMTUChanges(t, changes)
	after, err := compile.Compile(next)
	if err != nil {
		p.Error = "采用之后的拓扑不能编译：" + err.Error()
		return p
	}
	files := map[string][]string{}
	for path, body := range after.Files {
		if before.Files[path] != body {
			addNodeFile(files, path)
		}
	}
	for path := range before.Files {
		if _, ok := after.Files[path]; !ok {
			addNodeFile(files, path)
		}
	}
	ids := make([]string, 0, len(files))
	for id := range files {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		name := id
		if n, ok := t.NodeByID(id); ok && n.Name != "" {
			name = n.Name
		}
		sort.Strings(files[id])
		p.Nodes = append(p.Nodes, nodeFileDiff{NodeID: id, NodeName: name, Files: files[id]})
	}
	was := map[string]validate.PathReport{}
	for _, r := range before.Paths {
		was[r.ExitID] = r
	}
	for _, r := range after.Paths {
		b, ok := was[r.ExitID]
		if !ok || (b.MTU == r.MTU && b.MSS4 == r.MSS4 && b.MSS6 == r.MSS6) {
			continue
		}
		p.Paths = append(p.Paths, pathMTUDiff{ExitID: r.ExitID, MTUBefore: b.MTU, MTUAfter: r.MTU, MSS4Before: b.MSS4, MSS4After: r.MSS4, MSS6Before: b.MSS6, MSS6After: r.MSS6})
	}
	gwas := map[string]validate.GroupPathReport{}
	for _, r := range before.GroupPaths {
		gwas[r.GroupID] = r
	}
	for _, r := range after.GroupPaths {
		b, ok := gwas[r.GroupID]
		if !ok || (b.MTU == r.MTU && b.MSS4 == r.MSS4 && b.MSS6 == r.MSS6) {
			continue
		}
		p.GroupPaths = append(p.GroupPaths, groupPathMTUDiff{GroupID: r.GroupID, Mesh: r.Mesh, MTUBefore: b.MTU, MTUAfter: r.MTU, MSS4Before: b.MSS4, MSS4After: r.MSS4, MSS6Before: b.MSS6, MSS6After: r.MSS6})
	}
	return p
}

func addNodeFile(files map[string][]string, path string) {
	rest, ok := strings.CutPrefix(path, "nodes/")
	if !ok {
		return
	}
	id, file, ok := strings.Cut(rest, "/")
	if !ok {
		return
	}
	files[id] = append(files[id], "/"+file)
}

// applyMTUChanges returns a copy of t with the changes written into the
// links' fields.
func applyMTUChanges(t model.Topology, changes []mtuChange) model.Topology {
	next := t
	next.Links = append([]model.Link(nil), t.Links...)
	for _, c := range changes {
		for i := range next.Links {
			if next.Links[i].ID != c.LinkID {
				continue
			}
			switch c.Field {
			case "mtu":
				next.Links[i].MTU = c.To
			case "wss_mtu":
				next.Links[i].WSSMTU = c.To
			}
		}
	}
	return next
}

func (s *Server) uplinkMTUView(t model.Topology, now time.Time) uplinkMTUView {
	v := uplinkMTUView{Legs: s.uplinkLegs(t, now), TTLHours: int(uplinkFactTTL.Hours()), NotVerified: uplinkNotVerified}
	var changes []mtuChange
	for _, l := range v.Legs {
		if l.Adoptable {
			changes = append(changes, mtuChange{LinkID: l.LinkID, Field: l.Field, From: l.Configured, To: l.Suggested, FromEffective: l.TunnelMTU})
		}
	}
	if len(changes) > 0 {
		v.Proposal = mtuProposalFor(t, changes)
	}
	return v
}

func (s *Server) getUplinkMTU(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.uplinkMTUView(t, time.Now()))
}

type mtuAdoptBody struct {
	Changes []mtuChange `json:"changes"`
}

var errMTUChanged = errors.New("mtu changed")

// postUplinkMTUAdopt writes the confirmed suggestions into the topology.
// Every change must be one the current view offers, with the same field,
// the value the operator saw (From) and the suggestion (To); the write is
// a compare-and-set on From. It never touches a host.
func (s *Server) postUplinkMTUAdopt(w http.ResponseWriter, r *http.Request) {
	var body mtuAdoptBody
	if err := decodeStrict(w, r, &body, []string{"changes"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	for _, c := range body.Changes {
		if c.LinkID == "" || c.Field == "" || c.To <= 0 {
			writeCoded(w, http.StatusBadRequest, codeBadRequest, "每一项要有 link_id、field、from（看到的值，默认值为 0）和 to", nil)
			return
		}
	}
	if len(body.Changes) == 0 {
		writeCoded(w, http.StatusBadRequest, codeMTUNothing, "没有要采用的建议", nil)
		return
	}
	s.raMu.Lock()
	defer s.raMu.Unlock()
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	view := s.uplinkMTUView(t, time.Now())
	offered := map[string]uplinkLeg{}
	for _, l := range view.Legs {
		if l.Adoptable {
			offered[l.LinkID] = l
		}
	}
	seen := map[string]bool{}
	for i, c := range body.Changes {
		l, ok := offered[c.LinkID]
		if seen[c.LinkID] || !ok || l.Field != c.Field || l.Configured != c.From || l.Suggested != c.To {
			writeCoded(w, http.StatusConflict, codeMTUSuggestionChanged,
				fmt.Sprintf("链路 %s 的建议已经不是你看到的值（拓扑或预检结果变了），没有写入任何内容：刷新后重新确认", c.LinkID), map[string]any{"uplinks": view})
			return
		}
		seen[c.LinkID] = true
		body.Changes[i].FromEffective = l.TunnelMTU
	}
	proposal := mtuProposalFor(t, body.Changes)
	var issues []validate.Issue
	_, err = s.Store.Update(func(cur *model.Topology) (bool, error) {
		for _, c := range body.Changes {
			found := false
			for i := range cur.Links {
				l := &cur.Links[i]
				if l.ID != c.LinkID {
					continue
				}
				found = true
				if l.MTU != c.From {
					return false, errMTUChanged
				}
				l.MTU = c.To
			}
			if !found {
				return false, errMTUChanged
			}
		}
		res := validate.Run(*cur)
		if res.HasErrors() {
			issues = res.Issues
			return false, errInvalidAfterAdopt
		}
		return true, nil
	})
	switch {
	case errors.Is(err, errMTUChanged):
		writeCoded(w, http.StatusConflict, codeMTUSuggestionChanged, "写入前链路的 MTU 被别的保存改了，没有写入任何内容：刷新后重新确认", nil)
		return
	case errors.Is(err, errInvalidAfterAdopt):
		writeCoded(w, http.StatusUnprocessableEntity, codeTopologyInvalid, "采用之后的拓扑校验不通过，没有写入任何内容", map[string]any{"issues": issues})
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	stored, _ := s.topology()
	writeJSON(w, http.StatusOK, map[string]any{
		"topology": store.Redact(stored),
		"adopted":  body.Changes,
		"proposal": proposal,
		"message":  "已写入拓扑的 MTU 字段，没有下发到任何节点：到部署页预检、审阅每个节点的变更并确认后才会生效。",
	})
}

var errInvalidAfterAdopt = errors.New("invalid after adopt")
