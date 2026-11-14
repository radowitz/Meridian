package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
)

// Per-node install state.
//
// Every node is compared with what was actually installed on it, never
// with another node's install or with the gateway's applied snapshot:
//
//   - the gateway: its installed manifest (file hashes, written by the host
//     transaction) against the gateway files the stored topology compiles
//     to (statusInstall.State);
//   - a remote node: provisionOutcome.InstalledBundle (the digest of the
//     node's files of its last successful install, the same digest the
//     host's manifest records) against the digest of the node's files the
//     stored topology compiles to now, plus the identity it was installed
//     to and the last read-back of the host's record (Verify).
//
// So installing one remote node on its own changes that node's state only.

// Verify states.
const (
	verifyOK       = "verified"   // the host's record names this node, deployment, server and bundle
	verifyMismatch = "mismatch"   // the host's record says something else
	verifyUnread   = "unverified" // the record could not be read
)

// nodeVerify is one read-back of a remote node's own record.
type nodeVerify struct {
	At     time.Time `json:"at"`
	State  string    `json:"state"`
	Source string    `json:"source"` // post_install | preflight
	// HostBundle is the bundle digest the host's manifest records.
	HostBundle string `json:"host_bundle,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// migrateOutcome fills the installed-state fields of a record written
// before they existed: a record whose last outcome was a successful
// install carries exactly that install's bundle and identity. Idempotent;
// records it cannot fill stay "unknown" until a preflight reads the host's
// manifest (recordHostManifest) or the node is installed again.
func migrateOutcome(o provisionOutcome) provisionOutcome {
	if !o.Installed || o.InstalledBundle != "" || !o.OK || o.Bundle == "" {
		return o
	}
	at := o.At
	o.InstalledBundle, o.InstalledAt, o.InstalledRun = o.Bundle, &at, o.Run
	if o.InstalledTarget == nil {
		o.InstalledTarget = &targetIdentity{ServerID: o.ServerID, Address: o.Address, Port: o.Port, User: o.User, Fingerprint: o.Fingerprint, CredentialID: o.CredentialID}
	}
	return o
}

// verifyAgainst compares the host's record with what this panel installed.
func verifyAgainst(st *preflight.NodeState, node, deployment, server, bundle, run, source string, at time.Time) *nodeVerify {
	v := &nodeVerify{At: at, Source: source}
	if st == nil || !st.Complete {
		v.State, v.Detail = verifyUnread, "没有读到服务器上的安装记录（读取失败或输出不完整）"
		return v
	}
	m := st.Manifest
	switch {
	case m == nil:
		v.State, v.Detail = verifyMismatch, "服务器上没有 Meridian 节点清单"
	case m.Node != node || m.Deployment != deployment:
		v.State, v.Detail = verifyMismatch, fmt.Sprintf("服务器上的清单属于节点 %s / 部署 %s", orDashS(m.Node), orDashS(m.Deployment))
	case server != "" && m.Server != "" && m.Server != server:
		v.State, v.Detail = verifyMismatch, fmt.Sprintf("服务器上的清单记录的服务器是 %s，不是 %s", m.Server, server)
	case m.Bundle != bundle:
		v.State, v.Detail = verifyMismatch, "服务器上的清单记录的内容摘要与面板装上去的不一致"
	default:
		v.State = verifyOK
	}
	if m != nil {
		v.HostBundle = m.Bundle
	}
	if v.State == verifyOK && run != "" && st.Journal != nil && (st.Journal.Run != run || st.Journal.State != "done") {
		v.State, v.Detail = verifyMismatch, fmt.Sprintf("服务器上的 journal 记录的是运行 %s（状态 %s），不是这次的 %s", orDashS(st.Journal.Run), st.Journal.State, run)
	}
	return v
}

func orDashS(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// hostEvidence is what the host's journal says about run, when the
// script's own markers did not reach the panel.
type hostEvidence struct {
	Outcome   string // compensated | left_behind | installed | ""
	Leftovers []string
}

func evidenceOf(st *preflight.NodeState, node, deployment, bundle, run string) hostEvidence {
	if st == nil || !st.Complete || st.Journal == nil {
		return hostEvidence{}
	}
	j := st.Journal
	if j.Run != run || (j.Node != "" && j.Node != node) || (j.Deployment != "" && j.Deployment != deployment) {
		return hostEvidence{}
	}
	switch j.State {
	case "compensated":
		return hostEvidence{Outcome: "compensated", Leftovers: j.Leftovers}
	case "incomplete":
		return hostEvidence{Outcome: "left_behind", Leftovers: j.Leftovers}
	case "done":
		// Committed: the manifest was written by this run. Only when it
		// names this node, deployment and bundle is it taken as installed.
		if m := st.Manifest; m != nil && m.Node == node && m.Deployment == deployment && m.Bundle == bundle {
			return hostEvidence{Outcome: "installed"}
		}
	}
	return hostEvidence{}
}

// recordHostManifest updates a remote node's verify record from the host
// manifest a preflight read, and fills the installed bundle of a record
// migrated from before per-node state (the host's manifest says what was
// installed). Only for a node installed on this very server.
func (s *Server) recordHostManifest(node string, ident targetIdentity, deployment string, m *preflight.NodeManifest, at time.Time) {
	s.provMu.Lock()
	defer s.provMu.Unlock()
	all := s.loadOutcomes()
	o, ok := all[node]
	if !ok || !o.Installed || o.ServerID != ident.ServerID || o.Address != ident.Address || o.Fingerprint != ident.Fingerprint {
		return
	}
	st := &preflight.NodeState{Complete: true, Manifest: m}
	if o.InstalledBundle == "" && m != nil && m.Node == node && m.Deployment == deployment && m.Bundle != "" {
		// Migration: what the host says this panel installed there.
		o.InstalledBundle = m.Bundle
		if m.Installed > 0 {
			t := time.Unix(m.Installed, 0).UTC()
			o.InstalledAt = &t
		}
		if o.InstalledTarget == nil {
			o.InstalledTarget = &targetIdentity{ServerID: o.ServerID, Address: o.Address, Port: o.Port, User: o.User, Fingerprint: o.Fingerprint, CredentialID: o.CredentialID}
		}
	}
	if o.InstalledBundle == "" {
		return
	}
	o.Verify = verifyAgainst(st, node, deployment, ident.ServerID, o.InstalledBundle, "", "preflight", at)
	all[node] = o
	s.putOutcomes(all)
}

// putOutcomes writes the records (caller holds provMu).
func (s *Server) putOutcomes(all map[string]provisionOutcome) {
	if b, err := json.Marshal(all); err == nil {
		_ = s.Store.Put(provisionStateKey, string(b))
	}
}

// Node install states.
const (
	nodeInSync        = "in_sync"
	nodeChanged       = "changed"
	nodeNotInstalled  = "not_installed"
	nodeUnknown       = "unknown"
	nodeTargetChanged = "target_changed"
)

// nodeInstallState is one node's row of GET /api/status nodes and GET
// /api/provision/state states.
type nodeInstallState struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Role     string `json:"role"`
	// State: in_sync | changed | not_installed | unknown | target_changed
	// (remote) or the gateway's install.state (gateway).
	State string `json:"state"`
	// Pending: the node needs a preflight and an install (or the operator
	// must look: unknown, target_changed).
	Pending bool   `json:"pending"`
	Reason  string `json:"reason,omitempty"`
	// CurrentBundle is the digest of the node's files as the stored
	// topology compiles now; InstalledBundle what was installed.
	CurrentBundle   string          `json:"current_bundle,omitempty"`
	InstalledBundle string          `json:"installed_bundle,omitempty"`
	InstalledAt     *time.Time      `json:"installed_at,omitempty"`
	InstalledTarget *targetIdentity `json:"installed_target,omitempty"`
	Verify          *nodeVerify     `json:"verify,omitempty"`
	LastOutcome     string          `json:"last_outcome,omitempty"`
	Evidence        string          `json:"evidence,omitempty"`
}

// nodeStates computes every managed node's state against b (nil when the
// topology does not compile: every remote node is then "unknown").
func (s *Server) nodeStates(t model.Topology, b *compile.Bundle, gw statusInstall) []nodeInstallState {
	outs := s.loadOutcomes()
	var idents map[string]targetIdentity
	if cs, err := s.credStore(); err == nil {
		idents = map[string]targetIdentity{}
		for _, n := range t.Nodes {
			if n.ServerID != "" {
				if id, err := identityOf(cs, n); err == nil {
					idents[n.ID] = id
				}
			}
		}
	}
	var out []nodeInstallState
	for _, n := range t.Nodes {
		if !n.Managed {
			continue
		}
		row := nodeInstallState{NodeID: n.ID, NodeName: n.Name, Role: string(n.Role)}
		if n.Role == model.RoleGateway {
			row.State = gw.State
			row.Pending = gw.State != "in_sync"
			if gw.InstalledAt != "" {
				if at, err := time.Parse(time.RFC3339, gw.InstalledAt); err == nil {
					row.InstalledAt = &at
				}
			}
			out = append(out, row)
			continue
		}
		if b != nil {
			row.CurrentBundle = preflight.BundleDigest(provision.FilesFor(b.Files, n.ID))
		}
		o, ok := outs[n.ID]
		if ok {
			row.LastOutcome, row.Evidence, row.Verify = o.Outcome, o.Evidence, o.Verify
		}
		switch {
		case !ok || !o.Installed:
			row.State, row.Reason = nodeNotInstalled, "这个节点还没有经面板成功装过（或已撤回）"
		case o.Outcome == "unknown" || o.Outcome == "left_behind":
			row.State, row.Reason = nodeUnknown, "最近一次装机结果不明或有残留：先预检查看服务器上的 journal"
		case o.InstalledBundle == "":
			row.State, row.Reason = nodeUnknown, "这个节点在升级前装过，面板没有记录装上去的内容摘要：对它做一次预检（只读）即可补上"
		default:
			row.InstalledBundle, row.InstalledAt, row.InstalledTarget = o.InstalledBundle, o.InstalledAt, o.InstalledTarget
			cur, hasIdent := idents[n.ID]
			it := o.InstalledTarget
			switch {
			case n.ServerID == "" || !hasIdent:
				row.State, row.Reason = nodeTargetChanged, "节点现在没有可用的服务器"
			case it != nil && (it.ServerID != cur.ServerID || it.Address != cur.Address || it.Port != cur.Port || it.Fingerprint != cur.Fingerprint):
				row.State, row.Reason = nodeTargetChanged, "节点装在之前的服务器或身份上，现在指向另一台：先撤回旧的安装，再在新服务器上安装"
			case b == nil:
				row.State, row.Reason = nodeUnknown, "拓扑现在不能编译，无法比较"
			case row.CurrentBundle == o.InstalledBundle:
				row.State = nodeInSync
			default:
				row.State, row.Reason = nodeChanged, "这个节点要下发的文件与它上一次成功安装的不同"
			}
		}
		if row.State == nodeInSync && row.Verify != nil && row.Verify.State == verifyMismatch {
			row.Reason = "内容与上一次安装一致，但最近一次核对服务器上的记录不一致：" + row.Verify.Detail
		}
		row.Pending = row.State != nodeInSync
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Role == string(model.RoleGateway)) != (out[j].Role == string(model.RoleGateway)) {
			return out[i].Role == string(model.RoleGateway)
		}
		return false
	})
	return out
}
