package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
)

// Detection of host-level Cloudflare Mesh nodes (N1). It runs the fixed,
// read-only mesh.DetectScript through each node's managed server, only to a
// server whose host key the operator confirmed (the pinned fingerprint), and
// stores the evaluated result. It never writes on the host.

type meshDetectBody struct {
	// NodeID limits the detection to one topology node; empty: every node
	// of the Mesh plan.
	NodeID string `json:"node_id"`
}

// meshHostDetections is the stored detections with ownership refreshed
// from the journal.
func (s *Server) meshHostDetections() (map[string]model.HostMeshDetection, error) {
	m, err := mesh.LoadHostMesh(s.meshDir())
	j, _ := s.deployer(nil, nil).Load()
	for k, d := range m {
		mesh.ApplyOwnership(&d, j)
		m[k] = d
	}
	return m, err
}

func (s *Server) postMeshDetect(w http.ResponseWriter, r *http.Request) {
	var body meshDetectBody
	if err := decodeStrict(w, r, &body, []string{"node_id"}, meshRemoved, true); err != nil {
		writeResErr(w, err)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	b, err := s.compileTopo(t)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var ids []string
	if body.NodeID != "" {
		if _, ok := t.NodeByID(body.NodeID); !ok {
			writeErr(w, http.StatusNotFound, errors.New("没有这个节点"))
			return
		}
		ids = []string{body.NodeID}
	} else {
		p := mesh.BuildPlan(t, b.Files)
		for _, n := range p.Nodes {
			ids = append(ids, n.ID)
		}
	}
	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("拓扑里没有 Mesh 节点；指定 node_id 检测单个节点"))
		return
	}
	account := ""
	cs, csErr := s.credStore()
	if csErr == nil {
		if id := cs.MeshAccount(); id != "" {
			if a, err := cs.Account(id); err == nil {
				account = a.AccountID
			}
		}
	}
	rem, err := s.meshRemote()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.meshHostMu.Lock()
	defer s.meshHostMu.Unlock()
	all, _ := mesh.LoadHostMesh(s.meshDir())
	j, _ := s.deployer(nil, nil).Load()
	now := time.Now().UTC().Format(time.RFC3339)
	results := []model.HostMeshDetection{}
	for _, id := range ids {
		n, _ := t.NodeByID(id)
		d := s.detectNode(r.Context(), rem, n, account, provision.FilesFor(b.Files, id))
		d.NodeID, d.CheckedAt = id, now
		mesh.ApplyOwnership(&d, j)
		all[id] = d
		results = append(results, d)
	}
	sort.Slice(results, func(i, k int) bool { return results[i].NodeID < results[k].NodeID })
	if err := mesh.SaveHostMesh(s.meshDir(), all); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"detections": results})
}

// detectNode runs the detection on one node's server.
func (s *Server) detectNode(ctx context.Context, rem mesh.Remote, n model.Node, account string, files map[string]string) model.HostMeshDetection {
	cs, err := s.credStore()
	if err != nil || n.ServerID == "" {
		return mesh.DetectFailed(n.ID, "节点没有关联的服务器，未检测")
	}
	sv, err := cs.Server(n.ServerID)
	if err != nil {
		return mesh.DetectFailed(n.ID, "关联的服务器不存在，未检测")
	}
	if sv.HostKey.State != model.HostKeyTrusted || sv.HostKey.Fingerprint == "" {
		return mesh.DetectFailed(n.ID, "服务器的主机指纹还没确认，未连接")
	}
	if sv.CredentialID == "" {
		return mesh.DetectFailed(n.ID, "服务器没有 SSH 凭据，未连接")
	}
	nt := mesh.NodeTarget{ID: n.ID, Name: n.Name, Role: n.Role, ServerID: sv.ID, CredentialID: sv.CredentialID,
		SSHHost: sv.Address, SSHPort: sv.Port, SSHUser: sv.User, HostKey: sv.HostKey.Fingerprint}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, key, err := rem.Exec(cctx, nt, mesh.ActDetect, mesh.DetectScript())
	if err != nil {
		d := mesh.DetectFailed(n.ID, "SSH 检测失败："+err.Error())
		d.ServerID = sv.ID
		return d
	}
	if key != sv.HostKey.Fingerprint {
		d := mesh.DetectFailed(n.ID, "主机出示的指纹与已确认的不一致，结果作废")
		d.ServerID = sv.ID
		return d
	}
	fp := preflight.FootprintOf(files)
	res := mesh.Reserved{Tables: fp.Tables, Marks: fp.Marks}
	for _, ru := range fp.Rules {
		res.Priorities = append(res.Priorities, ru.Priority)
	}
	d := mesh.ParseHostMesh(out, account, res)
	d.ServerID, d.HostKey = sv.ID, key
	return d
}
