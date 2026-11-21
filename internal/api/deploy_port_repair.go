package api

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/validate"
)

var errWGPortRepairUnavailable = errors.New("当前部署没有可自动更换的 WireGuard 端口")

func (s *Server) postDeployRepairWGPort(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PreflightID string `json:"preflight_id"`
	}
	if err := decodeStrict(w, r, &body, []string{"preflight_id"}, nil, false); err != nil {
		writeResErr(w, err)
		return
	}
	refuse := func() {
		writeCoded(w, http.StatusConflict, "deploy_port_repair_unavailable", errWGPortRepairUnavailable.Error(), nil)
	}
	s.deployMu.Lock()
	defer s.deployMu.Unlock()

	run := s.loadRunLocked()
	if !run.open() || run.ID != r.PathValue("id") {
		refuse()
		return
	}
	for _, step := range run.Steps {
		if inFlight(step.Phase) {
			refuse()
			return
		}
	}
	idx := run.current()
	if idx < 0 {
		refuse()
		return
	}
	step := run.Steps[idx]
	pid := step.NodeID
	if step.Kind == "gateway" {
		pid = localNodeID
	}
	rec := s.loadPreflight(pid)
	if step.Phase != phaseBlocked || rec == nil || rec.ID != body.PreflightID ||
		step.PreflightID != rec.ID || !s.now().Before(rec.ExpiresAt) {
		refuse()
		return
	}
	live, err := s.liveDeploy()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if live.version != run.TopologyVersion || s.confirmationProblem(step, live, s.now()) != "" {
		refuse()
		return
	}
	linkID := ""
	for _, finding := range rec.Findings {
		if finding.Severity != preflight.Blocking {
			continue
		}
		fix := finding.Fix
		if finding.Code != preflight.CodePortInUse || fix == nil || fix.Kind != "link" || fix.Field != "wg_port" ||
			(linkID != "" && linkID != fix.ID) {
			refuse()
			return
		}
		linkID = fix.ID
	}
	isListener := false
	for _, ports := range validate.TunnelPorts(live.t) {
		if ports.LinkID == linkID && ports.Listener == step.NodeID {
			isListener = true
			break
		}
	}
	if !isListener {
		refuse()
		return
	}
	var change mtuChange
	found, err := s.Store.Update(func(t *model.Topology) (bool, error) {
		if topologyVersion(*t) != topologyVersion(live.t) {
			return false, errWGPortRepairUnavailable
		}
		for i := range t.Links {
			link := &t.Links[i]
			if link.ID != linkID {
				continue
			}
			from, fromOK := t.NodeByID(link.From)
			to, toOK := t.NodeByID(link.To)
			if !link.AutoWGPort || !link.Enabled || !fromOK || !toOK ||
				!from.Managed || !to.Managed || from.NatDialOut || to.NatDialOut ||
				from.ListenPort != 0 || to.ListenPort != 0 || link.Transport == model.TransportCFMesh {
				return false, errWGPortRepairUnavailable
			}
			port, err := otherWireGuardPort(*t, link.WGPort)
			if err != nil {
				return false, err
			}
			change = mtuChange{LinkID: linkID, Field: "wg_port", From: link.WGPort, To: port}
			link.WGPort = port
			if validate.Run(*t).HasErrors() {
				return false, errWGPortRepairUnavailable
			}
			return true, nil
		}
		return false, errWGPortRepairUnavailable
	})
	if errors.Is(err, errWGPortRepairUnavailable) || (err == nil && !found) {
		refuse()
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	run.event(s.now(), step.NodeID, fmt.Sprintf("自动修复：链路 %s UDP 端口 %d → %d（原端口被占用）", change.LinkID, change.From, change.To))
	s.saveRunLocked(run)
	writeJSON(w, http.StatusOK, map[string]any{"change": change})
}

func otherWireGuardPort(t model.Topology, old int) (int, error) {
	used := map[int]bool{old: true}
	for _, n := range t.Nodes {
		used[n.ListenPort] = true
		used[n.WSSListenPort] = true
	}
	for _, p := range validate.TunnelPorts(t) {
		used[p.WG], used[p.WSSLeg], used[p.Local] = true, true, true
	}
	const count = 9999
	start, err := rand.Int(rand.Reader, big.NewInt(count))
	if err != nil {
		return 0, err
	}
	for offset := 0; offset < count; offset++ {
		port := 20000 + (int(start.Int64())+offset)%count
		if !used[port] && !used[port+1] {
			return port, nil
		}
	}
	return 0, errWGPortRepairUnavailable
}
