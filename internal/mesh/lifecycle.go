package mesh

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// LegPlan describes the fixed WireGuard resources checked before publishing.
// No caller can supply shell fragments or substitute an endpoint.
type LegPlan struct {
	LinkID     string `json:"link_id"`
	HubID      string `json:"hub_id"`
	ExitID     string `json:"exit_id"`
	Network    string `json:"network"`
	Interface  string `json:"interface"`
	Port       int    `json:"port"`
	PathMTU    int    `json:"path_mtu"`
	DeviceMTU  int    `json:"device_mtu"`
	PayloadMTU int    `json:"payload_mtu"`
	// Reuse: which ends reuse a host-level Mesh node (ReuseBoth / ReuseHub
	// / ReuseExit), "" for the plain sidecar leg.
	Reuse string `json:"reuse,omitempty"`
}
type LegRecord struct {
	LegPlan
	State string `json:"state"`
}

func remoteRun(j *Journal, rm *OwnedRemote) string {
	if rm.RunID != "" {
		return rm.RunID
	}
	return j.RunID
}
func (j *Journal) hasRoute(id string) bool {
	for _, r := range j.Routes {
		if r.LinkID == id && r.State != ResRemoved {
			return true
		}
	}
	return false
}

// legPublished: the leg is published in this journal (a recorded leg in
// state published, or a legacy published route).
func (j *Journal) legPublished(id string) bool {
	for _, l := range j.Legs {
		if l.LinkID == id && l.State == StatePublished {
			return true
		}
	}
	return j.hasRoute(id)
}

func (j *Journal) sharedHost(id string) bool {
	if j.Baseline == nil {
		return false
	}
	for _, r := range j.Baseline.Remotes {
		if r.NodeID == id && r.State == ResCreated {
			return true
		}
	}
	return false
}
func (j *Journal) keepRoute(r OwnedRoute) bool {
	if j.Baseline != nil {
		for _, old := range j.Baseline.Routes {
			if old.LinkID == r.LinkID && old.State != ResRemoved {
				return true
			}
		}
	}
	if len(j.WithdrawLinks) > 0 {
		for _, id := range j.WithdrawLinks {
			if r.LinkID == id {
				return false
			}
		}
		return true
	}
	return false
}
func (j *Journal) keepHost(id string) bool {
	if j.sharedHost(id) {
		return true
	}
	if len(j.WithdrawLinks) == 0 {
		return false
	}
	for _, l := range j.Legs {
		if l.State == StateWithdrawn {
			continue
		}
		selected := false
		for _, target := range j.WithdrawLinks {
			selected = selected || target == l.LinkID
		}
		if !selected && (l.HubID == id || l.ExitID == id) {
			return true
		}
	}
	// A failed route deletion must not strand an active route without its node.
	for _, r := range j.Routes {
		if r.State != ResRemoved && !j.keepRoute(r) && r.ExitID == id {
			return true
		}
	}
	return false
}
func (j *Journal) hostPending(id string) bool {
	for _, r := range j.Remotes {
		if r.NodeID == id && r.State != ResRemoved {
			return true
		}
	}
	return false
}

// checkIncrement refuses silent migration, changed resources and host repointing.
// An operator first withdraws the affected leg, provisions the new compiled
// configuration, then deploys again. Unchanged published legs are retained.
func checkIncrement(prev *Journal, p Plan) error {
	if !prev.Underlay || len(prev.Legs) == 0 || len(prev.WithdrawLinks) != 0 || prev.Baseline != nil {
		return ErrBusy
	}
	added := false
	for _, old := range prev.Legs {
		if old.State == StateWithdrawn || old.State == StatePendingProvision {
			continue
		}
		found := false
		for _, leg := range p.Legs {
			if leg.LinkID == old.LinkID {
				found = reflect.DeepEqual(leg, old.LegPlan)
			}
		}
		if !found {
			return fmt.Errorf("%w：Mesh 腿 %s 已改变或移除；先单独撤回该腿，重新下发后再部署", ErrBusy, old.LinkID)
		}
	}
	for _, leg := range p.Legs {
		if !prev.legPublished(leg.LinkID) {
			added = true
		}
	}
	if !added {
		return ErrBusy
	}
	for _, n := range p.Nodes {
		if n.Existing() && prev.hostPending(n.ID) {
			return fmt.Errorf("%w：%s 现在沿用主机上已有的 Mesh 节点，但部署记录里还有面板在这台主机创建的资源；先撤回", ErrBusy, n.ID)
		}
		if n.Install && prev.hostPending(n.ID) {
			return fmt.Errorf("%w：%s 还有面板之前创建的资源（旧版 sidecar 或未完成的安装）；先撤回再安装主机级节点", ErrBusy, n.ID)
		}
		if old := prev.pin(n.ID); old != nil && prev.hostPending(n.ID) && !sameHost(*old, pinFor(n)) {
			return fmt.Errorf("%w：共享 sidecar %s 的主机身份变化；先撤回原主机资源", ErrBusy, n.ID)
		}
	}
	return nil
}

// WithdrawLeg withdraws just one leg, retaining every sidecar still referenced
// by another published leg. The selected link is persisted before changes, so
// the ordinary Withdraw retry resumes the same selection after a restart.
func (d *Deployer) WithdrawLeg(ctx context.Context, link string) (*Journal, error) {
	if link == "" {
		return nil, errors.New("Mesh 腿 ID 不能为空")
	}
	return d.withdraw(ctx, link)
}

func (j *Journal) routePending(id string) bool {
	for _, r := range j.Routes {
		if r.ExitID == id && r.State != ResRemoved && !j.keepRoute(r) {
			return true
		}
	}
	return false
}

func sameHost(a, b HostPin) bool {
	a.Name, b.Name = "", ""
	return a == b
}
