package hostexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Doer sends one request to the agent. *Client implements it.
type Doer interface {
	Do(ctx context.Context, req Request) (Result, error)
}

// GatewayDataPlane is what the upgrade check names: meridian.service (always
// checked by health and activate) plus both gateway nft tables. Units and
// interfaces of the installed manifest are started by meridian-up.sh itself.
var GatewayDataPlane = Resources{NFTTables: []string{"inet meridian", GuardTable}}

// GuardTable is the gateway's fail-closed LAN guard. A gateway withdraw
// (ActionWithdraw) keeps it loaded, with its boot file and
// meridian-guard.service, so LAN traffic is dropped rather than forwarded
// unguarded via ROS once the Meridian data plane is gone. Only an explicit,
// separate removal (rollback of this table, forwarding off first) drops it.
const GuardTable = "inet meridian_guard"

// GuardBootFile is the gateway file meridian-guard.service loads at boot
// (relative to the host root, as in the install manifest).
const GuardBootFile = "etc/nftables.d/meridian-guard.nft"

// RestoreReport is the outcome of RestoreDataPlane.
type RestoreReport struct {
	Healthy   bool   `json:"healthy"`
	Activated bool   `json:"activated"`
	Steps     []Step `json:"steps"`
	Error     string `json:"error,omitempty"`
}

// RestoreDataPlane is the upgrade path of deploy/debian/install.sh on a host
// whose data plane was running before the upgrade. It goes through the agent
// like the panel does:
//
//  1. health: meridian.service active and both gateway tables loaded (two
//     samples), and forwarding (when forwarding is non-nil) still on;
//  2. only if that fails and mayActivate is set: activate, i.e. restart
//     meridian.service (meridian-up.sh, the same path as at boot) and check
//     again, forwarding included.
//
// It never turns forwarding on by itself; only meridian-up.sh does, after the
// firewall and the guard are loaded. idPrefix makes the request ids unique.
func RestoreDataPlane(ctx context.Context, d Doer, forwarding func() (bool, error), mayActivate bool, idPrefix string) (RestoreReport, error) {
	var rep RestoreReport
	fwdOK := func() error {
		if forwarding == nil {
			return nil
		}
		on, err := forwarding()
		if err != nil {
			return fmt.Errorf("读取转发状态失败：%w", err)
		}
		if !on {
			return errors.New("转发未打开（升级前是打开的）")
		}
		return nil
	}
	res, err := d.Do(ctx, Request{Action: ActionHealth, RequestID: idPrefix + "/health", Resources: GatewayDataPlane})
	rep.Steps = append(rep.Steps, res.Steps...)
	if err == nil && res.OK {
		err = fwdOK()
	} else if err == nil {
		err = errors.New(res.Error)
	}
	if err == nil {
		rep.Healthy = true
		return rep, nil
	}
	if !mayActivate {
		rep.Error = "数据面健康检查失败：" + err.Error()
		return rep, errors.New(rep.Error)
	}
	rep.Steps = append(rep.Steps, Step{Name: "health before activate", OK: false, Detail: clip(err.Error())})
	res, err = d.Do(ctx, Request{Action: ActionActivate, RequestID: idPrefix + "/activate", Resources: GatewayDataPlane})
	rep.Steps = append(rep.Steps, res.Steps...)
	rep.Activated = true
	if err == nil && !res.OK {
		err = errors.New(res.Error)
	}
	if err == nil {
		err = fwdOK()
	}
	if err != nil {
		rep.Error = "重新激活数据面失败：" + err.Error()
		return rep, errors.New(rep.Error)
	}
	rep.Healthy = true
	return rep, nil
}

// TopologyRestoreOptions bound RestoreTopology.
type TopologyRestoreOptions struct {
	// IDPrefix makes the request ids unique.
	IDPrefix string
	// Wait is how long the host may take to equal the snapshot by itself
	// (the gateway's failover loop returns to its main path on its own
	// clock); FallbackWait the same after a re-activation; Poll the pause
	// between two comparisons (default 5s).
	Wait, FallbackWait, Poll time.Duration
	// MayActivate allows the re-activation of the data plane when the wait
	// ends with differences.
	MayActivate bool
}

// TopologyRestoreReport is the outcome of RestoreTopology.
type TopologyRestoreReport struct {
	// Restored: the host equals the snapshot and the data plane is healthy.
	Restored bool `json:"restored"`
	// Activated: the data plane was re-activated on the way.
	Activated bool   `json:"activated"`
	Steps     []Step `json:"steps"`
	// Residual lists what still differs. Empty exactly when Restored.
	Residual []string `json:"residual,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// RestoreTopology brings a host back to a recorded state after an
// acceptance drill and says so only when that state is verified. verify
// compares the host with the snapshot the drill took before it changed
// anything and returns the differences (links, interfaces, rules, the
// upstream record); it is the only thing that can make this report
// "restored". The steps:
//
//  1. compare, waiting up to Wait for the host to converge by itself;
//  2. if it still differs and MayActivate is set: RestoreDataPlane (health,
//     and activate when unhealthy); when the data plane is healthy and the
//     host still differs, one explicit activate (meridian.service, i.e.
//     meridian-up.sh re-installs the configured paths);
//  3. compare again, waiting up to FallbackWait;
//  4. with nothing left to differ, a final health check (forwarding
//     included). A healthy data plane that differs from the snapshot is not
//     restored, and a host that equals the snapshot but is unhealthy is not
//     either.
//
// An error is returned whenever Residual is not empty.
func RestoreTopology(ctx context.Context, d Doer, forwarding func() (bool, error), verify func(context.Context) ([]string, error), o TopologyRestoreOptions) (TopologyRestoreReport, error) {
	var rep TopologyRestoreReport
	poll := o.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	compare := func(wait time.Duration, name string) []string {
		deadline := time.Now().Add(wait)
		var residual []string
		for {
			diffs, err := verify(ctx)
			switch {
			case err != nil:
				residual = []string{"读不到当前状态，无法与演练前的快照核对：" + clip(firstLine(err.Error()))}
			default:
				residual = diffs
			}
			if len(residual) == 0 || !time.Now().Add(poll).Before(deadline) || ctx.Err() != nil {
				break
			}
			select {
			case <-time.After(poll):
			case <-ctx.Done():
			}
		}
		rep.Steps = append(rep.Steps, Step{Name: name, OK: len(residual) == 0, Detail: clip(strings.Join(residual, "\n"))})
		return residual
	}
	residual := compare(o.Wait, "compare with snapshot")
	if len(residual) > 0 && o.MayActivate && ctx.Err() == nil {
		dp, err := RestoreDataPlane(ctx, d, forwarding, true, o.IDPrefix+"/dataplane")
		rep.Steps = append(rep.Steps, dp.Steps...)
		rep.Activated = dp.Activated
		if err == nil && !dp.Activated {
			// Healthy, yet not the recorded topology: health is not the
			// criterion. Re-install the configured paths once.
			res, aerr := d.Do(ctx, Request{Action: ActionActivate, RequestID: o.IDPrefix + "/reactivate", Resources: GatewayDataPlane})
			rep.Steps = append(rep.Steps, res.Steps...)
			rep.Activated = true
			if aerr != nil {
				rep.Steps = append(rep.Steps, Step{Name: "re-activate data plane", OK: false, Detail: clip(aerr.Error())})
			}
		}
		residual = compare(o.FallbackWait, "compare with snapshot after re-activation")
	}
	if len(residual) == 0 {
		dp, err := RestoreDataPlane(ctx, d, forwarding, false, o.IDPrefix+"/final")
		rep.Steps = append(rep.Steps, dp.Steps...)
		if err != nil {
			residual = []string{"与快照一致，但" + err.Error()}
		}
	}
	rep.Residual = residual
	if len(residual) > 0 {
		rep.Error = "没有恢复到演练前的状态：" + strings.Join(residual, "；")
		return rep, errors.New(rep.Error)
	}
	rep.Restored = true
	return rep, nil
}

// ProcForwarding reads IPv4 and IPv6 (all) forwarding from /proc: true only
// when both are 1.
func ProcForwarding() (bool, error) {
	for _, p := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		b, err := os.ReadFile(p)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(string(b)) != "1" {
			return false, nil
		}
	}
	return true, nil
}
