package hostexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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
