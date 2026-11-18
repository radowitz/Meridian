package mesh

import (
	"errors"
	"fmt"
)

// DeploymentPreflight is the deploy-time check of one plan node. A host
// that gets the connector runs the read-only install preflight on itself
// (ConnectorPreflightScript: system, architecture, memory estimate, source
// reachability, no WARP already there); the run's own coexistence inputs
// are checked here first. A host that already is a host-level node runs
// HostPreflightScript. No sidecar is ever planned: any other target is
// refused.
func DeploymentPreflight(j *Journal, p Plan, n NodeTarget) (string, error) {
	switch {
	case n.Install:
		if intIn(n.Reserved.Tables, warpTable) {
			return "", fmt.Errorf("%s：Meridian 用了 WARP 客户端固定的路由表 %d", n.ID, warpTable)
		}
		for _, m := range n.Reserved.Marks {
			if normMark(m) == warpMark {
				return "", fmt.Errorf("%s：Meridian 的标记与 WARP 客户端的 %s 相同", n.ID, warpMark)
			}
		}
		return ConnectorPreflightScript(j.RunID, n.Role, n.Codename)
	case n.HostNode():
		return HostPreflightScript(j.RunID, p, n)
	}
	return "", errors.New("Mesh 节点既不是主机级节点也不在本次安装：不再部署 sidecar")
}

// hostIface: a host WARP interface name (e.g. CloudflareWARP).
func hostIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
