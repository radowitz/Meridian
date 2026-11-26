package validate

import (
	"fmt"

	"github.com/radowitz/meridian/internal/model"
)

// checkNodeOS: a node on Alpine (OpenRC, apk) can only be a managed exit
// with plain WireGuard links. Everything that needs systemd units, timers
// or Docker on the node itself (relay and hub services, WSS carriers,
// Cloudflare Mesh, external SOCKS carriers, endpoint refresh, the unlock
// probe's container) is only built for Debian / Ubuntu.
func checkNodeOS(t model.Topology) []Issue {
	var out []Issue
	add := func(n model.Node, code, linkID, field, format string, a ...any) {
		out = append(out, Issue{Code: code, Severity: SeverityError, NodeID: n.ID, LinkID: linkID, Field: field, Message: fmt.Sprintf(format, a...)})
	}
	carriers := map[string]bool{}
	for _, n := range t.Nodes {
		if model.IsExternal(n) {
			carriers[n.External.Carrier] = true
		}
	}
	for _, n := range t.Nodes {
		switch n.OS {
		case "":
			continue
		case model.OSAlpine:
		default:
			add(n, "node_os_unknown", "", "os", "%s 的系统类型 %q 不认识：留空（Debian / Ubuntu）或填 alpine。", n.Name, n.OS)
			continue
		}
		if n.Role != model.RoleExit || !n.Managed || model.IsExternal(n) || n.ViaExit != "" {
			add(n, "node_os_alpine_role", "", "os", "%s 标成了 Alpine。Alpine 只能用作直连枢纽的受管出口；网关、中继、枢纽、外部 SOCKS 出口和中继出口都要装在 Debian 或 Ubuntu 上。", n.Name)
			continue
		}
		if n.MeshHost != nil {
			add(n, "node_os_alpine_mesh", "", "mesh_host", "%s 在 Alpine 上，不能做 Cloudflare Mesh 节点（Mesh 需要 Docker 或 WARP 客户端）。", n.Name)
		}
		if carriers[n.ID] {
			add(n, "node_os_alpine_carrier", "", "os", "%s 在 Alpine 上，不能承载外部 SOCKS 出口。", n.Name)
		}
		if n.EndpointHost != "" {
			add(n, "node_os_alpine_endpoint_host", "", "endpoint_host", "%s 在 Alpine 上，不能用动态域名端点；填固定地址。", n.Name)
		}
		for _, l := range t.Links {
			if !l.Enabled || (l.From != n.ID && l.To != n.ID) {
				continue
			}
			if l.Transport != model.TransportDirectWG {
				add(n, "node_os_alpine_transport", l.ID, "transport", "%s 在 Alpine 上，链路 %s 只能用普通 WireGuard 直连（不支持 WSS、Mesh 和专线类型）。", n.Name, l.ID)
			}
		}
	}
	return out
}
