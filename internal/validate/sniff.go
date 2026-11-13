package validate

import (
	"fmt"
	"sort"

	"github.com/radowitz/meridian/internal/model"
	rulesorder "github.com/radowitz/meridian/internal/ordered"
)

// SniffListenPort is the gateway TCP port the name-sniffing forwarder
// listens on (all addresses; the gateway's input chain refuses every
// connection to it that the forwarder's redirect did not deliver).
const SniffListenPort = 5358

// sniffRefused are destination ports that can never be intercepted: DNS
// and DoT are answered by the gateway's resolver (dns_hijack), SSH stays a
// plain forwarded connection, and the forwarder's own port would loop.
var sniffRefused = map[int]string{22: "SSH", 53: "DNS（网关的解析器接管）", 853: "DoT（网关的解析器接管）", SniffListenPort: "嗅探转发服务自己的端口"}

// checkSniff validates settings.sniff (model.SniffSettings). Off: nothing.
func checkSniff(t model.Topology) []Issue {
	s := t.Settings.Sniff
	if s == nil || !s.Enabled {
		return nil
	}
	var out []Issue
	bad := func(field, msg string) {
		out = append(out, Issue{Code: "sniff_invalid", Severity: SeverityError, Field: field, Message: "按域名嗅探：" + msg})
	}
	gw := firstRole(t, model.RoleGateway)
	if gw.ID == "" {
		bad("enabled", "拓扑里没有网关节点，嗅探转发服务只在网关上运行。")
	} else if !gw.Managed {
		bad("enabled", "网关节点不是受管节点：嗅探转发服务要随网关安装事务一起安装。")
	}
	if len(s.Ports) > model.MaxSniffPorts {
		bad("ports", fmt.Sprintf("最多 %d 个端口，现在 %d 个。", model.MaxSniffPorts, len(s.Ports)))
	}
	seen := map[int]bool{}
	for _, p := range s.Ports {
		switch {
		case p <= 0 || p > 65535:
			bad("ports", fmt.Sprintf("端口 %d 不在 1–65535 之间。", p))
		case sniffRefused[p] != "":
			bad("ports", fmt.Sprintf("端口 %d 不能接管：留给 %s。", p, sniffRefused[p]))
		case seen[p]:
			bad("ports", fmt.Sprintf("端口 %d 重复。", p))
		}
		seen[p] = true
	}
	for _, n := range s.ECHPublicNames {
		if _, ok := rulesorder.NormDomain(n); !ok {
			bad("ech_public_names", fmt.Sprintf("「%s」不是域名。", n))
		}
	}
	if gw.ID != "" {
		uses := NodePorts(t, gw.ID)
		sort.SliceStable(uses, func(i, j int) bool { return uses[i].Port < uses[j].Port })
		for _, u := range uses {
			if u.Proto == "tcp" && u.Port == SniffListenPort {
				out = append(out, portIssue("port_conflict", u, fmt.Sprintf("%s 设为 tcp %d：网关上的嗅探转发服务用这个端口。", u.What, u.Port)))
			}
		}
		if PanelPort(t) == SniffListenPort {
			bad("enabled", fmt.Sprintf("面板端口 %d 与嗅探转发服务的端口相同。", SniffListenPort))
		}
	}
	return out
}
