package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// systemd-networkd restarting (an unattended systemd upgrade) deletes
// foreign ip rules: every meridian-up.sh writes the drop-in that stops it,
// without restarting networkd, and every failover loop re-runs the routes
// script when its first policy rule is gone.
func TestNetworkdDropInAndRuleHeal(t *testing.T) {
	topo := defaults.Example()
	model.MigrateRegionGroups(&topo)
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	ups, loops := 0, 0
	for p, body := range b.Files {
		switch {
		case strings.HasSuffix(p, "/usr/local/sbin/meridian-up.sh"):
			ups++
			i, j := strings.Index(body, NetworkdDropIn), strings.Index(body, "/usr/local/sbin/meridian-routes.sh\n")
			if i < 0 || j < i || !strings.Contains(body, "ManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no'") {
				t.Errorf("%s: no networkd drop-in before the routes script", p)
			}
			if strings.Contains(body, "restart systemd-networkd") || strings.Contains(body, "networkctl reload") {
				t.Errorf("%s restarts networkd", p)
			}
		case strings.HasSuffix(p, "/usr/local/sbin/meridian-failover.sh"):
			loops++
			node := strings.TrimSuffix(p, "usr/local/sbin/meridian-failover.sh")
			m := ruleSentinel.FindStringSubmatch(b.Files[node+"usr/local/sbin/meridian-routes.sh"])
			if m == nil || !strings.Contains(body, "RULE_SENTINEL="+m[1]+"\n") || !strings.Contains(body, "while true; do\n  rule_heal\n") {
				t.Errorf("%s: no rule self-heal on the routes script's first rule", p)
			}
		}
	}
	if ups == 0 || loops == 0 {
		t.Fatalf("up scripts %d, failover loops %d", ups, loops)
	}
	if got := withRuleHeal("x\nwhile true; do\n  a\ndone\nwhile true; do\ndone\n", "ip rule add from all lookup 1 priority 5\n"); strings.Contains(got, "rule_heal") {
		t.Error("two loops: must be left unchanged")
	}
}
