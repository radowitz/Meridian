package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/validate"
)

func alpineExit(t *testing.T, id string) model.Topology {
	t.Helper()
	topo := defaults.Example()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == id {
			topo.Nodes[i].OS = model.OSAlpine
		}
	}
	return topo
}

// An Alpine exit gets OpenRC services under the systemd unit names'
// counterparts, no systemd unit, no Docker unlock probe and no FORWARD DROP
// coexistence; a Debian exit's files are unchanged.
func TestAlpineExitFiles(t *testing.T) {
	plain := mustCompile(t, defaults.Example())
	topo := alpineExit(t, "jp")
	if issues := validate.Run(topo).Issues; hasCode(issues, "node_os_") {
		t.Fatalf("a plain Alpine exit refused: %+v", issues)
	}
	b := mustCompile(t, topo)
	files := map[string]string{}
	for p, body := range b.Files {
		if strings.HasPrefix(p, "nodes/jp/") {
			files["/"+strings.TrimPrefix(p, "nodes/jp/")] = body
		}
	}
	for _, need := range []string{"/etc/init.d/meridian-node", "/etc/init.d/meridian-smartdns", "/usr/local/sbin/meridian-up.sh", "/etc/smartdns/smartdns.conf"} {
		if files[need] == "" {
			t.Errorf("missing %s", need)
		}
	}
	for p := range files {
		if strings.HasPrefix(p, "/etc/systemd/") || strings.Contains(p, "unlock") || strings.Contains(p, "fwcompat") {
			t.Errorf("an Alpine exit must not get %s", p)
		}
	}
	if !strings.HasPrefix(files["/etc/init.d/meridian-smartdns"], "#!/sbin/openrc-run\n") || !strings.Contains(files["/etc/init.d/meridian-smartdns"], "\ncommand=/usr/local/sbin/meridian-smartdns\n") {
		t.Fatalf("smartdns service:\n%s", files["/etc/init.d/meridian-smartdns"])
	}
	up := files["/usr/local/sbin/meridian-up.sh"]
	if !strings.Contains(up, "rc-service meridian-smartdns restart") || strings.Contains(up, "systemctl") ||
		!strings.Contains(up, "[ -n \"$m_l\" ] || rc-update add meridian-smartdns default") {
		t.Fatalf("meridian-up.sh of an Alpine exit:\n%s", up)
	}
	fp := preflight.FootprintOf(files)
	if strings.Join(fp.Units, " ") != "meridian-node.service meridian-smartdns.service" || strings.Join(fp.Binaries, " ") != "smartdns" {
		t.Fatalf("footprint units %v binaries %v", fp.Units, fp.Binaries)
	}
	// Only this exit changed.
	for p, body := range plain.Files {
		if strings.HasPrefix(p, "nodes/jp/") {
			continue
		}
		if b.Files[p] != body {
			t.Errorf("%s changed for an Alpine exit elsewhere", p)
		}
	}
}

func TestAlpineNodeRefused(t *testing.T) {
	for _, c := range []struct {
		id, code string
	}{
		{"hk-hub", "node_os_alpine_role"},
		{"hk-2", "node_os_alpine_transport"}, // has a Cloudflare Mesh leg
	} {
		issues := validate.Run(alpineExit(t, c.id)).Issues
		if !hasCode(issues, c.code) {
			t.Errorf("%s on Alpine: want %s, got %+v", c.id, c.code, issues)
		}
	}
	topo := defaults.Example()
	topo.Nodes[len(topo.Nodes)-1].OS = "gentoo"
	if !hasCode(validate.Run(topo).Issues, "node_os_unknown") {
		t.Error("an unknown OS is accepted")
	}
}

func hasCode(issues []validate.Issue, prefix string) bool {
	for _, i := range issues {
		if strings.HasPrefix(i.Code, prefix) {
			return true
		}
	}
	return false
}
