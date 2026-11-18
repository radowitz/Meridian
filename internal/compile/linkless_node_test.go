package compile

import (
	"regexp"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// incompleteIP matches a generated ip command with a missing operand:
// "dev" (or "via", "table", "lookup") followed by nothing, or a doubled
// space where an operand was interpolated empty.
var incompleteIP = regexp.MustCompile(`^\s*(del_rule )?ip (-[46] )?\S.*(\b(dev|via|table|lookup|from|to)\s*$|  )`)

// A managed relay/hub/exit that was added but not yet linked must never
// get an ip command with an empty operand (the install ran
// `ip route replace … dev ` and iproute2 failed with exit 255).
func TestLinklessManagedNodeEmitsNoIncompleteIPCommands(t *testing.T) {
	base := defaults.Example()
	for _, role := range []model.Role{model.RoleRelay, model.RoleHub, model.RoleExit} {
		t.Run(string(role), func(t *testing.T) {
			top := defaults.Example()
			var tmpl model.Node
			for _, n := range base.Nodes {
				if n.Role == role && n.Managed {
					tmpl = n
					break
				}
			}
			tmpl.ID, tmpl.Name = "lonely", "lonely"
			top.Nodes = append(top.Nodes, tmpl)
			b, err := Compile(top)
			if err != nil {
				t.Skipf("compile refuses a linkless %s: %v", role, err)
			}
			prefix := "nodes/lonely/"
			n := 0
			for path, body := range b.Files {
				if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, ".sh") {
					continue
				}
				n++
				for i, line := range strings.Split(body, "\n") {
					if incompleteIP.MatchString(line) {
						t.Errorf("%s:%d incomplete ip command: %q", path, i+1, line)
					}
				}
			}
			if n == 0 {
				t.Fatalf("no scripts rendered for linkless %s", role)
			}
		})
	}
}
