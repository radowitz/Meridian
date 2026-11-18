package compile

import (
	"regexp"
	"strings"
)

// emptyDevRe matches a generated `ip` command whose interface operand is
// empty ("dev " followed by another space or the end of the line). That is
// what a node without an enabled tunnel link would otherwise get, and
// iproute2 rejects it ("Command line is not complete", exit 255).
var emptyDevRe = regexp.MustCompile(`^\s*(del_rule )?ip (-6 )?(route|rule|neigh|addr|link)\b.*\bdev( |$)( |$)`)

// dropEmptyOperandIPLines removes ip commands with an empty dev operand
// from a generated script. Scripts without such lines come back unchanged,
// so linked topologies render byte-identically.
func dropEmptyOperandIPLines(script string) string {
	if !strings.Contains(script, "dev  ") && !strings.Contains(script, "dev \n") {
		return script
	}
	lines := strings.Split(script, "\n")
	out := lines[:0]
	dropped := false
	for _, l := range lines {
		if emptyDevRe.MatchString(l) {
			dropped = true
			continue
		}
		out = append(out, l)
	}
	s := strings.Join(out, "\n")
	if dropped {
		s = strings.Replace(s, "set -euo pipefail\n", "set -euo pipefail\necho \"meridian: node has no enabled tunnel link; tunnel routes skipped\" >&2\n", 1)
	}
	return s
}
