package compile

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/sniff"
)

// The forwarder's checks of meridian-verify.sh (settings.sniff on): the
// installed binary's "meridian sniff-selfcheck" (stubbed here by its exit
// status and evidence lines) decides sniff_selfcheck, failing targets are
// listed, sniff_wg_outer must exist and sniff_denied must not grow over the
// sampling window around the self-check. What cannot be evaluated (an older
// binary, no target file, no socket, unreadable counters) is UNKNOWN, never
// PASS. Sniff off: none of these checks is in the script.
func TestVerifyScriptSniffSelfCheck(t *testing.T) {
	topo := defaults.Example()
	off := mustCompile(t, topo).File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	if strings.Contains(off, "sniff_") {
		t.Fatal("sniff checks in the script with sniff off")
	}
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
	b := mustCompile(t, topo)
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	marker := "# " + sniff.SelfCheckMarker + "\n"
	stub := func(body string) string {
		return "#!/bin/bash\n" + marker + `[ "$MERIDIAN_BIND" = "-" ] && [ "$1" = sniff-selfcheck ] || exit 9
echo ` + sniff.SelfCheckMarker + "\n" + body + "\n"
	}
	ok := stub(`echo "verdict ok"; echo "default group:hk ok"; echo "target group:hk ok [fd66::53:d]:53=answer tcp:[fd66::53:d]:53=connected"; exit 0`)
	other := stub(`echo "verdict ok"; echo "default group:hk ok"; echo "failing exit:jp-a：解析器 [fd66::54:3]:53 超时，没有任何回应"; exit 0`)
	// The incident: the default target's resolver times out, and the
	// dropped outer packets are counted.
	incident := stub(`echo "verdict default_failed"; echo "default group:hk failed"
echo "reason 默认目标 group:hk 的路径不通：解析器 [fd66::53:d]:53 超时，没有任何回应"
echo $(( $(cat "$MERIDIAN_VERIFY_ROOT/t/denied") + 2 )) > "$MERIDIAN_VERIFY_ROOT/t/denied"; exit 3`)
	notLoaded := stub(`echo "verdict timeout"; echo "reason 嗅探服务的自检没有按时完成：嗅探服务在 10s 内没有载入本次安装的规则"; exit 3`)
	noSocket := stub(`echo "verdict unavailable"; echo "reason 嗅探服务的自检无法执行：嗅探服务的状态套接字在 10s 内没有出现或没有回答"; exit 4`)
	counters := `c() { [ -f "$MERIDIAN_VERIFY_ROOT/t/$1" ] || exit 1; printf 'table inet meridian {\n\tcounter %s {\n\t\tpackets %s bytes 156\n\t}\n}\n' "$2" "$(cat "$MERIDIAN_VERIFY_ROOT/t/$1")"; exit 0; }
case "$*" in
'list counter inet meridian sniff_denied') c denied sniff_denied ;;
'list counter inet meridian sniff_wg_outer') c outer sniff_wg_outer ;;
esac`
	base := func(bin string) verifyHost {
		h := goodHost(t, b, topo)
		h.files["usr/local/bin/meridian"] = bin
		h.files["t/denied"] = "7\n"
		h.files["t/outer"] = "90210\n"
		h.wrap = map[string]string{"nft": counters}
		h.env = []string{"MERIDIAN_VERIFY_SNIFF_WINDOW=0"}
		return h
	}
	for _, c := range []struct {
		name            string
		host            func() verifyHost
		want, forbidden []string
	}{
		{"passes", func() verifyHost { return base(ok) },
			[]string{"PASS sniff_selfcheck: the forwarder's self-check of the installed rules passed for the default target group:hk", "PASS sniff_selfcheck_targets",
				"PASS sniff_wg_outer: counter sniff_wg_outer present (90210 packets", "PASS sniff_denied: sniff_denied did not grow"},
			[]string{"FAIL sniff_selfcheck", "UNKNOWN sniff_selfcheck", "UNKNOWN sniff_denied", "FAIL sniff_denied", "WARN sniff_selfcheck_targets"}},
		{"another target fails", func() verifyHost { return base(other) },
			[]string{"PASS sniff_selfcheck:", "WARN sniff_selfcheck_targets: targets whose resolver the forwarder could not reach", "exit:jp-a"},
			[]string{"FAIL sniff_selfcheck", "PASS sniff_selfcheck_targets"}},
		{"the incident", func() verifyHost { return base(incident) },
			[]string{"FAIL sniff_selfcheck: the forwarder's self-check of the installed rules failed: 默认目标 group:hk 的路径不通", "would have been rolled back",
				"FAIL sniff_denied: sniff_denied grew by 2 packets"},
			[]string{"PASS sniff_selfcheck", "PASS sniff_denied", "meridian-verify-local-ok"}},
		{"rules not loaded in time", func() verifyHost { return base(notLoaded) },
			[]string{"FAIL sniff_selfcheck: ", "没有按时完成"}, []string{"PASS sniff_selfcheck"}},
		{"no status socket", func() verifyHost { return base(noSocket) },
			[]string{"UNKNOWN sniff_selfcheck: the self-check could not be evaluated (exit 4)"}, []string{"PASS sniff_selfcheck", "FAIL sniff_selfcheck"}},
		{"older binary", func() verifyHost {
			return base("#!/bin/bash\necho 'meridian: unknown flag'\nexit 0\n")
		}, []string{"UNKNOWN sniff_selfcheck: ", "has no path self-check (an older binary)"}, []string{"PASS sniff_selfcheck", "FAIL sniff_selfcheck"}},
		{"no target file", func() verifyHost {
			h := base(ok)
			delete(h.files, strings.TrimPrefix(SniffTargetsPath, "/"))
			return h
		}, []string{"UNKNOWN sniff_selfcheck: no target file"}, []string{"PASS sniff_selfcheck"}},
		{"ruleset without the outer-packet counter", func() verifyHost {
			h := base(ok)
			delete(h.files, "t/outer")
			return h
		}, []string{"FAIL sniff_wg_outer: counter sniff_wg_outer is missing"}, []string{"PASS sniff_wg_outer"}},
		{"counters unreadable", func() verifyHost {
			h := base(ok)
			delete(h.files, "t/denied")
			return h
		}, []string{"UNKNOWN sniff_denied: counter sniff_denied could not be read"}, []string{"PASS sniff_denied", "FAIL sniff_denied"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := c.host()
			if _, ok := h.files[strings.TrimPrefix(SniffTargetsPath, "/")]; !ok && c.name != "no target file" {
				h.files[strings.TrimPrefix(SniffTargetsPath, "/")] = b.File("nodes/gw" + SniffTargetsPath)
			}
			_, out, _ := runVerify(t, script, h)
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q\n%s", w, out)
				}
			}
			for _, f := range c.forbidden {
				if strings.Contains(out, f) {
					t.Errorf("output must not contain %q\n%s", f, out)
				}
			}
		})
	}
}
