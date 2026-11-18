package compile

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
)

// unitDirectives returns the directive lines of one section of a unit.
func unitDirectives(unit, section string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(unit, "\n") {
		switch {
		case strings.HasPrefix(l, "["):
			in = l == "["+section+"]"
		case in && l != "" && !strings.HasPrefix(l, "#"):
			out = append(out, l)
		}
	}
	return out
}

func hasLine(lines []string, l string) bool {
	for _, x := range lines {
		if x == l {
			return true
		}
	}
	return false
}

// The layout systemd accepts (verified on a real Debian 13 / systemd 257
// host with throw-away units): the account comes from a separate root
// oneshot that the forwarder requires and is ordered after, stopped when
// unneeded; the forwarder's unit has no Exec line that would have to run
// before User= resolves. The "+" sysctl lines stay in the forwarder's unit
// (root, set at start, undone after stop).
func TestSniffUnitLayout(t *testing.T) {
	b := mustCompile(t, sniffOn(sniffRules(defaults.Example(), "jp")))
	gw := "nodes/gw/"
	unit := b.File(gw + "etc/systemd/system/" + SniffUnit)
	acct := b.File(gw + "etc/systemd/system/" + SniffAccountUnit)
	script := b.File(gw + strings.TrimPrefix(SniffUserScript, "/"))
	if unit == "" || acct == "" || script == "" {
		t.Fatal("a forwarder file is missing")
	}
	u := unitDirectives(unit, "Unit")
	for _, w := range []string{"Requires=" + SniffAccountUnit} {
		if !hasLine(u, w) {
			t.Errorf("[Unit] lacks %q: %v", w, u)
		}
	}
	after := ""
	for _, l := range u {
		if strings.HasPrefix(l, "After=") {
			after = l
		}
	}
	if !strings.Contains(" "+strings.TrimPrefix(after, "After=")+" ", " "+SniffAccountUnit+" ") {
		t.Errorf("not ordered after the account unit: %q", after)
	}
	svc := unitDirectives(unit, "Service")
	for _, w := range []string{"User=" + SniffUser, "Group=" + SniffUser, "RuntimeDirectory=" + SniffRuntimeDir, "RuntimeDirectoryMode=0755",
		"AmbientCapabilities=CAP_NET_ADMIN", "CapabilityBoundingSet=CAP_NET_ADMIN", "NoNewPrivileges=yes", "ProtectSystem=strict",
		"ExecStartPre=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=1", "ExecStopPost=+/usr/sbin/sysctl -q -w net.ipv4.tcp_fwmark_accept=0"} {
		if !hasLine(svc, w) {
			t.Errorf("[Service] lacks %q", w)
		}
	}
	for _, l := range svc {
		if strings.Contains(l, SniffUserScript) || strings.HasPrefix(l, "DynamicUser") || strings.HasPrefix(l, "SupplementaryGroups") {
			t.Errorf("forwarder unit line %q: the account must come from the account unit", l)
		}
	}
	if !strings.Contains(unit, "\n[Install]\nWantedBy=multi-user.target\n") {
		t.Error("forwarder not wanted at boot")
	}
	// Account unit: root oneshot, kept active, stopped when unneeded, never
	// enabled on its own.
	au := unitDirectives(acct, "Unit")
	as := unitDirectives(acct, "Service")
	for _, w := range []string{"StopWhenUnneeded=yes"} {
		if !hasLine(au, w) {
			t.Errorf("account [Unit] lacks %q", w)
		}
	}
	for _, w := range []string{"Type=oneshot", "RemainAfterExit=yes", "ExecStart=" + SniffUserScript + " add", "ExecStop=" + SniffUserScript + " del"} {
		if !hasLine(as, w) {
			t.Errorf("account [Service] lacks %q", w)
		}
	}
	for _, l := range as {
		if strings.HasPrefix(l, "User=") || strings.HasPrefix(l, "DynamicUser=") || strings.HasPrefix(l, "ProtectSystem=") {
			t.Errorf("account unit must run as root with write access to the user database: %q", l)
		}
	}
	if strings.Contains(acct, "[Install]") {
		t.Error("account unit has an [Install] section")
	}
	// The script is not under /run (noexec) and parses.
	if strings.HasPrefix(SniffUserScript, "/run/") || strings.HasPrefix(SniffUserScript, "/tmp/") {
		t.Fatal("account script path")
	}
	for _, w := range []string{"name=" + SniffUser + "\n", "id=65530\n", "meridian-sniff-user-conflict", "groupdel"} {
		if !strings.Contains(script, w) {
			t.Errorf("script lacks %q", w)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bash -n: %v %s", err, out)
		}
	}
	// The gateway spec is a valid spec, and the status socket follows it.
	if err := gatewaySniffSpec(sniffOn(defaults.Example()), &sniffPlan{Ports: []int{443}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

// The compiled gateway unit is RenderSniffUnit of the gateway spec, the
// function "meridian sniff-verify-render" calls with temporary names; the
// spec validation keeps those names plain and the paths out of /run, /tmp
// and the hidden home directories.
func TestSniffSpecRender(t *testing.T) {
	topo := sniffOn(sniffRules(defaults.Example(), "jp"))
	b := mustCompile(t, topo)
	prod := gatewaySniffSpec(topo, &sniffPlan{Ports: topo.Settings.Sniff.EffectivePorts(), ECH: topo.Settings.Sniff.EffectiveECHPublicNames()})
	if got := RenderSniffUnit(prod); got != b.File("nodes/gw/etc/systemd/system/"+SniffUnit) {
		t.Fatal("RenderSniffUnit differs from the compiled unit")
	}
	v := prod
	v.Unit, v.AccountUnit, v.User, v.UID = "meridian-vfy-sniff-1.service", "meridian-vfy-sniff-1-account.service", "meridian-vfy1", 65521
	v.AccountScript, v.RuntimeDir, v.Listen = "/var/lib/meridian-vfy-1/account.sh", "meridian-vfy-sniff-1", "127.0.0.1:25001"
	v.FwmarkAcceptOn, v.FwmarkAcceptOff = "0", "0"
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	unit, acct := RenderSniffUnit(v), RenderSniffAccountUnit(v)
	for _, w := range []string{"Requires=meridian-vfy-sniff-1-account.service", "User=meridian-vfy1", "RuntimeDirectory=meridian-vfy-sniff-1", "--status-socket /run/meridian-vfy-sniff-1/status.sock", "--listen 127.0.0.1:25001", "tcp_fwmark_accept=0\n"} {
		if !strings.Contains(unit, w) {
			t.Errorf("verify unit lacks %q", w)
		}
	}
	if !strings.Contains(acct, "ExecStart=/var/lib/meridian-vfy-1/account.sh add") || !strings.Contains(RenderSniffAccountScript(v), "id=65521\n") {
		t.Error("account unit / script not rendered from the spec")
	}
	for name, f := range map[string]func(*SniffUnitSpec){
		"script under /run": func(s *SniffUnitSpec) { s.AccountScript = "/run/x/account.sh" },
		"script in /tmp":    func(s *SniffUnitSpec) { s.AccountScript = "/tmp/a.sh" },
		"binary in /root":   func(s *SniffUnitSpec) { s.Binary = "/root/meridian" },
		"relative":          func(s *SniffUnitSpec) { s.Snapshot = "decide.json" },
		"specifier":         func(s *SniffUnitSpec) { s.Targets = "/var/lib/%n/t.json" },
		"root user":         func(s *SniffUnitSpec) { s.User = "root" },
		"uid 0":             func(s *SniffUnitSpec) { s.UID = 0 },
		"same unit":         func(s *SniffUnitSpec) { s.AccountUnit = s.Unit },
		"bad unit":          func(s *SniffUnitSpec) { s.Unit = "x.service; rm" },
		"sysctl value":      func(s *SniffUnitSpec) { s.FwmarkAcceptOn = "2" },
		"state dir path":    func(s *SniffUnitSpec) { s.StateDir = "../etc" },
		"listen":            func(s *SniffUnitSpec) { s.Listen = "nowhere" },
	} {
		x := v
		f(&x)
		if x.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The connection journal's directory: the unit's StateDirectory (systemd
// creates it 0700 owned by the forwarder's uid, writable under
// ProtectSystem=strict), passed to the forwarder as --journal-dir, and no
// other writable path; the generated verify script checks its modes; a
// spec without StateDir renders no journal at all.
func TestSniffJournalDir(t *testing.T) {
	b := mustCompile(t, sniffOn(sniffRules(defaults.Example(), "jp")))
	unit := b.File("nodes/gw/etc/systemd/system/" + SniffUnit)
	svc := unitDirectives(unit, "Service")
	for _, w := range []string{"StateDirectory=" + SniffStateDir, "StateDirectoryMode=0700"} {
		if !hasLine(svc, w) {
			t.Errorf("[Service] lacks %q", w)
		}
	}
	if SniffJournalDir != "/var/lib/meridian-sniff" {
		t.Fatal(SniffJournalDir)
	}
	execLine := ""
	for _, l := range svc {
		if strings.HasPrefix(l, "ExecStart=") {
			execLine = l
		}
		for _, bad := range []string{"ReadWritePaths", "StateDirectoryMode=07", "LogsDirectory", "CacheDirectory"} {
			if strings.HasPrefix(l, bad) && l != "StateDirectoryMode=0700" {
				t.Errorf("unexpected %q", l)
			}
		}
	}
	if !strings.Contains(execLine, " --journal-dir "+SniffJournalDir+" ") {
		t.Errorf("ExecStart lacks the journal: %q", execLine)
	}
	verify := ""
	for p, body := range b.Files {
		if strings.HasSuffix(p, "meridian-verify.sh") && strings.HasPrefix(p, "nodes/gw/") {
			verify = body
		}
	}
	for _, w := range []string{"sniff_journal_dir", `sniff_state="$root"` + SniffJournalDir, `"700 65530"`, "-perm /077"} {
		if !strings.Contains(verify, w) {
			t.Errorf("gateway verify script lacks %q", w)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil && verify != "" {
		if out, err := bashN(bash, verify); err != nil {
			t.Fatalf("bash -n: %v %s", err, out)
		}
	}
	spec := gatewaySniffSpec(sniffOn(defaults.Example()), &sniffPlan{Ports: []int{443}})
	spec.StateDir = ""
	if u := RenderSniffUnit(spec); strings.Contains(u, "StateDirectory") || strings.Contains(u, "--journal-dir") {
		t.Fatal("journal rendered without a state directory")
	}
	// Off: nothing of the forwarder, its journal included.
	off := mustCompile(t, defaults.Example())
	for p, body := range off.Files {
		if strings.Contains(body, "--journal-dir") || strings.Contains(body, "sniff_journal_dir") {
			t.Fatalf("%s mentions the journal with sniffing off", p)
		}
	}
}

func bashN(bash, script string) ([]byte, error) {
	cmd := exec.Command(bash, "-n")
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}
