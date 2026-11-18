package compile

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
)

// The DNS query journal (settings.dns_log; docs/architecture.md「网关解析
// 日志」) as compiled.

func dnsLogTopos() map[string]model.Topology {
	out := map[string]model.Topology{"example": defaults.Example()}
	for _, c := range dnsSettingsCases() {
		out[c.name] = c.topo()
	}
	sn := defaults.Example()
	sn.Settings.Sniff = &model.SniffSettings{Enabled: true}
	out["sniff"] = sn
	return out
}

// Off — never set, or set and off — compiles byte-identically; on changes
// exactly three gateway files and nothing of any other node.
func TestDNSLogOffIsByteIdenticalOnChangesThreeFiles(t *testing.T) {
	for name, topo := range dnsLogTopos() {
		base, err := Compile(topo)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		off := topo
		off.Settings.DNSLog = &model.DNSLogSettings{Enabled: false}
		ob, err := Compile(off)
		if err != nil {
			t.Fatal(err)
		}
		if ob.Canonical() != base.Canonical() || len(ob.Files) != len(base.Files) {
			t.Fatalf("%s: the setting, off, changed the bundle", name)
		}
		for p, body := range base.Files {
			if ob.Files[p] != body {
				t.Fatalf("%s: %s differs with the setting off", name, p)
			}
			if strings.Contains(body, "audit-enable") || strings.Contains(body, "dns-journal") || strings.Contains(body, "dns_log") || strings.Contains(body, dnsjournal.StateDir) {
				t.Fatalf("%s: %s mentions the query journal while it is off", name, p)
			}
		}
		on := topo
		on.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
		nb, err := Compile(on)
		if err != nil {
			t.Fatal(err)
		}
		var changed, added []string
		for p, body := range nb.Files {
			old, ok := base.Files[p]
			switch {
			case !ok:
				added = append(added, p)
			case old != body:
				changed = append(changed, p)
			}
		}
		for p := range base.Files {
			if _, ok := nb.Files[p]; !ok {
				t.Fatalf("%s: %s removed by turning the journal on", name, p)
			}
		}
		sort.Strings(changed)
		unit := "nodes/gw/etc/systemd/system/" + DNSJournalUnit
		if strings.Join(added, " ") != unit || strings.Join(changed, " ") != "nodes/gw/etc/smartdns/smartdns.conf nodes/gw/usr/local/sbin/meridian-verify.sh" {
			t.Fatalf("%s: added %v, changed %v", name, added, changed)
		}
		// smartdns.conf: only lines added, and of those only the four audit
		// directives are not comments.
		oldLines := map[string]int{}
		for _, l := range strings.Split(base.Files["nodes/gw/etc/smartdns/smartdns.conf"], "\n") {
			oldLines[l]++
		}
		var directives []string
		for _, l := range strings.Split(nb.Files["nodes/gw/etc/smartdns/smartdns.conf"], "\n") {
			if oldLines[l] > 0 {
				oldLines[l]--
				continue
			}
			if !strings.HasPrefix(l, "#") {
				directives = append(directives, l)
			}
		}
		for l, n := range oldLines {
			if n != 0 {
				t.Fatalf("%s: line %q of smartdns.conf went away", name, l)
			}
		}
		want := []string{"audit-enable yes", "audit-file /var/lib/meridian-dnslog/raw/audit.log", "audit-size 2048k", "audit-num 1"}
		if strings.Join(directives, "|") != strings.Join(want, "|") {
			t.Fatalf("%s: new directives %q", name, directives)
		}
		conf := nb.Files["nodes/gw/etc/smartdns/smartdns.conf"]
		if !SmartDNSAuditOn(conf) || SmartDNSAuditOn(base.Files["nodes/gw/etc/smartdns/smartdns.conf"]) || !dnsjournal.ReadAuditConfig(conf).Managed() {
			t.Fatalf("%s: audit detection", name)
		}
		// The audit file is not something the config loads: the read-only
		// shared directories are unchanged.
		if strings.Join(SmartDNSFileRefs(conf), " ") != strings.Join(SmartDNSFileRefs(base.Files["nodes/gw/etc/smartdns/smartdns.conf"]), " ") {
			t.Fatalf("%s: file references changed", name)
		}
		// The verify script: the old one with one block inserted.
		ov, nv := base.Files["nodes/gw/usr/local/sbin/meridian-verify.sh"], nb.Files["nodes/gw/usr/local/sbin/meridian-verify.sh"]
		if strings.Replace(nv, dnsLogVerifyBlock+"\n", "", 1) != ov {
			t.Fatalf("%s: the verify script changed beyond the inserted block", name)
		}
	}
}

func TestDNSJournalUnit(t *testing.T) {
	if hostexec.DNSJournalUnit != DNSJournalUnit || !hostexec.ValidUnit(DNSJournalUnit) {
		t.Fatalf("unit names: %q %q", hostexec.DNSJournalUnit, DNSJournalUnit)
	}
	topo := defaults.Example()
	topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	unit := b.File("nodes/gw/etc/systemd/system/" + DNSJournalUnit)
	for _, want := range []string{
		"ExecStartPre=/bin/grep -q " + dnsjournal.ReadyMarker + " /usr/local/bin/meridian\n",
		"ExecStartPre=/usr/local/bin/meridian dns-journal --prepare --raw-dir /var/lib/meridian-dnslog/raw --journal-dir /var/lib/meridian-dnslog/journal\n",
		"ExecStart=/usr/local/bin/meridian dns-journal --raw-dir /var/lib/meridian-dnslog/raw --journal-dir /var/lib/meridian-dnslog/journal --status-socket " + dnsjournal.StatusSocket + " --neigh-if " + gatewayLAN(topo) + "\n",
		"User=root\n", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "NoNewPrivileges=yes\n",
		"StateDirectory=meridian-dnslog\n", "StateDirectoryMode=0700\n", "RuntimeDirectory=meridian-dns-journal\n",
		"ProtectSystem=strict\n", "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n", "IPAddressDeny=any\n", "UMask=0077\n",
		"IOSchedulingClass=idle\n", "Nice=10\n", "MemoryMax=96M\n", "WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit misses %q", want)
		}
	}
	// The sink is prepared before the reader counts as started.
	if strings.Index(unit, "--prepare") > strings.Index(unit, "\nExecStart=") {
		t.Fatal("the audit sink is prepared after ExecStart")
	}
	for _, bad := range []string{"ReadWritePaths", "Capabilities=CAP", "CapabilityBoundingSet=CAP", "AF_INET", "docker"} {
		if strings.Contains(unit, bad) {
			t.Errorf("unit carries %q", bad)
		}
	}
	// The flags are the ones the reader parses, with its own defaults.
	args := strings.Fields(strings.TrimPrefix(regexp.MustCompile(`(?m)^ExecStart=.*$`).FindString(unit), "ExecStart=/usr/local/bin/meridian dns-journal "))
	c, err := dnsjournal.ParseArgs(args)
	if err != nil || c.RawDir != dnsjournal.RawDir || c.JournalDir != dnsjournal.JournalDir || c.StatusSocket != dnsjournal.StatusSocket ||
		c.MaxBytes != 32<<20 || c.MaxRecords != 50000 || c.MaxAge.Hours() != 24 || len(c.NeighIfaces) != 1 {
		t.Fatalf("%v %+v", err, c)
	}
	pre := strings.Fields(strings.TrimPrefix(regexp.MustCompile(`(?m)^ExecStartPre=.*--prepare.*$`).FindString(unit), "ExecStartPre=/usr/local/bin/meridian dns-journal "))
	if c, err := dnsjournal.ParseArgs(pre); err != nil || !c.PrepareOnly || c.RawDir != dnsjournal.RawDir {
		t.Fatalf("%v %+v", err, c)
	}
	// The binary the unit greps for the marker is this one.
	if !strings.Contains(dnsjournal.ReadyMarker, "meridian-dns-journal-ready") {
		t.Fatal("ready marker")
	}
}

// The resolver container: every mount read-only except the audit directory,
// which install.sh creates root-only before the container is.
func TestDNSLogComposeMountAndInstall(t *testing.T) {
	svc := composeService(repoFile(t, "deploy/docker-compose.yml"), "smartdns")
	var rw []string
	for _, l := range strings.Split(svc, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "- /") {
			continue
		}
		if !strings.HasSuffix(l, ":ro") {
			rw = append(rw, strings.TrimPrefix(l, "- "))
		}
	}
	if len(SmartDNSWritableDirs) != 1 || SmartDNSWritableDirs[0] != dnsjournal.RawDir ||
		len(rw) != 1 || rw[0] != dnsjournal.RawDir+":"+dnsjournal.RawDir {
		t.Fatalf("writable mounts of the resolver: %v", rw)
	}
	for _, d := range SmartDNSSharedDirs {
		if strings.HasPrefix(dnsjournal.RawDir, d) || strings.HasPrefix(d, dnsjournal.StateDir) {
			t.Fatalf("the audit directory overlaps the shared directory %s", d)
		}
	}
	if strings.Contains(svc, dnsjournal.JournalDir) || strings.Contains(svc, "- "+dnsjournal.StateDir+":") {
		t.Fatal("the resolver container must see the raw directory only, never the journal")
	}
	inst := repoFile(t, "deploy/debian/install.sh")
	if !strings.Contains(inst, "install -d -m 0700 "+dnsjournal.StateDir+" "+dnsjournal.RawDir+"\n") || !strings.Contains(inst, "chmod 0700 "+dnsjournal.StateDir+" "+dnsjournal.RawDir+"\n") {
		t.Fatal("install.sh does not create the audit directory 0700")
	}
	if !strings.Contains(repoFile(t, "deploy/debian/meridian-host.service"), " -"+dnsjournal.StateDir+"\n") {
		t.Fatal("the host agent cannot delete the journal's data (ReadWritePaths)")
	}
}

func TestDNSLogVerifyScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	topo := defaults.Example()
	topo.Settings.DNSLog = &model.DNSLogSettings{Enabled: true}
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	for _, want := range []string{"dns_log_reader", "dns_log_sink", "dns_log_journal_dir", "dns_log_budget", "dns_log_status_socket", "dns_log_config", "dns_log_real_binary",
		`dnslog_raw="$root"` + dnsjournal.RawDir, `"700 0"`, `! -type f`, "sniff_journal_dir", "32768"} {
		if !strings.Contains(script, want) {
			t.Errorf("verify script misses %q", want)
		}
	}
	if strings.Index(script, "dns_log_sink") > strings.Index(script, `emit "evidence: $evdir"`) {
		t.Fatal("the block is after the script's end")
	}
	f := filepath.Join(t.TempDir(), "verify.sh")
	if err := os.WriteFile(f, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}

	// The sink check itself, run against prepared directories: a regular
	// 0600 file in a 0700 directory passes; a FIFO, a symbolic link, a
	// world-readable file and an open directory fail. Ownership is the
	// test's own uid here (root on the gateway).
	start := strings.Index(dnsLogVerifyBlock, "dnslog_raw=")
	end := strings.Index(dnsLogVerifyBlock, "dnslog_journal=")
	check := strings.ReplaceAll(dnsLogVerifyBlock[start:end], `"700 0"`, `"700 $(id -u)"`)
	check = strings.ReplaceAll(check, "! -user 0", `! -user "$(id -u)"`)
	// The gateway has GNU stat ("stat -c '%a %u'"). Where this test runs
	// without it (BSD stat), a shell function gives the same two fields.
	shim := ""
	if out, err := exec.Command("stat", "-c", "%a %u", "/").CombinedOutput(); err != nil || !regexp.MustCompile(`^\d+ \d+\s*$`).Match(out) {
		if out, err := exec.Command("stat", "-f", "%Lp %u", "/").CombinedOutput(); err != nil || !regexp.MustCompile(`^\d+ \d+\s*$`).Match(out) {
			t.Skip("neither GNU nor BSD stat here: the check's logic was not run")
		}
		shim = `stat() { if [ "$1" = -c ]; then shift 2; command stat -f '%Lp %u' "$@"; else command stat "$@"; fi; }; `
	}
	// Likewise GNU find's "-perm /mode" (any of the bits) is "+mode" in BSD
	// find.
	if exec.Command("find", os.TempDir(), "-maxdepth", "0", "-perm", "/027").Run() != nil {
		check = strings.ReplaceAll(check, "-perm /", "-perm +")
	}
	run := func(root string) string {
		cmd := exec.Command("bash", "-c", shim+`pass() { echo "PASS $1"; }; fail() { echo "FAIL $1"; }; root="$1"; `+check, "bash", root)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	root := t.TempDir()
	raw := filepath.Join(root, dnsjournal.RawDir)
	if err := dnsjournal.PrepareSink(raw); err != nil {
		t.Fatal(err)
	}
	if got := run(root); got != "PASS dns_log_sink" {
		t.Fatalf("prepared sink: %s", got)
	}
	file := filepath.Join(raw, dnsjournal.AuditBase)
	os.Chmod(file, 0o644)
	if got := run(root); got != "FAIL dns_log_sink" {
		t.Fatalf("world-readable file: %s", got)
	}
	os.Chmod(file, 0o640) // just rotated by the resolver: tolerated
	if got := run(root); got != "PASS dns_log_sink" {
		t.Fatalf("0640 file: %s", got)
	}
	os.Remove(file)
	os.Symlink("/etc/hostname", file)
	if got := run(root); got != "FAIL dns_log_sink" {
		t.Fatalf("symbolic link: %s", got)
	}
	os.Remove(file)
	if exec.Command("mkfifo", file).Run() == nil {
		if got := run(root); got != "FAIL dns_log_sink" {
			t.Fatalf("FIFO: %s", got)
		}
	}
	os.Remove(file)
	dnsjournal.PrepareSink(raw)
	os.Chmod(raw, 0o755)
	if got := run(root); got != "FAIL dns_log_sink" {
		t.Fatalf("0755 directory: %s", got)
	}
}

// Every upstream group the gateway config can log is named for the panel.
func TestDNSLogGroups(t *testing.T) {
	for name, topo := range dnsLogTopos() {
		b, err := Compile(topo)
		if err != nil {
			t.Fatal(err)
		}
		gs, err := DNSLogGroups(topo)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		known := map[string]DNSLogGroup{}
		for _, g := range gs {
			if g.Group == "" || g.Kind == "" || g.Label == "" || !dnsjournal.GroupRe.MatchString(g.Group) {
				t.Fatalf("%s: %+v", name, g)
			}
			if _, dup := known[g.Group]; dup {
				t.Fatalf("%s: group %s twice", name, g.Group)
			}
			known[g.Group] = g
		}
		if known["domestic"].Kind != "domestic" || known["default"].Group == "" {
			t.Fatalf("%s: %+v", name, gs)
		}
		for _, m := range regexp.MustCompile(`(?m)^server\S* \S+ -group (\S+)`).FindAllStringSubmatch(b.File("nodes/gw/etc/smartdns/smartdns.conf"), -1) {
			if _, ok := known[m[1]]; !ok {
				t.Errorf("%s: the config's group %s has no name for the panel", name, m[1])
			}
		}
		for _, g := range gs {
			switch g.Kind {
			case "exit", "region_group":
				if g.ID == "" || !strings.Contains(g.Label, g.ID) {
					t.Errorf("%s: %+v", name, g)
				}
			}
		}
	}
}
