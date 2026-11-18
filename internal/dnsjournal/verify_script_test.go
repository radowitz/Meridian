package dnsjournal

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// deploy/verify-smartdns.sh --audit-check is how a SmartDNS version that is
// not in VerifiedVersions gets verified on a gateway. It is not run here
// (it needs Docker and an image); this pins what it may do and keeps its
// line pattern and record file in step with the parser and the gate.
func TestAuditCheckScript(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "verify-smartdns.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	start := strings.Index(script, "audit_check() {")
	end := strings.Index(script, `if [[ "${1:-}" == "--audit-check" ]]; then`)
	if start < 0 || end < start {
		t.Fatal("no audit_check in deploy/verify-smartdns.sh")
	}
	body := script[start:end]

	// The pattern it greps audit lines with accepts and refuses what the
	// parser does.
	m := regexp.MustCompile(`(?m)^audit_re='(.*)'$`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("no audit_re")
	}
	re, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("audit_re is not a pattern Go reads too: %v", err)
	}
	samples := strings.Split(strings.TrimSuffix(observedLines, "\n"), "\n")
	samples = append(samples,
		"[2026-11-15 13:00:18,410] 127.0.0.1 query multi.example.test, type 1, time 0ms, speed: -0.1ms, group default, result 192.0.2.1, 192.0.2.2, 192.0.2.3",
		"[2026-11-15 13:00:20,924] ::1 query b.example.test, type 28, time 0ms, speed: -0.1ms, group default, result 2001:db8::1",
		"[2026-11-15 13:00:54,100] 127.0.0.1 query odd name,x.example.test, type 1, time 2ms, speed: -0.1ms, group default, result ",
		"smartdns starting",
		"[2026-11-15 13:00:20,924] 127.0.0.1 query a.example.test, type A, time 0ms, speed: -0.1ms, group default, result 192.0.2.1",
		"[2026-11-15 13:00:20,924] 127.0.0.1 query a.example.test, type 1, time 0ms",
		"")
	for _, l := range samples {
		_, perr := ParseLine([]byte(l))
		if re.MatchString(l) != (perr == nil) {
			t.Errorf("the script's pattern and the parser disagree on %q (script %v, parser %v)", l, re.MatchString(l), perr)
		}
	}
	if !strings.Contains(script, "audit_record="+LocalVerifiedFile+"\n") {
		t.Fatal("the script records somewhere else than LocalVerifiedFile")
	}
	// The line it records is one ParseLocalVerified reads.
	if !strings.Contains(body, `echo "${version} ${image_id} $(date -u +%Y-%m-%d)" >>"$audit_record"`) {
		t.Fatal("the recorded line is not \"<version> <image id> <date>\"")
	}
	if rs := ParseLocalVerified("1.2027.01.02-0304 sha256:" + strings.Repeat("a", 64) + " 2027-01-05\n"); len(rs) != 1 {
		t.Fatal("such a line is not read back")
	}
	// Every container it starts has no network; nothing is pulled; the
	// running resolver is only looked at (one inspect for its image).
	runs := 0
	for _, l := range strings.Split(body, "\n") {
		code := strings.TrimSpace(l)
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "docker run") {
			runs++
			if !strings.Contains(code, "--network none") {
				t.Errorf("a container with a network: %s", code)
			}
		}
		for _, bad := range []string{"docker pull", "docker restart", "docker stop", "docker cp", "curl ", "wget ", "/etc/smartdns", "docker compose"} {
			if strings.Contains(code, bad) {
				t.Errorf("audit-check does %q: %s", bad, code)
			}
		}
		if strings.Contains(code, "meridian-smartdns") && !strings.Contains(code, "docker inspect --type container -f '{{.Image}}' meridian-smartdns") &&
			!strings.Contains(code, "echo \"") && !strings.Contains(code, "name the image") {
			t.Errorf("audit-check touches the running resolver: %s", code)
		}
	}
	if runs < 2 {
		t.Fatalf("%d docker run lines", runs)
	}
	// Only synthetic names and documentation addresses.
	for _, m := range regexp.MustCompile(`[a-z0-9-]+\.[a-z0-9.-]*[a-z]{2,}\b`).FindAllString(body, -1) {
		if strings.HasSuffix(m, ".test") || strings.HasSuffix(m, ".sh") || strings.HasSuffix(m, ".log") || strings.HasSuffix(m, ".gz") || strings.HasSuffix(m, ".conf") ||
			strings.HasSuffix(m, ".img") || strings.HasSuffix(m, ".ext4") || strings.HasPrefix(m, "audit.log") || strings.HasPrefix(m, "fs.") || strings.HasPrefix(m, "mkfs.") || strings.HasPrefix(m, "gate.go") {
			continue
		}
		t.Errorf("a name that is not synthetic: %s", m)
	}
	for _, m := range regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`).FindAllString(body, -1) {
		if !strings.HasPrefix(m, "192.0.2.") && m != "127.0.0.1" {
			t.Errorf("an address outside the documentation range: %s", m)
		}
	}
	// It only ever freezes the private loop mount it made, and always thaws.
	for _, want := range []string{`!= /dev/loop* ]]`, `fsfreeze -u "$mnt"`, "trap a_cleanup EXIT", `mktemp -d /var/tmp/meridian-audit-check.XXXXXX`, "skipped=${askip} (nothing is recorded)"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit-check misses %q", want)
		}
	}
	if strings.Index(body, "/dev/loop*") > strings.Index(body, `fsfreeze -f "$mnt"`) {
		t.Fatal("the loop-mount check comes after the freeze")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available: syntax and usage not checked")
	}
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
	// A wrong flag is refused before anything runs.
	err = exec.Command(bash, path, "--audit-check", "--bogus").Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
		t.Fatalf("usage error: %v", err)
	}
}
