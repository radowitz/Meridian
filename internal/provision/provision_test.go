package provision

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/defaults"
)

func TestKeypairShape(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(kp.Private)
	if err != nil || len(raw) != 32 {
		t.Fatalf("private key %q", kp.Private)
	}
	pub, err := base64.StdEncoding.DecodeString(kp.Public)
	if err != nil || len(pub) != 32 {
		t.Fatalf("public key %q", kp.Public)
	}
	if kp.Private == kp.Public {
		t.Fatal("keys must differ")
	}
}

func TestProvisionScript(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	files := FilesFor(b.Files, "tw")
	script := Script("台湾出口", files)
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("provision must not flush nftables")
	}
	if !strings.Contains(script, "wg syncconf") && !strings.Contains(script, "meridian-up.sh") {
		t.Fatal("NAT node updates must go through meridian-up (syncconf)")
	}
	if !strings.Contains(script, "MERIDIAN_PROVISION_OK") {
		t.Fatal("missing marker")
	}
	if strings.Contains(script, "cloudflare/mesh") {
		t.Fatal("home provision must not install mesh")
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	injected, err := InjectPrivate(files, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	shown := Redact(Script("台湾出口", injected), kp.Private)
	if strings.Contains(shown, kp.Private) {
		t.Fatal("redaction leaked the private key")
	}
}

func TestProvisionScriptInjectionAndGuards(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	files := FilesFor(b.Files, "tw")
	if _, err := InjectPrivate(files, ""); err == nil {
		t.Fatal("injecting an empty key must fail")
	}
	if _, err := InjectPrivate(files, "bad\nPostUp = id"); err == nil {
		t.Fatal("injecting a malformed key must fail")
	}

	preview := Script("台湾出口", files)
	guard := strings.Index(preview, "exit 1\n")
	firstWrite := strings.Index(preview, "cat > ")
	if guard < 0 || firstWrite < 0 || guard > firstWrite {
		t.Fatal("a preview with placeholders must refuse to run before writing files")
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	injected, err := InjectPrivate(files, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	script := Script("台湾出口", injected)
	if strings.Contains(script, PrivatePlaceholder) {
		t.Fatal("injected script still has the placeholder")
	}
	if !strings.Contains(script, "PrivateKey = "+kp.Private) {
		t.Fatal("key not injected")
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "mv -f") && strings.Contains(line, "/etc/wireguard/") {
			continue
		}
		if strings.HasPrefix(line, "chmod 644") && strings.Contains(line, "wireguard") {
			t.Fatalf("WireGuard config world-readable: %s", line)
		}
	}
	if !strings.Contains(script, "install -d -m 700 '/etc/wireguard'") || !strings.Contains(script, "chmod 600 \"$tmp\"") {
		t.Fatal("WireGuard configs must be written 0600 in a 0700 dir")
	}
	// Exit nodes get a resolver install before any write and a start check after up.
	install := strings.Index(script, "apt-get install -y -o Dpkg::Options::=--force-confold smartdns")
	up := strings.Index(script, "/usr/local/sbin/meridian-up.sh\n")
	active := strings.Index(script, "MERIDIAN_SMARTDNS_ACTIVE")
	if install < 0 || install > strings.Index(script, "cat > ") || active < up {
		t.Fatal("exit provision must install SmartDNS before writing and verify it after meridian-up")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

func TestResolveNodeKey(t *testing.T) {
	// First install: no keys, generate.
	topo := defaults.Example()
	key, changed, err := ResolveNodeKey(&topo, "gw", KeyGenerateIfMissing)
	if err != nil || !changed || key == "" {
		t.Fatalf("first install: key=%v changed=%v err=%v", key != "", changed, err)
	}
	gw, _ := topo.NodeByID("gw")
	if gw.PrivateKey != key {
		t.Fatal("generated key not stored on the node")
	}
	if pub, _ := PublicFromPrivate(key); pub != gw.PublicKey {
		t.Fatal("stored public key does not match")
	}
	// Database already has the key: reuse, no change.
	again, changed, err := ResolveNodeKey(&topo, "gw", KeyGenerateIfMissing)
	if err != nil || changed || again != key {
		t.Fatal("stored key was not reused")
	}
	reuse, changed, err := ResolveNodeKey(&topo, "gw", KeyReuse)
	if err != nil || changed || reuse != key {
		t.Fatal("generate_keys=false did not reuse the stored key")
	}
	// Rotate always makes a new one.
	rot, changed, err := ResolveNodeKey(&topo, "gw", KeyRotate)
	if err != nil || !changed || rot == key {
		t.Fatal("rotate did not generate a new key")
	}
	// Reuse with nothing stored fails without inventing a key.
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyReuse); err == nil {
		t.Fatal("reuse without a stored key must fail")
	}
	if tw, _ := topo.NodeByID("tw"); tw.PrivateKey != "" {
		t.Fatal("failed reuse stored a key")
	}
	// Public key only: the private half is elsewhere, do not replace it.
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].PublicKey = gw.PublicKey
		}
	}
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyGenerateIfMissing); err == nil {
		t.Fatal("public-only node must not get a fresh key silently")
	}
	// Mismatched pair and malformed keys fail, and never echo the key.
	other, _ := GenerateKeypair()
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].PrivateKey = other.Private
		}
	}
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyReuse); err == nil || strings.Contains(err.Error(), other.Private) {
		t.Fatalf("mismatched pair: %v", err)
	}
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == "tw" {
			topo.Nodes[i].PrivateKey = "garbage-key"
		}
	}
	if _, _, err := ResolveNodeKey(&topo, "tw", KeyReuse); err == nil || strings.Contains(err.Error(), "garbage-key") {
		t.Fatalf("malformed key: %v", err)
	}
}

func TestProvisionDoesNotExecuteFileBody(t *testing.T) {
	body := "config line\nMERIDIAN_EOF\necho INJECTED\n"
	script := Script("name\nrm -rf /\n", map[string]string{
		"/etc/sysctl.d/99-meridian.conf": body,
		"/etc/cron.d/evil":               "pwn",
		"/tmp/../etc/cron.d/evil":        "pwn",
	})
	if strings.Contains(script, "\nrm -rf /\n") {
		t.Fatal("node name broke out of the comment")
	}
	if strings.Contains(script, "cat > '/etc/cron.d/evil'") || strings.Contains(script, "cat > '/etc/cron.d/") {
		t.Fatal("provision wrote a cron file")
	}
	if !strings.Contains(script, "MERIDIAN_EOF_") {
		t.Fatal("default heredoc delimiter was not rotated")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}
