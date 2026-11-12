package provision

import (
	"encoding/base64"
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
	injected := InjectPrivate(files, kp.Private)
	shown := Redact(Script("台湾出口", injected), kp.Private)
	if strings.Contains(shown, kp.Private) {
		t.Fatal("redaction leaked the private key")
	}
}
