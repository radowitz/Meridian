package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
	"golang.org/x/crypto/ssh"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The SSH remote of the Mesh deployment accepts only the pinned host key;
// an unpinned host only with trust_new_host, reporting what it saw.
func TestMeshHostKeyCheck(t *testing.T) {
	real, impostor := hostKey(t), hostKey(t)
	fp := ssh.FingerprintSHA256(real)

	var seen string
	if err := meshHostKeyCheck(mesh.NodeTarget{SSHHost: "h"}, false, &seen)("h:22", nil, real); err == nil {
		t.Fatal("unpinned host accepted without trust")
	}
	if err := meshHostKeyCheck(mesh.NodeTarget{SSHHost: "h"}, true, &seen)("h:22", nil, real); err != nil || seen != fp {
		t.Fatalf("first contact: %v %q", err, seen)
	}
	pinned := mesh.NodeTarget{SSHHost: "h", HostKey: fp}
	seen = ""
	if err := meshHostKeyCheck(pinned, true, &seen)("h:22", nil, impostor); err == nil || seen != "" {
		t.Fatal("different host key accepted for a pinned host (even with trust)")
	}
	if err := meshHostKeyCheck(pinned, false, &seen)("h:22", nil, real); err != nil || seen != fp {
		t.Fatalf("pinned host refused: %v", err)
	}
}
