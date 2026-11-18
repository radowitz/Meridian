package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
)

// fakeSource is an ArtifactSource of fixed bytes per name.
type fakeSource map[string][]byte

func (f fakeSource) Read(name, arch string) ([]byte, artifacts.Pin, error) {
	b, ok := f[name]
	if !ok {
		return nil, artifacts.Pin{}, artifacts.ErrUnavailable
	}
	return b, artifacts.Pin{Name: name, Version: "1.0-test", Arch: arch, SHA256: artifacts.SHA256Of(b), Size: int64(len(b))}, nil
}

// The gateway's wstunnel is part of the install transaction: written and
// recorded on install, put back by a compensation after a failed update
// that replaced it, removed when no unit needs it any more; an unavailable
// copy refuses the install before anything is written; a foreign file at
// the path is never overwritten.
func TestGatewayArtifactTransaction(t *testing.T) {
	r := newRig(t)
	bin := filepath.Join(r.host, "usr", "local", "sbin", "meridian-wstunnel")
	v1 := []byte("#!/bin/sh\n# wstunnel v1\n")
	a := r.applier()
	a.Artifacts, a.Arch = fakeSource{"wstunnel": v1}, "x86_64"
	b := compileTopo(t, defaults.Example())
	if _, err := a.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(bin); string(got) != string(v1) {
		t.Fatalf("binary %q", got)
	}
	inst, _ := a.Installed()
	if len(inst.Artifacts) != 1 || inst.Artifacts[0].Path != "usr/local/sbin/meridian-wstunnel" || inst.Artifacts[0].SHA256 != artifacts.SHA256Of(v1) {
		t.Fatalf("manifest %+v", inst.Artifacts)
	}

	// An update with a new binary whose activation fails: compensated,
	// the previous binary is back.
	v2 := []byte("#!/bin/sh\n# wstunnel v2\n")
	a.Artifacts = fakeSource{"wstunnel": v2}
	r.sim.failOnce["systemctl restart meridian-failover.service"] = true
	_, err := a.Apply(b, false)
	var te *TxnError
	if !errors.As(err, &te) || !te.Compensated {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(bin); string(got) != string(v1) {
		t.Fatalf("compensation did not restore the previous binary: %q", got)
	}
	// The same update succeeds.
	if _, err := a.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(bin); string(got) != string(v2) {
		t.Fatalf("binary not replaced: %q", got)
	}

	// No unit needs wstunnel any more: removed with the units.
	topo := withoutHubWSS()
	for i, l := range topo.Links {
		if (l.From == "gw" || l.To == "gw") && (l.Transport == model.TransportWGOverWSS || l.Transport == model.TransportUDPWSSFailover) {
			topo.Links[i].Transport = model.TransportDirectWG
		}
	}
	nb := compileTopo(t, topo)
	for p := range nb.Files {
		if strings.HasPrefix(p, "nodes/gw/etc/systemd/system/wstunnel-") {
			t.Fatalf("test topology still has %s", p)
		}
	}
	if _, err := a.Apply(nb, false); err != nil {
		t.Fatal(err)
	}
	if exists(bin) {
		t.Fatal("binary left after its last unit went away")
	}

	// No verified copy: refused before any host file is written.
	r2 := newRig(t)
	a2 := r2.applier()
	a2.Artifacts, a2.Arch = fakeSource{}, "x86_64"
	if _, err := a2.Apply(b, false); err == nil {
		t.Fatal("install without the binary succeeded")
	}
	if entries, _ := os.ReadDir(r2.host); len(entries) != 0 {
		t.Fatalf("host written: %v", entries)
	}

	// A foreign file at the path: refused, compensated, left alone.
	r3 := newRig(t)
	foreign := filepath.Join(r3.host, "usr", "local", "sbin", "meridian-wstunnel")
	os.MkdirAll(filepath.Dir(foreign), 0o755)
	os.WriteFile(foreign, []byte("someone else's\n"), 0o755)
	a3 := r3.applier()
	a3.Artifacts, a3.Arch = fakeSource{"wstunnel": v1}, "x86_64"
	if _, err := a3.Apply(b, false); err == nil {
		t.Fatal("foreign binary overwritten")
	}
	if got, _ := os.ReadFile(foreign); string(got) != "someone else's\n" {
		t.Fatalf("foreign file changed: %q", got)
	}
}
