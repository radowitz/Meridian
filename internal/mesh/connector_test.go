package mesh_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
)

const run = "0123456789abcdef"

// The install script is fixed: the official source, the pinned key, the
// package and service, and the token only in a 0600 file of a temporary
// directory removed on exit. Bad inputs are refused before any script.
func TestConnectorInstallScriptIsFixed(t *testing.T) {
	tok := "synthetic-token-AbC123=="
	s, err := mesh.ConnectorInstallScript(run, "bookworm", testFpr, tok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		mesh.RepoKeyURL, mesh.RepoKeyring, mesh.RepoList, "deb [signed-by=" + mesh.RepoKeyring + "] " + mesh.RepoURL + " bookworm main",
		"'" + testFpr + "'", "fail key_fingerprint", `apt-get "${pin[@]}" install -y --no-install-recommends cloudflare-warp="$ver"`, `Pin: origin "pkg.cloudflareclient.com"`, "fail apt_install_origin", `apt-get "${one[@]}" update`, "fail candidate_not_official", "fail key_set_differs", "fail repo_list_differs", "ip -$f route show table 65743",
		"-o Dir::Etc::sourcelist=", "warp-cli --accept-tos connector new", `chmod 600 "$tmp/token"`, `trap 'rm -rf "$tmp"' EXIT`,
		"MESH_CREATED", "fail global_default", "MESH_NODE_ADDR CloudflareWARP", "/var/lib/meridian/mesh-deploy/" + run,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script lacks %q", want)
		}
	}
	if strings.Count(s, tok) != 1 {
		t.Fatal("the token appears outside its one heredoc")
	}
	for _, bad := range []string{"docker", "mode warp", "set-mode", "tunnel_protocol", "flush ruleset"} {
		if strings.Contains(s, bad) {
			t.Errorf("install script contains %q", bad)
		}
	}
	for name, args := range map[string][4]string{
		"run id":   {"xyz", "bookworm", testFpr, tok},
		"codename": {run, "bookworm; rm -rf /", testFpr, tok},
		"fpr":      {run, "bookworm", "ABC", tok},
		"token":    {run, "bookworm", testFpr, "tok'; reboot"},
		"empty":    {run, "bookworm", testFpr, ""},
	} {
		if _, err := mesh.ConnectorInstallScript(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := mesh.ConnectorPreflightScript(run, model.RoleHub, "noble;id"); err == nil {
		t.Error("preflight accepted a bad codename")
	}
	pre, err := mesh.ConnectorPreflightScript(run, model.RoleHub, "noble")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"repo_unreachable", "unsupported_os", "unsupported_arch", "host_warp", "memory", "mesh_underlay()", "lookup 65743"} {
		if !strings.Contains(pre, want) {
			t.Errorf("connector preflight lacks %q", want)
		}
	}
	for _, bad := range []string{"apt-get install", "connector new", "> /etc", "rm -"} {
		if strings.Contains(pre, bad) {
			t.Errorf("connector preflight writes: %q", bad)
		}
	}
}

// The removal undoes exactly the marked resources, one marker at a time.
func TestConnectorRemoveScriptByMarkers(t *testing.T) {
	s, err := mesh.ConnectorRemoveScript(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"registration", "service", "package", "repo", "key"} {
		if !strings.Contains(s, "has "+m) {
			t.Errorf("no marker check for %s", m)
		}
	}
	for _, want := range []string{"registration delete", "apt-get purge -y cloudflare-warp", "MESH_RESTORE_ABSENT", "MESH_RESTORE_OK", "done_ "} {
		if !strings.Contains(s, want) {
			t.Errorf("remove script lacks %q", want)
		}
	}
	if _, err := mesh.ConnectorRemoveScript("bad"); err == nil {
		t.Error("bad run id accepted")
	}
	if got := mesh.ParseCreated("MESH_CREATED repo\nMESH_CREATED key\nMESH_CREATED evil\nMESH_CREATED package\n"); strings.Join(got, ",") != "key,repo,package" {
		t.Errorf("created %v", got)
	}
	if _, _, ok := mesh.ParseNodeAddr("MESH_NODE_ADDR CloudflareWARP 10.0.0.1/32\n"); ok {
		t.Error("address outside the Mesh range accepted")
	}
	if a, i, ok := mesh.ParseNodeAddr("MESH_NODE_ADDR CloudflareWARP 100.96.3.4/32\n"); !ok || a != "100.96.3.4" || i != "CloudflareWARP" {
		t.Error("address not parsed")
	}
}

// Single-end install with a failing install on one host: compensation
// removes what each host reported as created and the run's registrations,
// and never a reused node. The panel's detection hook is told about
// installed nodes only when the run succeeds.
func TestConnectorInstallFailureCompensates(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{fail: map[string]bool{"connector_install/us": true}}
	d := newDeployer(t, f, srv, rem)
	var detected []string
	d.HostDetected = func(det model.HostMeshDetection) error { detected = append(detected, det.NodeID); return nil }
	j, err := d.Deploy(context.Background(), meshPlan(t))
	var se *mesh.StageError
	if !errors.As(err, &se) || se.Stage != mesh.StageInstall || !se.Compensated {
		t.Fatalf("install failure: %v", err)
	}
	if j.State != mesh.StateFailed || len(f.nodes) != 0 || len(detected) != 0 {
		t.Fatalf("state %s nodes %d detected %v", j.State, len(f.nodes), detected)
	}
	if !rem.has("connector_remove/us") || rem.has("connector_install/v6-v4out") {
		t.Fatalf("calls %v", rem.calls)
	}
}

// Both ends installed, then the panel records them (panel-owned) and the
// withdrawal invalidates exactly those records.
func TestConnectorOwnershipHooks(t *testing.T) {
	f, srv := newFakeCF(t)
	rem := &fakeRemote{}
	d := newDeployer(t, f, srv, rem)
	got := map[string]model.HostMeshDetection{}
	var removed []string
	d.HostDetected = func(det model.HostMeshDetection) error { got[det.NodeID] = det; return nil }
	d.HostRemoved = func(id string) { removed = append(removed, id) }
	p := meshPlan(t)
	j, err := d.Deploy(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(p.Nodes) {
		t.Fatalf("detections %d", len(got))
	}
	for id, det := range got {
		if det.Origin != model.MeshOriginPanelHost || !det.PanelOwned || model.MeshHostOf(det) == nil || det.MeshAddr != rem.installed[id] {
			t.Fatalf("%s: %+v", id, det)
		}
		// ApplyOwnership keeps it panel-owned while the journal holds it,
		// and marks it stale once withdrawn.
		cp := det
		mesh.ApplyOwnership(&cp, j)
		if cp.Origin != model.MeshOriginPanelHost || !cp.PanelOwned {
			t.Fatalf("ownership lost: %+v", cp)
		}
	}
	j, err = d.Withdraw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(p.Nodes) {
		t.Fatalf("removed %v", removed)
	}
	for _, det := range got {
		mesh.ApplyOwnership(&det, j)
		if det.State != model.HostMeshFailed || det.Reusable || model.MeshHostOf(det) != nil {
			t.Fatalf("stale panel node still usable: %+v", det)
		}
	}
	// A node found on the host stays existing_host whatever the journal says.
	ex := reusable("hk-2", reuseAddr(1))
	mesh.ApplyOwnership(&ex, j)
	if ex.Origin != model.MeshOriginExisting || ex.PanelOwned {
		t.Fatalf("existing node: %+v", ex)
	}
}

// A legacy sidecar record: it can only be withdrawn (with the sidecar
// restore), and a new connector install on that host is refused until then.
func TestLegacySidecarRecordWithdrawOnly(t *testing.T) {
	d, cf, rem := lifecycleDeployer(t)
	p := legSubset(meshPlan(t), 1)
	first, err := d.Deploy(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the record as a deployment made with sidecars.
	rewrite(t, d, func(j *mesh.Journal) { j.Remotes[0].Kind = mesh.RemoteSidecar })
	q := legSubset(meshPlan(t), 2)
	if _, err := d.Deploy(context.Background(), q); !errors.Is(err, mesh.ErrBusy) || !strings.Contains(err.Error(), "先撤回") {
		t.Fatalf("install next to a legacy sidecar: %v", err)
	}
	if _, err := d.Withdraw(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !rem.has("restore/"+first.Remotes[0].NodeID) || len(cf.nodes) != 0 {
		t.Fatalf("legacy sidecar not restored: %v", rem.calls)
	}
	det := model.HostMeshDetection{NodeID: first.Remotes[0].NodeID, State: model.HostMeshNone}
	j := &mesh.Journal{Remotes: []mesh.OwnedRemote{{NodeID: det.NodeID, State: mesh.ResCreated}}}
	mesh.ApplyOwnership(&det, j)
	if det.Origin != model.MeshOriginPanel || !strings.Contains(strings.Join(det.Reasons, " "), "迁移") {
		t.Fatalf("legacy sidecar origin: %+v", det)
	}
}
