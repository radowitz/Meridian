package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/wsstest"
)

// wssScript builds node's provision script from cs's current WSS state and
// records nothing; it returns the script, the injected files and the plan.
func wssScript(t *testing.T, cs *credentials.Store, node, expect, key string) (string, map[string]string, wsstest.Material) {
	t.Helper()
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	rb, mat := wsstest.ResolveWith(t, cs, b)
	files := FilesFor(rb.Files, node)
	injected, err := InjectPrivateWSS(files, key, mat.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{NodeID: node, Deployment: "dep-1", ServerID: "srv-1", Bundle: preflight.BundleDigest(files), Run: "run-1", Expect: expect, Artifacts: fakeArtifacts(files)}
	return ScriptWith("test", injected, o), injected, mat
}

func recordAll(t *testing.T, cs *credentials.Store, node string, mat wsstest.Material) {
	t.Helper()
	var ps []credentials.WSSPartyStage
	for _, p := range mat.Plan.ForNode(node) {
		ps = append(ps, credentials.WSSPartyStage{ListenerID: p.ListenerID, Party: p.Party, NodeID: p.NodeID, Stage: p.Stage})
	}
	if err := cs.RecordWSSInstall(node, ps, true, false, ""); err != nil {
		t.Fatal(err)
	}
}

func mode(t *testing.T, sb *sandbox, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(filepath.Join(sb.root, p))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The WSS files of a listener and a client: secret files 0600 in a 0700
// directory, certificates 0644; the manifest records them (hashes only);
// changed WSS files restart exactly their unit; a failed run puts the old
// files back and restarts the unit it restarted on them; a withdraw
// removes them and the directory.
func TestProvisionWSSFilesRestartAndCompensation(t *testing.T) {
	sb := newSandbox(t)
	topo := defaults.Example()
	cs := wsstest.Store(t, topo)
	kp, _ := GenerateKeypair()
	// systemctl: every unit is active; the next restart of the server unit
	// fails once when $SANDBOX/fail-srv exists.
	sys := "#!/bin/bash\necho \"systemctl $*\" >> \"$SANDBOX/calls.log\"\n" +
		"case \"$*\" in *nftables*|*smartdns*) [ \"$1\" = is-enabled ] || [ \"$1\" = is-active ] && exit 1 ;; esac\n" +
		"if [ \"$1\" = is-active ]; then echo active; exit 0; fi\n" +
		"if [ \"$1\" = is-enabled ]; then echo enabled; exit 0; fi\n" +
		"if [ \"$1\" = restart ] && [ \"$2\" = wstunnel-meridian.service ] && [ -f \"$SANDBOX/fail-srv\" ]; then rm -f \"$SANDBOX/fail-srv\"; exit 1; fi\nexit 0\n"
	os.WriteFile(filepath.Join(sb.bin, "systemctl"), []byte(sys), 0o755)

	script, files, mat := wssScript(t, cs, "ali", "none", kp.Private)
	out, code := sb.run(script)
	if code != 0 || !strings.Contains(out, "MERIDIAN_PROVISION_OK") {
		t.Fatalf("install %d %s", code, out)
	}
	if m := mode(t, sb, "/etc/meridian/wss"); m != 0o700 {
		t.Fatalf("wss dir %o", m)
	}
	for p, want := range map[string]os.FileMode{
		"/etc/meridian/wss/server.yaml": 0o600, "/etc/meridian/wss/server.key": 0o600, "/etc/meridian/wss/client-ali-hub-wss.env": 0o600,
		"/etc/meridian/wss/server.crt": 0o644, "/etc/meridian/wss/client-ali-hub-wss.trust.pem": 0o644,
	} {
		if got := mode(t, sb, p); got != want {
			t.Fatalf("%s mode %o, want %o", p, got, want)
		}
		if sb.read(p) != files[p] {
			t.Fatalf("%s content", p)
		}
	}
	calls := sb.read("/calls.log")
	if !strings.Contains(calls, "systemctl restart wstunnel-meridian.service") || !strings.Contains(calls, "systemctl restart wstunnel-client-ali-hub-wss.service") {
		t.Fatalf("new WSS units not (re)started:\n%s", calls)
	}
	man := sb.read("/var/lib/meridian/node/manifest")
	for _, p := range []string{"server.yaml", "server.key", "server.crt", "client-ali-hub-wss.env", "client-ali-hub-wss.trust.pem"} {
		if !strings.Contains(man, "file "+sb.root+"/etc/meridian/wss/"+p+" ") && !strings.Contains(man, "file /etc/meridian/wss/"+p+" ") {
			t.Fatalf("manifest lacks %s:\n%s", p, man)
		}
	}
	for id, v := range mat.Secrets {
		for _, line := range strings.Split(v, "\n") {
			if len(line) >= 16 && strings.Contains(man, line) {
				t.Fatalf("secret %s in the manifest", id)
			}
		}
	}
	recordAll(t, cs, "ali", mat)

	// A path rotation of ali's own client link: only the client's files
	// change, only the client unit restarts.
	if _, err := cs.RegenerateWSSPath("ali-hub-wss"); err != nil {
		t.Fatal(err)
	}
	upd, files2, mat2 := wssScript(t, cs, "ali", "same", kp.Private)
	os.Remove(filepath.Join(sb.root, "calls.log"))
	out, code = sb.run(upd)
	if code != 0 || !strings.Contains(out, "MERIDIAN_WSS_RESTARTED wstunnel-client-ali-hub-wss.service") {
		t.Fatalf("update %d %s", code, out)
	}
	calls = sb.read("/calls.log")
	if strings.Contains(calls, "restart wstunnel-meridian.service") {
		t.Fatalf("the server restarted although its files did not change:\n%s", calls)
	}
	if sb.read("/etc/meridian/wss/client-ali-hub-wss.env") != files2["/etc/meridian/wss/client-ali-hub-wss.env"] || files2["/etc/meridian/wss/client-ali-hub-wss.env"] == files["/etc/meridian/wss/client-ali-hub-wss.env"] {
		t.Fatal("new prefix not installed")
	}
	recordAll(t, cs, "ali", mat2)

	// A certificate rotation whose server restart fails: compensated, the
	// old certificate and key are back and the server unit is restarted on
	// them; the panel records the failure (stage unchanged).
	if _, err := cs.RegenerateWSSCert("ali", "manual_cert"); err != nil {
		t.Fatal(err)
	}
	// Move the client of gw-ali to stage 1 so the server may present the
	// new certificate (stage 2).
	cs.RecordWSSInstall("gw", []credentials.WSSPartyStage{{ListenerID: "ali", Party: "client:gw-ali", NodeID: "gw", Stage: 1}}, true, false, "")
	before := sb.read("/etc/meridian/wss/server.crt")
	bad, files3, _ := wssScript(t, cs, "ali", "same", kp.Private)
	if files3["/etc/meridian/wss/server.crt"] == before {
		t.Fatal("setup: the server certificate should change at stage 2")
	}
	os.WriteFile(filepath.Join(sb.root, "fail-srv"), nil, 0o644)
	os.Remove(filepath.Join(sb.root, "calls.log"))
	out, code = sb.run(bad)
	if code == 0 || !strings.Contains(out, "MERIDIAN_COMPENSATED") {
		t.Fatalf("failed update %d %s", code, out)
	}
	if sb.read("/etc/meridian/wss/server.crt") != before || sb.read("/etc/meridian/wss/server.key") != files2["/etc/meridian/wss/server.key"] {
		t.Fatal("old certificate and key not restored")
	}
	if n := strings.Count(sb.read("/calls.log"), "systemctl restart wstunnel-meridian.service"); n < 2 {
		t.Fatalf("server unit not restarted on the restored files:\n%s\n%s", sb.read("/calls.log"), out)
	}
	os.Remove(filepath.Join(sb.root, "fail-srv"))

	// Withdraw removes the WSS files and the directory.
	sb.hostPaths("/var/lib/meridian/node/manifest")
	withdrawStubs(t, sb)
	p := plan(t, sb, wopts("ali", WithdrawManifest, WithdrawPlan, ""))
	wout, wcode := sb.runRaw(WithdrawScript(wopts("ali", WithdrawManifest, WithdrawRun, p.Digest)))
	if wcode != 0 {
		t.Fatalf("withdraw %d %s", wcode, wout)
	}
	if sb.exists("/etc/meridian/wss/server.key") || sb.exists("/etc/meridian/wss/client-ali-hub-wss.env") || sb.exists("/etc/meridian/wss") {
		t.Fatalf("WSS files left after withdraw:\n%s", wout)
	}
}
