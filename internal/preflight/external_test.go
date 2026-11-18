package preflight

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func findCode(ev Evaluation, code string) *Finding {
	for i := range ev.Findings {
		if ev.Findings[i].Code == code {
			return &ev.Findings[i]
		}
	}
	return nil
}

// The carrier's preflight checks the external exit's interface, its route
// and one TCP connect to the proxy, read-only.
func TestExternalProxyChecks(t *testing.T) {
	fp := Footprint{External: []ExternalPlan{{ID: "myext", SOCKS: netip.MustParseAddr("198.51.100.66"), Port: 1080, Iface: "wg9"}}}
	if p := fp.PreflightProbes(); len(p) != 1 || p[0] != "tcp4:198.51.100.66:1080" {
		t.Fatalf("probes %v", p)
	}
	base := func() Report {
		r := newReport()
		r.Complete = true
		r.Links = []string{"lo", "eth0", "wg9"}
		r.Routes = []Route{
			{Family: 4, Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0"},
			{Family: 4, Dst: netip.MustParsePrefix("198.51.100.64/30"), Dev: "wg9"},
		}
		r.TCPConnect = map[string]bool{"198.51.100.66:1080": true}
		return r
	}
	ctx := Context{NodeID: "dc2"}
	if f := findCode(Evaluate(base(), fp, ctx), CodeExternal); f == nil || f.Severity != Info {
		t.Fatalf("healthy carrier: %+v", f)
	}
	r := base()
	r.Links = []string{"lo", "eth0"}
	if f := findCode(Evaluate(r, fp, ctx), CodeExternalIface); f == nil || f.Severity != Blocking {
		t.Fatalf("missing interface: %+v", f)
	}
	r = base()
	r.Routes = r.Routes[:1] // only the default route: it would leave over eth0
	if f := findCode(Evaluate(r, fp, ctx), CodeExternalIface); f == nil || f.Severity != Blocking || !strings.Contains(f.Message, "eth0") {
		t.Fatalf("route via the WAN: %+v", f)
	}
	r = base()
	r.TCPConnect["198.51.100.66:1080"] = false
	if f := findCode(Evaluate(r, fp, ctx), CodeExternalProxy); f == nil || f.Severity != Blocking {
		t.Fatalf("proxy unreachable: %+v", f)
	}
	// The report line is parsed; a malformed one is ignored.
	rep := Parse("meridian-preflight 1\ntcpconnect 198.51.100.66 1080 ok\ntcpconnect 198.51.100.67 x ok\nmeridian-preflight-end\n")
	if len(rep.TCPConnect) != 1 || !rep.TCPConnect["198.51.100.66:1080"] {
		t.Fatalf("parsed %v", rep.TCPConnect)
	}
	// Probe arguments are strictly shaped.
	for _, bad := range []string{"tcp4:198.51.100.66", "tcp4:198.51.100.66:0", "tcp4:host:80", "tcp4:198.51.100.66:80;id", "tcp6:[::1]:80"} {
		if ValidProbe(bad) {
			t.Errorf("probe %q accepted", bad)
		}
	}
	if _, err := ArgsWithProbes(nil, []string{"tcp4:198.51.100.66:1080;rm"}); err == nil {
		t.Error("bad probe passed ArgsWithProbes")
	}
}

// deployedCarrier is a carrier whose own install record (manifest of this
// node, deployment and server; meridian-up.sh unchanged since the install)
// shows external exit myext with the proxy at 198.51.100.66:1080 via wg9, while
// the proxy does not answer right now.
func deployedCarrier() (Report, Footprint, Context) {
	const upHash = "1111111111111111111111111111111111111111111111111111111111111111"
	fp := Footprint{
		Files:    []string{upScript},
		External: []ExternalPlan{{ID: "myext", SOCKS: netip.MustParseAddr("198.51.100.66"), Port: 1080, Iface: "wg9"}},
	}
	r := newReport()
	r.Complete = true
	r.Links = []string{"lo", "eth0", "wg9"}
	r.Routes = []Route{
		{Family: 4, Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0"},
		{Family: 4, Dst: netip.MustParsePrefix("198.51.100.64/30"), Dev: "wg9"},
	}
	r.TCPConnect = map[string]bool{"198.51.100.66:1080": false}
	r.Manifest = &NodeManifest{Node: "dc2", Deployment: "dep-1", Server: "srv-1", Files: map[string]string{upScript: upHash}}
	r.Journal = &NodeJournal{State: "done"}
	r.Paths[upScript] = PathInfo{Exists: true, Type: "file", Marker: true, SHA256: upHash}
	r.ExtInstalled = []ExternalPlan{{ID: "myext", SOCKS: netip.MustParseAddr("198.51.100.66"), Port: 1080, Iface: "wg9"}}
	return r, fp, Context{NodeID: "dc2", Deployment: "dep-1", Server: "srv-1"}
}

// An unreachable external proxy blocks only a first enable of that
// external exit (or of a changed proxy configuration of it); when the
// host's own trusted record shows exactly that external exit deployed, it
// is a warning that names what is affected. Nothing but the host's record
// can downgrade it.
func TestExternalProxyUnreachableByInstallIdentity(t *testing.T) {
	proxy := func(r Report, fp Footprint, ctx Context) *Finding {
		t.Helper()
		f := findCode(Evaluate(r, fp, ctx), CodeExternalProxy)
		if f == nil {
			t.Fatal("no external_proxy_unreachable finding")
		}
		return f
	}

	// Already deployed, same configuration: a warning, scoped to that exit.
	r, fp, ctx := deployedCarrier()
	ev := Evaluate(r, fp, ctx)
	f := findCode(ev, CodeExternalProxy)
	if f == nil || f.Severity != Warning {
		t.Fatalf("deployed external exit: %+v", f)
	}
	for _, want := range []string{"198.51.100.66:1080", "只有经外部出口 myext 的流量受影响", "既不会造成也不能修复", "已经是同一个外部出口 myext"} {
		if !strings.Contains(f.Message, want) {
			t.Fatalf("warning lacks %q: %s", want, f.Message)
		}
	}
	if !strings.Contains(f.Action, "可以继续安装") {
		t.Fatalf("action %q", f.Action)
	}
	for _, x := range ev.Findings {
		if x.Severity == Blocking && (x.Code == CodeExternalProxy || x.Code == CodeExternalIface) {
			t.Fatalf("the external exit still blocks: %+v", x)
		}
	}

	cases := []struct {
		name string
		edit func(r *Report, fp *Footprint, ctx *Context)
		want string
	}{
		{"first enable: no manifest at all", func(r *Report, _ *Footprint, _ *Context) { r.Manifest, r.Journal = nil, nil }, "没有本面板为这个节点和部署写下的安装清单"},
		{"first enable: installed config has no such exit", func(r *Report, _ *Footprint, _ *Context) { r.ExtInstalled = nil }, "还没有这个外部出口"},
		{"another external exit is deployed, not this one", func(r *Report, _ *Footprint, _ *Context) { r.ExtInstalled[0].ID = "my2" }, "还没有这个外部出口"},
		{"proxy port changed in this change", func(r *Report, _ *Footprint, _ *Context) { r.ExtInstalled[0].Port = 1081 }, "新的代理配置"},
		{"proxy address changed in this change", func(r *Report, _ *Footprint, _ *Context) {
			r.ExtInstalled[0].SOCKS = netip.MustParseAddr("198.51.100.65")
		}, "新的代理配置"},
		{"carrier interface changed in this change", func(r *Report, _ *Footprint, _ *Context) { r.ExtInstalled[0].Iface = "wg8" }, "新的代理配置"},
		{"manifest unreadable", func(r *Report, _ *Footprint, _ *Context) { r.Manifest.Node = "" }, "没有本面板为这个节点和部署写下的安装清单"},
		{"manifest of another deployment", func(r *Report, _ *Footprint, _ *Context) { r.Manifest.Deployment = "dep-other" }, "没有本面板为这个节点和部署写下的安装清单"},
		{"manifest of another server", func(r *Report, _ *Footprint, _ *Context) { r.Manifest.Server = "srv-2" }, "没有记录这台服务器"},
		{"server not known to the evaluation", func(_ *Report, _ *Footprint, ctx *Context) { ctx.Server = "" }, "没有记录这台服务器"},
		{"last run not finished", func(r *Report, _ *Footprint, _ *Context) { r.Journal.State = "running" }, "没有正常完成"},
		{"meridian-up.sh changed since the install", func(r *Report, _ *Footprint, _ *Context) {
			r.Paths[upScript] = PathInfo{Exists: true, Type: "file", SHA256: strings.Repeat("2", 64)}
		}, "无法与安装清单的哈希对上"},
		{"meridian-up.sh not hashed by the manifest", func(r *Report, _ *Footprint, _ *Context) { r.Manifest.Files = map[string]string{} }, "无法与安装清单的哈希对上"},
		{"meridian-up.sh missing on the host", func(r *Report, _ *Footprint, _ *Context) { r.Paths[upScript] = PathInfo{} }, "无法与安装清单的哈希对上"},
	}
	for _, c := range cases {
		r, fp, ctx := deployedCarrier()
		c.edit(&r, &fp, &ctx)
		f := proxy(r, fp, ctx)
		if f.Severity != Blocking || !strings.Contains(f.Message, c.want) || !strings.Contains(f.Message, "首次启用") {
			t.Errorf("%s: %s %s", c.name, f.Severity, f.Message)
		}
	}

	// A reachable proxy stays info; a missing probe result stays a warning,
	// whatever the record says.
	r, fp, ctx = deployedCarrier()
	r.TCPConnect["198.51.100.66:1080"] = true
	if f := findCode(Evaluate(r, fp, ctx), CodeExternal); f == nil || f.Severity != Info {
		t.Fatalf("reachable: %+v", f)
	}
	r, fp, ctx = deployedCarrier()
	r.Manifest, r.Journal = nil, nil
	delete(r.TCPConnect, "198.51.100.66:1080")
	if f := proxy(r, fp, ctx); f.Severity != Warning || !strings.Contains(f.Message, "没有报告") {
		t.Fatalf("no probe result: %+v", f)
	}
}

// The installed markers come from the preflight's own report lines; a
// malformed one is ignored. The script extracts them from the installed
// meridian-up.sh only.
func TestExtInstalledReportLines(t *testing.T) {
	rep := Parse("meridian-preflight 1\n" +
		"extinstalled myext 198.51.100.66 1080 wg9\n" +
		"extinstalled MY1 198.51.100.66 1080 wg9\n" +
		"extinstalled my2 2001:db8::1 1080 wg9\n" +
		"extinstalled my3 198.51.100.67 0 wg9\n" +
		"extinstalled my4 198.51.100.68 1080 wg9;id\n" +
		"meridian-preflight-end\n")
	if len(rep.ExtInstalled) != 1 || rep.ExtInstalled[0] != (ExternalPlan{ID: "myext", SOCKS: netip.MustParseAddr("198.51.100.66"), Port: 1080, Iface: "wg9"}) {
		t.Fatalf("parsed %+v", rep.ExtInstalled)
	}
	s := Script()
	var line string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "^# meridian-ext: ") {
			line = l
		}
	}
	if line == "" || !strings.Contains(s, `[ "$p" = /usr/local/sbin/meridian-up.sh ]`) {
		t.Fatal("the script does not read the installed markers of meridian-up.sh")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		return
	}
	// The extraction itself, on a stand-in file with the compiled marker
	// format (compile.extMarker) and lines that must not match.
	f := filepath.Join(t.TempDir(), "meridian-up.sh")
	body := "#!/bin/bash\n# meridian-ext: myext socks=198.51.100.66:1080 iface=wg9\n#  meridian-ext: my2 socks=198.51.100.67:1080 iface=wg9\necho '# meridian-ext: my3 socks=198.51.100.68:1080 iface=wg9'\n# meridian-ext: my4 socks=198.51.100.69:1080 iface=wg9;id\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", strings.ReplaceAll(line, `"$p"`, `"$1"`), "x", f)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if string(out) != "extinstalled myext 198.51.100.66 1080 wg9\n" {
		t.Fatalf("extracted %q", out)
	}
}
