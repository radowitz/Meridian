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
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/linkjournal"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/pathquality"
)

func gatewayID(t *testing.T, topo model.Topology) string {
	t.Helper()
	gw, ok := gatewayNode(topo)
	if !ok {
		t.Fatal("no gateway")
	}
	return gw.ID
}

func linkConfigOf(t *testing.T, b *Bundle, gw string) linkjournal.Config {
	t.Helper()
	c, err := linkjournal.ParseConfig([]byte(b.File("nodes/" + gw + "/" + strings.TrimPrefix(LinkJournalConfigPath, "/"))))
	if err != nil {
		t.Fatalf("the compiled object list is refused by the collector: %v", err)
	}
	return c
}

// Every gateway gets the collector's unit and its object list, nothing else
// of the gateway refers to them, and no other node gets anything. The
// object list names exactly the gateway's own tunnel interfaces and
// wstunnel client units, and records the carrying path the way the
// topology's failover does.
func TestLinkJournalFiles(t *testing.T) {
	for name, base := range sniffTopologies(t) {
		for _, sniffed := range []bool{false, true} {
			topo := base
			if sniffed {
				topo = sniffOn(topo)
			}
			b := mustCompile(t, topo)
			gw := gatewayID(t, topo)
			pre := "nodes/" + gw + "/"
			unit := b.File(pre + "etc/systemd/system/" + LinkJournalUnit)
			if unit == "" || unit != strings.TrimRight(RenderLinkJournalUnit(gatewayLinkJournalSpec()), "\n")+"\n" {
				t.Fatalf("%s: the gateway's collector unit is missing or not the rendered one", name)
			}
			c := linkConfigOf(t, b, gw)
			// Nothing else on the gateway mentions the collector (the verify
			// script checks it), and no other node has anything of it.
			for p, body := range b.Files {
				mentions := strings.Contains(body, "link-journal") || strings.Contains(body, "linklog") || strings.Contains(p, "link-journal")
				switch {
				case p == pre+"etc/systemd/system/"+LinkJournalUnit, p == pre+strings.TrimPrefix(LinkJournalConfigPath, "/"), p == pre+"usr/local/sbin/meridian-verify.sh":
					if !mentions {
						t.Errorf("%s: %s does not carry the link journal", name, p)
					}
				case mentions:
					t.Errorf("%s: %s mentions the link journal", name, p)
				}
			}
			// Tunnels: exactly the gateway's WireGuard interfaces, without mra.
			var want, got []string
			for p := range b.Files {
				if strings.HasPrefix(p, pre+"etc/wireguard/") {
					if i := strings.TrimSuffix(filepath.Base(p), ".conf"); i != "mra" {
						want = append(want, i)
					}
				}
			}
			for _, tun := range c.Tunnels {
				got = append(got, tun.Iface)
				conf := b.File(pre + "etc/wireguard/" + tun.Iface + ".conf")
				if !strings.Contains(conf, "# meridian link "+tun.Link+" mode "+tun.Mode+" ") || !strings.Contains(conf, "# peer-node "+tun.Peer+"\n") {
					t.Errorf("%s: tunnel %+v does not match its WireGuard file", name, tun)
				}
				// keepalive_s is what keeps the handshake fresh: it is in the
				// gateway's file whenever the gateway dials.
				if strings.Contains(conf, "PersistentKeepalive = ") != (tun.KeepaliveS > 0) && strings.Contains(conf, "Endpoint = ") {
					t.Errorf("%s: tunnel %s keepalive_s %d does not match its WireGuard file", name, tun.Iface, tun.KeepaliveS)
				}
				if !hostexec.ValidInterface(tun.Iface) {
					t.Errorf("%s: %s is not a managed interface", name, tun.Iface)
				}
			}
			sort.Strings(want)
			sort.Strings(got)
			if strings.Join(want, " ") != strings.Join(got, " ") || len(got) == 0 {
				t.Errorf("%s: tunnels %v, the gateway's WireGuard files are %v", name, got, want)
			}
			// WSS carriers: exactly the gateway's wstunnel client units.
			want, got = nil, nil
			for p := range b.Files {
				if u := filepath.Base(p); strings.HasPrefix(p, pre+"etc/systemd/system/wstunnel-client-") {
					want = append(want, u)
				}
			}
			for _, w := range c.WSS {
				got = append(got, w.Unit)
				if w.Unit != WSSClientUnit(w.Link) || !hostexec.ValidUnit(w.Unit) || !hasTunnel(c, w.Iface) {
					t.Errorf("%s: WSS carrier %+v", name, w)
				}
			}
			sort.Strings(want)
			sort.Strings(got)
			if strings.Join(want, " ") != strings.Join(got, " ") {
				t.Errorf("%s: WSS units %v, the gateway's unit files are %v", name, got, want)
			}
			// The carrying path is recorded the way this topology's failover
			// records it.
			failover := b.File(pre + "usr/local/sbin/meridian-failover.sh")
			for _, p := range c.Paths {
				if !hasTunnel(c, p.Iface) {
					t.Errorf("%s: path %+v is not one of the gateway's tunnels", name, p)
				}
			}
			switch {
			case topo.RelaySharing():
				if c.Mode != linkjournal.ModeShare || !strings.Contains(failover, "path-step") {
					t.Fatalf("%s: mode %s", name, c.Mode)
				}
				// The relay ids are the controller's (path-quality.json).
				pq := b.File(pre + strings.TrimPrefix(SharePathConfig, "/"))
				for _, p := range c.Paths {
					if p.Name == "relay" && !strings.Contains(pq, `"id": "`+p.Peer+`"`) {
						t.Errorf("%s: relay %s is not in the controller's config", name, p.Peer)
					}
					if p.Name == "relay" && !strings.Contains(pq, `"iface": "`+p.Iface+`"`) {
						t.Errorf("%s: leg %s is not in the controller's config", name, p.Iface)
					}
				}
			case topo.DualHub():
				if c.Mode != linkjournal.ModeDual {
					t.Fatalf("%s: mode %s", name, c.Mode)
				}
				m := regexp.MustCompile(`(?m)^UP_NAME=\((.*)\)$`).FindStringSubmatch(failover)
				mi := regexp.MustCompile(`(?m)^UP_IFACE=\((.*)\)$`).FindStringSubmatch(failover)
				if m == nil || mi == nil {
					t.Fatalf("%s: no UP_NAME in the failover script", name)
				}
				var names, ifaces []string
				for _, p := range c.Paths {
					names, ifaces = append(names, shQuote(p.Name)), append(ifaces, shQuote(p.Iface))
				}
				if strings.Join(names, " ") != m[1] || strings.Join(ifaces, " ") != mi[1] {
					t.Errorf("%s: paths %v %v, the failover script has %s %s", name, names, ifaces, m[1], mi[1])
				}
			default:
				if c.Mode != linkjournal.ModeSingle {
					t.Fatalf("%s: mode %s", name, c.Mode)
				}
				for _, p := range c.Paths {
					if !strings.Contains(failover, `"`+p.Iface+`"`) {
						t.Errorf("%s: path %+v is not a leg of the failover script", name, p)
					}
				}
				if len(c.Paths) == 0 || !strings.Contains(failover, "table 102") || linkjournal.ForeignTable != 102 {
					t.Errorf("%s: no path, or the foreign table moved", name)
				}
			}
			// Self-check targets: only with the forwarder; every target the
			// forwarder checks has a name in the list, and an external exit
			// is marked with its carrier.
			if (c.Sniff != nil) != sniffed {
				t.Fatalf("%s: sniff section %v with sniff %v", name, c.Sniff != nil, sniffed)
			}
			if sniffed {
				named := map[string]linkjournal.SniffTarget{}
				for _, tg := range c.Sniff.Targets {
					named[tg.Target] = tg
				}
				exits, groups := plans(t, topo)
				for _, tg := range planSniff(topo, exits, groups, nil).Targets {
					if _, ok := named[tg.Name]; !ok && !tg.Reject {
						t.Errorf("%s: self-check target %s has no name in the object list", name, tg.Name)
					}
				}
				for _, e := range exits {
					tg := named["exit:"+e.Node.ID]
					if tg.External != e.External || (e.External && tg.Carrier != model.HubSideOf(e.Node)) {
						t.Errorf("%s: exit %s: %+v", name, e.Node.ID, tg)
					}
				}
			}
		}
	}
}

func hasTunnel(c linkjournal.Config, iface string) bool {
	for _, t := range c.Tunnels {
		if t.Iface == iface {
			return true
		}
	}
	return false
}

// An unlock decision moves rules between exits; the object list does not
// follow it (it is not one of DecisionFiles), so the automatic install of a
// decision is never refused because of the link journal.
func TestLinkJournalConfigIgnoresDecisions(t *testing.T) {
	topo := sniffOn(sniffTopologies(t)["example"])
	_, groups := plans(t, topo)
	dec := map[string]string{}
	for _, gp := range groups {
		if gp.Group.Mode != model.GroupAuto || len(gp.Selection.Order) < 2 {
			continue
		}
		for _, r := range topo.Rules {
			if r.Enabled && r.TargetGroup == gp.Group.ID {
				dec[r.ID] = gp.Selection.Order[1]
			}
		}
	}
	if len(dec) == 0 {
		t.Fatal("no decision to make in this topology")
	}
	gw := gatewayID(t, topo)
	p := "nodes/" + gw + "/" + strings.TrimPrefix(LinkJournalConfigPath, "/")
	a, b := compileDec(t, topo, nil), compileDec(t, topo, dec)
	if a.File(p) != b.File(p) {
		t.Fatal("a decision changed the object list")
	}
	if a.File("nodes/"+gw+"/"+strings.TrimPrefix(SniffTargetsPath, "/")) == b.File("nodes/"+gw+"/"+strings.TrimPrefix(SniffTargetsPath, "/")) {
		t.Fatal("the decision did not change the forwarder's targets: the test proves nothing")
	}
	for _, f := range DecisionFiles {
		if strings.Contains(f, "link-journal") {
			t.Fatal("the object list must not be a decision file")
		}
	}
	// What the panel says about it does follow the decision.
	before, err := LinkJournalFor(topo, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := LinkJournalFor(topo, dec)
	if err != nil {
		t.Fatal(err)
	}
	observed := func(info LinkJournalInfo) string {
		var s []string
		for _, o := range info.Objects {
			if o.Kind == linkjournal.KindTarget && o.Observed {
				s = append(s, o.ID)
			}
		}
		return strings.Join(s, " ")
	}
	if observed(before) == observed(after) || observed(before) == "" {
		t.Fatalf("observed targets before %q, after %q", observed(before), observed(after))
	}
}

// What the panel says about external exits: observed only when the
// forwarder has a target of its own for the exit.
func TestLinkJournalExternals(t *testing.T) {
	topo := defaults.ExternalExample()
	model.MigrateRegionGroups(&topo)
	var ext model.Node
	for _, n := range topo.Nodes {
		if model.IsExternal(n) {
			ext = n
		}
	}
	if ext.ID == "" {
		t.Fatal("the external example has no external exit")
	}
	info, err := LinkJournalFor(topo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Externals) != 1 || info.Externals[0].ID != ext.ID || info.Externals[0].Observed || !strings.Contains(info.Externals[0].Note, "嗅探没有开启") || info.Externals[0].Carrier != model.HubSideOf(ext) {
		t.Fatalf("without the forwarder: %+v", info.Externals)
	}
	on := sniffOn(topo)
	info, err = LinkJournalFor(on, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Externals[0].Observed || !strings.Contains(info.Externals[0].Note, "不单独检查") {
		t.Fatalf("a member of a group only: %+v", info.Externals[0])
	}
	for _, o := range info.Objects {
		if o.Kind == linkjournal.KindExternal && (o.Observed || o.ID != ext.ID || o.Note == "") {
			t.Fatalf("%+v", o)
		}
	}
	// A rule pinned to the exit gives the forwarder a target for it.
	on.Rules = append(on.Rules, model.Rule{ID: "pin-ext", Name: "pin", Enabled: true, MatchType: model.MatchSuffix, MatchValue: "pin.example.net", TargetExit: ext.ID, Priority: 3})
	info, err = LinkJournalFor(on, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Externals[0].Observed || !strings.Contains(info.Externals[0].Note, "网关自检") {
		t.Fatalf("pinned: %+v", info.Externals[0])
	}
	var found bool
	for _, o := range info.Objects {
		if o.Kind == linkjournal.KindExternal && o.ID == ext.ID {
			found = o.Observed && o.Class == linkjournal.ClassExternalExit && strings.Contains(o.Label, "由 "+model.HubSideOf(ext)+" 承载")
		}
	}
	if !found {
		t.Fatalf("the pinned external exit is not an observed object: %+v", info.Objects)
	}
}

// The unit: root with CAP_NET_ADMIN only, no IP sockets, its own state
// directory, low priority; the fixed places agree across packages.
func TestLinkJournalUnit(t *testing.T) {
	u := RenderLinkJournalUnit(gatewayLinkJournalSpec())
	for _, want := range []string{
		"ExecStartPre=/bin/grep -q " + linkjournal.ReadyMarker + " /usr/local/bin/meridian\n",
		"ExecStart=/usr/local/bin/meridian link-journal --config " + linkjournal.ConfigPath + " --dir " + linkjournal.StateDir + " --status-socket " + linkjournal.StatusSocket + "\n",
		"User=root\n", "CapabilityBoundingSet=CAP_NET_ADMIN\n", "AmbientCapabilities=\n", "NoNewPrivileges=yes\n",
		"StateDirectory=" + linkjournal.StateDirName + "\n", "StateDirectoryMode=0700\n", "RuntimeDirectory=" + linkjournal.RuntimeDirName + "\n", "RuntimeDirectoryMode=0755\n",
		"ProtectSystem=strict\n", "ProtectHome=yes\n", "PrivateTmp=yes\n", "PrivateDevices=yes\n", "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n", "IPAddressDeny=any\n",
		"UMask=0077\n", "Nice=10\n", "CPUWeight=20\n", "IOSchedulingClass=idle\n", "MemoryMax=96M\n", "Restart=always\n", "WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	var directives []string
	for _, l := range strings.Split(u, "\n") {
		if !strings.HasPrefix(l, "#") {
			directives = append(directives, l)
		}
	}
	for _, never := range []string{"AF_INET", "ReadWritePaths", "CAP_SYS", "CAP_DAC", "ExecStop", "/bin/sh", "bash"} {
		if strings.Contains(strings.Join(directives, "\n"), never) {
			t.Errorf("unit contains %q", never)
		}
	}
	// It is not ordered against, and does not pull in, anything that carries
	// traffic.
	for _, l := range strings.Split(u, "\n") {
		for _, dep := range []string{"Requires=", "Wants=", "BindsTo=", "PartOf=", "Before=", "Conflicts="} {
			if strings.HasPrefix(l, dep) {
				t.Errorf("unit has a dependency: %s", l)
			}
		}
	}
	if !hostexec.ValidUnit(LinkJournalUnit) || LinkJournalUnit != hostexec.LinkJournalUnit {
		t.Fatal("the unit is not one the host agent accepts")
	}
	for _, pair := range [][2]string{{linkjournal.UpstreamFile, UpstreamStateFile}, {linkjournal.UpstreamFile, pathquality.StatusPath}, {linkjournal.SniffSocket, SniffStatusSocket}} {
		if pair[0] != pair[1] {
			t.Fatalf("the collector reads %s, the gateway's files write %s", pair[0], pair[1])
		}
	}
	if gatewayLinkJournalSpec().StatusSocket() != linkjournal.StatusSocket || "/var/lib/"+gatewayLinkJournalSpec().StateDir != linkjournal.StateDir {
		t.Fatal("the unit's directories are not the collector's")
	}
	// The binary carries the marker the unit greps for.
	if !strings.Contains(repoFile(t, "internal/linkjournal/journal.go"), `ReadyMarker = "`+linkjournal.ReadyMarker+`"`) || !strings.Contains(repoFile(t, "cmd/meridian/main.go"), `"link-journal"`) {
		t.Fatal("the binary has no link-journal subcommand or marker")
	}
	// The collector accepts every object list a topology can compile to:
	// a refused list would keep its unit from starting.
	if linkjournal.MaxTunnels < 2*model.MaxLinkSlots || linkjournal.MaxPaths < 2*model.MaxLinkSlots || linkjournal.MaxWSS < model.MaxLinkSlots ||
		linkjournal.MaxTargets < model.MaxMarkSlots+1 {
		t.Fatalf("the object list's limits (%d tunnels, %d paths, %d WSS, %d targets) are below what a topology can hold", linkjournal.MaxTunnels, linkjournal.MaxPaths, linkjournal.MaxWSS, linkjournal.MaxTargets)
	}
	// The install writes the object list where it may (etc/meridian) and
	// derives the unit from its file.
	if !strings.HasPrefix(LinkJournalConfigPath, "/etc/meridian/") {
		t.Fatal(LinkJournalConfigPath)
	}
}

// The verify script's block: a WARN when the collector is not running,
// never a failed check; nothing without systemctl.
func TestLinkJournalVerifyScript(t *testing.T) {
	topo := defaults.Example()
	b := mustCompile(t, topo)
	script := b.File("nodes/gw/usr/local/sbin/meridian-verify.sh")
	for _, want := range []string{"link_log_collector", "link_log_config", "link_log_dir", "link_log_budget", "link_log_status_socket", "netns_link_journal", "link_log_real_events",
		`linklog_dir="$root"` + linkjournal.StateDir, "-le 16384", "'^TestNetnsLinkJournal'", linkjournal.StatusSocket} {
		if !strings.Contains(script, want) {
			t.Errorf("verify script misses %q", want)
		}
	}
	if strings.Index(script, "link_log_collector") > strings.Index(script, `emit "evidence: $evdir"`) {
		t.Fatal("the block is after the script's end")
	}
	// No "fail" in the block: the collector records, it carries nothing.
	if strings.Contains(linkLogVerifyBlock, "\n  fail ") || strings.Contains(linkLogVerifyBlock, " fail link_log") || strings.Contains(linkLogVerifyBlock, "unknown link_log") {
		t.Fatal("a link journal problem must be a WARN, not a failed or unknown check")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	f := filepath.Join(t.TempDir(), "verify.sh")
	if err := os.WriteFile(f, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
	base := func() verifyHost { return goodHost(t, b, topo) }
	runVerifyCases(t, script, base, []verifyCase{
		{name: "no systemctl", wantCode: 0, want: []string{"local-ok", "NOT-RUN-HERE netns_link_journal", "PENDING-HUMAN link_log_real_events"},
			forbidden: []string{"link_log_collector", "WARN link_log", "FAIL link_log"}},
		{name: "collector not active", mutate: func(h *verifyHost) { h.systemctl = map[string]string{} }, wantCode: 0,
			want: []string{"local-ok", "WARN link_log_collector: " + LinkJournalUnit + " is not active", "forwarding and failover are not affected"}, forbidden: []string{"FAIL link_log", "PASS link_log"}},
		{name: "collector active", mutate: func(h *verifyHost) {
			h.systemctl = map[string]string{"is-active " + LinkJournalUnit: "active\n"}
			h.files[strings.TrimPrefix(LinkJournalConfigPath, "/")] = "{}\n"
		}, wantCode: 0, want: []string{"local-ok", "PASS link_log_collector", "PASS link_log_config"}, forbidden: []string{"FAIL link_log", "UNKNOWN link_log"}},
	})
}
