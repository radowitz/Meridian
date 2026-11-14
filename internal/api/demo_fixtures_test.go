package api

// Fixtures of the panel's demo preview (web/src/demo; web/README.md
// 「演示预览」, docs/ui-layout.md "Demo preview"), generated from the real
// handlers.
//
// buildDemo builds a synthetic gateway of real size (14 nodes with two
// relays, a primary and a backup hub, a nested exit and an external SOCKS
// exit; 7 region groups; 160+ ordered rules; 50+ rule-sets; a dozen-plus
// service groups; unlock results of the whole catalogue on 9 exits …) on
// the test seams only: an in-process host agent that answers healthy
// (demoHost), the fake host preflight, the fake rule-set downloader, the
// fake prober, fake upstream / sniff / remote-access / lists runtimes, the
// in-memory Cloudflare and Mesh remote, and for the deployment guide the
// SSH stand-ins of the deployment tests (sshtest servers on the loopback
// interface, reached only through the SSHDial seam). Nothing leaves the
// process's machine and no remote host is contacted. Names are "example"
// names, addresses are documentation ranges (RFC 5737, RFC 3849) or
// private LAN ranges.
//
// It then calls every GET endpoint the panel uses (and the read-only POSTs
// it calls to show state) and stores the JSON bodies per scenario
// (demoScenarioBase): healthy and unavailable are full sets; degraded, the
// deployment guide states (run in progress, rate-limit wait, failed and
// compensated, unknown outcome, finished with installed and adopted
// steps), the preflight with blocking findings and the refused save hold
// only the responses that differ from healthy. Every state is reached
// through the handlers on the seams; where a seam stands for a host the
// panel would read (the hubs' group reports, remote nodes recorded as
// installed, servers' connection tests, the gateway's upstream record,
// the forwarder's status, WireGuard peers, the lists status) the stored or
// returned state is built with the same functions and parsers the real
// path uses (saveGroupHub with hubstate.Parse, saveOutcome,
// RecordConnectionTest, hostexec.ParseUpstream, sniff.Health …). Nothing
// is hand-written into the fixture files.
//
// The run is made deterministic afterwards (normalizeRun, tokenMap):
// times become offsets from a fixed anchor (the demo shifts them back to
// "now" in the browser), every random token (IDs, keys, fingerprints,
// digests) is replaced by a stable value of the same shape — found by
// building everything twice and comparing — certificate bodies (random
// length) become one placeholder line, and the unlock history, whose order
// within one ingest follows map iteration, is sorted.
//
// Regenerate (one command, from the repository root; also
// `npm --prefix web run demo:fixtures`):
//
//	MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1
//
// Without the variable the test builds the fixtures once in memory and
// checks that the committed files still have the shape (fields and kinds)
// the handlers produce now.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/hubstate"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/mesh"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/probe"
	"github.com/radowitz/meridian/internal/sniff"
	"github.com/radowitz/meridian/internal/sshexec/sshtest"
)

// demoFixtureDir is web/src/demo/generated, relative to this package.
const demoFixtureDir = "../../web/src/demo/generated"

// demoAnchor is the "now" of every generated fixture.
var demoAnchor = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// ------------------------------------------------------------ runtimes ---

// demoHost is the host agent of a healthy gateway: every action succeeds.
type demoHost struct{}

func (demoHost) Do(_ context.Context, req hostexec.Request) (hostexec.Result, error) {
	return hostexec.Result{RequestID: req.RequestID, Action: req.Action, OK: true}, nil
}

type demoSniff struct{ st hostexec.SniffStatus }

func (d *demoSniff) SniffStatus(context.Context) (hostexec.SniffStatus, error) { return d.st, nil }

type demoRemote struct {
	mu sync.Mutex
	st hostexec.WGStatus
}

func (d *demoRemote) RemoteAccessStatus(context.Context) (hostexec.WGStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st, nil
}

// demoFetch serves synthetic rule-set contents; a URL in fail answers an
// error (the previous version stays active).
type demoFetch struct {
	mu   sync.Mutex
	body map[string]string
	fail map[string]string
}

func (f *demoFetch) Get(_ context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if msg, ok := f.fail[url]; ok {
		return nil, fmt.Errorf("%s", msg)
	}
	b, ok := f.body[url]
	if !ok {
		return nil, fmt.Errorf("HTTP 404")
	}
	return []byte(b), nil
}

// ------------------------------------------------------------ topology ---

var demoRegions = []string{"hk", "tw", "my", "jp", "sg", "us", "gb"}

func demoTopology() model.Topology {
	t := model.Topology{
		Settings: model.Settings{
			LANInterface:    "eth0",
			GatewayLANIP:    "192.168.77.2/24",
			ROSIPv4:         "192.168.77.1",
			ROSv6LLA:        "fe80::5054:ff:fe12:3456",
			LANIPv6Prefix:   "2001:db8:77::/64",
			ULAPrefix:       "fd66::/48",
			PanelBind:       "192.168.77.2:8787",
			DomesticDoT:     []string{"192.0.2.53", "198.51.100.53"},
			TransitV4Prefix: "10.77.200.0/24",
			TransitV6Prefix: "fd66:0:0:ff::/64",
			NAT64:           model.NAT64{Reserved: true},
			DefaultGroup:    "hk",
		},
		RulesOrdered: true,
	}
	exit := func(id, name, region, v4 string, x, y float64) model.Node {
		return model.Node{ID: id, Name: name, Role: model.RoleExit, Region: region, Managed: true, X: x, Y: y,
			EndpointV4: v4, WANInterface: "eth0", PathV4: true, EgressV4: true}
	}
	t.Nodes = []model.Node{
		{ID: "gw", Name: "家宽网关（客厅机柜）", Role: model.RoleGateway, Region: "cn", Managed: true, X: 0, Y: 260,
			LANInterface: "eth0", LANIPv4: "192.168.77.2/24", LANIPv6Prefix: "2001:db8:77::/64",
			UnderlayNextHop: "192.168.77.1", PathV4: true, PathV6: true},
		{ID: "ali", Name: "国内中继 · 华东一区（共享带宽，示例里名字特意写得很长）", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 200,
			WANInterface: "eth0", EndpointV4: "203.0.113.10", PathV4: true, WSSListenPort: 8443},
		{ID: "ali2", Name: "国内中继 2 · 华南", Role: model.RoleRelay, Region: "cn", Managed: true, X: 220, Y: 340,
			WANInterface: "eth0", EndpointV4: "203.0.113.11", PathV4: true},
		{ID: "ix", Name: "IX 专线（主枢纽）", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 200,
			HubTier: model.HubPrimary, IXLine: true, IngressV4: "198.51.100.10", EndpointV4: "203.0.113.20", WANInterface: "eth0", PathV4: true},
		{ID: "hk5", Name: "备用枢纽 · 香港机房五号", Role: model.RoleHub, Region: "hk", Managed: true, X: 440, Y: 380,
			HubTier: model.HubBackup, EndpointV4: "203.0.113.30", WANInterface: "eth0", WSSListenPort: 8443, PathV4: true},
		exit("dc1", "香港机房 1（中继出口，带台湾 NAT）", "hk", "203.0.113.41", 680, 80),
		exit("dc2", "香港机房 2（承载马来西亚 SOCKS）", "hk", "203.0.113.42", 680, 170),
		exit("jp1", "日本东京 · 一个很长很长的出口名字用来测试换行", "jp", "203.0.113.51", 680, 260),
		exit("sg1", "新加坡", "sg", "203.0.113.52", 680, 350),
		exit("us1", "美国西岸（双栈）", "us", "203.0.113.53", 680, 440),
		exit("us2", "美国东岸（家宽）", "us", "203.0.113.54", 680, 530),
		exit("gb1", "英国伦敦", "gb", "203.0.113.55", 680, 620),
		{ID: "tw2", Name: "台湾 NAT（只能拨出）", Role: model.RoleExit, Region: "tw", Managed: true, X: 900, Y: 80,
			WANInterface: "eth0", PathV4: true, EgressV4: true, NatDialOut: true, ViaExit: "dc1"},
		{ID: "my1", Name: "马来西亚路由器（外部 SOCKS）", Role: model.RoleExit, Region: "my", Managed: false, X: 900, Y: 170,
			PathV4: true, EgressV4: true,
			External: &model.ExternalExit{Carrier: "dc2", SOCKSAddress: "192.0.2.66", SOCKSPort: 1080, Interface: "wg9", CredentialID: "socks-placeholder"}},
	}
	for i := range t.Nodes {
		switch t.Nodes[i].ID {
		case "us1":
			t.Nodes[i].EndpointV6, t.Nodes[i].PathV6, t.Nodes[i].EgressV6 = "2001:db8:4000:1234:5678:9abc:def0:51", true, true
		case "us2":
			t.Nodes[i].Residential = true
		case "dc1":
			t.Nodes[i].IXBound = true
		}
	}
	link := func(id, name, from, to string, tr model.Transport) model.Link {
		return model.Link{ID: id, Name: name, From: from, To: to, Transport: tr, Enabled: true}
	}
	t.Links = []model.Link{
		link("gw-ali", "家宽 → 国内中继（UDP，WSS 兜底）", "gw", "ali", model.TransportUDPWSSFailover),
		link("gw-ali2", "家宽 → 国内中继 2", "gw", "ali2", model.TransportDirectWG),
		link("ali-ix", "国内中继 → IX（专线）", "ali", "ix", model.TransportDirectWG),
		link("ali2-ix", "国内中继 2 → IX（专线）", "ali2", "ix", model.TransportDirectWG),
		link("tw2-dc1", "台湾 NAT → 香港机房 1（中继出口）", "tw2", "dc1", model.TransportDirectWG),
	}
	backup := link("gw-hk5", "家宽 → 备用枢纽（WSS）", "gw", "hk5", model.TransportIXReplacementWSS)
	backup.Standby = true
	t.Links = append(t.Links, backup)
	for _, hub := range []string{"ix", "hk5"} {
		for _, ex := range []string{"dc1", "dc2", "jp1", "sg1", "us1", "us2", "gb1"} {
			t.Links = append(t.Links, link(hub+"-"+ex, "", hub, ex, model.TransportDirectWG))
		}
	}
	mesh := link("ix-jp1-mesh", "IX → 日本东京 Mesh 备路", "ix", "jp1", model.TransportCFMesh)
	mesh.Standby = true
	mesh.MeshRoutes = []string{"198.51.100.128/25"}
	t.Links = append(t.Links, mesh)

	t.Groups = []model.RegionGroup{
		{ID: "hk", Name: "香港机房", Region: "hk", Members: []string{"dc1", "dc2"}, Mode: model.GroupAuto, ExcludeResidential: true},
		{ID: "tw", Name: "台湾", Region: "tw", Members: []string{"tw2"}, Mode: model.GroupAuto},
		{ID: "my", Name: "马来西亚", Region: "my", Members: []string{"my1"}, Mode: model.GroupAuto},
		{ID: "jp", Name: "日本", Region: "jp", Members: []string{"jp1"}, Mode: model.GroupAuto},
		{ID: "sg", Name: "新加坡", Region: "sg", Members: []string{"sg1"}, Mode: model.GroupAuto},
		{ID: "us", Name: "美国（手动指定西岸，失败时回落）", Region: "us", Members: []string{"us1", "us2"}, Mode: model.GroupManual,
			Chosen: "us1", OnFailure: model.OnFailureFallback},
		{ID: "gb", Name: "英国", Region: "gb", Members: []string{"gb1"}, Mode: model.GroupAuto},
	}

	// Service groups (imported select groups).
	svcNames := []string{"AI 服务", "国际流媒体", "港澳台流媒体", "日本流媒体", "即时通讯", "游戏平台", "开发者工具", "云存储与同步",
		"新闻与资讯", "社交网络", "广告拦截", "国内直连服务", "下载与更新", "音乐平台"}
	svcTargets := []string{"us", "sg", "hk", "jp", "hk", "jp", "us", "us", "gb", "sg", "", "", "hk", "tw"}
	for i, n := range svcNames {
		g := model.ServiceGroup{ID: fmt.Sprintf("svc%02d", i+1), Name: n, Origin: "mihomo", TargetGroup: svcTargets[i]}
		switch n {
		case "广告拦截":
			g.TargetGroup, g.TargetAction = "", model.ActionReject
		case "国内直连服务":
			g.TargetGroup, g.TargetAction = "", model.ActionDirect
		}
		switch g.ID {
		case "svc01":
			g.Select, g.Probes = model.SelectAuto, []string{"auto-openai", "auto-anthropic", "auto-gemini", "auto-copilot", "auto-perplexity"}
		case "svc02":
			g.Select, g.Probes = model.SelectAuto, []string{"auto-netflix", "auto-disney", "primevideo", "youtube-premium"}
		case "svc03":
			g.Select, g.Probes = model.SelectAuto, []string{"auto-mytvsuper", "tvbanywhere"}
		case "svc04":
			g.Probes = []string{"auto-abema", "dmm-tv", "hulu-jp", "radiko"}
		}
		t.ServiceGroups = append(t.ServiceGroups, g)
	}
	// 56 rule-sets.
	for i := 1; i <= 56; i++ {
		rs := model.RuleSet{ID: fmt.Sprintf("rs%02d", i), Name: fmt.Sprintf("Service%02d", i), Origin: "mihomo",
			URL: fmt.Sprintf("https://rules.example.org/subscriptions/provider-%02d/a-rather-long-path/Service%02d.list", i, i)}
		if i == 3 {
			rs.Name = "StreamingWithExclusions"
			rs.Exclude = []string{"DOMAIN-SUFFIX,wide-cdn-03.example", "DOMAIN-SUFFIX,removed-upstream.example"}
		}
		if i%10 == 0 {
			rs.Behavior = "domain"
			rs.URL = fmt.Sprintf("https://rules.example.org/subscriptions/provider-%02d/Service%02d.yaml", i, i)
		}
		t.RuleSets = append(t.RuleSets, rs)
	}
	// 166 rules: manual rules first, then the imported list, then a few
	// non-manual rows.
	var rules []model.Rule
	add := func(r model.Rule) {
		r.Enabled = true
		r.Priority = (len(rules) + 1) * 10
		rules = append(rules, r)
	}
	add(model.Rule{ID: "m-quic", Name: "拒绝走隧道的 QUIC（UDP 443）", Manual: true, MatchType: model.MatchQUICReject})
	for i := 1; i <= 24; i++ {
		r := model.Rule{ID: fmt.Sprintf("m%02d", i), Manual: true}
		switch i % 6 {
		case 0:
			r.Name, r.MatchType, r.MatchValue, r.TargetGroup = fmt.Sprintf("手动 %02d · 整段地址", i), model.MatchCIDR, fmt.Sprintf("198.51.100.%d/32", i), demoRegions[i%7]
		case 1:
			r.Name, r.MatchType, r.MatchValue, r.TargetGroup = fmt.Sprintf("手动 %02d · api-%02d.example.com", i, i), model.MatchDomain, fmt.Sprintf("api-%02d.example.com", i), demoRegions[i%7]
			r.Domains = []string{r.MatchValue}
		case 2:
			r.Name, r.MatchType, r.MatchValue, r.TargetExit = fmt.Sprintf("手动 %02d · 钉死到美国西岸", i), model.MatchSuffix, fmt.Sprintf("pinned-%02d.example.net", i), "us1"
		case 3:
			r.Name, r.MatchType, r.MatchValue, r.TargetService = fmt.Sprintf("手动 %02d · 指向服务组", i), model.MatchSuffix, fmt.Sprintf("svc-%02d.a-very-long-subdomain-for-layout.example.org", i), fmt.Sprintf("svc%02d", (i%10)+1)
		case 4:
			r.Name, r.MatchType, r.MatchValue, r.TargetAction = fmt.Sprintf("手动 %02d · 直连", i), model.MatchSuffix, fmt.Sprintf("direct-%02d.example.cn", i), model.ActionDirect
		case 5:
			r.Name, r.MatchType, r.MatchValue, r.TargetGroup = fmt.Sprintf("手动 %02d · 书房电脑", i), model.MatchSuffix, fmt.Sprintf("study-%02d.example.net", i), "jp"
			r.SourceMAC = fmt.Sprintf("02:00:5e:00:53:%02x", i)
		}
		if i == 7 {
			r.Notes = "这条说明写得比较长：用于检查规则抽屉和表格里的长说明是否会把列撑开，或者被固定的操作列压住。"
		}
		add(r)
	}
	for i := 1; i <= 132; i++ {
		line := 200 + i
		r := model.Rule{ID: fmt.Sprintf("imp-%03d", i), Origin: "mihomo", SourceLine: line, Manual: true}
		svc := fmt.Sprintf("svc%02d", (i%14)+1)
		r.TargetService = svc
		switch {
		case i <= 56:
			rs := fmt.Sprintf("rs%02d", i)
			r.Name, r.MatchType, r.RuleSet = "RULE-SET "+t.RuleSets[i-1].Name, model.MatchRuleSet, rs
			r.SourceText = fmt.Sprintf("RULE-SET,%s,%s", t.RuleSets[i-1].Name, svcNames[(i%14)])
		case i%3 == 0:
			v := fmt.Sprintf("imported-%03d.example.com", i)
			r.Name, r.MatchType, r.MatchValue = "DOMAIN-SUFFIX "+v, model.MatchSuffix, v
			r.SourceText = fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", v, svcNames[(i%14)])
		case i%3 == 1:
			v := fmt.Sprintf("www.imported-%03d.example.org", i)
			r.Name, r.MatchType, r.MatchValue = "DOMAIN "+v, model.MatchDomain, v
			r.Domains = []string{v}
			r.SourceText = fmt.Sprintf("DOMAIN,%s,%s", v, svcNames[(i%14)])
		default:
			v := fmt.Sprintf("203.0.113.%d/32", i%250)
			r.Name, r.MatchType, r.MatchValue = "IP-CIDR "+v, model.MatchCIDR, v
			r.SourceText = fmt.Sprintf("IP-CIDR,%s,%s,no-resolve", v, svcNames[(i%14)])
		}
		add(r)
	}
	for i, reg := range []string{"hk", "tw", "jp", "us"} {
		v := fmt.Sprintf("streaming-%d.example", i+1)
		add(model.Rule{ID: "auto-" + reg, Name: "自动：" + v + " 按解锁结果", Manual: false, MatchType: model.MatchSuffix,
			MatchValue: v, TargetGroup: reg, Domains: []string{v}})
	}
	t.Rules = rules
	return t
}

// demoRuleSetBody is the synthetic content of rule-set i.
func demoRuleSetBody(i int, url string) string {
	var b strings.Builder
	if strings.HasSuffix(url, ".yaml") {
		b.WriteString("payload:\n")
		for k := 0; k < 30+i; k++ {
			fmt.Fprintf(&b, "  - '+.svc%02d-%03d.example'\n", i, k)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "# Service%02d (synthetic)\n", i)
	for k := 0; k < 20+i*3; k++ {
		fmt.Fprintf(&b, "DOMAIN-SUFFIX,svc%02d-%03d.example\n", i, k)
	}
	fmt.Fprintf(&b, "DOMAIN,api.svc%02d.example\nIP-CIDR,198.51.100.%d/32,no-resolve\n", i, i)
	if i%9 == 0 {
		b.WriteString("PROCESS-NAME,example-client.exe\nUSER-AGENT,ExampleAgent*\n")
	}
	if i == 3 {
		b.WriteString("DOMAIN-SUFFIX,wide-cdn-03.example\n")
	}
	return b.String()
}

// ------------------------------------------------------------- the rig ---

type demoRig struct {
	t       *testing.T
	s       *Server
	cs      *credentials.Store
	fetch   *demoFetch
	up      *fakeUpstream
	sn      *demoSniff
	ra      *demoRemote
	lists   *fakeLists
	prober  *fakeProber
	cf      *memCF
	rem     *okRemote
	hp      *fakeHostPreflight
	ids     map[string]string // random id -> stable id
	servers map[string]string // node -> server id
	pw      string            // password of cred-ops (the SSH stand-ins accept it)
	// SSH stand-ins (sshtest, in-process, reached only through SSHDial)
	// for the nodes the deployment guide scenarios install.
	ssh  map[string]*sshtest.Server
	host *deployFix // answers the stand-ins like the deployment tests
}

// demoSSHNodes are the remote nodes the guide scenarios install.
var demoSSHNodes = []string{"jp1", "sg1", "us2", "gb1", "ix", "hk5"}

func (r *demoRig) call(method, path string, body any, want int) []byte {
	r.t.Helper()
	var raw []byte
	if body != nil {
		raw = mustJSON(body)
	}
	rr := do(r.s, method, path, raw)
	if want != 0 && rr.Code != want {
		r.t.Fatalf("%s %s: %d %s", method, path, rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}

func (r *demoRig) id(random, stable string) { r.ids[random] = stable }

// post is one read-only POST's response as it is (any status).
func (r *demoRig) post(path, body string) demoResponse {
	rr := do(r.s, http.MethodPost, path, []byte(body))
	return demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
}

func newDemoRig(t *testing.T, healthy bool) *demoRig {
	t.Helper()
	s := newTest(t)
	s.HostRoot = t.TempDir()
	s.RuleSetDir = filepath.Join(t.TempDir(), "rulesets")
	s.ListsDir = t.TempDir()
	r := &demoRig{t: t, s: s, ids: map[string]string{}, servers: map[string]string{},
		fetch: &demoFetch{body: map[string]string{}, fail: map[string]string{}}}
	s.RuleSetFetch = func(RuleSetFetchOptions) RuleSetFetcher { return r.fetch }
	topo := demoTopology()
	for i, rs := range topo.RuleSets {
		r.fetch.body[rs.URL] = demoRuleSetBody(i+1, rs.URL)
	}
	if healthy {
		r.hp = &fakeHostPreflight{}
		r.up = &fakeUpstream{}
		r.sn = &demoSniff{}
		r.ra = &demoRemote{}
		r.lists = &fakeLists{}
		r.prober = &fakeProber{}
		s.Host, s.HostPreflight, s.Upstream, s.Sniff, s.RemoteStatus, s.Lists, s.Prober = demoHost{}, r.hp, r.up, r.sn, r.ra, r.lists, agedProber{fakeProber: r.prober}
		r.cf = &memCF{nodes: map[string]mesh.CFNode{}, routes: map[string]mesh.CFRoute{}, nodeToken: "eyJnode" + strings.Repeat("q", 30)}
		r.rem = &okRemote{keys: map[string]string{}}
		s.MeshCF = func(mesh.Credentials) (mesh.Cloudflare, error) { return r.cf, nil }
		s.MeshRemote = func() mesh.Remote { return r.rem }
		topo.Settings.UnlockProbe = &model.UnlockProbeSettings{ExitConcurrency: 1} // results in a fixed order
		r.ssh = map[string]*sshtest.Server{}
		r.host = &deployFix{s: s, extra: map[string]string{}, script: map[string]func(string) (string, uint32){}, host: map[string]string{}, runs: map[string]int{}, state: map[string]string{}}
		byAddr := map[string]*sshtest.Server{}
		for _, n := range topo.Nodes {
			if !slices.Contains(demoSSHNodes, n.ID) {
				continue
			}
			srv := startSSH(t)
			node := n.ID
			srv.SetHandler(func(cmd, stdin string) (string, uint32) { return r.host.answer(node, cmd, stdin) })
			r.ssh[n.ID] = srv
			addr := net.JoinHostPort(n.EndpointV4, "22")
			if n.ID == "ix" { // through a port-forward on the relay
				addr = "203.0.113.10:2222"
			}
			byAddr[addr] = srv
		}
		s.SSHDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			srv, ok := byAddr[addr]
			if !ok {
				return nil, fmt.Errorf("demo: no route to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(srv.Host, fmt.Sprint(srv.Port)))
		}
	}
	if err := s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	r.cs = cs
	return r
}

// resources: SSH credentials, SOCKS credential, one server per managed
// remote node (trusted host keys), the Cloudflare account.
func (r *demoRig) resources() {
	t := r.t
	type credOut struct {
		Credential struct {
			ID string `json:"id"`
		} `json:"credential"`
	}
	var c1, c2, c3, sc credOut
	mk := func(out *credOut, body map[string]any, stable string) {
		if err := json.Unmarshal(r.call(http.MethodPost, "/api/ssh-credentials", body, http.StatusCreated), out); err != nil {
			t.Fatal(err)
		}
		r.id(out.Credential.ID, stable)
	}
	r.pw = "pw-" + rnd(t, 10)
	for _, srv := range r.ssh {
		srv.SetPassword(r.pw)
	}
	mk(&c1, map[string]any{"name": "运维密码（所有机房）", "kind": "password", "password": r.pw, "notes": "合成数据：演示用"}, "cred-ops")
	mk(&c2, map[string]any{"name": "部署密钥 · ed25519 · 一个比较长的名字", "kind": "password", "password": "pw-" + rnd(t, 10)}, "cred-deploy")
	mk(&c3, map[string]any{"name": "备用枢纽专用", "kind": "password", "password": r.pw}, "cred-hub")
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/socks-credentials", map[string]any{"name": "马来西亚 SOCKS", "username": "demo-user", "password": "pw-" + rnd(t, 10)}, http.StatusCreated), &sc); err != nil {
		t.Fatal(err)
	}
	r.id(sc.Credential.ID, "socks-my")

	topo, _, _ := r.s.Store.Load()
	for i := range topo.Nodes {
		n := &topo.Nodes[i]
		if n.ID == "my1" {
			n.External.CredentialID = sc.Credential.ID
		}
		if !n.Managed || n.Role == model.RoleGateway {
			continue
		}
		cred, user, addr := c1.Credential.ID, "root", n.EndpointV4
		switch n.ID {
		case "hk5":
			cred = c3.Credential.ID
		case "ali", "ali2":
			cred, user = c2.Credential.ID, "deploy"
		case "tw2":
			addr = "nat-exit-taiwan.home-broadband.subscriber-line.example.net"
		case "us1":
			addr = "2001:db8:4000:1234:5678:9abc:def0:51"
		case "ix":
			addr = "203.0.113.10"
		}
		in := credentials.ServerInput{Name: "机器 " + n.Name, Address: addr, Port: 22, User: user, Auth: model.AuthPassword, CredentialID: cred,
			Tags: []string{n.Region, string(n.Role)}}
		if n.ID == "ix" {
			in.Port = 2222
			in.Notes = "经国内中继的端口转发登录"
		}
		sv, err := r.cs.CreateServer(in)
		if err != nil {
			t.Fatalf("server %s: %v", n.ID, err)
		}
		sum := sha256.Sum256([]byte("demo host key " + n.ID))
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		if srv := r.ssh[n.ID]; srv != nil {
			fp = srv.Fingerprint()
		}
		if _, err := r.cs.ObserveHostKey(sv.ID, "ssh-ed25519", fp); err != nil {
			t.Fatal(err)
		}
		if _, err := r.cs.TrustHostKey(sv.ID, fp); err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Add(-26 * time.Hour).Format(time.RFC3339)
		if _, err := r.cs.RecordConnectionTest(sv.ID, model.ConnectionTest{At: at, OK: true, AuthMethod: model.AuthPassword}); err != nil {
			t.Fatal(err)
		}
		r.id(sv.ID, "srv-"+n.ID)
		r.servers[n.ID] = sv.ID
		n.ServerID = sv.ID
	}
	// One server not bound to any node.
	sv, err := r.cs.CreateServer(credentials.ServerInput{Name: "闲置机器（还没有绑定节点）", Address: "198.51.100.200", Port: 22, User: "root", Auth: model.AuthPassword, CredentialID: c1.Credential.ID})
	if err != nil {
		t.Fatal(err)
	}
	r.id(sv.ID, "srv-spare")
	// … whose host key waits for the operator's confirmation.
	sum := sha256.Sum256([]byte("demo host key spare"))
	if _, err := r.cs.ObserveHostKey(sv.ID, "ssh-ed25519", "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Store.Save(topo); err != nil {
		t.Fatal(err)
	}

	var acct struct {
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/cloudflare/accounts", map[string]any{"name": "Cloudflare 主账户", "account_id": strings.Repeat("0123456789abcdef", 2), "api_token": "cfapitoken_" + rnd(t, 24)}, http.StatusCreated), &acct); err != nil {
		t.Fatal(err)
	}
	r.id(acct.Account.ID, "cf-main")
	r.call(http.MethodPut, "/api/cloudflare/mesh-account", map[string]string{"account": acct.Account.ID}, http.StatusOK)
	r.call(http.MethodPut, "/api/sniff", map[string]any{"enabled": true, "record_names": true}, http.StatusOK)
}

// fetchRuleSets downloads every rule-set through the handler.
func (r *demoRig) fetchRuleSets() {
	topo, _, _ := r.s.Store.Load()
	for _, rs := range topo.RuleSets {
		r.call(http.MethodPost, "/api/rule-sets/"+rs.ID+"/update", map[string]any{}, 0)
		waitRS(r.t, r.s, rs.ID, func(st *RuleSetStatus) bool { return st.State == "ok" || st.State == "failed" || st.State == "held" })
	}
}

// remote access: enabled with three devices.
func (r *demoRig) remoteAccess() {
	r.call(http.MethodPut, "/api/remote-access", map[string]any{"enabled": true, "endpoint": "vpn.home-gateway.example.net", "listen_port": 51820}, 0)
	for i, d := range []struct{ name, mode string }{{"手机 · 日常", "home"}, {"笔记本（出差用，名字比较长的一台设备）", "full"}, {"平板", "home"}} {
		var out struct {
			Device struct {
				ID string `json:"id"`
			} `json:"device"`
		}
		b := r.call(http.MethodPost, "/api/remote-access/devices", map[string]any{"name": d.name, "mode": d.mode}, 0)
		if err := json.Unmarshal(b, &out); err != nil || out.Device.ID == "" {
			r.t.Fatalf("device: %v %s", err, b)
		}
		r.id(out.Device.ID, fmt.Sprintf("dev-%d", i+1))
	}
}

// install: node keys, the gateway's preflight and install, every remote
// node recorded as installed with exactly its current content.
func (r *demoRig) install() {
	t := r.t
	if _, _, err := r.s.ensureNodeKeys(); err != nil {
		t.Fatal(err)
	}
	var pf struct {
		Preflight struct {
			ID string `json:"id"`
		} `json:"preflight"`
	}
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/host/preflight", map[string]any{}, http.StatusOK), &pf); err != nil {
		t.Fatal(err)
	}
	r.call(http.MethodPost, "/api/apply", map[string]any{"install": true, "preflight_id": pf.Preflight.ID}, http.StatusOK)
	r.markInSync(func(string) bool { return true })
}

func (r *demoRig) markInSync(sel func(string) bool) {
	l, err := r.s.liveDeploy()
	if err != nil {
		r.t.Fatal(err)
	}
	for _, n := range l.t.Nodes {
		if !n.Managed || n.Role == model.RoleGateway || !sel(n.ID) {
			continue
		}
		id := l.idents[n.ID]
		now := time.Now().UTC().Add(-26 * time.Hour)
		r.s.saveOutcome(provisionOutcome{NodeID: n.ID, ServerID: id.ServerID, Address: id.Address, Port: id.Port, Fingerprint: id.Fingerprint,
			User: id.User, CredentialID: id.CredentialID, Bundle: l.bundles[n.ID], At: now, OK: true, Outcome: "installed", Run: "run-seed",
			Verify: &nodeVerify{At: now, State: verifyOK, Source: "post_install", HostBundle: l.bundles[n.ID]}})
	}
}

// runtimes: what a healthy gateway reports right now.
func (r *demoRig) runtimes() {
	now := time.Now().UTC()
	beat := now.Unix() - 4
	r.setUpstream(demoUpstreamRecord(beat, false))

	// The forwarder runs the compiled target file of the installed bundle.
	topo, _, _ := r.s.Store.Load()
	b, err := r.s.compileTopo(topo)
	if err != nil {
		r.t.Fatal(err)
	}
	var tf sniff.TargetsFile
	if err := json.Unmarshal([]byte(b.Files["nodes/gw"+compile.SniffTargetsPath]), &tf); err != nil || len(tf.Targets) == 0 {
		r.t.Fatalf("sniff targets of the bundle: %v (%d)", err, len(tf.Targets))
	}
	var targets []string
	for _, x := range tf.Targets {
		targets = append(targets, x.Name)
	}
	health, _ := json.Marshal(sniff.Health{Ready: true, Mode: "redirect", Listen: "[::]:5358", Generation: 42, LoadedAt: now.Add(-3 * time.Hour),
		Rules: len(topo.Rules), Targets: targets, MACRules: true, MACLookup: true, Active: 37, MaxConns: 4096,
		RecordNames: true, Counters: map[string]uint64{"decided_by_name": 171002, "decided_by_address_ech": 6011, "decided_by_address_no_sni": 4200,
			"decided_by_address_other": 1131, "result_ok": 180110, "result_dial_failed": 21, "result_rejected": 902, "refused_overload": 0}})
	var recs []sniff.ConnRecord
	names := []string{"api-01.example.com", "www.imported-004.example.org", "svc03-010.example", "streaming-1.example", "", "pinned-02.example.net", "svc-03.a-very-long-subdomain-for-layout.example.org"}
	for i, nm := range names {
		rec := sniff.ConnRecord{Start: now.Add(-time.Duration(i*7) * time.Second), Source: fmt.Sprintf("192.168.77.%d:%d", 20+i, 50000+i), Dest: fmt.Sprintf("198.51.100.%d:443", 10+i),
			Proto: "tls", Name: nm, Sniffed: nm != "", By: "name", RuleIndex: 3 + i*11, RuleID: fmt.Sprintf("m%02d", i+1), Target: tf.Targets[i%len(tf.Targets)].Name, Mark: tf.Targets[i%len(tf.Targets)].Mark,
			Upstream: fmt.Sprintf("198.51.100.%d:443", 10+i), Result: "ok", DecideMS: int64(2 + i), Generation: 42}
		if nm == "" {
			rec.Why, rec.By, rec.ECH, rec.RuleID, rec.RuleIndex = sniff.WhyECH, "addr", true, "", 0
		}
		recs = append(recs, rec)
	}
	recent, _ := json.Marshal(map[string]any{"record_names": true, "connections": recs})
	r.sn.st = hostexec.SniffStatus{Present: true, Active: "active", Health: health, Recent: recent, ReadAt: now.Format(time.RFC3339)}

	var ra struct {
		Devices []struct {
			PublicKey string `json:"public_key"`
		} `json:"devices"`
	}
	_ = json.Unmarshal(r.call(http.MethodGet, "/api/remote-access/devices", nil, http.StatusOK), &ra)
	var peers []hostexec.WGPeer
	for i, d := range ra.Devices {
		hs := now.Unix() - int64(40+i*900)
		if i == 2 {
			hs = 0
		}
		peers = append(peers, hostexec.WGPeer{PublicKey: d.PublicKey, LatestHandshake: hs, RxBytes: int64(i+1) * 73 << 20, TxBytes: int64(i+1) * 9 << 20})
	}
	r.ra.mu.Lock()
	r.ra.st = hostexec.WGStatus{Interface: "mra", Present: true, Peers: peers, ReadAt: now.Format(time.RFC3339)}
	r.ra.mu.Unlock()

	pub := lists.Published{Source: "github", URL: "https://lists.example.org/geosite/cn.txt", UpdatedAt: now.Add(-5 * time.Hour), Count: 118204, Files: 1}
	r.lists.status = lists.Status{Published: map[string]lists.Published{
		"geosite:cn": pub,
		"chnroute4":  {Source: "github", URL: "https://lists.example.org/chnroute/v4.txt", UpdatedAt: now.Add(-5 * time.Hour), Count: 8840},
		"chnroute6":  {Source: "github", URL: "https://lists.example.org/chnroute/v6.txt", UpdatedAt: now.Add(-5 * time.Hour), Count: 1932},
	}}
}

// unlock: the whole catalogue on the nine exits (IPv4, and IPv6 where the
// exit has it), with a mix of results.
func (r *demoRig) unlock() {
	r.prober.answer = func(req hostexec.ProbeRequest, svc string) probe.Category {
		a, _ := probe.Lookup(svc)
		if a.Capability == probe.CapReachability {
			return probe.CatNetworkOK
		}
		h := sha256.Sum256([]byte(req.ExitID + "/" + svc + "/" + req.Family))
		switch v := binary.BigEndian.Uint16(h[:2]) % 20; {
		case v < 13:
			return probe.CatUnlocked
		case v < 17:
			return probe.CatNotUnlocked
		case v < 18:
			return probe.CatFailed
		default:
			return probe.CatUnknown
		}
	}
	var all []string
	for _, a := range probe.Catalog {
		if probe.Probeable(a.Service) {
			all = append(all, a.Service)
		}
	}
	for _, exits := range [][]string{{"dc1", "dc2"}, {"tw2", "my1"}, {"jp1", "sg1"}, {"us1", "us2"}, {"gb1"}} {
		runJob(r.t, r.s, string(mustJSON(map[string]any{"services": all, "exits": exits, "families": []string{"ipv4"}})))
	}
	runJob(r.t, r.s, string(mustJSON(map[string]any{"services": all, "exits": []string{"us1"}, "families": []string{"ipv6"}})))
}

// hubRead stores a fresh read of the primary hub reporting every group
// on its target member.
func (r *demoRig) hubRead(tier model.HubTier, age time.Duration, hop map[string]string) {
	topo, _, _ := r.s.Store.Load()
	hub, _ := hubByTier(topo, tier)
	plans, err := compile.PlanGroupsForHub(topo, hub.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	plan := compile.GroupPlanID(plans)
	now := time.Now().Add(-age).Unix()
	var blocks []string
	for _, g := range topo.Groups {
		h := hop[g.ID]
		if h == "" {
			h = g.Members[0]
			if g.Chosen != "" {
				h = g.Chosen
			}
		}
		blocks = append(blocks, hubReport(g.ID, plan, now-3, "hop "+h, "active "+h, "reason preferred", fmt.Sprintf("switched %d", now-7200)))
	}
	snap, err := hubstate.Parse(hubOutput(plan, now, blocks...))
	if err != nil {
		r.t.Fatal(err)
	}
	rd := hubstate.Read{ReadAt: time.Now().UTC().Add(-age), Identity: r.s.hubReachabilityTier(topo, tier).identity, Snapshot: &snap}
	if err := r.s.saveGroupHub(tier, rd); err != nil {
		r.t.Fatal(err)
	}
}

func (r *demoRig) meshDeploy() {
	for node, id := range r.servers {
		if sv, err := r.cs.Server(id); err == nil {
			r.rem.keys[node] = sv.HostKey.Fingerprint
		}
	}
	r.call(http.MethodPost, "/api/mesh/deploy", map[string]any{}, 0)
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := (&mesh.Deployer{Dir: r.s.meshDir()}).Load()
		if err == nil && j != nil && j.State != mesh.StateRunning && j.State != mesh.StateCompensating {
			if j.State != "published" && j.State != "done" {
				r.t.Logf("mesh state %s: %s", j.State, j.Error)
			}
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatal("mesh deploy did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ------------------------------------------------------------- collect ---

// demoGets are the read endpoints the panel calls, answered as they are.
var demoGets = []string{
	"/api/health", "/api/meta", "/api/status", "/api/host", "/api/topology", "/api/upstream", "/api/sniff",
	"/api/servers", "/api/ssh-credentials", "/api/socks-credentials", "/api/cloudflare/accounts", "/api/cloudflare/requirements",
	"/api/mesh", "/api/lists", "/api/lists/job", "/api/lists/status", "/api/region-groups", "/api/remote-access",
	"/api/remote-access/devices", "/api/unlock", "/api/unlock/catalog", "/api/unlock/jobs", "/api/unlock/results",
	"/api/deployments", "/api/wss", "/api/leakcheck", "/api/rule-sets", "/api/service-groups", "/api/rules/analysis",
	"/api/deploy", "/api/artifacts",
}

// demoPosts are the read-only POSTs the panel calls to show state, with
// the body it sends.
var demoPosts = []struct{ path, body string }{
	{"/api/diff", "{}"}, {"/api/validate", "{}"}, {"/api/topology/allocations", "{}"},
}

type demoResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

func (r *demoRig) collect() map[string]demoResponse {
	out := map[string]demoResponse{}
	get := func(key, method, path string, body []byte) []byte {
		rr := do(r.s, method, path, body)
		out[key] = demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
		return rr.Body.Bytes()
	}
	for _, p := range demoGets {
		get("GET "+p, http.MethodGet, p, nil)
	}
	for _, p := range demoPosts {
		get("POST "+p.path, http.MethodPost, p.path, []byte(p.body))
	}
	// Detail reads of every listed object.
	var ids struct {
		Servers []struct {
			ID string `json:"id"`
		} `json:"servers"`
		Credentials []struct {
			ID string `json:"id"`
		} `json:"credentials"`
		Accounts []struct {
			ID string `json:"id"`
		} `json:"accounts"`
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	for _, p := range []string{"/api/servers", "/api/ssh-credentials", "/api/cloudflare/accounts", "/api/region-groups", "/api/remote-access/devices", "/api/unlock/jobs"} {
		_ = json.Unmarshal(out["GET "+p].Body, &ids)
	}
	for _, x := range ids.Servers {
		get("GET /api/servers/"+x.ID, http.MethodGet, "/api/servers/"+x.ID, nil)
	}
	for _, x := range ids.Credentials {
		get("GET /api/ssh-credentials/"+x.ID, http.MethodGet, "/api/ssh-credentials/"+x.ID, nil)
	}
	for _, x := range ids.Accounts {
		get("GET /api/cloudflare/accounts/"+x.ID, http.MethodGet, "/api/cloudflare/accounts/"+x.ID, nil)
	}
	for _, x := range ids.Groups {
		get("GET /api/region-groups/"+x.ID, http.MethodGet, "/api/region-groups/"+x.ID, nil)
	}
	for _, x := range ids.Devices {
		get("GET /api/remote-access/devices/"+x.ID, http.MethodGet, "/api/remote-access/devices/"+x.ID, nil)
	}
	for _, x := range ids.Jobs {
		get("GET /api/unlock/jobs/"+x.ID, http.MethodGet, "/api/unlock/jobs/"+x.ID, nil)
	}
	// The rule tester on a few example names.
	for _, n := range []string{"api-01.example.com", "svc03-010.example", "wide-cdn-03.example", "unknown-name.example.net"} {
		get("POST /api/rules/test?name="+n, http.MethodPost, "/api/rules/test", mustJSON(map[string]string{"name": n}))
	}
	return out
}

// demoUpstreamRecord is the gateway's upstream record in its own grammar
// (pathquality.FormatStatus), parsed below by the agent's parser: two
// relays sharing the main path, or (degraded) the backup hub carrying
// with one relay down and one evicted for loss.
func demoUpstreamRecord(beat int64, degraded bool) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "meridian-upstream 2\nbeat %d\n", beat)
	relay := func(id, iface, status string, weight int, drain int, reason string, since int64, grade, rtt, loss, lastRTT, lastLoss string, rx, tx, rxBps, txBps, conns int64, probeKbps, probeLoss, probeOK string) {
		fmt.Fprintf(b, "relay %s %s %s %d %d %s %d %s %s %s %s %s %d %d %d %d %d %d - %d %s %s %s %d\n",
			id, iface, status, weight, drain, reason, since, grade, rtt, loss, lastRTT, lastLoss, beat-2, rx, tx, rxBps, txBps, conns, beat-600, probeKbps, probeLoss, probeOK, 3<<20)
	}
	if !degraded {
		fmt.Fprintf(b, "path main\niface m01\nhub ix\ntier primary\nsince %d\nstate ok\ncontroller go\nalert -\nswitched %d\ndesignated ali\n", beat-86400, beat-86400)
		relay("ali", "m01", "active", 600, 0, "-", beat-86400, "good", "21400", "2", "22300", "0", 38<<30, 4<<30, 11<<20, 1<<20, 412, "48000", "0", "1")
		relay("ali2", "m02", "active", 400, 0, "-", beat-86400, "good", "27800", "5", "28700", "0", 25<<30, 3<<30, 7<<20, 1<<20, 291, "41000", "0", "1")
		fmt.Fprintf(b, "backup hk5 m03 good 36500 3 36100 0 %d %d %d 0\nend\n", beat-30, 1<<20, 1<<20)
		return b.String()
	}
	fmt.Fprintf(b, "path backup\niface m03\nhub hk5\ntier backup\nsince %d\nstate ok\ncontroller go\nalert on_backup\nswitched %d\ndesignated backup\n", beat-1260, beat-1260)
	relay("ali", "m01", "evicted", 0, 1, "down", beat-1300, "down", "-", "1000", "-", "1000", 38<<30, 4<<30, 0, 0, 0, "-", "-", "0")
	relay("ali2", "m02", "evicted", 0, 1, "poor_loss", beat-1260, "poor", "61200", "186", "64800", "240", 25<<30, 3<<30, 12<<10, 3<<10, 0, "3100", "210", "0")
	fmt.Fprintf(b, "backup hk5 m03 good 38900 4 39200 0 %d %d %d 0\nend\n", beat-3, 9<<30, 1<<30)
	return b.String()
}

// setUpstream answers the upstream read with rec, parsed like the agent does.
func (r *demoRig) setUpstream(rec string) {
	st, err := hostexec.ParseUpstream(rec)
	if err != nil {
		r.t.Fatalf("upstream record: %v\n%s", err, rec)
	}
	r.up.mu.Lock()
	r.up.st = hostexec.UpstreamStatus{Present: true, Record: &st, ReadAt: time.Now().UTC().Format(time.RFC3339)}
	r.up.mu.Unlock()
}

// ------------------------------------------------- guide scenarios ---

// demoDeployKeys are the responses a deployment-guide scenario replaces.
var demoDeployKeys = []string{"GET /api/deploy", "GET /api/status", "GET /api/deployments", "GET /api/host", "POST /api/diff", "GET /api/topology", "GET /api/rules/analysis", "POST /api/validate"}

func (r *demoRig) collectKeys(keys []string) map[string]demoResponse {
	all := r.collect()
	out := map[string]demoResponse{}
	for _, k := range keys {
		out[k] = all[k]
	}
	return out
}

type demoRun struct {
	Run *struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Steps []struct {
			NodeID      string `json:"node_id"`
			Phase       string `json:"phase"`
			PreflightID string `json:"preflight_id"`
		} `json:"steps"`
	} `json:"run"`
}

func (r *demoRig) deployState() demoRun {
	var v demoRun
	if err := json.Unmarshal(r.call(http.MethodGet, "/api/deploy", nil, http.StatusOK), &v); err != nil {
		r.t.Fatal(err)
	}
	return v
}

func (r *demoRig) step(node string) (phase, preflight string) {
	v := r.deployState()
	for i := 0; v.Run == nil && i < 50; i++ { // read while a step is being written
		time.Sleep(10 * time.Millisecond)
		v = r.deployState()
	}
	if v.Run == nil {
		r.t.Fatal("no run")
	}
	for _, st := range v.Run.Steps {
		if st.NodeID == node {
			return st.Phase, st.PreflightID
		}
	}
	r.t.Fatalf("no step %s", node)
	return "", ""
}

func (r *demoRig) preflightStep(run, node string) {
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/preflight", map[string]any{"node_id": node}, http.StatusOK)
}

func (r *demoRig) installStep(run, node string) {
	_, pf := r.step(node)
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/install", map[string]any{"node_id": node, "preflight_id": pf}, http.StatusOK)
}

func (r *demoRig) startRun(stable string) string {
	var v demoRun
	if err := json.Unmarshal(r.call(http.MethodPost, "/api/deploy/runs", map[string]any{}, http.StatusOK), &v); err != nil || v.Run == nil {
		r.t.Fatalf("start run: %v", err)
	}
	r.id(v.Run.ID, stable)
	return v.Run.ID
}

// touch changes the content of the given exits' bundles (the MTU of
// their hub links, so both hubs change too) and, with gateway, of the
// gateway (a manual rule), so they are pending.
func (r *demoRig) touch(mtu int, gateway bool, exits ...string) {
	topo, _, _ := r.s.Store.Load()
	for i := range topo.Links {
		if slices.Contains(exits, topo.Links[i].To) && (topo.Links[i].From == "ix" || topo.Links[i].From == "hk5") && topo.Links[i].Transport == model.TransportDirectWG {
			topo.Links[i].MTU = mtu
		}
	}
	if gateway {
		for i := range topo.Rules {
			if topo.Rules[i].ID == "m01" {
				topo.Rules[i].MatchValue = fmt.Sprintf("api-01-v%d.example.com", mtu)
				topo.Rules[i].Domains = []string{topo.Rules[i].MatchValue}
			}
		}
	}
	if err := r.s.Store.Save(topo); err != nil {
		r.t.Fatal(err)
	}
}

// guide runs the deployment guide through its states on the SSH
// stand-ins and the in-process gateway, collecting each one.
func (r *demoRig) guide() map[string]map[string]demoResponse {
	out := map[string]map[string]demoResponse{}
	r.touch(1380, true, "jp1", "sg1", "us2", "gb1")

	// The plan's order of the remote steps.
	run := r.startRun("run-demo-1")
	var order []string
	for _, st := range r.deployState().Run.Steps {
		if st.NodeID != localNodeID {
			order = append(order, st.NodeID)
		}
	}
	if len(order) != len(demoSSHNodes) {
		r.t.Fatalf("plan %v", order)
	}
	a, b, c := order[0], order[1], order[2]

	// A run in progress: a installed, b installing right now.
	r.preflightStep(run, a)
	r.installStep(run, a)
	r.preflightStep(run, b)
	release, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.host.setScript(b, func(string) (string, uint32) {
		once.Do(func() { close(entered) })
		<-release
		return "MERIDIAN_PROVISION_OK\n", 0
	})
	done := make(chan struct{})
	_, pf := r.step(b)
	go func() {
		defer close(done)
		do(r.s, http.MethodPost, "/api/deploy/runs/"+run+"/install", mustJSON(map[string]any{"node_id": b, "preflight_id": pf}))
	}()
	// The install script is running on the stand-in (and waits there):
	// the stored run says "installing" and nothing else moves.
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		close(release)
		r.t.Fatalf("%s never reached its install script", b)
	}
	if ph, _ := r.step(b); ph != phaseInstalling {
		close(release)
		r.t.Fatalf("%s is %s while its script runs", b, ph)
	}
	out["deploy-running"] = r.collectKeys(demoDeployKeys)
	close(release)
	<-done
	r.host.setScript(b, nil)

	// c refuses the panel's address before the banner: wait for retry_after.
	r.ssh[c].RefuseBeforeBanner("Not allowed at this time")
	r.preflightStep(run, c)
	out["deploy-rate-limited"] = r.collectKeys(demoDeployKeys)
	r.ssh[c].RefuseBeforeBanner("")
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/cancel", map[string]any{}, http.StatusOK)
	r.s.sshPoolMu.Lock()
	r.s.SSHPool = nil // forget the remembered refusal
	r.s.sshPoolMu.Unlock()

	// c's install fails and is compensated: the run stops.
	run = r.startRun("run-demo-2")
	r.host.setScript(c, func(string) (string, uint32) { return "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_COMPENSATED\n", 1 })
	r.preflightStep(run, c)
	r.installStep(run, c)
	out["deploy-compensated"] = r.collectKeys(demoDeployKeys)
	r.call(http.MethodPost, "/api/deploy/runs/"+run+"/cancel", map[string]any{}, http.StatusOK)

	// c's answer is unreadable: the outcome is unknown and the run stops.
	run = r.startRun("run-demo-3")
	r.host.setScript(c, func(string) (string, uint32) { return "garbled\n", 1 })
	r.preflightStep(run, c)
	r.installStep(run, c)
	out["deploy-unknown"] = r.collectKeys(demoDeployKeys)

	// The re-check finds the content on the host and adopts it; d and the
	// gateway install: the run finishes with installed and adopted steps.
	l, err := r.s.liveDeploy()
	if err != nil {
		r.t.Fatal(err)
	}
	r.host.mu.Lock()
	r.host.extra[c] = "manifest-begin\nmanifest node " + c + "\nmanifest deployment " + mustDeployment(r.t, r.s) + "\nmanifest server " + r.servers[c] +
		"\nmanifest bundle " + l.bundles[c] + "\nmanifest-end\njournal-begin\njournal state done\njournal run run-x\njournal-end\n"
	r.host.mu.Unlock()
	r.host.setScript(c, nil)
	r.preflightStep(run, c)
	r.host.mu.Lock()
	r.host.extra[c] = ""
	r.host.mu.Unlock()
	for _, n := range append(order[3:], localNodeID) {
		r.preflightStep(run, n)
		r.installStep(run, n)
	}
	out["deploy-done"] = r.collectKeys(demoDeployKeys)
	return out
}

// ----------------------------------------------------------- degraded ---

// agedProber answers like fakeProber, with results from age ago, one
// millisecond apart (no two results share a time, so nothing depends on
// how ties are broken).
type agedProber struct {
	*fakeProber
	age time.Duration
}

func (a agedProber) Probe(ctx context.Context, req hostexec.ProbeRequest) (probe.Report, error) {
	rep, err := a.fakeProber.Probe(ctx, req)
	rep.StartedAt = rep.StartedAt.Add(-a.age)
	for i := range rep.Results {
		at := rep.StartedAt.Add(time.Duration(i+1) * time.Millisecond)
		rep.Results[i].StartedAt, rep.Results[i].FinishedAt = at, at.Add(time.Millisecond/2)
	}
	rep.FinishedAt = rep.StartedAt.Add(time.Duration(len(rep.Results)+1) * time.Millisecond)
	return rep, err
}

// degrade: the same gateway after things went wrong.
func (r *demoRig) degrade() {
	now := time.Now().UTC()
	r.setUpstream(demoUpstreamRecord(now.Unix()-6, true))

	// An exit fails its health checks: the hk group moves to dc2.
	for i := 0; i < 3; i++ {
		r.call(http.MethodPost, "/api/region-groups/health", map[string]any{"observations": []map[string]any{{"id": "dc1", "up": false}}}, http.StatusOK)
	}

	// A rule-set's download fails: the previous version stays active.
	topo, _, _ := r.s.Store.Load()
	rs := topo.RuleSets[6]
	r.fetch.mu.Lock()
	r.fetch.fail[rs.URL] = "HTTP 503 Service Unavailable"
	r.fetch.mu.Unlock()
	r.call(http.MethodPost, "/api/rule-sets/"+rs.ID+"/update", map[string]any{}, 0)
	waitRS(r.t, r.s, rs.ID, func(st *RuleSetStatus) bool { return st.LastError != "" })

	// Results of gb1 from three days ago: expired.
	var all []string
	for _, a := range probe.Catalog {
		if probe.Probeable(a.Service) {
			all = append(all, a.Service)
		}
	}
	r.s.Prober = agedProber{fakeProber: r.prober, age: 72 * time.Hour}
	runJob(r.t, r.s, string(mustJSON(map[string]any{"services": all, "exits": []string{"gb1"}, "families": []string{"ipv4"}})))
	r.s.Prober = agedProber{fakeProber: r.prober}

	// Pending changes on two nodes (hk5 and dc2).
	topo, _, _ = r.s.Store.Load()
	for i := range topo.Links {
		if topo.Links[i].ID == "hk5-dc2" {
			topo.Links[i].MTU = 1360
		}
	}
	if err := r.s.Store.Save(topo); err != nil {
		r.t.Fatal(err)
	}

	// The hub reports are old: the primary's from 25 minutes ago, the
	// backup's (which carries now) from 12 minutes ago.
	r.hubRead(model.HubPrimary, 25*time.Minute, nil)
	r.hubRead(model.HubBackup, 12*time.Minute, map[string]string{"hk": "dc2"})

	// A server stopped answering the connection test.
	if _, err := r.cs.RecordConnectionTest(r.servers["ali2"], model.ConnectionTest{At: now.Add(-9 * time.Minute).Format(time.RFC3339), OK: false, AuthMethod: model.AuthPassword,
		Code: "timeout", Error: "连接 203.0.113.11:22 超时（10 秒内没有完成 TCP 握手）", NotExecuted: true, SafeToRetry: true}); err != nil {
		r.t.Fatal(err)
	}

	// One remote device has not answered for three days.
	r.ra.mu.Lock()
	if len(r.ra.st.Peers) > 0 {
		r.ra.st.Peers[0].LatestHandshake = now.Unix() - 3*86400
	}
	r.ra.mu.Unlock()
}

// ---------------------------------------------------- single states ---

// extras are states of one request: the gateway preflight with blocking
// findings, a whole-topology save refused for a changed independent block.
func (r *demoRig) extras() map[string]map[string]demoResponse {
	out := map[string]map[string]demoResponse{}
	resp := func(method, path string, body []byte) demoResponse {
		rr := do(r.s, method, path, body)
		return demoResponse{Status: rr.Code, Body: json.RawMessage(bytes.TrimSpace(rr.Body.Bytes()))}
	}
	r.hp.mu.Lock()
	r.hp.extra = "ipt ipv4 -P FORWARD DROP\nunit docker.service active enabled 7\nss udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"dnsmasq\",pid=9,fd=4))\n"
	r.hp.mu.Unlock()
	out["preflight-blocked"] = map[string]demoResponse{"POST /api/host/preflight": resp(http.MethodPost, "/api/host/preflight", []byte("{}"))}
	r.hp.mu.Lock()
	r.hp.extra = ""
	r.hp.mu.Unlock()

	var topo map[string]any
	if err := json.Unmarshal(r.call(http.MethodGet, "/api/topology", nil, http.StatusOK), &topo); err != nil {
		r.t.Fatal(err)
	}
	if sg, ok := topo["service_groups"].([]any); ok && len(sg) > 0 {
		sg[0].(map[string]any)["target_group"] = "jp"
	}
	out["save-refused"] = map[string]demoResponse{"PUT /api/topology": resp(http.MethodPut, "/api/topology", mustJSON(topo))}
	return out
}

// buildDemo builds every scenario once. The base scenarios (healthy,
// unavailable) have every response; the others only the responses that
// differ from their base (demoScenarioBase).
func buildDemo(t *testing.T) (raw map[string]map[string]demoResponse, ids map[string]string) {
	raw = map[string]map[string]demoResponse{}

	h := newDemoRig(t, true)
	h.resources()
	h.fetchRuleSets()
	h.remoteAccess()
	h.install()
	h.runtimes()
	h.call(http.MethodPost, "/api/lists/update", map[string]any{}, http.StatusAccepted)
	waitJob(t, h.s)
	h.unlock()
	h.hubRead(model.HubPrimary, 20*time.Second, nil)
	h.meshDeploy()
	h.jobIDs()
	raw["healthy"] = h.collect()
	raw["healthy"]["POST /api/host/preflight"] = h.post("/api/host/preflight", "{}")
	for k, v := range h.extras() {
		raw[k] = v
	}
	for k, v := range h.guide() {
		raw[k] = v
	}
	h.degrade()
	h.jobIDs()
	raw["degraded"] = h.collect()

	u := newDemoRig(t, false)
	raw["unavailable"] = u.collect()
	raw["unavailable"]["POST /api/host/preflight"] = u.post("/api/host/preflight", "{}")
	for k, v := range u.ids {
		h.ids[k] = v
	}
	return raw, h.ids
}

// jobIDs gives the probe jobs stable names in the order they ran.
func (r *demoRig) jobIDs() {
	var jobs struct {
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	_ = json.Unmarshal(r.call(http.MethodGet, "/api/unlock/jobs", nil, http.StatusOK), &jobs)
	n := 0
	for _, j := range jobs.Jobs {
		if _, ok := r.ids[j.ID]; ok {
			n++
		}
	}
	for i := len(jobs.Jobs) - 1; i >= 0; i-- {
		if _, ok := r.ids[jobs.Jobs[i].ID]; !ok {
			n++
			r.id(jobs.Jobs[i].ID, fmt.Sprintf("job-demo-%02d", n))
		}
	}
}

// demoScenarioBase is the full scenario each partial one is applied to.
var demoScenarioBase = map[string]string{
	"healthy": "", "unavailable": "", "degraded": "healthy",
	"deploy-running": "healthy", "deploy-rate-limited": "healthy", "deploy-compensated": "healthy", "deploy-unknown": "healthy", "deploy-done": "healthy",
	"preflight-blocked": "healthy", "save-refused": "healthy",
}

// ---------------------------------------------------------- normalize ---

var (
	demoTimeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	// Certificates are random material whose length varies from run to
	// run: their body is replaced by a fixed line (the BEGIN/END lines and
	// the diff prefix stay).
	demoPEMRe   = regexp.MustCompile(`(-----BEGIN CERTIFICATE-----)(\n)([+ -]?)[\s\S]*?(-----END CERTIFICATE-----)`)
	demoTokenRe = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2}|[A-Za-z0-9+/=_-]+`)
)

// demoNormal is a run with the explicit IDs replaced and the times moved
// to the anchor: scenario → "METHOD /path" → {status, body}.
type demoNormal map[string]map[string]any

func normalizeRun(t *testing.T, raw map[string]map[string]demoResponse, ids map[string]string, start time.Time) demoNormal {
	t.Helper()
	keys := make([]string, 0, len(ids))
	for k := range ids {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j]) || len(keys[i]) == len(keys[j]) && keys[i] < keys[j]
	})
	pairs := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		pairs = append(pairs, k, ids[k])
	}
	rep := strings.NewReplacer(pairs...)
	shift := func(s string) string {
		s = demoPEMRe.ReplaceAllString(s, "${1}${2}${3}DEMO-CERTIFICATE-OMITTED${2}${3}${4}")
		return demoTimeRe.ReplaceAllStringFunc(s, func(m string) string {
			tm, err := time.Parse(time.RFC3339Nano, m)
			if err != nil {
				return m
			}
			return demoAnchor.Add(tm.Sub(start).Round(time.Minute)).Format(time.RFC3339)
		})
	}
	out := demoNormal{}
	for sc, m := range raw {
		out[sc] = map[string]any{}
		for k, r := range m {
			dec := json.NewDecoder(strings.NewReader(rep.Replace(string(r.Body))))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("%s %s: %v", sc, k, err)
			}
			if fix := demoFixups[k]; fix != nil {
				fix(v)
			}
			out[sc][rep.Replace(k)] = map[string]any{"status": json.Number(fmt.Sprint(r.Status)), "body": mapStrings(v, shift)}
		}
	}
	return out
}

// demoFixups make orders the handlers leave to chance (map iteration)
// fixed, before the times are moved.
var demoFixups = map[string]func(any){
	// History entries of one ingest share a stamp order that follows map
	// iteration: order them by report, exit, service and family.
	"GET /api/unlock": func(v any) {
		m, _ := v.(map[string]any)
		h, _ := m["history"].([]any)
		key := func(x any) string {
			e, _ := x.(map[string]any)
			return fmt.Sprint(e["exit_id"], "|", e["service"], "|", e["family"], "|", e["kind"], "|", e["observed_at"])
		}
		sort.SliceStable(h, func(i, j int) bool { return key(h[i]) < key(h[j]) })
	},
}

// mapStrings applies f to every string (object keys included).
func mapStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case []any:
		for i := range x {
			x[i] = mapStrings(x[i], f)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[f(k)] = mapStrings(e, f)
		}
		return out
	}
	return v
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tokenMap compares two runs of the same build and maps every token
// (letters, digits and + / = _ -) that differs between them — random
// IDs, keys, fingerprints, digests derived from them — to a stable
// replacement of the same shape. Anything else that differs fails.
func tokenMap(t *testing.T, a, b demoNormal) map[string]string {
	t.Helper()
	mapping := map[string]string{}
	seen := map[string]string{} // b token -> replacement
	n := 0
	var fails []string
	fail := func(path, format string, args ...any) {
		if len(fails) < 20 {
			fails = append(fails, path+": "+fmt.Sprintf(format, args...))
		}
	}
	var walk func(path string, x, y any)
	walk = func(path string, x, y any) {
		switch xa := x.(type) {
		case map[string]any:
			ya, ok := y.(map[string]any)
			if !ok {
				fail(path, "type differs")
				return
			}
			kx, ky := sortedKeys(xa), sortedKeys(ya)
			if len(kx) != len(ky) {
				fail(path, "keys %v vs %v", kx, ky)
				return
			}
			for i := range kx {
				if kx[i] != ky[i] {
					walk(path+".<key>", kx[i], ky[i])
				}
				walk(path+"."+kx[i], xa[kx[i]], ya[ky[i]])
			}
		case []any:
			ya, ok := y.([]any)
			if !ok || len(ya) != len(xa) {
				fail(path, "array differs")
				return
			}
			for i := range xa {
				walk(fmt.Sprintf("%s[%d]", path, i), xa[i], ya[i])
			}
		case string:
			ys, ok := y.(string)
			if !ok {
				fail(path, "type differs")
				return
			}
			if xa == ys {
				return
			}
			ix, iy := demoTokenRe.FindAllStringIndex(xa, -1), demoTokenRe.FindAllStringIndex(ys, -1)
			if len(ix) != len(iy) {
				fail(path, "%q vs %q", clipText(xa, 120), clipText(ys, 120))
				return
			}
			px, py := 0, 0
			for i := range ix {
				if xa[px:ix[i][0]] != ys[py:iy[i][0]] {
					fail(path, "%q vs %q", clipText(xa, 120), clipText(ys, 120))
					return
				}
				tx, ty := xa[ix[i][0]:ix[i][1]], ys[iy[i][0]:iy[i][1]]
				px, py = ix[i][1], iy[i][1]
				if tx == ty {
					continue
				}
				r, okx := mapping[tx]
				r2, oky := seen[ty]
				switch {
				case okx && oky && r != r2, okx != oky:
					fail(path, "token %q/%q mapped inconsistently", tx, ty)
					return
				case !okx:
					n++
					r = demoFake(tx, n)
					mapping[tx], seen[ty] = r, r
				}
			}
			if xa[px:] != ys[py:] {
				fail(path, "%q vs %q", clipText(xa, 120), clipText(ys, 120))
			}
		default:
			if fmt.Sprint(x) != fmt.Sprint(y) {
				fail(path, "%v vs %v", x, y)
			}
		}
	}
	for _, sc := range sortedKeys(a) {
		bs, ok := b[sc]
		if !ok {
			t.Fatalf("scenario %s missing in the second run", sc)
		}
		walk(sc, a[sc], bs)
	}
	if len(fails) > 0 {
		t.Fatalf("the two builds differ in more than random tokens:\n%s", strings.Join(fails, "\n"))
	}
	return mapping
}

// demoFake is a stable stand-in for a random token: the same length and
// the same alphabet (colon-separated hex, hex, or letters and digits with
// + and /), so the output depends only on n, never on which characters
// the random value happened to have. Short all-letter words between
// dashes (prefixes such as "pf", "dep", "boot") are kept.
func demoFake(tok string, n int) string {
	seed := sha256.Sum256([]byte(fmt.Sprintf("meridian-demo-token-%d", n)))
	stream := seed[:]
	next := func() byte {
		if len(stream) == 0 {
			s := sha256.Sum256(seed[:])
			seed = s
			stream = seed[:]
		}
		b := stream[0]
		stream = stream[1:]
		return b
	}
	const (
		hexLower = "0123456789abcdef"
		hexUpper = "0123456789ABCDEF"
		b64      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	)
	var b strings.Builder
	switch {
	case strings.Contains(tok, ":"):
		for _, c := range []byte(tok) {
			if c == ':' {
				b.WriteByte(c)
			} else {
				b.WriteByte(hexUpper[next()%16])
			}
		}
		return b.String()
	case strings.Trim(tok, hexLower) == "":
		for range tok {
			b.WriteByte(hexLower[next()%16])
		}
		return b.String()
	}
	for _, seg := range strings.SplitAfter(tok, "-") {
		word := strings.TrimSuffix(seg, "-")
		if strings.Contains(tok, "-") && word != "" && len(word) <= 8 && strings.Trim(word, "abcdefghijklmnopqrstuvwxyz") == "" {
			b.WriteString(seg)
			continue
		}
		alpha := b64
		if strings.Trim(word, hexLower) == "" {
			alpha = hexLower
		} else if strings.Contains(tok, "-") || strings.Contains(tok, "_") {
			alpha = b64[:62]
		}
		for _, c := range []byte(seg) {
			switch c {
			case '=', '-', '_':
				b.WriteByte(c)
			default:
				b.WriteByte(alpha[int(next())%len(alpha)])
			}
		}
	}
	return b.String()
}

// finalize applies the token map and keeps, for every partial scenario,
// only the responses that differ from its base.
func finalize(n demoNormal, tokens map[string]string) demoNormal {
	sub := func(s string) string {
		return demoTokenRe.ReplaceAllStringFunc(s, func(m string) string {
			if r, ok := tokens[m]; ok {
				return r
			}
			return m
		})
	}
	out := demoNormal{}
	for sc, m := range n {
		out[sc] = mapStrings(m, sub).(map[string]any)
	}
	for sc, base := range demoScenarioBase {
		if base == "" {
			continue
		}
		for k, v := range out[sc] {
			if bv, ok := out[base][k]; ok && demoJSON(bv) == demoJSON(v) {
				delete(out[sc], k)
			}
		}
	}
	return out
}

func demoJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	_ = enc.Encode(v)
	return b.String()
}

// demoFile is one scenario's file.
func demoFile(sc string, responses map[string]any) string {
	return demoJSON(map[string]any{
		"scenario":  sc,
		"base":      demoScenarioBase[sc],
		"anchor":    demoAnchor.Format(time.RFC3339),
		"generator": "internal/api/demo_fixtures_test.go (MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1)",
		"responses": responses,
	})
}

// shapeOf is the structure of a value: object keys with their shapes,
// array elements merged, primitive kinds. Null matches anything.
func shapeOf(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = shapeOf(e)
		}
		return out
	case []any:
		var el any
		for _, e := range x {
			el = mergeShape(el, shapeOf(e))
		}
		return []any{el}
	case string:
		return "string"
	case json.Number, float64:
		return "number"
	case bool:
		return "bool"
	}
	return nil
}

func mergeShape(a, b any) any {
	am, ok1 := a.(map[string]any)
	bm, ok2 := b.(map[string]any)
	if ok1 && ok2 {
		out := map[string]any{}
		for k, v := range am {
			out[k] = v
		}
		for k, v := range bm {
			out[k] = mergeShape(out[k], v)
		}
		return out
	}
	if a == nil {
		return b
	}
	return a
}

// shapeDiff lists the paths where the shapes differ.
func shapeDiff(path string, a, b any, out *[]string) {
	if a == nil || b == nil || len(*out) > 30 {
		return
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			*out = append(*out, path+": object vs "+fmt.Sprint(b))
			return
		}
		for _, k := range sortedKeys(x) {
			if _, ok := y[k]; !ok {
				*out = append(*out, path+"."+k+": only in the committed file")
				continue
			}
			shapeDiff(path+"."+k, x[k], y[k], out)
		}
		for _, k := range sortedKeys(y) {
			if _, ok := x[k]; !ok {
				*out = append(*out, path+"."+k+": only in the handlers' answer")
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok {
			*out = append(*out, path+": array vs "+fmt.Sprint(b))
			return
		}
		shapeDiff(path+"[]", x[0], y[0], out)
	default:
		if fmt.Sprint(a) != fmt.Sprint(b) {
			*out = append(*out, path+": "+fmt.Sprint(a)+" vs "+fmt.Sprint(b))
		}
	}
}

// TestDemoFixtures builds the demo's fixtures from the handlers. With
// MERIDIAN_DEMO_FIXTURES=write it builds them twice (to find the random
// tokens) and writes web/src/demo/generated/*.json; otherwise it builds
// them once and checks that every committed response still has the shape
// (fields, kinds) the handlers produce now, so the demo cannot drift from
// the backend unnoticed.
func TestDemoFixtures(t *testing.T) {
	write := os.Getenv("MERIDIAN_DEMO_FIXTURES") == "write"
	start := time.Now().UTC()
	rawA, idsA := buildDemo(t)
	a := normalizeRun(t, rawA, idsA, start)
	if !write {
		files, err := filepath.Glob(filepath.Join(demoFixtureDir, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no committed demo fixtures in %s (generate them: MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1)", demoFixtureDir)
		}
		if len(files) != len(demoScenarioBase) {
			t.Fatalf("%d fixture files, %d scenarios", len(files), len(demoScenarioBase))
		}
		fresh := finalize(a, nil)
		var diffs []string
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Scenario  string         `json:"scenario"`
				Responses map[string]any `json:"responses"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			got, ok := fresh[doc.Scenario]
			if !ok {
				t.Fatalf("%s: unknown scenario %q", f, doc.Scenario)
			}
			for _, k := range sortedKeys(doc.Responses) {
				gk := k
				if _, ok := got[gk]; !ok {
					// Partial scenarios keep only what differs from their base.
					if base := demoScenarioBase[doc.Scenario]; base != "" {
						if _, ok := fresh[base][k]; ok {
							got[gk] = fresh[base][k]
						}
					}
				}
				if _, ok := got[gk]; !ok {
					diffs = append(diffs, doc.Scenario+" "+k+": the handlers no longer answer it")
					continue
				}
				shapeDiff(doc.Scenario+" "+k, shapeOf(doc.Responses[k]), shapeOf(got[gk]), &diffs)
			}
		}
		if len(diffs) > 0 {
			t.Fatalf("the committed demo fixtures no longer match the handlers (regenerate: MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1):\n%s", strings.Join(diffs, "\n"))
		}
		return
	}
	start = time.Now().UTC()
	rawB, idsB := buildDemo(t)
	b := normalizeRun(t, rawB, idsB, start)
	out := finalize(a, tokenMap(t, a, b))
	if err := os.MkdirAll(demoFixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old, _ := filepath.Glob(filepath.Join(demoFixtureDir, "*.json"))
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	for _, sc := range sortedKeys(out) {
		if err := os.WriteFile(filepath.Join(demoFixtureDir, sc+".json"), []byte(demoFile(sc, out[sc])), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
