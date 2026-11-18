package acceptance

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/verify"
)

// memKV is an in-memory KV with an optional write fault.
type memKV struct {
	m    map[string]string
	fail error
}

func (k *memKV) Get(key string) (string, bool, error) { v, ok := k.m[key]; return v, ok, nil }
func (k *memKV) Put(key, value string) error {
	if k.fail != nil {
		return k.fail
	}
	if k.m == nil {
		k.m = map[string]string{}
	}
	k.m[key] = value
	return nil
}

// The minimum catalog: ids, where they are linked from, impact and time,
// how they are carried out and which fixed action they use.
func TestCatalogMinimum(t *testing.T) {
	want := []struct {
		id         string
		pages      []string
		interrupts bool
		max        int
		impact     string
		duration   string
		mode       string
		action     string
		parts      []string
	}{
		{"config-audit", []string{"leak", "deploy"}, false, 0, "不打断", "约 10 秒", ModeAuto, ActionConfigAudit, []string{PartConfig}},
		{"gateway-health", []string{"deploy", ""}, false, 0, "不打断", "约 30 秒", ModeAuto, hostexec.ActionHealth, []string{PartMeasured}},
		{"ipv6-firewall-reload", []string{"leak"}, true, 120, "可能短断", "最多 120 秒", ModeDrill, hostexec.DrillFirewallReload, []string{PartConfig, PartMeasured, PartSignoff}},
		{"dns-leak", []string{"dns", "leak"}, false, 0, "不打断", "约 2–5 分钟", ModeAuto, ActionResolverCheck, []string{PartConfig, PartMeasured, PartSignoff}},
		{"mesh-e2e", []string{"cloudflare", "topology"}, false, 0, "不打断", "约 1–3 分钟", ModeAuto, hostexec.CheckTunnelPaths, []string{PartConfig, PartMeasured, PartSignoff}},
		{"relay-removal", []string{"topology", "deploy"}, true, 180, "可能短断", "最多 180 秒", ModeDrill, hostexec.DrillRelayIsolation, []string{PartMeasured}},
		{"hub-failover", []string{"topology", "deploy"}, true, 180, "可能短断", "最多 180 秒", ModeDrill, hostexec.DrillHubIsolation, []string{PartMeasured}},
		{"unlock", []string{"unlock"}, false, 0, "不打断", "约 1–5 分钟", ModeAuto, ActionProbe, []string{PartMeasured, PartSignoff}},
		{"remote-access", []string{"remote"}, false, 0, "不打断现有上网", "约 5–10 分钟", ModeManual, "", []string{PartConfig, PartSignoff}},
	}
	for _, w := range want {
		it, ok := Lookup(w.id)
		if !ok {
			t.Fatalf("catalog lacks %s", w.id)
		}
		var pages []string
		for _, s := range it.Sources {
			pages = append(pages, s.Page)
		}
		if strings.Join(pages, ",") != strings.Join(w.pages, ",") {
			t.Errorf("%s: pages %v, want %v", w.id, pages, w.pages)
		}
		if it.Interrupts != w.interrupts || it.MaxSeconds != w.max || it.Impact != w.impact || !strings.HasPrefix(it.Duration, w.duration) {
			t.Errorf("%s: impact %v %d %q %q", w.id, it.Interrupts, it.MaxSeconds, it.Impact, it.Duration)
		}
		if it.Mode != w.mode || it.Action != w.action || strings.Join(it.Parts, ",") != strings.Join(w.parts, ",") {
			t.Errorf("%s: mode %q action %q parts %v", w.id, it.Mode, it.Action, it.Parts)
		}
	}
	// The separate leak-checklist items keep their own ids, steps and
	// evidence source.
	for _, id := range []string{"tunnel-cut", "webrtc", "router-ula", "integration-gateway-verify", "integration-netns-reload", "integration-smartdns", "integration-mesh-veth", "integration-host-exec", "integration-lists-update"} {
		it, ok := Lookup(id)
		if !ok || it.Mode != ModeManual || len(it.Steps) < 3 || it.EvidenceSource == "" || len(it.LeakItems) != 1 || !it.Needs(PartSignoff) {
			t.Errorf("%s: %+v", id, it)
		}
	}
	if it, _ := Lookup("remote-access"); !strings.Contains(it.Deferred, "本轮没有执行") {
		t.Errorf("remote-access must say it was not carried out: %q", it.Deferred)
	}
	if it, _ := Lookup("config-audit"); !strings.Contains(it.NotProves, "不等于实机通过") {
		t.Errorf("config-audit must say what it does not prove: %q", it.NotProves)
	}
	if it, _ := Lookup("dns-leak"); !strings.Contains(it.NotProves, "不等于没有泄漏") || len(it.Steps) == 0 {
		t.Errorf("dns-leak: an answering resolver must not pass for no leak: %q", it.NotProves)
	}
}

var idRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// Every item is complete, and what interrupts traffic is a drill with a
// confirmation, a restore and a bound.
func TestCatalogItemsAreComplete(t *testing.T) {
	hostActions := map[string]bool{
		hostexec.ActionHealth: true, hostexec.DrillFirewallReload: true, hostexec.DrillRelayIsolation: true,
		hostexec.DrillHubIsolation: true, hostexec.CheckTunnelPaths: true,
		ActionConfigAudit: true, ActionResolverCheck: true, ActionProbe: true,
	}
	seen := map[string]bool{}
	for _, it := range Catalog() {
		if !idRe.MatchString(it.ID) || seen[it.ID] {
			t.Errorf("id %q is malformed or repeated", it.ID)
		}
		seen[it.ID] = true
		if it.Title == "" || it.What == "" || len(it.Sources) == 0 || it.Impact == "" || it.Duration == "" || it.StaleWhen == "" || len(it.Parts) == 0 {
			t.Errorf("%s is incomplete: %+v", it.ID, it)
		}
		switch it.Mode {
		case ModeDrill:
			if !it.Interrupts || it.MaxSeconds <= 0 || it.MaxSeconds > 180 || it.Confirm == "" || it.Restore == "" || !strings.HasPrefix(it.Action, "drill_") || it.Validation == "" {
				t.Errorf("drill %s lacks a bound, a confirmation, a restore or a fixed action", it.ID)
			}
		case ModeAuto:
			if it.Interrupts || it.MaxSeconds != 0 || it.Action == "" || it.Validation == "" || it.Proves == "" || it.NotProves == "" {
				t.Errorf("check %s: %+v", it.ID, it)
			}
		case ModeManual:
			if it.Action != "" || len(it.Steps) == 0 || it.EvidenceSource == "" || !it.Needs(PartSignoff) || it.Needs(PartMeasured) {
				t.Errorf("manual %s: %+v", it.ID, it)
			}
		default:
			t.Errorf("%s: mode %q", it.ID, it.Mode)
		}
		if it.Action != "" && !hostActions[it.Action] {
			t.Errorf("%s names action %q, which is not a fixed action", it.ID, it.Action)
		}
		if it.Needs(PartSignoff) && len(it.Steps) == 0 {
			t.Errorf("%s needs a sign-off but has no steps", it.ID)
		}
		for _, banned := range []string{"任意命令", "自定义命令", "shell"} {
			if strings.Contains(it.ActionNote+it.Validation, banned) {
				t.Errorf("%s: action text mentions %q", it.ID, banned)
			}
		}
	}
}

// Every integration and human item of the leak checklist is carried out by
// exactly one acceptance item of its own: none is merged into a general
// "passed", and every configuration check an item names exists.
func TestCatalogCoversLeakChecklist(t *testing.T) {
	topo := model.Topology{}
	topo.RemoteAccess = &model.RemoteAccess{Enabled: true, ListenPort: 51820}
	topo.Settings.Sniff = &model.SniffSettings{Enabled: true}
	scopes := map[string]string{}
	for _, v := range verify.CheckBundle(topo, map[string]string{}) {
		scopes[v.ID] = v.Scope
		if v.Scope != verify.ScopeIntegration && v.Scope != verify.ScopeHuman {
			continue
		}
		it, ok := ForLeakItem(v.ID)
		if !ok {
			t.Errorf("leak item %s (%s) has no acceptance item", v.ID, v.Title)
			continue
		}
		if !it.Needs(PartSignoff) {
			t.Errorf("leak item %s maps to %s, which has no sign-off part", v.ID, it.ID)
		}
	}
	for _, it := range Catalog() {
		for _, id := range it.LeakItems {
			if s := scopes[id]; s != verify.ScopeIntegration && s != verify.ScopeHuman {
				t.Errorf("%s names leak item %q, which is not an integration or human item (%q)", it.ID, id, s)
			}
		}
		for _, id := range it.ConfigChecks {
			if scopes[id] != verify.ScopeAutomated {
				t.Errorf("%s names configuration check %q, which the leak checklist does not have", it.ID, id)
			}
		}
		for _, id := range it.Limits {
			if scopes[id] != verify.ScopeLimitation {
				t.Errorf("%s names limit %q, which the leak checklist does not have", it.ID, id)
			}
		}
	}
	// The dedicated item wins over a broad one that only lists it as related.
	if it, _ := ForLeakItem("netns_reload_no_leak"); it.ID != "integration-netns-reload" {
		t.Errorf("netns_reload_no_leak -> %s", it.ID)
	}
	if it, _ := ForLeakItem("tunnel_cut"); it.ID != "tunnel-cut" {
		t.Errorf("tunnel_cut -> %s", it.ID)
	}
	if it, _ := ForLeakItem("ros_ula_blackhole"); it.ID != "router-ula" {
		t.Errorf("ros_ula_blackhole -> %s", it.ID)
	}
	if it, _ := ForLeakItem("webrtc_srflx"); it.ID != "webrtc" {
		t.Errorf("webrtc_srflx -> %s", it.ID)
	}
	if _, ok := ForLeakItem("no_such"); ok {
		t.Error("unknown leak item resolved")
	}
}

// docs/verification.md publishes the catalog: every id with its impact,
// its bound and its fixed action.
func TestCatalogIsPublishedInDocs(t *testing.T) {
	raw, err := os.ReadFile("../../docs/verification.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i := strings.Index(doc, "## 验收目录")
	if i < 0 {
		t.Fatal("docs/verification.md has no 「验收目录」 section")
	}
	sec := doc[i:]
	if j := strings.Index(sec[1:], "\n## "); j > 0 {
		sec = sec[:j+1]
	}
	for _, it := range Catalog() {
		row := ""
		for _, l := range strings.Split(sec, "\n") {
			if strings.HasPrefix(l, "| `"+it.ID+"` |") {
				row = l
			}
		}
		if row == "" {
			t.Errorf("the table has no row for %s", it.ID)
			continue
		}
		if !strings.Contains(row, it.Impact) {
			t.Errorf("%s: the row does not state the impact %q", it.ID, it.Impact)
		}
		if it.Action != "" && !strings.Contains(row, "`"+it.Action+"`") {
			t.Errorf("%s: the row does not name the action %s", it.ID, it.Action)
		}
		for _, s := range it.Sources {
			if !strings.Contains(row, strings.SplitN(s.Label, "（", 2)[0]) {
				t.Errorf("%s: the row does not name the page %s", it.ID, s.Label)
			}
		}
	}
}

func res(item, part, outcome, fp string, at time.Time) Result {
	return Result{ItemID: item, Part: part, Method: ModeAuto, Outcome: outcome, Fingerprint: fp, At: at, Summary: "s"}
}

// Results are kept per part; a changed fingerprint keeps them and marks
// them stale; the state never merges the parts into one "passed".
func TestStoreViewAndStaleness(t *testing.T) {
	kv := &memKV{}
	s := NewStore(kv)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fp1, fp2 := Fingerprint("c1", "i1", 7), Fingerprint("c1", "i1", 8)
	if fp1 == fp2 || len(fp1) != 64 || Fingerprint("c2", "i1", 7) == fp1 || Fingerprint("c1", "i2", 7) == fp1 {
		t.Fatal("the fingerprint must change with the compiled config, the installed digest and the installed version")
	}
	v, err := s.View(fp1)
	if err != nil || v["dns-leak"].State != StateNotRun || len(v["dns-leak"].Parts) != 3 || len(v) != len(Catalog()) {
		t.Fatalf("%+v %v", v["dns-leak"], err)
	}
	// The measurement passes: the item is only partly verified.
	if _, err := s.Add(res("dns-leak", PartMeasured, OutcomePass, fp1, t0)); err != nil {
		t.Fatal(err)
	}
	v, _ = s.View(fp1)
	if got := v["dns-leak"]; got.State != StatePartial || got.Parts[1].Valid == nil || got.Parts[2].Valid != nil {
		t.Fatalf("an answering resolver alone verified the item: %+v", got)
	}
	// Config evidence and the sign-off complete it.
	s.Add(res("dns-leak", PartConfig, OutcomePass, fp1, t0.Add(time.Minute)))
	signed, err := s.Add(Result{ItemID: "dns-leak", Part: PartSignoff, Method: ModeManual, Outcome: OutcomePass, Fingerprint: fp1, At: t0.Add(2 * time.Minute), Note: "测试机 192.0.2.10 截图存档于 evidence/dns-1.png"})
	if err != nil || strings.Contains(signed.Note, "192.0.2.10") || !strings.Contains(signed.Note, "dns-1.png") || !strings.HasPrefix(signed.ID, "acc-") {
		t.Fatalf("%+v %v", signed, err)
	}
	v, _ = s.View(fp1)
	if v["dns-leak"].State != StateVerified || len(v["dns-leak"].History) != 3 || v["dns-leak"].History[0].Part != PartSignoff {
		t.Fatalf("%+v", v["dns-leak"])
	}
	// The installed version changes: everything is kept and stale.
	v, _ = s.View(fp2)
	got := v["dns-leak"]
	if got.State != StateStale || len(got.History) != 3 || !got.History[0].Stale {
		t.Fatalf("%+v", got)
	}
	for _, p := range got.Parts {
		if p.Valid != nil || p.Latest == nil || !p.Latest.Stale {
			t.Fatalf("part %s: %+v", p.Part, p)
		}
	}
	// A new failing sign-off under the new fingerprint: failed, whatever
	// the old results said.
	s.Add(Result{ItemID: "dns-leak", Part: PartSignoff, Method: ModeManual, Outcome: OutcomeFail, Fingerprint: fp2, At: t0.Add(time.Hour)})
	v, _ = s.View(fp2)
	if v["dns-leak"].State != StateFailed {
		t.Fatalf("%+v", v["dns-leak"])
	}
	// A drill whose restore was not verified is failed, never passed; the
	// later state of the same run replaces it.
	if _, err := s.Add(Result{ItemID: "relay-removal", RunID: "drill-1", Part: PartMeasured, Method: ModeDrill, Outcome: OutcomeRestoreFailed, Fingerprint: fp1, At: t0, Residual: []string{"承载路径不同"}}); err != nil {
		t.Fatal(err)
	}
	v, _ = s.View(fp1)
	if v["relay-removal"].State != StateFailed {
		t.Fatalf("%+v", v["relay-removal"])
	}
	if got, ok, _ := s.FindRun("relay-removal", PartMeasured, "drill-1"); !ok || got.Outcome != OutcomeRestoreFailed {
		t.Fatalf("FindRun: %+v %v", got, ok)
	}
	if _, ok, _ := s.FindRun("relay-removal", PartMeasured, "drill-2"); ok {
		t.Fatal("FindRun found a run that was never stored")
	}
	s.Add(Result{ItemID: "relay-removal", RunID: "drill-1", Part: PartMeasured, Method: ModeDrill, Outcome: OutcomePass, Fingerprint: fp1, At: t0.Add(time.Minute)})
	v, _ = s.View(fp1)
	if v["relay-removal"].State != StateVerified || len(v["relay-removal"].History) != 1 {
		t.Fatalf("%+v", v["relay-removal"])
	}
	// Cancelled or inconclusive decides nothing.
	s.Add(res("hub-failover", PartMeasured, OutcomeCancelled, fp1, t0))
	v, _ = s.View(fp1)
	if v["hub-failover"].State != StateInconclusive {
		t.Fatalf("%+v", v["hub-failover"])
	}
	// Survives a new store on the same KV (a panel restart).
	v2, err := NewStore(kv).View(fp1)
	if err != nil || v2["relay-removal"].State != StateVerified {
		t.Fatalf("%+v %v", v2["relay-removal"], err)
	}
}

func TestStoreRefusesAndBounds(t *testing.T) {
	kv := &memKV{}
	s := NewStore(kv)
	fp := Fingerprint("c", "i", 1)
	if _, err := s.Add(res("no-such-item", PartMeasured, OutcomePass, fp, time.Now())); !errors.Is(err, ErrUnknownItem) {
		t.Fatalf("%v", err)
	}
	// A manual item has no measured part; a check has no way to be
	// "passed" by hand under another part.
	if _, err := s.Add(res("webrtc", PartMeasured, OutcomePass, fp, time.Now())); err == nil {
		t.Fatal("stored a measurement for a manual item")
	}
	if _, err := s.Add(res("gateway-health", PartSignoff, OutcomePass, fp, time.Now())); err == nil {
		t.Fatal("stored a sign-off for an item without that part")
	}
	if _, err := s.Add(res("gateway-health", PartMeasured, "great", fp, time.Now())); err == nil {
		t.Fatal("stored an unknown outcome")
	}
	if _, err := s.Add(res("gateway-health", PartMeasured, OutcomePass, "", time.Now())); err == nil {
		t.Fatal("stored a result without a fingerprint")
	}
	// History is bounded, newest kept.
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < MaxPerItem+5; i++ {
		if _, err := s.Add(res("gateway-health", PartMeasured, OutcomePass, fp, t0.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := s.View(fp)
	h := v["gateway-health"].History
	if len(h) != MaxPerItem || !h[0].At.Equal(t0.Add(time.Duration(MaxPerItem+4)*time.Minute)) {
		t.Fatalf("%d %v", len(h), h[0].At)
	}
	// Long evidence is cut.
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, strings.Repeat("证", 400))
	}
	r, _ := s.Add(Result{ItemID: "gateway-health", Part: PartMeasured, Method: ModeAuto, Outcome: OutcomePass, Fingerprint: fp, Details: lines, Summary: strings.Repeat("总", 900)})
	if len(r.Details) != MaxDetails+1 || len([]rune(r.Details[0])) > 301 || len([]rune(r.Summary)) > 301 {
		t.Fatalf("%d %d %d", len(r.Details), len([]rune(r.Details[0])), len([]rune(r.Summary)))
	}
	// A write that fails is an error, not a silent loss.
	kv.fail = errors.New("disk full")
	if _, err := s.Add(res("gateway-health", PartMeasured, OutcomePass, fp, time.Now())); err == nil {
		t.Fatal("a failed write was reported as stored")
	}
	// A damaged document is an error.
	kv.fail = nil
	kv.m[Key] = "{broken"
	if _, err := s.View(fp); err == nil {
		t.Fatal("a damaged document was read as empty")
	}
}

func TestRedactNote(t *testing.T) {
	cases := map[string][]string{ // input -> substrings that must be gone
		"测试机 192.0.2.10 经 198.51.100.7:51820 出去":          {"192.0.2.10", "198.51.100.7"},
		"v6 是 2001:db8::1 和 2001:db8:1:2:3:4:5:6/64":      {"2001:db8"},
		"域名 relay.example.com 与 sub.example.org 都通":       {"example.com", "example.org"},
		"截图在 https://files.example.net/a/b?token=abc":     {"files.example.net", "token=abc", "https://"},
		"联系人 ops@example.com":                             {"ops@example.com", "example.com"},
		"MAC 02:00:5e:10:00:01":                           {"02:00:5e:10:00:01"},
		"密码: hunter2-very-secret 已改":                      {"hunter2"},
		"token=abcdef0123456789":                          {"abcdef0123456789"},
		"公钥 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=": {"AAAAAAAAAAAAAAAAAAAA"},
		"a\x00b\x1bc\nd":                                  {"\x00", "\x1b", "\n"},
	}
	for in, gone := range cases {
		out := RedactNote(in)
		for _, g := range gone {
			if strings.Contains(out, g) {
				t.Errorf("RedactNote(%q) = %q still contains %q", in, out, g)
			}
		}
	}
	// What a note is for stays readable.
	keep := "2026-01-02 12:30:05 张三在测试机上做了 dnsleaktest，截图存档 evidence/dns-leak-1.png，脚本 meridian-verify.sh 通过，meridian.service 正常，耗时 3 分钟"
	out := RedactNote(keep)
	for _, k := range []string{"12:30:05", "dns-leak-1.png", "meridian-verify.sh", "meridian.service", "3 分钟", "张三"} {
		if !strings.Contains(out, k) {
			t.Errorf("RedactNote removed %q: %q", k, out)
		}
	}
	if n := len([]rune(RedactNote(strings.Repeat("好", 2000)))); n != MaxNote+1 {
		t.Errorf("note length %d", n)
	}
}

// A confirmation is bound to the item, the action, the target and the
// fingerprint, expires, and is used once.
func TestConfirmations(t *testing.T) {
	var c Confirmations
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fp := Fingerprint("c", "i", 1)
	issue := func() Confirmation {
		return c.Issue("relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now)
	}
	cf := issue()
	if len(cf.Token) != 32 || !cf.ExpiresAt.Equal(now.Add(ConfirmTTLSeconds*time.Second)) {
		t.Fatalf("%+v", cf)
	}
	if err := c.Redeem(cf.Token, "relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Used once.
	if err := c.Redeem(cf.Token, "relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now.Add(2*time.Second)); !errors.Is(err, ErrConfirmMissing) {
		t.Fatalf("second use: %v", err)
	}
	if err := c.Redeem("", "relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now); !errors.Is(err, ErrConfirmMissing) {
		t.Fatalf("no token: %v", err)
	}
	if err := c.Redeem("ffffffffffffffffffffffffffffffff", "relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now); !errors.Is(err, ErrConfirmMissing) {
		t.Fatalf("unknown token: %v", err)
	}
	// Expired.
	cf = issue()
	if err := c.Redeem(cf.Token, "relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now.Add((ConfirmTTLSeconds+1)*time.Second)); !errors.Is(err, ErrConfirmExpired) {
		t.Fatalf("expired: %v", err)
	}
	// Another target, action, item or fingerprint: refused, and the token
	// is spent.
	for name, f := range map[string]func(tok string) error{
		"target": func(tok string) error {
			return c.Redeem(tok, "relay-removal", hostexec.DrillRelayIsolation, "relay-b", fp, now)
		},
		"action": func(tok string) error {
			return c.Redeem(tok, "relay-removal", hostexec.DrillHubIsolation, "relay-a", fp, now)
		},
		"item": func(tok string) error {
			return c.Redeem(tok, "hub-failover", hostexec.DrillRelayIsolation, "relay-a", fp, now)
		},
		"fingerprint": func(tok string) error {
			return c.Redeem(tok, "relay-removal", hostexec.DrillRelayIsolation, "relay-a", Fingerprint("c", "i", 2), now)
		},
	} {
		cf = issue()
		if err := f(cf.Token); !errors.Is(err, ErrConfirmChanged) {
			t.Fatalf("%s changed: %v", name, err)
		}
		if err := c.Redeem(cf.Token, "relay-removal", hostexec.DrillRelayIsolation, "relay-a", fp, now); !errors.Is(err, ErrConfirmMissing) {
			t.Fatalf("%s: the token survived a refused use: %v", name, err)
		}
	}
}

func TestMeshAcceptanceRequiresSameExitWireGuard(t *testing.T) {
	it, ok := Lookup("mesh-e2e")
	if !ok {
		t.Fatal("missing Mesh item")
	}
	steps := strings.Join(it.Steps, "\n")
	for _, want := range []string{"WireGuard UDP", "公网地址", "恢复", "枢纽 WAN", "existing_host", "对端 Mesh 地址", "默认路由", "原样保留", "panel-owned", "签名公钥指纹", "nft 丢弃"} {
		if !strings.Contains(steps, want) {
			t.Errorf("missing acceptance criterion %q", want)
		}
	}
	for _, old := range []string{"确认该出口表切到 mmesh", "成员全部失效", "共享 sidecar", "mmesh 只承载"} {
		if strings.Contains(steps, old) {
			t.Errorf("legacy acceptance step: %q", old)
		}
	}
	if !it.Needs(PartSignoff) {
		t.Fatal("publication and gateway handshakes cannot verify Mesh forwarding")
	}
}
