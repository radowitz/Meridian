package compile_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/wsstest"
)

func dualHub() model.Topology {
	topo := defaults.DualHubExample()
	model.MigrateRegionGroups(&topo)
	return topo
}

func execStart(t *testing.T, unit string) string {
	t.Helper()
	for _, l := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
			return v
		}
	}
	t.Fatalf("no ExecStart in\n%s", unit)
	return ""
}

// The rendered units: the server reads its prefixes and destinations from
// the 0600 restrictions file and presents the panel's certificate; the
// client verifies the certificate against the trust file only (no system
// roots, no directory), by the synthetic name, and gets the prefix from
// the environment — never from argv, never without verification.
func TestWSSRenderedUnits(t *testing.T) {
	for _, c := range []struct {
		name     string
		topo     model.Topology
		listener string
		port     string
		links    []string // link → client node
		clients  map[string]string
		dial     map[string]string
	}{
		{"single hub", defaults.Example(), "hk-hub", "443", []string{"ali-hub-wss", "gw-hub-wss"},
			map[string]string{"ali-hub-wss": "ali", "gw-hub-wss": "gw"}, map[string]string{"ali-hub-wss": "203.0.113.20:443"}},
		{"relay", defaults.Example(), "ali", "443", []string{"gw-ali"}, map[string]string{"gw-ali": "gw"}, map[string]string{"gw-ali": "203.0.113.10:443"}},
		{"dual hub: backup hub over WSS", dualHub(), "hk5", "8443", []string{"gw-hk5"}, map[string]string{"gw-hk5": "gw"}, nil},
		{"dual hub: relay failover leg", dualHub(), "ali", "8443", []string{"gw-ali"}, map[string]string{"gw-ali": "gw"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := compile.Compile(c.topo)
			if err != nil {
				t.Fatal(err)
			}
			pre := "nodes/" + c.listener + "/"
			srv := b.File(pre + "etc/systemd/system/wstunnel-meridian.service")
			want := "/usr/local/sbin/meridian-wstunnel server --restrict-config /etc/meridian/wss/server.yaml --tls-certificate /etc/meridian/wss/server.crt --tls-private-key /etc/meridian/wss/server.key wss://0.0.0.0:" + c.port
			if got := execStart(t, srv); got != want {
				t.Fatalf("server ExecStart\n got %s\nwant %s", got, want)
			}
			yaml := b.File(pre + "etc/meridian/wss/server.yaml")
			rules := regexp.MustCompile(`(?m)^  - name: "([a-z0-9-]+)"$`).FindAllStringSubmatch(yaml, -1)
			if len(rules) != len(c.links) {
				t.Fatalf("rules %v\n%s", rules, yaml)
			}
			for i, l := range c.links {
				if rules[i][1] != l || !strings.Contains(yaml, `!PathPrefix "^(?:__MERIDIAN_WSS_SRVPATHS_`+l+`__)$"`) {
					t.Fatalf("rule for %s\n%s", l, yaml)
				}
			}
			if !strings.Contains(yaml, "          - Udp\n") || !strings.Contains(yaml, "          - 127.0.0.1/32\n") || strings.Contains(yaml, "0.0.0.0/0") {
				t.Fatalf("restrictions must allow only UDP to 127.0.0.1\n%s", yaml)
			}
			if b.File(pre+"etc/meridian/wss/server.crt") != "__MERIDIAN_WSS_CERT_"+c.listener+"__\n" || b.File(pre+"etc/meridian/wss/server.key") != "__MERIDIAN_WSS_KEY_"+c.listener+"__\n" {
				t.Fatal("certificate and key must be tokens until resolved")
			}
			for _, l := range c.links {
				cp := "nodes/" + c.clients[l] + "/"
				unit := b.File(cp + "etc/systemd/system/wstunnel-client-" + l + ".service")
				ex := execStart(t, unit)
				for _, need := range []string{" client -L 'udp://127.0.0.1:", "?timeout_sec=0' ", " --tls-verify-certificate ", " --tls-sni-override ${MERIDIAN_WSS_SNI} wss://"} {
					if !strings.Contains(ex, need) {
						t.Fatalf("client ExecStart lacks %q: %s", need, ex)
					}
				}
				if d := c.dial[l]; d != "" && !strings.HasSuffix(ex, "wss://"+d) {
					t.Fatalf("dials %s", ex)
				}
				for _, bad := range []string{"--http-upgrade-path-prefix", "-P ", "--tls-sni-disable", "--tls-certificate", "example-wss"} {
					if strings.Contains(ex, bad) {
						t.Fatalf("client ExecStart has %q: %s", bad, ex)
					}
				}
				for _, need := range []string{
					"Environment=SSL_CERT_FILE=/etc/meridian/wss/client-" + l + ".trust.pem\n",
					"Environment=SSL_CERT_DIR=\n",
					"EnvironmentFile=/etc/meridian/wss/client-" + l + ".env\n",
				} {
					if !strings.Contains(unit, need) {
						t.Fatalf("client unit lacks %q\n%s", need, unit)
					}
				}
				env := b.File(cp + "etc/meridian/wss/client-" + l + ".env")
				if !strings.Contains(env, "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=__MERIDIAN_WSS_PATH_"+l+"__\n") || !strings.Contains(env, "MERIDIAN_WSS_SNI=__MERIDIAN_WSS_SNI_"+c.listener+"__\n") {
					t.Fatalf("env\n%s", env)
				}
			}
		})
	}
}

func TestWSSSecretFileRuleMatchesPreflight(t *testing.T) {
	b, err := compile.Compile(dualHub())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for p := range b.Files {
		parts := strings.SplitN(strings.TrimPrefix(p, "nodes/"), "/", 2)
		if !strings.HasPrefix(p, "nodes/") || len(parts) != 2 {
			continue
		}
		host := "/" + parts[1]
		if strings.HasPrefix(host, compile.WSSDir) {
			n++
			if compile.WSSSecretFile(host) != preflight.SecretFile(host) {
				t.Fatalf("%s: compile and preflight disagree", host)
			}
			secret := strings.HasSuffix(host, ".yaml") || strings.HasSuffix(host, ".key") || strings.HasSuffix(host, ".env")
			if compile.WSSSecretFile(host) != secret {
				t.Fatalf("%s secret=%v", host, compile.WSSSecretFile(host))
			}
		}
	}
	if n < 7 {
		t.Fatalf("only %d WSS files", n)
	}
}

// Unresolved material never reaches a host: the gateway install boundary
// and the provision injection refuse a token, and the script preview
// refuses to run.
func TestWSSUnresolvedIsRefused(t *testing.T) {
	b, err := compile.Compile(defaults.Example())
	if err != nil {
		t.Fatal(err)
	}
	rb, plan := compile.ResolveWSS(b, model.WSSState{})
	if len(plan.Missing) == 0 || !compile.HasWSSTokens(rb.File("nodes/ali/etc/meridian/wss/server.yaml")) {
		t.Fatal("missing material must stay visible")
	}
	if _, err := apply.InjectSecrets("etc/meridian/wss/server.crt", rb.File("nodes/ali/etc/meridian/wss/server.crt"), nil); err == nil {
		t.Fatal("token accepted by the install boundary")
	}
	files := provision.FilesFor(rb.Files, "ali")
	if _, err := provision.InjectPrivateWSS(files, strings.Repeat("A", 43)+"=", nil); err == nil {
		t.Fatal("token accepted by the provision injection")
	}
	if s := provision.Script("ali", files); !strings.Contains(s, "refusing") {
		t.Fatal("preview script must refuse")
	}
}

type resolved struct {
	b   *compile.Bundle
	mat wsstest.Material
}

func resolveFresh(t *testing.T, topo model.Topology) resolved {
	t.Helper()
	b, mat := wsstest.Compile(t, topo)
	return resolved{b, mat}
}

// host returns node's injected host files.
func (r resolved) host(t *testing.T, node string) map[string]string {
	t.Helper()
	files := provision.FilesFor(r.b.Files, node)
	kp, _ := provision.GenerateKeypair()
	out, err := provision.InjectPrivateWSS(files, kp.Private, r.mat.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWSSResolveRendersOnePathPerLinkAndNoSecretInBundle(t *testing.T) {
	r := resolveFresh(t, defaults.Example())
	canon := r.b.Canonical()
	for id, v := range r.mat.Secrets {
		for _, line := range strings.Split(v, "\n") {
			if len(line) >= 16 && strings.Contains(canon, line) {
				t.Fatalf("secret %s in the resolved bundle", id)
			}
		}
	}
	if compile.HasWSSTokens(canon) {
		t.Fatal("tokens left")
	}
	st := r.mat.State
	hub := st.Listener("hk-hub")
	yaml := r.b.File("nodes/hk-hub/etc/meridian/wss/server.yaml")
	for _, k := range hub.Links {
		if !strings.Contains(yaml, `"^(?:`+model.SecretPlaceholder(k.Path.SecretID)+`)$"`) {
			t.Fatalf("rule of %s\n%s", k.LinkID, yaml)
		}
	}
	gwEnv := r.b.File("nodes/gw/etc/meridian/wss/client-gw-hub-wss.env")
	if !strings.Contains(gwEnv, model.SecretPlaceholder(hub.Link("gw-hub-wss").Path.SecretID)) || !strings.Contains(gwEnv, "MERIDIAN_WSS_SNI="+hub.ServerName+"\n") {
		t.Fatalf("env\n%s", gwEnv)
	}
	trust := r.b.File("nodes/gw/etc/meridian/wss/client-gw-hub-wss.trust.pem")
	if strings.Count(trust, "BEGIN CERTIFICATE") != 1 || !strings.Contains(trust, strings.TrimSpace(hub.Cert.CertPEM)) || !strings.Contains(trust, hub.Cert.Fingerprint) {
		t.Fatalf("trust\n%s", trust)
	}
	if r.b.File("nodes/hk-hub/etc/meridian/wss/server.key") != model.SecretPlaceholder(hub.Cert.KeySecretID)+"\n" {
		t.Fatal("key placeholder")
	}
	// Distinct per link, and the injected host files carry them.
	h := r.host(t, "hk-hub")
	if strings.Count(h["/etc/meridian/wss/server.yaml"], r.mat.Secrets[hub.Link("gw-hub-wss").Path.SecretID]) != 1 ||
		strings.Count(h["/etc/meridian/wss/server.yaml"], r.mat.Secrets[hub.Link("ali-hub-wss").Path.SecretID]) != 1 {
		t.Fatal("injected restrictions")
	}
	if !credentials.ValidWSSKey(h["/etc/meridian/wss/server.key"]) {
		t.Fatal("injected key")
	}
	// A WSS path may not land in a WireGuard config, a remote-access key
	// not in a WSS file, a key not outside .key.
	pid := hub.Link("gw-hub-wss").Path.SecretID
	if _, err := apply.InjectSecrets("etc/wireguard/m00.conf", "PrivateKey = "+model.SecretPlaceholder(pid)+"\n", r.mat.Secrets); err == nil {
		t.Fatal("path accepted in a WireGuard config")
	}
	if _, err := apply.InjectSecrets("etc/meridian/wss/client-x.env", "X="+model.SecretPlaceholder("ra-key-test")+"\n", map[string]string{"ra-key-test": strings.Repeat("A", 43) + "="}); err == nil {
		t.Fatal("remote-access key accepted in a WSS file")
	}
	if _, err := apply.InjectSecrets("etc/meridian/wss/server.yaml", model.SecretPlaceholder(hub.Cert.KeySecretID), r.mat.Secrets); err == nil {
		t.Fatal("key accepted outside .key")
	}
	if _, err := provision.InjectPrivateWSS(map[string]string{"/etc/wireguard/mra.conf": "PrivateKey = " + model.SecretPlaceholder("ra-key-test") + "\n"}, "", map[string]string{"ra-key-test": strings.Repeat("A", 43) + "="}); err == nil {
		t.Fatal("a remote node must never receive a remote-access secret")
	}
}

// During a rotation each party is rendered at its target stage: the
// server accepts old and new prefixes, the client trusts old and new
// certificates, the server still presents the old one.
func TestWSSResolveRotationStages(t *testing.T) {
	topo := defaults.Example()
	cs := wsstest.Store(t, topo)
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	record := func(node string) {
		_, mat := wsstest.ResolveWith(t, cs, b)
		var ps []credentials.WSSPartyStage
		for _, p := range mat.Plan.ForNode(node) {
			ps = append(ps, credentials.WSSPartyStage{ListenerID: p.ListenerID, Party: p.Party, NodeID: p.NodeID, Stage: p.Stage})
		}
		if err := cs.RecordWSSInstall(node, ps, true, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	record("ali")
	record("gw")
	if _, err := cs.RegenerateWSSPath("gw-ali"); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.RegenerateWSSCert("ali", model.WSSReasonCert); err != nil {
		t.Fatal(err)
	}
	rb, mat := wsstest.ResolveWith(t, cs, b)
	l := mat.State.Listener("ali")
	yaml := rb.File("nodes/ali/etc/meridian/wss/server.yaml")
	if !strings.Contains(yaml, `"^(?:`+model.SecretPlaceholder(l.Links[0].Path.SecretID)+"|"+model.SecretPlaceholder(l.Links[0].Pending.SecretID)+`)$"`) {
		t.Fatalf("stage 1 server must accept both prefixes\n%s", yaml)
	}
	if rb.File("nodes/ali/etc/meridian/wss/server.key") != model.SecretPlaceholder(l.Cert.KeySecretID)+"\n" {
		t.Fatal("stage 1 server still presents the current certificate")
	}
	trust := rb.File("nodes/gw/etc/meridian/wss/client-gw-ali.trust.pem")
	if strings.Count(trust, "BEGIN CERTIFICATE") != 2 || !strings.Contains(trust, l.Pending.Fingerprint) {
		t.Fatalf("stage 1 client must trust both\n%s", trust)
	}
	if !strings.Contains(rb.File("nodes/gw/etc/meridian/wss/client-gw-ali.env"), model.SecretPlaceholder(l.Links[0].Path.SecretID)) {
		t.Fatal("stage 1 client still sends the current prefix")
	}
	// The other listener (hk-hub) is not affected.
	if strings.Count(rb.File("nodes/gw/etc/meridian/wss/client-gw-hub-wss.trust.pem"), "BEGIN CERTIFICATE") != 1 {
		t.Fatal("unrelated listener changed")
	}
	stages := map[string]int{}
	for _, p := range mat.Plan.Parties {
		if p.ListenerID == "ali" {
			stages[p.Party] = p.Stage
		}
	}
	if stages["server"] != 1 || stages["client:gw-ali"] != 1 {
		t.Fatalf("plan %+v", stages)
	}
}

// prefixRule mirrors wstunnel 11.1.0's server: the path prefix is the first
// segment of "/<prefix>/.../events"; a restriction matches when its
// PathPrefix regex matches that segment; the allowed destination is the
// rule's port.
type prefixRule struct {
	link string
	re   *regexp.Regexp
	port string
}

func parseRules(t *testing.T, yaml string) []prefixRule {
	t.Helper()
	re := regexp.MustCompile(`(?s)  - name: "([a-z0-9-]+)"\n    match:\n      - !PathPrefix "([^"]+)"\n.*?port:\n          - "([0-9]+)"`)
	var out []prefixRule
	for _, m := range re.FindAllStringSubmatch(yaml, -1) {
		out = append(out, prefixRule{link: m[1], re: regexp.MustCompile(m[2]), port: m[3]})
	}
	if len(out) == 0 {
		t.Fatalf("no rules\n%s", yaml)
	}
	return out
}

func allowedPort(rules []prefixRule, path string) string {
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	l, r, ok := strings.Cut(path[1:], "/")
	if !ok || !strings.HasSuffix(r, "events") {
		return ""
	}
	for _, x := range rules {
		if x.re.MatchString(l) {
			return x.port
		}
	}
	return ""
}

func envValue(env, key string) string {
	for _, l := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return v
		}
	}
	return ""
}

// Structural verification of the negatives (the real binary: the opt-in
// TestWstunnelRealBinary): with the injected files of a listener and its
// clients, the right prefix reaches only its own link's port, a wrong or
// other link's prefix none; the client's TLS settings (trust file as the
// only roots, the name from the env file) accept the listener's
// certificate and reject another listener's certificate and another name.
func TestWSSVerificationNegativesStructural(t *testing.T) {
	r := resolveFresh(t, defaults.Example())
	hub := r.host(t, "hk-hub")
	gw := r.host(t, "gw")
	ali := r.host(t, "ali")
	rules := parseRules(t, hub["/etc/meridian/wss/server.yaml"])
	gwPath := envValue(gw["/etc/meridian/wss/client-gw-hub-wss.env"], "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX")
	aliPath := envValue(ali["/etc/meridian/wss/client-ali-hub-wss.env"], "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX")
	relayPath := envValue(gw["/etc/meridian/wss/client-gw-ali.env"], "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX")
	if len(gwPath) != 48 || len(aliPath) != 48 || gwPath == aliPath || gwPath == relayPath {
		t.Fatalf("paths %q %q %q", gwPath, aliPath, relayPath)
	}
	gwPort, aliPort := "", ""
	for _, x := range rules {
		switch x.link {
		case "gw-hub-wss":
			gwPort = x.port
		case "ali-hub-wss":
			aliPort = x.port
		}
	}
	if p := allowedPort(rules, "/"+gwPath+"/events"); p != gwPort || p == "" {
		t.Fatalf("own prefix → %q, want %q", p, gwPort)
	}
	if p := allowedPort(rules, "/"+aliPath+"/events"); p != aliPort || p == gwPort {
		t.Fatal("a link's prefix must reach only its own port")
	}
	for _, bad := range []string{"/" + relayPath + "/events", "/example-wss-path-prefix/events", "/v1/events", "/" + gwPath[:47] + "/events",
		"/" + gwPath + "x/events", "/x" + gwPath + "/events", "/" + strings.ToUpper(gwPath) + "/events", "/", "/" + gwPath, "/" + gwPath + "/"} {
		if p := allowedPort(rules, bad); p != "" {
			t.Fatalf("%s accepted (port %s)", bad, p)
		}
	}
	// TLS: the listener presents server.crt/server.key; the client trusts
	// only its trust file and verifies MERIDIAN_WSS_SNI.
	pair, err := tls.X509KeyPair([]byte(hub["/etc/meridian/wss/server.crt"]), []byte(hub["/etc/meridian/wss/server.key"]))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	dial := func(trustFile, name string) error {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(trustFile)) {
			t.Fatal("trust file has no certificate")
		}
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: name})
		if err == nil {
			c.Close()
		}
		return err
	}
	sni := envValue(gw["/etc/meridian/wss/client-gw-hub-wss.env"], "MERIDIAN_WSS_SNI")
	if err := dial(gw["/etc/meridian/wss/client-gw-hub-wss.trust.pem"], sni); err != nil {
		t.Fatalf("the pinned listener was refused: %v", err)
	}
	if err := dial(gw["/etc/meridian/wss/client-gw-ali.trust.pem"], sni); err == nil {
		t.Fatal("another listener's trust file accepted this certificate")
	}
	if err := dial(gw["/etc/meridian/wss/client-gw-hub-wss.trust.pem"], envValue(gw["/etc/meridian/wss/client-gw-ali.env"], "MERIDIAN_WSS_SNI")); err == nil {
		t.Fatal("a different name was accepted")
	}
}
