package compile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/model"
)

// WSS carrier rendering (see docs/architecture.md「WSS 承载：随机路径与自签证书」).
//
// The compiler is a pure function of the topology, so it renders the WSS
// files with tokens (__MERIDIAN_WSS_<KIND>_<id>__) where per-listener
// material goes: ResolveWSS replaces them from the panel's WSS state
// (certificates, synthetic names, and the credential-store placeholders
// of the secrets), choosing each party's rotation stage. The secrets
// themselves (path prefixes, private key) stay __MERIDIAN_SECRET_<id>__
// placeholders until the install boundary. A bundle that still carries a
// token is refused by every install path: the WSS carrier never runs with
// missing material or without certificate verification.
//
// wstunnel 11.1.0 has no certificate or public-key pinning option. Its
// client verifies the server (--tls-verify-certificate) against the root
// store that rustls-native-certs 0.8 loads, which reads only SSL_CERT_FILE
// when that variable is set (SSL_CERT_DIR is set empty so no directory is
// added). The unit therefore points SSL_CERT_FILE at a trust file holding
// only the listener's self-signed certificate(s), and verifies the name
// given by --tls-sni-override (also the SNI it sends): a different
// certificate, a different name or an expired certificate fails the TLS
// handshake. The path prefix reaches the client through the environment
// (WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX, clap's env for
// --http-upgrade-path-prefix) from a 0600 file, never through argv.
// The server reads its accepted prefixes from a 0600 --restrict-config
// file: one rule per link, matching only that link's prefix(es) and
// allowing only UDP to that link's local WireGuard port.

// Host paths of the WSS files.
const (
	WSSDir        = "/etc/meridian/wss"
	WSSServerYAML = WSSDir + "/server.yaml"
	WSSServerCert = WSSDir + "/server.crt"
	WSSServerKey  = WSSDir + "/server.key"
	WSSServerUnit = "wstunnel-meridian.service"
)

// WSSClientEnv / WSSClientTrust are a link's client files.
func WSSClientEnv(linkID string) string   { return WSSDir + "/client-" + linkID + ".env" }
func WSSClientTrust(linkID string) string { return WSSDir + "/client-" + linkID + ".trust.pem" }

// WSSClientUnit is a link's client unit name.
func WSSClientUnit(linkID string) string { return "wstunnel-client-" + linkID + ".service" }

// WSSSecretFile reports whether a host path (with or without the leading
// slash) is a WSS file that carries a secret (installed 0600 in a 0700
// directory): the restrictions (accepted prefixes), the private key and
// the client environment (prefix). The certificate and trust files are
// public.
func WSSSecretFile(p string) bool {
	p = "/" + strings.TrimPrefix(p, "/")
	if !strings.HasPrefix(p, WSSDir+"/") {
		return false
	}
	return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".key") || strings.HasSuffix(p, ".env")
}

// Token kinds.
const (
	wssTokServerPaths = "SRVPATHS"
	wssTokCert        = "CERT"
	wssTokKey         = "KEY"
	wssTokPath        = "PATH"
	wssTokSNI         = "SNI"
	wssTokTrust       = "TRUST"
)

// WSSTokenRe matches an unresolved WSS token.
var WSSTokenRe = regexp.MustCompile(`__MERIDIAN_WSS_(SRVPATHS|CERT|KEY|PATH|SNI|TRUST)_([a-z0-9][a-z0-9-]{0,40})__`)

func wssToken(kind, id string) string { return "__MERIDIAN_WSS_" + kind + "_" + id + "__" }

// HasWSSTokens reports whether text still carries an unresolved token.
func HasWSSTokens(text string) bool { return WSSTokenRe.MatchString(text) }

// WSSEnds lists every enabled WSS link with its listening and dialing node
// (the same ends buildTunnels uses). Links whose ends cannot be resolved
// are skipped.
func WSSEnds(t model.Topology) []model.WSSEnd {
	var out []model.WSSEnd
	for _, l := range t.Links {
		if !l.Enabled {
			continue
		}
		switch l.Transport {
		case model.TransportWGOverWSS, model.TransportUDPWSSFailover, model.TransportIXReplacementWSS:
		default:
			continue
		}
		west, east, err := materialize(t, l)
		if err != nil {
			continue
		}
		lis, dial := east.node, west.node
		if east.node.NatDialOut {
			lis, dial = west.node, east.node
		}
		out = append(out, model.WSSEnd{LinkID: l.ID, ListenerID: lis.ID, DialerID: dial.ID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LinkID < out[j].LinkID })
	return out
}

// WstunnelServerArgs are the server's arguments (also used by the opt-in
// real-binary test).
func WstunnelServerArgs(yaml, cert, key string, listen string) []string {
	return []string{"server",
		"--restrict-config", yaml,
		"--tls-certificate", cert,
		"--tls-private-key", key,
		"wss://" + listen,
	}
}

// WstunnelClientArgs are the client's arguments: the name to verify is
// sni (the unit passes ${MERIDIAN_WSS_SNI}); the trust file and the path
// come from the environment (WstunnelClientEnv).
func WstunnelClientArgs(localUDP, wgPort int, sni, host string, port int) []string {
	return []string{"client",
		"-L", fmt.Sprintf("udp://127.0.0.1:%d:127.0.0.1:%d?timeout_sec=0", localUDP, wgPort),
		"--tls-verify-certificate",
		"--tls-sni-override", sni,
		fmt.Sprintf("wss://%s:%d", hostLiteral(host), port),
	}
}

// WstunnelClientEnv is the client's environment besides the env file:
// the trust file is the only root store, no directory is added.
func WstunnelClientEnv(trust string) []string {
	return []string{"SSL_CERT_FILE=" + trust, "SSL_CERT_DIR="}
}

func hostLiteral(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

func renderWstunnelServer(n model.Node, tunnels []Tunnel) string {
	if len(wssServerTunnels(n, tunnels)) == 0 {
		return ""
	}
	listen := n.WSSListenPort
	if listen == 0 {
		listen = 443
	}
	args := WstunnelServerArgs(WSSServerYAML, WSSServerCert, WSSServerKey, fmt.Sprintf("0.0.0.0:%d", listen))
	return systemdUnit(
		"Meridian wstunnel server (random path per link, panel-generated self-signed certificate)",
		artifacts.HostPath(artifacts.Wstunnel)+" "+strings.Join(args, " "),
	)
}

func wssServerTunnels(n model.Node, tunnels []Tunnel) []Tunnel {
	var out []Tunnel
	for _, tun := range tunnels {
		if tun.Mode == "wss" && tun.Listener().ID == n.ID {
			out = append(out, tun)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LinkID < out[j].LinkID })
	return out
}

// renderWSSRestrictions is the server's --restrict-config: one rule per
// link, matching only that link's prefix(es) (the token is resolved to an
// alternation of secret placeholders) and allowing only UDP to that link's
// WireGuard port on 127.0.0.1.
func renderWSSRestrictions(n model.Node, tunnels []Tunnel) string {
	var sb strings.Builder
	sb.WriteString("# Meridian wstunnel restrictions: one rule per WSS link (generated; secret, mode 0600).\n")
	sb.WriteString("# A request whose path prefix matches no rule is answered 400 and never tunnelled.\n")
	sb.WriteString("restrictions:\n")
	for _, tun := range wssServerTunnels(n, tunnels) {
		fmt.Fprintf(&sb, "  - name: \"%s\"\n", tun.LinkID)
		sb.WriteString("    match:\n")
		fmt.Fprintf(&sb, "      - !PathPrefix \"^(?:%s)$\"\n", wssToken(wssTokServerPaths, tun.LinkID))
		sb.WriteString("    allow:\n")
		sb.WriteString("      - !Tunnel\n")
		sb.WriteString("        protocol:\n          - Udp\n")
		fmt.Fprintf(&sb, "        port:\n          - \"%d\"\n", tun.WGPort)
		sb.WriteString("        cidr:\n          - 127.0.0.1/32\n")
	}
	return sb.String()
}

func renderWSSServerCert(n model.Node) string { return wssToken(wssTokCert, n.ID) + "\n" }
func renderWSSServerKey(n model.Node) string  { return wssToken(wssTokKey, n.ID) + "\n" }

func renderWSSClientEnv(tun Tunnel) string {
	return fmt.Sprintf("# Meridian wstunnel client of link %s (generated; secret, mode 0600).\n"+
		"WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=%s\nMERIDIAN_WSS_SNI=%s\n",
		tun.LinkID, wssToken(wssTokPath, tun.LinkID), wssToken(wssTokSNI, tun.Listener().ID))
}

func renderWSSClientTrust(tun Tunnel) string { return wssToken(wssTokTrust, tun.LinkID) + "\n" }

func renderWstunnelClient(tun Tunnel) string {
	srv := tun.Listener()
	host := tun.DialV4()
	if host == "" {
		host = "203.0.113.10"
	}
	port := srv.WSSListenPort
	if port == 0 {
		port = 443
	}
	args := WstunnelClientArgs(tun.ClientUDP, tun.WGPort, "${MERIDIAN_WSS_SNI}", host, port)
	// The -L value is quoted for systemd (it carries '?').
	args[2] = "'" + args[2] + "'"
	var env strings.Builder
	for _, e := range WstunnelClientEnv(WSSClientTrust(tun.LinkID)) {
		env.WriteString("Environment=" + e + "\n")
	}
	return fmt.Sprintf(`[Unit]
Description=Meridian wstunnel client for %s (%s; verifies the listener's pinned self-signed certificate)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%sEnvironmentFile=%s
ExecStart=%s %s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, tun.LinkID, tun.Mode, env.String(), WSSClientEnv(tun.LinkID), artifacts.HostPath(artifacts.Wstunnel), strings.Join(args, " "))
}

// WSSPlan says which rotation stage every WSS party of a resolved bundle
// was rendered at, and which tokens could not be resolved.
type WSSPlan struct {
	Parties []WSSPartyStage `json:"parties"`
	// Missing lists unresolved tokens (no material yet): such a bundle is
	// refused by every install path.
	Missing []string `json:"missing,omitempty"`
}

// WSSPartyStage is one rendered party.
type WSSPartyStage struct {
	ListenerID string `json:"listener_id"`
	Party      string `json:"party"`
	NodeID     string `json:"node_id"`
	Stage      int    `json:"stage"`
}

// ForNode returns the parties rendered on nodeID.
func (p *WSSPlan) ForNode(nodeID string) []WSSPartyStage {
	if p == nil {
		return nil
	}
	var out []WSSPartyStage
	for _, x := range p.Parties {
		if x.NodeID == nodeID {
			out = append(out, x)
		}
	}
	return out
}

// ResolveWSS returns a copy of b with every WSS token resolved from st:
// public material (certificates, the synthetic name) inline, secrets as
// __MERIDIAN_SECRET_<id>__ placeholders. Each party is rendered at its
// target stage (model.WSSListener.TargetServer / TargetClient). Tokens
// without state are left in place and listed in the plan's Missing.
func ResolveWSS(b *Bundle, st model.WSSState) (*Bundle, *WSSPlan) {
	out := &Bundle{Files: make(map[string]string, len(b.Files)), Order: b.Order, Issues: b.Issues, Paths: b.Paths}
	plan := &WSSPlan{}
	linkOf := map[string]*model.WSSListener{}
	for i := range st.Listeners {
		l := &st.Listeners[i]
		for _, k := range l.Links {
			linkOf[k.LinkID] = l
		}
	}
	seenParty := map[string]bool{}
	addParty := func(lis, party, node string, stage int) {
		key := lis + "\x00" + party + "\x00" + node
		if !seenParty[key] {
			seenParty[key] = true
			plan.Parties = append(plan.Parties, WSSPartyStage{ListenerID: lis, Party: party, NodeID: node, Stage: stage})
		}
	}
	missing := map[string]bool{}
	for path, body := range b.Files {
		if !strings.Contains(body, "__MERIDIAN_WSS_") {
			out.Files[path] = body
			continue
		}
		node := nodeOfPath(path)
		body = WSSTokenRe.ReplaceAllStringFunc(body, func(tok string) string {
			m := WSSTokenRe.FindStringSubmatch(tok)
			kind, id := m[1], m[2]
			switch kind {
			case wssTokServerPaths, wssTokPath, wssTokTrust:
				l := linkOf[id]
				if l == nil {
					missing[tok] = true
					return tok
				}
				k := l.Link(id)
				switch kind {
				case wssTokServerPaths:
					if l.NodeID != node {
						missing[tok] = true
						return tok
					}
					stage := l.TargetServer()
					addParty(l.NodeID, model.WSSPartyServer, node, stage)
					var ph []string
					for _, sid := range l.ServerPaths(k, stage) {
						ph = append(ph, model.SecretPlaceholder(sid))
					}
					return strings.Join(ph, "|")
				case wssTokPath:
					if k.DialerID != node {
						missing[tok] = true
						return tok
					}
					stage := l.TargetClient(k)
					addParty(l.NodeID, model.WSSClientParty(id), node, stage)
					return model.SecretPlaceholder(l.ClientPath(k, stage))
				default:
					if k.DialerID != node {
						missing[tok] = true
						return tok
					}
					stage := l.TargetClient(k)
					addParty(l.NodeID, model.WSSClientParty(id), node, stage)
					var sb strings.Builder
					fmt.Fprintf(&sb, "# Meridian WSS trust roots of link %s (listener %s, name %s): the only\n", id, l.NodeID, l.ServerName)
					sb.WriteString("# certificates this client accepts (SSL_CERT_FILE; no system roots).\n")
					for _, c := range l.ClientTrust(stage) {
						fmt.Fprintf(&sb, "# SHA-256 %s, valid until %s\n", c.Fingerprint, c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
						sb.WriteString(strings.TrimSpace(c.CertPEM) + "\n")
					}
					return strings.TrimSuffix(sb.String(), "\n")
				}
			case wssTokCert, wssTokKey:
				l := st.Listener(id)
				if l == nil || id != node {
					missing[tok] = true
					return tok
				}
				stage := l.TargetServer()
				addParty(l.NodeID, model.WSSPartyServer, node, stage)
				c := l.ServerCert(stage)
				if kind == wssTokKey {
					return model.SecretPlaceholder(c.KeySecretID)
				}
				return strings.TrimSpace(c.CertPEM)
			case wssTokSNI:
				l := st.Listener(id)
				if l == nil {
					missing[tok] = true
					return tok
				}
				return l.ServerName
			}
			missing[tok] = true
			return tok
		})
		out.Files[path] = body
	}
	for tok := range missing {
		plan.Missing = append(plan.Missing, tok)
	}
	sort.Strings(plan.Missing)
	out.WSS = plan
	sort.Slice(plan.Parties, func(i, j int) bool {
		a, c := plan.Parties[i], plan.Parties[j]
		if a.ListenerID != c.ListenerID {
			return a.ListenerID < c.ListenerID
		}
		return a.Party < c.Party
	})
	return out, plan
}

func nodeOfPath(p string) string {
	rest, ok := strings.CutPrefix(p, "nodes/")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, "/")
	return id
}
