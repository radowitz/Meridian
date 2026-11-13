package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ruleset"
)

// Rule-set subscription credentials and the download guard's
// topology-derived refusals (docs/architecture.md「规则集合的订阅认证」).
//
// The credential is write-only: PUT /api/rule-sets/{id}/auth stores or
// rotates it, DELETE removes it, and every rule-set view carries only
// {kind, secret_set, updated_at}. It is kept in the restricted credential
// store (credentials.SetRuleSetAuth), never in the topology, and is handed
// to the downloader for the configured URL's origin only.

// authBody is the write-only credential input.
type authBody struct {
	Kind     string `json:"kind"`
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Query    string `json:"query,omitempty"`
}

func (b authBody) auth() *ruleset.Auth {
	return &ruleset.Auth{Kind: b.Kind, Token: b.Token, Username: b.Username, Password: b.Password, Query: strings.TrimPrefix(b.Query, "?")}
}

func toStoreAuth(a *ruleset.Auth) credentials.RuleSetAuthInput {
	return credentials.RuleSetAuthInput{Kind: a.Kind, Token: a.Token, Username: a.Username, Password: a.Password, Query: a.Query}
}

// authView is what responses carry about a rule-set's credential.
type authView struct {
	Kind      string `json:"kind"`
	SecretSet bool   `json:"secret_set"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func (s *Server) ruleSetAuthView(id string) *authView {
	cs, err := s.credStore()
	if err != nil {
		return nil
	}
	m, ok := cs.RuleSetAuth(id)
	if !ok {
		return nil
	}
	return &authView{Kind: m.Kind, SecretSet: m.SecretSet, UpdatedAt: m.UpdatedAt}
}

// ruleSetAuth reads a rule-set's credential for a download (nil: none).
func (s *Server) ruleSetAuth(id string) (*ruleset.Auth, error) {
	cs, err := s.credStore()
	if err != nil {
		// Without a readable store no rule-set can have a credential the
		// panel could use; a public set still downloads (a private one gets
		// the server's refusal).
		return nil, nil
	}
	in, ok, err := cs.RuleSetAuthSecret(id)
	if err != nil || !ok {
		return nil, err
	}
	return &ruleset.Auth{Kind: in.Kind, Token: in.Token, Username: in.Username, Password: in.Password, Query: in.Query}, nil
}

func (s *Server) storeRuleSetAuth(id string, a *ruleset.Auth) error {
	if err := a.Check(); err != nil {
		return err
	}
	cs, err := s.credStore()
	if err != nil {
		return err
	}
	_, err = cs.SetRuleSetAuth(id, toStoreAuth(a))
	return err
}

func (s *Server) putRuleSetAuth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b authBody
	if err := decodeBody(w, r, &b); err != nil {
		// Never echo the decoder's message: it can quote the body.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误：需要 {\"kind\": \"bearer\"|\"basic\"|\"query\", …}", "code": "bad_request"})
		return
	}
	a := b.auth()
	if err := a.Check(); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "bad_auth"})
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rs, ok := t.RuleSetByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "规则集不存在"})
		return
	}
	if err := s.storeRuleSetAuth(id, a); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": ruleset.Scrub(err.Error(), a.Secrets()...), "code": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, s.ruleSetView(t, rs, s.loadRSStatus()))
}

func (s *Server) deleteRuleSetAuth(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rs, ok := t.RuleSetByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "规则集不存在"})
		return
	}
	cs, err := s.credStore()
	if err == nil {
		err = cs.DeleteRuleSetAuth(id)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.ruleSetView(t, rs, s.loadRSStatus()))
}

// queryRe finds a query string in free text (an old error message).
var queryRe = regexp.MustCompile(`\?[^\s"'；;,)）]+`)

// redactText drops query strings and user information from text shown
// about a download (status written by an older version may quote a URL).
func redactText(s string) string {
	s = queryRe.ReplaceAllString(s, "?…")
	return userinfoRe.ReplaceAllString(s, "://")
}

var userinfoRe = regexp.MustCompile(`://[^/\s@]+@`)

// gatewayDeny are the addresses a rule-set download may never connect to,
// even when the rule-set allows a LAN source: the gateway's own LAN
// address, the tunnel (link) and transit ranges, and the remote-access
// pools — all known from the topology. (Loopback, link-local and this
// host's interface addresses are refused by ruleset.AddrAllowed.)
func gatewayDeny(t model.Topology) []netip.Prefix {
	var out []netip.Prefix
	host := func(s string) {
		s = strings.TrimSpace(s)
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Addr().Unmap().BitLen()))
		}
	}
	nets := func(s string) {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			out = append(out, p.Masked())
		}
	}
	host(t.Settings.GatewayLANIP)
	for _, n := range t.Nodes {
		if n.Role == model.RoleGateway {
			host(n.LANIPv4)
		}
	}
	nets(t.Settings.TransitV4Prefix)
	nets(t.Settings.TransitV6Prefix)
	alloc := model.EffectiveAllocations(t)
	for _, l := range t.Links {
		for _, a := range []string{l.FromV4, l.ToV4, l.FromULA, l.ToULA} {
			host(a)
		}
		if slot, ok := alloc.LinkSlot(l.ID); ok {
			v4, ula, c4, cula := model.LinkAutoBlocks(slot)
			out = append(out, v4, ula, c4, cula)
		}
	}
	v4, v6 := model.DefaultRemoteV4Prefix, model.DefaultRemoteV6Prefix
	if ra := t.RemoteAccess; ra != nil {
		if ra.IPv4Prefix != "" {
			v4 = ra.IPv4Prefix
		}
		if ra.IPv6Prefix != "" {
			v6 = ra.IPv6Prefix
		}
	}
	nets(v4)
	nets(v6)
	return out
}

// migrateRuleSetSecrets moves credentials out of stored rule-set URLs
// (written before URLs were checked for them) into the credential store:
// user information becomes basic auth, secret-looking query parameters a
// query credential; the topology keeps the cleaned URL. A rule-set that
// already has a credential keeps it and only loses the URL part.
// Idempotent.
func (s *Server) migrateRuleSetSecrets(cs *credentials.Store) error {
	t, err := s.topology()
	if err != nil {
		return err
	}
	type move struct {
		id, clean string
		auth      *ruleset.Auth
	}
	var moves []move
	for _, rs := range t.RuleSets {
		if !ruleset.HasSecret(rs.URL) {
			continue
		}
		clean, a, err := ruleset.SplitSecret(rs.URL)
		if err != nil {
			return fmt.Errorf("规则集 %s 的 URL 带认证信息但不能自动拆分：%s", rs.ID, err.Error())
		}
		moves = append(moves, move{rs.ID, clean, a})
	}
	if len(moves) == 0 {
		return nil
	}
	for _, m := range moves {
		if _, has := cs.RuleSetAuth(m.id); has || m.auth == nil {
			continue
		}
		if _, err := cs.SetRuleSetAuth(m.id, toStoreAuth(m.auth)); err != nil {
			return errors.New("规则集订阅认证写入失败")
		}
	}
	_, err = s.Store.Update(func(tp *model.Topology) (bool, error) {
		changed := false
		for i := range tp.RuleSets {
			for _, m := range moves {
				if tp.RuleSets[i].ID == m.id && tp.RuleSets[i].URL != m.clean {
					tp.RuleSets[i].URL = m.clean
					changed = true
				}
			}
		}
		return changed, nil
	})
	return err
}
