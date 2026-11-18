package api

// The「解析配置」view and the exits' resolver upstream
// (docs/architecture.md「解析配置视图」「出口解析上游」).
//
//	GET    /api/dns                         the resolution of every kind of name
//	                                        (compile.ResolutionPlan), the exits'
//	                                        upstreams, planned vs installed
//	                                        SmartDNS configs by digest, the
//	                                        forwarder's per-resolver results and
//	                                        the last fixed checks
//	GET    /api/dns/config?node=<id>        one node's generated SmartDNS config
//	                                        (read-only; account values are never
//	                                        part of it, placeholders are masked)
//	PUT    /api/dns/upstream                {"global": upstream|null,
//	                                        "exits": {"<id>": upstream|null}}:
//	                                        saved into the topology; takes effect
//	                                        only through preflight → install.
//	                                        Only what the body names changes: an
//	                                        absent "global" keeps the global
//	                                        setting (null clears it), exits not
//	                                        listed keep their override (null:
//	                                        follow the global setting again;
//	                                        {"protocol":"builtin"}: keep the
//	                                        built-in resolvers)
//	POST   /api/dns/check                   {"exit_id"}: the fixed check through
//	                                        the host agent (hostexec/dns.go)
//	GET    /api/dns-accounts                DNS account identifiers (metadata)
//	POST   /api/dns-accounts                {"name","notes","account"}
//	PATCH  /api/dns-accounts/{id}           {"name","notes"}
//	PUT    /api/dns-accounts/{id}/secret    {"account"}
//	DELETE /api/dns-accounts/{id}
//
// An account value is accepted by the two writes above and never returned,
// logged, stored in the topology or shown: compile output names only the
// credential's placeholder, and the install boundary (provision_api.go)
// injects it into the exit's SmartDNS config.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
	"github.com/radowitz/meridian/internal/provision"
	"github.com/radowitz/meridian/internal/sniff"
)

// DNSCheckRuntime is the host agent's fixed exit resolver check
// (hostexec.Client; asked of Server.Prober).
type DNSCheckRuntime interface {
	DNSCheck(ctx context.Context, req hostexec.DNSCheckRequest) (hostexec.DNSCheckResult, error)
}

func (s *Server) registerDNS(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns", s.getDNS)
	mux.HandleFunc("GET /api/dns/config", s.getDNSConfig)
	mux.HandleFunc("PUT /api/dns/upstream", s.putDNSUpstream)
	mux.HandleFunc("POST /api/dns/check", s.postDNSCheck)
	mux.HandleFunc("GET /api/dns-accounts", s.listDNSAccounts)
	mux.HandleFunc("POST /api/dns-accounts", s.createDNSAccount)
	mux.HandleFunc("PATCH /api/dns-accounts/{id}", s.patchDNSAccount)
	mux.HandleFunc("PUT /api/dns-accounts/{id}/secret", s.rotateDNSAccount)
	mux.HandleFunc("DELETE /api/dns-accounts/{id}", s.deleteDNSAccount)
}

const smartDNSConfPath = "etc/smartdns/smartdns.conf"

// dnsConfigState is one node's SmartDNS config: planned vs installed.
type dnsConfigState struct {
	Node     string `json:"node"`
	NodeName string `json:"node_name"`
	Role     string `json:"role"`
	Path     string `json:"path"`
	// PlannedSHA256 is the digest of the compiled config (placeholders,
	// never a value).
	PlannedSHA256 string `json:"planned_sha256"`
	// Installed: same | differs | not_installed | unknown.
	Installed string `json:"installed"`
	// Basis says what the comparison used.
	Basis  string `json:"basis"`
	Detail string `json:"detail,omitempty"`
	// Restricted: the installed copy carries an injected account value
	// (written 0600 on the exit).
	Restricted bool `json:"restricted,omitempty"`
	// AccountVersion is the version of the DNS account identifier the
	// planned config names (dns_version.go; a counter, never the value),
	// InstalledAccountVersion the one the node's last successful install
	// applied (0: none recorded).
	AccountVersion          int `json:"account_version,omitempty"`
	InstalledAccountVersion int `json:"installed_account_version,omitempty"`
}

// dnsResolverStatus is one resolver of the forwarder as last measured.
type dnsResolverStatus struct {
	Target string                `json:"target"`
	Probe  sniff.SelfCheckProbe  `json:"probe"`
	Health *sniff.ResolverHealth `json:"health,omitempty"`
}

type dnsForwarderView struct {
	Available bool                `json:"available"`
	Code      string              `json:"code,omitempty"`
	Message   string              `json:"message,omitempty"`
	CheckedAt *time.Time          `json:"checked_at,omitempty"`
	Resolvers []dnsResolverStatus `json:"resolvers"`
}

// dnsUnverified are the parts of the view no host measurement backs; the
// panel labels them 未验证.
var dnsUnverified = []string{
	"面板显示的上游、传输和线路来自编译结果，不是在主机上读到的；只有嗅探转发服务的逐解析器自检和「解析检查」是实际测量",
	"出口的加密上游（DoT/DoH）在真实出口和真实提供方上没有验证过：证书校验、通配符证书的主机名匹配和 ca-file 路径以安装后的「解析检查」为准",
	"国内组的 DoT 是否校验证书链取决于 SmartDNS 的默认行为（没有设置 -tls-host-verify），没有在真实主机上验证",
	"网关主机自己的解析（/etc/resolv.conf）不由 Meridian 管理，面板没有读取",
}

func (s *Server) dnsPlan(t model.Topology) (*compile.DNSPlan, *compile.Bundle, error) {
	p, err := compile.ResolutionPlan(t, s.unlockDecisions(t))
	if err != nil {
		return nil, nil, err
	}
	b, err := s.compileTopo(t)
	if err != nil {
		return nil, nil, err
	}
	return p, b, nil
}

// maskPlaceholders replaces every credential placeholder in a config text
// with a marker (the text never holds a value; this keeps the ids out of
// sight too).
func maskPlaceholders(text string) string {
	return model.SecretPlaceholderRe.ReplaceAllString(text, compile.MaskedAccount)
}

func (s *Server) dnsConfigs(t model.Topology, b *compile.Bundle) []dnsConfigState {
	out := []dnsConfigState{}
	outcomes := s.loadOutcomes()
	for _, n := range t.Nodes {
		if !n.Managed && n.Role != model.RoleGateway {
			continue
		}
		files := provision.FilesFor(b.Files, n.ID)
		body, ok := files["/"+smartDNSConfPath]
		if !ok {
			continue
		}
		st := dnsConfigState{Node: n.ID, NodeName: n.Name, Role: string(n.Role), Path: "/" + smartDNSConfPath,
			PlannedSHA256: hashText(body), Restricted: strings.Contains(body, compile.ExitDNSRestrictedMarker)}
		if n.Role == model.RoleGateway {
			st.Basis = "gateway_installed_manifest"
			d, _, err := s.applier(true).InstalledFileDiff(map[string]string{smartDNSConfPath: body})
			switch {
			case err != nil:
				st.Installed, st.Detail = "unknown", "读不到网关的安装记录"
			case d == nil:
				st.Installed, st.Detail = "not_installed", "网关还没有安装过"
			case contains(d.FilesAdded, smartDNSConfPath):
				st.Installed, st.Detail = "differs", "已安装的版本没有这个文件"
			case contains(d.FilesChanged, smartDNSConfPath):
				st.Installed, st.Detail = "differs", "已安装的内容摘要与计划不同：下次网关安装后生效"
			default:
				st.Installed = "same"
			}
		} else {
			st.Basis = "node_bundle_digest"
			o, ok := outcomes[n.ID]
			planned := dnsAccountVersionsIn(body)
			for _, v := range planned {
				st.AccountVersion = v
			}
			if ok && o.InstalledBundle != "" {
				for id := range planned {
					st.InstalledAccountVersion = o.InstalledDNSAccounts[id]
				}
			}
			switch {
			case !ok || o.InstalledBundle == "":
				st.Installed, st.Detail = "not_installed", "这个节点没有成功安装的记录"
			case o.InstalledBundle == preflight.BundleDigest(files):
				st.Installed, st.Detail = "same", "节点整包摘要与计划一致（包含这个文件）"
				// The version is part of the digest: the installed one is
				// the planned one (also for a record adopted from the host).
				st.InstalledAccountVersion = st.AccountVersion
				if st.AccountVersion > 0 {
					st.Detail = fmt.Sprintf("节点整包摘要与计划一致（包含这个文件；DNS 账户标识版本 %d）", st.AccountVersion)
				}
			default:
				st.Installed, st.Detail = "differs", "节点整包摘要与计划不同：面板只记录整包摘要，这个文件本身是否不同要看预检的文件比较"
				if why := dnsAccountChangeReason(planned, o.InstalledDNSAccounts); why != "" {
					st.Detail = why
				}
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Role == string(model.RoleGateway)) != (out[j].Role == string(model.RoleGateway)) {
			return out[i].Role == string(model.RoleGateway)
		}
		return out[i].Node < out[j].Node
	})
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if strings.TrimPrefix(x, "/") == strings.TrimPrefix(s, "/") {
			return true
		}
	}
	return false
}

func hashText(s string) string { return apply.FileHash(s) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// dnsForwarder reads the forwarder's last self-check per resolver.
func (s *Server) dnsForwarder(ctx context.Context, t model.Topology) dnsForwarderView {
	v := dnsForwarderView{Resolvers: []dnsResolverStatus{}}
	switch {
	case !t.SniffOn():
		v.Code, v.Message = "sniff_off", "嗅探转发服务关闭：没有逐解析器的测量"
		return v
	case s.Sniff == nil:
		v.Code, v.Message = "agent_unavailable", "没有配置 host agent，读不到转发服务的自检"
		return v
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	st, err := s.Sniff.SniffStatus(cctx)
	switch {
	case err != nil && errors.Is(err, hostexec.ErrUnavailable):
		v.Code, v.Message = "agent_unavailable", err.Error()
		return v
	case err != nil:
		v.Code, v.Message = "read_failed", err.Error()
		return v
	case !st.Present:
		v.Code, v.Message = "not_running", "嗅探转发服务没有运行"
		return v
	}
	var h sniff.Health
	if len(st.Health) == 0 || jsonUnmarshal(st.Health, &h) != nil || h.SelfCheck == nil {
		v.Code, v.Message = "no_selfcheck", "转发服务还没有自检结果"
		return v
	}
	v.Available = true
	at := h.SelfCheck.FinishedAt
	v.CheckedAt = &at
	hm := map[string]sniff.ResolverHealth{}
	for _, x := range h.SelfCheck.ResolverHealth {
		hm[fmt.Sprintf("%s|%d", x.Server, x.Mark)] = x
	}
	for _, tg := range h.SelfCheck.Targets {
		for _, p := range tg.Resolvers {
			r := dnsResolverStatus{Target: tg.Target, Probe: p}
			if x, ok := hm[fmt.Sprintf("%s|%d", p.Server, tg.DNSMark)]; ok {
				r.Health = &x
			}
			v.Resolvers = append(v.Resolvers, r)
		}
	}
	return v
}

func (s *Server) getDNS(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	p, b, err := s.dnsPlan(t)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "拓扑没有通过校验，无法得出解析配置：" + err.Error(), "code": "invalid_topology"})
		return
	}
	s.dnsMu.Lock()
	checks := make([]hostexec.DNSCheckResult, 0, len(s.dnsChecks))
	for _, c := range s.dnsChecks {
		checks = append(checks, c)
	}
	s.dnsMu.Unlock()
	sort.Slice(checks, func(i, j int) bool { return checks[i].ExitID < checks[j].ExitID })
	_, canCheck := s.Prober.(DNSCheckRuntime)
	writeJSON(w, http.StatusOK, map[string]any{
		"paths": p.Paths, "exits": p.Exits, "global_upstream": t.Settings.ExitDNS,
		"configs": s.dnsConfigs(t, b), "forwarder": s.dnsForwarder(r.Context(), t),
		"checks": checks, "check_available": canCheck, "check_name": hostexec.DNSCheckName,
		"unverified": dnsUnverified, "masked": compile.MaskedAccount,
	})
}

func (s *Server) getDNSConfig(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("node")
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	n, ok := t.NodeByID(id)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("没有这个节点"))
		return
	}
	b, err := s.compileTopo(t)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "拓扑没有通过校验：" + err.Error(), "code": "invalid_topology"})
		return
	}
	body, ok := provision.FilesFor(b.Files, n.ID)["/"+smartDNSConfPath]
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("这个节点没有 SmartDNS 配置"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": n.ID, "path": "/" + smartDNSConfPath, "planned_sha256": hashText(body),
		"text": maskPlaceholders(body), "masked": strings.Contains(body, model.SecretPlaceholderPrefix)})
}

// dnsUpstreamBody: Global is kept raw so an absent key (keep the global
// setting) differs from null (clear it); one exit's override can be saved
// without restating the global setting or the other exits.
type dnsUpstreamBody struct {
	Global json.RawMessage                   `json:"global"`
	Exits  map[string]*model.ExitDNSUpstream `json:"exits"`
}

// effectiveUpstreams is every managed exit's effective upstream (canonical
// JSON, "" for the built-in resolvers): what a save changed for each exit.
func effectiveUpstreams(t model.Topology) map[string]string {
	out := map[string]string{}
	for _, n := range t.Nodes {
		if n.Role != model.RoleExit || !n.Managed || model.IsExternal(n) {
			continue
		}
		if u := t.ExitUpstream(n); u != nil {
			out[n.ID] = canonJSON(u)
		} else {
			out[n.ID] = ""
		}
	}
	return out
}

// dnsAccountRefs are the settings of t that name credential id.
func dnsAccountRefs(t model.Topology, id string) []credentials.Ref {
	refs := []credentials.Ref{}
	if u := t.Settings.ExitDNS; u != nil && u.AccountCredential == id {
		refs = append(refs, credentials.Ref{Kind: "setting", ID: "exit_dns", Name: "全局出口解析上游"})
	}
	for _, n := range t.Nodes {
		if n.ExitDNS != nil && n.ExitDNS.AccountCredential == id {
			refs = append(refs, credentials.Ref{Kind: "node", ID: n.ID, Name: n.Name})
		}
	}
	return refs
}

// checkDNSAccountCredentials: every account credential the upstream
// settings name exists in the store.
func checkDNSAccountCredentials(cs *credentials.Store, t model.Topology) error {
	ups := []*model.ExitDNSUpstream{t.Settings.ExitDNS}
	for _, n := range t.Nodes {
		ups = append(ups, n.ExitDNS)
	}
	for _, u := range ups {
		if u == nil || u.AccountCredential == "" {
			continue
		}
		if _, err := cs.DNSAccountCredential(u.AccountCredential); err != nil {
			return &credentials.Error{Code: "dns_account_missing", Field: "exit_dns.account_credential",
				Msg: fmt.Sprintf("出口解析上游引用的 DNS 账户标识 %s 不存在：先在「解析配置」里新建", u.AccountCredential)}
		}
	}
	return nil
}

func (s *Server) putDNSUpstream(w http.ResponseWriter, r *http.Request) {
	var b dnsUpstreamBody
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	setGlobal := b.Global != nil
	var global *model.ExitDNSUpstream
	if setGlobal && json.Unmarshal(b.Global, &global) != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	if !setGlobal && len(b.Exits) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("请求里既没有 global 也没有 exits：没有可保存的内容"))
		return
	}
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	s.resMu.Lock()
	defer s.resMu.Unlock()
	var before map[string]string
	t, issues, err := s.saveTopologyChecked(func(t *model.Topology) error {
		before = effectiveUpstreams(*t)
		if setGlobal {
			t.Settings.ExitDNS = global
		}
		for id, u := range b.Exits {
			found := false
			for i := range t.Nodes {
				if t.Nodes[i].ID == id {
					t.Nodes[i].ExitDNS, found = u, true
				}
			}
			if !found {
				return fmt.Errorf("404:没有节点 %s", id)
			}
		}
		if err := checkDNSAccountCredentials(cs, *t); err != nil {
			return fmt.Errorf("409:%s", err.Error())
		}
		return nil
	})
	if s.writeSaveErr(w, issues, err) {
		return
	}
	// changed_exits: the exits whose effective upstream this save changed;
	// each needs a preflight → install before it takes effect.
	changed := []string{}
	for id, v := range effectiveUpstreams(t) {
		if old, ok := before[id]; !ok || old != v {
			changed = append(changed, id)
		}
	}
	sort.Strings(changed)
	p, _, perr := s.dnsPlan(t)
	out := map[string]any{"global_upstream": t.Settings.ExitDNS, "changed_exits": changed, "note": "已保存到拓扑：要经过预检、确认并安装到各出口后才生效"}
	if perr == nil {
		out["exits"] = p.Exits
	}
	writeJSON(w, http.StatusOK, out)
}

type dnsCheckBody struct {
	ExitID string `json:"exit_id"`
}

func (s *Server) postDNSCheck(w http.ResponseWriter, r *http.Request) {
	var b dnsCheckBody
	if err := decodeBody(w, r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("请求格式错误"))
		return
	}
	rt, ok := s.Prober.(DNSCheckRuntime)
	if !ok || s.Prober == nil {
		writeCoded(w, http.StatusServiceUnavailable, "agent_unavailable", "面板没有宿主代理的检查能力（meridian-host 未运行或未挂载）：解析检查没有执行", nil)
		return
	}
	t, err := s.topology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	p, err := compile.ResolutionPlan(t, s.unlockDecisions(t))
	if err != nil {
		writeCoded(w, http.StatusUnprocessableEntity, "invalid_topology", "拓扑没有通过校验："+err.Error(), nil)
		return
	}
	var ex *compile.DNSExitRow
	for i := range p.Exits {
		if p.Exits[i].ID == b.ExitID {
			ex = &p.Exits[i]
		}
	}
	if ex == nil || !ex.Checkable {
		writeCoded(w, http.StatusBadRequest, "not_checkable", "这个出口没有可检查的隧道解析器（不是受管出口，或只经 Mesh）", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), hostexec.DNSCheckTimeout+20*time.Second)
	defer cancel()
	res, err := rt.DNSCheck(ctx, hostexec.DNSCheckRequest{RequestID: "dns-" + randHex(6), ExitID: ex.ID, Resolver: ex.Resolver})
	if err != nil {
		code := "check_failed"
		if errors.Is(err, hostexec.ErrUnavailable) {
			code = "agent_unavailable"
		}
		writeCoded(w, http.StatusBadGateway, code, "解析检查没有完成："+err.Error(), nil)
		return
	}
	s.dnsMu.Lock()
	if s.dnsChecks == nil {
		s.dnsChecks = map[string]hostexec.DNSCheckResult{}
	}
	s.dnsChecks[ex.ID] = res
	s.dnsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"check": res, "upstream": ex.Description})
}

// ------------------------------------------------- DNS account values ---

type dnsAccountView struct {
	credentials.DNSAccountCredential
	// Version counts the credential's values (1 when created, +1 per
	// rotation; dns_version.go). Never derived from the value.
	Version int               `json:"version"`
	UsedBy  []credentials.Ref `json:"used_by"`
	// Exits are the managed exits whose resolver uses it (global setting
	// or their own): after a rotation each must be installed again.
	Exits []string `json:"exits"`
}

func dnsAccountViewOf(cs *credentials.Store, t model.Topology, c credentials.DNSAccountCredential) dnsAccountView {
	return dnsAccountView{DNSAccountCredential: c, Version: cs.DNSAccountVersions([]string{c.ID})[c.ID], UsedBy: dnsAccountRefs(t, c.ID), Exits: dnsAccountExits(t, c.ID)}
}

type dnsAccountBody struct {
	Name  string `json:"name"`
	Notes string `json:"notes"`
	credentials.DNSAccountInput
}

func (s *Server) listDNSAccounts(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	out := []dnsAccountView{}
	for _, c := range cs.DNSAccountCredentials() {
		out = append(out, dnsAccountViewOf(cs, t, c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

func (s *Server) createDNSAccount(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	var body dnsAccountBody
	if err := decodeBody(w, r, &body); err != nil {
		writeResErr(w, err)
		return
	}
	c, err := cs.CreateDNSAccountCredential(body.Name, body.Notes, body.DNSAccountInput)
	if err != nil {
		writeResErr(w, err, body.Secrets()...)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"account": dnsAccountViewOf(cs, t, c)})
}

func (s *Server) patchDNSAccount(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	var p credentials.CredentialPatch
	if err := decodeBody(w, r, &p); err != nil {
		writeResErr(w, err)
		return
	}
	c, err := cs.UpdateDNSAccountCredential(r.PathValue("id"), p)
	if err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": dnsAccountViewOf(cs, t, c)})
}

func (s *Server) rotateDNSAccount(w http.ResponseWriter, r *http.Request) {
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	var in credentials.DNSAccountInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	c, err := cs.RotateDNSAccountCredential(r.PathValue("id"), in)
	if err != nil {
		writeResErr(w, err, in.Secrets()...)
		return
	}
	// The version went up: every exit that uses the credential is now
	// "changed" (dns_version.go) and keeps the old value until it is
	// preflighted and installed again; reviewed preflights no longer count.
	v := dnsAccountViewOf(cs, t, c)
	note := "已轮换：没有引用它的出口，不需要重新安装"
	if len(v.Exits) > 0 {
		note = fmt.Sprintf("已轮换（版本 %d）：出口 %s 在重新预检并安装之前仍在用旧的值；之前的预检已失效", v.Version, strings.Join(v.Exits, "、"))
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": v, "pending": v.Exits, "note": note})
}

func (s *Server) deleteDNSAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.resMu.Lock()
	defer s.resMu.Unlock()
	cs, t, ok := s.resCtx(w)
	if !ok {
		return
	}
	if err := cs.DeleteDNSAccountCredential(id, dnsAccountRefs(t, id)); err != nil {
		writeResErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
