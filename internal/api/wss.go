package api

import (
	"errors"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
)

// WSS carrier credentials: random path per link, self-signed certificate
// per listener, two-sided staged rotation (model.WSSListener). This file
// is the panel side: generation on compile, migration of the fixed-path
// topologies, the status view (public data only), the regenerate actions,
// the outcome records of the existing install paths and the expiry
// scheduler. Secrets never leave the credential store except through
// wgSecrets (install boundary).

func (s *Server) registerWSS(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/wss", s.getWSS)
	mux.HandleFunc("POST /api/wss/links/{id}/regenerate-path", s.postWSSRegeneratePath)
	mux.HandleFunc("POST /api/wss/listeners/{id}/regenerate-cert", s.postWSSRegenerateCert)
	mux.HandleFunc("POST /api/wss/listeners/{id}/cancel", s.postWSSCancel)
}

// wssDeployed reports whether a node was installed by this panel before
// (the gateway: an installed manifest; a remote node: a successful
// provision on record). Used once, by the first migration.
func (s *Server) wssDeployed(nodeID string) bool {
	if nodeID == localNodeID {
		inst, err := s.applier(false).Installed()
		return err == nil && !inst.Empty()
	}
	o, ok := s.loadOutcomes()[nodeID]
	return ok && o.Installed
}

// ensureWSS generates missing material for t's WSS links. On the first run
// the listeners of the fixed-path versions become legacy migrations.
func (s *Server) ensureWSS(cs *credentials.Store, t model.Topology) error {
	ends := compile.WSSEnds(t)
	var legacy map[string]credentials.WSSLegacy
	if st := cs.WSSState(); !st.Migrated {
		legacy = map[string]credentials.WSSLegacy{}
		for _, e := range ends {
			n, ok := t.NodeByID(e.ListenerID)
			if !ok {
				continue
			}
			p := n.WSSPathPrefix
			if p == "" {
				p = credentials.LegacyWSSDefaultPath
			}
			legacy[e.ListenerID] = credentials.WSSLegacy{Path: p}
		}
	}
	_, err := cs.EnsureWSS(ends, legacy, s.wssDeployed)
	return err
}

// migrateWSS generates the material (first run: legacy migration), then
// clears the fixed-path fields (wss_path_prefix, tls_cert_path,
// tls_key_path) from the stored topology. Idempotent.
func (s *Server) migrateWSS(cs *credentials.Store) error {
	t, ok, err := s.Store.Load()
	if err != nil || !ok {
		return err
	}
	if err := s.ensureWSS(cs, t); err != nil {
		return err
	}
	_, err = s.Store.Update(func(t *model.Topology) (bool, error) {
		changed := false
		for i := range t.Nodes {
			n := &t.Nodes[i]
			if n.WSSPathPrefix != "" || n.TLSCertPath != "" || n.TLSKeyPath != "" {
				n.WSSPathPrefix, n.TLSCertPath, n.TLSKeyPath = "", "", ""
				changed = true
			}
		}
		return changed, nil
	})
	return err
}

// resolveWSS resolves b's WSS tokens. Without a credential store, or when
// generation fails, the tokens stay (and are listed in b.WSS.Missing): the
// install paths refuse such a bundle.
func (s *Server) resolveWSS(t model.Topology, b *compile.Bundle) *compile.Bundle {
	cs, err := s.credStore()
	if err != nil {
		rb, _ := compile.ResolveWSS(b, model.WSSState{})
		return rb
	}
	if err := s.ensureWSS(cs, t); err != nil {
		log.Printf("wss: material generation failed: %v", err)
	}
	rb, _ := compile.ResolveWSS(b, cs.WSSState())
	return rb
}

// wssPartiesOf converts a bundle's plan for the store.
func wssPartiesOf(b *compile.Bundle, nodeID string) []credentials.WSSPartyStage {
	if b == nil {
		return nil
	}
	var out []credentials.WSSPartyStage
	for _, p := range b.WSS.ForNode(nodeID) {
		out = append(out, credentials.WSSPartyStage{ListenerID: p.ListenerID, Party: p.Party, NodeID: p.NodeID, Stage: p.Stage})
	}
	return out
}

// recordWSS stores an install outcome of nodeID for the WSS parties b
// rendered there. ok: installed; !ok && !unknown: failed and compensated
// (the previous files are back); unknown: the host may run either.
func (s *Server) recordWSS(nodeID string, b *compile.Bundle, ok, unknown bool, msg string) {
	parties := wssPartiesOf(b, nodeID)
	if len(parties) == 0 {
		return
	}
	cs, err := s.credStore()
	if err != nil {
		return
	}
	if err := cs.RecordWSSInstall(nodeID, parties, ok, unknown, msg); err != nil {
		log.Printf("wss: could not record the install of %s: %v", nodeID, err)
	}
	s.gcWSSSecrets(cs)
}

// markWSSNode sets every WSS party on nodeID to stage (unknown after a
// gateway rollback, none after a withdraw).
func (s *Server) markWSSNode(nodeID string, stage int, msg string) {
	cs, err := s.credStore()
	if err != nil {
		return
	}
	if err := cs.MarkWSSNode(nodeID, stage, msg); err != nil {
		log.Printf("wss: could not record %s: %v", nodeID, err)
	}
}

// gcWSSSecrets deletes WSS secrets no listener names and no gateway
// snapshot (applied, previous, installed, staged, held) references: a
// rollback or a recovery must still be able to inject them.
func (s *Server) gcWSSSecrets(cs *credentials.Store) {
	unused := cs.WSSUnusedSecrets()
	if len(unused) == 0 {
		return
	}
	refs, err := s.applier(true).ReferencedSecrets()
	if err != nil {
		log.Printf("wss: keeping unused secrets, snapshots unreadable: %v", err)
		return
	}
	var drop []string
	for _, id := range unused {
		if !refs[id] {
			drop = append(drop, id)
		}
	}
	if err := cs.DeleteWSSSecrets(drop); err != nil {
		log.Printf("wss: could not delete unused secrets: %v", err)
	}
}

// StartWSSScheduler checks the certificates once at start and then every
// hour: a certificate within model.WSSRotateBefore of its expiry gets a
// pending successor (the rotation then needs the listed installs; the
// panel warns until they ran). It never installs anything by itself.
func (s *Server) StartWSSScheduler() {
	go func() {
		s.WSSTick()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			s.WSSTick()
		}
	}()
}

// WSSTick runs one expiry check.
func (s *Server) WSSTick() []string {
	cs, err := s.credStore()
	if err != nil {
		return nil
	}
	started, err := cs.WSSExpiryTick()
	if err != nil {
		log.Printf("wss: expiry rotation could not start: %v", err)
	}
	for _, id := range started {
		log.Printf("wss: certificate of listener %s expires within %d days: rotation started, re-install the listed ends in order", id, int(model.WSSRotateBefore.Hours()/24))
	}
	return started
}

// ---------------------------------------------------------------- view ---

type wssCertView struct {
	Fingerprint string    `json:"fingerprint_sha256"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	CreatedAt   time.Time `json:"created_at"`
	DaysLeft    int       `json:"days_left"`
}

type wssLinkView struct {
	LinkID        string     `json:"link_id"`
	DialerID      string     `json:"dialer_id"`
	PathSet       bool       `json:"path_set"`
	PathCreatedAt time.Time  `json:"path_created_at"`
	PendingPathAt *time.Time `json:"pending_path_created_at,omitempty"`
	LegacyPath    bool       `json:"legacy_path_accepted,omitempty"`
}

type wssPartyView struct {
	Party     string `json:"party"`
	Role      string `json:"role"`
	LinkID    string `json:"link_id,omitempty"`
	NodeID    string `json:"node_id"`
	Installed int    `json:"installed_stage"`
	Uncertain bool   `json:"uncertain,omitempty"`
	Target    int    `json:"target_stage"`
	Involved  bool   `json:"involved"`
}

type wssWarning struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type wssListenerView struct {
	NodeID          string            `json:"node_id"`
	ServerName      string            `json:"server_name"`
	Cert            wssCertView       `json:"cert"`
	PendingCert     *wssCertView      `json:"pending_cert,omitempty"`
	Legacy          bool              `json:"legacy"`
	Rotating        bool              `json:"rotating"`
	RotationReason  string            `json:"rotation_reason,omitempty"`
	RotationStarted *time.Time        `json:"rotation_started,omitempty"`
	Inconsistent    bool              `json:"inconsistent"`
	Links           []wssLinkView     `json:"links"`
	Parties         []wssPartyView    `json:"parties"`
	NextSteps       []model.WSSStep   `json:"next_steps"`
	Results         []model.WSSResult `json:"results"`
	Warnings        []wssWarning      `json:"warnings"`
}

func certView(c model.WSSCert, now time.Time) wssCertView {
	return wssCertView{Fingerprint: c.Fingerprint, NotBefore: c.NotBefore, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt,
		DaysLeft: int(c.NotAfter.Sub(now).Hours() / 24)}
}

func wssView(st model.WSSState, now time.Time) []wssListenerView {
	out := []wssListenerView{}
	for i := range st.Listeners {
		l := &st.Listeners[i]
		v := wssListenerView{NodeID: l.NodeID, ServerName: l.ServerName, Cert: certView(l.Cert, now), Legacy: l.Legacy,
			Rotating: l.Rotating(), RotationReason: l.RotationReason, Inconsistent: l.Inconsistent(),
			Links: []wssLinkView{}, Parties: []wssPartyView{}, NextSteps: l.NextSteps(), Results: l.Results, Warnings: []wssWarning{}}
		if v.NextSteps == nil {
			v.NextSteps = []model.WSSStep{}
		}
		if v.Results == nil {
			v.Results = []model.WSSResult{}
		}
		if l.Pending != nil {
			pc := certView(*l.Pending, now)
			v.PendingCert = &pc
		}
		if !l.RotationStarted.IsZero() {
			rs := l.RotationStarted
			v.RotationStarted = &rs
		}
		_, srvUnc := l.Uncertain[model.WSSPartyServer]
		v.Parties = append(v.Parties, wssPartyView{Party: model.WSSPartyServer, Role: "server", NodeID: l.NodeID,
			Installed: l.InstalledStage(model.WSSPartyServer), Uncertain: srvUnc, Target: l.TargetServer(), Involved: true})
		for j := range l.Links {
			k := &l.Links[j]
			lv := wssLinkView{LinkID: k.LinkID, DialerID: k.DialerID, PathSet: k.Path.SecretID != "", PathCreatedAt: k.Path.CreatedAt, LegacyPath: k.Legacy != nil}
			if k.Pending != nil {
				pa := k.Pending.CreatedAt
				lv.PendingPathAt = &pa
			}
			v.Links = append(v.Links, lv)
			p := model.WSSClientParty(k.LinkID)
			_, unc := l.Uncertain[p]
			v.Parties = append(v.Parties, wssPartyView{Party: p, Role: "client", LinkID: k.LinkID, NodeID: k.DialerID,
				Installed: l.InstalledStage(p), Uncertain: unc, Target: l.TargetClient(k), Involved: l.Involved(k)})
		}
		v.Warnings = wssWarnings(l, now)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func wssWarnings(l *model.WSSListener, now time.Time) []wssWarning {
	w := []wssWarning{}
	left := l.Cert.NotAfter.Sub(now)
	switch {
	case left <= 0:
		w = append(w, wssWarning{"error", "证书已过期：客户端校验证书有效期，WSS 承载已无法建立。重新生成证书并按顺序下发两端。"})
	case left <= model.WSSUrgentBefore && l.Pending != nil:
		w = append(w, wssWarning{"error", "当前证书很快过期，新证书还没在两端装好：按「下一步」下发，否则到期后这条 WSS 承载会中断。"})
	case left <= model.WSSRotateBefore && l.Pending == nil && !l.Legacy:
		w = append(w, wssWarning{"warning", "证书将在 30 天内过期，但自动轮换还没开始（面板每小时检查一次）：可以手动重新生成证书。"})
	case left <= model.WSSRotateBefore && l.Pending != nil:
		w = append(w, wssWarning{"warning", "证书将在 30 天内过期，已自动生成新证书：按「下一步」依次下发两端完成轮换。"})
	}
	if l.Legacy {
		w = append(w, wssWarning{"warning", "从旧版固定路径迁移中：服务端暂时同时接受旧路径和新路径。先重新下发服务端，再重新下发每个客户端，最后再下发一次服务端，旧路径即被移除。"})
	}
	var unc []string
	for p := range l.Uncertain {
		unc = append(unc, p)
	}
	sort.Strings(unc)
	for _, p := range unc {
		w = append(w, wssWarning{"warning", p + " 的配置不确定（回滚或结果不明的安装之后）：重新下发该端；在这之前另一端保持不动。"})
	}
	if l.Inconsistent() && l.Rotating() {
		w = append(w, wssWarning{"warning", "两端暂不一致（只更新了一端）：这是轮换的中间状态，两端在相邻阶段时仍能互通；按「下一步」继续下发，直到两端都完成。"})
	}
	if n := len(l.Results); n > 0 && !l.Results[n-1].OK && l.Results[n-1].Stage >= 0 {
		r := l.Results[n-1]
		w = append(w, wssWarning{"warning", "上次在 " + r.NodeID + " 上安装 WSS 凭据失败（已补偿，旧配置仍在用）：" + r.Message})
	}
	sort.SliceStable(w, func(i, j int) bool { return w[i].Level == "error" && w[j].Level != "error" })
	return w
}

func (s *Server) getWSS(w http.ResponseWriter, r *http.Request) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	if t, err := s.topology(); err == nil {
		if err := s.ensureWSS(cs, t); err != nil {
			log.Printf("wss: material generation failed: %v", err)
		}
	}
	now := time.Now().UTC()
	if cs.Now != nil {
		now = cs.Now().UTC()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"listeners":       wssView(cs.WSSState(), now),
		"validity_days":   int(model.WSSCertValidity.Hours() / 24),
		"rotate_before":   int(model.WSSRotateBefore.Hours() / 24),
		"verification":    "wstunnel 11.1.0 没有指纹固定选项：客户端开启 --tls-verify-certificate，SSL_CERT_FILE 只含该监听的自签证书（唯一信任根），并按合成名称校验（--tls-sni-override）。",
		"interruption":    "每次在一端安装新阶段时，这端的 wstunnel 会重启，这条 WSS 承载中断几秒；两端始终处于相邻阶段，所以不会因为只更新了一端而断开。",
		"order":           "轮换顺序：服务端与客户端交替各下发约两次（面板列出下一步）；任一端失败会补偿回旧文件，旧凭据继续可用。",
		"secrets_visible": false,
	})
}

func (s *Server) wssAction(w http.ResponseWriter, f func(cs *credentials.Store) (model.WSSListener, error)) {
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	if t, err := s.topology(); err == nil {
		if err := s.ensureWSS(cs, t); err != nil {
			writeResErr(w, err)
			return
		}
	}
	l, err := f(cs)
	if err != nil {
		var ce *credentials.Error
		if errors.As(err, &ce) && ce.Code == credentials.CodeWSSRotating {
			writeCoded(w, http.StatusConflict, ce.Code, ce.Msg, nil)
			return
		}
		writeResErr(w, err)
		return
	}
	s.gcWSSSecrets(cs)
	now := time.Now().UTC()
	for _, v := range wssView(model.WSSState{Listeners: []model.WSSListener{l}}, now) {
		writeJSON(w, http.StatusOK, map[string]any{"listener": v, "committed": !l.Rotating()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) postWSSRegeneratePath(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wssAction(w, func(cs *credentials.Store) (model.WSSListener, error) { return cs.RegenerateWSSPath(id) })
}

func (s *Server) postWSSRegenerateCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wssAction(w, func(cs *credentials.Store) (model.WSSListener, error) {
		return cs.RegenerateWSSCert(id, model.WSSReasonCert)
	})
}

func (s *Server) postWSSCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wssAction(w, func(cs *credentials.Store) (model.WSSListener, error) {
		if err := cs.CancelWSSRotation(id); err != nil {
			return model.WSSListener{}, err
		}
		st := cs.WSSState()
		if l := st.Listener(id); l != nil {
			return *l, nil
		}
		return model.WSSListener{}, &credentials.Error{Code: credentials.CodeNotFound, Msg: "监听不存在"}
	})
}

// wssInstallResult maps a gateway install error to the WSS record.
func wssInstallResult(err error) (ok, unknown bool) {
	if err == nil {
		return true, false
	}
	var te *apply.TxnError
	if errors.As(err, &te) && !te.Compensated && te.CompErr != nil {
		return false, true
	}
	return false, false
}
