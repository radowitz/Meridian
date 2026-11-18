package api

// First-run setup wizard progress (GET/PUT /api/setup/wizard,
// POST /api/setup/wizard/complete).
//
// The wizard is shown only when the stored topology has no nodes (a fresh
// install), or while a wizard started on such an install is not finished
// yet (the wizard itself saves the topology half way). An existing
// deployment — nodes stored and no wizard record — never sees it.
//
// The record holds what the operator chose and typed that is not a secret:
// the gateway's LAN fields, the template, the template answers (server IDs
// only; SSH credentials stay in the credential store) and which steps are
// done. A change to an earlier step drops what depends on it (later steps,
// the saved topology version, the reviewed preflight), so nothing stale is
// carried into the install. The wizard never installs: its last step
// opens the existing deployment guide with its own preflight and
// confirmations.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/radowitz/meridian/internal/defaults"
)

const wizardKey = "setup_wizard"

// Wizard steps, in order.
var wizardSteps = []string{"gateway", "template", "servers", "topology", "preflight", "install"}

func wizardStepIndex(step string) int {
	for i, s := range wizardSteps {
		if s == step {
			return i
		}
	}
	return -1
}

type wizardGateway struct {
	LANInterface string `json:"lan_interface"`
	LANIPv4      string `json:"lan_ipv4"`
	RouterIPv4   string `json:"router_ipv4"`
}

// wizardInput is defaults.TemplateInput without the gateway block, so a
// stored or echoed state can never carry an (empty) gateway that would
// override wizardState.Gateway when the panel previews a template.
type wizardInput struct {
	Exits         []defaults.TemplateServer `json:"exits"`
	Relay         *defaults.TemplateServer  `json:"relay,omitempty"`
	Hub           *defaults.TemplateServer  `json:"hub,omitempty"`
	BackupHub     *defaults.TemplateServer  `json:"backup_hub,omitempty"`
	BackupRelays  []defaults.TemplateServer `json:"backup_relays,omitempty"`
	DefaultRegion string                    `json:"default_region"`
}

// wizardState is the stored record.
type wizardState struct {
	Step     string        `json:"step"`
	Done     []string      `json:"done"`
	Gateway  wizardGateway `json:"gateway"`
	Template string        `json:"template"`
	// Input: the template answers without the gateway block (that is
	// Gateway above); server references by ID only.
	Input           *wizardInput `json:"input,omitempty"`
	TopologyVersion string       `json:"topology_version,omitempty"`
	PreflightID     string       `json:"preflight_id,omitempty"`
	Started         bool         `json:"started"`
	Completed       bool         `json:"completed"`
	UpdatedAt       string       `json:"updated_at,omitempty"`
}

type wizardDetected struct {
	// LANIP is the address this request reached the panel at, when it is
	// a private or link-local IPv4 address (the panel listens on the LAN).
	LANIP string `json:"lan_ip,omitempty"`
}

type wizardView struct {
	Active   bool           `json:"active"`
	State    wizardState    `json:"state"`
	Detected wizardDetected `json:"detected"`
}

func (s *Server) registerWizard(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/setup/wizard", s.getWizard)
	mux.HandleFunc("PUT /api/setup/wizard", s.putWizard)
	mux.HandleFunc("POST /api/setup/wizard/complete", s.completeWizard)
}

func (s *Server) loadWizard() (wizardState, bool, error) {
	raw, ok, err := s.Store.Get(wizardKey)
	if err != nil || !ok {
		return wizardState{Step: "gateway", Done: []string{}}, false, err
	}
	var st wizardState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return wizardState{Step: "gateway", Done: []string{}}, false, nil
	}
	if st.Done == nil {
		st.Done = []string{}
	}
	if wizardStepIndex(st.Step) < 0 {
		st.Step = "gateway"
	}
	return st, true, nil
}

// wizardActive: no nodes stored, or a wizard begun on an empty install
// that is not completed.
func (s *Server) wizardActive(st wizardState, stored bool) (bool, error) {
	if st.Completed {
		return false, nil
	}
	if stored && st.Started {
		return true, nil
	}
	t, ok, err := s.Store.Load()
	if err != nil {
		return false, err
	}
	return !ok || len(t.Nodes) == 0, nil
}

func (s *Server) wizardView(r *http.Request, st wizardState, stored bool) (wizardView, error) {
	active, err := s.wizardActive(st, stored)
	if err != nil {
		return wizardView{}, err
	}
	v := wizardView{Active: active, State: st}
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ta, ok := a.(*net.TCPAddr); ok {
			if ip, ok := netip.AddrFromSlice(ta.IP); ok {
				ip = ip.Unmap()
				if ip.Is4() && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
					v.Detected.LANIP = ip.String()
				}
			}
		}
	}
	return v, nil
}

func (s *Server) getWizard(w http.ResponseWriter, r *http.Request) {
	st, stored, err := s.loadWizard()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	v, err := s.wizardView(r, st, stored)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func validWizard(st wizardState) error {
	if wizardStepIndex(st.Step) < 0 {
		return errors.New("没有这个步骤：" + st.Step)
	}
	for _, d := range st.Done {
		if wizardStepIndex(d) < 0 {
			return errors.New("没有这个步骤：" + d)
		}
	}
	if st.Template != "" {
		if _, ok := defaults.TemplateByID(st.Template); !ok {
			return errors.New("没有这个模板：" + st.Template)
		}
	}
	return nil
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// invalidate drops what depends on a changed earlier step: from the first
// changed step on, nothing counts as done, and the saved topology version
// and reviewed preflight are cleared.
func invalidate(prev, next wizardState) wizardState {
	first := -1
	switch {
	case !jsonEq(prev.Gateway, next.Gateway):
		first = wizardStepIndex("gateway")
	case prev.Template != next.Template:
		first = wizardStepIndex("template")
	case !jsonEq(prev.Input, next.Input):
		first = wizardStepIndex("servers")
	case prev.TopologyVersion != next.TopologyVersion && (next.PreflightID == "" || next.PreflightID == prev.PreflightID):
		// A new topology version without a new preflight review.
		first = wizardStepIndex("preflight")
	}
	if first < 0 {
		return next
	}
	var done []string
	for _, d := range next.Done {
		if i := wizardStepIndex(d); i >= 0 && i < first {
			done = append(done, d)
		}
	}
	if done == nil {
		done = []string{}
	}
	next.Done = done
	next.PreflightID = ""
	if first < wizardStepIndex("preflight") {
		next.TopologyVersion = ""
	}
	return next
}

func (s *Server) putWizard(w http.ResponseWriter, r *http.Request) {
	var in wizardState
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式不对：" + err.Error()})
		return
	}
	if err := validWizard(in); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	s.wizardMu.Lock()
	defer s.wizardMu.Unlock()
	prev, stored, err := s.loadWizard()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	active, err := s.wizardActive(prev, stored)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !active {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "已有部署，不使用配置向导", "code": "wizard_inactive"})
		return
	}
	if in.Done == nil {
		in.Done = []string{}
	}
	next := invalidate(prev, in)
	next.Started, next.Completed = true, false
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	buf, err := json.Marshal(next)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.Store.Put(wizardKey, string(buf)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	v, err := s.wizardView(r, next, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// completeWizard ends the wizard (the operator moved on to the deployment
// guide, or chose to leave it); the panel shows its normal pages from then
// on.
func (s *Server) completeWizard(w http.ResponseWriter, r *http.Request) {
	s.wizardMu.Lock()
	defer s.wizardMu.Unlock()
	st, _, err := s.loadWizard()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	st.Started, st.Completed = true, true
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	buf, _ := json.Marshal(st)
	if err := s.Store.Put(wizardKey, string(buf)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	v, err := s.wizardView(r, st, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
