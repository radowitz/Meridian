package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/remoteaccess"
	"github.com/radowitz/meridian/internal/validate"
)

// Remote access: the gateway's WireGuard entrance for the user's own
// devices. See docs/architecture.md「远程接入」. Every change edits the
// topology only (apply_required); it reaches the host through POST
// /api/apply. A device's configuration (with its private key) is returned
// exactly once, by create and regenerate; nothing else ever returns a
// private key or a pre-shared key.

func (s *Server) registerRemoteAccess(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/remote-access", s.getRemoteAccess)
	mux.HandleFunc("PUT /api/remote-access", s.putRemoteAccess)
	mux.HandleFunc("GET /api/remote-access/devices", s.listRemoteDevices)
	mux.HandleFunc("POST /api/remote-access/devices", s.createRemoteDevice)
	mux.HandleFunc("GET /api/remote-access/devices/{id}", s.getRemoteDevice)
	mux.HandleFunc("PATCH /api/remote-access/devices/{id}", s.patchRemoteDevice)
	mux.HandleFunc("DELETE /api/remote-access/devices/{id}", s.deleteRemoteDevice)
	mux.HandleFunc("POST /api/remote-access/devices/{id}/regenerate", s.regenerateRemoteDevice)
}

const (
	codeRemoteNotConfigured = "remote_not_configured"
	codeRemoteLimit         = "remote_device_limit"
	codeRemotePoolFull      = "remote_pool_full"
)

// ------------------------------------------------------------- views ---

type remoteSettingsView struct {
	Enabled     bool     `json:"enabled"`
	Endpoint    string   `json:"endpoint"`
	ListenPort  int      `json:"listen_port"`
	IPv4Prefix  string   `json:"ipv4_prefix"`
	IPv6Prefix  string   `json:"ipv6_prefix"`
	MTU         int      `json:"mtu"`
	Keepalive   int      `json:"keepalive"`
	Interface   string   `json:"interface"`
	GatewayIPv4 string   `json:"gateway_ipv4"`
	GatewayIPv6 string   `json:"gateway_ipv6"`
	DNS         []string `json:"dns"`
	PublicKey   string   `json:"public_key"`
	MaxDevices  int      `json:"max_devices"`
	DeviceCount int      `json:"device_count"`
	Defaults    struct {
		IPv4Prefix string `json:"ipv4_prefix"`
		IPv6Prefix string `json:"ipv6_prefix"`
		MTU        int    `json:"mtu"`
		Keepalive  int    `json:"keepalive"`
		Mode       string `json:"mode"`
	} `json:"defaults"`
	Modes map[string]string `json:"modes"`
}

type remoteDeviceView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Notes        string `json:"notes"`
	Mode         string `json:"mode"`
	Enabled      bool   `json:"enabled"`
	PublicKey    string `json:"public_key"`
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
	PresharedKey bool   `json:"preshared_key"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	KeyCreatedAt string `json:"key_created_at"`
	// ConfigAvailable is always false: the configuration (with the private
	// key) was shown once and is not stored. Regenerate to get a new one.
	ConfigAvailable bool `json:"config_available"`
	// ConfigOutdated: a server-side value the delivered configuration
	// embeds (endpoint, port, keys, pools, mode, MTU, keepalive) changed.
	ConfigOutdated bool `json:"config_outdated"`
	// Runtime is the peer's state on interface mra, read through the host
	// agent's parameterless status read and matched by public key. It is
	// null unless RuntimeState is "ok"; values are never invented.
	Runtime *deviceRuntime `json:"runtime"`
	// RuntimeState: ok, disabled (device disabled), not_installed (enabled
	// but not on the interface: apply pending), unavailable (agent or
	// interface not readable, see the top-level runtime), not_read (this
	// response did not read the runtime: mutations).
	RuntimeState string `json:"runtime_state"`
}

type deviceRuntime struct {
	// LastHandshakeAt is RFC 3339, or null when no handshake happened yet.
	LastHandshakeAt *string `json:"last_handshake_at"`
	RxBytes         int64   `json:"rx_bytes"`
	TxBytes         int64   `json:"tx_bytes"`
	// Online: a handshake within the last OnlineWindow seconds.
	Online bool `json:"online"`
}

// remoteOnlineWindow: WireGuard re-handshakes every 2 minutes while a peer
// sends traffic; 3 minutes without one counts as offline.
const remoteOnlineWindow = 180 * time.Second

// RemoteStatusRuntime is the host agent's remote-access status read
// (hostexec.Client in main).
type RemoteStatusRuntime interface {
	RemoteAccessStatus(ctx context.Context) (hostexec.WGStatus, error)
}

// remoteRuntimeView is the top-level runtime state of GET /api/remote-access.
type remoteRuntimeView struct {
	// Available: the peer table was read from the host.
	Available bool `json:"available"`
	// State: ok, disabled (remote access off), agent_unavailable,
	// interface_absent (mra does not exist: not applied yet), error.
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Interface string `json:"interface"`
	ReadAt    string `json:"read_at,omitempty"`
}

// readRemoteRuntime reads the peer table once (bounded to 15 s).
func (s *Server) readRemoteRuntime(ctx context.Context, t model.Topology) (remoteRuntimeView, map[string]hostexec.WGPeer) {
	v := remoteRuntimeView{Interface: model.RemoteAccessIface}
	switch {
	case !remoteOf(t).Enabled:
		v.State, v.Reason = "disabled", "远程接入未启用"
		return v, nil
	case s.RemoteStatus == nil:
		v.State, v.Reason = "agent_unavailable", "没有配置 host agent，读不到运行状态"
		return v, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	st, err := s.RemoteStatus.RemoteAccessStatus(ctx)
	switch {
	case err != nil && errors.Is(err, hostexec.ErrUnavailable):
		v.State, v.Reason = "agent_unavailable", err.Error()
		return v, nil
	case err != nil:
		v.State, v.Reason = "error", err.Error()
		return v, nil
	case !st.Present:
		v.State, v.Reason, v.ReadAt = "interface_absent", "接口 mra 不存在（还没有安装到本机，或已停用）", st.ReadAt
		return v, nil
	}
	v.Available, v.State, v.ReadAt = true, "ok", st.ReadAt
	peers := map[string]hostexec.WGPeer{}
	for _, p := range st.Peers {
		peers[p.PublicKey] = p
	}
	return v, peers
}

// withRuntime fills the devices' runtime from one read.
func withRuntime(views []remoteDeviceView, rt remoteRuntimeView, peers map[string]hostexec.WGPeer) []remoteDeviceView {
	now := time.Now()
	if t, err := time.Parse(time.RFC3339, rt.ReadAt); err == nil {
		now = t
	}
	for i := range views {
		v := &views[i]
		v.Runtime = nil
		switch {
		case !v.Enabled:
			v.RuntimeState = "disabled"
		case !rt.Available:
			v.RuntimeState = "unavailable"
		default:
			p, ok := peers[v.PublicKey]
			if !ok {
				v.RuntimeState = "not_installed"
				continue
			}
			r := &deviceRuntime{RxBytes: p.RxBytes, TxBytes: p.TxBytes}
			if p.LatestHandshake > 0 {
				at := time.Unix(p.LatestHandshake, 0).UTC()
				ts := at.Format(time.RFC3339)
				r.LastHandshakeAt = &ts
				r.Online = now.Sub(at) <= remoteOnlineWindow
			}
			v.Runtime, v.RuntimeState = r, "ok"
		}
	}
	return views
}

func remoteOf(t model.Topology) model.RemoteAccess {
	if t.RemoteAccess == nil {
		return model.RemoteAccess{}
	}
	return *t.RemoteAccess
}

func viewRemoteSettings(t model.Topology) remoteSettingsView {
	ra := remoteOf(t)
	v := remoteSettingsView{
		Enabled: ra.Enabled, Endpoint: ra.Endpoint, ListenPort: ra.ListenPort,
		IPv4Prefix: ra.V4Prefix(), IPv6Prefix: ra.V6Prefix(), MTU: ra.EffectiveMTU(), Keepalive: ra.EffectiveKeepalive(),
		Interface: model.RemoteAccessIface, PublicKey: ra.PublicKey,
		MaxDevices: model.MaxRemoteDevices, DeviceCount: len(ra.Devices),
		Modes: map[string]string{
			model.RemoteModeFull: remoteaccess.ModeExplanation(model.RemoteModeFull),
			model.RemoteModeHome: remoteaccess.ModeExplanation(model.RemoteModeHome),
		},
	}
	if a, _, ok := ra.GatewayV4(); ok {
		v.GatewayIPv4 = a.String()
	}
	if a, _, ok := ra.GatewayV6(); ok {
		v.GatewayIPv6 = a.String()
	}
	v.DNS = []string{}
	if v.GatewayIPv4 != "" && v.GatewayIPv6 != "" {
		v.DNS = []string{v.GatewayIPv4, v.GatewayIPv6}
	}
	v.Defaults.IPv4Prefix, v.Defaults.IPv6Prefix = model.DefaultRemoteV4Prefix, model.DefaultRemoteV6Prefix
	v.Defaults.MTU, v.Defaults.Keepalive, v.Defaults.Mode = model.DefaultRemoteMTU, model.DefaultRemoteKeepalive, model.RemoteModeFull
	return v
}

func viewRemoteDevice(t model.Topology, d model.RemoteDevice) remoteDeviceView {
	v := remoteDeviceView{
		ID: d.ID, Name: d.Name, Notes: d.Notes, Mode: d.Mode, Enabled: d.Enabled, PublicKey: d.PublicKey,
		IPv4: d.IPv4, IPv6: d.IPv6, PresharedKey: d.PSKID != "",
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, KeyCreatedAt: d.KeyCreatedAt,
		RuntimeState: "not_read",
	}
	if t.RemoteAccess != nil {
		v.ConfigOutdated = d.ConfigFingerprint != remoteaccess.Fingerprint(t, d)
	}
	return v
}

func viewRemoteDevices(t model.Topology) []remoteDeviceView {
	out := []remoteDeviceView{}
	for _, d := range remoteOf(t).Devices {
		out = append(out, viewRemoteDevice(t, d))
	}
	return out
}

// remoteIssues are the remote-access issues of t (checked as configured,
// enabled or not), for the panel.
func remoteIssues(t model.Topology) []validate.Issue {
	out := []validate.Issue{}
	return append(out, validate.CheckRemoteAccessConfig(t)...)
}

func (s *Server) getRemoteAccess(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	rt, peers := s.readRemoteRuntime(r.Context(), t)
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":       viewRemoteSettings(t),
		"router_forward": remoteaccess.Forward(t),
		"devices":        withRuntime(viewRemoteDevices(t), rt, peers),
		"runtime":        rt,
		"issues":         remoteIssues(t),
	})
}

// ---------------------------------------------------------- mutation ---

// remoteErrors returns the first remote-access error of next that prev did
// not already have, as an API error.
func remoteErrors(prev, next model.Topology) error {
	key := func(i validate.Issue) string { return i.Code + "|" + i.Field + "|" + i.DeviceID + "|" + i.Message }
	had := map[string]bool{}
	for _, i := range validate.CheckRemoteAccessConfig(prev) {
		had[key(i)] = true
	}
	for _, i := range validate.CheckRemoteAccessConfig(next) {
		if i.Severity != validate.SeverityError || had[key(i)] {
			continue
		}
		field := i.Field
		if i.DeviceID != "" {
			field = "devices." + field
		}
		return &credentials.Error{Code: i.Code, Field: field, Msg: i.Message}
	}
	return nil
}

// mutateRemote applies fn to the stored topology's remote-access block
// under raMu and the store lock, and refuses a change that adds a
// remote-access validation error.
func (s *Server) mutateRemote(fn func(t *model.Topology) error) (model.Topology, error) {
	var next model.Topology
	found, err := s.Store.Update(func(t *model.Topology) (bool, error) {
		prev := *t
		prev.RemoteAccess = t.RemoteAccess.Clone()
		t.RemoteAccess = t.RemoteAccess.Clone()
		if t.RemoteAccess == nil {
			t.RemoteAccess = &model.RemoteAccess{}
		}
		if err := fn(t); err != nil {
			return false, err
		}
		if err := remoteErrors(prev, *t); err != nil {
			return false, err
		}
		next = *t
		return true, nil
	})
	if err != nil {
		return model.Topology{}, err
	}
	if !found {
		if _, err := s.topology(); err != nil {
			return model.Topology{}, err
		}
		return s.mutateRemote(fn)
	}
	return next, nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// ensureGatewayKey makes sure the gateway's remote-access key exists in the
// credential store; a missing one is generated (its public key changes, so
// delivered client configurations become outdated). Call under raMu.
func ensureGatewayKey(cs *credentials.Store, ra *model.RemoteAccess) error {
	if ra.KeyID != "" && ra.PublicKey != "" {
		if _, err := cs.WGSecret(ra.KeyID); err == nil {
			return nil
		} else if !errors.Is(err, credentials.ErrNotFound) {
			return err
		}
	}
	kp, err := remoteaccess.GenerateKeypair()
	if err != nil {
		return err
	}
	id := cs.NewWGSecretID("ra-key")
	if err := cs.PutWGSecret(id, credentials.WGPurposeRemoteKey, kp.Private); err != nil {
		return err
	}
	ra.KeyID, ra.PublicKey = id, kp.Public
	return nil
}

type remoteSettingsInput struct {
	Enabled    *bool   `json:"enabled"`
	Endpoint   *string `json:"endpoint"`
	ListenPort *int    `json:"listen_port"`
	IPv4Prefix *string `json:"ipv4_prefix"`
	IPv6Prefix *string `json:"ipv6_prefix"`
	MTU        *int    `json:"mtu"`
	Keepalive  *int    `json:"keepalive"`
}

func (s *Server) putRemoteAccess(w http.ResponseWriter, r *http.Request) {
	var in remoteSettingsInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	s.raMu.Lock()
	defer s.raMu.Unlock()
	var newKey string
	t, err := s.mutateRemote(func(t *model.Topology) error {
		ra := t.RemoteAccess
		if in.Endpoint != nil {
			ep := strings.TrimSpace(*in.Endpoint)
			ep = strings.TrimSuffix(strings.TrimPrefix(ep, "["), "]")
			ra.Endpoint = ep
		}
		if in.ListenPort != nil {
			ra.ListenPort = *in.ListenPort
		}
		if in.MTU != nil {
			ra.MTU = *in.MTU
		}
		if in.Keepalive != nil {
			ra.Keepalive = *in.Keepalive
		}
		for _, p := range []struct {
			in   *string
			cur  *string
			def  string
			name string
		}{{in.IPv4Prefix, &ra.IPv4Prefix, model.DefaultRemoteV4Prefix, "ipv4_prefix"}, {in.IPv6Prefix, &ra.IPv6Prefix, model.DefaultRemoteV6Prefix, "ipv6_prefix"}} {
			if p.in == nil {
				continue
			}
			v := strings.TrimSpace(*p.in)
			if v == p.def {
				v = ""
			}
			if v != *p.cur && len(ra.Devices) > 0 {
				var refs []credentials.Ref
				for _, d := range ra.Devices {
					refs = append(refs, credentials.Ref{Kind: "remote_device", ID: d.ID, Name: d.Name})
				}
				return &credentials.Error{Code: credentials.CodeInUse, Field: p.name, InUse: refs,
					Msg: "地址池里还有设备；设备地址写在它们的配置里，先删除设备再改地址池"}
			}
			*p.cur = v
		}
		if in.Enabled != nil {
			ra.Enabled = *in.Enabled
		}
		if ra.Enabled {
			if strings.TrimSpace(ra.Endpoint) == "" || ra.ListenPort == 0 {
				return &credentials.Error{Code: codeRemoteNotConfigured, Field: "endpoint",
					Msg: "打开远程接入前必须填写 Endpoint 和监听端口"}
			}
		}
		before := ra.KeyID
		if err := ensureGatewayKey(cs, ra); err != nil {
			return err
		}
		if ra.KeyID != before {
			newKey = ra.KeyID
		}
		return nil
	})
	if err != nil {
		if newKey != "" {
			_ = cs.DeleteWGSecret(newKey)
		}
		writeResErr(w, err)
		return
	}
	s.gcRemoteSecretsLocked(cs, t)
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":       viewRemoteSettings(t),
		"router_forward": remoteaccess.Forward(t),
		"devices":        viewRemoteDevices(t),
		"issues":         remoteIssues(t),
		"apply_required": true,
	})
}

// ----------------------------------------------------------- devices ---

func remoteDeviceNotFound(id string) error {
	return &credentials.Error{Code: credentials.CodeNotFound, Field: "id", Msg: fmt.Sprintf("设备 %s 不存在", id)}
}

func (s *Server) listRemoteDevices(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	rt, peers := s.readRemoteRuntime(r.Context(), t)
	writeJSON(w, http.StatusOK, map[string]any{"devices": withRuntime(viewRemoteDevices(t), rt, peers), "runtime": rt})
}

func (s *Server) getRemoteDevice(w http.ResponseWriter, r *http.Request) {
	t, err := s.topology()
	if err != nil {
		writeResErr(w, err)
		return
	}
	d, ok := remoteOf(t).DeviceByID(r.PathValue("id"))
	if !ok {
		writeResErr(w, remoteDeviceNotFound(r.PathValue("id")))
		return
	}
	rt, peers := s.readRemoteRuntime(r.Context(), t)
	writeJSON(w, http.StatusOK, map[string]any{"device": withRuntime([]remoteDeviceView{viewRemoteDevice(t, d)}, rt, peers)[0], "runtime": rt})
}

type remoteDeviceInput struct {
	Name         *string `json:"name"`
	Notes        *string `json:"notes"`
	Mode         *string `json:"mode"`
	Enabled      *bool   `json:"enabled"`
	PresharedKey *bool   `json:"preshared_key"`
}

func (in remoteDeviceInput) applyTo(d *model.RemoteDevice) error {
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
	}
	if in.Notes != nil {
		if len(*in.Notes) > 1000 {
			return invalid("notes", "备注最长 1000 个字符")
		}
		d.Notes = *in.Notes
	}
	if in.Mode != nil {
		if *in.Mode != model.RemoteModeFull && *in.Mode != model.RemoteModeHome {
			return invalid("mode", "mode 只能是 full（全隧道）或 home（仅家网）")
		}
		d.Mode = *in.Mode
	}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	return nil
}

func requireConfigured(ra *model.RemoteAccess) error {
	if strings.TrimSpace(ra.Endpoint) == "" || ra.ListenPort == 0 {
		return &credentials.Error{Code: codeRemoteNotConfigured, Field: "endpoint",
			Msg: "先在远程接入设置里填写 Endpoint 和监听端口，设备配置里要用到它们"}
	}
	return nil
}

// issueDeviceKeys gives d a new key pair (and, when psk is set, a new
// pre-shared key stored under a new id). It returns the device's private
// key and the PSK value; both only go into the one-time response.
func issueDeviceKeys(cs *credentials.Store, d *model.RemoteDevice, psk bool) (private, pskValue, pskID string, err error) {
	kp, err := remoteaccess.GenerateKeypair()
	if err != nil {
		return "", "", "", err
	}
	d.PublicKey, d.KeyCreatedAt, d.PSKID = kp.Public, nowRFC3339(), ""
	if psk {
		if pskValue, err = remoteaccess.GeneratePSK(); err != nil {
			return "", "", "", err
		}
		pskID = cs.NewWGSecretID("ra-psk")
		if err := cs.PutWGSecret(pskID, credentials.WGPurposeRemotePSK, pskValue); err != nil {
			return "", "", "", err
		}
		d.PSKID = pskID
	}
	return kp.Private, pskValue, pskID, nil
}

// writeConfigResponse delivers the one-time configuration. The response
// must not be cached anywhere.
func writeConfigResponse(w http.ResponseWriter, code int, t model.Topology, d model.RemoteDevice, private, psk string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, code, map[string]any{
		"device":         viewRemoteDevice(t, d),
		"config":         remoteaccess.RenderClient(t, d, private, psk),
		"router_forward": remoteaccess.Forward(t),
		"apply_required": true,
	})
}

func (s *Server) createRemoteDevice(w http.ResponseWriter, r *http.Request) {
	var in remoteDeviceInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	s.raMu.Lock()
	defer s.raMu.Unlock()
	var private, psk, pskID, keyID, id string
	t, err := s.mutateRemote(func(t *model.Topology) error {
		ra := t.RemoteAccess
		if err := requireConfigured(ra); err != nil {
			return err
		}
		if len(ra.Devices) >= model.MaxRemoteDevices {
			return &credentials.Error{Code: codeRemoteLimit, Field: "devices", Msg: fmt.Sprintf("最多 %d 台设备", model.MaxRemoteDevices)}
		}
		before := ra.KeyID
		if err := ensureGatewayKey(cs, ra); err != nil {
			return err
		}
		if ra.KeyID != before {
			keyID = ra.KeyID
		}
		now := nowRFC3339()
		d := model.RemoteDevice{Mode: model.RemoteModeFull, Enabled: true, CreatedAt: now, UpdatedAt: now}
		if err := in.applyTo(&d); err != nil {
			return err
		}
		if d.Name == "" {
			return invalid("name", "设备名称不能为空")
		}
		d.ID = remoteaccess.NewDeviceID(func(id string) bool { _, ok := ra.DeviceByID(id); return ok })
		a4, a6, err := remoteaccess.AllocateAddresses(*ra)
		if err != nil {
			return &credentials.Error{Code: codeRemotePoolFull, Field: "ipv4_prefix", Msg: "设备地址池已满"}
		}
		d.IPv4, d.IPv6 = a4.String(), a6.String()
		if private, psk, pskID, err = issueDeviceKeys(cs, &d, in.PresharedKey == nil || *in.PresharedKey); err != nil {
			return err
		}
		ra.Devices = append(ra.Devices, d)
		d.ConfigFingerprint = remoteaccess.Fingerprint(*t, d)
		ra.Devices[len(ra.Devices)-1] = d
		id = d.ID
		return nil
	})
	if err != nil {
		for _, sid := range []string{pskID, keyID} {
			if sid != "" {
				_ = cs.DeleteWGSecret(sid)
			}
		}
		writeResErr(w, err, private, psk)
		return
	}
	d, _ := t.RemoteAccess.DeviceByID(id)
	writeConfigResponse(w, http.StatusCreated, t, d, private, psk)
}

func (s *Server) patchRemoteDevice(w http.ResponseWriter, r *http.Request) {
	var in remoteDeviceInput
	if err := decodeBody(w, r, &in); err != nil {
		writeResErr(w, err)
		return
	}
	if in.PresharedKey != nil {
		writeResErr(w, invalid("preshared_key", "预共享密钥只能在重新生成时改变"))
		return
	}
	id := r.PathValue("id")
	s.raMu.Lock()
	defer s.raMu.Unlock()
	t, err := s.mutateRemote(func(t *model.Topology) error {
		for i := range t.RemoteAccess.Devices {
			d := &t.RemoteAccess.Devices[i]
			if d.ID != id {
				continue
			}
			if err := in.applyTo(d); err != nil {
				return err
			}
			d.UpdatedAt = nowRFC3339()
			return nil
		}
		return remoteDeviceNotFound(id)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	d, _ := t.RemoteAccess.DeviceByID(id)
	writeJSON(w, http.StatusOK, map[string]any{"device": viewRemoteDevice(t, d), "apply_required": true})
}

func (s *Server) deleteRemoteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.raMu.Lock()
	defer s.raMu.Unlock()
	t, err := s.mutateRemote(func(t *model.Topology) error {
		ra := t.RemoteAccess
		for i, d := range ra.Devices {
			if d.ID == id {
				ra.Devices = append(ra.Devices[:i:i], ra.Devices[i+1:]...)
				return nil
			}
		}
		return remoteDeviceNotFound(id)
	})
	if err != nil {
		writeResErr(w, err)
		return
	}
	if cs, err := s.credStore(); err == nil {
		s.gcRemoteSecretsLocked(cs, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id, "apply_required": true})
}

type regenerateInput struct {
	PresharedKey *bool `json:"preshared_key"`
}

func (s *Server) regenerateRemoteDevice(w http.ResponseWriter, r *http.Request) {
	var in regenerateInput
	if err := decodeOptional(r, &in); err != nil {
		writeResErr(w, badRequest())
		return
	}
	id := r.PathValue("id")
	cs, err := s.credStore()
	if err != nil {
		writeResErr(w, err)
		return
	}
	s.raMu.Lock()
	defer s.raMu.Unlock()
	var private, psk, pskID, keyID string
	t, err := s.mutateRemote(func(t *model.Topology) error {
		ra := t.RemoteAccess
		if err := requireConfigured(ra); err != nil {
			return err
		}
		before := ra.KeyID
		if err := ensureGatewayKey(cs, ra); err != nil {
			return err
		}
		if ra.KeyID != before {
			keyID = ra.KeyID
		}
		for i := range ra.Devices {
			d := &ra.Devices[i]
			if d.ID != id {
				continue
			}
			want := d.PSKID != ""
			if in.PresharedKey != nil {
				want = *in.PresharedKey
			}
			var err error
			if private, psk, pskID, err = issueDeviceKeys(cs, d, want); err != nil {
				return err
			}
			d.UpdatedAt = nowRFC3339()
			d.ConfigFingerprint = remoteaccess.Fingerprint(*t, *d)
			return nil
		}
		return remoteDeviceNotFound(id)
	})
	if err != nil {
		for _, sid := range []string{pskID, keyID} {
			if sid != "" {
				_ = cs.DeleteWGSecret(sid)
			}
		}
		writeResErr(w, err, private, psk)
		return
	}
	s.gcRemoteSecretsLocked(cs, t)
	d, _ := t.RemoteAccess.DeviceByID(id)
	writeConfigResponse(w, http.StatusOK, t, d, private, psk)
}

// ------------------------------------------------------------ secrets ---

// gcRemoteSecretsLocked deletes WireGuard secrets nothing refers to any
// more: not the topology (gateway key, device PSKs) and no stored copy of a
// configuration (snapshots, installed copy, staged copy), so compensation
// and rollback can still restore the previous peers. Call under raMu.
func (s *Server) gcRemoteSecretsLocked(cs *credentials.Store, t model.Topology) {
	refs, err := s.applier(true).ReferencedSecrets()
	if err != nil {
		log.Printf("remote access: keeping WireGuard secrets, snapshots unreadable: %v", err)
		return
	}
	if ra := t.RemoteAccess; ra != nil {
		refs[ra.KeyID] = true
		for _, d := range ra.Devices {
			refs[d.PSKID] = true
		}
	}
	for _, m := range cs.WGSecretIDs() {
		if !refs[m.ID] {
			if err := cs.DeleteWGSecret(m.ID); err != nil {
				log.Printf("remote access: could not delete unused WireGuard secret %s: %v", m.ID, err)
			}
		}
	}
}

// GCRemoteSecrets runs the secret garbage collection after an install or a
// rollback committed (a removed device's PSK becomes unreferenced then).
func (s *Server) GCRemoteSecrets() {
	cs, err := s.credStore()
	if err != nil {
		return
	}
	t, err := s.topology()
	if err != nil {
		return
	}
	s.raMu.Lock()
	defer s.raMu.Unlock()
	s.gcRemoteSecretsLocked(cs, t)
	s.gcWSSSecrets(cs)
}

// wgSecrets are the WireGuard secrets for the install boundary. With no
// credential store there are none; an install whose configs need one then
// fails before anything is written (apply.ErrMissingSecret).
func (s *Server) wgSecrets() map[string]string {
	cs, err := s.credStore()
	if err != nil {
		return nil
	}
	m, err := cs.WGSecrets()
	if err != nil {
		log.Printf("remote access: WireGuard secrets unreadable: %v", err)
		return nil
	}
	// The WSS carriers' secrets (path prefixes, the listener's private
	// key) go through the same install boundary (apply.InjectSecrets
	// keeps each kind to its own files).
	w, err := cs.WSSSecrets()
	if err != nil {
		log.Printf("wss: secrets unreadable: %v", err)
		return m
	}
	for id, v := range w {
		m[id] = v
	}
	return m
}
