package model

import (
	"sort"
	"strings"
	"time"
)

// WSS carrier credentials (see docs/architecture.md「WSS 承载：随机路径与自签证书」).
//
// Every WSS listener (one wstunnel server per listening node, on its
// wss_listen_port) has a panel-generated self-signed certificate; every
// WSS link has a panel-generated random upgrade path prefix. The path and
// the certificate's private key are secrets in the credential store
// (internal/credentials); this file only holds the public state: the
// certificate itself, its fingerprint and validity, the synthetic name
// clients verify, which credential-store ids hold the secrets, and the
// two-sided rotation state. None of it is part of the topology.
//
// Rotation runs in stages so that the two ends never stop fitting
// together, whichever end is installed first and whether an install
// fails half-way. A party is one end of the carrier: the listener's
// server ("server") or the dialing end of one link ("client:<link>").
// For a rotation with a pending certificate C' and/or a pending path P'
// (current C, P):
//
//	stage  server accepts  server presents  client sends  client trusts
//	0      P               C                P             C
//	1      P, P'           C                P             C, C'
//	2      P, P'           C'               P'            C, C'
//	3      P'              C'               P'            C'
//
// Any two adjacent stages work together. A party is only ever installed
// at most one stage ahead of the other end's installed stage (Target*),
// so after each successful install, failed install or compensation the
// two ends are at most one stage apart and the carrier keeps working.
// When every deployed party reached stage 3 the pending material becomes
// current and the stages reset to 0 (stage 3 renders exactly like stage
// 0 of the new generation).
//
// A listener migrated from the pre-random-path versions (fixed
// wss_path_prefix, operator certificate files, unverified client) is
// Legacy: the new path and certificate are already current and the old
// fixed path is kept as an extra accepted prefix on the server until every
// deployed client runs the new, verifying configuration (server stage 1:
// old+new paths, new certificate; client: new path, trusts only the new
// certificate; server stage 3: new path only). The old client does not
// verify the certificate, so it keeps working against server stage 1.

// Party names.
const (
	WSSPartyServer       = "server"
	WSSPartyClientPrefix = "client:"
)

// Installed-stage sentinels.
const (
	// WSSStageNone: this party was never installed with managed material
	// (it constrains nobody).
	WSSStageNone = -1
	// WSSStageUnknown: passed to the store's MarkWSSNode after a gateway
	// rollback (the party may run any stage from 0 up to its recorded one:
	// see WSSListener.Uncertain).
	WSSStageUnknown = -2
)

// WSSClientParty is the party name of a link's dialing end.
func WSSClientParty(linkID string) string { return WSSPartyClientPrefix + linkID }

// WSSCert is one generation of a listener's certificate (public part).
type WSSCert struct {
	// Serial identifies the generation (hex of the X.509 serial).
	Serial string `json:"serial"`
	// CertPEM is the self-signed certificate (public; installed on the
	// server and, as the only trust root, on every client).
	CertPEM string `json:"cert_pem"`
	// Fingerprint is the SHA-256 of the DER certificate (hex, colon
	// separated): what the panel shows and what the trust file pins.
	Fingerprint string    `json:"fingerprint_sha256"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	CreatedAt   time.Time `json:"created_at"`
	// KeySecretID names the private key in the credential store.
	KeySecretID string `json:"key_secret_id"`
}

// WSSPath is one generation of a link's upgrade path prefix (the value is
// a credential-store secret).
type WSSPath struct {
	SecretID  string    `json:"secret_id"`
	CreatedAt time.Time `json:"created_at"`
}

// WSSLink is the path state of one WSS link of a listener.
type WSSLink struct {
	LinkID   string   `json:"link_id"`
	DialerID string   `json:"dialer_id"`
	Path     WSSPath  `json:"path"`
	Pending  *WSSPath `json:"pending,omitempty"`
	// Legacy is the pre-migration fixed prefix, still accepted by the
	// server during a legacy migration (nil when it was not a plain token
	// or the migration finished).
	Legacy *WSSPath `json:"legacy,omitempty"`
}

// WSSResult is one recorded install outcome of a party.
type WSSResult struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	NodeID  string    `json:"node_id"`
	Party   string    `json:"party"`
	Stage   int       `json:"stage"`
	Message string    `json:"message,omitempty"`
}

// WSSListener is the state of one listener (one wstunnel server).
type WSSListener struct {
	NodeID string `json:"node_id"`
	// ServerName is the synthetic DNS name in the certificate and the
	// name every client sends as SNI and verifies (never a real domain;
	// it ends in the reserved .invalid).
	ServerName string    `json:"server_name"`
	Cert       WSSCert   `json:"cert"`
	Pending    *WSSCert  `json:"pending,omitempty"`
	Legacy     bool      `json:"legacy,omitempty"`
	Links      []WSSLink `json:"links"`
	// Installed is the stage each party was last installed at
	// successfully (absent: WSSStageNone).
	Installed map[string]int `json:"installed,omitempty"`
	// Uncertain is the stage an install with an unknown outcome may have
	// applied (or 0 after a gateway rollback): the party may run anything
	// between it and its Installed stage until it is installed again.
	Uncertain       map[string]int `json:"uncertain,omitempty"`
	RotationReason  string         `json:"rotation_reason,omitempty"`
	RotationStarted time.Time      `json:"rotation_started,omitempty"`
	Results         []WSSResult    `json:"results,omitempty"`
}

// WSSState is every listener's state (kept in the credential store's
// index, outside the topology and the data-directory snapshots).
type WSSState struct {
	// Migrated is set once the first migration from the fixed-path
	// versions ran (a listener created afterwards is never Legacy).
	Migrated  bool          `json:"migrated,omitempty"`
	Listeners []WSSListener `json:"listeners,omitempty"`
}

// WSSEnd is one WSS link with its listening and dialing node.
type WSSEnd struct {
	LinkID     string
	ListenerID string
	DialerID   string
}

// Rotation reasons.
const (
	WSSReasonPath      = "manual_path"
	WSSReasonCert      = "manual_cert"
	WSSReasonExpiry    = "expiry"
	WSSReasonMigration = "migration"
)

// WSSRotateBefore is how long before expiry a rotation starts on its own;
// WSSUrgentBefore is when the warning becomes urgent.
const (
	WSSCertValidity = 365 * 24 * time.Hour
	WSSRotateBefore = 30 * 24 * time.Hour
	WSSUrgentBefore = 14 * 24 * time.Hour
)

// Listener returns a pointer to the listener of nodeID (nil when none).
func (s *WSSState) Listener(nodeID string) *WSSListener {
	for i := range s.Listeners {
		if s.Listeners[i].NodeID == nodeID {
			return &s.Listeners[i]
		}
	}
	return nil
}

// Sort orders listeners and links (stable JSON).
func (s *WSSState) Sort() {
	sort.Slice(s.Listeners, func(i, j int) bool { return s.Listeners[i].NodeID < s.Listeners[j].NodeID })
	for i := range s.Listeners {
		l := &s.Listeners[i]
		sort.Slice(l.Links, func(a, b int) bool { return l.Links[a].LinkID < l.Links[b].LinkID })
	}
}

// Link returns a pointer to the link state (nil when none).
func (l *WSSListener) Link(linkID string) *WSSLink {
	for i := range l.Links {
		if l.Links[i].LinkID == linkID {
			return &l.Links[i]
		}
	}
	return nil
}

// Rotating reports whether any pending material or a legacy migration is
// in progress.
func (l *WSSListener) Rotating() bool {
	if l.Pending != nil || l.Legacy {
		return true
	}
	for _, k := range l.Links {
		if k.Pending != nil {
			return true
		}
	}
	return false
}

// Involved reports whether the link's client takes part in the current
// rotation (a path-only rotation of another link leaves it alone).
func (l *WSSListener) Involved(k *WSSLink) bool {
	return l.Legacy || l.Pending != nil || k.Pending != nil
}

// InstalledStage is the recorded stage of a party (WSSStageNone if absent).
func (l *WSSListener) InstalledStage(party string) int {
	if v, ok := l.Installed[party]; ok {
		return v
	}
	return WSSStageNone
}

// StageRange is the range of stages a party may actually run: its last
// successful stage, widened by an install whose outcome is unknown (it may
// or may not have applied its target) or by a gateway rollback (anything
// from stage 0 up). ok is false for a party that was never installed.
func (l *WSSListener) StageRange(party string) (lo, hi int, ok bool) {
	inst := l.InstalledStage(party)
	u, unc := l.Uncertain[party]
	switch {
	case !unc && inst == WSSStageNone:
		return 0, 0, false
	case !unc:
		return inst, inst, true
	case inst == WSSStageNone:
		return u, u, true
	default:
		return min(inst, u), max(inst, u), true
	}
}

// TargetServer is the stage the server is rendered at for its next
// install: one ahead of the lowest stage any involved client may run, and
// never more than one behind the highest (so every possible client stage
// fits).
func (l *WSSListener) TargetServer() int {
	if !l.Rotating() {
		return 0
	}
	loMin, hiMax := 4, -1
	for i := range l.Links {
		k := &l.Links[i]
		if !l.Involved(k) {
			continue
		}
		lo, hi, ok := l.StageRange(WSSClientParty(k.LinkID))
		if !ok {
			continue
		}
		loMin, hiMax = min(loMin, lo), max(hiMax, hi)
	}
	if l.Legacy {
		// Old clients (stage 0: fixed path, no verification) need the old
		// prefix accepted; they accept any certificate.
		if loMin < 2 {
			return 1
		}
		return 3
	}
	if loMin == 4 {
		return 3
	}
	return max(min(3, loMin+1), hiMax-1)
}

// TargetClient is the stage the link's client is rendered at for its
// next install.
func (l *WSSListener) TargetClient(k *WSSLink) int {
	if !l.Rotating() || !l.Involved(k) {
		return 0
	}
	if l.Legacy {
		return 3
	}
	lo, hi, ok := l.StageRange(WSSPartyServer)
	if !ok {
		return 3
	}
	return max(min(3, lo+1), hi-1)
}

// ServerPaths are the credential-store ids of the prefixes the server
// accepts for link k at stage.
func (l *WSSListener) ServerPaths(k *WSSLink, stage int) []string {
	if l.Legacy {
		if stage < 3 && k.Legacy != nil {
			return []string{k.Legacy.SecretID, k.Path.SecretID}
		}
		return []string{k.Path.SecretID}
	}
	if k.Pending == nil {
		return []string{k.Path.SecretID}
	}
	switch {
	case stage <= 0:
		return []string{k.Path.SecretID}
	case stage >= 3:
		return []string{k.Pending.SecretID}
	default:
		return []string{k.Path.SecretID, k.Pending.SecretID}
	}
}

// ServerCert is the certificate the server presents at stage.
func (l *WSSListener) ServerCert(stage int) WSSCert {
	if !l.Legacy && l.Pending != nil && stage >= 2 {
		return *l.Pending
	}
	return l.Cert
}

// ClientPath is the credential-store id of the prefix the client of k
// sends at stage.
func (l *WSSListener) ClientPath(k *WSSLink, stage int) string {
	if !l.Legacy && k.Pending != nil && stage >= 2 {
		return k.Pending.SecretID
	}
	return k.Path.SecretID
}

// ClientTrust are the certificates a client trusts at stage (its only
// trust roots).
func (l *WSSListener) ClientTrust(stage int) []WSSCert {
	if l.Legacy || l.Pending == nil {
		return []WSSCert{l.Cert}
	}
	switch {
	case stage <= 0:
		return []WSSCert{l.Cert}
	case stage >= 3:
		return []WSSCert{*l.Pending}
	default:
		return []WSSCert{l.Cert, *l.Pending}
	}
}

// Deployed reports whether any party of the rotation has been installed.
func (l *WSSListener) anyInvolvedDeployed() bool {
	if _, _, ok := l.StageRange(WSSPartyServer); ok {
		return true
	}
	for i := range l.Links {
		k := &l.Links[i]
		if _, _, ok := l.StageRange(WSSClientParty(k.LinkID)); ok && l.Involved(k) {
			return true
		}
	}
	return false
}

// Complete reports whether every deployed party of the rotation reached
// stage 3 (nothing deployed counts as complete).
func (l *WSSListener) Complete() bool {
	if !l.Rotating() {
		return false
	}
	done := func(p string) bool {
		lo, hi, ok := l.StageRange(p)
		return !ok || (lo == 3 && hi == 3)
	}
	if !done(WSSPartyServer) {
		return false
	}
	for i := range l.Links {
		k := &l.Links[i]
		if l.Involved(k) && !done(WSSClientParty(k.LinkID)) {
			return false
		}
	}
	return true
}

// Commit makes the pending material current when the rotation is
// complete. It returns the credential-store ids no longer named by the
// listener (old paths, old key, legacy prefixes) and whether it committed.
func (l *WSSListener) Commit() ([]string, bool) {
	if !l.Complete() {
		return nil, false
	}
	var released []string
	if l.Pending != nil {
		released = append(released, l.Cert.KeySecretID)
		l.Cert = *l.Pending
		l.Pending = nil
	}
	for i := range l.Links {
		k := &l.Links[i]
		if k.Pending != nil {
			released = append(released, k.Path.SecretID)
			k.Path = *k.Pending
			k.Pending = nil
		}
		if k.Legacy != nil {
			released = append(released, k.Legacy.SecretID)
			k.Legacy = nil
		}
	}
	l.Legacy = false
	for p, v := range l.Installed {
		if v == 3 {
			l.Installed[p] = 0
		}
	}
	for p, v := range l.Uncertain {
		if v == 3 {
			l.Uncertain[p] = 0
		}
	}
	l.RotationReason = ""
	l.RotationStarted = time.Time{}
	return released, true
}

// Record stores an install outcome of a party and keeps the last results.
func (l *WSSListener) Record(r WSSResult) {
	if r.OK {
		if l.Installed == nil {
			l.Installed = map[string]int{}
		}
		l.Installed[r.Party] = r.Stage
		delete(l.Uncertain, r.Party)
	}
	l.Results = append(l.Results, r)
	if n := len(l.Results); n > 20 {
		l.Results = append([]WSSResult(nil), l.Results[n-20:]...)
	}
}

// SecretIDs lists every credential-store id the listener names.
func (l *WSSListener) SecretIDs() []string {
	out := []string{l.Cert.KeySecretID}
	if l.Pending != nil {
		out = append(out, l.Pending.KeySecretID)
	}
	for _, k := range l.Links {
		out = append(out, k.Path.SecretID)
		if k.Pending != nil {
			out = append(out, k.Pending.SecretID)
		}
		if k.Legacy != nil {
			out = append(out, k.Legacy.SecretID)
		}
	}
	return out
}

// StartedWithNothingDeployed reports whether the rotation can complete at
// once because no involved party was ever installed.
func (l *WSSListener) StartedWithNothingDeployed() bool {
	return l.Rotating() && !l.anyInvolvedDeployed()
}

// WSSStep is one install a rotation still needs.
type WSSStep struct {
	NodeID string `json:"node_id"`
	Party  string `json:"party"`
	From   int    `json:"from"`
	To     int    `json:"to"`
}

// NextSteps lists the parties whose next install advances the rotation.
func (l *WSSListener) NextSteps() []WSSStep {
	var out []WSSStep
	if !l.Rotating() {
		// Idle: only an uncertain end (rollback, unknown outcome) needs
		// an install.
		if l.uncertain(WSSPartyServer) {
			out = append(out, WSSStep{NodeID: l.NodeID, Party: WSSPartyServer, From: l.InstalledStage(WSSPartyServer), To: 0})
		}
		for i := range l.Links {
			k := &l.Links[i]
			if p := WSSClientParty(k.LinkID); l.uncertain(p) {
				out = append(out, WSSStep{NodeID: k.DialerID, Party: p, From: l.InstalledStage(p), To: 0})
			}
		}
		return out
	}
	// A party that was never installed is not waited for: its first
	// install renders whatever its target is then.
	if v, t := l.InstalledStage(WSSPartyServer), l.TargetServer(); (v != t && v != WSSStageNone) || l.uncertain(WSSPartyServer) {
		out = append(out, WSSStep{NodeID: l.NodeID, Party: WSSPartyServer, From: v, To: t})
	}
	for i := range l.Links {
		k := &l.Links[i]
		if !l.Involved(k) {
			continue
		}
		p := WSSClientParty(k.LinkID)
		if v, t := l.InstalledStage(p), l.TargetClient(k); (v != t && v != WSSStageNone) || l.uncertain(p) {
			out = append(out, WSSStep{NodeID: k.DialerID, Party: p, From: v, To: t})
		}
	}
	return out
}

func (l *WSSListener) uncertain(p string) bool {
	_, ok := l.Uncertain[p]
	return ok
}

// Inconsistent reports whether the ends are known to run different
// stages or one end's configuration is uncertain.
func (l *WSSListener) Inconsistent() bool {
	if len(l.Uncertain) > 0 {
		return true
	}
	seen := map[int]bool{}
	add := func(v int) {
		if v != WSSStageNone {
			seen[v] = true
		}
	}
	add(l.InstalledStage(WSSPartyServer))
	for i := range l.Links {
		k := &l.Links[i]
		if l.Involved(k) || !l.Rotating() {
			add(l.InstalledStage(WSSClientParty(k.LinkID)))
		}
	}
	return len(seen) > 1
}

// WSSServerName builds the synthetic verification name from a random
// label: "<label>.invalid" (RFC 6761: never resolves, never a real domain).
func WSSServerName(label string) string {
	return strings.ToLower(label) + ".invalid"
}
