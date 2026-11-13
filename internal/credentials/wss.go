package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

// WSS carrier secrets: every WSS link's random upgrade path prefix and
// every WSS listener's certificate private key. They are generated here,
// stored like the other secrets (0600 generation files, metadata in the
// index), never returned by the API and read back only for the install
// boundary (gateway install, remote provision). The public state
// (certificates, fingerprints, rotation stages) is model.WSSState in the
// index. See docs/architecture.md「WSS 承载：随机路径与自签证书」.

// WSS secret purposes.
const (
	WSSPurposePath = "wss_path"
	WSSPurposeKey  = "wss_key"
)

// ID prefixes of WSS secrets (apply.InjectSecrets tells the kinds apart by
// them: a path may only land in a WSS file, never in a WireGuard config).
const (
	WSSPathIDPrefix = "wssp"
	WSSKeyIDPrefix  = "wssk"
)

// WSSPathBytes is the entropy of a generated path prefix (192 bits, 48
// lowercase hex characters).
const WSSPathBytes = 24

// WSSSecretMeta is the index record of one WSS secret (no material).
type WSSSecretMeta struct {
	ID        string `json:"id"`
	Purpose   string `json:"purpose"`
	CreatedAt string `json:"created_at"`
	// Legacy marks a migrated fixed prefix (kept only while old clients
	// still need it).
	Legacy bool `json:"legacy,omitempty"`
}

var (
	wssGenPathRe = regexp.MustCompile(`^[0-9a-f]{48}$`)
	// WSSLegacyPathRe: a migrated fixed prefix that may be accepted during
	// the migration (a plain token: nothing a regex or YAML would read).
	WSSLegacyPathRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// LegacyWSSDefaultPath is what the fixed-path versions used when a node
// had no wss_path_prefix.
const LegacyWSSDefaultPath = "example-wss-path-prefix"

// ValidWSSPath reports whether v can be installed as a path prefix.
func ValidWSSPath(v string) bool {
	return wssGenPathRe.MatchString(v) || WSSLegacyPathRe.MatchString(v)
}

// ValidWSSKey reports whether v is a PEM private key we generated.
func ValidWSSKey(v string) bool {
	b, rest := pem.Decode([]byte(v))
	if b == nil || b.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return false
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return false
	}
	_, ok := k.(*ecdsa.PrivateKey)
	return ok
}

// GenerateWSSPath returns a new random path prefix.
func GenerateWSSPath() (string, error) {
	var b [WSSPathBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// GenerateWSSServerName returns a new synthetic verification name.
func GenerateWSSServerName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return model.WSSServerName("w" + hex.EncodeToString(b[:])), nil
}

// GenerateWSSCert creates a self-signed certificate for name: ECDSA P-256,
// SHA-256, a 128-bit random serial, CN and the only SAN dNSName = name,
// key usage digitalSignature, extended key usage serverAuth, not a CA,
// valid from now-48h (clock skew) to now+model.WSSCertValidity. It returns
// the certificate (public) and the PKCS#8 PEM private key (secret).
func GenerateWSSCert(name string, now time.Time) (model.WSSCert, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return model.WSSCert{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return model.WSSCert{}, "", err
	}
	now = now.UTC().Truncate(time.Second)
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(model.WSSCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return model.WSSCert{}, "", err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return model.WSSCert{}, "", err
	}
	c := model.WSSCert{
		Serial:      hex.EncodeToString(serial.Bytes()),
		CertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Fingerprint: WSSFingerprint(der),
		NotBefore:   tpl.NotBefore,
		NotAfter:    tpl.NotAfter,
		CreatedAt:   now,
	}
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})), nil
}

// WSSFingerprint is the SHA-256 of a DER certificate, hex with colons.
func WSSFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// wssTx collects the secrets a WSS state change writes in one commit.
type wssTx struct {
	s       *Store
	next    *index
	secrets map[string]secret
	now     time.Time
}

func (tx *wssTx) put(prefix, purpose, value string, legacy bool) string {
	var id string
	for {
		id = newID(prefix)
		if !tx.next.idTaken(id) {
			break
		}
	}
	tx.next.WSSSecrets = append(tx.next.WSSSecrets, WSSSecretMeta{ID: id, Purpose: purpose, CreatedAt: tx.now.UTC().Format(time.RFC3339), Legacy: legacy})
	tx.secrets[tx.s.secretPath(id, 1)] = secret{Kind: purpose, WSSValue: value}
	return id
}

func (tx *wssTx) newPath() (model.WSSPath, error) {
	v, err := GenerateWSSPath()
	if err != nil {
		return model.WSSPath{}, err
	}
	return model.WSSPath{SecretID: tx.put(WSSPathIDPrefix, WSSPurposePath, v, false), CreatedAt: tx.now.UTC().Truncate(time.Second)}, nil
}

func (tx *wssTx) newCert(name string) (model.WSSCert, error) {
	c, key, err := GenerateWSSCert(name, tx.now)
	if err != nil {
		return model.WSSCert{}, err
	}
	c.KeySecretID = tx.put(WSSKeyIDPrefix, WSSPurposeKey, key, false)
	return c, nil
}

// updateWSS runs f on a copy of the WSS state and commits the state and
// the new secrets together (nothing partial on error).
func (s *Store) updateWSS(now time.Time, f func(st *model.WSSState, tx *wssTx) (bool, error)) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	tx := &wssTx{s: s, next: &next, secrets: map[string]secret{}, now: now}
	changed, err := f(&next.WSS, tx)
	if err != nil || !changed {
		return false, err
	}
	next.WSS.Sort()
	return true, s.commit(next, tx.secrets)
}

func (s *Store) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// WSSState returns a copy of the public WSS state.
func (s *Store) WSSState() model.WSSState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneIndex(s.idx).WSS
}

// WSSSecretIDs lists the stored WSS secrets (metadata only), sorted.
func (s *Store) WSSSecretIDs() []WSSSecretMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]WSSSecretMeta(nil), s.idx.WSSSecrets...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// WSSSecrets reads every stored WSS secret, keyed by id, for the install
// boundary. Any unreadable or malformed one is an error.
func (s *Store) WSSSecrets() (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, m := range s.idx.WSSSecrets {
		sec, err := s.readSecret(m.ID, 1)
		if err != nil {
			return nil, err
		}
		ok := false
		switch m.Purpose {
		case WSSPurposePath:
			ok = ValidWSSPath(sec.WSSValue)
		case WSSPurposeKey:
			ok = ValidWSSKey(sec.WSSValue)
		}
		if !ok {
			return nil, errf(CodeStorage, "", "WSS 密钥 %s 的文件损坏", m.ID)
		}
		out[m.ID] = sec.WSSValue
	}
	return out, nil
}

// DeleteWSSSecrets removes WSS secrets; unknown ids are ignored. The
// caller makes sure nothing (state, gateway snapshots) names them.
func (s *Store) DeleteWSSSecrets(ids []string) error {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	kept := next.WSSSecrets[:0]
	for _, w := range next.WSSSecrets {
		if !drop[w.ID] {
			kept = append(kept, w)
		}
	}
	if len(kept) == len(s.idx.WSSSecrets) {
		return nil
	}
	next.WSSSecrets = kept
	return s.commit(next, nil)
}

// WSSUnusedSecrets lists stored WSS secrets the state no longer names.
func (s *Store) WSSUnusedSecrets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	used := map[string]bool{}
	for i := range s.idx.WSS.Listeners {
		for _, id := range s.idx.WSS.Listeners[i].SecretIDs() {
			used[id] = true
		}
	}
	var out []string
	for _, w := range s.idx.WSSSecrets {
		if !used[w.ID] {
			out = append(out, w.ID)
		}
	}
	sort.Strings(out)
	return out
}

// WSSLegacy describes a listener of the fixed-path versions.
type WSSLegacy struct {
	// Path is the old fixed prefix (LegacyWSSDefaultPath when the node had
	// none); a value that is not a plain token is not carried over.
	Path string
}

// EnsureWSS makes the state match the WSS links: a new listener gets a
// synthetic name and a certificate, a new link a random path, a link whose
// dialer changed loses its client's installed stage, and listeners and
// links that are gone are dropped (their secrets are deleted later by the
// caller's garbage collection, once no gateway snapshot names them).
//
// The first run (state not yet migrated) treats every listener in legacy
// as migrated from the fixed-path versions when deployed reports that the
// listener or one of its dialers was installed: the old prefix stays
// accepted until the clients are re-provisioned (see model.WSSListener).
// It is idempotent: a second run with the same input changes nothing.
func (s *Store) EnsureWSS(ends []model.WSSEnd, legacy map[string]WSSLegacy, deployed func(nodeID string) bool) (bool, error) {
	return s.updateWSS(s.clock(), func(st *model.WSSState, tx *wssTx) (bool, error) {
		changed := false
		byListener := map[string][]model.WSSEnd{}
		for _, e := range ends {
			byListener[e.ListenerID] = append(byListener[e.ListenerID], e)
		}
		firstRun := !st.Migrated
		if firstRun {
			st.Migrated = true
			changed = true
		}
		// Drop listeners without links.
		kept := st.Listeners[:0]
		for _, l := range st.Listeners {
			if _, ok := byListener[l.NodeID]; ok {
				kept = append(kept, l)
			} else {
				changed = true
			}
		}
		st.Listeners = kept
		ids := make([]string, 0, len(byListener))
		for id := range byListener {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, nodeID := range ids {
			es := byListener[nodeID]
			l := st.Listener(nodeID)
			if l == nil {
				name, err := GenerateWSSServerName()
				if err != nil {
					return false, err
				}
				c, err := tx.newCert(name)
				if err != nil {
					return false, err
				}
				st.Listeners = append(st.Listeners, model.WSSListener{NodeID: nodeID, ServerName: name, Cert: c})
				l = &st.Listeners[len(st.Listeners)-1]
				changed = true
				if _, ok := legacy[nodeID]; ok && firstRun && deployed != nil {
					wasDeployed := deployed(nodeID)
					for _, e := range es {
						wasDeployed = wasDeployed || deployed(e.DialerID)
					}
					if wasDeployed {
						l.Legacy = true
						l.RotationReason = model.WSSReasonMigration
						l.RotationStarted = tx.now.UTC().Truncate(time.Second)
						l.Installed = map[string]int{}
						if deployed(nodeID) {
							l.Installed[model.WSSPartyServer] = 0
						}
						for _, e := range es {
							if deployed(e.DialerID) {
								l.Installed[model.WSSClientParty(e.LinkID)] = 0
							}
						}
					}
				}
			}
			want := map[string]model.WSSEnd{}
			for _, e := range es {
				want[e.LinkID] = e
			}
			links := l.Links[:0]
			for _, k := range l.Links {
				if _, ok := want[k.LinkID]; ok {
					links = append(links, k)
				} else {
					delete(l.Installed, model.WSSClientParty(k.LinkID))
					delete(l.Uncertain, model.WSSClientParty(k.LinkID))
					changed = true
				}
			}
			l.Links = links
			for _, e := range es {
				k := l.Link(e.LinkID)
				if k == nil {
					p, err := tx.newPath()
					if err != nil {
						return false, err
					}
					nk := model.WSSLink{LinkID: e.LinkID, DialerID: e.DialerID, Path: p}
					if lg, ok := legacy[nodeID]; ok && l.Legacy && WSSLegacyPathRe.MatchString(lg.Path) {
						nk.Legacy = &model.WSSPath{SecretID: tx.put(WSSPathIDPrefix, WSSPurposePath, lg.Path, true), CreatedAt: tx.now.UTC().Truncate(time.Second)}
					}
					l.Links = append(l.Links, nk)
					changed = true
					continue
				}
				if k.DialerID != e.DialerID {
					k.DialerID = e.DialerID
					delete(l.Installed, model.WSSClientParty(e.LinkID))
					delete(l.Uncertain, model.WSSClientParty(e.LinkID))
					changed = true
				}
			}
			if l.Legacy && l.Complete() {
				l.Commit()
				changed = true
			}
		}
		return changed, nil
	})
}

// ErrWSSRotating: a rotation of this listener is already in progress.
const CodeWSSRotating = "wss_rotation_in_progress"

// RegenerateWSSPath starts a path rotation of one link. When neither end
// was ever installed the new path replaces the old one at once.
func (s *Store) RegenerateWSSPath(linkID string) (model.WSSListener, error) {
	var out model.WSSListener
	_, err := s.updateWSS(s.clock(), func(st *model.WSSState, tx *wssTx) (bool, error) {
		for i := range st.Listeners {
			l := &st.Listeners[i]
			k := l.Link(linkID)
			if k == nil {
				continue
			}
			if l.Legacy || k.Pending != nil {
				return false, errf(CodeWSSRotating, "link_id", "链路 %s 的 WSS 凭据正在轮换或迁移：先完成当前轮换", linkID)
			}
			p, err := tx.newPath()
			if err != nil {
				return false, err
			}
			k.Pending = &p
			startRotation(l, model.WSSReasonPath, tx.now)
			out = *l
			return true, nil
		}
		return false, errf(CodeNotFound, "link_id", "链路 %s 不是 WSS 链路，或还没有生成 WSS 凭据", linkID)
	})
	if err != nil {
		return model.WSSListener{}, err
	}
	return out, nil
}

// RegenerateWSSCert starts a certificate rotation of one listener.
func (s *Store) RegenerateWSSCert(nodeID, reason string) (model.WSSListener, error) {
	var out model.WSSListener
	_, err := s.updateWSS(s.clock(), func(st *model.WSSState, tx *wssTx) (bool, error) {
		l := st.Listener(nodeID)
		if l == nil {
			return false, errf(CodeNotFound, "node_id", "节点 %s 没有 WSS 监听", nodeID)
		}
		if l.Legacy || l.Pending != nil {
			return false, errf(CodeWSSRotating, "node_id", "节点 %s 的 WSS 证书正在轮换或迁移：先完成当前轮换", nodeID)
		}
		c, err := tx.newCert(l.ServerName)
		if err != nil {
			return false, err
		}
		l.Pending = &c
		startRotation(l, reason, tx.now)
		out = *l
		return true, nil
	})
	if err != nil {
		return model.WSSListener{}, err
	}
	return out, nil
}

func startRotation(l *model.WSSListener, reason string, now time.Time) {
	if l.RotationReason == "" {
		l.RotationReason = reason
		l.RotationStarted = now.UTC().Truncate(time.Second)
	}
	if l.StartedWithNothingDeployed() {
		l.Commit()
	}
}

// CancelWSSRotation drops the pending material of a listener while no
// involved party has been installed with it (every deployed party still
// at stage 0). A legacy migration cannot be cancelled.
func (s *Store) CancelWSSRotation(nodeID string) error {
	_, err := s.updateWSS(s.clock(), func(st *model.WSSState, _ *wssTx) (bool, error) {
		l := st.Listener(nodeID)
		if l == nil || !l.Rotating() {
			return false, errf(CodeNotFound, "node_id", "节点 %s 没有进行中的 WSS 轮换", nodeID)
		}
		if l.Legacy {
			return false, errf(CodeConflict, "node_id", "旧版固定路径的迁移不能取消：重新下发两端即可完成")
		}
		for p := range l.Uncertain {
			return false, errf(CodeConflict, "node_id", "%s 的配置不确定，不能取消：先重新下发该端", p)
		}
		for p, v := range l.Installed {
			if v != 0 && v != model.WSSStageNone {
				return false, errf(CodeConflict, "node_id", "已有一端（%s）装上了新凭据，不能取消：继续按顺序下发两端完成轮换", p)
			}
		}
		l.Pending = nil
		for i := range l.Links {
			l.Links[i].Pending = nil
		}
		l.RotationReason = ""
		l.RotationStarted = time.Time{}
		return true, nil
	})
	return err
}

// WSSPartyStage is one party a bundle rendered, at which stage.
type WSSPartyStage struct {
	ListenerID string `json:"listener_id"`
	Party      string `json:"party"`
	NodeID     string `json:"node_id"`
	Stage      int    `json:"stage"`
}

// RecordWSSInstall stores the outcome of an install of nodeID that
// rendered parties (only those on nodeID are recorded). ok=false keeps the
// installed stages (the compensation restored the previous files) and
// records the failure; unknown marks the parties' configuration unknown.
// A rotation whose every deployed party reached stage 3 is committed.
func (s *Store) RecordWSSInstall(nodeID string, parties []WSSPartyStage, ok, unknown bool, msg string) error {
	now := s.clock()
	_, err := s.updateWSS(now, func(st *model.WSSState, _ *wssTx) (bool, error) {
		changed := false
		for _, p := range parties {
			if p.NodeID != nodeID {
				continue
			}
			l := st.Listener(p.ListenerID)
			if l == nil {
				continue
			}
			if p.Party != model.WSSPartyServer {
				if k := l.Link(strings.TrimPrefix(p.Party, model.WSSPartyClientPrefix)); k == nil || k.DialerID != nodeID {
					continue
				}
			} else if l.NodeID != nodeID {
				continue
			}
			r := model.WSSResult{At: now.Truncate(time.Second), OK: ok, NodeID: nodeID, Party: p.Party, Stage: p.Stage, Message: msg}
			l.Record(r)
			if unknown {
				if l.Uncertain == nil {
					l.Uncertain = map[string]int{}
				}
				l.Uncertain[p.Party] = p.Stage
			}
			l.Commit()
			changed = true
		}
		return changed, nil
	})
	return err
}

// MarkWSSNode sets every party on nodeID to stage (model.WSSStageUnknown
// after a gateway rollback, model.WSSStageNone after a withdraw).
func (s *Store) MarkWSSNode(nodeID string, stage int, msg string) error {
	now := s.clock()
	_, err := s.updateWSS(now, func(st *model.WSSState, _ *wssTx) (bool, error) {
		changed := false
		for i := range st.Listeners {
			l := &st.Listeners[i]
			var parties []string
			if l.NodeID == nodeID {
				parties = append(parties, model.WSSPartyServer)
			}
			for _, k := range l.Links {
				if k.DialerID == nodeID {
					parties = append(parties, model.WSSClientParty(k.LinkID))
				}
			}
			for _, p := range parties {
				if l.Installed == nil {
					l.Installed = map[string]int{}
				}
				switch stage {
				case model.WSSStageNone:
					delete(l.Installed, p)
					delete(l.Uncertain, p)
				case model.WSSStageUnknown:
					// Anything from stage 0 up to the recorded stage.
					if l.Uncertain == nil {
						l.Uncertain = map[string]int{}
					}
					l.Uncertain[p] = 0
				default:
					l.Installed[p] = stage
				}
				l.Results = append(l.Results, model.WSSResult{At: now.Truncate(time.Second), OK: stage != model.WSSStageUnknown, NodeID: nodeID, Party: p, Stage: stage, Message: msg})
				changed = true
			}
			if len(parties) > 0 {
				l.Commit()
			}
		}
		return changed, nil
	})
	return err
}

// WSSExpiryTick starts a certificate rotation for every listener whose
// certificate expires within model.WSSRotateBefore and that is not
// rotating yet. It returns the listeners it started.
func (s *Store) WSSExpiryTick() ([]string, error) {
	var started []string
	_, err := s.updateWSS(s.clock(), func(st *model.WSSState, tx *wssTx) (bool, error) {
		for i := range st.Listeners {
			l := &st.Listeners[i]
			if l.Pending != nil || l.Legacy || l.Cert.NotAfter.Sub(tx.now) > model.WSSRotateBefore {
				continue
			}
			c, err := tx.newCert(l.ServerName)
			if err != nil {
				return false, err
			}
			l.Pending = &c
			startRotation(l, model.WSSReasonExpiry, tx.now)
			started = append(started, l.NodeID)
		}
		return len(started) > 0, nil
	})
	return started, err
}
