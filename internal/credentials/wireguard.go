package credentials

import (
	"encoding/base64"
	"sort"
)

// WireGuard secrets of the remote-access entrance: the gateway's
// remote-access private key and the optional per-device pre-shared keys.
// Device private keys are never stored. A value is only ever read back for
// the install boundary (apply.Applier.Secrets); the API never returns it.

// WireGuard secret purposes.
const (
	WGPurposeRemoteKey = "remote_access_key"
	WGPurposeRemotePSK = "remote_access_psk"
)

// WGSecretMeta is the index record of one WireGuard secret (no material).
type WGSecretMeta struct {
	ID        string `json:"id"`
	Purpose   string `json:"purpose"`
	CreatedAt string `json:"created_at"`
}

func validWGKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// NewWGSecretID returns an unused ID with the prefix.
func (s *Store) NewWGSecretID(prefix string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		id := newID(prefix)
		if !s.idx.idTaken(id) {
			return id
		}
	}
}

// PutWGSecret stores a new WireGuard key under id. An existing id is
// refused: a key is replaced by storing a new one under a new id.
func (s *Store) PutWGSecret(id, purpose, key string) error {
	if !ValidID(id) {
		return errf(CodeInvalid, "id", "密钥存储 ID 不合法")
	}
	if purpose != WGPurposeRemoteKey && purpose != WGPurposeRemotePSK {
		return errf(CodeInvalid, "purpose", "未知的 WireGuard 密钥用途")
	}
	if !validWGKey(key) {
		return errf(CodeInvalidKey, "key", "WireGuard 密钥格式不正确（应为 32 字节 base64）")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx.idTaken(id) {
		return errf(CodeConflict, "id", "存储 ID %s 已被占用", id)
	}
	next := cloneIndex(s.idx)
	next.WGSecrets = append(next.WGSecrets, WGSecretMeta{ID: id, Purpose: purpose, CreatedAt: s.now()})
	return s.commit(next, map[string]secret{s.secretPath(id, 1): {Kind: purpose, WGKey: key}})
}

// WGSecretIDs lists the stored WireGuard secrets (metadata only), sorted.
func (s *Store) WGSecretIDs() []WGSecretMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]WGSecretMeta(nil), s.idx.WGSecrets...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// WGSecret reads one WireGuard secret (install boundary only).
func (s *Store) WGSecret(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, w := range s.idx.WGSecrets {
		found = found || w.ID == id
	}
	if !found {
		return "", errf(CodeNotFound, "id", "WireGuard 密钥 %s 不存在", id)
	}
	sec, err := s.readSecret(id, 1)
	if err != nil {
		return "", err
	}
	if !validWGKey(sec.WGKey) {
		return "", errf(CodeStorage, "", "WireGuard 密钥 %s 的文件损坏", id)
	}
	return sec.WGKey, nil
}

// WGSecrets reads every stored WireGuard secret, keyed by id, for the
// install boundary. Any unreadable one is an error (nothing partial).
func (s *Store) WGSecrets() (map[string]string, error) {
	out := map[string]string{}
	for _, w := range s.WGSecretIDs() {
		v, err := s.WGSecret(w.ID)
		if err != nil {
			return nil, err
		}
		out[w.ID] = v
	}
	return out, nil
}

// DeleteWGSecret removes one WireGuard secret; an unknown id is a no-op.
func (s *Store) DeleteWGSecret(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	kept := next.WGSecrets[:0]
	found := false
	for _, w := range next.WGSecrets {
		if w.ID == id {
			found = true
			continue
		}
		kept = append(kept, w)
	}
	if !found {
		return nil
	}
	next.WGSecrets = kept
	return s.commit(next, nil)
}
