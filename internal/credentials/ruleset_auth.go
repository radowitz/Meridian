package credentials

import (
	"sort"
)

// Rule-set subscription credentials (internal/ruleset auth.go): the bearer
// token, basic-auth user and password, or secret query parameters a private
// rule-set URL needs. One per rule-set, keyed by the rule-set's ID. The
// material is write-only: never returned by the API, never in the topology,
// snapshots, exports, status, errors or logs; the panel reads it only to
// download that rule-set.

// RuleSetAuthIDPrefix starts every rule-set credential's store id.
const RuleSetAuthIDPrefix = "rsauth"

// RuleSetAuthMeta is the metadata of one rule-set credential (no material).
type RuleSetAuthMeta struct {
	ID        string `json:"id"`
	RuleSetID string `json:"rule_set_id"`
	Kind      string `json:"kind"` // bearer, basic, query
	SecretSet bool   `json:"secret_set"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type ruleSetAuthRecord struct {
	RuleSetAuthMeta
	Gen int `json:"gen"`
}

// RuleSetAuthInput is the material (write-only). Its validation is the
// caller's (ruleset.Auth.Check); the store only checks the kind.
type RuleSetAuthInput struct {
	Kind     string
	Token    string
	Username string
	Password string
	Query    string
}

func (i *index) rsAuth(ruleSetID string) int {
	for n, c := range i.RuleSetAuth {
		if c.RuleSetID == ruleSetID {
			return n
		}
	}
	return -1
}

func validRSKind(k string) bool { return k == "bearer" || k == "basic" || k == "query" }

// RuleSetAuth returns the metadata of a rule-set's credential.
func (s *Store) RuleSetAuth(ruleSetID string) (RuleSetAuthMeta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.rsAuth(ruleSetID)
	if n < 0 {
		return RuleSetAuthMeta{}, false
	}
	return s.idx.RuleSetAuth[n].RuleSetAuthMeta, true
}

// RuleSetAuths lists every rule-set credential (metadata only).
func (s *Store) RuleSetAuths() []RuleSetAuthMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RuleSetAuthMeta, 0, len(s.idx.RuleSetAuth))
	for _, c := range s.idx.RuleSetAuth {
		out = append(out, c.RuleSetAuthMeta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleSetID < out[j].RuleSetID })
	return out
}

// SetRuleSetAuth stores (or rotates) a rule-set's credential.
func (s *Store) SetRuleSetAuth(ruleSetID string, in RuleSetAuthInput) (RuleSetAuthMeta, error) {
	if !ValidID(ruleSetID) {
		return RuleSetAuthMeta{}, errf(CodeInvalid, "rule_set_id", "规则集 ID 不合法")
	}
	if !validRSKind(in.Kind) {
		return RuleSetAuthMeta{}, errf(CodeInvalid, "kind", "认证方式只能是 bearer、basic 或 query")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	now := s.now()
	n := next.rsAuth(ruleSetID)
	var rec ruleSetAuthRecord
	if n < 0 {
		id := RuleSetAuthIDPrefix + "-" + ruleSetID
		if !ValidID(id) || next.idTaken(id) {
			id = newID(RuleSetAuthIDPrefix)
			for next.idTaken(id) {
				id = newID(RuleSetAuthIDPrefix)
			}
		}
		rec = ruleSetAuthRecord{RuleSetAuthMeta: RuleSetAuthMeta{ID: id, RuleSetID: ruleSetID, CreatedAt: now}}
		next.RuleSetAuth = append(next.RuleSetAuth, rec)
		n = len(next.RuleSetAuth) - 1
	} else {
		rec = next.RuleSetAuth[n]
	}
	rec.Gen++
	rec.Kind, rec.SecretSet, rec.UpdatedAt = in.Kind, true, now
	next.RuleSetAuth[n] = rec
	sec := secret{Kind: "ruleset_auth"}
	switch in.Kind {
	case "bearer":
		sec.RSToken = in.Token
	case "basic":
		sec.RSUser, sec.RSPass = in.Username, in.Password
	case "query":
		sec.RSQuery = in.Query
	}
	if err := s.commit(next, map[string]secret{s.secretPath(rec.ID, rec.Gen): sec}); err != nil {
		return RuleSetAuthMeta{}, err
	}
	return rec.RuleSetAuthMeta, nil
}

// DeleteRuleSetAuth removes a rule-set's credential (no error when none).
func (s *Store) DeleteRuleSetAuth(ruleSetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.rsAuth(ruleSetID)
	if n < 0 {
		return nil
	}
	next := cloneIndex(s.idx)
	next.RuleSetAuth = append(next.RuleSetAuth[:n], next.RuleSetAuth[n+1:]...)
	return s.commit(next, nil)
}

// RuleSetAuthSecret reads a rule-set's credential for a download. ok is
// false when the rule-set has none.
func (s *Store) RuleSetAuthSecret(ruleSetID string) (RuleSetAuthInput, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.idx.rsAuth(ruleSetID)
	if n < 0 {
		return RuleSetAuthInput{}, false, nil
	}
	rec := s.idx.RuleSetAuth[n]
	sec, err := s.readSecret(rec.ID, rec.Gen)
	if err != nil {
		return RuleSetAuthInput{}, true, err
	}
	in := RuleSetAuthInput{Kind: rec.Kind, Token: sec.RSToken, Username: sec.RSUser, Password: sec.RSPass, Query: sec.RSQuery}
	switch {
	case in.Kind == "bearer" && in.Token == "",
		in.Kind == "basic" && in.Username == "",
		in.Kind == "query" && in.Query == "":
		return RuleSetAuthInput{}, true, errf(CodeStorage, "", "规则集 %s 的订阅认证文件损坏", ruleSetID)
	}
	return in, true, nil
}
