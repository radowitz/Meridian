package acceptance

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Outcomes of a stored result.
const (
	// OutcomePass / OutcomeFail: the check, the drill or the person's
	// sign-off concluded.
	OutcomePass = "pass"
	OutcomeFail = "fail"
	// OutcomeInconclusive: it ran, and what it looked for could not be
	// decided (part of the reaction was seen, a sample could not be read).
	OutcomeInconclusive = "inconclusive"
	// OutcomeCancelled: stopped before a conclusion; the host was restored.
	OutcomeCancelled = "cancelled"
	// OutcomeError: it could not be carried out (no host agent, refused).
	OutcomeError = "error"
	// OutcomeRestoreFailed: a drill whose restore was not verified. Never
	// shown as passed, whatever the drill observed.
	OutcomeRestoreFailed = "restore_failed"
)

var outcomes = map[string]bool{OutcomePass: true, OutcomeFail: true, OutcomeInconclusive: true, OutcomeCancelled: true, OutcomeError: true, OutcomeRestoreFailed: true}

// Result is one stored result of one part of one item.
type Result struct {
	// ID is the record id; RunID the id of the job or drill that produced
	// it (a later state of the same run replaces the earlier record).
	ID     string `json:"id"`
	RunID  string `json:"run_id,omitempty"`
	ItemID string `json:"item_id"`
	// Part is PartConfig, PartMeasured or PartSignoff; Method how it was
	// carried out (ModeAuto, ModeDrill, ModeManual).
	Part    string    `json:"part"`
	Method  string    `json:"method"`
	Action  string    `json:"action,omitempty"`
	Target  string    `json:"target,omitempty"`
	Outcome string    `json:"outcome"`
	At      time.Time `json:"at"`
	// DurationMS is how long it ran (0 for a sign-off).
	DurationMS int64 `json:"duration_ms,omitempty"`
	// Fingerprint is the configuration fingerprint it was carried out
	// under (Fingerprint); InstalledVersion the installed version then
	// (0: nothing installed).
	Fingerprint      string `json:"fingerprint"`
	InstalledVersion int64  `json:"installed_version,omitempty"`
	Summary          string `json:"summary"`
	// Details are short evidence lines (no address, key or name of a real
	// host: the callers pass node ids, interface names and counts).
	Details []string `json:"details,omitempty"`
	// Residual is what a drill left different from the state before.
	Residual []string `json:"residual,omitempty"`
	// Note is the operator's note, redacted (RedactNote).
	Note string `json:"note,omitempty"`
}

// Limits of the store.
const (
	// MaxPerItem bounds the history kept per item.
	MaxPerItem = 20
	// MaxNote bounds a note (runes), MaxDetails the evidence lines.
	MaxNote    = 500
	MaxDetails = 40
)

// KV is the persistence the store needs (store.Store implements it).
type KV interface {
	Get(key string) (string, bool, error)
	Put(key, value string) error
}

// Key is the document key in the panel's store.
const Key = "acceptance_results"

type doc struct {
	// Results per item id, oldest first.
	Results map[string][]Result `json:"results"`
}

// Store keeps the results. Safe for concurrent use.
type Store struct {
	mu sync.Mutex
	kv KV
}

// NewStore returns a store on kv.
func NewStore(kv KV) *Store { return &Store{kv: kv} }

func (s *Store) load() (doc, error) {
	d := doc{Results: map[string][]Result{}}
	raw, ok, err := s.kv.Get(Key)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return d, err
	}
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return doc{}, fmt.Errorf("验收记录损坏：%w", err)
	}
	if d.Results == nil {
		d.Results = map[string][]Result{}
	}
	return d, nil
}

// ErrUnknownItem is returned for a result of an item not in the catalog.
var ErrUnknownItem = errors.New("没有这个验收项")

// Add stores r (assigning ID when empty). A result with the RunID of a
// stored one of the same item and part replaces it. The note is redacted
// and the texts are bounded here, whatever the caller passed.
func (s *Store) Add(r Result) (Result, error) {
	it, ok := Lookup(r.ItemID)
	if !ok {
		return r, ErrUnknownItem
	}
	if !it.Needs(r.Part) {
		return r, fmt.Errorf("验收项 %s 没有「%s」这一部分", r.ItemID, r.Part)
	}
	if !outcomes[r.Outcome] {
		return r, fmt.Errorf("未知的结果 %q", r.Outcome)
	}
	if r.Fingerprint == "" {
		return r, errors.New("结果必须带配置指纹")
	}
	if r.ID == "" {
		r.ID = "acc-" + randHex(6)
	}
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	r.At = r.At.UTC()
	r.Note = RedactNote(r.Note)
	r.Summary = clipRunes(r.Summary, 300)
	r.Details = clipLines(r.Details)
	r.Residual = clipLines(r.Residual)
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return r, err
	}
	list := d.Results[r.ItemID]
	replaced := false
	if r.RunID != "" {
		for i := range list {
			if list[i].RunID == r.RunID && list[i].Part == r.Part {
				r.ID = list[i].ID
				list[i] = r
				replaced = true
			}
		}
	}
	if !replaced {
		list = append(list, r)
	}
	if len(list) > MaxPerItem {
		list = list[len(list)-MaxPerItem:]
	}
	d.Results[r.ItemID] = list
	b, err := json.Marshal(d)
	if err != nil {
		return r, err
	}
	return r, s.kv.Put(Key, string(b))
}

// FindRun returns the stored result of a run (a drill) for one part of an
// item, if any.
func (s *Store) FindRun(itemID, part, runID string) (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return Result{}, false, err
	}
	for _, r := range d.Results[itemID] {
		if r.RunID == runID && r.Part == part {
			return r, true, nil
		}
	}
	return Result{}, false, nil
}

// StoredResult is a result with its validity under the current fingerprint.
type StoredResult struct {
	Result
	// Stale: the configuration or the installed version changed since. The
	// result is kept and shown, and no longer counts.
	Stale bool `json:"stale"`
}

// PartView is one evidence part of an item.
type PartView struct {
	Part string `json:"part"`
	// Latest is the newest result of the part, stale or not; Valid the
	// newest one carried out under the current fingerprint (nil: none).
	Latest *StoredResult `json:"latest,omitempty"`
	Valid  *StoredResult `json:"valid,omitempty"`
}

// States of an item as a whole.
const (
	// StateVerified: every part the item needs has a valid passed result.
	StateVerified = "verified"
	// StateFailed: a valid result of some part failed (or a drill's
	// restore was not verified).
	StateFailed = "failed"
	// StatePartial: some parts have a valid passed result, others have no
	// valid result yet.
	StatePartial = "partial"
	// StateInconclusive: results under the current configuration exist, and
	// none of them decided anything (cancelled, inconclusive, error).
	StateInconclusive = "inconclusive"
	// StateStale: there are results, none of them under the current
	// configuration.
	StateStale = "stale"
	// StateNotRun: nothing was ever recorded.
	StateNotRun = "not_run"
)

// ItemView is what is stored for one item under the current fingerprint.
type ItemView struct {
	State   string         `json:"state"`
	Parts   []PartView     `json:"parts"`
	History []StoredResult `json:"history"`
}

// View returns every item's results, judged under fingerprint.
func (s *Store) View(fingerprint string) (map[string]ItemView, error) {
	s.mu.Lock()
	d, err := s.load()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := map[string]ItemView{}
	for _, it := range catalog {
		out[it.ID] = viewOf(it, d.Results[it.ID], fingerprint)
	}
	return out, nil
}

func viewOf(it Item, results []Result, fingerprint string) ItemView {
	v := ItemView{Parts: []PartView{}, History: []StoredResult{}}
	sorted := append([]Result(nil), results...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })
	for i := len(sorted) - 1; i >= 0; i-- {
		v.History = append(v.History, StoredResult{Result: sorted[i], Stale: sorted[i].Fingerprint != fingerprint})
	}
	passed, failed, missing := 0, 0, 0
	for _, part := range it.Parts {
		pv := PartView{Part: part}
		for i := range v.History {
			h := v.History[i]
			if h.Part != part {
				continue
			}
			if pv.Latest == nil {
				c := h
				pv.Latest = &c
			}
			if !h.Stale && pv.Valid == nil {
				c := h
				pv.Valid = &c
			}
		}
		switch {
		case pv.Valid == nil:
			missing++
		case pv.Valid.Outcome == OutcomePass:
			passed++
		case pv.Valid.Outcome == OutcomeFail || pv.Valid.Outcome == OutcomeRestoreFailed:
			failed++
		default:
			// Inconclusive, cancelled, error: carried out, decided nothing.
			missing++
		}
		v.Parts = append(v.Parts, pv)
	}
	current := false
	for _, h := range v.History {
		current = current || !h.Stale
	}
	switch {
	case failed > 0:
		v.State = StateFailed
	case missing == 0 && passed > 0:
		v.State = StateVerified
	case passed > 0:
		v.State = StatePartial
	case len(v.History) == 0:
		v.State = StateNotRun
	case current:
		v.State = StateInconclusive
	default:
		v.State = StateStale
	}
	return v
}

// Fingerprint identifies the configuration a result was obtained under:
// the digest of the compiled bundle, the digest the installed manifest
// records and the installed version. A change of any of them makes older
// results stale. compiled is "" when the topology does not compile.
func Fingerprint(compiled, installed string, installedVersion int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("meridian-acceptance-1\n%s\n%s\n%d\n", compiled, installed, installedVersion)))
	return hex.EncodeToString(sum[:])
}

// ------------------------------------------------------------ redaction ---

var (
	reIPv4   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?::[0-9]{1,5})?\b`)
	reIPv6   = regexp.MustCompile(`(?i)(?:\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}|::[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){0,6})(?:/[0-9]{1,3})?`)
	reMAC    = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	reURL    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s，。；、）)]+`)
	reEmail  = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)
	reDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,40})\b`)
	reKeyish = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
	reSecret = regexp.MustCompile(`(?i)(\b(?:pass(?:word|wd)?|token|secret|key|psk|bearer)\b|密码|口令|令牌|密钥)\s*(?:[:=：]|是|为)?\s*[^\s，。；、]+`)
)

// fileNames are endings that look like a top-level domain but name a file
// or a unit the notes legitimately mention.
var fileNames = map[string]bool{
	"sh": true, "go": true, "md": true, "log": true, "txt": true, "json": true, "pcap": true, "pcapng": true, "png": true, "jpg": true,
	"service": true, "timer": true, "conf": true, "nft": true, "yaml": true, "yml": true, "zip": true, "gz": true, "tar": true,
}

// RedactNote makes an operator's note safe to store and show: addresses,
// MAC addresses, URLs, e-mail addresses, host names, anything that follows
// a word for a credential and any long token are replaced by a marker. It
// errs on the side of removing: a note is for "who checked what, where the
// evidence is archived", not for the evidence itself.
func RedactNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	s = reSecret.ReplaceAllString(s, "$1 [已隐去]")
	s = reURL.ReplaceAllString(s, "[链接已隐去]")
	s = reEmail.ReplaceAllString(s, "[邮箱已隐去]")
	s = reMAC.ReplaceAllString(s, "[MAC 已隐去]")
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Count(m, ":") < 2 {
			return m
		}
		// "12:30:05" is a time of day, not an address.
		if !strings.Contains(m, "::") && strings.Count(m, ":") == 2 && !strings.ContainsAny(strings.ToLower(m), "abcdef") {
			return m
		}
		return "[地址已隐去]"
	})
	s = reIPv4.ReplaceAllString(s, "[地址已隐去]")
	s = reDomain.ReplaceAllStringFunc(s, func(m string) string {
		if i := strings.LastIndexByte(m, '.'); i >= 0 && fileNames[strings.ToLower(m[i+1:])] {
			return m
		}
		return "[域名已隐去]"
	})
	s = reKeyish.ReplaceAllString(s, "[已隐去]")
	return clipRunes(s, MaxNote)
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

func clipLines(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, l := range in {
		if len(out) == MaxDetails {
			out = append(out, fmt.Sprintf("……另有 %d 行", len(in)-MaxDetails))
			break
		}
		out = append(out, clipRunes(strings.TrimSpace(l), 300))
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// -------------------------------------------------------- confirmations ---

// Confirmation is the second confirmation of a drill. It is bound to one
// item, one action, one target and one configuration fingerprint, and it
// expires.
type Confirmation struct {
	Token       string    `json:"token"`
	ItemID      string    `json:"item_id"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Errors of Redeem. Each one means: confirm again.
var (
	ErrConfirmMissing = errors.New("这个演练需要二次确认")
	ErrConfirmExpired = errors.New("确认已过期，请重新确认")
	ErrConfirmChanged = errors.New("确认之后动作、目标或配置变了，请重新确认")
)

// Confirmations issues and redeems drill confirmations. In memory only: a
// panel restart drops them, which only means confirming again.
type Confirmations struct {
	mu    sync.Mutex
	items map[string]Confirmation
}

// Issue returns a confirmation for exactly this action, target and
// fingerprint, valid for ConfirmTTLSeconds from now.
func (c *Confirmations) Issue(itemID, action, target, fingerprint string, now time.Time) Confirmation {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[string]Confirmation{}
	}
	for k, v := range c.items {
		if now.After(v.ExpiresAt) {
			delete(c.items, k)
		}
	}
	cf := Confirmation{Token: randHex(16), ItemID: itemID, Action: action, Target: target, Fingerprint: fingerprint, ExpiresAt: now.Add(ConfirmTTLSeconds * time.Second).UTC()}
	c.items[cf.Token] = cf
	return cf
}

// Redeem consumes token when it was issued for exactly this item, action,
// target and fingerprint and has not expired. A token is used at most once,
// whatever the answer.
func (c *Confirmations) Redeem(token, itemID, action, target, fingerprint string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var found *Confirmation
	for k, v := range c.items {
		if len(k) == len(token) && subtle.ConstantTimeCompare([]byte(k), []byte(token)) == 1 {
			v := v
			found = &v
			delete(c.items, k)
		}
	}
	switch {
	case token == "" || found == nil:
		return ErrConfirmMissing
	case now.After(found.ExpiresAt):
		return ErrConfirmExpired
	case found.ItemID != itemID || found.Action != action || found.Target != target || found.Fingerprint != fingerprint:
		return ErrConfirmChanged
	}
	return nil
}
