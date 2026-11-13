// Package store persists the topology in SQLite. Private keys stay in the
// database on the gateway and are stripped from API responses. SSH and
// Cloudflare secrets are never stored here (see internal/credentials):
// topology nodes only refer to managed servers by ID.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/radowitz/meridian/internal/ruleset"
	"sort"
	"sync"

	"github.com/radowitz/meridian/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	// mu serialises read-modify-write of the topology (Save, Update).
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS kv (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Get(key string) (string, bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return raw, true, nil
}

func (s *Store) Put(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO kv(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) Load() (model.Topology, bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = 'topology'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Topology{}, false, nil
	}
	if err != nil {
		return model.Topology{}, false, err
	}
	var t model.Topology
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return model.Topology{}, false, err
	}
	// Legacy pool fields are read as region groups. The rewrite is pure and
	// deterministic; MigrateRegionGroups below persists it.
	model.MigrateRegionGroups(&t)
	// A row from before the allocation table gets the numbering it was
	// compiled with (positions, after the group migration above, exactly
	// as the compiler read it); MigrateAllocations below persists it.
	model.MigrateAllocations(&t)
	// The rule list becomes explicit in the order the compiler already
	// used (model.MigrateRuleOrder); saving persists it.
	model.MigrateRuleOrder(&t)
	return t, true, nil
}

// MigrateAllocations persists the allocation table of a stored topology
// from before it existed (docs/architecture.md「接口名、端口和网段的分配」):
// every link, exit and group keeps the interface, ports, subnets and mark
// its position gave it, so nothing changes on any host. Load already
// applies it in memory; this writes only when the stored row has no table.
// Running it again is a no-op. Reports whether it wrote.
func (s *Store) MigrateAllocations() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok, err := s.Get("topology")
	if err != nil || !ok {
		return false, err
	}
	var probe struct {
		Allocations json.RawMessage `json:"allocations"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return false, err
	}
	if len(probe.Allocations) > 0 && string(probe.Allocations) != "null" {
		return false, nil
	}
	t, _, err := s.Load()
	if err != nil {
		return false, err
	}
	return true, s.save(t, false)
}

// MigrateRegionGroups persists the region-group migration of the stored
// topology (docs/architecture.md「迁移」). Load already applies it in
// memory, so this only writes when the stored row still has legacy fields.
// One row is written in one statement: an interruption leaves either the
// old row (migrated again on the next read) or the new one. Running it
// again is a no-op.
func (s *Store) MigrateRegionGroups() (model.MigrationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = 'topology'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MigrationReport{}, nil
	}
	if err != nil {
		return model.MigrationReport{}, err
	}
	var t model.Topology
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return model.MigrationReport{}, err
	}
	rep := model.MigrateRegionGroups(&t)
	if !rep.Changed {
		return rep, nil
	}
	return rep, s.save(t, false)
}

// Save keeps stored private keys when the incoming document redacts them,
// and keeps the stored allocation table authoritative: every link, exit
// and group the stored table knows keeps its slot whatever the document
// says, the slots of deleted ones are retired, new ones get a free slot
// (model.ReconcileAllocations).
func (s *Store) Save(next model.Topology) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(next, false)
}

// SaveImport saves a whole document that replaces the stored one (an
// export brought back, PUT /api/topology?import=1): the document's own
// allocation table is taken as far as it is valid (in range, no slot
// twice), a document without one is numbered by position as at migration,
// and every slot the stored topology used is retired, so objects the
// document has no slot for never take one of them.
func (s *Store) SaveImport(next model.Topology) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(next, true)
}

// ImportBase is the base SaveImport reconciles against: no entry, every
// slot of cur (stored entries and retired ones) retired.
func ImportBase(cur *model.Allocations) *model.Allocations {
	base := &model.Allocations{}
	if cur == nil {
		return base
	}
	add := func(xs []int, v int) []int {
		for _, x := range xs {
			if x == v {
				return xs
			}
		}
		return append(xs, v)
	}
	base.RetiredLinks = append(base.RetiredLinks, cur.RetiredLinks...)
	base.RetiredMarks = append(base.RetiredMarks, cur.RetiredMarks...)
	for _, id := range sortedKeys(cur.Links) {
		base.RetiredLinks = add(base.RetiredLinks, cur.Links[id].Slot)
	}
	for _, id := range sortedKeys(cur.Exits) {
		base.RetiredMarks = add(base.RetiredMarks, cur.Exits[id].Slot)
	}
	for _, id := range sortedKeys(cur.Groups) {
		base.RetiredMarks = add(base.RetiredMarks, cur.Groups[id].Slot)
	}
	return base
}

func sortedKeys(m map[string]model.Slot) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ReconcileImport applies SaveImport's allocation rule to next in memory
// (cur: the stored table), for validating before the save.
func ReconcileImport(cur *model.Allocations, next *model.Topology) {
	if next.Allocations == nil {
		model.MigrateAllocations(next)
	}
	model.ReconcileAllocations(ImportBase(cur), next)
}

// Update loads the stored topology, lets fn change it, and saves it when fn
// reports a change, all under the store's lock, so a concurrent Save cannot
// slip in between. found is false when nothing is stored yet (fn is then
// not called).
func (s *Store) Update(fn func(t *model.Topology) (bool, error)) (found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok, err := s.Load()
	if err != nil || !ok {
		return ok, err
	}
	changed, err := fn(&t)
	if err != nil || !changed {
		return true, err
	}
	return true, s.save(t, false)
}

func (s *Store) save(next model.Topology, imported bool) error {
	prev, ok, err := s.Load()
	if err != nil {
		return err
	}
	if ok {
		kept := map[string]string{}
		for _, n := range prev.Nodes {
			if n.PrivateKey != "" {
				kept[n.ID] = n.PrivateKey
			}
		}
		for i := range next.Nodes {
			pk := next.Nodes[i].PrivateKey
			if pk == "" || pk == "***" {
				if old, ok := kept[next.Nodes[i].ID]; ok {
					next.Nodes[i].PrivateKey = old
				} else {
					next.Nodes[i].PrivateKey = ""
				}
			}
		}
	}
	// A stored topology never carries the legacy pool fields.
	model.MigrateRegionGroups(&next)
	// A document from an older client is put into the order it meant.
	model.MigrateRuleOrder(&next)
	// After the group migration: groups it creates get slots too.
	switch {
	case imported && ok:
		ReconcileImport(prev.Allocations, &next)
	case imported:
		ReconcileImport(nil, &next)
	case ok:
		// prev went through Load, so it has a table (migrated in memory
		// when the row had none).
		model.ReconcileAllocations(prev.Allocations, &next)
	default:
		model.ReconcileAllocations(nil, &next)
	}
	buf, err := json.Marshal(next)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO kv(key, value) VALUES('topology', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(buf))
	return err
}

func Redact(t model.Topology) model.Topology {
	for i := range t.Nodes {
		if t.Nodes[i].PrivateKey != "" {
			t.Nodes[i].PrivateKey = "***"
		}
	}
	// A rule-set URL never carries a credential once the panel has
	// migrated it into the credential store (api migrateRuleSetSecrets);
	// one that still does (a draft or an import awaiting the migration) is
	// shown without it.
	if len(t.RuleSets) > 0 {
		rs := append([]model.RuleSet(nil), t.RuleSets...)
		for i := range rs {
			if ruleset.HasSecret(rs[i].URL) {
				rs[i].URL = ruleset.Redact(rs[i].URL)
			}
		}
		t.RuleSets = rs
	}
	return t
}
