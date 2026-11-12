// Package store persists the topology in SQLite. Private keys stay in the
// database on the gateway and are stripped from API responses. SSH and
// Cloudflare secrets are never stored here (see internal/credentials):
// topology nodes only refer to managed servers by ID.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
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
	return t, true, nil
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
	return rep, s.save(t)
}

// Save keeps stored private keys when the incoming document redacts them.
func (s *Store) Save(next model.Topology) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(next)
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
	return true, s.save(t)
}

func (s *Store) save(next model.Topology) error {
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
	return t
}
