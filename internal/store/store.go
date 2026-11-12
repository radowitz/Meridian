// Package store persists the topology in SQLite. Private keys stay in the
// database on the gateway and are stripped from API responses.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/radowitz/meridian/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
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
	return t, true, nil
}

// Save keeps stored private keys when the incoming document redacts them.
func (s *Store) Save(next model.Topology) error {
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
