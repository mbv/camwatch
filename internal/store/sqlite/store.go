package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"camwatch/internal/domain"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS seen_events (
  key TEXT PRIMARY KEY,
  file_id TEXT,
  did TEXT,
  event_type TEXT,
  create_time_ms INTEGER,
  meta_json TEXT,
  seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tg_pick (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timeline_segments (
  did TEXT NOT NULL,
  start_unix INTEGER NOT NULL,
  duration_sec INTEGER NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (did, start_unix)
);
`)
	return err
}


func (s *Store) Seen(ctx context.Context, key string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM seen_events WHERE key = ?`, key).Scan(&n)
	return n > 0, err
}

func (s *Store) Mark(ctx context.Context, key string, meta domain.Event) error {
	b, _ := json.Marshal(meta)
	_, err := s.db.ExecContext(ctx, `
INSERT OR REPLACE INTO seen_events(key, file_id, did, event_type, create_time_ms, meta_json, seen_at)
VALUES(?,?,?,?,?,?,?)`,
		key, meta.FileID, meta.DID, meta.EventType, meta.CreateTimeMs, string(b), time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func (s *Store) SetMeta(ctx context.Context, k, v string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)`, k, v)
	return err
}

func (s *Store) GetMeta(ctx context.Context, k string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = ?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) String() string { return fmt.Sprintf("sqlite(%p)", s.db) }
