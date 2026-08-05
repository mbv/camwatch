package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/ports"
)

const (
	pickKindEvent    = "event"
	pickKindTimeline = "timeline"
)

func (s *Store) PutEvent(ctx context.Context, ev domain.Event, ttl time.Duration) (string, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	return s.put(ctx, pickKindEvent, b, ttl)
}

func (s *Store) GetEvent(ctx context.Context, id string) (domain.Event, error) {
	raw, err := s.get(ctx, id, pickKindEvent)
	if err != nil {
		return domain.Event{}, err
	}
	var ev domain.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return domain.Event{}, err
	}
	return ev, nil
}

func (s *Store) PutTimeline(ctx context.Context, sess ports.TimelineSession, ttl time.Duration) (string, error) {
	b, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	return s.put(ctx, pickKindTimeline, b, ttl)
}

func (s *Store) GetTimeline(ctx context.Context, id string) (ports.TimelineSession, error) {
	raw, err := s.get(ctx, id, pickKindTimeline)
	if err != nil {
		return ports.TimelineSession{}, err
	}
	var sess ports.TimelineSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return ports.TimelineSession{}, err
	}
	return sess, nil
}

func (s *Store) put(ctx context.Context, kind string, payload []byte, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	_ = s.expireOld(ctx)
	id, err := shortID(12)
	if err != nil {
		return "", err
	}
	exp := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO tg_pick(id, kind, payload_json, expires_at) VALUES(?,?,?,?)`,
		id, kind, string(payload), exp)
	return id, err
}

func (s *Store) get(ctx context.Context, id, kind string) ([]byte, error) {
	_ = s.expireOld(ctx)
	var payload, exp, gotKind string
	err := s.db.QueryRowContext(ctx, `
SELECT kind, payload_json, expires_at FROM tg_pick WHERE id = ?`, id).Scan(&gotKind, &payload, &exp)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("pick %s not found or expired", id)
	}
	if err != nil {
		return nil, err
	}
	if gotKind != kind {
		return nil, fmt.Errorf("pick %s wrong kind", id)
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil || time.Now().UTC().After(t) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM tg_pick WHERE id = ?`, id)
		return nil, fmt.Errorf("pick %s expired", id)
	}
	return []byte(payload), nil
}

func (s *Store) expireOld(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `DELETE FROM tg_pick WHERE expires_at < ?`, now)
	return err
}

func shortID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:12], nil
}

var _ ports.PickStore = (*Store)(nil)
