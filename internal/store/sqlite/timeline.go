package sqlite

import (
	"context"
	"time"

	"camwatch/internal/mtp"
)

// MergeSegments upserts each fetched TimeItem, deduplicated by (did,
// start_unix) — a segment already known keeps its first_seen but gets a
// fresh last_seen, and its duration is updated in case a later fetch
// resolved it more precisely. This is what lets coverage accumulate across
// many fetches instead of being discarded when each connection closes (see
// rdt.go's per-fetch ceiling investigation — native itself never gets the
// full index in one shot either, it just never throws away what it already
// has).
func (s *Store) MergeSegments(ctx context.Context, did string, segs []mtp.TimelineSeg) error {
	if len(segs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO timeline_segments(did, start_unix, duration_sec, first_seen, last_seen)
VALUES(?,?,?,?,?)
ON CONFLICT(did, start_unix) DO UPDATE SET
  duration_sec = excluded.duration_sec,
  last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, seg := range segs {
		if _, err := stmt.ExecContext(ctx, did, seg.StartUnix, seg.DurationSec, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Segments returns every TimeItem ever merged for did, oldest first.
func (s *Store) Segments(ctx context.Context, did string) ([]mtp.TimelineSeg, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT start_unix, duration_sec FROM timeline_segments WHERE did = ? ORDER BY start_unix ASC`, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var segs []mtp.TimelineSeg
	for rows.Next() {
		var seg mtp.TimelineSeg
		if err := rows.Scan(&seg.StartUnix, &seg.DurationSec); err != nil {
			return nil, err
		}
		segs = append(segs, seg)
	}
	return segs, rows.Err()
}
