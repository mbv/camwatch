package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"camwatch/internal/mtp"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMergeSegmentsDeduplicatesByStartUnix(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first := []mtp.TimelineSeg{
		{StartUnix: 1700000000, DurationSec: 60},
		{StartUnix: 1700000060, DurationSec: 60},
	}
	if err := s.MergeSegments(ctx, "dev1", first); err != nil {
		t.Fatalf("MergeSegments: %v", err)
	}

	// Second fetch overlaps one segment (same start, refined duration) and
	// adds one new one — mirrors two separate live fetches of the same camera.
	second := []mtp.TimelineSeg{
		{StartUnix: 1700000060, DurationSec: 61}, // refined duration for an existing record
		{StartUnix: 1700000120, DurationSec: 60}, // new
	}
	if err := s.MergeSegments(ctx, "dev1", second); err != nil {
		t.Fatalf("MergeSegments (second): %v", err)
	}

	got, err := s.Segments(ctx, "dev1")
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 deduplicated segments, got %d: %+v", len(got), got)
	}
	want := map[int64]int{1700000000: 60, 1700000060: 61, 1700000120: 60}
	for _, seg := range got {
		if d, ok := want[seg.StartUnix]; !ok || d != seg.DurationSec {
			t.Fatalf("unexpected segment %+v, want map %+v", seg, want)
		}
	}
}

func TestSegmentsScopedByDID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.MergeSegments(ctx, "devA", []mtp.TimelineSeg{{StartUnix: 100, DurationSec: 60}}); err != nil {
		t.Fatalf("MergeSegments devA: %v", err)
	}
	if err := s.MergeSegments(ctx, "devB", []mtp.TimelineSeg{{StartUnix: 200, DurationSec: 60}}); err != nil {
		t.Fatalf("MergeSegments devB: %v", err)
	}

	gotA, err := s.Segments(ctx, "devA")
	if err != nil {
		t.Fatalf("Segments devA: %v", err)
	}
	if len(gotA) != 1 || gotA[0].StartUnix != 100 {
		t.Fatalf("devA leaked cross-device segments: %+v", gotA)
	}

	gotB, err := s.Segments(ctx, "devB")
	if err != nil {
		t.Fatalf("Segments devB: %v", err)
	}
	if len(gotB) != 1 || gotB[0].StartUnix != 200 {
		t.Fatalf("devB leaked cross-device segments: %+v", gotB)
	}
}

func TestMergeSegmentsEmptyIsNoop(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.MergeSegments(ctx, "dev1", nil); err != nil {
		t.Fatalf("MergeSegments(nil): %v", err)
	}
	got, err := s.Segments(ctx, "dev1")
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no segments, got %+v", got)
	}
}
