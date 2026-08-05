package miss

import (
	"testing"

	"camwatch/internal/mtp"
)

func TestParsePlaybackRes(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		status string
		id     int64
		dur    int
		ok     bool
	}{
		{
			name:   "clean",
			raw:    `{"id":1700002000, "status":"filefound", "starttime":1700002000, "duration":60, "vchn":0}`,
			status: "filefound",
			id:     1700002000,
			dur:    60,
			ok:     true,
		},
		{
			name:   "trailing double-brace junk",
			raw:    `{"id":1700003000, "status":"filefound", "starttime":1700003000, "duration":60, "vchn":0}}N`,
			status: "filefound",
			id:     1700003000,
			dur:    60,
			ok:     true,
		},
		{
			name:   "nul padding",
			raw:    "{\"id\":1, \"status\":\"filenotfound\", \"vchn\":0}\x00\x00",
			status: "filenotfound",
			id:      1,
			ok:     true,
		},
		{
			name:   "prefix junk then object",
			raw:    "xx{\"id\":2, \"status\":\"filefound\", \"duration\":30}",
			status: "filefound",
			id:     2,
			dur:    30,
			ok:     true,
		},
		{
			name: "empty",
			raw:  "",
			ok:   false,
		},
		{
			name: "no status",
			raw:  `{"id":3}`,
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := parsePlaybackRes([]byte(tc.raw))
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v resp=%+v", ok, tc.ok, resp)
			}
			if !tc.ok {
				return
			}
			if resp.Status != tc.status || resp.ID != tc.id || resp.Duration != tc.dur {
				t.Fatalf("%+v", resp)
			}
		})
	}
}

func TestExtractJSONObjectBalanced(t *testing.T) {
	raw := []byte(`{"a":"}nested{"} , "b":1}}N`)
	got := extractJSONObject(raw)
	want := `{"a":"}nested{"}`
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSelectTimeItemWithPreRoll60s(t *testing.T) {
	const event int64 = 1700004000
	segs := []mtp.TimelineSeg{
		{StartUnix: event - 31, DurationSec: 316},
		{StartUnix: event - 28, DurationSec: 60},
	}
	plan, err := SelectTimeItemWithPreRoll(segs, event, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SessionID != event-28 {
		t.Fatalf("want 60s TimeItem, got %+v", plan)
	}
	// event offset into item = 28; pre-roll 8 → offset 20, trim 8
	if plan.OffsetSec != 20 || plan.TrimStartSec != 8 {
		t.Fatalf("pre-roll plan %+v", plan)
	}
	if plan.CaptureSec < 20+8 {
		t.Fatalf("capture too short %+v", plan)
	}
}

func TestSelectTimeItemWithPreRollNearStart(t *testing.T) {
	const start int64 = 1000000
	const event int64 = start + 3
	segs := []mtp.TimelineSeg{{StartUnix: start, DurationSec: 60}}
	plan, err := SelectTimeItemWithPreRoll(segs, event, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if plan.OffsetSec != 0 || plan.TrimStartSec != 3 {
		t.Fatalf("near-start plan %+v", plan)
	}
}

func TestSelectTimeItemNoGuesses(t *testing.T) {
	_, err := SelectTimeItemWithPreRoll(nil, 1700004000, 8, 20)
	if err == nil {
		t.Fatal("expected segment_not_found")
	}
}

func TestSelectTimeItemLongSpanOnly(t *testing.T) {
	const event int64 = 1700004000
	long := mtp.TimelineSeg{StartUnix: event - 31, DurationSec: 316}
	plan, err := SelectTimeItemWithPreRoll([]mtp.TimelineSeg{long}, event, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SessionID != long.StartUnix || plan.OffsetSec != 23 {
		t.Fatalf("long span plan %+v", plan)
	}
}

// TestSelectTimeItemCandidatesOverlappingPrefersButKeepsBoth reproduces two
// real, live-observed events (2026-08-03): a dur=316 span and a dur=60 entry
// starting exactly where its first minute would end, both covering the same
// eventUnix. SelectTimeItemWithPreRoll's own single-best pick (the 60s entry)
// went silent — no 0x10e — for both events, consistently, across many
// fresh-dialed retries over more than an hour. SelectTimeItemCandidates must
// keep the long-span entry as a second candidate instead of discarding it,
// so DownloadPlayback can fall back to it when the preferred pick times out.
func TestSelectTimeItemCandidatesOverlappingPrefersButKeepsBoth(t *testing.T) {
	const event int64 = 1700005000
	long := mtp.TimelineSeg{StartUnix: 1700004939, DurationSec: 316}
	short := mtp.TimelineSeg{StartUnix: 1700004999, DurationSec: 60}
	plans, err := SelectTimeItemCandidates([]mtp.TimelineSeg{long, short}, event, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("expected both covering TimeItems kept as candidates, got %d: %+v", len(plans), plans)
	}
	if plans[0].SessionID != short.StartUnix {
		t.Fatalf("expected the ~60s entry first (closest to 60s), got %+v", plans[0])
	}
	if plans[1].SessionID != long.StartUnix {
		t.Fatalf("expected the long span kept as fallback candidate, got %+v", plans[1])
	}
}

func TestSelectTimeItemCandidatesSingleCovering(t *testing.T) {
	const event int64 = 1700004000
	only := mtp.TimelineSeg{StartUnix: event - 5, DurationSec: 60}
	plans, err := SelectTimeItemCandidates([]mtp.TimelineSeg{only}, event, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].SessionID != only.StartUnix {
		t.Fatalf("expected exactly one candidate, got %+v", plans)
	}
}

func TestSelectTimeItemCandidatesNoCoveringNoGuesses(t *testing.T) {
	_, err := SelectTimeItemCandidates(nil, 1700004000, 8, 20)
	if err == nil {
		t.Fatal("expected segment_not_found")
	}
}

// TestSelectTimeItemCandidatesAppendsReachBackFallback reproduces the exact
// live scenario that motivated appendReachBackFallback (2026-08-04): a
// default (unpadded, DefaultPreRollSec=8) request whose only covering
// TimeItem is a long dur=316 span. Two real events sat in this exact shape
// for over 24 hours, the camera never once answering 0x10d for the long
// span's own sessionid — but the *same* event, requested with enough padding
// for PlanPaddedSeek to reach the segment immediately before it, got an
// immediate 0x10e and the camera's own auto-advance then carried the stream
// through the "stuck" segment as part of one continuous playback. The
// default/unpadded path must get this same fallback candidate, not just
// user-chosen padding — SelectTimeItemCandidates is used for both.
func TestSelectTimeItemCandidatesAppendsReachBackFallback(t *testing.T) {
	const event int64 = 1700006000
	long := mtp.TimelineSeg{StartUnix: 1700005987, DurationSec: 316} // the "stuck" span
	prev := mtp.TimelineSeg{StartUnix: 1700005927, DurationSec: 60}  // ends exactly at 1700005987
	plans, err := SelectTimeItemCandidates([]mtp.TimelineSeg{long, prev}, event, DefaultPreRollSec, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("expected the long span plus a reach-back fallback, got %d: %+v", len(plans), plans)
	}
	if plans[0].SessionID != long.StartUnix {
		t.Fatalf("expected the only covering TimeItem tried first, unchanged, got %+v", plans[0])
	}
	if plans[1].SessionID != prev.StartUnix {
		t.Fatalf("expected the preceding segment appended as a fallback, got %+v", plans[1])
	}
}

func TestPlanPaddedSeekFitsInCurrentSegment(t *testing.T) {
	const event int64 = 1700000030 // 30s into its segment
	segs := []mtp.TimelineSeg{{StartUnix: 1700000000, DurationSec: 60}}
	plans, err := PlanPaddedSeek(segs, event, 15, 15)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected a single plan (no reach-back needed), got %d: %+v", len(plans), plans)
	}
	p := plans[0]
	if p.SessionID != 1700000000 || p.OffsetSec != 15 || p.TrimStartSec != 15 || p.FinalDurSec != 30 {
		t.Fatalf("unexpected plan %+v", p)
	}
}

// TestPlanPaddedSeekCrossesContiguousPreviousSegment reproduces the case that
// motivated PlanPaddedSeek: the event sits only 5s into its own segment, and
// ±30s padding needs 25s from the contiguous previous segment. The returned
// plan must be a single seek rooted at the PREVIOUS segment's start (not two
// slices) — see PlanPaddedSeek's doc comment for why a single continuous
// seek is expected to work here.
func TestPlanPaddedSeekCrossesContiguousPreviousSegment(t *testing.T) {
	const event int64 = 1700000065 // 5s into the segment starting at 1700000060
	segs := []mtp.TimelineSeg{
		{StartUnix: 1700000000, DurationSec: 60}, // ends 1700000060, contiguous
		{StartUnix: 1700000060, DurationSec: 60},
	}
	plans, err := PlanPaddedSeek(segs, event, 30, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("expected 2 degrading candidates (reach-back root, then current-only), got %d: %+v", len(plans), plans)
	}
	best := plans[0]
	if best.SessionID != 1700000000 {
		t.Fatalf("expected the best candidate rooted at the previous segment, got %+v", best)
	}
	if best.OffsetSec != 35 || best.TrimStartSec != 30 || best.FinalDurSec != 60 {
		// offset = (eventUnix - root.StartUnix) - applied = 65 - 30 = 35; trim = 30 (full padding achieved).
		t.Fatalf("unexpected reach-back plan %+v", best)
	}
	fallback := plans[1]
	if fallback.SessionID != 1700000060 {
		t.Fatalf("expected the fallback candidate rooted at the current segment, got %+v", fallback)
	}
	if fallback.TrimStartSec != 5 {
		t.Fatalf("expected fallback pre-roll clamped to the 5s available in its own segment, got %+v", fallback)
	}
}

// TestPlanPaddedSeekClampsAcrossRealGap ensures a genuine event-triggered
// recording gap is never silently spliced into the padding window.
func TestPlanPaddedSeekClampsAcrossRealGap(t *testing.T) {
	const event int64 = 1700000605 // 5s into a segment with a real gap before it
	segs := []mtp.TimelineSeg{
		{StartUnix: 1700000000, DurationSec: 60}, // ends 1700000060 — far from 1700000600
		{StartUnix: 1700000600, DurationSec: 60},
	}
	plans, err := PlanPaddedSeek(segs, event, 30, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected no reach-back across the gap, got %d plans: %+v", len(plans), plans)
	}
	if plans[0].SessionID != 1700000600 || plans[0].TrimStartSec != 5 {
		t.Fatalf("expected clamped single plan, got %+v", plans[0])
	}
}

func TestPlanPaddedSeekWalksBackMultipleHops(t *testing.T) {
	const event int64 = 1700000185 // 5s into the segment starting at 1700000180
	segs := []mtp.TimelineSeg{
		{StartUnix: 1700000000, DurationSec: 60}, // ends 60 — one hop further than padding needs
		{StartUnix: 1700000060, DurationSec: 60}, // ends 120
		{StartUnix: 1700000120, DurationSec: 60}, // ends 180
		{StartUnix: 1700000180, DurationSec: 60}, // current, event 5s in
	}
	plans, err := PlanPaddedSeek(segs, event, 90, 20) // needs 2 hops back
	if err != nil {
		t.Fatal(err)
	}
	// 3 padding-driven candidates (2 hops back + current) plus one more:
	// appendReachBackFallback always tries one segment further back than the
	// best candidate as a safety net against the best candidate itself being
	// an unplayable long span (see its doc comment) — here that reaches the
	// 4th, genuinely contiguous segment the padding walk didn't need.
	if len(plans) != 4 {
		t.Fatalf("expected 3 padding candidates + 1 reach-back fallback, got %d: %+v", len(plans), plans)
	}
	if plans[0].SessionID != 1700000060 {
		t.Fatalf("expected the furthest-back reachable root first, got %+v", plans[0])
	}
	if plans[len(plans)-1].SessionID != 1700000000 {
		t.Fatalf("expected the extra reach-back fallback last, got %+v", plans[len(plans)-1])
	}
	if plans[len(plans)-2].SessionID != 1700000180 {
		t.Fatalf("expected the plain current-segment plan just before the fallback, got %+v", plans[len(plans)-2])
	}
}
