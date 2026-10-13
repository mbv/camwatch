package miss

import (
	"testing"

	"camwatch/internal/mtp"
)

func TestExtendPlanToRecordingEnd(t *testing.T) {
	// Event at 1000 inside [960,1020); recording continues 1020..1080..1140,
	// then a real gap, then an unrelated item at 2000.
	segs := []mtp.TimelineSeg{
		{StartUnix: 960, DurationSec: 60},
		{StartUnix: 1020, DurationSec: 60},
		{StartUnix: 1080, DurationSec: 60},
		{StartUnix: 2000, DurationSec: 60},
	}
	plans, err := SelectTimeItemCandidates(segs, 1000, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	p := plans[0]

	got := ExtendPlanToRecordingEnd(segs, p, 180, 0)
	if got.FinalDurSec != 140 { // 1140 - 1000
		t.Fatalf("FinalDurSec=%d want 140", got.FinalDurSec)
	}
	if got.CaptureSec != got.TrimStartSec+140+SyncSlackSec {
		t.Fatalf("CaptureSec=%d", got.CaptureSec)
	}

	// Cap wins over a longer recording.
	if c := ExtendPlanToRecordingEnd(segs, p, 60, 0); c.FinalDurSec != 60 {
		t.Fatalf("capped FinalDurSec=%d want 60", c.FinalDurSec)
	}
	// Cap below the configured floor never shortens the clip.
	if c := ExtendPlanToRecordingEnd(segs, p, 10, 0); c.FinalDurSec != 20 {
		t.Fatalf("floor FinalDurSec=%d want 20", c.FinalDurSec)
	}
	// Disabled when max <= 0.
	if c := ExtendPlanToRecordingEnd(segs, p, 0, 0); c != p {
		t.Fatal("max=0 must not change the plan")
	}
	// Lead is added on top: clip = lead + (recording end - event).
	if c := ExtendPlanToRecordingEnd(segs, p, 180, 10); c.FinalDurSec != 150 {
		t.Fatalf("lead FinalDurSec=%d want 150", c.FinalDurSec)
	}
	// Short recording (nothing follows): keeps the default length.
	lone := []mtp.TimelineSeg{{StartUnix: 960, DurationSec: 60}}
	pl, _ := SelectTimeItemCandidates(lone, 1000, 8, 20)
	if c := ExtendPlanToRecordingEnd(lone, pl[0], 180, 0); c.FinalDurSec != 20 {
		t.Fatalf("lone FinalDurSec=%d want 20", c.FinalDurSec)
	}
}

// Live 2026-10-13: entries 60s apart all claimed dur=316 while the camera's
// real files are ~60s. The earliest covering entry (start 656, offset 205 for
// an event at 869) made the camera play from 656 — 213s before the event. The
// entry starting closest before the event must be tried first.
func TestCandidatesPreferNearestStartWhenIndexDurationsLie(t *testing.T) {
	segs := []mtp.TimelineSeg{
		{StartUnix: 1791888656, DurationSec: 316},
		{StartUnix: 1791888716, DurationSec: 316},
		{StartUnix: 1791888776, DurationSec: 316},
		{StartUnix: 1791888836, DurationSec: 316},
	}
	const event = 1791888869
	plans, err := SelectTimeItemCandidates(segs, event, 8, 20)
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].SessionID != 1791888836 {
		t.Fatalf("first candidate sessionid=%d want 1791888836", plans[0].SessionID)
	}
	if want := int(event-1791888836) - plans[0].TrimStartSec; plans[0].OffsetSec != want {
		t.Fatalf("offset=%d want %d", plans[0].OffsetSec, want)
	}
	if seg, _, ok := mtp.LookupTimeline(segs, event); !ok || seg.StartUnix != 1791888836 {
		t.Fatalf("LookupTimeline picked %+v", seg)
	}
}
