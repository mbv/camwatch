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

	got := ExtendPlanToRecordingEnd(segs, p, 180)
	if got.FinalDurSec != 140 { // 1140 - 1000
		t.Fatalf("FinalDurSec=%d want 140", got.FinalDurSec)
	}
	if got.CaptureSec != got.TrimStartSec+140+SyncSlackSec {
		t.Fatalf("CaptureSec=%d", got.CaptureSec)
	}

	// Cap wins over a longer recording.
	if c := ExtendPlanToRecordingEnd(segs, p, 60); c.FinalDurSec != 60 {
		t.Fatalf("capped FinalDurSec=%d want 60", c.FinalDurSec)
	}
	// Cap below the configured floor never shortens the clip.
	if c := ExtendPlanToRecordingEnd(segs, p, 10); c.FinalDurSec != 20 {
		t.Fatalf("floor FinalDurSec=%d want 20", c.FinalDurSec)
	}
	// Disabled when max <= 0.
	if c := ExtendPlanToRecordingEnd(segs, p, 0); c != p {
		t.Fatal("max=0 must not change the plan")
	}
	// Short recording (nothing follows): keeps the default length.
	lone := []mtp.TimelineSeg{{StartUnix: 960, DurationSec: 60}}
	pl, _ := SelectTimeItemCandidates(lone, 1000, 8, 20)
	if c := ExtendPlanToRecordingEnd(lone, pl[0], 180); c.FinalDurSec != 20 {
		t.Fatalf("lone FinalDurSec=%d want 20", c.FinalDurSec)
	}
}
