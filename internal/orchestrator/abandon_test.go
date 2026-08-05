package orchestrator

import (
	"testing"

	"camwatch/internal/domain"
)

// TestShouldAbandonCaptureCoolsDownNotMark locks in the switch from a
// permanent store.Mark on repeated capture failure to an in-memory cooldown
// (o.rdtCooldown, shared with the RDT soft-failure gate). A protocol bug (the
// RDT index misparse this replaced was investigating) is not proof the event
// itself is undownloadable — a permanent Mark meant a fixed bug could never
// recover events it had already given up on, and cooldowns clear on restart
// so a deployed fix retries immediately.
func TestShouldAbandonCaptureCoolsDownNotMark(t *testing.T) {
	o := &Orchestrator{}
	ev := domain.Event{FileID: "12345"}
	err := errString("miss: playback_rejected: miss: no 0x10e within 5s")

	for i := 0; i < captureFailAbandon-1; i++ {
		if o.shouldAbandonCapture(ev, err) {
			t.Fatalf("abandoned too early on strike %d", i+1)
		}
		if o.inRDTCooldown(ev.Key()) {
			t.Fatalf("cooldown set before threshold reached (strike %d)", i+1)
		}
	}
	if !o.shouldAbandonCapture(ev, err) {
		t.Fatal("expected abandon on the final strike")
	}
	if !o.inRDTCooldown(ev.Key()) {
		t.Fatal("expected an in-memory cooldown to be set, not a permanent Mark")
	}
	if n := o.failCounts[ev.Key()]; n != 0 {
		t.Fatalf("failCounts should reset after abandon, got %d", n)
	}
}

// TestShouldAbandonCaptureIgnoresUnmatchedErrors ensures the dead
// "no SD segment" string (matched nowhere else in the codebase) was fixed to
// the real "segment_not_found" produced by native.go — otherwise segment
// misses never abandon/cool down and retry every poll indefinitely.
func TestShouldAbandonCaptureIgnoresUnmatchedErrors(t *testing.T) {
	o := &Orchestrator{}
	ev := domain.Event{FileID: "12345"}
	segErr := errString("miss: segment_not_found: no TimeItem covering event=1")
	for i := 0; i < captureFailAbandon+2; i++ {
		if !o.shouldAbandonCapture(ev, segErr) && i == captureFailAbandon-1 {
			t.Fatalf("segment_not_found must count toward abandon (strike %d)", i+1)
		}
	}
	if !o.inRDTCooldown(ev.Key()) {
		t.Fatal("expected segment_not_found to eventually cool down the event")
	}

	other := domain.Event{FileID: "67890"}
	unrelated := errString("some unrelated error")
	if o.shouldAbandonCapture(other, unrelated) {
		t.Fatal("unrelated errors must never trigger abandon")
	}
}
