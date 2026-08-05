package orchestrator

import (
	"fmt"
	"testing"
)

func TestKeepWarmAfterCapture(t *testing.T) {
	cases := []struct {
		err  error
		keep bool
	}{
		{nil, true},
		{errString("miss: segment_not_found: no TimeItem covering event=1"), true},
		{errString("miss: playback_rejected: status=\"filenotfound\""), true},
		{errString("miss: timeline_unavailable: mtp: rdt type6: deadline"), false},
		{errString("miss: stream_no_keyframe: timeout"), false},
		{errString("miss: no 0x10e within 12s"), false},
		// Reproduces the actual live bug (2026-08-03): session.go used to wrap
		// every nativePlaybackSeek failure as "playback_rejected", so a silent
		// timeout's error text contained both substrings. The drop-warm cases
		// must win regardless of what a caller's wrapping happens to contain —
		// this must return false even though "playback_rejected" also matches.
		{errString("miss: playback_rejected: miss: no 0x10e within 5s"), false},
		{errString("miss: playback_rejected: miss: no 0x10e for id=1 within 5s (only saw stale id=2 status=\"filefound\")"), false},
		{errString("miss: media session not ready"), false},
		{errString("p2p open: LoginResponse timeout"), false},
		{errString("mtp: closed"), false},
		{errString("recorder: remux_failed: exit status 1"), true},
	}
	for _, tc := range cases {
		if got := keepWarmAfterCapture(tc.err); got != tc.keep {
			t.Fatalf("keepWarmAfterCapture(%v)=%v want %v", tc.err, got, tc.keep)
		}
	}
}

func TestClassifyClipErr(t *testing.T) {
	err := classifyClipErr(fmt.Errorf("miss: timeline_unavailable: rdt silence"))
	if got := err.Error(); got[:20] != "timeline_unavailable" {
		t.Fatalf("got %q", got)
	}
}

func TestMediaPathDead(t *testing.T) {
	if !mediaPathDead(errString("miss: timeline_unavailable: media chk not alive")) {
		t.Fatal("expected dead")
	}
	if mediaPathDead(errString("miss: timeline_unavailable: mtp: rdt type6: deadline")) {
		t.Fatal("RDT silence on live session must not force redial")
	}
	if mediaPathDead(errString("miss: segment_not_found")) {
		t.Fatal("segment miss is not media-path dead")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
