package miss

import (
	"fmt"
	"sort"

	"camwatch/internal/mtp"
)

// Native Mi Home SD playback invariants (from x/frida-mtp-capture.log,
// x/new_command.log, x/go2rtc/MTP-PROTOCOL.md §9.4):
//
//  1. Full RDT type-6 index (~80KB, ~10k TimeItems), empty TX request size=0.
//  2. sessionid = TimeItem start unix (seconds), not minute-floored createTime.
//  3. Command order: 0x103 VideoStop → 0x10d PlaybackReq → 0x10f Speed →
//     wait 0x10e filefound → then video frames (H.265).
//  4. Open play uses endtime=0; 0x10e reports duration=60 for playable clips.
//  5. No shotgun minute guesses: only index TimeItem starts are seekable.
//
// Camwatch mirrors that path; pre-roll is a recorder-side addition so
// WaitAnnexBSync can discard mid-GOP bytes without losing the event moment.

const (
	// DefaultPreRollSec mirrors domain.DefaultPreRollSec for miss-local use.
	DefaultPreRollSec = 8
	// SyncSlackSec extra capture after pre-roll+duration for IDR wait / jitter.
	SyncSlackSec = 10
)

// SeekPlan is a deterministic native-style 0x10d target derived from the index.
type SeekPlan struct {
	SessionID    int64 // TimeItem start unix
	OffsetSec    int   // seconds into TimeItem for 0x10d
	ItemDurSec   int   // published TimeItem duration
	EventUnix    int64
	TrimStartSec int // seconds to trim after decode (= applied pre-roll)
	CaptureSec   int // how long to read the elementary stream
	FinalDurSec  int // clip duration after trim
}

// SelectTimeItemWithPreRoll picks one covering TimeItem from a validated index
// and computes a pre-roll seek offset. Prefers ~60s items (native 0x10e shape).
func SelectTimeItemWithPreRoll(segs []mtp.TimelineSeg, eventUnix int64, preRoll, finalDur int) (SeekPlan, error) {
	if eventUnix <= 0 {
		return SeekPlan{}, fmt.Errorf("miss: segment_not_found: bad eventUnix")
	}
	if preRoll < 0 {
		preRoll = 0
	}
	if finalDur <= 0 {
		finalDur = 20
	}

	seg, _, ok := mtp.LookupTimeline(segs, eventUnix)
	if !ok {
		// Index lag / partial fetch: allow a short skew past published end.
		seg, _, ok = mtp.LookupTimelineNear(segs, eventUnix, 180)
	}
	if !ok {
		var minS, maxS int64
		if len(segs) > 0 {
			minS, maxS = segs[0].StartUnix, segs[0].StartUnix
			for _, s := range segs {
				if s.StartUnix < minS {
					minS = s.StartUnix
				}
				end := s.StartUnix + int64(s.DurationSec)
				if end > maxS {
					maxS = end
				}
			}
		}
		return SeekPlan{}, fmt.Errorf("miss: segment_not_found: no TimeItem covering event=%d (index %d segs range=%d..%d)",
			eventUnix, len(segs), minS, maxS)
	}

	// Prefer a covering 45–90s item when LookupTimeline returned a long span
	// but a short one also covers (LookupTimeline already prefers ~60s).
	offFromStart := int(eventUnix - seg.StartUnix)
	if offFromStart < 0 {
		offFromStart = 0
	}
	applied := preRoll
	if applied > offFromStart {
		applied = offFromStart
	}
	offset := offFromStart - applied
	capture := applied + finalDur + SyncSlackSec
	if capture < finalDur+SyncSlackSec {
		capture = finalDur + SyncSlackSec
	}

	// offset can exceed seg.DurationSec when LookupTimelineNear matched via
	// its skew allowance (index lag: the segment is still being written and
	// the published duration is stale) — mtp.LookupTimelineNear bounds this to
	// at most DurationSec+skew(180s), so it's not unbounded, but it's worth a
	// visible signal since it means we're seeking past what the index claims
	// is the end of the clip.
	if offset > seg.DurationSec {
		mtp.Logp("miss: seek plan offset=%d exceeds itemDur=%d (index-lag near-match, sessionid=%d)\n",
			offset, seg.DurationSec, seg.StartUnix)
	}

	return planForSegment(seg, eventUnix, preRoll, finalDur), nil
}

func planForSegment(seg mtp.TimelineSeg, eventUnix int64, preRoll, finalDur int) SeekPlan {
	offFromStart := int(eventUnix - seg.StartUnix)
	if offFromStart < 0 {
		offFromStart = 0
	}
	applied := preRoll
	if applied > offFromStart {
		applied = offFromStart
	}
	offset := offFromStart - applied
	capture := applied + finalDur + SyncSlackSec
	if capture < finalDur+SyncSlackSec {
		capture = finalDur + SyncSlackSec
	}
	if offset > seg.DurationSec {
		mtp.Logp("miss: seek plan offset=%d exceeds itemDur=%d (index-lag near-match, sessionid=%d)\n",
			offset, seg.DurationSec, seg.StartUnix)
	}
	return SeekPlan{
		SessionID:    seg.StartUnix,
		OffsetSec:    offset,
		ItemDurSec:   seg.DurationSec,
		EventUnix:    eventUnix,
		TrimStartSec: applied,
		CaptureSec:   capture,
		FinalDurSec:  finalDur,
	}
}

// SelectTimeItemCandidates returns a SeekPlan for every TimeItem covering
// eventUnix, ordered the same way LookupTimeline picks its single best match
// (duration closest to 60s first, shorter on a tie) — but keeping the rest
// instead of discarding them.
//
// Proven live (2026-08-03): two separate real events each had more than one
// covering TimeItem (e.g. a dur=316 span and a dur=60 entry starting where
// its first minute would end), the ~60s-preferring entry was chosen, and the
// camera never sent 0x10e for it — consistently, across many fresh-dialed
// retries spanning over an hour, ruling out both connection staleness and
// "recording still in progress". Old, since-abandoned notes in this codebase
// already flagged that a long span's own start "often isn't playable" and
// described (but never shipped) probing alternatives instead of trusting a
// single selection. This does that: DownloadPlayback tries each candidate in
// turn on a "no 0x10e" failure specifically, instead of giving up after the
// first (highest-scored) one goes silent.
func SelectTimeItemCandidates(segs []mtp.TimelineSeg, eventUnix int64, preRoll, finalDur int) ([]SeekPlan, error) {
	if eventUnix <= 0 {
		return nil, fmt.Errorf("miss: segment_not_found: bad eventUnix")
	}
	if preRoll < 0 {
		preRoll = 0
	}
	if finalDur <= 0 {
		finalDur = 20
	}

	covering := mtp.CoveringSegments(segs, eventUnix)
	if len(covering) == 0 {
		if seg, _, ok := mtp.LookupTimelineNear(segs, eventUnix, 180); ok {
			plans := []SeekPlan{planForSegment(seg, eventUnix, preRoll, finalDur)}
			return appendReachBackFallback(segs, plans, eventUnix, preRoll, finalDur), nil
		}
		var minS, maxS int64
		if len(segs) > 0 {
			minS, maxS = segs[0].StartUnix, segs[0].StartUnix
			for _, s := range segs {
				if s.StartUnix < minS {
					minS = s.StartUnix
				}
				end := s.StartUnix + int64(s.DurationSec)
				if end > maxS {
					maxS = end
				}
			}
		}
		return nil, fmt.Errorf("miss: segment_not_found: no TimeItem covering event=%d (index %d segs range=%d..%d)",
			eventUnix, len(segs), minS, maxS)
	}

	sort.SliceStable(covering, func(i, j int) bool {
		si, sj := absInt(covering[i].DurationSec-60), absInt(covering[j].DurationSec-60)
		if si != sj {
			return si < sj
		}
		return covering[i].DurationSec < covering[j].DurationSec
	})
	plans := make([]SeekPlan, 0, len(covering))
	for _, seg := range covering {
		plans = append(plans, planForSegment(seg, eventUnix, preRoll, finalDur))
	}
	return appendReachBackFallback(segs, plans, eventUnix, preRoll, finalDur), nil
}

// appendReachBackFallback appends one more candidate, seeking the segment
// immediately preceding the best (first) candidate's own segment, if the
// index has one contiguous with it.
//
// Proven live (2026-08-04): two real events each had exactly one covering
// TimeItem, a long dur=316 span, and the camera never sent 0x10e for it —
// consistently, for over 24 hours across dozens of fresh-dialed retries,
// ruling out both connection staleness and "recording still in progress"
// (see PlanPaddedSeek's own doc comment for the ±30s case this was first
// found in). But when the SAME event was requested with a padding choice
// large enough for PlanPaddedSeek to reach into the *preceding* segment
// instead, that request got an immediate 0x10e, and the camera's own
// auto-advance then carried the stream forward through the exact segment
// that was stuck moments before — as one continuous playback, under the
// preceding segment's own id. Some long-span index entries apparently
// aren't independently requestable, but reaching back one segment and
// letting auto-advance carry through is. This must not depend on the
// caller having asked for extra padding: it's a fallback candidate for
// every request, default duration/pre-roll included, appended after
// whatever SelectTimeItemCandidates already found so the normal
// covering-segment preference is tried first, unchanged.
func appendReachBackFallback(segs []mtp.TimelineSeg, plans []SeekPlan, eventUnix int64, preRoll, finalDur int) []SeekPlan {
	if len(plans) == 0 {
		return plans
	}
	prev, ok := mtp.PrecedingSegment(segs, plans[0].SessionID, contiguityTolSec)
	if !ok {
		return plans
	}
	for _, p := range plans {
		if p.SessionID == prev.StartUnix {
			return plans // already a candidate; don't duplicate
		}
	}
	return append(plans, planForSegment(prev, eventUnix, preRoll, finalDur))
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// contiguityTolSec bounds the gap PrecedingSegment will still treat as "the
// same recording continuing" when walking back for padding. Real SD
// recordings are event-triggered, so a genuinely separate earlier recording
// (minutes or hours before) must never be silently spliced onto the current
// one just because the user asked for a large pre-roll.
const contiguityTolSec = 5

// PlanPaddedSeek builds a degrading ordered list of single-seek SeekPlans for
// a user-chosen padding window around eventUnix. It reaches back across SD
// segment boundaries via mtp.PrecedingSegment (one hop at a time, gated on
// contiguity) rather than doing a second seek + stream concatenation:
// waitPlaybackRes's own doc comment already documents, as proven live, that
// a single 0x10d continues streaming across segment boundaries via the
// camera's own auto-advance — planForSegment's existing CaptureSec headroom
// already relies on this for events near a segment's end without anyone
// having designed for it.
//
// The returned list is ordered most-padded first (the furthest-back
// contiguous root reachable within `before` seconds), then progressively
// less padding (fewer hops), ending with the plain single-segment plan
// (today's shape). This feeds directly into the exact same "advance to the
// next candidate only on a silent no-0x10e timeout" loop in DownloadPlayback
// added earlier today for the overlapping-candidate bug — a reach-back root
// that the camera won't answer for degrades to a less-padded candidate with
// zero new fallback machinery, and each candidate's TrimStartSec/CaptureSec/
// FinalDurSec is already correct for its own root (planForSegment), so
// there's no risk of the recorder trimming a padding window that streaming
// silently failed to include.
func PlanPaddedSeek(segs []mtp.TimelineSeg, eventUnix int64, before, after int) ([]SeekPlan, error) {
	if eventUnix <= 0 {
		return nil, fmt.Errorf("miss: segment_not_found: bad eventUnix")
	}
	if before < 0 {
		before = 0
	}
	if after < 0 {
		after = 0
	}
	finalDur := before + after
	if finalDur <= 0 {
		finalDur = 20
	}

	cur, _, ok := mtp.LookupTimeline(segs, eventUnix)
	if !ok {
		cur, _, ok = mtp.LookupTimelineNear(segs, eventUnix, 180)
	}
	if !ok {
		var minS, maxS int64
		if len(segs) > 0 {
			minS, maxS = segs[0].StartUnix, segs[0].StartUnix
			for _, s := range segs {
				if s.StartUnix < minS {
					minS = s.StartUnix
				}
				end := s.StartUnix + int64(s.DurationSec)
				if end > maxS {
					maxS = end
				}
			}
		}
		return nil, fmt.Errorf("miss: segment_not_found: no TimeItem covering event=%d (index %d segs range=%d..%d)",
			eventUnix, len(segs), minS, maxS)
	}

	// Walk back one hop at a time while the root we've reached still starts
	// after the instant `before` seconds of pre-roll would need. chain is
	// built nearest-first (chain[0] == cur); the candidate list below is
	// built in reverse, farthest-back (most padding) first.
	startInstant := eventUnix - int64(before)
	chain := []mtp.TimelineSeg{cur}
	root := cur
	for startInstant < root.StartUnix {
		prev, ok := mtp.PrecedingSegment(segs, root.StartUnix, contiguityTolSec)
		if !ok {
			mtp.Logp("miss: padded seek: no contiguous segment before start=%d; clamping pre-roll (event=%d before=%d)\n",
				root.StartUnix, eventUnix, before)
			break
		}
		chain = append(chain, prev)
		root = prev
	}

	plans := make([]SeekPlan, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		plans = append(plans, planForSegment(chain[i], eventUnix, before, finalDur))
	}
	// If `before` comfortably fit inside the current segment (no reach-back
	// walk above), the current segment is still the only candidate — and it
	// could be one of the anomalous long spans appendReachBackFallback's doc
	// comment describes. Safe to call unconditionally: when the walk above
	// already reached the furthest contiguous segment, PrecedingSegment will
	// fail the same way it did inside that loop, so this is a no-op then.
	return appendReachBackFallback(segs, plans, eventUnix, before, finalDur), nil
}

// ExtendPlanToRecordingEnd lengthens plan.FinalDurSec so the clip runs from the
// event to the end of the contiguous SD recording it belongs to. The cloud
// event is only a start marker (alarmStart, no end/duration), but the camera's
// recording is event-triggered, so a run of back-to-back TimeItems ends where
// the motion recording ends. One 0x10d keeps streaming across item boundaries
// (camera auto-advance, see PlanPaddedSeek), so only the capture budget grows.
//
// The result is never shorter than plan.FinalDurSec and never longer than
// maxSec after the event (continuous-recording cameras would otherwise chain
// forever). maxSec <= 0 leaves the plan untouched.
func ExtendPlanToRecordingEnd(segs []mtp.TimelineSeg, plan SeekPlan, maxSec int) SeekPlan {
	if maxSec <= 0 || plan.EventUnix <= 0 {
		return plan
	}
	limit := plan.EventUnix + int64(maxSec)
	end := plan.SessionID + int64(plan.ItemDurSec)
	// A covering item can itself extend past the event; walk its successors.
	for end < limit {
		next, ok := mtp.FollowingSegment(segs, end, contiguityTolSec)
		if !ok {
			break
		}
		end = next.StartUnix + int64(next.DurationSec)
	}
	if end > limit {
		end = limit
	}
	full := int(end - plan.EventUnix)
	if full <= plan.FinalDurSec {
		return plan
	}
	plan.FinalDurSec = full
	plan.CaptureSec = plan.TrimStartSec + full + SyncSlackSec
	return plan
}
