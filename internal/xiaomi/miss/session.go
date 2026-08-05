package miss

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/mtp"
	"camwatch/internal/ports"
	"camwatch/internal/xiaomi/api"
	xcrypto "camwatch/internal/xiaomi/crypto"
	"github.com/google/uuid"
)

const (
	cmdVideoStop     = 0x103
	cmdAudioStart    = 0x104
	cmdAudioStop     = 0x105
	cmdPlaybackReq   = 0x10d
	cmdPlaybackRes   = 0x10e
	cmdPlaybackSpeed = 0x10f

	codecH264 = 4
	codecH265 = 5
	hdrSize   = 32

	// playbackResTimeout bounds the wait for 0x10e after 0x10d/0x10f. Real
	// captures (x/mtp-native.pcap, 5 successful round trips) show the camera
	// replies in 0.65-0.95s; a 15s wait mostly meant an already-doomed request
	// (wrong sessionid — see the RDT index fix in rdt.go) sat idle for 15x
	// longer than necessary before failing, multiplying retry latency.
	playbackResTimeout = 5 * time.Second
	// timelineFetchTO bounds one RDT type-6 fetch. A live A/B on this camera
	// (2026-08-02) tried doubling this to 60s expecting more wall-clock time
	// to reach further back into a multi-day SD index — it didn't help
	// (35s baseline: 178-593 segments/fetch; 60s: 2-499, same order of
	// magnitude, one fetch even kept only 2 valid records out of ~1000 raw
	// 8-byte slots). The bottleneck is body reassembly correctness, not
	// budget — see the fragment-alignment investigation this comment points
	// at (rdt.go body accumulation). Reverted to 35s so retries aren't slower
	// for no benefit.
	timelineFetchTO  = 35 * time.Second
	timelineCacheTTL = 90 * time.Second
)

// SessionFactory implements ports.StreamSession.
type SessionFactory struct {
	API       *api.Client
	Timelines ports.TimelineStore // optional; nil disables persistent timeline caching
}

func NewSessionFactory(a *api.Client, timelines ports.TimelineStore) *SessionFactory {
	return &SessionFactory{API: a, Timelines: timelines}
}

func (f *SessionFactory) Open(ctx context.Context, device domain.Device, tokens domain.TokenBundle) (ports.P2PConn, error) {
	_ = tokens
	_ = f.API.WakeUp(ctx, device.DID, device.Region)

	mtpPub, mtpPriv, err := xcrypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	appPub, _, err := xcrypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	caller := uuid.NewString()
	res, err := f.API.MissGetVendor(ctx, device.Region, device.DID, "MTP", hex.EncodeToString(appPub), caller)
	if err != nil || !vendorIsMTP(res) {
		res2, err2 := f.API.MissGetVendor(ctx, device.Region, device.DID, "TUTK_CS2_MTP", hex.EncodeToString(appPub), caller)
		if err2 == nil && (vendorIsMTP(res2) || res == nil) {
			res, err = res2, nil
		}
		if err != nil {
			return nil, fmt.Errorf("miss_get_vendor: %w", err)
		}
	}
	var v struct {
		Vendor struct {
			ID     byte `json:"vendor"`
			Params struct {
				SSAddrs   []string `json:"ssAddrs"`
				AuthToken string   `json:"authToken"`
				AuthStr   string   `json:"authStr"`
				UIDMtp    string   `json:"uid"`
				SSVer     int      `json:"ssVer"`
			} `json:"vendor_params"`
		} `json:"vendor"`
		PublicKey string `json:"public_key"`
		Sign      string `json:"sign"`
	}
	if err := json.Unmarshal(res, &v); err != nil {
		return nil, err
	}
	if v.Vendor.ID != 6 {
		return nil, fmt.Errorf("miss: expected MTP vendor 6, got %d", v.Vendor.ID)
	}
	if len(v.Vendor.Params.SSAddrs) == 0 || v.Vendor.Params.AuthStr == "" {
		return nil, fmt.Errorf("miss: mtp missing ssAddrs/authStr")
	}

	conn, err := mtp.Dial(mtp.DialOptions{
		SSAddrs:      v.Vendor.Params.SSAddrs,
		AuthStr:      v.Vendor.Params.AuthStr,
		AuthToken:    v.Vendor.Params.AuthToken,
		DID:          device.DID,
		UID:          v.Vendor.Params.UIDMtp,
		CallerUUID:   caller,
		SSVer:        fmt.Sprintf("%d", v.Vendor.Params.SSVer),
		DevicePublic: v.PublicKey,
		MTPPrivate:   hex.EncodeToString(mtpPriv),
		MTPPublic:    hex.EncodeToString(mtpPub),
	})
	if err != nil {
		return nil, err
	}
	if err := conn.WaitMediaReady(45 * time.Second); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("miss: media ready: %w", err)
	}
	return &Conn{conn: conn, model: device.Model, did: device.DID, timelines: f.Timelines}, nil
}

func vendorIsMTP(res []byte) bool {
	if res == nil {
		return false
	}
	var v struct {
		Vendor struct {
			ID byte `json:"vendor"`
		} `json:"vendor"`
	}
	if json.Unmarshal(res, &v) != nil {
		return false
	}
	return v.Vendor.ID == 6
}

// Conn wraps mtp.Conn as ports.P2PConn.
type Conn struct {
	conn       *mtp.Conn
	model      string
	did        string
	timeline   []mtp.TimelineSeg
	timelineAt time.Time
	timelines  ports.TimelineStore
}

func (c *Conn) Close() error { return c.conn.Close() }

func (c *Conn) Alive() bool { return c != nil && c.conn != nil && c.conn.Alive() }

// stopLive stops AV. Does not drain the cmd channel — that would discard 0x10e.
func (c *Conn) stopLive() {
	_ = c.conn.WriteMediaCommand(cmdAudioStop, []byte(`{}`))
	_ = c.conn.WriteMediaCommand(cmdVideoStop, []byte(`{}`))
	time.Sleep(150 * time.Millisecond)
	n := c.conn.DrainMedia()
	if n > 0 {
		mtp.Logp("miss: drained %d live media frames\n", n)
	}
}

// DownloadPlayback seeks an SD TimeItem (native sequence) and streams annex-B.
// Resolves EventUnix via full RDT type-6 index when SessionID==0. Fills
// TrimStartSec / CaptureSec on req for the recorder to trim after sync.
func (c *Conn) DownloadPlayback(ctx context.Context, req *domain.PlaybackRequest) (io.ReadCloser, error) {
	if req == nil {
		return nil, fmt.Errorf("miss: nil PlaybackRequest")
	}
	if req.Speed <= 0 {
		req.Speed = 1
	}
	if req.DurationSec <= 0 {
		req.DurationSec = 20
	}
	if req.PreRollSec <= 0 {
		req.PreRollSec = DefaultPreRollSec
	}

	// Downloads need a proven CHK/cmd path — never RDT on bind-only (una=0).
	if err := c.conn.WaitMediaCmdReady(15 * time.Second); err != nil {
		mtp.Logp("miss: media not live (%v); nudging stream\n", err)
		_ = c.conn.NudgeMediaStream()
		if err2 := c.conn.WaitMediaCmdReady(12 * time.Second); err2 != nil {
			return nil, fmt.Errorf("miss: timeline_unavailable: media chk not alive: %w", err2)
		}
	}

	plans, err := c.resolveSeekPlan(ctx, *req)
	if err != nil {
		return nil, err
	}

	c.stopLive()

	// Try each covering TimeItem in preference order (best/~60s-closest
	// first), but only advance to the next on a SILENT timeout — an explicit
	// rejection (0x10e arrived with status != filefound) is a definitive
	// answer from the camera about THIS sessionid, not ambiguous, so it
	// returns immediately rather than masking it by trying another guess.
	//
	// Proven live (2026-08-03): two separate real events each had more than
	// one covering TimeItem (e.g. a dur=316 span and a dur=60 entry starting
	// where its first minute would end); the ~60s-preferring entry was
	// chosen and the camera never sent 0x10e for it — consistently, across
	// many fresh-dialed retries spanning over an hour, ruling out both
	// connection staleness and "recording still in progress". This tries the
	// other real candidate the index already offered instead of giving up
	// after the first, highest-scored one goes silent.
	var lastErr error
	for i, plan := range plans {
		mtp.Logp("miss: seek plan sessionid=%d offset=%d trim=%ds capture=%ds event=%d itemDur=%d (candidate %d/%d)\n",
			plan.SessionID, plan.OffsetSec, plan.TrimStartSec, plan.CaptureSec, plan.EventUnix, plan.ItemDurSec, i+1, len(plans))

		to := rdtBudget(ctx, playbackResTimeout)
		if to <= 0 {
			return nil, ctx.Err()
		}
		resp, err := c.nativePlaybackSeek(plan, req.Speed, to)
		if err != nil {
			// The camera has been observed to start streaming playback media even
			// when it never sends 0x10e (container logs: ~1200 B/packet bursts
			// following a 0x10d that then timed out waiting for 0x10e) — almost
			// certainly because the requested sessionid didn't match a real SD
			// segment. Stop it explicitly so it isn't still streaming into a
			// parked warm session for the next attempt to inherit.
			_ = c.conn.WriteMediaCommand(cmdVideoStop, []byte(`{}`))
			// A silent timeout (no 0x10e reply at all) is a different failure
			// mode than the camera explicitly rejecting the request (0x10e
			// arrived with status != filefound, handled below) — and
			// orchestrator.keepWarmAfterCapture/classifyClipErr both key off
			// exact substrings in this error's text. Proven live (2026-08-03):
			// wrapping every nativePlaybackSeek error as "playback_rejected"
			// made a silent timeout match keepWarmAfterCapture's
			// "playback_rejected" case (return true, keep warm) before its own
			// — correct — "no 0x10e" case (return false, drop it) ever got a
			// chance, since Go's switch takes the first matching case. A
			// connection that had gone silent for 0x10d specifically then kept
			// getting reused for every subsequent attempt instead of forcing a
			// fresh dial, and the user saw a misleading "playback rejected by
			// camera" for what was really "the camera never replied."
			if strings.Contains(err.Error(), "no 0x10e") {
				lastErr = err
				if i+1 < len(plans) {
					mtp.Logp("miss: no 0x10e for sessionid=%d, trying next candidate\n", plan.SessionID)
				}
				continue
			}
			return nil, fmt.Errorf("miss: playback_rejected: %w", err)
		}
		if resp.Status != "filefound" {
			_ = c.conn.WriteMediaCommand(cmdVideoStop, []byte(`{}`))
			return nil, fmt.Errorf("miss: playback_rejected: status=%q sessionid=%d", resp.Status, plan.SessionID)
		}
		mtp.Logp("miss: 0x10e filefound sessionid=%d duration=%d\n", resp.ID, resp.Duration)

		req.SessionID = plan.SessionID
		req.StartTime = plan.SessionID
		req.OffsetSec = plan.OffsetSec
		req.TrimStartSec = plan.TrimStartSec
		req.CaptureSec = plan.CaptureSec
		req.DurationSec = plan.FinalDurSec

		captureSec := plan.CaptureSec
		if captureSec <= 0 {
			captureSec = plan.FinalDurSec + SyncSlackSec
		}
		return c.openPlaybackStream(ctx, captureSec), nil
	}
	return nil, lastErr
}

// openPlaybackStream reads annex-B until captureSec of wall time after first frame
// or idle/context end. Recorder owns post-sync trim timing.
func (c *Conn) openPlaybackStream(ctx context.Context, captureSec int) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		deadline := time.Now().Add(time.Duration(captureSec+15) * time.Second)
		_ = c.conn.SetDeadline(deadline)
		var wrote int
		idleLimit := 10 * time.Second
		lastData := time.Now()
		started := time.Time{}
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				_ = pw.CloseWithError(ctx.Err())
				return
			default:
			}
			waitUntil := deadline
			if wrote > 0 {
				idleDead := lastData.Add(idleLimit)
				if idleDead.Before(waitUntil) {
					waitUntil = idleDead
				}
			}
			_ = c.conn.SetDeadline(waitUntil)
			hdr, payload, err := c.conn.ReadPacket()
			if err != nil {
				if wrote > 0 {
					return
				}
				_ = pw.CloseWithError(fmt.Errorf("miss: stream_no_keyframe: %w", err))
				return
			}
			if len(hdr) < hdrSize {
				continue
			}
			codec := binary.LittleEndian.Uint32(hdr[4:])
			if codec != codecH264 && codec != codecH265 {
				continue
			}
			ab := toAnnexB(payload)
			if len(ab) == 0 {
				continue
			}
			if _, err := pw.Write(ab); err != nil {
				return
			}
			if started.IsZero() {
				started = time.Now()
			}
			wrote += len(ab)
			lastData = time.Now()
			if captureSec > 0 && time.Since(started) >= time.Duration(captureSec)*time.Second {
				return
			}
		}
	}()
	return pr
}

// OpenLive keeps the camera in live mode and streams annex-B video until the
// reader is closed or ctx is cancelled. Does not seek SD / RDT.
func (c *Conn) OpenLive(ctx context.Context) (io.ReadCloser, error) {
	// Ensure live AV is running (bootstrap already sent VIDEO_START; nudge quality).
	_ = c.conn.WriteMediaCommand(0x109, []byte(`{"videoquality":0}`))
	_ = c.conn.WriteMediaCommand(cmdAudioStart, []byte(`{}`))
	time.Sleep(200 * time.Millisecond)
	_ = c.conn.DrainMedia()

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		_ = c.conn.SetDeadline(time.Time{})
		idleLimit := 15 * time.Second
		lastData := time.Now()
		var wrote int
		for {
			select {
			case <-ctx.Done():
				_ = pw.CloseWithError(ctx.Err())
				return
			default:
			}
			if wrote > 0 && time.Since(lastData) > idleLimit {
				_ = pw.CloseWithError(fmt.Errorf("miss: live idle timeout"))
				return
			}
			wait := time.Now().Add(5 * time.Second)
			_ = c.conn.SetDeadline(wait)
			hdr, payload, err := c.conn.ReadPacket()
			if err != nil {
				if wrote > 0 && ctx.Err() == nil {
					// transient deadline — keep going
					continue
				}
				if wrote == 0 {
					_ = pw.CloseWithError(err)
				}
				return
			}
			if len(hdr) < hdrSize {
				continue
			}
			codec := binary.LittleEndian.Uint32(hdr[4:])
			if codec != codecH264 && codec != codecH265 {
				continue
			}
			ab := toAnnexB(payload)
			if len(ab) == 0 {
				continue
			}
			if _, err := pw.Write(ab); err != nil {
				return
			}
			wrote += len(ab)
			lastData = time.Now()
		}
	}()
	return pr, nil
}

func rdtBudget(ctx context.Context, want time.Duration) time.Duration {
	if want <= 0 {
		want = time.Second
	}
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl)
		if rem <= 0 {
			return 0
		}
		if rem < want {
			return rem
		}
	}
	return want
}

// resolveSeekPlan loads the full RDT type-6 index and builds native SeekPlan
// candidates, best first (see SelectTimeItemCandidates) — DownloadPlayback
// tries the rest only if the best one specifically gets no 0x10e reply.
// No minute-floor guesses and no stale shared-index fallback for downloads.
func (c *Conn) resolveSeekPlan(ctx context.Context, req domain.PlaybackRequest) ([]SeekPlan, error) {
	if req.SessionID != 0 {
		pre := req.PreRollSec
		if pre <= 0 {
			pre = DefaultPreRollSec
		}
		final := req.DurationSec
		if final <= 0 {
			final = 20
		}
		off := req.OffsetSec
		if off < 0 {
			off = 0
		}
		applied := pre
		if applied > off {
			applied = off
		}
		return []SeekPlan{{
			SessionID:    req.SessionID,
			OffsetSec:    off - applied,
			ItemDurSec:   60,
			EventUnix:    req.EventUnix,
			TrimStartSec: applied,
			CaptureSec:   applied + final + SyncSlackSec,
			FinalDurSec:  final,
		}}, nil
	}
	if req.EventUnix <= 0 {
		return nil, fmt.Errorf("miss: need SessionID or EventUnix")
	}
	if err := c.ensureTimeline(ctx, req.EventUnix); err != nil {
		return nil, err
	}
	covering := mtp.CoveringSegments(c.timeline, req.EventUnix)
	mtp.Logp("miss: covering TimeItems event=%d n=%d index=%d\n",
		req.EventUnix, len(covering), len(c.timeline))
	for i, s := range covering {
		if i >= 5 {
			mtp.Logp("miss:   cover … (%d more)\n", len(covering)-5)
			break
		}
		mtp.Logp("miss:   cover start=%d dur=%d\n", s.StartUnix, s.DurationSec)
	}
	// A caller-requested pre-roll larger than the small keyframe-sync default
	// (DefaultPreRollSec=8, used by the auto-poll path and untouched here) is
	// a user-chosen padding window that should reach across SD segment
	// boundaries via PlanPaddedSeek — see its doc comment. The default case
	// keeps using SelectTimeItemCandidates's existing single-segment clamp
	// unchanged, so auto-poll behavior is byte-for-byte identical to before.
	selectPlans := SelectTimeItemCandidates
	if req.PreRollSec > DefaultPreRollSec {
		selectPlans = func(segs []mtp.TimelineSeg, eventUnix int64, preRoll, finalDur int) ([]SeekPlan, error) {
			return PlanPaddedSeek(segs, eventUnix, preRoll, finalDur-preRoll)
		}
	}

	plans, err := selectPlans(c.timeline, req.EventUnix, req.PreRollSec, req.DurationSec)
	if err != nil {
		// One forced refetch for SD index lag, then fail closed.
		c.timeline = nil
		c.timelineAt = time.Time{}
		if err2 := c.ensureTimeline(ctx, req.EventUnix); err2 != nil {
			return nil, fmt.Errorf("miss: timeline_unavailable: %w", err2)
		}
		plans, err = selectPlans(c.timeline, req.EventUnix, req.PreRollSec, req.DurationSec)
		if err != nil {
			return nil, err
		}
	}
	return plans, nil
}

// nativePlaybackSeek: single 0x103 → 0x10d (endtime=0) → 0x10f → wait 0x10e.
// Matches x/new_command.log / MTP-PROTOCOL.md §9.4 open-play shape.
func (c *Conn) nativePlaybackSeek(plan SeekPlan, speed int, timeout time.Duration) (playbackRes, error) {
	_ = c.conn.WriteMediaCommand(cmdVideoStop, []byte(`{}`))
	time.Sleep(100 * time.Millisecond)

	body := fmt.Sprintf(
		`{"sessionid":%d,"starttime":%d,"endtime":0,"autoswitchtolive":0,"offset":%d,"speed":%d,"avchannelmerge":1}`,
		plan.SessionID, plan.SessionID, plan.OffsetSec, speed,
	)
	speedBody := fmt.Sprintf(`{"sessionid":%d,"speed":%d}`, plan.SessionID, speed)
	mtp.Logp("miss: TX 0x10d sessionid=%d offset=%d endtime=0\n", plan.SessionID, plan.OffsetSec)
	if err := c.conn.WriteMediaCommand(cmdPlaybackReq, []byte(body)); err != nil {
		return playbackRes{}, err
	}
	_ = c.conn.WriteMediaCommand(cmdPlaybackSpeed, []byte(speedBody))
	resp, err := waitPlaybackRes(c.conn, timeout, plan.SessionID)
	if err != nil {
		return playbackRes{}, err
	}
	return resp, nil
}

func (c *Conn) ensureTimeline(ctx context.Context, eventUnix int64) error {
	if len(c.timeline) > 0 && time.Since(c.timelineAt) < timelineCacheTTL {
		mtp.Logp("miss: reusing session SD timeline (%d segs, age=%s)\n",
			len(c.timeline), time.Since(c.timelineAt).Round(time.Millisecond))
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	c.timeline = nil
	mtp.Logp("miss: fetching SD timeline via RDT type=6 (event=%d)\n", eventUnix)
	// Brief wait for video so KCP una climbs (matches native: 0x102+0x109
	// briefly before the RDT request).
	if !c.conn.WaitMediaVideo(2 * time.Second) {
		mtp.Logp("miss: no live video yet; sending RDT anyway\n")
	}
	// Stop video BEFORE fetching, matching native exactly (frida-mtp-capture,
	// 2026-08-02: miss_rdt_send type=6 immediately followed by 0x103, not the
	// reverse). This used to be a fallback only tried after a first attempt
	// with live video still running had already failed — "prefer RDT while
	// live CHK flows" was backwards. Concurrent live video competes with the
	// RDT stream for the same UDP path's bandwidth: the real client measured
	// ~3-4 KB/s fetching the full ~83 KB index with video stopped, while our
	// live-video-concurrent fetches were seeing far less and often timing out
	// having accumulated only a few KB.
	_ = c.conn.WriteMediaCommand(cmdVideoStop, []byte(`{}`))
	time.Sleep(100 * time.Millisecond)
	segs, err := c.conn.FetchTimelineIndex(rdtBudget(ctx, timelineFetchTO), eventUnix)
	if err != nil {
		mtp.Logp("miss: RDT failed (%v); retrying once\n", err)
		_ = c.conn.WriteMediaCommand(cmdVideoStop, []byte(`{}`))
		time.Sleep(400 * time.Millisecond)
		segs, err = c.conn.FetchTimelineIndex(rdtBudget(ctx, timelineFetchTO), eventUnix)
	}
	if err != nil {
		// A single live fetch only ever samples a small fraction of the
		// camera's full SD index (confirmed for both camwatch and the real
		// Mi Home app, 2026-08-02 — see TimelineStore's doc comment). Fall
		// back to whatever coverage past fetches already accumulated before
		// giving up outright.
		if c.timelines != nil {
			if cached, cerr := c.timelines.Segments(ctx, c.did); cerr == nil && len(cached) > 0 {
				mtp.Logp("miss: RDT fetch failed (%v); using %d cached segments from past fetches\n", err, len(cached))
				c.timeline = cached
				c.timelineAt = time.Now()
				return nil
			}
		}
		return fmt.Errorf("miss: timeline_unavailable: %w", err)
	}
	c.timeline = segs
	c.timelineAt = time.Now()
	if c.timelines != nil {
		if merr := c.timelines.MergeSegments(ctx, c.did, segs); merr != nil {
			mtp.Logp("miss: timeline cache merge failed: %v\n", merr)
		} else if cached, cerr := c.timelines.Segments(ctx, c.did); cerr == nil {
			mtp.Logp("miss: timeline cache now covers %d segments total (this fetch added %d)\n",
				len(cached), len(segs))
			c.timeline = cached
		}
	}
	return nil
}

type playbackRes struct {
	ID        int64  `json:"id"`
	Status    string `json:"status"`
	StartTime int64  `json:"starttime"`
	Duration  int    `json:"duration"`
	VChn      int    `json:"vchn"`
}

// waitPlaybackRes waits for the 0x10e reply to THIS request's 0x10d, matching
// on its echoed "id" field against expectedID (the sessionid we sent).
//
// Proven live (2026-08-02): on a reused warm P2P session, a previous
// request's playback keeps auto-advancing through timeline segments
// (each landing its own 0x10e) even after that request has returned and the
// connection was parked for reuse. Those stale replies sit in the shared cmd
// queue; the old code accepted the FIRST 0x10e it popped regardless of which
// sessionid it belonged to, so a new request could be handed a leftover
// "endoffile" from the prior session's playback and fail with
// playback_rejected — while the real, matching "filefound" for the new
// request was still sitting unclaimed in the queue right behind it. A retry
// then picked up that leftover correctly and succeeded, which is exactly the
// intermittent "fails then the identical retry works" pattern seen live.
func waitPlaybackRes(conn *mtp.Conn, timeout time.Duration, expectedID int64) (playbackRes, error) {
	deadline := time.Now().Add(timeout)
	var lastMismatched playbackRes
	for time.Now().Before(deadline) {
		// Channel-only wait: do not SetDeadline on the shared UDP socket or the
		// media demuxer will start timing out while we wait for 0x10e.
		cmd, data, err := conn.ReadCommandUntil(deadline)
		if err != nil {
			if time.Now().Before(deadline) {
				continue
			}
			break
		}
		if cmd != cmdPlaybackRes {
			continue
		}
		resp, ok := parsePlaybackRes(data)
		if !ok {
			mtp.Logp("miss: 0x10e unparseable len=%d %q\n", len(data), truncateForLog(data, 120))
			continue
		}
		if resp.ID != expectedID {
			mtp.Logp("miss: 0x10e id=%d status=%q ignored (waiting for id=%d, stale from a prior request)\n",
				resp.ID, resp.Status, expectedID)
			lastMismatched = resp
			continue
		}
		return resp, nil
	}
	if lastMismatched.Status != "" {
		return playbackRes{}, fmt.Errorf("miss: no 0x10e for id=%d within %s (only saw stale id=%d status=%q)",
			expectedID, timeout, lastMismatched.ID, lastMismatched.Status)
	}
	return playbackRes{}, fmt.Errorf("miss: no 0x10e within %s", timeout)
}

// parsePlaybackRes accepts firmwares that append junk after the JSON object
// (e.g. `...}}N`). Prefer Decoder (stops after first value); fall back to a
// brace-balanced scrape when needed.
func parsePlaybackRes(data []byte) (playbackRes, bool) {
	data = bytes.TrimRight(data, "\x00")
	var resp playbackRes
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&resp); err == nil && resp.Status != "" {
		return resp, true
	}
	if obj := extractJSONObject(data); len(obj) > 0 {
		resp = playbackRes{}
		if err := json.Unmarshal(obj, &resp); err == nil && resp.Status != "" {
			return resp, true
		}
	}
	return playbackRes{}, false
}

// extractJSONObject returns the first balanced {...} slice, respecting strings.
func extractJSONObject(data []byte) []byte {
	i := bytes.IndexByte(data, '{')
	if i < 0 {
		return nil
	}
	depth := 0
	inString := false
	escape := false
	for j := i; j < len(data); j++ {
		c := data[j]
		if inString {
			if escape {
				escape = false
				continue
			}
			switch c {
			case '\\':
				escape = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return data[i : j+1]
			}
		}
	}
	return nil
}

func truncateForLog(b []byte, n int) string {
	s := string(bytes.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '.'
		}
		return r
	}, b))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func toAnnexB(p []byte) []byte {
	if len(p) >= 4 && p[0] == 0 && p[1] == 0 && (p[2] == 1 || (p[2] == 0 && p[3] == 1)) {
		return p
	}
	var out []byte
	for i := 0; i+4 <= len(p); {
		n := int(binary.BigEndian.Uint32(p[i:]))
		i += 4
		if n <= 0 || i+n > len(p) {
			// Truncated length-prefixed AU — keep only complete NALs already
			// converted; never pass the raw buffer (confuses the HEVC decoder).
			if len(out) > 0 {
				return out
			}
			return nil
		}
		out = append(out, 0, 0, 0, 1)
		out = append(out, p[i:i+n]...)
		i += n
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
