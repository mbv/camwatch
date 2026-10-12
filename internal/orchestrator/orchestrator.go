package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/ports"
)

// ErrBusy is returned when another MTP download is already running for the DID.
var ErrBusy = errors.New("orchestrator: camera busy")

type Config struct {
	PollInterval time.Duration
	LogOnly      bool
	ClipDuration int
	Devices      []domain.Device
}

type Orchestrator struct {
	cfg      Config
	auth     ports.AuthProvider
	cloud    ports.CameraCloudAPI
	stream   ports.StreamSession
	recorder ports.Recorder
	notify   ports.Notifier
	store    ports.EventStore
	log      *slog.Logger

	mu          sync.Mutex
	inflight    map[string]bool      // did -> downloading or live
	claimed     map[string]bool      // event key -> capture/notify in progress
	failCounts  map[string]int       // event key -> consecutive hard capture failures
	rdtFails    map[string]int       // event key -> consecutive RDT soft failures
	rdtCooldown map[string]time.Time // event key -> do not auto-retry until
	warm        map[string]*warmSlot // did -> parked P2P (sticky like Mi Home)
	autoQuiet   map[string]time.Time // did -> skip auto-poll capture until (bot quiet window)

	livePub    ports.LivePublisher
	live       *LiveSession
	liveChatID string
	liveFFmpeg string
	liveW      int
	liveH      int
	liveFPS    int
}

func New(
	cfg Config,
	auth ports.AuthProvider,
	cloud ports.CameraCloudAPI,
	stream ports.StreamSession,
	recorder ports.Recorder,
	notify ports.Notifier,
	store ports.EventStore,
	log *slog.Logger,
) *Orchestrator {
	if log == nil {
		log = slog.Default()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 45 * time.Second
	}
	return &Orchestrator{
		cfg:         cfg,
		auth:        auth,
		cloud:       cloud,
		stream:      stream,
		recorder:    recorder,
		notify:      notify,
		store:       store,
		log:         log,
		inflight:    map[string]bool{},
		claimed:     map[string]bool{},
		failCounts:  map[string]int{},
		rdtFails:    map[string]int{},
		rdtCooldown: map[string]time.Time{},
		warm:        map[string]*warmSlot{},
		autoQuiet:   map[string]time.Time{},
	}
}

const autoQuietAfterManual = 90 * time.Second

// NoteManualClip tells auto-poll to leave this DID alone briefly so timeline
// taps are not blocked by a background capture ("Camera busy").
func (o *Orchestrator) NoteManualClip(did string) {
	o.mu.Lock()
	o.autoQuiet[did] = time.Now().Add(autoQuietAfterManual)
	o.mu.Unlock()
}

func (o *Orchestrator) Devices() []domain.Device {
	return append([]domain.Device(nil), o.cfg.Devices...)
}

func (o *Orchestrator) Run(ctx context.Context) error {
	if _, err := o.auth.EnsureValid(ctx); err != nil {
		return err
	}
	o.log.Info("camwatch started", "poll", o.cfg.PollInterval, "devices", len(o.cfg.Devices), "log_only", o.cfg.LogOnly)
	defer o.CloseWarmSessions()

	t := time.NewTicker(o.cfg.PollInterval)
	defer t.Stop()

	o.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if _, err := o.auth.EnsureValid(ctx); err != nil {
				o.log.Error("auth refresh", "err", err)
				continue
			}
			o.pollOnce(ctx)
		}
	}
}

const (
	freshEventDefer    = 90 * time.Second
	rdtFailCooldownAfter = 2
	rdtCooldownDuration = 10 * time.Minute
	// captureFailCooldownDuration bounds the auto-retry pause after
	// captureFailAbandon straight capture failures. Deliberately an in-memory
	// cooldown (shared o.rdtCooldown map/gate) rather than a persisted
	// store.Mark — a protocol bug (e.g. a bad SD index) is not evidence the
	// event itself is undownloadable, and a permanent Mark meant a fixed bug
	// could never recover events it had already given up on. A process
	// restart also clears this, so a deployed fix retries immediately.
	captureFailCooldownDuration = 30 * time.Minute
)

func (o *Orchestrator) pollOnce(ctx context.Context) {
	now := time.Now()
	for _, dev := range o.cfg.Devices {
		o.mu.Lock()
		quietUntil := o.autoQuiet[dev.DID]
		o.mu.Unlock()
		if now.Before(quietUntil) {
			o.log.Info("skip auto-capture; manual quiet window",
				"did", dev.DID, "until", quietUntil.UTC().Format(time.RFC3339))
			continue
		}
		events, err := o.ListEvents(ctx, dev, now.Add(-24*time.Hour).UnixMilli(), now.UnixMilli())
		if err != nil {
			o.log.Error("eventlist", "did", dev.DID, "err", err)
			continue
		}
		for _, ev := range events {
			key := ev.Key()
			seen, err := o.store.Seen(ctx, key)
			if err != nil {
				o.log.Error("store seen", "err", err)
				continue
			}
			if seen {
				continue
			}
			if o.inRDTCooldown(key) {
				continue
			}
			age := now.Sub(time.Unix(ev.SessionUnix(), 0))
			if age >= 0 && age < freshEventDefer {
				o.log.Info("defer capture; event too fresh",
					"fileId", ev.FileID, "age", age.Round(time.Second))
				continue
			}
			// One download per camera at a time: don't claim/spawn the rest of
			// the backlog just to have each goroutine bounce off ErrBusy.
			o.mu.Lock()
			busy := o.inflight[dev.DID]
			o.mu.Unlock()
			if busy {
				o.log.Debug("camera busy; leaving remaining events for next poll", "did", dev.DID)
				break
			}
			if !o.claimEvent(key) {
				continue
			}
			o.log.Info("new event", "type", ev.EventType, "fileId", ev.FileID, "time", time.Unix(ev.SessionUnix(), 0))
			if o.cfg.LogOnly {
				_ = o.store.Mark(ctx, key, ev)
				o.unclaimEvent(key)
				continue
			}
			go o.handleNewEvent(ctx, dev, ev)
			// The goroutine hasn't taken the inflight slot yet; stop here so
			// the rest of the backlog waits for the next poll.
			break
		}
	}
}

func (o *Orchestrator) claimEvent(key string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.claimed[key] {
		return false
	}
	o.claimed[key] = true
	return true
}

func (o *Orchestrator) unclaimEvent(key string) {
	o.mu.Lock()
	delete(o.claimed, key)
	o.mu.Unlock()
}

func (o *Orchestrator) handleNewEvent(ctx context.Context, dev domain.Device, ev domain.Event) {
	key := ev.Key()
	defer func() {
		// Keep claim if we marked the store (success / abandon); otherwise allow retry.
		seen, _ := o.store.Seen(ctx, key)
		if !seen {
			o.unclaimEvent(key)
		}
	}()

	clip, err := o.RequestClip(ctx, dev, ev, domain.ClipWindow{})
	if errors.Is(err, ErrBusy) {
		o.log.Info("skip event; download in flight", "did", dev.DID, "fileId", ev.FileID)
		return
	}
	if err != nil {
		o.log.Error("capture", "err", err)
		if o.noteRDTFailure(ev, err) {
			o.log.Warn("rdt cooldown after repeated timeouts",
				"fileId", ev.FileID, "for", rdtCooldownDuration, "err", err)
			return
		}
		// Stop hammering: camera gave no 0x10e (or SD miss) after several
		// polls. Cool down rather than permanently Mark — see
		// captureFailCooldownDuration doc comment.
		if o.shouldAbandonCapture(ev, err) {
			o.log.Warn("capture cooldown after repeated failures",
				"fileId", ev.FileID, "for", captureFailCooldownDuration, "err", err)
		}
		return
	}
	o.clearCaptureFails(ev)

	// Mark before notify so a slow/failed Telegram upload cannot spawn another
	// MTP download on the next poll (previously caused 3× clips for one fileId).
	if err := o.store.Mark(ctx, key, ev); err != nil {
		o.log.Error("mark seen", "err", err)
	}

	if err := o.notify.NotifyEvent(ctx, ev, clip, nil); err != nil {
		o.log.Error("notify", "err", err)
		return
	}
	o.log.Info("delivered", "path", clip.Path, "bytes", clip.Bytes, "type", ev.EventType)
}

const captureFailAbandon = 5

func (o *Orchestrator) shouldAbandonCapture(ev domain.Event, err error) bool {
	msg := err.Error()
	if !strings.Contains(msg, "no 0x10e") &&
		!strings.Contains(msg, "filenotfound") &&
		!strings.Contains(msg, "segment_not_found") {
		// "no SD segment" was dead — the actual error text produced by
		// native.go is "segment_not_found", so a real segment miss was never
		// abandoned and instead retried every poll indefinitely.
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failCounts == nil {
		o.failCounts = map[string]int{}
	}
	if o.rdtCooldown == nil {
		o.rdtCooldown = map[string]time.Time{}
	}
	k := ev.Key()
	o.failCounts[k]++
	n := o.failCounts[k]
	if n >= captureFailAbandon {
		delete(o.failCounts, k)
		o.rdtCooldown[k] = time.Now().Add(captureFailCooldownDuration)
		return true
	}
	return false
}

func isRDTSoftFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "rdt type6") ||
		strings.Contains(msg, "rdt timeline") ||
		(strings.Contains(msg, "deadline exceeded") && strings.Contains(msg, "rdt"))
}

// noteRDTFailure tracks soft RDT failures. After rdtFailCooldownAfter strikes,
// sets a cooldown without Marking seen (bot timeline tap can still retry).
func (o *Orchestrator) noteRDTFailure(ev domain.Event, err error) bool {
	if !isRDTSoftFailure(err) {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rdtFails == nil {
		o.rdtFails = map[string]int{}
	}
	if o.rdtCooldown == nil {
		o.rdtCooldown = map[string]time.Time{}
	}
	k := ev.Key()
	o.rdtFails[k]++
	if o.rdtFails[k] < rdtFailCooldownAfter {
		return false
	}
	delete(o.rdtFails, k)
	o.rdtCooldown[k] = time.Now().Add(rdtCooldownDuration)
	return true
}

func (o *Orchestrator) inRDTCooldown(key string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	until, ok := o.rdtCooldown[key]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(o.rdtCooldown, key)
	return false
}

func (o *Orchestrator) clearCaptureFails(ev domain.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	k := ev.Key()
	delete(o.failCounts, k)
	delete(o.rdtFails, k)
	delete(o.rdtCooldown, k)
}

// ListEvents implements ports.ClipRequester.
func (o *Orchestrator) ListEvents(ctx context.Context, device domain.Device, beginMs, endMs int64) ([]domain.Event, error) {
	if _, err := o.auth.EnsureValid(ctx); err != nil {
		return nil, err
	}
	q := domain.EventQuery{
		DID:     device.DID,
		Model:   device.Model,
		Region:  device.Region,
		BeginMs: beginMs,
		EndMs:   endMs,
		Limit:   50,
	}
	o.log.Debug("eventlist request", "did", device.DID, "begin", beginMs, "end", endMs)
	events, err := o.cloud.EventList(ctx, q)
	if err != nil {
		o.log.Warn("eventlist failed, refreshing auth", "did", device.DID, "err", err)
		// Invalidate the cached cloud first — EnsureValid otherwise short-
		// circuits to the in-memory session snapshot (no TTL/expiry check)
		// and hands Refresh the exact bundle that just failed. See
		// Provider.Invalidate doc comment.
		o.auth.Invalidate()
		if _, rerr := o.auth.Refresh(ctx, mustBundle(o.auth, ctx)); rerr == nil {
			events, err = o.cloud.EventList(ctx, q)
		}
		if err != nil {
			return nil, err
		}
	}
	for i := range events {
		events[i].DID = device.DID
		events[i].Model = device.Model
		events[i].Region = device.Region
	}
	return events, nil
}

// RequestClip implements ports.ClipRequester (single-flight per DID).
func (o *Orchestrator) RequestClip(ctx context.Context, device domain.Device, ev domain.Event, win domain.ClipWindow) (domain.Clip, error) {
	o.mu.Lock()
	if o.inflight[device.DID] {
		o.mu.Unlock()
		return domain.Clip{}, ErrBusy
	}
	o.inflight[device.DID] = true
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		delete(o.inflight, device.DID)
		o.mu.Unlock()
	}()

	ev.DID = device.DID
	ev.Model = device.Model
	ev.Region = device.Region
	o.log.Info("RequestClip",
		"fileId", ev.FileID,
		"eventUnix", ev.SessionUnix(),
		"isCloud", ev.IsCloud,
		"onlyShowImgNoPlay", ev.OnlyShowImgNoPlay,
	)

	// One native attempt, plus a single fresh-dial retry when the media path
	// never comes alive (bindOK without CHK/video → RDT silence). 150s was
	// sized for the ~20-38s default capture; a user-chosen padding window
	// (up to ±30s = 60s of media, on top of the reach-back candidates'
	// own seek/RDT-fetch overhead) can exceed it — rdtBudget silently
	// shrinks the 0x10e wait as this deadline nears rather than erroring, so
	// an unscaled timeout here would fail closed as a truncated clip instead
	// of a visible error.
	timeout := 150*time.Second + 2*time.Duration(win.BeforeSec+win.AfterSec)*time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tokens, err := o.auth.EnsureValid(ctx)
	if err != nil {
		return domain.Clip{}, err
	}
	conn, _, err := o.borrowP2P(ctx, device, tokens)
	if err != nil && isAuthErr(err) {
		// miss_get_vendor 401: the cached session is dead. EnsureValid never
		// revalidates it, so without this every capture fails until restart.
		o.log.Warn("p2p open unauthorized, refreshing auth", "did", device.DID, "err", err)
		o.auth.Invalidate()
		if t, rerr := o.auth.Refresh(ctx, mustBundle(o.auth, ctx)); rerr == nil {
			tokens = t
			conn, _, err = o.borrowP2P(ctx, device, tokens)
		} else {
			o.log.Error("auth refresh after 401", "err", rerr)
		}
	}
	if err != nil {
		return domain.Clip{}, fmt.Errorf("p2p open: %w", err)
	}

	clip, err := o.recorder.CaptureEvent(ctx, conn, ev, win)
	if err != nil && clip.Path == "" && mediaPathDead(err) {
		o.log.Warn("media path dead; redial once", "err", err)
		o.returnP2P(device.DID, conn, false)
		conn, _, err = o.borrowP2P(ctx, device, tokens)
		if err != nil {
			return domain.Clip{}, fmt.Errorf("p2p open: %w", err)
		}
		clip, err = o.recorder.CaptureEvent(ctx, conn, ev, win)
	}
	o.returnP2P(device.DID, conn, keepWarmAfterCapture(err))
	if err != nil && clip.Path == "" {
		return domain.Clip{}, classifyClipErr(err)
	}
	if err != nil {
		o.log.Warn("capture partial", "err", err, "path", clip.Path)
	}
	return clip, nil
}

func isAuthErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "401") || strings.Contains(msg, "Unauthorized")
}

func mediaPathDead(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Only redial when live CHK/video never started. RDT silence on a live
	// session is a different failure — redialing often loses the media path.
	return strings.Contains(msg, "media chk not alive") ||
		strings.Contains(msg, "media session not ready")
}

func classifyClipErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeline_unavailable"):
		return fmt.Errorf("timeline_unavailable: %w", err)
	case strings.Contains(msg, "segment_not_found"):
		return fmt.Errorf("segment_not_found: %w", err)
	case strings.Contains(msg, "playback_rejected"):
		return fmt.Errorf("playback_rejected: %w", err)
	case strings.Contains(msg, "stream_no_keyframe"):
		return fmt.Errorf("stream_no_keyframe: %w", err)
	case strings.Contains(msg, "remux_failed"):
		return fmt.Errorf("remux_failed: %w", err)
	default:
		return err
	}
}

func mustBundle(a ports.AuthProvider, ctx context.Context) domain.TokenBundle {
	t, _ := a.EnsureValid(ctx)
	return t
}

var _ ports.ClipRequester = (*Orchestrator)(nil)
