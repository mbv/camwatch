package orchestrator

import (
	"context"
	"fmt"
	"io"
	"sync"

	"camwatch/internal/domain"
	"camwatch/internal/notify/live"
	"camwatch/internal/ports"
)

// LiveSession owns one camera → Telegram VC publish pipeline.
type LiveSession struct {
	mu        sync.Mutex
	active    bool
	device    domain.Device
	cancel    context.CancelFunc
	conn      ports.P2PConn
	stopHTTP  func()
	publisher ports.LivePublisher
}

// SetLivePublisher wires the ntgcalls sidecar publisher (optional).
func (o *Orchestrator) SetLivePublisher(p ports.LivePublisher) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.livePub = p
}

// LiveActive reports whether a live publish is running.
func (o *Orchestrator) LiveActive() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.live != nil && o.live.active
}

// StartLive opens MTP live, remuxes to local MPEG-TS HTTP, and joins the group VC.
func (o *Orchestrator) StartLive(ctx context.Context, device domain.Device) error {
	o.mu.Lock()
	if o.inflight[device.DID] {
		o.mu.Unlock()
		return ErrBusy
	}
	if o.live != nil && o.live.active {
		o.mu.Unlock()
		return live.ErrLiveBusy
	}
	pub := o.livePub
	chatID := o.liveChatID
	ffmpeg := o.liveFFmpeg
	w, h, fps := o.liveW, o.liveH, o.liveFPS
	if pub == nil {
		o.mu.Unlock()
		return live.ErrLiveDisabled
	}
	o.inflight[device.DID] = true
	o.mu.Unlock()

	cleanupInflight := func() {
		o.mu.Lock()
		delete(o.inflight, device.DID)
		o.mu.Unlock()
	}

	tokens, err := o.auth.EnsureValid(ctx)
	if err != nil {
		cleanupInflight()
		return err
	}
	// Live needs exclusive media; drop any parked SD session for this DID.
	o.evictWarm(device.DID)
	conn, err := o.stream.Open(ctx, device, tokens)
	if err != nil {
		cleanupInflight()
		return fmt.Errorf("p2p open: %w", err)
	}
	liveCtx, cancel := context.WithCancel(context.Background())
	rc, err := conn.OpenLive(liveCtx)
	if err != nil {
		cancel()
		_ = conn.Close()
		cleanupInflight()
		return fmt.Errorf("open live: %w", err)
	}

	url, stopHTTP, err := live.ServeAnnexB(liveCtx, ffmpeg, w, h, fps, rc, o.log)
	if err != nil {
		cancel()
		_ = rc.Close()
		_ = conn.Close()
		cleanupInflight()
		return fmt.Errorf("mpegts: %w", err)
	}

	if err := pub.StartCall(ctx, chatID, url); err != nil {
		stopHTTP()
		cancel()
		_ = rc.Close()
		_ = conn.Close()
		cleanupInflight()
		return err
	}

	o.mu.Lock()
	o.live = &LiveSession{
		active:    true,
		device:    device,
		cancel:    cancel,
		conn:      conn,
		stopHTTP:  stopHTTP,
		publisher: pub,
	}
	// Keep DID marked inflight while live runs.
	o.mu.Unlock()
	o.log.Info("live started", "did", device.DID, "chat_id", chatID, "url", url)

	go func() {
		<-liveCtx.Done()
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}()
	return nil
}

// StartLiveTest joins the VC with the ntgcalls sample MP4 (no camera).
func (o *Orchestrator) StartLiveTest(ctx context.Context) error {
	o.mu.Lock()
	pub := o.livePub
	chatID := o.liveChatID
	if pub == nil {
		o.mu.Unlock()
		return live.ErrLiveDisabled
	}
	if o.live != nil && o.live.active {
		o.mu.Unlock()
		return live.ErrLiveBusy
	}
	o.mu.Unlock()
	if err := pub.StartTest(ctx, chatID); err != nil {
		return err
	}
	o.mu.Lock()
	o.live = &LiveSession{active: true, publisher: pub}
	o.mu.Unlock()
	o.log.Info("live test started", "chat_id", chatID)
	return nil
}

// StopLive tears down VC publish and MTP live.
func (o *Orchestrator) StopLive(ctx context.Context) error {
	o.mu.Lock()
	sess := o.live
	o.live = nil
	o.mu.Unlock()
	if sess == nil {
		return nil
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.active = false
	if sess.publisher != nil {
		_ = sess.publisher.Stop(ctx)
	}
	if sess.stopHTTP != nil {
		sess.stopHTTP()
	}
	if sess.cancel != nil {
		sess.cancel()
	}
	if sess.conn != nil {
		_ = sess.conn.Close()
	}
	if sess.device.DID != "" {
		o.mu.Lock()
		delete(o.inflight, sess.device.DID)
		o.mu.Unlock()
	}
	o.log.Info("live stopped")
	return nil
}

// ConfigureLive stores live publish settings on the orchestrator.
func (o *Orchestrator) ConfigureLive(chatID, ffmpeg string, w, h, fps int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.liveChatID = chatID
	o.liveFFmpeg = ffmpeg
	o.liveW, o.liveH, o.liveFPS = w, h, fps
}

var _ ports.LiveController = (*Orchestrator)(nil)