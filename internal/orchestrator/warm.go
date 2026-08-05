package orchestrator

import (
	"context"
	"strings"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/ports"
)

// Keep a sticky MTP session per DID (like Mi Home) so consecutive timeline
// downloads reuse media bind + cached RDT instead of redialing ssAddrs.
const warmIdleTTL = 3 * time.Minute

type warmSlot struct {
	conn  ports.P2PConn
	timer *time.Timer
}

// borrowP2P returns a warm connection when still alive, otherwise opens a new one.
func (o *Orchestrator) borrowP2P(ctx context.Context, device domain.Device, tokens domain.TokenBundle) (ports.P2PConn, bool, error) {
	o.mu.Lock()
	if w, ok := o.warm[device.DID]; ok {
		delete(o.warm, device.DID)
		if w.timer != nil {
			w.timer.Stop()
		}
		conn := w.conn
		o.mu.Unlock()
		if conn != nil && conn.Alive() {
			o.log.Info("p2p warm reuse", "did", device.DID)
			return conn, true, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		o.log.Info("p2p warm dead; opening new", "did", device.DID)
	} else {
		o.mu.Unlock()
	}

	conn, err := o.stream.Open(ctx, device, tokens)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}

// returnP2P parks a healthy session for warmIdleTTL, or closes it.
func (o *Orchestrator) returnP2P(did string, conn ports.P2PConn, keep bool) {
	if conn == nil {
		return
	}
	if !keep || !conn.Alive() {
		_ = conn.Close()
		return
	}

	o.mu.Lock()
	if old, ok := o.warm[did]; ok {
		if old.timer != nil {
			old.timer.Stop()
		}
		_ = old.conn.Close()
	}
	slot := &warmSlot{conn: conn}
	slot.timer = time.AfterFunc(warmIdleTTL, func() {
		o.expireWarm(did, conn)
	})
	o.warm[did] = slot
	o.mu.Unlock()
	o.log.Info("p2p warm parked", "did", did, "ttl", warmIdleTTL)
}

func (o *Orchestrator) expireWarm(did string, expect ports.P2PConn) {
	o.mu.Lock()
	w, ok := o.warm[did]
	if !ok || w.conn != expect {
		o.mu.Unlock()
		return
	}
	delete(o.warm, did)
	conn := w.conn
	o.mu.Unlock()
	_ = conn.Close()
	o.log.Info("p2p warm expired", "did", did)
}

// evictWarm closes any parked session for did (e.g. before /live).
func (o *Orchestrator) evictWarm(did string) {
	o.mu.Lock()
	w, ok := o.warm[did]
	if ok {
		delete(o.warm, did)
		if w.timer != nil {
			w.timer.Stop()
		}
	}
	o.mu.Unlock()
	if ok && w.conn != nil {
		_ = w.conn.Close()
		o.log.Info("p2p warm evicted", "did", did)
	}
}

// CloseWarmSessions drops all parked P2P connections (process shutdown).
func (o *Orchestrator) CloseWarmSessions() {
	o.mu.Lock()
	warm := o.warm
	o.warm = map[string]*warmSlot{}
	o.mu.Unlock()
	for did, w := range warm {
		if w.timer != nil {
			w.timer.Stop()
		}
		if w.conn != nil {
			_ = w.conn.Close()
		}
		o.log.Info("p2p warm closed", "did", did)
	}
}

func keepWarmAfterCapture(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	switch {
	// Checked before the "playback_rejected"/"segment_not_found" case below,
	// not just alongside it: proven live (2026-08-03) that session.go used to
	// wrap every nativePlaybackSeek failure — including a silent "no 0x10e"
	// timeout — as "miss: playback_rejected: %w", so a timeout's error text
	// contained BOTH substrings. Go's switch takes the first matching case,
	// and with "playback_rejected" listed first a genuine silent-timeout
	// connection kept getting judged "keep warm" and reused for every
	// subsequent attempt instead of forcing a fresh dial. session.go no
	// longer double-wraps, but this function must not depend on that: a
	// silent/dead-path signal must always win over a merely-broad
	// "playback_rejected"/"segment_not_found" substring match, regardless of
	// what any caller's error wrapping happens to contain.
	case strings.Contains(msg, "timeline_unavailable"),
		strings.Contains(msg, "rdt timeline"),
		strings.Contains(msg, "rdt type6"),
		strings.Contains(msg, "no 0x10e"),
		strings.Contains(msg, "stream_no_keyframe"),
		strings.Contains(msg, "media session not ready"),
		strings.Contains(msg, "media chk not alive"),
		strings.Contains(msg, "closed"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "LoginResponse"):
		// Drop warm after silent RDT/stream failure — next attempt needs a fresh bind.
		return false
	case strings.Contains(msg, "segment_not_found"),
		strings.Contains(msg, "filenotfound"),
		strings.Contains(msg, "playback_rejected"):
		// Index/seek answers were clear; session can stay warm for the next tap.
		return true
	default:
		return true
	}
}
