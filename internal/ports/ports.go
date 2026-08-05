package ports

import (
	"context"
	"io"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/mtp"
)

// AuthProvider manages Xiaomi account / API session tokens.
type AuthProvider interface {
	EnsureValid(ctx context.Context) (domain.TokenBundle, error)
	Login(ctx context.Context, user, pass string) (domain.TokenBundle, error)
	Refresh(ctx context.Context, t domain.TokenBundle) (domain.TokenBundle, error)
	LoadSession(ctx context.Context) (domain.TokenBundle, error)
	SaveSession(ctx context.Context, t domain.TokenBundle) error
	// Invalidate drops any cached in-memory session so the next EnsureValid
	// re-derives credentials from disk/pass_token/username instead of
	// returning the process's original in-memory snapshot forever (EnsureValid
	// has no TTL/expiry check of its own).
	Invalidate()
}

// CameraCloudAPI is the Xiaomi camera business HTTP API (RC4).
type CameraCloudAPI interface {
	EventList(ctx context.Context, q domain.EventQuery) ([]domain.Event, error)
	WakeUp(ctx context.Context, did, region string) error
}

// StreamCredentials are MTP dial inputs from miss_get_vendor.
type StreamCredentials struct {
	SSAddrs    []string
	AuthStr    string
	AuthToken  string
	UID        string
	SSVer      string
	CallerUUID string
	PublicKey  string // device hex
	Sign       string
	// App Curve25519 (miss shared) — kept for CS2 paths; MTP uses MTP* pair.
	ClientPublic  string
	ClientPrivate string
	// Native MTP CNT keypair (stable across vendor refreshes).
	MTPPublic  string
	MTPPrivate string
	LocalIP    string
	DID        string
	Model      string
}

// StreamSession opens a P2P connection (may be reused via orchestrator warm pool).
type StreamSession interface {
	Open(ctx context.Context, device domain.Device, tokens domain.TokenBundle) (P2PConn, error)
}

// P2PConn is an active MTP (or future vendor) session.
type P2PConn interface {
	// DownloadPlayback seeks SD playback. When req.SessionID==0, miss fills
	// SessionID/OffsetSec/TrimStartSec/CaptureSec from the RDT index.
	DownloadPlayback(ctx context.Context, req *domain.PlaybackRequest) (io.ReadCloser, error)
	// OpenLive streams live annex-B video (and keeps the camera in live mode).
	OpenLive(ctx context.Context) (io.ReadCloser, error)
	// Alive reports whether the transport is still usable for another seek.
	Alive() bool
	Close() error
}

// Recorder turns an event into a local clip file. win is the zero value for
// the auto-poll path (today's default duration/pre-roll, unchanged); a
// non-zero win widens the captured window around the event moment.
type Recorder interface {
	CaptureEvent(ctx context.Context, conn P2PConn, ev domain.Event, win domain.ClipWindow) (domain.Clip, error)
}

// Notifier delivers a clip (Telegram Bot API in v1).
type Notifier interface {
	NotifyEvent(ctx context.Context, ev domain.Event, clip domain.Clip, thumb []byte) error
}

// ClipRequester lists cloud events and downloads a clip on demand (bot + auto-poll).
type ClipRequester interface {
	ListEvents(ctx context.Context, device domain.Device, beginMs, endMs int64) ([]domain.Event, error)
	RequestClip(ctx context.Context, device domain.Device, ev domain.Event, win domain.ClipWindow) (domain.Clip, error)
}

// LiveController starts/stops camera → Telegram group voice-chat publish.
type LiveController interface {
	StartLive(ctx context.Context, device domain.Device) error
	StartLiveTest(ctx context.Context) error
	StopLive(ctx context.Context) error
	LiveActive() bool
}

// EventStore dedupes processed events.
type EventStore interface {
	Seen(ctx context.Context, key string) (bool, error)
	Mark(ctx context.Context, key string, meta domain.Event) error
}

// PickStore maps short Telegram callback ids to events / timeline sessions.
type PickStore interface {
	PutEvent(ctx context.Context, ev domain.Event, ttl time.Duration) (id string, err error)
	GetEvent(ctx context.Context, id string) (domain.Event, error)
	PutTimeline(ctx context.Context, sess TimelineSession, ttl time.Duration) (id string, err error)
	GetTimeline(ctx context.Context, id string) (TimelineSession, error)
}

// TimelineSession is browse state for /timeline pagination.
type TimelineSession struct {
	Device  domain.Device `json:"device"`
	BeginMs int64         `json:"beginMs"`
	EndMs   int64         `json:"endMs"`
}

// TimelineStore persists SD-card TimeItem index records per device across
// fetches, so coverage accumulates over time instead of being discarded when
// each connection closes. A single live fetch only ever samples a small
// fraction of the camera's full index (confirmed both for camwatch and for
// the real Mi Home app via pcap/frida analysis, 2026-08-02) — this is what
// lets repeated fetches, even ones that individually miss the target event,
// still add up to usable coverage over time.
type TimelineStore interface {
	MergeSegments(ctx context.Context, did string, segs []mtp.TimelineSeg) error
	Segments(ctx context.Context, did string) ([]mtp.TimelineSeg, error)
}

// ClipStore manages clip file paths.
type ClipStore interface {
	PathFor(ev domain.Event) string
	EnsureDir() error
}

// LivePublisher publishes AV into a Telegram group voice chat (ntgcalls/PyTgCalls).
type LivePublisher interface {
	// StartCall joins/creates the group VC and plays sourceURL (http(s) or file).
	StartCall(ctx context.Context, chatID string, sourceURL string) error
	// StartTest plays a built-in sample MP4 into the VC (Telegram-side spike).
	StartTest(ctx context.Context, chatID string) error
	Stop(ctx context.Context) error
	Close() error
}
