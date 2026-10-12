package domain

import (
	"fmt"
	"time"
)

// Device is a Xiaomi camera to watch.
type Device struct {
	DID    string `json:"did"`
	Model  string `json:"model"`
	Region string `json:"region"`
}

// Event is a cloud eventlist unit (Pet / PeopleMotion / …).
type Event struct {
	DID              string
	Model            string
	Region           string
	EventType        string
	FileID           string
	ImgStoreID       string
	CreateTimeMs     int64
	IsCloud          bool
	OnlyShowImgNoPlay bool
}

func (e Event) Key() string {
	if e.FileID != "" {
		return e.FileID
	}
	return fmt.Sprintf("%s|%d|%s", e.DID, e.CreateTimeMs, e.EventType)
}

// SessionUnix returns createTime as unix seconds.
func (e Event) SessionUnix() int64 {
	if e.CreateTimeMs > 1e12 {
		return e.CreateTimeMs / 1000
	}
	return e.CreateTimeMs
}

// DefaultPreRollSec seeks this many seconds before the event inside the
// selected TimeItem so keyframe sync does not drop the event itself.
const DefaultPreRollSec = 8

// MinuteSessionID is the SD-card minute unix used as MTP sessionid.
func (e Event) MinuteSessionID() int64 {
	sec := e.SessionUnix()
	return (sec / 60) * 60
}

// OffsetSec is seconds into the minute for MTP 0x10d.
func (e Event) OffsetSec() int {
	return int(e.SessionUnix() - e.MinuteSessionID())
}

// TokenBundle is a persisted Xiaomi Mi Home API session.
type TokenBundle struct {
	UserID       string    `json:"userId"`
	CUserID      string    `json:"cUserId"`
	PassToken    string    `json:"passToken,omitempty"`
	ServiceToken string    `json:"serviceToken"`
	Ssecurity    string    `json:"ssecurity"` // base64
	Cookies      string    `json:"cookies,omitempty"`
	SID          string    `json:"sid,omitempty"`
	DeviceID     string    `json:"deviceId,omitempty"`
	UpdatedAt    time.Time `json:"updatedAt,omitempty"`
}

// PlaybackRequest selects an SD segment for MTP download.
// Prefer EventUnix (cloud createTime) and leave SessionID=0 so the client
// resolves the real SD segment via RDT type-6 timeline index (TimeItem).
//
// Native sequence (Mi Home): RDT type-6 index → 0x103 → 0x10d → 0x10f →
// 0x10e filefound → video. Pre-roll seeks before EventUnix so decoder sync
// can discard mid-GOP bytes without losing the event.
type PlaybackRequest struct {
	SessionID    int64 // exact SD segment unix; 0 = resolve from EventUnix
	StartTime    int64
	EndTime      int64 // 0 = native open-ended seek (preferred)
	OffsetSec    int
	DurationSec  int // final clip length after trim (seconds)
	Speed        int
	EventUnix    int64 // event time (unix sec) used to resolve SessionID/OffsetSec
	ResolveSkew  int   // max seconds to walk back from EventUnix (default 120)
	PreRollSec   int   // seconds before event to include in the seek (default 8)
	TrimStartSec int   // filled by miss after resolution; recorder trims this many seconds
	CaptureSec   int   // filled by miss: stream read budget (pre-roll+duration+slack)
	// FullEvent asks miss to extend DurationSec to the end of the camera's
	// contiguous SD recording that starts at the event (cloud events carry no
	// end time), bounded by MaxDurationSec. DurationSec stays the floor.
	FullEvent      bool
	MaxDurationSec int
}

// ClipWindow is a user-chosen amount of context to include around an event
// moment, on top of the default clip length. The zero value means "use the
// recorder's configured default duration/pre-roll" — today's unchanged
// behavior, used by the auto-poll/notify path and the Telegram "Default"
// chooser option.
type ClipWindow struct {
	BeforeSec int // seconds of video before the event moment; 0 = recorder default
	AfterSec  int // seconds of video after the event moment; 0 = recorder default
}

// Clip is a saved local recording.
type Clip struct {
	Path      string
	EventKey  string
	Bytes     int64
	CreatedAt time.Time
}

// EventQuery bounds an eventlist poll.
type EventQuery struct {
	DID       string
	Model     string
	Region    string
	BeginMs   int64
	EndMs     int64
	Limit     int
	EventType string // "Default" for mixed gallery
}
