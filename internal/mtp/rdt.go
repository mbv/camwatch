package mtp

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	chkRDTFlag = 0xd800 // native CHK field for RDT (pcap: 0xd820 for 24 B plain)

	RDTTypeTimeline = 6 // SD TimeItem index: (start_unix, duration_sec) pairs

	// rdtHeaderSearchCap bounds how many raw pre-header bytes FetchTimelineIndex
	// accumulates while looking for the 12-byte TLV header before giving up and
	// falling back to the implicit raw-pairs heuristic. The real type-6 header
	// is followed by a ~2 KB first body chunk in native captures
	// (x/frida-mtp-capture.log "type6-start" bodyGot=2032); 4096 gives that
	// margin without growing unbounded on firmware that never sends a header.
	rdtHeaderSearchCap = 4096

	// rdtRawHardCap bounds raw growth when extractTimelineBytes has never
	// found a clean aligned run past rdtHeaderSearchCap. There is no reliable
	// way to guess the correct byte phase from content alone once the known-
	// good offsets fail (see handle()'s doc comment on this), so past this
	// cap the fetch fails outright instead of accumulating unbounded memory
	// or guessing.
	rdtRawHardCap = 8 * rdtHeaderSearchCap

	// rdtHeaderMinPlausibleSize is the minimum declared body Size accepted
	// when scanning the growing raw accumulation buffer for an explicit TLV
	// header (see findTimelineHeader's doc comment). Real captures declare
	// tens of KB (x/rdt-type6.bin: 83464 B / 10433 records); 2048 (256
	// records) comfortably clears any genuine response while sharply cutting
	// the false-positive rate of a byte-by-byte scan across a large buffer.
	rdtHeaderMinPlausibleSize = 2048
)

// RDTHeader is the 12-byte LE TLV prefix on channel-3 RDT payloads.
type RDTHeader struct {
	Type   uint32
	Size   uint32 // body length in bytes
	Status uint32
}

// TimelineSeg is one SD recording segment from an RDT type-6 body.
type TimelineSeg struct {
	StartUnix   int64
	DurationSec int
}

// EmptyRDTRequest builds the 24-byte padded empty RDT request (native miss_rdt_send).
func EmptyRDTRequest(typ uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:4], typ)
	return b
}

// RDTTypeDayQuery is an unrelated day-index-query TLV (native: type=11,
// `{"mac":"...","time":"YYYYMMDD"}`) — see rdtKeepalivePing's doc comment for
// why FetchTimelineIndex sends this repeatedly during a type-6 fetch despite
// it having nothing to do with the timeline index.
const RDTTypeDayQuery = 11

// rdtKeepalivePing builds a type=11 RDT TLV shaped like native's repeated
// "day query" (frida-mtp-capture.log, 2026-08-02: `{"mac":"F1F2F3F4F5F6",
// "time":"20260802"}`, sent every ~0.5-1.4s on channel 3 throughout a type-6
// fetch). A live pcap/frida comparison (mtp-native.pcap) proved native sends
// the type=6 request exactly ONCE and then keeps sending these instead — and
// that its RDT-tagged (0x58) packet count keeps climbing the entire time,
// unlike ours, which goes flat at ~80 packets partway through every fetch
// while unrelated video keeps flowing on the same session. That is only
// explained by the camera's type-6 dump needing periodic channel-3 activity
// to keep going (an idle/keepalive gate in the firmware, independent of what
// the activity means) — our own code sent the type=6 request once (plus one
// silence-triggered resend) and then only ever ACKed, never re-poked the
// channel. The exact mac value is very likely irrelevant to the firmware
// (this is a "day index" query for an unrelated feature per prior debugging
// notes) — what matters, per this hypothesis, is that channel 3 sees
// something every second or so.
func rdtKeepalivePing(now time.Time) []byte {
	body := fmt.Sprintf(`{"mac":"000000000000","time":"%s"}`, now.Format("20060102"))
	b := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint32(b[0:4], RDTTypeDayQuery)
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(body)))
	copy(b[8:], body)
	return b
}

func parseRDTHeader(b []byte) (RDTHeader, bool) {
	if len(b) < 12 {
		return RDTHeader{}, false
	}
	h := RDTHeader{
		Type:   binary.LittleEndian.Uint32(b[0:4]),
		Size:   binary.LittleEndian.Uint32(b[4:8]),
		Status: binary.LittleEndian.Uint32(b[8:12]),
	}
	if h.Type == 0 || h.Type > 64 || h.Size > 2_000_000 || h.Status > 255 {
		return RDTHeader{}, false
	}
	return h, true
}

func looksLikeRDTHeader(frame []byte) bool {
	_, ok := parseRDTHeader(frame)
	return ok
}

func isMissVideoFrame(frame []byte) bool {
	if len(frame) < 32 {
		return false
	}
	codec := binary.LittleEndian.Uint32(frame[4:8])
	switch codec {
	case 4, 5, 40: // H264 / H265 / observed media
		return true
	default:
		return false
	}
}

// leadingCleanRunRecords returns how many complete, valid TimeItem records
// decode contiguously from the start of b, stopping at the first record that
// fails ParseTimelineBodyCounted's own per-record checks (start range,
// duration ceiling). Used instead of an aggregate clean-ratio gate
// (looksLikeTimelineBody) when selecting a byte phase for a still-growing
// accumulation buffer: proven live, corruption (real network packet loss on
// the P2P relay, not a fixed decode bug — its position and content vary
// between otherwise-identical fetches of the same data) can appear anywhere
// after a genuinely clean prefix. An aggregate ratio over the WHOLE buffer
// can reject that buffer outright once enough garbage accumulates past the
// prefix, discarding clean data we already have and could have used —
// FinalizeTimelineBody's own per-record filtering only ever gets a chance to
// run on data that clears this gate first. Extracting just the leading clean
// run (see extractTimelineBytes) means a clean prefix is usable even when
// most of what came after it in the same fetch is garbage.
func leadingCleanRunRecords(b []byte) int {
	n := len(b) - len(b)%8
	count := 0
	for i := 0; i+8 <= n; i += 8 {
		start := binary.LittleEndian.Uint32(b[i : i+4])
		dur := binary.LittleEndian.Uint32(b[i+4 : i+8])
		if start == 0 {
			break
		}
		if dur == 0 {
			dur = 60
		}
		if start < 1_500_000_000 || start > 2_200_000_000 || dur > 3600 {
			break
		}
		count++
	}
	return count
}

// looksLikeTimelineBody reports whether b is mostly valid (start,dur) pairs.
// Native type-6 often arrives as raw pairs on 0x58xx without a TLV header.
func looksLikeTimelineBody(b []byte) bool {
	n := len(b) - len(b)%8
	if n < 8 {
		return false
	}
	segs, dropped := ParseTimelineBodyCounted(b[:n])
	if len(segs) == 0 {
		return false
	}
	if len(segs) == 1 {
		return dropped == 0
	}
	// Allow a little junk; reject mostly-invalid buffers. Tightened from a
	// ~33% tolerance (dropped*2<=len(segs)) to 20% (dropped*4<=len(segs)) —
	// the old threshold was loose enough to accept misaligned scans that
	// manufacture plausible-looking but fictional segments (see the "no
	// 0x10e" root-cause investigation: a minute-aligned sessionid with no
	// real SD segment behind it).
	return dropped*4 <= len(segs)
}

// ParseTimelineBody parses type-6 body as LE (start_unix, duration_sec) pairs.
// Drops absurd values (misaligned junk from non-RDT frames leaking into the body).
// Returns (segments, droppedInvalid).
func ParseTimelineBody(body []byte) []TimelineSeg {
	segs, _ := ParseTimelineBodyCounted(body)
	return segs
}

// ParseTimelineBodyCounted is like ParseTimelineBody but reports how many
// 8-byte records were rejected as out-of-range.
func ParseTimelineBodyCounted(body []byte) (segs []TimelineSeg, dropped int) {
	n := len(body) / 8
	segs = make([]TimelineSeg, 0, n)
	for i := 0; i+8 <= len(body); i += 8 {
		start := binary.LittleEndian.Uint32(body[i : i+4])
		dur := binary.LittleEndian.Uint32(body[i+4 : i+8])
		if start == 0 {
			dropped++
			continue
		}
		if dur == 0 {
			dur = 60
		}
		// SD sessionids are unix seconds; durations are minute-scale. Every
		// real duration observed across live captures and x/rdt-type6.bin is
		// <=316s; 3600 (1h) gives ample margin while decisively rejecting a
		// wrong byte phase. This ceiling matters more than it looks: a wrong
		// phase can pass the *count*-based quality gate just as cleanly as
		// the true one (proven live — an off-by-one-byte misread of this
		// exact file decoded to a CONSTANT 15466s/~4.3h duration for nearly
		// every record, 10433/10433 kept, indistinguishable from the correct
		// phase by count alone). The old 24h ceiling let that through; this
		// catches it at the per-record level instead of relying on
		// downstream ambiguity detection to notice.
		if start < 1_500_000_000 || start > 2_200_000_000 || dur > 3600 {
			dropped++
			continue
		}
		segs = append(segs, TimelineSeg{StartUnix: int64(start), DurationSec: int(dur)})
	}
	return segs, dropped
}

// WriteRDT sends a raw RDT TLV on media CHK~ (channel-3 / no 0x1001 prefix).
func (c *Conn) WriteRDT(payload []byte) error {
	if err := c.WaitMediaReady(45 * time.Second); err != nil {
		return err
	}
	ms := c.mediaSess.Load()
	if ms == nil {
		return fmt.Errorf("mtp: no media session")
	}
	return ms.sendRDT(payload)
}

// RDTTaggedRXCount returns how many CHK frames the media session has ever
// classified as RDT-tagged (0xd8/0x58, or an accepted 0x50), independent of
// SetRDTListen. Used to tell "the camera never sent any type-6 traffic" apart
// from "it sent some and we lost/misrouted it" when a fetch comes back empty.
func (c *Conn) RDTTaggedRXCount() uint64 {
	ms := c.mediaSess.Load()
	if ms == nil {
		return 0
	}
	return ms.rdtTaggedRX.Load()
}

// ForeignSessionRXCount returns how many KCP~ packets have been dropped by
// sessionMatches — packets from an extra media endpoint's session that,
// before this filter existed, got decrypted with our shareKey and produced
// effectively-random noise. A nonzero, growing count during a fetch that
// still shows corruption confirms foreign-session packets are still arriving
// (expected on some networks) but are now being correctly excluded rather
// than corrupting the accumulation.
func (c *Conn) ForeignSessionRXCount() uint64 {
	ms := c.mediaSess.Load()
	if ms == nil {
		return 0
	}
	return ms.foreignSessionRX.Load()
}

// RDTRawRXCount returns how many raw UDP datagrams loop() has seen while
// rdtListen was set, regardless of session/magic/type. Comparing this against
// RDTTaggedRXCount() during a stalled fetch tells apart "the camera stopped
// sending anything at all" from "something upstream of CHK classification
// (foreign-session filter, KCP parse, magic mismatch) is silently dropping
// packets that did arrive".
func (c *Conn) RDTRawRXCount() uint64 {
	ms := c.mediaSess.Load()
	if ms == nil {
		return 0
	}
	return ms.rdtRawRX.Load()
}

// FlushPendingACK sends whatever ACKs ackPUSH has batched but not yet flushed
// — see mediaSession.flushPendingACK's doc comment for why a timer-driven
// flush is needed alongside the size/time thresholds in ackPUSH itself.
func (c *Conn) FlushPendingACK() {
	if ms := c.mediaSess.Load(); ms != nil {
		ms.flushPendingACK()
	}
}

// SetRDTListen routes non-video CHK frames to the RDT queue while true.
func (c *Conn) SetRDTListen(v bool) {
	ms := c.mediaSess.Load()
	if ms == nil {
		return
	}
	ms.rdtListen.Store(v)
	if v && c.channels != nil && c.channels.rdt != nil {
		_ = c.channels.rdt.Drain()
	}
}

// ReadRDT waits for one reassembled RDT frame (header or body chunk).
func (c *Conn) ReadRDT(deadline time.Time) ([]byte, error) {
	if c.channels == nil || c.channels.rdt == nil {
		return nil, fmt.Errorf("mtp: no rdt channel")
	}
	return c.channels.rdt.PopWait(deadline)
}

// FetchTimelineIndex sends RDT type-6 and reassembles the SD segment index.
// eventUnix, when >0, lets implicit mode keep reading until that instant is
// covered (or the full index arrives).
//
// Native wire often delivers raw (start,dur) pairs on 0x58xx without a TLV header.
func (c *Conn) FetchTimelineIndex(timeout time.Duration, eventUnix int64) ([]TimelineSeg, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c.SetRDTListen(true)
	defer c.SetRDTListen(false)

	rdtTaggedAtStart := c.RDTTaggedRXCount()
	foreignAtStart := c.ForeignSessionRXCount()
	rawAtStart := c.RDTRawRXCount()
	req := EmptyRDTRequest(RDTTypeTimeline)
	if err := c.WriteRDT(req); err != nil {
		return nil, err
	}
	Logp("mtp: TX RDT type=%d (timeline index)\n", RDTTypeTimeline)
	lastTX := time.Now()
	lastPing := lastTX

	deadline := time.Now().Add(timeout)
	var (
		need     int
		got      int
		body     []byte
		header   bool
		implicit bool
		lastRX   time.Time
		frames   int
		statusErr error
		raw      []byte // accumulated pre-header bytes; see handle() below
		carry    []byte // unaligned tail bytes held over between implicit-mode frames; see handle() below
	)
	coversEvent := func() bool {
		if eventUnix <= 0 || len(body) < 16 {
			return false
		}
		n := len(body) - len(body)%8
		segs := ParseTimelineBody(body[:n])
		if _, _, ok := LookupTimeline(segs, eventUnix); ok {
			return true
		}
		_, _, ok := LookupTimelineNear(segs, eventUnix, 180)
		return ok
	}
	finishImplicit := func() bool {
		if !implicit || len(body) < 16 {
			return false
		}
		n := len(body) / 8
		var idle time.Duration
		if !lastRX.IsZero() {
			idle = time.Since(lastRX)
		}
		if n >= 12000 {
			return true
		}
		if coversEvent() && idle >= 800*time.Millisecond {
			return true
		}
		if n >= 8000 && idle >= 2*time.Second {
			return true
		}
		if n >= 3000 && idle >= 3*time.Second {
			return true
		}
		if n >= 1000 && time.Until(deadline) < 1500*time.Millisecond {
			return true
		}
		return false
	}

	handle := func(frame []byte) (done bool) {
		frames++
		lastRX = time.Now()
		if len(frame) >= 8 && binary.BigEndian.Uint32(frame[0:4]) == 0x1001 {
			return false
		}
		if !header {
			// The 12-byte TLV header does not always land in the first CHK
			// fragment — RDT fragments are pushed to the queue individually
			// (unlike video, they skip frag-based reassembly, see
			// media_kcp.go handleCHK case 0xd8/0x58), so a short first chunk
			// (observed as small as 16 B on the wire) can be pure header, pure
			// body, or a split of the two. Searching only `frame` in isolation
			// (as this used to do) means a header split across a chunk
			// boundary — or simply not present in chunk 1 — is never found,
			// and the code falls into implicit mode from a single unlucky
			// chunk for the rest of the session. Accumulate raw bytes and
			// search the whole prefix instead.
			prevLen := len(raw)
			raw = append(raw, frame...)
			if prevLen/16384 != len(raw)/16384 {
				Logp("mtp: rdt raw growth: %d -> %d B (frame=%d B, frames=%d, cap=%d)\n",
					prevLen, len(raw), len(frame), frames, rdtRawHardCap)
			}
			if off := findTimelineHeader(raw, rdtHeaderMinPlausibleSize); off >= 0 {
				h, ok := parseRDTHeader(raw[off:])
				if ok && h.Type == RDTTypeTimeline {
					if h.Status != 0 {
						statusErr = fmt.Errorf("mtp: rdt type6 status=%d", h.Status)
						return true
					}
					need = int(h.Size)
					chunk := raw[off+12:]
					if len(chunk) > need {
						chunk = chunk[:need]
					}
					body = append([]byte(nil), chunk...)
					got = len(body)
					header = true
					raw = nil
					Logp("mtp: RX RDT type=6 size=%d first=%d\n", need, got)
					return got >= need
				}
			}
			// No explicit header found yet. Give it a bounded window to show
			// up (rdtHeaderSearchCap) before falling back to the implicit
			// raw-pairs heuristic — committing to implicit too early is what
			// let a header arriving in a later, larger chunk get missed
			// forever.
			if len(raw) < rdtHeaderSearchCap {
				return false
			}
			if chunk := extractTimelineBytes(raw); len(chunk) >= 8 {
				searched := len(raw)
				body = append(body, chunk...)
				got = len(body)
				header = true
				implicit = true
				raw = nil
				Logp("mtp: RX RDT TimeItem stream (no TLV header) first=%d B (after %d B search)\n", got, searched)
				return finishImplicit()
			}
			// extractTimelineBytes tried the known-good offsets (0, +32,
			// 4-byte steps to 64) and found nothing clean. A prior version of
			// this code force-accepted offset 0 as a last resort ("the range
			// gate will filter junk") — that is unsound: adjacent byte phases
			// of a real, slowly-varying TimeItem stream can *also* pass the
			// range gate and even look chronologically ordered by
			// coincidence (proven live: a fetch that kept only 2/~1000
			// records at a wrong-but-plausible phase). There is no reliable
			// way to disambiguate two plausible phases from content alone, so
			// don't guess — keep accumulating and retrying extractTimelineBytes
			// as raw grows, and fail the whole fetch outright once
			// rdtRawHardCap is reached without ever finding a clean run.
			if len(raw) >= rdtRawHardCap {
				Logp("mtp: rdt raw hard cap hit: len(raw)=%d cap=%d frames=%d\n", len(raw), rdtRawHardCap, frames)
				Logp("mtp: rdt type6 raw hex dump (first 128 B of %d): %x\n", len(raw), raw[:min(128, len(raw))])
				Logp("mtp: rdt type6 raw hex dump (last 128 B of %d): %x\n", len(raw), raw[max(0, len(raw)-128):])
				statusErr = fmt.Errorf("mtp: rdt type6: no aligned TimeItem body found in %d B (no header, no clean phase)", len(raw))
				return true
			}
			return false
		}
		if implicit {
			// Once the bootstrap above has locked onto the right byte phase,
			// continuation frames must be treated as a continuous stream, not
			// independently re-searched from each frame's own byte 0.
			// Re-running extractTimelineBytes(frame) per frame (the old
			// behavior here) assumed every wire frame happens to start on an
			// 8-byte TimeItem boundary — but frame boundaries come from KCP/
			// CHK fragmentation, which has nothing to do with our 8-byte
			// record size. A record split across two frames failed that
			// frame's local clean-run search and was silently dropped,
			// regardless of how much more data kept arriving — proven live:
			// rdtTaggedRX climbing from 80 to 337 after adding the keepalive
			// ping (see rdtKeepalivePing) changed the extracted segment count
			// by nothing (313 either way). Carry the unaligned tail of each
			// frame into the next instead, so a record split at a frame
			// boundary reassembles correctly.
			//
			// One more wrinkle the live high-drop hex dump exposed: sending
			// rdtKeepalivePing (type=11) makes the camera send back type=11
			// RESPONSES on the exact same wire tag (0x58/0xd8) genuine type-6
			// continuation uses — our CHK-level classification only checks
			// that tag, not the TLV type inside the payload, so these were
			// getting concatenated straight into the timeline body (a real
			// RDT header, just for the wrong type: type=11 size=172 status=0,
			// not type=6). looksLikeRDTHeader already knows how to recognize
			// a fresh TLV header; reject any frame that looks like one for a
			// type other than the timeline before it ever reaches carry.
			if h, ok := parseRDTHeader(frame); ok && h.Type != RDTTypeTimeline {
				return false
			}
			oldCarryLen := len(carry)
			combined := append(carry, frame...)
			n := len(combined) - len(combined)%8
			if n < 8 {
				carry = combined
				return false
			}
			aligned, tail := combined[:n], combined[n:]
			carry = append([]byte(nil), tail...)
			segs, dropped := ParseTimelineBodyCounted(aligned)
			if len(segs) == 0 {
				return false
			}
			if dropped > 0 {
				Logp("mtp: RDT implicit continuation dropped %d/%d records (kept %d)\n",
					dropped, len(aligned)/8, len(segs))
				if dropped*2 >= len(aligned)/8 {
					Logp("mtp: RDT implicit continuation high-drop hex: carry_len=%d frame_len=%d combined_hex=%x\n",
						oldCarryLen, len(frame), combined[:min(96, len(combined))])
				}
			}
			body = append(body, aligned...)
			got = len(body)
			return finishImplicit()
		}
		remain := need - got
		if remain <= 0 {
			return true
		}
		if len(frame) > remain {
			frame = frame[:remain]
		}
		body = append(body, frame...)
		got = len(body)
		return got >= need
	}

	for time.Now().Before(deadline) {
		if statusErr != nil {
			return nil, statusErr
		}
		if finishImplicit() || (header && !implicit && got >= need && need > 0) {
			break
		}
		// See rdtKeepalivePing's doc comment: native keeps sending this
		// unrelated TLV on channel 3 every ~0.5-1.4s for the entire fetch,
		// and its RDT-tagged RX never goes flat the way ours does without
		// it. Runs regardless of header/implicit state, not just pre-header
		// like the type-6 resend below.
		if now := time.Now(); now.Sub(lastPing) >= time.Second {
			if werr := c.WriteRDT(rdtKeepalivePing(now)); werr == nil {
				lastPing = now
			}
		}
		// ackPUSH batches ACKs during an RDT fetch (see its doc comment) but
		// only checks its size/time thresholds when a new PUSH arrives — flush
		// here on a timer too, so a partial batch never sits unacked through a
		// lull in arrivals.
		c.FlushPendingACK()
		popDead := time.Now().Add(300 * time.Millisecond)
		if popDead.After(deadline) {
			popDead = deadline
		}
		raw0, err := c.ReadRDT(popDead)
		if err != nil {
			if e := c.Error(); e != nil {
				return nil, e
			}
			if finishImplicit() {
				break
			}
			if !header && time.Since(lastTX) >= 8*time.Second && time.Now().Before(deadline) {
				if werr := c.WriteRDT(req); werr == nil {
					Logp("mtp: TX RDT type=%d (timeline index resend)\n", RDTTypeTimeline)
					lastTX = time.Now()
				}
				continue
			}
			if time.Now().Before(deadline) {
				continue
			}
			if implicit && len(body) >= 16 {
				break
			}
			Logp("mtp: rdt type6 raw hex dump (first 128 B of %d): %x\n", len(raw), raw[:min(128, len(raw))])
			return nil, fmt.Errorf("mtp: rdt type6: %w (rdtTaggedRX +%d, foreignSessionRX +%d, rdtRawRX +%d since request, handle()-loop saw %d frames, raw accumulated=%d B)",
				err, c.RDTTaggedRXCount()-rdtTaggedAtStart, c.ForeignSessionRXCount()-foreignAtStart, c.RDTRawRXCount()-rawAtStart, frames, len(raw))
		}
		// Collect this burst (the item just popped plus everything already
		// queued) and sort by CHK sequence number before handing frames to
		// handle() — UDP doesn't guarantee delivery order, and handleCHK
		// pushes packets to this queue as they physically arrive. Every one
		// of handle()'s accumulation modes (raw, implicit body, explicit-
		// header body) just concatenates in receive order; without sorting
		// first, ordinary network reordering (not even true packet loss)
		// silently corrupts the byte stream. Proven live: a KCP receive
		// watermark frozen at an unresolved gap while hundreds of RDT-tagged
		// frames kept arriving and accumulating — those frames were being
		// appended past the hole, not in their true sequence.
		type rdtItem struct {
			seq     uint32
			payload []byte
		}
		burst := make([]rdtItem, 0, 8)
		seq0, payload0 := decodeRDTQueueItem(raw0)
		burst = append(burst, rdtItem{seq0, payload0})
		for {
			more, ok := c.channels.rdt.Pop()
			if !ok {
				break
			}
			s, p := decodeRDTQueueItem(more)
			burst = append(burst, rdtItem{s, p})
		}
		sort.Slice(burst, func(i, j int) bool { return burst[i].seq < burst[j].seq })
		stop := false
		for _, it := range burst {
			if handle(it.payload) {
				stop = true
				break
			}
		}
		if stop {
			break
		}
		if statusErr != nil {
			return nil, statusErr
		}
		if finishImplicit() || (header && !implicit && got >= need && need > 0) {
			break
		}
	}

	if !header {
		// frames = how many items this loop actually popped off channels.rdt
		// and ran through handle(). Comparing it to rdtTaggedRX pinpoints the
		// failure stage: frames==0 with rdtTaggedRX>0 means CHK-classified
		// frames never reached (or were never popped from) the RDT queue;
		// frames>0 but still !header means they arrived but never accumulated
		// into anything findTimelineHeader/extractTimelineBytes accepts.
		Logp("mtp: rdt type6 raw hex dump (first 128 B of %d): %x\n", len(raw), raw[:min(128, len(raw))])
		return nil, fmt.Errorf("mtp: rdt type6: no header/body within %s (rdtTaggedRX +%d, foreignSessionRX +%d, rdtRawRX +%d since request, handle()-loop saw %d frames, raw accumulated=%d B)",
			timeout, c.RDTTaggedRXCount()-rdtTaggedAtStart, c.ForeignSessionRXCount()-foreignAtStart, c.RDTRawRXCount()-rawAtStart, frames, len(raw))
	}
	if implicit {
		n := len(body) - len(body)%8
		if n < 16 {
			return nil, fmt.Errorf("mtp: rdt type6: implicit body too short (%d B)", len(body))
		}
		segs, err := FinalizeTimelineBody(n, body[:n])
		if err != nil {
			return nil, err
		}
		var minS, maxS int64
		if len(segs) > 0 {
			minS, maxS = segs[0].StartUnix, segs[0].StartUnix
			for _, s := range segs {
				if s.StartUnix < minS {
					minS = s.StartUnix
				}
				if s.StartUnix > maxS {
					maxS = s.StartUnix
				}
			}
		}
		Logp("mtp: RDT timeline index: %d segments (%d B, %d frames, implicit) range=%d..%d coverEvent=%v (rdtTaggedRX +%d, foreignSessionRX +%d, rdtRawRX +%d)\n",
			len(segs), n, frames, minS, maxS, coversEvent(),
			c.RDTTaggedRXCount()-rdtTaggedAtStart, c.ForeignSessionRXCount()-foreignAtStart, c.RDTRawRXCount()-rawAtStart)
		Logp("mtp: RDT duration histogram (implicit): %s\n", durationHistogram(segs))
		return segs, nil
	}
	if got < need {
		return nil, fmt.Errorf("mtp: rdt type6: got %d/%d body bytes", got, need)
	}
	segs, err := FinalizeTimelineBody(need, body[:need])
	if err != nil {
		return nil, err
	}
	Logp("mtp: RDT timeline index: %d segments (%d B, %d frames) (rdtTaggedRX +%d, foreignSessionRX +%d, rdtRawRX +%d)\n",
		len(segs), need, frames, c.RDTTaggedRXCount()-rdtTaggedAtStart, c.ForeignSessionRXCount()-foreignAtStart, c.RDTRawRXCount()-rawAtStart)
	Logp("mtp: RDT duration histogram: %s\n", durationHistogram(segs))
	return segs, nil
}

// durationHistogram summarizes segment durations for diagnosing a misparsed
// index — real captures (x/rdt-type6.bin) are overwhelmingly dur=60 with a
// handful of longer gap-spanning entries; a body dominated by unusual
// durations (or minute-aligned starts) is a strong signal of a body-offset
// bug rather than a genuine SD gap.
func durationHistogram(segs []TimelineSeg) string {
	counts := map[int]int{}
	minuteAligned := 0
	for _, s := range segs {
		counts[s.DurationSec]++
		if s.StartUnix%60 == 0 {
			minuteAligned++
		}
	}
	type kv struct {
		dur, n int
	}
	kvs := make([]kv, 0, len(counts))
	for d, n := range counts {
		kvs = append(kvs, kv{d, n})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].n > kvs[j].n })
	if len(kvs) > 6 {
		kvs = kvs[:6]
	}
	parts := make([]string, 0, len(kvs))
	for _, e := range kvs {
		parts = append(parts, fmt.Sprintf("%ds:%d", e.dur, e.n))
	}
	return fmt.Sprintf("top=[%s] minuteAlignedStarts=%d/%d", strings.Join(parts, " "), minuteAligned, len(segs))
}

// findTimelineHeader scans frame for the 12-byte TLV header. minSize raises
// the bar above parseRDTHeader's generic sanity check (Size>=16, i.e. just 2
// records) — that floor is fine for validating a header known to be at
// offset 0 of a single small CHK fragment, but far too permissive when
// scanning a large, arbitrarily-growing accumulated buffer byte-by-byte: a
// real type-6 response is always tens of KB (thousands of TimeItems), so a
// "header" whose declared Size is small is almost certainly a coincidental
// false-positive match on ordinary TimeItem content (duration fields are
// small integers with trailing zero bytes — e.g. dur=60 LE is 3C 00 00 00 —
// which is exactly the shape a Status==0 coincidence needs). A locked-on
// false header blocks the raw-growth hard-cap check from ever running (see
// handle()'s doc comment) and stalls the whole fetch waiting for a `need`
// real data will never satisfy — proven live: raw grew to 188 KB, far past
// rdtRawHardCap, because this scan kept re-finding the same false header.
func findTimelineHeader(frame []byte, minSize uint32) int {
	for i := 0; i+12 <= len(frame); i++ {
		h, ok := parseRDTHeader(frame[i:])
		if ok && h.Type == RDTTypeTimeline && h.Status == 0 && h.Size >= minSize && h.Size%8 == 0 {
			return i
		}
	}
	return -1
}

// extractTimelineBytes finds the byte phase (of the 8 possible for an 8-byte
// record, tried both from frame's start and from frame[32:] — native
// sometimes prefixes body chunks with a 32-byte miss media header) whose
// data decodes as the STRICTLY LONGEST contiguous run of valid TimeItem
// records, and returns just that leading run — not the whole candidate
// slice truncated to whatever aggregate ratio passed.
//
// This replaced an aggregate-ratio design (looksLikeTimelineBody over the
// whole candidate) that rejected an entire fetch's accumulated buffer once
// corruption appeared anywhere past a genuinely clean prefix — proven live:
// the same target repeatedly produced an identical clean prefix (same real
// segments, unchanged seconds apart) but the point and content of corruption
// after it varied between attempts, consistent with real, variable network
// loss on the P2P relay rather than a fixed decode bug. Discarding a clean
// prefix just because garbage came later in the SAME accumulation wasted
// data FinalizeTimelineBody's own per-record filtering would have happily
// kept, if only this gate had let the fetch commit at all.
//
// Only accepts a phase when its leading run is the unique strict maximum
// among all candidates (see leadingCleanRunRecords) and at least
// minLeadingRecords long — a short coincidental match on noise, or a tie
// between two phases, is refused rather than guessed (see this file's
// history for why a scored "pick the best of several plausible phases"
// approach was tried and reverted: adjacent phases of real, slowly-varying
// TimeItem data can tie by coincidence, and guessing between them risks the
// same "no 0x10e" failure class this whole file exists to fix).
func extractTimelineBytes(frame []byte) []byte {
	const minLeadingRecords = 2
	candidates := []int{0, 1, 2, 3, 4, 5, 6, 7}
	if len(frame) > 39 {
		candidates = append(candidates, 32, 33, 34, 35, 36, 37, 38, 39)
	}
	bestOff, bestCount := -1, 0
	ambiguous := false
	for _, off := range candidates {
		if off+8 > len(frame) {
			continue
		}
		count := leadingCleanRunRecords(frame[off:])
		switch {
		case count > bestCount:
			bestOff, bestCount, ambiguous = off, count, false
		case count == bestCount && count > 0:
			ambiguous = true
		}
	}
	if ambiguous || bestOff < 0 || bestCount < minLeadingRecords {
		return nil
	}
	return frame[bestOff : bestOff+bestCount*8]
}


// FinalizeTimelineBody validates a reassembled type-6 body and parses TimeItems.
// Declared size must be a multiple of 8; out-of-range records are dropped.
func FinalizeTimelineBody(need int, body []byte) ([]TimelineSeg, error) {
	if need <= 0 || len(body) < need {
		return nil, fmt.Errorf("mtp: rdt type6: incomplete body %d/%d", len(body), need)
	}
	if need%8 != 0 {
		return nil, fmt.Errorf("mtp: rdt type6: body size %d not aligned to 8-byte TimeItems", need)
	}
	segs, dropped := ParseTimelineBodyCounted(body[:need])
	if dropped > 0 {
		Logp("mtp: RDT timeline dropped %d invalid records (kept %d)\n", dropped, len(segs))
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("mtp: rdt type6: no valid TimeItems in %d B body", need)
	}
	return segs, nil
}

// LookupTimeline finds the segment covering eventUnix (start <= event < start+dur).
// The RDT index often lists overlapping spans (e.g. dur=316 covering the same
// wall-clock as several dur≈60 playable minutes). Prefer the covering entry
// whose duration is closest to 60s — that matches native 0x10e duration and
// avoids seeking a non-playable span.
func LookupTimeline(segs []TimelineSeg, eventUnix int64) (TimelineSeg, int, bool) {
	bestIdx := -1
	bestScore := int(^uint(0) >> 1) // max int
	for i, s := range segs {
		end := s.StartUnix + int64(s.DurationSec)
		if eventUnix < s.StartUnix || eventUnix >= end {
			continue
		}
		score := absInt(s.DurationSec - 60)
		// Prefer shorter spans on a tie (tighter match to a single SD minute).
		if score < bestScore || (score == bestScore && bestIdx >= 0 && s.DurationSec < segs[bestIdx].DurationSec) {
			bestScore = score
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		return TimelineSeg{}, 0, false
	}
	s := segs[bestIdx]
	return s, int(eventUnix - s.StartUnix), true
}

// CoveringSegments returns every TimeItem with start <= event < start+dur.
func CoveringSegments(segs []TimelineSeg, eventUnix int64) []TimelineSeg {
	var out []TimelineSeg
	for _, s := range segs {
		if s.DurationSec <= 0 {
			continue
		}
		end := s.StartUnix + int64(s.DurationSec)
		if eventUnix >= s.StartUnix && eventUnix < end {
			out = append(out, s)
		}
	}
	return out
}

// PrecedingSegment finds the segment ending at or within tolSec before
// startUnix — used to reach further back than one segment for a user-chosen
// pre-roll, one hop at a time (see miss.PlanPaddedSeek). Real SD recordings
// are event-triggered, so a "previous" segment can have a real wall-clock gap
// before startUnix; tolSec gates how much gap counts as still-contiguous
// rather than silently splicing across a real recording gap. Among segments
// ending in that window, prefer the one ending latest (most contiguous),
// tie-broken by duration closest to 60s to match LookupTimeline's convention.
func PrecedingSegment(segs []TimelineSeg, startUnix int64, tolSec int) (TimelineSeg, bool) {
	if tolSec < 0 {
		tolSec = 0
	}
	bestIdx := -1
	var bestEnd int64
	bestScore := int(^uint(0) >> 1)
	for i, s := range segs {
		if s.DurationSec <= 0 {
			continue
		}
		end := s.StartUnix + int64(s.DurationSec)
		gap := startUnix - end
		if gap < 0 || gap > int64(tolSec) {
			continue
		}
		score := absInt(s.DurationSec - 60)
		if end > bestEnd || (end == bestEnd && score < bestScore) {
			bestIdx, bestEnd, bestScore = i, end, score
		}
	}
	if bestIdx < 0 {
		return TimelineSeg{}, false
	}
	return segs[bestIdx], true
}

// LookupTimelineNear finds a segment when exact cover fails (SD index lag).
// Accepts a prior segment with start <= event and event within
// start+duration+skewSec (or within skewSec past the published end).
// Among candidates, prefer duration closest to 60s, then shorter spans.
func LookupTimelineNear(segs []TimelineSeg, eventUnix int64, skewSec int) (TimelineSeg, int, bool) {
	if skewSec <= 0 {
		skewSec = 120
	}
	if seg, off, ok := LookupTimeline(segs, eventUnix); ok {
		return seg, off, true
	}
	bestIdx := -1
	bestScore := int(^uint(0) >> 1)
	bestGap := int64(^uint64(0) >> 1)
	for i, s := range segs {
		if s.DurationSec <= 0 || eventUnix < s.StartUnix {
			continue
		}
		end := s.StartUnix + int64(s.DurationSec)
		// Within published span (shouldn't happen — LookupTimeline missed) or
		// slightly past end / within start+dur+skew for still-growing spans.
		if eventUnix >= end+int64(skewSec) {
			continue
		}
		if eventUnix-s.StartUnix > int64(s.DurationSec)+int64(skewSec) {
			continue
		}
		gap := int64(0)
		if eventUnix >= end {
			gap = eventUnix - end
		}
		score := absInt(s.DurationSec - 60)
		better := false
		if bestIdx < 0 {
			better = true
		} else if gap < bestGap {
			better = true
		} else if gap == bestGap && (score < bestScore ||
			(score == bestScore && s.DurationSec < segs[bestIdx].DurationSec)) {
			better = true
		}
		if better {
			bestGap = gap
			bestScore = score
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		return TimelineSeg{}, 0, false
	}
	s := segs[bestIdx]
	off := int(eventUnix - s.StartUnix)
	if off < 0 {
		off = 0
	}
	return s, off, true
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
