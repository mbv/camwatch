package mtp

import (
	"encoding/binary"
	"sort"
	"testing"
)

// buildTestCHK assembles a minimal CHK~ frame handleCHK will accept: a
// 36-byte header (seq at [12:16], frag/rest packed into [20:24]) followed by
// an 8-byte ChaCha20 nonce and ciphertext encrypted with key. No ServerSign
// TLV is appended — handleCHK only looks for one to trim it, absence is fine.
func buildTestCHK(seq uint32, frag, rest uint16, key, nonce, plain []byte) []byte {
	pay := make([]byte, chkHdrSize)
	binary.BigEndian.PutUint32(pay[12:16], seq)
	field := uint32(frag)<<16 | uint32(rest)
	binary.BigEndian.PutUint32(pay[20:24], field)
	cipher := make([]byte, len(plain))
	chacha20XOR(cipher, plain, nonce, key)
	pay = append(pay, nonce...)
	pay = append(pay, cipher...)
	return pay
}

// buildTimeItems encodes n consecutive 60s (start,dur) records starting at
// startUnix as raw LE bytes, matching real SD index records.
func buildTimeItems(startUnix uint32, n int) []byte {
	b := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		rec := make([]byte, 8)
		binary.LittleEndian.PutUint32(rec[0:4], startUnix+uint32(i*60))
		binary.LittleEndian.PutUint32(rec[4:8], 60)
		b = append(b, rec...)
	}
	return b
}

// TestHandleCHKRecognizesMultiFragmentRDTByContent reproduces the actual
// root cause found live on 2026-08-02 via byte-level verification against a
// fresh native capture (mtp-dissect.py, independently reproducing the same
// classifier flaw): the bulk of the type-6 continuation stream arrives as
// frag>0 CHK packets tagged like ordinary video (rest hi-byte e.g. 0x9c/0x1c),
// not the single-fragment 0xd8/0x58/0x50 tags handleCHK explicitly recognized.
// Each such fragment is independently a complete, self-contained run of
// TimeItem records — it does not need reassembly with sibling fragments —
// but the old code required every fragment 0..frameNeed to arrive before
// ever inspecting content, so a single lost sibling silently discarded the
// whole chunk. handleCHK must recognize RDT content directly for frag>0
// frames during an RDT fetch and push it immediately, without waiting on
// reassembly.
func TestHandleCHKRecognizesMultiFragmentRDTByContent(t *testing.T) {
	cs := newChannelSet()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ms := &mediaSession{parent: &Conn{channels: cs}, shareKey: key, frags: make(map[uint16][]byte)}
	ms.rdtListen.Store(true)

	plain := buildTimeItems(1700000000, 20) // 160 B, well past minLeadingRecords
	pay := buildTestCHK(42, 5 /* frag>0 */, 0x9c00 /* video-shaped tag */, key, nonce, plain)

	ms.handleCHK(pay)

	got, ok := cs.rdt.Pop()
	if !ok {
		t.Fatal("expected frame in RDT queue for frag>0 content that looks like TimeItems, got nothing")
	}
	seq, payload := decodeRDTQueueItem(got)
	if seq != 42 {
		t.Fatalf("seq = %d, want 42", seq)
	}
	if string(payload) != string(plain) {
		t.Fatalf("payload mismatch: got %x want %x", payload, plain)
	}
	// Must not have touched video frag-reassembly state.
	if len(ms.frags) != 0 {
		t.Fatalf("expected frag reassembly state untouched, got %d pending frags", len(ms.frags))
	}
}

// TestHandleCHKMultiFragmentRDTIgnoredOutsideRDTListen confirms the content
// check is gated on rdtListen — outside an RDT fetch, frag>0 frames must
// still go through ordinary video reassembly (waiting for the full fragment
// set), since real video legitimately uses this same framing.
func TestHandleCHKMultiFragmentRDTIgnoredOutsideRDTListen(t *testing.T) {
	cs := newChannelSet()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ms := &mediaSession{parent: &Conn{channels: cs}, shareKey: key, frags: make(map[uint16][]byte)}
	// rdtListen left false (default).

	plain := buildTimeItems(1700000000, 20)
	pay := buildTestCHK(42, 5, 0x9c00, key, nonce, plain)

	ms.handleCHK(pay)

	if _, ok := cs.rdt.Pop(); ok {
		t.Fatal("expected no frame in RDT queue when rdtListen is false")
	}
	if len(ms.frags) == 0 {
		t.Fatal("expected the frame to enter ordinary video frag reassembly when rdtListen is false")
	}
}

// TestPushRDTOrMediaKnownRDTBypassesVideoMisclassification reproduces a live
// failure (2026-08-02): a fetch where the camera sent 80-200 RDT-tagged CHK
// frames (confirmed via rdtTaggedRX) but the reassembler still reported
// "no header/body" — the frames were classified correctly at the CHK layer
// (rest hi-byte 0xd8/0x58) and then lost inside pushRDTOrMedia, which
// re-checked isMissVideoFrame(frame) and treated some fraction of RDT
// records as video whenever a record's second 4-byte field (a duration in
// seconds) coincidentally equaled a codec ID (4, 5, or 40s durations are
// entirely plausible real SD segment durations). knownRDT=true must bypass
// that check for CHK-tagged RDT frames.
func TestPushRDTOrMediaKnownRDTBypassesVideoMisclassification(t *testing.T) {
	cs := newChannelSet()
	ms := &mediaSession{parent: &Conn{channels: cs}}
	ms.rdtListen.Store(true)

	// (start_unix=1700000040, duration=40) — duration 40 matches codecH264(4)
	// is not it, but codec value 40 ("observed media") in isMissVideoFrame's
	// switch — bytes[4:8] LE == 40 triggers the false-positive video match.
	frame := make([]byte, 8)
	binary.LittleEndian.PutUint32(frame[0:4], 1700000040)
	binary.LittleEndian.PutUint32(frame[4:8], 40)

	if !isMissVideoFrame(append(frame, make([]byte, 24)...)) {
		t.Fatal("test setup invalid: frame must actually trigger the codec-40 false positive at >=32 B")
	}
	// Real single-fragment RDT chunks on the wire are well under 32 B (we've
	// observed 16-48 B), so pad to a realistic RDT fragment size while
	// keeping the duration field at the false-positive-triggering offset.
	padded := append(frame, make([]byte, 40)...)
	if !isMissVideoFrame(padded) {
		t.Fatal("test setup invalid: padded frame must still trigger the false positive")
	}

	ms.pushRDTOrMedia(padded, true, 42) // knownRDT: CHK field already said this is RDT
	if got, ok := cs.rdt.Pop(); !ok {
		t.Fatal("expected frame in RDT queue when knownRDT=true, got nothing (misrouted to video)")
	} else {
		seq, payload := decodeRDTQueueItem(got)
		if seq != 42 {
			t.Fatalf("seq = %d, want 42", seq)
		}
		if len(payload) != len(padded) {
			t.Fatalf("got %d bytes, want %d", len(payload), len(padded))
		}
	}

	// Sanity: the same frame with knownRDT=false (generic/ambiguous path)
	// must NOT reach the RDT queue — isMissVideoFrame legitimately gates that
	// path, since it also carries real video.
	ms.pushRDTOrMedia(padded, false, 43)
	if _, ok := cs.rdt.Pop(); ok {
		t.Fatal("expected no frame in RDT queue when knownRDT=false and the frame looks like video")
	}
}

// TestRDTQueueItemRoundTrip locks in the seq-prefix encoding pushRDTOrMedia
// uses and FetchTimelineIndex decodes to sort each drained burst back into
// true CHK sequence order before accumulating bytes — see
// encodeRDTQueueItem's doc comment for why arrival order (what the RDT queue
// naturally delivers, since UDP doesn't guarantee ordering) is not safe to
// trust directly.
func TestRDTQueueItemRoundTrip(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	encoded := encodeRDTQueueItem(0xdeadbeef, payload)
	seq, decoded := decodeRDTQueueItem(encoded)
	if seq != 0xdeadbeef {
		t.Fatalf("seq = %#x, want 0xdeadbeef", seq)
	}
	if string(decoded) != string(payload) {
		t.Fatalf("payload = %x, want %x", decoded, payload)
	}
}

// TestPushRDTOrMediaOutOfOrderBurstSortsCorrectly simulates the exact failure
// mode proven live: RDT-tagged CHK frames arriving out of their true
// sequence order (UDP reordering, not even packet loss). Pushes three
// fragments to the RDT queue in scrambled arrival order and confirms
// decoding+sorting by seq (what FetchTimelineIndex's burst-collection loop
// does before calling handle()) recovers the correct order — the seq values
// mirror three (start,dur) TimeItem records that would otherwise concatenate
// into a corrupted, misaligned byte stream if processed in arrival order.
func TestPushRDTOrMediaOutOfOrderBurstSortsCorrectly(t *testing.T) {
	cs := newChannelSet()
	ms := &mediaSession{parent: &Conn{channels: cs}}
	ms.rdtListen.Store(true)

	rec := func(start, dur uint32) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b[0:4], start)
		binary.LittleEndian.PutUint32(b[4:8], dur)
		return b
	}
	recA := rec(1700000000, 60) // true seq 10
	recB := rec(1700000060, 60) // true seq 11
	recC := rec(1700000120, 60) // true seq 12

	// Arrival order is scrambled: C, A, B.
	ms.pushRDTOrMedia(recC, true, 12)
	ms.pushRDTOrMedia(recA, true, 10)
	ms.pushRDTOrMedia(recB, true, 11)

	type item struct {
		seq     uint32
		payload []byte
	}
	var burst []item
	for {
		raw, ok := cs.rdt.Pop()
		if !ok {
			break
		}
		seq, payload := decodeRDTQueueItem(raw)
		burst = append(burst, item{seq, payload})
	}
	if len(burst) != 3 {
		t.Fatalf("expected 3 queued items, got %d", len(burst))
	}
	sort.Slice(burst, func(i, j int) bool { return burst[i].seq < burst[j].seq })

	var reassembled []byte
	for _, it := range burst {
		reassembled = append(reassembled, it.payload...)
	}
	segs, dropped := ParseTimelineBodyCounted(reassembled)
	if dropped != 0 || len(segs) != 3 {
		t.Fatalf("expected 3 clean records after sorting, got segs=%+v dropped=%d", segs, dropped)
	}
	if segs[0].StartUnix != 1700000000 || segs[1].StartUnix != 1700000060 || segs[2].StartUnix != 1700000120 {
		t.Fatalf("wrong order after sort: %+v", segs)
	}
}

// TestMediaSessionMatchesAcceptsFlipRejectsForeign locks in the fix for a bug
// analogous to one already found and fixed on the transport plane (Conn):
// extra media endpoints from the punch/bind dance keep sending on the shared
// :40000 socket after we settle on one session, each with its own shareKey.
// Without filtering, handle() decrypted those foreign-session packets with
// OUR shareKey, producing effectively-random noise that silently corrupted
// whatever it was appended to. The camera's own legitimate packets carry the
// session with the first byte's high bit flipped (see findEP's identical
// same/flip check used during bind) — sessionMatches must accept that
// exact convention while still rejecting a genuinely different session.
func TestMediaSessionMatchesAcceptsFlipRejectsForeign(t *testing.T) {
	ours := []byte{0x31, 0x08, 0x41, 0x28, 0x89, 0xf5, 0x60, 0x02}
	ms := &mediaSession{session: ours}

	exact := append([]byte(nil), ours...)
	if !ms.sessionMatches(exact) {
		t.Fatal("expected exact session match to be accepted")
	}

	flipped := append([]byte(nil), ours...)
	flipped[0] ^= 0x80
	if !ms.sessionMatches(flipped) {
		t.Fatal("expected the native high-bit-flip convention to be accepted")
	}

	foreign := append([]byte(nil), ours...)
	foreign[3] ^= 0x01 // differs somewhere other than the flip-eligible byte 0
	if ms.sessionMatches(foreign) {
		t.Fatal("expected a genuinely different session to be rejected")
	}

	tooShort := ours[:4]
	if ms.sessionMatches(tooShort) {
		t.Fatal("expected a too-short session field to be rejected, not panic")
	}
}
