package mtp

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTimelineBodyFromCapture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "x", "rdt-type6.bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("capture fixture missing: %v", err)
	}
	h, ok := parseRDTHeader(raw)
	if !ok || h.Type != 6 {
		t.Fatalf("header: ok=%v %+v", ok, h)
	}
	if int(h.Size)+12 > len(raw) {
		t.Fatalf("size %d+12 > file %d", h.Size, len(raw))
	}
	body := raw[12 : 12+int(h.Size)]
	segs := ParseTimelineBody(body)
	if len(segs) < 1000 {
		t.Fatalf("expected thousands of segments, got %d", len(segs))
	}
	// Structural checks only — do not assert dump-specific timestamps.
	if segs[0].StartUnix == 0 || segs[0].DurationSec != 60 {
		t.Fatalf("first seg %+v", segs[0])
	}
	last := segs[len(segs)-1]
	if last.StartUnix <= segs[0].StartUnix {
		t.Fatalf("timeline not chronological: first=%d last=%d", segs[0].StartUnix, last.StartUnix)
	}
	seg, off, ok := LookupTimeline(segs, last.StartUnix+10)
	if !ok || seg.StartUnix != last.StartUnix || off != 10 {
		t.Fatalf("lookup %+v off=%d ok=%v", seg, off, ok)
	}
}

func TestLookupTimelinePrefersNear60(t *testing.T) {
	segs := []TimelineSeg{
		{StartUnix: 1000, DurationSec: 316},
		{StartUnix: 1060, DurationSec: 60},
		{StartUnix: 1120, DurationSec: 60},
	}
	// Event inside the long span and the 60s slot at 1060.
	seg, off, ok := LookupTimeline(segs, 1070)
	if !ok || seg.StartUnix != 1060 || seg.DurationSec != 60 || off != 10 {
		t.Fatalf("got %+v off=%d ok=%v", seg, off, ok)
	}
	// Only the long span covers this instant — still return it.
	seg, off, ok = LookupTimeline(segs, 1010)
	if !ok || seg.StartUnix != 1000 || off != 10 {
		t.Fatalf("long-only got %+v off=%d ok=%v", seg, off, ok)
	}
}

func TestPrecedingSegmentContiguous(t *testing.T) {
	segs := []TimelineSeg{
		{StartUnix: 1000, DurationSec: 60}, // ends 1060
		{StartUnix: 1060, DurationSec: 60}, // ends 1120, contiguous with above
	}
	prev, ok := PrecedingSegment(segs, 1060, 5)
	if !ok || prev.StartUnix != 1000 {
		t.Fatalf("got %+v ok=%v", prev, ok)
	}
	// Walking back again from the found segment's own start reaches nothing further.
	if _, ok := PrecedingSegment(segs, 1000, 5); ok {
		t.Fatal("expected no segment before the first one")
	}
}

func TestPrecedingSegmentToleratesSmallGap(t *testing.T) {
	segs := []TimelineSeg{{StartUnix: 1000, DurationSec: 60}} // ends 1060
	prev, ok := PrecedingSegment(segs, 1062, 5)
	if !ok || prev.StartUnix != 1000 {
		t.Fatalf("got %+v ok=%v", prev, ok)
	}
}

func TestPrecedingSegmentRejectsRealGap(t *testing.T) {
	segs := []TimelineSeg{{StartUnix: 1000, DurationSec: 60}} // ends 1060
	// A genuine event-triggered recording gap (e.g. 10 minutes) must not be
	// treated as a reachable "previous" segment.
	if _, ok := PrecedingSegment(segs, 1600, 5); ok {
		t.Fatal("expected no match across a real recording gap")
	}
}

func TestPrecedingSegmentPrefersMostContiguousThen60s(t *testing.T) {
	segs := []TimelineSeg{
		{StartUnix: 800, DurationSec: 316}, // ends 1116 — long span, further away
		{StartUnix: 1060, DurationSec: 60}, // ends 1120 — closer, ~60s
	}
	prev, ok := PrecedingSegment(segs, 1120, 5)
	if !ok || prev.StartUnix != 1060 {
		t.Fatalf("expected the more contiguous 60s segment, got %+v ok=%v", prev, ok)
	}
}

func TestLookupTimelineNearSkew(t *testing.T) {
	segs := []TimelineSeg{
		{StartUnix: 1000, DurationSec: 60}, // ends 1060
		{StartUnix: 1120, DurationSec: 60}, // gap 1060–1120
	}
	// Exact cover still preferred when present.
	seg, off, ok := LookupTimelineNear(segs, 1130, 120)
	if !ok || seg.StartUnix != 1120 || off != 10 {
		t.Fatalf("exact via near: %+v off=%d ok=%v", seg, off, ok)
	}
	// Event slightly past published end of first segment (index lag).
	seg, off, ok = LookupTimelineNear(segs, 1075, 120)
	if !ok || seg.StartUnix != 1000 || off != 75 {
		t.Fatalf("skew past end: %+v off=%d ok=%v", seg, off, ok)
	}
	// Prefer ~60s prior over a long overlapping span when past published end.
	segs2 := []TimelineSeg{
		{StartUnix: 1000, DurationSec: 316},
		{StartUnix: 1300, DurationSec: 60}, // ends 1360
	}
	seg, off, ok = LookupTimelineNear(segs2, 1380, 120)
	if !ok || seg.StartUnix != 1300 || off != 80 {
		t.Fatalf("prefer 60s near: %+v off=%d ok=%v", seg, off, ok)
	}
	// Outside skew — no match.
	_, _, ok = LookupTimelineNear(segs, 1075, 10)
	if ok {
		t.Fatal("expected no match outside skew")
	}
}

func TestIsMissCmdFrameNotParsedAsTimeline(t *testing.T) {
	// Synthetic 0x10e control payload that historically leaked into RDT body
	// (92 bytes → breaks 8-byte alignment and invents huge durations).
	cmd := make([]byte, 0, 100)
	cmd = binary.BigEndian.AppendUint32(cmd, 0x1001)
	cmd = binary.BigEndian.AppendUint32(cmd, 0x10e)
	cmd = append(cmd, []byte(`{"id":1,"status":"filefound","duration":60}`)...)
	if !isMissCmdFrame(cmd) {
		t.Fatal("expected miss cmd frame")
	}
	// Body that starts valid then appends the cmd (misaligned remainder).
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, 1700001000)
	body = binary.LittleEndian.AppendUint32(body, 60)
	body = append(body, cmd...)
	segs, dropped := ParseTimelineBodyCounted(body)
	if len(segs) != 1 || segs[0].DurationSec != 60 {
		t.Fatalf("segs=%+v", segs)
	}
	if dropped < 1 {
		t.Fatalf("expected drops from cmd junk, dropped=%d", dropped)
	}
}

func TestFinalizeTimelineBodyRejectsUnalignedSize(t *testing.T) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint32(body[0:4], 1700001000)
	binary.LittleEndian.PutUint32(body[4:8], 60)
	if _, err := FinalizeTimelineBody(23, body[:23]); err == nil {
		t.Fatal("expected unaligned size rejection")
	}
	segs, err := FinalizeTimelineBody(8, body[:8])
	if err != nil || len(segs) != 1 {
		t.Fatalf("aligned: segs=%+v err=%v", segs, err)
	}
}

func TestMissCmdFrameNeverLooksLikeRDT(t *testing.T) {
	cmd := make([]byte, 0, 100)
	cmd = binary.BigEndian.AppendUint32(cmd, 0x1001)
	cmd = binary.BigEndian.AppendUint32(cmd, 0x10e)
	cmd = append(cmd, []byte(`{"id":1,"status":"filefound"}`)...)
	if looksLikeRDTHeader(cmd) {
		t.Fatal("0x10e must not parse as RDT header")
	}
	if !isMissCmdFrame(cmd) {
		t.Fatal("expected miss cmd")
	}
}

func TestNativeRDTFieldHiBytes(t *testing.T) {
	// new_command.log: type-6 chunks use 0xd8xx and 0x58xx single-frag fields.
	for _, rest := range []uint16{0xd820, 0xd838, 0xd8c0, 0x5814, 0x5818} {
		hi := rest >> 8
		if hi != 0xd8 && hi != 0x58 {
			t.Fatalf("rest %#x hi=%#x not treated as RDT", rest, hi)
		}
	}
}

func TestLooksLikeTimelineBody(t *testing.T) {
	var body []byte
	for i := 0; i < 4; i++ {
		body = binary.LittleEndian.AppendUint32(body, 1700000000+uint32(i*60))
		body = binary.LittleEndian.AppendUint32(body, 60)
	}
	if !looksLikeTimelineBody(body) {
		t.Fatal("expected timeline body")
	}
	junk := binary.BigEndian.AppendUint32(nil, 0x1001)
	if looksLikeTimelineBody(junk) {
		t.Fatal("miss cmd must not look like timeline")
	}
	prefixed := append(make([]byte, 32), body...)
	if extractTimelineBytes(prefixed) == nil {
		t.Fatal("expected extract after 32 B prefix")
	}
}

func TestParseTimelineBodyDropsGarbage(t *testing.T) {
	// Valid pair + misaligned junk that looks like huge dur covering everything.
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, 1700001000)
	body = binary.LittleEndian.AppendUint32(body, 316)
	body = binary.LittleEndian.AppendUint32(body, 0x10010000) // miss-cmd-ish
	body = binary.LittleEndian.AppendUint32(body, 0xdeadbeef)
	body = binary.LittleEndian.AppendUint32(body, 1700001013)
	body = binary.LittleEndian.AppendUint32(body, 60)
	segs := ParseTimelineBody(body)
	if len(segs) != 2 {
		t.Fatalf("want 2 valid segs, got %+v", segs)
	}
	if segs[0].StartUnix != 1700001000 || segs[0].DurationSec != 316 {
		t.Fatalf("first %+v", segs[0])
	}
	if segs[1].StartUnix != 1700001013 || segs[1].DurationSec != 60 {
		t.Fatalf("second %+v", segs[1])
	}
	covers := CoveringSegments(segs, 1700001019)
	if len(covers) != 2 {
		t.Fatalf("covers %+v", covers)
	}
	seg, _, ok := LookupTimeline(segs, 1700001019)
	if !ok || seg.DurationSec != 60 {
		t.Fatalf("prefer 60s cover, got %+v ok=%v", seg, ok)
	}
}

// TestFindTimelineHeaderAcrossGrowingPrefix simulates the real failure mode:
// the 12-byte TLV header does not arrive whole in the first wire chunk (RDT
// fragments bypass frag-based reassembly, see media_kcp.go handleCHK case
// 0xd8/0x58, and were observed on the wire as small as 16 B). FetchTimelineIndex
// now accumulates raw bytes across chunks and re-searches the whole prefix
// (rdt.go handle()) instead of only ever checking the first isolated chunk —
// this asserts the primitive it relies on, findTimelineHeader, behaves
// correctly as that prefix grows.
func TestFindTimelineHeaderAcrossGrowingPrefix(t *testing.T) {
	var full []byte
	full = binary.LittleEndian.AppendUint32(full, RDTTypeTimeline) // type=6
	full = binary.LittleEndian.AppendUint32(full, 16)              // size=16 (2 records)
	full = binary.LittleEndian.AppendUint32(full, 0)                // status=0
	full = binary.LittleEndian.AppendUint32(full, 1700002000)
	full = binary.LittleEndian.AppendUint32(full, 60)
	full = binary.LittleEndian.AppendUint32(full, 1700002060)
	full = binary.LittleEndian.AppendUint32(full, 60)

	// Chunk sizes chosen so the header (bytes 0..11) straddles two chunks —
	// the pre-fix code only ever looked at chunk 1 in isolation and would
	// never have found this header.
	chunkSizes := []int{5, 4, 3, 4, 4, 4, 4}
	var raw []byte
	found := -1
	for _, n := range chunkSizes {
		if n > len(full) {
			n = len(full)
		}
		raw = append(raw, full[:n]...)
		full = full[n:]
		// minSize=16 here: this test is about the growing-prefix search
		// mechanism, not the false-positive floor (rdtHeaderMinPlausibleSize)
		// — see TestFindTimelineHeaderRejectsImplausiblySmallSize for that.
		if off := findTimelineHeader(raw, 16); off >= 0 {
			found = off
			break
		}
	}
	if found != 0 {
		t.Fatalf("expected header found at offset 0 once enough bytes accumulated, got %d (raw len=%d)", found, len(raw))
	}
	h, ok := parseRDTHeader(raw[found:])
	if !ok || h.Type != RDTTypeTimeline || h.Size != 16 || h.Status != 0 {
		t.Fatalf("header %+v ok=%v", h, ok)
	}
}

// TestFindTimelineHeaderRejectsImplausiblySmallSize reproduces a live failure
// (2026-08-02): scanning a large, arbitrarily-growing accumulated buffer
// byte-by-byte for a 12-byte header with only a loose sanity floor
// (Size>=16, i.e. as few as 2 records) coincidentally matched ordinary
// TimeItem content deep inside the buffer often enough that a fetch got
// permanently stuck waiting for a `need` no real data would ever satisfy —
// raw grew to 188 KB (far past rdtRawHardCap) because the false-positive
// match blocked the hard-cap check from ever running (see findTimelineHeader
// and handle()'s doc comments). rdtHeaderMinPlausibleSize=2048 must reject a
// coincidental small-Size match while still finding a real one.
func TestFindTimelineHeaderRejectsImplausiblySmallSize(t *testing.T) {
	// A plausible-looking but tiny "header": Type=6, Size=16 (2 records),
	// Status=0 — exactly the shape a coincidence in real duration fields
	// (which have trailing zero bytes, e.g. dur=60 LE is 3C 00 00 00) can
	// produce inside a large buffer of genuine TimeItem data.
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, RDTTypeTimeline)
	buf = binary.LittleEndian.AppendUint32(buf, 16)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = append(buf, make([]byte, 32)...) // some trailing body-ish bytes

	if off := findTimelineHeader(buf, rdtHeaderMinPlausibleSize); off != -1 {
		t.Fatalf("expected small-Size match to be rejected, got offset %d", off)
	}
	// The same bytes, searched with no floor, must still find it — proves
	// the rejection above is really about the size floor, not a broken scan.
	if off := findTimelineHeader(buf, 16); off != 0 {
		t.Fatalf("expected match at offset 0 with a low floor, got %d", off)
	}

	// A genuinely large declared Size must still be found.
	var real []byte
	real = binary.LittleEndian.AppendUint32(real, RDTTypeTimeline)
	real = binary.LittleEndian.AppendUint32(real, rdtHeaderMinPlausibleSize)
	real = binary.LittleEndian.AppendUint32(real, 0)
	if off := findTimelineHeader(real, rdtHeaderMinPlausibleSize); off != 0 {
		t.Fatalf("expected a large-enough header to be found, got offset %d", off)
	}
}

// TestLooksLikeTimelineBodyTightenedThreshold locks in the tightened garbage
// tolerance (20%, was 50%) — the looser threshold let misaligned scans accept
// bodies that were mostly junk, which is how a fictional segment like the
// minute-aligned "sessionid=1700007000 dur=316" made it into a seek plan.
func TestLooksLikeTimelineBodyTightenedThreshold(t *testing.T) {
	// 4 valid records, 1 garbage record → 20% dropped: still accepted.
	var body []byte
	for i := 0; i < 4; i++ {
		body = binary.LittleEndian.AppendUint32(body, 1700000000+uint32(i*60))
		body = binary.LittleEndian.AppendUint32(body, 60)
	}
	body = binary.LittleEndian.AppendUint32(body, 0) // start==0 → dropped
	body = binary.LittleEndian.AppendUint32(body, 0)
	if !looksLikeTimelineBody(body) {
		t.Fatal("expected 20%% garbage to still pass")
	}

	// 2 valid, 2 garbage → 50% dropped: rejected under the tightened threshold
	// (the old dropped*2<=len(segs) gate would have accepted this).
	var half []byte
	for i := 0; i < 2; i++ {
		half = binary.LittleEndian.AppendUint32(half, 1700000000+uint32(i*60))
		half = binary.LittleEndian.AppendUint32(half, 60)
	}
	for i := 0; i < 2; i++ {
		half = binary.LittleEndian.AppendUint32(half, 0)
		half = binary.LittleEndian.AppendUint32(half, 0)
	}
	if looksLikeTimelineBody(half) {
		t.Fatal("expected 50%% garbage to be rejected under tightened threshold")
	}
}

// TestParseTimelineBodyFromCaptureChunked feeds the real capture through the
// same growing-prefix header search FetchTimelineIndex now uses, in small
// chunks (matching wire fragment sizes observed for camwatch, e.g. "first=16
// B"), proving the header is still found even though it never receives the
// whole 83 KB body as a single first read.
func TestParseTimelineBodyFromCaptureChunked(t *testing.T) {
	path := filepath.Join("..", "..", "..", "x", "rdt-type6.bin")
	full, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("capture fixture missing: %v", err)
	}
	const chunkSize = 16 // smallest chunk size observed on the camwatch wire
	var raw []byte
	off := -1
	for i := 0; i < len(full); i += chunkSize {
		end := i + chunkSize
		if end > len(full) {
			end = len(full)
		}
		raw = append(raw, full[i:end]...)
		if o := findTimelineHeader(raw, rdtHeaderMinPlausibleSize); o >= 0 {
			off = o
			break
		}
	}
	if off != 0 {
		t.Fatalf("expected header at offset 0 once >=12 B accumulated, got %d", off)
	}
	h, ok := parseRDTHeader(raw[off:])
	if !ok || h.Type != 6 {
		t.Fatalf("header ok=%v %+v", ok, h)
	}
	if int(h.Size) != len(full)-12 {
		t.Fatalf("size %d want %d", h.Size, len(full)-12)
	}
}

// TestExtractTimelineBytesRejectsPureNoise documents why FetchTimelineIndex no
// longer has a "try all 8 byte phases, take the best-scoring one" fallback
// when extractTimelineBytes's own checked offsets (0, +32, 4-byte-steps to
// 64) find nothing clean. That fallback (added, then reverted, in this same
// change) turned out to be unsound: a wrong byte phase of a real,
// slowly-varying TimeItem stream can pass the range gate AND look
// chronologically ordered purely by coincidence — proven both live (a fetch
// that kept only 2/~1000 records at a wrong-but-plausible phase) and in this
// test's own history (an 8-phase "pick the least-bad" scorer still picked a
// wrong phase on realistic irregular-duration fixtures). There is no
// reliable content-only way to disambiguate two plausible phases — not even
// offset 0 is inherently trustworthy once no explicit 12-byte TLV header
// confirms the true start. So the fix is to not guess further: when
// extractTimelineBytes finds nothing, FetchTimelineIndex fails the fetch
// (mtp: rdt type6: no aligned...) once rdtRawHardCap is reached, rather than
// accept an unverified phase. This test only pins down the base case —
// content that looks like nothing in particular must not parse as anything.
func TestExtractTimelineBytesRejectsPureNoise(t *testing.T) {
	noise := make([]byte, 256)
	for i := range noise {
		noise[i] = byte(i * 7) // deterministic, not zero, not TimeItem-shaped
	}
	if got := extractTimelineBytes(noise); got != nil {
		segs, dropped := ParseTimelineBodyCounted(got)
		t.Fatalf("expected nil on pure noise, got %d bytes (segs=%d dropped=%d)", len(got), len(segs), dropped)
	}
}

// TestExtractTimelineBytesRescuesCleanPrefixBeforeGarbage reproduces the
// live pattern that motivated leadingCleanRunRecords (2026-08-02): the same
// target repeatedly produced an identical clean prefix (same real SD
// segments — no new recording happened between attempts seconds apart) but
// the point and content of corruption after it varied between fetches,
// consistent with real network loss on the P2P relay rather than a fixed
// decode bug. The previous aggregate-ratio design (looksLikeTimelineBody
// over the whole buffer) rejected the ENTIRE accumulation once enough
// garbage piled up after the prefix — discarding clean records that were
// already sitting right there. extractTimelineBytes must now return just the
// clean leading run, truncated at the first bad record, instead of nil.
func TestExtractTimelineBytesRescuesCleanPrefixBeforeGarbage(t *testing.T) {
	var clean []byte
	durs := []uint32{60, 60, 61, 24, 60, 316, 36, 60, 57, 60}
	start := uint32(1700000000)
	for _, d := range durs {
		clean = binary.LittleEndian.AppendUint32(clean, start)
		clean = binary.LittleEndian.AppendUint32(clean, d)
		start += d + 40
	}
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i*37 + 11) // deterministic noise, not TimeItem-shaped
	}
	buf := append(append([]byte(nil), clean...), garbage...)

	got := extractTimelineBytes(buf)
	if got == nil {
		t.Fatal("expected the clean prefix to be rescued, got nil (whole buffer rejected)")
	}
	if len(got) != len(clean) {
		t.Fatalf("expected exactly the %d-byte clean prefix, got %d bytes", len(clean), len(got))
	}
	segs, dropped := ParseTimelineBodyCounted(got)
	if dropped != 0 || len(segs) != len(durs) {
		t.Fatalf("expected %d clean records with 0 dropped, got segs=%+v dropped=%d", len(durs), segs, dropped)
	}
	if segs[0].StartUnix != 1700000000 || segs[0].DurationSec != 60 {
		t.Fatalf("first record %+v", segs[0])
	}
}

// TestExtractTimelineBytesFindsFourByteShift reproduces a live failure
// (2026-08-02) using a synthetic 4-byte-shifted TimeItem fixture (shape from a stuck fetch):
// clean (start,dur) pairs shifted by exactly 4 bytes from raw's start
// (offset 0 and +32 — both ≡0 mod 8 — never touch that phase; an earlier
// version of the 8-phase scan also buggily skipped off=4 itself via
// `if off%4==0 { continue }`, mistaking "already tried at 0/32" — residue 0
// mod 8 — for "skip every multiple of 4", a different, larger set).
//
// This data has a second layer worth pinning down: read at the WRONG
// neighboring phase (off=3), it *also* decodes as 15/15 valid records with
// zero drops — count and drop-rate alone cannot tell the phases apart. What
// distinguishes them is duration plausibility: off=3's records all carry an
// absurd, constant ~15466s (~4.3h) duration, while only the true off=4 phase
// produces realistic small durations. The old 24h duration ceiling in
// ParseTimelineBodyCounted let the wrong phase through; tightened to 3600s
// (still 11x the largest duration ever observed, 316s), it correctly rejects
// off=3 so the phase scan finds a unique match instead of refusing to guess.
func TestExtractTimelineBytesFindsFourByteShift(t *testing.T) {
	raw, err := hex.DecodeString(
		"3d000000403363653c000000096d63653c000000456d63653c000000b9a86365" +
			"3c000000f5a863653c000000afe463653d000000ece463653c000000ed1e6465" +
			"3c000000291f64653c000000835864653c000000bf5864653c00000054926465" +
			"3c000000909264653c0000008ccc64653c000000c8cc64653d0000008c086565")
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	got := extractTimelineBytes(raw)
	if got == nil {
		t.Fatal("expected a unique match at the true 4-byte-shifted phase")
	}
	segs, dropped := ParseTimelineBodyCounted(got)
	if dropped != 0 {
		t.Fatalf("expected 0 dropped at the true phase, got %d (segs=%+v)", dropped, segs)
	}
	if len(segs) < 10 {
		t.Fatalf("expected most of the 16 records recovered, got %d: %+v", len(segs), segs)
	}
	for _, s := range segs {
		if s.DurationSec > 3600 {
			t.Fatalf("wrong phase leaked through: implausible duration %+v", s)
		}
	}
	if segs[0].StartUnix != 1701000000 || segs[0].DurationSec != 60 {
		t.Fatalf("first record %+v", segs[0])
	}
}

// TestExtractTimelineBytesFindsFourByteShiftAtScale is the same proof at
// production scale: the real capture (x/rdt-type6.bin) body, prefixed with 4
// junk bytes to simulate the shift. Confirms the wrong-phase-with-absurd-
// duration pattern above isn't a small-sample artifact — off=3 still decodes
// all 10433 records with 0 drops at full scale (a constant ~4.3h duration),
// and the tightened 3600s ceiling is what makes off=4 the unique winner.
func TestExtractTimelineBytesFindsFourByteShiftAtScale(t *testing.T) {
	path := filepath.Join("..", "..", "..", "x", "rdt-type6.bin")
	full, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("capture fixture missing: %v", err)
	}
	h, ok := parseRDTHeader(full)
	if !ok {
		t.Fatalf("fixture header invalid")
	}
	body := full[12 : 12+int(h.Size)]
	shifted := append([]byte{0xEE, 0xEE, 0xEE, 0xEE}, body...)

	got := extractTimelineBytes(shifted)
	if got == nil {
		t.Fatal("expected the 4-byte-shifted real body to be found unambiguously")
	}
	segs, dropped := ParseTimelineBodyCounted(got)
	if dropped != 0 {
		t.Fatalf("expected 0 dropped at the true phase, got %d (kept %d)", dropped, len(segs))
	}
	if len(segs) < 10000 {
		t.Fatalf("expected thousands of records recovered, got %d", len(segs))
	}
	if segs[0].StartUnix == 0 || segs[0].DurationSec != 60 {
		t.Fatalf("first record %+v", segs[0])
	}
}

func TestEmptyRDTRequest(t *testing.T) {
	b := EmptyRDTRequest(6)
	if len(b) != 24 {
		t.Fatalf("len %d", len(b))
	}
	if binary.LittleEndian.Uint32(b[0:4]) != 6 {
		t.Fatalf("type %x", b[:4])
	}
	for i := 4; i < 24; i++ {
		if b[i] != 0 {
			t.Fatalf("pad at %d", i)
		}
	}
}

func TestBuildCHK_RDTField(t *testing.T) {
	plain := EmptyRDTRequest(6)
	chk := buildCHK(make([]byte, 8), make([]byte, 32), 0, 0, plain, 0, chkModeRDT)
	if len(chk) < chkHdrSize+8+24 {
		t.Fatalf("short chk %d", len(chk))
	}
	field := binary.BigEndian.Uint32(chk[20:24])
	// nonce8 + plain24 = 32 → 0xd820
	if field != 0xd820 {
		t.Fatalf("field %#x want 0xd820", field)
	}
}
