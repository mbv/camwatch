package live

import "testing"

func TestPopAnnexBNAL(t *testing.T) {
	sps := []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00}
	pps := []byte{0x00, 0x00, 0x00, 0x01, 0x68, 0xce}
	idr := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84}
	buf := append(append(sps, pps...), idr...)

	n1, rest, ok := popAnnexBNAL(buf)
	if !ok || string(n1) != string(sps) {
		t.Fatalf("sps got %v ok=%v", n1, ok)
	}
	n2, rest, ok := popAnnexBNAL(rest)
	if !ok || string(n2) != string(pps) {
		t.Fatalf("pps")
	}
	// Last NAL stays buffered until the next start code arrives.
	if _, _, ok = popAnnexBNAL(rest); ok {
		t.Fatal("expected incomplete trailing NAL")
	}
	more := append(append([]byte(nil), rest...), 0x00, 0x00, 0x00, 0x01, 0x41)
	n3, rest, ok := popAnnexBNAL(more)
	if !ok || string(n3) != string(idr) {
		t.Fatalf("idr got %v", n3)
	}
	_ = rest
}

func TestH264LiveBufStartsAtIDR(t *testing.T) {
	b := newH264LiveBuf()
	// P-frame first — ignored until IDR.
	b.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x41, 0x01})
	b.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x42}) // SPS
	b.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x68, 0xce}) // PPS
	b.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x65, 0xaa}) // IDR
	b.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x41, 0xbb}) // P

	chunks, gen, dead := b.WaitReady()
	if dead || gen == 0 || len(chunks) < 3 {
		t.Fatalf("ready chunks=%d gen=%d dead=%v", len(chunks), gen, dead)
	}
	if chunks[0][4]&0x1f != 7 || chunks[1][4]&0x1f != 8 || chunks[2][4]&0x1f != 5 {
		t.Fatalf("expected SPS/PPS/IDR order")
	}
}
