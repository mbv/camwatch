package live

import "testing"

func TestRawFrameBufAlignment(t *testing.T) {
	const fs = 12 // tiny fake frame
	b := newRawFrameBuf(fs, 4)
	b.Write([]byte("aaaaaa"))      // incomplete
	b.Write([]byte("bbbbbbAAAA")) // frame1=aaaaaabbbbbb + partial AAAA
	b.Write([]byte("AAAAAAAA"))   // frame2

	// Live edge = latest frame (seq 2).
	fr, seq, dead := b.WaitFrame()
	if dead || seq != 2 || len(fr) != fs {
		t.Fatalf("latest len=%d seq=%d dead=%v", len(fr), seq, dead)
	}

	done := make(chan struct{})
	go func() {
		b.Write([]byte("xxxxxxxxxxxx")) // frame3
		close(done)
	}()
	fr2, seq2, dead := b.WaitNext(seq)
	<-done
	if dead || seq2 != 3 || len(fr2) != fs {
		t.Fatalf("next seq=%d want 3 dead=%v", seq2, dead)
	}
}
