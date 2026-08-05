package live

import "sync"

// rawFrameBuf holds complete yuv420p frames so HTTP clients never join mid-frame
// (mid-frame joins desync the raw pipe and paint the whole screen green).
type rawFrameBuf struct {
	mu        sync.Mutex
	cond      *sync.Cond
	frameSize int
	tail      []byte
	frames    [][]byte // ring, oldest first
	maxFrames int
	seq       uint64 // total frames ever written
	done      bool
}

func newRawFrameBuf(frameSize, maxFrames int) *rawFrameBuf {
	if maxFrames <= 0 {
		maxFrames = 60
	}
	b := &rawFrameBuf{frameSize: frameSize, maxFrames: maxFrames}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *rawFrameBuf) Close() {
	b.mu.Lock()
	b.done = true
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *rawFrameBuf) Write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tail = append(b.tail, p...)
	for len(b.tail) >= b.frameSize {
		fr := append([]byte(nil), b.tail[:b.frameSize]...)
		b.tail = b.tail[b.frameSize:]
		b.frames = append(b.frames, fr)
		b.seq++
		for len(b.frames) > b.maxFrames {
			b.frames = b.frames[1:]
		}
		b.cond.Broadcast()
	}
}

// WaitFrame blocks until at least one full frame exists.
func (b *rawFrameBuf) WaitFrame() (frame []byte, seq uint64, dead bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if len(b.frames) > 0 {
			// Join at latest frame (live edge), still frame-aligned.
			i := len(b.frames) - 1
			fr := append([]byte(nil), b.frames[i]...)
			seq := b.seq - uint64(len(b.frames)-1-i)
			return fr, seq, false
		}
		if b.done {
			return nil, b.seq, true
		}
		b.cond.Wait()
	}
}

// WaitNext returns the next frame after afterSeq.
func (b *rawFrameBuf) WaitNext(afterSeq uint64) (frame []byte, seq uint64, dead bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		// seq of frames[0] == b.seq - len + 1
		if len(b.frames) > 0 {
			firstSeq := b.seq - uint64(len(b.frames)) + 1
			if afterSeq < firstSeq {
				// Fell behind ring — resync to latest.
				i := len(b.frames) - 1
				fr := append([]byte(nil), b.frames[i]...)
				return fr, b.seq, false
			}
			want := afterSeq + 1
			if want <= b.seq {
				i := int(want - firstSeq)
				if i >= 0 && i < len(b.frames) {
					fr := append([]byte(nil), b.frames[i]...)
					return fr, want, false
				}
			}
		}
		if b.done {
			return nil, b.seq, true
		}
		b.cond.Wait()
	}
}
