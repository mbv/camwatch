package live

import "sync"

// h264LiveBuf stores annex-B H.264 so new readers always start at SPS/PPS + IDR.
// Chunks are append-only within a GOP (no mid-GOP trim) so readers never skip slices
// — mid-GOP drops show up as bright green bars in the decoded picture.
type h264LiveBuf struct {
	mu   sync.Mutex
	cond *sync.Cond

	sps, pps []byte
	fromIDR  [][]byte
	tail     []byte
	done     bool
	gen      uint64
}

func newH264LiveBuf() *h264LiveBuf {
	b := &h264LiveBuf{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *h264LiveBuf) Close() {
	b.mu.Lock()
	b.done = true
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *h264LiveBuf) Write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tail = append(b.tail, p...)
	for {
		nal, rest, ok := popAnnexBNAL(b.tail)
		if !ok {
			break
		}
		b.tail = rest
		b.ingestNAL(nal)
	}
	b.cond.Broadcast()
}

func (b *h264LiveBuf) ingestNAL(nal []byte) {
	sc := startCodeLen(nal, 0)
	if sc == 0 || len(nal) <= sc {
		return
	}
	nalType := nal[sc] & 0x1f
	cp := append([]byte(nil), nal...)
	switch nalType {
	case 7: // SPS
		b.sps = cp
	case 8: // PPS
		b.pps = cp
	case 5: // IDR — start a new independent window (drops previous GOP wholesale)
		next := make([][]byte, 0, 8)
		if len(b.sps) > 0 {
			next = append(next, append([]byte(nil), b.sps...))
		}
		if len(b.pps) > 0 {
			next = append(next, append([]byte(nil), b.pps...))
		}
		next = append(next, cp)
		b.fromIDR = next
		b.gen++
	default:
		if len(b.fromIDR) == 0 {
			return
		}
		b.fromIDR = append(b.fromIDR, cp)
	}
}

// WaitReady blocks until SPS+PPS+IDR are available.
func (b *h264LiveBuf) WaitReady() (chunks [][]byte, gen uint64, dead bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if len(b.fromIDR) > 0 && len(b.sps) > 0 && len(b.pps) > 0 {
			return cloneChunks(b.fromIDR), b.gen, false
		}
		if b.done {
			return nil, b.gen, true
		}
		b.cond.Wait()
	}
}

// WaitMore returns the next chunk after idx within gen, or restarts on new IDR.
func (b *h264LiveBuf) WaitMore(gen uint64, idx int) (chunk []byte, newGen uint64, newIdx int, dead bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if b.gen != gen {
			if len(b.fromIDR) == 0 {
				if b.done {
					return nil, b.gen, 0, true
				}
				b.cond.Wait()
				continue
			}
			// Full resync at new IDR (copy SPS/PPS/IDR…).
			c := append([]byte(nil), b.fromIDR[0]...)
			return c, b.gen, 1, false
		}
		if idx < len(b.fromIDR) {
			c := append([]byte(nil), b.fromIDR[idx]...)
			return c, b.gen, idx + 1, false
		}
		if b.done {
			return nil, b.gen, idx, true
		}
		b.cond.Wait()
	}
}

func cloneChunks(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, c := range in {
		out[i] = append([]byte(nil), c...)
	}
	return out
}

func popAnnexBNAL(buf []byte) (nal, rest []byte, ok bool) {
	i := 0
	for i < len(buf) {
		if startCodeLen(buf, i) > 0 {
			break
		}
		i++
	}
	if i >= len(buf) {
		return nil, buf, false
	}
	sc0 := startCodeLen(buf, i)
	j := i + sc0 + 1
	for j < len(buf) {
		if startCodeLen(buf, j) > 0 {
			return buf[i:j], buf[j:], true
		}
		j++
	}
	return nil, buf, false
}
