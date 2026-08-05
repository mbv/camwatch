package mtp

import (
	"sync"
	"sync/atomic"
	"time"
)

// dataChannel mirrors cs2's channel queue for commands (ch0) and media (ch2).
type dataChannel struct {
	ch      chan []byte
	drop    int // when full, drop oldest if drop>0
	name    string
	dropped uint64 // frames discarded because the queue was full (drop==0 path)
}

func newDataChannel(size, drop int) *dataChannel {
	return newNamedDataChannel(size, drop, "")
}

func newNamedDataChannel(size, drop int, name string) *dataChannel {
	if size <= 0 {
		size = 16
	}
	return &dataChannel{ch: make(chan []byte, size), drop: drop, name: name}
}

func (d *dataChannel) Push(b []byte) {
	buf := append([]byte(nil), b...)
	select {
	case d.ch <- buf:
	default:
		if d.drop > 0 {
			select {
			case <-d.ch:
			default:
			}
			select {
			case d.ch <- buf:
			default:
			}
			return
		}
		// drop==0: the queue is full and this frame is discarded. This used to
		// be silent — for the RDT queue that meant a truncated/misaligned SD
		// index with no diagnostic (root cause of "no 0x10e"-adjacent
		// segment_not_found investigations). Log the first drop and every
		// 1000th after, so an overflowing queue is always visible under
		// mtp_protocol without spamming.
		n := atomic.AddUint64(&d.dropped, 1)
		if n == 1 || n%1000 == 0 {
			label := d.name
			if label == "" {
				label = "channel"
			}
			// Logp (not Logf): this must be visible under mtp_protocol alone —
			// mtp_verbose is off by default (it floods and starves the RDT
			// queue, see media_kcp.go), so gating this on Verbose meant it
			// could never fire in the configuration actually used.
			Logp("mtp: %s queue full (cap=%d); dropped %d frame(s) so far\n", label, cap(d.ch), n)
		}
	}
}

func (d *dataChannel) Pop() ([]byte, bool) {
	select {
	case b := <-d.ch:
		return b, true
	default:
		return nil, false
	}
}

// Drain drops all queued buffers (non-blocking).
func (d *dataChannel) Drain() int {
	n := 0
	for {
		if _, ok := d.Pop(); !ok {
			return n
		}
		n++
	}
}

func (d *dataChannel) PopWait(deadline time.Time) ([]byte, error) {
	if deadline.IsZero() {
		b := <-d.ch
		return b, nil
	}
	dline := time.Until(deadline)
	if dline <= 0 {
		return nil, errDeadline
	}
	t := time.NewTimer(dline)
	defer t.Stop()
	select {
	case b := <-d.ch:
		return b, nil
	case <-t.C:
		return nil, errDeadline
	}
}

type channelSet struct {
	mu    sync.Mutex
	cmd   *dataChannel
	media *dataChannel
	rdt   *dataChannel // channel-3 RDT (timeline index, etc.)
}

func newChannelSet() *channelSet {
	return &channelSet{
		cmd:   newNamedDataChannel(64, 16, "cmd"), // drop oldest if full — never silently drop 0x10e
		media: newNamedDataChannel(256, 64, "media"),
		// Type-6 arrives as thousands of 16 B TimeItem frames in a burst; a
		// small queue drops most of them → sparse index → segment_not_found.
		rdt: newNamedDataChannel(16384, 0, "rdt"),
	}
}
