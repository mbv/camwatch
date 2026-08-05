package live

import (
	"bytes"
	"fmt"
	"io"
	"time"
)

// AnnexBSync holds a buffered prefix that starts at a decodable point.
type AnnexBSync struct {
	Format string // "hevc" or "h264"
	Prefix []byte
}

// WaitAnnexBSync reads from r until a clean keyframe AU is available, then
// returns a reader that starts at VPS/SPS/PPS+IRAP (HEVC) or SPS/PPS+IDR (AVC).
// Leading mid-GOP junk is discarded — feeding it causes "PPS id out of range"
// / missing POC refs and grey frames.
func WaitAnnexBSync(r io.Reader, maxWait time.Duration, maxBytes int) (AnnexBSync, io.Reader, error) {
	if maxWait <= 0 {
		maxWait = 15 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = 3 << 20
	}
	deadline := time.Now().Add(maxWait)
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		if syn, ok := inspectAnnexB(buf); ok {
			// Use cleaned Prefix only — never the raw buf (may contain pre-IRAP P-frames).
			return syn, io.MultiReader(bytes.NewReader(syn.Prefix), r), nil
		}
		if time.Now().After(deadline) {
			return AnnexBSync{}, nil, fmt.Errorf("live: no annex-B sync (VPS/SPS/PPS+IDR) within %s (%d B)", maxWait, len(buf))
		}
		if len(buf) >= maxBytes {
			return AnnexBSync{}, nil, fmt.Errorf("live: no annex-B sync after %d B", len(buf))
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return AnnexBSync{}, nil, fmt.Errorf("live: no annex-B sync within %s (%d B)", maxWait, len(buf))
		}
		type res struct {
			n   int
			err error
		}
		ch := make(chan res, 1)
		go func() {
			n, err := r.Read(tmp)
			ch <- res{n, err}
		}()
		var rr res
		select {
		case <-time.After(remain):
			return AnnexBSync{}, nil, fmt.Errorf("live: no annex-B sync within %s (%d B)", maxWait, len(buf))
		case rr = <-ch:
		}
		if rr.n > 0 {
			buf = append(buf, tmp[:rr.n]...)
		}
		if rr.err != nil {
			if len(buf) == 0 {
				return AnnexBSync{}, nil, rr.err
			}
			if syn, ok := inspectAnnexB(buf); ok {
				return syn, bytes.NewReader(syn.Prefix), nil
			}
			return AnnexBSync{}, nil, fmt.Errorf("live: stream ended before annex-B sync (%d B): %w", len(buf), rr.err)
		}
	}
}

type nalRef struct {
	start, end int
	hevcType   int // -1 if AVC
	avcType    int // -1 if HEVC
}

func parseNALs(buf []byte) []nalRef {
	var out []nalRef
	for i := 0; i+4 < len(buf); {
		sc := startCodeLen(buf, i)
		if sc == 0 {
			i++
			continue
		}
		j := i + sc + 1
		for j+3 < len(buf) {
			if startCodeLen(buf, j) > 0 {
				break
			}
			j++
		}
		if j > len(buf) {
			j = len(buf)
		}
		nal0 := buf[i+sc]
		out = append(out, nalRef{
			start:    i,
			end:      j,
			hevcType: int((nal0 >> 1) & 0x3f),
			avcType:  int(nal0 & 0x1f),
		})
		if j <= i {
			break
		}
		i = j
	}
	return out
}

func inspectAnnexB(buf []byte) (AnnexBSync, bool) {
	nals := parseNALs(buf)
	if len(nals) == 0 {
		return AnnexBSync{}, false
	}

	// HEVC: rebuild from latest VPS/SPS/PPS before the latest IRAP, then IRAP→EOF.
	lastIRAP := -1
	for i, n := range nals {
		if n.hevcType >= 16 && n.hevcType <= 21 {
			lastIRAP = i
		}
	}
	if lastIRAP >= 0 {
		var vps, sps, pps []byte
		for i := 0; i < lastIRAP; i++ {
			n := nals[i]
			switch n.hevcType {
			case 32:
				vps = buf[n.start:n.end]
			case 33:
				sps = buf[n.start:n.end]
			case 34:
				pps = buf[n.start:n.end]
			}
		}
		// Param sets sometimes arrive in the same AU after the IRAP start hunt —
		// also accept sets that appear immediately after IRAP before the next VCL.
		if vps == nil || sps == nil || pps == nil {
			for i := lastIRAP; i < len(nals); i++ {
				n := nals[i]
				switch n.hevcType {
				case 32:
					if vps == nil {
						vps = buf[n.start:n.end]
					}
				case 33:
					if sps == nil {
						sps = buf[n.start:n.end]
					}
				case 34:
					if pps == nil {
						pps = buf[n.start:n.end]
					}
				}
				if n.hevcType >= 1 && n.hevcType <= 9 && i > lastIRAP {
					break
				}
			}
		}
		if len(vps) > 0 && len(sps) > 0 && len(pps) > 0 {
			var out []byte
			out = append(out, vps...)
			out = append(out, sps...)
			out = append(out, pps...)
			out = append(out, buf[nals[lastIRAP].start:]...)
			return AnnexBSync{Format: "hevc", Prefix: out}, true
		}
	}

	// AVC: SPS+PPS + latest IDR → EOF.
	lastIDR := -1
	for i, n := range nals {
		if n.avcType == 5 {
			lastIDR = i
		}
	}
	if lastIDR >= 0 {
		var sps, pps []byte
		for i := 0; i < lastIDR; i++ {
			n := nals[i]
			switch n.avcType {
			case 7:
				sps = buf[n.start:n.end]
			case 8:
				pps = buf[n.start:n.end]
			}
		}
		if len(sps) > 0 && len(pps) > 0 {
			var out []byte
			out = append(out, sps...)
			out = append(out, pps...)
			out = append(out, buf[nals[lastIDR].start:]...)
			return AnnexBSync{Format: "h264", Prefix: out}, true
		}
	}
	return AnnexBSync{}, false
}

func startCodeLen(b []byte, i int) int {
	if i+3 < len(b) && b[i] == 0 && b[i+1] == 0 && b[i+2] == 0 && b[i+3] == 1 {
		return 4
	}
	if i+2 < len(b) && b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
		return 3
	}
	return 0
}
