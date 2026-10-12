package recorder

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/notify/live"
	"camwatch/internal/ports"
)

type Config struct {
	DurationSec int
	PreRollSec  int
	// FullEvent records until the camera's recording for the event ends (up to
	// MaxDurationSec) instead of a fixed DurationSec. Ignored when the caller
	// picked an explicit window.
	FullEvent      bool
	MaxDurationSec int
	FFmpeg         string
	Clips       ports.ClipStore
}

type Recorder struct {
	cfg Config
}

func New(cfg Config) *Recorder {
	if cfg.DurationSec <= 0 {
		cfg.DurationSec = 20
	}
	if cfg.PreRollSec <= 0 {
		cfg.PreRollSec = domain.DefaultPreRollSec
	}
	if cfg.FullEvent && cfg.MaxDurationSec < cfg.DurationSec {
		cfg.MaxDurationSec = cfg.DurationSec
	}
	if cfg.FFmpeg == "" {
		cfg.FFmpeg = "ffmpeg"
	}
	return &Recorder{cfg: cfg}
}

func (r *Recorder) CaptureEvent(ctx context.Context, conn ports.P2PConn, ev domain.Event, win domain.ClipWindow) (domain.Clip, error) {
	if err := r.cfg.Clips.EnsureDir(); err != nil {
		return domain.Clip{}, err
	}
	outMP4 := r.cfg.Clips.PathFor(ev)
	rawPath := outMP4[:len(outMP4)-len(filepath.Ext(outMP4))] + ".es"

	req := &domain.PlaybackRequest{
		EventUnix:   ev.SessionUnix(),
		DurationSec: r.cfg.DurationSec,
		PreRollSec:  r.cfg.PreRollSec,
		Speed:       1,
		EndTime:     0, // native open-ended seek
	}
	if win.BeforeSec > 0 || win.AfterSec > 0 {
		// PreRollSec is already exactly "how far back to seek" and DurationSec
		// "total final clip length" — miss.PlanPaddedSeek reaches across SD
		// segment boundaries using these same two numbers, just larger than
		// the small keyframe-sync default. No new PlaybackRequest fields needed.
		req.PreRollSec = win.BeforeSec
		req.DurationSec = win.BeforeSec + win.AfterSec
	} else if r.cfg.FullEvent {
		req.FullEvent = true
		req.MaxDurationSec = r.cfg.MaxDurationSec
	}

	rc, err := conn.DownloadPlayback(ctx, req)
	if err != nil {
		return domain.Clip{}, err
	}
	defer rc.Close()

	// SD seek often starts mid-GOP; discard leading P-frames until VPS/SPS/PPS+IDR.
	// Pre-roll in the seek means the event still lands after sync.
	_, synced, err := live.WaitAnnexBSync(rc, 15*time.Second, 4<<20)
	if err != nil {
		return domain.Clip{}, fmt.Errorf("recorder: stream_no_keyframe: %w", err)
	}

	// After sync, capture finalDur + remaining pre-roll (for ffmpeg trim).
	trim := req.TrimStartSec
	finalDur := req.DurationSec
	if finalDur <= 0 {
		finalDur = r.cfg.DurationSec
	}
	copySecs := trim + finalDur + 2
	// req.CaptureSec is miss's own budget for this exact seek (trim + final
	// duration + slack for the 0x10e wait and stream startup, computed by
	// planForSegment) — it was previously ignored here, so a slow 0x10e or
	// stream start could silently truncate the copy before ffmpeg ever got a
	// chance to trim to the right length. Use it as a floor, not a ceiling:
	// this only ever raises copySecs to cover the time miss knows the seek
	// itself may already have consumed.
	if req.CaptureSec > copySecs {
		copySecs = req.CaptureSec
	}
	copyCtx, cancel := context.WithTimeout(ctx, time.Duration(copySecs+10)*time.Second)
	defer cancel()

	f, err := os.Create(rawPath)
	if err != nil {
		return domain.Clip{}, err
	}
	n, copyErr := copyUntil(copyCtx, f, synced, time.Duration(copySecs)*time.Second)
	_ = f.Close()
	if copyErr != nil && n == 0 {
		_ = os.Remove(rawPath)
		return domain.Clip{}, copyErr
	}
	if n == 0 {
		_ = os.Remove(rawPath)
		return domain.Clip{}, fmt.Errorf("recorder: empty stream")
	}

	_ = os.Remove(outMP4)
	var fps float64
	if m, ok := conn.(streamFPSer); ok {
		fps = m.StreamFPS()
	}
	if err := remuxToMP4(ctx, r.cfg.FFmpeg, rawPath, outMP4, trim, finalDur, fps); err != nil {
		return domain.Clip{}, fmt.Errorf("recorder: remux_failed: %w", err)
	}
	_ = os.Remove(rawPath)
	st, err := os.Stat(outMP4)
	if err != nil {
		return domain.Clip{}, err
	}
	if st.Size() == 0 {
		_ = os.Remove(outMP4)
		return domain.Clip{}, fmt.Errorf("recorder: remux produced empty mp4")
	}
	return domain.Clip{Path: outMP4, EventKey: ev.Key(), Bytes: st.Size(), CreatedAt: time.Now().UTC()}, nil
}

func copyUntil(ctx context.Context, dst io.Writer, src io.Reader, max time.Duration) (int64, error) {
	deadline := time.Now().Add(max)
	buf := make([]byte, 32*1024)
	var n int64
	for {
		select {
		case <-ctx.Done():
			if n > 0 {
				return n, nil
			}
			return n, ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return n, nil
		}
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			n += int64(nw)
			if werr != nil {
				return n, werr
			}
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return n, err
		}
	}
}

// annexBFormat returns ffmpeg -f value for annex-B elementary stream.
func annexBFormat(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	n, _ := f.Read(buf)
	buf = buf[:n]

	sawH264, sawHEVC := false, false
	for i := 0; i+5 < len(buf); i++ {
		var sc int
		if buf[i] == 0 && buf[i+1] == 0 && buf[i+2] == 0 && buf[i+3] == 1 {
			sc = 4
		} else if buf[i] == 0 && buf[i+1] == 0 && buf[i+2] == 1 {
			sc = 3
		} else {
			continue
		}
		nal0 := buf[i+sc]
		hevcType := (nal0 >> 1) & 0x3f
		if hevcType == 32 || hevcType == 33 || hevcType == 34 {
			sawHEVC = true
		}
		avcType := nal0 & 0x1f
		if avcType == 7 || avcType == 8 {
			sawH264 = true
		}
		i += sc
	}
	if sawHEVC {
		return "hevc", nil
	}
	if sawH264 {
		return "h264", nil
	}
	return "h264", nil
}

// defaultFPS labels the raw stream when the camera's real rate is unknown.
const defaultFPS = 15.0

// streamFPSer is implemented by conns that can measure the real frame rate
// from the camera's frame timestamps (miss.Conn).
type streamFPSer interface{ StreamFPS() float64 }

// sanitizeFPS rejects missing or implausible measured rates.
func sanitizeFPS(fps float64) float64 {
	if fps < 1 || fps > 60 {
		return defaultFPS
	}
	return fps
}

func buildRemuxBaseArgs(format, in string, trimStartSec, durationSec int, fps float64) []string {
	// Invent CFR pts at the measured fps (the raw stream has none; a wrong
	// rate makes the clip play too fast/slow). -ss/-t after -i trim
	// post-decode so the pre-roll+sync buffer still contains the event.
	rate := strconv.FormatFloat(sanitizeFPS(fps), 'f', 3, 64)
	args := []string{"-y", "-loglevel", "error", "-fflags", "+genpts", "-f", format, "-r", rate, "-i", in}
	if trimStartSec > 0 {
		args = append(args, "-ss", strconv.Itoa(trimStartSec))
	}
	if durationSec > 0 {
		args = append(args, "-t", strconv.Itoa(durationSec))
	}
	return args
}

func remuxToMP4(ctx context.Context, ffmpeg, in, out string, trimStartSec, durationSec int, fps float64) error {
	format, err := annexBFormat(in)
	if err != nil {
		return err
	}
	orders := []string{format}
	if format == "h264" {
		orders = append(orders, "hevc")
	} else {
		orders = append(orders, "h264")
	}
	scale := "scale='min(1920,iw)':-2:flags=bicubic,setsar=1"
	var last error
	for _, format := range orders {
		var attempts [][]string
		inArgs := buildRemuxBaseArgs(format, in, trimStartSec, durationSec, fps)
		x264 := []string{
			"-vf", scale, "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
			"-g", "30", "-keyint_min", "30", "-bf", "0",
			"-pix_fmt", "yuv420p", "-movflags", "+faststart", out,
		}
		if format == "h264" {
			attempts = [][]string{
				append(append([]string{}, inArgs...), "-c", "copy", "-movflags", "+faststart", out),
				append(append([]string{}, inArgs...), x264...),
			}
		} else {
			attempts = [][]string{
				append(append([]string{}, inArgs...), x264...),
				append(append([]string{}, inArgs...), "-c", "copy", "-tag:v", "hvc1", "-movflags", "+faststart", out),
			}
		}
		for _, args := range attempts {
			_ = os.Remove(out)
			cmd := exec.CommandContext(ctx, ffmpeg, args...)
			outb, err := cmd.CombinedOutput()
			if err != nil {
				last = fmt.Errorf("%w: %s", err, string(outb))
				continue
			}
			st, err := os.Stat(out)
			if err != nil || st.Size() == 0 {
				last = fmt.Errorf("empty output after remux (%s)", format)
				continue
			}
			return nil
		}
	}
	return last
}
