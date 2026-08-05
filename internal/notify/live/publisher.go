package live

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"camwatch/internal/config"
)

var (
	ErrLiveDisabled = errors.New("live: telegram.live not enabled")
	ErrLiveBusy     = errors.New("live: already publishing")
)

const testSource = "test"

// Publisher drives the PyTgCalls/ntgcalls Python sidecar.
type Publisher struct {
	cfg    config.LiveCfg
	chatID string
	log    *slog.Logger

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	active bool
}

type Config struct {
	Live   config.LiveCfg
	ChatID string
	Log    *slog.Logger
}

func NewPublisher(cfg Config) (*Publisher, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Live.APIID == 0 || cfg.Live.APIHash == "" || cfg.Live.SessionFile == "" {
		return nil, fmt.Errorf("live: missing api_id/api_hash/session_file")
	}
	sidecar := cfg.Live.Sidecar
	if sidecar == "" {
		sidecar = "./scripts/tg_live_sidecar.py"
	}
	if _, err := os.Stat(sidecar); err != nil {
		return nil, fmt.Errorf("live: sidecar %s: %w", sidecar, err)
	}
	return &Publisher{
		cfg:    cfg.Live,
		chatID: cfg.ChatID,
		log:    cfg.Log,
	}, nil
}

func (p *Publisher) ensure(ctx context.Context) error {
	_ = ctx
	if p.cmd != nil && p.cmd.Process != nil {
		return nil
	}
	sidecar, err := filepath.Abs(p.cfg.Sidecar)
	if err != nil {
		return err
	}
	// Dedicated protocol pipe (child fd 3). stdout is polluted by MTProto libs.
	protoR, protoW, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(p.cfg.Python, "-u", sidecar)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TG_API_ID=%d", p.cfg.APIID),
		"TG_API_HASH="+p.cfg.APIHash,
		"TG_SESSION_FILE="+p.cfg.SessionFile,
		"PYTHONUNBUFFERED=1",
		"CW_PROTO_FD=3",
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr // library noise → docker logs, not the protocol reader
	cmd.ExtraFiles = []*os.File{protoW}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = protoR.Close()
		_ = protoW.Close()
		return err
	}
	p.log.Info("live starting sidecar", "path", sidecar)
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = protoR.Close()
		_ = protoW.Close()
		return fmt.Errorf("live: start sidecar: %w", err)
	}
	_ = protoW.Close() // child holds the write end
	p.cmd = cmd
	p.stdin = stdin
	p.stdout = bufio.NewReader(protoR)

	resp, err := p.readResp(45 * time.Second)
	if err != nil {
		_ = p.Close()
		return fmt.Errorf("live: sidecar ready: %w", err)
	}
	if !resp.OK {
		_ = p.Close()
		return fmt.Errorf("live: sidecar: %s", resp.Error)
	}
	p.log.Info("live sidecar ready", "event", resp.Event)
	return nil
}

type sidecarResp struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Event   string `json:"event"`
	ChatID  int64  `json:"chat_id"`
	Playing any    `json:"playing"`
}

func (p *Publisher) readResp(timeout time.Duration) (sidecarResp, error) {
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return sidecarResp{}, fmt.Errorf("timeout waiting for sidecar")
		}
		type result struct {
			line string
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			line, err := p.stdout.ReadString('\n')
			ch <- result{line, err}
		}()
		select {
		case <-time.After(remain):
			return sidecarResp{}, fmt.Errorf("timeout waiting for sidecar")
		case r := <-ch:
			if r.err != nil {
				return sidecarResp{}, r.err
			}
			line := strings.TrimSpace(r.line)
			if line == "" {
				continue
			}
			// Skip non-protocol stdout noise from MTProto libs.
			if line[0] != '{' {
				p.log.Debug("live sidecar stdout skip", "line", truncate(line, 120))
				continue
			}
			var resp sidecarResp
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				p.log.Warn("live sidecar bad json", "line", truncate(line, 120), "err", err)
				continue
			}
			return resp, nil
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (p *Publisher) send(ctx context.Context, msg map[string]any) (sidecarResp, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensure(ctx); err != nil {
		return sidecarResp{}, err
	}
	b, _ := json.Marshal(msg)
	b = append(b, '\n')
	p.log.Info("live sidecar send", "cmd", msg["cmd"], "chat_id", msg["chat_id"])
	if _, err := p.stdin.Write(b); err != nil {
		return sidecarResp{}, err
	}
	return p.readResp(90 * time.Second)
}

func (p *Publisher) parseChatID(chatID string) (int64, error) {
	if chatID == "" {
		chatID = p.chatID
	}
	return strconv.ParseInt(chatID, 10, 64)
}

func (p *Publisher) StartCall(ctx context.Context, chatID string, sourceURL string) error {
	id, err := p.parseChatID(chatID)
	if err != nil {
		return fmt.Errorf("live: chat_id: %w", err)
	}
	if sourceURL == "" {
		return fmt.Errorf("live: empty source")
	}
	resp, err := p.send(ctx, map[string]any{
		"cmd":     "start",
		"chat_id": id,
		"source":  sourceURL,
	})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("live: start: %s", resp.Error)
	}
	p.mu.Lock()
	p.active = true
	p.mu.Unlock()
	return nil
}

func (p *Publisher) StartTest(ctx context.Context, chatID string) error {
	id, err := p.parseChatID(chatID)
	if err != nil {
		return fmt.Errorf("live: chat_id: %w", err)
	}
	resp, err := p.send(ctx, map[string]any{
		"cmd":     "start",
		"chat_id": id,
		"source":  testSource,
	})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("live: start test: %s", resp.Error)
	}
	p.mu.Lock()
	p.active = true
	p.mu.Unlock()
	p.log.Info("live test stream started", "chat_id", id)
	return nil
}

func (p *Publisher) Stop(ctx context.Context) error {
	_ = ctx
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stdin == nil {
		p.active = false
		return nil
	}
	b, _ := json.Marshal(map[string]any{"cmd": "stop"})
	b = append(b, '\n')
	_, _ = p.stdin.Write(b)
	_, _ = p.readResp(15 * time.Second)
	p.active = false
	return nil
}

func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = false
	if p.stdin != nil {
		_ = p.stdin.Close()
		p.stdin = nil
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		p.cmd = nil
	}
	return nil
}

// ServeAnnexB decodes camera annex-B to framed raw yuv420p over HTTP for the
// Telegram sidecar. Raw (not H.264/MPEG-TS) avoids a second lossy decode and
// mid-GOP green corruption; frames are always aligned to width*height*3/2.
func ServeAnnexB(ctx context.Context, ffmpeg string, width, height, fps int, r io.Reader, log *slog.Logger) (url string, cancel func(), err error) {
	if ffmpeg == "" {
		ffmpeg = "ffmpeg"
	}
	if width <= 0 {
		width = 1280
	}
	if height <= 0 {
		height = 720
	}
	if fps <= 0 {
		fps = 25
	}
	// yuv420p requires even dimensions.
	width &^= 1
	height &^= 1
	if log == nil {
		log = slog.Default()
	}

	syn, synced, err := WaitAnnexBSync(r, 12*time.Second, 2<<20)
	if err != nil {
		return "", nil, err
	}
	log.Info("live annex-B sync", "format", syn.Format, "prefix_bytes", len(syn.Prefix))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	frameSize := width * height * 3 / 2
	args := []string{
		"-hide_banner", "-loglevel", "error",
		"-fflags", "+genpts+discardcorrupt", "-err_detect", "ignore_err",
		"-flags", "low_delay",
		"-probesize", "2M", "-analyzeduration", "2M",
		"-f", syn.Format, "-i", "pipe:0",
		"-an",
		"-vf", fmt.Sprintf("scale=%d:%d:flags=bilinear,fps=%d,format=yuv420p", width, height, fps),
		"-fps_mode", "cfr",
		"-f", "rawvideo", "-pix_fmt", "yuv420p",
		"-s", fmt.Sprintf("%dx%d", width, height),
		"-r", strconv.Itoa(fps),
		"pipe:1",
	}
	cmd := exec.Command(ffmpeg, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = ln.Close()
		return "", nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = ln.Close()
		return "", nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		return "", nil, err
	}

	go func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, synced)
	}()

	liveBuf := newRawFrameBuf(frameSize, fps*3) // ~3s ring
	var waitOnce sync.Once
	reap := func() {
		waitOnce.Do(func() {
			_ = cmd.Wait()
		})
	}
	go func() {
		buf := make([]byte, frameSize)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				liveBuf.Write(buf[:n])
			}
			if err != nil {
				liveBuf.Close()
				reap()
				return
			}
		}
	}()

	// Do not advertise the URL until at least one full frame exists — otherwise
	// the sidecar joins an empty raw stream and Telegram shows nothing.
	waitCtx, waitCancel := context.WithTimeout(ctx, 20*time.Second)
	defer waitCancel()
	waitDone := make(chan error, 1)
	go func() {
		fr, _, dead := liveBuf.WaitFrame()
		if dead || len(fr) != frameSize {
			waitDone <- fmt.Errorf("live: remux produced no frames")
			return
		}
		waitDone <- nil
	}()
	select {
	case <-waitCtx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		reap()
		liveBuf.Close()
		_ = ln.Close()
		return "", nil, fmt.Errorf("live: timed out waiting for first decoded frame")
	case err := <-waitDone:
		if err != nil {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			reap()
			liveBuf.Close()
			_ = ln.Close()
			return "", nil, err
		}
	}
	log.Info("live first frame ready", "frame_bytes", frameSize)
	serveLive := func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)

		frame, seq, dead := liveBuf.WaitFrame()
		if dead || len(frame) != frameSize {
			http.Error(w, "remux not producing frames", http.StatusServiceUnavailable)
			return
		}
		if _, err := w.Write(frame); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}

		for {
			var done bool
			frame, seq, done = liveBuf.WaitNext(seq)
			if done && frame == nil {
				return
			}
			if frame == nil {
				continue
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-req.Context().Done():
				return
			case <-ctx.Done():
				return
			default:
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/live.yuv", serveLive)
	mux.HandleFunc("/live.h264", serveLive)
	mux.HandleFunc("/live.ts", serveLive)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	cancel = func() {
		_ = srv.Close()
		_ = ln.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		reap()
		liveBuf.Close()
	}
	u := fmt.Sprintf("http://127.0.0.1:%d/live.yuv?w=%d&h=%d&fps=%d", port, width, height, fps)
	log.Info("live raw endpoint", "url", u, "format", syn.Format, "frame_bytes", frameSize)
	return u, cancel, nil
}

func totalSize(bufs [][]byte) int {
	n := 0
	for _, b := range bufs {
		n += len(b)
	}
	return n
}
