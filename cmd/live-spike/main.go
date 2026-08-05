package main

// live-spike joins the configured group VC with a sample MP4 (Telegram-side
// proof without Xiaomi). Usage:
//
//	go run ./cmd/live-spike -config configs/camwatch.yaml
//
// Requires telegram.live.{enabled,api_id,api_hash,session_file} and a logged-in
// user session (see scripts/tg_live_login.py).

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"camwatch/internal/config"
	"camwatch/internal/notify/live"
)

func main() {
	cfgPath := flag.String("config", "configs/camwatch.yaml", "config yaml")
	duration := flag.Duration("for", 60*time.Second, "how long to keep the test stream")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if !cfg.Telegram.LiveConfigured() {
		log.Error("enable telegram.live with api_id, api_hash, session_file")
		os.Exit(1)
	}
	sidecar := cfg.Telegram.Live.Sidecar
	if !filepath.IsAbs(sidecar) {
		if abs, err := filepath.Abs(sidecar); err == nil {
			sidecar = abs
		}
	}
	cfg.Telegram.Live.Sidecar = sidecar

	pub, err := live.NewPublisher(live.Config{
		Live:   cfg.Telegram.Live,
		ChatID: cfg.Telegram.LiveChatID(),
		Log:    log,
	})
	if err != nil {
		log.Error("publisher", "err", err)
		os.Exit(1)
	}
	defer pub.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting live test", "chat_id", cfg.Telegram.LiveChatID(), "for", *duration)
	if err := pub.StartTest(ctx, cfg.Telegram.LiveChatID()); err != nil {
		log.Error("start", "err", err)
		os.Exit(1)
	}
	fmt.Println("Playing sample into group VC — join the voice chat. Ctrl-C to stop.")

	select {
	case <-ctx.Done():
	case <-time.After(*duration):
	}
	_ = pub.Stop(context.Background())
	log.Info("stopped")
}
