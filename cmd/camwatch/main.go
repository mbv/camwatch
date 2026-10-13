package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"camwatch/internal/config"
	"camwatch/internal/domain"
	"camwatch/internal/mtp"
	"camwatch/internal/notify/live"
	"camwatch/internal/notify/telegram"
	"camwatch/internal/orchestrator"
	"camwatch/internal/ports"
	"camwatch/internal/recorder"
	"camwatch/internal/store/fs"
	"camwatch/internal/store/sqlite"
	"camwatch/internal/xiaomi/api"
	"camwatch/internal/xiaomi/auth"
	"camwatch/internal/xiaomi/miss"
	"golang.org/x/sync/errgroup"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "login" {
		os.Exit(runLogin(os.Args[2:]))
	}
	cfgPath := flag.String("config", "configs/camwatch.example.yaml", "path to config yaml")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	mtp.Verbose = cfg.MTPVerbose
	mtp.Protocol = cfg.MTPProtocol
	if cfg.MTPVerbose {
		log.Info("mtp_verbose enabled")
	} else if cfg.MTPProtocol {
		log.Info("mtp_protocol enabled")
	}

	authP := auth.NewProvider(
		cfg.Xiaomi.SID,
		cfg.Xiaomi.SessionFile,
		cfg.Xiaomi.Username,
		cfg.Xiaomi.Password,
		cfg.Xiaomi.UserID,
		cfg.Xiaomi.PassToken,
	)
	apiC := api.New(authP)
	store, err := sqlite.Open(cfg.Store.SQLite)
	if err != nil {
		log.Error("sqlite", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	clips := fs.New(cfg.Clip.OutDir)
	_ = clips.EnsureDir()

	var notifier portsNotifier
	var tgClient *telegram.Client
	if cfg.LogOnly {
		notifier = logNotifier{log: log}
	} else {
		tgClient = telegram.NewClient(cfg.Telegram.BotToken, cfg.Telegram.ChatID)
		notifier = &telegram.Notifier{Client: tgClient}
	}

	rec := recorder.New(recorder.Config{
		DurationSec:    cfg.Clip.DurationSec,
		LeadSec:        cfg.Clip.Lead(),
		FullEvent:      cfg.Clip.FullEventEnabled(),
		MaxDurationSec: cfg.Clip.MaxDurationSec,
		FFmpeg:         cfg.Clip.FFmpeg,
		Clips:       clips,
	})
	sessions := miss.NewSessionFactory(apiC, store)

	devices := make([]domain.Device, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		devices = append(devices, d.Domain())
	}

	orch := orchestrator.New(
		orchestrator.Config{
			PollInterval: cfg.PollInterval,
			LogOnly:      cfg.LogOnly,
			ClipDuration: cfg.Clip.DurationSec,
			MaxClipSec:   fullEventMax(cfg),
			Devices:      devices,
		},
		authP,
		apiC,
		sessions,
		rec,
		notifier,
		store,
		log,
	)

	var livePub ports.LivePublisher = live.Noop{}
	if cfg.Telegram.LiveConfigured() && !cfg.LogOnly {
		cfg.Telegram.Live.Sidecar = resolveSidecar(cfg.Telegram.Live.Sidecar, *cfgPath)
		pub, err := live.NewPublisher(live.Config{
			Live:   cfg.Telegram.Live,
			ChatID: cfg.Telegram.LiveChatID(),
			Log:    log,
		})
		if err != nil {
			log.Error("live publisher", "err", err)
			os.Exit(1)
		}
		livePub = pub
		orch.SetLivePublisher(pub)
		orch.ConfigureLive(
			cfg.Telegram.LiveChatID(),
			cfg.Telegram.Live.FFmpeg,
			cfg.Telegram.Live.Width,
			cfg.Telegram.Live.Height,
			cfg.Telegram.Live.FPS,
		)
		log.Info("live publish enabled", "chat_id", cfg.Telegram.LiveChatID(), "sidecar", cfg.Telegram.Live.Sidecar)
		defer func() { _ = livePub.Close() }()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		err := orch.Run(ctx)
		if err == context.Canceled {
			return nil
		}
		return err
	})

	if cfg.Telegram.BotEnabled && tgClient != nil {
		bot := telegram.NewBot(
			tgClient,
			orch,
			store,
			orch,
			log,
			cfg.Telegram.DMAllowed(),
			cfg.Telegram.AllowedChatIDs,
		)
		if cfg.Telegram.LiveConfigured() && !cfg.LogOnly {
			bot.Live = orch
		}
		if cfg.Xiaomi.Username != "" && cfg.Xiaomi.Password != "" {
			bot.Login = func(ctx context.Context, pr auth.Prompter) error {
				_, err := authP.LoginInteractive(ctx, cfg.Xiaomi.Username, cfg.Xiaomi.Password, pr)
				return err
			}
		}
		g.Go(func() error {
			err := bot.Run(ctx)
			if err == context.Canceled {
				return nil
			}
			return err
		})
	} else if cfg.Telegram.BotEnabled && cfg.LogOnly {
		log.Warn("telegram.bot_enabled ignored in log_only mode")
	}

	if err := g.Wait(); err != nil {
		log.Error("exit", "err", err)
		os.Exit(1)
	}
}

type portsNotifier interface {
	NotifyEvent(ctx context.Context, ev domain.Event, clip domain.Clip, thumb []byte) error
}

type logNotifier struct{ log *slog.Logger }

func (l logNotifier) NotifyEvent(ctx context.Context, ev domain.Event, clip domain.Clip, thumb []byte) error {
	_ = ctx
	_ = thumb
	l.log.Info("notify(log_only)", "type", ev.EventType, "fileId", ev.FileID, "path", clip.Path)
	return nil
}

func resolveSidecar(sidecar, cfgPath string) string {
	candidates := []string{sidecar}
	if !filepath.IsAbs(sidecar) {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(cfgPath), sidecar),
			filepath.Join(filepath.Dir(cfgPath), "..", sidecar),
			"/app/scripts/tg_live_sidecar.py",
		)
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	if abs, err := filepath.Abs(sidecar); err == nil {
		return abs
	}
	return sidecar
}

// fullEventMax is the longest auto clip, used to size the capture timeout.
func fullEventMax(cfg *config.Config) int {
	if cfg.Clip.FullEventEnabled() {
		return cfg.Clip.MaxDurationSec
	}
	return 0
}
