package config

import (
	"fmt"
	"os"
	"time"

	"camwatch/internal/domain"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	LogOnly      bool          `yaml:"log_only"`      // poll+dedupe without MTP/Telegram
	MTPVerbose   bool          `yaml:"mtp_verbose"`   // full wire-level CHK/KCP/CNT/media dumps
	MTPProtocol  bool          `yaml:"mtp_protocol"`  // concise MTP session milestones only
	Devices      []DeviceCfg   `yaml:"devices"`
	Xiaomi       XiaomiCfg     `yaml:"xiaomi"`
	Clip         ClipCfg       `yaml:"clip"`
	Telegram     TelegramCfg   `yaml:"telegram"`
	Store        StoreCfg      `yaml:"store"`
}

type DeviceCfg struct {
	DID    string `yaml:"did"`
	Model  string `yaml:"model"`
	Region string `yaml:"region"`
}

func (d DeviceCfg) Domain() domain.Device {
	return domain.Device{DID: d.DID, Model: d.Model, Region: d.Region}
}

type XiaomiCfg struct {
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	SID         string `yaml:"sid"`
	SessionFile string `yaml:"session_file"`
	UserID      string `yaml:"user_id"` // when using pass_token refresh
	PassToken   string `yaml:"pass_token"`
}

type ClipCfg struct {
	DurationSec int    `yaml:"duration_sec"`
	OutDir      string `yaml:"out_dir"`
	FFmpeg      string `yaml:"ffmpeg"` // path; default "ffmpeg"
	// FullEvent: record to the end of the camera's recording for the event
	// (cloud events have no end time). duration_sec becomes the minimum.
	// Nil/omitted => true.
	FullEvent *bool `yaml:"full_event"`
	// MaxDurationSec caps a full-event clip (default 180). Guards cameras
	// that record continuously, where the recording never "ends".
	MaxDurationSec int `yaml:"max_duration_sec"`
	// LeadSec: the clip starts this many seconds before the event (default 10,
	// 0 = start at the event). Never starts after it.
	LeadSec *int `yaml:"lead_sec"`
}

// Lead returns the lead-in seconds (default 10).
func (c ClipCfg) Lead() int {
	if c.LeadSec == nil {
		return 10
	}
	if *c.LeadSec < 0 {
		return 0
	}
	return *c.LeadSec
}

// FullEventEnabled reports whether full-event recording is on (default true).
func (c ClipCfg) FullEventEnabled() bool { return c.FullEvent == nil || *c.FullEvent }

type TelegramCfg struct {
	BotToken       string   `yaml:"bot_token"`
	ChatID         string   `yaml:"chat_id"`          // destination for auto-notify clips
	BotEnabled     bool     `yaml:"bot_enabled"`
	AllowDM        *bool    `yaml:"allow_dm"`         // nil/omitted => true; private chats may use commands
	AllowedChatIDs []string `yaml:"allowed_chat_ids"` // extra chats/users allowed to command the bot

	// Live group voice-chat publish (ntgcalls via Python sidecar). Optional.
	// Requires a user MTProto session — Bot API cannot join voice chats.
	Live LiveCfg `yaml:"live"`
}

// LiveCfg configures Telegram group VC publishing via PyTgCalls/ntgcalls sidecar.
type LiveCfg struct {
	Enabled     bool   `yaml:"enabled"`
	APIID       int    `yaml:"api_id"`
	APIHash     string `yaml:"api_hash"`
	SessionFile string `yaml:"session_file"` // Telethon/Pyrogram string session or path
	ChatID      string `yaml:"chat_id"`      // VC target; empty => telegram.chat_id
	Python      string `yaml:"python"`       // default "python3"
	Sidecar     string `yaml:"sidecar"`      // path to tg_live_sidecar.py
	FFmpeg      string `yaml:"ffmpeg"`       // empty => clip.ffmpeg
	Width       int    `yaml:"width"`        // output width for VC (default 1280)
	Height      int    `yaml:"height"`       // default 720
	FPS         int    `yaml:"fps"`          // default 25
}

// LiveChatID returns the group/channel id used for voice-chat publish.
func (t TelegramCfg) LiveChatID() string {
	if t.Live.ChatID != "" {
		return t.Live.ChatID
	}
	return t.ChatID
}

// LiveConfigured reports whether live publish is enabled with required MTProto fields.
func (t TelegramCfg) LiveConfigured() bool {
	return t.Live.Enabled && t.Live.APIID != 0 && t.Live.APIHash != "" && t.Live.SessionFile != ""
}

// DMAllowed reports whether private (positive) chat ids may use bot commands.
func (t TelegramCfg) DMAllowed() bool {
	if t.AllowDM == nil {
		return true
	}
	return *t.AllowDM
}

type StoreCfg struct {
	SQLite string `yaml:"sqlite"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Expand ${VAR} / $VAR against the process environment before parsing, so
	// secrets (telegram.bot_token, telegram.live.api_hash, xiaomi credentials)
	// can live in an env file / docker-compose `environment:` block instead of
	// being hardcoded in a YAML file that risks ending up in version control.
	b = []byte(os.ExpandEnv(string(b)))
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = 45 * time.Second
	}
	if c.Xiaomi.SID == "" {
		c.Xiaomi.SID = "xiaomiio"
	}
	if c.Xiaomi.SessionFile == "" {
		c.Xiaomi.SessionFile = "./data/session.json"
	}
	if c.Clip.DurationSec <= 0 {
		c.Clip.DurationSec = 20
	}
	if c.Clip.MaxDurationSec <= 0 {
		c.Clip.MaxDurationSec = 180
	}
	if c.Clip.OutDir == "" {
		c.Clip.OutDir = "./data/clips"
	}
	if c.Clip.FFmpeg == "" {
		c.Clip.FFmpeg = "ffmpeg"
	}
	if c.Store.SQLite == "" {
		c.Store.SQLite = "./data/camwatch.db"
	}
	for i := range c.Devices {
		if c.Devices[i].Region == "" {
			c.Devices[i].Region = "de"
		}
	}
	if c.Telegram.Live.Python == "" {
		c.Telegram.Live.Python = "python3"
	}
	if c.Telegram.Live.Sidecar == "" {
		c.Telegram.Live.Sidecar = "./scripts/tg_live_sidecar.py"
	}
	if c.Telegram.Live.FFmpeg == "" {
		c.Telegram.Live.FFmpeg = c.Clip.FFmpeg
	}
	if c.Telegram.Live.Width <= 0 {
		c.Telegram.Live.Width = 1280
	}
	if c.Telegram.Live.Height <= 0 {
		c.Telegram.Live.Height = 720
	}
	if c.Telegram.Live.FPS <= 0 {
		c.Telegram.Live.FPS = 25
	}
	if c.Telegram.Live.SessionFile == "" {
		c.Telegram.Live.SessionFile = "./data/tg_user.session"
	}
}

func (c *Config) validate() error {
	if len(c.Devices) == 0 {
		return fmt.Errorf("config: at least one device required")
	}
	for _, d := range c.Devices {
		if d.DID == "" || d.Model == "" {
			return fmt.Errorf("config: device needs did and model")
		}
	}
	hasSession := c.Xiaomi.SessionFile != ""
	hasLogin := c.Xiaomi.Username != "" && c.Xiaomi.Password != ""
	hasPass := c.Xiaomi.UserID != "" && c.Xiaomi.PassToken != ""
	if !hasSession && !hasLogin && !hasPass {
		return fmt.Errorf("config: provide xiaomi session_file, username/password, or user_id/pass_token")
	}
	if !c.LogOnly && (c.Telegram.BotToken == "" || c.Telegram.ChatID == "") {
		return fmt.Errorf("config: telegram bot_token and chat_id required unless log_only")
	}
	if c.Telegram.BotEnabled && (c.Telegram.BotToken == "" || c.Telegram.ChatID == "") {
		return fmt.Errorf("config: telegram.bot_enabled needs bot_token and chat_id")
	}
	if c.Telegram.Live.Enabled {
		if c.Telegram.Live.APIID == 0 || c.Telegram.Live.APIHash == "" {
			return fmt.Errorf("config: telegram.live.enabled needs api_id and api_hash")
		}
		if c.Telegram.Live.SessionFile == "" {
			return fmt.Errorf("config: telegram.live.enabled needs session_file")
		}
		if c.Telegram.LiveChatID() == "" {
			return fmt.Errorf("config: telegram.live needs chat_id (live.chat_id or telegram.chat_id)")
		}
	}
	return nil
}
