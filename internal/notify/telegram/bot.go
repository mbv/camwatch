package telegram

import (
	"camwatch/internal/xiaomi/auth"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/orchestrator"
	"camwatch/internal/ports"
)

const (
	pageSize    = 10
	pickTTL     = 24 * time.Hour
	longPollSec = 25
)

// DeviceSource exposes configured cameras (orchestrator).
type DeviceSource interface {
	Devices() []domain.Device
}

// Bot handles interactive timeline browse + on-demand clip requests.
type Bot struct {
	Client         *Client
	Clips          ports.ClipRequester
	Picks          ports.PickStore
	Devices        DeviceSource
	Live           ports.LiveController
	Log            *slog.Logger
	AllowDM        bool
	AllowedChatIDs []string
	// Login runs a Xiaomi password login, asking pr for captcha / 2FA codes.
	// nil disables /login.
	Login func(ctx context.Context, pr auth.Prompter) error

	offset  int64
	mu      sync.Mutex
	waiters map[string]chan string // chatID -> pending login reply
	loginOn bool
}

func NewBot(
	client *Client,
	clips ports.ClipRequester,
	picks ports.PickStore,
	devices DeviceSource,
	log *slog.Logger,
	allowDM bool,
	allowedChatIDs []string,
) *Bot {
	if log == nil {
		log = slog.Default()
	}
	return &Bot{
		Client:         client,
		Clips:          clips,
		Picks:          picks,
		Devices:        devices,
		Log:            log,
		AllowDM:        allowDM,
		AllowedChatIDs: append([]string(nil), allowedChatIDs...),
	}
}

func (b *Bot) Run(ctx context.Context) error {
	b.Log.Info("telegram bot started", "chat_id", b.Client.ChatID)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		updates, err := b.getUpdates(ctx)
		if err != nil {
			b.Log.Error("getUpdates", "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			b.offset = u.UpdateID + 1
			// Detach from getUpdates loop so Xiaomi/Telegram work cannot stall polling.
			go b.handleUpdate(context.WithoutCancel(ctx), u)
		}
	}
}

type update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *message       `json:"message"`
	ChannelPost   *message       `json:"channel_post"`
	CallbackQuery *callbackQuery `json:"callback_query"`
}

type message struct {
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
	Chat      struct {
		ID int64 `json:"id"`
	} `json:"chat"`
}

type callbackQuery struct {
	ID      string   `json:"id"`
	Data    string   `json:"data"`
	Message *message `json:"message"`
	From    struct {
		ID int64 `json:"id"`
	} `json:"from"`
}

func (b *Bot) getUpdates(ctx context.Context) ([]update, error) {
	payload := map[string]any{
		"timeout": longPollSec,
		"offset":  b.offset,
		// channel posts use channel_post (not message); groups/DMs use message.
		"allowed_updates": []string{"message", "channel_post", "callback_query"},
	}
	// Bound the long poll via context — never mutate shared Client.Timeout
	// (notifier/bot share the same *http.Client; concurrent Timeout writes race).
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(longPollSec+10)*time.Second)
	defer cancel()

	raw, err := b.Client.API(pollCtx, "getUpdates", payload)
	if err != nil {
		return nil, err
	}
	var list []update
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (b *Bot) allowedChat(chatID string) bool {
	if chatID == b.Client.ChatID {
		return true
	}
	for _, id := range b.AllowedChatIDs {
		if id == chatID {
			return true
		}
	}
	if b.AllowDM {
		if n, err := strconv.ParseInt(chatID, 10, 64); err == nil && n > 0 {
			return true
		}
	}
	return false
}

func (b *Bot) handleUpdate(ctx context.Context, u update) {
	if u.CallbackQuery != nil {
		b.handleCallback(ctx, u.CallbackQuery)
		return
	}
	// DMs/groups → message; channels → channel_post
	msg := u.Message
	if msg == nil {
		msg = u.ChannelPost
	}
	if msg == nil || msg.Text == "" {
		return
	}
	chatID := strconv.FormatInt(msg.Chat.ID, 10)
	if !b.allowedChat(chatID) {
		b.Log.Info("ignore chat", "chat_id", chatID)
		return
	}
	text := strings.TrimSpace(msg.Text)
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return
	}
	if !strings.HasPrefix(parts[0], "/") || parts[0] == "/cancel" {
		if b.deliverReply(chatID, text) {
			return
		}
	}
	cmd := strings.Split(parts[0], "@")[0]
	args := parts[1:]
	b.Log.Info("bot command", "cmd", cmd, "chat_id", chatID)
	switch cmd {
	case "/start", "/help":
		b.send(ctx, chatID, helpText(), nil)
	case "/devices":
		b.cmdDevices(ctx, chatID)
	case "/timeline":
		b.cmdTimeline(ctx, chatID, args)
	case "/live":
		b.cmdLive(ctx, chatID, args)
	case "/live_stop", "/stoplive":
		b.cmdLiveStop(ctx, chatID)
	case "/live_test":
		b.cmdLiveTest(ctx, chatID)
	case "/login":
		b.cmdLogin(ctx, chatID)
	default:
		b.send(ctx, chatID, "Unknown command. Try /help", nil)
	}
}

func helpText() string {
	return `<b>camwatch</b>
/timeline — today's events (UTC)
/timeline yesterday
/timeline 2026-07-28
/timeline 2026-07-28 &lt;did&gt;
/devices — configured cameras
/live [did] — publish camera live into group voice chat
/live_test — spike: play sample MP4 into voice chat (no camera)
/live_stop — stop live publish
/login — re-login to Xiaomi (private chat only; captcha/code asked here)
Tap an event to download the clip.`
}

func (b *Bot) cmdDevices(ctx context.Context, chatID string) {
	devs := b.Devices.Devices()
	if len(devs) == 0 {
		b.send(ctx, chatID, "No devices configured.", nil)
		return
	}
	var sb strings.Builder
	sb.WriteString("<b>Devices</b>\n")
	for _, d := range devs {
		fmt.Fprintf(&sb, "• <code>%s</code> %s (%s)\n", d.DID, d.Model, d.Region)
	}
	b.send(ctx, chatID, sb.String(), nil)
}

func (b *Bot) cmdLive(ctx context.Context, chatID string, args []string) {
	if b.Live == nil {
		_ = b.Client.SendMessage(ctx, chatID, "Live publish is not configured (telegram.live).", nil)
		return
	}
	if b.Live.LiveActive() {
		_ = b.Client.SendMessage(ctx, chatID, "Live already running. /live_stop first.", nil)
		return
	}
	did := ""
	if len(args) > 0 {
		did = args[0]
	}
	dev, err := b.resolveDevice(did)
	if err != nil {
		_ = b.Client.SendMessage(ctx, chatID, err.Error(), nil)
		return
	}
	_ = b.Client.SendMessage(ctx, chatID, fmt.Sprintf("Starting live for <code>%s</code>…", dev.DID), nil)
	// Detach from update ctx — MTP + remux + VC join outlive the webhook/poll tick.
	liveCtx := context.WithoutCancel(ctx)
	if err := b.Live.StartLive(liveCtx, dev); err != nil {
		b.Log.Error("live start", "err", err)
		_ = b.Client.SendMessage(ctx, chatID, "Live failed: "+err.Error(), nil)
		return
	}
	_ = b.Client.SendMessage(ctx, chatID, "Live started — join the group voice chat.", nil)
}

func (b *Bot) cmdLiveStop(ctx context.Context, chatID string) {
	if b.Live == nil {
		_ = b.Client.SendMessage(ctx, chatID, "Live publish is not configured.", nil)
		return
	}
	if err := b.Live.StopLive(ctx); err != nil {
		_ = b.Client.SendMessage(ctx, chatID, "Stop failed: "+err.Error(), nil)
		return
	}
	_ = b.Client.SendMessage(ctx, chatID, "Live stopped.", nil)
}

func (b *Bot) cmdLiveTest(ctx context.Context, chatID string) {
	if b.Live == nil {
		_ = b.Client.SendMessage(ctx, chatID, "Live test not available.", nil)
		return
	}
	_ = b.Client.SendMessage(ctx, chatID, "Starting live test (sample MP4)…", nil)
	if err := b.Live.StartLiveTest(ctx); err != nil {
		b.Log.Error("live test", "err", err)
		_ = b.Client.SendMessage(ctx, chatID, "Live test failed: "+err.Error(), nil)
		return
	}
	_ = b.Client.SendMessage(ctx, chatID, "Live test playing — join the group voice chat.", nil)
}

func (b *Bot) cmdTimeline(ctx context.Context, chatID string, args []string) {
	day, did, err := parseTimelineArgs(args)
	if err != nil {
		b.send(ctx, chatID, err.Error(), nil)
		return
	}
	dev, err := b.resolveDevice(did)
	if err != nil {
		b.send(ctx, chatID, err.Error(), nil)
		return
	}
	begin, end := utcDayBounds(day)
	sess := ports.TimelineSession{Device: dev, BeginMs: begin, EndMs: end}
	b.send(ctx, chatID, fmt.Sprintf("Fetching timeline for <code>%s</code>…", dev.DID), nil)

	tid, err := b.Picks.PutTimeline(ctx, sess, pickTTL)
	if err != nil {
		b.Log.Error("timeline put", "err", err)
		b.send(ctx, chatID, "Failed to store timeline session.", nil)
		return
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	b.Log.Info("timeline fetch", "did", dev.DID, "begin", begin, "end", end)
	text, kb, err := b.buildTimelinePage(fetchCtx, tid, sess, 0)
	if err != nil {
		b.Log.Error("timeline eventlist", "err", err)
		b.send(ctx, chatID, fmt.Sprintf("eventlist error: %v", err), nil)
		return
	}
	b.Log.Info("timeline ready", "did", dev.DID, "chars", len(text))
	b.send(ctx, chatID, text, kb)
}

func (b *Bot) send(ctx context.Context, chatID, text string, keyboard any) {
	if err := b.Client.SendMessage(ctx, chatID, text, normalizeKeyboard(keyboard)); err != nil {
		b.Log.Error("sendMessage", "chat_id", chatID, "err", err)
	}
}

// normalizeKeyboard drops empty inline keyboards so Telegram does not see
// {"inline_keyboard":null} (nil slice) which it rejects as non-Array.
func normalizeKeyboard(keyboard any) any {
	if keyboard == nil {
		return nil
	}
	switch kb := keyboard.(type) {
	case inlineKeyboard:
		if len(kb.InlineKeyboard) == 0 {
			return nil
		}
		return kb
	case *inlineKeyboard:
		if kb == nil || len(kb.InlineKeyboard) == 0 {
			return nil
		}
		return kb
	default:
		return keyboard
	}
}

func parseTimelineArgs(args []string) (day time.Time, did string, err error) {
	now := time.Now().UTC()
	day = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if len(args) == 0 {
		return day, "", nil
	}
	switch strings.ToLower(args[0]) {
	case "today":
		// day already today
	case "yesterday":
		day = day.AddDate(0, 0, -1)
	default:
		t, e := time.ParseInLocation("2006-01-02", args[0], time.UTC)
		if e != nil {
			return time.Time{}, "", fmt.Errorf("bad date %q (use today|yesterday|YYYY-MM-DD)", args[0])
		}
		day = t
	}
	if len(args) >= 2 {
		did = args[1]
	}
	return day, did, nil
}

func utcDayBounds(day time.Time) (beginMs, endMs int64) {
	begin := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	end := begin.Add(24*time.Hour - time.Millisecond)
	return begin.UnixMilli(), end.UnixMilli()
}

func (b *Bot) resolveDevice(did string) (domain.Device, error) {
	devs := b.Devices.Devices()
	if len(devs) == 0 {
		return domain.Device{}, fmt.Errorf("no devices configured")
	}
	if did == "" {
		return devs[0], nil
	}
	for _, d := range devs {
		if d.DID == did {
			return d, nil
		}
	}
	return domain.Device{}, fmt.Errorf("unknown did %s — /devices", did)
}

type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

func (b *Bot) buildTimelinePage(ctx context.Context, tid string, sess ports.TimelineSession, page int) (string, inlineKeyboard, error) {
	events, err := b.Clips.ListEvents(ctx, sess.Device, sess.BeginMs, sess.EndMs)
	if err != nil {
		return "", inlineKeyboard{}, err
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreateTimeMs > events[j].CreateTimeMs
	})
	totalPages := (len(events) + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page < 0 {
		page = 0
	}
	if page >= totalPages {
		page = totalPages - 1
	}
	start := page * pageSize
	end := start + pageSize
	if end > len(events) {
		end = len(events)
	}
	day := time.UnixMilli(sess.BeginMs).UTC().Format("2006-01-02")
	header := fmt.Sprintf("<b>Timeline</b> %s\n<code>%s</code>\n%d events — page %d/%d",
		day, sess.Device.DID, len(events), page+1, totalPages)

	var rows [][]inlineButton
	if len(events) == 0 {
		return header + "\n(no events)", inlineKeyboard{}, nil
	}
	for _, ev := range events[start:end] {
		id, err := b.Picks.PutEvent(ctx, ev, pickTTL)
		if err != nil {
			continue
		}
		label := fmt.Sprintf("%s %s",
			time.Unix(ev.SessionUnix(), 0).UTC().Format("15:04"),
			ev.EventType,
		)
		if len(label) > 60 {
			label = label[:57] + "…"
		}
		rows = append(rows, []inlineButton{{
			Text:         label,
			CallbackData: "g:" + id,
		}})
	}
	var nav []inlineButton
	if page > 0 {
		nav = append(nav, inlineButton{Text: "‹ Prev", CallbackData: fmt.Sprintf("p:%s:%d", tid, page-1)})
	}
	if page+1 < totalPages {
		nav = append(nav, inlineButton{Text: "Next ›", CallbackData: fmt.Sprintf("p:%s:%d", tid, page+1)})
	}
	if len(nav) > 0 {
		rows = append(rows, nav)
	}
	return header, inlineKeyboard{InlineKeyboard: rows}, nil
}

func (b *Bot) handleCallback(ctx context.Context, cq *callbackQuery) {
	chatID := b.Client.ChatID
	if cq.Message != nil {
		chatID = strconv.FormatInt(cq.Message.Chat.ID, 10)
	}
	if !b.allowedChat(chatID) {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "unauthorized")
		return
	}
	data := cq.Data
	switch {
	case strings.HasPrefix(data, "g:"):
		b.onGet(ctx, cq, chatID, strings.TrimPrefix(data, "g:"))
	case strings.HasPrefix(data, "pad:"):
		b.onPad(ctx, cq, chatID, strings.TrimPrefix(data, "pad:"))
	case strings.HasPrefix(data, "p:"):
		b.onPage(ctx, cq, chatID, strings.TrimPrefix(data, "p:"))
	default:
		_ = b.Client.AnswerCallback(ctx, cq.ID, "unknown")
	}
}

func (b *Bot) onPage(ctx context.Context, cq *callbackQuery, chatID, rest string) {
	parts := strings.Split(rest, ":")
	if len(parts) != 2 {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "bad page")
		return
	}
	page, err := strconv.Atoi(parts[1])
	if err != nil {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "bad page")
		return
	}
	sess, err := b.Picks.GetTimeline(ctx, parts[0])
	if err != nil {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "expired — /timeline again")
		return
	}
	text, kb, err := b.buildTimelinePage(ctx, parts[0], sess, page)
	if err != nil {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "error")
		_ = b.Client.SendMessage(ctx, chatID, err.Error(), nil)
		return
	}
	_ = b.Client.AnswerCallback(ctx, cq.ID, "")
	if cq.Message != nil {
		_ = b.Client.EditMessage(ctx, chatID, cq.Message.MessageID, text, normalizeKeyboard(kb))
	} else {
		b.send(ctx, chatID, text, kb)
	}
}

// onGet shows a padding chooser instead of downloading immediately — the
// same tapped row's keyboard is replaced with Default/±15s/±30s options,
// each carrying the same pick id forward via a "pad:" callback so no new
// PickStore entry or TTL is needed. onPad does the actual download once a
// choice is made.
func (b *Bot) onGet(ctx context.Context, cq *callbackQuery, chatID, id string) {
	if _, err := b.Picks.GetEvent(ctx, id); err != nil {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "expired — /timeline again")
		return
	}
	_ = b.Client.AnswerCallback(ctx, cq.ID, "")
	kb := inlineKeyboard{InlineKeyboard: [][]inlineButton{{
		{Text: "Default", CallbackData: "pad:" + id + ":0"},
		{Text: "±15s", CallbackData: "pad:" + id + ":15"},
		{Text: "±30s", CallbackData: "pad:" + id + ":30"},
	}}}
	if cq.Message == nil {
		return
	}
	if err := b.Client.EditMessage(ctx, chatID, cq.Message.MessageID, cq.Message.Text, normalizeKeyboard(kb)); err != nil {
		b.Log.Error("EditMessage (padding chooser)", "err", err)
	}
}

// onPad resolves a padding choice ("pad:<id>:<n>") and downloads exactly
// what onGet used to do unconditionally — n=0 is the plain default window.
func (b *Bot) onPad(ctx context.Context, cq *callbackQuery, chatID, rest string) {
	id, nStr, ok := strings.Cut(rest, ":")
	if !ok {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "bad padding")
		return
	}
	n, err := strconv.Atoi(nStr)
	if err != nil || n < 0 {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "bad padding")
		return
	}
	win := domain.ClipWindow{}
	if n > 0 {
		win = domain.ClipWindow{BeforeSec: n, AfterSec: n}
	}

	ev, err := b.Picks.GetEvent(ctx, id)
	if err != nil {
		_ = b.Client.AnswerCallback(ctx, cq.ID, "expired — /timeline again")
		return
	}
	dev := domain.Device{DID: ev.DID, Model: ev.Model, Region: ev.Region}
	if dev.DID == "" {
		devs := b.Devices.Devices()
		if len(devs) == 0 {
			_ = b.Client.AnswerCallback(ctx, cq.ID, "no device")
			return
		}
		dev = devs[0]
	}
	_ = b.Client.AnswerCallback(ctx, cq.ID, "Downloading…")
	_ = b.Client.SendMessage(ctx, chatID, fmt.Sprintf("Downloading %s %s…",
		time.Unix(ev.SessionUnix(), 0).UTC().Format("15:04"), ev.EventType), nil)

	if cb, ok := b.Clips.(interface{ NoteManualClip(string) }); ok {
		cb.NoteManualClip(dev.DID)
	}
	clip, err := b.Clips.RequestClip(ctx, dev, ev, win)
	if errors.Is(err, orchestrator.ErrBusy) {
		_ = b.Client.SendMessage(ctx, chatID,
			"Camera busy — another download is still running. Wait ~90s and tap again.", nil)
		return
	}
	if err != nil {
		b.Log.Error("RequestClip", "err", err)
		_ = b.Client.SendMessage(ctx, chatID, fmt.Sprintf("Download failed: %s", clipFailMsg(err)), nil)
		return
	}
	caption := fmt.Sprintf("%s\n%s\ndid=%s",
		ev.EventType,
		time.Unix(ev.SessionUnix(), 0).UTC().Format(time.RFC3339),
		ev.DID,
	)
	if err := b.Client.SendFile(ctx, chatID, clip.Path, caption); err != nil {
		_ = b.Client.SendMessage(ctx, chatID, fmt.Sprintf("Upload failed: %v", err), nil)
		return
	}
}

func clipFailMsg(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "media chk not alive"),
		strings.Contains(msg, "media session not ready"):
		return "camera media path not ready — tap again"
	case strings.Contains(msg, "timeline_unavailable"):
		return "timeline unavailable (RDT index)"
	case strings.Contains(msg, "segment_not_found"):
		return "segment not found in SD index"
	case strings.Contains(msg, "no 0x10e"):
		return "camera did not respond to playback request — retrying with a fresh connection"
	case strings.Contains(msg, "playback_rejected"):
		return "playback rejected by camera"
	case strings.Contains(msg, "stream_no_keyframe"):
		return "stream had no keyframe"
	case strings.Contains(msg, "remux_failed"):
		return "remux failed"
	default:
		return msg
	}
}
