package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"camwatch/internal/domain"
)

type Client struct {
	BotToken string
	ChatID   string
	HTTP     *http.Client
	// Upload is a separate client for SendFile: video/document uploads can
	// legitimately take much longer than the quick JSON calls HTTP is sized
	// for, and HTTP.Timeout must never be mutated post-construction (shared
	// between Notifier and Bot — see bot.go's poll-loop comment).
	Upload  *http.Client
	Retries int
}

func NewClient(botToken, chatID string) *Client {
	return &Client{
		BotToken: botToken,
		ChatID:   chatID,
		HTTP:     &http.Client{Timeout: 120 * time.Second},
		Upload:   &http.Client{Timeout: 10 * time.Minute},
		Retries:  3,
	}
}

// redactToken strips the bot token from an error's text. Telegram Bot API
// URLs embed the token in the path (apiURL below), and a failed http.Client
// request wraps that URL verbatim into a *url.Error — which callers here
// forward straight into user-visible chat messages (e.g. "Upload failed:
// %v"). Never return a raw transport error from this package.
func redactToken(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
}

// Notifier is the outbound clip delivery adapter (ports.Notifier).
type Notifier struct {
	*Client
}

func New(botToken, chatID string) *Notifier {
	return &Notifier{Client: NewClient(botToken, chatID)}
}

func (n *Notifier) NotifyEvent(ctx context.Context, ev domain.Event, clip domain.Clip, thumb []byte) error {
	_ = thumb
	caption := fmt.Sprintf("%s\n%s\ndid=%s\n%s",
		ev.EventType,
		time.Unix(ev.SessionUnix(), 0).Format(time.RFC3339),
		ev.DID,
		ev.FileID,
	)
	var last error
	for i := 0; i < n.Retries; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = n.SendFile(ctx, n.ChatID, clip.Path, caption)
		if last == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return last
}

func (c *Client) apiURL(method string) string {
	return fmt.Sprintf("https://api.telegram.org/bot%s/%s", c.BotToken, method)
}

func (c *Client) API(ctx context.Context, method string, payload any) (json.RawMessage, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL(method), body)
	if err != nil {
		return nil, redactToken(err, c.BotToken)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, redactToken(err, c.BotToken)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, err
	}
	if !wrap.OK {
		return nil, fmt.Errorf("telegram %s: %s", method, wrap.Description)
	}
	return wrap.Result, nil
}

func (c *Client) SendMessage(ctx context.Context, chatID, text string, keyboard any) error {
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if keyboard != nil {
		payload["reply_markup"] = keyboard
	}
	_, err := c.API(ctx, "sendMessage", payload)
	return err
}

func (c *Client) EditMessage(ctx context.Context, chatID string, messageID int64, text string, keyboard any) error {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if keyboard != nil {
		payload["reply_markup"] = keyboard
	}
	_, err := c.API(ctx, "editMessageText", payload)
	return err
}

func (c *Client) AnswerCallback(ctx context.Context, callbackID, text string) error {
	payload := map[string]any{"callback_query_id": callbackID}
	if text != "" {
		payload["text"] = text
	}
	_, err := c.API(ctx, "answerCallbackQuery", payload)
	return err
}

func (c *Client) SendFile(ctx context.Context, chatID, path, caption string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("chat_id", chatID)
	_ = w.WriteField("caption", caption)
	field := "document"
	method := "sendDocument"
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".mp4" || ext == ".mov" {
		field = "video"
		method = "sendVideo"
		_ = w.WriteField("supports_streaming", "true")
		// Explicit size prevents some Telegram clients from treating the video
		// as a square / wrong-aspect bubble when moov SAR is unset.
		if width, height, dur := probeVideoWH(path); width > 0 && height > 0 {
			_ = w.WriteField("width", fmt.Sprintf("%d", width))
			_ = w.WriteField("height", fmt.Sprintf("%d", height))
			if dur > 0 {
				_ = w.WriteField("duration", fmt.Sprintf("%d", dur))
			}
		}
	}
	part, err := w.CreateFormFile(field, filepath.Base(path))
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, f); err != nil {
		return err
	}
	_ = w.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL(method), &buf)
	if err != nil {
		return redactToken(err, c.BotToken)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := c.Upload.Do(req)
	if err != nil {
		return redactToken(err, c.BotToken)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var resp struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &resp)
	if res.StatusCode != 200 || !resp.OK {
		return fmt.Errorf("telegram: %s: %s", res.Status, resp.Description)
	}
	return nil
}

// probeVideoWH returns pixel size and duration seconds via ffprobe (best-effort).
func probeVideoWH(path string) (width, height, durationSec int) {
	cmd := exec.Command("ffprobe", "-v", "error",
		"-select_streams", "v:0",
		"-show_entries", "stream=width,height:format=duration",
		"-of", "csv=p=0:s=x",
		path,
	)
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, 0
	}
	// csv:s=x → "2304x1296x26.667000" or two lines depending on ffprobe version.
	s := strings.TrimSpace(string(out))
	s = strings.ReplaceAll(s, "\n", "x")
	parts := strings.Split(s, "x")
	if len(parts) >= 2 {
		fmt.Sscanf(parts[0], "%d", &width)
		fmt.Sscanf(parts[1], "%d", &height)
	}
	if len(parts) >= 3 {
		var d float64
		fmt.Sscanf(parts[2], "%f", &d)
		durationSec = int(d + 0.5)
	}
	return width, height, durationSec
}
