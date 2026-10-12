package telegram

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"
)

const loginReplyTimeout = 5 * time.Minute

var errLoginCancelled = errors.New("login cancelled")

// isPrivateChat reports whether chatID is a user DM (positive id), never a
// group or channel — captcha and verification codes must not be posted there.
func isPrivateChat(chatID string) bool {
	n, err := strconv.ParseInt(chatID, 10, 64)
	return err == nil && n > 0
}

func (b *Bot) cmdLogin(ctx context.Context, chatID string) {
	if b.Login == nil {
		b.send(ctx, chatID, "Login is not configured (set xiaomi.username and xiaomi.password).", nil)
		return
	}
	if !isPrivateChat(chatID) {
		b.send(ctx, chatID, "Use /login in a private chat with the bot, not a group or channel.", nil)
		return
	}
	b.mu.Lock()
	if b.loginOn {
		b.mu.Unlock()
		b.send(ctx, chatID, "A login is already in progress.", nil)
		return
	}
	b.loginOn = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.loginOn = false
		b.mu.Unlock()
	}()

	b.send(ctx, chatID, "Logging in to Xiaomi… (/cancel to abort)", nil)
	err := b.Login(ctx, &chatPrompter{b: b, chatID: chatID})
	switch {
	case err == nil:
		b.send(ctx, chatID, "✅ Logged in; session saved.", nil)
	case errors.Is(err, errLoginCancelled):
		b.send(ctx, chatID, "Login cancelled.", nil)
	default:
		b.Log.Error("telegram login", "err", err)
		b.send(ctx, chatID, "❌ Login failed: "+html.EscapeString(err.Error()), nil)
	}
}

// deliverReply hands text to a pending login prompt for chatID, if any.
func (b *Bot) deliverReply(chatID, text string) bool {
	b.mu.Lock()
	ch, ok := b.waiters[chatID]
	b.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- text:
	default:
	}
	return true
}

func (b *Bot) awaitReply(ctx context.Context, chatID string) (string, error) {
	ch := make(chan string, 1)
	b.mu.Lock()
	if b.waiters == nil {
		b.waiters = map[string]chan string{}
	}
	b.waiters[chatID] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.waiters, chatID)
		b.mu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(loginReplyTimeout):
		return "", errors.New("timed out waiting for reply")
	case txt := <-ch:
		txt = strings.TrimSpace(txt)
		if txt == "/cancel" {
			return "", errLoginCancelled
		}
		return txt, nil
	}
}

// chatPrompter implements auth.Prompter over a private Telegram chat.
type chatPrompter struct {
	b      *Bot
	chatID string
}

func (p *chatPrompter) Captcha(img []byte) (string, error) {
	ctx := context.Background()
	if err := p.b.Client.SendPhoto(ctx, p.chatID, img, "Xiaomi captcha — reply with the text shown"); err != nil {
		return "", err
	}
	return p.b.awaitReply(ctx, p.chatID)
}

func (p *chatPrompter) Code(phone, email string) (string, error) {
	ctx := context.Background()
	dest := phone
	if dest == "" {
		dest = email
	}
	p.b.send(ctx, p.chatID, fmt.Sprintf("Xiaomi sent a verification code to %s — reply with it.", html.EscapeString(dest)), nil)
	return p.b.awaitReply(ctx, p.chatID)
}
