package config

import "testing"

func TestLiveConfigured(t *testing.T) {
	tg := TelegramCfg{
		ChatID: "-1001",
		Live: LiveCfg{
			Enabled:     true,
			APIID:       1,
			APIHash:     "abc",
			SessionFile: "./data/tg_user.session",
		},
	}
	if !tg.LiveConfigured() {
		t.Fatal("expected configured")
	}
	if tg.LiveChatID() != "-1001" {
		t.Fatalf("chat %s", tg.LiveChatID())
	}
	tg.Live.ChatID = "-1002"
	if tg.LiveChatID() != "-1002" {
		t.Fatalf("override %s", tg.LiveChatID())
	}
	tg.Live.Enabled = false
	if tg.LiveConfigured() {
		t.Fatal("disabled should not be configured")
	}
}
