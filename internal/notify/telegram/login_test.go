package telegram

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIsPrivateChat(t *testing.T) {
	for id, want := range map[string]bool{"123": true, "-1003902466377": false, "-5": false, "x": false} {
		if got := isPrivateChat(id); got != want {
			t.Fatalf("isPrivateChat(%q)=%v want %v", id, got, want)
		}
	}
}

func TestAwaitReplyDelivery(t *testing.T) {
	b := &Bot{}
	go func() {
		for i := 0; i < 100; i++ {
			if b.deliverReply("42", " abc ") {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	got, err := b.awaitReply(context.Background(), "42")
	if err != nil || got != "abc" {
		t.Fatalf("got %q err %v", got, err)
	}
	if b.deliverReply("42", "late") {
		t.Fatal("waiter must be removed after reply")
	}
}

func TestAwaitReplyCancel(t *testing.T) {
	b := &Bot{}
	go func() {
		for !b.deliverReply("7", "/cancel") {
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if _, err := b.awaitReply(context.Background(), "7"); !errors.Is(err, errLoginCancelled) {
		t.Fatalf("want cancelled, got %v", err)
	}
}
