package auth

import (
	"strings"
	"testing"
)

func TestDeviceIDStableAcrossBundle(t *testing.T) {
	c := NewCloud("xiaomiio")
	id := c.DeviceID()
	if !strings.HasPrefix(id, "android_") || c.DeviceID() != id {
		t.Fatalf("device id %q not stable/android_-prefixed", id)
	}
	c.userID, c.ssecurity = "1", []byte("sec")
	b := BundleFromCloud(c)
	if b.DeviceID != id {
		t.Fatalf("bundle lost device id: %q", b.DeviceID)
	}
	c2 := NewCloud("xiaomiio")
	if err := ApplyBundle(c2, b); err != nil {
		t.Fatal(err)
	}
	if c2.DeviceID() != id {
		t.Fatalf("restored device id %q want %q", c2.DeviceID(), id)
	}
}
