package mtp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"
)

func TestAppendEncryptedAttrSize(t *testing.T) {
	// 320-byte authStr: outer must be 328 with no trailing pad (8 hdr + 320).
	val := make([]byte, authStrLen)
	out := appendEncryptedAttr(nil, tlvAuth, val)
	if len(out) != 328 {
		t.Fatalf("auth attr len=%d want 328", len(out))
	}
	if binary.BigEndian.Uint16(out[0:2]) != tlvAuth {
		t.Fatalf("type %#x", out[0:2])
	}
	if binary.BigEndian.Uint16(out[2:4]) != 328 {
		t.Fatalf("outer %#x want 328", out[2:4])
	}
	if binary.BigEndian.Uint16(out[4:6]) != authStrLen {
		t.Fatalf("actual %#x want %d", out[4:6], authStrLen)
	}

	// Odd length needs pad so total == outer.
	val3 := []byte{1, 2, 3}
	out3 := appendEncryptedAttr(nil, tlvEncryptedJSON, val3)
	outer := int(binary.BigEndian.Uint16(out3[2:4]))
	if len(out3) != outer {
		t.Fatalf("padded len=%d outer=%d", len(out3), outer)
	}
	if outer != 12 { // round-up (3+8) → 12
		t.Fatalf("outer=%d want 12", outer)
	}
}

func TestBuildConnectCNTWireSize(t *testing.T) {
	raw := make([]byte, 240)
	_, _ = rand.Read(raw)
	authStr := base64.StdEncoding.EncodeToString(raw)
	if len(authStr) != authStrLen {
		t.Fatalf("authStr len %d", len(authStr))
	}
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	pkt, err := buildConnectCNT(net.IPv4(1, 2, 3, 4), authStr, "tokentokentokentokentokentokentok", 1, pub)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicated on wire; single message is half.
	if len(pkt)%2 != 0 {
		t.Fatalf("dup length odd: %d", len(pkt))
	}
	msg := pkt[:len(pkt)/2]
	// Historical pcap size: 540 B through ServerSign trailer.
	if len(msg) != 540 {
		t.Fatalf("CNT msg len=%d want 540", len(msg))
	}
	decl := binary.BigEndian.Uint32(msg[12:16])
	if decl != 504 {
		t.Fatalf("declared len=%d want 504", decl)
	}
}
