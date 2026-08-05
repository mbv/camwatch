package mtp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// deriveAuthSignKey matches MTP_NET_ConnectionAuthTokenUpdate:
// packet_sign_key = HMAC-SHA256(key=authToken, data=authToken).
func deriveAuthSignKey(authToken string) []byte {
	mac := hmac.New(sha256.New, []byte(authToken))
	mac.Write([]byte(authToken))
	return mac.Sum(nil)
}

// deriveShareKey is libsodium crypto_box_beforenm (X25519 + HSalsa20).
func deriveShareKey(clientPriv, serverPub []byte) ([]byte, error) {
	if len(clientPriv) != 32 || len(serverPub) != 32 {
		return nil, fmt.Errorf("mtp: sharekey needs 32-byte keys (priv=%d pub=%d)", len(clientPriv), len(serverPub))
	}
	var shared, their, ours [32]byte
	copy(ours[:], clientPriv)
	copy(their[:], serverPub)
	box.Precompute(&shared, &their, &ours)
	return shared[:], nil
}

// deriveShareSignKey matches MTP_NET_ConnectionShareKeyUpdate.
func deriveShareSignKey(shareKey []byte) []byte {
	mac := hmac.New(sha256.New, shareKey)
	mac.Write(shareKey)
	return mac.Sum(nil)
}

// verifyServerSignCNT checks ServerSign 0x0025 with authToken HMAC key.
// Signed window is trailer BE16 length when present, else wire through 0x0025 hdr.
func verifyServerSignCNT(pkt []byte, authToken string) (ok bool, window string) {
	idx := -1
	for i := 0; i+4 <= len(pkt); i++ {
		if binary.BigEndian.Uint16(pkt[i:i+2]) == tlvServerSign &&
			binary.BigEndian.Uint16(pkt[i+2:i+4]) == fieldSignValueLen {
			idx = i
		}
	}
	if idx < 0 || idx+40 > len(pkt) {
		return false, "no-0025"
	}
	macWant := pkt[idx+4 : idx+36]
	key := deriveAuthSignKey(authToken)
	check := func(name string, data []byte) bool {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return hmac.Equal(mac.Sum(nil), macWant)
	}
	signedLen := binary.BigEndian.Uint16(pkt[idx+38 : idx+40])
	if n := int(signedLen); n > 0 && n <= len(pkt) && check("trailer-len-prefix", pkt[:n]) {
		return true, "trailer-len-prefix"
	}
	if check("wire-through-hdr", pkt[:idx+4]) {
		return true, "wire-through-hdr"
	}
	return false, "none"
}

// appendServerSignToCNT finishes a CNT\x7f message.
//
// MAC covers the full wire bytes through the 0x0025 TLV header
// (16-byte CNT hdr + body incl. 00 25 00 24).
//
// msg must already contain magic/session/len + body including 00 25 00 24.
func appendServerSignToCNT(msg, signKey []byte) []byte {
	signedLen := len(msg)
	mac := hmac.New(sha256.New, signKey)
	mac.Write(msg)
	msg = append(msg, mac.Sum(nil)...)
	msg = binary.BigEndian.AppendUint16(msg, signTrailerMagic)
	return binary.BigEndian.AppendUint16(msg, uint16(signedLen))
}

// appendServerSignTLV appends MSIP tlvServerSign over a body-only buffer (no CNT hdr).
func appendServerSignTLV(body, signKey []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, tlvServerSign)
	body = binary.BigEndian.AppendUint16(body, fieldSignValueLen)
	signedLen := len(body)
	mac := hmac.New(sha256.New, signKey)
	mac.Write(body)
	body = append(body, mac.Sum(nil)...)
	body = binary.BigEndian.AppendUint16(body, signTrailerMagic)
	return binary.BigEndian.AppendUint16(body, uint16(signedLen))
}

// appendPacketSignTLV appends MSIP attribute type tlvPacketSign (PacketSign).
func appendPacketSignTLV(body, signKey []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, tlvPacketSign)
	body = binary.BigEndian.AppendUint16(body, fieldSignValueLen)
	signedLen := len(body)
	mac := hmac.New(sha256.New, signKey)
	mac.Write(body)
	body = append(body, mac.Sum(nil)...)
	body = binary.BigEndian.AppendUint16(body, signTrailerMagic)
	return binary.BigEndian.AppendUint16(body, uint16(signedLen))
}
