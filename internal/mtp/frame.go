package mtp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	magicMTP  = "MTP\x7f"
	magicCHK  = "CHK~"
	magicKCPt = "KCP~" // media path

	// MTP\x7f MsgID at offset 12 — message-type enum, not a bitfield
	// (same wire slot as CNT~/CNT\x7f MsgID).
	mtpMsgLogin       uint16 = 6
	mtpMsgLoginResp   uint16 = 7
	mtpMsgSessConfirm uint16 = 8
	mtpMsgSessAck     uint16 = 12
	mtpMsgCandidates  uint16 = 0x000a
	mtpMsgStatus      uint16 = 0x0017 // DATA_CONNECTION_READY / VIDEO_START / miss cmds
)

// buildMTP builds an MTP\x7f frame for a KCP PUSH payload.
//
// Wire (playback_2 login):
//
//	MTP\x7f || session(8) || MsgID_BE(2) || DeclLen_BE(2) ||
//	  token(16) || seq_BE(4) || OuterLen_BE(4) || BlobLen_BE(2) || 0(2) ||
//	  AES blob (padLen||IV16||CBC) || 0000 || clear TLVs || PacketSign
//
// DeclLen under-reports by 20 (same overflow pattern as CNT): full body
// includes PacketSign value; declared length stops 20 bytes early.
//
// PacketSign (0x0026) for KCP PUSH is finalized in finalizePacketSignKCP after
// the KCP header is prepended (MTPGeneralMessageSignWithKcpHeader):
//
//	signedLen = 0x48 + bodyLen - 0x28 - 0x0c
//	          = fullWire - sizeof(0x002a) - sizeof(PacketSign)
//	mac = HMAC-SHA256(signKey, wire[:signedLen])
//	value = mac || 00 20 || BE16(signedLen)
//
// Encryption: ImportDataEncrypt mode=1 → AES-128-CBC(shareKey[:16]).
func buildMTP(session, token, shareKey, signKey []byte, msgID uint16, seq uint32, typ uint32, plaintext []byte) []byte {
	return buildMTPAt(
		session, token, shareKey, signKey, msgID, seq, typ, plaintext,
		randomUint32(), uint64(time.Now().UnixMilli()),
	)
}

func buildMTPAt(
	session, token, shareKey, signKey []byte, msgID uint16, seq uint32, typ uint32,
	plaintext []byte, transactionID uint32, timestamp uint64,
) []byte {
	if len(session) < 8 {
		session = append(session, make([]byte, 8-len(session))...)
	}
	if len(token) < 16 {
		t := make([]byte, 16)
		copy(t, token)
		_, _ = rand.Read(t[len(token):])
		token = t
	}

	// ImportDataEncrypt mode=1: AES-128-CBC blob (padLen||IV||cipher).
	// The leading BE32(padLen) occupies the old "typ" slot (padLen=4 for 348 B plain).
	_ = typ
	_ = signKey // HMAC runs after KCP wrap (finalizePacketSignKCP).
	blob := encryptCNTCipherBlob(plaintext, shareKey)
	blobLen := uint16(len(blob))
	outerLen := uint32(blobLen) + 8

	body := make([]byte, 0, 28+len(blob)+4+64+40)
	body = append(body, token[:16]...)
	body = binary.BigEndian.AppendUint32(body, seq)
	body = binary.BigEndian.AppendUint32(body, outerLen)
	body = binary.BigEndian.AppendUint16(body, blobLen)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, blob...)
	body = append(body, 0, 0, 0, 0) // 4 zero bytes before clear TLVs (pcap)

	// Cleartext MSIP TLVs after cipher area (observed on wire).
	body = appendTLV(body, tlvTransactionID, be32(transactionID))
	body = appendTLV(body, tlvFlag, tlvFlagOne())
	body = appendTLV(body, tlvSendTimestamp, be64(timestamp))

	msg := make([]byte, 0, 16+len(body)+40)
	msg = append(msg, magicMTP...)
	msg = append(msg, session[:8]...)
	msg = binary.BigEndian.AppendUint16(msg, msgID)
	msg = binary.BigEndian.AppendUint16(msg, 0) // length filled after sign
	msg = append(msg, body...)

	return appendPacketSignMTP(msg)
}

// appendPacketSignMTP appends a zeroed 0x0026 slot and sets the under-reported
// body length. MAC + trailer length are filled by finalizePacketSignKCP.
func appendPacketSignMTP(msg []byte) []byte {
	msg = binary.BigEndian.AppendUint16(msg, tlvPacketSign)
	msg = binary.BigEndian.AppendUint16(msg, fieldSignValueLen)
	msg = append(msg, make([]byte, 36)...) // mac||signTrailerMagic||BE16 placeholder

	body := msg[16:]
	valOff := len(msg) - 36
	msg[valOff+32] = byte(signTrailerMagic >> 8)
	msg[valOff+33] = byte(signTrailerMagic)
	// Provisional trailer (= body len); KCP finalize overwrites with signedLen.
	binary.BigEndian.PutUint16(msg[valOff+34:valOff+36], uint16(len(body)))

	// Declared body length omits the last 20 bytes (16 mac + 00 20 size).
	binary.BigEndian.PutUint16(msg[14:16], uint16(len(body)-20))
	return msg
}

// finalizePacketSignKCP writes PacketSign over a KCP PUSH that already contains
// an MTP payload with a zeroed 0x0026 value slot.
//
// Native (SignWithKcp): HMAC from KCP start for uVar3 bytes, where uVar3 is
// 0x48+bodyLen minus PacketSign (0x28) and any trailing buddy TLVs registered
// on the message (0x002a / 0x002b / 0x002c — 12/12/8 bytes). Clear TLVs
// 0x0008 / 0x000b / 0x0018 stay inside the signed window.
func finalizePacketSignKCP(pkt, signKey []byte) {
	if len(pkt) < 36+16+40 || len(signKey) == 0 {
		return
	}
	signOff := -1
	for i := len(pkt) - 40; i >= 36; i-- {
		if binary.BigEndian.Uint16(pkt[i:i+2]) == tlvPacketSign &&
			binary.BigEndian.Uint16(pkt[i+2:i+4]) == fieldSignValueLen {
			signOff = i
			break
		}
	}
	if signOff < 0 || signOff+40 > len(pkt) {
		return
	}
	signedLen := signOff
	// Walk trailing excluded TLVs immediately before PacketSign.
	for {
		if signedLen >= 36+12 &&
			(pkt[signedLen-12] == 0x00 && pkt[signedLen-10] == 0x00 && pkt[signedLen-9] == 0x08) &&
			(pkt[signedLen-11] == 0x2a || pkt[signedLen-11] == 0x2b) {
			signedLen -= 12
			continue
		}
		if signedLen >= 36+8 &&
			pkt[signedLen-8] == 0x00 && pkt[signedLen-7] == 0x2c &&
			pkt[signedLen-6] == 0x00 && pkt[signedLen-5] == 0x04 {
			signedLen -= 8
			continue
		}
		break
	}
	for i := 0; i < 36; i++ {
		pkt[signOff+4+i] = 0
	}
	mac := hmac.New(sha256.New, signKey)
	mac.Write(pkt[:signedLen])
	sum := mac.Sum(nil)
	copy(pkt[signOff+4:signOff+36], sum)
	pkt[signOff+36] = byte(signTrailerMagic >> 8)
	pkt[signOff+37] = byte(signTrailerMagic)
	binary.BigEndian.PutUint16(pkt[signOff+38:signOff+40], uint16(signedLen))
}

func parseMTP(pkt []byte) (msgID uint16, seq uint32, token, payload []byte, err error) {
	if len(pkt) < 16 || string(pkt[0:3]) != "MTP" {
		return 0, 0, nil, nil, fmt.Errorf("mtp: not an MTP frame")
	}
	msgID = binary.BigEndian.Uint16(pkt[12:14])
	ln := int(binary.BigEndian.Uint16(pkt[14:16]))
	// Full frame may extend 20 bytes past declared length (PacketSign overflow).
	body := pkt[16:]
	if len(body) < ln {
		ln = len(body)
	}
	// Prefer full body when overflow present.
	if len(pkt) >= 16+ln+20 {
		body = pkt[16:]
	} else {
		body = pkt[16 : 16+ln]
	}
	if len(body) < 32 {
		return msgID, 0, nil, body, nil
	}
	token = append([]byte(nil), body[:16]...)
	seq = binary.BigEndian.Uint32(body[16:20])
	blobLen := int(binary.BigEndian.Uint16(body[24:26]))
	// AES blob starts at body[28] (padLen is inside blob, not a separate typ).
	if 28+blobLen > len(body) {
		blobLen = len(body) - 28
		if blobLen < 0 {
			return msgID, seq, token, nil, fmt.Errorf("mtp: short body")
		}
	}
	payload = body[28 : 28+blobLen]
	return msgID, seq, token, payload, nil
}

// decryptMTPPayload decrypts an ImportDataEncrypt mode=1 AES-128-CBC blob.
func decryptMTPPayload(enc, shareKey []byte) ([]byte, error) {
	plain, ok := decryptCNTCipherBlobAES(enc, shareKey)
	if !ok {
		return nil, fmt.Errorf("mtp: AES decrypt failed (blob=%d)", len(enc))
	}
	return plain, nil
}

// encodeMissCommand builds BE cmd + payload as mtp_cmd_send does.
func encodeMissCommand(cmd uint32, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[0:4], cmd)
	copy(out[4:], data)
	return out
}

func decodeMissCommand(buf []byte) (cmd uint32, data []byte, err error) {
	if len(buf) < 4 {
		return 0, nil, fmt.Errorf("mtp: short command")
	}
	cmd = binary.BigEndian.Uint32(buf[0:4])
	data = buf[4:]
	return cmd, data, nil
}
