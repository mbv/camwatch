package mtp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	magicCNT   = "CNT\x7f"
	magicLAN   = "CNT\x00"
	authStrLen = 320 // cloud credential size (ASCII base64 of 240 bytes)
)

// buildConnectCNT builds the initial CNT\x7f for one ssAddr.
// Mi Home often sends the signed message twice in one UDP datagram.
func buildConnectCNT(dest net.IP, authStr, authToken string, seq uint32, clientPub32 []byte) ([]byte, error) {
	if len(authStr) != authStrLen {
		return nil, fmt.Errorf("mtp: authStr length %d want %d", len(authStr), authStrLen)
	}
	if len(clientPub32) != 32 {
		return nil, fmt.Errorf("mtp: client key must be 32 bytes")
	}
	dest4 := dest.To4()
	if dest4 == nil {
		return nil, fmt.Errorf("mtp: dest must be IPv4")
	}
	if len(authToken) == 0 {
		return nil, fmt.Errorf("mtp: authToken required for CNT sign")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Client-chosen ConnectionId (Mi Home uses 0x01xxccyy) and TransactionId.
	connectionID := randomConnectionID()
	transactionID := randomUint32()
	if transactionID < 0x04000000 {
		transactionID |= 0x04000000
	}

	body := make([]byte, 0, 512)
	body = append(body, nonce...)
	body = binary.BigEndian.AppendUint32(body, seq)
	body = appendTLV(body, tlvConnectionID, be32(connectionID))
	body = appendEncryptedAttr(body, tlvAuth, []byte(authStr))
	body = appendTLV(body, tlvEmpty, nil)
	keyVal := make([]byte, fieldPublicKeyAttrLen)
	binary.BigEndian.PutUint32(keyVal[0:4], pubKeyAttrHeader)
	copy(keyVal[4:36], clientPub32)
	body = appendTLV(body, tlvPublicKey, keyVal)
	body = appendTLV(body, tlvTransactionID, be32(transactionID))
	body = appendTLV(body, tlvFlag, tlvFlagOne())
	body = appendTLV(body, tlvCapability, []byte{0x00, 0x01, 0x00, 0x01})

	attr12 := make([]byte, fieldAddrAttrLen)
	attr12[0], attr12[1] = 0x02, 0x02
	binary.BigEndian.PutUint16(attr12[2:4], 30005)
	copy(attr12[4:8], dest4)
	body = appendTLV(body, tlvDestAddr, attr12)
	body = appendTLV(body, tlvFlags, []byte{0, 0, 0, 0x0f})

	ts := uint64(time.Now().UnixMilli())
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, ts)
	body = appendTLV(body, tlvTimestamp, tsBuf)
	binary.BigEndian.PutUint64(tsBuf, ts+1)
	body = appendTLV(body, tlvSendTimestamp, tsBuf)
	body = binary.BigEndian.AppendUint16(body, tlvServerSign)
	body = binary.BigEndian.AppendUint16(body, fieldSignValueLen) // ServerSign TLV hdr; MAC appended below

	msg := make([]byte, 0, 16+len(body)+40)
	msg = append(msg, magicCNT...)
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0) // session
	msg = binary.BigEndian.AppendUint32(msg, 0)  // declared length filled next
	msg = append(msg, body...)
	// Declared length = wire through ServerSign TLV hdr (excludes MAC trailer).
	binary.BigEndian.PutUint32(msg[12:16], uint32(len(msg)))
	msg = appendServerSignToCNT(msg, deriveAuthSignKey(authToken))

	out := make([]byte, len(msg)*2)
	copy(out, msg)
	copy(out[len(msg):], msg)
	return out, nil
}

func appendTLV(dst []byte, typ uint16, val []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(val)))
	return append(dst, val...)
}

func tlvValue(buf []byte, want uint16) []byte {
	off := 0
	for off+4 <= len(buf) {
		t := binary.BigEndian.Uint16(buf[off : off+2])
		l := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		off += 4
		if l < 0 || off+l > len(buf) {
			break
		}
		if t == want {
			return buf[off : off+l]
		}
		off += l
	}
	return nil
}

func parseCNTSession(pkt []byte) (session []byte, serverKey []byte, err error) {
	session, serverKey, _, _, err = parseCNTReply(pkt)
	return session, serverKey, err
}

func parseCNTReply(pkt []byte) (session, serverKey []byte, connectionID, transactionID uint32, err error) {
	if len(pkt) < 16 || string(pkt[0:4]) != magicCNT {
		return nil, nil, 0, 0, fmt.Errorf("mtp: not a CNT reply")
	}
	session = append([]byte(nil), pkt[4:12]...)
	if isZero(session) {
		return nil, nil, 0, 0, fmt.Errorf("mtp: empty session in CNT reply")
	}
	// Prefer scanning the clear TLV region after the cipher area when present.
	body := pkt[16:]
	tlvStart := 0
	if len(body) >= 32 {
		inner := int(binary.BigEndian.Uint16(body[24:26]))
		padHdr := binary.BigEndian.Uint32(body[28:32])
		if 28+inner <= len(body) && padHdr >= 1 && padHdr <= 16 {
			tlvStart = 28 + inner
			// 4 zero bytes before clear TLVs (pcap).
			if tlvStart+4 <= len(body) && binary.BigEndian.Uint32(body[tlvStart:tlvStart+4]) == 0 {
				tlvStart += 4
			}
		}
	}
	off := tlvStart
	for off+4 <= len(body) {
		t := binary.BigEndian.Uint16(body[off : off+2])
		l := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if l < 0 || off+l > len(body) {
			break
		}
		val := body[off : off+l]
		off += l
		switch t {
		case tlvPublicKey:
			if len(val) >= 36 {
				serverKey = append([]byte(nil), val[4:36]...)
			}
		case tlvTransactionID:
			if len(val) >= 4 {
				transactionID = binary.BigEndian.Uint32(val[:4])
			}
		case tlvConnectionID:
			if len(val) >= 4 {
				connectionID = binary.BigEndian.Uint32(val[:4])
			}
		}
		if t == tlvServerSign || t == tlvPacketSign {
			break
		}
	}
	return session, serverKey, connectionID, transactionID, nil
}

// decryptCNTCipherArea decrypts the transport CNT cipher blob (AES-128-CBC mode=1).
func decryptCNTCipherArea(pkt, shareKey []byte) ([]byte, bool) {
	if len(pkt) < 48 || string(pkt[0:4]) != magicCNT {
		return nil, false
	}
	body := pkt[16:]
	if len(body) < 32 {
		return nil, false
	}
	inner := int(binary.BigEndian.Uint16(body[24:26]))
	if 28+inner > len(body) || inner < 20 {
		return nil, false
	}
	return decryptCNTCipherBlobAES(body[28:28+inner], shareKey)
}

func mustHex32(h string) []byte {
	if len(h) != 64 {
		return nil
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		for n := 0; n < 2; n++ {
			c := h[i*2+n]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			default:
				return nil
			}
			b = b<<4 | v
		}
		out[i] = b
	}
	return out
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// buildLANPunchCNT builds the 384 B LAN/WAN punch used before media CNT~:
//
//	CNT\x00 → camera LAN:40000
//	CNT\x01 → camera LAN:40000 (second iface)
//	CNT|   → mapped public:40000
//
// Same cipher plain as media msgid=0x10, but no auth 0x0001 / ServerSign 0x0025 —
// only PacketSign 0x0026 (pcap signedLen=0x014c). Session is the channel session
// (...00), not a media endpoint session.
func buildLANPunchCNT(
	magic string,
	channelSession []byte,
	ctx *loginContext,
	shareKey []byte,
	localIP, cameraIP net.IP,
	endpointCount, seq, txn uint32,
) []byte {
	if ctx == nil || len(shareKey) < 32 {
		return nil
	}
	ts := uint64(time.Now().UnixMilli())
	if ctx.timestamp != 0 {
		ts = ctx.timestamp
	}
	hexTS := ctx.loginHexTS
	if hexTS == "" {
		hexTS = fmt.Sprintf("%016x", ts)
	}

	plain := make([]byte, 0, 180)
	plain = appendTLV(plain, tlvUID, paddedString(ctx.uid, fieldUIDLen))
	plain = appendTLV(plain, tlvCallerUUID, paddedString(ctx.callerUUID, fieldCallerUUIDLen))
	plain = appendTLV(plain, tlvHexTimestamp, paddedString(hexTS, fieldHexTSLen))
	plain = appendTLV(plain, tlvDeviceID, paddedString(ctx.did, fieldDIDLen))
	plain = appendTLV(plain, tlvTimestamp, be64(ts))

	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	cipher := make([]byte, len(plain))
	chacha20XOR(cipher, plain, nonce, shareKey)
	blob := append(append([]byte(nil), nonce...), cipher...)

	token := make([]byte, 16)
	_, _ = rand.Read(token)

	inner := uint16(len(blob)) // 188
	outer := uint32(220)

	body := make([]byte, 0, 360)
	body = append(body, token...)
	body = binary.BigEndian.AppendUint32(body, seq)
	body = binary.BigEndian.AppendUint32(body, outer)
	body = binary.BigEndian.AppendUint16(body, inner)
	body = binary.BigEndian.AppendUint16(body, 0x0018)
	body = append(body, blob...)
	body = append(body, make([]byte, 28)...) // padZeros
	body = appendTLV(body, tlvTransactionID, be32(txn))
	body = appendTLV(body, tlvFlag, tlvFlagOne())
	if localIP == nil {
		localIP = net.IPv4(10, 0, 2, 15)
	}
	if cameraIP == nil {
		cameraIP = localIP
	}
	body = appendTLV(body, tlvLocalAddr, mediaAddrAttr(mediaUDPPort, localIP))
	body = appendTLV(body, tlvCameraAddr, mediaAddrAttr(mediaUDPPort, cameraIP))
	if endpointCount == 0 {
		endpointCount = 1
	}
	body = appendTLV(body, tlvEndpointCount, be32(endpointCount))

	sess := channelSession
	if len(sess) != fieldChannelSessionLen {
		sess = make([]byte, fieldChannelSessionLen)
	}
	msg := make([]byte, 0, 16+len(body)+12+40)
	msg = append(msg, magic...)
	msg = append(msg, sess...)
	msg = binary.BigEndian.AppendUint16(msg, 0x0010)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, body...)
	// Pcap: PacketSign excludes trailing tlvSendTimestamp (signedLen=0x014c on 384 B).
	signedLen := len(msg)
	msg = appendTLV(msg, tlvSendTimestamp, be64(ts))
	binary.BigEndian.PutUint16(msg[14:16], uint16(len(msg)+40-16-20)) // under-report by 20

	shareSign := deriveShareSignKey(shareKey)
	msg = binary.BigEndian.AppendUint16(msg, tlvPacketSign)
	msg = binary.BigEndian.AppendUint16(msg, fieldSignValueLen)
	mac := hmac.New(sha256.New, shareSign)
	mac.Write(msg[:signedLen])
	msg = append(msg, mac.Sum(nil)...)
	msg = binary.BigEndian.AppendUint16(msg, signTrailerMagic)
	msg = binary.BigEndian.AppendUint16(msg, uint16(signedLen))
	return msg
}

// buildLANCNT is kept for Dial-time best-effort; prefer buildLANPunchCNT.
func buildLANCNT(session []byte) []byte {
	msg := make([]byte, 64)
	copy(msg[0:4], magicLAN)
	if len(session) >= 8 {
		copy(msg[4:12], session[:8])
	}
	binary.BigEndian.PutUint16(msg[14:16], 48)
	_, _ = rand.Read(msg[16:])
	return msg
}

// generateCNTKeypair returns Curve25519 private+public for CNT type 0x0002.
func generateCNTKeypair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	// clamp
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}
