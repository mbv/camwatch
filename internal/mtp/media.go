package mtp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// mediaEndpoint is one relay/LAN target from LoginResponse MSIP 0x0003.
//
// Wire: count_BE32 || N × (session8 || kind_BE16 || 0_BE16 || port_BE16 || port2_BE16 || ipv4 || pad12)
type mediaEndpoint struct {
	Session  []byte
	Kind     uint16
	Port     uint16
	Port2    uint16
	IP       net.IP
	ShareKey []byte // per-ssAddr ECDH key; nil => Conn.shareKey
}

func parseMediaEndpoints(val []byte) []mediaEndpoint {
	if len(val) < 4 {
		return nil
	}
	n := int(binary.BigEndian.Uint32(val[:4]))
	off := 4
	out := make([]mediaEndpoint, 0, n)
	for i := 0; i < n && off+32 <= len(val); i++ {
		ep := mediaEndpoint{
			Session: append([]byte(nil), val[off:off+8]...),
			Kind:    binary.BigEndian.Uint16(val[off+8 : off+10]),
			Port:    binary.BigEndian.Uint16(val[off+12 : off+14]),
			Port2:   binary.BigEndian.Uint16(val[off+14 : off+16]),
			IP:      net.IP(append([]byte(nil), val[off+16:off+20]...)),
		}
		off += 32
		if ep.Port == 0 || ep.IP.To4() == nil || isZero(ep.IP.To4()) {
			continue
		}
		out = append(out, ep)
	}
	return out
}

// sessionConfirmPlain is the msgid=8 MSIP sent after LoginResponse (pcap: 208 B).
func (ctx *loginContext) sessionConfirmPlain(channelSession []byte, reqID uint32) []byte {
	out := make([]byte, 0, 208)
	out = appendTLV(out, tlvUID, paddedString(ctx.uid, fieldUIDLen))
	out = appendTLV(out, tlvCallerUUID, paddedString(ctx.callerUUID, fieldCallerUUIDLen))
	hexTS := ctx.loginHexTS
	if hexTS == "" {
		hexTS = fmt.Sprintf("%016x", ctx.timestamp)
	}
	out = appendTLV(out, tlvHexTimestamp, paddedString(hexTS, fieldHexTSLen))
	out = appendTLV(out, tlvDeviceID, paddedString(ctx.did, fieldDIDLen))
	out = appendTLV(out, tlvRequestID, be32(reqID))
	sess := channelSession
	if len(sess) != fieldChannelSessionLen {
		sess = make([]byte, fieldChannelSessionLen)
	}
	out = appendTLV(out, tlvChannelSession, sess)
	out = appendTLV(out, tlvChangeFlags, be32(changeFlagEnable))
	out = appendTLV(out, tlvTimestamp, be64(ctx.timestamp))
	return out
}

func mediaAddrAttr(port uint16, ip net.IP) []byte {
	out := make([]byte, fieldAddrAttrLen)
	out[0], out[1] = 2, 2
	binary.BigEndian.PutUint16(out[2:4], port)
	if v4 := ip.To4(); v4 != nil {
		copy(out[4:8], v4)
	}
	return out
}

// buildMediaCNT builds MsgID=punch CNT~ media probe (~756 B).
func buildMediaCNT(
	ep mediaEndpoint,
	ctx *loginContext,
	shareKey, authToken []byte,
	localIP, cameraIP net.IP,
	endpointCount uint32,
	seq, txn uint32,
) []byte {
	return buildMediaCNTMsg(ep, ctx, shareKey, authToken, localIP, cameraIP, endpointCount, seq, txn, cntMsgPunch, nil)
}

// buildMediaCNTMsg builds CNT~ with the given message ID (dance step).
//
//	cntMsgPunch / Punch2: cipher UID..0x0017; clear … 0x002a; pad28; ~756 B
//	cntMsgReply (client TX = MediaBinding): cipher +0x002f=0; clear buddy; pad20; ~800 B
//	cntMsgBound: cipher like punch; clear buddy like reply; pad28; ~800 B
//
// ServerSign covers wire through end of 0x0020 (excludes buddy + signs).
//
// echoToken: when answering server CNT~ (pcap: S 0x12 → C 0x13), native copies
// the server's 16-byte token. Nil → fresh random token (client-initiated TX).
func buildMediaCNTMsg(
	ep mediaEndpoint,
	ctx *loginContext,
	shareKey, authToken []byte,
	localIP, cameraIP net.IP,
	endpointCount uint32,
	seq, txn uint32,
	msgID uint16,
	echoToken []byte,
) []byte {
	if ctx == nil {
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

	// Client TX of cntMsgReply is always MediaBinding (not punch-ack — server sends that).
	hasBuddy := msgID == cntMsgReply || msgID == cntMsgBound
	isBinding := msgID == cntMsgReply
	padZeros := 28
	if isBinding {
		padZeros = 20
	}
	// Layout after BlobLen: binding=0x10, else punch=0x18.
	layout := cntLayoutPunch
	if isBinding {
		layout = cntLayoutBinding
	}

	plain := make([]byte, 0, 188)
	plain = appendTLV(plain, tlvUID, paddedString(ctx.uid, fieldUIDLen))
	plain = appendTLV(plain, tlvCallerUUID, paddedString(ctx.callerUUID, fieldCallerUUIDLen))
	plain = appendTLV(plain, tlvHexTimestamp, paddedString(hexTS, fieldHexTSLen))
	plain = appendTLV(plain, tlvDeviceID, paddedString(ctx.did, fieldDIDLen))
	plain = appendTLV(plain, tlvTimestamp, be64(ts))
	if isBinding {
		// Native pcap client MediaBinding: tlvBindingFlag=0.
		// Server MediaBinding response: tlvBindingFlag=1 — do not send that on TX.
		plain = appendTLV(plain, tlvBindingFlag, be32(0))
	}

	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	cipher := make([]byte, len(plain))
	chacha20XOR(cipher, plain, nonce, shareKey)
	blob := append(append([]byte(nil), nonce...), cipher...)

	token := make([]byte, 16)
	if len(echoToken) >= 16 {
		copy(token, echoToken[:16])
	} else {
		_, _ = rand.Read(token)
	}

	blobLen := uint16(len(blob))
	// Pcap: OuterLen stays 220 (=188+32) even when binding grows BlobLen to 196.
	outerLen := uint32(188 + 32)

	body := make([]byte, 0, 780)
	body = append(body, token...)
	body = binary.BigEndian.AppendUint32(body, seq)
	body = binary.BigEndian.AppendUint32(body, outerLen)
	body = binary.BigEndian.AppendUint16(body, blobLen)
	body = binary.BigEndian.AppendUint16(body, layout)
	body = append(body, blob...)
	body = append(body, make([]byte, padZeros)...)

	auth := append([]byte(nil), ctx.authInfo...)
	if len(auth) != authStrLen {
		auth = make([]byte, authStrLen)
	}
	outerAuth := (len(auth) + 8) &^ 3
	authVal := make([]byte, outerAuth)
	binary.BigEndian.PutUint16(authVal[0:2], uint16(len(auth)))
	copy(authVal[4:], auth)
	body = appendTLV(body, tlvAuth, authVal)
	body = appendTLV(body, tlvTransactionID, be32(txn))
	body = appendTLV(body, tlvFlag, tlvFlagOne())
	if localIP == nil {
		localIP = net.IPv4(10, 0, 2, 15)
	}
	if cameraIP == nil {
		cameraIP = localIP
	}
	// Native: tlvLocalAddr = local/outbound iface:mediaUDPPort, tlvCameraAddr = camera LAN:mediaUDPPort.
	body = appendTLV(body, tlvLocalAddr, mediaAddrAttr(mediaUDPPort, localIP))
	body = appendTLV(body, tlvCameraAddr, mediaAddrAttr(mediaUDPPort, cameraIP))
	if endpointCount == 0 {
		endpointCount = 1
	}
	body = appendTLV(body, tlvEndpointCount, be32(endpointCount))

	sess := ep.Session
	if len(sess) != fieldChannelSessionLen {
		sess = make([]byte, fieldChannelSessionLen)
	}
	msg := make([]byte, 0, 16+len(body)+80+40)
	msg = append(msg, "CNT~"...)
	msg = append(msg, sess...)
	msg = binary.BigEndian.AppendUint16(msg, msgID)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, body...)

	buddy := 12 // tlvSendTimestamp
	if hasBuddy {
		buddy = 12 + 24 + 12 + 8 // tlvSessionToken + tlvMappedAddr + tlvBuddyTimestamp + tlvBuddyFlag
	}
	const signs = 40 + 40
	binary.BigEndian.PutUint16(msg[14:16], uint16(len(msg)+buddy+signs-16-20))

	var signedLen int
	if hasBuddy {
		// Native MediaBinding 0x0015 = LoginResponse MA_MAPPED_ADDR (pcap
		// 93.84.x:44128), NOT STUN XOR-MAPPED / punch-ack echo (46.205.x).
		pubIP := localIP
		pubPort := uint16(mediaUDPPort)
		src := []byte(nil)
		if ctx != nil {
			if len(ctx.buddyAddr) >= 8 {
				src = ctx.buddyAddr
			} else if len(ctx.relayAddr) >= 8 {
				src = ctx.relayAddr
			}
		}
		if len(src) >= 8 {
			if v4 := net.IP(src[4:8]).To4(); v4 != nil && !isZero(v4) {
				pubIP = v4
			}
			if p := binary.BigEndian.Uint16(src[2:4]); p != 0 {
				pubPort = p
			}
		}
		// 0x002c: native MediaBinding varies (pcap first replies use 5); outside sign.
		buddy2c := uint32(5)
		msg = appendTLV(msg, tlvSessionToken, make([]byte, fieldChannelSessionLen))
		msg = appendTLV(msg, tlvMappedAddr, mediaAddrAttr(pubPort, pubIP))
		// Pcap: ServerSign/PacketSign cover through end of tlvMappedAddr (slen=700 on
		// 800 B binding); tlvBuddyTimestamp/tlvBuddyFlag sit outside the signed window.
		signedLen = len(msg)
		msg = appendTLV(msg, tlvBuddyTimestamp, be64(ts))
		msg = appendTLV(msg, tlvBuddyFlag, be32(buddy2c))
	} else {
		// Pcap: punch sign through end of tlvEndpointCount; tlvSendTimestamp is outside (slen=664).
		signedLen = len(msg)
		msg = appendTLV(msg, tlvSendTimestamp, be64(ts))
	}

	authSign := deriveAuthSignKey(string(authToken))
	msg = binary.BigEndian.AppendUint16(msg, tlvServerSign)
	msg = binary.BigEndian.AppendUint16(msg, fieldSignValueLen)
	mac := hmac.New(sha256.New, authSign)
	mac.Write(msg[:signedLen])
	msg = append(msg, mac.Sum(nil)...)
	msg = binary.BigEndian.AppendUint16(msg, signTrailerMagic)
	msg = binary.BigEndian.AppendUint16(msg, uint16(signedLen))

	shareSign := deriveShareSignKey(shareKey)
	msg = binary.BigEndian.AppendUint16(msg, tlvPacketSign)
	msg = binary.BigEndian.AppendUint16(msg, fieldSignValueLen)
	msg = append(msg, mediaPacketSignMAC(msg[:signedLen], shareSign)...)
	msg = binary.BigEndian.AppendUint16(msg, signTrailerMagic)
	msg = binary.BigEndian.AppendUint16(msg, uint16(signedLen))
	return msg
}

// mediaPacketSignMAC is PacketSign for media CNT~ (SignWithoutKcpHeader).
//
// Native temporarily writes 0 at wire+0x20 (seq after the 16-byte token) before
// HMAC(mediaSign, …), then restores seq for ServerSign and the final packet.
// Verifying HMAC(mediaSign, finalWire[:signedLen]) therefore fails; zero seq first.
func mediaPacketSignMAC(signed, signKey []byte) []byte {
	buf := append([]byte(nil), signed...)
	if len(buf) >= 36 {
		buf[32], buf[33], buf[34], buf[35] = 0, 0, 0, 0
	}
	mac := hmac.New(sha256.New, signKey)
	mac.Write(buf)
	return mac.Sum(nil)
}

// buildMediaCNTFlags is a deprecated alias for buildMediaCNTMsg.
func buildMediaCNTFlags(
	ep mediaEndpoint,
	ctx *loginContext,
	shareKey, authToken []byte,
	localIP, cameraIP net.IP,
	endpointCount uint32,
	seq, txn uint32,
	msgID uint16,
) []byte {
	return buildMediaCNTMsg(ep, ctx, shareKey, authToken, localIP, cameraIP, endpointCount, seq, txn, msgID, nil)
}
