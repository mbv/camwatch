package mtp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// dataConnectionReadyPlain builds the msgid=0x17 MSIP plaintext that tells the
// camera the media relay path is up (Frida/pcap: RSLT=DATA_CONNECTION_READY).
//
//	0x0017 ts8 || 0x0028 encrypted-attr(JSON)
func dataConnectionReadyPlain(
	ctx *loginContext,
	signallingSession []byte,
	signallingRelay string, // host:port of ssAddr
	mediaSession []byte,
	mediaVA string, // host:port of selected media endpoint
) []byte {
	if ctx == nil {
		return nil
	}
	ts := ctx.timestamp
	hexTS := ctx.loginHexTS
	if hexTS == "" {
		hexTS = fmt.Sprintf("%016x", ts)
	}
	sigSess := fmt.Sprintf("%x", signallingSession[:min(8, len(signallingSession))])
	medSess := fmt.Sprintf("%x", mediaSession[:min(8, len(mediaSession))])
	// CSK/DCK shape from Frida; #126 is observed on CT_RELAY paths.
	json := fmt.Sprintf(
		`{"CSK":"%s#%s#%s#%s#%s#%s","SI":{"DCK":"%s#CT_RELAY#126","PL":"0","TSCon":"%d","TSC":"%d","RSLT":"DATA_CONNECTION_READY","VA":"%s"}}`,
		ctx.did, ctx.uid, ctx.callerUUID, hexTS, sigSess, signallingRelay,
		medSess, ts, ts, mediaVA,
	)

	out := make([]byte, 0, 12+8+len(json)+16)
	out = appendTLV(out, tlvTimestamp, be64(ts))
	out = appendEncryptedAttr(out, tlvEncryptedJSON, []byte(json))
	return out
}

// videoStartSentPlain is the follow-up msgid=0x17 status after CHK video-start.
func videoStartSentPlain(ctx *loginContext, signallingSession []byte, signallingRelay string) []byte {
	if ctx == nil {
		return nil
	}
	ts := ctx.timestamp
	hexTS := ctx.loginHexTS
	if hexTS == "" {
		hexTS = fmt.Sprintf("%016x", ts)
	}
	sigSess := fmt.Sprintf("%x", signallingSession[:min(8, len(signallingSession))])
	json := fmt.Sprintf(
		`{"CSK":"%s#%s#%s#%s#%s#%s","SI":{"RSLT":"MISS_CMD_VIDEO_START_SEND","CSID":0,"TSC":"%d"}}`,
		ctx.did, ctx.uid, ctx.callerUUID, hexTS, sigSess, signallingRelay, ts,
	)
	out := make([]byte, 0, 12+8+len(json)+16)
	out = appendTLV(out, tlvTimestamp, be64(ts))
	out = appendEncryptedAttr(out, tlvEncryptedJSON, []byte(json))
	return out
}

// candidateListPlain builds msgid=0x0a plaintext (Frida 336 B): identity +
// channel session + mapped address list (0x0006).
func candidateListPlain(ctx *loginContext, channelSession []byte, addrs [][]byte) []byte {
	if ctx == nil {
		return nil
	}
	ts := ctx.timestamp
	hexTS := ctx.loginHexTS
	if hexTS == "" {
		hexTS = fmt.Sprintf("%016x", ts)
	}
	sess := channelSession
	if len(sess) != fieldChannelSessionLen {
		sess = make([]byte, fieldChannelSessionLen)
	}
	if len(addrs) == 0 {
		addrs = [][]byte{make([]byte, fieldAddrAttrLen)}
		addrs[0][0], addrs[0][1] = 2, 2
	}
	list := make([]byte, 0, 4+fieldAddrAttrLen*len(addrs))
	list = binary.BigEndian.AppendUint32(list, uint32(len(addrs)))
	for _, a := range addrs {
		if len(a) < fieldAddrAttrLen {
			pad := make([]byte, fieldAddrAttrLen)
			copy(pad, a)
			a = pad
		}
		list = append(list, a[:fieldAddrAttrLen]...)
	}

	out := make([]byte, 0, 336)
	out = appendTLV(out, tlvUID, paddedString(ctx.uid, fieldUIDLen))
	out = appendTLV(out, tlvCallerUUID, paddedString(ctx.callerUUID, fieldCallerUUIDLen))
	out = appendTLV(out, tlvHexTimestamp, paddedString(hexTS, fieldHexTSLen))
	out = appendTLV(out, tlvDeviceID, paddedString(ctx.did, fieldDIDLen))
	out = appendTLV(out, tlvChannelSession, sess)
	out = appendTLV(out, tlvCandidateFlagB, be32(flagValueOne))
	out = appendTLV(out, tlvCandidateFlagA, be32(flagValueOne))
	out = appendTLV(out, tlvProbedAddrs, list)
	out = appendTLV(out, tlvTimestamp, be64(ts))
	return out
}

// buildStatusMTP builds an MTP status/info frame.
//
//	mtpMsgStatus (0x17): clear TLV 0x000b only (pcap)
//	mtpMsgCandidates (0x0a): clear TLV 0x0008=ffffffff + 0x000b (pcap)
func buildStatusMTP(session, token, shareKey, signKey []byte, msgID uint16, seq, txn uint32, plain []byte) []byte {
	if len(session) < 8 {
		session = append(session, make([]byte, 8-len(session))...)
	}
	if len(token) < 16 {
		t := make([]byte, 16)
		copy(t, token)
		token = t
	}
	blob := encryptCNTCipherBlob(plain, shareKey)
	blobLen := uint16(len(blob))
	outerLen := uint32(blobLen) + 8

	body := make([]byte, 0, 28+len(blob)+24+40)
	body = append(body, token[:16]...)
	body = binary.BigEndian.AppendUint32(body, seq)
	body = binary.BigEndian.AppendUint32(body, outerLen)
	body = binary.BigEndian.AppendUint16(body, blobLen)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, blob...)
	body = append(body, 0, 0, 0, 0)
	if msgID == mtpMsgCandidates {
		body = appendTLV(body, tlvTransactionID, []byte{0xff, 0xff, 0xff, 0xff})
	}
	_ = txn
	body = appendTLV(body, tlvFlag, tlvFlagOne())

	msg := make([]byte, 0, 16+len(body)+40)
	msg = append(msg, magicMTP...)
	msg = append(msg, session[:8]...)
	msg = binary.BigEndian.AppendUint16(msg, msgID)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, body...)
	_ = signKey
	return appendPacketSignMTP(msg)
}

func relayHostPort(addr *net.UDPAddr) string {
	if addr == nil || addr.IP == nil {
		return ""
	}
	return net.JoinHostPort(addr.IP.String(), fmt.Sprintf("%d", addr.Port))
}

// extractMappedAddr pulls MSIP tlvMappedAddr (fieldAddrAttrLen B) from a CNT~ packet if present.
func extractMappedAddr(pkt []byte) []byte {
	for i := 0; i+4+fieldAddrAttrLen <= len(pkt); i++ {
		if binary.BigEndian.Uint16(pkt[i:i+2]) == tlvMappedAddr &&
			binary.BigEndian.Uint16(pkt[i+2:i+4]) == fieldAddrAttrLen {
			out := append([]byte(nil), pkt[i+4:i+4+fieldAddrAttrLen]...)
			if out[0] == 2 && (out[4]|out[5]|out[6]|out[7]) != 0 {
				return out
			}
		}
	}
	return nil
}
