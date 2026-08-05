package mtp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
	"time"
)

const (
	kcpCmdPush = 0x51
	kcpCmdACK  = 0x52
	kcpHdrSize = 24 // without magic+session
)

// kcpState is a minimal big-endian Xiaomi KCP (no conv field).
type kcpState struct {
	session []byte
	sn      uint32
	una     uint32
	ackPad  uint32 // written into KCP pad; included in ACK PacketSign
	tsBase  uint32
	signKey []byte
}

func newKCP(session, signKey []byte) *kcpState {
	return &kcpState{
		session: append([]byte(nil), session...),
		tsBase:  uint32(time.Now().UnixMilli()),
		signKey: append([]byte(nil), signKey...),
		ackPad:  7, // client ACKs in playback_2 use pad=0x00000007-ish
	}
}

func (k *kcpState) nextSN() uint32 {
	return atomic.AddUint32(&k.sn, 1) - 1
}

func (k *kcpState) buildPUSH(payload []byte) []byte {
	sn := k.nextSN()
	pkt := k.pack(kcpCmdPush, 0, 128, sn, atomic.LoadUint32(&k.una), payload, false)
	// MTP PacketSign covers KCP||MTP (excl. 0x002a + sign TLV); see SignWithKcp.
	if len(payload) >= 4 && string(payload[0:3]) == "MTP" {
		finalizePacketSignKCP(pkt, k.signKey)
	}
	return pkt
}

func (k *kcpState) buildACK(sn, una uint32) []byte {
	pad := atomic.AddUint32(&k.ackPad, 1)
	pkt := k.pack(kcpCmdACK, 0, 128, sn, una, nil, true)
	// pack left pad=0; set pad before signing
	binary.BigEndian.PutUint32(pkt[32:36], pad)
	return k.appendACKSign(pkt)
}

func (k *kcpState) pack(cmd, frg byte, wnd uint16, sn, una uint32, payload []byte, _ bool) []byte {
	out := make([]byte, 12+kcpHdrSize+len(payload))
	copy(out[0:4], "KCP\x7f")
	copy(out[4:12], k.session)
	out[12] = cmd
	out[13] = frg
	binary.BigEndian.PutUint16(out[14:16], wnd)
	binary.BigEndian.PutUint32(out[16:20], uint32(time.Now().UnixMilli()))
	binary.BigEndian.PutUint32(out[20:24], sn)
	binary.BigEndian.PutUint32(out[24:28], una)
	binary.BigEndian.PutUint32(out[28:32], uint32(len(payload)))
	// pad [32:36] left zero (ACK overwrites before sign)
	copy(out[36:], payload)
	return out
}

// appendACKSign adds PacketSign 0x0026 over the 36-byte KCP header (playback_2: 76 B ACKs).
func (k *kcpState) appendACKSign(pkt []byte) []byte {
	const hdr = 36
	if len(pkt) < hdr {
		return pkt
	}
	signed := pkt[:hdr]
	mac := hmac.New(sha256.New, k.signKey)
	mac.Write(signed)
	sum := mac.Sum(nil)

	out := make([]byte, hdr+40)
	copy(out, signed)
	binary.BigEndian.PutUint16(out[hdr:hdr+2], tlvPacketSign)
	binary.BigEndian.PutUint16(out[hdr+2:hdr+4], fieldSignValueLen)
	copy(out[hdr+4:hdr+36], sum)
	binary.BigEndian.PutUint16(out[hdr+36:hdr+38], signTrailerMagic)
	binary.BigEndian.PutUint16(out[hdr+38:hdr+40], uint16(hdr))
	return out
}

func parseKCP(pkt []byte) (cmd byte, sn, una uint32, payload []byte, ok bool) {
	if len(pkt) < 12+kcpHdrSize || string(pkt[0:3]) != "KCP" {
		return 0, 0, 0, nil, false
	}
	cmd = pkt[12]
	sn = binary.BigEndian.Uint32(pkt[20:24])
	una = binary.BigEndian.Uint32(pkt[24:28])
	ln := int(binary.BigEndian.Uint32(pkt[28:32]))
	if 36+ln > len(pkt) {
		ln = len(pkt) - 36
		if ln < 0 {
			return 0, 0, 0, nil, false
		}
	}
	// ACK PacketSign sits after hdr when ln==0; ignore for payload.
	payload = pkt[36 : 36+ln]
	return cmd, sn, una, payload, true
}
