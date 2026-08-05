package mtp

import (
	"encoding/binary"
	"fmt"
)

// CNT~ header message IDs (u16 at offset 12). Enum / dance step — not a bitfield.
// Same wire slot as MTP\x7f MsgID, but values are media bind stages.
const (
	cntMsgPunch  uint16 = 0x0010 // client/server punch
	cntMsgReply  uint16 = 0x0011 // punch-ack OR MediaBinding (see Layout)
	cntMsgPunch2 uint16 = 0x0012 // second-stage punch
	cntMsgBound  uint16 = 0x0013 // bound confirmation
)

// CNT~ layout IDs (u16 after BlobLen). Selects cipher size + post-cipher pad.
const (
	cntLayoutBinding uint16 = 0x0010 // MediaBinding (pad=20; BlobLen typically 196)
	cntLayoutPunch   uint16 = 0x0018 // punch / punch-ack / bound (pad=28; BlobLen typically 188)
)

// CNT~ media envelope kinds (structural — not UDP length).
const (
	cntKindUnknown = iota
	cntKindPunch    // MsgID 0x10/0x12, Layout punch, clear ends with 0x2a
	cntKindPunchACK // MsgID 0x11 + Layout punch + buddy TLVs
	cntKindBinding  // Layout binding; MsgID usually 0x11
	cntKindBound    // MsgID 0x13 + buddy TLVs
)

// mediaCNT is a parsed CNT~ media-binding / punch frame.
type mediaCNT struct {
	Raw     []byte
	MsgID   uint16 // dance-step enum at offset 12 (shared slot with MTP MsgID)
	DeclLen uint16 // declared body length at offset 14 (under-reports)
	Session []byte
	Token   []byte
	Seq     uint32
	OuterLen uint32 // outer size field (pcap often 220)
	BlobLen  uint16 // length of nonce||ciphertext
	Layout   uint16 // cipher layout / pad hint (0x10 binding, 0x18 punch)
	Blob     []byte // nonce||ciphertext
	Pad      int
	Clear    []byte // clear TLVs through signs
	TLVs     map[uint16][]byte
	Plain    []byte // decrypted cipher area (nil if decrypt failed)
	Kind     int
}

func parseMediaCNT(pkt []byte) (*mediaCNT, error) {
	if len(pkt) < 48 || string(pkt[:4]) != "CNT~" {
		return nil, fmt.Errorf("mtp: not CNT~")
	}
	m := &mediaCNT{
		Raw:     pkt,
		Session: append([]byte(nil), pkt[4:12]...),
		MsgID:   binary.BigEndian.Uint16(pkt[12:14]),
		DeclLen: binary.BigEndian.Uint16(pkt[14:16]),
		TLVs:    make(map[uint16][]byte),
	}
	body := pkt[16:]
	if len(body) < 28 {
		return nil, fmt.Errorf("mtp: CNT~ body too short")
	}
	m.Token = append([]byte(nil), body[0:16]...)
	m.Seq = binary.BigEndian.Uint32(body[16:20])
	m.OuterLen = binary.BigEndian.Uint32(body[20:24])
	m.BlobLen = binary.BigEndian.Uint16(body[24:26])
	m.Layout = binary.BigEndian.Uint16(body[26:28])
	if 28+int(m.BlobLen) > len(body) {
		return nil, fmt.Errorf("mtp: CNT~ blob overflow")
	}
	m.Blob = append([]byte(nil), body[28:28+int(m.BlobLen)]...)

	// Native builder: pad 20 when Layout=binding, else 28.
	m.Pad = 28
	if m.Layout == cntLayoutBinding {
		m.Pad = 20
	}
	off := 28 + int(m.BlobLen) + m.Pad
	if off > len(body) {
		return nil, fmt.Errorf("mtp: CNT~ pad overflow")
	}
	m.Clear = body[off:]
	for o := 0; o+4 <= len(m.Clear); {
		t := binary.BigEndian.Uint16(m.Clear[o : o+2])
		l := int(binary.BigEndian.Uint16(m.Clear[o+2 : o+4]))
		o += 4
		if l < 0 || o+l > len(m.Clear) {
			break
		}
		m.TLVs[t] = append([]byte(nil), m.Clear[o:o+l]...)
		o += l
		if t == tlvServerSign || t == tlvPacketSign {
			break
		}
	}
	m.Kind = classifyMediaCNT(m)
	return m, nil
}

func classifyMediaCNT(m *mediaCNT) int {
	_, has18 := m.TLVs[tlvSessionToken]
	_, has15 := m.TLVs[tlvMappedAddr]
	_, has2a := m.TLVs[tlvSendTimestamp]
	hasBuddy := has18 && has15

	switch {
	case m.Layout == cntLayoutBinding:
		return cntKindBinding
	case m.MsgID == cntMsgBound && hasBuddy:
		return cntKindBound
	case m.MsgID == cntMsgReply && m.Layout == cntLayoutPunch && hasBuddy:
		return cntKindPunchACK
	case (m.MsgID == cntMsgPunch || m.MsgID == cntMsgPunch2) && has2a:
		return cntKindPunch
	default:
		return cntKindUnknown
	}
}

func (m *mediaCNT) kindName() string {
	switch m.Kind {
	case cntKindPunch:
		return "punch"
	case cntKindPunchACK:
		return "punch-ack"
	case cntKindBinding:
		return "binding"
	case cntKindBound:
		return "bound"
	default:
		return "unknown"
	}
}

// decrypt tries ChaCha20 (libsodium original-8) with shareKey over nonce||cipher.
func (m *mediaCNT) decrypt(shareKey []byte) bool {
	if len(shareKey) != 32 || len(m.Blob) < 9 {
		return false
	}
	nonce, cipher := m.Blob[:8], m.Blob[8:]
	out := make([]byte, len(cipher))
	chacha20XOR(out, cipher, nonce, shareKey)
	// Valid media cipher plains start with TLV tlvUID.
	if len(out) >= 4 && binary.BigEndian.Uint16(out[0:2]) == tlvUID {
		m.Plain = out
		return true
	}
	return false
}

func (m *mediaCNT) hasCipherTLV(typ uint16) bool {
	if len(m.Plain) == 0 {
		return false
	}
	return len(tlvValue(m.Plain, typ)) > 0
}

func (m *mediaCNT) authLen() int {
	if v, ok := m.TLVs[tlvAuth]; ok {
		return len(v)
	}
	return 0
}

func (m *mediaCNT) summary() string {
	plainN := 0
	if m.Plain != nil {
		plainN = len(m.Plain)
	}
	return fmt.Sprintf("kind=%s msgid=%#x len=%d blob=%d layout=%#x auth=%d plain=%d buddy15=%v",
		m.kindName(), m.MsgID, len(m.Raw), m.BlobLen, m.Layout, m.authLen(), plainN, m.TLVs[tlvMappedAddr] != nil)
}

func summarizeTLVs(buf []byte) string {
	if len(buf) == 0 {
		return "[]"
	}
	out := "["
	off := 0
	n := 0
	for off+4 <= len(buf) && n < 12 {
		t := binary.BigEndian.Uint16(buf[off : off+2])
		l := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		off += 4
		if l < 0 || off+l > len(buf) {
			break
		}
		if n > 0 {
			out += " "
		}
		out += fmt.Sprintf("%#x/%d", t, l)
		off += l
		n++
	}
	return out + "]"
}
