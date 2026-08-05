package mtp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
)

// Native bumps MSIP 0x0009 by this between successive MTP login plains.
const loginRequestIDStep = 0x400001

type loginContext struct {
	authInfo     []byte // 320-byte ASCII authStr (NOT base64-decoded)
	nativePublic []byte
	did          string
	uid          string
	callerUUID   string
	connectionID uint32
	// loginReqID is MSIP 0x0009 in MTP plains; starts near connectionID and
	// advances by loginRequestIDStep on each transport send (Frida).
	loginReqID  uint32
	transaction uint32
	server      net.IP
	port        uint16
	timestamp   uint64
	relayAddr   []byte // MSIP 0x0015 from CNT reply (transport NAT view)
	// buddyAddr is MediaBinding/bound clear 0x0015 (and CNT| target).
	// Native pcap: LoginResponse 0x0015 = 93.84.107.114:44128 — same value in
	// MediaBinding / CNT|; NOT STUN XOR-MAPPED and NOT punch-ack echo (both
	// 46.205.x). Seed from LoginResponse; STUN only for NAT registration.
	buddyAddr []byte
	stunAddrs []byte // MA_STUN_ADDRS (0x002d) from LoginResponse, if any

	loginHexTS string // stable 0x0011 value across login retries
	ssVer      uint32 // MSIP 0x000d in post-CNT (cloud ssVer, e.g. 453)
	// Post-CNT flag TLVs (overridden per phase by builders).
	changeFlags uint32 // 0x0023
	closeFlags  uint32 // 0x0019
}

func newLoginContext(
	authStr string, nativePublic []byte, server net.IP, port uint16,
	connectionID, replyTxn uint32, did, uid, callerUUID string,
) (*loginContext, error) {
	if len(authStr) != authStrLen {
		return nil, fmt.Errorf("mtp: authStr length %d want %d", len(authStr), authStrLen)
	}
	// Validate it is base64 of 240 bytes, but keep ASCII on the wire (Frida).
	if decoded, err := base64.StdEncoding.DecodeString(authStr); err != nil || len(decoded) != 240 {
		return nil, fmt.Errorf("mtp: authStr must be 320-char base64 of 240 bytes: %v", err)
	}
	if len(nativePublic) != 32 || server.To4() == nil {
		return nil, fmt.Errorf("mtp: invalid native login key/address")
	}
	if did == "" || uid == "" || callerUUID == "" {
		return nil, fmt.Errorf("mtp: did, mtp_uid and caller_uuid required for post-CNT")
	}
	if connectionID == 0 {
		connectionID = randomConnectionID()
	}
	txn := replyTxn
	if txn == 0 {
		txn = randomUint32() &^ 0x80001
	}
	return &loginContext{
		authInfo:     []byte(authStr),
		nativePublic: append([]byte(nil), nativePublic...),
		did:          did,
		uid:          uid,
		callerUUID:   callerUUID,
		connectionID: connectionID,
		loginReqID:   connectionID & connIDMask,
		transaction:  txn,
		server:       append(net.IP(nil), server.To4()...),
		port:         port,
	}, nil
}

func (ctx *loginContext) nextTransaction() uint32 {
	ctx.transaction += 0x80001
	return ctx.transaction
}

// nextLoginRequestID returns the current 0x0009 value and advances it the way
// Mi Home does between pre-login and login retries.
func (ctx *loginContext) nextLoginRequestID() uint32 {
	id := ctx.loginReqID
	ctx.loginReqID += loginRequestIDStep
	return id
}

func randomUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	value := binary.BigEndian.Uint32(b[:])
	if value == 0 {
		return 1
	}
	return value
}

func randomConnectionID() uint32 {
	var b [3]byte
	_, _ = rand.Read(b[:])
	// Mi Home uses values like 0x00a78258 / 0x000a6ef0 (top byte clear).
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func be32(value uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}

func be64(value uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, value)
	return out
}

func paddedString(s string, size int) []byte {
	out := make([]byte, size)
	n := copy(out, s)
	// Frida: fixed fields are NUL-padded with the string length in the last byte.
	if n < size {
		out[size-1] = byte(n)
	}
	return out
}

func (ctx *loginContext) serverAddress() []byte {
	out := make([]byte, fieldAddrAttrLen)
	out[0], out[1] = 2, 2
	binary.BigEndian.PutUint16(out[2:4], ctx.port)
	copy(out[4:8], ctx.server.To4())
	return out
}

// appendEncryptedAttr packs Encrypted* attrs the way FUN_0017835c does:
//
//	type | outer | actual_len | reserved=0 | data | pad-to-outer
//
// outer is the full TLV size from type through padding, rounded up to 4:
// (datalen+8+3)&^3. Pad is outer - 8 - datalen.
func appendEncryptedAttr(dst []byte, typ uint16, val []byte) []byte {
	outer := (len(val) + 8 + 3) &^ 3
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, uint16(outer))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(val)))
	dst = binary.BigEndian.AppendUint16(dst, 0)
	dst = append(dst, val...)
	if pad := outer - (8 + len(val)); pad > 0 {
		dst = append(dst, make([]byte, pad)...)
	}
	return dst
}

// localCandidates builds MSIP 0x0004: count_BE32 + 24-byte IPv4 UDP entries.
// Current native run sends 2 candidates.
func localCandidates() []byte {
	var ips []net.IP
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip4 := ip.To4(); ip4 != nil {
				ips = append(ips, append(net.IP(nil), ip4...))
				if len(ips) == 2 {
					break
				}
			}
		}
		if len(ips) == 2 {
			break
		}
	}
	for len(ips) < 2 {
		ips = append(ips, net.IPv4zero.To4())
	}
	ips = ips[:2]

	out := make([]byte, 4, 4+24*2)
	binary.BigEndian.PutUint32(out, 2)
	for _, ip := range ips {
		cand := make([]byte, 24)
		cand[0], cand[1] = 2, 3
		binary.BigEndian.PutUint16(cand[4:6], mediaUDPPort)
		binary.BigEndian.PutUint16(cand[6:8], mediaUDPPort)
		copy(cand[8:12], ip.To4())
		out = append(out, cand...)
	}
	return out
}

// postCNTPlain is the CNT cipher-area plaintext for device-login post-connect.
func (ctx *loginContext) postCNTPlain() []byte {
	return ctx.postCNTData(ctx.changeFlags, ctx.closeFlags)
}

// transportPlainPre is the first KCP/MTP plain after initial post-CNT.
// Same shape as login but without tlvChangeFlags.
func (ctx *loginContext) transportPlainPre() []byte {
	return ctx.transportPlainWith(false)
}

// transportPlain is the KCP LoginRequest plaintext (AES-CBC mode=1).
//
//	tlvUID + tlvCallerUUID + tlvHexTimestamp + tlvDeviceID +
//	tlvRequestID + tlvChannelSession + tlvPublicKey + tlvChangeFlags(enable) +
//	tlvCandidates + tlvMappedAddr + tlvTimestamp
func (ctx *loginContext) transportPlain() []byte {
	return ctx.transportPlainWith(true)
}

func (ctx *loginContext) transportPlainWith(includeChangeFlags bool) []byte {
	out := make([]byte, 0, 340)
	out = appendTLV(out, tlvUID, paddedString(ctx.uid, fieldUIDLen))
	out = appendTLV(out, tlvCallerUUID, paddedString(ctx.callerUUID, fieldCallerUUIDLen))
	hexTS := ctx.loginHexTS
	if hexTS == "" {
		hexTS = fmt.Sprintf("%016x", ctx.timestamp)
	}
	out = appendTLV(out, tlvHexTimestamp, paddedString(hexTS, fieldHexTSLen))
	out = appendTLV(out, tlvDeviceID, paddedString(ctx.did, fieldDIDLen))
	out = appendTLV(out, tlvRequestID, be32(ctx.nextLoginRequestID()))
	out = appendTLV(out, tlvChannelSession, make([]byte, fieldChannelSessionLen))
	keyVal := make([]byte, fieldPublicKeyAttrLen)
	binary.BigEndian.PutUint32(keyVal[0:4], pubKeyAttrHeader)
	copy(keyVal[4:36], ctx.nativePublic)
	out = appendTLV(out, tlvPublicKey, keyVal)
	if includeChangeFlags {
		out = appendTLV(out, tlvChangeFlags, be32(changeFlagEnable))
	}
	out = appendTLV(out, tlvCandidates, localCandidates())
	relay := ctx.relayAddr
	if len(relay) != fieldAddrAttrLen {
		relay = make([]byte, fieldAddrAttrLen)
		relay[0], relay[1] = 2, 2
	}
	out = appendTLV(out, tlvMappedAddr, relay)
	out = appendTLV(out, tlvTimestamp, be64(ctx.timestamp))
	return out
}

// postCNTData returns the device-login TLV block for post-connect CNT.
// Native phases (single connection):
//
//  1. changeFlags=0,    closeFlags=1   — announce
//  2. changeFlags=0,    closeFlags=0   — clear
//  3. changeFlags=changeFlagEnable, closeFlags=0 — enable media/login capability
func (ctx *loginContext) postCNTData(changeFlags, closeFlags uint32) []byte {
	out := make([]byte, 0, 240)
	out = appendTLV(out, tlvTimestamp, be64(ctx.timestamp))
	out = appendTLV(out, tlvDeviceID, paddedString(ctx.did, fieldDIDLen))
	out = appendTLV(out, tlvUID, paddedString(ctx.uid, fieldUIDLen))
	out = appendTLV(out, tlvCallerUUID, paddedString(ctx.callerUUID, fieldCallerUUIDLen))
	out = appendTLV(out, tlvCandidates, localCandidates())
	out = appendTLV(out, tlvChangeFlags, be32(changeFlags))
	out = appendTLV(out, tlvCloseFlags, be32(closeFlags))
	ver := ctx.ssVer
	if ver == 0 {
		ver = defaultSSVer
	}
	out = appendTLV(out, tlvSSVer, be32(ver))
	return out
}
