package mtp

// MSIP TLV type IDs (BE u16). Shared across CNT / MTP / CNT~ clear and cipher areas.
const (
	tlvEmpty          uint16 = 0x0000 // separator / empty attr
	tlvAuth           uint16 = 0x0001 // auth token / authStr
	tlvPublicKey      uint16 = 0x0002 // Curve25519 public (often len-prefixed 40 B)
	tlvMediaEndpoints uint16 = 0x0003 // LoginResponse media relay list
	tlvCandidates     uint16 = 0x0004 // local ICE-ish candidates
	tlvProbedAddrs    uint16 = 0x0006 // probed / candidate-list addresses
	tlvTransactionID  uint16 = 0x0008
	tlvRequestID      uint16 = 0x0009 // login / session request id
	tlvConnectionID   uint16 = 0x000a
	tlvFlag           uint16 = 0x000b // usually BE32(1)
	tlvCapability     uint16 = 0x000c
	tlvSSVer          uint16 = 0x000d // cloud signalling server version
	tlvDeviceID       uint16 = 0x000e // DID (padded)
	tlvUID            uint16 = 0x000f
	tlvCallerUUID     uint16 = 0x0010
	tlvHexTimestamp   uint16 = 0x0011 // ASCII hex of login timestamp
	tlvDestAddr       uint16 = 0x0012 // 20-byte address attr
	tlvLocalAddr      uint16 = 0x0013 // outbound iface :40000
	tlvCameraAddr     uint16 = 0x0014 // camera LAN :40000
	tlvMappedAddr     uint16 = 0x0015 // MA_MAPPED_ADDR / relay / buddy
	tlvTimestamp      uint16 = 0x0017 // unix-ms BE64
	tlvSessionToken   uint16 = 0x0018 // 8-byte session token (media clear)
	tlvCloseFlags     uint16 = 0x0019
	tlvFlags          uint16 = 0x001a
	tlvChannelSession uint16 = 0x001e // 8-byte channel session
	tlvEndpointCount  uint16 = 0x0020
	tlvCandidateFlagA uint16 = 0x0022
	tlvChangeFlags    uint16 = 0x0023
	tlvCandidateFlagB uint16 = 0x0024
	tlvServerSign     uint16 = 0x0025 // HMAC trailer (authToken key)
	tlvPacketSign     uint16 = 0x0026 // HMAC trailer (shareSign key)
	tlvEncryptedJSON  uint16 = 0x0028 // status CSK/SI JSON (len-prefixed attr)
	tlvSendTimestamp  uint16 = 0x002a // outside most HMAC windows
	tlvBuddyTimestamp uint16 = 0x002b
	tlvBuddyFlag      uint16 = 0x002c
	tlvStunAddrs      uint16 = 0x002d // MA_STUN_ADDRS
	tlvBindingFlag    uint16 = 0x002f // MediaBinding cipher flag
)

// Fixed padded field sizes on the wire (Frida: NUL-padded, length in last byte).
const (
	fieldUIDLen            = 24
	fieldCallerUUIDLen     = 40
	fieldDIDLen            = 68
	fieldHexTSLen          = 20
	fieldAddrAttrLen       = 20
	fieldChannelSessionLen = 8
	fieldPublicKeyAttrLen  = 40 // BE32 hdr + 32-byte key
	fieldSignValueLen      = 0x24 // 36: HMAC-32 || 00 20 || BE16(signedLen)
)

// Other wire constants with clear meaning.
const (
	mediaUDPPort       = 40000
	changeFlagEnable   = 0x10 // 0x0023 value that enables media/login
	pubKeyAttrHeader   = 0x00200000
	signTrailerMagic   = 0x0020 // u16 after HMAC inside sign TLV value
	flagValueOne       = uint32(1)
	connIDMask         = 0x000fffff
	defaultSSVer       = 0x01c5 // 453 — used when cloud ssVer unset
)

// tlvFlagOne is the common clear TLV 0x000b = BE32(1).
func tlvFlagOne() []byte { return []byte{0, 0, 0, 1} }
