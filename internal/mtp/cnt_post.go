package mtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
)

// buildPostConnectCNT continues the successful CNT sequence before KCP.
//
// PacketSign (playback_2): HMAC(signKey, wire[0:388]) where 388 covers
// CNT hdr + body through TLV 0x0012. Timestamp 0x002a is appended after the
// signed prefix (CNTMessageSendTimeStampSet patches it post-sign). Sign TLV
// 0x0026 is also outside the HMAC window — same trailer-len-prefix pattern
// as CNT reply ServerSign.
//
// Cipher area (ImportDataEncrypt mode=1): AES-128-CBC
//
//	inner blob = BE32(padLen) || IV(16) || AES-CBC(plain || PKCS7)
//	then 4 zero bytes, then clear TLVs.
func buildPostConnectCNT(
	session []byte, dest net.IP, port uint16, sequence uint32, ctx *loginContext,
	transactionID uint32, timestamp uint64, shareKey, signKey []byte,
) []byte {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	var plain []byte
	if ctx != nil {
		plain = ctx.postCNTPlain()
	}
	blob := encryptCNTCipherBlob(plain, shareKey)
	inner := uint16(len(blob))
	outer := uint16(inner + 8)

	body := make([]byte, 0, 28+len(blob)+4+80)
	body = append(body, nonce...)
	body = binary.BigEndian.AppendUint32(body, sequence)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint16(body, outer)
	body = binary.BigEndian.AppendUint16(body, inner)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, blob...)
	body = append(body, 0, 0, 0, 0) // 4 zero bytes before clear TLVs (pcap)

	body = appendTLV(body, tlvTransactionID, be32(transactionID))
	body = appendTLV(body, tlvFlag, tlvFlagOne())
	connID := uint32(0)
	if ctx != nil {
		connID = ctx.connectionID
	}
	body = appendTLV(body, tlvConnectionID, be32(connID))

	attr12 := make([]byte, fieldAddrAttrLen)
	attr12[0], attr12[1] = 0x02, 0x02
	binary.BigEndian.PutUint16(attr12[2:4], port)
	if d4 := dest.To4(); d4 != nil {
		copy(attr12[4:8], d4)
	}
	body = appendTLV(body, tlvDestAddr, attr12)

	// Prefix to sign: CNT hdr (16) + body so far (through tlvDestAddr).
	signedBodyLen := len(body)

	body = appendTLV(body, tlvSendTimestamp, be64(timestamp)) // outside HMAC window

	bodyBeforeSign := len(body)
	// blen under-reports PacketSign overflow by 20 (pcap: wire 440, blen 404).
	blen := uint16(bodyBeforeSign + 4 + 36 - 20)

	msg := make([]byte, 0, 16+bodyBeforeSign+40)
	msg = append(msg, magicCNT...)
	if len(session) >= 8 {
		msg = append(msg, session[:8]...)
	} else {
		msg = append(msg, make([]byte, 8)...)
	}
	msg = binary.BigEndian.AppendUint16(msg, 2) // MsgID (post-CNT)
	msg = binary.BigEndian.AppendUint16(msg, blen)
	msg = append(msg, body...)

	signedLen := 16 + signedBodyLen
	mac := hmac.New(sha256.New, signKey)
	mac.Write(msg[:signedLen])
	sum := mac.Sum(nil)

	msg = binary.BigEndian.AppendUint16(msg, tlvPacketSign)
	msg = binary.BigEndian.AppendUint16(msg, fieldSignValueLen)
	msg = append(msg, sum...)
	msg = binary.BigEndian.AppendUint16(msg, signTrailerMagic)
	msg = binary.BigEndian.AppendUint16(msg, uint16(signedLen))
	return msg
}

// encryptCNTCipherBlob builds the CNT inner cipher blob (ImportDataEncrypt mode=1):
//
//	BE32(padLen) || IV(16) || AES-128-CBC(plaintext || PKCS7)
//
// libmiss tiny-AES-c is compiled as AES-128 (RoundKey@176, Iv@0xb0).
func encryptCNTCipherBlob(plain, key32 []byte) []byte {
	if len(key32) < 16 {
		panic("mtp: AES key too short")
	}
	key := key32[:16]
	padLen := aes.BlockSize - (len(plain) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}
	padded := make([]byte, len(plain)+padLen)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipherText := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, padded)

	out := make([]byte, 0, 4+16+len(cipherText))
	out = binary.BigEndian.AppendUint32(out, uint32(padLen))
	out = append(out, iv...)
	out = append(out, cipherText...)
	return out
}

// decryptCNTCipherBlobAES decrypts an ImportDataEncrypt mode=1 blob (AES-128-CBC).
func decryptCNTCipherBlobAES(blob, key32 []byte) ([]byte, bool) {
	if len(key32) < 16 || len(blob) < 4+aes.BlockSize+aes.BlockSize {
		return nil, false
	}
	if (len(blob)-4-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, false
	}
	key := key32[:16]
	iv := blob[4 : 4+aes.BlockSize]
	ct := blob[4+aes.BlockSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	if len(plain) == 0 {
		return nil, false
	}
	padLen := int(plain[len(plain)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plain) {
		return nil, false
	}
	for i := 0; i < padLen; i++ {
		if plain[len(plain)-1-i] != byte(padLen) {
			return nil, false
		}
	}
	return plain[:len(plain)-padLen], true
}
