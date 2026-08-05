package mtp

import (
	"encoding/binary"
)

// chacha20XOR is libsodium crypto_stream_chacha20_xor (original 8-byte nonce /
// 64-bit counter). libmiss binds PTR_crypto_stream_chacha20_xor — NOT IETF.
func chacha20XOR(dst, src, nonce8, key32 []byte) {
	chacha20XOROriginal(dst, src, nonce8, key32)
}

// chacha20XOROriginal is libsodium crypto_stream_chacha20_xor (8-byte nonce).
func chacha20XOROriginal(dst, src, nonce8, key32 []byte) {
	var counter uint64
	var block [64]byte
	for off := 0; off < len(src); {
		chacha20BlockOriginal(&block, key32, counter, nonce8)
		counter++
		n := len(src) - off
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			dst[off+i] = src[off+i] ^ block[i]
		}
		off += n
	}
}

func chacha20BlockOriginal(out *[64]byte, key []byte, counter uint64, nonce []byte) {
	var s, w [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	s[12] = uint32(counter)
	s[13] = uint32(counter >> 32)
	s[14] = binary.LittleEndian.Uint32(nonce[0:4])
	s[15] = binary.LittleEndian.Uint32(nonce[4:8])
	w = s
	for i := 0; i < 10; i++ {
		quarterRound(&w, 0, 4, 8, 12)
		quarterRound(&w, 1, 5, 9, 13)
		quarterRound(&w, 2, 6, 10, 14)
		quarterRound(&w, 3, 7, 11, 15)
		quarterRound(&w, 0, 5, 10, 15)
		quarterRound(&w, 1, 6, 11, 12)
		quarterRound(&w, 2, 7, 8, 13)
		quarterRound(&w, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], w[i]+s[i])
	}
}

func quarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = s[d]<<16 | s[d]>>16
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = s[b]<<12 | s[b]>>20
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = s[d]<<8 | s[d]>>24
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = s[b]<<7 | s[b]>>25
}
