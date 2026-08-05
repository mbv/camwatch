package mtp

// CityHash128WithSeed for lengths < 128 (CityMurmur), enough for CHK PacketSign (52 B).
// Port of Google cityhash CityMurmur / CityHash128WithSeed.

const (
	cityK0 = 0xc3a5c85c97cb3127
	cityK1 = 0xb492b66fbe98f273
	cityK2 = 0x9ae16a3b2f90404f
)

func cityFetch64(s []byte, i int) uint64 {
	return uint64(s[i]) | uint64(s[i+1])<<8 | uint64(s[i+2])<<16 | uint64(s[i+3])<<24 |
		uint64(s[i+4])<<32 | uint64(s[i+5])<<40 | uint64(s[i+6])<<48 | uint64(s[i+7])<<56
}

func cityFetch32(s []byte, i int) uint32 {
	return uint32(s[i]) | uint32(s[i+1])<<8 | uint32(s[i+2])<<16 | uint32(s[i+3])<<24
}

func cityRotate(val uint64, shift uint) uint64 {
	if shift == 0 {
		return val
	}
	return (val >> shift) | (val << (64 - shift))
}

func cityShiftMix(val uint64) uint64 { return val ^ (val >> 47) }

func cityHash128to64(u, v uint64) uint64 {
	const mul = 0x9ddfea08eb382d69
	a := (u ^ v) * mul
	a ^= a >> 47
	b := (v ^ a) * mul
	b ^= b >> 47
	return b * mul
}

func cityHashLen16(u, v, mul uint64) uint64 {
	a := (u ^ v) * mul
	a ^= a >> 47
	b := (v ^ a) * mul
	b ^= b >> 47
	return b * mul
}

func cityHashLen16Default(u, v uint64) uint64 { return cityHash128to64(u, v) }

func cityHashLen0to16(s []byte) uint64 {
	length := len(s)
	if length >= 8 {
		mul := cityK2 + uint64(length)*2
		a := cityFetch64(s, 0) + cityK2
		b := cityFetch64(s, length-8)
		c := cityRotate(b, 37)*mul + a
		d := (cityRotate(a, 25) + b) * mul
		return cityHashLen16(c, d, mul)
	}
	if length >= 4 {
		mul := cityK2 + uint64(length)*2
		a := uint64(cityFetch32(s, 0))
		return cityHashLen16(uint64(length)+(a<<3), uint64(cityFetch32(s, length-4)), mul)
	}
	if length > 0 {
		a := uint64(s[0])
		b := uint64(s[length>>1])
		c := uint64(s[length-1])
		y := a + (b << 8)
		z := uint64(length) + (c << 2)
		return cityShiftMix(y*cityK2^(z*cityK0)) * cityK2
	}
	return cityK2
}

// cityHash128WithSeed returns (low, high) for len(s) < 128.
func cityHash128WithSeed(s []byte, seedLow, seedHigh uint64) (uint64, uint64) {
	length := len(s)
	a, b := seedLow, seedHigh
	var c, d uint64
	if length <= 16 {
		a = cityShiftMix(a*cityK1) * cityK1
		c = b*cityK1 + cityHashLen0to16(s)
		if length >= 8 {
			d = cityShiftMix(a + cityFetch64(s, 0))
		} else {
			d = cityShiftMix(a + c)
		}
	} else {
		c = cityHashLen16Default(cityFetch64(s, length-8)+cityK1, a)
		d = cityHashLen16Default(b+uint64(length), c+cityFetch64(s, length-16))
		a += d
		for length > 16 {
			a ^= cityShiftMix(cityFetch64(s, 0)*cityK1) * cityK1
			a *= cityK1
			b ^= a
			c ^= cityShiftMix(cityFetch64(s, 8)*cityK1) * cityK1
			c *= cityK1
			d ^= c
			s = s[16:]
			length -= 16
		}
	}
	a = cityHashLen16Default(a, c)
	b = cityHashLen16Default(d, b)
	return a ^ b, cityHashLen16Default(b, a)
}

// cityHash128MAC16 returns the 16-byte PacketSign MAC used on CHK~.
//
// Seed = (BE(shareSign[8:16]), BE(shareSign[0:8])); output is big-endian (hi||lo).
func cityHash128MAC16(data, shareSign []byte) []byte {
	if len(shareSign) < 16 {
		return make([]byte, 16)
	}
	s0 := uint64(shareSign[8])<<56 | uint64(shareSign[9])<<48 | uint64(shareSign[10])<<40 | uint64(shareSign[11])<<32 |
		uint64(shareSign[12])<<24 | uint64(shareSign[13])<<16 | uint64(shareSign[14])<<8 | uint64(shareSign[15])
	s1 := uint64(shareSign[0])<<56 | uint64(shareSign[1])<<48 | uint64(shareSign[2])<<40 | uint64(shareSign[3])<<32 |
		uint64(shareSign[4])<<24 | uint64(shareSign[5])<<16 | uint64(shareSign[6])<<8 | uint64(shareSign[7])
	lo, hi := cityHash128WithSeed(data, s0, s1)
	out := make([]byte, 16)
	for i := 0; i < 8; i++ {
		out[i] = byte(hi >> uint(56-8*i))
		out[8+i] = byte(lo >> uint(56-8*i))
	}
	return out
}
