package vncpasswd

import (
	"encoding/binary"
)

// deskey generates a DES key schedule from an 8-byte key.
//
// This function implements the DES key schedule algorithm as specified in
// ANSI X3.92-1981. It takes an 8-byte key and produces 32 subkeys (16 rounds
// with 2 subkeys per round) used in the DES encryption/decryption process.
//
// The decrypt parameter controls the order of the subkeys:
//   - false: subkeys are ordered for encryption
//   - true: subkeys are reversed for decryption
//
// Thanks to James Gillogly & Phil Karn for the original implementation.
func deskey(key [8]byte, decrypt bool) [32]uint32 {
	var pc1m, pcr [56]bool
	var kn [32]uint32

	for j := 0; j < 56; j++ {
		l := pc1[j]
		m := l & 7
		if (key[l>>3] & bytebit[m]) != 0 {
			pc1m[j] = true
		} else {
			pc1m[j] = false
		}
	}

	for i := 0; i < 16; i++ {
		var m int
		if decrypt {
			m = (15 - i) << 1
		} else {
			m = i << 1
		}
		n := m + 1
		kn[m], kn[n] = 0, 0
		for j := byte(0); j < 28; j++ {
			l := j + totrot[i]
			if l < 28 {
				pcr[j] = pc1m[l]
			} else {
				pcr[j] = pc1m[l-28]
			}
		}
		for j := byte(28); j < 56; j++ {
			l := j + totrot[i]
			if l < 56 {
				pcr[j] = pc1m[l]
			} else {
				pcr[j] = pc1m[l-28]
			}
		}
		for j := byte(0); j < 24; j++ {
			if pcr[pc2[j]] {
				kn[m] |= bigbyte[j]
			}
			if pcr[pc2[j+24]] {
				kn[n] |= bigbyte[j]
			}
		}
	}

	return cookey(kn)
}

// cookey transforms the raw key schedule into an optimized format.
//
// This function post-processes the key schedule produced by deskey,
// rearranging the bits for more efficient S-box lookups during the
// DES encryption/decryption rounds.
func cookey(raw [32]uint32) [32]uint32 {
	for i := byte(0); i < 32; i += 2 {
		raw0, raw1 := raw[i], raw[i+1]
		k := (raw0 & 0x00fc0000) << 6
		k |= (raw0 & 0x00000fc0) << 10
		k |= (raw1 & 0x00fc0000) >> 10
		k |= (raw1 & 0x00000fc0) >> 6
		raw[i] = k
		k = (raw0 & 0x0003f000) << 12
		k |= (raw0 & 0x0000003f) << 16
		k |= (raw1 & 0x0003f000) >> 4
		k |= (raw1 & 0x0000003f)
		raw[i+1] = k
	}

	return raw
}

// desfunc performs DES encryption or decryption on an 8-byte block.
//
// This function implements the core DES Feistel cipher. It takes an 8-byte
// input block and a key schedule (from deskey), and returns the encrypted
// or decrypted 8-byte result.
//
// The function performs:
//   - Initial permutation (IP)
//   - 16 rounds of the Feistel function using S-boxes (sp1-sp8)
//   - Final permutation (IP^-1)
//
// Whether encryption or decryption is performed depends on the key schedule
// ordering (set by the decrypt parameter in deskey).
func desfunc(block []byte, keys [32]uint32) []byte {
	var leftt, right uint32
	leftt = binary.BigEndian.Uint32(block[:4])
	right = binary.BigEndian.Uint32(block[4:])

	work := ((leftt >> 4) ^ right) & 0x0f0f0f0f
	right ^= work
	leftt ^= (work << 4)
	work = ((leftt >> 16) ^ right) & 0x0000ffff
	right ^= work
	leftt ^= (work << 16)
	work = ((right >> 2) ^ leftt) & 0x33333333
	leftt ^= work
	right ^= (work << 2)
	work = ((right >> 8) ^ leftt) & 0x00ff00ff
	leftt ^= work
	right ^= (work << 8)
	right = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff
	work = (leftt ^ right) & 0xaaaaaaaa
	leftt ^= work
	right ^= work
	leftt = ((leftt << 1) | ((leftt >> 31) & 1)) & 0xffffffff

	for i := 0; i < 32; i += 4 {
		work = (right << 28) | (right >> 4)
		work ^= keys[i]
		fval := sp7[work&0x3f]
		fval |= sp5[(work>>8)&0x3f]
		fval |= sp3[(work>>16)&0x3f]
		fval |= sp1[(work>>24)&0x3f]
		work = right ^ keys[i+1]
		fval |= sp8[work&0x3f]
		fval |= sp6[(work>>8)&0x3f]
		fval |= sp4[(work>>16)&0x3f]
		fval |= sp2[(work>>24)&0x3f]
		leftt ^= fval
		work = (leftt << 28) | (leftt >> 4)
		work ^= keys[i+2]
		fval = sp7[work&0x3f]
		fval |= sp5[(work>>8)&0x3f]
		fval |= sp3[(work>>16)&0x3f]
		fval |= sp1[(work>>24)&0x3f]
		work = leftt ^ keys[i+3]
		fval |= sp8[work&0x3f]
		fval |= sp6[(work>>8)&0x3f]
		fval |= sp4[(work>>16)&0x3f]
		fval |= sp2[(work>>24)&0x3f]
		right ^= fval

	}

	right = (right << 31) | (right >> 1)
	work = (leftt ^ right) & 0xaaaaaaaa
	leftt ^= work
	right ^= work
	leftt = (leftt << 31) | (leftt >> 1)
	work = ((leftt >> 8) ^ right) & 0x00ff00ff
	right ^= work
	leftt ^= (work << 8)
	work = ((leftt >> 2) ^ right) & 0x33333333
	right ^= work
	leftt ^= (work << 2)
	work = ((right >> 16) ^ leftt) & 0x0000ffff
	leftt ^= work
	right ^= (work << 16)
	work = ((right >> 4) ^ leftt) & 0x0f0f0f0f
	leftt ^= work
	right ^= (work << 4)

	leftt &= 0xffffffff
	right &= 0xffffffff

	res := make([]byte, 8)
	binary.BigEndian.PutUint32(res[:4], right)
	binary.BigEndian.PutUint32(res[4:], leftt)
	return res
}
