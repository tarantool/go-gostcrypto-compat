package gostcryptocompat

// KDFTree2012_256 — Streebog-256-based key derivation function tree per
// R 50.1.113-2016 §4.5, used by gost2015_acpkm_omac_init for the initial
// (master, kdf_seed) → (cipher_key, mac_key) split inside RFC 9367 ciphers.
//
// Mirrors gost-engine's gost_kdftree2012_256(..., representation=1):
//   HMAC_Streebog256(key,  i_byte(1) || label || 0x00 || seed || L_be(2))
// for i = 1..keyOutLen/32, where L_be(2) is the bit-length of the desired
// output big-endian (e.g. 0x02 0x00 for 64 bytes = 512 bits).

import (
	"crypto/hmac"
	"encoding/binary"

	"go.stargrave.org/gogost/v7/gost34112012256"
)

// KDFTree2012_256 derives keyOutLen bytes of key material from key + label + seed.
// keyOutLen must be a positive multiple of 32 and at most 8160 (per the
// 2-byte length encoding); typical TLS use is 64.
//
// Output bytes are produced by chained HMAC-Streebog-256 with a 1-byte
// big-endian iteration counter starting at 1.
func KDFTree2012_256(key, label, seed []byte, keyOutLen int) []byte {
	if keyOutLen <= 0 || keyOutLen%32 != 0 {
		panic("gost.KDFTree2012_256: keyOutLen must be a positive multiple of 32")
	}
	if keyOutLen > 0xFFFF/8 {
		panic("gost.KDFTree2012_256: keyOutLen too large for 2-byte length encoding")
	}

	out := make([]byte, keyOutLen)
	var lenBE [2]byte
	binary.BigEndian.PutUint16(lenBE[:], uint16(keyOutLen*8))

	iters := keyOutLen / 32
	for i := 1; i <= iters; i++ {
		h := hmac.New(gost34112012256.New, key)
		h.Write([]byte{byte(i)})
		h.Write(label)
		h.Write([]byte{0x00})
		h.Write(seed)
		h.Write(lenBE[:])
		copy(out[(i-1)*32:i*32], h.Sum(nil))
	}
	return out
}
