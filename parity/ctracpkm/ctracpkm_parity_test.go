// Package ctracpkmparity contains differential parity tests for the clean-room
// gostcrypto CTR / CTR-ACPKM implementation against the in-repo
// gostcryptocompat oracle (ctr_gost.go).
//
// NOTE — oracle independence (CTRA-03): vendored gogost v7 has NO CTR or
// CTR-ACPKM mode for Kuznyechik/Magma (third_party/gogost/gost3413/ contains
// only padding.go). The oracle here is gostcryptocompat.NewCTR /
// NewCTRACPKM (ctr_gost.go), which is independently anchored to gost-engine
// v3.0.3 KATs: cipher_modes_test.go (Kuznyechik CTR-ACPKM-32 and Master-96
// vectors), ctr_test.go (plain-CTR KATs), and magma_acpkm_test.go (Magma K2
// meshing etalon). This is therefore a clean-room ↔ engine-KAT-anchored-facade
// comparison, not a clean-room ↔ gogost comparison.
package ctracpkmparity

import (
	"bytes"
	"crypto/cipher"
	"testing"

	ref "github.com/tarantool/go-gostcrypto-compat"
	"github.com/tarantool/go-gostcrypto/ctracpkm"
	"github.com/tarantool/go-gostcrypto/kuznyechik"
	"github.com/tarantool/go-gostcrypto/magma"
)

// xorKeyStreamChunked feeds src into s via a deterministic chunk schedule
// seeded by chunkSeed, writing to dst. Both s and dst/src must correspond to
// a freshly constructed stream cipher so the streaming-state accumulates
// identically across calls.
func xorKeyStreamChunked(s cipher.Stream, dst, src []byte, chunkSeed uint8) {
	off := 0
	step := chunkSeed
	n := len(src)
	for off < n {
		chunk := 1 + int(step%13)
		if off+chunk > n {
			chunk = n - off
		}
		s.XORKeyStream(dst[off:off+chunk], src[off:off+chunk])
		off += chunk
		step = step*31 + 7
	}
}

// TestDiff_CTRACPKM_vs_Oracle drives the in-repo gost oracle and the clean-room
// impl with identical inputs and asserts byte-equal keystream. The oracle
// constructors are NewCTR(block, iv) and NewCTRACPKM(newBlock, key, iv,
// section) — ctr-acpkm.md §"Conformance" pins these signatures.
//
// For each (cipher, section, length) triple the test verifies:
//   - one-shot XORKeyStream (out-of-place)
//   - chunked XORKeyStream over a fixed set of chunk shapes (CTRA-01/04)
//   - in-place XORKeyStream dst==src (CTRA-06)
func TestDiff_CTRACPKM_vs_Oracle(t *testing.T) {
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	type tc struct {
		name     string
		newBlock func([]byte) cipher.Block
		ivLen    int
		sections []int
		lengths  []int
	}
	cases := []tc{
		{
			name:     "kuznyechik",
			newBlock: func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
			ivLen:    16,
			sections: []int{0, 16, 32, 64, 4096},
			lengths:  []int{1, 15, 16, 17, 31, 32, 33, 112, 257, 4096, 4097, 9000},
		},
		{
			name:     "magma",
			newBlock: func(k []byte) cipher.Block { return magma.NewCipher(k) },
			ivLen:    8,
			sections: []int{0, 8, 16, 1024},
			lengths:  []int{1, 7, 8, 9, 31, 32, 1024, 1025, 5000},
		},
	}

	// Fixed chunk schedules that exercise different boundary patterns.
	chunkSeeds := []uint8{1, 7, 13, 17, 31, 255}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			iv := make([]byte, c.ivLen)
			copy(iv, []byte{0x12, 0x34, 0x56, 0x78})
			for _, section := range c.sections {
				for _, n := range c.lengths {
					plain := make([]byte, n)
					for i := range plain {
						plain[i] = byte(i*7 + 3)
					}

					// --- one-shot out-of-place ---
					oracle, err := ref.NewCTRACPKM(c.newBlock, key, iv, section)
					if err != nil {
						t.Fatalf("oracle NewCTRACPKM(section=%d): %v", section, err)
					}
					refOut := make([]byte, n)
					oracle.XORKeyStream(refOut, plain)

					mine := ctracpkm.NewCTRACPKM(c.newBlock, key, iv, section)
					myOut := make([]byte, n)
					mine.XORKeyStream(myOut, plain)

					if !bytes.Equal(refOut, myOut) {
						t.Fatalf("%s section=%d len=%d divergence:\n ref %x\n new %x",
							c.name, section, n, refOut, myOut)
					}

					// --- chunked streaming (CTRA-01 / CTRA-04) ---
					for _, cs := range chunkSeeds {
						oracleC, err := ref.NewCTRACPKM(c.newBlock, key, iv, section)
						if err != nil {
							t.Fatalf("oracle NewCTRACPKM(section=%d) chunked: %v", section, err)
						}
						refChunked := make([]byte, n)
						xorKeyStreamChunked(oracleC, refChunked, plain, cs)

						mineC := ctracpkm.NewCTRACPKM(c.newBlock, key, iv, section)
						myChunked := make([]byte, n)
						xorKeyStreamChunked(mineC, myChunked, plain, cs)

						if !bytes.Equal(refChunked, myChunked) {
							t.Fatalf("%s section=%d len=%d chunkSeed=%d chunked divergence:\n ref %x\n new %x",
								c.name, section, n, cs, refChunked, myChunked)
						}
						// Cross-check: chunked output must equal one-shot output.
						if !bytes.Equal(refOut, refChunked) {
							t.Fatalf("%s section=%d len=%d chunkSeed=%d oracle chunked != one-shot:\n one-shot %x\n chunked  %x",
								c.name, section, n, cs, refOut, refChunked)
						}
					}

					// --- in-place dst==src (CTRA-06) ---
					oracleIP, err := ref.NewCTRACPKM(c.newBlock, key, iv, section)
					if err != nil {
						t.Fatalf("oracle NewCTRACPKM(section=%d) in-place: %v", section, err)
					}
					refInPlace := make([]byte, n)
					copy(refInPlace, plain)
					oracleIP.XORKeyStream(refInPlace, refInPlace)

					mineInPlace := make([]byte, n)
					copy(mineInPlace, plain)
					mineIP := ctracpkm.NewCTRACPKM(c.newBlock, key, iv, section)
					mineIP.XORKeyStream(mineInPlace, mineInPlace)

					if !bytes.Equal(refInPlace, mineInPlace) {
						t.Fatalf("%s section=%d len=%d in-place divergence:\n ref %x\n new %x",
							c.name, section, n, refInPlace, mineInPlace)
					}
					// Cross-check: in-place must equal out-of-place.
					if !bytes.Equal(refOut, refInPlace) {
						t.Fatalf("%s section=%d len=%d oracle in-place != out-of-place:\n out-of-place %x\n in-place     %x",
							c.name, section, n, refOut, refInPlace)
					}
				}
			}
		})
	}
}

// FuzzDiff_CTRACPKM_vs_Oracle mirrors TestDiff_CTRACPKM_vs_Oracle: it feeds the
// same key/iv/section/plaintext to the in-repo gost oracle and the clean-room
// CTR-ACPKM impl and asserts byte-equal keystream. The block-cipher choice is
// fuzzer-selected; key is normalized to 32 bytes and the IV to the cipher's
// block size, while the plaintext length stays variable so section boundaries
// (re-keying) are explored.
//
// This target also exercises:
//   - chunked streaming via a fuzzer-chosen chunkSeed (CTRA-01/04)
//   - in-place XORKeyStream dst==src (CTRA-06)
func FuzzDiff_CTRACPKM_vs_Oracle(f *testing.F) {
	// seed#0: Kuznyechik, section=32, out-of-place, chunkSeed=7
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("12345678000000000000000000000000"),
		uint16(32), uint8(7), false,
		[]byte("hello ctr-acpkm world, this is a longer plaintext"))
	// seed#1: Magma, section=8, out-of-place, chunkSeed=13
	f.Add(byte(1),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1234567800000000"),
		uint16(8), uint8(13), false,
		make([]byte, 100))
	// seed#2: Kuznyechik, section=0 (plain CTR), chunkSeed=1
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("12345678000000000000000000000000"),
		uint16(0), uint8(1), false,
		make([]byte, 33))
	// seed#3: Magma, section=1024 (ACPKM boundary crossing), chunkSeed=17
	f.Add(byte(1),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1234567800000000"),
		uint16(1024), uint8(17), false,
		make([]byte, 1025))
	// seed#4: Kuznyechik, in-place variant
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("12345678000000000000000000000000"),
		uint16(32), uint8(5), true,
		[]byte("in-place test data for ctracpkm"))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, rndIV []byte, sectionRaw uint16, chunkSeed uint8, inPlace bool, plain []byte) {
		var newBlock func([]byte) cipher.Block
		var ivLen int
		var bs int
		if sel&1 == 0 {
			newBlock = func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }
			ivLen = 16
			bs = 16
		} else {
			newBlock = func(k []byte) cipher.Block { return magma.NewCipher(k) }
			ivLen = 8
			bs = 8
		}
		key := fixLen(rndKey, 32)
		iv := fixLen(rndIV, ivLen)

		// CTRA-02: normalize section to a block multiple so nearly every input
		// reaches the clean-room. sectionRaw in [1,4096] → round down to nearest
		// bs multiple; treat 0 as plain-CTR (no ACPKM).
		var section int
		if sectionRaw == 0 {
			section = 0
		} else {
			// k = number of bs-size blocks that fit in sectionRaw, minimum 1.
			k := int(sectionRaw%4097) / bs
			if k == 0 {
				k = 1
			}
			section = k * bs
		}

		// Cap absurd plaintext lengths so the fuzzer stays fast.
		if len(plain) > 16384 {
			plain = plain[:16384]
		}

		oracle, err := ref.NewCTRACPKM(newBlock, key, iv, section)
		if err != nil {
			t.Fatalf("oracle NewCTRACPKM(section=%d): %v (should not fail after normalization)", section, err)
		}
		mine := ctracpkm.NewCTRACPKM(newBlock, key, iv, section)

		n := len(plain)
		refOut := make([]byte, n)
		myOut := make([]byte, n)

		if !inPlace {
			// --- out-of-place chunked streaming ---
			xorKeyStreamChunked(oracle, refOut, plain, chunkSeed)
			xorKeyStreamChunked(mine, myOut, plain, chunkSeed)
		} else {
			// --- in-place dst==src (CTRA-06) ---
			copy(refOut, plain)
			oracle.XORKeyStream(refOut, refOut)
			copy(myOut, plain)
			mine.XORKeyStream(myOut, myOut)
		}

		if !bytes.Equal(refOut, myOut) {
			t.Fatalf("sel=%d section=%d len=%d inPlace=%v chunkSeed=%d divergence:\n ref %x\n new %x",
				sel, section, n, inPlace, chunkSeed, refOut, myOut)
		}
	})
}

// TestDiff_PlainCTR_vs_Oracle checks NewCTR (plain CTR) against the oracle.
// CTRA-05: covers both Kuznyechik (16-byte block) and Magma (8-byte block).
func TestDiff_PlainCTR_vs_Oracle(t *testing.T) {
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	cases := []struct {
		name string
		blk  func() cipher.Block
		iv   []byte
	}{
		{
			name: "kuznyechik",
			blk:  func() cipher.Block { return kuznyechik.NewCipher(key) },
			iv:   mustHex(t, "1234567890abcef00000000000000000"),
		},
		{
			name: "magma",
			blk:  func() cipher.Block { return magma.NewCipher(key) },
			iv:   mustHex(t, "1234567800000000"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, n := range []int{1, 8, 9, 16, 33, 200, 4097} {
				plain := make([]byte, n)
				for i := range plain {
					plain[i] = byte(i)
				}

				oracle, err := ref.NewCTR(c.blk(), c.iv)
				if err != nil {
					t.Fatalf("oracle NewCTR: %v", err)
				}
				refOut := make([]byte, n)
				oracle.XORKeyStream(refOut, plain)

				myOut := make([]byte, n)
				ctracpkm.NewCTR(c.blk(), c.iv).XORKeyStream(myOut, plain)

				if !bytes.Equal(refOut, myOut) {
					t.Fatalf("%s plain CTR len=%d divergence:\n ref %x\n new %x", c.name, n, refOut, myOut)
				}

				// in-place variant
				refInPlace := make([]byte, n)
				copy(refInPlace, plain)
				refOrIP, err := ref.NewCTR(c.blk(), c.iv)
				if err != nil {
					t.Fatalf("oracle NewCTR in-place: %v", err)
				}
				refOrIP.XORKeyStream(refInPlace, refInPlace)

				myInPlace := make([]byte, n)
				copy(myInPlace, plain)
				ctracpkm.NewCTR(c.blk(), c.iv).XORKeyStream(myInPlace, myInPlace)

				if !bytes.Equal(refInPlace, myInPlace) {
					t.Fatalf("%s plain CTR in-place len=%d divergence:\n ref %x\n new %x", c.name, n, refInPlace, myInPlace)
				}
				if !bytes.Equal(refOut, refInPlace) {
					t.Fatalf("%s plain CTR oracle in-place != out-of-place len=%d", c.name, n)
				}
			}
		})
	}
}
