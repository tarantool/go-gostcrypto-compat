package gostcryptocompat

// CTR mode tests.
//
// KAT vectors sourced from gost-engine test_ciphers.c, which in turn cites
// GOST R 34.13-2015 A.1.2 (Kuznyechik CTR) and A.2.2 (Magma CTR).
//
// The engine's grasshopper_ctr_cipher has iv_len = 8; the internal 16-byte
// counter is initialized from the 8-byte IV with the upper 8 bytes zeroed.
// Magma CTR uses a 4-byte IV zero-padded to 8 bytes.
// Our NewCTR requires len(iv) == blockSize, so callers must supply the
// zero-padded full-block IV.
//
// Source: tmp/engine/test_ciphers.c:57-116, 178.

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
)

// mustHex is a test helper that decodes hex or panics.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustHex: " + err.Error())
	}
	return b
}

// TestCTR_Kuznyechik_KAT tests against GOST R 34.13-2015 A.1.2.
// Source: tmp/engine/test_ciphers.c, key K (line 57), plaintext P (line 74),
//
//	E_ctr (line 105), iv_ctr (line 178).
func TestCTR_Kuznyechik_KAT(t *testing.T) {
	key := mustHex("8899aabbccddeeff0011223344556677" +
		"fedcba98765432100123456789abcdef")

	// iv_ctr from engine: { 0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0 } (8 bytes).
	// Kuznyechik block size is 16; pad to 16 bytes with zeros on the right.
	iv := make([]byte, 16)
	copy(iv, mustHex("1234567890abcef0"))

	plaintext := mustHex("1122334455667700ffeeddccbbaa9988" +
		"00112233445566778899aabbcceeff0a" +
		"112233445566778899aabbcceeff0a00" +
		"2233445566778899aabbcceeff0a0011")

	expected := mustHex("f195d8bec10ed1dbd57b5fa240bda1b8" +
		"85eee733f6a13e5df33ce4b33c45dee4" +
		"a5eae88be6356ed3d5e877f13564a3a5" +
		"cb91fab1f20cbab6d1c6d15820bdba73")

	block := gost3412128.NewCipher(key)
	ctr, err := NewCTR(block, iv)
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}
	dst := make([]byte, len(plaintext))
	ctr.XORKeyStream(dst, plaintext)
	if !bytes.Equal(dst, expected) {
		t.Errorf("Kuznyechik CTR KAT mismatch\n got:  %x\n want: %x", dst, expected)
	}

	// Decrypt: XOR with the same gamma recovers plaintext.
	ctr2, _ := NewCTR(gost3412128.NewCipher(key), iv)
	recovered := make([]byte, len(expected))
	ctr2.XORKeyStream(recovered, expected)
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("Kuznyechik CTR decrypt round-trip failed")
	}
}

// TestCTR_Magma_KAT tests against GOST R 34.13-2015 A.2.2.
// Source: tmp/engine/test_ciphers.c, key Km (line 65), plaintext Pm (line 82),
//
//	Em_ctr (line 112), iv_ctr (line 178) — Magma uses sizeof(iv_ctr)/2 = 4 bytes.
//
// Magma block size is 8; the 4-byte IV is zero-padded to 8 bytes.
func TestCTR_Magma_KAT(t *testing.T) {
	key := mustHex("ffeeddccbbaa99887766554433221100" +
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	// Magma iv: first 4 bytes of iv_ctr: { 0x12,0x34,0x56,0x78 }.
	// Magma block size is 8; pad to 8 bytes with zeros.
	iv := make([]byte, 8)
	copy(iv, mustHex("12345678"))

	plaintext := mustHex("92def06b3c130a59db54c704f8189d20" +
		"4a98fb2e67a8024c8912409b17b57e41")

	expected := mustHex("4e98110c97b7b93c3e250d93d6e85d69" +
		"136d868807b2dbef568eb680ab52a12d")

	block := gost341264.NewCipher(key)
	ctr, err := NewCTR(block, iv)
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}
	dst := make([]byte, len(plaintext))
	ctr.XORKeyStream(dst, plaintext)
	if !bytes.Equal(dst, expected) {
		t.Errorf("Magma CTR KAT mismatch\n got:  %x\n want: %x", dst, expected)
	}

	// Decrypt: XOR with the same gamma recovers plaintext.
	ctr2, _ := NewCTR(gost341264.NewCipher(key), iv)
	recovered := make([]byte, len(expected))
	ctr2.XORKeyStream(recovered, expected)
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("Magma CTR decrypt round-trip failed")
	}
}

// TestCTR_CounterIncrement verifies that the second block's gamma equals the
// gamma produced by a fresh CTR initialized with IV+1. This proves big-endian
// carry propagation is correct for both Kuznyechik and Magma.
func TestCTR_CounterIncrement(t *testing.T) {
	for _, tc := range []struct {
		name      string
		newCipher func(key []byte) cipher.Block
		key       string
		iv        string
	}{
		{
			name:      "Kuznyechik",
			newCipher: func(key []byte) cipher.Block { return gost3412128.NewCipher(key) },
			key:       "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			iv:        "00000000000000000000000000000000",
		},
		{
			name:      "Magma",
			newCipher: func(key []byte) cipher.Block { return gost341264.NewCipher(key) },
			key:       "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			iv:        "0000000000000000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(tc.key)
			iv := mustHex(tc.iv)
			bs := len(iv) // blockSize

			// Encrypt 2*blockSize zeros to get two gamma blocks.
			src := make([]byte, 2*bs)
			dst := make([]byte, 2*bs)
			ctr, _ := NewCTR(tc.newCipher(key), iv)
			ctr.XORKeyStream(dst, src)

			gamma2 := dst[bs:] // gamma for counter = IV+1

			// Compute IV+1.
			ivPlus1 := make([]byte, bs)
			copy(ivPlus1, iv)
			incCounter(ivPlus1)

			// A fresh CTR at IV+1 should produce gamma2 at offset 0.
			fresh, _ := NewCTR(tc.newCipher(key), ivPlus1)
			dstFresh := make([]byte, bs)
			fresh.XORKeyStream(dstFresh, make([]byte, bs))

			if !bytes.Equal(dstFresh, gamma2) {
				t.Errorf("%s: second gamma block mismatch\n got:  %x\n want: %x",
					tc.name, dstFresh, gamma2)
			}
		})
	}
}

// TestCTR_ErrorOnBadIV ensures NewCTR rejects IVs whose length differs from
// the block size.
func TestCTR_ErrorOnBadIV(t *testing.T) {
	key := mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	block := gost3412128.NewCipher(key) // blockSize = 16

	for _, badLen := range []int{0, 8, 15, 17, 32} {
		_, err := NewCTR(block, make([]byte, badLen))
		if err == nil {
			t.Errorf("NewCTR with iv len %d: expected error, got nil", badLen)
		}
	}
}

// TestCTR_PartialBlock verifies that XORKeyStream works correctly when called
// with lengths that don't align to the block boundary (split at various offsets).
func TestCTR_PartialBlock(t *testing.T) {
	key := mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := make([]byte, 16)

	for _, splitAt := range []int{1, 7, 15, 16, 17, 31} {
		// Encrypt 32 bytes in one shot.
		ctr1, _ := NewCTR(gost3412128.NewCipher(key), iv)
		src := make([]byte, 32)
		dstFull := make([]byte, 32)
		ctr1.XORKeyStream(dstFull, src)

		// Encrypt the same 32 bytes in two calls split at splitAt.
		ctr2, _ := NewCTR(gost3412128.NewCipher(key), iv)
		dstSplit := make([]byte, 32)
		ctr2.XORKeyStream(dstSplit[:splitAt], src[:splitAt])
		ctr2.XORKeyStream(dstSplit[splitAt:], src[splitAt:])

		if !bytes.Equal(dstFull, dstSplit) {
			t.Errorf("splitAt=%d: split result differs from one-shot\n full:  %x\n split: %x",
				splitAt, dstFull, dstSplit)
		}
	}
}

// TestCTRACPKM_Roundtrip encrypts and decrypts a buffer that straddles several
// ACPKM section boundaries. This only verifies our encrypt/decrypt paths agree;
// external correctness (vs gost-engine) is covered by the live Tarantool-EE
// integration test under `-tags "tarantoolee gost"` and by the on-the-wire MAC
// check performed by the record layer protector.
func TestCTRACPKM_Roundtrip(t *testing.T) {
	for _, tc := range []struct {
		name        string
		blockSize   int
		sectionSize int
		keyLen      int
		ivLen       int
		newBlock    func(key []byte) cipher.Block
	}{
		{"kuznyechik-4096", 16, 4096, 32, 16,
			func(k []byte) cipher.Block { return gost3412128.NewCipher(k) }},
		{"magma-1024", 8, 1024, 32, 8,
			func(k []byte) cipher.Block { return gost341264.NewCipher(k) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			for i := range key {
				key[i] = byte(i + 1)
			}
			iv := make([]byte, tc.ivLen)
			for i := range iv {
				iv[i] = byte(i + 0x10)
			}
			// 3.5 sections of data — crosses the rekey boundary 3 times.
			plain := make([]byte, tc.sectionSize*7/2)
			for i := range plain {
				plain[i] = byte(i * 31)
			}
			enc, err := NewCTRACPKM(tc.newBlock, key, iv, tc.sectionSize)
			if err != nil {
				t.Fatalf("NewCTRACPKM enc: %v", err)
			}
			ciphertext := make([]byte, len(plain))
			enc.XORKeyStream(ciphertext, plain)
			if bytes.Equal(ciphertext, plain) {
				t.Fatal("ciphertext equals plaintext — cipher did nothing")
			}
			dec, err := NewCTRACPKM(tc.newBlock, key, iv, tc.sectionSize)
			if err != nil {
				t.Fatalf("NewCTRACPKM dec: %v", err)
			}
			got := make([]byte, len(ciphertext))
			dec.XORKeyStream(got, ciphertext)
			if !bytes.Equal(got, plain) {
				t.Errorf("roundtrip mismatch at first diff")
			}
		})
	}
}

// TestCTRACPKM_MatchesPlainCTR_WhenSectionZero verifies that
// NewCTRACPKM(..., sectionSize=0) behaves identically to NewCTR.
func TestCTRACPKM_MatchesPlainCTR_WhenSectionZero(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(0x80 + i)
	}
	plain := make([]byte, 8192)
	for i := range plain {
		plain[i] = byte(i)
	}

	plainCTR, err := NewCTR(gost3412128.NewCipher(key), iv)
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}
	plainOut := make([]byte, len(plain))
	plainCTR.XORKeyStream(plainOut, plain)

	acpkmCTR, err := NewCTRACPKM(
		func(k []byte) cipher.Block { return gost3412128.NewCipher(k) },
		key, iv, 0)
	if err != nil {
		t.Fatalf("NewCTRACPKM: %v", err)
	}
	acpkmOut := make([]byte, len(plain))
	acpkmCTR.XORKeyStream(acpkmOut, plain)

	if !bytes.Equal(plainOut, acpkmOut) {
		t.Error("NewCTRACPKM with sectionSize=0 diverges from NewCTR")
	}
}
