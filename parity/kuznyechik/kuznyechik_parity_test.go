package kuznyechikparity

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"

	mynew "github.com/tarantool/go-gostcrypto/kuznyechik"
)

// TestDiffAgainstGost runs the clean-room cipher against the
// gostcryptocompat.Kuznyechik{Encrypt,Decrypt} black-box oracle over random
// keys and blocks, requiring byte-exact agreement plus round-trip identity.
func TestDiffAgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0x6b757a))
	for iter := range 4096 {
		key := make([]byte, 32)
		blk := make([]byte, 16)
		rng.Read(key)
		rng.Read(blk)

		c := mynew.NewCipher(key)

		mineCT := make([]byte, 16)
		c.Encrypt(mineCT, blk)

		refCT, err := gost.KuznyechikEncrypt(key, blk)
		if err != nil {
			t.Fatalf("KuznyechikEncrypt iter=%d: %v", iter, err)
		}

		if !bytes.Equal(mineCT, refCT) {
			t.Fatalf("Encrypt mismatch iter=%d\n key=%x blk=%x\n mine=%x ref=%x",
				iter, key, blk, mineCT, refCT)
		}

		minePT := make([]byte, 16)
		c.Decrypt(minePT, refCT)
		if !bytes.Equal(minePT, blk) {
			t.Fatalf("round-trip Decrypt(Encrypt) != p iter=%d\n key=%x p=%x got=%x",
				iter, key, blk, minePT)
		}

		refPT, err := gost.KuznyechikDecrypt(key, mineCT)
		if err != nil {
			t.Fatalf("KuznyechikDecrypt iter=%d: %v", iter, err)
		}

		if !bytes.Equal(refPT, blk) {
			t.Fatalf("gost.KuznyechikDecrypt mismatch iter=%d\n key=%x ct=%x got=%x want=%x",
				iter, key, mineCT, refPT, blk)
		}
	}
}

// TestDiffKAT confirms the clean-room and the oracle agree on the pinned
// RFC 7801 §A.1 vector (GOST R 34.12-2015 §A.1 / RFC 7801 §5.5–5.6).
// It both anchors the literal expected ciphertext and diffs Decrypt on that
// pinned ciphertext so the function is self-contained as a spec anchor.
func TestDiffKAT(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")
	// wantCT: RFC 7801 §5.5 / GOST R 34.12-2015 §A.1 Kuznyechik ECB test vector.
	// Verified against gostcrypto/kuznyechik/kuznyechik_test.go:27 and
	// cipher_modes_test.go:86.
	wantCT, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd")

	c := mynew.NewCipher(key)
	mineCT := make([]byte, 16)
	c.Encrypt(mineCT, pt)

	// Anchor: clean-room output must match the RFC-specified literal ciphertext.
	if !bytes.Equal(mineCT, wantCT) {
		t.Fatalf("KAT Encrypt spec mismatch: got %x want %x", mineCT, wantCT)
	}

	refCT, err := gost.KuznyechikEncrypt(key, pt)
	if err != nil {
		t.Fatalf("KuznyechikEncrypt KAT: %v", err)
	}

	if !bytes.Equal(mineCT, refCT) {
		t.Fatalf("KAT Encrypt differential mismatch: mine=%x ref=%x", mineCT, refCT)
	}

	// Decrypt the pinned ciphertext — both sides must recover the original plaintext.
	minePT := make([]byte, 16)
	c.Decrypt(minePT, wantCT)
	if !bytes.Equal(minePT, pt) {
		t.Fatalf("KAT Decrypt clean-room mismatch: got %x want %x", minePT, pt)
	}

	refPT, err := gost.KuznyechikDecrypt(key, wantCT)
	if err != nil {
		t.Fatalf("KuznyechikDecrypt KAT: %v", err)
	}
	if !bytes.Equal(refPT, pt) {
		t.Fatalf("KAT Decrypt oracle mismatch: got %x want %x", refPT, pt)
	}
}

// FuzzDiffKuznyechik mirrors TestDiffAgainstGost: it pads the fuzzer's raw
// bytes to a valid 32-byte key and 16-byte block, then asserts byte-exact
// agreement between the clean-room cipher and the gost oracle on both Encrypt
// and Decrypt, plus clean-room round-trip identity.
func FuzzDiffKuznyechik(f *testing.F) {
	f.Add(
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa9988"))
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		seedHex("00000000000000000000000000000000"))

	f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte) {
		key := fixLen(rndKey, 32)
		blk := fixLen(rndBlk, 16)

		c := mynew.NewCipher(key)

		mineCT := make([]byte, 16)
		c.Encrypt(mineCT, blk)

		refCT, err := gost.KuznyechikEncrypt(key, blk)
		if err != nil {
			t.Fatalf("KuznyechikEncrypt: %v", err)
		}

		if !bytes.Equal(mineCT, refCT) {
			t.Fatalf("Encrypt mismatch\n key=%x blk=%x\n mine=%x ref=%x", key, blk, mineCT, refCT)
		}

		// In-place Encrypt (dst == src) must produce identical output as distinct-buffer.
		inBuf := make([]byte, 16)
		copy(inBuf, blk)
		c.Encrypt(inBuf, inBuf) // dst == src
		if !bytes.Equal(inBuf, mineCT) {
			t.Fatalf("Encrypt in-place mismatch\n key=%x blk=%x\n inplace=%x dist=%x",
				key, blk, inBuf, mineCT)
		}

		// Decrypt diff on an arbitrary block (fuzzer-supplied ciphertext).
		minePT := make([]byte, 16)
		c.Decrypt(minePT, blk)

		refPT, err := gost.KuznyechikDecrypt(key, blk)
		if err != nil {
			t.Fatalf("KuznyechikDecrypt: %v", err)
		}

		if !bytes.Equal(minePT, refPT) {
			t.Fatalf("Decrypt mismatch\n key=%x blk=%x\n mine=%x ref=%x", key, blk, minePT, refPT)
		}

		// In-place Decrypt (dst == src) must produce identical output as distinct-buffer.
		inBuf2 := make([]byte, 16)
		copy(inBuf2, blk)
		c.Decrypt(inBuf2, inBuf2) // dst == src
		if !bytes.Equal(inBuf2, minePT) {
			t.Fatalf("Decrypt in-place mismatch\n key=%x blk=%x\n inplace=%x dist=%x",
				key, blk, inBuf2, minePT)
		}

		// Round-trip on the clean-room side.
		back := make([]byte, 16)
		c.Decrypt(back, mineCT)
		if !bytes.Equal(back, blk) {
			t.Fatalf("round-trip Decrypt(Encrypt) != p\n key=%x p=%x got=%x", key, blk, back)
		}
	})
}

func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
