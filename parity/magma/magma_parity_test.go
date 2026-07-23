package magmaparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/tarantool/go-gostcrypto/magma"
	"math/rand"
	"testing"

	gostref "github.com/tarantool/go-gostcrypto-compat"
	gost341264ref "go.stargrave.org/gogost/v7/gost341264"
)

// MAG-02 (informational): invalid-length rejection is intentionally not parity-
// tested here. The clean-room panics on bad key/block size; the facade oracle
// returns an error; gogost also panics. These interfaces are not byte-for-byte
// comparable; the clean-room panic paths are covered by gostcrypto/magma/guard_test.go.

// TestMagmaDifferential cross-checks the clean-room impl against the repo's
// gostcryptocompat.MagmaEncrypt/MagmaDecrypt black-box oracle over random blocks.
func TestMagmaDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	key := make([]byte, KeySize)
	pt := make([]byte, BlockSize)

	for i := range 50000 {
		rng.Read(key)
		rng.Read(pt)

		ours := MagmaEncrypt(key, pt)

		theirs, err := gostref.MagmaEncrypt(key, pt)
		if err != nil {
			t.Fatalf("gostref.MagmaEncrypt i=%d: %v", i, err)
		}

		if !bytes.Equal(ours, theirs) {
			t.Fatalf("encrypt mismatch: key=%x pt=%x ours=%x ref=%x", key, pt, ours, theirs)
		}

		oursD := MagmaDecrypt(key, ours)

		theirsD, err := gostref.MagmaDecrypt(key, theirs)
		if err != nil {
			t.Fatalf("gostref.MagmaDecrypt i=%d: %v", i, err)
		}

		if !bytes.Equal(oursD, theirsD) {
			t.Fatalf("decrypt mismatch: key=%x ct=%x ours=%x ref=%x", key, ours, oursD, theirsD)
		}

		if !bytes.Equal(oursD, pt) {
			t.Fatalf("round-trip failed: key=%x pt=%x back=%x", key, pt, oursD)
		}
	}
}

// FuzzMagmaDifferential mirrors TestMagmaDifferential: it pads the fuzzer's raw
// bytes to a valid KeySize key and BlockSize block, then asserts byte-exact
// agreement between the clean-room impl and the gost oracle on both Encrypt and
// Decrypt, plus clean-room round-trip identity.
func FuzzMagmaDifferential(f *testing.F) {
	f.Add(
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("fedcba9876543210"))
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		seedHex("0000000000000000"))

	f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte) {
		key := fixLen(rndKey, KeySize)
		pt := fixLen(rndBlk, BlockSize)

		ours := MagmaEncrypt(key, pt)

		theirs, err := gostref.MagmaEncrypt(key, pt)
		if err != nil {
			t.Fatalf("gostref.MagmaEncrypt: %v", err)
		}

		if !bytes.Equal(ours, theirs) {
			t.Fatalf("encrypt mismatch: key=%x pt=%x ours=%x ref=%x", key, pt, ours, theirs)
		}

		// Decrypt diff on an arbitrary block (fuzzer-supplied ciphertext).
		oursD := MagmaDecrypt(key, pt)

		theirsD, err := gostref.MagmaDecrypt(key, pt)
		if err != nil {
			t.Fatalf("gostref.MagmaDecrypt: %v", err)
		}

		if !bytes.Equal(oursD, theirsD) {
			t.Fatalf("decrypt mismatch: key=%x ct=%x ours=%x ref=%x", key, pt, oursD, theirsD)
		}

		// Round-trip on the clean-room side.
		back := MagmaDecrypt(key, ours)
		if !bytes.Equal(back, pt) {
			t.Fatalf("round-trip failed: key=%x pt=%x back=%x", key, pt, back)
		}
	})
}

// TestMagmaCipherReuse exercises the Cipher object API: a single Cipher instance
// is reused across multiple sequential block encryptions. Both the clean-room and
// the gogost oracle must produce the same ciphertext for every block.
// MAG-01: instance-reuse path.
func TestMagmaCipherReuse(t *testing.T) {
	key := mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	blocks := [][]byte{
		mustHex("fedcba9876543210"),
		mustHex("0102030405060708"),
		mustHex("aabbccddeeff0011"),
	}

	ourC := NewCipher(key)
	theirC := gost341264ref.NewCipher(key)

	for i, pt := range blocks {
		ourDst := make([]byte, BlockSize)
		ourC.Encrypt(ourDst, pt)

		theirDst := make([]byte, BlockSize)
		theirC.Encrypt(theirDst, pt)

		if !bytes.Equal(ourDst, theirDst) {
			t.Fatalf("block %d encrypt mismatch: ours=%x ref=%x", i, ourDst, theirDst)
		}
	}
}

// TestMagmaDecryptCipherReuse exercises Cipher instance reuse across multiple
// sequential block decryptions. MAG-01: instance-reuse path for Decrypt.
func TestMagmaDecryptCipherReuse(t *testing.T) {
	key := mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	// Use ciphertext blocks (output of encryption for the same key above).
	blocks := [][]byte{
		mustHex("4ee901e5c2d8ca3d"),
		mustHex("4b12a4f8bacd5f2d"),
		mustHex("5ad705ebcd2e8e84"),
	}

	ourC := NewCipher(key)
	theirC := gost341264ref.NewCipher(key)

	for i, ct := range blocks {
		ourDst := make([]byte, BlockSize)
		ourC.Decrypt(ourDst, ct)

		theirDst := make([]byte, BlockSize)
		theirC.Decrypt(theirDst, ct)

		if !bytes.Equal(ourDst, theirDst) {
			t.Fatalf("block %d decrypt mismatch: ours=%x ref=%x", i, ourDst, theirDst)
		}
	}
}

// TestMagmaEncryptInPlace exercises dst==src aliasing: encrypting in-place must
// yield the same result as encrypting into a fresh destination buffer.
// MAG-01: dst==src aliasing path.
func TestMagmaEncryptInPlace(t *testing.T) {
	key := mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := mustHex("fedcba9876543210")

	// Clean-room: in-place (dst==src).
	ourBuf := make([]byte, BlockSize)
	copy(ourBuf, pt)
	NewCipher(key).Encrypt(ourBuf, ourBuf)

	// Clean-room: fresh dst, for comparison.
	expected := MagmaEncrypt(key, pt)
	if !bytes.Equal(ourBuf, expected) {
		t.Fatalf("clean-room in-place encrypt mismatch: got=%x want=%x", ourBuf, expected)
	}

	// gogost oracle: in-place.
	theirBuf := make([]byte, BlockSize)
	copy(theirBuf, pt)
	gost341264ref.NewCipher(key).Encrypt(theirBuf, theirBuf)

	if !bytes.Equal(ourBuf, theirBuf) {
		t.Fatalf("in-place encrypt parity mismatch: ours=%x ref=%x", ourBuf, theirBuf)
	}
}

// TestMagmaDecryptInPlace exercises dst==src aliasing for Decrypt.
// MAG-01: dst==src aliasing path for Decrypt.
func TestMagmaDecryptInPlace(t *testing.T) {
	key := mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	// Ciphertext: the result of encrypting "fedcba9876543210" with the key above.
	ct := MagmaEncrypt(key, mustHex("fedcba9876543210"))

	// Clean-room: in-place (dst==src).
	ourBuf := make([]byte, BlockSize)
	copy(ourBuf, ct)
	NewCipher(key).Decrypt(ourBuf, ourBuf)

	// Clean-room: fresh dst, for comparison.
	expected := MagmaDecrypt(key, ct)
	if !bytes.Equal(ourBuf, expected) {
		t.Fatalf("clean-room in-place decrypt mismatch: got=%x want=%x", ourBuf, expected)
	}

	// gogost oracle: in-place.
	theirBuf := make([]byte, BlockSize)
	copy(theirBuf, ct)
	gost341264ref.NewCipher(key).Decrypt(theirBuf, theirBuf)

	if !bytes.Equal(ourBuf, theirBuf) {
		t.Fatalf("in-place decrypt parity mismatch: ours=%x ref=%x", ourBuf, theirBuf)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
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
