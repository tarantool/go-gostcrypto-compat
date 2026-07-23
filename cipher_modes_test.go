package gostcryptocompat

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
)

func mustHexMode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func ecbEncrypt(block cipher.Block, pt []byte) []byte {
	out := make([]byte, len(pt))
	bs := block.BlockSize()
	for i := 0; i < len(pt); i += bs {
		block.Encrypt(out[i:i+bs], pt[i:i+bs])
	}
	return out
}

func ecbDecrypt(block cipher.Block, ct []byte) []byte {
	out := make([]byte, len(ct))
	bs := block.BlockSize()
	for i := 0; i < len(ct); i += bs {
		block.Decrypt(out[i:i+bs], ct[i:i+bs])
	}
	return out
}

func xorKeyStreamByChunks(s cipher.Stream, src []byte, chunk int) []byte {
	out := make([]byte, len(src))
	for off := 0; off < len(src); off += chunk {
		end := min(off+chunk, len(src))
		s.XORKeyStream(out[off:end], src[off:end])
	}
	return out
}

// TestCipherModes_EngineVectors ports the exact KATs from tmp/engine/test_ciphers.c
// that are not already covered by the existing CTR/OMAC tests.
func TestCipherModes_EngineVectors(t *testing.T) {
	keyKuz := mustHexMode(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	keyMag := mustHexMode(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	plainKuz := mustHexMode(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011")
	plainMag := mustHexMode(t,
		"92def06b3c130a59db54c704f8189d20"+
			"4a98fb2e67a8024c8912409b17b57e41")
	plainACPKM := mustHexMode(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011"+
			"33445566778899aabbcceeff0a001122"+
			"445566778899aabbcceeff0a00112233"+
			"5566778899aabbcceeff0a0011223344")
	plainACPKMMaster := make([]byte, 144)

	ivCTRKuz := make([]byte, 16)
	copy(ivCTRKuz, mustHexMode(t, "1234567890abcef0"))
	iv128 := mustHexMode(t, "1234567890abcef0a1b2c3d4e5f00112")
	ivMagCBC := mustHexMode(t, "1234567890abcdef")
	ivACPKMMaster := make([]byte, 16)
	copy(ivACPKMMaster, bytes.Repeat([]byte{0xff}, 8))

	t.Run("Kuznyechik-ECB", func(t *testing.T) {
		block := gost3412128.NewCipher(keyKuz)
		want := mustHexMode(t,
			"7f679d90bebc24305a468d42b9d4edcd"+
				"b429912c6e0032f9285452d76718d08b"+
				"f0ca33549d247ceef3f5a5313bd4b157"+
				"d0b09ccde830b9eb3a02c4c5aa8ada98")
		got := ecbEncrypt(block, plainKuz)
		if !bytes.Equal(got, want) {
			t.Fatalf("ECB encrypt mismatch:\n got  %x\n want %x", got, want)
		}
		if dec := ecbDecrypt(block, got); !bytes.Equal(dec, plainKuz) {
			t.Fatalf("ECB decrypt mismatch:\n got  %x\n want %x", dec, plainKuz)
		}
	})

	t.Run("Kuznyechik-OFB", func(t *testing.T) {
		block := gost3412128.NewCipher(keyKuz)
		want := mustHexMode(t,
			"81800a59b1842b24ff1f795e897abd95"+
				"779146db2d93a94ed93cf68b32397f19"+
				"e93c9e57441d870545f24036a58ceea3"+
				"cf3f0061d56423545b960d864cc868da")
		got := xorKeyStreamByChunks(cipher.NewOFB(block, iv128), plainKuz, len(plainKuz))
		if !bytes.Equal(got, want) {
			t.Fatalf("OFB encrypt mismatch:\n got  %x\n want %x", got, want)
		}
		gotChunked := xorKeyStreamByChunks(cipher.NewOFB(gost3412128.NewCipher(keyKuz), iv128), plainKuz, 16)
		if !bytes.Equal(gotChunked, want) {
			t.Fatalf("OFB chunked mismatch:\n got  %x\n want %x", gotChunked, want)
		}
	})

	t.Run("Kuznyechik-CBC", func(t *testing.T) {
		block := gost3412128.NewCipher(keyKuz)
		want := mustHexMode(t,
			"689972d4a085fa4d90e52e3d6d7dcc27"+
				"abf170b2b226c3010ccfa136d659cdaa"+
				"ca719272ab1d438e15507d521ecd5522"+
				"e01108ff8d9d3a6d8ca2a533fa614e71")
		got := make([]byte, len(plainKuz))
		cipher.NewCBCEncrypter(block, iv128).CryptBlocks(got, plainKuz)
		if !bytes.Equal(got, want) {
			t.Fatalf("CBC encrypt mismatch:\n got  %x\n want %x", got, want)
		}
		dec := make([]byte, len(got))
		cipher.NewCBCDecrypter(gost3412128.NewCipher(keyKuz), iv128).CryptBlocks(dec, got)
		if !bytes.Equal(dec, plainKuz) {
			t.Fatalf("CBC decrypt mismatch:\n got  %x\n want %x", dec, plainKuz)
		}
	})

	t.Run("Kuznyechik-CFB", func(t *testing.T) {
		block := gost3412128.NewCipher(keyKuz)
		want := mustHexMode(t,
			"81800a59b1842b24ff1f795e897abd95"+
				"68c1b99c4df59cc7951e3739b5b3cdbf"+
				"073f4dd2d6deb3cfb026545f7af1d8e8"+
				"e1c852e9a8567162dbb5da7f66dea926")
		got := xorKeyStreamByChunks(cipher.NewCFBEncrypter(block, iv128), plainKuz, len(plainKuz))
		if !bytes.Equal(got, want) {
			t.Fatalf("CFB encrypt mismatch:\n got  %x\n want %x", got, want)
		}
		dec := xorKeyStreamByChunks(cipher.NewCFBDecrypter(gost3412128.NewCipher(keyKuz), iv128), got, 16)
		if !bytes.Equal(dec, plainKuz) {
			t.Fatalf("CFB decrypt mismatch:\n got  %x\n want %x", dec, plainKuz)
		}
	})

	t.Run("Kuznyechik-CTR-ACPKM-32", func(t *testing.T) {
		iv := make([]byte, 16)
		copy(iv, mustHexMode(t, "1234567890abcef0"))
		want := mustHexMode(t,
			"f195d8bec10ed1dbd57b5fa240bda1b8"+
				"85eee733f6a13e5df33ce4b33c45dee4"+
				"4bceeb8f646f4c55001706275e85e800"+
				"587c4df568d094393e4834afd0805046"+
				"cf30f57686aeece11cfc6c316b8a896e"+
				"dffd07ec813636460c4f3b743423163e"+
				"6409a9c282fac8d469d221e7fbd6de5d")
		ctr, err := NewCTRACPKM(func(k []byte) cipher.Block { return gost3412128.NewCipher(k) }, keyKuz, iv, 32)
		if err != nil {
			t.Fatalf("NewCTRACPKM: %v", err)
		}
		got := make([]byte, len(plainACPKM))
		ctr.XORKeyStream(got, plainACPKM)
		if !bytes.Equal(got, want) {
			t.Fatalf("CTR-ACPKM mismatch:\n got  %x\n want %x", got, want)
		}
	})

	t.Run("Kuznyechik-CTR-ACPKM-Master-96", func(t *testing.T) {
		want := mustHexMode(t,
			"0cabf1f2efbc4ac16048df1a24c605b2"+
				"c0d1673d7586a8ec0dd42c45a4f95bae"+
				"0f2e2617e47148680fc3e6178df2c137"+
				"c9dda89cffa491feadd9b3eab703bb31"+
				"bc7e927f0494729f51b49d3df9c94608"+
				"00fbbcf5edee610ea02f01093c7bc742"+
				"d7d6271501b177775263c2a3495a8318"+
				"a81c79a04f29660ea3fda874c630799e"+
				"142c577914fea90d3bc2502e833685d9")
		ctr, err := NewCTRACPKM(func(k []byte) cipher.Block { return gost3412128.NewCipher(k) }, keyKuz, ivACPKMMaster, 96)
		if err != nil {
			t.Fatalf("NewCTRACPKM: %v", err)
		}
		got := make([]byte, len(plainACPKMMaster))
		ctr.XORKeyStream(got, plainACPKMMaster)
		if !bytes.Equal(got, want) {
			t.Fatalf("CTR-ACPKM master mismatch:\n got  %x\n want %x", got, want)
		}
	})

	t.Run("Magma-CBC", func(t *testing.T) {
		block := gost341264.NewCipher(keyMag)
		want := mustHexMode(t,
			"96d1b05eea683919f396b78c1d47bb61"+
				"6183e2cca976a4babe9ce87d6fa73cf2")
		got := make([]byte, len(plainMag))
		cipher.NewCBCEncrypter(block, ivMagCBC).CryptBlocks(got, plainMag)
		if !bytes.Equal(got, want) {
			t.Fatalf("Magma CBC encrypt mismatch:\n got  %x\n want %x", got, want)
		}
		dec := make([]byte, len(got))
		cipher.NewCBCDecrypter(gost341264.NewCipher(keyMag), ivMagCBC).CryptBlocks(dec, got)
		if !bytes.Equal(dec, plainMag) {
			t.Fatalf("Magma CBC decrypt mismatch:\n got  %x\n want %x", dec, plainMag)
		}
	})
}
