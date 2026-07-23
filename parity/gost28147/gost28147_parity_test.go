package gost28147parity

import (
	"bytes"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
	. "github.com/tarantool/go-gostcrypto/gost28147"
	gogost28147 "go.stargrave.org/gogost/v7/gost28147"
)

// TestDiff_InternalGostOracle treats gostcryptocompat as a black-box oracle
// (signatures taken from the guide, not the implementation source) and diffs
// its CryptoPro-A ECB output against the clean-room impl over the pinned
// vector and a spread of deterministic key/block pairs.
func TestDiff_InternalGostOracle(t *testing.T) {
	keys := [][]byte{
		mustHex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
	}
	for seed := range 64 {
		var k [KeySize]byte
		x := uint64(seed)*0x9E3779B97F4A7C15 + 0xABCDEF
		for i := range k {
			k[i] = byte(x>>(8*(i%8))) ^ byte(i*31)
		}
		keys = append(keys, k[:])
	}

	for ki, key := range keys {
		c := NewCipher(key, SboxCryptoProA)
		for seed := range 64 {
			var p [BlockSize]byte
			x := uint64(seed)*0x100000001B3 + uint64(ki)*0x9E3779B1
			for i := range BlockSize {
				p[i] = byte(x >> (8 * i))
			}
			want, err := gost.GOST2814789Encrypt(key, p[:])
			if err != nil {
				t.Fatalf("GOST2814789Encrypt key#%d: %v", ki, err)
			}

			got := make([]byte, BlockSize)
			c.Encrypt(got, p[:])
			if !bytes.Equal(got, want) {
				t.Fatalf("key#%d in=%x: clean-room %x != oracle %x", ki, p, got, want)
			}

			// Decrypt diff: call clean-room Decrypt and oracle Decrypt on the same
			// ciphertext (want = oracle Encrypt output), then compare both results.
			// This replaces the previous oracle-only self-round-trip which never
			// exercised c.Decrypt (Findings: G89-01).
			minePT := make([]byte, BlockSize)
			c.Decrypt(minePT, want)

			refPT, err := gost.GOST2814789Decrypt(key, want)
			if err != nil {
				t.Fatalf("GOST2814789Decrypt key#%d: %v", ki, err)
			}
			if !bytes.Equal(minePT, refPT) {
				t.Fatalf("Decrypt mismatch key#%d ct=%x: clean-room %x != oracle %x", ki, want, minePT, refPT)
			}
			// Sanity: clean-room round-trip must recover p.
			if !bytes.Equal(minePT, p[:]) {
				t.Fatalf("round-trip Decrypt(Encrypt(p)) != p key#%d", ki)
			}
		}
	}
}

// TestDiff_TC26Z_ECB diffs the clean-room SboxTC26Z ECB cipher against gogost
// (go.stargrave.org/gogost/v7/gost28147 with SboxIdtc26gost28147paramZ) for
// both Encrypt and Decrypt over a deterministic key/block grid.
//
// The facade oracle (gostcryptocompat) hardcodes SboxDefault (CryptoPro-A)
// internally, so this test drives gogost directly — the same technique used by
// parity/gost28147cnt (line 169 of its parity test).
//
// Findings: G89-02.
func TestDiff_TC26Z_ECB(t *testing.T) {
	keys := [][]byte{
		// All-zeros key (first trivial KAT input).
		mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		// Pinned KAT key from TestDiff_InternalGostOracle.
		mustHex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
	}
	for seed := range 64 {
		var k [KeySize]byte
		x := uint64(seed)*0x6C62272E07BB0142 + 0xFEDCBA98
		for i := range k {
			k[i] = byte(x>>(8*(i%8))) ^ byte(i*37)
		}
		keys = append(keys, k[:])
	}

	for ki, key := range keys {
		// Clean-room TC26-Z cipher.
		mine := NewCipher(key, SboxTC26Z)
		// gogost reference TC26-Z cipher (imported directly, not via facade).
		ref := gogost28147.NewCipher(key, &gogost28147.SboxIdtc26gost28147paramZ)

		for seed := range 64 {
			var p [BlockSize]byte
			x := uint64(seed)*0x100000001B3 + uint64(ki)*0xDEADBEEF
			for i := range BlockSize {
				p[i] = byte(x >> (8 * i))
			}

			// Encrypt diff.
			gotMine := make([]byte, BlockSize)
			gotRef := make([]byte, BlockSize)
			mine.Encrypt(gotMine, p[:])
			ref.Encrypt(gotRef, p[:])
			if !bytes.Equal(gotMine, gotRef) {
				t.Fatalf("TC26Z Encrypt mismatch key#%d in=%x: clean-room %x != gogost %x",
					ki, p, gotMine, gotRef)
			}

			// Decrypt diff on the freshly encrypted ciphertext.
			decMine := make([]byte, BlockSize)
			decRef := make([]byte, BlockSize)
			mine.Decrypt(decMine, gotMine)
			ref.Decrypt(decRef, gotRef)
			if !bytes.Equal(decMine, decRef) {
				t.Fatalf("TC26Z Decrypt mismatch key#%d ct=%x: clean-room %x != gogost %x",
					ki, gotMine, decMine, decRef)
			}
			// Sanity: round-trip must recover p on both sides.
			if !bytes.Equal(decMine, p[:]) {
				t.Fatalf("TC26Z round-trip key#%d: clean-room Decrypt(Encrypt(p)) != p", ki)
			}
			if !bytes.Equal(decRef, p[:]) {
				t.Fatalf("TC26Z round-trip key#%d: gogost Decrypt(Encrypt(p)) != p", ki)
			}
		}
	}
}

// FuzzDiffGost28147 mirrors TestDiff_InternalGostOracle: it pads the fuzzer's
// raw bytes to a valid KeySize key and BlockSize block, then asserts byte-exact
// agreement between the clean-room ECB cipher and the reference oracle on both
// Encrypt and Decrypt, plus clean-room round-trip identity.
//
// The sboxSel parameter (even=CryptoPro-A, odd=TC26-Z) exercises both exported
// S-box parameter sets (Findings: G89-03, G89-04).
func FuzzDiffGost28147(f *testing.F) {
	// Seed#0: CryptoPro-A (sboxSel even), pinned KAT key.
	f.Add(
		seedHex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
		seedHex("0011223344556677"),
		uint8(0))
	// Seed#1: CryptoPro-A, all-zeros key/block.
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		seedHex("0000000000000000"),
		uint8(0))
	// Seed#2: TC26-Z (sboxSel odd), pinned KAT key (G89-03: second S-box).
	f.Add(
		seedHex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
		seedHex("0011223344556677"),
		uint8(1))
	// Seed#3: TC26-Z, all-zeros key/block (G89-03: both S-boxes seeded).
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		seedHex("0000000000000000"),
		uint8(1))

	f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte, sboxSel uint8) {
		key := fixLen(rndKey, KeySize)
		p := fixLen(rndBlk, BlockSize)

		var (
			c         *Cipher
			oracleEnc func([]byte) []byte
			oracleDec func([]byte) []byte
		)
		if sboxSel%2 == 0 {
			// CryptoPro-A: use the facade oracle.
			c = NewCipher(key, SboxCryptoProA)
			oracleEnc = func(blk []byte) []byte {
				v, err := gost.GOST2814789Encrypt(key, blk)
				if err != nil {
					t.Fatalf("GOST2814789Encrypt: %v", err)
				}
				return v
			}
			oracleDec = func(blk []byte) []byte {
				v, err := gost.GOST2814789Decrypt(key, blk)
				if err != nil {
					t.Fatalf("GOST2814789Decrypt: %v", err)
				}
				return v
			}
		} else {
			// TC26-Z: drive gogost directly (facade hardcodes CryptoPro-A).
			c = NewCipher(key, SboxTC26Z)
			ref := gogost28147.NewCipher(key, &gogost28147.SboxIdtc26gost28147paramZ)
			oracleEnc = func(blk []byte) []byte {
				dst := make([]byte, BlockSize)
				ref.Encrypt(dst, blk)
				return dst
			}
			oracleDec = func(blk []byte) []byte {
				dst := make([]byte, BlockSize)
				ref.Decrypt(dst, blk)
				return dst
			}
		}

		got := make([]byte, BlockSize)
		c.Encrypt(got, p)
		want := oracleEnc(p)
		if !bytes.Equal(got, want) {
			t.Fatalf("Encrypt mismatch (sbox=%d): key=%x in=%x clean-room %x != oracle %x",
				sboxSel%2, key, p, got, want)
		}

		// Decrypt diff on an arbitrary block (fuzzer-supplied ciphertext).
		minePT := make([]byte, BlockSize)
		c.Decrypt(minePT, p)
		refPT := oracleDec(p)
		if !bytes.Equal(minePT, refPT) {
			t.Fatalf("Decrypt mismatch (sbox=%d): key=%x in=%x clean-room %x != oracle %x",
				sboxSel%2, key, p, minePT, refPT)
		}

		// Round-trip on the clean-room side.
		back := make([]byte, BlockSize)
		c.Decrypt(back, got)
		if !bytes.Equal(back, p) {
			t.Fatalf("round-trip Decrypt(Encrypt) != p (sbox=%d): key=%x p=%x got=%x",
				sboxSel%2, key, p, back)
		}
	})
}
