package gost28147imitparity

// Oracle-independence note (G89I-03): only the per-block 16-round MAC transform
// comes from gogost (mac.Write → xcrypt(SeqMAC)); the key-meshing schedule,
// count bookkeeping, and short-message finalization are reimplemented in the
// gostcryptocompat facade (primitives_gost.go:455-533) by the same project author,
// structurally isomorphic to the clean-room imit.go. A shared misreading of the
// engine semantics would pass parity. This is mitigated by the independent
// gost-engine KATs in the root package:
//   - TestGost_GOST28147_IMIT_Wrapper_KeyMeshing (primitives_engine_vectors_test.go:360)
//     pins the wrapper to gost-engine vector 5efab81f (266240-byte testbig.dat,
//     src: tmp/engine/test/02-mac.t:185).
//   - TestGost_GOST28147_IMIT_Wrapper_NoMeshing (primitives_engine_vectors_test.go:383)
//     pins the 1024-byte boundary to gost-engine vector 2ee8d13d
//     (src: tmp/engine/test/02-mac.t:162).
// Those same vectors are also pinned below as TestEngineVectors_IMIT, so this
// parity package carries its own independent anchor.

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"math/rand"

	"github.com/tarantool/go-gostcrypto/gost28147"
	. "github.com/tarantool/go-gostcrypto/gost28147imit"

	refgost "github.com/tarantool/go-gostcrypto-compat"
)

// seedHex decodes a hex string for f.Add seeds (which take no *testing.T).
func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestEngineVectors_IMIT pins the clean-room IMIT against independent
// gost-engine v3.0.3 vectors (test/02-mac.t), so this parity package carries
// its own anchor independent of the root-package oracle. These are the same
// vectors used in the root-package TestGost_GOST28147_IMIT_Wrapper_* tests.
func TestEngineVectors_IMIT(t *testing.T) {
	// key = "0123456789abcdef" x 2 (32 bytes raw ASCII)
	// src: tmp/engine/test/02-mac.t:51
	key := []byte("0123456789abcdef0123456789abcdef")

	t.Run("no-meshing-1024bytes", func(t *testing.T) {
		// testdata.dat = "12345670" x 128 (1024 bytes); meshing fires at >1024
		// so this vector sits exactly on the boundary without triggering it.
		// src: tmp/engine/test/02-mac.t:162 (gost-mac default 4-byte output)
		msg := []byte(strings.Repeat("12345670", 128))
		want, _ := hex.DecodeString("2ee8d13d")

		got := IMIT(key, msg)
		if !bytes.Equal(got, want) {
			t.Fatalf("no-meshing IMIT mismatch:\ngot  %x\nwant %x\n(src: test/02-mac.t:162)",
				got, want)
		}
	})

	t.Run("key-meshing-266240bytes", func(t *testing.T) {
		// testbig.dat = ("12345670" x 8 + "\n") x 4096 (266240 bytes);
		// crosses 260 CryptoPro meshing boundaries (every 1024 bytes).
		// src: tmp/engine/test/02-mac.t:185 (gost-mac default 4-byte output)
		msg := []byte(strings.Repeat(strings.Repeat("12345670", 8)+"\n", 4096))
		want, _ := hex.DecodeString("5efab81f")

		got := IMIT(key, msg)
		if !bytes.Equal(got, want) {
			t.Fatalf("key-meshing IMIT mismatch:\ngot  %x\nwant %x\n(src: test/02-mac.t:185)",
				got, want)
		}
	})
}

// TestDiff_InternalGostOracle treats gostcryptocompat.GOST28147_IMIT as a
// black-box oracle (signature from the guide §"Conformance & fuzz testing":
// returns the 4-byte TLS-truncated tag with CryptoPro key meshing) and diffs
// it against the clean-room IMIT over random keys and messages. Lengths are
// chosen to exercise the short-message finalization (1..8 and 9..16) and the
// key-meshing path (> 1024 bytes).
func TestDiff_InternalGostOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234_5678))

	// Deterministic length set: every short length 1..16 (short-message
	// trailing-zero-block window plus the first whole-block boundary), plus a
	// spread that straddles the 1024-byte meshing boundary several times.
	var lengths []int
	for n := 1; n <= 16; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths,
		17, 31, 32, 100, 255, 256, 1016, 1017, 1023, 1024, 1025, 1031,
		1032, 2048, 2049, 3072, 4097, 8192, 12345,
	)

	for range 200 {
		key := make([]byte, keySize)
		rng.Read(key)

		for _, n := range lengths {
			msg := make([]byte, n)
			rng.Read(msg)

			got := IMIT(key, msg)
			ref, err := refgost.GOST28147_IMIT(key, msg)
			if err != nil {
				t.Fatalf("oracle GOST28147_IMIT(len=%d): %v", n, err)
			}
			if !bytes.Equal(got, ref) {
				t.Fatalf("mismatch key=%x len=%d: clean-room %x != oracle %x",
					key, n, got, ref)
			}
		}
	}
}

// TestDiff_SeqMACBlock diffs the clean-room SeqMACBlock against the
// gogost-backed facade GOST28147Cipher.SeqMACBlock for both the CryptoPro-A
// and tc26-Z S-boxes over random keys and blocks, asserting full 8-byte
// equality. This closes two gaps:
//
//	(a) tc26-Z 16-round path is differentially validated against gogost for the
//	    first time (IMIT hardcodes CryptoPro-A, so that path was never covered).
//	(b) The full 8-byte SeqMAC state is byte-compared across modules; IMIT
//	    truncates to 4 bytes, so the upper 4 bytes were never directly diffed.
//
// Oracle note: GOST28147Cipher.SeqMACBlock (exports_gost.go:97) allocates a
// fresh MAC per call (NewMAC → Write → Sum), so MAC.Sum destructiveness does
// not apply here.
func TestDiff_SeqMACBlock(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDEAD_BEEF))

	sboxCases := []struct {
		name       string
		cleanSBox  gost28147.SBox
		oracleSBox *refgost.Sbox
	}{
		{"CryptoPro-A", gost28147.SboxCryptoProA, refgost.SboxCryptoProA},
		{"tc26-Z", gost28147.SboxTC26Z, refgost.SboxTC26Z},
	}

	const iterations = 200
	for _, sc := range sboxCases {
		t.Run(sc.name, func(t *testing.T) {
			for i := range iterations {
				key := make([]byte, keySize)
				rng.Read(key)
				block := make([]byte, 8) // gost28147.BlockSize
				rng.Read(block)

				got := SeqMACBlock(key, sc.cleanSBox, block)
				ref := refgost.NewGOST28147Cipher(key, sc.oracleSBox).SeqMACBlock(block)

				if len(got) != 8 {
					t.Fatalf("%s: SeqMACBlock returned %d bytes, want 8", sc.name, len(got))
				}
				if !bytes.Equal(got, ref) {
					t.Fatalf("%s: SeqMACBlock mismatch iter=%d key=%x block=%x:\n  clean-room %x\n  oracle     %x",
						sc.name, i, key, block, got, ref)
				}
			}
		})
	}
}

// FuzzDiff_SeqMACBlock is the fuzzing companion to TestDiff_SeqMACBlock.
// It diffs the clean-room SeqMACBlock against the oracle for a fuzzer-chosen
// key, block, and S-box selector, asserting full 8-byte equality.
func FuzzDiff_SeqMACBlock(f *testing.F) {
	// Seed: CryptoPro-A (sboxSel even → 0)
	f.Add(
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700"),
		byte(0), // CryptoPro-A
	)
	// Seed: tc26-Z (sboxSel odd → 1)
	f.Add(
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a59"),
		byte(1), // tc26-Z
	)

	f.Fuzz(func(t *testing.T, rndKey, rndBlock []byte, sboxSel byte) {
		key := fixLen(rndKey, keySize)
		block := fixLen(rndBlock, 8)

		var cleanSBox gost28147.SBox
		var oracleSBox *refgost.Sbox
		if sboxSel%2 == 0 {
			cleanSBox = gost28147.SboxCryptoProA
			oracleSBox = refgost.SboxCryptoProA
		} else {
			cleanSBox = gost28147.SboxTC26Z
			oracleSBox = refgost.SboxTC26Z
		}

		got := SeqMACBlock(key, cleanSBox, block)
		ref := refgost.NewGOST28147Cipher(key, oracleSBox).SeqMACBlock(block)

		if !bytes.Equal(got, ref) {
			t.Fatalf("SeqMACBlock mismatch sbox=%d key=%x block=%x:\n  clean-room %x\n  oracle     %x",
				sboxSel%2, key, block, got, ref)
		}
	})
}

// FuzzDiff_InternalGostOracle is the fuzzing companion to
// TestDiff_InternalGostOracle: it diffs the clean-room IMIT against the
// gostcryptocompat.GOST28147_IMIT black-box oracle (4-byte TLS-truncated tag with
// CryptoPro key meshing) over a fuzzer-chosen key and arbitrary-length message.
// Both sides are one-shot (the oracle exposes no streaming surface), so there
// is no MAC.Sum partial-block destructiveness to guard against here.
func FuzzDiff_InternalGostOracle(f *testing.F) {
	f.Add(
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa9988"))
	f.Add(
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a59"))
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		[]byte{0x01})
	// G89I-04: seeds that cross the 1024-byte CryptoPro key-meshing boundary
	// so the fuzzer starts from the right length scale and mesh-boundary edge
	// cases are exercised under seed replay.
	f.Add(
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		bytes.Repeat([]byte{0x42}, 1025))
	f.Add(
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		bytes.Repeat([]byte{0x5a}, 2049))

	f.Fuzz(func(t *testing.T, rndKey, msg []byte) {
		if len(msg) == 0 {
			// IMIT is undefined on the empty message: the clean-room primitive
			// panics and the oracle errors. The Test func only uses lengths >= 1.
			t.Skip("empty message is undefined for GOST 28147-89 IMIT")
		}
		key := fixLen(rndKey, keySize)

		ref, err := refgost.GOST28147_IMIT(key, msg)
		if err != nil {
			// G89I-02: after fixLen the key is always 32 bytes and msg is
			// non-empty, so GOST28147_IMIT has no legitimate error path at
			// this point. Any oracle error is unexpected — treat it as fatal
			// rather than silently skipping the comparison.
			t.Fatalf("oracle GOST28147_IMIT(len=%d): %v", len(msg), err)
		}
		got := IMIT(key, msg)
		if !bytes.Equal(got, ref) {
			t.Fatalf("mismatch key=%x len=%d: clean-room %x != oracle %x",
				key, len(msg), got, ref)
		}
	})
}
