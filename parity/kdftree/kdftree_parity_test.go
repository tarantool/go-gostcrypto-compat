// Package kdftreeparity diffs the clean-room KDFTree256 against the in-repo
// gostcryptocompat facade (gostref.KDFTree2012_256) and raw gogost KDF.Derive.
//
// Oracle independence note (rule 7):
//
// The vendored gogost v7 implements KDF_GOSTR3411_2012_256 only as a single-block
// function (gost34112012256.KDF.Derive hardcodes counter=0x01 and L=0x0100, so it
// only ever produces 32 bytes). It cannot
// serve as an oracle for the multi-block tree path. The primary multi-block oracle is
// gostcryptocompat.KDFTree2012_256 (kdftree_gost.go), which reimplements the same
// RFC 7836 §4.4 counter loop in this module, drawing only the Streebog-256 hash from
// gogost. Both sides were written from the same spec by the same project — this is a
// known, accepted consequence of the license boundary.
//
// The independence of multi-block parity therefore rests on:
//
//  1. RFC 7836 Appendix B example 10 (KDF-02 anchor): the 64-byte K1‖K2 vector is
//     pinned below from the RFC text (gostcrypto/kdftree/rfc/rfc7836.txt lines
//     1528-1555), and independently confirmed by gost-engine tmp/engine/
//     test_keyexpimp.c:78-97,164-165 (KAT-1 in the gostcrypto module tests).
//  2. RFC 7836 Appendix B example 9 (KDF-02 anchor): the 32-byte single-block
//     vector is pinned below from rfc7836.txt:1499-1526 and confirmed by raw gogost
//     KDF.Derive (which is the complete KDF_GOSTR3411_2012_256 at r=1, L=256).
//  3. The inline oracleHMAC helper (KDF-03 coverage): uses gost34112012256.New
//     directly to assemble per-iteration HMAC messages, independent of either
//     KDFTree256 or the facade loop — covers r=2..4, outLen>64, and truncation.
package kdftreeparity

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	. "github.com/tarantool/go-gostcrypto/kdftree"
	"testing"

	gostref "github.com/tarantool/go-gostcrypto-compat"
	"go.stargrave.org/gogost/v7/gost34112012256"
)

func mustHexG(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// oracleHMAC assembles one KDF tree iteration from scratch using gogost's
// Streebog-256 hash directly.  It is independent of both KDFTree256 and the
// facade loop, so it can serve as a per-block oracle for r>1 and outLen>64
// paths that the facade cannot cover (facade only supports r=1 and multiples
// of 32).  The message is:  counter || label || 0x00 || seed || lRepr.
func oracleHMAC(key, counter, label, seed, lRepr []byte) []byte {
	h := hmac.New(gost34112012256.New, key)
	h.Write(counter)
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(seed)
	h.Write(lRepr)
	return h.Sum(nil)
}

// Differential conformance against the in-repo oracle (gostcryptocompat), the
// pinned authoritative KAT-1 vector, and raw gogost KDF.Derive (32B only, D1).
func TestKDFTree256Conformance(t *testing.T) {
	key := mustHexG(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	cases := []struct {
		name      string
		label     []byte
		seed      []byte
		keyOutLen int
		want      string // "" => no pinned etalon, cross-check refs only
	}{
		{
			// RFC 7836 Appendix B example 10 (gostcrypto/kdftree/rfc/rfc7836.txt
			// lines 1528-1555): KDF_TREE_GOSTR3411_2012_256 with R=1, L=512 (64 bytes).
			// Independently confirmed by gost-engine tmp/engine/test_keyexpimp.c:78-97
			// (KAT-1 in gostcrypto/kdftree/kdftree_test.go:TestKDFTree256_KAT1_64B).
			// K1 = 22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b
			// K2 = 074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9
			name:      "KAT-1/64B",
			label:     mustHexG(t, "26BDB878"),
			seed:      mustHexG(t, "AF21434145656378"),
			keyOutLen: 64,
			want: "22B6837845C6BEF65EA71672B265831086D3C76AEBE6DAE91CAD51D83F79D16B" +
				"074C9330599D7F8D712FCA54392F4DDDE93751206B3584C8F43F9E6DC51531F9",
		},
		{
			// RFC 7836 Appendix B example 9 (gostcrypto/kdftree/rfc/rfc7836.txt
			// lines 1499-1526): KDF_GOSTR3411_2012_256 ≡ KDFTree256 with R=1, L=256.
			// HMAC message: 01|26bdb878|00|af21434145656378|0100
			// Expected: a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9
			// Also confirmed by raw gogost KDF.Derive (the D1 gogost-gotcha).
			//
			// TRAP: [L]_b differs between the 32B (0x0100) and 64B (0x0200) cases,
			// so pinning one does NOT pin the other (KDF-02 TRAP).
			name:      "KAT-2/32B",
			label:     mustHexG(t, "26BDB878"),
			seed:      mustHexG(t, "AF21434145656378"),
			keyOutLen: 32,
			want:      "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := KDFTree256(key, tc.label, tc.seed, 1, tc.keyOutLen)
			if len(got) != tc.keyOutLen {
				t.Fatalf("len = %d, want %d", len(got), tc.keyOutLen)
			}
			// Reference 1: in-repo corrected iterator.
			if ref := gostref.KDFTree2012_256(key, tc.label, tc.seed, tc.keyOutLen); !bytes.Equal(got, ref) {
				t.Fatalf("mismatch vs gostcryptocompat:\n got %x\n ref %x", got, ref)
			}
			// Reference 2: pinned authoritative etalon (RFC 7836 Appendix B).
			if tc.want != "" {
				if want := mustHexG(t, tc.want); !bytes.Equal(got, want) {
					t.Fatalf("mismatch vs pinned vector:\n got  %x\n want %x", got, want)
				}
			}
			// Reference 3: raw gogost — ONLY valid for the 32-byte single-block case (D1).
			if tc.keyOutLen == 32 {
				ref := gost34112012256.NewKDF(key).Derive(nil, tc.label, tc.seed)
				if !bytes.Equal(got, ref) {
					t.Fatalf("mismatch vs gogost KDF.Derive:\n got %x\n ref %x", got, ref)
				}
			}
		})
	}
}

// TestKDFTree256_CounterWidth_Parity diffs the clean-room r=2..4 counter-width
// path against the inline oracleHMAC, covering iteration counters up to 3 blocks
// (KDF-03: r>1 and outLen>64 never exercised through the facade oracle).
//
// oracleHMAC is independent of both KDFTree256 and the facade loop — it uses
// gogost's gost34112012256.New directly.
func TestKDFTree256_CounterWidth_Parity(t *testing.T) {
	key := mustHexG(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHexG(t, "26BDB878")
	seed := mustHexG(t, "AF21434145656378")

	// L=512 bits (outLen=64) → [L]_b = 0x02 0x00 (2 bytes, no leading zeros).
	lRepr64 := []byte{0x02, 0x00}

	for r := 2; r <= 4; r++ {
		r := r
		t.Run(map[int]string{2: "r=2", 3: "r=3", 4: "r=4"}[r], func(t *testing.T) {
			got := KDFTree256(key, label, seed, r, 64)
			if len(got) != 64 {
				t.Fatalf("len = %d, want 64", len(got))
			}
			// Build counter bytes [i]_b: low r bytes of i, big-endian.
			counter1 := make([]byte, r)
			counter1[r-1] = 0x01
			counter2 := make([]byte, r)
			counter2[r-1] = 0x02

			k1 := oracleHMAC(key, counter1, label, seed, lRepr64)
			k2 := oracleHMAC(key, counter2, label, seed, lRepr64)
			want := append(k1, k2...)

			if !bytes.Equal(got, want) {
				t.Fatalf("r=%d mismatch:\n got  %x\n want %x", r, got, want)
			}
		})
	}
}

// TestKDFTree256_MultiBlock_Parity diffs a 3-block (96-byte) output against
// the inline oracleHMAC, exercising counter value 3 (KDF-03: counter >= 3).
// The facade only supports multiples of 32, so we use oracleHMAC as the oracle.
func TestKDFTree256_MultiBlock_Parity(t *testing.T) {
	key := mustHexG(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHexG(t, "26BDB878")
	seed := mustHexG(t, "AF21434145656378")

	outLen := 96 // 3 × 32 bytes; counter reaches 3 at r=1.
	// L = 96*8 = 768 bits = 0x0300 (2 bytes, big-endian, no leading zeros).
	lRepr96 := []byte{0x03, 0x00}

	got := KDFTree256(key, label, seed, 1, outLen)
	if len(got) != outLen {
		t.Fatalf("len = %d, want %d", len(got), outLen)
	}

	k1 := oracleHMAC(key, []byte{0x01}, label, seed, lRepr96)
	k2 := oracleHMAC(key, []byte{0x02}, label, seed, lRepr96)
	k3 := oracleHMAC(key, []byte{0x03}, label, seed, lRepr96)
	want := append(append(k1, k2...), k3...)

	if !bytes.Equal(got, want) {
		t.Fatalf("3-block mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestKDFTree256_Truncation_Parity diffs the truncation path (outLen not a
// multiple of 32) against the inline oracleHMAC (KDF-03: non-multiples-of-32
// truncation never exercised via the facade, which panics on non-multiples).
func TestKDFTree256_Truncation_Parity(t *testing.T) {
	key := mustHexG(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHexG(t, "26BDB878")
	seed := mustHexG(t, "AF21434145656378")

	cases := []struct {
		outLen  int
		lRepr   []byte // [L]_b = encodeMinBE(outLen*8)
		nBlocks int
	}{
		{40, []byte{0x01, 0x40}, 2}, // 40*8=320=0x140 (2 bytes)
		{48, []byte{0x01, 0x80}, 2}, // 48*8=384=0x180 (2 bytes)
		{16, []byte{0x80}, 1},       // 16*8=128=0x80  (1 byte)
	}

	for _, tc := range cases {
		t.Run("outLen="+string(rune('0'+tc.outLen/10))+string(rune('0'+tc.outLen%10)), func(t *testing.T) {
			got := KDFTree256(key, label, seed, 1, tc.outLen)
			if len(got) != tc.outLen {
				t.Fatalf("len = %d, want %d", len(got), tc.outLen)
			}
			// Build expected from oracleHMAC blocks, then truncate.
			var want []byte
			for i := 1; i <= tc.nBlocks; i++ {
				counter := []byte{byte(i)}
				want = append(want, oracleHMAC(key, counter, label, seed, tc.lRepr)...)
			}
			want = want[:tc.outLen]

			if !bytes.Equal(got, want) {
				t.Fatalf("outLen=%d mismatch:\n got  %x\n want %x", tc.outLen, got, want)
			}
		})
	}
}

func FuzzKDFTree256Conformance(f *testing.F) {
	// Seed #0: KAT-1 key/label/seed with odd lenSel (65 → keyOutLen=64, the
	// multi-block path).  lenSel&1==1 selects keyOutLen=64.
	// Fixes KDF-04: previously uint8(64) was even → keyOutLen stayed 32.
	f.Add([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"+
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
		[]byte("\x26\xbd\xb8\x78"), []byte("\xaf\x21\x43\x41\x45\x65\x63\x78"), uint8(65))
	// Seed #1: short key, standard label, 32-byte output path (lenSel even).
	f.Add([]byte("short-key"), []byte("level1"), []byte("\x00\x00\x00\x00\x00\x00\x00\x01"), uint8(32))
	// Seed #2: key longer than the 64-byte HMAC block size — exercises the
	// hash-the-key path inside crypto/hmac (KDF-05).
	f.Add(make([]byte, 100), []byte("label"), []byte("seed"), uint8(1))
	// Seed #3: empty key (KDF-05).
	f.Add([]byte{}, []byte("label"), []byte("seed"), uint8(1))

	f.Fuzz(func(t *testing.T, rawKey, label, seed []byte, lenSel uint8) {
		// KDF-05: use rawKey directly (no clamping to 32 bytes) so keys of any
		// length are exercised, including keys > 64 bytes that hit the
		// hash-the-key path inside crypto/hmac.
		key := rawKey

		// Map lenSel to keyOutLen as a multiple of 32 in [32, 256].
		// lenSel%8 gives 0..7 → mult 1..8 → keyOutLen 32..256.
		// This exercises iteration counters 1..8 at r=1 (KDF-05).
		mult := int(lenSel%8) + 1
		keyOutLen := mult * 32

		got := KDFTree256(key, label, seed, 1, keyOutLen)
		if len(got) != keyOutLen {
			t.Fatalf("len = %d, want %d", len(got), keyOutLen)
		}

		// Reference 1: facade oracle (only supports multiples of 32 and any key length).
		if ref := gostref.KDFTree2012_256(key, label, seed, keyOutLen); !bytes.Equal(got, ref) {
			t.Fatalf("mismatch vs gostcryptocompat (len=%d):\n got %x\n ref %x", keyOutLen, got, ref)
		}

		// Reference 2: raw gogost KDF.Derive — ONLY valid for the 32-byte single-block
		// case (D1 gotcha: KDF.Derive hardcodes counter=0x01 and L=0x0100).
		if keyOutLen == 32 {
			ref := gost34112012256.NewKDF(key).Derive(nil, label, seed)
			if !bytes.Equal(got, ref) {
				t.Fatalf("mismatch vs gogost KDF.Derive:\n got %x\n ref %x", got, ref)
			}
		}
	})
}
