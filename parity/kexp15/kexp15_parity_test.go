// Package kexp15parity differentially tests the clean-room kexp15 against the
// in-repo gogost-backed oracle.
//
// Oracle-independence caveat (rule 7): gogost v7 ships no KExp15, OMAC/CMAC, or
// GOST-CTR. The facade oracle (gost.Kexp15) takes only the raw block ciphers
// (gost3412128/gost341264) from gogost and re-implements OMAC, CTR, and the
// OMAC-then-CTR composition locally, structurally parallel to the clean-room
// kexp15/omac/ctracpkm packages. The differential therefore strongly proves
// block-cipher parity but is weaker on the composition layer, where a bug common
// to both same-shaped implementations would pass. External correctness for that
// layer is anchored by independent pinned vectors:
//   - Magma:      gost-engine 3.0.3 etalon (TestKexp15Conformance below).
//   - Kuznyechik: RFC 9189 Appendix A.1.3.2 (TestKexp15Conformance_Kuznyechik).
//
// Only the block ciphers are independently sourced; the OMAC/CTR composition is
// facade-side. The two pinned KATs above are the external anchors the sibling
// oracle cannot provide on its own.
package kexp15parity

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/tarantool/go-gostcrypto/kexp15"

	gost "github.com/tarantool/go-gostcrypto-compat"
)

func mustHexF(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestKexp15Conformance asserts both the in-repo oracle and the clean-room
// impl reproduce the pinned Magma etalon (gost-engine 3.0.3,
// tmp/engine/test_keyexpimp.c:47-76).
func TestKexp15Conformance(t *testing.T) {
	shared := mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	cipherKey := mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637")
	macKey := mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f")
	iv := mustHexF("67bed654")
	want := mustHexF("cfd5a12d5b81b6e1e99c916d07900c6ac12703fb3abded55567bf3742c899c755dafe7b42e3a8bd9")

	ref, err := gost.Kexp15(gost.KexpMagma, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("gost.Kexp15: %v", err)
	}
	if !bytes.Equal(ref, want) {
		t.Fatalf("oracle disagrees with pinned vector:\n got  %x\n want %x", ref, want)
	}

	got, err := Kexp15(KexpMagma, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("clean-room mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestKexp15Conformance_Kuznyechik pins BOTH the gogost-backed oracle and the
// clean-room impl against the published RFC 9189 Appendix A.1.3.2 vector
// (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC). This is the independent
// external anchor for the Kuznyechik (128-bit) composition path: the sibling
// oracle re-implements OMAC/CTR locally, so without this pin a shared
// composition bug would pass the differential undetected (rule 7 / KXP-01).
//
// Provenance: extracted directly from the bundled RFC at
// ../../gostcrypto/kexp15/rfc/rfc9189.txt, the Client side of A.1.3.2:
//   - shared (PMS):                       lines 3158-3159
//   - K_Exp_MAC | K_Exp_ENC (mac|cipher): lines 3189-3192 (first 32B = macKey,
//     next 32B = cipherKey; KExp15 arg order per RFC 9189 §8.2.1 is
//     KExp15(S, K_Exp_MAC, K_Exp_ENC, IV))
//   - IV:                                 line 3195
//   - want (PMSEXP):                      lines 3198-3200
func TestKexp15Conformance_Kuznyechik(t *testing.T) {
	shared := mustHexF("a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d")
	macKey := mustHexF("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1")
	cipherKey := mustHexF("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24")
	iv := mustHexF("214a6a298e99e325")
	want := mustHexF("250d1b67a270ab04d3f65418e1d380b4cb945f0a3dca51500cf3a1bef37f76c07" +
		"341a9839ccf6cba7189da61eb67176c")

	ref, err := gost.Kexp15(gost.KexpKuznyechik, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("gost.Kexp15: %v", err)
	}
	if !bytes.Equal(ref, want) {
		t.Fatalf("oracle disagrees with RFC 9189 A.1.3.2:\n got  %x\n want %x", ref, want)
	}

	got, err := Kexp15(KexpKuznyechik, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("clean-room mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestKexp15_ErrorCasesParity asserts the oracle and the clean-room impl agree
// on accept/reject for invalid inputs (KXP-03): both must reject the same
// malformed key/IV/variant inputs. Mirrors gostcrypto/kexp15 TestKexp15_ErrorCases.
func TestKexp15_ErrorCasesParity(t *testing.T) {
	good := struct {
		shared, cipherKey, macKey, iv []byte
	}{
		shared:    mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		cipherKey: mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"),
		macKey:    mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"),
		iv:        mustHexF("67bed654"),
	}

	cases := []struct {
		name                          string
		refVariant                    gost.KexpVariant
		myVariant                     KexpVariant
		shared, cipherKey, macKey, iv []byte
	}{
		{"empty shared", gost.KexpMagma, KexpMagma, []byte{}, good.cipherKey, good.macKey, good.iv},
		{"short cipher key", gost.KexpMagma, KexpMagma, good.shared, good.cipherKey[:31], good.macKey, good.iv},
		{"short mac key", gost.KexpMagma, KexpMagma, good.shared, good.cipherKey, good.macKey[:31], good.iv},
		{"wrong iv len (magma)", gost.KexpMagma, KexpMagma, good.shared, good.cipherKey, good.macKey, good.iv[:3]},
		{"kuznyechik iv too short", gost.KexpKuznyechik, KexpKuznyechik, good.shared, good.cipherKey, good.macKey, good.iv},
		{"bad variant", gost.KexpVariant(99), KexpVariant(99), good.shared, good.cipherKey, good.macKey, good.iv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errRef := gost.Kexp15(tc.refVariant, tc.shared, tc.cipherKey, tc.macKey, tc.iv)
			_, errGot := Kexp15(tc.myVariant, tc.shared, tc.cipherKey, tc.macKey, tc.iv)

			if (errRef == nil) != (errGot == nil) {
				t.Fatalf("error-agreement mismatch: oracle err=%v clean-room err=%v", errRef, errGot)
			}
			if errRef == nil {
				t.Fatalf("expected both sides to reject, got nil error")
			}
		})
	}
}

// fixKey clamps b to exactly n bytes (zero-padded / truncated).
func fixKey(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func FuzzKexp15Conformance(f *testing.F) {
	// Magma etalon seed (gost-engine).
	f.Add(
		mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"),
		mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"),
		mustHexF("67bed654"),
		false,
	)
	// Kuznyechik seed (RFC 9189 A.1.3.2): exercises the kuz=true branch under
	// seed replay (KXP-04). OMAC input = iv(8) || shared(32) = 40 B over a
	// 16-byte block -> K2/padding branch.
	f.Add(
		mustHexF("a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d"),
		mustHexF("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24"),
		mustHexF("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1"),
		mustHexF("214a6a298e99e325"),
		true,
	)
	// Magma seed hitting the OMAC complete-final-block (K1) path (KXP-04):
	// OMAC input = iv(4) || shared(4) = 8 B, exactly one Magma block, so the
	// final block is full -> K1 subkey branch.
	f.Add(
		mustHexF("deadbeef"),
		mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"),
		mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"),
		mustHexF("67bed654"),
		false,
	)
	// Kuznyechik seed hitting the OMAC K1 path (KXP-04): OMAC input =
	// iv(8) || shared(8) = 16 B, exactly one Kuznyechik block -> K1 branch.
	f.Add(
		mustHexF("0123456789abcdef"),
		mustHexF("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24"),
		mustHexF("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1"),
		mustHexF("214a6a298e99e325"),
		true,
	)

	f.Fuzz(func(t *testing.T, shared, cipherRaw, macRaw, ivRaw []byte, kuz bool) {
		if len(shared) == 0 {
			shared = []byte{0x01}
		}
		refVariant := gost.KexpMagma
		myVariant := KexpMagma
		ivLen := 4
		if kuz {
			refVariant = gost.KexpKuznyechik
			myVariant = KexpKuznyechik
			ivLen = 8
		}
		cipherKey := fixKey(cipherRaw, 32)
		macKey := fixKey(macRaw, 32)
		iv := fixKey(ivRaw, ivLen)

		ref, errRef := gost.Kexp15(refVariant, shared, cipherKey, macKey, iv)
		got, errGot := Kexp15(myVariant, shared, cipherKey, macKey, iv)

		if (errRef == nil) != (errGot == nil) {
			t.Fatalf("error mismatch: ref=%v mynew=%v", errRef, errGot)
		}
		if errRef != nil {
			return
		}
		if !bytes.Equal(ref, got) {
			t.Fatalf("differential mismatch (kuz=%v):\n ref   %x\n mynew %x", kuz, ref, got)
		}
	})
}
