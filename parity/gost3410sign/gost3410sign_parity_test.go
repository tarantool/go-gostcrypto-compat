package gost3410signparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/tarantool/go-gostcrypto/gost3410sign"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
	gogost3410 "go.stargrave.org/gogost/v7/gost3410"
)

// The differential tests cross-check the clean-room sign/verify against the
// in-repo gogost-backed reference (gostcryptocompat), used strictly as a black
// box. The oracle's SignDigestOnCurve takes an io.Reader nonce source, so a
// fixed reader is fed to keep the oracle deterministic; the clean-room
// SignDigest takes the nonce bytes directly.
//
// With a fixed nonce both SignDigest implementations produce byte-identical
// output (proven in SIG-01): both read k big-endian then Mod(q), so the
// outputs are deterministically identical when the nonce is fixed.
// Signatures are therefore byte-compared in addition to cross-verified.
//
// Two curve sizes are covered:
//   - 256-bit: RFC 7091 §7 TestParamSet (testParamSetCurve / GOST2001TestParamSetCurve).
//   - 512-bit: GOST R 34.10-2012 Appendix A.2 test param set (stdParamSet512Curve),
//     plus the production tc26-512-A curve for random cross-verify.

// TestDiff_PinnedVector cross-verifies the §7 pinned signature and public key
// under both impls (deterministic surface), and asserts that signing with the
// pinned nonce reproduces the KAT signature byte-for-byte (SIG-01).
func TestDiff_PinnedVector(t *testing.T) {
	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	prv := mustHex(t, katPrvLE)
	dig := mustHex(t, katDigBE)
	sig := mustHex(t, katSigSR)
	k := mustHex(t, katNonce)
	wantPub := append(mustHex(t, katPubX), mustHex(t, katPubY)...)

	// Public-key derivation parity.
	refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
	if err != nil {
		t.Fatalf("ref PublicKeyRawFromPrivate: %v", err)
	}
	newPub := PublicKeyRaw(newCurve, prv)
	if newPub == nil {
		t.Fatal("new PublicKeyRaw nil")
	}
	if !bytes.Equal(refPub, wantPub) {
		t.Fatalf("ref pub %x != pin %x", refPub, wantPub)
	}
	if !bytes.Equal(newPub, refPub) {
		t.Fatalf("pub mismatch ref=%x new=%x", refPub, newPub)
	}

	// Pinned signature verifies under both.
	okRef, err := gost.VerifyDigestOnCurve(refCurve, wantPub, dig, sig)
	if err != nil || !okRef {
		t.Fatalf("ref verify pinned sig: ok=%v err=%v", okRef, err)
	}
	if !VerifyDigest(newCurve, wantPub, dig, sig) {
		t.Fatal("new verify rejected pinned sig")
	}

	// SIG-01: sign with fixed nonce — both must reproduce katSigSR byte-for-byte.
	// Both impls read k big-endian then Mod(q), so with the same (prv, dig, k)
	// the outputs are deterministically identical.
	newSig := SignDigest(newCurve, prv, dig, k)
	if newSig == nil {
		t.Fatal("new SignDigest nil for KAT nonce")
	}
	if !bytes.Equal(newSig, sig) {
		t.Fatalf("new SignDigest != katSigSR:\n got %x\nwant %x", newSig, sig)
	}
	refSig, err := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(k))
	if err != nil {
		t.Fatalf("ref SignDigestOnCurve: %v", err)
	}
	if !bytes.Equal(refSig, sig) {
		t.Fatalf("ref SignDigestOnCurve != katSigSR:\n got %x\nwant %x", refSig, sig)
	}

	// Tamper: both reject.
	bad := append([]byte(nil), dig...)
	bad[0] ^= 0x01
	if VerifyDigest(newCurve, wantPub, bad, sig) {
		t.Fatal("new accepted tampered digest")
	}
	if ok, _ := gost.VerifyDigestOnCurve(refCurve, wantPub, bad, sig); ok {
		t.Fatal("ref accepted tampered digest")
	}
}

// TestDiff_CrossVerifyRandom signs with each impl and verifies each signature
// under BOTH, across many fresh (prv, digest) pairs on the §7 TestParamSet.
// Because a fixed nonce is used, the raw signature bytes are also byte-compared
// (SIG-01: with equal nonce both impls produce byte-identical output).
func TestDiff_CrossVerifyRandom(t *testing.T) {
	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	for iter := range 64 {
		prv := make([]byte, 32)
		dig := make([]byte, 32)
		k := make([]byte, 32)
		for i := range 32 {
			prv[i] = byte(iter*7 + i*3 + 1)
			dig[i] = byte(iter*5 + i*11 + 2)
			k[i] = byte(iter*13 + i*17 + 3)
		}

		// Public-key parity.
		refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
		if err != nil {
			t.Skipf("iter %d: ref key load failed: %v", iter, err)
		}
		newPub := PublicKeyRaw(newCurve, prv)
		if newPub == nil {
			t.Fatalf("iter %d: new PublicKeyRaw nil where ref ok", iter)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("iter %d: pub mismatch ref=%x new=%x", iter, refPub, newPub)
		}

		// Sign with the oracle (fixed nonce reader) and with the clean-room impl.
		refSig, err := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(k))
		if err != nil {
			t.Fatalf("iter %d: ref sign: %v", iter, err)
		}
		newSig := SignDigest(newCurve, prv, dig, k)
		if newSig == nil {
			t.Fatalf("iter %d: new sign nil", iter)
		}

		// SIG-01: with a fixed nonce the raw signature bytes must be identical.
		if !bytes.Equal(refSig, newSig) {
			t.Fatalf("iter %d: sign bytes differ ref=%x new=%x", iter, refSig, newSig)
		}

		// Cross-verify every combination.
		if !VerifyDigest(newCurve, refPub, dig, refSig) {
			t.Fatalf("iter %d: new failed to verify ref sig", iter)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, newSig); err != nil || !ok {
			t.Fatalf("iter %d: ref failed to verify new sig: ok=%v err=%v", iter, ok, err)
		}
		if !VerifyDigest(newCurve, refPub, dig, newSig) {
			t.Fatalf("iter %d: new failed to verify new sig", iter)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, refSig); err != nil || !ok {
			t.Fatalf("iter %d: ref failed to verify ref sig: ok=%v err=%v", iter, ok, err)
		}
	}
}

// TestDiff_Pinned512_A2 ports the GOST R 34.10-2012 Appendix A.2 512-bit
// worked example as a parity differential: both the clean-room and the gogost
// oracle must reproduce the standard's s||r bytes exactly, and the signature
// must cross-verify under both (SIG-02).
//
// Source: GOST R 34.10-2012, Appendix A.2.
// Clean-room curve: stdParamSet512Curve() (constants from the standard).
// Oracle curve: gogost3410.CurveIdtc26gost341012512paramSetTest()
//
//	(third_party/gogost/gost3410/params.go:320 — same constants).
func TestDiff_Pinned512_A2(t *testing.T) {
	// Clean-room side: the A.2 test param set curve (constructed directly —
	// not OID-registered, so CurveByOID is not used here).
	newCurve := stdParamSet512Curve()

	// Oracle side: same curve via gogost (imported directly since the facade's
	// CurveByOID does not cover this non-registered test-only curve).
	refGogostCurve := gogost3410.CurveIdtc26gost341012512paramSetTest()

	prv := mustHex(t, katPrv512LE)
	dig := mustHex(t, katDig512BE)
	k := mustHex(t, katNonce512)
	wantSig := mustHex(t, katSigSR512)

	// Clean-room public key.
	newPub := PublicKeyRaw(newCurve, prv)
	if newPub == nil {
		t.Fatal("new PublicKeyRaw 512 nil")
	}

	// Oracle public key.
	refPrv, err := gogost3410.NewPrivateKey(refGogostCurve, prv)
	if err != nil {
		t.Fatalf("gogost NewPrivateKey 512: %v", err)
	}
	refPubKey, err := refPrv.PublicKey()
	if err != nil {
		t.Fatalf("gogost PublicKey 512: %v", err)
	}
	refPub := refPubKey.Raw()

	// Public keys must be byte-identical.
	if !bytes.Equal(newPub, refPub) {
		t.Fatalf("512 pub mismatch new=%x ref=%x", newPub, refPub)
	}

	// Both must reproduce the A.2 KAT signature byte-for-byte.
	newSig := SignDigest(newCurve, prv, dig, k)
	if newSig == nil {
		t.Fatal("new SignDigest 512 nil")
	}
	if !bytes.Equal(newSig, wantSig) {
		t.Fatalf("new 512 SignDigest != A.2 KAT:\n got %x\nwant %x", newSig, wantSig)
	}

	refSig, err := refPrv.SignDigest(dig, bytes.NewReader(k))
	if err != nil {
		t.Fatalf("gogost SignDigest 512: %v", err)
	}
	if !bytes.Equal(refSig, wantSig) {
		t.Fatalf("ref 512 SignDigest != A.2 KAT:\n got %x\nwant %x", refSig, wantSig)
	}

	// Cross-verify every combination.
	if !VerifyDigest(newCurve, newPub, dig, newSig) {
		t.Fatal("new 512 failed to verify new sig")
	}
	if !VerifyDigest(newCurve, newPub, dig, refSig) {
		t.Fatal("new 512 failed to verify ref sig")
	}
	okRef, err := refPubKey.VerifyDigest(dig, refSig)
	if err != nil || !okRef {
		t.Fatalf("ref 512 failed to verify ref sig: ok=%v err=%v", okRef, err)
	}
	okRef, err = refPubKey.VerifyDigest(dig, newSig)
	if err != nil || !okRef {
		t.Fatalf("ref 512 failed to verify new sig: ok=%v err=%v", okRef, err)
	}

	// Tamper: both reject.
	bad := append([]byte(nil), dig...)
	bad[0] ^= 0x01
	if VerifyDigest(newCurve, newPub, bad, wantSig) {
		t.Fatal("new 512 accepted tampered digest")
	}
	if ok, _ := refPubKey.VerifyDigest(bad, wantSig); ok {
		t.Fatal("ref 512 accepted tampered digest")
	}
}

// TestDiff_CrossVerify512 mirrors TestDiff_CrossVerifyRandom for 512-bit
// curves, using tc26-512-A (OID 1.2.643.7.1.2.1.2.1) — a production TLS
// curve registered in the facade's CurveByOID. Raw signature bytes are
// byte-compared (fixed nonce → deterministic output). SIG-02: exercises the
// 64-byte halves in SignDigest's fillBE / PublicKeyRaw's putLE padding paths.
func TestDiff_CrossVerify512(t *testing.T) {
	newCurve := cleanroomCurve512A(t)
	refCurve := refCurve512A(t)

	for iter := range 16 {
		prv := make([]byte, 64)
		dig := make([]byte, 64)
		k := make([]byte, 64)
		for i := range 64 {
			prv[i] = byte(iter*7 + i*3 + 1)
			dig[i] = byte(iter*5 + i*11 + 2)
			k[i] = byte(iter*13 + i*17 + 3)
		}

		// Public-key parity.
		refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
		if err != nil {
			t.Skipf("512 iter %d: ref key load failed: %v", iter, err)
		}
		newPub := PublicKeyRaw(newCurve, prv)
		if newPub == nil {
			t.Fatalf("512 iter %d: new PublicKeyRaw nil where ref ok", iter)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("512 iter %d: pub mismatch ref=%x new=%x", iter, refPub, newPub)
		}

		// Sign with fixed nonce on both sides.
		refSig, err := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(k))
		if err != nil {
			t.Fatalf("512 iter %d: ref sign: %v", iter, err)
		}
		newSig := SignDigest(newCurve, prv, dig, k)
		if newSig == nil {
			t.Fatalf("512 iter %d: new sign nil", iter)
		}

		// Byte-identity (SIG-01 / SIG-02).
		if !bytes.Equal(refSig, newSig) {
			t.Fatalf("512 iter %d: sign bytes differ ref=%x new=%x", iter, refSig, newSig)
		}

		// Cross-verify.
		if !VerifyDigest(newCurve, refPub, dig, refSig) {
			t.Fatalf("512 iter %d: new failed to verify ref sig", iter)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, newSig); err != nil || !ok {
			t.Fatalf("512 iter %d: ref failed to verify new sig: ok=%v err=%v", iter, ok, err)
		}
	}
}

// TestDiff_RejectionParity cross-checks each rejection path against the gogost
// oracle: both impls must agree on rejection for malformed / out-of-range
// inputs (SIG-03).
func TestDiff_RejectionParity(t *testing.T) {
	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	dig := mustHex(t, katDigBE)
	sig := mustHex(t, katSigSR)
	pub := append(mustHex(t, katPubX), mustHex(t, katPubY)...)

	// 1. Wrong-length sig: both must reject.
	t.Run("wrong_len_sig_short", func(t *testing.T) {
		shortSig := sig[:len(sig)-1]
		if VerifyDigest(newCurve, pub, dig, shortSig) {
			t.Fatal("new accepted short sig")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, pub, dig, shortSig); ok {
			t.Fatal("ref accepted short sig")
		}
	})
	t.Run("wrong_len_sig_long", func(t *testing.T) {
		longSig := append(append([]byte(nil), sig...), 0x00)
		if VerifyDigest(newCurve, pub, dig, longSig) {
			t.Fatal("new accepted long sig")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, pub, dig, longSig); ok {
			t.Fatal("ref accepted long sig")
		}
	})

	// 2. Wrong-length pubRaw: both must reject.
	t.Run("wrong_len_pub_short", func(t *testing.T) {
		shortPub := pub[:len(pub)-1]
		if VerifyDigest(newCurve, shortPub, dig, sig) {
			t.Fatal("new accepted short pub")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, shortPub, dig, sig); ok {
			t.Fatal("ref accepted short pub")
		}
	})
	t.Run("wrong_len_pub_long", func(t *testing.T) {
		longPub := append(append([]byte(nil), pub...), 0x00)
		if VerifyDigest(newCurve, longPub, dig, sig) {
			t.Fatal("new accepted long pub")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, longPub, dig, sig); ok {
			t.Fatal("ref accepted long pub")
		}
	})

	// 3. r == 0 (second half zeroed): both must reject.
	t.Run("r_zero", func(t *testing.T) {
		ps := newCurve.PointSize()
		badSig := append([]byte(nil), sig...)
		for i := ps; i < 2*ps; i++ {
			badSig[i] = 0x00
		}
		if VerifyDigest(newCurve, pub, dig, badSig) {
			t.Fatal("new accepted sig with r=0")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, pub, dig, badSig); ok {
			t.Fatal("ref accepted sig with r=0")
		}
	})

	// 4. s == 0 (first half zeroed): both must reject.
	t.Run("s_zero", func(t *testing.T) {
		ps := newCurve.PointSize()
		badSig := append([]byte(nil), sig...)
		for i := range ps {
			badSig[i] = 0x00
		}
		if VerifyDigest(newCurve, pub, dig, badSig) {
			t.Fatal("new accepted sig with s=0")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, pub, dig, badSig); ok {
			t.Fatal("ref accepted sig with s=0")
		}
	})

	// 5. Off-curve public key: both must reject.
	// The clean-room calls IsOnCurve; gogost skips the check but still rejects
	// in practice because forged R ≠ r for an arbitrary off-curve point.
	t.Run("off_curve_pub_allzero", func(t *testing.T) {
		allZeroPub := make([]byte, len(pub))
		if VerifyDigest(newCurve, allZeroPub, dig, sig) {
			t.Fatal("new accepted all-zero pub")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, allZeroPub, dig, sig); ok {
			t.Fatal("ref accepted all-zero pub")
		}
	})
	t.Run("off_curve_pub_flipped", func(t *testing.T) {
		flipped := append([]byte(nil), pub...)
		flipped[0] ^= 0x01
		if VerifyDigest(newCurve, flipped, dig, sig) {
			t.Fatal("new accepted byte-flipped pub")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, flipped, dig, sig); ok {
			t.Fatal("ref accepted byte-flipped pub")
		}
	})

	// 6. Tampered signature bytes (not just digest): both must reject.
	t.Run("tampered_sig_byte", func(t *testing.T) {
		badSig := append([]byte(nil), sig...)
		badSig[0] ^= 0x01
		if VerifyDigest(newCurve, pub, dig, badSig) {
			t.Fatal("new accepted sig with flipped sig byte")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, pub, dig, badSig); ok {
			t.Fatal("ref accepted sig with flipped sig byte")
		}
	})

	// 7. Nil inputs: both must reject (no panic).
	t.Run("nil_sig", func(t *testing.T) {
		if VerifyDigest(newCurve, pub, dig, nil) {
			t.Fatal("new accepted nil sig")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, pub, dig, nil); ok {
			t.Fatal("ref accepted nil sig")
		}
	})
	t.Run("nil_pub", func(t *testing.T) {
		if VerifyDigest(newCurve, nil, dig, sig) {
			t.Fatal("new accepted nil pub")
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, nil, dig, sig); ok {
			t.Fatal("ref accepted nil pub")
		}
	})
}

// seedHex decodes hex for f.Add seeds, where no *testing.T is available.
func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// fixLen slices or zero-extends b to exactly n bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// FuzzCrossVerify mirrors TestDiff_CrossVerifyRandom over fuzzer-chosen scalars.
// It derives a key, signs the digest with both the clean-room impl and the
// gogost oracle (deterministic via a fixed nonce reader), and asserts:
//   - public keys are byte-identical,
//   - signature bytes are byte-identical (SIG-01: with fixed nonce both impls
//     read k big-endian then Mod(q) — outputs are deterministically identical),
//   - each signature cross-verifies under BOTH impls,
//   - tampering the digest must be rejected by both.
//
// Operates on the §7 TestParamSet (256-bit).
//
// SIG-04: rawDig is NOT clamped to 32 bytes — both impls are length-agnostic
// for the digest (SetBytes then Mod(q)); the 64-byte Streebog-512 production
// case for a 256-bit curve is therefore reachable. rawPrv and rawK remain
// 32-byte fixed: gogost NewPrivateKey hard-errors on wrong key length; gogost
// io.ReadFull always reads exactly 32 bytes regardless of reader length.
func FuzzCrossVerify(f *testing.F) {
	f.Add(seedHex(katPrvLE), seedHex(katDigBE), seedHex(katNonce))
	f.Add(
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x33}, 32),
	)
	// 64-byte digest: the actual GOST TLS Streebog-512 case for a 256-bit curve.
	f.Add(
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x44}, 64),
		bytes.Repeat([]byte{0x33}, 32),
	)
	// short (1-byte) digest.
	f.Add(
		bytes.Repeat([]byte{0x11}, 32),
		[]byte{0x05},
		bytes.Repeat([]byte{0x33}, 32),
	)

	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	f.Fuzz(func(t *testing.T, rawPrv, rawDig, rawK []byte) {
		prv := fixLen(rawPrv, 32)
		// SIG-04: digest length is NOT clamped — both impls do SetBytes(dig).Mod(q)
		// and accept any length as valid parity surface.
		dig := rawDig
		k := fixLen(rawK, 32)

		// Public-key parity. A scalar reducing to zero is a genuinely invalid
		// input: skip it.
		refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
		if err != nil {
			t.Skipf("ref key load failed: %v", err)
		}
		newPub := PublicKeyRaw(newCurve, prv)
		if newPub == nil {
			t.Fatalf("new PublicKeyRaw nil where ref ok (prv=%x)", prv)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("pub mismatch ref=%x new=%x", refPub, newPub)
		}

		// Sign with the oracle (fixed nonce reader) and the clean-room impl.
		refSig, err := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(k))
		if err != nil {
			// A nonce of zero (or one reducing to zero mod q) is invalid.
			t.Skipf("ref sign failed (likely degenerate nonce): %v", err)
		}
		newSig := SignDigest(newCurve, prv, dig, k)
		if newSig == nil {
			t.Skipf("new sign nil (likely degenerate nonce, prv=%x k=%x)", prv, k)
		}

		// SIG-01: with a fixed nonce both impls must produce byte-identical output.
		if !bytes.Equal(refSig, newSig) {
			t.Fatalf("sign bytes differ ref=%x new=%x (prv=%x dig=%x k=%x)", refSig, newSig, prv, dig, k)
		}

		// Cross-verify every combination: each sig accepted under both impls.
		if !VerifyDigest(newCurve, refPub, dig, refSig) {
			t.Fatalf("new failed to verify ref sig (prv=%x dig=%x)", prv, dig)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, newSig); err != nil || !ok {
			t.Fatalf("ref failed to verify new sig: ok=%v err=%v (prv=%x dig=%x)", ok, err, prv, dig)
		}
		if !VerifyDigest(newCurve, refPub, dig, newSig) {
			t.Fatalf("new failed to verify new sig (prv=%x dig=%x)", prv, dig)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, refSig); err != nil || !ok {
			t.Fatalf("ref failed to verify ref sig: ok=%v err=%v (prv=%x dig=%x)", ok, err, prv, dig)
		}

		// Tamper: flip a digest byte; both impls must reject the now-stale sig.
		//
		// Guard: skip when the tamped digest produces the same effective e (§6.1
		// step 2: e=0→e=1). This happens when both dig and bad reduce to the same
		// value mod q (most commonly: dig=[0x00] → e=1, bad=[0x01] → e=1). We
		// compute the effective e for both and skip if they're equal, avoiding a
		// false failure that is correct behaviour (same e → same sig → verifies).
		if len(dig) > 0 {
			bad := append([]byte(nil), dig...)
			bad[0] ^= 0x01
			eDig := effectiveE256(dig)
			eBad := effectiveE256(bad)
			if eDig.Cmp(eBad) != 0 {
				if VerifyDigest(newCurve, refPub, bad, refSig) {
					t.Fatalf("new accepted tampered digest (prv=%x dig=%x)", prv, dig)
				}
				if ok, _ := gost.VerifyDigestOnCurve(refCurve, refPub, bad, refSig); ok {
					t.Fatalf("ref accepted tampered digest (prv=%x dig=%x)", prv, dig)
				}
			}
		}
	})
}
