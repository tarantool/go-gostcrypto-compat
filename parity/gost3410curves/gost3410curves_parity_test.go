package gost3410curvesparity

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
	"github.com/tarantool/go-gostcrypto/gost3410curves"
	"github.com/tarantool/go-gostcrypto/gost3410sign"
	gogostcurve "go.stargrave.org/gogost/v7/gost3410"
)

// oidToASN1 parses a dotted-decimal OID string into an asn1.ObjectIdentifier.
func oidToASN1(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n := 0
		for _, ch := range p {
			n = n*10 + int(ch-'0')
		}
		oid[i] = n
	}
	return oid
}

// mustGogostCurve resolves a gogost *gost3410.Curve directly by OID string,
// bypassing the facade wrapper so we can access raw field values (P, A, B, Q,
// X, Y, Co). This is necessary because the facade's *Curve wrapper exposes only
// Name() and PointSize().
func mustGogostCurve(t *testing.T, oidStr string) *gogostcurve.Curve {
	t.Helper()
	switch oidStr {
	case "1.2.643.2.2.35.1":
		return gogostcurve.CurveIdGostR34102001CryptoProAParamSet()
	case "1.2.643.2.2.35.2":
		return gogostcurve.CurveIdGostR34102001CryptoProBParamSet()
	case "1.2.643.2.2.35.3":
		return gogostcurve.CurveIdGostR34102001CryptoProCParamSet()
	case "1.2.643.7.1.2.1.1.1":
		return gogostcurve.CurveIdtc26gost341012256paramSetA()
	case "1.2.643.7.1.2.1.1.2":
		return gogostcurve.CurveIdtc26gost341012256paramSetB()
	case "1.2.643.7.1.2.1.1.3":
		return gogostcurve.CurveIdtc26gost341012256paramSetC()
	case "1.2.643.7.1.2.1.1.4":
		return gogostcurve.CurveIdtc26gost341012256paramSetD()
	case "1.2.643.7.1.2.1.2.1":
		return gogostcurve.CurveIdtc26gost341012512paramSetA()
	case "1.2.643.7.1.2.1.2.2":
		return gogostcurve.CurveIdtc26gost341012512paramSetB()
	case "1.2.643.7.1.2.1.2.3":
		return gogostcurve.CurveIdtc26gost341012512paramSetC()
	}
	t.Fatalf("mustGogostCurve: unknown OID %q", oidStr)
	return nil
}

// assertBigEq fails t if a.Cmp(b) != 0.
func assertBigEq(t *testing.T, field string, a, b *big.Int) {
	t.Helper()
	if a.Cmp(b) != 0 {
		t.Fatalf("%s mismatch:\n  mine=%x\n  ref =%x", field, a, b)
	}
}

// TestCurveConstantsDifferential compares the clean-room curve constants
// (P, A, B, Q, X, Y, Cofactor) against the gogost oracle for all 10 OIDs,
// and diffs IsOnCurve against gogost's Contains on both on-curve and off-curve
// points (CRV-01).
//
// Additionally it asserts the absolute tc.pointSize anchor from allOIDs
// (CRV-04).
func TestCurveConstantsDifferential(t *testing.T) {
	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			mine := mustCurve(t, tc.oid)
			ref := mustGogostCurve(t, tc.oid)

			// CRV-04: assert absolute point size from independent table.
			if mine.PointSize() != tc.pointSize {
				t.Fatalf("PointSize mine=%d want=%d (per allOIDs)", mine.PointSize(), tc.pointSize)
			}

			// CRV-01: constant-by-constant differential.
			assertBigEq(t, "P", mine.P, ref.P)
			assertBigEq(t, "A", mine.A, ref.A)
			assertBigEq(t, "B", mine.B, ref.B)
			assertBigEq(t, "Q", mine.Q, ref.Q)
			assertBigEq(t, "X", mine.X, ref.X)
			assertBigEq(t, "Y", mine.Y, ref.Y)
			wantCofactor := big.NewInt(int64(mine.Cofactor))
			if wantCofactor.Cmp(ref.Co) != 0 {
				t.Fatalf("Cofactor mine=%d gogost=%s", mine.Cofactor, ref.Co)
			}

			// CRV-01: IsOnCurve vs Contains — base point (must be on-curve on both).
			base := mine.Base()
			if !mine.IsOnCurve(base) {
				t.Fatalf("clean-room IsOnCurve(base) == false, want true")
			}
			if !ref.Contains(base.X, base.Y) {
				t.Fatalf("gogost Contains(base) == false, want true")
			}

			// CRV-01: off-curve point — (X, Y+1) must be rejected by both.
			offY := new(big.Int).Add(mine.Y, big.NewInt(1))
			offY.Mod(offY, mine.P)
			offPt := gost3410curves.Point{X: new(big.Int).Set(mine.X), Y: offY}
			mineOff := mine.IsOnCurve(offPt)
			refOff := ref.Contains(mine.X, offY)
			if mineOff != refOff {
				t.Fatalf("IsOnCurve/Contains disagree on off-curve point: mine=%v ref=%v", mineOff, refOff)
			}
			if mineOff {
				t.Fatalf("both claim off-curve point (X, Y+1) is on curve — bug in both?")
			}
		})
	}
}

// TestCrossCheckInternalGost cross-checks OID resolution using the
// gostcryptocompat facade (black-box, PointSize + name smoke).
// The full constant-parity burden is in TestCurveConstantsDifferential
// (CRV-01). CRV-02: kept here as a facade smoke test with noted name alias.
//
// Documented name alias (not a bug): the facade wraps gogost's internal name,
// which uses "...3410-2012-512..." while the clean-room uses "...3410-12-512..."
// for tc26-512-{A,B,C}. Name identity is therefore intentionally NOT asserted
// across the two implementations.
func TestCrossCheckInternalGost(t *testing.T) {
	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			mine := mustCurve(t, tc.oid)

			ref, err := gost.CurveByOID(oidToASN1(t, tc.oid))
			if err != nil {
				t.Fatalf("gostcryptocompat.CurveByOID(%s): %v", tc.oid, err)
			}
			if mine.PointSize() != ref.PointSize() {
				t.Fatalf("%s: PointSize mine=%d gogost=%d",
					tc.name, mine.PointSize(), ref.PointSize())
			}
			// CRV-04: assert absolute pointSize anchor.
			if mine.PointSize() != tc.pointSize {
				t.Fatalf("%s: PointSize mine=%d want=%d (per allOIDs)",
					tc.name, mine.PointSize(), tc.pointSize)
			}
			if ref.Name() == "" {
				t.Fatalf("%s: gogost returned empty name", tc.name)
			}
			t.Logf("%s: gogost name=%q PointSize=%d", tc.name, ref.Name(), ref.PointSize())
		})
	}
}

// TestPointEdgeCases exercises Add/Double edge branches (identity element,
// vertical tangent, p+(-p) identity) and Double with a known on-curve point
// diffed against gogost's Exp, as coverage for B-reading paths (CRV-05).
func TestPointEdgeCases(t *testing.T) {
	// Use CryptoPro-A (OID 1.2.643.2.2.35.1) as a representative 256-bit curve.
	mine := mustCurve(t, "1.2.643.2.2.35.1")
	ref := mustGogostCurve(t, "1.2.643.2.2.35.1")
	G := mine.Base()

	// Identity + G == G.
	id := gost3410curves.Point{}
	res := mine.Add(id, G)
	if res.X.Cmp(G.X) != 0 || res.Y.Cmp(G.Y) != 0 {
		t.Fatalf("Add(inf, G) != G: got (%x, %x)", res.X, res.Y)
	}
	// G + Identity == G.
	res2 := mine.Add(G, id)
	if res2.X.Cmp(G.X) != 0 || res2.Y.Cmp(G.Y) != 0 {
		t.Fatalf("Add(G, inf) != G: got (%x, %x)", res2.X, res2.Y)
	}

	// G + (-G) == identity. -G = (G.X, P - G.Y).
	negGY := new(big.Int).Sub(mine.P, G.Y)
	negG := gost3410curves.Point{X: new(big.Int).Set(G.X), Y: negGY}
	sum := mine.Add(G, negG)
	if !sum.IsInfinity() {
		t.Fatalf("Add(G, -G) should be identity, got (%x, %x)", sum.X, sum.Y)
	}

	// Double(G) should equal 2·G via gogost Exp(2, G.X, G.Y).
	dbl := mine.Double(G)
	refX, refY, err := ref.Exp(big.NewInt(2), G.X, G.Y)
	if err != nil {
		t.Fatalf("gogost Exp(2, G.X, G.Y): %v", err)
	}
	if dbl.X.Cmp(refX) != 0 || dbl.Y.Cmp(refY) != 0 {
		t.Fatalf("Double(G) mismatch with gogost Exp(2,G.X,G.Y):\n  mine=(%x,%x)\n  ref =(%x,%x)",
			dbl.X, dbl.Y, refX, refY)
	}

	// Double at identity should return identity.
	dblId := mine.Double(id)
	if !dblId.IsInfinity() {
		t.Fatalf("Double(inf) should be identity, got (%x, %x)", dblId.X, dblId.Y)
	}
}

// FuzzPointAdd diffs clean-room Add(P1, P2) against gogost Exp(s1+s2, G.X, G.Y)
// for arbitrary on-curve points P1=s1·G and P2=s2·G, exercising the
// non-base-point addition path and the B-dependent arithmetic branches (CRV-05).
//
// We use the linearity identity: s1·G + s2·G == (s1+s2)·G.
// The case s1 ≡ -s2 mod Q (P2 = -P1, gogost add is known-broken there) and
// s1 ≡ s2 mod Q (P1 == P2, hits doubling) are both skipped.
func FuzzPointAdd(f *testing.F) {
	// Seed: two independent 32-byte scalars on CryptoPro-A (idx=0).
	f.Add(0,
		[]byte{
			0x28, 0x3b, 0xec, 0x91, 0x98, 0xce, 0x19, 0x1d, 0xee, 0x7e, 0x39, 0x49,
			0x1f, 0x96, 0x60, 0x1b, 0xc1, 0x72, 0x9a, 0xd3, 0x9d, 0x35, 0xed, 0x10,
			0xbe, 0xb9, 0x9b, 0x78, 0xde, 0x9a, 0x92, 0x7a,
		},
		[]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
			0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		},
	)
	// Seed: two 64-byte scalars on tc26-512-A (idx=7).
	f.Add(7,
		bytes.Repeat([]byte{0x33}, 64),
		bytes.Repeat([]byte{0x55}, 64),
	)

	f.Fuzz(func(t *testing.T, sel int, raw1 []byte, raw2 []byte) {
		idx := sel % len(allOIDs)
		if idx < 0 {
			idx += len(allOIDs)
		}
		oidStr := allOIDs[idx].oid
		mine := mustCurve(t, oidStr)
		ref := mustGogostCurve(t, oidStr)

		ps := mine.PointSize()
		s1Bytes := fixLen(raw1, ps)
		s2Bytes := fixLen(raw2, ps)

		// Interpret as big-endian (no LE reversal — we drive Exp directly).
		s1 := new(big.Int).SetBytes(s1Bytes)
		s2 := new(big.Int).SetBytes(s2Bytes)

		// Reduce scalars modulo Q so they are in [0, Q).
		s1.Mod(s1, mine.Q)
		s2.Mod(s2, mine.Q)

		// Skip if either scalar is zero (point at infinity) or if they are equal
		// (doubling branch) or negatives of each other (gogost add is known-broken).
		if s1.Sign() == 0 || s2.Sign() == 0 {
			t.Skip("zero scalar")
		}
		if s1.Cmp(s2) == 0 {
			t.Skip("s1 == s2 (doubling)")
		}
		negS2 := new(big.Int).Sub(mine.Q, s2)
		if s1.Cmp(negS2) == 0 {
			t.Skip("s1 == -s2 mod Q (gogost add known-broken for p+(-p))")
		}

		// Derive P1 = s1·G and P2 = s2·G via gogost Exp to get on-curve points.
		G := mine.Base()
		refX1, refY1, err := ref.Exp(s1, G.X, G.Y)
		if err != nil {
			t.Skipf("gogost Exp(s1): %v", err)
		}
		refX2, refY2, err := ref.Exp(s2, G.X, G.Y)
		if err != nil {
			t.Skipf("gogost Exp(s2): %v", err)
		}

		P1 := gost3410curves.Point{X: refX1, Y: refY1}
		P2 := gost3410curves.Point{X: refX2, Y: refY2}

		// Clean-room Add(P1, P2).
		cleanResult := mine.Add(P1, P2)

		// Oracle: (s1+s2)·G via gogost Exp.
		s3 := new(big.Int).Add(s1, s2)
		s3.Mod(s3, mine.Q)
		if s3.Sign() == 0 {
			// s1+s2 ≡ 0 mod Q means result is identity.
			if !cleanResult.IsInfinity() {
				t.Fatalf("Add(P1,P2) should be identity when s1+s2≡0 mod Q, got (%x,%x)",
					cleanResult.X, cleanResult.Y)
			}
			return
		}
		oracleX, oracleY, err := ref.Exp(s3, G.X, G.Y)
		if err != nil {
			t.Skipf("gogost Exp(s1+s2): %v", err)
		}

		if cleanResult.IsInfinity() {
			t.Fatalf("clean-room Add returned infinity but oracle returned (%x,%x)", oracleX, oracleY)
		}
		if cleanResult.X.Cmp(oracleX) != 0 || cleanResult.Y.Cmp(oracleY) != 0 {
			t.Fatalf("%s Add(P1,P2) mismatch:\n  mine=(%x,%x)\n  ref =(%x,%x)",
				oidStr, cleanResult.X, cleanResult.Y, oracleX, oracleY)
		}
	})
}

// fixLen slices or zero-extends b to exactly n bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// FuzzScalarMult exercises the clean-room curve point arithmetic (ScalarMult of
// the base point, via PublicKeyRaw) against the gogost oracle byte-for-byte over
// a fuzzer-chosen scalar and a fuzzer-selected standard OID curve. Public-key
// derivation is scalar·Base, so a match proves the point-operation outputs agree
// across all standard param-set curves. The scalar is raw LE, sized to the
// curve's PointSize; a scalar reducing to zero is a genuinely invalid input
// (no public key) and is skipped.
func FuzzScalarMult(f *testing.F) {
	f.Add(0, []byte{
		0x28, 0x3b, 0xec, 0x91, 0x98, 0xce, 0x19, 0x1d, 0xee, 0x7e, 0x39, 0x49,
		0x1f, 0x96, 0x60, 0x1b, 0xc1, 0x72, 0x9a, 0xd3, 0x9d, 0x35, 0xed, 0x10,
		0xbe, 0xb9, 0x9b, 0x78, 0xde, 0x9a, 0x92, 0x7a,
	})
	f.Add(3, bytes.Repeat([]byte{0x42}, 32))
	f.Add(7, bytes.Repeat([]byte{0x11}, 64))

	// CRV-06: boundary-scalar seeds for 256-bit (idx=0, CryptoPro-A) and
	// 512-bit (idx=7, tc26-512-A) curves.
	//
	// CryptoPro-A Q (big-endian):
	//   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
	// Q-1 in LE (bytes 0..31):
	//   92 b8 61 b7 09 1b 84 45 00 d1 5a 99 70 10 61 6c ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
	f.Add(0, []byte{
		0x92, 0xb8, 0x61, 0xb7, 0x09, 0x1b, 0x84, 0x45,
		0x00, 0xd1, 0x5a, 0x99, 0x70, 0x10, 0x61, 0x6c,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})
	// Q+1 for CryptoPro-A in LE (reduces to 2, exercises mod path):
	//   94 b8 61 b7 09 1b 84 45 00 d1 5a 99 70 10 61 6c ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
	f.Add(0, []byte{
		0x94, 0xb8, 0x61, 0xb7, 0x09, 0x1b, 0x84, 0x45,
		0x00, 0xd1, 0x5a, 0x99, 0x70, 0x10, 0x61, 0x6c,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})
	// tc26-512-A Q (big-endian):
	//   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
	//   27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
	// Q-1 in LE (64 bytes):
	//   74 b2 10 1f 41 b1 cd ca 5d b8 d2 fa ab 38 4b 9b 60 60 05 4e 8d 2b f2 6f 11 89 8d f4 32 95 e6 27
	//   ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
	f.Add(7, []byte{
		0x74, 0xb2, 0x10, 0x1f, 0x41, 0xb1, 0xcd, 0xca,
		0x5d, 0xb8, 0xd2, 0xfa, 0xab, 0x38, 0x4b, 0x9b,
		0x60, 0x60, 0x05, 0x4e, 0x8d, 0x2b, 0xf2, 0x6f,
		0x11, 0x89, 0x8d, 0xf4, 0x32, 0x95, 0xe6, 0x27,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})
	// Q+1 for tc26-512-A in LE (reduces to 2, exercises mod path):
	//   76 b2 10 1f 41 b1 cd ca 5d b8 d2 fa ab 38 4b 9b 60 60 05 4e 8d 2b f2 6f 11 89 8d f4 32 95 e6 27
	//   ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
	f.Add(7, []byte{
		0x76, 0xb2, 0x10, 0x1f, 0x41, 0xb1, 0xcd, 0xca,
		0x5d, 0xb8, 0xd2, 0xfa, 0xab, 0x38, 0x4b, 0x9b,
		0x60, 0x60, 0x05, 0x4e, 0x8d, 0x2b, 0xf2, 0x6f,
		0x11, 0x89, 0x8d, 0xf4, 0x32, 0x95, 0xe6, 0x27,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})

	f.Fuzz(func(t *testing.T, sel int, rawPrv []byte) {
		// Pick a standard OID curve deterministically from sel.
		idx := sel % len(allOIDs)
		if idx < 0 {
			idx += len(allOIDs)
		}
		oid := allOIDs[idx].oid

		mine := mustCurve(t, oid)
		ref, err := gost.CurveByOID(oidToASN1(t, oid))
		if err != nil {
			t.Fatalf("gogost CurveByOID(%s): %v", oid, err)
		}

		prv := fixLen(rawPrv, mine.PointSize())

		refPub, err := gost.PublicKeyRawFromPrivate(ref, prv)
		if err != nil {
			// Scalar reduced to zero / invalid private key: genuinely no key.
			// CRV-03: assert the clean-room side also rejects before skipping,
			// so the "gogost errors but clean-room accepts" direction is not
			// silently dropped.
			newPub := gost3410sign.PublicKeyRaw(mine, prv)
			if newPub != nil {
				t.Fatalf("%s: clean-room PublicKeyRaw returned a key where gogost rejected (prv=%x)",
					oid, prv)
			}
			t.Skipf("ref key load failed on %s: %v", oid, err)
		}
		newPub := gost3410sign.PublicKeyRaw(mine, prv)
		if newPub == nil {
			t.Fatalf("%s: clean-room PublicKeyRaw nil where gogost ok (prv=%x)", oid, prv)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("%s: public point mismatch (prv=%x):\n ref  %x\n mine %x",
				oid, prv, refPub, newPub)
		}
	})
}
