package gostcryptocompat

import (
	"bytes"
	"math/big"
	"testing"

	"go.stargrave.org/gogost/v7/gost3410"
)

func deterministicPrivateKey(t *testing.T, curve *gost3410.Curve, seed byte) *gost3410.PrivateKey {
	t.Helper()
	raw := make([]byte, curve.PointSize())
	for i := range raw {
		raw[i] = seed + byte(i+1)
	}
	prv, err := gost3410.NewPrivateKey(curve, raw)
	if err != nil {
		t.Fatalf("NewPrivateKey(%s): %v", curve.Name, err)
	}
	return prv
}

// TestCurveSignVerify_AllCurves ports the intent of tmp/engine/test_sign.c:
// every supported signing curve should successfully sign and verify, and a
// tampered digest must fail verification.
func TestCurveSignVerify_AllCurves(t *testing.T) {
	cases := []struct {
		name    string
		curve   func() *gost3410.Curve
		digestN int
	}{
		{"GOST2001-CryptoPro-A", gost3410.CurveIdGostR34102001CryptoProAParamSet, 32},
		{"GOST2001-CryptoPro-B", gost3410.CurveIdGostR34102001CryptoProBParamSet, 32},
		{"GOST2001-CryptoPro-C", gost3410.CurveIdGostR34102001CryptoProCParamSet, 32},
		{"GOST2012-256-TC26-A", gost3410.CurveIdtc26gost341012256paramSetA, 32},
		{"GOST2012-256-TC26-B", gost3410.CurveIdtc26gost341012256paramSetB, 32},
		{"GOST2012-256-TC26-C", gost3410.CurveIdtc26gost341012256paramSetC, 32},
		{"GOST2012-256-TC26-D", gost3410.CurveIdtc26gost341012256paramSetD, 32},
		{"GOST2012-512-TC26-A", gost3410.CurveIdtc26gost341012512paramSetA, 64},
		{"GOST2012-512-TC26-B", gost3410.CurveIdtc26gost341012512paramSetB, 64},
		{"GOST2012-512-TC26-C", gost3410.CurveIdtc26gost341012512paramSetC, 64},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			curve := tc.curve()
			prv := deterministicPrivateKey(t, curve, byte(0x10+i))
			pub, err := prv.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey(%s): %v", curve.Name, err)
			}

			digest := make([]byte, tc.digestN)
			for i := range digest {
				digest[i] = byte(0x80 + i)
			}
			rnd := bytes.NewReader(bytes.Repeat([]byte{byte(0x30 + i + 1)}, curve.PointSize()*4))
			sig, err := prv.SignDigest(digest, rnd)
			if err != nil {
				t.Fatalf("SignDigest(%s): %v", curve.Name, err)
			}
			if len(sig) != 2*curve.PointSize() {
				t.Fatalf("signature len(%s)=%d, want %d", curve.Name, len(sig), 2*curve.PointSize())
			}

			ok, err := pub.VerifyDigest(digest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest(%s): %v", curve.Name, err)
			}
			if !ok {
				t.Fatalf("VerifyDigest(%s): signature rejected", curve.Name)
			}

			tamperedDigest := append([]byte(nil), digest...)
			tamperedDigest[len(tamperedDigest)-1] ^= 0x01
			ok, err = pub.VerifyDigest(tamperedDigest, sig)
			if err != nil {
				t.Fatalf("VerifyDigest tampered digest(%s): %v", curve.Name, err)
			}
			if ok {
				t.Fatalf("VerifyDigest(%s): tampered digest unexpectedly accepted", curve.Name)
			}
		})
	}
}

// TestCurveByOID_SupportedCurvesSanity checks the supported OID mappings and
// basic group invariants we rely on throughout the repo.
func TestCurveByOID_SupportedCurvesSanity(t *testing.T) {
	cases := []struct {
		name      string
		oid       []int
		curve     func() *gost3410.Curve
		pointSize int
	}{
		{"CryptoPro-A", []int{1, 2, 643, 2, 2, 35, 1}, gost3410.CurveIdGostR34102001CryptoProAParamSet, 32},
		{"CryptoPro-B", []int{1, 2, 643, 2, 2, 35, 2}, gost3410.CurveIdGostR34102001CryptoProBParamSet, 32},
		{"CryptoPro-C", []int{1, 2, 643, 2, 2, 35, 3}, gost3410.CurveIdGostR34102001CryptoProCParamSet, 32},
		{"TC26-256-A", []int{1, 2, 643, 7, 1, 2, 1, 1, 1}, gost3410.CurveIdtc26gost341012256paramSetA, 32},
		{"TC26-256-B", []int{1, 2, 643, 7, 1, 2, 1, 1, 2}, gost3410.CurveIdtc26gost341012256paramSetB, 32},
		{"TC26-256-C", []int{1, 2, 643, 7, 1, 2, 1, 1, 3}, gost3410.CurveIdtc26gost341012256paramSetC, 32},
		{"TC26-256-D", []int{1, 2, 643, 7, 1, 2, 1, 1, 4}, gost3410.CurveIdtc26gost341012256paramSetD, 32},
		{"TC26-512-A", []int{1, 2, 643, 7, 1, 2, 1, 2, 1}, gost3410.CurveIdtc26gost341012512paramSetA, 64},
		{"TC26-512-B", []int{1, 2, 643, 7, 1, 2, 1, 2, 2}, gost3410.CurveIdtc26gost341012512paramSetB, 64},
		{"TC26-512-C", []int{1, 2, 643, 7, 1, 2, 1, 2, 3}, gost3410.CurveIdtc26gost341012512paramSetC, 64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CurveByOID(tc.oid)
			if err != nil {
				t.Fatalf("CurveByOID(%v): %v", tc.oid, err)
			}
			want := tc.curve()
			if !got.inner.Equal(want) {
				t.Fatalf("CurveByOID(%v) returned unexpected curve:\n got  %s\n want %s", tc.oid, got.inner.Name, want.Name)
			}
			if got.inner.Name == "" {
				t.Fatal("curve Name is empty")
			}
			if got.PointSize() != tc.pointSize {
				t.Fatalf("PointSize(%s)=%d, want %d", got.inner.Name, got.PointSize(), tc.pointSize)
			}
			if !got.inner.Contains(got.inner.X, got.inner.Y) {
				t.Fatalf("generator for %s is not on curve", got.inner.Name)
			}
			if got.inner.Co.Cmp(big.NewInt(1)) != 0 && got.inner.Co.Cmp(big.NewInt(4)) != 0 {
				t.Fatalf("unexpected cofactor for %s: %s", got.inner.Name, got.inner.Co.String())
			}

			gc := got.inner
			qPlus1 := new(big.Int).Add(gc.Q, big.NewInt(1))
			x1, y1, err := gc.Exp(qPlus1, gc.X, gc.Y)
			if err != nil {
				t.Fatalf("Exp(Q+1, G) for %s: %v", gc.Name, err)
			}
			if x1.Cmp(gc.X) != 0 || y1.Cmp(gc.Y) != 0 {
				t.Fatalf("generator order invariant failed for %s", gc.Name)
			}

			qPlus3 := new(big.Int).Add(gc.Q, big.NewInt(3))
			x3a, y3a, err := gc.Exp(big.NewInt(3), gc.X, gc.Y)
			if err != nil {
				t.Fatalf("Exp(3, G) for %s: %v", gc.Name, err)
			}
			x3b, y3b, err := gc.Exp(qPlus3, gc.X, gc.Y)
			if err != nil {
				t.Fatalf("Exp(Q+3, G) for %s: %v", gc.Name, err)
			}
			if x3a.Cmp(x3b) != 0 || y3a.Cmp(y3b) != 0 {
				t.Fatalf("cyclic subgroup invariant failed for %s", gc.Name)
			}
		})
	}

	t.Run("UnknownOID", func(t *testing.T) {
		if _, err := CurveByOID([]int{1, 2, 3, 4, 5}); err == nil {
			t.Fatal("CurveByOID accepted unknown OID")
		}
	})
}
