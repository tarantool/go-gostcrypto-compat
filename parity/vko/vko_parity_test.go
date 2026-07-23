// Package vkoparity tests the clean-room vko package against the
// gostcryptocompat (gogost-backed) oracle.
//
// Oracle note: the primary oracle path goes through gostcryptocompat →
// gogost gost3410 KEK/KEK2001/KEK2012256/KEK2012512 (independent EC math
// and hashing). For DeriveQLE parity the oracle is gogost's
// PrivateKey.PublicKey().Raw(), imported directly from the vendored package.
package vkoparity

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	gogost3410 "go.stargrave.org/gogost/v7/gost3410"

	gostoracle "github.com/tarantool/go-gostcrypto-compat"
	"github.com/tarantool/go-gostcrypto/gost3410curves"
	"github.com/tarantool/go-gostcrypto/vko"
)

func mustHexF(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// deriveQ derives the LE public point d·P via the clean-room curve math so the
// 2001 KAT (scalars only) can feed both impls the same peer point.
func deriveQ(t *testing.T, c *gost3410curves.Curve, dLE []byte) []byte {
	t.Helper()
	q, err := vko.DeriveQLE(c, dLE)
	if err != nil {
		t.Fatalf("DeriveQLE: %v", err)
	}
	return q
}

// deriveQOracle derives the public point via the gogost oracle, producing
// LE(X)||LE(Y) (same encoding as DeriveQLE) — used to independently verify
// base-point multiplication (VKO-04).
func deriveQOracle(t *testing.T, gogostCurve *gogost3410.Curve, dLE []byte) []byte {
	t.Helper()
	prv, err := gogost3410.NewPrivateKeyLE(gogostCurve, dLE)
	if err != nil {
		t.Fatalf("oracle NewPrivateKeyLE: %v", err)
	}
	pub, err := prv.PublicKey()
	if err != nil {
		t.Fatalf("oracle PublicKey: %v", err)
	}
	return pub.Raw() // RawLE: LE(X)||LE(Y), matches DeriveQLE encoding
}

// oracleCurve2001Test returns the gogost curve matching vko.Curve2001Test()
// (id-GostR3410-2001-TestParamSet). Used for DeriveQLE oracle checks.
func oracleCurve2001Test(t *testing.T) *gogost3410.Curve {
	t.Helper()
	// gogost's id-GostR3410-2001-TestParamSet is the canonical form of the
	// same test-paramset used by vko.Curve2001Test().
	return gogost3410.CurveIdGostR34102001TestParamSet()
}

// oracleCurve512A returns the gogost id-tc26-gost-3410-12-512-paramSetA curve
// for DeriveQLE oracle cross-checks.
func oracleCurve512A() *gogost3410.Curve {
	return gogost3410.CurveIdtc26gost341012512paramSetA()
}

// oracleCurve256A returns the gogost id-tc26-gost-3410-12-256-paramSetA curve
// (cofactor-4, tc26-256-A) for DeriveQLE oracle cross-checks.
func oracleCurve256A() *gogost3410.Curve {
	return gogost3410.CurveIdtc26gost341012256paramSetA()
}

// TestDifferential asserts the clean-room VKO matches the gostcryptocompat oracle
// across all three variants and both agreement directions (D2 symmetry, D4
// X/Y order, D1 LE UKM).
//
// VKO-01: cofactor-4 cases (tc26-256-A) are included, exercising the
// cofactor-multiply and mod-fullOrder-reduction paths in agreementRaw.
// VKO-05: the large-UKM case uses a 32-byte UKM on tc26-256-A so that
// u = UKM*4 can exceed fullOrder = 4*Q, forcing the Mod branch.
func TestDifferential(t *testing.T) {
	c2001 := vko.Curve2001Test()

	d1 := mustHexF(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	d2 := mustHexF(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	ukm2001 := mustHexF(t, "5172be25f852a233")
	Q1 := deriveQ(t, c2001, d1)
	Q2 := deriveQ(t, c2001, d2)

	// Verify DeriveQLE vs oracle for the 2001 curve (VKO-04).
	gc2001 := oracleCurve2001Test(t)
	oQ1 := deriveQOracle(t, gc2001, d1)
	oQ2 := deriveQOracle(t, gc2001, d2)
	if !bytes.Equal(Q1, oQ1) {
		t.Fatalf("DeriveQLE 2001 Q1 mismatch:\n got=%x\n ref=%x", Q1, oQ1)
	}
	if !bytes.Equal(Q2, oQ2) {
		t.Fatalf("DeriveQLE 2001 Q2 mismatch:\n got=%x\n ref=%x", Q2, oQ2)
	}

	dA := mustHexF(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	QA := mustHexF(t, "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"+
		"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"+
		"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"+
		"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	dB := mustHexF(t, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
		"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	QB := mustHexF(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"+
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"+
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	ukm2012 := mustHexF(t, "1d80603c8544c727")

	// Verify DeriveQLE vs oracle for the 512-paramSetA curve (VKO-04).
	gc512A := oracleCurve512A()
	oQA := deriveQOracle(t, gc512A, dA)
	oQB := deriveQOracle(t, gc512A, dB)
	if !bytes.Equal(QA, oQA) {
		t.Fatalf("DeriveQLE 512A QA mismatch:\n got=%x\n ref=%x", QA, oQA)
	}
	if !bytes.Equal(QB, oQB) {
		t.Fatalf("DeriveQLE 512A QB mismatch:\n got=%x\n ref=%x", QB, oQB)
	}

	// VKO-01: cofactor-4 curve (tc26-256-A, OID 1.2.643.7.1.2.1.1.1).
	// Private keys are 32 bytes (PointSize=32 for a 256-bit curve).
	// Source: gostcrypto/vko/cofactor4_test.go (the pin values) plus
	// gostoracle.VKO2012_256OnCurve as the live oracle. The expected KEK is
	// computed at runtime from the oracle — not pinned — so both sides must agree.
	c256A, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.1.1")
	if err != nil {
		t.Fatalf("CurveByOID tc26-256-A: %v", err)
	}
	oidTc26256A := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	oracle256A, err := gostoracle.CurveByOID(oidTc26256A)
	if err != nil {
		t.Fatalf("oracle CurveByOID tc26-256-A: %v", err)
	}

	// 32-byte private scalars for the 256-bit cofactor-4 curve.
	dA256 := bytes.Repeat([]byte{0x11}, 32) // same as cofactor4_test.go
	dB256 := bytes.Repeat([]byte{0x22}, 32)
	ukmCof := []byte{1, 0, 0, 0, 0, 0, 0, 0}

	QA256 := deriveQ(t, c256A, dA256)
	QB256 := deriveQ(t, c256A, dB256)

	// VKO-04: DeriveQLE vs oracle on the cofactor-4 curve.
	gc256A := oracleCurve256A()
	oQA256 := deriveQOracle(t, gc256A, dA256)
	oQB256 := deriveQOracle(t, gc256A, dB256)
	if !bytes.Equal(QA256, oQA256) {
		t.Fatalf("DeriveQLE 256A QA256 mismatch:\n got=%x\n ref=%x", QA256, oQA256)
	}
	if !bytes.Equal(QB256, oQB256) {
		t.Fatalf("DeriveQLE 256A QB256 mismatch:\n got=%x\n ref=%x", QB256, oQB256)
	}

	// VKO-05: large UKM on tc26-256-A to exercise the mod-fullOrder reduction.
	// tc26-256-A has Q ≈ 255 bits; fullOrder = 4*Q ≈ 257 bits. Any UKM >= Q
	// (e.g. a 32-byte value with high bits set) forces u = UKM*4 to exceed
	// fullOrder, making the Mod branch non-trivial. The oracle (gogost) does no
	// reduction but the result is identical by group theory (ord(K1)|fullOrder).
	largeUKM := make([]byte, 32)
	largeUKM[0] = 0x01
	for i := 1; i < 32; i++ {
		largeUKM[i] = 0xff
	}

	type variant int
	const (
		v2001             variant = iota
		v2012256                  // default 512-paramSetA
		v2012512                  // default 512-paramSetA
		v2012256cof4              // tc26-256-A, cofactor-4, small UKM (VKO-01)
		v2012256cof4lgukm         // tc26-256-A, cofactor-4, large UKM (VKO-05)
	)

	clean := func(v variant, prv, peer, ukm []byte) ([]byte, error) {
		switch v {
		case v2001:
			return vko.VKO2001TestCurve(prv, peer, ukm)
		case v2012256:
			return vko.VKO2012_256(prv, peer, ukm)
		case v2012512:
			return vko.VKO2012_512(prv, peer, ukm)
		case v2012256cof4, v2012256cof4lgukm:
			return vko.KEK2012256(c256A, prv, peer, ukm)
		default:
			return nil, nil
		}
	}
	oracle := func(v variant, prv, peer, ukm []byte) ([]byte, error) {
		switch v {
		case v2001:
			return gostoracle.VKO2001TestCurve(prv, peer, ukm)
		case v2012256:
			return gostoracle.VKO2012_256(prv, peer, ukm)
		case v2012512:
			return gostoracle.VKO2012_512(prv, peer, ukm)
		case v2012256cof4, v2012256cof4lgukm:
			return gostoracle.VKO2012_256OnCurve(oracle256A, prv, peer, ukm)
		default:
			return nil, nil
		}
	}

	cases := []struct {
		name      string
		v         variant
		prv, peer []byte
		ukm       []byte
	}{
		{"2001/A", v2001, d1, Q2, ukm2001},
		{"2001/B", v2001, d2, Q1, ukm2001},
		{"2012_256/A", v2012256, dA, QB, ukm2012},
		{"2012_256/B", v2012256, dB, QA, ukm2012},
		{"2012_512/A", v2012512, dA, QB, ukm2012},
		{"2012_512/B", v2012512, dB, QA, ukm2012},
		// VKO-01: cofactor-4 curve with 8-byte UKM (u = UKM*4, no reduction needed).
		{"2012_256/cof4/A", v2012256cof4, dA256, QB256, ukmCof},
		{"2012_256/cof4/B", v2012256cof4, dB256, QA256, ukmCof},
		// VKO-05: large UKM on cofactor-4 curve forces mod-fullOrder reduction in clean-room.
		{"2012_256/cof4/largeUKM/A", v2012256cof4lgukm, dA256, QB256, largeUKM},
		{"2012_256/cof4/largeUKM/B", v2012256cof4lgukm, dB256, QA256, largeUKM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := clean(tc.v, tc.prv, tc.peer, tc.ukm)
			if err != nil {
				t.Fatalf("clean-room: %v", err)
			}
			ref, err := oracle(tc.v, tc.prv, tc.peer, tc.ukm)
			if err != nil {
				t.Fatalf("oracle: %v", err)
			}
			if !bytes.Equal(got, ref) {
				t.Fatalf("KEK mismatch vs oracle:\n got = %x\n ref = %x", got, ref)
			}
		})
	}
}

// norm slices or zero-extends b to n bytes (LE) and forces a non-zero low byte
// so a scalar/UKM is never all-zero (guide D7/D1).
func norm(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	out[0] |= 0x01
	return out
}

// FuzzDifferential: random scalar pair + UKM, dispatching across all three
// VKO variants (v2001 / v2012_256 / v2012_512) via variantByte (VKO-02).
// Asserts:
//   - agreement symmetry (kAB == kBA)
//   - equality against the gostcryptocompat oracle
//   - DeriveQLE parity vs gogost PublicKey.Raw() (VKO-04)
//   - symmetric accept/reject: if clean-room errors, oracle must also error (VKO-03)
func FuzzDifferential(f *testing.F) {
	// seed#0: v2012_256 (variantByte=0, even → v2012_256) on 512-paramSetA.
	f.Add(
		uint8(0), // variantByte → v2012_256
		mustHexFz(f, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
			"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"),
		mustHexFz(f, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
			"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"),
		mustHexFz(f, "1d80603c8544c727"),
	)
	// seed#1: v2001 (variantByte%3==1).
	f.Add(
		uint8(1), // variantByte → v2001
		mustHexFz(f, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928"),
		mustHexFz(f, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473"),
		mustHexFz(f, "5172be25f852a233"),
	)
	// seed#2: v2012_512 (variantByte%3==2).
	f.Add(
		uint8(2), // variantByte → v2012_512
		mustHexFz(f, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
			"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"),
		mustHexFz(f, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
			"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"),
		mustHexFz(f, "1d80603c8544c727"),
	)

	// Pre-resolve curves once outside the fuzz body.
	c512A := vko.Curve2012ParamSetA()
	c2001 := vko.Curve2001Test()
	gc512A := oracleCurve512A()
	gc2001 := gogost3410.CurveIdGostR34102001TestParamSet()
	oidTc26256A := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}

	f.Fuzz(func(t *testing.T, variantByte uint8, rawA, rawB, rawUKM []byte) {
		switch variantByte % 3 {
		case 0: // v2012_256 on default 512-paramSetA
			fuzzVKO2012256(t, c512A, gc512A, rawA, rawB, rawUKM)
		case 1: // v2001 on test curve (256-bit, 32-byte scalars)
			fuzzVKO2001(t, c2001, gc2001, rawA, rawB, rawUKM)
		case 2: // v2012_512 on default 512-paramSetA
			fuzzVKO2012512(t, c512A, gc512A, rawA, rawB, rawUKM)
		}
		_ = oidTc26256A // referenced in TestDifferential; suppress lint
	})
}

// fuzzVKO2012256 runs the VKO2012_256 differential for one fuzz input on
// the provided 512-bit curve. Also checks DeriveQLE vs oracle (VKO-04) and
// enforces symmetric accept/reject (VKO-03).
func fuzzVKO2012256(
	t *testing.T,
	c *gost3410curves.Curve,
	gc *gogost3410.Curve,
	rawA, rawB, rawUKM []byte,
) {
	t.Helper()
	dA := norm(rawA, 64)
	dB := norm(rawB, 64)
	ukm := norm(rawUKM, 8)

	// VKO-04: DeriveQLE parity vs oracle (before using QA/QB for KEK).
	QA, err := vko.DeriveQLE(c, dA)
	if err != nil {
		// VKO-03: clean-room DeriveQLE errors → oracle must also error.
		oprv, oErr := gogost3410.NewPrivateKeyLE(gc, dA)
		if oErr == nil {
			_, oErr = oprv.PublicKey()
		}
		if oErr == nil {
			t.Fatalf("clean-room DeriveQLE(A) failed but oracle accepts dA: %v", err)
		}
		return
	}
	oQA, oErr := func() ([]byte, error) {
		prv, e := gogost3410.NewPrivateKeyLE(gc, dA)
		if e != nil {
			return nil, e
		}
		pub, e := prv.PublicKey()
		if e != nil {
			return nil, e
		}
		return pub.Raw(), nil
	}()
	if oErr != nil {
		t.Fatalf("oracle DeriveQLE(A) failed but clean-room succeeded: %v", oErr)
	}
	if !bytes.Equal(QA, oQA) {
		t.Fatalf("DeriveQLE(A) mismatch:\n got=%x\n ref=%x", QA, oQA)
	}

	QB, err := vko.DeriveQLE(c, dB)
	if err != nil {
		// VKO-03: symmetric.
		oprv, oErr := gogost3410.NewPrivateKeyLE(gc, dB)
		if oErr == nil {
			_, oErr = oprv.PublicKey()
		}
		if oErr == nil {
			t.Fatalf("clean-room DeriveQLE(B) failed but oracle accepts dB: %v", err)
		}
		return
	}
	oQB, oErr := func() ([]byte, error) {
		prv, e := gogost3410.NewPrivateKeyLE(gc, dB)
		if e != nil {
			return nil, e
		}
		pub, e := prv.PublicKey()
		if e != nil {
			return nil, e
		}
		return pub.Raw(), nil
	}()
	if oErr != nil {
		t.Fatalf("oracle DeriveQLE(B) failed but clean-room succeeded: %v", oErr)
	}
	if !bytes.Equal(QB, oQB) {
		t.Fatalf("DeriveQLE(B) mismatch:\n got=%x\n ref=%x", QB, oQB)
	}

	kAB, err := vko.VKO2012_256(dA, QB, ukm)
	if err != nil {
		// VKO-03: clean-room KEK error → oracle must also error.
		if _, oErr := gostoracle.VKO2012_256(dA, QB, ukm); oErr == nil {
			t.Fatalf("clean-room VKO2012_256 failed but oracle succeeded: %v", err)
		}
		return
	}
	kBA, err := vko.VKO2012_256(dB, QA, ukm)
	if err != nil {
		t.Fatalf("asymmetric error: B->A failed but A->B did not: %v", err)
	}
	if !bytes.Equal(kAB, kBA) {
		t.Fatalf("symmetry broken: A->B=%x B->A=%x", kAB, kBA)
	}
	ref, err := gostoracle.VKO2012_256(dA, QB, ukm)
	if err != nil {
		t.Fatalf("oracle error where clean-room succeeded: %v", err)
	}
	if !bytes.Equal(kAB, ref) {
		t.Fatalf("KEK != oracle:\n got=%x\n ref=%x", kAB, ref)
	}
}

// fuzzVKO2001 runs the VKO2001 differential for one fuzz input on the 2001
// test curve (256-bit, 32-byte scalars). Also checks DeriveQLE vs oracle and
// enforces symmetric accept/reject.
func fuzzVKO2001(
	t *testing.T,
	c *gost3410curves.Curve,
	gc *gogost3410.Curve,
	rawA, rawB, rawUKM []byte,
) {
	t.Helper()
	// 256-bit curve: 32-byte scalars, 64-byte public keys.
	dA := norm(rawA, 32)
	dB := norm(rawB, 32)
	ukm := norm(rawUKM, 8)

	// VKO-04: DeriveQLE parity vs oracle.
	QA, err := vko.DeriveQLE(c, dA)
	if err != nil {
		oprv, oErr := gogost3410.NewPrivateKeyLE(gc, dA)
		if oErr == nil {
			_, oErr = oprv.PublicKey()
		}
		if oErr == nil {
			t.Fatalf("clean-room DeriveQLE(2001/A) failed but oracle accepts dA: %v", err)
		}
		return
	}
	oQA, oErr := func() ([]byte, error) {
		prv, e := gogost3410.NewPrivateKeyLE(gc, dA)
		if e != nil {
			return nil, e
		}
		pub, e := prv.PublicKey()
		if e != nil {
			return nil, e
		}
		return pub.Raw(), nil
	}()
	if oErr != nil {
		t.Fatalf("oracle DeriveQLE(2001/A) failed but clean-room succeeded: %v", oErr)
	}
	if !bytes.Equal(QA, oQA) {
		t.Fatalf("DeriveQLE(2001/A) mismatch:\n got=%x\n ref=%x", QA, oQA)
	}

	QB, err := vko.DeriveQLE(c, dB)
	if err != nil {
		oprv, oErr := gogost3410.NewPrivateKeyLE(gc, dB)
		if oErr == nil {
			_, oErr = oprv.PublicKey()
		}
		if oErr == nil {
			t.Fatalf("clean-room DeriveQLE(2001/B) failed but oracle accepts dB: %v", err)
		}
		return
	}
	oQB, oErr := func() ([]byte, error) {
		prv, e := gogost3410.NewPrivateKeyLE(gc, dB)
		if e != nil {
			return nil, e
		}
		pub, e := prv.PublicKey()
		if e != nil {
			return nil, e
		}
		return pub.Raw(), nil
	}()
	if oErr != nil {
		t.Fatalf("oracle DeriveQLE(2001/B) failed but clean-room succeeded: %v", oErr)
	}
	if !bytes.Equal(QB, oQB) {
		t.Fatalf("DeriveQLE(2001/B) mismatch:\n got=%x\n ref=%x", QB, oQB)
	}

	kAB, err := vko.VKO2001TestCurve(dA, QB, ukm)
	if err != nil {
		if _, oErr := gostoracle.VKO2001TestCurve(dA, QB, ukm); oErr == nil {
			t.Fatalf("clean-room VKO2001 failed but oracle succeeded: %v", err)
		}
		return
	}
	kBA, err := vko.VKO2001TestCurve(dB, QA, ukm)
	if err != nil {
		t.Fatalf("VKO2001: asymmetric error B->A: %v", err)
	}
	if !bytes.Equal(kAB, kBA) {
		t.Fatalf("VKO2001 symmetry broken: A->B=%x B->A=%x", kAB, kBA)
	}
	ref, err := gostoracle.VKO2001TestCurve(dA, QB, ukm)
	if err != nil {
		t.Fatalf("VKO2001 oracle error where clean-room succeeded: %v", err)
	}
	if !bytes.Equal(kAB, ref) {
		t.Fatalf("VKO2001 KEK != oracle:\n got=%x\n ref=%x", kAB, ref)
	}
}

// fuzzVKO2012512 runs the VKO2012_512 differential for one fuzz input on the
// 512-paramSetA curve. Also checks DeriveQLE vs oracle and symmetric accept/reject.
func fuzzVKO2012512(
	t *testing.T,
	c *gost3410curves.Curve,
	gc *gogost3410.Curve,
	rawA, rawB, rawUKM []byte,
) {
	t.Helper()
	dA := norm(rawA, 64)
	dB := norm(rawB, 64)
	ukm := norm(rawUKM, 8)

	// VKO-04: DeriveQLE parity vs oracle.
	QA, err := vko.DeriveQLE(c, dA)
	if err != nil {
		oprv, oErr := gogost3410.NewPrivateKeyLE(gc, dA)
		if oErr == nil {
			_, oErr = oprv.PublicKey()
		}
		if oErr == nil {
			t.Fatalf("clean-room DeriveQLE(512/A) failed but oracle accepts dA: %v", err)
		}
		return
	}
	oQA, oErr := func() ([]byte, error) {
		prv, e := gogost3410.NewPrivateKeyLE(gc, dA)
		if e != nil {
			return nil, e
		}
		pub, e := prv.PublicKey()
		if e != nil {
			return nil, e
		}
		return pub.Raw(), nil
	}()
	if oErr != nil {
		t.Fatalf("oracle DeriveQLE(512/A) failed but clean-room succeeded: %v", oErr)
	}
	if !bytes.Equal(QA, oQA) {
		t.Fatalf("DeriveQLE(512/A) mismatch:\n got=%x\n ref=%x", QA, oQA)
	}

	QB, err := vko.DeriveQLE(c, dB)
	if err != nil {
		oprv, oErr := gogost3410.NewPrivateKeyLE(gc, dB)
		if oErr == nil {
			_, oErr = oprv.PublicKey()
		}
		if oErr == nil {
			t.Fatalf("clean-room DeriveQLE(512/B) failed but oracle accepts dB: %v", err)
		}
		return
	}
	oQB, oErr := func() ([]byte, error) {
		prv, e := gogost3410.NewPrivateKeyLE(gc, dB)
		if e != nil {
			return nil, e
		}
		pub, e := prv.PublicKey()
		if e != nil {
			return nil, e
		}
		return pub.Raw(), nil
	}()
	if oErr != nil {
		t.Fatalf("oracle DeriveQLE(512/B) failed but clean-room succeeded: %v", oErr)
	}
	if !bytes.Equal(QB, oQB) {
		t.Fatalf("DeriveQLE(512/B) mismatch:\n got=%x\n ref=%x", QB, oQB)
	}

	kAB, err := vko.VKO2012_512(dA, QB, ukm)
	if err != nil {
		if _, oErr := gostoracle.VKO2012_512(dA, QB, ukm); oErr == nil {
			t.Fatalf("clean-room VKO2012_512 failed but oracle succeeded: %v", err)
		}
		return
	}
	kBA, err := vko.VKO2012_512(dB, QA, ukm)
	if err != nil {
		t.Fatalf("VKO2012_512: asymmetric error B->A: %v", err)
	}
	if !bytes.Equal(kAB, kBA) {
		t.Fatalf("VKO2012_512 symmetry broken: A->B=%x B->A=%x", kAB, kBA)
	}
	ref, err := gostoracle.VKO2012_512(dA, QB, ukm)
	if err != nil {
		t.Fatalf("VKO2012_512 oracle error where clean-room succeeded: %v", err)
	}
	if !bytes.Equal(kAB, ref) {
		t.Fatalf("VKO2012_512 KEK != oracle:\n got=%x\n ref=%x", kAB, ref)
	}
}

func mustHexFz(f *testing.F, s string) []byte {
	f.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
