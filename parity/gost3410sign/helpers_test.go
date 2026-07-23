package gost3410signparity

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
	curves "github.com/tarantool/go-gostcrypto/gost3410curves"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// testParamSetCurve builds the RFC 7091 §7.1 id-GostR3410-2001-TestParamSet
// curve from the guide's big-endian hex constants. This parameter set is not
// in the OID table (it is a test-only curve), so it is constructed here.
func testParamSetCurve() *curves.Curve {
	mustInt := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			panic("bad hex: " + s)
		}
		return n
	}
	return &curves.Curve{
		P:    mustInt("8000000000000000000000000000000000000000000000000000000000000431"),
		A:    mustInt("0000000000000000000000000000000000000000000000000000000000000007"),
		B:    mustInt("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		Q:    mustInt("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		X:    mustInt("0000000000000000000000000000000000000000000000000000000000000002"),
		Y:    mustInt("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
		Name: "id-GostR3410-2001-TestParamSet",
	}
}

// stdParamSet512Curve builds the GOST R 34.10-2012 Appendix A.2 test curve
// (512-bit, cofactor 1). This is "id-tc26-gost-3410-2012-512-TestParamSet"
// from the standard's worked example; it is not in the OID registry, so it is
// constructed directly from the standard's constants (matching
// gostcrypto/gost3410sign/gost3410sign_test.go:stdParamSet512Curve).
//
// Source: GOST R 34.10-2012 Appendix A.2.
func stdParamSet512Curve() *curves.Curve {
	mustInt := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			panic("bad hex: " + s)
		}
		return n
	}
	return &curves.Curve{
		P: mustInt("4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D" +
			"F1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373"),
		A: mustInt("0000000000000000000000000000000000000000000000000000000000000007"),
		B: mustInt("1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC43" +
			"61834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC"),
		Q: mustInt("4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D" +
			"A82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF"),
		X: mustInt("24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762" +
			"FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A"),
		Y: mustInt("2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C" +
			"83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E"),
		Name: "id-tc26-gost-3410-2012-512-TestParamSet",
	}
}

// gostRefCurve512Test returns the gogost oracle for the 512-bit GOST R
// 34.10-2012 Appendix A.2 test param set curve. The facade's CurveByOID does
// not cover this test-only curve, so it is accessed directly through the
// gostcryptocompat Tc26-512-A OID-keyed overload via a helper.
//
// We reuse the same OID-keyed facade lookup used by production TLS code, but
// for the Appendix A.2 KAT the curve must match stdParamSet512Curve exactly.
// We therefore obtain it via the facade's CurveByOID with tc26-512-A
// (1.2.643.7.1.2.1.2.1) for the random cross-verify test, but construct it
// directly via gost3410 for the pinned A.2 KAT.
var oidTc26_512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}

// refCurve512A returns the oracle side of the tc26-512-A (OID
// 1.2.643.7.1.2.1.2.1) curve as a facade *Curve for random cross-verify tests.
func refCurve512A(t *testing.T) *gost.Curve {
	t.Helper()
	c, err := gost.CurveByOID(oidTc26_512A)
	if err != nil {
		t.Fatalf("refCurve512A: CurveByOID: %v", err)
	}
	return c
}

// cleanroomCurve512A returns the clean-room side of the tc26-512-A curve.
func cleanroomCurve512A(t *testing.T) *curves.Curve {
	t.Helper()
	c, err := curves.CurveByOID("1.2.643.7.1.2.1.2.1")
	if err != nil {
		t.Fatalf("cleanroomCurve512A: CurveByOID: %v", err)
	}
	return c
}

// q256 is the subgroup order for the 256-bit RFC 7091 test param set curve.
// Used to compute the effective e value (for the e=0→1 substitution guard in
// the fuzz tamper check).
var q256, _ = new(big.Int).SetString(
	"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", 16,
)

// effectiveE256 returns the effective e value used by GOST sign/verify for a
// given digest byte slice on the 256-bit test param set curve (i.e., the e
// that will actually be used in the signing equation). Both impls substitute
// e=1 when the digest reduces to 0 mod q (§6.1 step 2).
func effectiveE256(dig []byte) *big.Int {
	e := new(big.Int).SetBytes(dig)
	e.Mod(e, q256)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

const (
	katPrvLE = "283bec9198ce191dee7e39491f96601bc1729ad39d35ed10beb99b78de9a927a"
	katDigBE = "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5"
	katPubX  = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f"
	katPubY  = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126"
	katNonce = "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3"
	katR     = "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493"
	katS     = "01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40"
	// raw form s||r, big-endian within each half.
	katSigSR = "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40" +
		"41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"

	// Pinned hex from GOST R 34.10-2012 Appendix A.2 (512-bit worked example).
	// The private key is stored little-endian (as the package consumes it); the
	// standard lists it big-endian, so katPrv512LE = reverse(d_BE).
	//
	// Source: GOST R 34.10-2012, Appendix A.2.
	// Copied verbatim from gostcrypto/gost3410sign/gost3410sign_test.go.
	katPrv512LE = "d48da11f826729c6dfaa18fd7b6b63a214277e82d2da223356a000223b12e872" +
		"20108b508e50e70e70694651e8a09130c9d75677d43609a41b24aead8a04a60b"
	katDig512BE = "3754f3cfacc9e0615c4f4a7c4d8dab531b09b6f9c170c533a71d147035b0c591" +
		"7184ee536593f4414339976c647c5d5a407adedb1d560c4fc6777d2972075b8c"
	katNonce512 = "0359e7f4b1410feacc570456c6801496946312120b39d019d455986e364f3658" +
		"86748ed7a44b3e794434006011842286212273a6d14cf70ea3af71bb1ae679f1"
	katR512 = "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd3" +
		"5492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36"
	katS512 = "1081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5" +
		"823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a"
	// raw s||r, big-endian within each 64-byte half.
	katSigSR512 = "1081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5" +
		"823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a" +
		"2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd3" +
		"5492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36"
)
