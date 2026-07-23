package gostcryptocompat

// Tests for KEG2012_256 (R 1323565.1.020-2018 §6.4.5.1).
//
// Engine oracle values (TestKEG2012_256_EngineOracle) were derived using:
//
//	OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
//	  /opt/homebrew/opt/openssl@3/bin/openssl pkeyutl -derive -engine gost \
//	    -inkey privA_tc26.pem -peerkey pubB_tc26.pem \
//	    -pkeyopt ukmhex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
//	    -out keg_AB.bin
//
// Both private keys were generated with:
//
//	OPENSSL_CONF=... openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:TCA
//
// (paramset:TCA = GOST R 34.10-2012 (256 bit) ParamSet A, OID 1.2.643.7.1.2.1.2.1.1,
// which corresponds to gost3410.CurveIdtc26gost341012256paramSetA() in gogost).
//
// Raw key material was extracted from the PKCS#8 OCTET STRING (private key)
// and SubjectPublicKeyInfo BIT STRING OCTET STRING (public key) via asn1parse.
// The engine's SubjectPublicKeyInfo public key OCTET STRING is in LE Y || LE X
// format, which is identical to gogost's pub.Raw() convention.
//
// Symmetry was verified by also deriving with privB + pubA, producing the same 64 bytes.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3410"
)

// TestKEG2012_256_RoundTrip tests the pair-symmetric property of KEG:
// KEG(B_pub, A_priv, ukm) == KEG(A_pub, B_priv, ukm).
// This mirrors the symmetric KEG test in tmp/engine/test_derive.c:338-364.
func TestKEG2012_256_RoundTrip(t *testing.T) {
	curve := &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetA()}

	// Generate key pair A and B from fixed seeds.
	seedA := make([]byte, 32)
	for i := range seedA {
		seedA[i] = byte(0x11 + i)
	}
	seedB := make([]byte, 32)
	for i := range seedB {
		seedB[i] = byte(0x55 + i)
	}

	privARaw, pubARaw, err := GenerateEphemeralKey(curve, bytes.NewReader(seedA))
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	privBRaw, pubBRaw, err := GenerateEphemeralKey(curve, bytes.NewReader(seedB))
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}

	// Fixed 32-byte UKM source.
	ukmSource := make([]byte, 32)
	for i := range ukmSource {
		ukmSource[i] = byte(i)
	}

	resultAB, err := KEG2012_256(curve, pubBRaw, privARaw, ukmSource)
	if err != nil {
		t.Fatalf("KEG(A→B): %v", err)
	}
	resultBA, err := KEG2012_256(curve, pubARaw, privBRaw, ukmSource)
	if err != nil {
		t.Fatalf("KEG(B→A): %v", err)
	}

	if resultAB != resultBA {
		t.Errorf("KEG is not symmetric:\n  A→B: %x\n  B→A: %x",
			resultAB[:], resultBA[:])
	}
}

// TestKEG2012_256_EngineOracle tests KEG output against a value produced by
// gost-engine 3.0.3 via openssl pkeyutl -derive -engine gost.
//
// Key material (GOST R 34.10-2012 256-bit, tc26 paramset A):
//
//	privA raw (LE, from PKCS#8 OCTET STRING):
//	  9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d
//	pubA raw (LE Y||X, from SubjectPublicKeyInfo BIT STRING OCTET STRING):
//	  a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c
//	  6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4
//	privB raw (LE):
//	  bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607
//	pubB raw (LE Y||X):
//	  c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888
//	  8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602
//
// UKM source: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//
// Expected output (64 bytes, both sides verified symmetric by the engine):
//
//	bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900
//	39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b
func TestKEG2012_256_EngineOracle(t *testing.T) {
	curve := &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetA()}

	// Private key A raw (LE, 32 bytes, from PKCS#8 OCTET STRING).
	privARaw, _ := hex.DecodeString(
		"9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d")
	// Public key A raw (LE Y || LE X, 64 bytes, from SubjectPublicKeyInfo BIT STRING OCTET STRING).
	// The engine's encoding matches gogost's pub.Raw() convention directly.
	pubARaw, _ := hex.DecodeString(
		"a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c" +
			"6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4")
	// Private key B raw (LE, 32 bytes).
	privBRaw, _ := hex.DecodeString(
		"bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607")
	// Public key B raw (LE Y || LE X, 64 bytes).
	pubBRaw, _ := hex.DecodeString(
		"c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888" +
			"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602")

	ukmSource, _ := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	// Expected: 64 bytes from engine, both sides verified symmetric.
	expected, _ := hex.DecodeString(
		"bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900" +
			"39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b")

	// Sanity-check: all four keys must parse on the curve.
	if _, err := gost3410.NewPrivateKey(curve.inner, privARaw); err != nil {
		t.Fatalf("privARaw invalid: %v", err)
	}
	if _, err := gost3410.NewPublicKey(curve.inner, pubARaw); err != nil {
		t.Fatalf("pubARaw invalid: %v", err)
	}
	if _, err := gost3410.NewPrivateKey(curve.inner, privBRaw); err != nil {
		t.Fatalf("privBRaw invalid: %v", err)
	}
	if _, err := gost3410.NewPublicKey(curve.inner, pubBRaw); err != nil {
		t.Fatalf("pubBRaw invalid: %v", err)
	}

	// KEG(A_priv, B_pub, ukm) — client side.
	resultAB, err := KEG2012_256(curve, pubBRaw, privARaw, ukmSource)
	if err != nil {
		t.Fatalf("KEG(A_priv, B_pub): %v", err)
	}

	// KEG(B_priv, A_pub, ukm) — server side; must equal resultAB.
	resultBA, err := KEG2012_256(curve, pubARaw, privBRaw, ukmSource)
	if err != nil {
		t.Fatalf("KEG(B_priv, A_pub): %v", err)
	}

	if resultAB != resultBA {
		t.Errorf("KEG not symmetric:\n  A→B: %x\n  B→A: %x", resultAB[:], resultBA[:])
	}

	if !bytes.Equal(resultAB[:], expected) {
		t.Errorf("KEG output does not match engine oracle:\n  got  %x\n  want %x",
			resultAB[:], expected)
	}
}
