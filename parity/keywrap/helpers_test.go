package keywrapparity

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

const (
	katKEK     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	katUKM     = "0102030405060708"
	katSession = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"

	// TC26-Z leg: full 44-byte wrap and its three sub-fields, all captured
	// from the gost-engine 3.0.3 keyWrapCryptoPro dylib (independent oracle,
	// see keywrap-cryptopro.md:332). katWrapped == katUKM ‖ katCEKENC ‖ katCEKMAC.
	katKEKUKM  = "c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18" // KEK(UKM) for TC26-Z (engine keyDiversifyCryptoPro)
	katCEKENC  = "940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1"
	katCEKMAC  = "e77d8bc3"
	katWrapped = "0102030405060708940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1e77d8bc3"

	// CryptoPro-A leg: full 44-byte wrap on the SAME KAT inputs (katKEK,
	// katUKM, katSession), generated independently from gost-engine 3.0.3
	// (tag v3.0.3, commit e0a500ab) — NOT from the clean-room or facade
	// (that would be circular, see remediation §1 rule 7). The engine's
	// keyWrapCryptoPro was driven via gost_init(&ctx,&Gost28147_CryptoProParamSetA).
	//
	// Reproduce (read-only clone at ../gostcrypto/tmp/engine):
	//
	//	ENGINE=../gostcrypto/tmp/engine
	//	cc -O2 -I"$ENGINE" -I/opt/homebrew/opt/openssl@3/include \
	//	  kat.c "$ENGINE/gost89.c" "$ENGINE/gost_keywrap.c" \
	//	  -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o kat && ./kat
	//
	// where kat.c calls
	//	gost_init(&ctx, &Gost28147_CryptoProParamSetA);
	//	keyWrapCryptoPro(&ctx, kek, ukm, sessionKey, wrapped);
	// on hex-decoded katKEK/katUKM/katSession. The same harness reproduces
	// katWrapped byte-for-byte with Gost28147_TC26ParamSetZ, confirming it.
	katWrappedCryptoProA = "01020304050607083ca0a6a7e806437aef9c45e89774cd74ea922434c8c02aabf39d9878551c263e7103a2d4"
)
