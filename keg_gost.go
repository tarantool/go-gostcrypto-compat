package gostcryptocompat

// KEG2012_256 — GOST 2018 key exchange (R 1323565.1.020-2018 §6.4.5.1).
//
// Implements gost_keg for the NID_id_GostR3410_2012_256 case:
//   tmp/engine/gost_ec_keyx.c:132-179 (gost_keg function, lines 156-175).
//
// Algorithm:
//  1. realUKM = reverseBytes(ukmSource[:16])
//     Special case: if ukmSource[:16] == zeros, set realUKM[15] = 1
//     (mirrors gost_keg:140-142 in gost_ec_keyx.c).
//  2. tmpkey = VKO-2012-256(privateKey, serverPublicKey, realUKM).
//  3. expkeys = KDFTree2012_256(tmpkey, "kdf tree", ukmSource[16:24], 64).

import (
	"fmt"

	"go.stargrave.org/gogost/v7/gost3410"
)

// KEG2012_256 derives a 64-byte shared secret using the GOST 2018 KEG
// algorithm on a 256-bit curve.
//
//   - curve: GOST 3410-2012 256-bit curve (e.g. CurveIdtc26gost341012256paramSetA).
//   - serverPubRaw: 64-byte LE-encoded peer public key (LE Y || LE X).
//   - clientPrivRaw: 32-byte LE-encoded local private key.
//   - ukmSource: exactly 32 bytes of UKM material. The first 16 bytes are
//     reversed to form realUKM for VKO; bytes [16:24] serve as the KDF seed.
//
// Returns a [64]byte containing the derived key material, or an error.
func KEG2012_256(curve *Curve, serverPubRaw, clientPrivRaw, ukmSource []byte) ([64]byte, error) {
	var out [64]byte

	if len(ukmSource) != 32 {
		return out, fmt.Errorf("gost.KEG2012_256: ukmSource must be 32 bytes, got %d", len(ukmSource))
	}

	// Step 1: derive realUKM — reverse of ukmSource[:16].
	// If ukmSource[:16] is all zeros, set realUKM[15] = 1 (gost_keg:140-142).
	realUKM := make([]byte, 16)
	allZero := true
	for _, b := range ukmSource[:16] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		realUKM[15] = 1
	} else {
		copy(realUKM, ukmSource[:16])
		reverseInPlace(realUKM)
	}

	// Step 2: VKO 2012-256 shared key.
	prv, err := gost3410.NewPrivateKey(curve.inner, clientPrivRaw)
	if err != nil {
		return out, fmt.Errorf("gost.KEG2012_256: invalid private key: %w", err)
	}
	pub, err := gost3410.NewPublicKey(curve.inner, serverPubRaw)
	if err != nil {
		return out, fmt.Errorf("gost.KEG2012_256: invalid public key: %w", err)
	}
	ukmBig := gost3410.NewUKM(realUKM)
	tmpkey, err := prv.KEK2012256(pub, ukmBig)
	if err != nil {
		return out, fmt.Errorf("gost.KEG2012_256: KEK2012256: %w", err)
	}

	// Step 3: KDFTree2012_256 with label="kdf tree", seed=ukmSource[16:24].
	// Reuses the KDFTree2012_256 helper from kdftree_gost.go.
	expkeys := KDFTree2012_256(tmpkey, []byte("kdf tree"), ukmSource[16:24], 64)
	copy(out[:], expkeys)
	return out, nil
}

// reverseInPlace reverses a byte slice in place.
func reverseInPlace(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
