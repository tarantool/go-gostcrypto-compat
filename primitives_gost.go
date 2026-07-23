// Package gostcryptocompat provides thin wrappers over GOST cryptographic
// primitives from go.stargrave.org/gogost/v7.
//
// Every function accepts and returns plain []byte so that callers never need to
// import the upstream module directly.
package gostcryptocompat

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"

	"go.stargrave.org/gogost/v7/gost28147"
	"go.stargrave.org/gogost/v7/gost3410"
	"go.stargrave.org/gogost/v7/gost34112012256"
	"go.stargrave.org/gogost/v7/gost34112012512"
	"go.stargrave.org/gogost/v7/gost341194"
	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
)

// Sentinel errors for the one-shot block helper input validation.
var (
	errKuznyechikInputLen = errors.New("gost: KuznyechikEncrypt/Decrypt: input must be exactly 16 bytes")
	errMagmaInputLen      = errors.New("gost: MagmaEncrypt/Decrypt: input must be exactly 8 bytes")
	errGOST28147InputLen  = errors.New("gost: GOST2814789Encrypt/Decrypt: input must be exactly 8 bytes")
)

// Curve is an opaque handle for a GOST R 34.10 curve. It wraps the gogost
// curve type so callers can pass a curve around without naming gogost. Obtain
// one via CurveByOID or GOST2001TestParamSetCurve.
type Curve struct{ inner *gost3410.Curve }

// Sbox is an opaque handle for a GOST 28147-89 S-box. It wraps the gogost
// S-box type so callers select a wrap / session S-box by identity without
// naming gogost. Use the SboxCryptoProA / SboxTC26Z package variables.
type Sbox struct{ inner *gost28147.Sbox }

// SboxCryptoProA is the GOST 28147-89 CryptoPro-A S-box, the default for
// legacy 2001-era deployments (RFC 4357) and the session-cipher S-box for
// 0x0081 / 0xFF85 record protection.
var SboxCryptoProA = &Sbox{inner: &gost28147.SboxIdGost2814789CryptoProAParamSet}

// SboxTC26Z is the GOST 28147-89 tc26 param-Z S-box, used by gost-engine for
// the CryptoPro key wrap step when the server certificate carries a
// GOST R 34.10-2012 public key.
var SboxTC26Z = &Sbox{inner: &gost28147.SboxIdtc26gost28147paramZ}

// CurveByOID returns the gogost GOST R 34.10 curve for a well-known curve
// parameter OID. Covers the curves Tarantool-EE is observed to issue in
// test fixtures and production: the CryptoPro-A/B/C 256-bit curves and the
// tc26 2012 256-bit and 512-bit parameter sets.
func CurveByOID(oid asn1.ObjectIdentifier) (*Curve, error) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}):
		return &Curve{inner: gost3410.CurveIdGostR34102001CryptoProAParamSet()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}):
		return &Curve{inner: gost3410.CurveIdGostR34102001CryptoProBParamSet()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}):
		return &Curve{inner: gost3410.CurveIdGostR34102001CryptoProCParamSet()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}):
		return &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetA()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}):
		return &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetB()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}):
		return &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetC()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}):
		return &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetD()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}):
		return &Curve{inner: gost3410.CurveIdtc26gost341012512paramSetA()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}):
		return &Curve{inner: gost3410.CurveIdtc26gost341012512paramSetB()}, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}):
		return &Curve{inner: gost3410.CurveIdtc26gost34102012512paramSetC()}, nil
	}
	return nil, fmt.Errorf("gost: unsupported curve OID %v", oid)
}

// ── Kuznyechik (GOST R 34.12-2015, 128-bit) ──────────────────────────────────

// KuznyechikEncrypt encrypts one 16-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 16 bytes.
func KuznyechikEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) != gost3412128.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errKuznyechikInputLen, len(plaintext))
	}

	c := gost3412128.NewCipher(key)
	dst := make([]byte, gost3412128.BlockSize)
	c.Encrypt(dst, plaintext)

	return dst, nil
}

// KuznyechikDecrypt decrypts one 16-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 16 bytes.
func KuznyechikDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != gost3412128.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errKuznyechikInputLen, len(ciphertext))
	}

	c := gost3412128.NewCipher(key)
	dst := make([]byte, gost3412128.BlockSize)
	c.Decrypt(dst, ciphertext)

	return dst, nil
}

// ── Magma (GOST R 34.12-2015, 64-bit) ────────────────────────────────────────

// MagmaEncrypt encrypts one 8-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 8 bytes.
func MagmaEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) != gost341264.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errMagmaInputLen, len(plaintext))
	}

	c := gost341264.NewCipher(key)
	dst := make([]byte, gost341264.BlockSize)
	c.Encrypt(dst, plaintext)

	return dst, nil
}

// MagmaDecrypt decrypts one 8-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 8 bytes.
func MagmaDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != gost341264.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errMagmaInputLen, len(ciphertext))
	}

	c := gost341264.NewCipher(key)
	dst := make([]byte, gost341264.BlockSize)
	c.Decrypt(dst, ciphertext)

	return dst, nil
}

// ── GOST 28147-89 ─────────────────────────────────────────────────────────────

// GOST2814789Encrypt encrypts one 8-byte block with the given 32-byte key using
// the default (CryptoPro-A) S-box. Returns an error if the input is not
// exactly 8 bytes.
func GOST2814789Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) != gost28147.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errGOST28147InputLen, len(plaintext))
	}

	c := gost28147.NewCipher(key, gost28147.SboxDefault)
	dst := make([]byte, gost28147.BlockSize)
	c.Encrypt(dst, plaintext)

	return dst, nil
}

// GOST2814789Decrypt decrypts one 8-byte block with the given 32-byte key using
// the default (CryptoPro-A) S-box. Returns an error if the input is not
// exactly 8 bytes.
func GOST2814789Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != gost28147.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errGOST28147InputLen, len(ciphertext))
	}

	c := gost28147.NewCipher(key, gost28147.SboxDefault)
	dst := make([]byte, gost28147.BlockSize)
	c.Decrypt(dst, ciphertext)

	return dst, nil
}

// ── Streebog (GOST R 34.11-2012) ─────────────────────────────────────────────

// Streebog256 computes the Streebog-256 (GOST R 34.11-2012, 256-bit) hash.
func Streebog256(msg []byte) []byte {
	h := gost34112012256.New()
	h.Write(msg)
	return h.Sum(nil)
}

// Streebog512 computes the Streebog-512 (GOST R 34.11-2012, 512-bit) hash.
func Streebog512(msg []byte) []byte {
	h := gost34112012512.New()
	h.Write(msg)
	return h.Sum(nil)
}

// ── GOST R 34.11-94 hash ──────────────────────────────────────────────────────

// GOSTR341194 computes the GOST R 34.11-94 hash using the CryptoPro parameter set.
func GOSTR341194(msg []byte) []byte {
	h := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	h.Write(msg)
	return h.Sum(nil)
}

// ── GOST R 34.10-2001 signature verify ───────────────────────────────────────

// R342001Verify verifies a GOST R 34.10-2001 signature.
// curve is the 256-bit CryptoPro-A parameter set (id-GostR3410-2001-CryptoPro-A).
// pubRaw is the LE-encoded public key (64 bytes).
// digest is the hash of the message (32 bytes).
// sig is the signature (64 bytes).
// Returns true if the signature is valid.
func R342001Verify(pubRaw, digest, sig []byte) (bool, error) {
	c := gost3410.CurveIdGostR34102001CryptoProAParamSet()
	pub, err := gost3410.NewPublicKey(c, pubRaw)
	if err != nil {
		return false, err
	}
	return pub.VerifyDigest(digest, sig)
}

// ── GOST R 34.10-2012 signature sign + verify ────────────────────────────────

// R341012Sign signs digest with a GOST R 34.10-2012 256-bit private key.
// prvRaw is the LE-encoded private key (32 bytes); uses the 2001 test parameter
// set curve (256-bit).
// Returns the 64-byte signature.
func R341012Sign(prvRaw, digest []byte) ([]byte, error) {
	c := gost3410.CurveIdGostR34102001TestParamSet()
	prv, err := gost3410.NewPrivateKey(c, prvRaw)
	if err != nil {
		return nil, err
	}
	return prv.SignDigest(digest, rand.Reader)
}

// R341012Verify verifies a GOST R 34.10-2012 256-bit signature.
// prvRaw is the LE-encoded private key (32 bytes) — the public key is derived.
// Uses the 2001 test parameter set curve (256-bit).
func R341012Verify(prvRaw, digest, sig []byte) (bool, error) {
	c := gost3410.CurveIdGostR34102001TestParamSet()
	prv, err := gost3410.NewPrivateKey(c, prvRaw)
	if err != nil {
		return false, err
	}
	pub, err := prv.PublicKey()
	if err != nil {
		return false, err
	}
	return pub.VerifyDigest(digest, sig)
}

// ── VKO GOST R 34.10-2001 key agreement ──────────────────────────────────────

// VKO2001 computes the VKO GOST R 34.10-2001 shared KEK (RFC 4357) on the
// id-GostR3410-2001-CryptoPro-A curve. Preserved as the default entry point
// used by unit-vector tests; production TLS callers use VKO2001OnCurve with
// the curve extracted from the server certificate.
func VKO2001(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return VKO2001OnCurve(&Curve{inner: gost3410.CurveIdGostR34102001CryptoProAParamSet()}, prvRaw, pubRaw, ukmRaw)
}

// VKO2001OnCurve is the curve-aware variant of VKO2001. The curve must match
// the server's certificate CurveOID.
func VKO2001OnCurve(curve *Curve, prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	prv, err := gost3410.NewPrivateKey(curve.inner, prvRaw)
	if err != nil {
		return nil, err
	}
	pub, err := gost3410.NewPublicKey(curve.inner, pubRaw)
	if err != nil {
		return nil, err
	}
	ukm := gost3410.NewUKM(ukmRaw)
	return prv.KEK2001(pub, ukm)
}

// VKO2001TestCurve computes VKO GOST R 34.10-2001 shared KEK using the
// test parameter set curve (CurveIdGostR34102001TestParamSet). This is only
// for testing with upstream gogost test vectors; TLS production code uses
// VKO2001 (CryptoPro-A).
func VKO2001TestCurve(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	c := gost3410.CurveIdGostR34102001TestParamSet()
	prv, err := gost3410.NewPrivateKey(c, prvRaw)
	if err != nil {
		return nil, err
	}
	pub, err := gost3410.NewPublicKey(c, pubRaw)
	if err != nil {
		return nil, err
	}
	ukm := gost3410.NewUKM(ukmRaw)
	return prv.KEK2001(pub, ukm)
}

// ── CryptoPro key wrap (RFC 4357 §6.3 + §6.5) ────────────────────────────────

// KeyWrapCryptoPro implements the CryptoPro key wrap algorithm defined in
// RFC 4357 §6.3 (wrap) and §6.5 (diversification). It is used by
// GOST_KEY_TRANSPORT in the TLS 1.2 GOST-CNT suites (RFC 9189 §4.1).
//
// Inputs:
//   - sbox: S-box for the GOST 28147-89 primitive. gost-engine selects
//     SboxTC26Z when the server certificate is GOST R 34.10-2012 and
//     SboxCryptoProA for GOST R 34.10-2001.
//   - kek: 32-byte key exchange key (the VKO-derived shared secret).
//   - ukm: 8-byte user keying material.
//   - sessionKey: 32-byte session key to wrap (the premaster secret).
//
// Returns a 44-byte buffer: [ukm(8) | encryptedSessionKey(32) | MAC(4)].
// The ukm bytes at [0:8] are identical to the input ukm; callers typically
// split the output as wrapped[8:40] (encrypted_key) and wrapped[40:44]
// (imit) when building a GOST_KEY_TRANSPORT structure.
func KeyWrapCryptoPro(sbox *Sbox, kek, ukm, sessionKey []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("gost: KeyWrapCryptoPro KEK must be 32 bytes, got %d", len(kek))
	}
	if len(ukm) != 8 {
		return nil, fmt.Errorf("gost: KeyWrapCryptoPro UKM must be 8 bytes, got %d", len(ukm))
	}
	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("gost: KeyWrapCryptoPro session key must be 32 bytes, got %d", len(sessionKey))
	}

	kekUKM := keyDiversifyCryptoPro(sbox, kek, ukm)

	// Encrypt sessionKey in ECB mode under the diversified key.
	c := gost28147.NewCipher(kekUKM, sbox.inner)
	encrypted := make([]byte, 32)
	for i := 0; i < 32; i += 8 {
		c.Encrypt(encrypted[i:i+8], sessionKey[i:i+8])
	}

	// MAC over sessionKey with iv=ukm, size=4 bytes, using the diversified key.
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		return nil, fmt.Errorf("gost: KeyWrapCryptoPro NewMAC: %w", err)
	}
	if _, err := mac.Write(sessionKey); err != nil {
		return nil, fmt.Errorf("gost: KeyWrapCryptoPro MAC write: %w", err)
	}
	macOut := mac.Sum(nil)

	out := make([]byte, 44)
	copy(out[0:8], ukm)
	copy(out[8:40], encrypted)
	copy(out[40:44], macOut)
	return out, nil
}

// keyDiversifyCryptoPro implements RFC 4357 §6.5 — eight rounds of 28147
// CFB encryption to diversify the KEK by the UKM. Mirrors gost-engine's
// keyDiversifyCryptoPro in gost_keywrap.c.
func keyDiversifyCryptoPro(sbox *Sbox, inputKey, ukm []byte) []byte {
	out := make([]byte, 32)
	copy(out, inputKey)

	for i := range 8 {
		var s1, s2 uint32
		for j := range 8 {
			k := uint32(out[4*j]) | uint32(out[4*j+1])<<8 | uint32(out[4*j+2])<<16 | uint32(out[4*j+3])<<24
			if ukm[i]&(1<<j) != 0 {
				s1 += k
			} else {
				s2 += k
			}
		}
		var S [8]byte
		S[0] = byte(s1)
		S[1] = byte(s1 >> 8)
		S[2] = byte(s1 >> 16)
		S[3] = byte(s1 >> 24)
		S[4] = byte(s2)
		S[5] = byte(s2 >> 8)
		S[6] = byte(s2 >> 16)
		S[7] = byte(s2 >> 24)

		c := gost28147.NewCipher(out, sbox.inner)
		cfb := c.NewCFBEncrypter(S[:])
		cfb.XORKeyStream(out, out)
	}
	return out
}

// ── VKO GOST R 34.10-2012 key agreement ──────────────────────────────────────

// VKO2012_256 computes VKO GOST R 34.10-2012 with 256-bit KEK output (RFC 7836)
// on the id-tc26-gost-3410-2012-512-paramSetA curve. Preserved as the default
// entry point used by unit-vector tests; production TLS callers use
// VKO2012_256OnCurve with the curve extracted from the server certificate.
func VKO2012_256(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return VKO2012_256OnCurve(&Curve{inner: gost3410.CurveIdtc26gost341012512paramSetA()}, prvRaw, pubRaw, ukmRaw)
}

// VKO2012_256OnCurve is the curve-aware variant of VKO2012_256. The curve
// must match the server's certificate CurveOID; callers typically resolve it
// via CurveByOID(cert.CurveOID).
func VKO2012_256OnCurve(curve *Curve, prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	prv, err := gost3410.NewPrivateKey(curve.inner, prvRaw)
	if err != nil {
		return nil, err
	}
	pub, err := gost3410.NewPublicKey(curve.inner, pubRaw)
	if err != nil {
		return nil, err
	}
	ukm := gost3410.NewUKM(ukmRaw)
	return prv.KEK2012256(pub, ukm)
}

// ── GOST 28147-89 CNT mode and IMIT MAC ──────────────────────────────────────

// NewGOST28147_CNT returns a cipher.Stream implementing GOST 28147-89 in CNT
// (counter stream) mode with the CryptoPro-A S-box (SboxDefault = CryptoPro-A,
// per RFC 4357 and OpenSSL gost-engine default).
//
// key must be 32 bytes. iv must be 8 bytes (one GOST block).
//
// The CTR counter increment constants (C1=0x01010104, C2=0x01010101) follow
// RFC 5830 §6.2 and gogost's implementation. Validated end-to-end against
// Tarantool-EE 3.5.0 via TestTarantoolEE_Ping_GOST_Pure (0x0081, 0xFF85).
func NewGOST28147_CNT(key, iv []byte) (*gost28147.CTR, error) {
	if len(key) != gost28147.KeySize {
		return nil, fmt.Errorf("gost: GOST28147_CNT key must be %d bytes, got %d", gost28147.KeySize, len(key))
	}
	if len(iv) != gost28147.BlockSize {
		return nil, fmt.Errorf("gost: GOST28147_CNT iv must be %d bytes, got %d", gost28147.BlockSize, len(iv))
	}
	c := gost28147.NewCipher(key, gost28147.SboxDefault)
	return c.NewCTR(iv), nil
}

// cryptoProKeyMeshingKey is the 32-byte constant used in CryptoPro key meshing
// (RFC 4357 §2.3.2). It is ECB-decrypted with the current key every 1024 bytes
// of MAC input to produce the next round key.
// Source: tmp/engine/gost89.c:240-245.
var cryptoProKeyMeshingKey = [32]byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

// GOST28147_IMIT computes the GOST 28147-89 IMIT MAC over msg using the given
// key and CryptoPro-A S-box with CryptoPro key meshing per RFC 4357 §2.3.2.
// Output is 4 bytes (truncated from 8-byte IMIT per RFC 9189 §4.2).
//
// Key meshing: every 1024 bytes of processed input, the current key is
// ECB-decrypted against cryptoProKeyMeshingKey to produce a new 32-byte key
// (engine reference: tmp/engine/gost_crypt.c:1510-1524 mac_block_mesh).
//
// Final-block handling mirrors engine's gost_imit_final
// (tmp/engine/gost_crypt.c:1559-1580): if no full blocks were processed yet
// but a partial remains, an all-zero 8-byte block is fed first; the partial
// block is then zero-padded and processed as a normal MAC block.
//
// key must be 32 bytes.
//
// The TLS MAC input framing (seq_num || type || version || length || plaintext,
// per RFC 5246 §6.2.3.1) is assembled by the Protector (protection_gost.go),
// not here. Validated end-to-end against Tarantool-EE 3.5.0 via
// TestTarantoolEE_Ping_GOST_Pure.
func GOST28147_IMIT(key, msg []byte) ([]byte, error) {
	if len(key) != gost28147.KeySize {
		return nil, fmt.Errorf("gost: GOST28147_IMIT key must be %d bytes, got %d", gost28147.KeySize, len(key))
	}
	const meshThreshold = 1024
	sbox := gost28147.SboxDefault

	currentKey := make([]byte, gost28147.KeySize)
	copy(currentKey, key)
	prev := make([]byte, gost28147.BlockSize) // zero IV
	c := gost28147.NewCipher(currentKey, sbox)
	mac, err := c.NewMAC(gost28147.BlockSize, prev)
	if err != nil {
		return nil, fmt.Errorf("gost: GOST28147_IMIT NewMAC: %w", err)
	}

	count := 0
	processBlock := func(blk []byte) error {
		if count == meshThreshold {
			// Capture in-flight prev state (buf is empty after a block boundary),
			// mesh the key, then rebuild cipher and MAC preserving prev.
			state := mac.Sum(nil)
			copy(prev, state)
			newKey := make([]byte, gost28147.KeySize)
			for j := range 4 {
				c.Decrypt(newKey[j*gost28147.BlockSize:(j+1)*gost28147.BlockSize],
					cryptoProKeyMeshingKey[j*gost28147.BlockSize:(j+1)*gost28147.BlockSize])
			}
			copy(currentKey, newKey)
			c = gost28147.NewCipher(currentKey, sbox)
			mac, err = c.NewMAC(gost28147.BlockSize, prev)
			if err != nil {
				return fmt.Errorf("gost: GOST28147_IMIT NewMAC after mesh: %w", err)
			}
			count = 0
		}
		if _, werr := mac.Write(blk); werr != nil {
			return fmt.Errorf("gost: GOST28147_IMIT Write: %w", werr)
		}
		count += gost28147.BlockSize
		return nil
	}

	nBlocks := len(msg) / gost28147.BlockSize
	remaining := len(msg) % gost28147.BlockSize

	if len(msg) > 0 && len(msg) <= gost28147.BlockSize {
		// Short-message finalization (gost-engine parity). For inputs of
		// 1..8 bytes no full block precedes the final chunk (count == 0), so
		// gost_imit_final MACs the zero-padded data block FIRST and then a
		// TRAILING all-zero block — including the exactly-8-byte case
		// (gost_crypt.c:1566-1577; one-shot gost_mac gost89.c:716-719).
		// Inputs > 8 bytes never reach here.
		last := make([]byte, gost28147.BlockSize)
		copy(last, msg)
		if err := processBlock(last); err != nil {
			return nil, err
		}
		if err := processBlock(make([]byte, gost28147.BlockSize)); err != nil {
			return nil, err
		}
	} else {
		for i := range nBlocks {
			if err := processBlock(msg[i*gost28147.BlockSize : (i+1)*gost28147.BlockSize]); err != nil {
				return nil, err
			}
		}
		if remaining > 0 {
			last := make([]byte, gost28147.BlockSize)
			copy(last, msg[nBlocks*gost28147.BlockSize:])
			if err := processBlock(last); err != nil {
				return nil, err
			}
		}
	}

	full := mac.Sum(nil)
	return full[:4], nil
}

// VKO2012_512 computes VKO GOST R 34.10-2012 with 512-bit KEK output (RFC 7836).
// prvRaw is the LE-encoded private key (64 bytes for the 512-bit curve).
// pubRaw is the LE-encoded peer public key (128 bytes for the 512-bit curve).
// ukmRaw is the 8-byte user keying material (little-endian).
// Uses the id-tc26-gost-3410-2012-512-paramSetA curve.
func VKO2012_512(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	c := gost3410.CurveIdtc26gost341012512paramSetA()
	prv, err := gost3410.NewPrivateKey(c, prvRaw)
	if err != nil {
		return nil, err
	}
	pub, err := gost3410.NewPublicKey(c, pubRaw)
	if err != nil {
		return nil, err
	}
	ukm := gost3410.NewUKM(ukmRaw)
	return prv.KEK2012512(pub, ukm)
}
