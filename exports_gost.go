package gostcryptocompat

// exports_gost.go is the gogost containment boundary. Every gogost type that
// would otherwise appear in a caller's signature is wrapped here so that
// consumers import only this package, never go.stargrave.org/gogost/v7
// directly. Swapping the GOST backend then becomes an edit confined to this
// package.

import (
	"crypto/cipher"
	"hash"
	"io"

	"go.stargrave.org/gogost/v7/gost28147"
	"go.stargrave.org/gogost/v7/gost3410"
	"go.stargrave.org/gogost/v7/gost34112012256"
	"go.stargrave.org/gogost/v7/gost34112012512"
	"go.stargrave.org/gogost/v7/gost341194"
	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
)

// Block-cipher dimensions, re-exported so callers size buffers without naming
// the gogost packages.
const (
	GOST28147BlockSize  = gost28147.BlockSize   // 8
	GOST28147KeySize    = gost28147.KeySize     // 32
	KuznyechikBlockSize = gost3412128.BlockSize // 16
	MagmaBlockSize      = gost341264.BlockSize  // 8
)

// ── Hash factories (return hash.Hash, never a gogost type) ───────────────────

// NewStreebog256Hash returns a fresh Streebog-256 (GOST R 34.11-2012) hash.
func NewStreebog256Hash() hash.Hash { return gost34112012256.New() }

// NewStreebog512Hash returns a fresh Streebog-512 (GOST R 34.11-2012) hash.
func NewStreebog512Hash() hash.Hash { return gost34112012512.New() }

// NewGOSTR341194CryptoProHash returns a fresh GOST R 34.11-94 hash using the
// CryptoPro parameter-set S-box.
func NewGOSTR341194CryptoProHash() hash.Hash {
	return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
}

// NewGOST28147IMITPlaceholderHash returns a GOST 28147-89 IMIT hash.Hash
// instantiated with an all-zero key and IV. It exists solely to satisfy the
// suite registry's MACSpec.Hash metadata field (consulted for KeyLen / MACLen
// reporting); the real record-layer MAC is computed by the protector with the
// session key, not this instance.
func NewGOST28147IMITPlaceholderHash() hash.Hash {
	key := make([]byte, GOST28147KeySize)
	c := gost28147.NewCipher(key, gost28147.SboxDefault)
	iv := make([]byte, GOST28147BlockSize)
	mac, err := c.NewMAC(4, iv)
	if err != nil {
		// NewMAC only fails on invalid size or IV length; both are hardcoded here.
		panic("gost.NewGOST28147IMITPlaceholderHash: " + err.Error())
	}
	return mac
}

// ── Block ciphers (return crypto/cipher.Block, never a gogost type) ──────────

// NewKuznyechikCipher returns a Kuznyechik (GOST R 34.12-2015, 128-bit) block
// cipher for the given 32-byte key.
func NewKuznyechikCipher(key []byte) cipher.Block { return gost3412128.NewCipher(key) }

// NewMagmaCipher returns a Magma (GOST R 34.12-2015, 64-bit) block cipher for
// the given 32-byte key.
func NewMagmaCipher(key []byte) cipher.Block { return gost341264.NewCipher(key) }

// ── GOST 28147-89 block cipher (opaque handle for the CNT/IMIT protector) ────

// GOST28147Cipher is an opaque GOST 28147-89 block cipher. It exposes the
// single-block primitives the record-layer CNT mode and IMIT MAC need, so a
// record layer can reimplement those modes without naming gogost. The 8-byte
// block / 32-byte key dimensions are GOST28147BlockSize / KeySize.
type GOST28147Cipher struct{ inner *gost28147.Cipher }

// NewGOST28147Cipher builds a GOST 28147-89 cipher from a 32-byte key and the
// given S-box.
func NewGOST28147Cipher(key []byte, sbox *Sbox) *GOST28147Cipher {
	return &GOST28147Cipher{inner: gost28147.NewCipher(key, sbox.inner)}
}

// Encrypt encrypts one 8-byte block (32-round schedule) from src into dst.
func (c *GOST28147Cipher) Encrypt(dst, src []byte) { c.inner.Encrypt(dst, src) }

// Decrypt decrypts one 8-byte block (32-round schedule) from src into dst.
func (c *GOST28147Cipher) Decrypt(dst, src []byte) { c.inner.Decrypt(dst, src) }

// SeqMACBlock runs the 16-round SeqMAC encryption of a single 8-byte block
// with a zero IV — the per-block step of the GOST 28147-89 IMIT MAC. The
// 16-round schedule differs from Encrypt's 32 rounds and is not otherwise
// reachable through the cipher API. block must be 8 bytes; returns 8 bytes.
func (c *GOST28147Cipher) SeqMACBlock(block []byte) []byte {
	zeroIV := make([]byte, GOST28147BlockSize)
	mac, _ := c.inner.NewMAC(GOST28147BlockSize, zeroIV)
	mac.Write(block)
	return mac.Sum(nil)
}

// ── GOST R 34.10 signature verify on an explicit curve ───────────────────────

// VerifyDigestOnCurve verifies a GOST R 34.10 signature over digest using the
// public key pubRaw on the given curve. pubRaw is the LE-encoded public key;
// sig is the raw signature. Used for certificate-chain verification, where the
// curve is resolved from the certificate's parameter OID.
func VerifyDigestOnCurve(curve *Curve, pubRaw, digest, sig []byte) (bool, error) {
	pub, err := gost3410.NewPublicKey(curve.inner, pubRaw)
	if err != nil {
		return false, err
	}
	return pub.VerifyDigest(digest, sig)
}

// Name returns the underlying curve's parameter-set name (e.g. for diagnostics
// and test assertions).
func (c *Curve) Name() string { return c.inner.Name }

// PointSize returns the curve's coordinate size in bytes (32 for 256-bit
// curves, 64 for 512-bit).
func (c *Curve) PointSize() int { return c.inner.PointSize() }

// PublicKeyRawFromPrivate derives the LE-encoded public key from prvRaw on the
// given curve.
func PublicKeyRawFromPrivate(curve *Curve, prvRaw []byte) ([]byte, error) {
	prv, err := gost3410.NewPrivateKey(curve.inner, prvRaw)
	if err != nil {
		return nil, err
	}
	pub, err := prv.PublicKey()
	if err != nil {
		return nil, err
	}
	return pub.Raw(), nil
}

// SignDigestOnCurve signs digest with the GOST R 34.10 private key prvRaw on
// the given curve, returning the raw signature. The counterpart to
// VerifyDigestOnCurve; rnd supplies the per-signature nonce.
func SignDigestOnCurve(curve *Curve, prvRaw, digest []byte, rnd io.Reader) ([]byte, error) {
	prv, err := gost3410.NewPrivateKey(curve.inner, prvRaw)
	if err != nil {
		return nil, err
	}
	return prv.SignDigest(digest, rnd)
}

// ── GOST R 34.10-2001 test-parameter-set helpers (test-vector support) ───────

// GOST2001TestParamSetCurve returns the GOST R 34.10-2001 test parameter set
// curve. It is used only by round-trip tests against upstream vectors; TLS
// production code resolves curves from the certificate via CurveByOID.
func GOST2001TestParamSetCurve() *Curve {
	return &Curve{inner: gost3410.CurveIdGostR34102001TestParamSet()}
}

// GOST2001CryptoProAParamSetCurve returns the GOST R 34.10-2001 CryptoPro-A
// parameter set curve (id-GostR3410-2001-CryptoPro-A-ParamSet, the 256-bit
// curve Tarantool-EE fixtures commonly use). Convenience accessor equivalent
// to CurveByOID(1.2.643.2.2.35.1).
func GOST2001CryptoProAParamSetCurve() *Curve {
	return &Curve{inner: gost3410.CurveIdGostR34102001CryptoProAParamSet()}
}

// PublicKeyRawFromPrivate2001Test derives the LE-encoded GOST R 34.10-2001
// public key from prvRaw on the test parameter set curve.
func PublicKeyRawFromPrivate2001Test(prvRaw []byte) ([]byte, error) {
	c := gost3410.CurveIdGostR34102001TestParamSet()
	prv, err := gost3410.NewPrivateKey(c, prvRaw)
	if err != nil {
		return nil, err
	}
	pub, err := prv.PublicKey()
	if err != nil {
		return nil, err
	}
	return pub.Raw(), nil
}
