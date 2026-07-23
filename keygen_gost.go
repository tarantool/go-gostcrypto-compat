package gostcryptocompat

// GenerateEphemeralKey generates a GOST R 34.10-2012 ephemeral key pair on
// the given curve using the provided random source.
//
// Returns:
//   - privRaw: little-endian raw private key (curve.PointSize() bytes).
//   - pubRaw:  little-endian raw public key (LE Y || LE X, 2×curve.PointSize() bytes).
//
// rnd is injectable so tests can pin output deterministically; production
// callers pass crypto/rand.Reader.

import (
	"fmt"
	"io"

	"go.stargrave.org/gogost/v7/gost3410"
)

// GenerateEphemeralKey generates an ephemeral GOST key pair on curve using rnd.
// Returns privRaw (LE, PointSize bytes) and pubRaw (LE Y||X, 2×PointSize bytes).
func GenerateEphemeralKey(curve *Curve, rnd io.Reader) (privRaw, pubRaw []byte, err error) {
	prv, err := gost3410.GenPrivateKey(curve.inner, rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("gost.GenerateEphemeralKey: %w", err)
	}
	pub, err := prv.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("gost.GenerateEphemeralKey: PublicKey: %w", err)
	}
	return prv.Raw(), pub.Raw(), nil
}
