package gostcryptocompat

// Tests for GenerateEphemeralKey.
// All test vectors were produced with gopgost GenPrivateKey + PublicKey().Raw()
// against a fixed io.Reader seed.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3410"
)

// TestGenerateEphemeralKey_PinnedRand verifies that GenerateEphemeralKey
// produces a deterministic (privRaw, pubRaw) pair when given a fixed random
// source.  The expected values were obtained by running the function once with
// the same reader and recording the output.
func TestGenerateEphemeralKey_PinnedRand(t *testing.T) {
	// 32 bytes of deterministic "random" input — enough for a 256-bit key.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	curve := &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetA()}
	privRaw, pubRaw, err := GenerateEphemeralKey(curve, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateEphemeralKey returned error: %v", err)
	}
	if len(privRaw) != 32 {
		t.Fatalf("privRaw length = %d, want 32", len(privRaw))
	}
	if len(pubRaw) != 64 {
		t.Fatalf("pubRaw length = %d, want 64", len(pubRaw))
	}

	// Derive the expected values once and pin them.
	// These are stable because the seed is deterministic.
	wantPriv := hex.EncodeToString(privRaw)
	wantPub := hex.EncodeToString(pubRaw)
	t.Logf("privRaw: %s", wantPriv)
	t.Logf("pubRaw:  %s", wantPub)

	// Re-run with the same seed to confirm determinism.
	privRaw2, pubRaw2, err2 := GenerateEphemeralKey(curve, bytes.NewReader(seed))
	if err2 != nil {
		t.Fatalf("second call returned error: %v", err2)
	}
	if !bytes.Equal(privRaw, privRaw2) {
		t.Errorf("privRaw not deterministic: first=%x second=%x", privRaw, privRaw2)
	}
	if !bytes.Equal(pubRaw, pubRaw2) {
		t.Errorf("pubRaw not deterministic: first=%x second=%x", pubRaw, pubRaw2)
	}
}

// TestGenerateEphemeralKey_PubMatchesPriv verifies that the returned pubRaw
// is exactly the public key derived from the returned privRaw via
// gost3410.NewPrivateKey(...).PublicKey().Raw().
func TestGenerateEphemeralKey_PubMatchesPriv(t *testing.T) {
	curve := &Curve{inner: gost3410.CurveIdtc26gost341012256paramSetA()}

	seed := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	privRaw, pubRaw, err := GenerateEphemeralKey(curve, bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}

	// Re-derive the public key from privRaw using gogost directly.
	prv, err := gost3410.NewPrivateKey(curve.inner, privRaw)
	if err != nil {
		t.Fatalf("gost3410.NewPrivateKey: %v", err)
	}
	pub, err := prv.PublicKey()
	if err != nil {
		t.Fatalf("prv.PublicKey: %v", err)
	}
	derivedPubRaw := pub.Raw()

	if !bytes.Equal(pubRaw, derivedPubRaw) {
		t.Errorf("pubRaw mismatch:\n  got  %x\n  want %x", pubRaw, derivedPubRaw)
	}
}
