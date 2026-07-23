package gostcryptocompat

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
)

// TestOMAC_Kuznyechik_KAT verifies the Kuznyechik OMAC/CMAC vector from
// GOST R 34.13-2015 A.1.6.
//
// Vector source: tmp/engine/test_digest.c:71-104
//
//	K (32 bytes):   8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
//	P (64 bytes):   1122334455667700ffeeddccbbaa9988...
//	MAC_omac (8 b): 336f4d296059fbe3
//
// The standard produces a 16-byte CMAC; only the leading 8 bytes match the
// published 8-byte truncated tag (tmp/engine/test_digest.c:104).
func TestOMAC_Kuznyechik_KAT(t *testing.T) {
	// Key K — tmp/engine/test_digest.c:71-74
	key, err := hex.DecodeString(
		"8899aabbccddeeff0011223344556677" +
			"fedcba98765432100123456789abcdef",
	)
	if err != nil {
		t.Fatalf("hex key: %v", err)
	}

	// Plaintext P — tmp/engine/test_digest.c:88-93
	pt, err := hex.DecodeString(
		"1122334455667700ffeeddccbbaa9988" +
			"00112233445566778899aabbcceeff0a" +
			"112233445566778899aabbcceeff0a00" +
			"2233445566778899aabbcceeff0a0011",
	)
	if err != nil {
		t.Fatalf("hex pt: %v", err)
	}

	// Expected 8-byte truncated MAC — tmp/engine/test_digest.c:104
	wantHex := "336f4d296059fbe3"
	want, _ := hex.DecodeString(wantHex)

	block := gost3412128.NewCipher(key)
	mac, err := NewOMAC(block, 8)
	if err != nil {
		t.Fatalf("NewOMAC: %v", err)
	}

	if _, err := mac.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := mac.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("Kuznyechik OMAC: got %x, want %x", got, want)
	}
}

// TestOMAC_Magma_KAT verifies the Magma OMAC/CMAC vector from
// GOST R 34.13-2015 A.2.6.
//
// Vector source: tmp/engine/test_digest.c:79-109
//
//	Km (32 bytes):  ffeeddccbbaa998877665544332211 00f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
//	Pm (32 bytes):  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
//	MAC_magma_omac (4 b): 154e7210
//
// The standard produces an 8-byte CMAC; only the leading 4 bytes match the
// published 4-byte truncated tag (tmp/engine/test_digest.c:109).
func TestOMAC_Magma_KAT(t *testing.T) {
	// Key Km — tmp/engine/test_digest.c:79-82
	key, err := hex.DecodeString(
		"ffeeddccbbaa99887766554433221100" +
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	)
	if err != nil {
		t.Fatalf("hex key: %v", err)
	}

	// Plaintext Pm — tmp/engine/test_digest.c:96-99
	pt, err := hex.DecodeString(
		"92def06b3c130a59db54c704f8189d20" +
			"4a98fb2e67a8024c8912409b17b57e41",
	)
	if err != nil {
		t.Fatalf("hex pt: %v", err)
	}

	// Expected 4-byte truncated MAC — tmp/engine/test_digest.c:109
	want, _ := hex.DecodeString("154e7210")

	block := gost341264.NewCipher(key)
	mac, err := NewOMAC(block, 4)
	if err != nil {
		t.Fatalf("NewOMAC: %v", err)
	}

	if _, err := mac.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := mac.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("Magma OMAC: got %x, want %x", got, want)
	}
}

// TestOMAC_SumIdempotent verifies that two consecutive Sum calls on the same
// OMAC state (without any intervening Writes) return identical bytes.
// Uses the Kuznyechik KAT vector as input.
func TestOMAC_SumIdempotent(t *testing.T) {
	key, _ := hex.DecodeString(
		"8899aabbccddeeff0011223344556677" +
			"fedcba98765432100123456789abcdef",
	)
	pt, _ := hex.DecodeString(
		"1122334455667700ffeeddccbbaa9988" +
			"00112233445566778899aabbcceeff0a" +
			"112233445566778899aabbcceeff0a00" +
			"2233445566778899aabbcceeff0a0011",
	)

	block := gost3412128.NewCipher(key)
	mac, err := NewOMAC(block, 8)
	if err != nil {
		t.Fatalf("NewOMAC: %v", err)
	}
	if _, err := mac.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}

	first := mac.Sum(nil)
	second := mac.Sum(nil)

	if !bytes.Equal(first, second) {
		t.Fatalf("Sum not idempotent: first=%x second=%x", first, second)
	}
}

// TestOMAC_SumAfterWrite verifies that:
//  1. Sum computes the MAC over data written so far.
//  2. After additional Write calls, Sum reflects the new (larger) input.
//  3. The second Sum matches a fresh OMAC over the full concatenated input.
//
// This confirms that Sum does not mutate receiver state — additional writes
// after a Sum must still work correctly.
func TestOMAC_SumAfterWrite(t *testing.T) {
	key, _ := hex.DecodeString(
		"8899aabbccddeeff0011223344556677" +
			"fedcba98765432100123456789abcdef",
	)
	// Split the 64-byte Kuznyechik plaintext into two halves.
	full, _ := hex.DecodeString(
		"1122334455667700ffeeddccbbaa9988" +
			"00112233445566778899aabbcceeff0a" +
			"112233445566778899aabbcceeff0a00" +
			"2233445566778899aabbcceeff0a0011",
	)
	half1 := full[:32]
	half2 := full[32:]

	// Incremental: write half1, sum, write half2, sum again.
	block1 := gost3412128.NewCipher(key)
	macIncr, err := NewOMAC(block1, 8)
	if err != nil {
		t.Fatalf("NewOMAC: %v", err)
	}
	if _, err := macIncr.Write(half1); err != nil {
		t.Fatalf("Write half1: %v", err)
	}
	_ = macIncr.Sum(nil) // first Sum — must not corrupt state
	if _, err := macIncr.Write(half2); err != nil {
		t.Fatalf("Write half2: %v", err)
	}
	gotIncr := macIncr.Sum(nil)

	// Reference: fresh OMAC over the full input.
	block2 := gost3412128.NewCipher(key)
	macFull, err := NewOMAC(block2, 8)
	if err != nil {
		t.Fatalf("NewOMAC ref: %v", err)
	}
	if _, err := macFull.Write(full); err != nil {
		t.Fatalf("Write full: %v", err)
	}
	wantFull := macFull.Sum(nil)

	if !bytes.Equal(gotIncr, wantFull) {
		t.Fatalf("SumAfterWrite: incremental=%x full=%x", gotIncr, wantFull)
	}
}
