package omacparity

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

// seedHex is the *testing.T-free variant of mustHex, usable from f.Add seeds.
func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// fixLen normalizes b to exactly n bytes (truncating or zero-padding).
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
