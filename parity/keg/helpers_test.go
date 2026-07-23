package kegparity

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

// seedHex decodes a hex string outside of a *testing.T context (e.g. in f.Add
// corpus seeds, where no *testing.T is available).
func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

const (
	privAHex = "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d"
	pubAHex  = "a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c" +
		"6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4"
	privBHex = "bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607"
	pubBHex  = "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888" +
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602"
	ukmHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	wantHex = "bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900" +
		"39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b"
)
