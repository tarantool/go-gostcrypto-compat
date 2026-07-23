package gostcryptocompat

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
	"go.stargrave.org/gogost/v7/mgm"
)

func mustHexMGM(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// TestMGM_EngineVectors ports the one-shot AEAD vectors from tmp/engine/test_mgm.c.
func TestMGM_EngineVectors(t *testing.T) {
	cases := []struct {
		name    string
		key     []byte
		nonce   []byte
		aad     []byte
		plain   []byte
		wantCT  []byte
		wantTag []byte
	}{
		{
			name: "Kuznyechik",
			key: mustHexMGM(t,
				"8899aabbccddeeff0011223344556677"+
					"fedcba98765432100123456789abcdef"),
			nonce: mustHexMGM(t, "1122334455667700ffeeddccbbaa9988"),
			aad: mustHexMGM(t,
				"02020202020202020101010101010101"+
					"04040404040404040303030303030303"+
					"ea0505050505050505"),
			plain: mustHexMGM(t,
				"1122334455667700ffeeddccbbaa9988"+
					"00112233445566778899aabbcceeff0a"+
					"112233445566778899aabbcceeff0a00"+
					"2233445566778899aabbcceeff0a0011"+
					"aabbcc"),
			wantCT: mustHexMGM(t,
				"a9757b8147956e9055b8a33de89f42fc"+
					"8075d2212bf9fd5bd3f7069aadc16b39"+
					"497ab15915a6ba85936b5d0ea9f6851c"+
					"c60c14d4d3f883d0ab94420695c76deb"+
					"2c7552"),
			wantTag: mustHexMGM(t, "cf5d656f40c34f5c46e8bb0e29fcdb4c"),
		},
		{
			name: "Magma",
			key: mustHexMGM(t,
				"ffeeddccbbaa99887766554433221100"+
					"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			nonce: mustHexMGM(t, "12def06b3c130a59"),
			aad: mustHexMGM(t,
				"01010101010101010202020202020202"+
					"03030303030303030404040404040404"+
					"0505050505050505ea"),
			plain: mustHexMGM(t,
				"ffeeddccbbaa99881122334455667700"+
					"8899aabbcceeff0a0011223344556677"+
					"99aabbcceeff0a001122334455667788"+
					"aabbcceeff0a00112233445566778899"+
					"aabbcc"),
			wantCT: mustHexMGM(t,
				"c795066c5f9ea03b85113342459185ae"+
					"1f2e00d6bf2b785d940470b8bb9c8e7d"+
					"9a5dd3731f7ddc70ec27cb0ace6fa576"+
					"70f65c646abb75d547aa37c3bcb5c34e"+
					"03bb9c"),
			wantTag: mustHexMGM(t, "a7928069aa10fd10"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				block cipher.Block
				aead  cipher.AEAD
				err   error
			)

			switch tc.name {
			case "Kuznyechik":
				b := gost3412128.NewCipher(tc.key)
				block = b
				aead, err = mgm.NewMGM(b, len(tc.wantTag))
			case "Magma":
				b := gost341264.NewCipher(tc.key)
				block = b
				aead, err = mgm.NewMGM(b, len(tc.wantTag))
			}
			if err != nil {
				t.Fatalf("NewMGM: %v", err)
			}
			if len(tc.nonce) != block.BlockSize() {
				t.Fatalf("nonce len=%d, blockSize=%d", len(tc.nonce), block.BlockSize())
			}

			got := aead.Seal(nil, tc.nonce, tc.plain, tc.aad)
			gotCT := got[:len(tc.plain)]
			gotTag := got[len(tc.plain):]
			if !bytes.Equal(gotCT, tc.wantCT) {
				t.Fatalf("ciphertext mismatch:\n got  %x\n want %x", gotCT, tc.wantCT)
			}
			if !bytes.Equal(gotTag, tc.wantTag) {
				t.Fatalf("tag mismatch:\n got  %x\n want %x", gotTag, tc.wantTag)
			}

			plain, err := aead.Open(nil, tc.nonce, got, tc.aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(plain, tc.plain) {
				t.Fatalf("plaintext mismatch:\n got  %x\n want %x", plain, tc.plain)
			}
		})
	}
}
