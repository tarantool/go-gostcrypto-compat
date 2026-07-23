package gostcryptocompat

// Cipher and MAC vectors ported from gost-engine v3.0.3.
// Source commit: e0a500a (tag v3.0.3). Not committed; lives in tmp/engine/.
//
// Sources used:
//   tmp/engine/test/02-mac.t   — GOST 28147-89 IMIT MAC vectors
//   tmp/engine/test/03-encrypt.t — GOST 28147-89 CNT stream cipher vectors

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"go.stargrave.org/gogost/v7/gost28147"
)

// TestGost_GOST28147_CNT_EngineVectors tests GOST 28147-89 CNT mode against
// vectors from gost-engine v3.0.3 test/03-encrypt.t.
//
// The engine's gost89-cnt uses the CryptoPro-A S-box (SboxDefault).
// The engine's gost89-cnt-12 uses the tc26-Z S-box (2012 paramset).
// Per test/03-encrypt.t line 179-183: the paramset argument does NOT affect CNT.
//
// src: tmp/engine/test/03-encrypt.t:140-195
func TestGost_GOST28147_CNT_EngineVectors(t *testing.T) {
	// key = '0123456789ABCDEF' x 4 = 32 bytes
	// src: tmp/engine/test/03-encrypt.t:140
	key, err := hex.DecodeString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	if err != nil {
		t.Fatalf("key decode: %v", err)
	}
	// iv = '0000000000000000' = 8 zero bytes
	// src: tmp/engine/test/03-encrypt.t:141
	iv, err := hex.DecodeString("0000000000000000")
	if err != nil {
		t.Fatalf("iv decode: %v", err)
	}
	// cleartext = "The quick brown fox jumps over the lazy dog\n"
	// src: tmp/engine/test/03-encrypt.t:142
	cleartext := []byte("The quick brown fox jumps over the lazy dog\n")

	cases := []struct {
		name       string
		sbox       *gost28147.Sbox
		ciphertext string // hex
		src        string // file:line in tmp/engine/
		skip       string // non-empty → t.Skip
	}{
		{
			// crypt_test(-alg => 'gost89-cnt', -paramset => "1.2.643.2.2.31.1", ...)
			// paramset does not affect CNT; SboxDefault = CryptoPro-A
			// src: tmp/engine/test/03-encrypt.t:173-178
			name:       "gost89-cnt-paramsetA",
			sbox:       gost28147.SboxDefault,
			ciphertext: "bcb821452e459f10f92019171e7c3b27b87f24b174306667f67704812c07b70b5e7420f74a9d54feb4897df8",
			src:        "test/03-encrypt.t:173",
		},
		{
			// crypt_test(-alg => 'gost89-cnt', -paramset => "1.2.643.2.2.31.2", ...)
			// same ciphertext — confirms paramset has no effect on CNT
			// src: tmp/engine/test/03-encrypt.t:179-183
			name:       "gost89-cnt-paramsetB-same-output",
			sbox:       gost28147.SboxDefault,
			ciphertext: "bcb821452e459f10f92019171e7c3b27b87f24b174306667f67704812c07b70b5e7420f74a9d54feb4897df8",
			src:        "test/03-encrypt.t:179",
		},
		{
			// crypt_test(-alg => 'gost89-cnt-12', ...)
			// gost89-cnt-12 uses 2012 paramset = tc26-Z S-box
			// src: tmp/engine/test/03-encrypt.t:185-189
			name:       "gost89-cnt-12-paramsetA",
			sbox:       &gost28147.SboxIdtc26gost28147paramZ,
			ciphertext: "cf3f5f713b3d10abd0c6f7bafb6aaffe13dfc12ef5c844f84873aeaaf6eb443a9747c9311b86f97ba3cdb5c4",
			src:        "test/03-encrypt.t:185",
		},
		{
			// same CNT-12 with paramset B — no effect
			// src: tmp/engine/test/03-encrypt.t:191-195
			name:       "gost89-cnt-12-paramsetB-same-output",
			sbox:       &gost28147.SboxIdtc26gost28147paramZ,
			ciphertext: "cf3f5f713b3d10abd0c6f7bafb6aaffe13dfc12ef5c844f84873aeaaf6eb443a9747c9311b86f97ba3cdb5c4",
			src:        "test/03-encrypt.t:191",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skipf("%s (src: %s)", tc.skip, tc.src)
			}
			want, err := hex.DecodeString(tc.ciphertext)
			if err != nil {
				t.Skipf("malformed ciphertext hex (src: %s): %v", tc.src, err)
			}

			// Encrypt
			c := gost28147.NewCipher(key, tc.sbox)
			ctr := c.NewCTR(iv)
			got := make([]byte, len(cleartext))
			ctr.XORKeyStream(got, cleartext)

			if !bytes.Equal(got, want) {
				t.Fatalf("CNT encrypt mismatch (src: %s):\ngot  %x\nwant %s", tc.src, got, tc.ciphertext)
			}

			// Decrypt round-trip
			c2 := gost28147.NewCipher(key, tc.sbox)
			ctr2 := c2.NewCTR(iv)
			plain := make([]byte, len(got))
			ctr2.XORKeyStream(plain, got)
			if !bytes.Equal(plain, cleartext) {
				t.Fatalf("CNT decrypt round-trip failed (src: %s): got %q", tc.src, plain)
			}
		})
	}
}

// TestGost_GOST28147_IMIT_EngineVectors tests GOST 28147-89 IMIT (CBC-MAC) against
// vectors from gost-engine v3.0.3 test/02-mac.t.
//
// Key encoding: in 02-mac.t the key is "$key='0123456789abcdef' x 2" passed as
// -macopt key:$key, i.e. 32 raw ASCII bytes (not hex).
//
// The engine's gost-mac uses the default CryptoPro-A S-box (SboxDefault).
// The engine's gost-mac-12 uses the 2012 S-box (SboxIdtc26gost28147paramZ).
//
// MAC computation: NewMAC(size, zeroIV); full message written to Write().
// Zero IV is consistent with RFC 9189 §4.2 (IV not specified = zeros).
//
// src: tmp/engine/test/02-mac.t:158-207
func TestGost_GOST28147_IMIT_EngineVectors(t *testing.T) {
	// key = "0123456789abcdef" x 2 (32 bytes raw ASCII)
	// src: tmp/engine/test/02-mac.t:51
	key := []byte("0123456789abcdef0123456789abcdef")

	// testdata.dat = "12345670" x 128 (1024 bytes)
	// src: tmp/engine/test/02-mac.t:44
	testdata := []byte(strings.Repeat("12345670", 128))

	// testbig.dat = ("12345670" x 8 + "\n") x 4096 (266240 bytes)
	// src: tmp/engine/test/02-mac.t:47
	testbig := []byte(strings.Repeat(strings.Repeat("12345670", 8)+"\n", 4096))
	_ = testbig // used in skipped vector below

	cases := []struct {
		name string
		sbox *gost28147.Sbox
		data []byte
		size int    // MAC output bytes
		want string // hex
		src  string
		skip string
	}{
		{
			// gost-mac default size (4 bytes), testdata.dat
			// src: tmp/engine/test/02-mac.t:158-164
			name: "gost-mac-testdata-4bytes",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 4,
			want: "2ee8d13d",
			src:  "test/02-mac.t:162",
		},
		{
			// gost-mac sizes 1–8: full 8-byte MAC is 2ee8d13dff7f037d
			// src: tmp/engine/test/02-mac.t:168-177
			name: "gost-mac-testdata-size1",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 1,
			want: "2e",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size2",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 2,
			want: "2ee8",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size3",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 3,
			want: "2ee8d1",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size4",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 4,
			want: "2ee8d13d",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size5",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 5,
			want: "2ee8d13dff",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size6",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 6,
			want: "2ee8d13dff7f",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size7",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 7,
			want: "2ee8d13dff7f03",
			src:  "test/02-mac.t:173",
		},
		{
			// src: tmp/engine/test/02-mac.t:173
			name: "gost-mac-testdata-size8",
			sbox: gost28147.SboxDefault,
			data: testdata,
			size: 8,
			want: "2ee8d13dff7f037d",
			src:  "test/02-mac.t:173",
		},
		{
			// gost-mac on testbig.dat: engine's gost-mac applies CryptoPro key
			// meshing (RFC 4357 §2.3.2) every 1024 bytes. gogost's raw
			// gost28147.MAC does not, so it disagrees here. Our GOST28147_IMIT
			// wrapper implements meshing; this vector is re-tested via that
			// wrapper in TestGost_GOST28147_IMIT_Wrapper_KeyMeshing below.
			// src: tmp/engine/test/02-mac.t:181-187
			name: "gost-mac-testbig-raw-skipped",
			sbox: gost28147.SboxDefault,
			data: testbig,
			size: 4,
			want: "5efab81f",
			src:  "test/02-mac.t:185",
			skip: "gogost raw MAC lacks CryptoPro key meshing; covered by wrapper test",
		},
		{
			// gost-mac-12 default size (4 bytes), testdata.dat
			// Uses tc26-Z (2012 paramset) S-box.
			// src: tmp/engine/test/02-mac.t:190-196
			name: "gost-mac-12-testdata-4bytes",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 4,
			want: "be4453ec",
			src:  "test/02-mac.t:194",
		},
		{
			// gost-mac-12 sizes 1–8: full 8-byte MAC is be4453ec1ec327be
			// src: tmp/engine/test/02-mac.t:198-207
			name: "gost-mac-12-testdata-size1",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 1,
			want: "be",
			src:  "test/02-mac.t:203",
		},
		{
			name: "gost-mac-12-testdata-size2",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 2,
			want: "be44",
			src:  "test/02-mac.t:203",
		},
		{
			name: "gost-mac-12-testdata-size3",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 3,
			want: "be4453",
			src:  "test/02-mac.t:203",
		},
		{
			name: "gost-mac-12-testdata-size5",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 5,
			want: "be4453ec1e",
			src:  "test/02-mac.t:203",
		},
		{
			name: "gost-mac-12-testdata-size6",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 6,
			want: "be4453ec1ec3",
			src:  "test/02-mac.t:203",
		},
		{
			name: "gost-mac-12-testdata-size7",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 7,
			want: "be4453ec1ec327",
			src:  "test/02-mac.t:203",
		},
		{
			name: "gost-mac-12-testdata-size8",
			sbox: &gost28147.SboxIdtc26gost28147paramZ,
			data: testdata,
			size: 8,
			want: "be4453ec1ec327be",
			src:  "test/02-mac.t:203",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skipf("%s (src: %s)", tc.skip, tc.src)
			}
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Skipf("malformed want hex (src: %s): %v", tc.src, err)
			}

			c := gost28147.NewCipher(key, tc.sbox)
			iv := make([]byte, gost28147.BlockSize) // zero IV per RFC 9189 §4.2
			mac, err := c.NewMAC(tc.size, iv)
			if err != nil {
				t.Fatalf("NewMAC: %v", err)
			}
			if len(tc.data) > 0 {
				if _, err := mac.Write(tc.data); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			got := mac.Sum(nil)

			if !bytes.Equal(got, want) {
				t.Fatalf("IMIT mismatch (src: %s):\ngot  %x\nwant %s", tc.src, got, tc.want)
			}
		})
	}
}

// TestGost_GOST28147_IMIT_Wrapper_KeyMeshing validates our GOST28147_IMIT
// wrapper against the testbig.dat vector from gost-engine v3.0.3 test/02-mac.t.
// The wrapper implements CryptoPro key meshing (RFC 4357 §2.3.2), which gogost's
// raw gost28147.MAC omits. Input exceeds 1024 bytes so meshing is exercised.
// src: tmp/engine/test/02-mac.t:181-187
func TestGost_GOST28147_IMIT_Wrapper_KeyMeshing(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	testbig := []byte(strings.Repeat(strings.Repeat("12345670", 8)+"\n", 4096))

	got, err := GOST28147_IMIT(key, testbig)
	if err != nil {
		t.Fatalf("GOST28147_IMIT: %v", err)
	}
	want, err := hex.DecodeString("5efab81f")
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("IMIT with key meshing mismatch:\ngot  %x\nwant %x\n(src: test/02-mac.t:185)",
			got, want)
	}
}

// TestGost_GOST28147_IMIT_Wrapper_NoMeshing sanity-checks the wrapper against
// a 1024-byte vector sitting exactly on the meshing boundary (no meshing event
// affects the result). Must match the raw-MAC result at the 1024-byte boundary:
// gost-mac on "12345670"x128 gives 2ee8d13d.
// src: tmp/engine/test/02-mac.t:158-164
func TestGost_GOST28147_IMIT_Wrapper_NoMeshing(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	testdata := []byte(strings.Repeat("12345670", 128))

	got, err := GOST28147_IMIT(key, testdata)
	if err != nil {
		t.Fatalf("GOST28147_IMIT: %v", err)
	}
	want, err := hex.DecodeString("2ee8d13d")
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("IMIT (no meshing) mismatch:\ngot  %x\nwant %x\n(src: test/02-mac.t:162)",
			got, want)
	}
}
