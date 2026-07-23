package keywrapparity

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/tarantool/go-gostcrypto/keywrap"

	gost "github.com/tarantool/go-gostcrypto-compat"
	gogostwrap "go.stargrave.org/gogost/v7/gost28147"
)

// Oracle independence (remediation §1 rule 7): the in-repo gostcryptocompat
// facade (gost.KeyWrapCryptoPro) shares the diversify/wrap orchestration with
// the clean-room — only the underlying gost28147 block cipher / CFB / MAC come
// from gogost, so the facade differential is meaningful only BELOW the
// orchestration layer. Two genuinely-independent anchors guard the orchestration:
//
//   - katWrapped / katWrappedCryptoProA: full 44-byte wrap KATs captured from
//     gost-engine 3.0.3 (TC26-Z and CryptoPro-A respectively); see helpers_test.go.
//   - gogostwrap.UnwrapCryptoPro / gogostwrap.DiversifyCryptoPro: gogost's OWN
//     CryptoPro-A diversify+unwrap, written by a different author. Used here as a
//     round-trip and a direct diversification oracle for the CryptoPro-A S-box
//     (gogost hardcodes CryptoPro-A in these, so they cannot anchor TC26-Z).

// pick maps an S-box name to both the clean-room and in-repo selectors.
func pick(name string) (Sbox, *gost.Sbox) {
	switch name {
	case "tc26-z":
		return SboxTC26Z, gost.SboxTC26Z
	case "cryptopro-a":
		return SboxCryptoProA, gost.SboxCryptoProA
	}
	panic("unknown sbox " + name)
}

// TestKeyWrapCryptoPro_Differential drives the clean-room impl and the in-repo
// gostcryptocompat oracle through identical inputs and asserts byte-for-byte
// equality of the 44-byte blob, on BOTH S-boxes. Each S-box additionally pins
// an independent gost-engine 3.0.3 KAT on the canonical inputs, and the
// CryptoPro-A legs are round-tripped through gogost's own UnwrapCryptoPro.
func TestKeyWrapCryptoPro_Differential(t *testing.T) {
	mh := func(s string) []byte { return mustHex(t, s) }

	cases := []struct {
		name, sbox    string
		kek, ukm, cek []byte
		wantPinned    []byte // independent gost-engine KAT; nil when inputs aren't the canonical KAT inputs
	}{
		{
			name:       "tc26z-kat",
			sbox:       "tc26-z",
			kek:        mh(katKEK),
			ukm:        mh(katUKM),
			cek:        mh(katSession),
			wantPinned: mh(katWrapped),
		},
		{
			name: "tc26z-other",
			sbox: "tc26-z",
			kek:  mh("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
			ukm:  mh("a1b2c3d4e5f60718"),
			cek:  mh("0011223344556677889900aabbccddeeff102030405060708090a0b0c0d0e0f0"),
		},
		{
			name:       "cryptopro-a-kat",
			sbox:       "cryptopro-a",
			kek:        mh(katKEK),
			ukm:        mh(katUKM),
			cek:        mh(katSession),
			wantPinned: mh(katWrappedCryptoProA),
		},
		{
			name: "cryptopro-a-other",
			sbox: "cryptopro-a",
			kek:  mh("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
			ukm:  mh("00ff00ff00ff00ff"),
			cek:  mh("deadbeefcafebabe0123456789abcdeffedcba98765432100f1e2d3c4b5a6978"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newSbox, repoSbox := pick(tc.sbox)

			gotNew, err := KeyWrapCryptoPro(newSbox, tc.kek, tc.ukm, tc.cek)
			if err != nil {
				t.Fatalf("clean-room KeyWrapCryptoPro: %v", err)
			}
			gotRepo, err := gost.KeyWrapCryptoPro(repoSbox, tc.kek, tc.ukm, tc.cek)
			if err != nil {
				t.Fatalf("oracle KeyWrapCryptoPro: %v", err)
			}
			if !bytes.Equal(gotNew, gotRepo) {
				t.Fatalf("clean-room vs oracle mismatch (sbox=%s)\n new: %x\nrepo: %x",
					tc.sbox, gotNew, gotRepo)
			}
			if tc.wantPinned != nil && !bytes.Equal(gotNew, tc.wantPinned) {
				t.Fatalf("engine KAT mismatch (sbox=%s)\n got: %x\nwant: %x",
					tc.sbox, gotNew, tc.wantPinned)
			}

			// KWP-01/02: gogost's own CryptoPro-A unwrap is an independent
			// oracle at the orchestration layer. It hardcodes CryptoPro-A, so
			// it only applies to that S-box. DiversifyCryptoPro aliases+overwrites
			// its kek argument, so the round-trip must see a copy.
			if tc.sbox == "cryptopro-a" {
				kekCopy := append([]byte(nil), tc.kek...)
				got := gogostwrap.UnwrapCryptoPro(kekCopy, gotNew)
				if got == nil {
					t.Fatalf("gogost UnwrapCryptoPro returned nil (MAC mismatch / bad wrap)")
				}
				if !bytes.Equal(got, tc.cek) {
					t.Fatalf("gogost round-trip mismatch (sbox=cryptopro-a)\n got: %x\nwant: %x",
						got, tc.cek)
				}
			}
		})
	}
}

// TestDiversify_Differential exercises the exported keywrap.Diversify step
// (RFC 4357 §6.5) on its own, which the full-wrap differential only covers
// implicitly. The TC26-Z leg pins the gost-engine-captured intermediate
// KEK(UKM) (katKEKUKM); the CryptoPro-A leg diffs against gogost's OWN
// DiversifyCryptoPro — an independent orchestration-layer oracle (gogost
// hardcodes CryptoPro-A, so it cannot anchor TC26-Z).
func TestDiversify_Differential(t *testing.T) {
	mh := func(s string) []byte { return mustHex(t, s) }

	// TC26-Z: independent engine KAT for KEK(UKM) on the canonical inputs.
	t.Run("tc26z-kat", func(t *testing.T) {
		got := Diversify(SboxTC26Z, mh(katKEK), mh(katUKM))
		if want := mh(katKEKUKM); !bytes.Equal(got, want) {
			t.Fatalf("Diversify(tc26-z) KAT mismatch\n got: %x\nwant: %x", got, want)
		}
	})

	// CryptoPro-A: diff against gogost's independent DiversifyCryptoPro on
	// several inputs. gogost mutates its kek argument in place, so pass a copy.
	cpaInputs := []struct {
		name, kek, ukm string
	}{
		{"kat-inputs", katKEK, katUKM},
		{"other", "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "00ff00ff00ff00ff"},
		{"zeros", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000"},
	}
	for _, in := range cpaInputs {
		t.Run("cryptopro-a/"+in.name, func(t *testing.T) {
			kek, ukm := mh(in.kek), mh(in.ukm)
			got := Diversify(SboxCryptoProA, kek, ukm)
			want := gogostwrap.DiversifyCryptoPro(append([]byte(nil), kek...), ukm)
			if !bytes.Equal(got, want) {
				t.Fatalf("Diversify vs gogost.DiversifyCryptoPro mismatch (%s)\n got: %x\ngogost: %x",
					in.name, got, want)
			}
		})
	}
}

// TestKeyWrapCryptoPro_ErrorParity pins the rejection contract: on a
// wrong-length kek/ukm/cek both the clean-room impl and the oracle must return
// a non-nil error and no output. The error texts intentionally differ; only the
// non-nil contract is compared.
func TestKeyWrapCryptoPro_ErrorParity(t *testing.T) {
	valid32 := bytes.Repeat([]byte{0xAA}, 32)
	valid8 := bytes.Repeat([]byte{0xBB}, 8)

	cases := []struct {
		name          string
		kek, ukm, cek []byte
	}{
		{"short-kek", valid32[:31], valid8, valid32},
		{"long-kek", append(append([]byte(nil), valid32...), 0x00), valid8, valid32},
		{"short-ukm", valid32, valid8[:7], valid32},
		{"long-ukm", valid32, append(append([]byte(nil), valid8...), 0x00), valid32},
		{"short-cek", valid32, valid8, valid32[:31]},
		{"long-cek", valid32, valid8, append(append([]byte(nil), valid32...), 0x00)},
	}

	for _, sbox := range []string{"tc26-z", "cryptopro-a"} {
		newSbox, repoSbox := pick(sbox)
		for _, tc := range cases {
			t.Run(sbox+"/"+tc.name, func(t *testing.T) {
				outNew, errNew := KeyWrapCryptoPro(newSbox, tc.kek, tc.ukm, tc.cek)
				if errNew == nil {
					t.Fatalf("clean-room: expected error for %s, got nil (out=%x)", tc.name, outNew)
				}
				if outNew != nil {
					t.Fatalf("clean-room: expected nil output on error, got %x", outNew)
				}
				outRepo, errRepo := gost.KeyWrapCryptoPro(repoSbox, tc.kek, tc.ukm, tc.cek)
				if errRepo == nil {
					t.Fatalf("oracle: expected error for %s, got nil (out=%x)", tc.name, outRepo)
				}
				if outRepo != nil {
					t.Fatalf("oracle: expected nil output on error, got %x", outRepo)
				}
			})
		}
	}
}

// FuzzKeyWrapCryptoPro_Differential drives wrap, diversify, and unwrap across
// both S-boxes, asserting the clean-room impl agrees with the in-repo oracle on
// the full wrap, agrees with gogost's independent DiversifyCryptoPro /
// UnwrapCryptoPro on the CryptoPro-A leg, and that the wrap always round-trips.
func FuzzKeyWrapCryptoPro_Differential(f *testing.F) {
	seed := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	kat := append(append(append([]byte{}, seed(katKEK)...), seed(katUKM)...), seed(katSession)...)

	// useTC26Z selects the S-box; raw is normalized into 32|8|32 = 72 bytes.
	f.Add(true, kat)
	f.Add(false, kat)
	f.Add(true, make([]byte, 72))                       // all-zero, tc26-z
	f.Add(false, make([]byte, 72))                      // all-zero, cryptopro-a
	f.Add(true, bytes.Repeat([]byte{0xFF}, 72))         // all-0xFF, tc26-z
	f.Add(false, bytes.Repeat([]byte{0xFF}, 72))        // all-0xFF, cryptopro-a
	f.Add(false, append(seed(katKEK), seed(katUKM)...)) // short raw -> zero-padded cek

	f.Fuzz(func(t *testing.T, useTC26Z bool, raw []byte) {
		sbox := "cryptopro-a"
		if useTC26Z {
			sbox = "tc26-z"
		}
		buf := make([]byte, 72)
		copy(buf, raw)
		k, u, c := buf[0:32], buf[32:40], buf[40:72]

		newSbox, repoSbox := pick(sbox)

		gotNew, err := KeyWrapCryptoPro(newSbox, k, u, c)
		if err != nil {
			t.Fatalf("clean-room KeyWrapCryptoPro: %v", err)
		}
		gotRepo, err := gost.KeyWrapCryptoPro(repoSbox, k, u, c)
		if err != nil {
			t.Fatalf("oracle KeyWrapCryptoPro: %v", err)
		}
		if !bytes.Equal(gotNew, gotRepo) {
			t.Fatalf("wrap mismatch (sbox=%s)\n kek=%x ukm=%x cek=%x\n new=%x\nrepo=%x",
				sbox, k, u, c, gotNew, gotRepo)
		}

		// CryptoPro-A: independent gogost orchestration-layer oracles.
		if !useTC26Z {
			// DiversifyCryptoPro mutates its kek arg in place: pass a copy.
			gotDiv := Diversify(newSbox, k, u)
			wantDiv := gogostwrap.DiversifyCryptoPro(append([]byte(nil), k...), u)
			if !bytes.Equal(gotDiv, wantDiv) {
				t.Fatalf("Diversify mismatch (cryptopro-a)\n new=%x\ngogost=%x", gotDiv, wantDiv)
			}
			// Round-trip the clean-room wrap through gogost's own unwrap.
			cek := gogostwrap.UnwrapCryptoPro(append([]byte(nil), k...), gotNew)
			if cek == nil {
				t.Fatalf("gogost UnwrapCryptoPro returned nil (kek=%x ukm=%x cek=%x)", k, u, c)
			}
			if !bytes.Equal(cek, c) {
				t.Fatalf("gogost round-trip mismatch (cryptopro-a)\n got=%x\nwant=%x", cek, c)
			}
		}
	})
}
