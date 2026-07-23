// Differential test of the clean-room MGM against the gogost oracle.
// gogost is used strictly as a BLACK BOX (imported and called; its source is
// not read). The diff covers both layers:
//   - clean-room MGM over clean-room block ciphers (kuznyechik/magma), vs
//   - gogost MGM over gogost block ciphers,
//
// fed identical key/nonce/aad/plaintext, asserting byte-identical output.
// Both Seal parity and Open cross-decryption are compared; a forgery-rejection
// differential confirms both sides reject tampered ciphertext.
package mgmparity

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	. "github.com/tarantool/go-gostcrypto/mgm"
	"math/rand"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
	gogostmgm "go.stargrave.org/gogost/v7/mgm"

	"github.com/tarantool/go-gostcrypto/kuznyechik"
	"github.com/tarantool/go-gostcrypto/magma"
)

type variant struct {
	name      string
	blockSize int
	newRef    func(key []byte) cipher.Block
	newMine   func(key []byte) cipher.Block
}

var variants = []variant{
	{
		name:      "Kuznyechik",
		blockSize: 16,
		newRef:    func(k []byte) cipher.Block { return gost3412128.NewCipher(k) },
		newMine:   func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
	},
	{
		name:      "Magma",
		blockSize: 8,
		newRef:    func(k []byte) cipher.Block { return gost341264.NewCipher(k) },
		newMine:   func(k []byte) cipher.Block { return magma.NewCipher(k) },
	},
}

// sealAndCheck runs one Seal differential for the given tagSize, asserts
// byte-identical Seal output, performs cross-decryption via mine.Open on the
// ref's sealed output (MGM-03), and asserts forgery rejection (MGM-03). rng
// may be nil in the fuzz path (a fixed flip position is used instead).
func sealAndCheck(t *testing.T, v variant, tagSize int, key, nonce, plain, aad []byte, rng *rand.Rand) {
	t.Helper()

	ref, err := gogostmgm.NewMGM(v.newRef(key), tagSize)
	if err != nil {
		t.Fatalf("ref NewMGM(tagSize=%d): %v", tagSize, err)
	}
	mine, err := NewMGM(v.newMine(key), tagSize)
	if err != nil {
		t.Fatalf("mine NewMGM(tagSize=%d): %v", tagSize, err)
	}

	gotRef := ref.Seal(nil, nonce, plain, aad)
	gotMine := mine.Seal(nil, nonce, plain, aad)
	if !bytes.Equal(gotRef, gotMine) {
		t.Fatalf("Seal mismatch (bs=%d tagSize=%d):\n ref  %x\n mine %x",
			v.blockSize, tagSize, gotRef, gotMine)
	}

	// MGM-03: Open cross-decryption — mine must accept gogost's sealed output.
	back, err := mine.Open(nil, nonce, gotRef, aad)
	if err != nil {
		t.Fatalf("mine Open rejected ref Seal (tagSize=%d): %v", tagSize, err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("cross-decrypt mismatch (tagSize=%d):\n got  %x\n want %x", tagSize, back, plain)
	}

	// MGM-03: Forgery rejection — a single bit flip must cause Open to fail.
	badMine := append([]byte{}, gotMine...)
	pos := 0
	if rng != nil {
		pos = rng.Intn(len(badMine))
	}
	badMine[pos] ^= 0x01
	if _, err3 := mine.Open(nil, nonce, badMine, aad); err3 == nil {
		t.Fatalf("mine Open accepted tampered ciphertext (tagSize=%d)", tagSize)
	}
}

func TestMGM_Differential(t *testing.T) {
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(0x9058))
			for range 500 {
				key := make([]byte, 32)
				rng.Read(key)
				nonce := make([]byte, v.blockSize)
				rng.Read(nonce)
				nonce[0] &= 0x7f // MSB-must-be-0

				adLen := rng.Intn(70)
				ptLen := rng.Intn(70)
				if adLen == 0 && ptLen == 0 {
					ptLen = 1 // MGM rejects empty text+aad
				}
				aad := make([]byte, adLen)
				rng.Read(aad)
				plain := make([]byte, ptLen)
				rng.Read(plain)

				// Full-block tag size (as before): proves Seal, cross-Open, forgery rejection.
				sealAndCheck(t, v, v.blockSize, key, nonce, plain, aad, rng)
			}

			// MGM-01: Truncated-tag sweep — tagSize in [4, blockSize].
			// Exercises both Seal output layout (ciphertext||truncated-tag) and
			// Open's ct/tag split at every permitted tag length, including the
			// MSB_S copy(tag, ek[:tagSize]) path.
			key := make([]byte, 32)
			rng.Read(key)
			nonce := make([]byte, v.blockSize)
			rng.Read(nonce)
			nonce[0] &= 0x7f
			aad := []byte{0x01, 0x02, 0x03}
			plain := []byte{0xAA, 0xBB, 0xCC, 0xDD}
			for tagSize := 4; tagSize <= v.blockSize; tagSize++ {
				tagSize := tagSize
				t.Run(fmt.Sprintf("tagSize=%d", tagSize), func(t *testing.T) {
					sealAndCheck(t, v, tagSize, key, nonce, plain, aad, rng)
				})
			}
		})
	}
}

func FuzzMGM_Differential(f *testing.F) {
	// MGM-02: seed#0 uses odd sel=1 → Kuznyechik; seed#1 uses even sel=0 → Magma.
	// Previously both seeds used even sel values (16 and 8), so the Kuznyechik
	// arm was dead under seed replay and the intended RFC 9058 Kuznyechik nonce
	// was silently truncated to 8 bytes by fixLen.
	//
	// Key/nonce/aad/plain for seed#0 are the RFC 9058 Kuznyechik worked example
	// (gostcrypto/mgm/mgm_test.go katCases[0]).
	f.Add(byte(1), // odd → Kuznyechik
		mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		mustHex("1122334455667700ffeeddccbbaa9988"),
		mustHex("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505"),
		mustHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0aaabbcc"))
	f.Add(byte(0), // even → Magma
		mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		mustHex("12def06b3c130a59"),
		mustHex("0101010101010101020202020202020203030303030303030404040404040404"),
		mustHex("ffeeddccbbaa998811223344556677008899aabbcceeff0aaabbcc"))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, rndNonce, aad, plain []byte) {
		v := variants[0] // Kuznyechik
		if sel&1 == 0 {
			v = variants[1] // Magma
		}
		key := fixLen(rndKey, 32)
		nonce := fixLen(rndNonce, v.blockSize)
		nonce[0] &= 0x7f
		if len(plain) == 0 && len(aad) == 0 {
			plain = []byte{0}
		}

		// MGM-01: derive tagSize from sel bits [7:1] in [4, v.blockSize].
		// 4 + (sel>>1) % (v.blockSize-3) covers the full [4,blockSize] range.
		tagSize := 4 + int(sel>>1)%(v.blockSize-3)

		ref, err := gogostmgm.NewMGM(v.newRef(key), tagSize)
		if err != nil {
			t.Skipf("ref NewMGM: %v", err)
		}
		mine, err := NewMGM(v.newMine(key), tagSize)
		if err != nil {
			t.Skipf("mine NewMGM: %v", err)
		}

		gotRef := ref.Seal(nil, nonce, plain, aad)
		gotMine := mine.Seal(nil, nonce, plain, aad)
		if !bytes.Equal(gotRef, gotMine) {
			t.Fatalf("Seal mismatch (bs=%d tagSize=%d):\n ref  %x\n mine %x",
				v.blockSize, tagSize, gotRef, gotMine)
		}

		// MGM-03: Open cross-decryption — mine must accept gogost's sealed output.
		back, err := mine.Open(nil, nonce, gotRef, aad)
		if err != nil {
			t.Fatalf("mine Open rejected ref Seal (tagSize=%d): %v", tagSize, err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("cross-decrypt mismatch (tagSize=%d):\n got  %x\n want %x", tagSize, back, plain)
		}

		// MGM-03: Forgery rejection — flip first byte; mine must reject.
		badMine := append([]byte{}, gotMine...)
		badMine[0] ^= 0x01
		if _, err3 := mine.Open(nil, nonce, badMine, aad); err3 == nil {
			t.Fatalf("mine Open accepted tampered ciphertext (tagSize=%d)", tagSize)
		}
	})
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
