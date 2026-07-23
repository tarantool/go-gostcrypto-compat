package tlstreeparity

import (
	"bytes"
	"fmt"
	"testing"

	gostref "github.com/tarantool/go-gostcrypto-compat"
	cleanroom "github.com/tarantool/go-gostcrypto/tlstree"
)

// Test_TLSTree_Conformance diffs the clean-room impl against the in-repo
// gostcryptocompat.TLSTree oracle, across both suites and a spread of sequence
// numbers. The reference is primed with Derive(0) first to dodge the documented
// D2 zero-key startup trap; the clean-room impl is never primed because it must
// not carry that bug.
func Test_TLSTree_Conformance(t *testing.T) {
	suites := []struct {
		name   string
		newRef func([]byte) *gostref.TLSTree
		newNew func([]byte) *cleanroom.TLSTree
	}{
		{"kuznyechik", gostref.NewTLSTreeKuznyechikCTROMAC, cleanroom.NewTLSTreeKuznyechikCTROMAC},
		{"magma", gostref.NewTLSTreeMagmaCTROMAC, cleanroom.NewTLSTreeMagmaCTROMAC},
	}

	masters := [][]byte{
		bytes.Repeat([]byte{0xFF}, 32),
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0x11}, 32),
		[]byte("0123456789abcdef0123456789abcdef"),
	}

	seqs := []uint64{0, 1, 63, 64, 65, 4095, 4096, 4097, 1 << 20, 1<<32 - 1, 1 << 32, 1 << 40}

	for _, su := range suites {
		for _, master := range masters {
			for _, seq := range seqs {
				ref := su.newRef(master)
				_ = ref.Derive(0) // prime (D2)
				want := ref.Derive(seq)

				got := su.newNew(master).Derive(seq) // first call, unprimed
				if !bytes.Equal(got, want) {
					t.Fatalf("%s master=%x seq=%d:\n ref %x\n new %x", su.name, master, seq, want, got)
				}
			}
		}
	}
}

// Test_TLSTree_BadMasterKeyLength asserts that both the clean-room and the
// gostcryptocompat facade panic identically when the master key is not 32 bytes.
// The facade adds an explicit guard that gogost itself lacks; this test catches
// a regression where the guard is accidentally removed, which would cause the
// facade to silently accept a bad-length key while the clean-room still panics.
// Finding: TLS-01.
func Test_TLSTree_BadMasterKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
			bad := make([]byte, n)
			mustPanic := func(name string, fn func()) {
				t.Helper()
				defer func() {
					if recover() == nil {
						t.Fatalf("%s(len=%d) did not panic", name, n)
					}
				}()
				fn()
			}
			mustPanic("cleanroom.NewTLSTreeKuznyechikCTROMAC", func() { cleanroom.NewTLSTreeKuznyechikCTROMAC(bad) })
			mustPanic("gostref.NewTLSTreeKuznyechikCTROMAC", func() { gostref.NewTLSTreeKuznyechikCTROMAC(bad) })
			mustPanic("cleanroom.NewTLSTreeMagmaCTROMAC", func() { cleanroom.NewTLSTreeMagmaCTROMAC(bad) })
			mustPanic("gostref.NewTLSTreeMagmaCTROMAC", func() { gostref.NewTLSTreeMagmaCTROMAC(bad) })
		})
	}
}

// Test_TLSTree_KAT_vs_Oracle re-pins the guide's exact Kuznyechik seq=63 hex
// vector against both the oracle (primed) and the clean-room impl (unprimed).
func Test_TLSTree_KAT_vs_Oracle(t *testing.T) {
	kFF := bytes.Repeat([]byte{0xFF}, 32)
	want := []byte{
		0x50, 0x76, 0x42, 0xd9, 0x58, 0xc5, 0x20, 0xc6,
		0xd7, 0xee, 0xf5, 0xca, 0x8a, 0x53, 0x16, 0xd4,
		0xf3, 0x4b, 0x85, 0x5d, 0x2d, 0xd4, 0xbc, 0xbf,
		0x4e, 0x5b, 0xf0, 0xff, 0x64, 0x1a, 0x19, 0xff,
	}

	ref := gostref.NewTLSTreeKuznyechikCTROMAC(kFF)
	_ = ref.Derive(0)
	if got := ref.Derive(63); !bytes.Equal(got, want) {
		t.Fatalf("oracle mismatch: got %x want %x", got, want)
	}

	if got := cleanroom.NewTLSTreeKuznyechikCTROMAC(kFF).Derive(63); !bytes.Equal(got, want) {
		t.Fatalf("clean-room mismatch: got %x want %x", got, want)
	}
}

// Fuzz_TLSTree_Conformance fuzzes the clean-room impl against the oracle over a
// random 32-byte master key, two uint64 sequence numbers, and suite selector.
// The two-seq design exercises gogost's DeriveCached cache path: after Derive(seq1)
// sets seqNumPrev, calling Derive(seq2) on the same ref object may hit the cache
// branch (if seq1 and seq2 fall in the same level-3 window) or recompute higher
// levels (if they cross a window boundary). The clean-room is stateless so it
// always recomputes, making any cache-mismatch visible as a divergence. Finding: TLS-02.
//
// Seeds anchor C3 boundaries (seq1=63/0/4096), level-1/level-2 boundaries for
// both suites (TLS-03), and a cross-C3-window case (seq1=63, seq2=64).
func Fuzz_TLSTree_Conformance(f *testing.F) {
	// C3-boundary seeds (original three, updated for two-seq signature).
	f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(63), uint64(64), false)    // cross-C3-window, Kuznyechik
	f.Add(bytes.Repeat([]byte{0x00}, 32), uint64(0), uint64(1), false)      // same C3 window
	f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(4096), uint64(4096), true) // same seq twice, Magma
	// Level-2 boundary seeds (TLS-03).
	// Kuznyechik C2 boundary: 2^19 = 524288
	f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(1)<<19, uint64(1)<<19+1, false)
	// Kuznyechik C1 boundary: 2^32
	f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(1)<<32, uint64(1)<<32+1, false)
	// Magma C2 boundary: 2^25 = 33554432
	f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(1)<<25, uint64(1)<<25+1, true)
	// Magma C1 boundary: 2^38
	f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(1)<<38, uint64(1)<<38+1, true)

	f.Fuzz(func(t *testing.T, raw []byte, seq1, seq2 uint64, magma bool) {
		master := make([]byte, 32)
		copy(master, raw)

		newRef, newNew := gostref.NewTLSTreeKuznyechikCTROMAC, cleanroom.NewTLSTreeKuznyechikCTROMAC
		window := uint64(64)
		if magma {
			newRef, newNew = gostref.NewTLSTreeMagmaCTROMAC, cleanroom.NewTLSTreeMagmaCTROMAC
			window = 4096
		}

		// First derive: check seq1 against a freshly-primed oracle.
		ref := newRef(master)
		_ = ref.Derive(0) // prime (D2 trap)
		gotRef1 := ref.Derive(seq1)
		gotNew1 := newNew(master).Derive(seq1)
		if !bytes.Equal(gotRef1, gotNew1) {
			t.Fatalf("mismatch master=%x seq=%d magma=%v\n ref: %x\n new: %x",
				master, seq1, magma, gotRef1, gotNew1)
		}

		// Sequential call: reuse the same ref to exercise DeriveCached's cache path.
		// After Derive(seq1) above seqNumPrev==seq1; Derive(seq2) may hit the cache
		// if seq2 falls in the same L1/L2/L3 window as seq1 (cache hit) or trigger
		// a full recompute (cache miss). Either way the result must match a fresh
		// clean-room derive for seq2.
		gotRef2 := ref.Derive(seq2)
		gotNew2 := newNew(master).Derive(seq2)
		if !bytes.Equal(gotRef2, gotNew2) {
			t.Fatalf("sequential mismatch master=%x seq1=%d seq2=%d magma=%v\n ref: %x\n new: %x",
				master, seq1, seq2, magma, gotRef2, gotNew2)
		}

		// Window-boundary invariant: keys within the same C3 window are equal;
		// keys across the boundary differ.
		base := seq1 - (seq1 % window)
		k0 := newNew(master).Derive(base)
		kIn := newNew(master).Derive(base + window - 1)
		kOut := newNew(master).Derive(base + window)
		if !bytes.Equal(k0, kIn) {
			t.Fatalf("intra-window key changed: master=%x base=%d window=%d", master, base, window)
		}
		if bytes.Equal(k0, kOut) {
			t.Fatalf("cross-window key unchanged: master=%x base=%d window=%d", master, base, window)
		}
	})
}
