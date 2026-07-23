package streebogparity

import (
	"bytes"
	"math/rand"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
	streebog "github.com/tarantool/go-gostcrypto/streebog"
)

// TestDiffAgainstGost compares the clean-room implementation against the
// gostcryptocompat black-box oracle over random-length messages, for both 256
// and 512 output sizes.
func TestDiffAgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))

	// Include boundary lengths explicitly plus randomized ones.
	lengths := []int{0, 1, 7, 31, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 1000, 4096}
	for range 200 {
		lengths = append(lengths, rng.Intn(2050))
	}

	for _, n := range lengths {
		msg := make([]byte, n)
		rng.Read(msg)

		got256 := streebog.Sum256(msg)
		ref256 := gost.Streebog256(msg)
		if !bytes.Equal(got256[:], ref256) {
			t.Fatalf("256 mismatch len=%d\n clean-room %x\n oracle     %x", n, got256, ref256)
		}

		got512 := streebog.Sum512(msg)
		ref512 := gost.Streebog512(msg)
		if !bytes.Equal(got512[:], ref512) {
			t.Fatalf("512 mismatch len=%d\n clean-room %x\n oracle     %x", n, got512, ref512)
		}
	}
}

// FuzzDiffAgainstGost is the fuzzing companion to TestDiffAgainstGost /
// TestDiffStreamingAgainstGost: it diffs the clean-room Streebog against the
// gostcryptocompat black-box oracle over a fuzzer-chosen arbitrary-length message,
// for both 256 and 512 output sizes, and additionally exercises a streaming
// (split) Write against the one-shot oracle for both 256 and 512 variants.
// Empty input is permitted (Streebog has no empty-input divergence).
func FuzzDiffAgainstGost(f *testing.F) {
	f.Add([]byte{}, uint(0))
	f.Add([]byte("012345678901234567890123456789012345678901234567890123456789012"), uint(7))
	f.Add(bytes.Repeat([]byte{0xfb}, 128), uint(64))

	f.Fuzz(func(t *testing.T, msg []byte, split uint) {
		got256 := streebog.Sum256(msg)
		ref256 := gost.Streebog256(msg)
		if !bytes.Equal(got256[:], ref256) {
			t.Fatalf("256 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), got256, ref256)
		}

		got512 := streebog.Sum512(msg)
		ref512 := gost.Streebog512(msg)
		if !bytes.Equal(got512[:], ref512) {
			t.Fatalf("512 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), got512, ref512)
		}

		// Streaming 512: split at a fuzzer-chosen offset, diff against one-shot.
		h512 := streebog.New512()
		if len(msg) > 0 {
			off := int(split % uint(len(msg)+1))
			h512.Write(msg[:off])
			h512.Write(msg[off:])
		} else {
			h512.Write(msg)
		}
		gotStream512 := h512.Sum(nil)
		if !bytes.Equal(gotStream512, ref512) {
			t.Fatalf("streaming 512 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), gotStream512, ref512)
		}

		// Streaming 256: same split, diff against one-shot oracle. Exercises
		// the 256-bit IV and MSB_256 truncation under partial-buffer state.
		h256 := streebog.New256()
		if len(msg) > 0 {
			off := int(split % uint(len(msg)+1))
			h256.Write(msg[:off])
			h256.Write(msg[off:])
		} else {
			h256.Write(msg)
		}
		gotStream256 := h256.Sum(nil)
		if !bytes.Equal(gotStream256, ref256) {
			t.Fatalf("streaming 256 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), gotStream256, ref256)
		}
	})
}

// FuzzDiffAgainstGostMultiChunk exercises >2-Write sequences (three chunks) for
// both 512 and 256 variants, covering repeated partial-buffer fills across more
// than two Write calls.
func FuzzDiffAgainstGostMultiChunk(f *testing.F) {
	// Seed: 193-byte message, splits at 64 and 128 — crosses a 64-byte block
	// boundary in the first chunk and leaves a partial block for the third.
	f.Add(bytes.Repeat([]byte{0xab}, 193), uint(64), uint(64))
	// Seed: empty message (both splits degenerate to zero).
	f.Add([]byte{}, uint(0), uint(0))
	// Seed: 65-byte message, splits 32+1+32 — crosses the block boundary
	// between the second and third Write.
	f.Add(bytes.Repeat([]byte{0xcd}, 65), uint(32), uint(1))

	f.Fuzz(func(t *testing.T, msg []byte, split1, split2 uint) {
		ref512 := gost.Streebog512(msg)
		ref256 := gost.Streebog256(msg)

		// Derive two split points, both in [0, len(msg)], with off1 <= off2.
		n := len(msg)
		var off1, off2 int
		if n > 0 {
			off1 = int(split1 % uint(n+1))
			rem := n - off1
			if rem > 0 {
				off2 = off1 + int(split2%uint(rem+1))
			} else {
				off2 = off1
			}
		}

		// Three-chunk streaming 512.
		h512 := streebog.New512()
		h512.Write(msg[:off1])
		h512.Write(msg[off1:off2])
		h512.Write(msg[off2:])
		got512 := h512.Sum(nil)
		if !bytes.Equal(got512, ref512) {
			t.Fatalf("3-chunk 512 mismatch len=%d splits=%d,%d\n got %x\n ref %x",
				n, off1, off2, got512, ref512)
		}

		// Three-chunk streaming 256.
		h256 := streebog.New256()
		h256.Write(msg[:off1])
		h256.Write(msg[off1:off2])
		h256.Write(msg[off2:])
		got256 := h256.Sum(nil)
		if !bytes.Equal(got256, ref256) {
			t.Fatalf("3-chunk 256 mismatch len=%d splits=%d,%d\n got %x\n ref %x",
				n, off1, off2, got256, ref256)
		}
	})
}

// TestDiffStreamingAgainstGost exercises chunked Write against the one-shot
// oracle (clean-room streaming vs reference one-shot) for the 512-bit variant.
func TestDiffStreamingAgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEF))
	for range 50 {
		n := rng.Intn(3000)
		msg := make([]byte, n)
		rng.Read(msg)

		h := streebog.New512()
		for off := 0; off < n; {
			chunk := rng.Intn(70) + 1
			end := min(off+chunk, n)
			h.Write(msg[off:end])
			off = end
		}
		got := h.Sum(nil)
		ref := gost.Streebog512(msg)
		if !bytes.Equal(got, ref) {
			t.Fatalf("streaming 512 mismatch len=%d\n clean-room %x\n oracle     %x", n, got, ref)
		}
	}
}

// TestDiffStreaming256AgainstGost exercises chunked Write against the one-shot
// oracle for the 256-bit variant, specifically exercising the 256-bit IV
// (all-0x01) and MSB_256 truncation under partial-buffer and multi-block state.
func TestDiffStreaming256AgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xCAFE))
	for range 50 {
		n := rng.Intn(3000)
		msg := make([]byte, n)
		rng.Read(msg)

		h := streebog.New256()
		for off := 0; off < n; {
			chunk := rng.Intn(70) + 1
			end := min(off+chunk, n)
			h.Write(msg[off:end])
			off = end
		}
		got := h.Sum(nil)
		ref := gost.Streebog256(msg)
		if !bytes.Equal(got, ref) {
			t.Fatalf("streaming 256 mismatch len=%d\n clean-room %x\n oracle     %x", n, got, ref)
		}
	}
}

// TestSumNonDestructiveParity verifies that Sum does not alter hash state on
// either side: calls Sum twice (must be equal), then writes more data, calls
// Sum again, and diffs against the oracle on the full concatenated input.
func TestSumNonDestructiveParity(t *testing.T) {
	msg1 := []byte("abc")
	msg2 := []byte("def")

	// Clean-room: Sum twice, then Write more, Sum again.
	h := streebog.New512()
	h.Write(msg1)
	d1a := h.Sum(nil)
	d1b := h.Sum(nil) // second Sum — must equal first
	if !bytes.Equal(d1a, d1b) {
		t.Fatalf("clean-room Sum mutated receiver: %x != %x", d1a, d1b)
	}
	h.Write(msg2)
	d2 := h.Sum(nil)

	// Oracle: hash of the concatenated input must equal d2.
	ref := gost.Streebog512(append(msg1, msg2...))
	if !bytes.Equal(d2, ref) {
		t.Fatalf("clean-room post-Sum Write mismatch\n got %x\n ref %x", d2, ref)
	}

	// The intermediate d1a must equal oracle of msg1 alone.
	ref1 := gost.Streebog512(msg1)
	if !bytes.Equal(d1a, ref1) {
		t.Fatalf("clean-room Sum(msg1) mismatch\n got %x\n ref %x", d1a, ref1)
	}

	// Repeat for the 256-bit variant.
	h256 := streebog.New256()
	h256.Write(msg1)
	d1a256 := h256.Sum(nil)
	d1b256 := h256.Sum(nil)
	if !bytes.Equal(d1a256, d1b256) {
		t.Fatalf("clean-room 256 Sum mutated receiver: %x != %x", d1a256, d1b256)
	}
	h256.Write(msg2)
	d2_256 := h256.Sum(nil)

	ref256 := gost.Streebog256(append(msg1, msg2...))
	if !bytes.Equal(d2_256, ref256) {
		t.Fatalf("clean-room 256 post-Sum Write mismatch\n got %x\n ref %x", d2_256, ref256)
	}
	ref1_256 := gost.Streebog256(msg1)
	if !bytes.Equal(d1a256, ref1_256) {
		t.Fatalf("clean-room 256 Sum(msg1) mismatch\n got %x\n ref %x", d1a256, ref1_256)
	}
}

// TestResetReuseParity verifies that Reset() produces the same result as a
// fresh digest, diffed against the oracle: hash msg1, sum (to trigger internal
// state), reset, hash msg2, diff result against oracle(msg2).
func TestResetReuseParity(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDEADBEEF))
	for range 20 {
		n := rng.Intn(300)
		msg1 := make([]byte, n)
		rng.Read(msg1)
		m2 := rng.Intn(300)
		msg2 := make([]byte, m2)
		rng.Read(msg2)

		// 512-bit reset-reuse.
		h512 := streebog.New512()
		h512.Write(msg1)
		_ = h512.Sum(nil) // consume once, then reset
		h512.Reset()
		h512.Write(msg2)
		got512 := h512.Sum(nil)
		ref512 := gost.Streebog512(msg2)
		if !bytes.Equal(got512, ref512) {
			t.Fatalf("512 reset-reuse mismatch len1=%d len2=%d\n got %x\n ref %x",
				n, m2, got512, ref512)
		}

		// 256-bit reset-reuse.
		h256 := streebog.New256()
		h256.Write(msg1)
		_ = h256.Sum(nil)
		h256.Reset()
		h256.Write(msg2)
		got256 := h256.Sum(nil)
		ref256 := gost.Streebog256(msg2)
		if !bytes.Equal(got256, ref256) {
			t.Fatalf("256 reset-reuse mismatch len1=%d len2=%d\n got %x\n ref %x",
				n, m2, got256, ref256)
		}
	}
}
