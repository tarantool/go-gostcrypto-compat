// Differential test: cross-check the clean-room GOST R 34.11-94 implementation
// against the in-repo gogost-backed oracle gostcryptocompat.GOSTR341194 (used here
// strictly as a BLACK BOX — its source is not read).
//
// EMPTY INPUT IS EXCLUDED on purpose. gogost and gost-engine disagree on the
// degenerate empty-message finalization (guide D1): gogost yields 981e5f3c…,
// gost-engine/Tarantool yields 3f25bc1f…. The clean-room implementation matches
// the ENGINE value (pinned in the KAT in gostr341194_test.go), so diffing it
// against the gogost oracle on empty input would (correctly) disagree. We
// therefore compare only NON-empty messages here, where gogost and the engine
// agree bit-for-bit.
package gostr341194parity

import (
	"bytes"
	"math/rand"
	"testing"

	. "github.com/tarantool/go-gostcrypto/gostr341194"

	gost "github.com/tarantool/go-gostcrypto-compat"
)

func TestDiffAgainstInternalGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))

	// Deterministic spread of lengths around block boundaries plus random
	// lengths, all strictly > 0 (empty is the documented D1 divergence).
	lengths := []int{1, 2, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1023, 1024, 2100}
	for range 200 {
		lengths = append(lengths, 1+rng.Intn(4096))
	}

	for _, n := range lengths {
		msg := make([]byte, n)
		rng.Read(msg)

		want := gost.GOSTR341194(msg) // black-box oracle
		got := Sum(msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", n, got[:], want)
		}
	}
}

// FuzzDiffAgainstInternalGost is the fuzzing companion to
// TestDiffAgainstInternalGost / TestDiffStreaming: it diffs the clean-room
// GOST R 34.11-94 against the gostcryptocompat black-box oracle over a
// fuzzer-chosen message, both one-shot and three-way streaming (two fuzzer-
// chosen split offsets — R94-04: lets the fuzzer explore the buf-fill-and-drain
// transition across three consecutive Writes, covering partial-block carry-over
// sequences that a single split cannot reach).
//
// EMPTY INPUT IS EXCLUDED (skipped) here for the same reason the Test func only
// uses lengths > 0: gogost and gost-engine disagree on the degenerate
// empty-message finalization (guide D1), and the clean-room implementation
// matches the ENGINE value, not the gogost oracle. That divergence is the known
// documented one, so we structure the fuzz to avoid it rather than asserting on
// it.
func FuzzDiffAgainstInternalGost(f *testing.F) {
	// Seeds carry three params after R94-04: msg, split, split2.
	// All seeds are non-empty (D1 exclusion).
	f.Add([]byte{0x00}, uint(0), uint(0))
	f.Add([]byte("This is message, length=32 bytes"), uint(13), uint(5))
	f.Add(bytes.Repeat([]byte{0xa5}, 257), uint(64), uint(100))
	// Extra seed reaching the multi-block carry-over path (three-Write with a
	// partial first chunk, a full-block-aligned second chunk, partial third).
	f.Add(bytes.Repeat([]byte{0x5a}, 65), uint(7), uint(32))

	f.Fuzz(func(t *testing.T, msg []byte, split uint, split2 uint) {
		if len(msg) == 0 {
			t.Skip("empty input is the documented D1 gogost/engine divergence")
		}

		want := gost.GOSTR341194(msg) // black-box oracle (one-shot)

		// One-shot clean-room.
		got := Sum(msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("one-shot len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", len(msg), got[:], want)
		}

		// Three-way streaming split (R94-04): two fuzzer-chosen offsets, yielding
		// three Write calls that exercise the buf-fill-and-drain carry-over path.
		n := len(msg)
		off1 := int(split % uint(n+1))
		remaining := n - off1
		var off2 int
		if remaining == 0 {
			off2 = off1
		} else {
			off2 = off1 + int(split2%uint(remaining+1))
		}
		h := New()
		h.Write(msg[:off1])
		h.Write(msg[off1:off2])
		h.Write(msg[off2:])
		gotStream := h.Sum(nil)
		if !bytes.Equal(gotStream, want) {
			t.Fatalf("streaming len=%d (off1=%d off2=%d) mismatch:\n clean-room %x\n gostcryptocompat %x", n, off1, off2, gotStream, want)
		}
	})
}

// TestDiffStreaming feeds the same random messages through the streaming
// hash.Hash interface in odd chunk sizes and diffs against the oracle.
func TestDiffStreaming(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234))
	for range 100 {
		n := 1 + rng.Intn(2048)
		msg := make([]byte, n)
		rng.Read(msg)

		h := New()
		for off := 0; off < len(msg); {
			chunk := 1 + rng.Intn(40)
			end := min(off+chunk, len(msg))
			h.Write(msg[off:end])
			off = end
		}
		got := h.Sum(nil)
		want := gost.GOSTR341194(msg)
		if !bytes.Equal(got, want) {
			t.Fatalf("streaming len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", n, got, want)
		}
	}
}

// TestDiffReset verifies R94-01: Reset() followed by re-hashing must produce
// the same digest as a fresh instance, and both must match the gogost oracle.
// Guards against a partial-clear refactor of Reset leaving a stale field (e.g.
// forgetting nbuf or sum in a future per-field clear).
func TestDiffReset(t *testing.T) {
	rng := rand.New(rand.NewSource(0x4E5E7))
	oracle := gost.NewGOSTR341194CryptoProHash() // gogost-backed hash.Hash

	for range 50 {
		// First message — non-empty to stay outside the D1 divergence.
		n1 := 1 + rng.Intn(512)
		msg1 := make([]byte, n1)
		rng.Read(msg1)

		// Second message — non-empty.
		n2 := 1 + rng.Intn(512)
		msg2 := make([]byte, n2)
		rng.Read(msg2)

		// Clean-room: hash msg1, Reset, hash msg2.
		h := New()
		h.Write(msg1)
		h.Reset()
		h.Write(msg2)
		gotAfterReset := h.Sum(nil)

		// Oracle: same sequence.
		oracle.Write(msg1)
		oracle.Reset()
		oracle.Write(msg2)
		wantAfterReset := oracle.Sum(nil)
		oracle.Reset()

		if !bytes.Equal(gotAfterReset, wantAfterReset) {
			t.Fatalf("post-Reset len=%d mismatch:\n clean-room %x\n gogost     %x", n2, gotAfterReset, wantAfterReset)
		}

		// Also verify it matches a freshly-constructed hash of msg2.
		fresh := Sum(msg2)
		if !bytes.Equal(gotAfterReset, fresh[:]) {
			t.Fatalf("Reset result differs from fresh hash for len=%d:\n after-Reset %x\n fresh       %x", n2, gotAfterReset, fresh[:])
		}
	}
}

// TestSumNonDestructive verifies R94-02: guide D8 states that Sum mid-stream
// must not corrupt the in-progress hash state so that subsequent Writes and a
// second Sum still produce the correct digest. Both the clean-room and the gogost
// oracle are non-destructive; this test ensures they agree on both the
// intermediate and final digests, catching any future regression on either side.
func TestSumNonDestructive(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDEAD))

	for range 50 {
		n := 1 + rng.Intn(2048)
		msg := make([]byte, n)
		rng.Read(msg)

		// Choose a split point to call Sum mid-stream.
		split := rng.Intn(n + 1) // 0..n inclusive

		// Clean-room: write first half, take intermediate Sum, write second half, take final Sum.
		h := New()
		h.Write(msg[:split])
		midSum := h.Sum(nil) // must not destroy state
		h.Write(msg[split:])
		finalSum := h.Sum(nil)

		// Oracle: same Write→Sum→Write→Sum sequence.
		og := gost.NewGOSTR341194CryptoProHash()
		og.Write(msg[:split])
		ogMid := og.Sum(nil)
		og.Write(msg[split:])
		ogFinal := og.Sum(nil)

		// Mid-stream digests must match each other.
		if !bytes.Equal(midSum, ogMid) {
			t.Fatalf("mid-stream split=%d len=%d mismatch:\n clean-room %x\n oracle     %x", split, n, midSum, ogMid)
		}
		// Final digests must match each other.
		if !bytes.Equal(finalSum, ogFinal) {
			t.Fatalf("post-mid-Sum final split=%d len=%d mismatch:\n clean-room %x\n oracle     %x", split, n, finalSum, ogFinal)
		}
		// Final digest must equal the one-shot oracle over the full message.
		wantFull := gost.GOSTR341194(msg)
		if !bytes.Equal(finalSum, wantFull) {
			t.Fatalf("post-mid-Sum final split=%d len=%d differs from one-shot:\n got  %x\n want %x", split, n, finalSum, wantFull)
		}
	}
}

// TestSumAppendPrefix verifies R94-03: hash.Hash.Sum(in) must append the digest
// to in (prefix-preserving). Both clean-room and oracle implement
// `return append(in, digest[:]...)` but the parity test never exercised the
// non-nil prefix path. This test diffs both sides with a fixed non-nil prefix
// and asserts that the prefix bytes are preserved and the appended digests match.
func TestSumAppendPrefix(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEF))
	prefix := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	for range 50 {
		n := 1 + rng.Intn(512)
		msg := make([]byte, n)
		rng.Read(msg)

		// Clean-room.
		h := New()
		h.Write(msg)
		gotWithPrefix := h.Sum(prefix)

		// Oracle.
		og := gost.NewGOSTR341194CryptoProHash()
		og.Write(msg)
		wantWithPrefix := og.Sum(prefix)

		// The appended results must be identical.
		if !bytes.Equal(gotWithPrefix, wantWithPrefix) {
			t.Fatalf("Sum(prefix) mismatch len=%d:\n clean-room %x\n oracle     %x", n, gotWithPrefix, wantWithPrefix)
		}
		// The prefix bytes must be preserved at the start.
		if !bytes.Equal(gotWithPrefix[:len(prefix)], prefix) {
			t.Fatalf("Sum(prefix) dropped prefix len=%d: got %x", n, gotWithPrefix[:len(prefix)])
		}
		// The appended suffix must match the one-shot oracle digest.
		wantDigest := gost.GOSTR341194(msg)
		if !bytes.Equal(gotWithPrefix[len(prefix):], wantDigest) {
			t.Fatalf("Sum(prefix) appended wrong digest len=%d:\n got  %x\n want %x", n, gotWithPrefix[len(prefix):], wantDigest)
		}
	}
}
