package gostcryptocompat

// OMAC (CMAC per RFC 4493 / NIST SP 800-38B) implemented over an arbitrary
// cipher.Block. Supports both 64-bit (Magma, Rb=0x1b per RFC 8645 §4.1.1)
// and 128-bit (Kuznyechik, Rb=0x87 per RFC 4493 §2.3) block sizes.
//
// Tag truncation: gost_omac.c:48-56 in gost-engine; GOST R 34.13-2015 §A.1.6
// (Kuznyechik) and §A.2.6 (Magma) provide the standard KAT vectors.

import (
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// OMAC holds the state for an OMAC1/CMAC computation. It implements
// hash.Hash (Write / Sum / Reset / BlockSize / Size).
//
// Sum is non-destructive: it operates on a snapshot of the current state and
// does not mutate the receiver. Repeated calls to Sum return identical bytes.
type OMAC struct {
	block     cipher.Block
	blockSize int
	tagSize   int
	k1        []byte // CMAC subkey K1
	k2        []byte // CMAC subkey K2
	state     []byte // running CBC chain value (blockSize bytes)
	buf       []byte // pending bytes not yet incorporated into state
}

// NewOMAC returns an OMAC/CMAC instance using the given block cipher.
// tagSize must be in [1, block.BlockSize()]; an error is returned otherwise.
//
// K1 and K2 subkeys are precomputed here per RFC 4493 §2.3.
func NewOMAC(block cipher.Block, tagSize int) (*OMAC, error) {
	bs := block.BlockSize()
	if tagSize < 1 || tagSize > bs {
		return nil, fmt.Errorf("gost: NewOMAC: tagSize %d out of range [1, %d]", tagSize, bs)
	}

	k1, k2 := cmacSubkeys(block)
	return &OMAC{
		block:     block,
		blockSize: bs,
		tagSize:   tagSize,
		k1:        k1,
		k2:        k2,
		state:     make([]byte, bs),
		buf:       make([]byte, 0, bs),
	}, nil
}

// cmacSubkeys derives subkeys K1 and K2 per RFC 4493 §2.3.
// The reduction polynomial constant Rb is:
//   - 0x87 for 128-bit block (Kuznyechik) — x^128 + x^7 + x^2 + x + 1
//   - 0x1b for 64-bit block (Magma) — x^64 + x^4 + x^3 + x + 1 (RFC 8645 §4.1.1)
func cmacSubkeys(block cipher.Block) (k1, k2 []byte) {
	bs := block.BlockSize()

	// L = Encrypt(0^bs)
	L := make([]byte, bs)
	block.Encrypt(L, L)

	var rb byte
	switch bs {
	case 16:
		rb = 0x87
	case 8:
		rb = 0x1b
	default:
		panic(fmt.Sprintf("gost: OMAC: unsupported block size %d (want 8 or 16)", bs))
	}

	k1 = shiftLeftXorRb(L, rb)
	k2 = shiftLeftXorRb(k1, rb)
	return k1, k2
}

// shiftLeftXorRb returns (in << 1) XOR (Rb if MSB(in) == 1, else 0).
// Input is treated as a big-endian bit string (MSB of in[0] is the leading bit).
func shiftLeftXorRb(in []byte, rb byte) []byte {
	out := make([]byte, len(in))
	msb := in[0] >> 7 // 1 if MSB set, 0 otherwise
	for i := 0; i < len(in)-1; i++ {
		out[i] = (in[i] << 1) | (in[i+1] >> 7)
	}
	out[len(in)-1] = in[len(in)-1] << 1
	if msb == 1 {
		out[len(in)-1] ^= rb
	}
	return out
}

// Write adds data to the running MAC state.
// Full block-sized chunks are immediately incorporated into the CBC chain.
// A trailing partial (or full) block is held in buf until the next Write or Sum.
//
// Invariant: after Write, len(buf) is in [0, blockSize]. A full block in buf
// is intentional — Sum needs to distinguish "exactly blockSize unprocessed
// bytes" (K1 path) from "less than blockSize" (K2/padding path).
func (o *OMAC) Write(p []byte) (int, error) {
	total := len(p)

	for len(p) > 0 {
		// Fill buf up to blockSize.
		free := o.blockSize - len(o.buf)
		take := min(free, len(p))
		o.buf = append(o.buf, p[:take]...)
		p = p[take:]

		// If buf is full AND there is still more data, process it now.
		// We must not process the last chunk here because we cannot know yet
		// whether it will remain the final block (K1) or be followed by more.
		if len(o.buf) == o.blockSize && len(p) > 0 {
			cbcStep(o.block, o.state, o.buf)
			o.buf = o.buf[:0]
		}
	}

	return total, nil
}

// cbcStep XORs blk into state and encrypts in place.
// state and blk must both be len(blockSize). state is modified in place.
func cbcStep(block cipher.Block, state, blk []byte) {
	subtle.XORBytes(state, state, blk)
	block.Encrypt(state, state)
}

// Sum appends the current MAC to b and returns the result.
// Sum is non-destructive: it works on copies of state and buf and does not
// modify the receiver. Repeated calls without intervening Writes return the
// same bytes.
func (o *OMAC) Sum(b []byte) []byte {
	// Take a snapshot of the running state so we do not mutate the receiver.
	stateSnap := make([]byte, o.blockSize)
	copy(stateSnap, o.state)
	bufSnap := make([]byte, len(o.buf))
	copy(bufSnap, o.buf)

	var finalBlock []byte
	if len(bufSnap) == o.blockSize {
		// Complete block: XOR with K1.
		finalBlock = xorBytes(bufSnap, o.k1)
	} else {
		// Partial (or empty) block: pad with 0x80 0x00… then XOR with K2.
		padded := make([]byte, o.blockSize)
		copy(padded, bufSnap)
		padded[len(bufSnap)] = 0x80
		// rest is already zero
		finalBlock = xorBytes(padded, o.k2)
	}

	cbcStep(o.block, stateSnap, finalBlock)

	return append(b, stateSnap[:o.tagSize]...)
}

// xorBytes returns a XOR b (same length). Both slices must have the same length.
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	subtle.XORBytes(out, a, b)
	return out
}

// Reset re-initialises the OMAC state to zero (as if freshly constructed).
// K1/K2 subkeys are preserved.
func (o *OMAC) Reset() {
	for i := range o.state {
		o.state[i] = 0
	}
	o.buf = o.buf[:0]
}

// BlockSize returns the block size of the underlying cipher.
// Satisfies hash.Hash.
func (o *OMAC) BlockSize() int { return o.blockSize }

// Size returns the tag size in bytes.
// Satisfies hash.Hash.
func (o *OMAC) Size() int { return o.tagSize }
