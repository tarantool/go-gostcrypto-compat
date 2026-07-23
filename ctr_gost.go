package gostcryptocompat

// CTR implements GOST R 34.13-2015 counter (CTR) mode over an arbitrary
// cipher.Block. A fresh CTR is constructed per record from the derived key and
// record IV; state is never carried across records.
//
// Counter increment: big-endian across the full block — the last byte
// increments first with carry propagating to lower-indexed bytes (matching
// gost-engine's ctr128_inc / ctr64_inc in gost_grasshopper_cipher.c).
//
// NewCTRACPKM adds intra-record ACPKM key meshing (RFC 8645, draft-irtf-cfrg-
// re-keying-12). Every sectionSize bytes the cipher key is refreshed by
// encrypting the fixed 32-byte ACPKM_D constant with the current key and
// adopting the result as the new key. This matches gost-engine's
// apply_acpkm_grasshopper / apply_acpkm_magma (gost_grasshopper_cipher.c:660,
// gost_crypt.c:814) — section_size is 4096 bytes for Kuznyechik and 1024
// bytes for Magma (gost_crypt.c:517, gost_grasshopper_cipher.c:334).

import (
	"crypto/cipher"
	"fmt"
)

// acpkmD is the fixed 32-byte constant fed to the current key's block cipher
// during ACPKM key refresh. gost-engine gost89.c:247 (ACPKM_D_const) and
// gost_grasshopper_cipher.c:155 (ACPKM_D_2018) — identical bytes.
var acpkmD = [32]byte{
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
}

// CTR holds per-record CTR state. Create one per record via NewCTR; discard
// after the record is processed.
type CTR struct {
	block cipher.Block
	// iv is the live counter — mutated in-place after each block encrypt.
	iv  []byte
	buf []byte // current gamma block (blockSize bytes), filled on demand
	num int    // bytes consumed from buf (0 means buf is exhausted)

	// ACPKM fields — populated only via NewCTRACPKM. Zero values disable
	// intra-record rekeying; the CTR then behaves as plain GOST-CTR.
	newBlock    func([]byte) cipher.Block // rebuild block with a fresh 32-byte key
	sectionSize int                       // bytes produced per key (0 = no ACPKM)
	sinceRekey  int                       // keystream bytes produced since last rekey
}

// NewCTR creates a new CTR stream cipher over block with the given iv.
// iv must be exactly block.BlockSize() bytes; any other length is an error.
func NewCTR(block cipher.Block, iv []byte) (*CTR, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, fmt.Errorf("gost/ctr: iv length %d does not match block size %d", len(iv), bs)
	}
	liveCtr := make([]byte, bs)
	copy(liveCtr, iv)
	return &CTR{
		block: block,
		iv:    liveCtr,
		buf:   make([]byte, bs),
		num:   0, // 0 == buf exhausted; generate on first call
	}, nil
}

// NewCTRACPKM creates a CTR with intra-record ACPKM key meshing enabled.
//
// newBlock builds a cipher.Block from a 32-byte key. key is the initial
// 32-byte cipher key. iv is block.BlockSize() bytes. sectionSize is the
// number of keystream bytes after which the key is refreshed; it must be a
// positive multiple of the block size. Pass sectionSize=0 to disable ACPKM
// (equivalent to NewCTR).
//
// Rekey rule (apply_acpkm_*): before generating the first keystream block
// whose cumulative byte count would reach or exceed sectionSize, derive a
// new 32-byte key by encrypting acpkmD with the current block (two 16-byte
// encrypts for Kuznyechik, four 8-byte encrypts for Magma), rebuild the
// block from that key, reset the byte counter. The counter IV is NOT
// reset by ACPKM — only by the TLSTree ctrl at record boundaries.
func NewCTRACPKM(
	newBlock func([]byte) cipher.Block,
	key []byte,
	iv []byte,
	sectionSize int,
) (*CTR, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("gost/ctr: ACPKM key length %d, want 32", len(key))
	}
	block := newBlock(key)
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, fmt.Errorf("gost/ctr: iv length %d does not match block size %d", len(iv), bs)
	}
	if sectionSize < 0 {
		return nil, fmt.Errorf("gost/ctr: negative sectionSize %d", sectionSize)
	}
	if sectionSize != 0 && sectionSize%bs != 0 {
		return nil, fmt.Errorf("gost/ctr: sectionSize %d not a multiple of block size %d", sectionSize, bs)
	}
	liveCtr := make([]byte, bs)
	copy(liveCtr, iv)
	return &CTR{
		block:       block,
		iv:          liveCtr,
		buf:         make([]byte, bs),
		num:         0,
		newBlock:    newBlock,
		sectionSize: sectionSize,
		sinceRekey:  0,
	}, nil
}

// rekeyACPKM derives the next key by encrypting acpkmD block-by-block with
// the current block cipher, then replaces the block with a fresh instance
// keyed on those 32 bytes. Counter IV is untouched.
func (c *CTR) rekeyACPKM() {
	bs := c.block.BlockSize()
	var newKey [32]byte
	for i := 0; i < 32; i += bs {
		c.block.Encrypt(newKey[i:i+bs], acpkmD[i:i+bs])
	}
	c.block = c.newBlock(newKey[:])
}

// XORKeyStream XORs each byte of src with the CTR gamma stream, writing the
// result into dst. dst and src must overlap entirely or not at all; len(dst)
// must be >= len(src).
func (c *CTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost/ctr: dst is shorter than src")
	}
	bs := c.block.BlockSize()
	for i, b := range src {
		if c.num == 0 {
			// Refresh the key once the previous section is fully consumed,
			// before generating the first block of the next section. Matches
			// gost-engine's apply_acpkm_grasshopper / apply_acpkm_magma:
			// the check runs at block boundaries (num is block-aligned when
			// a new gamma block is about to be generated), and sectionSize
			// is always a multiple of blockSize.
			if c.sectionSize > 0 && c.sinceRekey >= c.sectionSize {
				c.rekeyACPKM()
				c.sinceRekey = 0
			}
			// Generate next gamma block: encrypt the counter.
			c.block.Encrypt(c.buf, c.iv)
			// Increment the counter big-endian (last byte first, carry upward).
			incCounter(c.iv)
			c.sinceRekey += bs
		}
		dst[i] = b ^ c.buf[c.num]
		c.num++
		if c.num == bs {
			c.num = 0
		}
	}
}

// incCounter increments a big-endian counter in-place. The last byte carries
// upward — matching gost-engine's inc_counter / ctr128_inc / ctr64_inc.
func incCounter(ctr []byte) {
	for i := len(ctr) - 1; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			return
		}
	}
}
