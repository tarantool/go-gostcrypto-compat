package gostcryptocompat

// kexp15 — GOST 2018 key export (R 1323565.1.020-2018 §6.3.2).
//
// Implements gost_kexp15 (tmp/engine/gost_keyexpimp.c:34-109) for both the
// Magma (64-bit block) and Kuznyechik (128-bit block) variants.
//
// Algorithm (matching gost_keyexpimp.c:62-98):
//  1. iv_full = iv || zeros, padded to block_size.
//  2. mac = OMAC(mac_key, iv || shared_key), truncated to mac_len.
//  3. out = CTR(cipher_key, iv_full).XORKeyStream(shared_key || mac).

import (
	"crypto/cipher"
	"fmt"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
)

// KexpVariant selects the underlying block cipher for kexp15.
type KexpVariant int

const (
	// KexpKuznyechik uses Kuznyechik (GOST R 34.12-2015, 128-bit block).
	// iv_len=8, mac_len=16, block=16.
	KexpKuznyechik KexpVariant = iota

	// KexpMagma uses Magma (GOST R 34.12-2015, 64-bit block).
	// iv_len=4, mac_len=8, block=8.
	KexpMagma
)

// kexpParams holds the variant-specific constants.
type kexpParams struct {
	blockSize int
	ivLen     int
	macLen    int
}

func (v KexpVariant) params() (kexpParams, error) {
	switch v {
	case KexpKuznyechik:
		return kexpParams{blockSize: 16, ivLen: 8, macLen: 16}, nil
	case KexpMagma:
		return kexpParams{blockSize: 8, ivLen: 4, macLen: 8}, nil
	default:
		return kexpParams{}, fmt.Errorf("gost.Kexp15: unknown variant %d", v)
	}
}

// Kexp15 wraps a shared key for transport using gost_kexp15 from
// tmp/engine/gost_keyexpimp.c:34-109.
//
// Parameters:
//   - variant:    KexpKuznyechik or KexpMagma.
//   - sharedKey:  the key material to protect (any non-empty length).
//   - cipherKey:  32-byte CTR encryption key.
//   - macKey:     32-byte OMAC authentication key.
//   - iv:         initialization vector, exactly iv_len bytes for the variant.
//
// Returns len(sharedKey) + mac_len bytes.
func Kexp15(variant KexpVariant, sharedKey, cipherKey, macKey, iv []byte) ([]byte, error) {
	p, err := variant.params()
	if err != nil {
		return nil, err
	}

	if len(sharedKey) == 0 {
		return nil, fmt.Errorf("gost.Kexp15: sharedKey must not be empty")
	}
	if len(cipherKey) != 32 {
		return nil, fmt.Errorf("gost.Kexp15: cipherKey must be 32 bytes, got %d", len(cipherKey))
	}
	if len(macKey) != 32 {
		return nil, fmt.Errorf("gost.Kexp15: macKey must be 32 bytes, got %d", len(macKey))
	}
	if len(iv) != p.ivLen {
		return nil, fmt.Errorf("gost.Kexp15: iv must be %d bytes, got %d", p.ivLen, len(iv))
	}

	// Step 1: iv_full — pad iv with zeros to full block size.
	// (gost_keyexpimp.c:63-64: memset 0, memcpy iv)
	ivFull := make([]byte, p.blockSize)
	copy(ivFull, iv)

	// Instantiate the block cipher for the MAC and CTR layers.
	var macBlock, ctrBlock cipher.Block
	switch variant {
	case KexpKuznyechik:
		macBlock = gost3412128.NewCipher(macKey)
		ctrBlock = gost3412128.NewCipher(cipherKey)
	case KexpMagma:
		macBlock = gost341264.NewCipher(macKey)
		ctrBlock = gost341264.NewCipher(cipherKey)
	}

	// Step 2: MAC = OMAC(mac_key, iv || sharedKey), truncated to macLen.
	// (gost_keyexpimp.c:72-78: EVP_DigestUpdate iv then shared_key)
	omac, err := NewOMAC(macBlock, p.macLen)
	if err != nil {
		return nil, fmt.Errorf("gost.Kexp15: NewOMAC: %w", err)
	}
	if _, err := omac.Write(iv); err != nil {
		return nil, fmt.Errorf("gost.Kexp15: OMAC.Write(iv): %w", err)
	}
	if _, err := omac.Write(sharedKey); err != nil {
		return nil, fmt.Errorf("gost.Kexp15: OMAC.Write(sharedKey): %w", err)
	}
	mac := omac.Sum(nil) // mac_len bytes

	// Step 3: CTR-encrypt (sharedKey || mac) with iv_full.
	// (gost_keyexpimp.c:89-94: two EVP_CipherUpdate calls, sharedKey then mac_buf)
	plaintext := make([]byte, len(sharedKey)+p.macLen)
	copy(plaintext, sharedKey)
	copy(plaintext[len(sharedKey):], mac)

	ctr, err := NewCTR(ctrBlock, ivFull)
	if err != nil {
		return nil, fmt.Errorf("gost.Kexp15: NewCTR: %w", err)
	}
	out := make([]byte, len(plaintext))
	ctr.XORKeyStream(out, plaintext)

	return out, nil
}
