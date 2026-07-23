package gostcryptocompat

// TLSTree wrappers for RFC 9367 per-record key derivation.
//
// Two param sets are supported:
//   - TLSGOSTR341112256WithKuznyechikCTROMAC  (RFC 9367 §4.3)
//   - TLSGOSTR341112256WithMagmaCTROMAC       (RFC 9367 §4.4)
//
// A new TLSTree is created per direction (client→server, server→client) and
// per key type (enc, mac) — four trees total per connection.

import (
	"go.stargrave.org/gogost/v7/gost34112012256"
)

// TLSTree wraps a gogost TLSTree and ensures Derive returns a fresh slice that
// does not alias gogost's internal key buffer.
type TLSTree struct {
	inner *gost34112012256.TLSTree
}

// NewTLSTreeKuznyechikCTROMAC creates a TLSTree for the
// TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC cipher suite (RFC 9367 §4.3).
// masterKey must be exactly 32 bytes; any other length is a programmer error
// and panics.
func NewTLSTreeKuznyechikCTROMAC(masterKey []byte) *TLSTree {
	if len(masterKey) != 32 {
		panic("gost/tlstree: masterKey must be 32 bytes for KuznyechikCTROMAC")
	}
	return &TLSTree{
		inner: gost34112012256.NewTLSTree(
			gost34112012256.TLSGOSTR341112256WithKuznyechikCTROMAC,
			masterKey,
		),
	}
}

// NewTLSTreeMagmaCTROMAC creates a TLSTree for the
// TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC cipher suite (RFC 9367 §4.4).
// masterKey must be exactly 32 bytes; any other length is a programmer error
// and panics.
func NewTLSTreeMagmaCTROMAC(masterKey []byte) *TLSTree {
	if len(masterKey) != 32 {
		panic("gost/tlstree: masterKey must be 32 bytes for MagmaCTROMAC")
	}
	return &TLSTree{
		inner: gost34112012256.NewTLSTree(
			gost34112012256.TLSGOSTR341112256WithMagmaCTROMAC,
			masterKey,
		),
	}
}

// Derive returns a fresh 32-byte key for the given TLS record sequence number.
// The returned slice is an independent copy; it does not alias gogost's
// internal buffer. Callers must not retain the slice across the next Derive
// call if they share the TLSTree, but a fresh copy is safe to hold.
func (t *TLSTree) Derive(seqNum uint64) []byte {
	// gogost's DeriveCached returns a slice pointing into internal state;
	// calling it again on the same tree overwrites the buffer. Copy here.
	key, _ := t.inner.DeriveCached(seqNum)
	out := make([]byte, 32)
	copy(out, key)
	return out
}
