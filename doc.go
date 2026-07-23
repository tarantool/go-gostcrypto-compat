// Package gostcryptocompat is the GPL-3.0, gogost-backed implementation of the
// go-gostcrypto facade API.
//
// It exposes the same []byte-in/[]byte-out surface as
// github.com/tarantool/go-gostcrypto, but delegates every GOST primitive to the
// vendored gogost reference (go.stargrave.org/gogost/v7) instead of the
// clean-room BSD code. Import it when you want the reference backend; import
// go-gostcrypto for the pure-Go BSD one.
//
// This package — and the whole module — is GPL-3.0 because it links gogost. It
// is kept as a separate module from go-gostcrypto precisely so that GPL surface
// never enters go-gostcrypto's dependency graph. exports_gost.go is the gogost
// containment boundary: every gogost type that would otherwise appear in a
// caller's signature is wrapped here, so consumers import only this package.
//
// The parity/<primitive>/ subpackages are the module's other half: clean-room ↔
// gogost differential tests that diff go-gostcrypto against gogost byte-for-byte.
package gostcryptocompat
