# Vendored: github.com/aead/cmac

Source: https://github.com/aead/cmac (commit at clone time), MIT license (see
`LICENSE`). Andreas Auernhammer's CMAC / OMAC1 (RFC 4493 / NIST SP 800-38B)
over an arbitrary `crypto/cipher.Block`.

## Why it is vendored

Upstream predates Go modules and has no `go.mod`, and is unmaintained
(last commit 2016). It is wired in by a `replace` directive in the module
`go.mod`, the same pattern used for `third_party/gogost`.

## Why it is here at all

This module's `parity/omac` differential previously compared the clean-room
`gostcrypto/omac` only against the in-repo `gostcryptocompat.NewOMAC` oracle —
a *sibling* reimplementation. gogost ships no CMAC/OMAC, so there was no
independent oracle for the CMAC **mode** logic (subkey derivation, Write
buffering, K1/K2 finalization); a bug replicated in both in-repo twins would
pass every iteration (oracle-independence gap OMAC-01). `aead/cmac` is a
genuinely independent implementation and is used in `parity/omac` to close that
gap. It supports both 64-bit (Magma, Rb=0x1b) and 128-bit (Kuznyechik,
Rb=0x87) blocks and tag truncation.

## Local modifications

- Added `go.mod` (`module github.com/aead/cmac`) so the `replace` resolves.
- Dropped `xor_amd64.go` (unsafe `[]byte`→`[]uintptr` aliasing, old `// +build`
  syntax) and removed the `// +build !amd64` constraint from `xor.go`, so the
  portable XOR compiles on every architecture. Behaviour is identical; only the
  amd64 micro-optimization is gone, which is irrelevant for test-only code.
- `cmac.go` and `LICENSE` are upstream verbatim.

Test files (`cmac_test.go`, `vectors_test.go`, `xor_test.go`) and the `aes/`
sub-package were not vendored — only the importable `cmac` package is needed.
