# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public release of `go-gostcrypto-compat`: the GPL-3.0 companion
  module to [`go-gostcrypto`](https://github.com/tarantool/go-gostcrypto).
- Compatibility mode — package `gostcryptocompat`: a gogost-backed
  implementation of the `go-gostcrypto` facade API, with the same
  `[]byte`-in/`[]byte`-out surface, for callers who want the reference backend.
- Parity tests under `parity/<primitive>/`: clean-room ↔ gogost differential
  suites for every GOST primitive (Streebog, Kuznyechik, Magma, GOST 28147-89,
  GOST R 34.10 sign/VKO, CTR, CTR-ACPKM, OMAC, MGM, IMIT, KDFTree, TLSTree, KEG,
  KExp15, CryptoPro key wrap, GOST R 34.11-94), each with a companion
  differential `Fuzz` target and committed seed corpus.
- Facade KAT/vector tests ported from the gost-engine reference vector suite.
- The GPL surface (`go.stargrave.org/gogost/v7`) is vendored under
  `third_party/gogost` and kept out of `go-gostcrypto`'s dependency graph by
  living in this separate module.
