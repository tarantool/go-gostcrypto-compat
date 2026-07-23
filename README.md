# go-gostcrypto-compat

[![CI](https://github.com/tarantool/go-gostcrypto-compat/actions/workflows/ci.yml/badge.svg)](https://github.com/tarantool/go-gostcrypto-compat/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tarantool/go-gostcrypto-compat.svg)](https://pkg.go.dev/github.com/tarantool/go-gostcrypto-compat)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

GPL-3.0 companion to [`go-gostcrypto`](https://github.com/tarantool/go-gostcrypto).
It holds everything that touches the GPL-licensed
`go.stargrave.org/gogost/v7` reference implementation, kept in a **separate
module** so `go-gostcrypto` itself stays pure-Go BSD-2-Clause with zero GPL in
its dependency graph.

Two things live here:

1. **Compatibility mode** — package `gostcryptocompat` (module root): a
   gogost-backed implementation of the `go-gostcrypto` facade API. Import this
   if you want the reference backend rather than the clean-room one. Same
   `[]byte`-in/`[]byte`-out surface as `go-gostcrypto`.
2. **Parity tests** — `parity/<primitive>/`: the clean-room ↔ gogost
   differential tests. Each imports the BSD clean-room primitive from
   `go-gostcrypto` and compares it against gogost byte-for-byte. This is the gate
   that proves `go-gostcrypto`'s BSD code matches the reference.

```
go-gostcrypto-compat/
  <facade>.go            package gostcryptocompat — gogost-backed facade + KAT/vector tests
  parity/<prim>/         clean-room (go-gostcrypto) ↔ gogost differential tests
  third_party/gogost/    vendored gogost (GPL-3.0)
```

## Requirements

- Go 1.24 or later.
- A checkout of [`go-gostcrypto`](https://github.com/tarantool/go-gostcrypto) as
  a sibling directory (`../go-gostcrypto`) — see below.
- Linux, macOS, or any other platform the Go toolchain supports; pure-Go, builds
  with `CGO_ENABLED=0`.

## Quick start

`go-gostcrypto` is co-developed and not yet published, and gogost is not
resolvable through the stock Go proxy, so both are wired in by `replace`
directives in `go.mod`:

```
replace github.com/tarantool/go-gostcrypto => ../go-gostcrypto
replace go.stargrave.org/gogost/v7        => ./third_party/gogost
```

Check `go-gostcrypto` out as a sibling directory (`../go-gostcrypto`), then:

```sh
go build ./...
go test  ./...      # facade KAT/vector tests + all parity tests
make test           # same, via the Makefile (see `make help`)
```

## Documentation

API documentation is published on
[pkg.go.dev](https://pkg.go.dev/github.com/tarantool/go-gostcrypto-compat).
Locally, browse it with `go doc -http=:6060`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, commit
message conventions, and the pre-push gate.

## Licensing

GPL-3.0. This module is a **combined work**: it links and vendors
`go.stargrave.org/gogost/v7`, which is GPL-3.0, so the whole module — the
`gostcryptocompat` facade and the parity tests alike — is GPL-3.0. It is kept as
a deliberately **separate module** from `go-gostcrypto` so this GPL surface never
enters `go-gostcrypto`'s dependency graph; `go-gostcrypto` itself stays
BSD-2-Clause and links none of this. See [LICENSE](LICENSE) for the full license
text.

gogost is Sergey Matveev's reference implementation, distributed only through his
own infrastructure (a GOPROXY behind a custom CA, and a SHA-256 git repository) —
neither resolves through the stock Go toolchain, so the v7.0.0 source is vendored
under `third_party/gogost` and wired in by the `replace` above. See
[third_party/gogost/UPSTREAM.md](third_party/gogost/UPSTREAM.md) for the exact
tag/commit and the update procedure.
