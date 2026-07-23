module github.com/tarantool/go-gostcrypto-compat

go 1.24

require (
	github.com/aead/cmac v0.0.0
	github.com/tarantool/go-gostcrypto v0.1.0
	go.stargrave.org/gogost/v7 v7.0.0
)

// go-gostcrypto is pinned to its published v0.1.0 and resolves through the
// public proxy — no replace needed.
//
// gogost and aead/cmac cannot resolve through the public proxy and are
// permanently vendored under third_party/, wired in by replace:
//   - gogost is distributed only through the author's own infrastructure
//     (custom-CA GOPROXY + SHA-256 git upstream), so it never resolves through
//     proxy.golang.org.
//   - aead/cmac predates Go modules (no go.mod, unmaintained); it is a
//     test-only OMAC/CMAC oracle (see third_party/cmac/VENDORING.md).
replace go.stargrave.org/gogost/v7 => ./third_party/gogost

replace github.com/aead/cmac => ./third_party/cmac
