# Contribution Guide

## First steps

The project requires Go 1.24 or later. It is a GPL-3.0 module that links the
gogost reference implementation.
[`go-gostcrypto`](https://github.com/tarantool/go-gostcrypto) is an ordinary
dependency: `go.mod` pins a published release that resolves through the public
Go proxy, so a clone of this repository is all you need.

```sh
$ git clone https://github.com/tarantool/go-gostcrypto-compat
$ cd go-gostcrypto-compat
$ go build ./...
```

### Working against a local go-gostcrypto

A change that needs an unreleased `go-gostcrypto`, such as parity tests for a
`go-gostcrypto` change under review, is built against a local `go-gostcrypto`
tree. Clone it next to this module and span both in a Go workspace:

```sh
$ git clone https://github.com/tarantool/go-gostcrypto ../go-gostcrypto
$ go work init . ../go-gostcrypto
$ go build ./...
$ go test ./...
```

CI does the same: `parity-engine.yml` and `bump-gost-engine.yml` check
`go-gostcrypto` out next to this module and run `go work init . ../gostcrypto`.
The workspace overrides the pinned release for every `go` command run in this
directory; the `replace` directives for the vendored gogost and `aead/cmac`
still apply. `go.work` and `go.work.sum` are local and ignored by git: never
commit them. Set `GOWORK=off` to use the pinned release for a single command,
or delete both files to drop the workspace.

## The GPL boundary

This module is the deliberate home for everything that touches the GPL-licensed
`go.stargrave.org/gogost/v7`, so `go-gostcrypto` itself can stay BSD-2-Clause
with zero GPL in its dependency graph. Two rules follow:

- Anything added here that imports or derives from gogost keeps this module
  GPL-3.0. Do not copy gogost-derived code back into `go-gostcrypto`.
- The reverse of the sibling's rule applies: here gogost is **allowed** (the
  `depguard` config in `.golangci.yml` lists it). Nothing outside the vendored
  `third_party/` and the allow-list should sneak in new external dependencies.

## Branch naming conventions

When creating feature branches, follow these naming patterns:

- `<user.name>/gh-<issue-id>-short-description` (for GitHub issues)
- `<user.name>/gh-no-short-description` (for work not tied to an issue)

For release branches, use:

- `<user.name>/release-v<version>`

Replace `<user.name>` with your Git username, `<issue-id>` with the issue
number, and `<short-description>` with a brief description using lowercase,
hyphen-separated words. Do not use any symbols except numbers, letters and
dashes.

## Running tests

```sh
# Facade KAT/vector tests + all clean-room ↔ gogost parity tests:
make test

# Run the tests for a specific package (e.g., streebog parity):
go test ./parity/streebog/

# Run a single test:
go test ./parity/streebog/ -run Differential -v

# Bypass the build cache:
go test -count=1 ./...
```

Every primitive is validated against known-answer test (KAT) vectors and, in the
parity suites, diffed byte-for-byte against gogost. A bugfix must ship with a
regression test based on a reproducer.

### Fuzzing

Every `parity/<prim>/` package ships a differential `Fuzz` target alongside its
table tests. `make test` replays only the committed seed corpus; `make fuzz`
drives active fuzzing.

```sh
make fuzz FUZZTIME=1m
make fuzz PKG=./parity/mgm/ FUZZTIME=2m
```

## Linting and formatting

The project uses `golangci-lint` v2 with a strict `default: all` configuration
(individual linters disabled with a documented reason) and `goimports` for
formatting.

```sh
make lint       # run golangci-lint
make lint-fix   # apply autofixes
make fmt        # gofmt in place
make vet        # go vet
```

The set of allowed imports is pinned by the `depguard` linter in
`.golangci.yml`. Unlike `go-gostcrypto`, this module intentionally allows gogost
and the vendored `aead/cmac` oracle; keep the allow-list minimal.

## The pre-push gate

```sh
make ci   # lint + vet + test
```

## Commit message guidelines

Commit messages have a subject, a body and issue references.

- Subject: `prefix: short description` — a short prefix, colon, space, and a
  lowercase subject in the imperative mood that completes "If applied, this
  commit will …". Keep it within ~50 characters, no trailing period. Typical
  prefixes: `parity`, `facade`, `ci`, `tests`, `doc`, plus per-primitive
  prefixes such as `streebog:` or `mgm:`.
- Body: separated from the subject by a blank line, wrapped at ~72 characters.
  Explain what and why, not how.
- Issue references go in the last lines of the body, not the subject. Use
  `Part of #NNN` on intermediate commits and `Closes #NNN` on the final commit
  of a pull request.
- Use your real name and a working email address. Each commit is atomic and
  logically complete.

## Pull request process

1. Fork the repository and create a feature branch.
2. Ensure your code passes `make ci`.
3. Update `CHANGELOG.md` with a brief, user-facing description of your changes.
4. Open a pull request with a clear description of the change and its purpose.
