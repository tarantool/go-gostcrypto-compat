# Vendored: go.stargrave.org/gogost/v7

Source:  git://git.stargrave.org/gogost.git
Mirror:  anongit@master.git.stargrave.org:stargrave.org/gogost.git
Tag:     v7.0.0
Commit:  423c8222805794f7a46f13551f2637d76a1e0aa6590b2230c29625646e08e236
License: GPL-3.0 (see COPYING)

Vendored because go.stargrave.org is served only via the upstream GOPROXY
(proxy.go.stargrave.org) behind a custom CA the stock Go TLS stack rejects,
and the repo is SHA-256 (incompatible with git subtree into a SHA-1 repo).
Wired in via a relative `replace` in the root go.mod.

To update: `just gogost-update <tag>` (see justfile).
