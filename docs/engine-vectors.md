# gost-engine v3.0.5 vector port

Source: `tmp/engine/` (tag v3.0.5, commit 09fdd53). Not committed to this repo.
Moved from v3.0.3 (commit e0a500a); see "Last move" below.

## Engine versions in CI

`.github/gost-engine.json` names gost-engine tags in two roles:

- `vectors` is the tag the vectors in this file were ported from. They are
  constants in the test files, so a new engine release does not change them.
  The entry moves only in the commit that re-ports them (see below).
- `latest` is the newest gost-engine release. `bump-gost-engine.yml` checks
  for a new one daily, runs the parity suite against it, and if that passes
  opens a pull request that moves this entry.

`.github/workflows/parity-engine.yml` builds the engine at each of these
tags (once, if both name the same tag) and runs `go test ./...` with it. Only
the tests that run the live engine depend on its version: today that is
`parity/gost28147cnt`'s `TestDiff_GostEngineCLI`, which runs `openssl enc
-engine gost` and skips when the engine is missing. The ported vectors give
the same result with any engine, or with none.

The workflow is called by go-gostcrypto's `parity` workflow for every
go-gostcrypto change, and by `engine.yml` here when a change touches the
setup-gost-engine action, the versions file or these workflows.

### Moving the vector source

1. Clone the new tag into `tmp/engine/`, which git ignores:
   `git clone --branch vX.Y.Z --recurse-submodules https://github.com/gost-engine/engine.git tmp/engine`.
   A full clone also brings the old tag for the diff below.
2. Diff the engine tests against the old tag, e.g.
   `git -C tmp/engine diff v3.0.5 vX.Y.Z -- test tcl_tests`, port what changed
   into the test files listed below, and regenerate the vectors that were
   produced by running the engine (KEG-03, KWP-01/02). Where the engine cannot
   be run, diff the code path of each of these vectors between the two tags
   instead (the KEG-03 and KWP-01/02 sections list it) and keep the vector only
   if that path is unchanged in output.
3. Update this file: the title, the `Source:` line and the version numbers in
   the sections below.
4. In the same commit, set `vectors` in `.github/gost-engine.json` to the new
   tag.

### Last move: v3.0.3 → v3.0.5

`git diff v3.0.3 v3.0.5 -- test tcl_tests` holds no changed expected value for
the primitives below. What changed:

- `test/00-engine.t`, `01-digest.t`, `02-mac.t`, `03-encrypt.t`: scratch files
  are prefixed with the test target (`$ARGV[0]-`), so the engine and provider
  runs do not collide; `00-engine.t` lists `magma-ctr-acpkm-omac` once more.
- `test/04-pkey.t`: runs as `engine` or `provider`; the `derive` subtest gains
  a column of provider ECDHE hashes for the nine tc26 entries and checks that
  each derive succeeds; the line numbers shift by 5 to 20.
- New and out of scope: `test/05-tls13.t` and `tcl_tests/tls13.try` (TLS 1.3
  against live servers, no KATs), `test/pkcs12_rfc9337.sh` and
  `test/pkcs12_cross_mode_parity.sh` (PKCS#12 round-trips, no KATs),
  `tcl_tests/provider.try` (provider algorithm listing), the helpers
  `test/ProcessInteractor.pm`, `test/Utils.pm`, `tcl_tests/is_openssl_bug.tcl`.
- `tcl_tests/mac.try`: the gost-mac tests go through a `mac_testcase` helper
  that also drives `openssl mac` for the provider; the tag-size tests swap
  `-macopt size:` and `-sigopt size:` spellings, which adds one tag (2-byte
  gost-mac, `ad9a`); a duplicate "sigopt overrides macopt" test was dropped;
  the wrong-key-length tests no longer match the error text; the line numbers
  shift by 17.
- `tcl_tests/dgst.try`: a signature list for the provider target, and the
  wrong-digest signing test no longer matches the error text; the line numbers
  shift by 5.
- `tcl_tests/enc.try`: the shebang only.
- The other `.try` files: `engine_name` renamed to `test_target_name`, provider
  algorithm lists and skips (`ca`, `pkcs8`, `req-genpkey`, `req-newkey`,
  `engine`); no vectors.

Outside `test/` and `tcl_tests/`, `test_keyexpimp.c` was renamed to
`test_tls12additional.c` (its KDF_TREE and Magma KExp15 etalons unchanged),
which the KDF-02 and KXP-01 references below follow.

## test/01-digest.t + tcl_tests/dgst.try

Ported: 8 Streebog-256, 8 Streebog-512, 5 GOST R 34.11-94 vectors.
Also ported from tcl_tests/mac.try: 1 HMAC-Streebog-512, 1 HMAC-GOST R 34.11-94.
All live in `engine_hash_vectors_test.go`.

Skipped: GOSTR341194 empty-input vector (see Disagreements below).

Surprises / fixes:
- The carry-propagation test vector (dgst_CF.dat / `etalon/carry`) was originally
  hardcoded as 130 bytes in the test file instead of the correct 128 bytes. The
  error was 64×0xEE + 0x16 + **64**×0x11 + 0x16 (wrong) vs
  64×0xEE + 0x16 + **62**×0x11 + 0x16 (correct per `etalon/carry`).
  Corrected and all carry vectors now pass.

## test/02-mac.t + tcl_tests/mac.try

Ported to `primitives_engine_vectors_test.go`:
- gost-mac (SboxDefault = CryptoPro-A): 9 vectors — sizes 1–8 bytes (testdata.dat).
- gost-mac-12 (tc26-Z): 8 vectors — sizes 1–8 bytes (testdata.dat).
- mac.try gost-mac and gost-mac-12, key `12345678901234567890123456789012`:
  - `TestGost_GOST28147_IMIT_Wrapper_MacTry`, 4 vectors through the
    `GOST28147_IMIT` wrapper (CryptoPro-A, 4 bytes): dgst.dat (2100 bytes,
    key meshing) `37f646d2`, dgst0.dat (empty) `00000000`, dgst2.dat `87ea321f`,
    dgst8.dat `ad9aeae0`.
  - `TestGost_GOST28147_IMIT_MacTry_SboxAndSize`, 6 vectors on dgst8.dat through
    gogost's raw MAC plus the engine's trailing zero block: CryptoPro-A sizes
    8, 3 and 2 (`ad9a`, new in v3.0.5), tc26-Z sizes 4 and 6, CryptoPro-B size 4.

  The other mac.try gost-mac tests repeat one of these tags with another
  option spelling (hexkey, paramset, -sigopt).

Skipped: magma-mac and kuznyechik-mac (OMAC/CMAC) — out of scope.

Previously a disagreement on testbig.dat (266240 bytes, `5efab81f` vs `383059e8`) —
resolved 2026-04-20 by reimplementing `GOST28147_IMIT` with CryptoPro key meshing
(RFC 4357 §2.3.2, engine ref: `gost_crypt.c:1547-1561` in 3.0.5, `1510-1524` in
3.0.3; `mac_block_mesh`, `gost_imit_update` and `gost_imit_final` differ between
the two only in the context type). Validated by
`TestGost_GOST28147_IMIT_Wrapper_KeyMeshing`. gogost's raw `gost28147.MAC` still
lacks meshing, so that vector remains skipped in the raw-MAC loop.

The mac.try vectors were skipped until the v3.0.5 port: `37f646d2` for dgst.dat
"did not match any S-box". Re-checked 2026-11-20: gogost's raw MAC gives
`ab1fbf88` there, because it lacks the key meshing that the 2100-byte dgst.dat
needs, and it also lacks the engine's short-message finalization that dgst2.dat
and dgst8.dat need. With both, all 10 distinct tags reproduce, using the same
32 ASCII key bytes and the expected S-boxes.

## test/03-encrypt.t

Ported to `primitives_engine_vectors_test.go`:
- gost89-cnt (CryptoPro-A S-box): 2 vectors (paramset argument confirmed to have no effect).
- gost89-cnt-12 (tc26-Z S-box): 2 vectors.

Skipped: CFB mode (gost89 with paramset A/B/C/D) — not used in our TLS suites.
Skipped: CBC mode (gost89-cbc with paramset A/B/C/D) — not used in our TLS suites.
Skipped: magma-ctr (from tcl_tests/enc.try) — no Magma CTR wrapper in our primitives layer.

## test/04-pkey.t

Ported to `primitives_pkey_vectors_test.go`:
- R 34.10-2001 verify KAT using RFC 7091 §A.1 TestParamSet vector (1 PASS).
- R 34.10-2001 sign+verify round-trip via R341012Sign wrapper (1 PASS).
- Tamper-rejection check (1 PASS).

Skipped: all pkey 'keys' subtest vectors — text-output matching of PEM/DER key fields;
no raw cryptographic KAT extractable.

Skipped: all VKO 'derive' subtest vectors — expected values are sha256 of the
derived key, not raw shared-key bytes. Private keys are PEM-encoded; extracting the
LE raw bytes requires ASN.1 DER parsing outside the scope of this porting task.

Skipped: the ECDHE 'derive' column added in v3.0.5 (provider mode only: the X
coordinate of priv·pub with no UKM, `ecdhe_derive` in `gost_prov_keyexch.c`, for
the TLS 1.3 key exchange) — sha256 of the output on PEM keys, as above, and TLS 1.3
ECDHE is not used in our TLS suites.

Skipped: R 34.10-2012-512 sign/verify — our Phase-1 wrapper exposes only 256-bit sign.

## Parity-audit remediation — newly-ported vectors (2026-06-10)

The 18 parity lanes added the following external-anchor KATs. These are distinct
from the engine-vector suite above; they live in `parity/<prim>/` test files
rather than `*_engine_vectors_test.go` or `*_pkey_vectors_test.go`.

### KUZ-01 — Kuznyechik ECB RFC 7801 anchor

**File:** `parity/kuznyechik/kuznyechik_parity_test.go` → `TestDiffKAT`

Source: RFC 7801 §5.5 / GOST R 34.12-2015 §A.1. The pinned ciphertext
`7f679d90bebc24305a468d42b9d4edcd` for key `8899…abcdef` / pt `1122…9988`
is now both the Encrypt anchor and the Decrypt parity input. Previously the
test lacked an explicit `wantCT` literal.

### G89I-03 — GOST 28147 IMIT gost-engine vectors in parity package

**File:** `parity/gost28147imit/gost28147imit_parity_test.go` → `TestEngineVectors_IMIT`

Source: `tmp/engine/test/02-mac.t:162` (1024-byte, no meshing, want `2ee8d13d`)
and `tmp/engine/test/02-mac.t:185` (266240-byte testbig.dat, 260 meshing
boundaries, want `5efab81f`). These are the same vectors as the root-package
`TestGost_GOST28147_IMIT_Wrapper_*` tests; adding them here gives the parity
package an independent engine anchor that does not depend on the root oracle.

### KDF-02 — RFC 7836 Appendix B KDFTree anchor

**File:** `parity/kdftree/kdftree_parity_test.go` → `TestKDFTree256_PinnedRFC`

Sources:
- Example 10 (64-byte K1‖K2): `gostcrypto/kdftree/rfc/rfc7836.txt` lines
  1528–1555. K1 = `22b683…79d16b`, K2 = `074c93…1531f9`. Confirmed by
  `tmp/engine/test_tls12additional.c:95-115` (KAT-1; `test_keyexpimp.c:78-97`
  in 3.0.3).
- Example 9 (32-byte): `rfc7836.txt` lines 1499–1526. Want
  `a1aa5f…922ed9`. The [L]_b suffix differs between 32B and 64B, so each
  pins a distinct HMAC message — they are not redundant.

### SIG-02 — GOST R 34.10-2012 Appendix A.2 512-bit sign KAT

**File:** `parity/gost3410sign/gost3410sign_parity_test.go` → `TestDiff_Pinned512_A2`

Source: GOST R 34.10-2012, Appendix A.2 (512-bit test param set worked
example). The `katSigSR512` constant pins the `s‖r` signature bytes from the
standard. Both the clean-room `SignDigest` and the gogost oracle must reproduce
them byte-for-byte, and all four cross-verify combinations pass.

### KEG-03 — zero-UKM KEG vector (generated with gost-engine 3.0.3)

**File:** `parity/keg/keg_parity_test.go` → `TestKEG2012_256_ZeroUKM_KAT`

Source: gost-engine 3.0.3 via `openssl pkeyutl -derive -engine gost
-pkeyopt ukmhex:00…00` on privA/pubB TC26 256-A keys. The 64-byte output
`zeroUKMWantHex` pins the all-zero UKM special case (`real_ukm = 00…00 01`,
`gost_ec_keyx.c:150-152` in 3.0.5, `140-142` in 3.0.3). Pair-symmetry (B→A
produces identical bytes) verified. `keg_gost_test.go` →
`TestKEG2012_256_EngineOracle` (non-zero UKM) was produced the same way and takes
the same code path.

The engine was not run for 3.0.5. Its code path for this command is refactored
code, unchanged in output. Compared between v3.0.3 and v3.0.5:

- Unchanged byte for byte: `gost_keg` and `pkey_gost_ec_derive`
  (`gost_ec_keyx.c`); `gost_ec_point_mul`, `fill_GOST_EC_params` and
  `gost_ec_compute_public` (`gost_ec_sign.c`); the curve tables
  (`gost_params.c`); the Streebog core (`gosthash2012.c`,
  `gosthash2012_const.h`, `gosthash2012_precalc.h`, `gosthash2012_ref.h`,
  `gosthash2012_sse2.h`).
- Changed, without changing the output:
  1. `VKO_compute_key` (`gost_ec_keyx.c`): the ECDH step moved into the new
     `internal_compute_ecdh`. It still multiplies the peer point by
     LE(UKM)·priv mod q with `gost_ec_point_mul`, serializes X‖Y little-endian
     to the field size and hashes that with the same digest.
  2. `ukmhex` parsing (`gost_pmeth.c`): `pkey_gost_ec_ctrl_str_common` and
     `pkey_gost_ctrl` became `internal_ec_ctrl_str_common` and
     `internal_ec_ctrl`. The same `OPENSSL_hexstr2buf`, 32-byte limit and
     `EVP_PKEY_CTRL_SET_IV` copy into `shared_ukm` fill the same fields.
  3. `gost_kdftree2012_256`: moved from `gost_keyexpimp.c` to
     `gost_tls12_additional_kdftree.c`, from `HMAC_CTX` with
     `EVP_get_digestbynid(NID_id_GostR3411_2012_256)` to `EVP_MAC` HMAC with
     digest `md_gost12_256`. The HMAC-Streebog-256 input (counter, label, 0x00,
     seed, L) and the 32-byte output blocks are the same.
  4. Streebog `EVP_MD` wrapper (`gost_md2012.c`, new `gost_digest.c`,
     `gost_digest_ctx.c`, `gost_eng_digest.c`): the state now sits behind a
     `GOST_digest_ctx`, but init, update and final still call
     `init_gost2012_hash_ctx(…, 256)`, `gost2012_hash_block` and
     `gost2012_finish_hash` on the same bytes. `gosthash2012.h` only moved
     `ALIGN(16)` onto the union, an alignment change.
  5. Key decoding (`gost_ameth.c`): `priv_decode_gost` and `pub_decode_gost_ec`
     were split into `internal_priv_decode` and `internal_pub_decode_ec` with
     the same little-endian decoding. The new checks (`EC_KEY_check_key`, the
     public key length, `gost_ec_pub_key_subgroup_check`) can only reject a key.
- Corroboration: in v3.0.5, `test/04-pkey.t` keeps the same engine-mode VKO
  derive hashes, and `test_tls12additional.c` keeps the same KDF_TREE etalon.

### KXP-01 — RFC 9189 Appendix A.1.3.2 Kuznyechik KExp15 vector

**File:** `parity/kexp15/kexp15_parity_test.go` → `TestKexp15Conformance_Kuznyechik`

Source: bundled RFC 9189 at `gostcrypto/kexp15/rfc/rfc9189.txt`, Client side
of the TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC key-exchange example:
- shared (PMS): lines 3158–3159
- K_Exp_MAC ‖ K_Exp_ENC: lines 3189–3192
- IV: line 3195
- want (PMSEXP): lines 3198–3200

This is the only independent anchor for the Kuznyechik (128-bit block)
OMAC/CTR composition path; without it a shared mode bug in both twins passes.
The Magma etalon of `TestKexp15Conformance` in the same file comes from
`tmp/engine/test_tls12additional.c:64-93` (`test_keyexpimp.c:47-76` in 3.0.3).

### KWP-01/02 — CryptoPro-A and TC26-Z KeyWrap KATs (generated with gost-engine 3.0.3)

**File:** `parity/keywrap/helpers_test.go` (constants), consumed by
`parity/keywrap/keywrap_parity_test.go` → `TestKeyWrapCryptoPro_Differential`
and `TestDiversify_Differential`.

Sources:
- `katWrapped` (TC26-Z, 44 bytes): gost-engine 3.0.3 `keyWrapCryptoPro`
  dylib with `Gost28147_TC26ParamSetZ` on `katKEK`/`katUKM`/`katSession`
  (see `keywrap-cryptopro.md:332`). `katKEKUKM` pins the intermediate
  diversified KEK.
- `katWrappedCryptoProA` (CryptoPro-A, 44 bytes): same inputs, same engine
  version, `Gost28147_CryptoProParamSetA`. Reproduced via a minimal C harness
  (`kat.c` calling `keyWrapCryptoPro` from `gost_keywrap.c`); exact command
  in `helpers_test.go:36-47`.

The engine was not run for 3.0.5. The code path is unchanged byte for byte:
`gost89.c`, `gost89.h`, `gost_keywrap.c` and `gost_keywrap.h` have no diff
between v3.0.3 and v3.0.5. That covers `keyWrapCryptoPro`,
`keyDiversifyCryptoPro`, `gost_init`, `gost_key`, `gost_enc`, `gost_enc_cfb`,
`gost_mac_iv` and the `Gost28147_TC26ParamSetZ` and
`Gost28147_CryptoProParamSetA` S-box tables. Both vectors stand.

---

## Problems / disagreements

1. **GOSTR341194 empty-input** (`tcl_tests/dgst.try:92`): engine `3f25bc1f...`,
   gogost `981e5f3c...`. Root cause (2026-04-20): empty-input finalization differs.
   Engine's `finish_hash` at `gosthash.c:257-258` runs an extra
   `hash_step(H, zero_block)` when `fin_len == 0`; gogost's `Sum` does not.
   S-box bytes are equivalent; all 5 non-empty vectors pass. TLS PRF uses
   HMAC (never empty input), so this mismatch is benign for the TLS use case.
   Fix would require reimplementing GOST R 34.11-94 locally — deferred.
   Re-checked against v3.0.5: `gosthash.c` has no diff and the expected value is
   unchanged; the test moved from line 87 to 92.

2. ~~**IMIT on large data**~~ — resolved. See `test/02-mac.t` section above.

3. ~~**mac.try gost-mac key**~~ — resolved 2026-11-20, the vectors are ported.
   See `test/02-mac.t` section above.
