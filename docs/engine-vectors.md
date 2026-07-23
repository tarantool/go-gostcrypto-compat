# gost-engine v3.0.3 vector port

Source: `tmp/engine/` (tag v3.0.3, commit e0a500a). Not committed to this repo.

## test/01-digest.t + tcl_tests/dgst.try

Ported: 7 Streebog-256, 7 Streebog-512, 5 GOST R 34.11-94 vectors.
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

Skipped: `mac.try` gost-mac vectors (key `12345678901234567890123456789012`): expected
`37f646d2` for dgst.dat does not match any S-box in our library. Key encoding or
S-box selection differs from the `02-mac.t` key (`0123456789abcdef0123456789abcdef`).
Skipped: magma-mac and kuznyechik-mac (OMAC/CMAC) — out of scope.

Previously a disagreement on testbig.dat (266240 bytes, `5efab81f` vs `383059e8`) —
resolved 2026-04-20 by reimplementing `GOST28147_IMIT` with CryptoPro key meshing
(RFC 4357 §2.3.2, engine ref: `gost_crypt.c:1510-1524`). Validated by
`TestGost_GOST28147_IMIT_Wrapper_KeyMeshing`. gogost's raw `gost28147.MAC` still
lacks meshing, so that vector remains skipped in the raw-MAC loop.

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

Skipped: all VKO 'derive' subtest vectors — expected values are sha256(DER-encoded
derived key), not raw shared-key bytes. Private keys are PEM-encoded; extracting the
LE raw bytes requires ASN.1 DER parsing outside the scope of this porting task.

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
  `tmp/engine/test_keyexpimp.c:78-97` (KAT-1).
- Example 9 (32-byte): `rfc7836.txt` lines 1499–1526. Want
  `a1aa5f…922ed9`. The [L]_b suffix differs between 32B and 64B, so each
  pins a distinct HMAC message — they are not redundant.

### SIG-02 — GOST R 34.10-2012 Appendix A.2 512-bit sign KAT

**File:** `parity/gost3410sign/gost3410sign_parity_test.go` → `TestDiff_Pinned512_A2`

Source: GOST R 34.10-2012, Appendix A.2 (512-bit test param set worked
example). The `katSigSR512` constant pins the `s‖r` signature bytes from the
standard. Both the clean-room `SignDigest` and the gogost oracle must reproduce
them byte-for-byte, and all four cross-verify combinations pass.

### KEG-03 — gost-engine 3.0.3 zero-UKM KEG vector

**File:** `parity/keg/keg_parity_test.go` → `TestKEG2012_256_ZeroUKM_KAT`

Source: gost-engine 3.0.3 via `openssl pkeyutl -derive -engine gost
-pkeyopt ukmhex:00…00` on privA/pubB TC26 256-A keys. The 64-byte output
`zeroUKMWantHex` pins the all-zero UKM special case (`real_ukm = 00…00 01`,
`gost_ec_keyx.c:140-142`). Pair-symmetry (B→A produces identical bytes) verified.

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

### KWP-01/02 — gost-engine 3.0.3 CryptoPro-A and TC26-Z KeyWrap KATs

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

---

## Problems / disagreements

1. **GOSTR341194 empty-input** (`tcl_tests/dgst.try:87`): engine `3f25bc1f...`,
   gogost `981e5f3c...`. Root cause (2026-04-20): empty-input finalization differs.
   Engine's `finish_hash` at `gosthash.c:257-258` runs an extra
   `hash_step(H, zero_block)` when `fin_len == 0`; gogost's `Sum` does not.
   S-box bytes are equivalent; all 5 non-empty vectors pass. TLS PRF uses
   HMAC (never empty input), so this mismatch is benign for the TLS use case.
   Fix would require reimplementing GOST R 34.11-94 locally — deferred.

2. ~~**IMIT on large data**~~ — resolved. See `test/02-mac.t` section above.
