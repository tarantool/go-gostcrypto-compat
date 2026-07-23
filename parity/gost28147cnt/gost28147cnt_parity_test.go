package gost28147cntparity

import (
	"bytes"
	. "github.com/tarantool/go-gostcrypto/gost28147cnt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
	"github.com/tarantool/go-gostcrypto/gost28147"
	gogost28147 "go.stargrave.org/gogost/v7/gost28147"
)

// The gostcryptocompat.NewGOST28147_CNT oracle returns gogost's raw
// *gost28147.CTR. Per the guide's delta D4 it has two streaming defects that
// also make it an UNRELIABLE differential reference for arbitrary key/IV:
//
//   - it performs no CryptoPro key meshing, so it diverges from ground truth
//     at the 1024-byte boundary (TestDiff_OracleLacksMeshing); and
//   - it applies the end-around carry to the whole counter half differently
//     from the engine, so for many non-zero IVs it diverges from the engine
//     well before 1024 bytes (the very first time a counter half wraps).
//
// The guide only guarantees the oracle as a reference for the pinned
// zero-key/zero-IV case below 1024 bytes. For random key/IV the authoritative
// ground truth is the gost-engine CLI. So:
//
//   - TestDiff_GostEngineCLI is the real random-input differential, against
//     the engine, for BOTH S-boxes, including split (non-block-aligned)
//     streaming — this is the critical case.
//   - TestDiff_InternalGostOracle keeps the requested gogost-oracle diff but
//     restricted to the zero-IV, meshing-free regime where it is valid.
//   - TestDiff_OracleLacksMeshing locks in why the oracle cannot go past 1024.

const oracleMeshingFreeLimit = 1024

// opensslBin resolves the openssl CLI used as the gost-engine ground-truth
// oracle. OPENSSL_BIN, when set, wins outright; otherwise per-OS well-known
// paths are probed (Homebrew/MacPorts on macOS, the usual prefixes on Linux),
// falling back to a bare "openssl" looked up on PATH (covers any distro or
// custom install). Returns ok=false if none is found so the caller can skip.
func opensslBin() (string, bool) {
	if v := os.Getenv("OPENSSL_BIN"); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v, true
		}
		return "", false
	}
	for _, p := range opensslBinCandidates() {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	// Fall back to PATH (covers any distro or custom install).
	if p, err := exec.LookPath("openssl"); err == nil {
		return p, true
	}
	return "", false
}

func opensslBinCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/opt/homebrew/opt/openssl@3/bin/openssl", // Homebrew (Apple Silicon)
			"/usr/local/opt/openssl@3/bin/openssl",    // Homebrew (Intel)
			"/opt/local/bin/openssl",                  // MacPorts
		}
	case "linux":
		return []string{
			"/usr/bin/openssl",
			"/usr/local/bin/openssl",
			"/usr/local/ssl/bin/openssl", // source-build default prefix
		}
	default:
		return nil
	}
}

// gostEngineConf resolves the OpenSSL config that registers the gost engine,
// passed to the CLI via OPENSSL_CONF. An OPENSSL_CONF already set in the
// environment wins outright; otherwise per-OS well-known configs are probed.
// Returns "" when none is found, in which case the caller relies on the
// ambient OpenSSL config (the typical Linux case, where distro packages
// register the engine in the system openssl.cnf).
func gostEngineConf() string {
	if v := os.Getenv("OPENSSL_CONF"); v != "" {
		return v
	}
	for _, p := range gostEngineConfCandidates() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func gostEngineConfCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/opt/homebrew/etc/gost/gost-engine.cnf", // Homebrew (Apple Silicon)
			"/usr/local/etc/gost/gost-engine.cnf",    // Homebrew (Intel)
			"/opt/local/etc/gost/gost-engine.cnf",    // MacPorts
		}
	case "linux":
		return []string{
			"/etc/ssl/gost.cnf",
			"/etc/pki/tls/gost.cnf", // Fedora/RHEL layout
		}
	default:
		return nil
	}
}

// isEngineAvailable returns (path, true) only when the gost-engine CLI is both
// resolvable AND actually loadable, (_, false) otherwise. Call this ONCE before
// a loop; use mustEngineCNT inside the loop.
//
// Resolving the openssl binary is not enough: a box can ship openssl on PATH
// (e.g. the stock ubuntu-latest runner used by the engine-free `parity` CI job)
// without the gost engine installed, in which case `openssl enc -engine gost`
// exits non-zero. Probing the binary alone would let that job march into the
// per-iteration loop and t.Fatalf instead of skipping. So we exercise the
// engine with one real block of encryption here; if it errors, report
// unavailable and the caller skips. The dedicated `parity-engine` job, which
// builds gost-engine from source, still passes this probe and runs the full
// differential.
func isEngineAvailable() (string, bool) {
	bin, ok := opensslBin()
	if !ok {
		return "", false
	}
	// One block of zeros through the gost engine; success proves it loads.
	cmd := exec.Command(bin, "enc", "-engine", "gost", "-gost89-cnt",
		"-K", hexstr(make([]byte, gost28147.KeySize)),
		"-iv", hexstr(make([]byte, gost28147.BlockSize)), "-nopad")
	cmd.Stdin = bytes.NewReader(make([]byte, gost28147.BlockSize))
	cmd.Env = os.Environ()
	if conf := gostEngineConf(); conf != "" {
		cmd.Env = append(cmd.Env, "OPENSSL_CONF="+conf)
	}
	if out, err := cmd.Output(); err != nil || len(out) < gost28147.BlockSize {
		return "", false
	}
	return bin, true
}

// mustEngineCNT shells out to the gost-engine CLI to produce the ground-truth
// keystream (XOR over zero) for the given key/iv. tc26 selects -gost89-cnt-12
// (tc26-Z); otherwise -gost89-cnt (CryptoPro-A default).
// Precondition: the caller has already confirmed the engine is available via
// isEngineAvailable; any CLI error here is a real failure → t.Fatalf.
func mustEngineCNT(t *testing.T, bin string, key, iv []byte, n int, tc26 bool) []byte {
	t.Helper()
	mode := "-gost89-cnt"
	if tc26 {
		mode = "-gost89-cnt-12"
	}
	cmd := exec.Command(bin, "enc", "-engine", "gost", mode,
		"-K", hexstr(key), "-iv", hexstr(iv), "-nopad")
	cmd.Stdin = bytes.NewReader(make([]byte, n)) // n zero bytes
	cmd.Env = os.Environ()
	if conf := gostEngineConf(); conf != "" {
		cmd.Env = append(cmd.Env, "OPENSSL_CONF="+conf)
	}
	res, err := cmd.Output()
	if err != nil || len(res) < n {
		t.Fatalf("gost-engine CLI failed (binary exists but command errored): %v", err)
	}
	return res[:n]
}

func hexstr(b []byte) string {
	const hexd = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, v := range b {
		s[i*2] = hexd[v>>4]
		s[i*2+1] = hexd[v&0xF]
	}
	return string(s)
}

// TestDiff_GostEngineCLI is the authoritative random differential: it diffs
// the clean-room streaming impl against the gost-engine CLI ground truth over
// random key/IV and random lengths (including >1024 and >2048 to exercise
// first and second CryptoPro meshing boundaries), driving the clean-room side
// through random non-block-aligned chunk splits.
//
// G89C-01: availability is probed ONCE before the loop; any per-iteration CLI
// failure is a real error (t.Fatalf), not a skip.
// G89C-02: iter%7==0 generates n>=2049, exercising the second meshing boundary.
func TestDiff_GostEngineCLI(t *testing.T) {
	// G89C-01: probe availability once; skip the whole test if the binary is absent.
	bin, ok := isEngineAvailable()
	if !ok {
		t.Skip("gost-engine CLI not available")
	}

	r := rand.New(rand.NewSource(0x6057C17))
	for _, tc := range []struct {
		name string
		sbox gost28147.SBox
		tc26 bool
	}{
		{"CryptoPro-A", gost28147.SboxCryptoProA, false},
		{"tc26-Z", gost28147.SboxTC26Z, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for iter := range 40 {
				key := make([]byte, gost28147.KeySize)
				iv := make([]byte, gost28147.BlockSize)
				r.Read(key)
				r.Read(iv)
				n := r.Intn(1300)
				if iter%5 == 0 {
					n = 1024 + r.Intn(48) // straddle first meshing boundary
				}
				// G89C-02: straddle second meshing boundary (>=2048).
				if iter%7 == 0 {
					n = 2048 + r.Intn(100) // straddle second meshing boundary
				}

				// G89C-01: binary is confirmed available; any failure here is fatal.
				want := mustEngineCNT(t, bin, key, iv, n, tc.tc26)

				// Drive clean-room through random sub-block chunks.
				s := NewCNT(gost28147.NewCipher(key, tc.sbox), iv)
				got := make([]byte, n)
				zero := make([]byte, n)
				off := 0
				for off < n {
					chunk := 1 + r.Intn(13)
					if off+chunk > n {
						chunk = n - off
					}
					s.XORKeyStream(got[off:off+chunk], zero[off:off+chunk])
					off += chunk
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("iter=%d key=%x iv=%x n=%d\n got=%x\nwant=%x",
						iter, key, iv, n, got, want)
				}
			}
		})
	}
}

// TestDiff_InternalGostOracle keeps the requested gogost-oracle differential,
// now for BOTH S-boxes (CryptoPro-A and tc26-Z). The oracle is the guide's
// blessed reference ONLY for the pinned zero-key/zero-IV conformance vector:
// for non-zero IVs — and even for zero IV with certain keys — gogost's CTR
// carry bug (guide D4) makes it diverge from ground truth before 1024 bytes
// (this was observed and verified against the engine: the clean-room impl
// matched the engine byte-for-byte where the oracle did not). So this test
// pins the oracle on the zero/zero vector across a range of split-call
// boundaries; the random differential lives in TestDiff_GostEngineCLI against
// the engine ground truth instead.
//
// G89C-03: tc26-Z sub-test added. The gogost oracle for tc26-Z is built
// directly from gogost28147.NewCipher(key, &gogost28147.SboxIdtc26gost28147paramZ)
// (bypassing the facade which hardcodes CryptoPro-A). Under zero-key/zero-IV
// with n<1024 the counter never wraps within 128 blocks so the D4 carry
// defect does not trigger, making this a valid oracle for tc26-Z in this
// regime — same analysis as for CryptoPro-A.
func TestDiff_InternalGostOracle(t *testing.T) {
	key := make([]byte, gost28147.KeySize)
	iv := make([]byte, gost28147.BlockSize)
	r := rand.New(rand.NewSource(0xC0FFEE))

	type sboxCase struct {
		name     string
		cleanBox gost28147.SBox
		gogotBox *gogost28147.Sbox
	}
	cases := []sboxCase{
		{
			"CryptoPro-A",
			gost28147.SboxCryptoProA,
			gogost28147.SboxDefault, // SboxDefault == &SboxIdGost2814789CryptoProAParamSet
		},
		// G89C-03: tc26-Z always-on anchor via direct gogost oracle.
		{
			"tc26-Z",
			gost28147.SboxTC26Z,
			&gogost28147.SboxIdtc26gost28147paramZ,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r2 := rand.New(rand.NewSource(0xC0FFEE)) // same seed per S-box for reproducibility
			for iter := range 200 {
				n := r2.Intn(oracleMeshingFreeLimit) // < 1024: oracle meshing-free here
				pt := make([]byte, n)
				r2.Read(pt)

				// Build the gogost oracle directly for this S-box.
				gogostCipher := gogost28147.NewCipher(key, tc.gogotBox)
				gogostCTR := gogostCipher.NewCTR(iv)
				want := make([]byte, n)
				gogostCTR.XORKeyStream(want, pt) // ONE call only (D4)

				// Drive clean-room through random non-block-aligned chunk splits.
				s := NewCNT(gost28147.NewCipher(key, tc.cleanBox), iv)
				got := make([]byte, n)
				off := 0
				for off < n {
					chunk := 1 + r.Intn(13)
					if off+chunk > n {
						chunk = n - off
					}
					s.XORKeyStream(got[off:off+chunk], pt[off:off+chunk])
					off += chunk
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("sbox=%s iter=%d n=%d\n got=%x\nwant=%x",
						tc.name, iter, n, got, want)
				}
			}
		})
	}

}

// FuzzDiff_InternalGostOracle mirrors TestDiff_InternalGostOracle: it feeds the
// same plaintext to the in-repo gogost oracle (one XORKeyStream call, per D4)
// and to the clean-room impl (driven through fuzzer-chosen non-block-aligned
// chunk splits), asserting byte-equal output. As documented above, the gogost
// oracle is only a valid reference for the zero-key/zero-IV, meshing-free
// (n < 1024) regime, so the fuzzer holds key/IV at zero and caps the length;
// only the plaintext, the chunk-split schedule, and the S-box selector vary.
//
// G89C-03: sboxSel parameter added — even selects CryptoPro-A, odd selects
// tc26-Z. Each S-box is seeded explicitly so seed replay exercises both.
// The gogost oracle is built directly (not via the facade) for tc26-Z.
func FuzzDiff_InternalGostOracle(f *testing.F) {
	// sboxSel: even=CryptoPro-A, odd=tc26-Z
	f.Add([]byte("the quick brown fox"), uint8(7), uint8(0))               // CryptoPro-A
	f.Add(make([]byte, 512), uint8(13), uint8(0))                          // CryptoPro-A
	f.Add(seedHex("00112233445566778899aabbccddeeff"), uint8(1), uint8(0)) // CryptoPro-A
	f.Add([]byte("the quick brown fox"), uint8(7), uint8(1))               // tc26-Z
	f.Add(make([]byte, 512), uint8(13), uint8(1))                          // tc26-Z
	f.Add(seedHex("00112233445566778899aabbccddeeff"), uint8(1), uint8(1)) // tc26-Z

	f.Fuzz(func(t *testing.T, pt []byte, chunkSeed uint8, sboxSel uint8) {
		// Hold the oracle in its valid regime: zero key, zero IV, n < 1024.
		key := make([]byte, gost28147.KeySize)
		iv := make([]byte, gost28147.BlockSize)

		if len(pt) >= oracleMeshingFreeLimit {
			pt = pt[:oracleMeshingFreeLimit-1]
		}
		n := len(pt)

		// Select S-box pair: even=CryptoPro-A, odd=tc26-Z.
		var cleanBox gost28147.SBox
		var gogotBox *gogost28147.Sbox
		if sboxSel%2 == 0 {
			cleanBox = gost28147.SboxCryptoProA
			gogotBox = gogost28147.SboxDefault
		} else {
			cleanBox = gost28147.SboxTC26Z
			gogotBox = &gogost28147.SboxIdtc26gost28147paramZ
		}

		// Build gogost oracle directly for the selected S-box (the facade hardcodes
		// CryptoPro-A and cannot be used for tc26-Z). ONE XORKeyStream call only (D4).
		gogostCTR := gogost28147.NewCipher(key, gogotBox).NewCTR(iv)
		want := make([]byte, n)
		gogostCTR.XORKeyStream(want, pt)

		// Drive clean-room through a deterministic, fuzzer-seeded chunk split so
		// the partial-block streaming path is exercised across boundaries.
		s := NewCNT(gost28147.NewCipher(key, cleanBox), iv)
		got := make([]byte, n)
		off := 0
		step := chunkSeed
		for off < n {
			chunk := 1 + int(step%13)
			if off+chunk > n {
				chunk = n - off
			}
			s.XORKeyStream(got[off:off+chunk], pt[off:off+chunk])
			off += chunk
			step = step*31 + 7 // vary chunk sizes deterministically
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("sbox=%d n=%d\n got=%x\nwant=%x", sboxSel%2, n, got, want)
		}
	})
}

// TestDiff_OracleLacksMeshing documents (and locks in) the meshing boundary:
// the gogost oracle and the clean-room impl agree byte-for-byte up to 1024
// bytes (zero key/IV) and diverge at exactly offset 1024 because the oracle's
// raw gost28147.CTR performs no CryptoPro key meshing while we do. Our
// post-mesh bytes equal the pinned engine KAT, proving the divergence is the
// oracle's missing meshing, not a bug on our side.
func TestDiff_OracleLacksMeshing(t *testing.T) {
	key := make([]byte, gost28147.KeySize)
	iv := make([]byte, gost28147.BlockSize)
	sbox := gost28147.SboxCryptoProA
	const n = 1040

	ref, err := gost.NewGOST28147_CNT(key, iv)
	if err != nil {
		t.Fatalf("oracle ctor: %v", err)
	}
	oracle := make([]byte, n)
	ref.XORKeyStream(oracle, make([]byte, n))

	mine := make([]byte, n)
	NewCNT(gost28147.NewCipher(key, sbox), iv).XORKeyStream(mine, make([]byte, n))

	if !bytes.Equal(mine[:1024], oracle[:1024]) {
		t.Fatalf("clean-room and oracle disagree before the meshing boundary")
	}
	if bytes.Equal(mine[1024:1032], oracle[1024:1032]) {
		t.Fatalf("expected divergence at the meshing boundary, got agreement")
	}
	want := mustHex(t, "56f45eab8381b608") // pinned engine post-mesh (CryptoPro-A)
	if !bytes.Equal(mine[1024:1032], want) {
		t.Fatalf("post-mesh [1024:1032] = %x, want pinned engine %x", mine[1024:1032], want)
	}
}
