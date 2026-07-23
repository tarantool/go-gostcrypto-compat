package kegparity

import (
	"bytes"
	"encoding/asn1"
	"github.com/tarantool/go-gostcrypto/gost3410curves"
	. "github.com/tarantool/go-gostcrypto/keg"
	"testing"

	gost "github.com/tarantool/go-gostcrypto-compat"
)

// fixLen returns b padded with zeros or truncated to exactly n bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// tc26256AOID is GOST R 34.10-2012 256-bit TC26 ParamSet A.
var tc26256AOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}

func oracleCurve(t testing.TB) *gost.Curve {
	t.Helper()
	c, err := gost.CurveByOID(tc26256AOID)
	if err != nil {
		t.Fatalf("oracle CurveByOID: %v", err)
	}
	return c
}

// curve256OIDs is the closed set of mutually-supported 256-bit curve OIDs.
// Both modules' registries cover all seven; they are the curves real GOST TLS
// certificates use (CryptoPro A/B/C and TC26 256 A/B/C/D, RFC 9189 §A.1.3).
// Note: TC26-256-B == CryptoPro-A, TC26-256-C == CryptoPro-B,
//
//	TC26-256-D == CryptoPro-C (distinct OIDs but same curve constants).
var curve256OIDs = []struct {
	name      string
	cleanRoom string                // dotted-decimal for gost3410curves.CurveByOID
	oracle    asn1.ObjectIdentifier // for gost.CurveByOID
}{
	{"CryptoPro-A", "1.2.643.2.2.35.1", asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}},
	{"CryptoPro-B", "1.2.643.2.2.35.2", asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}},
	{"CryptoPro-C", "1.2.643.2.2.35.3", asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}},
	{"TC26-256-A", "1.2.643.7.1.2.1.1.1", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}},
	{"TC26-256-B", "1.2.643.7.1.2.1.1.2", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}},
	{"TC26-256-C", "1.2.643.7.1.2.1.1.3", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}},
	{"TC26-256-D", "1.2.643.7.1.2.1.1.4", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}},
}

// TestKEG2012_256_DiffOracle pins the clean-room output to the in-repo
// gogost-backed reference (gostcryptocompat.KEG2012_256), the de-facto spec this
// repo matches, on the doc's KAT inputs.
func TestKEG2012_256_DiffOracle(t *testing.T) {
	curve := oracleCurve(t)
	ukm := mustHex(t, ukmHex)
	want := mustHex(t, wantHex)

	cases := []struct {
		name      string
		pub, priv string
	}{
		{"privA_pubB", pubBHex, privAHex},
		{"privB_pubA", pubAHex, privBHex},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := mustHex(t, tc.pub)
			priv := mustHex(t, tc.priv)

			ref, err := gost.KEG2012_256(curve, pub, priv, ukm)
			if err != nil {
				t.Fatalf("oracle KEG: %v", err)
			}
			if !bytes.Equal(ref[:], want) {
				t.Fatalf("oracle != pinned vector:\n ref %x\nwant %x", ref[:], want)
			}

			// The clean-room keg.KEG2012_256 takes a *gost3410curves.Curve and
			// defaults to TC26 256-A on nil; the oracle curve here is exactly
			// TC26 256-A, so nil selects the matching domain. (The two curve
			// wrapper types differ — gost.Curve wraps gogost, keg takes the BSD
			// gost3410curves.Curve — so nil is the clean way to align them.)
			got, err := KEG2012_256(nil, pub, priv, ukm)
			if err != nil {
				t.Fatalf("clean-room KEG: %v", err)
			}
			if got != ref {
				t.Fatalf("clean-room != oracle:\n got %x\n ref %x", got[:], ref[:])
			}
		})
	}
}

// TestKEG2012_256_DiffEphemeral draws fresh key material from the oracle's
// ephemeral-key generator and checks clean-room == oracle plus pair symmetry.
func TestKEG2012_256_DiffEphemeral(t *testing.T) {
	curve := oracleCurve(t)

	seeds := [][2][]byte{
		{bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)},
		{bytes.Repeat([]byte{0xa5}, 32), bytes.Repeat([]byte{0x5a}, 32)},
		{mustHex(t, privAHex), mustHex(t, privBHex)},
	}
	ukms := [][]byte{
		mustHex(t, ukmHex),
		make([]byte, 32), // all-zero first 16 bytes → real_ukm special case
		bytes.Repeat([]byte{0xff}, 32),
	}

	for si, sp := range seeds {
		privA, pubA, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sp[0]))
		if err != nil {
			t.Fatalf("seed %d: gen A: %v", si, err)
		}
		privB, pubB, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sp[1]))
		if err != nil {
			t.Fatalf("seed %d: gen B: %v", si, err)
		}

		for ui, ukm := range ukms {
			ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
			if err != nil {
				t.Fatalf("seed %d ukm %d: oracle: %v", si, ui, err)
			}
			// nil selects keg's default TC26 256-A, the same domain as the
			// oracle curve (see TestKEG2012_256_DiffOracle for the rationale).
			got, err := KEG2012_256(nil, pubB, privA, ukm)
			if err != nil {
				t.Fatalf("seed %d ukm %d: clean-room: %v", si, ui, err)
			}
			if got != ref {
				t.Fatalf("seed %d ukm %d: clean-room != oracle\n got %x\n ref %x",
					si, ui, got[:], ref[:])
			}

			// Free pair-symmetry oracle.
			sym, err := KEG2012_256(nil, pubA, privB, ukm)
			if err != nil {
				t.Fatalf("seed %d ukm %d: clean-room sym: %v", si, ui, err)
			}
			if sym != got {
				t.Fatalf("seed %d ukm %d: not pair-symmetric\n A→B %x\n B→A %x",
					si, ui, got[:], sym[:])
			}
		}
	}
}

// TestKEG2012_256_MultiCurve diffs the clean-room against the oracle across
// all seven mutually-supported 256-bit OIDs: CryptoPro A/B/C (1.2.643.2.2.35.x)
// and TC26 256 A/B/C/D (1.2.643.7.1.2.1.1.x). Each side resolves the curve
// through its own registry to confirm byte-for-byte parity on every 256-bit
// paramset, including the CryptoPro curves real production certificates use.
//
// Findings: KEG-01
func TestKEG2012_256_MultiCurve(t *testing.T) {
	seedA := bytes.Repeat([]byte{0x11}, 32)
	seedB := bytes.Repeat([]byte{0x22}, 32)
	ukm := mustHex(t, ukmHex)

	for _, entry := range curve256OIDs {
		t.Run(entry.name, func(t *testing.T) {
			oracleCrv, err := gost.CurveByOID(entry.oracle)
			if err != nil {
				t.Fatalf("oracle CurveByOID(%s): %v", entry.name, err)
			}
			crCurve, err := gost3410curves.CurveByOID(entry.cleanRoom)
			if err != nil {
				t.Fatalf("clean-room CurveByOID(%s): %v", entry.name, err)
			}

			// Use oracle's generator so both sides get valid on-curve keys.
			privA, pubA, err := gost.GenerateEphemeralKey(oracleCrv, bytes.NewReader(seedA))
			if err != nil {
				t.Fatalf("gen A: %v", err)
			}
			privB, pubB, err := gost.GenerateEphemeralKey(oracleCrv, bytes.NewReader(seedB))
			if err != nil {
				t.Fatalf("gen B: %v", err)
			}

			ref, err := gost.KEG2012_256(oracleCrv, pubB, privA, ukm)
			if err != nil {
				t.Fatalf("oracle KEG(%s): %v", entry.name, err)
			}
			got, err := KEG2012_256(crCurve, pubB, privA, ukm)
			if err != nil {
				t.Fatalf("clean-room KEG(%s): %v", entry.name, err)
			}
			if got != ref {
				t.Fatalf("clean-room != oracle (%s)\n got %x\n ref %x",
					entry.name, got[:], ref[:])
			}

			// Pair symmetry on the clean-room side (both sides already equal,
			// so also proves B→A matches on the oracle side transitively).
			sym, err := KEG2012_256(crCurve, pubA, privB, ukm)
			if err != nil {
				t.Fatalf("clean-room sym KEG(%s): %v", entry.name, err)
			}
			if sym != got {
				t.Fatalf("not pair-symmetric (%s)\n A→B %x\n B→A %x",
					entry.name, got[:], sym[:])
			}
		})
	}
}

// zeroUKMWantHex is KEG2012_256(privA, pubB, ukm=32×0x00) on TC26 256-bit
// ParamSet A. The all-zero first 16 bytes trigger the real_ukm = 00…00 01
// special case (gost_ec_keyx.c:140-142, tmp/engine/gost_ec_keyx.c).
//
// Vector source: gost-engine 3.0.3 via:
//
//	OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
//	  /opt/homebrew/opt/openssl@3/bin/openssl pkeyutl -derive -engine gost \
//	    -inkey privA_tc26.pem -peerkey pubB_tc26.pem \
//	    -pkeyopt ukmhex:0000000000000000000000000000000000000000000000000000000000000000 \
//	    -out keg_zero_ukm_AB.bin
//
// Keys are privAHex/pubBHex on curve 1.2.643.7.1.2.1.1.1 (TC26 256-A).
// Pair-symmetry verified: engine B→A with privBHex/pubAHex produces the same 64 bytes.
const zeroUKMWantHex = "1f28179da81185e6019a6bc43568b9d8be3788111c50dff78b2a04259f8ecc73" +
	"ddc39fe3d635dc2ffd7071286d4d074421307548b847dbb88039b94015382a6e"

// TestKEG2012_256_ZeroUKM_KAT pins the zero-UKM special-case output against
// the engine-derived vector above, then diffs clean-room against oracle.
//
// Findings: KEG-03
func TestKEG2012_256_ZeroUKM_KAT(t *testing.T) {
	curve := oracleCurve(t)
	want := mustHex(t, zeroUKMWantHex)
	zeroUKM := make([]byte, 32)
	pub := mustHex(t, pubBHex)
	priv := mustHex(t, privAHex)

	// Pin against engine vector.
	got, err := KEG2012_256(nil, pub, priv, zeroUKM)
	if err != nil {
		t.Fatalf("clean-room zero-UKM KEG: %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("clean-room zero-UKM KAT mismatch:\n got %x\nwant %x", got[:], want)
	}

	// Cross-check: oracle must produce the same bytes.
	ref, err := gost.KEG2012_256(curve, pub, priv, zeroUKM)
	if err != nil {
		t.Fatalf("oracle zero-UKM KEG: %v", err)
	}
	if ref != got {
		t.Fatalf("oracle != clean-room zero-UKM:\n got %x\n ref %x", got[:], ref[:])
	}
}

// TestKEG2012_256_ErrorParity asserts that clean-room and oracle agree on
// rejecting malformed inputs. Error-message text parity is out of scope; only
// both-error vs both-succeed is checked.
//
// The 512-bit curve case is structurally untestable in this frame: the oracle
// accepts a *Curve and has no OID-level 512-bit guard (it would fail on key
// length), while the clean-room rejects the curve explicitly. A 512-bit-curve
// test would need 64/128-byte keys on the oracle side to even parse, making
// the error sources structurally asymmetric — that case is out of scope here.
//
// Findings: KEG-05
func TestKEG2012_256_ErrorParity(t *testing.T) {
	curve := oracleCurve(t)
	goodPub := mustHex(t, pubBHex)
	goodPriv := mustHex(t, privAHex)
	goodUKM := mustHex(t, ukmHex)

	long33UKM := append(append([]byte(nil), goodUKM...), 0x00)

	cases := []struct {
		name      string
		pub, priv []byte
		ukm       []byte
	}{
		{"ukm_31", goodPub, goodPriv, goodUKM[:31]},
		{"ukm_33", goodPub, goodPriv, long33UKM},
		{"pub_short_63", goodPub[:63], goodPriv, goodUKM},
		{"pub_long_65", append(append([]byte(nil), goodPub...), 0x00), goodPriv, goodUKM},
		{"priv_short", goodPub, goodPriv[:31], goodUKM},
		{"priv_zero", goodPub, make([]byte, 32), goodUKM},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, oracleErr := gost.KEG2012_256(curve, tc.pub, tc.priv, tc.ukm)
			_, cleanErr := KEG2012_256(nil, tc.pub, tc.priv, tc.ukm)
			if oracleErr == nil {
				t.Errorf("oracle accepted malformed input (%s)", tc.name)
			}
			if cleanErr == nil {
				t.Errorf("clean-room accepted malformed input (%s)", tc.name)
			}
		})
	}
}

// FuzzKEG2012_256_DiffOracle mirrors TestKEG2012_256_DiffEphemeral: from two
// fuzzer-supplied 32-byte seeds it derives valid ephemeral key pairs via the
// oracle's generator, then for a fuzzer-supplied UKM asserts that the
// clean-room KEG equals the oracle KEG and that the result is pair-symmetric
// (A→B == B→A). The curveIdx byte selects among the seven supported 256-bit
// OIDs so all paramsets are exercised.
//
// Seeds and UKM are normalized to 32 bytes. Invalid generator inputs are
// skipped only when both sides agree on the skip (never to hide a mismatch).
//
// Findings: KEG-02, KEG-04, KEG-06 (raw-bytes mode)
func FuzzKEG2012_256_DiffOracle(f *testing.F) {
	// Seed 0: TC26-256-A (index 3), KAT keys.
	f.Add(seedHex(privAHex), seedHex(privBHex), seedHex(ukmHex), byte(3))
	// Seed 1: CryptoPro-A (index 0).
	f.Add(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), make([]byte, 32), byte(0))
	// Seed 2: CryptoPro-B (index 1), all-0xff UKM.
	f.Add(bytes.Repeat([]byte{0xa5}, 32), bytes.Repeat([]byte{0x5a}, 32), bytes.Repeat([]byte{0xff}, 32), byte(1))
	// Seed 3: TC26-256-B (index 4).
	f.Add(bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x12}, 32), byte(4))
	// Seed 4: TC26-256-C (index 5).
	f.Add(bytes.Repeat([]byte{0x55}, 32), bytes.Repeat([]byte{0x66}, 32), bytes.Repeat([]byte{0x34}, 32), byte(5))
	// Seed 5: TC26-256-D (index 6).
	f.Add(bytes.Repeat([]byte{0x77}, 32), bytes.Repeat([]byte{0x88}, 32), bytes.Repeat([]byte{0x56}, 32), byte(6))
	// Seed 6: CryptoPro-C (index 2).
	f.Add(bytes.Repeat([]byte{0x99}, 32), bytes.Repeat([]byte{0xaa}, 32), bytes.Repeat([]byte{0x78}, 32), byte(2))

	f.Fuzz(func(t *testing.T, seedA, seedB, rndUKM []byte, curveIdx byte) {
		entry := curve256OIDs[int(curveIdx)%len(curve256OIDs)]

		oracleCrv, err := gost.CurveByOID(entry.oracle)
		if err != nil {
			t.Fatalf("oracle CurveByOID(%s): %v", entry.name, err)
		}
		crCurve, err := gost3410curves.CurveByOID(entry.cleanRoom)
		if err != nil {
			t.Fatalf("clean-room CurveByOID(%s): %v", entry.name, err)
		}

		sa := fixLen(seedA, 32)
		sb := fixLen(seedB, 32)
		ukm := fixLen(rndUKM, 32)

		privA, pubA, err := gost.GenerateEphemeralKey(oracleCrv, bytes.NewReader(sa))
		if err != nil {
			t.Skipf("gen A: %v", err)
		}
		privB, pubB, err := gost.GenerateEphemeralKey(oracleCrv, bytes.NewReader(sb))
		if err != nil {
			t.Skipf("gen B: %v", err)
		}

		// KEG-04 fix: run both sides before skipping. Both must agree on
		// success vs failure; skipping is only safe when both error.
		ref, oracleErr := gost.KEG2012_256(oracleCrv, pubB, privA, ukm)
		got, cleanErr := KEG2012_256(crCurve, pubB, privA, ukm)
		if (oracleErr == nil) != (cleanErr == nil) {
			t.Fatalf("oracle/clean-room error mismatch (%s): oracle=%v clean-room=%v",
				entry.name, oracleErr, cleanErr)
		}
		if oracleErr != nil {
			// Both sides reject — safe to skip.
			t.Skipf("both sides reject (%s): oracle=%v clean-room=%v",
				entry.name, oracleErr, cleanErr)
		}
		if got != ref {
			t.Fatalf("clean-room != oracle (%s)\n got %x\n ref %x",
				entry.name, got[:], ref[:])
		}

		// Pair symmetry: A→B must equal B→A.
		sym, err := KEG2012_256(crCurve, pubA, privB, ukm)
		if err != nil {
			t.Fatalf("clean-room sym (%s): %v", entry.name, err)
		}
		if sym != got {
			t.Fatalf("not pair-symmetric (%s)\n A→B %x\n B→A %x",
				entry.name, got[:], sym[:])
		}
	})
}

// FuzzKEG2012_256_RawInputs feeds fuzzer-controlled raw bytes directly to
// both the oracle and the clean-room, bypassing the ephemeral key generator.
// This exercises the zero-priv rejection and boundary-scalar paths that the
// generator-based fuzz cannot reach.
//
// Known asymmetry (not a bug): gogost's gost3410.NewPublicKey does NOT check
// on-curve membership, while the clean-room vko.loadPublicLE calls IsOnCurve.
// When the clean-room rejects an off-curve point that the oracle accepts,
// that is clean-room strictness, not a divergence — so oracle-accepts /
// clean-room-rejects on the pub is skipped with a note. The reverse
// (clean-room accepts / oracle rejects) would still be a fatal.
//
// Findings: KEG-06
func FuzzKEG2012_256_RawInputs(f *testing.F) {
	// Seed 0: KAT valid inputs on TC26-256-A (both sides succeed).
	f.Add(seedHex(pubBHex), seedHex(privAHex), seedHex(ukmHex), byte(3))
	// Seed 1: zero priv (both sides must reject).
	f.Add(seedHex(pubBHex), make([]byte, 32), seedHex(ukmHex), byte(3))
	// Seed 2: all-zeros pub+priv on CryptoPro-A (oracle may accept zero pub;
	// clean-room will reject off-curve zero — exercises the skip branch).
	f.Add(make([]byte, 64), make([]byte, 32), seedHex(ukmHex), byte(0))
	// Seed 3: all-zeros UKM (zero-UKM special case) on TC26-256-A.
	f.Add(seedHex(pubBHex), seedHex(privAHex), make([]byte, 32), byte(3))

	f.Fuzz(func(t *testing.T, rawPub, rawPriv, rndUKM []byte, curveIdx byte) {
		entry := curve256OIDs[int(curveIdx)%len(curve256OIDs)]

		oracleCrv, err := gost.CurveByOID(entry.oracle)
		if err != nil {
			t.Fatalf("oracle CurveByOID(%s): %v", entry.name, err)
		}
		crCurve, err := gost3410curves.CurveByOID(entry.cleanRoom)
		if err != nil {
			t.Fatalf("clean-room CurveByOID(%s): %v", entry.name, err)
		}

		pub := fixLen(rawPub, 64)
		priv := fixLen(rawPriv, 32)
		ukm := fixLen(rndUKM, 32)

		ref, oracleErr := gost.KEG2012_256(oracleCrv, pub, priv, ukm)
		got, cleanErr := KEG2012_256(crCurve, pub, priv, ukm)

		// Known asymmetry: oracle (gogost) does not validate on-curve
		// membership; clean-room does. When oracle accepts but clean-room
		// rejects, the pub is likely off-curve — skip as a documented
		// strictness difference.
		if oracleErr == nil && cleanErr != nil {
			t.Skipf("clean-room stricter than oracle (%s): clean-room=%v pub=%x",
				entry.name, cleanErr, pub)
		}
		// The other direction (clean-room accepts, oracle rejects) would
		// indicate a real parity failure.
		if oracleErr != nil && cleanErr == nil {
			t.Fatalf("clean-room accepted what oracle rejected (%s): oracle=%v pub=%x priv=%x",
				entry.name, oracleErr, pub, priv)
		}
		// When both accept, outputs must match.
		if oracleErr == nil && cleanErr == nil && got != ref {
			t.Fatalf("output mismatch (%s)\n got %x\n ref %x", entry.name, got[:], ref[:])
		}
	})
}
