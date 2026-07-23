package gost3410curvesparity

import (
	"testing"

	. "github.com/tarantool/go-gostcrypto/gost3410curves"
)

// allOIDs lists the supported OID arcs and their expected PointSize.
var allOIDs = []struct {
	oid       string
	name      string
	pointSize int
}{
	{"1.2.643.2.2.35.1", "CryptoPro-A", 32},
	{"1.2.643.2.2.35.2", "CryptoPro-B", 32},
	{"1.2.643.2.2.35.3", "CryptoPro-C", 32},
	{"1.2.643.7.1.2.1.1.1", "tc26-256-A", 32},
	{"1.2.643.7.1.2.1.1.2", "tc26-256-B", 32},
	{"1.2.643.7.1.2.1.1.3", "tc26-256-C", 32},
	{"1.2.643.7.1.2.1.1.4", "tc26-256-D", 32},
	{"1.2.643.7.1.2.1.2.1", "tc26-512-A", 64},
	{"1.2.643.7.1.2.1.2.2", "tc26-512-B", 64},
	{"1.2.643.7.1.2.1.2.3", "tc26-512-C", 64},
}

func mustCurve(t *testing.T, oid string) *Curve {
	t.Helper()
	c, err := CurveByOID(oid)
	if err != nil {
		t.Fatalf("CurveByOID(%s): %v", oid, err)
	}
	return c
}
