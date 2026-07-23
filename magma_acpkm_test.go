package gostcryptocompat

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost341264"
)

func mustHexMagmaMesh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

var acpkmDTest = [32]byte{
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
}

func magmaACPKMMesh(key []byte) []byte {
	block := gost341264.NewCipher(key)
	out := make([]byte, 32)
	for i := 0; i < 32; i += block.BlockSize() {
		block.Encrypt(out[i:i+block.BlockSize()], acpkmDTest[i:i+block.BlockSize()])
	}
	return out
}

// TestMagmaACPKM_KeyMeshing_EngineEtalon ports the K2 etalon from tmp/engine/test_gost89.c.
func TestMagmaACPKM_KeyMeshing_EngineEtalon(t *testing.T) {
	initialKey := mustHexMagmaMesh(t,
		"8899aabbccddeeff0011223344556677"+
			"fedcba98765432100123456789abcdef")
	wantK2 := mustHexMagmaMesh(t,
		"863ea017842c3d372b18a85a28e2317d"+
			"74befc107720de0c9e8ab974abd00ca0")

	gotK2 := magmaACPKMMesh(initialKey)
	if !bytes.Equal(gotK2, wantK2) {
		t.Fatalf("K2 mismatch:\n got  %x\n want %x", gotK2, wantK2)
	}

	k3 := magmaACPKMMesh(gotK2)
	k4 := magmaACPKMMesh(k3)
	if bytes.Equal(k3, gotK2) {
		t.Fatal("K3 unexpectedly equals K2")
	}
	if bytes.Equal(k4, k3) {
		t.Fatal("K4 unexpectedly equals K3")
	}
	if len(k4) != 32 {
		t.Fatalf("K4 len=%d, want 32", len(k4))
	}
}
