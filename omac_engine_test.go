package gostcryptocompat

import (
	"encoding/hex"
	"strings"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
)

// TestOMAC_Kuznyechik_EngineOracle cross-checks our OMAC against
// gost-engine's kuznyechik-mac CLI output:
//
//	printf 'hello' | openssl dgst -engine gost -mac kuznyechik-mac \
//	  -macopt hexkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
//	=> 96e6c1913fd788e3922e617fdd341edf
func TestOMAC_Kuznyechik_EngineOracle(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xAA
	}
	block := gost3412128.NewCipher(key)
	omac, err := NewOMAC(block, 16)
	if err != nil {
		t.Fatalf("NewOMAC: %v", err)
	}
	omac.Write([]byte("hello"))
	got := omac.Sum(nil)
	want := "96e6c1913fd788e3922e617fdd341edf"
	if strings.ToLower(hex.EncodeToString(got)) != want {
		t.Errorf("OMAC(key=0xAAx32, plain='hello')\n got: %s\nwant: %s",
			hex.EncodeToString(got), want)
	}
}
