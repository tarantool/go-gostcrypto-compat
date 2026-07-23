// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package cmac

// xor xors the bytes in dst with src and writes the result to dst.
// The destination is assumed to have enough space.
//
// Vendoring note: upstream ships a second, amd64-only xor implementation
// (xor_amd64.go) that reinterprets the byte slices as []uintptr via unsafe.
// That optimized path is intentionally omitted here — this oracle is test-only,
// so the portable, allocation-free loop is kept for every architecture and the
// unsafe pointer aliasing is avoided. The upstream `// +build !amd64`
// constraint is dropped so this file compiles everywhere.
func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}
