package gost28147imitparity

// keySize is the GOST 28147-89 key length in bytes (unexported in the
// clean-room package; inlined here for the parity test).
const keySize = 32

// fixLen normalizes b to exactly n bytes (truncating or zero-padding), used to
// derive a valid-length key from raw fuzzer bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
