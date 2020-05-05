package basics

// Xor applies xor operation on [a] and [b] and return the resulting byte array
func Xor(dst, a, b []byte) int {
	var n = len(a)
	if n > len(b) {
		n = len(b)
	}

	if n == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}
