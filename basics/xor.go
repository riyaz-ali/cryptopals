package basics

import "errors"

// Xor applies xor operation on [a] and [b] and return the resulting byte array
func Xor(dst, a, b []byte) (int, error) {
	if len(a) != len(b) {
		return -1, errors.New("inputs not of same length")
	}

	var i = 0
	for i < len(a) {
		dst[i] = a[i] ^ b[i]
		i++
	}

	return i, nil
}
