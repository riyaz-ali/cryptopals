package block

import "errors"

// error to return when the supplied buffer doesn't have a valid PKCS#7 padding
var ErrInvalidPadding = errors.New("crypto/pkcs: invalid padding")

// PKCS7 pads the [in] byte array using PKCS#7 padding scheme
func PKCS7(in []byte, size int) (out []byte) {
	var diff = size - (len(in) % size)
	out = make([]byte, len(in)+diff)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(diff)
	}
	return out
}

// ValidatePadding validates that the given [in] buffer has valid PKCS#7 padding
func ValidatePadding(in []byte) ([]byte, error) {
	var n = in[len(in)-1]

	// make sure we are within range of input
	if int(n) > len(in) || n == 0 {
		return nil, ErrInvalidPadding
	}

	// get the last n bytes
	// and make sure the bytes are correct
	for i := 1; i < int(n); i++ {
		if in[len(in)-1-i] != n {
			return nil, ErrInvalidPadding
		}
	}

	return in[:len(in)-int(n)], nil
}
