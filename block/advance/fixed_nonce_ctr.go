package advance

import (
	"crypto.io/basics"
	. "crypto.io/block"
	"crypto/aes"
	"math"
)

func fixedNonceOracle() OracleFn {
	var k = Key()
	var cp, _ = aes.NewCipher(k)
	var nonce = make([]byte, cp.BlockSize()/2)

	return func(src []byte) []byte {
		var ctr, _ = NewCTR(cp, nonce)
		var dst = make([]byte, len(src))
		ctr.XORKeyStream(dst, src)
		return dst
	}
}

func AttackFixedNonceOracle(ciphers [][]byte) []byte {
	var min = math.MaxInt16
	{ // find the min length for the smallest cipher
		for i := range ciphers {
			if l := len(ciphers[i]); l < min {
				min = l
			}
		}
	}

	// bytes at same index in [ciphers] are encrypted with same key
	// we treat those bytes as [column] and break it using [basics.SingleKeyCipher]
	var matrix = make(basics.Matrix, len(ciphers))
	{ // fill the matrix
		for i := range ciphers {
			matrix[i] = make([]byte, min)
			copy(matrix[i], ciphers[i][:min])
		}
	}
	matrix = matrix.Transpose()

	// keystream is the recovered keystream from the ciphertext
	var keystream = make([]byte, min)
	var scorer = basics.EnglishScore(basics.WikipediaMap)
	for row := 0; row < len(matrix); row++ {
		_, keystream[row] = basics.SingleKeyCipher(matrix[row], scorer)
	}
	
	return keystream
}
