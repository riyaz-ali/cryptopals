package basics

import (
	"math"
)

// Alias for [][]byte
type matrix [][]byte

// transpose performs matrix transposition and returns a new [][]byte
func (b matrix) transpose() [][]byte {
	xl := len(b[0])              // rows
	yl := len(b)                 // cols
	result := make([][]byte, xl) // use rows' length for cols coz we're transposing
	for i := range result {
		result[i] = make([]byte, yl)
	}
	for i := 0; i < xl; i++ {
		for j := 0; j < yl; j++ {
			result[i][j] = b[j][i]
		}
	}
	return result
}

// BreakRepeatingKeyXOR breaks repeating key XOR by using algorithm defined at [https://cryptopals.com/sets/1/challenges/6]
func BreakRepeatingKeyXOR(input []byte) ([]byte, error) {
	// find the likely keysize
	var keysize = 0
	{
		var bestScore = math.MaxFloat64
		for i := 2; i*4*2 < len(input); i++ {
			var a, b = string(input[:i*4]), string(input[i*4 : i*4*2])
			var score = float64(Hamming(a, b)) / float64(i)
			if score < bestScore {
				keysize = i
				bestScore = score
			}
		}
	}

	// divide the ciphertext into blocks of length [ks]
	var blocks = make(matrix, len(input)/keysize)
	for i := 0; i < (len(input) / keysize); i++ {
		var start = i * keysize
		var end = start + keysize
		blocks[i] = make([]byte, end-start)
		copy(blocks[i], input[start:end])
	}
	blocks = blocks.transpose() // transpose the blocks

	var key = make([]byte, keysize)
	for i, block := range blocks {
		var _, k = SingleKeyCipher(block, EnglishScore(AliceInWonderland))
		key[i] = k
	}

	return RepeatingKeyXOR(input, key), nil
}
