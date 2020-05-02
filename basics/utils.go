package basics

import "math/bits"

// Hamming returns the Hamming distance / edit distance between any two []byte.
// It returns negative math.Inf if len(a) != len(b)
func Hamming(a, b string) int {
	var r1 = []rune(a)
	var r2 = []rune(b)

	var min = func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}

	var distance = 0
	for i := 0; i < min(len(r1), len(r2)); i++ {
		distance += bits.OnesCount8(uint8(r1[i] ^ r2[i]))
	}
	return distance
}
