package advance

import (
	"testing"
)

// Challenge #21
func TestMT19937(t *testing.T) {
	// values taken from https://create.stephan-brumme.com/mersenne-twister with seed = 0x1234
	var known = []int32{1199130486, 1013474448, 1514048812, -1491904197, 1013596837, 431003429, 1048473815, -361364450, 763979878, -1615509913}
	var prng = NewMT19937(0x1234)
	for i := 0; i < len(known); i++ {
		if v := prng.Next(); known[i] != v {
			t.Fail()
		}
	}
}
