package basics

import "testing"

func Test_HammingDistance(t *testing.T) {
	t.Run("should return correct distance for values with equal length", func(t *testing.T) {
		const expected = 37
		if distance := Hamming("this is a test", "wokka wokka!!!"); distance != expected {
			t.Errorf("incorrect distance value! expected: '%v' got: '%v'", expected, distance)
		}
	})
}
