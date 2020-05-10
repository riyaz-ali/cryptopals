package basics

import (
	"io/ioutil"
	"testing"
)

// Challenge #6
func Test_BreakRepeatingKeyXOR(t *testing.T) {
	var input, _ = ioutil.ReadFile("6.txt")
	input, _ = DecodeBase64(input)
	var got = RepeatingKeyXOR(input, BreakRepeatingKeyXOR(input, HammingDistanceKeyFn, EnglishScore(AliceInWonderland)))
	t.Logf("\n%s", string(got))
}
