package basics

import (
	"testing"
)

func Test_singleKeyCipher(t *testing.T) {
	var input, _ = DecodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	var got, key = SingleKeyCipher(input)
	t.Logf("key: %s", string(key))
	t.Logf("msg: %s", string(got))
}
