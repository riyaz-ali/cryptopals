package basics

import "testing"

func Test_repeating_key_xor(t *testing.T) {
	var input = []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	var expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	var key = []byte{'I', 'C', 'E'}

	if got := RepeatingKeyXOR(input, key); EncodeHex(got) != expected {
		t.Errorf("mismatched output!\nexpected '%s'\ngot '%s'", expected, got)
	}
}
