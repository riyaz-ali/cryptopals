package basics

import "testing"

func Test_hexToBase64(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	var h, _ = DecodeHex(input)
	var b = EncodeBase64(h)
	if  b != expected {
		t.Errorf("mismatched output!\nexpected '%s'\ngot '%s'", expected, b)
	}
}
