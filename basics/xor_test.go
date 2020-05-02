package basics

import "testing"

func Test_xor(t *testing.T) {
	var input = make([][]byte, 2)
	input[0], _ = DecodeHex("1c0111001f010100061a024b53535009181c")
	input[1], _ = DecodeHex("686974207468652062756c6c277320657965")

	var expected = "746865206b696420646f6e277420706c6179"

	var xd = make([]byte, len(input[0]))
	_, _ = Xor(xd, input[0], input[1])
	if EncodeHex(xd) != expected {
		t.Errorf("mismatched output!\nexpected '%s'\ngot '%s'", expected, EncodeHex(xd))
	}
}
