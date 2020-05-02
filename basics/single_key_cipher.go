package basics


// singleCharacterXOR XORs the given [input] bytes with [char] value and returns the resulting []byte
func singleCharacterXOR(input []byte, char byte) []byte {
	out := make([]byte, len(input))
	for i, c := range input {
		out[i] = c^char
	}
	return out
}

// englishScore computes a score for the given [input] string using character frequency technique
// see: https://en.wikipedia.org/wiki/Letter_frequency
// see: https://laconicwolf.com/2018/05/29/cryptopals-challenge-3-single-byte-xor-cipher-in-python
func englishScore(input string) float32 {
	var characterFrequencies = map[rune]float32{
		'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
		'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
		'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
		'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
		'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
		'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
		'y': .01974, 'z': .00074, ' ': .13000,
	}

	sum := float32(0)
	for _, char := range input {
		if freq, ok := characterFrequencies[char]; ok {
			sum += freq
		}
	}
	return sum
}

// SingleKeyCipher decrypts the given [enc] parameter by XOR'ing it against a single character key
func SingleKeyCipher(enc []byte) ([]byte, byte) {
	var score = float32(0)
	var result []byte
	var key byte
	for k := 0; k < 256; k++ {
		r := singleCharacterXOR(enc, byte(k))
		s := englishScore(string(r))
		if s > score {
			result = r
			score = s
			key = byte(k)
		}
	}
	return result, key
}
