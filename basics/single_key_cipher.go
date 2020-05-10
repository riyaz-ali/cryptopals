package basics

import (
	"io/ioutil"
	"unicode"
	"unicode/utf8"
)

// singleCharacterXOR XORs the given [input] bytes with [char] value and returns the resulting []byte
func singleCharacterXOR(input []byte, char byte) []byte {
	out := make([]byte, len(input))
	for i, c := range input {
		out[i] = c ^ char
	}
	return out
}

// Corpus is map of char occurrence frequency
type Corpus map[rune]float64

// BuildCorpus builds a [Corpus] from a file
func BuildCorpus(file string) Corpus {
	var text, _ = ioutil.ReadFile(file)
	var corpus = make(Corpus)
	for _, char := range string(text) {
		corpus[char]++
	}
	var total = utf8.RuneCountInString(string(text))
	for char := range corpus { // normalize frequencies
		corpus[char] = corpus[char] / float64(total)
	}
	return corpus
}

// AliceInWonderland is a Corpus (character frequency map) build from text file containing full volume of "Alice in Wonderland"
var AliceInWonderland = BuildCorpus("aliceinwonderland.txt")

// WikipediaMap is a Corpus derived from letter frequency map on wikipedia
var WikipediaMap = Corpus{
	'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
	'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
	'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
	'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
	'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
	'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
	'y': .01974, 'z': .00074, ' ': .13000,
}

// ScoringFunction defines a function that takes in an input string and outputs a score for it
type ScoringFunction func(input string) float64

// EnglishScore computes a score for the given [input] string using character frequency technique
func EnglishScore(corpus Corpus) ScoringFunction {
	return func(input string) float64 {
		var sum float64
		for _, char := range input {
			sum += corpus[unicode.ToLower(char)]
		}
		return sum / float64(utf8.RuneCountInString(input))
	}
}

// SingleKeyCipher decrypts the given [enc] parameter by XOR'ing it against a single character key
func SingleKeyCipher(enc []byte, scorer ScoringFunction) ([]byte, byte) {
	var score = float64(0)
	var result []byte
	var key byte
	for k := 0; k < 256; k++ {
		r := singleCharacterXOR(enc, byte(k))
		s := scorer(string(r))
		if s > score {
			result = r
			score = s
			key = byte(k)
		}
	}
	return result, key
}
