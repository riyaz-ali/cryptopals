package block

import (
	"bytes"
	"crypto.io/basics"
	"testing"
)

// Challenge  #12
func TestChosenPlainTextAttack(t *testing.T) {
	var secret, _ = basics.DecodeBase64([]byte(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`))
	var oracle = consistentEncryptOracle(secret)

	var result = chosenPlainTextAttack(oracle)
	if !bytes.Equal(secret, result[:len(secret)]) {  // trim extra stuff
		t.Error("result != secret")
	}
}

// Challenge  #14
func TestHarderChosenPlainTextAttack(t *testing.T) {
	var secret, _ = basics.DecodeBase64([]byte(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`))
	var oracle = harderConsistentEncryptOracle(secret)

	var result = harderChosenPlainTextAttack(oracle)
	if !bytes.Equal(secret, result[:len(secret)]) {  // trim extra stuff
		t.Error("result != secret")
	}
}