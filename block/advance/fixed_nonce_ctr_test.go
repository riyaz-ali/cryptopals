package advance

import (
	"bufio"
	"bytes"
	"crypto.io/basics"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
)

func lines(f io.Reader) ([][]byte, error) {
	var lines [][]byte
	var scanner = bufio.NewScanner(f)

	for scanner.Scan() {
		lines = append(lines, b64(scanner.Text()))
	}

	return lines, scanner.Err()
}

func xor(cipher, key []byte) []byte {
	var plain = make([]byte, len(cipher))
	basics.Xor(plain, cipher, key)
	return plain
}

// Challenge #20
func TestFixedNonceOracle(t *testing.T) {
	var f, _ = ioutil.ReadFile("20.txt")
	var buf = bytes.NewBuffer(f)

	var oracle = fixedNonceOracle()

	var plain, _ = lines(buf)
	var ciphers = make([][]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		ciphers[i] = oracle(plain[i])
	}

	var key = AttackFixedNonceOracle(ciphers)
	for i := 0; i < len(ciphers); i++ {
		fmt.Printf("i: %d\t%s\n", i, xor(ciphers[i], key))
	}
}
