package basics

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"
)

// Challenge  #7
func Test_ECB_Decrypt(t *testing.T) {
	var b, _ = ioutil.ReadFile("7.txt")
	var input, _ = DecodeBase64(b)
	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}
	var cp, _ = aes.NewCipher(key)
	var ecb = NewECBDecrypter(cp)

	var dst = make([]byte, len(input))
	ecb.CryptBlocks(dst, input)
	t.Logf("\n%s", hex.Dump(dst))
}

// Challenge  #8
func Test_ECB_Detect(t *testing.T) {
	var file, _ = os.Open("8.txt")
	defer file.Close()

	var scanner = bufio.NewScanner(file)
	var lines [][]byte
	for scanner.Scan() {
		var line, _ = DecodeHex(scanner.Text())
		lines = append(lines, line)
	}

	if scanner.Err() != nil {
		t.Errorf("failed to read input: %v", scanner.Err())
		return
	}

	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}
	var cp, _ = aes.NewCipher(key)
	var ecb = NewECB(cp)
	for i, line := range lines {
		if is, err := ecb.Detect(line); is {
			t.Logf("line %d is encrypted with ECB", i+1)
		} else if err != nil {
			t.Errorf("failed to detect mode: %v", err)
		}
	}
}
