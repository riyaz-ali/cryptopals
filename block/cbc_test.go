package block

import (
	"bytes"
	"crypto.io/basics"
	"crypto/aes"
	"encoding/hex"
	"io/ioutil"
	"testing"
)

// Challenge  #10 part 1
func TestCbcEncrypter(t *testing.T) {
	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}
	var cp, _ = aes.NewCipher(key)
	var iv = make([]byte, cp.BlockSize()) // all zero iv
	var cbc = NewCBCEncrypter(cp, iv)

	// test values
	var txt = "hello crypto!"
	var enc, _ = basics.DecodeBase64([]byte("sfAskbkmOdvRGvuVdytc/Q=="))

	var src = PKCS7([]byte(txt), cbc.BlockSize())
	var dst = make([]byte, len(src))
	cbc.CryptBlocks(dst, src)

	if !bytes.Equal(dst, enc) {
		t.Errorf("unexpected output:\n%s", hex.Dump(dst))
	}
}

// Challenge  #10 part 2
func TestCbcDecrypter(t *testing.T) {
	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}
	var cp, _ = aes.NewCipher(key)
	var iv = make([]byte, cp.BlockSize()) // all zero iv
	var cbc = NewCBCDecrypter(cp, iv)

	var src, _ = ioutil.ReadFile("10.txt")
	src, _ = basics.DecodeBase64(src)
	var dst = make([]byte, len(src))
	cbc.CryptBlocks(dst, src)

	t.Logf("got:\n%s", hex.Dump(dst))
}
