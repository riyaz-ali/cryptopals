package advance

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// Challenge #18 part 1
func TestCtrDecrypt(t *testing.T) {
	var in = b64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	var expected = b64("WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA==")
	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}
	var nonce = make([]byte, 8)  // all empty nonce

	var cp, _ = aes.NewCipher(key)
	var ctr, _ = NewCTR(cp, nonce)

	var dst = make([]byte, len(in))
	ctr.XORKeyStream(dst, in)

	if !bytes.Equal(dst, expected) {
		t.Fail()
	}
}

// Challenge #18 part 2
func TestCtrEncrypt(t *testing.T) {
	var in = b64("WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA==")
	var expected = b64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}
	var nonce = make([]byte, 8)  // all empty nonce

	var cp, _ = aes.NewCipher(key)
	var ctr, _ = NewCTR(cp, nonce)

	var dst = make([]byte, len(in))
	ctr.XORKeyStream(dst, in)

	if !bytes.Equal(dst, expected) {
		t.Fail()
	}
}