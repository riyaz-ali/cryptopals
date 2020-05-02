package block

import (
	"crypto.io/basics"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"time"
)

func key() []byte {
	var p [16]byte
	rand.Read(p[:])
	return p[:]
}

func rnd(min, max int) int {
	return rand.Intn(max-min) + min
}

func selector(cp cipher.Block) cipher.BlockMode {
	if rand.Int()%2 == 0 {
		return basics.NewECBEncrypter(cp)
	} else {
		var iv [16]byte
		rand.Read(iv[:])
		return NewCBCEncrypter(cp, iv[:])
	}
}

func EncryptOracle(in []byte) []byte {
	var cp, _ = aes.NewCipher(key())
	var mode = selector(cp)

	var pre, post = rnd(5, 10), rnd(5, 10)
	var src = make([]byte, pre+len(in)+post)
	rand.Read(src[:pre])
	copy(src[pre:], in)
	rand.Read(src[pre+len(in):])
	src = PKCS7(src, cp.BlockSize())

	var dst = make([]byte, len(src))
	mode.CryptBlocks(dst, src)

	return dst
}

func init() {
	rand.Seed(time.Now().UnixNano())
}