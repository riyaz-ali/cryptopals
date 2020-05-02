package block

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"net/url"
	"strings"
)

func newBitFlippinOracle() (OracleFn, OracleFn) {
	var k = key()
	var iv = key()
	var cp, _ = aes.NewCipher(k)

	// pre- and post- fix to add to payload
	var pre, post = []byte("comment1=cooking%20MCs;userdata="), []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	// enc is the encryption oracle
	// that adds a prefix and suffix to the supplied input
	var enc = func(in []byte) []byte {
		// TODO: fix own CbcEncrypter and use it instead of one from stdlib
		var cbc = cipher.NewCBCEncrypter(cp, iv)

		in = []byte(url.QueryEscape(url.PathEscape(string(in))))
		var src = append(pre, append(in, post...)...)
		src = PKCS7(src, cbc.BlockSize())

		var dst = make([]byte, len(src))
		cbc.CryptBlocks(dst, src)

		return dst
	}

	// dec is the decryption oracle
	// that decrypts the payload and returns true if it contains value 'admin=true'
	var dec = func(src []byte) []byte {
		var cbc = NewCBCDecrypter(cp, iv)

		var dst = make([]byte, len(src))
		cbc.CryptBlocks(dst, src)
		dst, _ = ValidatePadding(dst)

		return dst
	}

	return enc, dec
}

func isAdmin(s []byte) bool {
	for _, s := range strings.Split(string(s), ";") {
		if s == "admin=true" {
			return true
		}
	}
	return false
}

func BitFlippinAttack(enc OracleFn) []byte {
	// find the block size of the oracle
	var bs = blockSize(enc)

	// create a buffer of [bs] bytes
	var craft = append(bytes.Repeat([]byte{'X'}, bs), "......admin.true"...)

	// encrypt the message
	var msg = enc(craft)

	// third block is our target; it contains our X's
	// manipulate it to flip around stuff in '......admin.true' block
	var block = msg[32:48]
	block[5] = block[5] ^ (';' ^ '.')
	block[11] = block[11] ^ ('=' ^ '.')

	return msg
}
