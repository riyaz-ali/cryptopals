package block

import (
	"crypto.io/basics"
	"crypto/cipher"
)

// cbc is a cipher.BlockMode implementation where each block of plaintext is XORed with the
// previous ciphertext block before being encrypted.
//
// see also: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
type cbc struct {
	// underlying block cipher
	cp cipher.Block

	// mode initialisation vector
	iv []byte
}

func newCBC(cp cipher.Block, iv []byte) *cbc {
	if len(iv) != cp.BlockSize() {
		panic("crypto/cbc: length of iv must be equal to block size of cipher")
	}
	return &cbc{cp: cp, iv: iv}
}

func NewCBCEncrypter(cp cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcEncrypter)(newCBC(cp, iv))
}

func NewCBCDecrypter(cp cipher.Block, iv []byte) cipher.BlockMode {
	return (*cbcDecrypter)(newCBC(cp, iv))
}

// cbcEncrypter implements an encrypting cipher.BlockMode for cbc
type cbcEncrypter cbc

func (cbc *cbcEncrypter) BlockSize() int {
	return cbc.cp.BlockSize()
}

func (cbc *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%cbc.cp.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	var blockSize = cbc.cp.BlockSize()
	var last = cbc.iv
	for len(src) > 0 {
		_, _ = basics.Xor(dst[:blockSize], src[:blockSize], last)
		cbc.cp.Encrypt(dst[:blockSize], dst[:blockSize])

		last = dst[:blockSize]
		src = src[blockSize:]
		dst = dst[blockSize:]
	}

	// save for next call to CryptBlocks
	copy(cbc.iv, last)
}

// cbcDecrypter implements an decrypting cipher.BlockMode for cbc
type cbcDecrypter cbc

func (cbc *cbcDecrypter) BlockSize() int {
	return cbc.cp.BlockSize()
}

func (cbc *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%cbc.cp.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	var last = cbc.iv
	var blockSize = cbc.cp.BlockSize()
	for i := 0; i < len(src); i += blockSize {
		var cph = src[i : i+blockSize]
		cbc.cp.Decrypt(dst[i:i+blockSize], cph)
		_, _ = basics.Xor(dst[i:i+blockSize], dst[i:i+blockSize], last)
		last = cph
	}

	// save for next call to CryptBlocks
	copy(cbc.iv, last)
}

// guard rail
var _ cipher.BlockMode = (*cbcEncrypter)(nil)
var _ cipher.BlockMode = (*cbcDecrypter)(nil)
