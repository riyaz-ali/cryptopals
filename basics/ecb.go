package basics

import (
	"crypto/cipher"
	"github.com/pkg/errors"
)

// ECB is a container type for methods that implement block cipher encryption using ECB mode
type ECB struct {
	cp        cipher.Block
	blockSize int
}

// NewECB returns *ECB that uses the given block cipher and operates in ECB mode
func NewECB(cp cipher.Block) *ECB {
	return &ECB{cp: cp, blockSize: cp.BlockSize()}
}

func NewECBEncrypter(cp cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(NewECB(cp))
}

func NewECBDecrypter(cp cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(NewECB(cp))
}

// Detect checks whether the given [input] is encrypted using ECB
func (ecb *ECB) Detect(inputs []byte) (ok bool, err error) {
	if len(inputs)%ecb.blockSize != 0 {
		return false, errors.New("length is not multiple of block size")
	}

	var cache = make(map[string]struct{})
	for i := 0; i < len(inputs); i += ecb.blockSize {
		var chunk = string(inputs[i : i+ecb.blockSize])
		if _, seen := cache[chunk]; seen {
			return true, nil
		}
		cache[chunk] = struct{}{}
	}

	return false, nil
}

// ====================
// cipher.BlockMode implementation for ECB
// ====================

// ecbEncrypter implements an encrypting cipher.BlockMode for ECB
type ecbEncrypter ECB

func (ecb *ecbEncrypter) BlockSize() int {
	return ecb.cp.BlockSize()
}

func (ecb *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%ecb.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for i := 0; i < len(src); i += ecb.blockSize {
		ecb.cp.Encrypt(dst[i:], src[i:])
	}
}

// ecbDecrypter implements a decrypting cipher.BlockMode for ECB
type ecbDecrypter ECB

func (ecb *ecbDecrypter) BlockSize() int {
	return ecb.cp.BlockSize()
}

func (ecb *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%ecb.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for i := 0; i < len(src); i += ecb.blockSize {
		ecb.cp.Decrypt(dst[i:], src[i:])
	}
}


// guardrails...
var _ cipher.BlockMode = (*ecbEncrypter)(nil)
