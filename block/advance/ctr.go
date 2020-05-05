package advance

import (
	"crypto.io/basics"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

var (
	ErrInvalidNonceLength = errors.New("crypto/ctr: invalid nonce length")
)

// ctr implements "Counter-mode" for Block cipher operations https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
// effectively turning the underlying cipher.Block into a stream cipher
type ctr struct {
	// the underlying block cipher
	block cipher.Block
	// current counter position
	counter []byte
	nonce   []byte
}

func NewCTR(block cipher.Block, nonce []byte) (cipher.Stream, error){
	if len(nonce) != block.BlockSize()/2 {
		return nil, ErrInvalidNonceLength
	}

	var _nonce = make([]byte, len(nonce))
	copy(_nonce, nonce)

	return &ctr{block: block, nonce: _nonce, counter: make([]byte, block.BlockSize()/2)}, nil
}

func (ctr *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/ctr: destination buffer cannot be smaller than source")
	}

	var bs = ctr.block.BlockSize()

	var nonce = binary.LittleEndian.Uint64(ctr.nonce)
	var counter = binary.LittleEndian.Uint64(ctr.counter)
	var key = make([]byte, bs)

	for len(src) > 0 {
		binary.LittleEndian.PutUint64(key[:bs/2], nonce)
		binary.LittleEndian.PutUint64(key[bs/2:], counter)
		counter++

		// generate next key from keystream
		ctr.block.Encrypt(key, key)

		// and XOR it with data from [src] to produce output in [dst]
		var n = basics.Xor(dst, src, key)

		src = src[n:]
		dst = dst[n:]
	}

	binary.LittleEndian.PutUint64(ctr.nonce, nonce)
	binary.LittleEndian.PutUint64(ctr.counter, counter)
}
