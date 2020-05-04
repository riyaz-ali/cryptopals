package advance

import (
	. "crypto.io/block"
	"crypto/aes"
	"crypto/cipher"
)

func newPaddingOracle(c []byte) (func() []byte, func([]byte) error) {
	var k = Key()
	var cp, _ = aes.NewCipher(k)

	var enc = func() []byte {
		var iv = Key()
		var cbc = cipher.NewCBCEncrypter(cp, iv)

		var src = PKCS7(c, cbc.BlockSize())
		var dst = make([]byte, len(src))
		cbc.CryptBlocks(dst, src)

		return append(iv, dst...)
	}

	var dec = func(src []byte) error {
		var cbc = cipher.NewCBCDecrypter(cp, src[:cp.BlockSize()])

		var dst = make([]byte, len(src)-cbc.BlockSize())
		cbc.CryptBlocks(dst, src[cbc.BlockSize():])

		// we aren't interested in the decrypted value
		var _, err = ValidatePadding(dst)
		return err
	}

	return enc, dec
}

func PaddingOracleAttack(enc func() []byte, dec func([]byte) error) ([]byte, error) {
	// we already know the block size
	const bs = 16

	// first, we get the encrypted payload and iv from our encryption oracle
	var out = enc()

	var plaintext []byte
	// loop through [out] until we've reached the last block
	// take two blocks at a time, [:2*bs]
	// manipulate values in ciphertext of block [:bs] to cause changes in plaintext of block[bs : 2*bs]
	for len(out) > bs {
		var result, intermediate [bs]byte
		var c0, c1 = make([]byte, bs), make([]byte, bs)
		copy(c0, out[:bs])
		copy(c1, out[bs:2*bs])

		for i := 0; i < bs; i++ {
			// the current byte position that we're decrypting
			var pos = bs - i - 1
			var value = byte(i + 1) // the expected value that would generate a correct padding

			// forge fake values using existing knowledge of intermediary values
			// to generate expected padding in i-1 blocks
			for k := 0; k < i; k++ {
				c0[bs-k-1] = value ^ intermediate[bs-k-1]
			}

			// for all possible byte combination
			for j := 0; j < 256; j++ {
				c0[pos] = byte(j)
				if err := dec(append(c0, c1...)); err == nil {
					// work around for false positive cases
					// ------------------------
					// this is a _really_ interesting edge cases
					// because of the way we treat the last padding block (we treat it similar to other blocks)
					// we might run into a situation where we might accidentally test a value for [j]
					// which actually produces a correct padding!
					// e.g. if we have a block (this is the case with the first message) like this,
					// A B C 13 13 13 13 13 13 13 13 13 13 13 13 13
					// and we are testing for the padding byte (or the last byte in sequence)
					// there is a possibility where we might set [j] to a value that yields 13 in plaintext
					// and the oracle would happily return true for it but what we actually wanted
					// was to set the byte to 0x01 and "recover" 13 as a result
					// a better description to this could be found at [https://eklitzke.org/the-cbc-padding-oracle-problem]
					if i == 0 {
						var a = c0[pos-1]
						c0[pos-1] = 0xff
						err = dec(append(c0, c1...))
						c0[pos-1] = a
						if err != nil {
							continue
						}
					}

					// the intermediate byte (one that's decrypted but not XOR'd)
					// is given by equation, Dk(c1) = p1 ^ c0
					// for byte position n, Dk(c1)[n] = p1[n] ^ c0[n]
					// in our case, we know p1[n] will be equal to (value + 1) or current index (see PKCS7)
					// so, to get the intermediate we do:
					intermediate[pos] = value ^ byte(j)
					result[pos] = intermediate[pos] ^ out[pos] // get real plaintext by XORing with original C0 byte
					break
				}
			}
		}

		plaintext = append(plaintext, result[:]...)
		out = out[bs:]
	}

	return ValidatePadding(plaintext)
}
