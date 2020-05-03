package block

import (
	"bytes"
	"crypto.io/basics"
	"crypto/aes"
	"math/rand"
)

type OracleFn func([]byte) []byte

func consistentEncryptOracle(secret []byte) OracleFn {
	var k = Key() // consistent but unknown

	return func(in []byte) []byte {
		var cp, _ = aes.NewCipher(k)
		var ecb = basics.NewECBEncrypter(cp)

		var src = append(in, secret...)
		src = PKCS7(src, cp.BlockSize())
		var dst = make([]byte, len(src))
		ecb.CryptBlocks(dst, src)

		return dst
	}
}

func harderConsistentEncryptOracle(secret []byte) OracleFn {
	// consistent encrypting OracleFn
	var o = consistentEncryptOracle(secret)

	// random prefix
	var r = make([]byte, rand.Intn(100))

	return func(in []byte) []byte {
		rand.Read(r[:])
		// append random prefix before forwarding to OracleFn
		return o(append(r, in...))
	}
}

// blockSize returns the calculated block size for the given OracleFn function
func blockSize(oracle OracleFn) int {
	var delta, last, length = 0, 0, 0
	for i := 0; i < 50; i++ {
		var p = bytes.Repeat([]byte{'A'}, i)
		if l := len(oracle(p)); l > length {
			delta, length, last = i-last, l, i
		}
	}
	return delta
}

// mod normalizes modulo such that it doesn't return negative if a < 0
func mod(a, b int) int {
	return (a%b + b) % b
}

func chosenPlainTextAttack(oracle OracleFn) []byte {
	// find the block size used
	var blockSize = blockSize(oracle)

	// prepare a map of _known_ plain text to cipher text blocks
	// to do this, have a crafted input which is exactly one byte shorter than the block size
	// and loop over all 256 possible bytes, passing to the OracleFn and recording the returned ciphertext block
	var buildMap = func(known []byte) map[string]byte {
		var bs = blockSize

		var craftd = bytes.Repeat([]byte{'A'}, bs)
		craftd = append(craftd, known...)
		craftd = append(craftd, '?')
		craftd = craftd[len(craftd)-bs:] // just pick the last block

		var res = make(map[string]byte)
		for i := 0; i < 256; i++ {
			craftd[bs-1] = byte(i)
			var block = oracle(craftd)[:bs] // read only the first block
			res[string(block)] = byte(i)
		}
		return res
	}

	// now, for each ciphertext byte, create a crafted payload and pass it to the OracleFn
	// the last byte of the payload must be the byte from ciphertext
	// map the response to values in your ciphertext dictionary, and voila! you've broken the encryption
	var plaintext []byte
	var cipherTextLength = len(oracle([]byte{}))
	for i := 0; i < cipherTextLength; i++ {
		var d = buildMap(plaintext)
		var p = bytes.Repeat([]byte{'A'}, mod(blockSize-i-1, blockSize))

		var block = oracle(p)
		var x = (i / blockSize) * blockSize // skip blocks..
		block = block[x:][:blockSize]       // read only a single from [x:]

		var rec = d[string(block)]
		plaintext = append(plaintext, rec)
	}
	return plaintext
}

func harderChosenPlainTextAttack(oracle OracleFn) []byte {
	// find the block size used
	var bs = blockSize(oracle)

	// determine the prefix length
	var prefixLength = func() int {

		// index returns the index position of the first block
		// in a pair of similar consecutive blocks
		var index = func(b []byte, bs int) int {
			// loop through all the blocks and get the first
			// identical set of blocks those would be our [x] bytes
			for i := 1; i < len(b)/bs; i++ {
				var prev = b[(i-1)*bs : ((i-1)*bs)+bs]
				var curr = b[i*bs : (i*bs)+bs]
				if bytes.Equal(prev, curr) {
					// we've found our buffers!
					// now determine the start address of [prev]
					return (i - 1) * bs
				}
			}
			return -1
		}

		// create a large buffer of known characters
		// and encrypt it using the OracleFn
		// the OracleFn will add the prefix and suffix such that it becomes
		// append(append(prefix, x...), suffix...)
		var out = oracle(bytes.Repeat([]byte{0x42}, 500))
		var s = index(out, bs) // s is the start position for our blocks containing [x] bytes

		// next, we determine the prefix length by iterating over values < bs
		// and creating known character buffer of size (p + (bs * 2) + 1)
		// here, we are trying to locate the two adjacent blocks (remember, bs * 2)
		// and we find those, p would give us the additional padding blocks consumed by prefix to complete a block
		// we subtract that from our previous block start pointer and we got the prefix length
		for p := 0; p < bs; p++ {
			var m = append(bytes.Repeat([]byte{0x42}, p+(bs*2)), 'X')
			if index(oracle(m), bs) == s {
				return s - p
			}
		}
		return 0
	}()

	// use existing function with a normalised OracleFn that removes the prefix
	return chosenPlainTextAttack(func(in []byte) []byte {
		var x = bs - (prefixLength % bs)
		var pad = append(bytes.Repeat([]byte{'A'}, x), in...) // pad evens out the prefix into uniform blocks
		var out = oracle(pad)
		return out[prefixLength+x:]
	})
}
