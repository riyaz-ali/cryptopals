package block

import (
	"crypto.io/basics"
	"crypto/aes"
)

type BlockMode int

const (
	ECB BlockMode = iota
	CBC
)

func DetectionOracle(in []byte) BlockMode {
	var k = make([]byte, 16) // Key isn't that important here
	var cp, _ = aes.NewCipher(k)

	var ecb = basics.NewECB(cp)
	if ok, _ := ecb.Detect(in); ok {
		return ECB
	}
	return CBC
}
