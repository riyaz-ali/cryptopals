package block

import (
	"bytes"
	"testing"
)

func TestDetectionOracle(t *testing.T) {
	var txt = bytes.Repeat([]byte{0x97}, 16*3)

	var ecb, cbc = 0, 0
	for i := 0; i < 1000; i++ {
		var mode = DetectionOracle(EncryptOracle(txt))
		if mode == ECB {
			ecb++
		} else {
			cbc++
		}
	}
	t.Logf("ecb: %d, cbc: %d", ecb, cbc)
}
