package advance

import (
	"bytes"
	"crypto.io/basics"
	"fmt"
	"testing"
)

// just a helper to decode base64 strings w/o dealing with error
func b64(s string) []byte {
	b, _ := basics.DecodeBase64([]byte(s))
	return b
}

func TestPaddingOracle(t *testing.T) {
	e, d := newPaddingOracle(b64("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="))
	b := e()
	b[47] = b[63] ^ 0x00
	if err := d(b); err == nil {
		t.Fail()
	}
}

// Challenge #17
func TestPaddingOracleAttack(t *testing.T) {
	var msgs = [][]byte{
		b64("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		b64("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		b64("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		b64("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		b64("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		b64("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		b64("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		b64("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		b64("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		b64("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}

	for i := 0; i < len(msgs); i++ {
		t.Run(fmt.Sprintf("msg#%d", i+1), func(t *testing.T) {
			if result, err := PaddingOracleAttack(newPaddingOracle(msgs[i])); err != nil {
				t.Errorf("attack failed: %v", err)
			} else {
				if !bytes.Equal(msgs[i], result) {
					t.Fail()
				}
			}
		})
	}
}
