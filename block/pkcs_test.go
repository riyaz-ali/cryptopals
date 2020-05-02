package block

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Challenge  #9
func Test_PKCS(t *testing.T) {
	var key = []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}

	if r := PKCS7(key, 16); !bytes.Equal(r, []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E', 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}) {
		t.Errorf("unexpected result: got: \n%s", hex.Dump(r))
	}
	if r := PKCS7(key, 20); !bytes.Equal(r, []byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E', 0x04, 0x04, 0x04, 0x04}) {
		t.Errorf("unexpected result: got: \n%s", hex.Dump(r))
	}
}

// Challenge  #15
func TestValidatePadding(t *testing.T) {
	var cases = []struct {
		Input  []byte
		Output []byte
	}{
		{[]byte("ICE ICE BABY\x04\x04\x04\x04"), []byte("ICE ICE BABY")},
		{[]byte("ICE ICE BABY\x05\x05\x05\x05"), nil},
		{[]byte("ICE ICE BABY\x01\x02\x03\x04"), nil},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("case#%d", i), func(t *testing.T) {
			var b, e = ValidatePadding(tc.Input)
			if tc.Output != nil && e != nil {
				t.Errorf("expected input to be valid but failed with error: %v", e)
			} else if tc.Output == nil && e == nil {
				t.Error("expected input to be invalid but got no error")
			} else if !bytes.Equal(tc.Output, b) {
				t.Error("mis-matched result")
			}
		})
	}
}
