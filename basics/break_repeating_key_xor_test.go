package basics

import (
	"io/ioutil"
	"testing"
)

// Challenge #6
func Test_BreakRepeatingKeyXOR(t *testing.T) {
	var input, _ = ioutil.ReadFile("6.txt")
	if got, err := BreakRepeatingKeyXOR(input); err != nil {
		t.Errorf("failed to decrypt ciphertext! error: %s", err)
	} else {
		t.Logf("\n%s", string(got))
	}
}
