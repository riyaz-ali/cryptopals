package block

import (
	"testing"
)

func TestBitFlippinOracle(t *testing.T) {
	e, d := newBitFlippinOracle()
	if isAdmin(d(e([]byte(";admin=true")))) {
		t.Fail()
	}
}

// Challenge  #16
func TestBitFlippinAttack(t *testing.T) {
	e, d := newBitFlippinOracle()
	if !isAdmin(d(BitFlippinAttack(e))) {
		t.Fail()
	}
}
