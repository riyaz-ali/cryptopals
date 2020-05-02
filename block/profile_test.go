package block

import (
	"strings"
	"testing"
)

func TestProfile(t *testing.T) {
	var profile = ProfileFor("foo@bar.com&role=admin")
	var parsed = From(profile)

	if parsed["role"] == "admin" {
		t.Fail()
	}
}

func TestEcbCutPaste(t *testing.T) {
	var buffer []byte

	// first block containing email=foo@bar.in
	buffer = append(buffer, ProfileFor("foo@bar.in")[:16]...)
	// second block containing AAAAAAAAAA&role=
	buffer = append(buffer, ProfileFor(strings.Repeat("A", 20))[16:32]...)
	// third block containing admin&role=user&
	buffer = append(buffer, ProfileFor(strings.Repeat("A", 10) + "admin")[16:32]...)
	// last block containing role=user&uid=xx + padding
	buffer = append(buffer, ProfileFor(strings.Repeat("A", 9))[16:48]...)

	if hacked := From(buffer); hacked["role"] != "admin" {
		t.Error("role of hacked profile must be admin")
	}
}
