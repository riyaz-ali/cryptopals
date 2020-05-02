package block

import (
	"crypto.io/basics"
	"crypto/aes"
	"math/rand"
	"net/url"
	"strconv"
)

type UserProfile map[string]string

// key is a random but consistent (in a single run) key
var k = key() //[]byte{'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'}

// parse parses kv into a UserProfile
func parse(cookie string) UserProfile {
	var result = make(UserProfile)
	var values, _ = url.ParseQuery(cookie)
	for key := range values {
		result[key] = values.Get(key)
	}
	return result
}

// Encrypt encrypts the encoded user profile under AES-128-ECB mode
func Encrypt(profile []byte) []byte {
	var cp, _ = aes.NewCipher(k)
	var ecb = basics.NewECBEncrypter(cp)

	var src = PKCS7(profile, ecb.BlockSize())
	var dst = make([]byte, len(src))
	ecb.CryptBlocks(dst, src)

	return dst
}

// ProfileFor returns a new user profile for the given email
func ProfileFor(email string) []byte {
	var v = url.Values{}
	v.Set("email", email)
	v.Set("uid", strconv.Itoa(10+rand.Intn(90)))
	v.Set("role", "user")
	return Encrypt([]byte(v.Encode()))
}

// From decrypts the given buffer and passes it to [Parse] to create a new UserProfile
func From(p []byte) UserProfile {
	var cp, _ = aes.NewCipher(k)
	var ecb = basics.NewECBDecrypter(cp)

	var dst = make([]byte, len(p))
	ecb.CryptBlocks(dst, p)

	// strip PKCS#7 padding
	var count = int(dst[len(dst)-1])
	dst = dst[:len(dst)-count]

	return parse(string(dst))
}
