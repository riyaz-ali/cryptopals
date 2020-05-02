package basics

import (
	b "encoding/base64"
	h "encoding/hex"
)

// DecodeHex decodes the hex string representation into a slice of bytes
func DecodeHex(hex string) ([]byte, error) {
	out := make([]byte, h.DecodedLen(len(hex)))
	n, err := h.Decode(out, []byte(hex))
	return out[:n], err
}

// EncodeHex encodes the given src byte array into a hex string
func EncodeHex(src []byte) string {
	return h.EncodeToString(src)
}

// EncodeBase64 encodes the given [src] bytes into Base64 string representation
func EncodeBase64(src []byte) string {
	return b.StdEncoding.EncodeToString(src)
}

// DecodeBase64 decodes the given [src] string from Base64 representation
func DecodeBase64(src []byte) ([]byte, error) {
	var dst = make([]byte, b.StdEncoding.DecodedLen(len(src)))
	if n, err := b.StdEncoding.Decode(dst, src); err != nil {
		return nil, err
	} else {
		return dst[:n], nil
	}
}
