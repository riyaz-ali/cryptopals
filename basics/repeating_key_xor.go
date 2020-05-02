package basics

// RepeatingKeyXOR implements repeating key XOR encryption and returns the encrypted string for the given [src] using [key]
func RepeatingKeyXOR(src, key []byte) []byte {
	// fn is a helper function that takes a key and returns a function that
	// return the next byte from key in repeatating manner
	var next = func(key []byte) func() byte {
		state := -1
		return func() byte {
			state++
			return key[state%len(key)]
		}
	}(key)

	var out = make([]byte, len(src))
	for i, val := range src {
		out[i] = byte(val) ^ next()
	}
	return out
}
