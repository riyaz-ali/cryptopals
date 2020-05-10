package advance

// This file contains an implementation of Mersenne Twister pseudorandom number generator
//
// For more details on values and an overview of the algorithm,
// check out the Wikipedia entry at https://en.wikipedia.org/wiki/Mersenne_Twister
//
// Word size used for this implementation is fixed at 32-bits

// These are the coefficients for MT19937
// For a description of what these value refer to, please check out the Wikipedia entry
const (
	w, n, m, r = 32, 624, 397, 31
	a          = 0x9908B0DF
	u, d       = 11, 0xFFFFFFFF
	s, b       = 7, 0x9D2C5680
	t, c       = 15, 0xEFC60000
	l          = 18
	f          = 1812433253

	// lower and upper masks to extract bits
	lower = uint32((1 << r) - 1) // 0x7fffffff
	upper = ^lower               // 0x80000000
)

// MT19937 is the original 32-bit variant of the algorithm
type MT19937 struct {
	// pos is the current position in the state array
	index uint16
	// state is the current internal state of the PRNG
	state [n]uint32
}

// NewMT19937 returns a new MT19937 PRNG initialized / seeded with [seed] value
func NewMT19937(seed uint32) *MT19937 {
	var m = &MT19937{}
	m.seed(seed)
	return m
}

// seed initializes / seeds the PRNG
func (mt *MT19937) seed(val uint32) {
	mt.index = n
	mt.state[0] = val
	for i := 1; i < (n - 1); i++ {
		mt.state[i] = f*(mt.state[i-1]^(mt.state[i-1]>>(w-2))) + uint32(i)
	}
}

// twist generates the next [n] values from the series
func (mt *MT19937) twist() {
	for i := 0; i < (n - 1); i++ {
		var x = (mt.state[i] & upper) + (mt.state[(i+1)%n] & lower)
		var next = x >> 1
		if (x % 2) != 0 {
			next = next ^ a
		}
		mt.state[i] = mt.state[(i+m)%n] ^ next
	}
	mt.index = 0
}

// temper applies additional transformation to input to "add more randomness"
func (mt *MT19937) temper(y uint32) uint32 {
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	return y
}

// Next returns the next random number from the sequence
func (mt *MT19937) Next() int32 {
	if mt.index >= n {
		if mt.index > n {
			// if not already seeded, seed it manually; 5489 appears in reference implementation
			// this implementation should _never_ reach this block
			// this is here just for sake of completeness
			mt.seed(5489)
		}
		mt.twist()
	}

	var y = mt.state[mt.index]
	mt.index++
	return int32(mt.temper(y))
}
