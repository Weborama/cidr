This package provides an implementation of a 128 bit unsigned integer with some
implementations of:
- arithmetic operators (Add, Sub, Incr, Decr)
- binary operations (AND, OR, XOR, NOT, AND NOT, shifts)
- math/bits operations (LeadingZeros, Len, OnesCount, Reverse, ReverseBytes, TrailingZeros)

Missing operators (Mult, Div, Mod, RotateLeft etc.) to be added later.

Uses a modified copy (changes to the generated package declaration) of make_tables.go from https://github.com/golang/go/tree/master/src/math/bits.

Original use case for this package is implementing IPv6 calculations (see
[github.com/weborama/cidr](http://github.com/weborama/cidr)).
