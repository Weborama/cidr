This package provides an implementation of a 128 bit unsigned integer with some
implementations of:
- arithmetic operators (Add, Sub, Incr, Decr)
- binary operations (AND, OR, XOR, NOT, AND NOT, shifts)
- math/bits operations (LeadingZeros, Len, OnesCount, Reverse, ReverseBytes, TrailingZeros)

Missing operators (Mult, Div, Mod, RotateLeft etc.) to be added later.

Original use case for this package is implementing IPv6 calculations (see
[github.com/Weborama/cidr](http://github.com/Weborama/cidr)).
