// Copyright 2017 Weborama. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uint128

//go:generate go run make_tables.go

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

var (
	// Zero is a 0 valued Uint128
	Zero = Uint128{0x0, 0x0}
	// MaxUint128 defines the maximum value for an Uint128
	MaxUint128 = Uint128{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
)

// Uint128 defines an unsigned integer of 128 bits
type Uint128 struct {
	H, L uint64
}

// Cmp compares two Uint128 and returns one of the following values:
//   -1 if x <  y
//    0 if x == y
//   +1 if x >  y
func (x Uint128) Cmp(y Uint128) int {
	return Cmp(x, y)
}

// IsZero returns true if x is zero.
func (x Uint128) IsZero() bool {
	return IsZero(x)
}

// ShiftLeft shifts x to the left by the provided number of bits.
func (x Uint128) ShiftLeft(bits uint) Uint128 {
	return ShiftLeft(x, bits)
}

// ShiftRight shifts x to the right by the provided number of bits.
func (x Uint128) ShiftRight(bits uint) Uint128 {
	return ShiftRight(x, bits)
}

// And returns the logical AND of x and o
func (x Uint128) And(y Uint128) Uint128 {
	return And(x, y)
}

// AndNot returns the logical AND NOT of x and o
func (x Uint128) AndNot(y Uint128) Uint128 {
	return AndNot(x, y)
}

// Not returns the logical AND of x and o
func (x Uint128) Not() Uint128 {
	return Not(x)
}

// Xor returns the logical XOR of x and o
func (x Uint128) Xor(y Uint128) Uint128 {
	return Xor(x, y)
}

// Or returns the logical OR of x and o
func (x Uint128) Or(y Uint128) Uint128 {
	return Or(x, y)
}

// Add adds x and o
func (x Uint128) Add(y Uint128) Uint128 {
	return Add(x, y)
}

// Incr increments x by one
func (x Uint128) Incr() Uint128 {
	return Incr(x)
}

// Sub substracts x and o
func (x Uint128) Sub(y Uint128) Uint128 {
	return Sub(x, y)
}

// Decr decrements x by one
func (x Uint128) Decr() Uint128 {
	return Decr(x)
}

// NewFromString creates a new Uint128 from its string representation
func NewFromString(s string) (x Uint128, err error) {
	x = Uint128{0, 0}
	if len(s) > 32 {
		return x, fmt.Errorf("s:%s length greater than 32", s)
	}

	b, err := hex.DecodeString(fmt.Sprintf("%032s", s))
	if err != nil {
		return x, err
	}
	rdr := bytes.NewReader(b)
	err = binary.Read(rdr, binary.BigEndian, &x)
	return
}

// HexString returns a Hexadecimal string representation of an Uint128
func (x Uint128) HexString() string {
	if x.H == 0 {
		return fmt.Sprintf("%x", x.L)
	}
	return fmt.Sprintf("%x%016x", x.H, x.L)
}

func (x Uint128) String() string {
	return fmt.Sprintf("0x%032x", x.HexString())
}

// Format is a custom formatter for Uint128
// TODO: Do a proper job of it.
func (x Uint128) Format(f fmt.State, c rune) {
	switch c {
	case 'v':
		if f.Flag('+') {
			fmt.Fprintf(f, "(%+v, %+v)", x.H, x.L)
		} else if f.Flag('#') {
			fmt.Fprintf(f, "(%#v, %#v)", x.H, x.L)
		} else {
			fmt.Fprintf(f, "(%v, %v)", x.H, x.L)
		}
	case 'T':
		fmt.Fprintf(f, "%T", x)
	case 'b':
		fmt.Fprintf(f, "%0b%064b", x.H, x.L)
	// case 'd':
	// 	fmt.Fprintf(f, "%0d%064d", x.H, x.L)
	// case 'o':
	// 	fmt.Fprintf(f, "%0o%064o", x.H, x.L)
	case 'x':
		fmt.Fprintf(f, "0x%032x", x.HexString())
	case 'X':
		fmt.Fprintf(f, "0x%032X", x.HexString())
	}
}

// Cmp compares two Uint128 and returns one of the following values:
//   -1 if x <  y
//    0 if x == y
//   +1 if x >  y
func Cmp(x, y Uint128) int {
	if x.H < y.H {
		return -1
	} else if x.H > y.H {
		return 1
	}

	if x.L < y.L {
		return -1
	} else if x.L > y.L {
		return 1
	}

	return 0
}

// IsZero returns true if x is zero.
func IsZero(x Uint128) bool {
	return x.H == 0 && x.L == 0
}

// ShiftLeft shifts x to the left by the provided number of bits.
func ShiftLeft(x Uint128, b uint) Uint128 {
	if b >= 128 {
		x.H = 0
		x.L = 0
	} else if b >= 64 {
		x.H = x.L << (b - 64)
		x.L = 0
	} else {
		x.H <<= b
		x.H |= x.L >> (64 - b)
		x.L <<= b
	}
	return x
}

// ShiftRight shifts x to the right by the provided number of bits.
func ShiftRight(x Uint128, b uint) Uint128 {
	if b >= 128 {
		x.H = 0
		x.L = 0
	} else if b >= 64 {
		x.L = x.H >> (b - 64)
		x.H = 0
	} else {
		x.L >>= b
		x.L |= x.H << (64 - b)
		x.H >>= b
	}
	return x
}

// And returns the logical AND of x and y
func And(x, y Uint128) Uint128 {
	x.H &= y.H
	x.L &= y.L
	return x
}

// AndNot returns the logical AND NOT of x and y
func AndNot(x, y Uint128) Uint128 {
	x.H &^= y.H
	x.L &^= y.L
	return x
}

// Not returns the logical NOT of x and o
func Not(x Uint128) Uint128 {
	x.H = ^x.H
	x.L = ^x.L
	return x
}

// Xor returns the logical XOR of x and y
func Xor(x, y Uint128) Uint128 {
	x.H ^= y.H
	x.L ^= y.L
	return x
}

// Or returns the logical OR of x and y
func Or(x, y Uint128) Uint128 {
	x.H |= y.H
	x.L |= y.L
	return x
}

// Add adds x and y
func Add(x, y Uint128) Uint128 {
	pL := x.L
	x.L += y.L
	x.H += y.H
	if x.L < pL {
		x.H++
	}
	return x
}

// Incr increments x by one
func Incr(x Uint128) Uint128 {
	pL := x.L
	x.L++
	if x.L < pL {
		x.H++
	}
	return x
}

// Sub substracts x and y
func Sub(x, y Uint128) Uint128 {
	pL := x.L
	x.L -= y.L
	x.H -= y.H
	if x.L > pL {
		x.H--
	}
	return x
}

// Decr decrements x by one
func Decr(x Uint128) Uint128 {
	pL := x.L
	x.L--
	if x.L > pL {
		x.H--
	}
	return x
}

// Len returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len(x Uint128) int {
	if x.H == 0 {
		return bits.Len64(x.L)
	}
	return 64 + bits.Len64(x.H)
}

// LeadingZeros returns the number of leading zero bits in x; the result is 128 for x == 0.
func LeadingZeros(x Uint128) int {
	return 128 - Len(x)
}

// OnesCount returns the number of one bits ("population count") in x.
func OnesCount(x Uint128) int {
	return bits.OnesCount64(x.H) + bits.OnesCount64(x.L)
}

// TrailingZeros returns the number of trailing zero bits in x; the result is 128 for x == 0.
func TrailingZeros(x Uint128) int {
	if x.L == 0 {
		return bits.TrailingZeros64(x.H) + 64
	}
	return bits.TrailingZeros64(x.L)
}

// Reverse returns the value of x with its bits in reversed order.
func Reverse(x Uint128) (y Uint128) {
	y.L, y.H = bits.Reverse64(x.H), bits.Reverse64(x.L)
	return
}

// ReverseBytes returns the value of x with its bytes in reversed order.
func ReverseBytes(x Uint128) (y Uint128) {
	y.L, y.H = bits.ReverseBytes64(x.H), bits.ReverseBytes64(x.L)
	return
}
