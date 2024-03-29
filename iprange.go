// Copyright 2017 Weborama. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cidr // import "github.com/weborama/cidr"

import (
	"encoding/binary"
	"math/bits"
	"net"

	"github.com/weborama/uint128"
)

const (
	numIPv4Bits  = 32
	numIPv6Bits  = 128
	numIPv6Bytes = 16
)

// IPv4ToUint32 converts an IPv4 representation to uint32.
func IPv4ToUint32(address net.IP) uint32 {
	if len(address) == numIPv6Bytes {
		// Extract the 4 last bytes if we have an IPv6 length IP address
		return binary.BigEndian.Uint32(address[12:16])
	}

	return binary.BigEndian.Uint32(address)
}

// Uint32ToIPv4 converts an uint32 back to IPv4 representation.
func Uint32ToIPv4(i uint32) (address net.IP) {
	address = make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(address, i)

	return address
}

// IPv6ToUint128 converts an IPv6 representation to uint128.Uint128.
func IPv6ToUint128(address net.IP) uint128.Uint128 {
	return uint128.Uint128{
		H: binary.BigEndian.Uint64(address[0:8]),
		L: binary.BigEndian.Uint64(address[8:16]),
	}
}

// Uint128ToIPv6 converts an uint128.Uint128 back to IPv4 representation.
func Uint128ToIPv6(x uint128.Uint128) (address net.IP) {
	address = make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(address[0:8], x.H)
	binary.BigEndian.PutUint64(address[8:16], x.L)

	return address
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

// IPRange2CIDR returns a slice of CIDR for the provided IP range.
// Returns nil if IP order is wrong.
func IPRange2CIDR(startIP, endIP net.IP) []net.IPNet {
	if startIPv4, endIPv4 := startIP.To4(), endIP.To4(); startIPv4 != nil && endIPv4 != nil {
		return IPv4Range2CIDR(startIPv4, endIPv4)
	}

	return IPv6Range2CIDR(startIP.To16(), endIP.To16())
}

// AdaptCallbackToIPv4 func.
func AdaptCallbackToIPv4(callback func(net.IPNet)) func(uint32, int, int) {
	return func(ip uint32, ones, bits int) {
		callback(net.IPNet{
			IP:   Uint32ToIPv4(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	}
}

// AdaptCallbackToIPv6 func.
func AdaptCallbackToIPv6(callback func(net.IPNet)) func(uint128.Uint128, int, int) {
	return func(ip uint128.Uint128, ones, bits int) {
		callback(net.IPNet{
			IP:   Uint128ToIPv6(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	}
}

// EachIPRange2CIDR execute the callback for each CIDR for the provided IP range.
func EachIPRange2CIDR(startIP, endIP net.IP, callback func(net.IPNet)) {
	if startIPv4, endIPv4 := startIP.To4(), endIP.To4(); startIPv4 != nil && endIPv4 != nil {
		start := IPv4ToUint32(startIPv4)
		end := IPv4ToUint32(endIPv4)

		EachIPv4Range2CIDR(start, end, AdaptCallbackToIPv4(callback))
	} else if startIPv6, endIPv6 := startIP.To16(), endIP.To16(); startIPv6 != nil && endIPv6 != nil {
		start := IPv6ToUint128(startIPv6)
		end := IPv6ToUint128(endIPv6)

		EachIPv6Range2CIDR(start, end, AdaptCallbackToIPv6(callback))
	}
}

// IPv4Range2CIDR returns a slice of CIDR for the provided IPv4 range.
// Returns nil if IP order is wrong
// Returns nil if provided IPs are not IPv4.
func IPv4Range2CIDR(startIP, endIP net.IP) (ipNetSlice []net.IPNet) {
	// Ensure IPs are IPv4
	startIP, endIP = startIP.To4(), endIP.To4()
	if startIP == nil || endIP == nil {
		return
	}

	// Convert to uint32
	start := IPv4ToUint32(startIP)
	end := IPv4ToUint32(endIP)

	// XXX: Find number of CIDRs for a given address range and preallocate slice
	// Worst case is ipNetSlice = make([]net.IPNet, 0, 32*2-2)
	// QUESTION: Some way to preallocate net.IP and net.CIDRMask as well?
	EachIPv4Range2CIDR(start, end, func(ip uint32, ones, bits int) {
		ipNetSlice = append(ipNetSlice, net.IPNet{
			IP:   Uint32ToIPv4(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	})

	return ipNetSlice
}

// IPv6Range2CIDR returns a slice of CIDR for the provided IPv6 range.
// Returns nil if IP order is wrong
// Returns nil if provided IPs are not IPv4.
func IPv6Range2CIDR(startIP, endIP net.IP) (ipNetSlice []net.IPNet) {
	// Ensure IPs are IPv6
	startIP, endIP = startIP.To16(), endIP.To16()
	if startIP == nil || endIP == nil {
		return
	}

	// Convert to uint128
	start := IPv6ToUint128(startIP)
	end := IPv6ToUint128(endIP)

	// XXX: Find number of CIDRs for a given address range and preallocate slice
	// Worst case is ipNetSlice = make([]net.IPNet, 0, 128*2-2)
	// QUESTION: Some way to preallocate net.IP and net.CIDRMask as well?
	EachIPv6Range2CIDR(start, end, func(ip uint128.Uint128, ones, bits int) {
		ipNetSlice = append(ipNetSlice, net.IPNet{
			IP:   Uint128ToIPv6(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	})

	return ipNetSlice
}

// EachIPv4Range2CIDR will execute the callback parameter with each CIDR
// for the provided IPv4 range.
func EachIPv4Range2CIDR(start, end uint32, callback func(ip uint32, ones, bits int)) {
	if start > end {
		return
	}

	var (
		zeroBits    int
		currentBits int
		carryOut    uint32
	)

	for start <= end && carryOut == 0 {
		zeroBits = bits.TrailingZeros32(start)

		currentBits = min(numIPv4Bits-bits.LeadingZeros32(end-start+1)-1, zeroBits)

		callback(start, numIPv4Bits-currentBits, numIPv4Bits)

		var incr uint32 = 1 << uint(currentBits)
		start, carryOut = bits.Add32(start, incr, 0)
	}
}

// EachIPv6Range2CIDR will execute the callback parameter with each CIDR
// for the provided IPv6 range.
func EachIPv6Range2CIDR(start, end uint128.Uint128, callback func(ip uint128.Uint128, ones, bits int)) {
	if start.Cmp(end) > 0 {
		return
	}

	var (
		zeroBits    int
		currentBits int
	)

	carryOut := uint128.Zero()
	for start.Cmp(end) <= 0 && carryOut.IsZero() {
		zeroBits = uint128.TrailingZeros(start)

		currentBits = min(numIPv6Bits-uint128.LeadingZeros(end.Sub(start).Incr())-1, zeroBits)

		callback(start, numIPv6Bits-currentBits, numIPv6Bits)

		incr := uint128.Incr(uint128.Zero()).ShiftLeft(uint(currentBits))
		start, carryOut = uint128.Add128(start, incr, uint128.Zero())
	}
}
