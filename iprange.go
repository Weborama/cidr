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

// IPv4ToUint32 converts an IPv4 representation to uint32
func IPv4ToUint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}

	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIPv4 converts an uint32 back to IPv4 representation
func Uint32ToIPv4(i uint32) (ip net.IP) {
	ip = make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, i)

	return ip
}

// IPv6ToUint128 converts an IPv6 representation to uint128.Uint128
func IPv6ToUint128(ip net.IP) uint128.Uint128 {
	return uint128.Uint128{
		H: binary.BigEndian.Uint64(ip[0:8]),
		L: binary.BigEndian.Uint64(ip[8:16]),
	}
}

// Uint128ToIPv6 converts an uint128.Uint128 back to IPv4 representation
func Uint128ToIPv6(x uint128.Uint128) (ip net.IP) {
	ip = make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(ip[0:8], x.H)
	binary.BigEndian.PutUint64(ip[8:16], x.L)

	return ip
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

// AdaptCallbackToIPv4 func
func AdaptCallbackToIPv4(callback func(net.IPNet)) func(uint32, int, int) {
	return func(ip uint32, ones, bits int) {
		callback(net.IPNet{
			IP:   Uint32ToIPv4(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	}
}

// AdaptCallbackToIPv6 func
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
		EachIPv4Range2CIDR(startIPv4, endIPv4, AdaptCallbackToIPv4(callback))
	} else {
		EachIPv6Range2CIDR(startIP.To16(), endIP.To16(), AdaptCallbackToIPv6(callback))
	}
}

// IPv4Range2CIDR returns a slice of CIDR for the provided IPv4 range.
// Returns nil if IP order is wrong
// Returns nil if provided IPs are not IPv4
func IPv4Range2CIDR(startIP, endIP net.IP) (ipNetSlice []net.IPNet) {
	EachIPv4Range2CIDR(startIP, endIP, func(ip uint32, ones, bits int) {
		ipNetSlice = append(ipNetSlice, net.IPNet{
			IP:   Uint32ToIPv4(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	})

	return ipNetSlice
}

// IPv6Range2CIDR returns a slice of CIDR for the provided IPv6 range.
// Returns nil if IP order is wrong
// Returns nil if provided IPs are not IPv4
func IPv6Range2CIDR(startIP, endIP net.IP) (ipNetSlice []net.IPNet) {
	EachIPv6Range2CIDR(startIP, endIP, func(ip uint128.Uint128, ones, bits int) {
		ipNetSlice = append(ipNetSlice, net.IPNet{
			IP:   Uint128ToIPv6(ip),
			Mask: net.CIDRMask(ones, bits),
		})
	})

	return ipNetSlice
}

// EachIPv4Range2CIDR will execute the callback parameter with each CIDR
// for the provided IPv4 range
func EachIPv4Range2CIDR(startIP, endIP net.IP, callback func(ip uint32, ones, bits int)) {
	// Ensure IPs are IPV4
	startIP, endIP = startIP.To4(), endIP.To4()
	if startIP == nil || endIP == nil {
		return
	}

	// Convert to uint32
	start := IPv4ToUint32(startIP)
	end := IPv4ToUint32(endIP)

	if start > end {
		return
	}

	var (
		zeroBits    int
		currentBits int
	)

	for start <= end {
		zeroBits = bits.TrailingZeros32(start)

		currentBits = min(32-bits.LeadingZeros32(end-start+1)-1, zeroBits)

		callback(start, 32-currentBits, 32)

		start += 1 << uint(currentBits)
	}
}

// EachIPv6Range2CIDR will execute the callback parameter with each CIDR
// for the provided IPv6 range
func EachIPv6Range2CIDR(startIP, endIP net.IP, callback func(ip uint128.Uint128, ones, bits int)) {
	// Ensure IPs are IPV6
	if len(startIP) != net.IPv6len || len(endIP) != net.IPv6len {
		return
	}

	// Convert to uint128
	start := IPv6ToUint128(startIP)
	end := IPv6ToUint128(endIP)

	if start.Cmp(end) > 0 {
		return
	}

	// XXX: Find number of CIDRs for a given address range and preallocate slice
	// Worst case is ipNetSlice = make([]net.IPNet, 0, 128*2-2)
	// QUESTION: Some way to preallocate net.IP and net.CIDRMask as well?
	var (
		zeroBits    int
		currentBits int
	)

	for start.Cmp(end) <= 0 {
		zeroBits = uint128.TrailingZeros(start)

		currentBits = min(128-uint128.LeadingZeros(end.Sub(start).Incr())-1, zeroBits)

		callback(start, 128-currentBits, 128)

		start = start.Add(uint128.Incr(uint128.Zero()).ShiftLeft(uint(currentBits)))
	}
}
