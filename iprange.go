// Copyright 2017 Weborama. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cidr

import (
	"math/bits"
	"net"

	"github.com/Weborama/uint128"
)

// IPv4ToUint32 converts an IPv4 representation to uint32
func IPv4ToUint32(ip net.IP) (i uint32) {
	i = uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	return
}

// Uint32ToIPv4 converts an Uint32 back to IPv4 representation
func Uint32ToIPv4(i uint32) net.IP {
	return net.IPv4(byte(i>>24)&0xFF, byte(i>>16)&0xFF, byte(i>>8)&0xFF, byte(i&0xFF))
}

// IPv6ToUint128Alt converts an IPv6 representation to uint32
// func IPv6ToUint128Alt(ip net.IP) (o uint128.Uint128) {
// 	var i uint
// 	for i = 0; i < 16; i++ {
// 		if i < 8 {
// 			b := (8 - i - 1) * 8
// 			o.H |= uint64(ip[i]) << b
// 		} else {
// 			b := (16 - i - 1) * 8
// 			o.L |= uint64(ip[i]) << b
// 		}
// 	}
// 	return
// }

// IPv6ToUint128 converts an IPv6 representation to uint32
func IPv6ToUint128(ip net.IP) uint128.Uint128 {
	return uint128.Uint128{
		H: uint64(ip[0])<<56 | uint64(ip[1])<<48 | uint64(ip[2])<<40 | uint64(ip[3])<<32 | uint64(ip[4])<<24 | uint64(ip[5])<<16 | uint64(ip[6])<<8 | uint64(ip[7])<<0,
		L: uint64(ip[8])<<56 | uint64(ip[9])<<48 | uint64(ip[10])<<40 | uint64(ip[11])<<32 | uint64(ip[12])<<24 | uint64(ip[13])<<16 | uint64(ip[14])<<8 | uint64(ip[15])<<0,
	}
}

// Uint128ToIPv6Alt converts an Uint32 back to IPv4 representation
// func Uint128ToIPv6Alt(x uint128.Uint128) net.IP {
// 	ip := make(net.IP, net.IPv6len)
// 	var i uint
// 	for i = 0; i < 16; i++ {
// 		if i < 8 {
// 			b := (8 - i - 1) * 8
// 			ip[i] = byte(x.H>>b) & 0xFF
// 		} else {
// 			b := (16 - i - 1) * 8
// 			ip[i] = byte(x.L>>b) & 0xFF
// 		}
// 	}
// 	return ip
// }

// Uint128ToIPv6 converts an Uint32 back to IPv4 representation
func Uint128ToIPv6(x uint128.Uint128) (ip net.IP) {
	ip = make(net.IP, net.IPv6len)
	ip[0] = byte(x.H>>56) & 0xFF
	ip[1] = byte(x.H>>48) & 0xFF
	ip[2] = byte(x.H>>40) & 0xFF
	ip[3] = byte(x.H>>32) & 0xFF
	ip[4] = byte(x.H>>24) & 0xFF
	ip[5] = byte(x.H>>16) & 0xFF
	ip[6] = byte(x.H>>8) & 0xFF
	ip[7] = byte(x.H>>0) & 0xFF
	ip[8] = byte(x.L>>56) & 0xFF
	ip[9] = byte(x.L>>48) & 0xFF
	ip[10] = byte(x.L>>40) & 0xFF
	ip[11] = byte(x.L>>32) & 0xFF
	ip[12] = byte(x.L>>24) & 0xFF
	ip[13] = byte(x.L>>16) & 0xFF
	ip[14] = byte(x.L>>8) & 0xFF
	ip[15] = byte(x.L>>0) & 0xFF
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
	startIP, endIP = startIP.To16(), endIP.To16()
	if len(startIP) == net.IPv4len && len(endIP) == net.IPv4len {
		return IPv4Range2CIDR(startIP, endIP)
	}
	if startIP != nil && endIP != nil {
		return IPv6Range2CIDR(startIP, endIP)
	}
	return nil
}

// IPv4Range2CIDR returns a slice of CIDR for the provided IPv4 range.
// Returns nil if IP order is wrong
// Returns nil if provided IPs are not IPv4
func IPv4Range2CIDR(startIP, endIP net.IP) (ipNetSlice []net.IPNet) {
	// Ensure IPs are IPV4
	startIP, endIP = startIP.To4(), endIP.To4()
	if startIP == nil || endIP == nil {
		return nil
	}

	// Convert to uint32
	start := IPv4ToUint32(startIP)
	end := IPv4ToUint32(endIP)
	if start > end {
		return nil
	}

	// TODO: Find number of CIDRs for a given address range and preallocate slice
	// Worst case is ipNetSlice = make([]net.IPNet, 0, 32*2-2)
	// QUESTION: Some way to preallocate net.IP and net.CIDRMask as well?

	var zeroBits, currentBits int
	for start <= end {
		zeroBits = bits.TrailingZeros32(start)

		currentBits = min(32-bits.LeadingZeros32(end-start+1)-1, zeroBits)
		ipNetSlice = append(ipNetSlice, net.IPNet{
			IP:   Uint32ToIPv4(start),
			Mask: net.CIDRMask(32-currentBits, 32),
		})
		start += 1 << uint(currentBits)
	}

	if len(ipNetSlice) == 0 {
		return nil
	}

	return ipNetSlice
}

// IPv6Range2CIDR returns a slice of CIDR for the provided IPv6 range.
// Returns nil if IP order is wrong
// Returns nil if provided IPs are not IPv4
func IPv6Range2CIDR(startIP, endIP net.IP) (ipNetSlice []net.IPNet) {
	// Ensure IPs are IPV6
	if len(startIP) != net.IPv6len || len(endIP) != net.IPv6len {
		return nil
	}

	// Convert to uint32
	start := IPv6ToUint128(startIP)
	end := IPv6ToUint128(endIP)
	if start.Cmp(end) > 0 {
		return nil
	}

	// TODO: Find number of CIDRs for a given address range and preallocate slice
	// Worst case is ipNetSlice = make([]net.IPNet, 0, 128*2-2)
	// QUESTION: Some way to preallocate net.IP and net.CIDRMask as well?

	var zeroBits, currentBits int
	for start.Cmp(end) <= 0 {
		zeroBits = uint128.TrailingZeros(start)

		currentBits = min(128-uint128.LeadingZeros(end.Sub(start).Incr())-1, zeroBits)
		ipNetSlice = append(ipNetSlice, net.IPNet{
			IP:   Uint128ToIPv6(start),
			Mask: net.CIDRMask(128-currentBits, 128),
		})
		start = start.Add(uint128.Incr(uint128.Zero).ShiftLeft(uint(currentBits)))
	}

	if len(ipNetSlice) == 0 {
		return nil
	}

	return ipNetSlice
}
