# github.com/weborama/cidr

[![Godoc for weborama/cidr](https://pkg.go.dev/badge/github.com/weborama/cidr)](https://pkg.go.dev/github.com/weborama/cidr)
[![Go Report Card](https://goreportcard.com/badge/github.com/weborama/cidr)](https://goreportcard.com/report/github.com/weborama/cidr)
[![Go](https://github.com/Weborama/cidr/actions/workflows/go.yml/badge.svg)](https://github.com/Weborama/cidr/actions/workflows/go.yml)
[![golangci-lint](https://github.com/Weborama/cidr/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/Weborama/cidr/actions/workflows/golangci-lint.yml)

This package provides converters of IP ranges to CIDR IP networks (both for IPv4
and IPv6).

Typical use case of this package is for converting IP range lists (geolocation,
blacklists etc.) for storage in radix trees for fast lookup.

[C implementation](https://gist.github.com/citrin/4202877) used for inspiration.
