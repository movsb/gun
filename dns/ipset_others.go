//go:build !linux

package dns

import "net/netip"

func AddIPSet(name string, ip netip.Addr) {}
