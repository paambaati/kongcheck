package router

import (
	"encoding/binary"
	"net/netip"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
)

// ParseIPv4 parses a dotted-decimal IPv4 address into a 32-bit integer. It
// returns false for anything else (IPv6, malformed input).
//
// Building block for the CIDR checks that mirror lua-resty-ipmatcher as used
// by Kong's `create_range_f` (traditional.lua ~L279-L284).
func ParseIPv4(ip string) (uint32, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return 0, false
	}
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:]), true
}

// CIDRToRange parses an IPv4 CIDR (e.g. "10.0.0.0/8") into an inclusive
// [lo, hi] range. It returns false for IPv6, malformed input, or an
// out-of-range prefix length. Callers treat false as "unknown" and assume a
// potential overlap rather than risk a false negative.
func CIDRToRange(cidr string) (lo, hi uint32, ok bool) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return 0, 0, false
	}
	bits := prefix.Bits()
	var mask uint32
	if bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	b := prefix.Masked().Addr().As4()
	lo = binary.BigEndian.Uint32(b[:])
	return lo, lo | ^mask, true
}

// ipRange resolves a plain IPv4 address or CIDR to an inclusive range.
func ipRange(ip string) (lo, hi uint32, ok bool) {
	if strings.Contains(ip, "/") {
		return CIDRToRange(ip)
	}
	p, ok := ParseIPv4(ip)
	return p, p, ok
}

// IPsCanOverlap reports whether two IPv4 addresses or CIDRs can describe at
// least one common address. It is conservative: anything it cannot parse
// (IPv6, malformed) is assumed to overlap, so it never yields a false
// negative.
func IPsCanOverlap(a, b string) bool {
	aLo, aHi, aOK := ipRange(a)
	bLo, bHi, bOK := ipRange(b)
	if !aOK || !bOK {
		return true
	}
	return aLo <= bHi && bLo <= aHi
}

// IPPortListsOverlap reports whether any pair of entries (one from each list)
// can match the same IP+port, i.e. the two source/destination constraint
// lists are not mutually exclusive.
//
// An entry without an IP matches any IP; without a port, any port. Two entries
// are disjoint when both constrain a port and the ports differ, or both
// constrain an IP and the addresses/ranges do not overlap.
//
// Kong source: traditional.lua `matcher_src_dst` (~L880-L900).
func IPPortListsOverlap(listA, listB []model.IPPort) bool {
	for _, a := range listA {
		for _, b := range listB {
			if a.Port != 0 && b.Port != 0 && a.Port != b.Port {
				continue
			}
			if a.IP != "" && b.IP != "" && !IPsCanOverlap(a.IP, b.IP) {
				continue
			}
			return true
		}
	}
	return false
}

// matchSrcDstEntry tests one source/destination entry against a concrete
// connection address (Kong `matcher_src_dst` per-entry logic).
func matchSrcDstEntry(entry model.IPPort, reqIP string, reqPort *int) bool {
	switch {
	case entry.IP == "":
		// No IP constraint.
	case strings.Contains(entry.IP, "/"):
		if prefix, err := netip.ParsePrefix(entry.IP); err == nil {
			if ip, err := netip.ParseAddr(reqIP); err == nil {
				if !prefix.Contains(ip) {
					return false
				}
			} else {
				return false
			}
		} else {
			lo, hi, ok := CIDRToRange(entry.IP)
			ip, ipOK := ParseIPv4(reqIP)
			if !ok || !ipOK || ip < lo || ip > hi {
				return false
			}
		}
	default:
		if entryAddr, err := netip.ParseAddr(entry.IP); err == nil {
			if reqAddr, err := netip.ParseAddr(reqIP); err == nil {
				if entryAddr != reqAddr {
					return false
				}
			} else if entry.IP != reqIP {
				return false
			}
		} else if entry.IP != reqIP {
			return false
		}
	}
	return entry.Port == 0 || (reqPort != nil && entry.Port == *reqPort)
}

// matchSrcDst reports whether any entry matches (OR semantics).
func matchSrcDst(entries []model.IPPort, reqIP string, reqPort *int) bool {
	for _, e := range entries {
		if matchSrcDstEntry(e, reqIP, reqPort) {
			return true
		}
	}
	return false
}
