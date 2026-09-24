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
// net/netip enforces strict RFC 6943 dotted-decimal syntax and rejects any
// octet with a leading zero (e.g. "010.0.0.1"). Kong's own IP matching
// (lua-resty-ipmatcher, a tonumber-based parser) and this tool's TypeScript
// predecessor (Number(part)) both accept leading zeros, so a route CIDR/IP
// written that way must still match — falling back to net/netip's strict
// parser alone would silently and incorrectly treat such routes as never
// matching. Retry once with each octet's leading zeros stripped before
// giving up.
//
// Building block for the CIDR checks that mirror lua-resty-ipmatcher as used
// by Kong's `create_range_f` (traditional.lua ~L279-L284).
func ParseIPv4(ip string) (uint32, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		if normalized, ok := stripLeadingZeroOctets(ip); ok {
			addr, err = netip.ParseAddr(normalized)
		}
	}
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
//
// Like ParseIPv4, this tolerates leading-zero octets and prefix lengths
// (e.g. "010.0.0.0/08") that net/netip's strict parser rejects outright, to
// match Kong's own lenient CIDR parsing.
func CIDRToRange(cidr string) (lo, hi uint32, ok bool) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		if normalized, changed := stripLeadingZeroCIDR(cidr); changed {
			prefix, err = netip.ParsePrefix(normalized)
		}
	}
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

// stripLeadingZeroOctets removes a leading-zero-tolerant IPv4 dotted-decimal
// string's redundant zeros (e.g. "010.000.0.1" -> "10.0.0.1"). changed is
// false when s is not shaped like four dot-separated decimal octets, or when
// none of them had a leading zero to strip — in both cases s is returned
// unchanged and the caller's original strict-parser error stands.
func stripLeadingZeroOctets(s string) (result string, changed bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return s, false
	}
	for i, p := range parts {
		trimmed, valid := trimLeadingZeros(p)
		if !valid {
			return s, false
		}
		if trimmed != p {
			parts[i] = trimmed
			changed = true
		}
	}
	if !changed {
		return s, false
	}
	return strings.Join(parts, "."), true
}

// stripLeadingZeroCIDR applies stripLeadingZeroOctets to the address part of
// an "addr/bits" CIDR string and strips leading zeros from the prefix length
// too (net/netip also rejects e.g. "/08").
func stripLeadingZeroCIDR(cidr string) (result string, changed bool) {
	addr, bits, ok := strings.Cut(cidr, "/")
	if !ok {
		return cidr, false
	}
	normAddr, addrChanged := stripLeadingZeroOctets(addr)
	if !addrChanged {
		normAddr = addr
	}
	trimmedBits, bitsValid := trimLeadingZeros(bits)
	bitsChanged := bitsValid && trimmedBits != bits
	if !bitsChanged {
		trimmedBits = bits
	}
	if !addrChanged && !bitsChanged {
		return cidr, false
	}
	return normAddr + "/" + trimmedBits, true
}

// trimLeadingZeros strips leading zeros from a decimal string (e.g. "007" ->
// "7", "0" -> "0", "10" -> "10" unchanged). valid is false when s is empty or
// contains a non-digit; result equals s whenever there is nothing to trim.
func trimLeadingZeros(s string) (result string, valid bool) {
	if s == "" {
		return s, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s, false
		}
	}
	if s[0] != '0' || len(s) == 1 {
		return s, true
	}
	trimmed := strings.TrimLeft(s, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	return trimmed, true
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
			// Fast path: strict RFC parsing succeeded outright (also covers
			// IPv6 CIDRs, which CIDRToRange below does not support).
			if ip, err := netip.ParseAddr(reqIP); err == nil {
				if !prefix.Contains(ip) {
					return false
				}
			} else {
				return false
			}
		} else {
			// Falls back to the leading-zero-tolerant IPv4 parser (matches
			// Kong's own lenient lua-resty-ipmatcher parsing) before giving
			// up on a CIDR net/netip's strict parser rejected outright.
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
		} else if entryNum, entryOK := ParseIPv4(entry.IP); entryOK {
			// entry.IP has a leading-zero IPv4 octet net/netip's strict
			// parser rejects but ParseIPv4 tolerates; compare numerically
			// instead of falling through to a literal string comparison
			// that would spuriously fail against a normalized reqIP.
			reqNum, reqOK := ParseIPv4(reqIP)
			if !reqOK || entryNum != reqNum {
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
