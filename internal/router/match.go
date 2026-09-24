package router

import (
	"slices"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
)

// SimRequest describes a request for the simulator.
//
// Optional L7/L4 attributes follow a "nil means skip" policy: when a field is
// nil the corresponding route constraint is not evaluated, so every route
// remains a candidate (the conservative static-analysis mode). When set, the
// constraint is evaluated strictly.
type SimRequest struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	// Headers are keyed by header name. A nil map skips header constraints;
	// a non-nil (even empty) map evaluates them strictly.
	Headers map[string]string `json:"headers,omitempty"`
	// SNI is the TLS SNI value (Kong MATCH_RULES.SNI, ~L1072-L1077).
	SNI *string `json:"sni,omitempty"`
	// SourceIP/SourcePort and DestIP/DestPort are the connection addresses
	// (Kong matcher_src_dst, ~L880-L900). Ports are only evaluated together
	// with their IP.
	SourceIP   *string `json:"sourceIp,omitempty"`
	SourcePort *int    `json:"sourcePort,omitempty"`
	DestIP     *string `json:"destIp,omitempty"`
	DestPort   *int    `json:"destPort,omitempty"`
}

// MatchRoute reports whether a route matches the request. All of the
// following must hold:
//   - some path pattern matches (routes without paths match any URI)
//   - the method is allowed (or unconstrained)
//   - the host matches (exact, `*`, or `*.domain[:port]` wildcard)
//   - header, SNI, source and destination constraints are satisfied when the
//     request supplies those attributes
//
// The path is checked first: it rejects the vast majority of candidates
// before the costlier checks run.
//
// Kong source: traditional.lua `match_route` (~L1089-L1125).
func MatchRoute(mr *MarshalledRoute, req *SimRequest) bool {
	if len(mr.ParsedPaths) > 0 {
		matched := false
		for i := range mr.ParsedPaths {
			if MatchPath(&mr.ParsedPaths[i], req.Path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	r := mr.Route
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, strings.ToUpper(req.Method)) {
		return false
	}

	if len(r.Hosts) > 0 && !slices.ContainsFunc(r.Hosts, func(h string) bool { return matchHost(h, req.Host) }) {
		return false
	}

	if req.Headers != nil && len(r.Headers) > 0 && !matchHeaders(r.Headers, req.Headers, mr.HeaderPatterns) {
		return false
	}

	// SNI: trailing dots in FQDNs are stripped, mirroring Kong's
	// `sub(sni, 1, -2)` normalisation (~L511-L513).
	if req.SNI != nil && len(r.SNIs) > 0 {
		want := trimTrailingDot(*req.SNI)
		if !slices.ContainsFunc(r.SNIs, func(s string) bool { return trimTrailingDot(s) == want }) {
			return false
		}
	}

	if req.SourceIP != nil && len(r.Sources) > 0 && !matchSrcDst(r.Sources, *req.SourceIP, req.SourcePort) {
		return false
	}
	if req.DestIP != nil && len(r.Destinations) > 0 && !matchSrcDst(r.Destinations, *req.DestIP, req.DestPort) {
		return false
	}
	return true
}

// matchHost implements Kong's host matcher (MATCH_RULES.HOST, ~L937-L962).
//
// Kong compiles `*.example.com` as `.+\.example\.com(?::\d+)?$` (any port or
// none) and `*.example.com:8080` as `.+\.example\.com:8080$` (that port only).
func matchHost(constraint, reqHost string) bool {
	if constraint == "*" || constraint == reqHost {
		return true
	}
	if !strings.HasPrefix(constraint, "*.") {
		return false
	}
	suffix, constraintPort, hasConstraintPort := splitHostPort(constraint[1:])
	reqDomain, reqPort, hasReqPort := splitHostPort(reqHost)
	if !strings.HasSuffix(reqDomain, suffix) {
		return false
	}
	if hasConstraintPort {
		return hasReqPort && reqPort == constraintPort
	}
	return true
}

// splitHostPort splits "domain:port" when the last colon comes after the last
// dot (so IPv6-like or malformed values are not mistaken for ports).
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i > 0 && strings.LastIndexByte(s, '.') < i {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// matchHeaders ports Kong's MATCH_RULES.HEADER matcher (~L963-L1007):
// every constrained header must be present (AND); any allowed value may match
// (OR); comparison is case-insensitive; a single `~*` value is a regex.
func matchHeaders(constraints model.Headers, reqHeaders map[string]string, patterns map[string]*Pattern) bool {
	for _, c := range constraints {
		lowerName := strings.ToLower(c.Name)
		value, ok := reqHeaders[lowerName]
		if !ok {
			value, ok = reqHeaders[c.Name]
		}
		if !ok {
			return false
		}
		lowerValue := strings.ToLower(value)
		matched := slices.ContainsFunc(c.Values, func(v string) bool { return strings.ToLower(v) == lowerValue })
		if !matched {
			if p := patterns[lowerName]; p != nil && p.MatchString(lowerValue) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func trimTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}
