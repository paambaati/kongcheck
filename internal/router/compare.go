package router

import (
	"cmp"
	"slices"
)

// CompareRoutes orders two marshalled routes by Kong's sort_routes
// tie-breaking chain. It returns a negative number when a has higher
// priority, positive when b does, and 0 when they are equal by Kong's rules.
//
// Precedence (highest first):
//  1. submatch_weight, compared as an unsigned integer (higher wins) (~L682-L684)
//  2. header count (more wins) (~L686-L688)
//  3. regex_priority, only when both routes are regex routes (~L690-L699)
//  4. max_uri_length (longer wins) (~L702-L704)
//  5. created_at, only when both are set (earlier wins) (~L706-L708)
//
// Kong source: traditional.lua `sort_routes` (~L681-L709).
func CompareRoutes(a, b *MarshalledRoute) int {
	if a.SubMatchWeight != b.SubMatchWeight {
		return cmp.Compare(b.SubMatchWeight, a.SubMatchWeight)
	}
	if a.HeaderCount != b.HeaderCount {
		return cmp.Compare(b.HeaderCount, a.HeaderCount)
	}
	if a.HasRegexPath && b.HasRegexPath && a.Route.RegexPriority != b.Route.RegexPriority {
		return cmp.Compare(b.Route.RegexPriority, a.Route.RegexPriority)
	}
	if a.MaxURILength != b.MaxURILength {
		return cmp.Compare(b.MaxURILength, a.MaxURILength)
	}
	if ac, bc := a.Route.CreatedAt, b.Route.CreatedAt; ac != nil && bc != nil && *ac != *bc {
		return cmp.Compare(*ac, *bc)
	}
	return 0
}

// SortRoutes returns a copy of routes in Kong priority order (winner first),
// using a stable sort.
//
// Note: CompareRoutes is not transitive when some routes lack created_at,
// because Kong only compares timestamps when both routes have one. For such
// inputs the relative order of otherwise-tied routes is implementation-defined
// (it differs between Kong's Lua sort, V8 and JavaScriptCore too). Konnect
// always sets created_at, so real configurations are unaffected.
func SortRoutes(routes []*MarshalledRoute) []*MarshalledRoute {
	sorted := slices.Clone(routes)
	slices.SortStableFunc(sorted, CompareRoutes)
	return sorted
}
