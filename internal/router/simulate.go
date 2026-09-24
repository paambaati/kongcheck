package router

import (
	"fmt"
	"time"
)

// SimResult is the outcome of simulating a request.
type SimResult struct {
	Request SimRequest `json:"request"`
	// MatchedRoutes are all matching routes in priority order (winner first).
	MatchedRoutes []*MarshalledRoute `json:"matchedRoutes"`
	// Winner is the highest-priority match, or nil when nothing matched.
	Winner *MarshalledRoute `json:"winner"`

	explanation []string
}

// Explanation returns a human-readable account of why the winner was chosen
// (or why nothing matched). It is computed on first use and cached: building
// it is comparatively expensive, and the analyzer only needs it for the few
// simulations that turn into findings.
func (r *SimResult) Explanation() []string {
	if r.explanation == nil {
		if r.Winner == nil {
			req := r.Request
			r.explanation = []string{fmt.Sprintf("No route matched request: %s %s%s", req.Method, req.Host, req.Path)}
		} else {
			r.explanation = buildWinnerExplanation(r.MatchedRoutes, &r.Request)
		}
	}
	return r.explanation
}

// SimulateRequest evaluates a request against routes that are already sorted
// by CompareRoutes. The first match is the winner, mirroring Kong's
// find_match loop which returns on the first candidate in priority order.
//
// Kong source: traditional.lua `find_route` / `find_match` (~L1400-L1688).
func SimulateRequest(sorted []*MarshalledRoute, req SimRequest) *SimResult {
	res := &SimResult{Request: req, MatchedRoutes: []*MarshalledRoute{}}
	for _, r := range sorted {
		if MatchRoute(r, &res.Request) {
			res.MatchedRoutes = append(res.MatchedRoutes, r)
		}
	}
	if len(res.MatchedRoutes) > 0 {
		res.Winner = res.MatchedRoutes[0]
	}
	return res
}

func buildWinnerExplanation(matched []*MarshalledRoute, req *SimRequest) []string {
	winner := matched[0]
	lines := []string{fmt.Sprintf("Route \"%s\" wins for %s %s", winner.Route.DisplayName(), req.Method, req.Path)}
	if len(matched) == 1 {
		return append(lines, "It is the only route that matches this request.")
	}
	losers := matched[1:]
	lines = append(lines, fmt.Sprintf("%d other route(s) also match but lose the priority contest:", len(losers)))
	for _, l := range losers {
		lines = append(lines, fmt.Sprintf("  - \"%s\" loses because: %s", l.Route.DisplayName(), ExplainPairOrdering(winner, l)))
	}
	return lines
}

// ExplainPairOrdering returns one sentence explaining why winner beats loser
// in Kong's sort_routes chain.
func ExplainPairOrdering(winner, loser *MarshalledRoute) string {
	w, l := winner.SubMatchWeight, loser.SubMatchWeight
	if w != l {
		switch {
		case w&SubmatchHasRegexURI != l&SubmatchHasRegexURI:
			if w&SubmatchHasRegexURI != 0 {
				return "regex routes beat plain-prefix routes (HAS_REGEX_URI bit of submatch_weight)"
			}
			return "plain-prefix routes beat regex routes (HAS_REGEX_URI) — unexpected!"
		case w&SubmatchPlainHostsOnly != l&SubmatchPlainHostsOnly:
			if w&SubmatchPlainHostsOnly != 0 {
				return "plain-host routes beat wildcard-host routes (PLAIN_HOSTS_ONLY bit of submatch_weight)"
			}
			return "wildcard-host route beats plain-host route (PLAIN_HOSTS_ONLY) — unexpected!"
		case w&SubmatchHasWildcardHostPort != l&SubmatchHasWildcardHostPort:
			if w&SubmatchHasWildcardHostPort != 0 {
				return "wildcard host with explicit port beats one without (HAS_WILDCARD_HOST_PORT bit)"
			}
			return "wildcard host without port beats one with port (HAS_WILDCARD_HOST_PORT) — unexpected!"
		}
	}

	if winner.HeaderCount != loser.HeaderCount {
		return fmt.Sprintf("more header constraints win (%d > %d distinct headers)", winner.HeaderCount, loser.HeaderCount)
	}

	if winner.HasRegexPath && loser.HasRegexPath {
		if wp, lp := winner.Route.RegexPriority, loser.Route.RegexPriority; wp > lp {
			return fmt.Sprintf("higher regex_priority (%d > %d)", wp, lp)
		}
	}

	if winner.MaxURILength > loser.MaxURILength {
		return fmt.Sprintf("longer path pattern (%d chars > %d chars)", winner.MaxURILength, loser.MaxURILength)
	}

	if wc, lc := winner.Route.CreatedAt, loser.Route.CreatedAt; wc != nil && lc != nil && *wc < *lc {
		return fmt.Sprintf("earlier created_at (%s < %s)", ISOTime(*wc), ISOTime(*lc))
	}

	return "routes are equal by all ordering criteria (non-deterministic)"
}

// ISOTime formats a Unix timestamp (seconds) like JavaScript's
// Date.prototype.toISOString, e.g. "2023-11-14T22:13:20.000Z".
func ISOTime(epochSeconds int64) string {
	return time.Unix(epochSeconds, 0).UTC().Format("2006-01-02T15:04:05.000Z")
}
