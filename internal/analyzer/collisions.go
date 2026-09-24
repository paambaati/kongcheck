package analyzer

import (
	"context"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// pairKey identifies an unordered pair of route IDs.
type pairKey struct{ a, b string }

func makePairKey(x, y string) pairKey {
	if x < y {
		return pairKey{x, y}
	}
	return pairKey{y, x}
}

// simulateAll runs every candidate request against the sorted routes. The
// simulations are independent, so they are spread across CPUs; results are
// returned in candidate order so downstream processing stays deterministic.
func simulateAll(ctx context.Context, sorted []*router.MarshalledRoute, candidates []router.SimRequest) []*router.SimResult {
	results := make([]*router.SimResult, len(candidates))
	parallelFor(ctx, len(candidates), func(i int) {
		results[i] = router.SimulateRequest(sorted, candidates[i])
	})
	return results
}

// parallelFor calls fn(i) for i in [0, n) using up to GOMAXPROCS workers.
func parallelFor(ctx context.Context, n int, fn func(i int)) {
	if ctx.Err() != nil {
		return
	}
	workers := min(runtime.GOMAXPROCS(0), n)
	if workers <= 1 {
		for i := range n {
			if ctx.Err() != nil {
				return
			}
			fn(i)
		}
		return
	}
	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for start := 0; start < n; start += chunk {
		end := min(start+chunk, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := start; i < end; i++ {
				if ctx.Err() != nil {
					return
				}
				fn(i)
			}
		}()
	}
	wg.Wait()
}

// detectCollisions simulates candidate requests and emits a finding for each
// route pair matched by the same request (one finding per pair; later
// requests only add samples).
func detectCollisions(ctx context.Context, sorted []*router.MarshalledRoute, flavor model.RouterFlavor, includeInfo bool) []*model.Finding {
	candidates := GenerateCandidateRequests(sorted)
	results := simulateAll(ctx, sorted, candidates)

	// allPrefixes is a pure function of a route's own paths, but the same
	// (winner, loser) pair recurs across many candidate requests —
	// GenerateCandidateRequests deliberately produces siblings/children/
	// parents of the same base paths — so computing it fresh per occurrence
	// reallocates the same two prefix slices over and over. Precompute it
	// once per route instead.
	prefixes := newPrefixCache(sorted)

	seen := make(map[pairKey]bool)
	byPair := make(map[pairKey]*model.Finding)
	findings := []*model.Finding{}

	for i, res := range results {
		// res is nil when ctx was cancelled before parallelFor reached index i
		// (simulateAll pre-allocates the slice but only fills indices that were
		// actually visited); skip unresolved candidates instead of panicking.
		if res == nil {
			continue
		}
		if len(res.MatchedRoutes) < 2 {
			continue
		}
		reqPath := candidates[i].Path
		winner := res.Winner

		for _, loser := range res.MatchedRoutes[1:] {
			// A universal matcher (e.g. `/`) losing to more specific routes is
			// the intended behaviour of a catch-all; flagging it is O(n) noise.
			if loser.IsUniversal {
				continue
			}
			// Parent → child hierarchies (/chat vs /chat/history) are resolved
			// deterministically by max_uri_length.
			if prefixes.isHierarchicalChild(winner, loser) {
				continue
			}
			// Split paths of the same multi-path route are not a collision.
			if winner.Route.ID == loser.Route.ID {
				continue
			}
			// `{variable}` placeholders are PCRE literals that real traffic never
			// sends, so such a winner cannot shadow anything.
			if winner.HasTemplatePlaceholder {
				continue
			}

			key := makePairKey(winner.Route.ID, loser.Route.ID)
			if seen[key] {
				if f := byPair[key]; f != nil && !slices.Contains(f.Samples, reqPath) {
					f.Samples = append(f.Samples, reqPath)
				}
				continue
			}
			seen[key] = true

			// L4 stratification applies to every path configuration, so it is
			// checked before the identical-path header checks.
			if reason, ok := isL4Stratified(winner, loser); ok {
				if includeInfo {
					f := buildL4StratifiedFinding(winner, loser, reqPath, flavor, reason)
					findings = append(findings, f)
					byPair[key] = f
				}
				continue
			}

			if haveIdenticalPaths(winner, loser) {
				switch isHeaderStratified(winner, loser) {
				case headersStratified:
					if includeInfo {
						f := buildHeaderStratifiedFinding(winner, loser, reqPath, flavor)
						findings = append(findings, f)
						byPair[key] = f
					}
					continue
				case headersRegexOpaque:
					f := buildRegexHeaderOpaqueFinding(winner, loser, reqPath, flavor)
					findings = append(findings, f)
					byPair[key] = f
					continue
				}
			}

			findingType := model.FindingCollision
			if isShadowing(winner, loser) {
				findingType = model.FindingShadowing
			}
			f := &model.Finding{
				Severity:     classifyCollisionSeverity(winner, loser),
				Type:         findingType,
				RouterFlavor: flavor,
				Routes:       []*model.KongRoute{winner.Route, loser.Route},
				Samples:      []string{reqPath},
				WinnerID:     winner.Route.ID,
				Reason:       buildCollisionReason(winner, loser, reqPath, flavor, res.Explanation()),
				Suggestions:  buildCollisionSuggestions(winner, loser),
			}
			findings = append(findings, f)
			byPair[key] = f
		}
	}
	return findings
}

// prefixCache memoizes each route's allPrefixes result (keyed by route ID),
// computed once per route rather than once per (candidate, pair)
// occurrence — the same pair can recur across many candidate requests, and
// allPrefixes is a pure function of the route's own paths.
type prefixCache map[string]prefixResult

// prefixResult is one route's memoized allPrefixes outcome.
type prefixResult struct {
	prefixes []string
	ok       bool
}

// newPrefixCache precomputes allPrefixes for every route.
func newPrefixCache(routes []*router.MarshalledRoute) prefixCache {
	c := make(prefixCache, len(routes))
	for _, mr := range routes {
		prefixes, ok := allPrefixes(mr)
		c[mr.Route.ID] = prefixResult{prefixes: prefixes, ok: ok}
	}
	return c
}

// isHierarchicalChild reports whether loser is a proper path-segment ancestor
// of winner (e.g. /chat vs /chat/history, but not /payments vs /payments-v2).
// Such parent → child hierarchies are resolved deterministically by Kong's
// max_uri_length tie-breaker. Only applies when both routes are exclusively
// plain-prefix.
func (c prefixCache) isHierarchicalChild(winner, loser *router.MarshalledRoute) bool {
	lp := c[loser.Route.ID]
	if !lp.ok {
		return false
	}
	wp := c[winner.Route.ID]
	if !wp.ok {
		return false
	}
	for _, l := range lp.prefixes {
		// Strip a trailing '/' first to avoid a double slash (/api/ vs /api/ws).
		boundary := strings.TrimSuffix(l, "/") + "/"
		for _, w := range wp.prefixes {
			if !strings.HasPrefix(w, boundary) {
				return false
			}
		}
	}
	return true
}

// allPrefixes returns the route's prefixes when it has at least one path and
// every path is a plain prefix.
func allPrefixes(mr *router.MarshalledRoute) ([]string, bool) {
	if len(mr.ParsedPaths) == 0 {
		return nil, false
	}
	out := make([]string, len(mr.ParsedPaths))
	for i := range mr.ParsedPaths {
		if mr.ParsedPaths[i].Kind != router.PathPrefix {
			return nil, false
		}
		out[i] = mr.ParsedPaths[i].Prefix
	}
	return out, true
}

// isShadowing reports whether the winner has a broad regex that matches the
// loser's own path pattern used as a sample — i.e. it captures requests
// clearly intended for the loser, rather than merely overlapping.
func isShadowing(winner, loser *router.MarshalledRoute) bool {
	for wi := range winner.ParsedPaths {
		wp := &winner.ParsedPaths[wi]
		if wp.Kind != router.PathRegex {
			continue
		}
		for li := range loser.ParsedPaths {
			sample := patternText(&loser.ParsedPaths[li])
			if sample != "" && router.MatchPath(wp, sample) {
				return true
			}
		}
	}
	return false
}

// patternText returns the prefix of a plain path or the source of a regex path.
func patternText(p *router.ParsedPath) string {
	if p.Kind == router.PathPrefix {
		return p.Prefix
	}
	return p.RegexSource
}

// classifyCollisionSeverity rates a collision:
//   - HIGH: different services (traffic reaches the wrong backend).
//   - LOW: an intentional same-service refinement — an explicit higher
//     regex_priority, or a more specific route overriding a catch-all.
//   - MEDIUM: same service, ambiguous overlap.
func classifyCollisionSeverity(winner, loser *router.MarshalledRoute) model.Severity {
	if w, l := serviceID(winner), serviceID(loser); w != "" && l != "" && w != l {
		return model.SeverityHigh
	}
	if winner.Route.RegexPriority > loser.Route.RegexPriority {
		return model.SeverityLow
	}
	if winner.MaxURILength > loser.MaxURILength {
		return model.SeverityLow
	}
	// max_uri_length is always 0 for regex paths in Kong, so the regex source
	// length serves as the specificity proxy.
	if maxRegexSpecificity(winner) > maxRegexSpecificity(loser) {
		return model.SeverityLow
	}
	return model.SeverityMedium
}

func maxRegexSpecificity(mr *router.MarshalledRoute) int {
	n := 0
	for i := range mr.ParsedPaths {
		if p := &mr.ParsedPaths[i]; p.Kind == router.PathRegex {
			n = max(n, len(p.RegexSource))
		}
	}
	return n
}

// buildCollisionReason builds the explanation chain for a collision. The
// explanation from the triggering simulation is reused when available.
func buildCollisionReason(winner, loser *router.MarshalledRoute, sample string, flavor model.RouterFlavor, explanation []string) []string {
	lines := make([]string, 0, 8)
	for _, item := range []struct {
		label string
		mr    *router.MarshalledRoute
	}{{"winner", winner}, {"shadowed", loser}} {
		r := item.mr.Route
		paths := "(no paths)"
		if r.Paths != nil {
			paths = strings.Join(r.Paths, ", ")
		}
		created := "unknown"
		if r.CreatedAt != nil && *r.CreatedAt != 0 {
			created = router.ISOTime(*r.CreatedAt)
		}
		lines = append(lines, `Route "`+r.DisplayName()+`" (`+item.label+`): paths=[`+paths+`], `+
			"regex_priority="+strconv.Itoa(r.RegexPriority)+", created_at="+created)
	}

	lines = append(lines, `Both routes match sample request path "`+sample+`".`)

	for i := range winner.ParsedPaths {
		p := &winner.ParsedPaths[i]
		if p.Kind != router.PathRegex {
			continue
		}
		if issues := DetectSuspiciousRegexIssues(p.Raw); len(issues) > 0 {
			lines = append(lines, `Winner path "`+p.Raw+`" is a regex path (compiled as: `+p.RegexSource+`) `+
				"under "+string(flavor)+" flavor – not a glob.")
			lines = append(lines, issues...)
		}
	}

	if len(explanation) == 0 {
		res := router.SimulateRequest([]*router.MarshalledRoute{winner, loser},
			router.SimRequest{Method: candidateMethod, Host: candidateHost, Path: sample})
		explanation = res.Explanation()
	}
	return append(lines, explanation...)
}

// buildCollisionSuggestions returns de-duplicated safer patterns for both
// routes, plus a note when the routes are exact duplicates (the duplicate, not
// the regex, is then the root cause).
func buildCollisionSuggestions(winner, loser *router.MarshalledRoute) []string {
	out := []string{}
	for _, mr := range []*router.MarshalledRoute{winner, loser} {
		for i := range mr.ParsedPaths {
			if fix := SuggestRegexFix(mr.ParsedPaths[i].Raw); fix != "" && !slices.Contains(out, fix) {
				out = append(out, fix)
			}
		}
	}
	if haveIdenticalPaths(winner, loser) {
		out = append(out, "These routes have identical paths — delete the shadowed route, "+
			"or differentiate using hosts / methods / headers constraints")
	}
	return out
}
