package analyzer

import (
	"unicode/utf8"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// overlapHit is a candidate sibling overlap between routes[i] and routes[j].
type overlapHit struct {
	i, j   int
	sample string
}

// findOverlapHits scans all route pairs (i < j) for a sibling overlap sample.
// The scan is O(n²) but embarrassingly parallel: each row is processed
// independently and hits are returned in (i, j) order, matching a sequential
// nested loop exactly.
func findOverlapHits(routes []*router.MarshalledRoute) []overlapHit {
	rows := make([][]overlapHit, len(routes))
	parallelFor(len(routes), func(i int) {
		a := routes[i]
		if a.IsUniversal {
			return
		}
		for j := i + 1; j < len(routes); j++ {
			b := routes[j]
			if b.IsUniversal || a.Route.ID == b.Route.ID {
				continue
			}
			if sample, ok := findSiblingOverlapSample(a, b); ok {
				rows[i] = append(rows[i], overlapHit{i: i, j: j, sample: sample})
			}
		}
	})
	var hits []overlapHit
	for _, row := range rows {
		hits = append(hits, row...)
	}
	return hits
}

// detectSiblingOverlaps flags route pairs whose path prefixes share a common
// stem (e.g. /payments and /payments-v2: the /payments prefix also matches
// /payments-v2/...) that the collision pass did not already report.
func detectSiblingOverlaps(routes []*router.MarshalledRoute, flavor model.RouterFlavor, existing []*model.Finding, includeInfo bool) []*model.Finding {
	covered := make(map[pairKey]bool, len(existing))
	for _, f := range existing {
		if len(f.Routes) >= 2 {
			covered[makePairKey(f.Routes[0].ID, f.Routes[1].ID)] = true
		}
	}

	findings := []*model.Finding{}
	for _, hit := range findOverlapHits(routes) {
		a, b := routes[hit.i], routes[hit.j]
		key := makePairKey(a.Route.ID, b.Route.ID)
		if covered[key] {
			continue
		}
		covered[key] = true

		winner, loser := a, b
		if router.CompareRoutes(a, b) > 0 {
			winner, loser = b, a
		}

		if winner.HasTemplatePlaceholder {
			continue
		}

		if reason, ok := isL4Stratified(winner, loser); ok {
			if includeInfo {
				findings = append(findings, buildL4StratifiedFinding(winner, loser, hit.sample, flavor, reason))
			}
			continue
		}

		if haveIdenticalPaths(winner, loser) {
			switch isHeaderStratified(winner, loser) {
			case headersStratified:
				if includeInfo {
					findings = append(findings, buildHeaderStratifiedFinding(winner, loser, hit.sample, flavor))
				}
				continue
			case headersRegexOpaque:
				findings = append(findings, buildRegexHeaderOpaqueFinding(winner, loser, hit.sample, flavor))
				continue
			}
		}

		findings = append(findings, &model.Finding{
			Severity:     classifyCollisionSeverity(winner, loser),
			Type:         model.FindingShadowing,
			RouterFlavor: flavor,
			Routes:       []*model.KongRoute{winner.Route, loser.Route},
			Samples:      []string{hit.sample},
			WinnerID:     winner.Route.ID,
			Reason: []string{
				`Route "` + winner.Route.DisplayName() + `" has a path that can match requests ` +
					`intended for "` + loser.Route.DisplayName() + `".`,
				`Sample request "` + hit.sample + `" matches both routes.`,
				"This is a sibling namespace overlap: the path prefixes/patterns share a common stem.",
			},
			Suggestions: buildCollisionSuggestions(winner, loser),
		})
	}
	return findings
}

// findSiblingOverlapSample looks for a path matched by both routes: each
// route's pre-computed path samples are tried against the other route's
// patterns (b's samples first, then a's).
//
// A match that ends on a clean segment boundary is not an overlap: the next
// sample character is '/', the match consumed the whole sample, or the match
// itself ends with '/'.
func findSiblingOverlapSample(a, b *router.MarshalledRoute) (string, bool) {
	if s, ok := overlapSample(b, a); ok {
		return s, true
	}
	return overlapSample(a, b)
}

// overlapSample tries samples from src against the patterns of dst.
func overlapSample(src, dst *router.MarshalledRoute) (string, bool) {
	for si := range src.ParsedPaths {
		sample := src.ParsedPaths[si].Sample
		if sample == "" {
			continue
		}
		for di := range dst.ParsedPaths {
			p := &dst.ParsedPaths[di]
			if !router.MatchPath(p, sample) {
				continue
			}
			// matchEnd is the length of the matched text (for regexes, the
			// match length — not its end offset — exactly as the reference
			// implementation computes it).
			var matchEnd int
			if p.Kind == router.PathPrefix {
				matchEnd = utf8.RuneCountInString(p.Prefix)
			} else if m, ok := p.Regex.FindString(sample); ok {
				matchEnd = utf8.RuneCountInString(m)
			}
			if !isCleanBoundary([]rune(sample), matchEnd) {
				return sample, true
			}
		}
	}
	return "", false
}

func isCleanBoundary(sample []rune, matchEnd int) bool {
	if matchEnd >= len(sample) || sample[matchEnd] == '/' {
		return true
	}
	return matchEnd > 0 && sample[matchEnd-1] == '/'
}
