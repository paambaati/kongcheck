package analyzer

import (
	"context"
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
// Pairs already present in covered (already reported as a collision by the
// earlier pass) are skipped before paying for the sample-matching work, not
// just filtered out afterward — findSiblingOverlapSample is comparatively
// expensive (regex evaluation against every path sample of both routes), and
// a control plane where the collision pass already resolved most pairs would
// otherwise pay that cost twice for no benefit.
//
// The scan is O(n²) but embarrassingly parallel: each row is processed
// independently and hits are returned in (i, j) order, matching a sequential
// nested loop exactly. covered is only read here, never written, so
// concurrent access from parallelFor's workers is safe.
func findOverlapHits(ctx context.Context, routes []*router.MarshalledRoute, covered map[pairKey]bool) []overlapHit {
	rows := make([][]overlapHit, len(routes))
	parallelFor(ctx, len(routes), func(i int) {
		a := routes[i]
		if a.IsUniversal {
			return
		}
		for j := i + 1; j < len(routes); j++ {
			if ctx.Err() != nil {
				return
			}
			b := routes[j]
			if b.IsUniversal || a.Route.ID == b.Route.ID {
				continue
			}
			if covered[makePairKey(a.Route.ID, b.Route.ID)] {
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
func detectSiblingOverlaps(ctx context.Context, routes []*router.MarshalledRoute, flavor model.RouterFlavor, existing []*model.Finding, includeInfo bool) []*model.Finding {
	covered := make(map[pairKey]bool, len(existing))
	for _, f := range existing {
		if len(f.Routes) >= 2 {
			covered[makePairKey(f.Routes[0].ID, f.Routes[1].ID)] = true
		}
	}

	findings := []*model.Finding{}
	for _, hit := range findOverlapHits(ctx, routes, covered) {
		a, b := routes[hit.i], routes[hit.j]
		key := makePairKey(a.Route.ID, b.Route.ID)
		// findOverlapHits already excluded pairs covered before the scan
		// started; this guards against this pass emitting its own
		// duplicate if a pair somehow appears twice (it currently can't,
		// since each unordered (i, j) pair is visited exactly once above).
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
			if !isCleanBoundary(sample, matchEnd) {
				return sample, true
			}
		}
	}
	return "", false
}

func isCleanBoundary(sample string, matchEnd int) bool {
	// Fast path for ASCII URLs (no allocations). Byte length equals rune
	// count only in this branch, so the len(sample) comparison is only valid
	// here — it must not be hoisted above the ASCII check (see non-ASCII
	// branch below, where matchEnd is a rune count but len(sample) is a byte
	// count).
	isASCII := true
	for i := 0; i < len(sample); i++ {
		if sample[i] >= utf8.RuneSelf {
			isASCII = false
			break
		}
	}
	if isASCII {
		if matchEnd >= len(sample) {
			return true
		}
		if sample[matchEnd] == '/' {
			return true
		}
		return matchEnd > 0 && sample[matchEnd-1] == '/'
	}

	// For non-ASCII, decode runes without slice allocation, comparing
	// matchEnd against the rune count rather than the byte length.
	var prevRune, curRune rune
	runeIdx := 0
	reachedMatchEnd := false
	for _, r := range sample {
		if runeIdx == matchEnd-1 {
			prevRune = r
		}
		if runeIdx == matchEnd {
			curRune = r
			reachedMatchEnd = true
			break
		}
		runeIdx++
	}
	if !reachedMatchEnd {
		// matchEnd is at or past the sample's total rune count: the match
		// consumed the whole sample, which is always a clean boundary.
		return true
	}
	if curRune == '/' {
		return true
	}
	return matchEnd > 0 && prevRune == '/'
}
