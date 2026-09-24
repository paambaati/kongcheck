// White-box regression tests for isCleanBoundary's Unicode handling.
//
// matchEnd is always a rune count (see overlapSample), but isCleanBoundary
// used to compare it against len(sample), which is a byte count for any
// string containing multi-byte UTF-8 characters. That mismatch made the
// "match consumed the whole sample" fast path silently fail to fire for
// non-ASCII samples, falling through to a decode loop that never assigned
// curRune for a full match and produced a wrong answer that depended on the
// sample's last byte rather than short-circuiting to "not an overlap".
package analyzer

import (
	"context"
	"testing"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// marshalledRouteWithPrefix builds a minimal MarshalledRoute with a single
// plain-prefix path, whose pre-computed Sample is the prefix itself — enough
// to exercise overlapSample without going through the full marshal pipeline.
func marshalledRouteWithPrefix(id, prefix string) *router.MarshalledRoute {
	return &router.MarshalledRoute{
		Route: &model.KongRoute{ID: id, Paths: []string{prefix}},
		ParsedPaths: []router.ParsedPath{
			{Kind: router.PathPrefix, Raw: prefix, Prefix: prefix, Sample: prefix},
		},
	}
}

func TestIsCleanBoundary_FullMatchNonASCII(t *testing.T) {
	// "/café" is 5 runes but 6 bytes ('é' is 2 UTF-8 bytes). A match that
	// consumes the whole sample must always be a clean boundary, regardless
	// of what the last rune happens to be.
	sample := "/café"
	matchEnd := len([]rune(sample)) // 5: the pattern matched every rune
	if !isCleanBoundary(sample, matchEnd) {
		t.Fatalf("isCleanBoundary(%q, %d) = false, want true (match consumed the whole sample)", sample, matchEnd)
	}
}

func TestIsCleanBoundary_FullMatchNonASCIINotEndingInSlash(t *testing.T) {
	// Same as above but with a sample that does NOT end in '/' or a rune
	// that could coincidentally look like a boundary — this is the case the
	// pre-fix code got wrong (it returned prevRune == '/').
	for _, sample := range []string{"/résumé", "/naïve", "/日本語"} {
		matchEnd := len([]rune(sample))
		if !isCleanBoundary(sample, matchEnd) {
			t.Errorf("isCleanBoundary(%q, %d) = false, want true (full match)", sample, matchEnd)
		}
	}
}

func TestIsCleanBoundary_PartialMatchNonASCIICleanBoundary(t *testing.T) {
	// "/café" (5 runes) matched inside "/café/extra" — the next rune is '/',
	// a clean boundary.
	sample := "/café/extra"
	matchEnd := len([]rune("/café"))
	if !isCleanBoundary(sample, matchEnd) {
		t.Fatalf("isCleanBoundary(%q, %d) = false, want true (next rune is '/')", sample, matchEnd)
	}
}

func TestIsCleanBoundary_PartialMatchNonASCIIDirtyBoundary(t *testing.T) {
	// "/café" (5 runes) matched inside "/café-x" — the next rune is '-', not
	// a clean boundary, so this must still be reported as an overlap.
	sample := "/café-x"
	matchEnd := len([]rune("/café"))
	if isCleanBoundary(sample, matchEnd) {
		t.Fatalf("isCleanBoundary(%q, %d) = true, want false (next rune is '-', not a boundary)", sample, matchEnd)
	}
}

func TestIsCleanBoundary_ASCIIUnaffected(t *testing.T) {
	// Pure-ASCII behaviour must be unchanged: full match, clean '/' boundary,
	// and a dirty boundary.
	cases := []struct {
		sample   string
		matchEnd int
		want     bool
	}{
		{"/payments", 9, true},        // full match
		{"/payments/status", 9, true}, // next char '/'
		{"/payments-v2", 9, false},    // next char '-'
		{"/api/", 4, true},            // match ends right before trailing '/'
	}
	for _, c := range cases {
		if got := isCleanBoundary(c.sample, c.matchEnd); got != c.want {
			t.Errorf("isCleanBoundary(%q, %d) = %v, want %v", c.sample, c.matchEnd, got, c.want)
		}
	}
}

// TestOverlapSample_FullMatchNonASCIINotFalsePositive is an end-to-end
// regression test through overlapSample (not just the isCleanBoundary unit):
// two routes sharing the exact same non-ASCII plain prefix must not be
// reported as a "dirty boundary" sibling overlap.
func TestOverlapSample_FullMatchNonASCIINotFalsePositive(t *testing.T) {
	src := marshalledRouteWithPrefix("r1", "/café")
	dst := marshalledRouteWithPrefix("r2", "/café")

	if _, ok := overlapSample(src, dst); ok {
		t.Fatal("overlapSample reported a dirty-boundary overlap for two routes with an identical full-length non-ASCII prefix match")
	}
}

// TestFindOverlapHits_SkipsCoveredPairsBeforeMatching guards against
// detectSiblingOverlaps/findOverlapHits paying for the (comparatively
// expensive) sample-matching work on a pair the collision pass already
// reported. Before this fix, the covered-set check happened only after
// findSiblingOverlapSample had already run for every pair; findOverlapHits
// now takes covered directly and skips the match call entirely.
func TestFindOverlapHits_SkipsCoveredPairsBeforeMatching(t *testing.T) {
	a := marshalledRouteWithPrefix("r1", "/payments")
	b := marshalledRouteWithPrefix("r2", "/payments-v2")
	routes := []*router.MarshalledRoute{a, b}

	hits := findOverlapHits(context.Background(), routes, map[pairKey]bool{})
	if len(hits) != 1 {
		t.Fatalf("expected 1 overlap hit when the pair is not covered, got %d: %+v", len(hits), hits)
	}

	key := makePairKey("r1", "r2")
	hits = findOverlapHits(context.Background(), routes, map[pairKey]bool{key: true})
	if len(hits) != 0 {
		t.Fatalf("expected 0 overlap hits once the pair is already covered, got %d: %+v", len(hits), hits)
	}
}

// TestDetectSiblingOverlaps_DoesNotDuplicateAnAlreadyCoveredPair is the
// end-to-end counterpart: a pair already present in the collision pass's
// findings must not also produce a sibling-overlap finding.
func TestDetectSiblingOverlaps_DoesNotDuplicateAnAlreadyCoveredPair(t *testing.T) {
	a := marshalledRouteWithPrefix("r1", "/payments")
	b := marshalledRouteWithPrefix("r2", "/payments-v2")
	routes := []*router.MarshalledRoute{a, b}

	existing := []*model.Finding{{
		Routes: []*model.KongRoute{a.Route, b.Route},
	}}

	findings := detectSiblingOverlaps(context.Background(), routes, model.FlavorTraditional, existing, true)
	if len(findings) != 0 {
		t.Fatalf("expected no sibling-overlap finding for a pair already covered by the collision pass, got %d: %+v",
			len(findings), findings)
	}
}
