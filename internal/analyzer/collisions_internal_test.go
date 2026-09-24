// White-box regression tests for the cancellation-safety of detectCollisions.
//
// simulateAll pre-allocates a []*router.SimResult and only fills the indices
// that parallelFor actually visits before ctx is cancelled; skipped indices
// stay nil. detectCollisions must not dereference those nil entries.
package analyzer

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// countingCancelContext behaves like context.Background() except its Err
// method returns context.Canceled once it has been called more than allow
// times. It deterministically simulates a context that gets cancelled after
// some amount of work has already started, without relying on goroutine
// scheduling or wall-clock timing.
type countingCancelContext struct {
	context.Context
	calls int64
	allow int64
}

func (c *countingCancelContext) Err() error {
	if atomic.AddInt64(&c.calls, 1) > c.allow {
		return context.Canceled
	}
	return nil
}

// manyRoutes builds n simple, non-colliding routes so GenerateCandidateRequests
// produces a healthy number of candidates for parallelFor to (partially) work
// through.
func manyRoutes(n int) []*router.MarshalledRoute {
	routes := make([]*model.KongRoute, n)
	for i := range routes {
		routes[i] = &model.KongRoute{
			ID:    "r" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Name:  "route",
			Paths: []string{"/svc" + string(rune('a'+i%26)) + string(rune('0'+i/26))},
		}
	}
	data := &model.KonnectData{Routes: routes, Services: model.NewServiceIndex(), RouterFlavor: model.FlavorTraditional}
	return router.SortRoutes(router.MarshalRoutes(data, model.FlavorTraditional))
}

func TestDetectCollisions_NilSafeOnAlreadyCancelledContext(t *testing.T) {
	sorted := manyRoutes(20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before detectCollisions ever calls simulateAll

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("detectCollisions panicked on an already-cancelled context: %v", r)
		}
	}()

	findings := detectCollisions(ctx, sorted, model.FlavorTraditional, true)
	if len(findings) != 0 {
		t.Errorf("expected no findings when every simulation is skipped, got %d", len(findings))
	}
}

func TestDetectCollisions_NilSafeOnMidFlightCancellation(t *testing.T) {
	sorted := manyRoutes(50)

	// Allow a handful of parallelFor's ctx.Err() checks to succeed before
	// cancelling, so some candidates are simulated (non-nil results) and
	// others are skipped (nil results) in the same run.
	ctx := &countingCancelContext{Context: context.Background(), allow: 5}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("detectCollisions panicked on a mid-flight cancelled context: %v", r)
		}
	}()

	// Must not panic regardless of how many (if any) candidates were
	// resolved before cancellation took effect.
	_ = detectCollisions(ctx, sorted, model.FlavorTraditional, true)
}

func TestSimulateAll_LeavesSkippedEntriesNil(t *testing.T) {
	sorted := manyRoutes(10)
	candidates := GenerateCandidateRequests(sorted)
	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate request for a non-empty route set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := simulateAll(ctx, sorted, candidates)
	if len(results) != len(candidates) {
		t.Fatalf("expected %d results, got %d", len(candidates), len(results))
	}
	for i, res := range results {
		if res != nil {
			t.Fatalf("expected results[%d] to be nil on a pre-cancelled context, got %+v", i, res)
		}
	}
}

// TestPrefixCache_MemoizesPerRouteNotPerPair guards against allPrefixes being
// recomputed from scratch on every (candidate, pair) occurrence instead of
// once per route. newPrefixCache must hold exactly one entry per route
// (built in a single pass over the route list), and prefixCache.
// isHierarchicalChild must behave identically to the pre-memoization
// standalone implementation.
func TestPrefixCache_MemoizesPerRouteNotPerPair(t *testing.T) {
	parent := marshalledRouteWithPrefix("r1", "/chat")
	child := marshalledRouteWithPrefix("r2", "/chat/history")
	sibling := marshalledRouteWithPrefix("r4", "/payments-v2")
	regexRoute := &router.MarshalledRoute{
		Route: &model.KongRoute{ID: "r3"},
		ParsedPaths: []router.ParsedPath{
			{Kind: router.PathRegex, Raw: "~/foo", RegexSource: "/foo"},
		},
	}
	routes := []*router.MarshalledRoute{parent, child, regexRoute, sibling}

	cache := newPrefixCache(routes)
	if len(cache) != len(routes) {
		t.Fatalf("expected exactly one cache entry per route, got %d entries for %d routes", len(cache), len(routes))
	}

	if r1 := cache["r1"]; !r1.ok || len(r1.prefixes) != 1 || r1.prefixes[0] != "/chat" {
		t.Errorf("unexpected cache entry for r1: %+v", r1)
	}
	if r3 := cache["r3"]; r3.ok {
		t.Errorf("expected a regex-path route to have ok=false, got %+v", r3)
	}

	if !cache.isHierarchicalChild(child, parent) {
		t.Error("expected child (/chat/history) to be classified as a hierarchical child of parent (/chat)")
	}
	if cache.isHierarchicalChild(parent, child) {
		t.Error("expected parent (/chat) to NOT be classified as a hierarchical child of child (/chat/history)")
	}
	if cache.isHierarchicalChild(sibling, parent) {
		t.Error("expected unrelated sibling paths (/chat vs /payments-v2) to not be classified as hierarchical")
	}
	if cache.isHierarchicalChild(regexRoute, parent) || cache.isHierarchicalChild(parent, regexRoute) {
		t.Error("expected a regex-path route to never be classified as hierarchical (allPrefixes requires all-plain-prefix)")
	}

	// Looking up the same pair repeatedly (as detectCollisions does across
	// many candidate requests) must be stable and side-effect-free.
	for range 5 {
		if !cache.isHierarchicalChild(child, parent) {
			t.Fatal("expected isHierarchicalChild to be stable across repeated calls for the same pair")
		}
	}
}
