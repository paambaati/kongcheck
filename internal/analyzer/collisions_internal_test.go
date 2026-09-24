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
