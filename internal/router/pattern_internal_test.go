// White-box regression test for Pattern's per-pattern timeout circuit
// breaker.
//
// patternMatchTimeout (regexp2.MatchTimeout) bounds any single backtracking
// match, but the O(n²) analysis passes (candidate simulation, sibling
// overlap detection) evaluate the same *Pattern against many different
// strings. Without a breaker, a single pathological PCRE-only pattern (one
// requiring lookaround/backreference syntax RE2 can't compile, combined with
// a nested quantifier) reused across many routes could cost one full
// patternMatchTimeout stall per evaluation — multiplying into minutes
// against a large route table. The breaker caps this to a small, fixed
// number of stalls per pattern.
package router

import (
	"testing"
	"time"
)

func TestPattern_TimeoutBreakerBoundsAggregateCost(t *testing.T) {
	// Shrink the timeout so the test runs fast; restore afterwards since
	// patternMatchTimeout is a package-level var shared by other tests.
	origTimeout := patternMatchTimeout
	patternMatchTimeout = 80 * time.Millisecond
	t.Cleanup(func() { patternMatchTimeout = origTimeout })

	// Lookahead forces the PCRE (regexp2) fallback — RE2 doesn't support
	// `(?=`. The nested quantifier (a+)+ inside it is a classic catastrophic
	// backtracking trigger against an input with no trailing 'b'.
	p := CompilePattern(`^(?=(a+)+b)`)
	if p.re2 != nil || p.pcre == nil {
		t.Fatal("expected this pattern to compile via the PCRE fallback, not RE2")
	}

	adversarialInput := ""
	for range 40 {
		adversarialInput += "a"
	}

	// The first patternBreakerThreshold calls each pay up to one timeout.
	start := time.Now()
	for i := 0; i < patternBreakerThreshold; i++ {
		if p.MatchString(adversarialInput) {
			t.Fatalf("call %d: expected no match (input has no trailing 'b')", i)
		}
	}
	costOfThreshold := time.Since(start)
	if !p.breakerTripped() {
		t.Fatalf("expected breaker to be tripped after %d consecutive timeouts", patternBreakerThreshold)
	}

	// Many more calls after the breaker trips must be cheap: each one would
	// otherwise cost another patternMatchTimeout.
	start = time.Now()
	const callsAfterTrip = 50
	for i := 0; i < callsAfterTrip; i++ {
		if p.MatchString(adversarialInput) {
			t.Fatalf("call %d: expected no match once the breaker is tripped", i)
		}
		if _, ok := p.FindString(adversarialInput); ok {
			t.Fatalf("call %d: expected no match from FindString once the breaker is tripped", i)
		}
	}
	costAfterTrip := time.Since(start)

	if costAfterTrip >= costOfThreshold {
		t.Fatalf("expected %d calls after the breaker tripped (%v) to be cheaper than "+
			"the %d calls that tripped it (%v) — got the opposite, meaning every call "+
			"is still paying a full timeout", callsAfterTrip, costAfterTrip, patternBreakerThreshold, costOfThreshold)
	}
	// Comfortably under one more timeout for all 50*2 calls combined (each
	// would otherwise cost ~80ms, i.e. ~8s for 100 calls).
	if costAfterTrip >= patternMatchTimeout {
		t.Fatalf("expected %d post-trip calls to cost less than one timeout (%v) combined, took %v",
			callsAfterTrip, patternMatchTimeout, costAfterTrip)
	}
}

func TestPattern_TimeoutBreakerResetsOnCleanMatch(t *testing.T) {
	origTimeout := patternMatchTimeout
	patternMatchTimeout = 80 * time.Millisecond
	t.Cleanup(func() { patternMatchTimeout = origTimeout })

	p := CompilePattern(`^(?=(a+)+b)`)
	adversarialInput := ""
	for range 40 {
		adversarialInput += "a"
	}
	cleanInput := "ab" // matches instantly: the lookahead is satisfied immediately

	for i := 0; i < patternBreakerThreshold-1; i++ {
		p.MatchString(adversarialInput)
	}
	if p.breakerTripped() {
		t.Fatal("breaker must not trip before reaching the threshold")
	}
	if !p.MatchString(cleanInput) {
		t.Fatal("expected a clean, fast match against 'b' to succeed")
	}
	if p.consecutiveTimeouts.Load() != 0 {
		t.Fatalf("expected a successful match to reset the counter, got %d", p.consecutiveTimeouts.Load())
	}
}
