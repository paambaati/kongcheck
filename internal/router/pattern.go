package router

import (
	"encoding/json"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
)

// patternMatchTimeout bounds a single backtracking match so a pathological
// user-supplied regex (ReDoS) cannot hang the analysis. A var (not a const)
// so tests can shrink it instead of waiting out the real 1s.
var patternMatchTimeout = time.Second

// patternBreakerThreshold is how many consecutive regexp2 evaluation
// failures (in practice, almost always a MatchTimeout) a Pattern tolerates
// before its circuit breaker trips. See consecutiveTimeouts.
const patternBreakerThreshold = 3

// Pattern is a compiled route regex.
//
// Kong evaluates route regexes with PCRE. Patterns are compiled with Go's
// linear-time RE2 engine whenever the syntax allows it (the common case, and
// the fast path in the O(n²) analysis loops); patterns using PCRE-only syntax
// such as lookarounds or backreferences fall back to a backtracking PCRE-style
// engine. Malformed patterns become a never-matching sentinel so analysis can
// still flag them instead of crashing.
//
// A Pattern is safe for concurrent use.
type Pattern struct {
	source string
	re2    *regexp.Regexp
	pcre   *regexp2.Regexp

	// consecutiveTimeouts counts consecutive regexp2 evaluation failures for
	// this specific compiled pattern (see recordResult). patternMatchTimeout
	// bounds any single match, but the O(n²) analysis passes evaluate the
	// same *Pattern against many different candidate/sample strings — a
	// pathological pattern shared across many routes could otherwise cost
	// one full patternMatchTimeout stall per evaluation, multiplying into
	// minutes. Once the count reaches patternBreakerThreshold, MatchString
	// and FindString short-circuit to "no match" instead of invoking the
	// backtracking engine again, capping this pattern's aggregate cost to a
	// small, fixed number of stalls. A successful match resets the counter,
	// so an occasionally-slow-but-not-pathological pattern is never
	// penalized for one-off slowness.
	consecutiveTimeouts atomic.Int32
}

// CompilePattern compiles src. It never fails; invalid patterns never match
// (see Valid).
func CompilePattern(src string) *Pattern {
	p := &Pattern{source: src}
	if re, err := regexp.Compile(src); err == nil {
		p.re2 = re
		return p
	}
	if re, err := regexp2.Compile(src, regexp2.None); err == nil {
		re.MatchTimeout = patternMatchTimeout
		p.pcre = re
	}
	return p
}

// Source returns the pattern source as compiled.
func (p *Pattern) Source() string { return p.source }

// Valid reports whether the pattern compiled successfully.
func (p *Pattern) Valid() bool { return p.re2 != nil || p.pcre != nil }

// breakerTripped reports whether this pattern has failed
// patternBreakerThreshold times in a row and should be treated as
// permanently non-matching for the rest of the process's lifetime.
func (p *Pattern) breakerTripped() bool {
	return p.consecutiveTimeouts.Load() >= patternBreakerThreshold
}

// recordResult updates the consecutive-failure counter after a regexp2
// evaluation: err != nil (almost always a MatchTimeout) increments it, a
// clean evaluation resets it.
func (p *Pattern) recordResult(err error) {
	if err != nil {
		p.consecutiveTimeouts.Add(1)
	} else {
		p.consecutiveTimeouts.Store(0)
	}
}

// MatchString reports whether the pattern matches anywhere in s.
func (p *Pattern) MatchString(s string) bool {
	switch {
	case p.re2 != nil:
		return p.re2.MatchString(s)
	case p.pcre != nil:
		if p.breakerTripped() {
			return false
		}
		ok, err := p.pcre.MatchString(s)
		p.recordResult(err)
		return err == nil && ok
	}
	return false
}

// FindString returns the leftmost match in s and whether one was found.
func (p *Pattern) FindString(s string) (string, bool) {
	switch {
	case p.re2 != nil:
		loc := p.re2.FindStringIndex(s)
		if loc == nil {
			return "", false
		}
		return s[loc[0]:loc[1]], true
	case p.pcre != nil:
		if p.breakerTripped() {
			return "", false
		}
		m, err := p.pcre.FindStringMatch(s)
		p.recordResult(err)
		if err != nil || m == nil {
			return "", false
		}
		return m.String(), true
	}
	return "", false
}

// MarshalJSON renders the pattern as its source string.
func (p *Pattern) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.source)
}
