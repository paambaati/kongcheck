package router

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/dlclark/regexp2"
)

// patternMatchTimeout bounds a single backtracking match so a pathological
// user-supplied regex (ReDoS) cannot hang the analysis.
const patternMatchTimeout = time.Second

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

// MatchString reports whether the pattern matches anywhere in s.
func (p *Pattern) MatchString(s string) bool {
	switch {
	case p.re2 != nil:
		return p.re2.MatchString(s)
	case p.pcre != nil:
		ok, err := p.pcre.MatchString(s)
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
		m, err := p.pcre.FindStringMatch(s)
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
