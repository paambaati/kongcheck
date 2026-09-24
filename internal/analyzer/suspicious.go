package analyzer

import (
	"regexp"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
)

// suspiciousPattern describes a regex-path anti-pattern: syntax that suggests
// the author meant a glob wildcard but wrote PCRE.
type suspiciousPattern struct {
	// test is matched against the raw path string (including the leading `~`).
	test        *regexp.Regexp
	description string
	suggestion  func(raw string) string
	// severity overrides the default MEDIUM (HIGH for ReDoS-prone patterns).
	severity model.Severity
}

var (
	trailingSlashStarRe = regexp.MustCompile(`/\*$`)
	middleSlashStarRe   = regexp.MustCompile(`/\*/`)
	wordCharStarRe      = regexp.MustCompile(`[a-zA-Z0-9]\*$`)
)

// suspiciousPatterns is evaluated in order; SuggestRegexFix uses the first hit.
var suspiciousPatterns = []suspiciousPattern{
	{
		// ~/foo/* — a trailing `/*` is almost always a glob mistake.
		test: trailingSlashStarRe,
		description: "`*` at end of path is a PCRE quantifier (zero or more of the preceding char '/'), " +
			"not a glob wildcard. It does NOT mean 'anything after this prefix'.",
		suggestion: func(raw string) string {
			return "~" + trailingSlashStarRe.ReplaceAllString(raw[1:], "") + "(?:/.*)?$"
		},
	},
	{
		// ~/foo/*/bar — `/*/` in the middle.
		test: middleSlashStarRe,
		description: "`/*/` in a regex path uses `*` as a PCRE quantifier on '/', which matches zero or more " +
			"slashes – not 'any path segment'. Consider using `/[^/]+/` for a single dynamic segment.",
		suggestion: func(raw string) string {
			return middleSlashStarRe.ReplaceAllLiteralString(raw, "/[^/]+/")
		},
	},
	{
		// ~/foo* — `*` quantifies the previous character.
		test: wordCharStarRe,
		description: "Trailing `*` after a word character quantifies that character (zero or more occurrences), " +
			"not the whole path segment. E.g. `~/payments*` matches `/payment`, `/payments`, `/paymentss`, etc., " +
			"but NOT `/payments/anything`.",
		suggestion: func(raw string) string {
			return "~" + strings.TrimSuffix(raw[1:], "*") + "(?:/.*)?$"
		},
	},
	{
		// ~/?$, ~/?, ~/, ~$ — optional-slash patterns are universal matchers in
		// the traditional flavor: without a `^` anchor, `/?$` matches the end of
		// every URL. Authors usually meant the root path only.
		test: regexp.MustCompile(`^~/?\??\$?$`),
		description: "This regex path is an unintentional universal matcher in `traditional` flavor. " +
			"`/?$` (and similar patterns) match the *end* of every URL because the `traditional` " +
			"router does not add a `^` start anchor. In `traditional_compatible` flavor this would " +
			"correctly match only the root path `/`. " +
			"Use the plain path `/` (no `~`) for a catch-all, or `~^/$` (anchored) to match only root.",
		suggestion: func(string) string { return "/" },
	},
	{
		// Nested quantifier such as (a+)* or (/[^/]+)+ — a classic source of
		// catastrophic backtracking (ReDoS) in PCRE. Only an outer `+` or `*` is
		// dangerous; `(?:/.*)?` (outer `?`) is safe and not flagged.
		test: regexp.MustCompile(`\([^)]*[+*?{][^)]*\)[+*]`),
		description: "Nested quantifier detected: a group containing a quantifier (`+`, `*`, `?`, `{`) is " +
			"itself followed by `+` or `*`. This is a classic ReDoS (Regular Expression Denial of " +
			"Service) pattern. On crafted input strings, PCRE can take exponential time to evaluate " +
			"this match, stalling Kong workers.",
		suggestion: func(raw string) string {
			return raw + " (simplify: remove the inner quantifier or rewrite as a flat repetition, e.g. `(/[^/]+)+` → `(/[^/]*)+`)"
		},
		severity: model.SeverityHigh,
	},
}

// EvaluateSuspiciousRegex checks raw against all known suspicious patterns in
// a single pass, returning all issues, the first suggested fix, and the overall
// severity (HIGH if any matching pattern is HIGH, else MEDIUM).
func EvaluateSuspiciousRegex(raw string) (issues []string, fix string, severity model.Severity) {
	severity = model.SeverityMedium
	if !strings.HasPrefix(raw, "~") {
		return nil, "", severity
	}
	for _, p := range suspiciousPatterns {
		if p.test.MatchString(raw) {
			issues = append(issues, p.description)
			if fix == "" && p.suggestion != nil {
				fix = p.suggestion(raw)
			}
			if p.severity == model.SeverityHigh {
				severity = model.SeverityHigh
			}
		}
	}
	return issues, fix, severity
}

// DetectSuspiciousRegexIssues returns a description for every known
// anti-pattern in a regex path. Plain paths (no `~`) are never flagged.
func DetectSuspiciousRegexIssues(raw string) []string {
	issues, _, _ := EvaluateSuspiciousRegex(raw)
	if issues == nil {
		return []string{}
	}
	return issues
}

// SuggestRegexFix returns a safer replacement for a suspicious regex path, or
// "" when no suggestion applies.
func SuggestRegexFix(raw string) string {
	_, fix, _ := EvaluateSuspiciousRegex(raw)
	return fix
}
