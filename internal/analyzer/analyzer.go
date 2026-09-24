// Package analyzer performs static risk analysis over Kong routes and
// produces human-meaningful findings. It covers:
//
//  1. Suspicious regex paths — regex paths that use `*` as if it were a glob.
//     In PCRE `*` quantifies the previous token, so `~/payments/*` means
//     "/payments followed by zero or more slashes", not "anything under
//     /payments/", and can match unintended siblings.
//  2. Shadowing / collisions — candidate requests derived from the routes'
//     own patterns are simulated to find requests matched by several routes.
//  3. Sibling namespace overlaps — route pairs whose prefixes share a stem
//     (e.g. /payments and /payments-v2), even when no candidate hit them.
//  4. Universal matchers — catch-all routes, reported as INFO.
package analyzer

import (
	"slices"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// Options configures Analyze.
type Options struct {
	// Flavor overrides the router flavor. When empty, the flavor detected from
	// the control plane is used, falling back to traditional.
	Flavor model.RouterFlavor
	// ExcludeInfo drops INFO-level findings (header/L4-stratified pairs and
	// universal catch-all annotations). Suspicious-regex, collision and
	// shadowing findings are always returned.
	ExcludeInfo bool
}

// universalProbePaths are deliberately unrelated paths: a route matching all
// of them is treated as a universal matcher (an intentional catch-all such as
// a SPA served from `/`).
var universalProbePaths = [...]string{"/api-probe-a/test", "/static-probe-b/app.js", "/zz-probe-c/deep/nested/path"}

func isUniversalMatcher(mr *router.MarshalledRoute) bool {
	for _, probe := range universalProbePaths {
		matched := false
		for i := range mr.ParsedPaths {
			if router.MatchPath(&mr.ParsedPaths[i], probe) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// Analyze runs every analysis pass and returns the findings sorted by
// severity (HIGH first; the order within a severity is stable).
func Analyze(data *model.KonnectData, opts Options) []*model.Finding {
	flavor := opts.Flavor
	if flavor == "" {
		flavor = data.RouterFlavor
	}
	if flavor == "" {
		flavor = model.FlavorTraditional
	}
	includeInfo := !opts.ExcludeInfo

	sorted := router.SortRoutes(router.MarshalRoutes(data, flavor))

	// Stamp universality once instead of once per pair in the O(n²) passes.
	for _, mr := range sorted {
		mr.IsUniversal = isUniversalMatcher(mr)
	}

	findings := lintSuspiciousRegex(sorted, flavor)
	findings = append(findings, detectCollisions(sorted, flavor, includeInfo)...)
	findings = append(findings, detectSiblingOverlaps(sorted, flavor, findings, includeInfo)...)

	// Routes already flagged as suspicious (accidental catch-alls such as
	// `~/?$`) are not reported a second time as universal matchers.
	suspicious := make(map[string]bool)
	for _, f := range findings {
		if f.Type == model.FindingSuspiciousRegex {
			for _, r := range f.Routes {
				suspicious[r.ID] = true
			}
		}
	}
	findings = append(findings, lintUniversalMatchers(sorted, flavor, suspicious, includeInfo)...)

	slices.SortStableFunc(findings, func(a, b *model.Finding) int {
		return a.Severity.Rank() - b.Severity.Rank()
	})
	return findings
}

// lintSuspiciousRegex emits suspicious_regex findings for regex paths that
// match a known anti-pattern, plus a probe-based catch for regex routes that
// turn out to be universal matchers without matching any listed pattern
// (e.g. `~.*`).
func lintSuspiciousRegex(routes []*router.MarshalledRoute, flavor model.RouterFlavor) []*model.Finding {
	findings := []*model.Finding{}
	for _, mr := range routes {
		if mr.IsUniversal && mr.HasRegexPath {
			var regexPaths []string
			alreadyCaught := false
			for i := range mr.ParsedPaths {
				if p := &mr.ParsedPaths[i]; p.Kind == router.PathRegex {
					regexPaths = append(regexPaths, p.Raw)
					if len(DetectSuspiciousRegexIssues(p.Raw)) > 0 {
						alreadyCaught = true
					}
				}
			}
			if !alreadyCaught {
				suggestions := make([]string, len(regexPaths))
				for i, p := range regexPaths {
					suggestions[i] = "~/" + strings.TrimPrefix(p, "~") + " (review intent; likely should be a plain path prefix)"
				}
				findings = append(findings, &model.Finding{
					Severity:     model.SeverityHigh,
					Type:         model.FindingSuspiciousRegex,
					RouterFlavor: flavor,
					Routes:       []*model.KongRoute{mr.Route},
					Samples:      []string{},
					Reason: []string{
						`Route "` + mr.Route.DisplayName() + `" has a regex path that matches every request URL ` +
							"in `" + string(flavor) + "` flavor – it is an accidental universal catch-all.",
						"Paths: " + strings.Join(regexPaths, ", "),
						"In `traditional` flavor the router does not add a `^` start anchor, so patterns " +
							"like `~.*` or `~/.*` match any position in the URL string, not just the start.",
						"This route will be shadowed by every more-specific route and silently handle " +
							"traffic intended for routes that are unavailable or misconfigured.",
					},
					Suggestions: suggestions,
				})
			}
		}

		for i := range mr.ParsedPaths {
			p := &mr.ParsedPaths[i]
			if p.Kind != router.PathRegex {
				continue
			}
			issues := DetectSuspiciousRegexIssues(p.Raw)
			if len(issues) == 0 {
				continue
			}
			suggestions := []string{}
			if fix := SuggestRegexFix(p.Raw); fix != "" {
				suggestions = append(suggestions, fix)
			}
			reason := make([]string, 0, len(issues)+3)
			reason = append(reason, `Path "`+p.Raw+`" uses regex syntax in a way that is likely unintentional:`)
			reason = append(reason, issues...)
			reason = append(reason,
				"Under "+string(flavor)+" flavor, this path is compiled as: "+p.RegexSource,
				"The `~` prefix means this is a PCRE regex path, not a glob pattern.")
			findings = append(findings, &model.Finding{
				Severity:     suspiciousSeverity(p.Raw),
				Type:         model.FindingSuspiciousRegex,
				RouterFlavor: flavor,
				Routes:       []*model.KongRoute{mr.Route},
				Samples:      []string{},
				Reason:       reason,
				Suggestions:  suggestions,
			})
		}
	}
	return findings
}

// lintUniversalMatchers annotates catch-all routes with INFO findings. These
// routes are excluded from collision reporting to prevent noise; this pass
// surfaces them explicitly. Routes in skip already have a suspicious_regex
// finding.
func lintUniversalMatchers(routes []*router.MarshalledRoute, flavor model.RouterFlavor, skip map[string]bool, includeInfo bool) []*model.Finding {
	findings := []*model.Finding{}
	if !includeInfo {
		return findings
	}
	for _, mr := range routes {
		if skip[mr.Route.ID] || !mr.IsUniversal {
			continue
		}
		paths := strings.Join(mr.Route.Paths, ", ")
		if paths == "" {
			paths = "(no paths)"
		}
		findings = append(findings, &model.Finding{
			Severity:     model.SeverityInfo,
			Type:         model.FindingUniversalMatcher,
			RouterFlavor: flavor,
			Routes:       []*model.KongRoute{mr.Route},
			Samples:      []string{},
			Reason: []string{
				`Route "` + mr.Route.DisplayName() + `" is a universal catch-all – it matches every request URL.`,
				"Paths: " + paths,
				"This route is intentionally excluded from collision and shadowing findings to avoid noise.",
				"Common examples: a SPA frontend served from plain prefix `/`, or a default upstream.",
				"If this catch-all is unexpected, review its path configuration.",
			},
			Suggestions: []string{},
		})
	}
	return findings
}
