// Tests for the Kong Route Analyzer (1:1 port of src/analyzer.test.ts).
//
// Tests validate –
//   - Suspicious regex pattern detection (glob-style `*` in PCRE paths)
//   - Collision detection via candidate simulation
//   - Sibling namespace overlap detection
//   - Severity classification
//   - Suggestion generation
package analyzer_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/paambaati/kongcheck/internal/analyzer"
	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// ─── Fixture helpers ─────────────────────────────────────────────────────────

func i64(v int64) *int64 { return &v }

type routeOpt func(*model.KongRoute)

func createdAt(v int64) routeOpt   { return func(r *model.KongRoute) { r.CreatedAt = i64(v) } }
func regexPriority(p int) routeOpt { return func(r *model.KongRoute) { r.RegexPriority = p } }
func service(id string) routeOpt {
	return func(r *model.KongRoute) { r.Service = &model.ServiceRef{ID: id} }
}
func headers(h model.Headers) routeOpt { return func(r *model.KongRoute) { r.Headers = h } }
func hosts(h ...string) routeOpt       { return func(r *model.KongRoute) { r.Hosts = h } }
func snis(s ...string) routeOpt        { return func(r *model.KongRoute) { r.SNIs = s } }
func protocols(p ...string) routeOpt   { return func(r *model.KongRoute) { r.Protocols = p } }
func sources(s ...model.IPPort) routeOpt {
	return func(r *model.KongRoute) { r.Sources = s }
}
func destinations(d ...model.IPPort) routeOpt {
	return func(r *model.KongRoute) { r.Destinations = d }
}

// route builds a minimal KongRoute (regex_priority 0, created_at 1_700_000_000).
func route(id, name string, paths []string, opts ...routeOpt) *model.KongRoute {
	r := &model.KongRoute{
		ID:            id,
		Name:          name,
		Paths:         paths,
		RegexPriority: 0,
		CreatedAt:     i64(1_700_000_000),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// makeConfig builds a minimal KonnectData payload for analyzer tests.
func makeConfig(routes []*model.KongRoute, flavor ...model.RouterFlavor) *model.KonnectData {
	f := model.FlavorTraditional
	if len(flavor) > 0 {
		f = flavor[0]
	}
	return &model.KonnectData{Routes: routes, Services: model.NewServiceIndex(), RouterFlavor: f}
}

// makeConfigWithServices builds a traditional-flavor KonnectData with services.
func makeConfigWithServices(routes []*model.KongRoute, services ...*model.KongService) *model.KonnectData {
	return &model.KonnectData{Routes: routes, Services: model.NewServiceIndex(services...), RouterFlavor: model.FlavorTraditional}
}

func svc(id, name string) *model.KongService { return &model.KongService{ID: id, Name: name} }

// analyzeRoutes mirrors the TS analyzeRoutes(config, options) defaults
// (includeInfo defaults to true).
func analyzeRoutes(config *model.KonnectData) []*model.Finding {
	return analyzer.Analyze(context.Background(), config, analyzer.Options{})
}

func analyzeRoutesWith(config *model.KonnectData, flavor model.RouterFlavor, includeInfo bool) []*model.Finding {
	return analyzer.Analyze(context.Background(), config, analyzer.Options{Flavor: flavor, ExcludeInfo: !includeInfo})
}

func marshalRoute(r *model.KongRoute) *router.MarshalledRoute {
	return router.MarshalRoute(r, nil, model.FlavorTraditional)
}

func filter(fs []*model.Finding, pred func(*model.Finding) bool) []*model.Finding {
	out := []*model.Finding{}
	for _, f := range fs {
		if pred(f) {
			out = append(out, f)
		}
	}
	return out
}

func find(fs []*model.Finding, pred func(*model.Finding) bool) *model.Finding {
	for _, f := range fs {
		if pred(f) {
			return f
		}
	}
	return nil
}

func every(fs []*model.Finding, pred func(*model.Finding) bool) bool {
	for _, f := range fs {
		if !pred(f) {
			return false
		}
	}
	return true
}

func some(fs []*model.Finding, pred func(*model.Finding) bool) bool {
	return find(fs, pred) != nil
}

func anyString(ss []string, pred func(string) bool) bool {
	return slices.ContainsFunc(ss, pred)
}

func allStrings(ss []string, pred func(string) bool) bool {
	for _, s := range ss {
		if !pred(s) {
			return false
		}
	}
	return true
}

func uniqueCount(ss []string) int {
	set := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		set[s] = struct{}{}
	}
	return len(set)
}

func isType(types ...model.FindingType) func(*model.Finding) bool {
	return func(f *model.Finding) bool { return slices.Contains(types, f.Type) }
}

var isOverlap = isType(model.FindingShadowing, model.FindingCollision)

func isOverlapWithSeverity(s model.Severity) func(*model.Finding) bool {
	return func(f *model.Finding) bool { return isOverlap(f) && f.Severity == s }
}

func hasSeverity(s model.Severity) func(*model.Finding) bool {
	return func(f *model.Finding) bool { return f.Severity == s }
}

func involvesRoute(id string) func(*model.Finding) bool {
	return func(f *model.Finding) bool {
		return slices.ContainsFunc(f.Routes, func(r *model.KongRoute) bool { return r.ID == id })
	}
}

func samplesLen(f *model.Finding) int {
	if f == nil {
		return 0
	}
	return len(f.Samples)
}

func suggestionsLen(f *model.Finding) int {
	if f == nil {
		return 0
	}
	return len(f.Suggestions)
}

func candidatePaths(cs []router.SimRequest) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Path
	}
	return out
}

// ─── Assertion helpers ───────────────────────────────────────────────────────

func expectGT(t *testing.T, got, bound int, msg string) {
	t.Helper()
	if !(got > bound) {
		t.Errorf("%s: got %d, want > %d", msg, got, bound)
	}
}

func expectGTE(t *testing.T, got, bound int, msg string) {
	t.Helper()
	if !(got >= bound) {
		t.Errorf("%s: got %d, want >= %d", msg, got, bound)
	}
}

func expectEq[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %#v, want %#v", msg, got, want)
	}
}

func dumpFindings(fs []*model.Finding) string {
	var b strings.Builder
	for i, f := range fs {
		ids := make([]string, len(f.Routes))
		for j, r := range f.Routes {
			ids[j] = r.ID
		}
		fmt.Fprintf(&b, "\n  [%d] %s %s routes=%v samples=%v", i, f.Severity, f.Type, ids, f.Samples)
	}
	return b.String()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestAnalyzer(t *testing.T) {
	t.Run("detectSuspiciousRegexIssues – catches glob-style * in PCRE paths", func(t *testing.T) {
		t.Run("flags ~/payments/* because trailing /* is a PCRE quantifier on '/', not a glob", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/payments/*")
			expectGT(t, len(issues), 0, "~/payments/* must be flagged: * quantifies the previous '/' char, not 'anything'")
		})

		t.Run("flags ~/payments-v2/* for the same reason", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/payments-v2/*")
			expectGT(t, len(issues), 0, "~/payments-v2/* must also be flagged – same glob-style * mistake")
		})

		t.Run("flags ~/foo/*/bar because /* in the middle also misuses *", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/foo/*/bar")
			expectGT(t, len(issues), 0, "A /* in the middle of a regex path is equally suspicious")
		})

		t.Run("flags ~/payments* because trailing * after a word char quantifies that char", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/payments*")
			expectGT(t, len(issues), 0,
				"~/payments* means '/ep' followed by zero-or-more 'p' chars, not 'anything under /payments'")
		})

		t.Run("does NOT flag ~/payments(?:/.*)?$ which is a correctly written anchored regex", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/payments(?:/.*)?$")
			expectEq(t, len(issues), 0,
				"~/payments(?:/.*)?$ is a safe, correctly anchored pattern and should not be flagged")
		})

		t.Run("does NOT flag a plain (non-regex) path /payments/*", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("/payments/*")
			expectEq(t, len(issues), 0,
				"/payments/* does not start with ~ so it is not a regex path; should not be flagged by this function")
		})

		t.Run("returns an empty array for a well-formed regex like ~/api/v[0-9]+/.*", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/api/v[0-9]+/.*")
			if len(issues) != 0 {
				t.Errorf("%s: got %q (length %d), want length 0",
					"A properly written regex path with .* (not /*) should not trigger the suspicious pattern detector",
					issues, len(issues))
			}
		})
	})

	t.Run("suggestRegexFix – generates safer replacement patterns", func(t *testing.T) {
		t.Run("suggests ~/payments(?:/.*)?$ for ~/payments/*", func(t *testing.T) {
			fix := analyzer.SuggestRegexFix("~/payments/*")
			expectEq(t, fix, "~/payments(?:/.*)?$",
				"The safe fix for ~/payments/* should anchor the pattern and use (?:/.*)? to allow sub-paths")
		})

		t.Run("suggests ~/payments-v2(?:/.*)?$ for ~/payments-v2/*", func(t *testing.T) {
			fix := analyzer.SuggestRegexFix("~/payments-v2/*")
			expectEq(t, fix, "~/payments-v2(?:/.*)?$",
				"The safe fix for ~/payments-v2/* should match the entire /payments-v2 sub-tree")
		})

		t.Run("returns undefined for a path that is not flagged", func(t *testing.T) {
			fix := analyzer.SuggestRegexFix("~/payments(?:/.*)?$")
			expectEq(t, fix, "", "No suggestion should be generated for a path that is already safe")
		})

		t.Run("returns undefined for a plain path (no ~ prefix)", func(t *testing.T) {
			fix := analyzer.SuggestRegexFix("/api")
			expectEq(t, fix, "", "Plain paths are not regex paths; no fix suggestion is applicable")
		})
	})

	t.Run("generateCandidateRequests – produces covering test paths from route patterns", func(t *testing.T) {
		t.Run("generates at least one path derived from each route's path patterns", func(t *testing.T) {
			routes := []*router.MarshalledRoute{
				marshalRoute(route("r1", "payments", []string{"~/payments/*"})),
				marshalRoute(route("r2", "payments-v2", []string{"~/payments-v2/*"})),
			}
			candidates := analyzer.GenerateCandidateRequests(routes)
			expectGTE(t, len(candidates), 2, "At least one candidate path must be generated per route")
		})

		t.Run("candidates include child paths (e.g. /payments/extra) to trigger deeper collisions", func(t *testing.T) {
			routes := []*router.MarshalledRoute{marshalRoute(route("r1", "payments", []string{"/payments"}))}
			candidates := analyzer.GenerateCandidateRequests(routes)
			paths := candidatePaths(candidates)
			if !anyString(paths, func(p string) bool { return strings.HasPrefix(p, "/payments/") }) {
				t.Errorf("%s: got paths %q, want some path starting with /payments/",
					"Candidate generation should include child paths like /payments/extra to test deeper collisions", paths)
			}
		})

		t.Run("candidates are deduplicated (no duplicate paths)", func(t *testing.T) {
			routes := []*router.MarshalledRoute{
				marshalRoute(route("r1", "a", []string{"/api"})),
				marshalRoute(route("r2", "b", []string{"/api"})),
			}
			candidates := analyzer.GenerateCandidateRequests(routes)
			paths := candidatePaths(candidates)
			expectEq(t, uniqueCount(paths), len(paths),
				"Generated candidates must be deduplicated to avoid redundant simulation")
		})
	})

	t.Run("analyzeRoutes – the motivating ~/payments/* vs ~/payments-v2/* example", func(t *testing.T) {
		config := makeConfig([]*model.KongRoute{
			route("r-payments", "payments", []string{"~/payments/*"}, regexPriority(0), createdAt(1_700_000_000)),
			route("r-payments-v2", "payments-v2", []string{"~/payments-v2/*"}, regexPriority(0), createdAt(1_710_000_000)),
		})

		t.Run("produces at least one finding for the payments / payments-v2 pair", func(t *testing.T) {
			findings := analyzeRoutes(config)
			expectGT(t, len(findings), 0,
				"The ~/payments/* vs ~/payments-v2/* pair is a textbook shadowing case and must produce findings")
		})

		t.Run("produces a suspicious_regex finding for ~/payments/* (glob-style * usage)", func(t *testing.T) {
			findings := analyzeRoutes(config)
			suspicious := filter(findings, isType(model.FindingSuspiciousRegex))
			expectGTE(t, len(suspicious), 1,
				"Both ~/payments/* and ~/payments-v2/* should be flagged as suspicious regex patterns")
		})

		t.Run("produces a shadowing or collision finding for the pair", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := filter(findings, isOverlap)
			expectGT(t, len(collision), 0, "The overlapping regex paths must produce a shadowing or collision finding")
		})

		t.Run("collision finding includes at least one sample request path", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := find(findings, isOverlap)
			expectGT(t, samplesLen(collision), 0,
				"A collision finding must include at least one sample request path to demonstrate the problem")
		})

		t.Run("collision finding includes suggestions for safer replacement patterns", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := find(findings, isOverlap)
			expectGT(t, suggestionsLen(collision), 0,
				"Each collision finding should suggest at least one safer replacement pattern")
		})

		t.Run("suggestions for ~/payments/* include an anchored alternative ending with $", func(t *testing.T) {
			findings := analyzeRoutes(config)
			var allSuggestions []string
			for _, f := range findings {
				allSuggestions = append(allSuggestions, f.Suggestions...)
			}
			if !anyString(allSuggestions, func(s string) bool { return strings.Contains(s, "$") }) {
				t.Errorf("%s: got suggestions %q, want some containing $",
					"At least one suggestion should use a $ end anchor to prevent unintentional prefix matching", allSuggestions)
			}
		})

		t.Run("findings are returned sorted with highest severity first", func(t *testing.T) {
			findings := analyzeRoutes(config)
			order := map[model.Severity]int{model.SeverityHigh: 0, model.SeverityMedium: 1, model.SeverityLow: 2, model.SeverityInfo: 3}
			rank := func(s model.Severity) int {
				if v, ok := order[s]; ok {
					return v
				}
				return 99
			}
			for i := 1; i < len(findings); i++ {
				if !(rank(findings[i-1].Severity) <= rank(findings[i].Severity)) {
					t.Errorf("Finding at index %d (%s) should be at least as severe as finding at %d (%s): got false, want true",
						i-1, findings[i-1].Severity, i, findings[i].Severity)
				}
			}
		})
	})

	t.Run("analyzeRoutes – plain prefix sibling overlap /payments vs /payments-v2", func(t *testing.T) {
		config := makeConfig([]*model.KongRoute{
			route("r1", "payments", []string{"/payments"}, createdAt(1_700_000_000)),
			route("r2", "payments-v2", []string{"/payments-v2"}, createdAt(1_710_000_000)),
		})

		t.Run("detects that /payments prefix matches /payments-v2 requests (sibling overlap)", func(t *testing.T) {
			findings := analyzeRoutes(config)
			overlap := filter(findings, isOverlap)
			expectGT(t, len(overlap), 0,
				"Plain prefix /payments matches /payments-v2 because startsWith('/payments') is true for /payments-v2")
		})
	})

	t.Run("analyzeRoutes – clean configuration produces no high-severity findings", func(t *testing.T) {
		config := makeConfig([]*model.KongRoute{
			route("r1", "payments", []string{"~/payments(?:/.*)?$"}),
			route("r2", "payments-v2", []string{"~/payments-v2(?:/.*)?$"}),
		})

		t.Run("produces no shadowing or collision findings when routes use safe anchored patterns", func(t *testing.T) {
			findings := analyzeRoutes(config)
			high := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			expectEq(t, len(high), 0,
				"Correctly anchored regex paths ~/payments(?:/.*)?$ and ~/payments-v2(?:/.*)?$ should not shadow each other")
		})
	})

	t.Run("analyzeRoutes – routes for different services are rated HIGH severity", func(t *testing.T) {
		config := makeConfig([]*model.KongRoute{
			route("r1", "payments", []string{"~/payments/*"}, service("svc-a"), createdAt(1_700_000_000)),
			route("r2", "payments-v2", []string{"~/payments-v2/*"}, service("svc-b"), createdAt(1_710_000_000)),
		})
		// Add services to the map
		configWithServices := &model.KonnectData{
			Routes:       config.Routes,
			Services:     model.NewServiceIndex(svc("svc-a", "service-a"), svc("svc-b", "service-b")),
			RouterFlavor: config.RouterFlavor,
		}

		t.Run("rates collision as HIGH when routes point to different backend services", func(t *testing.T) {
			findings := analyzeRoutes(configWithServices)
			highCollisions := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			expectGT(t, len(highCollisions), 0, "Traffic misrouting to the wrong backend service is a HIGH severity finding")
		})
	})

	t.Run("analyzeRoutes – expressions flavor emits no false positives from anchor differences", func(t *testing.T) {
		// Under expressions/traditional_compatible, regex paths get ^ anchored.
		// ~/payments-v2/* becomes ^/payments-v2/* which still matches /payments-v2/... correctly.
		config := makeConfig([]*model.KongRoute{
			route("r1", "payments", []string{"~/payments/*"}, createdAt(1_700_000_000)),
			route("r2", "payments-v2", []string{"~/payments-v2/*"}, createdAt(1_710_000_000)),
		}, model.FlavorTraditionalCompatible)

		t.Run("still produces suspicious_regex findings under traditional_compatible flavor", func(t *testing.T) {
			findings := analyzer.Analyze(context.Background(), config, analyzer.Options{Flavor: model.FlavorTraditionalCompatible})
			suspicious := filter(findings, isType(model.FindingSuspiciousRegex))
			expectGT(t, len(suspicious), 0, "Suspicious regex linting should fire regardless of router flavor")
		})
	})

	t.Run("analyzeRoutes – routes with multiple paths are split correctly", func(t *testing.T) {
		// A single KongRoute with two regex paths is internally split into two
		// MarshalledRoutes so that max_uri_length scoring works per-path.
		config := makeConfig([]*model.KongRoute{
			route("r1", "multi-path", []string{"~/payments/*", "~/payments-v2/*"}),
			route("r2", "other", []string{"/other"}, createdAt(1_710_000_000)),
		})

		t.Run("produces findings even when a route has multiple paths", func(t *testing.T) {
			findings := analyzeRoutes(config)
			expectGT(t, len(findings), 0,
				"Multi-path routes must be split before analysis – findings should still be produced")
		})

		t.Run("suspicious_regex is reported for both paths of a multi-path route", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			suspicious := filter(findings, isType(model.FindingSuspiciousRegex))
			var involvedPaths []string
			for _, f := range suspicious {
				for _, r := range f.Routes {
					involvedPaths = append(involvedPaths, r.Paths...)
				}
			}
			if !slices.Contains(involvedPaths, "~/payments/*") {
				t.Errorf("%s: got involved paths %q, want to contain ~/payments/*",
					"~/payments/* must be individually flagged even when it shares a KongRoute with ~/payments-v2/*", involvedPaths)
			}
		})
	})

	t.Run("analyzeRoutes – universal_matcher INFO findings (includeInfo: true)", func(t *testing.T) {
		// A route with ~.* matches every request URL – Kong's traditional router
		// does not add a ^ anchor, so the pattern matches at any position.
		config := makeConfig([]*model.KongRoute{
			route("r1", "catch-all", []string{"~.*"}, createdAt(1_700_000_000)),
			route("r2", "specific", []string{"/api/v1"}, createdAt(1_710_000_000)),
		})

		t.Run("produces a HIGH suspicious_regex finding for ~.* (probe-based universal matcher catch)", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			suspicious := filter(findings, isType(model.FindingSuspiciousRegex))
			expectGT(t, len(suspicious), 0,
				"~.* is not caught by pattern-list rules but must be caught by the probe-based universal matcher check")
			var first model.Severity // "" mirrors TS undefined
			if len(suspicious) > 0 {
				first = suspicious[0].Severity
			}
			expectEq(t, first, model.SeverityHigh, "An accidental universal-matcher regex should be rated HIGH, not MEDIUM")
		})

		t.Run("produces a universal_matcher INFO finding for a plain / catch-all when includeInfo=true", func(t *testing.T) {
			plainCatchAll := makeConfig([]*model.KongRoute{
				route("r1", "spa-frontend", []string{"/"}),
				route("r2", "api", []string{"/api/v1"}),
			})
			findings := analyzeRoutesWith(plainCatchAll, "", true)
			info := filter(findings, isType(model.FindingUniversalMatcher))
			expectGT(t, len(info), 0,
				"A plain / route is a universal catch-all and should produce a universal_matcher INFO finding")
		})

		t.Run("does NOT produce universal_matcher findings when includeInfo=false", func(t *testing.T) {
			plainCatchAll := makeConfig([]*model.KongRoute{
				route("r1", "spa-frontend", []string{"/"}),
				route("r2", "api", []string{"/api/v1"}),
			})
			findings := analyzeRoutesWith(plainCatchAll, "", false)
			info := filter(findings, isType(model.FindingUniversalMatcher))
			expectEq(t, len(info), 0, "INFO findings must be suppressed when includeInfo is false")
		})
	})

	t.Run("suggestRegexFix – word-char trailing * pattern (~/payments*)", func(t *testing.T) {
		t.Run("suggests an anchored alternative for ~/payments* (trailing * after word char)", func(t *testing.T) {
			fix := analyzer.SuggestRegexFix("~/payments*")
			if fix == "" {
				t.Errorf("%s: got undefined (\"\"), want defined",
					"suggestRegexFix must return a non-empty suggestion for the ~/payments* pattern")
			}
			if !strings.Contains(fix, "$") {
				t.Errorf("%s: got %q, want to contain %q",
					"Suggestion should use $ end anchor to prevent unintentional prefix matching", fix, "$")
			}
			if !strings.Contains(fix, "/payments") {
				t.Errorf("%s: got %q, want to contain %q", "Suggestion should preserve the /payments stem", fix, "/payments")
			}
		})

		t.Run("flags ~/payments* as suspicious (trailing * after word char quantifies that char)", func(t *testing.T) {
			issues := analyzer.DetectSuspiciousRegexIssues("~/payments*")
			expectGT(t, len(issues), 0,
				"~/payments* must be flagged: trailing * quantifies 'p' (zero or more p's), not anything after /payments")
		})
	})

	t.Run("analyzeRoutes – sibling overlap detected via a-paths-as-candidates branch", func(t *testing.T) {
		// When route A's path can match route B's pattern (not just the reverse),
		// findSiblingOverlapSample exercises the second candidate-generation branch.
		config := makeConfig([]*model.KongRoute{
			// r1 has a plain prefix /api that matches /api-v2 (the prefix of r2).
			route("r1", "api-base", []string{"/api"}, createdAt(1_700_000_000)),
			route("r2", "api-v2", []string{"/api-v2"}, createdAt(1_710_000_000)),
		})

		t.Run("detects that /api prefix shadows /api-v2 requests (a-as-candidate branch)", func(t *testing.T) {
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0, "/api startsWith-matches /api-v2 so it must be flagged as a sibling overlap")
		})
	})

	t.Run("analyzeRoutes – parent/child paths are NOT flagged as sibling collisions", func(t *testing.T) {
		// /chat and /chat/history are a proper parent - child hierarchy.
		// Kong's max_uri_length tie-breaker handles this correctly: /chat/history
		// is longer so it wins for /chat/history requests, and /chat wins for
		// everything else. There is no ambiguity and no false bleed.
		t.Run("does NOT flag /chat vs /chat/history as a sibling overlap", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "adk-chat", []string{"/api/v1/chat"}, createdAt(1_740_000_000)),
				route("r2", "adk-history", []string{"/api/v1/chat/history"}, createdAt(1_740_000_000)),
			})
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectEq(t, len(overlaps), 0,
				"/chat and /chat/history are a parent - child hierarchy handled correctly by max_uri_length; must not be flagged")
		})

		t.Run("does NOT flag /api vs /api/v1 as a sibling overlap", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "api-root", []string{"/api"}, createdAt(1_700_000_000)),
				route("r2", "api-v1", []string{"/api/v1"}, createdAt(1_710_000_000)),
			})
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectEq(t, len(overlaps), 0,
				"/api and /api/v1 are correctly ordered by path length; must not be flagged as a collision")
		})

		t.Run("still flags /payments vs /payments-v2 as a mid-segment bleed", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "payments", []string{"/payments"}, createdAt(1_700_000_000)),
				route("r2", "payments-v2", []string{"/payments-v2"}, createdAt(1_710_000_000)),
			})
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0,
				"/payments bleeds into /payments-v2 mid-segment (the - is not a path separator); must still be flagged")
		})
	})

	t.Run("analyzeRoutes – trailing-slash parent paths are NOT flagged as sibling collisions", func(t *testing.T) {
		// A route with path /prefix/ (trailing slash) must be recognised as a
		// hierarchical ancestor of /prefix/child routes, not a sibling bleed.
		t.Run("does NOT flag /ava-live-agent-api/ vs /ava-live-agent-api/ws", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "health", []string{"/ava-live-agent-api/"}, createdAt(1_700_000_000)),
				route("r2", "ws", []string{"/ava-live-agent-api/ws"}, createdAt(1_710_000_000)),
			})
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectEq(t, len(overlaps), 0,
				"/ava-live-agent-api/ is the trailing-slash parent of /ava-live-agent-api/ws; must not be flagged")
		})

		t.Run("still flags /ws vs /ws-simple as a mid-segment bleed even with trailing-slash fix", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "ws", []string{"/ava-live-agent-api/ws"}, createdAt(1_700_000_000)),
				route("r2", "ws-simple", []string{"/ava-live-agent-api/ws-simple"}, createdAt(1_710_000_000)),
			})
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0, "/ws bleeds into /ws-simple mid-segment; must still be flagged")
		})
	})

	t.Run("analyzeRoutes – same-route self-collision is NOT flagged", func(t *testing.T) {
		// A multi-path route is split into separate MarshalledRoutes per path.
		// If one path is a prefix of another on the same route, it must NOT be
		// reported as a collision — it's intentional within a single route config.
		t.Run("does NOT flag a route whose own paths overlap each other (same route ID)", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "multi-path", []string{"/api/v1", "/api/v1/extra"}, createdAt(1_700_000_000)),
			})
			findings := analyzeRoutes(config)
			collisions := filter(findings, isOverlap)
			expectEq(t, len(collisions), 0, "A route shadowing its own paths must not be reported as a collision")
		})
	})

	t.Run("analyzeRoutes – {variable} placeholder regex paths do not generate false positives", func(t *testing.T) {
		// Kong routes sometimes use {id}-style template placeholders in regex paths.
		// In PCRE these are literal matches for the string "{id}" — not wildcards.
		// No real request sends "{id}" unencoded, so these routes cannot shadow
		// the plain-prefix parent route and must not be flagged.
		t.Run("does NOT flag a {id}-style regex route as shadowing its plain-prefix parent", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "agents-list", []string{"/api/v1/agents"}, createdAt(1_700_000_000)),
				route("r2", "agent-by-id", []string{"~/api/v1/agents/{id}/sources"}, createdAt(1_710_000_000)),
			})
			findings := analyzeRoutes(config)
			collisions := filter(findings, isOverlap)
			expectEq(t, len(collisions), 0,
				"~/api/v1/agents/{id}/sources uses a literal {id} in PCRE; must not shadow the plain prefix route")
		})
	})

	t.Run("generateCandidateRequests – capture groups become id placeholders", func(t *testing.T) {
		t.Run(`replaces ([^/]+) capture groups with "id" to produce a valid sample path`, func(t *testing.T) {
			routes := []*router.MarshalledRoute{
				marshalRoute(route("r1", "containers", []string{"~/api/containers/([^/]+)/items/([^/]+)"})),
			}
			candidates := analyzer.GenerateCandidateRequests(routes)
			paths := candidatePaths(candidates)
			// Must not contain empty-segment artifacts like ///
			if !allStrings(paths, func(p string) bool { return !strings.Contains(p, "//") }) {
				t.Errorf("%s: got paths %q", "Candidate paths must not have consecutive slashes from empty capture groups", paths)
			}
			// Must include a path with the id placeholder
			if !anyString(paths, func(p string) bool { return strings.Contains(p, "/id/") }) {
				t.Errorf("%s: got paths %q", `Capture groups should be replaced with the "id" placeholder to produce a valid path`, paths)
			}
		})

		t.Run(`replaces {variable} template placeholders with "id"`, func(t *testing.T) {
			routes := []*router.MarshalledRoute{
				marshalRoute(route("r1", "agents", []string{"~/api/v1/agents/{agentId}/sources"})),
			}
			candidates := analyzer.GenerateCandidateRequests(routes)
			paths := candidatePaths(candidates)
			if !allStrings(paths, func(p string) bool { return !strings.Contains(p, "{") }) {
				t.Errorf("%s: got paths %q", "Candidate paths must not contain literal { from template placeholders", paths)
			}
			if !anyString(paths, func(p string) bool { return strings.Contains(p, "/id/") }) {
				t.Errorf("%s: got paths %q", `{agentId} should be replaced with "id"`, paths)
			}
		})
	})

	// ─── LOW severity classification ────────────────────────────────────────────

	t.Run("analyzeRoutes – regex_priority override within same service is LOW", func(t *testing.T) {
		// A specific route with higher regex_priority intentionally overrides a
		// same-service catch-all. This is the supported Kong override mechanism.
		configWithServices := makeConfigWithServices([]*model.KongRoute{
			route("r-specific", "delegation-sync-block", []string{"~/timesheetmanager-v2/api/delegation-form/sync$"},
				regexPriority(100), service("svc-tsm"), createdAt(1_700_000_000)),
			route("r-catchall", "api-route", []string{"~/timesheetmanager-v2/*"},
				regexPriority(0), service("svc-tsm"), createdAt(1_700_000_000)),
		}, svc("svc-tsm", "timesheetmanager-v2"))

		t.Run("classifies explicit regex_priority override as LOW, not MEDIUM", func(t *testing.T) {
			findings := analyzeRoutes(configWithServices)
			collisions := filter(findings, isOverlap)
			expectGT(t, len(collisions), 0, "Should detect the overlap")
			if !every(collisions, func(f *model.Finding) bool {
				return f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium
			}) {
				t.Errorf("%s: got false, want true; findings:%s",
					"A deliberate regex_priority override within the same service must be LOW, not HIGH or MEDIUM", dumpFindings(collisions))
			}
		})
	})

	t.Run("analyzeRoutes – specific sub-route overriding same-service catch-all is LOW", func(t *testing.T) {
		// The more-specific SSE route (created earlier) overrides the shorter same-service
		// catch-all via created_at tiebreaker (both are regex, max_uri_length=0, regex_priority=0).
		// This is an intentional routing refinement.
		configWithServices := makeConfigWithServices([]*model.KongRoute{
			route("r-sse", "sse-route", []string{"~/proposal-pal-api/v2/api/v1/proposals/~*/stream"},
				service("svc-ppa"), createdAt(1_711_000_000)),
			route("r-catchall", "api-route", []string{"~/proposal-pal-api/v2/*"},
				service("svc-ppa"), createdAt(1_711_000_001)),
		}, svc("svc-ppa", "proposal-pal-api"))

		t.Run("classifies a same-service specific-overrides-catchall collision as LOW", func(t *testing.T) {
			findings := analyzeRoutes(configWithServices)
			collisions := filter(findings, isOverlap)
			expectGT(t, len(collisions), 0, "Should detect the overlap")
			if !every(collisions, func(f *model.Finding) bool {
				return f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium
			}) {
				t.Errorf("%s: got false, want true; findings:%s",
					"A specific sub-route correctly overriding a same-service catch-all must be LOW", dumpFindings(collisions))
			}
		})
	})

	t.Run("analyzeRoutes – header-stratified identical-path pair is INFO", func(t *testing.T) {
		// Two routes targeting different services but with identical paths. The
		// winner requires a header constraint that the loser does not. Kong
		// evaluates the header constraint before selecting the route, so no
		// cross-service misrouting occurs — this is intentional traffic partitioning.
		configWithServices := makeConfigWithServices([]*model.KongRoute{
			route("r-dev", "auth-dev-users", []string{"/userinfo"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-internal", Values: []string{"dev"}}}),
				service("svc-dev"), createdAt(1_700_000_001)),
			route("r-internal", "auth-prod-users", []string{"/userinfo"},
				service("svc-internal"), createdAt(1_700_000_000)),
		}, svc("svc-dev", "auth-dev"), svc("svc-internal", "auth-internal"))

		t.Run("emits an INFO finding (not HIGH/MEDIUM/LOW) for the stratified pair", func(t *testing.T) {
			findings := analyzeRoutes(configWithServices)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0, "Should detect the overlap")
			if !every(overlaps, hasSeverity(model.SeverityInfo)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"Header-stratified identical-path pair must be INFO, not HIGH/MEDIUM/LOW", dumpFindings(overlaps))
			}
		})

		t.Run("includes explain-request suggestions naming the stratifying header", func(t *testing.T) {
			findings := analyzeRoutes(configWithServices)
			info := find(findings, isOverlapWithSeverity(model.SeverityInfo))
			if info == nil {
				t.Errorf("%s: got undefined, want defined", "INFO finding must exist")
			}
			var suggestions []string
			if info != nil {
				suggestions = info.Suggestions
			}
			if info == nil || !anyString(suggestions, func(s string) bool {
				return strings.Contains(s, "explain-request") && strings.Contains(s, "x-internal")
			}) {
				t.Errorf("%s: got suggestions %q, want true",
					"Must include an explain-request command carrying the stratifying header", suggestions)
			}
			if info == nil || !anyString(suggestions, func(s string) bool {
				return strings.Contains(s, "explain-request") && !strings.Contains(s, "--header")
			}) {
				t.Errorf("%s: got suggestions %q, want true",
					"Must include a header-free explain-request command for the unconstrained route", suggestions)
			}
		})
	})

	t.Run("analyzeRoutes – identical-path collision suggestions are deduplicated", func(t *testing.T) {
		// When both routes share the same path expression, the regex fix is
		// identical for both. The suggestion list must not contain duplicates and
		// must include a note about route differentiation.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r1", "summarizer-agent-internal", []string{"~/legal-agent-mesh/summarizer-agent/*"},
				service("svc-a"), createdAt(1_700_000_000)),
			route("r2", "legal-agent-mesh-summarizer-agent-internal", []string{"~/legal-agent-mesh/summarizer-agent/*"},
				service("svc-b"), createdAt(1_700_003_600)),
		}, svc("svc-a", "summarizer-agent"), svc("svc-b", "legal-agent-mesh-summarizer"))

		t.Run("does not emit the same regex fix twice for identical-path routes", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := find(findings, isOverlap)
			if collision == nil {
				t.Errorf("%s: got undefined, want defined", "Should detect a collision")
			}
			var regexFixes []string
			if collision != nil {
				for _, s := range collision.Suggestions {
					if strings.HasPrefix(s, "~") {
						regexFixes = append(regexFixes, s)
					}
				}
			}
			expectEq(t, uniqueCount(regexFixes), len(regexFixes), "Duplicate regex fixes must be deduplicated")
		})

		t.Run("appends a route-differentiation note when paths are identical", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := find(findings, isOverlap)
			var suggestions []string
			if collision != nil {
				suggestions = collision.Suggestions
			}
			if collision == nil || !anyString(suggestions, func(s string) bool {
				l := strings.ToLower(s)
				return strings.Contains(l, "delete") || strings.Contains(l, "differentiate")
			}) {
				t.Errorf("%s: got suggestions %q (finding present: %v), want true",
					"Identical-path collision must suggest deleting or differentiating the shadowed route", suggestions, collision != nil)
			}
		})
	})

	// ─── detectSuspiciousRegexIssues – root-path universal-matcher patterns ──────

	t.Run("detectSuspiciousRegexIssues – root-path universal-matcher patterns", func(t *testing.T) {
		// The regex ~/ matches the end of every URL because the traditional router
		// adds no ^ anchor, making it a universal catch-all.
		t.Run("flags ~/ (bare tilde-slash) as suspicious", func(t *testing.T) {
			expectGT(t, len(analyzer.DetectSuspiciousRegexIssues("~/")), 0, "~/ is a universal matcher and must be flagged")
		})

		t.Run("flags ~/?$ (optional-slash with end anchor) as suspicious", func(t *testing.T) {
			expectGT(t, len(analyzer.DetectSuspiciousRegexIssues("~/?$")), 0,
				"~/?$ matches the end of every URL in traditional flavor — must be flagged")
		})

		t.Run("flags ~$ (just end-anchor) as suspicious", func(t *testing.T) {
			expectGT(t, len(analyzer.DetectSuspiciousRegexIssues("~$")), 0,
				"~$ matches the end of every URL in traditional flavor — must be flagged")
		})
	})

	// ─── suggestRegexFix – universal-matcher patterns ────────────────────────────

	t.Run("suggestRegexFix – universal-matcher patterns suggest the plain root path", func(t *testing.T) {
		t.Run("returns / for ~/", func(t *testing.T) {
			expectEq(t, analyzer.SuggestRegexFix("~/"), "/",
				"The safe replacement for a universal-matcher path is the plain prefix /")
		})

		t.Run("returns / for ~/?$", func(t *testing.T) {
			expectEq(t, analyzer.SuggestRegexFix("~/?$"), "/", "The safe replacement for ~/?$ is the plain prefix /")
		})
	})

	// ─── MEDIUM severity ─────────────────────────────────────────────────────────

	t.Run("analyzeRoutes – ambiguous same-service overlap is MEDIUM", func(t *testing.T) {
		// Two routes on the same service with identical paths, no regex_priority
		// difference and no path-length difference. There is no priority signal
		// (no intentional override), so the finding is MEDIUM.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r1", "auth-login", []string{"/login"}, service("svc-auth"), createdAt(1_700_000_000)),
			route("r2", "auth-login-v2", []string{"/login"}, service("svc-auth"), createdAt(1_700_000_001)),
		}, svc("svc-auth", "auth-service"))

		t.Run("produces at least one collision or shadowing finding", func(t *testing.T) {
			findings := analyzeRoutes(config)
			expectGT(t, len(filter(findings, isOverlap)), 0,
				"expected findings.filter(shadowing || collision).length to be greater than 0")
		})

		t.Run("classifies same-service identical-path overlap with no priority signal as MEDIUM", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collisions := filter(findings, isOverlap)
			if !every(collisions, hasSeverity(model.SeverityMedium)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"Identical-path same-service routes with no regex_priority or path-length difference must be MEDIUM",
					dumpFindings(collisions))
			}
		})
	})

	// ─── isHeaderStratified – value-level paths ──────────────────────────────────

	t.Run("analyzeRoutes – header stratification: disjoint values on same header name", func(t *testing.T) {
		// Winner: x-env:[prod]  Loser: x-env:[dev, staging]
		// The value sets are disjoint — no request can satisfy both constraints simultaneously.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-prod", "prod-api", []string{"/api/users"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"prod"}}}),
				service("svc-prod"), createdAt(1_700_000_001)),
			route("r-non-prod", "non-prod-api", []string{"/api/users"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev", "staging"}}}),
				service("svc-non-prod"), createdAt(1_700_000_000)),
		}, svc("svc-prod", "prod-api"), svc("svc-non-prod", "non-prod-api"))

		t.Run("treats routes with disjoint header values as stratified (INFO, not HIGH)", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0, "Pair must be detected")
			if !every(overlaps, hasSeverity(model.SeverityInfo)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"Routes whose header values are fully disjoint partition traffic with no overlap — must be INFO",
					dumpFindings(overlaps))
			}
		})
	})

	t.Run("analyzeRoutes – header stratification: overlapping values on same header name", func(t *testing.T) {
		// Winner: x-env:[prod, staging]  Loser: x-env:[staging, dev]
		// "staging" appears in both — a request with x-env:staging matches both routes.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-a", "service-a-users", []string{"/users"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"prod", "staging"}}}),
				service("svc-a"), createdAt(1_700_000_001)),
			route("r-b", "service-b-users", []string{"/users"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"staging", "dev"}}}),
				service("svc-b"), createdAt(1_700_000_000)),
		}, svc("svc-a", "service-a"), svc("svc-b", "service-b"))

		t.Run("treats overlapping header values as a real collision (HIGH, not INFO)", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			collisions := filter(findings, isOverlap)
			expectGT(t, len(collisions), 0, "Pair must be detected")
			if !some(collisions, hasSeverity(model.SeverityHigh)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"Overlapping header values mean a request with x-env:staging reaches both routes — must be HIGH",
					dumpFindings(collisions))
			}
		})
	})

	// ─── includeInfo: false behaviour ────────────────────────────────────────────

	t.Run("analyzeRoutes – includeInfo: false does not suppress MEDIUM or HIGH findings", func(t *testing.T) {
		t.Run("returns suspicious_regex MEDIUM findings even when includeInfo is false", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{route("r1", "bad-regex", []string{"~/api/*"})})
			findings := analyzeRoutesWith(config, "", false)
			expectGT(t, len(filter(findings, isType(model.FindingSuspiciousRegex))), 0,
				"MEDIUM suspicious_regex findings must not be suppressed by includeInfo: false")
		})

		t.Run("returns HIGH collision findings when includeInfo is false", func(t *testing.T) {
			config := makeConfigWithServices([]*model.KongRoute{
				route("r1", "broad-regex", []string{"~/api/([^/]+)"}, service("svc-a"), createdAt(1_700_000_000)),
				route("r2", "specific-path", []string{"/marketing/api/profile"}, service("svc-b"), createdAt(1_700_000_001)),
			}, svc("svc-a", "service-a"), svc("svc-b", "service-b"))
			findings := analyzeRoutesWith(config, "", false)
			if !some(findings, hasSeverity(model.SeverityHigh)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"HIGH collision findings must not be suppressed by includeInfo: false", dumpFindings(findings))
			}
		})

		t.Run("suppresses INFO header-stratified findings when includeInfo is false", func(t *testing.T) {
			config := makeConfigWithServices([]*model.KongRoute{
				route("r-dev", "dev-userinfo", []string{"/userinfo"},
					headers(model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev"}}}),
					service("svc-dev"), createdAt(1_700_000_001)),
				route("r-prod", "prod-userinfo", []string{"/userinfo"},
					service("svc-prod"), createdAt(1_700_000_000)),
			}, svc("svc-dev", "dev"), svc("svc-prod", "prod"))
			findings := analyzeRoutesWith(config, "", false)
			expectEq(t, len(filter(findings, hasSeverity(model.SeverityInfo))), 0,
				"INFO findings must be suppressed when includeInfo is false")
		})

		t.Run("suppresses universal_matcher INFO findings when includeInfo is false", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "spa", []string{"/"}),
				route("r2", "api", []string{"/api/v1"}),
			})
			findings := analyzeRoutesWith(config, "", false)
			expectEq(t, len(filter(findings, isType(model.FindingUniversalMatcher))), 0,
				"universal_matcher INFO findings must be suppressed when includeInfo is false")
		})
	})

	// ─── lintUniversalMatchers skip-ids ──────────────────────────────────────────

	t.Run("analyzeRoutes – universal_matcher INFO is not emitted for routes already flagged by suspicious_regex", func(t *testing.T) {
		// ~/?$ is caught by the suspicious_regex pattern list (emits MEDIUM).
		// It is also a universal matcher. lintUniversalMatchers must skip it so the
		// route does not appear in two separate findings.
		t.Run("does not produce a universal_matcher INFO finding for a route that already has a suspicious_regex finding", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r1", "root-catchall", []string{"~/?$"}, createdAt(1_700_000_000)),
				route("r2", "specific", []string{"/api/v1"}, createdAt(1_710_000_000)),
			})
			findings := analyzeRoutesWith(config, "", true)
			r1Findings := filter(findings, involvesRoute("r1"))
			expectEq(t, len(filter(r1Findings, isType(model.FindingUniversalMatcher))), 0,
				"A route with a suspicious_regex finding must not also receive a universal_matcher INFO finding")
		})
	})

	// ─── detectCollisions – sample accumulation ──────────────────────────────────

	t.Run("detectCollisions – same route pair accumulates samples across multiple candidate paths", func(t *testing.T) {
		// ~/users/([^/]+) and ~/users/([a-z]+) both match /users/id, /users/id/,
		// /users/id/extra, etc. The first match creates the finding; subsequent
		// matches for the same pair must add to samples[] rather than creating
		// duplicate findings.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-wide", "svc-a-users", []string{"~/users/([^/]+)"}, service("svc-a"), createdAt(1_700_000_000)),
			route("r-narrow", "svc-b-users", []string{"~/users/([a-z]+)"}, service("svc-b"), createdAt(1_700_000_001)),
		}, svc("svc-a", "service-a"), svc("svc-b", "service-b"))

		isWideOverlap := func(f *model.Finding) bool { return isOverlap(f) && involvesRoute("r-wide")(f) }

		t.Run("produces exactly one finding for the pair (no duplicates)", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collisions := filter(findings, isWideOverlap)
			if len(collisions) != 1 {
				t.Errorf("%s: got %d, want 1; findings:%s",
					"The same route pair must produce exactly one finding regardless of how many candidates match",
					len(collisions), dumpFindings(collisions))
			}
		})

		t.Run("accumulates more than one sample path in the finding", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := find(findings, isWideOverlap)
			if collision == nil {
				t.Errorf("%s: got undefined, want defined", "Finding must exist")
			}
			if !(samplesLen(collision) > 1) {
				t.Errorf("%s: got samples length %d, want > 1",
					"A broadly matching pair should accumulate multiple sample paths in a single finding", samplesLen(collision))
			}
		})

		t.Run("does not duplicate sample paths within the same finding", func(t *testing.T) {
			findings := analyzeRoutes(config)
			collision := find(findings, isWideOverlap)
			var samples []string
			if collision != nil {
				samples = collision.Samples
			}
			expectEq(t, uniqueCount(samples), len(samples), "Sample paths within a finding must be deduplicated")
		})
	})

	// ─── isShadowing – finding type ──────────────────────────────────────────────

	t.Run("analyzeRoutes – finding type reflects the winner/loser path relationship", func(t *testing.T) {
		t.Run("emits collision type (not shadowing) when identical plain-prefix routes serve different services", func(t *testing.T) {
			// Plain-prefix winner has no regex paths → isShadowing returns false → type = 'collision'.
			config := makeConfigWithServices([]*model.KongRoute{
				route("r1", "login-auth", []string{"/login"}, service("svc-a"), createdAt(1_700_000_000)),
				route("r2", "login-identity", []string{"/login"}, service("svc-b"), createdAt(1_700_000_001)),
			}, svc("svc-a", "auth"), svc("svc-b", "identity"))
			findings := analyzeRoutes(config)
			// No header stratification (neither route has headers), different services → HIGH collision.
			collisionType := filter(findings, isType(model.FindingCollision))
			expectGT(t, len(collisionType), 0,
				"Plain-prefix winner has no regex — isShadowing must return false, emitting collision not shadowing")
		})

		t.Run("emits shadowing type when winner regex subsumes the loser plain path", func(t *testing.T) {
			// ~/users/([^/]+) matches /users/profile literally, so isShadowing returns true.
			config := makeConfigWithServices([]*model.KongRoute{
				route("r-regex", "regex-route", []string{"~/users/([^/]+)"}, service("svc-a"), createdAt(1_700_000_000)),
				route("r-plain", "plain-route", []string{"/users/profile"}, service("svc-b"), createdAt(1_700_000_001)),
			}, svc("svc-a", "service-a"), svc("svc-b", "service-b"))
			findings := analyzeRoutes(config)
			shadowingType := filter(findings, isType(model.FindingShadowing))
			expectGT(t, len(shadowingType), 0,
				"Winner regex matches the loser plain path — isShadowing must return true, emitting shadowing not collision")
		})
	})

	t.Run("analyzeRoutes – ~* regex header values produce MEDIUM (not HIGH) findings", func(t *testing.T) {
		// When header constraints use ~* regex values, static analysis cannot determine
		// whether the patterns are disjoint. The finding is downgraded from HIGH to MEDIUM
		// with a note indicating manual verification is required.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-canary", "canary-api", []string{"/api/v1"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-version", Values: []string{"~*^v[0-9]+$"}}}), // regex: any vN value
				service("svc-canary"), createdAt(1_700_000_001)),
			route("r-stable", "stable-api", []string{"/api/v1"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-version", Values: []string{"~*^stable.*"}}}), // regex: anything starting with "stable"
				service("svc-stable"), createdAt(1_700_000_000)),
		}, svc("svc-canary", "canary"), svc("svc-stable", "stable"))

		t.Run("produces a finding for the pair (not silently suppressed)", func(t *testing.T) {
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0, "Route pair with ~* header values must still produce a finding")
		})

		t.Run("finding is MEDIUM (not HIGH or INFO), reflecting analysis uncertainty", func(t *testing.T) {
			findings := analyzeRoutes(config)
			overlaps := filter(findings, isOverlap)
			if !every(overlaps, hasSeverity(model.SeverityMedium)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"~* regex header values → MEDIUM severity (cannot statically determine disjointness)", dumpFindings(overlaps))
			}
		})

		t.Run("reason chain mentions ~* regex header analysis limitation", func(t *testing.T) {
			findings := analyzeRoutes(config)
			f := find(findings, isOverlap)
			allReason := ""
			if f != nil {
				allReason = strings.Join(f.Reason, " ")
			}
			if !(strings.Contains(allReason, "~*") || strings.Contains(strings.ToLower(allReason), "regex")) {
				t.Errorf("%s: got reason %q, want true", "Reason must mention the ~* regex header analysis limitation", allReason)
			}
		})
	})

	t.Run("analyzeRoutes – plain header value + ~* header value: plain wins if disjoint", func(t *testing.T) {
		// When the winner has a plain header value and the loser has none (or vice versa),
		// it is still stratified — the ~* opaque logic should not override a definitively
		// stratified dimension.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-prod", "prod-route", []string{"/api"},
				headers(model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"prod"}}}), // plain value
				service("svc-prod"), createdAt(1_700_000_001)),
			route("r-default", "default-route", []string{"/api"},
				// No headers — handles all requests without x-env header.
				service("svc-default"), createdAt(1_700_000_000)),
		}, svc("svc-prod", "prod"), svc("svc-default", "default"))

		t.Run("emits INFO (stratified), not MEDIUM, when winner has a plain header and loser has none", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			overlaps := filter(findings, isOverlap)
			expectGT(t, len(overlaps), 0, "Pair must be detected")
			if !every(overlaps, hasSeverity(model.SeverityInfo)) {
				t.Errorf("%s: got false, want true; findings:%s",
					"Winner has plain header constraint, loser has none → stratified → INFO", dumpFindings(overlaps))
			}
		})
	})

	t.Run("analyzeRoutes – plain-host vs wildcard-host correctly ordered (not a collision)", func(t *testing.T) {
		// payments.internal.example.com → svc-payments (plain host)
		// *.internal.example.com        → svc-catchall  (wildcard host)
		// Both have the same path. In Kong, the plain-host route deterministically wins
		// (PLAIN_HOSTS_ONLY bit). kongcheck must not report this as a HIGH collision.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-plain", "payments", []string{"/v1/payments"},
				hosts("payments.internal.example.com"), service("svc-payments"), createdAt(1_700_000_000)),
			route("r-wildcard", "catchall", []string{"/v1/payments"},
				hosts("*.internal.example.com"), service("svc-catchall"), createdAt(1_700_000_001)),
		}, svc("svc-payments", "payments"), svc("svc-catchall", "catchall"))

		t.Run("does NOT produce a HIGH finding for plain-host vs wildcard-host on same path", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			highCollisions := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			if len(highCollisions) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"Plain-host beats wildcard-host deterministically via PLAIN_HOSTS_ONLY — must not be HIGH",
					len(highCollisions), dumpFindings(highCollisions))
			}
		})

		t.Run("the plain-host route wins the simulation for a matching request", func(t *testing.T) {
			services := config.Services
			r1, r2 := config.Routes[0], config.Routes[1]
			m1 := router.MarshalRoute(r1, services.Get("svc-payments"), model.FlavorTraditional)
			m2 := router.MarshalRoute(r2, services.Get("svc-catchall"), model.FlavorTraditional)
			sorted := []*router.MarshalledRoute{m1, m2}
			slices.SortStableFunc(sorted, router.CompareRoutes)
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "payments.internal.example.com",
				Path:   "/v1/payments",
			})
			winnerID := "" // "" mirrors TS undefined
			if result.Winner != nil {
				winnerID = result.Winner.Route.ID
			}
			expectEq(t, winnerID, "r-plain", "The plain-host route must win")
		})
	})

	// ─── Gap #1 deep coverage – wildcard-with-port vs plain-host ─────────────────

	t.Run("analyzeRoutes – wildcard-with-port vs wildcard-without-port is correctly ordered (not HIGH) (Gap #1)", func(t *testing.T) {
		// *.internal.example.com:8443  → svc-tls  (wildcard host with explicit port)
		// *.internal.example.com       → svc-http  (wildcard host, no port)
		// Both have the same path. In Kong, HAS_WILDCARD_HOST_PORT (bit 2 = 0x04) makes the ported
		// route win deterministically. kongcheck must not report this as a HIGH collision.
		config := makeConfigWithServices([]*model.KongRoute{
			route("r-ported", "tls-catchall", []string{"/v1/api"},
				hosts("*.internal.example.com:8443"), service("svc-tls"), createdAt(1_700_000_001)),
			route("r-unported", "http-catchall", []string{"/v1/api"},
				hosts("*.internal.example.com"), service("svc-http"), createdAt(1_700_000_000)),
		}, svc("svc-tls", "tls-backend"), svc("svc-http", "http-backend"))

		t.Run("does NOT produce a HIGH finding for wildcard-with-port vs wildcard-without-port on same path", func(t *testing.T) {
			findings := analyzeRoutesWith(config, "", true)
			highCollisions := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			if len(highCollisions) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"Wildcard-with-port beats wildcard-without-port deterministically via HAS_WILDCARD_HOST_PORT — must not be HIGH",
					len(highCollisions), dumpFindings(highCollisions))
			}
		})

		t.Run("the wildcard-with-port route wins the simulation for a ported request", func(t *testing.T) {
			services := config.Services
			r1, r2 := config.Routes[0], config.Routes[1]
			m1 := router.MarshalRoute(r1, services.Get("svc-tls"), model.FlavorTraditional)
			m2 := router.MarshalRoute(r2, services.Get("svc-http"), model.FlavorTraditional)
			sorted := []*router.MarshalledRoute{m1, m2}
			slices.SortStableFunc(sorted, router.CompareRoutes)
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "api.internal.example.com:8443",
				Path:   "/v1/api",
			})
			winnerID := "" // "" mirrors TS undefined
			if result.Winner != nil {
				winnerID = result.Winner.Route.ID
			}
			expectEq(t, winnerID, "r-ported",
				"The wildcard-with-port route (HAS_WILDCARD_HOST_PORT) must win for a ported request")
		})
	})

	// ─────────────────────────────────────────────────────────────────────────────
	// SNI / source IP / destination IP / protocol-family stratification
	// Kong source: traditional.lua#L1072-L1085, #L880-L900
	// ─────────────────────────────────────────────────────────────────────────────

	isHighOrMediumOverlap := func(f *model.Finding) bool {
		return isOverlap(f) && (f.Severity == model.SeverityHigh || f.Severity == model.SeverityMedium)
	}
	isInfoCollision := func(f *model.Finding) bool {
		return f.Type == model.FindingCollision && f.Severity == model.SeverityInfo
	}

	t.Run("analyzeRoutes – SNI stratification (INFO, not HIGH/MEDIUM)", func(t *testing.T) {
		t.Run("emits INFO (not HIGH) when two routes share paths but have fully disjoint SNI sets", func(t *testing.T) {
			// Two stream routes targeting different services, same path, but non-overlapping SNIs.
			// Kong routes each TLS connection to the correct route by SNI → no misrouting.
			config := makeConfig([]*model.KongRoute{
				route("r-sni-a", "sni-route-a", []string{"/stream"}, service("svc-a"), snis("a.example.com")),
				route("r-sni-b", "sni-route-b", []string{"/stream"}, service("svc-b"), snis("b.example.com")),
			})

			findings := analyzeRoutesWith(config, "", true)
			highOrMedium := filter(findings, isHighOrMediumOverlap)
			if len(highOrMedium) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"Disjoint SNI sets fully stratify traffic – must produce zero HIGH or MEDIUM collision findings",
					len(highOrMedium), dumpFindings(highOrMedium))
			}

			infoFindings := filter(findings, isInfoCollision)
			expectGT(t, len(infoFindings), 0,
				"Disjoint SNI sets must produce an INFO finding so operators can confirm the stratification is intentional")
		})

		t.Run("does NOT emit an INFO finding when includeInfo is false", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-sni-a", "sni-route-a", []string{"/stream"}, service("svc-a"), snis("a.example.com")),
				route("r-sni-b", "sni-route-b", []string{"/stream"}, service("svc-b"), snis("b.example.com")),
			})

			findings := analyzeRoutesWith(config, "", false)
			anyFinding := filter(findings, isOverlap)
			if len(anyFinding) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"When includeInfo=false no collision/stratification findings must be emitted",
					len(anyFinding), dumpFindings(anyFinding))
			}
		})

		t.Run("still emits a HIGH finding when SNI sets overlap (shared SNI value)", func(t *testing.T) {
			// Both routes accept 'shared.example.com' → Kong cannot differentiate them on SNI alone.
			config := makeConfig([]*model.KongRoute{
				route("r-sni-x", "sni-route-x", []string{"/stream"}, service("svc-x"), snis("shared.example.com", "x.example.com")),
				route("r-sni-y", "sni-route-y", []string{"/stream"}, service("svc-y"), snis("shared.example.com", "y.example.com")),
			})

			findings := analyzeRoutesWith(config, "", true)
			highFindings := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			expectGT(t, len(highFindings), 0,
				"Overlapping SNI sets mean a connection to shared.example.com is ambiguous – must emit HIGH")
		})

		t.Run(`handles FQDN trailing-dot normalisation: snis ["api.example.com."] and ["api.example.com"] are the SAME SNI`, func(t *testing.T) {
			// Kong strips trailing dots in marshall_route. If route A has "api.example.com." and
			// route B has "api.example.com", they resolve to the same SNI → NOT stratified.
			config := makeConfig([]*model.KongRoute{
				route("r-dot", "route-fqdn-dot", []string{"/stream"}, service("svc-dot"), snis("api.example.com.")),
				route("r-nodot", "route-no-dot", []string{"/stream"}, service("svc-nodot"), snis("api.example.com")),
			})

			findings := analyzeRoutesWith(config, "", true)
			// After normalisation both SNIs are "api.example.com" → overlap → must NOT be INFO-stratified.
			infoStratified := filter(findings, func(f *model.Finding) bool {
				return f.Severity == model.SeverityInfo && f.Type == model.FindingCollision && involvesRoute("r-dot")(f)
			})
			if len(infoStratified) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"After trailing-dot normalisation the SNIs are identical → not stratified → must produce no INFO stratification",
					len(infoStratified), dumpFindings(infoStratified))
			}
		})
	})

	t.Run("analyzeRoutes – source IP/port stratification (INFO, not HIGH/MEDIUM)", func(t *testing.T) {
		t.Run("emits INFO when two routes have non-overlapping source CIDR constraints", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-src-a", "src-route-a", []string{"/tcp"}, service("svc-a"), sources(model.IPPort{IP: "10.0.0.0/24"})),
				route("r-src-b", "src-route-b", []string{"/tcp"}, service("svc-b"), sources(model.IPPort{IP: "10.0.1.0/24"})),
			})

			findings := analyzeRoutesWith(config, "", true)
			highOrMedium := filter(findings, isHighOrMediumOverlap)
			if len(highOrMedium) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"Non-overlapping source CIDRs (10.0.0.x vs 10.0.1.x) fully stratify traffic → zero HIGH/MEDIUM",
					len(highOrMedium), dumpFindings(highOrMedium))
			}

			infoFindings := filter(findings, isInfoCollision)
			expectGT(t, len(infoFindings), 0, "Non-overlapping source CIDRs must produce an INFO stratification finding")
		})

		t.Run("emits HIGH when source CIDRs overlap (supernet/subnet)", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-src-broad", "src-broad", []string{"/tcp"}, service("svc-broad"),
					sources(model.IPPort{IP: "10.0.0.0/8"})), // broader range
				route("r-src-narrow", "src-narrow", []string{"/tcp"}, service("svc-narrow"),
					sources(model.IPPort{IP: "10.1.0.0/16"})), // inside broad range
			})

			findings := analyzeRoutesWith(config, "", true)
			highFindings := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			expectGT(t, len(highFindings), 0,
				"10.1.0.0/16 is inside 10.0.0.0/8 → source ranges overlap → must emit HIGH collision")
		})

		t.Run("emits INFO when source port constraints are disjoint", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-port-80", "route-port-80", []string{"/tcp"}, service("svc-80"), sources(model.IPPort{Port: 80})),
				route("r-port-443", "route-port-443", []string{"/tcp"}, service("svc-443"), sources(model.IPPort{Port: 443})),
			})

			findings := analyzeRoutesWith(config, "", true)
			highOrMedium := filter(findings, isHighOrMediumOverlap)
			if len(highOrMedium) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"Disjoint source ports (80 vs 443) fully stratify traffic → zero HIGH/MEDIUM",
					len(highOrMedium), dumpFindings(highOrMedium))
			}
		})
	})

	t.Run("analyzeRoutes – destination IP/port stratification (INFO, not HIGH/MEDIUM)", func(t *testing.T) {
		t.Run("emits INFO when destination IP constraints are non-overlapping", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-dst-a", "dst-route-a", []string{"/tcp"}, service("svc-a"), destinations(model.IPPort{IP: "192.168.0.0/24"})),
				route("r-dst-b", "dst-route-b", []string{"/tcp"}, service("svc-b"), destinations(model.IPPort{IP: "192.168.1.0/24"})),
			})

			findings := analyzeRoutesWith(config, "", true)
			highOrMedium := filter(findings, isHighOrMediumOverlap)
			if len(highOrMedium) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"Non-overlapping destination CIDRs fully stratify traffic → zero HIGH/MEDIUM",
					len(highOrMedium), dumpFindings(highOrMedium))
			}

			infoFindings := filter(findings, isInfoCollision)
			expectGT(t, len(infoFindings), 0, "Non-overlapping destination CIDRs must produce an INFO stratification finding")
		})
	})

	t.Run("analyzeRoutes – protocol-family stratification (INFO, not HIGH/MEDIUM)", func(t *testing.T) {
		t.Run("emits INFO when one route is all-HTTP and the other is all-stream", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-http", "http-route", []string{"/api"}, service("svc-http"), protocols("http", "https")),
				route("r-tcp", "tcp-route", []string{"/api"}, service("svc-tcp"), protocols("tcp", "tls")),
			})

			findings := analyzeRoutesWith(config, "", true)
			highOrMedium := filter(findings, isHighOrMediumOverlap)
			if len(highOrMedium) != 0 {
				t.Errorf("%s: got %d, want 0; findings:%s",
					"HTTP protocols (http/https) and stream protocols (tcp/tls) are mutually exclusive → zero HIGH/MEDIUM",
					len(highOrMedium), dumpFindings(highOrMedium))
			}

			infoFindings := filter(findings, isInfoCollision)
			expectGT(t, len(infoFindings), 0, "Disjoint protocol families must produce an INFO stratification finding")
		})

		t.Run("emits HIGH when both routes have overlapping protocol sets (both http+https)", func(t *testing.T) {
			config := makeConfig([]*model.KongRoute{
				route("r-http-a", "http-a", []string{"/api"}, service("svc-a"), protocols("http", "https")),
				route("r-http-b", "http-b", []string{"/api"}, service("svc-b"), protocols("http", "https")),
			})

			findings := analyzeRoutesWith(config, "", true)
			highFindings := filter(findings, isOverlapWithSeverity(model.SeverityHigh))
			expectGT(t, len(highFindings), 0,
				"Identical protocol sets on same-path, different-service routes must emit HIGH")
		})
	})

	t.Run("analyzeRoutes – L4 stratification is not triggered when only one route has the constraint", func(t *testing.T) {
		t.Run("emits HIGH (not INFO) when only one route has snis and the other has none", func(t *testing.T) {
			// Route B has no snis → it acts as a wildcard (matches all SNIs).
			// Route A has specific snis. They can both match a connection for A's SNIs.
			config := makeConfig([]*model.KongRoute{
				route("r-sni", "constrained", []string{"/stream"}, service("svc-sni"), snis("api.example.com")),
				route("r-open", "open", []string{"/stream"}, service("svc-open")),
				// no snis → matches all SNIs
			})

			findings := analyzeRoutesWith(config, "", true)
			// The open route (no SNI constraint) can receive the same connection as the constrained route.
			// This is a real collision risk, not stratification.
			collisionFindings := filter(findings, isOverlap)
			expectGT(t, len(collisionFindings), 0,
				"When one route has no SNI constraint it acts as a wildcard → real collision risk → must produce a finding")

			infoOnly := every(collisionFindings, hasSeverity(model.SeverityInfo))
			expectEq(t, infoOnly, false,
				"At least one finding must be HIGH or MEDIUM since the unconstrained route can intercept all SNIs")
		})
	})

	t.Run("analyzeRoutes – respects context cancellation", func(t *testing.T) {
		config := makeConfig([]*model.KongRoute{
			route("r1", "p1", []string{"/payments"}),
			route("r2", "p2", []string{"/payments/status"}),
		}, model.FlavorTraditional)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel
		findings := analyzer.Analyze(ctx, config, analyzer.Options{})
		if len(findings) != 0 {
			t.Errorf("expected 0 findings on pre-cancelled context, got %d", len(findings))
		}
	})
}
