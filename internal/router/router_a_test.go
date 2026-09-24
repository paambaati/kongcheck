package router_test

import (
	"strings"
	"testing"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// jsSourceA renders a regex source the way JavaScript's RegExp.prototype.source
// serialises it (EscapeRegExpPattern): unescaped '/' outside character classes
// and line terminators are escaped. The TS tests assert on that serialised
// form, so the Go port applies the same serialisation to Pattern.Source().
func jsSourceA(src string) string {
	var b strings.Builder
	inClass := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\\' && i+1 < len(src):
			b.WriteByte(c)
			i++
			b.WriteByte(src[i])
			continue
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			b.WriteString(`\/`)
			continue
		case c == '\n':
			b.WriteString(`\n`)
			continue
		case c == '\r':
			b.WriteString(`\r`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// winnerNameA mirrors `result.winner?.route.name` (undefined when no winner).
func winnerNameA(res *router.SimResult) string {
	if res.Winner == nil {
		return "<undefined>"
	}
	return res.Winner.Route.Name
}

// winnerIDA mirrors `result.winner?.route.id` (undefined when no winner).
func winnerIDA(res *router.SimResult) string {
	if res.Winner == nil {
		return "<undefined>"
	}
	return res.Winner.Route.ID
}

func TestRouterA(t *testing.T) {
	t.Run("isRegexPath", func(t *testing.T) {
		t.Run("returns true for paths beginning with ~ (Kong regex path marker)", func(t *testing.T) {
			if got := router.IsRegexPath("~/payments/*"); got != true {
				t.Errorf("~/payments/* starts with ~ so Kong treats it as a PCRE regex path: got %v, want true", got)
			}
		})

		t.Run("returns false for plain prefix paths that have no ~ prefix", func(t *testing.T) {
			if got := router.IsRegexPath("/api/v1"); got != false {
				t.Errorf("/api/v1 is a plain prefix path; Kong matches it with startsWith semantics: got %v, want false", got)
			}
		})

		t.Run("returns false for an empty string", func(t *testing.T) {
			if got := router.IsRegexPath(""); got != false {
				t.Errorf("An empty string is not a regex path: got %v, want false", got)
			}
		})
	})

	t.Run("stripRegexPrefix", func(t *testing.T) {
		t.Run("removes the leading ~ to produce the bare PCRE pattern string", func(t *testing.T) {
			got, err := router.StripRegexPrefix("~/payments/*")
			if err != nil {
				t.Fatalf("Kong strips the ~ before compiling the PCRE: ~/payments/* → /payments/*: unexpected error %v", err)
			}
			if got != "/payments/*" {
				t.Errorf("Kong strips the ~ before compiling the PCRE: ~/payments/* → /payments/*: got %q, want %q", got, "/payments/*")
			}
		})

		t.Run("throws when called on a non-regex path (missing ~)", func(t *testing.T) {
			_, err := router.StripRegexPrefix("/plain")
			if err == nil {
				t.Fatalf("Calling stripRegexPrefix on a plain path is a programming error: got nil error, want error matching /regex path/")
			}
			if !strings.Contains(err.Error(), "regex path") {
				t.Errorf("Calling stripRegexPrefix on a plain path is a programming error: got error %q, want it to match /regex path/", err.Error())
			}
		})
	})

	t.Run("classifyPath – traditional flavor (no start anchor)", func(t *testing.T) {
		t.Run("classifies a ~ path as kind='regex' with regexSource stripped of ~", func(t *testing.T) {
			p := router.ClassifyPath("~/payments/*", model.FlavorTraditional)
			if p.Kind != router.PathRegex {
				t.Errorf("~/payments/* is a regex path in Kong's traditional router: got %q, want %q", p.Kind, router.PathRegex)
			}
			if p.RegexSource != "/payments/*" {
				t.Errorf("The regex source should be the raw path minus the leading ~: got %q, want %q", p.RegexSource, "/payments/*")
			}
		})

		t.Run("does NOT add a ^ start anchor for traditional flavor", func(t *testing.T) {
			p := router.ClassifyPath("~/payments/*", model.FlavorTraditional)
			if p.Regex == nil {
				t.Fatalf("Traditional flavor: Kong does not anchor regex paths at the start by default: regex is nil (undefined), want a compiled regex")
			}
			if got := strings.HasPrefix(p.Regex.Source(), "^"); got != false {
				t.Errorf("Traditional flavor: Kong does not anchor regex paths at the start by default: startsWith('^') got %v, want false (source %q)", got, p.Regex.Source())
			}
			// JS serialises the regex source with escape sequences; verify the escaped form.
			if got := jsSourceA(p.Regex.Source()); got != "\\/payments\\/*" {
				t.Errorf("The regex source for ~/payments/* in traditional flavor should be the bare PCRE pattern: got %q (raw %q), want %q", got, p.Regex.Source(), "\\/payments\\/*")
			}
		})

		t.Run("classifies a plain path as kind='prefix'", func(t *testing.T) {
			p := router.ClassifyPath("/api/v1", model.FlavorTraditional)
			if p.Kind != router.PathPrefix {
				t.Errorf("/api/v1 is a plain prefix path: got %q, want %q", p.Kind, router.PathPrefix)
			}
			if p.Prefix != "/api/v1" {
				t.Errorf("The prefix field should hold the full plain path: got %q, want %q", p.Prefix, "/api/v1")
			}
		})
	})

	t.Run("classifyPath – traditional_compatible flavor (^ start anchor)", func(t *testing.T) {
		t.Run("adds a ^ start anchor to regex paths under traditional_compatible", func(t *testing.T) {
			p := router.ClassifyPath("~/payments/*", model.FlavorTraditionalCompatible)
			if p.Regex == nil {
				t.Fatalf("Kong's transform.lua prefixes regex paths with ^ in traditional_compatible flavor: regex is nil (undefined), want a compiled regex")
			}
			if got := strings.HasPrefix(p.Regex.Source(), "^"); got != true {
				t.Errorf("Kong's transform.lua prefixes regex paths with ^ in traditional_compatible flavor: startsWith('^') got %v, want true (source %q)", got, p.Regex.Source())
			}
			if got := jsSourceA(p.Regex.Source()); got != "^\\/payments\\/*" {
				t.Errorf("The regex source for ~/payments/* in traditional_compatible should start with ^ (JS-escaped): got %q (raw %q), want %q", got, p.Regex.Source(), "^\\/payments\\/*")
			}
		})

		t.Run("plain paths are unchanged by the flavor parameter", func(t *testing.T) {
			p := router.ClassifyPath("/api/v1", model.FlavorTraditionalCompatible)
			if p.Kind != router.PathPrefix {
				t.Errorf("flavor does not affect plain prefix paths – they remain kind='prefix': got %q, want %q", p.Kind, router.PathPrefix)
			}
			if p.Prefix != "/api/v1" {
				t.Errorf("the prefix field should still hold the unmodified plain path: got %q, want %q", p.Prefix, "/api/v1")
			}
		})
	})

	t.Run("matchPath – regex paths", func(t *testing.T) {
		t.Run("~/payments/* matches /payments/ (traditional: no end anchor → prefix-like)", func(t *testing.T) {
			p := router.ClassifyPath("~/payments/*", model.FlavorTraditional)
			if got := router.MatchPath(&p, "/payments/"); got != true {
				t.Errorf("Without an end anchor Kong regex routes behave like prefix matches: got %v, want true", got)
			}
		})

		t.Run("~/payments/* matches /payments-v2/docs – the motivating shadowing example", func(t *testing.T) {
			p := router.ClassifyPath("~/payments/*", model.FlavorTraditional)
			// /payments/* → regex /payments/* → `/payments` followed by 0+ slashes.
			// The regex matches /payments at the start of /payments-v2/docs.
			if got := router.MatchPath(&p, "/payments-v2/docs"); got != true {
				t.Errorf("This is the core of the problem: ~/payments/* (regex /payments/*) matches /payments-v2/docs "+
					"because * in PCRE quantifies the previous char '/', not 'anything': got %v, want true", got)
			}
		})

		t.Run("~/payments(?:/.*)?$ does NOT match /payments-v2/docs (safe anchored alternative)", func(t *testing.T) {
			p := router.ClassifyPath("~/payments(?:/.*)?$", model.FlavorTraditional)
			if got := router.MatchPath(&p, "/payments-v2/docs"); got != false {
				t.Errorf("The anchored safe alternative ~/payments(?:/.*)?$ must not match /payments-v2/docs: got %v, want false", got)
			}
		})

		t.Run("~/payments(?:/.*)?$ matches /payments/something (correct match)", func(t *testing.T) {
			p := router.ClassifyPath("~/payments(?:/.*)?$", model.FlavorTraditional)
			if got := router.MatchPath(&p, "/payments/something"); got != true {
				t.Errorf("matchPath(~/payments(?:/.*)?$, /payments/something): got %v, want true", got)
			}
		})

		t.Run("~/payments-v2(?:/.*)?$ matches /payments-v2/docs and not /payments/docs", func(t *testing.T) {
			p := router.ClassifyPath("~/payments-v2(?:/.*)?$", model.FlavorTraditional)
			if got := router.MatchPath(&p, "/payments-v2/docs"); got != true {
				t.Errorf("The payments-v2 safe alternative should match its own path: got %v, want true", got)
			}
			if got := router.MatchPath(&p, "/payments/docs"); got != false {
				t.Errorf("The payments-v2 safe alternative must not match an unrelated /payments path: got %v, want false", got)
			}
		})
	})

	t.Run("matchPath – plain prefix paths", func(t *testing.T) {
		t.Run("/api/v1 prefix matches /api/v1/users", func(t *testing.T) {
			p := router.ClassifyPath("/api/v1", model.FlavorTraditional)
			if got := router.MatchPath(&p, "/api/v1/users"); got != true {
				t.Errorf("Prefix /api/v1 matches any path starting with it: got %v, want true", got)
			}
		})

		t.Run("/api/v1 prefix DOES match /api/v10/users (Kong uses byte-level startsWith, not token boundaries)", func(t *testing.T) {
			p := router.ClassifyPath("/api/v1", model.FlavorTraditional)
			// Kong's traditional router plain-prefix matching uses startsWith at the byte level.
			// /api/v1 is a byte-level prefix of /api/v10, so it matches. This is a known Kong gotcha –
			// if you need token-level isolation, use a regex path like ~/api/v1(?:/.*)?$
			if got := router.MatchPath(&p, "/api/v10/users"); got != true {
				t.Errorf("/api/v1 matches /api/v10/users via startsWith – use ~/api/v1(?:/.*)?$ for token isolation: got %v, want true", got)
			}
		})

		t.Run("exact path /health matches /health exactly", func(t *testing.T) {
			p := router.ClassifyPath("/health", model.FlavorTraditional)
			if got := router.MatchPath(&p, "/health"); got != true {
				t.Errorf("matchPath(/health, /health): got %v, want true", got)
			}
		})
	})

	t.Run("compareRoutes – Kong sort_routes tie-breaking (traditional.lua ~L681-L709)", func(t *testing.T) {
		t.Run("regex route has higher priority than a plain prefix route (HAS_REGEX_URI submatch weight)", func(t *testing.T) {
			regexRoute := makeRoute(model.KongRoute{ID: "r1", Paths: []string{"~/api/.*"}})
			plainRoute := makeRoute(model.KongRoute{ID: "r2", Paths: []string{"/api"}})

			if got := router.CompareRoutes(regexRoute, plainRoute); !(got < 0) {
				t.Errorf("Kong: regex routes beat plain-prefix routes due to submatch_weight: got %d, want < 0", got)
			}
		})

		t.Run("between two regex routes, higher regex_priority wins", func(t *testing.T) {
			highPri := makeRoute(model.KongRoute{
				ID:            "r1",
				Paths:         []string{"~/api/.*"},
				RegexPriority: 10,
			})
			lowPri := makeRoute(model.KongRoute{
				ID:            "r2",
				Paths:         []string{"~/api/v1/.*"},
				RegexPriority: 0,
			})

			if got := router.CompareRoutes(highPri, lowPri); !(got < 0) {
				t.Errorf("Kong: higher regex_priority wins when both routes are regex type: got %d, want < 0", got)
			}
		})

		t.Run("between equal-priority regex routes, max_uri_length is 0 for both so created_at decides", func(t *testing.T) {
			older := makeRoute(model.KongRoute{ID: "r1", Paths: []string{"~/api/v1/users"}, RegexPriority: 0, CreatedAt: ptr[int64](1000)})
			newer := makeRoute(model.KongRoute{ID: "r2", Paths: []string{"~/api"}, RegexPriority: 0, CreatedAt: ptr[int64](2000)})

			if got := router.CompareRoutes(older, newer); !(got < 0) {
				t.Errorf("Kong: regex paths do not contribute to max_uri_length → both are 0 → older wins by created_at: got %d, want < 0", got)
			}
		})

		t.Run("between equal-length equal-priority regex routes, earlier created_at wins", func(t *testing.T) {
			older := makeRoute(model.KongRoute{
				ID:            "r1",
				Paths:         []string{"~/payments/*"},
				RegexPriority: 0,
				CreatedAt:     ptr[int64](1000),
			})
			newer := makeRoute(model.KongRoute{
				ID:            "r2",
				Paths:         []string{"~/payments/*"},
				RegexPriority: 0,
				CreatedAt:     ptr[int64](2000),
			})

			if got := router.CompareRoutes(older, newer); !(got < 0) {
				t.Errorf("Kong: earlier created_at wins when all other criteria are equal – older route shadow newer one: got %d, want < 0", got)
			}
		})

		t.Run("two identical routes compare as equal (return 0)", func(t *testing.T) {
			a := makeRoute(model.KongRoute{ID: "r1", Paths: []string{"~/api/.*"}, RegexPriority: 0, CreatedAt: ptr[int64](1000)})
			b := makeRoute(model.KongRoute{ID: "r2", Paths: []string{"~/api/.*"}, RegexPriority: 0, CreatedAt: ptr[int64](1000)})
			if got := router.CompareRoutes(a, b); got != 0 {
				t.Errorf("Fully identical routes (by ordering criteria) should compare as equal: got %d, want 0", got)
			}
		})

		t.Run("created_at is NOT compared when one route has nil created_at (Kong: only compares when both are non-nil)", func(t *testing.T) {
			// Kong L706: "if r1.route.created_at ~= nil and r2.route.created_at ~= nil"
			// When one route is missing created_at, the created_at tier is skipped entirely.
			withCreated := makeRoute(model.KongRoute{ID: "r-older", Paths: []string{"/api"}, CreatedAt: ptr[int64](1000)})
			withoutCreated := makeRoute(model.KongRoute{ID: "r-missing", Paths: []string{"/api"}}) // no created_at
			if got := router.CompareRoutes(withCreated, withoutCreated); got != 0 {
				t.Errorf("When route B has no created_at, the created_at tier must be skipped — routes are equal by all compared criteria: got %d, want 0", got)
			}
		})

		t.Run("created_at is NOT compared when both routes have nil created_at", func(t *testing.T) {
			a := makeRoute(model.KongRoute{ID: "r-a", Paths: []string{"/api"}}) // no created_at
			b := makeRoute(model.KongRoute{ID: "r-b", Paths: []string{"/api"}}) // no created_at
			if got := router.CompareRoutes(a, b); got != 0 {
				t.Errorf("When both routes lack created_at, the sort falls through all tiers and returns 0: got %d, want 0", got)
			}
		})

		t.Run("~/payments/* ties ~/payments-v2/* on max_uri_length (both regex → both 0), falls to created_at", func(t *testing.T) {
			// Both are regex paths → Kong sets max_uri_length = 0 for both.
			// So length does NOT break the tie; created_at decides.
			payments := makeRoute(model.KongRoute{ID: "r1", Paths: []string{"~/payments/*"}, RegexPriority: 0, CreatedAt: ptr[int64](1000)})
			paymentsV2 := makeRoute(model.KongRoute{
				ID:            "r2",
				Paths:         []string{"~/payments-v2/*"},
				RegexPriority: 0,
				CreatedAt:     ptr[int64](1000),
			})

			if got := router.CompareRoutes(paymentsV2, payments); got != 0 {
				t.Errorf("regex paths have max_uri_length=0, so both routes tie on all criteria including created_at (both 1000): got %d, want 0", got)
			}
		})

		t.Run("~/payments/* beats ~/payments-v2/* when ~/payments/* was created earlier (same length-adjusted priority)", func(t *testing.T) {
			// Same regex_priority, same length → falls through to created_at.
			payments := makeRoute(model.KongRoute{ID: "r1", Paths: []string{"~/payments/*"}, RegexPriority: 0, CreatedAt: ptr[int64](1000)})
			paymentsV2SameLen := makeRoute(model.KongRoute{
				ID:            "r2",
				Paths:         []string{"~/payments/*"}, // same length to force created_at tie-break
				RegexPriority: 0,
				CreatedAt:     ptr[int64](2000),
			})

			if got := router.CompareRoutes(payments, paymentsV2SameLen); !(got < 0) {
				t.Errorf("When all other criteria are equal, the route created earlier (smaller created_at) wins: got %d, want < 0", got)
			}
		})
	})

	t.Run("matchRoute – method and host filtering", func(t *testing.T) {
		t.Run("route with methods constraint does not match a different method", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Methods: []string{"POST"}})
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api"}
			if got := router.MatchRoute(mr, &req); got != false {
				t.Errorf("A route constrained to POST must not match a GET request: got %v, want false", got)
			}
		})

		t.Run("route with no methods constraint matches any method", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			req := router.SimRequest{Method: "DELETE", Host: "example.com", Path: "/api"}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("A route with no methods constraint should match any HTTP method: got %v, want true", got)
			}
		})

		t.Run("route with host constraint does not match a different host", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"api.example.com"}})
			req := router.SimRequest{Method: "GET", Host: "other.example.com", Path: "/api"}
			if got := router.MatchRoute(mr, &req); got != false {
				t.Errorf("A route constrained to api.example.com must not match other.example.com: got %v, want false", got)
			}
		})

		t.Run("route with wildcard host *.example.com matches sub.example.com", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			req := router.SimRequest{Method: "GET", Host: "sub.example.com", Path: "/api"}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("A wildcard host *.example.com should match any subdomain: got %v, want true", got)
			}
		})
	})

	t.Run("matchRoute – route with no path constraints matches any URI (Kong: MATCH_RULES.URI bit absent)", func(t *testing.T) {
		t.Run("route with empty paths array matches any request path", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{}})
			req1 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/any/random/path"}
			if got := router.MatchRoute(mr, &req1); got != true {
				t.Errorf("A route with no path constraints (empty paths array) must match any URI: got %v, want true", got)
			}
			req2 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/completely/different"}
			if got := router.MatchRoute(mr, &req2); got != true {
				t.Errorf("Empty paths route should still match another different URI: got %v, want true", got)
			}
			req3 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/"}
			if got := router.MatchRoute(mr, &req3); got != true {
				t.Errorf("Empty paths route must match the root path as well: got %v, want true", got)
			}
		})

		t.Run("route with no paths property at all (undefined) matches any request path", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{}})
			req := router.SimRequest{Method: "POST", Host: "any-host.com", Path: "/some/deeply/nested/path"}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("A route with no path constraints must match regardless of path depth: got %v, want true", got)
			}
		})

		t.Run("route with explicit path only matches requests beginning with that prefix", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			req1 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api/v1/users"}
			if got := router.MatchRoute(mr, &req1); got != true {
				t.Errorf("A route with a path constraint must match a request whose URI starts with that prefix: got %v, want true", got)
			}
			req2 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/other"}
			if got := router.MatchRoute(mr, &req2); got != false {
				t.Errorf("A route with a path constraint must not match a request with a different URI prefix: got %v, want false", got)
			}
		})

		t.Run("route with empty paths beats route with non-empty paths in sort_routes when no path is a deciding factor", func(t *testing.T) {
			// Both routes have identical ordering criteria except one has empty paths.
			// Empty-paths routes have maxUriLength = 0 and no hasRegexPath, so they tie
			// on all tiers with a route that also has no regex/hosts/headers.
			emptyPaths := makeRoute(model.KongRoute{ID: "r-empty", Paths: []string{}, CreatedAt: ptr[int64](1000)})
			withPath := makeRoute(model.KongRoute{ID: "r-path", Paths: []string{"/api"}, CreatedAt: ptr[int64](2000)})
			// maxUriLength: empty=0, /api=4 → /api wins on tier 4 (longer wins)
			if got := router.CompareRoutes(withPath, emptyPaths); !(got < 0) {
				t.Errorf("A prefix route with /api (maxUriLength=4) beats an empty-paths route (maxUriLength=0) on max_uri_length: got %d, want < 0", got)
			}
		})
	})

	t.Run("simulateRequest – the motivating ~/payments/* vs ~/payments-v2/* example", func(t *testing.T) {
		paymentsRoute := makeRoute(model.KongRoute{
			ID:            "route-payments",
			Name:          "payments",
			Paths:         []string{"~/payments/*"},
			RegexPriority: 0,
			CreatedAt:     ptr[int64](1736500800), // earlier
		})

		paymentsV2Route := makeRoute(model.KongRoute{
			ID:            "route-payments-v2",
			Name:          "payments-v2",
			Paths:         []string{"~/payments-v2/*"},
			RegexPriority: 0,
			CreatedAt:     ptr[int64](1738742400), // later
		})

		sorted := router.SortRoutes([]*router.MarshalledRoute{paymentsV2Route, paymentsRoute})

		t.Run("both routes match /payments-v2/docs (demonstrates the shadowing problem)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "example.com",
				Path:   "/payments-v2/docs",
			})
			if got := len(result.MatchedRoutes); !(got >= 2) {
				t.Errorf("Both ~/payments/* and ~/payments-v2/* must match /payments-v2/docs for the shadowing to occur: got %d, want >= 2", got)
			}
		})

		t.Run("~/payments/* (earlier created_at) wins over ~/payments-v2/* for /payments-v2/docs (both regex, same regex_priority)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "example.com",
				Path:   "/payments-v2/docs",
			})
			if got := winnerNameA(result); got != "payments" {
				t.Errorf("regex paths have max_uri_length=0 in Kong, so the older (earlier created_at) route wins: got %q, want %q", got, "payments")
			}
		})

		t.Run("~/payments/* still wins for /payments/something (correct routing)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "example.com",
				Path:   "/payments/something",
			})
			if got := winnerNameA(result); got != "payments" {
				t.Errorf("~/payments/* should win for its own path /payments/something: got %q, want %q", got, "payments")
			}
		})

		t.Run("the explanation mentions the winning route (payments, because it was created earlier)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "example.com",
				Path:   "/payments-v2/docs",
			})
			fullExplanation := strings.Join(result.Explanation(), "\n")
			if !strings.Contains(fullExplanation, "payments") {
				t.Errorf("The explanation should mention the route name that wins: got %q, want it to contain %q", fullExplanation, "payments")
			}
		})

		t.Run("when ~/payments/* is older, it wins for a path matching only ~/payments/* (no collision for /payments/x)", func(t *testing.T) {
			// /payments/x only matches ~/payments/*, not ~/payments-v2/*
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "example.com",
				Path:   "/payments/x",
			})
			if got := len(result.MatchedRoutes); got != 1 {
				t.Errorf("Only ~/payments/* should match /payments/x: got %d, want 1", got)
			}
			if got := winnerNameA(result); got != "payments" {
				t.Errorf("/payments/x only matches ~/payments/*, so that route must be the winner: got %q, want %q", got, "payments")
			}
		})
	})

	t.Run("simulateRequest – no match", func(t *testing.T) {
		t.Run("returns undefined winner and a descriptive explanation when nothing matches", func(t *testing.T) {
			route := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			result := router.SimulateRequest([]*router.MarshalledRoute{route}, router.SimRequest{
				Method: "GET",
				Host:   "example.com",
				Path:   "/completely-different",
			})
			if result.Winner != nil {
				t.Errorf("No route should match an unrelated path: got winner %q, want nil (undefined)", result.Winner.Route.ID)
			}
			explanation := result.Explanation()
			if len(explanation) == 0 {
				t.Fatalf("The explanation should describe the unmatched request: got empty explanation, want explanation[0] containing %q", "No route matched")
			}
			if !strings.Contains(explanation[0], "No route matched") {
				t.Errorf("The explanation should describe the unmatched request: got %q, want it to contain %q", explanation[0], "No route matched")
			}
		})
	})

	t.Run("sanitizeUriPostfix – matches Kong utils.lua sanitize_uri_postfix", func(t *testing.T) {
		t.Run("returns an empty string for '.' (current dir reference)", func(t *testing.T) {
			if got := router.SanitizeURIPostfix("."); got != "" {
				t.Errorf("Kong sanitises '.' to empty string: got %q, want %q", got, "")
			}
		})

		t.Run("returns an empty string for '..' (parent dir reference)", func(t *testing.T) {
			if got := router.SanitizeURIPostfix(".."); got != "" {
				t.Errorf("Kong sanitises '..' to empty string: got %q, want %q", got, "")
			}
		})

		t.Run("strips leading ./ from the postfix", func(t *testing.T) {
			if got := router.SanitizeURIPostfix("./secret"); got != "secret" {
				t.Errorf("Kong strips './' prefix from URI postfix to prevent path traversal: got %q, want %q", got, "secret")
			}
		})

		t.Run("strips leading ../ from the postfix", func(t *testing.T) {
			if got := router.SanitizeURIPostfix("../secret"); got != "secret" {
				t.Errorf("Kong strips '../' prefix from URI postfix: got %q, want %q", got, "secret")
			}
		})

		t.Run("leaves a normal postfix unchanged", func(t *testing.T) {
			if got := router.SanitizeURIPostfix("docs/intro"); got != "docs/intro" {
				t.Errorf("A normal postfix is returned as-is: got %q, want %q", got, "docs/intro")
			}
		})
	})

	t.Run("computeUpstreamUri – strip_path does NOT affect winner selection", func(t *testing.T) {
		t.Run("strip_path=true: strips the matched prefix from the upstream URI", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, StripPath: ptr(true)})
			upstream := router.ComputeUpstreamURI(mr, "/api/users", "/api", "/")
			if upstream != "/users" {
				t.Errorf("With strip_path=true, /api prefix is stripped and /users is forwarded: got %q, want %q", upstream, "/users")
			}
		})

		t.Run("strip_path=false: full original path is forwarded to upstream", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, StripPath: ptr(false)})
			upstream := router.ComputeUpstreamURI(mr, "/api/users", "/api", "/")
			if upstream != "/api/users" {
				t.Errorf("With strip_path=false, the full path /api/users is forwarded: got %q, want %q", upstream, "/api/users")
			}
		})

		t.Run("strip_path=true with upstream base '/backend/': correctly joins paths", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, StripPath: ptr(true)})
			upstream := router.ComputeUpstreamURI(mr, "/api/v1/users", "/api", "/backend/")
			if upstream != "/backend/v1/users" {
				t.Errorf("Upstream base /backend/ + stripped postfix /v1/users = /backend/v1/users: got %q, want %q", upstream, "/backend/v1/users")
			}
		})
	})

	t.Run("marshalRoute – derived fields", func(t *testing.T) {
		t.Run("sets hasRegexPath=true when any path starts with ~", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/plain", "~/regex/.*"}})
			if mr.HasRegexPath != true {
				t.Errorf("hasRegexPath should be true if even one path is a regex path: got %v, want true", mr.HasRegexPath)
			}
		})

		t.Run("sets hasRegexPath=false when all paths are plain prefix", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api", "/health"}})
			if mr.HasRegexPath != false {
				t.Errorf("hasRegexPath should be false when no path starts with ~: got %v, want false", mr.HasRegexPath)
			}
		})

		t.Run("maxUriLength is 0 for regex-only paths (Kong: max_uri_length only counts non-regex paths)", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"~/short", "~/a/longer/pattern"}})
			if mr.MaxURILength != 0 {
				t.Errorf("maxUriLength must be 0 when all paths are regex: got %d, want 0", mr.MaxURILength)
			}
		})

		t.Run("parsedPaths contains one entry per path in route.paths", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/a", "/b", "~/c/.*"}})
			if got := len(mr.ParsedPaths); got != 3 {
				t.Errorf("parsedPaths should have one entry per path in route.paths: got %d, want 3", got)
			}
		})

		t.Run("headerCount excludes the host header (Kong filters \"host\" when building headers_t)", func(t *testing.T) {
			route := model.KongRoute{
				ID:    "r-filter-host",
				Paths: []string{"/api"},
				Headers: model.Headers{
					model.HeaderConstraint{Name: "host", Values: []string{"api.example.com"}},
					model.HeaderConstraint{Name: "x-env", Values: []string{"prod"}},
					model.HeaderConstraint{Name: "x-tenant", Values: []string{"acme"}},
				},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			if mr.HeaderCount != 2 {
				t.Errorf("headerCount must not count the \"host\" header — only x-env and x-tenant should count (2 distinct headers): got %d, want 2", mr.HeaderCount)
			}
		})

		t.Run("headerCount is 0 when the only header is \"host\"", func(t *testing.T) {
			route := model.KongRoute{
				ID:      "r-only-host",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "host", Values: []string{"api.example.com"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			if mr.HeaderCount != 0 {
				t.Errorf("headerCount must be 0 when the only header constraint is \"host\" — Kong excludes host from headers_t: got %d, want 0", mr.HeaderCount)
			}
		})

		t.Run("headerCount is 0 when there are no header constraints", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			if mr.HeaderCount != 0 {
				t.Errorf("headerCount must be 0 for routes with no headers constraint: got %d, want 0", mr.HeaderCount)
			}
		})
	})

	t.Run("matchRoute – header constraints (traditional.lua MATCH_RULES.HEADER ~L966–L1011)", func(t *testing.T) {
		t.Run("route with no headers constraint matches a request with no headers (undefined)", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api"}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("A route without header constraints must match regardless of request headers: got %v, want true", got)
			}
		})

		t.Run("route with header constraint does NOT match when request.headers is {} (header absent)", func(t *testing.T) {
			route := model.KongRoute{
				ID:      "r-header",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev", "develop", "development"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{}}
			if got := router.MatchRoute(mr, &req); got != false {
				t.Errorf("When request has no headers and route requires x-env, the route must not match: got %v, want false", got)
			}
		})

		t.Run("route with header constraint matches when request includes the required header value (exact, case-insensitive)", func(t *testing.T) {
			route := model.KongRoute{
				ID:      "r-header",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev", "develop", "development"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-env": "dev"}}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("request header x-env=dev matches allowed value \"dev\": got %v, want true", got)
			}
		})

		t.Run("header value comparison is case-insensitive (Kong lowercases both sides)", func(t *testing.T) {
			route := model.KongRoute{
				ID:      "r-header",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-env": "DEV"}}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("header value matching is case-insensitive: \"DEV\" must match allowed value \"dev\": got %v, want true", got)
			}
		})

		t.Run("header name lookup is case-insensitive", func(t *testing.T) {
			route := model.KongRoute{
				ID:      "r-header",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "X-Custom-Header", Values: []string{"expected"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			// request headers passed in lowercase (as HTTP/2 mandates)
			req := router.SimRequest{
				Method:  "GET",
				Host:    "example.com",
				Path:    "/api",
				Headers: map[string]string{"x-custom-header": "expected"},
			}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("header name lookup must be case-insensitive: got %v, want true", got)
			}
		})

		t.Run("route with multiple header constraints requires ALL of them (AND semantics)", func(t *testing.T) {
			route := model.KongRoute{
				ID:    "r-multi-header",
				Paths: []string{"/api"},
				Headers: model.Headers{
					model.HeaderConstraint{Name: "x-tenant", Values: []string{"acme"}},
					model.HeaderConstraint{Name: "x-role", Values: []string{"admin"}},
				},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			// Only one header present → should not match
			req := router.SimRequest{
				Method:  "GET",
				Host:    "example.com",
				Path:    "/api",
				Headers: map[string]string{"x-tenant": "acme"},
			}
			if got := router.MatchRoute(mr, &req); got != false {
				t.Errorf("All header constraints must be satisfied; missing x-role means no match: got %v, want false", got)
			}
		})

		t.Run("route with multiple header constraints matches when ALL are present", func(t *testing.T) {
			route := model.KongRoute{
				ID:    "r-multi-header",
				Paths: []string{"/api"},
				Headers: model.Headers{
					model.HeaderConstraint{Name: "x-tenant", Values: []string{"acme"}},
					model.HeaderConstraint{Name: "x-role", Values: []string{"admin"}},
				},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req := router.SimRequest{
				Method:  "GET",
				Host:    "example.com",
				Path:    "/api",
				Headers: map[string]string{"x-tenant": "acme", "x-role": "admin"},
			}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("All header constraints satisfied → route must match: got %v, want true", got)
			}
		})

		t.Run("multiple allowed values for a header use OR semantics (any value satisfies the constraint)", func(t *testing.T) {
			route := model.KongRoute{
				ID:      "r-multi-value",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev", "develop", "development"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req1 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-env": "develop"}}
			if got := router.MatchRoute(mr, &req1); got != true {
				t.Errorf("\"develop\" is one of the allowed values for x-env → should match: got %v, want true", got)
			}
			req2 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-env": "staging"}}
			if got := router.MatchRoute(mr, &req2); got != false {
				t.Errorf("\"staging\" is not in the allowed values list → should not match: got %v, want false", got)
			}
		})

		t.Run("header constraint with ~* prefix uses regex matching (Kong header_pattern)", func(t *testing.T) {
			// Kong only sets header_pattern when there is exactly ONE value starting with ~*
			route := model.KongRoute{
				ID:      "r-regex-header",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-version", Values: []string{"~*^v[0-9]+$"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req1 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-version": "v3"}}
			if got := router.MatchRoute(mr, &req1); got != true {
				t.Errorf("x-version=v3 matches regex ^v[0-9]+$: got %v, want true", got)
			}
			req2 := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-version": "beta"}}
			if got := router.MatchRoute(mr, &req2); got != false {
				t.Errorf("x-version=beta does not match regex ^v[0-9]+$: got %v, want false", got)
			}
		})

		t.Run("when request.headers is undefined, header constraints are skipped (static analysis mode)", func(t *testing.T) {
			// In static analysis (analyzer), SimRequest.headers is always undefined.
			// Header-constrained routes must still be treated as potential candidates.
			route := model.KongRoute{
				ID:      "r-header",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev"}}},
			}
			mr := router.MarshalRoute(&route, nil, model.FlavorTraditional)
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api"}
			if got := router.MatchRoute(mr, &req); got != true {
				t.Errorf("When request.headers is undefined the header constraint is ignored (static analysis mode): got %v, want true", got)
			}
		})
	})

	t.Run("compareRoutes – header count sort tier (sort_routes L686–L688)", func(t *testing.T) {
		t.Run("route with more header constraints beats one with fewer at same submatch_weight", func(t *testing.T) {
			twoHeaders := model.KongRoute{
				ID:    "r-two",
				Paths: []string{"~/users/(.+)"},
				Headers: model.Headers{
					model.HeaderConstraint{Name: "x-tenant", Values: []string{"acme"}},
					model.HeaderConstraint{Name: "x-role", Values: []string{"admin"}},
				},
			}
			oneHeader := model.KongRoute{
				ID:      "r-one",
				Paths:   []string{"~/users/(.+)"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-tenant", Values: []string{"acme"}}},
			}
			mrTwo := router.MarshalRoute(&twoHeaders, nil, model.FlavorTraditional)
			mrOne := router.MarshalRoute(&oneHeader, nil, model.FlavorTraditional)

			if got := router.CompareRoutes(mrTwo, mrOne); !(got < 0) {
				t.Errorf("Route with 2 header constraints must beat route with 1 (Kong: headers[0] count): got %d, want < 0", got)
			}
		})

		t.Run("route with header constraints beats route with no headers (same path)", func(t *testing.T) {
			withHeader := model.KongRoute{
				ID:      "r-with",
				Paths:   []string{"~/users/(.+)"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev", "develop", "development"}}},
			}
			noHeader := model.KongRoute{ID: "r-without", Paths: []string{"~/users/(.+)"}}
			mrWith := router.MarshalRoute(&withHeader, nil, model.FlavorTraditional)
			mrNo := router.MarshalRoute(&noHeader, nil, model.FlavorTraditional)

			if got := router.CompareRoutes(mrWith, mrNo); !(got < 0) {
				t.Errorf("A header-constrained route has higher priority than an unconstrained route at the same path: got %d, want < 0", got)
			}
		})

		t.Run("host header is excluded from headerCount so it does NOT boost sort priority (Kong filters host from headers_t)", func(t *testing.T) {
			onlyHost := model.KongRoute{
				ID:      "r-only-host",
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "host", Values: []string{"api.example.com"}}},
			}
			noHeaders := model.KongRoute{ID: "r-no-headers", Paths: []string{"/api"}}
			mrHost := router.MarshalRoute(&onlyHost, nil, model.FlavorTraditional)
			mrNo := router.MarshalRoute(&noHeaders, nil, model.FlavorTraditional)

			if mrHost.HeaderCount != 0 {
				t.Errorf("A route with only a \"host\" header constraint must have headerCount=0: got %d, want 0", mrHost.HeaderCount)
			}
			if got := router.CompareRoutes(mrHost, mrNo); got != 0 {
				t.Errorf("host header is excluded from headerCount, so route with only \"host\" header ties with no-headers route at the header-count tier: got %d, want 0", got)
			}
		})
	})

	t.Run("compareRoutes – regex_priority (sort_routes L692–L697)", func(t *testing.T) {
		t.Run("regex route with higher regex_priority beats one with lower", func(t *testing.T) {
			highPriRoute := model.KongRoute{
				ID:            "r-high",
				Paths:         []string{"~/timesheetmanager-v2/api/delegation-form/sync$"},
				RegexPriority: 100,
			}
			lowPriRoute := model.KongRoute{
				ID:            "r-low",
				Paths:         []string{"~/timesheetmanager-v2/(.*)"},
				RegexPriority: 0,
			}
			mrHigh := router.MarshalRoute(&highPriRoute, nil, model.FlavorTraditional)
			mrLow := router.MarshalRoute(&lowPriRoute, nil, model.FlavorTraditional)

			if got := router.CompareRoutes(mrHigh, mrLow); !(got < 0) {
				t.Errorf("regex_priority=100 must beat regex_priority=0 between two regex routes: got %d, want < 0", got)
			}
		})

		t.Run("regex_priority is NOT compared between a regex and a plain route (submatch_weight decides first)", func(t *testing.T) {
			// A plain route with any regex_priority value still loses to a regex route
			// because submatch_weight (HAS_REGEX_URI) is evaluated first.
			regexRoute := model.KongRoute{ID: "r-regex", Paths: []string{"~/api/(.*)"}, RegexPriority: 0}
			plainRoute := model.KongRoute{ID: "r-plain", Paths: []string{"/api"}, RegexPriority: 999}
			mrRegex := router.MarshalRoute(&regexRoute, nil, model.FlavorTraditional)
			mrPlain := router.MarshalRoute(&plainRoute, nil, model.FlavorTraditional)

			if got := router.CompareRoutes(mrRegex, mrPlain); !(got < 0) {
				t.Errorf("The regex route wins regardless of regex_priority because submatch_weight is evaluated first: got %d, want < 0", got)
			}
		})

		t.Run("header count is evaluated before regex_priority when both routes are regex", func(t *testing.T) {
			// One route has a higher regex_priority but fewer header constraints.
			// The route with more headers should still win (header count is tier 2, regex_priority is tier 3).
			moreHeaders := model.KongRoute{
				ID:            "r-headers",
				Paths:         []string{"~/api/(.*)"},
				Headers:       model.Headers{model.HeaderConstraint{Name: "x-tenant", Values: []string{"acme"}}},
				RegexPriority: 0,
			}
			highPriNoHeaders := model.KongRoute{ID: "r-hipri", Paths: []string{"~/api/(.*)"}, RegexPriority: 50}
			mrHeaders := router.MarshalRoute(&moreHeaders, nil, model.FlavorTraditional)
			mrHiPri := router.MarshalRoute(&highPriNoHeaders, nil, model.FlavorTraditional)

			if got := router.CompareRoutes(mrHeaders, mrHiPri); !(got < 0) {
				t.Errorf("header count (tier 2) is evaluated before regex_priority (tier 3): more headers wins: got %d, want < 0", got)
			}
		})
	})

	t.Run("simulateRequest – header-constrained routing (real-world x-env pattern)", func(t *testing.T) {
		// Mirrors the exact pattern seen in the integration control plane –
		//   auth-dev-users   ~/users/([^/]+)  headers: {x-env: [dev, develop, development]}
		//   auth-prod-users  ~/users/([^/]+)  (no header constraint)
		devRoute := model.KongRoute{
			ID:            "auth-dev",
			Name:          "auth-dev-users",
			Paths:         []string{"~/users/([^/]+)"},
			Methods:       []string{"GET"},
			Headers:       model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"dev", "develop", "development"}}},
			RegexPriority: 0,
			CreatedAt:     ptr[int64](1700000000),
		}
		internalRoute := model.KongRoute{
			ID:            "auth-internal",
			Name:          "auth-prod-users",
			Paths:         []string{"~/users/([^/]+)"},
			Methods:       []string{"GET"},
			RegexPriority: 0,
			CreatedAt:     ptr[int64](1700000001), // created slightly later
		}
		mrDev := router.MarshalRoute(&devRoute, nil, model.FlavorTraditional)
		mrInternal := router.MarshalRoute(&internalRoute, nil, model.FlavorTraditional)
		sorted := router.SortRoutes([]*router.MarshalledRoute{mrDev, mrInternal})

		t.Run("with x-env:dev header, the dev route wins (header-constrained route has higher sort priority)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method:  "GET",
				Host:    "api.example.com",
				Path:    "/users/alice",
				Headers: map[string]string{"x-env": "dev"},
			})
			if got := winnerIDA(result); got != "auth-dev" {
				t.Errorf("dev route must win when x-env=dev is present: got %q, want %q", got, "auth-dev")
			}
		})

		t.Run("without x-env header, the internal (unconstrained) route wins", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method:  "GET",
				Host:    "api.example.com",
				Path:    "/users/alice",
				Headers: map[string]string{}, // explicit empty = no headers
			})
			if got := winnerIDA(result); got != "auth-internal" {
				t.Errorf("internal route must win when x-env header is absent: got %q, want %q", got, "auth-internal")
			}
		})

		t.Run("with an unrecognised x-env value, the internal route wins (dev route does not match)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method:  "GET",
				Host:    "api.example.com",
				Path:    "/users/alice",
				Headers: map[string]string{"x-env": "production"},
			})
			if got := winnerIDA(result); got != "auth-internal" {
				t.Errorf("\"production\" is not in dev route allowed values → internal route wins: got %q, want %q", got, "auth-internal")
			}
		})

		t.Run("in static analysis mode (no headers in request), both routes are candidates (header constraints skipped)", func(t *testing.T) {
			result := router.SimulateRequest(sorted, router.SimRequest{
				Method: "GET",
				Host:   "api.example.com",
				Path:   "/users/alice",
				// headers intentionally omitted = static analysis mode
			})
			if got := len(result.MatchedRoutes); got != 2 {
				t.Errorf("Both routes should be considered in static analysis mode (headers constraints are skipped): got %d, want 2", got)
			}
		})
	})

	t.Run("classifyPath – malformed regex path", func(t *testing.T) {
		t.Run("does not throw for a malformed regex; stores a never-matching sentinel instead", func(t *testing.T) {
			// ~/[invalid is not valid PCRE – the missing ] makes it a syntax error.
			// classifyPath should catch this and store /(?!)/ so analysis can
			// continue and still flag it as suspicious.
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("classifyPath must not throw even when the regex path is malformed PCRE: got panic %v, want no panic", r)
					}
				}()
				_ = router.ClassifyPath("~/[invalid", model.FlavorTraditional)
			}()
			parsed := router.ClassifyPath("~/[invalid", model.FlavorTraditional)
			if parsed.Kind != router.PathRegex {
				t.Errorf("A malformed regex path is still classified as kind=regex (it starts with ~): got %q, want %q", parsed.Kind, router.PathRegex)
			}
			if parsed.Regex == nil {
				t.Fatalf("The sentinel /(?!)/ never matches anything, so test() must return false: regex is nil (undefined), want a never-matching sentinel")
			}
			if got := parsed.Regex.MatchString("/any/path"); got != false {
				t.Errorf("The sentinel /(?!)/ never matches anything, so test() must return false: got %v, want false", got)
			}
		})
	})
}
