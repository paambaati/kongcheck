// Tests for internal/filter – route filter predicates and finding-level filtering.
//
// Ported 1:1 from src/filter.test.ts.
//
// The --filter feature supports the following predicates:
//
//	path:<prefix>   – routes whose path stem starts with prefix
//	name:<substr>   – routes whose name contains substr (case-insensitive)
//	service:<value> – routes whose service id equals value OR service name contains value
//	tag:<value>     – routes tagged with exactly this value
//	id:<uuid>       – routes with this exact id
//
// AND between different keys, OR within the same key.
// A finding is included when ANY of its involved routes satisfies all predicates.
package filter_test

import (
	"regexp"
	"testing"

	"github.com/paambaati/kongcheck/internal/filter"
	"github.com/paambaati/kongcheck/internal/model"
)

var (
	serviceA = &model.KongService{ID: "svc-a", Name: "payments-service", Host: "payments.internal"}
	serviceB = &model.KongService{ID: "svc-b", Name: "payments-v2-service", Host: "payments-v2.internal"}
	serviceC = &model.KongService{ID: "svc-c", Name: "unrelated-service", Host: "other.internal"}
)

var routePayments = &model.KongRoute{
	ID:      "route-payments",
	Name:    "payments-route",
	Paths:   []string{"~/payments/*"},
	Tags:    []string{"team-platform", "env-prod"},
	Service: &model.ServiceRef{ID: "svc-a"},
}

var routePaymentsV2 = &model.KongRoute{
	ID:      "route-payments-v2",
	Name:    "payments-v2-route",
	Paths:   []string{"/payments-v2/docs", "/payments-v2/api"},
	Tags:    []string{"team-platform", "env-dev"},
	Service: &model.ServiceRef{ID: "svc-b"},
}

var routeUnrelated = &model.KongRoute{
	ID:      "route-unrelated",
	Name:    "unrelated-route",
	Paths:   []string{"/healthz"},
	Tags:    []string{"team-ops"},
	Service: &model.ServiceRef{ID: "svc-c"},
}

var services = model.NewServiceIndex(serviceA, serviceB, serviceC)

func makeFinding(routes []*model.KongRoute, severity ...model.Severity) *model.Finding {
	sev := model.SeverityHigh
	if len(severity) > 0 {
		sev = severity[0]
	}
	winnerID := ""
	if len(routes) > 0 && routes[0] != nil {
		winnerID = routes[0].ID
	}
	return &model.Finding{
		Severity:     sev,
		Type:         model.FindingShadowing,
		RouterFlavor: model.FlavorTraditional,
		Routes:       routes,
		Samples:      []string{"/payments-v2/docs"},
		WinnerID:     winnerID,
		Reason:       []string{"test finding"},
		Suggestions:  []string{},
	}
}

func routes(rs ...*model.KongRoute) []*model.KongRoute { return rs }

func findings(fs ...*model.Finding) []*model.Finding { return fs }

func mustParse(t *testing.T, raw string) filter.Predicate {
	t.Helper()
	p, err := filter.Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q) returned unexpected error: %v", raw, err)
	}
	return p
}

func expectParseError(t *testing.T, raw string, pattern string, msg string) {
	t.Helper()
	_, err := filter.Parse(raw)
	if err == nil {
		t.Fatalf("%s: Parse(%q) returned nil error; want error matching /%s/", msg, raw, pattern)
	}
	if !regexp.MustCompile(pattern).MatchString(err.Error()) {
		t.Errorf("%s: Parse(%q) error = %q; want match for /%s/", msg, raw, err.Error(), pattern)
	}
}

func expectBool(t *testing.T, got, want bool, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

func expectLen(t *testing.T, got []*model.Finding, want int, msg string) {
	t.Helper()
	if len(got) != want {
		t.Fatalf("%s: got length %d, want %d", msg, len(got), want)
	}
}

func expectFirstRouteID(t *testing.T, result []*model.Finding, want string, msg string) {
	t.Helper()
	if len(result) == 0 || len(result[0].Routes) == 0 || result[0].Routes[0] == nil {
		t.Fatalf("%s: result has no first route; want id %q", msg, want)
	}
	if got := result[0].Routes[0].ID; got != want {
		t.Errorf("%s: got %q, want %q", msg, got, want)
	}
}

func TestFilter(t *testing.T) {
	t.Run("parseFilter – parsing --filter key:value strings", func(t *testing.T) {
		t.Run("parses a path predicate", func(t *testing.T) {
			p := mustParse(t, "path:/api/v2")
			if p.Key != filter.KeyPath {
				t.Errorf("key should be 'path': got %q, want %q", p.Key, filter.KeyPath)
			}
			if p.Value != "/api/v2" {
				t.Errorf("value should be the path prefix: got %q, want %q", p.Value, "/api/v2")
			}
		})

		t.Run("parses a name predicate", func(t *testing.T) {
			p := mustParse(t, "name:payments")
			if p.Key != filter.KeyName {
				t.Errorf("key should be 'name': got %q, want %q", p.Key, filter.KeyName)
			}
			if p.Value != "payments" {
				t.Errorf("value should be the name substring: got %q, want %q", p.Value, "payments")
			}
		})

		t.Run("parses a service predicate", func(t *testing.T) {
			p := mustParse(t, "service:payments-svc")
			if p.Key != filter.KeyService {
				t.Errorf("key should be 'service': got %q, want %q", p.Key, filter.KeyService)
			}
			if p.Value != "payments-svc" {
				t.Errorf("value should be the service name/id to match: got %q, want %q", p.Value, "payments-svc")
			}
		})

		t.Run("parses a tag predicate", func(t *testing.T) {
			p := mustParse(t, "tag:team-platform")
			if p.Key != filter.KeyTag {
				t.Errorf("key should be 'tag': got %q, want %q", p.Key, filter.KeyTag)
			}
			if p.Value != "team-platform" {
				t.Errorf("value should be the exact tag string to match: got %q, want %q", p.Value, "team-platform")
			}
		})

		t.Run("parses an id predicate", func(t *testing.T) {
			p := mustParse(t, "id:route-payments")
			if p.Key != filter.KeyID {
				t.Errorf("key should be 'id': got %q, want %q", p.Key, filter.KeyID)
			}
			if p.Value != "route-payments" {
				t.Errorf("value should be the exact route UUID to match: got %q, want %q", p.Value, "route-payments")
			}
		})

		t.Run("preserves colons in the value (value may itself contain colons)", func(t *testing.T) {
			p := mustParse(t, "path:~/api:v2/resource")
			if p.Key != filter.KeyPath {
				t.Errorf("key should stop at first colon: got %q, want %q", p.Key, filter.KeyPath)
			}
			if p.Value != "~/api:v2/resource" {
				t.Errorf("value includes everything after the first colon: got %q, want %q", p.Value, "~/api:v2/resource")
			}
		})

		t.Run("throws when no colon is present", func(t *testing.T) {
			expectParseError(t, "pathapi", `expected format key:value`, "missing colon should throw")
		})

		t.Run("throws on an unrecognised key", func(t *testing.T) {
			expectParseError(t, "host:example.com", `Unknown filter key "host"`, "unknown key should throw")
		})

		t.Run("throws when the value is empty", func(t *testing.T) {
			expectParseError(t, "name:", `must not be empty`, "empty value should throw")
		})
	})

	t.Run("parseFilters – wraps parseFilter for CLI option values", func(t *testing.T) {
		t.Run("returns empty array for undefined (flag not provided)", func(t *testing.T) {
			preds, err := filter.ParseAll(nil)
			if err != nil {
				t.Fatalf("no --filter flags → empty predicate list: unexpected error: %v", err)
			}
			if len(preds) != 0 {
				t.Errorf("no --filter flags → empty predicate list: got %v, want []", preds)
			}
		})

		t.Run("wraps a single string in an array", func(t *testing.T) {
			preds, err := filter.ParseAll([]string{"path:/api"})
			if err != nil {
				t.Fatalf("a single filter string should produce exactly one predicate: unexpected error: %v", err)
			}
			if len(preds) != 1 {
				t.Fatalf("a single filter string should produce exactly one predicate: got length %d, want 1", len(preds))
			}
			if preds[0].Key != filter.KeyPath {
				t.Errorf("the parsed predicate key should be 'path': got %q, want %q", preds[0].Key, filter.KeyPath)
			}
		})

		t.Run("parses an array (flag provided multiple times)", func(t *testing.T) {
			preds, err := filter.ParseAll([]string{"tag:team-a", "service:payments-svc"})
			if err != nil {
				t.Fatalf("two filter strings should produce two predicates: unexpected error: %v", err)
			}
			if len(preds) != 2 {
				t.Fatalf("two filter strings should produce two predicates: got length %d, want 2", len(preds))
			}
			if preds[0].Key != filter.KeyTag {
				t.Errorf("first predicate key should be 'tag': got %q, want %q", preds[0].Key, filter.KeyTag)
			}
			if preds[1].Key != filter.KeyService {
				t.Errorf("second predicate key should be 'service': got %q, want %q", preds[1].Key, filter.KeyService)
			}
		})
	})

	t.Run("routeMatchesPredicate – path predicate", func(t *testing.T) {
		t.Run("matches a plain-prefix path by prefix", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePaymentsV2, serviceB, filter.Predicate{Key: filter.KeyPath, Value: "/payments-v2"}),
				true,
				"--filter path:/payments-v2 matches route with path /payments-v2/docs",
			)
		})

		t.Run("matches a regex path after stripping the leading ~", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyPath, Value: "/payments"}),
				true,
				"--filter path:/payments matches route with regex path ~/payments/* (~ stripped before comparison)",
			)
		})

		t.Run("does NOT match when no path starts with the prefix", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routeUnrelated, serviceC, filter.Predicate{Key: filter.KeyPath, Value: "/api"}),
				false,
				"--filter path:/api should not match a route whose only path is /healthz",
			)
		})

		t.Run("matches the exact path prefix /payments-v2/docs but not /payments-v2/other", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePaymentsV2, serviceB, filter.Predicate{Key: filter.KeyPath, Value: "/payments-v2/docs"}),
				true,
				"exact-prefix filter matches the matching path",
			)
		})

		t.Run("does NOT match /payments-v2/docs filter against a route with only /payments-v2/api", func(t *testing.T) {
			route := *routePaymentsV2
			route.Paths = []string{"/payments-v2/api"}
			expectBool(t,
				filter.RouteMatches(&route, serviceB, filter.Predicate{Key: filter.KeyPath, Value: "/payments-v2/docs"}),
				false,
				"route with only /payments-v2/api should not match filter path:/payments-v2/docs",
			)
		})
	})

	t.Run("routeMatchesPredicate – name predicate (case-insensitive substring)", func(t *testing.T) {
		t.Run("matches when the filter value is a substring of the route name", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyName, Value: "payments"}),
				true,
				"'payments' is a substring of 'payments-route'",
			)
		})

		t.Run("matches case-insensitively", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyName, Value: "PAYMENTS"}),
				true,
				"'PAYMENTS' should match 'payments-route' case-insensitively",
			)
		})

		t.Run("does NOT match when the route name does not contain the substring", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routeUnrelated, serviceC, filter.Predicate{Key: filter.KeyName, Value: "payments"}),
				false,
				"'payments' is not a substring of 'unrelated-route'",
			)
		})

		t.Run("matches a route with no name (empty string never matches a non-empty filter)", func(t *testing.T) {
			route := *routePayments
			route.Name = ""
			expectBool(t,
				filter.RouteMatches(&route, serviceA, filter.Predicate{Key: filter.KeyName, Value: "payments"}),
				false,
				"route without name → empty string → does not contain 'payments'",
			)
		})
	})

	t.Run("routeMatchesPredicate – service predicate", func(t *testing.T) {
		t.Run("matches by exact service id", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyService, Value: "svc-a"}),
				true,
				"exact service id match",
			)
		})

		t.Run("matches by service name substring (case-insensitive)", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyService, Value: "payments-service"}),
				true,
				"exact service name match",
			)
		})

		t.Run("matches service name case-insensitively by substring", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyService, Value: "PAYMENTS"}),
				true,
				"'PAYMENTS' is a case-insensitive substring of 'payments-service'",
			)
		})

		t.Run("does NOT match when service id and name differ from the filter value", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routeUnrelated, serviceC, filter.Predicate{Key: filter.KeyService, Value: "payments-service"}),
				false,
				"svc-c 'unrelated-service' should not match filter service:payments-service",
			)
		})

		t.Run("falls back to route.service.id when no resolved service is provided", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, nil, filter.Predicate{Key: filter.KeyService, Value: "svc-a"}),
				true,
				"route.service.id used when resolved service is not provided",
			)
		})
	})

	t.Run("routeMatchesPredicate – tag predicate (exact match)", func(t *testing.T) {
		t.Run("matches when the route has the exact tag", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyTag, Value: "team-platform"}),
				true,
				"route has tag 'team-platform'",
			)
		})

		t.Run("does NOT match a partial tag name", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyTag, Value: "platform"}),
				false,
				"tag filter is exact – 'platform' should not match 'team-platform'",
			)
		})

		t.Run("does NOT match when the route has no tags", func(t *testing.T) {
			route := *routePayments
			route.Tags = nil
			expectBool(t,
				filter.RouteMatches(&route, serviceA, filter.Predicate{Key: filter.KeyTag, Value: "team-platform"}),
				false,
				"route without tags field should not match any tag filter",
			)
		})
	})

	t.Run("routeMatchesPredicate – id predicate (exact UUID match)", func(t *testing.T) {
		t.Run("matches the exact id", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyID, Value: "route-payments"}),
				true,
				"exact id match",
			)
		})

		t.Run("does NOT match a partial id", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatches(routePayments, serviceA, filter.Predicate{Key: filter.KeyID, Value: "route"}),
				false,
				"partial id should not match – id filter is exact",
			)
		})
	})

	t.Run("routeMatchesAllPredicates – AND between keys, OR within same key", func(t *testing.T) {
		t.Run("returns true when predicates list is empty (no filter = match all)", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatchesAll(routePayments, serviceA, []filter.Predicate{}),
				true,
				"empty predicates → always matches",
			)
		})

		t.Run("matches when a single predicate is satisfied", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatchesAll(routePayments, serviceA, []filter.Predicate{{Key: filter.KeyTag, Value: "team-platform"}}),
				true,
				"single matching tag predicate",
			)
		})

		t.Run("two different keys are ANDed – both must match", func(t *testing.T) {
			// route has tag team-platform AND service svc-a → should match
			expectBool(t,
				filter.RouteMatchesAll(routePayments, serviceA, []filter.Predicate{
					{Key: filter.KeyTag, Value: "team-platform"},
					{Key: filter.KeyService, Value: "svc-a"},
				}),
				true,
				"tag:team-platform AND service:svc-a – payments-route satisfies both",
			)
		})

		t.Run("two different keys ANDed – fails when one key doesn't match", func(t *testing.T) {
			// route has tag team-platform but NOT service svc-b
			expectBool(t,
				filter.RouteMatchesAll(routePayments, serviceA, []filter.Predicate{
					{Key: filter.KeyTag, Value: "team-platform"},
					{Key: filter.KeyService, Value: "svc-b"},
				}),
				false,
				"tag:team-platform AND service:svc-b – payments-route is on svc-a, not svc-b → no match",
			)
		})

		t.Run("two predicates for the same key are ORed – either value suffices", func(t *testing.T) {
			// route has tag "team-platform" but NOT "team-ops"
			// filter: tag:team-platform OR tag:team-ops → should match because team-platform is present
			expectBool(t,
				filter.RouteMatchesAll(routePayments, serviceA, []filter.Predicate{
					{Key: filter.KeyTag, Value: "team-platform"},
					{Key: filter.KeyTag, Value: "team-ops"},
				}),
				true,
				"tag:team-platform OR tag:team-ops – payments-route has team-platform → matches",
			)
		})

		t.Run("same-key OR does not match when neither value is present", func(t *testing.T) {
			expectBool(t,
				filter.RouteMatchesAll(routePayments, serviceA, []filter.Predicate{
					{Key: filter.KeyTag, Value: "team-ops"},
					{Key: filter.KeyTag, Value: "team-devex"},
				}),
				false,
				"tag:team-ops OR tag:team-devex – payments-route has neither → no match",
			)
		})

		t.Run("mixed AND/OR: two tags ORed AND a service ANDed", func(t *testing.T) {
			// payments-v2-route: tags=[team-platform, env-dev], service=svc-b
			// filter: (tag:team-platform OR tag:team-ops) AND service:svc-b
			expectBool(t,
				filter.RouteMatchesAll(routePaymentsV2, serviceB, []filter.Predicate{
					{Key: filter.KeyTag, Value: "team-platform"},
					{Key: filter.KeyTag, Value: "team-ops"},
					{Key: filter.KeyService, Value: "svc-b"},
				}),
				true,
				"(tag:team-platform OR tag:team-ops) AND service:svc-b – payments-v2 has team-platform and svc-b",
			)
		})
	})

	t.Run("applyFindingFilter – includes finding when ANY involved route matches", func(t *testing.T) {
		t.Run("returns all findings when predicates list is empty", func(t *testing.T) {
			fs := findings(makeFinding(routes(routePayments)), makeFinding(routes(routePaymentsV2)), makeFinding(routes(routeUnrelated)))
			expectLen(t, filter.Apply(fs, []filter.Predicate{}, services), 3, "no --filter flags → all findings returned")
		})

		t.Run("includes a finding whose sole route matches the filter", func(t *testing.T) {
			fs := findings(makeFinding(routes(routePayments)), makeFinding(routes(routeUnrelated)))
			result := filter.Apply(fs, []filter.Predicate{{Key: filter.KeyTag, Value: "team-platform"}}, services)
			expectLen(t, result, 1, "only the payments finding has tag team-platform")
			expectFirstRouteID(t, result, "route-payments",
				"the surviving finding's first route must be the payments-route, not the unrelated one")
		})

		t.Run("includes a cross-team collision finding when ANY route matches", func(t *testing.T) {
			// Finding involves payments-route (team-platform) AND unrelated-route (team-ops)
			finding := makeFinding(routes(routePayments, routeUnrelated))
			result := filter.Apply(findings(finding), []filter.Predicate{{Key: filter.KeyTag, Value: "team-platform"}}, services)
			expectLen(t, result, 1, "cross-team finding shown because payments-route (ANY match) satisfies the filter")
		})

		t.Run("excludes a finding where NO involved route matches the filter", func(t *testing.T) {
			finding := makeFinding(routes(routeUnrelated))
			result := filter.Apply(findings(finding), []filter.Predicate{{Key: filter.KeyTag, Value: "team-platform"}}, services)
			expectLen(t, result, 0, "unrelated-route has tag team-ops, not team-platform → excluded")
		})

		t.Run("service filter: includes finding for routes on the named service", func(t *testing.T) {
			fs := findings(
				makeFinding(routes(routePayments)),   // svc-a / payments-service
				makeFinding(routes(routePaymentsV2)), // svc-b / payments-v2-service
				makeFinding(routes(routeUnrelated)),  // svc-c / unrelated-service
			)
			result := filter.Apply(fs, []filter.Predicate{{Key: filter.KeyService, Value: "payments-service"}}, services)
			expectLen(t, result, 1, "only the payments-route finding belongs to payments-service")
			expectFirstRouteID(t, result, "route-payments",
				"the surviving finding's first route must be the payments-route (service svc-a / payments-service)")
		})

		t.Run("path filter: includes only findings involving routes under /payments-v2", func(t *testing.T) {
			fs := findings(
				makeFinding(routes(routePayments)),   // paths: ~/payments/*  (stem /payments)
				makeFinding(routes(routePaymentsV2)), // paths: /payments-v2/docs, /payments-v2/api
				makeFinding(routes(routeUnrelated)),  // paths: /healthz
			)
			result := filter.Apply(fs, []filter.Predicate{{Key: filter.KeyPath, Value: "/payments-v2"}}, services)
			expectLen(t, result, 1, "--filter path:/payments-v2 includes only the payments-v2-route finding")
			expectFirstRouteID(t, result, "route-payments-v2",
				"the surviving finding's first route must be the payments-v2-route (paths /payments-v2/...)")
		})

		t.Run("tag OR: includes findings from either team when two same-key predicates given", func(t *testing.T) {
			fs := findings(
				makeFinding(routes(routePayments)),  // tag: team-platform
				makeFinding(routes(routeUnrelated)), // tag: team-ops
			)
			result := filter.Apply(fs, []filter.Predicate{
				{Key: filter.KeyTag, Value: "team-platform"},
				{Key: filter.KeyTag, Value: "team-ops"},
			}, services)
			expectLen(t, result, 2, "tag:team-platform OR tag:team-ops → both findings included")
		})

		t.Run("AND across keys: only includes findings satisfying all key groups", func(t *testing.T) {
			fs := findings(
				makeFinding(routes(routePayments)),   // tag: team-platform, service: svc-a
				makeFinding(routes(routePaymentsV2)), // tag: team-platform, service: svc-b
				makeFinding(routes(routeUnrelated)),  // tag: team-ops,      service: svc-c
			)
			// Only payments-route satisfies tag:team-platform AND service:svc-a
			result := filter.Apply(fs, []filter.Predicate{
				{Key: filter.KeyTag, Value: "team-platform"},
				{Key: filter.KeyService, Value: "svc-a"},
			}, services)
			expectLen(t, result, 1, "tag:team-platform AND service:svc-a → only payments-route finding")
			expectFirstRouteID(t, result, "route-payments",
				"the surviving finding's first route must be route-payments (tagged team-platform on svc-a)")
		})
	})
}
