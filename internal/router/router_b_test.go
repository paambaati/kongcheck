package router_test

import (
	"strings"
	"testing"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// matchB is a thin wrapper around router.MatchRoute taking the request by value.
func matchB(mr *router.MarshalledRoute, req router.SimRequest) bool {
	return router.MatchRoute(mr, &req)
}

// expectBoolB asserts got == want, reporting the TS assertion message.
func expectBoolB(t *testing.T, got, want bool, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

// expectIntB asserts got == want, reporting the TS assertion message.
func expectIntB(t *testing.T, got, want int, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %d, want %d", msg, got, want)
	}
}

// expectStrB asserts got == want, reporting the TS assertion message.
func expectStrB(t *testing.T, got, want, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", msg, got, want)
	}
}

// expectLessThanZeroB asserts got < 0 (vitest toBeLessThan(0)).
func expectLessThanZeroB(t *testing.T, got int, msg string) {
	t.Helper()
	if !(got < 0) {
		t.Errorf("%s: got %d, want < 0", msg, got)
	}
}

// expectIPv4B asserts ParseIPv4 returns (want, true).
func expectIPv4B(t *testing.T, s string, want uint32, msg string) {
	t.Helper()
	got, ok := router.ParseIPv4(s)
	if !ok {
		t.Errorf("%s: got null (ok=false), want %d", msg, want)
		return
	}
	if got != want {
		t.Errorf("%s: got %d, want %d", msg, got, want)
	}
}

// expectIPv4NullB asserts ParseIPv4 returns ok == false (TS null).
func expectIPv4NullB(t *testing.T, s string, msg string) {
	t.Helper()
	if got, ok := router.ParseIPv4(s); ok {
		t.Errorf("%s: got %d, want null (ok=false)", msg, got)
	}
}

// mustIPv4B mirrors TS `parseIpv4(x)!`.
func mustIPv4B(t *testing.T, s string) uint32 {
	t.Helper()
	v, ok := router.ParseIPv4(s)
	if !ok {
		t.Fatalf("parseIpv4(%q) unexpectedly returned null", s)
	}
	return v
}

func TestRouterB(t *testing.T) {
	t.Run(`matchRoute – universal host wildcard "*"`, func(t *testing.T) {
		t.Run(`route with hosts: ["*"] matches any host value`, func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "anything.example.com", Path: "/api/test"}),
				true,
				`hosts: ["*"] is a universal host wildcard and must match every host`)
		})

		t.Run("route with exact host matches only that host", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"api.example.com"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "other.example.com", Path: "/api/test"}),
				false,
				"An exact host constraint must NOT match a different host")
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "api.example.com", Path: "/api/test"}),
				true,
				"An exact host constraint must match the exact host")
		})
	})

	t.Run("matchRoute – malformed ~* header regex does not crash", func(t *testing.T) {
		t.Run("treats a malformed ~* header regex as a non-match (does not throw)", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{
				Paths:   []string{"/api"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"~*[invalid"}}}, // [invalid is not valid PCRE
			})
			req := router.SimRequest{Method: "GET", Host: "example.com", Path: "/api", Headers: map[string]string{"x-env": "prod"}}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("A malformed ~* header regex must not throw: got panic %v, want no panic", r)
					}
				}()
				matchB(mr, req)
			}()
			expectBoolB(t,
				matchB(mr, req),
				false,
				"When the ~* header regex is malformed, the route should not match (null pattern → no regex match)")
		})
	})

	t.Run("computeUpstreamUri – non-trailing-slash upstreamBase branches", func(t *testing.T) {
		t.Run("strip_path=true, upstreamBase without trailing slash, postfix without leading slash", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, StripPath: ptr(true)})
			// reqPath=/api/users, matchedPrefix=/api → postfix=users (no leading slash after sanitize)
			// upstreamBase=/backend (no trailing slash) → /backend/users
			result := router.ComputeUpstreamURI(mr, "/api/users", "/api", "/backend")
			expectStrB(t, result, "/backend/users", "upstreamBase /backend + postfix /users = /backend/users")
		})

		t.Run("strip_path=true, upstreamBase without trailing slash, no postfix → returns upstreamBase as-is", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, StripPath: ptr(true)})
			// reqPath=/api, matchedPrefix=/api → postfix='' (empty)
			result := router.ComputeUpstreamURI(mr, "/api", "/api", "/backend")
			expectStrB(t, result, "/backend", "When postfix is empty, upstreamBase /backend is returned unchanged")
		})

		t.Run("strip_path=false, reqPath=/ returns upstreamBase unchanged", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/"}, StripPath: ptr(false)})
			result := router.ComputeUpstreamURI(mr, "/", "/", "/backend/")
			expectStrB(t, result, "/backend/", "strip_path=false and reqPath=/ should return the upstreamBase verbatim")
		})

		t.Run("strip_path=true, upstreamBase=/ with no postfix → returns /", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, StripPath: ptr(true)})
			// reqPath=/api, matchedPrefix=/api → postfix='' → upstreamBase='/' → return '/'
			result := router.ComputeUpstreamURI(mr, "/api", "/api", "/")
			expectStrB(t, result, "/", "strip_path=true with empty postfix and upstreamBase=/ should return /")
		})
	})

	t.Run("extractMatchedPrefix", func(t *testing.T) {
		t.Run("returns the plain prefix for a prefix route", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api/v1"}})
			expectStrB(t,
				router.ExtractMatchedPrefix(mr, "/api/v1/users"),
				"/api/v1",
				"For a plain prefix route, the matched prefix is the route path itself")
		})

		t.Run("returns the regex-matched portion for a regex route", func(t *testing.T) {
			// ~/api/v[0-9]+ matches /api/v1 but not the /users part.
			mr := makeRoute(model.KongRoute{Paths: []string{"~/api/v[0-9]+"}})
			expectStrB(t,
				router.ExtractMatchedPrefix(mr, "/api/v1/users"),
				"/api/v1",
				"For a regex route, extractMatchedPrefix returns the portion matched by the regex")
		})

		t.Run("returns empty string when no path matches", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/other"}})
			expectStrB(t,
				router.ExtractMatchedPrefix(mr, "/api/v1/users"),
				"",
				"When no path matches the request, extractMatchedPrefix returns an empty string")
		})
	})

	t.Run("marshalRoute – subMatchWeight 3-bit field (traditional.lua MATCH_SUBRULES)", func(t *testing.T) {
		t.Run("bit 0 (HAS_REGEX_URI) is set when any path is a regex path", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"~/api/.*"}})
			expectIntB(t, mr.SubMatchWeight&0x01, 1, "Bit 0 must be set when the route has a regex path")
		})

		t.Run("bit 0 is NOT set for a plain-prefix route", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			expectIntB(t, mr.SubMatchWeight&0x01, 0, "Bit 0 must be 0 for plain-prefix routes")
		})

		t.Run("bit 1 (PLAIN_HOSTS_ONLY) is set when all hosts are plain (no wildcards)", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"api.example.com"}})
			expectIntB(t, mr.SubMatchWeight&0x02, 2, "Bit 1 must be set when every host constraint is a plain hostname")
		})

		t.Run("bit 1 (PLAIN_HOSTS_ONLY) is NOT set when any host is a wildcard", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectIntB(t, mr.SubMatchWeight&0x02, 0, "Bit 1 must be 0 when the route has a wildcard host constraint")
		})

		t.Run("bit 1 is NOT set when the route has no host constraints (no hosts array = any host)", func(t *testing.T) {
			// A route with no hosts is open to any host — it is not "plain hosts only"
			// in the PLAIN_HOSTS_ONLY sense (Kong only sets this bit when there are hosts
			// AND none are wildcards). When hosts is absent/empty Kong skips the whole block.
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			expectIntB(t, mr.SubMatchWeight&0x02, 0,
				"Bit 1 must be 0 when there are no host constraints (Kong does not set PLAIN_HOSTS_ONLY for unconstrained routes)")
		})

		t.Run("bit 2 (HAS_WILDCARD_HOST_PORT) is set when a wildcard host has an explicit port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			expectIntB(t, mr.SubMatchWeight&0x04, 4, "Bit 2 must be set when a wildcard host includes an explicit port")
		})

		t.Run("bit 2 is NOT set when the wildcard host has no explicit port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectIntB(t, mr.SubMatchWeight&0x04, 0, "Bit 2 must be 0 when the wildcard host has no explicit port")
		})

		t.Run("mixed route: regex path (bit 0) + plain hosts (bit 1) → subMatchWeight = 3", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"~/api/.*"}, Hosts: []string{"api.example.com"}})
			expectIntB(t, mr.SubMatchWeight, 3, "Regex path (bit 0) + plain host (bit 1) = 0b011 = 3")
		})

		t.Run("hasRegexPath is always consistent with bit 0 of subMatchWeight", func(t *testing.T) {
			withRegex := makeRoute(model.KongRoute{Paths: []string{"~/api/.*"}})
			withPlain := makeRoute(model.KongRoute{Paths: []string{"/api"}})
			expectBoolB(t, withRegex.HasRegexPath, withRegex.SubMatchWeight&0x01 != 0,
				"withRegex.hasRegexPath must equal !!(withRegex.subMatchWeight & 0x01)")
			expectBoolB(t, withPlain.HasRegexPath, withPlain.SubMatchWeight&0x01 != 0,
				"withPlain.hasRegexPath must equal !!(withPlain.subMatchWeight & 0x01)")
		})
	})

	t.Run("compareRoutes – PLAIN_HOSTS_ONLY beats wildcard-host at same path", func(t *testing.T) {
		t.Run("plain-host route beats wildcard-host route at the same path and regex_priority", func(t *testing.T) {
			// This is the most common multi-tenant Kong pattern:
			//   payments.internal.example.com → specific service (plain host)
			//   *.internal.example.com        → catch-all (wildcard host)
			// Kong: PLAIN_HOSTS_ONLY (bit 1) is set on the plain-host route, making
			// its subMatchWeight higher (at least 0x02 vs 0x00 for wildcard).
			plainHost := makeRoute(model.KongRoute{ID: "r-plain", Paths: []string{"/v1/users"}, Hosts: []string{"api.example.com"}})
			wildcardHost := makeRoute(model.KongRoute{ID: "r-wildcard", Paths: []string{"/v1/users"}, Hosts: []string{"*.example.com"}})
			expectLessThanZeroB(t, router.CompareRoutes(plainHost, wildcardHost),
				"Plain-host route must beat wildcard-host route (PLAIN_HOSTS_ONLY bit 1 > 0)")
		})

		t.Run("wildcard-host-with-port beats wildcard-host-without-port at the same path", func(t *testing.T) {
			// Kong: HAS_WILDCARD_HOST_PORT (bit 2) ranks *.example.com:8080 above *.example.com.
			withPort := makeRoute(model.KongRoute{ID: "r-with-port", Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			withoutPort := makeRoute(model.KongRoute{ID: "r-without-port", Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectLessThanZeroB(t, router.CompareRoutes(withPort, withoutPort),
				"Wildcard host with explicit port must beat wildcard host without port (HAS_WILDCARD_HOST_PORT bit 2)")
		})

		t.Run("wildcard-host-with-port (0x04) beats plain-host-no-regex (0x02) — HAS_WILDCARD_HOST_PORT outranks PLAIN_HOSTS_ONLY alone", func(t *testing.T) {
			// Kong source (traditional.lua L682-684): sort_routes compares
			// submatch_weight as a raw integer — higher wins. 4 > 2.
			plainNoRegex := makeRoute(model.KongRoute{ID: "r-plain", Paths: []string{"/api"}, Hosts: []string{"api.example.com"}})
			wildcardWithPort := makeRoute(model.KongRoute{ID: "r-wc-port", Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			expectIntB(t, plainNoRegex.SubMatchWeight, 2,
				"plain host, no regex path → only PLAIN_HOSTS_ONLY (bit 1) is set → subMatchWeight = 2")
			expectIntB(t, wildcardWithPort.SubMatchWeight, 4,
				"wildcard host with explicit port, no regex → only HAS_WILDCARD_HOST_PORT (bit 2) is set → subMatchWeight = 4")
			expectLessThanZeroB(t, router.CompareRoutes(wildcardWithPort, plainNoRegex),
				"HAS_WILDCARD_HOST_PORT (0x04 = 4) outranks PLAIN_HOSTS_ONLY (0x02 = 2) in Kong integer comparison — wildcard-with-port wins")
		})
	})

	t.Run("compareRoutes – subMatchWeight sort tier takes precedence over all others", func(t *testing.T) {
		t.Run("plain-host route wins over wildcard-host even when wildcard has higher regex_priority", func(t *testing.T) {
			// regex_priority is only compared within the same submatch_weight tier (tier 3).
			// subMatchWeight is tier 1, so a plain-host route wins regardless of regex_priority.
			plainHost := makeRoute(model.KongRoute{ID: "r-plain", Paths: []string{"~/api/.*"}, Hosts: []string{"api.example.com"}, RegexPriority: 0})
			wildcardHighPri := makeRoute(model.KongRoute{ID: "r-wildcard", Paths: []string{"~/api/.*"}, Hosts: []string{"*.example.com"}, RegexPriority: 100})
			expectLessThanZeroB(t, router.CompareRoutes(plainHost, wildcardHighPri),
				"subMatchWeight (tier 1) is evaluated before regex_priority (tier 3); plain-host wins")
		})
	})

	t.Run("simulateRequest – explanation text for subMatchWeight ordering", func(t *testing.T) {
		t.Run("explanation mentions PLAIN_HOSTS_ONLY when plain-host beats wildcard-host", func(t *testing.T) {
			plainHost := makeRoute(model.KongRoute{ID: "r-plain", Paths: []string{"/v1/users"}, Hosts: []string{"api.example.com"}})
			wildcardHost := makeRoute(model.KongRoute{ID: "r-wildcard", Paths: []string{"/v1/users"}, Hosts: []string{"*.example.com"}})
			sorted := router.SortRoutes([]*router.MarshalledRoute{plainHost, wildcardHost})
			result := router.SimulateRequest(sorted, router.SimRequest{Method: "GET", Host: "api.example.com", Path: "/v1/users"})
			text := strings.Join(result.Explanation(), " ")
			lower := strings.ToLower(text)
			expectBoolB(t,
				strings.Contains(lower, "plain") || strings.Contains(lower, "submatch"),
				true,
				"Explanation must mention plain-host priority or submatch_weight (text: "+text+")")
		})
	})

	t.Run("matchRoute – wildcard host port handling", func(t *testing.T) {
		t.Run("*.example.com (no port) matches a request Host with an explicit port", func(t *testing.T) {
			// Kong compiles *.example.com as /.+\.example\.com(?::\d+)?$/ — it accepts any port.
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "foo.example.com:8443", Path: "/api"}),
				true,
				"*.example.com (no port in constraint) must match foo.example.com:8443")
		})

		t.Run("*.example.com (no port) matches a request Host without a port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "foo.example.com", Path: "/api"}),
				true,
				"*.example.com must still match foo.example.com when no port is present")
		})

		t.Run("*.example.com:8080 (explicit port) matches only requests with that port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "foo.example.com:8080", Path: "/api"}),
				true,
				"*.example.com:8080 must match foo.example.com:8080")
		})

		t.Run("*.example.com:8080 does NOT match a request with a different port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "foo.example.com:9090", Path: "/api"}),
				false,
				"*.example.com:8080 must not match foo.example.com:9090 (wrong port)")
		})

		t.Run("*.example.com:8080 does NOT match a request without a port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "foo.example.com", Path: "/api"}),
				false,
				"*.example.com:8080 must not match foo.example.com (port required)")
		})

		t.Run("*.example.com does NOT match a plain domain (must have a subdomain)", func(t *testing.T) {
			// Kong pattern: .+\.example\.com — requires at least one character before the dot.
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "example.com", Path: "/api"}),
				false,
				"*.example.com must NOT match example.com (no subdomain)")
		})

		t.Run("*.example.com does NOT match an entirely different domain (example.org)", func(t *testing.T) {
			// Regression guard: the suffix check must be exact.
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "foo.example.org", Path: "/api"}),
				false,
				"*.example.com must NOT match foo.example.org — different TLD/domain")
		})

		t.Run("route with multiple host constraints matches a host that satisfies ANY of them", func(t *testing.T) {
			// Kong: any of the listed host constraints matching is sufficient (OR semantics).
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"api.example.com", "*.other.com"}})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "api.example.com", Path: "/api"}),
				true,
				"The plain host api.example.com must match when it is explicitly listed")
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "sub.other.com", Path: "/api"}),
				true,
				"The wildcard *.other.com must match sub.other.com (second constraint)")
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Host: "unrelated.example.net", Path: "/api"}),
				false,
				"A host not matching any of the listed constraints must not match the route")
		})
	})

	// marshalRoute – subMatchWeight edge cases (Kong traditional.lua L333–L374)
	t.Run("marshalRoute – subMatchWeight edge cases: mixed and multi-wildcard hosts", func(t *testing.T) {
		t.Run("PLAIN_HOSTS_ONLY (bit 1) is NOT set when hosts array contains BOTH plain and wildcard entries", func(t *testing.T) {
			// Kong L368: "if not has_host_wildcard then submatch_weight |= PLAIN_HOSTS_ONLY"
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"api.example.com", "*.fallback.example.com"}})
			expectIntB(t, mr.SubMatchWeight&0x02, 0,
				"A host array containing any wildcard must NOT set PLAIN_HOSTS_ONLY (bit 1) — even one wildcard disqualifies the route")
		})

		t.Run("PLAIN_HOSTS_ONLY (bit 1) IS set when all hosts in a multi-entry array are plain", func(t *testing.T) {
			// Multiple plain hosts: still no wildcard → PLAIN_HOSTS_ONLY is set.
			mr := makeRoute(model.KongRoute{
				Paths: []string{"/api"},
				Hosts: []string{"api.example.com", "api.staging.example.com", "api.dev.example.com"},
			})
			expectIntB(t, mr.SubMatchWeight&0x02, 2, "All three hosts are plain (no wildcards) → PLAIN_HOSTS_ONLY must be set")
		})

		t.Run("HAS_WILDCARD_HOST_PORT (bit 2) is set when the SECOND wildcard host has a port (first has none)", func(t *testing.T) {
			// Kong L345: fires for ANY wildcard with a port, not just the first.
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.no-port.com", "*.example.com:8080"}})
			expectIntB(t, mr.SubMatchWeight&0x04, 4,
				"Bit 2 must be set even when only the second wildcard host has an explicit port")
		})

		t.Run("HAS_WILDCARD_HOST_PORT (bit 2) is NOT set when all wildcards have no port", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"/api"}, Hosts: []string{"*.foo.com", "*.bar.com"}})
			expectIntB(t, mr.SubMatchWeight&0x04, 0,
				"No wildcard in the array has a port → HAS_WILDCARD_HOST_PORT (bit 2) must remain 0")
		})

		t.Run("regex path + plain hosts: subMatchWeight has both bit 0 (HAS_REGEX_URI) and bit 1 (PLAIN_HOSTS_ONLY) set", func(t *testing.T) {
			// Combination: regex path sets bit 0; all-plain hosts set bit 1 → 0x01 | 0x02 = 0x03
			mr := makeRoute(model.KongRoute{Paths: []string{"~/api/v[0-9]+"}, Hosts: []string{"api.example.com"}})
			expectIntB(t, mr.SubMatchWeight, 3,
				"Regex path (bit 0 = 0x01) AND plain host (bit 1 = 0x02) → subMatchWeight = 0x03 = 3")
		})

		t.Run("regex path + wildcard hosts: only bit 0 (HAS_REGEX_URI) is set — PLAIN_HOSTS_ONLY is absent", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{Paths: []string{"~/api/v[0-9]+"}, Hosts: []string{"*.example.com"}})
			expectIntB(t, mr.SubMatchWeight, 1,
				"Regex path (bit 0) but wildcard host → PLAIN_HOSTS_ONLY not set → subMatchWeight = 0x01 = 1")
		})
	})

	// ─── compareRoutes – all subMatchWeight bit combinations (Gap #1 deep coverage) ──
	t.Run("compareRoutes – all subMatchWeight combinations (Gap #1 deep coverage)", func(t *testing.T) {
		t.Run("wildcard-with-port (0x04) beats regex-plain-host (0x03) — bit 2 integer-dominates bits 0+1", func(t *testing.T) {
			regexPlainHost := makeRoute(model.KongRoute{ID: "r-regex-plain", Paths: []string{"~/api/v[0-9]+"}, Hosts: []string{"api.example.com"}})
			noRegexWildcardPort := makeRoute(model.KongRoute{ID: "r-wc-port", Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			expectIntB(t, regexPlainHost.SubMatchWeight, 3, "Regex path (bit 0) + plain host (bit 1) → 0x01 | 0x02 = 0x03 = 3")
			expectIntB(t, noRegexWildcardPort.SubMatchWeight, 4, "No regex path, wildcard host with port (bit 2 only) → 0x04 = 4")
			expectLessThanZeroB(t, router.CompareRoutes(noRegexWildcardPort, regexPlainHost),
				"subMatchWeight 4 (wildcard-with-port) > 3 (regex-plain-host) — wildcard-with-port wins by integer comparison")
		})

		t.Run("plain-host route (0x02) beats wildcard-host route (0x00) at same path — simple common case", func(t *testing.T) {
			plainHost := makeRoute(model.KongRoute{ID: "r-plain", Paths: []string{"/api"}, Hosts: []string{"payments.internal.example.com"}})
			wildcardHost := makeRoute(model.KongRoute{ID: "r-wildcard", Paths: []string{"/api"}, Hosts: []string{"*.internal.example.com"}})
			expectIntB(t, plainHost.SubMatchWeight, 2, "Plain host, no regex → only PLAIN_HOSTS_ONLY (bit 1) = 0x02 = 2")
			expectIntB(t, wildcardHost.SubMatchWeight, 0, "Wildcard host (no port), no regex → no bits set → subMatchWeight = 0")
			expectLessThanZeroB(t, router.CompareRoutes(plainHost, wildcardHost),
				"Plain-host route (subMatchWeight=2) must beat wildcard-host route (subMatchWeight=0)")
		})

		t.Run("when subMatchWeight is equal, header count is the next tiebreaker (not regex_priority)", func(t *testing.T) {
			withHeader := makeRoute(model.KongRoute{
				ID:      "r-header",
				Paths:   []string{"/api"},
				Hosts:   []string{"api.example.com"},
				Headers: model.Headers{model.HeaderConstraint{Name: "x-env", Values: []string{"prod"}}},
			})
			noHeader := makeRoute(model.KongRoute{ID: "r-no-header", Paths: []string{"/api"}, Hosts: []string{"api.example.com"}})
			expectIntB(t, withHeader.SubMatchWeight, 2,
				"Plain host with header constraint → subMatchWeight = 0x02 (same as next route)")
			expectIntB(t, noHeader.SubMatchWeight, 2, "Plain host with no header constraint → subMatchWeight = 0x02")
			expectLessThanZeroB(t, router.CompareRoutes(withHeader, noHeader),
				"Tie on subMatchWeight: route with header constraint wins via header-count tier (tier 2)")
		})
	})

	// ─── simulateRequest – HAS_WILDCARD_HOST_PORT explanation (Gap #1 deep coverage) ──
	t.Run("simulateRequest – explanation text for HAS_WILDCARD_HOST_PORT ordering (Gap #1)", func(t *testing.T) {
		t.Run("explanation mentions HAS_WILDCARD_HOST_PORT when wildcard-with-port beats wildcard-without-port", func(t *testing.T) {
			withPort := makeRoute(model.KongRoute{ID: "r-with-port", Name: "wildcard-ported", Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			withoutPort := makeRoute(model.KongRoute{ID: "r-without-port", Name: "wildcard-unported", Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			sorted := router.SortRoutes([]*router.MarshalledRoute{withPort, withoutPort})
			result := router.SimulateRequest(sorted, router.SimRequest{Method: "GET", Host: "foo.example.com:8080", Path: "/api"})
			text := strings.Join(result.Explanation(), " ")
			lower := strings.ToLower(text)
			expectBoolB(t,
				strings.Contains(lower, "wildcard") || strings.Contains(lower, "port") || strings.Contains(lower, "submatch"),
				true,
				"Explanation for HAS_WILDCARD_HOST_PORT ordering must mention port, wildcard, or submatch_weight (text: "+text+")")
		})

		t.Run("wildcard-with-port wins the simulation when both routes match a ported request", func(t *testing.T) {
			withPort := makeRoute(model.KongRoute{ID: "r-with-port", Name: "ported", Paths: []string{"/api"}, Hosts: []string{"*.example.com:8080"}})
			withoutPort := makeRoute(model.KongRoute{ID: "r-without-port", Name: "unported", Paths: []string{"/api"}, Hosts: []string{"*.example.com"}})
			sorted := router.SortRoutes([]*router.MarshalledRoute{withPort, withoutPort})
			result := router.SimulateRequest(sorted, router.SimRequest{Method: "GET", Host: "foo.example.com:8080", Path: "/api"})
			const msg = "Wildcard-with-port (HAS_WILDCARD_HOST_PORT, subMatchWeight=4) must win over wildcard-without-port (subMatchWeight=0)"
			if result.Winner == nil {
				t.Fatalf("%s: got winner nil (undefined), want %q", msg, "r-with-port")
			}
			expectStrB(t, result.Winner.Route.ID, "r-with-port", msg)
		})
	})

	// IPv4 / CIDR utilities. Mirrors Kong's lua-resty-ipmatcher behaviour used
	// in create_range_f (traditional.lua#L279-L284).
	t.Run("parseIpv4 – converts dotted-decimal to 32-bit integer", func(t *testing.T) {
		t.Run("parses 0.0.0.0 as 0", func(t *testing.T) {
			expectIPv4B(t, "0.0.0.0", 0, "0.0.0.0 must equal integer 0")
		})

		t.Run("parses 255.255.255.255 as 0xFFFFFFFF (4294967295)", func(t *testing.T) {
			expectIPv4B(t, "255.255.255.255", 0xFFFFFFFF, "255.255.255.255 is the all-ones address (max IPv4)")
		})

		t.Run("parses 10.0.0.1 correctly", func(t *testing.T) {
			// 10*2^24 + 0*2^16 + 0*2^8 + 1 = 167772161
			expectIPv4B(t, "10.0.0.1", 167772161, "10.0.0.1 = 0x0A000001 = 167772161")
		})

		t.Run("parses 192.168.1.100 correctly", func(t *testing.T) {
			// 192*2^24 + 168*2^16 + 1*2^8 + 100
			expected := uint32(192)<<24 + uint32(168)<<16 + uint32(1)<<8 + 100
			expectIPv4B(t, "192.168.1.100", expected, "192.168.1.100 must be parsed to its 32-bit representation")
		})

		t.Run("returns null for an IPv6 address (not dotted-decimal)", func(t *testing.T) {
			expectIPv4NullB(t, "::1", "IPv6 addresses must return null – CIDR utils only support IPv4")
		})

		t.Run("returns null for a malformed address with too few octets", func(t *testing.T) {
			expectIPv4NullB(t, "10.0.1", "Three-octet string is not a valid IPv4 address")
		})

		t.Run("returns null for an octet out of range", func(t *testing.T) {
			expectIPv4NullB(t, "10.0.0.256", "Octet 256 is out of [0,255] range")
		})

		t.Run("returns null for an empty string", func(t *testing.T) {
			expectIPv4NullB(t, "", "Empty string is not a valid IPv4 address")
		})

		// net/netip enforces strict RFC 6943 syntax and rejects a leading
		// zero in any octet. Kong's own IP matching (lua-resty-ipmatcher, a
		// tonumber-based parser) and the TS predecessor (Number(part)) both
		// accept it, so a route CIDR/IP written this way must still parse.
		t.Run("accepts a leading-zero octet (lenient, matches Kong's own parser)", func(t *testing.T) {
			expectIPv4B(t, "010.0.0.1", mustIPv4B(t, "10.0.0.1"), "010.0.0.1 must parse the same as 10.0.0.1")
		})

		t.Run("accepts leading zeros in multiple octets", func(t *testing.T) {
			expectIPv4B(t, "010.000.000.001", mustIPv4B(t, "10.0.0.1"), "010.000.000.001 must parse the same as 10.0.0.1")
		})

		t.Run("still returns null when a leading-zero octet is out of range", func(t *testing.T) {
			expectIPv4NullB(t, "010.0.0.256", "Octet 256 is out of range even after stripping the leading zero elsewhere")
		})
	})

	t.Run("cidrToRange – CIDR notation to inclusive [lo, hi] range", func(t *testing.T) {
		checkRangeB := func(t *testing.T, cidr, validMsg string, wantLo uint32, loMsg string, wantHi uint32, hiMsg string) {
			t.Helper()
			lo, hi, ok := router.CIDRToRange(cidr)
			if !ok {
				t.Fatalf("%s: got null, want non-null", validMsg)
			}
			if lo != wantLo {
				t.Errorf("%s: got %d, want %d", loMsg, lo, wantLo)
			}
			if hi != wantHi {
				t.Errorf("%s: got %d, want %d", hiMsg, hi, wantHi)
			}
		}
		expectNullRangeB := func(t *testing.T, cidr, msg string) {
			t.Helper()
			if lo, hi, ok := router.CIDRToRange(cidr); ok {
				t.Errorf("%s: got [%d, %d], want null", msg, lo, hi)
			}
		}

		t.Run("parses 10.0.0.0/8 as the full 10.x.x.x range", func(t *testing.T) {
			lo := mustIPv4B(t, "10.0.0.0")
			hi := mustIPv4B(t, "10.255.255.255")
			checkRangeB(t, "10.0.0.0/8", "10.0.0.0/8 must produce a valid range",
				lo, "10.0.0.0/8 lo must be 10.0.0.0",
				hi, "10.0.0.0/8 hi must be 10.255.255.255")
		})

		t.Run("parses 192.168.0.0/24 as the standard /24 range", func(t *testing.T) {
			checkRangeB(t, "192.168.0.0/24", "192.168.0.0/24 must produce a valid range",
				mustIPv4B(t, "192.168.0.0"), "192.168.0.0/24 lo must be 192.168.0.0",
				mustIPv4B(t, "192.168.0.255"), "192.168.0.0/24 hi must be 192.168.0.255")
		})

		t.Run("parses /32 as a single-host range ([host, host])", func(t *testing.T) {
			host := mustIPv4B(t, "10.1.2.3")
			checkRangeB(t, "10.1.2.3/32", "10.1.2.3/32 must parse to a valid range",
				host, "/32 lo must equal the host address",
				host, "/32 hi must equal the host address (single-host range)")
		})

		t.Run("parses /0 as the entire IPv4 address space", func(t *testing.T) {
			checkRangeB(t, "0.0.0.0/0", "0.0.0.0/0 must produce a valid range",
				0, "0.0.0.0/0 lo must be 0",
				0xFFFFFFFF, "0.0.0.0/0 hi must be 0xFFFFFFFF")
		})

		t.Run("accepts a leading-zero octet in the network address", func(t *testing.T) {
			checkRangeB(t, "010.0.0.0/8", "010.0.0.0/8 must parse the same as 10.0.0.0/8",
				mustIPv4B(t, "10.0.0.0"), "010.0.0.0/8 lo must be 10.0.0.0",
				mustIPv4B(t, "10.255.255.255"), "010.0.0.0/8 hi must be 10.255.255.255")
		})

		t.Run("accepts a leading-zero prefix length", func(t *testing.T) {
			checkRangeB(t, "192.168.0.0/024", "192.168.0.0/024 must parse the same as 192.168.0.0/24",
				mustIPv4B(t, "192.168.0.0"), "192.168.0.0/024 lo must be 192.168.0.0",
				mustIPv4B(t, "192.168.0.255"), "192.168.0.0/024 hi must be 192.168.0.255")
		})

		t.Run("returns null for an IPv6 CIDR", func(t *testing.T) {
			expectNullRangeB(t, "::1/128", "IPv6 CIDRs must return null – conservative: callers assume potential overlap")
		})

		t.Run("returns null for a string without a slash", func(t *testing.T) {
			expectNullRangeB(t, "10.0.0.1", "A plain IP string without / must return null from cidrToRange")
		})

		t.Run("returns null for prefix length > 32", func(t *testing.T) {
			expectNullRangeB(t, "10.0.0.0/33", "Prefix length 33 is out of range and must return null")
		})
	})

	t.Run("ipsCanOverlap – checks whether two IP/CIDR constraints could match the same address", func(t *testing.T) {
		t.Run("returns true for identical plain IPs", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("10.0.0.1", "10.0.0.1"), true, "Identical IPs always overlap")
		})

		t.Run("returns false for two different plain IPs", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("10.0.0.1", "10.0.0.2"), false, "Different plain IPs never overlap")
		})

		t.Run("returns true when a plain IP falls inside a CIDR", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("10.0.0.5", "10.0.0.0/24"), true, "10.0.0.5 is inside 10.0.0.0/24")
		})

		t.Run("returns false when a plain IP is outside a CIDR", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("10.1.0.1", "10.0.0.0/24"), false, "10.1.0.1 is outside 10.0.0.0/24")
		})

		t.Run("returns true for two overlapping CIDRs (supernet/subnet relationship)", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("10.0.0.0/8", "10.1.0.0/16"), true, "10.1.0.0/16 is entirely within 10.0.0.0/8")
		})

		t.Run("returns false for two non-overlapping CIDRs", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("192.168.0.0/24", "192.168.1.0/24"), false, "192.168.0.x and 192.168.1.x are disjoint")
		})

		t.Run("returns true (conservative) for an IPv6 address", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("::1", "10.0.0.1"), true,
				"IPv6 addresses cannot be parsed as IPv4 – conservative overlap assumed")
		})

		t.Run("returns true (conservative) for an IPv6 CIDR", func(t *testing.T) {
			expectBoolB(t, router.IPsCanOverlap("::1/128", "10.0.0.1"), true,
				"IPv6 CIDRs cannot be parsed – conservative overlap assumed")
		})
	})

	// matchSrcDstEntry (exercised indirectly via MatchRoute's Sources check)
	// must tolerate leading-zero IPv4 octets the same way parseIpv4/
	// cidrToRange do, for both the exact-match and CIDR-match branches.
	t.Run("matchRoute – Sources IP matching tolerates leading-zero octets", func(t *testing.T) {
		t.Run("exact-match entry with a leading-zero octet matches a normalized request IP", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{
				Paths:   []string{"/api"},
				Sources: []model.IPPort{{IP: "010.0.0.1"}},
			})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Path: "/api", SourceIP: ptr("10.0.0.1")}),
				true,
				`Sources entry "010.0.0.1" must match request source IP "10.0.0.1" (leading zero tolerated)`)
		})

		t.Run("exact-match entry with a leading-zero octet does not match a different IP", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{
				Paths:   []string{"/api"},
				Sources: []model.IPPort{{IP: "010.0.0.1"}},
			})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Path: "/api", SourceIP: ptr("10.0.0.2")}),
				false,
				`Sources entry "010.0.0.1" must not match a genuinely different source IP`)
		})

		t.Run("CIDR entry with a leading-zero network address matches an IP inside the range", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{
				Paths:   []string{"/api"},
				Sources: []model.IPPort{{IP: "010.0.0.0/8"}},
			})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Path: "/api", SourceIP: ptr("10.5.5.5")}),
				true,
				`Sources entry "010.0.0.0/8" must match "10.5.5.5" (leading zero tolerated, same as Kong's own CIDR parsing)`)
		})

		t.Run("CIDR entry with a leading-zero network address does not match an IP outside the range", func(t *testing.T) {
			mr := makeRoute(model.KongRoute{
				Paths:   []string{"/api"},
				Sources: []model.IPPort{{IP: "010.0.0.0/8"}},
			})
			expectBoolB(t,
				matchB(mr, router.SimRequest{Method: "GET", Path: "/api", SourceIP: ptr("11.0.0.1")}),
				false,
				`Sources entry "010.0.0.0/8" must not match "11.0.0.1", which is outside 10.0.0.0/8`)
		})
	})

	t.Run("ipPortListsOverlap – OR-of-ANDs across entry pairs", func(t *testing.T) {
		t.Run("returns true when both lists are empty (vacuously: no entries to be disjoint)", func(t *testing.T) {
			// Empty source list in Kong means "no constraint applied" which would never
			// reach the matcher; but for safety verify the function is stable.
			expectBoolB(t, router.IPPortListsOverlap([]model.IPPort{}, []model.IPPort{}), false,
				"Empty lists have no pairs to check – returns false (no overlap possible)")
		})

		t.Run("returns true when both lists have identical IP+port entries", func(t *testing.T) {
			a := []model.IPPort{{IP: "10.0.0.1", Port: 80}}
			b := []model.IPPort{{IP: "10.0.0.1", Port: 80}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), true, "Identical IP+port entries trivially overlap")
		})

		t.Run("returns false when ports differ (port-disjoint entries)", func(t *testing.T) {
			a := []model.IPPort{{IP: "10.0.0.1", Port: 80}}
			b := []model.IPPort{{IP: "10.0.0.1", Port: 443}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), false,
				"Same IP but different ports: no single connection can satisfy both → disjoint")
		})

		t.Run("returns false when IPs are in disjoint CIDRs", func(t *testing.T) {
			a := []model.IPPort{{IP: "10.0.0.0/24"}}
			b := []model.IPPort{{IP: "10.0.1.0/24"}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), false, "10.0.0.x/24 and 10.0.1.x/24 are disjoint address blocks")
		})

		t.Run("returns true when one entry has no IP (wildcard) and other has an IP", func(t *testing.T) {
			a := []model.IPPort{{Port: 80}} // no IP → wildcard
			b := []model.IPPort{{IP: "10.0.0.1", Port: 80}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), true,
				"Wildcard IP (absent) on one side always overlaps with any specific IP on the other")
		})

		t.Run("returns true when one entry has no port (wildcard) and other has a port", func(t *testing.T) {
			a := []model.IPPort{{IP: "10.0.0.1"}} // no port → wildcard
			b := []model.IPPort{{IP: "10.0.0.1", Port: 80}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), true,
				"Wildcard port (absent) on one side always overlaps with any specific port on the other")
		})

		t.Run("returns true when any single pair across multi-entry lists can overlap", func(t *testing.T) {
			// listA entry 0 is disjoint with listB entry 0 (port mismatch)
			// listA entry 1 overlaps with listB entry 0 (same IP, no port on either)
			a := []model.IPPort{
				{IP: "10.0.0.1", Port: 9000},
				{IP: "10.0.0.1"}, // wildcard port
			}
			b := []model.IPPort{{IP: "10.0.0.1", Port: 80}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), true,
				"At least one pair (entry 1 from A, entry 0 from B) can overlap → lists overlap")
		})

		t.Run("returns false when ALL pairs across multi-entry lists are disjoint", func(t *testing.T) {
			// Both entries in listA use port 80; listB only has port 443 → all pairs disjoint on port.
			a := []model.IPPort{
				{IP: "10.0.0.1", Port: 80},
				{IP: "10.0.0.2", Port: 80},
			}
			b := []model.IPPort{{IP: "10.0.0.1", Port: 443}}
			expectBoolB(t, router.IPPortListsOverlap(a, b), false,
				"All pairs have differing ports (80 vs 443) → all disjoint → no overlap")
		})
	})

	t.Run("matchRoute – SNI constraint (stream-route explicit simulation mode)", func(t *testing.T) {
		t.Run("matches when request.sni is undefined (static-analysis mode: SNI check skipped)", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-sni", Paths: []string{"/tcp"}, SNIs: []string{"api.example.com"}})
			// No sni on request → conservative, treat as matching
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp"}),
				true,
				"When request.sni is undefined the SNI check is skipped (static-analysis mode)")
		})

		t.Run("matches when request.sni is in the route SNI set", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-sni", Paths: []string{"/tcp"}, SNIs: []string{"api.example.com", "admin.example.com"}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SNI: ptr("api.example.com")}),
				true,
				"request.sni matching a value in route.snis must produce a match")
		})

		t.Run("does not match when request.sni is absent from the route SNI set", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-sni", Paths: []string{"/tcp"}, SNIs: []string{"api.example.com"}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SNI: ptr("other.example.com")}),
				false,
				"request.sni not in route.snis must fail the SNI constraint")
		})

		t.Run("strips trailing dot from FQDN SNI before comparing (Kong normalisation)", func(t *testing.T) {
			// Kong strips the trailing dot in marshall_route: traditional.lua#L511-L513
			r := makeRoute(model.KongRoute{ID: "r-sni-fqdn", Paths: []string{"/tcp"}, SNIs: []string{"api.example.com."}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SNI: ptr("api.example.com")}),
				true,
				"Trailing dot in route SNI FQDN must be stripped before comparison – should match")
		})

		t.Run("matches any SNI when route has no snis list", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-no-sni", Paths: []string{"/tcp"}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SNI: ptr("anything.example.com")}),
				true,
				"A route with no snis constraint matches any SNI value")
		})
	})

	t.Run("matchRoute – source IP/port constraint", func(t *testing.T) {
		t.Run("matches when request.sourceIp is undefined (static-analysis mode: source check skipped)", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-src", Paths: []string{"/tcp"}, Sources: []model.IPPort{{IP: "10.0.0.1", Port: 80}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp"}),
				true,
				"When request.sourceIp is undefined the source constraint is skipped")
		})

		t.Run("matches on exact IP match with no port constraint on the entry", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-src", Paths: []string{"/tcp"}, Sources: []model.IPPort{{IP: "10.0.0.5"}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("10.0.0.5")}),
				true,
				"Exact IP match with no port constraint on route must succeed")
		})

		t.Run("matches when source IP is inside a CIDR range", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-src-cidr", Paths: []string{"/tcp"}, Sources: []model.IPPort{{IP: "10.0.0.0/8"}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("10.5.6.7")}),
				true,
				"Source IP 10.5.6.7 must match CIDR 10.0.0.0/8")
		})

		t.Run("does not match when source IP is outside the CIDR range", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-src-cidr", Paths: []string{"/tcp"}, Sources: []model.IPPort{{IP: "10.0.0.0/24"}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("10.0.1.1")}),
				false,
				"Source IP 10.0.1.1 is outside 10.0.0.0/24 and must not match")
		})

		t.Run("matches when both IP and port satisfy the entry constraint", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-src-ip-port", Paths: []string{"/tcp"}, Sources: []model.IPPort{{IP: "10.0.0.1", Port: 1234}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("10.0.0.1"), SourcePort: ptr(1234)}),
				true,
				"Matching IP and matching port must satisfy the IP+port entry")
		})

		t.Run("does not match when IP matches but port differs", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-src-ip-port", Paths: []string{"/tcp"}, Sources: []model.IPPort{{IP: "10.0.0.1", Port: 1234}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("10.0.0.1"), SourcePort: ptr(9999)}),
				false,
				"Port mismatch (1234 vs 9999) must fail the source constraint")
		})

		t.Run("matches on wildcard entry (no ip, no port in entry) with any source", func(t *testing.T) {
			// Kong: when entry has no ip and no port both ip_ok and port check pass immediately.
			r := makeRoute(model.KongRoute{ID: "r-src-wildcard", Paths: []string{"/tcp"}, Sources: []model.IPPort{{}}}) // wildcard entry
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("1.2.3.4"), SourcePort: ptr(9999)}),
				true,
				"A source entry with no IP and no port constraint matches any source")
		})

		t.Run("matches when any entry in a multi-entry list satisfies the source (OR semantics)", func(t *testing.T) {
			r := makeRoute(model.KongRoute{
				ID:      "r-src-multi",
				Paths:   []string{"/tcp"},
				Sources: []model.IPPort{{IP: "10.0.0.1", Port: 80}, {IP: "192.168.0.0/16"}},
			})
			// Second entry (CIDR, no port) must match 192.168.5.5
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", SourceIP: ptr("192.168.5.5")}),
				true,
				"192.168.5.5 matches the CIDR entry 192.168.0.0/16 (OR semantics across source entries)")
		})
	})

	t.Run("matchRoute – destination IP/port constraint", func(t *testing.T) {
		t.Run("matches when request.destIp is undefined (static-analysis mode)", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-dst", Paths: []string{"/tcp"}, Destinations: []model.IPPort{{IP: "172.16.0.1", Port: 443}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp"}),
				true,
				"When request.destIp is undefined the destination constraint is skipped")
		})

		t.Run("matches when destination IP+port satisfy the entry", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-dst", Paths: []string{"/tcp"}, Destinations: []model.IPPort{{IP: "172.16.0.1", Port: 443}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", DestIP: ptr("172.16.0.1"), DestPort: ptr(443)}),
				true,
				"Matching dest IP and port must satisfy the destination entry")
		})

		t.Run("does not match when destination IP is outside the constraint", func(t *testing.T) {
			r := makeRoute(model.KongRoute{ID: "r-dst-cidr", Paths: []string{"/tcp"}, Destinations: []model.IPPort{{IP: "172.16.0.0/24", Port: 443}}})
			expectBoolB(t,
				matchB(r, router.SimRequest{Method: "GET", Host: "example.com", Path: "/tcp", DestIP: ptr("172.16.1.5"), DestPort: ptr(443)}),
				false,
				"172.16.1.5 is outside 172.16.0.0/24 and must not match the destination constraint")
		})
	})
}
