/**
 * Tests for the Kong Route Analyzer (src/analyzer.ts).
 *
 * Tests validate –
 * - Suspicious regex pattern detection (glob-style `*` in PCRE paths)
 * - Collision detection via candidate simulation
 * - Sibling namespace overlap detection
 * - Severity classification
 * - Suggestion generation
 */

import { describe, expect, it } from 'bun:test';

import {
	analyzeRoutes,
	detectSuspiciousRegexIssues,
	generateCandidateRequests,
	suggestRegexFix,
} from '../src/analyzer.ts';
import { marshalRoute } from '../src/router.ts';
import type { KonnectData, KongRoute, RouterFlavor } from '../src/types.ts';

/** Builds a minimal KonnectData payload for analyzer tests. */
function makeConfig(routes: KongRoute[], flavor: RouterFlavor = 'traditional'): KonnectData {
	return {
		routes,
		services: new Map(),
		routerFlavor: flavor,
	};
}

/** Builds a minimal KongRoute. */
function route(id: string, name: string, paths: string[], overrides: Partial<KongRoute> = {}): KongRoute {
	return {
		id,
		name,
		paths,
		regex_priority: 0,
		created_at: 1_700_000_000,
		...overrides,
	};
}

describe('detectSuspiciousRegexIssues – catches glob-style * in PCRE paths', () => {
	it("flags ~/payments/* because trailing /* is a PCRE quantifier on '/', not a glob", () => {
		const issues = detectSuspiciousRegexIssues('~/payments/*');
		expect(
			issues.length,
			"~/payments/* must be flagged: * quantifies the previous '/' char, not 'anything'",
		).toBeGreaterThan(0);
	});

	it('flags ~/payments-v2/* for the same reason', () => {
		const issues = detectSuspiciousRegexIssues('~/payments-v2/*');
		expect(issues.length, '~/payments-v2/* must also be flagged – same glob-style * mistake').toBeGreaterThan(0);
	});

	it('flags ~/foo/*/bar because /* in the middle also misuses *', () => {
		const issues = detectSuspiciousRegexIssues('~/foo/*/bar');
		expect(issues.length, 'A /* in the middle of a regex path is equally suspicious').toBeGreaterThan(0);
	});

	it('flags ~/payments* because trailing * after a word char quantifies that char', () => {
		const issues = detectSuspiciousRegexIssues('~/payments*');
		expect(
			issues.length,
			"~/payments* means '/ep' followed by zero-or-more 'p' chars, not 'anything under /payments'",
		).toBeGreaterThan(0);
	});

	it('does NOT flag ~/payments(?:/.*)?$ which is a correctly written anchored regex', () => {
		const issues = detectSuspiciousRegexIssues('~/payments(?:/.*)?$');
		expect(issues.length, '~/payments(?:/.*)?$ is a safe, correctly anchored pattern and should not be flagged').toBe(
			0,
		);
	});

	it('does NOT flag a plain (non-regex) path /payments/*', () => {
		const issues = detectSuspiciousRegexIssues('/payments/*');
		expect(
			issues.length,
			'/payments/* does not start with ~ so it is not a regex path; should not be flagged by this function',
		).toBe(0);
	});

	it('returns an empty array for a well-formed regex like ~/api/v[0-9]+/.*', () => {
		const issues = detectSuspiciousRegexIssues('~/api/v[0-9]+/.*');
		expect(
			issues,
			'A properly written regex path with .* (not /*) should not trigger the suspicious pattern detector',
		).toHaveLength(0);
	});
});

describe('suggestRegexFix – generates safer replacement patterns', () => {
	it('suggests ~/payments(?:/.*)?$ for ~/payments/*', () => {
		const fix = suggestRegexFix('~/payments/*');
		expect(fix, 'The safe fix for ~/payments/* should anchor the pattern and use (?:/.*)? to allow sub-paths').toBe(
			'~/payments(?:/.*)?$',
		);
	});

	it('suggests ~/payments-v2(?:/.*)?$ for ~/payments-v2/*', () => {
		const fix = suggestRegexFix('~/payments-v2/*');
		expect(fix, 'The safe fix for ~/payments-v2/* should match the entire /payments-v2 sub-tree').toBe(
			'~/payments-v2(?:/.*)?$',
		);
	});

	it('returns undefined for a path that is not flagged', () => {
		const fix = suggestRegexFix('~/payments(?:/.*)?$');
		expect(fix, 'No suggestion should be generated for a path that is already safe').toBeUndefined();
	});

	it('returns undefined for a plain path (no ~ prefix)', () => {
		const fix = suggestRegexFix('/api');
		expect(fix, 'Plain paths are not regex paths; no fix suggestion is applicable').toBeUndefined();
	});
});

describe('generateCandidateRequests – produces covering test paths from route patterns', () => {
	it("generates at least one path derived from each route's path patterns", () => {
		const routes = [
			marshalRoute(route('r1', 'payments', ['~/payments/*'])),
			marshalRoute(route('r2', 'payments-v2', ['~/payments-v2/*'])),
		];
		const candidates = generateCandidateRequests(routes);
		expect(candidates.length, 'At least one candidate path must be generated per route').toBeGreaterThanOrEqual(2);
	});

	it('candidates include child paths (e.g. /payments/extra) to trigger deeper collisions', () => {
		const routes = [marshalRoute(route('r1', 'payments', ['/payments']))];
		const candidates = generateCandidateRequests(routes);
		const paths = candidates.map((c) => c.path);
		expect(
			paths.some((p) => p.startsWith('/payments/')),
			'Candidate generation should include child paths like /payments/extra to test deeper collisions',
		).toBe(true);
	});

	it('candidates are deduplicated (no duplicate paths)', () => {
		const routes = [marshalRoute(route('r1', 'a', ['/api'])), marshalRoute(route('r2', 'b', ['/api']))];
		const candidates = generateCandidateRequests(routes);
		const paths = candidates.map((c) => c.path);
		const unique = new Set(paths);
		expect(unique.size, 'Generated candidates must be deduplicated to avoid redundant simulation').toBe(paths.length);
	});
});

describe('analyzeRoutes – the motivating ~/payments/* vs ~/payments-v2/* example', () => {
	const config = makeConfig([
		route('r-payments', 'payments', ['~/payments/*'], {
			regex_priority: 0,
			created_at: 1_700_000_000,
		}),
		route('r-payments-v2', 'payments-v2', ['~/payments-v2/*'], {
			regex_priority: 0,
			created_at: 1_710_000_000,
		}),
	]);

	it('produces at least one finding for the payments / payments-v2 pair', () => {
		const findings = analyzeRoutes(config);
		expect(
			findings.length,
			'The ~/payments/* vs ~/payments-v2/* pair is a textbook shadowing case and must produce findings',
		).toBeGreaterThan(0);
	});

	it('produces a suspicious_regex finding for ~/payments/* (glob-style * usage)', () => {
		const findings = analyzeRoutes(config);
		const suspicious = findings.filter((f) => f.type === 'suspicious_regex');
		expect(
			suspicious.length,
			'Both ~/payments/* and ~/payments-v2/* should be flagged as suspicious regex patterns',
		).toBeGreaterThanOrEqual(1);
	});

	it('produces a shadowing or collision finding for the pair', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			collision.length,
			'The overlapping regex paths must produce a shadowing or collision finding',
		).toBeGreaterThan(0);
	});

	it('collision finding includes at least one sample request path', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.find((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			collision?.samples.length ?? 0,
			'A collision finding must include at least one sample request path to demonstrate the problem',
		).toBeGreaterThan(0);
	});

	it('collision finding includes suggestions for safer replacement patterns', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.find((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			collision?.suggestions.length ?? 0,
			'Each collision finding should suggest at least one safer replacement pattern',
		).toBeGreaterThan(0);
	});

	it('suggestions for ~/payments/* include an anchored alternative ending with $', () => {
		const findings = analyzeRoutes(config);
		const allSuggestions = findings.flatMap((f) => f.suggestions);
		expect(
			allSuggestions.some((s) => s.includes('$')),
			'At least one suggestion should use a $ end anchor to prevent unintentional prefix matching',
		).toBe(true);
	});

	it('findings are returned sorted with highest severity first', () => {
		const findings = analyzeRoutes(config);
		const order: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
		for (let i = 1; i < findings.length; i++) {
			expect(
				(order[findings[i - 1]!.severity] ?? 99) <= (order[findings[i]!.severity] ?? 99),
				`Finding at index ${i - 1} (${findings[i - 1]!.severity}) should be at least as severe as finding at ${i} (${findings[i]!.severity})`,
			).toBe(true);
		}
	});
});

describe('analyzeRoutes – plain prefix sibling overlap /payments vs /payments-v2', () => {
	const config = makeConfig([
		route('r1', 'payments', ['/payments'], { created_at: 1_700_000_000 }),
		route('r2', 'payments-v2', ['/payments-v2'], { created_at: 1_710_000_000 }),
	]);

	it('detects that /payments prefix matches /payments-v2 requests (sibling overlap)', () => {
		const findings = analyzeRoutes(config);
		const overlap = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlap.length,
			"Plain prefix /payments matches /payments-v2 because startsWith('/payments') is true for /payments-v2",
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – clean configuration produces no high-severity findings', () => {
	const config = makeConfig([
		route('r1', 'payments', ['~/payments(?:/.*)?$']),
		route('r2', 'payments-v2', ['~/payments-v2(?:/.*)?$']),
	]);

	it('produces no shadowing or collision findings when routes use safe anchored patterns', () => {
		const findings = analyzeRoutes(config);
		const high = findings.filter((f) => (f.type === 'shadowing' || f.type === 'collision') && f.severity === 'HIGH');
		expect(
			high.length,
			'Correctly anchored regex paths ~/payments(?:/.*)?$ and ~/payments-v2(?:/.*)?$ should not shadow each other',
		).toBe(0);
	});
});

describe('analyzeRoutes – routes for different services are rated HIGH severity', () => {
	const config = makeConfig([
		route('r1', 'payments', ['~/payments/*'], {
			service: { id: 'svc-a' },
			created_at: 1_700_000_000,
		}),
		route('r2', 'payments-v2', ['~/payments-v2/*'], {
			service: { id: 'svc-b' },
			created_at: 1_710_000_000,
		}),
	]);
	// Add services to the map
	const configWithServices: KonnectData = {
		...config,
		services: new Map([
			['svc-a', { id: 'svc-a', name: 'service-a' }],
			['svc-b', { id: 'svc-b', name: 'service-b' }],
		]),
	};

	it('rates collision as HIGH when routes point to different backend services', () => {
		const findings = analyzeRoutes(configWithServices);
		const highCollisions = findings.filter(
			(f) => (f.type === 'shadowing' || f.type === 'collision') && f.severity === 'HIGH',
		);
		expect(
			highCollisions.length,
			'Traffic misrouting to the wrong backend service is a HIGH severity finding',
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – expressions flavor emits no false positives from anchor differences', () => {
	// Under expressions/traditional_compatible, regex paths get ^ anchored.
	// ~/payments-v2/* becomes ^/payments-v2/* which still matches /payments-v2/... correctly.
	const config = makeConfig(
		[
			route('r1', 'payments', ['~/payments/*'], { created_at: 1_700_000_000 }),
			route('r2', 'payments-v2', ['~/payments-v2/*'], { created_at: 1_710_000_000 }),
		],
		'traditional_compatible',
	);

	it('still produces suspicious_regex findings under traditional_compatible flavor', () => {
		const findings = analyzeRoutes(config, { flavor: 'traditional_compatible' });
		const suspicious = findings.filter((f) => f.type === 'suspicious_regex');
		expect(suspicious.length, 'Suspicious regex linting should fire regardless of router flavor').toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – routes with multiple paths are split correctly', () => {
	// A single KongRoute with two regex paths is internally split into two
	// MarshalledRoutes so that max_uri_length scoring works per-path.
	const config = makeConfig([
		{
			...route('r1', 'multi-path', ['~/payments/*', '~/payments-v2/*']),
		},
		route('r2', 'other', ['/other'], { created_at: 1_710_000_000 }),
	]);

	it('produces findings even when a route has multiple paths', () => {
		const findings = analyzeRoutes(config);
		expect(
			findings.length,
			'Multi-path routes must be split before analysis – findings should still be produced',
		).toBeGreaterThan(0);
	});

	it('suspicious_regex is reported for both paths of a multi-path route', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const suspicious = findings.filter((f) => f.type === 'suspicious_regex');
		const involvedPaths = suspicious.flatMap((f) => f.routes.flatMap((r) => r.paths ?? []));
		expect(
			involvedPaths.some((p) => p === '~/payments/*'),
			'~/payments/* must be individually flagged even when it shares a KongRoute with ~/payments-v2/*',
		).toBe(true);
	});
});

describe('analyzeRoutes – universal_matcher INFO findings (includeInfo: true)', () => {
	// A route with ~.* matches every request URL – Kong's traditional router
	// does not add a ^ anchor, so the pattern matches at any position.
	const config = makeConfig([
		route('r1', 'catch-all', ['~.*'], { created_at: 1_700_000_000 }),
		route('r2', 'specific', ['/api/v1'], { created_at: 1_710_000_000 }),
	]);

	it('produces a HIGH suspicious_regex finding for ~.* (probe-based universal matcher catch)', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const suspicious = findings.filter((f) => f.type === 'suspicious_regex');
		expect(
			suspicious.length,
			'~.* is not caught by pattern-list rules but must be caught by the probe-based universal matcher check',
		).toBeGreaterThan(0);
		expect(suspicious[0]?.severity, 'An accidental universal-matcher regex should be rated HIGH, not MEDIUM').toBe(
			'HIGH',
		);
	});

	it('produces a universal_matcher INFO finding for a plain / catch-all when includeInfo=true', () => {
		const plainCatchAll = makeConfig([route('r1', 'spa-frontend', ['/']), route('r2', 'api', ['/api/v1'])]);
		const findings = analyzeRoutes(plainCatchAll, { includeInfo: true });
		const info = findings.filter((f) => f.type === 'universal_matcher');
		expect(
			info.length,
			'A plain / route is a universal catch-all and should produce a universal_matcher INFO finding',
		).toBeGreaterThan(0);
	});

	it('does NOT produce universal_matcher findings when includeInfo=false', () => {
		const plainCatchAll = makeConfig([route('r1', 'spa-frontend', ['/']), route('r2', 'api', ['/api/v1'])]);
		const findings = analyzeRoutes(plainCatchAll, { includeInfo: false });
		const info = findings.filter((f) => f.type === 'universal_matcher');
		expect(info.length, 'INFO findings must be suppressed when includeInfo is false').toBe(0);
	});
});

describe('suggestRegexFix – word-char trailing * pattern (~/payments*)', () => {
	it('suggests an anchored alternative for ~/payments* (trailing * after word char)', () => {
		const fix = suggestRegexFix('~/payments*');
		expect(fix, 'suggestRegexFix must return a non-empty suggestion for the ~/payments* pattern').toBeDefined();
		expect(fix, 'Suggestion should use $ end anchor to prevent unintentional prefix matching').toContain('$');
		expect(fix, 'Suggestion should preserve the /payments stem').toContain('/payments');
	});

	it('flags ~/payments* as suspicious (trailing * after word char quantifies that char)', () => {
		const issues = detectSuspiciousRegexIssues('~/payments*');
		expect(
			issues.length,
			"~/payments* must be flagged: trailing * quantifies 'p' (zero or more p's), not anything after /payments",
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – sibling overlap detected via a-paths-as-candidates branch', () => {
	// When route A's path can match route B's pattern (not just the reverse),
	// findSiblingOverlapSample exercises the second candidate-generation branch.
	const config = makeConfig([
		// r1 has a plain prefix /api that matches /api-v2 (the prefix of r2).
		route('r1', 'api-base', ['/api'], { created_at: 1_700_000_000 }),
		route('r2', 'api-v2', ['/api-v2'], { created_at: 1_710_000_000 }),
	]);

	it('detects that /api prefix shadows /api-v2 requests (a-as-candidate branch)', () => {
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlaps.length,
			'/api startsWith-matches /api-v2 so it must be flagged as a sibling overlap',
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – parent/child paths are NOT flagged as sibling collisions', () => {
	// /chat and /chat/history are a proper parent - child hierarchy.
	// Kong's max_uri_length tie-breaker handles this correctly: /chat/history
	// is longer so it wins for /chat/history requests, and /chat wins for
	// everything else. There is no ambiguity and no false bleed.
	it('does NOT flag /chat vs /chat/history as a sibling overlap', () => {
		const config = makeConfig([
			route('r1', 'adk-chat', ['/api/v1/chat'], { created_at: 1_740_000_000 }),
			route('r2', 'adk-history', ['/api/v1/chat/history'], { created_at: 1_740_000_000 }),
		]);
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlaps.length,
			'/chat and /chat/history are a parent - child hierarchy handled correctly by max_uri_length; must not be flagged',
		).toBe(0);
	});

	it('does NOT flag /api vs /api/v1 as a sibling overlap', () => {
		const config = makeConfig([
			route('r1', 'api-root', ['/api'], { created_at: 1_700_000_000 }),
			route('r2', 'api-v1', ['/api/v1'], { created_at: 1_710_000_000 }),
		]);
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlaps.length,
			'/api and /api/v1 are correctly ordered by path length; must not be flagged as a collision',
		).toBe(0);
	});

	it('still flags /payments vs /payments-v2 as a mid-segment bleed', () => {
		const config = makeConfig([
			route('r1', 'payments', ['/payments'], { created_at: 1_700_000_000 }),
			route('r2', 'payments-v2', ['/payments-v2'], { created_at: 1_710_000_000 }),
		]);
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlaps.length,
			'/payments bleeds into /payments-v2 mid-segment (the - is not a path separator); must still be flagged',
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – trailing-slash parent paths are NOT flagged as sibling collisions', () => {
	// A route with path /prefix/ (trailing slash) must be recognised as a
	// hierarchical ancestor of /prefix/child routes, not a sibling bleed.
	it('does NOT flag /ava-live-agent-api/ vs /ava-live-agent-api/ws', () => {
		const config = makeConfig([
			route('r1', 'health', ['/ava-live-agent-api/'], { created_at: 1_700_000_000 }),
			route('r2', 'ws', ['/ava-live-agent-api/ws'], { created_at: 1_710_000_000 }),
		]);
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlaps.length,
			'/ava-live-agent-api/ is the trailing-slash parent of /ava-live-agent-api/ws; must not be flagged',
		).toBe(0);
	});

	it('still flags /ws vs /ws-simple as a mid-segment bleed even with trailing-slash fix', () => {
		const config = makeConfig([
			route('r1', 'ws', ['/ava-live-agent-api/ws'], { created_at: 1_700_000_000 }),
			route('r2', 'ws-simple', ['/ava-live-agent-api/ws-simple'], { created_at: 1_710_000_000 }),
		]);
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(overlaps.length, '/ws bleeds into /ws-simple mid-segment; must still be flagged').toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – same-route self-collision is NOT flagged', () => {
	// A multi-path route is split into separate MarshalledRoutes per path.
	// If one path is a prefix of another on the same route, it must NOT be
	// reported as a collision — it's intentional within a single route config.
	it('does NOT flag a route whose own paths overlap each other (same route ID)', () => {
		const config = makeConfig([route('r1', 'multi-path', ['/api/v1', '/api/v1/extra'], { created_at: 1_700_000_000 })]);
		const findings = analyzeRoutes(config);
		const collisions = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(collisions.length, 'A route shadowing its own paths must not be reported as a collision').toBe(0);
	});
});

describe('analyzeRoutes – {variable} placeholder regex paths do not generate false positives', () => {
	// Kong routes sometimes use {id}-style template placeholders in regex paths.
	// In PCRE these are literal matches for the string "{id}" — not wildcards.
	// No real request sends "{id}" unencoded, so these routes cannot shadow
	// the plain-prefix parent route and must not be flagged.
	it('does NOT flag a {id}-style regex route as shadowing its plain-prefix parent', () => {
		const config = makeConfig([
			route('r1', 'agents-list', ['/api/v1/agents'], { created_at: 1_700_000_000 }),
			route('r2', 'agent-by-id', ['~/api/v1/agents/{id}/sources'], { created_at: 1_710_000_000 }),
		]);
		const findings = analyzeRoutes(config);
		const collisions = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			collisions.length,
			'~/api/v1/agents/{id}/sources uses a literal {id} in PCRE; must not shadow the plain prefix route',
		).toBe(0);
	});
});

describe('generateCandidateRequests – capture groups become id placeholders', () => {
	it('replaces ([^/]+) capture groups with "id" to produce a valid sample path', () => {
		const routes = [marshalRoute(route('r1', 'containers', ['~/api/containers/([^/]+)/items/([^/]+)']))];
		const candidates = generateCandidateRequests(routes);
		const paths = candidates.map((c) => c.path);
		// Must not contain empty-segment artifacts like ///
		expect(
			paths.every((p) => !p.includes('//')),
			'Candidate paths must not have consecutive slashes from empty capture groups',
		).toBe(true);
		// Must include a path with the id placeholder
		expect(
			paths.some((p) => p.includes('/id/')),
			'Capture groups should be replaced with the "id" placeholder to produce a valid path',
		).toBe(true);
	});

	it('replaces {variable} template placeholders with "id"', () => {
		const routes = [marshalRoute(route('r1', 'agents', ['~/api/v1/agents/{agentId}/sources']))];
		const candidates = generateCandidateRequests(routes);
		const paths = candidates.map((c) => c.path);
		expect(
			paths.every((p) => !p.includes('{')),
			'Candidate paths must not contain literal { from template placeholders',
		).toBe(true);
		expect(
			paths.some((p) => p.includes('/id/')),
			'{agentId} should be replaced with "id"',
		).toBe(true);
	});
});

// ─── LOW severity classification ────────────────────────────────────────────

describe('analyzeRoutes – regex_priority override within same service is LOW', () => {
	// A specific route with higher regex_priority intentionally overrides a
	// same-service catch-all. This is the supported Kong override mechanism.
	const configWithServices: KonnectData = {
		routes: [
			route('r-specific', 'delegation-sync-block', ['~/timesheetmanager-v2/api/delegation-form/sync$'], {
				regex_priority: 100,
				service: { id: 'svc-tsm' },
				created_at: 1_700_000_000,
			}),
			route('r-catchall', 'api-route', ['~/timesheetmanager-v2/*'], {
				regex_priority: 0,
				service: { id: 'svc-tsm' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([['svc-tsm', { id: 'svc-tsm', name: 'timesheetmanager-v2' }]]),
		routerFlavor: 'traditional',
	};

	it('classifies explicit regex_priority override as LOW, not MEDIUM', () => {
		const findings = analyzeRoutes(configWithServices);
		const collisions = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(collisions.length, 'Should detect the overlap').toBeGreaterThan(0);
		expect(
			collisions.every((f) => f.severity !== 'HIGH' && f.severity !== 'MEDIUM'),
			'A deliberate regex_priority override within the same service must be LOW, not HIGH or MEDIUM',
		).toBe(true);
	});
});

describe('analyzeRoutes – specific sub-route overriding same-service catch-all is LOW', () => {
	// A longer, more-specific route (SSE endpoint) correctly overrides a shorter
	// same-service catch-all. This is an intentional routing refinement.
	const configWithServices: KonnectData = {
		routes: [
			route('r-sse', 'sse-route', ['~/proposal-pal-api/v2/api/v1/proposals/~*/stream'], {
				service: { id: 'svc-ppa' },
				created_at: 1_711_000_001,
			}),
			route('r-catchall', 'api-route', ['~/proposal-pal-api/v2/*'], {
				service: { id: 'svc-ppa' },
				created_at: 1_711_000_000,
			}),
		],
		services: new Map([['svc-ppa', { id: 'svc-ppa', name: 'proposal-pal-api' }]]),
		routerFlavor: 'traditional',
	};

	it('classifies a same-service specific-overrides-catchall collision as LOW', () => {
		const findings = analyzeRoutes(configWithServices);
		const collisions = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(collisions.length, 'Should detect the overlap').toBeGreaterThan(0);
		expect(
			collisions.every((f) => f.severity !== 'HIGH' && f.severity !== 'MEDIUM'),
			'A specific sub-route correctly overriding a same-service catch-all must be LOW',
		).toBe(true);
	});
});

describe('analyzeRoutes – header-stratified identical-path pair is INFO', () => {
	// Two routes targeting different services but with identical paths. The
	// winner requires a header constraint that the loser does not. Kong
	// evaluates the header constraint before selecting the route, so no
	// cross-service misrouting occurs — this is intentional traffic partitioning.
	const configWithServices: KonnectData = {
		routes: [
			route('r-dev', 'auth-dev-users', ['/userinfo'], {
				headers: { 'x-internal': ['dev'] },
				service: { id: 'svc-dev' },
				created_at: 1_700_000_001,
			}),
			route('r-internal', 'auth-prod-users', ['/userinfo'], {
				service: { id: 'svc-internal' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([
			['svc-dev', { id: 'svc-dev', name: 'auth-dev' }],
			['svc-internal', { id: 'svc-internal', name: 'auth-internal' }],
		]),
		routerFlavor: 'traditional',
	};

	it('emits an INFO finding (not HIGH/MEDIUM/LOW) for the stratified pair', () => {
		const findings = analyzeRoutes(configWithServices);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(overlaps.length, 'Should detect the overlap').toBeGreaterThan(0);
		expect(
			overlaps.every((f) => f.severity === 'INFO'),
			'Header-stratified identical-path pair must be INFO, not HIGH/MEDIUM/LOW',
		).toBe(true);
	});

	it('includes explain-request suggestions naming the stratifying header', () => {
		const findings = analyzeRoutes(configWithServices);
		const info = findings.find((f) => (f.type === 'shadowing' || f.type === 'collision') && f.severity === 'INFO');
		expect(info, 'INFO finding must exist').toBeDefined();
		expect(
			info?.suggestions.some((s) => s.includes('explain-request') && s.includes('x-internal')),
			'Must include an explain-request command carrying the stratifying header',
		).toBe(true);
		expect(
			info?.suggestions.some((s) => s.includes('explain-request') && !s.includes('--header')),
			'Must include a header-free explain-request command for the unconstrained route',
		).toBe(true);
	});
});

describe('analyzeRoutes – identical-path collision suggestions are deduplicated', () => {
	// When both routes share the same path expression, the regex fix is
	// identical for both. The suggestion list must not contain duplicates and
	// must include a note about route differentiation.
	const config: KonnectData = {
		routes: [
			route('r1', 'summarizer-agent-internal', ['~/legal-agent-mesh/summarizer-agent/*'], {
				service: { id: 'svc-a' },
				created_at: 1_700_000_000,
			}),
			route('r2', 'legal-agent-mesh-summarizer-agent-internal', ['~/legal-agent-mesh/summarizer-agent/*'], {
				service: { id: 'svc-b' },
				created_at: 1_700_003_600,
			}),
		],
		services: new Map([
			['svc-a', { id: 'svc-a', name: 'summarizer-agent' }],
			['svc-b', { id: 'svc-b', name: 'legal-agent-mesh-summarizer' }],
		]),
		routerFlavor: 'traditional',
	};

	it('does not emit the same regex fix twice for identical-path routes', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.find((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(collision, 'Should detect a collision').toBeDefined();
		const regexFixes = (collision?.suggestions ?? []).filter((s) => s.startsWith('~'));
		const unique = new Set(regexFixes);
		expect(unique.size, 'Duplicate regex fixes must be deduplicated').toBe(regexFixes.length);
	});

	it('appends a route-differentiation note when paths are identical', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.find((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			collision?.suggestions.some(
				(s) => s.toLowerCase().includes('delete') || s.toLowerCase().includes('differentiate'),
			),
			'Identical-path collision must suggest deleting or differentiating the shadowed route',
		).toBe(true);
	});
});

// ─── detectSuspiciousRegexIssues – root-path universal-matcher patterns ──────

describe('detectSuspiciousRegexIssues – root-path universal-matcher patterns', () => {
	// The regex ~/ matches the end of every URL because the traditional router
	// adds no ^ anchor, making it a universal catch-all.
	it('flags ~/ (bare tilde-slash) as suspicious', () => {
		expect(detectSuspiciousRegexIssues('~/').length, '~/ is a universal matcher and must be flagged').toBeGreaterThan(
			0,
		);
	});

	it('flags ~/?$ (optional-slash with end anchor) as suspicious', () => {
		expect(
			detectSuspiciousRegexIssues('~/?$').length,
			'~/?$ matches the end of every URL in traditional flavor — must be flagged',
		).toBeGreaterThan(0);
	});

	it('flags ~$ (just end-anchor) as suspicious', () => {
		expect(
			detectSuspiciousRegexIssues('~$').length,
			'~$ matches the end of every URL in traditional flavor — must be flagged',
		).toBeGreaterThan(0);
	});
});

// ─── suggestRegexFix – universal-matcher patterns ────────────────────────────

describe('suggestRegexFix – universal-matcher patterns suggest the plain root path', () => {
	it('returns / for ~/', () => {
		expect(suggestRegexFix('~/'), 'The safe replacement for a universal-matcher path is the plain prefix /').toBe('/');
	});

	it('returns / for ~/?$', () => {
		expect(suggestRegexFix('~/?$'), 'The safe replacement for ~/?$ is the plain prefix /').toBe('/');
	});
});

// ─── MEDIUM severity ─────────────────────────────────────────────────────────

describe('analyzeRoutes – ambiguous same-service overlap is MEDIUM', () => {
	// Two routes on the same service with identical paths, no regex_priority
	// difference and no path-length difference. There is no priority signal
	// (no intentional override), so the finding is MEDIUM.
	const config: KonnectData = {
		routes: [
			route('r1', 'auth-login', ['/login'], { service: { id: 'svc-auth' }, created_at: 1_700_000_000 }),
			route('r2', 'auth-login-v2', ['/login'], { service: { id: 'svc-auth' }, created_at: 1_700_000_001 }),
		],
		services: new Map([['svc-auth', { id: 'svc-auth', name: 'auth-service' }]]),
		routerFlavor: 'traditional',
	};

	it('produces at least one collision or shadowing finding', () => {
		const findings = analyzeRoutes(config);
		expect(findings.filter((f) => f.type === 'shadowing' || f.type === 'collision').length).toBeGreaterThan(0);
	});

	it('classifies same-service identical-path overlap with no priority signal as MEDIUM', () => {
		const findings = analyzeRoutes(config);
		const collisions = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			collisions.every((f) => f.severity === 'MEDIUM'),
			'Identical-path same-service routes with no regex_priority or path-length difference must be MEDIUM',
		).toBe(true);
	});
});

// ─── isHeaderStratified – value-level paths ──────────────────────────────────

describe('analyzeRoutes – header stratification: disjoint values on same header name', () => {
	// Winner: x-env:[prod]  Loser: x-env:[dev, staging]
	// The value sets are disjoint — no request can satisfy both constraints simultaneously.
	const config: KonnectData = {
		routes: [
			route('r-prod', 'prod-api', ['/api/users'], {
				headers: { 'x-env': ['prod'] },
				service: { id: 'svc-prod' },
				created_at: 1_700_000_001,
			}),
			route('r-non-prod', 'non-prod-api', ['/api/users'], {
				headers: { 'x-env': ['dev', 'staging'] },
				service: { id: 'svc-non-prod' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([
			['svc-prod', { id: 'svc-prod', name: 'prod-api' }],
			['svc-non-prod', { id: 'svc-non-prod', name: 'non-prod-api' }],
		]),
		routerFlavor: 'traditional',
	};

	it('treats routes with disjoint header values as stratified (INFO, not HIGH)', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(overlaps.length, 'Pair must be detected').toBeGreaterThan(0);
		expect(
			overlaps.every((f) => f.severity === 'INFO'),
			'Routes whose header values are fully disjoint partition traffic with no overlap — must be INFO',
		).toBe(true);
	});
});

describe('analyzeRoutes – header stratification: overlapping values on same header name', () => {
	// Winner: x-env:[prod, staging]  Loser: x-env:[staging, dev]
	// "staging" appears in both — a request with x-env:staging matches both routes.
	const config: KonnectData = {
		routes: [
			route('r-a', 'service-a-users', ['/users'], {
				headers: { 'x-env': ['prod', 'staging'] },
				service: { id: 'svc-a' },
				created_at: 1_700_000_001,
			}),
			route('r-b', 'service-b-users', ['/users'], {
				headers: { 'x-env': ['staging', 'dev'] },
				service: { id: 'svc-b' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([
			['svc-a', { id: 'svc-a', name: 'service-a' }],
			['svc-b', { id: 'svc-b', name: 'service-b' }],
		]),
		routerFlavor: 'traditional',
	};

	it('treats overlapping header values as a real collision (HIGH, not INFO)', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const collisions = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(collisions.length, 'Pair must be detected').toBeGreaterThan(0);
		expect(
			collisions.some((f) => f.severity === 'HIGH'),
			'Overlapping header values mean a request with x-env:staging reaches both routes — must be HIGH',
		).toBe(true);
	});
});

// ─── includeInfo: false behaviour ────────────────────────────────────────────

describe('analyzeRoutes – includeInfo: false does not suppress MEDIUM or HIGH findings', () => {
	it('returns suspicious_regex MEDIUM findings even when includeInfo is false', () => {
		const config = makeConfig([route('r1', 'bad-regex', ['~/api/*'])]);
		const findings = analyzeRoutes(config, { includeInfo: false });
		expect(
			findings.filter((f) => f.type === 'suspicious_regex').length,
			'MEDIUM suspicious_regex findings must not be suppressed by includeInfo: false',
		).toBeGreaterThan(0);
	});

	it('returns HIGH collision findings when includeInfo is false', () => {
		const config: KonnectData = {
			routes: [
				route('r1', 'broad-regex', ['~/api/([^/]+)'], { service: { id: 'svc-a' }, created_at: 1_700_000_000 }),
				route('r2', 'specific-path', ['/marketing/api/profile'], {
					service: { id: 'svc-b' },
					created_at: 1_700_000_001,
				}),
			],
			services: new Map([
				['svc-a', { id: 'svc-a', name: 'service-a' }],
				['svc-b', { id: 'svc-b', name: 'service-b' }],
			]),
			routerFlavor: 'traditional',
		};
		const findings = analyzeRoutes(config, { includeInfo: false });
		expect(
			findings.some((f) => f.severity === 'HIGH'),
			'HIGH collision findings must not be suppressed by includeInfo: false',
		).toBe(true);
	});

	it('suppresses INFO header-stratified findings when includeInfo is false', () => {
		const config: KonnectData = {
			routes: [
				route('r-dev', 'dev-userinfo', ['/userinfo'], {
					headers: { 'x-env': ['dev'] },
					service: { id: 'svc-dev' },
					created_at: 1_700_000_001,
				}),
				route('r-prod', 'prod-userinfo', ['/userinfo'], {
					service: { id: 'svc-prod' },
					created_at: 1_700_000_000,
				}),
			],
			services: new Map([
				['svc-dev', { id: 'svc-dev', name: 'dev' }],
				['svc-prod', { id: 'svc-prod', name: 'prod' }],
			]),
			routerFlavor: 'traditional',
		};
		const findings = analyzeRoutes(config, { includeInfo: false });
		expect(
			findings.filter((f) => f.severity === 'INFO').length,
			'INFO findings must be suppressed when includeInfo is false',
		).toBe(0);
	});

	it('suppresses universal_matcher INFO findings when includeInfo is false', () => {
		const config = makeConfig([route('r1', 'spa', ['/']), route('r2', 'api', ['/api/v1'])]);
		const findings = analyzeRoutes(config, { includeInfo: false });
		expect(
			findings.filter((f) => f.type === 'universal_matcher').length,
			'universal_matcher INFO findings must be suppressed when includeInfo is false',
		).toBe(0);
	});
});

// ─── lintUniversalMatchers skip-ids ──────────────────────────────────────────

describe('analyzeRoutes – universal_matcher INFO is not emitted for routes already flagged by suspicious_regex', () => {
	// ~/?$ is caught by the suspicious_regex pattern list (emits MEDIUM).
	// It is also a universal matcher. lintUniversalMatchers must skip it so the
	// route does not appear in two separate findings.
	it('does not produce a universal_matcher INFO finding for a route that already has a suspicious_regex finding', () => {
		const config = makeConfig([
			route('r1', 'root-catchall', ['~/?$'], { created_at: 1_700_000_000 }),
			route('r2', 'specific', ['/api/v1'], { created_at: 1_710_000_000 }),
		]);
		const findings = analyzeRoutes(config, { includeInfo: true });
		const r1Findings = findings.filter((f) => f.routes.some((r) => r.id === 'r1'));
		expect(
			r1Findings.filter((f) => f.type === 'universal_matcher').length,
			'A route with a suspicious_regex finding must not also receive a universal_matcher INFO finding',
		).toBe(0);
	});
});

// ─── detectCollisions – sample accumulation ──────────────────────────────────

describe('detectCollisions – same route pair accumulates samples across multiple candidate paths', () => {
	// ~/users/([^/]+) and ~/users/([a-z]+) both match /users/id, /users/id/,
	// /users/id/extra, etc. The first match creates the finding; subsequent
	// matches for the same pair must add to samples[] rather than creating
	// duplicate findings.
	const config: KonnectData = {
		routes: [
			route('r-wide', 'svc-a-users', ['~/users/([^/]+)'], { service: { id: 'svc-a' }, created_at: 1_700_000_000 }),
			route('r-narrow', 'svc-b-users', ['~/users/([a-z]+)'], {
				service: { id: 'svc-b' },
				created_at: 1_700_000_001,
			}),
		],
		services: new Map([
			['svc-a', { id: 'svc-a', name: 'service-a' }],
			['svc-b', { id: 'svc-b', name: 'service-b' }],
		]),
		routerFlavor: 'traditional',
	};

	it('produces exactly one finding for the pair (no duplicates)', () => {
		const findings = analyzeRoutes(config);
		const collisions = findings.filter(
			(f) => (f.type === 'shadowing' || f.type === 'collision') && f.routes.some((r) => r.id === 'r-wide'),
		);
		expect(
			collisions.length,
			'The same route pair must produce exactly one finding regardless of how many candidates match',
		).toBe(1);
	});

	it('accumulates more than one sample path in the finding', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.find(
			(f) => (f.type === 'shadowing' || f.type === 'collision') && f.routes.some((r) => r.id === 'r-wide'),
		);
		expect(collision, 'Finding must exist').toBeDefined();
		expect(
			(collision?.samples.length ?? 0) > 1,
			'A broadly matching pair should accumulate multiple sample paths in a single finding',
		).toBe(true);
	});

	it('does not duplicate sample paths within the same finding', () => {
		const findings = analyzeRoutes(config);
		const collision = findings.find(
			(f) => (f.type === 'shadowing' || f.type === 'collision') && f.routes.some((r) => r.id === 'r-wide'),
		);
		const samples = collision?.samples ?? [];
		const uniqueSamples = new Set(samples);
		expect(uniqueSamples.size, 'Sample paths within a finding must be deduplicated').toBe(samples.length);
	});
});

// ─── isShadowing – finding type ──────────────────────────────────────────────

describe('analyzeRoutes – finding type reflects the winner/loser path relationship', () => {
	it('emits collision type (not shadowing) when identical plain-prefix routes serve different services', () => {
		// Plain-prefix winner has no regex paths → isShadowing returns false → type = 'collision'.
		const config: KonnectData = {
			routes: [
				route('r1', 'login-auth', ['/login'], { service: { id: 'svc-a' }, created_at: 1_700_000_000 }),
				route('r2', 'login-identity', ['/login'], { service: { id: 'svc-b' }, created_at: 1_700_000_001 }),
			],
			services: new Map([
				['svc-a', { id: 'svc-a', name: 'auth' }],
				['svc-b', { id: 'svc-b', name: 'identity' }],
			]),
			routerFlavor: 'traditional',
		};
		const findings = analyzeRoutes(config);
		// No header stratification (neither route has headers), different services → HIGH collision.
		const collisionType = findings.filter((f) => f.type === 'collision');
		expect(
			collisionType.length,
			'Plain-prefix winner has no regex — isShadowing must return false, emitting collision not shadowing',
		).toBeGreaterThan(0);
	});

	it('emits shadowing type when winner regex subsumes the loser plain path', () => {
		// ~/users/([^/]+) matches /users/profile literally, so isShadowing returns true.
		const config: KonnectData = {
			routes: [
				route('r-regex', 'regex-route', ['~/users/([^/]+)'], {
					service: { id: 'svc-a' },
					created_at: 1_700_000_000,
				}),
				route('r-plain', 'plain-route', ['/users/profile'], { service: { id: 'svc-b' }, created_at: 1_700_000_001 }),
			],
			services: new Map([
				['svc-a', { id: 'svc-a', name: 'service-a' }],
				['svc-b', { id: 'svc-b', name: 'service-b' }],
			]),
			routerFlavor: 'traditional',
		};
		const findings = analyzeRoutes(config);
		const shadowingType = findings.filter((f) => f.type === 'shadowing');
		expect(
			shadowingType.length,
			'Winner regex matches the loser plain path — isShadowing must return true, emitting shadowing not collision',
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – ~* regex header values produce MEDIUM (not HIGH) findings', () => {
	// When header constraints use ~* regex values, static analysis cannot determine
	// whether the patterns are disjoint. The finding is downgraded from HIGH to MEDIUM
	// with a note indicating manual verification is required.
	const config: KonnectData = {
		routes: [
			route('r-canary', 'canary-api', ['/api/v1'], {
				headers: { 'x-version': ['~*^v[0-9]+$'] }, // regex: any vN value
				service: { id: 'svc-canary' },
				created_at: 1_700_000_001,
			}),
			route('r-stable', 'stable-api', ['/api/v1'], {
				headers: { 'x-version': ['~*^stable.*'] }, // regex: anything starting with "stable"
				service: { id: 'svc-stable' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([
			['svc-canary', { id: 'svc-canary', name: 'canary' }],
			['svc-stable', { id: 'svc-stable', name: 'stable' }],
		]),
		routerFlavor: 'traditional',
	};

	it('produces a finding for the pair (not silently suppressed)', () => {
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(overlaps.length, 'Route pair with ~* header values must still produce a finding').toBeGreaterThan(0);
	});

	it('finding is MEDIUM (not HIGH or INFO), reflecting analysis uncertainty', () => {
		const findings = analyzeRoutes(config);
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(
			overlaps.every((f) => f.severity === 'MEDIUM'),
			'~* regex header values → MEDIUM severity (cannot statically determine disjointness)',
		).toBe(true);
	});

	it('reason chain mentions ~* regex header analysis limitation', () => {
		const findings = analyzeRoutes(config);
		const f = findings.find((f) => f.type === 'shadowing' || f.type === 'collision');
		const allReason = f?.reason.join(' ') ?? '';
		expect(
			allReason.includes('~*') || allReason.toLowerCase().includes('regex'),
			'Reason must mention the ~* regex header analysis limitation',
		).toBe(true);
	});
});

describe('analyzeRoutes – plain header value + ~* header value: plain wins if disjoint', () => {
	// When the winner has a plain header value and the loser has none (or vice versa),
	// it is still stratified — the ~* opaque logic should not override a definitively
	// stratified dimension.
	const config: KonnectData = {
		routes: [
			route('r-prod', 'prod-route', ['/api'], {
				headers: { 'x-env': ['prod'] }, // plain value
				service: { id: 'svc-prod' },
				created_at: 1_700_000_001,
			}),
			route('r-default', 'default-route', ['/api'], {
				// No headers — handles all requests without x-env header.
				service: { id: 'svc-default' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([
			['svc-prod', { id: 'svc-prod', name: 'prod' }],
			['svc-default', { id: 'svc-default', name: 'default' }],
		]),
		routerFlavor: 'traditional',
	};

	it('emits INFO (stratified), not MEDIUM, when winner has a plain header and loser has none', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const overlaps = findings.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		expect(overlaps.length, 'Pair must be detected').toBeGreaterThan(0);
		expect(
			overlaps.every((f) => f.severity === 'INFO'),
			'Winner has plain header constraint, loser has none → stratified → INFO',
		).toBe(true);
	});
});

describe('analyzeRoutes – plain-host vs wildcard-host correctly ordered (not a collision)', () => {
	// payments.internal.example.com → svc-payments (plain host)
	// *.internal.example.com        → svc-catchall  (wildcard host)
	// Both have the same path. In Kong, the plain-host route deterministically wins
	// (PLAIN_HOSTS_ONLY bit). kongcheck must not report this as a HIGH collision.
	const config: KonnectData = {
		routes: [
			route('r-plain', 'payments', ['/v1/payments'], {
				hosts: ['payments.internal.example.com'],
				service: { id: 'svc-payments' },
				created_at: 1_700_000_000,
			}),
			route('r-wildcard', 'catchall', ['/v1/payments'], {
				hosts: ['*.internal.example.com'],
				service: { id: 'svc-catchall' },
				created_at: 1_700_000_001,
			}),
		],
		services: new Map([
			['svc-payments', { id: 'svc-payments', name: 'payments' }],
			['svc-catchall', { id: 'svc-catchall', name: 'catchall' }],
		]),
		routerFlavor: 'traditional',
	};

	it('does NOT produce a HIGH finding for plain-host vs wildcard-host on same path', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const highCollisions = findings.filter(
			(f) => (f.type === 'shadowing' || f.type === 'collision') && f.severity === 'HIGH',
		);
		expect(
			highCollisions.length,
			'Plain-host beats wildcard-host deterministically via PLAIN_HOSTS_ONLY — must not be HIGH',
		).toBe(0);
	});

	it('the plain-host route wins the simulation for a matching request', () => {
		const { marshalRoute: mr, compareRoutes: cr, simulateRequest: sr } = require('../src/router.ts');
		const services = config.services;
		const [r1, r2] = config.routes;
		const m1 = mr(r1, services.get('svc-payments'), 'traditional');
		const m2 = mr(r2, services.get('svc-catchall'), 'traditional');
		const sorted = [m1, m2].sort(cr);
		const result = sr(sorted, {
			method: 'GET',
			host: 'payments.internal.example.com',
			path: '/v1/payments',
		});
		expect(result.winner?.route.id, 'The plain-host route must win').toBe('r-plain');
	});
});

// ─── Gap #1 deep coverage – wildcard-with-port vs plain-host ─────────────────

describe('analyzeRoutes – wildcard-with-port vs wildcard-without-port is correctly ordered (not HIGH) (Gap #1)', () => {
	// *.internal.example.com:8443  → svc-tls  (wildcard host with explicit port)
	// *.internal.example.com       → svc-http  (wildcard host, no port)
	// Both have the same path. In Kong, HAS_WILDCARD_HOST_PORT (bit 2 = 0x04) makes the ported
	// route win deterministically. kongcheck must not report this as a HIGH collision.
	const config: KonnectData = {
		routes: [
			route('r-ported', 'tls-catchall', ['/v1/api'], {
				hosts: ['*.internal.example.com:8443'],
				service: { id: 'svc-tls' },
				created_at: 1_700_000_001,
			}),
			route('r-unported', 'http-catchall', ['/v1/api'], {
				hosts: ['*.internal.example.com'],
				service: { id: 'svc-http' },
				created_at: 1_700_000_000,
			}),
		],
		services: new Map([
			['svc-tls', { id: 'svc-tls', name: 'tls-backend' }],
			['svc-http', { id: 'svc-http', name: 'http-backend' }],
		]),
		routerFlavor: 'traditional',
	};

	it('does NOT produce a HIGH finding for wildcard-with-port vs wildcard-without-port on same path', () => {
		const findings = analyzeRoutes(config, { includeInfo: true });
		const highCollisions = findings.filter(
			(f) => (f.type === 'shadowing' || f.type === 'collision') && f.severity === 'HIGH',
		);
		expect(
			highCollisions.length,
			'Wildcard-with-port beats wildcard-without-port deterministically via HAS_WILDCARD_HOST_PORT — must not be HIGH',
		).toBe(0);
	});

	it('the wildcard-with-port route wins the simulation for a ported request', () => {
		const { marshalRoute: mr, compareRoutes: cr, simulateRequest: sr } = require('../src/router.ts');
		const services = config.services;
		const [r1, r2] = config.routes;
		const m1 = mr(r1, services.get('svc-tls'), 'traditional');
		const m2 = mr(r2, services.get('svc-http'), 'traditional');
		const sorted = [m1, m2].sort(cr);
		const result = sr(sorted, {
			method: 'GET',
			host: 'api.internal.example.com:8443',
			path: '/v1/api',
		});
		expect(
			result.winner?.route.id,
			'The wildcard-with-port route (HAS_WILDCARD_HOST_PORT) must win for a ported request',
		).toBe('r-ported');
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// SNI / source IP / destination IP / protocol-family stratification
// Kong source: traditional.lua#L1072-L1085, #L880-L900
// ─────────────────────────────────────────────────────────────────────────────

describe('analyzeRoutes – SNI stratification (INFO, not HIGH/MEDIUM)', () => {
	it('emits INFO (not HIGH) when two routes share paths but have fully disjoint SNI sets', () => {
		// Two stream routes targeting different services, same path, but non-overlapping SNIs.
		// Kong routes each TLS connection to the correct route by SNI → no misrouting.
		const config = makeConfig([
			route('r-sni-a', 'sni-route-a', ['/stream'], {
				service: { id: 'svc-a' },
				snis: ['a.example.com'],
			}),
			route('r-sni-b', 'sni-route-b', ['/stream'], {
				service: { id: 'svc-b' },
				snis: ['b.example.com'],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highOrMedium = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && (f.severity === 'HIGH' || f.severity === 'MEDIUM'),
		);
		expect(
			highOrMedium.length,
			'Disjoint SNI sets fully stratify traffic – must produce zero HIGH or MEDIUM collision findings',
		).toBe(0);

		const infoFindings = findings.filter((f) => f.type === 'collision' && f.severity === 'INFO');
		expect(
			infoFindings.length,
			'Disjoint SNI sets must produce an INFO finding so operators can confirm the stratification is intentional',
		).toBeGreaterThan(0);
	});

	it('does NOT emit an INFO finding when includeInfo is false', () => {
		const config = makeConfig([
			route('r-sni-a', 'sni-route-a', ['/stream'], { service: { id: 'svc-a' }, snis: ['a.example.com'] }),
			route('r-sni-b', 'sni-route-b', ['/stream'], { service: { id: 'svc-b' }, snis: ['b.example.com'] }),
		]);

		const findings = analyzeRoutes(config, { includeInfo: false });
		const anyFinding = findings.filter((f) => f.type === 'collision' || f.type === 'shadowing');
		expect(anyFinding.length, 'When includeInfo=false no collision/stratification findings must be emitted').toBe(0);
	});

	it('still emits a HIGH finding when SNI sets overlap (shared SNI value)', () => {
		// Both routes accept 'shared.example.com' → Kong cannot differentiate them on SNI alone.
		const config = makeConfig([
			route('r-sni-x', 'sni-route-x', ['/stream'], {
				service: { id: 'svc-x' },
				snis: ['shared.example.com', 'x.example.com'],
			}),
			route('r-sni-y', 'sni-route-y', ['/stream'], {
				service: { id: 'svc-y' },
				snis: ['shared.example.com', 'y.example.com'],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highFindings = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && f.severity === 'HIGH',
		);
		expect(
			highFindings.length,
			'Overlapping SNI sets mean a connection to shared.example.com is ambiguous – must emit HIGH',
		).toBeGreaterThan(0);
	});

	it('handles FQDN trailing-dot normalisation: snis ["api.example.com."] and ["api.example.com"] are the SAME SNI', () => {
		// Kong strips trailing dots in marshall_route. If route A has "api.example.com." and
		// route B has "api.example.com", they resolve to the same SNI → NOT stratified.
		const config = makeConfig([
			route('r-dot', 'route-fqdn-dot', ['/stream'], {
				service: { id: 'svc-dot' },
				snis: ['api.example.com.'],
			}),
			route('r-nodot', 'route-no-dot', ['/stream'], {
				service: { id: 'svc-nodot' },
				snis: ['api.example.com'],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		// After normalisation both SNIs are "api.example.com" → overlap → must NOT be INFO-stratified.
		const infoStratified = findings.filter(
			(f) => f.severity === 'INFO' && f.type === 'collision' && f.routes.some((r) => r.id === 'r-dot'),
		);
		expect(
			infoStratified.length,
			'After trailing-dot normalisation the SNIs are identical → not stratified → must produce no INFO stratification',
		).toBe(0);
	});
});

describe('analyzeRoutes – source IP/port stratification (INFO, not HIGH/MEDIUM)', () => {
	it('emits INFO when two routes have non-overlapping source CIDR constraints', () => {
		const config = makeConfig([
			route('r-src-a', 'src-route-a', ['/tcp'], {
				service: { id: 'svc-a' },
				sources: [{ ip: '10.0.0.0/24' }],
			}),
			route('r-src-b', 'src-route-b', ['/tcp'], {
				service: { id: 'svc-b' },
				sources: [{ ip: '10.0.1.0/24' }],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highOrMedium = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && (f.severity === 'HIGH' || f.severity === 'MEDIUM'),
		);
		expect(
			highOrMedium.length,
			'Non-overlapping source CIDRs (10.0.0.x vs 10.0.1.x) fully stratify traffic → zero HIGH/MEDIUM',
		).toBe(0);

		const infoFindings = findings.filter((f) => f.type === 'collision' && f.severity === 'INFO');
		expect(
			infoFindings.length,
			'Non-overlapping source CIDRs must produce an INFO stratification finding',
		).toBeGreaterThan(0);
	});

	it('emits HIGH when source CIDRs overlap (supernet/subnet)', () => {
		const config = makeConfig([
			route('r-src-broad', 'src-broad', ['/tcp'], {
				service: { id: 'svc-broad' },
				sources: [{ ip: '10.0.0.0/8' }], // broader range
			}),
			route('r-src-narrow', 'src-narrow', ['/tcp'], {
				service: { id: 'svc-narrow' },
				sources: [{ ip: '10.1.0.0/16' }], // inside broad range
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highFindings = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && f.severity === 'HIGH',
		);
		expect(
			highFindings.length,
			'10.1.0.0/16 is inside 10.0.0.0/8 → source ranges overlap → must emit HIGH collision',
		).toBeGreaterThan(0);
	});

	it('emits INFO when source port constraints are disjoint', () => {
		const config = makeConfig([
			route('r-port-80', 'route-port-80', ['/tcp'], {
				service: { id: 'svc-80' },
				sources: [{ port: 80 }],
			}),
			route('r-port-443', 'route-port-443', ['/tcp'], {
				service: { id: 'svc-443' },
				sources: [{ port: 443 }],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highOrMedium = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && (f.severity === 'HIGH' || f.severity === 'MEDIUM'),
		);
		expect(highOrMedium.length, 'Disjoint source ports (80 vs 443) fully stratify traffic → zero HIGH/MEDIUM').toBe(0);
	});
});

describe('analyzeRoutes – destination IP/port stratification (INFO, not HIGH/MEDIUM)', () => {
	it('emits INFO when destination IP constraints are non-overlapping', () => {
		const config = makeConfig([
			route('r-dst-a', 'dst-route-a', ['/tcp'], {
				service: { id: 'svc-a' },
				destinations: [{ ip: '192.168.0.0/24' }],
			}),
			route('r-dst-b', 'dst-route-b', ['/tcp'], {
				service: { id: 'svc-b' },
				destinations: [{ ip: '192.168.1.0/24' }],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highOrMedium = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && (f.severity === 'HIGH' || f.severity === 'MEDIUM'),
		);
		expect(highOrMedium.length, 'Non-overlapping destination CIDRs fully stratify traffic → zero HIGH/MEDIUM').toBe(0);

		const infoFindings = findings.filter((f) => f.type === 'collision' && f.severity === 'INFO');
		expect(
			infoFindings.length,
			'Non-overlapping destination CIDRs must produce an INFO stratification finding',
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – protocol-family stratification (INFO, not HIGH/MEDIUM)', () => {
	it('emits INFO when one route is all-HTTP and the other is all-stream', () => {
		const config = makeConfig([
			route('r-http', 'http-route', ['/api'], {
				service: { id: 'svc-http' },
				protocols: ['http', 'https'],
			}),
			route('r-tcp', 'tcp-route', ['/api'], {
				service: { id: 'svc-tcp' },
				protocols: ['tcp', 'tls'],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highOrMedium = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && (f.severity === 'HIGH' || f.severity === 'MEDIUM'),
		);
		expect(
			highOrMedium.length,
			'HTTP protocols (http/https) and stream protocols (tcp/tls) are mutually exclusive → zero HIGH/MEDIUM',
		).toBe(0);

		const infoFindings = findings.filter((f) => f.type === 'collision' && f.severity === 'INFO');
		expect(
			infoFindings.length,
			'Disjoint protocol families must produce an INFO stratification finding',
		).toBeGreaterThan(0);
	});

	it('emits HIGH when both routes have overlapping protocol sets (both http+https)', () => {
		const config = makeConfig([
			route('r-http-a', 'http-a', ['/api'], {
				service: { id: 'svc-a' },
				protocols: ['http', 'https'],
			}),
			route('r-http-b', 'http-b', ['/api'], {
				service: { id: 'svc-b' },
				protocols: ['http', 'https'],
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		const highFindings = findings.filter(
			(f) => (f.type === 'collision' || f.type === 'shadowing') && f.severity === 'HIGH',
		);
		expect(
			highFindings.length,
			'Identical protocol sets on same-path, different-service routes must emit HIGH',
		).toBeGreaterThan(0);
	});
});

describe('analyzeRoutes – L4 stratification is not triggered when only one route has the constraint', () => {
	it('emits HIGH (not INFO) when only one route has snis and the other has none', () => {
		// Route B has no snis → it acts as a wildcard (matches all SNIs).
		// Route A has specific snis. They can both match a connection for A's SNIs.
		const config = makeConfig([
			route('r-sni', 'constrained', ['/stream'], {
				service: { id: 'svc-sni' },
				snis: ['api.example.com'],
			}),
			route('r-open', 'open', ['/stream'], {
				service: { id: 'svc-open' },
				// no snis → matches all SNIs
			}),
		]);

		const findings = analyzeRoutes(config, { includeInfo: true });
		// The open route (no SNI constraint) can receive the same connection as the constrained route.
		// This is a real collision risk, not stratification.
		const collisionFindings = findings.filter((f) => f.type === 'collision' || f.type === 'shadowing');
		expect(
			collisionFindings.length,
			'When one route has no SNI constraint it acts as a wildcard → real collision risk → must produce a finding',
		).toBeGreaterThan(0);

		const infoOnly = collisionFindings.every((f) => f.severity === 'INFO');
		expect(
			infoOnly,
			'At least one finding must be HIGH or MEDIUM since the unconstrained route can intercept all SNIs',
		).toBe(false);
	});
});
