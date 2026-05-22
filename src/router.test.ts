/**
 * Tests for the Kong router core (src/router.ts).
 *
 * Each test corresponds to a specific behaviour described in the Kong
 * traditional router source (`kong/router/traditional.lua`, commit 2ffd3b1)
 * and is named so that the assertion messages make the expected Kong semantics
 * completely clear without needing to read the source.
 */

import { describe, expect, it } from 'bun:test';

import {
	classifyPath,
	compareRoutes,
	computeUpstreamUri,
	extractMatchedPrefix,
	isRegexPath,
	marshalRoute,
	matchPath,
	matchRoute,
	sanitizeUriPostfix,
	simulateRequest,
	stripRegexPrefix,
} from '../src/router.ts';
import type { KongRoute, MarshalledRoute } from '../src/types.ts';

/**
 * Builds a minimal MarshalledRoute for testing without needing a full
 * KongRoute shape every time.
 */
function makeRoute(overrides: Partial<KongRoute> & { paths: string[] }): MarshalledRoute {
	const route: KongRoute = {
		id: overrides.id ?? 'route-' + Math.random().toString(36).slice(2),
		name: overrides.name,
		paths: overrides.paths,
		methods: overrides.methods,
		hosts: overrides.hosts,
		headers: overrides.headers,
		regex_priority: overrides.regex_priority ?? 0,
		created_at: overrides.created_at,
		strip_path: overrides.strip_path,
		service: overrides.service,
	};
	return marshalRoute(route, undefined, 'traditional');
}

describe('isRegexPath', () => {
	it('returns true for paths beginning with ~ (Kong regex path marker)', () => {
		expect(isRegexPath('~/payments/*'), '~/payments/* starts with ~ so Kong treats it as a PCRE regex path').toBe(true);
	});

	it('returns false for plain prefix paths that have no ~ prefix', () => {
		expect(isRegexPath('/api/v1'), '/api/v1 is a plain prefix path; Kong matches it with startsWith semantics').toBe(
			false,
		);
	});

	it('returns false for an empty string', () => {
		expect(isRegexPath(''), 'An empty string is not a regex path').toBe(false);
	});
});

describe('stripRegexPrefix', () => {
	it('removes the leading ~ to produce the bare PCRE pattern string', () => {
		expect(
			stripRegexPrefix('~/payments/*'),
			'Kong strips the ~ before compiling the PCRE: ~/payments/* → /payments/*',
		).toBe('/payments/*');
	});

	it('throws when called on a non-regex path (missing ~)', () => {
		expect(() => stripRegexPrefix('/plain'), 'Calling stripRegexPrefix on a plain path is a programming error').toThrow(
			/regex path/,
		);
	});
});

describe('classifyPath – traditional flavor (no start anchor)', () => {
	it("classifies a ~ path as kind='regex' with regexSource stripped of ~", () => {
		const p = classifyPath('~/payments/*', 'traditional');
		expect(p.kind, "~/payments/* is a regex path in Kong's traditional router").toBe('regex');
		expect(p.regexSource, 'The regex source should be the raw path minus the leading ~').toBe('/payments/*');
	});

	it('does NOT add a ^ start anchor for traditional flavor', () => {
		const p = classifyPath('~/payments/*', 'traditional');
		expect(
			p.regex?.source.startsWith('^'),
			'Traditional flavor: Kong does not anchor regex paths at the start by default',
		).toBe(false);
		// JS serialises the regex source with escape sequences; verify the escaped form.
		expect(
			p.regex?.source,
			'The regex source for ~/payments/* in traditional flavor should be the bare PCRE pattern',
		).toBe('\\/payments\\/*');
	});

	it("classifies a plain path as kind='prefix'", () => {
		const p = classifyPath('/api/v1', 'traditional');
		expect(p.kind, '/api/v1 is a plain prefix path').toBe('prefix');
		expect(p.prefix, 'The prefix field should hold the full plain path').toBe('/api/v1');
	});
});

describe('classifyPath – traditional_compatible flavor (^ start anchor)', () => {
	it('adds a ^ start anchor to regex paths under traditional_compatible', () => {
		const p = classifyPath('~/payments/*', 'traditional_compatible');
		expect(
			p.regex?.source.startsWith('^'),
			"Kong's transform.lua prefixes regex paths with ^ in traditional_compatible flavor",
		).toBe(true);
		expect(
			p.regex?.source,
			'The regex source for ~/payments/* in traditional_compatible should start with ^ (JS-escaped)',
		).toBe('^\\/payments\\/*');
	});

	it('plain paths are unchanged by the flavor parameter', () => {
		const p = classifyPath('/api/v1', 'traditional_compatible');
		expect(p.kind, "flavor does not affect plain prefix paths – they remain kind='prefix'").toBe('prefix');
		expect(p.prefix, 'the prefix field should still hold the unmodified plain path').toBe('/api/v1');
	});
});

describe('matchPath – regex paths', () => {
	it('~/payments/* matches /payments/ (traditional: no end anchor → prefix-like)', () => {
		const p = classifyPath('~/payments/*', 'traditional');
		expect(matchPath(p, '/payments/'), 'Without an end anchor Kong regex routes behave like prefix matches').toBe(true);
	});

	it('~/payments/* matches /payments-v2/docs – the motivating shadowing example', () => {
		const p = classifyPath('~/payments/*', 'traditional');
		// /payments/* → regex /payments/* → `/payments` followed by 0+ slashes.
		// The regex matches /payments at the start of /payments-v2/docs.
		expect(
			matchPath(p, '/payments-v2/docs'),
			'This is the core of the problem: ~/payments/* (regex /payments/*) matches /payments-v2/docs ' +
				"because * in PCRE quantifies the previous char '/', not 'anything'",
		).toBe(true);
	});

	it('~/payments(?:/.*)?$ does NOT match /payments-v2/docs (safe anchored alternative)', () => {
		const p = classifyPath('~/payments(?:/.*)?$', 'traditional');
		expect(
			matchPath(p, '/payments-v2/docs'),
			'The anchored safe alternative ~/payments(?:/.*)?$ must not match /payments-v2/docs',
		).toBe(false);
	});

	it('~/payments(?:/.*)?$ matches /payments/something (correct match)', () => {
		const p = classifyPath('~/payments(?:/.*)?$', 'traditional');
		expect(matchPath(p, '/payments/something')).toBe(true);
	});

	it('~/payments-v2(?:/.*)?$ matches /payments-v2/docs and not /payments/docs', () => {
		const p = classifyPath('~/payments-v2(?:/.*)?$', 'traditional');
		expect(matchPath(p, '/payments-v2/docs'), 'The payments-v2 safe alternative should match its own path').toBe(true);
		expect(
			matchPath(p, '/payments/docs'),
			'The payments-v2 safe alternative must not match an unrelated /payments path',
		).toBe(false);
	});
});

describe('matchPath – plain prefix paths', () => {
	it('/api/v1 prefix matches /api/v1/users', () => {
		const p = classifyPath('/api/v1', 'traditional');
		expect(matchPath(p, '/api/v1/users'), 'Prefix /api/v1 matches any path starting with it').toBe(true);
	});

	it('/api/v1 prefix DOES match /api/v10/users (Kong uses byte-level startsWith, not token boundaries)', () => {
		const p = classifyPath('/api/v1', 'traditional');
		// Kong's traditional router plain-prefix matching uses startsWith at the byte level.
		// /api/v1 is a byte-level prefix of /api/v10, so it matches. This is a known Kong gotcha –
		// if you need token-level isolation, use a regex path like ~/api/v1(?:/.*)?$
		expect(
			matchPath(p, '/api/v10/users'),
			'/api/v1 matches /api/v10/users via startsWith – use ~/api/v1(?:/.*)?$ for token isolation',
		).toBe(true);
	});

	it('exact path /health matches /health exactly', () => {
		const p = classifyPath('/health', 'traditional');
		expect(matchPath(p, '/health')).toBe(true);
	});
});

describe('compareRoutes – Kong sort_routes tie-breaking (traditional.lua ~L681-L709)', () => {
	it('regex route has higher priority than a plain prefix route (HAS_REGEX_URI submatch weight)', () => {
		const regexRoute = makeRoute({ id: 'r1', paths: ['~/api/.*'] });
		const plainRoute = makeRoute({ id: 'r2', paths: ['/api'] });

		expect(
			compareRoutes(regexRoute, plainRoute),
			'Kong: regex routes beat plain-prefix routes due to submatch_weight',
		).toBeLessThan(0);
	});

	it('between two regex routes, higher regex_priority wins', () => {
		const highPri = makeRoute({
			id: 'r1',
			paths: ['~/api/.*'],
			regex_priority: 10,
		});
		const lowPri = makeRoute({
			id: 'r2',
			paths: ['~/api/v1/.*'],
			regex_priority: 0,
		});

		expect(
			compareRoutes(highPri, lowPri),
			'Kong: higher regex_priority wins when both routes are regex type',
		).toBeLessThan(0);
	});

	it('between equal-priority regex routes, longer path pattern wins', () => {
		const longer = makeRoute({ id: 'r1', paths: ['~/api/v1/users'], regex_priority: 0 });
		const shorter = makeRoute({ id: 'r2', paths: ['~/api'], regex_priority: 0 });

		expect(
			compareRoutes(longer, shorter),
			'Kong: max_uri_length tie-breaker – longer path wins over shorter',
		).toBeLessThan(0);
	});

	it('between equal-length equal-priority regex routes, earlier created_at wins', () => {
		const older = makeRoute({
			id: 'r1',
			paths: ['~/payments/*'],
			regex_priority: 0,
			created_at: 1000,
		});
		const newer = makeRoute({
			id: 'r2',
			paths: ['~/payments/*'],
			regex_priority: 0,
			created_at: 2000,
		});

		expect(
			compareRoutes(older, newer),
			'Kong: earlier created_at wins when all other criteria are equal – older route shadow newer one',
		).toBeLessThan(0);
	});

	it('two identical routes compare as equal (return 0)', () => {
		const a = makeRoute({ id: 'r1', paths: ['~/api/.*'], regex_priority: 0, created_at: 1000 });
		const b = makeRoute({ id: 'r2', paths: ['~/api/.*'], regex_priority: 0, created_at: 1000 });
		expect(compareRoutes(a, b), 'Fully identical routes (by ordering criteria) should compare as equal').toBe(0);
	});

	it('~/payments/* beats ~/payments-v2/* when both have equal regex_priority (length tie-break)', () => {
		// ~/payments/* is 7 chars; ~/payments-v2/* is 11 chars.
		// So ~/payments-v2/* should actually WIN by length… let's verify that.
		const payments = makeRoute({ id: 'r1', paths: ['~/payments/*'], regex_priority: 0, created_at: 1000 });
		const paymentsV2 = makeRoute({
			id: 'r2',
			paths: ['~/payments-v2/*'],
			regex_priority: 0,
			created_at: 1000,
		});

		expect(
			compareRoutes(paymentsV2, payments),
			'~/payments-v2/* (11 chars) has a longer path than ~/payments/* (7 chars) ' +
				'so ~/payments-v2/* wins by max_uri_length – but both still have the suspicious /* pattern',
		).toBeLessThan(0);
	});

	it('~/payments/* beats ~/payments-v2/* when ~/payments/* was created earlier (same length-adjusted priority)', () => {
		// Same regex_priority, same length → falls through to created_at.
		const payments = makeRoute({ id: 'r1', paths: ['~/payments/*'], regex_priority: 0, created_at: 1000 });
		const paymentsV2SameLen = makeRoute({
			id: 'r2',
			paths: ['~/payments/*'], // same length to force created_at tie-break
			regex_priority: 0,
			created_at: 2000,
		});

		expect(
			compareRoutes(payments, paymentsV2SameLen),
			'When all other criteria are equal, the route created earlier (smaller created_at) wins',
		).toBeLessThan(0);
	});
});

describe('matchRoute – method and host filtering', () => {
	it('route with methods constraint does not match a different method', () => {
		const mr = makeRoute({ paths: ['/api'], methods: ['POST'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api' }),
			'A route constrained to POST must not match a GET request',
		).toBe(false);
	});

	it('route with no methods constraint matches any method', () => {
		const mr = makeRoute({ paths: ['/api'] });
		expect(
			matchRoute(mr, { method: 'DELETE', host: 'example.com', path: '/api' }),
			'A route with no methods constraint should match any HTTP method',
		).toBe(true);
	});

	it('route with host constraint does not match a different host', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['api.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'other.example.com', path: '/api' }),
			'A route constrained to api.example.com must not match other.example.com',
		).toBe(false);
	});

	it('route with wildcard host *.example.com matches sub.example.com', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'sub.example.com', path: '/api' }),
			'A wildcard host *.example.com should match any subdomain',
		).toBe(true);
	});
});

describe('simulateRequest – the motivating ~/payments/* vs ~/payments-v2/* example', () => {
	const paymentsRoute = makeRoute({
		id: 'route-payments',
		name: 'payments',
		paths: ['~/payments/*'],
		regex_priority: 0,
		created_at: 1736500800, // earlier
	});

	const paymentsV2Route = makeRoute({
		id: 'route-payments-v2',
		name: 'payments-v2',
		paths: ['~/payments-v2/*'],
		regex_priority: 0,
		created_at: 1738742400, // later
	});

	const sorted = [paymentsV2Route, paymentsRoute].sort(compareRoutes);

	it('both routes match /payments-v2/docs (demonstrates the shadowing problem)', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'example.com',
			path: '/payments-v2/docs',
		});
		expect(
			result.matchedRoutes.length,
			'Both ~/payments/* and ~/payments-v2/* must match /payments-v2/docs for the shadowing to occur',
		).toBeGreaterThanOrEqual(2);
	});

	it('~/payments-v2/* wins over ~/payments/* for /payments-v2/docs because it is longer (max_uri_length)', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'example.com',
			path: '/payments-v2/docs',
		});
		expect(
			result.winner?.route.name,
			'~/payments-v2/* (11 chars) is longer than ~/payments/* (7 chars) so it wins by max_uri_length',
		).toBe('payments-v2');
	});

	it('~/payments/* still wins for /payments/something (correct routing)', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'example.com',
			path: '/payments/something',
		});
		expect(result.winner?.route.name, '~/payments/* should win for its own path /payments/something').toBe('payments');
	});

	it('the explanation mentions the reason ~/payments-v2/* wins', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'example.com',
			path: '/payments-v2/docs',
		});
		const fullExplanation = result.explanation.join('\n');
		expect(fullExplanation, 'The explanation should mention the route name that wins').toContain('payments-v2');
	});

	it('when ~/payments/* is older, it wins for a path matching only ~/payments/* (no collision for /payments/x)', () => {
		// /payments/x only matches ~/payments/*, not ~/payments-v2/*
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'example.com',
			path: '/payments/x',
		});
		expect(result.matchedRoutes.length, 'Only ~/payments/* should match /payments/x').toBe(1);
		expect(result.winner?.route.name, '/payments/x only matches ~/payments/*, so that route must be the winner').toBe(
			'payments',
		);
	});
});

describe('simulateRequest – no match', () => {
	it('returns undefined winner and a descriptive explanation when nothing matches', () => {
		const route = makeRoute({ paths: ['/api'] });
		const result = simulateRequest([route], {
			method: 'GET',
			host: 'example.com',
			path: '/completely-different',
		});
		expect(result.winner, 'No route should match an unrelated path').toBeUndefined();
		expect(result.explanation[0], 'The explanation should describe the unmatched request').toContain(
			'No route matched',
		);
	});
});

describe('sanitizeUriPostfix – matches Kong utils.lua sanitize_uri_postfix', () => {
	it("returns an empty string for '.' (current dir reference)", () => {
		expect(sanitizeUriPostfix('.'), "Kong sanitises '.' to empty string").toBe('');
	});

	it("returns an empty string for '..' (parent dir reference)", () => {
		expect(sanitizeUriPostfix('..'), "Kong sanitises '..' to empty string").toBe('');
	});

	it('strips leading ./ from the postfix', () => {
		expect(sanitizeUriPostfix('./secret'), "Kong strips './' prefix from URI postfix to prevent path traversal").toBe(
			'secret',
		);
	});

	it('strips leading ../ from the postfix', () => {
		expect(sanitizeUriPostfix('../secret'), "Kong strips '../' prefix from URI postfix").toBe('secret');
	});

	it('leaves a normal postfix unchanged', () => {
		expect(sanitizeUriPostfix('docs/intro'), 'A normal postfix is returned as-is').toBe('docs/intro');
	});
});

describe('computeUpstreamUri – strip_path does NOT affect winner selection', () => {
	it('strip_path=true: strips the matched prefix from the upstream URI', () => {
		const mr = makeRoute({ paths: ['/api'], strip_path: true });
		const upstream = computeUpstreamUri(mr, '/api/users', '/api', '/');
		expect(upstream, 'With strip_path=true, /api prefix is stripped and /users is forwarded').toBe('/users');
	});

	it('strip_path=false: full original path is forwarded to upstream', () => {
		const mr = makeRoute({ paths: ['/api'], strip_path: false });
		const upstream = computeUpstreamUri(mr, '/api/users', '/api', '/');
		expect(upstream, 'With strip_path=false, the full path /api/users is forwarded').toBe('/api/users');
	});

	it("strip_path=true with upstream base '/backend/': correctly joins paths", () => {
		const mr = makeRoute({ paths: ['/api'], strip_path: true });
		const upstream = computeUpstreamUri(mr, '/api/v1/users', '/api', '/backend/');
		expect(upstream, 'Upstream base /backend/ + stripped postfix /v1/users = /backend/v1/users').toBe(
			'/backend/v1/users',
		);
	});
});

describe('marshalRoute – derived fields', () => {
	it('sets hasRegexPath=true when any path starts with ~', () => {
		const mr = makeRoute({ paths: ['/plain', '~/regex/.*'] });
		expect(mr.hasRegexPath, 'hasRegexPath should be true if even one path is a regex path').toBe(true);
	});

	it('sets hasRegexPath=false when all paths are plain prefix', () => {
		const mr = makeRoute({ paths: ['/api', '/health'] });
		expect(mr.hasRegexPath, 'hasRegexPath should be false when no path starts with ~').toBe(false);
	});

	it('maxUriLength reflects the length of the longest raw path string', () => {
		const mr = makeRoute({ paths: ['~/short', '~/a/longer/pattern'] });
		expect(mr.maxUriLength, 'maxUriLength must equal the length of the longest raw path string').toBe(
			'~/a/longer/pattern'.length,
		);
	});

	it('parsedPaths contains one entry per path in route.paths', () => {
		const mr = makeRoute({ paths: ['/a', '/b', '~/c/.*'] });
		expect(mr.parsedPaths.length, 'parsedPaths should have one entry per path in route.paths').toBe(3);
	});
});

describe('matchRoute – header constraints (traditional.lua MATCH_RULES.HEADER ~L966–L1011)', () => {
	it('route with no headers constraint matches a request with no headers (undefined)', () => {
		const mr = makeRoute({ paths: ['/api'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api' }),
			'A route without header constraints must match regardless of request headers',
		).toBe(true);
	});

	it('route with header constraint does NOT match when request.headers is {} (header absent)', () => {
		const route: KongRoute = {
			id: 'r-header',
			paths: ['/api'],
			headers: { 'x-env': ['dev', 'develop', 'development'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: {} }),
			'When request has no headers and route requires x-env, the route must not match',
		).toBe(false);
	});

	it('route with header constraint matches when request includes the required header value (exact, case-insensitive)', () => {
		const route: KongRoute = {
			id: 'r-header',
			paths: ['/api'],
			headers: { 'x-env': ['dev', 'develop', 'development'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-env': 'dev' } }),
			'request header x-env=dev matches allowed value "dev"',
		).toBe(true);
	});

	it('header value comparison is case-insensitive (Kong lowercases both sides)', () => {
		const route: KongRoute = {
			id: 'r-header',
			paths: ['/api'],
			headers: { 'x-env': ['dev'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-env': 'DEV' } }),
			'header value matching is case-insensitive: "DEV" must match allowed value "dev"',
		).toBe(true);
	});

	it('header name lookup is case-insensitive', () => {
		const route: KongRoute = {
			id: 'r-header',
			paths: ['/api'],
			headers: { 'X-Custom-Header': ['expected'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		// request headers passed in lowercase (as HTTP/2 mandates)
		expect(
			matchRoute(mr, {
				method: 'GET',
				host: 'example.com',
				path: '/api',
				headers: { 'x-custom-header': 'expected' },
			}),
			'header name lookup must be case-insensitive',
		).toBe(true);
	});

	it('route with multiple header constraints requires ALL of them (AND semantics)', () => {
		const route: KongRoute = {
			id: 'r-multi-header',
			paths: ['/api'],
			headers: {
				'x-tenant': ['acme'],
				'x-role': ['admin'],
			},
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		// Only one header present → should not match
		expect(
			matchRoute(mr, {
				method: 'GET',
				host: 'example.com',
				path: '/api',
				headers: { 'x-tenant': 'acme' },
			}),
			'All header constraints must be satisfied; missing x-role means no match',
		).toBe(false);
	});

	it('route with multiple header constraints matches when ALL are present', () => {
		const route: KongRoute = {
			id: 'r-multi-header',
			paths: ['/api'],
			headers: {
				'x-tenant': ['acme'],
				'x-role': ['admin'],
			},
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, {
				method: 'GET',
				host: 'example.com',
				path: '/api',
				headers: { 'x-tenant': 'acme', 'x-role': 'admin' },
			}),
			'All header constraints satisfied → route must match',
		).toBe(true);
	});

	it('multiple allowed values for a header use OR semantics (any value satisfies the constraint)', () => {
		const route: KongRoute = {
			id: 'r-multi-value',
			paths: ['/api'],
			headers: { 'x-env': ['dev', 'develop', 'development'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-env': 'develop' } }),
			'"develop" is one of the allowed values for x-env → should match',
		).toBe(true);
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-env': 'staging' } }),
			'"staging" is not in the allowed values list → should not match',
		).toBe(false);
	});

	it('header constraint with ~* prefix uses regex matching (Kong header_pattern)', () => {
		// Kong only sets header_pattern when there is exactly ONE value starting with ~*
		const route: KongRoute = {
			id: 'r-regex-header',
			paths: ['/api'],
			headers: { 'x-version': ['~*^v[0-9]+$'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-version': 'v3' } }),
			'x-version=v3 matches regex ^v[0-9]+$',
		).toBe(true);
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-version': 'beta' } }),
			'x-version=beta does not match regex ^v[0-9]+$',
		).toBe(false);
	});

	it('when request.headers is undefined, header constraints are skipped (static analysis mode)', () => {
		// In static analysis (analyzer), SimRequest.headers is always undefined.
		// Header-constrained routes must still be treated as potential candidates.
		const route: KongRoute = {
			id: 'r-header',
			paths: ['/api'],
			headers: { 'x-env': ['dev'] },
		};
		const mr = marshalRoute(route, undefined, 'traditional');
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api' }),
			'When request.headers is undefined the header constraint is ignored (static analysis mode)',
		).toBe(true);
	});
});

describe('compareRoutes – header count sort tier (sort_routes L686–L688)', () => {
	it('route with more header constraints beats one with fewer at same submatch_weight', () => {
		const twoHeaders: KongRoute = {
			id: 'r-two',
			paths: ['~/users/(.+)'],
			headers: { 'x-tenant': ['acme'], 'x-role': ['admin'] },
		};
		const oneHeader: KongRoute = {
			id: 'r-one',
			paths: ['~/users/(.+)'],
			headers: { 'x-tenant': ['acme'] },
		};
		const mrTwo = marshalRoute(twoHeaders, undefined, 'traditional');
		const mrOne = marshalRoute(oneHeader, undefined, 'traditional');

		expect(
			compareRoutes(mrTwo, mrOne),
			'Route with 2 header constraints must beat route with 1 (Kong: headers[0] count)',
		).toBeLessThan(0);
	});

	it('route with header constraints beats route with no headers (same path)', () => {
		const withHeader: KongRoute = {
			id: 'r-with',
			paths: ['~/users/(.+)'],
			headers: { 'x-env': ['dev', 'develop', 'development'] },
		};
		const noHeader: KongRoute = { id: 'r-without', paths: ['~/users/(.+)'] };
		const mrWith = marshalRoute(withHeader, undefined, 'traditional');
		const mrNo = marshalRoute(noHeader, undefined, 'traditional');

		expect(
			compareRoutes(mrWith, mrNo),
			'A header-constrained route has higher priority than an unconstrained route at the same path',
		).toBeLessThan(0);
	});
});

describe('compareRoutes – regex_priority (sort_routes L692–L697)', () => {
	it('regex route with higher regex_priority beats one with lower', () => {
		const highPriRoute: KongRoute = {
			id: 'r-high',
			paths: ['~/timesheetmanager-v2/api/delegation-form/sync$'],
			regex_priority: 100,
		};
		const lowPriRoute: KongRoute = {
			id: 'r-low',
			paths: ['~/timesheetmanager-v2/(.*)'],
			regex_priority: 0,
		};
		const mrHigh = marshalRoute(highPriRoute, undefined, 'traditional');
		const mrLow = marshalRoute(lowPriRoute, undefined, 'traditional');

		expect(
			compareRoutes(mrHigh, mrLow),
			'regex_priority=100 must beat regex_priority=0 between two regex routes',
		).toBeLessThan(0);
	});

	it('regex_priority is NOT compared between a regex and a plain route (submatch_weight decides first)', () => {
		// A plain route with any regex_priority value still loses to a regex route
		// because submatch_weight (HAS_REGEX_URI) is evaluated first.
		const regexRoute: KongRoute = { id: 'r-regex', paths: ['~/api/(.*)'], regex_priority: 0 };
		const plainRoute: KongRoute = { id: 'r-plain', paths: ['/api'], regex_priority: 999 };
		const mrRegex = marshalRoute(regexRoute, undefined, 'traditional');
		const mrPlain = marshalRoute(plainRoute, undefined, 'traditional');

		expect(
			compareRoutes(mrRegex, mrPlain),
			'The regex route wins regardless of regex_priority because submatch_weight is evaluated first',
		).toBeLessThan(0);
	});

	it('header count is evaluated before regex_priority when both routes are regex', () => {
		// One route has a higher regex_priority but fewer header constraints.
		// The route with more headers should still win (header count is tier 2, regex_priority is tier 3).
		const moreHeaders: KongRoute = {
			id: 'r-headers',
			paths: ['~/api/(.*)'],
			headers: { 'x-tenant': ['acme'] },
			regex_priority: 0,
		};
		const highPriNoHeaders: KongRoute = { id: 'r-hipri', paths: ['~/api/(.*)'], regex_priority: 50 };
		const mrHeaders = marshalRoute(moreHeaders, undefined, 'traditional');
		const mrHiPri = marshalRoute(highPriNoHeaders, undefined, 'traditional');

		expect(
			compareRoutes(mrHeaders, mrHiPri),
			'header count (tier 2) is evaluated before regex_priority (tier 3): more headers wins',
		).toBeLessThan(0);
	});
});

describe('simulateRequest – header-constrained routing (real-world x-env pattern)', () => {
	// Mirrors the exact pattern seen in the integration control plane –
	//   auth-dev-users   ~/users/([^/]+)  headers: {x-env: [dev, develop, development]}
	//   auth-prod-users  ~/users/([^/]+)  (no header constraint)
	const devRoute: KongRoute = {
		id: 'auth-dev',
		name: 'auth-dev-users',
		paths: ['~/users/([^/]+)'],
		methods: ['GET'],
		headers: { 'x-env': ['dev', 'develop', 'development'] },
		regex_priority: 0,
		created_at: 1700000000,
	};
	const internalRoute: KongRoute = {
		id: 'auth-internal',
		name: 'auth-prod-users',
		paths: ['~/users/([^/]+)'],
		methods: ['GET'],
		regex_priority: 0,
		created_at: 1700000001, // created slightly later
	};
	const mrDev = marshalRoute(devRoute, undefined, 'traditional');
	const mrInternal = marshalRoute(internalRoute, undefined, 'traditional');
	const sorted = [mrDev, mrInternal].sort(compareRoutes);

	it('with x-env:dev header, the dev route wins (header-constrained route has higher sort priority)', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'api.example.com',
			path: '/users/alice',
			headers: { 'x-env': 'dev' },
		});
		expect(result.winner?.route.id, 'dev route must win when x-env=dev is present').toBe('auth-dev');
	});

	it('without x-env header, the internal (unconstrained) route wins', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'api.example.com',
			path: '/users/alice',
			headers: {}, // explicit empty = no headers
		});
		expect(result.winner?.route.id, 'internal route must win when x-env header is absent').toBe('auth-internal');
	});

	it('with an unrecognised x-env value, the internal route wins (dev route does not match)', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'api.example.com',
			path: '/users/alice',
			headers: { 'x-env': 'production' },
		});
		expect(result.winner?.route.id, '"production" is not in dev route allowed values → internal route wins').toBe(
			'auth-internal',
		);
	});

	it('in static analysis mode (no headers in request), both routes are candidates (header constraints skipped)', () => {
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'api.example.com',
			path: '/users/alice',
			// headers intentionally omitted = static analysis mode
		});
		expect(
			result.matchedRoutes.length,
			'Both routes should be considered in static analysis mode (headers constraints are skipped)',
		).toBe(2);
	});
});

describe('classifyPath – malformed regex path', () => {
	it('does not throw for a malformed regex; stores a never-matching sentinel instead', () => {
		// ~/[invalid is not valid PCRE – the missing ] makes it a syntax error.
		// classifyPath should catch this and store /(?!)/ so analysis can
		// continue and still flag it as suspicious.
		expect(
			() => classifyPath('~/[invalid', 'traditional'),
			'classifyPath must not throw even when the regex path is malformed PCRE',
		).not.toThrow();
		const parsed = classifyPath('~/[invalid', 'traditional');
		expect(parsed.kind, 'A malformed regex path is still classified as kind=regex (it starts with ~)').toBe('regex');
		expect(
			parsed.regex?.test('/any/path'),
			'The sentinel /(?!)/ never matches anything, so test() must return false',
		).toBe(false);
	});
});

describe('matchRoute – universal host wildcard "*"', () => {
	it('route with hosts: ["*"] matches any host value', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'anything.example.com', path: '/api/test' }),
			'hosts: ["*"] is a universal host wildcard and must match every host',
		).toBe(true);
	});

	it('route with exact host matches only that host', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['api.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'other.example.com', path: '/api/test' }),
			'An exact host constraint must NOT match a different host',
		).toBe(false);
		expect(
			matchRoute(mr, { method: 'GET', host: 'api.example.com', path: '/api/test' }),
			'An exact host constraint must match the exact host',
		).toBe(true);
	});
});

describe('matchRoute – malformed ~* header regex does not crash', () => {
	it('treats a malformed ~* header regex as a non-match (does not throw)', () => {
		const mr = makeRoute({
			paths: ['/api'],
			headers: { 'x-env': ['~*[invalid'] }, // [invalid is not valid PCRE
		});
		expect(
			() => matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-env': 'prod' } }),
			'A malformed ~* header regex must not throw',
		).not.toThrow();
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api', headers: { 'x-env': 'prod' } }),
			'When the ~* header regex is malformed, the route should not match (null pattern → no regex match)',
		).toBe(false);
	});
});

describe('computeUpstreamUri – non-trailing-slash upstreamBase branches', () => {
	it('strip_path=true, upstreamBase without trailing slash, postfix without leading slash', () => {
		const mr = makeRoute({ paths: ['/api'], strip_path: true });
		// reqPath=/api/users, matchedPrefix=/api → postfix=users (no leading slash after sanitize)
		// upstreamBase=/backend (no trailing slash) → /backend/users
		const result = computeUpstreamUri(mr, '/api/users', '/api', '/backend');
		expect(result, 'upstreamBase /backend + postfix /users = /backend/users').toBe('/backend/users');
	});

	it('strip_path=true, upstreamBase without trailing slash, no postfix → returns upstreamBase as-is', () => {
		const mr = makeRoute({ paths: ['/api'], strip_path: true });
		// reqPath=/api, matchedPrefix=/api → postfix='' (empty)
		const result = computeUpstreamUri(mr, '/api', '/api', '/backend');
		expect(result, 'When postfix is empty, upstreamBase /backend is returned unchanged').toBe('/backend');
	});

	it('strip_path=false, reqPath=/ returns upstreamBase unchanged', () => {
		const mr = makeRoute({ paths: ['/'], strip_path: false });
		const result = computeUpstreamUri(mr, '/', '/', '/backend/');
		expect(result, 'strip_path=false and reqPath=/ should return the upstreamBase verbatim').toBe('/backend/');
	});

	it('strip_path=true, upstreamBase=/ with no postfix → returns /', () => {
		const mr = makeRoute({ paths: ['/api'], strip_path: true });
		// reqPath=/api, matchedPrefix=/api → postfix='' → upstreamBase='/' → return '/'
		const result = computeUpstreamUri(mr, '/api', '/api', '/');
		expect(result, 'strip_path=true with empty postfix and upstreamBase=/ should return /').toBe('/');
	});
});

describe('extractMatchedPrefix', () => {
	it('returns the plain prefix for a prefix route', () => {
		const mr = makeRoute({ paths: ['/api/v1'] });
		expect(
			extractMatchedPrefix(mr, '/api/v1/users'),
			'For a plain prefix route, the matched prefix is the route path itself',
		).toBe('/api/v1');
	});

	it('returns the regex-matched portion for a regex route', () => {
		// ~/api/v[0-9]+ matches /api/v1 but not the /users part.
		const mr = makeRoute({ paths: ['~/api/v[0-9]+'] });
		expect(
			extractMatchedPrefix(mr, '/api/v1/users'),
			'For a regex route, extractMatchedPrefix returns the portion matched by the regex',
		).toBe('/api/v1');
	});

	it('returns empty string when no path matches', () => {
		const mr = makeRoute({ paths: ['/other'] });
		expect(
			extractMatchedPrefix(mr, '/api/v1/users'),
			'When no path matches the request, extractMatchedPrefix returns an empty string',
		).toBe('');
	});
});

describe('marshalRoute – subMatchWeight 3-bit field (traditional.lua MATCH_SUBRULES)', () => {
	it('bit 0 (HAS_REGEX_URI) is set when any path is a regex path', () => {
		const mr = makeRoute({ paths: ['~/api/.*'] });
		expect(mr.subMatchWeight & 0x01, 'Bit 0 must be set when the route has a regex path').toBe(1);
	});

	it('bit 0 is NOT set for a plain-prefix route', () => {
		const mr = makeRoute({ paths: ['/api'] });
		expect(mr.subMatchWeight & 0x01, 'Bit 0 must be 0 for plain-prefix routes').toBe(0);
	});

	it('bit 1 (PLAIN_HOSTS_ONLY) is set when all hosts are plain (no wildcards)', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['api.example.com'] });
		expect(mr.subMatchWeight & 0x02, 'Bit 1 must be set when every host constraint is a plain hostname').toBe(2);
	});

	it('bit 1 (PLAIN_HOSTS_ONLY) is NOT set when any host is a wildcard', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(mr.subMatchWeight & 0x02, 'Bit 1 must be 0 when the route has a wildcard host constraint').toBe(0);
	});

	it('bit 1 is NOT set when the route has no host constraints (no hosts array = any host)', () => {
		// A route with no hosts is open to any host — it is not "plain hosts only"
		// in the PLAIN_HOSTS_ONLY sense (Kong only sets this bit when there are hosts
		// AND none are wildcards). When hosts is absent/empty Kong skips the whole block.
		const mr = makeRoute({ paths: ['/api'] });
		expect(
			mr.subMatchWeight & 0x02,
			'Bit 1 must be 0 when there are no host constraints (Kong does not set PLAIN_HOSTS_ONLY for unconstrained routes)',
		).toBe(0);
	});

	it('bit 2 (HAS_WILDCARD_HOST_PORT) is set when a wildcard host has an explicit port', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com:8080'] });
		expect(mr.subMatchWeight & 0x04, 'Bit 2 must be set when a wildcard host includes an explicit port').toBe(4);
	});

	it('bit 2 is NOT set when the wildcard host has no explicit port', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(mr.subMatchWeight & 0x04, 'Bit 2 must be 0 when the wildcard host has no explicit port').toBe(0);
	});

	it('mixed route: regex path (bit 0) + plain hosts (bit 1) → subMatchWeight = 3', () => {
		const mr = makeRoute({ paths: ['~/api/.*'], hosts: ['api.example.com'] });
		expect(mr.subMatchWeight, 'Regex path (bit 0) + plain host (bit 1) = 0b011 = 3').toBe(3);
	});

	it('hasRegexPath is always consistent with bit 0 of subMatchWeight', () => {
		const withRegex = makeRoute({ paths: ['~/api/.*'] });
		const withPlain = makeRoute({ paths: ['/api'] });
		expect(withRegex.hasRegexPath).toBe(!!(withRegex.subMatchWeight & 0x01));
		expect(withPlain.hasRegexPath).toBe(!!(withPlain.subMatchWeight & 0x01));
	});
});

describe('compareRoutes – PLAIN_HOSTS_ONLY beats wildcard-host at same path', () => {
	it('plain-host route beats wildcard-host route at the same path and regex_priority', () => {
		// This is the most common multi-tenant Kong pattern:
		//   payments.internal.example.com → specific service (plain host)
		//   *.internal.example.com        → catch-all (wildcard host)
		// Kong: PLAIN_HOSTS_ONLY (bit 1) is set on the plain-host route, making
		// its subMatchWeight higher (at least 0x02 vs 0x00 for wildcard).
		const plainHost = makeRoute({
			id: 'r-plain',
			paths: ['/v1/users'],
			hosts: ['api.example.com'],
		});
		const wildcardHost = makeRoute({
			id: 'r-wildcard',
			paths: ['/v1/users'],
			hosts: ['*.example.com'],
		});

		expect(
			compareRoutes(plainHost, wildcardHost),
			'Plain-host route must beat wildcard-host route (PLAIN_HOSTS_ONLY bit 1 > 0)',
		).toBeLessThan(0);
	});

	it('wildcard-host-with-port beats wildcard-host-without-port at the same path', () => {
		// Kong: HAS_WILDCARD_HOST_PORT (bit 2) ranks *.example.com:8080 above *.example.com.
		const withPort = makeRoute({
			id: 'r-with-port',
			paths: ['/api'],
			hosts: ['*.example.com:8080'],
		});
		const withoutPort = makeRoute({
			id: 'r-without-port',
			paths: ['/api'],
			hosts: ['*.example.com'],
		});

		expect(
			compareRoutes(withPort, withoutPort),
			'Wildcard host with explicit port must beat wildcard host without port (HAS_WILDCARD_HOST_PORT bit 2)',
		).toBeLessThan(0);
	});

	it('wildcard-host-with-port (0x04) beats plain-host-no-regex (0x02) — HAS_WILDCARD_HOST_PORT outranks PLAIN_HOSTS_ONLY alone', () => {
		// Counter-intuitive edge case confirmed by Kong source (traditional.lua L682-684):
		//   sort_routes compares submatch_weight as a raw integer — higher wins.
		// Plain host (no regex path):            PLAIN_HOSTS_ONLY (bit 1)              = 0x02 = 2
		// Wildcard host with port (no regex):    HAS_WILDCARD_HOST_PORT (bit 2)         = 0x04 = 4
		// Because 4 > 2, the wildcard-with-port route wins over the plain-host route.
		// To beat a wildcard-with-port, a plain-host route must ALSO have a regex path:
		//   plain-host + regex: bit 0 + bit 1 = 0x03 = 3 — still less than 4.
		// So a wildcard-with-port (0x04) always beats a plain-host (0x02 or 0x03) in Kong's
		// submatch_weight ordering. This is a subtle but important nuance.
		const plainNoRegex = makeRoute({
			id: 'r-plain',
			paths: ['/api'],
			hosts: ['api.example.com'],
		});
		const wildcardWithPort = makeRoute({
			id: 'r-wc-port',
			paths: ['/api'],
			hosts: ['*.example.com:8080'],
		});

		expect(
			plainNoRegex.subMatchWeight,
			'plain host, no regex path → only PLAIN_HOSTS_ONLY (bit 1) is set → subMatchWeight = 2',
		).toBe(2);
		expect(
			wildcardWithPort.subMatchWeight,
			'wildcard host with explicit port, no regex → only HAS_WILDCARD_HOST_PORT (bit 2) is set → subMatchWeight = 4',
		).toBe(4);
		expect(
			compareRoutes(wildcardWithPort, plainNoRegex),
			'HAS_WILDCARD_HOST_PORT (0x04 = 4) outranks PLAIN_HOSTS_ONLY (0x02 = 2) in Kong integer comparison — wildcard-with-port wins',
		).toBeLessThan(0);
	});
});

describe('compareRoutes – subMatchWeight sort tier takes precedence over all others', () => {
	it('plain-host route wins over wildcard-host even when wildcard has higher regex_priority', () => {
		// regex_priority is only compared within the same submatch_weight tier (tier 3).
		// subMatchWeight is tier 1, so a plain-host route wins regardless of regex_priority.
		const plainHost = makeRoute({
			id: 'r-plain',
			paths: ['~/api/.*'],
			hosts: ['api.example.com'],
			regex_priority: 0,
		});
		const wildcardHighPri = makeRoute({
			id: 'r-wildcard',
			paths: ['~/api/.*'],
			hosts: ['*.example.com'],
			regex_priority: 100,
		});

		expect(
			compareRoutes(plainHost, wildcardHighPri),
			'subMatchWeight (tier 1) is evaluated before regex_priority (tier 3); plain-host wins',
		).toBeLessThan(0);
	});
});

describe('simulateRequest – explanation text for subMatchWeight ordering', () => {
	it('explanation mentions PLAIN_HOSTS_ONLY when plain-host beats wildcard-host', () => {
		const plainHost = makeRoute({ id: 'r-plain', paths: ['/v1/users'], hosts: ['api.example.com'] });
		const wildcardHost = makeRoute({ id: 'r-wildcard', paths: ['/v1/users'], hosts: ['*.example.com'] });
		const sorted = [plainHost, wildcardHost].sort(compareRoutes);
		const result = simulateRequest(sorted, { method: 'GET', host: 'api.example.com', path: '/v1/users' });
		const text = result.explanation.join(' ');
		expect(
			text.toLowerCase().includes('plain') || text.toLowerCase().includes('submatch'),
			'Explanation must mention plain-host priority or submatch_weight',
		).toBe(true);
	});
});

describe('matchRoute – wildcard host port handling', () => {
	it('*.example.com (no port) matches a request Host with an explicit port', () => {
		// Kong compiles *.example.com as /.+\.example\.com(?::\d+)?$/ — it accepts
		// any port. Our previous endsWith check would have returned false for
		// "foo.example.com:8443".
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'foo.example.com:8443', path: '/api' }),
			'*.example.com (no port in constraint) must match foo.example.com:8443',
		).toBe(true);
	});

	it('*.example.com (no port) matches a request Host without a port', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'foo.example.com', path: '/api' }),
			'*.example.com must still match foo.example.com when no port is present',
		).toBe(true);
	});

	it('*.example.com:8080 (explicit port) matches only requests with that port', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com:8080'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'foo.example.com:8080', path: '/api' }),
			'*.example.com:8080 must match foo.example.com:8080',
		).toBe(true);
	});

	it('*.example.com:8080 does NOT match a request with a different port', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com:8080'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'foo.example.com:9090', path: '/api' }),
			'*.example.com:8080 must not match foo.example.com:9090 (wrong port)',
		).toBe(false);
	});

	it('*.example.com:8080 does NOT match a request without a port', () => {
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com:8080'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'foo.example.com', path: '/api' }),
			'*.example.com:8080 must not match foo.example.com (port required)',
		).toBe(false);
	});

	it('*.example.com does NOT match a plain domain (must have a subdomain)', () => {
		// Kong pattern: .+\.example\.com — requires at least one character before the dot.
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'example.com', path: '/api' }),
			'*.example.com must NOT match example.com (no subdomain)',
		).toBe(false);
	});

	it('*.example.com does NOT match an entirely different domain (example.org)', () => {
		// Regression guard: the suffix check must be exact — "example.org" does not end with
		// ".example.com", so it must never match the *.example.com constraint.
		const mr = makeRoute({ paths: ['/api'], hosts: ['*.example.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'foo.example.org', path: '/api' }),
			'*.example.com must NOT match foo.example.org — different TLD/domain',
		).toBe(false);
	});

	it('route with multiple host constraints matches a host that satisfies ANY of them', () => {
		// Kong: any of the listed host constraints matching is sufficient (OR semantics).
		const mr = makeRoute({ paths: ['/api'], hosts: ['api.example.com', '*.other.com'] });
		expect(
			matchRoute(mr, { method: 'GET', host: 'api.example.com', path: '/api' }),
			'The plain host api.example.com must match when it is explicitly listed',
		).toBe(true);
		expect(
			matchRoute(mr, { method: 'GET', host: 'sub.other.com', path: '/api' }),
			'The wildcard *.other.com must match sub.other.com (second constraint)',
		).toBe(true);
		expect(
			matchRoute(mr, { method: 'GET', host: 'unrelated.example.net', path: '/api' }),
			'A host not matching any of the listed constraints must not match the route',
		).toBe(false);
	});
});

// ─── marshalRoute – subMatchWeight edge cases (Kong traditional.lua L333–L374) ──

describe('marshalRoute – subMatchWeight edge cases: mixed and multi-wildcard hosts', () => {
	it('PLAIN_HOSTS_ONLY (bit 1) is NOT set when hosts array contains BOTH plain and wildcard entries', () => {
		// Kong L368: "if not has_host_wildcard then submatch_weight |= PLAIN_HOSTS_ONLY"
		// When the array has even ONE wildcard, has_host_wildcard is true → bit 1 is never set.
		// So "api.example.com, *.fallback.com" is NOT treated as plain-hosts-only.
		const mr = makeRoute({
			paths: ['/api'],
			hosts: ['api.example.com', '*.fallback.example.com'],
		});
		expect(
			mr.subMatchWeight & 0x02,
			'A host array containing any wildcard must NOT set PLAIN_HOSTS_ONLY (bit 1) — even one wildcard disqualifies the route',
		).toBe(0);
	});

	it('PLAIN_HOSTS_ONLY (bit 1) IS set when all hosts in a multi-entry array are plain', () => {
		// Multiple plain hosts: still no wildcard → PLAIN_HOSTS_ONLY is set.
		const mr = makeRoute({
			paths: ['/api'],
			hosts: ['api.example.com', 'api.staging.example.com', 'api.dev.example.com'],
		});
		expect(mr.subMatchWeight & 0x02, 'All three hosts are plain (no wildcards) → PLAIN_HOSTS_ONLY must be set').toBe(2);
	});

	it('HAS_WILDCARD_HOST_PORT (bit 2) is set when the SECOND wildcard host has a port (first has none)', () => {
		// Kong L345: "if has_wildcard_host_port == nil and has_port then has_wildcard_host_port = true"
		// This fires for ANY wildcard with a port, not just the first.
		// hosts: ['*.no-port.com', '*.example.com:8080'] — first wildcard has no port, second does.
		const mr = makeRoute({
			paths: ['/api'],
			hosts: ['*.no-port.com', '*.example.com:8080'],
		});
		expect(
			mr.subMatchWeight & 0x04,
			'Bit 2 must be set even when only the second wildcard host has an explicit port',
		).toBe(4);
	});

	it('HAS_WILDCARD_HOST_PORT (bit 2) is NOT set when all wildcards have no port', () => {
		const mr = makeRoute({
			paths: ['/api'],
			hosts: ['*.foo.com', '*.bar.com'],
		});
		expect(
			mr.subMatchWeight & 0x04,
			'No wildcard in the array has a port → HAS_WILDCARD_HOST_PORT (bit 2) must remain 0',
		).toBe(0);
	});

	it('regex path + plain hosts: subMatchWeight has both bit 0 (HAS_REGEX_URI) and bit 1 (PLAIN_HOSTS_ONLY) set', () => {
		// Combination: regex path sets bit 0; all-plain hosts set bit 1 → 0x01 | 0x02 = 0x03
		const mr = makeRoute({
			paths: ['~/api/v[0-9]+'],
			hosts: ['api.example.com'],
		});
		expect(
			mr.subMatchWeight,
			'Regex path (bit 0 = 0x01) AND plain host (bit 1 = 0x02) → subMatchWeight = 0x03 = 3',
		).toBe(3);
	});

	it('regex path + wildcard hosts: only bit 0 (HAS_REGEX_URI) is set — PLAIN_HOSTS_ONLY is absent', () => {
		const mr = makeRoute({
			paths: ['~/api/v[0-9]+'],
			hosts: ['*.example.com'],
		});
		expect(
			mr.subMatchWeight,
			'Regex path (bit 0) but wildcard host → PLAIN_HOSTS_ONLY not set → subMatchWeight = 0x01 = 1',
		).toBe(1);
	});
});

// ─── compareRoutes – all subMatchWeight bit combinations (Gap #1 deep coverage) ──

describe('compareRoutes – all subMatchWeight combinations (Gap #1 deep coverage)', () => {
	it('wildcard-with-port (0x04) beats regex-plain-host (0x03) — bit 2 integer-dominates bits 0+1', () => {
		// A route with regex path + plain hosts has subMatchWeight = 0x03.
		// A route with no regex path but a wildcard-with-port has subMatchWeight = 0x04.
		// Kong compares submatch_weight as a raw unsigned integer → 4 > 3, wildcard-with-port wins.
		// This is the most surprising edge case: a more-constrained route (regex + plain host) loses
		// to a less-constrained wildcard-with-port route solely because of how the bits are assigned.
		const regexPlainHost = makeRoute({
			id: 'r-regex-plain',
			paths: ['~/api/v[0-9]+'],
			hosts: ['api.example.com'],
		});
		const noRegexWildcardPort = makeRoute({
			id: 'r-wc-port',
			paths: ['/api'],
			hosts: ['*.example.com:8080'],
		});

		expect(regexPlainHost.subMatchWeight, 'Regex path (bit 0) + plain host (bit 1) → 0x01 | 0x02 = 0x03 = 3').toBe(3);
		expect(noRegexWildcardPort.subMatchWeight, 'No regex path, wildcard host with port (bit 2 only) → 0x04 = 4').toBe(
			4,
		);
		expect(
			compareRoutes(noRegexWildcardPort, regexPlainHost),
			'subMatchWeight 4 (wildcard-with-port) > 3 (regex-plain-host) — wildcard-with-port wins by integer comparison',
		).toBeLessThan(0);
	});

	it('plain-host route (0x02) beats wildcard-host route (0x00) at same path — simple common case', () => {
		// This is the main practical case: a named service route beating a wildcard catch-all.
		// plain-host (no regex): PLAIN_HOSTS_ONLY (bit 1) → 0x02
		// wildcard-host (no regex, no port): 0x00
		// 0x02 > 0x00 → plain-host wins.
		const plainHost = makeRoute({
			id: 'r-plain',
			paths: ['/api'],
			hosts: ['payments.internal.example.com'],
		});
		const wildcardHost = makeRoute({
			id: 'r-wildcard',
			paths: ['/api'],
			hosts: ['*.internal.example.com'],
		});

		expect(plainHost.subMatchWeight, 'Plain host, no regex → only PLAIN_HOSTS_ONLY (bit 1) = 0x02 = 2').toBe(2);
		expect(wildcardHost.subMatchWeight, 'Wildcard host (no port), no regex → no bits set → subMatchWeight = 0').toBe(0);
		expect(
			compareRoutes(plainHost, wildcardHost),
			'Plain-host route (subMatchWeight=2) must beat wildcard-host route (subMatchWeight=0)',
		).toBeLessThan(0);
	});

	it('when subMatchWeight is equal, header count is the next tiebreaker (not regex_priority)', () => {
		// Both routes: no regex, plain host → subMatchWeight = 0x02.
		// Route A has one header constraint, route B has none.
		// A must win by header count (tier 2), not by any subMatchWeight difference.
		const withHeader = makeRoute({
			id: 'r-header',
			paths: ['/api'],
			hosts: ['api.example.com'],
			headers: { 'x-env': ['prod'] },
		});
		const noHeader = makeRoute({
			id: 'r-no-header',
			paths: ['/api'],
			hosts: ['api.example.com'],
		});

		expect(
			withHeader.subMatchWeight,
			'Plain host with header constraint → subMatchWeight = 0x02 (same as next route)',
		).toBe(2);
		expect(noHeader.subMatchWeight, 'Plain host with no header constraint → subMatchWeight = 0x02').toBe(2);
		expect(
			compareRoutes(withHeader, noHeader),
			'Tie on subMatchWeight: route with header constraint wins via header-count tier (tier 2)',
		).toBeLessThan(0);
	});
});

// ─── simulateRequest – HAS_WILDCARD_HOST_PORT explanation (Gap #1 deep coverage) ──

describe('simulateRequest – explanation text for HAS_WILDCARD_HOST_PORT ordering (Gap #1)', () => {
	it('explanation mentions HAS_WILDCARD_HOST_PORT when wildcard-with-port beats wildcard-without-port', () => {
		const withPort = makeRoute({
			id: 'r-with-port',
			name: 'wildcard-ported',
			paths: ['/api'],
			hosts: ['*.example.com:8080'],
		});
		const withoutPort = makeRoute({
			id: 'r-without-port',
			name: 'wildcard-unported',
			paths: ['/api'],
			hosts: ['*.example.com'],
		});
		const sorted = [withPort, withoutPort].sort(compareRoutes);
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'foo.example.com:8080',
			path: '/api',
		});
		const text = result.explanation.join(' ');
		expect(
			text.toLowerCase().includes('wildcard') ||
				text.toLowerCase().includes('port') ||
				text.toLowerCase().includes('submatch'),
			'Explanation for HAS_WILDCARD_HOST_PORT ordering must mention port, wildcard, or submatch_weight',
		).toBe(true);
	});

	it('wildcard-with-port wins the simulation when both routes match a ported request', () => {
		const withPort = makeRoute({
			id: 'r-with-port',
			name: 'ported',
			paths: ['/api'],
			hosts: ['*.example.com:8080'],
		});
		const withoutPort = makeRoute({
			id: 'r-without-port',
			name: 'unported',
			paths: ['/api'],
			hosts: ['*.example.com'],
		});
		const sorted = [withPort, withoutPort].sort(compareRoutes);
		const result = simulateRequest(sorted, {
			method: 'GET',
			host: 'foo.example.com:8080',
			path: '/api',
		});
		expect(
			result.winner?.route.id,
			'Wildcard-with-port (HAS_WILDCARD_HOST_PORT, subMatchWeight=4) must win over wildcard-without-port (subMatchWeight=0)',
		).toBe('r-with-port');
	});
});
