/**
 * Tests for src/filter.ts – route filter predicates and finding-level filtering.
 *
 * The --filter feature supports the following predicates:
 *   path:<prefix>   – routes whose path stem starts with prefix
 *   name:<substr>   – routes whose name contains substr (case-insensitive)
 *   service:<value> – routes whose service id equals value OR service name contains value
 *   tag:<value>     – routes tagged with exactly this value
 *   id:<uuid>       – routes with this exact id
 *
 * AND between different keys, OR within the same key.
 * A finding is included when ANY of its involved routes satisfies all predicates.
 */

import { describe, it, expect } from 'bun:test';

import {
	parseFilter,
	parseFilters,
	routeMatchesPredicate,
	routeMatchesAllPredicates,
	applyFindingFilter,
} from './filter.ts';
import type { Finding, KongRoute, KongService } from './types.ts';

const serviceA: KongService = { id: 'svc-a', name: 'epp-service', host: 'epp.internal' };
const serviceB: KongService = { id: 'svc-b', name: 'epp-poc-service', host: 'poc.internal' };
const serviceC: KongService = { id: 'svc-c', name: 'unrelated-service', host: 'other.internal' };

const routeEpp: KongRoute = {
	id: 'route-epp',
	name: 'epp-route',
	paths: ['~/epp/*'],
	tags: ['team-platform', 'env-prod'],
	service: { id: 'svc-a' },
};

const routeEppPoc: KongRoute = {
	id: 'route-epp-poc',
	name: 'epp-poc-route',
	paths: ['/epp-poc/docs', '/epp-poc/api'],
	tags: ['team-platform', 'env-dev'],
	service: { id: 'svc-b' },
};

const routeUnrelated: KongRoute = {
	id: 'route-unrelated',
	name: 'unrelated-route',
	paths: ['/healthz'],
	tags: ['team-ops'],
	service: { id: 'svc-c' },
};

const services = new Map<string, KongService>([
	['svc-a', serviceA],
	['svc-b', serviceB],
	['svc-c', serviceC],
]);

function makeFinding(routes: KongRoute[], severity: Finding['severity'] = 'HIGH'): Finding {
	return {
		severity,
		type: 'shadowing',
		routerFlavor: 'traditional',
		routes,
		samples: ['/epp-poc/docs'],
		winnerId: routes[0]?.id,
		reason: ['test finding'],
		suggestions: [],
	};
}

describe('parseFilter – parsing --filter key:value strings', () => {
	it('parses a path predicate', () => {
		const p = parseFilter('path:/api/v2');
		expect(p.key, "key should be 'path'").toBe('path');
		expect(p.value, 'value should be the path prefix').toBe('/api/v2');
	});

	it('parses a name predicate', () => {
		const p = parseFilter('name:epp');
		expect(p.key, "key should be 'name'").toBe('name');
		expect(p.value, 'value should be the name substring').toBe('epp');
	});

	it('parses a service predicate', () => {
		const p = parseFilter('service:epp-svc');
		expect(p.key, "key should be 'service'").toBe('service');
		expect(p.value, 'value should be the service name/id to match').toBe('epp-svc');
	});

	it('parses a tag predicate', () => {
		const p = parseFilter('tag:team-platform');
		expect(p.key, "key should be 'tag'").toBe('tag');
		expect(p.value, 'value should be the exact tag string to match').toBe('team-platform');
	});

	it('parses an id predicate', () => {
		const p = parseFilter('id:route-epp');
		expect(p.key, "key should be 'id'").toBe('id');
		expect(p.value, 'value should be the exact route UUID to match').toBe('route-epp');
	});

	it('preserves colons in the value (value may itself contain colons)', () => {
		const p = parseFilter('path:~/api:v2/resource');
		expect(p.key, 'key should stop at first colon').toBe('path');
		expect(p.value, 'value includes everything after the first colon').toBe('~/api:v2/resource');
	});

	it('throws when no colon is present', () => {
		expect(() => parseFilter('pathapi'), 'missing colon should throw').toThrow(/expected format key:value/);
	});

	it('throws on an unrecognised key', () => {
		expect(() => parseFilter('host:example.com'), 'unknown key should throw').toThrow(/Unknown filter key "host"/);
	});

	it('throws when the value is empty', () => {
		expect(() => parseFilter('name:'), 'empty value should throw').toThrow(/must not be empty/);
	});
});

describe('parseFilters – wraps parseFilter for CLI option values', () => {
	it('returns empty array for undefined (flag not provided)', () => {
		expect(parseFilters(undefined), 'no --filter flags → empty predicate list').toEqual([]);
	});

	it('wraps a single string in an array', () => {
		const preds = parseFilters('path:/api');
		expect(preds, 'a single filter string should produce exactly one predicate').toHaveLength(1);
		expect(preds[0]!.key, "the parsed predicate key should be 'path'").toBe('path');
	});

	it('parses an array (flag provided multiple times)', () => {
		const preds = parseFilters(['tag:team-a', 'service:epp-svc']);
		expect(preds, 'two filter strings should produce two predicates').toHaveLength(2);
		expect(preds[0]!.key, "first predicate key should be 'tag'").toBe('tag');
		expect(preds[1]!.key, "second predicate key should be 'service'").toBe('service');
	});
});

describe('routeMatchesPredicate – path predicate', () => {
	it('matches a plain-prefix path by prefix', () => {
		expect(
			routeMatchesPredicate(routeEppPoc, serviceB, { key: 'path', value: '/epp-poc' }),
			'--filter path:/epp-poc matches route with path /epp-poc/docs',
		).toBe(true);
	});

	it('matches a regex path after stripping the leading ~', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'path', value: '/epp' }),
			'--filter path:/epp matches route with regex path ~/epp/* (~ stripped before comparison)',
		).toBe(true);
	});

	it('does NOT match when no path starts with the prefix', () => {
		expect(
			routeMatchesPredicate(routeUnrelated, serviceC, { key: 'path', value: '/api' }),
			'--filter path:/api should not match a route whose only path is /healthz',
		).toBe(false);
	});

	it('matches the exact path prefix /epp-poc/docs but not /epp-poc/other', () => {
		expect(
			routeMatchesPredicate(routeEppPoc, serviceB, { key: 'path', value: '/epp-poc/docs' }),
			'exact-prefix filter matches the matching path',
		).toBe(true);
	});

	it('does NOT match /epp-poc/docs filter against a route with only /epp-poc/api', () => {
		const route: KongRoute = { ...routeEppPoc, paths: ['/epp-poc/api'] };
		expect(
			routeMatchesPredicate(route, serviceB, { key: 'path', value: '/epp-poc/docs' }),
			'route with only /epp-poc/api should not match filter path:/epp-poc/docs',
		).toBe(false);
	});
});

describe('routeMatchesPredicate – name predicate (case-insensitive substring)', () => {
	it('matches when the filter value is a substring of the route name', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'name', value: 'epp' }),
			"'epp' is a substring of 'epp-route'",
		).toBe(true);
	});

	it('matches case-insensitively', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'name', value: 'EPP' }),
			"'EPP' should match 'epp-route' case-insensitively",
		).toBe(true);
	});

	it('does NOT match when the route name does not contain the substring', () => {
		expect(
			routeMatchesPredicate(routeUnrelated, serviceC, { key: 'name', value: 'epp' }),
			"'epp' is not a substring of 'unrelated-route'",
		).toBe(false);
	});

	it('matches a route with no name (empty string never matches a non-empty filter)', () => {
		const route: KongRoute = { ...routeEpp, name: undefined };
		expect(
			routeMatchesPredicate(route, serviceA, { key: 'name', value: 'epp' }),
			"route without name → empty string → does not contain 'epp'",
		).toBe(false);
	});
});

describe('routeMatchesPredicate – service predicate', () => {
	it('matches by exact service id', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'service', value: 'svc-a' }),
			'exact service id match',
		).toBe(true);
	});

	it('matches by service name substring (case-insensitive)', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'service', value: 'epp-service' }),
			'exact service name match',
		).toBe(true);
	});

	it('matches service name case-insensitively by substring', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'service', value: 'EPP' }),
			"'EPP' is a case-insensitive substring of 'epp-service'",
		).toBe(true);
	});

	it('does NOT match when service id and name differ from the filter value', () => {
		expect(
			routeMatchesPredicate(routeUnrelated, serviceC, { key: 'service', value: 'epp-service' }),
			"svc-c 'unrelated-service' should not match filter service:epp-service",
		).toBe(false);
	});

	it('falls back to route.service.id when no resolved service is provided', () => {
		expect(
			routeMatchesPredicate(routeEpp, undefined, { key: 'service', value: 'svc-a' }),
			'route.service.id used when resolved service is not provided',
		).toBe(true);
	});
});

describe('routeMatchesPredicate – tag predicate (exact match)', () => {
	it('matches when the route has the exact tag', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'tag', value: 'team-platform' }),
			"route has tag 'team-platform'",
		).toBe(true);
	});

	it('does NOT match a partial tag name', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'tag', value: 'platform' }),
			"tag filter is exact – 'platform' should not match 'team-platform'",
		).toBe(false);
	});

	it('does NOT match when the route has no tags', () => {
		const route: KongRoute = { ...routeEpp, tags: undefined };
		expect(
			routeMatchesPredicate(route, serviceA, { key: 'tag', value: 'team-platform' }),
			'route without tags field should not match any tag filter',
		).toBe(false);
	});
});

describe('routeMatchesPredicate – id predicate (exact UUID match)', () => {
	it('matches the exact id', () => {
		expect(routeMatchesPredicate(routeEpp, serviceA, { key: 'id', value: 'route-epp' }), 'exact id match').toBe(true);
	});

	it('does NOT match a partial id', () => {
		expect(
			routeMatchesPredicate(routeEpp, serviceA, { key: 'id', value: 'route' }),
			'partial id should not match – id filter is exact',
		).toBe(false);
	});
});

describe('routeMatchesAllPredicates – AND between keys, OR within same key', () => {
	it('returns true when predicates list is empty (no filter = match all)', () => {
		expect(routeMatchesAllPredicates(routeEpp, serviceA, []), 'empty predicates → always matches').toBe(true);
	});

	it('matches when a single predicate is satisfied', () => {
		expect(
			routeMatchesAllPredicates(routeEpp, serviceA, [{ key: 'tag', value: 'team-platform' }]),
			'single matching tag predicate',
		).toBe(true);
	});

	it('two different keys are ANDed – both must match', () => {
		// route has tag team-platform AND service svc-a → should match
		expect(
			routeMatchesAllPredicates(routeEpp, serviceA, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'service', value: 'svc-a' },
			]),
			'tag:team-platform AND service:svc-a – epp-route satisfies both',
		).toBe(true);
	});

	it("two different keys ANDed – fails when one key doesn't match", () => {
		// route has tag team-platform but NOT service svc-b
		expect(
			routeMatchesAllPredicates(routeEpp, serviceA, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'service', value: 'svc-b' },
			]),
			'tag:team-platform AND service:svc-b – epp-route is on svc-a, not svc-b → no match',
		).toBe(false);
	});

	it('two predicates for the same key are ORed – either value suffices', () => {
		// route has tag "team-platform" but NOT "team-ops"
		// filter: tag:team-platform OR tag:team-ops → should match because team-platform is present
		expect(
			routeMatchesAllPredicates(routeEpp, serviceA, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'tag', value: 'team-ops' },
			]),
			'tag:team-platform OR tag:team-ops – epp-route has team-platform → matches',
		).toBe(true);
	});

	it('same-key OR does not match when neither value is present', () => {
		expect(
			routeMatchesAllPredicates(routeEpp, serviceA, [
				{ key: 'tag', value: 'team-ops' },
				{ key: 'tag', value: 'team-devex' },
			]),
			'tag:team-ops OR tag:team-devex – epp-route has neither → no match',
		).toBe(false);
	});

	it('mixed AND/OR: two tags ORed AND a service ANDed', () => {
		// epp-poc-route: tags=[team-platform, env-dev], service=svc-b
		// filter: (tag:team-platform OR tag:team-ops) AND service:svc-b
		expect(
			routeMatchesAllPredicates(routeEppPoc, serviceB, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'tag', value: 'team-ops' },
				{ key: 'service', value: 'svc-b' },
			]),
			'(tag:team-platform OR tag:team-ops) AND service:svc-b – epp-poc has team-platform and svc-b',
		).toBe(true);
	});
});

describe('applyFindingFilter – includes finding when ANY involved route matches', () => {
	it('returns all findings when predicates list is empty', () => {
		const findings = [makeFinding([routeEpp]), makeFinding([routeEppPoc]), makeFinding([routeUnrelated])];
		expect(applyFindingFilter(findings, [], services), 'no --filter flags → all findings returned').toHaveLength(3);
	});

	it('includes a finding whose sole route matches the filter', () => {
		const findings = [makeFinding([routeEpp]), makeFinding([routeUnrelated])];
		const result = applyFindingFilter(findings, [{ key: 'tag', value: 'team-platform' }], services);
		expect(result, 'only the epp finding has tag team-platform').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be the epp-route, not the unrelated one",
		).toBe('route-epp');
	});

	it('includes a cross-team collision finding when ANY route matches', () => {
		// Finding involves epp-route (team-platform) AND unrelated-route (team-ops)
		const finding = makeFinding([routeEpp, routeUnrelated]);
		const result = applyFindingFilter([finding], [{ key: 'tag', value: 'team-platform' }], services);
		expect(result, 'cross-team finding shown because epp-route (ANY match) satisfies the filter').toHaveLength(1);
	});

	it('excludes a finding where NO involved route matches the filter', () => {
		const finding = makeFinding([routeUnrelated]);
		const result = applyFindingFilter([finding], [{ key: 'tag', value: 'team-platform' }], services);
		expect(result, 'unrelated-route has tag team-ops, not team-platform → excluded').toHaveLength(0);
	});

	it('service filter: includes finding for routes on the named service', () => {
		const findings = [
			makeFinding([routeEpp]), // svc-a / epp-service
			makeFinding([routeEppPoc]), // svc-b / epp-poc-service
			makeFinding([routeUnrelated]), // svc-c / unrelated-service
		];
		const result = applyFindingFilter(findings, [{ key: 'service', value: 'epp-service' }], services);
		expect(result, 'only the epp-route finding belongs to epp-service').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be the epp-route (service svc-a / epp-service)",
		).toBe('route-epp');
	});

	it('path filter: includes only findings involving routes under /epp-poc', () => {
		const findings = [
			makeFinding([routeEpp]), // paths: ~/epp/*  (stem /epp)
			makeFinding([routeEppPoc]), // paths: /epp-poc/docs, /epp-poc/api
			makeFinding([routeUnrelated]), // paths: /healthz
		];
		const result = applyFindingFilter(findings, [{ key: 'path', value: '/epp-poc' }], services);
		expect(result, '--filter path:/epp-poc includes only the epp-poc-route finding').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be the epp-poc-route (paths /epp-poc/...)",
		).toBe('route-epp-poc');
	});

	it('tag OR: includes findings from either team when two same-key predicates given', () => {
		const findings = [
			makeFinding([routeEpp]), // tag: team-platform
			makeFinding([routeUnrelated]), // tag: team-ops
		];
		const result = applyFindingFilter(
			findings,
			[
				{ key: 'tag', value: 'team-platform' },
				{ key: 'tag', value: 'team-ops' },
			],
			services,
		);
		expect(result, 'tag:team-platform OR tag:team-ops → both findings included').toHaveLength(2);
	});

	it('AND across keys: only includes findings satisfying all key groups', () => {
		const findings = [
			makeFinding([routeEpp]), // tag: team-platform, service: svc-a
			makeFinding([routeEppPoc]), // tag: team-platform, service: svc-b
			makeFinding([routeUnrelated]), // tag: team-ops,      service: svc-c
		];
		// Only epp-route satisfies tag:team-platform AND service:svc-a
		const result = applyFindingFilter(
			findings,
			[
				{ key: 'tag', value: 'team-platform' },
				{ key: 'service', value: 'svc-a' },
			],
			services,
		);
		expect(result, 'tag:team-platform AND service:svc-a → only epp-route finding').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be route-epp (tagged team-platform on svc-a)",
		).toBe('route-epp');
	});
});
