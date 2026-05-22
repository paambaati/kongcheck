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

const serviceA: KongService = { id: 'svc-a', name: 'payments-service', host: 'payments.internal' };
const serviceB: KongService = { id: 'svc-b', name: 'payments-v2-service', host: 'payments-v2.internal' };
const serviceC: KongService = { id: 'svc-c', name: 'unrelated-service', host: 'other.internal' };

const routePayments: KongRoute = {
	id: 'route-payments',
	name: 'payments-route',
	paths: ['~/payments/*'],
	tags: ['team-platform', 'env-prod'],
	service: { id: 'svc-a' },
};

const routePaymentsV2: KongRoute = {
	id: 'route-payments-v2',
	name: 'payments-v2-route',
	paths: ['/payments-v2/docs', '/payments-v2/api'],
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
		samples: ['/payments-v2/docs'],
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
		const p = parseFilter('name:payments');
		expect(p.key, "key should be 'name'").toBe('name');
		expect(p.value, 'value should be the name substring').toBe('payments');
	});

	it('parses a service predicate', () => {
		const p = parseFilter('service:payments-svc');
		expect(p.key, "key should be 'service'").toBe('service');
		expect(p.value, 'value should be the service name/id to match').toBe('payments-svc');
	});

	it('parses a tag predicate', () => {
		const p = parseFilter('tag:team-platform');
		expect(p.key, "key should be 'tag'").toBe('tag');
		expect(p.value, 'value should be the exact tag string to match').toBe('team-platform');
	});

	it('parses an id predicate', () => {
		const p = parseFilter('id:route-payments');
		expect(p.key, "key should be 'id'").toBe('id');
		expect(p.value, 'value should be the exact route UUID to match').toBe('route-payments');
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
		const preds = parseFilters(['tag:team-a', 'service:payments-svc']);
		expect(preds, 'two filter strings should produce two predicates').toHaveLength(2);
		expect(preds[0]!.key, "first predicate key should be 'tag'").toBe('tag');
		expect(preds[1]!.key, "second predicate key should be 'service'").toBe('service');
	});
});

describe('routeMatchesPredicate – path predicate', () => {
	it('matches a plain-prefix path by prefix', () => {
		expect(
			routeMatchesPredicate(routePaymentsV2, serviceB, { key: 'path', value: '/payments-v2' }),
			'--filter path:/payments-v2 matches route with path /payments-v2/docs',
		).toBe(true);
	});

	it('matches a regex path after stripping the leading ~', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'path', value: '/payments' }),
			'--filter path:/payments matches route with regex path ~/payments/* (~ stripped before comparison)',
		).toBe(true);
	});

	it('does NOT match when no path starts with the prefix', () => {
		expect(
			routeMatchesPredicate(routeUnrelated, serviceC, { key: 'path', value: '/api' }),
			'--filter path:/api should not match a route whose only path is /healthz',
		).toBe(false);
	});

	it('matches the exact path prefix /payments-v2/docs but not /payments-v2/other', () => {
		expect(
			routeMatchesPredicate(routePaymentsV2, serviceB, { key: 'path', value: '/payments-v2/docs' }),
			'exact-prefix filter matches the matching path',
		).toBe(true);
	});

	it('does NOT match /payments-v2/docs filter against a route with only /payments-v2/api', () => {
		const route: KongRoute = { ...routePaymentsV2, paths: ['/payments-v2/api'] };
		expect(
			routeMatchesPredicate(route, serviceB, { key: 'path', value: '/payments-v2/docs' }),
			'route with only /payments-v2/api should not match filter path:/payments-v2/docs',
		).toBe(false);
	});
});

describe('routeMatchesPredicate – name predicate (case-insensitive substring)', () => {
	it('matches when the filter value is a substring of the route name', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'name', value: 'payments' }),
			"'payments' is a substring of 'payments-route'",
		).toBe(true);
	});

	it('matches case-insensitively', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'name', value: 'PAYMENTS' }),
			"'PAYMENTS' should match 'payments-route' case-insensitively",
		).toBe(true);
	});

	it('does NOT match when the route name does not contain the substring', () => {
		expect(
			routeMatchesPredicate(routeUnrelated, serviceC, { key: 'name', value: 'payments' }),
			"'payments' is not a substring of 'unrelated-route'",
		).toBe(false);
	});

	it('matches a route with no name (empty string never matches a non-empty filter)', () => {
		const route: KongRoute = { ...routePayments, name: undefined };
		expect(
			routeMatchesPredicate(route, serviceA, { key: 'name', value: 'payments' }),
			"route without name → empty string → does not contain 'payments'",
		).toBe(false);
	});
});

describe('routeMatchesPredicate – service predicate', () => {
	it('matches by exact service id', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'service', value: 'svc-a' }),
			'exact service id match',
		).toBe(true);
	});

	it('matches by service name substring (case-insensitive)', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'service', value: 'payments-service' }),
			'exact service name match',
		).toBe(true);
	});

	it('matches service name case-insensitively by substring', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'service', value: 'PAYMENTS' }),
			"'PAYMENTS' is a case-insensitive substring of 'payments-service'",
		).toBe(true);
	});

	it('does NOT match when service id and name differ from the filter value', () => {
		expect(
			routeMatchesPredicate(routeUnrelated, serviceC, { key: 'service', value: 'payments-service' }),
			"svc-c 'unrelated-service' should not match filter service:payments-service",
		).toBe(false);
	});

	it('falls back to route.service.id when no resolved service is provided', () => {
		expect(
			routeMatchesPredicate(routePayments, undefined, { key: 'service', value: 'svc-a' }),
			'route.service.id used when resolved service is not provided',
		).toBe(true);
	});
});

describe('routeMatchesPredicate – tag predicate (exact match)', () => {
	it('matches when the route has the exact tag', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'tag', value: 'team-platform' }),
			"route has tag 'team-platform'",
		).toBe(true);
	});

	it('does NOT match a partial tag name', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'tag', value: 'platform' }),
			"tag filter is exact – 'platform' should not match 'team-platform'",
		).toBe(false);
	});

	it('does NOT match when the route has no tags', () => {
		const route: KongRoute = { ...routePayments, tags: undefined };
		expect(
			routeMatchesPredicate(route, serviceA, { key: 'tag', value: 'team-platform' }),
			'route without tags field should not match any tag filter',
		).toBe(false);
	});
});

describe('routeMatchesPredicate – id predicate (exact UUID match)', () => {
	it('matches the exact id', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'id', value: 'route-payments' }),
			'exact id match',
		).toBe(true);
	});

	it('does NOT match a partial id', () => {
		expect(
			routeMatchesPredicate(routePayments, serviceA, { key: 'id', value: 'route' }),
			'partial id should not match – id filter is exact',
		).toBe(false);
	});
});

describe('routeMatchesAllPredicates – AND between keys, OR within same key', () => {
	it('returns true when predicates list is empty (no filter = match all)', () => {
		expect(routeMatchesAllPredicates(routePayments, serviceA, []), 'empty predicates → always matches').toBe(true);
	});

	it('matches when a single predicate is satisfied', () => {
		expect(
			routeMatchesAllPredicates(routePayments, serviceA, [{ key: 'tag', value: 'team-platform' }]),
			'single matching tag predicate',
		).toBe(true);
	});

	it('two different keys are ANDed – both must match', () => {
		// route has tag team-platform AND service svc-a → should match
		expect(
			routeMatchesAllPredicates(routePayments, serviceA, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'service', value: 'svc-a' },
			]),
			'tag:team-platform AND service:svc-a – payments-route satisfies both',
		).toBe(true);
	});

	it("two different keys ANDed – fails when one key doesn't match", () => {
		// route has tag team-platform but NOT service svc-b
		expect(
			routeMatchesAllPredicates(routePayments, serviceA, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'service', value: 'svc-b' },
			]),
			'tag:team-platform AND service:svc-b – payments-route is on svc-a, not svc-b → no match',
		).toBe(false);
	});

	it('two predicates for the same key are ORed – either value suffices', () => {
		// route has tag "team-platform" but NOT "team-ops"
		// filter: tag:team-platform OR tag:team-ops → should match because team-platform is present
		expect(
			routeMatchesAllPredicates(routePayments, serviceA, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'tag', value: 'team-ops' },
			]),
			'tag:team-platform OR tag:team-ops – payments-route has team-platform → matches',
		).toBe(true);
	});

	it('same-key OR does not match when neither value is present', () => {
		expect(
			routeMatchesAllPredicates(routePayments, serviceA, [
				{ key: 'tag', value: 'team-ops' },
				{ key: 'tag', value: 'team-devex' },
			]),
			'tag:team-ops OR tag:team-devex – payments-route has neither → no match',
		).toBe(false);
	});

	it('mixed AND/OR: two tags ORed AND a service ANDed', () => {
		// payments-v2-route: tags=[team-platform, env-dev], service=svc-b
		// filter: (tag:team-platform OR tag:team-ops) AND service:svc-b
		expect(
			routeMatchesAllPredicates(routePaymentsV2, serviceB, [
				{ key: 'tag', value: 'team-platform' },
				{ key: 'tag', value: 'team-ops' },
				{ key: 'service', value: 'svc-b' },
			]),
			'(tag:team-platform OR tag:team-ops) AND service:svc-b – payments-v2 has team-platform and svc-b',
		).toBe(true);
	});
});

describe('applyFindingFilter – includes finding when ANY involved route matches', () => {
	it('returns all findings when predicates list is empty', () => {
		const findings = [makeFinding([routePayments]), makeFinding([routePaymentsV2]), makeFinding([routeUnrelated])];
		expect(applyFindingFilter(findings, [], services), 'no --filter flags → all findings returned').toHaveLength(3);
	});

	it('includes a finding whose sole route matches the filter', () => {
		const findings = [makeFinding([routePayments]), makeFinding([routeUnrelated])];
		const result = applyFindingFilter(findings, [{ key: 'tag', value: 'team-platform' }], services);
		expect(result, 'only the payments finding has tag team-platform').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be the payments-route, not the unrelated one",
		).toBe('route-payments');
	});

	it('includes a cross-team collision finding when ANY route matches', () => {
		// Finding involves payments-route (team-platform) AND unrelated-route (team-ops)
		const finding = makeFinding([routePayments, routeUnrelated]);
		const result = applyFindingFilter([finding], [{ key: 'tag', value: 'team-platform' }], services);
		expect(result, 'cross-team finding shown because payments-route (ANY match) satisfies the filter').toHaveLength(1);
	});

	it('excludes a finding where NO involved route matches the filter', () => {
		const finding = makeFinding([routeUnrelated]);
		const result = applyFindingFilter([finding], [{ key: 'tag', value: 'team-platform' }], services);
		expect(result, 'unrelated-route has tag team-ops, not team-platform → excluded').toHaveLength(0);
	});

	it('service filter: includes finding for routes on the named service', () => {
		const findings = [
			makeFinding([routePayments]), // svc-a / payments-service
			makeFinding([routePaymentsV2]), // svc-b / payments-v2-service
			makeFinding([routeUnrelated]), // svc-c / unrelated-service
		];
		const result = applyFindingFilter(findings, [{ key: 'service', value: 'payments-service' }], services);
		expect(result, 'only the payments-route finding belongs to payments-service').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be the payments-route (service svc-a / payments-service)",
		).toBe('route-payments');
	});

	it('path filter: includes only findings involving routes under /payments-v2', () => {
		const findings = [
			makeFinding([routePayments]), // paths: ~/payments/*  (stem /payments)
			makeFinding([routePaymentsV2]), // paths: /payments-v2/docs, /payments-v2/api
			makeFinding([routeUnrelated]), // paths: /healthz
		];
		const result = applyFindingFilter(findings, [{ key: 'path', value: '/payments-v2' }], services);
		expect(result, '--filter path:/payments-v2 includes only the payments-v2-route finding').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be the payments-v2-route (paths /payments-v2/...)",
		).toBe('route-payments-v2');
	});

	it('tag OR: includes findings from either team when two same-key predicates given', () => {
		const findings = [
			makeFinding([routePayments]), // tag: team-platform
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
			makeFinding([routePayments]), // tag: team-platform, service: svc-a
			makeFinding([routePaymentsV2]), // tag: team-platform, service: svc-b
			makeFinding([routeUnrelated]), // tag: team-ops,      service: svc-c
		];
		// Only payments-route satisfies tag:team-platform AND service:svc-a
		const result = applyFindingFilter(
			findings,
			[
				{ key: 'tag', value: 'team-platform' },
				{ key: 'service', value: 'svc-a' },
			],
			services,
		);
		expect(result, 'tag:team-platform AND service:svc-a → only payments-route finding').toHaveLength(1);
		expect(
			result[0]!.routes[0]!.id,
			"the surviving finding's first route must be route-payments (tagged team-platform on svc-a)",
		).toBe('route-payments');
	});
});
