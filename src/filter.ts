/**
 * Route filter predicates for the `--filter` CLI option.
 *
 * Predicates are written as `key:value` strings and are applied to the
 * findings produced by the analyzer. The inclusion rule is –
 *
 * - A **finding** is included when **any** of its involved routes satisfies
 *   the full predicate set.
 * - Within a single predicate set, **different keys** are combined with AND:
 *   the route must satisfy all key groups.
 * - **Multiple predicates with the same key** are combined with OR: the route
 *   must match at least one value for that key.
 *
 * @example
 * // Include findings that touch any route belonging to "payments-svc":
 * // --filter service:payments-svc
 *
 * // Include findings touching routes tagged "team-a" OR "team-b":
 * // --filter tag:team-a --filter tag:team-b
 *
 * // Include findings touching routes tagged "team-a" AND under /payments:
 * // --filter tag:team-a --filter path:/payments
 */

import type { Finding, KongRoute, KongService } from './types.ts';

/** Supported filter key names. */
export type FilterKey = 'path' | 'name' | 'service' | 'tag' | 'id';

/**
 * A single parsed filter predicate.
 *
 * Produced by {@link parseFilter} from a raw `key:value` string.
 */
export interface FilterPredicate {
	/**
	 * The dimension to test.
	 *
	 * | key       | Match semantics                                                               |
	 * |-----------|-------------------------------------------------------------------------------|
	 * | `path`    | Route has ≥1 path whose stem (after stripping leading `~`) starts with value  |
	 * | `name`    | Route name contains value (case-insensitive substring)                        |
	 * | `service` | Route's service id equals value, OR service name contains value (case-insen.) |
	 * | `tag`     | Route has a tag with exactly this value                                       |
	 * | `id`      | Route id equals value (exact UUID match)                                      |
	 */
	key: FilterKey;
	/** The value to test against. */
	value: string;
}

/**
 * Parses a single `--filter key:value` argument string into a
 * {@link FilterPredicate}.
 *
 * The key and the first colon are mandatory; the value may itself contain
 * colons (e.g. `path:~/api:v2`).
 *
 * @param raw - The raw filter string, e.g. `"path:/api/v2"`.
 * @throws {Error} When the string has no colon or the key is not recognised.
 */
export function parseFilter(raw: string): FilterPredicate {
	const colonIdx = raw.indexOf(':');
	if (colonIdx === -1) {
		throw new Error(
			`Invalid --filter "${raw}": expected format key:value ` +
				`(e.g. path:/api, name:payments, service:payments-svc, tag:team-a, id:<uuid>)`,
		);
	}
	const key = raw.slice(0, colonIdx);
	const value = raw.slice(colonIdx + 1);

	const validKeys: FilterKey[] = ['path', 'name', 'service', 'tag', 'id'];
	if (!(validKeys as string[]).includes(key)) {
		throw new Error(`Unknown filter key "${key}". Supported keys: ${validKeys.join(', ')}`);
	}

	if (!value) {
		throw new Error(`Filter value for key "${key}" must not be empty.`);
	}

	return { key: key as FilterKey, value };
}

/**
 * Convenience helper that accepts the raw CLI option value (which may be a
 * single string, an array of strings if the flag was passed multiple times,
 * or undefined when omitted) and returns a parsed {@link FilterPredicate}
 * array.
 *
 * @param raw - The raw value(s) from the `--filter` CLI option.
 */
export function parseFilters(raw: string | string[] | undefined): FilterPredicate[] {
	if (!raw) return [];
	const values = Array.isArray(raw) ? raw : [raw];
	return values.map(parseFilter);
}

/**
 * Tests a single route/service pair against one {@link FilterPredicate}.
 *
 * @param route   - The route to test.
 * @param service - The resolved service for the route, if available.
 * @param pred    - The predicate to evaluate.
 */
export function routeMatchesPredicate(
	route: KongRoute,
	service: KongService | undefined,
	pred: FilterPredicate,
): boolean {
	switch (pred.key) {
		case 'path': {
			// Strip leading `~` so --filter path:/api matches both plain `/api/v2`
			// and regex `~/api/v2.*` paths.
			return (route.paths ?? []).some((p) => {
				const stem = p.startsWith('~') ? p.slice(1) : p;
				return stem.startsWith(pred.value);
			});
		}

		case 'name': {
			// Case-insensitive substring match: --filter name:payments matches
			// "payments-route", "payments-v2-route", "my-payments-service-route", etc.
			const name = route.name ?? '';
			return name.toLowerCase().includes(pred.value.toLowerCase());
		}

		case 'service': {
			// Exact UUID match on route.service.id.
			if (route.service?.id === pred.value) return true;
			// Exact UUID match on resolved service.id (redundant but defensive).
			if (service?.id === pred.value) return true;
			// Case-insensitive substring on service name.
			if (service?.name) {
				return service.name.toLowerCase().includes(pred.value.toLowerCase());
			}
			return false;
		}

		case 'tag': {
			// Exact tag match (tags are opaque strings in Kong).
			return (route.tags ?? []).includes(pred.value);
		}

		case 'id': {
			return route.id === pred.value;
		}
	}
}

/**
 * Tests a route against a full set of predicates.
 *
 * **AND between keys, OR within the same key.**
 *
 * Groups predicates by key, then requires that for each key group at least
 * one value satisfies the predicate (OR within group), and all key groups
 * must be satisfied (AND across groups).
 *
 * An empty predicate array always returns `true`.
 *
 * @param route      - The route to test.
 * @param service    - The resolved service for the route, if available.
 * @param predicates - All active predicates.
 */
export function routeMatchesAllPredicates(
	route: KongRoute,
	service: KongService | undefined,
	predicates: FilterPredicate[],
): boolean {
	if (predicates.length === 0) return true;

	// Group predicates by key.
	const groups = new Map<FilterKey, string[]>();
	for (const pred of predicates) {
		const existing = groups.get(pred.key) ?? [];
		existing.push(pred.value);
		groups.set(pred.key, existing);
	}

	// Every group must have at least one matching value.
	for (const [key, values] of groups) {
		const groupMatches = values.some((v) => routeMatchesPredicate(route, service, { key, value: v }));
		if (!groupMatches) return false;
	}

	return true;
}

/**
 * Filters an array of findings to those where **any** involved route satisfies
 * all active predicates.
 *
 * The "any route" inclusion rule means cross-team collision findings are still
 * surfaced when you filter to your own service — the colliding route from
 * another team is shown alongside yours.
 *
 * @param findings   - All findings from the analyzer.
 * @param predicates - Active filter predicates (empty = return all).
 * @param services   - Service map for resolving `service:` predicates.
 */
export function applyFindingFilter(
	findings: Finding[],
	predicates: FilterPredicate[],
	services: Map<string, KongService>,
): Finding[] {
	if (predicates.length === 0) return findings;

	return findings.filter((f) =>
		f.routes.some((r) =>
			routeMatchesAllPredicates(r, r.service?.id ? services.get(r.service.id) : undefined, predicates),
		),
	);
}
