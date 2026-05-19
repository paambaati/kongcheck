/**
 * Kong Traditional Router – TypeScript port of the routing core.
 *
 * This module ports the route classification, sorting and matching logic from
 * Kong's `kong/router/traditional.lua` (commit 2ffd3b1, Kong 3.x) into plain
 * TypeScript so it can run inside a Bun single-binary without any OpenResty /
 * LuaJIT dependency.
 *
 * **Portability scope**
 * Only the subset that affects *which route wins* is ported –
 *  - Path classification (`~`-prefix → regex, plain → prefix)
 *  - `sort_routes` tie-breaking chain
 *  - `match_regex_uri` / plain-prefix matching
 *  - `find_match` candidate evaluation loop
 *
 * Everything that only affects *what happens after the winner is chosen*
 * (strip_path, upstream URI construction, debug headers, phonehome telemetry,
 * LRU cache, ngx.* bindings) is intentionally omitted.
 *
 * Each function is annotated with the Kong source location it was derived from
 * so that upstream drift can be spotted at a glance.
 *
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/utils.lua
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua
 */

import type {
	KongRoute,
	KongService,
	MarshalledRoute,
	ParsedPath,
	PathKind,
	RouterFlavor,
	SimRequest,
	SimResult,
} from './types.ts';

/**
 * Returns `true` when the raw path string is a **regex path** in Kong
 * semantics: it must start with the tilde character `~`.
 *
 * Kong source: `traditional.lua` – `is_regex` check inside `marshall_route`
 * ([Kong 3.x commit 2ffd3b1, ~L430](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L430)).
 *
 * @param raw - The raw path string from a route's `paths` array.
 *
 * @example
 * isRegexPath("~/epp/*")   // true
 * isRegexPath("/api/v1")   // false
 */
export function isRegexPath(raw: string): boolean {
	return raw.startsWith('~');
}

/**
 * Strips the leading `~` from a regex path to obtain the bare PCRE pattern
 * string.
 *
 * Kong source: `traditional.lua` – `path = sub(path, 2)`
 * ([~L437](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L437)).
 *
 * @param raw - A raw regex path, e.g. `"~/epp/*"`.
 * @returns The PCRE pattern without the leading `~`, e.g. `"/epp/*"`.
 *
 * @throws {Error} If called on a non-regex path (missing `~` prefix).
 */
export function stripRegexPrefix(raw: string): string {
	if (!raw.startsWith('~')) {
		throw new Error(`stripRegexPrefix: expected a regex path starting with '~', got '${raw}'`);
	}
	return raw.slice(1);
}

/**
 * Classifies a raw path string and returns a {@link ParsedPath} ready for use
 * in the matching engine.
 *
 * For **regex paths** (`~`-prefixed), the pattern is compiled to a
 * `RegExp`. When the router flavor is `traditional_compatible` or
 * `expressions`, a `^` start anchor is prepended – matching Kong's
 * `path_val_transform` in `transform.lua`
 * ([~L322-L330](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua#L322-L330)).
 *
 * For **plain paths**, the string is stored as-is in `prefix` for
 * `String.prototype.startsWith` comparison.
 *
 * Kong sources –
 * - [`traditional.lua` – `marshall_route` path block (~L426-L467)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L426-L467)
 * - [`transform.lua` – `path_val_transform` (~L322-L330)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua#L322-L330)
 *
 * @param raw    - The raw path string from the route entity.
 * @param flavor - The router flavor, which determines whether regex paths
 *                 receive a `^` start anchor.
 *
 * @example
 * // traditional flavor – no start anchor
 * // classifyPath("~/epp/*", "traditional")
 * //   kind: "regex", regexSource: "/epp/*", regex.source: "/epp/*"
 *
 * // traditional_compatible – start anchor added
 * // classifyPath("~/epp/*", "traditional_compatible")
 * //   kind: "regex", regexSource: "/epp/*", regex.source: "^/epp/*"
 *
 * // classifyPath("/api/v1", "traditional")
 * //   kind: "prefix", prefix: "/api/v1"
 */
export function classifyPath(raw: string, flavor: RouterFlavor): ParsedPath {
	const kind: PathKind = isRegexPath(raw) ? 'regex' : 'prefix';

	if (kind === 'regex') {
		const regexSource = stripRegexPrefix(raw);
		// traditional_compatible and expressions flavors anchor at start.
		// Kong source: transform.lua – path_val_transform
		// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua#L322-L330
		//   return "^" .. p:sub(2):gsub("?<", "?P<")
		const anchoredSource = flavor === 'traditional' ? regexSource : '^' + regexSource;

		let regex: RegExp;
		try {
			regex = new RegExp(anchoredSource);
		} catch {
			// Malformed regex – store a never-matching sentinel so analysis can
			// still flag it as a suspicious pattern rather than crashing.
			regex = /(?!)/;
		}

		return { raw, kind, regexSource, regex };
	}

	// Plain prefix path.
	return { raw, kind, prefix: raw };
}

/**
 * Converts a raw {@link KongRoute} entity (as returned by the Konnect API)
 * into a {@link MarshalledRoute} that is ready for use by the matching engine
 * and the analyzer.
 *
 * Corresponds to `marshall_route` in Kong's `traditional.lua`
 * ([~L370-L520](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L370-L520)),
 * restricted to the HTTP/path-related fields that matter for route-winner
 * selection.
 *
 * @param route   - The raw route entity.
 * @param service - The associated service entity, if available.
 * @param flavor  - The router flavor in effect for this control plane.
 */
export function marshalRoute(
	route: KongRoute,
	service?: KongService,
	flavor: RouterFlavor = 'traditional',
): MarshalledRoute {
	const paths = route.paths ?? [];
	const parsedPaths: ParsedPath[] = paths.map((p) => classifyPath(p, flavor));

	// max_uri_length: used as a tie-breaker – the route with the longest path
	// pattern wins when regex_priority and header count are equal.
	// Kong source: https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L514-L517 – max_uri_length field.
	const maxUriLength = parsedPaths.reduce((max, p) => Math.max(max, p.raw.length), 0);

	// HAS_REGEX_URI submatch weight bit: true iff any path is a regex path.
	// Kong source: https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L150 – MATCH_SUBRULES.HAS_REGEX_URI.
	const hasRegexPath = parsedPaths.some((p) => p.kind === 'regex');

	// Full 3-bit submatch_weight, mirroring Kong's MATCH_SUBRULES bitmap.
	// Bits are OR-ed in exactly the same order as marshall_route in traditional.lua.
	// Kong source: https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L209-L213 (MATCH_SUBRULES)
	//              https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L368-L373 (bit assignment)
	let subMatchWeight = 0;

	// Bit 0 – HAS_REGEX_URI.
	if (hasRegexPath) subMatchWeight |= 0x01;

	// Bits 1 and 2 – host-related subrules.
	// Kong evaluates these inside marshall_route when processing the `hosts` array.
	// We replicate the same logic over route.hosts.
	// Kong: if find(host, "*", nil, true) then has_host_wildcard = true
	//       if not has_host_wildcard then submatch_weight |= PLAIN_HOSTS_ONLY
	//       if has_wildcard_host_port then submatch_weight |= HAS_WILDCARD_HOST_PORT
	// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L333-L373
	const hosts = route.hosts;
	if (hosts && hosts.length > 0) {
		let hasHostWildcard = false;
		let hasWildcardHostPort = false;
		for (const h of hosts) {
			if (h.includes('*')) {
				hasHostWildcard = true;
				// Detect explicit port on the wildcard host, e.g. "*.example.com:8080".
				// Kong: split_port returns has_port; we split on the last ':' after the wildcard.
				// A colon after the TLD part (after the last '.') indicates a port.
				// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L340-L346
				const afterWildcard = h.slice(h.indexOf('*') + 1); // ".example.com" or ".example.com:8080"
				if (afterWildcard.includes(':')) {
					hasWildcardHostPort = true;
				}
			}
		}
		// Bit 1 – PLAIN_HOSTS_ONLY: set when there are NO wildcard hosts.
		if (!hasHostWildcard) subMatchWeight |= 0x02;
		// Bit 2 – HAS_WILDCARD_HOST_PORT: set when any wildcard host has an explicit port.
		if (hasWildcardHostPort) subMatchWeight |= 0x04;
	}

	// headerCount: number of distinct header-name constraints on the route.
	// Used as the second sort tier in sort_routes (between submatch_weight and
	// regex_priority). headers[0] is the Lua array length (count of entries).
	// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L378-L418 (marshal, builds headers_t)
	// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L686-L688 (sort, headers[0] comparison)
	const headerCount = route.headers ? Object.keys(route.headers).length : 0;

	return { route, service, parsedPaths, maxUriLength, hasRegexPath, subMatchWeight, headerCount, flavor };
}

/**
 * Comparator for two marshalled routes implementing Kong's `sort_routes`
 * tie-breaking chain.
 *
 * The chain (highest to lowest precedence) –
 * 1. **`subMatchWeight`** – the full 3-bit `MATCH_SUBRULES` field (higher wins):
 *    - Bit 0 `HAS_REGEX_URI`: regex routes beat plain-prefix routes.
 *    - Bit 1 `PLAIN_HOSTS_ONLY`: plain-host routes beat wildcard-host routes.
 *    - Bit 2 `HAS_WILDCARD_HOST_PORT`: wildcard-host-with-port beats one without.
 *    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L682-L684
 * 2. **Header count** – more `headers` constraints = higher priority.
 *    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L686-L688
 * 3. **`regex_priority`** – only compared when both routes are regex routes.
 *    Higher wins.
 *    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L690-L699
 * 4. **`max_uri_length`** – longer path patterns win.
 *    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L702-L704
 * 5. **`created_at`** – earlier creation time wins (smaller Unix timestamp).
 *    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L706-L708
 *
 * Returns a negative number when `a` should come *before* `b` (i.e. `a` has
 * higher priority), positive when `b` has higher priority, and `0` when the
 * routes are fully equal by Kong's ordering rules.
 *
 * Kong source: [`traditional.lua` – `sort_routes` function (~L681-L709)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L681-L709).
 *
 * @param a - First marshalled route.
 * @param b - Second marshalled route.
 *
 * @example
 * const sorted = marshalledRoutes.sort(compareRoutes);
 * const winner = sorted[0]; // highest-priority route
 */
export function compareRoutes(a: MarshalledRoute, b: MarshalledRoute): number {
	// 1. submatch_weight – the full 3-bit field from Kong's MATCH_SUBRULES.
	//    Bit 0: HAS_REGEX_URI (regex beats plain).
	//    Bit 1: PLAIN_HOSTS_ONLY (plain-host routes beat wildcard-host routes).
	//    Bit 2: HAS_WILDCARD_HOST_PORT (wildcard with explicit port beats one without).
	//    Kong: if r1.submatch_weight ~= r2.submatch_weight then return r1.submatch_weight > r2.submatch_weight
	//    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L682-L684
	if (a.subMatchWeight !== b.subMatchWeight) return b.subMatchWeight - a.subMatchWeight; // higher first

	// 2. Header count – more headers constraints win.
	//    Kong: r1.headers[0] > r2.headers[0]
	//    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L686-L688
	if (a.headerCount !== b.headerCount) return b.headerCount - a.headerCount; // higher first

	// 3. regex_priority (only for regex routes).
	//    Kong: if band(r1.submatch_weight, MATCH_SUBRULES.HAS_REGEX_URI) ~= 0
	//    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L690-L699
	if (a.hasRegexPath && b.hasRegexPath) {
		const aPriority = a.route.regex_priority ?? 0;
		const bPriority = b.route.regex_priority ?? 0;
		if (aPriority !== bPriority) return bPriority - aPriority; // higher first
	}

	// 4. max_uri_length – longer wins.
	//    Kong: r1.max_uri_length > r2.max_uri_length
	//    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L702-L704
	if (a.maxUriLength !== b.maxUriLength) return b.maxUriLength - a.maxUriLength; // higher first

	// 5. created_at – earlier creation wins.
	//    Kong: r1.route.created_at < r2.route.created_at
	//    https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L706-L708
	const aCreated = a.route.created_at ?? 0;
	const bCreated = b.route.created_at ?? 0;
	if (aCreated !== bCreated) return aCreated - bCreated; // lower first (earlier wins)

	return 0;
}

/**
 * Tests whether a single {@link ParsedPath} matches the given request URI.
 *
 * For **regex paths**, this reproduces Kong's `match_regex_uri` behaviour –
 * the PCRE pattern is matched against the front of the request URI (because
 * Kong appends `(?<uri_postfix>.*)` to the pattern, making it prefix-like
 * by default unless the author explicitly end-anchors with `$`).
 *
 * For **plain paths**, a `String.prototype.startsWith` check is used,
 * mirroring Kong's exact prefix match.
 *
 * Kong source –
 * - regex: [`traditional.lua` – `match_regex_uri` (~L903-L931)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L903-L931)
 * - plain: [`traditional.lua` – MATCH_RULES.URI handler (~L1070-L1100)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L1070-L1100)
 *
 * @param parsed  - The pre-classified path descriptor.
 * @param reqPath - The incoming request URI path, e.g. `"/epp-poc/docs"`.
 */
export function matchPath(parsed: ParsedPath, reqPath: string): boolean {
	if (parsed.kind === 'regex') {
		return parsed.regex?.test(reqPath) ?? false;
	}
	// Plain prefix match.
	return reqPath.startsWith(parsed.prefix!);
}

/**
 * Matches header constraints from a Kong route against the headers in a
 * simulated request.
 *
 * Faithful port of the `MATCH_RULES.HEADER` matcher in Kong's
 * `traditional.lua` –
 *
 * - Each header name in `route.headers` **must** be present in the request
 *   (AND semantics across header names).
 * - Within a single header name, **any** of the allowed values may match
 *   (OR semantics across values).
 * - Values are compared **case-insensitively** (Kong lowercases both sides).
 * - A single value starting with `~*` is treated as a PCRE/JS regex –
 *   `header_pattern = value.slice(2)` is matched with `RegExp.test()`.
 *   This mirrors the `header_pattern` field built in Kong's `marshall_route` –
 *   the regex branch is only enabled when there is exactly one value **and**
 *   it starts with `~*`.
 *
 * Kong source (marshal, `header_pattern` construction) –
 *   https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L378-L418
 * Kong source (match, `MATCH_RULES.HEADER` handler) –
 *   https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L963-L1007
 *
 * @param routeHeaders  - The `route.headers` map from the Kong route entity.
 * @param reqHeaders    - The incoming request headers (key → single value).
 * @returns `true` when all header constraints are satisfied.
 */
function matchHeaders(routeHeaders: Record<string, string[]>, reqHeaders: Record<string, string>): boolean {
	for (const [headerName, allowedValues] of Object.entries(routeHeaders)) {
		const lowerName = headerName.toLowerCase();
		const reqValue = reqHeaders[lowerName] ?? reqHeaders[headerName];

		// The header is absent from the request → route does not match.
		if (reqValue === undefined) return false;

		const lowerReqValue = reqValue.toLowerCase();

		// Determine whether this constraint uses regex matching.
		// Kong only sets `header_pattern` when there is exactly ONE value and
		// it starts with `~*`.
		// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L400-L412
		const headerPattern: RegExp | null =
			allowedValues.length === 1 && allowedValues[0]!.startsWith('~*')
				? (() => {
						try {
							return new RegExp(allowedValues[0]!.slice(2));
						} catch {
							return null; // malformed pattern → treat as no-match
						}
					})()
				: null;

		// Check whether the request header value satisfies this constraint.
		// Kong checks values_map first, then falls back to header_pattern regex.
		// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L974-L992
		const matched =
			// 1. Exact match from the values map (case-insensitive).
			allowedValues.some((v) => v.toLowerCase() === lowerReqValue) ||
			// 2. Regex fallback (only when headerPattern is set).
			(headerPattern !== null && headerPattern.test(lowerReqValue));

		if (!matched) return false;
	}
	return true;
}

/**
 * Tests whether a marshalled route matches an incoming request, considering
 * paths, methods, hosts, and header constraints.
 *
 * A route matches if **all** of the following hold –
 * - At least one path pattern matches the request URI.
 * - The HTTP method is in the route's `methods` list, or the route has no
 *   method constraint.
 * - The `Host` header is in the route's `hosts` list, or the route has no
 *   host constraint.
 * - **All** header constraints are satisfied (see {@link matchHeaders}), or
 *   the route has no header constraints.
 *
 * **Header constraint evaluation policy:**
 * When `request.headers` is `undefined` (the default for static analyzer
 * sample requests), header constraints are **skipped** — every route is
 * treated as if it has no header requirements. This preserves the static
 * collision/shadowing analysis behaviour where the tool reports potential
 * conflicts regardless of headers.
 * When `request.headers` is provided (including as `{}`), constraints are
 * evaluated strictly: a route that requires a header not present in the
 * request will not match.
 *
 * Kong source (`match_route` combinator that ORs all active matchers) –
 *   https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L1089-L1125
 *
 * @param mr      - The marshalled route to test.
 * @param request - The simulated request.
 */
export function matchRoute(mr: MarshalledRoute, request: SimRequest): boolean {
	// Method check.
	const methods = mr.route.methods;
	if (methods && methods.length > 0) {
		if (!methods.includes(request.method.toUpperCase())) return false;
	}

	// Host check (exact match or wildcard, with port-aware semantics).
	//
	// Kong source (MATCH_RULES.HOST matcher) –
	// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L937-L962
	//
	// Kong compiles *.example.com (no port) as: .+\.example\.com(?::\d+)?$
	// meaning it matches both "foo.example.com" and "foo.example.com:8443".
	// Kong compiles *.example.com:8080 (explicit port) as: .+\.example\.com:8080$
	// meaning it only matches the exact port.
	//
	// We replicate this logic without a full regex engine by:
	//  1. Splitting the wildcard constraint into (domain_pattern, constraint_port).
	//  2. Splitting the request host into (req_domain, req_port).
	//  3. Checking domain suffix match (req_domain ends with ".example.com").
	//  4. If constraint has no port: accept any request port (strip port from req host).
	//  5. If constraint has an explicit port: require exact match.
	//
	// Gap 2 fix – https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L337-L343
	const hosts = mr.route.hosts;
	if (hosts && hosts.length > 0) {
		const hostMatched = hosts.some((h) => {
			if (h === '*') return true;
			if (h === request.host) return true;

			if (h.startsWith('*.')) {
				// Parse constraint: "*.example.com" or "*.example.com:8080"
				const constraintBody = h.slice(1); // ".example.com" or ".example.com:8080"
				const constraintColonIdx = constraintBody.lastIndexOf(':');
				// Only treat it as a port if the colon comes AFTER a dot
				// (to avoid treating IPv6 or misformed patterns as ports).
				const constraintPort =
					constraintColonIdx > 0 && constraintBody.lastIndexOf('.') < constraintColonIdx
						? constraintBody.slice(constraintColonIdx + 1)
						: null;
				// Domain pattern without port, e.g. ".example.com"
				const domainSuffix = constraintPort !== null ? constraintBody.slice(0, constraintColonIdx) : constraintBody;

				// Parse request host: "foo.example.com" or "foo.example.com:8443"
				const reqColonIdx = request.host.lastIndexOf(':');
				const reqPort =
					reqColonIdx > 0 && request.host.lastIndexOf('.') < reqColonIdx ? request.host.slice(reqColonIdx + 1) : null;
				const reqDomain = reqPort !== null ? request.host.slice(0, reqColonIdx) : request.host;

				// Domain suffix must match (e.g. "foo.example.com" ends with ".example.com").
				if (!reqDomain.endsWith(domainSuffix)) return false;

				// Port matching:
				// - No constraint port → accept any request port (Kong appends (?::\d+)?$).
				// - Constraint port present → require exact match.
				if (constraintPort !== null) {
					return reqPort === constraintPort;
				}
				// No constraint port: any port (or no port) in the request is accepted.
				return true;
			}

			return false;
		});
		if (!hostMatched) return false;
	}

	// Header constraint check.
	// Only evaluated when the caller supplies `request.headers` (explicit
	// simulation mode). When `request.headers` is `undefined` the static
	// analyzer is running and we intentionally skip this check so that routes
	// with header constraints are still considered as collision candidates.
	// Kong source (MATCH_RULES.HEADER matcher) –
	// https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L963-L1007
	if (request.headers !== undefined && mr.route.headers) {
		if (!matchHeaders(mr.route.headers, request.headers)) return false;
	}

	// Path check – any path pattern matching is sufficient.
	return mr.parsedPaths.some((p) => matchPath(p, request.path));
}

/**
 * Simulates a request against a sorted list of marshalled routes and returns
 * the winning route plus a human-readable explanation of why it won.
 *
 * The routes **must** already be sorted by `sort_routes` order (i.e. via
 * `[...routes].sort(compareRoutes)`). The first matching route in that sorted
 * list is the winner – this mirrors Kong's `find_match` logic which iterates
 * candidates in priority order and returns on first match.
 *
 * Kong source: [`traditional.lua` – `find_route` / `find_match` (~L1400-L1688)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L1400-L1688).
 *
 * @param sortedRoutes - Routes sorted by {@link compareRoutes} (highest priority first).
 * @param request      - The request to simulate.
 *
 * @example
 * const sorted = routes.sort(compareRoutes);
 * const result = simulateRequest(sorted, { method: "GET", host: "example.com", path: "/epp-poc/docs" });
 * console.log(result.winner?.route.name, result.explanation);
 */
export function simulateRequest(sortedRoutes: MarshalledRoute[], request: SimRequest): SimResult {
	const matchedRoutes = sortedRoutes.filter((r) => matchRoute(r, request));

	if (matchedRoutes.length === 0) {
		return {
			request,
			matchedRoutes: [],
			winner: undefined,
			explanation: [`No route matched request: ${request.method} ${request.host}${request.path}`],
		};
	}

	const winner = matchedRoutes[0]!;
	const explanation = buildWinnerExplanation(winner, matchedRoutes, request);

	return { request, matchedRoutes, winner, explanation };
}

/**
 * Builds a human-readable explanation chain describing why `winner` was
 * selected over the other matching routes.
 *
 * The explanation mirrors the tie-breaking chain in {@link compareRoutes}.
 *
 * @param winner        - The winning route (first in sorted order).
 * @param allMatched    - All matching routes in priority order.
 * @param request       - The simulated request.
 */
function buildWinnerExplanation(winner: MarshalledRoute, allMatched: MarshalledRoute[], request: SimRequest): string[] {
	const lines: string[] = [];
	const winnerName = winner.route.name ?? winner.route.id;

	lines.push(`Route "${winnerName}" wins for ${request.method} ${request.path}`);

	if (allMatched.length === 1) {
		lines.push('It is the only route that matches this request.');
		return lines;
	}

	const losers = allMatched.slice(1);
	lines.push(`${losers.length} other route(s) also match but lose the priority contest:`);

	for (const loser of losers) {
		const loserName = loser.route.name ?? loser.route.id;
		const reason = explainPairOrdering(winner, loser);
		lines.push(`  - "${loserName}" loses because: ${reason}`);
	}

	return lines;
}

/**
 * Returns a single sentence explaining why `winner` beats `loser` in Kong's
 * `sort_routes` chain.
 *
 * @param winner - The higher-priority route.
 * @param loser  - The lower-priority route.
 */
function explainPairOrdering(winner: MarshalledRoute, loser: MarshalledRoute): string {
	// 1. Full submatch_weight integer comparison (3-bit MATCH_SUBRULES field).
	if (winner.subMatchWeight !== loser.subMatchWeight) {
		const w = winner.subMatchWeight;
		const l = loser.subMatchWeight;
		// Describe the dominant bit difference.
		if ((w & 0x01) !== (l & 0x01)) {
			return w & 0x01
				? 'regex routes beat plain-prefix routes (HAS_REGEX_URI bit of submatch_weight)'
				: 'plain-prefix routes beat regex routes (HAS_REGEX_URI) — unexpected!';
		}
		if ((w & 0x02) !== (l & 0x02)) {
			return w & 0x02
				? 'plain-host routes beat wildcard-host routes (PLAIN_HOSTS_ONLY bit of submatch_weight)'
				: 'wildcard-host route beats plain-host route (PLAIN_HOSTS_ONLY) — unexpected!';
		}
		if ((w & 0x04) !== (l & 0x04)) {
			return w & 0x04
				? 'wildcard host with explicit port beats one without (HAS_WILDCARD_HOST_PORT bit)'
				: 'wildcard host without port beats one with port (HAS_WILDCARD_HOST_PORT) — unexpected!';
		}
	}

	// 2. Header count – more headers constraints win.
	if (winner.headerCount !== loser.headerCount)
		return `more header constraints win (${winner.headerCount} > ${loser.headerCount} distinct headers)`;

	// 3. regex_priority (regex-only).
	if (winner.hasRegexPath && loser.hasRegexPath) {
		const wp = winner.route.regex_priority ?? 0;
		const lp = loser.route.regex_priority ?? 0;
		if (wp > lp) return `higher regex_priority (${wp} > ${lp})`;
	}

	// 4. max_uri_length.
	if (winner.maxUriLength > loser.maxUriLength)
		return `longer path pattern (${winner.maxUriLength} chars > ${loser.maxUriLength} chars)`;

	// 5. created_at.
	const wc = winner.route.created_at ?? 0;
	const lc = loser.route.created_at ?? 0;
	if (wc < lc)
		return `earlier created_at (${new Date(wc * 1000).toISOString()} < ${new Date(lc * 1000).toISOString()})`;

	return 'routes are equal by all ordering criteria (non-deterministic)';
}

/**
 * Sanitises the URI postfix (the portion of the request path after the
 * matched prefix/regex), replicating Kong's `sanitize_uri_postfix` in
 * [`utils.lua` (~L20-L40)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/utils.lua#L20-L40).
 *
 * This is used when constructing the upstream URI after `strip_path = true`.
 * It is included here for completeness and for the upstream-path display in
 * diagnostic output.
 *
 * @param postfix - The raw URI postfix, e.g. `"./secret"`.
 * @returns The sanitised postfix, e.g. `"secret"`.
 */
export function sanitizeUriPostfix(postfix: string): string {
	if (!postfix || postfix === '') return postfix;
	if (postfix === '.' || postfix === '..') return '';
	if (postfix.startsWith('./')) return postfix.slice(2);
	if (postfix.startsWith('../')) return postfix.slice(3);
	return postfix;
}

/**
 * Computes the upstream URI that Kong would forward to the service after the
 * winning route is selected.
 *
 * Implements `get_upstream_uri_v0` from
 * [`kong/router/utils.lua` (~L80-L140)](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/utils.lua#L80-L140)
 * for `path_handling = "v0"` (the default).
 *
 * This is informational – it does **not** affect which route wins.
 *
 * @param mr           - The winning marshalled route.
 * @param reqPath      - The original request path.
 * @param matchedPrefix - The matched path prefix (for plain routes) or the
 *                        regex-matched portion (best-effort for regex routes).
 * @param upstreamBase  - The upstream service path prefix, defaults to `"/"`.
 */
export function computeUpstreamUri(
	mr: MarshalledRoute,
	reqPath: string,
	matchedPrefix: string,
	upstreamBase = '/',
): string {
	const stripPath = mr.route.strip_path ?? true;

	if (!stripPath) {
		if (reqPath === '/') return upstreamBase;
		return upstreamBase + reqPath.slice(1);
	}

	// strip_path = true: remove the matched prefix, then append to upstreamBase.
	const postfix = sanitizeUriPostfix(reqPath.slice(matchedPrefix.length));

	if (upstreamBase.endsWith('/')) {
		if (!postfix) {
			if (upstreamBase === '/') return '/';
			return upstreamBase.slice(0, -1);
		}
		if (postfix.startsWith('/')) return upstreamBase.slice(0, -1) + postfix;
		return upstreamBase + postfix;
	}

	if (!postfix) return upstreamBase;
	if (postfix.startsWith('/')) return upstreamBase + postfix;
	return upstreamBase + '/' + postfix;
}

/**
 * Returns the portion of `reqPath` that was matched by the route's path
 * patterns. Used for upstream URI computation and diagnostic display.
 *
 * For plain routes, this is the prefix string itself.
 * For regex routes, this is the full regex match (first match of the pattern).
 *
 * @param mr      - The matched route.
 * @param reqPath - The request path.
 */
export function extractMatchedPrefix(mr: MarshalledRoute, reqPath: string): string {
	for (const p of mr.parsedPaths) {
		if (p.kind === 'prefix' && p.prefix && reqPath.startsWith(p.prefix)) {
			return p.prefix;
		}
		if (p.kind === 'regex' && p.regex) {
			const m = p.regex.exec(reqPath);
			if (m) return m[0];
		}
	}
	return '';
}
