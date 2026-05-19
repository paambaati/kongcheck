/**
 * Core domain types for Kong route analysis.
 *
 * All field names mirror the Kong Admin API / Konnect Control Planes Config v2
 * so that API responses can be cast directly without transformation.
 *
 * @see https://developer.konghq.com/api/konnect/control-planes-config/v2/
 */

/**
 * A Kong service entity as returned by the Konnect Control Planes Config API.
 * Only the fields relevant to routing diagnostics are required here; additional
 * fields are allowed via the index signature.
 */
export interface KongService {
	/** The service's UUID. */
	id: string;
	/** Human-readable name, e.g. "my-backend". */
	name?: string;
	/** Protocol the service listens on, e.g. "http", "https". */
	protocol?: string;
	/** Upstream hostname or IP. */
	host?: string;
	/** Upstream port. */
	port?: number;
	/** Upstream path prefix, defaults to "/". */
	path?: string;
}

/**
 * A Kong route entity as returned by the Konnect Control Planes Config API.
 *
 * Paths starting with `~` are **regex paths** (PCRE), not glob patterns.
 * All other paths are treated as plain prefix matches.
 *
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua (Kong 3.x) – `marshall_route`, `sort_routes`
 */
export interface KongRoute {
	/** The route's UUID. */
	id: string;
	/** Human-readable name, e.g. "epp-route". */
	name?: string;
	/**
	 * List of path patterns. A leading `~` indicates a regex path.
	 * Example: `["~/epp/*", "/plain-prefix"]`
	 */
	paths?: string[];
	/**
	 * Allowed HTTP methods. When absent or empty, all methods are permitted.
	 * Example: `["GET", "POST"]`
	 */
	methods?: string[];
	/**
	 * Host constraints. Supports wildcards like `*.example.com`.
	 * When absent, the route matches any host.
	 */
	hosts?: string[];
	/**
	 * Header constraints. Keys are header names; values are allowed header values.
	 * Each value may begin with `~*` to indicate a regex match.
	 */
	headers?: Record<string, string[]>;
	/**
	 * When `true` (default), the matched URI prefix is stripped before
	 * forwarding to the upstream. Note: this affects upstream path construction
	 * **after** the winning route is selected – it has no effect on which route
	 * wins the match.
	 */
	strip_path?: boolean;
	/**
	 * Controls how the upstream path is constructed. `"v0"` (default) or `"v1"`.
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/utils.lua#L80-L140 – `get_upstream_uri_v0`
	 */
	path_handling?: 'v0' | 'v1';
	/**
	 * Priority for regex routes. Higher values win over lower values when both
	 * routes are regex routes with equal specificity. Plain prefix routes do not
	 * use this field.
	 *
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L681-L709 – `sort_routes`
	 */
	regex_priority?: number;
	/**
	 * Unix epoch (seconds) at which the route was created.
	 * Used as the final tie-breaker in sort_routes: the earlier route wins.
	 */
	created_at?: number;
	/**
	 * Partial service reference embedded in the route response.
	 * Only `id` is guaranteed; the full service object is fetched separately.
	 */
	service?: { id: string };
	/**
	 * User-defined tags attached to the route.
	 * Used by the `tag:<value>` filter predicate.
	 */
	tags?: string[];
	/** SNI constraints (stream routes). */
	snis?: string[];
	/** Source IP/port constraints (stream routes). */
	sources?: Array<{ ip?: string; port?: number }>;
	/** Destination IP/port constraints (stream routes). */
	destinations?: Array<{ ip?: string; port?: number }>;
	/**
	 * ATC router expression. Only present when the control plane uses the
	 * `expressions` router flavor. Its presence is used to infer flavor when
	 * the CP config endpoint does not expose `router_flavor`.
	 */
	expression?: string | null;
}

/**
 * Classification of a single path pattern, produced by `classifyPath`.
 *
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L426-L467 – `marshall_route` (path classification block)
 */
export type PathKind = 'regex' | 'prefix';

/**
 * A parsed, ready-to-match representation of a single path pattern.
 *
 * Derived from Kong's `uri_t` internal structure in `traditional.lua`.
 */
export interface ParsedPath {
	/** The raw path string as supplied by the user, e.g. `"~/epp/*"`. */
	raw: string;
	/** Whether this path is a regex path (raw starts with `~`). */
	kind: PathKind;
	/**
	 * The regex string used for matching (without the leading `~`).
	 * Only meaningful when `kind === "regex"`. Corresponds to `uri_t.regex` in
	 * Kong's traditional router.
	 *
	 * @example For `~/epp/*` → `"/epp/*"`
	 */
	regexSource?: string;
	/**
	 * The compiled JavaScript RegExp, ready for matching.
	 * Corresponds to `uri_t.strip_regex` in Kong's traditional router –
	 * Kong appends `(?<uri_postfix>.*)` for strip logic, but we match the raw
	 * pattern because we only need a boolean match result, not capture groups.
	 *
	 * For `traditional_compatible` / `expressions` flavors the pattern is
	 * additionally prefixed with `^` (start-of-string anchor).
	 *
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua#L322-L330 – `path_val_transform`
	 */
	regex?: RegExp;
	/**
	 * The plain prefix string.
	 * Only meaningful when `kind === "prefix"`.
	 *
	 * @example `"/api/v1"` matches any request path that starts with `/api/v1`.
	 */
	prefix?: string;
}

/**
 * A fully marshalled route, ready for use in the routing engine.
 *
 * Corresponds to the `route_t` structure produced by `marshall_route` in
 * Kong's `traditional.lua`.
 */
export interface MarshalledRoute {
	/** The original KongRoute object, preserved for diagnostics. */
	route: KongRoute;
	/** Resolved service, if available. */
	service?: KongService;
	/**
	 * Parsed path objects for each entry in `route.paths`.
	 * A route may have multiple paths; the route matches if **any** path matches.
	 */
	parsedPaths: ParsedPath[];
	/**
	 * The length of the longest path pattern.
	 * Used as a tie-breaker in `sort_routes`: longer paths beat shorter ones.
	 *
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L514-L517 – `max_uri_length` field in `route_t`
	 */
	maxUriLength: number;
	/**
	 * Whether any of the route's paths is a regex path.
	 * Corresponds to the `HAS_REGEX_URI` submatch weight bit (bit 0).
	 * Convenience alias: `subMatchWeight & 0x01 !== 0`.
	 *
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L150 – `MATCH_SUBRULES.HAS_REGEX_URI`
	 */
	hasRegexPath: boolean;
	/**
	 * The full 3-bit `submatch_weight` field, mirroring Kong's `route_t.submatch_weight`.
	 *
	 * Bit layout (matches `MATCH_SUBRULES` in `traditional.lua` ~L209-L213):
	 * - Bit 0 (`0x01`) – `HAS_REGEX_URI`: any path is a regex path.
	 * - Bit 1 (`0x02`) – `PLAIN_HOSTS_ONLY`: all host constraints are plain (no wildcards).
	 *   Routes with only plain hosts beat wildcard-host routes at the same path specificity.
	 * - Bit 2 (`0x04`) – `HAS_WILDCARD_HOST_PORT`: any wildcard host has an explicit port.
	 *
	 * `compareRoutes` compares this field as an unsigned integer (higher wins).
	 *
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L209-L213 – `MATCH_SUBRULES`
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L368-L373 – bit assignment in `marshall_route`
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L682-L684 – `sort_routes` comparison
	 */
	subMatchWeight: number;
	/**
	 * Number of distinct header constraints on the route.
	 * Used as the second sort key in `sort_routes`, between `submatch_weight`
	 * and `regex_priority`. More header constraints = higher priority.
	 *
	 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L686-L688
	 */
	headerCount: number;
	/**
	 * The router flavor under which this route was marshalled.
	 * Affects whether regex paths receive a `^` start anchor.
	 */
	flavor: RouterFlavor;
}

/**
 * Kong router flavors, determining matching semantics.
 *
 * - `traditional` – original regex/prefix router, no start anchor on regex paths.
 * - `traditional_compatible` – traditional-style routes compiled to ATC
 *   expressions; regex paths receive a `^` anchor.
 * - `expressions` – native ATC expression router; not fully supported by this
 *   tool (analysis is skipped with a warning).
 *
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/init.lua – `FLAVOR_TO_MODULE`
 * @see https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua#L322-L330 – `path_val_transform`
 */
export type RouterFlavor = 'traditional' | 'traditional_compatible' | 'expressions';

/**
 * Severity level for a diagnostic finding, ordered from most to least severe.
 */
export type Severity = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/**
 * Type discriminator for analysis findings.
 *
 * - `shadowing` – one route's regex matches paths the human author clearly
 *   intended to be handled by a more-specific sibling route.
 * - `collision` – two or more routes match the same request; winner is
 *   non-obvious.
 * - `suspicious_regex` – a regex path uses `*` as if it were a glob wildcard,
 *   which has different semantics in PCRE.
 * - `universal_matcher` – a route that matches every request URL (e.g. a SPA
 *   fallback at `/`). Informational only; these routes are intentionally
 *   excluded from collision / shadowing findings to avoid noise.
 */
export type FindingType = 'shadowing' | 'collision' | 'suspicious_regex' | 'universal_matcher';

/**
 * A single diagnostic finding produced by the analyzer.
 */
export interface Finding {
	/** How severe the finding is. */
	severity: Severity;
	/** What kind of problem was detected. */
	type: FindingType;
	/** The router flavor in effect when the finding was produced. */
	routerFlavor: RouterFlavor;
	/**
	 * The routes involved in the finding. For shadowing/collision, index 0 is
	 * the winner; subsequent entries are the routes being shadowed/collided.
	 */
	routes: KongRoute[];
	/**
	 * Sample request paths that demonstrate the problem.
	 * Each path is chosen to trigger the collision or shadowing scenario.
	 */
	samples: string[];
	/**
	 * UUID of the route that wins for the given sample requests, when
	 * determinable. `undefined` for pure `suspicious_regex` findings where no
	 * simulation was performed.
	 */
	winnerId?: string;
	/**
	 * Ordered list of human-readable sentences explaining why the finding exists
	 * and how Kong arrives at the observed winner.
	 */
	reason: string[];
	/**
	 * Safer replacement path patterns for each route listed in `routes`,
	 * indexed in the same order. May be empty if no replacement is obvious.
	 */
	suggestions: string[];
}

/**
 * An HTTP request descriptor used by the request simulator.
 */
export interface SimRequest {
	/** HTTP method, e.g. `"GET"`. */
	method: string;
	/** Host header value, e.g. `"api.example.com"`. */
	host: string;
	/** Request URI path, e.g. `"/epp-poc/docs"`. */
	path: string;
	/** Optional request headers for header-constrained routes. */
	headers?: Record<string, string>;
}

/**
 * Result of simulating a request against the marshalled route set.
 */
export interface SimResult {
	/** The request that was simulated. */
	request: SimRequest;
	/** All routes whose patterns match the request, in priority order (winner first). */
	matchedRoutes: MarshalledRoute[];
	/**
	 * The winning (highest-priority) route, or `undefined` if no route matched.
	 */
	winner?: MarshalledRoute;
	/**
	 * Human-readable explanation of why the winner was selected (or why nothing
	 * matched).
	 */
	explanation: string[];
}

/**
 * Options for connecting to a Konnect control plane.
 */
export interface KonnectConfig {
	/** Personal Access Token or System Account Access Token. */
	token: string;
	/** UUID of the Konnect control plane to inspect. */
	controlPlaneId: string;
	/**
	 * Konnect region subdomain. Defaults to `"us"`.
	 * Maps to `https://{region}.api.konghq.com`.
	 */
	region?: string;
}

/**
 * The full configuration payload fetched from Konnect, normalised for
 * offline analysis.
 */
export interface KonnectData {
	/** All routes in the control plane. */
	routes: KongRoute[];
	/** All services in the control plane, keyed by service UUID for fast lookup. */
	services: Map<string, KongService>;
	/** Router flavor configured for the control plane, if detectable. */
	routerFlavor?: RouterFlavor;
	/**
	 * Konnect control plane UUID. Present when fetched live from the Konnect
	 * API; `undefined` when loaded from a local dump file.
	 * Used to construct Konnect UI deep-links.
	 */
	controlPlaneId?: string;
	/**
	 * Konnect region code, e.g. `"us"`. Present when fetched live; `undefined`
	 * in offline / `--file` mode.
	 */
	region?: string;
}
