/**
 * kongcheck MCP server – exposes route analysis and simulation as MCP tools
 * so AI agents can call them directly.
 *
 * Transport: stdio (the dominant real-world pattern – the MCP host spawns this
 * process and speaks to it over stdin/stdout).
 *
 * Authentication design –
 *   - KONNECT_TOKEN is read from the environment at process start.
 *     The MCP host sets this once in its config file; it never travels over the
 *     MCP wire.
 *   - controlPlaneId is an optional per-call parameter so the agent can query
 *     different control planes in the same session. Falls back to
 *     KONNECT_CONTROL_PLANE_ID when omitted.
 *   - region is also optional per-call, falling back to KONNECT_REGION or "us".
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { name, version } from '../package.json';
import { analyzeRoutes } from './analyzer.ts';
import { fetchKonnectConfig, REGION_MAP } from './client.ts';
import { applyFindingFilter, parseFilters, type FilterKey } from './filter.ts';
import { compareRoutes, marshalRoute, simulateRequest } from './router.ts';
import type { KonnectData, KonnectConfig, MarshalledRoute, RouterFlavor } from './types.ts';
import { normalizePath } from './utils.ts';

/** Fields common to every tool that needs a live Konnect connection. */
const konnectParams = {
	controlPlaneId: z
		.uuid()
		.optional()
		.describe(
			'UUID of the Konnect control plane to inspect. ' +
				'Falls back to the KONNECT_CONTROL_PLANE_ID environment variable.',
		),
	region: z
		.enum(Object.keys(REGION_MAP))
		.optional()
		.describe('Konnect region. Defaults to KONNECT_REGION environment variable or "us".'),
};

const flavorParam = z
	.enum(['traditional', 'traditional_compatible', 'expressions'])
	.optional()
	.describe('Override router flavor. Auto-detected from Konnect when omitted.');

const FILTER_KEYS = ['path', 'name', 'service', 'tag', 'id'] as const satisfies FilterKey[];

const filterParam = z
	.array(
		z.object({
			key: z.enum(FILTER_KEYS).describe('Attribute to filter on.'),
			value: z.string().describe('Substring to match against (case-insensitive).'),
		}),
	)
	.optional()
	.describe(
		'Filter findings to routes matching all given key/value pairs (ANDed). ' +
			'Supported keys: path, name, service, tag, id.',
	);

/**
 * In-memory config cache (only for MCP mode)/
 */
interface CacheEntry {
	data: KonnectData;
	fetchedAt: number;
	/**
	 * Lazily populated cache of marshalled+sorted routes per router flavor.
	 *
	 * `explain_request` marshals routes on the first call for a given flavor
	 * and stores the result here, so subsequent calls with the same flavor
	 * within the TTL window skip the marshal+sort pass.
	 *
	 * Cleared automatically whenever the data entry is evicted or overwritten.
	 */
	marshalledByFlavor: Map<RouterFlavor, MarshalledRoute[]>;
}

/**
 * Fetches a Konnect control-plane config, returning a cached copy when one
 * exists and is still within the TTL.
 *
 * The cache is intentionally module-level so it survives across MCP tool
 * calls within the same server process. CLI commands never call this function,
 * so they are unaffected.
 *
 * Pass `cacheTtlMs = 0` to disable caching entirely.
 */
/** @internal Exported for testing only. */
export const _cache = new Map<string, CacheEntry>();

export async function fetchKonnectConfigCached(
	cfg: KonnectConfig,
	cacheTtlMs: number,
	/** @internal Override the fetch implementation (used in tests). */
	_fetchFn: (cfg: KonnectConfig) => Promise<KonnectData> = fetchKonnectConfig,
): Promise<KonnectData> {
	if (cacheTtlMs > 0) {
		const key = `${cfg.region}:${cfg.controlPlaneId}`;
		const now = Date.now();
		const entry = _cache.get(key);
		if (entry && now - entry.fetchedAt < cacheTtlMs) {
			return entry.data;
		}
		const data = await _fetchFn(cfg);
		_cache.set(key, { data, fetchedAt: now, marshalledByFlavor: new Map() });
		// Evict any other entries that have already expired so stale data
		// doesn't linger in memory after its TTL window closes.
		for (const [k, e] of _cache) {
			if (k !== key && now - e.fetchedAt >= cacheTtlMs) _cache.delete(k);
		}
		return data;
	}
	return _fetchFn(cfg);
}

// ---------------------------------------------------------------------------

/**
 * Resolves the Konnect connection config from per-call params and env vars.
 * Throws a descriptive error if the token or control-plane-id is missing.
 */
/** @internal Exported for testing only. */
export function resolveConfig(params: { controlPlaneId?: string; region?: string }): KonnectConfig {
	const token = process.env['KONNECT_TOKEN'];
	if (!token) {
		throw new Error(
			'KONNECT_TOKEN environment variable is not set. ' +
				'Configure it in your MCP host config so it is available to kongcheck.',
		);
	}

	const controlPlaneId = params.controlPlaneId ?? process.env['KONNECT_CONTROL_PLANE_ID'];
	if (!controlPlaneId) {
		throw new Error(
			'controlPlaneId was not provided in the tool call and ' +
				'KONNECT_CONTROL_PLANE_ID environment variable is not set.',
		);
	}

	const region = params.region ?? process.env['KONNECT_REGION'] ?? 'us';
	return { token, controlPlaneId, region };
}

/**
 * Connects the MCP server to the stdio transport and begins serving requests.
 *
 * @param cacheTtlMs - How long (in milliseconds) to cache fetched Konnect
 *   config per control-plane within a single server session. Pass `0` to
 *   disable caching entirely. Defaults to 60,000 ms (60 seconds).
 */
export async function startMcpServer(cacheTtlMs = 60_000): Promise<void> {
	const fetch = (cfg: KonnectConfig) => fetchKonnectConfigCached(cfg, cacheTtlMs);

	const server = new McpServer(
		{ name, version },
		{
			instructions:
				'kongcheck audits Kong Konnect route configurations for collisions, ' +
				'shadowing, and suspicious regex patterns. Use analyze_routes for a full ' +
				'audit, get_collisions for a focused collision report, explain_request to ' +
				'simulate a specific HTTP or TCP/TLS stream request, and get_route_config ' +
				'to inspect the raw route/service data.',
		},
	);

	server.registerTool(
		'analyze_routes',
		{
			description:
				'Run a full four-pass audit of a Konnect control plane: suspicious regex paths, ' +
				'route collisions, shadowing, and (optionally) universal catch-all routes.',
			inputSchema: {
				...konnectParams,
				flavor: flavorParam,
				includeInfo: z
					.boolean()
					.optional()
					.default(false)
					.describe(
						'Include INFO-level findings. INFO covers: universal catch-all routes that ' +
							'match every request, and route pairs that are structurally stratified ' +
							'(mutually exclusive by SNI, source/destination IP, or protocol family) ' +
							'so a collision is impossible. Default: false.',
					),
				filter: filterParam,
			},
		},
		async ({ controlPlaneId, region, flavor, includeInfo, filter }) => {
			try {
				const cfg = resolveConfig({ controlPlaneId, region });
				const fetched = await fetch(cfg);
				const resolvedFlavor: RouterFlavor = flavor ?? fetched.routerFlavor ?? 'traditional';
				const allFindings = analyzeRoutes(fetched, { flavor: resolvedFlavor, includeInfo });
				const predicates = parseFilters(filter?.map((f) => `${f.key}:${f.value}`));
				const findings = applyFindingFilter(allFindings, predicates, fetched.services);

				return {
					content: [
						{
							type: 'text',
							text: JSON.stringify({
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: resolvedFlavor,
								totalRoutes: fetched.routes.length,
								totalFindings: findings.length,
								summary: {
									HIGH: findings.filter((f) => f.severity === 'HIGH').length,
									MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
									LOW: findings.filter((f) => f.severity === 'LOW').length,
									INFO: findings.filter((f) => f.severity === 'INFO').length,
								},
								findings,
							}),
						},
					],
				};
			} catch (err) {
				let msg = err instanceof Error ? err.message : String(err);
				msg = msg.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
				return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
			}
		},
	);

	server.registerTool(
		'get_collisions',
		{
			description:
				'Return only shadowing and collision findings for a Konnect control plane. ' +
				'Excludes suspicious-regex findings.',
			inputSchema: {
				...konnectParams,
				flavor: flavorParam,
				filter: filterParam,
			},
		},
		async ({ controlPlaneId, region, flavor, filter }) => {
			try {
				const cfg = resolveConfig({ controlPlaneId, region });
				const fetched = await fetch(cfg);
				const resolvedFlavor: RouterFlavor = flavor ?? fetched.routerFlavor ?? 'traditional';
				const all = analyzeRoutes(fetched, { flavor: resolvedFlavor, includeInfo: false });
				const collisions = all.filter((f) => f.type === 'shadowing' || f.type === 'collision');
				const predicates = parseFilters(filter?.map((f) => `${f.key}:${f.value}`));
				const findings = applyFindingFilter(collisions, predicates, fetched.services);

				return {
					content: [
						{
							type: 'text',
							text: JSON.stringify({
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: resolvedFlavor,
								totalRoutes: fetched.routes.length,
								totalFindings: findings.length,
								findings,
							}),
						},
					],
				};
			} catch (err) {
				let msg = err instanceof Error ? err.message : String(err);
				msg = msg.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
				return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
			}
		},
	);

	server.registerTool(
		'explain_request',
		{
			description:
				'Simulate a specific HTTP or TCP/TLS stream request against a Konnect control ' +
				'plane and return the winning route with a step-by-step explanation of why it won. ' +
				'For stream routes, supply sni / sourceIp / sourcePort / destIp / destPort as needed. ' +
				'When an L4 field is omitted, the corresponding route constraint is skipped ' +
				'(conservative mode: every route is a candidate). ' +
				'The path is normalised before matching: query strings and fragments are stripped ' +
				'and dot-segments are resolved.',
			inputSchema: {
				...konnectParams,
				flavor: flavorParam,
				method: z.string().default('GET').describe('HTTP method, e.g. "GET".'),
				host: z
					.string()
					.optional()
					.describe(
						'Host header value, e.g. "api.example.com". ' +
							'Defaults to "example.com" when omitted (sufficient for path-only matching).',
					),
				path: z
					.string()
					.describe('Request path, e.g. "/api/v1/users". Query strings and fragments are stripped automatically.'),
				headers: z
					.record(z.string(), z.string())
					.optional()
					.describe(
						'Optional request headers as a key/value object, e.g. {"x-env": "prod"}. ' +
							'When provided, routes with header constraints are evaluated strictly. ' +
							'When omitted, header constraints are skipped (every route is a candidate).',
					),
				sni: z
					.string()
					.optional()
					.describe(
						'TLS SNI value for stream route simulation, e.g. "api.example.com". ' +
							'When provided, routes with snis constraints are evaluated strictly.',
					),
				sourceIp: z
					.string()
					.optional()
					.describe(
						'Source IP address of the connection, e.g. "10.0.1.5". IPv4 and IPv6 are ' +
							'accepted; CIDR matching applies to the route constraints. When provided, ' +
							'sources constraints on routes are evaluated strictly.',
					),
				sourcePort: z
					.number()
					.int()
					.min(1)
					.max(65535)
					.optional()
					.describe(
						'Source TCP/UDP port of the connection, e.g. 54321. Evaluated only when sourceIp is also provided.',
					),
				destIp: z
					.string()
					.optional()
					.describe(
						'Destination IP address of the connection, e.g. "192.168.1.10". When provided, ' +
							'destinations constraints on routes are evaluated strictly.',
					),
				destPort: z
					.number()
					.int()
					.min(1)
					.max(65535)
					.optional()
					.describe('Destination TCP/UDP port, e.g. 443. Evaluated only when destIp is also provided.'),
			},
		},
		async ({
			controlPlaneId,
			region,
			flavor,
			method,
			host,
			path,
			headers,
			sni,
			sourceIp,
			sourcePort,
			destIp,
			destPort,
		}) => {
			try {
				const cfg = resolveConfig({ controlPlaneId, region });
				const fetched = await fetch(cfg);
				const resolvedFlavor: RouterFlavor = flavor ?? fetched.routerFlavor ?? 'traditional';

				// Use the cached marshalled+sorted route set when available.
				// The cache entry is keyed the same way as fetchKonnectConfigCached.
				const cacheKey = `${cfg.region}:${cfg.controlPlaneId}`;
				const cacheEntry = _cache.get(cacheKey);
				let sorted: MarshalledRoute[];
				if (cacheEntry?.marshalledByFlavor.has(resolvedFlavor)) {
					sorted = cacheEntry.marshalledByFlavor.get(resolvedFlavor)!;
				} else {
					const marshalled: MarshalledRoute[] = [];
					for (const r of fetched.routes) {
						const svc = r.service?.id ? fetched.services.get(r.service.id) : undefined;
						const paths = r.paths ?? [];
						if (paths.length <= 1) {
							marshalled.push(marshalRoute(r, svc, resolvedFlavor));
						} else {
							for (const p of paths) {
								marshalled.push(marshalRoute({ ...r, paths: [p] } as typeof r, svc, resolvedFlavor));
							}
						}
					}
					sorted = [...marshalled].sort(compareRoutes);
					// Store in the cache entry for reuse within the same TTL window.
					cacheEntry?.marshalledByFlavor.set(resolvedFlavor, sorted);
				}

				// Normalise the path: strip query strings, fragments, and resolve dot-segments.
				const normalizedPath = normalizePath(path);

				const result = simulateRequest(sorted, {
					method,
					host: host ?? 'example.com',
					path: normalizedPath,
					// When headers is provided (even empty object), header constraints are
					// evaluated strictly. When undefined, they are skipped.
					headers: headers as Record<string, string> | undefined,
					// L4 fields: only applied when the caller provides them.
					// Undefined = skip the check (conservative / static-analysis mode).
					sni,
					sourceIp,
					sourcePort,
					destIp,
					destPort,
				});

				return {
					content: [
						{
							type: 'text',
							text: JSON.stringify({
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: resolvedFlavor,
								request: result.request,
								pathNormalized: normalizedPath !== path ? normalizedPath : undefined,
								matched: !!result.winner,
								winner: result.winner
									? {
											id: result.winner.route.id,
											name: result.winner.route.name,
											paths: result.winner.route.paths,
											regex_priority: result.winner.route.regex_priority,
										}
									: null,
								explanation: result.explanation,
								otherMatchedRoutes: result.matchedRoutes.slice(1).map((mr) => ({
									id: mr.route.id,
									name: mr.route.name,
									paths: mr.route.paths,
								})),
							}),
						},
					],
				};
			} catch (err) {
				let msg = err instanceof Error ? err.message : String(err);
				msg = msg.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
				return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
			}
		},
	);

	server.registerTool(
		'get_route_config',
		{
			description:
				'Fetch the raw routes and services from a Konnect control plane as structured data. ' +
				'Useful when the agent needs to inspect or reason about the full route list directly.',
			inputSchema: {
				...konnectParams,
			},
		},
		async ({ controlPlaneId, region }) => {
			try {
				const cfg = resolveConfig({ controlPlaneId, region });
				const fetched = await fetch(cfg);

				return {
					content: [
						{
							type: 'text',
							text: JSON.stringify({
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: fetched.routerFlavor,
								totalRoutes: fetched.routes.length,
								totalServices: fetched.services.size,
								routes: fetched.routes,
								services: Array.from(fetched.services.values()),
							}),
						},
					],
				};
			} catch (err) {
				let msg = err instanceof Error ? err.message : String(err);
				msg = msg.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
				return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
			}
		},
	);

	const transport = new StdioServerTransport();
	await server.connect(transport);
}
