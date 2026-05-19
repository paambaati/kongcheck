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
import { fetchKonnectConfig } from './client.ts';
import { applyFindingFilter, parseFilters, type FilterKey } from './filter.ts';
import { compareRoutes, marshalRoute, simulateRequest } from './router.ts';
import type { KonnectData, KonnectConfig, RouterFlavor } from './types.ts';

/** Fields common to every tool that needs a live Konnect connection. */
const konnectParams = {
	controlPlaneId: z
		.string()
		.optional()
		.describe(
			'UUID of the Konnect control plane to inspect. ' +
				'Falls back to the KONNECT_CONTROL_PLANE_ID environment variable.',
		),
	region: z
		.union([z.enum(['us', 'eu', 'au', 'me', 'in', 'sg']), z.string()])
		.optional()
		.describe('Konnect region (us | eu | au | me | in | sg). Defaults to KONNECT_REGION env var or "us".'),
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
		_cache.set(key, { data, fetchedAt: now });
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
				'simulate a specific HTTP request, and get_route_config to inspect the raw ' +
				'route/service data.',
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
					.describe('Include INFO-level universal-matcher findings. Default: false.'),
				filter: filterParam,
			},
		},
		async ({ controlPlaneId, region, flavor, includeInfo, filter }) => {
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
						text: JSON.stringify(
							{
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
							},
							null,
							2,
						),
					},
				],
			};
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
						text: JSON.stringify(
							{
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: resolvedFlavor,
								totalRoutes: fetched.routes.length,
								totalFindings: findings.length,
								findings,
							},
							null,
							2,
						),
					},
				],
			};
		},
	);

	server.registerTool(
		'explain_request',
		{
			description:
				'Simulate a specific HTTP request against a Konnect control plane and return ' +
				'the winning route with a step-by-step explanation of why it won.',
			inputSchema: {
				...konnectParams,
				flavor: flavorParam,
				method: z.string().default('GET').describe('HTTP method, e.g. "GET".'),
				host: z.string().describe('Host header value, e.g. "api.example.com".'),
				path: z.string().describe('Request path, e.g. "/api/v1/users".'),
				headers: z
					.record(z.string(), z.string())
					.optional()
					.describe('Optional request headers as a key/value object, e.g. {"x-env": "prod"}.'),
			},
		},
		async ({ controlPlaneId, region, flavor, method, host, path, headers }) => {
			const cfg = resolveConfig({ controlPlaneId, region });
			const fetched = await fetch(cfg);
			const resolvedFlavor: RouterFlavor = flavor ?? fetched.routerFlavor ?? 'traditional';

			const marshalled: ReturnType<typeof marshalRoute>[] = [];
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
			const sorted = [...marshalled].sort(compareRoutes);

			const result = simulateRequest(sorted, {
				method,
				host,
				path,
				headers: headers as Record<string, string> | undefined,
			});

			return {
				content: [
					{
						type: 'text',
						text: JSON.stringify(
							{
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: resolvedFlavor,
								request: result.request,
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
							},
							null,
							2,
						),
					},
				],
			};
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
			const cfg = resolveConfig({ controlPlaneId, region });
			const fetched = await fetch(cfg);

			return {
				content: [
					{
						type: 'text',
						text: JSON.stringify(
							{
								controlPlaneId: cfg.controlPlaneId,
								routerFlavor: fetched.routerFlavor,
								totalRoutes: fetched.routes.length,
								totalServices: fetched.services.size,
								routes: fetched.routes,
								services: Array.from(fetched.services.values()),
							},
							null,
							2,
						),
					},
				],
			};
		},
	);

	const transport = new StdioServerTransport();
	await server.connect(transport);
}
