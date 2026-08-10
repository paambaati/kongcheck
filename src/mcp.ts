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

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
	ListToolsRequestSchema,
	CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as v from 'valibot';

import { name, version } from './generated-version.ts';
import { analyzeRoutes } from './analyzer.ts';
import { fetchKonnectConfig, REGION_MAP } from './client.ts';
import { applyFindingFilter, parseFilters, type FilterKey } from './filter.ts';
import { compareRoutes, marshalRoute, simulateRequest } from './router.ts';
import type { KonnectData, KonnectConfig, MarshalledRoute, RouterFlavor } from './types.ts';
import { normalizePath } from './utils.ts';

// ---------------------------------------------------------------------------
// Valibot schemas for tool argument validation
// ---------------------------------------------------------------------------

const AnalyzeRoutesSchema = v.object({
	controlPlaneId: v.optional(v.pipe(v.string(), v.uuid())),
	region: v.optional(v.picklist(['us', 'eu', 'au', 'me', 'in', 'sg'])),
	flavor: v.optional(v.picklist(['traditional', 'traditional_compatible', 'expressions'])),
	includeInfo: v.optional(v.boolean(), false),
	filter: v.optional(v.array(
		v.object({
			key: v.picklist(['path', 'name', 'service', 'tag', 'id']),
			value: v.string(),
		})
	)),
});

const GetCollisionsSchema = v.object({
	controlPlaneId: v.optional(v.pipe(v.string(), v.uuid())),
	region: v.optional(v.picklist(['us', 'eu', 'au', 'me', 'in', 'sg'])),
	flavor: v.optional(v.picklist(['traditional', 'traditional_compatible', 'expressions'])),
	filter: v.optional(v.array(
		v.object({
			key: v.picklist(['path', 'name', 'service', 'tag', 'id']),
			value: v.string(),
		})
	)),
});

const ExplainRequestSchema = v.object({
	controlPlaneId: v.optional(v.pipe(v.string(), v.uuid())),
	region: v.optional(v.picklist(['us', 'eu', 'au', 'me', 'in', 'sg'])),
	flavor: v.optional(v.picklist(['traditional', 'traditional_compatible', 'expressions'])),
	method: v.optional(v.string(), 'GET'),
	host: v.optional(v.string()),
	path: v.string(),
	headers: v.optional(v.record(v.string(), v.string())),
	sni: v.optional(v.string()),
	sourceIp: v.optional(v.string()),
	sourcePort: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(65535))),
	destIp: v.optional(v.string()),
	destPort: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(65535))),
});

const GetRouteConfigSchema = v.object({
	controlPlaneId: v.optional(v.pipe(v.string(), v.uuid())),
	region: v.optional(v.picklist(['us', 'eu', 'au', 'me', 'in', 'sg'])),
});

// ---------------------------------------------------------------------------

/**
 * In-memory config cache (only for MCP mode)
 */
interface CacheEntry {
	data: KonnectData;
	fetchedAt: number;
	marshalledByFlavor: Map<RouterFlavor, MarshalledRoute[]>;
}

export const _cache = new Map<string, CacheEntry>();

export async function fetchKonnectConfigCached(
	cfg: KonnectConfig,
	cacheTtlMs: number,
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
		for (const [k, e] of _cache) {
			if (k !== key && now - e.fetchedAt >= cacheTtlMs) _cache.delete(k);
		}
		return data;
	}
	return _fetchFn(cfg);
}

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

export async function startMcpServer(cacheTtlMs = 60_000): Promise<void> {
	const fetch = (cfg: KonnectConfig) => fetchKonnectConfigCached(cfg, cacheTtlMs);

	const server = new Server(
		{ name, version },
		{
			capabilities: {
				tools: {}
			}
		}
	);

	server.setRequestHandler(ListToolsRequestSchema, async () => {
		return {
			tools: [
				{
					name: 'analyze_routes',
					description:
						'Run a full four-pass audit of a Konnect control plane: suspicious regex paths, ' +
						'route collisions, shadowing, and (optionally) universal catch-all routes.',
					inputSchema: {
						type: 'object',
						properties: {
							controlPlaneId: {
								type: 'string',
								description: 'UUID of the Konnect control plane to inspect. Falls back to the KONNECT_CONTROL_PLANE_ID environment variable.'
							},
							region: {
								type: 'string',
								enum: ['us', 'eu', 'au', 'me', 'in', 'sg'],
								description: 'Konnect region. Defaults to KONNECT_REGION environment variable or "us".'
							},
							flavor: {
								type: 'string',
								enum: ['traditional', 'traditional_compatible', 'expressions'],
								description: 'Override router flavor. Auto-detected from Konnect when omitted.'
							},
							includeInfo: {
								type: 'boolean',
								description: 'Include INFO-level findings (universal catch-all, stratified route pairs). Default: false.'
							},
							filter: {
								type: 'array',
								description: 'Filter findings to routes matching all given key/value pairs (ANDed).',
								items: {
									type: 'object',
									properties: {
										key: { type: 'string', enum: ['path', 'name', 'service', 'tag', 'id'] },
										value: { type: 'string' }
									},
									required: ['key', 'value']
								}
							}
						}
					}
				},
				{
					name: 'get_collisions',
					description:
						'Return only shadowing and collision findings for a Konnect control plane. Excludes suspicious-regex findings.',
					inputSchema: {
						type: 'object',
						properties: {
							controlPlaneId: {
								type: 'string',
								description: 'UUID of the Konnect control plane to inspect. Falls back to the KONNECT_CONTROL_PLANE_ID environment variable.'
							},
							region: {
								type: 'string',
								enum: ['us', 'eu', 'au', 'me', 'in', 'sg'],
								description: 'Konnect region. Defaults to KONNECT_REGION environment variable or "us".'
							},
							flavor: {
								type: 'string',
								enum: ['traditional', 'traditional_compatible', 'expressions'],
								description: 'Override router flavor. Auto-detected from Konnect when omitted.'
							},
							filter: {
								type: 'array',
								description: 'Filter findings to routes matching all given key/value pairs (ANDed).',
								items: {
									type: 'object',
									properties: {
										key: { type: 'string', enum: ['path', 'name', 'service', 'tag', 'id'] },
										value: { type: 'string' }
									},
									required: ['key', 'value']
								}
							}
						}
					}
				},
				{
					name: 'explain_request',
					description:
						'Simulate a specific HTTP or TCP/TLS stream request against a Konnect control plane and return the winning route with a step-by-step explanation. ' +
						'When an L4 field is omitted, the corresponding constraint is skipped.',
					inputSchema: {
						type: 'object',
						properties: {
							controlPlaneId: { type: 'string' },
							region: { type: 'string', enum: ['us', 'eu', 'au', 'me', 'in', 'sg'] },
							flavor: { type: 'string', enum: ['traditional', 'traditional_compatible', 'expressions'] },
							method: { type: 'string', description: 'HTTP method, e.g. "GET". Default: "GET".' },
							host: { type: 'string', description: 'Host header value, e.g. "api.example.com".' },
							path: { type: 'string', description: 'Request path, e.g. "/api/v1/users".' },
							headers: { type: 'object', description: 'Optional request headers as a key/value object.' },
							sni: { type: 'string', description: 'TLS SNI value for stream route simulation.' },
							sourceIp: { type: 'string', description: 'Source IP address of the connection.' },
							sourcePort: { type: 'number', minimum: 1, maximum: 65535, description: 'Source TCP/UDP port.' },
							destIp: { type: 'string', description: 'Destination IP address of the connection.' },
							destPort: { type: 'number', minimum: 1, maximum: 65535, description: 'Destination TCP/UDP port.' }
						},
						required: ['path']
					}
				},
				{
					name: 'get_route_config',
					description:
						'Fetch the raw routes and services from a Konnect control plane as structured data. Useful when the agent needs to inspect raw configs directly.',
					inputSchema: {
						type: 'object',
						properties: {
							controlPlaneId: { type: 'string' },
							region: { type: 'string', enum: ['us', 'eu', 'au', 'me', 'in', 'sg'] }
						}
					}
				}
			]
		};
	});

	server.setRequestHandler(CallToolRequestSchema, async (request) => {
		const { name: toolName, arguments: args } = request.params;

		try {
			if (toolName === 'analyze_routes') {
				const parseResult = v.safeParse(AnalyzeRoutesSchema, args);
				if (!parseResult.success) {
					const errorMsg = parseResult.issues.map(i => `${i.path?.[0]?.key ?? 'arg'}: ${i.message}`).join(', ');
					return { isError: true, content: [{ type: 'text', text: `Invalid arguments: ${errorMsg}` }] };
				}
				const { controlPlaneId, region, flavor, includeInfo, filter } = parseResult.output;

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
			}

			if (toolName === 'get_collisions') {
				const parseResult = v.safeParse(GetCollisionsSchema, args);
				if (!parseResult.success) {
					const errorMsg = parseResult.issues.map(i => `${i.path?.[0]?.key ?? 'arg'}: ${i.message}`).join(', ');
					return { isError: true, content: [{ type: 'text', text: `Invalid arguments: ${errorMsg}` }] };
				}
				const { controlPlaneId, region, flavor, filter } = parseResult.output;

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
			}

			if (toolName === 'explain_request') {
				const parseResult = v.safeParse(ExplainRequestSchema, args);
				if (!parseResult.success) {
					const errorMsg = parseResult.issues.map(i => `${i.path?.[0]?.key ?? 'arg'}: ${i.message}`).join(', ');
					return { isError: true, content: [{ type: 'text', text: `Invalid arguments: ${errorMsg}` }] };
				}
				const {
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
				} = parseResult.output;

				const cfg = resolveConfig({ controlPlaneId, region });
				const fetched = await fetch(cfg);
				const resolvedFlavor: RouterFlavor = flavor ?? fetched.routerFlavor ?? 'traditional';

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
					cacheEntry?.marshalledByFlavor.set(resolvedFlavor, sorted);
				}

				const normalizedPath = normalizePath(path);

				const result = simulateRequest(sorted, {
					method: method ?? 'GET',
					host: host ?? 'example.com',
					path: normalizedPath,
					headers: headers as Record<string, string> | undefined,
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
			}

			if (toolName === 'get_route_config') {
				const parseResult = v.safeParse(GetRouteConfigSchema, args);
				if (!parseResult.success) {
					const errorMsg = parseResult.issues.map(i => `${i.path?.[0]?.key ?? 'arg'}: ${i.message}`).join(', ');
					return { isError: true, content: [{ type: 'text', text: `Invalid arguments: ${errorMsg}` }] };
				}
				const { controlPlaneId, region } = parseResult.output;

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
			}

			throw new Error(`Unknown tool: ${toolName}`);
		} catch (err) {
			let msg = err instanceof Error ? err.message : String(err);
			msg = msg.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
			return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
		}
	});

	const transport = new StdioServerTransport();
	await server.connect(transport);
}
