#!/usr/bin/env bun
/**
 * kongcheck – main CLI entry point.
 *
 * Commands:
 *   analyze         Full audit of a control plane.
 *   collisions      Show only overlapping / shadowed route pairs.
 *   explain-request Simulate a specific request and show the winning route.
 *   dump-config     Fetch and save routes/services to a local JSON file.
 *
 * Global options:
 *   --token           Konnect API token  (env: KONNECT_TOKEN)
 *   --control-plane-id Control plane UUID (env: KONNECT_CONTROL_PLANE_ID)
 *   --region          Konnect region (default: "us")
 *   --format          Output format: "human" | "json"  (default: "human")
 *   --fail-on         Exit non-zero when findings >= this severity
 *   --flavor          Override router flavor
 *   --file            Load config from a local JSON dump instead of Konnect API
 *   --verbose         Print progress to stderr
 *   --filter          Filter findings by route attributes (repeatable).
 *                     Format: key:value  Supported keys: path, name, service, tag, id
 *                     AND across different keys; OR within the same key.
 *                     A finding is shown when ANY involved route satisfies all predicates.
 */

import cac from 'cac';
import { Spinner } from 'nspin-bun';

import { name, version } from '../package.json';
import { analyzeRoutes } from './analyzer.ts';
import { fetchKonnectConfig, loadLocalConfig } from './client.ts';
import { applyFindingFilter, parseFilters } from './filter.ts';
import { formatHuman, formatJSON, formatCSV, formatDumpSummary, shouldFail, konnectRouteUrl } from './formatter.ts';
import type { KonnectContext } from './formatter.ts';
import { startMcpServer } from './mcp.ts';
import { compareRoutes, marshalRoute, simulateRequest } from './router.ts';
import type { Finding, KonnectConfig, KonnectData, RouterFlavor } from './types.ts';

const cli = cac(name);

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸'];

/**
 * Returns an animated Spinner when stdout is a TTY and verbose mode is off.
 * Returns a silent no-op otherwise — so piped output and verbose logs are
 * never polluted by spinner control sequences.
 */
function makeSpinner(verbose: boolean) {
	if (verbose || !process.stdout.isTTY) {
		return { start(_?: string) {}, updateText(_: string) {}, stop(_?: string) {} };
	}
	return new Spinner({ frames: SPINNER_FRAMES, interval: 80 });
}

cli
	.help()
	.version(version)
	.option('--token <token>', 'Konnect API token (or set KONNECT_TOKEN env var)')
	.option('--control-plane-id <id>', 'Konnect control plane UUID (or set KONNECT_CONTROL_PLANE_ID env var)')
	.option('--region <region>', 'Konnect region: us | eu | au | me | in | sg', {
		default: 'us',
	})
	.option('--format <fmt>', 'Output format: human | json | csv', {
		default: 'human',
	})
	.option('--fail-on <severity>', 'Exit non-zero if findings at or above this severity: HIGH | MEDIUM | LOW | INFO')
	.option('--flavor <flavor>', 'Override router flavor: traditional | traditional_compatible | expressions')
	.option('--file <path>', 'Load config from a local JSON dump file instead of the Konnect API')
	.option('--verbose', 'Print progress information to stderr')
	.option('--show-info', 'Include INFO-level findings (universal catch-all routes) in output')
	.option(
		'--filter <predicate>',
		'Filter findings by route attribute (repeatable). Format: key:value. ' +
			'Keys: path, name, service, tag, id. ' +
			'AND across different keys; OR within the same key. ' +
			'A finding is shown when ANY involved route matches.',
	);

/**
 * Resolves the Konnect connection config from CLI options and environment
 * variables. Token and control-plane-id can be supplied as options or env vars.
 */
function resolveKonnectConfig(options: Record<string, unknown>): KonnectConfig {
	const token = (options['token'] as string | undefined) ?? process.env['KONNECT_TOKEN'];
	const controlPlaneId = (options['controlPlaneId'] as string | undefined) ?? process.env['KONNECT_CONTROL_PLANE_ID'];

	if (!token) {
		console.error('Error: --token or KONNECT_TOKEN environment variable is required.');
		process.exit(1);
	}
	if (!controlPlaneId) {
		console.error('Error: --control-plane-id or KONNECT_CONTROL_PLANE_ID environment variable is required.');
		process.exit(1);
	}

	return {
		token,
		controlPlaneId,
		region: (options['region'] as string | undefined) ?? 'us',
	};
}

/**
 * Fetches config from either a local file (--file) or the Konnect API.
 * Returns the normalised {@link KonnectData}.
 */
async function resolveConfig(options: Record<string, unknown>): Promise<KonnectData> {
	const filePath = options['file'] as string | undefined;
	if (filePath) {
		if (options['verbose']) console.log(`Loading config from ${filePath} ...`);
		return loadLocalConfig(filePath);
	}

	const konnectConfig = resolveKonnectConfig(options);
	return fetchKonnectConfig(konnectConfig, { verbose: !!options['verbose'] });
}

/**
 * Applies the --flavor override if provided, otherwise uses the detected
 * flavor from the fetched config, falling back to "traditional".
 */
function resolveFlavorOption(options: Record<string, unknown>, fetched: KonnectData): RouterFlavor {
	const raw = options['flavor'] as string | undefined;
	if (raw === 'traditional' || raw === 'traditional_compatible' || raw === 'expressions') {
		return raw;
	}
	return fetched.routerFlavor ?? 'traditional';
}

/**
 * Derives a {@link KonnectContext} from a fetched config, if connection details
 * are available. Returns `undefined` in offline / `--file` mode.
 */
function resolveKonnectContext(fetched: KonnectData): KonnectContext | undefined {
	if (fetched.controlPlaneId && fetched.region) {
		return { controlPlaneId: fetched.controlPlaneId, region: fetched.region };
	}
	return undefined;
}

/**
 * Prints findings to stdout in the requested format and optionally exits
 * non-zero based on --fail-on.
 */
function outputAndMaybeExit(
	findings: Finding[],
	flavor: RouterFlavor,
	options: Record<string, unknown>,
	ctx?: KonnectContext,
	hiddenInfoCount = 0,
): void {
	const format = (options['format'] as string | undefined) ?? 'human';
	let output: string;
	if (format === 'json') {
		output = formatJSON(findings, flavor, ctx);
	} else if (format === 'csv') {
		output = formatCSV(findings, flavor, ctx);
	} else {
		output = formatHuman(findings, flavor, ctx, hiddenInfoCount);
	}
	console.log(output);

	const failOn = options['failOn'] as string | undefined;
	if (failOn) {
		const upper = failOn.toUpperCase() as Finding['severity'];
		if (shouldFail(findings, upper)) process.exit(1);
	}
}

cli
	.command('analyze', 'Run full audit of suspicious regexes, collisions, and shadowing')
	.example('  kongcheck analyze --control-plane-id <id> --token $TOKEN')
	.example(
		'  kongcheck analyze --control-plane-id <id> --token $TOKEN --filter tag:team-a --filter service:payments-svc',
	)
	.action(async (options: Record<string, unknown>) => {
		const verbose = !!options['verbose'];
		const spinner = makeSpinner(verbose);
		spinner.start('Fetching config...');
		const fetched = await resolveConfig(options);
		spinner.updateText('Analysing routes...');
		const flavor = resolveFlavorOption(options, fetched);
		const allFindings = analyzeRoutes(fetched, { flavor, includeInfo: true });
		const predicates = parseFilters(options['filter'] as string | string[] | undefined);
		const findings = applyFindingFilter(allFindings, predicates, fetched.services);
		const showInfo = !!options['showInfo'];
		const visibleFindings = showInfo ? findings : findings.filter((f) => f.severity !== 'INFO');
		const hiddenInfoCount = findings.length - visibleFindings.length;
		spinner.stop();
		outputAndMaybeExit(visibleFindings, flavor, options, resolveKonnectContext(fetched), hiddenInfoCount);
	});

cli
	.command('collisions', 'Show only routes that overlap or shadow each other (no suspicious-regex findings)')
	.example('  kongcheck collisions --control-plane-id <id> --token $TOKEN --format json')
	.example('  kongcheck collisions --control-plane-id <id> --token $TOKEN --filter path:/payments')
	.action(async (options: Record<string, unknown>) => {
		const verbose = !!options['verbose'];
		const spinner = makeSpinner(verbose);
		spinner.start('Fetching config...');
		const fetched = await resolveConfig(options);
		spinner.updateText('Analysing routes...');
		const flavor = resolveFlavorOption(options, fetched);
		const all = analyzeRoutes(fetched, { flavor, includeInfo: true });
		const collisionFindings = all.filter((f) => f.type === 'shadowing' || f.type === 'collision');
		const predicates = parseFilters(options['filter'] as string | string[] | undefined);
		const findings = applyFindingFilter(collisionFindings, predicates, fetched.services);
		const showInfo = !!options['showInfo'];
		const visibleFindings = showInfo ? findings : findings.filter((f) => f.severity !== 'INFO');
		const hiddenInfoCount = findings.length - visibleFindings.length;
		spinner.stop();
		outputAndMaybeExit(visibleFindings, flavor, options, resolveKonnectContext(fetched), hiddenInfoCount);
	});

cli
	.command('explain-request', 'Simulate a specific request and show which route wins and why')
	.option('--method <method>', 'HTTP method, e.g. GET', { default: 'GET' })
	.option('--host <host>', 'Host header, e.g. api.example.com', {
		default: 'example.com',
	})
	.option('--path <path>', 'Request path, e.g. /payments-v2/docs')
	.option('--header <header>', 'Request header as key:value (repeat for multiple), e.g. --header x-env:dev')
	.example(
		'  kongcheck explain-request --control-plane-id <id> --token $TOKEN ' +
			'--method GET --host example.com --path /payments-v2/docs',
	)
	.action(async (options: Record<string, unknown>) => {
		const reqPath = options['path'] as string | undefined;
		if (!reqPath) {
			console.error('Error: --path is required for explain-request.');
			process.exit(1);
		}

		const verbose = !!options['verbose'];
		const spinner = makeSpinner(verbose);
		spinner.start('Fetching config...');
		const fetched = await resolveConfig(options);
		spinner.stop();
		const flavor = resolveFlavorOption(options, fetched);

		// Split multi-path routes into one marshalled route per path, matching
		// Kong's own behaviour before sort_routes is applied.
		const marshalled: ReturnType<typeof marshalRoute>[] = [];
		for (const r of fetched.routes) {
			const svc = r.service?.id ? fetched.services.get(r.service.id) : undefined;
			const paths = r.paths ?? [];
			if (paths.length <= 1) {
				marshalled.push(marshalRoute(r, svc, flavor));
			} else {
				for (const path of paths) {
					marshalled.push(marshalRoute({ ...r, paths: [path] } as typeof r, svc, flavor));
				}
			}
		}
		const sorted = [...marshalled].sort(compareRoutes);

		// Parse --header key:value flags into a headers map.
		// cac collects repeated options as an array; a single use is a string.
		const rawHeaders = options['header'];
		const reqHeaders: Record<string, string> = {};
		const headerList: string[] = rawHeaders
			? Array.isArray(rawHeaders)
				? (rawHeaders as string[])
				: [rawHeaders as string]
			: [];
		for (const h of headerList) {
			const colonIdx = h.indexOf(':');
			if (colonIdx < 1) {
				console.error(`Error: --header value must be key:value, got '${h}'`);
				process.exit(1);
			}
			const key = h.slice(0, colonIdx).trim().toLowerCase();
			const val = h.slice(colonIdx + 1).trim();
			reqHeaders[key] = val;
		}

		const result = simulateRequest(sorted, {
			method: (options['method'] as string) ?? 'GET',
			host: (options['host'] as string) ?? 'example.com',
			path: reqPath,
			// Pass headers map so header-constrained routes are evaluated strictly.
			// An empty object means "no headers" (routes requiring headers won't match).
			headers: reqHeaders,
		});

		const format = (options['format'] as string | undefined) ?? 'human';
		const ctx = resolveKonnectContext(fetched);
		const headerSummary =
			Object.keys(reqHeaders).length > 0
				? '  headers: ' +
					Object.entries(reqHeaders)
						.map(([k, v]) => `${k}=${v}`)
						.join(', ')
				: '';
		if (format === 'json') {
			const jsonResult = {
				...result,
				winner: result.winner
					? {
							...result.winner,
							_konnectUrl: konnectRouteUrl(result.winner.route.id, ctx),
						}
					: null,
				matchedRoutes: result.matchedRoutes.map((mr) => ({
					...mr,
					_konnectUrl: konnectRouteUrl(mr.route.id, ctx),
				})),
			};
			console.log(JSON.stringify(jsonResult, null, 2));
		} else {
			if (!result.winner) {
				console.log(`No route matched: ${result.request.method} ${result.request.path}`);
				if (headerSummary) console.log(headerSummary);
			} else {
				const name = result.winner.route.name ?? result.winner.route.id;
				const winnerUrl = konnectRouteUrl(result.winner.route.id, ctx);
				console.log(
					`\nWinning route: ${name}  (id: ${result.winner.route.id})` +
						(winnerUrl ? `\n               ${winnerUrl}` : ''),
				);
				if (headerSummary) console.log('\nSimulated with' + headerSummary);
				console.log(`\nExplanation:`);
				for (const line of result.explanation) {
					console.log(`  ${line}`);
				}
				if (result.matchedRoutes.length > 1) {
					console.log(`\n${result.matchedRoutes.length - 1} other route(s) also matched:`);
					for (const mr of result.matchedRoutes.slice(1)) {
						const n = mr.route.name ?? mr.route.id;
						const url = konnectRouteUrl(mr.route.id, ctx);
						console.log(`  - ${n}  paths: ${mr.route.paths?.join(', ')}` + (url ? `\n    ${url}` : ''));
					}
				}
			}
		}
	});

cli
	.command(
		'dump-config [output-file]',
		'Fetch and save route/service config to JSON. Writes to stdout when no file is given (or when "-" is passed).',
	)
	.example('  kongcheck dump-config --control-plane-id <id> --token $TOKEN')
	.example('  kongcheck dump-config - --control-plane-id <id> --token $TOKEN | kongcheck analyze --file -')
	.example('  kongcheck dump-config routes-dump.json --control-plane-id <id> --token $TOKEN')
	.action(async (outputFile: string | undefined, options: Record<string, unknown>) => {
		const verbose = !!options['verbose'];
		const spinner = makeSpinner(verbose);
		spinner.start('Fetching config...');
		const konnectConfig = resolveKonnectConfig(options);
		const fetched = await fetchKonnectConfig(konnectConfig, { verbose });
		spinner.stop();

		const dump = {
			routerFlavor: fetched.routerFlavor,
			routes: fetched.routes,
			services: Array.from(fetched.services.values()),
		};

		const json = JSON.stringify(dump, null, 2);

		if (!outputFile || outputFile === '-') {
			console.log(json);
			if (process.stdout.isTTY) {
				console.log(formatDumpSummary(fetched));
			}
		} else {
			await Bun.write(outputFile, json);
			console.log(`Config saved to ${outputFile}. ${formatDumpSummary(fetched)}`);
		}
	});

cli
	.command('mcp', 'Start the kongcheck MCP server (stdio transport) for use with AI agents')
	.option(
		'--cache-ttl <seconds>',
		'Seconds to cache fetched Konnect config per control-plane within a session. 0 disables caching. (default: 60)',
	)
	.example('  # Typically invoked by the MCP host, not manually')
	.example('  kongcheck mcp')
	.example('  kongcheck mcp --cache-ttl 120   # cache for 2 minutes')
	.example('  kongcheck mcp --cache-ttl 0     # disable caching')
	.action(async (options: Record<string, unknown>) => {
		const rawTtl = options['cacheTtl'];
		const cacheTtlMs = rawTtl !== undefined ? Number(rawTtl) * 1000 : 60_000;
		if (isNaN(cacheTtlMs) || cacheTtlMs < 0) {
			console.error('Error: --cache-ttl must be a non-negative number of seconds.');
			process.exit(1);
		}
		await startMcpServer(cacheTtlMs);
	});

cli.addEventListener('command:*', () => {
	console.error('Error: Invalid command: %s', cli.args.join(' '));
	process.exit(1);
});

try {
	cli.parse();
} catch (err) {
	const msg = err instanceof Error ? err.message : String(err);
	console.error(`Error: ${msg}`);
	cli.outputHelp();
	process.exit(1);
}
