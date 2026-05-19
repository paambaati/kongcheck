/**
 * Output formatters for analysis findings.
 *
 * Three formats are supported –
 * - **human** – coloured terminal output, indented, easy to read at a glance.
 * - **json**  – machine-readable JSON suitable for piping or CI ingestion.
 * - **csv**   – spreadsheet-friendly CSV, one row per route involved in a finding.
 *
 * Both formats expose the same information; only the presentation differs.
 */

import relativeDate from 'tiny-relative-date';

import type { Finding, KonnectData, RouterFlavor } from './types.ts';

/**
 * Konnect-specific context used to generate UI deep-links.
 * Absent in offline / `--file` mode.
 */
export interface KonnectContext {
	/** UUID of the control plane being audited. */
	controlPlaneId: string;
	/** Konnect region code, e.g. `"us"`. */
	region: string;
}

/**
 * Returns a clickable Konnect UI URL for a route, or `undefined` when
 * context is not available (offline / `--file` mode).
 *
 * URL pattern: https://cloud.konghq.com/{region}/gateway-manager/{cpId}/routes/{routeId}
 */
export function konnectRouteUrl(routeId: string, ctx: KonnectContext | undefined): string | undefined {
	if (!ctx) return undefined;
	return `https://cloud.konghq.com/${ctx.region}/gateway-manager/${ctx.controlPlaneId}/routes/${routeId}`;
}

const isTTY = process.stdout.isTTY;

/**
 * Returns the ANSI escape sequence for the given CSS color name, using
 * `Bun.color` to auto-detect terminal color depth (24-bit / 256 / 16 / none).
 * Returns an empty string when the terminal doesn't support ANSI colors.
 *
 * @see https://bun.sh/docs/runtime/color
 */
function ansiColor(name: string): string {
	return Bun.color(name, 'ansi') ?? '';
}

/** ANSI reset sequence – clears both color and style attributes. */
const RESET = '\x1b[0m';

/**
 * Wraps a string in an ANSI foreground color using `Bun.color`.
 * Falls back to the plain string when color output is not supported.
 */
function withColor(name: string, s: string): string {
	if (!isTTY) return s;
	const esc = ansiColor(name);
	return esc ? `${esc}${s}${RESET}` : s;
}

const colour = {
	// Text attributes – Bun.color only handles colors, not styles.
	// We use raw ANSI codes here, gated on the same condition as Bun.color
	// (i.e. whether the terminal actually supports ANSI sequences).
	bold: (s: string) => (isTTY ? `\x1b[1m${s}${RESET}` : s),
	dim: (s: string) => (isTTY ? `\x1b[2m${s}${RESET}` : s),
	// Colors via Bun.color – depth-aware, no isTTY guard needed.
	red: (s: string) => withColor('red', s),
	yellow: (s: string) => withColor('yellow', s),
	cyan: (s: string) => withColor('cyan', s),
	green: (s: string) => withColor('green', s),
	gray: (s: string) => withColor('#808080', s),
};

/** Maps severity levels to terminal colour functions. */
function severityColor(severity: Finding['severity']): (s: string) => string {
	switch (severity) {
		case 'HIGH':
			return colour.red;
		case 'MEDIUM':
			return colour.yellow;
		case 'LOW':
			return colour.cyan;
		case 'INFO':
			return colour.gray;
	}
}

/**
 * Formats a list of findings as a human-readable terminal report.
 *
 * Output structure for each finding –
 * ```
 * ──────────────────────────────────────────
 * [HIGH] potential_shadowing  (traditional)
 *
 *   Route: epp  (id: 111)  paths: ~/epp/*  regex_priority: 0
 *   Route: epp-poc  (id: 222)  paths: ~/epp-poc/*  regex_priority: 0
 *
 *   Sample requests: /epp-poc, /epp-poc/docs
 *   Winning route:   epp (id: 111)
 *
 *   Why:
 *     - Both routes match ...
 *
 *   Suggestions:
 *     - ~/epp(?:/.*)?$
 * ```
 *
 * @param findings     - Findings to format, typically already sorted by severity.
 * @param routerFlavor - The flavor under which analysis was performed.
 */
export function formatHuman(
	findings: Finding[],
	routerFlavor: RouterFlavor,
	ctx?: KonnectContext,
	hiddenInfoCount = 0,
): string {
	const timestamp = new Date().toISOString();
	const headerLines: string[] = [];
	if (ctx) {
		const cpUrl = `https://cloud.konghq.com/${ctx.region}/gateway-manager/${ctx.controlPlaneId}`;
		headerLines.push(colour.bold('Control plane:') + `  ${ctx.controlPlaneId}`);
		headerLines.push(colour.bold('Konnect link: ') + `  ${cpUrl}`);
		headerLines.push(colour.bold('Analysed at:  ') + `  ${timestamp}`);
		headerLines.push('');
	}

	if (findings.length === 0) {
		return headerLines.join('\n') + colour.green('✓ No route findings. Your routing configuration looks clean.\n');
	}

	const lines: string[] = [...headerLines];
	lines.push(
		colour.bold(`Kong Route Audit – ${findings.length} finding(s)`) +
			colour.dim(`  router_flavor: ${routerFlavor}`) +
			'\n',
	);

	for (const f of findings) {
		const color = severityColor(f.severity);
		lines.push(colour.dim('─'.repeat(60)));
		lines.push(color(colour.bold(`[${f.severity}]`)) + `  ${f.type}` + colour.dim(`  (${f.routerFlavor})`));
		lines.push('');

		// Route summary table.
		for (const [idx, route] of f.routes.entries()) {
			const tag =
				f.type === 'universal_matcher'
					? colour.gray('catch-all')
					: idx === 0
						? colour.bold('winner  ')
						: colour.dim('shadowed');
			const paths = (route.paths ?? []).join(', ') || colour.dim('(no paths)');
			const rp = route.regex_priority ?? 0;
			const name = route.name ?? colour.dim('(unnamed)');
			const createdDate = new Date(route.created_at! * 1000);
			const uiUrl = konnectRouteUrl(route.id, ctx);
			lines.push(
				`  ${tag}  ${colour.bold(name)}` +
					colour.dim(`  id: ${route.id}`) +
					`\n          paths: ${paths}` +
					`  regex_priority: ${rp}` +
					(route.created_at
						? `  created: ${createdDate.toISOString()} ${colour.dim('(' + relativeDate(createdDate) + ')')}`
						: '') +
					(uiUrl ? `\n          ${colour.dim(uiUrl)}` : ''),
			);
		}

		lines.push('');

		// Sample requests.
		if (f.samples.length > 0) {
			lines.push(`  Sample requests: ${f.samples.map((s) => colour.cyan(s)).join(', ')}`);
		}
		if (f.winnerId) {
			const winnerRoute = f.routes.find((r) => r.id === f.winnerId);
			const winnerName = winnerRoute?.name ?? f.winnerId;
			lines.push(`  Winning route:   ${colour.bold(winnerName)}  ${colour.dim(`(id: ${f.winnerId})`)}`);
		}

		// Reason chain.
		if (f.reason.length > 0) {
			lines.push('');
			lines.push('  Why:');
			for (const r of f.reason) {
				lines.push(`    ${colour.dim('–')} ${r}`);
			}
		}

		// Suggestions.
		if (f.suggestions.length > 0) {
			lines.push('');
			lines.push('  Suggested fixes:');
			for (const s of f.suggestions) {
				lines.push(`    ${colour.green('→')} ${colour.bold(s)}`);
			}
		}

		lines.push('');
	}

	// Summary footer.
	const counts = countBySeverity(findings);
	const totalInfo = counts.INFO + hiddenInfoCount;
	lines.push(
		colour.bold('Summary:') +
			`  HIGH: ${colour.red(String(counts.HIGH))}` +
			`  MEDIUM: ${colour.yellow(String(counts.MEDIUM))}` +
			`  LOW: ${colour.cyan(String(counts.LOW))}` +
			`  INFO: ${colour.gray(String(totalInfo))}`,
	);
	if (hiddenInfoCount > 0) {
		lines.push(colour.dim(`(${hiddenInfoCount} INFO finding(s) not shown – rerun with --show-info to expand)`));
	}

	return lines.join('\n') + '\n';
}

/**
 * Shape of the JSON output produced by {@link formatJSON}.
 */
export interface JSONReport {
	/** ISO 8601 timestamp of when the report was generated. */
	generatedAt: string;
	/** The router flavor used for analysis. */
	routerFlavor: RouterFlavor;
	/** Total number of findings. */
	totalFindings: number;
	/** Finding counts per severity level. */
	summary: Record<Finding['severity'], number>;
	/** The full list of findings. */
	findings: Finding[];
}

/**
 * Formats a list of findings as a JSON report string.
 *
 * The output is a single JSON object conforming to {@link JSONReport}.
 * Sorted by severity (HIGH first).
 *
 * @param findings     - Findings to include in the report.
 * @param routerFlavor - The flavor under which analysis was performed.
 * @param pretty       - When `true` (default), the JSON is pretty-printed with
 *                       2-space indentation.
 */
export function formatJSON(
	findings: Finding[],
	routerFlavor: RouterFlavor,
	ctx?: KonnectContext,
	pretty = true,
): string {
	const findingsWithLinks = ctx
		? findings.map((f) => ({
				...f,
				routes: f.routes.map((r) => ({
					...r,
					_konnectUrl: konnectRouteUrl(r.id, ctx),
				})),
			}))
		: findings;
	const report: JSONReport = {
		generatedAt: new Date().toISOString(),
		routerFlavor,
		totalFindings: findings.length,
		summary: countBySeverity(findings),
		findings: findingsWithLinks,
	};
	return JSON.stringify(report, null, pretty ? 2 : 0);
}

/**
 * Counts findings by severity level.
 *
 * @param findings - The findings to count.
 */
function countBySeverity(findings: Finding[]): Record<Finding['severity'], number> {
	return {
		HIGH: findings.filter((f) => f.severity === 'HIGH').length,
		MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
		LOW: findings.filter((f) => f.severity === 'LOW').length,
		INFO: findings.filter((f) => f.severity === 'INFO').length,
	};
}

/**
 * Returns the highest severity present in a list of findings, or `undefined`
 * if the list is empty. Used by the CLI to determine the exit code.
 *
 * @param findings - The findings to inspect.
 */
export function highestSeverity(findings: Finding[]): Finding['severity'] | undefined {
	const order: Finding['severity'][] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];
	for (const s of order) {
		if (findings.some((f) => f.severity === s)) return s;
	}
	return undefined;
}

/**
 * Returns `true` when the findings contain at least one finding at or above
 * the specified severity threshold.
 *
 * @param findings  - The findings to inspect.
 * @param threshold - The minimum severity to trigger a `true` return.
 */
export function shouldFail(findings: Finding[], threshold: Finding['severity']): boolean {
	const order: Finding['severity'][] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];
	const thresholdIdx = order.indexOf(threshold);
	return findings.some((f) => order.indexOf(f.severity) <= thresholdIdx);
}

/**
 * Formats a brief one-line summary for use after the `dump-config` command.
 *
 * @param fetched - The config that was fetched and saved.
 */
export function formatDumpSummary(fetched: KonnectData): string {
	return (
		`Dumped ${fetched.routes.length} route(s) and ` +
		`${fetched.services.size} service(s) on control plane ID ${fetched.controlPlaneId}.` +
		(fetched.routerFlavor
			? ` Detected router flavor: ${fetched.routerFlavor}.`
			: " Router flavor: unknown (defaulting to 'traditional' for analysis).")
	);
}

/**
 * Escapes a single CSV field value.
 * Wraps the value in double-quotes and escapes any embedded double-quotes
 * by doubling them, per RFC 4180.
 */
function csvField(value: string): string {
	return `"${value.replace(/"/g, '""')}"`;
}

/**
 * Formats a list of findings as a CSV string.
 *
 * One row is emitted per route involved in a finding, so a shadowing finding
 * with two routes produces two rows sharing the same finding-level columns.
 * This makes it easy to load into a spreadsheet or query with `cut`/`awk`.
 *
 * Columns:
 *   severity, type, router_flavor, route_role, route_id, route_name,
 *   route_paths, route_regex_priority, route_created_at,
 *   winner_id, samples, reason, suggestions, konnect_url
 */
export function formatCSV(findings: Finding[], _routerFlavor: RouterFlavor, ctx?: KonnectContext): string {
	const HEADER = [
		'severity',
		'type',
		'router_flavor',
		'route_role',
		'route_id',
		'route_name',
		'route_paths',
		'route_regex_priority',
		'route_created_at',
		'winner_id',
		'samples',
		'reason',
		'suggestions',
		'konnect_url',
	];

	const rows: string[] = [HEADER.join(',')];

	for (const f of findings) {
		const samples = f.samples.join(' | ');
		const reason = f.reason.join(' | ');
		const suggestions = f.suggestions.join(' | ');

		for (const [idx, route] of f.routes.entries()) {
			// role: for shadowing/collision idx 0 = winner, rest = shadowed.
			// For other types every route is labelled 'route'.
			let role: string;
			if (f.type === 'shadowing' || f.type === 'collision') {
				role = idx === 0 ? 'winner' : 'shadowed';
			} else {
				role = 'route';
			}

			const paths = (route.paths ?? []).join(' | ');
			const createdAt = route.created_at ? new Date(route.created_at * 1000).toISOString() : '';
			const url = konnectRouteUrl(route.id, ctx) ?? '';

			rows.push(
				[
					csvField(f.severity),
					csvField(f.type),
					csvField(f.routerFlavor),
					csvField(role),
					csvField(route.id),
					csvField(route.name ?? ''),
					csvField(paths),
					csvField(String(route.regex_priority ?? 0)),
					csvField(createdAt),
					csvField(f.winnerId ?? ''),
					csvField(samples),
					csvField(reason),
					csvField(suggestions),
					csvField(url),
				].join(','),
			);
		}
	}

	return rows.join('\n');
}
