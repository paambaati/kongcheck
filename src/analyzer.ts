/**
 * Kong Route Analyzer
 *
 * Performs static risk analysis over a set of marshalled routes and produces
 * human-meaningful {@link Finding} objects.
 *
 * The analyzer covers three categories:
 *
 * 1. **Suspicious regex paths** – regex paths that use `*` as if it were a
 *    glob wildcard. In PCRE, `*` is a quantifier on the *previous* token, not
 *    "anything". Users frequently write `~/payments/*` expecting it to mean
 *    "anything under /payments/", but it actually means "/payments" followed by zero or
 *    more slashes – which can match unintended sibling paths.
 *
 * 2. **Shadowing / collision** – two or more routes match overlapping request
 *    paths. The analyzer generates candidate request paths derived from the
 *    routes' own path patterns and simulates each one to find collisions.
 *
 * 3. **Sibling namespace overlaps** – plain prefix or regex routes whose path
 *    prefixes share a common stem (e.g. `/payments` and `/payments-v2`) where one
 *    could be shadowed by the other.
 *
 * @see src/router.ts – compareRoutes, simulateRequest
 */

import { compareRoutes, ipPortListsOverlap, marshalRoute, matchPath, simulateRequest } from './router.ts';
import type { Finding, KonnectData, MarshalledRoute, RouterFlavor, Severity, SimRequest } from './types.ts';

/**
 * Patterns that indicate the user likely intended glob-style wildcards but
 * wrote PCRE instead. Each entry is a human-readable description of the
 * problem.
 *
 * Based on the motivating example in the problem statement: `~/payments/*` where
 * `*` is used as a glob but has PCRE quantifier semantics (zero or more of
 * the previous character).
 */
const SUSPICIOUS_REGEX_PATTERNS: Array<{
	/** RegExp tested against the raw path string (without leading `~`). */
	test: RegExp;
	/** Human-readable description of the issue. */
	description: string;
	/** Suggested fix template. `{path}` is replaced with the cleaned path stem. */
	suggestion: (raw: string) => string;
	/**
	 * Optional severity override. Defaults to `'MEDIUM'`.
	 * Use `'HIGH'` for patterns that introduce ReDoS risk or are otherwise
	 * especially dangerous.
	 */
	severity?: Severity;
}> = [
	{
		// ~/foo/* or ~/foo/bar/* — trailing `/*` is almost always a glob mistake.
		test: /\/\*$/,
		description:
			"`*` at end of path is a PCRE quantifier (zero or more of the preceding char '/'), " +
			"not a glob wildcard. It does NOT mean 'anything after this prefix'.",
		suggestion: (raw: string) => {
			// Remove leading ~, strip trailing /*, suggest anchored form.
			const stem = raw.slice(1).replace(/\/\*$/, '');
			return `~${stem}(?:/.*)?$`;
		},
	},
	{
		// ~/foo/* in the middle, e.g. ~/foo/*/bar
		test: /\/\*\//,
		description:
			"`/*/` in a regex path uses `*` as a PCRE quantifier on '/', which matches zero or more " +
			"slashes – not 'any path segment'. Consider using `/[^/]+/` for a single dynamic segment.",
		suggestion: (raw: string) => raw.replace(/\/\*\//g, '/[^/]+/'),
	},
	{
		// ~/foo* (no slash before *) – * quantifies the previous letter, e.g. 'o'
		test: /[a-zA-Z0-9]\*$/,
		description:
			'Trailing `*` after a word character quantifies that character (zero or more occurrences), ' +
			'not the whole path segment. E.g. `~/payments*` matches `/payment`, `/payments`, `/paymentss`, etc., ' +
			'but NOT `/payments/anything`.',
		suggestion: (raw: string) => {
			const stem = raw.slice(1).replace(/[a-zA-Z0-9]\*$/, (m) => m[0]!);
			return `~${stem}(?:/.*)?$`;
		},
	},
	{
		// ~/?$ or ~/? or ~/ — optional-slash patterns that are universal matchers in
		// traditional flavor. Without a leading ^ anchor (which traditional flavor does
		// NOT add), `/?$` matches the END of any string, making it a catch-all for every
		// path. Authors usually intend this to match only the root path `/`; they should
		// use the plain path `/` (no `~`) or the anchored form `~^/$`.
		//
		// The test is applied to the raw path string (including the leading `~`), so we
		// anchor after `~` with `^~`.
		test: /^~\/?\??\$?$/,
		description:
			'This regex path is an unintentional universal matcher in `traditional` flavor. ' +
			'`/?$` (and similar patterns) match the *end* of every URL because the `traditional` ' +
			'router does not add a `^` start anchor. In `traditional_compatible` flavor this would ' +
			'correctly match only the root path `/`. ' +
			'Use the plain path `/` (no `~`) for a catch-all, or `~^/$` (anchored) to match only root.',
		suggestion: (_raw: string) => '/',
	},
	{
		// Nested quantifier: (group)[+*] — patterns like (a+)* or (/segment+)+
		// are a classic source of catastrophic backtracking (ReDoS). Kong uses PCRE under the
		// hood; on certain input strings these patterns can cause exponential match time and
		// stall the Kong worker.
		//
		// Only the outer quantifiers `+` and `*` cause exponential backtracking.
		// An outer `?` (zero-or-one) is NOT dangerous and must NOT be flagged — e.g.
		// `(?:/.*)? ` is a common, safe optional-path suffix that should be allowed.
		//
		// Pattern: a capturing or non-capturing group that contains a quantifier (+, *, ?, {)
		// and is itself followed by `+` or `*` (not `?`). Examples:
		//   ~/api(/v[0-9]+)*$  →  (/v[0-9]+)* is a nested quantifier (ReDoS risk)
		//   ~/paths(/[^/]+)+   →  (/[^/]+)+   is a nested quantifier (ReDoS risk)
		//   ~/payments(?:/.*)?$ →  (?:/.*)?  outer ? → safe, NOT flagged
		test: /\([^)]*[+*?{][^)]*\)[+*]/,
		description:
			'Nested quantifier detected: a group containing a quantifier (`+`, `*`, `?`, `{`) is ' +
			'itself followed by `+` or `*`. This is a classic ReDoS (Regular Expression Denial of ' +
			'Service) pattern. On crafted input strings, PCRE can take exponential time to evaluate ' +
			'this match, stalling Kong workers.',
		suggestion: (raw: string) =>
			raw + ' (simplify: remove the inner quantifier or rewrite as a flat repetition, e.g. `(/[^/]+)+` → `(/[^/]*)+`)',
		severity: 'HIGH',
	},
];

/**
 * Three deliberately unrelated probe paths used to detect "universal matcher"
 * routes – routes whose paths match every possible request.
 *
 * A route is a universal matcher when ALL probe paths are matched by at least
 * one of its path patterns. Such routes are intentional catch-alls (e.g. a
 * SPA frontend served from `/`) and should not generate collision findings
 * when they appear as the *loser* in a pair – being shadowed by every more-
 * specific route is expected and correct behaviour.
 */
const UNIVERSAL_PROBE_PATHS = ['/api-probe-a/test', '/static-probe-b/app.js', '/zz-probe-c/deep/nested/path'] as const;

/**
 * Returns `true` when the route matches ALL universal probe paths, indicating
 * that it is an intentional catch-all rather than a misconfigured route.
 *
 * Plain path `/` is always a universal matcher (every request starts with `/`).
 * Regex paths that match everything (e.g. `~/?$` in traditional flavor) are
 * detected via probe testing.
 *
 * @param mr - The marshalled route to test.
 */
function isUniversalMatcher(mr: MarshalledRoute): boolean {
	return UNIVERSAL_PROBE_PATHS.every((probe) => mr.parsedPaths.some((p) => matchPath(p, probe)));
}

/**
 * Inspects a single regex path string for known suspicious patterns.
 *
 * @param raw - The raw path string (must start with `~`).
 * @returns An array of issue description strings. Empty if the path looks safe.
 */
export function detectSuspiciousRegexIssues(raw: string): string[] {
	if (!raw.startsWith('~')) return [];
	const issues: string[] = [];
	for (const { test, description } of SUSPICIOUS_REGEX_PATTERNS) {
		if (test.test(raw)) issues.push(description);
	}
	return issues;
}

/**
 * Returns a safer suggested replacement for a suspicious regex path, or
 * `undefined` if no specific suggestion is available.
 *
 * @param raw - The raw path string (must start with `~`).
 */
export function suggestRegexFix(raw: string): string | undefined {
	if (!raw.startsWith('~')) return undefined;
	for (const { test, suggestion } of SUSPICIOUS_REGEX_PATTERNS) {
		if (test.test(raw)) return suggestion(raw);
	}
	return undefined;
}

/**
 * Generates a diverse set of candidate request paths derived from the routes'
 * own path patterns.
 *
 * The goal is to produce paths that are likely to trigger collisions between
 * sibling routes –
 *  - The base path itself (e.g. `/payments-v2/docs`)
 *  - A child path (e.g. `/payments-v2/docs/sub`)
 *  - A sibling path (e.g. `/payments-docs`)
 *  - Slash/no-slash variants
 *  - The parent path (e.g. `/payments-v2`)
 *
 * @param routes - All marshalled routes; their path patterns are used as seeds.
 * @returns Deduplicated list of candidate {@link SimRequest} objects.
 */
export function generateCandidateRequests(routes: MarshalledRoute[]): SimRequest[] {
	const pathSet = new Set<string>();

	for (const mr of routes) {
		for (const p of mr.parsedPaths) {
			let base: string;

			if (p.kind === 'regex') {
				// Strip leading ~ and simplify regex metacharacters to a plain path.
				base = (p.regexSource ?? '')
					.replace(/\{[^}]+\}/g, 'id') // {variable} template placeholders → id
					.replace(/\([^)]+\)/g, 'id') // (capture groups) → id placeholder
					.replace(/\(\?P?<[^>]+>/g, '') // strip named group openers (remaining unclosed)
					.replace(/\(\?:/g, '') // strip non-capturing group openers
					.replace(/[()]/g, '') // strip remaining parens
					.replace(/\?/g, '') // strip optional quantifiers
					.replace(/\.\*/g, 'test') // .* → "test"
					.replace(/\*/g, '') // remaining * → remove
					.replace(/\+/g, '') // + → remove
					.replace(/\$$/, '') // strip end anchor
					.replace(/\^/, ''); // strip start anchor
				// Ensure leading slash.
				if (!base.startsWith('/')) base = '/' + base;
			} else {
				base = p.prefix ?? '/';
			}

			// Normalise double slashes.
			base = base.replace(/\/+/g, '/');

			pathSet.add(base);
			// Trailing slash variant.
			if (!base.endsWith('/')) pathSet.add(base + '/');
			// Child path.
			pathSet.add(base.replace(/\/$/, '') + '/extra');
			// Parent path.
			const parent = base.replace(/\/$/, '').replace(/\/[^/]+$/, '');
			if (parent) pathSet.add(parent);
		}
	}

	return Array.from(pathSet).map((path) => ({
		method: 'GET',
		host: 'example.com',
		path,
	}));
}

/**
 * Options for the route analyzer.
 */
export interface AnalyzeOptions {
	/**
	 * Router flavor to use for analysis.
	 * Defaults to the flavor detected from the control plane config, or
	 * `"traditional"` if not detectable.
	 */
	flavor?: RouterFlavor;
	/**
	 * When `true`, include `INFO`-level findings: header-stratified route-pair
	 * notices and universal catch-all route annotations.
	 * `suspicious_regex` (MEDIUM/HIGH) and collision/shadowing findings are
	 * always returned regardless of this flag.
	 * Defaults to `true`.
	 */
	includeInfo?: boolean;
}

/**
 * Analyses a set of routes fetched from Konnect and returns all findings.
 *
 * The analysis proceeds in three passes:
 * 1. **Suspicious regex linting** – each regex path is scanned for known
 *    anti-patterns (glob-style `*` usage).
 * 2. **Collision simulation** – candidate requests are generated from the
 *    routes' path patterns and each is simulated to find multi-match
 *    collisions.
 * 3. **Sibling namespace detection** – route pairs whose path prefixes share a
 *    common stem are flagged as potential shadows even if candidate generation
 *    didn't produce a specific colliding request.
 *
 * @param fetched - The normalised config fetched from Konnect (or loaded
 *                  from a local dump).
 * @param options - Analysis options.
 * @returns All findings, sorted by severity (HIGH first).
 *
 * @example
 * const findings = analyzeRoutes(fetchedConfig, { flavor: "traditional" });
 * for (const f of findings) {
 *   console.log(`[${f.severity}] ${f.type}: ${f.reason[0]}`);
 * }
 */
export function analyzeRoutes(fetched: KonnectData, options: AnalyzeOptions = {}): Finding[] {
	const flavor = options.flavor ?? fetched.routerFlavor ?? 'traditional';
	const includeInfo = options.includeInfo ?? true;

	// Marshal routes, splitting multi-path routes into one MarshalledRoute per
	// path – mirroring Kong's own behaviour in `_M.new` (~L1430-L1449):
	//   "split routes by paths to sort properly"
	// After sorting, we deduplicate by route ID for display purposes (findings
	// still reference the original KongRoute with all its paths).
	const marshalledRoutes: MarshalledRoute[] = [];
	for (const r of fetched.routes) {
		const svc = r.service?.id ? fetched.services.get(r.service.id) : undefined;
		const paths = r.paths ?? [];
		if (paths.length <= 1) {
			marshalledRoutes.push(marshalRoute(r, svc, flavor));
		} else {
			// One marshalled route per path; the route object is shared but each
			// gets its own single-path slice so max_uri_length scores correctly.
			for (const path of paths) {
				const singlePathRoute = { ...r, paths: [path] };
				marshalledRoutes.push(marshalRoute(singlePathRoute as typeof r, svc, flavor));
			}
		}
	}

	// Sort once – highest priority first.
	const sorted = [...marshalledRoutes].sort(compareRoutes);

	// Stamp isUniversal on each route once, before the analysis passes.
	// This avoids calling isUniversalMatcher() (3× UNIVERSAL_PROBE_PATHS simulations)
	// once per pair in detectCollisions/detectSiblingOverlaps (which are O(n²)).
	for (const mr of sorted) {
		mr.isUniversal = isUniversalMatcher(mr);
	}

	const findings: Finding[] = [];

	// Pass 1: suspicious regex linting (always runs; emits MEDIUM/HIGH findings
	// regardless of includeInfo – only INFO-severity passes are gated below).
	findings.push(...lintSuspiciousRegex(sorted, flavor));

	// Pass 2: collision simulation.
	findings.push(...detectCollisions(sorted, flavor, includeInfo));

	// Pass 3: sibling namespace detection (catches pairs not hit by simulation).
	findings.push(...detectSiblingOverlaps(sorted, flavor, findings, includeInfo));

	// Pass 4: universal-matcher annotation (INFO). Skip routes already flagged
	// by suspicious_regex to avoid double-reporting an accidental catch-all.
	const suspiciousIds = new Set(
		findings.filter((f) => f.type === 'suspicious_regex').flatMap((f) => f.routes.map((r) => r.id)),
	);
	findings.push(...lintUniversalMatchers(sorted, flavor, suspiciousIds, includeInfo));

	// Sort findings: HIGH > MEDIUM > LOW > INFO.
	const severityOrder: Record<Severity, number> = {
		HIGH: 0,
		MEDIUM: 1,
		LOW: 2,
		INFO: 3,
	};
	findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

	return findings;
}

/**
 * Annotates universal-matcher routes with INFO-level findings.
 *
 * A universal matcher is a route whose path(s) collectively match every
 * request URL (e.g. a plain prefix `/`, or a regex that compiles to match
 * anything). These routes are already excluded from collision/shadowing
 * reporting to prevent noise; this pass surfaces them explicitly so users
 * auditing their routing config know they exist.
 *
 * Routes that already have a `suspicious_regex` finding (accidental catch-alls
 * like `~/?$`) are skipped here – they are reported at a higher severity
 * and do not need a second finding.
 *
 * @param routes      - All marshalled routes, sorted by priority.
 * @param flavor      - The active router flavor.
 * @param skipIds     - Route IDs that already have a suspicious_regex finding.
 * @param includeInfo - When `false`, returns an empty array immediately.
 */
function lintUniversalMatchers(
	routes: MarshalledRoute[],
	flavor: RouterFlavor,
	skipIds: Set<string>,
	includeInfo: boolean,
): Finding[] {
	if (!includeInfo) return [];
	const findings: Finding[] = [];

	for (const mr of routes) {
		if (skipIds.has(mr.route.id)) continue;
		if (!mr.isUniversal) continue;

		const paths = (mr.route.paths ?? []).join(', ') || '(no paths)';
		findings.push({
			severity: 'INFO',
			type: 'universal_matcher',
			routerFlavor: flavor,
			routes: [mr.route],
			samples: [],
			reason: [
				`Route "${mr.route.name ?? mr.route.id}" is a universal catch-all – it matches every request URL.`,
				`Paths: ${paths}`,
				'This route is intentionally excluded from collision and shadowing findings to avoid noise.',
				'Common examples: a SPA frontend served from plain prefix `/`, or a default upstream.',
				'If this catch-all is unexpected, review its path configuration.',
			],
			suggestions: [],
		});
	}

	return findings;
}

/**
 * Scans every regex path in the route set for suspicious patterns and emits
 * `suspicious_regex` findings.
 */
function lintSuspiciousRegex(routes: MarshalledRoute[], flavor: RouterFlavor): Finding[] {
	const findings: Finding[] = [];

	for (const mr of routes) {
		// Probe-based catch: emit a suspicious_regex finding for any regex route
		// that compiles to a universal matcher (matches every probe path) but was
		// not already caught by the pattern-list above. This catches patterns like
		// `~.*` or `~.*$` that we haven't explicitly enumerated.
		if (mr.isUniversal && mr.parsedPaths.some((p) => p.kind === 'regex')) {
			const alreadyCaught = mr.parsedPaths.some(
				(p) => p.kind === 'regex' && detectSuspiciousRegexIssues(p.raw).length > 0,
			);
			if (!alreadyCaught) {
				const universalPaths = mr.parsedPaths.filter((p) => p.kind === 'regex').map((p) => p.raw);
				findings.push({
					severity: 'HIGH',
					type: 'suspicious_regex',
					routerFlavor: flavor,
					routes: [mr.route],
					samples: [],
					reason: [
						`Route "${mr.route.name ?? mr.route.id}" has a regex path that matches every request URL ` +
							`in \`${flavor}\` flavor – it is an accidental universal catch-all.`,
						`Paths: ${universalPaths.join(', ')}`,
						'In `traditional` flavor the router does not add a `^` start anchor, so patterns ' +
							'like `~.*` or `~/.*` match any position in the URL string, not just the start.',
						'This route will be shadowed by every more-specific route and silently handle ' +
							'traffic intended for routes that are unavailable or misconfigured.',
					],
					suggestions: universalPaths.map(
						(p) => p.replace(/^~/, '~/') + ' (review intent; likely should be a plain path prefix)',
					),
				});
			}
		}

		for (const p of mr.parsedPaths) {
			if (p.kind !== 'regex') continue;
			const issues = detectSuspiciousRegexIssues(p.raw);
			if (issues.length === 0) continue;

			const fix = suggestRegexFix(p.raw);
			// Use the highest severity among all matching patterns (default MEDIUM).
			let pSeverity: Severity = 'MEDIUM';
			for (const { test, severity } of SUSPICIOUS_REGEX_PATTERNS) {
				if (test.test(p.raw) && severity === 'HIGH') {
					pSeverity = 'HIGH';
					break;
				}
			}
			findings.push({
				severity: pSeverity,
				type: 'suspicious_regex',
				routerFlavor: flavor,
				routes: [mr.route],
				samples: [],
				reason: [
					`Path "${p.raw}" uses regex syntax in a way that is likely unintentional:`,
					...issues,
					`Under ${flavor} flavor, this path is compiled as: ${p.regexSource}`,
					'The `~` prefix means this is a PCRE regex path, not a glob pattern.',
				],
				suggestions: fix ? [fix] : [],
			});
		}
	}

	return findings;
}

/**
 * Returns `true` when the loser route is a proper path-segment ancestor of the
 * winner route — i.e. every loser plain-prefix path ends at a `/` boundary
 * inside every winner plain-prefix path.
 *
 * Example: loser=/chat, winner=/chat/history → `/chat/history`.startsWith(`/chat/`) → true.
 * Example: loser=/payments, winner=/payments-v2 → `/payments-v2`.startsWith(`/payments/`) → false.
 *
 * This identifies legitimate parent→child routing hierarchies that are handled
 * correctly and deterministically by Kong's max_uri_length tie-breaker. Only
 * applies when both routes have exclusively plain-prefix paths.
 */
function isHierarchicalChild(winner: MarshalledRoute, loser: MarshalledRoute): boolean {
	const loserPrefixes = loser.parsedPaths.filter((p) => p.kind === 'prefix').map((p) => p.prefix!);
	const winnerPrefixes = winner.parsedPaths.filter((p) => p.kind === 'prefix').map((p) => p.prefix!);
	// Only applies when both routes are exclusively plain-prefix (no regex paths).
	if (loserPrefixes.length === 0 || winnerPrefixes.length === 0) return false;
	if (loserPrefixes.length !== loser.parsedPaths.length) return false;
	if (winnerPrefixes.length !== winner.parsedPaths.length) return false;
	// Every loser prefix must be a proper path-segment ancestor of every winner prefix.
	// Strip any trailing '/' from the loser prefix before appending '/' to avoid double-slash
	// when the loser path itself ends with '/' (e.g. /ava-live-agent-api/).
	return loserPrefixes.every((lp) => winnerPrefixes.every((wp) => wp.startsWith(lp.replace(/\/$/, '') + '/')));
}

/**
 * Generates candidate requests, simulates each against the route set, and
 * emits findings for any request that is matched by more than one route.
 */
function detectCollisions(sorted: MarshalledRoute[], flavor: RouterFlavor, includeInfo: boolean): Finding[] {
	const candidates = generateCandidateRequests(sorted);
	// Deduplicate findings by route-pair key to avoid repeating the same pair
	// for many similar requests.
	const seenPairs = new Set<string>();
	// O(1) lookup map for augmenting existing findings with additional sample paths.
	const findingByPair = new Map<string, Finding>();
	const findings: Finding[] = [];

	for (const req of candidates) {
		const result = simulateRequest(sorted, req);
		if (result.matchedRoutes.length < 2) continue;

		const winner = result.winner!;
		const losers = result.matchedRoutes.slice(1);

		for (const loser of losers) {
			// Skip: loser is a universal-match (intentional catch-all like path `/`
			// or regex `~/?$`). Being shadowed by every more-specific route is the
			// expected behaviour for a catch-all; flagging it generates O(n) noise.
			if (loser.isUniversal) continue;

			// Skip: loser is a proper path-segment ancestor of the winner
			// (e.g. /chat vs /chat/history). Kong's max_uri_length tie-breaker
			// resolves this deterministically; flagging it is a false positive.
			if (isHierarchicalChild(winner, loser)) continue;

			// Skip: winner and loser are the same route (multi-path route split into multiple
			// MarshalledRoutes that share the same route ID). One path can be a prefix/subset
			// of another path on the same route — this is not a collision, it's intentional.
			if (winner.route.id === loser.route.id) continue;

			// Skip: winner has {variable} template placeholders in its regex path. In PCRE,
			// {id} is a literal match for the string "{id}", not a wildcard. No real HTTP
			// request sends "{var}" unencoded in a URL path, so these routes effectively never
			// match real traffic and cannot shadow anything.
			if (winner.parsedPaths.some((p) => p.kind === 'regex' && /\{[^}]+\}/.test(p.regexSource ?? ''))) continue;

			const pairKey = [winner.route.id, loser.route.id].sort().join('|');
			if (seenPairs.has(pairKey)) {
				// Already have a finding for this pair; add this sample to it.
				const existing = findingByPair.get(pairKey);
				if (existing && !existing.samples.includes(req.path)) {
					existing.samples.push(req.path);
				}
				continue;
			}
			seenPairs.add(pairKey);

			// L4 stratification: SNI/source IP/dest IP/protocol-disjoint pairs.
			// If two routes can never receive the same connection because they differ
			// on a network-layer attribute, emit an INFO notice and skip the collision
			// finding. Checked before haveIdenticalPaths so it applies to all path
			// configurations, not just identical-path pairs.
			const sniIpStrat = isSniIpStratified(winner, loser);
			if (sniIpStrat !== false) {
				if (includeInfo) {
					const f = buildSniIpStratifiedFinding(winner, loser, req.path, flavor, sniIpStrat.reason);
					findings.push(f);
					findingByPair.set(pairKey, f);
				}
				continue;
			}

			// INFO/MEDIUM: identical-path, header-stratified pair.
			// 'stratified' → Kong partitions traffic correctly; emit INFO notice.
			// 'regex-opaque' → cannot determine disjointness statically; emit MEDIUM
			if (haveIdenticalPaths(winner, loser)) {
				const stratification = isHeaderStratified(winner, loser);
				if (stratification === 'stratified') {
					if (includeInfo) {
						const f = buildHeaderStratifiedFinding(winner, loser, req.path, flavor);
						findings.push(f);
						findingByPair.set(pairKey, f);
					}
					continue;
				}
				if (stratification === 'regex-opaque') {
					const f = buildRegexHeaderOpaqueFinding(winner, loser, req.path, flavor);
					findings.push(f);
					findingByPair.set(pairKey, f);
					continue;
				}
			}

			const severity = classifyCollisionSeverity(winner, loser);
			const reason = buildCollisionReason(winner, loser, req.path, flavor, result.explanation);
			const suggestions = buildCollisionSuggestions(winner, loser);

			const f: Finding = {
				severity,
				type: isShadowing(winner, loser) ? 'shadowing' : 'collision',
				routerFlavor: flavor,
				routes: [winner.route, loser.route],
				samples: [req.path],
				winnerId: winner.route.id,
				reason,
				suggestions,
			};
			findings.push(f);
			findingByPair.set(pairKey, f);
		}
	}

	return findings;
}
/**
 * Determines whether the relationship between a winning and a losing route
 * constitutes "shadowing" (winner can capture requests clearly intended for
 * loser) vs a general "collision" (both routes overlap but neither obviously
 * subsumes the other).
 */
function isShadowing(winner: MarshalledRoute, loser: MarshalledRoute): boolean {
	// If the winner has a broad regex that can match all of the loser's paths,
	// it is shadowing the loser.
	for (const winnerPath of winner.parsedPaths) {
		if (winnerPath.kind !== 'regex') continue;
		for (const loserPath of loser.parsedPaths) {
			// The loser's path pattern, when used as a sample, matches the winner.
			const loserSample = loserPath.prefix ?? loserPath.regexSource ?? '';
			if (loserSample && matchPath(winnerPath, loserSample)) return true;
		}
	}
	return false;
}

/**
 * Returns true when the two routes have exactly the same set of path strings
 * (order-independent). Used to detect duplicate routes and header-gated env
 * routing pairs.
 *
 * Uses the pre-computed `pathFingerprint` field from `marshalRoute` for O(1)
 * comparison (avoids sorting + joining on every O(n²) call).
 */
function haveIdenticalPaths(a: MarshalledRoute, b: MarshalledRoute): boolean {
	return a.pathFingerprint === b.pathFingerprint;
}

/**
 * Inspects a header constraint value list to determine whether it contains any
 * `~*`-prefixed regex values.
 *
 * Kong header values starting with `~*` are PCRE patterns. Static analysis
 * cannot determine whether two arbitrary regex patterns are disjoint — that
 * would require regular-language intersection testing (PCRE product automaton).
 * When a `~*` value is present we therefore cannot safely classify the pair as
 * fully stratified or as a genuine collision.
 */
function hasRegexHeaderValue(values: string[]): boolean {
	return values.some((v) => v.startsWith('~*'));
}

/**
 * Classifies the header-constraint relationship between two routes.
 *
 * Returns:
 * - `'stratified'`    – winner's headers partition traffic; loser handles the
 *                        remainder. No misrouting.
 * - `'regex-opaque'`  – one or more header values use `~*` PCRE patterns; static
 *                        analysis cannot determine disjointness. The finding is
 *                        downgraded to MEDIUM to signal the uncertainty.
 * - `false`           – the constraints overlap (or the winner has no constraints);
 *                        a genuine collision may exist.
 *
 * Only meaningful when the two routes share identical paths (see callers).
 *
 * Kong source (header matching, `header_pattern` construction) –
 *   https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L400-L412
 */
function isHeaderStratified(winner: MarshalledRoute, loser: MarshalledRoute): 'stratified' | 'regex-opaque' | false {
	const winHeaders = winner.route.headers;
	if (!winHeaders || Object.keys(winHeaders).length === 0) return false;

	const loseHeaders = loser.route.headers ?? {};

	// Track whether we encounter any ~* regex values while scanning.
	// We complete the full scan before returning regex-opaque so that a
	// definitively stratified dimension (no constraint on the loser side)
	// takes precedence — stratified is more informative than regex-opaque.
	let foundRegexHeader = false;

	for (const [headerName, winValues] of Object.entries(winHeaders)) {
		// Find the matching key in the loser's constraints (case-insensitive).
		const loseKey = Object.keys(loseHeaders).find((k) => k.toLowerCase() === headerName.toLowerCase());
		const loseValues = loseKey ? loseHeaders[loseKey] : undefined;

		if (!loseValues) {
			// Loser has no constraint on this header — requests without the header
			// go exclusively to the loser. Fully stratified on this dimension.
			return 'stratified';
		}

		// Both constrain the same header.
		// Check for ~* regex values on either side — static disjointness cannot
		// be determined; flag as opaque and continue scanning.
		if (hasRegexHeaderValue(winValues) || hasRegexHeaderValue(loseValues)) {
			foundRegexHeader = true;
			continue; // might still find a definitively stratified dimension
		}

		// Check whether their allowed values are disjoint.
		const winSet = new Set(winValues.map((v) => v.toLowerCase()));
		const hasOverlap = loseValues.some((v) => winSet.has(v.toLowerCase()));
		if (!hasOverlap) return 'stratified'; // non-overlapping plain values → stratified
	}

	if (foundRegexHeader) return 'regex-opaque';
	return false;
}

/**
 * HTTP-family protocols handled by Kong's HTTP subsystem.
 * Routes whose `protocols` set is entirely within this family cannot receive
 * TCP/TLS/UDP stream connections.
 *
 * Kong source: `traditional.lua` – `SORTED_MATCH_RULES` (is_http branch)
 *   https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L194-L200
 */
const HTTP_PROTOCOLS = new Set(['http', 'https', 'grpc', 'grpcs']);

/**
 * Stream-family protocols handled by Kong's stream subsystem.
 * Routes whose `protocols` set is entirely within this family cannot receive
 * HTTP connections.
 *
 * Kong source: `traditional.lua` – `SORTED_MATCH_RULES` (stream branch)
 *   https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua#L201-L206
 */
const STREAM_PROTOCOLS = new Set(['tcp', 'tls', 'udp', 'tls_passthrough']);

/**
 * Returns `true` when the two protocol lists are mutually exclusive — one list
 * is entirely HTTP-family and the other is entirely stream-family. In that
 * case Kong would never route the same connection to both routes.
 *
 * @param a - `protocols` array from route A.
 * @param b - `protocols` array from route B.
 */
function protocolsAreDisjoint(a: string[], b: string[]): boolean {
	const aLower = a.map((p) => p.toLowerCase());
	const bLower = b.map((p) => p.toLowerCase());
	const aIsHttp = aLower.every((p) => HTTP_PROTOCOLS.has(p));
	const bIsStream = bLower.every((p) => STREAM_PROTOCOLS.has(p));
	if (aIsHttp && bIsStream) return true;
	const bIsHttp = bLower.every((p) => HTTP_PROTOCOLS.has(p));
	const aIsStream = aLower.every((p) => STREAM_PROTOCOLS.has(p));
	return bIsHttp && aIsStream;
}

/**
 * Result type returned by {@link isSniIpStratified}: either a stratified
 * finding with a human-readable reason, or `false` (not stratified on any
 * L4 dimension).
 */
type SniIpStratification = { stratified: true; reason: string } | false;

/**
 * Checks whether two routes are mutually exclusive on any L4 dimension —
 * protocol family, SNI, source IP/port, or destination IP/port.
 *
 * Returns a {@link SniIpStratification} with a human-readable reason when the
 * routes are stratified; returns `false` when no L4 stratification can be
 * determined statically.
 *
 * Dimension checks (in order):
 * 1. **Protocol family** — one route is all-HTTP, the other all-stream.
 * 2. **SNI** — both routes have non-empty `snis` sets and the sets are
 *    completely disjoint (no shared SNI value).
 * 3. **Source IP/port** — both routes have non-empty `sources` lists and
 *    {@link ipPortListsOverlap} returns `false`.
 * 4. **Destination IP/port** — both routes have non-empty `destinations`
 *    lists and {@link ipPortListsOverlap} returns `false`.
 *
 * **Conservative by design**: when a constraint list is absent on one route
 * (meaning "match anything"), that dimension is NOT flagged as stratified —
 * the absent constraint side could receive any connection and would potentially
 * overlap with the other route.
 *
 * Kong sources:
 * - SNI normalisation (trailing-dot strip): traditional.lua#L511-L513
 * - MATCH_RULES.SNI: traditional.lua#L1072-L1077
 * - matcher_src_dst: traditional.lua#L880-L900
 */
function isSniIpStratified(a: MarshalledRoute, b: MarshalledRoute): SniIpStratification {
	// 1. Protocol-family disjointness.
	const aProtos = a.route.protocols;
	const bProtos = b.route.protocols;
	if (aProtos && aProtos.length > 0 && bProtos && bProtos.length > 0) {
		if (protocolsAreDisjoint(aProtos, bProtos)) {
			return {
				stratified: true,
				reason: `routes use mutually exclusive protocol families (${aProtos.join(', ')} vs ${bProtos.join(', ')})`,
			};
		}
	}

	// 2. SNI disjointness.
	// Both routes must have a non-empty snis list; otherwise the absent side is
	// a wildcard (matches all SNIs) and cannot be disjoint from any other set.
	// Kong strips trailing dots from FQDNs before indexing (traditional.lua#L511-L513).
	const aSnis = a.route.snis;
	const bSnis = b.route.snis;
	if (aSnis && aSnis.length > 0 && bSnis && bSnis.length > 0) {
		const aNorm = new Set(aSnis.map((s) => (s.endsWith('.') ? s.slice(0, -1) : s)));
		const bNorm = new Set(bSnis.map((s) => (s.endsWith('.') ? s.slice(0, -1) : s)));
		const hasOverlap = [...aNorm].some((s) => bNorm.has(s));
		if (!hasOverlap) {
			return {
				stratified: true,
				reason: `routes have disjoint SNI sets ([${[...aNorm].join(', ')}] vs [${[...bNorm].join(', ')}])`,
			};
		}
	}

	// 3. Source IP/port disjointness.
	const aSrcs = a.route.sources;
	const bSrcs = b.route.sources;
	if (aSrcs && aSrcs.length > 0 && bSrcs && bSrcs.length > 0) {
		if (!ipPortListsOverlap(aSrcs, bSrcs)) {
			return {
				stratified: true,
				reason: 'routes have non-overlapping source IP/port constraints',
			};
		}
	}

	// 4. Destination IP/port disjointness.
	const aDsts = a.route.destinations;
	const bDsts = b.route.destinations;
	if (aDsts && aDsts.length > 0 && bDsts && bDsts.length > 0) {
		if (!ipPortListsOverlap(aDsts, bDsts)) {
			return {
				stratified: true,
				reason: 'routes have non-overlapping destination IP/port constraints',
			};
		}
	}

	return false;
}

/**
 * Builds an INFO-level finding for a route pair that is correctly stratified
 * by L4 constraints (SNI, source/destination IP/port, or protocol family).
 *
 * The finding explains which L4 attribute distinguishes the two routes and
 * confirms that no misrouting occurs.
 */
function buildSniIpStratifiedFinding(
	winner: MarshalledRoute,
	loser: MarshalledRoute,
	samplePath: string,
	flavor: RouterFlavor,
	reason: string,
): Finding {
	const winName = winner.route.name ?? winner.route.id;
	const loseName = loser.route.name ?? loser.route.id;
	const paths = (winner.route.paths ?? []).join(', ') || samplePath;

	return {
		severity: 'INFO',
		type: 'collision',
		routerFlavor: flavor,
		routes: [winner.route, loser.route],
		samples: [samplePath],
		winnerId: winner.route.id,
		reason: [
			`Routes "${winName}" and "${loseName}" share overlapping path(s) but are correctly stratified by L4 constraints.`,
			`Path(s): ${paths}`,
			`Stratification: ${reason}.`,
			'Kong routes each connection to the correct route based on L4 attributes. No misrouting occurs.',
			'Confirm this L4 stratification is intentional.',
		],
		suggestions: [],
	};
}

/**
 * Builds an INFO-level finding for a route pair that is correctly stratified
 * by a header constraint.
 *
 * The finding documents exactly which header value to send with
 * `kongcheck explain-request` to confirm that Kong routes each request to the
 * intended service, so the operator can verify the pattern is intentional.
 */
function buildHeaderStratifiedFinding(
	winner: MarshalledRoute,
	loser: MarshalledRoute,
	samplePath: string,
	flavor: RouterFlavor,
): Finding {
	const winName = winner.route.name ?? winner.route.id;
	const loseName = loser.route.name ?? loser.route.id;
	const winHeaders = winner.route.headers ?? {};

	const headerDesc = Object.entries(winHeaders)
		.map(([k, vs]) => `${k}: [${vs.join(', ')}]`)
		.join('; ');

	// Build --header flags using the first value of each required header so
	// the operator can copy-paste a ready-to-run command.
	const headerFlags = Object.entries(winHeaders)
		.map(([k, vs]) => `--header ${k}:${vs[0]!}`)
		.join(' ');

	const paths = (winner.route.paths ?? []).join(', ') || samplePath;

	return {
		severity: 'INFO',
		type: 'collision',
		routerFlavor: flavor,
		routes: [winner.route, loser.route],
		samples: [samplePath],
		winnerId: winner.route.id,
		reason: [
			`Routes "${winName}" and "${loseName}" share identical path(s) and are correctly stratified by header.`,
			`Path(s): ${paths}`,
			`"${winName}" requires: ${headerDesc}`,
			`"${loseName}" has no matching constraint — it handles all requests that lack the required header.`,
			'Kong routes to the header-constrained route when the header is present; all other requests reach the unconstrained route.',
			'No misrouting occurs. Confirm this header stratification is intentional.',
		],
		suggestions: [
			`kongcheck explain-request GET ${samplePath} ${headerFlags}  →  should route to "${winName}"`,
			`kongcheck explain-request GET ${samplePath}  →  should route to "${loseName}" (no header required)`,
		],
	};
}

/**
 * Builds a MEDIUM-level finding for a route pair where header constraints use
 * `~*`-prefixed regex values, making static stratification analysis impossible.
 *
 * Kong can match these headers correctly at runtime, but we cannot determine
 * at static-analysis time whether the patterns are disjoint (that would require
 * PCRE intersection testing). We conservatively emit MEDIUM with an explanatory
 * note so the operator knows to verify the routing manually.
 */
function buildRegexHeaderOpaqueFinding(
	winner: MarshalledRoute,
	loser: MarshalledRoute,
	samplePath: string,
	flavor: RouterFlavor,
): Finding {
	const winName = winner.route.name ?? winner.route.id;
	const loseName = loser.route.name ?? loser.route.id;

	// Collect all ~* values from both routes for display.
	const regexValues: string[] = [];
	for (const values of Object.values(winner.route.headers ?? {})) {
		regexValues.push(...values.filter((v) => v.startsWith('~*')));
	}
	for (const values of Object.values(loser.route.headers ?? {})) {
		regexValues.push(...values.filter((v) => v.startsWith('~*')));
	}

	const winSvc = winner.service?.id ?? winner.route.service?.id;
	const loseSvc = loser.service?.id ?? loser.route.service?.id;
	const crossService = winSvc && loseSvc && winSvc !== loseSvc;

	return {
		severity: 'MEDIUM',
		type: 'collision',
		routerFlavor: flavor,
		routes: [winner.route, loser.route],
		samples: [samplePath],
		winnerId: winner.route.id,
		reason: [
			`Routes "${winName}" and "${loseName}" share identical path(s) and both use ` +
				'`~*`-prefixed regex header values.',
			`Regex header values detected: ${regexValues.join(', ')}`,
			'Static analysis cannot determine whether these regex patterns are disjoint — ' +
				'PCRE intersection testing is required to be certain.',
			crossService
				? `⚠  Routes target DIFFERENT services. If the regex patterns overlap, ` +
					`requests could be misrouted between "${winName}" (${winSvc}) and "${loseName}" (${loseSvc}).`
				: 'Both routes target the same service; misrouting risk is lower but the overlap should be verified.',
			'Use `kongcheck explain-request` with representative header values to confirm correct routing.',
		],
		suggestions: [
			`Verify manually that the ~* header patterns are truly disjoint for all real traffic values.`,
			`kongcheck explain-request GET ${samplePath}  →  observe which route wins for each header value`,
		],
	};
}

/**
 * Classifies the severity of a collision finding.
 *
 * - `HIGH`:   Different services; misrouting traffic to the wrong backend.
 * - `MEDIUM`: Same service, ambiguous overlap (no clear intentional pattern).
 * - `LOW`:    Intentional routing pattern within the same service — no misrouting
 *             occurs in practice. Two sub-cases:
 *             1. Explicit `regex_priority` override: the operator deliberately
 *                set a higher value on the winner.
 *             2. More-specific route correctly overrides a same-service catch-all
 *                (winner's `maxUriLength` > loser's).
 *
 * Note: identical-path, header-stratified pairs (different services) are
 * intercepted by the caller before reaching this function and emitted as INFO.
 */
function classifyCollisionSeverity(winner: MarshalledRoute, loser: MarshalledRoute): Severity {
	const winSvc = winner.service?.id ?? winner.route.service?.id;
	const loseSvc = loser.service?.id ?? loser.route.service?.id;

	if (winSvc && loseSvc && winSvc !== loseSvc) {
		return 'HIGH';
	}

	// Same service below.

	// LOW: explicit regex_priority override. The operator deliberately assigned a
	// higher priority to the winner as an intentional routing refinement.
	const winRp = winner.route.regex_priority ?? 0;
	const loseRp = loser.route.regex_priority ?? 0;
	if (winRp > loseRp) return 'LOW';

	// LOW: more-specific route correctly overrides a same-service catch-all.
	// The winner has a longer path pattern (max_uri_length tie-breaker), meaning
	// it is a more-specific refinement route intentionally overriding the broader
	// catch-all within the same service.
	// For regex paths (max_uri_length is always 0 in Kong), we compare the
	// regex source length as a specificity proxy.
	if (winner.maxUriLength > loser.maxUriLength) return 'LOW';

	const winSpecificity = maxRegexSpecificity(winner);
	const loseSpecificity = maxRegexSpecificity(loser);
	if (winSpecificity > loseSpecificity) return 'LOW';

	return 'MEDIUM';

	/**
	 * Returns the maximum regex source length across all parsed paths for a route.
	 * Used as a specificity proxy for regex routes (max_uri_length is always 0 for
	 * regex paths in Kong, so we fall back to the pattern string length).
	 */
	function maxRegexSpecificity(mr: MarshalledRoute): number {
		return mr.parsedPaths.reduce((max, p) => {
			if (p.kind === 'regex' && p.regexSource) {
				return Math.max(max, p.regexSource.length);
			}
			return max;
		}, 0);
	}
}

/**
 * Builds the human-readable reason chain for a collision finding.
 *
 * @param precomputedExplanation - Optional explanation lines already produced
 *   by the `simulateRequest` call in the caller. When provided, re-simulation
 *   is skipped; falls back to a fresh simulation only when absent.
 */
function buildCollisionReason(
	winner: MarshalledRoute,
	loser: MarshalledRoute,
	samplePath: string,
	flavor: RouterFlavor,
	precomputedExplanation?: string[],
): string[] {
	const winName = winner.route.name ?? winner.route.id;
	const loseName = loser.route.name ?? loser.route.id;
	const lines: string[] = [];

	// Describe what each route looks like.
	for (const [label, mr] of [
		['winner', winner],
		['shadowed', loser],
	] as const) {
		const paths = mr.route.paths?.join(', ') ?? '(no paths)';
		const rp = mr.route.regex_priority ?? 0;
		const ca = mr.route.created_at ? new Date(mr.route.created_at * 1000).toISOString() : 'unknown';
		lines.push(
			`Route "${label === 'winner' ? winName : loseName}" (${label}): paths=[${paths}], ` +
				`regex_priority=${rp}, created_at=${ca}`,
		);
	}

	lines.push(`Both routes match sample request path "${samplePath}".`);

	// Explain the path semantics of the winner if it has suspicious regex paths.
	for (const p of winner.parsedPaths) {
		if (p.kind === 'regex') {
			const issues = detectSuspiciousRegexIssues(p.raw);
			if (issues.length > 0) {
				lines.push(
					`Winner path "${p.raw}" is a regex path (compiled as: ${p.regexSource}) ` +
						`under ${flavor} flavor – not a glob.`,
				);
				lines.push(...issues);
			}
		}
	}

	if (precomputedExplanation && precomputedExplanation.length > 0) {
		lines.push(...precomputedExplanation);
	} else {
		const result = simulateRequest([winner, loser], {
			method: 'GET',
			host: 'example.com',
			path: samplePath,
		});
		lines.push(...result.explanation);
	}

	return lines;
}

/**
 * Builds suggested safer replacement path patterns for the routes in a
 * collision finding.
 *
 * When both routes share identical path strings the regex suggestion would be
 * the same for both — emitting it twice is confusing. We deduplicate and
 * append an explanatory note so the reader understands the root cause is a
 * duplicate route, not just a regex issue.
 */
function buildCollisionSuggestions(winner: MarshalledRoute, loser: MarshalledRoute): string[] {
	const raw: string[] = [];
	for (const mr of [winner, loser]) {
		for (const p of mr.parsedPaths) {
			const fix = suggestRegexFix(p.raw);
			if (fix) raw.push(fix);
		}
	}
	// Deduplicate — identical paths produce identical fixes; showing the same
	// suggestion twice misleads the reader into thinking there are two separate
	// things to fix.
	const unique = [...new Set(raw)];

	// When both routes have exactly the same path(s), the path regex is not the
	// root cause — the duplicate route itself is. Add an actionable note.
	if (haveIdenticalPaths(winner, loser)) {
		unique.push(
			'These routes have identical paths — delete the shadowed route, ' +
				'or differentiate using hosts / methods / headers constraints',
		);
	}

	return unique;
}

/**
 * Detects route pairs whose path prefixes share a common stem but where
 * simulation (pass 2) may not have generated a covering request.
 *
 * Classic example: `/payments` and `/payments-v2` — a route matching the prefix `/payments`
 * will also match requests to `/payments-v2/...`.
 *
 * Only emits findings for pairs not already covered by the collision pass.
 */
function detectSiblingOverlaps(
	routes: MarshalledRoute[],
	flavor: RouterFlavor,
	existingFindings: Finding[],
	includeInfo: boolean,
): Finding[] {
	const findings: Finding[] = [];
	const coveredPairs = new Set<string>(
		existingFindings.flatMap((f) =>
			f.routes.length >= 2 ? [[f.routes[0]!.id, f.routes[1]!.id].sort().join('|')] : [],
		),
	);

	for (let i = 0; i < routes.length; i++) {
		for (let j = i + 1; j < routes.length; j++) {
			const a = routes[i]!;
			const b = routes[j]!;

			// Skip pairs where either route is a universal matcher (catch-all).
			// A catch-all overlaps with every route by definition; flagging all
			// those pairs would produce O(n) noise with no actionable insight.
			if (a.isUniversal || b.isUniversal) continue;

			// Skip: same-route pair (multi-path route split into multiple MarshalledRoutes).
			if (a.route.id === b.route.id) continue;

			const pairKey = [a.route.id, b.route.id].sort().join('|');
			if (coveredPairs.has(pairKey)) continue;

			const overlap = findSiblingOverlapSample(a, b);
			if (!overlap) continue;

			coveredPairs.add(pairKey);

			// Determine winner by sort order.
			const [winner, loser] = compareRoutes(a, b) <= 0 ? [a, b] : [b, a];

			// Skip: winner has {variable} template placeholders (PCRE literals, not wildcards).
			if (winner.parsedPaths.some((p) => p.kind === 'regex' && /\{[^}]+\}/.test(p.regexSource ?? ''))) continue;

			// L4 stratification: SNI/source IP/dest IP/protocol-disjoint pairs.
			// Same logic as in detectCollisions — checked before haveIdenticalPaths.
			const sniIpStrat = isSniIpStratified(winner, loser);
			if (sniIpStrat !== false) {
				if (includeInfo) findings.push(buildSniIpStratifiedFinding(winner, loser, overlap, flavor, sniIpStrat.reason));
				continue;
			}

			// INFO/MEDIUM: identical-path, header-stratified pair. Same logic as detectCollisions.
			if (haveIdenticalPaths(winner, loser)) {
				const stratification = isHeaderStratified(winner, loser);
				if (stratification === 'stratified') {
					if (includeInfo) findings.push(buildHeaderStratifiedFinding(winner, loser, overlap, flavor));
					continue;
				}
				if (stratification === 'regex-opaque') {
					findings.push(buildRegexHeaderOpaqueFinding(winner, loser, overlap, flavor));
					coveredPairs.add(pairKey);
					continue;
				}
			}

			const severity = classifyCollisionSeverity(winner, loser);
			const suggestions = buildCollisionSuggestions(winner, loser);

			findings.push({
				severity,
				type: 'shadowing',
				routerFlavor: flavor,
				routes: [winner.route, loser.route],
				samples: [overlap],
				winnerId: winner.route.id,
				reason: [
					`Route "${winner.route.name ?? winner.route.id}" has a path that can match requests ` +
						`intended for "${loser.route.name ?? loser.route.id}".`,
					`Sample request "${overlap}" matches both routes.`,
					`This is a sibling namespace overlap: the path prefixes/patterns share a common stem.`,
				],
				suggestions,
			});
		}
	}

	return findings;
}

/**
 * For two routes, tries to find a path that would be matched by both.
 *
 * Specifically, checks whether any path pattern of route `a` can match a
 * canonical sample path derived from route `b`'s path patterns, and vice
 * versa.
 *
 * @returns A sample path string if an overlap is found, or `undefined`.
 */
function findSiblingOverlapSample(a: MarshalledRoute, b: MarshalledRoute): string | undefined {
	// Try b's paths as candidates for a's patterns.
	for (const bPath of b.parsedPaths) {
		const sample =
			bPath.prefix ??
			bPath.regexSource
				?.replace(/\{[^}]+\}/g, 'id')
				?.replace(/\([^)]+\)/g, 'id')
				?.replace(/[^/a-zA-Z0-9-]/g, '') ??
			'';
		if (!sample) continue;
		for (const ap of a.parsedPaths) {
			if (!matchPath(ap, sample)) continue;
			// Determine where the match ends on the sample string.
			const matchEnd = ap.kind === 'prefix' ? (ap.prefix?.length ?? 0) : (ap.regex?.exec(sample)?.[0].length ?? 0);
			// Skip when the match is a clean path boundary:
			// - nextChar is '/' → the match ends right before a new segment.
			// - nextChar is undefined → the match consumed the full sample.
			// - the last char consumed by the match is '/' → the prefix itself
			//   ends with a trailing slash (e.g. /prefix/ vs /prefix/child).
			const nextChar = sample[matchEnd];
			const matchEndChar = matchEnd > 0 ? sample[matchEnd - 1] : undefined;
			if (nextChar === undefined || nextChar === '/' || matchEndChar === '/') continue;
			return sample;
		}
	}

	// Try a's paths as candidates for b's patterns.
	for (const aPath of a.parsedPaths) {
		const sample =
			aPath.prefix ??
			aPath.regexSource
				?.replace(/\{[^}]+\}/g, 'id')
				?.replace(/\([^)]+\)/g, 'id')
				?.replace(/[^/a-zA-Z0-9-]/g, '') ??
			'';
		if (!sample) continue;
		for (const bp of b.parsedPaths) {
			if (!matchPath(bp, sample)) continue;
			const matchEnd = bp.kind === 'prefix' ? (bp.prefix?.length ?? 0) : (bp.regex?.exec(sample)?.[0].length ?? 0);
			const nextChar = sample[matchEnd];
			const matchEndChar = matchEnd > 0 ? sample[matchEnd - 1] : undefined;
			if (nextChar === undefined || nextChar === '/' || matchEndChar === '/') continue;
			return sample;
		}
	}

	return undefined;
}
