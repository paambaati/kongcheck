/**
 * Konnect Control Planes Config API client.
 *
 * Fetches routes and services from a Kong Konnect control plane using the
 * Konnect Control Planes Config v2 API and paginates automatically.
 *
 * Authentication: Bearer token passed in the `Authorization` header.
 * Token types supported – Personal Access Token (PAT) and System Account
 * Access Token (SPAT).
 *
 * @see https://developer.konghq.com/api/konnect/control-planes-config/v2/
 */

import type { KongRoute, KongService, KonnectConfig, KonnectData, RouterFlavor } from './types.ts';

/** Maps short region codes to their Konnect API base URLs. */
export const REGION_MAP: Record<string, string> = {
	us: 'https://us.api.konghq.com',
	eu: 'https://eu.api.konghq.com',
	au: 'https://au.api.konghq.com',
	me: 'https://me.api.konghq.com',
	in: 'https://in.api.konghq.com',
	sg: 'https://sg.api.konghq.com',
} as const;

/**
 * UUID v4 pattern.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Maximum number of pages to fetch per resource type.
 * Guards against infinite pagination loops or unexpectedly large data sets.
 */
const MAX_PAGES = 200;

/**
 * Maximum number of times to retry a retryable API error (429 / 503) before
 * giving up.
 */
const MAX_RETRIES = 3;

/**
 * Error thrown when the Konnect API returns a non-2xx status code.
 *
 * Carries the numeric HTTP status so that the retry logic in `fetchPage` can
 * distinguish retryable errors (429 rate-limited, 503 service unavailable)
 * from fatal errors (401 unauthorised, 404 not found, etc.).
 *
 * Error messages have any embedded Bearer tokens redacted and are truncated to
 * 1024 characters to prevent large API response bodies (which may contain
 * sensitive routing config) from leaking into logs or being displayed to
 * end-users.
 */
export class KonnectApiError extends Error {
	constructor(
		message: string,
		public readonly status: number,
	) {
		super(message);
		this.name = 'KonnectApiError';
	}
}

/**
 * Shape of a single page returned by the Konnect list endpoints.
 *
 * The Konnect Control Planes Config v2 API returns pagination cursors at the
 * **top level** of the response object, not nested under a `meta` key.
 * Empirically confirmed: `{ data: [...], next: "<cursor>" | null, offset: "..." }`
 * @internal
 */
interface KonnectPage<T> {
	data: T[];
	/** Cursor URL for the next page; absent or null on the last page. */
	next?: string | null;
	/** Offset token (alternative pagination field; present but not used for cursoring). */
	offset?: string | null;
}

/**
 * Parses the `Retry-After` response header and returns the delay in
 * milliseconds.
 *
 * The header may contain either an integer number of seconds or an HTTP-date
 * string. Returns `undefined` when the header is absent or unparsable.
 *
 * @param header - Raw value of the `Retry-After` header, or `null` if absent.
 */
function parseRetryAfterMs(header: string | null): number | undefined {
	if (!header) return undefined;
	// Integer seconds (most common).
	const seconds = Number(header);
	if (isFinite(seconds) && seconds >= 0) return seconds * 1000;
	// HTTP-date string ("Mon, 01 Jan 2024 00:00:00 GMT").
	const epoch = Date.parse(header);
	if (!isNaN(epoch)) return Math.max(0, epoch - Date.now());
	return undefined;
}

/**
 * Fetches a single page from a Konnect list endpoint.
 *
 * Automatically retries on HTTP 429 (rate-limited) and 503 (service
 * unavailable), honouring the `Retry-After` response header when present and
 * falling back to exponential backoff otherwise. Non-retryable errors are
 * thrown immediately as {@link KonnectApiError}.
 *
 * Error bodies are redacted (Bearer tokens removed) and truncated to 1024
 * characters before being included in the error message.
 *
 * @param url     - Fully-qualified URL, including any query parameters.
 * @param token   - Bearer token.
 * @param signal  - Optional AbortSignal for request cancellation.
 * @returns The parsed JSON response.
 * @throws {@link KonnectApiError} If the HTTP response status is not 2xx.
 */
async function fetchPage<T>(url: string, token: string, signal?: AbortSignal): Promise<KonnectPage<T>> {
	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		const response = await fetch(url, {
			signal,
			headers: {
				Authorization: `Bearer ${token}`,
				Accept: 'application/json',
			},
		});

		if (response.ok) {
			return response.json() as Promise<KonnectPage<T>>;
		}

		// Sanitise the error body before surfacing it –
		// 1. Redact Bearer tokens that may appear in error reflections.
		// 2. Truncate to 1024 chars to prevent log-flooding.
		let body = await response.text().catch(() => '(unreadable body)');
		body = body.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
		if (body.length > 1024) body = body.slice(0, 1024) + '... (truncated)';

		const err = new KonnectApiError(
			`Konnect API error: ${response.status} ${response.statusText} – ${url}\n${body}`,
			response.status,
		);

		// Only retry on 429 (rate limited) and 503 (service unavailable);
		// throw all other errors immediately without burning retries.
		const isRetryable = response.status === 429 || response.status === 503;
		if (!isRetryable || attempt >= MAX_RETRIES) {
			throw err;
		}

		// Compute delay: honour Retry-After header; fall back to exponential backoff.
		// Exponential schedule: 1 s (attempt 0), 2 s (attempt 1), 4 s (attempt 2).
		const delayMs = parseRetryAfterMs(response.headers.get('Retry-After')) ?? 1000 * Math.pow(2, attempt);
		await Bun.sleep(delayMs);
	}

	// TypeScript requires an unreachable return — the loop always throws first.
	/* c8 ignore next */
	throw new Error('fetchPage: exhausted retries without resolving');
}

/** Options forwarded from {@link fetchKonnectConfig} into {@link fetchAll}. */
interface FetchAllOptions {
	pageSize?: number;
	verbose?: boolean;
	/** Human-readable label printed in verbose messages (e.g. `"routes"`). */
	label?: string;
}

/**
 * Query-parameter names that are safe to forward from a pagination cursor URL
 * to the next-page request. All other params returned by `page.next`
 * are discarded to prevent cursor-injection attacks.
 */
const ALLOWED_CURSOR_PARAMS = new Set(['offset', 'size']);

/**
 * Iterates all pages of a Konnect list endpoint and collects the full result
 * set.
 *
 * The Konnect API returns a `next` field containing a pre-built URL path for
 * the next page (e.g. `"/routes?offset=TOKEN&size=100"`). We resolve that path
 * against the API origin and forward only the `offset` and `size` query
 * parameters — discarding any unexpected params that could be injected via a
 * malicious cursor.
 *
 * Pagination is capped at {@link MAX_PAGES} pages per resource type to guard
 * against infinite loops or unexpectedly large data sets.
 */
async function fetchAll<T>(baseUrl: string, token: string, opts: FetchAllOptions = {}): Promise<T[]> {
	const { pageSize = 100, verbose = false, label = '' } = opts;
	const displayLabel = label || new URL(baseUrl).pathname.split('/').pop() || 'items';
	const items: T[] = [];

	// `nextPath` is the relative path+query for the next page, or null on the first request.
	let nextPath: string | null = null;
	let pageNum = 0;

	do {
		pageNum++;

		// Guard: stop if we exceed the page cap.
		if (pageNum > MAX_PAGES) {
			if (verbose) console.warn(`  [${displayLabel}] warning: reached MAX_PAGES=${MAX_PAGES} limit, stopping`);
			break;
		}

		// First page: build URL from baseUrl with ?size=N.
		// Subsequent pages: follow the `page.next` cursor but forward only
		// the whitelisted params (offset, size) to prevent cursor injection.
		let requestUrl: string;
		if (nextPath) {
			const u = new URL(baseUrl);
			const cursor = new URL(nextPath, 'https://x');
			u.search = '';
			for (const key of ALLOWED_CURSOR_PARAMS) {
				const val = cursor.searchParams.get(key);
				if (val !== null) u.searchParams.set(key, val);
			}
			requestUrl = u.toString();
		} else {
			const u = new URL(baseUrl);
			u.searchParams.set('size', String(pageSize));
			requestUrl = u.toString();
		}

		if (verbose) {
			console.log(`  [${displayLabel}] fetching page ${pageNum}`);
		}

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 30_000);
		let page: KonnectPage<T>;
		try {
			page = await fetchPage<T>(requestUrl, token, controller.signal);
		} finally {
			clearTimeout(timeout);
		}

		items.push(...page.data);

		if (verbose) {
			console.log(
				`  [${displayLabel}] page ${pageNum}: got ${page.data.length} items` +
					` (${items.length} total)${page.next ? ', more pages follow' : ', last page'}`,
			);
		}

		// Guard: an empty page with a non-null `next` would loop forever.
		if (page.data.length === 0) break;

		const prevPath: string | null = nextPath;
		nextPath = page.next ?? null;

		// Guard: if the API returns the same `next` path we just used, stop.
		if (nextPath && nextPath === prevPath) {
			if (verbose) console.warn(`  [${displayLabel}] warning: next URL repeated, stopping`);
			break;
		}
	} while (nextPath);

	return items;
}

/**
 * Fetches all routes and services from a Konnect control plane and returns
 * them as a normalised {@link KonnectData} object.
 *
 * Both collections are fetched in parallel. Services are indexed by UUID
 * for O(1) lookup when correlating routes to services.
 *
 * @param config - Connection and authentication configuration.
 * @param options.verbose - When `true`, progress messages are printed to stderr.
 *
 * @example
 * const data = await fetchKonnectConfig({
 *   token: process.env.KONNECT_TOKEN!,
 *   controlPlaneId: process.env.KONNECT_CONTROL_PLANE_ID!,
 *   region: "us",
 * });
 * console.log(`Fetched ${data.routes.length} routes`);
 */
export async function fetchKonnectConfig(
	config: KonnectConfig,
	options: { verbose?: boolean } = {},
): Promise<KonnectData> {
	const region = config.region ?? 'us';
	const baseUrl = REGION_MAP[region];
	if (!baseUrl) {
		throw new Error(`Unknown region "${region}". Valid regions – ${Object.keys(REGION_MAP).join(', ')}`);
	}

	// Validate controlPlaneId is a well-formed UUID before interpolating it
	// into API URLs. This prevents path-traversal or injection via a malformed
	// ID value.
	if (!UUID_RE.test(config.controlPlaneId)) {
		throw new Error(
			`Invalid controlPlaneId: "${config.controlPlaneId}" is not a UUID. ` +
				'Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
		);
	}

	// Encode the ID defensively even though it is UUID-validated above, so that
	// any future relaxation of the format validation cannot introduce injection.
	const encodedCpId = encodeURIComponent(config.controlPlaneId);
	const entityBase = `${baseUrl}/v2/control-planes/${encodedCpId}/core-entities`;

	if (options.verbose) {
		console.log(`Fetching routes and services from ${entityBase} ...`);
	}

	// Fetch routes then services. Sequential in verbose mode keeps log lines readable;
	// parallel in non-verbose mode keeps things fast.
	let rawRoutes: KongRoute[];
	let rawServices: KongService[];
	if (options.verbose) {
		rawRoutes = await fetchAll<KongRoute>(`${entityBase}/routes`, config.token, { verbose: true, label: 'routes' });
		rawServices = await fetchAll<KongService>(`${entityBase}/services`, config.token, {
			verbose: true,
			label: 'services',
		});
	} else {
		[rawRoutes, rawServices] = await Promise.all([
			fetchAll<KongRoute>(`${entityBase}/routes`, config.token),
			fetchAll<KongService>(`${entityBase}/services`, config.token),
		]);
	}

	if (options.verbose) {
		console.log(`  Done: ${rawRoutes.length} routes, ${rawServices.length} services total.`);
	}

	// Index services by UUID for fast lookup.
	const services = new Map<string, KongService>();
	for (const svc of rawServices) {
		services.set(svc.id, svc);
	}

	// Detect router flavor. First try the control plane config endpoint (works for
	// dedicated/self-managed CPs). If that returns nothing, fall back to inspecting the
	// fetched routes: expression-flavor routes carry an `expression` field that
	// traditional routes never have.
	const routerFlavor =
		(await detectRouterFlavor(baseUrl, encodedCpId, config.token)) ?? inferFlavorFromRoutes(rawRoutes, options.verbose);

	return {
		routes: rawRoutes,
		services,
		routerFlavor,
		controlPlaneId: config.controlPlaneId,
		region: region,
	};
}

/**
 * Infers the router flavor by inspecting already-fetched routes.
 *
 * If any route has a non-empty `expression` field the control plane is running
 * the `expressions` router. Otherwise the flavor cannot be determined from
 * routes alone (both `traditional` and `traditional_compatible` use plain
 * path/method/host fields), so `undefined` is returned and the caller should
 * default to `"traditional"`.
 */
function inferFlavorFromRoutes(routes: KongRoute[], verbose?: boolean): RouterFlavor | undefined {
	const hasExpressionRoute = routes.some((r) => r.expression != null && r.expression !== '');
	if (hasExpressionRoute) {
		if (verbose) {
			console.log("  Note: router flavor inferred as 'expressions' from route objects.");
		}
		return 'expressions';
	}
	if (verbose) {
		console.log("  Note: could not detect router flavor; defaulting to 'traditional'.");
	}
	return undefined;
}

/**
 * Attempts to detect the router flavor configured for the control plane by
 * inspecting the control plane's configuration endpoint.
 *
 * This is the first-pass detection: it works for dedicated / self-managed
 * Konnect CPs that expose `config.router_flavor`. For standard serverless CPs
 * the endpoint omits that field and `undefined` is returned; the caller falls
 * back to {@link inferFlavorFromRoutes}.
 *
 * @param baseUrl        - Konnect API base URL, e.g. `"https://us.api.konghq.com"`.
 * @param encodedCpId    - URL-encoded UUID of the control plane.
 * @param token          - Bearer token.
 */
async function detectRouterFlavor(
	baseUrl: string,
	encodedCpId: string,
	token: string,
): Promise<RouterFlavor | undefined> {
	try {
		const url = `${baseUrl}/v2/control-planes/${encodedCpId}`;
		const response = await fetch(url, {
			headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
		});
		if (!response.ok) return undefined;

		// The shape of this response is not fully typed here; we only care about
		// the `config.router_flavor` field if it exists.
		const body = (await response.json()) as {
			config?: { router_flavor?: string };
		};
		const raw = body?.config?.router_flavor;
		if (raw === 'traditional' || raw === 'traditional_compatible' || raw === 'expressions') {
			return raw as RouterFlavor;
		}
	} catch {
		// Ignore – flavor detection is best-effort; inferFlavorFromRoutes is tried next.
	}

	return undefined;
}

/**
 * Shape of a locally-saved config dump produced by the `dump-config` command.
 */
export interface LocalConfigDump {
	routerFlavor?: RouterFlavor;
	routes: KongRoute[];
	services: KongService[];
}

/**
 * Loads a previously-saved config dump from a JSON file on disk and returns
 * a normalised {@link KonnectData}.
 *
 * This enables offline analysis without a live Konnect API connection, which
 * is useful for CI/CD workflows and offline debugging.
 *
 * @param filePath - Absolute or relative path to the JSON dump file.
 *
 * @example
 * const data = await loadLocalConfig("./routes-dump.json");
 */
export async function loadLocalConfig(filePath: string): Promise<KonnectData> {
	const text = await Bun.file(filePath).text();
	const parsed: LocalConfigDump = JSON.parse(text);

	const services = new Map<string, KongService>();
	for (const svc of parsed.services ?? []) {
		services.set(svc.id, svc);
	}

	return {
		routes: parsed.routes ?? [],
		services,
		routerFlavor: parsed.routerFlavor,
	};
}
