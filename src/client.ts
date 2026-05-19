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
const REGION_MAP: Record<string, string> = {
	us: 'https://us.api.konghq.com',
	eu: 'https://eu.api.konghq.com',
	au: 'https://au.api.konghq.com',
	me: 'https://me.api.konghq.com',
	in: 'https://in.api.konghq.com',
	sg: 'https://sg.api.konghq.com',
};

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
 * Fetches a single page from a Konnect list endpoint.
 *
 * @param url     - Fully-qualified URL, including any query parameters.
 * @param token   - Bearer token.
 * @returns The parsed JSON response.
 * @throws If the HTTP response status is not 2xx.
 */
async function fetchPage<T>(url: string, token: string, signal?: AbortSignal): Promise<KonnectPage<T>> {
	const response = await fetch(url, {
		signal,
		headers: {
			Authorization: `Bearer ${token}`,
			Accept: 'application/json',
		},
	});

	if (!response.ok) {
		const body = await response.text().catch(() => '(unreadable body)');
		throw new Error(`Konnect API error: ${response.status} ${response.statusText} – ${url}\n${body}`);
	}

	return response.json() as Promise<KonnectPage<T>>;
}

/** Options forwarded from {@link fetchKonnectConfig} into {@link fetchAll}. */
interface FetchAllOptions {
	pageSize?: number;
	verbose?: boolean;
	/** Human-readable label printed in verbose messages (e.g. `"routes"`). */
	label?: string;
}

/**
 * Iterates all pages of a Konnect list endpoint and collects the full result
 * set.
 *
 * The Konnect API returns a `next` field containing a pre-built URL path for
 * the next page (e.g. `"/routes?offset=TOKEN&size=100"`). We follow that path
 * directly by resolving it against the API origin — this avoids any ambiguity
 * about which query-parameter name (`cursor` vs `offset`) the API uses.
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

		// First page: build URL from baseUrl with ?size=N.
		// Subsequent pages: keep baseUrl path but replace the query string with whatever
		// the API returned in `page.next`. The `next` value is a path like
		// "/routes?offset=TOKEN&size=100" — it has the right query params but lacks the
		// full control-plane URL prefix, so we resolve against baseUrl not the origin.
		let requestUrl: string;
		if (nextPath) {
			const u = new URL(baseUrl);
			u.search = new URL(nextPath, 'https://x').search;
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

	const entityBase = `${baseUrl}/v2/control-planes/${config.controlPlaneId}/core-entities`;

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
		(await detectRouterFlavor(baseUrl, config.controlPlaneId, config.token)) ??
		inferFlavorFromRoutes(rawRoutes, options.verbose);

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
 * @param controlPlaneId - UUID of the control plane.
 * @param token          - Bearer token.
 */
async function detectRouterFlavor(
	baseUrl: string,
	controlPlaneId: string,
	token: string,
): Promise<RouterFlavor | undefined> {
	try {
		const url = `${baseUrl}/v2/control-planes/${controlPlaneId}`;
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
