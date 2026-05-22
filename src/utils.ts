/**
 * Normalizes a request path the same way Kong does before route matching:
 *  1. Strip the query string (everything from '?' onwards).
 *  2. Strip a URL fragment (everything from '#' onwards).
 *  3. Resolve '.' and '..' dot-segments.
 *
 * Percent-encoding is preserved as-is: Kong's traditional router matches the
 * raw URI without decoding, so `/hello%20world` and `/hello world` are
 * distinct paths.
 *
 * Uses the WHATWG URL parser so dot-segment resolution and query/fragment
 * stripping match nginx-level behaviour.  Falls back to the raw input if the
 * path cannot be parsed (e.g. an opaque or malformed string).
 */
export function normalizePath(rawPath: string): string {
	try {
		// URL requires an absolute reference; use a throwaway base.
		const url = new URL(rawPath, 'http://x');
		// url.pathname is dot-resolved and never includes ? or #.
		// Percent-encoding is intentionally preserved (Kong matches raw URI).
		return url.pathname;
	} catch {
		// Not a valid URL path — return as-is so we don't silently drop input.
		return rawPath;
	}
}
