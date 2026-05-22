import { describe, it, expect } from 'bun:test';

import { normalizePath } from './utils.ts';

describe('normalizePath', () => {
	describe('query-string stripping', () => {
		it('strips a query string from a plain path', () => {
			expect(normalizePath('/api/v1/users?debug=1'), 'query string must be stripped').toBe('/api/v1/users');
		});

		it('strips a query string with multiple parameters', () => {
			expect(normalizePath('/search?q=hello&page=2'), 'full query string must be stripped').toBe('/search');
		});

		it('returns the original path unchanged when there is no query string', () => {
			expect(normalizePath('/api/v1/users'), 'clean path must not be altered').toBe('/api/v1/users');
		});
	});

	describe('fragment stripping', () => {
		it('strips a URL fragment', () => {
			expect(normalizePath('/docs/guide#installation'), 'fragment must be stripped').toBe('/docs/guide');
		});

		it('strips both a query string and a fragment', () => {
			expect(normalizePath('/page?foo=1#section'), 'query string and fragment must both be stripped').toBe('/page');
		});
	});

	describe('percent-encoding preservation', () => {
		it('preserves percent-encoded characters unchanged', () => {
			// Kong matches the raw URI; /hello%20world and /hello world are distinct.
			expect(normalizePath('/api/v1/hello%20world'), 'percent encoding must be preserved').toBe(
				'/api/v1/hello%20world',
			);
		});

		it('strips a query string while preserving percent-encoding in the path', () => {
			expect(
				normalizePath('/api/v1/hello%20world?debug=1'),
				'query string must be stripped but encoding must be left intact',
			).toBe('/api/v1/hello%20world');
		});
	});

	describe('dot-segment resolution', () => {
		it('resolves a single-dot segment', () => {
			expect(normalizePath('/api/v1/./users'), 'single-dot segment must be removed').toBe('/api/v1/users');
		});

		it('resolves double-dot parent traversal', () => {
			expect(normalizePath('/api/v1/../v2/users'), 'double-dot must navigate to parent').toBe('/api/v2/users');
		});

		it('handles consecutive double-dot at the root', () => {
			expect(normalizePath('/a/b/../../c'), 'traversal past root must stop at root').toBe('/c');
		});
	});

	describe('clean-path passthrough', () => {
		it('preserves a clean root path', () => {
			expect(normalizePath('/'), 'root path must be preserved unchanged').toBe('/');
		});

		it('preserves a clean multi-segment path', () => {
			expect(normalizePath('/payments/checkout'), 'clean path must be returned as-is').toBe('/payments/checkout');
		});
	});

	describe('malformed / edge-case input', () => {
		it('always returns a string, never throws', () => {
			const weird = 'relative-no-slash';
			const result = normalizePath(weird);
			expect(typeof result, 'result must always be a string').toBe('string');
		});

		it('handles empty input without throwing', () => {
			const result = normalizePath('');
			expect(typeof result, 'result must be a string even for empty input').toBe('string');
		});
	});
});
