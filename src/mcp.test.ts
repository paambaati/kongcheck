import { afterEach, beforeEach, describe, expect, it } from 'bun:test';

import { _cache, fetchKonnectConfigCached, resolveConfig } from './mcp.ts';
import type { KonnectData, KonnectConfig } from './types.ts';

// Snapshot the real env before every test and restore it after, so nothing
// leaks between tests or into the rest of the suite.
let savedEnv: NodeJS.ProcessEnv;

beforeEach(() => {
	savedEnv = { ...process.env };
	delete process.env['KONNECT_TOKEN'];
	delete process.env['KONNECT_CONTROL_PLANE_ID'];
	delete process.env['KONNECT_REGION'];
});

afterEach(() => {
	// Restore only the keys we touch — avoids stomping unrelated env vars.
	for (const key of ['KONNECT_TOKEN', 'KONNECT_CONTROL_PLANE_ID', 'KONNECT_REGION']) {
		if (savedEnv[key] !== undefined) {
			process.env[key] = savedEnv[key];
		} else {
			delete process.env[key];
		}
	}
});

describe('resolveConfig', () => {
	describe('token resolution', () => {
		it('throws when KONNECT_TOKEN is absent and no per-call token', () => {
			expect(() => resolveConfig({ controlPlaneId: 'cp-123' })).toThrow(
				'KONNECT_TOKEN environment variable is not set',
			);
		});

		it('throws with a message that mentions the MCP host config', () => {
			expect(() => resolveConfig({ controlPlaneId: 'cp-123' })).toThrow('MCP host config');
		});

		it('uses KONNECT_TOKEN from the environment', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-123';
			const cfg = resolveConfig({});
			expect(cfg.token, 'token should be read from KONNECT_TOKEN env var').toBe('kpat_test');
		});
	});

	describe('controlPlaneId resolution', () => {
		it('throws when controlPlaneId is absent from both call params and env', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			expect(() => resolveConfig({})).toThrow(
				'controlPlaneId was not provided in the tool call and ' +
					'KONNECT_CONTROL_PLANE_ID environment variable is not set',
			);
		});

		it('uses controlPlaneId from the per-call param', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			const cfg = resolveConfig({ controlPlaneId: 'cp-call' });
			expect(cfg.controlPlaneId, 'per-call controlPlaneId should be used directly').toBe('cp-call');
		});

		it('falls back to KONNECT_CONTROL_PLANE_ID env var when param is absent', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-env';
			const cfg = resolveConfig({});
			expect(cfg.controlPlaneId, 'should fall back to KONNECT_CONTROL_PLANE_ID when no per-call param').toBe('cp-env');
		});

		it('prefers the per-call param over the env var', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-env';
			const cfg = resolveConfig({ controlPlaneId: 'cp-call' });
			expect(cfg.controlPlaneId, 'per-call controlPlaneId should override KONNECT_CONTROL_PLANE_ID env var').toBe(
				'cp-call',
			);
		});
	});

	describe('region resolution', () => {
		it('defaults to "us" when no region is provided anywhere', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-123';
			const cfg = resolveConfig({});
			expect(cfg.region, 'region should default to "us" when neither param nor env var is set').toBe('us');
		});

		it('uses KONNECT_REGION from the environment', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-123';
			process.env['KONNECT_REGION'] = 'eu';
			const cfg = resolveConfig({});
			expect(cfg.region, 'region should be read from KONNECT_REGION env var').toBe('eu');
		});

		it('uses the per-call region param', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-123';
			const cfg = resolveConfig({ region: 'au' });
			expect(cfg.region, 'per-call region param should be used directly').toBe('au');
		});

		it('prefers the per-call region param over the env var', () => {
			process.env['KONNECT_TOKEN'] = 'kpat_test';
			process.env['KONNECT_CONTROL_PLANE_ID'] = 'cp-123';
			process.env['KONNECT_REGION'] = 'eu';
			const cfg = resolveConfig({ region: 'sg' });
			expect(cfg.region, 'per-call region should override KONNECT_REGION env var').toBe('sg');
		});
	});
});

/** Minimal KonnectData stub sufficient for cache tests, with an extra `_label`
 * field so individual tests can confirm which stub was returned. */
function stubData(label: string): KonnectData & { _label: string } {
	return {
		controlPlaneId: 'cp-test',
		routes: [],
		services: new Map(),
		routerFlavor: 'traditional',
		_label: label,
	} as unknown as KonnectData & { _label: string };
}

const fakeCfg: KonnectConfig = { token: 'tok', controlPlaneId: 'cp-test', region: 'us' };

describe('fetchKonnectConfigCached', () => {
	// Clear the shared module-level cache before every test so tests are isolated.
	beforeEach(() => _cache.clear());

	it('calls the fetch function on the first request', async () => {
		let calls = 0;
		const stub = async (_cfg: KonnectConfig) => {
			calls++;
			return stubData('first');
		};
		await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		expect(calls, 'fetch function must be called once for a cold cache').toBe(1);
	});

	it('returns cached data on the second call within the TTL', async () => {
		let calls = 0;
		const stub = async (_cfg: KonnectConfig) => {
			calls++;
			return stubData(`call-${calls}`);
		};
		const first = await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		const second = await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		expect(calls, 'fetch function must only be called once for two calls within TTL').toBe(1);
		expect(second, 'second call must return the cached object (same reference)').toBe(first);
	});

	it('refetches after the TTL has elapsed', async () => {
		let calls = 0;
		const stub = async (_cfg: KonnectConfig) => {
			calls++;
			return stubData(`call-${calls}`);
		};
		// Seed the cache with a timestamp far in the past (already expired).
		_cache.set('us:cp-test', { data: stubData('stale'), fetchedAt: Date.now() - 120_000 });
		const result = await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		expect(calls, 'fetch function must be called once when cache entry is expired').toBe(1);
		expect(
			(result as KonnectData & { _label: string })._label,
			'must return freshly fetched data, not the stale entry',
		).toBe('call-1');
	});

	it('keys the cache by region:controlPlaneId — different keys get independent entries', async () => {
		let calls = 0;
		const stub = async (_cfg: KonnectConfig) => {
			calls++;
			return stubData(`call-${calls}`);
		};
		const cfgUs = { ...fakeCfg, region: 'us' };
		const cfgEu = { ...fakeCfg, region: 'eu' };
		await fetchKonnectConfigCached(cfgUs, 60_000, stub);
		await fetchKonnectConfigCached(cfgEu, 60_000, stub);
		expect(calls, 'each region:controlPlaneId pair must be fetched independently').toBe(2);
		expect(_cache.size, 'cache must hold one entry per distinct key').toBe(2);
	});

	it('second call to the same key does not increment the cache size', async () => {
		const stub = async (_cfg: KonnectConfig) => stubData('x');
		await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		expect(_cache.size, 'repeated calls to the same key must not grow the cache').toBe(1);
	});

	it('bypasses the cache entirely when cacheTtlMs is 0', async () => {
		let calls = 0;
		const stub = async (_cfg: KonnectConfig) => {
			calls++;
			return stubData(`call-${calls}`);
		};
		await fetchKonnectConfigCached(fakeCfg, 0, stub);
		await fetchKonnectConfigCached(fakeCfg, 0, stub);
		expect(calls, 'TTL=0 must bypass the cache and always fetch').toBe(2);
		expect(_cache.size, 'TTL=0 must not write to the cache').toBe(0);
	});

	it('evicts expired entries for other keys when writing a fresh entry', async () => {
		// Pre-seed two expired entries for different keys.
		const expiredAt = Date.now() - 120_000;
		_cache.set('us:cp-other-1', { data: stubData('old-1'), fetchedAt: expiredAt });
		_cache.set('eu:cp-other-2', { data: stubData('old-2'), fetchedAt: expiredAt });
		const stub = async (_cfg: KonnectConfig) => stubData('fresh');
		await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		expect(_cache.has('us:cp-other-1'), 'expired entry for a different key must be evicted on write').toBe(false);
		expect(_cache.has('eu:cp-other-2'), 'expired entry for a different key must be evicted on write').toBe(false);
		expect(_cache.has('us:cp-test'), 'freshly written entry must remain').toBe(true);
	});

	it('does not evict a still-valid entry for a different key', async () => {
		// Pre-seed a non-expired entry for a different key.
		_cache.set('eu:cp-other', { data: stubData('valid'), fetchedAt: Date.now() });
		const stub = async (_cfg: KonnectConfig) => stubData('fresh');
		await fetchKonnectConfigCached(fakeCfg, 60_000, stub);
		expect(_cache.has('eu:cp-other'), 'a non-expired entry for a different key must not be evicted').toBe(true);
	});
});
