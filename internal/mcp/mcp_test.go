// Ported 1:1 from src/mcp.test.ts.
package mcp_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paambaati/kongcheck/internal/mcp"
	"github.com/paambaati/kongcheck/internal/model"
)

var konnectEnvKeys = []string{"KONNECT_TOKEN", "KONNECT_CONTROL_PLANE_ID", "KONNECT_REGION"}

// isolateEnv mirrors the TS beforeEach/afterEach: it removes the Konnect env
// vars for the duration of the test and restores their original values after.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, key := range konnectEnvKeys {
		t.Setenv(key, "") // registers restore of the original value
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("os.Unsetenv(%q): %v", key, err)
		}
	}
}

func expectResolveError(t *testing.T, p mcp.ResolveParams, want string) {
	t.Helper()
	cfg, err := mcp.ResolveConfig(p)
	if err == nil {
		t.Fatalf("ResolveConfig(%+v) = %+v, nil; want error containing %q", p, cfg, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("ResolveConfig(%+v) error = %q; want error containing %q", p, err.Error(), want)
	}
}

func mustResolve(t *testing.T, p mcp.ResolveParams) model.KonnectConfig {
	t.Helper()
	cfg, err := mcp.ResolveConfig(p)
	if err != nil {
		t.Fatalf("ResolveConfig(%+v) returned unexpected error: %v", p, err)
	}
	return cfg
}

func TestResolveConfig(t *testing.T) {
	t.Run("resolveConfig", func(t *testing.T) {
		t.Run("token resolution", func(t *testing.T) {
			t.Run("throws when KONNECT_TOKEN is absent and no per-call token", func(t *testing.T) {
				isolateEnv(t)
				expectResolveError(t, mcp.ResolveParams{ControlPlaneID: "cp-123"},
					"KONNECT_TOKEN environment variable is not set")
			})

			t.Run("throws with a message that mentions the MCP host config", func(t *testing.T) {
				isolateEnv(t)
				expectResolveError(t, mcp.ResolveParams{ControlPlaneID: "cp-123"}, "MCP host config")
			})

			t.Run("uses KONNECT_TOKEN from the environment", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-123")
				cfg := mustResolve(t, mcp.ResolveParams{})
				if cfg.Token != "kpat_test" {
					t.Errorf("token should be read from KONNECT_TOKEN env var: got %q, want %q", cfg.Token, "kpat_test")
				}
			})
		})

		t.Run("controlPlaneId resolution", func(t *testing.T) {
			t.Run("throws when controlPlaneId is absent from both call params and env", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				expectResolveError(t, mcp.ResolveParams{},
					"controlPlaneId was not provided in the tool call and "+
						"KONNECT_CONTROL_PLANE_ID environment variable is not set")
			})

			t.Run("uses controlPlaneId from the per-call param", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				cfg := mustResolve(t, mcp.ResolveParams{ControlPlaneID: "cp-call"})
				if cfg.ControlPlaneID != "cp-call" {
					t.Errorf("per-call controlPlaneId should be used directly: got %q, want %q", cfg.ControlPlaneID, "cp-call")
				}
			})

			t.Run("falls back to KONNECT_CONTROL_PLANE_ID env var when param is absent", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-env")
				cfg := mustResolve(t, mcp.ResolveParams{})
				if cfg.ControlPlaneID != "cp-env" {
					t.Errorf("should fall back to KONNECT_CONTROL_PLANE_ID when no per-call param: got %q, want %q",
						cfg.ControlPlaneID, "cp-env")
				}
			})

			t.Run("prefers the per-call param over the env var", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-env")
				cfg := mustResolve(t, mcp.ResolveParams{ControlPlaneID: "cp-call"})
				if cfg.ControlPlaneID != "cp-call" {
					t.Errorf("per-call controlPlaneId should override KONNECT_CONTROL_PLANE_ID env var: got %q, want %q",
						cfg.ControlPlaneID, "cp-call")
				}
			})
		})

		t.Run("region resolution", func(t *testing.T) {
			t.Run(`defaults to "us" when no region is provided anywhere`, func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-123")
				cfg := mustResolve(t, mcp.ResolveParams{})
				if cfg.Region != "us" {
					t.Errorf(`region should default to "us" when neither param nor env var is set: got %q, want %q`,
						cfg.Region, "us")
				}
			})

			t.Run("uses KONNECT_REGION from the environment", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-123")
				t.Setenv("KONNECT_REGION", "eu")
				cfg := mustResolve(t, mcp.ResolveParams{})
				if cfg.Region != "eu" {
					t.Errorf("region should be read from KONNECT_REGION env var: got %q, want %q", cfg.Region, "eu")
				}
			})

			t.Run("uses the per-call region param", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-123")
				cfg := mustResolve(t, mcp.ResolveParams{Region: "au"})
				if cfg.Region != "au" {
					t.Errorf("per-call region param should be used directly: got %q, want %q", cfg.Region, "au")
				}
			})

			t.Run("prefers the per-call region param over the env var", func(t *testing.T) {
				isolateEnv(t)
				t.Setenv("KONNECT_TOKEN", "kpat_test")
				t.Setenv("KONNECT_CONTROL_PLANE_ID", "cp-123")
				t.Setenv("KONNECT_REGION", "eu")
				cfg := mustResolve(t, mcp.ResolveParams{Region: "sg"})
				if cfg.Region != "sg" {
					t.Errorf("per-call region should override KONNECT_REGION env var: got %q, want %q", cfg.Region, "sg")
				}
			})
		})
	})
}

// stubs produces minimal KonnectData values sufficient for cache tests and
// remembers a label for each one (the Go analogue of the TS `_label` field)
// so individual tests can confirm which stub was returned.
type stubs struct {
	labels map[*model.KonnectData]string
}

func newStubs() *stubs { return &stubs{labels: make(map[*model.KonnectData]string)} }

func (s *stubs) data(label string) *model.KonnectData {
	d := &model.KonnectData{
		ControlPlaneID: "cp-test",
		Routes:         []*model.KongRoute{},
		Services:       model.NewServiceIndex(),
		RouterFlavor:   model.FlavorTraditional,
	}
	s.labels[d] = label
	return d
}

func (s *stubs) label(d *model.KonnectData) string { return s.labels[d] }

var fakeCfg = model.KonnectConfig{Token: "tok", ControlPlaneID: "cp-test", Region: "us"}

const ttl60s = 60 * time.Second

func mustFetch(t *testing.T, cache *mcp.Cache, cfg model.KonnectConfig, ttl time.Duration, fn mcp.FetchFunc) *model.KonnectData {
	t.Helper()
	d, err := cache.Fetch(context.Background(), cfg, ttl, fn)
	if err != nil {
		t.Fatalf("cache.Fetch(%+v, %v) returned unexpected error: %v", cfg, ttl, err)
	}
	return d
}

func TestFetchKonnectConfigCached(t *testing.T) {
	t.Run("fetchKonnectConfigCached", func(t *testing.T) {
		t.Run("calls the fetch function on the first request", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			calls := 0
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				calls++
				return s.data("first"), nil
			}
			mustFetch(t, cache, fakeCfg, ttl60s, stub)
			if calls != 1 {
				t.Errorf("fetch function must be called once for a cold cache: got %d, want 1", calls)
			}
		})

		t.Run("returns cached data on the second call within the TTL", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			calls := 0
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				calls++
				return s.data(fmt.Sprintf("call-%d", calls)), nil
			}
			first := mustFetch(t, cache, fakeCfg, ttl60s, stub)
			second := mustFetch(t, cache, fakeCfg, ttl60s, stub)
			if calls != 1 {
				t.Errorf("fetch function must only be called once for two calls within TTL: got %d, want 1", calls)
			}
			if second != first {
				t.Errorf("second call must return the cached object (same reference): got %p (%q), want %p (%q)",
					second, s.label(second), first, s.label(first))
			}
		})

		t.Run("refetches after the TTL has elapsed", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			calls := 0
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				calls++
				return s.data(fmt.Sprintf("call-%d", calls)), nil
			}
			// Seed the cache with a timestamp far in the past (already expired).
			cache.Set("us:cp-test", &mcp.CacheEntry{
				Data:      s.data("stale"),
				FetchedAt: time.Now().Add(-120 * time.Second),
			})
			result := mustFetch(t, cache, fakeCfg, ttl60s, stub)
			if calls != 1 {
				t.Errorf("fetch function must be called once when cache entry is expired: got %d, want 1", calls)
			}
			if got := s.label(result); got != "call-1" {
				t.Errorf("must return freshly fetched data, not the stale entry: got %q, want %q", got, "call-1")
			}
		})

		t.Run("keys the cache by region:controlPlaneId — different keys get independent entries", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			calls := 0
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				calls++
				return s.data(fmt.Sprintf("call-%d", calls)), nil
			}
			cfgUs := fakeCfg
			cfgUs.Region = "us"
			cfgEu := fakeCfg
			cfgEu.Region = "eu"
			mustFetch(t, cache, cfgUs, ttl60s, stub)
			mustFetch(t, cache, cfgEu, ttl60s, stub)
			if calls != 2 {
				t.Errorf("each region:controlPlaneId pair must be fetched independently: got %d, want 2", calls)
			}
			if got := cache.Len(); got != 2 {
				t.Errorf("cache must hold one entry per distinct key: got %d, want 2", got)
			}
		})

		t.Run("second call to the same key does not increment the cache size", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				return s.data("x"), nil
			}
			mustFetch(t, cache, fakeCfg, ttl60s, stub)
			mustFetch(t, cache, fakeCfg, ttl60s, stub)
			if got := cache.Len(); got != 1 {
				t.Errorf("repeated calls to the same key must not grow the cache: got %d, want 1", got)
			}
		})

		t.Run("bypasses the cache entirely when cacheTtlMs is 0", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			calls := 0
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				calls++
				return s.data(fmt.Sprintf("call-%d", calls)), nil
			}
			mustFetch(t, cache, fakeCfg, 0, stub)
			mustFetch(t, cache, fakeCfg, 0, stub)
			if calls != 2 {
				t.Errorf("TTL=0 must bypass the cache and always fetch: got %d, want 2", calls)
			}
			if got := cache.Len(); got != 0 {
				t.Errorf("TTL=0 must not write to the cache: got %d, want 0", got)
			}
		})

		t.Run("evicts expired entries for other keys when writing a fresh entry", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			// Pre-seed two expired entries for different keys.
			expiredAt := time.Now().Add(-120 * time.Second)
			cache.Set("us:cp-other-1", &mcp.CacheEntry{Data: s.data("old-1"), FetchedAt: expiredAt})
			cache.Set("eu:cp-other-2", &mcp.CacheEntry{Data: s.data("old-2"), FetchedAt: expiredAt})
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				return s.data("fresh"), nil
			}
			mustFetch(t, cache, fakeCfg, ttl60s, stub)
			if got := cache.Has("us:cp-other-1"); got != false {
				t.Errorf("expired entry for a different key must be evicted on write: Has(%q) = %v, want false", "us:cp-other-1", got)
			}
			if got := cache.Has("eu:cp-other-2"); got != false {
				t.Errorf("expired entry for a different key must be evicted on write: Has(%q) = %v, want false", "eu:cp-other-2", got)
			}
			if got := cache.Has("us:cp-test"); got != true {
				t.Errorf("freshly written entry must remain: Has(%q) = %v, want true", "us:cp-test", got)
			}
		})

		t.Run("does not evict a still-valid entry for a different key", func(t *testing.T) {
			isolateEnv(t)
			cache := mcp.NewCache()
			s := newStubs()
			// Pre-seed a non-expired entry for a different key.
			cache.Set("eu:cp-other", &mcp.CacheEntry{Data: s.data("valid"), FetchedAt: time.Now()})
			stub := func(_ context.Context, _ model.KonnectConfig) (*model.KonnectData, error) {
				return s.data("fresh"), nil
			}
			mustFetch(t, cache, fakeCfg, ttl60s, stub)
			if got := cache.Has("eu:cp-other"); got != true {
				t.Errorf("a non-expired entry for a different key must not be evicted: Has(%q) = %v, want true", "eu:cp-other", got)
			}
		})
	})
}

func TestMCPServer_Tools(t *testing.T) {
	isolateEnv(t)
	t.Setenv("KONNECT_TOKEN", "kpat_test_secret")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s := mcp.New(mcp.Options{
		Name:    "kongcheck-test",
		Version: "1.0.0",
		Fetch: func(_ context.Context, cfg model.KonnectConfig) (*model.KonnectData, error) {
			routes := []*model.KongRoute{
				{
					ID:    "r1",
					Name:  "route-1",
					Paths: []string{"/api/v1"},
				},
				{
					ID:    "r2",
					Name:  "route-2",
					Paths: []string{"/api/v1/child"},
				},
			}
			return &model.KonnectData{
				Routes:         routes,
				Services:       model.NewServiceIndex(),
				RouterFlavor:   model.FlavorTraditional,
				ControlPlaneID: cfg.ControlPlaneID,
				Region:         cfg.Region,
			}, nil
		},
	})

	serverTransport, clientTransport := sdk.NewInMemoryTransports()
	go func() {
		_ = s.Run(ctx, serverTransport)
	}()

	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer session.Close()

	t.Run("list tools", func(t *testing.T) {
		toolsRes, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if len(toolsRes.Tools) != 4 {
			t.Errorf("expected 4 tools, got %d", len(toolsRes.Tools))
		}
	})

	t.Run("call analyze_routes", func(t *testing.T) {
		res, err := session.CallTool(ctx, &sdk.CallToolParams{
			Name: "analyze_routes",
			Arguments: map[string]any{
				"controlPlaneId": "11111111-1111-1111-1111-111111111111",
				"region":         "us",
			},
		})
		if err != nil {
			t.Fatalf("CallTool analyze_routes: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected tool error in analyze_routes: %+v", res)
		}
	})

	t.Run("call get_collisions", func(t *testing.T) {
		res, err := session.CallTool(ctx, &sdk.CallToolParams{
			Name: "get_collisions",
			Arguments: map[string]any{
				"controlPlaneId": "11111111-1111-1111-1111-111111111111",
				"region":         "us",
			},
		})
		if err != nil {
			t.Fatalf("CallTool get_collisions: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected tool error in get_collisions: %+v", res)
		}
	})

	t.Run("call explain_request", func(t *testing.T) {
		res, err := session.CallTool(ctx, &sdk.CallToolParams{
			Name: "explain_request",
			Arguments: map[string]any{
				"controlPlaneId": "11111111-1111-1111-1111-111111111111",
				"region":         "us",
				"path":           "/api/v1",
			},
		})
		if err != nil {
			t.Fatalf("CallTool explain_request: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected tool error in explain_request: %+v", res)
		}
	})

	t.Run("call get_route_config", func(t *testing.T) {
		res, err := session.CallTool(ctx, &sdk.CallToolParams{
			Name: "get_route_config",
			Arguments: map[string]any{
				"controlPlaneId": "11111111-1111-1111-1111-111111111111",
				"region":         "us",
			},
		})
		if err != nil {
			t.Fatalf("CallTool get_route_config: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected tool error in get_route_config: %+v", res)
		}
	})
}
