package mcp

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
	"github.com/paambaati/kongcheck/internal/strutil"
)

// ResolveParams are the per-call connection parameters of a tool call.
// Empty fields fall back to the environment.
type ResolveParams struct {
	ControlPlaneID string
	Region         string
}

// ResolveConfig builds the Konnect connection config from per-call parameters
// and environment variables.
func ResolveConfig(p ResolveParams) (model.KonnectConfig, error) {
	token := os.Getenv("KONNECT_TOKEN")
	if token == "" {
		return model.KonnectConfig{}, errors.New("KONNECT_TOKEN environment variable is not set. " +
			"Configure it in your MCP host config so it is available to kongcheck.")
	}
	cpID := strutil.FirstNonEmpty(p.ControlPlaneID, os.Getenv("KONNECT_CONTROL_PLANE_ID"))
	if cpID == "" {
		return model.KonnectConfig{}, errors.New("controlPlaneId was not provided in the tool call and " +
			"KONNECT_CONTROL_PLANE_ID environment variable is not set.")
	}
	region := strutil.FirstNonEmpty(p.Region, os.Getenv("KONNECT_REGION"), "us")
	return model.KonnectConfig{Token: token, ControlPlaneID: cpID, Region: region}, nil
}

// FetchFunc fetches a control plane's configuration.
type FetchFunc func(ctx context.Context, cfg model.KonnectConfig) (*model.KonnectData, error)

// CacheEntry is one cached control plane configuration.
type CacheEntry struct {
	Data      *model.KonnectData
	FetchedAt time.Time
	// sorted lazily caches marshalled, priority-sorted routes per flavor so
	// repeated explain_request calls skip the marshal+sort pass.
	sorted map[model.RouterFlavor][]*router.MarshalledRoute
}

// Cache is an in-memory, per-session cache of fetched configurations keyed by
// "region:controlPlaneId". It is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*CacheEntry
	// Now returns the current time (overridable in tests).
	Now func() time.Time
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{entries: make(map[string]*CacheEntry), Now: time.Now}
}

// CacheKey returns the cache key for a connection config.
func CacheKey(cfg model.KonnectConfig) string {
	return cfg.Region + ":" + cfg.ControlPlaneID
}

// Fetch returns cached data when an entry exists and is younger than ttl;
// otherwise it calls fetch and stores the result, evicting other expired
// entries so stale data does not linger. A ttl <= 0 bypasses the cache.
func (c *Cache) Fetch(ctx context.Context, cfg model.KonnectConfig, ttl time.Duration, fetch FetchFunc) (*model.KonnectData, error) {
	if ttl <= 0 {
		return fetch(ctx, cfg)
	}
	key := CacheKey(cfg)
	now := c.Now()

	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Sub(e.FetchedAt) < ttl {
		c.mu.Unlock()
		return e.Data, nil
	}
	c.mu.Unlock()

	data, err := fetch(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Stamp after the fetch returns so TTL is measured from when the data
	// actually landed, not from when the request started (slow fetches would
	// otherwise look older than they are).
	fetchedAt := c.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = &CacheEntry{Data: data, FetchedAt: fetchedAt}
	for k, e := range c.entries {
		if k != key && fetchedAt.Sub(e.FetchedAt) >= ttl {
			delete(c.entries, k)
		}
	}
	return data, nil
}

// Set stores an entry directly (used to seed the cache in tests).
func (c *Cache) Set(key string, e *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}

// Has reports whether key is cached.
func (c *Cache) Has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// SortedRoutes returns the marshalled, sorted routes of data for flavor,
// reusing the copy memoized on the cache entry for key when the entry still
// holds the same data.
func (c *Cache) SortedRoutes(key string, data *model.KonnectData, flavor model.RouterFlavor) []*router.MarshalledRoute {
	c.mu.Lock()
	e, ok := c.entries[key]
	if ok && e.Data == data {
		if sorted, hit := e.sorted[flavor]; hit {
			c.mu.Unlock()
			return sorted
		}
	}
	c.mu.Unlock()

	sorted := router.SortRoutes(router.MarshalRoutes(data, flavor))

	if ok && e.Data == data {
		c.mu.Lock()
		if e.sorted == nil {
			e.sorted = make(map[model.RouterFlavor][]*router.MarshalledRoute)
		}
		e.sorted[flavor] = sorted
		c.mu.Unlock()
	}
	return sorted
}
