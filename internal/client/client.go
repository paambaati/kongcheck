// Package client fetches routes and services from the Konnect Control Planes
// Config v2 API (paginating automatically) and loads offline config dumps.
//
// Authentication uses a Bearer token (Personal Access Token or System Account
// Access Token).
//
// See https://developer.konghq.com/api/konnect/control-planes-config/v2/
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/strutil"
)

// Region codes in display order. Prefer RegionCodes/RegionBaseURL over the
// raw tables so callers cannot mutate shared state.
var regionCodes = []string{"us", "eu", "au", "me", "in", "sg"}

var regions = map[string]string{
	"us": "https://us.api.konghq.com",
	"eu": "https://eu.api.konghq.com",
	"au": "https://au.api.konghq.com",
	"me": "https://me.api.konghq.com",
	"in": "https://in.api.konghq.com",
	"sg": "https://sg.api.konghq.com",
}

// RegionCodes returns the region codes in display order (a fresh slice).
func RegionCodes() []string {
	return slices.Clone(regionCodes)
}

// RegionBaseURL maps a region code to its Konnect API base URL.
func RegionBaseURL(code string) (string, bool) {
	u, ok := regions[code]
	return u, ok
}

const (
	// maxPages caps pagination per resource type, guarding against runaway
	// cursors or unexpectedly large data sets.
	maxPages = 200
	// maxRetries is how often a retryable error (429 / 503) is retried.
	maxRetries = 3
	// pageTimeout bounds each page request.
	pageTimeout = 30 * time.Second
	// maxErrorBody truncates error bodies in messages.
	maxErrorBody = 1024
	// maxResponseBytes caps how much of a response body is read into memory.
	maxResponseBytes = 64 << 20 // 64 MiB
	// defaultPageSize is the page size requested from the list endpoints.
	defaultPageSize = 100
)

var (
	bearerRe = regexp.MustCompile(`(?i)Bearer\s+\S+`)
	// Kong personal access tokens (kpat_) and system account access tokens (spat_).
	kpatRe = regexp.MustCompile(`(?:kpat|spat)_[A-Za-z0-9_-]+`)
)

// RedactBearer replaces Bearer credentials and bare Kong PATs/SAATs in s with a
// placeholder so tokens never reach logs, errors, or MCP tool results.
func RedactBearer(s string) string {
	s = bearerRe.ReplaceAllString(s, "Bearer [REDACTED]")
	return kpatRe.ReplaceAllString(s, "[REDACTED]")
}

// RedactToken redacts Bearer tokens, Kong PATs/SAATs, and any explicit token string.
func RedactToken(s, token string) string {
	s = RedactBearer(s)
	if token != "" {
		s = strings.ReplaceAll(s, token, "[REDACTED]")
	}
	return s
}

// APIError is returned when the Konnect API responds with a non-2xx status.
// Its message has Bearer tokens redacted and the body truncated, so large
// responses (which may contain routing config) do not leak into logs.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

// Options configures FetchKonnectConfig.
type Options struct {
	// Verbose prints progress to Log.
	Verbose bool
	// Log receives verbose progress output (defaults to os.Stderr).
	Log io.Writer
}

// Client talks to the Konnect API. The zero value is ready to use.
type Client struct {
	// HTTP is the HTTP client (defaults to DefaultHTTPClient).
	HTTP *http.Client
	// BaseURLs overrides the region → base URL mapping (used in tests).
	BaseURLs map[string]string
	// Sleep waits between retries (defaults to a context-aware sleep).
	Sleep func(ctx context.Context, d time.Duration) error
}

// DefaultHTTPClient is a dedicated client with connection pooling and
// keep-alives sized for concurrent Konnect fetches (routes + services in
// parallel against one or two hosts). Prefer it over http.DefaultClient,
// which shares a package-global transport with unrelated callers.
var DefaultHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
	// Overall request ceiling; per-request context timeouts still apply.
	Timeout: 60 * time.Second,
}

// FetchKonnectConfig fetches all routes and services of a control plane using
// the default client.
func FetchKonnectConfig(ctx context.Context, cfg model.KonnectConfig, opts Options) (*model.KonnectData, error) {
	return (&Client{}).FetchKonnectConfig(ctx, cfg, opts)
}

// FetchKonnectConfig fetches all routes and services of a control plane and
// detects its router flavor.
func (c *Client) FetchKonnectConfig(ctx context.Context, cfg model.KonnectConfig, opts Options) (*model.KonnectData, error) {
	logw := opts.Log
	if logw == nil {
		logw = os.Stderr
	}
	logf := func(format string, a ...any) {
		if opts.Verbose {
			fmt.Fprintf(logw, format+"\n", a...)
		}
	}

	region := cfg.Region
	if region == "" {
		region = "us"
	}
	baseURL, ok := c.baseURLs()[region]
	if !ok {
		return nil, fmt.Errorf(`Unknown region "%s". Valid regions – %s`, region, strings.Join(RegionCodes(), ", "))
	}

	// Validate before interpolating into URLs to rule out path injection.
	if !strutil.IsUUID(cfg.ControlPlaneID) {
		return nil, fmt.Errorf(`Invalid controlPlaneId: "%s" is not a UUID. Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, cfg.ControlPlaneID)
	}
	cpID := url.PathEscape(cfg.ControlPlaneID)
	entityBase := baseURL + "/v2/control-planes/" + cpID + "/core-entities"

	logf("Fetching routes and services from %s ...", entityBase)

	var (
		routes   []*model.KongRoute
		services []*model.KongService
		err      error
	)
	if opts.Verbose {
		// Sequential keeps the progress output readable.
		if routes, err = fetchAll[*model.KongRoute](ctx, c, entityBase+"/routes", cfg.Token, "routes", logf); err != nil {
			return nil, err
		}
		if services, err = fetchAll[*model.KongService](ctx, c, entityBase+"/services", cfg.Token, "services", logf); err != nil {
			return nil, err
		}
	} else {
		var wg sync.WaitGroup
		var routesErr, servicesErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			routes, routesErr = fetchAll[*model.KongRoute](ctx, c, entityBase+"/routes", cfg.Token, "routes", logf)
		}()
		go func() {
			defer wg.Done()
			services, servicesErr = fetchAll[*model.KongService](ctx, c, entityBase+"/services", cfg.Token, "services", logf)
		}()
		wg.Wait()
		if err := errors.Join(routesErr, servicesErr); err != nil {
			return nil, err
		}
	}

	logf("  Done: %d routes, %d services total.", len(routes), len(services))

	flavor := c.detectRouterFlavor(ctx, baseURL, cpID, cfg.Token)
	if flavor == "" {
		flavor = inferFlavorFromRoutes(routes, logf)
	}

	return &model.KonnectData{
		Routes:         routes,
		Services:       model.NewServiceIndex(services...),
		RouterFlavor:   flavor,
		ControlPlaneID: cfg.ControlPlaneID,
		Region:         region,
	}, nil
}

func (c *Client) baseURLs() map[string]string {
	if c.BaseURLs != nil {
		return c.BaseURLs
	}
	return regions
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return DefaultHTTPClient
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type page[T any] struct {
	Data []T `json:"data"`
	// Next is the cursor path for the next page; null on the last page.
	Next *string `json:"next"`
}

// allowedCursorParams are the only query parameters forwarded from a `next`
// cursor, preventing cursor injection.
var allowedCursorParams = []string{"offset", "size"}

// fetchAll collects every page of a list endpoint.
func fetchAll[T any](ctx context.Context, c *Client, baseURL, token, label string, logf func(string, ...any)) ([]T, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if label == "" {
		label = path.Base(base.Path)
	}

	var items []T
	nextPath := ""
	for pageNum := 1; ; pageNum++ {
		if pageNum > maxPages {
			logf("  [%s] warning: reached MAX_PAGES=%d limit, stopping", label, maxPages)
			break
		}

		u := *base
		q := url.Values{}
		if nextPath != "" {
			cursor, err := url.Parse(nextPath)
			if err != nil {
				return nil, fmt.Errorf("invalid pagination cursor %q: %w", nextPath, err)
			}
			for _, k := range allowedCursorParams {
				if v, ok := cursor.Query()[k]; ok && len(v) > 0 {
					q.Set(k, v[0])
				}
			}
		} else {
			q.Set("size", strconv.Itoa(defaultPageSize))
		}
		u.RawQuery = q.Encode()

		logf("  [%s] fetching page %d", label, pageNum)

		var p page[T]
		if err := c.fetchPage(ctx, u.String(), token, &p); err != nil {
			return nil, err
		}
		items = append(items, p.Data...)

		more := ", last page"
		if p.Next != nil && *p.Next != "" {
			more = ", more pages follow"
		}
		logf("  [%s] page %d: got %d items (%d total)%s", label, pageNum, len(p.Data), len(items), more)

		// An empty page with a cursor would loop forever.
		if len(p.Data) == 0 || p.Next == nil || *p.Next == "" {
			break
		}
		if *p.Next == nextPath {
			logf("  [%s] warning: next URL repeated, stopping", label)
			break
		}
		nextPath = *p.Next
	}
	if items == nil {
		items = []T{}
	}
	return items, nil
}

// fetchPage GETs one page, retrying 429 and 503 responses (honouring
// Retry-After, else exponential backoff of 1s, 2s, 4s). Other errors fail
// immediately.
func (c *Client) fetchPage(ctx context.Context, rawURL, token string, out any) error {
	for attempt := 0; ; attempt++ {
		status, header, body, err := c.get(ctx, rawURL, token)
		if err != nil {
			return err
		}
		if status >= 200 && status < 300 {
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("decoding %s: %w", rawURL, err)
			}
			return nil
		}

		text := RedactToken(string(body), token)
		if len(text) > maxErrorBody {
			text = text[:maxErrorBody] + "... (truncated)"
		}
		apiErr := &APIError{
			Status:  status,
			Message: fmt.Sprintf("Konnect API error: %d %s – %s\n%s", status, http.StatusText(status), rawURL, text),
		}

		retryable := status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
		if !retryable || attempt >= maxRetries {
			return apiErr
		}
		delay, ok := parseRetryAfter(header.Get("Retry-After"), time.Now())
		if !ok {
			delay = time.Second << attempt
		}
		if err := c.sleep(ctx, delay); err != nil {
			return err
		}
	}
}

func (c *Client) get(ctx context.Context, rawURL, token string) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, pageTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, nil, errors.New(RedactToken(err.Error(), token))
	}
	defer func() { _ = resp.Body.Close() }()
	// Cap how much we buffer so a hostile or misbehaving endpoint cannot
	// exhaust memory; read up to maxResponseBytes + 1 to detect truncation.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, nil, errors.New(RedactToken(fmt.Sprintf("reading response from %s: %v", rawURL, err), token))
	}
	if int64(len(body)) > maxResponseBytes {
		return 0, nil, nil, fmt.Errorf("response body from %s exceeded %d bytes limit", rawURL, maxResponseBytes)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// parseRetryAfter parses a Retry-After header (seconds or an HTTP date).
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.ParseFloat(strings.TrimSpace(h), 64); err == nil && secs >= 0 {
		return time.Duration(secs * float64(time.Second)), true
	}
	if t, err := http.ParseTime(h); err == nil {
		return max(0, t.Sub(now)), true
	}
	return 0, false
}

// detectRouterFlavor reads `config.router_flavor` from the control plane
// endpoint. It is best-effort: dedicated/self-managed control planes expose
// the field, serverless ones do not, and any failure yields "".
func (c *Client) detectRouterFlavor(ctx context.Context, baseURL, cpID, token string) model.RouterFlavor {
	status, _, body, err := c.get(ctx, baseURL+"/v2/control-planes/"+cpID, token)
	if err != nil || status < 200 || status >= 300 {
		return ""
	}
	var cp struct {
		Config struct {
			RouterFlavor string `json:"router_flavor"`
		} `json:"config"`
	}
	if json.Unmarshal(body, &cp) != nil {
		return ""
	}
	return model.ParseFlavor(cp.Config.RouterFlavor)
}

// inferFlavorFromRoutes detects the expressions flavor from route objects
// (only expression routes carry an `expression`). traditional and
// traditional_compatible are indistinguishable from routes alone, so it
// otherwise returns "" and callers default to traditional.
func inferFlavorFromRoutes(routes []*model.KongRoute, logf func(string, ...any)) model.RouterFlavor {
	for _, r := range routes {
		if r.Expression != nil && *r.Expression != "" {
			logf("  Note: router flavor inferred as 'expressions' from route objects.")
			return model.FlavorExpressions
		}
	}
	logf("  Note: could not detect router flavor; defaulting to 'traditional'.")
	return ""
}
