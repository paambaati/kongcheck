package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paambaati/kongcheck/internal/analyzer"
	"github.com/paambaati/kongcheck/internal/client"
	"github.com/paambaati/kongcheck/internal/filter"
	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
	"github.com/paambaati/kongcheck/internal/strutil"
	"github.com/paambaati/kongcheck/internal/urlutil"
)

const instructions = "kongcheck audits Kong Konnect route configurations for collisions, " +
	"shadowing, and suspicious regex patterns. Use analyze_routes for a full " +
	"audit, get_collisions for a focused collision report, explain_request to " +
	"simulate a specific HTTP or TCP/TLS stream request, and get_route_config " +
	"to inspect the raw route/service data."

// Options configures the MCP server.
type Options struct {
	// Name and Version identify the server to clients.
	Name, Version string
	// CacheTTL is how long fetched configs are reused; 0 disables caching.
	CacheTTL time.Duration
	// Fetch overrides how configs are fetched (defaults to the Konnect API).
	Fetch FetchFunc
}

// Server wraps the official MCP SDK server with kongcheck tools and caching.
type Server struct {
	sdkServer *sdk.Server
	cache     *Cache
	cacheTTL  time.Duration
	fetch     FetchFunc
}

// New builds the MCP server with all tools registered using the official MCP Go SDK.
func New(opts Options) *Server {
	s := &Server{
		cache:    NewCache(),
		cacheTTL: opts.CacheTTL,
		fetch:    opts.Fetch,
	}
	if s.fetch == nil {
		s.fetch = func(ctx context.Context, cfg model.KonnectConfig) (*model.KonnectData, error) {
			return client.FetchKonnectConfig(ctx, cfg, client.Options{})
		}
	}

	impl := &sdk.Implementation{
		Name:    opts.Name,
		Version: opts.Version,
	}
	sdkServer := sdk.NewServer(impl, &sdk.ServerOptions{
		Instructions: instructions,
	})
	s.sdkServer = sdkServer

	sdk.AddTool(sdkServer, &sdk.Tool{
		Name:        "analyze_routes",
		Description: "Run a full four-pass audit of a Konnect control plane: suspicious regex paths, route collisions, shadowing, and (optionally) universal catch-all routes.",
	}, s.handleAnalyze)

	sdk.AddTool(sdkServer, &sdk.Tool{
		Name:        "get_collisions",
		Description: "Return only shadowing and collision findings for a Konnect control plane. Excludes suspicious-regex findings.",
	}, s.handleCollisions)

	sdk.AddTool(sdkServer, &sdk.Tool{
		Name:        "explain_request",
		Description: "Simulate a specific HTTP or TCP/TLS stream request against a Konnect control plane and return the winning route with a step-by-step explanation of why it won. For stream routes, supply sni / sourceIp / sourcePort / destIp / destPort as needed. When an L4 field is omitted, the corresponding route constraint is skipped (conservative mode: every route is a candidate). The path is normalised before matching: query strings and fragments are stripped and dot-segments are resolved.",
	}, s.handleExplain)

	sdk.AddTool(sdkServer, &sdk.Tool{
		Name:        "get_route_config",
		Description: "Fetch the raw routes and services from a Konnect control plane as structured data. Useful when the agent needs to inspect or reason about the full route list directly.",
	}, s.handleRouteConfig)

	return s
}

// Run runs the MCP server on transport.
func (s *Server) Run(ctx context.Context, transport sdk.Transport) error {
	return s.sdkServer.Run(ctx, transport)
}

// Serve runs the MCP server over stdio until EOF or context cancellation.
func Serve(ctx context.Context, opts Options) error {
	s := New(opts)
	return s.sdkServer.Run(ctx, &sdk.StdioTransport{})
}

// ServeIO runs the MCP server using separate reader and writer (used in tests).
func (s *Server) ServeIO(ctx context.Context, in io.Reader, out io.Writer) error {
	return s.sdkServer.Run(ctx, &sdk.IOTransport{
		Reader: toReadCloser(in),
		Writer: toWriteCloser(out),
	})
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func toReadCloser(r io.Reader) io.ReadCloser {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	return io.NopCloser(r)
}

func toWriteCloser(w io.Writer) io.WriteCloser {
	if wc, ok := w.(io.WriteCloser); ok {
		return wc
	}
	return nopWriteCloser{Writer: w}
}

// TargetArgs are the common connection parameters.
type TargetArgs struct {
	ControlPlaneID string `json:"controlPlaneId,omitempty" jsonschema:"UUID of the Konnect control plane to inspect. Falls back to KONNECT_CONTROL_PLANE_ID env var."`
	Region         string `json:"region,omitempty" jsonschema:"Konnect region (us, eu, au, me, in, sg). Defaults to KONNECT_REGION env var or 'us'."`
}

func (a TargetArgs) validate() error {
	if a.ControlPlaneID != "" && !strutil.IsUUID(a.ControlPlaneID) {
		return fmt.Errorf("controlPlaneId: invalid UUID %q", a.ControlPlaneID)
	}
	if a.Region != "" && !slices.Contains(client.RegionCodes(), a.Region) {
		return fmt.Errorf("region: expected one of %s, got %q", strings.Join(client.RegionCodes(), ", "), a.Region)
	}
	return nil
}

// FilterArg is one attribute filter.
type FilterArg struct {
	Key   string `json:"key" jsonschema:"Attribute to filter on: path, name, service, tag, id."`
	Value string `json:"value" jsonschema:"Substring to match against (case-insensitive)."`
}

// AnalysisArgs are arguments for analyze_routes.
type AnalysisArgs struct {
	TargetArgs
	Flavor      string      `json:"flavor,omitempty" jsonschema:"Override router flavor: traditional, traditional_compatible, expressions."`
	IncludeInfo bool        `json:"includeInfo,omitempty" jsonschema:"Include INFO-level findings. Default: false."`
	Filter      []FilterArg `json:"filter,omitempty" jsonschema:"Filter findings by route attributes."`
}

func (a AnalysisArgs) validate() error {
	if err := a.TargetArgs.validate(); err != nil {
		return err
	}
	if a.Flavor != "" && model.ParseFlavor(a.Flavor) == "" {
		return fmt.Errorf("flavor: expected one of traditional, traditional_compatible, expressions, got %q", a.Flavor)
	}
	return nil
}

func (a AnalysisArgs) predicates() ([]filter.Predicate, error) {
	raw := make([]string, len(a.Filter))
	for i, f := range a.Filter {
		raw[i] = f.Key + ":" + f.Value
	}
	return filter.ParseAll(raw)
}

// CollisionsArgs are arguments for get_collisions.
type CollisionsArgs struct {
	TargetArgs
	Flavor string      `json:"flavor,omitempty" jsonschema:"Override router flavor: traditional, traditional_compatible, expressions."`
	Filter []FilterArg `json:"filter,omitempty" jsonschema:"Filter findings by route attributes."`
}

func (c CollisionsArgs) toAnalysisArgs() AnalysisArgs {
	return AnalysisArgs{
		TargetArgs: c.TargetArgs,
		Flavor:     c.Flavor,
		Filter:     c.Filter,
	}
}

// ExplainArgs are arguments for explain_request.
type ExplainArgs struct {
	TargetArgs
	Flavor     string            `json:"flavor,omitempty" jsonschema:"Override router flavor."`
	Method     string            `json:"method,omitempty" jsonschema:"HTTP method, e.g. GET. Default: GET."`
	Host       string            `json:"host,omitempty" jsonschema:"Host header value, e.g. api.example.com. Default: example.com."`
	Path       string            `json:"path" jsonschema:"Request path, e.g. /api/v1/users."`
	Headers    map[string]string `json:"headers,omitempty" jsonschema:"Optional request headers as a key/value object."`
	SNI        *string           `json:"sni,omitempty" jsonschema:"TLS SNI value for stream route simulation."`
	SourceIP   *string           `json:"sourceIp,omitempty" jsonschema:"Source IP address of the connection."`
	SourcePort *int              `json:"sourcePort,omitempty" jsonschema:"Source TCP/UDP port (1-65535)."`
	DestIP     *string           `json:"destIp,omitempty" jsonschema:"Destination IP address."`
	DestPort   *int              `json:"destPort,omitempty" jsonschema:"Destination TCP/UDP port (1-65535)."`
}

func (e ExplainArgs) validate() error {
	if e.Path == "" {
		return fmt.Errorf("path: required")
	}
	if err := e.TargetArgs.validate(); err != nil {
		return err
	}
	if e.Flavor != "" && model.ParseFlavor(e.Flavor) == "" {
		return fmt.Errorf("flavor: expected one of traditional, traditional_compatible, expressions, got %q", e.Flavor)
	}
	if e.SourcePort != nil && (*e.SourcePort < 1 || *e.SourcePort > 65535) {
		return fmt.Errorf("sourcePort: expected an integer between 1 and 65535, got %d", *e.SourcePort)
	}
	if e.DestPort != nil && (*e.DestPort < 1 || *e.DestPort > 65535) {
		return fmt.Errorf("destPort: expected an integer between 1 and 65535, got %d", *e.DestPort)
	}
	return nil
}

// RouteConfigArgs are arguments for get_route_config.
type RouteConfigArgs struct {
	TargetArgs
}

func (s *Server) load(ctx context.Context, t TargetArgs) (model.KonnectConfig, *model.KonnectData, error) {
	cfg, err := ResolveConfig(ResolveParams(t))
	if err != nil {
		return cfg, nil, err
	}
	data, err := s.cache.Fetch(ctx, cfg, s.cacheTTL, s.fetch)
	return cfg, data, err
}

func resolveFlavor(requested string, data *model.KonnectData) model.RouterFlavor {
	if f := model.ParseFlavor(requested); f != "" {
		return f
	}
	if data.RouterFlavor != "" {
		return data.RouterFlavor
	}
	return model.FlavorTraditional
}

func toolSuccess(text string) (*sdk.CallToolResult, any, error) {
	return &sdk.CallToolResult{
		Content: []sdk.Content{
			&sdk.TextContent{Text: text},
		},
	}, nil, nil
}

func toolError(err error) (*sdk.CallToolResult, any, error) {
	errText, _ := toJSON(map[string]string{"error": client.RedactBearer(err.Error())})
	return &sdk.CallToolResult{
		Content: []sdk.Content{
			&sdk.TextContent{Text: errText},
		},
		IsError: true,
	}, nil, nil
}

func (s *Server) handleAnalyze(ctx context.Context, _ *sdk.CallToolRequest, args AnalysisArgs) (*sdk.CallToolResult, any, error) {
	if err := args.validate(); err != nil {
		return toolError(err)
	}
	cfg, data, err := s.load(ctx, args.TargetArgs)
	if err != nil {
		return toolError(err)
	}
	flavor := resolveFlavor(args.Flavor, data)
	preds, err := args.predicates()
	if err != nil {
		return toolError(err)
	}
	all := analyzer.Analyze(ctx, data, analyzer.Options{Flavor: flavor, ExcludeInfo: !args.IncludeInfo})
	findings := filter.Apply(all, preds, data.Services)
	res, err := toJSON(struct {
		ControlPlaneID string                `json:"controlPlaneId"`
		RouterFlavor   model.RouterFlavor    `json:"routerFlavor"`
		TotalRoutes    int                   `json:"totalRoutes"`
		TotalFindings  int                   `json:"totalFindings"`
		Summary        model.SeveritySummary `json:"summary"`
		Findings       []*model.Finding      `json:"findings"`
	}{cfg.ControlPlaneID, flavor, len(data.Routes), len(findings), model.Summarize(findings), findings})
	if err != nil {
		return nil, nil, err
	}
	return toolSuccess(res)
}

func (s *Server) handleCollisions(ctx context.Context, _ *sdk.CallToolRequest, args CollisionsArgs) (*sdk.CallToolResult, any, error) {
	analysisArgs := args.toAnalysisArgs()
	if err := analysisArgs.validate(); err != nil {
		return toolError(err)
	}
	cfg, data, err := s.load(ctx, args.TargetArgs)
	if err != nil {
		return toolError(err)
	}
	flavor := resolveFlavor(args.Flavor, data)
	preds, err := analysisArgs.predicates()
	if err != nil {
		return toolError(err)
	}
	var collisions []*model.Finding
	for _, f := range analyzer.Analyze(ctx, data, analyzer.Options{Flavor: flavor, ExcludeInfo: true}) {
		if f.Type == model.FindingShadowing || f.Type == model.FindingCollision {
			collisions = append(collisions, f)
		}
	}
	findings := filter.Apply(collisions, preds, data.Services)
	if findings == nil {
		findings = []*model.Finding{}
	}
	res, err := toJSON(struct {
		ControlPlaneID string             `json:"controlPlaneId"`
		RouterFlavor   model.RouterFlavor `json:"routerFlavor"`
		TotalRoutes    int                `json:"totalRoutes"`
		TotalFindings  int                `json:"totalFindings"`
		Findings       []*model.Finding   `json:"findings"`
	}{cfg.ControlPlaneID, flavor, len(data.Routes), len(findings), findings})
	if err != nil {
		return nil, nil, err
	}
	return toolSuccess(res)
}

type routeSummary struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	RegexPriority *int     `json:"regex_priority,omitempty"`
}

func (s *Server) handleExplain(ctx context.Context, _ *sdk.CallToolRequest, args ExplainArgs) (*sdk.CallToolResult, any, error) {
	if err := args.validate(); err != nil {
		return toolError(err)
	}
	cfg, data, err := s.load(ctx, args.TargetArgs)
	if err != nil {
		return toolError(err)
	}
	flavor := resolveFlavor(args.Flavor, data)
	sorted := s.cache.SortedRoutes(CacheKey(cfg), data, flavor)

	normalized := urlutil.NormalizePath(args.Path)
	reqHeaders := args.Headers
	if reqHeaders != nil {
		reqHeaders = make(map[string]string, len(args.Headers))
		for k, v := range args.Headers {
			reqHeaders[strings.ToLower(k)] = v
		}
	}
	res := router.SimulateRequest(sorted, router.SimRequest{
		Method:     strutil.FirstNonEmpty(args.Method, "GET"),
		Host:       strutil.FirstNonEmpty(args.Host, "example.com"),
		Path:       normalized,
		Headers:    reqHeaders,
		SNI:        args.SNI,
		SourceIP:   args.SourceIP,
		SourcePort: args.SourcePort,
		DestIP:     args.DestIP,
		DestPort:   args.DestPort,
	})

	var winner *routeSummary
	if res.Winner != nil {
		r := res.Winner.Route
		rp := r.RegexPriority
		winner = &routeSummary{ID: r.ID, Name: r.Name, Paths: r.Paths, RegexPriority: &rp}
	}
	others := []routeSummary{}
	if len(res.MatchedRoutes) > 1 {
		for _, mr := range res.MatchedRoutes[1:] {
			others = append(others, routeSummary{ID: mr.Route.ID, Name: mr.Route.Name, Paths: mr.Route.Paths})
		}
	}
	pathNormalized := ""
	if normalized != args.Path {
		pathNormalized = normalized
	}
	resText, err := toJSON(struct {
		ControlPlaneID     string             `json:"controlPlaneId"`
		RouterFlavor       model.RouterFlavor `json:"routerFlavor"`
		Request            router.SimRequest  `json:"request"`
		PathNormalized     string             `json:"pathNormalized,omitempty"`
		Matched            bool               `json:"matched"`
		Winner             *routeSummary      `json:"winner"`
		Explanation        []string           `json:"explanation"`
		OtherMatchedRoutes []routeSummary     `json:"otherMatchedRoutes"`
	}{cfg.ControlPlaneID, flavor, res.Request, pathNormalized, res.Winner != nil, winner, res.Explanation(), others})
	if err != nil {
		return nil, nil, err
	}
	return toolSuccess(resText)
}

func (s *Server) handleRouteConfig(ctx context.Context, _ *sdk.CallToolRequest, args RouteConfigArgs) (*sdk.CallToolResult, any, error) {
	if err := args.validate(); err != nil {
		return toolError(err)
	}
	cfg, data, err := s.load(ctx, args.TargetArgs)
	if err != nil {
		return toolError(err)
	}
	res, err := toJSON(struct {
		ControlPlaneID string               `json:"controlPlaneId"`
		RouterFlavor   model.RouterFlavor   `json:"routerFlavor,omitempty"`
		TotalRoutes    int                  `json:"totalRoutes"`
		TotalServices  int                  `json:"totalServices"`
		Routes         []*model.KongRoute   `json:"routes"`
		Services       []*model.KongService `json:"services"`
	}{cfg.ControlPlaneID, data.RouterFlavor, len(data.Routes), data.Services.Len(), data.Routes, data.Services.All()})
	if err != nil {
		return nil, nil, err
	}
	return toolSuccess(res)
}

func toJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
