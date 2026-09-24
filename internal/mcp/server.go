package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

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

// Tool represents a registered MCP tool.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	handler     func(ctx context.Context, arguments json.RawMessage) (string, error)
}

// Server holds the state and tool handlers of an MCP server session.
type Server struct {
	name     string
	version  string
	cache    *Cache
	cacheTTL time.Duration
	fetch    FetchFunc
	tools    []Tool
	toolMap  map[string]Tool
}

// Options configures the MCP server.
type Options struct {
	// Name and Version identify the server to clients.
	Name, Version string
	// CacheTTL is how long fetched configs are reused; 0 disables caching.
	CacheTTL time.Duration
	// Fetch overrides how configs are fetched (defaults to the Konnect API).
	Fetch FetchFunc
}

// New builds the MCP server with all tools registered.
func New(opts Options) *Server {
	s := &Server{
		name:     opts.Name,
		version:  opts.Version,
		cache:    NewCache(),
		cacheTTL: opts.CacheTTL,
		fetch:    opts.Fetch,
		toolMap:  make(map[string]Tool),
	}
	if s.fetch == nil {
		s.fetch = func(ctx context.Context, cfg model.KonnectConfig) (*model.KonnectData, error) {
			return client.FetchKonnectConfig(ctx, cfg, client.Options{})
		}
	}

	s.addTool(Tool{
		Name:        "analyze_routes",
		Description: "Run a full four-pass audit of a Konnect control plane: suspicious regex paths, route collisions, shadowing, and (optionally) universal catch-all routes.",
		InputSchema: analyzeSchema,
		handler:     s.handleAnalyze,
	})
	s.addTool(Tool{
		Name:        "get_collisions",
		Description: "Return only shadowing and collision findings for a Konnect control plane. Excludes suspicious-regex findings.",
		InputSchema: collisionsSchema,
		handler:     s.handleCollisions,
	})
	s.addTool(Tool{
		Name:        "explain_request",
		Description: "Simulate a specific HTTP or TCP/TLS stream request against a Konnect control plane and return the winning route with a step-by-step explanation of why it won. For stream routes, supply sni / sourceIp / sourcePort / destIp / destPort as needed. When an L4 field is omitted, the corresponding route constraint is skipped (conservative mode: every route is a candidate). The path is normalised before matching: query strings and fragments are stripped and dot-segments are resolved.",
		InputSchema: explainSchema,
		handler:     s.handleExplain,
	})
	s.addTool(Tool{
		Name:        "get_route_config",
		Description: "Fetch the raw routes and services from a Konnect control plane as structured data. Useful when the agent needs to inspect or reason about the full route list directly.",
		InputSchema: routeConfigSchema,
		handler:     s.handleRouteConfig,
	})
	return s
}

func (s *Server) addTool(t Tool) {
	s.tools = append(s.tools, t)
	s.toolMap[t.Name] = t
}

// Serve runs the MCP server over stdio until stdin EOF or context cancellation.
// The context is threaded into every tool handler (and thus Konnect fetches)
// so SIGINT/cancellation aborts in-flight work.
func Serve(ctx context.Context, opts Options) error {
	s := New(opts)
	return s.ServeIO(ctx, os.Stdin, os.Stdout)
}

// JSON-RPC 2.0 messages
type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeIO runs the JSON-RPC loop reading from in and writing to out.
// Cancelling ctx stops between messages and aborts in-flight tool handlers;
// blocked reads on in only end when the reader returns (stdin EOF or close).
func (s *Server) ServeIO(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Allow large messages up to 16MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 16*1024*1024)

	var mu sync.Mutex
	send := func(resp *jsonRPCMessage) error {
		b, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		_, err = fmt.Fprintf(out, "%s\n", b)
		return err
	}

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var req jsonRPCMessage
		if err := json.Unmarshal(line, &req); err != nil {
			// JSON-RPC requires id: null when the id cannot be parsed.
			_ = send(&jsonRPCMessage{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &jsonRPCError{Code: -32700, Message: "Parse error"},
			})
			continue
		}

		// Notifications have no ID
		isNotification := len(req.ID) == 0 || bytes.Equal(req.ID, []byte("null"))

		switch req.Method {
		case "initialize":
			_ = send(&jsonRPCMessage{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					// Fixed protocol revision we implement; clients negotiate
					// down via their own protocolVersion if needed.
					"protocolVersion": "2025-06-18",
					"capabilities": map[string]any{
						"tools": map[string]any{"listChanged": true},
					},
					"serverInfo": map[string]any{
						"name":    s.name,
						"version": s.version,
					},
					"instructions": instructions,
				},
			})

		case "notifications/initialized":
			// Handshake acknowledgement notification, no response required.

		case "ping":
			if !isNotification {
				_ = send(&jsonRPCMessage{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  map[string]any{},
				})
			}

		case "tools/list":
			toolList := make([]map[string]any, len(s.tools))
			for i, t := range s.tools {
				toolList[i] = map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"inputSchema": t.InputSchema,
				}
			}
			_ = send(&jsonRPCMessage{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"tools": toolList,
				},
			})

		case "tools/call":
			var callParams struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &callParams); err != nil {
				_ = send(&jsonRPCMessage{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &jsonRPCError{Code: -32602, Message: "Invalid params"},
				})
				continue
			}

			tool, exists := s.toolMap[callParams.Name]
			if !exists {
				_ = send(&jsonRPCMessage{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &jsonRPCError{Code: -32601, Message: fmt.Sprintf("Tool not found: %s", callParams.Name)},
				})
				continue
			}

			text, err := tool.handler(ctx, callParams.Arguments)
			if err != nil {
				errText, _ := toJSON(map[string]string{"error": client.RedactBearer(err.Error())})
				_ = send(&jsonRPCMessage{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: map[string]any{
						"content": []map[string]any{
							{"type": "text", "text": errText},
						},
						"isError": true,
					},
				})
			} else {
				_ = send(&jsonRPCMessage{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result: map[string]any{
						"content": []map[string]any{
							{"type": "text", "text": text},
						},
					},
				})
			}

		default:
			if !isNotification {
				_ = send(&jsonRPCMessage{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &jsonRPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
				})
			}
		}
	}
	return scanner.Err()
}

// --- arguments & validation -------------------------------------------------

type targetArgs struct {
	ControlPlaneID string `json:"controlPlaneId"`
	Region         string `json:"region"`
}

func (a targetArgs) validate() error {
	if a.ControlPlaneID != "" && !strutil.IsUUID(a.ControlPlaneID) {
		return fmt.Errorf("controlPlaneId: invalid UUID %q", a.ControlPlaneID)
	}
	if a.Region != "" && !slices.Contains(client.RegionCodes(), a.Region) {
		return fmt.Errorf("region: expected one of %s, got %q", strings.Join(client.RegionCodes(), ", "), a.Region)
	}
	return nil
}

type filterArg struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type analysisArgs struct {
	targetArgs
	Flavor      string      `json:"flavor"`
	IncludeInfo bool        `json:"includeInfo"`
	Filter      []filterArg `json:"filter"`
}

func (a analysisArgs) validate() error {
	if err := a.targetArgs.validate(); err != nil {
		return err
	}
	if a.Flavor != "" && model.ParseFlavor(a.Flavor) == "" {
		return fmt.Errorf("flavor: expected one of traditional, traditional_compatible, expressions, got %q", a.Flavor)
	}
	return nil
}

func (a analysisArgs) predicates() ([]filter.Predicate, error) {
	raw := make([]string, len(a.Filter))
	for i, f := range a.Filter {
		raw[i] = f.Key + ":" + f.Value
	}
	return filter.ParseAll(raw)
}

type explainArgs struct {
	targetArgs
	Flavor     string            `json:"flavor"`
	Method     string            `json:"method"`
	Host       string            `json:"host"`
	Path       *string           `json:"path"`
	Headers    map[string]string `json:"headers"`
	SNI        *string           `json:"sni"`
	SourceIP   *string           `json:"sourceIp"`
	SourcePort *float64          `json:"sourcePort"`
	DestIP     *string           `json:"destIp"`
	DestPort   *float64          `json:"destPort"`
}

func portArg(name string, v *float64) (*int, error) {
	if v == nil {
		return nil, nil
	}
	if *v != float64(int(*v)) || *v < 1 || *v > 65535 {
		return nil, fmt.Errorf("%s: expected an integer between 1 and 65535, got %v", name, *v)
	}
	p := int(*v)
	return &p, nil
}

func (s *Server) load(ctx context.Context, t targetArgs) (model.KonnectConfig, *model.KonnectData, error) {
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

func (s *Server) handleAnalyze(ctx context.Context, argsRaw json.RawMessage) (string, error) {
	var args analysisArgs
	if err := bind(argsRaw, &args); err != nil {
		return "", err
	}
	cfg, data, err := s.load(ctx, args.targetArgs)
	if err != nil {
		return "", err
	}
	flavor := resolveFlavor(args.Flavor, data)
	preds, err := args.predicates()
	if err != nil {
		return "", err
	}
	all := analyzer.Analyze(data, analyzer.Options{Flavor: flavor, ExcludeInfo: !args.IncludeInfo})
	findings := filter.Apply(all, preds, data.Services)
	return toJSON(struct {
		ControlPlaneID string                `json:"controlPlaneId"`
		RouterFlavor   model.RouterFlavor    `json:"routerFlavor"`
		TotalRoutes    int                   `json:"totalRoutes"`
		TotalFindings  int                   `json:"totalFindings"`
		Summary        model.SeveritySummary `json:"summary"`
		Findings       []*model.Finding      `json:"findings"`
	}{cfg.ControlPlaneID, flavor, len(data.Routes), len(findings), model.Summarize(findings), findings})
}

func (s *Server) handleCollisions(ctx context.Context, argsRaw json.RawMessage) (string, error) {
	var args analysisArgs
	if err := bind(argsRaw, &args); err != nil {
		return "", err
	}
	cfg, data, err := s.load(ctx, args.targetArgs)
	if err != nil {
		return "", err
	}
	flavor := resolveFlavor(args.Flavor, data)
	preds, err := args.predicates()
	if err != nil {
		return "", err
	}
	var collisions []*model.Finding
	for _, f := range analyzer.Analyze(data, analyzer.Options{Flavor: flavor, ExcludeInfo: true}) {
		if f.Type == model.FindingShadowing || f.Type == model.FindingCollision {
			collisions = append(collisions, f)
		}
	}
	findings := filter.Apply(collisions, preds, data.Services)
	if findings == nil {
		findings = []*model.Finding{}
	}
	return toJSON(struct {
		ControlPlaneID string             `json:"controlPlaneId"`
		RouterFlavor   model.RouterFlavor `json:"routerFlavor"`
		TotalRoutes    int                `json:"totalRoutes"`
		TotalFindings  int                `json:"totalFindings"`
		Findings       []*model.Finding   `json:"findings"`
	}{cfg.ControlPlaneID, flavor, len(data.Routes), len(findings), findings})
}

type routeSummary struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	RegexPriority *int     `json:"regex_priority,omitempty"`
}

func (s *Server) handleExplain(ctx context.Context, argsRaw json.RawMessage) (string, error) {
	var args explainArgs
	if err := bind(argsRaw, &args); err != nil {
		return "", err
	}
	if args.Path == nil {
		return "", fmt.Errorf("path: required")
	}
	if err := (analysisArgs{targetArgs: args.targetArgs, Flavor: args.Flavor}).validate(); err != nil {
		return "", err
	}
	sourcePort, err := portArg("sourcePort", args.SourcePort)
	if err != nil {
		return "", err
	}
	destPort, err := portArg("destPort", args.DestPort)
	if err != nil {
		return "", err
	}

	cfg, data, err := s.load(ctx, args.targetArgs)
	if err != nil {
		return "", err
	}
	flavor := resolveFlavor(args.Flavor, data)
	sorted := s.cache.SortedRoutes(CacheKey(cfg), data, flavor)

	normalized := urlutil.NormalizePath(*args.Path)
	// HTTP header names are case-insensitive; normalise to lowercase so
	// constraints keyed lower (or mixed) always resolve, matching the CLI.
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
		SourcePort: sourcePort,
		DestIP:     args.DestIP,
		DestPort:   destPort,
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
	if normalized != *args.Path {
		pathNormalized = normalized
	}
	return toJSON(struct {
		ControlPlaneID     string             `json:"controlPlaneId"`
		RouterFlavor       model.RouterFlavor `json:"routerFlavor"`
		Request            router.SimRequest  `json:"request"`
		PathNormalized     string             `json:"pathNormalized,omitempty"`
		Matched            bool               `json:"matched"`
		Winner             *routeSummary      `json:"winner"`
		Explanation        []string           `json:"explanation"`
		OtherMatchedRoutes []routeSummary     `json:"otherMatchedRoutes"`
	}{cfg.ControlPlaneID, flavor, res.Request, pathNormalized, res.Winner != nil, winner, res.Explanation(), others})
}

func (s *Server) handleRouteConfig(ctx context.Context, argsRaw json.RawMessage) (string, error) {
	var args targetArgs
	if err := bind(argsRaw, &args); err != nil {
		return "", err
	}
	cfg, data, err := s.load(ctx, args)
	if err != nil {
		return "", err
	}
	return toJSON(struct {
		ControlPlaneID string               `json:"controlPlaneId"`
		RouterFlavor   model.RouterFlavor   `json:"routerFlavor,omitempty"`
		TotalRoutes    int                  `json:"totalRoutes"`
		TotalServices  int                  `json:"totalServices"`
		Routes         []*model.KongRoute   `json:"routes"`
		Services       []*model.KongService `json:"services"`
	}{cfg.ControlPlaneID, data.RouterFlavor, len(data.Routes), data.Services.Len(), data.Routes, data.Services.All()})
}

// --- helpers --------------------------------------------------------------

type validator interface{ validate() error }

func bind(raw json.RawMessage, target any) error {
	if len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("invalid arguments: %w", err)
		}
	}
	if v, ok := target.(validator); ok {
		return v.validate()
	}
	return nil
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
