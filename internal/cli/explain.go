package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/paambaati/kongcheck/internal/format"
	"github.com/paambaati/kongcheck/internal/router"
	"github.com/paambaati/kongcheck/internal/urlutil"
)

type explainFlags struct {
	method, host, path    string
	headers               []string
	sni, sourceIP, destIP string
	sourcePort, destPort  string
}

func (a *App) newExplainCommand(g *globalFlags) *cobra.Command {
	f := &explainFlags{}
	cmd := &cobra.Command{
		Use:   "explain-request",
		Short: "Simulate a specific request and show which route wins and why",
		Example: "  kongcheck explain-request --control-plane-id <id> --token $TOKEN --method GET --host example.com --path /payments-v2/docs\n" +
			"  # Simulate a stream-route connection (SNI + source IP)\n" +
			"  kongcheck explain-request --path /tcp/service --sni api.example.com --source-ip 10.0.0.5",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runExplain(cmd, g, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.method, "method", "GET", "HTTP method, e.g. GET")
	fl.StringVar(&f.host, "host", "example.com", "Host header, e.g. api.example.com")
	fl.StringVar(&f.path, "path", "", "Request path, e.g. /payments-v2/docs")
	fl.StringArrayVar(&f.headers, "header", nil, "Request header as key:value (repeat for multiple), e.g. --header x-env:dev")
	fl.StringVar(&f.sni, "sni", "", "TLS SNI value for stream-route simulation, e.g. api.example.com")
	fl.StringVar(&f.sourceIP, "source-ip", "", "Source IP address for stream-route simulation, e.g. 10.0.0.5")
	fl.StringVar(&f.sourcePort, "source-port", "", "Source TCP/UDP port for stream-route simulation, e.g. 54321")
	fl.StringVar(&f.destIP, "dest-ip", "", "Destination IP address for stream-route simulation, e.g. 192.168.1.1")
	fl.StringVar(&f.destPort, "dest-port", "", "Destination TCP/UDP port for stream-route simulation, e.g. 5432")
	return cmd
}

// orderedHeaders keeps request headers in first-seen order for display.
type orderedHeaders struct {
	keys   []string
	values map[string]string
}

func (a *App) runExplain(cmd *cobra.Command, g *globalFlags, f *explainFlags) error {
	flags := cmd.Flags()
	if f.path == "" {
		return fail("--path is required for explain-request.")
	}

	// Normalise the path the way Kong does before matching, and say so when
	// that changed the value.
	path := urlutil.NormalizePath(f.path)
	if path != f.path {
		fmt.Fprintf(a.Stderr, "Warning: --path was normalized from '%s' to '%s'.\n", f.path, path)
	}

	hdrs := orderedHeaders{values: map[string]string{}}
	for _, h := range f.headers {
		i := strings.IndexByte(h, ':')
		if i < 1 {
			return fail("--header value must be key:value, got '%s'", h)
		}
		k := strings.ToLower(strings.TrimSpace(h[:i]))
		if _, seen := hdrs.values[k]; !seen {
			hdrs.keys = append(hdrs.keys, k)
		}
		hdrs.values[k] = strings.TrimSpace(h[i+1:])
	}

	sourcePort, err := parsePortFlag("--source-port", f.sourcePort, flags.Changed("source-port"))
	if err != nil {
		return err
	}
	destPort, err := parsePortFlag("--dest-port", f.destPort, flags.Changed("dest-port"))
	if err != nil {
		return err
	}

	spin := newSpinner(a.Stdout, a.StdoutIsTTY && !g.verbose)
	spin.Start("Fetching config...")
	data, err := a.loadData(cmd.Context(), g)
	spin.Stop()
	if err != nil {
		return err
	}

	sorted := router.SortRoutes(router.MarshalRoutes(data, g.flavorFor(data)))

	// Headers are always passed, so header-constrained routes are evaluated
	// strictly; L4 fields are only set when their flag was given.
	req := router.SimRequest{
		Method:  f.method,
		Host:    f.host,
		Path:    path,
		Headers: hdrs.values,
	}
	if flags.Changed("sni") {
		req.SNI = &f.sni
	}
	if flags.Changed("source-ip") {
		req.SourceIP = &f.sourceIP
		req.SourcePort = sourcePort
	}
	if flags.Changed("dest-ip") {
		req.DestIP = &f.destIP
		req.DestPort = destPort
	}
	res := router.SimulateRequest(sorted, req)
	ctx := format.ContextFor(data)

	if g.format == "json" {
		return a.printExplainJSON(res, ctx)
	}

	var parts []string
	if len(hdrs.keys) > 0 {
		kv := make([]string, len(hdrs.keys))
		for i, k := range hdrs.keys {
			kv[i] = k + "=" + hdrs.values[k]
		}
		parts = append(parts, "headers: "+strings.Join(kv, ", "))
	}
	if req.SNI != nil {
		parts = append(parts, "sni: "+*req.SNI)
	}
	if req.SourceIP != nil {
		parts = append(parts, "source: "+*req.SourceIP+portSuffix(sourcePort))
	}
	if req.DestIP != nil {
		parts = append(parts, "dest: "+*req.DestIP+portSuffix(destPort))
	}
	simulatedWith := ""
	if len(parts) > 0 {
		simulatedWith = "  " + strings.Join(parts, "  ")
	}

	out := a.Stdout
	if res.Winner == nil {
		fmt.Fprintf(out, "No route matched: %s %s\n", res.Request.Method, res.Request.Path)
		if simulatedWith != "" {
			fmt.Fprintln(out, simulatedWith)
		}
		return nil
	}

	w := res.Winner.Route
	line := fmt.Sprintf("\nWinning route: %s  (id: %s)", w.DisplayName(), w.ID)
	if u := format.RouteURL(w.ID, ctx); u != "" {
		line += "\n               " + u
	}
	fmt.Fprintln(out, line)
	if simulatedWith != "" {
		fmt.Fprintln(out, "\nSimulated with"+simulatedWith)
	}
	fmt.Fprintln(out, "\nExplanation:")
	for _, l := range res.Explanation() {
		fmt.Fprintln(out, "  "+l)
	}
	if others := res.MatchedRoutes[1:]; len(others) > 0 {
		fmt.Fprintf(out, "\n%d other route(s) also matched:\n", len(others))
		for _, mr := range others {
			line := fmt.Sprintf("  - %s  paths: %s", mr.Route.DisplayName(), strings.Join(mr.Route.Paths, ", "))
			if u := format.RouteURL(mr.Route.ID, ctx); u != "" {
				line += "\n    " + u
			}
			fmt.Fprintln(out, line)
		}
	}
	return nil
}

// printExplainJSON writes the simulation result, adding `_konnectUrl` to
// every matched route when a Konnect context is available. `_konnectUrl` is
// spliced in after the route's other fields via raw bytes, preserving their
// original marshal order — round-tripping through a map[string]json.RawMessage
// would force encoding/json to alphabetize every key on re-marshal.
func (a *App) printExplainJSON(res *router.SimResult, ctx *format.KonnectContext) error {
	withURL := func(mr *router.MarshalledRoute) (json.RawMessage, error) {
		b, err := json.Marshal(mr)
		if err != nil {
			return nil, err
		}
		u := format.RouteURL(mr.Route.ID, ctx)
		if u == "" || len(b) == 0 || b[len(b)-1] != '}' {
			return b, nil
		}
		urlJSON, err := json.Marshal(u)
		if err != nil {
			return nil, err
		}
		out := make(json.RawMessage, 0, len(b)+len(urlJSON)+len(`,"_konnectUrl":`))
		out = append(out, b[:len(b)-1]...)
		out = append(out, `,"_konnectUrl":`...)
		out = append(out, urlJSON...)
		out = append(out, '}')
		return out, nil
	}

	matched := make([]json.RawMessage, 0, len(res.MatchedRoutes))
	for _, mr := range res.MatchedRoutes {
		m, err := withURL(mr)
		if err != nil {
			return err
		}
		matched = append(matched, m)
	}
	var winner json.RawMessage
	if res.Winner != nil {
		winner = matched[0]
	}

	b, err := json.MarshalIndent(struct {
		Request       router.SimRequest `json:"request"`
		MatchedRoutes []json.RawMessage `json:"matchedRoutes"`
		Winner        json.RawMessage   `json:"winner"`
		Explanation   []string          `json:"explanation"`
	}{res.Request, matched, winner, res.Explanation()}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, string(b))
	return nil
}

// parsePortFlag validates an optional port flag (an integer in 1..65535).
func parsePortFlag(name, raw string, set bool) (*int, error) {
	if !set {
		return nil, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > 65535 {
		return nil, fail("%s must be an integer between 1 and 65535, got '%s'", name, raw)
	}
	return &n, nil
}

func portSuffix(p *int) string {
	if p == nil {
		return ""
	}
	return ":" + strconv.Itoa(*p)
}
