package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/paambaati/kongcheck/internal/client"
	"github.com/paambaati/kongcheck/internal/format"
	"github.com/paambaati/kongcheck/internal/mcp"
	"github.com/paambaati/kongcheck/internal/version"
)

func (a *App) newDumpCommand(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "dump-config [output-file]",
		Short: `Fetch and save route/service config to JSON. Writes to stdout when no file is given (or when "-" is passed).`,
		Example: "  kongcheck dump-config --control-plane-id <id> --token $TOKEN\n" +
			"  kongcheck dump-config - --control-plane-id <id> --token $TOKEN | kongcheck analyze --file -\n" +
			"  kongcheck dump-config routes-dump.json --control-plane-id <id> --token $TOKEN",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outputFile := ""
			if len(args) > 0 {
				outputFile = args[0]
			}

			cfg, err := a.konnectConfig(g)
			if err != nil {
				return err
			}
			spin := newSpinner(a.Stdout, a.StdoutIsTTY && !g.verbose)
			spin.Start("Fetching config...")
			data, err := a.Fetch(cmd.Context(), cfg, client.Options{Verbose: g.verbose, Log: a.Stderr})
			spin.Stop()
			if err != nil {
				return err
			}

			b, err := json.MarshalIndent(client.NewLocalConfigDump(data), "", "  ")
			if err != nil {
				return err
			}

			if outputFile == "" || outputFile == "-" {
				fmt.Fprintln(a.Stdout, string(b))
				if a.StdoutIsTTY {
					fmt.Fprintln(a.Stdout, format.DumpSummary(data))
				}
				return nil
			}
			if err := os.WriteFile(outputFile, b, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Config saved to %s. %s\n", outputFile, format.DumpSummary(data))
			return nil
		},
	}
}

func (a *App) newMCPCommand() *cobra.Command {
	var cacheTTL string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the kongcheck MCP server (stdio transport) for use with AI agents",
		Example: "  # Typically invoked by the MCP host, not manually\n" +
			"  kongcheck mcp\n" +
			"  kongcheck mcp --cache-ttl 120   # cache for 2 minutes\n" +
			"  kongcheck mcp --cache-ttl 0     # disable caching",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ttl := 60 * time.Second
			if cmd.Flags().Changed("cache-ttl") {
				secs, err := strconv.ParseFloat(cacheTTL, 64)
				if err != nil || secs < 0 {
					return fail("--cache-ttl must be a non-negative number of seconds.")
				}
				ttl = time.Duration(secs * float64(time.Second))
			}
			return mcp.Serve(mcp.Options{Name: version.Name, Version: version.Version, CacheTTL: ttl})
		},
	}
	cmd.Flags().StringVar(&cacheTTL, "cache-ttl", "", "Seconds to cache fetched Konnect config per control-plane within a session. 0 disables caching. (default: 60)")
	return cmd
}
