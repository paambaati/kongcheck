// Package cli implements the kongcheck command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/paambaati/kongcheck/internal/client"
	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/strutil"
	"github.com/paambaati/kongcheck/internal/version"
)

// App is one CLI invocation's environment. Streams and the environment are
// injectable so commands can be exercised end-to-end in tests.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Getenv looks up environment variables (defaults to os.Getenv).
	Getenv func(string) string
	// StdoutIsTTY enables colors, spinners and TTY-only summaries.
	StdoutIsTTY bool
	// Fetch fetches a live control plane (defaults to the Konnect API).
	Fetch func(ctx context.Context, cfg model.KonnectConfig, opts client.Options) (*model.KonnectData, error)
	// LoadFile loads an offline dump (defaults to client.LoadLocalConfig).
	LoadFile func(path string) (*model.KonnectData, error)
}

// NewApp returns an App wired to the real process environment.
func NewApp() *App {
	return &App{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Getenv:      os.Getenv,
		StdoutIsTTY: isTerminal(os.Stdout),
		Fetch:       client.FetchKonnectConfig,
		LoadFile:    client.LoadLocalConfig,
	}
}

// exitError ends the program with a status code; an empty message means the
// reason has already been reported (e.g. --fail-on).
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(format string, a ...any) error {
	return &exitError{code: 1, msg: fmt.Sprintf(format, a...)}
}

// Run executes the CLI with args (excluding the program name) and returns the
// process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	root := a.newRootCommand()
	root.SetArgs(args)
	root.SetIn(a.Stdin)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(a.Stderr, "Error: "+ee.msg)
		}
		return ee.code
	}
	fmt.Fprintln(a.Stderr, "Error: "+err.Error())
	return 1
}

// globalFlags are accepted by every command.
type globalFlags struct {
	token          string
	controlPlaneID string
	region         string
	format         string
	failOn         string
	flavor         string
	file           string
	verbose        bool
	showInfo       bool
	filters        []string
}

func (a *App) newRootCommand() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:           version.Name,
		Short:         "Detect Kong Konnect route collisions and shadowing",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fail("Invalid command: %s", strings.Join(args, " "))
			}
			return cmd.Help()
		},
	}
	root.SetVersionTemplate(version.String() + "\n")
	root.CompletionOptions.DisableDefaultCmd = true

	pf := root.PersistentFlags()
	pf.StringVar(&g.token, "token", "", "Konnect API token (or set KONNECT_TOKEN env var)")
	pf.StringVar(&g.controlPlaneID, "control-plane-id", "", "Konnect control plane UUID (or set KONNECT_CONTROL_PLANE_ID env var)")
	pf.StringVar(&g.region, "region", "us", "Konnect region: us | eu | au | me | in | sg")
	pf.StringVar(&g.format, "format", "human", "Output format: human | json | csv")
	pf.StringVar(&g.failOn, "fail-on", "", "Exit non-zero if findings at or above this severity: HIGH | MEDIUM | LOW | INFO")
	pf.StringVar(&g.flavor, "flavor", "", "Override router flavor: traditional | traditional_compatible | expressions")
	pf.StringVar(&g.file, "file", "", `Load config from a local JSON dump file instead of the Konnect API ("-" reads stdin)`)
	pf.BoolVar(&g.verbose, "verbose", false, "Print progress information to stderr")
	pf.BoolVar(&g.showInfo, "show-info", false, "Include INFO-level findings (universal catch-all routes) in output")
	pf.StringArrayVar(&g.filters, "filter", nil, "Filter findings by route attribute (repeatable). Format: key:value. "+
		"Keys: path, name, service, tag, id. AND across different keys; OR within the same key. "+
		"A finding is shown when ANY involved route matches.")

	root.AddCommand(
		a.newAnalyzeCommand(g),
		a.newCollisionsCommand(g),
		a.newExplainCommand(g),
		a.newDumpCommand(g),
		a.newMCPCommand(),
	)
	return root
}

// konnectConfig resolves connection settings from flags and the environment.
func (a *App) konnectConfig(g *globalFlags) (model.KonnectConfig, error) {
	token := strutil.FirstNonEmpty(g.token, a.Getenv("KONNECT_TOKEN"))
	if token == "" {
		return model.KonnectConfig{}, fail("--token or KONNECT_TOKEN environment variable is required.")
	}
	cpID := strutil.FirstNonEmpty(g.controlPlaneID, a.Getenv("KONNECT_CONTROL_PLANE_ID"))
	if cpID == "" {
		return model.KonnectConfig{}, fail("--control-plane-id or KONNECT_CONTROL_PLANE_ID environment variable is required.")
	}
	return model.KonnectConfig{Token: token, ControlPlaneID: cpID, Region: strutil.FirstNonEmpty(g.region, "us")}, nil
}

// loadData reads the config from --file, or fetches it from Konnect.
func (a *App) loadData(ctx context.Context, g *globalFlags) (*model.KonnectData, error) {
	if g.file != "" {
		if g.verbose {
			fmt.Fprintf(a.Stderr, "Loading config from %s ...\n", g.file)
		}
		return a.LoadFile(g.file)
	}
	cfg, err := a.konnectConfig(g)
	if err != nil {
		return nil, err
	}
	return a.Fetch(ctx, cfg, client.Options{Verbose: g.verbose, Log: a.Stderr})
}

// flavor applies the --flavor override, else the detected flavor, else
// traditional. Unknown --flavor values are ignored.
func (g *globalFlags) flavorFor(data *model.KonnectData) model.RouterFlavor {
	if f := model.ParseFlavor(g.flavor); f != "" {
		return f
	}
	if data.RouterFlavor != "" {
		return data.RouterFlavor
	}
	return model.FlavorTraditional
}

// isTerminal reports whether f is a character device (a terminal).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
