package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/paambaati/kongcheck/internal/analyzer"
	"github.com/paambaati/kongcheck/internal/filter"
	"github.com/paambaati/kongcheck/internal/format"
	"github.com/paambaati/kongcheck/internal/model"
)

func (a *App) newAnalyzeCommand(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "analyze",
		Short: "Run full audit of suspicious regexes, collisions, and shadowing",
		Example: "  kongcheck analyze --control-plane-id <id> --token $TOKEN\n" +
			"  kongcheck analyze --control-plane-id <id> --token $TOKEN --filter tag:team-a --filter service:payments-svc",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runAudit(cmd, g, false)
		},
	}
}

func (a *App) newCollisionsCommand(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "collisions",
		Short: "Show only routes that overlap or shadow each other (no suspicious-regex findings)",
		Example: "  kongcheck collisions --control-plane-id <id> --token $TOKEN --format json\n" +
			"  kongcheck collisions --control-plane-id <id> --token $TOKEN --filter path:/payments",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runAudit(cmd, g, true)
		},
	}
}

// runAudit implements analyze and collisions.
func (a *App) runAudit(cmd *cobra.Command, g *globalFlags, collisionsOnly bool) error {
	preds, err := filter.ParseAll(g.filters)
	if err != nil {
		return fail("%s", err.Error())
	}

	spin := newSpinner(a.Stdout, a.StdoutIsTTY && !g.verbose)
	spin.Start("Fetching config...")
	data, err := a.loadData(cmd.Context(), g)
	if err != nil {
		spin.Stop()
		return err
	}
	spin.Update("Analysing routes...")

	flavor := g.flavorFor(data)
	findings := analyzer.Analyze(data, analyzer.Options{Flavor: flavor})
	if collisionsOnly {
		kept := findings[:0:0]
		for _, f := range findings {
			if f.Type == model.FindingShadowing || f.Type == model.FindingCollision {
				kept = append(kept, f)
			}
		}
		findings = kept
	}
	findings = filter.Apply(findings, preds, data.Services)

	visible := findings
	if !g.showInfo {
		visible = make([]*model.Finding, 0, len(findings))
		for _, f := range findings {
			if f.Severity != model.SeverityInfo {
				visible = append(visible, f)
			}
		}
	}
	spin.Stop()

	return a.printFindings(visible, flavor, g, format.ContextFor(data), len(findings)-len(visible))
}

// printFindings writes findings in the requested format and applies --fail-on.
func (a *App) printFindings(findings []*model.Finding, flavor model.RouterFlavor, g *globalFlags, ctx *format.KonnectContext, hiddenInfo int) error {
	var out string
	switch g.format {
	case "json":
		s, err := format.JSON(findings, flavor, ctx)
		if err != nil {
			return err
		}
		out = s
	case "csv":
		out = format.CSV(findings, ctx)
	default:
		out = format.Human(findings, flavor, ctx, format.HumanOptions{
			Color:      a.StdoutIsTTY && a.Getenv("NO_COLOR") == "",
			HiddenInfo: hiddenInfo,
		})
	}
	fmt.Fprintln(a.Stdout, out)

	if g.failOn != "" && format.ShouldFail(findings, model.Severity(strings.ToUpper(g.failOn))) {
		return &exitError{code: 1}
	}
	return nil
}
