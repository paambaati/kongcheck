// Package format renders analysis findings as human-readable terminal output,
// JSON, or CSV. All formats expose the same information.
//
// Human rendering sanitizes every Kong-supplied string (route name/paths/ID,
// finding reason/suggestion text, sample requests) with
// strutil.SanitizeControlChars before writing it to the terminal: a
// compromised or malicious control plane — or an attacker with limited
// route-creation privileges — could embed raw ANSI/terminal escape sequences
// in a route's name or paths, which would otherwise let it manipulate the
// terminal (move the cursor, hide/rewrite prior output, or worse on
// terminals with OSC-based features) when the operator runs `kongcheck
// analyze`. JSON and CSV output are unaffected: they are not executed as
// terminal control sequences, and CSV already has its own formula-injection
// defense (see csvQuoted).
package format

import (
	"fmt"
	"strings"
	"time"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/strutil"
)

// KonnectContext carries the control plane identity used to build Konnect UI
// deep-links. It is nil in offline (--file) mode.
type KonnectContext struct {
	ControlPlaneID string
	Region         string
}

// ContextFor returns the Konnect context of live-fetched data, or nil.
func ContextFor(data *model.KonnectData) *KonnectContext {
	if data.ControlPlaneID == "" || data.Region == "" {
		return nil
	}
	return &KonnectContext{ControlPlaneID: data.ControlPlaneID, Region: data.Region}
}

// RouteURL returns the Konnect UI URL for a route, or "" without a context.
func RouteURL(routeID string, ctx *KonnectContext) string {
	if ctx == nil {
		return ""
	}
	return fmt.Sprintf("https://cloud.konghq.com/%s/gateway-manager/%s/routes/%s", ctx.Region, ctx.ControlPlaneID, routeID)
}

// ShouldFail reports whether any finding is at or above threshold. An unknown
// threshold never fails.
func ShouldFail(findings []*model.Finding, threshold model.Severity) bool {
	t := threshold.Rank()
	for _, f := range findings {
		if r := f.Severity.Rank(); r >= 0 && r <= t {
			return true
		}
	}
	return false
}

// HighestSeverity returns the most severe level present, or "" when empty.
func HighestSeverity(findings []*model.Finding) model.Severity {
	best := -1
	for _, f := range findings {
		if r := f.Severity.Rank(); r >= 0 && (best < 0 || r < best) {
			best = r
		}
	}
	if best < 0 {
		return ""
	}
	return model.Severities[best]
}

// DumpSummary is the one-line summary printed after `dump-config`.
func DumpSummary(data *model.KonnectData) string {
	s := fmt.Sprintf("Dumped %d route(s) and %d service(s) on control plane ID %s.",
		len(data.Routes), data.Services.Len(), data.ControlPlaneID)
	if data.RouterFlavor != "" {
		return s + " Detected router flavor: " + string(data.RouterFlavor) + "."
	}
	return s + " Router flavor: unknown (defaulting to 'traditional' for analysis)."
}

// ISOTimestamp formats t like JavaScript's Date.prototype.toISOString.
func ISOTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// RelativeDate renders the time elapsed between date and now, e.g.
// "3 days ago".
func RelativeDate(date, now time.Time) string {
	sec := int64(now.Sub(date) / time.Second)
	minutes, hours := sec/60, sec/3600
	days := hours / 24
	unit := func(n int64, name string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s ago", n, name)
		}
		return fmt.Sprintf("%d %ss ago", n, name)
	}
	switch {
	case sec < 60:
		return "just now"
	case minutes < 60:
		return unit(minutes, "minute")
	case hours < 24:
		return unit(hours, "hour")
	case days < 30:
		return unit(days, "day")
	}
	months := days / 30
	if months < 12 {
		return unit(months, "month")
	}
	return unit(months/12, "year")
}

// palette applies ANSI styles when enabled.
type palette struct{ enabled bool }

// sanitizeAll strips terminal control characters from every element of ss,
// used for route path lists (see strutil.SanitizeControlChars).
func sanitizeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strutil.SanitizeControlChars(s)
	}
	return out
}

const reset = "\x1b[0m"

func (p palette) wrap(code, s string) string {
	if !p.enabled {
		return s
	}
	return code + s + reset
}

func (p palette) bold(s string) string   { return p.wrap("\x1b[1m", s) }
func (p palette) dim(s string) string    { return p.wrap("\x1b[2m", s) }
func (p palette) red(s string) string    { return p.wrap("\x1b[31m", s) }
func (p palette) yellow(s string) string { return p.wrap("\x1b[33m", s) }
func (p palette) cyan(s string) string   { return p.wrap("\x1b[36m", s) }
func (p palette) green(s string) string  { return p.wrap("\x1b[32m", s) }
func (p palette) gray(s string) string   { return p.wrap("\x1b[90m", s) }

func (p palette) severity(s model.Severity) func(string) string {
	switch s {
	case model.SeverityHigh:
		return p.red
	case model.SeverityMedium:
		return p.yellow
	case model.SeverityLow:
		return p.cyan
	}
	return p.gray
}

// HumanOptions configures Human.
type HumanOptions struct {
	// Color enables ANSI styling (typically: stdout is a terminal).
	Color bool
	// Now is the report time (defaults to time.Now()).
	Now time.Time
	// HiddenInfo is the number of INFO findings filtered out of the list,
	// reported in the summary footer.
	HiddenInfo int
}

// Human renders findings as a terminal report.
func Human(findings []*model.Finding, flavor model.RouterFlavor, ctx *KonnectContext, opts HumanOptions) string {
	c := palette{enabled: opts.Color}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	var header []string
	if ctx != nil {
		cpURL := fmt.Sprintf("https://cloud.konghq.com/%s/gateway-manager/%s", ctx.Region, ctx.ControlPlaneID)
		header = append(header,
			c.bold("Control plane:")+"  "+ctx.ControlPlaneID,
			c.bold("Konnect link: ")+"  "+cpURL,
			c.bold("Analysed at:  ")+"  "+ISOTimestamp(now),
			"")
	}

	if len(findings) == 0 {
		return strings.Join(header, "\n") + c.green("✓ No route findings. Your routing configuration looks clean.\n")
	}

	lines := append([]string{}, header...)
	lines = append(lines, c.bold(fmt.Sprintf("Kong Route Audit – %d finding(s)", len(findings)))+
		c.dim("  router_flavor: "+string(flavor))+"\n")

	for _, f := range findings {
		lines = append(lines,
			c.dim(strings.Repeat("─", 60)),
			c.severity(f.Severity)(c.bold("["+string(f.Severity)+"]"))+"  "+string(f.Type)+c.dim("  ("+string(f.RouterFlavor)+")"),
			"")

		for idx, r := range f.Routes {
			var tag string
			switch {
			case f.Type == model.FindingUniversalMatcher:
				tag = c.gray("catch-all")
			case idx == 0:
				tag = c.bold("winner  ")
			default:
				tag = c.dim("shadowed")
			}
			paths := strings.Join(sanitizeAll(r.Paths), ", ")
			if paths == "" {
				paths = c.dim("(no paths)")
			}
			name := strutil.SanitizeControlChars(r.Name)
			if name == "" {
				name = c.dim("(unnamed)")
			}
			line := "  " + tag + "  " + c.bold(name) + c.dim("  id: "+strutil.SanitizeControlChars(r.ID)) +
				"\n          paths: " + paths +
				fmt.Sprintf("  regex_priority: %d", r.RegexPriority)
			if r.CreatedAt != nil && *r.CreatedAt != 0 {
				created := time.Unix(*r.CreatedAt, 0)
				line += "  created: " + ISOTimestamp(created) + " " + c.dim("("+RelativeDate(created, now)+")")
			}
			if u := RouteURL(r.ID, ctx); u != "" {
				line += "\n          " + c.dim(u)
			}
			lines = append(lines, line)
		}
		lines = append(lines, "")

		if len(f.Samples) > 0 {
			samples := make([]string, len(f.Samples))
			for i, s := range f.Samples {
				samples[i] = c.cyan(strutil.SanitizeControlChars(s))
			}
			lines = append(lines, "  Sample requests: "+strings.Join(samples, ", "))
		}
		if f.WinnerID != "" {
			winnerName := f.WinnerID
			for _, r := range f.Routes {
				if r.ID == f.WinnerID {
					if r.Name != "" {
						winnerName = r.Name
					}
					break
				}
			}
			winnerName = strutil.SanitizeControlChars(winnerName)
			lines = append(lines, "  Winning route:   "+c.bold(winnerName)+"  "+c.dim("(id: "+strutil.SanitizeControlChars(f.WinnerID)+")"))
		}

		if len(f.Reason) > 0 {
			lines = append(lines, "", "  Why:")
			for _, r := range f.Reason {
				lines = append(lines, "    "+c.dim("–")+" "+strutil.SanitizeControlChars(r))
			}
		}
		if len(f.Suggestions) > 0 {
			lines = append(lines, "", "  Suggested fixes:")
			for _, s := range f.Suggestions {
				lines = append(lines, "    "+c.green("→")+" "+c.bold(strutil.SanitizeControlChars(s)))
			}
		}
		lines = append(lines, "")
	}

	counts := model.CountBySeverity(findings)
	lines = append(lines, c.bold("Summary:")+
		"  HIGH: "+c.red(fmt.Sprint(counts[model.SeverityHigh]))+
		"  MEDIUM: "+c.yellow(fmt.Sprint(counts[model.SeverityMedium]))+
		"  LOW: "+c.cyan(fmt.Sprint(counts[model.SeverityLow]))+
		"  INFO: "+c.gray(fmt.Sprint(counts[model.SeverityInfo]+opts.HiddenInfo)))
	if opts.HiddenInfo > 0 {
		lines = append(lines, c.dim(fmt.Sprintf("(%d INFO finding(s) not shown – rerun with --show-info to expand)", opts.HiddenInfo)))
	}
	return strings.Join(lines, "\n") + "\n"
}
