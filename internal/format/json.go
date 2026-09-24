package format

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/paambaati/kongcheck/internal/model"
)

// LinkedRoute encodes a route with an added `_konnectUrl` key.
type LinkedRoute struct {
	Route *model.KongRoute
	URL   string
}

// MarshalJSON implements json.Marshaler.
func (l LinkedRoute) MarshalJSON() ([]byte, error) {
	m, err := l.Route.ToMap()
	if err != nil {
		return nil, err
	}
	u, err := json.Marshal(l.URL)
	if err != nil {
		return nil, err
	}
	m["_konnectUrl"] = u
	return json.Marshal(m)
}

// jsonFinding mirrors model.Finding with routes that may carry deep-links.
type jsonFinding struct {
	Severity     model.Severity     `json:"severity"`
	Type         model.FindingType  `json:"type"`
	RouterFlavor model.RouterFlavor `json:"routerFlavor"`
	Routes       []any              `json:"routes"`
	Samples      []string           `json:"samples"`
	WinnerID     string             `json:"winnerId,omitempty"`
	Reason       []string           `json:"reason"`
	Suggestions  []string           `json:"suggestions"`
}

// Report is the JSON output document.
type Report struct {
	GeneratedAt   string                `json:"generatedAt"`
	RouterFlavor  model.RouterFlavor    `json:"routerFlavor"`
	TotalFindings int                   `json:"totalFindings"`
	Summary       model.SeveritySummary `json:"summary"`
	Findings      []jsonFinding         `json:"findings"`
}

// NewReport builds the JSON report. With a Konnect context every route gains
// a `_konnectUrl` deep-link.
func NewReport(findings []*model.Finding, flavor model.RouterFlavor, ctx *KonnectContext, now time.Time) Report {
	if now.IsZero() {
		now = time.Now()
	}
	out := make([]jsonFinding, len(findings))
	for i, f := range findings {
		routes := make([]any, len(f.Routes))
		for j, r := range f.Routes {
			if ctx != nil {
				routes[j] = LinkedRoute{Route: r, URL: RouteURL(r.ID, ctx)}
			} else {
				routes[j] = r
			}
		}
		out[i] = jsonFinding{
			Severity: f.Severity, Type: f.Type, RouterFlavor: f.RouterFlavor,
			Routes: routes, Samples: f.Samples, WinnerID: f.WinnerID,
			Reason: f.Reason, Suggestions: f.Suggestions,
		}
	}
	return Report{
		GeneratedAt:   ISOTimestamp(now),
		RouterFlavor:  flavor,
		TotalFindings: len(findings),
		Summary:       model.Summarize(findings),
		Findings:      out,
	}
}

// JSON renders findings as a pretty-printed JSON report.
func JSON(findings []*model.Finding, flavor model.RouterFlavor, ctx *KonnectContext) (string, error) {
	b, err := json.MarshalIndent(NewReport(findings, flavor, ctx, time.Time{}), "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

var csvHeader = []string{
	"severity", "type", "router_flavor", "route_role", "route_id", "route_name",
	"route_paths", "route_regex_priority", "route_created_at",
	"winner_id", "samples", "reason", "suggestions", "konnect_url",
}

// CSV renders findings with one row per route involved in a finding, so a
// two-route shadowing finding yields two rows sharing the finding columns.
// Every field is quoted per RFC 4180.
func CSV(findings []*model.Finding, ctx *KonnectContext) string {
	rows := []string{strings.Join(csvHeader, ",")}
	for _, f := range findings {
		samples := strings.Join(f.Samples, " | ")
		reason := strings.Join(f.Reason, " | ")
		suggestions := strings.Join(f.Suggestions, " | ")

		for idx, r := range f.Routes {
			role := "route"
			if f.Type == model.FindingShadowing || f.Type == model.FindingCollision {
				role = "shadowed"
				if idx == 0 {
					role = "winner"
				}
			}
			created := ""
			if r.CreatedAt != nil && *r.CreatedAt != 0 {
				created = ISOTimestamp(time.Unix(*r.CreatedAt, 0))
			}
			fields := []string{
				string(f.Severity), string(f.Type), string(f.RouterFlavor), role,
				r.ID, r.Name, strings.Join(r.Paths, " | "), strconv.Itoa(r.RegexPriority), created,
				f.WinnerID, samples, reason, suggestions, RouteURL(r.ID, ctx),
			}
			for i, v := range fields {
				fields[i] = `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
			}
			rows = append(rows, strings.Join(fields, ","))
		}
	}
	return strings.Join(rows, "\n")
}
