package model

// RouterFlavor is a Kong router flavor, determining matching semantics.
//
//   - traditional: original regex/prefix router, no start anchor on regex paths.
//   - traditional_compatible: traditional routes compiled to ATC expressions;
//     regex paths receive a `^` anchor.
//   - expressions: native ATC expression router (partially supported).
//
// See https://github.com/Kong/kong/blob/2ffd3b1/kong/router/transform.lua#L322-L330
type RouterFlavor string

// Router flavors.
const (
	FlavorTraditional           RouterFlavor = "traditional"
	FlavorTraditionalCompatible RouterFlavor = "traditional_compatible"
	FlavorExpressions           RouterFlavor = "expressions"
)

// Valid reports whether f is a known router flavor.
func (f RouterFlavor) Valid() bool {
	switch f {
	case FlavorTraditional, FlavorTraditionalCompatible, FlavorExpressions:
		return true
	}
	return false
}

// ParseFlavor returns the flavor for s, or "" when s is not a known flavor.
func ParseFlavor(s string) RouterFlavor {
	if f := RouterFlavor(s); f.Valid() {
		return f
	}
	return ""
}

// Severity of a finding, ordered from most to least severe.
type Severity string

// Severity levels.
const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"
)

// Severities lists all severities from most to least severe.
var Severities = []Severity{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// Rank returns 0 for HIGH through 3 for INFO, or -1 for unknown values.
func (s Severity) Rank() int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// FindingType discriminates analysis findings.
type FindingType string

// Finding types.
const (
	// FindingShadowing: one route's pattern captures requests clearly intended
	// for a more specific sibling.
	FindingShadowing FindingType = "shadowing"
	// FindingCollision: several routes match the same request; the winner is
	// non-obvious.
	FindingCollision FindingType = "collision"
	// FindingSuspiciousRegex: a regex path uses `*` as if it were a glob.
	FindingSuspiciousRegex FindingType = "suspicious_regex"
	// FindingUniversalMatcher: a route matches every request URL.
	FindingUniversalMatcher FindingType = "universal_matcher"
)

// Finding is a single diagnostic produced by the analyzer.
type Finding struct {
	Severity     Severity     `json:"severity"`
	Type         FindingType  `json:"type"`
	RouterFlavor RouterFlavor `json:"routerFlavor"`
	// Routes involved; for shadowing/collision index 0 is the winner.
	Routes []*KongRoute `json:"routes"`
	// Samples are request paths that demonstrate the problem.
	Samples []string `json:"samples"`
	// WinnerID is the winning route's ID when determinable.
	WinnerID string `json:"winnerId,omitempty"`
	// Reason is an ordered explanation of the finding.
	Reason []string `json:"reason"`
	// Suggestions are safer replacement patterns or remediation notes.
	Suggestions []string `json:"suggestions"`
}

// CountBySeverity counts findings per severity level.
func CountBySeverity(findings []*Finding) map[Severity]int {
	counts := map[Severity]int{SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// SeveritySummary is a JSON-friendly per-severity count with a stable key order.
type SeveritySummary struct {
	High   int `json:"HIGH"`
	Medium int `json:"MEDIUM"`
	Low    int `json:"LOW"`
	Info   int `json:"INFO"`
}

// Summarize returns the per-severity counts of findings.
func Summarize(findings []*Finding) SeveritySummary {
	c := CountBySeverity(findings)
	return SeveritySummary{High: c[SeverityHigh], Medium: c[SeverityMedium], Low: c[SeverityLow], Info: c[SeverityInfo]}
}
