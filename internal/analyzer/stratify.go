package analyzer

import (
	"fmt"
	"slices"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

// haveIdenticalPaths reports whether two routes have exactly the same path
// set (order-independent), via the pre-computed fingerprint.
func haveIdenticalPaths(a, b *router.MarshalledRoute) bool {
	return a.PathFingerprint == b.PathFingerprint
}

// headerStratification classifies the header relationship of two routes.
type headerStratification int

const (
	// headersOverlap: constraints overlap (or the winner has none) — a genuine
	// collision may exist.
	headersOverlap headerStratification = iota
	// headersStratified: the winner's headers partition traffic; the loser
	// handles the remainder, so nothing is misrouted.
	headersStratified
	// headersRegexOpaque: `~*` regex header values make static disjointness
	// undecidable (it would need PCRE intersection testing).
	headersRegexOpaque
)

func hasRegexHeaderValue(values []string) bool {
	return slices.ContainsFunc(values, func(v string) bool { return strings.HasPrefix(v, "~*") })
}

// isHeaderStratified classifies the header constraints of two routes that
// share identical paths. A definitively stratified dimension takes precedence
// over a regex-opaque one.
//
// Kong source: traditional.lua header_pattern construction (~L400-L412).
func isHeaderStratified(winner, loser *router.MarshalledRoute) headerStratification {
	winHeaders := winner.Route.Headers
	if len(winHeaders) == 0 {
		return headersOverlap
	}
	loseHeaders := loser.Route.Headers

	foundRegex := false
	for _, wh := range winHeaders {
		loseValues, ok := loseHeaders.Lookup(wh.Name)
		if !ok || loseValues == nil {
			// The loser does not constrain this header, so requests without it
			// go exclusively to the loser.
			return headersStratified
		}
		if hasRegexHeaderValue(wh.Values) || hasRegexHeaderValue(loseValues) {
			foundRegex = true
			continue // a later header may still be definitively stratified
		}
		overlap := slices.ContainsFunc(loseValues, func(lv string) bool {
			return slices.ContainsFunc(wh.Values, func(wv string) bool { return strings.EqualFold(wv, lv) })
		})
		if !overlap {
			return headersStratified
		}
	}
	if foundRegex {
		return headersRegexOpaque
	}
	return headersOverlap
}

// Protocol families handled by Kong's HTTP and stream subsystems
// (traditional.lua SORTED_MATCH_RULES, ~L194-L206).
var (
	httpProtocols   = map[string]bool{"http": true, "https": true, "grpc": true, "grpcs": true}
	streamProtocols = map[string]bool{"tcp": true, "tls": true, "udp": true, "tls_passthrough": true}
)

func allIn(protocols []string, family map[string]bool) bool {
	for _, p := range protocols {
		if !family[strings.ToLower(p)] {
			return false
		}
	}
	return true
}

// protocolsAreDisjoint reports whether one list is entirely HTTP-family and
// the other entirely stream-family, so Kong can never route the same
// connection to both.
func protocolsAreDisjoint(a, b []string) bool {
	return (allIn(a, httpProtocols) && allIn(b, streamProtocols)) ||
		(allIn(b, httpProtocols) && allIn(a, streamProtocols))
}

// isL4Stratified checks whether two routes are mutually exclusive on an L4
// dimension — protocol family, SNI, source IP/port, or destination IP/port —
// and returns a human-readable reason when they are.
//
// It is conservative: a dimension only counts when both routes constrain it,
// because an absent constraint matches anything.
//
// Kong sources: SNI normalisation (~L511-L513), MATCH_RULES.SNI
// (~L1072-L1077), matcher_src_dst (~L880-L900).
func isL4Stratified(a, b *router.MarshalledRoute) (reason string, ok bool) {
	ar, br := a.Route, b.Route

	if len(ar.Protocols) > 0 && len(br.Protocols) > 0 && protocolsAreDisjoint(ar.Protocols, br.Protocols) {
		return fmt.Sprintf("routes use mutually exclusive protocol families (%s vs %s)",
			strings.Join(ar.Protocols, ", "), strings.Join(br.Protocols, ", ")), true
	}

	if len(ar.SNIs) > 0 && len(br.SNIs) > 0 {
		aNorm, bNorm := normalizeSNIs(ar.SNIs), normalizeSNIs(br.SNIs)
		if !slices.ContainsFunc(aNorm, func(s string) bool { return slices.Contains(bNorm, s) }) {
			return fmt.Sprintf("routes have disjoint SNI sets ([%s] vs [%s])",
				strings.Join(aNorm, ", "), strings.Join(bNorm, ", ")), true
		}
	}

	if len(ar.Sources) > 0 && len(br.Sources) > 0 && !router.IPPortListsOverlap(ar.Sources, br.Sources) {
		return "routes have non-overlapping source IP/port constraints", true
	}

	if len(ar.Destinations) > 0 && len(br.Destinations) > 0 && !router.IPPortListsOverlap(ar.Destinations, br.Destinations) {
		return "routes have non-overlapping destination IP/port constraints", true
	}

	return "", false
}

// normalizeSNIs strips one trailing dot from each SNI and de-duplicates,
// keeping first-seen order.
func normalizeSNIs(snis []string) []string {
	out := make([]string, 0, len(snis))
	for _, s := range snis {
		s = strings.TrimSuffix(s, ".")
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// joinPathsOr joins a route's paths, or returns fallback when that is empty.
func joinPathsOr(r *model.KongRoute, fallback string) string {
	if joined := strings.Join(r.Paths, ", "); joined != "" {
		return joined
	}
	return fallback
}

// buildL4StratifiedFinding documents a pair that shares paths but is
// correctly partitioned by L4 attributes.
func buildL4StratifiedFinding(winner, loser *router.MarshalledRoute, sample string, flavor model.RouterFlavor, reason string) *model.Finding {
	winName, loseName := winner.Route.DisplayName(), loser.Route.DisplayName()
	return &model.Finding{
		Severity:     model.SeverityInfo,
		Type:         model.FindingCollision,
		RouterFlavor: flavor,
		Routes:       []*model.KongRoute{winner.Route, loser.Route},
		Samples:      []string{sample},
		WinnerID:     winner.Route.ID,
		Reason: []string{
			`Routes "` + winName + `" and "` + loseName + `" share overlapping path(s) but are correctly stratified by L4 constraints.`,
			"Path(s): " + joinPathsOr(winner.Route, sample),
			"Stratification: " + reason + ".",
			"Kong routes each connection to the correct route based on L4 attributes. No misrouting occurs.",
			"Confirm this L4 stratification is intentional.",
		},
		Suggestions: []string{},
	}
}

// buildHeaderStratifiedFinding documents a pair correctly partitioned by a
// header, including ready-to-run `explain-request` commands to verify it.
func buildHeaderStratifiedFinding(winner, loser *router.MarshalledRoute, sample string, flavor model.RouterFlavor) *model.Finding {
	winName, loseName := winner.Route.DisplayName(), loser.Route.DisplayName()

	descs := make([]string, 0, len(winner.Route.Headers))
	flags := make([]string, 0, len(winner.Route.Headers))
	for _, h := range winner.Route.Headers {
		descs = append(descs, h.Name+": ["+strings.Join(h.Values, ", ")+"]")
		first := ""
		if len(h.Values) > 0 {
			first = h.Values[0]
		}
		flags = append(flags, "--header "+h.Name+":"+first)
	}
	headerFlags := strings.Join(flags, " ")

	return &model.Finding{
		Severity:     model.SeverityInfo,
		Type:         model.FindingCollision,
		RouterFlavor: flavor,
		Routes:       []*model.KongRoute{winner.Route, loser.Route},
		Samples:      []string{sample},
		WinnerID:     winner.Route.ID,
		Reason: []string{
			`Routes "` + winName + `" and "` + loseName + `" share identical path(s) and are correctly stratified by header.`,
			"Path(s): " + joinPathsOr(winner.Route, sample),
			`"` + winName + `" requires: ` + strings.Join(descs, "; "),
			`"` + loseName + `" has no matching constraint — it handles all requests that lack the required header.`,
			"Kong routes to the header-constrained route when the header is present; all other requests reach the unconstrained route.",
			"No misrouting occurs. Confirm this header stratification is intentional.",
		},
		Suggestions: []string{
			"kongcheck explain-request GET " + sample + " " + headerFlags + `  →  should route to "` + winName + `"`,
			"kongcheck explain-request GET " + sample + `  →  should route to "` + loseName + `" (no header required)`,
		},
	}
}

// buildRegexHeaderOpaqueFinding flags a pair whose `~*` header regexes make
// static stratification analysis impossible (MEDIUM: verify manually).
func buildRegexHeaderOpaqueFinding(winner, loser *router.MarshalledRoute, sample string, flavor model.RouterFlavor) *model.Finding {
	winName, loseName := winner.Route.DisplayName(), loser.Route.DisplayName()

	var regexValues []string
	for _, r := range []*model.KongRoute{winner.Route, loser.Route} {
		for _, h := range r.Headers {
			for _, v := range h.Values {
				if strings.HasPrefix(v, "~*") {
					regexValues = append(regexValues, v)
				}
			}
		}
	}

	winSvc, loseSvc := serviceID(winner), serviceID(loser)
	serviceNote := "Both routes target the same service; misrouting risk is lower but the overlap should be verified."
	if winSvc != "" && loseSvc != "" && winSvc != loseSvc {
		serviceNote = "⚠  Routes target DIFFERENT services. If the regex patterns overlap, " +
			`requests could be misrouted between "` + winName + `" (` + winSvc + `) and "` + loseName + `" (` + loseSvc + `).`
	}

	return &model.Finding{
		Severity:     model.SeverityMedium,
		Type:         model.FindingCollision,
		RouterFlavor: flavor,
		Routes:       []*model.KongRoute{winner.Route, loser.Route},
		Samples:      []string{sample},
		WinnerID:     winner.Route.ID,
		Reason: []string{
			`Routes "` + winName + `" and "` + loseName + `" share identical path(s) and both use ` +
				"`~*`-prefixed regex header values.",
			"Regex header values detected: " + strings.Join(regexValues, ", "),
			"Static analysis cannot determine whether these regex patterns are disjoint — " +
				"PCRE intersection testing is required to be certain.",
			serviceNote,
			"Use `kongcheck explain-request` with representative header values to confirm correct routing.",
		},
		Suggestions: []string{
			"Verify manually that the ~* header patterns are truly disjoint for all real traffic values.",
			"kongcheck explain-request GET " + sample + "  →  observe which route wins for each header value",
		},
	}
}

// serviceID resolves a route's service ID from the resolved service or the
// route's own reference.
func serviceID(mr *router.MarshalledRoute) string {
	if mr.Service != nil && mr.Service.ID != "" {
		return mr.Service.ID
	}
	return mr.Route.ServiceID()
}
