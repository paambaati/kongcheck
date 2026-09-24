// Package router is a Go port of the routing core of Kong's traditional
// router (kong/router/traditional.lua, commit 2ffd3b1, Kong 3.x).
//
// Only the subset that affects which route wins is ported:
//   - path classification (`~` prefix → regex, otherwise plain prefix)
//   - the sort_routes tie-breaking chain
//   - match_regex_uri / plain-prefix matching and the other matchers
//   - the find_match candidate evaluation loop
//
// Everything that only affects what happens after the winner is chosen
// (strip_path, upstream URI construction, debug headers, caches) is omitted,
// except for the informational helpers in upstream.go.
//
// Each function notes the Kong source location it was derived from so that
// upstream drift can be spotted at a glance.
//
// See https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua
package router

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
)

// PathKind classifies a path pattern.
type PathKind string

// Path kinds.
const (
	PathRegex  PathKind = "regex"
	PathPrefix PathKind = "prefix"
)

// ParsedPath is a ready-to-match representation of one path pattern, derived
// from Kong's internal uri_t structure.
type ParsedPath struct {
	// Raw is the path exactly as configured, e.g. "~/payments/*".
	Raw  string   `json:"raw"`
	Kind PathKind `json:"kind"`
	// RegexSource is the pattern without the leading `~` (regex paths only).
	RegexSource string `json:"regexSource,omitempty"`
	// Regex is the compiled pattern (regex paths only). For the
	// traditional_compatible and expressions flavors it carries a `^` anchor.
	Regex *Pattern `json:"regex,omitempty"`
	// Prefix is the plain prefix string (prefix paths only).
	Prefix string `json:"prefix,omitempty"`
	// Sample is a concrete request path derived from the pattern, used for
	// sibling-overlap probing. Pre-computed once to keep the O(n²) analysis
	// loops allocation-free.
	Sample string `json:"sample,omitempty"`
}

// IsRegexPath reports whether raw is a regex path in Kong semantics (it
// starts with `~`).
//
// Kong source: traditional.lua `marshall_route` (~L430).
func IsRegexPath(raw string) bool {
	return strings.HasPrefix(raw, "~")
}

// StripRegexPrefix removes the leading `~` from a regex path.
//
// Kong source: traditional.lua `path = sub(path, 2)` (~L437).
func StripRegexPrefix(raw string) (string, error) {
	if !IsRegexPath(raw) {
		return "", fmt.Errorf("stripRegexPrefix: expected a regex path starting with '~', got '%s'", raw)
	}
	return raw[1:], nil
}

var (
	templatePlaceholderRe = regexp.MustCompile(`\{[^}]+\}`)
	captureGroupRe        = regexp.MustCompile(`\([^)]+\)`)
	nonSampleCharRe       = regexp.MustCompile(`[^/a-zA-Z0-9-]`)
)

// ClassifyPath parses a raw path pattern.
//
// Regex paths are compiled; under the traditional_compatible and expressions
// flavors a `^` start anchor is prepended, matching Kong's
// `path_val_transform`.
//
// Kong sources:
//   - traditional.lua `marshall_route` path block (~L426-L467)
//   - transform.lua `path_val_transform` (~L322-L330)
func ClassifyPath(raw string, flavor model.RouterFlavor) ParsedPath {
	if !IsRegexPath(raw) {
		return ParsedPath{Raw: raw, Kind: PathPrefix, Prefix: raw, Sample: raw}
	}

	source := raw[1:]
	anchored := source
	if flavor != model.FlavorTraditional {
		anchored = "^" + source
	}

	sample := templatePlaceholderRe.ReplaceAllString(source, "id")
	sample = captureGroupRe.ReplaceAllString(sample, "id")
	sample = nonSampleCharRe.ReplaceAllString(sample, "")

	return ParsedPath{
		Raw:         raw,
		Kind:        PathRegex,
		RegexSource: source,
		Regex:       CompilePattern(anchored),
		Sample:      sample,
	}
}

// MatchPath reports whether a single parsed path matches the request path.
//
// Regex paths reproduce Kong's `match_regex_uri`: the pattern may match
// anywhere unless it is anchored (Kong appends `(?<uri_postfix>.*)`, so a
// pattern is prefix-like unless the author end-anchors it with `$`). Plain
// paths use exact prefix comparison.
//
// Kong sources: traditional.lua `match_regex_uri` (~L903-L931) and the
// MATCH_RULES.URI handler (~L1070-L1100).
func MatchPath(p *ParsedPath, reqPath string) bool {
	if p.Kind == PathRegex {
		return p.Regex != nil && p.Regex.MatchString(reqPath)
	}
	return strings.HasPrefix(reqPath, p.Prefix)
}

// MarshalledRoute is a route prepared for the matching engine, mirroring the
// route_t structure produced by Kong's `marshall_route`.
type MarshalledRoute struct {
	// Route is the original route entity, preserved for diagnostics.
	Route *model.KongRoute `json:"route"`
	// Service is the resolved service, if available.
	Service *model.KongService `json:"service,omitempty"`
	// ParsedPaths holds one entry per path; the route matches if any matches.
	ParsedPaths []ParsedPath `json:"parsedPaths"`
	// MaxURILength is the longest plain-prefix path length (regex paths do not
	// count), used as a sort tie-breaker.
	MaxURILength int `json:"maxUriLength"`
	// HasRegexPath mirrors the HAS_REGEX_URI submatch bit.
	HasRegexPath bool `json:"hasRegexPath"`
	// SubMatchWeight is Kong's 3-bit MATCH_SUBRULES field (higher wins):
	//   - 0x01 HAS_REGEX_URI: any path is a regex path.
	//   - 0x02 PLAIN_HOSTS_ONLY: all host constraints are plain.
	//   - 0x04 HAS_WILDCARD_HOST_PORT: a wildcard host has an explicit port.
	SubMatchWeight int `json:"subMatchWeight"`
	// HeaderCount is the number of non-host header constraints.
	HeaderCount int `json:"headerCount"`
	// Flavor is the router flavor the route was marshalled under.
	Flavor model.RouterFlavor `json:"flavor"`
	// PathFingerprint is the sorted, pipe-joined path set, for O(1)
	// identical-path comparison.
	PathFingerprint string `json:"pathFingerprint"`
	// IsUniversal marks routes whose paths match every request URL. It is
	// false after MarshalRoute and stamped by the analyzer.
	IsUniversal bool `json:"isUniversal"`
	// HeaderPatterns holds pre-compiled `~*` header regexes keyed by lowercase
	// header name. Present only for headers with exactly one `~*` value.
	HeaderPatterns map[string]*Pattern `json:"-"`
	// HasTemplatePlaceholder reports whether any regex path contains a literal
	// `{variable}` placeholder (in PCRE `{id}` matches the text "{id}").
	HasTemplatePlaceholder bool `json:"hasTemplatePlaceholder"`
}

// Submatch weight bits (traditional.lua MATCH_SUBRULES, ~L209-L213).
const (
	SubmatchHasRegexURI         = 0x01
	SubmatchPlainHostsOnly      = 0x02
	SubmatchHasWildcardHostPort = 0x04
)

// MarshalRoute converts a route entity into a MarshalledRoute.
//
// Kong source: traditional.lua `marshall_route` (~L370-L520), restricted to
// the fields that matter for route-winner selection.
func MarshalRoute(route *model.KongRoute, service *model.KongService, flavor model.RouterFlavor) *MarshalledRoute {
	if flavor == "" {
		flavor = model.FlavorTraditional
	}
	mr := &MarshalledRoute{
		Route:          route,
		Service:        service,
		ParsedPaths:    make([]ParsedPath, len(route.Paths)),
		Flavor:         flavor,
		HeaderPatterns: map[string]*Pattern{},
	}

	for i, raw := range route.Paths {
		p := ClassifyPath(raw, flavor)
		mr.ParsedPaths[i] = p
		if p.Kind == PathRegex {
			mr.HasRegexPath = true
			if templatePlaceholderRe.MatchString(p.RegexSource) {
				mr.HasTemplatePlaceholder = true
			}
			continue
		}
		// Kong only counts plain-prefix lengths for max_uri_length (~L439-L449).
		mr.MaxURILength = max(mr.MaxURILength, len(p.Raw))
	}

	// Bit 0 – HAS_REGEX_URI.
	if mr.HasRegexPath {
		mr.SubMatchWeight |= SubmatchHasRegexURI
	}

	// Bits 1 and 2 – host subrules (~L333-L373). A colon after the wildcard
	// marks an explicit port, e.g. "*.example.com:8080".
	if len(route.Hosts) > 0 {
		hasWildcard, hasWildcardPort := false, false
		for _, h := range route.Hosts {
			if i := strings.IndexByte(h, '*'); i >= 0 {
				hasWildcard = true
				if strings.Contains(h[i+1:], ":") {
					hasWildcardPort = true
				}
			}
		}
		if !hasWildcard {
			mr.SubMatchWeight |= SubmatchPlainHostsOnly
		}
		if hasWildcardPort {
			mr.SubMatchWeight |= SubmatchHasWildcardHostPort
		}
	}

	// Header count and `~*` patterns. Kong drops the "host" header when
	// building headers_t, so it does not count towards sort priority
	// (~L378-L418 marshal, ~L686-L688 sort).
	for _, h := range route.Headers {
		if !strings.EqualFold(h.Name, "host") {
			mr.HeaderCount++
		}
		if len(h.Values) == 1 && strings.HasPrefix(h.Values[0], "~*") {
			// (?i): Kong treats ~* header regexes as case-insensitive; without
			// it a pattern with uppercase literals never matches the lowercased
			// request value we compare against.
			mr.HeaderPatterns[strings.ToLower(h.Name)] = CompilePattern("(?i)" + h.Values[0][2:])
		}
	}

	sorted := append([]string(nil), route.Paths...)
	sort.Strings(sorted)
	mr.PathFingerprint = strings.Join(sorted, "|")

	return mr
}

// MarshalRoutes marshals routes the way Kong does before sorting: routes with
// several paths are split into one MarshalledRoute per path so each path is
// scored independently (Kong `_M.new`, ~L1430-L1449: "split routes by paths
// to sort properly").
func MarshalRoutes(data *model.KonnectData, flavor model.RouterFlavor) []*MarshalledRoute {
	out := make([]*MarshalledRoute, 0, len(data.Routes))
	for _, r := range data.Routes {
		svc := data.ServiceFor(r)
		if len(r.Paths) <= 1 {
			out = append(out, MarshalRoute(r, svc, flavor))
			continue
		}
		for _, p := range r.Paths {
			out = append(out, MarshalRoute(r.WithPaths([]string{p}), svc, flavor))
		}
	}
	return out
}
