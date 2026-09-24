package analyzer

import (
	"regexp"
	"strings"

	"github.com/paambaati/kongcheck/internal/router"
)

var (
	namedGroupOpenRe = regexp.MustCompile(`\(\?P?<[^>]+>`)
	parenRe          = regexp.MustCompile(`[()]`)
	multiSlashRe     = regexp.MustCompile(`/+`)
	lastSegmentRe    = regexp.MustCompile(`/[^/]+$`)
	templateRe       = regexp.MustCompile(`\{[^}]+\}`)
	captureRe        = regexp.MustCompile(`\([^)]+\)`)
)

// candidateHost and candidateMethod are used for all generated requests.
const (
	candidateMethod = "GET"
	candidateHost   = "example.com"
)

// GenerateCandidateRequests derives probe requests from the routes' own path
// patterns: each base path, its trailing-slash variant, a child path
// (`/extra`), and its parent. The result is de-duplicated and keeps
// first-seen order, which keeps the analysis output deterministic.
func GenerateCandidateRequests(routes []*router.MarshalledRoute) []router.SimRequest {
	seen := make(map[string]struct{})
	var paths []string
	add := func(p string) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}

	for _, mr := range routes {
		for i := range mr.ParsedPaths {
			p := &mr.ParsedPaths[i]
			var base string
			if p.Kind == router.PathRegex {
				base = regexToSamplePath(p.RegexSource)
			} else {
				base = p.Prefix
			}
			base = multiSlashRe.ReplaceAllString(base, "/")

			add(base)
			if !strings.HasSuffix(base, "/") {
				add(base + "/")
			}
			trimmed := strings.TrimSuffix(base, "/")
			add(trimmed + "/extra")
			if parent := lastSegmentRe.ReplaceAllString(trimmed, ""); parent != "" {
				add(parent)
			}
		}
	}

	reqs := make([]router.SimRequest, len(paths))
	for i, p := range paths {
		reqs[i] = router.SimRequest{Method: candidateMethod, Host: candidateHost, Path: p}
	}
	return reqs
}

// regexToSamplePath simplifies a regex source into a plausible plain path.
func regexToSamplePath(src string) string {
	s := templateRe.ReplaceAllString(src, "id")  // {variable} placeholders → id
	s = captureRe.ReplaceAllString(s, "id")      // (capture groups) → id
	s = namedGroupOpenRe.ReplaceAllString(s, "") // unclosed named-group openers
	s = strings.ReplaceAll(s, "(?:", "")         // non-capturing group openers
	s = parenRe.ReplaceAllString(s, "")          // remaining parens
	s = strings.ReplaceAll(s, "?", "")           // optional quantifiers
	s = strings.ReplaceAll(s, ".*", "test")      // .* → "test"
	s = strings.ReplaceAll(s, "*", "")           // remaining *
	s = strings.ReplaceAll(s, "+", "")           // +
	s = strings.TrimSuffix(s, "$")               // end anchor
	s = strings.Replace(s, "^", "", 1)           // first start anchor
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return s
}
