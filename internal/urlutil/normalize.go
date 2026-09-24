// Package urlutil normalizes request paths the way Kong sees them.
package urlutil

import (
	"net/url"
	"strings"
)

// NormalizePath normalizes a request path the same way Kong does before
// route matching:
//
//  1. Strip the query string (everything from '?' onwards).
//  2. Strip a URL fragment (everything from '#' onwards).
//  3. Resolve '.' and '..' dot-segments.
//
// Percent-encoding is preserved as-is: Kong's traditional router matches the
// raw URI without decoding, so `/hello%20world` and `/hello world` are
// distinct paths.
//
// The behaviour follows the WHATWG URL parser's path handling (relative to a
// throwaway `http://x` base), which matches nginx-level behaviour: relative
// input is resolved against `/`, backslashes act as separators, `%2e` counts
// as a dot, and characters outside the path percent-encode set are encoded.
func NormalizePath(raw string) string {
	s := trimC0(raw)
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)

	// Absolute http(s) URLs: use their path component.
	if u, err := url.Parse(s); err == nil && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) {
		s = u.EscapedPath()
		if s == "" {
			s = "/"
		}
	}

	// Cut query and fragment, whichever comes first.
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, `\`, "/")

	// A scheme-relative reference ("//host/path") carries an authority.
	// WHATWG's "special authority slashes state" tolerates (and consumes)
	// any number of leading slashes here, not just exactly two — e.g.
	// "///admin" is parsed the same as "//admin" (empty host, path
	// "/admin"), and "////a" the same as "//a" (host "a", empty path). This
	// matters because 3+ leading slashes is a known reverse-proxy path-
	// confusion technique. For a special scheme (http, as used by our
	// throwaway base), an authority with an empty host — nothing at all
	// left after consuming the slashes — is a hard parse failure; WHATWG's
	// `new URL()` throws, and the reference TypeScript implementation
	// catches that and returns the original input completely unprocessed
	// rather than guessing at a partial normalization.
	if strings.HasPrefix(s, "//") {
		rest := strings.TrimLeft(s, "/")
		if rest == "" {
			return raw
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			s = rest[i:]
		} else {
			s = "/"
		}
	}

	return "/" + resolveSegments(strings.Split(strings.TrimPrefix(s, "/"), "/"))
}

// resolveSegments applies WHATWG dot-segment resolution and percent-encodes
// each segment with the path percent-encode set.
func resolveSegments(segments []string) string {
	out := make([]string, 0, len(segments))
	for i, seg := range segments {
		last := i == len(segments)-1
		switch {
		case isDoubleDot(seg):
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case isSingleDot(seg):
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, encodePathSegment(seg))
		}
	}
	return strings.Join(out, "/")
}

func isSingleDot(s string) bool {
	return s == "." || strings.EqualFold(s, "%2e")
}

func isDoubleDot(s string) bool {
	switch strings.ToLower(s) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

// encodePathSegment percent-encodes bytes in the WHATWG path percent-encode
// set (C0 controls, space, `"`, `#`, `<`, `>`, `?`, backtick, `{`, `}`, and
// any byte >= 0x7F). Existing percent-escapes are left untouched.
func encodePathSegment(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7F || strings.IndexByte("\"#<>?`{}", c) >= 0 {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// trimC0 strips leading and trailing C0 control characters and spaces.
func trimC0(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= 0x20 })
}
