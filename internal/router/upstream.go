package router

import "strings"

// SanitizeURIPostfix sanitises the part of the request path after the matched
// prefix, replicating Kong's `sanitize_uri_postfix` (utils.lua ~L20-L40).
func SanitizeURIPostfix(postfix string) string {
	switch {
	case postfix == "":
		return postfix
	case postfix == "." || postfix == "..":
		return ""
	case strings.HasPrefix(postfix, "./"):
		return postfix[2:]
	case strings.HasPrefix(postfix, "../"):
		return postfix[3:]
	}
	return postfix
}

// ComputeUpstreamURI computes the upstream URI Kong would forward to after
// selecting mr, implementing `get_upstream_uri_v0` (utils.lua ~L80-L140) for
// the default path_handling "v0". Informational only — it never affects which
// route wins. upstreamBase is the service path ("/" when empty).
func ComputeUpstreamURI(mr *MarshalledRoute, reqPath, matchedPrefix, upstreamBase string) string {
	if upstreamBase == "" {
		upstreamBase = "/"
	}
	stripPath := mr.Route.StripPath == nil || *mr.Route.StripPath

	if !stripPath {
		if reqPath == "/" {
			return upstreamBase
		}
		return upstreamBase + reqPath[1:]
	}

	postfix := ""
	if len(matchedPrefix) < len(reqPath) {
		postfix = reqPath[len(matchedPrefix):]
	}
	postfix = SanitizeURIPostfix(postfix)

	if strings.HasSuffix(upstreamBase, "/") {
		switch {
		case postfix == "" && upstreamBase == "/":
			return "/"
		case postfix == "":
			return upstreamBase[:len(upstreamBase)-1]
		case strings.HasPrefix(postfix, "/"):
			return upstreamBase[:len(upstreamBase)-1] + postfix
		}
		return upstreamBase + postfix
	}

	switch {
	case postfix == "":
		return upstreamBase
	case strings.HasPrefix(postfix, "/"):
		return upstreamBase + postfix
	}
	return upstreamBase + "/" + postfix
}

// ExtractMatchedPrefix returns the portion of reqPath matched by the route:
// the prefix itself for plain paths, or the full regex match for regex paths.
// It returns "" when no path matches.
func ExtractMatchedPrefix(mr *MarshalledRoute, reqPath string) string {
	for i := range mr.ParsedPaths {
		p := &mr.ParsedPaths[i]
		if p.Kind == PathPrefix && p.Prefix != "" && strings.HasPrefix(reqPath, p.Prefix) {
			return p.Prefix
		}
		if p.Kind == PathRegex && p.Regex != nil {
			if m, ok := p.Regex.FindString(reqPath); ok {
				return m
			}
		}
	}
	return ""
}
