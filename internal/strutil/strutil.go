// Package strutil holds small shared string helpers used across packages.
package strutil

import "regexp"

// uuidRe matches a canonical 8-4-4-4-12 hex UUID (case-insensitive).
var uuidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsUUID reports whether s is a canonical UUID string.
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// FirstNonEmpty returns the first non-empty value, or "".
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
