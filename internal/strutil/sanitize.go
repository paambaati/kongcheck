package strutil

import "strings"

// SanitizeControlChars strips ASCII C0/C1 control characters and DEL from s.
//
// Route/service `name` and `paths` values come from the Kong control plane —
// data this tool does not fully trust (a compromised or malicious control
// plane, or an attacker with limited route-creation privileges, could embed
// raw terminal escape sequences in them). When such a string is written
// verbatim to a terminal as part of a human-readable report, an embedded
// ESC/CSI/OSC sequence can move the cursor, hide or rewrite prior output, or
// (on some terminals) trigger OSC-based exploits — all without the operator
// running kongcheck seeing anything unusual in the source data. Route names
// and paths have no legitimate use for control characters, so this strips
// all of them (including bare newlines/carriage returns, which could
// otherwise be used to fabricate fake report lines) rather than trying to
// allow-list "safe" escape sequences.
//
// JSON and CSV output are not affected by this function (and don't need to
// be): they are not executed as terminal control sequences by the consuming
// tool, and CSV has its own formula-injection defense (see csvQuoted).
func SanitizeControlChars(s string) string {
	if !strings.ContainsFunc(s, isControlChar) {
		return s // fast path: no allocation for the overwhelmingly common case
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControlChar(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isControlChar reports whether r is an ASCII C0 control character (0x00-0x1F),
// DEL (0x7F), or a C1 control character (0x80-0x9F) — the ranges that cover
// every ANSI/terminal escape and control sequence (ESC is 0x1B; the C1 range
// includes the single-byte forms of CSI/OSC/etc. some terminals recognize).
func isControlChar(r rune) bool {
	return (r >= 0x00 && r <= 0x1F) || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}
