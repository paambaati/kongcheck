package strutil

import "testing"

func TestIsUUID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"11111111-1111-1111-1111-111111111111", true},
		{"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", true},
		{"not-a-uuid", false},
		{"11111111-1111-1111-1111", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsUUID(c.in); got != c.want {
			t.Errorf("IsUUID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty("", "b", "c"); got != "b" {
		t.Errorf("FirstNonEmpty = %q, want b", got)
	}
	if got := FirstNonEmpty("", ""); got != "" {
		t.Errorf("FirstNonEmpty = %q, want empty", got)
	}
}

func TestSanitizeControlChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ASCII passthrough (fast path)", "payments-winner", "payments-winner"},
		{"unicode passthrough", "café-route", "café-route"},
		{"empty string", "", ""},
		{
			// Stripping the ESC trigger byte is sufficient: a terminal only
			// interprets "[1m" as an SGR control sequence when it's preceded
			// by the literal ESC (0x1B) byte. Without it, the brackets/digits
			// are inert, harmless, visible text — there's no need to also
			// parse and strip the rest of the CSI sequence.
			name: "strips ANSI SGR escape sequence's ESC trigger byte, neutralizing it",
			in:   "\x1b[1m\x1b[31mHIDDEN\x1b[0mnormal-name",
			want: "[1m[31mHIDDEN[0mnormal-name",
		},
		{
			name: "strips bare ESC byte",
			in:   "route\x1bname",
			want: "routename",
		},
		{
			name: "strips embedded newline and carriage return (fake report lines)",
			in:   "route\nname\rwith-lines",
			want: "routenamewith-lines",
		},
		{
			name: "strips DEL",
			in:   "route\x7fname",
			want: "routename",
		},
		{
			name: "strips C1 control range (single-byte CSI/OSC forms)",
			in:   "route\u0090name\u009b",
			want: "routename",
		},
		{
			name: "strips tab",
			in:   "route\tname",
			want: "routename",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SanitizeControlChars(c.in); got != c.want {
				t.Errorf("SanitizeControlChars(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
