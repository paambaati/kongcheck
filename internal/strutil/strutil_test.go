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
