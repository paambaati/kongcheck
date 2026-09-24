package format_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/paambaati/kongcheck/internal/format"
	"github.com/paambaati/kongcheck/internal/model"
)

func TestFormatters(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	created := int64(1700000000)

	r1 := &model.KongRoute{
		ID:        "r1",
		Name:      "payments-winner",
		Paths:     []string{"~/payments(?:/.*)?"},
		CreatedAt: &created,
	}
	r2 := &model.KongRoute{
		ID:        "r2",
		Name:      "payments-shadowed",
		Paths:     []string{"/payments"},
		CreatedAt: &created,
	}

	findings := []*model.Finding{
		{
			Severity:     model.SeverityHigh,
			Type:         model.FindingShadowing,
			RouterFlavor: model.FlavorTraditional,
			Routes:       []*model.KongRoute{r1, r2},
			Samples:      []string{"/payments/test"},
			WinnerID:     "r1",
			Reason:       []string{"winner captures shadowed"},
			Suggestions:  []string{"~/payments(?:/.*)?$"},
		},
		{
			Severity:     model.SeverityInfo,
			Type:         model.FindingUniversalMatcher,
			RouterFlavor: model.FlavorTraditional,
			Routes:       []*model.KongRoute{r2},
			Samples:      nil,
			Reason:       []string{"catch-all"},
		},
	}

	ctx := &format.KonnectContext{ControlPlaneID: "cp-1", Region: "us"}

	t.Run("RelativeDate", func(t *testing.T) {
		past := now.Add(-5 * time.Minute)
		if got := format.RelativeDate(past, now); got != "5 minutes ago" {
			t.Errorf("expected '5 minutes ago', got %s", got)
		}
		yesterday := now.Add(-24 * time.Hour)
		if got := format.RelativeDate(yesterday, now); got != "1 day ago" {
			t.Errorf("expected '1 day ago', got %s", got)
		}
	})

	t.Run("Severity helpers", func(t *testing.T) {
		if !format.ShouldFail(findings, model.SeverityHigh) {
			t.Errorf("expected ShouldFail true for HIGH")
		}
		if format.ShouldFail([]*model.Finding{findings[1]}, model.SeverityMedium) {
			t.Errorf("expected ShouldFail false for INFO when threshold is MEDIUM")
		}
		if got := format.HighestSeverity(findings); got != model.SeverityHigh {
			t.Errorf("expected HighestSeverity HIGH, got %v", got)
		}
	})

	t.Run("JSON format", func(t *testing.T) {
		out, err := format.JSON(findings, model.FlavorTraditional, ctx)
		if err != nil {
			t.Fatalf("JSON format failed: %v", err)
		}
		var rep format.Report
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if rep.TotalFindings != 2 {
			t.Errorf("expected 2 findings, got %d", rep.TotalFindings)
		}
		if rep.Summary.High != 1 || rep.Summary.Info != 1 {
			t.Errorf("unexpected summary: %+v", rep.Summary)
		}
		if !strings.Contains(out, "_konnectUrl") {
			t.Errorf("expected _konnectUrl in output")
		}
	})

	t.Run("CSV format", func(t *testing.T) {
		csv := format.CSV(findings, ctx)
		lines := strings.Split(strings.TrimSpace(csv), "\n")
		// Header + 2 rows for finding 0 + 1 row for finding 1 = 4 lines
		if len(lines) != 4 {
			t.Fatalf("expected 4 lines in CSV, got %d:\n%s", len(lines), csv)
		}
		if !strings.Contains(lines[1], `"winner"`) || !strings.Contains(lines[2], `"shadowed"`) {
			t.Errorf("expected winner and shadowed roles in CSV lines:\n%s", csv)
		}
	})

	t.Run("CSV formula injection is neutralized", func(t *testing.T) {
		evil := []*model.Finding{{
			Severity:     model.SeverityHigh,
			Type:         model.FindingCollision,
			RouterFlavor: model.FlavorTraditional,
			Routes: []*model.KongRoute{{
				ID:    "   =cmd|'/c calc'!A0",
				Name:  "+SUM(A1:A9)",
				Paths: []string{"@SUM(1+1)"},
			}},
			Reason: []string{"-1+2"},
		}}
		out := format.CSV(evil, nil)
		for _, bad := range []string{`"=cmd`, `"+SUM`, `"@SUM`, `"-1+2`, `"   =cmd`} {
			if strings.Contains(out, bad) {
				t.Errorf("CSV field must be ' prefixed before quoting; found %s in:\n%s", bad, out)
			}
		}
		for _, good := range []string{`"'   =cmd`, `'+SUM`, `'@SUM`, `'-1+2`} {
			if !strings.Contains(out, good) {
				t.Errorf("expected neutralized field %s in:\n%s", good, out)
			}
		}
	})

	t.Run("Human format", func(t *testing.T) {
		human := format.Human(findings, model.FlavorTraditional, ctx, format.HumanOptions{
			Color:      false,
			Now:        now,
			HiddenInfo: 1,
		})
		if !strings.Contains(human, "Kong Route Audit – 2 finding(s)") {
			t.Errorf("missing header in human output:\n%s", human)
		}
		if !strings.Contains(human, "1 INFO finding(s) not shown") {
			t.Errorf("missing hidden info footnote in human output:\n%s", human)
		}
		if !strings.Contains(human, "Summary:  HIGH: 1  MEDIUM: 0  LOW: 0  INFO: 2") {
			t.Errorf("unexpected summary footer in human output:\n%s", human)
		}
	})
}

// TestJSON_PreservesRouteFieldOrder guards against JSON output (live mode,
// where every route gains a `_konnectUrl` deep-link) reordering a route's
// fields alphabetically. LinkedRoute used to build a map[string]json.RawMessage
// and re-marshal it, and encoding/json always sorts map keys — silently
// reordering every field relative to what Konnect actually returned.
func TestJSON_PreservesRouteFieldOrder(t *testing.T) {
	// Deliberately neither alphabetical nor in KongRoute's Go struct
	// declaration order, so this can only pass if the route's original byte
	// order survived all the way through LinkedRoute's _konnectUrl injection.
	raw := []byte(`{"name":"my-route","protocols":["http"],"id":"r-json-order","paths":["/foo"]}`)
	var route model.KongRoute
	if err := json.Unmarshal(raw, &route); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	findings := []*model.Finding{{
		Severity:     model.SeverityInfo,
		Type:         model.FindingUniversalMatcher,
		RouterFlavor: model.FlavorTraditional,
		Routes:       []*model.KongRoute{&route},
		Reason:       []string{"catch-all"},
	}}
	ctx := &format.KonnectContext{ControlPlaneID: "cp-1", Region: "us"}

	out, err := format.JSON(findings, model.FlavorTraditional, ctx)
	if err != nil {
		t.Fatalf("JSON format failed: %v", err)
	}

	pos := func(key string) int {
		i := strings.Index(out, `"`+key+`"`)
		if i < 0 {
			t.Fatalf("expected key %q in output:\n%s", key, out)
		}
		return i
	}
	name, protocols, id, paths, konnectURL := pos("name"), pos("protocols"), pos("id"), pos("paths"), pos("_konnectUrl")
	if !(name < protocols && protocols < id && id < paths && paths < konnectURL) {
		t.Errorf("expected field order name, protocols, id, paths, _konnectUrl "+
			"(original API order preserved, _konnectUrl appended last); got positions "+
			"name=%d protocols=%d id=%d paths=%d _konnectUrl=%d in:\n%s",
			name, protocols, id, paths, konnectURL, out)
	}
}
