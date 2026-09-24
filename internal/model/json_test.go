// Tests for lossless, order-preserving JSON handling of KongRoute (Fields,
// MarshalFields, MarshalJSON). encoding/json always sorts map keys
// alphabetically on marshal; these tests guard against that regressing back
// in, since the original bug was exactly that: routes decoded from Konnect
// (whose field order this tool does not control) came back out of
// format.LinkedRoute's JSON output alphabetized instead of in their
// original order.
package model_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/paambaati/kongcheck/internal/model"
)

// keyOrder returns the order keys first appear in a JSON object's rendered
// bytes (not its parsed form, which would lose order).
func keyOrder(t *testing.T, b []byte, keys ...string) []int {
	t.Helper()
	s := string(b)
	idx := make([]int, len(keys))
	for i, k := range keys {
		pos := strings.Index(s, `"`+k+`"`)
		if pos < 0 {
			t.Fatalf("expected key %q in %s", k, s)
		}
		idx[i] = pos
	}
	return idx
}

func assertIncreasing(t *testing.T, idx []int, labels []string) {
	t.Helper()
	for i := 1; i < len(idx); i++ {
		if idx[i-1] >= idx[i] {
			t.Fatalf("expected %s before %s (got positions %v for %v)", labels[i-1], labels[i], idx, labels)
		}
	}
}

func TestKongRoute_Fields_PreservesOriginalOrderNotAlphabetical(t *testing.T) {
	// Deliberately not alphabetical and not in KongRoute's Go struct
	// declaration order, so passing this test can only mean the original
	// byte order was preserved, not any other deterministic-but-wrong order.
	raw := []byte(`{"name":"my-route","protocols":["http"],"id":"r1","paths":["/foo"]}`)
	var r model.KongRoute
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	fields, err := r.Fields()
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	got := make([]string, len(fields))
	for i, f := range fields {
		got[i] = f.Key
	}
	want := []string{"name", "protocols", "id", "paths"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Fields() order = %v, want %v", got, want)
	}

	b, err := json.Marshal(&r)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(b) != string(raw) {
		t.Fatalf("MarshalJSON = %s, want byte-identical round trip %s", b, raw)
	}
}

func TestKongRoute_Fields_WithPathsKeepsOriginalKeyPosition(t *testing.T) {
	// "paths" is deliberately the first field here; overriding it via
	// WithPaths must update its value in place, not move it to the end.
	raw := []byte(`{"paths":["/old"],"id":"r1","name":"my-route"}`)
	var r model.KongRoute
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	split := r.WithPaths([]string{"/new"})
	fields, err := split.Fields()
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if len(fields) != 3 || fields[0].Key != "paths" {
		t.Fatalf("expected 'paths' to stay first, got %+v", fields)
	}
	if string(fields[0].Value) != `["/new"]` {
		t.Fatalf("expected paths value updated to [\"/new\"], got %s", fields[0].Value)
	}

	// The original route's cached fields must be unaffected by the copy's
	// override (WithPaths must not mutate the shared underlying data).
	origFields, err := r.Fields()
	if err != nil {
		t.Fatalf("Fields (original): %v", err)
	}
	if string(origFields[0].Value) != `["/old"]` {
		t.Fatalf("expected original route's paths unaffected by WithPaths, got %s", origFields[0].Value)
	}
}

func TestKongRoute_Fields_NoRawFallsBackToDeterministicOrder(t *testing.T) {
	r := &model.KongRoute{ID: "r1", Name: "in-code-route", Paths: []string{"/api"}}
	fields, err := r.Fields()
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if len(fields) == 0 {
		t.Fatal("expected at least the modelled fields")
	}
	// Struct declaration order is id, name, paths, ... — assert at least
	// that id precedes name precedes paths (deterministic, not alphabetical
	// happenstance, since alphabetical would also put id before name before
	// paths — the real guard here is TestKongRoute_Fields_PreservesOriginalOrderNotAlphabetical
	// above; this test just guards against a panic/empty result in the
	// no-raw fallback path).
	idx := keyOrder(t, mustMarshalFields(t, fields), "id", "name", "paths")
	assertIncreasing(t, idx, []string{"id", "name", "paths"})
}

func mustMarshalFields(t *testing.T, fields []model.RawField) []byte {
	t.Helper()
	b, err := model.MarshalFields(fields)
	if err != nil {
		t.Fatalf("MarshalFields: %v", err)
	}
	return b
}
