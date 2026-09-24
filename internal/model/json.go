package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// Lossless JSON handling for Kong entities.
//
// Konnect returns many fields this tool does not model (preserve_host,
// https_redirect_status_code, updated_at, ...). Decoded entities keep their
// raw JSON bytes and re-encode lazily, so a fetch → dump round trip
// never drops or rewrites data. Entities are treated as immutable; the only
// derivation, KongRoute.WithPaths (used to split multi-path routes), is
// reflected by overriding "paths". Entities built in code (no raw object)
// encode their modelled fields.
//
// Route fields are preserved in their original order (see RawField):
// encoding/json always sorts map[string]any keys alphabetically on marshal,
// which would silently reorder every field relative to what Konnect actually
// returned. That matters here because format.LinkedRoute appends a
// `_konnectUrl` key onto a route's fields for JSON output — doing that via a
// map broke the original field order for every live (non-offline) JSON
// report.

// RawField is one key/value pair of a route's JSON fields, preserving the
// original order they were decoded in (or, for a route built in code with no
// raw payload, the order its modelled fields are declared in).
type RawField struct {
	Key   string
	Value json.RawMessage
}

// MarshalFields encodes fields as a JSON object, preserving their order.
func MarshalFields(fields []RawField) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(f.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		if len(f.Value) == 0 {
			buf.WriteString("null")
		} else {
			buf.Write(f.Value)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// parseOrderedFields decodes a JSON object into RawFields in their original
// key order, using a streaming token decoder (json.Unmarshal into a map
// would report keys in an unspecified, effectively random, order).
func parseOrderedFields(raw []byte) ([]RawField, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	var fields []RawField
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		fields = append(fields, RawField{Key: key, Value: value})
	}
	return fields, nil
}

// setField returns fields with key's value set to value, updating it in
// place if key is already present (preserving its original position) or
// appending a new entry otherwise. The input slice is not mutated.
func setField(fields []RawField, key string, value json.RawMessage) []RawField {
	out := slices.Clone(fields)
	for i := range out {
		if out[i].Key == key {
			out[i].Value = value
			return out
		}
	}
	return append(out, RawField{Key: key, Value: value})
}

// orderedFieldsOf marshals v (a struct) and re-decodes it into RawFields.
// encoding/json marshals struct fields in declaration order (unlike map
// keys, which it always sorts), so this preserves a deterministic, sensible
// order for entities with no original raw payload to preserve order from.
func orderedFieldsOf(v any) ([]RawField, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return parseOrderedFields(b)
}

// UnmarshalJSON decodes a route and retains all unmodelled fields lazily.
func (r *KongRoute) UnmarshalJSON(b []byte) error {
	type plain KongRoute
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*r = KongRoute(p)
	r.raw = bytes.Clone(b)
	return nil
}

// MarshalJSON encodes the route including any unmodelled fields, preserving
// their original field order.
func (r *KongRoute) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	if !r.pathsOverridden && len(r.raw) > 0 {
		return r.raw, nil
	}
	fields, err := r.Fields()
	if err != nil {
		return nil, err
	}
	return MarshalFields(fields)
}

// Fields returns the route's fields (modelled fields overlaid on the
// original payload) in their original API response order. Callers may
// append additional fields, e.g. `_konnectUrl`.
func (r *KongRoute) Fields() ([]RawField, error) {
	if r.extra == nil && len(r.raw) > 0 {
		fields, err := parseOrderedFields(r.raw)
		if err != nil {
			return nil, err
		}
		r.extra = fields
	}
	if r.extra == nil {
		type plain KongRoute
		return orderedFieldsOf(plain(*r))
	}
	out := slices.Clone(r.extra)
	if r.pathsOverridden {
		b, err := json.Marshal(r.Paths)
		if err != nil {
			return nil, err
		}
		out = setField(out, "paths", b)
	}
	return out, nil
}

// UnmarshalJSON decodes a service and retains all unmodelled fields lazily.
func (s *KongService) UnmarshalJSON(b []byte) error {
	type plain KongService
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*s = KongService(p)
	s.raw = bytes.Clone(b)
	return nil
}

// MarshalJSON encodes the service including any unmodelled fields.
func (s *KongService) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}
	if len(s.raw) > 0 {
		return s.raw, nil
	}
	if s.extra != nil {
		return json.Marshal(s.extra)
	}
	type plain KongService
	return json.Marshal(plain(*s))
}
