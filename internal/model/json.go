package model

import (
	"bytes"
	"encoding/json"
	"maps"
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

// MarshalJSON encodes the route including any unmodelled fields.
func (r *KongRoute) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	if !r.pathsOverridden && len(r.raw) > 0 {
		return r.raw, nil
	}
	m, err := r.ToMap()
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// ToMap returns the route as a JSON-ready map (modelled fields overlaid on
// the original payload). Callers may add keys, e.g. `_konnectUrl`.
func (r *KongRoute) ToMap() (map[string]json.RawMessage, error) {
	if r.extra == nil && len(r.raw) > 0 {
		var extra map[string]json.RawMessage
		if err := json.Unmarshal(r.raw, &extra); err != nil {
			return nil, err
		}
		r.extra = extra
	}
	if r.extra == nil {
		type plain KongRoute
		return fieldsOf(plain(*r))
	}
	out := maps.Clone(r.extra)
	if r.pathsOverridden {
		b, err := json.Marshal(r.Paths)
		if err != nil {
			return nil, err
		}
		out["paths"] = b
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

func fieldsOf(v any) (map[string]json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	err = json.Unmarshal(b, &fields)
	return fields, err
}
