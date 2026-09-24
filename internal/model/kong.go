// Package model defines the core domain types for Kong route analysis.
//
// All JSON field names mirror the Kong Admin API / Konnect Control Planes
// Config v2 so that API responses can be decoded directly. Kong entities keep
// every field of the original payload (including ones this tool does not
// model), so re-encoding a fetched entity is lossless.
//
// See https://developer.konghq.com/api/konnect/control-planes-config/v2/
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// KongService is a Kong service entity. Only the fields relevant to routing
// diagnostics are modelled; all other fields are preserved for re-encoding.
type KongService struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`

	raw   []byte
	extra map[string]json.RawMessage
}

// ServiceRef is the partial service reference embedded in a route.
type ServiceRef struct {
	ID string `json:"id"`
}

// IPPort is a source or destination constraint on a stream route.
// An empty IP or a zero Port means "unconstrained" on that dimension.
type IPPort struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// KongRoute is a Kong route entity.
//
// Paths starting with `~` are regex paths (PCRE), not glob patterns. All other
// paths are plain prefix matches.
//
// See https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua
type KongRoute struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Paths is nil when the route has no paths; a leading `~` marks a regex path.
	Paths []string `json:"paths,omitempty"`
	// Methods lists allowed HTTP methods; empty means all methods.
	Methods []string `json:"methods,omitempty"`
	// Hosts lists host constraints (wildcards like `*.example.com` allowed).
	Hosts []string `json:"hosts,omitempty"`
	// Headers lists header constraints in their original order. A single value
	// starting with `~*` is a regex match.
	Headers Headers `json:"headers,omitempty"`
	// StripPath affects upstream URI construction only, never route selection.
	StripPath    *bool  `json:"strip_path,omitempty"`
	PathHandling string `json:"path_handling,omitempty"`
	// RegexPriority breaks ties between regex routes (higher wins).
	RegexPriority int `json:"regex_priority,omitempty"`
	// CreatedAt is the Unix epoch (seconds); earlier wins the final tie-break.
	// Nil when unknown — Kong only compares it when both routes have one.
	CreatedAt    *int64      `json:"created_at,omitempty"`
	Service      *ServiceRef `json:"service,omitempty"`
	Tags         []string    `json:"tags,omitempty"`
	Protocols    []string    `json:"protocols,omitempty"`
	SNIs         []string    `json:"snis,omitempty"`
	Sources      []IPPort    `json:"sources,omitempty"`
	Destinations []IPPort    `json:"destinations,omitempty"`
	// Expression is only present on control planes using the `expressions`
	// router flavor.
	Expression *string `json:"expression,omitempty"`

	raw []byte
	// extra holds every field of the original payload this tool does not
	// model, in their original API response order (so re-encoding stays
	// byte-order-faithful instead of the alphabetical order a
	// map[string]json.RawMessage would force on re-marshal). See Fields.
	extra           []RawField
	pathsOverridden bool
}

// DisplayName returns the route name, falling back to its ID.
func (r *KongRoute) DisplayName() string {
	if r.Name != "" {
		return r.Name
	}
	return r.ID
}

// ServiceID returns the ID of the service referenced by the route, or "".
func (r *KongRoute) ServiceID() string {
	if r.Service == nil {
		return ""
	}
	return r.Service.ID
}

// WithPaths returns a shallow copy of the route whose Paths are replaced.
// Used when splitting multi-path routes, mirroring Kong's own
// "split routes by paths to sort properly" behaviour.
func (r *KongRoute) WithPaths(paths []string) *KongRoute {
	c := *r
	c.Paths = paths
	c.pathsOverridden = true
	return &c
}

// HeaderConstraint is one header-name constraint and its allowed values.
type HeaderConstraint struct {
	Name   string
	Values []string
}

// Headers is an ordered list of header constraints. It encodes to and from a
// JSON object while preserving key order.
type Headers []HeaderConstraint

// Lookup returns the values for a header name (case-insensitive).
func (h Headers) Lookup(name string) ([]string, bool) {
	for _, c := range h {
		if strings.EqualFold(c.Name, name) {
			return c.Values, true
		}
	}
	return nil, false
}

// UnmarshalJSON decodes a JSON object, preserving key order.
func (h *Headers) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*h = nil
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("headers: expected JSON object")
	}
	out := Headers{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		var values []string
		if err := dec.Decode(&values); err != nil {
			return fmt.Errorf("headers[%q]: %w", key, err)
		}
		out = append(out, HeaderConstraint{Name: key, Values: values})
	}
	*h = out
	return nil
}

// MarshalJSON encodes the headers as a JSON object in their original order.
func (h Headers) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, c := range h {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(c.Name)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(nonNil(c.Values))
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ServiceIndex holds services keyed by ID while preserving insertion order,
// matching JavaScript Map semantics (re-setting a key keeps its position).
type ServiceIndex struct {
	order []string
	byID  map[string]*KongService
}

// NewServiceIndex builds an index from a list of services.
func NewServiceIndex(services ...*KongService) *ServiceIndex {
	idx := &ServiceIndex{byID: make(map[string]*KongService, len(services))}
	for _, s := range services {
		if s != nil {
			idx.Set(s)
		}
	}
	return idx
}

// Set inserts or replaces a service.
func (i *ServiceIndex) Set(s *KongService) {
	if i.byID == nil {
		i.byID = make(map[string]*KongService)
	}
	if _, ok := i.byID[s.ID]; !ok {
		i.order = append(i.order, s.ID)
	}
	i.byID[s.ID] = s
}

// Get returns the service with the given ID, or nil. Safe on a nil index.
func (i *ServiceIndex) Get(id string) *KongService {
	if i == nil || id == "" {
		return nil
	}
	return i.byID[id]
}

// Len returns the number of services. Safe on a nil index.
func (i *ServiceIndex) Len() int {
	if i == nil {
		return 0
	}
	return len(i.order)
}

// All returns the services in insertion order. Safe on a nil index.
func (i *ServiceIndex) All() []*KongService {
	if i == nil {
		return []*KongService{}
	}
	out := make([]*KongService, 0, len(i.order))
	for _, id := range i.order {
		out = append(out, i.byID[id])
	}
	return out
}

// KonnectConfig holds connection options for a Konnect control plane.
type KonnectConfig struct {
	Token          string
	ControlPlaneID string
	// Region is the Konnect region code; empty means "us".
	Region string
}

// KonnectData is the full configuration payload, normalised for analysis.
type KonnectData struct {
	Routes   []*KongRoute
	Services *ServiceIndex
	// RouterFlavor is empty when it could not be detected.
	RouterFlavor RouterFlavor
	// ControlPlaneID and Region are set when fetched live from Konnect and
	// empty in offline (--file) mode. They drive Konnect UI deep-links.
	ControlPlaneID string
	Region         string
}

// ServiceFor resolves the service referenced by a route, or nil.
func (d *KonnectData) ServiceFor(r *KongRoute) *KongService {
	return d.Services.Get(r.ServiceID())
}
