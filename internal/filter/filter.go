// Package filter implements the `--filter key:value` finding predicates.
//
// A finding is included when any of its routes satisfies the full predicate
// set. Different keys combine with AND; repeated keys combine with OR:
//
//	--filter service:payments-svc                  # findings touching that service
//	--filter tag:team-a --filter tag:team-b        # team-a OR team-b
//	--filter tag:team-a --filter path:/payments    # team-a AND under /payments
package filter

import (
	"fmt"
	"slices"
	"strings"

	"github.com/paambaati/kongcheck/internal/model"
)

// Key is a filter dimension.
type Key string

// Supported filter keys.
//
//	path     route has a path whose stem (leading `~` stripped) starts with value
//	name     route name contains value (case-insensitive)
//	service  service ID equals value, or service name contains value (case-insensitive)
//	tag      route has exactly this tag
//	id       route ID equals value
const (
	KeyPath    Key = "path"
	KeyName    Key = "name"
	KeyService Key = "service"
	KeyTag     Key = "tag"
	KeyID      Key = "id"
)

// Keys lists the supported keys in documentation order.
var Keys = []Key{KeyPath, KeyName, KeyService, KeyTag, KeyID}

// Predicate is one parsed `key:value` filter.
type Predicate struct {
	Key   Key
	Value string
	// valueFold is strings.ToLower(Value), precomputed once so case-insensitive
	// name/service matching does not allocate per route.
	valueFold string
}

// Parse parses a single `key:value` filter. The value may itself contain
// colons (e.g. `path:~/api:v2`).
func Parse(raw string) (Predicate, error) {
	key, value, ok := strings.Cut(raw, ":")
	if !ok {
		return Predicate{}, fmt.Errorf(`Invalid --filter "%s": expected format key:value `+
			`(e.g. path:/api, name:payments, service:payments-svc, tag:team-a, id:<uuid>)`, raw)
	}
	if !slices.Contains(Keys, Key(key)) {
		names := make([]string, len(Keys))
		for i, k := range Keys {
			names[i] = string(k)
		}
		return Predicate{}, fmt.Errorf(`Unknown filter key "%s". Supported keys: %s`, key, strings.Join(names, ", "))
	}
	if value == "" {
		return Predicate{}, fmt.Errorf(`Filter value for key "%s" must not be empty.`, key)
	}
	return Predicate{Key: Key(key), Value: value, valueFold: strings.ToLower(value)}, nil
}

// ParseAll parses every raw filter; nil or empty input yields no predicates.
func ParseAll(raw []string) ([]Predicate, error) {
	preds := make([]Predicate, 0, len(raw))
	for _, r := range raw {
		p, err := Parse(r)
		if err != nil {
			return nil, err
		}
		preds = append(preds, p)
	}
	return preds, nil
}

// RouteMatches tests a route (and its resolved service, which may be nil)
// against a single predicate.
func RouteMatches(route *model.KongRoute, service *model.KongService, p Predicate) bool {
	// Ensure valueFold is set even for predicates built inline in tests.
	fold := p.valueFold
	if fold == "" {
		fold = strings.ToLower(p.Value)
	}
	switch p.Key {
	case KeyPath:
		// Stripping `~` lets path:/api match both /api/v2 and ~/api/v2.*.
		return slices.ContainsFunc(route.Paths, func(path string) bool {
			return strings.HasPrefix(strings.TrimPrefix(path, "~"), p.Value)
		})
	case KeyName:
		return containsFoldLower(route.Name, fold)
	case KeyService:
		if (route.Service != nil && route.Service.ID == p.Value) || (service != nil && service.ID == p.Value) {
			return true
		}
		return service != nil && service.Name != "" && containsFoldLower(service.Name, fold)
	case KeyTag:
		return slices.Contains(route.Tags, p.Value)
	case KeyID:
		return route.ID == p.Value
	}
	return false
}

// FilterSet groups predicates by key for efficient repeated matching without
// per-route map allocations.
type FilterSet struct {
	order  []Key
	groups map[Key][]Predicate
}

// NewFilterSet groups predicates by key, preserving first-seen key order.
func NewFilterSet(preds []Predicate) FilterSet {
	var order []Key
	groups := make(map[Key][]Predicate)
	for _, p := range preds {
		if _, ok := groups[p.Key]; !ok {
			order = append(order, p.Key)
		}
		groups[p.Key] = append(groups[p.Key], p)
	}
	return FilterSet{order: order, groups: groups}
}

// Matches tests whether route satisfies all key groups in the filter set.
func (fs FilterSet) Matches(route *model.KongRoute, service *model.KongService) bool {
	for _, k := range fs.order {
		if !slices.ContainsFunc(fs.groups[k], func(p Predicate) bool {
			return RouteMatches(route, service, p)
		}) {
			return false
		}
	}
	return true
}

// RouteMatchesAll applies AND across keys and OR within a key. An empty
// predicate set matches every route.
func RouteMatchesAll(route *model.KongRoute, service *model.KongService, preds []Predicate) bool {
	if len(preds) == 0 {
		return true
	}
	return NewFilterSet(preds).Matches(route, service)
}

// Apply keeps findings where any involved route satisfies all predicates, so
// a cross-team collision still surfaces when filtering to your own service.
func Apply(findings []*model.Finding, preds []Predicate, services *model.ServiceIndex) []*model.Finding {
	if len(preds) == 0 {
		return findings
	}
	fs := NewFilterSet(preds)
	out := make([]*model.Finding, 0, len(findings))
	for _, f := range findings {
		if slices.ContainsFunc(f.Routes, func(r *model.KongRoute) bool {
			return fs.Matches(r, services.Get(r.ServiceID()))
		}) {
			out = append(out, f)
		}
	}
	return out
}

// containsFoldLower reports whether s contains substr (already lowercased).
func containsFoldLower(s, substrLower string) bool {
	return strings.Contains(strings.ToLower(s), substrLower)
}
