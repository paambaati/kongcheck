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
	return Predicate{Key: Key(key), Value: value}, nil
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
	switch p.Key {
	case KeyPath:
		// Stripping `~` lets path:/api match both /api/v2 and ~/api/v2.*.
		return slices.ContainsFunc(route.Paths, func(path string) bool {
			return strings.HasPrefix(strings.TrimPrefix(path, "~"), p.Value)
		})
	case KeyName:
		return containsFold(route.Name, p.Value)
	case KeyService:
		if (route.Service != nil && route.Service.ID == p.Value) || (service != nil && service.ID == p.Value) {
			return true
		}
		return service != nil && service.Name != "" && containsFold(service.Name, p.Value)
	case KeyTag:
		return slices.Contains(route.Tags, p.Value)
	case KeyID:
		return route.ID == p.Value
	}
	return false
}

// RouteMatchesAll applies AND across keys and OR within a key. An empty
// predicate set matches every route.
func RouteMatchesAll(route *model.KongRoute, service *model.KongService, preds []Predicate) bool {
	// Group values by key, keeping first-seen key order.
	var order []Key
	groups := make(map[Key][]string)
	for _, p := range preds {
		if _, ok := groups[p.Key]; !ok {
			order = append(order, p.Key)
		}
		groups[p.Key] = append(groups[p.Key], p.Value)
	}
	for _, k := range order {
		if !slices.ContainsFunc(groups[k], func(v string) bool {
			return RouteMatches(route, service, Predicate{Key: k, Value: v})
		}) {
			return false
		}
	}
	return true
}

// Apply keeps findings where any involved route satisfies all predicates, so
// a cross-team collision still surfaces when filtering to your own service.
func Apply(findings []*model.Finding, preds []Predicate, services *model.ServiceIndex) []*model.Finding {
	if len(preds) == 0 {
		return findings
	}
	out := make([]*model.Finding, 0, len(findings))
	for _, f := range findings {
		if slices.ContainsFunc(f.Routes, func(r *model.KongRoute) bool {
			return RouteMatchesAll(r, services.Get(r.ServiceID()), preds)
		}) {
			out = append(out, f)
		}
	}
	return out
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
