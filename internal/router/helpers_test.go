package router_test

import (
	"fmt"
	"sync/atomic"

	"github.com/paambaati/kongcheck/internal/model"
	"github.com/paambaati/kongcheck/internal/router"
)

var routeSeq atomic.Int64

// makeRoute builds a MarshalledRoute (traditional flavor) from a partial
// route, mirroring the TS test helper. Routes without an ID get a unique,
// deterministic one.
func makeRoute(r model.KongRoute) *router.MarshalledRoute {
	if r.ID == "" {
		r.ID = fmt.Sprintf("route-%d", routeSeq.Add(1))
	}
	return router.MarshalRoute(&r, nil, model.FlavorTraditional)
}

// ptr returns a pointer to v (for optional fields such as CreatedAt or SNI).
func ptr[T any](v T) *T { return &v }
