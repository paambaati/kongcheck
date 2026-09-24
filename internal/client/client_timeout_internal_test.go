// White-box regression test for fetchPage's timeout budget.
//
// fetchPage retries 429/503 responses. The context.WithTimeout that bounds
// those retries must wrap the whole retry loop (every attempt plus its
// backoff sleep) once, not be re-armed fresh for each attempt inside get —
// otherwise a slow/hanging endpoint can make one page take up to
// (maxRetries+1) x pageTimeout instead of a single pageTimeout ceiling.
package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchPage_SharesOneTimeoutAcrossRetries(t *testing.T) {
	// Shrink the shared budget so the test runs fast; restore afterwards
	// since pageTimeout is a package-level var shared by other tests.
	origTimeout := pageTimeout
	pageTimeout = 60 * time.Millisecond
	t.Cleanup(func() { pageTimeout = origTimeout })

	const perAttemptDelay = 25 * time.Millisecond

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(perAttemptDelay)
		w.Header().Set("Retry-After", "0") // instant retry, no extra backoff wait
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"message":"unavailable"}`))
	}))
	defer ts.Close()

	c := &Client{HTTP: ts.Client()}

	start := time.Now()
	var out any
	err := c.fetchPage(context.Background(), ts.URL, "test-token", &out)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected fetchPage to fail (server always returns 503), got nil error")
	}
	if _, isAPIErr := err.(*APIError); isAPIErr {
		t.Fatalf("expected the shared pageTimeout budget to cut retries short with a "+
			"context/transport error, got an *APIError instead (all retries ran to completion): %v", err)
	}

	// maxRetries=3 means up to 4 attempts; each takes perAttemptDelay=25ms.
	// If each attempt re-armed its own fresh pageTimeout (the bug), all 4
	// would complete: ~100ms, comfortably over budget. With one shared
	// pageTimeout=60ms, the call must be cut off close to 60ms — well under
	// what 4 full attempts would take.
	maxAllAttempts := 4 * perAttemptDelay
	if elapsed >= maxAllAttempts {
		t.Fatalf("fetchPage took %v, want well under %v (all %d attempts would have completed, "+
			"meaning the timeout was re-armed per attempt instead of shared)", elapsed, maxAllAttempts, 4)
	}
}
