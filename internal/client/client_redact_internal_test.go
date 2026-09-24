// White-box regression tests proving redactedError preserves the original
// error in the chain (for errors.Is/errors.As) while still redacting secrets
// from its Error() string. Before this fix, both get() error paths
// (transport Do() failures and response-body read failures) wrapped the
// redacted message in a plain errors.New, discarding the original error's
// type — so a caller could never tell a context.DeadlineExceeded/Canceled
// or a *net.OpError timeout apart from any other failure.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRedactedError_PreservesChainAndRedactsMessage(t *testing.T) {
	const token = "super-secret-token"
	original := fmt.Errorf("dial failed: Bearer %s rejected", token)

	err := redactedError(original, token)

	if strings.Contains(err.Error(), token) {
		t.Fatalf("expected token redacted from message, got: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("expected a [REDACTED] placeholder in message, got: %v", err)
	}
	if !errors.Is(err, original) {
		t.Fatal("expected errors.Is(err, original) to succeed through Unwrap")
	}

	wrapped := fmt.Errorf("get: %w", original)
	err2 := redactedError(wrapped, token)
	if !errors.Is(err2, original) {
		t.Fatal("expected errors.Is to see through both the redactedError and the inner %w wrap")
	}
}

func TestGet_TransportFailurePreservesDeadlineExceededForErrorsIs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer ts.Close()

	c := &Client{HTTP: ts.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, _, _, err := c.get(ctx, ts.URL, "test-token-value")
	if err == nil {
		t.Fatal("expected get() to fail once the context deadline is exceeded")
	}
	if strings.Contains(err.Error(), "test-token-value") {
		t.Fatalf("expected token redacted from transport error message, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected errors.Is(err, context.DeadlineExceeded) to succeed "+
			"(the original *url.Error must survive redaction), got: %v", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Not all platforms surface this as a net.Error wrapping the
		// deadline, but when they do it must still be reachable through the
		// redacted wrapper.
		if !netErr.Timeout() {
			t.Errorf("expected net.Error.Timeout() to be true")
		}
	}
}
