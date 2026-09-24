package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paambaati/kongcheck/internal/client"
	"github.com/paambaati/kongcheck/internal/model"
)

func TestClient_RedactBearer(t *testing.T) {
	t.Run("bearer tokens", func(t *testing.T) {
		msg := "failed with Bearer secret123 and Bearer token-xyz"
		redacted := client.RedactBearer(msg)
		if strings.Contains(redacted, "secret123") || strings.Contains(redacted, "token-xyz") {
			t.Fatalf("expected tokens redacted, got %s", redacted)
		}
		if !strings.Contains(redacted, "Bearer [REDACTED]") {
			t.Fatalf("expected placeholder present, got %s", redacted)
		}
	})

	t.Run("bare Kong personal access tokens", func(t *testing.T) {
		msg := "POST https://us.api.konghq.com/v2?token=kpat_ABCdef123456-_ failed"
		redacted := client.RedactBearer(msg)
		if strings.Contains(redacted, "kpat_ABCdef123456-_") {
			t.Fatalf("expected bare PAT redacted, got %s", redacted)
		}
		if !strings.Contains(redacted, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] placeholder, got %s", redacted)
		}
	})

	t.Run("Authorization header value with PAT", func(t *testing.T) {
		msg := "Authorization: Bearer kpat_live_secret_value"
		redacted := client.RedactBearer(msg)
		if strings.Contains(redacted, "kpat_live_secret_value") {
			t.Fatalf("expected PAT redacted, got %s", redacted)
		}
	})

	t.Run("does not mangle non-secret text", func(t *testing.T) {
		msg := "route path /api/v1/users has no secrets"
		if got := client.RedactBearer(msg); got != msg {
			t.Fatalf("expected no change, got %s", got)
		}
	})
}

func TestClient_FetchKonnectConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/core-entities/routes"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"r1","name":"route-1","paths":["/test"]}],"next":null}`))
		case strings.HasSuffix(r.URL.Path, "/core-entities/services"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"s1","name":"service-1"}],"next":null}`))
		case strings.Contains(r.URL.Path, "/v2/control-planes/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"config":{"router_flavor":"traditional"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := &client.Client{
		HTTP:     ts.Client(),
		BaseURLs: map[string]string{"us": ts.URL},
	}

	data, err := c.FetchKonnectConfig(context.Background(), model.KonnectConfig{
		Token:          "test-token",
		ControlPlaneID: "11111111-1111-1111-1111-111111111111",
		Region:         "us",
	}, client.Options{Verbose: true})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Routes) != 1 || data.Routes[0].Name != "route-1" {
		t.Errorf("expected 1 route, got %+v", data.Routes)
	}
	if data.Services.Len() != 1 || data.Services.Get("s1") == nil {
		t.Errorf("expected service s1 in index")
	}
	if data.RouterFlavor != model.FlavorTraditional {
		t.Errorf("expected traditional flavor, got %v", data.RouterFlavor)
	}
}

func TestClient_LoadLocalConfig(t *testing.T) {
	tmp := t.TempDir()
	dumpPath := filepath.Join(tmp, "dump.json")
	content := `{"routerFlavor":"traditional","routes":[{"id":"r1","paths":["/api"]}],"services":[{"id":"s1","name":"svc"}]}`
	if err := os.WriteFile(dumpPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := client.LoadLocalConfig(dumpPath)
	if err != nil {
		t.Fatalf("LoadLocalConfig failed: %v", err)
	}
	if len(data.Routes) != 1 || data.Routes[0].ID != "r1" {
		t.Errorf("expected route r1, got %+v", data.Routes)
	}
	if data.Services.Get("s1") == nil {
		t.Errorf("expected service s1")
	}

	// Dump representation roundtrip
	dump := client.NewLocalConfigDump(data)
	if dump.RouterFlavor != model.FlavorTraditional || len(dump.Routes) != 1 || len(dump.Services) != 1 {
		t.Errorf("unexpected dump output: %+v", dump)
	}
}

func TestClient_RetryLogic(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := attempts.Add(1)
		if att < 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"next":null}`))
	}))
	defer ts.Close()

	c := &client.Client{
		HTTP:     ts.Client(),
		BaseURLs: map[string]string{"us": ts.URL},
		Sleep: func(ctx context.Context, d time.Duration) error {
			return nil
		},
	}

	data, err := c.FetchKonnectConfig(context.Background(), model.KonnectConfig{
		Token:          "test-token",
		ControlPlaneID: "22222222-2222-2222-2222-222222222222",
		Region:         "us",
	}, client.Options{})

	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if data == nil {
		t.Fatal("expected data non-nil")
	}
}
