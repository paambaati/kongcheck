package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/paambaati/kongcheck/internal/cli"
	"github.com/paambaati/kongcheck/internal/client"
	"github.com/paambaati/kongcheck/internal/model"
)

func stubApp(data *model.KonnectData) (*cli.App, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app := &cli.App{
		Stdin:       strings.NewReader(""),
		Stdout:      stdout,
		Stderr:      stderr,
		Getenv:      func(string) string { return "" },
		StdoutIsTTY: false,
		Fetch: func(ctx context.Context, cfg model.KonnectConfig, opts client.Options) (*model.KonnectData, error) {
			return data, nil
		},
		LoadFile: func(path string) (*model.KonnectData, error) {
			return data, nil
		},
	}
	return app, stdout, stderr
}

func sampleData() *model.KonnectData {
	created := int64(1700000000)
	routes := []*model.KongRoute{
		{
			ID:        "00000000-0000-0000-0000-000000000001",
			Name:      "r1",
			Paths:     []string{"/api/v1/users"},
			CreatedAt: &created,
		},
		{
			ID:        "00000000-0000-0000-0000-000000000002",
			Name:      "r2",
			Paths:     []string{"~/api/v1/users.*"},
			CreatedAt: &created,
		},
	}
	return &model.KonnectData{
		Routes:         routes,
		Services:       model.NewServiceIndex(),
		RouterFlavor:   model.FlavorTraditional,
		ControlPlaneID: "11111111-1111-1111-1111-111111111111",
		Region:         "us",
	}
}

func TestCLI_Analyze(t *testing.T) {
	app, stdout, stderr := stubApp(sampleData())
	code := app.Run(context.Background(), []string{"analyze", "--file", "mock.json", "--format", "json"})
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"totalFindings": 1`) {
		t.Errorf("expected 1 finding in json output:\n%s", stdout.String())
	}
}

func TestCLI_Collisions(t *testing.T) {
	app, stdout, stderr := stubApp(sampleData())
	code := app.Run(context.Background(), []string{"collisions", "--file", "mock.json", "--format", "csv"})
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "severity,type,router_flavor") {
		t.Errorf("expected CSV header:\n%s", stdout.String())
	}
}

func TestCLI_ExplainRequest(t *testing.T) {
	app, stdout, stderr := stubApp(sampleData())
	code := app.Run(context.Background(), []string{
		"explain-request",
		"--file", "mock.json",
		"--path", "/api/v1/userstest",
		"--method", "GET",
	})
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Winning route: r2") {
		t.Errorf("expected r2 as winner in explanation:\n%s", stdout.String())
	}
}

// TestCLI_ExplainRequest_JSONPreservesRouteFieldOrder guards against
// printExplainJSON's `_konnectUrl` injection reordering a matched route's
// fields. It used to round-trip through a map[string]json.RawMessage, which
// encoding/json always re-marshals with alphabetically sorted keys — putting
// "_konnectUrl" (ASCII '_' sorts before any lowercase letter) first, ahead of
// every field of the route itself, instead of appended last as intended.
func TestCLI_ExplainRequest_JSONPreservesRouteFieldOrder(t *testing.T) {
	app, stdout, stderr := stubApp(sampleData())
	code := app.Run(context.Background(), []string{
		"explain-request",
		"--file", "mock.json",
		"--path", "/api/v1/userstest",
		"--method", "GET",
		"--format", "json",
	})
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	route := strings.Index(out, `"route"`)
	flavor := strings.Index(out, `"flavor"`)
	konnectURL := strings.Index(out, `"_konnectUrl"`)
	if route < 0 || flavor < 0 || konnectURL < 0 {
		t.Fatalf("expected route, flavor, and _konnectUrl keys in output:\n%s", out)
	}
	// MarshalledRoute declares "route" before "flavor" before "_konnectUrl"
	// is appended; alphabetical order would reverse all three.
	if !(route < flavor && flavor < konnectURL) {
		t.Errorf("expected declaration order (route, ..., flavor, ..., _konnectUrl last), "+
			"got positions route=%d flavor=%d _konnectUrl=%d in:\n%s", route, flavor, konnectURL, out)
	}
}

// TestCLI_ExplainRequest_SanitizesTerminalControlCharacters guards against
// ANSI/terminal escape-sequence injection via an untrusted route `name` in
// explain-request's plain-text output (printExplainJSON's JSON output isn't
// rendered to a terminal, so it's out of scope here).
func TestCLI_ExplainRequest_SanitizesTerminalControlCharacters(t *testing.T) {
	const esc = "\x1b"
	created := int64(1700000000)
	data := &model.KonnectData{
		Routes: []*model.KongRoute{{
			ID:        "r1",
			Name:      esc + "[8m" + esc + "[31mHIDDEN" + esc + "[0mnormal-name",
			Paths:     []string{"/api"},
			CreatedAt: &created,
		}},
		Services:     model.NewServiceIndex(),
		RouterFlavor: model.FlavorTraditional,
	}
	app, stdout, stderr := stubApp(data)
	code := app.Run(context.Background(), []string{
		"explain-request", "--file", "mock.json", "--path", "/api", "--method", "GET",
	})
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if strings.Contains(out, esc) {
		t.Fatalf("expected all ESC (0x1B) bytes stripped from explain-request output, found one in:\n%q", out)
	}
	if !strings.Contains(out, "HIDDEN") || !strings.Contains(out, "normal-name") {
		t.Errorf("expected sanitized route name to remain visible, got:\n%q", out)
	}
}

func TestCLI_DumpConfig(t *testing.T) {
	app, stdout, stderr := stubApp(sampleData())
	code := app.Run(context.Background(), []string{
		"dump-config", "-",
		"--token", "tok",
		"--control-plane-id", "11111111-1111-1111-1111-111111111111",
	})
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"routerFlavor": "traditional"`) {
		t.Errorf("expected json dump in stdout:\n%s", stdout.String())
	}
}

func TestCLI_ValidationErrors(t *testing.T) {
	t.Run("missing token", func(t *testing.T) {
		app, _, stderr := stubApp(sampleData())
		code := app.Run(context.Background(), []string{"analyze"})
		if code == 0 || !strings.Contains(stderr.String(), "--token or KONNECT_TOKEN environment variable is required") {
			t.Errorf("expected missing token error, got code %d, stderr: %s", code, stderr.String())
		}
	})

	t.Run("missing path for explain", func(t *testing.T) {
		app, _, stderr := stubApp(sampleData())
		code := app.Run(context.Background(), []string{"explain-request", "--file", "mock.json"})
		if code == 0 || !strings.Contains(stderr.String(), "--path is required") {
			t.Errorf("expected missing path error, got code %d, stderr: %s", code, stderr.String())
		}
	})

	t.Run("invalid command", func(t *testing.T) {
		app, _, stderr := stubApp(sampleData())
		code := app.Run(context.Background(), []string{"foobar"})
		if code == 0 || !strings.Contains(stderr.String(), "Invalid command: foobar") {
			t.Errorf("expected invalid command error, got code %d, stderr: %s", code, stderr.String())
		}
	})
}

func TestCLI_FailOnInfoWithoutShowInfo(t *testing.T) {
	// Universal catch-all produces an INFO finding. --fail-on INFO must still
	// exit 1 even when the finding is hidden from the rendered report.
	created := int64(1700000000)
	data := &model.KonnectData{
		Routes: []*model.KongRoute{{
			ID:        "00000000-0000-0000-0000-000000000009",
			Name:      "catch-all",
			Paths:     []string{"/"},
			CreatedAt: &created,
		}},
		Services:       model.NewServiceIndex(),
		RouterFlavor:   model.FlavorTraditional,
		ControlPlaneID: "11111111-1111-1111-1111-111111111111",
		Region:         "us",
	}
	app, stdout, stderr := stubApp(data)
	code := app.Run(context.Background(), []string{"analyze", "--file", "mock.json", "--fail-on", "INFO"})
	if code != 1 {
		t.Fatalf("expected exit 1 for --fail-on INFO without --show-info, got %d. stdout: %s stderr: %s",
			code, stdout.String(), stderr.String())
	}
}

func TestCLI_ParsePortFlag(t *testing.T) {
	app, _, stderr := stubApp(sampleData())
	for _, bad := range []string{"0", "65536", "80.5", "abc", "NaN", "Inf"} {
		code := app.Run(context.Background(), []string{
			"explain-request", "--file", "mock.json", "--path", "/api",
			"--source-ip", "10.0.0.1", "--source-port", bad,
		})
		if code != 1 {
			t.Errorf("port %q: expected exit 1, got %d (stderr: %s)", bad, code, stderr.String())
		}
	}
	app2, stdout, stderr2 := stubApp(sampleData())
	code := app2.Run(context.Background(), []string{
		"explain-request", "--file", "mock.json", "--path", "/api/v1/userstest",
		"--source-ip", "10.0.0.1", "--source-port", "8080",
	})
	if code != 0 {
		t.Fatalf("valid port should succeed, got %d: %s", code, stderr2.String())
	}
	if !strings.Contains(stdout.String(), "Winning route") {
		t.Errorf("expected winner output:\n%s", stdout.String())
	}
}
