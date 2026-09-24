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
