// White-box regression tests for LoadLocalConfig's size bounding.
//
// The HTTP fetch path (get, in client.go) reads up to maxResponseBytes+1
// bytes and returns a clear "exceeded limit" error when the extra byte is
// present, rather than silently handing truncated data to the JSON decoder.
// LoadLocalConfig's "-" (stdin) and file-path branches must behave the same
// way instead of (a) silently truncating stdin with no overflow check, or
// (b) not bounding file reads at all.
package client

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// oversizedPayload returns a byte slice one byte larger than the configured
// limit, wrapped in enough JSON structure that — were it not rejected for
// size first — it would otherwise fail to parse anyway, so a passing test
// can only mean the size check fired.
func oversizedPayload() []byte {
	return bytes.Repeat([]byte("a"), maxResponseBytes+1)
}

func TestReadLimited_ExceedsLimitReturnsClearError(t *testing.T) {
	_, err := readLimited(bytes.NewReader(oversizedPayload()))
	if err == nil {
		t.Fatal("expected an error for input exceeding maxResponseBytes, got nil")
	}
	if got := err.Error(); got == "" || !bytes.Contains([]byte(got), []byte("exceeded")) {
		t.Fatalf("expected a clear 'exceeded ... limit' error, got: %v", err)
	}
}

func TestReadLimited_AtExactLimitSucceeds(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), maxResponseBytes)
	b, err := readLimited(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("expected exactly maxResponseBytes to be accepted, got error: %v", err)
	}
	if len(b) != maxResponseBytes {
		t.Fatalf("expected %d bytes, got %d", maxResponseBytes, len(b))
	}
}

func TestLoadLocalConfig_StdinExceedsLimitReturnsClearError(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	payload := oversizedPayload()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.Write(payload)
		_ = w.Close()
	}()

	_, loadErr := LoadLocalConfig("-")
	<-done
	_ = r.Close()

	if loadErr == nil {
		t.Fatal("expected LoadLocalConfig(\"-\") to fail on oversized stdin, got nil")
	}
	if got := loadErr.Error(); !bytes.Contains([]byte(got), []byte("exceeded")) {
		t.Fatalf("expected a clear 'exceeded ... limit' error (not a JSON decode error "+
			"over silently-truncated data), got: %v", loadErr)
	}
}

func TestLoadLocalConfig_FilePathExceedsLimitReturnsClearError(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "oversized.json")
	if err := os.WriteFile(p, oversizedPayload(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadLocalConfig(p)
	if err == nil {
		t.Fatal("expected LoadLocalConfig to reject a file exceeding maxResponseBytes, got nil")
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("exceeded")) {
		t.Fatalf("expected a clear 'exceeded ... limit' error, got: %v", err)
	}
}

func TestLoadLocalConfig_StdinWithinLimitSucceeds(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	const content = `{"routerFlavor":"traditional","routes":[{"id":"r1","paths":["/api"]}],"services":[]}`
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.Write([]byte(content))
		_ = w.Close()
	}()

	data, err := LoadLocalConfig("-")
	<-done
	_ = r.Close()

	if err != nil {
		t.Fatalf("unexpected error reading a well-within-limit stdin payload: %v", err)
	}
	if len(data.Routes) != 1 || data.Routes[0].ID != "r1" {
		t.Fatalf("expected route r1 decoded from stdin, got %+v", data.Routes)
	}
}
