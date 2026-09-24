// Package version holds build metadata.
package version

import (
	"fmt"
	"runtime"
)

// Name is the program name.
const Name = "kongcheck"

// Version is the release version. Release builds override it with
// -ldflags "-X github.com/paambaati/kongcheck/internal/version.Version=...";
// the default is kept in sync by release-please.
var Version = "1.3.0" // x-release-please-version

// String returns the `--version` line, e.g. "kongcheck/1.3.0 darwin-arm64 go1.27.1".
func String() string {
	return fmt.Sprintf("%s/%s %s-%s %s", Name, Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
