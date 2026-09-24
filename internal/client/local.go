package client

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/paambaati/kongcheck/internal/model"
)

// LocalConfigDump is the file format written by `dump-config`.
type LocalConfigDump struct {
	RouterFlavor model.RouterFlavor   `json:"routerFlavor,omitempty"`
	Routes       []*model.KongRoute   `json:"routes"`
	Services     []*model.KongService `json:"services"`
}

// NewLocalConfigDump builds the dump representation of fetched data.
func NewLocalConfigDump(data *model.KonnectData) LocalConfigDump {
	routes := data.Routes
	if routes == nil {
		routes = []*model.KongRoute{}
	}
	return LocalConfigDump{RouterFlavor: data.RouterFlavor, Routes: routes, Services: data.Services.All()}
}

// LoadLocalConfig loads a config dump from a JSON file for offline analysis.
// The path "-" reads from standard input, so `dump-config -` can be piped
// straight into `analyze --file -`. Both stdin and file reads are bounded by
// maxResponseBytes, and — like the HTTP fetch path — read one byte past the
// limit so an oversized input produces a clear "exceeded limit" error instead
// of a silent truncation that then fails (or worse, "succeeds") with a
// confusing JSON-decode error over an incomplete document.
func LoadLocalConfig(filePath string) (*model.KonnectData, error) {
	var (
		b   []byte
		err error
	)
	if filePath == "-" {
		b, err = readLimited(os.Stdin)
	} else {
		var f *os.File
		if f, err = os.Open(filePath); err == nil {
			defer func() { _ = f.Close() }()
			b, err = readLimited(f)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("reading local config %q: %w", filePath, err)
	}
	return ParseLocalConfig(b)
}

// readLimited reads at most maxResponseBytes from r, returning a descriptive
// error (rather than silently truncated data) when that limit is exceeded.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxResponseBytes {
		return nil, fmt.Errorf("exceeded %d bytes limit", maxResponseBytes)
	}
	return b, nil
}

// ParseLocalConfig decodes a config dump.
func ParseLocalConfig(b []byte) (*model.KonnectData, error) {
	var dump LocalConfigDump
	if err := json.Unmarshal(b, &dump); err != nil {
		return nil, fmt.Errorf("invalid config dump: %w", err)
	}
	routes := make([]*model.KongRoute, 0, len(dump.Routes))
	for _, r := range dump.Routes {
		if r != nil {
			routes = append(routes, r)
		}
	}
	return &model.KonnectData{
		Routes:       routes,
		Services:     model.NewServiceIndex(dump.Services...),
		RouterFlavor: model.ParseFlavor(string(dump.RouterFlavor)),
	}, nil
}
