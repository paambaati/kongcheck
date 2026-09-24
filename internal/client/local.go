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
// straight into `analyze --file -`.
func LoadLocalConfig(filePath string) (*model.KonnectData, error) {
	var (
		b   []byte
		err error
	)
	if filePath == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(filePath)
	}
	if err != nil {
		return nil, err
	}
	return ParseLocalConfig(b)
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
