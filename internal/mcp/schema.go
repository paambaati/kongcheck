package mcp

import (
	"encoding/json"
	"maps"
	"strings"

	"github.com/paambaati/kongcheck/internal/client"
)

// Tool input schemas (JSON Schema draft-07), mirroring the published
// kongcheck MCP tool contract.

type schemaProps map[string]any

func objectSchema(required []string, props ...schemaProps) json.RawMessage {
	all := schemaProps{}
	for _, p := range props {
		maps.Copy(all, p)
	}
	s := map[string]any{
		"$schema":    "http://json-schema.org/draft-07/schema#",
		"type":       "object",
		"properties": all,
	}
	if required == nil {
		required = []string{}
	}
	s["required"] = required
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return b
}

var targetProps = schemaProps{
	"controlPlaneId": map[string]any{
		"type":   "string",
		"format": "uuid",
		"description": "UUID of the Konnect control plane to inspect. " +
			"Falls back to the KONNECT_CONTROL_PLANE_ID environment variable.",
	},
	"region": map[string]any{
		"type":        "string",
		"enum":        client.RegionCodes,
		"description": `Konnect region. Defaults to KONNECT_REGION environment variable or "us".`,
	},
}

var flavorProps = schemaProps{
	"flavor": map[string]any{
		"type":        "string",
		"enum":        []string{"traditional", "traditional_compatible", "expressions"},
		"description": "Override router flavor. Auto-detected from Konnect when omitted.",
	},
}

var filterProps = schemaProps{
	"filter": map[string]any{
		"type": "array",
		"items": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"key": map[string]any{
					"type":        "string",
					"enum":        []string{"path", "name", "service", "tag", "id"},
					"description": "Attribute to filter on.",
				},
				"value": map[string]any{
					"type":        "string",
					"description": "Substring to match against (case-insensitive).",
				},
			},
			"required": []string{"key", "value"},
		},
		"description": "Filter findings to routes matching all given key/value pairs (ANDed). " +
			"Supported keys: " + strings.Join([]string{"path", "name", "service", "tag", "id"}, ", ") + ".",
	},
}

func portProp(description string) map[string]any {
	return map[string]any{"type": "integer", "minimum": 1, "maximum": 65535, "description": description}
}

var (
	analyzeSchema = objectSchema(nil, targetProps, flavorProps, filterProps, schemaProps{
		"includeInfo": map[string]any{
			"type":    "boolean",
			"default": false,
			"description": "Include INFO-level findings. INFO covers: universal catch-all routes that " +
				"match every request, and route pairs that are structurally stratified " +
				"(mutually exclusive by SNI, source/destination IP, or protocol family) " +
				"so a collision is impossible. Default: false.",
		},
	})

	collisionsSchema = objectSchema(nil, targetProps, flavorProps, filterProps)

	explainSchema = objectSchema([]string{"path"}, targetProps, flavorProps, schemaProps{
		"method": map[string]any{"type": "string", "default": "GET", "description": `HTTP method, e.g. "GET".`},
		"host": map[string]any{
			"type": "string",
			"description": `Host header value, e.g. "api.example.com". ` +
				`Defaults to "example.com" when omitted (sufficient for path-only matching).`,
		},
		"path": map[string]any{
			"type":        "string",
			"description": `Request path, e.g. "/api/v1/users". Query strings and fragments are stripped automatically.`,
		},
		"headers": map[string]any{
			"type":                 "object",
			"additionalProperties": map[string]any{"type": "string"},
			"description": `Optional request headers as a key/value object, e.g. {"x-env": "prod"}. ` +
				"When provided, routes with header constraints are evaluated strictly. " +
				"When omitted, header constraints are skipped (every route is a candidate).",
		},
		"sni": map[string]any{
			"type": "string",
			"description": `TLS SNI value for stream route simulation, e.g. "api.example.com". ` +
				"When provided, routes with snis constraints are evaluated strictly.",
		},
		"sourceIp": map[string]any{
			"type": "string",
			"description": `Source IP address of the connection, e.g. "10.0.1.5". IPv4 and IPv6 are ` +
				"accepted; CIDR matching applies to the route constraints. When provided, " +
				"sources constraints on routes are evaluated strictly.",
		},
		"sourcePort": portProp("Source TCP/UDP port of the connection, e.g. 54321. Evaluated only when sourceIp is also provided."),
		"destIp": map[string]any{
			"type": "string",
			"description": `Destination IP address of the connection, e.g. "192.168.1.10". When provided, ` +
				"destinations constraints on routes are evaluated strictly.",
		},
		"destPort": portProp("Destination TCP/UDP port, e.g. 443. Evaluated only when destIp is also provided."),
	})

	routeConfigSchema = objectSchema(nil, targetProps)
)
