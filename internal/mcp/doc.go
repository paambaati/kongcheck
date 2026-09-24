// Package mcp exposes route analysis and request simulation as Model Context
// Protocol tools so AI agents can call them directly.
//
// Transport is stdio: the MCP host spawns `kongcheck mcp` and speaks JSON-RPC
// over stdin/stdout.
//
// Authentication: KONNECT_TOKEN is read from the environment (set once in the
// MCP host config; it never travels over the MCP wire). controlPlaneId and
// region are optional per-call parameters falling back to
// KONNECT_CONTROL_PLANE_ID and KONNECT_REGION (default "us"), so an agent can
// query several control planes in one session.
package mcp
