# `kongcheck`

<img src="docs/images/kongcheck.svg" height="100" width="100"/>

An LLM-friendly CLI tool for auditing [Kong Konnect](https://konghq.com/products/kong-konnect) routing configuration.

> **Konnect only.** `kongcheck` connects to the [Konnect Control Planes Config v2 API](https://developer.konghq.com/api/konnect/control-planes-config/v2/) and is designed specifically for Konnect-managed control planes. Self-managed / on-premise Kong Gateway instances using the Kong Admin API are not supported.

- **Route collisions and shadowing** – requests that match more than one route, where the winner may surprise you.
- **Suspicious regex paths** – paths that use `*` as a glob wildcard but are actually PCRE patterns (a very common mistake).
- **Universal catch-all routes** – routes that match every request URL (informational; shown with `--show-info`).

Results are explained in plain language, with sample requests that reproduce each finding, and suggested fixes where applicable.

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Commands](#commands)
  - [`analyze`](#analyze)
  - [`collisions`](#collisions)
  - [`explain-request`](#explain-request)
  - [`dump-config`](#dump-config)
  - [`mcp`](#mcp)
- [Global options](#global-options)
- [Filtering with `--filter`](#filtering-with---filter)
- [Output formats](#output-formats)
- [CI integration with `--fail-on`](#ci-integration-with---fail-on)
- [Offline mode with `--file`](#offline-mode-with---file)
- [Severity levels](#severity-levels)
- [Finding types](#finding-types)
- [Router flavors](#router-flavors)
- [Building a standalone binary](#building-a-standalone-binary)
- [MCP server](#mcp-server)
- [Unsupported features and known gaps](#unsupported-features-and-known-gaps)
- [FAQs](#faqs)

---

## Installation

**Prerequisites** – [Bun](https://bun.sh) v1.3 or later.

```bash
git clone <repo-url> kongcheck
cd kongcheck
bun install
```

To run directly without building –

```bash
bun run start <command> [options]
```

To build a self-contained binary –

```bash
bun run build
# produces ./kongcheck
```

---

## Quick start

Set your credentials as environment variables so you don't have to repeat them on every command –

```bash
export KONNECT_TOKEN="kpat_..."
export KONNECT_CONTROL_PLANE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export KONNECT_REGION="us"   # optional, defaults to "us"
```

Run a full audit –

```bash
kongcheck analyze
```

You'll see a detailed report with every finding, grouped by severity.

If you'd like to change the control plane ID for a single invocation, most commands support the `--control-plane-id` flag –

```bash
kongcheck analyze --control-plane-id 2eb539a8-a0ba-4c6a-9e06-682fbfcd8e70
```

---

## How it works

Kong's router uses deterministic priority rules to select a winning route for each request. `kongcheck` ports those rules from Kong's source ([`traditional.lua`](https://github.com/Kong/kong/blob/2ffd3b1/kong/router/traditional.lua)) into TypeScript and replays them against your live configuration.

The analysis runs four passes –

1. **Suspicious regex linting** – each regex path (`~`-prefixed) is checked for glob-style `*` usage, which has different semantics in PCRE.
2. **Collision simulation** – candidate request paths are derived from your routes' own patterns and each is simulated to find routes that overlap.
3. **Sibling namespace detection** – route pairs whose path prefixes share a common stem (e.g. `/epp` and `/epp-poc`) are flagged as potential shadows even when simulation didn't generate a specific colliding request.
4. **Universal-matcher annotation** – catch-all routes (e.g. a SPA served from `/`) are identified and optionally surfaced as `INFO` findings.

> **Note on router flavor** – `kongcheck` auto-detects your control plane's router flavor (`traditional`, `traditional_compatible`, or `expressions`) from the Konnect API. You can override it with `--flavor` if needed. The analysis is meaningless for `expressions` flavor, which uses a completely different routing syntax.

---

## Commands

### `analyze`

**Full audit** – runs all four analysis passes and reports everything – suspicious regex patterns, route collisions, shadowing, and (optionally) catch-all routes.

**When to use** – your first stop. Run this to get a complete picture of your control plane's routing health.

```bash
kongcheck analyze
```

```bash
# Scope the audit to a single team's routes
kongcheck analyze --filter tag:team-payments

# Show only findings for routes under /api/v2
kongcheck analyze --filter path:/api/v2

# Include INFO-level findings (catch-all routes)
kongcheck analyze --show-info

# Machine-readable output for piping/scripting
kongcheck analyze --format json | jq '.findings[] | select(.severity == "HIGH")'

# Exit non-zero if any HIGH findings are present (for CI)
kongcheck analyze --fail-on HIGH
```

---

### `collisions`

**Collision/shadowing only** – identical to `analyze` but filters out suspicious-regex findings. Only shows routes that are actively shadowing or colliding with each other.

**When to use** – when you already know you have regex issues and want to focus on routing correctness – or when you're investigating a specific request that seems to be hitting the wrong route.

```bash
kongcheck collisions
```

```bash
# Check collision findings for a specific service
kongcheck collisions --filter service:checkout-api

# Narrow to a specific path namespace
kongcheck collisions --filter path:/payments

# JSON output for automated triage
kongcheck collisions --format json
```

---

### `explain-request`

**Request simulation** – simulates a specific HTTP request against your live route configuration and tells you exactly which route wins and why.

**When to use** – when a request in production is hitting the wrong backend and you want to understand why. Ideal for debugging "why is `/api/v1/users` going to the wrong service?" type questions.

```bash
kongcheck explain-request --path /api/v1/users
```

```bash
# Simulate a specific method + host + path combination
kongcheck explain-request \
  --method POST \
  --host api.example.com \
  --path /payments/checkout

# JSON output (includes full match details and explanation)
kongcheck explain-request --path /api/v1/users --format json
```

The output shows –

- The **winning route** name and ID
- A step-by-step **explanation** of why it won (regex_priority, path specificity, creation date tie-breaking)
- All **other routes that also matched**, in priority order

---

### `dump-config`

**Save config locally** – fetches your control plane's routes and services and writes them as JSON. By default (no output file given, or `-` passed explicitly) the JSON is written to **stdout**, making it easy to pipe to other tools or commands. A human-readable summary is always printed to **stderr**.

**When to use** –

- You want to analyse the same snapshot multiple times without hitting the API
- You're sharing a problematic config with a colleague for debugging
- You're running `kongcheck` in a CI environment without direct Konnect access at analysis time
- You want to pipe the output directly into another command or process

```bash
# Write to stdout (pipe-friendly) – summary goes to stderr
kongcheck dump-config

# Explicitly request stdout with "-"
kongcheck dump-config -

# Pipe directly into jq
kongcheck dump-config | jq '.routes | length'

# Save to a named file
kongcheck dump-config my-cp-snapshot.json
# writes my-cp-snapshot.json, prints summary to stdout
```

The JSON can be passed to any analysis command with `--file` –

```bash
kongcheck analyze --file my-cp-snapshot.json
kongcheck collisions --file my-cp-snapshot.json
kongcheck explain-request --file my-cp-snapshot.json --path /api/v1/users
```

---

### `mcp`

**Start a local MCP server** – starts an MCP server on the `stdio` transport.

**When to use** –

- You want to use the `kongcheck` tool through an AI or LLM of your choice

```bash
# Start MCP server with default Kong Konnect data cache with a TTL of 60 seconds.
kongcheck mcp

# Start MCP server, and disable cache, letting every tool call fetch fresh data from Kong Konnect.
kongcheck mcp --cache-ttl 0
```

You can also inspect the MCP server's tool calls locally –

```bash
bunx @modelcontextprotocol/inspector -e KONNECT_TOKEN=$KONNECT_TOKEN kongcheck mcp
```

See [MCP server](#mcp-server) for more ways to access the server through the AI/LLM of your choice.

---

## Global options

All commands accept these options. Authentication options can also be set as environment variables.

| Option                    | Env var                    | Default       | Description                                                                                  |
| ------------------------- | -------------------------- | ------------- | -------------------------------------------------------------------------------------------- |
| `--token <token>`         | `KONNECT_TOKEN`            | —             | Konnect personal access token or system account token                                        |
| `--control-plane-id <id>` | `KONNECT_CONTROL_PLANE_ID` | —             | UUID of the control plane to inspect                                                         |
| `--region <region>`       | `KONNECT_REGION`           | `us`          | Konnect region – `us`, `eu`, `au`, `me`, `in`, `sg`                                          |
| `--format <fmt>`          | —                          | `human`       | Output format – `human` (colour terminal), `json`, `csv`                                     |
| `--fail-on <severity>`    | —                          | —             | Exit non-zero when any finding is at or above this severity: `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--flavor <flavor>`       | —                          | auto-detected | Override router flavor – `traditional`, `traditional_compatible`, `expressions`              |
| `--file <path>`           | —                          | —             | Load config from a local JSON dump instead of the Konnect API                                |
| `--verbose`               | —                          | —             | Print progress information to stderr                                                         |
| `--show-info`             | —                          | —             | Include `INFO`-level findings in output (catch-all routes)                                   |
| `--filter <predicate>`    | —                          | —             | Filter findings (see [Filtering](#filtering-with---filter)); repeatable                      |

---

## Filtering with `--filter`

`--filter` lets any command operate on a **subset** of findings. It is especially useful in large control planes shared across many teams.

### Format

```
--filter key:value
```

Supported keys –

| Key       | Match semantics                                                                                           |
| --------- | --------------------------------------------------------------------------------------------------------- |
| `path`    | Route has at least one path whose stem (leading `~` stripped) starts with the given value                 |
| `name`    | Route name contains the value (case-insensitive substring)                                                |
| `service` | Route's service UUID matches exactly, **or** service name contains the value (case-insensitive substring) |
| `tag`     | Route has a tag with exactly this value                                                                   |
| `id`      | Route UUID matches exactly                                                                                |

### AND / OR logic

- **Different keys** are combined with **AND** – the route must satisfy every key group.
- **Same key repeated** is combined with **OR** – the route must match at least one value for that key.
- A finding is included when **any** of its involved routes satisfies the full predicate set.

```bash
# Only findings involving routes tagged "team-a"
kongcheck analyze --filter tag:team-a

# Only findings involving routes tagged "team-a" OR "team-b"
kongcheck analyze --filter tag:team-a --filter tag:team-b

# Only findings involving routes tagged "team-a" AND under /api
kongcheck analyze --filter tag:team-a --filter path:/api

# Only findings for a specific service (by name substring)
kongcheck analyze --filter service:checkout

# Only findings for a specific route by UUID
kongcheck analyze --filter id:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## Output formats

### Human (default)

Colour-coded terminal output with a finding-per-block layout –

```
Kong Route Audit – 3 finding(s)  router_flavor: traditional

────────────────────────────────────────────────────────────
[HIGH]  suspicious_regex  (traditional)

  winner    my-route  id: abc-123
            paths: ~/epp/*  regex_priority: 0  created: 2024-01-15T10:00:00.000Z (16 months ago)

  Why:
    – Path "~/epp/*" uses regex syntax in a way that is likely unintentional:
    – `*` after `/` is a PCRE quantifier meaning "zero or more slashes", not a glob wildcard.

  Suggested fixes:
    → ~/epp/.*
```

### JSON (`--format json`)

A structured JSON object suitable for piping, CI ingestion, or custom dashboards –

```jsonc
{
  "generatedAt": "2026-05-07T10:00:00.000Z",
  "routerFlavor": "traditional",
  "totalFindings": 3,
  "summary": { "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 0 },
  "findings": [
    {
      "severity": "HIGH",
      "type": "suspicious_regex",
      "routerFlavor": "traditional",
      "routes": [ { "id": "abc-123", "name": "my-route", "paths": ["~/epp/*"], ... } ],
      "samples": [],
      "reason": [ "Path \"~/epp/*\" uses regex syntax ..." ],
      "suggestions": ["~/epp/.*"]
    }
  ]
}
```

---

## CI integration with `--fail-on`

Use `--fail-on` to make `kongcheck` exit with code `1` when findings at or above a threshold are found. This integrates cleanly with CI pipelines.

```bash
# Fail the pipeline on any HIGH or MEDIUM finding
kongcheck analyze --fail-on MEDIUM

# Fail only on HIGH findings; treat everything else as informational
kongcheck analyze --fail-on HIGH

# Scope to your team's routes only
kongcheck analyze --filter tag:team-payments --fail-on MEDIUM
```

Combined with `--format json`, findings can be parsed and posted as PR annotations or fed into alerting systems.

---

## Offline mode with `--file`

When you don't have network access to Konnect, or want to analyse a specific point-in-time snapshot, use `dump-config` to save first, then pass the file to analysis commands.

> **Self-managed Kong?** `kongcheck` does not connect to the Kong Admin API. If you run self-hosted Kong Gateway, you can produce a compatible dump manually by exporting your routes and services via the Admin API and shaping the JSON to match the `dump-config` output format, then passing it with `--file`. The required shape is `{ routerFlavor?, routes: KongRoute[], services: KongService[] }` — see the TypeScript types in `src/types.ts`.

```bash
# Pipe directly into analysis without a temp file
kongcheck dump-config | kongcheck analyze --file /dev/stdin

# Save today's config
kongcheck dump-config snapshots/$(date +%F).json

# Analyse the snapshot
kongcheck analyze --file snapshots/2026-05-07.json

# Compare snapshots over time by running analyze on each
kongcheck analyze --file snapshots/2026-05-01.json --format json > before.json
kongcheck analyze --file snapshots/2026-05-07.json --format json > after.json
```

---

## Severity levels

| Severity | Meaning                                                                                                                                                                         |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HIGH`   | A route is an accidental universal catch-all (matches every request), or a proven shadowing scenario with a clear winner. Likely causing silent traffic misdirection right now. |
| `MEDIUM` | A suspicious regex path or a collision that may or may not be intentional. Worth reviewing.                                                                                     |
| `LOW`    | Sibling namespace overlap where the routes could shadow each other under some request patterns. Lower confidence.                                                               |
| `INFO`   | Informational only. Universal catch-all routes that are intentional (e.g. a SPA fallback). Shown only with `--show-info`.                                                       |

---

## Finding types

| Type                | Description                                                                                                                                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `suspicious_regex`  | A regex path (`~`-prefixed) uses `*` as if it were a glob wildcard. In PCRE, `*` is a quantifier on the preceding token, not "anything". E.g. `~/epp/*` means "/epp" followed by zero or more `/`, not "anything under /epp/". Use `~/epp/.*` instead. |
| `shadowing`         | Route A wins every request that route B can match, so route B can never be reached. Kong's priority rules (regex_priority → path length → created_at) determine the winner deterministically.                                                          |
| `collision`         | Two or more routes match the same request. The winner is determined by Kong's sort order, but the situation is fragile – a small change (e.g. adding a header constraint) could silently shift traffic.                                                |
| `universal_matcher` | A route that matches every request URL. Common examples – a catch-all served from plain prefix `/`, or a default upstream. Shown only with `--show-info`.                                                                                              |

---

## Router flavors

Kong supports three router flavors. `kongcheck` auto-detects the flavor from your control plane configuration.

| Flavor                   | Path behavior                                                                                                                                                   |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `traditional`            | Regex paths (`~` prefix) are PCRE patterns **without** an implicit `^` start anchor. A pattern like `~/api` matches the string `/api` anywhere in the URL path. |
| `traditional_compatible` | Same as `traditional` but a `^` start anchor **is** added to all regex paths, anchoring them to the start of the URL.                                           |
| `expressions`            | Uses a completely different routing expression language. `kongcheck` will load the config but analysis results are not meaningful for this flavor.              |

> **Common trap** – in `traditional` flavor, a regex like `~/?$` does **not** mean "match the root path". Because there is no `^` anchor, `/?$` matches the end of any string, making the route an accidental universal catch-all. `kongcheck` detects and flags this as a `suspicious_regex` / `MEDIUM` finding.

---

## MCP server

`kongcheck` includes an [MCP](https://modelcontextprotocol.io) (Model Context Protocol) server so AI agents — Claude Desktop, Cursor, VS Code Copilot, and others — can call its tools directly without copy-pasting terminal output.

### Transport

The server uses the **stdio** transport – the MCP host spawns `kongcheck mcp` as a child process and speaks to it over stdin/stdout.

### Authentication design

| What              | How                                                                                                                                                                            |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Token**         | Set `KONNECT_TOKEN` in the MCP host config once. It never travels over the MCP wire.                                                                                           |
| **Control plane** | Passed as an optional `controlPlaneId` parameter on each tool call. Falls back to `KONNECT_CONTROL_PLANE_ID` env var when omitted — useful when most calls target the same CP. |
| **Region**        | Optional per-call `region` parameter. Falls back to `KONNECT_REGION` env var or `"us"`.                                                                                        |

This lets a single running server query multiple control planes in one session (e.g. compare integration vs prod) without restarting.

### Tools

| Tool               | Equivalent CLI command      | Description                                                               |
| ------------------ | --------------------------- | ------------------------------------------------------------------------- |
| `analyze_routes`   | `kongcheck analyze`         | Full four-pass audit: suspicious regex, collisions, shadowing, catch-alls |
| `get_collisions`   | `kongcheck collisions`      | Shadowing and collision findings only                                     |
| `explain_request`  | `kongcheck explain-request` | Simulate a request, return winning route + explanation                    |
| `get_route_config` | `kongcheck dump-config`     | Raw routes and services JSON for the agent to inspect                     |

### Configuration

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` –

```json
{
	"mcpServers": {
		"kongcheck": {
			"command": "/path/to/kongcheck",
			"args": ["mcp"],
			"env": {
				"KONNECT_TOKEN": "kpat_...",
				"KONNECT_CONTROL_PLANE_ID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				"KONNECT_REGION": "us"
			}
		}
	}
}
```

**Cursor** — `.cursor/mcp.json` in your project root (same shape as above).

**VS Code Copilot** — `.vscode/mcp.json` –

```json
{
	"servers": {
		"kongcheck": {
			"type": "stdio",
			"command": "/path/to/kongcheck",
			"args": ["mcp"],
			"env": {
				"KONNECT_TOKEN": "${env:KONNECT_TOKEN}"
			}
		}
	}
}
```

---

## Unsupported features and known gaps

`kongcheck` is a faithful port of Kong's `traditional` router core, but several matching dimensions are not (yet) simulated. In each case below the tool **will not catch the described scenario** — it is documented here so you know where to apply manual review.

---

### `PLAIN_HOSTS_ONLY` and wildcard-host sort ordering

Kong uses a three-bit `submatch_weight` field to rank routes. In addition to "has regex path", it records whether all hosts are plain (no wildcards) and whether a wildcard host includes an explicit port. Routes with only plain hosts outrank routes with wildcard hosts at the same path specificity.

`kongcheck` only models the **regex-vs-plain path** bit. Host type does not affect the sort order in the tool.

**Not caught by this tool**

```
# Route A – plain host, plain path
route-a: host=api.example.com  path=/v1/users

# Route B – wildcard host, plain path  (should lose to A in Kong)
route-b: host=*.example.com    path=/v1/users
```

Kong will always send `GET api.example.com /v1/users` to `route-a`. `kongcheck` may report these as a `collision` without identifying `route-a` as the definitive winner.

---

### Wildcard host port handling

When a wildcard host includes an explicit port (`*.example.com:8080`), Kong builds a regex that pins the port. When the port is absent, Kong appends `(?::\d+)?` to also match requests that include a port in their `Host` header.

`kongcheck` performs a plain string suffix check (`host.endsWith(".example.com")`) and does not handle ports in the request `Host` header.

**Not caught by this tool**

```
# Route constrained to *.example.com (no port)
# Kong matches both –
#   Host: api.example.com
#   Host: api.example.com:8443

# kongcheck matches only:
#   Host: api.example.com         ✓
#   Host: api.example.com:8443    ✗  (suffix check fails)
```

If your Kong routes are behind a proxy that passes an explicit port in the `Host` header, `explain-request` may report no winner when Kong would successfully route the request.

---

### Header-constrained routes with identical paths

When the winner has a header constraint and the loser does not, and both routes share **identical paths**, the static analyzer now classifies this as **INFO** rather than HIGH/MEDIUM/LOW. The finding includes ready-to-run `kongcheck explain-request` commands so you can confirm that Kong routes each request to the intended service:

```
[INFO] Routes "platform-auth-dev-userinfo" and "platform-auth-internal-userinfo"
       share identical path(s) and are correctly stratified by header.

       Path(s): /userinfo
       "platform-auth-dev-userinfo" requires: x-smp-env: [dev, develop, development]
       "platform-auth-internal-userinfo" has no matching constraint

→ kongcheck explain-request GET /userinfo --header x-smp-env:dev
    → should route to "platform-auth-dev-userinfo"
→ kongcheck explain-request GET /userinfo
    → should route to "platform-auth-internal-userinfo" (no header required)
```

---

### Regex header values (`~*` prefix)

A header constraint value can start with `~*` to indicate a PCRE regex match. `kongcheck` supports this in `explain-request` (via `--header`) and in exact matching. However, the **static analyzer** cannot determine at analysis time whether a `~*` pattern is disjoint from another route's literal values — it only compares plain string values when deciding whether to suppress a finding.

**Not caught by this tool**

```
# Route A and Route B share the same path ~/users/([^/]+)
# Route A: headers: { x-version: ["~*^v[0-9]+$"] }   ← only matches versioned clients
# Route B: no header constraint

# The analyzer cannot verify that the regex values are disjoint from Route B's
# unconstrained header handling. It emits an INFO finding with explain-request
# commands; use them to confirm which route wins for your specific header value.
```

Use `explain-request --header x-version:v3` to confirm which route wins.

---

### Non-identical paths with header constraint on the winner

When the winner has a **broader regex path** than the loser (non-identical paths) AND the winner has a header constraint, the analyzer still flags this as **HIGH**. The path over-match is a genuine risk independent of the header: any request to the loser's specific path that also carries the winner's required header will misroute to the winner's service.

**Example — still flagged as HIGH**

```
# Route A: path=~/users/([^/]+)  headers={x-smp-env:[dev,...]}  → auth-dev service
# Route B: path=/marketing/userprofile/users/resend-activation-email  (no headers)

# In a dev environment where every request carries x-smp-env:dev, Route A
# intercepts all traffic to Route B's path. The header does not fix the
# path over-match. This is a real misrouting risk.
```

---

### URI normalization and query-string stripping

Before matching, Kong strips the query string from the request URI and normalizes percent-encoding and `.`/`..` path segments. `kongcheck` takes the path exactly as you supply it.

**Not caught by this tool**

```bash
# These two simulate differently even though Kong treats them as the same path –
kongcheck explain-request --path /api/v1
kongcheck explain-request --path /api/v1?debug=1   # ← '?' and beyond included in prefix check
```

Always pass a clean path (no query string) to `explain-request`.

---

### PCRE backtracking limit (`(*LIMIT_MATCH=10000)`)

Kong prepends `(*LIMIT_MATCH=10000)` to every compiled regex path. This caps PCRE backtracking at 10 000 steps and prevents catastrophic backtracking from hanging the gateway. JavaScript's `RegExp` engine has no equivalent control.

**Not caught by this tool**

```
# A pathological regex such as ~/api/(a+)+$ can trigger catastrophic backtracking.
# Kong would abort the match at 10 000 steps and move to the next route.
# kongcheck will run the regex to completion, potentially hanging on that route.
```

In practice this only affects intentionally or accidentally malformed regex paths. The `suspicious_regex` finding flags patterns that use `*` as a glob (a common source of degenerate patterns), which partially mitigates this.

---

### SNI, source IP, and destination IP/port constraints

Kong supports matching on TLS SNI values, client source IP/CIDR and port, and destination IP/CIDR and port. These are L4 (stream) routing fields.

`kongcheck` does not evaluate any of these constraints. **All three are completely ignored.**

**Not caught by this tool**

```
# Route A: snis=["api.example.com"]       (TLS SNI match)
# Route B: sources=[{ ip: "10.0.0.0/8" }] (client IP range)
# Route C: destinations=[{ port: 5432 }]  (destination port)

# kongcheck treats A, B, and C as if they have no constraints.
# Collision and shadowing analysis between stream routes and HTTP routes
# will produce false positives.
```

If your control plane contains stream (TCP/TLS) routes alongside HTTP routes, filter them out with `--filter tag:<stream-tag>` or review them manually.

---

## FAQs

<details>
<summary><strong>A finding shows two routes colliding, but the sample request clearly goes to the right route. Is this a false positive?</strong></summary>

Not necessarily. The sample request demonstrates that both routes _match_, not that traffic is misrouted _today_.

For example, given –

```
winner  ~/persona-index-survey-be-service/*
loser   ~/persona-index-survey-be/*
```

The sample `/persona-index-survey-be-service/` does go to the correct (longer) route — Kong's path-length tie-breaker picks it. But the finding is flagging a structural fragility –

1. **The shorter route over-matches.** `~/persona-index-survey-be/*` is unanchored PCRE, so it matches any URL containing `/persona-index-survey-be` as a substring, including `/persona-index-survey-be-service/`, `/persona-index-survey-be-v2/`, `/some/internal/persona-index-survey-be/resource`, etc.
2. **The overlap is latent, not active.** Right now the longer route always wins on path length. But if the longer route is ever deleted, all its traffic silently falls to the shorter one without any error.
3. **Any future sibling is stolen.** A new route `~/persona-index-survey-be-mobile/*` added later would immediately have its traffic poached by the unanchored shorter route.

**Here is a request where the shorter route wins right now**

```
Request: GET /persona-index-survey-be/login

~/persona-index-survey-be-service/*   NO MATCH  ← path has no "-service" segment
~/persona-index-survey-be/*            MATCH     ← wins; silently proxied to the wrong service
```

`/persona-index-survey-be/login` does not contain `-service`, so the longer route never matches. The shorter route is the only candidate and wins unconditionally. Any request that belongs to the `persona-index-survey-be` service but does not go through the `-service` namespace is already being misrouted today.

The fix — `~/persona-index-survey-be(?:/.*)?$` — adds an end anchor and a clean path-boundary check, so the route only matches URLs that actually start with `/persona-index-survey-be` at a `/` boundary.

</details>

<details>
<summary><strong>Why does <code>~/persona-index-survey-be/*</code> match <code>/persona-index-survey-be-service/</code>? They look like different paths.</strong></summary>

Because in `traditional` flavor Kong does **not** add a `^` start anchor to regex paths, and `*` is a PCRE quantifier, not a glob wildcard.

Step by step, the regex `/persona-index-survey-be/*` applied to `/persona-index-survey-be-service/` –

```
/persona-index-survey-be/*
         ↑ no ^ anchor — the engine searches for this pattern anywhere in the URL

URL: /persona-index-survey-be-service/
     ^^^^^^^^^^^^^^^^^^^^^^^^            ← the engine finds /persona-index-survey-be at position 0
                             -service/   ← this suffix is left over
                         *              ← * means "zero or more of the preceding char ('/')"
                                        ← matches zero times here, consuming nothing
                                        ← no $ end anchor, so the leftover -service/ is ignored
→ MATCH
```

Compare with the anchored fix `~/persona-index-survey-be(?:/.*)?$` –

```
URL: /persona-index-survey-be-service/
     ^^^^^^^^^^^^^^^^^^^^^^^^            ← matches /persona-index-survey-be
                             -service/   ← (?:/.*)? requires a '/' or nothing — but '-' is next
→ NO MATCH ✓
```

The same trap applies to any pair of routes where one path name is a prefix of another, separated by a non-`/` character (a dash, a digit, a letter). Examples – `/api` vs `/api-v2`, `/service` vs `/service-worker`, `/genai` vs `/genai-eval`.

</details>

<details>
<summary><strong>Two identical-path routes are flagged as shadowing each other. Is one of them permanently unreachable?</strong></summary>

Yes — when two routes have identical path patterns (e.g. both `~/ds-proposals/*` or both `/userinfo`), Kong's sort order is fully deterministic: the route with the earlier `created_at` timestamp always wins. The later-created route is permanently unreachable for any request that matches that path.

The tool reports the creation timestamps for both routes so you can identify which one is dead –

```
winner    ds-proposals-api-route        created: 2024-07-03T10:08:00Z
shadowed  ds-proposals-templates-route  created: 2024-07-03T10:08:03Z  ← dead
```

Common causes –

- A route was recreated (e.g. via a new deployment) while the old one was not deleted first.
- Two different services were accidentally given the same path prefix.
- A route was cloned for a different team/service but the path was not updated.

To fix: delete the dead route, or differentiate the paths (e.g. add a version prefix, or use host constraints to direct traffic to the correct service by `Host` header).

</details>

<details>
<summary><strong>The <code>~/mcp/*</code> route is generating dozens of collision findings. Why is one route causing so many?</strong></summary>

Because `~/mcp/*` is an extremely broad unanchored regex. In `traditional` flavor –

- No `^` anchor → the pattern matches `/mcp` appearing **anywhere** in the URL, not just at the start.
- `*` after `/` → matches zero or more `/` characters at that position.

So `~/mcp/*` matches every URL that contains the substring `/mcp` — including –

```
/genai/v1/test-smp-mcp-template/mcp/    ← /mcp appears near the end
/finance/project/mcp                     ← /mcp at the end
/genai/v0/marketplace/mcp-servers        ← /mcp- mid-segment
/.well-known/oauth-protected-resource    ← does NOT match (no /mcp)
```

Every more-specific route that contains `/mcp` anywhere in its path will win the priority contest (longer pattern), but the broad route is still considered a match — and if any of those specific routes are removed, `~/mcp/*` silently absorbs their traffic.

The fix `~/mcp(?:/.*)?$` anchors the match to the start of the URL (via Kong's effective behavior once the pattern is made specific enough) and requires `/mcp` to be followed by end-of-string or a `/`-delimited continuation –

```
/mcp                    ✓  matches
/mcp/sse                ✓  matches
/genai/v1/.../mcp/      ✗  does not match (not at start)
/finance/project/mcp    ✗  does not match
```

</details>

<details>
<summary><strong>Why does the <code>~/users/([^/]+)</code> route match <code>/marketing/userprofile/unauth/users/resend-user-activation-email</code>?</strong></summary>

Because in `traditional` flavor the regex `/users/([^/]+)` has no `^` start anchor, so the engine searches for the pattern anywhere in the URL string.

Applied to `/marketing/userprofile/unauth/users/resend-user-activation-email` –

```
/marketing/userprofile/unauth/users/resend-user-activation-email
                              ^^^^^^                               ← /users/ found at position 31
                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^    ← ([^/]+) matches one or more non-slash chars
→ MATCH
```

The route `~/users/([^/]+)` was almost certainly intended to match only top-level `/users/<id>` requests. In `traditional_compatible` flavor a `^` anchor would be added automatically, giving `^/users/([^/]+)`, which would **not** match the long marketing path. In `traditional` flavor you must add the anchor explicitly – `~/^users/([^/]+)` or migrate to `traditional_compatible`.

This type of finding is real — Kong genuinely routes `/marketing/userprofile/unauth/users/resend-user-activation-email` to the `~/users/([^/]+)` route when both are present and the regex route wins on `submatch_weight`. Whether it causes a problem in practice depends on whether these routes are constrained to different `Host` headers (which `kongcheck` does not evaluate statically — see [Unsupported features](#unsupported-features-and-known-gaps)).

</details>

<details>
<summary><strong>Shared health-check or OpenAPI paths (<code>/health/ready</code>, <code>/openapi.json</code>) are flagged as HIGH collisions across unrelated services. Are these real?</strong></summary>

Yes — these are genuine collisions. Multiple services each registered their own `/health/ready` or `/openapi.json` route **without** a differentiating `Host` header or path prefix, so every request to `/health/ready` goes to whichever route has the earliest `created_at` timestamp. All the other services' health endpoints are permanently unreachable via Kong.

This is a common pattern when services are onboarded from a template that includes a generic health route, without scoping it to the service's own path namespace.

**Recommended fixes**

1. **Prefix the path** — each service registers `/my-service/health/ready` instead of the bare `/health/ready`. This is the cleanest solution and works without host-based routing.

2. **Use host constraints** — each service's health route is constrained to its own virtual host (`host=my-service.internal`). Kong will then route by `Host` header before comparing paths.

3. **Centralise health checking** — a single health-aggregator route at `/health/ready` proxies to each service's internal health endpoint. Only one Kong route is needed.

Note that for external health probers (load balancers, Kubernetes liveness probes) option 1 usually requires updating the prober configuration to use the prefixed path.

</details>
