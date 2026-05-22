# Unsupported Features and Known Gaps — Implementation Analysis

Each gap in `kongcheck`'s static analyzer is assessed across four dimensions:

- **Complexity** — estimated implementation effort (Low / Medium / High / Very High)
- **Usefulness** — how much it would improve the quality of findings if addressed (Low / Medium / High)
- **Testability** — how easy it is to write confident, deterministic tests (Easy / Medium / Hard)
- **Realism** — how frequently this scenario appears in real Konnect control planes in the wild (Rare / Occasional / Common / Very Common)

---

## 1. ~~`PLAIN_HOSTS_ONLY` and wildcard-host sort ordering~~ ✓ IMPLEMENTED

### What is missing

Kong's route sort key begins with a three-bit `submatch_weight` field. `kongcheck` only models bit 0 (has-regex-path). Bits 1 and 2 encode:

- Bit 1: all hosts on the route are plain (no wildcards) → the route ranks higher than a wildcard-host route at the same path specificity.
- Bit 2: the wildcard host includes an explicit port.

A plain-host route at `/v1/users` should deterministically beat a `*.example.com`-constrained route at `/v1/users`. `kongcheck` may call this a `collision` without identifying the correct winner — or, worse, invert the winner.

### Implementation complexity — **Medium** ✓ Done

**IMPLEMENTED.** Changes made:

- `src/types.ts`: Added `subMatchWeight: number` to `MarshalledRoute` with full JSDoc describing all 3 bits.
- `src/router.ts` `marshalRoute`: Computes all 3 bits from `route.hosts` — `HAS_REGEX_URI` (bit 0), `PLAIN_HOSTS_ONLY` (bit 1, set when no host contains `*`), `HAS_WILDCARD_HOST_PORT` (bit 2, set when any wildcard host has an explicit port after `*`).
- `src/router.ts` `compareRoutes`: Now uses `subMatchWeight` as an unsigned integer (same as Kong's `r1.submatch_weight > r2.submatch_weight`) instead of the previous `hasRegexPath ? 1 : 0`.
- `src/router.ts` `explainPairOrdering`: Describes each bit case distinctly in the explanation chain.
- Tests: `marshalRoute – subMatchWeight 3-bit field`, `compareRoutes – PLAIN_HOSTS_ONLY beats wildcard-host`, `compareRoutes – subMatchWeight sort tier takes precedence over all others`, `simulateRequest – explanation text for subMatchWeight ordering`.

The original text describing the approach:

Inspecting each route's `hosts` array: any entry containing `*` → wildcard.
Computing a three-bit weight per route (previously just `hasRegexPath ? 1 : 0`).
No changes were needed to the Kong API fetch or data model; the `hosts` field is already present on every marshalled route.

### Usefulness — **High**

Host-based routing is one of the most common multi-tenant Kong patterns. A platform team typically has a wildcard `*.internal.example.com` catch-all route, and each service team registers a plain-host `payments.internal.example.com` route. Without this fix, `kongcheck` reports these as a `collision` (or even the wrong winner), generating high-noise false positives that erode trust in the tool.

Fixing this would directly reduce false-positive `collision` / `shadowing` findings for any control plane that uses virtual hosting.

### Testability — **Easy**

The sort logic is pure and deterministic. Unit tests just need:

- Two routes with the same path, one `host=api.example.com` (plain) and one `host=*.example.com` (wildcard) → verify the plain-host route is the winner.
- Two routes with the same path, both wildcard, one with an explicit port → verify the ported route loses.
- Integration with `classifyCollisionSeverity` to check severity assignment is correct.

No mocking or Konnect API calls required.

### Realism — **Very Common**

Virtual hosting is standard practice on Kong Konnect. Nearly every production control plane that serves more than one team or service uses a combination of plain-host and wildcard-host routes. This is the single highest-impact gap to close.

---

## 2. ~~Wildcard host port handling~~ ✓ IMPLEMENTED

### What is missing

When a wildcard host value omits a port (e.g. `*.example.com`), Kong internally compiles it as a regex that also matches requests with an explicit port in their `Host` header: `(?:\.example\.com)(?::\d+)?`. When a port is explicit (e.g. `*.example.com:8080`), Kong compiles it as `(?:\.example\.com:8080)`.

`kongcheck`'s `explain-request` host matching uses a plain `endsWith(".example.com")` check and never inspects the port component of the simulated request's `Host` header. This means:

- `Host: api.example.com:8443` does not match `*.example.com` in `kongcheck` — it would in Kong.
- `Host: api.example.com` does not match `*.example.com:8080` in `kongcheck` — correct, but the check is coincidentally right for the wrong reason.

### Implementation complexity — **Low** ✓ Done

**IMPLEMENTED.** The `matchRoute` wildcard host check in `src/router.ts` was replaced with a full port-aware implementation:

1. Parse constraint `*.example.com` or `*.example.com:8080` into `(domainSuffix, constraintPort)`.
2. Parse request host `foo.example.com` or `foo.example.com:8443` into `(reqDomain, reqPort)`.
3. Check domain suffix: `reqDomain.endsWith(domainSuffix)`.
4. No constraint port → accept any request port (Kong appends `(?::\d+)?$`).
5. Constraint port present → require exact match.

Tests: `matchRoute – wildcard host port handling (Gap #2)` — all six combinations of (port in constraint / no port) × (port in request / no port / wrong port).

### Usefulness — **Medium**

In practice, `explain-request` is the main surface where this matters. Users who call `kongcheck explain-request --path /api/v1/users` rarely include a port in their `--host` argument. The gap would produce a confusing "no winner found" result in environments where an upstream proxy forwards an explicit port (e.g. `Host: api.internal.example.com:8443`), but this is a somewhat niche invocation pattern.

For the static collision analysis it matters less: collisions are already found by comparing routes against each other, not by replaying requests. A false-negative in host matching here would only cause a missed collision if **both** routes depend on the port behaviour difference — an unlikely setup.

### Testability — **Easy**

Pure string-matching logic. Tests just need to assert the four combinations of (constraint has port / no port) × (request has port / no port).

### Realism — **Occasional**

Most developers test `explain-request` with clean hostnames. This gap becomes relevant only when:

- The Kong control plane is fronted by an L7 proxy that forwards `Host` with an explicit port.
- Developers use `--host` in `explain-request` with a port number.

Probably affects 10–20 % of production deployments that terminate TLS at a non-standard port.

---

## 3. Header-constrained routes with identical paths (INFO tier, partially handled)

### What is missing

This gap is **partially closed**: the static analyzer now emits an `INFO` finding with `explain-request` commands when the winner has a header constraint and both routes share identical paths. The remaining hole is specifically about **regex header values** (`~*` prefix), which is documented separately below (gap 4).

The current implementation correctly handles:

- Winner has a plain header constraint, loser has none → `INFO` (stratified).
- Both routes have header constraints with disjoint plain values on the same header name → `INFO` (stratified).
- Both routes have header constraints with overlapping plain values → `HIGH` (real collision).

What it does **not** handle:

- Either route uses a `~*`-prefixed regex header value (see gap 4).
- The loser has a header constraint and the winner does not (the winner wins unconditionally regardless of header — this is actually a real collision and correctly emitted as `HIGH`).

### Implementation complexity — **N/A (partially done)**

The remaining work is entirely contained in gap 4.

### Usefulness — **N/A (partially done)**

### Testability — **N/A (partially done)**

### Realism — **N/A (partially done)**

---

## 4. ~~Regex header values (`~*` prefix) — Option A~~ ✓ IMPLEMENTED (Option A)

### What is missing

A Kong header constraint value can start with `~*` to indicate a PCRE case-insensitive regex match against the incoming header value. Example:

```
Route A: headers: { x-version: ["~*^v[0-9]+$"] }   ← matches any vN string
Route B: no header constraint
```

The static analyzer's `isHeaderStratified` function compares header values as plain lowercase strings. When it encounters `~*^v[0-9]+$`, it cannot determine at analysis time whether the pattern is disjoint from another route's unconstrained handling or overlapping with a sibling route's plain literal values.

Currently, `isHeaderStratified` returns `false` (not stratified) when it cannot confirm disjointness — meaning the pair gets classified as a regular collision at whatever severity the path analysis dictates. This is conservative (no false-negative suppression) but produces false-positive findings for well-structured regex header constraints.

### Implementation complexity — **High** (Option A: ✓ Done; Option B: not implemented)

There are two viable approaches:

**Option A — Semantic approximation** ✓ IMPLEMENTED

`isHeaderStratified` now returns a 3-way discriminant: `'stratified'` | `'regex-opaque'` | `false`.

When any involved header value starts with `~*`, and no dimension is definitively stratified (no constraint on the loser for the same header), the function returns `'regex-opaque'`. Callers (`detectCollisions` and `detectSiblingOverlaps`) then emit a `MEDIUM` finding via `buildRegexHeaderOpaqueFinding`, which:

- Explains that static analysis of regex header patterns is not supported.
- Lists the `~*` values that triggered the downgrade.
- Notes whether the routes target different services (higher risk).
- Suggests `kongcheck explain-request` for manual verification.

A definitively stratified dimension (loser has no constraint on a header the winner requires) still takes precedence and returns `'stratified'` → INFO, even if other dimensions have `~*` values.

Tests: `analyzeRoutes – ~* regex header values produce MEDIUM (not HIGH) findings (Gap #4 Option A)`.

**Option B — Full PCRE intersection analysis (Very High effort)**

To know whether `~*^v[0-9]+$` is disjoint from `~*^legacy$`, you need to decide if two regular languages have a non-empty intersection. This is decidable for regular languages (product automaton construction) but is extremely complex to implement correctly in TypeScript, requires a full PCRE-to-NFA compiler, and would be its own significant project. The Bun/V8 `RegExp` engine provides no API for intersection testing.

The practical ceiling for this feature is Option A: flag regex-header constraints as opaque, note the limitation, and keep the conservative worst-case severity.

### Usefulness — **Medium**

Regex header constraints are an advanced Kong feature used by teams doing traffic splitting by header value patterns (e.g. canary releases by user-agent version). These teams are experienced Kong users likely to understand the tool's limitation. However, for control planes that heavily use `~*` header values, the number of false-positive `HIGH` findings grows proportionally with route count.

### Testability — **Easy (for Option A)**

Option A just needs a test asserting that a route pair with a `~*` header value is emitted at `MEDIUM` severity (not `HIGH`) with an appropriate note. Option B would require extensive PCRE intersection test cases.

### Realism — **Occasional**

`~*` header values are uncommon in most Kong deployments. They appear mainly in canary-release pipelines and A/B test infrastructure. Probably found in 5–15 % of production control planes that have any header constraints at all.

---

## 5. Non-identical paths with header constraint on the winner (always HIGH — intentional)

### What is missing

This is not really a gap — it is a deliberate design choice. When a broad-regex winner also has a header constraint but has a **different (broader) path** than the loser, `kongcheck` still emits `HIGH`. The header does not fix the path over-match: in any environment where the winner's header is routinely present, the winner intercepts all traffic destined for the loser's specific path.

The documentation calls this out explicitly:

> A route with `path=~/users/([^/]+)` and `headers={x-env:[dev,...]}` intercepts `/marketing/userprofile/users/resend-activation-email` in any dev environment where every request carries `x-env:dev`.

The finding is intentionally conservative. Suppressing it would require proving that the header constraint fully partitions the traffic space between the two routes — which requires the identical-path precondition (gap 3/4 above).

### Implementation complexity — **N/A (intentional)**

### Usefulness — **N/A (intentional)**

### Testability — **N/A (intentional)**

### Realism — **N/A (intentional)**

---

## 6. ~~URI normalization and query-string stripping~~ ✓ Done

### What was missing

Before matching, Kong applies several normalizations to the incoming request URI:

1. Strips the query string (`?` and everything after).
2. Strips the URL fragment (`#` and everything after).
3. Resolves `.` and `..` segments.

`kongcheck` took the path as supplied by `--path` and applied no normalization. A user who passed `--path /api/v1?debug=1` would get a prefix-match result that included `?debug=1` in the tested string, potentially causing a false "no winner" result even though Kong would strip the query string first.

The practical surface is `explain-request`. The static collision analysis uses `generateCandidateRequests` to synthesize paths — these are always clean (no query strings), so normalization gaps do not affect collision detection.

### Implementation

`normalizePath(rawPath: string): string` added to `src/cli.ts` (exported for testing).

Uses the WHATWG `URL` parser with a throwaway base (`http://x`). `url.pathname` is dot-resolved and never includes `?` or `#`. Falls back to the raw input if parsing fails (no silent data loss).

Percent-encoding is intentionally **preserved**: Kong's traditional router matches the raw URI without decoding, so `/hello%20world` and `/hello world` are distinct paths.

When `normalizePath` changes the value, a warning is printed to `stderr`:

```
Warning: --path was normalized from '/api/v1?debug=1' to '/api/v1'.
```

Tests: `src/cli.test.ts` — `normalizePath` suite (query-string stripping, fragment stripping, percent-encoding preservation, dot-segment resolution, clean-path passthrough, edge cases).

### Implementation complexity — **Low** ✓ Done

### Usefulness — **Low** ✓ Done

This only matters if a user accidentally passes a query string or a dotpath to `--path`. The README documents "always pass a clean path (no query string)". In practice, developers copy-paste clean path segments rather than full URLs. This is a quality-of-life fix rather than a correctness fix.

### Testability — **Easy** ✓ Done

Unit tests for the normalization function in `src/cli.test.ts`.

### Realism — **Rare**

Most users follow the documented guidance. A copy-paste from a browser address bar is the most likely trigger.

---

## 7. PCRE backtracking limit (`(*LIMIT_MATCH=10000)`)

### What is missing

Kong prepends `(*LIMIT_MATCH=10000)` to every compiled regex path before evaluating it. This caps PCRE backtracking at 10,000 steps and prevents catastrophic backtracking (ReDoS) from hanging the gateway. The route is considered a non-match when the limit is exceeded, and Kong moves to the next candidate.

JavaScript's `RegExp` engine (V8) has no direct equivalent. Bun uses JavaScriptCore which also lacks this control. When `kongcheck` evaluates a pathological regex, it runs to completion — which might mean:

1. A very slow test for complex patterns (JavaScriptCore does have some internal backtrack limiting, but it is not equivalent to PCRE's precise 10,000-step cap).
2. A false-positive match: `kongcheck` says the regex matches a given path, but Kong would have aborted and treated it as a non-match (moving to the next route).

In practice, case 2 means `kongcheck` could report a shadowing scenario that Kong never actually triggers in production.

### Implementation complexity — **Very High**

There is no standard way to instrument `RegExp.exec()` in V8/JSC with a step counter. Options:

**Option A — Timeout-based proxy (Hacky, Low effort)**
Run each `RegExp.exec()` call in a `setTimeout`/`Worker` with a wall-clock deadline. If it doesn't complete in N ms, assume non-match. This is non-deterministic across machines, doesn't map to Kong's backtrack-count semantics, and introduces significant complexity for parallel route evaluation.

**Option B — Re-implement regex evaluation with a step counter (Very High effort)**
Port a PCRE-compatible NFA/backtracking engine to TypeScript with an instrumented step counter. This is a multi-week project, effectively building a regex engine from scratch.

**Option C — Static pattern analysis to flag high-backtrack-risk patterns (Medium effort)**
Use static analysis (e.g. detecting nested quantifiers, exponential ambiguity) to flag patterns that are likely to exceed the backtrack limit. This is the approach taken by tools like `safe-regex`. It doesn't solve the problem precisely but catches the most dangerous patterns (which the `suspicious_regex` linter already partially covers).

Option C is the most pragmatic. The `suspicious_regex` linter already flags `*` after non-trivial tokens, which is the most common source of catastrophic backtracking in Kong paths.

### Usefulness — **Low**

In real-world Kong deployments, route paths are written by developers using the Kong UI or declarative config tools. Pathological regex patterns (ones that actually exhaust 10,000 backtrack steps on typical URL paths) are almost never seen in production. The `suspicious_regex` linter catches the subset of patterns that are both common and dangerous.

The false-positive risk (case 2 above) is also low: for a JavaScript runtime to match a path that PCRE would backtrack-abort on, the path itself would need to be adversarially constructed — not something that arises from realistic URL structures.

### Testability — **Hard**

Testing Kong's exact backtrack-limit behaviour requires running the same regex through a PCRE engine and through V8 on the same input and comparing results. This is not feasible within the existing Bun test infrastructure without a native PCRE addon.

### Realism — **Rare**

Catastrophic backtracking in Kong paths is a theoretical concern. In practice, it would be caught by Kong's own logging (the match would be aborted with an error log entry) long before it caused a routing discrepancy that `kongcheck` would mismodel. No known production incident has been reported that traces to this gap.

---

## 8. ~~SNI, source IP, and destination IP/port constraints~~ ✓ Done

### What was missing

Kong supports L4 routing constraints beyond HTTP: TLS SNI values, client source IP address/CIDR ranges and ports, and destination IP/CIDR ranges and ports. These are used to route TCP/TLS stream traffic (Kong's stream routing mode) and, in some configurations, HTTP routes with IP allowlist-style constraints.

`kongcheck` previously ignored all three. Every route that had these constraints was analyzed as if those constraints did not exist. Consequences were:

- **False positives**: a stream route constrained to `sources=[{ip:"10.0.0.0/8"}]` and an HTTP route constrained to `sources=[{ip:"203.0.113.0/24"}]` would be reported as a collision even though they can never receive the same request.
- **Incorrect winner identification**: in `explain-request`, SNI/IP constraints were not applied during route filtering, so the wrong route could be reported as the winner.
- **Mixed control planes**: control planes that handle both HTTP and TCP/TLS traffic produced a high number of meaningless cross-protocol findings.

### Implementation

All three dimensions are now implemented. Ported faithfully from `kong/router/traditional.lua` (commit 2ffd3b1):

1. **CIDR/IP utilities** (`src/router.ts`) — `parseIpv4`, `cidrToRange`, `ipsCanOverlap`, `ipPortListsOverlap`.
   IPv4 full support; IPv6 is conservative (returns `true` / assumes overlap — no false negatives).
   Mirrors Kong's `lua-resty-ipmatcher`-backed `create_range_f` logic.

2. **`matchRoute` simulation** (`src/router.ts`) — SNI, source IP/port, and destination IP/port checks are applied when the corresponding `request.sni` / `request.sourceIp` / `request.destIp` fields are defined (explicit simulation mode).
   When those fields are `undefined`, the checks are skipped (conservative static-analysis mode — every route remains a collision candidate).
   Mirrors the `request.headers === undefined` sentinel already used for header constraints.

3. **Stratification analysis** (`src/analyzer.ts`) — `isSniIpStratified` classifies route pairs on four L4 dimensions:
   - **Protocol family**: one route all-HTTP (`http/https/grpc/grpcs`), other all-stream (`tcp/tls/udp/tls_passthrough`) → mutually exclusive.
   - **SNI**: both routes have non-empty `snis` sets and they are completely disjoint (FQDN trailing-dot normalised to match Kong's `sub(sni, 1, -2)`).
   - **Source IP/port**: both routes have `sources` lists and `ipPortListsOverlap` returns `false`.
   - **Destination IP/port**: both routes have `destinations` lists and `ipPortListsOverlap` returns `false`.
     Stratified pairs emit an **INFO** finding (gated by `--no-info`) instead of a HIGH/MEDIUM collision.
     This check runs before the `haveIdenticalPaths` / header-stratification block in both `detectCollisions` and `detectSiblingOverlaps`.

### Kong source references

- `traditional.lua#L279–L284` — `create_range_f` (CIDR factory using `lua-resty-ipmatcher`)
- `traditional.lua#L493–L518` — SNI marshalling (trailing-dot strip, `snis_t` map)
- `traditional.lua#L522–L577` — sources/destinations marshalling
- `traditional.lua#L880–L900` — `matcher_src_dst` (per-entry IP+port check, OR semantics)
- `traditional.lua#L1072–L1085` — `MATCH_RULES.SNI`, `MATCH_RULES.SRC`, `MATCH_RULES.DST` handlers

### Test coverage

- `src/router.test.ts` — unit tests for `parseIpv4`, `cidrToRange`, `ipsCanOverlap`, `ipPortListsOverlap`; `matchRoute` with SNI/source/dest fields.
- `src/analyzer.test.ts` — integration tests for SNI stratification (disjoint/overlapping sets, trailing-dot normalisation, `includeInfo=false`), source/dest CIDR stratification, protocol-family stratification, and the "only one side has the constraint" case.

---

## Summary table

| #   | Gap                                        | Complexity         | Usefulness                          | Testability    | Realism            |
| --- | ------------------------------------------ | ------------------ | ----------------------------------- | -------------- | ------------------ |
| 1   | `PLAIN_HOSTS_ONLY` / wildcard-host sort    | Medium ✓           | **High**                            | Easy           | **Very Common**    |
| 2   | Wildcard host port handling                | Low ✓              | Medium                              | Easy           | Occasional         |
| 3   | Header-constrained identical paths         | — (partially done) | —                                   | —              | —                  |
| 4   | Regex header values (`~*`) — Option A      | Low ✓ (approx.)    | Medium                              | Easy (approx.) | Occasional         |
| 5   | Non-identical paths + header on winner     | — (intentional)    | —                                   | —              | —                  |
| 6   | URI normalization / query-string stripping | Low ✓              | Low                                 | Easy ✓         | Rare               |
| 7   | PCRE backtrack limit                       | Very High          | Low                                 | Hard           | Rare               |
| 8   | SNI / source IP / destination IP+port      | Medium–High ✓      | High (stream CPs) / Low (HTTP-only) | Medium         | Common (mixed CPs) |

### Recommended implementation priority

~~1. **Gap 1 (wildcard-host sort)**~~ ✓ Done.
~~2. **Gap 4 (regex header values) — Option A**~~ ✓ Done.
~~3. **Gap 2 (wildcard host port)**~~ ✓ Done.
~~4. **Gap 8 (SNI / IP constraints)**~~ ✓ Done.
~~5. **Gap 6 (URI normalization)**~~ ✓ Done. 6. **Gap 7 (PCRE backtrack limit)** — theoretical; not worth implementing beyond what the existing `suspicious_regex` linter already provides.
