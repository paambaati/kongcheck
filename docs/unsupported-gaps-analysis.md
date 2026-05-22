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

## 6. URI normalization and query-string stripping

### What is missing

Before matching, Kong applies several normalizations to the incoming request URI:

1. Strips the query string (`?` and everything after).
2. Percent-decodes path segments (or normalizes encoding).
3. Resolves `.` and `..` segments.

`kongcheck` takes the path as supplied by `--path` and does no normalization. A user who passes `--path /api/v1?debug=1` will get a prefix-match result that includes `?debug=1` in the tested string, potentially causing a false "no winner" result even though Kong would strip the query string first.

The practical surface is `explain-request`. The static collision analysis uses `generateCandidateRequests` to synthesize paths — these are always clean (no query strings), so normalization gaps do not affect collision detection.

### Implementation complexity — **Low**

Stripping the query string is a one-liner (`path.split('?')[0]`). Percent-decoding and dotpath resolution add perhaps 10–15 lines. Applying these normalizations at the `explain-request` ingestion point (before path matching) fully closes the gap.

A warning could also be emitted to `stderr` when the user passes a path containing `?`, `%`, or dotpath segments.

### Usefulness — **Low**

This only matters if a user accidentally passes a query string or percent-encoded path to `--path`. The README documents "always pass a clean path (no query string)". In practice, developers copy-paste clean path segments rather than full URLs. This is a quality-of-life fix rather than a correctness fix.

### Testability — **Easy**

Unit tests for the normalization function. Integration tests for `explain-request` asserting that `--path /api/v1?debug=1` gives the same result as `--path /api/v1`.

### Realism — **Rare**

Most users follow the documented guidance. A copy-paste from a browser address bar is the most likely trigger. Low priority.

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

## 8. SNI, source IP, and destination IP/port constraints

### What is missing

Kong supports L4 routing constraints beyond HTTP: TLS SNI values, client source IP address/CIDR ranges and ports, and destination IP/CIDR ranges and ports. These are used to route TCP/TLS stream traffic (Kong's stream routing mode) and, in some configurations, HTTP routes with IP allowlist-style constraints.

`kongcheck` completely ignores all three. Every route that has these constraints is analyzed as if those constraints do not exist. Consequences:

- **False positives**: a stream route constrained to `sources=[{ip:"10.0.0.0/8"}]` and an HTTP route constrained to `sources=[{ip:"203.0.113.0/24"}]` would be reported as a collision even though they can never receive the same request.
- **Incorrect winner identification**: in `explain-request`, SNI/IP constraints are not applied during route filtering, so the wrong route may be reported as the winner.
- **Mixed control planes**: control planes that handle both HTTP and TCP/TLS traffic produce a high number of meaningless cross-protocol findings.

### Implementation complexity — **Medium to High**

The data is already fetched (the Konnect API returns `snis`, `sources`, and `destinations` fields on route objects). Three things are needed:

1. **Marshalling** — add the three fields to `MarshalledRoute` (or its underlying `KongRoute` type in `src/types.ts`).
2. **Filtering/matching** — implement IP-in-CIDR matching for `sources` and `destinations` (requires a small CIDR library or hand-rolled implementation), and exact-string SNI matching. CIDR matching in TypeScript is straightforward for IPv4 but adds complexity for IPv6.
3. **Sort / stratification** — Kong's sort order does not change based on SNI/IP constraints (they don't affect `submatch_weight`, `headerCount`, or `regex_priority`). However, for collision analysis, two routes that are mutually exclusive by SNI or source IP should be treated as stratified (no collision) rather than as overlapping.

The CIDR matching logic is the non-trivial piece. Interval intersection for arbitrary CIDR sets is correct but tedious to implement correctly (and even more so for IPv6).

### Usefulness — **High (for stream-route users), Low (for HTTP-only users)**

For control planes that are HTTP-only, this gap produces zero false positives and zero missed findings. For control planes that mix HTTP and stream routes, this is probably the most disruptive source of noise — every stream route pair generates false-positive collision findings, drowning out the real findings.

The practical fix for HTTP-only users today is `--filter tag:<stream-tag>` to exclude stream routes. But this requires user knowledge of which routes are stream routes and consistent tagging discipline.

### Testability — **Medium**

IP matching and CIDR interval logic is easily unit-tested in isolation. Integration tests for `analyzeRoutes` with stream-route configurations are straightforward to write: two routes with non-overlapping source IP ranges and the same path → no finding.

The complexity rises when testing CIDR intersection (overlapping ranges on the same route) and IPv6 edge cases.

### Realism — **Common (for multi-protocol control planes)**

Kong Konnect is increasingly used for L4 routing (database proxying, IoT, gRPC over TCP). Any control plane that hosts both HTTP APIs and TCP stream routes will produce false-positive collision findings for every stream route that happens to share a path pattern with an HTTP route. This is the second-highest-impact gap after the wildcard-host sort ordering issue (gap 1).

For pure HTTP-only control planes (still the majority of production deployments), this gap has zero practical impact.

---

## Summary table

| #   | Gap                                        | Complexity         | Usefulness                          | Testability    | Realism            |
| --- | ------------------------------------------ | ------------------ | ----------------------------------- | -------------- | ------------------ |
| 1   | `PLAIN_HOSTS_ONLY` / wildcard-host sort    | Medium ✓           | **High**                            | Easy           | **Very Common**    |
| 2   | Wildcard host port handling                | Low ✓              | Medium                              | Easy           | Occasional         |
| 3   | Header-constrained identical paths         | — (partially done) | —                                   | —              | —                  |
| 4   | Regex header values (`~*`) — Option A      | Low ✓ (approx.)    | Medium                              | Easy (approx.) | Occasional         |
| 5   | Non-identical paths + header on winner     | — (intentional)    | —                                   | —              | —                  |
| 6   | URI normalization / query-string stripping | Low                | Low                                 | Easy           | Rare               |
| 7   | PCRE backtrack limit                       | Very High          | Low                                 | Hard           | Rare               |
| 8   | SNI / source IP / destination IP+port      | Medium–High        | High (stream CPs) / Low (HTTP-only) | Medium         | Common (mixed CPs) |

### Recommended implementation priority

~~1. **Gap 1 (wildcard-host sort)**~~ ✓ Done.
~~2. **Gap 4 (regex header values) — Option A**~~ ✓ Done.
~~3. **Gap 2 (wildcard host port)**~~ ✓ Done. 4. **Gap 8 (SNI / IP constraints)** — critical for mixed HTTP+stream control planes; zero impact on HTTP-only deployments. An interim `--filter` workaround exists. 5. **Gap 6 (URI normalization)** — quality-of-life, very low priority. 6. **Gap 7 (PCRE backtrack limit)** — theoretical; not worth implementing beyond what the existing `suspicious_regex` linter already provides.
