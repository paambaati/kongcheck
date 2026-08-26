# Native Port Handoff Notes (`feat/native-port`)

> **Status as of Aug 2026:** Branch is fully merged with `main` (v1.3.0), all commits SSH-signed,
> 332 tests green under Vitest, `bun build --compile` works. Porting work is **paused** waiting on
> a PerryTS release newer than `0.5.1220`.

---

## 1. Original Goals

1. **Reduce binary size** — the Bun-compiled binary embeds the whole JSC runtime (~90 MB). Goal was
   platform-specific binaries in the low-MB range.
2. **Fast performance** — instant startup, competitive execution speed for a CLI audit tool.
3. **Keep test infrastructure** — the 300+ unit tests had to keep running locally without change.
4. **Compile to small native binaries** for Linux (x64/arm64), macOS (x64/arm64), Windows x64.

Candidate runtimes originally shortlisted: **QuickJS** (plain / embedded), **Porffor**, **Perry**
(https://docs.perryts.com/).

---

## 2. What We Tried (chronological)

### Phase 1 — Pure-JS decoupling ✅ DONE (kept)

Removed every Bun-only API so the codebase runs on any ES2022+ engine:

| Was | Now | File |
|---|---|---|
| `Bun.sleep(ms)` | `new Promise(r => setTimeout(r, ms))` | `src/client.ts` |
| `Bun.file(p).text()` | `fs.readFile(p, 'utf-8')` (`node:fs/promises`) | `src/client.ts` |
| `Bun.write(f, s)` | `fs.writeFile(f, s, 'utf-8')` | `src/cli.ts` |
| `Bun.color(name,'ansi')` | static ANSI escape map (`ansiColor()`) | `src/formatter.ts` |
| `nspin-bun` dep | inline ~35-line vanilla `Spinner` class | `src/cli.ts` |
| `tiny-relative-date` dep | inline `getRelativeDate()` helper | `src/formatter.ts` |
| `bun:test` imports | **Vitest** (`vitest@4.1.10`, `@vitest/coverage-v8`) | all `*.test.ts` |
| `import {name,version} from '../package.json'` | build-time generated `src/generated-version.ts` | `src/cli.ts`, `src/mcp.ts` |

Version constants are produced by `scripts/generate-version.js` (reads `package.json`, writes
`src/generated-version.ts`). Run manually via `npm run codegen:version`. This sidesteps Perry's
broken JSON-import lowering (see Phase 3).

### Phase 2 — Validation library ✅ DONE (superseded by main)

Zod was removed entirely:
- Zod v4 crashes under any fixed-layout AOT engine: `TypeError: Cannot convert undefined or null to
  object` at `zod/src/v4/core/core.ts:38` — v4 mutates class prototypes / trait sets at runtime,
  which fixed-layout compilers cannot represent.
- Replaced with **Valibot v1.4.2** (functional schema builders, tree-shakeable).
- Upstream `main` then landed its own migration (PR #11, SDK v2): `@modelcontextprotocol/server@2.0.0`
  + `@valibot/to-json-schema` feeding `toStandardJsonSchema()` into high-level
  `McpServer.registerTool()`. **Main's approach won** and is canonical on the branch now.

⚠️ Note: SDK v2 still depends on **zod ^4.2.0 transitively**. Harmless on Bun/Node; may resurface
under AOT if Perry's class-layout handling doesn't cover it after their fixes land.

### Phase 3 — Perry AOT ❌ BLOCKED (upstream bugs)

Target: `@perryts/perry@0.5.1220` (latest published; npm `latest` tag == GitHub release, both
Jul 4 2026).

Failures encountered, root-caused against the Perry tracker:

| Symptom | Root cause | Tracker status |
|---|---|---|
| `ld: symbol(s) not found`: `_js_ext_http_agent_*`, `_js_http_has_pending`, etc. | `libperry_stdlib.a` references fetch/http bridge symbols that prebuilt `libperry_runtime.a` no longer exports (V8 support removed from AOT builds) | **Fixed on `main`** — issue [#8155](https://github.com/PerryTS/perry/issues/8155), PR [#8197](https://github.com/PerryTS/perry/pull/8197) (merged Aug 16 2026). **Not released.** |
| `ld: 3149 duplicate symbols` between `libperry_stdlib.a` and `libperry_runtime.a` (hard error) | Same family; Apple `ld-prime` (Xcode 15+) treats duplicates as fatal where older `ld` warned | Related: [#8455](https://github.com/PerryTS/perry/issues/8455), [#8064](https://github.com/PerryTS/perry/issues/8064) — closed on `main`. **Not released.** |
| `___perry_wrap_perry_fn_package_json__name` undefined | Perry lowers named imports from `package.json` into wrapper fns that fail to link | Worked around permanently via `generated-version.ts` |
| Zod v4 runtime crash | Documented limitation (no prototype mutation), not a bug | N/A — solved by Valibot |

Workarounds attempted and abandoned: C FFI stubs via `perry.nativeLibrary` (+ dead-path references
to force symbol retention), `-Wl,-allow_duplicates`, `-Wl,-ld_classic` (none survive Xcode 21
`ld-prime`). All stub artifacts were deleted afterwards.

### Phase 4 — Alternative small runtimes (evaluated, not implemented)

| Candidate | Verdict |
|---|---|
| `sebastianwessel/quickjs` | **Rejected** — it's a WASM *sandbox library* that runs inside a host engine (Bun/Node). Using it would *grow* the binary, not shrink it. |
| **txiki.js** (`tjs compile`) | Best pure-binary candidate: ~2 MB standalone, WinterCG APIs, native WHATWG `fetch`. Quirk: zero Node stdlib shims, ESM-only, needs transpile step. |
| **AWS LLRT** | Solid runner (Rust+QuickJS, Node shims) but Lambda-oriented, explicitly experimental, no first-class standalone-binary story. |
| **Porffor** | Blocked — subset lacks classes/`Map`/`Set` patterns used heavily here. |

---

## 3. Current Branch State

- Branch `feat/native-port`, history linearized onto `origin/main` via rebase; every commit
  SSH-signed (`%G? = S`; local verification needs `~/.ssh/allowed_signers` — see below).
- Build/test/lint all green: `bun install && bun test && bun run typecheck && bun run lint && bun run build`.
- Compiled binary reports `kongcheck/1.3.0`; MCP stdio handshake verified over JSON-RPC.
- `package.json` currently has **no `perry.*` config block** (removed when reverting to Bun builds).
  The block to re-add is in §4.
- CI `.github/workflows/release.yml` uses `bun build --compile --bytecode --minify --target …`
  cross-compiling all 5 targets from one Linux runner; Bun pinned to `1.4.x`.

Local signature verification setup (already applied globally):

```bash
echo "me@httgp.com $(cat ~/.ssh/gp_personal_id_ed25519.pub)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

---

## 4. Resume Checklist (when `@perryts/perry` > 0.5.1220 ships)

```bash
npm view @perryts/perry version        # wait until > 0.5.1220
```

1. `bun add -d @perryts/perry@<new>` (or global).
2. Re-add to `package.json`:

```jsonc
"perry": {
  "codegen": [
    { "label": "generate version", "command": "node scripts/generate-version.js" }
  ],
  "compilePackages": [
    "cac", "valibot", "@modelcontextprotocol/sdk", "@modelcontextprotocol/server",
    "@modelcontextprotocol/core", "@valibot/to-json-schema",
    "ajv", "ajv-formats", "fast-deep-equal", "fast-uri",
    "json-schema-traverse", "zod", "zod-to-json-schema"
  ],
  "allow": { "compilePackages": ["*"] }
}
```

   (Adjust the list to whatever the compiler flags as "still routed to runtime JavaScript" —
   Perry prints an exact missing-package hint on each run.)

3. Trial compile:

```bash
npm run codegen:version
npx @perryts/perry compile src/cli.ts -o dist/kongcheck-perry
./dist/kongcheck-perry --version
```

4. Decision gates:
   - If it links & runs → flip `"build"` script back to `perry …`, restore the matrix in
     `release.yml` (targets seen working in docs: `macos-arm64`, `macos-x64`, `linux-x64`,
     `linux-arm64`, `windows-x64`; also `--libc musl` for static Linux).
   - If the zod-v4 prototype crash returns inside SDK v2 (`core.ts:38`): options are (a) wait for
     Perry class-layout fixes, (b) pin/downgrade SDK, or (c) fall back to txiki.js.
   - If duplicate-symbol errors persist on macOS arm64 only: consider building perry from source
     (`cargo build --release` per their docs) which includes post-0.5.1220 linker fixes.
5. Keep Bun path intact as fallback — nothing on the branch blocks shipping with Bun today.

---

## 5. Future: Next-Gen AOT Candidates

*Space reserved for evaluating future projects that take JS/TS → native code. Fill in as they
appear. Minimum bar derived from everything above:*

| Criterion | Required? |
|---|---|
| Compiles classes with **fixed layouts** but tolerates prototype reads/writes OR ecosystem libs avoid proto mutation | ✅ hard requirement (zod/SDK lesson) |
| Native HTTPS client (`fetch` or node:http) without external V8/JSC host | ✅ hard requirement |
| Static ESM imports incl. JSON or a supported codegen hook | ✅ hard requirement |
| `Map` / `Set` / generators / async-await / regex lookbehind-free PCRE | ✅ hard requirement |
| Cross-compiles (or per-platform CI matrix) to linux-x64/arm64, darwin-x64/arm64, win-x64 | ✅ required for release parity |
| Binary ≤ ~5 MB, startup < ~10 ms | goal |
| Can consume bundled ESM output from esbuild/bun build (decouples bundling from compilation) | strongly preferred |
| Test-runner compatibility (Vitest under Node/Bun for dev; runtime only needs to execute compiled bundle) | preferred |

Candidates to track (add notes/dates as they evolve):

- [ ] **PerryTS** — pending release > 0.5.1220 (issues #8155/#8455 fixes). Primary candidate.
- [ ] **txiki.js** — fallback plan; needs Node-shim polyfill pass over `cac` usage.
- [ ] **LLRT** — revisit if it gains a standalone-binary story.
- [ ] _(new candidate)_
- [ ] _(new candidate)_

---

## 6. Quick Reference

- Branch: `feat/native-port` (linearized, all-signed)
- Merge base: current `origin/main` @ v1.3.0
- Test command: `bun run test` (Vitest, 332 tests)
- Build command: `bun run build`
- Codegen: `npm run codegen:version` → regenerates `src/generated-version.ts` from `package.json`
- Perry tracker watch-list: https://github.com/PerryTS/perry/releases (need tag > `v0.5.1220`)
