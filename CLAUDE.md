# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Aguara v0.28.0 (2026-09-10): untrusted-project defaults, audit triage and agent handoff, skill/helper and script checks, parser/report hardening, and verified September 7 embedded intelligence (35,774 record rows + 203,639 all-version entries; not unique package totals). Previous release: v0.27.0 (2026-06-12). Current tree: 24 fuzz targets, 191 YAML rules + 68 analyzer-emitted (259 cataloged), 13 YAML categories (+ analyzer categories incl. agent-trust), 16 per-file scan analyzers (pattern, ci-trust, mcpcapability, kubepolicy, pkgmeta, jsrisk, pyrisk, scriptrisk, rsbuild, npmpolicy, pnpmpolicy, agentpolicy, skillpolicy, NLP, toxicflow, rugpull) plus the skill-chain project correlation and the `aguara check` incident command (npm/PyPI installed trees + pre-install npm lockfiles pnpm-lock.yaml / package-lock.json / yarn.lock classic v1 / yarn.lock Berry v2+ / bun.lock text - all with `npm:` alias resolution to the real package - and Go/Rust/PHP/Ruby/Java/.NET lockfiles), 0 lint issues.

Distribution: install.sh (mandatory checksum verification, bounded curl + retry), Homebrew tap, Docker (GHCR, multi-arch `linux/amd64+arm64`, runs as non-root UID 10001, base images digest-pinned, signed at digest with Cosign + SBOM + SLSA provenance attestations), GoReleaser (releases signed via Cosign keyless, SPDX SBOM per archive, `-trimpath` for reproducibility), GitHub Action, go install.

Pattern matcher already uses an Aho-Corasick keyword prefilter (active in production since v0.14.0). Real perf is ~210ms/op on the synthetic bench (was ~770ms without AC), so do not treat "pattern matcher perf" as an open backlog item unless pprof shows a concrete regression. Pending improvements: WASM build (cmd/wasm/ incomplete), adoption/marketing.

## Build & Test Commands

```bash
make build          # Production binary with version/commit ldflags
make test           # go test -race -count=1 ./...
make lint           # golangci-lint run ./...
make vet            # go vet ./...
make fmt            # gofmt -w .
make run ARGS="scan ./path"  # Development run

# Single package test
go test -race -count=1 ./internal/rules/...

# Single test function
go test -race -count=1 -run TestFunctionName ./internal/engine/pattern/...

# Benchmarks
go test -bench=. -benchtime=3x ./internal/engine/pattern/
go test -bench=. -benchtime=3x ./internal/engine/nlp/
go test -bench=. -benchtime=3x ./internal/scanner/
```

CI requires: `make build && make test && make vet && make lint` all passing.

## Architecture

Aguara is a deterministic static security scanner for AI agent skills and MCP servers. No LLM, no network calls. The minimum Go version is declared in `go.mod`; module `github.com/garagon/aguara`.

### Public Library API (`aguara.go`, `options.go`)

Root package re-exports types from `internal/types` and exposes: `Scan()`, `ScanContent()`, `ListRules()`, `ExplainRule()`, `Discover()`. Used by external consumers like `aguara-mcp`. Functional options pattern (`WithMinSeverity()`, `WithWorkers()`, etc.).

Analyzer wiring is centralized: add an analyzer in `internal/engine/engine.go` (`DefaultAnalyzers` + `RuleMetadata`) - one place, not the old four call sites. Emit-site RuleName/Severity/Category derive from each analyzer's `RuleMetadata()` via `rulemeta.Index` (no string drift).

### Analysis Pipeline (15 default analyzers + rug-pull when --monitor is set, run sequentially per file)

1. **Pattern Matcher** (`internal/engine/pattern/`) - Regex/contains matching against compiled rules. 8 decoders (base64, hex, URL encoding, Unicode escapes, HTML entities, hex escapes, base32, C-style octal escapes) for encoded evasion detection. Markdown code-block severity downgrade. Dynamic confidence based on pattern hit ratio.
2. **CI Trust** (`internal/engine/ci/`) - YAML parser for `.github/workflows/*.yml`. Detects `pull_request_target` pwn-request chains, cache poisoning, OIDC token surface, and persisted-credentials checkouts. Emits `GHA_PWN_REQUEST_001` / `GHA_CACHE_001` / `GHA_OIDC_001` / `GHA_CHECKOUT_001`.
3. **PkgMeta** (`internal/engine/pkgmeta/`) - JSON parser for `package.json`. Detects npm install-time lifecycle scripts paired with git-sourced dependencies, optional-git deps, and publish-surface chains. Emits `NPM_LIFECYCLE_GIT_001` / `NPM_OPTIONAL_GIT_001` / `NPM_PUBLISH_SURFACE_001`.
4. **JSRisk** (`internal/engine/jsrisk/`) - Single-pass JavaScript scanner for `.js`/`.mjs`/`.cjs`. Detects obfuscator-shape payloads, install-time daemonization, CI secret harvesting, runner process-memory pivots, and Claude Code/VS Code persistence. Emits `JS_OBF_001` / `JS_DAEMON_001` / `JS_CI_SECRET_HARVEST_001` / `JS_PROC_MEM_OIDC_001` / `AGENT_PERSISTENCE_001`.
5. **PyRisk** (`internal/engine/pyrisk/`) - Flow-sensitive single-pass scanner for `setup.py`/`__init__.py`. Binds a remote-JS fetch to a `node -e`/`--eval` execution sink (≤2 hops, taint cleared on safe reassignment). Emits `PY_IMPORTTIME_REMOTE_JS_001` (moved from a co-presence YAML rule in v0.22.0).
6. **ScriptRisk** (`internal/engine/scriptrisk/`) - Evidence scanner for local Python and shell scripts. Binds decoded, character-constructed, or remotely fetched Python values to `exec`/`eval`, identifies sensitive local context paired with a bound HTTP write, detects literal world-writable permission changes through bound Python APIs or commands, resolves structured pathlib/subprocess systemd persistence, and flags real pip/npm commands using unencrypted dependency sources. Emits `PY_DECODE_EXEC_001`, `PY_REMOTE_FETCH_EXEC_001`, `PY_CONTEXT_EXFIL_001`, `PY_WORLD_WRITABLE_001`, `SC-EX-007` (migrated from YAML), `SHELL_UNSAFE_PIP_SOURCE_001`, and `SHELL_UNSAFE_NPM_SOURCE_001`.
7. **RSBuild** (`internal/engine/rsbuild/`) - Flow-sensitive single-pass scanner for `build.rs`. Binds a wallet/keystore read to a network send sink (the tainted value must reach a send/body argument; ≤2 hops). Emits `RS_BUILD_WALLET_EXFIL_001` (moved from a co-presence YAML rule in v0.22.0).
8. **NpmPolicy** (`internal/engine/npmpolicy/`) - Reads `package.json` (`allowScripts` policy) and project `.npmrc` for npm v12 install-trust weakenings: the `dangerously-allow-all-scripts` escape hatch, unpinned approvals, `allow-git`/`allow-remote` relaxations. Ground-truthed against npm 11.16.0 (deny entries are name-only false and never fire; quoted+comment values are inert; last-wins; empty boolean = true; manifest keys case-sensitive). Emits 4 `NPM_*` rules (1 HIGH, 3 MEDIUM), category supply-chain.
9. **PnpmPolicy** (`internal/engine/pnpmpolicy/`) - yaml.Node parser for `pnpm-workspace.yaml` (exact target, base name only). Flags pnpm supply-chain settings weakened below the v11 defaults; absence of a setting never fires. Only exact camelCase keys match (ground truth pnpm 11.5.2: kebab-case in pnpm-workspace.yaml is silently IGNORED by pnpm - kebab is the .npmrc spelling - so kebab must NOT fire), YAML merge keys expand (visited-set bounded), explicit beats merged, booleans follow pnpm's js-yaml 1.1 loader (yes/no/on/off ARE booleans - do not "fix" to yaml.v3 tags). Emits 9 `PNPM_*` rules (1 HIGH `PNPM_DANGEROUS_BUILDS_001`, 4 MEDIUM, 3 LOW, 1 INFO), all category supply-chain.
10. **AgentPolicy** (`internal/engine/agentpolicy/`) - JSON parser for Claude Code `.claude/settings.json` / `settings.local.json` (exact target via `.claude/` path suffix). Flags host config dangerous to inherit from a cloned repo: hooks that fetch-and-execute, code-injection env vars (NODE_OPTIONS --require, LD_PRELOAD, BASH_ENV…), `bypassPermissions`, `enableAllProjectMcpServers`, broad/secret-read allow rules, repo-relative credential helpers. Per-key independent decode (one bad block doesn't blind the rest); absence never fires; fires on dangerous value SHAPE only. Emits 8 `AGENTCFG_*` rules (1 CRITICAL, 2 HIGH, 4 MEDIUM, 1 LOW), category `agent-trust`.
11. **SkillPolicy** (`internal/engine/skillpolicy/`) - Bounded `yaml.Node` parser for the real `SKILL.md` frontmatter only. Flags an exact whole-value `allowed-tools` wildcard; body examples, scoped command wildcards, malformed metadata, and similarly named keys stay quiet. Emits `AGENT_SKILL_WILDCARD_TOOLS_001` (MEDIUM), category `agent-trust`.
12. **NLP Analyzer** (`internal/engine/nlp/`) - Goldmark AST walker for markdown; JSON/YAML string extractor for structured files. Keyword classification with proximity weighting. Detects prompt injection, authority claims, credential+exfil combos.
13. **ToxicFlow** (`internal/engine/toxicflow/`) - Single-file source/sink co-occurrence + cross-file capability correlation (`crossfile.go`). Detects dangerous capability combinations within and across files in the same directory. Flat-dir filter (>50 files) prevents FPs on registries.
14. **Rug-Pull** (`internal/engine/rugpull/`) - SHA256-based tool description change detection. CLI via `--monitor`, library via `WithStateDir()`.

**MCP Capability** (`internal/engine/mcpcapability/`) runs after CI Trust.
It owns MCP_009 (HIGH, mcp-attack), parsing literal capability/permission
grants in JSON/YAML rather than matching nearby words. Drops, denies, comments,
opaque strings and sibling fields are not grant evidence. The rule retains
legacy severity/disable overrides; other analyzer override behavior is unchanged.

**Kubernetes Policy** (`internal/engine/kubepolicy/`) runs after MCP Capability.
It shares bounded source-span recognition with SUPPLY_007 through
`internal/kubeconfig`. Explicit SETUID/SETGID additions in recognized workloads
emit `K8S_IDENTITY_CAPABILITIES_001` (LOW, context, container-security).
Only those exact scalars leave SUPPLY_007; commands and unsupported input retain
existing matching. No cluster access, template evaluation or runtime inference.
`Target.PrivilegeAnalysis` shares only immutable spans/classification between the
two consumers. It keeps no YAML tree or global cache, and does not memoize cancelled
parses. Loaded target bytes and paths must remain immutable during analysis.

All sixteen implement the `Analyzer` interface (`internal/scanner/analyzer.go`): `Name() string` + `Analyze(ctx, *Target) ([]Finding, error)`. Fifteen run on every scan; rug-pull only joins when the caller passes `--monitor` (CLI) or `WithStateDir` (library). `aguara check` (`internal/incident/`, `internal/packagecheck/`) is a separate command-line entry point, not part of the scan pipeline.

After per-file analysis, **SkillChain** (`internal/engine/skillchain/`) runs as a
`CrossFileAccumulator`. It binds mandatory execution instructions in
`SKILL.md` to the exact local helper path and emits
`AGENT_FORCED_HELPER_RISK_001` only when that helper contains a strong hidden
behavior. It shares the cross-file group with ToxicFlow but does not implement
the per-file `Analyzer` interface.

### Key Package Relationships

- `internal/types/` - Lowest layer. `Finding`, `Severity`, `ScanResult`. No internal imports. **`Severity` is `type int`, serializes as a number in JSON (0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL), NOT a string.**
- `Finding.DecisionImpact` and catalog `Rule.DecisionImpact` are the trust-decision layer, not a replacement for severity. Unknown and custom rule IDs default to `review`; only explicitly classified context rules may avoid restricting the default audit handoff. Findings remain visible and explicit `--fail-on` gates remain authoritative.
- `internal/rules/` - YAML to CompiledRule. `builtin/` embeds 13 YAML files via `go:embed`.
- `internal/scanner/` - Orchestrator. Discovers files, spawns workers, runs analyzers, applies inline ignore filtering, aggregates results. Imports `meta/` for post-processing.
- `internal/meta/` - Dedup, scoring, correlation. Imports `types/` only (NOT `scanner/` - this prevents import cycles).
- `internal/output/` - Formatters (terminal, JSON, SARIF, markdown) implementing `Formatter` interface. Markdown header is `## Aguara Security Scan`, not `# Aguara Scan Report`.
- `internal/config/` - `.aguara.yml` loader. Supports `disable_rules` list and `rule_overrides` map.
- `discover/` - MCP client auto-discovery. `Scan()`, `FormatTree()`, `FormatMarkdown()`. Public package.
- `cmd/aguara/commands/` - Cobra CLI wiring. Version/Commit injected via ldflags. **Uses global package-level flag vars that leak between tests - always call `resetFlags()` in tests.** `discover` command supports `--format` flag: `terminal` (default, tree), `json`, `markdown`/`md`.

### Import Cycle Constraint

`scanner` -> `meta` -> `types`. The `meta` package must never import `scanner`.

## Rules System

191 rules in `internal/rules/builtin/*.yaml` across 13 files. Each rule requires:

- `id`, `name`, `severity`, `category`, `patterns` (type: `regex` or `contains`)
- `match_mode`: `any` (OR, default) or `all` (AND)
- `remediation`: actionable fix guidance (all 193 rules have this)
- `examples.true_positive` and `examples.false_positive` - **self-tested automatically by `make test`**
- Optional: `targets` (file globs), `exclude_patterns` (context-based suppression)

### Rule Field Placement

The `remediation:` field goes after `match_mode:` (or `category:`/`targets:` if no match_mode) and before `patterns:`.

### Go Regexp Constraint

Go's `regexp` does NOT support lookaheads (`(?!...)`) or lookbehinds. Use `exclude_patterns` or `match_mode: all` with multiple patterns instead. For JSON keys, account for optional quotes: `["']?key["']?`. Max pattern length: 4096 chars (enforced at compile time).

## Testing Notes

- Race detector (`-race`) is mandatory - all tests run with it.
- Integration tests in `internal/scanner/integration_test.go` skip when `testdata/` is absent. Testdata exists locally (1275 files, gitignored) with 10 malicious + 6 benign scenarios.
- NLP classifier uses Go maps - tied scores produce nondeterministic winners. Don't write tests asserting a single winner on tied scores.
- Rule self-tests validate `true_positive` matches and `false_positive` non-matches respecting `match_mode`.
- CLI tests (`cmd/aguara/commands/scan_test.go`) use `scanToFile` helper that writes output to temp file via `-o` flag, since Cobra `SetOut()` doesn't capture output from `writeOutput` which writes to `os.Stdout`.
- Always call `resetFlags()` at the start of each CLI test to avoid global flag state leaking.

## Release Process

1. Create branch `release/vX.Y.Z` from main
2. Update `CHANGELOG.md`
3. Commit, push, create PR, merge
4. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
5. GoReleaser auto-runs: builds binaries, updates Homebrew tap (`garagon/homebrew-tap`), publishes Docker image to `ghcr.io/garagon/aguara`
6. Clean up: delete release branch locally and remotely

## Community Contributions

When reviewing external PRs:
- CI doesn't run on fork PRs (branch protection). Pull locally and run `make build && make test && make vet && make lint` before merging.
- Use `gh pr merge <N> --merge --admin --delete-branch` to bypass branch protection for verified fork PRs.
- After merging rule PRs, update rule count references in README.md, CONTRIBUTING.md, and CLAUDE.md.
- Good-first-issue PRs that close issues will auto-close the linked issues on merge.

## Communication Rules

- Never include `Co-Authored-By: Claude` in commits to this repository.
- Never include "Generated with Claude Code" in PR descriptions.
- Never use em dashes (-) in LinkedIn posts or external communications. Use hyphens (-) instead.
- All commits and PRs are authored entirely under garagon's name.
