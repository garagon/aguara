# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Aguara v0.15.0 (2026-05-13). 193 rules, 13 categories, 7 scan analyzers (pattern, ci-trust, pkgmeta, jsrisk, NLP, toxicflow, rugpull) plus the `aguara check --ecosystem {python,npm}` incident command, ~750 tests, 0 lint issues.

Distribution: install.sh (mandatory checksum verification, bounded curl + retry), Homebrew tap, Docker (GHCR, multi-arch `linux/amd64+arm64`, runs as non-root UID 10001, base images digest-pinned, signed at digest with Cosign + SBOM + SLSA provenance attestations), GoReleaser (releases signed via Cosign keyless, SPDX SBOM per archive, `-trimpath` for reproducibility), GitHub Action, go install.

GitHub: 48 stars, 6 forks. 0 open PRs, 0 open issues. 7 awesome-list PRs pending review in external repos. 7 forks on garagon account (pending cleanup after awesome-list PRs resolve).

Pattern matcher already uses an Aho-Corasick keyword prefilter (active in production since v0.14.0). Real perf is ~210ms/op on the synthetic bench (was ~770ms without AC), so do not treat "pattern matcher perf" as an open backlog item unless pprof shows a concrete regression. Pending improvements: WASM build (cmd/wasm/ incomplete), adoption/marketing.

Internal docs (gitignored) in `DOCS/` as an Obsidian vault. See `DOCS/Aguara/CONVENTIONS.md` for vault rules and `DOCS/Aguara/00 Dashboard.md` for the entry point.

Key locations:
- Dashboard (MOC): `DOCS/Aguara/00 Dashboard.md`
- Conventions: `DOCS/Aguara/CONVENTIONS.md` - frontmatter schema, types, statuses, tags, naming
- Product versions: `DOCS/Aguara/product/v0.10.0/_index.md` (version hub with links to all generated content; v0.11.0–v0.14.0 hubs not yet created)
- Distribution channels: `DOCS/Aguara/distribution/<channel>/_index.md` (each has submission log)
- Growth plan: `DOCS/Aguara/product/roadmap.md`
- Templates: `DOCS/Aguara/templates/` (channel.md, product-version.md)
- Demo video project: `/Users/dev/Dev/videos/aguara-demo/` (Remotion, React-based)
- Oktsec docs (separate project): `DOCS/Oktsec/`

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

Aguara is a deterministic static security scanner for AI agent skills and MCP servers. No LLM, no network calls. Go 1.25, module `github.com/garagon/aguara`.

### Public Library API (`aguara.go`, `options.go`)

Root package re-exports types from `internal/types` and exposes: `Scan()`, `ScanContent()`, `ListRules()`, `ExplainRule()`, `Discover()`. Used by external consumers like `aguara-mcp`. Functional options pattern (`WithMinSeverity()`, `WithWorkers()`, etc.).

### Analysis Pipeline (6 default analyzers + rug-pull when --monitor is set, run sequentially per file)

1. **Pattern Matcher** (`internal/engine/pattern/`) - Regex/contains matching against compiled rules. 8 decoders (base64, hex, URL encoding, Unicode escapes, HTML entities, hex escapes, base32, C-style octal escapes) for encoded evasion detection. Markdown code-block severity downgrade. Dynamic confidence based on pattern hit ratio.
2. **CI Trust** (`internal/engine/ci/`) - YAML parser for `.github/workflows/*.yml`. Detects `pull_request_target` pwn-request chains, cache poisoning, OIDC token surface, and persisted-credentials checkouts. Emits `GHA_PWN_REQUEST_001` / `GHA_CACHE_001` / `GHA_OIDC_001` / `GHA_CHECKOUT_001`.
3. **PkgMeta** (`internal/engine/pkgmeta/`) - JSON parser for `package.json`. Detects npm install-time lifecycle scripts paired with git-sourced dependencies, optional-git deps, and publish-surface chains. Emits `NPM_LIFECYCLE_GIT_001` / `NPM_OPTIONAL_GIT_001` / `NPM_PUBLISH_SURFACE_001`.
4. **JSRisk** (`internal/engine/jsrisk/`) - Single-pass JavaScript scanner for `.js`/`.mjs`/`.cjs`. Detects obfuscator-shape payloads, install-time daemonization, CI secret harvesting, runner process-memory pivots, and Claude Code/VS Code persistence. Emits `JS_OBF_001` / `JS_DAEMON_001` / `JS_CI_SECRET_HARVEST_001` / `JS_PROC_MEM_OIDC_001` / `AGENT_PERSISTENCE_001`.
5. **NLP Analyzer** (`internal/engine/nlp/`) - Goldmark AST walker for markdown; JSON/YAML string extractor for structured files. Keyword classification with proximity weighting. Detects prompt injection, authority claims, credential+exfil combos.
6. **ToxicFlow** (`internal/engine/toxicflow/`) - Single-file taint tracking + cross-file correlation (`crossfile.go`). Detects dangerous capability combinations within and across files in the same directory. Flat-dir filter (>50 files) prevents FPs on registries.
7. **Rug-Pull** (`internal/engine/rugpull/`) - SHA256-based tool description change detection. CLI via `--monitor`, library via `WithStateDir()`.

All seven implement the `Analyzer` interface (`internal/scanner/analyzer.go`): `Name() string` + `Analyze(ctx, *Target) ([]Finding, error)`. The first six run on every scan; rug-pull only joins when the caller passes `--monitor` (CLI) or `WithStateDir` (library). `aguara check --ecosystem npm` (`internal/incident/npm.go`) is a separate command-line entry point, not part of the scan pipeline.

### Key Package Relationships

- `internal/types/` - Lowest layer. `Finding`, `Severity`, `ScanResult`. No internal imports. **`Severity` is `type int`, serializes as a number in JSON (0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL), NOT a string.**
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

193 rules in `internal/rules/builtin/*.yaml` across 13 files. Each rule requires:

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

## Obsidian Vault Workflow (DOCS/Aguara/)

The `DOCS/Aguara/` directory is an Obsidian vault. Claude Code must follow `CONVENTIONS.md` when creating or editing docs.

### Working with the vault

1. **Start from the Dashboard**: Read `DOCS/Aguara/00 Dashboard.md` to understand current state.
2. **Follow CONVENTIONS.md**: Every `.md` file needs frontmatter (type, tags, status, dates). Read `DOCS/Aguara/CONVENTIONS.md` before creating files.
3. **Use templates**: Copy from `DOCS/Aguara/templates/` when creating new channels or product versions.
4. **Use wikilinks**: Link between docs with `[[path/to/file]]` syntax (Obsidian-style).

### Automatic checklist and status tracking

When completing a distribution task (submitting a post, publishing a blog, opening a PR):
1. **Update the submission log** in the channel's `_index.md` - add a row with date, action, status, URL.
2. **Update frontmatter status** - change `status: ready` to `status: published`, add `published_url:` and `posted: YYYY-MM-DD`.
3. **Update the Dashboard** - mark the channel as done in the Distribution table (`00 Dashboard.md`).
4. **Update the version hub** - if content was for a specific version, confirm links in `product/vX.Y.Z/_index.md`.

When completing a product task (fixing a bug, adding a feature, releasing a version):
1. **Update Dashboard metrics** - star count, rule count, test count, coverage.
2. **Update CLAUDE.md** - if rule count, test count, or version changes.
3. **Create status file** - `product/vX.Y.Z/status-YYYY-MM-DD.md` for significant milestones.

### Data consistency rule

When any of these values change, update ALL references across the vault:
- Rule count (currently 193)
- Test count (currently ~750)
- Coverage (currently 80%)
- Star/fork count (currently 48/6)
- Watch skill count (currently 28,000+)
- Version number (currently v0.15.0)

Use `Grep` to find all occurrences before updating.

### Content generation workflow

All external content (blog posts, social media, Reddit, newsletters) MUST go through this 4-stage pipeline:

1. **Literature Scout** - Research what already exists on the topic. Check competitor tools, recent posts in the target community, trending discussions. Identify gaps and angles that haven't been covered.
2. **Cybersecurity Analyzer** - Validate every technical claim against the actual codebase. Cross-reference rule IDs, analysis layers, detection capabilities. No exaggeration, no hand-waving.
3. **Research Cybersecurity** - Ground the content in real threat models, CVEs, attack patterns, or published research. Link claims to concrete examples (e.g., specific prompt injection techniques, real supply chain attacks).
4. **Editor** - Final pass for tone and quality. Must read like a human wrote it - natural, accessible, didactic. No AI patterns ("leverage", "utilize", "robust", "cutting-edge", "seamlessly", "game-changing", "in today's landscape"). No em-dashes. No filler. Direct, technical, conversational.

Content must pass ALL four stages before being marked `status: ready`.

### Review checklist (before publishing any content)

- [ ] Data check: rule count, test count, star count, Watch skill count are current
- [ ] Technical accuracy: claims match actual implementation
- [ ] No AI patterns: no "leverage", "utilize", "robust", "cutting-edge", "game-changing"
- [ ] No em-dashes: use hyphens (-) not em-dashes
- [ ] Natural voice: reads like a person wrote it
- [ ] Links work: GitHub URLs, Watch URL, install commands are correct

## Growth & Visibility

- **Awesome list PRs**: Create fork -> PR -> delete fork immediately after merge/close (keep garagon account clean). Currently 7 forks + 7 open PRs across external repos.
- **punkpeye awesome-mcp repos** use emoji format: `🏎️` (Go), `🏠` (local), `🍎🪟🐧` (OS).
- **wong2/awesome-mcp-servers** does NOT accept PRs - must use mcpservers.org/submit web form.
- **GitHub topics**: 15 keywords max useful for SEO.
- **OpenAlternative.co / OpenSourceAlternative.to**: Don't accept CLIs. Descartados.
- **awesome-go**: Blocked until July 2026 (requires 5-month repo age). Also needs Codecov badge integration.
- **Official MCP Registry**: Only accepts npm/TypeScript packages. Not applicable for Go.
- Distribution channels with submission tracking: `DOCS/Aguara/distribution/`.
- Demo video: Remotion project at `/Users/dev/Dev/videos/aguara-demo/`. Terminal segments recorded with VHS (charmbracelet/vhs), slides as React components, rendered with `npx remotion render AguaraDemo output.mp4`.

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
