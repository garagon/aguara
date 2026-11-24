# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Aguara v0.29.0 (released 2026-11-24): structured capability checks (MCP_009 moved from a YAML rule to the `mcp-capability` analyzer; the new `kube-policy` analyzer reports `K8S_IDENTITY_CAPABILITIES_001`), restored Python cron-write detection in `SC-EX-007`, embedded intelligence from the verified November 23 snapshot (39,337 record rows across eight ecosystems), Go 1.27 release builds, and Go 1.26.0 as the minimum for source builds and library use. Previous release: v0.28.0 (2026-09-10). `CHANGELOG.md` has the details.

Current tree: 259 cataloged detections = 191 YAML pattern rules in 13 files (named after the 13 pattern categories; `INDIRECT_010` in indirect-injection.yaml is categorized command-execution) + 68 analyzer-emitted rules. Categories: the 13 pattern categories plus 4 analyzer-only ones (`toxic-flow`, `agent-trust`, `container-security`, `rug-pull`). 15 per-file analyzers run by default (the pattern matcher plus the 14 in `engine.DefaultAnalyzers`), rug-pull joins with `--monitor`, and a cross-file pass runs toxic-flow and skill-chain correlation. 27 fuzz targets across 16 packages (`make fuzz`, nightly `.github/workflows/fuzz.yml`). `aguara list-rules --format json` on a fresh build is the reference for rule counts.

`aguara check` covers npm/PyPI installed trees, pre-install npm lockfiles (pnpm-lock.yaml, package-lock.json, yarn.lock classic v1 and Berry v2+, text bun.lock; `npm:` aliases resolve to the real package) and Go/Rust/PHP/Ruby/Java/.NET lockfiles and manifests.

Distribution: install.sh (mandatory checksum verification, bounded curl + retry), Homebrew tap, Docker (GHCR, multi-arch `linux/amd64+arm64`, runs as non-root UID 10001, base images digest-pinned, signed at digest with Cosign + SBOM + SLSA provenance attestations), GoReleaser (releases signed via Cosign keyless, SPDX SBOM per archive, `-trimpath` for reproducibility), GitHub Action, go install.

The pattern matcher already uses an Aho-Corasick keyword prefilter. Do not treat pattern-matcher performance as open work unless a pprof profile shows a concrete regression. `cmd/wasm/` is a browser example built with `make wasm` and tested by `.github/workflows/wasm-ui.yml`.

## Build & Test Commands

```bash
make build          # Production binary with version/commit ldflags
make test           # go test -race -count=1 ./...
make lint           # golangci-lint run ./... (CI uses golangci-lint v2.15.0)
make vet            # go vet ./...
make fmt            # gofmt -w .
make run ARGS="scan ./path"  # Development run
make bench          # Library, NLP and scanner benchmarks
make fuzz           # Every Fuzz* target for FUZZTIME (default 10s)

# Lint without a local golangci-lint install
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...

# Single package test
go test -race -count=1 ./internal/rules/...

# Single test function
go test -race -count=1 -run TestFunctionName ./internal/engine/pattern/...

# Benchmarks
go test -bench=. -benchtime=3x ./internal/engine/pattern/
go test -bench=. -benchtime=3x ./internal/engine/nlp/
go test -bench=. -benchtime=3x ./internal/scanner/
```

CI requires: `make build && make test && make vet && make lint` all passing. CI uses Go 1.27.

## Architecture

Aguara is a deterministic static security scanner for AI agent skills, MCP servers, agent and package-manager configuration, CI workflows and dependencies. It calls no LLM and never executes the code it inspects. The minimum Go version is declared in `go.mod` (currently 1.26.0); module `github.com/garagon/aguara`.

Scans and default `check`/`audit` runs are offline: they use the embedded intelligence snapshot and any verified local cache. Network access happens only in these places:

- `aguara update`, and `check --fresh` / `audit --fresh`, download the signed advisory bundle from the `intel-latest` release and verify its Sigstore signature and digests before using it (`--insecure-intel` skips the signature check only when `AGUARA_INSECURE_INTEL=1` is also set).
- `aguara version` queries the GitHub Releases API for a newer release. It is skipped with `--no-update-check`, `AGUARA_NO_UPDATE_CHECK=1`, or when a CI environment is detected.
- `install.sh` and the GitHub Action download release artifacts (not part of the binary).

### Public Library API (`aguara.go`, `options.go`)

Root package re-exports types from `internal/types` (`Severity`, `Finding`, `ScanResult`, `ContextLine`, `Verdict`, `ScanProfile`, `DeduplicateMode` and their constants) and `discover` (`DiscoverResult`, `DiscoveredServer`, `DiscoveredClient`), and defines `RuleOverride`, `RuleInfo`, `RuleDetail` and `ErrIncompleteScan`.

- Package functions: `Scan()`, `ScanContent()`, `ScanContentAs()`, `ListRules()`, `ExplainRule()`, `Discover()`, `NewScanner()`.
- Reusable `*Scanner` methods: `Scan()`, `ScanContent()`, `ScanContentAs()`, `ListRules()`, `ExplainRule()`, `RulesLoaded()`.
- Options: `WithCustomRules`, `WithDisabledRules`, `WithRuleOverrides`, `WithMinSeverity`, `WithWorkers`, `WithIgnorePatterns`, `WithMaxFileSize`, `WithCategory` (ListRules only), `WithToolName`, `WithScanProfile`, `WithDeduplicateMode`, `WithStateDir`, `WithRedaction`, `WithTrustedTargetPolicy`, `WithUntrustedTarget`.

Used by external consumers like `aguara-mcp`. Library scans treat their input as untrusted by default: target-owned `.aguaraignore` files and inline `aguara-ignore` directives are ignored unless the caller passes `WithTrustedTargetPolicy()`. The library never reads `.aguara.yml`. Redaction of sensitive matched text is on by default.

Analyzer wiring is centralized: add an analyzer in `internal/engine/engine.go` (`DefaultAnalyzers` + `RuleMetadata`). The CLI (`buildScanner` in `cmd/aguara/commands/scan.go`) and both library constructors register the pattern matcher first, then `engine.RegisterDefaults`, then rug-pull when a state store is configured. Most analyzers derive emit-site RuleName/Severity/Category from their own `RuleMetadata()` through `rulemeta.Index`. NLP and toxicflow still set rule names at the emit site (NLP uses a per-finding description; the `TOXIC_CROSS_*` names differ from the catalog), so check both places when renaming. The `analyzer` value on findings also differs from the catalog in three cases: pattern findings report `pattern` or `pattern-decoder` (the catalog leaves it empty), NLP reports `nlp-injection` (catalog `nlp`), and cross-file toxic-flow reports `toxicflow-crossfile` (catalog `toxicflow`).

### Analysis Pipeline

Files are processed in parallel by `--workers` goroutines. For each file, the registered analyzers run sequentially in this order; each implements the `Analyzer` interface (`internal/scanner/analyzer.go`): `Name() string` + `Analyze(ctx, *Target) ([]Finding, error)`. An analyzer error makes the scan incomplete (`ErrIncompleteScan`) rather than clean. Rule IDs below come from each analyzer's `RuleMetadata()`; catalog severities are base values, and several analyzers raise severity when extra evidence is present.

1. **Pattern Matcher** (`internal/engine/pattern/`, caller-registered) - Regex/contains matching of the compiled YAML rules (191 built-in plus any `--rules` / `WithCustomRules` rules) behind an Aho-Corasick keyword prefilter. 8 decoders (base64, hex, URL encoding, Unicode escapes, hex escapes, HTML entities, base32, C-style octal escapes) re-scan decoded blobs. Matches inside Markdown code blocks are downgraded one severity level. Confidence is 0.70 to 0.95 depending on the share of the rule's patterns that hit, then adjusted in `internal/meta`. Not part of `DefaultAnalyzers` because it is built from compiled rules (the library reuses a pre-compiled matcher).
2. **CI Trust** (`internal/engine/ci/`, `ci-trust`) - yaml.v3 parser for `.github/workflows/*.yml|*.yaml`. Chain-first: `pull_request_target` pwn-request chains, cache poisoning across the fork/base boundary, OIDC token exposure to install/build/test code, and persisted-credentials checkouts; single weak signals never fire. Emits `GHA_PWN_REQUEST_001`, `GHA_CACHE_001`, `GHA_OIDC_001`, `GHA_CHECKOUT_001`.
3. **MCP Capability** (`internal/engine/mcpcapability/`, `mcp-capability`) - Parses literal capability/permission grants in JSON/YAML (and `.md`/`.txt` snippets) instead of matching nearby words. Drops, denies, comments, opaque strings and sibling fields are not grant evidence. Inputs needing structure analysis are bounded to 2 MiB and 100,000 nodes; exceeding a budget is an analyzer error. Emits `MCP_009` (HIGH, `mcp-attack`), which keeps its former pattern-rule severity/disable override contract; the analyzer is skipped when MCP_009 is disabled.
4. **Kubernetes Policy** (`internal/engine/kubepolicy/`, `kube-policy`) - Shares bounded source-span recognition with SUPPLY_007 through `internal/kubeconfig`. Explicit SETUID/SETGID additions in recognized workloads emit `K8S_IDENTITY_CAPABILITIES_001` (LOW, `container-security`, decision impact `context`). Only those exact scalars leave SUPPLY_007; commands and unsupported input keep existing matching. No cluster access, template evaluation or runtime inference. `Target.PrivilegeAnalysis` shares only immutable spans/classification between the two consumers, keeps no YAML tree or global cache, and does not memoize cancelled parses. Loaded target bytes and paths must remain immutable during analysis.
5. **PkgMeta** (`internal/engine/pkgmeta/`, `pkgmeta`) - JSON parser for `package.json`. Lifecycle scripts paired with git-sourced dependencies, optional git dependencies, publish surfaces reachable from install-time code, lifecycle hooks that run local JavaScript, and npm v12 readiness notes for git/remote-tarball dependencies. Emits `NPM_LIFECYCLE_GIT_001`, `NPM_OPTIONAL_GIT_001`, `NPM_PUBLISH_SURFACE_001`, `SUPPLY_026`, `NPM_GIT_INSTALL_TRUST_001`, `NPM_REMOTE_INSTALL_TRUST_001`.
6. **JSRisk** (`internal/engine/jsrisk/`, `jsrisk`) - Single-pass scanner for `.js`/`.mjs`/`.cjs` (not a JavaScript parser). Obfuscator-shape payloads, detached background execution, CI secret harvesting with a network or registry sink, runner process-memory pivots, Claude Code/VS Code workspace persistence, DNS TXT exfiltration, Bun second stages, GitHub as a payload/command channel, sudoers and host-trust tampering, and destructive wipes. Emits `JS_OBF_001`, `JS_DAEMON_001`, `JS_CI_SECRET_HARVEST_001`, `JS_PROC_MEM_OIDC_001`, `AGENT_PERSISTENCE_001`, `JS_DNS_TXT_EXFIL_001`, `JS_BUN_SECOND_STAGE_001`, `JS_GITHUB_C2_001`, `JS_SUDOERS_TAMPER_001`, `JS_HOST_TRUST_TAMPER_001`, `JS_WIPER_TRIPWIRE_001`.
7. **PyRisk** (`internal/engine/pyrisk/`, `pyrisk`) - Line-based, flow-sensitive scanner for `setup.py`/`__init__.py`. Binds a remote-JS fetch to a `node -e`/`--eval` execution sink (at most 2 hops, taint cleared on safe reassignment). Emits `PY_IMPORTTIME_REMOTE_JS_001` (moved from a co-presence YAML rule in v0.22.0).
8. **RSBuild** (`internal/engine/rsbuild/`, `rsbuild`) - Line-based, flow-sensitive scanner for `build.rs`. Binds a wallet/keystore read to a network send sink (the tainted value must reach a send/body argument; at most 2 hops). Emits `RS_BUILD_WALLET_EXFIL_001` (moved from a co-presence YAML rule in v0.22.0).
9. **NpmPolicy** (`internal/engine/npmpolicy/`, `npm-policy`) - Reads `package.json` (`allowScripts` policy) and project `.npmrc` for npm v12 install-trust weakenings: the `dangerously-allow-all-scripts` escape hatch, unpinned approvals, `allow-git`/`allow-remote` relaxations. Ground-truthed against npm 11.16.0 (deny entries are name-only false and never fire; quoted+comment values are inert; last-wins; empty boolean = true; manifest keys case-sensitive). Emits `NPM_DANGEROUS_ALL_SCRIPTS_001` (HIGH), `NPM_ALLOW_SCRIPTS_UNPINNED_001`, `NPM_ALLOW_GIT_RELAXED_001`, `NPM_ALLOW_REMOTE_RELAXED_001` (MEDIUM), category supply-chain.
10. **PnpmPolicy** (`internal/engine/pnpmpolicy/`, `pnpm-policy`) - yaml.Node parser for `pnpm-workspace.yaml` (exact target, base name only). Flags pnpm supply-chain settings weakened below the v11 defaults; absence of a setting never fires. Only exact camelCase keys match (ground truth pnpm 11.5.2: kebab-case in pnpm-workspace.yaml is silently IGNORED by pnpm - kebab is the .npmrc spelling - so kebab must NOT fire), YAML merge keys expand (visited-set bounded), explicit beats merged, booleans follow pnpm's js-yaml 1.1 loader (yes/no/on/off ARE booleans - do not "fix" to yaml.v3 tags). Emits 9 `PNPM_*` rules (1 HIGH `PNPM_DANGEROUS_BUILDS_001`, 4 MEDIUM, 3 LOW, 1 INFO), all category supply-chain.
11. **AgentPolicy** (`internal/engine/agentpolicy/`, `agent-policy`) - JSON parser for Claude Code `.claude/settings.json` / `settings.local.json` (exact target via `.claude/` path suffix). Flags host config dangerous to inherit from a cloned repo: hooks that fetch-and-execute, code-injection env vars (NODE_OPTIONS --require, LD_PRELOAD, BASH_ENV...), `bypassPermissions`, `enableAllProjectMcpServers`, broad/secret-read allow rules, repo-relative credential helpers. Per-key independent decode (one bad block doesn't blind the rest); absence never fires; fires on dangerous value SHAPE only. Emits 8 `AGENTCFG_*` rules (1 CRITICAL, 2 HIGH, 4 MEDIUM, 1 LOW), category `agent-trust`.
12. **SkillPolicy** (`internal/engine/skillpolicy/`, `skill-policy`) - Bounded `yaml.Node` parser for the real `SKILL.md` frontmatter only. Flags an exact whole-value `allowed-tools` wildcard; body examples, scoped command wildcards, malformed metadata, and similarly named keys stay quiet. Emits `AGENT_SKILL_WILDCARD_TOOLS_001` (MEDIUM, `agent-trust`).
13. **ScriptRisk** (`internal/engine/scriptrisk/`, `script-risk`) - Evidence scanner for local `.py` and `.sh`/`.bash`/`.zsh` scripts. Binds decoded, character-constructed, or remotely fetched Python values to `exec`/`eval`, pairs sensitive local context with a bound HTTP write, detects literal world-writable permission changes, resolves systemd/cron persistence (Python pathlib/subprocess systemd writes and direct `open(...).write(...)` cron writes; shell `systemctl enable`, crontab feeds, user unit files, and payload writes to shell profiles), and flags pip/npm commands that use unencrypted dependency sources. Emits `PY_DECODE_EXEC_001`, `PY_REMOTE_FETCH_EXEC_001`, `PY_CONTEXT_EXFIL_001`, `PY_WORLD_WRITABLE_001`, `SC-EX-007` (migrated from YAML, same ID), `SHELL_UNSAFE_PIP_SOURCE_001`, `SHELL_UNSAFE_NPM_SOURCE_001`.
14. **NLP Analyzer** (`internal/engine/nlp/`, `nlp`) - Goldmark AST walker for markdown (`.md`, `.markdown`, `.txt` and agent instruction files such as `AGENTS.md` or `.cursorrules`); JSON/YAML string extractor for structured files. Keyword classification with proximity weighting. Emits `NLP_HEADING_MISMATCH`, `NLP_AUTHORITY_CLAIM`, `NLP_CRED_EXFIL_COMBO`, `NLP_HIDDEN_INSTRUCTION`, `NLP_CODE_MISMATCH`, `NLP_OVERRIDE_DANGEROUS`.
15. **ToxicFlow** (`internal/engine/toxicflow/`, `toxicflow`) - Single-file capability co-occurrence (private data read, public output, code execution, destructive action). Emits `TOXIC_001`, `TOXIC_002`, `TOXIC_003`. Its cross-file half runs in the cross-file pass below.
16. **Rug-Pull** (`internal/engine/rugpull/`, `rugpull`, optional) - SHA256-based change detection on scanned files: a changed file whose new content matches a dangerous pattern emits `RUGPULL_001` (CRITICAL). Registered only with `--monitor` (CLI) or `WithStateDir()` (library); its rule is always in the catalog.

After every file has been analyzed, the cross-file accumulator group set by `RegisterDefaults` finalizes, in this order:

- **ToxicFlow cross-file** (`internal/engine/toxicflow/crossfile.go`) - Correlates capabilities across files in the same directory. Directories with more than 50 files are treated as flat registries and skipped to avoid false positives. Emits `TOXIC_CROSS_001`, `TOXIC_CROSS_002`, `TOXIC_CROSS_003`.
- **SkillChain** (`internal/engine/skillchain/`, `skill-chain`) - Binds mandatory execution instructions in `SKILL.md` to the exact local helper path and emits `AGENT_FORCED_HELPER_RISK_001` (HIGH, `agent-trust`) only when that helper contains a strong hidden behavior. It implements `CrossFileAccumulator`, not the per-file `Analyzer` interface.

`aguara check` (`internal/incident/`, `internal/packagecheck/`, `internal/intel/`) is a separate entry point, not part of the scan pipeline; `aguara audit` runs check and scan together and produces one verdict.

### Key Package Relationships

- `internal/types/` - Lowest layer. `Finding`, `Severity`, `ScanResult`. No internal imports. **`Severity` is `type int`, serializes as a number in JSON (0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL), NOT a string.**
- `Finding.DecisionImpact` and catalog `Rule.DecisionImpact` are the trust-decision layer, not a replacement for severity. Unknown and custom rule IDs default to `review`; only explicitly classified context rules may avoid restricting the default audit handoff. Findings remain visible and explicit `--fail-on` gates remain authoritative.
- `internal/rules/` - YAML to CompiledRule. `builtin/` embeds 13 YAML files via `go:embed`.
- `internal/rulemeta/`, `internal/rulecatalog/` - Analyzer rule metadata, decision impact, and the unified catalog behind `list-rules` / `explain` / `ListRules`.
- `internal/scanner/` - Orchestrator. Discovers files, spawns workers, runs analyzers, applies inline ignore filtering, aggregates results. Imports `meta/` for post-processing.
- `internal/meta/` - Dedup, scoring, correlation. Imports `types/` only (NOT `scanner/` - this prevents import cycles).
- `internal/output/` - Formatters (terminal, JSON, SARIF, markdown) implementing `Formatter` interface. Markdown header is `## Aguara Security Scan`, not `# Aguara Scan Report`.
- `internal/config/` - `.aguara.yml` loader, read only from the scan root (no parent-directory lookup; symlinked or >1 MB files are rejected). Keys: `ignore`, `severity`, `fail_on`, `format`, `rules`, `disable_rules`, `rule_overrides` (per rule: `severity`, `disabled`, `apply_to_tools`, `exempt_tools`), `max_file_size`, `baseline`. `paths` is parsed but not used by the CLI. `rule_overrides` severity/disable changes apply to pattern rules and MCP_009; disable other analyzer rules with `disable_rules`.
- `internal/packagecheck/`, `internal/incident/`, `internal/intel/` - Lockfile parsers, compromised-package checks and cleanup, and the intel snapshot with signed-bundle verification (`intel/bundle`).
- `discover/` - MCP client auto-discovery. `Scan()`, `FormatTree()`, `FormatMarkdown()`. Public package.
- `cmd/aguara/commands/` - Cobra CLI wiring. Version/Commit injected via ldflags. **Uses global package-level flag vars that leak between tests - always call `resetFlags()` in tests.** `discover` command supports `--format` flag: `terminal` (default, tree), `json`, `markdown`/`md`.

### Project-Owned Policy

Since v0.28.0, files in the scanned project cannot silently change what a security review sees unless the caller trusts them. Project-owned policy means `.aguara.yml`, `.aguaraignore` and inline `aguara-ignore` directives.

- `scan` defaults to `--project-policy auto`: trusted for a local scan, ignored with `--ci` and with `--auto`.
- `audit` ignores project policy by default (`--project-policy trust` opts in).
- The GitHub Action passes `--project-policy ignore`.
- The library ignores `.aguaraignore` and inline directives unless `WithTrustedTargetPolicy()` is set, and never reads `.aguara.yml`.

When project policy is ignored, `.aguara.yml` is not loaded at all. Caller-supplied flags and options (`--disable-rule`, `--rules`, `WithIgnorePatterns`, ...) still apply.

### Import Cycle Constraint

`scanner` -> `meta` -> `types`. The `meta` package must never import `scanner`.

## Rules System

191 rules in `internal/rules/builtin/*.yaml` across 13 files. Each rule requires:

- `id`, `name`, `severity`, `category`, `patterns` (type: `regex` or `contains`)
- `match_mode`: `any` (OR, default) or `all` (AND)
- `remediation`: actionable fix guidance (all 191 built-in rules have this)
- `examples.true_positive` and `examples.false_positive` - **self-tested automatically by `make test`**
- Optional: `targets` (file globs), `exclude_patterns` (context-based suppression)

When a detection moves from YAML into an analyzer, keep the rule ID (as with `PY_IMPORTTIME_REMOTE_JS_001`, `RS_BUILD_WALLET_EXFIL_001`, `SC-EX-007` and `MCP_009`) and update `RULES.md` and the counts in `README.md`, `CONTRIBUTING.md` and this file.

### Rule Field Placement

The `remediation:` field goes after `match_mode:` (or `category:`/`targets:` if no match_mode) and before `patterns:`.

### Go Regexp Constraint

Go's `regexp` does NOT support lookaheads (`(?!...)`) or lookbehinds. Use `exclude_patterns` or `match_mode: all` with multiple patterns instead. For JSON keys, account for optional quotes: `["']?key["']?`. Max pattern length: 4096 chars (enforced at compile time).

## Testing Notes

- Race detector (`-race`) is mandatory - all tests run with it.
- Integration tests in `internal/scanner/integration_test.go` read 10 malicious and 6 benign scenarios from a root `testdata/` directory. That directory is gitignored and not part of a clone; the tests skip when it is absent. Committed fixtures live under each package's own `testdata/` (for example `internal/packagecheck/testdata/`).
- Fuzz seed corpora run as part of `make test`; time-budgeted fuzzing runs only through `make fuzz` and the nightly fuzz workflow. Do not start long fuzzing or benchmark runs without being asked.
- Scan results are deterministic: findings are sorted by severity, path, line, column, rule ID and analyzer; the NLP classifier walks categories in a fixed order (`categoryOrder`, the earlier category wins a tied score); NLP JSON extraction visits object keys in sorted order; cross-file toxic-flow pairs are chosen in path order. Do not reintroduce map iteration into anything that selects or orders findings. `aguara_determinism_test.go` scans the same inputs repeatedly and requires byte-identical JSON.
- Rule self-tests validate `true_positive` matches and `false_positive` non-matches respecting `match_mode`.
- CLI tests (`cmd/aguara/commands/scan_test.go`) use the `scanToFile` helper, which writes output to a temp file via the `-o` flag, because report output goes to `os.Stdout` directly and Cobra `SetOut()` does not capture it.
- Always call `resetFlags()` at the start of each CLI test to avoid global flag state leaking.

## Release Process

1. Create branch `release/vX.Y.Z` from main. Commit the version pins (`cmd/aguara/commands/init.go` scaffold, `action.yml` `DEFAULT_REF`, `Makefile` `INSTALL_SH_TEST_VERSION`, README install snippets and version references) and the `CHANGELOG.md` entry for the release.
2. Run `VERSION=vX.Y.Z .github/scripts/check-version-pins.sh` until it exits 0.
3. Push the branch, open the release PR, and merge it once CI passes.
4. Create an annotated tag on the merge commit and push it: `git tag -a vX.Y.Z -m "Aguara vX.Y.Z" <merge-commit> && git push origin vX.Y.Z`.
5. The tag starts two workflows:
   - `.github/workflows/release.yml` runs GoReleaser (`.goreleaser.yml`): linux/darwin/windows amd64+arm64 archives built with `-trimpath`, `checksums.txt` signed with Cosign keyless (`checksums.txt.bundle`), an SPDX SBOM per archive (syft), the Homebrew formula in `garagon/homebrew-tap`, and a GitHub-native changelog as the release body.
   - `.github/workflows/docker.yml` builds the multi-arch image, pushes it to `ghcr.io/garagon/aguara` with SBOM and SLSA provenance attestations, and signs it at its digest with Cosign.
6. Run `VERSION=vX.Y.Z .github/scripts/verify-release.sh` from a clean machine: it verifies the checksum signature and archive hash, runs the binary, verifies the image signature, runs the image on the host architecture, and checks its SBOM and provenance. Do not announce the release before it passes.
7. Replace the generated release body with written release notes (`gh release edit vX.Y.Z --notes-file <file>`); the release body is not a copy of `CHANGELOG.md`.
8. Delete the release branch locally and remotely.

## Community Contributions

When reviewing external PRs:
- CI checks do not run automatically on PRs from forks. Pull the branch locally and run `make build && make test && make vet && make lint` before merging.
- Use `gh pr merge <N> --merge --admin --delete-branch` to bypass branch protection for verified fork PRs.
- After merging rule PRs, update rule count references in README.md, CONTRIBUTING.md, RULES.md, and CLAUDE.md.
- Good-first-issue PRs that close issues will auto-close the linked issues on merge.

## Communication Rules

- Never include `Co-Authored-By: Claude` in commits to this repository.
- Never include "Generated with Claude Code" in PR descriptions.
- Never use em dashes (U+2014) in commits, PR text, release notes, documentation or other external communication. Use a plain hyphen (-) instead.
- All commits and PRs are authored entirely under garagon's name.
