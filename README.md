<p align="center">
  <h1 align="center">Aguara</h1>
  <p align="center">
    Security scanner for AI agents and software supply chains.
    <br />
    Aguara checks the trust points modern projects rely on: dependencies, lockfiles, install scripts, CI workflows, MCP configs, and AI agent tools.
  </p>
</p>

<p align="center">
  <a href="https://github.com/garagon/aguara/actions/workflows/ci.yml"><img src="https://github.com/garagon/aguara/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/garagon/aguara"><img src="https://goreportcard.com/badge/github.com/garagon/aguara" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/garagon/aguara"><img src="https://pkg.go.dev/badge/github.com/garagon/aguara.svg" alt="Go Reference"></a>
  <a href="https://github.com/garagon/aguara/releases"><img src="https://img.shields.io/github/v/release/garagon/aguara" alt="GitHub Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/garagon/aguara" alt="License"></a>
  <a href="https://github.com/garagon/aguara/stargazers"><img src="https://img.shields.io/github/stars/garagon/aguara?style=flat" alt="GitHub Stars"></a>
  <a href="https://github.com/garagon/aguara/blob/main/Dockerfile"><img src="https://img.shields.io/badge/docker-ghcr.io%2Fgaragon%2Faguara-blue?logo=docker" alt="Docker"></a>
  <a href="#installation"><img src="https://img.shields.io/badge/homebrew-garagon%2Ftap-orange" alt="Homebrew"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-aguara-checks">What Aguara Checks</a> &bull;
  <a href="#supply-chain-check">Supply-Chain Check</a> &bull;
  <a href="#ai-agent-and-mcp-security">AI Agent & MCP Security</a> &bull;
  <a href="#ci-integration">CI Integration</a> &bull;
  <a href="#rules">Rules</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

https://github.com/user-attachments/assets/851333be-048f-48fa-aaf3-f8cc1d4aa594

**Local-first. No SaaS account. No telemetry. No LLM calls. Signed releases.**

## Why Aguara?

Supply-chain attacks are not just vulnerabilities in your code. They often arrive through something your project is about to trust: a dependency version, an install script, a lockfile entry, a CI workflow, or an agent tool.

Security reviews used to focus mostly on application code. Modern projects also depend on package registries, lockfiles, install scripts, CI workflows, MCP servers, and AI agent tools. Recent supply-chain incidents have shown the pattern: a legitimate package publishes a malicious version, a project installs it, and the attacker gets a chance to steal tokens, cloud credentials, CI secrets, or local files.

Aguara gives teams a local check before they trust those inputs:

- before running `pnpm install` on a pnpm project (Aguara reads `pnpm-lock.yaml` directly)
- before letting CI execute install-time scripts
- before accepting a new MCP server config
- before letting an agent use a third-party skill or tool
- before uploading findings to a code-scanning dashboard

For dependencies, Aguara reads resolved lockfiles where it has parsers (today this is `pnpm-lock.yaml` plus Go / Rust / PHP / Ruby / Java / .NET lockfiles) and installed package trees otherwise. Plain npm with only `package-lock.json` / `yarn.lock` and no install is on the next-layer list, not shipping today.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install garagon/tap/aguara
```

### Docker

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/garagon/aguara:0.18.3 check /repo
```

The image is multi-arch (`linux/amd64` and `linux/arm64`), runs as non-root UID 10001, base images are digest-pinned, and the image is signed at the digest with Cosign plus SPDX SBOM and SLSA provenance attestations. Tag a specific release for reproducibility.

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh \
  | VERSION=v0.18.3 sh
```

`install.sh` downloads `checksums.txt` from the release and verifies the archive's SHA256 against it, aborting if neither `sha256sum` nor `shasum` is available. This catches a tampered or corrupted archive at the registry layer, but it does not verify the Cosign signature on `checksums.txt` itself. For full keyless-signature verification on the curl-pipe path, follow up with the Cosign step in [Verifying signed releases](#verifying-signed-releases). Default install location is `~/.local/bin`. Override for CI or containers:

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh \
  | VERSION=v0.18.3 INSTALL_DIR=/usr/local/bin sh
```

### From source

```bash
go install github.com/garagon/aguara/cmd/aguara@latest
```

Requires Go 1.25+. Binaries built this way report `dev` version metadata because Go does not inject release ldflags. For signed releases use Homebrew, Docker, or the install script above.

Pre-built binaries for Linux, macOS, and Windows are also on the [Releases page](https://github.com/garagon/aguara/releases).

### Verifying signed releases

Every release is signed with [Cosign](https://github.com/sigstore/cosign) keyless, ships an SPDX SBOM per archive, and is built with `-trimpath` for reproducibility. The container image is signed at the digest and carries SBOM + SLSA provenance attestations.

**Verify the release archive**:

```bash
VERSION=v0.18.3
ARCHIVE=aguara_${VERSION#v}_linux_amd64.tar.gz

curl -fsSLO https://github.com/garagon/aguara/releases/download/${VERSION}/${ARCHIVE}
curl -fsSLO https://github.com/garagon/aguara/releases/download/${VERSION}/checksums.txt
curl -fsSLO https://github.com/garagon/aguara/releases/download/${VERSION}/checksums.txt.bundle

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/garagon/aguara/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

sha256sum --check --ignore-missing checksums.txt
```

**Verify the container image**:

```bash
cosign verify ghcr.io/garagon/aguara:${VERSION#v} \
  --certificate-identity "https://github.com/garagon/aguara/.github/workflows/docker.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

**Inspect the SBOM and provenance**:

```bash
# Release archive SBOM (SPDX 2.3)
curl -fsSL https://github.com/garagon/aguara/releases/download/${VERSION}/${ARCHIVE}.sbom.json | jq .

# Container image SBOM and SLSA build provenance.
# docker/build-push-action publishes these as BuildKit attestation manifests
# (in-toto / SLSA spec) attached to the OCI image index, not as cosign
# attestations. Use `docker buildx imagetools inspect` to read them:
docker buildx imagetools inspect ghcr.io/garagon/aguara:${VERSION#v} \
  --format '{{ json .SBOM }}' | jq .
docker buildx imagetools inspect ghcr.io/garagon/aguara:${VERSION#v} \
  --format '{{ json .Provenance }}' | jq .
```

## Quick Start

Check whether the current project depends on a known compromised package:

```bash
aguara check .
```

Run the full project audit for CI:

```bash
aguara audit . --ci
```

Scan AI agent skills, prompts, and MCP-related files:

```bash
aguara scan .claude/skills/ --ci
```

Discover MCP client configs on the machine:

```bash
aguara discover
```

Refresh local threat intel when you want network access:

```bash
aguara update
aguara check . --fresh
```

By default, all checks use the threat-intel snapshot embedded in the binary. Network access is opt-in through `aguara update` or `--fresh`.

## What Aguara Checks

| Surface | Examples | Command |
|---|---|---|
| Dependencies | npm, pnpm, PyPI, Go, Rust, PHP, Ruby, Java, .NET | `aguara check .` |
| AI agent files | skills, prompts, tool descriptions | `aguara scan <path>` |
| MCP configs | Claude Desktop, Cursor, VS Code, Cline, others | `aguara discover`, `aguara scan --auto` |
| CI workflows | GitHub Actions trust-chain risks | `aguara scan .github/workflows` |
| Combined audit | dependencies + content scan | `aguara audit . --ci` |

## Supply-Chain Check

`aguara check .` answers a practical question: "Does this project depend on a package version that is already known to be malicious?"

It checks two real-world states:

1. **Before install**, when resolved versions are present in lockfiles such as `pnpm-lock.yaml`, `go.sum`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, Maven/Gradle files, or NuGet files.
2. **After install**, when packages are already present in trees such as `node_modules`, pnpm's `.pnpm` store, or Python `site-packages`.

This lets teams catch known malicious packages before executing install-time code, and audit existing projects or CI workspaces that may already contain compromised versions.

Aguara compares package names and versions against an embedded threat-intel snapshot built from [OSV.dev](https://osv.dev), [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages), and a short hand-curated list of high-priority emergency advisories. The snapshot ships inside the binary; network access is opt-in through `aguara update` or `--fresh`.

### `aguara check`: am I exposed?

```bash
# Run from a repo root. Aguara finds installed npm and Python
# environments AND lockfiles for every supported ecosystem recursively
# under the path, then matches every declared package against the
# snapshot.
aguara check .

# Refresh threat intel from OSV first, then check. The only check
# mode that uses the network; the rest stay offline. --fresh
# refreshes only the ecosystems the plan actually touches.
aguara check --fresh

# CI gate: --fail-on critical, no color, exit 1 on compromised packages
aguara check --ci

# Constrain to specific ecosystems (repeatable or comma-separated)
aguara check --ecosystem go,ruby
aguara check --ecosystem maven --ecosystem nuget

# Machine-readable
aguara check --format json
```

For pnpm projects, Aguara reads `pnpm-lock.yaml` directly. You do not need to run `pnpm install` first:

```bash
git clone <pnpm-repo>
cd <pnpm-repo>
aguara check .
```

### Coverage by ecosystem

| Ecosystem | Evidence read | Coverage |
|---|---|---|
| npm | `node_modules`, pnpm `.pnpm` store, `pnpm-lock.yaml` | Strong malicious-package coverage. `pnpm-lock.yaml` works before install. |
| PyPI | `site-packages`, `.pth`, pip/uv/npx caches | Strong malicious-package + persistence coverage. |
| RubyGems | `Gemfile.lock` | Strong malicious-package coverage. |
| NuGet | `packages.lock.json`, `*.csproj`, `*.fsproj`, `*.vbproj` | Strong exact-version malicious-package coverage. |
| Go | `go.sum`, `go.mod` | Parser ready; limited exact-version embedded matches today. |
| crates.io | `Cargo.lock` (public registry only) | Parser ready; range-aware OSV matching deferred. |
| Packagist | `composer.lock` | Parser ready; range-aware OSV matching deferred. |
| Maven | `pom.xml`, `gradle.lockfile`, `gradle/dependency-locks/*` | Parser ready; range-aware OSV matching deferred. |

Aguara is not a full SCA scanner yet. It focuses on known malicious-package records and high-confidence advisories. General CVE/range matching is the next layer.

What `aguara check` also catches when the path includes a Python environment:

- **`.pth` files with executable code** (import, subprocess, exec, eval)
- **pip/uv/npx caches** so a compromised package in the cache surfaces even without a virtualenv (Python and npm only)
- **Persistence backdoors** (systemd user services, sysmon artifacts)
- **Credential files at risk** (SSH, AWS, K8s, git, npm, PyPI, databases)

### Auto-detection rules

In order:

- If the path is or contains `node_modules`, run the installed-tree npm check (covers both flat `node_modules/<pkg>` and pnpm's `.pnpm` store).
- Walk the path recursively for lockfiles (`pnpm-lock.yaml`, `go.sum`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pom.xml`, `gradle.lockfile`, `gradle/dependency-locks/*.lockfile`, `packages.lock.json`, `*.csproj`/`*.fsproj`/`*.vbproj`). Skip `.git/`, `vendor/`, `node_modules/`, `.aguara/`, `target/`, `bin/`, `obj/`, `.gradle/`.
- If the explicit `--path` looks like a Python install (`site-packages` / `dist-packages` basename, or contains `*.dist-info`), run the Python check.
- If `aguara check` runs with no flags and no signals are found, fall back to global Python `site-packages` autodiscovery (legacy behaviour).

An explicit `--path` with no signals returns a clean result with `"ecosystems": []` and never silently falls back to the host's global Python.

### `aguara audit`: code AND packages, one verdict

```bash
aguara audit          # check + scan on the current directory
aguara audit --ci     # CI gate: --fail-on critical, no color
aguara audit --fresh  # refresh intel, then audit
```

`aguara audit` composes the supply-chain check and the content scan into a single verdict. JSON output carries both sub-results (`.check` and `.scan`) plus per-section counts so a dashboard can drill into either side.

### `aguara status`: is my threat intel fresh?

```bash
aguara status
```

Prints the Aguara version, the embedded snapshot's generated-at date and record count, and whether a local cached snapshot exists from a prior `aguara update` run. Does no network I/O.

### `aguara update`: refresh intel for future offline checks

```bash
aguara update                       # fetch every supported ecosystem, cache locally
aguara update --ecosystem npm       # just npm
aguara update --ecosystem go,ruby   # scope to Go + RubyGems
```

`aguara update` and `--fresh` are the only commands that use the network. The default refreshes every ecosystem the registry supports (npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven, NuGet); scope with `--ecosystem` (repeatable or comma-separated). The refreshed cache lives at `~/.aguara/intel/snapshot.json`; subsequent `aguara check` runs layer it over the embedded snapshot automatically and stay offline.

`aguara check --fresh` refreshes only the ecosystems the plan actually touches, so `aguara check --fresh --ecosystem maven` does not pull npm, PyPI, or the other six.

If a refresh returns zero records (upstream outage, schema shift), the update is refused so cached intel cannot be silently wiped. Pass `--allow-empty` to override during initial bootstrap.

### `aguara clean`: quarantine compromised Python packages

> `aguara clean` is scoped to Python packages and persistence cleanup today. Multi-ecosystem remediation is deferred.

```bash
aguara clean                       # interactive confirmation
aguara clean --yes --purge-caches  # non-interactive, also purge pip/uv caches
aguara clean --dry-run             # preview
```

Files are quarantined to `/tmp/aguara-quarantine/`, not deleted. After cleaning, Aguara prints a credential rotation checklist for every credential file present on the system.

### Advanced: explicit ecosystem and path

Use these when auto-detection cannot find the environment you want to check:

```bash
aguara check --ecosystem python --path /opt/venv/lib/python3.12/site-packages/
aguara check --ecosystem npm --path ./node_modules
```

### Threat-intel sources

The embedded snapshot is built from two sources:

- **Manual**: a short hand-curated list of high-priority emergency advisories. Takes display precedence when an advisory ID also appears in OSV.
- **OSV.dev**: high-confidence records only. OpenSSF Malicious Packages IDs (the `MAL-` namespace), records with `database_specific.malicious-packages-origins`, plus keyword-qualified records that carry exact affected versions. Generic CVE / DoS records are filtered out at import time so Aguara stays focused on malicious packages, not general SCA.

## AI Agent and MCP Security

Aguara also scans the files that agents and MCP clients consume directly:

- prompt injection and instruction override attempts
- tool poisoning in tool descriptions and configs
- unsafe MCP command definitions
- hardcoded secrets and credential leaks
- webhook, DNS, and file-based exfiltration
- unsafe GitHub Actions trust-chain patterns
- Unicode and encoded payload evasion

```bash
# Scan a skills directory or any path
aguara scan .claude/skills/

# Discover and scan every MCP config on this machine
aguara scan --auto

# Scan a CI workflow surface
aguara scan .github/workflows/
```

Aguara auto-detects MCP configurations across **17 clients**: Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw, OpenCode, Zed, Amp, Gemini CLI, Copilot CLI, Amazon Q, Claude Code, Roo Code, Kilo Code, BoltAI, and JetBrains.

```bash
# List all detected MCP configs
aguara discover

# JSON output (sensitive env values are automatically redacted)
aguara discover --format json
```

## CI Integration

### GitHub Action

```yaml
- uses: garagon/aguara@v0.18.3
  with:
    path: .
    fail-on: high
    version: v0.18.3
```

Both pins (the action ref AND the `version:` input) are required. The action ref alone pins only the composite action and its install script; `version:` pins the Aguara binary the action installs. Setting both makes the workflow reproducible and dependabot-friendly: when a new release lands, the bot updates both together.

Scans your repository, uploads findings to GitHub Code Scanning, and optionally fails the build:

```yaml
- uses: garagon/aguara@v0.18.3
  with:
    path: ./mcp-server/
    severity: medium
    fail-on: high
    version: v0.18.3
```

All inputs are optional. See [`action.yml`](action.yml) for the full list.

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `./` | Path to scan |
| `severity` | `info` | Minimum severity to report |
| `fail-on` | _(none)_ | Fail if findings at or above this severity |
| `format` | `sarif` | Output format: sarif, json, terminal, markdown |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning |
| `version` | _(latest)_ | Pin a specific Aguara version |

> SARIF upload requires the `security-events: write` permission and is free for public repositories.

### Docker in CI

```yaml
- name: Scan for security issues
  run: docker run --rm -v "${{ github.workspace }}:/scan:ro" ghcr.io/garagon/aguara:0.18.3 scan /scan --ci
```

### Manual / GitLab CI

```yaml
# GitHub Actions (without the action)
- name: Scan skills for security issues
  run: |
    curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | VERSION=v0.18.3 sh
    aguara scan .claude/skills/ --ci
```

```yaml
# GitLab CI
security-scan:
  script:
    - curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | VERSION=v0.18.3 sh
    - aguara scan .claude/skills/ --format sarif -o gl-sast-report.sarif --fail-on high
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

## How It Works

Aguara runs 6 scan analyzers sequentially on every file by default; a 7th (Rug-Pull) joins when `--monitor` is enabled and a state store is configured. Each catches a different class of attack:

| Analyzer | Engine | What it catches |
|----------|--------|-----------------|
| **Pattern Matcher** | Regex + Aho-Corasick | Known attack signatures, credential patterns, dangerous commands. Aho-Corasick automaton for O(n+m) multi-pattern search. 8 decoders (base64, hex, URL, Unicode escapes, HTML entities, hex escapes, base32, octal escapes) decode obfuscated payloads and re-scan. Code-block severity downgrade. Dynamic confidence based on pattern hit ratio. |
| **CI Trust** | GitHub Actions YAML parser | `pull_request_target` chains, cache poisoning across fork boundaries, OIDC token surface paired with install/build/test, persisted-credentials checkouts on PR head refs. |
| **PkgMeta** | `package.json` JSON parser | npm install-time lifecycle scripts plus git-sourced dependencies, optional-git deps with suspicious names, publish surfaces paired with trusted-publishing references. |
| **JSRisk** | JavaScript single-pass scanner | Obfuscator-shape payloads, install-time daemonization via `child_process`, CI secret harvesting through real `process.env` reads plus network/registry sinks, runner-process memory pivots to extract OIDC tokens, Claude Code / VS Code workspace persistence, chain-aware DNS TXT exfil. |
| **NLP Analyzer** | Goldmark AST + JSON/YAML extraction | Prompt injection in markdown structure, plus tool poisoning in JSON/YAML description fields. Keyword classification with proximity weighting; clustered keywords score higher, sparse keywords in long text get penalized. |
| **Taint Tracker** | Source-to-sink flow analysis | Dangerous capability combinations within a single file and across files in the same directory. Detects credential reads paired with webhook sends, env vars flowing to shell execution, destructive plus exec combos across MCP server tools. |
| **Rug-Pull Detector** | SHA256 hash tracking | Tool descriptions that change between scans. CLI: `--monitor` flag. Library: `WithStateDir()` for persistent consumers. |

Separate `aguara check` and `aguara audit` commands inspect installed package trees (Python `site-packages`, npm `node_modules` including the pnpm `.pnpm` store) and walk the repo recursively for Go, Rust, PHP, Ruby, Java, and .NET lockfiles, matching every declared package against the embedded threat-intel snapshot. See [Supply-Chain Check](#supply-chain-check) for the full surface.

All content is NFKC-normalized before scanning to prevent Unicode evasion attacks. All layers report findings with severity, dynamic confidence score (0.50-0.95), matched text, file location with context lines, and remediation guidance. An aggregate risk score (0-100) summarizes overall threat level.

## Usage

```
aguara scan [path] [flags]

Flags:
      --auto                  Auto-discover and scan all MCP client configs
      --severity string       Minimum severity to report: critical, high, medium, low, info (default "info")
      --format string         Output format: terminal, json, sarif, markdown (default "terminal")
  -o, --output string         Output file path (default: stdout)
      --workers int           Number of worker goroutines (default: NumCPU)
      --rules string          Additional rules directory
      --disable-rule strings  Rule IDs to disable (comma-separated, repeatable)
      --max-file-size string  Maximum file size to scan (e.g. 50MB, 100MB; default 50MB, range 1MB-500MB)
      --tool-name string      Tool context for false-positive reduction (e.g. Bash, Edit, WebFetch)
      --profile string        Scan profile: strict (default), content-aware, minimal
      --no-color              Disable colored output
      --no-update-check       Disable automatic update check (also: AGUARA_NO_UPDATE_CHECK=1)
      --fail-on string        Exit code 1 if findings at or above this severity
      --ci                    CI mode: --fail-on high --no-color
      --changed               Only scan git-changed files
      --monitor               Enable rug-pull detection: track file hashes across runs
  -v, --verbose               Show rule descriptions, confidence scores, and remediation
  -h, --help                  Help
```

### Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| **Terminal** | `--format terminal` (default) | Human-readable with color, severity dashboard, top-files chart |
| **JSON** | `--format json` | Machine processing, API integration, custom tooling |
| **SARIF** | `--format sarif` | GitHub Code Scanning, IDE integrations, SAST dashboards |
| **Markdown** | `--format markdown` | GitHub Actions job summaries, PR comments |

## Configuration

Create `.aguara.yml` in your project root:

```yaml
severity: medium
fail_on: high
max_file_size: 104857600  # 100 MB (default: 50 MB, range: 1 MB-500 MB)
ignore:
  - "vendor/**"
  - "node_modules/**"
rule_overrides:
  CRED_004:
    severity: low
  EXTDL_004:
    disabled: true
  TC-005:
    apply_to_tools: ["Bash"]       # only enforce on Bash
  MCPCFG_004:
    exempt_tools: ["WebFetch"]     # enforce on everything except WebFetch
```

`apply_to_tools` and `exempt_tools` are mutually exclusive per rule. They filter findings at scan time when a tool name is provided via `--tool-name` or the library API.

### Inline ignore

Suppress specific findings directly in source files using inline comments:

```yaml
# aguara-ignore CRED_004
api_key: "sk-test-1234567890"  # this finding is suppressed
```

```markdown
<!-- aguara-ignore-next-line PROMPT_INJECTION_001 -->
Ignore all previous instructions (this is a test)
```

Supported directives:

| Directive | Effect |
|-----------|--------|
| `# aguara-ignore RULE_ID` | Suppress rule on the same line |
| `# aguara-ignore RULE_ID, RULE_ID2` | Suppress multiple rules on the same line |
| `# aguara-ignore-next-line RULE_ID` | Suppress rule on the next line |
| `# aguara-ignore` | Suppress all rules on the same line |
| `<!-- aguara-ignore RULE_ID -->` | HTML/Markdown comment variant |
| `// aguara-ignore RULE_ID` | C-style comment variant |

## Rules

Aguara currently exposes **219 cataloged detections** through `aguara list-rules`:

- **193 embedded YAML pattern rules** across 13 categories
- **26 analyzer-emitted detections** from ci-trust, pkgmeta, jsrisk, NLP, toxic-flow, and rug-pull

The table groups coverage by emit-time category for readability:

| Category | Rules | What it detects |
|----------|-------|-----------------|
| Credential Leak | 22 | API keys (OpenAI, AWS, GCP, Stripe, ...), private keys, DB strings, HMAC secrets |
| Prompt Injection | 18 + NLP | Instruction overrides, role switching, delimiter injection, jailbreaks, event injection |
| Supply Chain | 24 | Download-and-execute, reverse shells, sandbox escape, symlink attacks, privilege escalation, OIDC token vars, runner-pivot memory, Claude Code persistence path |
| External Download | 16 | Binary downloads, curl-pipe-shell, auto-installs, profile persistence |
| MCP Attack | 16 | Tool injection, name shadowing, canonicalization bypass, capability escalation |
| Data Exfiltration | 16 + NLP | Webhook exfil, DNS tunneling, sensitive file reads, env var leaks |
| Command Execution | 16 | shell=True, eval, subprocess, child_process, PowerShell |
| MCP Config | 13 | Unpinned npx/uvx servers, hardcoded secrets, Docker cap-add, host networking, pip without hashes |
| Indirect Injection | 10 | Fetch-and-follow, remote config, DB-driven instructions, webhook registration |
| SSRF & Cloud | 11 | Cloud metadata, IMDS, Docker socket, internal IPs, redirect following |
| Third-Party Content | 10 | eval with external data, unsafe deserialization, missing SRI, HTTP downgrade |
| Unicode Attack | 10 | RTL override, bidi, homoglyphs, zero-width sequences, normalization bypass |
| Supply Chain Exfil | 11 | Credential file reads, .pth executable code, bulk env collection, K8s secrets access, systemd persistence, archive+POST exfil, Session-Network endpoints |
| Toxic Flow | 3 + cross-file | Single-file taint tracking plus cross-file correlation across MCP server directories |

See [RULES.md](RULES.md) for the complete rule catalog with IDs and severity levels.

### Remediation Guidance

All 193 YAML rules include remediation text. It appears in every output format:

- **Terminal**: always shown for CRITICAL findings, shown for all severities with `--verbose`
- **JSON**: included in every finding object
- **SARIF**: mapped to the `help` field on each rule
- **Markdown**: shown for HIGH and CRITICAL findings
- **Explain**: `aguara explain RULE_ID` shows the full remediation text

```bash
# See remediation for a specific rule
aguara explain CRED_002

# Terminal output with remediation for all findings
aguara scan . --verbose
```

```json
{
  "rule_id": "PROMPT_INJECTION_001",
  "severity": 4,
  "matched_text": "Ignore all previous instructions",
  "remediation": "Remove instruction override text. If this is documentation, wrap it in a code block to indicate it is an example.",
  "confidence": 0.95
}
```

### Custom rules

```yaml
id: CUSTOM_001
name: "Internal API endpoint"
description: "Detects references to internal APIs"
severity: HIGH
category: custom
targets: ["*.md", "*.txt"]
match_mode: any
remediation: "Replace internal API URLs with the public endpoint or environment variable."
patterns:
  - type: regex
    value: "https?://internal\\.mycompany\\.com"
  - type: contains
    value: "api.internal"
exclude_patterns:            # optional: suppress match in these contexts
  - type: contains
    value: "## documentation"
examples:
  true_positive:
    - "Fetch data from https://internal.mycompany.com/api/users"
  false_positive:
    - "Our public API is at https://api.mycompany.com"
```

`exclude_patterns` suppress a match when the matched line (or up to 3 lines before it) matches any exclude pattern. Useful for reducing false positives in documentation headings, installation guides, etc.

Custom rules are validated at load time: unknown YAML fields are rejected, and all rules require `id`, `name`, `category`, and at least one pattern.

```bash
aguara scan .claude/skills/ --rules ./my-rules/
```

## Aguara MCP

[Aguara MCP](https://github.com/garagon/mcp-aguara) is an MCP server that lets AI agents call Aguara before they install or trust third-party tools. It imports Aguara as a Go library, so it does not shell out to a separate scanner binary.

The agent gets 4 tools: `scan_content`, `check_mcp_config`, `list_rules`, and `explain_rule`. No network, no LLM, millisecond scans.

See the [mcp-aguara README](https://github.com/garagon/mcp-aguara) for install, the canonical binary name, and client registration (Claude Code, Cursor, Windsurf, others).

## Aguara Watch

Aguara Watch is being reworked. The previous public observatory is stale, so it is not a supported product surface for v0.18.3. The supported surfaces are the CLI, GitHub Action, Docker image, signed releases, and Go library.

## Enterprise use

Aguara is designed for local and CI use in environments where source code, prompts, configs, and dependency data cannot be uploaded to a third-party scanner.

## Go Library

Aguara exposes a public Go API for embedding the scanner in other tools. [Aguara MCP](https://github.com/garagon/mcp-aguara) uses this API.

```go
import "github.com/garagon/aguara"

// Scan a directory
result, err := aguara.Scan(ctx, "./skills/")

// Scan inline content (no disk I/O, NFKC-normalized)
result, err := aguara.ScanContent(ctx, content, "skill.md")

// Scan with tool context for false-positive reduction
result, err := aguara.ScanContentAs(ctx, content, "skill.md", "Edit")
// result.Verdict: aguara.VerdictClean, VerdictFlag, or VerdictBlock
// result.ToolName: "Edit"
// result.Findings: always preserved (even when verdict is clean)

// Scan with a profile
result, err := aguara.ScanContent(ctx, content, "skill.md",
    aguara.WithToolName("Edit"),
    aguara.WithScanProfile(aguara.ProfileContentAware),
)
// result.RiskScore: 0-100 aggregate risk score

// Preserve cross-rule findings (for verdict pipelines)
result, err := aguara.ScanContent(ctx, content, "skill.md",
    aguara.WithDeduplicateMode(aguara.DeduplicateSameRuleOnly),
)

// Enable rug-pull detection with persistent state
result, err := aguara.ScanContent(ctx, content, "tool.md",
    aguara.WithStateDir("/var/lib/myapp/aguara-state"),
)

// Discover all MCP client configs on the machine
discovered, err := aguara.Discover()
for _, client := range discovered.Clients {
    fmt.Printf("%s: %d servers\n", client.Client, len(client.Servers))
}

// List rules, optionally filtered
rules := aguara.ListRules(aguara.WithCategory("prompt-injection"))

// Get rule details with remediation
detail, err := aguara.ExplainRule("PROMPT_INJECTION_001")
fmt.Println(detail.Remediation)
```

Options: `WithMinSeverity()`, `WithDisabledRules()`, `WithCustomRules()`, `WithRuleOverrides()`, `WithWorkers()`, `WithIgnorePatterns()`, `WithMaxFileSize()`, `WithCategory()`, `WithToolName()`, `WithScanProfile()`, `WithDeduplicateMode()`, `WithStateDir()`.

## Architecture

```
aguara.go              Public API: Scan, ScanContent, ScanContentAs, Discover, ListRules, ExplainRule
options.go             Functional options (WithToolName, WithStateDir, WithDeduplicateMode, ...)
discover/              MCP client discovery: 17 clients, config parsers, auto-detection
cmd/aguara/            CLI entry point (Cobra)
cmd/wasm/              WASM build for browser-based scanning
internal/
  engine/
    pattern/           Pattern matcher: Aho-Corasick + regex, 8 decoders (base64, hex, URL, Unicode, HTML, hex-escape, base32, octal-escape)
    ci/                CI Trust: .github/workflows/ YAML parser, pwn-request / cache / OIDC / persisted-credentials chains
    pkgmeta/           PkgMeta: package.json parser, npm lifecycle / git source / publish-surface chains
    jsrisk/            JSRisk: .js / .mjs / .cjs scanner, obfuscation / daemonization / CI-secret-harvest / runner-pivot / agent-persistence
    nlp/               NLP: markdown AST + JSON/YAML string extraction, proximity-weighted classifier
    toxicflow/         Taint: single-file taint tracking + cross-file correlation across directories
    rugpull/           Rug-pull: SHA256 change detection (CLI --monitor, library WithStateDir)
  rules/               Rule engine: YAML loader, compiler, self-tester
    builtin/           193 embedded YAML rules across 13 files (go:embed)
  scanner/             Orchestrator: file discovery, parallel analysis, inline ignore, result aggregation
    exemptions.go      Tool exemptions, scan profiles, verdict computation
  meta/                Post-processing: configurable dedup, scoring, risk score, correlation, confidence
  output/              Formatters: terminal (ANSI), JSON, SARIF, Markdown
  config/              .aguara.yml loader (supports tool-scoped rules)
  incident/            Incident response: compromised package detection, cleanup, quarantine
  intel/               Threat-intel snapshot loader, matcher, embedded OSV records
  packagecheck/        Multi-ecosystem lockfile parsers (Go, Rust, PHP, Ruby, Java, .NET, pnpm)
  state/               Persistence for rug-pull detection (CLI and library mode)
  types/               Shared types (Finding, Severity, ScanResult, Verdict, DeduplicateMode)
```

## Comparison

Aguara is purpose-built for AI agent content AND supply-chain trust points. General-purpose SAST tools target application source code, not the skill files, tool descriptions, MCP configs, and lockfiles that modern projects consume.

| Feature | Aguara | Semgrep | Snyk Code | CodeQL |
|---------|--------|---------|-----------|--------|
| AI agent skill scanning | Yes | No | No | No |
| MCP config analysis | Yes | No | No | No |
| Prompt injection detection | Yes (18 rules + NLP) | No | No | No |
| Rug-pull detection | Yes | No | No | No |
| Supply chain exfil detection | Yes (11 rules) | No | No | No |
| Multi-ecosystem package check | Yes (npm, pnpm, PyPI, Go, Rust, PHP, Ruby, Java, .NET) | No | Partial | No |
| Pre-install lockfile coverage | Yes (pnpm-lock.yaml today) | No | Partial | No |
| Incident response (check/clean) | Yes | No | No | No |
| Taint tracking for skills | Yes | Yes | Yes | Yes |
| Offline / no account | Yes | Partial | No | Partial |
| Custom YAML rules | Yes | Yes | No | No |
| SARIF output | Yes | Yes | Yes | Yes |
| Free and open source | Yes (Apache 2.0) | Partial | No | Partial |

Aguara complements traditional SAST: use Semgrep for your app code, Aguara for your agent skills, MCP servers, and dependency surface.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, adding rules, and the PR process.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
