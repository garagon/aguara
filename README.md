<p align="center">
  <h1 align="center">Aguara</h1>
  <p align="center">
    Security scanner for AI agent skills and MCP servers.
    <br />
    Detect prompt injection, data exfiltration, and supply-chain attacks before they reach production.
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
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#rules">Rules</a> &bull;
  <a href="#incident-response">Incident Response</a> &bull;
  <a href="#aguara-mcp">Aguara MCP</a> &bull;
  <a href="#aguara-watch">Aguara Watch</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

https://github.com/user-attachments/assets/851333be-048f-48fa-aaf3-f8cc1d4aa594

## Why Aguara?

AI agents and MCP servers run code on your behalf. A single malicious skill file can exfiltrate credentials, inject prompts, or install backdoors. Aguara catches these threats **before deployment** with static analysis that requires no API keys, no cloud, and no LLM.

- **187 detection rules across 14 categories** — prompt injection, data exfiltration, credential leaks, supply-chain attacks, MCP-specific threats, command execution, SSRF, unicode attacks, and more.
- **4-layer analysis engine** — pattern matching, NLP analysis, taint tracking, and rug-pull detection work together to catch threats that any single technique would miss.
- **6 decoders for encoded evasion** — base64, hex, URL encoding, Unicode escapes, HTML entities, and hex escapes. Obfuscated payloads are decoded and re-scanned automatically.
- **NLP on markdown, JSON, and YAML** — goldmark AST analysis for markdown files, plus string extraction and classification for JSON/YAML tool descriptions. Catches MCP tool poisoning in structured configs.
- **Cross-file toxic flow analysis** — detects dangerous capability combinations split across files in the same MCP server directory (e.g., one tool reads credentials, another sends to a webhook).
- **Aggregate risk score** — 0-100 score with diminishing returns across findings. Available in JSON, SARIF, and terminal output.
- **Context-aware scanning** — pass the tool name (`--tool-name Edit`) and the scanner automatically skips rules that are always false positives for that tool. Built-in exemptions for Edit, Write, WebFetch, Bash, and more.
- **Scan profiles** — `strict` (default), `content-aware`, or `minimal` enforcement. Findings are always preserved for audit; only the verdict (clean/flag/block) changes.
- **Evasion prevention** — NFKC normalization catches fullwidth character evasion. 6 decoders catch encoded payloads. Crypto address filtering prevents hex decoder false positives.
- **Dynamic confidence scoring** — every finding carries a confidence level (0.50-0.95) that reflects signal quality: pattern hit ratio, classifier score, and code-block awareness.
- **Remediation guidance** — all 187 rules include actionable fix suggestions, shown in every output format.
- **Deterministic** — same input, same output. Every scan is reproducible.
- **CI-ready** — JSON, SARIF, and Markdown output. GitHub Action. `--fail-on` threshold. `--changed` for incremental scans.
- **17 MCP clients supported** — auto-discover and scan configs from Claude Desktop, Cursor, VS Code, Windsurf, and 13 more.
- **Library API for embedding** — `WithDeduplicateMode()` preserves all cross-rule findings for verdict pipelines. `WithStateDir()` enables rug-pull detection for persistent consumers.
- **Extensible** — write custom rules in YAML. No code required.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | bash
```

Installs the latest binary to `~/.local/bin`. Customize with environment variables:

```bash
VERSION=v0.11.0 curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | bash
INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | bash
```

### Alternative methods

**Homebrew** (macOS/Linux):

```bash
brew install garagon/tap/aguara
```

**Docker** (no install required):

```bash
# Scan current directory
docker run --rm -v "$(pwd)":/scan ghcr.io/garagon/aguara scan /scan

# Scan with options
docker run --rm -v "$(pwd)":/scan ghcr.io/garagon/aguara scan /scan --severity high --format json

# Use a specific version
docker run --rm -v "$(pwd)":/scan ghcr.io/garagon/aguara:v0.11.1 scan /scan
```

**From source** (requires Go 1.25+):

```bash
go install github.com/garagon/aguara/cmd/aguara@latest
```

Pre-built binaries for Linux, macOS, and Windows are also available on the [Releases page](https://github.com/garagon/aguara/releases).

## Quick Start

```bash
# Auto-discover and scan all MCP configs on your machine
aguara scan --auto

# Discover which MCP clients are configured (no scanning)
aguara discover

# Scan a skills directory
aguara scan .claude/skills/

# Scan a single file
aguara scan .claude/skills/deploy/SKILL.md

# Only high and critical findings
aguara scan . --severity high

# CI mode (exit 1 on high+, no color)
aguara scan .claude/skills/ --ci

# Verbose mode (show descriptions, confidence scores, remediation)
aguara scan . --verbose

# Check for compromised Python packages (litellm, etc.)
aguara check

# Clean up compromised packages and persistence artifacts
aguara clean --dry-run
```

## How It Works

Aguara runs 4 analysis layers sequentially on every file. Each layer catches different attack patterns:

| Layer | Engine | What it catches |
|-------|--------|-----------------|
| **Pattern Matcher** | Regex + Aho-Corasick matching | Known attack signatures, credential patterns, dangerous commands. Aho-Corasick automaton for O(n+m) multi-pattern search. 6 decoders (base64, hex, URL encoding, Unicode escapes, HTML entities, hex escapes) decode obfuscated payloads and re-scan. Code-block severity downgrade. Dynamic confidence based on pattern hit ratio. |
| **NLP Analyzer** | Goldmark AST + JSON/YAML extraction | Prompt injection in markdown structure, plus tool poisoning in JSON/YAML description fields. Keyword classification with proximity weighting - clustered keywords score higher, sparse keywords in long text get penalized. |
| **Taint Tracker** | Source-to-sink flow analysis | Dangerous capability combinations within a single file and across files in the same directory. Detects credential reads paired with webhook sends, env vars flowing to shell execution, and destructive + exec combos across MCP server tools. |
| **Rug-Pull Detector** | SHA256 hash tracking | Tool descriptions that change between scans. CLI: `--monitor` flag. Library: `WithStateDir()` for persistent consumers. |

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

### MCP Client Discovery

Aguara auto-detects MCP configurations across **17 clients**: Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw, OpenCode, Zed, Amp, Gemini CLI, Copilot CLI, Amazon Q, Claude Code, Roo Code, Kilo Code, BoltAI, and JetBrains.

```bash
# List all detected MCP configs
aguara discover

# JSON output (sensitive env values are automatically redacted)
aguara discover --format json

# Markdown output
aguara discover --format markdown

# Discover + scan in one command
aguara scan --auto
```

### CI Integration

#### GitHub Action

```yaml
- uses: garagon/aguara@v1
```

Scans your repository, uploads findings to GitHub Code Scanning, and optionally fails the build:

```yaml
- uses: garagon/aguara@v1
  with:
    path: ./mcp-server/
    severity: medium
    fail-on: high
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

> **Note**: SARIF upload requires the `security-events: write` permission and is free for public repositories.

#### Docker in CI

```yaml
# GitHub Actions with Docker (no install step)
- name: Scan for security issues
  run: docker run --rm -v "${{ github.workspace }}":/scan ghcr.io/garagon/aguara scan /scan --ci
```

#### Manual / GitLab CI

```yaml
# GitHub Actions (without the action)
- name: Scan skills for security issues
  run: |
    curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | bash
    aguara scan .claude/skills/ --ci
```

```yaml
# GitLab CI
security-scan:
  script:
    - curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | bash
    - aguara scan .claude/skills/ --format sarif -o gl-sast-report.sarif --fail-on high
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

### Configuration

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

### Inline Ignore

Suppress specific findings directly in your source files using inline comments:

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

187 built-in rules across 14 categories:

| Category | Rules | What it detects |
|----------|-------|-----------------|
| Credential Leak | 22 | API keys (OpenAI, AWS, GCP, Stripe, ...), private keys, DB strings, HMAC secrets |
| Prompt Injection | 18 + NLP | Instruction overrides, role switching, delimiter injection, jailbreaks, event injection |
| Supply Chain | 21 | Download-and-execute, reverse shells, sandbox escape, symlink attacks, privilege escalation |
| External Download | 16 | Binary downloads, curl-pipe-shell, auto-installs, profile persistence |
| MCP Attack | 16 | Tool injection, name shadowing, canonicalization bypass, capability escalation |
| Data Exfiltration | 16 + NLP | Webhook exfil, DNS tunneling, sensitive file reads, env var leaks |
| Command Execution | 16 | shell=True, eval, subprocess, child_process, PowerShell |
| MCP Config | 11 | Unpinned npx servers, hardcoded secrets, Docker cap-add, host networking |
| Indirect Injection | 10 | Fetch-and-follow, remote config, DB-driven instructions, webhook registration |
| SSRF & Cloud | 11 | Cloud metadata, IMDS, Docker socket, internal IPs, redirect following |
| Third-Party Content | 10 | eval with external data, unsafe deserialization, missing SRI, HTTP downgrade |
| Unicode Attack | 10 | RTL override, bidi, homoglyphs, zero-width sequences, normalization bypass |
| Supply Chain Exfil | 10 | Credential file reads, .pth executable code, bulk env collection, K8s secrets access, systemd persistence, archive+POST exfil |
| Toxic Flow | 3 + cross-file | Single-file taint tracking plus cross-file correlation across MCP server directories |

See [RULES.md](RULES.md) for the complete rule catalog with IDs and severity levels.

### Remediation Guidance

All 187 rules include remediation text. It appears in every output format:

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

### Custom Rules

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

## Incident Response

Aguara can detect and clean compromised Python packages. Built in response to the [litellm supply chain attack](https://github.com/garagon/aguara/releases/tag/v0.11.0) (March 2026), where malicious `.pth` files exfiltrated credentials and installed K8s backdoors.

### `aguara check`

Scans installed Python environments for compromised packages, malicious `.pth` files, and persistence artifacts.

```bash
# Auto-discover Python environment and check
aguara check

# Check a specific virtualenv
aguara check --path /opt/venv/lib/python3.12/site-packages/

# Also check pip/uv caches
aguara check --include-caches

# Machine-readable output
aguara check --format json
```

What it checks:
- **Known compromised versions** (embedded database, updated with each release)
- **`.pth` files with executable code** (import, subprocess, exec, eval)
- **Persistence backdoors** (systemd user services, sysmon artifacts)
- **Credential files at risk** (SSH, AWS, K8s, git, npm, PyPI, databases)

### `aguara clean`

Removes compromised packages and quarantines malicious files for forensics.

```bash
# Preview what would be removed
aguara clean --dry-run

# Remove everything (interactive confirmation)
aguara clean

# Non-interactive, also purge pip/uv caches
aguara clean --yes --purge-caches
```

Files are quarantined to `/tmp/aguara-quarantine/`, not deleted. After cleaning, Aguara prints a credential rotation checklist for every credential file that exists on the system.

## Aguara MCP

[Aguara MCP](https://github.com/garagon/aguara-mcp) is an MCP server that gives AI agents the ability to scan skills and configurations for security threats — before installing or running them. It imports Aguara as a Go library — one `go install`, no external binary needed.

```bash
# Install and register with Claude Code
go install github.com/garagon/aguara-mcp@latest
claude mcp add aguara -- aguara-mcp
```

Your agent gets 4 tools: `scan_content`, `check_mcp_config`, `list_rules`, and `explain_rule`. No network, no LLM, millisecond scans — the agent checks first, then decides.

## Aguara Watch

[Aguara Watch](https://watch.aguarascan.com/) continuously scans **28,000+ AI agent skills** across 6 public registries to track the real-world threat landscape for AI agents. All scans are powered by Aguara.

## Go Library

Aguara exposes a public Go API for embedding the scanner in other tools. [Aguara MCP](https://github.com/garagon/aguara-mcp) uses this API.

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
    pattern/           Layer 1: Aho-Corasick + regex, 6 decoders (base64/hex/URL/Unicode/HTML/hex-escape)
    nlp/               Layer 2: markdown AST + JSON/YAML string extraction, proximity-weighted classifier
    toxicflow/         Layer 3: single-file taint tracking + cross-file correlation across directories
    rugpull/           Layer 4: SHA256 change detection (CLI --monitor, library WithStateDir)
  rules/               Rule engine: YAML loader, compiler, self-tester
    builtin/           187 embedded rules across 13 YAML files (go:embed)
  scanner/             Orchestrator: file discovery, parallel analysis, inline ignore, result aggregation
    exemptions.go      Tool exemptions, scan profiles, verdict computation
  meta/                Post-processing: configurable dedup, scoring, risk score, correlation, confidence
  output/              Formatters: terminal (ANSI), JSON, SARIF, Markdown
  config/              .aguara.yml loader (supports tool-scoped rules)
  incident/            Incident response: compromised package detection, cleanup, quarantine
  state/               Persistence for rug-pull detection (CLI and library mode)
  types/               Shared types (Finding, Severity, ScanResult, Verdict, DeduplicateMode)
```

## Comparison

Aguara is purpose-built for AI agent content. General-purpose SAST tools target application source code, not the skill files, tool descriptions, and MCP configs that agents consume.

| Feature | Aguara | Semgrep | Snyk Code | CodeQL |
|---------|--------|---------|-----------|--------|
| AI agent skill scanning | Yes | No | No | No |
| MCP config analysis | Yes | No | No | No |
| Prompt injection detection | Yes (18 rules + NLP) | No | No | No |
| Rug-pull detection | Yes | No | No | No |
| Supply chain exfil detection | Yes (10 rules) | No | No | No |
| Incident response (check/clean) | Yes | No | No | No |
| Taint tracking for skills | Yes | Yes | Yes | Yes |
| Offline / no account | Yes | Partial | No | Partial |
| Custom YAML rules | Yes | Yes | No | No |
| SARIF output | Yes | Yes | Yes | Yes |
| Free & open source | Yes (Apache 2.0) | Partial | No | Partial |

Aguara complements traditional SAST - use Semgrep for your app code, Aguara for your agent skills and MCP servers.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, adding rules, and the PR process.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
