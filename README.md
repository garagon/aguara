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
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#rules">Rules</a> &bull;
  <a href="#aguara-mcp">Aguara MCP</a> &bull;
  <a href="#aguara-watch">Aguara Watch</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

https://github.com/user-attachments/assets/851333be-048f-48fa-aaf3-f8cc1d4aa594

## Why Aguara?

AI agents and MCP servers run code on your behalf. A single malicious skill file can exfiltrate credentials, inject prompts, or install backdoors. Aguara catches these threats **before deployment** with static analysis that requires no API keys, no cloud, and no LLM.

- **138+ rules across 15 categories** covering prompt injection, data exfiltration, credential leaks, supply-chain attacks, MCP-specific threats, and more.
- **Catches obfuscated attacks** that regex-only tools miss, using NLP-based markdown structure analysis and taint tracking.
- **Deterministic** — same input, same output. Every scan is reproducible.
- **CI-ready** — JSON, SARIF, and Markdown output. `--fail-on` threshold. `--changed` for incremental scans.
- **Extensible** — write custom rules in YAML. No code required.

## Installation

```bash
go install github.com/garagon/aguara/cmd/aguara@latest
```

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases page](https://github.com/garagon/aguara/releases).

## Quick Start

```bash
# Scan a skills directory
aguara scan .claude/skills/

# Scan a single file
aguara scan .claude/skills/deploy/SKILL.md

# Only high and critical findings
aguara scan . --severity high

# CI mode (exit 1 on high+, no color)
aguara scan .claude/skills/ --ci
```

## Usage

```
aguara scan <path> [flags]

Flags:
      --severity string       Minimum severity to report: critical, high, medium, low, info (default "info")
      --format string         Output format: terminal, json, sarif, markdown (default "terminal")
  -o, --output string         Output file path (default: stdout)
      --workers int           Number of worker goroutines (default: NumCPU)
      --rules string          Additional rules directory
      --disable-rule strings  Rule IDs to disable (comma-separated, repeatable)
      --no-color              Disable colored output
      --fail-on string        Exit code 1 if findings at or above this severity
      --ci                    CI mode: --fail-on high --no-color
      --changed               Only scan git-changed files
  -v, --verbose               Show rule descriptions for critical and high findings
  -h, --help                  Help
```

### CI Integration

```yaml
# GitHub Actions
- name: Scan skills for security issues
  run: |
    go install github.com/garagon/aguara/cmd/aguara@latest
    aguara scan .claude/skills/ --ci
```

```yaml
# GitLab CI
security-scan:
  script:
    - go install github.com/garagon/aguara/cmd/aguara@latest
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
ignore:
  - "vendor/**"
  - "node_modules/**"
rule_overrides:
  CRED_004:
    severity: low
  EXTDL_004:
    disabled: true
```

## Rules

138+ built-in rules across 15 categories:

| Category | Rules | What it detects |
|----------|-------|-----------------|
| Prompt Injection | 17 + NLP | Instruction overrides, role switching, delimiter injection, jailbreaks |
| Data Exfiltration | 16 + NLP | Webhook exfil, DNS tunneling, sensitive file reads, env var leaks |
| Credential Leak | 17 | API keys (OpenAI, AWS, GCP, Stripe, ...), private keys, DB strings |
| MCP Attack | 11 | Tool injection, name shadowing, manifest tampering, capability escalation |
| MCP Config | 8 | Unpinned npx servers, hardcoded secrets, shell metacharacters |
| Supply Chain | 14 | Download-and-execute, reverse shells, obfuscated commands, privilege escalation |
| External Download | 16 | Binary downloads, curl-pipe-shell, auto-installs, profile persistence |
| Command Execution | 13 | shell=True, eval, subprocess, child_process, PowerShell |
| Indirect Injection | 7 | Fetch-and-follow, remote config, email-as-instructions |
| SSRF & Cloud | 8 | Cloud metadata, IMDS, Docker socket, internal IPs |
| Unicode Attack | 7 | RTL override, bidi, homoglyphs, tag characters |
| Third-Party Content | 4 | Mutable raw content, unvalidated API responses, remote templates |
| Toxic Flow | 3 | User input to dangerous sinks, env vars to shell, API to eval |

See [RULES.md](RULES.md) for the complete rule catalog with IDs and severity levels.

### Custom Rules

```yaml
id: CUSTOM_001
name: "Internal API endpoint"
description: "Detects references to internal APIs"
severity: HIGH
category: custom
targets: ["*.md", "*.txt"]
match_mode: any
patterns:
  - type: regex
    value: "https?://internal\\.mycompany\\.com"
  - type: contains
    value: "api.internal"
examples:
  true_positive:
    - "Fetch data from https://internal.mycompany.com/api/users"
  false_positive:
    - "Our public API is at https://api.mycompany.com"
```

```bash
aguara scan .claude/skills/ --rules ./my-rules/
```

## Aguara MCP

[Aguara MCP](https://github.com/garagon/aguara-mcp) is an MCP server that gives AI agents the ability to scan skills and configurations for security threats — before installing or running them. It imports Aguara as a Go library — one `go install`, no external binary needed.

```bash
# Install and register with Claude Code
go install github.com/garagon/aguara-mcp@latest
claude mcp add aguara -- aguara-mcp
```

Your agent gets 4 tools: `scan_content`, `check_mcp_config`, `list_rules`, and `explain_rule`. No network, no LLM, millisecond scans — the agent checks first, then decides.

## Aguara Watch

[Aguara Watch](https://watch.aguarascan.com/) continuously scans **28,000+ AI agent skills** across 5 public registries to track the real-world threat landscape for AI agents. All scans are powered by Aguara.

## Go Library

Aguara exposes a public Go API for embedding the scanner in other tools. [Aguara MCP](https://github.com/garagon/aguara-mcp) uses this API.

```go
import "github.com/garagon/aguara"

// Scan a directory
result, err := aguara.Scan(ctx, "./skills/")

// Scan inline content (no disk I/O)
result, err := aguara.ScanContent(ctx, content, "skill.md")

// List rules, optionally filtered
rules := aguara.ListRules(aguara.WithCategory("prompt-injection"))

// Get rule details
detail, err := aguara.ExplainRule("PROMPT_INJECTION_001")
```

Options: `WithMinSeverity()`, `WithDisabledRules()`, `WithCustomRules()`, `WithRuleOverrides()`, `WithWorkers()`, `WithIgnorePatterns()`.

## Architecture

```
aguara.go              Public API: Scan, ScanContent, ListRules, ExplainRule
options.go             Functional options for the public API
cmd/aguara/            CLI entry point (Cobra)
internal/
  engine/
    pattern/           Layer 1: regex/contains matcher + base64/hex decoder + code block awareness
    nlp/               Layer 2: goldmark AST walker, keyword classifier, injection detector
    rugpull/           Rug-pull detection analyzer
    toxicflow/         Taint tracking: source -> sink flow analysis
  rules/               Rule engine: YAML loader, compiler, self-tester
    builtin/           138 embedded rules across 12 YAML files (go:embed)
  scanner/             Orchestrator: file discovery, parallel analysis, result aggregation
  meta/                Post-processing: dedup, scoring, cross-finding correlation
  output/              Formatters: terminal (ANSI), JSON, SARIF, Markdown
  config/              .aguara.yml loader
  state/               Persistence for incremental scanning
  types/               Shared types (Finding, Severity, ScanResult)
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, adding rules, and the PR process.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
