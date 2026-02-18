<p align="center">
  <h1 align="center">Aguara</h1>
  <p align="center">
    Security scanner for AI agent skills and MCP servers.
    <br />
    Detect prompt injection, data exfiltration, and supply-chain attacks before they reach production.
  </p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#rules">Rules</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#building">Building</a>
</p>

## Quick Start

```bash
go install github.com/garagon/aguara/cmd/aguara@latest

aguara scan .claude/skills/
```

## What it does

Aguara statically analyzes skill files (`SKILL.md`, supporting scripts, configs) looking for patterns that indicate prompt injection, data exfiltration, credential leaks, supply-chain attacks, and more.

- **85 built-in rules** across 8 categories, each with self-testing examples.
- **Deterministic** — same input, same output. No LLM, no cloud, no API keys.
- **Multi-layer** — regex pattern matching + NLP-based markdown structure analysis.
- **CI-ready** — JSON and SARIF output, `--fail-on` threshold, `--changed` for git diffs.
- **Extensible** — custom rules in YAML.

## Usage

```
aguara scan <path> [flags]

Flags:
      --severity string       Minimum severity to report: critical, high, medium, low, info (default "info")
      --format string         Output format: terminal, json, sarif (default "terminal")
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

### Examples

```bash
# Scan a skills directory
aguara scan .claude/skills/

# Scan a single skill
aguara scan .claude/skills/deploy/SKILL.md

# JSON output for scripting
aguara scan ./skills/ --format json -o results.json

# Only high and critical findings
aguara scan . --severity high

# CI mode (exit 1 on high+, no color)
aguara scan .claude/skills/ --ci
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

85 built-in rules across 8 categories.

<details>
<summary><strong>Prompt Injection</strong> (17 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| PROMPT_INJECTION_001 | CRITICAL | Instruction override attempt |
| PROMPT_INJECTION_002 | HIGH | Role switching attempt |
| PROMPT_INJECTION_003 | HIGH | Hidden HTML comment with instructions |
| PROMPT_INJECTION_004 | HIGH | Zero-width character obfuscation |
| PROMPT_INJECTION_005 | MEDIUM | Urgency and authority manipulation |
| PROMPT_INJECTION_006 | CRITICAL | Delimiter injection |
| PROMPT_INJECTION_007 | HIGH | Conversation history poisoning |
| PROMPT_INJECTION_008 | HIGH | Secrecy instruction |
| PROMPT_INJECTION_009 | HIGH | Base64-encoded instructions |
| PROMPT_INJECTION_010 | CRITICAL | Fake system prompt |
| PROMPT_INJECTION_011 | CRITICAL | Jailbreak template |
| PROMPT_INJECTION_012 | MEDIUM | Markdown link with deceptive action text |
| PROMPT_INJECTION_013 | MEDIUM | Instruction in image alt text |
| PROMPT_INJECTION_014 | MEDIUM | Multi-language injection |
| PROMPT_INJECTION_015 | MEDIUM | Prompt leaking attempt |
| PROMPT_INJECTION_016 | HIGH | Self-modifying agent instructions |
| PROMPT_INJECTION_017 | HIGH | Autonomous agent spawning |

</details>

<details>
<summary><strong>Data Exfiltration</strong> (12 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| EXFIL_001 | HIGH | Webhook URL for data exfiltration |
| EXFIL_002 | HIGH | Sensitive file read pattern |
| EXFIL_003 | HIGH | Data transmission pattern |
| EXFIL_004 | HIGH | DNS exfiltration pattern |
| EXFIL_005 | HIGH | curl/wget POST with sensitive data |
| EXFIL_006 | MEDIUM | Clipboard access with network |
| EXFIL_007 | HIGH | Environment variable exfiltration |
| EXFIL_008 | HIGH | File read piped to HTTP transmission |
| EXFIL_009 | MEDIUM | Base64 encode and send |
| EXFIL_010 | MEDIUM | Non-standard port communication |
| EXFIL_011 | HIGH | External context or knowledge sync |
| EXFIL_012 | HIGH | Unrestricted email or messaging access |

</details>

<details>
<summary><strong>Credential Leak</strong> (11 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| CRED_001 | CRITICAL | OpenAI API key |
| CRED_002 | CRITICAL | AWS access key |
| CRED_003 | CRITICAL | GitHub personal access token |
| CRED_004 | MEDIUM | Generic API key pattern |
| CRED_005 | CRITICAL | Private key block |
| CRED_006 | HIGH | Database connection string |
| CRED_007 | HIGH | Hardcoded password |
| CRED_008 | HIGH | Slack or Discord webhook |
| CRED_009 | CRITICAL | GCP service account key |
| CRED_010 | MEDIUM | JWT token |
| CRED_011 | HIGH | Credential in shell export |

</details>

<details>
<summary><strong>MCP Attack</strong> (11 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| MCP_001 | CRITICAL | Tool description injection |
| MCP_002 | HIGH | Tool name shadowing |
| MCP_003 | HIGH | Resource URI manipulation |
| MCP_004 | HIGH | Parameter schema injection |
| MCP_005 | CRITICAL | Hidden tool registration |
| MCP_006 | HIGH | Tool output interception |
| MCP_007 | HIGH | Cross-tool data leakage |
| MCP_008 | CRITICAL | Server manifest tampering |
| MCP_009 | HIGH | Capability escalation |
| MCP_010 | HIGH | Prompt cache poisoning |
| MCP_011 | HIGH | Arbitrary MCP server execution |

</details>

<details>
<summary><strong>Supply Chain</strong> (11 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| SUPPLY_001 | HIGH | Suspicious npm install script |
| SUPPLY_002 | HIGH | Python setup.py execution |
| SUPPLY_003 | CRITICAL | Download-and-execute |
| SUPPLY_004 | HIGH | Makefile hidden commands |
| SUPPLY_005 | HIGH | Conditional CI execution |
| SUPPLY_006 | HIGH | Obfuscated shell command |
| SUPPLY_007 | HIGH | Privilege escalation |
| SUPPLY_008 | CRITICAL | Reverse shell pattern |
| SUPPLY_009 | HIGH | Path traversal attempt |
| SUPPLY_010 | MEDIUM | Symlink attack |
| SUPPLY_011 | HIGH | Unattended auto-update |

</details>

<details>
<summary><strong>External Download</strong> (8 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| EXTDL_001 | HIGH | Runtime URL controls agent behavior |
| EXTDL_002 | MEDIUM | Remote SDK or script fetch as agent input |
| EXTDL_003 | HIGH | npx auto-install without confirmation |
| EXTDL_004 | MEDIUM | Global package installation |
| EXTDL_005 | HIGH | Shell profile modification for persistence |
| EXTDL_006 | HIGH | MCP server auto-registration |
| EXTDL_007 | CRITICAL | Binary download and execute |
| EXTDL_008 | MEDIUM | Unverified npx package execution |

</details>

<details>
<summary><strong>SSRF & Cloud</strong> (8 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| SSRF_001 | CRITICAL | Cloud metadata URL |
| SSRF_002 | HIGH | Internal IP range access |
| SSRF_003 | HIGH | Kubernetes service discovery |
| SSRF_004 | CRITICAL | AWS IMDS token request |
| SSRF_005 | HIGH | Docker socket access |
| SSRF_006 | HIGH | Localhost bypass |
| SSRF_007 | CRITICAL | Cloud credential endpoint |
| SSRF_008 | MEDIUM | DNS rebinding setup |

</details>

<details>
<summary><strong>Unicode Attack</strong> (7 rules)</summary>

| Rule | Severity | Description |
|------|----------|-------------|
| UNI_001 | HIGH | Right-to-left override |
| UNI_002 | HIGH | Bidi text manipulation |
| UNI_003 | MEDIUM | Homoglyph domain spoofing |
| UNI_004 | MEDIUM | Invisible separator injection |
| UNI_005 | MEDIUM | Combining character obfuscation |
| UNI_006 | HIGH | Tag characters for hidden data |
| UNI_007 | MEDIUM | Punycode domains |

</details>

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

## Architecture

```
cmd/aguara/            CLI entry point (Cobra)
internal/
  engine/
    pattern/           Layer 1: regex/contains matcher + base64/hex decoder
    nlp/               Layer 2: goldmark AST walker, keyword classifier, injection detector
  rules/               Rule engine: YAML loader, compiler, self-tester
    builtin/           85 embedded rules across 8 YAML files (go:embed)
  scanner/             Orchestrator: file discovery, parallel analysis, result aggregation
  meta/                Post-processing: dedup, scoring, cross-finding correlation
  output/              Formatters: terminal (ANSI), JSON, SARIF
  config/              .aguara.yml loader
  types/               Shared types (Finding, Severity, ScanResult)
```

## Building

Requires Go 1.25+.

```bash
make build        # Production binary
make test         # Tests with race detector
make lint         # golangci-lint
make fmt          # gofmt
make vet          # go vet
make clean        # Remove binary
```

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
