# AGENTS.md - Aguara Reference for AI Agents

Aguara is a static security scanner for AI agent skills and MCP server configurations. Single Go binary, fully offline, deterministic, no LLM. Think "Semgrep for AI agents."

## Quick Start

```bash
# Install
go install github.com/garagon/aguara@latest

# Scan a directory
aguara scan ./skills/

# Scan with CI defaults (fail on high+, no color)
aguara scan --ci ./skills/

# JSON output
aguara scan --format json ./skills/

# List all rules
aguara list-rules
```

## Go Library API

```go
import "github.com/garagon/aguara"

// Scan a file or directory
result, err := aguara.Scan(ctx, "./skills/")

// Scan inline content (no disk I/O)
result, err := aguara.ScanContent(ctx, content, "skill.md")

// List rules
rules := aguara.ListRules()

// Explain a rule
detail, err := aguara.ExplainRule("PROMPT_INJECTION_001")
```

### Options

```go
aguara.Scan(ctx, path,
    aguara.WithMinSeverity(aguara.SeverityMedium),
    aguara.WithDisabledRules("EXFIL_005", "CRED_001"),
    aguara.WithCustomRules("./custom-rules/"),
    aguara.WithWorkers(4),
    aguara.WithRuleOverrides(map[string]aguara.RuleOverride{
        "PROMPT_INJECTION_001": {Severity: "medium"},
        "EXFIL_005":           {Disabled: true},
    }),
)
```

### Types

```go
type ScanResult struct {
    Findings     []Finding
    FilesScanned int
    RulesLoaded  int
    DurationMs   int64    // in JSON output
}

type Finding struct {
    RuleID      string        // "PROMPT_INJECTION_001"
    RuleName    string        // "Instruction override attempt"
    Severity    Severity      // 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    Category    string        // "prompt-injection"
    Description string        // rule description
    FilePath    string        // "skills/evil.md"
    Line        int           // 1-indexed
    Column      int
    MatchedText string        // text that triggered the rule
    Context     []ContextLine // surrounding lines
    Score       float64       // 0-100 risk score
    Analyzer    string        // "pattern", "nlp-injection", "toxicflow", "rugpull"
    InCodeBlock bool          // true if match is inside a fenced code block
}

type Severity int // SeverityInfo=0, SeverityLow=1, SeverityMedium=2, SeverityHigh=3, SeverityCritical=4
```

## CLI Commands

### `aguara scan <path>`

Scan a file or directory.

| Flag | Default | Description |
|---|---|---|
| `--severity` | `info` | Minimum severity: critical, high, medium, low, info |
| `--format` | `terminal` | Output: terminal, json, sarif, markdown |
| `-o, --output` | stdout | Output file path |
| `--fail-on` | (none) | Exit 1 if findings at or above this severity |
| `--ci` | false | CI mode: `--fail-on high --no-color` |
| `-v, --verbose` | false | Show rule descriptions for critical/high findings |
| `--changed` | false | Only scan git-changed files |
| `--monitor` | false | Enable rug-pull detection (track file changes) |
| `--state-path` | `~/.aguara/state.json` | State file for `--monitor` |
| `--workers` | NumCPU | Concurrent worker goroutines |
| `--rules` | (none) | Additional rules directory |
| `--disable-rule` | (none) | Rule IDs to skip (repeatable) |
| `--no-color` | false | Disable ANSI colors |

### `aguara list-rules`

List all detection rules. Supports `--category`, `--format json`, `--rules`.

### `aguara explain <RULE_ID>`

Show full rule details: ID, name, severity, category, description, patterns, examples.

### `aguara init [path]`

Scaffold `.aguara.yml`, `.aguaraignore`, and optionally `--hook` (git pre-commit) or `--ci` (GitHub Actions workflow).

### `aguara version`

Print version and commit hash.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No findings above `--fail-on` threshold (or no `--fail-on` set) |
| 1 | Findings at or above `--fail-on` severity, or any error |

## Output Formats

| Format | Flag | Use Case |
|---|---|---|
| `terminal` | `--format terminal` | Human-readable, ANSI colors, severity histogram |
| `json` | `--format json` | Machine parsing, CI integration |
| `sarif` | `--format sarif` | GitHub Code Scanning (SARIF 2.1.0) |
| `markdown` | `--format markdown` | GitHub Actions job summaries, PR comments |

### JSON Schema

```json
{
  "findings": [
    {
      "rule_id": "PROMPT_INJECTION_001",
      "rule_name": "Instruction override attempt",
      "severity": 4,
      "category": "prompt-injection",
      "description": "Detects attempts to override or ignore previous instructions",
      "file_path": "skills/evil.md",
      "line": 3,
      "column": 0,
      "matched_text": "Ignore all previous instructions",
      "context": [
        {"line": 2, "content": "", "is_match": false},
        {"line": 3, "content": "Ignore all previous instructions", "is_match": true}
      ],
      "score": 60.0,
      "analyzer": "pattern",
      "in_code_block": false
    }
  ],
  "files_scanned": 5,
  "rules_loaded": 138,
  "duration_ms": 42
}
```

Severity is an integer: 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL.

## Detection Rules

138+ built-in rules across 14 categories.

| Category | Rules | What It Detects |
|---|---|---|
| `prompt-injection` | 22 | Instruction overrides, role switching, delimiter injection, jailbreaks |
| `credential-leak` | 17 | API keys (OpenAI, AWS, GCP, Stripe, Anthropic, GitHub), private keys, DB strings |
| `exfiltration` | 17 | Webhook exfil, DNS tunneling, sensitive file reads, env var leaks |
| `external-download` | 16 | Binary downloads, curl-pipe-shell, auto-installs |
| `supply-chain` | 14 | Download-and-execute, reverse shells, obfuscated commands |
| `command-execution` | 13 | shell=True, eval, subprocess, child_process, PowerShell |
| `mcp-attack` | 11 | Tool injection, name shadowing, manifest tampering, capability escalation |
| `ssrf-cloud` | 8 | Cloud metadata (IMDS), Docker socket, internal IPs |
| `mcp-config` | 8 | Unpinned npx, hardcoded secrets, shell metacharacters in args |
| `unicode-attack` | 7 | RTL override, bidi, homoglyphs, tag characters |
| `indirect-injection` | 7 | Fetch-and-follow, remote config, email-as-instructions |
| `third-party-content` | 4 | Mutable raw content, unvalidated API responses |
| `toxic-flow` | 3 | User input to dangerous sinks, taint tracking |
| `rug-pull` | 1 | Tool description changed with dangerous content (requires `--monitor`) |

Use `aguara list-rules` to see all rules. Use `aguara explain <id>` for patterns and examples.

### Rule YAML Schema

```yaml
id: RULE_ID_001
name: "Human-readable name"
severity: CRITICAL          # CRITICAL | HIGH | MEDIUM | LOW | INFO
category: prompt-injection
description: "What it detects"
targets:                    # file globs; empty = all files
  - "*.md"
  - "*.json"
match_mode: any             # "any" (OR, default) | "all" (AND)
patterns:
  - type: regex             # "regex" (RE2) | "contains"
    value: "(?i)pattern"
examples:
  true_positive:
    - "Text that should trigger"
  false_positive:
    - "Text that should not trigger"
```

## Analyzers

Aguara runs four analysis engines in sequence on each file:

| Analyzer | ID | Targets | What It Does |
|---|---|---|---|
| Pattern Matcher | `pattern` | All files | Regex/contains matching against YAML rules. Includes base64/hex decoder. |
| NLP Injection | `nlp-injection` | `.md`, `.txt` only | Goldmark AST walker. Detects hidden instructions in comments, code/heading mismatches, authority claims, credential+network combos. |
| Toxic Flow | `toxicflow` | All files | Taint tracking: detects dangerous source-to-sink flows (user input to exec, env vars to shell, API data to eval). |
| Rug-Pull | `rugpull` | All files | Compares file hashes against previous scan state. Only active with `--monitor`. |

### Scoring

Each finding gets a risk score (0-100):
- Base: CRITICAL=40, HIGH=25, MEDIUM=15, LOW=8, INFO=3
- Multiplied by category weight (1.1x to 1.5x)
- Correlated findings within 5 lines get +5 bonus each
- Capped at 100

### Code Block Downgrade

In markdown files, findings inside fenced code blocks (` ``` `) are automatically downgraded one severity level (CRITICAL to HIGH, HIGH to MEDIUM, etc.). The finding's `in_code_block` field is set to `true`.

## Config File (.aguara.yml)

Loaded from the scan target directory (or parent of target file).

```yaml
ignore:
  - "vendor/"
  - "node_modules/"
  - "*.log"

severity: info              # minimum severity filter
fail_on: high               # exit 1 threshold
format: terminal            # output format
rules: custom-rules/        # additional rules directory

rule_overrides:
  PROMPT_INJECTION_001:
    severity: medium        # override severity
  EXFIL_005:
    disabled: true          # disable rule
```

CLI flags override config values.

### .aguaraignore

Gitignore-style file at scan root. One pattern per line, `#` for comments. Supports `*`, `?`, `[...]`, and `**` for recursive matching.

Always skipped: `.git/`, `node_modules/`, `.aguara/`, binary files (.exe, .dll, .so, .png, .jpg, .zip, .pdf, etc.).

## Incremental Scanning

### Git-changed files (`--changed`)

Scans only files modified in git (staged, unstaged, untracked). No state persistence.

```bash
aguara scan --changed .
```

### Rug-pull detection (`--monitor`)

Tracks file hashes across scans. If a file's content changes and the new content matches dangerous patterns (instruction overrides, reverse shells, credential exfil, etc.), emits a CRITICAL `RUGPULL_001` finding.

```bash
aguara scan --monitor ./skills/
```

State stored in `~/.aguara/state.json` (override with `--state-path`).

## Constraints

- Go `regexp` (RE2): no lookaheads `(?!...)` or lookbehinds `(?<=...)`
- Fully offline: no network calls, no URL fetching, no stdin
- No code AST analysis (only markdown AST via goldmark)
- Pattern matching only, not semantic understanding
