# Changelog

All notable changes to Aguara are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.10.0] — 2026-03-24

Engine improvements for evasion prevention, signal quality, and library consumer API. Derived from oktsec IPI Arena benchmark analysis. Validated against 28,207 real MCP skills from Aguara Watch.

### Added

#### Additional decoders in pattern layer

Four new decoders alongside existing base64/hex for detecting encoded evasion attacks:

- URL encoding (`%49%67%6E%6F%72%65` -> "Ignore")
- Unicode escapes (`\u0049\u0067\u006E` -> "Ign")
- HTML entities (`&#73;&#103;&#110;` -> "Ign")
- Hex escapes (`\x49\x67\x6E` -> "Ign")

Shared `maxBlobsPerFile=10` cap across all decoder types. Crypto address filter excludes Ethereum addresses from hex decoding.

#### NLP analysis for JSON/YAML files

`InjectionAnalyzer` now processes `.json`, `.yaml`, and `.yml` files. Extracts string values >= 50 chars and runs `checkAuthorityClaim` and `checkDangerousCombos`. Catches MCP tool description poisoning in structured config files.

#### Aggregate RiskScore

`ScanResult` includes `RiskScore float64` (0-100) computed with diminishing returns: highest-scoring finding contributes 100%, second 50%, third 25%, etc. Shown in JSON, SARIF (`run.properties.riskScore`), and terminal footer.

#### Proximity weighting in NLP classifier

`Classify`/`ClassifyAll` now consider keyword clustering and text density. Clustered keywords get a 1.3x bonus; keywords spread across long text get a 0.7x penalty. Reduces false positives on legitimate API documentation.

#### Dynamic confidence scores

Pattern matcher confidence varies by hit ratio: `0.70 + 0.25 * (hitPatterns/totalPatterns)`. NLP confidence derives from classifier score (0.50-0.90). Replaces flat 0.85/0.70 values.

#### Configurable cross-rule dedup

New `WithDeduplicateMode` option. `DeduplicateFull` (default) collapses cross-rule duplicates per line. `DeduplicateSameRuleOnly` preserves all cross-rule findings for library consumers that need complete signal.

#### Cross-file toxicflow correlation

New `CrossFileAnalyzer` detects dangerous capability combinations across files in the same directory. Rules: TOXIC_CROSS_001 (cred read + public output), TOXIC_CROSS_002 (cred read + code exec), TOXIC_CROSS_003 (destructive + code exec). Skips directories with >50 files (flat registry heuristic).

#### Library-mode rug-pull state API

New `WithStateDir` option enables rug-pull detection for library consumers. State persists between scans. First scan records baseline hashes; subsequent scans detect content changes with dangerous patterns.

### Changed

- Confidence values now vary based on signal quality instead of flat per-analyzer values
- NLP classifier applies proximity and density factors to keyword scoring

### API additions (non-breaking)

```go
aguara.WithDeduplicateMode(aguara.DeduplicateSameRuleOnly)
aguara.WithStateDir("/path/to/state")
aguara.ScanResult.RiskScore // float64, 0-100
aguara.DeduplicateMode      // DeduplicateFull | DeduplicateSameRuleOnly
```

## [0.9.0] — 2026-03-20

Context-aware scanning, false-positive reduction infrastructure, Unicode evasion prevention, and performance optimization.

### Added

#### Context-aware scanning API

New `ScanContentAs()` function accepts a tool name for context-aware false-positive reduction:

```go
result, err := aguara.ScanContentAs(ctx, content, "skill.md", "Edit")
```

When the scanner knows which tool generated the content, it can automatically skip rules that are always false positives for that tool. Also available as an option: `aguara.WithToolName("Edit")`.

#### Built-in tool exemptions

Automatic false-positive elimination for known tool+rule combinations:

| Rule | Exempt tools | Reason |
|------|-------------|--------|
| TC-005 | Bash, Write, Edit, MultiEdit, NotebookEdit, Agent | Shell metacharacters are normal syntax in these tools |
| MCPCFG_002 | Bash, Write, Edit, MultiEdit, NotebookEdit, Agent | MCP config patterns in file-editing tools |
| MCPCFG_004 | WebFetch, Fetch, WebSearch | Remote URLs are the purpose of fetch tools |
| MCPCFG_006 | Bash, Write, Edit, MultiEdit, NotebookEdit | Server config patterns in file-editing tools |
| THIRDPARTY_001 | WebFetch, Fetch, WebSearch | Third-party content is the purpose of fetch tools |

Exemptions activate automatically when a tool name is provided. User config overrides take precedence.

#### Scan profiles

Three enforcement profiles control how aggressively findings block:

| Profile | Behavior | Use case |
|---------|----------|----------|
| `strict` | All rules enforce (default) | Standalone scanning, untrusted agents |
| `content-aware` | Only TC-001, TC-003, TC-006 block | Development agents (Claude Code, Cursor) |
| `minimal` | TC-001, TC-003, TC-006 flag only | Trusted internal agents |

Findings are always preserved in the result. Only the verdict changes. CLI: `--profile content-aware`.

#### Verdict field

`ScanResult` now includes a `Verdict` field (clean/flag/block) computed from findings and profile:

```json
{"findings": [...], "verdict": 2, "tool_name": "Edit", ...}
```

- `0` = clean (no actionable findings)
- `1` = flag (informational)
- `2` = block (action required)

#### Tool-scoped rules in config

Rules can be restricted to specific tools in `.aguara.yml`:

```yaml
rule_overrides:
  TC-005:
    apply_to_tools: ["Bash"]       # only enforce on Bash
  MCPCFG_004:
    exempt_tools: ["WebFetch"]     # enforce on everything except WebFetch
```

`apply_to_tools` and `exempt_tools` are mutually exclusive per rule.

#### NFKC Unicode normalization

All content is NFKC-normalized before scanning, both in `ScanContent()`/`ScanContentAs()` and in file-based `Scan()`. Fullwidth characters, compatibility forms, and homoglyphs are collapsed to their canonical ASCII equivalents before pattern matching.

Example: `\uFF29\uFF47\uFF4E\uFF4F\uFF52\uFF45` (fullwidth "Ignore") is normalized to ASCII "Ignore" and detected by existing rules. Zero false-positive cost.

#### CLI flags

- `--tool-name <name>`: Set tool context for false-positive reduction
- `--profile <strict|content-aware|minimal>`: Set scan enforcement profile

#### WASM build

- `make wasm` produces `aguara.wasm` (6.1MB) + `wasm_exec.js`
- Exposes `aguaraScanContent`, `aguaraScanContentAs`, `aguaraListRules` to JavaScript
- Example HTML page at `cmd/wasm/index.html` for browser-based scanning
- Client-side only, no data leaves the browser

### Improved

#### Aho-Corasick multi-pattern matching

Pattern matcher now uses an Aho-Corasick automaton for `contains` patterns. All substring patterns are compiled into a single DFA at initialization, enabling O(n+m) multi-pattern search. Rules with only `contains` patterns that have no matches are skipped entirely without running individual pattern matching.

Measured improvement: ~7.5% faster on clean files (majority case). The main bottleneck remains regex matching.

### Summary

**177 YAML rules + 4 dynamic** across 13 categories. 7 distribution channels (+ WASM). 500 tests. 0 lint issues. 2 new dependencies (`golang.org/x/text`, `petar-dambovaliev/aho-corasick`).

---

## [0.8.0] — 2026-03-11

Community contributions, 3-phase security audit, and developer experience improvements.

### Added

#### 4 new detection rules

**Supply Chain** (+2 rules, 18 → 20)

| Rule | Name | Severity |
|------|------|----------|
| SUPPLY_020 | GitHub Actions workflow injection via untrusted input | HIGH |
| SUPPLY_021 | GitHub Actions expression injection in run step | HIGH |

**Credential Leak** (+2 rules, 20 → 22)

| Rule | Name | Severity |
|------|------|----------|
| CRED_021 | .env file with secrets committed to repository | HIGH |
| CRED_022 | Environment variable exposure in shell history or logs | MEDIUM |

#### Markdown output for `aguara discover`

`aguara discover --format markdown` generates a structured markdown report of discovered MCP configurations, suitable for documentation or issue templates.

#### Remediation in all output formats

Remediation guidance now appears in every output format, not just `--verbose` terminal and JSON:

- **Terminal**: always shown for CRITICAL findings; shown for all severities in `--verbose` mode
- **JSON**: `remediation` field on every finding
- **SARIF**: `help` field on each rule entry
- **Markdown**: blockquote remediation for HIGH+ findings after the results table
- **Explain**: `aguara explain RULE_ID` shows remediation in both terminal and JSON output

#### Credential redaction in discover output

`aguara discover --format json` now redacts environment variable values by default, replacing them with `***REDACTED***` to prevent accidental credential exposure.

### Improved

#### Security audit (3 phases, 24 fixes)

Ran a comprehensive security audit across the entire codebase, resulting in 24 fixes across 3 PRs:

**Phase 1 - Hardening (12 fixes)**
- Strict YAML field validation (`KnownFields(true)`) rejects unknown keys in custom rule files
- Hardened regex patterns across credential-leak, prompt-injection, and unicode-attack rules
- Added `exclude_patterns` to reduce false positives in documentation contexts
- Secured binary extension check with case-insensitive comparison

**Phase 2 - Performance and correctness (5 fixes)**
- `StringContent()` method with `sync.Once` cache eliminates 4-5 redundant `string(Content)` conversions per file
- Pre-computed `lowerContent` avoids repeated `strings.ToLower()` in pattern matching
- Deterministic dedup with stable `RuleID` tiebreaker - same input always produces same output
- Capped base64/hex blob scanning (`maxBlobsPerFile*3`) prevents quadratic behavior
- Rule pre-filtering passes only applicable rules to the decoder, removing redundant target checks

**Phase 3 - Developer experience and quality (7 fixes)**
- Remediation text in all output formats (see above)
- Fixed mismatched remediation text on CRED_002 (AWS keys) and CRED_003 (GitHub tokens)
- Added `false_positive` examples to 6 rules that were missing them
- Pre-computed `lowerDecoded` in decoder for base64/hex content scanning

- **Test count**: 447 → 454 test functions
- **Rules**: 173 → 177 YAML rules (all with remediation and false_positive examples)
- **README**: updated to reflect all improvements from Phases 1-3

### Fixed

- Escape pipe characters in markdown table paths
- Add `.gitguardian.yaml` to exclude test fixture files from secret scanning
- Fix `md` alias and plural grammar in `FormatMarkdown`

### Summary

**177 YAML rules + 4 dynamic** across 13 categories. 6 distribution channels. 80% test coverage. 454 tests. 0 lint issues.

---

## [0.7.0] — 2026-03-05

Remediation guidance on all rules, Docker distribution, Homebrew tap, inline ignore comments, and 80% test coverage.

### Added

#### Remediation guidance — all rules

Every detection rule now includes a `remediation` field with actionable fix guidance. Shown in `--verbose` terminal output, JSON, and SARIF.

```json
{
  "rule_id": "PROMPT_INJECTION_001",
  "remediation": "Remove instruction override text. If this is documentation, wrap it in a code block."
}
```

#### Docker distribution

- Multi-stage Dockerfile (golang:1.25-alpine → alpine:3.21)
- GHCR publish workflow: `ghcr.io/garagon/aguara` with semver tags
- `docker run --rm -v "$(pwd)":/scan ghcr.io/garagon/aguara scan /scan`

#### Homebrew tap

```bash
brew install garagon/tap/aguara
```

Auto-updated by GoReleaser on every release via `garagon/homebrew-tap`.

#### Inline ignore comments

Suppress findings directly in source files:

| Directive | Effect |
|-----------|--------|
| `# aguara-ignore RULE_ID` | Suppress on same line |
| `# aguara-ignore-next-line RULE_ID` | Suppress on next line |
| `# aguara-ignore` | Suppress all rules on same line |
| `<!-- aguara-ignore RULE_ID -->` | HTML/Markdown variant |
| `// aguara-ignore RULE_ID` | C-style variant |

#### `disable_rules` config shorthand

New `.aguara.yml` field for simpler rule disabling:

```yaml
disable_rules:
  - CRED_004
  - EXFIL_005
```

#### GitHub Action for CI scanning

```yaml
- uses: garagon/aguara@v1
```

Scans repository, uploads SARIF to GitHub Code Scanning, optionally fails build.

#### Pattern matcher deduplication

Findings are now deduplicated by line within `match_mode: any` rules — multiple patterns matching the same line produce a single finding.

### Improved

- **Test coverage**: 76.3% → 80.0% global (NLP 69.1% → 93.2%, cmd 57.9% → 63.2%)
- **447 test functions** across 28 test files
- **NLP and scanner E2E benchmarks** added
- **README**: new "How It Works" section, output formats table, Docker/CI docs, remediation examples

### Fixed

- **Regex pattern length limit**: patterns exceeding 4096 chars are rejected at compile time
- **Community docs**: improved CODE_OF_CONDUCT.md and PR template

### Summary

**173 YAML rules + 4 dynamic** across 13 categories. 6 distribution channels. 80% test coverage. 447 tests. 0 lint issues.

---

## [0.5.0] — 2026-03-03

153 → **173 rules**, new confidence scoring system, configurable file-size limits, and security hardening improvements.

### Added

#### 20 new detection rules

**Indirect Injection** (+4 rules, 6 → 10)

| Rule | Name | Severity |
|------|------|----------|
| INDIRECT_011 | Database/cache query driving agent behavior | HIGH |
| INDIRECT_012 | Webhook/callback registration with external service | HIGH |
| INDIRECT_013 | Git clone and execute fetched code | HIGH |
| INDIRECT_014 | Environment variable injection from external source | MEDIUM |

**Third-Party Content** (+5 rules, 5 → 10)

| Rule | Name | Severity |
|------|------|----------|
| THIRDPARTY_003 | JavaScript eval/Function with external data | HIGH |
| THIRDPARTY_007 | Unsafe deserialization from untrusted source | HIGH |
| THIRDPARTY_008 | Script/asset without integrity check | MEDIUM |
| THIRDPARTY_009 | HTTP downgrade from HTTPS | MEDIUM |
| THIRDPARTY_010 | Unsigned plugin/extension loading | HIGH |

**Unicode Attack** (+3 rules, 7 → 10)

| Rule | Name | Severity |
|------|------|----------|
| UNI_008 | Zero-width character sequences | MEDIUM |
| UNI_009 | Unicode normalization inconsistency | MEDIUM |
| UNI_010 | Mixed-script confusable in identifiers | MEDIUM |

**MCP Config** (+2 rules, 9 → 11)

| Rule | Name | Severity |
|------|------|----------|
| MCPCFG_010 | Docker capabilities escalation (`--cap-add`) | HIGH |
| MCPCFG_011 | Unrestricted container network access (`--network host`) | MEDIUM |

**MCP Attack** (+2 rules, 14 → 16)

| Rule | Name | Severity |
|------|------|----------|
| MCP_015 | Auth-before-body parsing (slow-body DoS) | MEDIUM |
| MCP_016 | Canonicalization bypass (double-encoding) | HIGH |

**Supply Chain** (+2 rules, 16 → 18)

| Rule | Name | Severity |
|------|------|----------|
| SUPPLY_017 | Symlink/hardlink to sensitive path outside workspace | HIGH |
| SUPPLY_018 | Sandbox escape via process spawn | CRITICAL |

**Prompt Injection** (+1 rule, 17 → 18)

| Rule | Name | Severity |
|------|------|----------|
| PROMPT_INJECTION_018 | Runtime events as user-role prompt | HIGH |

**Credential Leak** (+1 rule, 19 → 20)

| Rule | Name | Severity |
|------|------|----------|
| CREDLEAK_019 | HMAC/signing secret in source | HIGH |

#### Confidence scoring system

New `Confidence` field (0.0–1.0) on every finding, measuring how certain the scanner is that a finding is a true positive. Independent from the existing risk `Score` (0–100).

- **Base confidence by analyzer**: pattern `match_mode=all` → 0.95, pattern `match_mode=any` → 0.85, decoded content → 0.90, NLP → 0.70, ToxicFlow → 0.90, Rug-Pull → 0.95
- **Post-processing adjustments**: findings inside markdown code blocks → ×0.6 downgrade; correlated findings (2+ within 5 lines) → ×1.1 boost (capped at 1.0)
- **Output**: `confidence` field in JSON/SARIF output; `[85%]` badge in `--verbose` terminal mode; SARIF `rank` property (0–100 scale)

#### Configurable max file size

- New `--max-file-size` CLI flag (e.g. `--max-file-size 100MB`), range 1 MB–500 MB, default 50 MB
- New `max_file_size` field in `.aguara.yml` config
- New `WithMaxFileSize(bytes)` library option

### Fixed

- **Atomic state file writes**: State persistence (`~/.aguara/state.json`) now uses tmp+rename pattern to prevent corruption on crash or power loss

### Summary

**177 total rules** (173 YAML + 4 dynamic from analyzers) across 13 categories.

| Category | Rules | Severity Breakdown |
|----------|-------|-------------------|
| credential-leak | 20 | 7 CRITICAL, 8 HIGH, 4 MEDIUM, 1 LOW |
| prompt-injection | 18 | 4 CRITICAL, 9 HIGH, 5 MEDIUM |
| supply-chain | 18 | 2 CRITICAL, 10 HIGH, 6 MEDIUM |
| external-download | 17 | 3 CRITICAL, 2 HIGH, 5 MEDIUM, 7 LOW |
| command-execution | 16 | 6 HIGH, 7 MEDIUM, 3 LOW |
| exfiltration | 16 | 10 HIGH, 6 MEDIUM |
| mcp-attack | 16 | 3 CRITICAL, 10 HIGH, 3 MEDIUM |
| mcp-config | 11 | 5 HIGH, 3 MEDIUM, 3 LOW |
| ssrf-cloud | 11 | 3 CRITICAL, 7 HIGH, 1 MEDIUM |
| indirect-injection | 10 | 7 HIGH, 2 MEDIUM, 1 LOW |
| third-party-content | 10 | 5 HIGH, 2 MEDIUM, 3 LOW |
| unicode-attack | 10 | 3 HIGH, 7 MEDIUM |

**5 analyzer engines**: Pattern Matcher → NLP Injection Detector → Toxic Flow Analyzer → Rug Pull Detector → Post-processing (dedup, scoring, correlation, confidence)

---

## [0.4.0] — 2026-02-28

### Added

- **5 new detection rules** from OpenClaw security analysis:
  - CREDLEAK_018: Hardcoded credentials in environment mappings (MEDIUM, credential-leak)
  - MCPATTACK_012: MCP tool name shadowing / override attack (HIGH, mcp-attack)
  - MCPATTACK_013: Permissive MCP tool auto-approval patterns (HIGH, mcp-attack)
  - SSRF_009: SSRF via server-controlled redirect following (HIGH, ssrf-cloud)
  - SUPPLY_015: Executable download disguised as data file (HIGH, supply-chain)
- **Install script** (`install.sh`): `curl | bash` installer for binary distribution
- **PATH hint**: One-time hint after `go install` when `~/go/bin` is not in PATH

### Fixed

- **Security hardening**: File-size guardrails (10 MB limit), symlink protection (resolved before read), and stricter input validation across scanner, config loader, rule loader, state persistence, and pattern decoder
- `.gitignore`: Added `sandbox/` and `coverage.out`

### Summary

**153 total rules** (149 YAML + 4 dynamic from analyzers) across 13 categories.

---

## [0.2.3] — 2026-02-23

### Added

- **`exclude_patterns` for rules**: Rules can now define patterns that cancel a match when the matched line (or up to 3 lines before it) matches an exclude pattern. Reduces false positives in documentation contexts like installation guides and setup headings.
- Applied `exclude_patterns` to 4 high-FP rules: EXTDL_004, EXTDL_009, EXTDL_011, CMDEXEC_009.

### Changed

- Documented `exclude_patterns` in README and AGENTS.md custom rules schema.

---

## [0.2.2] — 2026-02-21

### Changed

- Reduced cyclomatic complexity across multiple packages (`gocyclo` clean)
- Applied `gofmt -s` simplifications project-wide

---

## [0.2.1] — 2026-02-21

### Added

- **Public Go API** for embedding Aguara as a library:
  - `aguara.Scan(ctx, path, ...Option)` — scan files/directories
  - `aguara.ScanContent(ctx, content, filename, ...Option)` — scan inline content (no disk I/O)
  - `aguara.ListRules(...Option)` — list detection rules
  - `aguara.ExplainRule(id, ...Option)` — explain a rule by ID
  - Options: `WithMinSeverity`, `WithDisabledRules`, `WithCustomRules`, `WithWorkers`, `WithRuleOverrides`, `WithIgnorePatterns`, `WithCategory`
  - Re-exported types: `Severity`, `Finding`, `ScanResult`, `ContextLine`

---

## [0.2.0] — 2026-02-18

Major expansion: 85 → **138 rules** across 12 YAML files, 2 → **5 analyzers**, 7 new rule categories, and 2 new CLI flags.

### Added

#### New rule categories

**Command Execution** — `command-execution.yaml` (13 rules)

| Rule | Name | Severity |
|------|------|----------|
| CMDEXEC_001 | Shell subprocess with `shell=True` | HIGH |
| CMDEXEC_002 | Dynamic code evaluation (`eval`, `exec`, backticks) | HIGH |
| CMDEXEC_003 | Python subprocess execution | HIGH |
| CMDEXEC_004 | Node.js child process execution | HIGH |
| CMDEXEC_005 | Shell command with dangerous payload (`bash -c`, `sh -c`) | HIGH |
| CMDEXEC_006 | Java/Go command execution API | HIGH |
| CMDEXEC_007 | PowerShell command execution | HIGH |
| CMDEXEC_008 | Terminal multiplexer command injection | MEDIUM |
| CMDEXEC_009 | Agent shell tool usage | MEDIUM |
| CMDEXEC_010 | MCP code execution tool | MEDIUM |
| CMDEXEC_011 | Cron or scheduled command execution | MEDIUM |
| CMDEXEC_012 | Chained shell command execution | MEDIUM |
| CMDEXEC_013 | Shell script file execution (`bash script.sh`, `./script.sh`, `source`) | MEDIUM |

**Indirect Injection** — `indirect-injection.yaml` (7 rules)

| Rule | Name | Severity |
|------|------|----------|
| INDIRECT_001 | Fetch URL and use as instructions | HIGH |
| INDIRECT_003 | Read external content and apply as rules | HIGH |
| INDIRECT_004 | Remote config controlling agent behavior | HIGH |
| INDIRECT_005 | User-provided URL consumed by agent | MEDIUM |
| INDIRECT_008 | Email or message content as instructions | HIGH |
| INDIRECT_009 | External API response drives agent behavior | MEDIUM |
| INDIRECT_010 | Unscoped Bash tool in allowed tools | MEDIUM |

**Third-Party Content** — `third-party-content.yaml` (4 rules)

| Rule | Name | Severity |
|------|------|----------|
| THIRDPARTY_001 | Runtime URL controlling behavior (no pinning) | MEDIUM |
| THIRDPARTY_002 | Mutable GitHub raw content reference (`/main/`, `/master/`) | MEDIUM |
| THIRDPARTY_004 | External API response used without validation | MEDIUM |
| THIRDPARTY_005 | Remote template or prompt loaded at runtime | HIGH |

**MCP Config Security** — `mcp-config.yaml` (8 rules)

| Rule | Name | Severity |
|------|------|----------|
| MCPCFG_001 | npx MCP server without version pin | HIGH |
| MCPCFG_002 | Shell metacharacters in MCP config args | HIGH |
| MCPCFG_003 | Hardcoded secrets in MCP env block | MEDIUM |
| MCPCFG_004 | Non-localhost remote MCP server URL | MEDIUM |
| MCPCFG_005 | sudo in MCP server command | HIGH |
| MCPCFG_006 | Inline code execution in MCP command | HIGH |
| MCPCFG_007 | Docker privileged or host mount in MCP config | HIGH |
| MCPCFG_008 | Auto-confirm flag bypassing user verification | MEDIUM |

#### Expanded rule files

- **`credential-leak.yaml`** (+6 rules, 11 → 17): Stripe/Anthropic API keys, SendGrid/Twilio keys, CLI credential flags, SSH private keys, Docker env credentials
- **`exfiltration.yaml`** (+4 rules, 12 → 16): Sensitive file read + transmit, env var credentials in POST data, screenshot capture + transmission, git history access + transmission
- **`external-download.yaml`** (+8 rules, 8 → 16): pip/go/brew/apt/cargo/gem install, curl/wget piped to shell, conditional download-and-install, Docker pull+run, binary/archive download from URL
- **`supply-chain.yaml`** (+3 rules, 11 → 14): Git clone and execute chain, unpinned GitHub Actions, package install from arbitrary URL

#### New analyzers

**Rug Pull Detection** (`--monitor` flag)

Detects tool description changes (rug-pull attacks) by tracking file content SHA-256 hashes across scan runs. When a previously-safe file changes to contain dangerous patterns (prompt injection, reverse shells, exfiltration commands), a CRITICAL finding is emitted.

- New CLI flags: `--monitor` (enables hash tracking), `--state-path` (overrides state file location)
- Persistent state stored at `~/.aguara/state.json`
- Rule: RUGPULL_001 (CRITICAL)

**Toxic Flow Analysis** (always-on)

Detects dangerous capability combinations within a single skill — e.g., a tool that both reads private data AND writes to public channels.

- Capability classifier labels files: `reads_private_data`, `writes_public_output`, `executes_code`, `destructive`
- TOXIC_001: Private data read + public output (exfiltration risk) — HIGH
- TOXIC_002: Private data read + code execution (credential theft) — HIGH
- TOXIC_003: Destructive actions + code execution (ransomware risk) — HIGH

### Fixed

- **NLP_HIDDEN_INSTRUCTION**: Whitelisted semantic XML tags (`<system-reminder>`, `<context>`, etc.)
- **EXFIL_009**: Excluded `openssl rand` context from base64 encode+send rule
- **EXTDL_008**: Added version-pinned scoped packages to false positive list
- **NLP_HEADING_MISMATCH**: Extended `configHeadingRe` with more benign heading patterns
- **PROMPT_INJECTION_017**: Narrowed pattern to require lack-of-oversight language
- **EXFIL_014**: Narrowed to only match credential vars in POST data, not in auth headers
- **SUPPLY_013**: Removed `@v\d+` pattern — major version pinning is acceptable
- **SUPPLY_012**: Narrowed execute patterns to require proximity to `git clone`
- **SUPPLY_009**: Removed broad `(\.\./)` pattern; kept only targeted sensitive-file traversal
- **INDIRECT_001**: Tightened fetch-to-instructions proximity window

### Summary

**142 total rules** (138 YAML + 4 dynamic from analyzers)

| Category | Rules | Severity Breakdown |
|----------|-------|-------------------|
| prompt-injection | 17 | 4 CRITICAL, 5 HIGH, 4 MEDIUM |
| credential-leak | 17 | 6 CRITICAL, 4 HIGH, 4 MEDIUM |
| exfiltration | 16 | 10 HIGH, 4 MEDIUM |
| external-download | 16 | 2 CRITICAL, 4 HIGH, 10 MEDIUM |
| supply-chain | 14 | 2 CRITICAL, 7 HIGH, 4 MEDIUM |
| command-execution | 13 | 6 HIGH, 7 MEDIUM |
| mcp-attack | 11 | 3 CRITICAL, 7 HIGH |
| mcp-config | 8 | 4 HIGH, 4 MEDIUM |
| ssrf-cloud | 8 | 3 CRITICAL, 4 HIGH, 1 MEDIUM |
| indirect-injection | 7 | 4 HIGH, 2 MEDIUM |
| unicode-attack | 7 | 3 HIGH, 4 MEDIUM |
| third-party-content | 4 | 1 HIGH, 3 MEDIUM |

**5 analyzer engines**: Pattern Matcher → NLP Injection Detector → Toxic Flow Analyzer → Rug Pull Detector → Post-processing (dedup, scoring, correlation)

---

## [0.1.0] — 2026-01-15

Initial release.

### Added

- 85 built-in rules across 8 YAML files
- 2 analyzers: pattern matcher + NLP injection detector
- Categories: prompt-injection, exfiltration, credential-leak, mcp-attack, ssrf-cloud, supply-chain, unicode-attack, external-download
- Output formats: terminal (ANSI), JSON, SARIF, Markdown
- CLI commands: `aguara scan`, `aguara init`, `aguara version`
- Flags: `--severity`, `--format`, `--fail-on`, `--ci`, `--changed`, `--verbose`, `--rules`, `--disable-rule`, `--workers`, `--output`, `--no-color`
- Config file: `.aguara.yml` with ignore patterns, severity overrides, rule disabling
- SARIF output for GitHub Code Scanning integration
