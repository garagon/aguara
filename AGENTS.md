# Aguara: Reference for Contributors and AI Agents

Aguara is an open-source security engine for AI agent and supply-chain trust.
It inspects skills, agent configuration, code, automation and dependencies before
they are trusted or executed. Scans are static and deterministic: they do not
execute inspected packages, call an LLM, or send telemetry.

This file describes the source checkout, not necessarily the published release.
Check `aguara version`, [development coverage](README.md#development-version)
and [unreleased changes](CHANGELOG.md#unreleased) before claiming a feature ships.
The installed binary's catalog is authoritative for that binary.

## Choose the Entry Point

| Task | Command |
|---|---|
| Inspect skills, code or agent configuration | `aguara scan ./skills/ --project-policy ignore` |
| Scan several files and directories as one report | `aguara scan SKILL.md scripts/ --root .` |
| Scan piped content (a tool description, a file about to be written) | `aguara scan - --stdin-filename SKILL.md` |
| Check dependencies against malicious-package intelligence | `aguara check .` |
| Combine content and dependency checks | `aguara audit .` |
| Produce machine-readable audit results | `aguara audit . --format json` |
| Gate a change in CI | `aguara audit . --ci` |
| Inspect the installed catalog | `aguara list-rules --format json` |
| Understand a detection | `aguara explain SC-EX-007` |
| Refresh signed advisory data | `aguara update` |

Default scans use embedded or available local intelligence offline. `update`
and explicit freshness options fetch data; those operations are not offline.
`check` detects known malicious packages, not comprehensive CVE/SCA coverage.
See [package coverage](README.md#packages-and-lockfiles) for evidence and
version-matching limits.

## Trust Boundary

From v0.28.0, `audit` and `scan --ci` ignore target-owned policy (`.aguara.yml`,
`.aguaraignore`, inline `aguara-ignore` directives) by default. In this checkout,
`scan` also ignores it when a CI environment is detected, except a `fail_on` in
`.aguara.yml` when `--fail-on` is not passed (a threshold can only add a gate),
and says so on stderr. It prints a stderr notice naming the files whenever
applying the policy changed the result. A local `scan` can still trust
it. Use `--project-policy ignore` when inspecting unfamiliar content. Content piped to
`scan -` never applies project policy, and `--project-policy trust` is rejected there.
Commit hooks (`aguara init --hook`, `.pre-commit-hooks.yaml`) apply the committer's own
policy; enforce in CI with `--project-policy ignore`.
The public Go scanning APIs ignore target-owned `.aguaraignore` and
inline suppression directives by default. `WithTrustedTargetPolicy()` opts in
when the caller owns that policy.

Older binaries may honor repository-owned exclusions. Check the version before
relying on this boundary.
Caller-supplied exclusions, overrides and custom rules also affect coverage.

A clean result means no matching finding in the analyzed input, not proof of
safety. Never turn an error or incomplete scan into a successful clean result.
Review reports before sharing: redaction does not guarantee that every field is
safe to publish.

## Go API

Public constructors and aliases live in [aguara.go](aguara.go); options live in
[options.go](options.go). Use the module API rather than importing `internal/`.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/garagon/aguara"
)

func main() {
    scanner, err := aguara.NewScanner(aguara.WithWorkers(2))
    if err != nil {
        log.Fatal(err)
    }
    result, err := scanner.ScanContent(context.Background(), "Content to inspect", "skill.md")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%d findings\n", len(result.Findings))
}
```

Build a reusable `Scanner` once for repeated requests. Package-level `Scan`,
`ScanContent` and `ScanContentAs` also exist. The filename selects relevant
analyzers; do not relabel every input as text. `ScanContentAs` supplies tool
context. A single inline scan does not inspect neighboring files.

Important options:

- `WithDisabledRules(ids...)` and `WithRuleOverrides(...)`: caller-owned catalog
  controls for pattern and analyzer rules alike. IDs must exist in the loaded
  catalog (case-insensitive).
- `WithMinSeverity(...)`: reported-finding threshold.
- `WithMaxFileSize(bytes)`: disk-read limit, default 50 MiB; does not cap inline content.
- `WithIgnorePatterns([]string{...})`: caller-owned exclusions in the `.aguaraignore`
  syntax (`dist/` excludes every `dist` directory, `/build` only the root one; a
  pattern without a slash matches file names only; `!` negation is unsupported and
  never matches). Repeated use accumulates; earlier versions kept only the last call.
- `WithCustomRules(dirs...)`: additional YAML rules. Repeated use accumulates
  directories; it does not replace earlier ones.
- `WithStateDir(dir)`: enables stateful rug-pull tracking.
- `WithRedaction(false)`: exposes raw sensitive evidence; do not use by default.
- `WithLenientConfig()`: skip invalid rule configuration instead of failing;
  the skipped problems are returned by `Scanner.ConfigProblems()`.

Invalid rule configuration (a custom rule that does not compile or reuses an
existing rule ID, an unknown rule ID in a disable list or override, an invalid
override severity, conflicting tool scopes) makes `NewScanner`, the scan
functions and `ListRulesE` return a `*ConfigError`; use `errors.As` to read its
problems. `ListRules` returns nil in that case. `ExplainRule` reports an unknown
ID with an error matching `errors.Is(err, ErrRuleNotFound)` and reports rule
loading problems as themselves.

Consumers must bound inline inputs and execution resources themselves. A context
does not guarantee immediate interruption of every parser or regular expression.
Do not advertise a hard real-time deadline from this API.

## Result Contracts

Use the actual types in [internal/types/types.go](internal/types/types.go),
exported through public aliases, rather than copying a partial struct.

- Severity is numeric in JSON: INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4.
- `decision_impact` distinguishes `context` and `review`; it is not a downstream
  application's allow/block policy.
- `verdict` (clean=0, flag=1, block=2) depends on the scan profile. A finding
  from a rule named in `WithProfileEnforcedRules` blocks under every profile
  except `minimal`. Otherwise the default `strict` profile blocks on any HIGH or
  CRITICAL finding, `content-aware` flags HIGH or CRITICAL findings, and
  `minimal` never blocks and flags enforced-rule and HIGH or CRITICAL findings.
  No profile reports `clean` while a HIGH or CRITICAL finding remains. Findings
  are reported in every profile.
- The CLI (`--profile`) and the WASM build have no enforcement list, so there
  `content-aware` and `minimal` behave the same: HIGH or CRITICAL findings flag
  and nothing blocks.
- The verdict is computed from the findings that remain after disabled rules,
  tool exemptions (built-in or tool-scoped overrides) and the minimum-severity
  filter. These can remove an enforced rule's finding before the verdict sees it.
- `matched_text`, description and context may be redacted. Do not parse them as
  stable identifiers or expect raw secrets.
- Go results have `Duration time.Duration`; JSON exposes `duration_ms`.
- Empty scan findings serialize as `[]`, not `null`.
- CLI JSON from `scan`, `check` and `audit` carries a `coverage` block: files
  scanned, package evidence read (with `unpinned` counts),
  `unsupported_evidence` (dependency files found but not evaluated, each with
  a `reason`, including manifests such as `package.json` or `pyproject.toml`
  that declare dependencies without a lockfile, `manifest_without_lockfile`)
  and `unresolved_includes` (requirements includes not read). Zero files,
  zero evaluated evidence, unsupported files, a manifest without a lockfile or
  any unpinned requirement is not a clean result. Only the exact pins of
  unsupported files are matched (`exact_pins_checked`), except a
  `format_not_parsed` requirements file with `skipped_lines`: it was read
  and matched in full except for those lines. Library `ScanResult` values
  leave `coverage` unset.
- `ListRules` and `ExplainRule` include pattern and analyzer metadata.
  `RulesLoaded` counts compiled pattern rules, not the entire available catalog.
- Availability does not imply activation: `RUGPULL_001` is explainable without a
  state store, but rug-pull analysis needs one.

`audit` has its own aggregate output, including triage and agent-handoff guidance
from v0.28.0. Do not assume it has the same schema as `ScanResult`. Severity,
confidence, score and decision impact are distinct. Keep downstream identity,
session policy and enforcement decisions outside Aguara's core.

## Architecture and Change Ownership

| Source | Responsibility |
|---|---|
| `aguara.go`, `options.go` | Public API and reusable scanner |
| `cmd/aguara/commands` | CLI, audit composition and report workflows |
| `internal/scanner` | Discovery, input loading and analyzer execution |
| `internal/engine/engine.go` | Shared analyzer registration and metadata |
| `internal/rules`, `internal/rulecatalog` | Pattern compilation and unified catalog |
| `internal/packagecheck` | Lockfile and dependency-manifest parsing |
| `internal/incident`, `internal/intel` | Intelligence, provenance and package matching |
| `internal/output`, `internal/types` | Reports, result contracts and redaction |

Content checks combine patterns, decoding, configuration parsing, language-specific
analysis and heuristic correlation. They are not a whole-program semantic proof.
The pattern matcher is caller-registered; the shared registry adds stateless
analyzers. Rug-pull is optional. Toxic-flow and skill-chain correlation also have
cross-file paths. See [RULES.md](RULES.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

Before adding a rule, check existing ownership. Preserve rule IDs when moving
detection into an analyzer, and verify library/CLI catalog consistency. Add
realistic positive and benign fixtures, including comments, examples, aliases
and nearby unrelated evidence where relevant. Do not weaken negatives just to
make a rule pass.

Use structured parsers for structured inputs. Go regex uses RE2 without
lookaround. Do not claim dataflow or full shell parsing from file-level
co-occurrence. Keep parser errors distinct from empty valid input. Preserve
source locations and redact evidence before output.

## Validation and Delivery

Inspect `git status` before editing. Preserve unrelated changes. Work on a branch
and submit focused PRs describing behavior, compatibility, tests and known limits.

Use the Go version in [go.mod](go.mod). Run focused tests first; CI runs broader
checks. Respect the operator's resource budget. Do not start fuzzing, benchmarks
or sustained stress work without explicit authorization. Static fixtures must
not execute malicious examples, install package scripts or alter host trust.

For releases, use the checked-in workflows and verification scripts. Update pins
through the existing guardrail. Distinguish development builds from signed
releases and validate artifacts before announcing them. Do not publish a tag,
deploy content or bypass branch protection merely because local tests passed.
