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

On `main`, `audit` and CI scans ignore target-owned policy by default. A local
`scan` can still trust it. Use `--project-policy ignore` when inspecting unfamiliar
content. The public Go scanning APIs ignore target-owned `.aguaraignore` and
inline suppression directives by default. `WithTrustedTargetPolicy()` opts in
when the caller owns that policy.

These controls are development features until released. Older binaries may honor
repository-owned exclusions. Check the version before relying on this boundary.
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

- `WithDisabledRules(ids...)` and `WithRuleOverrides(...)`: caller-owned catalog controls.
- `WithMinSeverity(...)`: reported-finding threshold.
- `WithMaxFileSize(bytes)`: disk-read limit, default 50 MiB; does not cap inline content.
- `WithIgnorePatterns([]string{...})`: caller-owned directory exclusions.
- `WithCustomRules(dir)`: additional YAML rules.
- `WithStateDir(dir)`: enables stateful rug-pull tracking.
- `WithRedaction(false)`: exposes raw sensitive evidence; do not use by default.

Consumers must bound inline inputs and execution resources themselves. A context
does not guarantee immediate interruption of every parser or regular expression.
Do not advertise a hard real-time deadline from this API.

## Result Contracts

Use the actual types in [internal/types/types.go](internal/types/types.go),
exported through public aliases, rather than copying a partial struct.

- Severity is numeric in JSON: INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4.
- `decision_impact` distinguishes `context` and `review`; it is not a downstream
  application's allow/block policy.
- `matched_text`, description and context may be redacted. Do not parse them as
  stable identifiers or expect raw secrets.
- Go results have `Duration time.Duration`; JSON exposes `duration_ms`.
- Empty scan findings serialize as `[]`, not `null`.
- `ListRules` and `ExplainRule` include pattern and analyzer metadata.
  `RulesLoaded` counts compiled pattern rules, not the entire available catalog.
- Availability does not imply activation: `RUGPULL_001` is explainable without a
  state store, but rug-pull analysis needs one.

`audit` has its own aggregate output, including triage and agent-handoff guidance
on `main`. Do not assume it has the same schema as `ScanResult`. Severity,
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
