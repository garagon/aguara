<h1 align="center">Aguara</h1>
<p align="center"><strong>Check what your AI agents are about to trust.</strong></p>
<p align="center">Open-source security engine for agent instructions, tool configurations, and software dependencies.</p>

<p align="center">
  <a href="https://github.com/garagon/aguara/actions/workflows/ci.yml"><img src="https://github.com/garagon/aguara/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/garagon/aguara"><img src="https://codecov.io/gh/garagon/aguara/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://goreportcard.com/report/github.com/garagon/aguara"><img src="https://goreportcard.com/badge/github.com/garagon/aguara" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/garagon/aguara"><img src="https://pkg.go.dev/badge/github.com/garagon/aguara.svg" alt="Go Reference"></a>
  <a href="https://github.com/garagon/aguara/releases"><img src="https://img.shields.io/github/v/release/garagon/aguara" alt="GitHub Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/garagon/aguara" alt="License"></a>
</p>

A project brings more than source code into your environment. Its dependencies can run install scripts. Its agent settings can approve commands or start tools. Its instructions can ask an agent to read credentials or execute a helper you have not reviewed.

Aguara checks those files for known-malicious packages, suspicious behavior, and risky permissions **before you use them**. The report points you to the affected package or file so you can investigate before installing dependencies, running CI, or giving an agent access to the project.

Use it when evaluating a repository or skill, reviewing a change, or adding a security check to an agent workflow. You do not need an AI agent to use its package and code checks.

**Analysis runs locally. No package execution, content upload, telemetry, or LLM calls.**

[Quick start](#quick-start) | [Coverage](#what-aguara-checks) | [CI](#adopting-aguara-in-ci) | [Integrations](#outputs-and-integrations) | [Development](#development) | [Security](#security)

## Quick Start

Install the published release:

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/aguara/v0.29.0/install.sh \
  | VERSION=v0.29.0 sh
```

The default location is `~/.local/bin`; add it to your `PATH` if needed. The installer verifies the archive checksum. See [signature verification](#verifying-signed-releases) for verifying its signing identity, or [other installation options](#installation).

From the project directory, run:

```bash
aguara audit .
```

This combines a malicious-package check with a content scan. It does not install dependencies or run the project's commands. Read the findings before taking the next step; a passing result is not a guarantee that the project is safe.

**Trust boundary:** from v0.28.0, `audit`, `scan --ci` and the public scanning API ignore exclusions and suppressions owned by the scanned project (`.aguara.yml`, `.aguaraignore` and inline `aguara-ignore` directives) by default. A local `scan` still applies them; use `--project-policy ignore` for unfamiliar projects. In v0.29.0, a `scan` in CI without `--ci` also applies them. The development version ignores them when `scan` detects a CI environment, except a `fail_on` in `.aguara.yml`, which still applies when `--fail-on` is not passed because a failure threshold can only add a gate; a notice on stderr says what was skipped. It also prints a notice naming the files whenever applying them changed the result. Older releases may trust repository-owned policy. See the [upgrade notes](CHANGELOG.md#0280---2026-09-10) before changing an existing integration.

### Reading a finding

For example, a `.claude/settings.json` containing `"allow": ["Bash(*)"]` grants broad shell approval. Aguara reports that configuration for review. A shortened JSON finding from v0.29.0:

```json
{
  "rule_id": "AGENTCFG_BROAD_ALLOW_001",
  "rule_name": "Claude Code permissions pre-approve dangerous commands",
  "severity": 2,
  "file_path": ".claude/settings.json",
  "line": 3,
  "matched_text": "Bash(*)"
}
```

Here `severity: 2` means MEDIUM. The finding is not a claim that the project is malware. It identifies a permission decision to review: does the tool need unrestricted shell access, or can the approval be narrowed?

```bash
aguara explain AGENTCFG_BROAD_ALLOW_001
aguara audit . --verbose
aguara audit . --format json
```

Review known-malicious package matches first, then the content findings and their explanations. An exit code reflects the command's failure threshold, not the absence of every risk.

## What Aguara Checks

| What you are reviewing | What Aguara looks for | Command |
|---|---|---|
| A project | Package matches and content findings together | `aguara audit .` |
| Dependencies | Resolved packages covered by malicious-package advisories | `aguara check .` |
| Agent skills and instructions | Prompt injection, suspicious requests for secrets or execution, and tool poisoning | `aguara scan ./skills/` |
| MCP configuration | Risky tool launch commands, embedded credentials, and configuration patterns | `aguara scan --auto` |
| Agent host settings | Broad approvals, fetch-and-execute hooks, and code-injection environment settings in Claude Code `.claude/settings.json` and `settings.local.json` | `aguara scan .claude/` |
| Package-manager policy | Explicit npm and pnpm settings that relax install-time protections | `aguara scan .` |
| Project code and CI | Suspicious install hooks, credential access, execution chains, and GitHub Actions trust risks | `aguara scan .` |

`scan --auto` discovers supported MCP client configurations on the machine. Use `aguara discover` to inspect that inventory. Configuration coverage is specific to supported file formats; it does not imply support for every agent host.

### Packages and lockfiles

Lockfiles let Aguara check resolved dependencies without installing them. Coverage depends on what the file records and what the active intelligence snapshot knows.

| Ecosystem | Evidence read |
|---|---|
| npm | `node_modules`, pnpm store, `package-lock.json`, `pnpm-lock.yaml`, classic and Berry `yarn.lock`, text `bun.lock` |
| PyPI | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `pylock.toml` and `pylock.<name>.toml`, `requirements*.txt` and `constraints*.txt`, the project's virtual environment; installed `site-packages`, `.pth` files, supported cache locations |
| Go | `go.sum`, `go.mod` |
| Rust | Public-registry entries in `Cargo.lock` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |
| Java | `pom.xml`, Gradle lockfiles |
| .NET | `packages.lock.json`, supported project files |

Dependency files outside this table are not parsed, for example `npm-shrinkwrap.json`, `deno.lock`, `gems.locked`, `packages.config` and `paket.lock`, and pip requirements files under names that are not discovered (see below). `check` and `audit` list the ones they find under `coverage.unsupported_evidence`, together with lockfiles of ecosystems Aguara has no package intelligence for (`pubspec.lock`, `Podfile.lock`, `Package.resolved`, `mix.lock`), which the reports describe as such. When any are found, `audit` triage returns `review` and its action plan does not allow installing dependencies, even if other lockfiles were checked.

Matching supports exact versions and advisories affecting every version of a package. Bounded version ranges are supported for npm semver, not arbitrary ranges in every ecosystem. This is malicious-package detection, not comprehensive CVE coverage.

Unambiguous `npm:` aliases resolve to the real package in package-lock, pnpm, Yarn classic, Yarn Berry, and Bun. Classic Yarn uses the alias target name and the block's resolved version; conflicting descriptors and ambiguous non-registry identities are skipped rather than assigned a guessed package identity. Binary `bun.lockb` is not parsed; a repository with only that file returns an error asking for text `bun.lock`.

Python dependency files are read in development builds after v0.29.0 (see [Unreleased](CHANGELOG.md#unreleased)); v0.29.0 reads installed environments only. Aguara does not run uv, Poetry, Pipenv, PDM or pip to read them. Only packages resolved from a package index are matched: Git, local path, direct URL, editable and workspace entries have no PyPI identity and are skipped. Names are compared after PEP 503 normalization and versions with PEP 440 equality, so `Foo_Bar 1.0` matches an advisory for `foo-bar 1.0.0`. Findings name the file and, for TOML lockfiles and requirements files, the line of the matching entry, and list every advisory ID that matched (in the title and in the JSON `advisory_ids` array).

Packages from any index are matched by their PyPI name, including private indexes and mirrors: a lockfile cannot show whether a mirror proxies PyPI. An internal package that shares its name with a malicious PyPI package is therefore reported. Read that finding as a dependency-confusion exposure: check which index actually serves the package and pin that index for it.

In requirements and constraints files only `==` and `===` pins identify a version. Other requirements can match only advisories that cover every version; Aguara does not guess a version for them. A requirement counts as `unpinned` unless an exact pin of the same name in the same file, or in a constraint it reads through `-c`, covers it. Constraints themselves never count, and constraints files are not counted: they install nothing. The terminal report says how many unpinned entries there are, and the JSON `ecosystems` and `coverage.package_evidence` entries count them as `unpinned`. Any unpinned entry lets an install resolve a version nothing checked, so `audit` triage returns `review`, even when the rest of the file is pinned. Environment markers are not evaluated, so a pin counts for every platform. Files are decoded and split into lines as pip does; a file that declares an encoding other than UTF-8 or ASCII is an error. `-r` and `-c` includes are followed only inside the checked directory, up to eight levels of nesting (deeper nesting is an error). URL includes, includes outside the directory, includes through an environment variable and missing files are not read: each one is a WARNING finding with its file and line, so the result is not a clean pass; the JSON `ecosystems` entry counts them as `unresolved_includes`, and `coverage.unresolved_includes` lists them. Index options, hashes, editable installs and URL requirements are ignored. `pyproject.toml`, `Pipfile` and `requirements.in` declare ranges, not resolved versions, and are not read.

Only files named `requirements*.txt` and `constraints*.txt` are discovered. Files such as `dev-requirements.txt`, `test_requirements.txt` or `requirements/dev.txt` are read only when a discovered file includes them with `-r` or `-c`. Otherwise, when such a file parses as pip requirements and names at least one requirement (pinned or a range) or include, `check` and `audit` list it under `coverage.unsupported_evidence`, so the audit asks for review instead of treating it as checked. pip files under other names, for example `dev-reqs.txt` or `requirements.pip`, are neither read nor listed.

For a directory, `check` and `audit` read the same evidence: the dependency files under it and the packages installed in its virtual environment (the directory itself, `.venv`, `venv`, or `VIRTUAL_ENV` when that points inside the directory). With no path argument, both also read the active `VIRTUAL_ENV` wherever it is; an explicit path never reads an unrelated environment. An environment inside the directory is read only when it has a `pyvenv.cfg` file; conda environments and a `.venv` without `pyvenv.cfg` are not read. Below the checked directory, `.venv`, `site-packages`, `dist-packages` and `__pypackages__` directories are not searched for dependency files; every other directory is, including a virtual environment with another name. A project's virtual environment contributes installed package versions only. `.pth` inspection, persistence artifacts, credential files and caches remain part of the installed-environment check: `aguara check <site-packages>`, `--ecosystem python`, or `aguara check` with no path when the directory has no non-Python dependency files.

Lockfile and dependency-manifest inputs must be regular files no larger than 50 MiB. Leaf symlinks, including dangling links, return an error rather than being followed or silently skipped. This read boundary does not confine parent directories or guarantee that file contents remain unchanged during a check. Installed-package scanning is a separate path.

Legacy `package-lock.json` dependency trees have a 128-level nesting limit and a
50 MiB cumulative subtree-decoding budget, in addition to the file-size limit.
Exceeding either returns an error, not a partial successful package check.

### Behavior and policy

Aguara also inspects code for behaviors that do not depend on a package already being listed in an advisory: suspicious second-stage execution, credential transmission, host-file tampering, and destructive cleanup. It combines signatures, parsed configuration, bounded code analysis, and heuristic correlations. Binding checks to actual calls reduces noise, but it does not eliminate false positives or provide whole-program dataflow analysis.

The npm checks read `package.json` and project `.npmrc`; pnpm checks read `pnpm-workspace.yaml`. They flag explicit settings such as blanket script approval or weakened source restrictions. A missing setting is not reported. That does **not** prove the effective package-manager configuration is secure: the installed version, environment, and command-line overrides also matter. See [the rule reference](RULES.md) for individual checks and use `aguara explain <RULE_ID>` for their scope.

## Threat Intel

The binary includes an advisory snapshot sourced from [OSV](https://osv.dev), including [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages), alongside manually curated incident records. OSV is an open-source vulnerability database developed by Google; Aguara imports a malicious-package-focused subset, not its entire CVE database.

Descriptions mentioning malware are not enough to classify a package as malicious.
Imports require source evidence or explicitly reviewed affected versions. Older
OSV snapshots are filtered before use, including the embedded data and verified
cache, so past keyword-based classifications cannot reappear after a refresh.
See the [admission policy](internal/intel/ADMISSION.md) for accepted evidence and
the bounded historical compatibility list. This filtering requires an updated
binary; an intel refresh alone does not change older binaries.

A package finding identifies the advisory behind the match. Check that record and its affected versions when investigating; the snapshot is not a complete inventory of every malicious package.

Checks use embedded intelligence and any configured local cache without fetching the files being scanned. Refreshing intelligence is an explicit network operation:

```bash
aguara status
aguara update
aguara check . --fresh
```

`update` and `--fresh` fetch and verify Aguara's signed advisory bundle. Later checks can use the verified local cache offline. Snapshot age is context, not evidence that a dependency is safe or malicious.

The explicit `--insecure-intel` escape hatch skips signature verification only
when `AGUARA_INSECURE_INTEL=1` is also set. Such downloads are labeled unverified
and cannot be reused by default checks or `--allow-stale`. Older cache markers
do not reliably establish that a signature was verified; run `aguara update`
without `--insecure-intel` to restore verified offline use after upgrading.

Release notices are separate from analysis: `aguara version` can check for a newer release; `scan` does not. Set `AGUARA_NO_UPDATE_CHECK=1` to disable release notices. For network-isolated use, set that variable and avoid `update` and `--fresh`; no online lookup is needed to analyze the content.

## Adopting Aguara in CI

Run the audit **before** dependency installation or project commands:

```bash
aguara audit . --ci
```

`audit --ci` fails on critical findings by default. `scan --ci` uses a high-or-above threshold instead. Review the threshold for the command you integrate; they are not interchangeable.

In the development version, `--fail-on` takes the same five levels on `scan`, `check` and `audit`: `critical`, `high`, `medium`, `low` and `info`. Package findings are CRITICAL, WARNING or INFO; against a threshold, CRITICAL counts as critical, WARNING as high and INFO as info, so `audit --fail-on medium` gates on MEDIUM content findings and on every WARNING or CRITICAL package finding. `warning` is still accepted as an alias of `high`, which is exactly what it meant for `check` and `audit`, so existing gates behave as before. `scan` and `.aguara.yml` `fail_on` now accept it too; they rejected it with exit code 2. `--ci` keeps its meaning on each command. `audit --fail-on-decision review` (or `stop`) exits 1 when the triage decision is at least that restrictive, for pipelines and agents that act on the audit decision rather than on severities. When a gate trips, the error names the findings at or above the threshold, where the threshold came from (`--fail-on`, `--ci` or a `fail_on` in `.aguara.yml`) and how many baselined findings were not counted.

| Exit code | Meaning |
|---|---|
| 0 | The command completed and no gate tripped. Findings can still be present. |
| 1 | A gate tripped: `--fail-on`, `--ci`, an applied `fail_on`, or `audit --fail-on-decision`. |
| 2 | The command failed or was used incorrectly: an invalid flag or value, an unreadable target, invalid rule configuration, an incomplete scan, or `--fail-on-empty` with nothing scanned. Never treat it as a pass. |

In the development version each command's `--help` also lists its exit codes.

A scan that matches no files reports that nothing was scanned and exits 0. Add `--fail-on-empty` to a `scan` gate so a mistyped path or an empty change set fails the step with exit code 2 instead.

A CI gate should not let the repository under review decide what it sees. `--ci` sets `--fail-on high` unless `--fail-on` is given, disables color and ignores project-owned policy. In the development version, `scan` without `--ci` also ignores that policy when a CI environment is detected (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `BUILDKITE`, `JENKINS_URL`, `TEAMCITY_VERSION` or `TRAVIS` set). The one exception is a `fail_on` in `.aguara.yml`: it still applies when `--fail-on` is not passed, since a failure threshold can only add a gate. A notice on stderr names the CI variable, the policy that was skipped and any `fail_on` that was applied. Pass `--project-policy trust` only when the policy files are owned by the pipeline, not by the change being checked, and `--project-policy ignore` to skip `fail_on` too.

To introduce a gate in an existing project, record and review a baseline:

```bash
aguara audit . --write-baseline .aguara-baseline.json
aguara audit . --ci --baseline .aguara-baseline.json
```

Baseline-matched content findings remain visible but do not fail the gate. New findings are evaluated against the selected threshold. Compromised-package findings are not baselineable, and sensitive findings are omitted when writing a baseline. A missing or malformed baseline returns an error. Treat baseline changes as security decisions during review.

## Installation

The following alternatives install the published release:

```bash
# Homebrew
brew install garagon/tap/aguara

# Docker: read-only project mount, non-root container
docker run --rm -v "$PWD:/repo:ro" ghcr.io/garagon/aguara:0.29.0 audit /repo

# Go: pinned release; requires Go 1.26.0 or later
go install github.com/garagon/aguara/cmd/aguara@v0.29.0
```

Release binaries are available for Linux, macOS, and Windows on the [Releases page](https://github.com/garagon/aguara/releases). The container supports Linux amd64 and arm64. Go installs do not inject release version metadata; use release artifacts when that metadata or signature verification is required.

### GitHub Action

The Action runs a content scan, not the combined package audit. Pin both the Action and its binary:

```yaml
- uses: garagon/aguara@v0.29.0
  with:
    path: .
    fail-on: high
    version: v0.29.0
```

The default SARIF upload needs `security-events: write`. See [`action.yml`](action.yml) for inputs; use the CLI audit in a separate CI step when you also need package-intelligence checks. With a development build, SARIF locations are relative to the repository root even when `path` points below it, and the `sarif-category` input keeps several Aguara uploads in one workflow apart, for example one per package directory. Leave it empty to keep alerts in the existing analysis.

## Outputs and Integrations

`scan` offers terminal, JSON, SARIF, and Markdown output. `audit` offers a combined terminal or JSON report, and `check` offers terminal or JSON; in the development version both also write SARIF and Markdown. Use SARIF for GitHub Code Scanning; other SAST services may require a different schema.

In the development version, SARIF is shaped for code scanning:

- Every rule carries `security-severity` (CRITICAL 9.5, HIGH 8.0, MEDIUM 5.5, LOW 2.0, INFO 0.0), inside the bands GitHub documents for its [SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning): over 9.0 critical, 7.0 to 8.9 high, 4.0 to 6.9 medium, 0.1 to 3.9 low. Result levels are unchanged (CRITICAL `error`, HIGH `warning`, MEDIUM and LOW `note`, INFO `none`); the score is what separates MEDIUM from LOW. Rules also carry the `security` tag, `fullDescription`, `help` text (the description followed by the remediation) and Markdown, a `helpUri` to the rule's own row in [RULES.md](RULES.md) for built-in rules, and, for rules with an unambiguous CWE mapping, tags such as `external/cwe/cwe-079` (zero-padded like CodeQL's) and a CWE taxonomy.
- When the target is inside a git work tree, artifact URIs are relative to the work tree root (`uriBaseId` `%SRCROOT%`), so `scan ./skills` maps to repository files; otherwise they stay relative to the target. URIs are percent-encoded path segments (a space is `%20`) and are never absolute. Run properties and notification text carry no local absolute paths either: paths under the repository are made relative and others are left out. A column is reported only where the analyzer knows one.
- `partialFingerprints` (`aguara/v1`) are the baseline fingerprints, unchanged, so baseline files and tools that match on them keep working. GitHub code scanning matches alerts by rule, file path and the `primaryLocationLineHash` the upload action computes, not by this key. Baselined findings are still uploaded as results.
- `invocations[0]` records `executionSuccessful`, the exit code and why the run ends that way. `--sarif-category` sets `automationDetails.id` for repositories that upload several analyses per commit.
- `check` and `audit` report package findings at the dependency file and, where it records one, the line. Each finding class has one rule (`CHECK_COMPROMISED_PACKAGE`, `CHECK_UNRESOLVED_INCLUDE` and so on), the package, version and advisory IDs are result properties, and the fingerprint (`aguara/package/v1`) is built from the class, ecosystem, package, version and file, so it stays the same across runs and when a new advisory covers the same release; like `aguara/v1`, it is for tools that match on fingerprints, not what GitHub uses to track alerts. An unread requirements include (`CHECK_UNRESOLVED_INCLUDE`) gates like any WARNING package finding but has a `security-severity` of 5.5, because it reports a gap in what was checked rather than a compromise. A finding outside the repository, such as a global environment or a file in the home directory, is a tool notification instead of a result. `audit` puts its verdict and triage in `runs[0].properties.audit`.

JSON reports from `scan`, `check` and `audit` in the development version start with `schema_version` (`1.0`), `tool` (name, version and commit) and `catalog` (detection, pattern rule and analyzer rule counts, and a `sha256:` digest that changes whenever the rule set does); `aguara version --format json` prints the same identity. Additive changes bump the minor version and removing, renaming or retyping a field bumps the major version, so accept any `1.x` report and ignore fields you do not know. Findings keep the numeric `severity` and add `severity_label`, a `fingerprint` (the baseline and SARIF value, absent for findings whose matched text is redacted) and, when a baseline is applied, `baseline_state` (`new`, `baselined` or `non_baselineable`). Scan results add `verdict_label`. Confidence is rounded to 4 decimal places and scores to 2. Package findings add `kind`, `ecosystem`, `package` and `version`, and findings from an installed npm tree also list `advisory_ids`. JSON Schema files for the three reports are in [schema/](schema/); the test suite validates real command output against them.

Findings reported on the same file and line are still merged into the most severe one. In the development version the surviving finding lists the others in `also_matched` (rule ID, severity and category, never their matched text), the terminal and Markdown reports show `+N more on this line`, and `suppressed` counts the findings removed by deduplication, the minimum severity, disabled rules, tool exemptions and inline directives, and the files excluded by ignore patterns.

In the development version, a `--format` value a command cannot render is rejected with exit code 2 instead of falling back to the terminal report, and `-o` writes the selected format, terminal included, to the file without color. Flags such as `--severity`, `--rules`, `--disable-rule` and `--workers` are accepted only by the commands they affect; `aguara <command> --help` lists them.

JSON reports from `scan`, `check` and `audit` include a `coverage` block stating what was evaluated: files scanned, package evidence read per ecosystem and source (with an `unpinned` count where entries have no exact version), `unsupported_evidence`, dependency files that were found but that Aguara cannot evaluate (for example `deno.lock`, `gems.locked`, `Podfile.lock`, or a `dev-requirements.txt` that no discovered requirements file includes), and `unresolved_includes`, requirements includes that were not read. No packages in unsupported files were checked. Read the coverage before treating an empty result as clean.

The [Go library](https://pkg.go.dev/github.com/garagon/aguara) exposes the same content-scanning engine for tools that need analysis without a CLI subprocess:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/garagon/aguara"
)

func main() {
    result, err := aguara.ScanContent(context.Background(), "Content to inspect", "skill.md")
    if err != nil {
        log.Fatal(err)
    }
    for _, finding := range result.Findings {
        fmt.Printf("%s %s:%d\n", finding.RuleID, finding.FilePath, finding.Line)
    }
}
```

`Scan` accepts a file or directory; `ScanContent` accepts content directly without loading a file. `ListRules` and `ExplainRule` expose the catalog. Pin the Go module version in your application. Consumers can call the engine during a live workflow, but interception, authorization, session policy, and enforcement remain the consumer's responsibility.

[Aguara MCP](https://github.com/garagon/mcp-aguara) is a separate integration that exposes scanning tools to agents. Aguara itself does not require an MCP server, hosted account, or model provider.

## Limitations

- **A clean report is not a safety certificate.** Unsupported formats, dynamic code, incomplete inputs, and threats absent from the rules or intelligence can be missed. Inspect errors and what was actually scanned.
- **A finding is evidence to review, not always proof of malicious intent.** Legitimate provisioning, release scripts, and examples can resemble risky behavior.
- **Static analysis does not enforce runtime isolation.** Aguara does not sandbox a package, revoke a credential, intercept a tool call, or prevent an agent from executing a command on its own.
- **Coverage is bounded.** It does not replace application SAST, general CVE/SCA analysis, or runtime monitoring. Shell parsing and dataflow support vary by detector.
- **Results depend on the analysis inputs.** Compare findings with the same engine version, rules, configuration, intelligence snapshot, and monitor state where applicable. Timing fields are not deterministic.
- **Reports can contain sensitive material.** Review findings and context before sharing or retaining them; do not assume every part of a report is safe to publish.

## Development Version

**v0.29.0 includes the capabilities below.** The "Since" column shows the release that introduced each one. Later changes on `main` are listed under [Unreleased](CHANGELOG.md#unreleased). Building from source is not equivalent to installing a signed release.

| Capability | Since | What changes for the caller |
|---|---|---|
| Kubernetes capability requests | v0.29.0 | Explicit `SETUID`/`SETGID` additions in recognized Kubernetes workloads are reported as LOW `K8S_IDENTITY_CAPABILITIES_001` context findings in the `container-security` category, not as HIGH SUPPLY_007. Privilege commands still report SUPPLY_007. |
| Structured capability checks | v0.29.0 | MCP_009 and SUPPLY_007 read JSON/YAML structure, so capability drops, `setuid: false`, comments and descriptions no longer count as grants where the syntax is unambiguous. MCP_009 findings report the `mcp-capability` analyzer. |
| Untrusted-project policy | v0.28.0 | `audit` and `scan --ci` ignore target-owned suppressions by default; local `scan`, and in v0.29.0 a CI `scan` without `--ci`, can still trust project policy. Use `--project-policy ignore` explicitly when inspecting unfamiliar content. |
| Triage and agent handoff | v0.28.0 | Audit JSON adds `triage`, `agent_handoff`, and `action_plan`: review priorities and guidance about the next action. These fields do not enforce permissions. |
| Decision impact | v0.28.0 | Findings distinguish supporting `context` from `review` signals. Severity and explicit failure thresholds remain separate. |
| Skill and helper checks | v0.28.0 | Skill frontmatter and instruction-to-helper correlation add checks for broad tool approval and required local helpers with suspicious behavior. |
| Script analysis and catalog | v0.28.0 | Additional Python/shell analysis and unified rule enumeration expose analyzer rules through `list-rules` and `explain`. |

For a development build, clone the repository, review and check out the commit you intend to test, then run `make build`. Record that commit alongside your results. Use the resulting local binary, not an older installation on your `PATH`:

```bash
./aguara scan ./skills/ --project-policy ignore
./aguara audit . --format json
```

The v0.29.0 catalog contains **259 detections: 191 YAML pattern rules and 68 analyzer-emitted detections**. The installed binary's `aguara list-rules` is the reference for its own catalog. This count is not the number of malicious-package records in the intelligence snapshot.

## Rules and Architecture

Content analysis combines pattern matching and decoding, configuration parsers, language-specific checks, prompt-injection analysis, and bounded cross-file correlation. Fifteen per-file analyzers run by default; rug-pull tracking joins with `--monitor`. After the per-file pass, toxic-flow and skill-chain correlation run across files.

From v0.29.0, MCP_009 runs as a configuration parser: broad capability grants are
distinguished from `drop`/`deny` values and unrelated fields. Explicit Kubernetes
`SETUID`/`SETGID` requests are reported as LOW configuration observations, while
privilege commands retain SUPPLY_007. This is not a full Kubernetes compliance check.

Package-intelligence checking is a separate path used by `check` and combined with content analysis by `audit`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the package layout and [RULES.md](RULES.md) for detection details.

| Component | Responsibility |
|---|---|
| [`aguara.go`](aguara.go) | Public Go API and result types |
| [`internal/scanner`](internal/scanner) | File discovery, analyzer execution, and result collection |
| [`internal/engine`](internal/engine) | Content analyzers and their registry |
| [`internal/rules`](internal/rules) | Pattern-rule loading, compilation, and built-in definitions |
| [`internal/packagecheck`](internal/packagecheck) | Package and lockfile parsing |
| [`internal/incident`](internal/incident) | Package-intelligence checks and incident evidence |
| [`cmd/aguara`](cmd/aguara) | CLI commands and workflow integration |

```bash
aguara list-rules
aguara explain CRED_002
aguara scan . --rules ./my-rules/
```

Custom rules and local configuration can change coverage. Review `.aguara.yml`, `.aguaraignore`, custom rules, and inline suppressions before trusting a project's scan policy. Use `aguara init` to scaffold a local configuration. The `--project-policy` boundary described above is available from v0.28.0.

## Verifying Signed Releases

Release archives have checksums signed with Cosign keyless and include SPDX SBOMs. Container images are signed at their digest with SBOM and SLSA provenance attestations.

Use Cosign v2.6.5 or newer on the 2.x line, or v3.1.3 or newer on 3.x. Older versions can skip the identity check for this bundle format ([GHSA-fx35-mq7g-6g98](https://github.com/sigstore/cosign/security/advisories/GHSA-fx35-mq7g-6g98)).

Verify the signing identity as well as the checksum:

```bash
VERSION=v0.29.0
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

For the container:

```bash
cosign verify ghcr.io/garagon/aguara:${VERSION#v} \
  --certificate-identity "https://github.com/garagon/aguara/.github/workflows/docker.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

The install script checks archive integrity but does not perform this signature-verification step. A verified release identifies the publisher and artifact; it does not guarantee detection of every threat.

## Development

Use the Go version required by [`go.mod`](go.mod) and install golangci-lint for the lint target. From a reviewed checkout:

```bash
make build
make test
make vet
make lint
```

`make build` writes `./aguara`. `make test` runs the Go suite with the race detector, including positive and negative rule examples and saved fuzz inputs. The repository also includes native fuzz targets and benchmarks; see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Makefile](Makefile) for targeted runs.

This repository intentionally contains attack examples and detection fixtures. Scanning the Aguara checkout is not a substitute for running its tests, and findings in those fixtures are not evidence that the scanner itself is compromised.

## Contributing

For a bug or false positive, [open an issue](https://github.com/garagon/aguara/issues) with the engine version, command, expected result, and a minimal non-sensitive example. Discuss substantial changes before implementation. Detection changes should include positive cases and realistic benign cases, not just additional signatures.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the pull request process, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations. Changes go through pull requests and CI. Release history is in [CHANGELOG.md](CHANGELOG.md).

The previous Aguara Watch observatory is not a supported product surface. Current development focuses on the scanner and its integrations.

## Security

Report vulnerabilities in Aguara privately through [GitHub Security Advisories](https://github.com/garagon/aguara/security/advisories/new), not a public issue. See [SECURITY.md](SECURITY.md) for scope and supported versions. Do not include credentials or private project content in public reports.

## License

[Apache License 2.0](LICENSE)
