<p align="center">
  <h1 align="center">Aguara</h1>
  <p align="center">
    Open source security engine for AI agent and supply-chain trust.
    <br />
    Aguara checks the things modern projects and agents are about to trust: packages, lockfiles, install scripts, MCP configs, CI workflows, and agent tools. It runs locally, deterministically, and before execution.
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
  <a href="#why-aguara">Why Aguara</a> &bull;
  <a href="#what-aguara-checks">What it checks</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#before-install-before-delegation-before-ci">Before install / delegation / CI</a> &bull;
  <a href="#threat-intel">Threat intel</a> &bull;
  <a href="#behavioral-detection">Behavioral detection</a> &bull;
  <a href="#adopting-aguara-in-ci">CI adoption</a> &bull;
  <a href="#installation">Install</a>
</p>

https://github.com/user-attachments/assets/851333be-048f-48fa-aaf3-f8cc1d4aa594

**No SaaS account. No telemetry. No LLM calls. Signed releases. Signed threat intel.**

- **Runs locally** — your code, prompts, configs, and dependency data never leave the machine.
- **No telemetry** — nothing is phoned home.
- **No LLM calls** — deterministic static analysis, same input gives the same result.
- **Signed threat intel** — an embedded snapshot ships in the binary; fresh updates are signed and opt-in.

## Why Aguara

Modern software does not only run your code. It runs package install scripts, lockfile-resolved dependencies, CI workflows, MCP servers, agent skills, and tool configs.

Aguara checks those trust points before they execute or become part of your workflow. The recurring supply-chain pattern is simple: a legitimate package publishes a malicious version, a project installs it, and the install-time code steals tokens, cloud credentials, CI secrets, or local files. The same risk now extends to the agent layer, where an MCP server or a third-party tool description is trusted before a single line of your code runs.

So Aguara looks at the trust layer around your project and your agents, locally and deterministically, before it runs.

## What Aguara Checks

| Surface | Examples | Command |
|---|---|---|
| Packages and lockfiles | npm, pnpm, PyPI, Go, Rust, PHP, Ruby, Java, .NET | `aguara check .` |
| Package manager policy | pnpm supply-chain settings in `pnpm-workspace.yaml` | `aguara scan .`, `aguara audit .` |
| Install scripts | npm lifecycle hooks, install-time JS / Python / Rust behavior | `aguara scan .`, `aguara check .` |
| MCP configs | Claude Desktop, Cursor, VS Code, Cline, and 13 more | `aguara discover`, `aguara scan --auto` |
| Agent skills and tools | skills, prompts, tool descriptions | `aguara scan <path>` |
| CI workflows | GitHub Actions trust-chain risks | `aguara scan .github/workflows` |
| Combined audit | packages + content, one verdict | `aguara audit . --ci` |

## Quick Start

```bash
# Does this project depend on a known-compromised package?
aguara check .

# Full project audit for CI (packages + content, one verdict)
aguara audit . --ci

# Discover and scan every MCP config on this machine
aguara scan --auto

# Refresh signed threat intel for future offline checks (opt-in network)
aguara update
```

By default every command uses the threat-intel snapshot embedded in the binary. Network access is opt-in, through `aguara update` or `--fresh`.

## Before install, before delegation, before CI

Aguara is organized around the moments where trust is granted.

### Before install

`aguara check .` answers: does this project depend on a package version already known to be malicious? It reads resolved lockfiles where it has parsers, so a freshly cloned project can be checked **before any install runs**:

```bash
git clone <repo>
cd <repo>
aguara check .          # reads pnpm-lock.yaml / go.sum / Cargo.lock / ... directly
```

It also matches installed package trees (`node_modules`, the pnpm `.pnpm` store, Python `site-packages`) so existing projects and CI workspaces can be audited after the fact.

### Before delegation

Before you let an agent use a third-party skill or tool, or accept a new MCP server config, scan what the agent is about to trust:

```bash
aguara scan .claude/skills/   # skills, prompts, tool descriptions
aguara discover               # find every MCP config on the machine
aguara scan --auto            # discover and scan them
```

This catches prompt injection, tool poisoning, unsafe MCP command definitions, hardcoded secrets, exfiltration patterns, and Unicode/encoded evasion in the files agents and MCP clients consume directly.

### Before CI execution

`aguara audit . --ci` composes the package check and the content scan into a single gate, so CI can stop before it executes install-time scripts or merges a workflow change:

```bash
aguara audit . --ci     # --fail-on critical, no color, exit 1 on compromised packages
```

JSON output carries both sub-results (`.check` and `.scan`) plus per-section counts, so a dashboard can drill into either side.

## Threat Intel

Aguara matches package names and versions against a threat-intel snapshot built from:

- **[OSV.dev](https://osv.dev)** — high-confidence records only: OpenSSF Malicious Packages (`MAL-` namespace), records flagged malicious-package origin, and keyword-qualified records with exact affected versions. Generic CVE / DoS records are filtered out at import time, so Aguara stays focused on malicious packages, not general SCA.
- **[OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)** — surfaced through the OSV import above.
- **Manual emergency advisories** — a short hand-curated list of high-priority incidents, taking display precedence when an advisory ID also appears in OSV.

The snapshot ships **inside the binary**, so checks run offline by default. `aguara update` fetches fresh records over the network (the only commands that do, alongside `--fresh`), verifies them, and seeds a local cache at `~/.aguara/intel/snapshot.json` that later checks layer over the embedded snapshot automatically. A refresh that returns zero records is refused, so cached intel cannot be silently wiped.

```bash
aguara status              # version, snapshot date + record count, local-cache state (no network)
aguara update              # refresh + cache locally (opt-in network)
aguara check . --fresh     # refresh only the ecosystems this run touches, then check
```

### Coverage by ecosystem

| Ecosystem | Evidence read | Coverage |
|---|---|---|
| npm | `node_modules`, pnpm `.pnpm` store, `pnpm-lock.yaml` | Strong malicious-package coverage; `pnpm-lock.yaml` works before install. Alias-shaped (`npm:`) lockfile entries resolve to the real registry package, so a hand-edited lockfile cannot hide a compromised package behind a local dependency name. |
| PyPI | `site-packages`, `.pth`, pip/uv/npx caches | Strong malicious-package + persistence coverage. |
| RubyGems | `Gemfile.lock` | Strong malicious-package coverage. |
| NuGet | `packages.lock.json`, `*.csproj`/`*.fsproj`/`*.vbproj` | Strong exact-version coverage. |
| Go | `go.sum`, `go.mod` | Parser ready; limited exact-version embedded matches today. |
| crates.io | `Cargo.lock` (public registry only) | Parser ready; range-aware matching deferred. |
| Packagist | `composer.lock` | Parser ready; range-aware matching deferred. |
| Maven | `pom.xml`, Gradle lockfiles | Parser ready; range-aware matching deferred. |

Aguara focuses on known malicious-package records and high-confidence advisories. General CVE/range matching is the next layer, not a claim today.

## Behavioral Detection

Beyond "is this package version known-bad," Aguara has analyzers that flag install-time and runtime *behavior* in package code itself, locally and deterministically:

| Behavior | Detector |
|---|---|
| npm lifecycle hook runs local JS (`preinstall`/`postinstall`/`prepare` → `node`/`bun`) | `pkgmeta` (`SUPPLY_026`) |
| Node downloads and runs a Bun second stage to evade Node-focused monitoring | `jsrisk` (`JS_BUN_SECOND_STAGE_001`) |
| GitHub API used as a payload/command channel (write mutations, Octokit writes, REST git-data) | `jsrisk` (`JS_GITHUB_C2_001`) |
| Host trust tampering: writes to sudoers, loader preload, CA stores, SSH, hosts/resolver | `jsrisk` (`JS_SUDOERS_TAMPER_001`, `JS_HOST_TRUST_TAMPER_001`) |
| Destructive cleanup: deletes credential stores, agent files, evidence, or wipes the home directory | `jsrisk` (`JS_WIPER_TRIPWIRE_001`) |
| Python install hook fetches remote JavaScript and runs it through `node -e` | `pyrisk` (`PY_IMPORTTIME_REMOTE_JS_001`) |
| Rust `build.rs` reads wallet/keystore material and sends it to a network sink | `rsbuild` (`RS_BUILD_WALLET_EXFIL_001`) |

These are structural detections bound to real calls (a bound `child_process`/`fs` call, a real `process.env` read, a flow from a fetch to an execution sink), not text matches, so a documented command or an example string does not trigger them.

## pnpm Supply-Chain Posture

pnpm v11 ships some of the strongest supply-chain controls in the Node ecosystem: build-script approval, a release-age window for new versions, exotic-source blocking, and trust policies. Aguara verifies a project is actually using them. The `pnpm-policy` analyzer reads `pnpm-workspace.yaml` and flags settings that weaken those protections:

| Finding | Severity | Setting |
|---|---|---|
| All dependencies may run install scripts | HIGH | `dangerouslyAllowAllBuilds: true` |
| Unapproved build scripts warn instead of failing | MEDIUM | `strictDepBuilds: false` |
| Transitive deps may resolve from git/tarball URLs | MEDIUM | `blockExoticSubdeps: false` |
| Lockfile entries skip supply-chain verification | MEDIUM | `trustLockfile: true` |
| Build approval still pending for a package | MEDIUM | undecided `allowBuilds` entry |
| Release-age window disabled or not enforced | LOW | `minimumReleaseAge: 0`, non-strict mode |
| Trust policy explicitly opted out | LOW | `trustPolicy: off` |
| pnpm v10 build settings that v11 no longer honors | INFO | `onlyBuiltDependencies` and friends |

A missing setting is treated as the secure pnpm v11 default and never reported; only an explicit value less safe than the default fires. Each finding points at the exact line and ships remediation, and every rule is explainable via `aguara explain <RULE_ID>`.

## Agent Host Config Posture

A cloned repo can ship a `.claude/settings.json` that Claude Code loads when you open it. After the one-time workspace-trust prompt, its hooks and credential helpers run automatically (a `SessionStart` hook fires on session open), it can inject environment variables into every subprocess, and it can pre-disable the tool-approval prompt - all from a checked-in file. The `agent-policy` analyzer reads that file and flags what is dangerous to inherit from someone else's repo:

| Finding | Severity | What it catches |
|---|---|---|
| Hook downloads and executes remote code | CRITICAL | a hook command piping a network fetch into a shell (`curl \| sh`), run automatically on session open |
| Code-execution environment variable | HIGH | `env` setting `NODE_OPTIONS --require`, `LD_PRELOAD`, `BASH_ENV`, and similar |
| Permissions default to bypass | HIGH | `defaultMode: "bypassPermissions"` shipped in the repo |
| MCP servers auto-approved | MEDIUM | `enableAllProjectMcpServers: true` |
| Dangerous command pre-approved | MEDIUM | `allow` rules like `Bash(*)` or `Bash(curl *)` |
| Secret read pre-approved | MEDIUM | `allow` rules over `.env`, `~/.ssh`, `~/.aws`, private keys |
| Repo-shipped credential helper | MEDIUM | `apiKeyHelper` / `awsAuthRefresh` pointing at a repo-relative script |
| Auto-approving default mode | LOW | `defaultMode: "acceptEdits"` / `"auto"` shipped in the repo |

The analyzer judges the dangerous shape of a value, never the mere presence of hooks or permissions (both normal). A benign config with narrow allow rules and local hooks stays quiet.

## Adopting Aguara in CI

Adopt Aguara without turning the first CI run into a wall of pre-existing findings. `aguara audit` (and `aguara scan`) support a baseline so a new gate fails only on **new** scan findings:

```bash
# 1. Record the current scan state once.
aguara audit . --write-baseline .aguara-baseline.json

# 2. From then on, gate only on findings not in the baseline.
aguara audit . --ci --baseline .aguara-baseline.json
```

- Existing scan findings stay visible in the report; they just do not gate.
- Only **new** scan findings fail the build.
- Compromised-package findings are never baselineable — a known-malicious dependency always gates, even on the first run.
- A missing or malformed baseline fails closed.

Sensitive findings (credential leaks) are skipped when writing a baseline, so a baseline file never carries a secret forward.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install garagon/tap/aguara
```

### Docker

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/garagon/aguara:0.23.0 check /repo
```

Multi-arch (`linux/amd64` + `linux/arm64`), runs as non-root UID 10001, base images digest-pinned, and signed at the digest with Cosign plus SPDX SBOM and SLSA provenance attestations. Pin a specific release tag for reproducibility.

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh \
  | VERSION=v0.23.0 sh
```

`install.sh` downloads `checksums.txt` and verifies the archive's SHA256 against it, aborting if neither `sha256sum` nor `shasum` is available. This catches a tampered archive at the registry layer but does not verify the Cosign signature on `checksums.txt` itself; for full keyless-signature verification on the curl-pipe path, follow the Cosign step in [Verifying signed releases](#verifying-signed-releases). Default install location is `~/.local/bin`; override with `INSTALL_DIR` for CI or containers.

### GitHub Action

```yaml
- uses: garagon/aguara@v0.23.0
  with:
    path: .
    fail-on: high
    version: v0.23.0
```

Both pins are required: the action ref pins the composite action and its install script, and `version:` pins the Aguara binary it installs. Setting both keeps the workflow reproducible and dependabot-friendly. See [`action.yml`](action.yml) for all inputs.

### From source

```bash
go install github.com/garagon/aguara/cmd/aguara@latest
```

Requires Go 1.25+. Binaries built this way report `dev` version metadata (Go does not inject release ldflags). For signed releases use Homebrew, Docker, or the install script. Pre-built binaries for Linux, macOS, and Windows are on the [Releases page](https://github.com/garagon/aguara/releases).

## Outputs and Integrations

| Output / Integration | How |
|---|---|
| Terminal | `--format terminal` (default): color, severity dashboard, top-files chart |
| JSON | `--format json`: machine processing, API integration |
| SARIF | `--format sarif`: GitHub Code Scanning, IDE / SAST dashboards |
| Markdown | `--format markdown`: GitHub Actions job summaries, PR comments |
| Go library | `import "github.com/garagon/aguara"` — `Scan`, `ScanContent`, `Discover`, `ListRules`, `ExplainRule` |
| MCP server | [Aguara MCP](https://github.com/garagon/mcp-aguara): lets an agent call Aguara before it installs or trusts a tool |

A short Go example:

```go
import "github.com/garagon/aguara"

result, err := aguara.Scan(ctx, "./skills/")
result, err = aguara.ScanContent(ctx, content, "skill.md") // no disk I/O, NFKC-normalized
detail, err := aguara.ExplainRule("PROMPT_INJECTION_001")
```

GitHub Code Scanning, GitLab SAST, and plain Docker-in-CI examples are below.

```yaml
# GitHub Action with SARIF upload (needs security-events: write)
- uses: garagon/aguara@v0.23.0
  with: { path: ., severity: medium, fail-on: high, version: v0.23.0 }
```

```yaml
# GitLab CI
security-scan:
  script:
    - curl -fsSL https://raw.githubusercontent.com/garagon/aguara/main/install.sh | VERSION=v0.23.0 sh
    - aguara scan . --format sarif -o gl-sast-report.sarif --fail-on high
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

## What Aguara Is Not

- **Not a full SCA platform.** It matches known malicious-package records and high-confidence advisories, not every CVE across every version range.
- **Not a CVE scanner for arbitrary ranges.** Range-aware OSV matching is the next layer, not a claim today.
- **Not a hosted dashboard.** There is no SaaS account, no upload, no telemetry.
- **Not an LLM judge.** Detection is deterministic static analysis; there are no model calls.

Aguara complements tools like Semgrep, Snyk, CodeQL, and traditional SCA: use them for your application source and CVE coverage, and use Aguara for the trust layer around it — packages, lockfiles, install-time behavior, MCP configs, CI workflows, and agent tools.

## Rules

Aguara exposes **244 cataloged detections** through `aguara list-rules`:

- **193 embedded YAML pattern rules** across 13 categories
- **51 analyzer-emitted detections** from ci-trust, pkgmeta, jsrisk, pyrisk, rsbuild, pnpm-policy, agent-policy, NLP, toxic-flow, and rug-pull

Every YAML rule ships remediation text, surfaced in every output format and via `aguara explain <RULE_ID>`. Custom rules load from `--rules <dir>` (validated at load time; unknown fields rejected). See [RULES.md](RULES.md) for the full catalog with IDs and severities.

```bash
aguara list-rules                 # full catalog
aguara explain CRED_002           # one rule with remediation
aguara scan . --rules ./my-rules/ # add custom YAML rules
```

## Architecture

Eleven scan analyzers run per file (ten by default; rug-pull joins with `--monitor`), each catching a different class of attack:

| Analyzer | Engine | What it catches |
|---|---|---|
| Pattern Matcher | Aho-Corasick + regex, 8 decoders | Attack signatures, credential patterns, dangerous commands; decodes obfuscated payloads and re-scans |
| CI Trust | GitHub Actions YAML | `pull_request_target` chains, cache poisoning, OIDC token surface, persisted-credentials checkouts |
| PkgMeta | `package.json` JSON | npm lifecycle + git-source / publish-surface chains, install-time local JS |
| JSRisk | JavaScript single-pass | Obfuscation, install-time daemonization, CI secret harvest, OIDC runner pivot, DNS-TXT exfil, Bun second stage, GitHub C2, host-trust tampering |
| PyRisk | Python install-hook scanner | `setup.py`/`__init__.py` that fetch remote JS and run it via `node -e` (flow-sensitive) |
| RSBuild | Cargo build-script scanner | `build.rs` reading wallet/keystore material and sending it to a network sink (flow-sensitive) |
| Pnpm Policy | `pnpm-workspace.yaml` YAML | pnpm supply-chain settings weakened below the v11 defaults (build approval, release age, exotic sources, trust policy) |
| Agent Policy | `.claude/settings.json` JSON | Claude Code host config that is dangerous to inherit from a cloned repo: hooks that fetch-and-execute, code-injection env vars, `bypassPermissions`, MCP auto-approval, dangerous allow rules, repo-shipped credential helpers |
| NLP | Goldmark AST + JSON/YAML | Prompt injection, tool poisoning, proximity-weighted keyword classification |
| Toxic Flow | Capability correlation | Dangerous source/sink combinations within a file and across files in a directory |
| Rug-Pull | SHA256 change tracking | Tool descriptions that change between scans (`--monitor`) |

A separate `aguara check` / `aguara audit` path inspects installed package trees and lockfiles against the threat-intel snapshot. All content is NFKC-normalized before scanning to defeat Unicode evasion. Findings carry severity, a dynamic confidence score (0.50–0.95), matched text, file location with context, and remediation. The public Go API and CLI share one engine. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full package layout.

## Verifying signed releases

Every release is signed with [Cosign](https://github.com/sigstore/cosign) keyless, ships an SPDX SBOM per archive, and is built with `-trimpath` for reproducibility. The container image is signed at the digest with SBOM + SLSA provenance attestations.

```bash
VERSION=v0.23.0
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

```bash
# Container image signature
cosign verify ghcr.io/garagon/aguara:${VERSION#v} \
  --certificate-identity "https://github.com/garagon/aguara/.github/workflows/docker.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Configuration

Create `.aguara.yml` in your project root:

```yaml
severity: medium
fail_on: high
ignore:
  - "vendor/**"
  - "node_modules/**"
rule_overrides:
  CRED_004: { severity: low }
  EXTDL_004: { disabled: true }
  TC-005: { apply_to_tools: ["Bash"] }      # only enforce on Bash
  MCPCFG_004: { exempt_tools: ["WebFetch"] } # enforce on all except WebFetch
```

Suppress individual findings inline with `# aguara-ignore RULE_ID` (also `-next-line`, HTML/`//` comment variants).

## Aguara MCP

[Aguara MCP](https://github.com/garagon/mcp-aguara) is an MCP server that lets AI agents call Aguara before they install or trust third-party tools. It imports Aguara as a Go library (no shelling out) and exposes four tools: `scan_content`, `check_mcp_config`, `list_rules`, and `explain_rule`. No network, no LLM, millisecond scans.

## Aguara Watch

Aguara Watch is being reworked. The previous public observatory is stale and is not a supported surface for v0.23.0. The supported surfaces are the CLI, GitHub Action, Docker image, signed releases, and Go library.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, adding rules, and the PR process. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
