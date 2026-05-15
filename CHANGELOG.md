# Changelog

All notable changes to Aguara are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.16.0] - 2026-05-15

Aguara now ships with built-in threat intelligence. Where prior
releases caught attacks inside the code you wrote, v0.16 also
catches attacks hiding inside the packages your code installs --
event-stream, litellm, node-ipc, and ~21,500 more malicious or
compromised package versions, all checked offline.

### What's new

**Find compromised packages with one command.** Run `aguara check`
in any project and the tool figures out the rest:

```bash
# Auto-detects npm vs Python in the current directory
aguara check
```

Example output for a project that pins a known-bad version:

```
Scanning npm node_modules tree: ./node_modules
Packages read: 142

CRITICAL   event-stream 3.3.6 is a known compromised npm package (GHSA-mh6f-8j2x-4483)
           Path: ./node_modules/event-stream
           event-stream 3.3.6 shipped a malicious flatmap-stream dependency...

Action required:
  1. Remove the affected packages with `npm uninstall <name>`
  2. Rotate ALL credentials reachable from runs that included the compromised version
  3. Audit recent CI runs, especially trusted-publishing / OIDC steps
```

**Gate CI on compromised packages.** `--ci` is a one-flag CI gate:
fails the job (exit code 1) on any critical finding, no colour
codes in the log.

```bash
aguara check --ci
```

**Audit code + packages in one shot.** `aguara audit` composes the
content scan (rules, NLP, taint, etc.) with the package check and
prints a single verdict:

```bash
aguara audit --ci
```

The JSON output (`--format json`) carries both sub-results under
`.scan` and `.check`, plus a `.verdict` with per-section severity
counts so a dashboard can drill into either side.

**Refresh threat intel without rebuilding.** The default workflow
stays offline; intel comes baked into the binary. When you want
the freshest data, opt in explicitly:

```bash
# One-shot: refresh, then check
aguara check --fresh

# Or refresh the local cache once, use it on every subsequent run
aguara update
aguara check        # picks up the refreshed cache automatically
```

**Check threat-intel freshness anytime:**

```bash
aguara status
```

Prints the binary version, the embedded snapshot's date and record
count, and whether a local cached refresh exists. No network.

### Where the threat intelligence comes from

The binary ships with two sources merged into one matcher:

- **Manual list** — a hand-curated set of high-priority emergency
  advisories (event-stream, node-ipc 2022 + 2026, litellm). These
  take display precedence when an advisory also appears in OSV.
- **OSV.dev** — high-confidence malicious-package records only
  (the `MAL-*` namespace from OpenSSF Malicious Packages, plus
  records flagged as malicious-packages-origins). Generic CVE /
  DoS entries are filtered out at import time so Aguara stays
  focused on malicious packages, not general SCA.

This release embeds 21,518 records, regenerated from OSV.dev on
2026-05-15. By ecosystem: ~9,624 npm, ~1,399 PyPI. Source dump
SHA256s for reproducible regeneration:

```
osv-npm.zip   sha256: 3d5a8e00d69c170a4ba138cde35cfa4f6c21258e7d9227b5b300998f6e91b9cb
osv-pypi.zip  sha256: 1156159eac3ae589a7cc95c12fc99e022df653dc727dfd85a210227782b9360b
```

### Library API

External callers (e.g. [aguara-mcp](https://github.com/garagon/aguara-mcp))
get the same intel surface as the CLI:

- `incident.CheckResult` carries an `Intel` field describing the
  snapshot that produced the findings (`mode = offline|online`,
  `snapshot = embedded|local|remote-fresh`, sources list,
  generated-at).
- `incident.CheckOptions.Intel *IntelOverride` lets you inject a
  custom snapshot set without mutating any package-level state.
- A new `internal/intel/` package exposes `Snapshot`, `Record`,
  `Matcher`, and `Store` for consumers building their own check
  pipelines.

### Quieter CI logs

CI errors from `aguara scan`, `check`, `audit`, and `update` no
longer dump the full `--help` block on top of the error line. A
threshold-exceeded run now reads as a single clean message, not as
command misuse. Flag-parse errors (`--unknown-flag`,
`--ecosystem ruby`) still surface with a clear error message.

### Detection coverage carried over from v0.15.x track

- `aguara check` now flags the **May 2026 node-ipc compromise**
  (versions 9.1.6, 9.2.3, 12.0.1; advisory
  `SOCKET-2026-05-14-node-ipc`). The historical 2022 "peacenotwar"
  releases (10.1.1, 10.1.2, 11.0.0, 11.1.0) are tracked as a
  separate `SOCKET-node-ipc-historical-malicious` entry so the two
  incidents stay legible.
- New `jsrisk` rule `JS_DNS_TXT_EXFIL_001` detects credential
  exfiltration via DNS TXT queries (the exact mechanism the 2026
  node-ipc compromise used). Requires a real `resolveTxt`
  invocation plus at least one chain signal: CI/cloud secret read,
  on-disk credential stage, archive staged under `os.tmpdir()`,
  install-time daemonization, or a known IOC. Fires HIGH on a
  single signal, CRITICAL on three-plus or a known IOC.

### Fixed

- `install.sh` extraction now passes `-o` to tar so the install
  succeeds under hardened container runtimes that drop `CAP_CHOWN`
  (`--cap-drop ALL`, rootless containers).
- README install snippets corrected: env vars now sit on the right
  side of the pipe (`curl ... | VERSION=vX.Y.Z sh` rather than
  `VERSION=vX.Y.Z curl ... | bash`) so `VERSION` actually reaches
  the script.
- README and CI snippets pipe the installer into `sh`, matching the
  script's `#!/bin/sh` shebang and avoiding breakage on Alpine /
  BusyBox systems.
- `action.yml` `DEFAULT_REF` bumped to the current release so
  consumers who do not pin a tag fetch the right `install.sh`.

### Added

- `make test-install-sh-docker` acceptance target that exercises
  the full install path under `--cap-drop ALL
  --security-opt no-new-privileges`. Kept out of `verify-docker`
  because it requires network access.
- Docker content-claims for every command this release introduces
  (`check`, `check --ci`, `status`, `audit`, `audit --ci`) so docs
  and binary stay in sync.

### Performance

- The Python cache scan went from 30+ seconds on hosts with active
  pip/uv caches (40k+ files is common) to under a second by
  switching from per-file substring scans against the entire intel
  set to a precomputed name index keyed by PEP 503 normalisation.
  The same change removed a false-positive class where short
  record names (`4123`) or typosquat prefixes (`nump`) matched
  hex hash filenames or legitimate package prefixes.

## [0.15.0] - 2026-05-13

Minor release. Supply-chain trust analysis round: three new chain-aware scan analyzers (ci-trust, pkgmeta, jsrisk), an npm ecosystem check added to `aguara check`, four new pattern rules, and a hardened Docker validation harness. Detection coverage grows from 189 to 193 rules. JSON output shape stabilized so machine consumers see `findings: []` instead of `findings: null` on clean scans.

### Added

#### Chain-aware scan analyzers

Three new `supply-chain` category analyzers run as part of `aguara scan` and detect attack shapes that require multiple aligned signals at the same call site or syntactic structure. Single weak signals never fire.

`ci-trust` (`internal/engine/ci/`) inspects `.github/workflows/*.yml`:

- `GHA_PWN_REQUEST_001` (HIGH; CRITICAL with write perms): `pull_request_target` with PR-controlled checkout running install/build/test/interpreter code in the same job.
- `GHA_CACHE_001` (HIGH; CRITICAL with code execution): same chain plus a cache write (`actions/cache`, `actions/cache/save`).
- `GHA_OIDC_001` (HIGH; CRITICAL with publish): `id-token: write` granted on a job that also runs install/build/test. Suppressed for publish-only jobs (intended OIDC use).
- `GHA_CHECKOUT_001` (HIGH): `pull_request_target` checkout of PR head ref without `persist-credentials: false`.

`pkgmeta` (`internal/engine/pkgmeta/`) inspects `package.json`:

- `NPM_LIFECYCLE_GIT_001` (HIGH; CRITICAL on `optionalDependencies` + suspicious name): git-sourced dependency plus install-time lifecycle script (`preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`).
- `NPM_OPTIONAL_GIT_001` (MEDIUM; HIGH on suspicious name): git-sourced `optionalDependency` on its own. Suppressed when `NPM_LIFECYCLE_GIT_001` covers the same dep.
- `NPM_PUBLISH_SURFACE_001` (HIGH): `publishConfig` or publish script plus install/build/test script plus a value-aware reference to trusted publishing.

`jsrisk` (`internal/engine/jsrisk/`) inspects `.js` / `.mjs` / `.cjs`:

- `JS_OBF_001` (MEDIUM; HIGH with env/cp/network): obfuscator-shape payload (hex identifier density, dispatcher calls, `while(!![])`, plus a size or line-length signal).
- `JS_DAEMON_001` (HIGH; CRITICAL with secret/sink): real `child_process` invocation with `detached: true` AND `stdio: 'ignore'` in its own arguments.
- `JS_CI_SECRET_HARVEST_001` (CRITICAL): real `process.env` read of a CI/cloud secret (direct, bracket, optional-chaining, template-bracket, destructured forms including aliases and ESM imports) plus a network, npm registry, GitHub GraphQL, or session-exfil sink.
- `JS_PROC_MEM_OIDC_001` (CRITICAL): `/proc/<pid>/(mem|maps|cmdline|environ)` access plus `ACTIONS_ID_TOKEN_REQUEST_*` or `Runner.Worker` reference.
- `AGENT_PERSISTENCE_001` (HIGH; CRITICAL with harvest or daemonization): reference to a Claude Code automation file (`.claude/settings.json`, `.claude/router_runtime.js`, `.claude/setup.mjs`, `.claude/hooks/`) OR the pair `.vscode/tasks.json` plus `runOn: folderOpen`.

#### Pattern rules

Four targeted YAML rules complement the chain analyzers, covering shell/Python/Ruby/Perl/Go/Rust + workflow YAML + `action.yml` composite manifests:

- `SUPPLY_022` (HIGH): `ACTIONS_ID_TOKEN_REQUEST_TOKEN` / `_URL` in executable code (excludes workflow YAML, owned by `ci-trust`).
- `SUPPLY_023` (CRITICAL, match-all): `/proc/<pid>/(mem|maps|cmdline|environ)` plus `Runner.Worker` or `ACTIONS_ID_TOKEN` env in the same file.
- `SUPPLY_024` (HIGH, category `supply-chain-exfil`): Session-Network exfil endpoints (`*.getsession.org`) used in the Mini Shai-Hulud incident.
- `SUPPLY_025` (HIGH): Claude Code workspace persistence path (`.claude/settings.json`, `.claude/router_runtime.js`, `.claude/setup.mjs`, `.claude/hooks/`). VS Code persistence is handled by `jsrisk` with the precise `tasks.json` + `runOn:folderOpen` pair.

#### `aguara check --ecosystem npm`

The incident checker grows an npm branch. `aguara check --ecosystem npm --path <node_modules>` (or a project root with a `node_modules` child) walks the install graph, supports npm classic and pnpm's `.pnpm` virtual store, handles scoped packages and nested installs, and rejects fixture trees inside packages. Five historical npm advisories ship in the embedded list:

| Name | Versions | Advisory |
|---|---|---|
| `event-stream` | 3.3.6 | GHSA-mh6f-8j2x-4483 |
| `flatmap-stream` | 0.1.1 | GHSA-mh6f-8j2x-4483 |
| `ua-parser-js` | 0.7.29, 0.8.0, 1.0.0 | GHSA-pjwm-rvh2-c87w |
| `coa` | 2.0.3, 2.0.4, 2.1.1, 2.1.3, 3.0.1, 3.1.3 | GHSA-73qr-pfmq-6rp8 |
| `rc` | 1.2.9, 1.3.9, 2.3.9 | GHSA-g2q5-5433-rhrf |

The Python `aguara check` path is unchanged and continues to auto-discover site-packages.

#### Docker validation harness

New `make` targets give reproducible offline validation that any maintainer or agent can run:

- `make bench-docker`: existing target, now passes `AGUARA_VERSION` / `AGUARA_COMMIT` build args so the in-image binary reports the real revision instead of `dev` / `none`.
- `make test-race-docker`: `go test -race -count=1 ./...` inside a hardened Docker image (same Go base + digest pin, `build-base` for cgo).
- `make smoke-docker`: behavioral smokes for the npm incident check (compromised / clean / fixture-nested / bare-dir cases) and the supply-chain chain rules (pwn-request workflow + lifecycle-git package + CI-secret-exfil payload).
- `make verify-docker`: meta-target chaining bench, race, and smokes.

All Docker invocations share the existing hardened runtime: `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `/tmp` tmpfs. New artifacts: `.bench/provenance.json` and `.bench/provenance-race.json` record `aguara_version`, `aguara_commit`, `go_version`, `docker_image`, `timestamp_utc`, and command for each run. Per-target artifact cleanup at the start of each Docker target prevents stale outputs from mixing with fresh runs.

#### Analyzer micro-benchmarks

`BenchmarkCITrustAnalyzer`, `BenchmarkPkgMetaAnalyzer`, `BenchmarkJSRiskAnalyzer`, `BenchmarkIncidentNPMCheck`. No thresholds; the runs land in `.bench/go-bench-analyzers.txt` so per-analyzer cost is observable across releases.

### Changed

#### `--disable-rule` now suppresses analyzer-emitted findings

The flag previously filtered only the compiled pattern rule list, so analyzer-emitted IDs (`GHA_*`, `NPM_*`, `JS_*`, `AGENT_PERSISTENCE_001`, `TOXIC_*`, `RUGPULL_001`, NLP injection IDs) bypassed it. The filter now runs inside the scanner pipeline before tool exemptions, dedup, scoring, and min-severity filtering, so every analyzer sees the same suppression. `.aguara.yml disable_rules` benefits the same way. No flag or schema change; behavior expansion only.

#### JSON output stability: `findings: []` on clean results

Both `aguara scan --format json` and `aguara check --format json` emit `"findings": []` (and `"credentials": []` for `check`) on clean results instead of `null`. `ScanResult.MarshalJSON` normalizes at the serialization boundary, covering every producer including the CLI's auto-discover aggregate path. `CheckResult` is initialized with empty slices at construction in both `Check` and `CheckNPM`. Public schema unchanged; only the empty-list representation flips from `null` to `[]`.

#### `goreleaser` archives schema modernized

`archives[].format` / `format_overrides[].format` updated to the plural `formats: [...]` array form. Output artifacts unchanged. `brews` to `homebrew_casks` migration is intentionally deferred to a follow-up release because it changes the Homebrew tap layout from `Formula/aguara.rb` to `Casks/aguara.rb` and is user-facing.

### Fixed

- `IsCompromised(name, version)` (the legacy two-argument helper) now scopes to PyPI, so a Python package whose metadata name+version coincides with a newly-shipped npm advisory (`rc`, `event-stream`) is not falsely flagged by the Python checker.
- `/proc/<pid>/<sub>` detection correctly excludes root-level files (`/proc/meminfo`, `/proc/cmdline`, `/proc/stat`, `/proc/cpuinfo`).
- VS Code persistence detection requires the actual auto-execution primitive (`.vscode/tasks.json` plus `runOn: folderOpen`) rather than firing on either alone.
- `actions/cache/restore` no longer triggers `GHA_CACHE_001` (the action is read-only and cannot poison a downstream privileged workflow).
- `GHA_PWN_REQUEST_001` requires code execution AFTER the untrusted checkout, not anywhere in the job, so trusted setup before the PR checkout no longer creates a false chain.
- npm metadata: credentialed git URLs (`git+https://user:token@host/...`) are stripped of credentials before being emitted in finding text.

### Internal

- 7 PRs (#70 - #78) drove the round; 1 follow-up chore (#79) cleaned the GoReleaser deprecation warnings.
- 193 detection rules (up from 189), 13 categories, 7 scan analyzers (pattern, ci-trust, pkgmeta, jsrisk, NLP, toxicflow, rugpull) up from 4, ~750 tests.
- The `--disable-rule` analyzer-wide filter, `findings: []` JSON normalization, and Docker harness are durable infrastructure available to every future PR.

## [0.14.5] — 2026-04-24

Patch release. Four audit items surfaced by an external review of v0.14.4: the public library used to print credentials verbatim in scan output, the bare CLI used to phone home from CI, `--changed` used to follow committed symlinks, and `.gitignore` did not cover the obvious secret file patterns. One API addition (`WithRedaction`), one new CLI flag (`--no-redact`), one behavior change that library consumers must know about (credential-leak `matched_text` is now scrubbed by default). Plus incidental docs and dev-tooling cleanup landed in the same window.

### Added

#### `WithRedaction` option and `--no-redact` flag

Library consumers can now opt out of the new redaction default with `aguara.WithRedaction(false)`. The CLI `scan` command gained `--no-redact` with the same semantics for per-invocation opt-out. Intended for credential-rotation pipelines, detection-accuracy measurement, or other workflows that need the raw match.

#### Auto-suppress update check in recognized CI environments

`Execute()` in the root command now flips `flagNoUpdateCheck` automatically when `CI=true` (the de-facto standard, set by GitHub Actions, GitLab, CircleCI, Travis, Buildkite, Bitbucket Pipelines, Drone, Woodpecker, and most others), or when any of `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `BUILDKITE`, `JENKINS_URL`, `TEAMCITY_VERSION`, `TRAVIS` is set. `CI=false` / `CI=0` / `CI=` are correctly ignored. The existing `--no-update-check` flag and `AGUARA_NO_UPDATE_CHECK=1` env var remain as explicit opt-outs.

This addresses a real gap in the offline/deterministic positioning: the GitHub Action already passed `--no-update-check`, but anyone invoking the bare binary inside a CI job (Dockerfile, Makefile, ad-hoc script) was leaking timing and user-agent metadata from supposedly-isolated environments.

#### Repo-level `.aguara.yml` and `Running Aguara on this repo` docs

Aguara is a scanner whose own source intentionally contains attack-pattern signatures (rule YAML `examples.true_positive` blocks, `testdata/`, `sandbox/`, documentation). A clean `aguara scan .` against the repo produced ~9,600 findings dominated by by-design content. A repo-root `.aguara.yml` now scopes contributor self-scans to production code paths (~63 findings, all in test files that embed payloads). `CONTRIBUTING.md` grew a `Running Aguara on this repo` section explaining the expectation.

### Changed

#### Credential-leak findings are redacted by default (library and CLI)

Detecting a secret and then writing it verbatim to terminal output, JSON, SARIF, or an `-o` file creates a second copy of the secret in a location that often has weaker access controls than the original: CI logs retained for days, GitHub Code Scanning history, Slack notifications, shared `results.json` files checked into git by accident. The scan artifact becomes the leak.

`Finding.MatchedText` and any `Context` lines marked `is_match=true` are now replaced with the literal string `[REDACTED]` (`types.RedactedPlaceholder`) when the finding's category is `credential-leak`. Rules in other categories are untouched because their match is typically a pattern signature (e.g. `ignore previous instructions`) rather than a secret that needs protecting.

**This is a behavior change for library consumers.** Any code that was parsing `matched_text` of a CRED_* finding as the credential value itself will now see `[REDACTED]`. The known consumers:

- `oktsec` already redacts credentials in its own scanner wrapper (`internal/engine/scanner.go`). Double-redacted text stays `[REDACTED]`; no code change required.
- `aguara-mcp` returns findings to MCP clients (AI agents). Having credentials scrubbed before crossing that boundary is strictly better for most threat models; no code change required.

Consumers that genuinely need the raw match must pass `aguara.WithRedaction(false)`.

#### GitHub Action `DEFAULT_REF` bumped to v0.14.4

The fallback ref used when a consumer pins a non-semver value (`uses: garagon/aguara@main`, which the action still rejects with a warning) now points at the previous release's `install.sh`. Version string examples in the `action.yml` input descriptions bumped accordingly. No behavior change for consumers who pin a semver tag or SHA.

### Fixed

#### `--changed` scan followed committed symlinks

The regular directory walk in `internal/scanner/target.go` rejects symlinks via `info.Mode()&os.ModeSymlink`. `scanChangedFiles` got its paths from git and used `os.Stat`, which resolves symlinks to their target. A symlink committed to the repo pointing at `/etc/passwd` or `~/.ssh/id_rsa` would be followed on the next `--changed` CI run and the target's contents would surface in findings (and in any SARIF upload to GitHub Code Scanning).

Fix: `os.Stat` is replaced with `os.Lstat` and symlinks are skipped. Regression test creates a git repo with a symlink pointing to an out-of-tree secret file and asserts the symlink is not scanned.

#### `.gitignore` did not cover `.env`, `.env.*`, `*.pem`, `*.key`

Prophylactic. `git log --all` confirms the repo has never contained such files, but a scanner's own repo really should not ship a misplaced credential file by accident. `.env.example` is explicitly allow-listed so templates stay trackable.

#### Stale documentation drift

`CLAUDE.md` and `README.md` were bumped to v0.14.4 and corrected references that had fallen behind. `CONTRIBUTING.md`'s `Project Structure` block no longer claims "177 embedded rules across 12 YAML files" (real: 189 across 13). The `action.yml` example-version strings moved from `v0.14.2` to `v0.14.4`.

### Library API

New: `aguara.WithRedaction(enabled bool) Option`. Enabled by default.

New: `types.RedactedPlaceholder` (string constant, value `[REDACTED]`) and `types.RedactCredentialFindings([]Finding)` (exposed so consumers can apply the same redaction to findings they obtained via other code paths).

Changed: `aguara.Scan`, `aguara.ScanContent`, `aguara.ScanContentAs`, `(*Scanner).Scan`, `(*Scanner).ScanContent`, `(*Scanner).ScanContentAs` now scrub credential-leak matches before returning. Apply `WithRedaction(false)` at the call site to preserve the previous behavior.

No signature changes. No removed symbols. No rule-count change.

### Process

The audit items were surfaced by an external review (Codex) of the v0.14.4 repo on 2026-04-24. Two P2 items from the same audit are deferred to v0.15.0: rule target globs beyond the `*.ext` fast path (depends on the `match_mode` proximity work already planned as T1-01), and decoder-cap bypass via benign-padding (needs perf benchmarks before raising the cap or adding hash-based dedup).

## [0.14.4] — 2026-04-24

Patch release. Bundles one high-severity engine bug that silently dropped true positives since v0.14.0, plus Docker image hardening surfaced during a post-release audit. No API changes, no rule-count change. Consumers of the Go library (`aguara-mcp`, `oktsec`) should upgrade to recover dropped detections; the public API is identical.

### Fixed

#### Keyword prefilter silently dropped rule candidates on overlapping literals

The Aho-Corasick keyword prefilter introduced in v0.14.0 (commit `191f51b`) used `FindAll` for candidate lookup. `FindAll` returns non-overlapping matches, so when a shorter keyword was a prefix of a longer keyword at the same content offset, only the shorter one was emitted and every rule keyed on the longer literal was silently dropped from the candidate set. The regex layer never saw those rules, so true positives vanished without any signal that the rule had been skipped.

EXTDL_005 ("Shell profile modification for persistence") was the first observed production victim: content like `cat payload >> ~/.bashrc` matched the rule's regex in isolation but returned zero findings through the full engine because the prefilter collapsed `"bash"` (4 chars, keyword of many other rules) with `"bashrc"` (6 chars, keyword of EXTDL_005) at the same offset, and EXTDL_005 lost the race. The `zshrc` variant of the same content was detected correctly because `"zshrc"` had no short-prefix collision.

Fix: switch `candidateRules` to `IterOverlapping`, which reports every keyword match at every position. `StandardMatch` is already the configured match kind, which is the precondition the library requires for overlapping iteration.

Impact measured on `testdata/malicious/` (19 files): 98 -> 102 findings, zero lost. The four recovered are legitimate detections the prefilter had been hiding:

- `CRED_007` in `combined-attack/install.sh:4` (hardcoded password).
- `CRED_007` in `credential-leak/helper.py:6` (hardcoded password).
- `SSRF_002` in `ssrf-metadata/helper.sh:5` and `:14` (internal IP SSRF).

Surfaced by the `oktsec` team while triaging a custom inter-agent rule (`MEM-006`, npm/pip lifecycle hooks with filesystem writes). The likely breadth of affected rules is anywhere a keyword shares a short prefix with a commonly-used literal (`bash`, `curl`, `http`, `user`, `post`, etc.), but the observed production cases concentrate on shell-profile persistence rules. No known exploitation.

Performance: scanner end-to-end bench is unchanged within noise (28.3M ns/op post-fix vs. 29.1M baseline). Pattern-matcher micro-bench shows a +29% regression in isolation (202M -> 261M ns/op), but regex execution dominates real scans so it does not surface at the macro level. Still ~3x faster than the no-AC path (777M ns/op).

Regression test `TestPrefilterOverlappingKeywords` locks both directions: the longer keyword's rules must route when content has only the longer literal, and the shorter keyword's rules must NOT route when content has only the shorter literal.

#### Docker image ran as root

The published `ghcr.io/garagon/aguara` container image had no `USER` directive, so `aguara scan` ran as `uid=0(root)` inside the container. Combined with a writable `/` and BusyBox's `wget`/`nc` applets in the Alpine base, a container escape or arbitrary-file-write bug would have had unnecessarily broad blast radius on the scanning host.

Fix: add a dedicated `aguara` user (UID 10001) and switch to it before `ENTRYPOINT`. `/usr/local/bin/aguara` and `/` become non-writable; `/tmp` and user-mounted volumes work as before.

On macOS Docker Desktop the transition is transparent. On Linux, users writing output (`-o`) to a mounted host directory may need to `chown` the mount to UID 10001 or pass `--user $(id -u):$(id -g)` to match the host UID.

#### Docker base images used floating tags

`FROM golang:1.25-alpine` and `FROM alpine:3.21` without digest pins meant two rebuilds of the same commit could produce different layers, and a compromised upstream tag would flow straight into the next `docker build` without a signal. Both stages are now pinned to their current multi-arch index digests:

- `golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f`
- `alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d`

When upgrading the tag (e.g. `alpine` 3.22), bump both the tag and the digest in the same commit.

### Library API

No public API changes. `aguara.Scan`, `aguara.ScanContent`, `aguara.NewScanner`, options, and re-exported types are unchanged. Library consumers (`aguara-mcp`, `oktsec`) need no migration code; recompile against v0.14.4 and dropped true positives return automatically.

### Process

The prefilter bug was caught by `oktsec` integration triage after v0.14.3 was already out. The Docker findings came from a routine post-release inspection of the published image. Both fixes shipped with regression coverage to prevent recurrence in Tier 1 of v0.15.0.

## [0.14.3] — 2026-04-21

Maintenance release. Bundles one install-reliability fix, four rule calibration tweaks, a noisy update-check message, and a hardening change to the composite action. No engine changes, no rule-count change. There is no CVE, no known exploitation, and no action required beyond upgrading normally.

### Fixed

#### Fresh installs of v0.14.0 / v0.14.1 / v0.14.2 were failing

`install.sh` extracted the expected checksum with `grep "$file" checksums.txt | awk '{print $1}'`. After v0.14.0 started shipping per-archive SBOMs, the substring grep also matched the sibling `.sbom.json` line, so `awk '{print $1}'` returned two hashes concatenated. Every install aborted with `checksum mismatch: expected <hash1><hash2>, got <hash1>`. The script was failing **closed** - no one was silently compromised - but nobody could install Aguara fresh. Fix: exact-filename match on column 2 with awk. Users who already had v0.14.x installed (via Homebrew, `go install`, or a pre-v0.14 install.sh) were unaffected.

The bug slipped past CI because the Test Action workflow only triggers on `action.yml` / `test-action.yml` changes, and none landed between v0.14.0 and this release.

#### Four rule false positives on real-world skill docs

Detection-engineering pass over `testdata/real-skills/` (1247 files) caught four regexes firing on legitimate content without any corresponding true-positive loss:

- `PROMPT_INJECTION_004` (Zero-width char obfuscation) fired on a single UTF-8 BOM at file start. Pattern 2 now requires `{2,}` like pattern 1.
- `PROMPT_INJECTION_011` (Jailbreak template) matched `DAN` inside unrelated words - `Enable zone re` **`DAN`** `dancy`, `clippy::pe` **`DAN`** `tic`. Tokens are now anchored with `\b`.
- `UNI_001` (RTL override) fired on U+202D (LRO), which appears in legitimate mixed-direction layout. Narrowed to U+202E (RLO, the actual Trojan Source signal).
- `UNI_006` (Tag characters) had a range that missed U+E0000 (LANGUAGE TAG). Extended to the full Unicode Tag Characters block.

All true-positive coverage preserved. `testdata/malicious/` still produces 98 findings, unchanged.

#### `Update available: v0.14.2 → v0.14.2` on every invocation

The ldflag-injected binary version comes in as `0.14.2` while the GitHub Releases API returns `v0.14.2`. The equality check compared them as raw strings, so up-to-date binaries kept printing an "update available" line pointing to the same version they were running. Fix: strip the leading `v` on both sides before comparing.

The `tag_name` returned by the GitHub API is now also validated against `^v\d+\.\d+\.\d+$` before being displayed, so a future hijacked release page cannot surface arbitrary text in the user's terminal.

### Changed

#### `action.yml` no longer pulls `install.sh` from `main`

The composite action previously fetched `install.sh` directly from the `main` branch on every consumer run. That's a poor supply-chain pattern - a future compromise of the repository's write access would propagate to downstream CI without a release ever being cut, bypassing the Cosign/SBOM/SLSA signing pipeline that covers the tagged path. This is a hardening change, not a response to any observed incident.

The action now resolves the install ref from `inputs.install-script-ref` → `github.action_ref` → a baked-in tag default, rejecting anything that is not a semver tag (`vX.Y.Z`) or a 40-char commit SHA. `@main`, `@v1`, `@<branch>` all fall back to the pinned default and emit a GHA `::warning::`. Consumers who pin `uses: garagon/aguara@v0.14.3` (or any exact tag or SHA) see no behavior change.

`DEFAULT_REF` is bumped to `v0.14.3` so consumers using non-semver refs fall back to this release's fixed `install.sh`.

### Process

The fixes were surfaced by a four-angle review of v0.14.2 (offensive FN hunt, detection-engineering FP calibration, supply-chain self-audit, competitive product review). The full v0.15.x technical spec - `match_mode: all` proximity, CMDEXEC_013 recalibration, YAML frontmatter analyzer, pre-commit hook, `--remote` scan - lives outside this release and will sequence in over the next weeks.

## [0.14.2] — 2026-04-18

Patch fix caught by the new `verify-release.sh` acceptance script when running it against the freshly-published `v0.14.1`. No engine, library, or rule changes.

### Fixed

- **Docker image reported `aguara v0.14.1`** (with the leading `v`) while the tar.gz binaries reported `aguara 0.14.1` (without). The asymmetry came from `docker.yml` passing `VERSION=${{ github.ref_name }}` (raw tag name `v0.14.1`) while `.goreleaser.yml` uses `{{.Version}}` (which strips the prefix). Anything parsing `aguara version` output as semver would see two different strings depending on whether it ran the binary or the container.
- Fix: `docker.yml` now passes `VERSION=${{ steps.meta.outputs.version }}`, the same `0.14.2` form `docker/metadata-action` already uses for the image tags.

### Process win

Caught **before** announcing the release. `verify-release.sh` check 6 (extracted binary version vs. expected) failed on `v0.14.1`, the release went on hold, this patch shipped, and the script will rerun on `v0.14.2` from arm64 before this version is treated as final.

## [0.14.1] — 2026-04-18

Patch release fixing two preexisting Docker distribution bugs that were exposed only after pulling and running the published `v0.14.0` image. No engine, library, or rule changes.

### Fixed

- **`aguara version` inside the Docker image reported `dev (commit: none)`** instead of the actual release tag. The Dockerfile compiled the binary without injecting the `Version` and `Commit` ldflags, so only the `tar.gz` binaries (built by GoReleaser) carried the right values. The Dockerfile now accepts `ARG VERSION` and `ARG COMMIT` and the workflow passes the tag and SHA via `build-args`.
- **The Docker image was published only for `linux/amd64`**. Macs (Apple Silicon), AWS Graviton, GitHub ARM runners, and any Linux ARM host could not pull the image without `--platform linux/amd64` (QEMU emulation). The Docker workflow now sets up QEMU and builds for both `linux/amd64` and `linux/arm64` natively.

### Added

- `.github/scripts/verify-release.sh` runs after every tag to validate the published artifacts. Six checks: cosign-signed checksums, archive sha256 match, extracted binary version (catches missing ldflags), cosign-signed image, native pull for the host architecture (catches missing arm64 manifest), and SBOM + SLSA provenance attestations on the image. Exits 1 on the first failure with a clear message.
- `CONTRIBUTING.md` "Release Process" section documents the new step: `VERSION=vX.Y.Z .github/scripts/verify-release.sh` before announcing any release.

### Why a patch instead of a minor

Both bugs are infrastructural — they predate `v0.14.0` and slipped past the CI green check because no acceptance test ran against the actually-distributed artifact. There are no functional changes to the binary, library API, or rules. Existing consumers see the image's `version` command suddenly start reporting the right thing and the image start pulling on ARM. Neither is a behavior change anyone would script against.

## [0.14.0] — 2026-04-17

Supply-chain hardening release. Every release artifact and the container image are now cryptographically signed with Cosign keyless via GitHub OIDC, ship an SPDX SBOM, and are built reproducibly with `-trimpath`. The `install.sh` script now refuses to install when integrity verification cannot be performed. Two new evasion decoders (base32, C-style octal escapes) extend pattern-layer coverage to 8 encodings.

### Added

#### Signed releases (Cosign keyless)

`checksums.txt` is signed during release with `cosign sign-blob --bundle`, producing `checksums.txt.bundle`. The container image is signed at the digest. No long-lived signing keys; identity is proven by the GitHub Actions OIDC token at release time.

```bash
VERSION=v0.14.0
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/garagon/aguara/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

cosign verify ghcr.io/garagon/aguara:${VERSION#v} \
  --certificate-identity "https://github.com/garagon/aguara/.github/workflows/docker.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

#### SPDX SBOMs per archive

Goreleaser invokes `syft` to generate an SBOM (`<archive>.sbom.json`) for every release archive. The container image carries SBOM and SLSA build provenance attestations attached via `docker/build-push-action` (`sbom: true`, `provenance: mode=max`); fetch with `cosign download attestation`.

#### Reproducible builds (`-trimpath`)

All build paths (`Makefile`, `Dockerfile`, `.goreleaser.yml`, wasm target) now pass `-trimpath`. Strips `$GOPATH`/`$HOME` from binaries, so stack traces no longer leak the build host's directory layout, and bytes can be reproduced from a clean checkout.

#### Two new evasion decoders

Pattern layer now decodes 8 encodings (was 6):

- `base32` (RFC 4648, alphabet `A-Z` + `2-7`, min 40 chars to avoid matching ALL_CAPS identifiers, padding optional)
- `octal escapes` (`\NNN`, 4+ contiguous, first digit constrained to `[0-3]` to keep byte values in 0-255)

Both feed into the existing `DecodeAndRescan` pipeline and respect the shared `maxBlobsPerFile=10` cap.

### Changed

#### `install.sh` aborts when SHA256 tooling is missing

Previously `install.sh` issued a warning and continued the install if neither `sha256sum` (Linux coreutils) nor `shasum` (macOS, perl-Digest-SHA on minimal Linux) was available. An attacker positioned on the network could swap the binary on machines lacking those tools while users only saw a yellow warning.

Now `install.sh` checks for a SHA256 tool at startup, before any download, and aborts with a clear remediation message if neither is found. **This is technically a breaking change** for users on minimal images that lacked these tools and were silently installing without verification — but those installs were never safe.

#### `install.sh` downloads are bounded with retry

All `curl` invocations now use `--max-time` (120s for archives, 30s for the API call) and `--retry 3 --retry-delay 2 --retry-connrefused`. Hung TCP connections can no longer stall the install indefinitely; transient network blips no longer require manual rerun.

#### CI pipeline (no runtime impact)

- Go module cache enabled in `setup-go@v5` via `cache: true` (CI runs ~30-45s faster).
- `concurrency` groups with `cancel-in-progress: true` on `ci.yml`, `test-action.yml`, `docker.yml` (release.yml intentionally excluded so an in-flight release is never cancelled).
- Explicit `timeout-minutes` per job (10 CI / 15 test-action / 30 release+docker).
- `fail-fast: false` on the test-action OS matrix.
- Dockerfile runtime layer no longer installs `git` (image shrinks ~28MB → ~24MB; `aguara` never invoked git).

#### GitHub Action authenticates the GitHub API

`install.sh` (and therefore the action's install step) now sends `Authorization: Bearer ${GITHUB_TOKEN}` when the env var is present, raising the rate limit from 60/h anonymous to 5000/h authenticated. Fixes intermittent 403 failures on macOS Actions runners that share IP pools. The action passes `${{ github.token }}` into the install step automatically.

#### Test isolation for `fail-on` action job

The `test-action-fail-on` workflow job previously scanned `internal/rules/builtin/` and assumed it was clean — but as of v0.10.0 the rules detect their own `true_positive` examples (260 findings, risk 100/100). The job now scans a controlled `.github/test-fixtures/clean/` fixture (verified to produce zero findings even at `--severity info`).

### Fixed

- `install.sh`: silent-fallback bypass when SHA256 tools were missing (see Changed).
- Container image: removed unused `git` package (~5MB smaller).

### Library API

No public API changes. Existing `aguara.Scan`, `aguara.ScanContent`, `aguara.NewScanner`, options, and re-exported types are unchanged. Library consumers (`aguara-mcp`, `oktsec`) need no migration. The new decoders may produce additional `Finding` entries on payloads that were previously undetected; rule IDs and the `Analyzer` field (`pattern-decoder`) follow the existing scheme, with new `RuleName` suffixes `(decoded base32)` and `(decoded octal-escape)`.

### Known gap

The CHANGELOG entries for `v0.11.0`, `v0.11.1`, `v0.12.0`, `v0.12.1`, `v0.13.0` were not added at the time of those releases. The git history records what each one contained; reconstructing those entries is tracked separately.

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
