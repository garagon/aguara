# Changelog

All notable changes to Aguara are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Local Python and shell scripts now contribute concrete behavior evidence:
  decoded or character-constructed Python values reaching `exec`/`eval`,
  remote Python response bodies flowing into execution, structured systemd
  or cron persistence, and real pip/npm commands using unencrypted dependency
  sources. Python files that read high-trust local context and then perform a
  bound HTTP write are also surfaced for review.
  The existing `SC-EX-007` persistence rule keeps its ID while moving from a
  flat pattern to the script analyzer, so saved policies remain compatible.

### Changed

- `aguara audit` JSON now includes an additive `triage` block with a
  deterministic `proceed` / `review` / `stop` decision, reasons, and
  next steps for humans, CI dashboards, and agent workflows. The
  existing `verdict.status`, `threshold_exceeded`, and exit-code
  behavior are unchanged.
- `aguara audit` now also emits agent handoff guidance derived from
  triage, with explicit `allowed`, `review_only`, or `blocked` status
  plus allowed and blocked actions for agent workflows. This gives AI
  coding tools a safer pre-execution contract without changing scan
  findings, gates, or exit codes.
- `aguara audit` JSON now includes an additive `action_plan` block with
  machine-readable permissions for install, execution, CI, repo agent
  config, editing, and finding explanation. It is derived from triage
  and agent handoff so wrappers and MCP clients can apply the same
  trust decision without parsing prose.
- README positioning now leads with when to run Aguara - before
  install, before CI, or before handing a repo to an AI coding agent -
  and adds a short "When to Use Aguara" section mapping real trust
  decisions to the corresponding commands.

## [0.27.0] - 2026-06-12

The terminal experience grows up. Every Aguara command now speaks the
same visual language, adapts to where its output is going, and the
parsers that read attacker-controlled files gain a native fuzz harness
that runs nightly. JSON, SARIF, and markdown outputs are unchanged.

### Added

- **Shared terminal style layer** (#221): one palette, severity icons,
  section headers, and separators across `scan`, `check`, `audit`,
  `explain`, and `clean` - commands no longer hand-roll their own ANSI
  codes. `aguara audit` opens with a framed header, lists findings in
  aligned columns under `PACKAGE CHECK` and `CONTENT SCAN` sections,
  and closes with a framed verdict (green PASS, yellow FINDINGS, red
  FAIL). New `--verbose` flag on `audit` lists every content finding
  instead of capping at 10. `aguara --help` groups commands by
  workflow and shows copy-paste examples; `scan` and `audit` close
  with a `Next: aguara explain <rule>` hint for the most severe
  finding.
- **Native fuzz harness** (#223): 22 Go fuzz targets covering every
  parser that touches untrusted input - the ten lockfile parsers
  behind `aguara check`, the pattern engine with its NFKC
  normalization and 8-decoder rescan, the markdown/JSON/YAML NLP
  extractor, the JS/Python/Rust scanners, the policy analyzers, and
  the custom-rule loader. Each target asserts the parser never panics
  and never emits a finding without a rule ID. Seed corpora run inside
  `make test`; a nightly workflow fuzzes each target for 60 seconds
  and uploads any crasher as a reproducible artifact. `make fuzz` runs
  the same loop locally. Initial shakeout: ~37M executions, zero
  crashes.

### Fixed

- **Terminal detection** (#220): color and the progress spinner now
  turn themselves off when stdout is not an interactive terminal -
  piped output, file redirection, and CI logs no longer collect ANSI
  escape codes or spinner frames. `NO_COLOR` now covers every command,
  including `explain` and `clean`, which previously ignored it.
  Separators and the spinner size themselves to the real terminal
  width. `aguara audit` renders the FINDINGS verdict in yellow instead
  of green: exit code 0 with unresolved findings is not a clean pass.

### Changed

- Dependency updates: Go modules minor/patch group (#222);
  `actions/checkout` v6, `github/codeql-action` v4,
  `goreleaser-action` 7.2.2 (#186, #187, #188).

## [0.26.0] - 2026-06-11

Threat-intel coverage grows by an order of magnitude. Until now the
advisory importer kept only records with exact affected versions; OSV
advisories that describe affected versions as ranges were dropped. A
measurement pass (#216) showed over 99% of those malicious range
advisories share one shape: every version of the package is malicious.
Matching that shape needs no version comparison at all, so this release
imports them - around 196,000 npm and 6,400 PyPI packages that were
invisible to `aguara check` before now flag at any installed version.
Checks stay offline and deterministic; the JSON output contract is
unchanged.

### Added

- **All-versions advisory matching** (#217): OSV malicious records
  whose ranges mark every version affected (`introduced: 0`, no upper
  bound) are imported as a compact `(ecosystem, package) -> advisory ID`
  set and matched by name alone, in any ecosystem. The match result
  carries a synthesized summary and the `osv.dev` reference for the
  advisory. The snapshot format gains a parallel `all_versions`
  section: old binaries ignore it, new binaries accept old snapshots.
  Both range channels require the firm malicious-package signal
  (`MAL-` namespace or OpenSSF malicious-packages origin); the
  keyword channel qualifies exact-version records only, because a
  keyword false positive on a range would flag every version below
  the bound.
- **npm bounded-range advisories** (#218): malicious npm records with
  real version boundaries are now kept at import and evaluated by the
  existing semver engine (introduced inclusive, fixed exclusive,
  verified against real OSV shapes). OSV `limit` events close the open
  segment conservatively - versions at or above the limit never match.
  Ranges the matcher cannot evaluate (GIT-typed, empty events) are
  dropped rather than imported dead. npm only, by measurement: the
  bounded-range residual outside npm is single digits.
- **Regenerated embedded snapshot** (OSV 2026-06-11): 26,268 records
  plus 202,526 all-versions entries (was 23,926 records, no entries).
  Blob 1.0 -> 3.1 MB gzipped; measured steady-state intel heap 32.7 MB.
  `aguara status` reports the all-versions entry count alongside
  records.

### Changed

- README coverage table updated per ecosystem: all-versions advisories
  match everywhere, version-range evaluation is npm semver only -
  documented as a measured decision, not a deferral.

## [0.25.0] - 2026-06-11

npm v12 (estimated July 2026) makes install-time trust explicit:
dependency install scripts, git dependencies, and remote tarballs stop
behaving as implicit defaults. Aguara now reviews those trust decisions
before install, in CI, and before an agent inherits them. Everything
stays deterministic and offline: no package execution, no network calls
during a scan. Existing rule IDs, severities, and the `Severity` JSON
encoding are unchanged.

### Added

- **npm-policy analyzer** (`internal/engine/npmpolicy/`), the twelfth
  scan analyzer. Reads `package.json` (the `allowScripts` policy) and
  the project `.npmrc`, and flags install-trust decisions weakened
  below the npm v12 baseline, with four rules (category
  `supply-chain`): `NPM_DANGEROUS_ALL_SCRIPTS_001` (HIGH, the
  documented approve-all escape hatch left committed),
  `NPM_ALLOW_SCRIPTS_UNPINNED_001` (MEDIUM, name-only approvals or
  `allow-scripts-pin=false`), `NPM_ALLOW_GIT_RELAXED_001` and
  `NPM_ALLOW_REMOTE_RELAXED_001` (MEDIUM, resolution pinned open
  against the v12 default of none). A missing setting never fires.
  Parser behavior is verified against real npm 11.16.0: pinned vs
  name-only approvals, deny entries, inline comments, quoted values,
  repeated keys (last-wins), empty boolean assignments, and manifest
  key case-sensitivity.
- **npm v12 readiness findings** (pkgmeta): two INFO rules,
  `NPM_GIT_INSTALL_TRUST_001` and `NPM_REMOTE_INSTALL_TRUST_001`, turn
  git and remote-tarball dependency declarations into migration
  information - which explicit trust exceptions the project will need
  under npm v12 - with exact line anchors. INFO severity never fails
  default CI thresholds. URL classification follows npm's actual
  install gates (verified via EALLOWGIT / EALLOWREMOTE): hosted
  repository URLs need allow-git; archive, tarball and release
  endpoints need allow-remote; a `.git` URL on an unknown host is a
  remote dependency unless it uses a `git+` scheme (this also corrects
  the pre-existing git classification in the lifecycle and optional-git
  rules). Credentialed source URLs are redacted from finding output.

### Changed

- **`SUPPLY_026` wording** no longer claims npm always runs lifecycle
  hooks automatically: it now describes the install-time execution path
  as conditional on npm versions or configurations where dependency
  scripts are allowed, matching the npm v12 model.
- Rule catalog grows to 250 cataloged detections (193 YAML + 57
  analyzer-emitted) across 12 analyzers.

## [0.24.0] - 2026-06-10

Extends Aguara's trust layer in both directions: what an AI agent is
about to obey, and what a package manager is about to install. On the
agent side, a cloned repo's Claude Code settings are now vetted before
their hooks and helpers run, and agent instruction files like
`.cursorrules` and `AGENTS.md` are treated as the high-trust prompt
surfaces they are. On the package side, pnpm projects are checked for
weakened supply-chain policy, and Bun and Yarn Berry lockfiles join the
pre-install parsers, so every major npm-family lockfile can now be
audited before a single install script runs. The rule catalog grows to
244 cataloged detections (193 YAML + 51 analyzer-emitted) and gains an
`agent-trust` category. Everything stays deterministic and offline:
no package execution, no network calls during a scan. Existing rule
IDs, severities, and the `Severity` JSON encoding are unchanged.

### Added

- **agent-policy analyzer** (`internal/engine/agentpolicy/`). A cloned
  repo can ship a `.claude/settings.json` that Claude Code loads when
  the workspace is trusted; from then on its hooks and credential
  helpers run automatically. The new analyzer reads
  `.claude/settings.json` / `settings.local.json` and flags host
  configuration that is dangerous to inherit from someone else's repo,
  with eight new rules in the new `agent-trust` category:
  - `AGENTCFG_HOOK_FETCH_EXEC_001` (CRITICAL): a hook command downloads
    and runs remote code (`curl | sh`, `eval $(curl ...)`), executed
    automatically when a session opens in the repo.
  - `AGENTCFG_ENV_EXEC_001` (HIGH): the `env` block sets a
    code-execution variable (`NODE_OPTIONS --require`, `LD_PRELOAD`,
    `BASH_ENV`, and similar).
  - `AGENTCFG_BYPASS_PERMS_001` (HIGH): `permissions.defaultMode` is
    `bypassPermissions`, weakening tool approval for the workspace.
  - `AGENTCFG_MCP_AUTOAPPROVE_001` (MEDIUM):
    `enableAllProjectMcpServers: true` auto-loads every `.mcp.json`
    server.
  - `AGENTCFG_BROAD_ALLOW_001` (MEDIUM): a blanket or dangerous
    `permissions.allow` rule (`Bash(*)`, `Bash(curl *)`).
  - `AGENTCFG_SECRET_READ_ALLOW_001` (MEDIUM): an allow rule over a
    secret path (`.env`, `~/.ssh`, `~/.aws`, private keys).
  - `AGENTCFG_HELPER_REPO_SCRIPT_001` (MEDIUM): a credential helper
    (`apiKeyHelper`, `awsAuthRefresh`) runs a repo-shipped script.
  - `AGENTCFG_PERMS_WEAK_MODE_001` (LOW): `defaultMode` is `acceptEdits`
    shipped as a project default.

  A missing setting is treated as the secure default and never fires;
  the analyzer judges the dangerous shape of a value, not the presence
  of hooks or permissions. Claude Code is the first agent-policy
  surface; the same posture applies to other agent host configs.

- **Agent instruction files treated as a high-trust prompt surface.**
  Files agentic coding tools load as persistent context --
  `.cursorrules`, `.windsurfrules`, `.clinerules`, `AGENTS.md`, and
  `copilot-instructions.md` -- are now run through the prompt-injection
  (NLP) analyzer even when they have no `.md` extension, and a finding
  in one is weighted up rather than getting the documentation penalty a
  README receives. An injected directive in these files is closer to
  the agent's operating instructions than to prose, so the same payload
  scores higher here. The directory-scoped Cursor and Windsurf rule
  formats (`.cursor/rules/*.mdc`, `.windsurf/rules/*`) and pattern-rule
  coverage of the extensionless files are a follow-up. `CLAUDE.md` is
  intentionally left out for now: it is so widely used for legitimate
  project instructions that flagging it needs a dedicated
  false-positive pass first.

- **pnpm-policy analyzer** (`internal/engine/pnpmpolicy/`). pnpm v11
  ships real supply-chain controls -- build-script approval, a release
  age window, exotic-source blocking -- but a single
  `pnpm-workspace.yaml` line can quietly turn them off. The new
  analyzer reads `pnpm-workspace.yaml` and flags settings weakened
  below the v11 defaults, with nine new rules (all category
  `supply-chain`):
  - `PNPM_DANGEROUS_BUILDS_001` (HIGH): `dangerouslyAllowAllBuilds: true`
    lets every dependency run install-time lifecycle scripts without
    approval.
  - `PNPM_STRICT_DEP_BUILDS_DISABLED_001` (MEDIUM): `strictDepBuilds:
    false` downgrades unapproved build scripts from a failure to a
    warning.
  - `PNPM_EXOTIC_SUBDEPS_DISABLED_001` (MEDIUM): `blockExoticSubdeps:
    false` lets transitive deps resolve from git/tarball URLs.
  - `PNPM_TRUST_LOCKFILE_001` (MEDIUM): `trustLockfile: true` skips
    supply-chain verification for lockfile entries.
  - `PNPM_BUILD_APPROVAL_PENDING_001` (MEDIUM): an `allowBuilds` entry
    left undecided means a build script is still pending review.
  - `PNPM_MIN_RELEASE_AGE_DISABLED_001` / `_NON_STRICT_001` (LOW): the
    release-age window is disabled or not strictly enforced.
  - `PNPM_TRUST_POLICY_OFF_001` (LOW): `trustPolicy: off` set
    explicitly.
  - `PNPM_LEGACY_BUILD_POLICY_001` (INFO): pnpm v10 build settings that
    v11 no longer honors (migrate to `allowBuilds`).

  A missing setting is treated as the secure v11 default and never
  fires. Only the exact camelCase keys pnpm honors in
  `pnpm-workspace.yaml` match (verified against pnpm 11.5.2: a
  kebab-case key there is silently ignored by pnpm, so flagging it
  would be a false positive). YAML merge keys (`<<:`) are expanded, and
  each finding points at the exact line.

- **bun.lock and yarn Berry lockfile parsing** (`aguara check` /
  `aguara audit`). A freshly cloned Bun or Yarn v2+ project can now be
  audited before install: `bun.lock` (the text lockfile) and `yarn.lock`
  Berry (v2+) join the existing `pnpm-lock.yaml` / `package-lock.json` /
  classic `yarn.lock` parsers. Both resolve `npm:` aliases to the real
  registry package -- Bun records it as the resolved first element, Berry
  as the `resolution:` field -- so a compromised package cannot hide
  behind a local alias. Conservative, like the other npm parsers: only
  exact registry tuples are emitted; git/file/workspace/patch sources and
  ranges are skipped, and results dedupe on (name, version). A Berry
  lockfile previously errored out as unsupported; it is now parsed.
  The legacy binary `bun.lockb` is not parsed (it cannot be read without
  running Bun); a repo whose only lockfile is `bun.lockb` fails with a
  clear message to commit the text `bun.lock` instead, rather than
  passing as audited with zero packages read.

- **`npm:` alias resolution in `pnpm-lock.yaml`** (`aguara check` /
  `aguara audit`). An alias-shaped lockfile entry such as
  `safe-ipc@npm:node-ipc@9.2.3` now matches advisories for the real
  registry package (`node-ipc@9.2.3`), never the local alias name.
  pnpm itself normalizes aliased installs to real-name lockfile keys
  (verified on pnpm 8/10/11), so this is hardening for hand-edited or
  poisoned lockfiles and historical shapes rather than a gap in normal
  installs. Unscoped and scoped aliases, scoped real targets,
  leading-slash and peer-decorated keys are handled. Only unambiguous
  aliases with an exact pinned version resolve; ranges, dist-tags,
  malformed specs, and non-registry sources (`workspace:` / `file:` /
  `link:` / `github:` / `git:` / `http(s):` / `jsr:`) are skipped, and
  alias + direct entries for the same package dedup to one finding.

## [0.23.0] - 2026-06-07

Expands Aguara's offline coverage of supply-chain behavioral attack
chains, informed by the Red Hat / Miasma npm worm. Six new behavioral
detections span the chain from install-time execution through second
stages, repository-as-control channels, host trust tampering, and
destructive cleanup. Intel freshness is now visible in `check` /
`audit` / `status`, and the JavaScript analyzer is faster. Everything
stays deterministic and offline: no package execution, no network calls
during a scan. Existing rule IDs, severities, and the `Severity`
JSON encoding are unchanged.

### Added

- **npm lifecycle scripts that run local JavaScript** (`SUPPLY_026`,
  pkgmeta analyzer). Flags a `package.json` whose install-time lifecycle
  hooks (`preinstall` / `install` / `postinstall` / `prepare` and the
  related pre/post keys) execute a local `.js` / `.cjs` / `.mjs` file,
  `node -e`, or a `bun` stage. This is the entry point of the Miasma
  chain, where a published package runs its own code the moment it is
  installed.
- **Node-to-Bun second-stage execution** (`JS_BUN_SECOND_STAGE_001`,
  jsrisk). Flags package code that shells out to the Bun runtime as a
  second stage and pairs it with a strong supply-chain signal
  (obfuscator-shape payload, CI/cloud secret read, or a network exfil
  sink). Running an ordinary Bun command never fires on its own.
  CRITICAL when a secret read and an exfil sink are both present.
- **Repository used as a payload or command channel**
  (`JS_GITHUB_C2_001`, jsrisk). Flags code that writes or controls
  GitHub-hosted content (a GraphQL write mutation, an Octokit write
  method, or a REST contents / git-data write to `api.github.com`) and
  pairs it with a strong partner that a normal release bot does not
  carry. CRITICAL when a non-GitHub credential is also read.
- **Sudoers privilege tampering** (`JS_SUDOERS_TAMPER_001`, jsrisk).
  Flags a real write to `/etc/sudoers` or `/etc/sudoers.d/*`, whether a
  bound filesystem write or a bound shell redirect / `tee` / `sed -i`.
  CRITICAL when the written content grants passwordless or unrestricted
  sudo. Validation-only (`visudo -c`) and `chmod` without a write do not
  match.
- **Host trust surface tampering** (`JS_HOST_TRUST_TAMPER_001`, jsrisk).
  Flags a write to the dynamic linker preload (`/etc/ld.so.preload`), a
  CA certificate store, the SSH daemon config, the global shell profile,
  or name resolution (`/etc/hosts`, `/etc/resolv.conf`) pointed at a
  sensitive domain.
- **Destructive wipe of sensitive paths** (`JS_WIPER_TRIPWIRE_001`,
  jsrisk). Flags a real deletion of a credential store
  (`.ssh` / `.aws` / `.gnupg` / `.kube` / `.azure` / `.docker` / gcloud),
  agent or editor trust (`.claude` / `CLAUDE.md` / `.cursorrules` /
  `.vscode`), shell history, an evidence log, or a honeytoken, plus a
  broad wipe of `$HOME` / `~` / `/root` / root. Detection is by the
  actual delete capability of the call (a non-recursive `rm`, an
  `unlink`, or a `fs/promises` call that has no such method cannot
  destroy a directory), through a bound `fs` / `fs-extra` / `rimraf`
  delete or a bound shell `rm` / `unlink` / `rmdir` / `find -delete`.
  Build and cache cleanup (`node_modules`, `dist`, `/tmp`) does not
  match. CRITICAL on a broad home or root wipe, on deleting two distinct
  credential stores, or when paired with a strong partner.

This closes the chain end to end: install hook, second stage, control
channel, host tampering, destructive cleanup. Coverage is static and
chain-gated, not a claim of complete worm detection.

### Changed

- **Advisory intel freshness is now visible.** `aguara check`,
  `aguara audit`, and `aguara status` show the age and source of the
  embedded or refreshed advisory intel, and JSON output gains an
  `age_days` field and a real `stale` flag. This is informational only:
  it never changes exit codes, `--fail-on`, or a verdict, and under
  `--ci` the freshness note goes to stderr so stdout stays clean.
- **Faster JavaScript risk analysis.** The jsrisk analyzer now masks
  comments, regex-literal bodies, and string interiors in a single
  shared pass, so code-token signals (network sinks, child-process
  spawns, env reads, obfuscation shape) no longer match inside comments
  or strings. The shared pass is about 8% faster than before with far
  fewer allocations. No rule or severity change.

### Notes

- Rule catalog is now 193 YAML rules plus 34 analyzer-emitted rules
  (227 cataloged) across 9 scan analyzers. The new detections are
  emitted by the existing `pkgmeta` and `jsrisk` analyzers; no new
  analyzer was added.

## [0.22.2] - 2026-06-03

### Fixed

- Completes offline detection for the Red Hat/Miasma npm compromise. Aguara now covers the full OSV/GHSA-confirmed set of affected `@redhat-cloud-services/*` package versions, so `aguara check` and `aguara audit` can catch the incident across installed dependencies and npm lockfiles without executing package code or querying a registry during the scan.

### Notes

- This is an intel-only patch. Matching remains exact by package and version; clean neighbouring releases stay clean.

## [0.22.1] - 2026-06-01

Offline detection for the Red Hat / Miasma npm compromise reported on
2026-06-01. `aguara check` and `aguara audit` flag the affected
`@redhat-cloud-services/*` packages by exact package and version, with no
package execution and no registry lookup during the scan. This is a
focused incident-response patch; rule IDs, severities, and
offline-by-default behavior are otherwise unchanged.

### Added

- **Red Hat / Miasma npm compromise intel.** Adds the advisory
  `AIKIDO-2026-06-01-redhat-miasma` to the built-in known-compromised
  list, covering the 32 affected `@redhat-cloud-services/*` packages and
  the malicious versions enumerated in the public report. The malicious
  releases declared a `preinstall` hook running `node index.js` and
  shipped an obfuscated install-time payload that harvested CI/OIDC
  tokens, npm/PyPI publish tokens, cloud credentials, Vault tokens,
  kubeconfig, SSH/GPG keys, Docker registry credentials, and `.env`
  files, published via GitHub Actions OIDC trusted-publishing abuse.
  Detection works across `node_modules`, `package-lock.json`,
  `pnpm-lock.yaml`, and `yarn.lock` (classic). Matching is exact by
  (ecosystem, package, version), so neighbouring clean releases stay
  clean.

## [0.22.0] - 2026-05-29

Check more npm projects before install, and reduce false positives on
two high-risk install-script rules. `aguara check` now reads
`package-lock.json` and `yarn.lock` (classic) pre-install, alongside the
existing `pnpm-lock.yaml` support, and two co-presence rules become
flow-sensitive bindings. Rule IDs, severities, and offline-by-default
behavior are unchanged.

### Added

- **Pre-install npm coverage for `package-lock.json`.** `aguara check`
  reads `package-lock.json` on a freshly cloned npm project, before
  `npm install` has created `node_modules`. It parses lockfile versions
  1, 2, and 3, resolves npm aliases (`"alias": "npm:real@ver"`) to the
  real registry package, and conservatively skips local / git /
  workspace / aliased entries it cannot map with confidence to a
  registry (name, version). Exact and npm range advisories both apply.
- **Pre-install npm coverage for `yarn.lock` (classic v1).** The same
  pre-install audit for Yarn classic projects, with the same
  conservative skip rules. A Yarn Berry (v2+) lockfile is detected and
  reported with a clear error instead of being parsed, so a Berry repo
  is never silently treated as audited. Berry parsing is a future layer.

So a freshly cloned npm, pnpm, or Yarn classic project can be checked
before any install runs.

### Changed

- **Flow-sensitive binding for two high-risk rules.**
  `PY_IMPORTTIME_REMOTE_JS_001` (Python install hooks that fetch and
  `node -e` remote JavaScript) and `RS_BUILD_WALLET_EXFIL_001` (Cargo
  `build.rs` scripts that read wallet/keystore material and send it)
  moved from co-presence pattern rules to dedicated flow-sensitive
  analyzers. They now fire only when the source value reaches the
  execution or exfiltration sink within one or two hops, instead of when
  the two halves merely co-occur in the same file. This cuts false
  positives on both rules; the rule IDs and severity are unchanged.

### Deprecated

- `intel.Update` (the library helper that fetched OSV directly) is now
  marked deprecated in favor of the signed-bundle refresh path added in
  0.21.0. The API is retained for compatibility and no CLI path uses it.

## [0.21.0] - 2026-05-28

Trusted fresh threat intel. `aguara update` and `--fresh` checks now
refresh from a signed advisory bundle that Aguara publishes and verifies
before use, instead of fetching OSV directly. Detection rules, advisory
coverage, and offline-by-default behavior are unchanged.

### Added

- **Signed advisory bundles for `--fresh` / `aguara update`.** Aguara
  publishes a signed advisory bundle (the same snapshot it embeds) on a
  schedule. `aguara update`, `aguara check --fresh`, and
  `aguara audit --fresh` fetch that bundle and verify it in-process
  before trusting it: Sigstore signature + the expected publisher
  identity, then the manifest against the blob (schema, name, sizes,
  SHA-256 digests) and a schema-compatible decode. A bundle that fails
  any check is never used and never written to the cache (no partial
  writes). Verification is offline (the Sigstore trusted root is
  embedded).
- **`--insecure-intel`** (on `update` / `check` / `audit`): skips only
  the signature/identity check for mirrors, air-gapped hosts, and tests.
  It requires both the flag and `AGUARA_INSECURE_INTEL=1`, is never read
  from config, prints a warning on every run, and still enforces the
  manifest/blob digest and schema checks.

### Changed

- **`--fresh` no longer fetches OSV directly.** It refreshes from
  Aguara's signed advisory bundle, which covers all supported
  ecosystems. OSV is consumed and signed in the publishing workflow, not
  at runtime.
- **`--allow-stale` falls back only to previously verified local
  intel.** A successful verified refresh records a provenance marker; on
  a failed refresh, `--allow-stale` reuses the local cache only when that
  marker is present and matches the snapshot, and errors otherwise
  rather than silently using unverified data.

### Upgrade note

A local snapshot cached by an older version has no verification marker,
so it is ignored by default and by `--allow-stale`. This is intentional:
unverified cached intel is not trusted. Run `aguara update` once after
upgrading to seed the verified local cache. Default `aguara check` keeps
working offline against the binary's embedded snapshot in the meantime.

## [0.20.0] - 2026-05-28

Scan baseline / diff mode plus a smaller, more maintainable embedded
advisory snapshot. No detection-engine changes and no change to advisory
coverage or runtime matching behavior.

### Added

- **Scan baseline / diff mode.** `aguara scan --baseline <file>` gates
  only on findings that are not already recorded in a baseline, so CI can
  adopt Aguara on an existing repository without failing on pre-existing
  findings. `--write-baseline <file>` records the current findings as
  accepted. `aguara audit --baseline` / `--write-baseline` apply to the
  scan half only; known-malicious package (check) findings always gate.
  Fingerprints are line-independent (they survive line churn) and
  per-occurrence (distinct findings in one file stay distinct).
  Secret-bearing findings are never baselineable and are always reported.
  Baseline metadata is surfaced in the terminal footer, the JSON
  `baseline` summary, and SARIF `partialFingerprints`. `.aguara.yml`
  accepts a `baseline:` key.

### Changed

- **Embedded advisory snapshot is now compressed.** The build-time OSV
  snapshot ships as gzipped JSON via `go:embed` instead of a generated Go
  literal, alongside a committed `generated_intel.meta.json` sidecar
  (record count, ecosystems, content hashes) that keeps a regeneration
  reviewable. Snapshot contents and runtime matching are unchanged; the
  binary is roughly 11 MB smaller. `aguara update` and
  `tools/update-intel` now emit the gzipped bundle plus the sidecar.
- **Documentation describes the toxic-flow analyzer as capability
  correlation / source-sink co-occurrence** rather than taint tracking,
  to match what the analyzer actually does.

The intel schema version and the on-disk update-cache format are
unchanged.

## [0.19.0] - 2026-05-25

Range-aware malicious-package matching plus static behavioral detection
for confirmed TrapDoor-style payloads. This extends Aguara from exact
incident advisories into version-range matching for supported semver
ecosystems and deterministic detection of two payload shapes from the
TrapDoor campaign. It is range + behavioral coverage for the confirmed
TrapDoor surfaces, not full coverage of the campaign.

### Added

- **Range-aware matching for supported semver ecosystems (npm).** The
  intel matcher now evaluates OSV-style version ranges, not just exact
  versions, for ecosystems whose grammar a semver engine can resolve
  (npm in this release). `aguara check` now flags the 16 npm TrapDoor
  packages npm security-held in their entirety (OSV records them as
  `introduced:0`, every version malicious) at any installed version,
  offline, across installed npm trees and pnpm lockfiles. These ride
  hand-curated range-only advisories under `SOCKET-2026-05-24-trapdoor`;
  the rule deliberately does not embed OSV's full npm range corpus.
- **`PY_IMPORTTIME_REMOTE_JS_001`** (supply-chain, CRITICAL): detects a
  Python package that, at install or import time (`setup.py` /
  `__init__.py`), downloads remote JavaScript and runs it through Node
  (`node -e` / `--eval`). Requires the fetch of a `.js` payload and the
  Node eval together; mentions of Node or JavaScript in docs do not
  trip it.
- **`RS_BUILD_WALLET_EXFIL_001`** (supply-chain, CRITICAL): detects a
  Cargo build script (`build.rs`) that reads crypto wallet/keystore
  material (Sui / Move / Solana / Aptos) and sends it over the network.
  Requires an actual keystore read plus a network exfil sink; a build
  that only compiles native code or only reads a path does not fire.

Both behavioral rules are static pattern detections and do not execute
package code. Analyzer-level data-flow hardening for each is tracked as
follow-up work.

## [0.18.4] - 2026-05-25

Patch release adding local threat-intel advisories for the TrapDoor
crypto-stealer supply-chain campaign (Socket, 2026-05-24). `aguara check`
now blocks the confirmed malicious package/version tuples offline, without
waiting for an embedded OSV snapshot refresh. Scope is limited to the 12
packages with an exact confirmed malicious version; the campaign's
range-only npm packages and its crates.io packages are intentionally not
listed because no exact malicious version is available for them yet. No
detection rules or analyzers changed.

### Added

- **Local advisories for the TrapDoor crypto-stealer campaign.** `aguara
  check` now blocks the confirmed malicious package/version tuples from
  the TrapDoor supply-chain campaign (Socket, 2026-05-24) under advisory
  `SOCKET-2026-05-24-trapdoor`: 5 npm packages at `1.0.12`
  (`build-scripts-utils`, `dev-env-bootstrapper`, `llm-context-compressor`,
  `prompt-engineering-toolkit`, `token-usage-tracker`) and 7 PyPI packages
  at `0.1.0`/`0.1.1` (`cryptowallet-safety`, `data-pipeline-check`,
  `defi-risk-scanner`, `env-loader-cli`, `eth-security-auditor`,
  `git-config-sync`, `solidity-build-guard`). Detection is offline and
  covers pnpm lockfiles, installed npm trees, and installed Python
  environments. Only tuples with an exact confirmed malicious version are
  included; the campaign's range-only npm packages and its crates.io
  packages (no exact version available yet) are intentionally not listed.

## [0.18.3] - 2026-05-21

Patch release closing four built-in rule false negatives caused by the
Aho-Corasick keyword prefilter trusting weak literal evidence.
`MCPCFG_003` ("Hardcoded secrets in MCP env block") on payloads naming
the env var `API_KEY` and `SSRF_002` / `SSRF_006` / `SSRF_009` on
content with `http://` rather than `https://` were silently filtered
out by `aguara scan` even though their YAML rule self-tests passed.
The same shape also affected user-authored custom rules with top-level
alternations like `api|secret`. No detection rule was changed; the fix
is entirely in the prefilter's keyword extraction.

### Fixed

- **Pattern prefilter no longer silently filters rules whose literal
  evidence is hidden inside weak alternation branches or optional
  characters.** The keyword extractor used by the Aho-Corasick
  prefilter now treats an alternation as filterable only when every
  branch produces at least one literal of `minKeywordLen` or more.
  This applies to alternation groups (`(api|secret)`), top-level
  alternations in a regex pattern (`api|secret` with no enclosing
  parens, the form a custom rule might write directly), and nested
  alternations. Alternations with even one weak branch contribute no
  keywords; outer literals carry the filter when present. Optional
  quantifiers (`?`, `*`, `{0,n}`) on a literal character now trim
  that character from the indexed keyword, so a regex like
  `https?://` indexes "http", not "https". Optional groups
  (`(...)?` and friends) likewise contribute no keywords. Under
  `match_mode: any`, a rule with any unfilterable pattern now falls
  back to "always run" instead of being filtered on the remaining
  patterns' literals. Concrete impact on built-in rules: `MCPCFG_003`
  ("Hardcoded secrets in MCP env block"), `SSRF_002`, `SSRF_006`,
  and `SSRF_009` were silently filtered out by `aguara scan` even
  though their YAML rule self-tests passed. They now reach the regex
  stage on every applicable file. A new
  `TestRuleSelfTestsRunThroughMatcher` in `internal/engine/pattern/`
  runs every built-in rule's `true_positive` through the real
  `Matcher` (prefilter included) so future drift in keyword
  extraction (or in custom rule authoring with top-level
  alternations) surfaces in CI.

## [0.18.2] - 2026-05-19

Patch release fixing duplicate findings when `aguara check --fresh`
pulls a refreshed OSV snapshot that has caught up to a hand-curated
manual advisory. Without the fix, a single real-world exposure
showed up as two findings: one for the manual advisory ID and one
for the OSV one. `aguara check` (offline default) was unaffected
because the embedded snapshots did not overlap.

### Fixed

- `aguara check` and `aguara audit` now emit one Finding per
  `(ecosystem, name, version, path)` tuple even when multiple
  intel records cover the same exposure. The check output layer
  collapses duplicates to a single Finding; the matcher itself
  keeps returning every record so correlation consumers see the
  full set. `EmbeddedSnapshots()` returns the manual snapshot
  first, so the curated advisory ID wins the title when both
  manual and OSV cover the same tuple. User-facing advisory tokens
  stay stable across `aguara check` and `aguara check --fresh`.

### Compatibility

Drop-in for v0.18.1. No JSON schema changes, no flag renames, no
rule ID changes. JSON consumers that drove `findings_count` off
the `--fresh` path will see a lower count for projects exposed to
the AntV wave once OSV ingested the same tuples; the underlying
exposure is identical, the count now reflects one row per real
exposure.

## [0.18.1] - 2026-05-19

Patch release adding manual threat-intel coverage for the May 2026
npm supply-chain incident affecting AntV visualization libraries
and a small set of related packages. The embedded OSV snapshot did
not carry these tuples at the time of release, so `aguara check`
returned clean on installed trees and `pnpm-lock.yaml` lockfiles
that pinned the malicious versions. v0.18.1 closes that gap.

### Added

- Manual `KnownCompromised` entries for the @antv wave: `@antv/g2`,
  `@antv/g6`, `@antv/x6`, `@antv/l7`, `@antv/f2`, `@antv/data-set`,
  `@antv/g-image-exporter`, `@antv/infographic`, plus
  `echarts-for-react`, `timeago.js`, `size-sensor`, `canvas-nest.js`.
  Twelve packages, 22 confirmed compromised versions. Every entry
  is verified against `registry.npmjs.org`: the `deprecated` field
  on the version carries an explicit security, `"risk"`, `"published
  in error"`, or malicious-version notice from the package
  maintainer. Versions without that registry signal are not
  included even when third-party trackers list the package.
- IOC metadata on the @antv advisory carrier entry for the direct
  HTTPS exfiltration channel (`t.m-kosche.com`,
  `/api/public/otel/v1/traces`).
- Regression test
  `TestKnownCompromisedSnapshotGeneratedAtCoversFreshestEntry` that
  walks every dated entry in `KnownCompromised` and requires the
  manual snapshot's `GeneratedAt` to be at or after the freshest
  entry. Future intel additions that forget to bump the timestamp
  fail the suite with a direct pointer at `intel_adapter.go`.

### Changed

- `knownCompromisedGeneratedAt` bumped to `2026-05-19` to cover the
  new entries.

### Compatibility

Drop-in for v0.18.0. No schema changes, no flag renames, no rule
ID changes. Consumers reading `verdict.status` and `ecosystems[]`
continue to see the same field shapes; the @antv-affected projects
now produce CRITICAL findings where v0.18.0 was silent.

The TanStack / Mistral / UiPath wave reported in the same campaign
is already covered by the embedded OSV snapshot (`MAL-2026-3432`
and adjacent `MAL-2026-*` records) and is not duplicated by the
manual intel.

## [0.18.0] - 2026-05-18

`aguara check .` now reads `pnpm-lock.yaml` directly. A pnpm
project freshly cloned from git — no `pnpm install` yet, no
`node_modules` — is now checked against the embedded npm
threat-intel snapshot the same way an installed npm tree is.
Compromised packages declared in the lockfile surface as CRITICAL
findings before any install runs.

This closes the largest gap in v0.17.x's "supply-chain check"
story: the public framing claimed Aguara walked the dependency
surface of a modern repo, but pnpm — the package manager a large
slice of modern Node projects use — had no pre-install coverage.
`aguara check .` returned `ecosystems: []` for the npm pipeline on
any pnpm repo until the user ran `pnpm install` first.

### Added

- **`pnpm-lock.yaml` parser in the packagecheck path** (#119).
  Refs are routed through the existing npm ecosystem so they
  match against the same OSV npm advisories the installed-tree
  pipeline uses. No new ecosystem, no new OSV bucket. Coverage:
  - modern v6+ keys (`name@version`, `@scope/pkg@version`)
  - legacy v5 slash-form keys (`/name/version`, `/@scope/pkg/version`)
  - v9+ paren-encoded peer-dep suffixes including scoped peers
    (`@commitlint/cli@19.6.1(@types/node@22.10.2)`)
  - pre-v9 underscore-encoded peer-dep suffixes
  - dedup of peer-resolved duplicate entries so a package
    consumed with multiple peer resolutions counts once
  - deterministic output ordering (sorted keys)
  - rejection of non-registry sources: `workspace:`, `file:`,
    `link:`, `github:`, `git:`, `http:`, `https:`
- **`aguara check .` (no flags) now autodetects pnpm-lock.yaml
  alongside the other six packagecheck ecosystems and the
  installed-tree npm path.** A repo with both `pnpm-lock.yaml`
  and `node_modules` produces two `ecosystems[]` entries with
  `source: "pnpm-lock.yaml"` and `source: "node_modules"`
  respectively so consumers see both surfaces independently.
- **`aguara check --ecosystem npm`** now covers both surfaces.
  Gated on `node_modules` existing so a pnpm-only repo (no
  install yet) no longer errors with "no node_modules
  directory"; the packagecheck lockfile pipeline runs in that
  case.

### Changed

- `aguara check` terminal output for single-ecosystem npm plans
  now reads "Scanning npm dependencies" instead of "npm
  node_modules tree". The neutral wording covers both the
  installed-tree and pnpm-lock-only surfaces without
  misrepresenting either.

### Compatibility

Drop-in for v0.17.x. No schema changes, no flag renames, no rule
ID changes. Consumers reading `verdict.status` and `ecosystems[]`
continue to see the same field shapes; pnpm projects will start
producing additional entries where the array was empty before.

## [0.17.1] - 2026-05-18

QA backlog patch release. Four release-blocker bugs surfaced by
end-to-end testing of v0.17.0 in Docker are fixed. No new
analyzers, no schema changes to existing tools, no new commands.
Verified end-to-end side-by-side against `ghcr.io/garagon/aguara:0.17.0`.

### Fixed

- **MCPCFG_003 leaked captured matched_text into JSON and SARIF output** (#108). The rule was missed in the original `sensitive:` flag rollout. Now carries `sensitive: true`; `RedactSensitiveFindings` scrubs `matched_text` before any output formatter sees it. Regression tests pin the YAML→runtime→output chain.
- **`aguara check` JSON output was missing npm and PyPI entries in `ecosystems[]`** (#114, closes #109). The incident path that handles npm and PyPI initialised `Ecosystems` to an empty non-nil slice and never appended an entry of its own. Dashboards iterating `ecosystems[]` for coverage saw "npm/PyPI not covered" even when packages were checked and findings fired. Both paths now append one `EcosystemResult` per call with `ecosystem`, `path`, `source`, `packages_read`, `findings_count`. Unreadable target directories now return an explicit error instead of silently emitting a misleading "scanned 0 packages" entry.
- **`aguara check [path]` ignored positional arguments** (#116, closes #111). `aguara check ./myrepo` silently scanned the current directory because the runtime only read `--path`. The positional form is now accepted via `cobra.MaximumNArgs(1)`; `--path` and the positional together produce an explicit `ambiguous path` error rather than silent precedence.
- **`aguara audit` reported `verdict.status: "pass"` when criticals existed** (#117, closes #110). The verdict status is now tri-state `pass | findings | fail`: `pass` only when zero findings, `findings` when findings exist but no gate (`--ci` / `--fail-on`) was crossed (exit 0), `fail` when the gate was crossed (exit non-zero, unchanged from v0.17.0).

### Backward compatibility notes

- `verdict.status` in `aguara audit` output may now be `"findings"` in cases where v0.17.0 returned `"pass"`. Consumers that switch on `{"pass", "fail"}` should add a `"findings"` arm or treat it as a non-fail signal. The `"fail"` arm continues to fire on exactly the same input set; `ThresholdExceeded` is unchanged.
- `ecosystems[]` in `aguara check` JSON may now contain entries where v0.17.0 returned `[]` for npm-only or PyPI-only paths. Consumers iterating the array unconditionally already handle this; consumers checking `len == 0` as "not scanned" should look at the per-entry data instead.

## [0.17.0] - 2026-05-17

`aguara check .` now walks the dependency surface of a modern repo
instead of stopping at npm/Python. v0.17 adds offline malicious-package
checks across npm, PyPI, Go, Rust, PHP/Composer, Ruby/Bundler,
Java/Maven/Gradle, and .NET/NuGet, built from OSV.dev + OpenSSF
Malicious Packages records.

### Added

- Recursive multi-ecosystem `aguara check`. Running `aguara check .` from a repo root walks the path for npm `node_modules`, Python `site-packages`, plus lockfiles for Go (`go.sum`/`go.mod`), Rust (`Cargo.lock`, crates.io registry only), PHP (`composer.lock`), Ruby (`Gemfile.lock`), Java (`pom.xml`, `gradle.lockfile`, `gradle/dependency-locks/*.lockfile`), and .NET (`packages.lock.json`, `*.csproj`/`*.fsproj`/`*.vbproj`). One `EcosystemResult` entry per discovered lockfile; top-level `findings[]` stays flat.
- `--ecosystem` now accepts multiple values, comma-separated (`--ecosystem go,ruby`) or repeated (`--ecosystem go --ecosystem ruby`). Aliases: `python`, `pypi`, `golang`, `cargo`, `rust`, `php`, `composer`, `gem`, `rubygems`, `java`, `dotnet`, `csharp`.
- `aguara audit` now uses the same multi-ecosystem check plan as `aguara check`, so `audit --path . --format json` includes the recursive `ecosystems[]` slice.
- Embedded threat-intel snapshot now ships records for all 8 ecosystems (23,926 records total, up from ~21,500 in v0.16). Strong embedded coverage today on npm, PyPI, RubyGems, NuGet; parser-ready coverage on Go, crates.io, Packagist, Maven (range-aware OSV matching deferred to a follow-up).

### Changed

- `aguara update` default refreshes every supported ecosystem (npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven, NuGet) instead of only npm + PyPI. Use `--ecosystem` to scope a refresh.
- `aguara check --fresh` now refreshes only the ecosystems the plan actually touches. `aguara check --fresh --ecosystem maven` no longer pulls npm + PyPI as a side effect of the legacy default. `--fresh` on an empty plan skips the network entirely.
- `aguara check` terminal output for multi-ecosystem runs frames the scan as "project dependencies" and reports `Targets found:` instead of the single-ecosystem `Lockfiles found:` line. Action guidance for packagecheck-routed ecosystems no longer recommends `aguara clean` (which only knows Python persistence artifacts).
- Default `aguara check` on an explicit `--path` with no signals returns a clean result with `"ecosystems": []` instead of silently falling back to the host's global Python `site-packages`.
- README "Aguara Watch" section: previous public observatory is stale; section now states Watch is being reworked and points users at the scanner / CLI / Docker image / signed release artifacts as the supported v0.17 surfaces.

### Known limitations

- Range-aware OSV matching is deferred. Go / crates.io / Packagist / Maven ship parsers with limited current coverage today because their OSV streams are CVE/range-shaped and the matcher only consumes exact versions. Tracking issue: [#105](https://github.com/garagon/aguara/issues/105).

## [0.16.2] - 2026-05-16

Patch release. Closes the P1 secret-leak found in the v0.16.1 security audit.

### Fixed

- Aguara previously redacted findings only when `Category == "credential-leak"`. That missed credential-bearing findings emitted under other categories: `MCP_007` (mcp-attack), `NLP_CRED_EXFIL_COMBO` (exfiltration), toxic-flow credential-bound pairs (`TOXIC_001/002`, `TOXIC_CROSS_001/002`), and selected exfiltration / supply-chain exfil pattern rules. Those findings could copy raw secrets into `matched_text`, `context`, and SARIF `message.text`, so CI logs or GitHub Code Scanning artifacts became a second copy of the secret. (#97)
- Cross-finding context bleed: a non-sensitive finding whose context window overlapped a sensitive sibling's match line no longer serializes that line raw.
- Dedup-survivor leak: when a non-sensitive finding outranks a sensitive one on the same line at dedup time, the survivor now inherits the redaction obligation.

### Changed

- `types.Finding` gains an optional `Sensitive bool` (`"sensitive"` in JSON, emitted only when true).
- YAML rules can opt in to redaction via `sensitive: true`. Analyzer emit sites (`NLP_CRED_EXFIL_COMBO`, `NLP_OVERRIDE_DANGEROUS` when credentials contribute, `TOXIC_*` cred-bound) mark findings sensitive inline.
- `types.RedactCredentialFindings` is renamed to `RedactSensitiveFindings`; the old name is kept as a deprecated alias so library consumers keep compiling. Backward compatible: `Category == "credential-leak"` still triggers redaction even without the new flag.
- `--no-redact` / `WithRedaction(false)` remain the explicit raw-output escape hatch.

### Known follow-ups (v0.16.3)

- `match_mode: all` rules whose secondary pattern hit lands more than ~3 lines from the anchor: that line is outside the recorded sensitive set. Will need `Finding.MatchedLines []int` plumbing.
- Sensitive findings dropped by the `--severity` filter before redaction can leave their secret lines unmarked in surviving findings' context windows. Will need to collect sensitive lines inside `scanner.postProcess` before the severity filter.

## [0.16.1] - 2026-05-16

Patch release for v0.16.0 focused on onboarding, CLI output contracts, and release hygiene.

### Fixed

- `aguara init --ci` now scaffolds the official `garagon/aguara` GitHub Action with both the action ref and binary version pinned to the release tag. This replaces the broken direct download of a non-existent `aguara-linux-amd64` asset.
- `aguara check --path <missing>` now fails loudly when the user explicitly passes a missing or non-directory path instead of silently falling back to autodiscovery.
- `aguara explain <RULE_ID>` and `aguara list-rules` now include analyzer-emitted rules such as `JS_DNS_TXT_EXFIL_001`, with metadata matching the analyzer emit site.
- `aguara update --format json` now emits stable JSON, honors `-o`, and refuses output paths that would overwrite the local threat-intel snapshot.
- Release prep now has `.github/scripts/check-version-pins.sh`, which fails before tagging if the init scaffold, action default ref, install.sh test pin, or README install snippets still point at a previous release.

### Verified

- Docker validation passed with `make verify-docker`.
- Real OSV refresh was validated in Docker with isolated `HOME=/tmp/home`.
- `aguara check --fresh` and `aguara audit --fresh --ci` were validated against `event-stream@3.3.6`.

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
