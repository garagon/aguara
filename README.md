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

`scan --auto` discovers supported MCP client configurations on the machine. Use `aguara discover` to inspect that inventory; in the development version it also lists, in every format (`unreadable` in JSON), configurations that exist but could not be read, such as a named pipe at a configuration path, whose servers are unknown. Configuration coverage is specific to supported file formats; it does not imply support for every agent host.

In the development version, `discover` shows the transport and URL of remote servers and redacts what looks secret in commands, arguments, environment values, URLs and headers: values of options and variables with sensitive names, URL credentials, every query and fragment value and credential-like path segments, header values other than `Accept`, `Content-Type`, `User-Agent` and `MCP-Protocol-Version`, and known token formats. Commands and arguments are read like a shell, including the commands inside a `$( )` substitution, and only the secret part of a word is replaced, so the rest of a command line stays readable; a command whose redacted text still looks secret is masked from its first argument, and an argument list from the first argument the secret-looking text spans. Any other value, such as an environment value, is replaced whole when any part of it looks secret, except a value that is one URL, JSON or a connection string, which is redacted by its parts. Environment values are never masked less than in v0.29.0. Configuration entries of an unexpected type are read leniently and reported as warnings, so one odd value no longer hides a file's servers from `discover` and `scan --auto`. A configuration file that cannot be read as JSON, for example because it has comments or trailing commas, is listed with a warning and still scanned by `scan --auto`.

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

Dependency files outside this table are not parsed, for example `npm-shrinkwrap.json`, `deno.lock`, `gems.locked`, `packages.config` and `paket.lock`, and pip requirements files under names that are not discovered (see below). `check` and `audit` list the ones they find under `coverage.unsupported_evidence`, together with lockfiles of ecosystems Aguara has no package intelligence for (`pubspec.lock`, `Podfile.lock`, `Package.resolved`, `mix.lock`), which the reports describe as such. When any are found, `audit` triage returns `review` and its action plan does not allow installing dependencies, even if other lockfiles were checked. Each entry's `reason` says why it was not evaluated: `format_not_parsed`, `no_package_intelligence`, `requirements_name_not_read` or `manifest_without_lockfile`.

Manifests record what to install, not the versions an install resolves: `package.json`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, pip-tools inputs (`*requirements*.in`, `requirements/*.in`), `Cargo.toml`, `Gemfile` or `gems.rb`, and `composer.json`. (`go.mod`, `pom.xml` and .NET project files are read, see the table.) A manifest that declares at least one dependency resolved from a registry is listed with reason `manifest_without_lockfile` unless a lockfile of its ecosystem that `check` reads or lists sits in its directory or a parent directory inside the checked directory. For Python, `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock` and `pylock.toml` cover a manifest this way. A discovered `requirements*.txt` covers it only when it stands for the manifest: it has no editable or local-path entry (`-e`, `.`, `./x`, a local archive, `file:`), and it pins with `==` or `===`, itself or through `-r` includes (a `-c` pin counts only for a name the file or its `-r` includes require), every dependency a plain install of the manifest pulls (project dependencies, Poetry main dependencies, Pipfile `[packages]`, `install_requires`, `requirements.in` entries). Extras and dependency groups need not be pinned, because pip installs them only on request and a compiled requirements file usually pins the default set; a manifest that declares only groups needs its groups pinned. When some dependency names cannot be read (a computed `setup.py` list or `setup(**config)`, a dynamic `pyproject.toml` list, a setuptools `file:` directive, a `requirements.in` include that is not read, such as a URL; its `-r` includes inside the checked directory are read for names, its `-c` includes add none), the names that can be read must still be pinned, and the file covers the rest only if the manifest names it as their source and it has at least one exact pin and no entry without one: `[tool.setuptools.dynamic] dependencies = {file = [...]}` or `install_requires = file: ...` lists it, `setup.py` names it (as in `open("requirements.txt")`), or it is the `.txt` that pip-compile writes for a `requirements.in`. A pinned file the manifest does not name says nothing about what the manifest installs. A requirements file whose editable or local-path entry installs the manifest's project (the path read relative to the file and to the checked directory) must also pin those dependencies itself or through its includes; otherwise the manifest is listed even when another file pins them, since installing from that file does not read the other one. A constraints file alone does not cover a manifest. When a requirements file falls short, the entry names it (`requirements_file`), lists the declared dependencies it does not pin (`not_pinned`) and says why (`detail`). A lockfile at a workspace root therefore covers its members (npm, Yarn, Bun and pnpm workspaces, Cargo and uv workspaces), and one at the project root covers nested fixtures and path dependencies. When a workspace root has no lockfile, only the root is listed, with `nested_manifests` counting the manifests below it. `audit` triage then returns `review` with reason `manifest_without_lockfile` and the next step to generate or commit a lockfile and audit again, and the action plan does not allow installing dependencies. A manifest without dependencies (only scripts, platform requirements such as `php` or `ext-*`, or build requirements) changes nothing; `peerDependencies` count, because npm 7 and later and pnpm install them. Manifests are read only as far as needed: JSON and TOML are parsed with exact keys and size limits, `setup.cfg` as an INI file, and `setup.py` and `Gemfile` are checked as text, never run (a `setup.py` counts when its code passes `install_requires` or `extras_require`, or calls `setup()` with unpacked keyword arguments such as `**config`, and literal lists of strings given to those keywords, directly or through a name bound only to such lists, are read like any other manifest's; a `Gemfile` when it has a `gem`, `gemspec` or `eval_gemfile` line, including a `gem` call with a computed name; TOML inline tables such as `optional-dependencies = {...}` read like the tables they stand for, and Hatch environment dependencies count as optional groups). A manifest that cannot be read counts as declaring dependencies; so does one past the discovery's read budget (10,000 manifests and pip files under undiscovered names, and 256 MiB read from them in all), which is listed without being read. A conda environment file (`environment.yml` or `environment.yaml` whose `dependencies` is a list of conda specs and at most a `pip:` list) is listed as `no_package_intelligence` when it declares dependencies: Aguara reads no conda lockfile and has no intelligence for conda channels.

In files listed this way, entries that pin one exact release are still matched against exact-version and every-version advisories, and `exact_pins_checked` counts them; a match is a CRITICAL finding with the file and, where the format has one, the line. Exact pins are npm versions as npm reads them in loose mode, such as `"1.3.0"`, `"=1.3.0"`, `"03.3.6"` or `npm:pkg@1.3.0`; `==` and `===` in PEP 508 strings, Pipfile and Poetry entries (Poetry also reads a bare `"1.2.3"` as exact); `=1.2.3` with all three components in `Cargo.toml`; a single exact version in a `Gemfile` `gem` line without a Git or path option and outside a `git`, `github` or `path` block; a single exact version in `composer.json`; and `==` and `===` pins in a conda `pip:` list and in listed requirements files. Ranges and everything else in those files are not checked.

Matching supports exact versions and advisories affecting every version of a package. Bounded version ranges are supported for npm semver, not arbitrary ranges in every ecosystem. This is malicious-package detection, not comprehensive CVE coverage.

Versions are compared the way each ecosystem's tooling compares them, so the spelling in a lockfile and in an advisory need not be identical. Go module versions match with or without the leading `v` that `go.sum` and `go.mod` write (OSV Go records omit it) and with or without `+incompatible`; pseudo-versions, pre-releases and every other component must be equal. A `go.sum` version that has only a `/go.mod` hash, and that the `go.mod` beside it does not require, was read during version selection and never downloaded or built: it is matched only against advisories covering every version of the module. A version `go.mod` requires is matched in full even when `go.sum` lacks it. `replace` directives do not change what is matched; a finding for a replaced module says what the build uses instead. Nor do `exclude` directives: a compromised version that `go.mod` both requires and excludes is still reported, and the finding says that the go command ignores that requirement. Packagist versions are compared after Composer's normalization (`v1.2.3` equals `1.2.3` and `1.2.3.0`). NuGet versions are compared after NuGet's normalization (`1.0`, `1.0.0` and `1.0.0.0` are equal, build metadata is dropped, pre-release labels ignore case), and a project file version written as `[1.2.3]` is read as `1.2.3`. With central package management, a `PackageReference` without a version takes it from its `VersionOverride` or from the `PackageVersion` items of the nearest `Directory.Packages.props` in its directory or a parent inside the checked directory, whose `GlobalPackageReference` items apply too. Every version declared for a package is checked, since conditional `PackageVersion` items can declare several. `ManagePackageVersionsCentrally` set to `false`, in the project file or else in `Directory.Packages.props`, turns central versions off. Each `Directory.Packages.props` is read once per run, up to 4 MiB; a larger, symlinked or malformed one is an error. Floating versions (`1.*`), ranges (`[1.0,2.0)`, `(1.0,)`), a version taken from a property the project file does not define (`$(PkgVersion)` set in `Directory.Build.props`, which is not read) and references whose version cannot be found count as `unpinned`, so `audit` asks for review, unless a `packages.lock.json` beside the project records what restore chose. PyPI uses PEP 440 equality. npm, crates.io, RubyGems and Maven lockfiles record the registry's own version string and are compared literally; a `Gemfile.lock` platform gem such as `nokogiri (1.16.2-x86_64-linux)` is read as version `1.16.2`, as Bundler reads it.

Unambiguous `npm:` aliases resolve to the real package in package-lock, pnpm, Yarn classic, Yarn Berry, and Bun. Classic Yarn uses the alias target name and the block's resolved version; conflicting descriptors and ambiguous non-registry identities are skipped rather than assigned a guessed package identity. Binary `bun.lockb` is not parsed; a repository with only that file returns an error asking for text `bun.lock`.

Python dependency files are read in development builds after v0.29.0 (see [Unreleased](CHANGELOG.md#unreleased)); v0.29.0 reads installed environments only. Aguara does not run uv, Poetry, Pipenv, PDM or pip to read them. Only packages resolved from a package index are matched: Git, local path, direct URL, editable and workspace entries have no PyPI identity and are skipped. The exception is a direct URL to a wheel or source distribution on `files.pythonhosted.org`, PyPI's file host, in a requirements file, `uv.lock` or `poetry.lock`: its file name names the release (read with the PyPA file name conventions), and it is matched when the name agrees with the declared one. In a requirements file the reference may be bare, or follow `name @` with or without spaces (`name@url`, `name[extra]@url`). Names are compared after PEP 503 normalization and versions with PEP 440 equality, so `Foo_Bar 1.0` matches an advisory for `foo-bar 1.0.0`. A `===` pin is compared as pip compares it, as a string against the normalized version of each release, so `===1.0` matches an advisory for `1.0` but not for `1.0.0`. Findings name the file and, for TOML lockfiles and requirements files, the line of the matching entry, and list every advisory ID that matched (in the title and in the JSON `advisory_ids` array).

Packages from any index are matched by their PyPI name, including private indexes and mirrors: a lockfile cannot show whether a mirror proxies PyPI. An internal package that shares its name with a malicious PyPI package is therefore reported. Read that finding as a dependency-confusion exposure: check which index actually serves the package and pin that index for it.

In requirements and constraints files only `==` and `===` pins identify a version. Other requirements can match only advisories that cover every version; Aguara does not guess a version for them. A requirement counts as `unpinned` unless an exact pin of the same name in the same file, or in a constraint it reads through `-c`, covers it. An editable or local-path entry counts as `unpinned` too unless it is a Python project directory inside the checked directory (a local archive, an editable VCS checkout or a path outside it installs dependencies nothing pins); a project directory is checked against its manifest instead (see above). Constraints themselves never count, and constraints files are not counted: they install nothing. The terminal report says how many unpinned entries there are, and the JSON `ecosystems` and `coverage.package_evidence` entries count them as `unpinned`. Any unpinned entry lets an install resolve a version nothing checked, so `audit` triage returns `review`, even when the rest of the file is pinned. Environment markers are not evaluated, so a pin counts for every platform. Files are decoded and split into lines as pip does; a file that declares an encoding other than UTF-8 or ASCII is an error. Options are read as pip 25.2 and 26.0 read them: their requirements-file options, a long option abbreviated to any prefix that names exactly one of them (`--extra-index`, `--constr`, `--edit`), the options after a requirement read and ignored, and one include or editable install per line (`-e` before `-r` before `-c`). A line outside the pip grammar Aguara reads (an unknown or ambiguous option such as `--req`, a malformed requirement, specifier, version, extras or marker, an unterminated quote, an option without its value) is skipped and the rest of the file is read: its pins are matched, with findings and exit codes as usual, and its includes are followed. A requirement whose trailing options are rejected is still read. Requirements follow pip's PEP 508 grammar: an empty marker after `;` is no marker, one trailing comma ends a specifier (`name==1.0,`), and a marker must parse (`; python_version >= '3' and` does not). A skipped line that still starts with an exact pin (`name==1.0` or `name===1.0`, with optional extras and an opening parenthesis) or with a `files.pythonhosted.org` reference keeps that pin for matching, so a line pip would reject cannot hide a pin from the check, and the file stays listed as partly read. A discovered `requirements*.txt` or `constraints*.txt` with such a line, itself or in a file it includes, is also listed under `coverage.unsupported_evidence` with reason `format_not_parsed`, the first skipped line in `detail` and the number of skipped lines in `skipped_lines`, so `audit` asks for review, and it never covers a manifest (see above). Input that pip could still read and install from stays an error: a symlinked, special or oversized file, a declared encoding other than UTF-8 or ASCII, content that is not UTF-8, a line over 1 MiB, more than 100,000 entries, or includes nested more than eight levels deep. `-r` and `-c` includes are followed only inside the checked directory, up to eight levels of nesting (deeper nesting is an error). URL includes, includes outside the directory, includes through an environment variable and missing files are not read: each one is a WARNING finding with its file and line, so the result is not a clean pass; the JSON `ecosystems` entry counts them as `unresolved_includes`, and `coverage.unresolved_includes` lists them. Index options, hashes, editable installs and URL requirements other than PyPI files are ignored. `pyproject.toml`, `Pipfile` and `requirements.in` are manifests (see above): they are listed when no lockfile covers them, and only their exact pins are matched.

Only files named `requirements*.txt` and `constraints*.txt` are discovered. pip files under the other common names, `*requirements*.txt` (such as `dev-requirements.txt` or `test_requirements.txt`), `reqs*.txt`, `*-reqs*.txt`, `*_reqs*.txt`, `*.pip` and `requirements/*.txt`, are read only when a discovered file includes them with `-r` or `-c`. Otherwise, when such a file parses as pip requirements and names at least one requirement (pinned or a range) or include, `check` and `audit` list it under `coverage.unsupported_evidence` with reason `requirements_name_not_read`, so the audit asks for review instead of treating it as checked, and its exact pins are matched. A file with a line outside the pip grammar is listed only when it also pins an exact version, so a text file such as prose is not listed, and other names (for example `prereqs.txt`) are not considered.

For a directory, `check` and `audit` read the same evidence: the dependency files under it and the packages installed in its virtual environment (the directory itself, `.venv`, `venv`, or `VIRTUAL_ENV` when that points inside the directory). With no path argument, both also read the active `VIRTUAL_ENV` wherever it is; an explicit path never reads an unrelated environment. An environment inside the directory is read only when it has a `pyvenv.cfg` file; conda environments and a `.venv` without `pyvenv.cfg` are not read. Below the checked directory, `.venv`, `site-packages`, `dist-packages` and `__pypackages__` directories are not searched for dependency files; every other directory is, including a virtual environment with another name. A project's virtual environment contributes installed package versions only. `.pth` inspection, persistence artifacts, credential files and caches remain part of the installed-environment check: `aguara check <site-packages>`, `--ecosystem python`, or `aguara check` with no path when the directory has no non-Python dependency files.

Lockfile and dependency-manifest inputs must be regular files no larger than 50 MiB. In the development version, a dependency file is also an error when it yields more than 100,000 package entries, when a JSON or YAML lockfile has more than 2,000,000 structural values (counted before decoding) or one object, array, mapping or sequence with more than 100,000 members (a package-lock.json with more than 100,000 install paths is rejected even when they hold fewer unique packages), when a TOML expression has more than 200,000, or when an XML file has more than 2,000,000 tokens or nests elements more than 256 levels deep. The same limits apply to the dependency manifests read without a lockfile (`package.json` and `composer.json` as JSON, `pyproject.toml`, `Cargo.toml` and `Pipfile` as TOML, `Directory.Packages.props` as XML), and a conda `environment.yml` is limited to 200,000 YAML values; a manifest over a limit makes the check incomplete instead of an error (see below), while a `Directory.Packages.props` over one is an error like the project files. Real lockfiles are far below these limits. Leaf symlinks, including dangling links, return an error rather than being followed or silently skipped. This read boundary does not confine parent directories or guarantee that file contents remain unchanged during a check. Installed-package scanning is a separate path.

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

A scan that matches no files reports that nothing was scanned and exits 0. Add `--fail-on-empty` to a `scan` gate so a mistyped path or an empty change set fails the step with exit code 2 instead.

A CI gate should not let the repository under review decide what it sees. `--ci` sets `--fail-on high` unless `--fail-on` is given, disables color and ignores project-owned policy. In the development version, `scan` without `--ci` also ignores that policy when a CI environment is detected (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `BUILDKITE`, `JENKINS_URL`, `TEAMCITY_VERSION` or `TRAVIS` set). The one exception is a `fail_on` in `.aguara.yml`: it still applies when `--fail-on` is not passed, since a failure threshold can only add a gate. A notice on stderr names the CI variable, the policy that was skipped and any `fail_on` that was applied. Pass `--project-policy trust` only when the policy files are owned by the pipeline, not by the change being checked, and `--project-policy ignore` to skip `fail_on` too.

To introduce a gate in an existing project, record and review a baseline:

```bash
aguara audit . --write-baseline .aguara-baseline.json
aguara audit . --ci --baseline .aguara-baseline.json
```

Baseline-matched content findings remain visible but do not fail the gate. New findings are evaluated against the selected threshold. Compromised-package findings are not baselineable, and sensitive findings are omitted when writing a baseline. A missing or malformed baseline returns an error. Treat baseline changes as security decisions during review.

### Scaffolded workflow and commit hooks

`aguara init` writes `.aguara.yml`, `.aguaraignore` and `.github/workflows/aguara.yml`, and never overwrites an existing file. In the development version the workflow runs `aguara audit . --ci --project-policy ignore` with the binary the pinned Action installs, uploads the Action's content findings to code scanning, and writes the audit report to the job summary instead of commenting on pull requests. It requests `contents: read`, `security-events: write` and `actions: read`. The upload is skipped for pull requests from forks, which cannot write to code scanning, and when the repository variable `AGUARA_UPLOAD_SARIF` is `false`, for example in a private repository without code scanning; a failed upload does not fail the job. The SARIF file and the audit report are written to `$RUNNER_TEMP`, not into the checkout the audit scans. When the Action's scan is incomplete (exit code 2) its SARIF is not uploaded and the step fails, and the audit still runs, so the job summary says what was not evaluated and the job fails. The scaffolded `.aguara.yml` no longer includes a `paths` example, a key that never had an effect; a file that still sets it gets a notice saying so on each local scan.

`aguara init --hook` writes a git pre-commit hook into the hooks directory git uses, including in a linked worktree; with a global `core.hooksPath`, that directory serves every repository that uses it, so the hook runs for all of them. In the development version it scans the staged version of added, copied, modified, renamed and type-changed files, which is what the commit will contain, and blocks the commit on HIGH or CRITICAL findings; `git commit --no-verify` skips it once. It does not use `scan --changed`, which reads the work tree copy of changed and untracked files. It sees only the staged files, so cross-file checks do not see helpers or other files the commit leaves unchanged.

Commit hooks, this one and the pre-commit framework hooks below, apply the committer's own `.aguara.yml` and `.aguaraignore`, as a local `aguara scan .` does. They help the author; the enforcement point is CI with `--project-policy ignore`, which `audit`, `scan --ci`, the GitHub Action and the scaffolded workflow use.

For the [pre-commit](https://pre-commit.com) framework, the development version adds `.pre-commit-hooks.yaml` with two hooks: `aguara` builds the scanner at the pinned revision (Go 1.26 or later), and `aguara-system` runs the `aguara` already on your `PATH`.

```yaml
repos:
  - repo: https://github.com/garagon/aguara
    rev: <a commit or a release after v0.29.0>
    hooks:
      - id: aguara
```

Both run `aguara scan --root . --fail-on high --` with the file names pre-commit passes, as one scan rooted at the repository root. The final `--` keeps a file name that starts with a dash from being read as a flag; keep it last if you override `args`. pre-commit splits very long file lists into several runs; cross-file checks then see only the files of the same run.

### Several paths in one scan

```bash
aguara scan SKILL.md scripts/ .mcp.json
```

In the development version, `scan` accepts several files and directories and writes one report. The scan is rooted at the current directory, or at `--root DIR`, which also works with a single path: policy files are read from the root, ignore patterns apply to every path including files named on the command line, and findings report paths relative to the root, so baselines written by `aguara scan .` match. Every path must be inside the root. As in a directory walk, symbolic links named on the command line are not followed and paths inside `.git/`, `node_modules/` or `.aguara/` are not scanned; a notice names them, and they are listed under `skipped` with the paths an ignore pattern excludes. A named path that does not exist, is a named pipe or device, or is over the size limit makes the scan incomplete (exit code 2) while the other paths are still scanned and reported. After `--`, every argument is a path, including one named `-`. Cross-file checks group the scanned files by directory and see only the files of this scan. `--changed` takes a single path. A single path without `--root` behaves as before: a file is reported by its name and policy is read from its directory.

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

The default SARIF upload needs `security-events: write`. See [`action.yml`](action.yml) for inputs; use the CLI audit in a separate CI step when you also need package-intelligence checks. In the development version, a scan that exits with code 2 (for example an incomplete scan) fails the step with an error annotation, and its partial SARIF is not uploaded, so Code Scanning does not close alerts for files that were not evaluated.

The Action writes its report to `aguara-results.sarif` in the working directory by default. When a later step scans the checkout again, set `output: ${{ runner.temp }}/aguara-results.sarif`: a scan reads a report left in the target as a JSON file, so a finding a Markdown fence lowers in its source would come back at full severity. In the development version, a local scan that applies project policy does not read the report or baseline that the same invocation writes (`-o`, `--write-baseline`), and a notice on stderr names the skipped file; other report files in the target are scanned as usual. This follows the trust boundary: a local run already lets the project's own `.aguaraignore` exclude files, so a project that ships a file under the name you write to is no more trusted than it already was. With `--ci`, `audit`, the GitHub Action, `--project-policy ignore` or in a detected CI environment, a file already at that path is part of the checkout under review and is scanned.

## Outputs and Integrations

`scan` offers terminal, JSON, SARIF, and Markdown output. `audit` offers a combined terminal or JSON report, and `check` offers terminal or JSON. Use SARIF from `scan` for GitHub Code Scanning; other SAST services may require a different schema.

In the development version, a `--format` value a command cannot render is rejected with exit code 2 instead of falling back to the terminal report, and `-o` writes the selected format, terminal included, to the file without color. Flags such as `--severity`, `--rules`, `--disable-rule` and `--workers` are accepted only by the commands they affect; `aguara <command> --help` lists them.

### Scanning piped content

```bash
cat tool-description.md | aguara scan - --stdin-filename SKILL.md --fail-on high
```

In the development version, `scan -` reads the content to scan from standard input, up to `--max-file-size` (50 MB by default), and supports every scan format and the usual exit codes. The name given with `--stdin-filename` decides how the content is analyzed, as a file with that name would be: `SKILL.md` for a skill, `mcp.json` for an MCP configuration, `.github/workflows/ci.yml` for a workflow. The default is `skill.md`, the same as the Go API's `ScanContent`. Piped content is untrusted input: no `.aguara.yml` or `.aguaraignore` is read for it, inline `aguara-ignore` directives in it are not honored, and `--project-policy trust` is rejected. Empty input is a scan of nothing, which `--fail-on-empty` turns into exit code 2. When standard input is a terminal, `scan -` exits with code 2 and a usage hint instead of waiting for input. Piped content that one analyzer cannot evaluate within its budget is reported like any incomplete scan: the other analyzers' findings are written and the command exits 2. `/dev/stdin`, `/dev/fd/0` and `/proc/self/fd/0` are read the same way as `-`; earlier versions scanned them as a file named `stdin` with no extension, so only rules that apply to every file ran and Markdown rules such as prompt injection did not.

An agent host that runs a command before a tool call can use this to check the content a tool is about to write, or the description of a tool it is about to load. This sketch reads a JSON event on standard input, scans `tool_input.content` under the name in `tool_input.file_path`, and blocks the call when Aguara reports HIGH or CRITICAL findings or cannot complete the scan. Adapt the field names and the blocking exit code to your host's hook contract:

```sh
#!/bin/sh
event=$(cat)
name=$(printf '%s' "$event" | jq -r '.tool_input.file_path // "tool.md"')
printf '%s' "$event" | jq -r '.tool_input.content // .tool_input.description // empty' |
  aguara scan - --stdin-filename "$name" --fail-on high --no-color >&2
[ "$?" -eq 0 ] || exit 2
```

JSON reports from `scan`, `check` and `audit` include a `coverage` block stating what was evaluated: files scanned, package evidence read per ecosystem and source (with an `unpinned` count where entries have no exact version), `unsupported_evidence`, dependency files that were found but that Aguara did not evaluate (for example `deno.lock`, `gems.locked`, `Podfile.lock`, a `dev-requirements.txt` that no discovered requirements file includes, or a `package.json` without a lockfile), each with a `reason`, and `unresolved_includes`, requirements includes that were not read. Only the exact pins of unsupported files were checked (`exact_pins_checked`). Read the coverage before treating an empty result as clean.

In the development version, `scan` and `audit` also list under `skipped` and `coverage.skipped` the entries they did not read because they are not regular files: symbolic links (never followed inside a directory), named pipes, sockets and devices. A scan of several paths also lists the paths it was given that a scan of the root would not read (`in_skipped_dir` for a path inside `.git/`, `node_modules/` or `.aguara/`, `ignored` for a path an ignore pattern excludes), and a local run that applies project policy lists the report or baseline it writes when it finds it in the target (`output_file`). Such entries hold no file content to evaluate and never block the scan. A skipped link carries `resolves`: `inside` (content the scan reads anyway), `excluded` (a part of the target the scan does not read: a file with a binary extension, anything under `.git`, `node_modules` or `.aguara`, a path an ignore pattern excludes, a file over the size limit or one that is not a regular file), `outside` the target, or `dangling`. `audit` triage returns `review` (reason `entries_not_evaluated`) for a named pipe, socket or device, a link that does not resolve `inside`, or a named path inside `.git/`, `node_modules/` or `.aguara/`, because an agent would read what the scan did not; an `ignored` path and an `output_file` were left out on purpose and do not. A link that an ignore pattern matches is not listed, so with `--project-policy trust` the target's own `.aguaraignore` can keep a skipped link out of triage. A scan target that is itself a named pipe or device is an error (exit code 2). `scan --changed` scans a changed git submodule whole, under its path. A changed submodule that is not checked out at the commit the index records for it makes the scan incomplete (reason `not_scanned`; run `git submodule update --init` and scan again): when nothing is checked out nothing is scanned, and when another commit is checked out its files are scanned but the recorded commit is not. A submodule checked out at its recorded commit is scanned with any local edits, and one that holds no scannable files adds no files and leaves the scan complete.

A scan that cannot evaluate everything is incomplete and exits with code 2, whatever `--fail-on` says: a file that cannot be read or exceeds the size limit, an analyzer that fails or exceeds its budget on a file, or an interrupted run. In the development version, the report is still written, in every format and to `-o`: the findings from everything that was evaluated are kept, the terminal and Markdown reports open with a "SCAN INCOMPLETE" notice, JSON has `"complete": false` and lists what failed under `errors` (with `failed_operations` counting all of them), and SARIF marks the invocation `executionSuccessful: false` with one notification per failure. The verdict of an incomplete result is never `clean`. No baseline is written and no rug-pull state is saved from an incomplete scan. `audit` reports the same way, with `"complete": false`, `verdict.status` `incomplete` (unless the gate failed) and a `scan_incomplete` triage reason, so triage is never `proceed`.

`check` is incomplete the same way when a dependency manifest it found exceeds a parsing budget (see the limits above): the manifest is still listed under `coverage.unsupported_evidence` with its dependencies unknown, every other result is kept, JSON has `"complete": false` and the file under `errors` (reason `budget`, with `failed_operations`), the terminal report says CHECK INCOMPLETE, and the command exits 2. `audit` then reports `"complete": false`, `verdict.status` `incomplete` and a `check_incomplete` triage reason (`check.errors` lists the files). A manifest larger than 4 MiB, a symbolic link or special file in its place, or one past the discovery read budget is listed as not evaluated without making the run incomplete.

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

### Ignore patterns

`.aguaraignore` (one pattern per line, `#` starts a comment) and the `ignore:` list of `.aguara.yml` exclude files from a local scan. `audit`, `scan --ci`, the GitHub Action and a scan in a detected CI environment do not read them. The Go API's `WithIgnorePatterns` uses the same syntax. `node_modules/` and `.git/` are always skipped.

| Pattern | Excludes |
|---|---|
| `dist/` | every directory named `dist` and everything in it, at any depth |
| `/build/` or `/build` | `build` at the scan root only |
| `**/fixtures/` | every directory named `fixtures` |
| `docs/internal` | the file or directory at that path from the scan root |
| `docs/*.md` | Markdown files directly in `docs/` |
| `generated/**` | everything under `generated/` |
| `*.min.js` | files with a matching name at any depth |

The syntax borrows gitignore's directory forms but is not gitignore. Exactly:

- A trailing slash matches directories and everything in them: `dist/` or `build-*/` at any depth, and a pattern with another slash inside, such as `packages/*/dist/`, from the scan root.
- A leading `/` or `./` anchors a pattern to the scan root, where it matches a file or a directory: `/build`, `/docs/*.md`, `/logs/*/`.
- A path with a slash inside and no `*`, `?` or `[`, such as `docs/internal`, matches that file or directory from the scan root.
- Other patterns with a slash match file paths only, as in earlier releases: `docs/*.md`, `**/*.yaml` and `generated/**` (everything under `generated/`). `**/name` and `a/**/b` without a trailing slash do not match directories.
- A pattern without a slash, such as `vendor` or `*.log`, matches file names at any depth and never directories; add a trailing slash to exclude directories with that name.
- `**` and `/**` match everything; `**/` matches every directory below the scan root, not the files at the root.
- `*` and `?` stay within one path segment. Character classes `[a-z]`, `[^a]` and `[!a]` work, and `\` escapes a special character except on Windows.
- Matching is case-sensitive, also on case-insensitive filesystems such as the macOS and Windows defaults.
- Negation (`!pattern`) is not supported: a scan warns about such a line, and it has no effect.

In the development version, patterns with a trailing slash, a leading slash or `./`, a literal path naming a directory, and `**` alone take effect; in v0.29.0 and earlier they matched nothing, so `dist/` excluded nothing while `dist/**` did. Patterns that matched before match the same files, except a character class that starts with `!`, such as `[!a]`, which now negates (it used to match a literal `!`). `scan --verbose` lists the patterns that matched nothing in that scan, with a hint when a bare name matches a directory that was scanned.

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
