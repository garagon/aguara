# Before Execution: A Deterministic Trust Layer for AI Agents and Software Supply Chains

## Abstract

Modern development environments execute decisions that were made outside the
application's source code. Package managers resolve lockfiles and run install
hooks. CI workflows receive tokens and publish artifacts. AI coding agents load
repository instructions, settings, tools, and MCP server definitions before a
developer has reviewed every file.

The security boundary therefore starts before runtime. A repository can be
dangerous even when its application code is never launched.

Aguara is an open source security engine for this boundary. It inspects the
files and dependency evidence a developer, CI job, or AI agent is about to
trust, before installing packages or executing project-defined code. Scans are
local and deterministic. They do not execute packages, call an LLM, upload the
repository, or require a hosted account.

This report defines Aguara's before-execution model, its threat boundaries, and
the method used to evaluate detection quality without hiding false positives.

## The problem is inherited execution

A fresh clone is commonly treated as inert. In practice, the next ordinary
action can grant it execution:

- `npm install` can run dependency lifecycle scripts.
- A lockfile selects exact package artifacts, including aliased dependencies
  whose public name differs from the package actually installed.
- A CI workflow can expose OIDC tokens, repository credentials, caches, and
  publishing permissions to code from the repository.
- An AI coding agent can inherit persistent instructions, hooks, permission
  defaults, credential helpers, and MCP server configuration from project
  files.

The Miasma npm campaign demonstrated the full chain. Compromised packages used
a preinstall hook, launched a Bun-based second stage, harvested developer and
CI credentials, abused GitHub as a control and exfiltration channel, modified
host trust surfaces, propagated through package publishing, and included a
destructive home-directory tripwire. The application did not need to reach its
normal runtime for the compromise to begin.

npm's v12 trust changes point in the same direction. Dependency scripts, Git
dependencies, and remote tarballs move from implicit behavior toward explicit
project policy. This reduces automatic execution, but it also makes committed
policy files security-sensitive inputs that must be reviewed.

## The before-execution model

Aguara treats a project as a set of proposed trust decisions rather than only
as source code. The model has four stages.

### 1. Identify what will be trusted

The engine discovers lockfiles, package manifests, package-manager policy,
install hooks, CI workflows, agent instruction files, agent host settings, MCP
configuration, skills, and tool descriptions.

Discovery is conservative. When a parser cannot map an alias or version to a
registry package with confidence, it does not invent an identity. Unsupported
or malformed formats fail visibly where silence could produce a false clean
result.

### 2. Evaluate identity, policy, and behavior

Aguara uses three complementary forms of evidence:

- **Threat intelligence** answers whether resolved dependency evidence matches
  a package already known to be malicious. The embedded snapshot is derived
  from high-confidence OSV and manually verified incident records.
- **Policy analysis** identifies explicit repository settings that weaken npm,
  pnpm, CI, MCP, or agent trust boundaries.
- **Behavioral analysis** looks for bounded chains such as remote content
  reaching execution, secrets reaching a network sink, GitHub writes paired
  with malicious partners, host-trust modification, or destructive cleanup.

Strong behavioral rules require a source, transformation, or sink relationship
where the file format permits it. A weak keyword near another weak keyword is
not sufficient for high-severity findings.

### 3. Produce an actionable trust decision

`aguara scan` evaluates repository content. `aguara check` evaluates resolved
dependency evidence. `aguara audit` combines both and returns three layers of
output:

- raw findings with evidence, severity, confidence, and remediation;
- triage stating `proceed`, `review`, or `stop` and explaining why;
- an agent handoff and action plan stating whether installation, project-code
  execution, CI, repository agent configuration, and file edits are allowed.

The result is intended to be consumed before the next action. A human can read
it in the terminal; CI can use exit codes and SARIF; an agent can consume the
structured JSON contract.

### 4. Preserve local control

Default scans use the threat-intel snapshot embedded in the signed binary. A
user may explicitly refresh from Aguara's signed advisory bundle, which is
verified before it can replace the local cache. Scan content is not sent to a
service. There are no telemetry or model calls in the detection path.

This is both a privacy property and a reproducibility property. The same
binary, snapshot, configuration, and input produce the same result.

## Precision is part of the security boundary

A security gate that reports ordinary release automation, documentation, or
cleanup as malicious will eventually be disabled. False positives are not only
a usability defect; they erode the control the scanner is meant to provide.

Aguara therefore favors bounded analyzers over broad co-presence rules. Parsers
use structured formats when available. JavaScript behavior is anchored to
recognized execution, filesystem, network, and package APIs. Benign neighboring
cases are tested alongside malicious ones. When precision would require a full
language or shell parser, the limit is documented instead of approximated with
an increasingly broad regular expression.

## Aguara Trust Bench

Aguara Trust Bench makes this discipline externally reproducible. The runner
executes the public binary against labeled projects, then compares the complete
JSON output with expected observations.

The v1 seed corpus contains 20 synthetic fixtures: 10 positive and 10 benign
cases across agent configuration, install policy, behavioral chains, host
impact, package-manager policy, and dependency intelligence. On the initial
baseline it records:

| Metric | Seed result |
|---|---:|
| Recall | 1.0000 |
| Precision | 0.9091 |
| Benign-case false-positive rate | 0.1000 |

The false positive is retained rather than relabeled: a legitimate release bot
using `GITHUB_TOKEN` to write release content is still classified by the CI
secret-harvest detector. The GitHub C2 detector correctly stays quiet. This
case is a tracked detector gap and an example of why public negative fixtures
matter.

These values describe the seed corpus only. They are not a claim about all
repositories, package ecosystems, or agent configurations. A statistically
useful effectiveness benchmark requires a larger independently labeled corpus,
clear provenance, and license-compatible real-world samples. The seed corpus
is the first reproducible gate and the schema on which that dataset can grow.

## Threat boundaries and limitations

Aguara is not a sandbox and does not prove that a repository is safe. It does
not execute suspicious code, inspect a running endpoint, replace endpoint
protection, or provide complete CVE coverage. Static analysis also has explicit
limits:

- file-local analyzers do not provide complete interprocedural data flow;
- bounded shell handling is not a full shell parser;
- dynamically constructed dependency names and paths may be skipped when a
  trustworthy mapping is unavailable;
- known-malicious package detection is limited by the quality and freshness of
  its source advisories;
- a clean result means no covered risk was found, not that no risk exists.

The action plan reflects these limits. `proceed` is a preflight signal, not an
attestation of universal safety. High-risk findings stop execution; ambiguous
evidence asks for review; unsupported evidence should fail visibly instead of
being presented as clean.

## Availability and reproducibility

Aguara and Aguara Trust Bench are Apache-2.0 licensed. The benchmark manifest,
runner, and labels live with the source code, and each run records the manifest
digest and Aguara version in its machine-readable report. Every detection
change can therefore be evaluated in the same pull request.

The next benchmark stage will add license-compatible real artifacts, independent
label review, per-rule-family coverage, and release-to-release quality history.
The architectural goal remains unchanged: review trust before execution, and
make the decision explainable enough that people and agents can act on it.

## References

1. [GitHub, Upcoming breaking changes for npm v12](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/)
2. [Microsoft Security, Preinstall to persistence: the Red Hat npm Miasma campaign](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
3. [OSV, Open Source Vulnerabilities](https://osv.dev/)
4. [Sigstore](https://www.sigstore.dev/)
