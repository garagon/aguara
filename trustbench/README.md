# Aguara Trust Bench

Aguara Trust Bench is the public quality gate for Aguara's before-execution
security model. It measures whether the released CLI detects known risky trust
decisions without turning ordinary project behavior into findings.

The benchmark executes the real `aguara` binary under test. It does not call analyzer
packages directly, so discovery, parsing, rule correlation, embedded threat
intel, deduplication, and JSON serialization are all part of the result.

## Current scope

The v1 seed corpus contains 20 synthetic cases arranged as 10 positive/benign
pairs across six trust surfaces:

| Surface | Examples |
|---|---|
| Agent configuration | fetch-and-execute hooks, bypassed approvals, narrow local configuration |
| Install policy | npm lifecycle execution versus ordinary build scripts |
| Behavioral chains | Bun second stages, GitHub write/control behavior, legitimate release automation |
| Host impact | sudoers modification, home-directory wiping, ordinary cleanup and read-only validation |
| Package-manager policy | explicit npm/pnpm trust opt-outs versus their safer defaults |
| Dependency intel | known-malicious lockfile evidence versus a clean neighboring version |

All fixture content was authored for this benchmark and is licensed under the
repository's Apache-2.0 license. The local research corpus under
`testdata/real-skills` is deliberately excluded because its third-party
provenance and redistribution rights have not yet been normalized.

## Metrics

Trust Bench reports:

- **Precision**: expected observations divided by all observations.
- **Recall**: expected observations found divided by all expected observations.
- **Benign-case FPR**: benign cases with at least one finding divided by all
  benign cases.
- **Per-surface metrics**: the same measures split by trust surface.

Labels are exact rule IDs for `scan` findings and stable title fragments for
known-malicious package findings. Observations are deduplicated by rule ID or
title within a case. This makes the benchmark a product-level regression gate,
not a count of repeated line matches.

The seed corpus is intentionally small. Its metrics describe these 20 fixtures
only and must not be presented as ecosystem-wide accuracy. The next dataset
stage is a larger, independently labeled corpus of license-compatible real
projects and agent artifacts.

## Run it

```bash
make build
make trustbench
```

For machine-readable output:

```bash
go run ./trustbench/cmd/trustbench \
  -binary ./aguara \
  -manifest trustbench/manifest.yaml \
  -format json \
  -output trustbench-report.json
```

The runner creates an isolated home directory for every case and always passes
`--no-update-check`. It never refreshes intel or accesses the network.

## Gate policy

The command exits non-zero when an expected observation is missing or a new
unexpected observation appears. A known false positive may be named explicitly
under `known_unexpected`; it remains included in the published precision and
FPR, but does not make every unrelated PR fail.

The current seed corpus records one such gap: a legitimate GitHub release bot
that reads `GITHUB_TOKEN` and writes release content is excluded by the GitHub
C2 rule but still triggers `JS_CI_SECRET_HARVEST_001`. The case stays in the
benchmark until the detector is tightened in a separate behavior change.

Known gaps must be exact observations, not wildcard exceptions. Adding a new
one requires the same review as changing a detection rule. The gate also fails
when an exception stops reproducing, forcing the stale waiver to be removed.

## Adding a case

Each case in `manifest.yaml` must include:

1. A stable ID and one trust surface.
2. The public command under test: `scan`, `check`, or `audit`.
3. Self-contained files written into an isolated temporary project.
4. Exact expected observations, or an empty list for a benign case.
5. A paired case demonstrating the nearest legitimate behavior when practical.

Do not copy third-party code into the manifest without recording its license,
source revision, and redistribution terms. Synthetic minimal reproductions are
preferred for the regression corpus.
