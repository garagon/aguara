#!/bin/sh
#
# check-version-pins.sh -- verify that every release-pinned tag
# reference in the repository points at the version about to be
# tagged. Run as a release-prep step BEFORE `git tag vX.Y.Z`:
#
#   VERSION=v0.17.0 .github/scripts/check-version-pins.sh
#
# Why this script exists
# ----------------------
# Several files hardcode the current release tag so that consumers
# get a reproducible default rather than a floating ref:
#
#   cmd/aguara/commands/init.go    scaffolded GHA workflow:
#                                  uses: garagon/aguara@vX.Y.Z
#                                  version: vX.Y.Z
#   action.yml                     DEFAULT_REF="vX.Y.Z" (fallback
#                                  for consumers who do not pin)
#   Makefile                       INSTALL_SH_TEST_VERSION ?= vX.Y.Z
#                                  (install.sh acceptance test target)
#   README.md                      curl-pipe install snippets:
#                                  VERSION=vX.Y.Z sh
#
# Bumping ONLY the git tag while leaving any of these on the old
# version ships a release whose first-touch UX (init scaffold, action
# default) still points at the prior version. PR #92 was the
# fallout from exactly that pattern; this script makes the same
# class of mistake fail loud BEFORE the tag is pushed.
#
# This script is intentionally NOT wired into `make test`. It is a
# release-prep gate the maintainer runs alongside `verify-release.sh`
# (verify-release.sh runs POST-tag against the published artifacts;
# this one runs PRE-tag against the working tree).
#
# Exit codes:
#   0   every pin matches $VERSION
#   1   one or more pins drifted; the report lists each location and
#       what is currently there vs. what was expected
#   2   missing or malformed $VERSION env var
set -eu

if [ -z "${VERSION:-}" ]; then
  echo "check-version-pins: VERSION env var is required (e.g. VERSION=v0.17.0)" >&2
  exit 2
fi

# Validate semver shape. The version MUST look exactly like
# vMAJOR.MINOR.PATCH; anything else (pre-release suffixes,
# trailing junk like 'v0.17.0foo') is a typo the release flow
# does not handle yet.
#
# `case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*)` is NOT strict
# enough -- the trailing `*` in a shell glob consumes any
# characters, so 'v0.17.0foo' would match. Use a grep -E anchor
# instead, which is POSIX and enforces exact end-of-string.
if ! printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "check-version-pins: VERSION must be a semver tag like vX.Y.Z, got: $VERSION" >&2
  exit 2
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

drift_count=0
report() {
  printf 'DRIFT: %s\n' "$1" >&2
  drift_count=$((drift_count + 1))
}

# Each check below prints a DRIFT: line on failure and increments
# drift_count. We do NOT exit on the first failure -- the maintainer
# wants the full list in one run so they can fix everything in one
# commit.

# 1. cmd/aguara/commands/init.go: scaffolded GHA workflow action ref.
if ! grep -Fq "uses: garagon/aguara@$VERSION" cmd/aguara/commands/init.go; then
  report "cmd/aguara/commands/init.go: scaffolded workflow does not pin 'uses: garagon/aguara@$VERSION'"
fi

# 2. cmd/aguara/commands/init.go: scaffolded workflow binary version.
if ! grep -Fq "version: $VERSION" cmd/aguara/commands/init.go; then
  report "cmd/aguara/commands/init.go: scaffolded workflow does not pin 'version: $VERSION' (action input)"
fi

# 3. action.yml: DEFAULT_REF fallback for consumers who do not pin
#    `uses: garagon/aguara@<ref>`. Lives in the install-script ref
#    selection block.
if ! grep -Eq "DEFAULT_REF=\"$VERSION\"" action.yml; then
  report "action.yml: DEFAULT_REF is not \"$VERSION\""
fi

# 4. Makefile: INSTALL_SH_TEST_VERSION default for the install.sh
#    acceptance target. The variable is ?=-assigned, so the literal
#    must be on the right of '?='.
if ! grep -Eq "^INSTALL_SH_TEST_VERSION[[:space:]]*\?=[[:space:]]*$VERSION\$" Makefile; then
  report "Makefile: INSTALL_SH_TEST_VERSION does not default to $VERSION"
fi

# 5. README.md: curl-pipe install snippets that document
#    VERSION=<tag> sh. Every snippet matching the shape
#    `VERSION=vX.Y.Z sh` MUST pin to $VERSION; anything else is a
#    stale snippet a maintainer forgot to bump.
#
# Walking the matches line-by-line (rather than counting +
# negative-grep) means a README with two updated + one stale
# snippet fails too. The previous count-based check passed in
# that scenario because the count threshold was satisfied.
stale_readme=$(grep -nE "VERSION=v[0-9]+\.[0-9]+\.[0-9]+ sh" README.md | grep -v "VERSION=$VERSION sh" || true)
if [ -n "$stale_readme" ]; then
  # Use a here-doc to feed the while loop instead of a pipe. A
  # pipe spawns the right-hand side in a subshell, so 'report'
  # would bump a copy of drift_count that vanishes when the
  # subshell exits -- the parent's count then under-reports the
  # number of locations the maintainer has to fix. The here-doc
  # keeps the loop in the current shell so each stale snippet
  # increments drift_count for real.
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    report "README.md:$line (must pin to $VERSION)"
  done <<EOF
$stale_readme
EOF
fi

# Sanity: if README has ZERO matching snippets at all, even after
# the stale-snippets check, that's also a drift (someone removed
# the example entirely or the convention changed).
if ! grep -Fq "VERSION=$VERSION sh" README.md; then
  report "README.md: no install snippet pins 'VERSION=$VERSION sh' (the canonical example)"
fi

if [ "$drift_count" -gt 0 ]; then
  echo "" >&2
  echo "check-version-pins: $drift_count location(s) drifted from $VERSION" >&2
  echo "  Fix each DRIFT: line above and re-run before tagging." >&2
  exit 1
fi

echo "check-version-pins: all release pins agree on $VERSION"
exit 0
