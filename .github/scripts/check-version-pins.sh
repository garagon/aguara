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

# Validate semver shape. The version MUST look like vMAJOR.MINOR.PATCH;
# anything else would be a typo (or a pre-release the release flow
# does not handle yet).
case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "check-version-pins: VERSION must be a semver tag like vX.Y.Z, got: $VERSION" >&2
    exit 2
    ;;
esac

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

# 5+6. README.md: curl-pipe install snippets that document
#      VERSION=<tag> sh. There are two of these (quick install +
#      pin-to-version examples); both must match.
readme_hits=$(grep -c "VERSION=$VERSION sh" README.md || true)
if [ "$readme_hits" -lt 2 ]; then
  report "README.md: expected >=2 install snippets with 'VERSION=$VERSION sh' (found $readme_hits)"
fi

# Report stale README snippets too -- if VERSION=v0.15.0 still
# appears, the user will know which line to fix.
if grep -nE "VERSION=v[0-9]+\.[0-9]+\.[0-9]+ sh" README.md | grep -vE "VERSION=$VERSION sh"; then
  : # the grep above prints the offending lines on stderr-equivalent;
    # increment the counter via a sentinel marker.
  if grep -nqE "VERSION=v[0-9]+\.[0-9]+\.[0-9]+ sh" README.md && \
     ! grep -nq "VERSION=$VERSION sh" README.md; then
    report "README.md: install snippets reference a different VERSION than $VERSION (see lines above)"
  fi
fi

if [ "$drift_count" -gt 0 ]; then
  echo "" >&2
  echo "check-version-pins: $drift_count location(s) drifted from $VERSION" >&2
  echo "  Fix each DRIFT: line above and re-run before tagging." >&2
  exit 1
fi

echo "check-version-pins: all release pins agree on $VERSION"
exit 0
