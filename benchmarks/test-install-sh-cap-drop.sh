#!/bin/sh
#
# Acceptance test: install.sh must succeed inside a container started
# with `--cap-drop ALL --security-opt no-new-privileges`.
#
# Background: the release archive records uid/gid 1001 for its entries.
# Without CAP_CHOWN, tar's default behavior of restoring ownership
# fails with `Cannot change ownership to uid 1001, gid 1001`. The
# install.sh extract step passes `-o` (POSIX no-same-owner) so the
# extract succeeds even when the runtime cannot apply ownership.
#
# This script is invoked as the container ENTRYPOINT. It assumes the
# image bundles install.sh at /work/install.sh and that the caller
# exports VERSION (e.g. v0.15.0) so the test pins to a known release.
set -eu

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
    echo "TEST FAIL: VERSION env var is required (e.g. VERSION=v0.15.0)" >&2
    exit 1
fi

INSTALL_DIR="${INSTALL_DIR:-/tmp/bin}"
mkdir -p "$INSTALL_DIR"

echo "Running install.sh with VERSION=${VERSION} INSTALL_DIR=${INSTALL_DIR}"
echo "Container caps: $(cat /proc/self/status | grep -E '^Cap(Eff|Bnd):' || true)"

VERSION="$VERSION" INSTALL_DIR="$INSTALL_DIR" sh /work/install.sh

bin="${INSTALL_DIR}/aguara"
if [ ! -x "$bin" ]; then
    echo "TEST FAIL: ${bin} not installed" >&2
    exit 1
fi

# Strip the leading v to compare against `aguara version` output which
# prints the GoReleaser-stripped semver.
version_stripped=$(echo "$VERSION" | sed 's/^v//')
out=$("$bin" version 2>&1)
echo "binary output: ${out}"

if ! echo "$out" | grep -Fq "${version_stripped}"; then
    echo "TEST FAIL: installed binary did not report version ${version_stripped}" >&2
    exit 1
fi

echo "TEST OK: install.sh succeeded under --cap-drop ALL, binary reports ${version_stripped}"
