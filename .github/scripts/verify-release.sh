#!/bin/sh
# verify-release.sh - Acceptance test for a published Aguara release.
#
# Validates from a clean machine that the artifacts at github.com/garagon/aguara
# and ghcr.io/garagon/aguara for the given VERSION are:
#   1. signed by the release workflow (cosign verify-blob, cosign verify image)
#   2. consistent with their checksums (sha256 -c)
#   3. functionally working (aguara version, list-rules, scan)
#
# Required tools: curl, tar, sha256sum or shasum, cosign, docker, jq.
# The script auto-detects the host OS/arch for the binary download and pulls
# the matching Docker image manifest.
#
# Usage:
#   VERSION=v0.14.1 scripts/verify-release.sh
#
# Exits 0 if every check passes, 1 on the first failure with a clear message.
set -eu

REPO="garagon/aguara"
IMAGE="ghcr.io/${REPO}"
VERSION="${VERSION:?VERSION env var required, e.g. VERSION=v0.14.1}"
VERSION_STRIPPED="${VERSION#v}"

# Detect host
case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    *) err "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "unsupported arch: $(uname -m)" ;;
esac

ARCHIVE="aguara_${VERSION_STRIPPED}_${OS}_${ARCH}.tar.gz"

green() { printf '\033[1;32m%s\033[0m\n' "$1"; }
red() { printf '\033[1;31m%s\033[0m\n' "$1" >&2; }
info() { printf '  %s\n' "$1"; }
err() { red "FAIL: $1"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"; }

need curl; need tar; need cosign; need docker; need jq
if command -v sha256sum >/dev/null 2>&1; then
    SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA="shasum -a 256"
else
    err "no sha256 tool (need sha256sum or shasum)"
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

green ">> 1/6 download release artifacts"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
curl -fsSL --max-time 120 --retry 3 -O "${DOWNLOAD_BASE}/${ARCHIVE}" || err "archive download failed"
curl -fsSL --max-time 30  --retry 3 -O "${DOWNLOAD_BASE}/checksums.txt" || err "checksums download failed"
curl -fsSL --max-time 30  --retry 3 -O "${DOWNLOAD_BASE}/checksums.txt.bundle" || err "cosign bundle download failed"
info "downloaded: ${ARCHIVE} + checksums.txt + checksums.txt.bundle"

green ">> 2/6 cosign verify-blob (checksums.txt signed by release workflow)"
cosign verify-blob \
    --bundle checksums.txt.bundle \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    checksums.txt >/dev/null || err "cosign verify-blob failed"
info "checksums.txt signature verified"

green ">> 3/6 sha256 of archive matches signed checksums"
EXPECTED=$(grep " ${ARCHIVE}$" checksums.txt | awk '{print $1}')
[ -n "$EXPECTED" ] || err "checksum entry for ${ARCHIVE} missing from checksums.txt"
ACTUAL=$($SHA "${ARCHIVE}" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED" ] || err "sha256 mismatch: expected $EXPECTED got $ACTUAL"
info "sha256 ok: ${EXPECTED}"

green ">> 4/6 binary works and reports the right version"
tar -xzf "${ARCHIVE}"
[ -x ./aguara ] || err "binary not extracted or not executable"
BINARY_VERSION=$(./aguara version | awk 'NR==1 {print $2}')
[ "$BINARY_VERSION" = "$VERSION_STRIPPED" ] || err "binary reports version '${BINARY_VERSION}', expected '${VERSION_STRIPPED}'"
info "binary version: ${BINARY_VERSION}"
RULE_COUNT=$(./aguara list-rules --no-update-check | tail -1 | awk '{print $1}')
[ -n "$RULE_COUNT" ] && [ "$RULE_COUNT" -gt 0 ] 2>/dev/null || err "list-rules returned no rule count"
info "rules loaded: ${RULE_COUNT}"

green ">> 5/6 cosign verify Docker image at digest"
cosign verify "${IMAGE}:${VERSION_STRIPPED}" \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/docker.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" >/dev/null 2>&1 \
    || err "cosign verify image failed"
info "image signature verified"

green ">> 6/6 Docker image runs natively on host arch and reports the right version"
docker pull "${IMAGE}:${VERSION_STRIPPED}" >/dev/null 2>&1 || err "docker pull failed (image likely missing linux/${ARCH} manifest)"
DOCKER_VERSION=$(docker run --rm "${IMAGE}:${VERSION_STRIPPED}" version | awk 'NR==1 {print $2}')
[ "$DOCKER_VERSION" = "$VERSION_STRIPPED" ] || err "docker image reports version '${DOCKER_VERSION}', expected '${VERSION_STRIPPED}'"
info "docker version: ${DOCKER_VERSION}"

docker buildx imagetools inspect "${IMAGE}:${VERSION_STRIPPED}" --format '{{json .SBOM}}' \
    | jq -e '.SPDX.SPDXID == "SPDXRef-DOCUMENT"' >/dev/null \
    || err "Docker image SBOM (SPDX) missing or malformed"
info "image SBOM: SPDX present"
docker buildx imagetools inspect "${IMAGE}:${VERSION_STRIPPED}" --format '{{json .Provenance}}' \
    | jq -e '.SLSA.buildDefinition.buildType | startswith("https://")' >/dev/null \
    || err "Docker image SLSA provenance missing or malformed"
info "image provenance: SLSA present"

green ">> ALL CHECKS PASSED for ${VERSION} (${OS}/${ARCH})"
