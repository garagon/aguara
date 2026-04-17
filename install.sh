#!/bin/sh
set -eu

REPO="garagon/aguara"
BINARY="aguara"

main() {
    need_cmd curl
    need_cmd tar
    need_checksum_tool

    os=$(detect_os)
    arch=$(detect_arch)

    if [ -n "${VERSION:-}" ]; then
        version="$VERSION"
    else
        version=$(get_latest_version)
    fi

    # GoReleaser strips the v prefix in archive names
    version_stripped=$(echo "$version" | sed 's/^v//')

    archive="${BINARY}_${version_stripped}_${os}_${arch}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${version}/${archive}"
    checksums_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"

    install_dir="${INSTALL_DIR:-}"
    if [ -z "$install_dir" ]; then
        install_dir="$HOME/.local/bin"
    fi

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    log "Installing ${BINARY} ${version} (${os}/${arch})"

    # Download archive
    log "Downloading ${archive}..."
    download "$url" "${tmpdir}/${archive}"

    # Download and verify checksum
    log "Verifying checksum..."
    download "$checksums_url" "${tmpdir}/checksums.txt"
    verify_checksum "$tmpdir" "$archive"

    # Extract binary
    tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"

    if [ ! -f "${tmpdir}/${BINARY}" ]; then
        err "binary not found in archive"
    fi

    # Install
    mkdir -p "$install_dir"
    if [ -w "$install_dir" ]; then
        mv "${tmpdir}/${BINARY}" "${install_dir}/${BINARY}"
    else
        log "Elevated permissions required to install to ${install_dir}"
        sudo mv "${tmpdir}/${BINARY}" "${install_dir}/${BINARY}"
    fi
    chmod +x "${install_dir}/${BINARY}"

    # Verify
    if "${install_dir}/${BINARY}" version >/dev/null 2>&1; then
        installed_version=$("${install_dir}/${BINARY}" version 2>/dev/null || true)
        log "Installed ${BINARY} ${installed_version} to ${install_dir}/${BINARY}"
    else
        log "Installed ${BINARY} to ${install_dir}/${BINARY}"
    fi

    # PATH check
    case ":${PATH}:" in
        *":${install_dir}:"*) ;;
        *)
            warn "${install_dir} is not in your PATH"
            printf '\n  Add this to your shell config (~/.bashrc, ~/.zshrc, etc.):\n'
            printf '\n    export PATH="%s:$PATH"\n\n' "$install_dir"
            printf '  Then restart your terminal or run: source ~/.zshrc\n\n'
            ;;
    esac
}

detect_os() {
    uname_s=$(uname -s)
    case "$uname_s" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       err "unsupported OS: ${uname_s}. Use 'go install' instead." ;;
    esac
}

detect_arch() {
    uname_m=$(uname -m)
    case "$uname_m" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             err "unsupported architecture: ${uname_m}" ;;
    esac
}

# download fetches a URL into a local file with bounded time and retries.
# Used for release artifacts (archive, checksums.txt). Times out at 120s
# so a hung TCP connection cannot stall the install indefinitely.
download() {
    url="$1"
    output="$2"
    curl -fsSL \
        --max-time 120 \
        --retry 3 \
        --retry-delay 2 \
        --retry-connrefused \
        -o "$output" "$url" \
        || err "failed to download: ${url}"
}

get_latest_version() {
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    # GitHub API has a 60/h anonymous rate limit per IP. CI runners share
    # IP pools and exhaust this quickly; sending GITHUB_TOKEN raises the
    # ceiling to 5000/h authenticated. Token is never echoed or logged.
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        response=$(curl -fsSL \
            --max-time 30 \
            --retry 3 \
            --retry-delay 2 \
            --retry-connrefused \
            -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            "$api_url") \
            || err "failed to fetch latest version from GitHub"
    else
        response=$(curl -fsSL \
            --max-time 30 \
            --retry 3 \
            --retry-delay 2 \
            --retry-connrefused \
            "$api_url") \
            || err "failed to fetch latest version from GitHub (set GITHUB_TOKEN to avoid anonymous rate limits)"
    fi
    version=$(echo "$response" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
    if [ -z "$version" ]; then
        err "could not determine latest version"
    fi
    echo "$version"
}

# verify_checksum aborts on any failure, including missing tooling.
# Skipping checksum verification would let a network MITM swap the binary,
# so a missing sha256sum/shasum is a hard error rather than a warning.
verify_checksum() {
    dir="$1"
    file="$2"
    expected=$(grep "$file" "${dir}/checksums.txt" | awk '{print $1}')
    if [ -z "$expected" ]; then
        err "checksum not found for ${file} in checksums.txt"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${dir}/${file}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${dir}/${file}" | awk '{print $1}')
    else
        # Should be unreachable: need_checksum_tool runs at startup.
        err "no sha256 tool available; install coreutils or perl-Digest-SHA"
    fi
    if [ "$actual" != "$expected" ]; then
        err "checksum mismatch: expected ${expected}, got ${actual}"
    fi
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "required command not found: $1"
    fi
}

# need_checksum_tool aborts the install up front if neither sha256sum nor
# shasum is available, rather than discovering it after downloading.
# macOS ships shasum by default; Linux distros ship sha256sum via coreutils.
need_checksum_tool() {
    if command -v sha256sum >/dev/null 2>&1; then return; fi
    if command -v shasum >/dev/null 2>&1; then return; fi
    err "no sha256 tool found (need sha256sum or shasum). Install coreutils (Linux) or perl-Digest-SHA, then retry."
}

log() {
    printf '  \033[1;32m>\033[0m %s\n' "$1"
}

warn() {
    printf '  \033[1;33m!\033[0m %s\n' "$1"
}

err() {
    printf '  \033[1;31mx\033[0m %s\n' "$1" >&2
    exit 1
}

main
