#!/bin/sh
set -eu

REPO="garagon/aguara"
BINARY="aguara"

main() {
    need_cmd curl
    need_cmd tar

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
    curl -fsSL -o "${tmpdir}/${archive}" "$url"

    # Download and verify checksum
    log "Verifying checksum..."
    curl -fsSL -o "${tmpdir}/checksums.txt" "$checksums_url"
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

get_latest_version() {
    response=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest") || err "failed to fetch latest version from GitHub"
    version=$(echo "$response" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
    if [ -z "$version" ]; then
        err "could not determine latest version"
    fi
    echo "$version"
}

verify_checksum() {
    dir="$1"
    file="$2"
    expected=$(grep "$file" "${dir}/checksums.txt" | awk '{print $1}')
    if [ -z "$expected" ]; then
        err "checksum not found for ${file}"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${dir}/${file}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${dir}/${file}" | awk '{print $1}')
    else
        warn "sha256sum/shasum not found, skipping checksum verification"
        return
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
