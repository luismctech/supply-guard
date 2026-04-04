#!/bin/sh
set -e

REPO="AlbertoMZCruz/supply-guard"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY="supply-guard"

info() { printf "\033[1;34m%s\033[0m\n" "$1"; }
error() { printf "\033[1;31mError: %s\033[0m\n" "$1" >&2; exit 1; }
ok() { printf "\033[1;32m%s\033[0m\n" "$1"; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    else
        error "Neither curl nor wget found. Install one of them and retry."
    fi
}

download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    else
        wget -qO "$dest" "$url"
    fi
}

main() {
    VERSION="${VERSION:-}"
    OS=$(detect_os)
    ARCH=$(detect_arch)

    if [ -z "$VERSION" ]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
    fi

    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Set VERSION env var manually."
    fi

    VERSION_NUM="${VERSION#v}"

    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
    fi

    FILENAME="${BINARY}_${VERSION_NUM}_${OS}_${ARCH}.${EXT}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

    info "Downloading supply-guard ${VERSION} for ${OS}/${ARCH}..."

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    download "$URL" "${TMPDIR}/${FILENAME}"

    info "Verifying checksum..."
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    download "$CHECKSUM_URL" "${TMPDIR}/checksums.txt"

    EXPECTED_HASH=$(grep "${FILENAME}" "${TMPDIR}/checksums.txt" | awk '{print $1}')
    if [ -z "$EXPECTED_HASH" ]; then
        error "Could not find checksum for ${FILENAME} in checksums.txt"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_HASH=$(sha256sum "${TMPDIR}/${FILENAME}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_HASH=$(shasum -a 256 "${TMPDIR}/${FILENAME}" | awk '{print $1}')
    else
        error "Neither sha256sum nor shasum found. Cannot verify checksum."
    fi

    if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
        error "Checksum mismatch! Expected: ${EXPECTED_HASH}, Got: ${ACTUAL_HASH}. The download may have been tampered with."
    fi
    ok "Checksum verified"

    info "Extracting..."
    if [ "$EXT" = "zip" ]; then
        unzip -q "${TMPDIR}/${FILENAME}" -d "${TMPDIR}"
    else
        tar xzf "${TMPDIR}/${FILENAME}" -C "${TMPDIR}"
    fi

    if [ ! -f "${TMPDIR}/${BINARY}" ]; then
        error "Binary not found in archive. Contents: $(ls "${TMPDIR}")"
    fi

    chmod +x "${TMPDIR}/${BINARY}"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    fi

    ok "supply-guard ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"
    "${INSTALL_DIR}/${BINARY}" version
}

main
