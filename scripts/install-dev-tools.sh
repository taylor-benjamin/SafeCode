#!/usr/bin/env bash
# Download the same pinned scanner versions the Docker image uses into .tools/,
# verifying each download's SHA-256 checksum. For local development and tests;
# the Action itself uses the Dockerfile. Works on Linux, macOS, and Git Bash on Windows.
#
# Usage: scripts/install-dev-tools.sh   (then run pytest; tests/conftest.py finds .tools/)
set -euo pipefail

# Keep in sync with the Dockerfile.
GITLEAKS_VERSION=8.30.1
OSV_SCANNER_VERSION=2.6.0
SEMGREP_VERSION=1.179.0

cd "$(dirname "$0")/.."
mkdir -p .tools/bin
cd .tools

case "$(uname -s)" in
  Linux*)  os=linux;   gl_os=linux;   exe="" ;;
  Darwin*) os=darwin;  gl_os=darwin;  exe="" ;;
  MINGW*|MSYS*|CYGWIN*) os=windows; gl_os=windows; exe=".exe" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; gl_arch=x64 ;;
  arm64|aarch64) arch=arm64; gl_arch=arm64 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

echo "Installing Gitleaks ${GITLEAKS_VERSION}"
gl_base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
gl_file="gitleaks_${GITLEAKS_VERSION}_${gl_os}_${gl_arch}"
gl_file+=$([ "$os" = windows ] && echo ".zip" || echo ".tar.gz")
curl -fsSL -o "$gl_file" "$gl_base/$gl_file"
curl -fsSL "$gl_base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" | grep " ${gl_file}\$" | sha256 -c -
if [ "$os" = windows ]; then unzip -o -q "$gl_file" gitleaks.exe -d bin; else tar -xzf "$gl_file" -C bin gitleaks; fi
rm "$gl_file"

echo "Installing OSV-Scanner ${OSV_SCANNER_VERSION}"
osv_base="https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}"
osv_file="osv-scanner_${os}_${arch}${exe}"
curl -fsSL -o "$osv_file" "$osv_base/$osv_file"
curl -fsSL "$osv_base/osv-scanner_SHA256SUMS" | grep " ${osv_file}\$" | sha256 -c -
mv "$osv_file" "bin/osv-scanner${exe}"
chmod +x "bin/osv-scanner${exe}"

echo "Installing Semgrep ${SEMGREP_VERSION} (isolated virtualenv)"
python3 -m venv semgrep-venv 2>/dev/null || python -m venv semgrep-venv
if [ -x semgrep-venv/bin/pip ]; then pip=semgrep-venv/bin/pip; else pip=semgrep-venv/Scripts/pip; fi
"$pip" install -q "semgrep==${SEMGREP_VERSION}"

echo "Done. Tools are in .tools/ (git-ignored)."
