# SAFECODE GitHub Action image.
#
# Every external input is pinned: the base image by digest, the scanner
# binaries by version *and* SHA-256 checksum, and Python packages by version
# (SAFECODE's own dependencies also by hash). To upgrade a scanner, change its
# version and checksum together; the checksums come from each project's
# release page.

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG OSV_SCANNER_VERSION=2.6.0
ARG OSV_SCANNER_SHA256=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
ARG SEMGREP_VERSION=1.179.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Semgrep: no telemetry, no version-check network call.
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

# git is required by Gitleaks to read history; curl is only used during the build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Gitleaks (secrets, including git history)
RUN curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz

# OSV-Scanner (known-vulnerable dependencies)
RUN curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    && echo "${OSV_SCANNER_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c - \
    && chmod +x /usr/local/bin/osv-scanner

# Semgrep (code patterns). Installed in its own virtualenv so its dependency
# tree can never conflict with SAFECODE's.
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

# The Actions runner mounts the workspace owned by a different user than the
# container's root user; without this, git refuses to read the repository.
RUN git config --system --add safe.directory '*'

WORKDIR /app
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt

COPY src/ src/
COPY rules/ rules/
ENV PYTHONPATH=/app/src

# Docker actions run as root by GitHub's design (the workspace and the
# GITHUB_OUTPUT / GITHUB_STEP_SUMMARY files are owned by the runner), so no USER is set.
ENTRYPOINT ["python", "-m", "safecode"]
