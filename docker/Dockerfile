#
# Aerospike asbackup / asrestore — Docker image.
#
# https://github.com/aerospike/aerospike-tools-backup
#
# Supports linux/amd64 and linux/arm64.
# Driven by docker/docker-build.sh, which passes the version-specific URLs +
# SHA256s as build args (and optionally an in-context .deb via ASBACKUP_LOCAL_PKG*).
# Build directly only if you set those args yourself; otherwise use the script.
#
# Base: debian:trixie-slim. The .deb is built on Ubuntu 24.04; trixie ships a
# recent glibc and common C libs the binary may dynamically link to — apt
# installs the .deb and anything it (transitively) needs.
#

ARG ASBACKUP_AMD64_URL=""
ARG ASBACKUP_AMD64_SHA256=""
ARG ASBACKUP_ARM64_URL=""
ARG ASBACKUP_ARM64_SHA256=""

FROM debian:trixie-slim

ARG ASBACKUP_AMD64_URL
ARG ASBACKUP_AMD64_SHA256
ARG ASBACKUP_ARM64_URL
ARG ASBACKUP_ARM64_SHA256
ARG ASBACKUP_LOCAL_PKG=""
ARG ASBACKUP_LOCAL_PKG_AMD64=""
ARG ASBACKUP_LOCAL_PKG_ARM64=""

LABEL org.opencontainers.image.title="Aerospike asbackup" \
      org.opencontainers.image.description="asbackup and asrestore — backup and restore tools for Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-tools-backup" \
      org.opencontainers.image.base.name="docker.io/library/debian:trixie-slim" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN --mount=type=bind,source=.,target=/build-ctx \
    export DEBIAN_FRONTEND=noninteractive && \
    ARCH="$(dpkg --print-architecture)" && \
    if [ "${ARCH}" = "amd64" ]; then \
        PKG_URL="${ASBACKUP_AMD64_URL}"; PKG_SHA="${ASBACKUP_AMD64_SHA256}"; \
        LOCAL_PKG="${ASBACKUP_LOCAL_PKG_AMD64:-${ASBACKUP_LOCAL_PKG}}"; \
    else \
        PKG_URL="${ASBACKUP_ARM64_URL}"; PKG_SHA="${ASBACKUP_ARM64_SHA256}"; \
        LOCAL_PKG="${ASBACKUP_LOCAL_PKG_ARM64:-${ASBACKUP_LOCAL_PKG}}"; \
    fi && \
    apt-get update -y && \
    if [ -n "${LOCAL_PKG}" ] && [ -f "/build-ctx/${LOCAL_PKG}" ]; then \
        cp "/build-ctx/${LOCAL_PKG}" /tmp/asbackup.deb; \
    else \
        apt-get install -y --no-install-recommends curl ca-certificates && \
        curl -fsSL --retry 3 --retry-delay 3 "${PKG_URL}" -o /tmp/asbackup.deb && \
        apt-get purge -y --auto-remove curl; \
    fi && \
    if [ -n "${PKG_SHA}" ] && [ "${PKG_SHA}" != "PLACEHOLDER" ]; then \
        echo "${PKG_SHA}  /tmp/asbackup.deb" | sha256sum -c -; \
    fi && \
    apt-get install -y --no-install-recommends /tmp/asbackup.deb && \
    rm -f /tmp/asbackup.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["asbackup"]
