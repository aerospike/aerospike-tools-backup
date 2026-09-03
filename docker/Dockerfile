# syntax=docker/dockerfile:1
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

FROM debian:trixie-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8

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
    apt-get install -y --no-install-recommends ca-certificates tini /tmp/asbackup.deb && \
    PKG_NAME="$(dpkg-deb -f /tmp/asbackup.deb Package)" && \
    PKG_VERSION="$(dpkg-query -W -f='${Version}' "${PKG_NAME}")" && \
    mkdir -p /usr/local/share/aerospike && \
    dpkg-query -L "${PKG_NAME}" \
      | { grep -E '^/usr/(local/)?bin/.' || true; } \
      | while read -r f; do \
            if [ -f "${f}" ] && [ -x "${f}" ]; then basename "${f}"; fi; \
        done \
      | sort -u > /usr/local/share/aerospike/tools && \
    if [ ! -s /usr/local/share/aerospike/tools ]; then \
        echo "no tool binaries found in ${PKG_NAME}" >&2; exit 1; \
    fi && \
    printf '%s image (%s %s)\n' "${PKG_NAME}" "${PKG_NAME}" "${PKG_VERSION}" \
      > /usr/local/share/aerospike/image-info && \
    groupadd --system --gid 10001 aerospike && \
    useradd --system --uid 10001 --gid 10001 --create-home \
      --home-dir /home/aerospike --shell /bin/bash aerospike && \
    rm -f /tmp/asbackup.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# tini is PID 1 so the tool runs as a child, where the kernel's default signal
# dispositions apply: `docker stop` on a tool that installs no SIGTERM handler
# (asbench, aql, asadm) exits at once instead of waiting out the timeout and
# being SIGKILLed. It also reaps orphans.
#
# The entrypoint script is the help entrypoint: it runs the binary named as the
# first argument, and prints usage listing the binaries this image ships when
# the caller names none or names something else. `--entrypoint bash` still gives
# a shell. No CMD: a default binary would hide the usage message, and images
# that ship several binaries have no correct default.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]

# The image runs as root so writes into bind-mounted directories keep working.
# An unprivileged `aerospike` user (uid/gid 10001) is present for callers that
# need one: `docker run --user 10001:10001 ...`, or runAsUser in a pod spec.

# Dynamic labels last: they change every build, so anything after them would
# have to rebuild with them.
ARG IMAGE_VERSION=""
ARG IMAGE_REVISION=""
ARG IMAGE_CREATED=""

LABEL org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.created="${IMAGE_CREATED}"
