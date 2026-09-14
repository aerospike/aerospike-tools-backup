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
# Base: ubuntu:24.04, the distro the .deb is built on, so its Depends resolve
# against the packages they were compiled against. It is also the base the
# legacy aerospike-tools image used and the one aerospike-server.docker
# publishes — apt installs the .deb and anything it (transitively) needs.
#

ARG ASBACKUP_AMD64_URL=""
ARG ASBACKUP_AMD64_SHA256=""
ARG ASBACKUP_ARM64_URL=""
ARG ASBACKUP_ARM64_SHA256=""

FROM ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254

ARG ASBACKUP_AMD64_URL
ARG ASBACKUP_AMD64_SHA256
ARG ASBACKUP_ARM64_URL
ARG ASBACKUP_ARM64_SHA256
ARG ASBACKUP_LOCAL_PKG=""
ARG ASBACKUP_LOCAL_PKG_AMD64=""
ARG ASBACKUP_LOCAL_PKG_ARM64=""
# Path of the entrypoint script inside the build context. CI (docker-verify
# and the shared publish workflow) builds from the repo root, where
# .dockerignore re-includes exactly this file; docker/docker-build.sh bakes
# from docker/ and overrides it to the bare file name.
ARG ENTRYPOINT_SRC=docker/docker-entrypoint.sh

LABEL org.opencontainers.image.title="Aerospike asbackup" \
      org.opencontainers.image.description="asbackup and asrestore — backup and restore tools for Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-tools-backup" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:24.04" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

# glibc otherwise resolves the POSIX locale, whose ANSI_X3.4-1968 charmap strips
# non-ASCII from tool output. ENV rather than an entrypoint export, so docker exec,
# --entrypoint overrides and K8s pod specs inherit it; the pre-13.0.3 wrapper only
# covered its own process. C.utf8 is glibc-builtin on trixie: no locales package,
# no size cost. LC_CTYPE is pinned alongside LANG deliberately -- C.utf8 is the
# image's only UTF-8 locale, so -e LANG=<ungenerated> would fall back to ASCII.
# Precedence is LC_ALL > LC_CTYPE > LANG, so override the ctype via LC_ALL or
# LC_CTYPE. Deviates from python/postgres, which set LANG only and ship locales.
ENV LANG=C.UTF-8 \
    LC_CTYPE=C.UTF-8

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

# Then record, from the installed package's own file list, the executables it
# put on PATH: docker-entrypoint.sh reads /usr/local/share/aerospike/tools and
# image-info to print usage, so the list is generated, never hand-maintained.
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
    if [ -n "${LOCAL_PKG}" ]; then \
        if [ ! -f "/build-ctx/${LOCAL_PKG}" ]; then \
            echo "ERROR: ${LOCAL_PKG} not in the build context." >&2; \
            echo "Available .deb: $(find /build-ctx -name '*.deb' -printf '%P ' 2>/dev/null)" >&2; \
            echo "The name is derived by the caller from pkg_release.sh; fix the derivation rather than falling back to an unverified download." >&2; \
            exit 1; \
        fi; \
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
        echo "ERROR: ${PKG_NAME} installed no executables under /usr/bin; the entrypoint usage would be empty." >&2; \
        exit 1; \
    fi && \
    printf 'Aerospike %s image (%s %s)\n' "${PKG_NAME#aerospike-}" "${PKG_NAME}" "${PKG_VERSION}" \
      > /usr/local/share/aerospike/image-info && \
    rm -f /tmp/asbackup.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# The .deb installs /usr/bin/asbackup and /usr/bin/asrestore; both are on PATH.
# Convention: `docker run --rm IMAGE <binary> [args]`.
# The entrypoint execs whatever is named (a passthrough, so `IMAGE bash` still
# works) and prints usage built from /usr/local/share/aerospike/tools when
# nothing, or an option, is named. No CMD: a default binary would hide that
# usage and a multi-binary image has no right default. Exec form so the script
# -- and, after exec, the tool -- is PID 1 and gets `docker stop`'s SIGTERM.
COPY --chmod=0755 ${ENTRYPOINT_SRC} /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
