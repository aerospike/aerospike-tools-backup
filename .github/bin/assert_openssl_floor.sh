#!/usr/bin/env bash
# Fail the build if the freshly linked asbackup/asrestore reference any OpenSSL symbol
# version above the EL9/EL10 GA floor (OPENSSL_3.2.0, from Rocky vault openssl-libs
# 3.2.2). This is the container-independent backstop for the dynamic-link regression:
# if the build floats to a newer libcrypto (3.5 -> OPENSSL_3.4.0 symbols, pulled in via
# the AWS SDK), the binary fails to load on RHEL 9.x/10.0 customers. Checking the
# dynamic symbol table catches it at build time even for lazily bound symbols that
# `asbackup --help` never exercises, and it asserts the floor directly instead of just
# confirming build-env == test-env. No-op on other distros.
set -euo pipefail

distro="${1:-${ENV_DISTRO:-}}"
case "$distro" in
  el9|el10) ;;
  *) echo "assert_openssl_floor: nothing to check for '${distro:-<unset>}'"; exit 0 ;;
esac

floor_minor=2   # allow OPENSSL_3.0 .. 3.2; fail on 3.3 and newer
violations=""
for bin in bin/asbackup bin/asrestore; do
  if [[ ! -f "$bin" ]]; then
    echo "assert_openssl_floor: expected built binary $bin not found" >&2
    exit 1
  fi
  # objdump -T lists the dynamic (undefined) symbols this binary needs from libcrypto/
  # libssl, versioned as OPENSSL_3.x. awk picks any minor above the floor.
  bad="$(objdump -T "$bin" \
    | grep -oE 'OPENSSL_3\.[0-9]+' \
    | sort -u \
    | awk -F. -v floor="$floor_minor" '$2 > floor {print}')"
  if [[ -n "$bad" ]]; then
    violations+="${bin}:"$'\n'"${bad}"$'\n'
  fi
done

if [[ -n "$violations" ]]; then
  echo "::error::asbackup/asrestore reference OpenSSL symbols above the GA 3.${floor_minor} floor:" >&2
  printf '%s' "$violations" >&2
  echo "The EL build floated past the pinned Rocky vault OpenSSL; these binaries will not load on older RHEL ${distro#el}.x." >&2
  exit 1
fi

echo "assert_openssl_floor: ${distro} OK (no OpenSSL symbols above 3.${floor_minor})"
